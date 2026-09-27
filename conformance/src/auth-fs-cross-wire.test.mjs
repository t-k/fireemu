import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import http2 from "node:http2";
import { test } from "node:test";

import { bearerHash, createWireLedger, installWireGuard } from "./auth-fs-cross/sdk-wire.mjs";

const sha = (text) => createHash("sha256").update(text).digest("hex");

test("the ledger admits allowed hosts up to its cap and hashes the bearer", () => {
  const seen = [];
  const ledger = createWireLedger({ hosts: ["a.example"], cap: 2, onRecord: (r) => seen.push(r) });
  assert.deepEqual(ledger.admit("a.example", "/x", "Bearer tok"), {
    n: 1,
    host: "a.example",
    path: "/x",
    bearer: sha("tok"),
  });
  assert.equal(ledger.admit("a.example", "/y", undefined).bearer, null);
  assert.throws(() => ledger.admit("a.example", "/z", undefined), /cap 2 reached/);
  assert.throws(
    () => createWireLedger({ hosts: ["a.example"], cap: 9 }).admit("evil.example", "/", ""),
    /not an allowed host/,
  );
  assert.equal(seen.length, 2);
  assert.doesNotMatch(JSON.stringify(ledger.records), /tok\b/);
});

test("a bearer is compared by its hash, whatever its scheme spelling", () => {
  assert.equal(bearerHash("Bearer abc"), sha("abc"));
  assert.equal(bearerHash("bearer abc"), sha("abc"));
  assert.equal(bearerHash(["Bearer abc"]), sha("abc"));
  assert.equal(bearerHash(""), null);
});

test("fetch goes through the ledger and a refused host is never fetched", async () => {
  const ledger = createWireLedger({ hosts: ["identitytoolkit.googleapis.com"], cap: 5 });
  const fetched = [];
  const restore = installWireGuard(ledger, {
    fetchImpl: async (input) => {
      fetched.push(String(input));
      return new Response("{}");
    },
  });
  try {
    await globalThis.fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=k", {
      headers: { authorization: "Bearer t1" },
    });
    await assert.rejects(globalThis.fetch("https://evil.example/"), /not an allowed host/);
  } finally {
    restore();
  }
  assert.deepEqual(fetched, ["https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=k"]);
  assert.deepEqual(
    ledger.records.map(({ path, bearer }) => [path, bearer]),
    [["/v1/accounts:lookup", sha("t1")]],
  );
});

test("every HTTP/2 request goes through the ledger with its bearer hashed", async (t) => {
  const server = http2.createServer();
  server.on("stream", (stream) => {
    stream.respond({ ":status": 200 });
    stream.end("ok");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const ledger = createWireLedger({ hosts: ["127.0.0.1"], cap: 5 });
  const restore = installWireGuard(ledger);
  try {
    const session = http2.connect(`http://127.0.0.1:${port}`);
    const request = session.request({
      ":path": "/google.firestore.v1.Firestore/Listen",
      authorization: "Bearer t2",
    });
    request.resume();
    await new Promise((resolve) => request.on("end", resolve));
    session.close();
  } finally {
    restore();
  }
  assert.deepEqual(ledger.records, [
    { n: 1, host: "127.0.0.1", path: "/google.firestore.v1.Firestore/Listen", bearer: sha("t2") },
  ]);
});

test("each refusal is reported with its host, path and reason, never its bearer", () => {
  const refused = [];
  const ledger = createWireLedger({
    hosts: ["a.example"],
    cap: 1,
    onRefuse: (r) => refused.push(r),
  });
  ledger.admit("a.example", "/one", "Bearer SECRET");
  assert.throws(() => ledger.admit("a.example", "/two", "Bearer SECRET"), /request cap 1 reached/);
  assert.throws(
    () => ledger.admit("b.example", "/three", "Bearer SECRET"),
    /b.example is not an allowed host/,
  );
  assert.deepEqual(refused, [
    { host: "a.example", path: "/two", reason: "request cap 1 reached" },
    { host: "b.example", path: "/three", reason: "b.example is not an allowed host" },
  ]);
  assert.equal(ledger.records.length, 1);
});
