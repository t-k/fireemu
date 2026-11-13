import "../storage-signed-put/test-preload.mjs";
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { requests, targetOf } from "./guard.mjs";
import { fetchNet, installEgressGuard } from "./egress.mjs";
import { createWire, openJournal } from "./wire.mjs";

const target = targetOf({
  project: "fireemu-oracle-query",
  defaultBucket: "fireemu-oracle-query.firebasestorage.app",
  runId: "ss-0123abcd",
});
const response = { status: 404, headers: {}, body: Buffer.from("missing") };
function wire(net, extra = {}) {
  const entries = [];
  return {
    entries,
    client: createWire({
      target,
      net,
      journal: { append: (entry) => entries.push(entry) },
      ...extra,
    }),
  };
}

test("the sixty-first call is refused before network or journal emission", async () => {
  let calls = 0;
  const { entries, client } = wire(async () => {
    calls++;
    return response;
  });
  for (let i = 0; i < 60; i++) await client.wire(requests(target).P1);
  await assert.rejects(client.wire(requests(target).P1), /budget/);
  assert.equal(calls, 60);
  assert.equal(entries.length, 120);
});

test("classification happens before counting and sending", async () => {
  let calls = 0;
  const { client, entries } = wire(async () => {
    calls++;
    return response;
  });
  await assert.rejects(client.wire({ ...requests(target).P1, url: "https://example.com/" }));
  assert.equal(calls, 0);
  assert.equal(client.budget.count, 0);
  assert.deepEqual(entries, []);
});

test("fetch disables redirects and reads the body before completing", async () => {
  const local = { ...target, local: "http://localhost:9199" };
  let calls = 0;
  let init;
  const net = fetchNet(local, async (_url, options) => {
    calls++;
    init = options;
    return {
      status: 302,
      headers: new Headers({ location: "https://storage.googleapis.com/" }),
      arrayBuffer: async () => Buffer.from("redirect"),
    };
  });
  const { client } = wire(net, { target: local });
  const answer = await client.wire(requests(local).P1);
  assert.equal(init.redirect, "manual");
  assert.ok(init.signal instanceof AbortSignal);
  assert.equal(answer.unknown, true);
  assert.equal(calls, 1);
});

test("unreadable and cancelled bodies are unknown and never retried", async () => {
  const local = { ...target, local: "http://localhost:9199" };
  for (const name of ["Error", "AbortError"]) {
    let calls = 0;
    const net = fetchNet(local, async () => {
      calls++;
      return {
        status: 200,
        headers: new Headers(),
        arrayBuffer: async () => {
          const error = new Error("body failed");
          error.name = name;
          throw error;
        },
      };
    });
    const { client, entries } = wire(net, { target: local });
    assert.equal((await client.wire(requests(local).W1)).unknown, true);
    assert.equal(calls, 1);
    assert.equal(entries.at(-1).status, 200);
    assert.equal(entries.at(-1).bodyBytes, null);
    assert.equal(entries.at(-1).unreadable, true);
  }
});

test("the whole-run deadline aborts an in-flight request and refuses later cleanup sends", async () => {
  let signal;
  const { client } = wire(
    (_r, options) => {
      signal = options.signal;
      return new Promise(() => {});
    },
    { deadline: Date.now() + 25 },
  );
  assert.equal((await client.wire(requests(target).W1)).unknown, true);
  assert.equal(signal.aborted, true);
  await assert.rejects(client.wire(requests(target).K3), /deadline/);
});

test("bucket creation has a sixty-second cap and every other call has thirty seconds", async () => {
  const { client, entries } = wire(async () => response);
  await client.wire(requests(target).W1);
  await client.wire(requests(target).W3);
  assert.deepEqual(
    entries.filter((e) => e.phase === "before").map((e) => e.timeoutMs),
    [60_000, 30_000],
  );
});

test("an unknown delete cannot be resent even with a different case or dialect", async () => {
  const { client } = wire(async () => ({ ...response, status: 503 }));
  await client.wire(requests(target).F2);
  await assert.rejects(client.wire(requests(target).K7), /cannot be resent/);
  assert.equal(client.budget.count, 1);
});

test("journal files are private, exclusive, newline-delimited and byte preserving", () => {
  const directory = mkdtempSync(join(tmpdir(), "strictness-journal-"));
  try {
    const path = join(directory, "journal.jsonl");
    const journal = openJournal(path);
    try {
      journal.append({ status: 200, bodyBase64: "ZmlyZQ==", bodyBytes: 4 });
      assert.throws(() => openJournal(path), /EEXIST/);
    } finally {
      journal.close();
    }
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(
      readFileSync(path, "utf8"),
      '{"status":200,"bodyBase64":"ZmlyZQ==","bodyBytes":4}\n',
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("seeded credential echoes cannot reach a journal as text or decoded body bytes", async () => {
  let seed = 0x51a7;
  for (let i = 0; i < 100; i++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const token = `synthetic-${seed.toString(16)}-owner`;
    const body = i % 2 ? Buffer.from(`echo ${token}`) : Buffer.from("fire");
    const { client, entries } = wire(
      async () => ({
        status: 200,
        headers: { Authorization: `Bearer ${token}`, "x-echo": token },
        body,
      }),
      { token },
    );
    await client.wire(requests(target).P1);
    for (const entry of entries) {
      const line = JSON.stringify(entry);
      assert.equal(line.includes(token), false);
      assert.equal(line.includes(`Bearer ${token}`), false);
      assert.equal(
        Buffer.from(entry.bodyBase64 ?? "", "base64").includes(Buffer.from(token)),
        false,
      );
      assert.equal(entry.requestHeaders.authorization, "<redacted>");
    }
    assert.equal(entries.at(-1).unknown, true);
    assert.equal(entries.at(-1).bodyBytes, body.length);
  }
});

test("alternate HTTP paths are blocked and restored without leaving a global guard behind", () => {
  const saved = [http.request, https.get, globalThis.fetch];
  const restore = installEgressGuard();
  try {
    assert.throws(() => http.request("http://localhost/"), /unguarded/);
    assert.throws(() => https.get("https://storage.googleapis.com/"), /unguarded/);
    assert.throws(() => globalThis.fetch("https://storage.googleapis.com/"), /unguarded/);
  } finally {
    restore();
  }
  assert.deepEqual([http.request, https.get, globalThis.fetch], saved);
});
