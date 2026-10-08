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

test("the first refusal is reported once and closes the ledger to every later request", () => {
  const refused = [];
  const ledger = createWireLedger({
    hosts: ["a.example"],
    cap: 1,
    onRefuse: (r) => refused.push(r),
  });
  ledger.admit("a.example", "/one", "Bearer SECRET");
  assert.equal(ledger.closed(), false);
  ledger.connect("a.example");
  assert.throws(() => ledger.admit("a.example", "/two", "Bearer SECRET"), /request cap 1 reached/);
  assert.equal(ledger.closed(), true);
  // Every later request and connection is refused at once, and not reported again.
  assert.throws(() => ledger.admit("a.example", "/three"), /client is closed/);
  assert.throws(() => ledger.connect("a.example"), /client is closed/);
  assert.deepEqual(refused, [{ host: "a.example", path: "/two", reason: "request cap 1 reached" }]);
  assert.equal(JSON.stringify(refused).includes("SECRET"), false);
  assert.equal(ledger.records.length, 1);
  // A host outside the list closes it the same way.
  const other = createWireLedger({
    hosts: ["a.example"],
    cap: 9,
    onRefuse: (r) => refused.push(r),
  });
  assert.throws(() => other.admit("b.example", "/x"), /b.example is not an allowed host/);
  assert.throws(() => other.admit("a.example", "/y"), /client is closed/);
  assert.equal(refused.length, 2);
});

test("the connection past the cap is destroyed before it connects, and closes the client", async () => {
  const { installSocketGuard } = await import("./auth-fs-cross/sdk-wire.mjs");
  const net = await import("node:net");
  const server = net.createServer((socket) => socket.end());
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const refused = [];
  const seen = [];
  const ledger = createWireLedger({
    hosts: [],
    cap: 0,
    connectionCap: 2,
    onConnection: (c) => seen.push(c),
    onRefuse: (r) => refused.push(r),
  });
  let accepted = 0;
  server.on("connection", () => {
    accepted += 1;
  });
  const restore = installSocketGuard(ledger);
  const attempt = () =>
    new Promise((resolve) => {
      const socket = net.connect(port, "127.0.0.1");
      socket.on("connect", () => {
        socket.destroy();
        resolve("connected");
      });
      socket.on("error", (error) => resolve(error.message));
    });
  try {
    assert.equal(await attempt(), "connected");
    assert.equal(await attempt(), "connected");
    assert.match(await attempt(), /connection cap 2 reached/);
    assert.match(await attempt(), /client is closed/);
  } finally {
    restore();
  }
  // The server may see a connection a moment after the client did: wait for it, then count.
  const until = Date.now() + 2_000;
  const seenByServer = () => accepted;
  while (seenByServer() < 2 && Date.now() < until)
    await new Promise((resolve) => setTimeout(resolve, 10));
  await new Promise((resolve) => setTimeout(resolve, 50));
  server.close();
  assert.equal(accepted, 2);
  assert.deepEqual(
    seen.map((c) => c.n),
    [1, 2],
  );
  assert.deepEqual(refused, [{ host: "127.0.0.1", path: "", reason: "connection cap 2 reached" }]);
  assert.equal(ledger.connections(), 2);
});

test("S5b transaction capture whitelists only the two RPCs and fails closed", async () => {
  const { transactionWireEvidence } = await import("./auth-fs-cross/sdk-wire.mjs");
  const secret = { authorization: "Bearer SECRET", apiKey: "SECRET", query: "SECRET" };
  for (let i = 0; i < 50; i += 1) {
    const name = `projects/demo-p/databases/(default)/documents/s5b/d${i}`;
    const version = `2026-10-07T00:00:00.${String(i).padStart(9, "0")}Z`;
    const evidence = transactionWireEvidence(
      "Commit",
      {
        ...secret,
        writes: [
          {
            ...secret,
            update: { name, fields: { value: { integerValue: String(i), ...secret } } },
            currentDocument: { updateTime: version, ...secret },
          },
        ],
      },
      { ...secret, writeResults: [{ updateTime: version, ...secret }], commitTime: version },
      200,
    );
    assert.equal(evidence.complete, true);
    assert.equal(evidence.request.writes[0].currentDocument?.updateTime, version);
    assert.doesNotMatch(JSON.stringify(evidence), /SECRET|authorization|apiKey|query/);
    assert.equal(transactionWireEvidence("Listen", {}, {}, 200), null);
    for (const response of [null, "{", "x".repeat(65537)])
      assert.equal(transactionWireEvidence("Commit", {}, response, 200).complete, false);
    assert.equal(transactionWireEvidence("Commit", {}, {}, 503).complete, false);
  }
});

test("S5b capture is opt-in, observes fetch once and preserves the original response", async () => {
  const observed = [];
  let calls = 0;
  const ledger = createWireLedger({ hosts: ["127.0.0.1"], cap: 5 });
  const response = new Response(JSON.stringify([{ found: { name: "n", updateTime: "v" } }]), {
    status: 200,
  });
  const restore = installWireGuard(ledger, {
    fetchImpl: async () => {
      calls += 1;
      return response;
    },
    onTransaction: (e) => observed.push(e),
  });
  try {
    const answer = await fetch(
      "http://127.0.0.1/v1/projects/demo-p/databases/(default)/documents:batchGet?key=SECRET",
      { method: "POST", body: JSON.stringify({ documents: ["n"], apiKey: "SECRET" }) },
    );
    assert.equal(answer, response);
    assert.equal((await answer.json())[0].found.updateTime, "v");
  } finally {
    restore();
  }
  assert.equal(calls, 1);
  assert.equal(ledger.records.length, 1);
  assert.equal(observed.length, 1);
  assert.equal(observed[0].n, 1);
  assert.deepEqual(observed[0].response.documents, [{ name: "n", updateTime: "v" }]);
  assert.doesNotMatch(JSON.stringify(observed), /SECRET/);
});

test("S5b request/response size boundaries and malformed shapes remain incomplete", async () => {
  const { transactionMethod, transactionWireEvidence } =
    await import("./auth-fs-cross/sdk-wire.mjs");
  assert.equal(
    transactionMethod("/v1/projects/demo-p/databases/(default)/documents:commit"),
    "Commit",
  );
  for (const path of [
    "/v1/accounts:lookup",
    "/v1/projects/p/databases/d/documents:commit?key=secret",
    "/google.firestore.v1.Firestore/Listen",
    "/Commit",
  ])
    assert.equal(transactionMethod(path), null);
  const request = { documents: ["n"] },
    response = [{ found: { name: "n", updateTime: "v" } }];
  assert.equal(transactionWireEvidence("BatchGetDocuments", request, response, 200).complete, true);
  for (const status of [0, 199, 302, 503])
    assert.equal(
      transactionWireEvidence("BatchGetDocuments", request, response, status).complete,
      false,
    );
  for (const malformed of [{}, [], { documents: null }, { documents: [] }])
    assert.equal(
      transactionWireEvidence("BatchGetDocuments", malformed, response, 200).complete,
      false,
    );
  const prefix = JSON.stringify(request);
  assert.equal(
    transactionWireEvidence(
      "BatchGetDocuments",
      prefix + " ".repeat(65536 - prefix.length),
      response,
      200,
    ).complete,
    true,
  );
  assert.equal(
    transactionWireEvidence(
      "BatchGetDocuments",
      prefix + " ".repeat(65537 - prefix.length),
      response,
      200,
    ).complete,
    false,
  );
});

test("transaction fetch waits for admission and refuses missing acknowledgment before payload", async () => {
  const calls = [];
  let acknowledge;
  const ledger = createWireLedger({ hosts: ["firestore.googleapis.com"], cap: 1 });
  const restore = installWireGuard(ledger, {
    beforeTransaction: async ({ method, request, record }) => {
      assert.equal(method, "BatchGetDocuments");
      assert.equal(record.bearer, null);
      assert.deepEqual(request.documents, ["fixture-document"]);
      await new Promise((resolve) => { acknowledge = resolve; });
      calls.push("ack");
    },
    fetchImpl: async (request) => {
      assert.equal(await request.clone().text(), JSON.stringify({ documents: ["fixture-document"] }));
      assert.equal(request.headers.get("authorization"), null);
      calls.push("payload"); return new Response("{}");
    },
  });
  try {
    const init = { method: "POST", headers: {}, body: JSON.stringify({ documents: ["fixture-document"] }) };
    const pending = fetch("https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents:batchGet", init);
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(calls, []);
    assert.equal(typeof acknowledge, "function");
    init.body = JSON.stringify({ documents: ["foreign-document"] });
    init.headers.authorization = "Bearer forbidden-after-ack";
    acknowledge();
    await pending;
    assert.deepEqual(calls, ["ack", "payload"]);
  } finally { restore(); }
  const refused = installWireGuard(createWireLedger({ hosts: ["firestore.googleapis.com"], cap: 1 }), {
    beforeTransaction: async () => { throw new Error("journal refused"); },
    fetchImpl: async () => { assert.fail("refused payload sent"); },
  });
  try {
    await assert.rejects(fetch("https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents:commit", { method: "POST", body: "{}" }), /journal refused/);
  } finally { refused(); }
});

test("HTTP2 transaction payload is buffered until decoded admission resolves", async () => {
  const { EventEmitter } = await import("node:events");
  const payload = [];
  const original = http2.connect;
  let acknowledge;
  const stream = new EventEmitter();
  stream.write = (chunk) => { payload.push(String(chunk)); return true; };
  stream.end = (chunk) => { if (chunk != null) payload.push(String(chunk)); payload.push("end"); return stream; };
  stream.destroy = (error) => stream.emit("error", error);
  stream.on("error", () => {});
  http2.connect = () => ({ request: () => stream });
  const restore = installWireGuard(createWireLedger({ hosts: ["firestore.googleapis.com"], cap: 1 }), {
    onTransaction: () => {},
    decodeGrpc: (_method, bytes) => ({ documents: [bytes.toString()] }),
    beforeTransaction: async ({ request }) => {
      assert.deepEqual(request, { documents: ["firstsecond"] });
      await new Promise((resolve) => { acknowledge = resolve; });
      payload.push("ack");
    },
  });
  try {
    const actual = http2.connect("https://firestore.googleapis.com").request({ ":path": "/google.firestore.v1.Firestore/BatchGetDocuments" });
    const first = Buffer.from("first"), second = Buffer.from("second");
    actual.write(first);
    actual.end(second);
    first.fill(0); second.fill(0);
    await Promise.resolve();
    assert.deepEqual(payload, []);
    acknowledge();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(payload, ["ack", "first", "second", "end"]);
  } finally { restore(); http2.connect = original; }
});

test("transaction operation opts into two attempts and preserves the default SDK call", async () => {
  const { createOperations } = await import("./auth-fs-cross/sdk-operations.mjs");
  const calls = [];
  const events = [];
  const run = createOperations({
    fb: {
      onIdTokenChanged: () => {},
      doc: (_db, path) => path,
      runTransaction: async (...args) => { calls.push(args); return args[1]({ set: () => {} }); },
    },
    auth: {}, db: {}, emit: (event) => events.push(event), onToken: () => {}, exit: () => {},
  });
  const command = { op: "transaction", name: "fixture", reads: [], write: { path: "fixture", data: {} }, pauseAttempts: 0 };
  await run({ ...command, maxAttempts: 2 });
  assert.deepEqual(calls[0][2], { maxAttempts: 2 });
  await run(command);
  assert.equal(calls[1].length, 2);
  for (const maxAttempts of [0, 1.5, 3, "2", null]) {
    await run({ ...command, maxAttempts });
    assert.equal(events.at(-1).ok, false);
  }
  assert.equal(calls.length, 2);
});

test("S5b admission binds exact transport names and awaits a correlated acknowledgment", async () => {
  const { createS5bAdmission } = await import("./auth-fs-cross/sdk-wire.mjs");
  const events = [];
  const nonce = "a".repeat(32), ownerId = "b".repeat(32);
  const admission = createS5bAdmission({ mode: "production", web: { projectId: "fireemu-oracle-query" }, wireCap: 1, connectionCap: 20, s5bAdmission: { authorized: true, nonce, ownerId, transport: "node", probe: true } }, (event) => events.push(event));
  const name = `projects/fireemu-oracle-query/databases/(default)/documents/conf_txn/s5b_${nonce}_node_probe`;
  let done = false;
  const pending = admission.beforeTransaction({ method: "BatchGetDocuments", request: { documents: [name], database: "projects/fireemu-oracle-query/databases/(default)" }, record: { n: 1, host: "firestore.googleapis.com", path: "/google.firestore.v1.Firestore/BatchGetDocuments", bearer: null } }).then(() => { done = true; });
  await Promise.resolve();
  assert.equal(done, false);
  assert.equal(events.length, 1);
  assert.equal(events[0].event, "transaction-dispatch");
  assert.equal(admission.accept({ op: "transactionAdmission", id: events[0].id, authorized: true }), true);
  await pending;
  assert.equal(done, true);
  assert.throws(() => admission.accept({ op: "transactionAdmission", id: events[0].id, authorized: true }), /unknown/);
  const cases = [
    { method: "Commit", request: { writes: [] } },
    { method: "BatchGetDocuments", request: { documents: [name.replace("node_probe", "browser_probe")] } },
    { method: "BatchGetDocuments", request: { documents: [name], transaction: "foreign" } },
    { method: "BatchGetDocuments", request: { documents: [name] }, record: { n: 2, host: "evil.example", bearer: null } },
  ];
  for (const change of cases) {
    await assert.rejects(admission.beforeTransaction({ method: "BatchGetDocuments", request: { documents: [name] }, record: { n: 2, host: "firestore.googleapis.com", bearer: null }, ...change }));
  }
  assert.equal(events.length, 1);
});

test("SDK client acknowledges dispatch only after the parent's durable callback", async () => {
  const { spawnSdk } = await import("./auth-fs-cross/sdk-client.mjs");
  const { PassThrough } = await import("node:stream");
  const { EventEmitter } = await import("node:events");
  const child = new EventEmitter();
  child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  const replies = [];
  child.stdin.on("data", (bytes) => replies.push(JSON.parse(bytes.toString())));
  let release;
  const client = spawnSdk({}, { spawnImpl: () => child, onTransactionAdmission: async (event) => {
    assert.equal(event.id, "s5b-1");
    await new Promise((resolve) => { release = resolve; });
    return true;
  } });
  child.stdout.write(JSON.stringify({ event: "transaction-dispatch", id: "s5b-1" }) + "\n");
  await Promise.resolve();
  assert.deepEqual(replies, []);
  release();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(replies, [{ op: "transactionAdmission", id: "s5b-1", authorized: true }]);
  child.emit("close", 0, null);
  await client.close();
  child.stdin.end(); child.stdout.end(); child.stderr.end();
});

test("S5b write admission refuses foreign ownership, missing version, and probe Commit", async () => {
  const { createS5bAdmission } = await import("./auth-fs-cross/sdk-wire.mjs");
  const nonce = "a".repeat(32), ownerId = "b".repeat(32);
  const config = { mode: "production", web: { projectId: "fireemu-oracle-query" }, wireCap: 6, connectionCap: 20, s5bAdmission: { authorized: true, nonce, ownerId, transport: "node", probe: false } };
  const name = `projects/fireemu-oracle-query/databases/(default)/documents/conf_txn/s5b_${nonce}_node_control`;
  const request = { writes: [{ update: { name, fields: { owner: { stringValue: ownerId }, nonce: { stringValue: nonce }, case: { stringValue: "control" }, value: { integerValue: "3" } } }, currentDocument: { updateTime: "2030-01-01T00:00:00Z" } }] };
  const row = { method: "Commit", request, record: { n: 1, host: "firestore.googleapis.com", path: "/google.firestore.v1.Firestore/Commit", bearer: null } };
  const changes = [
    (r) => { r.request.writes[0].update.name += "_other"; },
    (r) => { r.request.writes[0].update.fields.owner.stringValue = "c".repeat(32); },
    (r) => { r.request.writes[0].currentDocument = { exists: true }; },
    (r) => { r.request.writes[0].currentDocument.updateTime = null; },
    (r) => { r.request.writes[0].currentDocument.updateTime = ""; },
    (r) => { r.request.writes[0].update.fields.nonce.extra = "secret"; },
    (r) => { r.record.bearer = "forbidden"; },
    (r) => { r.request.transaction = "foreign"; },
  ];
  for (const change of changes) {
    const changed = structuredClone(row); change(changed);
    const observed = [];
    const admission = createS5bAdmission(config, (event) => {
      observed.push(event);
      queueMicrotask(() => admission.accept({ op: "transactionAdmission", id: event.id, authorized: false }));
    });
    await assert.rejects(admission.beforeTransaction(changed), /scope|ownership or version/);
    assert.deepEqual(observed, []);
    await assert.rejects(admission.beforeTransaction(row), /scope/);
  }
  const events = [];
  const admission = createS5bAdmission(config, (event) => events.push(event));
  const pending = admission.beforeTransaction(row);
  admission.accept({ op: "transactionAdmission", id: events[0].id, authorized: false });
  await assert.rejects(pending, /refused/);
  await assert.rejects(admission.beforeTransaction(row), /scope/);
  const probe = createS5bAdmission({ ...config, wireCap: 1, s5bAdmission: { ...config.s5bAdmission, probe: true } }, () => assert.fail("probe Commit journaled"));
  await assert.rejects(probe.beforeTransaction(row), /probe/);
});
