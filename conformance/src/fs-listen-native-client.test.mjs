import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";

import { FRAME_CAP, createNativeClient } from "./fs-listen/native-client.mjs";

const PROJECT = "fireemu-oracle-txn";
const ROOT = `projects/${PROJECT}/databases/(default)/documents`;
const name = (n) => `${ROOT}/lsn_native/r1-${n}`;

/**
 * A fake grpc.Client. `unary[method]` answers a unary call (a function of the request that
 * returns a response or throws); `serverStream[method]` returns the messages of a server-streaming
 * call (or an Error to fail it); `bidi` collects the Listen streams it handed out.
 */
function fakeGrpc({ unary = {}, serverStream = {} } = {}) {
  const calls = [];
  const bidi = [];
  return {
    calls,
    bidi,
    close: () => calls.push(["close"]),
    makeUnaryRequest(path, serialize, deserialize, request, metadata, options, callback) {
      const method = path.split("/").at(-1);
      calls.push([method, request, metadata, options]);
      setImmediate(() => {
        try {
          callback(null, unary[method](request));
        } catch (error) {
          callback(error);
        }
      });
    },
    makeServerStreamRequest(path, serialize, deserialize, request, metadata) {
      const method = path.split("/").at(-1);
      calls.push([method, request, metadata]);
      const stream = new EventEmitter();
      setImmediate(() => {
        const answer = serverStream[method](request);
        if (answer instanceof Error) return stream.emit("error", answer);
        for (const message of answer) stream.emit("data", message);
        return stream.emit("end");
      });
      return stream;
    },
    makeBidiStreamRequest(path, serialize, deserialize, metadata) {
      const stream = new EventEmitter();
      stream.written = [];
      stream.cancelled = false;
      stream.write = (request) => stream.written.push(request);
      stream.cancel = () => {
        stream.cancelled = true;
      };
      calls.push(["Listen", undefined, metadata]);
      bidi.push(stream);
      return stream;
    },
  };
}

const client = (grpcClient, extra = {}) =>
  createNativeClient({
    project: PROJECT,
    target: { kind: "production" },
    token: "TOKEN-1",
    grpcClient,
    ...extra,
  });

test("ListDocuments is paged until the token runs out, and only names with the prefix come back", async () => {
  const pages = [
    {
      documents: [{ name: name("a") }, { name: `${ROOT}/lsn_native/other-1` }],
      nextPageToken: "t2",
    },
    { documents: [{ name: name("b") }], nextPageToken: "t3" },
    { documents: [{ name: name("c") }], nextPageToken: "" },
  ];
  const seen = [];
  const grpcClient = fakeGrpc({
    unary: {
      ListDocuments: (request) => {
        seen.push(request.pageToken);
        return pages[seen.length - 1];
      },
    },
  });
  const ids = await client(grpcClient).listIds({
    parent: ROOT,
    collectionId: "lsn_native",
    prefix: "r1-",
  });
  assert.deepEqual(ids, [name("a"), name("b"), name("c")]);
  assert.deepEqual(seen, ["", "t2", "t3"]);
  const first = grpcClient.calls[0][1];
  assert.equal(first.parent, ROOT);
  assert.equal(first.collectionId, "lsn_native");
  assert.equal(first.showMissing, false);
});

test("an error on page 2 of a listing rejects the whole listing, not a short list", async () => {
  let page = 0;
  const grpcClient = fakeGrpc({
    unary: {
      ListDocuments: () => {
        page += 1;
        if (page === 2) throw Object.assign(new Error("unavailable"), { code: 14 });
        return { documents: [{ name: name("a") }], nextPageToken: "t2" };
      },
    },
  });
  await assert.rejects(
    client(grpcClient).listIds({ parent: ROOT, collectionId: "lsn_native", prefix: "" }),
    (error) => error.code === 14,
  );
});

test("an empty prefix lists every document of the collection", async () => {
  const grpcClient = fakeGrpc({
    unary: {
      ListDocuments: () => ({ documents: [{ name: name("a") }, { name: `${ROOT}/lsn_native/z` }] }),
    },
  });
  assert.deepEqual(
    await client(grpcClient).listIds({ parent: ROOT, collectionId: "lsn_native", prefix: "" }),
    [name("a"), `${ROOT}/lsn_native/z`],
  );
});

test("a read-back of 101 names goes in two BatchGetDocuments calls of 100 and 1, in order", async () => {
  const names = Array.from({ length: 101 }, (_, i) => name(String(i)));
  const grpcClient = fakeGrpc({
    serverStream: {
      BatchGetDocuments: (request) =>
        request.documents.map((n, i) => (i % 2 ? { missing: n } : { found: { name: n } })),
    },
  });
  const out = await client(grpcClient).missing(names);
  const batches = grpcClient.calls.filter(([method]) => method === "BatchGetDocuments");
  assert.deepEqual(
    batches.map(([, request]) => request.documents.length),
    [100, 1],
  );
  assert.equal(out.length, 101);
  assert.deepEqual(
    out.map((e) => e.name),
    names,
  );
  assert.equal(out[0].exists, true);
  assert.equal(out[1].exists, false);
  assert.equal(out[100].exists, true);
  // Exactly 100 is one call, and none is no call.
  const exact = fakeGrpc({
    serverStream: { BatchGetDocuments: (r) => r.documents.map((n) => ({ missing: n })) },
  });
  await client(exact).missing(names.slice(0, 100));
  assert.equal(exact.calls.filter(([m]) => m === "BatchGetDocuments").length, 1);
  const none = fakeGrpc();
  assert.deepEqual(await client(none).missing([]), []);
  assert.equal(none.calls.length, 0);
});

test("a BatchGet answer that omits a requested name, or fails, rejects instead of reading as absent", async () => {
  const omits = fakeGrpc({ serverStream: { BatchGetDocuments: () => [{ missing: name("0") }] } });
  await assert.rejects(client(omits).missing([name("0"), name("1")]), /did not mention/);
  const fails = fakeGrpc({
    serverStream: { BatchGetDocuments: () => Object.assign(new Error("x"), { code: 14 }) },
  });
  await assert.rejects(client(fails).missing([name("0")]), (error) => error.code === 14);
});

test("every RPC is counted when it starts: unary, server-streaming and Listen", async () => {
  const grpcClient = fakeGrpc({
    unary: { Commit: () => ({}), BeginTransaction: () => ({ transaction: Buffer.from("t") }) },
    serverStream: { BatchGetDocuments: (r) => r.documents.map((n) => ({ missing: n })) },
  });
  const c = client(grpcClient);
  assert.equal(c.requestCount(), 0);
  await c.commit({ writes: [] });
  await c.beginTransaction();
  await c.missing([name("a")]);
  c.openStream();
  assert.equal(c.requestCount(), 4);
  // A refused call still counted.
  const refusing = fakeGrpc({
    unary: {
      Commit: () => {
        throw new Error("no");
      },
    },
  });
  const r = client(refusing);
  await assert.rejects(r.commit({ writes: [] }));
  assert.equal(r.requestCount(), 1);
});

test("production calls carry the bearer, the routing headers and the quota project; local carries the owner", async () => {
  const grpcClient = fakeGrpc({ unary: { Commit: () => ({}) } });
  const c = client(grpcClient);
  await c.commit({ writes: [] });
  const meta = grpcClient.calls[0][2];
  assert.deepEqual(meta.get("authorization"), ["Bearer TOKEN-1"]);
  assert.deepEqual(meta.get("x-goog-user-project"), [PROJECT]);
  assert.deepEqual(meta.get("google-cloud-resource-prefix"), [
    `projects/${PROJECT}/databases/(default)`,
  ]);
  assert.equal(grpcClient.calls[0][3].deadline instanceof Date, true);
  const local = fakeGrpc({ unary: { Commit: () => ({}) } });
  await createNativeClient({
    project: "demo",
    target: { kind: "local", host: "h", port: 1 },
    grpcClient: local,
  }).commit({ writes: [] });
  assert.deepEqual(local.calls[0][2].get("authorization"), ["Bearer owner"]);
  assert.deepEqual(local.calls[0][2].get("x-goog-user-project"), []);
});

test("refresh swaps the bearer for later calls, and a client without a refresher keeps its token", async () => {
  const grpcClient = fakeGrpc({ unary: { Commit: () => ({}) } });
  const c = client(grpcClient, { refreshToken: async () => "TOKEN-2" });
  await c.commit({ writes: [] });
  await c.refresh();
  await c.commit({ writes: [] });
  assert.deepEqual(grpcClient.calls[0][2].get("authorization"), ["Bearer TOKEN-1"]);
  assert.deepEqual(grpcClient.calls[1][2].get("authorization"), ["Bearer TOKEN-2"]);
  const plain = fakeGrpc({ unary: { Commit: () => ({}) } });
  const p = client(plain);
  await p.refresh();
  await p.commit({ writes: [] });
  assert.deepEqual(plain.calls[0][2].get("authorization"), ["Bearer TOKEN-1"]);
});

const frame = { responseType: "targetChange", targetChange: { targetChangeType: "NO_CHANGE" } };

test("a Listen stream records its frames; a status of OK is 'ended' with code 0", async () => {
  const grpcClient = fakeGrpc();
  const stream = client(grpcClient).openStream();
  const raw = grpcClient.bidi[0];
  raw.emit("data", frame);
  raw.emit("status", { code: 0, details: "" });
  raw.emit("end");
  assert.equal(stream.frames.length, 1);
  assert.equal(stream.frames[0].kind, "targetChange");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual({ ...stream.ended(), at: 0 }, { at: 0, reason: "ended", code: 0 });
});

test("a stream that ends with no status is 'ended-without-status', never an OK status (S3)", async () => {
  const grpcClient = fakeGrpc();
  const stream = client(grpcClient).openStream();
  grpcClient.bidi[0].emit("end");
  await new Promise((resolve) => setImmediate(resolve));
  const end = stream.ended();
  assert.equal(end.reason, "ended-without-status");
  assert.equal(end.code, null);
});

test("a status that arrives right before the end decides, and the end after it changes nothing", async () => {
  const grpcClient = fakeGrpc();
  const stream = client(grpcClient).openStream();
  const raw = grpcClient.bidi[0];
  raw.emit("status", { code: 7, details: "denied" });
  raw.emit("end");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(stream.ended().reason, "error");
  assert.equal(stream.ended().code, 7);
  assert.equal(stream.ended().details, "denied");
});

test("a stream error is recorded with its code and details, once", async () => {
  const grpcClient = fakeGrpc();
  const stream = client(grpcClient).openStream();
  const raw = grpcClient.bidi[0];
  raw.emit("error", Object.assign(new Error("e"), { code: 3, details: "bad target" }));
  raw.emit("status", { code: 3, details: "again" });
  assert.deepEqual(
    { ...stream.ended(), at: 0 },
    { at: 0, reason: "error", code: 3, details: "bad target" },
  );
});

test("a stream past the frame cap is closed as frame-cap and cancelled", () => {
  const grpcClient = fakeGrpc();
  const stream = client(grpcClient).openStream();
  const raw = grpcClient.bidi[0];
  for (let i = 0; i < FRAME_CAP; i += 1) raw.emit("data", frame);
  assert.equal(stream.frames.length, FRAME_CAP);
  assert.equal(stream.ended(), undefined);
  raw.emit("data", frame);
  assert.equal(stream.frames.length, FRAME_CAP, "the frame past the cap is not kept");
  assert.equal(stream.ended().reason, "frame-cap");
  assert.equal(raw.cancelled, true);
});

test("close ends an open stream as closed-by-harness once and cancels it; a finished one is left alone", async () => {
  const grpcClient = fakeGrpc();
  const open = client(grpcClient).openStream();
  open.send({ addTarget: 1 });
  assert.deepEqual(grpcClient.bidi[0].written, [{ addTarget: 1 }]);
  const end = await open.close();
  assert.equal(end.reason, "closed-by-harness");
  assert.equal(grpcClient.bidi[0].cancelled, true);
  const done = fakeGrpc();
  const finished = client(done).openStream();
  done.bidi[0].emit("status", { code: 0, details: "" });
  await finished.close();
  assert.equal(done.bidi[0].cancelled, false);
  assert.equal(finished.ended().reason, "ended");
});

test("close closes the gRPC client", () => {
  const grpcClient = fakeGrpc();
  client(grpcClient).close();
  assert.deepEqual(grpcClient.calls, [["close"]]);
});
