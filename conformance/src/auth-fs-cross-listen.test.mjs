import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";

import { describeFrame, listenTarget, openListen } from "./auth-fs-cross/listen-grpc.mjs";

/** A fake grpc.Client whose one bidi stream the test drives. */
function fakeClient() {
  const stream = new EventEmitter();
  stream.written = [];
  stream.write = (message) => stream.written.push(message);
  stream.cancelled = false;
  stream.cancel = () => {
    stream.cancelled = true;
  };
  const client = {
    calls: [],
    makeBidiStreamRequest(path, serialize, deserialize, metadata, options) {
      client.calls.push({ path, metadata, options });
      return stream;
    },
  };
  return { client, stream };
}

const protos = { google: { firestore: { v1: { ListenRequest: {}, ListenResponse: {} } } } };

test("a listen target names one document or one query", () => {
  assert.deepEqual(listenTarget(1, { document: "projects/p/databases/(default)/documents/c/d" }), {
    targetId: 1,
    documents: { documents: ["projects/p/databases/(default)/documents/c/d"] },
  });
  assert.deepEqual(listenTarget(2, { query: { from: [{ collectionId: "c" }] }, parent: "x" }), {
    targetId: 2,
    query: { parent: "x", structuredQuery: { from: [{ collectionId: "c" }] } },
  });
  assert.throws(() => listenTarget(3, {}), /document or a query/);
});

test("a stream adds its targets, records frames with times, and ends once", async () => {
  const { client, stream } = fakeClient();
  let clock = 1000;
  const listen = openListen({
    client,
    protos,
    database: "projects/p/databases/(default)",
    targets: [listenTarget(1, { document: "d" })],
    metadata: { m: 1 },
    now: () => clock,
  });
  assert.equal(client.calls[0].path, "/google.firestore.v1.Firestore/Listen");
  assert.deepEqual(stream.written, [
    {
      database: "projects/p/databases/(default)",
      addTarget: { targetId: 1, documents: { documents: ["d"] } },
    },
  ]);
  clock = 1250;
  stream.emit("data", {
    responseType: "targetChange",
    targetChange: { targetChangeType: "ADD", targetIds: [1] },
  });
  const mark = listen.frames.length;
  clock = 1600;
  stream.emit("data", {
    responseType: "targetChange",
    targetChange: { targetChangeType: "REMOVE", cause: { code: 7 } },
  });
  assert.deepEqual(
    listen.since(mark).map(({ at, kind }) => [at, kind]),
    [[600, "targetChange"]],
  );
  clock = 1700;
  stream.emit("error", { code: 7, details: "Missing or insufficient permissions." });
  stream.emit("status", { code: 0 });
  assert.deepEqual(await listen.closed, {
    at: 700,
    reason: "error",
    code: 7,
    details: "Missing or insufficient permissions.",
  });
  assert.deepEqual(listen.ended(), await listen.closed);
});

test("a clean end, a harness close and the frame cap are told apart", async () => {
  const ended = fakeClient();
  const a = openListen({
    client: ended.client,
    protos,
    database: "db",
    targets: [],
    metadata: {},
    now: () => 0,
  });
  ended.stream.emit("status", { code: 0 });
  assert.equal((await a.closed).reason, "ended");

  const closed = fakeClient();
  const b = openListen({
    client: closed.client,
    protos,
    database: "db",
    targets: [],
    metadata: {},
    now: () => 0,
  });
  assert.equal((await b.close()).reason, "closed-by-harness");
  assert.equal(closed.stream.cancelled, true);

  const capped = fakeClient();
  const c = openListen({
    client: capped.client,
    protos,
    database: "db",
    targets: [],
    metadata: {},
    now: () => 0,
    cap: 2,
  });
  for (let i = 0; i < 3; i += 1)
    capped.stream.emit("data", { responseType: "filter", filter: { count: i } });
  assert.equal(c.frames.length, 2);
  assert.equal((await c.closed).reason, "frame-cap");
  assert.equal(capped.stream.cancelled, true);
});

test("frames are plain JSON with bytes as base64", () => {
  const frame = {
    responseType: "targetChange",
    targetChange: { resumeToken: Buffer.from([1, 2, 3]) },
  };
  assert.deepEqual(describeFrame(frame), {
    kind: "targetChange",
    responseType: "targetChange",
    targetChange: { resumeToken: "AQID" },
  });
});
