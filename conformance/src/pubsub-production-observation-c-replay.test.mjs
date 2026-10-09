import test from "node:test";
import assert from "node:assert/strict";
import { makePlan, PROJECT, SUITE } from "./pubsub-observation-c/plan.mjs";
import { importRecording, replayRecording } from "./pubsub-observation-c/replay-core.mjs";
import { createWire } from "./pubsub-observation-c/wire.mjs";
import { createMeter } from "./pubsub-observation-c/meter.mjs";
import { createServer } from "node:http";
import { replayLocal } from "./pubsub-observation-c/replay.mjs";
import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";

const runId = "0123456789ab",
  head = "a".repeat(40),
  packetSha256 = "b".repeat(64),
  descriptorSha256 = "c".repeat(64);
const time = "2026-10-09T00:00:00.000Z";
function fixture() {
  const packet = {
    sourceHead: head,
    descriptorSha256,
    runIds: [runId, "abcdef012345"],
    plan: makePlan(),
  };
  const metadata = {
    event: "run-start",
    n: 1,
    at: time,
    runId,
    sourceHead: head,
    suite: SUITE,
    project: PROJECT,
    envelopeId: "PUBSUB-OBSERVATION-C-TEST",
    packetSha256,
    descriptorSha256,
  };
  const rows = [metadata],
    results = [];
  for (const cell of packet.plan.cells.filter((c) => !c.reserve)) {
    const result = {
      event: "case-result",
      cellId: cell.id,
      complete: true,
      cleanupClosed: true,
      observations: [],
    };
    rows.push({ ...result, n: rows.length + 1, at: time });
    results.push(result);
  }
  return {
    packet,
    descriptor: { head, suite: SUITE },
    summary: { ...metadata, results, recordingComplete: true, resourcesClosed: true },
    rows,
    issued: [],
    packetSha256,
    descriptorSha256,
  };
}
function exchange(input, cellId, method, request, reply, requestId) {
  const at = time,
    n = input.rows.length + 1;
  input.rows.splice(
    input.rows.findIndex((r) => r.cellId === cellId && r.event === "case-result"),
    0,
    {
      event: "request-dispatch",
      n,
      at,
      cellId,
      requestId,
      method,
      request,
      category: method === "Publish" ? "publish" : method === "Pull" ? "pull" : "ackControl",
      transport: cellId.startsWith("R") ? "rest" : "grpc",
    },
    {
      event: "response",
      n: n + 1,
      at,
      cellId,
      requestId,
      method,
      transport: cellId.startsWith("R") ? "rest" : "grpc",
      reply,
    },
  );
  input.rows.forEach((r, i) => (r.n = i + 1));
}
const reply = (body) => ({
  ok: true,
  code: "OK",
  status: 200,
  unknown: false,
  body,
  bodyBytes: 2,
  bodySha256: "d".repeat(64),
});
const topic = (cell) => `projects/${PROJECT}/topics/fe${runId}-${cell.toLowerCase()}-t`;
const sub = (cell) => `projects/${PROJECT}/subscriptions/fe${runId}-${cell.toLowerCase()}-s`;
function deliveries() {
  const f = fixture();
  exchange(
    f,
    "R1",
    "Publish",
    { topic: topic("R1"), messages: [{ data: "eA==" }] },
    reply({ messageIds: ["123"] }),
    1,
  );
  exchange(
    f,
    "R1",
    "Pull",
    { subscription: sub("R1"), maxMessages: 1 },
    reply({
      receivedMessages: [
        { ackId: "source-token", message: { messageId: "123", data: "eA==", publishTime: time } },
      ],
    }),
    2,
  );
  exchange(
    f,
    "R1",
    "Acknowledge",
    { subscription: sub("R1"), ackIds: ["source-token"] },
    reply({}),
    3,
  );
  return f;
}
function local(source) {
  const r = structuredClone(source.reply);
  if (source.method === "Publish") r.body.messageIds = ["456"];
  if (source.method === "Pull") {
    r.body.receivedMessages[0].ackId = "local-token!";
    r.body.receivedMessages[0].message.messageId = "456";
  }
  return r;
}
test("C accepts only the original 26 active cells and inactive reserves", () => {
  assert.equal(importRecording(fixture()).cells.length, 26);
  for (const alter of [
    (f) => f.packet.plan.cells.pop(),
    (f) =>
      f.rows.push({
        event: "case-result",
        cellId: "R1F",
        n: 100,
        at: time,
        complete: true,
        cleanupClosed: true,
      }),
    (f) => f.summary.results.pop(),
    (f) => (f.rows[0].suite = "pubsub-observation-a-v1"),
    (f) => (f.rows[0].sourceHead = "e".repeat(40)),
  ]) {
    const f = fixture();
    alter(f);
    assert.throws(() => importRecording(f));
  }
});
test("C maps actual publication and received ACK identity without copying source tokens", async () => {
  const input = importRecording(deliveries());
  const sent = [],
    before = structuredClone(input);
  const result = await replayRecording(input, async (call, source) => {
    sent.push(call);
    return local(source);
  });
  assert.equal(result.cells[0].semanticVerdict, "MATCH");
  assert.deepEqual(sent.find((c) => c.method === "Acknowledge").request.ackIds, ["local-token!"]);
  assert.deepEqual(input, before);
});
const pin = {
  profile: "release",
  rustcWrapper: "",
  sha256: "a".repeat(64),
  head: "b".repeat(40),
  command: ["cargo", "build", "--release"],
  path: "/p/release/fireemu",
};
test("explicit admitted local C REST transport omits credentials and captures real body bytes", async () => {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push({
      url: req.url,
      authorization: req.headers.authorization,
      quota: req.headers["x-goog-user-project"],
    });
    res.setHeader("content-type", "application/json");
    res.end('{"name":"own"}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const host = `127.0.0.1:${server.address().port}`;
  const meter = createMeter();
  meter.enter(makePlan().cells[0]);
  const wire = createWire({
    meter,
    journal: { write() {} },
    localRuntime: {
      pin,
      environment: {
        PUBSUB_EMULATOR_HOST: host,
        FIREEMU_CONTROL_URL: `http://${host}/v1/`,
        FIREEMU_CONTROL_TOKEN: "test",
      },
      clock: () => 0,
    },
  });
  try {
    const r = await wire.call({
      cellId: "R1",
      category: "get",
      transport: "rest",
      service: "Publisher",
      method: "GetTopic",
      request: { name: topic("R1") },
    });
    assert.equal(r.ok, true);
    assert.equal(r.bodyBytes, 14);
    assert.equal(seen[0].authorization, undefined);
    assert.equal(seen[0].quota, undefined);
    assert.equal(seen[0].url, `/v1/${topic("R1")}`);
  } finally {
    wire.close();
    await new Promise((resolve) => server.close(resolve));
  }
});
test("C local transport admission refuses nonloopback before credential or request", () => {
  const meter = createMeter();
  meter.enter(makePlan().cells[0]);
  assert.throws(() =>
    createWire({
      meter,
      journal: { write() {} },
      localRuntime: {
        pin,
        environment: {
          PUBSUB_EMULATOR_HOST: "pubsub.googleapis.com:443",
          FIREEMU_CONTROL_URL: "http://127.0.0.1:1234/v1/",
          FIREEMU_CONTROL_TOKEN: "test",
        },
        clock: () => 0,
      },
    }),
  );
});
test("actual clock readback is awaited and wrong instant stops the cell before publication", async () => {
  const environment = {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:1235/v1/",
    FIREEMU_CONTROL_TOKEN: "test",
  };
  const sent = [];
  const report = await replayLocal(importRecording(deliveries()), environment, pin, {
    fetch: async () =>
      new Response(JSON.stringify({ clock: "2026-10-09T00:00:00.001Z" }), { status: 200 }),
    wireFactory: () => ({
      close() {},
      abortSource() {},
      call: async (c) => {
        sent.push(c);
        return reply({});
      },
    }),
  });
  assert.equal(report.cells[0].semanticVerdict, "NOT_COMPARABLE");
  assert.equal(sent.length, 0);
});
test("C native unary captures actual successful protobuf and keeps exact error details without fabricated raw error", async () => {
  const server = new grpc.Server();
  const topicType = protos.google.pubsub.v1.Topic;
  server.addService(
    {
      getTopic: {
        path: "/google.pubsub.v1.Publisher/GetTopic",
        requestStream: false,
        responseStream: false,
        requestSerialize: (v) => v,
        requestDeserialize: (v) => v,
        responseSerialize: (v) => v,
        responseDeserialize: (v) => v,
      },
    },
    {
      getTopic(call, callback) {
        if (call.request.length === 0)
          callback({ code: grpc.status.INVALID_ARGUMENT, details: "exact failure" });
        else callback(null, Buffer.from(topicType.encode({ name: "own" }).finish()));
      },
    },
  );
  const port = await new Promise((resolve, reject) =>
    server.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (e, p) =>
      e ? reject(e) : resolve(p),
    ),
  );
  server.start();
  const meter = createMeter();
  meter.enter(makePlan().cells.find((c) => c.id === "N1"));
  const raw = [];
  const wire = createWire({
    meter,
    journal: { write() {} },
    localRuntime: {
      pin,
      environment: {
        PUBSUB_EMULATOR_HOST: `127.0.0.1:${port}`,
        FIREEMU_CONTROL_URL: `http://127.0.0.1:${port}/v1/`,
        FIREEMU_CONTROL_TOKEN: "test",
      },
      clock: () => 0,
      captureBody: (_, __, bytes) => raw.push(bytes),
    },
  });
  try {
    const actual = await wire.call({
      cellId: "N1",
      category: "get",
      transport: "grpc",
      service: "Publisher",
      method: "GetTopic",
      request: { name: topic("N1") },
    });
    assert.equal(actual.ok, true);
    assert.equal(actual.body.name, "own");
    assert.equal(actual.bodyBytes, raw[0].length);
    assert.equal(actual.bodySha256.length, 64);
  } finally {
    wire.close();
    await new Promise((resolve) => server.tryShutdown(resolve));
  }
});
test("C intentional pending cancellation uses its actual transport origin and real 1s observer", async () => {
  const server = createServer((req, res) => {
    if (req.url.endsWith(":pull")) {
      req.on("close", () => res.destroy());
    } else res.end("{}");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const host = `127.0.0.1:${server.address().port}`;
  const meter = createMeter();
  meter.enter(makePlan().cells.find((c) => c.id === "R3"));
  let logical = 0;
  const events = [];
  const wire = createWire({
    meter,
    journal: { write: (r) => events.push(r) },
    localRuntime: {
      pin,
      environment: {
        PUBSUB_EMULATOR_HOST: host,
        FIREEMU_CONTROL_URL: `http://${host}/v1/`,
        FIREEMU_CONTROL_TOKEN: "test",
      },
      clock: () => logical,
    },
  });
  const call = {
    cellId: "R3",
    category: "pull",
    transport: "rest",
    service: "Subscriber",
    method: "Pull",
    request: { subscription: sub("R3"), maxMessages: 1, returnImmediately: false },
    cancelObservation: true,
    cancelBinding: {
      outstandingMessageId: "123",
      outstandingAckId: "one",
      ackedControlMessageId: "456",
      ackedControlAckId: "two",
      deliveredAt: 0,
    },
  };
  const started = performance.now();
  try {
    const result = await wire.call(call);
    assert.equal(result.clientCancellation.cause, "intentional-unary-cancel");
    assert.equal(result.clientCancellation.transportAction, "AbortController.abort");
    assert.equal(result.clientCancellation.pending, true);
    assert.ok(performance.now() - started >= 900);
    assert.equal(events.filter((r) => r.event === "client-cancel").length, 1);
    await assert.rejects(
      wire.call({ ...call, cancelObservation: undefined, cancelBinding: undefined }),
    );
    logical = 61000;
    const cleanup = await wire.call({
      cellId: "R3",
      category: "cleanupDelete",
      transport: "rest",
      service: "Subscriber",
      method: "DeleteSubscription",
      request: { name: sub("R3") },
    });
    assert.equal(cleanup.ok, true);
  } finally {
    wire.close();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
test("missing or foreign local delivery stays NOT_COMPARABLE before ACK", async () => {
  for (const change of [
    (r) => (r.body.receivedMessages = []),
    (r) => (r.body.receivedMessages[0].message.data = "foreign"),
    (r) => (r.body.receivedMessages[0].message.messageId = "999"),
  ]) {
    const sent = [];
    const result = await replayRecording(importRecording(deliveries()), async (call, source) => {
      sent.push(call);
      const r = local(source);
      if (call.method === "Pull") change(r);
      return r;
    });
    assert.equal(result.cells[0].semanticVerdict, "NOT_COMPARABLE");
    assert.equal(
      sent.some((c) => c.method === "Acknowledge"),
      false,
    );
  }
});
test("unapproved timestamp, field presence, error details and physical layout remain strict", async () => {
  const result = await replayRecording(importRecording(deliveries()), async (call, source) => {
    const r = local(source);
    if (call.method === "Pull")
      r.body.receivedMessages[0].message.publishTime = "2026-10-09T00:00:00.001Z";
    return r;
  });
  assert.equal(result.cells[0].semanticVerdict, "DIVERGES");
});
test("native errors without recorded raw body never become physical MATCH", async () => {
  const f = fixture();
  exchange(
    f,
    "N11",
    "Seek",
    { subscription: sub("N11"), snapshot: `projects/${PROJECT}/snapshots/fe${runId}-n11-snap` },
    {
      ok: false,
      code: "INVALID_ARGUMENT",
      unknown: false,
      body: { error: { status: "INVALID_ARGUMENT", message: "wrong topic" } },
      bodyBytes: null,
      layoutVerdict: "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED",
    },
    1,
  );
  const result = await replayRecording(importRecording(f), async (_, source) =>
    structuredClone(source.reply),
  );
  assert.equal(result.cells.find((c) => c.id === "N11").physicalVerdict, "NOT_COMPARABLE");
});
test("C preserves the production default header contract with explicit offline transport stubs", async () => {
  const calls = [];
  const meter = createMeter();
  meter.enter(makePlan().cells[0]);
  const wire = createWire({
    meter,
    journal: { write() {} },
    client: { close() {} },
    getToken: async () => "offline-proof",
    fetch: async (url, options) => {
      calls.push({ url, options });
      return new Response("{}", { status: 200 });
    },
  });
  try {
    await wire.call({
      cellId: "R1",
      category: "get",
      transport: "rest",
      service: "Publisher",
      method: "GetTopic",
      request: { name: topic("R1") },
    });
    assert.equal(calls[0].url, `https://pubsub.googleapis.com/v1/${topic("R1")}`);
    assert.equal(calls[0].options.headers.authorization, "Bearer offline-proof");
    assert.equal(calls[0].options.headers["x-goog-user-project"], PROJECT);
  } finally {
    wire.close();
  }
});
test("source dispatch/cell and ACK selector proof cannot migrate between cells", async () => {
  const f = deliveries();
  const foreign = structuredClone(f);
  foreign.rows.find((r) => r.event === "response").cellId = "R2";
  assert.throws(() => importRecording(foreign));
  const missing = structuredClone(f);
  missing.rows.find(
    (r) => r.method === "Acknowledge" && r.event === "request-dispatch",
  ).request.ackIds = ["unseen"];
  const result = await replayRecording(importRecording(missing), async (_, source) =>
    local(source),
  );
  assert.equal(result.cells[0].semanticVerdict, "NOT_COMPARABLE");
});
test("delivery order, JSON presence and exact native error message are strict", async () => {
  for (const alter of [
    (r) => delete r.body.receivedMessages[0].message.publishTime,
    (r) => (r.body.extra = true),
  ]) {
    const result = await replayRecording(importRecording(deliveries()), async (call, source) => {
      const r = local(source);
      if (call.method === "Pull") alter(r);
      return r;
    });
    assert.equal(result.cells[0].semanticVerdict, "DIVERGES");
  }
  const f = fixture();
  exchange(
    f,
    "N11",
    "Seek",
    { subscription: sub("N11"), snapshot: `projects/${PROJECT}/snapshots/fe${runId}-n11-snap` },
    {
      ok: false,
      code: "INVALID_ARGUMENT",
      unknown: false,
      body: { error: { status: "INVALID_ARGUMENT", message: "wrong topic" } },
      bodyBytes: null,
    },
    1,
  );
  const result = await replayRecording(importRecording(f), async (_, source) => ({
    ...source.reply,
    body: { error: { status: "INVALID_ARGUMENT", message: "other details" } },
  }));
  assert.equal(result.cells.find((c) => c.id === "N11").semanticVerdict, "DIVERGES");
});
function cancelledFixture() {
  const f = fixture(),
    s = sub("R3");
  exchange(
    f,
    "R3",
    "Publish",
    { topic: topic("R3"), messages: [{ data: "eA==" }, { data: "eQ==" }] },
    reply({ messageIds: ["123", "124"] }),
    1,
  );
  exchange(
    f,
    "R3",
    "Pull",
    { subscription: s, maxMessages: 2 },
    reply({
      receivedMessages: [
        { ackId: "a", message: { messageId: "123", data: "eA==", publishTime: time } },
        { ackId: "b", message: { messageId: "124", data: "eQ==", publishTime: time } },
      ],
    }),
    2,
  );
  exchange(f, "R3", "Acknowledge", { subscription: s, ackIds: ["b"] }, reply({}), 3);
  exchange(
    f,
    "R3",
    "Pull",
    { subscription: s, maxMessages: 1, returnImmediately: false },
    { ok: false, code: "UNKNOWN", unknown: true, body: {} },
    4,
  );
  const i = f.rows.findIndex((r) => r.event === "response" && r.requestId === 4);
  f.rows.splice(i, 0, {
    event: "client-cancel",
    at: time,
    cellId: "R3",
    requestId: 4,
    transport: "rest",
    method: "Pull",
    subscription: s,
    cause: "intentional-unary-cancel",
    pending: true,
    lastObservedUnacked: { messageId: "123", ackId: "a" },
    acknowledgedControl: { messageId: "124", ackId: "b" },
  });
  f.rows.forEach((r, n) => (r.n = n + 1));
  return f;
}
test("cancel correlation requires distinct delivered outstanding and actually ACKed control; early normal completion fails closed", async () => {
  async function run(alter) {
    return replayRecording(importRecording(cancelledFixture()), async (call, _source) => {
      if (call.method === "Publish") return reply({ messageIds: ["456", "457"] });
      if (call.method === "Pull" && !call.cancelObservation)
        return reply({
          receivedMessages: [
            { ackId: "local-a", message: { messageId: "456", data: "eA==", publishTime: time } },
            { ackId: "local-b", message: { messageId: "457", data: "eQ==", publishTime: time } },
          ],
        });
      if (call.cancelObservation) {
        const r = {
          ok: false,
          code: "UNKNOWN",
          unknown: true,
          body: {},
          clientCancellation: {
            cellId: call.cellId,
            subscription: call.request.subscription,
            transport: call.transport,
            cause: "intentional-unary-cancel",
            pending: true,
            lastObservedUnacked: { messageId: call.cancelBinding.outstandingMessageId },
            acknowledgedControl: { messageId: call.cancelBinding.ackedControlMessageId },
          },
        };
        alter?.(r);
        return r;
      }
      return reply({});
    });
  }
  assert.equal((await run()).cells.find((c) => c.id === "R3").semanticVerdict, "MATCH");
  for (const alter of [
    (r) => delete r.clientCancellation,
    (r) => (r.clientCancellation.pending = false),
    (r) => (r.clientCancellation.cellId = "R2"),
    (r) => (r.clientCancellation.acknowledgedControl.messageId = "foreign"),
  ]) {
    assert.equal(
      (await run(alter)).cells.find((c) => c.id === "R3").semanticVerdict,
      "NOT_COMPARABLE",
    );
  }
});
test("two own deliveries remain in recorded order", async () => {
  const f = fixture();
  exchange(
    f,
    "N9",
    "Publish",
    {
      topic: topic("N9"),
      messages: [
        { data: "eA==", orderingKey: "A" },
        { data: "eQ==", orderingKey: "B" },
      ],
    },
    reply({ messageIds: ["123", "124"] }),
    1,
  );
  exchange(
    f,
    "N9",
    "Pull",
    { subscription: sub("N9"), maxMessages: 2 },
    reply({
      receivedMessages: [
        {
          ackId: "a",
          message: { messageId: "123", data: "eA==", orderingKey: "A", publishTime: time },
        },
        {
          ackId: "b",
          message: { messageId: "124", data: "eQ==", orderingKey: "B", publishTime: time },
        },
      ],
    }),
    2,
  );
  const run = (reverse) =>
    replayRecording(importRecording(structuredClone(f)), async (call, source) => {
      const r = structuredClone(source.reply);
      if (call.method === "Publish") r.body.messageIds = ["456", "457"];
      if (call.method === "Pull") {
        r.body.receivedMessages.forEach((m, i) => {
          m.message.messageId = ["456", "457"][i];
          m.ackId = `local${i}`;
        });
        if (reverse) r.body.receivedMessages.reverse();
      }
      return r;
    });
  assert.equal((await run(false)).cells.find((c) => c.id === "N9").semanticVerdict, "MATCH");
  assert.equal((await run(true)).cells.find((c) => c.id === "N9").semanticVerdict, "DIVERGES");
});
test("cell remaining bounds an unresolved local operation and closes its client", async () => {
  let ticks = 0,
    closed = false;
  const environment = {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:1235/v1/",
    FIREEMU_CONTROL_TOKEN: "test",
  };
  const report = await replayLocal(importRecording(deliveries()), environment, pin, {
    now: () => ticks,
    fetch: async () => {
      ticks = 139990;
      return new Response(JSON.stringify({ clock: time }), { status: 200 });
    },
    wireFactory: () => ({
      close() {
        closed = true;
      },
      abortSource() {},
      call: () => new Promise(() => {}),
    }),
  });
  assert.equal(report.cells[0].semanticVerdict, "NOT_COMPARABLE");
  assert.match(report.cells[0].exchanges[0].reason, /time exhausted/);
  assert.equal(closed, true);
});
test("snapshot ACK split, original Seek selector and actual post-Seek membership remain connected", async () => {
  const f = fixture(),
    s = sub("R12"),
    snapshot = `projects/${PROJECT}/snapshots/fe${runId}-r12-snap`;
  exchange(
    f,
    "R12",
    "Publish",
    { topic: topic("R12"), messages: [{ data: "eA==" }, { data: "eQ==" }] },
    reply({ messageIds: ["123", "124"] }),
    1,
  );
  const first = { ackId: "a", message: { messageId: "123", data: "eA==", publishTime: time } },
    second = { ackId: "b", message: { messageId: "124", data: "eQ==", publishTime: time } };
  exchange(
    f,
    "R12",
    "Pull",
    { subscription: s, maxMessages: 2 },
    reply({ receivedMessages: [first, second] }),
    2,
  );
  exchange(f, "R12", "Acknowledge", { subscription: s, ackIds: ["a"] }, reply({}), 3);
  exchange(
    f,
    "R12",
    "CreateSnapshot",
    { name: snapshot, subscription: s },
    reply({ name: snapshot, topic: topic("R12"), expireTime: "2026-10-10T00:00:00Z" }),
    4,
  );
  exchange(f, "R12", "Seek", { subscription: s, snapshot }, reply({}), 5);
  exchange(
    f,
    "R12",
    "Pull",
    { subscription: s, maxMessages: 2 },
    reply({ receivedMessages: [second] }),
    6,
  );
  const sent = [];
  const result = await replayRecording(importRecording(f), async (call, source) => {
    sent.push(call);
    const r = structuredClone(source.reply);
    if (call.method === "Publish") r.body.messageIds = ["456", "457"];
    if (call.method === "Pull")
      r.body.receivedMessages.forEach((item) => {
        item.message.messageId = item.message.messageId === "123" ? "456" : "457";
        item.ackId = `local-${item.ackId}`;
      });
    return r;
  });
  assert.equal(result.cells.find((c) => c.id === "R12").semanticVerdict, "MATCH");
  assert.deepEqual(sent.find((c) => c.method === "Seek").request, { subscription: s, snapshot });
  assert.deepEqual(sent.find((c) => c.method === "Acknowledge").request.ackIds, ["local-a"]);
});
function simultaneousFixture() {
  const f = fixture();
  exchange(
    f,
    "R12",
    "Publish",
    { topic: topic("R12"), messages: [{ data: "eA==" }] },
    reply({ messageIds: ["123"] }),
    1,
  );
  exchange(
    f,
    "R12",
    "Publish",
    { topic: topic("R12"), messages: [{ data: "eQ==" }] },
    reply({ messageIds: ["124"] }),
    2,
  );
  exchange(
    f,
    "R12",
    "Pull",
    { subscription: sub("R12"), maxMessages: 2 },
    reply({
      receivedMessages: [
        { ackId: "source-a", message: { messageId: "123", data: "eA==" } },
        { ackId: "source-b", message: { messageId: "124", data: "eQ==" } },
      ],
    }),
    3,
  );
  exchange(
    f,
    "R12",
    "Acknowledge",
    { subscription: sub("R12"), ackIds: ["source-a", "source-b"] },
    reply({}),
    4,
  );
  return f;
}
async function simultaneousReplay(mode) {
  const sent = [];
  let publication = 0;
  const report = await replayRecording(
    importRecording(simultaneousFixture()),
    async (call, source) => {
      sent.push(call);
      const r = structuredClone(source.reply);
      if (call.method === "Publish")
        r.body.messageIds = [
          mode === "duplicateAcrossPublish" ? "456" : String(456 + publication++),
        ];
      if (call.method === "Pull")
        for (const [i, item] of r.body.receivedMessages.entries()) {
          item.message.messageId = mode === "duplicateAcrossPublish" ? "456" : String(456 + i);
          item.ackId =
            mode === "sameAckForSimultaneousDistinctDeliveries" ? "same-local-ack" : `local-${i}`;
        }
      return r;
    },
  );
  return { cell: report.cells.find((c) => c.id === "R12"), sent };
}
test("distinct same-topic Publish calls cannot collapse publication identity before dependent ACK", async () => {
  assert.equal((await simultaneousReplay("positive")).cell.semanticVerdict, "MATCH");
  const negative = await simultaneousReplay("duplicateAcrossPublish");
  assert.equal(negative.cell.semanticVerdict, "NOT_COMPARABLE");
  assert.equal(
    negative.sent.some((call) => call.method === "Acknowledge"),
    false,
  );
});
test("simultaneous distinct deliveries cannot collapse ACK equality classes on one subscription", async () => {
  assert.equal((await simultaneousReplay("positive")).cell.semanticVerdict, "MATCH");
  const negative = await simultaneousReplay("sameAckForSimultaneousDistinctDeliveries");
  assert.equal(negative.cell.semanticVerdict, "NOT_COMPARABLE");
  assert.equal(
    negative.sent.some((call) => call.method === "Acknowledge"),
    false,
  );
});
test("publication identity is scoped to topic and consistent repeated source publication identity is retained", async () => {
  for (const sameTopic of [false, true]) {
    const f = fixture();
    for (const requestId of [1, 2])
      exchange(
        f,
        "R11",
        "Publish",
        {
          topic: sameTopic || requestId === 1 ? topic("R11") : topic("R11").replace(/-t$/, "-u"),
          messages: [{ data: "eA==" }],
        },
        reply({ messageIds: ["123"] }),
        requestId,
      );
    const result = await replayRecording(importRecording(f), async () =>
      reply({ messageIds: ["456"] }),
    );
    assert.equal(result.cells.find((c) => c.id === "R11").semanticVerdict, "MATCH");
  }
});
test("repeated delivery may reuse an actual token while the original stale-token selector remains bound", async () => {
  const f = fixture(),
    s = sub("R2");
  exchange(
    f,
    "R2",
    "Publish",
    { topic: topic("R2"), messages: [{ data: "eA==" }] },
    reply({ messageIds: ["123"] }),
    1,
  );
  for (const [requestId, ackId] of [
    [2, "old-source"],
    [3, "new-source"],
  ])
    exchange(
      f,
      "R2",
      "Pull",
      { subscription: s, maxMessages: 1 },
      reply({
        receivedMessages: [
          { ackId, message: { messageId: "123", data: "eA==", publishTime: time } },
        ],
      }),
      requestId,
    );
  exchange(f, "R2", "Acknowledge", { subscription: s, ackIds: ["old-source"] }, reply({}), 4);
  const sent = [];
  const result = await replayRecording(importRecording(f), async (call, source) => {
    sent.push(call);
    const r = structuredClone(source.reply);
    if (call.method === "Publish") r.body.messageIds = ["456"];
    if (call.method === "Pull") {
      r.body.receivedMessages[0].message.messageId = "456";
      r.body.receivedMessages[0].ackId = "same-actual-token";
    }
    return r;
  });
  assert.equal(result.cells.find((c) => c.id === "R2").semanticVerdict, "MATCH");
  assert.deepEqual(sent.find((c) => c.method === "Acknowledge").request.ackIds, [
    "same-actual-token",
  ]);
});

import * as cReplay from "./pubsub-observation-c/replay.mjs";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
const configDigest = (bytes) => createHash("sha256").update(bytes).digest("hex");
test("C lifecycle persists bounded strict config before runtime-start and survives temporary removal", () => {
  const dir = mkdtempSync(join(tmpdir(), "c-lifecycle-test-"));
  try {
    const temporary = join(dir, "temporary.json"),
      out = join(dir, "out");
    const bytes = Buffer.from(JSON.stringify({ daemon: { clockStart: time } }));
    // The producer's output directory already exists before the worker starts.
    mkdirSync(out);
    writeFileSync(temporary, bytes);
    cReplay.persistRuntimeStart(
      out,
      {
        config: temporary,
        configSha256: configDigest(bytes),
        serverPid: 101,
      },
      time,
    );
    rmSync(temporary);
    const receipt = JSON.parse(readFileSync(join(out, "runtime-start.json")));
    assert.equal(receipt.serverPid, 101);
    assert.equal(receipt.workerPid, process.pid);
    assert.equal(receipt.strictConfigPath, join(out, "strict-config.json"));
    assert.equal(receipt.strictConfigBytes, bytes.length);
    assert.equal(receipt.strictConfigSha256, configDigest(bytes));
    assert.deepEqual(readFileSync(receipt.strictConfigPath), bytes);
    assert.throws(
      () =>
        cReplay.persistRuntimeStart(
          out,
          {
            config: receipt.strictConfigPath,
            configSha256: configDigest(bytes),
            serverPid: 101,
          },
          time,
        ),
      /EEXIST/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("C lifecycle refuses bad hash clock symlink or oversized config before runtime-start", () => {
  const dir = mkdtempSync(join(tmpdir(), "c-lifecycle-rejection-"));
  try {
    assert.equal(typeof cReplay.persistRuntimeStart, "function");
    for (const mode of ["hash", "clock", "symlink", "oversize"]) {
      const temporary = join(dir, `${mode}.json`),
        out = join(dir, mode);
      const bytes = Buffer.from(
        mode === "oversize"
          ? JSON.stringify({ daemon: { clockStart: time } }) + " ".repeat(1_000_001)
          : JSON.stringify({ daemon: { clockStart: mode === "clock" ? "wrong" : time } }),
      );
      mkdirSync(out);
      writeFileSync(temporary, bytes);
      let path = temporary;
      if (mode === "symlink") {
        path += ".link";
        symlinkSync(temporary, path);
      }
      assert.throws(() =>
        cReplay.persistRuntimeStart(
          out,
          {
            config: path,
            configSha256: mode === "hash" ? "0".repeat(64) : configDigest(bytes),
            serverPid: 101,
          },
          time,
        ),
      );
      assert.throws(() => readFileSync(join(out, "runtime-start.json")), /ENOENT/);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("C lifecycle cannot publish runtime-start when persistent config creation fails", () => {
  const dir = mkdtempSync(join(tmpdir(), "c-lifecycle-order-"));
  try {
    const temporary = join(dir, "temporary.json"),
      out = join(dir, "out");
    mkdirSync(out);
    const bytes = Buffer.from(JSON.stringify({ daemon: { clockStart: time } }));
    writeFileSync(temporary, bytes);
    writeFileSync(join(out, "strict-config.json"), "existing");
    assert.throws(
      () =>
        cReplay.persistRuntimeStart(
          out,
          {
            config: temporary,
            configSha256: configDigest(bytes),
            serverPid: 101,
          },
          time,
        ),
      /EEXIST/,
    );
    assert.throws(() => readFileSync(join(out, "runtime-start.json")), /ENOENT/);
    assert.equal(readFileSync(join(out, "strict-config.json"), "utf8"), "existing");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("C runtime joins persisted publication clock with approved source and build disposition", async () => {
  for (const variant of [
    "valid",
    "absent",
    "stale-source",
    "wrong-binary",
    "wrong-inputs",
    "wrong-owner",
    "stale-clock",
    "stale-request-id",
    "wrong-clock",
  ]) {
    const f = fixture();
    exchange(
      f,
      "R1",
      "CreateSubscription",
      { name: sub("R1"), topic: topic("R1") },
      reply({ name: sub("R1"), topic: topic("R1") }),
      10,
    );
    const deliveriesInput = deliveries();
    for (const source of importRecording(deliveriesInput).cells[0].exchanges)
      exchange(f, "R1", source.method, source.request, source.reply, source.requestId);
    f.rows.find(
      (r) => r.event === "response" && r.method === "Pull",
    ).reply.body.receivedMessages[0].message.publishTime = "2026-10-09T00:00:02.000Z";
    const input = importRecording(f);
    const build = { ...pin, binaryInputsSha256: "c".repeat(64) };
    const disposition = {
      owner1135: {
        proposalSha256: "8238575c8202949f721b59bb9c97ee36b3f0ae701efd552f4169c70fcf0c1c53",
      },
      owner1146: {
        proposalSha256: "c11c23ae6486c496c9f8f5469dd8bed3ac2630f0274b0f44b270196df4c35a78",
      },
      source: { runId, sourceHead: head, packetSha256, descriptorSha256 },
      runtimeInputs: { binarySha256: build.sha256, inputsSha256: build.binaryInputsSha256 },
      cellIds: ["R1"],
    };
    if (variant === "stale-source") disposition.source.packetSha256 = "f".repeat(64);
    if (variant === "wrong-binary") disposition.runtimeInputs.binarySha256 = "f".repeat(64);
    if (variant === "wrong-inputs") disposition.runtimeInputs.inputsSha256 = "f".repeat(64);
    if (variant === "wrong-owner") disposition.owner1135.proposalSha256 = "f".repeat(64);
    // An untrusted source input must not replace the current build witness.
    input.runtimeInputs = { ...disposition.runtimeInputs };
    const persisted = [],
      calls = [];
    const report = await replayLocal(
      input,
      {
        PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
        FIREEMU_CONTROL_URL: "http://127.0.0.1:1235/v1/",
        FIREEMU_CONTROL_TOKEN: "test",
      },
      build,
      {
        timestampDisposition: variant === "absent" ? undefined : disposition,
        fetch: async () =>
          new Response(
            JSON.stringify({
              clock: variant === "wrong-clock" ? "2026-10-09T00:00:00.001Z" : time,
            }),
            { status: 200 },
          ),
        persist: (kind, value) => {
          persisted.push({ kind, value: structuredClone(value) });
          if (kind === "clock" && variant === "stale-clock") value.sourceN++;
          if (kind === "clock" && variant === "stale-request-id") value.sourceRequestId++;
        },
        wireFactory: () => ({
          close() {},
          abortSource() {},
          call: async (call) => {
            calls.push(call);
            const source = input.cells[0].exchanges.find((s) => s.method === call.method);
            const actual = local(source);
            if (call.method === "Pull") actual.body.receivedMessages[0].message.publishTime = time;
            return actual;
          },
        }),
      },
    );
    if (variant === "wrong-clock") {
      assert.equal(calls.length, 0);
      continue;
    }
    const pulled = report.cells[0].exchanges.find((e) => e.method === "Pull");
    assert.equal(
      pulled.semanticVerdict,
      variant === "valid" ? "MATCH" : variant === "absent" ? "DIVERGES" : "NOT_COMPARABLE",
      variant,
    );
    assert.equal(persisted.filter((e) => e.kind === "clock").length, calls.length);
    assert.deepEqual(report.runtimeInputs, {
      binarySha256: build.sha256,
      inputsSha256: build.binaryInputsSha256,
    });
  }
});

test("C entrypoint binds the 338 compiled inputs including resource IAM before worker admission", async () => {
  const { fileURLToPath } = await import("node:url");
  const { syncBuiltinESMExports } = await import("node:module");
  const childProcess = (await import("node:child_process")).default;
  const { main } = await import("./pubsub-observation-c/replay.mjs");
  const directory = mkdtempSync(join(tmpdir(), "fireemu-c-inputs-"));
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const put = (name, value) => {
    const path = join(directory, name),
      bytes = Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
    writeFileSync(path, bytes);
    return { path, sha256: hash(bytes) };
  };
  const originalExec = childProcess.execFileSync;
  try {
    const recording = fixture();
    recording.descriptor.sources = [];
    const descriptor = put("descriptor.json", recording.descriptor);
    recording.packet.descriptorSha256 = descriptor.sha256;
    const packet = put("packet.json", recording.packet);
    for (const object of [recording.rows[0], recording.summary]) {
      object.packetSha256 = packet.sha256;
      object.descriptorSha256 = descriptor.sha256;
    }
    const binding = put("input.json", {
      packet,
      descriptor,
      summary: put("summary.json", recording.summary),
      capture: put(
        "capture.jsonl",
        recording.rows.map((row) => JSON.stringify(row)).join("\n") + "\n",
      ),
      issued: put("issued.jsonl", ""),
    });
    const iam = "crates/fireemu-core-pubsub/src/iam.rs";
    const candidates = originalExec("git", ["-C", root, "ls-files", "crates", "--", "*.rs"], {
      encoding: "utf8",
    })
      .trim()
      .split("\n")
      .filter((path) => path !== iam);
    const paths = [iam, ...candidates].slice(0, 338);
    assert.equal(paths.length, 338);
    const files = Object.fromEntries(
      paths.map((path) => [path, hash(readFileSync(join(root, path)))]),
    );
    mkdirSync(join(directory, "release"));
    const binary = put("release/fireemu", "synthetic pinned binary, never executed");
    childProcess.execFileSync = (file, args, options) => {
      if (file === "git" && args.includes("verify-commit")) return Buffer.alloc(0);
      return originalExec(file, args, options);
    };
    syncBuiltinESMExports();
    for (const variant of ["valid", "missing-iam", "wrong-source-pin", "wrong-file-pin"]) {
      const manifest = {
        sourceHead: head,
        sourceTree: "d".repeat(40),
        files: structuredClone(files),
      };
      if (variant === "missing-iam") {
        delete manifest.files[iam];
        const replacement = candidates.find((path) => !Object.hasOwn(manifest.files, path));
        manifest.files[replacement] = hash(readFileSync(join(root, replacement)));
      }
      if (variant === "wrong-source-pin") manifest.sourceHead = "e".repeat(40);
      if (variant === "wrong-file-pin") manifest.files[iam] = "0".repeat(64);
      const inputs = put(`${variant}-compiled.json`, manifest);
      const build = put(`${variant}-pin.json`, {
        ...pin,
        head,
        tree: "d".repeat(40),
        ...binary,
        binaryInputsPath: inputs.path,
        binaryInputsSha256: inputs.sha256,
      });
      const argv = [
        "--input",
        binding.path,
        "--input-sha256",
        binding.sha256,
        "--build-pin",
        build.path,
        "--build-pin-sha256",
        build.sha256,
        "--out",
        join(directory, variant),
      ];
      await assert.rejects(
        main(argv, {}, { serverPid: -1 }),
        variant === "valid"
          ? /internal worker must be the pinned fireemu child/
          : variant === "wrong-file-pin"
            ? /input byte pin refused/
            : /C compiled input coverage refused/,
      );
    }
  } finally {
    childProcess.execFileSync = originalExec;
    syncBuiltinESMExports();
    rmSync(directory, { recursive: true, force: true });
  }
});
