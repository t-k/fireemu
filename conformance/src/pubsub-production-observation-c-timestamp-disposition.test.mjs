import test from "node:test";
import assert from "node:assert/strict";
import { makePlan, PROJECT, SUITE } from "./pubsub-observation-c/plan.mjs";
import { importRecording, replayRecording } from "./pubsub-observation-c/replay-core.mjs";

const time = "2026-10-09T00:00:00.000Z";
const runtimeInputs = { binarySha256: "1".repeat(64), inputsSha256: "2".repeat(64) };
function fixture(cellId = "R1") {
  const metadata = {
    event: "run-start",
    n: 1,
    at: time,
    runId: "0123456789ab",
    sourceHead: "a".repeat(40),
    suite: SUITE,
    project: PROJECT,
    envelopeId: "C-TIMESTAMP-TEST",
    packetSha256: "b".repeat(64),
    descriptorSha256: "c".repeat(64),
  };
  const f = {
    packet: {
      sourceHead: metadata.sourceHead,
      descriptorSha256: metadata.descriptorSha256,
      runIds: [metadata.runId],
      plan: makePlan(),
    },
    descriptor: { head: metadata.sourceHead, suite: SUITE },
    summary: { ...metadata, recordingComplete: true, resourcesClosed: true, results: [] },
    rows: [metadata],
    issued: [],
    packetSha256: metadata.packetSha256,
    descriptorSha256: metadata.descriptorSha256,
    runtimeInputs,
    cellId,
    locals: new Map(),
  };
  for (const cell of f.packet.plan.cells.filter((c) => !c.reserve)) {
    const result = {
      event: "case-result",
      cellId: cell.id,
      complete: true,
      cleanupClosed: true,
      observations: [],
    };
    f.rows.push({ ...result, n: f.rows.length + 1, at: time });
    f.summary.results.push(result);
  }
  f.topic = `projects/${PROJECT}/topics/fe${metadata.runId}-${cellId.toLowerCase()}-t`;
  f.subscription = `projects/${PROJECT}/subscriptions/fe${metadata.runId}-${cellId.toLowerCase()}-s`;
  f.snapshot = `projects/${PROJECT}/snapshots/fe${metadata.runId}-${cellId.toLowerCase()}-snap`;
  return f;
}
const reply = (body, hash = "d") => ({
  ok: true,
  code: "OK",
  status: 200,
  body,
  bodyBytes: 100,
  bodySha256: hash.repeat(64),
});
function add(f, method, request, body, localBody = body, at = time) {
  const requestId = f.locals.size + 1;
  const transport = f.cellId.startsWith("R") ? "rest" : "grpc";
  const index = f.rows.findIndex((r) => r.cellId === f.cellId && r.event === "case-result");
  f.rows.splice(
    index,
    0,
    {
      event: "request-dispatch",
      at,
      cellId: f.cellId,
      requestId,
      method,
      request,
      transport,
      category: method.startsWith("Delete") ? "cleanupDelete" : method,
    },
    { event: "response", at, cellId: f.cellId, requestId, method, transport, reply: reply(body) },
  );
  f.rows.forEach((r, i) => (r.n = i + 1));
  f.locals.set(requestId, reply(structuredClone(localBody), "e"));
  return requestId;
}
function setup(f, filter) {
  add(f, "CreateTopic", { name: f.topic }, { name: f.topic });
  add(
    f,
    "CreateSubscription",
    { name: f.subscription, topic: f.topic, ...(filter ? { filter } : {}) },
    { name: f.subscription, topic: f.topic, ...(filter ? { filter } : {}) },
  );
}
function publish(f, id, at) {
  return add(
    f,
    "Publish",
    { topic: f.topic, messages: [{ data: "eA==", attributes: { id } }] },
    { messageIds: [id] },
    { messageIds: [`9${id}`] },
    at,
  );
}
function pull(f, id, sourceTime, localTime, at = "2026-10-09T00:10:00.000Z") {
  const body = (messageId, ackId, publishTime) => ({
    receivedMessages: [
      { ackId, message: { messageId, data: "eA==", attributes: { id }, publishTime } },
    ],
  });
  return add(
    f,
    "Pull",
    { subscription: f.subscription, maxMessages: 1 },
    body(id, `source-${id}`, sourceTime),
    body(`9${id}`, `local-${id}`, localTime),
    at,
  );
}
function disposition(input) {
  const { runId, sourceHead, packetSha256, descriptorSha256 } = input.metadata;
  return {
    owner1135: {
      proposalSha256: "8238575c8202949f721b59bb9c97ee36b3f0ae701efd552f4169c70fcf0c1c53",
    },
    owner1146: {
      proposalSha256: "c11c23ae6486c496c9f8f5469dd8bed3ac2630f0274b0f44b270196df4c35a78",
    },
    source: { runId, sourceHead, packetSha256, descriptorSha256 },
    runtimeInputs: structuredClone(runtimeInputs),
    cellIds: [input.cellId],
  };
}
async function run(f, alter = () => {}, options = {}) {
  // Renumbering timestamps preserves the fixture's dispatch chronology before import.
  let last = time;
  for (const row of f.rows) {
    if (row.at < last) row.at = last;
    last = row.at;
  }
  const input = importRecording(f);
  const receipts = new Map(
    input.cells
      .find((c) => c.id === f.cellId)
      .exchanges.map((s) => [
        s.requestId,
        {
          sourceRequestId: s.requestId,
          sourceN: s.n,
          requestedInstant: s.at,
          status: 200,
          body: { clock: s.at },
        },
      ]),
  );
  const opts = {
    timestampDisposition: disposition(input),
    clockReceiptFor: (s) => receipts.get(s.requestId),
    ...options,
  };
  alter({ input, receipts, opts });
  const observed = [],
    sent = [];
  const before = structuredClone(input);
  const result = await replayRecording(
    input,
    async (call, source) => {
      sent.push(source.method);
      return structuredClone(f.locals.get(source.requestId));
    },
    { ...opts, observe: (e) => observed.push(structuredClone(e)) },
  );
  assert.deepEqual(input, before);
  return { cell: result.cells.find((c) => c.id === f.cellId), result, observed, sent };
}
function delivered(cellId = "R1") {
  const f = fixture(cellId);
  setup(f);
  publish(f, "123", time);
  pull(f, "123", "2026-10-09T00:00:00.097Z", time);
  add(f, "Acknowledge", { subscription: f.subscription, ackIds: ["source-123"] }, {});
  return f;
}
const entry = (result, method) => result.cell.exchanges.find((e) => e.method === method);
for (const cellId of ["R1", "N1"]) {
  test(`C ${cellId} publication predicate uses the Publish clock and retains physical evidence`, async () => {
    const r = await run(delivered(cellId));
    assert.equal(entry(r, "Pull").semanticVerdict, "MATCH");
    assert.equal(entry(r, "Pull").physicalVerdict, "DIVERGES");
    assert.equal(entry(r, "Pull").timestampProofs[0].owner, 1135);
    if (cellId.startsWith("N")) assert.equal(entry(r, "Pull").wireVerdict, "NOT_COMPARABLE");
    assert.equal(r.result.parentClosureReady, false);
    assert.ok(r.sent.includes("Acknowledge"));
  });
}
test("C keeps literal comparison when no timestamp disposition is supplied", async () => {
  const r = await run(delivered(), () => {}, { timestampDisposition: undefined });
  assert.equal(entry(r, "Pull").semanticVerdict, "DIVERGES");
});
test("C missing or incorrectly joined clock proof is NC without suppressing later requests", async () => {
  for (const change of [
    ({ receipts }) => receipts.clear(),
    ({ receipts }) => {
      for (const receipt of receipts.values()) receipt.sourceN++;
    },
    ({ receipts }) => {
      for (const receipt of receipts.values()) receipt.sourceRequestId++;
    },
    ({ receipts }) => {
      for (const receipt of receipts.values()) receipt.status = 201;
    },
    ({ receipts }) => {
      for (const receipt of receipts.values())
        receipt.requestedInstant = "2026-10-09T00:10:00.000Z";
    },
  ]) {
    const r = await run(delivered(), change);
    assert.equal(entry(r, "Pull").semanticVerdict, "NOT_COMPARABLE");
    assert.ok(r.sent.includes("Acknowledge"));
  }
});
test("C rejects stale source, cell, runtime and proposal authority", async () => {
  for (const change of [
    (d) => {
      d.source.packetSha256 = "f".repeat(64);
    },
    (d) => {
      d.source.descriptorSha256 = "f".repeat(64);
    },
    (d) => {
      d.source.runId = "abcdef012345";
    },
    (d) => {
      d.source.sourceHead = "f".repeat(40);
    },
    (d) => {
      d.cellIds = ["R2"];
    },
    (d) => {
      d.runtimeInputs.binarySha256 = "f".repeat(64);
    },
    (d) => {
      d.runtimeInputs.inputsSha256 = "f".repeat(64);
    },
    (d) => {
      d.owner1135.proposalSha256 = "f".repeat(64);
    },
  ]) {
    const r = await run(delivered(), ({ opts }) => change(opts.timestampDisposition));
    assert.equal(entry(r, "Pull").semanticVerdict, "NOT_COMPARABLE");
  }
});
test("C saved timestamp must equal actual publication and remain stable on both sides", async () => {
  const f = delivered();
  f.locals.get(4).body.receivedMessages[0].message.publishTime = "2026-10-09T00:10:00.000Z";
  assert.equal(entry(await run(f), "Pull").semanticVerdict, "DIVERGES");
  for (const side of ["source", "local"]) {
    const g = delivered();
    pull(
      g,
      "123",
      side === "source" ? "2026-10-09T00:00:00.098Z" : "2026-10-09T00:00:00.097Z",
      side === "local" ? "2026-10-09T00:00:00.001Z" : time,
    );
    const r = await run(g);
    assert.equal(
      r.cell.exchanges.filter((e) => e.method === "Pull")[1].semanticVerdict,
      "DIVERGES",
    );
  }
});
test("C timestamp precision, presence, range and unrelated fields remain strict", async () => {
  for (const value of [
    undefined,
    42,
    "2026-10-09T00:00:00.0Z",
    "2026-02-30T00:00:00.000Z",
    "2026-10-09T00:00:00.000+00:00",
    "2026-10-09T00:00:60.000Z",
    "0000-01-01T00:00:00.000Z",
    "2026-10-09T00:00:00.000000Z",
  ]) {
    const f = delivered();
    f.locals.get(4).body.receivedMessages[0].message.publishTime = value;
    assert.equal(entry(await run(f), "Pull").semanticVerdict, "DIVERGES");
  }
  const f = delivered();
  f.locals.get(4).body.receivedMessages[0].message.expireTime = time;
  assert.equal(entry(await run(f), "Pull").semanticVerdict, "DIVERGES");
});
test("C legal precision properties compare nanoseconds exactly", async () => {
  for (const precision of [0, 3, 6, 9]) {
    const suffix = precision ? `.${"0".repeat(precision)}` : "";
    const f = delivered();
    f.locals.get(4).body.receivedMessages[0].message.publishTime = `2026-10-09T00:00:00${suffix}Z`;
    f.rows.find(
      (r) => r.event === "response" && r.method === "Pull",
    ).reply.body.receivedMessages[0].message.publishTime = `2026-10-09T00:00:01${suffix}Z`;
    assert.equal(entry(await run(f), "Pull").semanticVerdict, "MATCH");
  }
});
function snapshotFixture() {
  const f = fixture("R12");
  setup(f);
  publish(f, "123", time);
  pull(f, "123", "2026-10-09T00:00:00.097Z", time);
  publish(f, "124", "2026-10-09T00:20:00.000Z");
  pull(
    f,
    "124",
    "2026-10-09T00:20:00.097Z",
    "2026-10-09T00:20:00.000Z",
    "2026-10-09T00:30:00.000Z",
  );
  const body = {
    name: f.snapshot,
    topic: f.topic,
    labels: { proof: "owned" },
    expireTime: "2026-10-16T00:00:00.097Z",
  };
  const local = { ...body, expireTime: "2026-10-16T00:00:00.000Z" };
  add(
    f,
    "CreateSnapshot",
    { name: f.snapshot, subscription: f.subscription },
    body,
    local,
    "2026-10-09T01:00:00.000Z",
  );
  add(f, "GetSnapshot", { name: f.snapshot }, body, local, "2026-10-09T01:10:00.000Z");
  return f;
}
test("C Snapshot lifetime uses the oldest proven unacknowledged publication and finalizes Create before Get", async () => {
  const r = await run(snapshotFixture());
  assert.equal(entry(r, "CreateSnapshot").semanticVerdict, "NOT_COMPARABLE");
  assert.equal(entry(r, "GetSnapshot").semanticVerdict, "NOT_COMPARABLE");
  const notifications = r.observed.filter((e) => /Snapshot/.test(e.method));
  assert.deepEqual(
    notifications.map((e) => e.method),
    ["CreateSnapshot", "GetSnapshot"],
  );
  assert.ok(notifications.every((e) => e.semanticVerdict === "NOT_COMPARABLE"));
  assert.equal(notifications[0].timestampProofs[0].owner, 1146);
});
test("C Snapshot newest publication and changed Get are divergences", async () => {
  for (const alter of [
    (f) => {
      f.locals.get(7).body.expireTime = "2026-10-16T00:20:00.000Z";
      f.locals.get(8).body.expireTime = "2026-10-16T00:20:00.000Z";
    },
    (f) => {
      f.locals.get(8).body.expireTime = "2026-10-16T00:00:00.001Z";
    },
    (f) => {
      f.rows.find(
        (r) => r.event === "response" && r.method === "GetSnapshot",
      ).reply.body.expireTime = "2026-10-16T00:00:00.098Z";
    },
    (f) => {
      f.locals.get(8).body.topic += "-wrong";
    },
  ]) {
    const f = snapshotFixture();
    alter(f);
    const r = await run(f);
    assert.equal(entry(r, "GetSnapshot").semanticVerdict, "DIVERGES");
    assert.equal(entry(r, "CreateSnapshot").semanticVerdict, "DIVERGES");
  }
});
test("C Snapshot missing Get and unavailable backlog proof remain NC", async () => {
  for (const alter of [
    (f) => {
      f.rows = f.rows.filter((r) => r.method !== "GetSnapshot");
    },
    (f) => {
      f.rows.find(
        (r) => r.method === "CreateSubscription" && r.event === "response",
      ).reply.body.filter = "attributes.x";
      f.locals.get(2).body.filter = "attributes.x";
    },
    (f) => {
      f.rows.find(
        (r) => r.method === "CreateSnapshot" && r.event === "request-dispatch",
      ).request.subscription += "-unknown";
    },
    (f) => {
      f.rows.find((r) => r.method === "CreateTopic" && r.event === "response").reply.ok = false;
      f.locals.get(1).ok = false;
    },
  ]) {
    const f = snapshotFixture();
    alter(f);
    f.rows.forEach((r, i) => (r.n = i + 1));
    const r = await run(f);
    assert.equal(entry(r, "CreateSnapshot").semanticVerdict, "NOT_COMPARABLE");
  }
});
test("C generated nanosecond cases preserve exact instants without tolerance", async () => {
  let seed = 747;
  for (let i = 0; i < 24; i++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const nanos = seed % 999999999;
    const instant = `2026-10-09T00:00:00.${String(nanos).padStart(9, "0")}Z`;
    const sourceTime = `2026-10-09T00:00:01.${String(nanos).padStart(9, "0")}Z`;
    const f = fixture();
    setup(f);
    publish(f, "123", instant);
    pull(f, "123", sourceTime, instant);
    assert.equal(entry(await run(f), "Pull").semanticVerdict, "MATCH");
    f.locals.get(4).body.receivedMessages[0].message.publishTime =
      `2026-10-09T00:00:00.${String(nanos + 1).padStart(9, "0")}Z`;
    assert.equal(entry(await run(f), "Pull").semanticVerdict, "DIVERGES");
  }
});
test("C unavailable runtime and subscription proof cannot become a timestamp match", async () => {
  for (const change of [
    ({ input }) => {
      delete input.runtimeInputs;
    },
    ({ input }) => {
      input.cells[0].exchanges[1].reply.body.topic += "-unknown";
    },
  ]) {
    assert.equal(entry(await run(delivered(), change), "Pull").semanticVerdict, "NOT_COMPARABLE");
  }
});
test("C Snapshot ACK, Seek, missing saved message or local subscription proof stays NC", async () => {
  for (const alter of [
    (f) => {
      f.rows.find(
        (r) => r.event === "response" && r.method === "Pull",
      ).reply.body.receivedMessages = [];
      f.locals.get(4).body.receivedMessages = [];
    },
    (f) => {
      f.locals.get(2).body.filter = "attributes.x";
    },
    (f) => {
      const dispatch = f.rows.find(
        (r) => r.event === "request-dispatch" && r.method === "GetSnapshot",
      );
      dispatch.method = "Seek";
      dispatch.request = { subscription: f.subscription, time };
      f.rows.find((r) => r.event === "response" && r.method === "GetSnapshot").method = "Seek";
    },
  ]) {
    const f = snapshotFixture();
    alter(f);
    assert.equal(entry(await run(f), "CreateSnapshot").semanticVerdict, "NOT_COMPARABLE");
  }
  const f = snapshotFixture();
  // Insert a successfully bound ACK before creation, preserving source order.
  const createIndex = f.rows.findIndex(
    (r) => r.event === "request-dispatch" && r.method === "CreateSnapshot",
  );
  const requestId = add(
    f,
    "Acknowledge",
    { subscription: f.subscription, ackIds: ["source-123"] },
    {},
    {},
    "2026-10-09T00:40:00.000Z",
  );
  const ackRows = f.rows.splice(
    f.rows.findIndex((r) => r.requestId === requestId),
    2,
  );
  f.rows.splice(createIndex, 0, ...ackRows);
  f.rows.forEach((r, i) => (r.n = i + 1));
  assert.equal(entry(await run(f), "CreateSnapshot").semanticVerdict, "NOT_COMPARABLE");
});
test("C Snapshot minimum lifetime, precision and owner1146 remain required", async () => {
  const f = snapshotFixture();
  for (const row of f.rows.filter((r) => /Snapshot/.test(r.method)))
    row.at = "2026-10-15T23:30:00.000Z";
  assert.equal(entry(await run(f), "CreateSnapshot").semanticVerdict, "DIVERGES");
  const g = snapshotFixture();
  g.locals.get(7).body.expireTime = "2026-10-16T00:00:00.000000Z";
  g.locals.get(8).body.expireTime = "2026-10-16T00:00:00.000000Z";
  assert.equal(entry(await run(g), "CreateSnapshot").semanticVerdict, "DIVERGES");
  const h = await run(snapshotFixture(), ({ opts }) => {
    delete opts.timestampDisposition.owner1146;
  });
  assert.equal(entry(h, "CreateSnapshot").semanticVerdict, "NOT_COMPARABLE");
});
test("C Snapshot Get status and code differences cannot finalize a successful Create proof", async () => {
  const f = snapshotFixture();
  f.locals.get(8).code = "INTERNAL";
  f.locals.get(8).status = 503;
  const r = await run(f);
  assert.equal(entry(r, "GetSnapshot").semanticVerdict, "DIVERGES");
  assert.equal(entry(r, "CreateSnapshot").semanticVerdict, "DIVERGES");
});
test("C actual repeated delivery drift is a divergence even when the clock witness is unavailable", async () => {
  const f = delivered();
  pull(f, "123", "2026-10-09T00:00:00.097Z", "2026-10-09T00:00:00.001Z");
  const r = await run(f, ({ receipts }) => receipts.clear());
  assert.deepEqual(
    r.cell.exchanges.filter((e) => e.method === "Pull").map((e) => e.semanticVerdict),
    ["NOT_COMPARABLE", "DIVERGES"],
  );
});
test("C predicates are invariant under an aged virtual clock", async () => {
  const shift = (value) => {
    if (typeof value === "string" && /^2026-10-\d\dT/.test(value))
      return new Date(Date.parse(value) + 13 * 3600000).toISOString();
    if (Array.isArray(value)) return value.map(shift);
    if (value !== null && typeof value === "object")
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, shift(item)]));
    return value;
  };
  for (const f of [delivered(), snapshotFixture()]) {
    f.rows = shift(f.rows);
    f.locals = new Map([...f.locals].map(([key, value]) => [key, shift(value)]));
    const r = await run(f);
    assert.ok(
      r.cell.exchanges
        .filter((e) => ["Pull", "CreateSnapshot", "GetSnapshot"].includes(e.method))
        .every((e) => e.semanticVerdict === (e.method === "Pull" ? "MATCH" : "NOT_COMPARABLE")),
    );
  }
});

test("C Snapshot source lifetime remains NC with a production clock two seconds ahead", async () => {
  const f = fixture("R12");
  setup(f);
  publish(f, "123", time);
  pull(f, "123", "2026-10-09T00:00:02.000Z", time, "2026-10-09T00:00:00.500Z");
  const body = { name: f.snapshot, topic: f.topic, expireTime: "2026-10-16T00:00:02.000Z" };
  const local = { ...body, expireTime: "2026-10-16T00:00:00.000Z" };
  add(
    f,
    "CreateSnapshot",
    { name: f.snapshot, subscription: f.subscription },
    body,
    local,
    "2026-10-09T00:00:01.000Z",
  );
  add(f, "GetSnapshot", { name: f.snapshot }, body, local, "2026-10-09T00:00:01.500Z");
  const r = await run(f);
  assert.equal(entry(r, "Pull").semanticVerdict, "MATCH");
  assert.equal(entry(r, "CreateSnapshot").semanticVerdict, "NOT_COMPARABLE");
  assert.equal(entry(r, "GetSnapshot").semanticVerdict, "NOT_COMPARABLE");
});
for (const coordinate of ["sourceN", "sourceRequestId"]) {
  test(`C stale clock receipt ${coordinate} directly yields NC`, async () => {
    const r = await run(delivered(), ({ receipts }) => {
      for (const receipt of receipts.values()) receipt[coordinate]++;
    });
    assert.equal(entry(r, "Pull").semanticVerdict, "NOT_COMPARABLE");
  });
}

test("C Snapshot source oldest-publication relation remains strict without server creation evidence", async () => {
  const f = snapshotFixture();
  for (const row of f.rows.filter((r) => r.event === "response" && /Snapshot/.test(r.method)))
    row.reply.body.expireTime = "2026-10-16T00:00:00.098Z";
  const r = await run(f);
  assert.equal(entry(r, "CreateSnapshot").semanticVerdict, "DIVERGES");
  assert.equal(entry(r, "GetSnapshot").semanticVerdict, "DIVERGES");
});
test("C Snapshot actual local creation clock remains required", async () => {
  for (const change of [
    ({ receipts }) => receipts.delete(7),
    ({ receipts }) => {
      receipts.get(7).body.clock = "2026-10-09T01:00:00.001Z";
    },
  ]) {
    const f = snapshotFixture();
    // An invalid local lifetime must not be judged from an unavailable local clock.
    f.locals.get(7).body.expireTime = "2026-10-16T00:00:00.001Z";
    f.locals.get(8).body.expireTime = "2026-10-16T00:00:00.001Z";
    assert.equal(entry(await run(f, change), "CreateSnapshot").semanticVerdict, "NOT_COMPARABLE");
  }
});
