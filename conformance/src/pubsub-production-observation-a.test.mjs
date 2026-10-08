import assert from "node:assert/strict";
import test from "node:test";
import { makePlan, CAPS } from "./pubsub-observation/plan.mjs";

test("observation A fixes the adjudicated per-set category and frame ceilings", () => {
  const plan = makePlan();
  assert.deepEqual(plan.caps, {
    G1: { requests: 240, rest: 120, grpc: 120, streams: 0, cellMs: 120000 },
    G4: { requests: 306, rest: 289, grpc: 0, streams: 17, cellMs: 180000 },
    G7: { requests: 14, rest: 14, grpc: 0, streams: 0 },
    sourceRequests: 546,
    totalRequests: 560,
    framesOut: 102,
    framesIn: 102,
    frameBytes: 65536,
    metadataBytesEachDirection: 65536,
    largePublishes: 40,
    largeEncodedPayloadBytes: 16777216,
    smallPublishes: 51,
    smallEncodedPayloadBytes: 1024,
    sourceWallMs: 5460000,
    cleanupReserveMs: 40000,
  });
});

test("observation A declares all eleven stream witnesses and five invalid supplements", () => {
  const plan = makePlan();
  const stream = plan.cells.filter((cell) => cell.group === "G4" && !cell.reserve);
  assert.equal(stream.length, 16);
  assert.deepEqual(
    stream.slice(0, 11).map((cell) => cell.canonicalCase),
    [
      "opening-frame",
      "future-publications",
      "in-stream-ack",
      "in-stream-nack",
      "in-stream-deadline-update",
      "flow-control",
      "client-cancel",
      "half-close",
      "missing-subscription",
      "invalid-opening-frame",
      "invalid-update-frame",
    ],
  );
  assert.equal(stream.filter((cell) => cell.supplement).length, 5);
  assert.equal(plan.cells.filter((cell) => cell.group === "G1" && !cell.reserve).length, 16);
  assert.equal(plan.cells.filter((cell) => cell.reserve).length, 5);
  assert.equal(new Set(plan.cells.map((cell) => cell.id)).size, plan.cells.length);
  assert.equal(stream.at(-1).invalidAck, "invalid-ack-for-stream-observation");
  assert.equal(plan.ackSelector, "NOT_COMPARABLE-until-observed");
});

const { createMeter } = await import("./pubsub-observation/meter.mjs");
test("meter counts starts before tokens and reserves cleanup within the cell clock", () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock });
  const cell = makePlan().cells[0];
  meter.enter(cell);
  meter.start("create", "rest");
  meter.start("create", "rest");
  assert.throws(() => meter.start("create", "rest"), /category/);
  clock = 140000;
  assert.throws(() => meter.start("target", "rest"), /time/);
  meter.start("cleanupGet", "rest");
  clock = 180000;
  assert.throws(() => meter.start("cleanupGet", "rest"), /time/);
  assert.equal(meter.snapshot().groups.G4.requests, 3);
});
test("meter frame and payload bounds are independent of request starts", () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  for (let i = 0; i < 6; i++) meter.frame("out", 65536);
  assert.throws(() => meter.frame("out", 1), /frame/);
  assert.throws(() => meter.frame("in", 65537), /byte/);
  assert.equal(meter.snapshot().requests, 0);
  assert.throws(() => meter.payload(1025), /payload/);
});
test("meter state agrees with an independent bounded vector model", () => {
  for (let seed = 1; seed <= 250; seed++) {
    let state = seed;
    const meter = createMeter({ now: () => 0 });
    const cell = makePlan().cells.find((item) => item.id === "R1");
    meter.enter(cell);
    const reference = { create: 0, get: 0, target: 0, cleanupDelete: 0, cleanupGet: 0 };
    const ceilings = [2, 2, 4, 2, 2];
    for (let step = 0; step < 35; step++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      const index = state % 5;
      const category = Object.keys(reference)[index];
      if (reference[category] === ceilings[index])
        assert.throws(() => meter.start(category, "rest"));
      else {
        meter.start(category, "rest");
        reference[category]++;
      }
      assert.deepEqual(meter.snapshot().cell.categories, reference);
      assert.equal(
        meter.snapshot().requests,
        Object.values(reference).reduce((a, b) => a + b, 0),
      );
    }
  }
});

const { boundaryPayload, encodedSizes } = await import("./pubsub-observation/payload.mjs");
test("exact boundaries use JSON for REST and protobuf for native unary", () => {
  const topic = "projects/fixture-project/topics/fe123456abcdef-boundary";
  for (const transport of ["rest", "grpc"])
    for (const target of [10000000, 10000001, 10485760, 10485761]) {
      const value = boundaryPayload({ topic, transport, target, kind: "request" });
      const sizes = encodedSizes(topic, value.messages);
      assert.equal(sizes[transport === "rest" ? "json" : "protobuf"], target);
      assert.ok(sizes.payload <= 16777216);
    }
});
test("boundary encoding properties hold for small exact byte targets and message targets", () => {
  const topic = "projects/fixture-project/topics/fe123456abcdef-boundary";
  for (const transport of ["rest", "grpc"])
    for (let target = 256; target < 400; target++) {
      const value = boundaryPayload({ topic, transport, target, kind: "request" });
      const sizes = encodedSizes(topic, value.messages);
      assert.equal(sizes[transport === "rest" ? "json" : "protobuf"], target);
    }
  for (const target of [10000000, 10000001]) {
    const value = boundaryPayload({ topic, transport: "rest", target, kind: "message" });
    assert.equal(encodedSizes(topic, value.messages).message, target);
  }
});

const { createWire, readResponse } = await import("./pubsub-observation/wire.mjs");
const { encodeRequest, typeOf } = await import("./pubsub-observation/wire.mjs");
const { SERVICES } = await import("./pubsub-production/grpc.mjs");

test("REST bounded reader cancels oversized bodies before buffering the whole response", async () => {
  let cancelled = 0,
    reads = 0;
  const response = {
    body: {
      getReader: () => ({
        read: async () =>
          ++reads === 1 ? { done: false, value: Buffer.alloc(65537) } : { done: true },
        cancel: async () => {
          cancelled++;
        },
        releaseLock() {},
      }),
    },
  };
  await assert.rejects(readResponse(response), /response byte/);
  assert.equal(cancelled, 1);
});
test("wire refuses exhausted categories before retrieving credentials or dispatching", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells.find((cell) => cell.id === "R1"));
  let tokens = 0,
    dispatches = 0;
  const rows = [];
  const wire = createWire({
    meter,
    journal: { write: (row) => rows.push(row) },
    getToken: async () => {
      tokens++;
      return "fake-token-only";
    },
    fetch: async () => {
      dispatches++;
      return new Response('{"name":"fixture"}', { status: 200 });
    },
    client: { close() {} },
  });
  const call = {
    category: "create",
    transport: "rest",
    service: "Publisher",
    method: "CreateTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  };
  await wire.call(call);
  await wire.call(call);
  await assert.rejects(wire.call(call), /category/);
  assert.equal(tokens, 2);
  assert.equal(dispatches, 2);
  assert.equal(rows.filter((row) => row.event === "request-dispatch").length, 2);
  wire.close();
});

const { EventEmitter } = await import("node:events");
const { protos } = await import("@google-cloud/pubsub");
const { openStream } = await import("./pubsub-observation/stream.mjs");
test("native stream records cancel and half-close separately and preserves exact update presence", async (context) => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  const rpc = new EventEmitter();
  const writes = [];
  rpc.write = (bytes) => {
    writes.push(bytes);
    return true;
  };
  rpc.end = () => {
    rpc.ended = true;
  };
  rpc.cancel = () => {
    rpc.cancelled = true;
  };
  const rows = [];
  const stream = await openStream({
    meter,
    client: { makeBidiStreamRequest: () => rpc },
    journal: { write: (row) => rows.push(row), frame: (_raw, row) => rows.push(row) },
    credential: async () => "fake",
    now: () => 1000,
    cellId: "S01",
    opener: {
      subscription: "projects/fixture/subscriptions/fe123456abcdef-a",
      streamAckDeadlineSeconds: 10,
      maxOutstandingMessages: "1",
      maxOutstandingBytes: "1024",
    },
  });
  stream.write({ modifyDeadlineAckIds: ["own-runtime-token"], modifyDeadlineSeconds: [] });
  const entry = rows.find((row) => row.event === "stream-frame" && row.body.modifyDeadlineAckIds);
  context.after(() => stream.dispose());
  assert.deepEqual(entry.body.modifyDeadlineSeconds, []);
  stream.end();
  stream.cancel("test");
  assert.equal(rpc.ended, true);
  assert.equal(rpc.cancelled, true);
  assert.equal(writes.length, 2);
  assert.equal(meter.snapshot().framesOut, 2);
  assert.ok(rows.some((row) => row.event === "stream-write-end"));
  assert.ok(rows.some((row) => row.event === "stream-cancel"));
  stream.dispose();
});
test("inbound stream overflow is incomplete, cancels once, and never reopens", async (context) => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  const rpc = new EventEmitter();
  let cancelled = 0,
    starts = 0;
  rpc.write = () => true;
  rpc.cancel = () => {
    cancelled++;
  };
  rpc.end = () => {};
  const stream = await openStream({
    meter,
    client: {
      makeBidiStreamRequest: () => {
        starts++;
        return rpc;
      },
    },
    journal: { write() {}, frame() {} },
    credential: async () => "fake",
    now: () => 1,
    cellId: "S01",
    opener: {
      subscription: "projects/fixture/subscriptions/fe123456abcdef-a",
      streamAckDeadlineSeconds: 10,
    },
  });
  const bytes = Buffer.from(protos.google.pubsub.v1.StreamingPullResponse.encode({}).finish());
  for (let i = 0; i < 7; i++) rpc.emit("data", bytes);
  context.after(() => stream.dispose());
  assert.equal(stream.state().incomplete, true);
  assert.equal(cancelled, 1);
  assert.equal(starts, 1);
  assert.equal(meter.snapshot().framesIn, 6);
  stream.dispose();
});

const { runCell, recoverA2, selectOwn } = await import("./pubsub-observation/scenarios.mjs");
const { createLedger } = await import("./pubsub-production/ledger.mjs");
test("ACK selection requires the witnessed publication ID and exact marker, never a width selector", () => {
  const published = new Map([["own-id", "b3du"]]);
  assert.equal(
    selectOwn(
      {
        receivedMessages: [
          { ackId: "195-width-token", message: { messageId: "other", data: "b3du" } },
        ],
      },
      published,
    ).length,
    0,
  );
  assert.equal(
    selectOwn(
      { receivedMessages: [{ ackId: "token", message: { messageId: "own-id", data: "other" } }] },
      published,
    ).length,
    0,
  );
  assert.equal(
    selectOwn(
      { receivedMessages: [{ ackId: "token", message: { messageId: "own-id", data: "b3du" } }] },
      published,
    )[0].ackId,
    "token",
  );
});
function fakeWorld({ clock, unknown = null } = {}) {
  const resources = new Map(),
    calls = [];
  return {
    calls,
    resources,
    async call(call) {
      calls.push(call);
      if (clock)
        clock.value +=
          call.method === "CreateTopic"
            ? 37666
            : call.method === "CreateSubscription"
              ? 13024
              : 700;
      if (call.method === unknown) return { ok: false, unknown: true, code: "UNKNOWN", body: {} };
      const name =
        call.request.name ??
        call.request.subscription?.name ??
        call.request.subscription ??
        call.request.topic;
      if (call.method.startsWith("Create")) {
        assert.equal(typeof call.request.name, "string");
        if (call.method === "CreateSubscription") assert.equal(typeof call.request.topic, "string");
        if (resources.has(name))
          return {
            ok: false,
            code: "ALREADY_EXISTS",
            status: 409,
            body: { error: { status: "ALREADY_EXISTS" } },
          };
        const body = { ...call.request };
        resources.set(name, body);
        return { ok: true, code: "OK", body };
      }
      if (call.method.startsWith("Get"))
        return resources.has(name)
          ? { ok: true, code: "OK", body: resources.get(name) }
          : { ok: false, code: "NOT_FOUND", status: 404, body: { error: { status: "NOT_FOUND" } } };
      if (call.method.startsWith("Delete")) {
        resources.delete(name);
        return { ok: true, code: "OK", body: {} };
      }
      if (call.method === "UpdateSubscription") {
        if (call.request.updateMask.includes("fieldThatDoesNotExist"))
          return {
            ok: false,
            code: "INVALID_ARGUMENT",
            body: { error: { status: "INVALID_ARGUMENT" } },
          };
        const body = { ...resources.get(name), ...call.request.subscription };
        resources.set(name, body);
        return { ok: true, code: "OK", body };
      }
      if (call.method === "Publish")
        return { ok: true, code: "OK", body: { messageIds: ["own-id"] } };
      return { ok: true, code: "OK", body: {} };
    },
  };
}
test("unknown creation stays open and prevents unsafe deletion or next-cell success", async () => {
  const ledger = createLedger(),
    meter = createMeter({ now: () => 0 });
  const cell = makePlan().cells.find((cell) => cell.id === "R3");
  meter.enter(cell);
  const world = fakeWorld({ unknown: "CreateTopic" });
  const result = await runCell({
    cell,
    meter,
    wire: world,
    ledger,
    runId: "123456abcdef",
    journal: { write() {} },
  });
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, false);
  assert.equal(world.calls.filter((call) => call.method === "DeleteTopic").length, 0);
  assert.ok(ledger.outstanding().some((item) => item.action === "create"));
});
test("maximum recorded create latencies count toward the G4 window and cleanup", async () => {
  const clock = { value: 0 },
    meter = createMeter({ now: () => clock.value });
  const cell = makePlan().cells[0];
  meter.enter(cell);
  const world = fakeWorld({ clock });
  let window;
  world.open = async () => {
    meter.start("stream", "streams");
    window = Math.min(90000, meter.remaining() - 1);
    clock.value += window;
    return {
      next: async () => null,
      cancel() {},
      dispose() {},
      state: () => ({ windowMs: window, incomplete: window < 90000, terminal: null }),
    };
  };
  const result = await runCell({
    cell,
    meter,
    wire: world,
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: { write() {} },
  });
  assert.ok(window < 90000);
  assert.ok(clock.value <= 180000);
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, true);
  assert.equal(world.calls.filter((call) => call.method.startsWith("Create")).length, 2);
});
test("A2 is read-only, aged, eligible and cannot settle unknown creation on 404", async () => {
  const ledger = createLedger();
  const name = "projects/fireemu-oracle-idp/topics/fe123456abcdef-test";
  const id = ledger.sent({ name, action: "create", transport: "rest" });
  ledger.answered({ name, action: "create", transport: "rest", requestId: id, kind: "unknown" });
  const world = fakeWorld();
  await assert.rejects(
    recoverA2({ wire: world, ledger, runId: "123456abcdef", elapsedMs: 599999 }),
    /age/,
  );
  const result = await recoverA2({ wire: world, ledger, runId: "123456abcdef", elapsedMs: 600000 });
  assert.equal(result.closed, false);
  assert.ok(world.calls.every((call) => call.method.startsWith("Get")));
  assert.equal(world.calls.length, 1);
});

const { main, parseArgs } = await import("./pubsub-observation/record.mjs");
const { verifyScope, scopeDigest, verifyProof } =
  await import("./pubsub-observation/admission.mjs");
test("default recorder path is prepare-only and creates no credentials or wire", async () => {
  const events = [];
  const descriptor = await main([], {
    describe: () => {
      events.push("describe");
      return { suite: "prepared" };
    },
    createCredentials: () => {
      events.push("credentials");
      throw new Error("must not execute");
    },
    print: (value) => events.push(value.suite),
  });
  assert.deepEqual(events, ["describe", "prepared"]);
  assert.equal(descriptor.suite, "prepared");
  assert.throws(() => parseArgs(["--max-requests", "999"]), /unknown/);
  assert.throws(() => parseArgs(["--record"]), /required/);
});
test("source-bound scope rejects altered caps and requires exact APPROVE scope SHA", () => {
  const scope = {
    taskId: "PUBSUB-OBSERVATION-A",
    suite: "pubsub-observation-a-v1",
    envelopeId: "PUBSUB-OBSERVATION-A-V1",
    sourceHead: "a".repeat(40),
    descriptorSha256: "b".repeat(64),
    packetSha256: "c".repeat(64),
    project: "fireemu-oracle-idp",
    runIds: ["123456abcdef", "123456abcdee"],
    runOutputs: { "123456abcdef": "/fixture/run1", "123456abcdee": "/fixture/run2" },
    recoveryOutputs: { "123456abcdef": "/fixture/a2run1", "123456abcdee": "/fixture/a2run2" },
    expiresAt: "2099-01-01T00:00:00Z",
    plan: makePlan(),
  };
  verifyScope(
    scope,
    { head: scope.sourceHead },
    scope.descriptorSha256,
    { runId: scope.runIds[0], out: "/fixture/run1" },
    0,
  );
  const wrong = structuredClone(scope);
  wrong.plan.caps.totalRequests++;
  assert.throws(
    () =>
      verifyScope(
        wrong,
        { head: scope.sourceHead },
        scope.descriptorSha256,
        { runId: scope.runIds[0], out: "/fixture/run1" },
        0,
      ),
    /plan/,
  );
  const row = { ...scope, kind: "E", state: "APPROVED" };
  const line = `| PUBSUB-OBSERVATION-A envelope | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${scopeDigest(row)} |`;
  verifyProof(row, line, scope, "E");
  assert.throws(
    () => verifyProof(row, line.replace("decision=APPROVE", "decision=DRAFT"), scope, "E"),
    /approve/,
  );
  assert.throws(() => verifyProof({ ...row, plan: wrong.plan }, line, scope, "E"), /scope/);
});

test("complete source CLI arguments parse; prepare rejects live arguments", () => {
  const args = [
    "--record",
    ...["authority", "descriptor", "packet", "E", "V", "lock", "run-id", "out"].flatMap((name) => [
      `--${name}`,
      name === "run-id" ? "123456abcdef" : `/fixture/${name}`,
    ]),
  ];
  assert.equal(parseArgs(args).mode, "record");
  assert.throws(() => parseArgs(["--prepare", "--authority", "/fixture/authority"]), /prepare/);
});
test("REST subscription update uses the request subscription name and field mask", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells.find((item) => item.id === "R3"));
  let sent;
  const wire = createWire({
    meter,
    journal: { write() {} },
    getToken: async () => "fake",
    client: { close() {} },
    fetch: async (url, options) => {
      sent = { url, ...options };
      return new Response("{}", { status: 200 });
    },
  });
  await wire.call({
    category: "target",
    transport: "rest",
    service: "Subscriber",
    method: "UpdateSubscription",
    request: {
      subscription: {
        name: "projects/fixture/subscriptions/fe123456abcdef-a",
        labels: { env: "test" },
      },
      updateMask: "labels",
    },
  });
  assert.equal(sent.method, "PATCH");
  assert.ok(sent.url.endsWith("/subscriptions/fe123456abcdef-a"));
  assert.equal(JSON.parse(sent.body).updateMask, "labels");
  wire.close();
});

const { readFileSync } = await import("node:fs");
test("resource ownership replays both recorded route sets and rejects nearby name and status shapes", () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL("./pubsub-observation/fixtures/recorded-resources.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(fixture.records.length, 16);
  for (const record of fixture.records) {
    const response = record.response;
    if (record.route.startsWith("GET ")) {
      const name = response.body.name,
        ledger = createLedger();
      const id = ledger.sent({ name, action: "create", transport: "rest" });
      ledger.answered({
        name,
        action: "create",
        transport: "rest",
        requestId: id,
        kind: "unknown",
      });
      assert.equal(
        ledger.observeRead(name, { ...response, ok: true, code: "OK" }),
        true,
        `${record.runId}/n${record.n}`,
      );
      assert.equal(
        ledger.observeRead(`${name}-nearby`, { ...response, ok: true, code: "OK" }),
        false,
      );
      for (const status of [199, 302, 503])
        assert.equal(
          ledger.observeRead(name, { ...response, status, ok: true, code: "OK" }),
          false,
        );
    } else if (record.route.startsWith("GET404")) {
      const name = "projects/redacted-project/topics/resource",
        ledger = createLedger();
      const id = ledger.sent({ name, action: "create", transport: "rest" });
      ledger.answered({
        name,
        action: "create",
        transport: "rest",
        requestId: id,
        kind: "unknown",
      });
      assert.equal(
        ledger.settleAbsent(
          name,
          { ...response, ok: false, code: response.body.error.status },
          { a2ElapsedMs: 600000 },
        ),
        false,
      );
    } else assert.equal(response.status, 200);
  }
});
test("path/body mismatch tracks only the complete witnessed own identity and cleans it", async () => {
  const meter = createMeter({ now: () => 0 });
  const cell = makePlan().cells.find((item) => item.id === "R1");
  meter.enter(cell);
  const world = fakeWorld();
  const ledger = createLedger();
  const result = await runCell({
    cell,
    meter,
    wire: world,
    ledger,
    runId: "123456abcdef",
    journal: { write() {} },
  });
  assert.equal(result.complete, true);
  assert.equal(result.cleanupClosed, true);
  const deletes = world.calls.filter((call) => call.method === "DeleteTopic");
  assert.equal(deletes.length, 1);
  assert.ok(deletes[0].request.name.endsWith("-body"));
  assert.equal(world.resources.size, 0);
});
test("late absence and sticky unknown delete require the original aged A2 read", async () => {
  for (const action of ["create", "delete"]) {
    const ledger = createLedger(),
      name = "projects/fireemu-oracle-idp/topics/fe123456abcdef-test";
    const create = ledger.sent({ name, action: "create", transport: "rest" });
    ledger.answered({ name, action: "create", transport: "rest", requestId: create, kind: "ok" });
    if (action === "delete") {
      const id = ledger.sent({ name, action: "delete", transport: "rest" });
      ledger.answered({
        name,
        action: "delete",
        transport: "rest",
        requestId: id,
        kind: "unknown",
      });
    }
    const absent = {
      ok: false,
      status: 404,
      code: "NOT_FOUND",
      body: { error: { status: "NOT_FOUND" } },
    };
    assert.equal(ledger.settleAbsent(name, absent), false);
    const world = fakeWorld();
    const recovered = await recoverA2({
      wire: world,
      ledger,
      runId: "123456abcdef",
      elapsedMs: 600000,
    });
    assert.equal(recovered.closed, true);
    assert.equal(world.calls.length, 1);
    assert.equal(world.calls[0].method, "GetTopic");
  }
});

test("nonadjacent cell reuse and source clock exhaustion refuse a new dispatch", () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock });
  const plan = makePlan();
  meter.enter(plan.cells[0]);
  meter.enter(plan.cells[1]);
  assert.throws(() => meter.enter(plan.cells[0]), /reopen/);
  clock = plan.caps.sourceWallMs;
  assert.throws(() => meter.enter(plan.cells[2]), /time/);
  assert.equal(meter.snapshot().requests, 0);
});
test("foreign creation bodies and unknown path aliases never authorize a DELETE", async () => {
  for (const variant of ["foreign", "unknown"]) {
    const meter = createMeter({ now: () => 0 }),
      cell = makePlan().cells.find((item) => item.id === "R1");
    meter.enter(cell);
    const world = fakeWorld();
    const original = world.call;
    world.call = async (call) =>
      call.method === "CreateTopic"
        ? variant === "foreign"
          ? { ok: true, code: "OK", body: { name: "projects/foreign/topics/do-not-adopt" } }
          : { ok: false, unknown: true, code: "UNKNOWN", body: {} }
        : original(call);
    const result = await runCell({
      cell,
      meter,
      wire: world,
      ledger: createLedger(),
      runId: "123456abcdef",
      journal: { write() {} },
    });
    assert.equal(result.complete, false);
    assert.equal(result.cleanupClosed, false);
    assert.equal(world.calls.filter((call) => call.method.startsWith("Delete")).length, 0);
  }
});

test("all baseline cell drivers execute their exact requests and causal stream stimuli inside vectors", async () => {
  for (const cell of makePlan().cells.filter((item) => !item.reserve)) {
    const clock = { value: Number(process.env.OBSERVATION_TEST_CLOCK_MS ?? 0) },
      meter = createMeter({ now: () => clock.value });
    meter.enter(cell);
    const world = fakeWorld(),
      original = world.call,
      published = [];
    let delivered = [],
      credit = true,
      terminal = null,
      update = null;
    world.call = async (call) => {
      meter.start(call.category, call.transport);
      clock.value += 50;
      if (call.method === "Publish") {
        meter.payload(encodedSizes(call.request.topic, call.request.messages).payload);
        const messageId = `message-${published.length + 1}`;
        published.push({ messageId, data: call.request.messages[0].data });
        return { ok: true, code: "OK", body: { messageIds: [messageId] } };
      }
      if (call.method === "Pull")
        return { ok: true, code: "OK", body: { receivedMessages: delivered.slice(0, 1) } };
      return original(call);
    };
    const inputs = [],
      events = [];
    world.open = async ({ opener }) => {
      let controlSent = false;
      meter.start("stream", "streams");
      const begin = clock.value;
      const write = (body) => {
        meter.frame(
          "out",
          protos.google.pubsub.v1.StreamingPullRequest.encode(
            protos.google.pubsub.v1.StreamingPullRequest.fromObject(body),
          ).finish().length,
        );
        inputs.push(body);
        if (body.ackIds) credit = true;
        if (body.modifyDeadlineAckIds) {
          update = body.modifyDeadlineSeconds;
          if (update[0] === 0) delivered = [];
        }
      };
      write(opener);
      if (
        !opener.subscription ||
        opener.streamAckDeadlineSeconds === 601 ||
        cell.variant === "missing-subscription"
      )
        terminal = { code: 3 };
      if (opener.streamAckDeadlineSeconds === 0) terminal = { code: 0 };
      return {
        write,
        end: () => events.push("end"),
        cancel: () => events.push("cancel"),
        dispose() {},
        state: () => ({ windowMs: 90000, incomplete: false, terminal }),
        next: async (delay = 90000) => {
          if (terminal) return null;
          if (!controlSent && published.length) {
            controlSent = true;
            meter.frame("in", 0);
            return {};
          }
          const next = published.find(
            (message) => !delivered.some((item) => item.message.messageId === message.messageId),
          );
          if (credit && next) {
            const item = { ackId: `received-${next.messageId}`, message: next };
            delivered.push(item);
            credit = cell.variant !== "flow-control";
            meter.frame(
              "in",
              protos.google.pubsub.v1.StreamingPullResponse.encode(
                protos.google.pubsub.v1.StreamingPullResponse.fromObject({
                  receivedMessages: [item],
                }),
              ).finish().length,
            );
            return { receivedMessages: [item] };
          }
          clock.value = Math.min(begin + 90000, clock.value + delay);
          return null;
        },
      };
    };
    const result = await runCell({
      cell,
      meter,
      wire: world,
      ledger: createLedger(),
      runId: "123456abcdef",
      journal: { write() {} },
      sleep: async (ms) => {
        clock.value += ms;
      },
    });
    assert.equal(result.complete, true, `${cell.id}: ${result.reason}`);
    assert.equal(result.cleanupClosed, true, cell.id);
    assert.ok(meter.snapshot().requests <= (cell.group === "G4" ? 18 : 12));
    if (cell.variant === "half-close") assert.ok(events.includes("end"));
    if (cell.variant === "client-cancel") assert.ok(events.includes("cancel"));
    if (cell.variant === "in-stream-nack") assert.deepEqual(update, [0]);
    if (cell.variant === "invalid-update-frame") assert.deepEqual(update, [-1]);
    if (cell.variant === "update-array-length") assert.deepEqual(update, []);
    if (cell.variant === "update-deadline-601") assert.deepEqual(update, [601]);
    if (cell.variant === "invalid-ack-silence")
      assert.deepEqual(inputs.at(-1), { ackIds: ["invalid-ack-for-stream-observation"] });
  }
});

test("native unary rejects a valid oversized protobuf response before decoding it", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells.find((item) => item.id === "N3"));
  const response = Buffer.from(
    protos.google.pubsub.v1.Topic.encode(
      protos.google.pubsub.v1.Topic.fromObject({
        name: "projects/fixture/topics/fe123456abcdef-a",
        labels: { huge: "a".repeat(65536) },
      }),
    ).finish(),
  );
  const wire = createWire({
    meter,
    journal: { write() {} },
    getToken: async () => "fake",
    client: {
      close() {},
      makeUnaryRequest(...args) {
        const rpc = new EventEmitter();
        rpc.cancel = () => {};
        queueMicrotask(() => {
          args.at(-1)(null, response);
          rpc.emit("status", { code: 0, details: "" });
        });
        return rpc;
      },
    },
  });
  const reply = await wire.call({
    category: "get",
    transport: "grpc",
    service: "Publisher",
    method: "GetTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  });
  assert.equal(reply.unknown, true);
  wire.close();
});

test("prior-run closure pin is part of the ledger-approved proof scope", () => {
  const scope = { envelopeId: "PUBSUB-OBSERVATION-A-V1", previousAttempt: null };
  const row = { ...scope, kind: "E", state: "APPROVED" };
  const line = `| PUBSUB-OBSERVATION-A envelope | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${scopeDigest(row)} |`;
  verifyProof(row, line, scope, "E");
  assert.throws(
    () =>
      verifyProof(
        { ...row, previousAttempt: { path: "/fixture/forged", sha256: "a".repeat(64) } },
        line,
        scope,
        "E",
      ),
    /scope/,
  );
});

test("source abort cancels an actual pending REST request while permitting bounded cleanup", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  let dispatched = false;
  const wire = createWire({
    meter,
    journal: { write() {} },
    getToken: async () => "fake",
    client: { close() {} },
    fetch: async (_url, { signal, method }) => {
      if (method === "GET") return new Response("{}", { status: 200 });
      dispatched = true;
      return new Promise((_, reject) =>
        signal.addEventListener("abort", () => reject(new Error("test aborted")), { once: true }),
      );
    },
  });
  const call = {
    category: "create",
    transport: "rest",
    service: "Publisher",
    method: "CreateTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  };
  const pending = wire.call(call);
  while (!dispatched) await new Promise((resolve) => setImmediate(resolve));
  wire.abortSource();
  const reply = await pending;
  assert.equal(reply.unknown, true);
  await assert.rejects(wire.call(call), /source stopped/);
  await wire.call({ ...call, category: "cleanupGet", method: "GetTopic" });
  assert.equal(meter.snapshot().requests, 2);
  wire.close();
});

test("REST metadata reservation includes headers and response framing reserve", async () => {
  const response = new Response("a".repeat(62000), { headers: { etag: "e".repeat(1000) } });
  await assert.rejects(readResponse(response), /response byte/);
});

test("native request duration uses the meter clock rather than wall clock adjustments", async () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells.find((item) => item.id === "N3"));
  const raw = Buffer.from(
    protos.google.pubsub.v1.Topic.encode({
      name: "projects/fixture/topics/fe123456abcdef-a",
    }).finish(),
  );
  const wire = createWire({
    meter,
    journal: { write() {} },
    getToken: async () => "fake",
    now: () => 1000,
    client: {
      close() {},
      makeUnaryRequest(...args) {
        const rpc = new EventEmitter();
        rpc.cancel = () => {};
        queueMicrotask(() => {
          clock += 5;
          args.at(-1)(null, raw);
          rpc.emit("status", { code: 0, details: "" });
        });
        return rpc;
      },
    },
  });
  const reply = await wire.call({
    category: "get",
    transport: "grpc",
    service: "Publisher",
    method: "GetTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  });
  assert.equal(reply.durationMs, 5);
  wire.close();
});

test("a mutation with less than the recorded latency margin is refused before credentials", async () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells.find((item) => item.id === "R3"));
  clock = 50000;
  let tokens = 0,
    dispatches = 0;
  const wire = createWire({
    meter,
    journal: { write() {} },
    getToken: async () => {
      tokens++;
      return "fake";
    },
    client: { close() {} },
    fetch: async () => {
      dispatches++;
      return new Response("{}");
    },
  });
  await assert.rejects(
    wire.call({
      category: "create",
      transport: "rest",
      service: "Publisher",
      method: "CreateTopic",
      request: { name: "projects/fixture/topics/fe123456abcdef-a" },
    }),
    /latency margin/,
  );
  assert.equal(tokens, 0);
  assert.equal(dispatches, 0);
  wire.close();
});

test("late native lifecycle callbacks cannot write a disposed journal", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  const rpc = new EventEmitter();
  rpc.write = () => true;
  rpc.cancel = () => {};
  rpc.end = () => {};
  let closed = false;
  const journal = {
    write() {
      if (closed) throw new Error("closed journal");
    },
    frame() {},
  };
  const stream = await openStream({
    meter,
    client: { makeBidiStreamRequest: () => rpc },
    journal,
    credential: async () => "fake",
    now: () => 1,
    cellId: "S01",
    opener: {
      subscription: "projects/fixture/subscriptions/fe123456abcdef-a",
      streamAckDeadlineSeconds: 10,
    },
  });
  stream.dispose();
  closed = true;
  for (const event of ["status", "end", "close", "error"])
    assert.doesNotThrow(() => rpc.emit(event, { code: 1 }));
});

test("setup GET with a foreign response name stops before target writes", async () => {
  const meter = createMeter({ now: () => 0 }),
    cell = makePlan().cells.find((item) => item.id === "R3");
  meter.enter(cell);
  const world = fakeWorld(),
    original = world.call;
  world.call = async (call) =>
    call.category === "get"
      ? { ok: true, code: "OK", body: { name: "projects/foreign/topics/other" } }
      : original(call);
  const result = await runCell({
    cell,
    meter,
    wire: world,
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: { write() {} },
  });
  assert.equal(result.complete, false);
  assert.equal(
    world.calls.some((call) => call.category === "target"),
    false,
  );
});

test("wire revalidates authority after asynchronous credentials before dispatch", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells.find((item) => item.id === "R3"));
  let valid = true,
    dispatches = 0,
    checks = 0;
  const wire = createWire({
    meter,
    journal: { write() {} },
    getToken: async () => {
      valid = false;
      return "fake";
    },
    beforeDispatch: () => {
      checks++;
      if (!valid) throw new Error("authority changed");
    },
    client: { close() {} },
    fetch: async () => {
      dispatches++;
      return new Response("{}");
    },
  });
  const reply = await wire.call({
    category: "get",
    transport: "rest",
    service: "Publisher",
    method: "GetTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  });
  assert.equal(reply.unknown, true);
  assert.equal(dispatches, 0);
  assert.equal(checks, 1);
  wire.close();
});

test("stream revalidates authority after asynchronous credentials before opening", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  let dispatches = 0;
  await assert.rejects(
    openStream({
      meter,
      credential: async () => "fake",
      beforeDispatch: () => {
        throw new Error("authority changed");
      },
      client: {
        makeBidiStreamRequest() {
          dispatches++;
          throw new Error("unexpected dispatch");
        },
      },
      journal: { write() {}, frame() {} },
      cellId: "S01",
      opener: {},
    }),
    /authority changed/,
  );
  assert.equal(dispatches, 0);
});

test("durable dispatch time is charged before a request can enter the wire", async () => {
  let clock = 0,
    dispatches = 0;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells.find((item) => item.id === "R3"));
  const wire = createWire({
    meter,
    journal: {
      write(row) {
        if (row.event === "request-dispatch") clock = 50000;
      },
    },
    getToken: async () => "fake",
    client: { close() {} },
    fetch: async () => {
      dispatches++;
      return new Response("{}");
    },
  });
  const reply = await wire.call({
    category: "create",
    transport: "rest",
    service: "Publisher",
    method: "CreateTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  });
  assert.equal(reply.unknown, true);
  assert.equal(dispatches, 0);
  wire.close();
});

test("unavailable stream status cannot become a complete production witness", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  const rpc = new EventEmitter();
  rpc.write = () => true;
  rpc.cancel = () => {};
  rpc.end = () => {};
  const stream = await openStream({
    meter,
    client: { makeBidiStreamRequest: () => rpc },
    journal: { write() {}, frame() {} },
    credential: async () => "fake",
    cellId: "S01",
    opener: {
      subscription: "projects/fixture/subscriptions/fe123456abcdef-a",
      streamAckDeadlineSeconds: 10,
    },
  });
  try {
    rpc.emit("status", { code: 14 });
    assert.equal(stream.state().incomplete, true);
  } finally {
    stream.dispose();
  }
});

test("normal opener cannot be complete merely because the server rejected the stream", async () => {
  const meter = createMeter({ now: () => 0 }),
    cell = makePlan().cells[0];
  meter.enter(cell);
  const world = fakeWorld();
  world.open = async () => ({
    next: async () => null,
    dispose() {},
    state: () => ({ incomplete: false, terminal: { code: 3 } }),
  });
  const result = await runCell({
    cell,
    meter,
    wire: world,
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: { write() {} },
  });
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, true);
});

test("every later outbound stream frame revalidates current authority", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  const rpc = new EventEmitter();
  let valid = true,
    writes = 0;
  rpc.write = () => {
    writes++;
    return true;
  };
  rpc.cancel = () => {};
  rpc.end = () => {};
  const stream = await openStream({
    meter,
    client: { makeBidiStreamRequest: () => rpc },
    journal: { write() {}, frame() {} },
    credential: async () => "fake",
    beforeDispatch: () => {
      if (!valid) throw new Error("authority changed");
    },
    cellId: "S01",
    opener: {
      subscription: "projects/fixture/subscriptions/fe123456abcdef-a",
      streamAckDeadlineSeconds: 10,
    },
  });
  try {
    valid = false;
    assert.throws(() => stream.write({ ackIds: ["own-observed-ack"] }), /authority changed/);
    assert.equal(writes, 1);
  } finally {
    stream.dispose();
  }
});

test("stream persistence exhausting the window refuses physical opening", async () => {
  let clock = 0,
    opens = 0;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells[0]);
  await assert.rejects(
    openStream({
      meter,
      credential: async () => "fake",
      client: {
        makeBidiStreamRequest() {
          opens++;
          throw new Error("unexpected dispatch");
        },
      },
      journal: {
        write(row) {
          if (row.event === "stream-dispatch") clock += 140000;
        },
        frame() {},
      },
      cellId: "S01",
      opener: {},
    }),
    /time exhausted/,
  );
  assert.equal(opens, 0);
});

test("actual main wires admission to dispatch and keeps the parent open after signal or unknown write", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  for (const signal of [false, true]) {
    const out = mkdtempSync(join(tmpdir(), "pubsub-obsa-main-")),
      runId = "123456abcdef",
      signals = new EventEmitter();
    let code, guard;
    try {
      const summary = await main(
        [
          "--record",
          ...Object.entries({
            authority: "fixture",
            descriptor: "fixture",
            packet: "fixture",
            E: "fixture",
            V: "fixture",
            lock: "fixture",
            "run-id": runId,
            out,
          }).flatMap(([k, v]) => [`--${k}`, v]),
        ],
        {
          admit: () => ({
            plan: makePlan(),
            check() {},
            descriptor: { head: "a".repeat(40) },
            descriptorSha256: "b".repeat(64),
            scope: { envelopeId: "FIXTURE-A", packetSha256: "c".repeat(64) },
          }),
          createCredentials: () => async () => "fake",
          signals,
          setExitCode: (value) => {
            code = value;
          },
          createWire: (options) => {
            guard = options.beforeDispatch;
            return {
              close() {},
              abortSource() {},
              open: async () => {
                throw new Error("no stream");
              },
              call: async (call) => {
                if (call.category === "create") {
                  if (signal) signals.emit("SIGTERM");
                  return { ok: false, unknown: true, code: "UNKNOWN", body: {} };
                }
                return {
                  ok: false,
                  status: 404,
                  code: "NOT_FOUND",
                  body: { error: { status: "NOT_FOUND" } },
                };
              },
            };
          },
        },
      );
      assert.equal(typeof guard, "function");
      assert.equal(summary.parentClosureReady, false);
      assert.equal(summary.resourcesClosed, false);
      assert.equal(code, 2);
      assert.equal(signals.listenerCount("SIGTERM"), 0);
      assert.equal(signals.listenerCount("SIGINT"), 0);
      assert.equal(
        JSON.parse(readFileSync(join(out, `summary-${runId}.json`))).parentClosureReady,
        false,
      );
    } finally {
      rmSync(out, { recursive: true });
    }
  }
});

test("owned delivery selection properties exclude missing data and unknown identities", () => {
  for (let seed = 1; seed <= 256; seed++) {
    const id = `own-${seed}`,
      data = Buffer.from(`marker-${seed}`).toString("base64"),
      published = new Map([[id, data]]);
    const messages = [
      { ackId: "valid", message: { messageId: id, data } },
      { ackId: "other", message: { messageId: `foreign-${seed}` } },
      { ackId: "missing", message: { messageId: id } },
      { ackId: "", message: { messageId: id, data } },
      { ackId: "changed", message: { messageId: id, data: `${data}x` } },
    ];
    assert.deepEqual(selectOwn({ receivedMessages: messages }, published), [messages[0]]);
  }
});

test("REST cancellation uses the absolute remaining deadline after durable persistence", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let clock = 0,
    dispatched = false,
    aborted = false;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells.find((item) => item.id === "R3"));
  const wire = createWire({
    meter,
    now: () => 1000000 + clock,
    journal: {
      write(row) {
        if (row.event === "request-dispatch") clock += 5000;
      },
    },
    getToken: async () => "fake",
    client: { close() {} },
    fetch: async (_, options) => {
      dispatched = true;
      return new Promise((_, reject) =>
        options.signal.addEventListener(
          "abort",
          () => {
            aborted = true;
            reject(new Error("deadline reached"));
          },
          { once: true },
        ),
      );
    },
  });
  context.after(() => {
    wire.abortSource();
    wire.close();
  });
  const pending = wire.call({
    category: "get",
    transport: "rest",
    service: "Publisher",
    method: "GetTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  });
  while (!dispatched) await new Promise((done) => setImmediate(done));
  context.mock.timers.tick(24999);
  assert.equal(aborted, false);
  clock += 25000;
  context.mock.timers.tick(1);
  assert.equal(aborted, true);
  const reply = await pending;
  assert.equal(reply.unknown, true);
  assert.equal(reply.durationMs, 30000);
  wire.close();
});

test("stream dispatch persistence clips the effective window within the original cell", async () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells[0]);
  const rpc = new EventEmitter();
  rpc.write = () => true;
  rpc.cancel = () => {};
  rpc.end = () => {};
  const stream = await openStream({
    meter,
    credential: async () => "fake",
    client: { makeBidiStreamRequest: () => rpc },
    journal: {
      write(row) {
        if (row.event === "stream-dispatch") clock += 100000;
      },
      frame() {},
    },
    cellId: "S01",
    opener: {},
  });
  try {
    assert.equal(stream.state().windowMs, 39999);
    assert.equal(stream.state().preDispatchMs, 100000);
    assert.equal(stream.state().incomplete, true);
  } finally {
    stream.dispose();
  }
});

test("intentional local cancellation is distinct from unrelated uncertain transport statuses", async () => {
  for (const code of [1, 2, 4, 8, 13, 14, 15]) {
    const meter = createMeter({ now: () => 0 });
    meter.enter(makePlan().cells[0]);
    const rpc = new EventEmitter();
    rpc.write = () => true;
    rpc.cancel = () => {};
    rpc.end = () => {};
    const stream = await openStream({
      meter,
      credential: async () => "fake",
      client: { makeBidiStreamRequest: () => rpc },
      journal: { write() {}, frame() {} },
      cellId: "S01",
      opener: {},
    });
    try {
      stream.cancel("unacked-owned-delivery");
      rpc.emit("status", { code });
      assert.equal(stream.state().incomplete, code !== 1);
    } finally {
      stream.dispose();
    }
  }
});

test("native unary aggregates headers, body and trailers before accepting success", async () => {
  const { default: grpc } = await import("@grpc/grpc-js");
  const initial = new grpc.Metadata(),
    trailing = new grpc.Metadata();
  initial.add("x-first", "a".repeat(20000));
  trailing.add("x-last", "b".repeat(45000));
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells.find((item) => item.id === "N3"));
  const raw = Buffer.from(
    protos.google.pubsub.v1.Topic.encode({
      name: "projects/fixture/topics/fe123456abcdef-a",
    }).finish(),
  );
  const wire = createWire({
    meter,
    journal: { write() {} },
    getToken: async () => "fake",
    client: {
      close() {},
      makeUnaryRequest(...args) {
        const rpc = new EventEmitter();
        rpc.cancel = () => {};
        queueMicrotask(() => {
          rpc.emit("metadata", initial);
          args.at(-1)(null, raw);
          rpc.emit("status", { code: 0, details: "", metadata: trailing });
        });
        return rpc;
      },
    },
  });
  const reply = await wire.call({
    category: "get",
    transport: "grpc",
    service: "Publisher",
    method: "GetTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  });
  assert.equal(reply.unknown, true);
  wire.close();
});

test("stream metadata includes both initial headers and trailing metadata", async () => {
  const { default: grpc } = await import("@grpc/grpc-js");
  const first = new grpc.Metadata(),
    last = new grpc.Metadata();
  first.add("x-first", "a".repeat(20000));
  last.add("x-last", "b".repeat(45000));
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  const rpc = new EventEmitter();
  rpc.write = () => true;
  rpc.cancel = () => {};
  rpc.end = () => {};
  const stream = await openStream({
    meter,
    credential: async () => "fake",
    client: { makeBidiStreamRequest: () => rpc },
    journal: { write() {}, frame() {} },
    cellId: "S01",
    opener: {},
  });
  try {
    rpc.emit("metadata", first);
    rpc.emit("status", { code: 0, details: "", metadata: last });
    assert.equal(stream.state().incomplete, true);
  } finally {
    stream.dispose();
  }
});

test("over-budget stream credentials are refused before physical opening", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  const rpc = new EventEmitter();
  rpc.write = () => true;
  rpc.cancel = () => {};
  rpc.end = () => {};
  let opens = 0,
    stream;
  try {
    await assert.rejects(async () => {
      stream = await openStream({
        meter,
        credential: async () => "x".repeat(65537),
        client: {
          makeBidiStreamRequest: () => {
            opens++;
            return rpc;
          },
        },
        journal: { write() {}, frame() {} },
        cellId: "S01",
        opener: {},
      });
    }, /metadata/);
    assert.equal(opens, 0);
  } finally {
    stream?.dispose();
  }
});

test("response persistence overrun retains its actual answer and stops cell completion", async () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells.find((item) => item.id === "R3"));
  const wire = createWire({
    meter,
    journal: {
      write(row) {
        if (row.event === "response") clock = 120000;
      },
    },
    getToken: async () => "fake",
    client: { close() {} },
    fetch: async () => new Response('{"name":"projects/fixture/topics/fe123456abcdef-a"}'),
  });
  const reply = await wire.call({
    category: "get",
    transport: "rest",
    service: "Publisher",
    method: "GetTopic",
    request: { name: "projects/fixture/topics/fe123456abcdef-a" },
  });
  assert.equal(reply.ok, true);
  assert.equal(reply.budgetOverrun, true);
  assert.throws(() => meter.enter(makePlan().cells[0]), /time/);
  wire.close();
});

test("final settlement and case-result fsync overruns cannot advance the next cell", async () => {
  for (const at of ["settlement", "case-result"]) {
    let clock = 0;
    const meter = createMeter({ now: () => clock }),
      cell = makePlan().cells.find((item) => item.id === "R3");
    meter.enter(cell);
    const ledger = createLedger({
      journal: {
        write(row) {
          if (
            at === "settlement" &&
            row.phase === "resolved" &&
            row.resolution === "gone" &&
            row.name.endsWith("-topic")
          )
            clock = 120000;
        },
      },
    });
    const result = await runCell({
      cell,
      meter,
      wire: fakeWorld(),
      ledger,
      runId: "123456abcdef",
      journal: {
        write(row) {
          if (at === "case-result" && row.event === "case-result") clock = 120000;
        },
      },
    });
    assert.equal(result.complete, false, at);
    assert.equal(result.cleanupClosed, true, at);
    assert.throws(() => meter.enter(makePlan().cells[0]), /time/);
  }
});

test("metadata byte properties preserve repeated UTF-8 and binary value widths", async () => {
  const { metadataBytes } = await import("./pubsub-observation/metadata.mjs"),
    { default: grpc } = await import("@grpc/grpc-js");
  for (let seed = 0; seed < 256; seed++) {
    const metadata = new grpc.Metadata(),
      binary = Buffer.from("é".repeat(seed)),
      values = ["ascii-%C3%A9", String(seed)];
    for (const value of values) metadata.add("x-text", value);
    metadata.add("x-bin", binary);
    const raw =
      values.map((value) => `x-text: ${value}\r\n`).join("") +
      `x-bin: ${binary.toString("base64")}\r\n`;
    assert.equal(metadataBytes(metadata), Buffer.byteLength(raw));
    const details = `é message ${seed}`;
    assert.ok(
      metadataBytes(metadata, details) >=
        Buffer.byteLength(raw) + Buffer.byteLength(encodeURIComponent(details)),
    );
  }
});

test("uncertain native CREATE failures retain an outstanding ownership obligation", async () => {
  for (const code of [1, 2, 4, 8, 13, 14, 15]) {
    const meter = createMeter({ now: () => 0 }),
      cell = makePlan().cells.find((item) => item.id === "N3"),
      ledger = createLedger(),
      applied = new Set();
    meter.enter(cell);
    const wire = createWire({
      meter,
      journal: { write() {} },
      getToken: async () => "fake",
      client: {
        close() {},
        makeUnaryRequest(...args) {
          if (args[0].endsWith("/CreateTopic")) applied.add("remotely-created-topic");
          const rpc = new EventEmitter();
          rpc.cancel = () => {};
          queueMicrotask(() => {
            args.at(-1)({
              code,
              details: code === 8 ? "Received message larger than max" : "lost result",
            });
            rpc.emit("status", { code, details: "lost result" });
          });
          return rpc;
        },
      },
    });
    try {
      const result = await runCell({
        cell,
        meter,
        wire,
        ledger,
        runId: "123456abcdef",
        journal: { write() {} },
      });
      assert.equal(applied.size, 1, String(code));
      assert.equal(result.complete, false, String(code));
      assert.equal(result.cleanupClosed, false, String(code));
      assert.ok(
        ledger.outstanding().some((item) => item.action === "create"),
        String(code),
      );
    } finally {
      wire.close();
    }
  }
});

test("last target persistence overrun stays incomplete even when cleanup fits the reserve", async () => {
  let clock = 0,
    targetReads = 0;
  const meter = createMeter({ now: () => clock }),
    cell = makePlan().cells.find((item) => item.id === "R3"),
    world = fakeWorld();
  meter.enter(cell);
  const result = await runCell({
    cell,
    meter,
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: { write() {} },
    wire: {
      async call(call) {
        const reply = await world.call(call);
        if (call.category === "target" && call.method === "GetSubscription" && ++targetReads === 2)
          clock = 80000;
        return reply;
      },
    },
  });
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, true);
  assert.equal(result.budgetOverrun, true);
  assert.ok(meter.remaining(true) > 0);
});

test("six early control frames cannot complete the invalid-ACK silence interval", async () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock }),
    cell = makePlan().cells.find((item) => item.variant === "invalid-ack-silence"),
    world = fakeWorld();
  meter.enter(cell);
  world.open = async () => ({
    write() {},
    dispose() {},
    async next() {
      clock += 100;
      return {};
    },
    state: () => ({ windowMs: 90000, incomplete: false, terminal: null }),
  });
  const result = await runCell({
    cell,
    meter,
    wire: world,
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: { write() {} },
  });
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, true);
});

test("source deadline properties also bind a delayed first cell", () => {
  for (let seed = 0; seed < 256; seed++) {
    let clock = 0;
    const meter = createMeter({ now: () => clock }),
      offset = seed - 128;
    clock = CAPS.sourceWallMs + offset;
    if (offset >= 0) assert.throws(() => meter.enter(makePlan().cells[0]), /time/);
    else {
      meter.enter(makePlan().cells[0]);
      assert.equal(meter.remaining(), -offset);
      clock = CAPS.sourceWallMs;
      assert.throws(() => meter.start("create", "rest"), /time/);
    }
  }
});

test("native resource exhaustion after an owned stream delivery stays incomplete", async () => {
  const meter = createMeter({ now: () => 0 }),
    cell = makePlan().cells.find((item) => item.id === "S01"),
    world = fakeWorld();
  meter.enter(cell);
  let payload;
  const original = world.call;
  world.call = async (call) => {
    if (call.method === "Publish") payload = call.request.messages[0].data;
    return original(call);
  };
  world.open = async ({ opener, cellId }) => {
    const rpc = new EventEmitter();
    rpc.cancel = () => {};
    rpc.write = () => {
      queueMicrotask(() => {
        const Type = protos.google.pubsub.v1.StreamingPullResponse;
        rpc.emit(
          "data",
          Buffer.from(
            Type.encode(
              Type.fromObject({
                receivedMessages: [
                  { ackId: "owned-ack", message: { messageId: "own-id", data: payload } },
                ],
              }),
            ).finish(),
          ),
        );
        rpc.emit("error", { code: 8, details: "Received message larger than max" });
        rpc.emit("status", { code: 8, details: "lost terminal result" });
      });
      return true;
    };
    return openStream({
      meter,
      opener,
      cellId,
      credential: async () => "fake",
      journal: { write() {}, frame() {} },
      client: { makeBidiStreamRequest: () => rpc },
    });
  };
  const result = await runCell({
    cell,
    meter,
    wire: world,
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: { write() {} },
  });
  assert.equal(result.complete, false);
  assert.equal(result.cleanupClosed, true);
});

test("native Get/Delete selectors preserve exact generated resource names on all four routes", () => {
  for (const [kind, service, suffix] of [
    ["topics", "Publisher", "Topic"],
    ["subscriptions", "Subscriber", "Subscription"],
  ]) {
    const field = suffix === "Topic" ? "topic" : "subscription";
    for (const verb of ["Get", "Delete"])
      for (let seed = 0; seed < 256; seed++) {
        const name = `projects/fixture-${seed % 17}/${kind}/fe123456abcdef-${seed}-${seed % 2 ? "é" : "e\u0301"}`;
        const method = `${verb}${suffix}`;
        const request = Object.freeze({ name });
        const Type = typeOf(SERVICES[service].methods[method][0]);
        const raw = encodeRequest(service, method, request);
        const decoded = Type.toObject(Type.decode(raw), { defaults: false });
        assert.deepEqual(decoded, { [field]: name }, `${method}/${seed}`);
        assert.deepEqual(request, { name });
        assert.equal(raw.length, Buffer.byteLength(name) + 2);
      }
  }
});

test("native G1 setup update and cleanup traverse decoded protobuf requests", async () => {
  const cell = makePlan().cells.find((item) => item.id === "N3");
  const meter = createMeter({ now: () => 0 });
  meter.enter(cell);
  const world = fakeWorld();
  const methods = [];
  const wire = createWire({
    meter,
    getToken: async () => "fake",
    journal: { write() {} },
    client: {
      close() {},
      makeUnaryRequest(path, _encode, _decode, raw, _metadata, _options, callback) {
        const method = path.split("/").at(-1);
        const service = path.includes("Publisher") ? "Publisher" : "Subscriber";
        const [input, output] = SERVICES[service].methods[method];
        const request = typeOf(input).toObject(typeOf(input).decode(raw), {
          defaults: false,
          bytes: String,
          longs: String,
        });
        methods.push(method);
        const rpc = new EventEmitter();
        rpc.cancel = () => {};
        queueMicrotask(async () => {
          const selector = method.endsWith("Topic") ? "topic" : "subscription";
          if (method.startsWith("Get") || method.startsWith("Delete")) {
            if (typeof request[selector] !== "string" || request[selector].length === 0) {
              callback({ code: 3, details: "missing native resource selector" });
              rpc.emit("status", { code: 3, details: "missing native resource selector" });
              return;
            }
            request.name = request[selector];
          }
          if (method === "UpdateSubscription")
            request.updateMask = request.updateMask.paths.join(",");
          const reply = await world.call({ method, request });
          const Type = typeOf(output);
          callback(
            reply.ok ? null : { code: 5, details: "missing own resource" },
            reply.ok ? Buffer.from(Type.encode(Type.fromObject(reply.body)).finish()) : undefined,
          );
          rpc.emit("status", { code: reply.ok ? 0 : 5, details: "" });
        });
        return rpc;
      },
    },
  });
  try {
    const ledger = createLedger();
    const result = await runCell({
      cell,
      meter,
      wire,
      ledger,
      runId: "123456abcdef",
      journal: { write() {} },
    });
    assert.equal(result.complete, true);
    assert.equal(result.cleanupClosed, true);
    assert.equal(world.resources.size, 0);
    assert.equal(ledger.outstanding().length, 0);
    for (const method of [
      "CreateTopic",
      "CreateSubscription",
      "GetTopic",
      "GetSubscription",
      "UpdateSubscription",
      "DeleteTopic",
      "DeleteSubscription",
    ])
      assert.ok(methods.includes(method), method);
  } finally {
    wire.close();
  }
});

const successorIds = {
  "s10-diagnostic": ["S10"],
  residual: [
    "S11",
    "S12",
    "S13",
    "S14",
    "S15",
    "S16",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "N1",
    "N2",
    "N3",
    "N4",
    "N5",
    "N6",
    "N7",
    "N8",
  ],
};
test("successor plans select only the exact diagnostic and residual domains", async () => {
  const { validatePlan } = await import("./pubsub-observation/plan.mjs");
  const full = makePlan();
  assert.deepEqual(makePlan("full"), full);
  assert.equal(full.selection, undefined);
  for (const [selection, ids] of Object.entries(successorIds)) {
    const selected = makePlan(selection);
    assert.equal(selected.selection, selection);
    assert.deepEqual(
      selected.cells.map((cell) => cell.id),
      ids,
    );
    assert.deepEqual(
      selected.cells,
      ids.map((id) => full.cells.find((cell) => cell.id === id)),
    );
    const { cells: _selectedCells, selection: _selection, ...unchanged } = selected;
    assert.deepEqual(unchanged, (({ cells: _fullCells, ...rest }) => rest)(full));
    assert.doesNotThrow(() => validatePlan(selected));
    for (let seed = 0; seed < 96; seed++) {
      const changed = structuredClone(selected);
      const index = seed % changed.cells.length;
      switch (seed % 6) {
        case 0:
          changed.cells[index].id = `foreign-${seed}`;
          break;
        case 1:
          changed.cells.splice(index, 0, structuredClone(changed.cells[index]));
          break;
        case 2:
          changed.cells.splice(index, 1);
          break;
        case 3:
          changed.cells[index].variant += "-changed";
          break;
        case 4:
          changed.caps.sourceRequests++;
          break;
        case 5:
          changed.selection = `unsupported-${seed}`;
          break;
      }
      assert.throws(() => validatePlan(changed), /plan|selection/, `${selection}/${seed}`);
    }
    if (ids.length > 1) {
      const changed = structuredClone(selected);
      [changed.cells[0], changed.cells[1]] = [changed.cells[1], changed.cells[0]];
      assert.throws(() => validatePlan(changed), /plan/);
    }
  }
  for (const selection of ["", "resume", "S10", null, {}, ["S10"]])
    assert.throws(() => makePlan(selection), /selection/);
});

test("successor packet and authority plans must agree before credentials", async () => {
  const { verifyPacket } = await import("./pubsub-observation/admission.mjs");
  assert.equal(typeof verifyPacket, "function");
  const modes = ["full", "s10-diagnostic", "residual"];
  for (const selected of modes)
    for (const other of modes) {
      const descriptor = { head: "a".repeat(40) };
      const scope = {
        taskId: "PUBSUB-OBSERVATION-A",
        sourceHead: descriptor.head,
        descriptorSha256: "b".repeat(64),
        packetSha256: "c".repeat(64),
        runIds: ["123456abcdef", "123456abcdee"],
        runOutputs: {},
        recoveryOutputs: {},
        plan: makePlan(selected),
      };
      const packet = {
        sha256: scope.packetSha256,
        value: {
          schema: 1,
          taskId: scope.taskId,
          version: "v1",
          sourceHead: scope.sourceHead,
          descriptorSha256: scope.descriptorSha256,
          runIds: scope.runIds,
          runOutputs: scope.runOutputs,
          recoveryOutputs: scope.recoveryOutputs,
          plan: makePlan(other),
        },
      };
      if (selected === other)
        assert.doesNotThrow(() => verifyPacket(packet, scope, descriptor, scope.descriptorSha256));
      else {
        let credentials = 0;
        await assert.rejects(
          main(
            [
              "--record",
              ...Object.entries({
                authority: "unused",
                descriptor: "unused",
                packet: "unused",
                E: "unused",
                V: "unused",
                lock: "unused",
                "run-id": "123456abcdef",
                out: "/unused",
              }).flatMap(([key, value]) => [`--${key}`, value]),
            ],
            {
              admit: () => verifyPacket(packet, scope, descriptor, scope.descriptorSha256),
              createCredentials: () => {
                credentials++;
                throw new Error("unexpected credentials");
              },
            },
          ),
          /packet|plan/,
        );
        assert.equal(credentials, 0);
      }
    }
});

test("successor completion requires exact ordered cell results rather than a count alone", async () => {
  const { isRecordingComplete } = await import("./pubsub-observation/record.mjs");
  assert.equal(typeof isRecordingComplete, "function");
  for (const selection of ["full", ...Object.keys(successorIds)]) {
    const plan = makePlan(selection);
    const rows = plan.cells
      .filter((cell) => !cell.reserve)
      .map((cell) => ({ cellId: cell.id, complete: true, cleanupClosed: true }));
    assert.equal(isRecordingComplete(plan, rows), true);
    for (let seed = 0; seed < 128; seed++) {
      const changed = structuredClone(rows),
        index = seed % rows.length;
      switch (seed % 4) {
        case 0:
          changed[index].cellId = `foreign-${seed}`;
          break;
        case 1:
          changed[index].complete = false;
          break;
        case 2:
          changed.splice(index, 1);
          break;
        case 3:
          changed.push(structuredClone(changed[index]));
          break;
      }
      assert.doesNotThrow(() => {
        assert.equal(isRecordingComplete(plan, changed), false, `${selection}/${seed}`);
      });
    }
    if (rows.length > 1) {
      const changed = structuredClone(rows);
      [changed[0], changed[1]] = [changed[1], changed[0]];
      assert.equal(isRecordingComplete(plan, changed), false);
    }
    assert.equal(
      isRecordingComplete(
        plan,
        rows.map((row) => ({ ...row, cleanupClosed: false })),
      ),
      true,
      "resource closure remains a separate verdict",
    );
  }
});

test("successor actual recorder runs only its admitted domain and keeps incomplete observations open", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  for (const [selection, terminalCode, unknown] of [
    ["s10-diagnostic", 3, null],
    ["s10-diagnostic", 13, null],
    ["residual", 3, null],
    ["residual", 3, "CreateTopic"],
  ]) {
    const plan = makePlan(selection);
    assert.equal(plan.selection, selection);
    const out = mkdtempSync(join(tmpdir(), "pubsub-successor-")),
      runId = "123456abcdef",
      signals = new EventEmitter();
    let exitCode,
      credentials = 0;
    const world = fakeWorld({ unknown });
    try {
      const summary = await main(
        [
          "--record",
          ...Object.entries({
            authority: "fixture",
            descriptor: "fixture",
            packet: "fixture",
            E: "fixture",
            V: "fixture",
            lock: "fixture",
            "run-id": runId,
            out,
          }).flatMap(([key, value]) => [`--${key}`, value]),
        ],
        {
          admit: () => ({
            plan,
            check() {},
            descriptor: { head: "a".repeat(40) },
            descriptorSha256: "b".repeat(64),
            scope: { plan, envelopeId: "FIXTURE-SUCCESSOR", packetSha256: "c".repeat(64) },
          }),
          signals,
          createCredentials: () => {
            credentials++;
            return async () => "fake";
          },
          setExitCode: (code) => {
            exitCode = code;
          },
          createWire: ({ meter }) => {
            const call = world.call.bind(world);
            world.call = async (value) => {
              meter.start(value.category, value.transport);
              return call(value);
            };
            world.close = () => {};
            world.open = async () => {
              meter.start("stream", "streams");
              return {
                write() {},
                dispose() {},
                cancel() {},
                end() {},
                state: () => ({
                  incomplete: terminalCode === 13,
                  terminal: { code: terminalCode },
                }),
                next: async () => {
                  const publish = world.calls.findLast((item) => item.method === "Publish");
                  return publish
                    ? {
                        receivedMessages: [
                          {
                            ackId: "owned-ack",
                            message: {
                              messageId: "own-id",
                              data: publish.request.messages[0].data,
                            },
                          },
                        ],
                      }
                    : null;
                },
              };
            };
            return world;
          },
        },
      );
      const success = terminalCode !== 13 && !unknown;
      assert.deepEqual(
        summary.results.map((row) => row.cellId),
        success ? successorIds[selection] : [successorIds[selection][0]],
      );
      assert.equal(summary.recordingComplete, success);
      assert.equal(summary.resourcesClosed, !unknown);
      assert.equal(summary.parentClosureReady, false);
      assert.deepEqual(summary.recordingDomain, { selection, cellIds: successorIds[selection] });
      assert.equal(credentials, 1);
      assert.equal(exitCode, success ? undefined : 2);
      assert.equal(signals.listenerCount("SIGTERM"), 0);
      assert.deepEqual(
        JSON.parse(readFileSync(join(out, `summary-${runId}.json`))).recordingDomain,
        summary.recordingDomain,
      );
    } finally {
      rmSync(out, { recursive: true });
    }
  }
});

test("successor actual admission returns its bound plan and refuses old second-run provenance", async () => {
  const { admit, verifyPacket, verifyScope, verifyProof, scopeDigest } =
    await import("./pubsub-observation/admission.mjs");
  const { sha256 } = await import("./pubsub-production/admission.mjs");
  const { dirname, resolve } = await import("node:path");
  // Retain the actual admission body; replace only source, file and authority boundaries.
  const bindAdmission = new Function(
    "readJson",
    "verifyDescriptor",
    "verifyScope",
    "verifyPacket",
    "dirname",
    "git",
    "resolve",
    "readFileSync",
    "sha256",
    "verifyProof",
    "PROJECT",
    "verifyLiveLock",
    "unusedRunPreflight",
    `return (${admit.toString()});`,
  );
  for (const selection of ["full", ...Object.keys(successorIds)]) {
    const descriptor = { head: "a".repeat(40), sources: [] };
    const descriptorFile = { value: descriptor, sha256: "b".repeat(64) };
    const runIds = ["123456abcdef", "123456abcdee"];
    const scope = {
      taskId: "PUBSUB-OBSERVATION-A",
      suite: "pubsub-observation-a-v1",
      project: "fireemu-oracle-idp",
      envelopeId: "FIXTURE-SUCCESSOR",
      sourceHead: descriptor.head,
      descriptorSha256: descriptorFile.sha256,
      packetSha256: "c".repeat(64),
      runIds,
      runOutputs: Object.fromEntries(runIds.map((id, i) => [id, `/fixture/run${i + 1}`])),
      recoveryOutputs: Object.fromEntries(runIds.map((id, i) => [id, `/fixture/a2-${i + 1}`])),
      expiresAt: "2099-01-01T00:00:00Z",
      plan: makePlan(selection),
      previousAttempt: { path: `/fixture/run1/summary-${runIds[0]}.json`, sha256: "d".repeat(64) },
    };
    const rows = {},
      lines = [];
    for (const kind of ["E", "V"]) {
      const row = { ...scope, kind, state: "APPROVED", ledgerLine: lines.length + 1 };
      const label = kind === "E" ? "PUBSUB-OBSERVATION-A envelope" : "PUBSUB-OBSERVATION-A";
      const line = `| ${label} | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${scopeDigest(row)} |`;
      lines.push(line);
      row.ledgerLineSha256 = sha256(line);
      rows[kind] = { value: row, sha256: kind === "E" ? "e".repeat(64) : "f".repeat(64) };
      scope[kind] = { sha256: rows[kind].sha256 };
    }
    const packet = {
      sha256: scope.packetSha256,
      value: {
        schema: 1,
        taskId: scope.taskId,
        version: "v1",
        sourceHead: scope.sourceHead,
        descriptorSha256: scope.descriptorSha256,
        runIds: scope.runIds,
        runOutputs: scope.runOutputs,
        recoveryOutputs: scope.recoveryOutputs,
        plan: scope.plan,
      },
    };
    const previous = {
      value: {
        runId: runIds[0],
        sourceHead: descriptor.head,
        envelopeId: scope.envelopeId,
        packetSha256: scope.packetSha256,
        resourcesClosed: true,
        recordingComplete: true,
      },
      sha256: scope.previousAttempt.sha256,
    };
    const files = new Map([
      ["descriptor", descriptorFile],
      ["authority", { value: scope }],
      ["packet", packet],
      ["E", rows.E],
      ["V", rows.V],
      [scope.previousAttempt.path, previous],
    ]);
    const actual = bindAdmission(
      (path) => {
        assert.ok(files.has(path), `unexpected fixture read ${path}`);
        return files.get(path);
      },
      () => descriptor,
      verifyScope,
      verifyPacket,
      dirname,
      (...args) => (args.includes("--git-common-dir") ? "/fixture/.git" : descriptor.head),
      resolve,
      () => lines.join("\n"),
      sha256,
      verifyProof,
      scope.project,
      () => {},
      () => {},
    );
    const options = {
      descriptor: "descriptor",
      authority: "authority",
      packet: "packet",
      E: "E",
      V: "V",
      lock: "fixture",
      runId: runIds[0],
      out: scope.runOutputs[runIds[0]],
      a2: false,
    };
    assert.deepEqual(actual(options, 0).plan, scope.plan);
    packet.value.plan = makePlan(selection === "residual" ? "s10-diagnostic" : "residual");
    assert.throws(() => actual(options, 0), /packet/);
    packet.value.plan = scope.plan;
    const second = { ...options, runId: runIds[1], out: scope.runOutputs[runIds[1]] };
    assert.deepEqual(actual(second, 0).plan, scope.plan);
    for (const [key, value] of [
      ["recordingComplete", false],
      ["resourcesClosed", false],
      ["sourceHead", "7".repeat(40)],
      ["packetSha256", "0".repeat(64)],
    ]) {
      const original = previous.value[key];
      previous.value[key] = value;
      assert.throws(() => actual(second, 0), /complete closed run1/);
      previous.value[key] = original;
    }
  }
});

test("successor refuses malformed admitted plans before output claim or credentials", async () => {
  const { tempDir } = await import("./test-tmpdir.mjs");
  const { existsSync } = await import("node:fs"),
    { join } = await import("node:path");
  const altered = makePlan("residual");
  altered.caps.sourceRequests++;
  const duplicate = makePlan("s10-diagnostic");
  duplicate.cells.push(duplicate.cells[0]);
  for (const plan of [undefined, { selection: "resume" }, altered, duplicate]) {
    const out = tempDir("pubsub-successor-refuse-"),
      runId = "123456abcdef";
    let credentials = 0;
    await assert.rejects(
      main(
        [
          "--record",
          ...Object.entries({
            authority: "fixture",
            descriptor: "fixture",
            packet: "fixture",
            E: "fixture",
            V: "fixture",
            lock: "fixture",
            "run-id": runId,
            out,
          }).flatMap(([key, value]) => [`--${key}`, value]),
        ],
        {
          admit: () => ({
            plan,
            descriptor: { head: "a".repeat(40) },
            descriptorSha256: "b".repeat(64),
            scope: { envelopeId: "FIXTURE-SUCCESSOR", packetSha256: "c".repeat(64) },
          }),
          createCredentials: () => {
            credentials++;
            throw new Error("unexpected credentials");
          },
        },
      ),
      /plan|selection/,
    );
    assert.equal(credentials, 0);
    assert.equal(existsSync(join(out, `source-started-${runId}.json`)), false);
  }
});

test("stream diagnostics retain bounded sanitized details without changing terminal or cancellation semantics", async () => {
  const { default: grpc } = await import("@grpc/grpc-js");
  const cases = [
    { details: "deadline zero was refused", expected: "deadline zero was refused" },
    {
      details: "token=fixture-private-token; Bearer another-secret",
      expected: "token=[REDACTED]; Bearer [REDACTED]",
    },
    {
      details: "bearer mixed-secret fixture-private-token",
      expected: "Bearer [REDACTED] [REDACTED]",
    },
    { details: "é".repeat(10240), expected: "é".repeat(10240) },
    { details: "é".repeat(10241), expected: null },
    { details: 13, expected: null },
    { details: undefined, expected: undefined },
  ];
  for (const unit of ["a", "é", "€", "😀"])
    for (const remaining of [0, 12, 60, 61440]) {
      const limit = Math.floor(remaining / (3 * Buffer.byteLength(unit)));
      for (const count of [Math.max(0, limit - 1), limit, limit + 1]) {
        const details = unit.repeat(count);
        cases.push({ remaining, details, expected: count <= limit ? details : null });
      }
    }
  const original = "fixture-private-token".repeat(1000);
  assert.ok(3 * Buffer.byteLength(original) > 61440);
  assert.ok(
    3 * Buffer.byteLength(original.replaceAll("fixture-private-token", "[REDACTED]")) < 61440,
  );
  cases.push({ details: original, expected: null });
  for (const { details, expected, remaining = 61440 } of cases) {
    const meter = createMeter({ now: () => 0 });
    meter.enter(makePlan().cells[0]);
    const rpc = new EventEmitter(),
      rows = [];
    let cancelled = 0;
    rpc.write = () => true;
    rpc.cancel = () => {
      cancelled++;
    };
    rpc.end = () => {};
    const stream = await openStream({
      meter,
      credential: async () => "fixture-private-token",
      client: { makeBidiStreamRequest: () => rpc },
      journal: { write: (row) => rows.push(row), frame() {} },
      cellId: "S10",
      opener: {},
    });
    try {
      if (remaining < 61440) {
        const metadata = new grpc.Metadata();
        metadata.add("x", "a".repeat(61440 - remaining - 5));
        rpc.emit("metadata", metadata);
      }
      rpc.emit("error", { code: 13, details });
      const error = rows.find((row) => row.event === "stream-error");
      assert.equal(error.details, expected);
      assert.equal(Object.hasOwn(error, "details"), details !== undefined);
      assert.equal(stream.state().metadataBytesIn, 65536 - remaining);
      rpc.emit("status", { code: 13, details });
      const status = rows.find((row) => row.event === "stream-status");
      assert.equal(status.details, expected);
      assert.equal(Object.hasOwn(status, "details"), details !== undefined);
      assert.equal(
        stream.state().metadataBytesIn,
        65536 - remaining + (typeof details === "string" ? 3 * Buffer.byteLength(details) : 0),
      );
      assert.deepEqual(stream.state().terminal, { code: 13 });
      assert.equal(stream.state().incomplete, true);
      assert.equal(cancelled, expected === null && typeof details === "string" ? 1 : 0);
      assert.ok(!JSON.stringify(rows).includes("fixture-private-token"));
      assert.ok(!JSON.stringify(rows).includes("another-secret"));
    } finally {
      stream.dispose();
    }
  }
});

test("stream diagnostics honor metadata remaining before status accounting and preserve local cancellation", async () => {
  const { default: grpc } = await import("@grpc/grpc-js");
  for (const code of [1, 13]) {
    const meter = createMeter({ now: () => 0 });
    meter.enter(makePlan().cells[0]);
    const rpc = new EventEmitter(),
      rows = [];
    rpc.write = () => true;
    rpc.cancel = () => {};
    rpc.end = () => {};
    const stream = await openStream({
      meter,
      credential: async () => "fixture-private-token",
      client: { makeBidiStreamRequest: () => rpc },
      journal: { write: (row) => rows.push(row), frame() {} },
      cellId: "S10",
      opener: {},
    });
    try {
      stream.cancel("unacked-owned-delivery");
      const metadata = new grpc.Metadata();
      metadata.add("x", "a".repeat(61426));
      rpc.emit("metadata", metadata);
      rpc.emit("error", { code, details: "four" });
      rpc.emit("status", { code, details: "four" });
      assert.equal(rows.find((row) => row.event === "stream-error").details, null);
      assert.equal(rows.find((row) => row.event === "stream-status").details, null);
      assert.equal(stream.state().incomplete, true);
      assert.deepEqual(stream.state().terminal, { code });
    } finally {
      stream.dispose();
    }
  }
});

// Task28 keeps semantic source records and resource-only settlement independently pinned.
function settlementFixture() {
  const runId = "123456abcdef",
    files = new Map();
  const pin = (name, value, jsonl = false) => {
    const bytes = Buffer.from(
      jsonl ? value.map((row) => JSON.stringify(row)).join("\n") + "\n" : JSON.stringify(value),
    );
    const path = `/fixture/original/${name}`;
    files.set(path, bytes);
    return { path, sha256: sha256(bytes) };
  };
  const plan = makePlan("invalid-path-gap");
  const descriptor = {
    head: "a".repeat(40),
    sources: [
      ...["record", "scenarios", "wire", "ledger", "plan"].map((name) => ({
        path: `conformance/src/pubsub-observation/${name}.mjs`,
        sha256: sha256(Buffer.from("core-" + name)),
      })),
      { path: "conformance/src/pubsub-observation/admission.mjs", sha256: "2".repeat(64) },
    ],
  };
  const source = {
    runId,
    sourceHead: descriptor.head,
    envelopeId: "PUBSUB-OBSERVATION-A-ORIGINAL",
    packetSha256: "3".repeat(64),
  };
  const packet = {
    schema: 1,
    taskId: "PUBSUB-OBSERVATION-A",
    version: "v1",
    sourceHead: source.sourceHead,
    descriptorSha256: "",
    plan,
    runIds: [runId, "123456abcdee"],
  };
  const descriptorPin = pin("descriptor.json", descriptor);
  packet.descriptorSha256 = descriptorPin.sha256;
  const packetPin = pin("packet.json", packet);
  source.packetSha256 = packetPin.sha256;
  const context = { suite: "pubsub-observation-a-v1", project: "fireemu-oracle-idp", ...source };
  const name = `projects/fireemu-oracle-idp/subscriptions/fe${runId}-r2-sub`;
  const issued = [
    { phase: "sent", name, action: "create", transport: "rest", requestId: "own-create" },
    {
      phase: "answered",
      name,
      action: "create",
      transport: "rest",
      requestId: "own-create",
      kind: "ok",
    },
  ];
  const results = plan.cells
    .filter((cell) => !cell.reserve)
    .map((cell) => ({ cellId: cell.id, complete: true }));
  const capture = [
    {
      event: "run-start",
      at: "2026-10-08T10:00:00.000Z",
      ...context,
      descriptorSha256: descriptorPin.sha256,
    },
    ...results.map((result) => ({
      event: "case-result",
      at: "2026-10-08T10:00:00.000Z",
      ...result,
    })),
  ];
  const capturePin = pin(`capture-${runId}.jsonl`, capture, true),
    issuedPin = pin(`issued-${runId}.jsonl`, issued, true);
  const summary = {
    ...context,
    a2: false,
    recordingComplete: true,
    resourcesClosed: false,
    error: null,
    signalled: false,
    results,
    captureSha256: capturePin.sha256,
    issuedSha256: issuedPin.sha256,
    recordingDomain: { selection: plan.selection, cellIds: results.map((r) => r.cellId) },
  };
  const summaryPin = pin(`summary-${runId}.json`, summary);
  const elapsedMs = 600000;
  const a2Issued = [
    {
      phase: "resolved",
      name,
      requestId: "own-create",
      resolution: "gone-a2",
      proof: { kind: "aged-a2-404", elapsedMs },
    },
  ];
  const a2Capture = [
    {
      event: "run-start",
      at: "2026-10-08T10:10:00.000Z",
      ...context,
      descriptorSha256: descriptorPin.sha256,
    },
    {
      event: "request-dispatch",
      at: "2026-10-08T10:10:00.000Z",
      cellId: "A2",
      requestId: 1,
      transport: "rest",
      category: "resourceRead",
      method: "GetSubscription",
      request: { name },
    },
    {
      event: "response",
      at: "2026-10-08T10:10:00.000Z",
      cellId: "A2",
      requestId: 1,
      transport: "rest",
      method: "GetSubscription",
      reply: {
        ok: false,
        status: 404,
        code: "NOT_FOUND",
        unknown: false,
        body: { error: { code: 404, status: "NOT_FOUND" } },
      },
    },
  ];
  const a2CapturePin = pin("a2-capture.jsonl", a2Capture, true),
    a2IssuedPin = pin("a2-issued.jsonl", a2Issued, true);
  const a2Summary = {
    ...context,
    a2: true,
    recordingComplete: false,
    resourcesClosed: true,
    error: null,
    signalled: false,
    closureReady: false,
    parentClosureReady: false,
    captureSha256: a2CapturePin.sha256,
    issuedSha256: a2IssuedPin.sha256,
    results: [
      {
        closed: true,
        reads: 1,
        resourceReads: 1,
        unknownDeleteReads: 0,
        iamReads: 0,
        outstanding: [],
      },
    ],
  };
  const binding = {
    ...source,
    descriptor: descriptorPin,
    packet: packetPin,
    capture: capturePin,
    issued: issuedPin,
    summary: summaryPin,
    settlement: {
      capture: a2CapturePin,
      issued: a2IssuedPin,
      summary: pin("a2-summary.json", a2Summary),
    },
  };
  const activeDescriptor = structuredClone(descriptor);
  activeDescriptor.head = "b".repeat(40);
  activeDescriptor.sources.at(-1).sha256 = sha256(Buffer.from("successor-admission"));
  for (const entry of activeDescriptor.sources)
    files.set(
      `/fixture/current/${entry.path}`,
      Buffer.from(
        entry.path.endsWith("admission.mjs")
          ? "successor-admission"
          : "core-" + entry.path.split("/").at(-1).replace(".mjs", ""),
      ),
    );
  return {
    binding,
    plan,
    activeDescriptor,
    files,
    pin,
    summary,
    a2Summary,
    a2Capture,
    a2Issued,
    issued,
  };
}

const { sha256 } = await import("./pubsub-production/admission.mjs");
test("Task28 admits original complete source through exact resource-only A2 settlement", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  const f = settlementFixture();
  const original = Buffer.from(f.files.get(f.binding.summary.path));
  const value = verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) =>
    f.files.get(path),
  );
  assert.equal(value.summary.recordingComplete, true);
  assert.equal(value.summary.resourcesClosed, false);
  assert.deepEqual(f.files.get(f.binding.summary.path), original);
});

test("Task28 actual admit verifies original/successor provenance before run2 output claim", async () => {
  const a = await import("./pubsub-observation/admission.mjs");
  const { dirname, resolve } = await import("node:path");
  for (const fixture of [settlementFixture, maintenanceFixture]) {
    const f = fixture(),
      descriptor = f.activeDescriptor;
    const descriptorFile = { value: descriptor, sha256: "8".repeat(64) };
    const runIds = [f.binding.runId, "123456abcdee"];
    const scope = {
      taskId: "PUBSUB-OBSERVATION-A",
      suite: "pubsub-observation-a-v1",
      project: "fireemu-oracle-idp",
      envelopeId: "PUBSUB-OBSERVATION-A-SUCCESSOR",
      sourceHead: descriptor.head,
      descriptorSha256: descriptorFile.sha256,
      packetSha256: "9".repeat(64),
      runIds,
      runOutputs: { [runIds[0]]: "/fixture/original", [runIds[1]]: "/fixture/successor" },
      recoveryOutputs: { [runIds[0]]: "/fixture/original-a2", [runIds[1]]: "/fixture/successor-a2" },
      expiresAt: "2099-01-01T00:00:00Z",
      plan: f.plan,
      previousAttempt: { ...f.binding.summary, record: f.binding },
    };
    const packet = {
      sha256: scope.packetSha256,
      value: {
        schema: 1,
        version: "v1",
        taskId: scope.taskId,
        sourceHead: scope.sourceHead,
        descriptorSha256: scope.descriptorSha256,
        runIds,
        runOutputs: scope.runOutputs,
        recoveryOutputs: scope.recoveryOutputs,
        plan: scope.plan,
      },
    };
    const lines = [],
      files = new Map([
        ["descriptor", descriptorFile],
        ["authority", { value: scope }],
        ["packet", packet],
      ]);
    const bindProofs = () => {
      lines.length = 0;
      for (const kind of ["E", "V"]) {
        const row = { ...scope, kind, state: "APPROVED", ledgerLine: lines.length + 1 };
        const line = `| PUBSUB-OBSERVATION-A${kind === "E" ? " envelope" : ""} | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${a.scopeDigest(row)} |`;
        lines.push(line);
        row.ledgerLineSha256 = sha256(line);
        files.set(kind, { value: row, sha256: kind === "E" ? "e".repeat(64) : "f".repeat(64) });
        scope[kind] = { sha256: files.get(kind).sha256 };
      }
    };
    bindProofs();
    const boundaries = {
      root: "/fixture/current",
      readJson: (path) => {
        if (files.has(path)) return files.get(path);
        const bytes = f.files.get(path);
        assert.ok(bytes, path);
        return { value: JSON.parse(bytes), sha256: sha256(bytes) };
      },
      verifyDescriptor: () => descriptor,
      verifyScope: a.verifyScope,
      verifyPacket: a.verifyPacket,
      dirname,
      git: (...args) => (args.includes("--git-common-dir") ? "/fixture/.git" : descriptor.head),
      resolve,
      readFileSync: (path) =>
        path.endsWith("owner-decisions.md") ? lines.join("\n") : f.files.get(path),
      sha256,
      verifyProof: a.verifyProof,
      PROJECT: scope.project,
      verifyLiveLock() {},
      unusedRunPreflight() {
        throw new Error("must remain before preflight");
      },
      verifySourceRecord: a.verifySourceRecord,
    };
    const actual = new Function(...Object.keys(boundaries), `return (${a.admit.toString()});`)(
      ...Object.values(boundaries),
    );
    const options = {
      descriptor: "descriptor",
      authority: "authority",
      packet: "packet",
      E: "E",
      V: "V",
      lock: "fixture",
      runId: runIds[1],
      out: scope.runOutputs[runIds[1]],
      a2: false,
    };
    assert.deepEqual(actual(options, 0).plan, scope.plan);
    const maintenance = f.binding.settlement.maintenance;
    const capture = maintenance ? f.cleanupCapture : f.a2Capture;
    const originalReply = structuredClone(capture.at(-1).reply);
    for (const edit of [
      (reply) => { delete reply.status; },
      (reply) => { delete reply.body; },
      (reply) => { delete reply.body.error.status; },
      (reply) => { delete reply.status; reply.body = {}; },
    ]) {
      capture.at(-1).reply = structuredClone(originalReply);
      edit(capture.at(-1).reply);
      const target = maintenance ?? f.binding.settlement;
      target.capture = f.pin(maintenance ? "cleanup-capture.jsonl" : "a2-capture.jsonl", capture, true);
      const summary = maintenance ? f.receipt : f.a2Summary;
      summary.captureSha256 = target.capture.sha256;
      target.summary = f.pin(maintenance ? "cleanup-summary.json" : "a2-summary.json", summary);
      bindProofs();
      assert.throws(() => actual(options, 0), /source record proof/);
    }
    f.files.set(f.binding.settlement.capture.path, Buffer.from("changed"));
    assert.throws(() => actual(options, 0));
  }
});

test("Task28 source identity and settlement pin near-misses never admit", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  for (const edit of [
    (f) => {
      f.binding.sourceHead = "c".repeat(40);
    },
    (f) => {
      f.binding.envelopeId = "PUBSUB-OBSERVATION-A-FOREIGN";
    },
    (f) => {
      f.binding.runId = "123456abcdee";
    },
    (f) => {
      f.binding.packetSha256 = "5".repeat(64);
    },
    (f) => {
      f.activeDescriptor.sources[0].sha256 = "6".repeat(64);
    },
    (f) => {
      f.plan.cells[0].variant = "different-input";
    },
    (f) => {
      delete f.binding.settlement;
    },
    (f) => {
      f.summary.recordingComplete = false;
      f.binding.summary = f.pin(`summary-${f.binding.runId}.json`, f.summary);
    },
    (f) => {
      f.summary.a2 = true;
      f.binding.summary = f.pin(`summary-${f.binding.runId}.json`, f.summary);
    },
    (f) => {
      f.summary.results.pop();
      f.binding.summary = f.pin(`summary-${f.binding.runId}.json`, f.summary);
    },
    (f) => {
      f.summary.recordingDomain.selection = "full";
      f.binding.summary = f.pin(`summary-${f.binding.runId}.json`, f.summary);
    },
    (f) => {
      f.a2Summary.resourcesClosed = false;
      f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
    },
    (f) => {
      f.a2Summary.results[0].closed = false;
      f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
    },
    (f) => {
      f.a2Summary.recordingComplete = true;
      f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
    },
    (f) => {
      f.a2Summary.captureSha256 = "0".repeat(64);
      f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
    },
    (f) => {
      f.binding.settlement.issued.sha256 = "0".repeat(64);
    },
    (f) => {
      f.binding.descriptor.sha256 = "0".repeat(64);
    },
    (f) => {
      f.binding.summary.path = "relative-summary.json";
    },
  ]) {
    const f = settlementFixture();
    edit(f);
    assert.throws(() =>
      verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) => f.files.get(path)),
    );
  }
});

test("Task28 bounded generated A2 outcomes follow exact typed absence and age rules", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  for (const status of [200, 302, 400, 404, 418, 500])
    for (const unknown of [false, true])
      for (const elapsedMs of [599999, 600000, 600001]) {
        const f = settlementFixture();
        f.a2Capture[2].reply = {
          ok: false,
          status,
          code: "NOT_FOUND",
          unknown,
          body: { error: { code: status, status: "NOT_FOUND" } },
        };
        f.a2Issued[0].proof.elapsedMs = elapsedMs;
        f.a2Capture[1].at = new Date(
          Date.parse("2026-10-08T10:00:00.000Z") + elapsedMs,
        ).toISOString();
        f.binding.settlement.capture = f.pin("a2-capture.jsonl", f.a2Capture, true);
        f.binding.settlement.issued = f.pin("a2-issued.jsonl", f.a2Issued, true);
        f.a2Summary.captureSha256 = f.binding.settlement.capture.sha256;
        f.a2Summary.issuedSha256 = f.binding.settlement.issued.sha256;
        f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
        const verify = () =>
          verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) => f.files.get(path));
        if (status === 404 && !unknown && elapsedMs >= 600000) assert.doesNotThrow(verify);
        else assert.throws(verify, undefined, `${status}/${unknown}/${elapsedMs}`);
      }
});

test("Task28 rejects synthetic A2 request substitution and forged issued resolutions", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  for (const edit of [
    (f) => {
      f.a2Capture[1].method = "DeleteSubscription";
    },
    (f) => {
      f.a2Capture[1].request.name += "-foreign";
    },
    (f) => {
      f.a2Capture[1].category = "unknownDeleteRead";
    },
    (f) => {
      f.a2Capture[1].at = "2026-10-08T10:09:59.999Z";
    },
    (f) => {
      f.a2Capture.push({ ...f.a2Capture[1] });
    },
    (f) => {
      f.a2Capture[2].requestId = 2;
    },
    (f) => {
      f.a2Capture[2].reply.body.error.status = "INVALID_ARGUMENT";
    },
    (f) => {
      f.a2Issued[0].requestId = "unissued";
    },
    (f) => {
      f.a2Issued[0].proof.elapsedMs = 599999;
    },
    (f) => {
      f.issued[1].kind = "unknown";
    },
  ]) {
    const f = settlementFixture();
    edit(f);
    f.binding.issued = f.pin(`issued-${f.binding.runId}.jsonl`, f.issued, true);
    f.summary.issuedSha256 = f.binding.issued.sha256;
    f.binding.summary = f.pin(`summary-${f.binding.runId}.json`, f.summary);
    f.binding.settlement.capture = f.pin("a2-capture.jsonl", f.a2Capture, true);
    f.binding.settlement.issued = f.pin("a2-issued.jsonl", f.a2Issued, true);
    f.a2Summary.captureSha256 = f.binding.settlement.capture.sha256;
    f.a2Summary.issuedSha256 = f.binding.settlement.issued.sha256;
    f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
    assert.throws(() =>
      verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) => f.files.get(path)),
    );
  }
});

test("Task28 actual-shaped positive A2 read cannot turn empty outstanding requests into closed proof", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  for (const resourcesClosed of [false, true]) {
    const f = settlementFixture();
    f.a2Capture[2].reply = {
      ok: true,
      status: 200,
      code: "OK",
      unknown: false,
      body: { name: f.a2Capture[1].request.name, state: "ACTIVE", topic: "_deleted-topic_" },
    };
    f.binding.settlement.capture = f.pin("a2-capture.jsonl", f.a2Capture, true);
    f.binding.settlement.issued = f.pin("a2-issued.jsonl", [], true);
    f.a2Summary.resourcesClosed = resourcesClosed;
    f.a2Summary.results[0].closed = resourcesClosed;
    f.a2Summary.captureSha256 = f.binding.settlement.capture.sha256;
    f.a2Summary.issuedSha256 = f.binding.settlement.issued.sha256;
    f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
    assert.throws(() =>
      verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) => f.files.get(path)),
    );
  }
});

function maintenanceFixture() {
  const f = settlementFixture(),
    name = f.a2Capture[1].request.name;
  const positive = {
    ok: true,
    status: 200,
    code: "OK",
    unknown: false,
    body: { name, state: "ACTIVE", topic: "_deleted-topic_" },
  };
  f.a2Capture[2].reply = positive;
  f.binding.settlement.capture = f.pin("a2-capture.jsonl", f.a2Capture, true);
  f.binding.settlement.issued = f.pin("a2-issued.jsonl", [], true);
  f.a2Summary.resourcesClosed = false;
  f.a2Summary.results[0].closed = false;
  f.a2Summary.captureSha256 = f.binding.settlement.capture.sha256;
  f.a2Summary.issuedSha256 = f.binding.settlement.issued.sha256;
  f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
  const source = {
    path: "/fixture/private/cleanup.mjs",
    sha256: sha256(Buffer.from("synthetic-cleanup-source")),
  };
  f.files.set(source.path, Buffer.from("synthetic-cleanup-source"));
  const cleanupEnvelopeId = "PUBSUB-OWNED-CLEANUP-FIXTURE",
    cleanupPacketSha256 = "7".repeat(64);
  const context = {
    runId: f.binding.runId,
    sourceHead: f.binding.sourceHead,
    envelopeId: f.binding.envelopeId,
    packetSha256: f.binding.packetSha256,
    suite: "pubsub-observation-a-v1",
    project: "fireemu-oracle-idp",
  };
  const at = "2026-10-08T10:11:00.000Z";
  const cleanupCapture = [
    {
      event: "run-start",
      at,
      ...context,
      descriptorSha256: f.binding.descriptor.sha256,
      cleanupSourceSha256: source.sha256,
      cleanupEnvelopeId,
      cleanupPacketSha256,
    },
  ];
  for (const [index, method] of [
    "GetSubscription",
    "DeleteSubscription",
    "GetSubscription",
  ].entries()) {
    cleanupCapture.push({
      event: "request-dispatch",
      at,
      cellId: "R2",
      requestId: index + 1,
      transport: "rest",
      category: method.startsWith("Delete") ? "cleanupDelete" : "cleanupGet",
      method,
      request: { name },
    });
    cleanupCapture.push({
      event: "response",
      at,
      cellId: "R2",
      requestId: index + 1,
      transport: "rest",
      method,
      reply:
        index === 0
          ? positive
          : index === 1
            ? { ok: true, status: 200, code: "OK", unknown: false, body: {} }
            : {
                ok: false,
                status: 404,
                code: "NOT_FOUND",
                unknown: false,
                body: { error: { code: 404, status: "NOT_FOUND" } },
              },
    });
  }
  const cleanupIssued = [
    { phase: "sent", name, action: "delete", transport: "rest", requestId: `${name}#2` },
    {
      phase: "answered",
      name,
      action: "delete",
      transport: "rest",
      requestId: `${name}#2`,
      kind: "ok",
    },
    ...["own-create", `${name}#2`].map((requestId) => ({
      phase: "resolved",
      name,
      requestId,
      resolution: "gone",
      proof: { kind: "own-delete-404" },
    })),
  ];
  const capture = f.pin("cleanup-capture.jsonl", cleanupCapture, true),
    issued = f.pin("cleanup-issued.jsonl", cleanupIssued, true);
  const original = Object.fromEntries(
    ["capture", "issued", "summary"].map((field) => [field + "Sha256", f.binding[field].sha256]),
  );
  const priorA2 = Object.fromEntries(
    ["capture", "issued", "summary"].map((field) => [
      field + "Sha256",
      f.binding.settlement[field].sha256,
    ]),
  );
  const receipt = {
    ...context,
    maintenance: true,
    cleanupSourceSha256: source.sha256,
    cleanupEnvelopeId,
    cleanupPacketSha256,
    original,
    priorA2,
    captureSha256: capture.sha256,
    issuedSha256: issued.sha256,
    resourcesClosed: true,
    recordingComplete: false,
    closureReady: false,
    parentClosureReady: false,
    signalled: false,
    error: null,
    results: [{ closed: true, reads: 2, deletes: 1, outstanding: [] }],
  };
  f.binding.settlement.maintenance = {
    source,
    envelopeId: cleanupEnvelopeId,
    packetSha256: cleanupPacketSha256,
    capture,
    issued,
    summary: f.pin("cleanup-summary.json", receipt),
  };
  return { ...f, cleanupCapture, cleanupIssued, receipt };
}

test("Task28 separate confirmed-owned DELETE proof settles without rewriting unclosed A2", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  const f = maintenanceFixture(),
    original = Buffer.from(f.files.get(f.binding.summary.path)),
    a2 = Buffer.from(f.files.get(f.binding.settlement.summary.path));
  assert.doesNotThrow(() =>
    verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) => f.files.get(path)),
  );
  assert.deepEqual(f.files.get(f.binding.summary.path), original);
  assert.deepEqual(f.files.get(f.binding.settlement.summary.path), a2);
  assert.equal(JSON.parse(a2).resourcesClosed, false);
});

test("Task28 maintenance requires exact new authority, own successful DELETE and unchanged evidence", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  for (const edit of [
    (f) => {
      f.binding.settlement.maintenance.envelopeId += "-FOREIGN";
    },
    (f) => {
      f.binding.settlement.maintenance.packetSha256 = "0".repeat(64);
    },
    (f) => {
      f.receipt.original.summarySha256 = "0".repeat(64);
    },
    (f) => {
      f.receipt.priorA2.summarySha256 = "0".repeat(64);
    },
    (f) => {
      f.receipt.cleanupSourceSha256 = "0".repeat(64);
    },
    (f) => {
      f.receipt.recordingComplete = true;
    },
    (f) => {
      f.receipt.resourcesClosed = false;
    },
    (f) => {
      f.cleanupCapture[1].request.name += "-foreign";
    },
    (f) => {
      f.cleanupCapture[2].reply.body.state = "INACTIVE";
    },
    (f) => {
      f.cleanupCapture[2].reply.body.topic = "projects/foreign/topics/other";
    },
    (f) => {
      f.cleanupCapture[4].reply = {
        ok: false,
        status: 404,
        code: "NOT_FOUND",
        unknown: false,
        body: { error: { code: 404, status: "NOT_FOUND" } },
      };
    },
    (f) => {
      f.cleanupCapture[4].reply.unknown = true;
    },
    (f) => {
      f.cleanupCapture[4].reply.status = 500;
    },
    (f) => {
      f.cleanupCapture[6].reply.unknown = true;
    },
    (f) => {
      f.cleanupCapture[6].reply.status = 400;
    },
    (f) => {
      f.cleanupCapture.push({ ...f.cleanupCapture[3] });
    },
    (f) => {
      f.cleanupCapture[4].requestId = 1;
    },
    (f) => {
      f.cleanupCapture.splice(3, 2);
    },
    (f) => {
      f.cleanupIssued[2].proof = { kind: "aged-a2-404", elapsedMs: 600000 };
    },
    (f) => {
      f.cleanupIssued[0].requestId = "unissued";
    },
  ]) {
    const f = maintenanceFixture();
    edit(f);
    const maintenance = f.binding.settlement.maintenance;
    maintenance.capture = f.pin("cleanup-capture.jsonl", f.cleanupCapture, true);
    maintenance.issued = f.pin("cleanup-issued.jsonl", f.cleanupIssued, true);
    f.receipt.captureSha256 = maintenance.capture.sha256;
    f.receipt.issuedSha256 = maintenance.issued.sha256;
    maintenance.summary = f.pin("cleanup-summary.json", f.receipt);
    assert.throws(() =>
      verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) => f.files.get(path)),
    );
  }
});

test("Task28 coherently repinned descriptor head must equal the original observation identity", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  const f = settlementFixture();
  const descriptor = JSON.parse(f.files.get(f.binding.descriptor.path));
  descriptor.head = "c".repeat(40);
  f.binding.descriptor = f.pin("descriptor.json", descriptor);
  const packet = JSON.parse(f.files.get(f.binding.packet.path));
  packet.descriptorSha256 = f.binding.descriptor.sha256;
  f.binding.packet = f.pin("packet.json", packet);
  f.binding.packetSha256 = f.binding.packet.sha256;
  const capture = f.files.get(f.binding.capture.path).toString().trim().split("\n").map(JSON.parse);
  capture[0].descriptorSha256 = f.binding.descriptor.sha256;
  capture[0].packetSha256 = f.binding.packetSha256;
  f.binding.capture = f.pin(`capture-${f.binding.runId}.jsonl`, capture, true);
  f.summary.captureSha256 = f.binding.capture.sha256;
  f.summary.packetSha256 = f.binding.packetSha256;
  f.binding.summary = f.pin(`summary-${f.binding.runId}.json`, f.summary);
  f.a2Capture[0].descriptorSha256 = f.binding.descriptor.sha256;
  f.a2Capture[0].packetSha256 = f.binding.packetSha256;
  f.binding.settlement.capture = f.pin("a2-capture.jsonl", f.a2Capture, true);
  f.a2Summary.captureSha256 = f.binding.settlement.capture.sha256;
  f.a2Summary.packetSha256 = f.binding.packetSha256;
  f.binding.settlement.summary = f.pin("a2-summary.json", f.a2Summary);
  assert.throws(
    () => verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) => f.files.get(path)),
    /source record proof/,
  );
});


test("Task28 REST settlement rejects missing HTTP status or typed error evidence", async () => {
  const { verifySourceRecord } = await import("./pubsub-observation/admission.mjs");
  for (const fixture of [settlementFixture, maintenanceFixture]) {
    for (const edit of [
      (reply) => { delete reply.status; },
      (reply) => { delete reply.body; },
      (reply) => { delete reply.body.error.status; },
      (reply) => { delete reply.status; reply.body = {}; },
    ]) {
      const f = fixture(), maintenance = f.binding.settlement.maintenance;
      const capture = maintenance ? f.cleanupCapture : f.a2Capture;
      edit(capture.at(-1).reply);
      const target = maintenance ?? f.binding.settlement;
      target.capture = f.pin(maintenance ? "cleanup-capture.jsonl" : "a2-capture.jsonl", capture, true);
      const summary = maintenance ? f.receipt : f.a2Summary;
      summary.captureSha256 = target.capture.sha256;
      target.summary = f.pin(maintenance ? "cleanup-summary.json" : "a2-summary.json", summary);
      assert.throws(() => verifySourceRecord(f.binding, f.plan, f.activeDescriptor, (path) => f.files.get(path)), /source record proof/);
    }
  }
});
