import assert from "node:assert/strict";
import test from "node:test";
import { makePlan } from "./pubsub-observation/plan.mjs";

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
test("REST bounded reader cancels oversized bodies before buffering the whole response", async () => {
  let cancelled = 0;
  const response = {
    body: {
      getReader: () => ({
        read: async () => ({ done: false, value: Buffer.alloc(65537) }),
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
test("native stream records cancel and half-close separately and preserves exact update presence", async () => {
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
test("inbound stream overflow is incomplete, cancels once, and never reopens", async () => {
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
            ? 37100
            : call.method === "CreateSubscription"
              ? 13000
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
        ledger.observeRead(name, { ...response, ok: true }),
        true,
        `${record.runId}/n${record.n}`,
      );
      assert.equal(ledger.observeRead(`${name}-nearby`, { ...response, ok: true }), false);
      for (const status of [199, 302, 503])
        assert.equal(ledger.observeRead(name, { ...response, status, ok: true }), false);
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
