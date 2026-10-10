import assert from "node:assert/strict";
import test from "node:test";
import { makePlan, categoryCaps } from "./pubsub-observation/plan.mjs";

test("successor gap covers NOT and positive extension on both transports without changing reserve", () => {
  const plan = makePlan("closure-mandatory-gap");
  assert.equal(plan.cells.length, 29);
  assert.deepEqual(
    plan.cells.slice(-4).map((c) => [c.id, c.transport, c.coordinate, c.cellMs]),
    [
      ["R12", "rest", "/conditions/10/cases/7", 240000],
      ["N14", "grpc", "/conditions/10/cases/7", 240000],
      ["R13", "rest", "/conditions/9/cases/1", 360000],
      ["N15", "grpc", "/conditions/9/cases/1", 360000],
    ],
  );
  assert.deepEqual(
    [plan.caps.sourceRequests, plan.caps.totalRequests, plan.caps.sourceWallMs],
    [398, 412, 4860000],
  );
  assert.deepEqual(
    [plan.caps.G1.requests, plan.caps.G1.rest, plan.caps.G1.grpc, plan.caps.largePublishes],
    [272, 124, 148, 6],
  );
  assert.deepEqual(plan.caps.G7, makePlan().caps.G7);
  assert.deepEqual([plan.caps.G4.requests, plan.caps.G4.rest, plan.caps.G4.streams], [126, 119, 7]);
  for (const cell of plan.cells.slice(-4)) {
    const caps = categoryCaps(cell.group, cell.variant);
    assert.equal(caps.publish, 1);
    assert.equal(caps.target, cell.variant === "filter-negation" ? 4 : 5);
    assert.equal(
      Object.values(caps).reduce((a, b) => a + b),
      cell.variant === "filter-negation" ? 13 : 14,
    );
  }
});

import { createMeter } from "./pubsub-observation/meter.mjs";
import { runCell } from "./pubsub-observation/scenarios.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";

async function witnessWorld(id, options = {}) {
  const plan = makePlan("closure-mandatory-gap"),
    cell = plan.cells.find((c) => c.id === id);
  let now = 0,
    pulls = 0,
    sleeps = 0;
  const meter = createMeter({ now: () => now, plan });
  meter.enter(cell);
  const calls = [],
    rows = [],
    resources = new Map();
  let messages = [];
  const wire = {
    async call(call) {
      meter.start(call.category, call.transport);
      calls.push(structuredClone(call));
      const q = call.request,
        method = call.method;
      let body = {};
      if (method.startsWith("Create")) {
        resources.set(q.name, structuredClone(q));
        body = q;
      } else if (method.startsWith("Get")) {
        if (!resources.has(q.name))
          return {
            ok: false,
            unknown: false,
            code: "NOT_FOUND",
            status: 404,
            body: { error: { status: "NOT_FOUND" } },
          };
        body = resources.get(q.name);
      } else if (method.startsWith("Delete")) resources.delete(q.name);
      else if (method === "Publish") {
        meter.payload(Buffer.byteLength(JSON.stringify(q.messages)));
        messages = structuredClone(q.messages);
        body = {
          messageIds: options.duplicatePublish
            ? ["id-0", "id-0", "id-2"]
            : messages.map((_, i) => `id-${i}`).slice(0, options.truncatedPublish ? 2 : undefined),
        };
      } else if (method === "Pull") {
        pulls++;
        const delivered =
          cell.variant === "filter-negation"
            ? (pulls === 1 || options.repeatedBlue) && !options.noBlue
              ? [1, ...(options.deliverMissing ? [2] : [])]
              : []
            : pulls === 2 ||
                (options.noRedelivery && pulls === 3) ||
                (options.noInitial && pulls === 1)
              ? []
              : options.duplicateDelivery
                ? [0, 0]
                : [0];
        body = {
          receivedMessages: delivered.map((i) => ({
            ackId: options.emptyToken ? "" : `token-${pulls}-${i}`,
            message: {
              ...messages[i],
              messageId: options.foreign ? "foreign" : `id-${i}`,
              ...(options.badData ? { data: Buffer.from("wrong").toString("base64") } : {}),
              ...(options.badAttributes ? { attributes: { color: "wrong" } } : {}),
            },
          })),
        };
        if (options.initialLatency && pulls === 1) now += options.initialLatency;
        if (options.beforeLatency && pulls === 2) now += options.beforeLatency;
        if (options.afterLatency && pulls === 3) now += options.afterLatency;
      } else if (method === "ModifyAckDeadline") {
        if (options.modifyLatency) now += options.modifyLatency;
        if (options.modifyUnknown) return { ok: false, unknown: true, code: "UNKNOWN", body: {} };
      } else if (method === "Acknowledge") {
        if (options.ackLatency) now += options.ackLatency;
        if (options.ackRefused)
          return {
            ok: false,
            unknown: false,
            code: "INVALID_ARGUMENT",
            status: 400,
            body: { error: { status: "INVALID_ARGUMENT" } },
          };
        if (options.ackUnknown) return { ok: false, unknown: true, code: "UNKNOWN", body: {} };
      } else throw Error(`unexpected ${method}`);
      return { ok: true, unknown: false, code: "OK", status: 200, body };
    },
  };
  const result = await runCell({
    cell,
    meter,
    wire,
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: { write: (r) => rows.push(r) },
    sleep: async (ms) => {
      sleeps++;
      now +=
        ms +
        (options.waitOverrun ?? 0) -
        (options.undersleep && sleeps === 1 ? 1 : 0) -
        (options.undersleepAfter && sleeps === 2 ? 1 : 0);
    },
  });
  return { result, calls, rows, resources, meter };
}

test("NOT witnesses pull the exact filtered subscription and preserve bounded missing outcomes", async () => {
  for (const id of ["R12", "N14"]) {
    const f = await witnessWorld(id, { deliverMissing: true });
    assert.equal(f.result.complete, true);
    assert.equal(f.result.cleanupClosed, true);
    const sub = f.calls.find((c) => c.method === "CreateSubscription").request;
    assert.equal(sub.filter, 'NOT attributes.color = "red"');
    assert.equal(f.calls.filter((c) => c.method === "CreateSubscription").length, 1);
    const pulls = f.calls.filter((c) => c.method === "Pull");
    assert.equal(pulls.length, 2);
    assert.ok(pulls.every((c) => c.request.subscription === sub.name));
    const event = f.rows.find((r) => r.event === "negation-bounded-witness");
    assert.deepEqual(event.deliveredIndices, [1, 2]);
    assert.deepEqual(event.unobservedIndices, [0]);
    assert.equal(event.permanentExclusionClaimed, false);
    assert.equal(event.missingRuleAssumed, false);
    assert.equal(f.calls.find((c) => c.method === "Publish").request.messages.length, 3);
    assert.ok(
      f.calls
        .filter((c) => c.method === "Acknowledge")
        .every((c) => c.request.ackIds.every((t) => t.startsWith("token-"))),
    );
    assert.ok(f.calls.every((c) => c.transport === (id === "R12" ? "rest" : "grpc")));
  }
});

test("positive extension brackets unknown delivery and application instants with current-token redelivery", async () => {
  for (const id of ["R13", "N15"]) {
    const f = await witnessWorld(id);
    assert.equal(f.result.complete, true);
    assert.equal(f.result.cleanupClosed, true);
    const modify = f.calls.find((c) => c.method === "ModifyAckDeadline");
    assert.equal(modify.request.ackDeadlineSeconds, 60);
    assert.deepEqual(modify.request.ackIds, ["token-1-0"]);
    assert.deepEqual(f.calls.find((c) => c.method === "Acknowledge").request.ackIds, ["token-3-0"]);
    assert.equal(f.calls.filter((c) => c.method === "Pull").length, 3);
    const event = f.rows.find((r) => r.event === "deadline-extension-witness");
    assert.ok(event.modify.replied < event.initial.dispatch + 10000);
    assert.ok(event.before.dispatch >= event.initial.replied + 10000);
    assert.ok(event.before.replied < event.modify.dispatch + 60000);
    assert.ok(event.after.dispatch >= event.modify.replied + 60000);
    assert.equal(event.originalSeconds, 10);
    assert.equal(event.extensionSeconds, 60);
    assert.equal(event.applicationInstantKnown, false);
    assert.equal(event.messageId, "id-0");
    assert.equal(f.calls.length, 14);
  }
});

test("NOT missing delivery stays bounded and no assumed missing-attribute rule is required", async () => {
  for (const id of ["R12", "N14"]) {
    const f = await witnessWorld(id);
    assert.equal(f.result.complete, true);
    assert.deepEqual(
      f.rows.find((r) => r.event === "negation-bounded-witness").unobservedIndices,
      [0, 2],
    );
    assert.equal(f.calls.filter((c) => c.method === "Pull").length, 2);
  }
});
for (const [name, options] of Object.entries({
  noBlue: { noBlue: true },
  expiredPullToken: { initialLatency: 10000 },
  expiredAckToken: { ackLatency: 10000 },
  combinedTokenExpiry: { initialLatency: 9000, ackLatency: 1001 },
  foreign: { foreign: true },
  badData: { badData: true },
  badAttributes: { badAttributes: true },
  duplicatePublish: { duplicatePublish: true },
  truncatedPublish: { truncatedPublish: true },
  emptyToken: { emptyToken: true },
  repeatedBlue: { repeatedBlue: true },
  ackUnknown: { ackUnknown: true },
  ackRefused: { ackRefused: true },
}))
  test(`NOT refuses ${name} without claiming a complete witness`, async () => {
    for (const id of ["R12", "N14"]) {
      const f = await witnessWorld(id, options);
      assert.equal(f.result.complete, false);
      assert.equal(f.result.cleanupClosed, true);
      if ((options.initialLatency ?? 0) >= 10000)
        assert.equal(f.calls.filter((c) => c.method === "Acknowledge").length, 0);
    }
  });
for (const [name, options] of Object.entries({
  noInitial: { noInitial: true },
  duplicateDelivery: { duplicateDelivery: true },
  foreign: { foreign: true },
  badData: { badData: true },
  badAttributes: { badAttributes: true },
  emptyToken: { emptyToken: true },
  initialLatency: { initialLatency: 10001 },
  modifyLatency: { modifyLatency: 10000 },
  modifyUnknown: { modifyUnknown: true },
  beforeLatency: { beforeLatency: 50000 },
  missingRedelivery: { noRedelivery: true },
  expiredRedeliveryToken: { afterLatency: 10000 },
  expiredAckToken: { ackLatency: 10000 },
  combinedTokenExpiry: { afterLatency: 9000, ackLatency: 1001 },
  lostPullMargin: { waitOverrun: 35000 },
  beforeTooEarly: { undersleep: true },
  afterTooEarly: { undersleepAfter: true },
  ackUnknown: { ackUnknown: true },
  ackRefused: { ackRefused: true },
}))
  test(`extension leaves ${name} incomplete with owned cleanup`, async () => {
    for (const id of ["R13", "N15"]) {
      const f = await witnessWorld(id, options);
      assert.equal(f.result.complete, false);
      assert.equal(f.result.cleanupClosed, true);
      if ((options.afterLatency ?? 0) >= 10000)
        assert.equal(f.calls.filter((c) => c.method === "Acknowledge").length, 0);
    }
  });
