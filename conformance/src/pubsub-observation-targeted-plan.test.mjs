import assert from "node:assert/strict";
import test from "node:test";
import { makePlan, validatePlan, categoryCaps } from "./pubsub-observation/plan.mjs";

const firstIds = ["R13", "N15", "R2"];
const secondIds = [
  "S10",
  "S11",
  "R1",
  "R2",
  "R3",
  "R4",
  "R5",
  "N1",
  "N2",
  "N3",
  "N4",
  "N5",
  "R9",
  "N9",
  "R10",
  "N10",
  "R11",
  "N13",
  "N11",
  "N12",
  "R12",
  "N14",
  "R13",
  "N15",
];
const selections = ["closure-targeted-first-complement", "closure-targeted-independent-second"];

test("fixed targeted selections preserve exact original cells and omit supplements", () => {
  const full = makePlan("closure-mandatory-gap");
  for (const [index, selection] of selections.entries()) {
    const plan = makePlan(selection);
    assert.deepEqual(
      plan.cells.map((cell) => cell.id),
      index === 0 ? firstIds : secondIds,
    );
    for (const cell of plan.cells)
      assert.deepEqual(
        cell,
        full.cells.find((original) => original.id === cell.id),
      );
    assert.equal(plan.recordings, 1);
    assert.equal(validatePlan(plan), plan);
    assert.equal(
      plan.cells.some((cell) => cell.supplement),
      false,
    );
  }
  assert.throws(() => makePlan("closure-targeted-arbitrary"), /fixed observation selection/);
});

test("targeted caps include every selected category, stream and independent recovery reserve", () => {
  const first = makePlan(selections[0]);
  const second = makePlan(selections[1]);
  assert.deepEqual(first.groups, ["G1", "G7"]);
  assert.deepEqual(second.groups, ["G4", "G1", "G7"]);
  assert.deepEqual(
    [
      first.caps.G1.requests,
      first.caps.G1.rest,
      first.caps.G1.grpc,
      first.caps.G4.requests,
      first.caps.G4.streams,
    ],
    [40, 26, 14, 0, 0],
  );
  assert.deepEqual(
    [
      second.caps.G1.requests,
      second.caps.G1.rest,
      second.caps.G1.grpc,
      second.caps.G4.requests,
      second.caps.G4.rest,
      second.caps.G4.streams,
    ],
    [274, 125, 149, 36, 34, 2],
  );
  assert.deepEqual(
    [
      first.caps.sourceRequests,
      first.caps.totalRequests,
      first.caps.sourceWallMs,
      first.caps.framesOut,
      first.caps.framesIn,
    ],
    [40, 54, 840000, 0, 0],
  );
  assert.deepEqual(
    [
      second.caps.sourceRequests,
      second.caps.totalRequests,
      second.caps.sourceWallMs,
      second.caps.framesOut,
      second.caps.framesIn,
    ],
    [310, 324, 3960000, 12, 12],
  );
  const aggregate = 318 + first.caps.totalRequests + second.caps.totalRequests;
  assert.equal(aggregate, 696);
  assert.ok(aggregate <= 824);
  for (const plan of [first, second]) {
    const starts = plan.cells.reduce(
      (sum, cell) =>
        sum + Object.values(categoryCaps(cell.group, cell.variant)).reduce((a, b) => a + b, 0),
      0,
    );
    assert.equal(plan.caps.sourceRequests, starts);
    assert.equal(plan.caps.totalRequests - starts, 14);
    assert.deepEqual(plan.caps.G7, makePlan().caps.G7);
    assert.equal(plan.caps.cleanupReserveMs, 40000);
    assert.equal(plan.caps.largePublishes, plan.selection.endsWith("second") ? 8 : 2);
    assert.equal(plan.caps.smallPublishes, plan.selection.endsWith("second") ? 2 : 0);
    assert.equal(plan.caps.largeEncodedPayloadBytes, 1024);
    assert.equal(plan.caps.smallEncodedPayloadBytes, 1024);
    assert.equal(plan.caps.frameBytes, 65536);
    assert.equal(plan.caps.metadataBytesEachDirection, 65536);
  }
});

test("targeted admission rejects omitted coverage, changed transport, inflated caps and shortened windows", () => {
  for (const selection of selections) {
    const original = makePlan(selection);
    const changes = [
      (plan) => plan.cells.pop(),
      (plan) =>
        plan.cells.push(makePlan("closure-mandatory-gap").cells.find((cell) => cell.id === "S16")),
      (plan) => {
        plan.cells[0].transport = "grpc";
      },
      (plan) => {
        plan.caps.sourceRequests++;
      },
      (plan) => {
        plan.caps.totalRequests = plan.caps.sourceRequests;
      },
      (plan) => {
        plan.caps.sourceWallMs -= 120000;
      },
      (plan) => {
        plan.cells.find((cell) => cell.id === "R13").cellMs = 120000;
      },
    ];
    for (const change of changes) {
      const altered = structuredClone(original);
      change(altered);
      assert.throws(() => validatePlan(altered), /fixed observation plan mismatch/);
    }
  }
});

test("targeted generation is fresh and does not alter the full H1 or legacy selections", () => {
  const before = makePlan("closure-mandatory-gap");
  const first = makePlan(selections[0]);
  first.cells[0].coordinate = "forged";
  first.caps.G7.requests = 0;
  assert.deepEqual(makePlan("closure-mandatory-gap"), before);
  assert.equal(makePlan(selections[0]).caps.G7.requests, 14);
  assert.equal(makePlan("valid-stream-gap").cells.length, 9);
  assert.equal(makePlan("s10-diagnostic").cells[0].id, "S10");
});

import { verifyScope, verifyPacket } from "./pubsub-observation/admission.mjs";

test("each targeted phase admits exactly one source namespace without weakening global evidence accounting", () => {
  for (const selection of selections) {
    const plan = makePlan(selection);
    const runId = "123456789abc";
    const descriptor = { head: "a".repeat(40) };
    const digest = "b".repeat(64);
    const scope = {
      taskId: "PUBSUB-OBSERVATION-A",
      suite: plan.suite,
      project: plan.project,
      envelopeId: "TARGETED-UNIT-FIXTURE",
      sourceHead: descriptor.head,
      descriptorSha256: digest,
      packetSha256: "c".repeat(64),
      plan,
      runIds: [runId],
      runOutputs: { [runId]: "/fixture/source" },
      recoveryOutputs: { [runId]: "/fixture/recovery" },
      expiresAt: new Date(60000).toISOString(),
    };
    const options = { runId, out: "/fixture/source", a2: false };
    assert.equal(verifyScope(scope, descriptor, digest, options, 0), scope);
    const packet = { sha256: scope.packetSha256, value: { ...scope, schema: 1, version: "v1" } };
    assert.equal(verifyPacket(packet, scope, descriptor, digest), plan);
    const extraNamespace = structuredClone(scope);
    extraNamespace.runIds.push("abcdef123456");
    assert.throws(
      () => verifyScope(extraNamespace, descriptor, digest, options, 0),
      /source-bound scope mismatch/,
    );
    const changedPacket = structuredClone(packet);
    changedPacket.value.plan.caps.totalRequests++;
    assert.throws(
      () => verifyPacket(changedPacket, scope, descriptor, digest),
      /packet identity mismatch/,
    );
  }
});

test("real meter admits every fixed cross-cell Publish then rejects one excess without changing classification", async () => {
  const { createMeter } = await import("./pubsub-observation/meter.mjs");
  const { encodedSizes } = await import("./pubsub-observation/payload.mjs");
  for (const selection of selections) {
    const plan = makePlan(selection),
      meter = createMeter({ plan, now: () => 0 });
    let large = 0,
      small = 0;
    for (const cell of plan.cells) {
      meter.enter(cell);
      const calls =
        cell.variant === "publish-wire-eight"
          ? 2
          : [
                "filter-negation",
                "positive-deadline-extension",
                "terminal-details",
                "presend-details",
              ].includes(cell.variant)
            ? 1
            : 0;
      const marker = cell.group === "G4";
      const count = marker ? 1 : calls;
      for (let i = 0; i < count; i++) {
        meter.start("publish", cell.transport);
        const request = {
          topic: "projects/unit/topics/owned",
          messages: [
            { data: Buffer.from(marker ? `${cell.id}:marker0` : cell.variant).toString("base64") },
          ],
        };
        const bytes = encodedSizes(request.topic, request.messages).payload;
        assert.doesNotThrow(() => meter.payload(bytes), `${selection}/${cell.id}`);
        if (marker) small++;
        else large++;
      }
    }
    assert.equal(large, selection.endsWith("second") ? 8 : 2);
    assert.equal(small, selection.endsWith("second") ? 2 : 0);
    assert.equal(meter.snapshot().largePublishes, large);
    assert.equal(meter.snapshot().smallPublishes, small);
    assert.throws(() => meter.payload(1), /publish payload cap exhausted/);
    assert.equal(plan.caps.largeEncodedPayloadBytes, 1024);
    assert.equal(plan.caps.smallEncodedPayloadBytes, 1024);
    assert.ok((large + small) * 1024 <= 27 * 1024);
  }
});
