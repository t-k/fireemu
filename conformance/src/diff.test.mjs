// Self-test for the gate itself: `node --test src/diff.test.mjs`, no emulator needed.
//
// The suite is only worth running if drift is actually caught, so each of the four fixture
// statuses is exercised here against a mutated run: a parity row that changed, a documented
// divergence that moved, a debt row that changed (reported, never a gate), a pending row that
// produced an observation, a step the fixture does not describe and one it describes alone.

import assert from "node:assert/strict";
import { test } from "node:test";

import { classifyScenario, compareScenario, deepEqual } from "./diff.mjs";
import { normalizeError } from "./normalize.mjs";

const fixture = {
  id: "example/scenario",
  schemaVersion: 1,
  steps: [
    { id: "agrees", status: "parity", value: { status: 200 } },
    {
      id: "differs-on-purpose",
      status: "documented-divergence",
      oracle: { status: 200 },
      testd: { status: 403 },
      documents: "README.md",
      reason: "fireemu enforces here",
    },
    { id: "known-debt", status: "debt", oracle: { m: "a" }, testd: { m: "b" } },
    { id: "unanswerable", status: "pending", reason: "needs a real project", production: "..." },
  ],
};

const run = (steps) => ({ id: fixture.id, fault: null, steps });

const faithful = [
  { id: "agrees", value: { status: 200 } },
  { id: "differs-on-purpose", value: { status: 403 } },
  { id: "known-debt", value: { m: "b" } },
  { id: "unanswerable", pending: true, reason: "needs a real project" },
];

test("deepEqual distinguishes shape, order and key set", () => {
  assert.ok(deepEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] }));
  assert.ok(!deepEqual([1, 2], [2, 1]));
  assert.ok(!deepEqual({ a: 1 }, { a: 1, b: undefined }));
  assert.ok(!deepEqual({ a: 1 }, { a: "1" }));
});

test("an unvalidated annotation cannot promote a mismatch to documented divergence", () => {
  const steps = classifyScenario({
    scenarioId: "example/scenario",
    oracleScenario: { steps: [{ id: "read", value: { status: 200 } }] },
    testdScenario: { steps: [{ id: "read", value: { status: 403 } }] },
    annotations: {
      "example/scenario#read": {
        documents: "README.md",
        reason: "not verified",
        authority: { kind: "unverified" },
      },
    },
  });
  assert.equal(steps[0].status, "debt");
});

test("a faithful replay passes and counts only the gated rows", () => {
  const result = compareScenario({ fixture, testdScenario: run(faithful) });
  assert.ok(result.isOk());
  assert.equal(result._unsafeUnwrap().checked, 2);
  assert.deepEqual(result._unsafeUnwrap().warnings, []);
});

test("a parity row that drifts fails the gate", () => {
  const drifted = faithful.map((s) => (s.id === "agrees" ? { ...s, value: { status: 201 } } : s));
  const result = compareScenario({ fixture, testdScenario: run(drifted) });
  assert.ok(result.isErr());
  assert.match(result._unsafeUnwrapErr().failures[0], /parity drift/);
});

test("a documented divergence that moves off its recorded value fails the gate", () => {
  const drifted = faithful.map((s) =>
    s.id === "differs-on-purpose" ? { ...s, value: { status: 200 } } : s,
  );
  const result = compareScenario({ fixture, testdScenario: run(drifted) });
  assert.ok(result.isErr());
  assert.match(result._unsafeUnwrapErr().failures[0], /documented divergence drifted/);
});

test("a debt row that changes is reported and never fails the gate", () => {
  const drifted = faithful.map((s) => (s.id === "known-debt" ? { ...s, value: { m: "c" } } : s));
  const result = compareScenario({ fixture, testdScenario: run(drifted) });
  assert.ok(result.isOk());
  assert.equal(result._unsafeUnwrap().warnings.length, 1);
});

test("a pending row that produces an observation fails the gate", () => {
  const observed = faithful.map((s) =>
    s.id === "unanswerable" ? { id: s.id, value: { status: 403 } } : s,
  );
  const result = compareScenario({ fixture, testdScenario: run(observed) });
  assert.ok(result.isErr());
  assert.match(result._unsafeUnwrapErr().failures[0], /recorded as pending/);
});

test("a step the fixture does not describe fails the gate", () => {
  const extra = [...faithful, { id: "brand-new", value: { status: 500 } }];
  const result = compareScenario({ fixture, testdScenario: run(extra) });
  assert.ok(result.isErr());
  assert.match(result._unsafeUnwrapErr().failures[0], /the fixture does not describe/);
});

test("a step that vanished from the run fails the gate", () => {
  const missing = faithful.filter((s) => s.id !== "agrees");
  const result = compareScenario({ fixture, testdScenario: run(missing) });
  assert.ok(result.isErr());
  assert.match(result._unsafeUnwrapErr().failures[0], /the run does not/);
});

test("a scenario that faulted mid-run fails the gate", () => {
  const faulted = { ...run(faithful), fault: "connection reset" };
  const result = compareScenario({ fixture, testdScenario: faulted });
  assert.ok(result.isErr());
  assert.match(result._unsafeUnwrapErr().failures[0], /faulted during the run/);
});

test("gRPC error trailers preserve duplicate ASCII values and binary bytes line by line", () => {
  const metadata = {
    getMap() {
      return {
        date: "Wed, 02 Sep 2026 03:01:11 GMT",
        "fireemu-reason": "first",
        "grpc-status-details-bin": Buffer.from([0, 255]),
      };
    },
    get(key) {
      if (key === "date") return ["Wed, 02 Sep 2026 03:01:11 GMT"];
      if (key === "fireemu-reason") return ["first", "second"];
      if (key === "grpc-status-details-bin") return [Buffer.from([0, 255]), Buffer.alloc(0)];
      return [];
    },
  };

  assert.deepEqual(normalizeError({ code: 7, details: "denied", metadata }), {
    thrown: true,
    code: "7",
    message: null,
    details: "denied",
    trailers: [
      { key: "fireemu-reason", kind: "ascii", value: "first" },
      { key: "fireemu-reason", kind: "ascii", value: "second" },
      { key: "grpc-status-details-bin", kind: "binary", valueBase64: "AP8=" },
      { key: "grpc-status-details-bin", kind: "binary", valueBase64: "" },
    ],
  });
});
