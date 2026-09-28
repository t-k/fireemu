import assert from "node:assert/strict";
import test from "node:test";
import { createStage3WireBudget } from "./storage-object/wire-budget.mjs";

const limits = () => ({
  maxRequestBytes: 100,
  maxResponseBytes: 50000,
  maxPerResponseWireBytes: 16,
  responseReadUnitBytes: 8192,
});
const budget = (delta = {}, reserve = async () => {}) =>
  createStage3WireBudget({ ...limits(), ...delta }, { onReserve: reserve });

test("all services and phases share persistent byte totals; an outgoing next byte rejects before intent", async () => {
  const events = [];
  const meter = budget({}, async (row) => events.push(row));
  for (const service of ["storage", "auth", "oauth", "rules"]) {
    const attempt = await meter.reserve(`${service}/cleanup`, 25);
    attempt.receive(4);
    attempt.finish();
  }
  assert.equal(meter.snapshot().requestReservedBytes, 100);
  assert.equal(meter.snapshot().responseObservedBytes, 16);
  await assert.rejects(meter.reserve("next", 1), /request wire cap/);
  assert.equal(events.length, 4);
  assert.equal(meter.snapshot().attempts, 4);
});

test("the maximum response and full read-unit overshoot must fit before any reservation is persisted", async () => {
  let calls = 0;
  const meter = budget({ maxResponseBytes: 8207 }, async () => calls++);
  await assert.rejects(meter.reserve("write", 1), /response wire cap/);
  assert.equal(calls, 0);
  assert.equal(meter.snapshot().attempts, 0);
});

test("an exact reservation admits and unused incoming capacity is released after actual receipt", async () => {
  const meter = budget({ maxResponseBytes: 8208 });
  const first = await meter.reserve("first", 1);
  first.receive(1);
  first.finish();
  await assert.rejects(meter.reserve("second", 1), /response wire cap/);
  assert.equal(meter.snapshot().responseObservedBytes, 1);
});

test("first-overflow counts the full delivered unit including equality-at-limit; halt forbids continuation", async () => {
  const meter = budget();
  const attempt = await meter.reserve("write", 1);
  attempt.receive(16);
  assert.throws(() => attempt.receive(8192), /response attempt cap/);
  assert.equal(meter.snapshot().responseObservedBytes, 8208);
  assert.equal(meter.snapshot().largestResponseReadBytes, 8192);
  assert.equal(meter.snapshot().halted, true);
  assert.throws(() => attempt.receive(1), /halted/);
  assert.equal(meter.snapshot().responseObservedBytes, 8209);
  assert.equal(meter.snapshot().readAfterHaltBytes, 1);
  attempt.finish();
  await assert.rejects(meter.reserve("after-halt", 1), /halted/);
});

test("a stale attempt and concurrent intent cannot write or release another attempt", async () => {
  const meter = budget();
  const first = await meter.reserve("first", 10);
  await assert.rejects(meter.reserve("second", 1), /active/);
  first.receive(1);
  first.finish();
  const next = await meter.reserve("second", 10);
  assert.throws(() => first.receive(1), /inactive/);
  assert.throws(() => first.finish(), /inactive/);
  next.finish();
  assert.equal(meter.snapshot().requestReservedBytes, 20);
});

test("durable writer failure never admits transport, and later caller mutation cannot expand the limits", async () => {
  const plan = limits();
  const meter = createStage3WireBudget(plan, {
    onReserve: async () => {
      throw new Error("disk failure");
    },
  });
  await assert.rejects(meter.reserve("first", 1), /disk failure/);
  assert.equal(meter.snapshot().attempts, 0);
  const captured = createStage3WireBudget(plan, { onReserve: async () => {} });
  plan.maxRequestBytes = Infinity;
  plan.maxPerResponseWireBytes = 0;
  const attempt = await captured.reserve("first", 100);
  attempt.finish();
  await assert.rejects(captured.reserve("next", 1), /request wire cap/);
});

for (const [key, value] of [
  ["maxRequestBytes", NaN],
  ["maxResponseBytes", -1],
  ["responseReadUnitBytes", 8193],
  ["maxPerResponseWireBytes", Number.MAX_SAFE_INTEGER],
]) {
  test(`invalid limits reject ${key}`, () =>
    assert.throws(() => budget({ [key]: value }), /wire budget bound/));
}
