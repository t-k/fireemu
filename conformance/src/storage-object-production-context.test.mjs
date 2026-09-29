import assert from "node:assert/strict";
import test from "node:test";
import { copyCanonicalProductionStage3Plan } from "./storage-object/production-context.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});

test("canonical context copies all plan data into a deeply frozen original snapshot", () => {
  const input = structuredClone(plan),
    copy = copyCanonicalProductionStage3Plan(input);
  assert.deepEqual(copy, plan);
  assert.notEqual(copy, input);
  function frozen(value) {
    if (!value || typeof value !== "object") return;
    assert.equal(Object.isFrozen(value), true);
    for (const entry of Object.values(value)) frozen(entry);
  }
  frozen(copy);
  input.recordings[0].runId = "changed";
  assert.equal(copy.recordings[0].runId, "recordone");
});

test("canonical context rejects getters, proxies, sparse arrays and extra fields without hooks", () => {
  let hooks = 0;
  const nested = structuredClone(plan);
  Object.defineProperty(nested.recordings[0], "runId", {
    enumerable: true,
    get() {
      hooks++;
      return "recordone";
    },
  });
  const sparse = structuredClone(plan);
  delete sparse.recordings[0];
  const arrayExtra = structuredClone(plan);
  arrayExtra.recordings.extra = true;
  const symbol = structuredClone(plan);
  symbol[Symbol("extra")] = true;
  const nonEnumerable = structuredClone(plan);
  Object.defineProperty(nonEnumerable, "extra", { value: true });
  const revoked = Proxy.revocable(plan, {});
  revoked.revoke();
  const proxy = new Proxy(plan, {
    get() {
      hooks++;
      throw new Error("hook");
    },
    ownKeys() {
      hooks++;
      throw new Error("hook");
    },
  });
  const arrayPrototypeObject = Object.assign(Object.create(Array.prototype), plan);
  for (const value of [
    nested,
    sparse,
    arrayExtra,
    symbol,
    nonEnumerable,
    revoked.proxy,
    proxy,
    arrayPrototypeObject,
    { ...plan, ignored: true },
    { ...plan, status: "LOCAL_DRAFT" },
  ]) {
    assert.throws(
      () => copyCanonicalProductionStage3Plan(value),
      /invalid production canonical plan/,
    );
  }
  assert.equal(hooks, 0);
});

test("canonical context rejects finite ceiling violations and unsupported values", () => {
  const deep = {};
  let cursor = deep;
  for (let i = 0; i < 18; i++) {
    cursor.next = {};
    cursor = cursor.next;
  }
  for (const value of [
    undefined,
    () => {},
    NaN,
    Infinity,
    { ...plan, projectId: "x".repeat(8193) },
    { ...plan, projectId: "\uD800" },
    { ...plan, extra: Array(65).fill(0) },
    { ...plan, extra: Object.fromEntries(Array.from({ length: 65 }, (_, i) => [String(i), i])) },
    { ...plan, extra: deep },
    { ...plan, extra: Array(16).fill("x".repeat(8192)) },
  ]) {
    assert.throws(
      () => copyCanonicalProductionStage3Plan(value),
      /invalid production canonical plan/,
    );
  }
});
