import assert from "node:assert/strict";
import test from "node:test";
import { estimateStage3Budget } from "./storage-object/budget-model.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const plan = () =>
  buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: ["recordone", "recordtwo"],
  });

test("the whole planned quote includes every request, ingress, storage and owned account", () => {
  assert.deepEqual(estimateStage3Budget(plan()), {
    requestMicroUsd: 85800,
    responseMicroUsd: 57502,
    storageAllowanceMicroUsd: 100000,
    authMicroUsd: 44000,
    totalMicroUsd: 287302,
    estimatedMicroUsd: 300000,
    reservedMicroUsd: 1000000,
    status: "PLANNED_COST_BOUND_NOT_BILLING_PROOF",
  });
});

for (const [key, value] of [
  ["responseReadUnitBytes", 8193],
  ["maxRequests", -1],
  ["maxRequests", 1.5],
  ["maxRequestBytes", NaN],
  ["maxResponseBytes", Number.MAX_SAFE_INTEGER],
  ["maxOwnedAuthAccounts", -1],
  ["estimatedUsd", 0.287299],
  ["maxUsdReservation", 0.299999],
  ["maxUsdReservation", Infinity],
  ["estimatedUsd", 0.3000001],
]) {
  test(`invalid or uncovered budget rejects ${key}=${value}`, () => {
    assert.throws(
      () => estimateStage3Budget({ ...plan(), [key]: value }),
      /budget|estimate|reservation|bound/,
    );
  });
}

test("the bound cannot discard another planned account's charge", () => {
  const original = estimateStage3Budget(plan());
  const larger = estimateStage3Budget({ ...plan(), maxOwnedAuthAccounts: 9 });
  assert.equal(larger.totalMicroUsd - original.totalMicroUsd, 5500);
});
