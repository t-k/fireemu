import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const closureUrl = new URL("../../spec/compatibility/closure/FS-TRANSACTION.json", import.meta.url);
const required = new Set([
  "read-write-lifecycle",
  "read-only-snapshot",
  "read-time-snapshot",
  "token-validation-and-ownership",
  "read-set-conflict",
  "write-set-atomicity",
  "query-range-lock",
  "failed-commit-and-rollback",
  "retry-token-lifecycle",
  "idle-expiry",
  "total-lifetime-expiry",
  "read-time-retention",
  "web-sdk-optimistic-retry",
  "admin-sdk-server-retry",
  "commit-atomic-visibility",
  "paging-and-cancellation",
  "final-artifact-regression",
  "closure-review",
]);

test("FS-TRANSACTION proposal names every acceptance boundary without claiming closure", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  assert.equal(closure.parent, "FS-TRANSACTION");
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.inventoryStatus, "PROPOSED");
  assert.equal(closure.freezeState, "UNFROZEN");
  assert.equal(closure.closureReview.decision, "PENDING");
  assert.deepEqual(new Set(closure.conditions.map(({ conditionId }) => conditionId.split("/")[1])), required);
  assert.equal(closure.conditions.length, required.size);
  const recipes = closure.conditions.flatMap(({ recipeIds }) => recipeIds);
  assert.equal(recipes.length, new Set(recipes).size);
  for (const condition of closure.conditions) {
    assert.ok(condition.source);
    assert.ok(condition.observation.method);
    assert.ok(condition.observation.credentials, `${condition.conditionId} must name its credential context`);
    assert.ok(condition.verification.requiredEvidence.length);
    assert.ok(["PENDING_CORPUS", "PENDING_RECORDING", "PENDING_REVIEW"].includes(condition.status));
    for (const recipe of condition.recipeIds) assert.equal(recipe, `fs-transaction/${condition.conditionId.split("/")[1]}`);
  }
  const preparedCases = closure.conditions.flatMap(({ observation }) => observation.existingCaseIds ?? []);
  assert.deepEqual(new Set(preparedCases), new Set([
    "idle-expiry/commit-before-idle",
    "idle-expiry/commit-after-idle",
    "idle-expiry/rollback-after-idle",
    "idle-expiry/lock-held-before-idle",
    "idle-expiry/lock-released-after-idle",
    "finished-token/rollback-after-begin",
    "finished-token/rollback-after-commit",
    "finished-token/rollback-after-rollback",
    "retry-token/retry-with-rolled-back-previous",
    "retry-token/retry-with-committed-previous",
    "retry-token/retry-with-read-only-previous",
    "retry-token/retry-with-unissued-previous",
    "retry-token/retry-with-malformed-previous",
  ]));
  assert.equal(preparedCases.length, 13, "each prepared case belongs to one condition");
  const sdk = closure.conditions.find(({ conditionId }) => conditionId === "FS-TRANSACTION/web-sdk-optimistic-retry");
  assert.deepEqual(sdk.observation.transports, ["node-web-sdk", "browser-webchannel"]);
  assert.equal(sdk.verification.recordingsRequiredPerTransport, 2);
  assert.match(sdk.observation.method, /BatchGetDocuments.*precondition.*Commit.*callback count/);
  const admin = closure.conditions.find(({ conditionId }) => conditionId === "FS-TRANSACTION/admin-sdk-server-retry");
  assert.match(admin.observation.method, /firebase-admin 14\.3\.0.*retryTransaction/);
  assert.match(closure.conditions.find(({ conditionId }) => conditionId === "FS-TRANSACTION/idle-expiry").observation.limitId, /^FS-LIMIT-TRANSACTION-IDLE-TIME$/);
  assert.match(closure.conditions.find(({ conditionId }) => conditionId === "FS-TRANSACTION/total-lifetime-expiry").observation.limitId, /^FS-LIMIT-TRANSACTION-TOTAL-TIME$/);
  const readTime = closure.conditions.find(({ conditionId }) => conditionId === "FS-TRANSACTION/read-time-snapshot");
  assert.ok(!readTime.localEvidence.references.some((path) => path.includes("expiry-retry")));
  assert.match(closure.scopeDecisions.find(({ id }) => id === "T5").recommendation, /do not import O7\/O8 Gate/);
  assert.equal(closure.productionPlan.preparedCampaign.project, "fireemu-oracle-sbx");
  assert.equal(closure.productionPlan.preparedCampaign.authorizesProduction, false);
  assert.equal(closure.productionPlan.preparedCampaign.recordingsNeeded, 2);
  assert.equal(closure.productionPlan.preparedCampaign.totalRequestEstimate, 190);
  assert.ok(closure.productionPlan.unestimatedConditions.length);
  assert.ok(closure.productionPlan.unestimatedConditions.includes("FS-TRANSACTION/failed-commit-and-rollback"));
  assert.ok(closure.scopeDecisions.every(({ status, decision, decidedBy, decidedOn }) => status === "DECIDED" && decision && decidedBy && decidedOn));
  assert.equal(closure.scopeDecisions.find(({ id }) => id === "OT-1").decision, "PESSIMISTIC_ONLY_OPTIMISTIC_FOLLOW_UP");
  assert.equal(closure.profileComparison.profile, "strict");
  assert.equal(closure.profileComparison.emulatorCompatibilityCheck, "PENDING_LOCAL_OBSERVATION");
  assert.equal(closure.parentStatus === "COMPAT_VERIFIED", closure.conditions.every(({ status }) => status === "VERIFIED") && closure.closureReview.decision === "APPROVED");
});
