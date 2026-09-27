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
const statuses = new Set([
  "PENDING_CORPUS",
  "PENDING_RECORDING",
  "PENDING_REVIEW",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
]);
const requiredScopeDecisions = new Set(["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "OT-1"]);

test("FS-TRANSACTION proposal names every acceptance boundary without claiming closure", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  assert.equal(closure.parent, "FS-TRANSACTION");
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(closure.freezeState, "FROZEN");
  assert.match(closure.frozenOn, /^\d{4}-\d{2}-\d{2}$/);
  assert.deepEqual(new Set(closure.conditions.map(({ conditionId }) => conditionId.split("/")[1])), required);
  assert.equal(closure.conditions.length, required.size);
  const recipes = closure.conditions.flatMap(({ recipeIds }) => recipeIds);
  assert.equal(recipes.length, new Set(recipes).size);
  for (const condition of closure.conditions) {
    assert.ok(condition.source);
    assert.ok(condition.observation.method);
    assert.ok(condition.observation.credentials, `${condition.conditionId} must name its credential context`);
    assert.ok(condition.note?.trim(), `${condition.conditionId} must state its remaining boundary`);
    assert.ok(condition.verification.requiredEvidence.length);
    assert.ok(statuses.has(condition.status), `${condition.conditionId}: ${condition.status}`);
    if (condition.status === "VERIFIED") assert.ok(condition.evidence, `${condition.conditionId}: evidence`);
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
  assert.equal(closure.productionPlan.preparedCampaign.project, "fireemu-oracle-sbx");
  assert.equal(closure.productionPlan.preparedCampaign.authorizesProduction, false);
  assert.equal(closure.productionPlan.preparedCampaign.recordingsNeeded, 2);
  assert.ok(closure.productionPlan.unestimatedConditions.length);
  assert.ok(closure.productionPlan.unestimatedConditions.includes("FS-TRANSACTION/failed-commit-and-rollback"));
  assert.deepEqual(new Set(closure.scopeDecisions.map(({ id }) => id)), requiredScopeDecisions);
  for (const decision of closure.scopeDecisions) {
    assert.equal(decision.status, "DECIDED");
    assert.ok(decision.decision?.trim());
    assert.match(decision.decidedBy, /^(owner|coordinator)/);
    assert.match(decision.decidedOn, /^\d{4}-\d{2}-\d{2}$/);
  }
  assert.match(closure.scopeDecisions.find(({ id }) => id === "T7").decisionRef, /owner-decisions/);
  assert.equal(closure.scopeDecisions.find(({ id }) => id === "T8").movedTo, "FS-DATA-WRITE");
  assert.equal(closure.scopeDecisions.find(({ id }) => id === "T9").movedTo, "FS-DATA-WRITE");
  assert.match(closure.scopeDecisions.find(({ id }) => id === "OT-1").decidedBy, /^owner/);
  assert.match(closure.scopeDecisions.find(({ id }) => id === "OT-1").decision, /PESSIMISTIC.*OPTIMISTIC/);
  assert.equal(closure.profileComparison.profile, "strict");
  assert.equal(closure.profileComparison.emulatorCompatibilityCheck, "PENDING_LOCAL_OBSERVATION");
  assert.equal(closure.parentStatus === "COMPAT_VERIFIED", closure.conditions.every(({ status }) => status === "VERIFIED") && closure.closureReview.decision === "APPROVED");
});
