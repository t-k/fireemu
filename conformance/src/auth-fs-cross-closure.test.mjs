import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const closureUrl = new URL("../../spec/compatibility/closure/AUTH-FS-CROSS.json", import.meta.url);
const required = new Set([
  "principal-get-query",
  "claims-refresh",
  "tenant-same-uid",
  "credential-refusal",
  "token-revoked-disabled-deleted",
  "transaction-principal-binding",
  "atomic-write-after-auth-change",
  "listen-auth-switch",
  "listen-token-refresh",
  "listen-revocation-deletion",
  "listen-tenant-deletion",
  "query-listener-authorization",
  "sdk-cache-pending-write",
  "final-artifact-regression",
  "closure-review",
]);

test("AUTH-FS-CROSS proposal keeps local and other-parent evidence distinct from closure", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  assert.equal(closure.parent, "AUTH-FS-CROSS");
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.inventoryStatus, "PROPOSED");
  assert.equal(closure.freezeState, "UNFROZEN");
  assert.equal(closure.closureReview.decision, "PENDING");
  assert.deepEqual(new Set(closure.conditions.map(({ conditionId }) => conditionId.split("/")[1])), required);
  assert.equal(closure.conditions.length, required.size);
  const recipes = closure.conditions.flatMap(({ recipeIds }) => recipeIds);
  assert.equal(recipes.length, new Set(recipes).size);
  for (const condition of closure.conditions) {
    assert.ok(condition.source && condition.observation.method);
    assert.ok(condition.verification.requiredEvidence.length);
    assert.notEqual(condition.status, "VERIFIED");
    assert.equal(condition.localEvidence.productionExecuted, false);
    for (const recipe of condition.recipeIds) assert.equal(recipe, `auth-fs-cross/${condition.conditionId.split("/")[1]}`);
  }
  const queryListen = closure.conditions.find(({ conditionId }) => conditionId === "AUTH-FS-CROSS/query-listener-authorization");
  assert.match(queryListen.observation.method, /query listeners/);
  assert.equal(queryListen.verification.recordingsRequired, 2);
  const sdkCatalogRef = "tools/sdk-smoke/sdk-listen-coverage.json";
  const catalogUsers = closure.conditions.filter(({ localEvidence }) => localEvidence.references.includes(sdkCatalogRef));
  assert.deepEqual(catalogUsers.map(({ conditionId }) => conditionId), ["AUTH-FS-CROSS/listen-auth-switch"]);
  assert.equal(closure.productionPlan.project, "fireemu-oracle-idp");
  assert.equal(closure.productionPlan.authorizesProduction, false);
  assert.equal(closure.productionPlan.recordingsRequired, 2);
  assert.ok(closure.productionPlan.allWireCapRequiresNewInstrumentation);
  assert.ok(closure.scopeDecisions.every(({ status }) => status === "PROPOSED"));
});
