import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const closureUrl = new URL("../../spec/compatibility/closure/AUTH-FS-CROSS.json", import.meta.url);
const load = () => JSON.parse(readFileSync(closureUrl, "utf8"));

// The closure inventory. Adding or removing a condition needs a new production mismatch or an
// uncovered acceptance requirement, and an edit of AUTH-FS-CROSS.json in the same commit.
const conditions = {
  "tenant-same-uid": 1,
  "read-only-transaction-binding": 1,
  "foreign-project-token": 1,
  "sdk-optimistic-transaction": 2,
  "listen-sign-out-and-switch": 2,
  "listen-token-refresh": 2,
  "listen-revocation-disable-delete": 2,
  "listen-tenant-deletion": 2,
  "pending-write-across-switch": 2,
  "final-artifact-regression": null,
  "closure-review": null,
};
const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);
const requiredScopeDecisions = ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "OX-1", "OX-2", "OX-3", "X3", "X9"];
// Conditions that C1 moved to FS-RULES, where they are VERIFIED; they must not come back.
const movedToFsRules = [
  "principal-get-query",
  "credential-refusal",
  "token-revoked-disabled-deleted",
  "claims-refresh",
  "atomic-write-after-auth-change",
];

test("AUTH-FS-CROSS closure inventory cannot silently omit or add a condition", () => {
  const closure = load();
  assert.equal(closure.parent, "AUTH-FS-CROSS");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.deepEqual(ids.toSorted(), Object.keys(conditions).map((id) => `AUTH-FS-CROSS/${id}`).toSorted());
  for (const moved of movedToFsRules) assert.ok(!ids.includes(`AUTH-FS-CROSS/${moved}`), moved);
});

test("every AUTH-FS-CROSS condition names its scope, stage, recipe and status", () => {
  const closure = load();
  const stages = { 1: [], 2: [] };
  for (const condition of closure.conditions) {
    const id = condition.conditionId.split("/")[1];
    assert.ok(statuses.has(condition.status), `${id}: status ${condition.status}`);
    assert.ok(condition.note?.trim(), `${id}: note`);
    assert.ok(condition.observation?.method?.trim(), `${id}: observation`);
    assert.deepEqual(condition.recipeIds, [`auth-fs-cross/${id}`]);
    assert.equal(condition.stage ?? null, conditions[id], `${id}: stage`);
    if (condition.stage) stages[condition.stage].push(id);
    if (condition.status === "VERIFIED") assert.ok(condition.evidence, `${id}: evidence`);
  }
  assert.deepEqual(closure.productionPlan.stages, stages);
  // Catalog cases that FS-RULES R2 moved from FS-LISTEN-SDK are each owned by exactly one condition.
  const cases = closure.conditions.flatMap(({ observation }) => observation.catalogCases ?? []);
  assert.deepEqual(cases.toSorted(), ["FS-LISTEN-SDK-106", "FS-LISTEN-SDK-109", "FS-LISTEN-SDK-109C"]);
});

test("AUTH-FS-CROSS scope decisions are recorded, not implied", () => {
  const closure = load();
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const id of requiredScopeDecisions) assert.ok(decided.has(id), `scope decision ${id}`);
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision?.trim(), decision.id);
    assert.match(decision.decidedBy, /^(owner|coordinator)/, `${decision.id}: owner or delegated coordinator`);
    assert.match(decision.decidedOn, /^\d{4}-\d{2}-\d{2}$/, decision.id);
    if (decision.id.startsWith("OX-") || decision.id === "X3" || decision.id === "X9")
      assert.match(decision.decidedBy, /^owner/, `${decision.id}: only the owner decides it`);
    for (const key of ["movedTo", "movedFrom"])
      if (decision[key]) assert.match(decision[key], /^(AUTH|FS)-[A-Z-]+$/, `${decision.id}: ${key}`);
  }
  assert.equal(closure.scopeDecisions.find(({ id }) => id === "C1").movedTo, "FS-RULES");
  assert.equal(closure.scopeDecisions.find(({ id }) => id === "C3").movedFrom, "FS-LISTEN-SDK");
});

test("AUTH-FS-CROSS parent promotion requires every condition and an approved closure review", () => {
  const closure = load();
  const allVerified = closure.conditions.every(({ status }) => status === "VERIFIED");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    allVerified && closure.closureReview?.decision === "APPROVED",
  );
  // Frozen on 2026-09-27: the condition set above may change only as its comment says.
  assert.equal(closure.freezeState, "FROZEN");
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.match(closure.frozenOn, /^\d{4}-\d{2}-\d{2}$/);
  assert.equal(closure.oracle.project, "fireemu-oracle-idp");
  assert.equal(closure.oracle.database, "(default)");
});

test("the closure proposal authorizes no production request", () => {
  const { productionPlan } = load();
  assert.equal(productionPlan.authorizesProduction, false);
  assert.equal(productionPlan.recordingsRequired, 2);
});
