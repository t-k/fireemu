import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const root = new URL("../../", import.meta.url);
const closurePath = new URL("spec/compatibility/closure/STORAGE-RULES.json", root);
const load = () => JSON.parse(readFileSync(closurePath, "utf8"));

const requiredConditions = new Set([
  "STORAGE-RULES/method-grants",
  "STORAGE-RULES/list-v2",
  "STORAGE-RULES/anonymous-and-id-token",
  "STORAGE-RULES/token-claims",
  "STORAGE-RULES/token-refusal",
  "STORAGE-RULES/upload-request-resource",
  "STORAGE-RULES/metadata-request-resource",
  "STORAGE-RULES/stored-resource",
  "STORAGE-RULES/create-update-delete-state",
  "STORAGE-RULES/request-time",
  "STORAGE-RULES/path-variables",
  "STORAGE-RULES/recursive-wildcard",
  "STORAGE-RULES/storage-service-compile",
  "STORAGE-RULES/firestore-get",
  "STORAGE-RULES/firestore-exists",
  "STORAGE-RULES/firestore-access-budget",
  "STORAGE-RULES/firebase-denial-shape",
  "STORAGE-RULES/denial-precedence",
  "STORAGE-RULES/gcs-admin-boundary",
  "STORAGE-RULES/download-token-boundary",
  "STORAGE-RULES/release-switch",
  "STORAGE-RULES/no-release",
  "STORAGE-RULES/final-artifact-regression",
  "STORAGE-RULES/closure-review",
]);

const pendingOrVerified = new Set([
  "PENDING_CORPUS",
  "PENDING_RECORDING",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

test("STORAGE-RULES freeze retains all behavioral obligations", () => {
  const closure = load();
  assert.equal(closure.schemaVersion, 1);
  assert.equal(closure.parent, "STORAGE-RULES");
  assert.equal(closure.inventoryState, "FROZEN");
  assert.equal(closure.observationContract.productionRecordingsRequired, 2);
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size);
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const row of closure.conditions) {
    assert.ok(row.source?.length > 0, row.conditionId);
    assert.ok(row.recipeIds?.length > 0, row.conditionId);
    assert.ok(row.checks?.length > 0, row.conditionId);
    assert.ok(pendingOrVerified.has(row.status), row.conditionId);
    if (row.status === "VERIFIED") {
      assert.equal(row.evidence?.productionRecordings?.length, 2, row.conditionId);
      assert.match(row.evidence.finalArtifactSha256, /^[0-9a-f]{64}$/, row.conditionId);
      assert.ok(row.evidence.comparisonPath?.length > 0, row.conditionId);
    }
  }
});

test("scope decisions cite the recorded owner or delegated decisions", () => {
  const closure = load();
  assert.deepEqual(new Set(closure.scopeDecisions.map(({ id }) => id)), new Set(["S1", "S2", "S3", "S4", "S5", "S6"]));
  for (const row of closure.scopeDecisions) {
    assert.equal(row.status, "APPROVED", row.id);
    assert.equal(row.decidedOn, "2026-09-25", row.id);
    assert.match(row.decisionRef, /owner-decisions\.md.*STORAGE-RULES/, row.id);
    assert.equal(row.decidedBy, ["S2", "S4", "S5"].includes(row.id) ? "owner" : "coordinator (delegated)", row.id);
  }
});

test("COMPAT_VERIFIED requires every condition and independent closure review", () => {
  const closure = load();
  const eligible = closure.inventoryState === "FROZEN" &&
    closure.scopeDecisions.every(({ status }) => status === "APPROVED") &&
    closure.conditions.every(({ status }) => status === "VERIFIED") &&
    closure.closureReview.decision === "APPROVED";
  assert.equal(closure.parentStatus === "COMPAT_VERIFIED", eligible);
});
