import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = new URL("../../", import.meta.url);
const closurePath = new URL("spec/compatibility/closure/STORAGE-OBJECT.json", root);

// The inventory is deliberately separate from the official-emulator storage matrix.
// A new production mismatch or uncovered acceptance requirement requires reviewing this set.
const requiredConditions = new Set([
  "STORAGE-OBJECT/firebase-simple-upload",
  "STORAGE-OBJECT/firebase-multipart-upload",
  "STORAGE-OBJECT/firebase-resumable-upload",
  "STORAGE-OBJECT/firebase-download",
  "STORAGE-OBJECT/firebase-download-tokens",
  "STORAGE-OBJECT/firebase-metadata",
  "STORAGE-OBJECT/firebase-delete",
  "STORAGE-OBJECT/firebase-list",
  "STORAGE-OBJECT/firebase-overwrite",
  "STORAGE-OBJECT/gcs-simple-multipart-upload",
  "STORAGE-OBJECT/gcs-resumable-upload",
  "STORAGE-OBJECT/gcs-download",
  "STORAGE-OBJECT/gcs-metadata",
  "STORAGE-OBJECT/gcs-delete",
  "STORAGE-OBJECT/gcs-list",
  "STORAGE-OBJECT/gcs-copy-rewrite",
  "STORAGE-OBJECT/generation-preconditions",
  "STORAGE-OBJECT/metageneration-preconditions",
  "STORAGE-OBJECT/checksums",
  "STORAGE-OBJECT/missing-object-errors",
  "STORAGE-OBJECT/authorization-errors",
  "STORAGE-OBJECT/invalid-object-name-errors",
  "STORAGE-OBJECT/invalid-range-errors",
  "STORAGE-OBJECT/admin-credential",
  "STORAGE-OBJECT/firebase-id-token",
  "STORAGE-OBJECT/cross-dialect-state",
  "STORAGE-OBJECT/final-artifact-regression",
  "STORAGE-OBJECT/closure-review",
]);

const statuses = new Set([
  "PENDING_CORPUS",
  "PENDING_RECORDING",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

const load = () => JSON.parse(readFileSync(closurePath, "utf8"));

test("STORAGE-OBJECT inventory fixes the production closure obligations", () => {
  const closure = load();
  assert.equal(closure.schemaVersion, 1);
  assert.equal(closure.parent, "STORAGE-OBJECT");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.ok(["PROPOSED", "FROZEN"].includes(closure.inventoryState));
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const row of closure.conditions) {
    assert.ok(row.source?.length > 0, row.conditionId);
    assert.ok(row.recipeIds?.length > 0, row.conditionId);
    assert.ok(row.checks?.length > 0, row.conditionId);
    assert.ok(statuses.has(row.status), row.conditionId);
    if (row.status === "VERIFIED") {
      assert.ok(closure.inventoryState === "FROZEN", row.conditionId);
      assert.equal(row.evidence?.productionRecordings?.length, 2, row.conditionId);
      assert.ok(row.evidence.productionRecordings.every((run) => run.project === "fireemu-oracle-query"));
      assert.match(row.evidence.finalArtifactSha256, /^[0-9a-f]{64}$/, row.conditionId);
      const comparison = JSON.parse(
        readFileSync(new URL(row.evidence.comparisonPath, root), "utf8"),
      );
      assert.equal(comparison.artifactSha256, row.evidence.finalArtifactSha256, row.conditionId);
      const isGate = row.conditionId === "STORAGE-OBJECT/final-artifact-regression" ||
        row.conditionId === "STORAGE-OBJECT/closure-review";
      const compared = isGate
        ? comparison.rows
        : comparison.rows.filter(({ row: key }) =>
            row.recipeIds.some((recipe) => key.split("#")[0] === recipe),
          );
      assert.ok(compared.length > 0, `${row.conditionId}: no compared rows`);
      assert.ok(compared.every(({ status }) => status === "MATCH"), row.conditionId);
      if (row.conditionId === "STORAGE-OBJECT/closure-review") {
        assert.equal(closure.closureReview.decision, "APPROVED");
        assert.equal(closure.closureReview.finalArtifactSha256, row.evidence.finalArtifactSha256);
      }
    }
  }
});

test("scope decisions remain visible until the owner decides them", () => {
  const closure = load();
  assert.deepEqual(
    new Set(closure.scopeDecisions.map(({ id }) => id)),
    new Set(["S1", "S2", "S3", "S4", "S5", "S6", "S7"]),
  );
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision?.length > 0, decision.id);
    assert.ok(decision.recommendation?.length > 0, decision.id);
    assert.ok(["PROPOSED", "APPROVED"].includes(decision.status), decision.id);
    if (decision.status === "APPROVED") assert.ok(decision.decidedOn, decision.id);
  }
});

test("parent promotion requires frozen scope, two recordings, final comparison and review", () => {
  const closure = load();
  const allVerified = closure.conditions.every(({ status }) => status === "VERIFIED");
  const approvedScope = closure.scopeDecisions.every(({ status }) => status === "APPROVED");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    closure.inventoryState === "FROZEN" &&
      allVerified &&
      approvedScope &&
      closure.closureReview?.decision === "APPROVED",
  );
});
