import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FS-DATA-WRITE.json", import.meta.url),
);

const requiredConditions = new Set([
  "FS-WRITE-LIMITS-03/batch-malformed-middle",
  "FS-WRITE-LIMITS-03/batch-undecodable-value",
  "FS-WRITE-LIMITS-03/batch-duplicate-document",
  "FS-LIMIT-COLLECTION-ID",
  "FS-LIMIT-SUBCOLLECTION-DEPTH",
  "FS-LIMIT-DOCUMENT-NAME-BYTES",
  "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
  "FS-LIMIT-INDEX-ENTRY-BYTES",
  "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
  "FS-LIMIT-FIELD-PATH-BYTES",
  "FS-LIMIT-FIELD-VALUE-BYTES/scalar-refusal",
  "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-string",
  "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-map",
  "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES",
  "FS-WRITE-LIMITS-03/implied-map",
  "FS-WRITE-LIMITS-03/implied-array",
  "FS-LIMIT-API-REQUEST-BYTES/decoded-10mib",
  "FS-LIMIT-API-REQUEST-BYTES/raw-16mib-over",
  "FS-DATA-WRITE/stream-transaction-precedence",
  "FS-DATA-WRITE/write-stream-trailing-metadata",
  "FS-DATA-WRITE/write-stream-half-close",
  "FS-DATA-WRITE/final-artifact-regression",
  "FS-DATA-WRITE/closure-review",
]);

const requiredRecipes = new Map([
  [
    "FS-LIMIT-COLLECTION-ID",
    new Set([
      "writes/limits/collection-id-boundary",
      "writes/limits/collection-id-slash",
      "writes/limits/collection-id-dot",
      "writes/limits/collection-id-dot-dot",
      "writes/limits/collection-id-reserved",
    ]),
  ],
  [
    "FS-LIMIT-FIELD-PATH-BYTES",
    new Set([
      "writes/limits/implied-map",
      "writes/limits/implied-array",
      "writes/limits/field-path-direct-mask",
      "writes/limits/field-path-mask/1499",
      "writes/limits/field-path-mask/1500",
      "writes/limits/implied-array-key/1494",
      "writes/limits/implied-array-key/1495",
    ]),
  ],
  [
    "FS-DATA-WRITE/final-artifact-regression",
    new Set([
      "firestore/historical-324",
      "writes/batch-write-malformed",
      "writes/limits",
      "writes/write-stream-transaction",
      "writes/write-stream-terminal",
    ]),
  ],
]);

test("FS-DATA-WRITE closure inventory cannot silently omit a declared condition", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  assert.equal(closure.parent, "FS-DATA-WRITE");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const condition of closure.conditions) {
    assert.equal(typeof condition.source, "string");
    assert.ok(condition.source.length > 0);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0);
    assert.ok(
      [
        "PENDING_CORPUS",
        "SAVED_REFERENCE_PENDING_FINAL",
        "PRODUCTION_RECORDED",
        "MISMATCH",
        "VERIFIED",
        "PENDING_REVIEW",
      ].includes(condition.status),
      `${condition.conditionId}: unknown status`,
    );
    if (condition.status === "VERIFIED") {
      assert.equal(condition.evidence?.productionRecordings?.length, 2);
      assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/);
      assert.ok(condition.evidence?.comparisonPath);
    }
  }
  for (const [conditionId, recipes] of requiredRecipes) {
    const condition = closure.conditions.find((row) => row.conditionId === conditionId);
    assert.deepEqual(
      new Set(condition.recipeIds),
      recipes,
      `${conditionId}: incomplete recipe mapping`,
    );
  }
  for (const conditionId of [
    "FS-LIMIT-DOCUMENT-NAME-BYTES",
    "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
    "FS-LIMIT-INDEX-ENTRY-BYTES",
    "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
    "FS-LIMIT-FIELD-PATH-BYTES",
    "FS-WRITE-LIMITS-03/implied-array",
  ]) {
    const condition = closure.conditions.find((row) => row.conditionId === conditionId);
    assert.ok(
      ["UNBRACKETED_EXACT", "PENDING_RECORDING", "BRACKETED_IN_INTERMEDIATE_RECORDING"].includes(
        condition.boundaryStatus,
      ),
      `${conditionId}: boundary state must not be inferred from recipe presence`,
    );
  }
  const allVerified = closure.conditions.every(({ status }) => status === "VERIFIED");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    allVerified && closure.closureReview?.decision === "APPROVED",
    "parent promotion requires every condition and independent closure review",
  );
});
