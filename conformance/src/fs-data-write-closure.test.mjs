import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FS-DATA-WRITE.json", import.meta.url),
);
const fixturePath = fileURLToPath(
  new URL("../fs-data-write-production-matrix.json", import.meta.url),
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

function verifyAcceptedCondition(condition) {
  if (condition.status !== "VERIFIED") return;
  assert.ok(
    ["BRACKETED", "RULE_TRANSITION", "NOT_APPLICABLE"].includes(condition.boundaryStatus),
    `${condition.conditionId}: unresolved boundary cannot be VERIFIED`,
  );
  assert.equal(condition.evidence?.productionRecordings?.length, 2);
  assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/);
  assert.ok(condition.evidence?.comparisonPath);
}

test("VERIFIED requires a resolved production boundary classification", () => {
  const condition = {
    conditionId: "example",
    status: "VERIFIED",
    evidence: {
      productionRecordings: ["first", "second"],
      finalArtifactSha256: "a".repeat(64),
      comparisonPath: "example.json",
    },
  };
  for (const boundaryStatus of ["UNBRACKETED", "PENDING_RECORDING"]) {
    assert.throws(() => verifyAcceptedCondition({ ...condition, boundaryStatus }), /boundary/);
  }
  for (const boundaryStatus of ["BRACKETED", "RULE_TRANSITION", "NOT_APPLICABLE"]) {
    assert.doesNotThrow(() => verifyAcceptedCondition({ ...condition, boundaryStatus }));
  }
});

test("FS-DATA-WRITE closure inventory cannot silently omit a declared condition", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
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
        "BRACKETED",
        "RULE_TRANSITION",
        "UNBRACKETED",
        "NOT_APPLICABLE",
        "PENDING_RECORDING",
      ].includes(condition.boundaryStatus),
      `${condition.conditionId}: missing boundary classification`,
    );
    if (["BRACKETED", "RULE_TRANSITION"].includes(condition.boundaryStatus)) {
      assert.equal(condition.boundaryEvidence?.length, 2, condition.conditionId);
      const shape = (reference) => reference.split("#")[0].replace(/\/[^/]+$/, "");
      assert.equal(
        shape(condition.boundaryEvidence[0]),
        shape(condition.boundaryEvidence[1]),
        `${condition.conditionId}: evidence must keep the same recipe family`,
      );
      const pair = condition.boundaryEvidence.map((reference) => {
        const [programId, stepId] = reference.split("#");
        const step = fixture.programs[programId]?.steps[stepId];
        assert.ok(step, `${condition.conditionId}: missing fixture step ${reference}`);
        return step;
      });
      if (condition.boundaryStatus === "BRACKETED") {
        assert.ok(
          pair.some((step) => step.status < 300),
          condition.conditionId,
        );
        assert.ok(
          pair.some((step) => step.status >= 400),
          condition.conditionId,
        );
      } else {
        assert.ok(
          pair.every((step) => step.status >= 400),
          condition.conditionId,
        );
        assert.notEqual(pair[0].message, pair[1].message, condition.conditionId);
      }
    }
    if (condition.recipeIds.some((recipe) => fixture.programs[recipe])) {
      assert.notEqual(condition.status, "PENDING_CORPUS", condition.conditionId);
    }
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
    verifyAcceptedCondition(condition);
  }
  for (const [conditionId, recipes] of requiredRecipes) {
    const condition = closure.conditions.find((row) => row.conditionId === conditionId);
    assert.deepEqual(
      new Set(condition.recipeIds),
      recipes,
      `${conditionId}: incomplete recipe mapping`,
    );
  }
  const allVerified = closure.conditions.every(({ status }) => status === "VERIFIED");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    allVerified && closure.closureReview?.decision === "APPROVED",
    "parent promotion requires every condition and independent closure review",
  );
});
