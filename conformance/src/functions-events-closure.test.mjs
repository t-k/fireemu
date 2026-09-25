import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FUNCTIONS-EVENTS.json", import.meta.url),
);

const requiredConditions = new Set([
  "FUNCTIONS-EVENTS/firestore-created",
  "FUNCTIONS-EVENTS/firestore-updated",
  "FUNCTIONS-EVENTS/firestore-deleted",
  "FUNCTIONS-EVENTS/firestore-written",
  "FUNCTIONS-EVENTS/firestore-noop",
  "FUNCTIONS-EVENTS/firestore-routing-params",
  "FUNCTIONS-EVENTS/firestore-payload",
  "FUNCTIONS-EVENTS/firestore-auth-context",
  "FUNCTIONS-EVENTS/storage-finalized",
  "FUNCTIONS-EVENTS/storage-deleted",
  "FUNCTIONS-EVENTS/storage-metadata-updated",
  "FUNCTIONS-EVENTS/storage-archived",
  "FUNCTIONS-EVENTS/storage-payload",
  "FUNCTIONS-EVENTS/storage-bucket-routing",
  "FUNCTIONS-EVENTS/auth-created",
  "FUNCTIONS-EVENTS/auth-deleted",
  "FUNCTIONS-EVENTS/auth-payload",
  "FUNCTIONS-EVENTS/pubsub-published",
  "FUNCTIONS-EVENTS/pubsub-topic-routing",
  "FUNCTIONS-EVENTS/delivery-retry-identity",
  "FUNCTIONS-EVENTS/final-artifact-regression",
  "FUNCTIONS-EVENTS/closure-review",
]);

const requiredCases = {
  "firestore-created": ["new-document", "before-absent", "after-present"],
  "firestore-updated": ["changed-field", "before-present", "after-present"],
  "firestore-deleted": ["deleted-document", "before-present", "after-absent"],
  "firestore-written": ["create", "update", "delete"],
  "firestore-noop": ["same-value-write-no-event"],
  "firestore-routing-params": ["matching-path", "nonmatching-path", "wildcard-param"],
  "firestore-payload": [
    "handler-envelope",
    "field-values",
    "document-name",
    "update-time",
    "event-metadata",
  ],
  "firestore-auth-context": ["authenticated-write", "admin-write", "auth-type-and-id"],
  "storage-finalized": ["new-object", "overwritten-generation", "failed-upload-no-event"],
  "storage-deleted": ["live-object-delete", "no-event-for-missing-object"],
  "storage-metadata-updated": ["custom-metadata-change", "metageneration"],
  "storage-archived": ["versioned-overwrite", "archived-generation"],
  "storage-payload": [
    "handler-envelope",
    "name-and-bucket",
    "generation",
    "content-type",
    "event-metadata",
  ],
  "storage-bucket-routing": [
    "matching-bucket",
    "nonmatching-bucket",
    "same-bucket-other-prefix-delivered",
  ],
  "auth-created": ["admin-create", "email-password-create", "repeat-sign-in-no-event"],
  "auth-deleted": ["single-user-delete", "bulk-delete-no-event"],
  "auth-payload": ["handler-envelope", "uid", "email", "empty-provider-data", "event-metadata"],
  "pubsub-published": [
    "handler-envelope",
    "base64-data",
    "attributes",
    "message-id",
    "publish-time",
  ],
  "pubsub-topic-routing": ["matching-topic", "nonmatching-topic", "ordering-key"],
  "delivery-retry-identity": [
    "handler-failure",
    "fail-once-then-success",
    "retry-enabled",
    "event-id-across-attempts",
  ],
  "final-artifact-regression": [
    "two-production-recordings",
    "same-source-final-artifact-comparison",
    "workspace-regression",
  ],
  "closure-review": ["independent-coordinator-approval"],
};

const readClosure = () => JSON.parse(readFileSync(closurePath, "utf8"));
const readRepo = (path) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), "utf8"));

function assertCaseCoverage(condition, rows) {
  const label = condition.conditionId;
  const generations = condition.generations ?? [null];
  for (const name of condition.cases) {
    for (const generation of generations) {
      const caseRows = rows.filter(
        (row) => row.case === name && (row.generation ?? null) === generation,
      );
      const caseLabel = generation === null ? name : `${name} v${generation}`;
      assert.ok(caseRows.length > 0, `${label}: ${caseLabel} comparison rows`);
      assert.ok(
        caseRows.every(({ status }) => status === "MATCH"),
        `${label}: ${caseLabel} comparison matches`,
      );
    }
  }
}

function validateClosure(closure) {
  assert.equal(closure.schemaVersion, 1);
  assert.equal(closure.parent, "FUNCTIONS-EVENTS");
  assert.ok(["IMPLEMENTING", "COMPAT_VERIFIED"].includes(closure.parentStatus));
  assert.ok(["PROPOSED", "FROZEN"].includes(closure.inventoryStatus));
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.equal(closure.oracle.plannedProject, "fireemu-oracle-events");
  assert.ok(["PLANNED", "READY"].includes(closure.oracle.projectStatus));
  assert.ok(["PENDING", "APPROVED"].includes(closure.closureReview.decision));
  if (closure.inventoryStatus === "FROZEN") {
    assert.match(closure.frozenOn, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(closure.freezeAuthority);
  }

  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const [suffix, cases] of Object.entries(requiredCases)) {
    const condition = closure.conditions.find(
      ({ conditionId }) => conditionId === `FUNCTIONS-EVENTS/${suffix}`,
    );
    assert.ok(condition, suffix);
    for (const name of cases) assert.ok(condition.cases.includes(name), `${suffix}: ${name}`);
  }
  assert.deepEqual(
    new Set(closure.scopeDecisions.map(({ id }) => id)),
    new Set(["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9"]),
  );
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision && decision.rationale, decision.id);
    assert.ok(["FROZEN", "PROPOSED"].includes(decision.status), decision.id);
    if (decision.id === "E1" || decision.status === "FROZEN") {
      assert.ok(decision.decidedBy && decision.decidedOn && decision.decisionRef, decision.id);
    }
    if (closure.inventoryStatus === "FROZEN") assert.equal(decision.status, "FROZEN");
  }
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    assert.ok(typeof condition.source === "string" && condition.source.length > 0, label);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0, label);
    assert.ok(
      condition.recipeIds.every((id) => id.startsWith("functions-events/")),
      label,
    );
    assert.ok(Array.isArray(condition.cases) && condition.cases.length > 0, label);
    assert.ok(
      [
        "PENDING_CORPUS",
        "PENDING_SCOPE",
        "PENDING_REVIEW",
        "PRODUCTION_RECORDED",
        "MISMATCH",
        "VERIFIED",
      ].includes(condition.status),
      label,
    );
    if (closure.inventoryStatus === "PROPOSED") {
      assert.ok(
        ["PENDING_CORPUS", "PENDING_SCOPE", "PENDING_REVIEW"].includes(condition.status),
        label,
      );
      assert.equal(
        condition.evidence,
        undefined,
        `${label}: proposal cannot claim production evidence`,
      );
    }
    const source = label.split("/")[1].split("-")[0];
    if (["firestore", "storage", "pubsub"].includes(source)) {
      assert.deepEqual(
        condition.generations,
        label.endsWith("/firestore-auth-context") ? [2] : [1, 2],
        `${label}: generation coverage`,
      );
    } else if (source === "auth") {
      assert.deepEqual(condition.generations, [1], `${label}: generation coverage`);
    } else if (source === "delivery") {
      assert.deepEqual(condition.generations, [2], `${label}: representative generation`);
      assert.deepEqual(condition.sources, ["firestore"], `${label}: representative source`);
    }
    if (condition.status !== "VERIFIED") continue;
    const recordings = condition.evidence?.productionRecordings ?? [];
    assert.equal(recordings.length, 2, `${label}: two production recordings`);
    assert.notEqual(recordings[0].recordedAt, recordings[1].recordedAt, label);
    for (const recording of recordings) {
      assert.equal(recording.project, "fireemu-oracle-events", label);
      assert.match(recording.corpusDigest, /^[0-9a-f]{64}$/, label);
    }
    assert.equal(recordings[0].corpusDigest, recordings[1].corpusDigest, label);
    assert.match(condition.evidence.finalArtifactSha256, /^[0-9a-f]{64}$/, label);
    const comparison = readRepo(condition.evidence.comparisonPath);
    assert.equal(comparison.artifactSha256, condition.evidence.finalArtifactSha256, label);
    const rows = comparison.rows.filter(({ row }) =>
      condition.recipeIds.some((recipe) =>
        recipe.endsWith("/")
          ? row.startsWith(recipe)
          : row === recipe || row.startsWith(`${recipe}#`),
      ),
    );
    assert.ok(rows.length > 0, `${label}: comparison rows`);
    assert.ok(
      rows.every(({ status }) => status === "MATCH"),
      `${label}: comparison matches`,
    );
    assertCaseCoverage(condition, rows);
    if (label === "FUNCTIONS-EVENTS/closure-review") {
      assert.equal(closure.closureReview.decision, "APPROVED");
      assert.equal(closure.closureReview.finalArtifactSha256, comparison.artifactSha256);
      assert.ok(closure.closureReview.reviewer && closure.closureReview.reviewRef);
      assert.match(closure.closureReview.decidedOn, /^\d{4}-\d{2}-\d{2}$/);
      assert.match(closure.closureReview.reviewedCommit, /^[0-9a-f]{40}$/);
    }
  }
  if (closure.inventoryStatus === "PROPOSED") {
    assert.equal(
      closure.conditions.find(({ conditionId }) => conditionId.endsWith("/storage-archived"))
        .status,
      "PENDING_SCOPE",
    );
  }
  if (closure.parentStatus === "COMPAT_VERIFIED") {
    assert.equal(closure.inventoryStatus, "FROZEN");
    assert.ok(closure.conditions.every(({ status }) => status === "VERIFIED"));
    assert.equal(closure.closureReview.decision, "APPROVED");
  }
}

test("FUNCTIONS-EVENTS proposal retains the source, routing, payload, and review obligations", () => {
  validateClosure(readClosure());
});

test("FUNCTIONS-EVENTS proposal rejects a missing event case and false evidence", () => {
  const missing = readClosure();
  const pubsub = missing.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/pubsub-published"),
  );
  pubsub.cases = pubsub.cases.filter((name) => name !== "attributes");
  assert.throws(() => validateClosure(missing), /pubsub-published: attributes/);

  const falseEvidence = readClosure();
  falseEvidence.conditions[0].evidence = { productionRecordings: [] };
  assert.throws(() => validateClosure(falseEvidence), /proposal cannot claim production evidence/);

  const falsePromotion = readClosure();
  falsePromotion.parentStatus = "COMPAT_VERIFIED";
  assert.throws(() => validateClosure(falsePromotion), /FROZEN/);

  const firestoreCreate = readClosure().conditions.find(({ conditionId }) =>
    conditionId.endsWith("/firestore-created"),
  );
  assert.throws(
    () =>
      assertCaseCoverage(firestoreCreate, [
        {
          row: "functions-events/firestore/create#new-document#v1",
          case: "new-document",
          generation: 1,
          status: "MATCH",
        },
      ]),
    /new-document v2 comparison rows/,
  );

  const finalArtifact = readClosure().conditions.find(({ conditionId }) =>
    conditionId.endsWith("/final-artifact-regression"),
  );
  assert.throws(
    () =>
      assertCaseCoverage(finalArtifact, [
        {
          row: "functions-events/firestore/create#new-document#v1",
          case: "new-document",
          generation: 1,
          status: "MATCH",
        },
      ]),
    /two-production-recordings comparison rows/,
  );
});
