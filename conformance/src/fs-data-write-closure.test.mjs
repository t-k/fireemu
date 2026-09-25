import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { compareSandboxArtifact } from "./fs-data-write-sandbox.mjs";
import {
  prepareSandboxCorpus,
  selectComparableSandboxRecipes,
  selectSupplementComparisons,
} from "./fs-data-write-sandbox-run.mjs";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FS-DATA-WRITE.json", import.meta.url),
);
const fixturePath = fileURLToPath(
  new URL("../fs-data-write-production-matrix.json", import.meta.url),
);
const manifestPath = fileURLToPath(
  new URL("../fs-data-write-recipe-digests.json", import.meta.url),
);
const reviewCandidatePath = fileURLToPath(
  new URL(
    "../../spec/compatibility/closure/evidence/FS-DATA-WRITE-current-comparison.json",
    import.meta.url,
  ),
);
const acceptedConditionsPath = fileURLToPath(
  new URL(
    "../../spec/compatibility/closure/evidence/FS-DATA-WRITE-current-accepted-conditions.json",
    import.meta.url,
  ),
);
const acceptedLocalRowsPath = fileURLToPath(
  new URL(
    "../../spec/compatibility/closure/evidence/FS-DATA-WRITE-current-accepted-local-rows.json",
    import.meta.url,
  ),
);
const savedStreamReplayPath = fileURLToPath(
  new URL(
    "../../spec/compatibility/closure/evidence/FS-DATA-WRITE-stream-transaction-current-saved-replay.json",
    import.meta.url,
  ),
);
const listComparisonPath = fileURLToPath(
  new URL(
    "../../spec/compatibility/closure/evidence/FS-DATA-WRITE-LIST-comparison.json",
    import.meta.url,
  ),
);
const terminalConditionPath = fileURLToPath(
  new URL(
    "../../spec/compatibility/closure/evidence/FS-DATA-WRITE-terminal-local-digests.json",
    import.meta.url,
  ),
);
const supplements = [
  "partial-7bfd51026a2ac56617d81504.json",
  "delta-v3-a14f265fea575003423c7ebd.json",
].map((name) => ({
  name,
  fixture: JSON.parse(
    readFileSync(
      new URL(`../fs-data-write-production-supplements/${name}`, import.meta.url),
      "utf8",
    ),
  ),
}));

function currentRecordingSelection(fixture, manifest, corpus) {
  const base = selectComparableSandboxRecipes(fixture, manifest, corpus, corpus);
  const supplemental = selectSupplementComparisons(
    supplements,
    corpus,
    base.pendingRestIds,
    base.pendingStreamIds,
  );
  return { base, supplemental };
}

test("final write comparison keeps approved B1 rows and unresolved D5 rows explicit", () => {
  const candidate = JSON.parse(readFileSync(reviewCandidatePath, "utf8"));
  assert.equal(candidate.task, "FS-DATA-WRITE");
  assert.equal(candidate.decision, "PENDING_REVIEW");
  assert.match(candidate.sourceHead, /^[0-9a-f]{40}$/);
  assert.match(candidate.executableSha256, /^[0-9a-f]{64}$/);
  assert.equal(candidate.comparedRestPrograms, 74);
  assert.equal(candidate.comparedGrpcStreams, 7);
  assert.deepEqual(candidate.pendingRestIds, []);
  assert.deepEqual(candidate.pendingStreamIds, []);
  assert.deepEqual(candidate.otherDifferenceIds, []);
  assert.equal(candidate.retiredRestIds.length, 10);
  assert.deepEqual(
    candidate.approvedKnownDifferenceIds,
    [
      ...Array.from({ length: 4 }, (_, at) => `writes/limits/index-entry-bytes#observation-${at}`),
      ...Array.from(
        { length: 4 },
        (_, at) => `writes/limits/index-entry-sum-per-document#observation-${at}`,
      ),
      "writes/limits/empty-document-name/4628#readback",
      "writes/limits/empty-document-name/4628#write",
    ].toSorted(),
  );
  assert.deepEqual(candidate.pendingOracleDifferenceIds, [
    "writes/limits/grpc-stream-request-bytes/10485760#grpc",
    "writes/limits/grpc-stream-request-bytes/10485761#grpc",
  ]);
  assert.equal(candidate.historicalRegression, undefined);
  assert.ok(candidate.reviewNotes.every((note) => !note.includes("remain pending integration")));
  for (const fixture of candidate.productionFixtures) {
    const path = fileURLToPath(new URL(`../../${fixture.path}`, import.meta.url));
    const digest = createHash("sha256").update(readFileSync(path)).digest("hex");
    assert.equal(fixture.sha256, digest, fixture.path);
    assert.equal(fixture.recordingDigests.length, 2, fixture.path);
  }
});

test("current accepted conditions bind every selected row and only D3 differences", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const candidate = JSON.parse(readFileSync(reviewCandidatePath, "utf8"));
  const accepted = JSON.parse(readFileSync(acceptedConditionsPath, "utf8"));
  const localRows = JSON.parse(readFileSync(acceptedLocalRowsPath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const { base, supplemental } = currentRecordingSelection(fixture, manifest, corpus);
  const sourceById = new Map();
  for (const selection of [{ name: "base", ...base }, ...supplemental.comparisons]) {
    for (const id of [...selection.matchedRestIds, ...selection.matchedStreamIds]) {
      assert.ok(!sourceById.has(id), `${id}: duplicate current recording`);
      sourceById.set(id, selection);
    }
  }
  const acceptedIds = new Map([
    ["FS-WRITE-LIMITS-03/batch-undecodable-value", "VERIFIED"],
    ["FS-DATA-WRITE/map-value-key-validation", "VERIFIED"],
    ["FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT", "VERIFIED"],
    ["FS-LIMIT-FIELD-PATH-BYTES", "VERIFIED"],
    ["FS-DATA-WRITE/write-stream-trailing-metadata", "VERIFIED"],
    ["FS-DATA-WRITE/write-stream-empty-write-response", "VERIFIED"],
    ["FS-LIMIT-INDEX-ENTRY-BYTES", "DIVERGENCE_APPROVED"],
    ["FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT", "DIVERGENCE_APPROVED"],
  ]);
  assert.deepEqual(new Set(Object.keys(accepted.conditions)), new Set(acceptedIds.keys()));
  assert.equal(accepted.sourceHead, candidate.sourceHead);
  assert.equal(accepted.executableSha256, candidate.executableSha256);
  assert.equal(
    accepted.currentComparisonSha256,
    createHash("sha256").update(readFileSync(reviewCandidatePath)).digest("hex"),
  );
  assert.deepEqual(accepted.localResultDigests, candidate.localResultDigests);
  assert.equal(
    accepted.localProjectionPath,
    "spec/compatibility/closure/evidence/FS-DATA-WRITE-current-accepted-local-rows.json",
  );
  assert.equal(
    accepted.localProjectionSha256,
    createHash("sha256").update(readFileSync(acceptedLocalRowsPath)).digest("hex"),
  );
  assert.equal(localRows.sourceHead, accepted.sourceHead);
  assert.equal(localRows.executableSha256, accepted.executableSha256);
  assert.deepEqual(localRows.sourceResultDigests, accepted.localResultDigests);
  const acceptedSha256 = createHash("sha256")
    .update(readFileSync(acceptedConditionsPath))
    .digest("hex");
  const b1Rows = new Set(candidate.approvedKnownDifferenceIds);
  const usedLocalRows = new Set();
  for (const [conditionId, status] of acceptedIds) {
    const condition = closure.conditions.find((row) => row.conditionId === conditionId);
    const comparison = accepted.conditions[conditionId];
    assert.equal(condition.status, status, conditionId);
    assert.deepEqual(new Set(comparison.recipeIds), new Set(condition.recipeIds), conditionId);
    assert.equal(
      condition.evidence.comparisonPath,
      "spec/compatibility/closure/evidence/FS-DATA-WRITE-current-accepted-conditions.json",
    );
    assert.equal(condition.evidence.comparisonSha256, acceptedSha256);
    assert.equal(condition.evidence.finalArtifactSha256, accepted.executableSha256);
    assert.equal(condition.evidence.sourceHead, accepted.sourceHead);
    assert.deepEqual(
      condition.evidence.productionRecordings,
      comparison.productionRecordingSetDigests,
    );
    assert.deepEqual(condition.evidence.productionRecordingSources, comparison.sourceFixtures);
    const sourceFixtures = new Map();
    for (const recipeId of condition.recipeIds) {
      const source = sourceById.get(recipeId);
      assert.ok(source, `${conditionId}: missing current recording ${recipeId}`);
      const transport = source.matchedStreamIds.includes(recipeId) ? "grpc" : "rest";
      const path =
        source.name === "base"
          ? "conformance/fs-data-write-production-matrix.json"
          : `conformance/fs-data-write-production-supplements/${source.name}`;
      const recordingDigests =
        transport === "grpc"
          ? source.fixture.evidence.streamRecordingDigests
          : source.fixture.evidence.recordingDigests;
      sourceFixtures.set(`${path}:${transport}`, {
        path,
        sha256: createHash("sha256")
          .update(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url))))
          .digest("hex"),
        recordingDigests,
        transport,
      });
    }
    const expectedSources = [...sourceFixtures.values()].toSorted(
      (a, b) => a.path.localeCompare(b.path) || a.transport.localeCompare(b.transport),
    );
    assert.deepEqual(comparison.sourceFixtures, expectedSources, conditionId);
    assert.ok(expectedSources.every(({ recordingDigests }) => recordingDigests.length === 2));
    assert.deepEqual(
      comparison.productionRecordingSetDigests,
      [0, 1].map((pass) =>
        createHash("sha256")
          .update(
            JSON.stringify(
              expectedSources.map(({ path, sha256, recordingDigests, transport }) => ({
                path,
                sha256,
                transport,
                recordingDigest: recordingDigests[pass],
              })),
            ),
          )
          .digest("hex"),
      ),
      conditionId,
    );
    const expectedRows = condition.recipeIds.flatMap((id) => {
      const source = sourceById.get(id);
      assert.ok(source, `${conditionId}: missing current recording ${id}`);
      if (source.matchedStreamIds.includes(id)) return [`${id}#grpc`];
      return Object.keys(source.fixture.programs[id].steps).map((step) => `${id}#${step}`);
    });
    const actualDifferences = new Set();
    for (const recipeId of condition.recipeIds) {
      const source = sourceById.get(recipeId);
      const stream = source.matchedStreamIds.includes(recipeId);
      const ids = stream
        ? [`${recipeId}#grpc`]
        : Object.keys(source.fixture.programs[recipeId].steps).map((step) => `${recipeId}#${step}`);
      const local = stream
        ? localRows.rows[ids[0]]
        : {
            steps: Object.fromEntries(
              ids.map((id) => [id.slice(id.lastIndexOf("#") + 1), localRows.rows[id]]),
            ),
          };
      assert.ok(
        ids.every((id) => localRows.rows[id] !== undefined),
        recipeId,
      );
      ids.forEach((id) => usedLocalRows.add(id));
      const recipe = corpus.restPrograms.find(({ id }) => id === recipeId);
      const differences = compareSandboxArtifact(
        stream
          ? { streams: { [recipeId]: source.fixture.streams[recipeId] } }
          : { programs: { [recipeId]: source.fixture.programs[recipeId] } },
        stream ? {} : { [recipeId]: local },
        stream ? { [recipeId]: local } : {},
        { restPrograms: recipe ? [recipe] : [] },
      );
      differences.forEach((id) => actualDifferences.add(id));
    }
    assert.equal(comparison.rows.length, expectedRows.length, conditionId);
    assert.equal(new Set(expectedRows).size, expectedRows.length, conditionId);
    assert.deepEqual(
      new Set(comparison.rows.map(({ id }) => id)),
      new Set(expectedRows),
      conditionId,
    );
    const differenceIds = [...actualDifferences].toSorted();
    const knownIds =
      status === "DIVERGENCE_APPROVED"
        ? expectedRows.filter((id) => b1Rows.has(id)).toSorted()
        : [];
    assert.deepEqual(differenceIds, knownIds, conditionId);
    if (status === "DIVERGENCE_APPROVED") {
      assert.equal(condition.evidence.ownerDecision, "2026-09-25 FS-DATA-WRITE D3");
      assert.deepEqual(condition.evidence.knownDifferenceIds, differenceIds, conditionId);
    } else {
      assert.equal(condition.evidence.knownDifferenceIds, undefined);
    }
    for (const row of comparison.rows) {
      const recipeId = row.id.slice(0, row.id.lastIndexOf("#"));
      const stepId = row.id.slice(row.id.lastIndexOf("#") + 1);
      const source = sourceById.get(recipeId);
      assert.equal(
        row.fixture,
        source.name === "base"
          ? "conformance/fs-data-write-production-matrix.json"
          : `conformance/fs-data-write-production-supplements/${source.name}`,
      );
      const production =
        stepId === "grpc"
          ? source.fixture.streams[recipeId]
          : source.fixture.programs[recipeId].steps[stepId];
      assert.equal(
        row.productionSha256,
        createHash("sha256").update(JSON.stringify(production)).digest("hex"),
        row.id,
      );
      assert.equal(
        row.productionStatus,
        stepId === "grpc" ? production.status.code : production.status,
        row.id,
      );
      assert.equal(row.productionCode, stepId === "grpc" ? "GRPC" : production.code, row.id);
      const local = localRows.rows[row.id];
      assert.equal(
        row.localSha256,
        createHash("sha256").update(JSON.stringify(local)).digest("hex"),
        row.id,
      );
      assert.equal(row.localStatus, stepId === "grpc" ? local.status.code : local.status, row.id);
      assert.equal(row.localCode, stepId === "grpc" ? "GRPC" : local.code, row.id);
      const mismatch = actualDifferences.has(row.id);
      assert.equal(row.comparisonResult, mismatch ? "MISMATCH" : "MATCH", row.id);
      assert.equal(row.outcome, mismatch ? "DIVERGENCE_APPROVED" : "MATCH", row.id);
      if (mismatch) {
        assert.equal(row.outcome, "DIVERGENCE_APPROVED");
        assert.equal(row.ownerDecision, "2026-09-25 FS-DATA-WRITE D3");
        assert.ok(b1Rows.has(row.id), row.id);
      }
    }
  }
  assert.deepEqual(new Set(Object.keys(localRows.rows)), usedLocalRows);
  assert.deepEqual(new Set(accepted.approvedDifferenceIds), b1Rows);
  assert.deepEqual(accepted.unresolvedDifferenceIds, candidate.pendingOracleDifferenceIds);
});

test("saved stream transaction recompare binds its one production campaign and current local artifact", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/stream-transaction-precedence",
  );
  const evidence = JSON.parse(readFileSync(savedStreamReplayPath, "utf8"));
  const publicProductionPath = fileURLToPath(
    new URL(`../../${evidence.productionPublicResultPath}`, import.meta.url),
  );
  const publicSavedPath = fileURLToPath(
    new URL(`../../${evidence.savedComparisonPath}`, import.meta.url),
  );
  const publicProduction = JSON.parse(readFileSync(publicProductionPath, "utf8"));
  const publicSaved = JSON.parse(readFileSync(publicSavedPath, "utf8"));
  const recipeDigests = JSON.parse(readFileSync(manifestPath, "utf8"));
  assert.equal(condition.status, "VERIFIED");
  assert.deepEqual(condition.recipeIds, ["writes/write-stream-transaction"]);
  assert.equal(condition.boundaryStatus, "NOT_APPLICABLE");
  assert.equal(
    condition.evidence.comparisonPath,
    "spec/compatibility/closure/evidence/FS-DATA-WRITE-stream-transaction-current-saved-replay.json",
  );
  assert.equal(
    condition.evidence.comparisonSha256,
    createHash("sha256").update(readFileSync(savedStreamReplayPath)).digest("hex"),
  );
  assert.equal(condition.evidence.finalArtifactSha256, evidence.binarySha256);
  assert.equal(condition.evidence.sourceHead, evidence.sourceCommit);
  assert.equal(condition.evidence.productionReceiptSha256, evidence.productionReceiptSha256);
  assert.equal(
    condition.evidence.savedProductionAuthorityDigest,
    evidence.savedProductionAuthorityDigest,
  );
  assert.equal(condition.evidence.productionRecordings, undefined);
  assert.equal(evidence.recipeDigest, recipeDigests.streams[condition.recipeIds[0]]);
  assert.equal(
    evidence.productionPublicResultSha256,
    createHash("sha256").update(readFileSync(publicProductionPath)).digest("hex"),
  );
  assert.equal(
    evidence.savedComparisonSha256,
    createHash("sha256").update(readFileSync(publicSavedPath)).digest("hex"),
  );
  assert.equal(
    publicProduction.privateEvidenceSha256.productionReceipt,
    evidence.productionReceiptSha256,
  );
  assert.equal(publicProduction.production.dataRequests, 23);
  assert.equal(publicProduction.production.cleanupComplete, true);
  assert.equal(
    publicSaved.privateEvidenceSha256.originalProductionReceipt,
    evidence.productionReceiptSha256,
  );
  assert.equal(publicSaved.repairedClassification, "EXPECTED_NONDETERMINISM");
  assert.deepEqual(evidence.comparison, {
    v1Classification: "SEMANTIC_MISMATCH",
    v2Classification: "EXPECTED_NONDETERMINISM",
    v1ComparedSlotCount: 15,
    v1DifferingSlotCount: 5,
    v1DifferenceLeafCount: 32,
    indeterminate: 0,
  });
  assert.deepEqual(evidence.localRun, {
    gateEvents: 23,
    observations: 15,
    recoveryObservations: 10,
    resourcesAbsent: 3,
    processStopped: true,
    listenersClosed: true,
    reservationReleased: true,
    configurationUnchanged: true,
  });
  assert.match(evidence.sourceCommit, /^[0-9a-f]{40}$/);
  for (const field of [
    "binarySha256",
    "buildManifestSha256",
    "localReceiptSha256",
    "productionReceiptSha256",
    "savedProductionAuthorityDigest",
    "runtimeInputsDigest",
  ]) {
    assert.match(evidence[field], /^[0-9a-f]{64}$/, field);
  }
  assert.ok(evidence.runtimeInputCount > 400);
  for (const [path, digest] of Object.entries(evidence.comparatorSourceSha256)) {
    const absolute = fileURLToPath(new URL(`../../${path}`, import.meta.url));
    assert.equal(digest, createHash("sha256").update(readFileSync(absolute)).digest("hex"), path);
  }
});

const requiredConditions = new Set([
  "FS-WRITE-LIMITS-03/batch-malformed-middle",
  "FS-WRITE-LIMITS-03/batch-undecodable-value",
  "FS-DATA-WRITE/map-value-key-validation",
  "FS-WRITE-LIMITS-03/batch-duplicate-document",
  "FS-LIMIT-COLLECTION-ID",
  "FS-LIMIT-SUBCOLLECTION-DEPTH",
  "FS-LIMIT-DOCUMENT-NAME-BYTES",
  "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
  "FS-LIMIT-INDEX-ENTRY-BYTES",
  "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
  "FS-DATA-WRITE/near-limit-delete-refusal",
  "FS-LIMIT-FIELD-PATH-BYTES",
  "FS-LIMIT-FIELD-VALUE-BYTES/scalar-refusal",
  "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-string",
  "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-map",
  "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES",
  "FS-WRITE-LIMITS-03/implied-map",
  "FS-WRITE-LIMITS-03/implied-array",
  "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
  "FS-LIMIT-API-REQUEST-BYTES/raw-16mib-over",
  "FS-LIMIT-API-REQUEST-BYTES/non-commit-rest",
  "FS-LIMIT-API-REQUEST-BYTES/webchannel",
  "FS-LIMIT-API-REQUEST-BYTES/grpc",
  "FS-DATA-WRITE/stream-transaction-precedence",
  "FS-DATA-WRITE/write-stream-trailing-metadata",
  "FS-DATA-WRITE/write-stream-half-close",
  "FS-DATA-WRITE/write-stream-empty-write-response",
  "FS-DATA-WRITE/final-artifact-regression",
  "FS-DATA-WRITE/closure-review",
  "FS-DATA-WRITE-LIST/list-documents-rest",
  "FS-DATA-WRITE-LIST/list-collection-ids-rest",
  "FS-DATA-WRITE-LIST/list-grpc",
  "FS-DATA-WRITE-LIST/setup-writes",
]);

const requiredRecipes = new Map([
  [
    "FS-WRITE-LIMITS-03/batch-undecodable-value",
    new Set([
      "writes/batch-write-malformed/undecodable-value",
      "writes/batch-write-malformed/bad-integer",
      "writes/batch-write-malformed/two-fields-bad-integer",
      "writes/batch-write-malformed/unknown-value-kind",
      "writes/batch-write-malformed/bad-timestamp",
    ]),
  ],
  [
    "FS-DATA-WRITE/map-value-key-validation",
    new Set([
      "writes/map-key-validation/reserved/write",
      "writes/map-key-validation/reserved/query",
      "writes/map-key-validation/empty/write",
      "writes/map-key-validation/empty/query",
      "writes/map-key-validation/overlong/write",
      "writes/map-key-validation/overlong/query",
      "writes/map-key-validation/type-tag/query",
    ]),
  ],
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
    "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-map",
    new Set(["writes/limits/aggregate-map", "writes/limits/aggregate-map/strict-only"]),
  ],
  [
    "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
    new Set([
      "writes/limits/decoded-request-bytes/under",
      "writes/limits/decoded-request-bytes/exact",
      "writes/limits/decoded-request-bytes/over",
      "writes/limits/decoded-11x1040000",
    ]),
  ],
  [
    "FS-LIMIT-API-REQUEST-BYTES/non-commit-rest",
    new Set(["writes/limits/non-commit-rest-request-bytes"]),
  ],
  ["FS-LIMIT-API-REQUEST-BYTES/webchannel", new Set(["writes/limits/webchannel-request-bytes"])],
  [
    "FS-LIMIT-API-REQUEST-BYTES/grpc",
    new Set(["writes/limits/grpc-unary-request-bytes", "writes/limits/grpc-stream-request-bytes"]),
  ],
  ["FS-DATA-WRITE/write-stream-half-close", new Set(["writes/write-stream-terminal/half-close"])],
  [
    "FS-DATA-WRITE/write-stream-empty-write-response",
    new Set(["writes/write-stream-terminal/response-before-half-close"]),
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
  if (!["VERIFIED", "DIVERGENCE_APPROVED"].includes(condition.status)) return;
  const observedListCap =
    condition.conditionId === "FS-DATA-WRITE-LIST/list-documents-rest" &&
    condition.boundaryStatus === "OBSERVED (page size 300)";
  const terminalBoundary = new Map([
    ["FS-DATA-WRITE/near-limit-delete-refusal", "NONDETERMINISTIC_BAND"],
  ]).get(condition.conditionId);
  const approvedTerminal = terminalBoundary === condition.boundaryStatus;
  assert.ok(
    observedListCap ||
      approvedTerminal ||
      ["BRACKETED", "RULE_TRANSITION", "NOT_APPLICABLE"].includes(condition.boundaryStatus),
    `${condition.conditionId}: unresolved boundary cannot be VERIFIED`,
  );
  if (approvedTerminal && terminalBoundary === "NONDETERMINISTIC_BAND") {
    assert.equal(condition.terminalOwnerDecision, "2026-09-25 FS-DATA-WRITE A");
  }
  if (condition.conditionId === "FS-DATA-WRITE/stream-transaction-precedence") {
    assert.equal(condition.boundaryStatus, "NOT_APPLICABLE");
    assert.match(condition.evidence?.productionReceiptSha256 ?? "", /^[0-9a-f]{64}$/);
    assert.match(condition.evidence?.savedProductionAuthorityDigest ?? "", /^[0-9a-f]{64}$/);
    assert.equal(condition.evidence?.productionRecordings, undefined);
  } else {
    assert.equal(condition.evidence?.productionRecordings?.length, 2);
  }
  assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/);
  assert.ok(condition.evidence?.comparisonPath);
  if (condition.status === "DIVERGENCE_APPROVED") {
    assert.equal(condition.boundaryStatus, "BRACKETED");
    assert.equal(condition.evidence.ownerDecision, "2026-09-25 FS-DATA-WRITE D3");
  }
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
  for (const boundaryStatus of ["NONDETERMINISTIC_BAND", "INFERRED_UPPER_BOUND"]) {
    assert.throws(() => verifyAcceptedCondition({ ...condition, boundaryStatus }), /boundary/);
  }
  for (const boundaryStatus of ["BRACKETED", "RULE_TRANSITION", "NOT_APPLICABLE"]) {
    assert.doesNotThrow(() => verifyAcceptedCondition({ ...condition, boundaryStatus }));
  }
});

test("integrated list conditions retain exact recipe ownership", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const expected = new Map([
    [
      "FS-DATA-WRITE-LIST/list-documents-rest",
      [127, "1733f727d1ee927c7979be913f961f155ef1bb27f02dbf9e887e8550ef8f8f07"],
    ],
    [
      "FS-DATA-WRITE-LIST/list-collection-ids-rest",
      [35, "209eacb4c61e14a8fe58f1575e9689cab030e8855b37a00d7255d7cfb84e889c"],
    ],
    [
      "FS-DATA-WRITE-LIST/list-grpc",
      [36, "ee99ec519d91cefe373559b1766b986832b858133ddd8f16361e2f9cb8670229"],
    ],
    [
      "FS-DATA-WRITE-LIST/setup-writes",
      [3, "923390681e5cfaad43aba4c31f5066c0d334164284d29a3ca60745a4905dfac8"],
    ],
  ]);
  const listConditions = closure.conditions.filter(({ conditionId }) =>
    conditionId.startsWith("FS-DATA-WRITE-LIST/"),
  );

  assert.equal(closure.conditions.length, 33);
  assert.equal(listConditions.length, expected.size);
  const recipeIds = [];
  for (const condition of listConditions) {
    const [count, digest] = expected.get(condition.conditionId) ?? [];
    assert.ok(count, `unexpected list condition ${condition.conditionId}`);
    assert.equal(condition.status, "VERIFIED");
    assert.equal(condition.recipeIds.length, count, condition.conditionId);
    assert.equal(
      createHash("sha256")
        .update([...condition.recipeIds].sort().join("\n"))
        .digest("hex"),
      digest,
      condition.conditionId,
    );
    assert.deepEqual(condition.evidence.productionRecordings, [
      "e6bcc4b467e48d8a285d1cb754ce37bc3decf56dd5e822ef7f1e77abb089ed33",
      "5ef3ad1593391e2948f980cfde0b39747406c56d14597cbe7950158aafac3637",
    ]);
    assert.equal(condition.evidence.fixturePath, "conformance/fs-data-write-list-production.json");
    assert.equal(
      condition.evidence.comparisonPath,
      "spec/compatibility/closure/evidence/FS-DATA-WRITE-LIST-comparison.json",
    );
    assert.equal(condition.evidence.sourceHead, "a2aec9fbc12c3bd6e35547c6239e46527fb55cd2");
    assert.equal(
      condition.evidence.finalArtifactSha256,
      "5c92dbc39f1b9bd5d78ff9cf37e3717e5295c64c7277d918d174bc340ab93aa3",
    );
    recipeIds.push(...condition.recipeIds);
  }
  assert.equal(recipeIds.length, 201);
  assert.equal(new Set(recipeIds).size, 201, "each proposed recipe must belong to one condition");
  assert.equal(closure.parentStatus, "WAITING_ORACLE");
  assert.equal(closure.closureReview.decision, "PENDING");
});

test("verified conditions are bound to their saved comparisons", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const digestProgram = (program) => ({
    steps: Object.fromEntries(
      Object.entries(program.steps).map(([stepId, step]) => {
        const body = JSON.stringify(step.body);
        return [
          stepId,
          {
            status: step.status,
            code: step.code,
            bodyBytes: Buffer.byteLength(body),
            bodySha256: createHash("sha256").update(body).digest("hex"),
          },
        ];
      }),
    ),
  });
  const verified = closure.conditions.filter(({ status }) => status === "VERIFIED");
  for (const conditionId of [
    "FS-LIMIT-SUBCOLLECTION-DEPTH",
    "FS-LIMIT-DOCUMENT-NAME-BYTES",
    "FS-WRITE-LIMITS-03/batch-duplicate-document",
    "FS-WRITE-LIMITS-03/batch-malformed-middle",
    "FS-LIMIT-FIELD-VALUE-BYTES/scalar-refusal",
    "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-string",
    "FS-WRITE-LIMITS-03/implied-map",
    "FS-WRITE-LIMITS-03/implied-array",
    "FS-LIMIT-API-REQUEST-BYTES/raw-16mib-over",
    "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
  ]) {
    assert.ok(verified.some((condition) => condition.conditionId === conditionId));
  }
  for (const condition of verified) {
    const comparisonPath = fileURLToPath(
      new URL(`../../${condition.evidence.comparisonPath}`, import.meta.url),
    );
    const comparison = JSON.parse(readFileSync(comparisonPath, "utf8"));
    if (comparisonPath === savedStreamReplayPath) {
      assert.equal(comparison.sourceCommit, condition.evidence.sourceHead);
      assert.equal(comparison.binarySha256, condition.evidence.finalArtifactSha256);
      assert.equal(comparison.productionReceiptSha256, condition.evidence.productionReceiptSha256);
      continue;
    }
    if (comparisonPath === acceptedConditionsPath) {
      assert.ok(comparison.conditions[condition.conditionId]);
      assert.equal(
        condition.evidence.comparisonSha256,
        createHash("sha256").update(readFileSync(comparisonPath)).digest("hex"),
      );
      assert.equal(condition.evidence.finalArtifactSha256, comparison.executableSha256);
      assert.equal(condition.evidence.sourceHead, comparison.sourceHead);
      continue;
    }
    if (comparisonPath === listComparisonPath) {
      assert.equal(
        condition.evidence.comparisonSha256,
        createHash("sha256").update(readFileSync(comparisonPath)).digest("hex"),
      );
      assert.equal(condition.evidence.finalArtifactSha256, comparison.artifactSha256);
      assert.equal(condition.evidence.sourceHead, "a2aec9fbc12c3bd6e35547c6239e46527fb55cd2");
      assert.deepEqual(
        new Set(
          comparison.rows
            .filter(({ row }) => condition.recipeIds.includes(row))
            .map(({ row }) => row),
        ),
        new Set(condition.recipeIds),
      );
      continue;
    }
    if (comparisonPath === terminalConditionPath) {
      assert.ok(comparison.conditions[condition.conditionId]);
      assert.equal(
        condition.evidence.comparisonSha256,
        createHash("sha256").update(readFileSync(comparisonPath)).digest("hex"),
      );
      assert.equal(condition.evidence.finalArtifactSha256, comparison.binarySha256);
      assert.equal(condition.evidence.sourceHead, comparison.sourceHead);
      continue;
    }
    assert.equal(comparison.conditionId, condition.conditionId);
    assert.deepEqual(new Set(comparison.recipeIds), new Set(condition.recipeIds));
    const streamComparison = comparison.comparisonMode === "sandbox-stream-comparator";
    assert.deepEqual(
      comparison.productionRecordingDigests,
      streamComparison
        ? fixture.evidence.streamRecordingDigests
        : fixture.evidence.recordingDigests,
    );
    assert.deepEqual(
      condition.evidence.productionRecordings,
      comparison.productionRecordingDigests,
    );
    assert.equal(
      condition.evidence.finalArtifactSha256,
      comparison.artifactSha256 ?? comparison.localExecutableSha256,
    );
    assert.equal(comparison.result.comparableRecipes, condition.recipeIds.length);
    assert.equal(comparison.result.mismatchedRecipes, 0);
    if (streamComparison) {
      assert.match(comparison.artifactSourceCommit, /^[0-9a-f]{40}$/);
      assert.ok(
        condition.evidence.comparisonPath.includes(comparison.artifactSourceCommit.slice(0, 9)),
      );
      assert.equal(
        comparison.localConfigSha256,
        createHash("sha256")
          .update(readFileSync(new URL("../fs-data-write-sandbox.fireemu.json", import.meta.url)))
          .digest("hex"),
      );
      assert.deepEqual(
        new Set(Object.keys(comparison.productionStreams)),
        new Set(condition.recipeIds),
      );
      assert.deepEqual(new Set(Object.keys(comparison.localStreams)), new Set(condition.recipeIds));
      for (const recipeId of condition.recipeIds) {
        assert.deepEqual(comparison.productionStreams[recipeId], fixture.streams[recipeId]);
        const recipe = corpus.streamRecipes.find(({ id }) => id === recipeId);
        assert.ok(recipe);
        const recipeDigest = createHash("sha256").update(JSON.stringify(recipe)).digest("hex");
        assert.equal(recipeDigest, manifest.streams[recipeId]);
        assert.equal(comparison.recipeSha256, recipeDigest);
      }
      assert.deepEqual(
        compareSandboxArtifact(
          { programs: {}, streams: comparison.productionStreams },
          {},
          comparison.localStreams,
          {
            restPrograms: [],
            streamRecipes: corpus.streamRecipes.filter(({ id }) =>
              condition.recipeIds.includes(id),
            ),
          },
        ),
        [],
      );
      continue;
    }
    assert.deepEqual(
      new Set(Object.keys(comparison.productionPrograms)),
      new Set(condition.recipeIds),
    );
    assert.deepEqual(new Set(Object.keys(comparison.localPrograms)), new Set(condition.recipeIds));
    for (const recipeId of condition.recipeIds) {
      const expected =
        comparison.comparisonMode === "digest-per-step"
          ? digestProgram(fixture.programs[recipeId])
          : fixture.programs[recipeId];
      assert.deepEqual(comparison.productionPrograms[recipeId], expected);
      if (
        comparison.comparisonMode !== "sandbox-comparator" &&
        !comparison.comparisonMode?.startsWith("existing-sandbox-comparator;")
      ) {
        assert.deepEqual(
          comparison.localPrograms[recipeId],
          comparison.productionPrograms[recipeId],
        );
      }
    }
    if (condition.conditionId === "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples") {
      const programs = condition.recipeIds.map((recipeId) =>
        corpus.restPrograms.find(({ id }) => id === recipeId),
      );
      assert.ok(programs.every(Boolean));
      assert.deepEqual(
        programs
          .slice(0, 3)
          .map((program) => Buffer.byteLength(JSON.stringify(program.steps[0].body))),
        comparison.measurement.firstThreeRawBytes,
      );
      assert.equal(Buffer.byteLength(JSON.stringify(programs[3].steps[0].body)), 11_441_443);
      for (const program of Object.values(comparison.localPrograms)) {
        assert.ok(
          Object.values(program.steps).every(({ status, code }) => status === 200 && code === "OK"),
        );
      }
    }
    if (comparison.comparisonMode === "sandbox-comparator") {
      assert.deepEqual(
        compareSandboxArtifact(
          { programs: comparison.productionPrograms, streams: {} },
          comparison.localPrograms,
          {},
          {
            restPrograms: corpus.restPrograms.filter(({ id }) => condition.recipeIds.includes(id)),
          },
        ),
        [],
      );
    }
    if (comparison.crossRecipeBoundary) {
      assert.equal(comparison.crossRecipeBoundary.classification, condition.boundaryStatus);
      assert.deepEqual(comparison.crossRecipeBoundary.evidence, condition.boundaryEvidence);
      const crossPath = fileURLToPath(
        new URL(`../../${comparison.crossRecipeBoundary.comparisonPath}`, import.meta.url),
      );
      const crossComparison = JSON.parse(readFileSync(crossPath, "utf8"));
      assert.ok(verified.some(({ conditionId }) => conditionId === crossComparison.conditionId));
      for (const reference of comparison.crossRecipeBoundary.evidence) {
        const [recipeId] = reference.split("#");
        assert.deepEqual(crossComparison.productionPrograms[recipeId], fixture.programs[recipeId]);
      }
    }
  }
});

test("10 MiB accepted samples and strict 11 MiB Commit probes keep separate recipe identities", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const accepted = closure.conditions.find(
    ({ conditionId }) =>
      conditionId === "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
  );
  const strict = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-LIMIT-API-REQUEST-BYTES/raw-16mib-over",
  );
  const acceptedIds = [
    "writes/limits/decoded-request-bytes/under",
    "writes/limits/decoded-request-bytes/exact",
    "writes/limits/decoded-request-bytes/over",
  ];
  const strictIds = ["writes/limits/raw-11mib/11534336", "writes/limits/raw-11mib/11534337"];
  assert.ok(accepted);
  assert.ok(strict);
  assert.deepEqual(accepted.recipeIds.slice(0, 3), acceptedIds);
  assert.ok(strictIds.every((recipeId) => strict.recipeIds.includes(recipeId)));
  assert.ok(acceptedIds.every((recipeId) => !strict.recipeIds.includes(recipeId)));

  for (const [index, recipeId] of acceptedIds.entries()) {
    const program = corpus.restPrograms.find(({ id }) => id === recipeId);
    assert.ok(program, recipeId);
    assert.equal(
      Buffer.byteLength(JSON.stringify(program.steps[0].body)),
      [10_485_759, 10_485_760, 10_485_761][index],
    );
    assert.equal(
      createHash("sha256").update(JSON.stringify(program)).digest("hex"),
      manifest.programs[recipeId],
    );
  }

  for (const [index, recipeId] of strictIds.entries()) {
    const program = corpus.restPrograms.find(({ id }) => id === recipeId);
    assert.ok(program, recipeId);
    assert.equal(Buffer.byteLength(program.steps[0].body), [11_534_336, 11_534_337][index]);
    assert.equal(
      createHash("sha256").update(JSON.stringify(program)).digest("hex"),
      manifest.programs[recipeId],
    );
  }
});

test("final artifact closure names both saved production regression commands", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/final-artifact-regression",
  );
  assert.deepEqual(condition.regressionCommands, [
    "pnpm -C conformance firestore:check-production",
    "pnpm -C conformance fs-data-write:check",
  ]);
  assert.notEqual(condition.status, "VERIFIED");
});

test("request-byte transports distinguish inferred bounds from the unresolved gRPC token mismatch", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const commit = closure.conditions.find(
    (row) => row.conditionId === "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
  );
  assert.match(commit.scopeNote, /D4/);
  assert.match(commit.scopeNote, /unobserved estimate/);
  const nonCommitRest = closure.conditions.find(
    (row) => row.conditionId === "FS-LIMIT-API-REQUEST-BYTES/non-commit-rest",
  );
  assert.equal(nonCommitRest.status, "PRODUCTION_RECORDED");
  assert.equal(nonCommitRest.boundaryStatus, "INFERRED_UPPER_BOUND");
  assert.throws(
    () => verifyAcceptedCondition({ ...nonCommitRest, status: "VERIFIED" }),
    /boundary/,
  );
  const grpc = closure.conditions.find(
    (row) => row.conditionId === "FS-LIMIT-API-REQUEST-BYTES/grpc",
  );
  assert.equal(grpc.status, "MISMATCH");
  assert.equal(grpc.boundaryStatus, "UNBRACKETED");
  const webchannel = closure.conditions.find(
    (row) => row.conditionId === "FS-LIMIT-API-REQUEST-BYTES/webchannel",
  );
  assert.equal(webchannel.status, "PRODUCTION_RECORDED");
  assert.equal(webchannel.boundaryStatus, "INFERRED_UPPER_BOUND");
  assert.throws(() => verifyAcceptedCondition({ ...webchannel, status: "VERIFIED" }), /boundary/);
  for (const condition of [nonCommitRest, webchannel, grpc]) {
    assert.equal(condition.strictLimitEstimateBytes, 11 * 1024 * 1024);
    assert.equal(condition.estimateOwnerDecision, "2026-09-25 FS-DATA-WRITE D4");
    assert.match(condition.scopeNote, /unobserved estimate/);
    assert.match(condition.scopeNote, /production upper boundary remains unresolved/);
  }
});

test("VERIFIED evidence never depends on a private path", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const verified = closure.conditions.filter(({ status }) => status === "VERIFIED");
  assert.equal(verified.length, 24);
  for (const condition of verified) {
    assert.ok(
      !JSON.stringify(condition.evidence ?? {}).includes("docs.local/"),
      condition.conditionId,
    );
  }
});

test("new strict-only map observation is recorded for closure review", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-map",
  );
  assert.ok(condition.recipeIds.includes("writes/limits/aggregate-map/strict-only"));
  assert.equal(condition.status, "PRODUCTION_RECORDED");
});

test("near-limit deletion names all six recorded route and size combinations", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/near-limit-delete-refusal",
  );
  const expected = ["rest", "commit", "batch-write"].flatMap((route) =>
    [12112, 12113].map((count) => `writes/limits/near-limit-delete-refusal/${route}/${count}`),
  );
  assert.deepEqual(new Set(condition.recipeIds), new Set(expected));
  assert.equal(condition.status, "VERIFIED");
  assert.equal(condition.boundaryStatus, "NONDETERMINISTIC_BAND");
  const delta = supplements.find(({ name }) => name.startsWith("delta-v3"));
  assert.deepEqual(new Set(Object.keys(delta.fixture.programs)), new Set(expected));
  assert.deepEqual(
    new Set(delta.fixture.evidence.nondeterministicPrograms),
    new Set([
      "writes/limits/near-limit-delete-refusal/rest/12112",
      "writes/limits/near-limit-delete-refusal/batch-write/12112",
    ]),
  );
});

test("changed field-path and indexed-value recipes are covered by the partial supplement", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const { base, supplemental } = currentRecordingSelection(fixture, manifest, corpus);
  for (const [conditionId, recipeId] of [
    ["FS-LIMIT-FIELD-PATH-BYTES", "writes/limits/field-path-mask/1500"],
    ["FS-LIMIT-INDEXED-FIELD-VALUE-BYTES", "writes/limits/indexed-field-value-bytes"],
  ]) {
    const condition = closure.conditions.find((row) => row.conditionId === conditionId);
    assert.ok(condition.recipeIds.includes(recipeId));
    assert.ok(base.pendingRestIds.includes(recipeId));
    assert.ok(!supplemental.pendingRestIds.includes(recipeId));
    assert.equal(
      condition.status,
      conditionId === "FS-LIMIT-FIELD-PATH-BYTES" ? "VERIFIED" : "PRODUCTION_RECORDED",
      conditionId,
    );
  }
});

test("the recorded empty-write response remains separate from half-close and trailing metadata", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const { base, supplemental } = currentRecordingSelection(fixture, manifest, corpus);
  const responseId = "writes/write-stream-terminal/response-before-half-close";
  const response = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-empty-write-response",
  );
  const halfClose = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-half-close",
  );
  assert.ok(base.pendingStreamIds.includes(responseId));
  assert.ok(!supplemental.pendingStreamIds.includes(responseId));
  assert.equal(response.status, "VERIFIED");
  assert.deepEqual(response.recipeIds, [responseId]);
  assert.equal(halfClose.status, "VERIFIED");
  assert.match(
    halfClose.comparisonNormalizationApproval,
    /2026-09-24.*addendum 4.*content-disposition is stable/,
  );
  assert.ok(!halfClose.recipeIds.includes(responseId));
});

test("half-close accepts the source-bound current run without rewriting historical evidence", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-half-close",
  );
  const comparisonPath = fileURLToPath(
    new URL(
      "../../spec/compatibility/broad-runs/fs-stream-half-close-1cb475837-current-comparison.json",
      import.meta.url,
    ),
  );
  const comparison = JSON.parse(readFileSync(comparisonPath, "utf8"));
  const historicalPath = fileURLToPath(
    new URL(`../../${condition.historicalComparison.comparisonPath}`, import.meta.url),
  );
  const historical = JSON.parse(readFileSync(historicalPath, "utf8"));

  assert.equal(condition.status, "VERIFIED");
  assert.deepEqual(condition.evidence.productionRecordings, [
    "ba880dc6feb56588256298deba48c9cbfd53de115e2f9381968867a28279d56f",
    "ba880dc6feb56588256298deba48c9cbfd53de115e2f9381968867a28279d56f",
  ]);
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  assert.deepEqual(comparison.productionRecordingDigests, fixture.evidence.streamRecordingDigests);
  assert.deepEqual(comparison.productionRecordingTimes, fixture.evidence.recordedAt);
  assert.equal(new Set(comparison.productionRecordingTimes).size, 2);
  assert.equal(
    comparison.productionFixturePath,
    "conformance/fs-data-write-production-matrix.json",
  );
  assert.equal(
    condition.evidence.comparisonPath,
    "spec/compatibility/broad-runs/fs-stream-half-close-1cb475837-current-comparison.json",
  );
  assert.deepEqual(condition.historicalComparison, {
    productionRecordings: historical.productionRecordingDigests,
    finalArtifactSha256: historical.artifactSha256,
    comparisonPath:
      "spec/compatibility/broad-runs/fs-stream-half-close-542b868b7-saved-comparison.json",
  });
  assert.deepEqual(comparison.sourceBinding, {
    sourceHead: "1cb4758372f21a467306a0a701994b7c1a02a8bb",
    executableSha256: "2af3f08c4d453459af86c9258f2283cb38fc7e74d83d388018cbdbb29e892a6a",
    executableSha256After: "2af3f08c4d453459af86c9258f2283cb38fc7e74d83d388018cbdbb29e892a6a",
    bindingFileSha256: "ea1c8bf15deb90fb70723e7a9a0ca3e1854779da79fb3473c6f8ab6451f7d37d",
    streamResultsSha256: "552b434a93f637be61d4d1ac5d8e22ecc682bad60958603bb29029b8e305fa80",
    corpusSha256: "407099fc6bb3137fdf2ca5294f0b8ef347e819bead6ab3085e804842bdb20450",
  });
  assert.deepEqual(comparison.result, {
    comparableRecipes: 1,
    mismatchedRecipes: 0,
    wholeRunComparableRestPrograms: 39,
    wholeRunComparableStreams: 2,
    wholeRunKnownMismatchRows: 9,
    wholeRunPendingRestPrograms: 39,
    wholeRunPendingStreams: 5,
  });
  assert.equal(
    comparison.localStreams[condition.recipeIds[0]].status.trailers[0].key,
    "content-disposition",
  );
  assert.deepEqual(comparison.differences, []);

  const trailingMetadata = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-trailing-metadata",
  );
  const emptyResponse = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-empty-write-response",
  );
  const finalRegression = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/final-artifact-regression",
  );
  assert.equal(trailingMetadata.status, "VERIFIED");
  assert.equal(emptyResponse.status, "VERIFIED");
  assert.equal(finalRegression.status, "PENDING_REVIEW");
  assert.equal(comparison.result.wholeRunKnownMismatchRows, 9);
  assert.equal(comparison.result.wholeRunPendingStreams, 5);
  assert.notEqual(historical.artifactSha256, comparison.artifactSha256);
});

test("batch malformed-middle is rebound to the current source-bound comparison", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-WRITE-LIMITS-03/batch-malformed-middle",
  );
  const comparisonPath = fileURLToPath(
    new URL(
      "../../spec/compatibility/broad-runs/fs-batch-malformed-middle-8a0f205-current-comparison.json",
      import.meta.url,
    ),
  );
  const comparison = JSON.parse(readFileSync(comparisonPath, "utf8"));

  assert.equal(condition.status, "VERIFIED");
  assert.equal(
    condition.evidence.comparisonPath,
    "spec/compatibility/broad-runs/fs-batch-malformed-middle-8a0f205-current-comparison.json",
  );
  assert.equal(condition.evidence.finalArtifactSha256, comparison.localExecutableSha256);
  assert.equal(condition.evidence.sourceCommit, comparison.sourceCommit);
  assert.equal(condition.evidence.sourceBindingSha256, comparison.localRunBindingSha256);
  assert.equal(
    condition.evidence.comparisonSha256,
    createHash("sha256").update(readFileSync(comparisonPath)).digest("hex"),
  );
  assert.deepEqual(condition.historicalEvidence, {
    productionRecordings: [
      "7c794af67119e745072ceae3d742bd463df28c0aa804998c2155b1333b1625d9",
      "7c794af67119e745072ceae3d742bd463df28c0aa804998c2155b1333b1625d9",
    ],
    finalArtifactSha256: "d6db62596e71c152883dc5b83bf8dc48b79b703777d49bab10874c1fae6dfc6d",
    comparisonPath:
      "spec/compatibility/broad-runs/fs-batch-malformed-middle-3d7ceabb8-saved-comparison.json",
  });
  assert.equal(comparison.result.comparableRecipes, condition.recipeIds.length);
  assert.equal(comparison.result.mismatchedRecipes, 0);
  assert.equal(comparison.closurePromotion, "none");
});

test("recorded conditions contain no changed or unrecorded runnable recipes", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const { supplemental } = currentRecordingSelection(fixture, manifest, corpus);
  const pending = new Set([...supplemental.pendingRestIds, ...supplemental.pendingStreamIds]);
  const failures = closure.conditions
    .filter(({ status }) =>
      ["PRODUCTION_RECORDED", "VERIFIED", "DIVERGENCE_APPROVED"].includes(status),
    )
    .flatMap(({ conditionId, recipeIds }) =>
      recipeIds
        .filter((recipeId) => pending.has(recipeId))
        .map((recipeId) => `${conditionId}: ${recipeId}`),
    );
  assert.deepEqual(failures, []);
});

test("FS-DATA-WRITE closure inventory cannot silently omit a declared condition", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const allPrograms = Object.assign(
    {},
    fixture.programs,
    ...supplements.map(({ fixture: additional }) => additional.programs),
  );
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
        "NONDETERMINISTIC_BAND",
        "INFERRED_UPPER_BOUND",
        "NOT_APPLICABLE",
        "PENDING_RECORDING",
        "OBSERVED (page size 300)",
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
        const step = allPrograms[programId]?.steps[stepId];
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
    if (condition.recipeIds.some((recipe) => allPrograms[recipe])) {
      assert.notEqual(condition.status, "PENDING_CORPUS", condition.conditionId);
    }
    assert.ok(
      [
        "PENDING_CORPUS",
        "PENDING_RECORDING",
        "SAVED_REFERENCE_PENDING_FINAL",
        "PRODUCTION_RECORDED",
        "MISMATCH",
        "VERIFIED",
        "DIVERGENCE_APPROVED",
        "PENDING_REVIEW",
        "PENDING_INTEGRATION",
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
  const approvedD3Conditions = new Set([
    "FS-LIMIT-INDEX-ENTRY-BYTES",
    "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
  ]);
  const allVerified = closure.conditions.every(
    ({ conditionId, status }) =>
      status === "VERIFIED" ||
      (approvedD3Conditions.has(conditionId) && status === "DIVERGENCE_APPROVED"),
  );
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    allVerified && closure.closureReview?.decision === "APPROVED",
    "parent promotion requires every condition and independent closure review",
  );
});
