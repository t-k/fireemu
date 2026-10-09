import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { readReleaseJson } from "./release-strict-regression.mjs";
import { validateEventarcSemantics } from "./eventarc-production/run.mjs";

const root = new URL("../../", import.meta.url);
const readRepo = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const sha256 = (path) =>
  createHash("sha256")
    .update(readFileSync(new URL(path, root)))
    .digest("hex");
const hash = /^[a-f0-9]{64}$/;
const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
  "OUT_OF_SCOPE_OBSERVED",
]);

const required = {
  PUBSUB: {
    "topic-lifecycle": [
      "create-get-list-delete",
      "duplicate-create",
      "delete-topic-with-subscription",
    ],
    "resource-names": ["valid-name", "invalid-name", "path-body-mismatch"],
    "list-pagination": ["page-traversal", "invalid-page-token"],
    "subscription-lifecycle": ["default-ack-deadline", "explicit-ack-deadline", "missing-topic"],
    "subscription-configuration": [
      "message-retention-duration",
      "retain-acked-messages",
      "atomic-field-mask-update",
    ],
    "push-configuration": [
      "create-push-config",
      "get-push-config",
      "modify-push-config",
      "invalid-push-config",
    ],
    "publish-wire": [
      "binary-data",
      "attributes-only",
      "ordering-key",
      "publish-pull-id-correlation",
    ],
    "publish-limits": ["request-bytes-boundary", "batch-count-boundary", "attribute-size-boundary"],
    "pull-ack": ["publish-pull-ack", "unknown-ack-id", "stale-ack-id"],
    "nack-deadline-redelivery": [
      "nack-zero",
      "deadline-extension",
      "deadline-expiry",
      "redelivery-id-correlation",
    ],
    "filter-evaluation": ["match", "nonmatch", "missing-attribute", "invalid-filter"],
    ordering: ["single-key-sequence", "nack-blocks-key", "ack-unblocks-key"],
    "retry-dead-letter": [
      "policy-round-trip",
      "delivery-attempt-without-policy",
      "eventual-forwarding",
    ],
    "streaming-pull": [
      "opening-frame",
      "in-stream-ack",
      "in-stream-nack",
      "flow-control",
      "client-cancel",
      "half-close",
    ],
    "snapshot-seek": [
      "snapshot-lifecycle",
      "post-snapshot-publication",
      "seek-time-retain-true",
      "seek-time-retain-false",
    ],
    "errors-authentication": ["missing-resource", "invalid-argument", "no-token", "invalid-token"],
    "final-artifact-regression": ["strict-production", "emulator-official", "complete-case-set"],
    "closure-review": ["independent-approval"],
  },
  EVENTARC: {
    "channel-lifecycle": ["providerless-create-capability", "get-channel", "delete-owned-channel"],
    "publish-envelope": [
      "single-event",
      "multiple-events",
      "required-attributes",
      "invalid-timestamp",
    ],
    "publish-content": [
      "json-object",
      "json-null",
      "text",
      "binary-data",
      "invalid-json",
      "oneof-collision",
    ],
    "admin-sdk-publish": [
      "full-channel",
      "relative-channel",
      "default-channel",
      "generated-metadata",
      "allowed-event-types",
    ],
    "publish-limits": ["request-bytes-boundary", "event-count-boundary", "event-bytes-boundary"],
    "custom-handler-envelope": [
      "required-attributes",
      "optional-attribute-absence",
      "extension-attributes",
      "binary-data",
    ],
    "trigger-filters": [
      "type",
      "source",
      "extension-attribute",
      "nonmatch",
      "channel-isolation",
      "unsupported-filter-refusal",
    ],
    "delivery-retry-identity": ["fail-then-succeed", "stable-id-and-data"],
    "errors-authentication": ["missing-channel", "invalid-event", "no-token", "invalid-token"],
    "final-artifact-regression": ["strict-production", "emulator-official", "complete-case-set"],
    "closure-review": ["independent-approval"],
  },
};

function assertRecordings(condition, parent) {
  const runs = condition.evidence?.productionRecordings;
  assert.equal(runs?.length, 2, `${condition.conditionId}: two production recordings`);
  assert.deepEqual(
    runs.map(({ pass }) => pass),
    [1, 2],
  );
  for (const run of runs) {
    assert.equal(run.project, "fireemu-oracle-idp");
    assert.match(run.corpusDigest, hash);
    assert.match(run.recordingSha256, hash);
    assert.ok(Number.isFinite(Date.parse(run.recordedAt)), "recording time");
    assert.equal(sha256(run.recordingPath), run.recordingSha256);
    const recording = readRepo(run.recordingPath);
    assert.equal(recording.parent, parent);
    assert.equal(recording.corpusDigest, run.corpusDigest);
    assert.equal(recording.pass, run.pass);
  }
  assert.equal(runs[0].corpusDigest, runs[1].corpusDigest);
  return runs;
}

function assertClosure(closure) {
  const { parent } = closure;
  const retrospective =
    parent === "EVENTARC" &&
    closure.retrospectiveAdjudication?.mode === "reviewed-retrospective-composition";
  if (retrospective && closure.parentStatus === "COMPAT_VERIFIED")
    assert.ok(
      closure.conditions.every(({ status }) => status === "VERIFIED"),
      "all required conditions must be verified",
    );
  assert.ok(Object.hasOwn(required, parent));
  assert.equal(closure.schemaVersion, 1);
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(closure.frozenOn, "2026-09-30");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.equal(closure.oracle.project, "fireemu-oracle-idp");
  assert.equal(closure.oracle.region, "us-central1");
  assert.ok(["IMPLEMENTING", "COMPAT_VERIFIED"].includes(closure.parentStatus));
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(new Set(ids).size, ids.length, "duplicate condition");
  assert.deepEqual(
    new Set(ids),
    new Set(Object.keys(required[parent]).map((id) => `${parent}/${id}`)),
  );
  const scopeIds =
    parent === "PUBSUB" ? ["P1", "P2", "P3", "P4", "P5", "P6"] : ["E1", "E2", "E3", "E4"];
  assert.deepEqual(
    closure.scopeDecisions.map(({ id }) => id),
    scopeIds,
  );
  for (const decision of closure.scopeDecisions) {
    assert.equal(decision.status, "FROZEN");
    assert.ok(decision.decision && decision.rationale && decision.decidedBy);
    assert.equal(decision.decidedOn, "2026-09-30");
    assert.match(decision.decisionRef, /PUBSUB and EVENTARC scope: coordinator rulings/);
  }
  if (parent === "PUBSUB") {
    assert.match(
      closure.scopeDecisions.find(({ id }) => id === "P4").decision,
      /configuration API/,
    );
    assert.match(closure.scopeDecisions.find(({ id }) => id === "P4").decision, /never publish/i);
    assert.match(
      closure.scopeDecisions.find(({ id }) => id === "P5").decision,
      /IAM permission refusal.*outside/i,
    );
  } else {
    assert.match(closure.scopeDecisions.find(({ id }) => id === "E1").decision, /provider-less/);
    assert.match(closure.scopeDecisions.find(({ id }) => id === "E1").decision, /record.*outside/i);
  }

  for (const condition of closure.conditions) {
    const suffix = condition.conditionId.slice(parent.length + 1);
    assert.ok(statuses.has(condition.status), condition.conditionId);
    assert.ok(condition.source);
    assert.equal(condition.recipeIds.length, 1);
    assert.ok(condition.recipeIds[0].startsWith(`${parent.toLowerCase()}/`));
    assert.equal(new Set(condition.cases).size, condition.cases.length, "duplicate case");
    for (const name of required[parent][suffix])
      assert.ok(condition.cases.includes(name), `${suffix}: ${name}`);
    const local = ["final-artifact-regression", "closure-review"].includes(suffix);
    const expectedTransports = local
      ? ["artifact"]
      : parent === "PUBSUB" && suffix !== "streaming-pull"
        ? ["rest", "grpc"]
        : parent === "PUBSUB"
          ? ["grpc"]
          : ["rest"];
    assert.deepEqual(condition.transports, expectedTransports, condition.conditionId);
    if (retrospective) continue;
    if (condition.status === "OUT_OF_SCOPE_OBSERVED") {
      assert.equal(
        condition.conditionId,
        "EVENTARC/channel-lifecycle",
        "only the approved conditional lifecycle exclusion",
      );
      const runs = assertRecordings(condition, parent);
      assert.ok(runs.every(({ operationSupported }) => operationSupported === false));
      assert.equal(condition.evidence.scopeReview.decision, "APPROVED");
      assert.ok(condition.evidence.scopeReview.decisionRef);
      continue;
    }
    if (condition.status !== "VERIFIED") {
      if (condition.status === "PENDING_CORPUS")
        assert.ok(!condition.evidence, "pending corpus must not claim evidence");
      if (condition.status === "PRODUCTION_RECORDED") assertRecordings(condition, parent);
      continue;
    }
    assertRecordings(condition, parent);
    const { evidence } = condition;
    assert.match(evidence.finalArtifactSha256, hash);
    assert.match(evidence.comparisonSha256, hash);
    assert.equal(sha256(evidence.comparisonPath), evidence.comparisonSha256);
    const comparison = readRepo(evidence.comparisonPath);
    assert.equal(comparison.parent, parent);
    assert.equal(comparison.artifactSha256, evidence.finalArtifactSha256);
    for (const name of condition.cases) {
      for (const transport of condition.transports) {
        const matches = comparison.rows.filter(
          ({ row, transport: actual }) =>
            row === `${condition.recipeIds[0]}#${name}` && actual === transport,
        );
        assert.equal(
          matches.length,
          1,
          `${condition.conditionId}: ${name}/${transport} must appear exactly once`,
        );
        assert.equal(matches[0].status, "MATCH");
      }
    }
    if (suffix === "closure-review") {
      assert.equal(closure.closureReview.decision, "APPROVED");
      assert.equal(closure.closureReview.finalArtifactSha256, evidence.finalArtifactSha256);
      assert.equal(closure.closureReview.comparisonSha256, evidence.comparisonSha256);
    }
  }
  if (retrospective) {
    const binding = closure.retrospectiveAdjudication;
    assert.equal(binding.path, adjudicationPath);
    assert.equal(sha256(binding.path), binding.sha256, "public adjudication bytes");
    assertRetrospectiveClosure(closure, readRepo(binding.path));
    return;
  }
  if (closure.parentStatus === "COMPAT_VERIFIED") {
    assert.ok(
      closure.conditions.every(({ status }) =>
        ["VERIFIED", "OUT_OF_SCOPE_OBSERVED"].includes(status),
      ),
      "all required conditions must be verified",
    );
    assert.equal(closure.closureReview.decision, "APPROVED");
    const artifacts = closure.conditions
      .filter(({ status }) => status === "VERIFIED")
      .map(({ evidence }) => evidence.finalArtifactSha256);
    assert.equal(new Set(artifacts).size, 1, "same final artifact for every condition");
  }
}

for (const parent of Object.keys(required)) {
  const path = `spec/compatibility/closure/${parent}.json`;
  test(`${parent} has its approved frozen closure inventory`, () => {
    assert.ok(existsSync(new URL(path, root)), `${parent} closure inventory is missing`);
    assertClosure(readRepo(path));
  });
  test(`${parent} cannot promote incomplete evidence`, () => {
    assert.ok(existsSync(new URL(path, root)), `${parent} closure inventory is missing`);
    const closure = readRepo(path);
    closure.parentStatus = "COMPAT_VERIFIED";
    closure.conditions[0].status = "PENDING_CORPUS";
    delete closure.conditions[0].evidence;
    assert.throws(() => assertClosure(closure), /all required conditions/);
  });
}

const technicalReviewSha = "aa4b7a854ece0acfa8470ec319f4a5006c15dd9041c2b4d5c2b00439b3fcc224";
const originalProofSha = "a82eded4a149e795d62b8a78fbc400de7e8f4e11de9e7e897ebb1ae29ba04678";
const adjudicationPath = "spec/compatibility/closure/evidence/EVENTARC-adjudication.json";
const acquisitionPath = "spec/compatibility/closure/evidence/EVENTARC-comparison.json.gz";
const acquisitionSha = "5dda2ef8de3aeeed554a54d63cb1bed50fedee538369e5f2408b7c9230d18ae1";
const decodedAcquisitionSha = "76c47b99496a616e8c2faab841e8267901f985e95221b43cd38dbf82d973f907";
const sortedValue = (value) =>
  Array.isArray(value)
    ? value.map(sortedValue)
    : value && typeof value === "object"
      ? Object.fromEntries(
          Object.keys(value)
            .toSorted()
            .map((key) => [key, sortedValue(value[key])]),
        )
      : value;
const bindingSha = (value) =>
  createHash("sha256")
    .update(JSON.stringify(sortedValue(value)))
    .digest("hex");
let acquisitionCache;
let acquisitionCacheValidated = false;
function acquisitionComparison() {
  acquisitionCache ??= readReleaseJson(fileURLToPath(root), acquisitionPath);
  if (!acquisitionCacheValidated) {
    validateEventarcSemantics(acquisitionCache);
    acquisitionCacheValidated = true;
  }
  return acquisitionCache;
}

function assertRetrospectiveClosure(
  closure,
  adjudication,
  comparison = acquisitionComparison(),
  publicSha = sha256,
) {
  assert.equal(closure.parent, "EVENTARC");
  assert.equal(adjudication.schemaVersion, 1);
  assert.equal(adjudication.parent, "EVENTARC");
  assert.equal(adjudication.mode, "reviewed-retrospective-composition");
  assert.equal(adjudication.originalCaseProof.sha256, originalProofSha);
  assert.equal(adjudication.originalCaseProof.custody, "private-review-attested");
  const review = adjudication.technicalReview;
  assert.equal(review.sha256, technicalReviewSha, "original independent review pin");
  assert.equal(review.decision, "ACCEPT_SCOPED_CANDIDATE");
  assert.equal(review.privatePrimaryInspected, true);
  assert.equal(review.ciInspectsPrivatePrimary, false, "CI does not inspect private custody");
  assert.equal(review.custody, "private-review-attested");
  const acquisition = adjudication.acquisitionComparison;
  assert.equal(acquisition.path, acquisitionPath);
  assert.equal(acquisition.sha256, acquisitionSha);
  assert.equal(publicSha(acquisition.path), acquisition.sha256, "public acquisition bytes");
  assert.equal(acquisition.decodedSha256, decodedAcquisitionSha);
  assert.equal(acquisition.decodedBytes, 141778655);
  assert.equal(acquisition.selector, "/rows", "public acquisition selector");
  assert.equal(acquisition.custody, "public-repository");
  assert.equal(acquisition.generatedStatus, "PENDING");
  assert.equal(comparison.parent, "EVENTARC");
  assert.equal(comparison.rows.length, 70);
  assert.ok(
    comparison.rows.every(({ status }) => status === "PENDING"),
    "original generated rows remain PENDING",
  );
  assert.equal(comparison.artifactSha256, acquisition.artifactSha256);
  assert.equal(
    new Set(comparison.rows.map(({ row, transport }) => `${row}/${transport}`)).size,
    70,
  );
  const expected = closure.conditions.flatMap((condition) =>
    condition.cases.flatMap((name) =>
      condition.transports.map((transport) => ({
        id: `${condition.conditionId}/${name}`,
        row: `${condition.recipeIds[0]}#${name}`,
        transport,
      })),
    ),
  );
  assert.equal(expected.length, 70, "original coordinate count");
  assert.deepEqual(
    new Set(expected.map(({ row, transport }) => `${row}/${transport}`)),
    new Set(comparison.rows.map(({ row, transport }) => `${row}/${transport}`)),
    "original coordinate set",
  );
  assert.equal(adjudication.cases.length, 70, "adjudicated coordinate count");
  assert.deepEqual(
    adjudication.cases.map(({ id, transport }) => ({ id, transport })),
    expected.map(({ id, transport }) => ({ id, transport })),
    "exact original coordinates",
  );
  for (const condition of closure.conditions) {
    assert.equal(
      condition.evidence?.originalCaseProofSha256,
      originalProofSha,
      "condition original proof pin",
    );
    assert.deepEqual(
      condition.evidence.originalCaseProofSelectors,
      adjudication.cases
        .filter(({ id }) => id.startsWith(`${condition.conditionId}/`))
        .map(({ originalProofSelector }) => originalProofSelector),
      "condition original selectors",
    );
  }
  const publicSources = [
    "run.mjs",
    "compare.mjs",
    "lifecycle-evidence.mjs",
    "sdk.mjs",
    "probe-sdk.mjs",
  ].map((name) => `conformance/src/eventarc-production/${name}`);
  assert.deepEqual(
    adjudication.sources.map(({ path }) => path),
    publicSources,
  );
  for (const source of adjudication.sources) {
    assert.equal(source.custody, "public-repository");
    assert.equal(source.selector, "whole-file");
    assert.equal(publicSha(source.path), source.sha256, "public source bytes");
  }
  for (const [index, entry] of adjudication.cases.entries()) {
    assert.equal(entry.originalProofSelector, `/cases/${index}`, "original proof selector");
    const { reviewedBindingSha256, ...reviewed } = entry;
    assert.equal(bindingSha(reviewed), reviewedBindingSha256, "reviewed primary binding");
    for (const key of ["nativePrimary", "currentPrimary", "independentReviews"]) {
      assert.ok(Array.isArray(entry[key]));
      if (entry.decision === "ACCEPT_SCOPED_CANDIDATE")
        assert.ok(entry[key].length > 0, "accepted primary/review linkage");
      for (const reference of entry[key]) {
        assert.equal(reference.custody, "private-review-attested");
        assert.equal(reference.inspectionReviewSha256, technicalReviewSha);
        assert.match(reference.sha256, hash);
        assert.ok(
          reference.path && !reference.path.startsWith("/") && reference.selector,
          "private primary locator/hash/selector",
        );
      }
    }
    if (entry.transport === "rest") {
      assert.ok(
        Number.isSafeInteger(entry.selectedNativeWitnessCount) &&
          entry.selectedNativeWitnessCount >= 1,
        "at least one genuine native witness",
      );
      assert.ok(entry.nativeRecordingPaths.length >= 1);
    }
  }
  assert.deepEqual(adjudication.originalProjects, ["fireemu-oracle-idp", "fireemu-oracle-events"]);
  assert.equal(
    adjudication.nativeProjectQualification.BAndCAndNativeSupplement,
    "fireemu-oracle-idp",
  );
  assert.equal(adjudication.nativeProjectQualification.HAndW, "fireemu-oracle-events");
  assert.equal(adjudication.nativeProjectQualification.retrospectiveComposition, true);
  assert.match(adjudication.nativeProjectQualification.numericProjectProjection, /same-width/);
  assert.match(adjudication.retrospectiveSource.sourceHead, /^[a-f0-9]{40}$/);
  assert.equal(
    adjudication.retrospectiveSource.binaryInputsSha256,
    "bcc4628b1e53b158edebd232bca3febd7f92b279f0a24d2c22772dadf2170631",
  );
  assert.equal(adjudication.retrospectiveSource.binarySha256, acquisition.artifactSha256);
  assert.ok(
    adjudication.compositionQualification.includes("retrospective") &&
      adjudication.compositionQualification.includes("projection"),
  );
  const limits = adjudication.limitations;
  assert.deepEqual(
    limits.historicalPublish404.cases,
    ["C182", "C183", "C307"],
    "exact owner1181 exception set",
  );
  assert.equal(limits.historicalPublish404.native404Local200Unresolved, true);
  assert.match(
    limits.historicalPublish404.scope,
    /Normal single\/three-event REST publication and genuine SDK relative-name parity/,
  );
  assert.equal(limits.mockCredentialCatalog.googleTokenValidityVerified, false);
  assert.equal(limits.mockCredentialCatalog.defaultConfigurationGapDisclosed, true);
  for (const key of [
    "lifecycleDisposition",
    "compositionDisposition",
    "physicalParity",
    "sdkSupervision",
  ])
    assert.ok(limits[key], `retained ${key}`);
  assert.deepEqual(adjudication.currentSdk, {
    firebaseAdminVersion: "14.3.0",
    calls: 13,
    forwardedRequests: 6,
    workFulfilled: 21,
    closed: true,
    unsettled: false,
    zeroWireValidationCasesRetained: true,
  });
  assert.match(adjudication.finalArtifact.releaseBinarySha256, hash);
  assert.match(adjudication.finalArtifact.sourceCommit, /^[a-f0-9]{40}$/);
  const accepted = adjudication.cases.filter(
    ({ decision }) => decision === "ACCEPT_SCOPED_CANDIDATE",
  );
  const deferred = adjudication.cases.filter(
    ({ decision }) => decision === "DEFERRED_FINAL_CANONICAL_REVIEW",
  );
  if (closure.parentStatus === "IMPLEMENTING") {
    assert.equal(accepted.length, 69);
    assert.equal(deferred.length, 1);
    assert.equal(deferred[0].id, "EVENTARC/closure-review/independent-approval");
    assert.equal(review.acceptedPredicates, 69);
    assert.equal(review.deferredPredicates, 1);
    assert.equal(adjudication.parentClosureApproved, false);
    assert.equal(closure.closureReview.decision, "PENDING");
    assert.equal(adjudication.finalArtifact.finalR20, "PENDING");
    assert.equal(adjudication.finalArtifact.independentApproval, "PENDING");
  } else {
    assert.ok(
      closure.conditions.every(({ status }) => status === "VERIFIED"),
      "all required conditions must be verified",
    );
    assert.equal(adjudication.parentClosureApproved, true, "final independent approval required");
    assert.equal(deferred.length, 0, "no deferred original predicate");
    assert.equal(accepted.length, 69);
    assert.equal(
      adjudication.cases.filter(({ decision }) => decision === "APPROVED_FINAL_CANONICAL_REVIEW")
        .length,
      1,
    );
    assert.equal(adjudication.finalArtifact.finalR20, "PASSED", "settled final R20 required");
    assert.equal(adjudication.finalArtifact.independentApproval, "APPROVED");
    assert.equal(closure.closureReview.decision, "APPROVED");
    assert.equal(
      closure.closureReview.finalArtifactSha256,
      adjudication.finalArtifact.releaseBinarySha256,
    );
    for (const key of ["finalR20Evidence", "independentApprovalEvidence"]) {
      const evidence = adjudication.finalArtifact[key];
      assert.equal(evidence?.custody, "private-review-attested", "genuine final evidence required");
      assert.match(evidence.sha256, hash);
      assert.ok(evidence.path && evidence.selector);
      assert.equal(evidence.artifactSha256, adjudication.finalArtifact.releaseBinarySha256);
      assert.equal(evidence.sourceCommit, adjudication.finalArtifact.sourceCommit);
    }
    const approval = adjudication.finalArtifact.independentApprovalEvidence;
    assert.notEqual(approval.sha256, technicalReviewSha, "candidate review is not final approval");
    assert.ok(
      closure.closureReview.reviews.some(
        ({ reportPath, reportSha256 }) =>
          reportPath === approval.path && reportSha256 === approval.sha256,
      ),
      "final review linkage",
    );
  }
}

const eventarcFixture = () => ({
  closure: readRepo("spec/compatibility/closure/EVENTARC.json"),
  adjudication: readRepo(adjudicationPath),
});
const smallAcquisition = (adjudication) => ({
  parent: "EVENTARC",
  artifactSha256: adjudication.acquisitionComparison.artifactSha256,
  rows: adjudication.cases.map(({ id, transport }) => {
    const slash = id.lastIndexOf("/");
    const recipe = readRepo("spec/compatibility/closure/EVENTARC.json").conditions.find(
      ({ conditionId }) => conditionId === id.slice(0, slash),
    ).recipeIds[0];
    return { row: `${recipe}#${id.slice(slash + 1)}`, transport, status: "PENDING" };
  }),
});
function updateCaseBinding(entry) {
  const { reviewedBindingSha256: _reviewedBindingSha256, ...reviewed } = entry;
  entry.reviewedBindingSha256 = bindingSha(reviewed);
}
test("EVENTARC retrospective composition uses genuine public comparison and private inspected custody", () => {
  const { closure, adjudication } = eventarcFixture();
  assertRetrospectiveClosure(closure, adjudication);
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(
    adjudication.cases.filter(({ decision }) => decision === "DEFERRED_FINAL_CANONICAL_REVIEW")
      .length,
    1,
  );
});
const retrospectiveCounters = [
  ["lost coordinate", (a) => a.cases.pop(), /coordinate count/],
  [
    "duplicate coordinate",
    (a) => (a.cases[1] = structuredClone(a.cases[0])),
    /exact original coordinates/,
  ],
  [
    "wrong original selector",
    (a) => (a.cases[0].originalProofSelector = "/cases/1"),
    /original.*selector/,
  ],
  [
    "wrong private primary selector",
    (a) => (a.cases[0].nativePrimary[0].selector += ":foreign"),
    /reviewed primary binding/,
  ],
  [
    "wrong private primary hash",
    (a) => (a.cases[0].nativePrimary[0].sha256 = "0".repeat(64)),
    /reviewed primary binding/,
  ],
  [
    "missing native witness",
    (a) => {
      a.cases[0].selectedNativeWitnessCount = 0;
      updateCaseBinding(a.cases[0]);
    },
    /genuine native witness/,
  ],
  [
    "missing native primary",
    (a) => {
      a.cases[0].nativePrimary = [];
      updateCaseBinding(a.cases[0]);
    },
    /accepted primary/,
  ],
  [
    "missing independent review",
    (a) => {
      a.cases[0].independentReviews = [];
      updateCaseBinding(a.cases[0]);
    },
    /accepted primary/,
  ],
  [
    "private custody presented as CI inspection",
    (a) => (a.technicalReview.ciInspectsPrivatePrimary = true),
    /CI does not inspect/,
  ],
  [
    "wrong independent review pin",
    (a) => (a.technicalReview.sha256 = "0".repeat(64)),
    /independent review pin/,
  ],
  [
    "wrong public selector",
    (a) => (a.acquisitionComparison.selector = "/rows/70"),
    /public acquisition selector/,
  ],
  ["wrong public source pin", (a) => (a.sources[0].sha256 = "0".repeat(64)), /public source bytes/],
  [
    "widened historical exception",
    (a) => a.limitations.historicalPublish404.cases.push("C124"),
    /exception set/,
  ],
  [
    "missing unresolved difference",
    (a) => (a.limitations.historicalPublish404.native404Local200Unresolved = false),
    /strictly equal/,
  ],
  [
    "missing normal publication and SDK disclosure",
    (a) => (a.limitations.historicalPublish404.scope = "Only historical publication"),
    /Normal single/,
  ],
  [
    "missing default credential gap",
    (a) => (a.limitations.mockCredentialCatalog.defaultConfigurationGapDisclosed = false),
    /strictly equal/,
  ],
  [
    "missing lifecycle qualification",
    (a) => delete a.limitations.lifecycleDisposition,
    /retained lifecycle/,
  ],
  ["unsettled SDK work", (a) => (a.currentSdk.unsettled = true), /deep-equal/],
  [
    "unreviewed technical decision",
    (a) => {
      a.cases[0].decision = "NOT_COMPARABLE";
      updateCaseBinding(a.cases[0]);
    },
    /68.*69/,
  ],
];
for (const [name, mutate, message] of retrospectiveCounters) {
  test(`EVENTARC retrospective rejects ${name}`, () => {
    const { closure, adjudication } = eventarcFixture();
    const comparison = smallAcquisition(adjudication);
    mutate(adjudication);
    assert.throws(() => assertRetrospectiveClosure(closure, adjudication, comparison), message);
  });
}
test("EVENTARC retrospective rejects missing public bytes", () => {
  const { closure, adjudication } = eventarcFixture();
  assert.throws(
    () =>
      assertRetrospectiveClosure(closure, adjudication, smallAcquisition(adjudication), (path) => {
        if (path === acquisitionPath) throw new Error("missing public acquisition");
        return sha256(path);
      }),
    /missing public acquisition/,
  );
});
test("EVENTARC retrospective cannot turn generated PENDING into MATCH", () => {
  const { closure, adjudication } = eventarcFixture();
  const comparison = smallAcquisition(adjudication);
  comparison.rows[0].status = "MATCH";
  assert.throws(
    () => assertRetrospectiveClosure(closure, adjudication, comparison),
    /remain PENDING/,
  );
});
test("EVENTARC retrospective cannot promote without final approval and settled R20", () => {
  const { closure, adjudication } = eventarcFixture();
  closure.parentStatus = "COMPAT_VERIFIED";
  closure.conditions.forEach((condition) => (condition.status = "VERIFIED"));
  assert.throws(
    () => assertRetrospectiveClosure(closure, adjudication, smallAcquisition(adjudication)),
    /final independent approval/,
  );
  adjudication.parentClosureApproved = true;
  adjudication.cases.at(-1).decision = "APPROVED_FINAL_CANONICAL_REVIEW";
  updateCaseBinding(adjudication.cases.at(-1));
  assert.throws(
    () => assertRetrospectiveClosure(closure, adjudication, smallAcquisition(adjudication)),
    /settled final R20/,
  );
});
test("PUBSUB retains its two-recording contract", () => {
  assert.throws(
    () =>
      assertRecordings(
        { conditionId: "PUBSUB/topic-lifecycle", evidence: { productionRecordings: [{}] } },
        "PUBSUB",
      ),
    /two production recordings/,
  );
});

test("EVENTARC retrospective rejects a wrong condition proof pin", () => {
  const { closure, adjudication } = eventarcFixture();
  closure.conditions[0].evidence.originalCaseProofSha256 = "0".repeat(64);
  assert.throws(
    () => assertRetrospectiveClosure(closure, adjudication, smallAcquisition(adjudication)),
    /condition original proof pin/,
  );
});
test("EVENTARC retrospective retains original project and source qualifications", () => {
  const { closure, adjudication } = eventarcFixture();
  adjudication.nativeProjectQualification.HAndW = "fireemu-oracle-idp";
  assert.throws(
    () => assertRetrospectiveClosure(closure, adjudication, smallAcquisition(adjudication)),
    /strictly equal/,
  );
});
test("EVENTARC retrospective rejects corrupt public acquisition bytes", () => {
  const { closure, adjudication } = eventarcFixture();
  assert.throws(
    () =>
      assertRetrospectiveClosure(closure, adjudication, smallAcquisition(adjudication), (path) =>
        path === acquisitionPath ? "0".repeat(64) : sha256(path),
      ),
    /public acquisition bytes/,
  );
});
test("EVENTARC retrospective cannot promote from flags without final evidence", () => {
  const { closure, adjudication } = eventarcFixture();
  closure.parentStatus = "COMPAT_VERIFIED";
  closure.conditions.forEach((condition) => (condition.status = "VERIFIED"));
  closure.closureReview.decision = "APPROVED";
  closure.closureReview.finalArtifactSha256 = adjudication.finalArtifact.releaseBinarySha256;
  adjudication.parentClosureApproved = true;
  adjudication.cases.at(-1).decision = "APPROVED_FINAL_CANONICAL_REVIEW";
  updateCaseBinding(adjudication.cases.at(-1));
  adjudication.finalArtifact.finalR20 = "PASSED";
  adjudication.finalArtifact.independentApproval = "APPROVED";
  assert.throws(
    () => assertRetrospectiveClosure(closure, adjudication, smallAcquisition(adjudication)),
    /genuine final evidence required/,
  );
});
