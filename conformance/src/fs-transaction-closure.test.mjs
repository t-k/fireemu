import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { RUNS, planComparisons } from "./release-strict-regression.mjs";

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
const requiredScopeDecisions = new Set([
  "T1",
  "T2",
  "T3",
  "T4",
  "T5",
  "T6",
  "T7",
  "T8",
  "T9",
  "OT-1",
]);

const recordedConditions = new Map([
  ["FS-TRANSACTION/read-write-lifecycle", ["P01", "P02B"]],
  ["FS-TRANSACTION/read-only-snapshot", ["P02", "P02B"]],
  ["FS-TRANSACTION/read-time-snapshot", ["P03"]],
  ["FS-TRANSACTION/token-validation-and-ownership", ["P01", "P14", "P16"]],
  ["FS-TRANSACTION/read-set-conflict", ["P05"]],
  ["FS-TRANSACTION/write-set-atomicity", ["P14"]],
  ["FS-TRANSACTION/query-range-lock", ["P14"]],
  ["FS-TRANSACTION/failed-commit-and-rollback", ["P08", "P09"]],
  ["FS-TRANSACTION/retry-token-lifecycle", ["P09", "P13B"]],
  ["FS-TRANSACTION/idle-expiry", ["P10-A", "P10-B", "P10-C", "P13A"]],
  ["FS-TRANSACTION/total-lifetime-expiry", ["P11", "P12", "P13A"]],
  ["FS-TRANSACTION/read-time-retention", ["P14"]],
  ["FS-TRANSACTION/paging-and-cancellation", ["P14"]],
]);

test("FS-TRANSACTION approved regression is rerun through the public recipe route", () => {
  const path = "spec/compatibility/broad-runs/fs-transaction-integrated-regression-v1.json";
  const plan = planComparisons(
    [
      {
        closure: {
          parent: "FS-TRANSACTION",
          parentStatus: "COMPAT_VERIFIED",
          integratedRegression: { comparisons: [{ path }] },
        },
      },
    ],
    () => ({
      kind: "fs-transaction-integrated-regression-v1",
      rows: [{ row: "recipe/control", status: "MATCH" }],
    }),
    { excludedKinds: [] },
  );
  assert.deepEqual(plan.errors, []);
  assert.equal(plan.excluded.length, 0);
  assert.deepEqual(plan.comparisons[0].runIds, ["R19"]);
  const run = RUNS.find(({ id }) => id === "R19");
  assert.deepEqual(
    run.commands.map(({ mode }) => mode),
    ["check", "export-comparison"],
  );
  assert.ok(run.commands.every(({ argv }) => argv.includes("{bin}") && argv.includes("--binary")));
  assert.ok(
    run.commands.every(
      ({ expectedExitCodes }) => expectedExitCodes.length === 1 && expectedExitCodes[0] === 0,
    ),
  );
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  const regression = closure.integratedRegression;
  assert.ok(regression, "the genuine final-source regression binding is required");
  const root = new URL("../../", import.meta.url);
  const buildBytes = readFileSync(new URL(regression.buildReceiptPath, root));
  const build = JSON.parse(buildBytes);
  const fixtureBytes = readFileSync(new URL(path, root));
  const fixture = JSON.parse(fixtureBytes);
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  assert.equal(regression.releaseBinarySha256, build.binarySha256);
  assert.equal(regression.buildReceiptSha256, digest(buildBytes));
  assert.match(regression.integrationCommit, /^[0-9a-f]{40}$/);
  assert.equal(regression.comparisons.length, 1);
  const comparison = regression.comparisons[0];
  assert.equal(comparison.path, path);
  assert.equal(comparison.sha256, digest(fixtureBytes));
  assert.equal(comparison.rows, fixture.rows.length);
  assert.deepEqual(comparison.summary, fixture.summary);
  assert.equal(fixture.fixtureSha256, digest(readFileSync(new URL(regression.fixturePath, root))));
  assert.deepEqual(regression.result, "IDENTICAL_TO_LANE");
  assert.equal(regression.productionRequests, 0);
});

const shippedSource = "dee94974292f4a49a10be6d586491e1ce663ad78";
const shippedArtifact = "429bb8a023e5adc52acbe7c8ce318c23710e9e0de9059850496c1224776c0cf6";
const shippedReview = "c63746d538b4600d1f095e3f1aa52eea9a21d5ec39da642ccb275a5b2d4b7ad8";

function assertCurrentDomainEvidence(comparison, build) {
  assert.equal(build.profile, "release");
  assert.equal(build.binarySha256, shippedArtifact);
  assert.equal(build.sourceCommit, shippedSource);
  assert.equal(build.producerSourceCommit, shippedSource);
  assert.equal(comparison.producerSourceCommit, shippedSource);
  assert.equal(build.buildInputs.scheme, "crates-without-test-trees-v1");
  assert.equal(build.buildInputs.dirty, false);
  assert.equal(
    build.buildInputs.inputsSha256,
    "14fa8adc424c133022eb864d36894fd253a02f606a9ff8c30c81c48d47e99187",
  );
  assert.deepEqual(build.command, [
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "fireemu",
    "--target",
    "x86_64-unknown-linux-musl",
  ]);
  assert.equal(build.sourceBoundBuildProof.headSha, shippedSource);
  assert.equal(build.sourceBoundBuildProof.buildConclusion, "success");
  assert.equal(build.sourceBoundBuildProof.installedIdentityStep.conclusion, "success");
  assertDomainEvidence(comparison, build, {
    processReceiptSha256: comparison.webSdk.lifecycle.processReceiptSha256,
    processReaped: true,
    exitCode: 0,
    driverReportsClosed: [true, true],
  });
  assert.equal(comparison.atomicVisibility.local.provenance.sourceCommit, shippedSource);
  assert.deepEqual(comparison.atomicVisibility.local.provenance.buildInputs, build.buildInputs);
}

function debugSnapshot(closure) {
  return {
    ...closure,
    parentStatus: closure.debugParentStatus,
    closureReview: closure.debugClosureReview,
    integratedRegression: closure.debugIntegratedRegression,
    conditions: closure.conditions.map((condition) => ({
      ...condition,
      status: condition.debugStatus,
      evidence: condition.debugEvidence,
      note: condition.debugNote,
    })),
  };
}

function assertApprovedReview(closure, build, comparison) {
  assert.equal(closure.parentStatus, "COMPAT_VERIFIED");
  const review = closure.closureReview;
  assert.equal(review.decision, "APPROVED");
  assert.equal(review.reviewScope, "FULL_PARENT");
  assert.equal(review.reviewedCommit, shippedSource);
  assert.equal(review.finalArtifactSha256, shippedArtifact);
  assert.equal(review.reviewSha256, shippedReview);
  assert.equal(closure.conditions.length, 18);
  assert.deepEqual(
    new Set(
      closure.conditions.map(({ conditionId }) => conditionId.replace("FS-TRANSACTION/", "")),
    ),
    required,
  );
  assert.ok(closure.conditions.every(({ status }) => status === "VERIFIED"));
  assertCurrentDomainEvidence(comparison, build);
  assert.equal(closure.integratedRegression.releaseBinarySha256, build.binarySha256);
  assert.equal(closure.integratedRegression.buildSourceCommit, build.sourceCommit);
  assert.equal(closure.integratedRegression.integrationCommit, shippedSource);
  for (const regression of [closure.integratedRegression, comparison.releaseRegression]) {
    assert.equal(regression.binaryProfile, "release");
    assert.equal(regression.checkExitCode, 0);
    assert.equal(regression.exportExitCode, 0);
    assert.equal(regression.checkExportIdentical, true);
    assert.equal(regression.reviewScope, review.reviewScope);
    assert.equal(regression.reviewSha256, review.reviewSha256);
  }
  assert.equal(closure.integratedRegression.reviewStatus, review.decision);
  assert.equal(comparison.releaseRegression.independentReview, review.decision);
  assert.equal(
    comparison.releaseRegression.comparisonSha256,
    closure.integratedRegression.actualComparisonSha256,
  );
  assert.equal(
    closure.integratedRegression.actualComparisonSha256,
    "859029091064115fb6883336676ffcf4d0d05b0c25e59ddbbe7c96478d6ebdf4",
  );
  assert.equal(comparison.releaseRegression.artifactSha256, shippedArtifact);
  assert.equal(comparison.releaseRegression.producerSourceCommit, shippedSource);
  for (const id of ["final-artifact-regression", "closure-review"]) {
    const evidence = closure.conditions.find(
      ({ conditionId }) => conditionId === `FS-TRANSACTION/${id}`,
    ).evidence;
    assert.equal(evidence.sourceCommit, review.reviewedCommit);
    assert.equal(evidence.finalArtifactSha256, review.finalArtifactSha256);
    assert.equal(evidence.reviewStatus, review.decision);
    assert.equal(evidence.reviewScope, review.reviewScope);
    assert.equal(evidence.reviewSha256, review.reviewSha256);
  }
}

function assertDomainEvidence(comparison, build, lifecycle) {
  assert.equal(comparison.artifactSha256, build.binarySha256);
  assert.equal(comparison.sourceCommit, build.sourceCommit);
  assert.equal(comparison.binaryProfile, build.profile);
  assert.equal(comparison.sourceBound, true);
  assert.deepEqual(comparison.buildInputs, build.buildInputs);
  assert.equal(comparison.programReplay.recordings, 32);
  assert.equal(comparison.programReplay.publisherRows, 1302);
  assert.equal(comparison.programReplay.tokenAgeRows, 142);
  assert.equal(comparison.programReplay.matchedRows, 1444);
  assert.equal(comparison.adminSdk.comparisons.length, 4);
  assert.equal(comparison.adminSdk.localReceipts.length, 2);
  assert.deepEqual(comparison.adminSdk.productionSha256, [
    "e6e754055db0555a77d67faf79ffad97b564de56781c1640d6a666d62c9ed0d9",
    "50ec52e2c1f17f497928c2c6b75fe6931d31a70d96c54c10643872d254f5f227",
  ]);
  for (const receipt of comparison.adminSdk.localReceipts) {
    assert.equal(receipt.complete, true);
    assert.equal(receipt.graphComplete, true);
    assert.equal(receipt.cleanupAbsent, true);
    assert.match(receipt.sha256, /^[0-9a-f]{64}$/);
  }
  for (const record of comparison.adminSdk.comparisons) {
    assert.equal(record.complete, true);
    assert.equal(record.matchedRows, 5);
    assert.equal(record.rows.length, 5);
    assert.ok(record.rows.every(({ status }) => status === "MATCH"));
    assert.match(record.comparisonSha256, /^[0-9a-f]{64}$/);
  }
  assert.equal(comparison.webSdk.comparisons.length, 2);
  assert.deepEqual(
    comparison.webSdk.production.map(({ sha256 }) => sha256),
    [
      "2d3518a8c275f0b9f2e219cdbb0ce1c22c4a55dc169ddd290e1e14c556b8e819",
      "2ad186b4a3aa35a41b501316feb1cf7d9e54f043dfa2b7d92eb56edc47fa4773",
    ],
  );
  assert.ok(comparison.webSdk.production.every(({ complete }) => complete === true));
  assert.equal(comparison.webSdk.localComplete, true);
  assert.equal(comparison.webSdk.localReceipt.complete, true);
  assert.equal(comparison.webSdk.localReceipt.reportedArtifactSourceCommit, null);
  assert.deepEqual(comparison.webSdk.lifecycle, lifecycle);
  assert.deepEqual(comparison.webSdk.lifecycle.driverReportsClosed, [true, true]);
  assert.match(comparison.webSdk.lifecycle.processReceiptSha256, /^[0-9a-f]{64}$/);
  for (const record of comparison.webSdk.comparisons) {
    assert.equal(record.matchedRows, 4);
    assert.equal(record.rows.length, 4);
    assert.ok(record.rows.every(({ status }) => status === "MATCH"));
  }
  assert.equal(comparison.atomicVisibility.rows.length, 4);
  assert.ok(
    comparison.atomicVisibility.rows.every(
      ({ status, matchedRows }) => status === "MATCH" && matchedRows === 2,
    ),
  );
  assert.equal(comparison.atomicVisibility.pairedRows.length, 8);
  assert.ok(comparison.atomicVisibility.pairedRows.every(({ status }) => status === "MATCH"));
  assert.equal(
    comparison.atomicVisibility.fullCorpusComparison,
    "NOT_EVALUATED_IN_TRANSACTION_RELEASE_SCOPE",
  );
  assert.equal(comparison.atomicVisibility.local.cleanupComplete, true);
  assert.equal(
    comparison.atomicVisibility.local.provenance.binarySha256,
    comparison.artifactSha256,
  );
  assert.equal(comparison.expiryRetry.summary.rows, 36);
  assert.equal(comparison.expiryRetry.summary.recordings, 2);
  assert.equal(comparison.expiryRetry.summary.mismatches, 0);
  assert.equal(comparison.expiryRetry.coverage, "PARTIAL");
  assert.match(comparison.expiryRetry.resultSha256, /^[0-9a-f]{64}$/);
  for (const domain of [
    comparison.programReplay,
    comparison.adminSdk,
    comparison.webSdk,
    comparison.atomicVisibility,
    comparison.expiryRetry,
  ]) {
    assert.equal(domain.artifactSha256, comparison.artifactSha256);
  }
  assert.notEqual(comparison.historicalComparison.artifactSha256, comparison.artifactSha256);
}

function assertHistoricalDomainEvidence(comparison) {
  assert.equal(comparison.programReplay.recordings, 32);
  assert.equal(comparison.programReplay.publisherRows, 1302);
  assert.equal(comparison.programReplay.tokenAgeRows, 142);
  assert.equal(comparison.programReplay.matchedRows, 1444);
  assert.equal(comparison.adminSdk.comparisons.length, 4);
  assert.deepEqual(comparison.adminSdk.productionSha256, [
    "e6e754055db0555a77d67faf79ffad97b564de56781c1640d6a666d62c9ed0d9",
    "50ec52e2c1f17f497928c2c6b75fe6931d31a70d96c54c10643872d254f5f227",
  ]);
  assert.equal(comparison.adminSdk.localReceipts.length, 2);
  assert.ok(
    comparison.adminSdk.localReceipts.every(
      ({ remainingOwnedProcesses }) => Object.keys(remainingOwnedProcesses).length === 0,
    ),
  );
  for (const record of comparison.adminSdk.comparisons) {
    assert.equal(record.complete, true);
    assert.equal(record.attempts.length, 5);
    assert.ok(record.attempts.every(({ match }) => match === true));
  }
  assert.equal(comparison.webSdk.comparisons.length, 2);
  assert.deepEqual(
    comparison.webSdk.production.map(({ sha256 }) => sha256),
    [
      "2d3518a8c275f0b9f2e219cdbb0ce1c22c4a55dc169ddd290e1e14c556b8e819",
      "2ad186b4a3aa35a41b501316feb1cf7d9e54f043dfa2b7d92eb56edc47fa4773",
    ],
  );
  assert.ok(
    comparison.webSdk.production.every(
      ({ complete, sandboxRequests }) => complete && sandboxRequests === 63,
    ),
  );
  assert.equal(comparison.webSdk.localReceipt.complete, true);
  assert.equal(comparison.webSdk.localReceipt.exitCode, 0);
  assert.equal(comparison.webSdk.lifecycle.observedProcessesAbsent, true);
  assert.equal(comparison.webSdk.lifecycle.readyDescriptorWithdrawn, true);
  for (const record of comparison.webSdk.comparisons) {
    assert.equal(record.cases.length, 4);
    for (const row of record.cases) {
      assert.equal(row.status, "MATCH");
      assert.equal(row.production.scenarioComplete, true);
      assert.equal(row.local.scenarioComplete, true);
      assert.equal(row.production.reportClosed, true);
      assert.equal(row.local.reportClosed, true);
      assert.deepEqual(row.production.semantic, row.local.semantic);
      assert.ok(row.production.semantic.wire.every(({ complete }) => complete === true));
      assert.equal(row.production.semantic.attempts, row.scenario === "control" ? 1 : 2);
    }
  }
  assert.equal(comparison.atomicVisibility.rows.length, 4);
  assert.ok(comparison.atomicVisibility.rows.every(({ status }) => status === "MATCH"));
  assert.equal(comparison.atomicVisibility.fullCorpusOk, false);
  assert.equal(comparison.expiryRetry.summary.rows, 36);
  assert.equal(comparison.expiryRetry.summary.mismatches, 0);
  for (const domain of [
    comparison.programReplay,
    comparison.adminSdk,
    comparison.webSdk,
    comparison.atomicVisibility,
    comparison.expiryRetry,
  ]) {
    assert.equal(domain.artifactSha256, comparison.artifactSha256);
  }
}

function assertCurrentProgramBindings(condition, current, fixture, inputs) {
  const { evidence, historicalEvidence, recordedComparison } = condition;
  assert.deepEqual(evidence.comparisonPaths, [
    "spec/compatibility/closure/evidence/FS-TRANSACTION-comparison.json",
  ]);
  assert.equal(evidence.finalArtifactSha256, current.artifactSha256);
  assert.equal(evidence.sourceCommit, current.sourceCommit);
  assert.equal(evidence.producerSourceCommit, current.producerSourceCommit);
  assert.deepEqual(evidence.productionRecordings, historicalEvidence.productionRecordings);
  let total = 0;
  for (const entry of recordedComparison.programs) {
    const selected = current.programReplay.replays.filter(
      ({ program }) => program === entry.program,
    );
    const original = current.historicalComparison.programReplay.replays.filter(
      ({ program }) => program === entry.program,
    );
    assert.equal(selected.length, 2, entry.program);
    assert.deepEqual(selected.map(({ recording }) => recording).toSorted(), [1, 2]);
    const identities = (rows) =>
      rows
        .map(({ program, recording, productionSha256 }) =>
          JSON.stringify([program, recording, productionSha256]),
        )
        .toSorted();
    assert.deepEqual(identities(selected), identities(original), entry.program);
    const recipes = inputs.programs.filter(({ recordings }) =>
      recordings.every(({ expectation }) => expectation.projection.program === entry.program),
    );
    assert.equal(recipes.length, 1);
    const recipe = recipes[0];
    let publisherRows = 0;
    for (const replay of selected) {
      const prefix = `${recipe.key}/r${replay.recording}/`;
      const rows = fixture.rows.filter(({ row }) => row.startsWith(prefix));
      const publisher = rows.filter(({ row }) => !row.startsWith(`${prefix}tokenAges/`));
      const ages = rows.filter(({ row }) => row.startsWith(`${prefix}tokenAges/`));
      const recordings = recipe.recordings.filter(
        ({ originSha256 }) => originSha256 === replay.productionSha256,
      );
      assert.equal(recordings.length, 1);
      const expectedIds = Object.entries(recordings[0].inventory)
        .flatMap(([section, rowIds]) => rowIds.map((identity) => `${prefix}${section}/${identity}`))
        .toSorted();
      assert.deepEqual(rows.map(({ row }) => row).toSorted(), expectedIds);
      assert.ok(rows.every(({ status }) => status === "MATCH"));
      assert.equal(replay.matchedRows, publisher.length + ages.length);
      publisherRows += publisher.length;
      assert.ok(replay.matchedRows > 0);
      assert.match(replay.resultSha256, /^[0-9a-f]{64}$/);
      const aggregate = current.rows.filter(
        ({ row }) => row === `${replay.program}/recording-${replay.recording}`,
      );
      assert.equal(aggregate.length, 1);
      assert.equal(aggregate[0].conditionId, "FS-TRANSACTION/final-artifact-regression");
      assert.equal(aggregate[0].status, "MATCH");
      assert.equal(aggregate[0].matchedRows, replay.matchedRows);
      assert.equal(aggregate[0].resultSha256, replay.resultSha256);
    }
    assert.equal(publisherRows, entry.rows);
    total += publisherRows;
  }
  assert.deepEqual(evidence.rows, { MATCH: total });
  assert.deepEqual(evidence.rows, historicalEvidence.rows);
}

function assertDebugReview(closure) {
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.closureReview.decision, "APPROVED_WITH_BOUNDED_QUALIFICATIONS");
  assert.equal(closure.closureReview.reviewScope, "FINAL_DEBUG_ARTIFACT_EVIDENCE");
  assert.equal(
    closure.conditions.find(({ conditionId }) => conditionId === "FS-TRANSACTION/closure-review")
      .status,
    "PENDING_REVIEW",
  );
  const final = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-TRANSACTION/final-artifact-regression",
  );
  assert.equal(final.status, "VERIFIED");
  assert.equal(final.evidence.reviewScope, closure.closureReview.reviewScope);
  assert.equal(final.evidence.reviewStatus, closure.closureReview.decision);
  assert.equal(final.evidence.reviewSha256, closure.closureReview.reviewSha256);
  assert.equal(final.evidence.finalArtifactSha256, closure.closureReview.finalArtifactSha256);
  assert.match(closure.closureReview.reviewSha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(closure.closureReview.pendingGates, {
    sameTreeCi: "PENDING",
    shippedReleaseProfileValidation: "PENDING",
    stagingAndSignatureChecks: "PENDING",
    formalClosurePromotion: "PENDING",
    releasePromotion: "PENDING",
  });
}

test("FS-TRANSACTION final domain evidence retains genuine replay coverage on one binary", () => {
  const root = new URL("../../", import.meta.url);
  const build = JSON.parse(
    readFileSync(
      new URL("spec/compatibility/closure/evidence/FS-TRANSACTION-build.json", root),
      "utf8",
    ),
  );
  const comparison = JSON.parse(
    readFileSync(
      new URL("spec/compatibility/closure/evidence/FS-TRANSACTION-comparison.json", root),
      "utf8",
    ),
  );
  assertCurrentDomainEvidence(comparison, build);
  assert.equal(build.debugBuild.profile, "debug");
  assert.equal(build.debugBuild.buildInputs.scheme, "binary-v1");
  assert.equal(build.debugBuild.buildInputs.inputCount, 337);
  assertDomainEvidence(
    { ...comparison.debugComparison, historicalComparison: comparison.historicalComparison },
    build.debugBuild,
    {
      processReceiptSha256: comparison.debugComparison.webSdk.lifecycle.processReceiptSha256,
      processGroupAbsent: true,
      driverReportsClosed: [true, true],
    },
  );
  assertHistoricalDomainEvidence(comparison.historicalComparison);
  for (const mutate of [
    (value) => {
      value.adminSdk.localReceipts[0].remainingOwnedProcesses.leaked = 1;
    },
    (value) => {
      value.adminSdk.comparisons[0].attempts[0].match = false;
    },
    (value) => {
      value.webSdk.comparisons[0].cases[0].local.scenarioComplete = false;
    },
    (value) => {
      value.webSdk.comparisons[0].cases[0].local.reportClosed = false;
    },
    (value) => {
      value.webSdk.lifecycle.readyDescriptorWithdrawn = false;
    },
  ]) {
    const changed = structuredClone(comparison.historicalComparison);
    mutate(changed);
    assert.throws(() => assertHistoricalDomainEvidence(changed));
  }
  const mutations = [
    (value) => {
      delete value.adminSdk.localReceipts[0].cleanupAbsent;
    },
    (value) => {
      value.adminSdk.localReceipts[0].cleanupAbsent = false;
    },
    (value) => {
      value.adminSdk.comparisons.pop();
    },
    (value) => {
      value.webSdk.production[0].complete = false;
    },
    (value) => {
      value.webSdk.comparisons[0].rows.pop();
    },
    (value) => {
      value.webSdk.lifecycle.driverReportsClosed[1] = false;
    },
    (value) => {
      value.atomicVisibility.fullCorpusComparison = "APPROVED";
    },
    (value) => {
      value.expiryRetry.coverage = "FULL";
    },
    (value) => {
      value.artifactSha256 = value.historicalComparison.artifactSha256;
    },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(comparison);
    mutate(changed);
    assert.throws(() => assertCurrentDomainEvidence(changed, build));
  }
});

test("FS-TRANSACTION bounded debug approval cannot promote formal closure", () => {
  const closure = debugSnapshot(JSON.parse(readFileSync(closureUrl, "utf8")));
  assertDebugReview(closure);
  for (const mutate of [
    (value) => {
      value.parentStatus = "COMPAT_VERIFIED";
    },
    (value) => {
      value.closureReview.decision = "APPROVED";
    },
    (value) => {
      value.closureReview.reviewScope = "FULL_PARENT";
    },
    (value) => {
      value.closureReview.pendingGates.shippedReleaseProfileValidation = "PASS";
    },
    (value) => {
      delete value.closureReview.reviewSha256;
    },
    (value) => {
      value.conditions.find(
        ({ conditionId }) => conditionId === "FS-TRANSACTION/closure-review",
      ).status = "VERIFIED";
    },
  ]) {
    const changed = structuredClone(closure);
    mutate(changed);
    assert.throws(() => assertDebugReview(changed));
  }
});

test("FS-TRANSACTION published program records retain thirteen condition mappings", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  const root = new URL("../../", import.meta.url);
  assert.equal(closure.conditions.filter(({ status }) => status === "VERIFIED").length, 18);
  for (const condition of closure.conditions) {
    const expected = recordedConditions.get(condition.conditionId);
    if (!expected) {
      assert.equal(condition.recordedComparison, undefined, condition.conditionId);
      continue;
    }
    assert.equal(condition.status, "VERIFIED", condition.conditionId);
    assert.equal(condition.productionObservation, "RECORDED_TWICE_STRICT_COMPARED");
    const recorded = condition.recordedComparison;
    assert.equal(recorded.profile, "strict");
    assert.equal(recorded.recordings, 2);
    const programs = recorded.programs.map(({ program }) =>
      program
        .replace(/^FS-TRANSACTION-/, "")
        .split("-")
        .slice(0, program.includes("P10-") ? 2 : 1)
        .join("-"),
    );
    assert.deepEqual(programs, expected, condition.conditionId);
    for (const entry of recorded.programs) {
      assert.equal(entry.mismatches, 0, entry.program);
      assert.ok(entry.rows > 0, entry.program);
      const observations = JSON.parse(readFileSync(new URL(entry.observationsPath, root), "utf8"));
      const comparison = JSON.parse(readFileSync(new URL(entry.comparisonPath, root), "utf8"));
      assert.equal(observations.kind, "fs-transaction-recorded-observations-v1");
      assert.equal(comparison.kind, "fs-transaction-recorded-comparison-v1");
      assert.ok(observations.condition.includes(condition.conditionId), entry.program);
      assert.ok(comparison.condition.includes(condition.conditionId), entry.program);
      assert.equal(comparison.program, entry.program);
      assert.equal(comparison.profile, "strict");
      assert.equal(comparison.authorizesProduction, false);
      assert.equal(comparison.productionRequests, 0);
      assert.deepEqual(comparison.summary, { recordings: 2, rows: entry.rows, mismatches: 0 });
      assert.equal(comparison.recordings.length, 2);
      if (comparison.program === "FS-TRANSACTION-P16-FOREIGN-TOKENS") {
        assert.equal(comparison.comparer.replaySetup.managementLifecycleReplayed, false);
        assert.match(comparison.comparer.replaySetup.operationalLauncherSha256, /^[0-9a-f]{64}$/);
        assert.equal(comparison.comparer.replaySetup.configurationFiles.length, 2);
      }
      assert.equal(observations.corpora[0].agree, true);
      assert.match(comparison.artifact.sourceCommit, /^[0-9a-f]{40}$/);
      assert.match(comparison.artifact.binarySha256, /^[0-9a-f]{64}$/);
      assert.ok(existsSync(new URL(entry.comparisonPath, root)));
    }
    if (
      ["FS-TRANSACTION/idle-expiry", "FS-TRANSACTION/total-lifetime-expiry"].includes(
        condition.conditionId,
      )
    )
      assert.match(recorded.boundaryRuling, /110\.70, 122\.96.*298\.7, 302\.2/);
    // the evidence block names the recordings, the one artifact and exactly the records above
    const evidence = condition.historicalEvidence;
    assert.deepEqual(
      evidence.productionRecordings.map(({ program }) => program),
      recorded.programs.map(({ program }) => program),
    );
    for (const run of evidence.productionRecordings) {
      assert.equal(run.recordings, 2, run.program);
      assert.match(run.project, /^fireemu-oracle-(sbx|txn|query)$/, run.program);
    }
    assert.deepEqual(
      evidence.comparisonPaths,
      recorded.programs.map(({ comparisonPath }) => comparisonPath),
    );
    assert.deepEqual(evidence.rows, {
      MATCH: recorded.programs.reduce((sum, { rows }) => sum + rows, 0),
    });
    assert.match(evidence.finalArtifactSha256, /^[0-9a-f]{64}$/);
    assert.match(evidence.sourceCommit, /^[0-9a-f]{40}$/);
    for (const entry of recorded.programs) {
      const { artifact } = JSON.parse(readFileSync(new URL(entry.comparisonPath, root), "utf8"));
      assert.equal(artifact.binarySha256, evidence.finalArtifactSha256, entry.program);
      assert.equal(artifact.sourceCommit, evidence.sourceCommit, entry.program);
    }
    const current = JSON.parse(
      readFileSync(
        new URL("spec/compatibility/closure/evidence/FS-TRANSACTION-comparison.json", root),
        "utf8",
      ),
    );
    const fixture = JSON.parse(
      readFileSync(
        new URL("spec/compatibility/broad-runs/fs-transaction-integrated-regression-v1.json", root),
        "utf8",
      ),
    );
    const inputs = JSON.parse(
      readFileSync(
        new URL("spec/compatibility/broad-runs/fs-transaction-release-replay-inputs-v1.json", root),
        "utf8",
      ),
    );
    assertCurrentProgramBindings(condition, current, fixture, inputs);
    assertDebugReview(debugSnapshot(closure));
    assert.doesNotMatch(condition.note, /not a published redacted record yet/i);
  }
  // one strict artifact per publication: every record names the same commit and binary
  const artifacts = new Set(
    [...recordedConditions.keys()].flatMap((id) =>
      closure.conditions
        .find(({ conditionId }) => conditionId === id)
        .recordedComparison.programs.map(({ comparisonPath }) => {
          const { artifact } = JSON.parse(readFileSync(new URL(comparisonPath, root), "utf8"));
          return `${artifact.sourceCommit} ${artifact.binarySha256}`;
        }),
    ),
  );
  assert.equal(artifacts.size, 1);
});

test("FS-TRANSACTION current program identities reject substituted recordings and results", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  const current = JSON.parse(
    readFileSync(
      new URL(
        "../../spec/compatibility/closure/evidence/FS-TRANSACTION-comparison.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const root = new URL("../../", import.meta.url);
  const fixture = JSON.parse(
    readFileSync(
      new URL("spec/compatibility/broad-runs/fs-transaction-integrated-regression-v1.json", root),
      "utf8",
    ),
  );
  const inputs = JSON.parse(
    readFileSync(
      new URL("spec/compatibility/broad-runs/fs-transaction-release-replay-inputs-v1.json", root),
      "utf8",
    ),
  );
  const condition = closure.conditions[0];
  assertCurrentProgramBindings(condition, current, fixture, inputs);
  for (const mutate of [
    (value) => {
      value.programReplay.replays[0].recording = 1;
    },
    (value) => {
      value.programReplay.replays[0].productionSha256 = "0".repeat(64);
    },
    (value) => {
      value.programReplay.replays[0].matchedRows -= 1;
    },
    (value) => {
      value.programReplay.replays[0].resultSha256 = "0".repeat(64);
    },
    (value) => {
      value.programReplay.replays.splice(0, 1);
    },
    (value) => {
      value.rows[0].status = "MISMATCH";
    },
  ]) {
    const changed = structuredClone(current);
    mutate(changed);
    assert.throws(() => assertCurrentProgramBindings(condition, changed, fixture, inputs));
  }
  const retry = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-TRANSACTION/retry-token-lifecycle",
  );
  assertCurrentProgramBindings(retry, current, fixture, inputs);
  const missingAge = structuredClone(fixture);
  missingAge.rows.splice(
    missingAge.rows.findIndex(({ row }) => row.startsWith("p13b/r1/tokenAges/")),
    1,
  );
  assert.throws(() => assertCurrentProgramBindings(retry, current, missingAge, inputs));
  const missingContribution = structuredClone(current);
  const replay = missingContribution.programReplay.replays.find(
    ({ program, recording }) => program.includes("P13B-") && recording === 1,
  );
  replay.matchedRows -= 1;
  missingContribution.rows.find(({ row }) => row === `${replay.program}/recording-1`).matchedRows -=
    1;
  assert.throws(() => assertCurrentProgramBindings(retry, missingContribution, fixture, inputs));
  const changedCondition = structuredClone(retry);
  changedCondition.evidence.rows.MATCH += 16;
  assert.throws(() => assertCurrentProgramBindings(changedCondition, current, fixture, inputs));
});

test("FS-TRANSACTION supplementary REST evidence stays partial beside independent domain evidence", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  const partial = new Map([
    ["FS-TRANSACTION/idle-expiry", 5],
    ["FS-TRANSACTION/failed-commit-and-rollback", 3],
    ["FS-TRANSACTION/retry-token-lifecycle", 5],
  ]);
  const reference =
    "spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-recorded-comparison-v1.json";
  const observed = [];
  for (const condition of closure.conditions) {
    assert.equal(
      condition.status === "VERIFIED",
      recordedConditions.has(condition.conditionId) ||
        [
          "FS-TRANSACTION/admin-sdk-server-retry",
          "FS-TRANSACTION/web-sdk-optimistic-retry",
          "FS-TRANSACTION/commit-atomic-visibility",
          "FS-TRANSACTION/final-artifact-regression",
        ].includes(condition.conditionId) ||
        closure.closureReview.decision === "APPROVED",
      condition.conditionId,
    );
    if (partial.has(condition.conditionId)) {
      assert.equal(condition.status, "VERIFIED");
      assert.equal(condition.partialEvidence.coverage, "PARTIAL");
      assert.equal(condition.partialEvidence.reference, reference);
      assert.equal(condition.partialEvidence.transport, "rest");
      assert.equal(condition.partialEvidence.recordings, 2);
      assert.equal(condition.partialEvidence.caseIds.length, partial.get(condition.conditionId));
      assert.ok(condition.partialEvidence.remainingBoundaries.length);
      observed.push(...condition.partialEvidence.caseIds);
    } else if (
      recordedConditions.has(condition.conditionId) ||
      [
        "FS-TRANSACTION/admin-sdk-server-retry",
        "FS-TRANSACTION/web-sdk-optimistic-retry",
        "FS-TRANSACTION/commit-atomic-visibility",
      ].includes(condition.conditionId)
    ) {
      assert.equal(condition.productionObservation, "RECORDED_TWICE_STRICT_COMPARED");
    } else {
      assert.equal(condition.productionObservation, "UNOBSERVED_BY_RECORDED_CORPUS");
    }
  }
  assert.equal(observed.length, 13);
  assert.equal(new Set(observed).size, 13);
  assert.equal(
    closure.parentStatus,
    closure.closureReview.decision === "APPROVED" ? "COMPAT_VERIFIED" : "IMPLEMENTING",
  );
  assertDebugReview(debugSnapshot(closure));
  assert.equal(closure.profileComparison.emulatorCompatibilityCheck, "SEPARATE_TRACK");
  assert.equal(closure.productionPlan.preparedCampaign.authorizesProduction, false);
  assert.deepEqual(closure.productionPlan.preparedCampaign.actualRequestsPerRecording, [75, 75]);
});

test("FS-TRANSACTION proposal names every acceptance boundary without claiming closure", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  assert.equal(closure.parent, "FS-TRANSACTION");
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(closure.freezeState, "FROZEN");
  assert.match(closure.frozenOn, /^\d{4}-\d{2}-\d{2}$/);
  assert.deepEqual(
    new Set(closure.conditions.map(({ conditionId }) => conditionId.split("/")[1])),
    required,
  );
  assert.equal(closure.conditions.length, required.size);
  const recipes = closure.conditions.flatMap(({ recipeIds }) => recipeIds);
  assert.equal(recipes.length, new Set(recipes).size);
  for (const condition of closure.conditions) {
    assert.ok(condition.source);
    assert.ok(condition.observation.method);
    assert.ok(
      condition.observation.credentials,
      `${condition.conditionId} must name its credential context`,
    );
    assert.ok(condition.note?.trim(), `${condition.conditionId} must state its remaining boundary`);
    assert.ok(condition.verification.requiredEvidence.length);
    assert.ok(statuses.has(condition.status), `${condition.conditionId}: ${condition.status}`);
    if (condition.status === "VERIFIED")
      assert.ok(condition.evidence, `${condition.conditionId}: evidence`);
    for (const recipe of condition.recipeIds)
      assert.equal(recipe, `fs-transaction/${condition.conditionId.split("/")[1]}`);
  }
  const preparedCases = closure.conditions.flatMap(
    ({ observation }) => observation.existingCaseIds ?? [],
  );
  assert.deepEqual(
    new Set(preparedCases),
    new Set([
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
    ]),
  );
  assert.equal(preparedCases.length, 13, "each prepared case belongs to one condition");
  const sdk = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-TRANSACTION/web-sdk-optimistic-retry",
  );
  assert.deepEqual(sdk.observation.transports, ["node-web-sdk", "browser-webchannel"]);
  assert.equal(sdk.verification.recordingsRequiredPerTransport, 2);
  assert.match(sdk.observation.method, /BatchGetDocuments.*precondition.*Commit.*callback count/);
  const admin = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-TRANSACTION/admin-sdk-server-retry",
  );
  assert.match(admin.observation.method, /firebase-admin 14\.3\.0.*retryTransaction/);
  assert.match(
    closure.conditions.find(({ conditionId }) => conditionId === "FS-TRANSACTION/idle-expiry")
      .observation.limitId,
    /^FS-LIMIT-TRANSACTION-IDLE-TIME$/,
  );
  assert.match(
    closure.conditions.find(
      ({ conditionId }) => conditionId === "FS-TRANSACTION/total-lifetime-expiry",
    ).observation.limitId,
    /^FS-LIMIT-TRANSACTION-TOTAL-TIME$/,
  );
  const readTime = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-TRANSACTION/read-time-snapshot",
  );
  assert.ok(!readTime.localEvidence.references.some((path) => path.includes("expiry-retry")));
  assert.equal(closure.productionPlan.preparedCampaign.project, "fireemu-oracle-sbx");
  assert.equal(closure.productionPlan.preparedCampaign.authorizesProduction, false);
  assert.equal(closure.productionPlan.preparedCampaign.recordingsNeeded, 2);
  assert.ok(closure.productionPlan.unestimatedConditions.length);
  assert.ok(
    closure.productionPlan.unestimatedConditions.includes(
      "FS-TRANSACTION/failed-commit-and-rollback",
    ),
  );
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
  assert.match(
    closure.scopeDecisions.find(({ id }) => id === "OT-1").decision,
    /PESSIMISTIC.*OPTIMISTIC/,
  );
  assert.equal(closure.profileComparison.profile, "strict");
  assert.equal(closure.profileComparison.emulatorCompatibilityCheck, "SEPARATE_TRACK");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    closure.conditions.every(({ status }) => status === "VERIFIED") &&
      closure.closureReview.decision === "APPROVED",
  );
});

test("FS-TRANSACTION notes of VERIFIED conditions do not call the condition open", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  const stale =
    /remains open|remain required|no status change|gRPC is not recorded|until local shadow v5|older strict/i;
  for (const condition of closure.conditions.filter(({ status }) => status === "VERIFIED")) {
    assert.doesNotMatch(condition.note, stale, condition.conditionId);
    for (const item of condition.partialEvidence?.remainingBoundaries ?? [])
      assert.doesNotMatch(item, stale, condition.conditionId);
  }
});

test("FS-TRANSACTION historical E04 rows of the verified conditions retain their original release binary, the idle cases at 121 s of idle", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  const root = new URL("../../", import.meta.url);
  const prefixes = new Map([
    ["FS-TRANSACTION/idle-expiry", "idle-expiry/"],
    ["FS-TRANSACTION/failed-commit-and-rollback", "finished-token/"],
    ["FS-TRANSACTION/retry-token-lifecycle", "retry-token/"],
  ]);
  for (const [id, prefix] of prefixes) {
    const condition = closure.conditions.find(({ conditionId }) => conditionId === id);
    assert.equal(condition.status, "VERIFIED", id);
    const releaseReplay = condition.partialEvidence.historicalReleaseReplay;
    assert.deepEqual(condition.historicalEvidence.e04ReleaseReplay, releaseReplay, id);
    assert.equal(condition.evidence.e04ReleaseReplay, undefined, id);
    const record = JSON.parse(readFileSync(new URL(releaseReplay.path, root), "utf8"));
    assert.equal(record.kind, "fs-transaction-expiry-retry-04-release-replay-v1");
    assert.equal(
      record.artifact.binarySha256,
      condition.historicalEvidence.finalArtifactSha256,
      id,
    );
    assert.equal(record.artifact.sourceCommit, condition.historicalEvidence.sourceCommit, id);
    assert.equal(releaseReplay.finalArtifactSha256, record.artifact.binarySha256, id);
    assert.equal(releaseReplay.sourceCommit, record.artifact.sourceCommit, id);
    assert.equal(record.summary.mismatches, 0);
    const rows = record.recordings
      .flatMap((entry) => entry.rows)
      .filter((row) => row.caseId.startsWith(prefix));
    assert.equal(releaseReplay.rows.MATCH, rows.length, id);
    assert.ok(
      rows.every((row) => row.match),
      id,
    );
    for (const caseId of condition.partialEvidence.caseIds) {
      assert.ok(
        rows.some((row) => row.caseId === caseId),
        `${id}: ${caseId} is replayed`,
      );
      if (id === "FS-TRANSACTION/idle-expiry" && record.replay.idleCases.includes(caseId))
        assert.ok(
          rows.some((row) => row.caseId === `${caseId}#postState`),
          `${id}: ${caseId} post state is replayed`,
        );
    }
  }
  // the idle observations ran at 121 s of idle on the control clock, inside the interval production narrowed for the idle threshold (the commit and the rollback were recorded at 120.35 to 121.15 s;
  // the lock release at 124.7 to 125.2 s, which strict refuses as it refuses every idle above 120 s)
  const record = JSON.parse(
    readFileSync(
      new URL(
        "spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-release-replay-v1.json",
        root,
      ),
      "utf8",
    ),
  );
  assert.equal(record.replay.idleCases.length, 3);
  const idles = Object.values(record.replay.localIdleSeconds);
  assert.ok(
    idles.length >= 3 && idles.every((idle) => (idle >= 110.7 && idle < 122.96) || idle === 20),
  );
});

test("FS-TRANSACTION full-parent approval binds the actual shipped artifact and all eighteen conditions", () => {
  const root = new URL("../../", import.meta.url);
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  const build = JSON.parse(
    readFileSync(
      new URL("spec/compatibility/closure/evidence/FS-TRANSACTION-build.json", root),
      "utf8",
    ),
  );
  const comparison = JSON.parse(
    readFileSync(
      new URL("spec/compatibility/closure/evidence/FS-TRANSACTION-comparison.json", root),
      "utf8",
    ),
  );
  assertApprovedReview(closure, build, comparison);
  for (const mutate of [
    (value) => {
      value.closureReview.reviewSha256 = "0".repeat(64);
    },
    (value) => {
      value.closureReview.reviewedCommit = value.debugClosureReview.reviewedCommit;
    },
    (value) => {
      value.closureReview.finalArtifactSha256 = value.debugClosureReview.finalArtifactSha256;
    },
    (value) => {
      value.closureReview.reviewScope = "FINAL_DEBUG_ARTIFACT_EVIDENCE";
    },
    (value) => {
      value.conditions.shift();
    },
    (value) => {
      value.conditions[0].status = "PENDING_REVIEW";
    },
    (value) => {
      value.integratedRegression.checkExportIdentical = false;
    },
  ]) {
    const changed = structuredClone(closure);
    mutate(changed);
    assert.throws(() => assertApprovedReview(changed, build, comparison));
  }
  for (const [key, value] of [
    ["reviewSha256", "0".repeat(64)],
    ["reviewScope", "FINAL_DEBUG_ARTIFACT_EVIDENCE"],
  ]) {
    const changed = structuredClone(closure);
    const changedComparison = structuredClone(comparison);
    changed.closureReview[key] = value;
    changed.integratedRegression[key] = value;
    changedComparison.releaseRegression[key] = value;
    for (const id of ["final-artifact-regression", "closure-review"]) {
      changed.conditions.find(({ conditionId }) => conditionId === `FS-TRANSACTION/${id}`).evidence[
        key
      ] = value;
    }
    assert.throws(() => assertApprovedReview(changed, build, changedComparison));
  }
  const changedClosure = structuredClone(closure);
  const changedComparison = structuredClone(comparison);
  changedClosure.integratedRegression.actualComparisonSha256 = "0".repeat(64);
  changedComparison.releaseRegression.comparisonSha256 = "0".repeat(64);
  assert.throws(() => assertApprovedReview(changedClosure, build, changedComparison));
  const changedBuild = structuredClone(build);
  changedBuild.buildInputs.inputsSha256 = "0".repeat(64);
  const changedInputsComparison = structuredClone(comparison);
  changedInputsComparison.buildInputs = changedBuild.buildInputs;
  changedInputsComparison.atomicVisibility.local.provenance.buildInputs = changedBuild.buildInputs;
  assert.throws(() => assertApprovedReview(closure, changedBuild, changedInputsComparison));
  const debugBuild = { ...build.debugBuild, historicalBuild: build.historicalBuild };
  assert.throws(() => assertApprovedReview(closure, debugBuild, comparison));
});
