import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createHash } from "node:crypto";

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

test("FS-TRANSACTION recorded REST subset leaves every frozen condition open", () => {
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
    assert.notEqual(condition.status, "VERIFIED");
    if (partial.has(condition.conditionId)) {
      assert.equal(condition.status, "PRODUCTION_RECORDED");
      assert.equal(condition.partialEvidence.coverage, "PARTIAL");
      assert.equal(condition.partialEvidence.reference, reference);
      assert.equal(condition.partialEvidence.transport, "rest");
      assert.equal(condition.partialEvidence.recordings, 2);
      assert.equal(condition.partialEvidence.caseIds.length, partial.get(condition.conditionId));
      assert.ok(condition.partialEvidence.remainingBoundaries.length);
      assert.match(condition.partialEvidence.remainingBoundaries.join(" "), /gRPC/);
      observed.push(...condition.partialEvidence.caseIds);
    } else if (condition.conditionId === "FS-TRANSACTION/read-only-snapshot") {
      assert.equal(condition.productionObservation, "RECORDED_P02_P02B_SUBSET");
      assert.equal(condition.partialEvidence.coverage, "PARTIAL");
    } else {
      assert.equal(condition.productionObservation, "UNOBSERVED_BY_RECORDED_CORPUS");
    }
  }
  assert.equal(observed.length, 13);
  assert.equal(new Set(observed).size, 13);
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.closureReview.decision, "PENDING");
  assert.equal(closure.profileComparison.emulatorCompatibilityCheck, "PENDING_LOCAL_OBSERVATION");
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
  assert.equal(closure.profileComparison.emulatorCompatibilityCheck, "PENDING_LOCAL_OBSERVATION");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    closure.conditions.every(({ status }) => status === "VERIFIED") &&
      closure.closureReview.decision === "APPROVED",
  );
});

test("P02/P02b retained read-only evidence preserves all steps and current profile differences without closure", () => {
  const base = new URL("../../spec/compatibility/broad-runs/", import.meta.url);
  const observed = JSON.parse(
    readFileSync(new URL("fs-transaction-p02-recorded-observations-v1.json", base), "utf8"),
  );
  const compared = JSON.parse(
    readFileSync(new URL("fs-transaction-p02-recorded-comparison-v1.json", base), "utf8"),
  );
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  assert.equal(observed.authorizesProduction, false);
  assert.equal(observed.coverage, "PARTIAL");
  assert.equal(compared.promotionReady, false);
  assert.equal(compared.productionRequests, 0);
  assert.equal(compared.coverage, "PARTIAL");
  const producerBytes = readFileSync(new URL(`../../${compared.producer.path}`, import.meta.url));
  assert.equal(compared.producer.sha256, createHash("sha256").update(producerBytes).digest("hex"));
  assert.equal(compared.corpora.length, 2);
  for (const [index, corpus] of observed.corpora.entries()) {
    const steps = index === 0 ? 35 : 42;
    const cases = index === 0 ? 16 : 24;
    assert.equal(corpus.recordings.length, 2);
    assert.equal(corpus.agree, true);
    assert.equal(corpus.recipes.length, steps);
    assert.equal(new Set(corpus.recipes.map(({ id }) => id)).size, steps);
    assert.equal(Object.keys(corpus.semantics.steps).length, steps);
    assert.deepEqual(
      new Set(Object.keys(corpus.semantics.steps)),
      new Set(corpus.recipes.map(({ id }) => id)),
    );
    assert.equal(corpus.recipes.filter(({ caseId }) => caseId).length, cases);
    for (const recording of corpus.recordings) {
      assert.equal(recording.complete, true);
      assert.equal(recording.graphComplete, true);
      assert.equal(recording.cleanupAbsent, true);
      assert.equal(recording.openTokens, 0);
      assert.equal(recording.unknownOutcomes, 0);
      assert.match(recording.sha256, /^[a-f0-9]{64}$/);
      assert.equal(recording.requests, index === 0 ? 47 : 53);
    }
    const result = compared.corpora[index];
    assert.equal(result.program, corpus.program);
    assert.deepEqual(
      result.results.map(({ profile, recording }) => `${profile}/${recording}`),
      ["strict/1", "strict/2", "emulator/1", "emulator/2"],
    );
    for (const replay of result.results) {
      assert.equal(replay.complete, true);
      assert.equal(replay.allSteps.length, steps);
      assert.deepEqual(
        new Set(replay.allSteps.map(({ site }) => site)),
        new Set(corpus.recipes.map(({ id }) => id)),
      );
      for (const row of replay.allSteps)
        assert.deepEqual(row.production, corpus.semantics.steps[row.site]);
      const mismatchCount =
        [...replay.allSteps, ...replay.cases, ...replay.reads, ...replay.commitTimes].filter(
          ({ match }) => !match,
        ).length + (replay.cleanupMatch ? 0 : 1);
      assert.equal(replay.mismatches, mismatchCount);
      assert.equal(replay.runtimeInputsValidated, true);
      assert.equal(replay.childStopped, true);
      assert.equal(replay.sourceCommit, compared.artifact.sourceCommit);
      assert.equal(replay.binarySha256, compared.artifact.binarySha256);
      assert.equal(replay.runtime.nodeVersion, "v24.14.0");
      assert.equal(replay.runtime.pythonVersion, "3.12.13");
      assert.equal(replay.runtime.workerSha256, compared.producer.transportWorkerSha256);
      for (const key of ["nodeSha256", "pythonSha256", "workerSha256", "lockSha256"])
        assert.match(replay.runtime[key], /^[a-f0-9]{64}$/);
      if (replay.profile === "strict") assert.equal(replay.mismatches, 0);
    }
  }
  assert.ok(
    compared.corpora[1].results
      .filter(({ profile }) => profile === "emulator")
      .every(({ mismatches }) => mismatches > 0),
  );
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-TRANSACTION/read-only-snapshot",
  );
  assert.notEqual(condition.status, "VERIFIED");
  assert.equal(condition.partialEvidence.coverage, "PARTIAL");
  assert.equal(condition.partialEvidence.recordingsPerCorpus, 2);
  assert.equal(
    condition.partialEvidence.reference,
    "spec/compatibility/broad-runs/fs-transaction-p02-recorded-comparison-v1.json",
  );
  assert.equal(closure.conditions.length, 18);
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.closureReview.decision, "PENDING");
});
