import { assertCurrentParentEvidence, loadRepository } from "./production-closure.mjs";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { createHash } from "node:crypto";

const root = new URL("../../", import.meta.url);
const admission = assertCurrentParentEvidence(loadRepository(root), "FS-TRANSACTION");

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

test("FS-TRANSACTION recorded REST subset keeps its original partial boundary", () => {
  const closure = JSON.parse(
    readFileSync(
      new URL(
        "../../spec/compatibility/official-compatibility/history/e57a78e0/FS-TRANSACTION.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
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
  assert.equal(closure.parentStatus === "COMPAT_VERIFIED", admission.eligible);
  assert.equal(closure.productionPlan.preparedCampaign.authorizesProduction, false);
  assert.deepEqual(closure.productionPlan.preparedCampaign.actualRequestsPerRecording, [75, 75]);
});

function p13bDigest(value) {
  const canonical = (item) => {
    if (Array.isArray(item)) return item.map(canonical);
    if (item !== null && typeof item === "object")
      return Object.fromEntries(
        Object.keys(item)
          .toSorted()
          .map((key) => [key, canonical(item[key])]),
      );
    return item;
  };
  return createHash("sha256")
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
}

function assertP13bPreparation(observed, compared, closure) {
  for (const record of [observed, compared]) {
    assert.equal(record.coverage, "PARTIAL");
    assert.equal(record.authorizesProduction, false);
    assert.equal(record.promotionReady, false);
    assert.match(record.remainingBoundaries.join(" "), /bodyBytes.*content-length.*member-order/);
    assert.match(record.remainingBoundaries.join(" "), /18.*conditions/);
  }
  assert.equal(observed.decodedSemanticsValidated, true);
  assert.equal(observed.rawRestWireLayoutValidated, false);
  assert.equal(observed.corpora.length, 1);
  const corpus = observed.corpora[0];
  assert.equal(corpus.program, "FS-TRANSACTION-P13B-RETRY-ANSWERS");
  assert.equal(corpus.sourceCommit, "2991d2f1e055407badaaac2e9edab688d42c9d1a");
  assert.equal(
    corpus.tableSourceDigest,
    "6716e049745af5532b837e7c9c06c199f92c8f253c2cb7341dbf7b4a299ce468",
  );
  assert.equal(
    corpus.corpusDigest,
    "3c91e4695ace7cccb5089f3c8fc88425f1393ee40a13c28f97bf15ac05a63751",
  );
  assert.equal(
    corpus.freezeSha256,
    "9c7ff93d46ebecdf6f4e312bee443de1eea57b666499599879f7c4b96983f132",
  );
  assert.equal(
    corpus.packetSha256,
    "c3274163a581342d288a0a9c1448f724258f72f106e9506c8758ec79c1526dc7",
  );
  assert.equal(
    corpus.originalRunnerSha256,
    "7211a1ab2296db4e0712399a17b4ab26fad2beb953b44135475f58513921ec35",
  );
  assert.equal(corpus.historicalInstalledRuntimeInputsValidated, "UNKNOWN");
  const sites = ["setup/absence-a", "setup/create-a"];
  for (const [chain, names] of [
    ["rt1", ["begin", "read-a", "rollback", "retry-begin", "writer", "first-read", "commit"]],
    ["rt2", ["begin", "read-a", "retry-idle"]],
    ["rt3", ["begin", "read-a", "rollback-idle", "retry-after-rollback"]],
    [
      "rt4",
      [
        "begin",
        "read-a",
        ...Array.from({ length: 9 }, (_, index) => `keepalive-${index + 1}`),
        "live-read",
        "retry-lifetime",
      ],
    ],
  ])
    sites.push(...names.map((name) => `rest/${chain}/${name}`));
  sites.push("final/post-read-a");
  assert.deepEqual(
    corpus.recipes.map(({ id }) => id),
    sites,
  );
  assert.equal(new Set(sites).size, 30);
  assert.deepEqual(Object.keys(corpus.semantics.steps), sites);
  for (const recipe of corpus.recipes) {
    const row = corpus.semantics.steps[recipe.id];
    assert.equal(row.transport, recipe.transport);
    assert.equal(row.rpc, recipe.rpc);
    assert.equal(row.caseId, recipe.caseId);
    if (recipe.transport === "rest") {
      assert.equal(row.code, 0);
      assert.equal(row.http, 200);
      assert.equal(row.details, "");
    }
  }
  const cases = [
    "rest/rt1-rollback",
    "rest/rt1-writer",
    "rest/rt1-first-read",
    "rest/rt1-commit",
    "rest/rt2-retry-idle",
    "rest/rt3-rollback-idle",
    "rest/rt3-retry-after-rollback",
    "rest/rt4-retry-lifetime",
  ];
  assert.deepEqual(
    corpus.projection.cases.map(({ caseId }) => caseId),
    cases,
  );
  for (const row of corpus.projection.cases) {
    assert.equal(row.transport, "rest");
    assert.equal(row.code, 0);
    assert.equal(row.details, "");
  }
  assert.equal(corpus.projection.reads.length, 17);
  assert.equal(corpus.agree, true);
  assert.equal(corpus.recordings.length, 2);
  assert.deepEqual(
    corpus.recordings.map(({ sha256 }) => sha256),
    [
      "0c3d167857686716f8d2ecb0b65e37cd82e3fab04676e8c8ebe0c2fc2b5d22d5",
      "1621e5c5822245d65da750d139d879c6c07a1d41e187790341ff5232de6be8cd",
    ],
  );
  for (const [index, recording] of corpus.recordings.entries()) {
    assert.equal(recording.recording, index + 1);
    assert.equal(recording.complete, true);
    assert.equal(recording.graphComplete, true);
    assert.equal(recording.cleanupAbsent, true);
    assert.equal(recording.openTokens, 0);
    assert.equal(recording.unknownOutcomes, 0);
    assert.equal(recording.requests, 45);
    assert.deepEqual(recording.phaseRequests, {
      credential: 1,
      documentCleanup: 3,
      management: 6,
      observation: 30,
      tokenCleanup: 5,
    });
    assert.deepEqual(recording.transportObservations, { rest: 8 });
    assert.equal(recording.semanticDigest, p13bDigest(corpus.semantics));
    assert.equal(recording.projectionDigest, p13bDigest(corpus.projection));
    assert.equal(recording.issuedTokensDistinct, true);
    assert.equal(recording.nativeLifecycle.length, 38);
    assert.deepEqual(
      recording.nativeLifecycle.map(({ sequence }) => sequence),
      Array.from({ length: 38 }, (_, n) => n),
    );
    assert.deepEqual(
      new Set(recording.nativeLifecycle.map(({ site }) => site)),
      new Set([...sites, ...Object.keys(corpus.semantics.cleanupSteps)]),
    );
    for (const row of recording.nativeLifecycle) {
      assert.equal(row.complete, true);
      assert.equal(row.ipcComplete, true);
      assert.equal(row.childReaped, true);
      assert.equal(row.workerExitCode, 0);
      assert.equal(row.dispatchedRequests, 1);
    }
    const waits = new Map(recording.waits.map((entry) => [entry.site, entry]));
    assert.equal(waits.size, 13);
    assert.equal(recording.waitsDigest, p13bDigest(recording.waits));
    for (const site of ["rest/rt2/retry-idle", "rest/rt3/rollback-idle"]) {
      assert.ok(waits.get(site).idleInterval.lowerSeconds >= 130);
      assert.ok(waits.get(site).totalAgeInterval.upperSeconds < 270);
    }
    assert.ok(waits.get("rest/rt4/retry-lifetime").totalAgeInterval.lowerSeconds > 275);
    assert.ok(waits.get("rest/rt4/retry-lifetime").idleInterval.upperSeconds < 120);
    assert.equal(recording.recordedRuntime.nodeVersion, "v24.14.0");
    assert.equal(recording.recordedRuntime.pythonVersion, "3.12.13");
    assert.equal(
      recording.recordedRuntime.workerSha256,
      "4047804796a8a7dd4319c70f6bbe8aa3c38873ef57047761e6a1f5629b1dfea5",
    );
    assert.equal(
      recording.recordedRuntime.lockSha256,
      "04f7f2526af7ce07ca39ceffd0712eec9b5e5e212503c7cb791ab5021a49dc60",
    );
  }
  const retrySites = [
    "rest/rt1/retry-begin",
    "rest/rt2/retry-idle",
    "rest/rt3/retry-after-rollback",
    "rest/rt4/retry-lifetime",
  ];
  for (const [index, site] of retrySites.entries()) {
    const recipe = corpus.recipes.find(({ id }) => id === site);
    assert.equal(recipe.retryOf, `t${index + 1}`);
    assert.equal(recipe.tokenOutput, `t${index + 1}r`);
    assert.deepEqual(corpus.retryConsequences[index], {
      site,
      namedToken: recipe.retryOf,
      issuedToken: recipe.tokenOutput,
      issuedDifferent: true,
    });
  }
  const steps = corpus.semantics.steps;
  assert.equal(steps["rest/rt1/first-read"].read.state, "rest-rt1-writer");
  assert.equal(
    steps["rest/rt1/first-read"].versions["/updateTime"].rank,
    steps["rest/rt1/writer"].versions["/writeResults/0/updateTime"].rank,
  );
  assert.equal(steps["final/post-read-a"].read.state, "rest-rt1-commit");
  assert.equal(
    steps["final/post-read-a"].versions["/updateTime"].rank,
    steps["rest/rt1/commit"].versions["/writeResults/0/updateTime"].rank,
  );
  assert.equal(corpus.projection.expectedStates.a, "rest-rt1-commit");
  assert.equal(corpus.semantics.tokens.t1r.state, "committed");
  assert.equal(corpus.semantics.tokens.t4.state, "released-refused");
  assert.deepEqual(Object.keys(corpus.semantics.cleanupSteps), [
    "cleanup/token/t2",
    "cleanup/token/t2r",
    "cleanup/token/t3r",
    "cleanup/token/t4",
    "cleanup/token/t4r",
    "cleanup/read/a",
    "cleanup/delete/a",
    "cleanup/verify/a",
  ]);
  assert.equal(corpus.semantics.cleanupSteps["cleanup/token/t4"].code, 10);
  assert.equal(corpus.semantics.cleanupSteps["cleanup/token/t4"].http, 409);
  assert.equal(
    corpus.semantics.cleanupSteps["cleanup/token/t4"].details,
    "The referenced transaction has expired or is no longer valid.",
  );
  assert.equal(corpus.semantics.cleanupSteps["cleanup/token/t4r"].code, 0);
  assert.equal(corpus.semantics.cleanupSteps["cleanup/verify/a"].code, 5);
  assert.deepEqual(corpus.semantics.cleanup, { absent: true });
  assert.equal(compared.status, "PENDING_FINAL_ARTIFACT_REPLAY");
  assert.equal(compared.artifact, null);
  assert.equal(compared.productionRequests, 0);
  assert.equal(compared.capturedReplays, 0);
  assert.equal(compared.requiredReplays, 4);
  assert.deepEqual(compared.corpora, [{ program: corpus.program, results: [] }]);
  assert.deepEqual(
    compared.plannedReplays.map(({ profile, recording }) => `${profile}/${recording}`),
    ["strict/1", "strict/2", "emulator/1", "emulator/2"],
  );
  for (const replay of compared.plannedReplays)
    assert.equal(replay.productionFileSha256, corpus.recordings[replay.recording - 1].sha256);
  assert.equal(
    compared.producer.sha256,
    createHash("sha256")
      .update(readFileSync(new URL(`../../${compared.producer.path}`, import.meta.url)))
      .digest("hex"),
  );
  assert.equal(compared.producer.tableSha256, corpus.tableSourceDigest);
  assert.equal(compared.producer.tableSourceCommit, corpus.sourceCommit);
  assert.equal(
    compared.producer.currentTableSha256,
    createHash("sha256")
      .update(readFileSync(new URL(`../../${corpus.table}`, import.meta.url)))
      .digest("hex"),
  );
  assert.notEqual(compared.producer.currentTableSha256, corpus.tableSourceDigest);
  const retry = closure.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/retry-token-lifecycle"),
  );
  assert.equal(retry.partialEvidence.caseIds.length, 5);
  assert.equal(
    retry.partialEvidence.reference,
    "spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-recorded-comparison-v1.json",
  );
  const subset = retry.partialEvidence.additionalRecordedSubsets.find(({ observations }) =>
    observations.endsWith("p13b-recorded-observations-v1.json"),
  );
  assert.equal(subset.coverage, "PARTIAL");
  assert.equal(subset.transport, "rest");
  assert.equal(subset.rawRestWireLayoutValidated, false);
  assert.equal(subset.localComparisonStatus, compared.status);
  assert.deepEqual(subset.caseIds, cases);
  assert.match(retry.note, /P13b.*first read.*writer/);
  assert.match(closure.note, /P13b.*decoded/);
  assert.match(closure.oracle.coverage, /P13B/);
  assert.equal(closure.conditions.length, 18);
}

test("P13b saved retry observations publish source-bound partial proof with a pending comparison", () => {
  const base = new URL("../../spec/compatibility/broad-runs/", import.meta.url);
  const observedUrl = new URL("fs-transaction-p13b-recorded-observations-v1.json", base);
  const comparedUrl = new URL("fs-transaction-p13b-recorded-comparison-v1.json", base);
  assert.ok(existsSync(observedUrl), "P13b decoded observations must be published");
  assert.ok(existsSync(comparedUrl), "P13b comparison preparation must be published");
  assertP13bPreparation(
    JSON.parse(readFileSync(observedUrl)),
    JSON.parse(readFileSync(comparedUrl)),
    JSON.parse(readFileSync(closureUrl)),
  );
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
  assert.equal(closure.parentStatus === "COMPAT_VERIFIED", admission.eligible);
  assert.equal(closure.parentStatus === "COMPAT_VERIFIED", admission.eligible);
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

test("P08 retained refusal chains preserve decoded partial evidence and normal runtime-wave comparisons", () => {
  const base = new URL("../../spec/compatibility/broad-runs/", import.meta.url);
  const observed = JSON.parse(
    readFileSync(new URL("fs-transaction-p08-recorded-observations-v1.json", base), "utf8"),
  );
  const compared = JSON.parse(
    readFileSync(new URL("fs-transaction-p08-recorded-comparison-v1.json", base), "utf8"),
  );
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  for (const record of [observed, compared]) {
    assert.equal(record.coverage, "PARTIAL");
    assert.equal(record.authorizesProduction, false);
    assert.equal(record.promotionReady, false);
  }
  assert.equal(observed.decodedSemanticsValidated, true);
  assert.equal(observed.rawRestWireLayoutValidated, false);
  assert.equal(observed.postRefusalMissingDocumentReadValidated, false);
  assert.equal(observed.corpora.length, 1);
  const corpus = observed.corpora[0];
  assert.equal(corpus.program, "FS-TRANSACTION-P08-FAILED-COMMIT");
  assert.equal(corpus.sourceCommit, "181b00247bfc2456c687c45ab213d5050d069791");
  assert.equal(
    corpus.tableSourceDigest,
    "7379ce5f1a9fd23d1d54dcfdef2e8705b315d72fe95547d105894d3d5f7004c5",
  );
  assert.equal(
    corpus.corpusDigest,
    "1dc1d44eca4b99a23d8f3b480eb9b8d71aec4ef0894509b149fa12354c9d92bc",
  );
  assert.equal(
    corpus.freezeSha256,
    "31d7df5ad3a8c5e4b539f86944b034768deb2ed2f6e8d15c8a09bfa750d6540b",
  );
  assert.equal(
    corpus.packetSha256,
    "83f7d3f8cf3fb74d5260da1bdc6c1194add8e9f0837530850592f16779a5fec7",
  );
  const sites = ["setup/absence-a", "setup/absence-m", "setup/create-a"];
  const cases = new Map();
  for (const transport of ["rest", "grpc"]) {
    for (const [chain, names] of [
      [
        "a",
        [
          "begin",
          "read-a",
          "fail-commit",
          "plain-read-a",
          "same-token-read-a",
          "writer",
          "corrected-commit",
          "rollback",
          "rollback-again",
          "post-read-a",
        ],
      ],
      [
        "b",
        ["begin", "read-a", "fail-commit", "rollback", "writer", "rollback-again", "post-read-a"],
      ],
      ["c", ["begin", "read-a", "commit", "rollback-after-commit"]],
    ])
      sites.push(...names.map((name) => `${transport}/${chain}/${name}`));
    for (const [chain, name, code] of [
      ["a", "fail-commit", 5],
      ["a", "plain-read", 0],
      ["a", "same-token-read", 3],
      ["a", "writer", 0],
      ["a", "corrected-commit", 3],
      ["a", "rollback", 0],
      ["a", "rollback-again", 0],
      ["b", "fail-commit", 5],
      ["b", "rollback", 0],
      ["b", "writer", 0],
      ["b", "rollback-again", 0],
      ["c", "commit", 0],
      ["c", "rollback-after-commit", 10],
    ])
      cases.set(`${transport}/${chain}-${name}`, code);
  }
  assert.deepEqual(
    corpus.recipes.map(({ id }) => id),
    sites,
  );
  assert.equal(new Set(corpus.recipes.map(({ id }) => id)).size, 45);
  assert.deepEqual(new Set(Object.keys(corpus.semantics.steps)), new Set(sites));
  assert.equal(corpus.recipes.filter(({ caseId }) => caseId).length, 26);
  assert.equal(corpus.projection.cases.length, 26);
  assert.deepEqual(
    new Map(corpus.projection.cases.map(({ caseId, code }) => [caseId, code])),
    cases,
  );
  assert.equal(corpus.projection.reads.length, 16);
  assert.equal(corpus.agree, true);
  const canonical = (value) => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value !== null && typeof value === "object")
      return Object.fromEntries(
        Object.keys(value)
          .toSorted()
          .map((key) => [key, canonical(value[key])]),
      );
    return value;
  };
  const digest = (value) =>
    createHash("sha256")
      .update(JSON.stringify(canonical(value)))
      .digest("hex");
  assert.equal(digest(corpus.semantics), corpus.recordings[0].semanticDigest);
  assert.equal(digest(corpus.projection), corpus.recordings[0].projectionDigest);
  assert.deepEqual(corpus.semantics.cleanup, { absent: true });
  const tokens = {};
  for (const transport of ["rest", "grpc"])
    for (const chain of ["a", "b", "c"])
      tokens[`${transport}-${chain}`] = {
        transport,
        state: chain === "c" ? "committed" : "rolled-back",
      };
  assert.deepEqual(corpus.semantics.tokens, tokens);
  assert.deepEqual(Object.keys(corpus.semantics.commitTimes), [
    "setup/create-a",
    "rest/a/writer",
    "rest/b/writer",
    "rest/c/commit",
    "grpc/a/writer",
    "grpc/b/writer",
    "grpc/c/commit",
  ]);
  for (const entry of Object.values(corpus.semantics.commitTimes))
    assert.deepEqual(entry, { commitTime: true, relation: null });
  assert.deepEqual(
    corpus.recordings.map(({ recording, sha256 }) => [recording, sha256]),
    [
      [1, "c9d1dc8f081c1f18f9fc7872729b7f21a6c79e95c83938425ff9112c9de99214"],
      [2, "40fe3fe74e6dd11c98fe1a1950f8ec46ebab9b29c703d67530a105196b576bf6"],
    ],
  );
  for (const recording of corpus.recordings) {
    assert.equal(recording.complete, true);
    assert.equal(recording.graphComplete, true);
    assert.equal(recording.cleanupAbsent, true);
    assert.equal(recording.openTokens, 0);
    assert.equal(recording.unknownOutcomes, 0);
    assert.equal(recording.requests, 56);
    assert.deepEqual(recording.transportObservations, { rest: 13, grpc: 13 });
    assert.deepEqual(recording.phaseRequests, {
      credential: 1,
      documentCleanup: 3,
      management: 7,
      observation: 45,
      tokenCleanup: 0,
    });
    assert.match(recording.semanticDigest, /^[a-f0-9]{64}$/);
    assert.equal(recording.semanticDigest, corpus.recordings[0].semanticDigest);
  }
  for (const transport of ["rest", "grpc"]) {
    const semantic = corpus.semantics.steps;
    assert.equal(
      semantic[`${transport}/a/fail-commit`].details,
      "No document to update: projects/<project>/databases/(default)/documents/oracle/<nonce>/txn-p08/m",
    );
    for (const site of ["same-token-read-a", "corrected-commit"])
      assert.equal(
        semantic[`${transport}/a/${site}`].details,
        "The referenced transaction has expired or is no longer valid.",
      );
    assert.equal(semantic[`${transport}/a/fail-commit`].code, 5);
    assert.equal(semantic[`${transport}/a/same-token-read-a`].code, 3);
    assert.equal(semantic[`${transport}/a/corrected-commit`].code, 3);
    assert.deepEqual(
      semantic[`${transport}/a/plain-read-a`].versions,
      semantic[`${transport}/a/read-a`].versions,
    );
    assert.equal(semantic[`${transport}/a/post-read-a`].read.state, `${transport}-a-writer`);
    assert.equal(semantic[`${transport}/b/post-read-a`].read.state, `${transport}-b-writer`);
    assert.equal(semantic[`${transport}/c/rollback-after-commit`].code, 10);
  }
  assert.equal(corpus.semantics.steps["rest/a/fail-commit"].http, 404);
  assert.deepEqual(Object.keys(corpus.semantics.cleanupSteps), [
    "cleanup/read/a",
    "cleanup/delete/a",
    "cleanup/verify/a",
  ]);
  assert.equal(corpus.semantics.cleanupSteps["cleanup/read/a"].read, null);
  assert.equal(corpus.semantics.cleanupSteps["cleanup/verify/a"].code, 5);
  assert.equal(corpus.projection.expectedStates.a, "grpc-c-commit");
  assert.equal(corpus.semantics.steps["setup/absence-m"].code, 5);
  assert.match(observed.remainingBoundaries.join(" "), /bodyBytes.*content-length.*member-order/);
  assert.match(observed.remainingBoundaries.join(" "), /post-refusal.*missing document/);
  assert.equal(compared.status, "RECORDED_NORMAL_RUNTIME_WAVE_PARTIAL");
  assert.equal(compared.artifact.sourceCommit, "3df108a312fdf2bdd6d059bd7fa2e5e904254f02");
  assert.equal(compared.artifact.sourceTree, "2b2a4dc9c1790bdd9001666fde5a07270b44299d");
  assert.equal(
    compared.artifact.binarySha256,
    "3334b797dab43668e3a3ddf185625967c3b1aa0175bf4ce2f3a5fb7836b68edf",
  );
  assert.equal(
    compared.artifact.role,
    "NORMAL_RUNTIME_VALIDATION_WAVE_NOT_FINAL_ALLPARENTS_SOURCE",
  );
  assert.equal(compared.artifact.finalWholeTreeSourceBound, false);
  assert.equal(compared.artifact.inputCount, 3700);
  assert.equal(
    compared.artifact.runtimeProofSha256,
    "647c8dff1c720e19643e7c417b806580ced95f317175155a7076b0e36188fa0f",
  );
  assert.equal(
    compared.artifact.runtimeInputReceiptSha256,
    "fb453b9246bb52870ff043fe506ff8f149d8839700a4a7484749481fb9e603c8",
  );
  assert.equal(
    compared.artifact.sourceInputBaselineSha256,
    "36f71b09a28c45f43a41b56b4693ddcc0ba74ec7e99c9d246aabb9c024f8a938",
  );
  assert.equal(compared.artifact.runnerFiles, 14);

  assert.equal(compared.productionRequests, 0);
  assert.equal(compared.capturedReplays, 4);
  assert.equal(compared.requiredReplays, 4);
  assert.equal(compared.corpora.length, 1);
  assert.equal(compared.corpora[0].program, corpus.program);
  assert.equal(compared.corpora[0].results.length, 4);
  const cells = ["strict/1", "strict/2", "emulator/1", "emulator/2"];
  assert.deepEqual(
    compared.plannedReplays.map(({ profile, recording }) => `${profile}/${recording}`),
    cells,
  );
  assert.deepEqual(
    compared.corpora[0].results.map(({ profile, recording }) => `${profile}/${recording}`),
    cells,
  );
  for (const replay of compared.plannedReplays)
    assert.equal(replay.productionFileSha256, corpus.recordings[replay.recording - 1].sha256);
  for (const replay of compared.corpora[0].results) {
    assert.equal(replay.complete, true);
    assert.equal(replay.failure, null);
    assert.equal(replay.exitCode, 0);
    assert.equal(replay.runtimeInputsValidated, true);
    assert.equal(replay.childStopped, true);
    assert.equal(replay.cleanupAbsent, true);
    assert.equal(replay.sourceCommit, compared.artifact.sourceCommit);
    assert.equal(replay.binarySha256, compared.artifact.binarySha256);
    assert.equal(replay.productionFileSha256, corpus.recordings[replay.recording - 1].sha256);
    assert.equal(replay.allSteps.length, 45);
    assert.deepEqual(
      replay.allSteps.map(({ site }) => site),
      sites,
    );
    for (const row of replay.allSteps)
      assert.deepEqual(row.production, corpus.semantics.steps[row.site]);
    for (const row of [
      ...replay.allSteps,
      ...replay.cases,
      ...replay.reads,
      ...replay.commitTimes,
    ]) {
      assert.ok(Object.hasOwn(row, "production"));
      assert.ok(Object.hasOwn(row, "local"));
      assert.equal(row.match, digest(row.production) === digest(row.local));
    }
    assert.deepEqual(new Set(replay.cases.map(({ caseId }) => caseId)), new Set(cases.keys()));
    assert.deepEqual(
      new Set(replay.commitTimes.map(({ site }) => site)),
      new Set(Object.keys(corpus.semantics.commitTimes)),
    );

    const differences =
      [...replay.allSteps, ...replay.cases, ...replay.reads, ...replay.commitTimes].filter(
        ({ match }) => !match,
      ).length + (replay.cleanupMatch ? 0 : 1);
    assert.equal(replay.mismatches, differences);
    assert.equal(replay.mismatches, replay.profile === "strict" ? 0 : 10);
    assert.equal(replay.runtime.nodeVersion, "v24.14.0");
    assert.equal(replay.runtime.pythonVersion, "3.12.13");
    assert.equal(replay.runtime.dependencyRoots, 114);
    assert.equal(replay.runtime.dependencyFiles, 3396);
    assert.equal(
      replay.runtime.nodeSha256,
      "20a18709f0154d668f1bd6f6ea8c2a7ae001447b4b2c339732f22e57a8767a55",
    );
    assert.equal(
      replay.runtime.pythonSha256,
      "f8cf5db64fd3715840686fcdb0f00b8b7e6c9b1e9b5f10a31183160c9bb6a6fc",
    );
    assert.equal(
      replay.runtime.workerSha256,
      createHash("sha256")
        .update(
          readFileSync(
            new URL(
              "../../tools/compat-broad/fs-write-txn/txn_program_transport.mjs",
              import.meta.url,
            ),
          ),
        )
        .digest("hex"),
    );
    assert.equal(
      replay.runtime.lockSha256,
      createHash("sha256")
        .update(readFileSync(new URL("../pnpm-lock.yaml", import.meta.url)))
        .digest("hex"),
    );

    for (const key of ["nodeSha256", "pythonSha256", "workerSha256", "lockSha256"])
      assert.match(replay.runtime[key], /^[a-f0-9]{64}$/);
    for (const key of ["comparisonSha256", "localReceiptSha256", "captureSha256"])
      assert.match(replay[key], /^[a-f0-9]{64}$/);
  }
  assert.match(compared.remainingBoundaries.join(" "), /final whole-tree/);
  assert.equal(
    compared.producer.sha256,
    createHash("sha256")
      .update(readFileSync(new URL(`../../${compared.producer.path}`, import.meta.url)))
      .digest("hex"),
  );
  assert.equal(compared.producer.tableSha256, corpus.tableSourceDigest);
  assert.equal(
    corpus.tableSourceDigest,
    createHash("sha256")
      .update(readFileSync(new URL(`../../${corpus.table}`, import.meta.url)))
      .digest("hex"),
  );
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-TRANSACTION/failed-commit-and-rollback",
  );
  assert.equal(condition.status, "PRODUCTION_RECORDED");
  assert.equal(condition.partialEvidence.caseIds.length, 3);
  assert.equal(condition.partialEvidence.transport, "rest");
  assert.equal(
    condition.partialEvidence.reference,
    "spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-recorded-comparison-v1.json",
  );
  assert.equal(condition.partialEvidence.additionalRecordedSubsets.length, 1);
  const subset = condition.partialEvidence.additionalRecordedSubsets[0];
  assert.equal(subset.coverage, "PARTIAL");
  assert.equal(
    subset.observations,
    "spec/compatibility/broad-runs/fs-transaction-p08-recorded-observations-v1.json",
  );
  assert.equal(
    subset.comparison,
    "spec/compatibility/broad-runs/fs-transaction-p08-recorded-comparison-v1.json",
  );
  assert.equal(subset.localComparisonStatus, compared.status);
  assert.equal(subset.rawRestWireLayoutValidated, false);
  assert.equal(subset.postRefusalMissingDocumentReadValidated, false);
  assert.match(closure.note, /P08.*decoded/);
  assert.match(closure.oracle.coverage, /P08/);
  assert.equal(closure.conditions.length, 18);
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.closureReview.decision, "PENDING");
});

test("FS-TRANSACTION rejects an actual current inventory byte mismatch", () => {
  const value = loadRepository(root);
  value.registry.parents.find((p) => p.parent === "FS-TRANSACTION").currentBinding.inventorySha256 =
    "0".repeat(64);
  assert.throws(
    () => assertCurrentParentEvidence(value, "FS-TRANSACTION"),
    /current inventory bytes differ/,
  );
});
