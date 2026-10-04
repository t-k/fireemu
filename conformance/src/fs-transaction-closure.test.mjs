import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

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
  ["FS-TRANSACTION/read-set-conflict", ["P05"]],
  ["FS-TRANSACTION/failed-commit-and-rollback", ["P08", "P09"]],
  ["FS-TRANSACTION/retry-token-lifecycle", ["P09", "P13B"]],
  ["FS-TRANSACTION/idle-expiry", ["P10-A", "P10-B", "P10-C", "P13A"]],
  ["FS-TRANSACTION/total-lifetime-expiry", ["P11", "P12", "P13A"]],
]);

test("FS-TRANSACTION published records verify eight conditions and not the parent", () => {
  const closure = JSON.parse(readFileSync(closureUrl, "utf8"));
  const root = new URL("../../", import.meta.url);
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
      program.replace(/^FS-TRANSACTION-/, "").split("-").slice(0, program.includes("P10-") ? 2 : 1).join("-"),
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
      assert.equal(observations.corpora[0].agree, true);
      assert.match(comparison.artifact.sourceCommit, /^[0-9a-f]{40}$/);
      assert.match(comparison.artifact.binarySha256, /^[0-9a-f]{64}$/);
      assert.ok(existsSync(new URL(entry.comparisonPath, root)));
    }
    if (["FS-TRANSACTION/idle-expiry", "FS-TRANSACTION/total-lifetime-expiry"].includes(condition.conditionId))
      assert.match(recorded.boundaryRuling, /110\.70, 122\.96.*298\.7, 302\.2/);
    // the evidence block names the recordings, the one artifact and exactly the records above
    const { evidence } = condition;
    assert.deepEqual(
      evidence.productionRecordings.map(({ program }) => program),
      recorded.programs.map(({ program }) => program),
    );
    for (const run of evidence.productionRecordings) {
      assert.equal(run.recordings, 2, run.program);
      assert.match(run.project, /^fireemu-oracle-(sbx|txn)$/, run.program);
    }
    assert.deepEqual(evidence.comparisonPaths, recorded.programs.map(({ comparisonPath }) => comparisonPath));
    assert.deepEqual(evidence.rows, { MATCH: recorded.programs.reduce((sum, { rows }) => sum + rows, 0) });
    assert.match(evidence.finalArtifactSha256, /^[0-9a-f]{64}$/);
    assert.match(evidence.sourceCommit, /^[0-9a-f]{40}$/);
    for (const entry of recorded.programs) {
      const { artifact } = JSON.parse(readFileSync(new URL(entry.comparisonPath, root), "utf8"));
      assert.equal(artifact.binarySha256, evidence.finalArtifactSha256, entry.program);
      assert.equal(artifact.sourceCommit, evidence.sourceCommit, entry.program);
    }
    assert.match(condition.note, /not COMPAT_VERIFIED/);
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

test("FS-TRANSACTION recorded REST subset leaves the other frozen conditions open", () => {
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
    assert.equal(condition.status === "VERIFIED", recordedConditions.has(condition.conditionId), condition.conditionId);
    if (partial.has(condition.conditionId)) {
      assert.equal(condition.status, "VERIFIED");
      assert.equal(condition.partialEvidence.coverage, "PARTIAL");
      assert.equal(condition.partialEvidence.reference, reference);
      assert.equal(condition.partialEvidence.transport, "rest");
      assert.equal(condition.partialEvidence.recordings, 2);
      assert.equal(condition.partialEvidence.caseIds.length, partial.get(condition.conditionId));
      assert.ok(condition.partialEvidence.remainingBoundaries.length);
      observed.push(...condition.partialEvidence.caseIds);
    } else if (recordedConditions.has(condition.conditionId)) {
      assert.equal(condition.productionObservation, "RECORDED_TWICE_STRICT_COMPARED");
    } else {
      assert.equal(condition.productionObservation, "UNOBSERVED_BY_RECORDED_CORPUS");
    }
  }
  assert.equal(observed.length, 13);
  assert.equal(new Set(observed).size, 13);
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.closureReview.decision, "PENDING");
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
  const stale = /remains open|remain required|no status change|gRPC is not recorded|until local shadow v5/i;
  for (const condition of closure.conditions.filter(({ status }) => status === "VERIFIED")) {
    assert.doesNotMatch(condition.note, stale, condition.conditionId);
    for (const item of condition.partialEvidence?.remainingBoundaries ?? [])
      assert.doesNotMatch(item, stale, condition.conditionId);
  }
});

test("FS-TRANSACTION E04 rows of the verified conditions are replayed on the release binary at the recorded idle", () => {
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
    const { releaseReplay } = condition.partialEvidence;
    assert.deepEqual(condition.evidence.e04ReleaseReplay, releaseReplay, id);
    const record = JSON.parse(readFileSync(new URL(releaseReplay.path, root), "utf8"));
    assert.equal(record.kind, "fs-transaction-expiry-retry-04-release-replay-v1");
    assert.equal(record.artifact.binarySha256, condition.evidence.finalArtifactSha256, id);
    assert.equal(record.artifact.sourceCommit, condition.evidence.sourceCommit, id);
    assert.equal(record.summary.mismatches, 0);
    const rows = record.recordings.flatMap((entry) => entry.rows).filter((row) => row.caseId.startsWith(prefix));
    assert.equal(releaseReplay.rows.MATCH, rows.length, id);
    assert.ok(rows.every((row) => row.match), id);
    for (const caseId of condition.partialEvidence.caseIds) {
      assert.ok(rows.some((row) => row.caseId === caseId), `${id}: ${caseId} is replayed`);
      assert.ok(rows.some((row) => row.caseId === `${caseId}#postState`), `${id}: ${caseId} post state is replayed`);
    }
  }
  // the idle observations ran at the idle production measured, inside the interval it narrowed
  const record = JSON.parse(
    readFileSync(new URL("spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-release-replay-v1.json", root), "utf8"),
  );
  assert.equal(record.replay.idleCases.length, 3);
  const idles = Object.values(record.replay.localIdleSeconds);
  assert.ok(idles.length >= 3 && idles.every((idle) => idle >= 110.7 && idle < 122.96 || idle === 20));
});
