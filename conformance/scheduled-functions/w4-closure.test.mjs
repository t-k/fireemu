import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const closure = JSON.parse(
  readFileSync(
    new URL("../../spec/compatibility/closure/SCHEDULED-FUNCTIONS.json", import.meta.url),
  ),
);
const ruling =
  "docs.local/runs/sched-lane/coordinator-rulings.md#2026-10-06-0710z-rulings-on-the-closure-proposal-section-3-a0-owner-ledger-922-coordinator-approval-plus-the-opus-closure-review";

test("W4 preserves the frozen inventory and binds reviewed final artifact evidence to the promoted parent", () => {
  const frozen = closure.conditions
    .map(({ conditionId, evidenceType, recipeIds, cases }) => [
      conditionId,
      evidenceType,
      recipeIds,
      cases,
    ])
    .toSorted(([a], [b]) => a.localeCompare(b));
  assert.equal(
    createHash("sha256").update(JSON.stringify(frozen)).digest("hex"),
    "6e615aa9a88b4fcbeed492ddf9e690562c9661cc1ae3252773ec7c034dd4b68a",
  );
  assert.equal(closure.parentStatus, "COMPAT_VERIFIED");
  assert.equal(closure.closureReview.decision, "APPROVED");
  assert.equal(closure.integratedRegression.release, "closure-base-0b6d27a96");
  const buildPath = closure.integratedRegression.buildReceiptPath;
  const buildBytes = readFileSync(new URL(`../../${buildPath}`, import.meta.url));
  const build = JSON.parse(buildBytes);
  assert.deepEqual(Object.keys(build).toSorted(), [
    "binarySha256",
    "cargoVersion",
    "gitStatusOutsideBuildOutput",
    "locked",
    "sourceCommit",
  ]);
  assert.deepEqual(build.gitStatusOutsideBuildOutput, []);
  assert.equal(build.locked, true);
  assert.equal(closure.integratedRegression.integrationCommit, build.sourceCommit);
  assert.equal(closure.integratedRegression.releaseBinarySha256, build.binarySha256);
  assert.equal(
    closure.integratedRegression.buildReceiptSha256,
    createHash("sha256").update(buildBytes).digest("hex"),
  );
  assert.equal(
    closure.conditions.filter(
      ({ evidenceType, status }) => evidenceType === "fireemu-only" && status === "VERIFIED",
    ).length,
    9,
  );
  for (const comparison of closure.integratedRegression.comparisons) {
    const bytes = readFileSync(new URL(`../../${comparison.path}`, import.meta.url));
    const result = JSON.parse(bytes);
    assert.equal(comparison.sha256, createHash("sha256").update(bytes).digest("hex"));
    assert.equal(result.artifactSha256, build.binarySha256);
    assert.equal(comparison.rows, result.rows.length);
    assert.equal(result.sourceCommit, build.sourceCommit);
    assert.equal(
      result.runnerSha256,
      createHash("sha256").update(result.runnerTreeManifest).digest("hex"),
    );
    assert.doesNotMatch(bytes.toString(), /\/Users\/|\/home\/|Bearer |eyJ[A-Za-z0-9_-]+\./);
  }
  for (const condition of closure.conditions.filter(({ status }) => status !== "VERIFIED")) {
    assert.ok(condition.note?.length > 20, condition.conditionId);
  }
  assert.equal(
    closure.conditions.find(({ conditionId }) => conditionId.endsWith("/closure-review")).status,
    "VERIFIED",
  );
  const gate = closure.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/final-artifact-regression"),
  );
  const gateEvidence = JSON.parse(
    readFileSync(new URL(`../../${gate.evidence.comparisonPath}`, import.meta.url)),
  );
  assert.equal(gate.status, "VERIFIED");
  assert.equal(gateEvidence.pending, undefined);
  assert.deepEqual(
    gateEvidence.rows
      .filter(({ conditionId }) => conditionId === gate.conditionId)
      .map(({ caseId }) => caseId),
    [
      "two-production-recordings",
      "exact-frozen-case-set",
      "strict-production-comparison",
      "emulator-no-new-refusals",
      "local-properties",
      "workspace-regression",
      "artifact-runner-binding",
    ],
  );
  assert.ok(gateEvidence.rows.every(({ status }) => status === "PASS"));
  assert.equal(gateEvidence.productionRecordings, undefined);
});

test("exactly seven job resource cases cite S4 and the coordinator approval", () => {
  const expected = [
    "declarations-v1-v2/attempt-deadline",
    "declarations-v1-v2/omitted-versus-null-reset",
    "declarations-v1-v2/SDK-attemptDeadline-versus-CLI-timeout",
    "declarations-v1-v2/v1-App-Engine-job-location",
    "declarations-v1-v2/v2-function-region-job-location",
    "deadline-and-overlap/attemptDeadline-readback",
    "retry-config-validation/attemptDeadline-boundary",
  ];
  // The bounded handler timeout is covered by the 2026-10-06 10:24Z ruling (S4, S7 and 3.3), not by 3.5.
  const timeoutCase = "deadline-and-overlap/bounded-handler-timeout";
  const rows = closure.conditions.flatMap((condition) =>
    (condition.caseDecisions ?? []).flatMap((row) => {
      assert.ok(condition.cases.includes(row.caseId));
      const id = `${condition.conditionId.slice("SCHEDULED-FUNCTIONS/".length)}/${row.caseId}`;
      if ([timeoutCase, "v1-two-stage-retry/publish-ack-versus-handler-failure"].includes(id)) {
        assert.ok(["S4, S7 and 3.3", "S4"].includes(row.decisionOfRecord));
        assert.match(row.decisionRef, /rulings-on-th/);
        return [];
      }
      assert.equal(row.status, "DIVERGENCE_APPROVED");
      assert.equal(row.decisionOfRecord, "S4");
      assert.equal(row.decisionRef, `${ruling} (3.5)`);
      return [id];
    }),
  );
  assert.deepEqual(rows.toSorted(), expected.toSorted());
});

test("closure notes distinguish declared differences, undetermined observations and missing delivery", () => {
  for (const [key, sections] of Object.entries({
    declaredDifferences: ["3.1", "3.2", "3.4"],
    undetermined: ["3.3", "3.6"],
    notImplemented: ["3.7"],
  })) {
    assert.deepEqual(
      closure.closureNotes[key].map(({ section }) => section),
      sections,
    );
    for (const row of closure.closureNotes[key]) {
      assert.equal(row.decisionRef, `${ruling} (${row.section})`);
      assert.ok(row.note.length > 30);
    }
  }
  assert.equal(closure.closureNotes.jobResourceReadings.decisionRef, `${ruling} (3.5)`);
  for (const row of closure.closureNotes.undetermined) {
    assert.equal(row.status, row.section === "3.6" ? "OBSERVATION" : "DIVERGENCE_APPROVED");
  }
});

test("final-binary measurements bind the frozen cases and preserve declared acknowledgement limits", () => {
  for (const area of [
    "declarations-v1-v2",
    "retry-config-validation",
    "timezone-validation-defaults",
    "v1-two-stage-retry",
    "deadline-and-overlap",
  ]) {
    const condition = closure.conditions.find(({ conditionId }) =>
      conditionId.endsWith(`/${area}`),
    );
    assert.deepEqual(
      condition.caseEvidence.map(({ caseId }) => caseId).toSorted(),
      [...condition.cases].toSorted(),
    );
    assert.equal(condition.status, "VERIFIED");
    if (["v1-two-stage-retry", "deadline-and-overlap"].includes(area)) {
      assert.deepEqual(condition.evidence.coverage, condition.evidence.rows);
    }
    assert.doesNotMatch(
      condition.note ?? "",
      /covered outside|no measurement|approval is pending/i,
    );
    for (const binding of condition.caseEvidence) {
      let sources = binding.sources;
      if (binding.comparisonPath) {
        const bytes = readFileSync(new URL(`../../${binding.comparisonPath}`, import.meta.url));
        assert.equal(binding.comparisonSha256, createHash("sha256").update(bytes).digest("hex"));
        const row = JSON.parse(bytes).rows.find(
          (row) => row.conditionId === condition.conditionId && row.caseId === binding.caseId,
        );
        assert.equal(row.status, binding.status);
        sources = row.evidenceSources ?? [];
      }
      for (const source of sources) {
        assert.match(source.sha256, /^[0-9a-f]{64}$/);
        if (source.path.startsWith("docs.local/")) continue;
        const bytes = readFileSync(new URL(`../../${source.path}`, import.meta.url));
        assert.equal(source.sha256, createHash("sha256").update(bytes).digest("hex"));
        if (source.path.endsWith("-calendar-comparison.json")) {
          assert.ok(
            JSON.parse(bytes).rows.some(
              (row) =>
                row.conditionId === condition.conditionId &&
                row.caseId === binding.caseId &&
                row.status === "MATCH",
            ),
          );
        }
        if (source.testId?.startsWith("crates/")) {
          assert.ok(
            JSON.parse(bytes).localVerificationRows.some(({ tests }) =>
              tests.some(({ id, result }) => id === source.testId && result === "PASS"),
            ),
          );
        }
      }
    }
  }
  const groc = closure.conditions.find(({ conditionId }) => conditionId.endsWith("/groc-grammar"));
  assert.equal(groc.status, "VERIFIED");
  assert.deepEqual(groc.evidence.rows, { MATCH: 13 });
  assert.deepEqual(groc.evidence.coverage, { MATCH: 13 });
  assert.equal(groc.evidence.approvedDifferences, undefined);
  assert.equal(
    JSON.parse(
      readFileSync(new URL(`../../${groc.evidence.comparisonPath}`, import.meta.url)),
    ).rows.find(
      ({ conditionId, caseId }) =>
        conditionId === groc.conditionId && caseId === "synchronized-window",
    ).status,
    "MATCH",
  );
  const deadline = closure.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/deadline-and-overlap"),
  );
  assert.equal(
    deadline.caseEvidence.find(
      ({ caseId }) => caseId === "scheduler-attempt-versus-handler-instance",
    ).decisionRef,
    `${ruling} (3.3)`,
  );
  assert.match(deadline.note, /HTTP 504/);
  const delivery = JSON.parse(
    readFileSync(
      new URL(
        "../../spec/compatibility/closure/evidence/SCHEDULED-FUNCTIONS-delivery-comparison.json",
        import.meta.url,
      ),
    ),
  );
  for (const [area, caseId] of [
    ["declarations-v1-v2", "v1-schedule-chain"],
    ["declarations-v1-v2", "v2-onSchedule-string"],
    ["declarations-v1-v2", "v2-onSchedule-options"],
    ["declarations-v1-v2", "omitted-timezone"],
    ["declarations-v1-v2", "explicit-timezone"],
    ["declarations-v1-v2", "retry-options-preserved"],
    ["retry-config-validation", "omitted-options"],
  ]) {
    const row = delivery.rows.find(
      (r) => r.conditionId === `SCHEDULED-FUNCTIONS/${area}` && r.caseId === caseId,
    );
    assert.equal(row.status, "MATCH");
    assert.equal(row.comparedRows.length, 1);
  }
  for (const caseId of [
    "publish-ack-versus-handler-failure",
    "scheduled-occurrence-identity",
    "bounded-handler-timeout",
  ]) {
    const row = delivery.rows.find((r) => r.caseId === caseId);
    assert.equal(
      row.status,
      caseId === "scheduled-occurrence-identity" ? "MATCH" : "DIVERGENCE_APPROVED",
    );
    assert.equal(row.comparedRows.length, 1);
    if (caseId !== "scheduled-occurrence-identity") {
      assert.equal(row.observedStatus, "NOT_COMPARABLE");
    }
  }
});

test("run-3 retry evidence compares both production passes within strict tolerance", () => {
  const delivery = JSON.parse(
    readFileSync(
      new URL(
        "../../spec/compatibility/closure/evidence/SCHEDULED-FUNCTIONS-delivery-comparison.json",
        import.meta.url,
      ),
    ),
  );
  for (const [conditionId, caseId] of [
    ["SCHEDULED-FUNCTIONS/v2-retry-limits", "count-and-duration-interaction"],
    ["SCHEDULED-FUNCTIONS/v2-retry-limits", "duration-only"],
    ["SCHEDULED-FUNCTIONS/v2-retry-limits", "finite-retry-count"],
    ["SCHEDULED-FUNCTIONS/v2-backoff", "first-delay"],
    ["SCHEDULED-FUNCTIONS/v2-backoff", "stable-scheduleTime"],
  ]) {
    const row = delivery.rows.find(
      (candidate) => candidate.conditionId === conditionId && candidate.caseId === caseId,
    );
    assert.deepEqual(
      row.productionPassComparisons.map(({ pass }) => pass),
      [1, 2],
    );
    for (const comparison of row.productionPassComparisons) {
      assert.equal(comparison.verdict, "MATCH");
      assert.equal(
        comparison.productionOffsetsSeconds.length,
        comparison.strictOffsetsSeconds.length,
      );
      comparison.strictDifferenceSeconds.forEach((difference, index) => {
        assert.ok(difference >= -0.5);
        assert.ok(difference <= 1.2 * index + 1);
      });
    }
  }
});

test("overlap policy keeps the frozen cases and verifies the W3 rows on the final inputs", () => {
  const condition = closure.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/overlap-policy"),
  );
  assert.equal(condition.status, "VERIFIED");
  assert.equal(
    condition.evidence.finalArtifactSha256,
    closure.integratedRegression.releaseBinarySha256,
  );
  assert.deepEqual(
    condition.localVerificationRows.map(({ row }) => row),
    [
      "allow-and-queue",
      "skip",
      "reject",
      "manual-run-against-scheduler-run",
      "skip-in-flight-strict-default",
      "skip-in-flight-manual-never-refused",
      "skip-in-flight-one-sweep-not-counted",
      "long-running-handler",
    ],
  );
  for (const row of condition.localVerificationRows) {
    assert.equal(row.status, "PASS");
    for (const reference of row.tests) {
      const [path, name] = reference.split(":");
      assert.ok(
        readFileSync(new URL(`../../${path}`, import.meta.url), "utf8").includes(`fn ${name}(`),
        reference,
      );
    }
  }
});
