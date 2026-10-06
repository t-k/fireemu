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

test("W4 preserves the frozen inventory and leaves final artifact promotion pending", () => {
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
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.integratedRegression, undefined);
  assert.equal(closure.conditions.filter(({ status }) => status === "VERIFIED").length, 8);
  for (const condition of closure.conditions.filter(
    ({ evidenceType }) => evidenceType === "production-parity",
  )) {
    assert.equal(condition.status, "PENDING_CORPUS");
    assert.equal(condition.evidence, null);
  }
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
  const rows = closure.conditions.flatMap((condition) =>
    (condition.caseDecisions ?? []).map((row) => {
      assert.ok(condition.cases.includes(row.caseId));
      assert.equal(row.status, "DIVERGENCE_APPROVED");
      assert.equal(row.decisionOfRecord, "S4");
      assert.equal(row.decisionRef, `${ruling} (3.5)`);
      return `${condition.conditionId.slice("SCHEDULED-FUNCTIONS/".length)}/${row.caseId}`;
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
});

test("overlap policy keeps the frozen cases and drafts the W3 rows without verification", () => {
  const condition = closure.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/overlap-policy"),
  );
  assert.equal(condition.status, "PENDING_LOCAL_VERIFICATION");
  assert.equal(condition.evidence, null);
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
    assert.equal(row.status, "PENDING_LOCAL_VERIFICATION");
    for (const reference of row.tests) {
      const [path, name] = reference.split(":");
      assert.ok(
        readFileSync(new URL(`../../${path}`, import.meta.url), "utf8").includes(`fn ${name}(`),
        reference,
      );
    }
  }
});
