import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const readRepo = (path) =>
  JSON.parse(
    readFileSync(isAbsolute(path) ? path : new URL(`../../${path}`, import.meta.url), "utf8"),
  );
const closurePath = "spec/compatibility/closure/SCHEDULED-FUNCTIONS.json";
// The coordinator-approved exact condition, evidence type, recipe and case inventory.
const inventorySha256 = "6e615aa9a88b4fcbeed492ddf9e690562c9661cc1ae3252773ec7c034dd4b68a";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function validateInventory(closure) {
  assert.equal(closure.parent, "SCHEDULED-FUNCTIONS");
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.deepEqual(closure.oracle.generations, [1, 2]);
  assert.equal(closure.oracle.region, "us-central1");
  assert.ok(["IMPLEMENTING", "COMPAT_VERIFIED"].includes(closure.parentStatus));
  assert.equal(closure.conditions.length, 25);
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(new Set(ids).size, ids.length);
  const frozen = closure.conditions
    .map(({ conditionId, evidenceType, recipeIds, cases }) => [
      conditionId,
      evidenceType,
      recipeIds,
      cases,
    ])
    .toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  assert.equal(
    sha256(JSON.stringify(frozen)),
    inventorySha256,
    "exact frozen cases and evidence types",
  );
  assert.deepEqual(
    closure.scopeDecisions.map(({ id }) => id),
    ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"],
  );
  for (const scope of closure.scopeDecisions) {
    assert.equal(scope.status, "FROZEN");
    assert.ok(
      scope.decision && scope.rationale && scope.decidedBy && scope.decidedOn && scope.decisionRef,
    );
  }
  for (const condition of closure.conditions) {
    assert.ok(condition.source.length > 0, condition.conditionId);
    assert.equal(new Set(condition.cases).size, condition.cases.length);
    const pending = {
      "production-parity": "PENDING_CORPUS",
      "fireemu-only": "PENDING_LOCAL_VERIFICATION",
      "closure-gate": "PENDING_REVIEW",
    }[condition.evidenceType];
    assert.ok([pending, "PRODUCTION_RECORDED", "MISMATCH", "VERIFIED"].includes(condition.status));
    assert.ok(
      ["debt", "covered"].includes(condition.coverageStatus),
      `${condition.conditionId}: coverageStatus ${JSON.stringify(condition.coverageStatus)}`,
    );
    assert.equal(
      condition.coverageStatus === "covered",
      condition.status === "VERIFIED",
      `${condition.conditionId}: covered exactly when verified`,
    );
    if (condition.status !== "VERIFIED") continue;
    const evidence = condition.evidence;
    assert.ok(evidence, `${condition.conditionId}: missing evidence`);
    assert.equal(evidence.evidenceType, condition.evidenceType);
    assert.match(evidence.finalArtifactSha256, /^[0-9a-f]{64}$/);
    assert.match(evidence.runnerSha256, /^[0-9a-f]{64}$/);
    if (condition.evidenceType === "production-parity") {
      assert.equal(evidence.productionRecordings.length, 2);
      assert.deepEqual(
        evidence.productionRecordings.map(({ pass }) => pass),
        [1, 2],
      );
      assert.equal(
        new Set(evidence.productionRecordings.map(({ recordingId }) => recordingId)).size,
        2,
      );
      for (const recording of evidence.productionRecordings) {
        assert.ok(recording.recordingId);
        assert.equal(recording.project, closure.oracle.project);
        assert.match(recording.corpusDigest, /^[0-9a-f]{64}$/);
      }
      assert.equal(
        evidence.productionRecordings[0].corpusDigest,
        evidence.productionRecordings[1].corpusDigest,
      );
    } else {
      assert.equal(
        evidence.productionRecordings,
        undefined,
        "local/review evidence cannot claim production recordings",
      );
    }
    const result = readRepo(evidence.comparisonPath);
    assert.equal(result.artifactSha256, evidence.finalArtifactSha256);
    assert.equal(result.runnerSha256, evidence.runnerSha256);
    const rows = result.rows.filter(({ conditionId }) => conditionId === condition.conditionId);
    for (const supplemental of evidence.supplementalComparisons ?? []) {
      const extra = readRepo(supplemental.path);
      assert.equal(extra.artifactSha256, evidence.finalArtifactSha256);
      assert.equal(extra.runnerSha256, evidence.runnerSha256);
      assert.equal(
        createHash("sha256")
          .update(readFileSync(new URL(`../../${supplemental.path}`, import.meta.url)))
          .digest("hex"),
        supplemental.sha256,
      );
      const selected = new Set(supplemental.caseIds ?? []);
      rows.push(
        ...extra.rows.filter(
          ({ conditionId, caseId }) =>
            conditionId === condition.conditionId && selected.has(caseId),
        ),
      );
      assert.deepEqual(
        extra.rows
          .filter(
            ({ conditionId, caseId }) =>
              conditionId === condition.conditionId && selected.has(caseId),
          )
          .map(({ caseId }) => caseId)
          .toSorted(),
        [...selected].toSorted(),
      );
    }
    assert.equal(rows.length, condition.cases.length, "every exact case, once");
    assert.deepEqual(rows.map(({ caseId }) => caseId).toSorted(), [...condition.cases].toSorted());
    assert.ok(
      rows.every(({ caseId, status, decisionRef }) => {
        if (status === (condition.evidenceType === "production-parity" ? "MATCH" : "PASS"))
          return true;
        if (condition.evidenceType !== "production-parity" || status !== "DIVERGENCE_APPROVED")
          return false;
        const section = {
          "SCHEDULED-FUNCTIONS/declarations-v1-v2/attempt-deadline": "3.5",
          "SCHEDULED-FUNCTIONS/declarations-v1-v2/omitted-versus-null-reset": "3.5",
          "SCHEDULED-FUNCTIONS/declarations-v1-v2/SDK-attemptDeadline-versus-CLI-timeout": "3.5",
          "SCHEDULED-FUNCTIONS/declarations-v1-v2/v1-App-Engine-job-location": "3.5",
          "SCHEDULED-FUNCTIONS/declarations-v1-v2/v2-function-region-job-location": "3.5",
          "SCHEDULED-FUNCTIONS/retry-config-validation/attemptDeadline-boundary": "3.5",
          "SCHEDULED-FUNCTIONS/deadline-and-overlap/attemptDeadline-readback": "3.5",
          "SCHEDULED-FUNCTIONS/deadline-and-overlap/scheduler-attempt-versus-handler-instance":
            "3.3",
          "SCHEDULED-FUNCTIONS/forced-and-natural-invocation/Cloud-Scheduler-run-now": "3.4",
          "SCHEDULED-FUNCTIONS/v1-two-stage-retry/publish-ack-versus-handler-failure": "10:24Z",
          "SCHEDULED-FUNCTIONS/v1-two-stage-retry/scheduled-occurrence-identity": "10:24Z",
          "SCHEDULED-FUNCTIONS/deadline-and-overlap/bounded-handler-timeout": "10:24Z",
        }[`${condition.conditionId}/${caseId}`];
        const difference = evidence.approvedDifferences?.find((row) => row.caseId === caseId);
        const expectedRef =
          section === "10:24Z"
            ? "docs.local/runs/sched-lane/coordinator-rulings.md#2026-10-06-1024z-rulings-on-the-last-three-sched-cases-final-binary-evidence-round-3"
            : `docs.local/runs/sched-lane/coordinator-rulings.md#2026-10-06-0710z-rulings-on-the-closure-proposal-section-3-a0-owner-ledger-922-coordinator-approval-plus-the-opus-closure-review (${section})`;
        return Boolean(
          section &&
          difference?.status === "DIVERGENCE_APPROVED" &&
          difference.decisionRef === expectedRef &&
          decisionRef === difference.decisionRef,
        );
      }),
      `${condition.conditionId}: every row must match or cite its approved difference`,
    );
  }
  if (closure.parentStatus === "COMPAT_VERIFIED") {
    assert.ok(
      closure.conditions.every(({ status }) => status === "VERIFIED"),
      "every condition must be verified",
    );
    assert.equal(closure.closureReview.decision, "APPROVED");
    assert.ok(closure.closureReview.reviewer && closure.closureReview.decisionRef);
    assert.match(closure.closureReview.finalArtifactSha256, /^[0-9a-f]{64}$/);
  }
}

test("SCHEDULED-FUNCTIONS preserves the approved inventory and evidence boundaries", () => {
  validateInventory(readRepo(closurePath));
});

test("approved run-now remains cited and synchronized-window remains a match", () => {
  const closure = readRepo(closurePath);
  const forced = closure.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/forced-and-natural-invocation"),
  );
  const difference = forced.evidence.approvedDifferences.find(
    (row) => row.caseId === "Cloud-Scheduler-run-now",
  );
  assert.equal(difference.status, "DIVERGENCE_APPROVED");
  assert.ok(difference.decisionRef.endsWith(" (3.4)"));
  const groc = closure.conditions.find(({ conditionId }) => conditionId.endsWith("/groc-grammar"));
  const comparison = readRepo(groc.evidence.comparisonPath);
  assert.equal(
    comparison.rows.find(({ caseId }) => caseId === "synchronized-window").status,
    "MATCH",
  );
  validateInventory(closure);
});

test("an approved difference cannot excuse another case or an uncited ruling", () => {
  for (const change of [
    (difference) => delete difference.decisionRef,
    (difference) => {
      difference.decisionRef = "unapproved (3.4)";
    },
    (difference) => {
      difference.decisionRef = difference.decisionRef.replace("(3.4)", "(3.3)");
    },
    (difference) => {
      difference.status = "DIVERGES";
    },
    (difference) => {
      difference.caseId = "natural-scheduled-run";
    },
  ]) {
    const closure = readRepo(closurePath);
    const condition = closure.conditions.find(({ conditionId }) =>
      conditionId.endsWith("/forced-and-natural-invocation"),
    );
    change(condition.evidence.approvedDifferences[0]);
    assert.throws(() => validateInventory(closure));
  }
});

test("unapproved comparison verdicts and local differences remain refused", (t) => {
  const directory = join(
    fileURLToPath(new URL("../../target/codex-out/", import.meta.url)),
    `scheduled-validator-${process.pid}`,
  );
  mkdirSync(directory, { recursive: true });
  const file = join(directory, "comparison.json");
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = file;
  for (const [area, caseId, status, forgedApproval] of [
    ["forced-and-natural-invocation", "natural-scheduled-run", "DIVERGES", false],
    ["forced-and-natural-invocation", "natural-scheduled-run", "NOT_COMPARABLE", false],
    ["forced-and-natural-invocation", "natural-scheduled-run", "DIVERGENCE_APPROVED", true],
    ["manual-schedule", "known-schedule", "DIVERGENCE_APPROVED", true],
  ]) {
    const closure = readRepo(closurePath);
    const condition = closure.conditions.find(({ conditionId }) =>
      conditionId.endsWith(`/${area}`),
    );
    const comparison = readRepo(condition.evidence.comparisonPath);
    const row = comparison.rows.find(
      (row) =>
        row.conditionId === condition.conditionId &&
        (area === "manual-schedule" || row.caseId === caseId),
    );
    row.status = status;
    if (forgedApproval) {
      const ruling = closure.closureNotes.declaredDifferences.find(
        ({ section }) => section === "3.4",
      );
      row.decisionRef = ruling.decisionRef;
      condition.evidence.approvedDifferences = [
        ...(condition.evidence.approvedDifferences ?? []),
        { ...ruling, caseId: row.caseId },
      ];
    }
    writeFileSync(file, JSON.stringify(comparison));
    condition.evidence.comparisonPath = path;
    assert.throws(
      () => validateInventory(closure),
      /every row must match or cite its approved difference/,
    );
  }
  {
    const closure = readRepo(closurePath);
    const condition = closure.conditions.find(({ conditionId }) =>
      conditionId.endsWith("/forced-and-natural-invocation"),
    );
    const comparison = readRepo(condition.evidence.comparisonPath);
    const row = comparison.rows.find(({ caseId }) => caseId === "natural-scheduled-run");
    row.status = "DIVERGENCE_APPROVED";
    row.decisionRef =
      "docs.local/runs/sched-lane/coordinator-rulings.md#2026-10-06-1024z-rulings-on-the-last-three-sched-cases-final-binary-evidence-round-3";
    const difference = { caseId: row.caseId, status: row.status, decisionRef: row.decisionRef };
    condition.evidence.approvedDifferences = [difference];
    writeFileSync(file, JSON.stringify(comparison));
    condition.evidence.comparisonPath = path;
    assert.throws(
      () => validateInventory(closure),
      /every row must match or cite its approved difference/,
    );
  }
  for (const decisionRef of [undefined, "unapproved (3.4)"]) {
    const closure = readRepo(closurePath);
    const condition = closure.conditions.find(({ conditionId }) =>
      conditionId.endsWith("/forced-and-natural-invocation"),
    );
    const comparison = readRepo(condition.evidence.comparisonPath);
    comparison.rows.find(({ caseId }) => caseId === "Cloud-Scheduler-run-now").decisionRef =
      decisionRef;
    writeFileSync(file, JSON.stringify(comparison));
    condition.evidence.comparisonPath = path;
    assert.throws(
      () => validateInventory(closure),
      /every row must match or cite its approved difference/,
    );
  }
  for (const [caseId, status, reference] of [
    ["Cloud-Scheduler-run-now", "NOT_COMPARABLE", "approved"],
    ["Cloud-Scheduler-run-now", "DIVERGES", "approved"],
    ["Cloud-Scheduler-run-now", "DIVERGENCE_APPROVED", "unapproved (3.4)"],
    ["natural-scheduled-run", "DIVERGENCE_APPROVED", "undefined-section"],
  ]) {
    const closure = readRepo(closurePath);
    const condition = closure.conditions.find(({ conditionId }) =>
      conditionId.endsWith("/forced-and-natural-invocation"),
    );
    const comparison = readRepo(condition.evidence.comparisonPath);
    const row = comparison.rows.find((row) => row.caseId === caseId);
    const difference = { ...condition.evidence.approvedDifferences[0], caseId };
    if (reference === "undefined-section")
      difference.decisionRef = difference.decisionRef.replace("(3.4)", "(undefined)");
    else if (reference !== "approved") difference.decisionRef = reference;
    row.status = status;
    row.decisionRef = difference.decisionRef;
    condition.evidence.approvedDifferences = [
      ...condition.evidence.approvedDifferences.filter((entry) => entry.caseId !== caseId),
      difference,
    ];
    writeFileSync(file, JSON.stringify(comparison));
    condition.evidence.comparisonPath = path;
    assert.throws(
      () => validateInventory(closure),
      /every row must match or cite its approved difference/,
    );
  }
});

test("pending SCHEDULED-FUNCTIONS cannot be promoted", () => {
  const closure = readRepo(closurePath);
  const gate = closure.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/closure-review"),
  );
  gate.status = "PENDING_REVIEW";
  gate.coverageStatus = "debt";
  closure.parentStatus = "COMPAT_VERIFIED";
  assert.throws(() => validateInventory(closure), /every condition must be verified/);
});

test("a mistyped or inconsistent coverageStatus is refused", () => {
  const typo = readRepo(closurePath);
  typo.conditions[0].coverageStatus = "coverd";
  assert.throws(() => validateInventory(typo), /coverageStatus/);
  const optimistic = readRepo(closurePath);
  const pending = optimistic.conditions.find(({ conditionId }) =>
    conditionId.endsWith("/closure-review"),
  );
  pending.status = "PENDING_REVIEW";
  pending.coverageStatus = "covered";
  assert.throws(() => validateInventory(optimistic), /covered exactly when verified/);
});

test("dropping a frozen case or disguising local evidence is refused", () => {
  const missing = readRepo(closurePath);
  missing.conditions[0].cases.pop();
  assert.throws(() => validateInventory(missing), /exact frozen cases/);
  const disguised = readRepo(closurePath);
  disguised.conditions.find(({ evidenceType }) => evidenceType === "fireemu-only").evidenceType =
    "production-parity";
  assert.throws(() => validateInventory(disguised), /exact frozen cases/);
});

if (process.env.FIREEMU_REQUIRE_SCHEDULED_CLOSURE === "1") {
  test("SCHEDULED-FUNCTIONS has reached reviewed COMPAT_VERIFIED", () => {
    const closure = readRepo(closurePath);
    validateInventory(closure);
    assert.equal(closure.parentStatus, "COMPAT_VERIFIED", "closure remains unfinished");
  });
}
