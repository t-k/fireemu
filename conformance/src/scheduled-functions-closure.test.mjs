import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const readRepo = (path) =>
  JSON.parse(readFileSync(new URL(`../../${path}`, import.meta.url), "utf8"));
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
    assert.equal(rows.length, condition.cases.length, "every exact case, once");
    assert.deepEqual(rows.map(({ caseId }) => caseId).toSorted(), [...condition.cases].toSorted());
    assert.ok(
      rows.every(
        ({ status }) =>
          status === (condition.evidenceType === "production-parity" ? "MATCH" : "PASS"),
      ),
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

test("pending SCHEDULED-FUNCTIONS cannot be promoted", () => {
  const closure = readRepo(closurePath);
  if (closure.conditions.every(({ status }) => status === "VERIFIED")) return;
  closure.parentStatus = "COMPAT_VERIFIED";
  assert.throws(() => validateInventory(closure), /every condition must be verified/);
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
