import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FS-RULES.json", import.meta.url),
);

// The frozen FS-RULES inventory. Adding or removing a row requires a new production mismatch or
// an uncovered acceptance requirement, and an edit here in the same commit.
const requiredConditions = new Set([
  "FS-RULES/principals",
  "FS-RULES/auth-token-fields",
  "FS-RULES/tenant",
  "FS-RULES/request-resource",
  "FS-RULES/document-access",
  "FS-RULES/query-proofs",
  "FS-RULES/access-budgets",
  "FS-RULES/compile-limits",
  "FS-RULES/runtime-limits",
  "FS-RULES/atomic-writes",
  "FS-RULES/refusal-shape",
  "FS-RULES/token-states",
  "FS-RULES/token-expiry",
  "FS-RULES/publication",
  "FS-RULES/named-database",
  "FS-RULES/final-artifact-regression",
  "FS-RULES/closure-review",
]);

const requiredScopeDecisions = ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10"];

const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

const load = () => JSON.parse(readFileSync(closurePath, "utf8"));

test("FS-RULES closure inventory cannot silently omit a declared condition", () => {
  const closure = load();
  assert.equal(closure.parent, "FS-RULES");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.equal(closure.oracle.project, "fireemu-oracle-idp");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    assert.ok(typeof condition.source === "string" && condition.source.length > 0, label);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0, label);
    assert.ok(statuses.has(condition.status), `${label}: unknown status`);
    assert.deepEqual(condition.configProjections, ["default"], label);
    assert.ok(typeof condition.note === "string" && condition.note.length > 0, label);
  }
});

test("FS-RULES scope decisions are recorded, not implied", () => {
  const closure = load();
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const id of requiredScopeDecisions) {
    assert.ok(decided.has(id), `scope decision ${id} must be recorded`);
  }
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision && decision.decidedBy && decision.decidedOn, decision.id);
    assert.match(decision.decidedBy, /^owner/, `${decision.id}: only the owner decides scope`);
    if (decision.movedTo) assert.match(decision.movedTo, /^(AUTH|FS)-[A-Z-]+$/, decision.id);
  }
});

test("FS-RULES parent promotion requires every condition and an approved closure review", () => {
  const closure = load();
  const allVerified = closure.conditions.every(({ status }) => status === "VERIFIED");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    allVerified && closure.closureReview?.decision === "APPROVED",
  );
});
