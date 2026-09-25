import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/AUTH-TENANT-BLOCKING.json", import.meta.url),
);

// The frozen AUTH-TENANT-BLOCKING inventory (conditions frozen 2026-09-25 after the owner's
// decisions TB1-TB5). Adding or removing a row requires a new production mismatch or an
// uncovered acceptance requirement, and an edit here in the same commit.
const requiredConditions = new Set([
  "AUTH-TENANT-BLOCKING/tenant-management",
  "AUTH-TENANT-BLOCKING/multi-tenant-switch",
  "AUTH-TENANT-BLOCKING/tenant-selection",
  "AUTH-TENANT-BLOCKING/credential-isolation",
  "AUTH-TENANT-BLOCKING/admin-accounts",
  "AUTH-TENANT-BLOCKING/tenant-sign-in-settings",
  "AUTH-TENANT-BLOCKING/inheritance",
  "AUTH-TENANT-BLOCKING/tenant-password-policy",
  "AUTH-TENANT-BLOCKING/tenant-mfa",
  "AUTH-TENANT-BLOCKING/tenant-deletion",
  "AUTH-TENANT-BLOCKING/tenant-actions",
  "AUTH-TENANT-BLOCKING/provider-isolation",
  "AUTH-TENANT-BLOCKING/event-selection",
  "AUTH-TENANT-BLOCKING/ordering-and-visibility",
  "AUTH-TENANT-BLOCKING/refusal",
  "AUTH-TENANT-BLOCKING/rollback",
  "AUTH-TENANT-BLOCKING/timeout",
  "AUTH-TENANT-BLOCKING/claims",
  "AUTH-TENANT-BLOCKING/response-validation",
  "AUTH-TENANT-BLOCKING/blocking-config",
  "AUTH-TENANT-BLOCKING/event-payload",
  "AUTH-TENANT-BLOCKING/tenant-events",
  "AUTH-TENANT-BLOCKING/send-email-sms",
  "AUTH-TENANT-BLOCKING/session-isolation",
  "AUTH-TENANT-BLOCKING/hook-concurrency",
  "AUTH-TENANT-BLOCKING/final-artifact-regression",
  "AUTH-TENANT-BLOCKING/closure-review",
]);

const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

const load = () => JSON.parse(readFileSync(closurePath, "utf8"));

test("AUTH-TENANT-BLOCKING closure inventory cannot silently omit a declared condition", () => {
  const closure = load();
  assert.equal(closure.parent, "AUTH-TENANT-BLOCKING");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    assert.ok(typeof condition.source === "string" && condition.source.length > 0, label);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0, label);
    assert.ok(statuses.has(condition.status), `${label}: unknown status`);
    assert.deepEqual(condition.configProjections, ["default"], label);
    // No condition is verified before its production evidence exists (added with the
    // comparison, as in the AUTH-MFA closure test).
    assert.notEqual(condition.status, "VERIFIED", `${label}: verified without evidence checks`);
  }
});

test("scope decisions are recorded, not implied", () => {
  const closure = load();
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const id of ["TB1", "TB2", "TB3", "TB4", "TB5", "TB6", "TB7", "TB8", "M2", "M6", "E4"]) {
    assert.ok(decided.has(id), `scope decision ${id} must be recorded`);
  }
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision && decision.decidedBy && decision.decidedOn, decision.id);
    if (decision.movedTo) assert.match(decision.movedTo, /^(AUTH|FS)-[A-Z-]+$/, decision.id);
  }
});

test("parent promotion requires every condition and an approved closure review", () => {
  const closure = load();
  const allVerified = closure.conditions.every(({ status }) => status === "VERIFIED");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    allVerified && closure.closureReview?.decision === "APPROVED",
  );
});

test("tenant recipes and tenant corpus programs cover each other", async () => {
  const { PROGRAMS } = await import("./auth-tenant-blocking/corpus.mjs");
  const recipes = load().conditions.flatMap(({ recipeIds }) => recipeIds);
  const covers = (recipe, programId) => programId === recipe || programId.startsWith(`${recipe}/`);
  const own = recipes.filter((id) => id.startsWith("atb/tenant/"));
  for (const recipe of own) {
    assert.ok(
      PROGRAMS.some(({ id }) => covers(recipe, id)),
      `closure recipe ${recipe} has no corpus program`,
    );
  }
  for (const { id } of PROGRAMS) {
    assert.ok(
      own.some((recipe) => covers(recipe, id)),
      `corpus program ${id} belongs to no closure recipe`,
    );
  }
});
