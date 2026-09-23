import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/AUTH-ACCOUNT.json", import.meta.url),
);

// The frozen AUTH-ACCOUNT inventory. Adding or removing a row requires a new production
// mismatch or an uncovered acceptance requirement, and an edit here in the same commit.
const requiredConditions = new Set([
  "AUTH-ACCOUNT/client-password-lifecycle",
  "AUTH-ACCOUNT/client-profile-attributes",
  "AUTH-ACCOUNT/client-password-change",
  "AUTH-ACCOUNT/input-validation-basic",
  "AUTH-ACCOUNT/anonymous-basic",
  "AUTH-ACCOUNT/email-canonical-and-duplicate",
  "AUTH-ACCOUNT/disable-reenable",
  "AUTH-ACCOUNT/delete-effects",
  "AUTH-ACCOUNT/default-policy-client-update",
  "AUTH-ACCOUNT/tampered-token-privileged-update",
  "AUTH-ACCOUNT/anonymous-upgrade",
  "AUTH-ACCOUNT/client-email-change",
  "AUTH-ACCOUNT/admin-create",
  "AUTH-ACCOUNT/admin-lookup-selectors",
  "AUTH-ACCOUNT/admin-update-fields",
  "AUTH-ACCOUNT/custom-attributes",
  "AUTH-ACCOUNT/privilege-boundary",
  "AUTH-ACCOUNT/admin-delete-and-batch-delete",
  "AUTH-ACCOUNT/admin-list-export",
  "AUTH-ACCOUNT/admin-query",
  "AUTH-ACCOUNT/import-basic",
  "AUTH-ACCOUNT/import-hash-formats",
  "AUTH-ACCOUNT/phone-accounts",
  "AUTH-ACCOUNT/provider-link-unlink",
  "AUTH-ACCOUNT/uid-reuse-after-delete",
  "AUTH-ACCOUNT/duplicate-email-mode",
  "AUTH-ACCOUNT/email-privacy-off",
  "AUTH-ACCOUNT/password-policy-routes-and-custom",
  "AUTH-ACCOUNT/client-permissions",
  "AUTH-ACCOUNT/value-classes",
  "AUTH-ACCOUNT/final-artifact-regression",
  "AUTH-ACCOUNT/closure-review",
]);

// Every password hash algorithm production `accounts:batchCreate` accepts, per the Identity
// Toolkit v1 discovery document read on 2026-09-23 (owner decision 2026-09-23: all formats are
// in scope, none is a documented divergence).
const requiredHashAlgorithms = new Set([
  "HMAC_SHA512",
  "HMAC_SHA256",
  "HMAC_SHA1",
  "HMAC_MD5",
  "MD5",
  "SHA1",
  "SHA256",
  "SHA512",
  "PBKDF_SHA1",
  "PBKDF2_SHA256",
  "SCRYPT",
  "STANDARD_SCRYPT",
  "BCRYPT",
  "ARGON2",
]);

const configProjections = new Set([
  "default",
  "privacy-off",
  "dup-email",
  "policy-enforce-custom",
  "policy-not-enforce",
  "client-permissions",
]);

const statuses = new Set([
  "PENDING_CORPUS",
  "SAVED_REFERENCE_PENDING_FINAL",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

const load = () => JSON.parse(readFileSync(closurePath, "utf8"));

test("AUTH-ACCOUNT closure inventory cannot silently omit a declared condition", () => {
  const closure = load();
  assert.equal(closure.parent, "AUTH-ACCOUNT");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    assert.ok(typeof condition.source === "string" && condition.source.length > 0, label);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0, label);
    assert.ok(statuses.has(condition.status), `${label}: unknown status`);
    assert.ok(
      Array.isArray(condition.configProjections) &&
        condition.configProjections.length > 0 &&
        condition.configProjections.every((p) => configProjections.has(p)),
      `${label}: every Auth condition names the configuration it is observed under`,
    );
    if (condition.status === "VERIFIED") {
      assert.equal(condition.evidence?.productionRecordings?.length, 2, label);
      assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/, label);
      assert.ok(condition.evidence?.comparisonPath, label);
    }
  }
});

test("hash-format closure covers every production import algorithm", () => {
  const row = load().conditions.find(
    ({ conditionId }) => conditionId === "AUTH-ACCOUNT/import-hash-formats",
  );
  const covered = new Set(
    row.recipeIds
      .map((id) => /^auth-account\/admin\/import-hash\/([A-Z0-9_]+)$/.exec(id)?.[1])
      .filter(Boolean),
  );
  assert.deepEqual(covered, requiredHashAlgorithms);
  assert.ok(row.recipeIds.includes("auth-account/admin/import-hash/errors"));
});

test("scope decisions are recorded, not implied", () => {
  const closure = load();
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const id of ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11"]) {
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
