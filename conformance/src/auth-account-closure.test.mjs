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
      const runs = condition.evidence?.productionRecordings ?? [];
      assert.ok(runs.length > 0, `${label}: names its production runs`);
      for (const run of runs) {
        assert.equal(run.recordings, 2, `${label}: every production run is recorded twice`);
        assert.equal(run.project, "fireemu-oracle-idp", label);
      }
      assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/, label);
      assert.ok(condition.evidence?.comparisonPath, label);
      // A verified row is backed by the committed comparison of the same artifact: every row
      // of its programs matches production.
      const comparison = JSON.parse(
        readFileSync(
          fileURLToPath(new URL(`../../${condition.evidence.comparisonPath}`, import.meta.url)),
          "utf8",
        ),
      );
      assert.equal(comparison.artifactSha256, condition.evidence.finalArtifactSha256, label);
      const recipes = condition.recipeIds.filter(
        (id) => id.startsWith("auth-account/") || id === "auth-account",
      );
      const covered = (row) => {
        const program = row.split("#")[0];
        return recipes.some(
          (r) => r === "auth-account" || program === r || program.startsWith(`${r}/`),
        );
      };
      const rows = comparison.rows.filter(({ row }) => covered(row));
      assert.ok(rows.length > 0, `${label}: has compared rows`);
      // A row may differ only as an owner-decided, documented divergence of this condition.
      const divergences = condition.evidence.documentedDivergences ?? [];
      for (const divergence of divergences) {
        assert.equal(divergence.decidedBy, "owner", `${label}: ${divergence.row}`);
        assert.ok(divergence.decidedOn && divergence.reason && divergence.kind, divergence.row);
        assert.ok(
          closure.scopeDecisions.some(({ id }) => id === divergence.scopeDecision),
          `${label}: ${divergence.row} names a recorded scope decision`,
        );
      }
      // A message-text divergence may differ only in the text after the error code.
      for (const divergence of divergences.filter(({ kind }) => kind === "message-text")) {
        const compared = comparison.rows.find(({ row }) => row === divergence.row);
        assert.ok(compared, `${label}: ${divergence.row} is compared`);
        assert.notEqual(
          compared.status,
          "MATCH",
          `${label}: ${divergence.row} now matches; remove its stale divergence`,
        );
        assert.equal(compared.sameErrorCode, true, `${label}: ${divergence.row} keeps the code`);
        assert.deepEqual(
          compared.differences.toSorted(),
          ["body.error.errors.0.message", "body.error.message"],
          `${label}: ${divergence.row} differs only in its message`,
        );
      }
      const documented = new Set(divergences.map(({ row }) => row));
      const off = rows
        .filter(({ status, row }) => status !== "MATCH" && !documented.has(row))
        .map(({ row }) => row);
      if (condition.conditionId === "AUTH-ACCOUNT/closure-review") {
        assert.equal(closure.closureReview?.decision, "APPROVED", label);
        assert.equal(
          closure.closureReview.finalArtifactSha256,
          condition.evidence.finalArtifactSha256,
          `${label}: the approval names the artifact the evidence is bound to`,
        );
      } else if (condition.conditionId !== "AUTH-ACCOUNT/final-artifact-regression") {
        assert.deepEqual(off, [], `${label}: every row matches production`);
      } else {
        // The regression's figures are read from the committed evidence, not typed by hand.
        assert.deepEqual(condition.evidence.authAccount, comparison.summary, label);
        const everyDocumented = new Set(
          closure.conditions.flatMap(({ evidence }) =>
            (evidence?.documentedDivergences ?? []).map(({ row }) => row),
          ),
        );
        assert.deepEqual(
          off.filter((row) => !everyDocumented.has(row)),
          [],
          `${label}: every differing row is a documented divergence`,
        );
        const replay = JSON.parse(
          readFileSync(
            fileURLToPath(
              new URL(`../../${condition.evidence.savedReference.path}`, import.meta.url),
            ),
            "utf8",
          ),
        );
        assert.equal(replay.allCasesMatch, true, label);
        assert.equal(replay.sourceCommit, condition.evidence.savedReference.sourceCommit, label);
        for (const corpus of Object.values(replay.corpora)) {
          assert.equal(
            corpus.currentLocal.localArtifactSha256,
            condition.evidence.savedReference.artifactSha256,
            label,
          );
        }
        assert.equal(
          condition.evidence.execution.artifactSha256,
          condition.evidence.finalArtifactSha256,
        );
        assert.equal(
          condition.evidence.execution.receiptSha256,
          comparison.execution.receiptSha256,
        );
        assert.equal(
          condition.evidence.execution.buildReceiptSha256,
          comparison.execution.buildReceiptSha256,
        );
        assert.equal(
          condition.evidence.execution.runtimeInputMapSha256,
          "dbe45128dc806dc439c70f1f09d7bd669868ce737e5272445bdc2df03c605e4",
        );
      }
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

test("AUTH-ACCOUNT A12 and final regression bind to the current attested artifact", () => {
  const closure = load();
  const a12 = closure.conditions.find(
    ({ conditionId }) => conditionId === "AUTH-ACCOUNT/custom-attributes",
  );
  const regression = closure.conditions.find(
    ({ conditionId }) => conditionId === "AUTH-ACCOUNT/final-artifact-regression",
  );
  assert.equal(a12.status, "VERIFIED");
  assert.deepEqual(a12.evidence.rows, { MATCH: 31 });
  assert.equal(a12.evidence.documentedDivergences, undefined);
  assert.equal(regression.status, "VERIFIED");
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(
    regression.evidence.finalArtifactSha256,
    "a8bfc5dc1737dee01bae028b2e3dd421f04326e12640cb4936d896ebfcfa358a",
  );
  assert.equal(regression.evidence.sourceCommit, "c86b8490c1717bce2881eac051bef94388a84001");
  assert.equal(
    closure.conditions.find(
      ({ conditionId }) => conditionId === "AUTH-ACCOUNT/closure-review",
    ).status,
    "PENDING_REVIEW",
  );
});

test("scope decisions are recorded, not implied", () => {
  const closure = load();
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const id of ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12"]) {
    assert.ok(decided.has(id), `scope decision ${id} must be recorded`);
  }
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision && decision.decidedBy && decision.decidedOn, decision.id);
    if (decision.movedTo) assert.match(decision.movedTo, /^(AUTH|FS)-[A-Z-]+$/, decision.id);
  }
});

test("parent promotion requires every condition and an approved closure review", () => {
  const closure = load();
  const allVerified = closure.conditions.every(({ status, evidence }) => {
    const resultCounts = { ...evidence?.rows, ...evidence?.authAccount };
    return status === "VERIFIED" && !(resultCounts.MISMATCH > 0);
  });
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    allVerified && closure.closureReview?.decision === "APPROVED",
  );
});

test("closure recipes and corpus programs cover each other", async () => {
  const { PROGRAMS } = await import("./auth-account/corpus.mjs");
  const recipes = load()
    .conditions.flatMap(({ recipeIds }) => recipeIds)
    .filter((id) => id.startsWith("auth-account/"));
  const covers = (recipe, programId) => programId === recipe || programId.startsWith(`${recipe}/`);
  for (const recipe of recipes) {
    assert.ok(
      PROGRAMS.some(({ id }) => covers(recipe, id)),
      `closure recipe ${recipe} has no corpus program`,
    );
  }
  for (const { id } of PROGRAMS) {
    assert.ok(
      recipes.some((recipe) => covers(recipe, id)),
      `corpus program ${id} belongs to no closure recipe`,
    );
  }
});
