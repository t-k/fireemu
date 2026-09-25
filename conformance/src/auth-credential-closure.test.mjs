import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/AUTH-CREDENTIAL.json", import.meta.url),
);

// The frozen AUTH-CREDENTIAL inventory. Adding or removing a row requires a new production
// mismatch or an uncovered acceptance requirement, and an edit here in the same commit.
const requiredConditions = new Set([
  "AUTH-CREDENTIAL/id-token-composition",
  "AUTH-CREDENTIAL/legacy-token-without-return-secure-token",
  "AUTH-CREDENTIAL/refresh-exchange",
  "AUTH-CREDENTIAL/refresh-refusals",
  "AUTH-CREDENTIAL/id-token-refusals",
  "AUTH-CREDENTIAL/revocation-valid-since",
  "AUTH-CREDENTIAL/custom-token-sign-in",
  "AUTH-CREDENTIAL/custom-token-validation",
  "AUTH-CREDENTIAL/claim-precedence",
  "AUTH-CREDENTIAL/session-cookie-durations",
  "AUTH-CREDENTIAL/session-cookie-sessions",
  "AUTH-CREDENTIAL/token-expiry",
  "AUTH-CREDENTIAL/account-state-token-refusals",
  "AUTH-CREDENTIAL/final-artifact-regression",
  "AUTH-CREDENTIAL/closure-review",
]);

// Every claim name the Admin SDK reserves for custom-token developer claims. Each one is
// offered to production once, so the server's own refusal set is observed, not assumed.
const reservedClaims = [
  "acr",
  "amr",
  "at_hash",
  "aud",
  "auth_time",
  "azp",
  "cnf",
  "c_hash",
  "exp",
  "firebase",
  "iat",
  "iss",
  "jti",
  "nbf",
  "nonce",
  "sub",
];

const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

const load = () => JSON.parse(readFileSync(closurePath, "utf8"));
const readJson = (path) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), "utf8"));

// A comparison is evidence only for the committed fixture it names and only when it covers every
// recorded row of that fixture: a re-recorded fixture or a dropped row breaks the binding.
const FIXTURES = {
  "auth-credential-comparison-v1": "conformance/auth-credential-production.json",
  "auth-account-comparison-v1": "conformance/auth-account-production.json",
};

function assertBoundToFixture(comparison, label) {
  const fixturePath = FIXTURES[comparison.kind];
  assert.ok(fixturePath, `${label}: unknown comparison kind ${comparison.kind}`);
  const text = readFileSync(
    fileURLToPath(new URL(`../../${fixturePath}`, import.meta.url)),
    "utf8",
  );
  assert.equal(
    comparison.fixtureSha256,
    createHash("sha256").update(text).digest("hex"),
    `${label}: the comparison was made against the committed ${fixturePath}`,
  );
  const recorded = Object.entries(JSON.parse(text).programs).flatMap(([program, { steps }]) =>
    Object.keys(steps).map((step) => `${program}#${step}`),
  );
  assert.deepEqual(
    comparison.rows.map(({ row }) => row).toSorted(),
    recorded.toSorted(),
    `${label}: the comparison covers exactly the recorded rows of ${fixturePath}`,
  );
}

const readFixture = (path) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), "utf8"));

/** `recordedAt gitSha` of every fixture program a condition's recipes cover, deduplicated. */
function recordedRuns(recipes) {
  const covers = (recipe, program) => program === recipe || program.startsWith(`${recipe}/`);
  const runs = new Set();
  for (const path of Object.values(FIXTURES)) {
    for (const [program, { recordedAt, gitSha }] of Object.entries(readFixture(path).programs)) {
      if (recipes.some((recipe) => covers(recipe, program))) runs.add(`${recordedAt} ${gitSha}`);
    }
  }
  return [...runs].toSorted();
}

test("the fixture binding refuses a stale digest and a dropped row", () => {
  const comparison = readJson(
    "spec/compatibility/closure/evidence/AUTH-CREDENTIAL-comparison.json",
  );
  assert.doesNotThrow(() => assertBoundToFixture(comparison, "committed"));
  assert.throws(
    () => assertBoundToFixture({ ...comparison, fixtureSha256: "0".repeat(64) }, "stale"),
    /committed conformance\/auth-credential-production.json/,
  );
  assert.throws(
    () => assertBoundToFixture({ ...comparison, rows: comparison.rows.slice(1) }, "dropped"),
    /exactly the recorded rows/,
  );
  assert.throws(
    () => assertBoundToFixture({ ...comparison, kind: "unknown" }, "kind"),
    /unknown comparison kind/,
  );
});

test("AUTH-CREDENTIAL closure inventory cannot silently omit a declared condition", () => {
  const closure = load();
  assert.equal(closure.parent, "AUTH-CREDENTIAL");
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
    if (condition.status !== "VERIFIED") continue;
    const runs = condition.evidence?.productionRecordings ?? [];
    assert.ok(runs.length > 0, `${label}: names its production runs`);
    for (const run of runs) {
      assert.equal(run.recordings, 2, `${label}: every production run is recorded twice`);
      assert.equal(run.project, "fireemu-oracle-idp", label);
    }
    // The named runs are exactly the recordings the fixtures hold for the condition's programs.
    assert.deepEqual(
      runs.map(({ recordedAt, gitSha }) => `${recordedAt} ${gitSha}`).toSorted(),
      recordedRuns(condition.recipeIds),
      `${label}: productionRecordings name the fixtures' own recordings`,
    );
    assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/, label);
    // A verified row is backed by committed comparisons of the same artifact in which every
    // row of its programs matches production.
    const comparisons = (condition.evidence.comparisonPaths ?? []).map(readJson);
    assert.ok(comparisons.length > 0, `${label}: names its comparisons`);
    for (const comparison of comparisons) {
      assert.equal(comparison.artifactSha256, condition.evidence.finalArtifactSha256, label);
      assertBoundToFixture(comparison, label);
    }
    const covered = (row) => {
      const programId = row.split("#")[0];
      return condition.recipeIds.some(
        (r) =>
          r === "auth-credential" ||
          r === "auth-account" ||
          programId === r ||
          programId.startsWith(`${r}/`),
      );
    };
    const rows = comparisons.flatMap(({ rows: all }) => all.filter(({ row }) => covered(row)));
    assert.ok(rows.length > 0, `${label}: has compared rows`);
    const divergences = condition.evidence.documentedDivergences ?? [];
    for (const divergence of divergences) {
      assert.equal(divergence.decidedBy, "owner", `${label}: ${divergence.row}`);
      assert.ok(divergence.decidedOn && divergence.reason && divergence.kind, divergence.row);
      assert.ok(
        closure.scopeDecisions.some(({ id }) => id === divergence.scopeDecision),
        `${label}: ${divergence.row} names a recorded scope decision`,
      );
    }
    const documented = new Set(divergences.map(({ row }) => row));
    const off = rows
      .filter(({ status, row }) => status !== "MATCH" && !documented.has(row))
      .map(({ row }) => row);
    if (label === "AUTH-CREDENTIAL/closure-review") {
      assert.equal(closure.closureReview?.decision, "APPROVED", label);
      assert.equal(
        closure.closureReview.finalArtifactSha256,
        condition.evidence.finalArtifactSha256,
        `${label}: the approval names the artifact the evidence is bound to`,
      );
    } else if (label === "AUTH-CREDENTIAL/final-artifact-regression") {
      const currentComparison = readJson(
        "spec/compatibility/closure/evidence/AUTH-CREDENTIAL-account-regression.json",
      );
      const credentialComparison = readJson(
        "spec/compatibility/closure/evidence/AUTH-CREDENTIAL-comparison.json",
      );
      assert.equal(currentComparison.artifactSha256, condition.evidence.finalArtifactSha256);
      assert.equal(condition.evidence.execution.runId, currentComparison.execution.runId);
      assert.equal(
        condition.evidence.execution.receiptSha256,
        currentComparison.execution.receiptSha256,
      );
      assert.equal(
        condition.evidence.execution.buildReceiptSha256,
        currentComparison.execution.buildReceiptSha256,
      );
      assert.equal(
        condition.evidence.execution.runtimeInputMapSha256,
        "dbe45128dc806dc439c70f1f09d7bd669868ce737e5272445bdc2df03c605e4",
      );
      assert.equal(
        condition.evidence.execution.artifactSha256,
        currentComparison.artifactSha256,
      );
      assert.equal(credentialComparison.artifactSha256, condition.evidence.finalArtifactSha256);
      assert.deepEqual(credentialComparison.summary, { MATCH: 222 });
      assertBoundToFixture(credentialComparison, label);
      assert.deepEqual(credentialComparison.execution.command, [
        "node",
        "src/auth-credential/run.mjs",
        "check",
      ]);
      assert.equal(credentialComparison.execution.rowCount, 222);
      assert.equal(credentialComparison.execution.selector.state, "unset");
      assert.equal(
        condition.evidence.credentialExecution.runtimeInputMapSha256,
        "dbe45128dc806dc439c70f1f09d7bd669868ce737e5272445bdc2df03c605e4",
      );
      assert.equal(
        credentialComparison.fixtureSha256,
        createHash("sha256")
          .update(
            readFileSync(
              fileURLToPath(
                new URL("../../conformance/auth-credential-production.json", import.meta.url),
              ),
              "utf8",
            ),
          )
          .digest("hex"),
      );
      assert.equal(
        condition.evidence.credentialExecution.fixtureSha256,
        credentialComparison.fixtureSha256,
      );
      assert.equal(
        condition.evidence.credentialExecution.sanitizedExportSha256,
        credentialComparison.execution.sanitizedExportSha256,
      );
      assert.equal(condition.evidence.credentialExecution.runId, credentialComparison.execution.runId);
      assert.equal(
        condition.evidence.credentialExecution.receiptSha256,
        credentialComparison.execution.receiptSha256,
      );
      assert.equal(
        condition.evidence.credentialExecution.buildReceiptSha256,
        credentialComparison.execution.buildReceiptSha256,
      );
      assert.equal(
        condition.evidence.credentialExecution.artifactSha256,
        credentialComparison.artifactSha256,
      );
      assert.deepEqual(condition.evidence.credentialRows, { MATCH: 222 });
      assert.deepEqual(condition.evidence.inheritedAccountRows, { MATCH: 631 });
      assert.deepEqual(condition.evidence.rows, { MATCH: 853 });
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
    } else {
      assert.deepEqual(off, [], `${label}: every row matches production`);
    }
  }
});

test("scope decisions are recorded, not implied", () => {
  const closure = load();
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const id of ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"]) {
    assert.ok(decided.has(id), `scope decision ${id} must be recorded`);
  }
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision && decision.decidedBy && decision.decidedOn, decision.id);
    if (decision.movedTo) assert.match(decision.movedTo, /^(AUTH|FS)-[A-Z-]+$/, decision.id);
  }
});

test("AUTH-CREDENTIAL final regression requires current 631-row and 222-row comparisons", () => {
  const closure = load();
  const regression = closure.conditions.find(
    ({ conditionId }) => conditionId === "AUTH-CREDENTIAL/final-artifact-regression",
  );
  const accountComparison = readJson(
    "spec/compatibility/closure/evidence/AUTH-CREDENTIAL-account-regression.json",
  );
  const credentialComparison = readJson(
    "spec/compatibility/closure/evidence/AUTH-CREDENTIAL-comparison.json",
  );
  assert.equal(regression.status, "VERIFIED");
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(
    regression.evidence.finalArtifactSha256,
    "a8bfc5dc1737dee01bae028b2e3dd421f04326e12640cb4936d896ebfcfa358a",
  );
  assert.equal(regression.evidence.sourceCommit, "c86b8490c1717bce2881eac051bef94388a84001");
  assert.deepEqual(accountComparison.summary, { MATCH: 631 });
  assert.equal(accountComparison.artifactSha256, regression.evidence.finalArtifactSha256);
  assert.deepEqual(credentialComparison.summary, { MATCH: 222 });
  assert.equal(credentialComparison.artifactSha256, regression.evidence.finalArtifactSha256);
  assert.deepEqual(regression.evidence.comparisonPaths, [
    "spec/compatibility/closure/evidence/AUTH-CREDENTIAL-account-regression.json",
    "spec/compatibility/closure/evidence/AUTH-CREDENTIAL-comparison.json",
  ]);
  assert.deepEqual(regression.evidence.credentialRows, { MATCH: 222 });
  assert.deepEqual(regression.evidence.inheritedAccountRows, { MATCH: 631 });
  assert.deepEqual(regression.evidence.rows, { MATCH: 853 });
  assert.equal(regression.evidence.pendingCredentialComparison, undefined);
  for (const condition of closure.conditions.filter(({ status }) => status === "VERIFIED")) {
    assert.equal(condition.evidence.finalArtifactSha256, regression.evidence.finalArtifactSha256);
    assert.equal(condition.evidence.sourceCommit, regression.evidence.sourceCommit);
  }
  assert.equal(
    closure.conditions.find(
      ({ conditionId }) => conditionId === "AUTH-CREDENTIAL/closure-review",
    ).status,
    "PENDING_REVIEW",
  );
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
  const { PROGRAMS } = await import("./auth-credential/corpus.mjs");
  const { PROGRAMS: ACCOUNT_PROGRAMS } = await import("./auth-account/corpus.mjs");
  const recipes = load().conditions.flatMap(({ recipeIds }) => recipeIds);
  const covers = (recipe, programId) => programId === recipe || programId.startsWith(`${recipe}/`);
  for (const recipe of recipes.filter((id) => id.startsWith("auth-credential/"))) {
    assert.ok(
      PROGRAMS.some(({ id }) => covers(recipe, id)),
      `closure recipe ${recipe} has no corpus program`,
    );
  }
  for (const recipe of recipes.filter((id) => id.startsWith("auth-account/"))) {
    assert.ok(
      ACCOUNT_PROGRAMS.some(({ id }) => covers(recipe, id)),
      `referenced AUTH-ACCOUNT recipe ${recipe} has no corpus program`,
    );
  }
  const own = recipes.filter((id) => id.startsWith("auth-credential/"));
  for (const { id } of PROGRAMS) {
    assert.ok(
      own.some((recipe) => covers(recipe, id)),
      `corpus program ${id} belongs to no closure recipe`,
    );
  }
});

test("the validation program offers every reserved claim name", async () => {
  const { PROGRAMS } = await import("./auth-credential/corpus.mjs");
  const validation = PROGRAMS.find(({ id }) => id === "auth-credential/custom-token/validation");
  const offered = Object.values(validation.tokens)
    .flatMap(({ claims }) => Object.keys(claims ?? {}))
    .filter((name) => reservedClaims.includes(name));
  assert.deepEqual(offered.toSorted(), reservedClaims.toSorted());
});
