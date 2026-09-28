import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

const MATCHING = new Set([
  "MATCH",
  "MATCH_NONDETERMINISTIC",
  "MATCH_TIMING_DEPENDENT",
  "REOBSERVED_MATCH",
]);

const FIXTURES = {
  "auth-tenant-blocking-comparison-v1": "conformance/auth-tenant-blocking-production.json",
  "auth-mfa-comparison-v1": "conformance/auth-mfa-production.json",
  "auth-action-comparison-v1": "conformance/auth-action-production.json",
  "auth-credential-comparison-v1": "conformance/auth-credential-production.json",
  "auth-account-comparison-v1": "conformance/auth-account-production.json",
};

/** The conditions observed locally only: production has no session reset or hook race. */
const LOCAL_ONLY = new Set([
  "AUTH-TENANT-BLOCKING/session-isolation",
  "AUTH-TENANT-BLOCKING/hook-concurrency",
]);

/** The lanes a recorded row may wait for before it is compared again (TB11). */
const AWAITED_LANES = new Set(["AUTH-FEDERATION", "FUNCTIONS-HTTP"]);

const repoText = (path) =>
  readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), "utf8");
const readJson = (path) => JSON.parse(repoText(path));
const covers = (recipe, programId) => programId === recipe || programId.startsWith(`${recipe}/`);

/** The recorded rows of a fixture, as `program#step`. */
function recordedRows(fixturePath) {
  return Object.entries(readJson(fixturePath).programs).flatMap(([program, { steps }]) =>
    Object.keys(steps).map((step) => `${program}#${step}`),
  );
}

/**
 * A comparison is bound to its committed fixture and covers exactly its recorded rows (for this
 * parent's fixture, the rows of the suite it compared: tenant or blocking).
 */
function assertBoundToFixture(comparison, label) {
  const fixturePath = FIXTURES[comparison.kind];
  assert.ok(fixturePath, `${label}: unknown comparison kind ${comparison.kind}`);
  assert.equal(
    comparison.fixtureSha256,
    createHash("sha256").update(repoText(fixturePath)).digest("hex"),
    `${label}: the comparison was made against the committed ${fixturePath}`,
  );
  const compared = comparison.rows.map(({ row }) => row).toSorted();
  let recorded = recordedRows(fixturePath);
  if (comparison.kind === "auth-tenant-blocking-comparison-v1") {
    const suites = new Set(compared.map((row) => row.split("/").slice(0, 2).join("/")));
    recorded = recorded.filter((row) => suites.has(row.split("/").slice(0, 2).join("/")));
  }
  assert.deepEqual(compared, recorded.toSorted(), `${label}: covers exactly the recorded rows`);
}

/** `recordedAt gitSha` of every program of this parent's fixture a recipe covers. */
function recordedRuns(recipes) {
  const runs = new Set();
  const { programs } = readJson(FIXTURES["auth-tenant-blocking-comparison-v1"]);
  for (const [program, { recordedAt, gitSha }] of Object.entries(programs)) {
    if (recipes.some((recipe) => covers(recipe, program))) runs.add(`${recordedAt} ${gitSha}`);
  }
  return [...runs].toSorted();
}

const regressionRecipes = new Set(["auth-mfa", "auth-action", "auth-credential", "auth-account"]);

test("each recorded condition is backed by committed comparisons of one artifact", () => {
  const closure = load();
  const artifacts = new Set(
    closure.conditions.map(({ evidence }) => evidence?.finalArtifactSha256),
  );
  assert.equal(artifacts.size, 1, "every condition is bound to the same final artifact");
  const [artifact] = artifacts;
  assert.match(artifact ?? "", /^[0-9a-f]{64}$/);
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    if (LOCAL_ONLY.has(label) || !["VERIFIED", "PRODUCTION_RECORDED"].includes(condition.status))
      continue;
    const { evidence } = condition;
    const runs = evidence.productionRecordings ?? [];
    for (const run of runs) {
      assert.equal(run.recordings, 2, `${label}: every production run is recorded twice`);
      assert.equal(run.project, "fireemu-oracle-idp", label);
    }
    assert.deepEqual(
      runs.map(({ recordedAt, gitSha }) => `${recordedAt} ${gitSha}`).toSorted(),
      recordedRuns(condition.recipeIds.filter((recipe) => !regressionRecipes.has(recipe))),
      `${label}: productionRecordings name the fixture's own recordings`,
    );
    const comparisons = (evidence.comparisonPaths ?? []).map(readJson);
    assert.ok(comparisons.length > 0, `${label}: names its comparisons`);
    for (const comparison of comparisons) {
      assert.equal(comparison.artifactSha256, artifact, `${label}: bound to the final artifact`);
      assertBoundToFixture(comparison, label);
    }
    const rows = comparisons.flatMap(({ rows: all }) =>
      all.filter(({ row }) =>
        condition.recipeIds.some(
          (recipe) => regressionRecipes.has(recipe) || covers(recipe, row.split("#")[0]),
        ),
      ),
    );
    assert.ok(rows.length > 0, `${label}: has compared rows`);
    const counts = {};
    for (const { status } of rows) counts[status] = (counts[status] ?? 0) + 1;
    assert.deepEqual(evidence.rows, counts, `${label}: its row counts are its comparisons' own`);
    const divergences = evidence.documentedDivergences ?? [];
    for (const divergence of divergences) {
      assert.equal(divergence.decidedBy, "owner", `${label}: ${divergence.row}`);
      assert.ok(divergence.decidedOn && divergence.reason && divergence.kind, divergence.row);
      assert.ok(decided.has(divergence.scopeDecision), `${label}: ${divergence.row}`);
    }
    const documented = new Set(divergences.map(({ row }) => row));
    const off = rows
      .filter(({ status, row }) => !MATCHING.has(status) && !documented.has(row))
      .map(({ row }) => row)
      .toSorted();
    const pending = evidence.pendingAfterIntegration ?? [];
    for (const { row, awaits } of pending) {
      assert.ok(AWAITED_LANES.has(awaits), `${label}: ${row} waits for a named lane`);
    }
    if (condition.status === "VERIFIED") {
      assert.deepEqual(off, [], `${label}: every row matches production`);
      assert.deepEqual(pending, [], `${label}: nothing is left for after the integration`);
    } else {
      // A recorded condition is not verified only because of the rows it names as waiting for
      // another lane, and it names every such row.
      assert.ok(
        off.length > 0,
        `${label}: a recorded condition with every row matching is verified`,
      );
      assert.deepEqual(pending.map(({ row }) => row).toSorted(), off, `${label}: pending rows`);
    }
  }
});

test("the local-only conditions name the tests that pin them", () => {
  const closure = load();
  for (const condition of closure.conditions.filter(({ conditionId }) =>
    LOCAL_ONLY.has(conditionId),
  )) {
    const label = condition.conditionId;
    if (condition.status !== "VERIFIED") continue;
    const local = condition.evidence?.localEvidence;
    assert.ok(local?.tests?.length > 0 && local?.fixedIn?.length > 0, label);
    for (const { path, name } of local.tests) {
      assert.match(repoText(path), new RegExp(`fn ${name}\\(`), `${label}: ${path} ${name}`);
    }
  }
});

test("blocking recipes and blocking corpus programs cover each other", async () => {
  const { BLOCKING_PROGRAMS } = await import("./auth-tenant-blocking/blocking-corpus.mjs");
  const recipes = load()
    .conditions.flatMap(({ recipeIds }) => recipeIds)
    .filter((id) => id.startsWith("atb/blocking/"));
  for (const recipe of recipes) {
    assert.ok(
      BLOCKING_PROGRAMS.some(({ id }) => covers(recipe, id)),
      `closure recipe ${recipe} has no blocking program`,
    );
  }
  for (const { id } of BLOCKING_PROGRAMS) {
    assert.ok(
      recipes.some((recipe) => covers(recipe, id)),
      `blocking program ${id} belongs to no closure recipe`,
    );
  }
});
