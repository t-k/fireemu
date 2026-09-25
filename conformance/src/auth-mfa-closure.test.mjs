import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/AUTH-MFA.json", import.meta.url),
);

// The frozen AUTH-MFA inventory. Adding or removing a row requires a new production
// mismatch or an uncovered acceptance requirement, and an edit here in the same commit.
const requiredConditions = new Set([
  "AUTH-MFA/disabled-project",
  "AUTH-MFA/project-config",
  "AUTH-MFA/totp-enrollment",
  "AUTH-MFA/totp-sign-in",
  "AUTH-MFA/withdrawal-and-revocation",
  "AUTH-MFA/sms",
  "AUTH-MFA/interactions",
  "AUTH-MFA/admin-factors",
  "AUTH-MFA/other-first-factors",
  "AUTH-MFA/second-factor-claims",
  "AUTH-MFA/pending-credential-lifetime",
  "AUTH-MFA/enrollment-session-lifetime",
  "AUTH-MFA/final-artifact-regression",
  "AUTH-MFA/closure-review",
]);

const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

// The comparison statuses that match production (conformance/src/auth-mfa/run.mjs `classify`):
// the same answer; one of the two recordings' answers where they differed; for the phone control
// starts of auth-mfa/lifetime, an answer production recorded for such a row (it depends on the
// second the sign-in and the enrollment fell in); and a quota-limited row whose re-observation
// matched with fireemu giving the re-observed answer on the row itself (scope decision M10).
const MATCHING = new Set([
  "MATCH",
  "MATCH_NONDETERMINISTIC",
  "MATCH_TIMING_DEPENDENT",
  "REOBSERVED_MATCH",
]);

const load = () => JSON.parse(readFileSync(closurePath, "utf8"));
const readJson = (path) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), "utf8"));

// A comparison is evidence only for the committed fixture it names and only when it covers every
// recorded row of that fixture: a re-recorded fixture or a dropped row breaks the binding.
const FIXTURES = {
  "auth-mfa-comparison-v1": "conformance/auth-mfa-production.json",
  "auth-action-comparison-v1": "conformance/auth-action-production.json",
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

test("AUTH-MFA closure inventory cannot silently omit a declared condition", () => {
  const closure = load();
  assert.equal(closure.parent, "AUTH-MFA");
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
          r === "auth-mfa" ||
          r === "auth-action" ||
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
      .filter(({ status, row }) => !MATCHING.has(status) && !documented.has(row))
      .map(({ row }) => row);
    if (label === "AUTH-MFA/closure-review") {
      assert.equal(closure.closureReview?.decision, "APPROVED", label);
      assert.equal(
        closure.closureReview.finalArtifactSha256,
        condition.evidence.finalArtifactSha256,
        `${label}: the approval names the artifact the evidence is bound to`,
      );
    } else if (label === "AUTH-MFA/final-artifact-regression") {
      // Every other condition of this parent is bound to the same artifact.
      for (const other of closure.conditions) {
        assert.equal(
          other.evidence?.finalArtifactSha256,
          condition.evidence.finalArtifactSha256,
          `${other.conditionId}: bound to the final artifact`,
        );
      }
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
  for (const id of ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10", "M10a", "M10b", "M11", "M12", "M13", "M14"]) {
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

test("closure recipes and corpus programs cover each other", async () => {
  const { PROGRAMS } = await import("./auth-mfa/corpus.mjs");
  const recipes = load().conditions.flatMap(({ recipeIds }) => recipeIds);
  const covers = (recipe, programId) => programId === recipe || programId.startsWith(`${recipe}/`);
  const own = recipes.filter((id) => id.startsWith("auth-mfa/"));
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

test("only the first program runs with MFA off, and only the email-link program switches links on", async () => {
  const { PROGRAMS } = await import("./auth-mfa/corpus.mjs");
  const { MFA_CONFIGS } = await import("./auth-mfa/guard.mjs");
  const [first, ...rest] = PROGRAMS;
  assert.equal(first.config, undefined, first.id);
  for (const { id, config, steps } of rest) {
    assert.deepEqual(config.mfa, MFA_CONFIGS.enabled, id);
    const links = steps.some(({ path }) => path.endsWith("signInWithEmailLink"));
    assert.equal("signIn.email.passwordRequired" in config, links, id);
    if (links) assert.equal(config["signIn.email.passwordRequired"], false, id);
  }
  const minting = PROGRAMS.filter(({ tokens }) => tokens).map(({ id }) => id);
  assert.deepEqual(minting, ["auth-mfa/first-factor/custom-token"]);
});

test("every aged row is followed at once by a same-account control (owner decision M4)", async () => {
  const { PROGRAMS } = await import("./auth-mfa/corpus.mjs");
  const lifetime = PROGRAMS.at(-1);
  assert.equal(lifetime.id, "auth-mfa/lifetime");
  for (const program of PROGRAMS.filter(({ id }) => id.startsWith("auth-mfa/lifetime"))) {
    checkAgedRows(program);
  }
  const pendingAges = lifetime.steps
    .filter(({ id }) => id.startsWith("aged-pending-"))
    .map((row) => row.age.seconds);
  assert.deepEqual(pendingAges, [300, 450, 600, 1800]);
});

function checkAgedRows({ id: programId, steps }) {
  const agedRows = steps.filter(({ id }) => id.startsWith("aged-"));
  assert.ok(agedRows.length > 0, programId);
  // The wait is on the aged row itself, or on the fresh sign-in or SMS start right before it.
  const waitOf = (row) => {
    const previous = steps[steps.indexOf(row) - 1];
    if (row.age) return row;
    return /^(fresh-sign-in|sms-start-aged)-/.test(previous?.id ?? "") ? previous : undefined;
  };
  for (const row of agedRows) {
    const waiting = waitOf(row);
    assert.ok(waiting?.age, `${row.id} waits for its age`);
    assert.ok(waiting.age.seconds <= 1800, row.id);
    const index = steps.indexOf(row);
    const name = row.id.replace(/^aged-(pending|session|token-start)-/, "");
    const [control, finalize] = steps.slice(index + 1, index + 3);
    assert.match(control.id, new RegExp(`^control-(pending|start|sign-in)-${name}$`), row.id);
    assert.match(finalize.id, new RegExp(`^control-(finalize|session|start)-${name}$`), row.id);
    // An enrollment session is finalized with a token of a sign-in made after the wait.
    if (row.id.startsWith("aged-session-")) {
      assert.equal(row.body.idToken.$from, `fresh-sign-in-${name}:idToken`, row.id);
      assert.equal(control.body.idToken.$from, `fresh-sign-in-${name}:idToken`, row.id);
    }
  }
  // Every aged resource is acquired before the first wait.
  const waits = steps.filter((step) => step.age);
  const firstWait = steps.indexOf(waits[0]);
  for (const {
    age: { from },
  } of waits) {
    assert.ok(
      steps.findIndex(({ id }) => id === from) < firstWait,
      `${from} is acquired before the first wait`,
    );
  }
}

test("a passing status other than MATCH appears only where its rule applies", async () => {
  const { REOBSERVED } = await import("./auth-mfa/run.mjs");
  const comparison = readJson("spec/compatibility/closure/evidence/AUTH-MFA-comparison.json");
  const fixture = readFixture("conformance/auth-mfa-production.json").programs;
  const status = new Map(comparison.rows.map(({ row, status: s }) => [row, s]));
  for (const { row, status: s } of comparison.rows) {
    const [program, step] = row.split("#");
    if (s === "MATCH_NONDETERMINISTIC") {
      assert.ok(fixture[program]?.second?.[step] !== undefined, `${row}: the recordings differed`);
    } else if (s === "MATCH_TIMING_DEPENDENT") {
      assert.match(row, /^auth-mfa\/lifetime#control-start-s\d+$/, row);
    } else if (s === "REOBSERVED_MATCH") {
      assert.ok(REOBSERVED[row], `${row}: a re-observed row`);
      assert.equal(status.get(REOBSERVED[row]), "MATCH", `${row}: its re-observation matched`);
    }
  }
});

test("each verified condition's row counts are its comparisons' own", () => {
  const closure = load();
  const covers = (recipes, row) => {
    const program = row.split("#")[0];
    return recipes.some(
      (r) =>
        ["auth-mfa", "auth-action", "auth-credential", "auth-account"].includes(r) ||
        program === r ||
        program.startsWith(`${r}/`),
    );
  };
  for (const condition of closure.conditions) {
    if (!condition.evidence) continue;
    const counts = {};
    for (const path of condition.evidence.comparisonPaths) {
      for (const { row, status } of readJson(path).rows) {
        if (covers(condition.recipeIds, row)) counts[status] = (counts[status] ?? 0) + 1;
      }
    }
    assert.deepEqual(counts, condition.evidence.rows, condition.conditionId);
  }
});

test("the lifetime programs sample exactly the decided ages (M4, M8, M13)", async () => {
  const { PROGRAMS } = await import("./auth-mfa/corpus.mjs");
  const ages = (programId, prefix) => {
    const { steps } = PROGRAMS.find(({ id }) => id === programId);
    return steps.filter(({ id, age }) => id.startsWith(prefix) && age).map(({ age }) => age.seconds);
  };
  assert.deepEqual(ages("auth-mfa/lifetime-short", "aged-pending-q"), [60, 120, 180, 240, 290]);
  assert.deepEqual(ages("auth-mfa/lifetime-short", "sms-start-aged-m"), [150, 300]);
  assert.deepEqual(ages("auth-mfa/lifetime-short", "aged-token-start-r"), [240, 330]);
  assert.deepEqual(ages("auth-mfa/lifetime-sms", "sms-start-aged-m"), [450, 600, 1800]);
});

test("an SMS pending row's control is a new sign-in of the same account that completes", async () => {
  const { PROGRAMS } = await import("./auth-mfa/corpus.mjs");
  for (const programId of ["auth-mfa/lifetime-short", "auth-mfa/lifetime-sms"]) {
    const { steps } = PROGRAMS.find(({ id }) => id === programId);
    const byId = new Map(steps.map((step) => [step.id, step]));
    for (const aged of steps.filter(({ id }) => /^aged-pending-m\d+$/.test(id))) {
      const name = aged.id.replace("aged-pending-", "");
      const index = steps.indexOf(aged);
      assert.deepEqual(
        steps.slice(index + 1, index + 4).map(({ id }) => id),
        [`control-pending-${name}`, `control-start-${name}`, `control-finalize-${name}`],
        aged.id,
      );
      const source = byId.get(aged.body.mfaPendingCredential.$from.split(":")[0]);
      const control = byId.get(`control-pending-${name}`);
      assert.equal(control.body.email, source.body.email, `${aged.id}: same account`);
      for (const id of [`control-start-${name}`, `control-finalize-${name}`]) {
        assert.equal(
          byId.get(id).body.mfaPendingCredential.$from,
          `control-pending-${name}:mfaPendingCredential`,
          id,
        );
      }
      assert.equal(
        byId.get(`control-finalize-${name}`).body.phoneVerificationInfo.sessionInfo.$from,
        `control-start-${name}:phoneResponseInfo.sessionInfo`,
      );
    }
  }
});
