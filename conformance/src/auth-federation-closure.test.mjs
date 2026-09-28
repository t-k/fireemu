import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/AUTH-FEDERATION.json", import.meta.url),
);

// The frozen AUTH-FEDERATION inventory (frozen 2026-09-27 after the owner decisions O1 to O6). Adding or removing a row requires a new production
// mismatch or an uncovered acceptance requirement, and an edit here in the same commit.
const requiredConditions = new Set([
  "AUTH-FEDERATION/provider-config-oidc",
  "AUTH-FEDERATION/provider-config-saml",
  "AUTH-FEDERATION/provider-config-default-supported",
  "AUTH-FEDERATION/provider-enablement",
  "AUTH-FEDERATION/oidc-token-verification",
  "AUTH-FEDERATION/oidc-nonce",
  "AUTH-FEDERATION/oidc-replay",
  "AUTH-FEDERATION/saml-response-verification",
  "AUTH-FEDERATION/saml-nameid-and-attributes",
  "AUTH-FEDERATION/create-auth-uri-provider",
  "AUTH-FEDERATION/request-uri-session",
  "AUTH-FEDERATION/idp-new-account",
  "AUTH-FEDERATION/idp-returning-account",
  "AUTH-FEDERATION/collision-verified-email",
  "AUTH-FEDERATION/collision-unverified-email",
  "AUTH-FEDERATION/link-with-id-token",
  "AUTH-FEDERATION/duplicate-email-mode",
  "AUTH-FEDERATION/pending-token",
  "AUTH-FEDERATION/idp-claims-sign-in",
  "AUTH-FEDERATION/idp-claims-refresh",
  "AUTH-FEDERATION/idp-claims-session-cookie",
  "AUTH-FEDERATION/third-party-refusals",
  "AUTH-FEDERATION/final-artifact-regression",
  "AUTH-FEDERATION/closure-review",
]);

/** The fireemu configuration each condition's rows are compared under (F1; AUTH-CONFIG-SDK K5). */
const projections = new Set(["strict", "strict-unsigned-emulator", "emulator"]);

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
  "auth-federation-comparison-v1": "conformance/auth-federation-production.json",
  "auth-federation-saml-comparison-v1": "conformance/auth-federation-saml-production.json",
  "auth-config-sdk-comparison-v1": "conformance/auth-config-sdk-production.json",
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

const EVIDENCE = "spec/compatibility/closure/evidence/AUTH-FEDERATION-comparison.json";
const noEvidence = !existsSync(fileURLToPath(new URL(`../../${EVIDENCE}`, import.meta.url)));

test(
  "the fixture binding refuses a stale digest and a dropped row",
  {
    skip: noEvidence && "no comparison has been exported yet",
  },
  () => {
    const comparison = readJson(EVIDENCE);
    assert.doesNotThrow(() => assertBoundToFixture(comparison, "committed"));
    assert.throws(
      () => assertBoundToFixture({ ...comparison, fixtureSha256: "0".repeat(64) }, "stale"),
      /committed conformance\/auth-federation-production.json/,
    );
    assert.throws(
      () => assertBoundToFixture({ ...comparison, rows: comparison.rows.slice(1) }, "dropped"),
      /exactly the recorded rows/,
    );
    assert.throws(
      () => assertBoundToFixture({ ...comparison, kind: "unknown" }, "kind"),
      /unknown comparison kind/,
    );
  },
);

test("AUTH-FEDERATION closure inventory cannot silently omit a declared condition", () => {
  const closure = load();
  assert.equal(closure.parent, "AUTH-FEDERATION");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    assert.ok(typeof condition.source === "string" && condition.source.length > 0, label);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0, label);
    assert.ok(statuses.has(condition.status), `${label}: unknown status`);
    assert.ok(condition.configProjections.length > 0, label);
    for (const projection of condition.configProjections)
      assert.ok(projections.has(projection), `${label}: unknown projection ${projection}`);
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
          r === "auth-federation" ||
          r === "auth-config-sdk" ||
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
      .filter(({ status, row }) => status !== "MATCH" && !documented.has(row))
      .map(({ row }) => row);
    if (label === "AUTH-FEDERATION/closure-review") {
      assert.equal(closure.closureReview?.decision, "APPROVED", label);
      assert.equal(
        closure.closureReview.finalArtifactSha256,
        condition.evidence.finalArtifactSha256,
        `${label}: the approval names the artifact the evidence is bound to`,
      );
    } else if (label === "AUTH-FEDERATION/final-artifact-regression") {
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
  for (let n = 1; n <= 10; n += 1) assert.ok(decided.has(`F${n}`), `scope decision F${n}`);
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

/** Both corpora: record-oidc's and record-saml's programs. */
async function corpusPrograms() {
  const { PROGRAMS } = await import("./auth-federation/corpus.mjs");
  const { SAML_PROGRAMS } = await import("./auth-federation/corpus-saml.mjs");
  return [...PROGRAMS, ...SAML_PROGRAMS];
}

test("closure recipes and corpus programs cover each other", async () => {
  const PROGRAMS = await corpusPrograms();
  const recipes = load().conditions.flatMap(({ recipeIds }) => recipeIds);
  const covers = (recipe, programId) => programId === recipe || programId.startsWith(`${recipe}/`);
  const own = recipes.filter((id) => id.startsWith("auth-federation/"));
  // A recipe may have no program yet only while its condition waits for the corpus.
  for (const condition of load().conditions) {
    if (condition.status === "PENDING_CORPUS") continue;
    for (const recipe of condition.recipeIds.filter((id) => id.startsWith("auth-federation/"))) {
      assert.ok(
        PROGRAMS.some(({ id }) => covers(recipe, id)),
        `closure recipe ${recipe} has no corpus program`,
      );
    }
  }
  for (const { id } of PROGRAMS) {
    assert.ok(
      own.some((recipe) => covers(recipe, id)),
      `corpus program ${id} belongs to no closure recipe`,
    );
  }
});

test("each program runs under the projection its condition names", async () => {
  const PROGRAMS = await corpusPrograms();
  const conditions = load().conditions.filter(({ recipeIds }) =>
    recipeIds.every((id) => id.startsWith("auth-federation/")),
  );
  for (const program of PROGRAMS) {
    const owner = conditions.find(({ recipeIds }) =>
      recipeIds.some((r) => program.id === r || program.id.startsWith(`${r}/`)),
    );
    assert.deepEqual([program.projection ?? "strict"], owner.configProjections, program.id);
  }
});
