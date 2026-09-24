import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FS-CONFIG-LIFECYCLE.json", import.meta.url),
);

// The frozen FS-CONFIG-LIFECYCLE inventory. Adding or removing a row requires a new production
// mismatch or an uncovered acceptance requirement, and an edit here in the same commit.
const requiredConditions = new Set([
  "FS-CONFIG-LIFECYCLE/database-projection",
  "FS-CONFIG-LIFECYCLE/database-create",
  "FS-CONFIG-LIFECYCLE/database-delete",
  "FS-CONFIG-LIFECYCLE/database-patch",
  "FS-CONFIG-LIFECYCLE/database-mode-gating",
  "FS-CONFIG-LIFECYCLE/default-database-lifecycle",
  "FS-CONFIG-LIFECYCLE/project-boundary",
  "FS-CONFIG-LIFECYCLE/locations",
  "FS-CONFIG-LIFECYCLE/index-lifecycle",
  "FS-CONFIG-LIFECYCLE/index-query-effect",
  "FS-CONFIG-LIFECYCLE/field-index-config",
  "FS-CONFIG-LIFECYCLE/ttl-config",
  "FS-CONFIG-LIFECYCLE/operations",
  "FS-CONFIG-LIFECYCLE/export",
  "FS-CONFIG-LIFECYCLE/import",
  "FS-CONFIG-LIFECYCLE/export-format-interop",
  "FS-CONFIG-LIFECYCLE/bulk-delete",
  "FS-CONFIG-LIFECYCLE/grpc-admin-transport",
  "FS-CONFIG-LIFECYCLE/final-artifact-regression",
  "FS-CONFIG-LIFECYCLE/closure-review",
]);

// Scope decisions that must stay recorded (owner decisions of 2026-09-24 and the agent's
// delegated calls).
const requiredDecisions = [
  "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14",
  "C15", "C16",
];

// The managed-infrastructure methods C1 keeps out of scope. None of them may be a recipe.
const excludedSurfaces = ["backup", "backupSchedule", "restore", "clone", "pitr"];

// Where each condition is observed: the query sandbox's named databases, or (C9 only) the
// FS-DATA-WRITE bisection project at its cleanup.
const projects = {
  "FS-CONFIG-LIFECYCLE/default-database-lifecycle": "fireemu-fs-bisect-0924a",
};
const defaultProject = "fireemu-oracle-query";

const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

const load = () => JSON.parse(readFileSync(closurePath, "utf8"));
const fromRoot = (path) => fileURLToPath(new URL(`../../${path}`, import.meta.url));

test("FS-CONFIG-LIFECYCLE closure inventory cannot silently omit a declared condition", () => {
  const closure = load();
  assert.equal(closure.parent, "FS-CONFIG-LIFECYCLE");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    assert.ok(typeof condition.source === "string" && condition.source.length > 0, label);
    assert.ok(existsSync(fromRoot(condition.source.split("#")[0])), `${label}: source exists`);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0, label);
    assert.ok(statuses.has(condition.status), `${label}: unknown status`);
    for (const recipe of condition.recipeIds) {
      for (const excluded of excludedSurfaces) {
        assert.ok(
          !recipe.toLowerCase().includes(excluded.toLowerCase()),
          `${label}: ${recipe} names a surface C1 excludes`,
        );
      }
    }
    if (condition.status !== "VERIFIED") continue;
    const runs = condition.evidence?.productionRecordings ?? [];
    assert.ok(runs.length > 0, `${label}: names its production runs`);
    for (const run of runs) {
      assert.equal(run.recordings, 2, `${label}: every production run is recorded twice`);
      // The whole-corpus regression and its review span both projects; every other condition
      // names one.
      const allowed =
        label === "FS-CONFIG-LIFECYCLE/final-artifact-regression" ||
        label === "FS-CONFIG-LIFECYCLE/closure-review"
          ? [defaultProject, ...Object.values(projects)]
          : [projects[label] ?? defaultProject];
      assert.ok(allowed.includes(run.project), `${label}: ${run.project}`);
    }
    assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/, label);
    assert.ok(condition.evidence?.comparisonPath, label);
    // A verified row is backed by the committed comparison of the same artifact: every row
    // of its programs matches production, or is an owner-decided documented divergence.
    const comparison = JSON.parse(
      readFileSync(fromRoot(condition.evidence.comparisonPath), "utf8"),
    );
    assert.equal(comparison.artifactSha256, condition.evidence.finalArtifactSha256, label);
    const recipes = condition.recipeIds.filter(
      (id) => id === "fs-config" || id.startsWith("fs-config/"),
    );
    const covered = (row) => {
      const program = row.split("#")[0];
      return recipes.some((r) => r === "fs-config" || program === r || program.startsWith(`${r}/`));
    };
    const rows = comparison.rows.filter(({ row }) => covered(row));
    assert.ok(rows.length > 0, `${label}: has compared rows`);
    // The comparison is of the committed fixture, and the condition's counts are its rows.
    const fixture = readFileSync(fromRoot("conformance/fs-config-lifecycle-production.json"));
    assert.equal(
      comparison.fixtureSha256,
      createHash("sha256").update(fixture).digest("hex"),
      `${label}: the comparison is of the committed fixture`,
    );
    const counted = {};
    for (const { status } of rows) counted[status] = (counted[status] ?? 0) + 1;
    if (label !== "FS-CONFIG-LIFECYCLE/closure-review")
      assert.deepEqual(condition.evidence.rows, counted, `${label}: row counts`);
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
      .filter(({ status, row }) => !status.startsWith("MATCH") && !documented.has(row))
      .map(({ row }) => row);
    if (label === "FS-CONFIG-LIFECYCLE/closure-review") {
      assert.equal(closure.closureReview?.decision, "APPROVED", label);
      assert.equal(
        closure.closureReview.finalArtifactSha256,
        condition.evidence.finalArtifactSha256,
        `${label}: the approval names the artifact the evidence is bound to`,
      );
    } else if (label === "FS-CONFIG-LIFECYCLE/final-artifact-regression") {
      assert.deepEqual(condition.evidence.fsConfig, comparison.summary, label);
      // Every row that passes on one of production's two recordings is a variation production
      // itself showed, named with its reason and the recording it matches; no other row may.
      const variations = condition.evidence.productionVariations ?? [];
      for (const variation of variations)
        assert.ok(variation.reason, `${label}: ${variation.row} names why production varies`);
      assert.deepEqual(
        rows
          .filter(({ status }) => status === "MATCH_NONDETERMINISTIC")
          .map(({ row, matched }) => ({ row, matched })),
        variations.map(({ row, matched }) => ({ row, matched })),
        `${label}: production variations are listed with the recording they match`,
      );
      // Every row that passes only modulo id numbering is named, so the rule stays visible.
      assert.deepEqual(
        rows.filter(({ status }) => status === "MATCH_RELABELED").map(({ row }) => row),
        condition.evidence.relabeledRows ?? [],
        `${label}: relabeled rows are listed`,
      );
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
  for (const id of requiredDecisions) assert.ok(decided.has(id), `scope decision ${id}`);
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision && decision.decidedBy && decision.decidedOn, decision.id);
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

test("closure recipes and corpus programs cover each other", async (t) => {
  const corpusPath = new URL("./fs-config-lifecycle/corpus.mjs", import.meta.url);
  if (!existsSync(fileURLToPath(corpusPath))) {
    // Until the corpus lands, no condition may claim a recording.
    assert.ok(load().conditions.every(({ status }) => status === "PENDING_CORPUS"));
    t.skip("corpus not written yet");
    return;
  }
  const { PROGRAMS } = await import(corpusPath);
  const recipes = load()
    .conditions.flatMap(({ recipeIds }) => recipeIds)
    .filter((id) => id.startsWith("fs-config/"));
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

test("the contract lists the refusals the Admin API adds beyond production's", () => {
  // C14/C15: fireemu-only behaviour is documented; a new Admin-only refusal must be listed.
  const contract = JSON.parse(readFileSync(fromRoot("spec/compatibility/contract.json"), "utf8"));
  const entries = contract.surfaces
    .flatMap((surface) => surface.claims ?? [])
    .flatMap((claim) => claim.fireemuOnly ?? [])
    .filter((item) => item.behaviour.startsWith("The Firestore Admin API"));
  assert.equal(entries.length, 1, "one fireemuOnly entry describes the Admin API");
  const text = entries[0].behaviour;
  for (const refusal of [
    "third concurrent managed import answers RESOURCE_EXHAUSTED",
    "1,000,000 documents",
    "a document id carrying a slash",
    "a bucket belongs to the first project",
    "import from it",
    "resource name is not of the kind the method takes answers INVALID_ARGUMENT",
  ])
    assert.ok(text.includes(refusal), `contract names: ${refusal}`);
});

