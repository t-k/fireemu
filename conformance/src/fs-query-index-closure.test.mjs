import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { PROGRAMS } from "./fs-query-index/corpus.mjs";
import { DIVERGENCES, RANGE_ROWS } from "./fs-query-index/divergences.mjs";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FS-QUERY-INDEX.json", import.meta.url),
);

// The frozen FS-QUERY-INDEX inventory. Adding or removing a row requires a new production
// mismatch or an uncovered acceptance requirement, and an edit here in the same commit.
const requiredConditions = new Set([
  "FS-QUERY-INDEX/field-filters",
  "FS-QUERY-INDEX/unary-filters",
  "FS-QUERY-INDEX/composite-filters",
  "FS-QUERY-INDEX/filter-validation",
  "FS-QUERY-INDEX/query-limits",
  "FS-QUERY-INDEX/order-by",
  "FS-QUERY-INDEX/cursors",
  "FS-QUERY-INDEX/offset-limit",
  "FS-QUERY-INDEX/projection",
  "FS-QUERY-INDEX/collection-group",
  "FS-QUERY-INDEX/aggregation",
  "FS-QUERY-INDEX/vector",
  "FS-QUERY-INDEX/partition-query",
  "FS-QUERY-INDEX/explain",
  "FS-QUERY-INDEX/index-selection",
  "FS-QUERY-INDEX/read-time",
  "FS-QUERY-INDEX/request-shape",
  "FS-QUERY-INDEX/pipeline-standard-refusal",
  "FS-QUERY-INDEX/grpc-transport",
  "FS-QUERY-INDEX/final-artifact-regression",
  "FS-QUERY-INDEX/closure-review",
]);

// The parent's named surfaces (docs/compatibility/ip-fs-production-compatibility.md, the
// FS-QUERY-INDEX row) and the condition that observes each.
const parentSurfaces = {
  filters: [
    "field-filters",
    "unary-filters",
    "composite-filters",
    "filter-validation",
    "query-limits",
  ],
  projection: ["projection"],
  sort: ["order-by"],
  cursor: ["cursors"],
  offset: ["offset-limit"],
  limit: ["offset-limit"],
  "collection group": ["collection-group"],
  aggregation: ["aggregation"],
  vector: ["vector"],
  PartitionQuery: ["partition-query"],
  Explain: ["explain"],
  "index acceptance/refusal": ["index-selection"],
};

const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

const load = () => JSON.parse(readFileSync(closurePath, "utf8"));

/** The response paths each owner decision lets a row differ at. */
const DECISION_PATHS = {
  S4: [/\.error\.message$/, /\.indexesUsed\.\d+\.properties$/, /\.index_entries_scanned$/],
  S5: [/\.partitions\.\d+(\.values\.0\.referenceValue)?$/, /\.aggregateFields\.c\.integerValue$/],
};

/** Whether a condition covers the partition range rows, whose totals must be recorded. */
const rowsOwnRanges = (condition) =>
  RANGE_ROWS.some((row) =>
    condition.recipeIds.some(
      (recipe) => recipe === "fs-query-index" || row.startsWith(`${recipe}/`),
    ),
  );
const readRepo = (path) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), "utf8"));

test("FS-QUERY-INDEX closure inventory cannot silently omit a declared condition", () => {
  const closure = load();
  assert.equal(closure.parent, "FS-QUERY-INDEX");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.equal(closure.oracle.project, "fireemu-oracle-query");
  assert.equal(closure.oracle.database, "(default)");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const [surface, owners] of Object.entries(parentSurfaces)) {
    for (const owner of owners) {
      assert.ok(ids.includes(`FS-QUERY-INDEX/${owner}`), `${surface} is observed by ${owner}`);
    }
  }
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    assert.ok(typeof condition.source === "string" && condition.source.length > 0, label);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0, label);
    assert.ok(statuses.has(condition.status), `${label}: unknown status`);
    if (condition.status !== "VERIFIED") continue;
    const runs = condition.evidence?.productionRecordings ?? [];
    assert.ok(runs.length > 0, `${label}: names its production runs`);
    for (const run of runs) {
      assert.equal(run.recordings, 2, `${label}: every production run is recorded twice`);
      assert.equal(run.project, "fireemu-oracle-query", label);
    }
    assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/, label);
    const comparison = readRepo(condition.evidence.comparisonPath);
    assert.equal(comparison.kind, "fs-query-index-comparison-v1", label);
    assert.equal(comparison.artifactSha256, condition.evidence.finalArtifactSha256, label);
    const covered = (row) => {
      const program = row.split("#")[0];
      return condition.recipeIds.some(
        (r) => r === "fs-query-index" || program === r || program.startsWith(`${r}/`),
      );
    };
    // The comparison is bound to the committed fixture, covers every corpus step exactly once,
    // and its figures and recordings are the ones this condition claims.
    const fixtureText = readFileSync(
      fileURLToPath(new URL("../fs-query-index-production.json", import.meta.url)),
      "utf8",
    );
    assert.equal(
      comparison.fixtureSha256,
      createHash("sha256").update(fixtureText).digest("hex"),
      `${label}: the comparison was made against the committed fixture`,
    );
    const steps = PROGRAMS.flatMap((program) =>
      program.steps.map((step) => `${program.id}#${step.id}`),
    );
    assert.deepEqual(
      comparison.rows.map(({ row }) => row).toSorted(),
      steps.toSorted(),
      `${label}: the comparison covers every corpus step once`,
    );
    if (rowsOwnRanges(condition)) {
      assert.ok(comparison.rangeTotals, `${label}: the range totals are recorded`);
      assert.equal(comparison.rangeTotals.production, comparison.rangeTotals.fireemu, label);
    }
    const rows = comparison.rows.filter(({ row }) => covered(row));
    const counted = {};
    for (const { status } of rows) counted[status] = (counted[status] ?? 0) + 1;
    // The review covers the whole lane, so its figures are the comparison's summary.
    assert.deepEqual(
      condition.evidence.rows,
      label === "FS-QUERY-INDEX/closure-review" ? comparison.summary : counted,
      `${label}: its figures are the comparison's`,
    );
    const fixture = JSON.parse(fixtureText);
    for (const program of new Set(rows.map(({ row }) => row.split("#")[0]))) {
      const { recordedAt, gitSha } = fixture.programs[program];
      assert.ok(
        runs.some((run) => run.recordedAt === recordedAt && run.gitSha === gitSha),
        `${label}: the recording of ${program} (${recordedAt}) is named`,
      );
    }
    // A row may differ only as an owner-decided, documented divergence of this condition.
    const divergences = condition.evidence.documentedDivergences ?? [];
    for (const divergence of divergences) {
      assert.equal(divergence.decidedBy, "owner", `${label}: ${divergence.row}`);
      assert.ok(divergence.decidedOn && divergence.reason, divergence.row);
      assert.ok(
        closure.scopeDecisions.some(({ id }) => id === divergence.scopeDecision),
        `${label}: ${divergence.row} names a recorded scope decision`,
      );
      const compared = comparison.rows.find(({ row }) => row === divergence.row);
      assert.equal(
        compared?.status,
        "DIVERGENCE_APPROVED",
        `${label}: ${divergence.row} differs only as its decision allows`,
      );
      assert.equal(compared.decision, divergence.scopeDecision, `${label}: ${divergence.row}`);
      // The committed evidence carries no bodies, but its difference paths must lie within
      // what the decision names.
      const allowed = DECISION_PATHS[divergence.scopeDecision];
      assert.ok(
        compared.differences?.length > 0,
        `${label}: ${divergence.row} lists its differences`,
      );
      for (const path of compared.differences) {
        assert.ok(
          allowed.some((pattern) => pattern.test(path)),
          `${label}: ${divergence.row} differs at ${path}, outside ${divergence.scopeDecision}`,
        );
      }
    }
    const documented = new Set(divergences.map(({ row }) => row));
    const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC"]);
    const off = rows
      .filter(({ status, row }) => !passing.has(status) && !documented.has(row))
      .map(({ row }) => row);
    if (label === "FS-QUERY-INDEX/closure-review") {
      assert.equal(closure.closureReview?.decision, "APPROVED", label);
      assert.equal(
        closure.closureReview.finalArtifactSha256,
        condition.evidence.finalArtifactSha256,
        `${label}: the approval names the artifact the evidence is bound to`,
      );
      continue;
    }
    assert.ok(rows.length > 0, `${label}: has compared rows`);
    if (label === "FS-QUERY-INDEX/final-artifact-regression") {
      // The regression's figures are read from the committed evidence, not typed by hand.
      assert.deepEqual(condition.evidence.rows, comparison.summary, label);
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

test("the comparison's approved divergences are the documented ones", () => {
  const closure = load();
  const documented = closure.conditions.flatMap(({ conditionId, evidence }) =>
    (evidence?.documentedDivergences ?? []).map((divergence) => ({
      conditionId,
      ...divergence,
    })),
  );
  const approved = DIVERGENCES.flatMap(({ decision, rows }) =>
    rows.map((row) => ({ row, decision })),
  );
  const programs = new Map(PROGRAMS.map((program) => [program.id, program]));
  for (const { row, decision } of approved) {
    const [programId, stepId] = row.split("#");
    assert.ok(
      programs.get(programId)?.steps.some(({ id }) => id === stepId),
      `${row} is a corpus step`,
    );
    const entries = documented.filter((divergence) => divergence.row === row);
    // Before the evidence is written no condition documents a row yet.
    if (documented.length === 0) continue;
    assert.equal(entries.length, 1, `${row} is documented by exactly one condition`);
    assert.equal(entries[0].scopeDecision, decision, row);
  }
  for (const { row } of documented) {
    assert.ok(
      approved.some((entry) => entry.row === row),
      `${row} is approved in divergences.mjs`,
    );
  }
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const { decision } of DIVERGENCES) assert.ok(decided.has(decision), decision);
});

test("scope decisions are recorded, not implied", () => {
  const closure = load();
  const decided = new Set(closure.scopeDecisions.map(({ id }) => id));
  for (const id of ["Q1", "Q2", "Q3", "Q4a", "Q4b", "Q4c", "Q4d", "S1", "S2", "S3", "S4", "S5"]) {
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
  const recipes = load()
    .conditions.flatMap(({ recipeIds }) => recipeIds)
    .filter((id) => id.startsWith("fs-query-index/"));
  const covers = (recipe, programId) => programId === recipe || programId.startsWith(`${recipe}/`);
  for (const recipe of recipes) {
    assert.ok(
      PROGRAMS.some(({ id }) => covers(recipe, id)),
      `closure recipe ${recipe} has no corpus program`,
    );
  }
  for (const { id } of PROGRAMS) {
    const owners = recipes.filter((recipe) => covers(recipe, id));
    assert.equal(owners.length, 1, `corpus program ${id} belongs to exactly one closure recipe`);
  }
});

test("the local configuration uses the lane indexes under the strict profile", () => {
  const config = readRepo("conformance/fs-query-index.fireemu.json");
  assert.equal(config.profile, "strict");
  assert.equal(config.firestore.edition, "standard");
  assert.equal(config.firestore.indexFile, "conformance/fs-query-index.indexes.json");
  assert.equal(config.daemon?.clockStart, undefined, "run-window masking needs the wall clock");
  // The sandbox database's createTime (gcloud firestore databases describe), so read times
  // within the retention hour but before the daemon started behave as they do there.
  assert.equal(config.firestore.databaseCreateTime, "2026-09-23T23:01:49.496838Z");
  // The lane file is a superset of the shared file other campaigns bind (scope decision Q2).
  const shared = readRepo("conformance/firestore.indexes.json");
  const lane = readRepo("conformance/fs-query-index.indexes.json");
  const text = (value) => JSON.stringify(value);
  for (const index of shared.indexes)
    assert.ok(
      lane.indexes.some((i) => text(i) === text(index)),
      text(index),
    );
  for (const override of shared.fieldOverrides)
    assert.ok(
      lane.fieldOverrides.some((o) => text(o) === text(override)),
      text(override),
    );
});
