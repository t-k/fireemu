import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

test("closure recipes and corpus programs cover each other", async () => {
  const { PROGRAMS } = await import("./fs-rules/corpus.mjs");
  const covers = (recipe, programId) => programId === recipe || programId.startsWith(`${recipe}/`);
  const own = load()
    .conditions.flatMap(({ recipeIds }) => recipeIds)
    .filter((id) => id.startsWith("fs-rules/"));
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

const readRepo = (path) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), "utf8"));

const PASSING = new Set(["MATCH", "MATCH_NONDETERMINISTIC", "DEPENDENCY_REFUSED"]);

test("a verified condition is bound to the committed comparison, fixture and final artifact", async () => {
  const { PROGRAMS } = await import("./fs-rules/corpus.mjs");
  const closure = load();
  const fixtureText = readFileSync(
    fileURLToPath(new URL("../fs-rules-production.json", import.meta.url)),
    "utf8",
  );
  const fixture = JSON.parse(fixtureText);
  const steps = PROGRAMS.flatMap((program) =>
    program.steps.filter((step) => !step.action).map((step) => `${program.id}#${step.id}`),
  );
  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    if (condition.status !== "VERIFIED") continue;
    const evidence = condition.evidence ?? {};
    assert.match(evidence.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/, label);
    assert.match(evidence.sourceCommit ?? "", /^[0-9a-f]{40}$/, label);
    const comparison = readRepo(evidence.comparisonPath);
    assert.equal(comparison.kind, "fs-rules-comparison-v1", label);
    assert.equal(comparison.artifactSha256, evidence.finalArtifactSha256, label);
    assert.equal(
      comparison.fixtureSha256,
      createHash("sha256").update(fixtureText).digest("hex"),
      `${label}: the comparison was made against the committed fixture`,
    );
    assert.deepEqual(
      comparison.rows.map(({ row }) => row).toSorted(),
      steps.toSorted(),
      `${label}: the comparison covers every corpus step once`,
    );
    const off = comparison.rows.filter(({ status }) => !PASSING.has(status));
    assert.deepEqual(off, [], `${label}: every row passes`);
    if (label === "FS-RULES/final-artifact-regression") {
      assert.deepEqual(evidence.rows, comparison.summary, label);
      // The other parents' comparisons ran on the same artifact and are recorded with it.
      for (const parent of ["auth-account", "auth-credential", "fs-query-index"]) {
        const result = evidence.regressions?.[parent];
        assert.ok(result, `${label}: ${parent} is recorded`);
        assert.equal(result.artifactSha256, evidence.finalArtifactSha256, `${label}: ${parent}`);
        assert.match(
          result.comparisonPath ?? "",
          /^spec\/compatibility\/closure\/evidence\/FS-RULES-.*-regression\.json$/,
          `${label}: ${parent} has committed row evidence`,
        );
        const regression = readRepo(result.comparisonPath);
        assert.equal(regression.kind, `${parent}-comparison-v1`, `${label}: ${parent}`);
        assert.equal(regression.artifactSha256, result.artifactSha256, `${label}: ${parent}`);
        assert.deepEqual(regression.summary, result.summary, `${label}: ${parent}`);
        const regressionFixture = readFileSync(
          fileURLToPath(new URL(`../${parent}-production.json`, import.meta.url)),
          "utf8",
        );
        const currentFixtureSha256 = createHash("sha256").update(regressionFixture).digest("hex");
        if (parent === "fs-query-index" && currentFixtureSha256 !== regression.fixtureSha256) {
          // The integrated tree carries the query fixture after the FS-DATA-WRITE-LIST lane
          // shared its harness: only the harness digests and their note changed. Restoring them
          // must reproduce the exact fixture the FS-RULES regression was compared against.
          const rebind = readRepo(
            "spec/compatibility/closure/evidence/FS-RULES-fs-query-index-fixture-rebind.json",
          );
          assert.equal(
            rebind.kind,
            "fs-rules-query-fixture-provenance-rebind-v1",
            `${label}: ${parent} rebind kind`,
          );
          assert.equal(
            rebind.fixturePath,
            "conformance/fs-query-index-production.json",
            `${label}: ${parent} rebind path`,
          );
          assert.equal(rebind.currentFixtureSha256, currentFixtureSha256);
          assert.equal(rebind.sourceFixtureSha256, regression.fixtureSha256);
          const sourceFixture = JSON.parse(regressionFixture);
          assert.deepEqual(
            Object.keys(rebind.sourceHarnessDigests).toSorted(),
            Object.keys(sourceFixture.programs).toSorted(),
            `${label}: ${parent} rebind programs`,
          );
          sourceFixture.recordedAgainst.note = rebind.sourceRecordedAgainstNote;
          for (const [programId, digest] of Object.entries(rebind.sourceHarnessDigests)) {
            assert.match(digest, /^[0-9a-f]{64}$/, `${label}: ${programId} harness digest`);
            sourceFixture.programs[programId].harnessDigest = digest;
          }
          assert.equal(
            createHash("sha256")
              .update(`${JSON.stringify(sourceFixture, null, 2)}\n`)
              .digest("hex"),
            regression.fixtureSha256,
            `${label}: ${parent} original fixture reconstruction`,
          );
        } else {
          assert.equal(
            regression.fixtureSha256,
            currentFixtureSha256,
            `${label}: ${parent} fixture`,
          );
        }
        assert.equal(
          regression.rows.length,
          Object.values(regression.summary).reduce((total, count) => total + count, 0),
          `${label}: ${parent} row count`,
        );
        const rowIds = regression.rows.map(({ row }) => row);
        assert.equal(rowIds.length, new Set(rowIds).size, `${label}: ${parent} unique row IDs`);
        const counted = {};
        for (const row of regression.rows) {
          counted[row.status] = (counted[row.status] ?? 0) + 1;
          if (row.status === "DIVERGENCE_APPROVED") {
            assert.ok(row.decision && row.differences?.length, `${label}: ${parent} approved row`);
          }
        }
        assert.deepEqual(counted, regression.summary, `${label}: ${parent} row statuses`);
        const parentEvidence = readRepo(
          `spec/compatibility/closure/evidence/${parent.toUpperCase()}-comparison.json`,
        );
        assert.deepEqual(regression.rows, parentEvidence.rows, `${label}: ${parent} original rows`);
        assert.ok(
          Object.keys(result.summary).every((status) =>
            ["MATCH", "MATCH_NONDETERMINISTIC", "DIVERGENCE_APPROVED"].includes(status),
          ),
          `${label}: ${parent} passes`,
        );
      }
      continue;
    }
    const covered = ({ row }) => {
      const program = row.split("#")[0];
      return condition.recipeIds.some((r) => program === r || program.startsWith(`${r}/`));
    };
    const rows = comparison.rows.filter(covered);
    assert.ok(rows.length > 0, `${label}: its programs have rows`);
    const counted = {};
    for (const { status } of rows) counted[status] = (counted[status] ?? 0) + 1;
    assert.deepEqual(evidence.rows, counted, `${label}: its figures are the comparison's`);
    const runs = evidence.productionRecordings ?? [];
    for (const run of runs) {
      assert.equal(run.recordings, 2, `${label}: every production run is recorded twice`);
      assert.equal(run.project, "fireemu-oracle-idp", label);
    }
    for (const program of new Set(rows.map(({ row }) => row.split("#")[0]))) {
      const { recordedAt, gitSha } = fixture.programs[program];
      assert.ok(
        runs.some((run) => run.recordedAt === recordedAt && run.gitSha === gitSha),
        `${label}: the recording of ${program} (${recordedAt}) is named`,
      );
    }
  }
});

test("a dependency-refused row depends on a compared step that matched", () => {
  const fixture = JSON.parse(
    readFileSync(fileURLToPath(new URL("../fs-rules-production.json", import.meta.url)), "utf8"),
  );
  const paths = new Set(
    load()
      .conditions.map(({ evidence }) => evidence?.comparisonPath)
      .filter(Boolean),
  );
  assert.ok(paths.size > 0);
  for (const path of paths) {
    const { rows } = readRepo(path);
    const status = new Map(rows.map(({ row, status }) => [row, status]));
    for (const { row } of rows.filter(({ status }) => status === "DEPENDENCY_REFUSED")) {
      const [program, step] = row.split("#");
      const recorded = fixture.programs[program]?.steps?.[step];
      const dependency = /^step (\S+) recorded nothing at \S+$/.exec(
        recorded?.unresolved ?? "",
      )?.[1];
      assert.ok(dependency, `${row}: production names the unresolved dependency`);
      assert.equal(recorded.dependencyTransient, false, `${row}: the dependency was not transient`);
      assert.equal(
        status.get(`${program}#${dependency}`),
        "MATCH",
        `${row}: ${dependency} was compared`,
      );
    }
  }
});
