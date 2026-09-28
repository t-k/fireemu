import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PROGRAMS as historicalPrograms } from "./firestore-probe/programs.mjs";
import { PROGRAMS as listPrograms } from "./fs-list/corpus.mjs";
import { PROGRAMS as queryPrograms } from "./fs-query-index/corpus.mjs";
import { approvedDivergence, crossRowChecks } from "./fs-query-index/divergences.mjs";
import { classify, differencePaths, programDigest } from "./fs-query-index/run.mjs";

const read = (path) => JSON.parse(readFileSync(new URL(`../../${path}`, import.meta.url), "utf8"));
const sha = (path) =>
  createHash("sha256")
    .update(readFileSync(new URL(`../../${path}`, import.meta.url)))
    .digest("hex");
const bundlePath = "spec/compatibility/closure/evidence/FS-DATA-WRITE-release-artifact.json";
const closure = read("spec/compatibility/closure/FS-DATA-WRITE.json");

function verifySeries(bundle, name, programs, fixturePath, expectedSummary, mutants = {}) {
  const series = bundle.series[name];
  const fixture = read(fixturePath);
  const report = mutants.report ?? read(series.reportPath);
  const local = mutants.local ?? read(series.localProjectionPath);
  assert.equal(series.reportSha256, sha(series.reportPath));
  assert.equal(series.localProjectionSha256, sha(series.localProjectionPath));
  assert.equal(series.fixtureSha256, sha(fixturePath));
  assert.equal(report.artifactSha256, bundle.binarySha256);
  assert.equal(report.fixtureSha256, series.fixtureSha256);
  assert.equal(local.sourceCommit, bundle.sourceCommit);
  assert.equal(local.binarySha256, bundle.binarySha256);
  assert.equal(local.sourceResultSha256, series.privateResultSha256);
  assert.deepEqual(report.summary, expectedSummary);
  const expectedRows = new Map();
  for (const program of programs) {
    const saved = fixture.programs[program.id];
    assert.ok(saved, program.id);
    assert.equal(saved.corpusDigest, programDigest(program), program.id);
    for (const step of program.steps) {
      const id = `${program.id}#${step.id}`;
      assert.ok(!expectedRows.has(id), `${id}: duplicate corpus row`);
      expectedRows.set(id, {
        production: saved.steps[step.id],
        alternative: saved.second?.[step.id],
      });
    }
  }
  assert.equal(report.rows.length, expectedRows.size);
  assert.deepEqual(new Set(report.rows.map(({ row }) => row)), new Set(expectedRows.keys()));
  assert.deepEqual(new Set(Object.keys(local.rows)), new Set(expectedRows.keys()));
  const independent = [];
  for (const exported of report.rows) {
    const { production, alternative } = expectedRows.get(exported.row);
    const fireemu = local.rows[exported.row];
    let status = classify({ stale: false, production, alternative, fireemu });
    const decision =
      name === "query" && status === "MISMATCH"
        ? approvedDivergence(exported.row, production, fireemu)
        : undefined;
    if (decision) status = "DIVERGENCE_APPROVED";
    independent.push({ row: exported.row, status, decision, production, fireemu });
  }
  if (name === "query") {
    const { demote, rangeTotals } = crossRowChecks(independent);
    assert.deepEqual(report.rangeTotals, rangeTotals);
    for (const row of independent) {
      if (demote.has(row.row) && row.status === "DIVERGENCE_APPROVED") {
        row.status = "MISMATCH";
        row.decision = undefined;
      }
    }
  }
  for (const [index, row] of independent.entries()) {
    assert.equal(report.rows[index].status, row.status, row.row);
    assert.equal(report.rows[index].decision, row.decision, row.row);
    if (name === "query") {
      const expectedPaths =
        row.status === "DIVERGENCE_APPROVED"
          ? differencePaths(row.production, row.fireemu)
          : undefined;
      assert.deepEqual(report.rows[index].differences, expectedPaths, row.row);
    }
  }
  assert.deepEqual(
    Object.fromEntries(
      [...new Set(independent.map(({ status }) => status))].map((status) => [
        status,
        independent.filter((row) => row.status === status).length,
      ]),
    ),
    expectedSummary,
  );
  return report;
}

test("one release artifact binds write, list, query and saved transaction evidence", () => {
  const bundle = read(bundlePath);
  assert.equal(bundle.sourceCommit, "da47b5e137a275576d00f6cd75be7e29e5aaa160");
  assert.equal(
    bundle.binarySha256,
    "eec383e576e5de8c63fd934ef55dde6592bb6b69888a7f00bb4129c6a9338593",
  );
  assert.equal(bundle.buildProfile, "release");
  assert.deepEqual(bundle.buildCommand, [
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "fireemu",
    "--message-format=json",
  ]);
  assert.deepEqual(
    new Set(Object.keys(bundle.series)),
    new Set(["write", "list", "query", "savedTransaction", "historical"]),
  );
  for (const series of Object.values(bundle.series)) {
    assert.equal(series.reportSha256, sha(series.reportPath));
    const report = read(series.reportPath);
    assert.equal(
      report.artifactSha256 ?? report.executableSha256 ?? report.binarySha256,
      bundle.binarySha256,
    );
  }
  const write = read(bundle.series.write.reportPath);
  const accepted = read(bundle.series.write.acceptedPath);
  const saved = read(bundle.series.savedTransaction.reportPath);
  assert.equal(write.sourceHead, bundle.sourceCommit);
  assert.equal(accepted.sourceHead, bundle.sourceCommit);
  assert.equal(accepted.executableSha256, bundle.binarySha256);
  assert.equal(bundle.series.write.acceptedSha256, sha(bundle.series.write.acceptedPath));
  assert.equal(saved.sourceCommit, bundle.sourceCommit);
  assert.equal(saved.buildProfile, "release");
  assert.equal(saved.newProductionRequests, 0);
  assert.equal(closure.closureReview.candidateSourceHead, bundle.sourceCommit);
  assert.equal(closure.closureReview.candidateExecutableSha256, bundle.binarySha256);
  for (const id of [
    "FS-DATA-WRITE/stream-transaction-precedence",
    "FS-WRITE-LIMITS-03/batch-undecodable-value",
    "FS-LIMIT-INDEX-ENTRY-BYTES",
    "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
  ]) {
    const condition = closure.conditions.find((row) => row.conditionId === id);
    assert.equal(condition.evidence.finalArtifactSha256, bundle.binarySha256, id);
    assert.equal(condition.evidence.sourceHead, bundle.sourceCommit, id);
  }
  assert.equal(closure.parentStatus, "COMPAT_VERIFIED");
});

const HISTORICAL_PATH =
  "spec/compatibility/closure/evidence/FS-DATA-WRITE-historical-regression.json";

test("the historical production regression ran on the release artifact and explains every open row", () => {
  const bundle = read(bundlePath);
  const report = read(HISTORICAL_PATH);
  assert.equal(bundle.series.historical.reportPath, HISTORICAL_PATH);
  assert.equal(bundle.series.historical.reportSha256, sha(HISTORICAL_PATH));
  assert.equal(report.command, "pnpm -C conformance firestore:check-production");
  assert.equal(report.sourceCommit, bundle.sourceCommit);
  assert.equal(report.binarySha256, bundle.binarySha256);
  // The launch receipt: the binary the command ran is the release artifact before and after.
  assert.equal(report.binarySha256Before, bundle.binarySha256);
  assert.equal(report.binarySha256After, bundle.binarySha256);
  assert.equal(report.configPath, "conformance/firestore-probe.fireemu.json");
  assert.equal(report.configSha256, sha(report.configPath));
  // The pinned historical inputs are the ones the command itself checks before running.
  const run = readFileSync(new URL("./firestore-probe/run.mjs", import.meta.url), "utf8");
  const pinned = (name) => new RegExp(`${name} =\\s*"sha256-([0-9a-f]{64})"`).exec(run)[1];
  assert.equal(report.inputs.programsSha256, pinned("HISTORICAL_PROGRAMS_DIGEST"));
  assert.equal(report.inputs.productionMatrixPath, "conformance/firestore-production-matrix.json");
  assert.equal(report.inputs.productionMatrixSha256, pinned("HISTORICAL_MATRIX_DIGEST"));
  assert.equal(sha(report.inputs.productionMatrixPath), report.inputs.productionMatrixSha256);
  assert.deepEqual(report.counts, {
    comparableRows: 322,
    knownMismatches: 16,
    indeterminateRows: 1,
    newMismatches: 0,
    newIndeterminateRows: 0,
  });
  const byClass = (kind) => report.rows.filter(({ classification }) => classification === kind);
  assert.equal(byClass("known-mismatch").length, 16);
  assert.equal(byClass("indeterminate").length, 1);
  assert.equal(report.rows.length, 17);
  assert.equal(new Set(report.rows.map(({ row }) => row)).size, 17);
  for (const row of report.rows) {
    assert.ok(row.reason?.length > 0, row.row);
    // Every open row cites the public matrix line that records it and at least one public
    // document that explains it.
    assert.ok(
      row.references.some(({ path }) => path === "conformance/FIRESTORE-PRODUCTION-MATRIX.md"),
      row.row,
    );
    assert.ok(
      row.references.some(({ path }) => path.startsWith("docs/")),
      `${row.row}: no public explanation`,
    );
    for (const reference of row.references) {
      assert.ok(!reference.path.includes("docs.local"), row.row);
      const lines = readFileSync(new URL(`../../${reference.path}`, import.meta.url), "utf8").split(
        "\n",
      );
      assert.ok(
        lines[reference.line - 1]?.includes(reference.contains),
        `${row.row}: ${reference.path}:${reference.line} does not contain ${reference.contains}`,
      );
    }
  }
  // An excluded row production answered with 200 on its real API is either compared row by row
  // on this release artifact elsewhere, or named as a follow-up of the closure review.
  const accepted = read(
    "spec/compatibility/closure/evidence/FS-DATA-WRITE-current-accepted-conditions.json",
  );
  const production = read(report.inputs.productionMatrixPath);
  const answer = (row) => {
    const [program, step] = row.split("#");
    return production.programs.find(({ id }) => id === program).steps[step].production;
  };
  const step = (row) => {
    const [program, id] = row.split("#");
    return historicalPrograms.find((entry) => entry.id === program).steps.find((s) => s.id === id);
  };
  for (const row of report.rows) {
    assert.equal(row.productionStatus, answer(row.row).status, row.row);
    assert.ok(Number.isInteger(row.fireemuStatus), row.row);
    if (row.row.startsWith("emulator/routes#")) {
      // The cited sources support "a row of the local-only program", not "an emulator-only route".
      assert.doesNotMatch(row.reason, /emulator-only route/i, row.row);
      // A production API route that production refused and fireemu serves cites the ticket that
      // explains it, or is a named follow-up.
      if (
        step(row.row).path.startsWith("/v1/") &&
        row.productionStatus >= 400 &&
        row.fireemuStatus < 300
      ) {
        assert.ok(
          row.references.some(
            ({ path }) => path === "docs/compatibility/fs-config-lifecycle-classification.md",
          ) || closure.closureReview.followUps.includes(row.row),
          `${row.row}: production refused, fireemu serves, and nothing explains it`,
        );
      }
    }
    for (const { conditionId, rows } of row.comparedElsewhere ?? []) {
      const condition = closure.conditions.find((entry) => entry.conditionId === conditionId);
      assert.equal(condition.status, "VERIFIED", conditionId);
      for (const id of rows) {
        const compared = accepted.conditions[conditionId].rows.find((entry) => entry.id === id);
        assert.equal(compared?.comparisonResult, "MATCH", id);
      }
    }
    const served = answer(row.row).status >= 200 && answer(row.row).status < 300;
    if (row.row.startsWith("emulator/routes#") && served && !row.comparedElsewhere) {
      assert.ok(
        closure.closureReview.followUps.includes(row.row),
        `${row.row}: unexplained exclusion`,
      );
    }
  }
  const text = JSON.stringify(report);
  for (const forbidden of ["docs.local", "/Users/", "fireemu-oracle", "ya29.", "AIza"]) {
    assert.ok(!text.includes(forbidden), forbidden);
  }
});

test("LIST and QUERY release outcomes recompute from saved production and local projections", () => {
  const bundle = read(bundlePath);
  const list = verifySeries(
    bundle,
    "list",
    listPrograms,
    "conformance/fs-data-write-list-production.json",
    { MATCH: 200, MATCH_NONDETERMINISTIC: 1 },
  );
  verifySeries(bundle, "query", queryPrograms, "conformance/fs-query-index-production.json", {
    MATCH: 675,
    DIVERGENCE_APPROVED: 35,
  });
  const listConditions = closure.conditions.filter(({ conditionId }) =>
    conditionId.startsWith("FS-DATA-WRITE-LIST/"),
  );
  const used = [];
  for (const condition of listConditions) {
    assert.equal(condition.status, "VERIFIED", condition.conditionId);
    assert.equal(condition.evidence.comparisonPath, bundle.series.list.reportPath);
    assert.equal(condition.evidence.comparisonSha256, bundle.series.list.reportSha256);
    assert.equal(condition.evidence.finalArtifactSha256, bundle.binarySha256);
    assert.equal(condition.evidence.sourceHead, bundle.sourceCommit);
    const rows = list.rows.filter(({ row }) => condition.recipeIds.includes(row));
    assert.equal(rows.length, condition.recipeIds.length, condition.conditionId);
    assert.ok(rows.every(({ status }) => ["MATCH", "MATCH_NONDETERMINISTIC"].includes(status)));
    used.push(...condition.recipeIds);
  }
  assert.deepEqual(new Set(used), new Set(list.rows.map(({ row }) => row)));
  assert.equal(used.length, list.rows.length);
});

test("release row gate rejects a missing row, false MATCH, and substituted local result", () => {
  const bundle = read(bundlePath);
  const series = bundle.series.list;
  const report = read(series.reportPath);
  const local = read(series.localProjectionPath);
  const fixture = "conformance/fs-data-write-list-production.json";
  const summary = { MATCH: 200, MATCH_NONDETERMINISTIC: 1 };
  assert.throws(
    () =>
      verifySeries(bundle, "list", listPrograms, fixture, summary, {
        report: { ...report, rows: report.rows.slice(1) },
      }),
    /Expected values to be strictly equal/,
  );
  const falseMatch = structuredClone(report);
  falseMatch.rows.find((row) => row.status === "MATCH_NONDETERMINISTIC").status = "MATCH";
  assert.throws(
    () => verifySeries(bundle, "list", listPrograms, fixture, summary, { report: falseMatch }),
    /MATCH_NONDETERMINISTIC/,
  );
  const substituted = structuredClone(local);
  const id = report.rows[0].row;
  substituted.rows[id] = { status: 599, body: {} };
  assert.throws(
    () => verifySeries(bundle, "list", listPrograms, fixture, summary, { local: substituted }),
    /MATCH/,
  );
});
