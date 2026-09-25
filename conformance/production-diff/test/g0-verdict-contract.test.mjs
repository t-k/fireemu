import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { mock, test } from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compareG0 } from "../g0.mjs";
import { gateExitCode, resultEnvelope } from "../core.mjs";

const artifactHash = "a".repeat(64);
const entry = {
  id: "g0-verdict-fixture",
  parent: "FS-DATA-WRITE",
  adapter: "g0",
  productionResultPath: "G0_VERDICT_TEST_INPUT",
  evidenceKind: "saved-production-reference",
  oracleKind: "normalized-g0-runtime-recomparison",
  profile: "strict",
  transport: "local-only",
  compared: [],
  notEstablished: [],
};
const program = {
  jobs: {
    first: { observation: Array.from({ length: 7 }, () => ({})) },
    second: { observation: Array.from({ length: 5 }, () => ({})) },
  },
};
const execution = {
  state: "completed",
  artifact: { sha256: artifactHash },
  cleanup: { state: "confirmed" },
  process: { state: "stopped" },
};

function withComparatorReply(reply, run) {
  const previous = process.env.G0_VERDICT_TEST_INPUT;
  process.env.G0_VERDICT_TEST_INPUT = "/test-only/input.json";
  const replacement = mock.method(childProcess, "execFileSync", () => JSON.stringify(reply));
  syncBuiltinESMExports();
  try {
    return run(() => compareG0({
      repo: process.cwd(),
      entry,
      program,
      actual: { fixture: true },
      execution,
      build: { artifactSha256: artifactHash },
    }));
  } finally {
    replacement.mock.restore();
    syncBuiltinESMExports();
    if (previous === undefined) delete process.env.G0_VERDICT_TEST_INPUT;
    else process.env.G0_VERDICT_TEST_INPUT = previous;
  }
}

function withPythonComparatorReply(reply, run) {
  const repo = mkdtempSync(join(tmpdir(), "g0-verdict-ipc-"));
  const modules = join(repo, "tools", "compat-broad");
  mkdirSync(modules, { recursive: true });
  writeFileSync(
    join(modules, "shared_production_pair.py"),
    [
      "def compare_g0_current_runtime_recompare(production_path, local, repo, runtime):",
      "    assert production_path == '/test-only/input.json'",
      "    assert runtime == {'artifactSha256': 'a' * 64}",
      "    return local['fixtureReply']",
      "",
    ].join("\n"),
  );
  const previous = process.env.G0_VERDICT_TEST_INPUT;
  process.env.G0_VERDICT_TEST_INPUT = "/test-only/input.json";
  const realExec = childProcess.execFileSync;
  const replacement = mock.method(childProcess, "execFileSync", (command, args, options) => {
    assert.equal(command, "uv");
    return realExec("python3", args.slice(2), { ...options, cwd: repo, timeout: 5000 });
  });
  syncBuiltinESMExports();
  try {
    return run((fixtureReply) => compareG0({
      repo,
      entry,
      program,
      actual: { fixtureReply },
      execution,
      build: { artifactSha256: artifactHash },
    }));
  } finally {
    replacement.mock.restore();
    syncBuiltinESMExports();
    if (previous === undefined) delete process.env.G0_VERDICT_TEST_INPUT;
    else process.env.G0_VERDICT_TEST_INPUT = previous;
    rmSync(repo, { recursive: true, force: true });
  }
}

function completeRows(verdict = "match") {
  return [
    ...Array.from({ length: 7 }, (_, index) => ({ job: "first", index, verdict })),
    ...Array.from({ length: 5 }, (_, index) => ({ job: "second", index, verdict })),
  ];
}

test("an indeterminate comparator with no rows cannot become a completed mismatch", () => {
  withComparatorReply(
    { compatibility: "indeterminate", rows: [], reason: "cleanup evidence incomplete" },
    (compare) => {
      const comparison = compare();
      assert.equal(comparison.verdict, "INDETERMINATE");
      assert.deepEqual(comparison.counts, { match: 0, mismatch: 0, indeterminate: 12 });
      const result = resultEnvelope({ entry, comparison, execution, provenance: {} });
      assert.equal(result.complete, false);
      assert.equal(result.gatePassed, false);
      assert.equal(gateExitCode(result), 2);
    },
  );
});

test("a complete twelve-row match remains a match", () => {
  withComparatorReply({ compatibility: "match", rows: completeRows(), reason: null }, (compare) => {
    const comparison = compare();
    assert.equal(comparison.verdict, "MATCH");
    assert.deepEqual(comparison.counts, { match: 12, mismatch: 0, indeterminate: 0 });
    assert.equal(gateExitCode(resultEnvelope({ entry, comparison, execution, provenance: {} })), 0);
  });
});

test("a complete semantic mismatch remains a completed failure", () => {
  const rows = completeRows();
  rows[2].verdict = "mismatch";
  withComparatorReply({ compatibility: "mismatch", rows, reason: null }, (compare) => {
    const comparison = compare();
    assert.deepEqual(comparison.counts, { match: 11, mismatch: 1, indeterminate: 0 });
    const result = resultEnvelope({ entry, comparison, execution, provenance: {} });
    assert.equal(result.complete, true);
    assert.equal(result.gatePassed, false);
    assert.equal(gateExitCode(result), 1);
  });
});

test("an indeterminate reply retains reported rows as diagnostics only", () => {
  const rows = completeRows();
  rows[4].verdict = "mismatch";
  withComparatorReply(
    { compatibility: "indeterminate", rows: rows.slice(0, 5), reason: "record incomplete" },
    (compare) => {
      const comparison = compare();
      assert.equal(comparison.verdict, "INDETERMINATE");
      assert.equal(comparison.reportedRowCount, 5);
      assert.deepEqual(comparison.counts, { match: 0, mismatch: 0, indeterminate: 12 });
      assert.equal(comparison.rows[4].reportedComparison, "MISMATCH");
      assert.equal(comparison.rows[5].comparisonReported, false);
      assert.equal(gateExitCode(resultEnvelope({ entry, comparison, execution, provenance: {} })), 2);
    },
  );
});

for (const [name, mutate, error] of [
  ["duplicate row", (rows) => rows.splice(1, 1, { ...rows[0] }), /g0-comparator-row-shape/],
  ["extra row", (rows) => rows.push({ ...rows[0] }), /g0-comparator-result-shape/],
  ["foreign job", (rows) => { rows[0].job = "foreign"; }, /g0-comparator-row-shape/],
  ["unknown verdict", (rows) => { rows[0].verdict = "cancelled"; }, /g0-comparator-row-shape/],
]) {
  test(`rejects ${name} before producing a verdict`, () => {
    const rows = completeRows();
    mutate(rows);
    withComparatorReply({ compatibility: "indeterminate", rows, reason: "invalid" }, (compare) => {
      assert.throws(compare, error);
    });
  });
}

for (const phase of ["execution", "cleanup", "process"]) {
  test(`an exact match cannot override unconfirmed ${phase}`, () => {
    withComparatorReply({ compatibility: "match", rows: completeRows(), reason: null }, (compare) => {
      const changed = structuredClone(execution);
      if (phase === "execution") changed.state = "failed";
      else changed[phase] = { state: "unconfirmed" };
      const comparison = compare();
      const result = resultEnvelope({ entry, comparison, execution: changed, provenance: {} });
      assert.equal(result.complete, false);
      assert.equal(result.gatePassed, false);
      assert.equal(gateExitCode(result), 2);
    });
  });
}

test("the producer's Python IPC preserves indeterminate without native or production access", () => {
  withPythonComparatorReply(
    { compatibility: "indeterminate", rows: [], reason: "fixture cleanup incomplete" },
    (compare) => {
      const comparison = compare({ compatibility: "indeterminate", rows: [], reason: "fixture cleanup incomplete" });
      assert.equal(comparison.verdict, "INDETERMINATE");
      assert.deepEqual(comparison.counts, { match: 0, mismatch: 0, indeterminate: 12 });
      assert.equal(gateExitCode(resultEnvelope({ entry, comparison, execution, provenance: {} })), 2);
    },
  );
});
