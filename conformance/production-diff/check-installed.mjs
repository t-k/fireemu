// On-checkout acceptance of real, pinned repository sources/observations.
// This is historical-record comparison, NOT a current fireemu execution.
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { prepare } from "./legacy.mjs";
import { compareRecords, validateProgram } from "./core.mjs";

const repo = process.argv[2]
  ? resolve(process.argv[2])
  : resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const p = await prepare(repo);
const matrix = JSON.parse(await fs.readFile(join(repo, p.entry.matrixPath)));
const stored = matrix.programs.find((x) => x.id === p.entry.programId);
const actual = {
  [p.entry.programId]: {
    steps: Object.fromEntries(
      p.entry.stepIds.map((id) => [id, structuredClone(stored.steps[id].fireemu)]),
    ),
  },
};
const run = (value) => compareRecords({ ...p, actual: value });
const baseline = run(actual);
assert.equal(baseline.verdict, "MATCH");
assert.equal(baseline.counts.match, 5);
const original = p.comparator({
  production: p.production,
  fireemu: actual,
  programDefinitions: [p.program],
});
assert.deepEqual(
  baseline.rows.map((row) => row.comparison),
  original.rows.map((row) => row.comparison.toUpperCase()),
);
const code = structuredClone(actual);
code[p.entry.programId].steps["non-atomic-batch"].code = "FAILED_PRECONDITION";
assert.equal(run(code).verdict, "MISMATCH");
const state = structuredClone(actual);
state[p.entry.programId].steps["one-was-written"] = { status: 200, code: "OK", body: {} };
assert.equal(run(state).verdict, "MISMATCH");
const missing = structuredClone(actual);
delete missing[p.entry.programId].steps["empty-batch"];
assert.equal(run(missing).verdict, "INDETERMINATE");
const changedProgram = structuredClone(p.program);
changedProgram.steps[0].body.writes.pop();
assert.throws(() => validateProgram(changedProgram, p.entry));
console.log(
  JSON.stringify(
    {
      caseId: p.entry.id,
      historicalComparatorCheck: "passed",
      historicalRows: baseline.counts,
      semanticMutantsDetected: 2,
      missingRowRejected: true,
      changedInputRejected: true,
      productionExecuted: false,
      currentNativeExecuted: false,
      historicalArtifact: matrix.evidence.observations.fireemu.artifact,
      provenance: p.provenance,
    },
    null,
    2,
  ),
);
