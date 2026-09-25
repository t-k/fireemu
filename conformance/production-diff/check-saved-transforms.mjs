#!/usr/bin/env node
// Read-only join of the test fixture with the FULL pinned historical Git corpus
// and production matrix. No synthetic fallback, native execution or production I/O.
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { TRANSFORMS_CASE } from "./registry.mjs";
import { prepare } from "./legacy.mjs";
import { compareRecords, digestJson, safeCode } from "./core.mjs";

const here = dirname(fileURLToPath(import.meta.url));
try {
  if (process.argv.length > 3) throw new Error("invalid-arguments");
  const repo = resolve(process.argv[2] ?? resolve(here, "../.."));
  const fixture = JSON.parse(await fs.readFile(resolve(here, "test/fixtures/saved-transforms.json"), "utf8"));
  const prepared = await prepare(repo, TRANSFORMS_CASE);
  for (const key of ["matrixPath", "matrixBlob", "corpusPath", "corpusBlob", "observedSource"])
    assert.equal(fixture.source[key], TRANSFORMS_CASE[key]);
  assert.deepEqual(fixture.program, prepared.program);
  assert.equal(fixture.newProductionObservation, false);
  const actual = {
    [TRANSFORMS_CASE.programId]: {
      steps: Object.fromEntries(Object.entries(fixture.production.programs[0].steps)
        .map(([id, row]) => [id, row.production])),
    },
  };
  const comparison = compareRecords({ ...prepared, actual });
  assert.equal(comparison.verdict, "MATCH");
  assert.deepEqual(comparison.counts, { match: 18, mismatch: 0, indeterminate: 0 });
  console.log(JSON.stringify({
    caseId: TRANSFORMS_CASE.id,
    fixtureJoinValidated: true,
    repository: prepared.state,
    historicalSource: TRANSFORMS_CASE.observedSource,
    programDigest: digestJson(prepared.program),
    oracleProjectionDigest: prepared.provenance.oracle.projectionDigest,
    checkedDecisionRows: comparison.rows.length,
    nativeExecuted: false,
    productionExecuted: false,
    parentPromotion: false,
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({ fixtureJoinValidated: false, code: safeCode(error), nativeExecuted: false, productionExecuted: false }));
  process.exitCode = 2;
}
