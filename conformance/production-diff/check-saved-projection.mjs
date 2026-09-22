#!/usr/bin/env node
// Read-only join of the COMPLETE historical corpus/matrix to the bounded input fixture.
// No HTTP client, production credential, new Oracle or acceptance decision is added.
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PROJECTION_CASE as entry } from "./registry.mjs";
import { prepare } from "./legacy.mjs";
import { digestJson, safeCode } from "./core.mjs";
const here = dirname(fileURLToPath(import.meta.url));
try {
  if (process.argv.length > 3) throw new Error("invalid-arguments");
  const repo = resolve(process.argv[2] ?? resolve(here, "../.."));
  const fixture = JSON.parse(await fs.readFile(
    resolve(here, "test/fixtures/saved-projection-program.json"), "utf8"));
  const prepared = await prepare(repo, entry);
  assert.deepEqual(prepared.program, fixture);
  assert.equal(prepared.program.seed.length, 3);
  assert.equal(prepared.program.steps.length, 18);
  assert.equal(prepared.production.programs[0].area, "queries");
  assert.deepEqual(Object.keys(prepared.production.programs[0].steps), entry.stepIds);
  console.log(JSON.stringify({
    caseId: entry.id, sourceAndOracleJoinValidated: true,
    repository: prepared.state, programDigest: digestJson(prepared.program),
    expectedDecisionRows: 18, setupRequests: 4, cleanupRequests: 6,
    oracleProjectionDigest: prepared.provenance.oracle.projectionDigest,
    nativeExecuted: false, productionExecuted: false, parentPromotion: false,
    note: "Input and saved-evidence join only; not a comparison against fireemu.",
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({
    sourceAndOracleJoinValidated: false, code: safeCode(error),
    nativeExecuted: false, productionExecuted: false, parentPromotion: false,
  }));
  process.exitCode = 2;
}
