#!/usr/bin/env node
// Read-only source/evidence join; NOT a Firestore implementation or a parity claim.
// Uses the COMPLETE pinned corpus and production matrix through the existing adapter.
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AGGREGATIONS_CASE as entry } from "./registry.mjs";
import { prepare } from "./legacy.mjs";
import { digestJson, safeCode } from "./core.mjs";
const here = dirname(fileURLToPath(import.meta.url));
try {
  if (process.argv.length > 3) throw new Error("invalid-arguments");
  const repo = resolve(process.argv[2] ?? resolve(here, "../.."));
  const fixture = JSON.parse(await fs.readFile(
    resolve(here, "test/fixtures/saved-aggregations-program.json"), "utf8"));
  const prepared = await prepare(repo, entry);
  assert.deepEqual(prepared.program, fixture);
  assert.equal(prepared.program.seed.length, 6);
  assert.equal(prepared.program.steps.length, 23);
  assert.equal(prepared.production.programs[0].area, "queries");
  assert.deepEqual(Object.keys(prepared.production.programs[0].steps), entry.stepIds);
  assert.deepEqual(prepared.program.seed.map(seed => seed.path.split("/documents/")[1]), entry.ownedDocuments);
  console.log(JSON.stringify({
    caseId: entry.id, parent: entry.parent, sourceAndOracleJoinValidated: true,
    repository: prepared.state, programDigest: digestJson(prepared.program),
    expectedDecisionRows: 23, setupRequests: 7, cleanupRequests: 7,
    oracleProjectionDigest: prepared.provenance.oracle.projectionDigest,
    nativeExecuted: false, productionExecuted: false, parentPromotion: false,
    note: "Full pinned source/evidence join only; native replay and independent review remain required.",
  }, null, 2));
} catch (error) {
  console.error(JSON.stringify({
    sourceAndOracleJoinValidated: false, code: safeCode(error),
    nativeExecuted: false, productionExecuted: false, parentPromotion: false,
  }));
  process.exitCode = 2;
}
