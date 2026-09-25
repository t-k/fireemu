#!/usr/bin/env node
// Read-only source/Oracle join. No fake response is an Oracle; no network/backend is added.
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PRECONDITIONS_CASE as entry } from './registry.mjs';
import { prepare } from './legacy.mjs';
import { digestJson, safeCode } from './core.mjs';
const here=dirname(fileURLToPath(import.meta.url));
try {
 if(process.argv.length>3)throw new Error('invalid-arguments');
 const repo=resolve(process.argv[2]??resolve(here,'../..'));
 const fixture=JSON.parse(await fs.readFile(resolve(here,'test/fixtures/saved-preconditions-program.json'),'utf8'));
 // prepare validates complete corpus/matrix blob pins and observation/source bindings,
 // imports the historic corpus, selects only production and keeps the comparator pin.
 const prepared=await prepare(repo,entry);
 assert.deepEqual(prepared.program,fixture);
 assert.equal(prepared.program.steps.length,34);
 assert.deepEqual(Object.keys(prepared.production.programs[0].steps),entry.stepIds);
 console.log(JSON.stringify({
  caseId:entry.id,sourceAndOracleJoinValidated:true,repository:prepared.state,
  programDigest:digestJson(prepared.program),expectedDecisionRows:34,
  oracleProjectionDigest:prepared.provenance.oracle.projectionDigest,
  nativeExecuted:false,productionExecuted:false,parentPromotion:false,
  note:'This validates input and saved evidence wiring, not a comparison against fireemu.',
 },null,2));
} catch(error) {
 console.error(JSON.stringify({sourceAndOracleJoinValidated:false,code:safeCode(error),nativeExecuted:false,productionExecuted:false,parentPromotion:false}));
 process.exitCode=2;
}
