import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runAggregateVectorBatch} from './fs-ent-pipeline/aggregate-vector-batch.mjs';
import {createAggregateVectorSupport} from './fs-ent-pipeline/aggregate-vector-support.mjs';
import {SANDBOX_PROJECT} from './fs-ent-pipeline/harness.mjs';

const rows=readFileSync(new URL('./fs-ent-pipeline/fixtures/aggregate-vector-pict.tsv',import.meta.url),'utf8').trim().split('\n').map(line=>line.split('\t'));
const ctx={project:SANDBOX_PROJECT,database:'entpipe2-20000101',stageContextDatabase:'entpipe2-20000101',target:{kind:'production',token:'fake-secret',quotaProject:SANDBOX_PROJECT}};
const required=[['exact','empty','ok','full'],['wrong','empty','ok','full'],['exact','occupied','ok','full'],['exact','paginated','ok','full'],['exact','unknown','ok','full'],['exact','empty','unknown','full'],['exact','empty','ok','low']];
test('generated PICT rows include mandatory scenarios',()=>{assert.deepEqual(rows[0],['identity','collection','write','budget']);for(const seed of required)assert(rows.slice(1).some(row=>row.join('\t')===seed.join('\t')));});
for(const [identity,collection,write,budget] of rows.slice(1))test(`generated case ${identity}/${collection}/${write}/${budget}`,async()=>{
 const calls=[];const io=async(op)=>{calls.push(op);if(op==='describe')return {known:true,uid:identity==='exact'?'owned':'wrong',enterprise:true};if(op==='collection-baseline'){const support=createAggregateVectorSupport(ctx,{claim:async()=>{},journal:async()=>{},fetchFn:async()=>{if(collection==='unknown')throw Error('transport');const body=collection==='empty'?{}:collection==='occupied'?{documents:[{}]}:{nextPageToken:'next'};return {status:200,text:async()=>JSON.stringify(body)};}});return support(op);}if(op==='seed'&&write==='unknown')throw Error('unknown');return {known:true,ok:true};};
 if(identity==='exact'&&collection==='empty'&&write==='ok'&&budget==='full')assert.equal((await runAggregateVectorBatch({uid:'owned',io})).directRequests,45);else await assert.rejects(runAggregateVectorBatch({uid:'owned',io,maximum:budget==='low'?4:45}));
 if(identity==='wrong'||collection!=='empty'||budget==='low')assert(!calls.includes('seed'));if(write==='unknown'&&calls.includes('seed'))assert.equal(calls.at(-1),'seed');
});
