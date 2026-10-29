import test from 'node:test';
import assert from 'node:assert/strict';
import {aggregateVectorRecipes, aggregateVectorFields} from './aggregate-vector-corpus.mjs';

test('separate SDK-backed aggregate and vector requests have bounded sources',()=>{
 const recipes=aggregateVectorRecipes();assert.equal(recipes.length,9);assert.equal(new Set(recipes.map(x=>x.id)).size,9);
 for(const {step} of recipes){assert.equal(step.transport,'grpc');const stages=step.body.structuredPipeline.pipeline.stages;assert.equal(stages[0].name,['collection','documents'].includes(stages[0].name)?stages[0].name:'');assert.equal(stages.at(-1).name,stages[0].name==='collection'?'aggregate':'select');}
});
test('seed has three ordered documents and typed vectors',()=>{const docs=aggregateVectorFields();assert.equal(docs.length,3);assert.deepEqual(docs.map(x=>x.seq.integerValue),['1','2','3']);assert.equal(docs[0].a.mapValue.fields.__type__.stringValue,'__vector__');assert.equal(docs[0].a.mapValue.fields.value.arrayValue.values[0].doubleValue,1);});

test('two rounds count each owned document and stop on unknown',async()=>{
 const {runAggregateVectorBatch}=await import('./aggregate-vector-batch.mjs');let calls=[];
 const io=async(op,detail)=>{calls.push([op,detail]);return op==='describe'?{known:true,uid:'owned',enterprise:true}:{known:true,ok:true};};
 const result=await runAggregateVectorBatch({uid:'owned',io});assert.deepEqual(result,{directRequests:45,observations:18});assert.equal(calls.filter(([op])=>op==='observe').length,18);assert.equal(calls.filter(([op])=>op==='verify-absence').length,6);
 calls=[];await assert.rejects(runAggregateVectorBatch({uid:'owned',io:async(op,detail)=>{calls.push([op,detail]);if(op==='seed')throw Error('lost response');return op==='describe'?{known:true,uid:'owned',enterprise:true}:{known:true,ok:true};}}),/unknown seed/);assert.equal(calls.at(-1)[0],'seed');
});
test('wrong database UID prevents seed and all observations',async()=>{const {runAggregateVectorBatch}=await import('./aggregate-vector-batch.mjs');let calls=[];await assert.rejects(runAggregateVectorBatch({uid:'owned',io:async(op)=>{calls.push(op);return op==='describe'?{known:true,uid:'different',enterprise:true}:{known:true,ok:true};}}),/identity mismatch/);assert.deepEqual(calls,['identity','identity','describe']);});
