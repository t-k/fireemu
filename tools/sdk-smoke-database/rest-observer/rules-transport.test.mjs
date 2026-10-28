import test from 'node:test';
import assert from 'node:assert/strict';
import {makeWire,createTransport} from './transport.mjs';
import {mkdtemp,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';
const base='https://demo-observer.firebaseio.com/rnext1_0123456789abcdef01234567/r1/validation/negative.json';
test('case denial is fully recorded and anonymous; owner setup has exact quota/auth',async()=>{
 const seen=[];const wire=makeWire({instance:'demo-observer',project:'demo-project',token:'private',fetchImpl:async(u,options)=>{seen.push(options.headers);return new Response('{"error":"Permission denied"}',{status:401});}});
 const dir=await mkdtemp(join(tmpdir(),'rules-observer-'));const io=await createTransport({file:join(dir,'journal'),max:10,reserve:1,wire});
 const response=await io({step:'rules-case',method:'PUT',url:base,body:'-1',phase:'normal'});assert.equal(response.status,401);assert.equal(seen[0].authorization,undefined);assert.equal(seen[0]['x-goog-user-project'],undefined);const rows=(await readFile(join(dir,'journal'),'utf8')).trim().split('\n').map(JSON.parse);assert.equal(rows.at(-1).state,'response-persisted');await io.close();
 let headers;const admin=makeWire({instance:'demo-observer',project:'demo-project',token:'private',fetchImpl:async(u,o)=>{headers=o.headers;return new Response('null',{status:200});}});await admin({step:'rules-owner-seed',method:'PATCH',url:base,body:'{}'});assert.equal(headers.authorization,'Bearer private');assert.equal(headers['x-goog-user-project'],'demo-project');
});
test('unrelated non-success remains a rejection',async()=>{const wire=makeWire({instance:'demo-observer',project:'demo-project',token:'private',fetchImpl:async()=>new Response('no',{status:401})});await assert.rejects(wire({step:'rules-case',method:'PUT',url:'https://demo-observer.firebaseio.com/outside.json',body:'-1'}));});
test('Rules anchor and readiness sentinel stay anonymous',async()=>{const seen=[];const wire=makeWire({instance:'demo-observer',project:'demo-project',token:'private',fetchImpl:async(u,o)=>{seen.push(o.headers);return new Response('null',{status:200});}});for(const step of ['rules-anchor','rules-propagation'])await wire({step,method:'GET',url:base});for(const headers of seen){assert.equal(headers.authorization,undefined);assert.equal(headers['x-goog-user-project'],undefined);}});
test('sentinel propagation accepts only the exact owned readiness path',async()=>{const wire=makeWire({instance:'demo-observer',project:'demo-project',token:'private',fetchImpl:async()=>new Response('{"error":"Permission denied"}',{status:401})});await wire({step:'rules-propagation',method:'GET',url:'https://demo-observer.firebaseio.com/rnext1_0123456789abcdef01234567/ready.json'});await assert.rejects(wire({step:'rules-propagation',method:'GET',url:'https://demo-observer.firebaseio.com/rnext1_0123456789abcdef01234567/other.json'}));});
