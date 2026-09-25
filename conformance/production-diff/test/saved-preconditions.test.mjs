// Real pinned recorder + real loopback HTTP, with explicitly synthetic replies.
// This tests the bridge, NOT fireemu behavior or a new production observation.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { promises as fs } from 'node:fs';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CASE, TRANSFORMS_CASE, PRECONDITIONS_CASE as entry, PROJECTION_CASE, AGGREGATIONS_CASE, selectCase } from '../registry.mjs';
import { blobSha, digestJson, sha256, equal, validateProgram, resolveRecordedValue, expectedCleanupDocuments } from '../core.mjs';
import { cleanEnvironment } from '../io.mjs';
import { verifySession, parseArgs, main } from '../pilot.mjs';
const HERE=dirname(fileURLToPath(import.meta.url));
const program=JSON.parse(await fs.readFile(join(HERE,'fixtures/saved-preconditions-program.json'),'utf8'));
const GENERIC_NAME=`projects/${entry.project}/databases/(default)/documents/wr/AbCdEfGhIj0123456789`;
const TIME1='2026-01-02T03:04:05.123456Z';
const TIME2='2026-01-02T03:04:06.123456Z';

test('registration pins the complete 34-step observed program, including its suffix',()=>{
 assert.equal(selectCase(entry.id),entry);
 assert.equal(entry.stepIds.length,34);
 assert.equal(digestJson(program),entry.programDigest);
 assert.equal(validateProgram(program,entry),program);
 assert.equal(program.steps.at(-1).id,'delete-with-exists-precondition');
 for(const k of ['matrixBlob','observedSource','corpusBlob','corpusDigest','comparatorSliceSha256','sessionBlob','credentialsBlob'])assert.equal(entry[k],CASE[k]);
 assert.equal(entry.evidenceKind,'saved-production-reference');
 assert.equal(entry.parent,'FS-DATA-WRITE');
});
test('old cases do not silently admit PATCH or DELETE operations',()=>{
 for(const e of [CASE,TRANSFORMS_CASE]){
  const p={id:e.programId,area:'writes',seed:[{}],steps:e.stepIds.map(id=>({id,method:'PATCH',path:'/v1/projects/PROJECT/databases/(default)/documents/x/y'}))};
  assert.throws(()=>validateProgram(p,e),/program-route/);
 }
});
test('program drift and split programs cannot borrow the saved production identity',()=>{
 for(const mutate of [p=>{p.steps.pop();},p=>{p.steps.reverse();},p=>{p.steps[11].body.writes[0].currentDocument.updateTime=TIME1;},p=>{p.seed[0].fields.a.integerValue='999';}]){
  const p=structuredClone(program);mutate(p);assert.throws(()=>validateProgram(p,entry),/program-(step-set|input-drift)/);
 }
});
test('metadata explicitly disclaims time equality and random-ID properties',()=>{
 assert.ok(entry.notEstablished.some(x=>x.includes('No-op updateTime equality')));
 assert.ok(entry.notEstablished.some(x=>x.includes('Auto-ID entropy')));
 assert.ok(Object.isFrozen(entry.allowedMethods));assert.ok(Object.isFrozen(entry.generatedDocumentSteps));
});
test('both updateTime uses resolve the original raw response, not a later response',()=>{
 const replies=new Map([['read-after-replace',{updateTime:TIME1}],['update-time-precondition-matches',{writeResults:[{updateTime:TIME2}]}]]);
 for(const i of [11,12])assert.equal(resolveRecordedValue(program.steps[i].body,replies).writes[0].currentDocument.updateTime,TIME1);
 assert.equal(typeof program.steps[11].body.writes[0].currentDocument.updateTime,'object');
});
for(const [label,value] of [['null',null],['boolean',false],['number',0],['empty string',''],['object',{a:[1,2]}]])test(`reference preserves ${label} without inventing a replacement`,()=>{
 const result=resolveRecordedValue({$from:'source',path:'a.0.value'},new Map([['source',{a:[{value}]}]]));
 assert.deepEqual(result,value); if(result&&typeof result==='object')assert.notEqual(result,value);
});
for(const [label,ref,replies] of [
 ['future source',{$from:'future',path:'v'},new Map()],
 ['missing path',{$from:'a',path:'no'},new Map([['a',{}]])],
 ['null source',{$from:'a',path:'v'},new Map([['a',null]])],
 ['prototype path',{$from:'a',path:'toString'},new Map([['a',{}]])],
 ['non-string path',{$from:'a',path:2},new Map([['a',{v:1}]])],
])test(`reference refuses ${label}`,()=>assert.throws(()=>resolveRecordedValue(ref,replies),/recorder-reference-unavailable/));
test('nested literal __proto__ remains data, not an object prototype',()=>{
 const input=JSON.parse('{"__proto__":{"v":1},"normal":[{"$from":"a","path":"v"}]}');
 const result=resolveRecordedValue(input,new Map([['a',{v:TIME1}]]));
 assert.ok(Object.hasOwn(result,'__proto__'));assert.equal(Object.getPrototypeOf(result),Object.prototype);assert.equal(result.normal[0],TIME1);
});
function generatedRow(changes={}){const generatedResponseText=JSON.stringify({name:GENERIC_NAME});return {generatedResponseText,responseSha256:sha256(generatedResponseText),phase:'create-document-with-generated-id',method:'POST',path:`/v1/projects/${entry.project}/databases/(default)/documents/wr`,status:200,generatedDocument:GENERIC_NAME,...changes};}
test('cleanup includes the exact generated document, not its normalized name',()=>{
 assert.deepEqual(expectedCleanupDocuments(entry,[generatedRow()]),[...entry.ownedDocuments,'wr/AbCdEfGhIj0123456789']);
 assert.deepEqual(expectedCleanupDocuments(entry,[]),entry.ownedDocuments);
 assert.deepEqual(expectedCleanupDocuments(CASE,[]),CASE.ownedDocuments);
});
for(const [label,changes] of [
 ['foreign project',{generatedDocument:GENERIC_NAME.replace(entry.project,'foreign')}],
 ['foreign collection',{generatedDocument:GENERIC_NAME.replace('/wr/','/other/')}],
 ['path traversal',{generatedDocument:GENERIC_NAME.replace('AbCdEfGhIj0123456789','../x')}],
 ['percent escape',{generatedDocument:GENERIC_NAME.replace('AbCdEfGhIj0123456789','%2e%2e')}],
 ['normalized ID',{generatedDocument:GENERIC_NAME.replace('AbCdEfGhIj0123456789','<auto-id>')}],
 ['missing name',{generatedDocument:undefined}],
 ['wrong operation',{method:'GET'}],
 ['wrong route',{path:'/v1/foreign'}],
 ['string status',{status:'200'}],
])test(`cleanup refuses ${label}`,()=>assert.throws(()=>expectedCleanupDocuments(entry,[generatedRow(changes)]),/generated-document-receipt-invalid/));
test('duplicate generated-name acknowledgement is rejected',()=>assert.throws(()=>expectedCleanupDocuments(entry,[generatedRow(),generatedRow()]),/generated-document-receipt-invalid/));
test('rejected create cannot supply a generated deletion target',()=>{
 assert.deepEqual(expectedCleanupDocuments(entry,[generatedRow({status:400,generatedDocument:undefined,generatedResponseText:undefined})]),entry.ownedDocuments);
 assert.throws(()=>expectedCleanupDocuments(entry,[generatedRow({status:400})]),/generated-document-receipt-invalid/);
});

// Deliberately synthetic protocol bodies. Only the recorded PROGRAM is copied from
// the historical source; these replies must NEVER enter a production fixture.
function syntheticReply(spec,{missingTime=false,badGenerated=false}={}){
 if(spec.id==='create-document-with-generated-id')return {status:200,body:{name:badGenerated?GENERIC_NAME.replace('/wr/','/foreign/'):GENERIC_NAME,fields:{a:{integerValue:'1'}},createTime:TIME1,updateTime:TIME1}};
 if(spec.id==='read-after-replace')return {status:200,body:{name:`projects/${entry.project}/databases/(default)/documents/wr/existing`,fields:{only:{booleanValue:true}},...(missingTime?{}:{updateTime:TIME1})}};
 if(spec.id==='update-time-precondition-matches')return {status:200,body:{writeResults:[{updateTime:TIME2}],commitTime:TIME2}};
 if(spec.id==='update-time-precondition-is-stale')return {status:400,body:{error:{code:400,status:'FAILED_PRECONDITION',message:'synthetic stale response'}}};
 return {status:200,body:{fixtureStep:spec.id,updateTime:TIME1}};
}
async function wire({missingTime=false,badGenerated=false,missingGeneratedCleanup=false,drift=false,caseId=entry.id}={}){
 const dir=await fs.mkdtemp(join(tmpdir(),'fireemu-masks-022-'));
 const requests=[],errors=[];let resets=0,count=0,child;
 const localProgram=structuredClone(program);if(drift)localProgram.steps[11].body.writes[0].currentDocument.updateTime=TIME1;
 const project=entry.project;
 const reset=`/emulator/v1/projects/${project}/databases/(default)/documents`;
 const substitute=x=>x===undefined?undefined:JSON.parse(JSON.stringify(x).replaceAll('PROJECT',project));
 const server=createServer(async(req,res)=>{
  const send=(status,body)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(body));};
  try{
   const chunks=[];for await(const c of req)chunks.push(c);const text=Buffer.concat(chunks).toString();const body=text?JSON.parse(text):undefined;
   requests.push({method:req.method,path:req.url,body});
   if(req.url===reset&&req.method==='DELETE'){assert.equal(req.headers.authorization,undefined);resets++;return send(200,{});}
   assert.equal(req.headers.authorization,'Bearer owner');
   if(resets===2){
    assert.equal(req.method,'GET');const suffix=req.url.split('/documents/')[1];assert.ok([...entry.ownedDocuments,'wr/AbCdEfGhIj0123456789'].includes(suffix));
    if(missingGeneratedCleanup&&suffix==='wr/AbCdEfGhIj0123456789')return send(200,{name:GENERIC_NAME});
    return send(404,{error:{code:404,status:'NOT_FOUND'}});
   }
   assert.equal(resets,1);
   if(count===0){assert.equal(req.method,'PATCH');assert.equal(req.url,substitute(program.seed[0].path));assert.deepEqual(body,{fields:substitute(program.seed[0].fields)});count++;return send(200,{updateTime:TIME1});}
   const spec=program.steps[count-1];assert.ok(spec);assert.equal(req.method,spec.method);assert.equal(req.url,substitute(spec.path));
   const wanted=substitute(spec.body);
   // Independent finite reference check: neither production code's resolver nor
   // any normalized response is used to choose these two exact request values.
   if([11,12].includes(count-1))wanted.writes[0].currentDocument.updateTime=TIME1;
   assert.deepEqual(body,wanted);count++;
   const reply=syntheticReply(spec,{missingTime,badGenerated});return send(reply.status,reply.body);
  }catch(e){errors.push(String(e));return send(500,{error:{code:500,status:'INTERNAL'}});}
 });
 try{
  await fs.mkdir(join(dir,'legacy'));
  for(const [name,pin] of [['session.mjs',entry.sessionBlob],['credentials.mjs',entry.credentialsBlob]]){
   const b=await fs.readFile(resolve(HERE,'../../src/firestore-probe',name));assert.equal(blobSha(b),pin);await fs.writeFile(join(dir,'legacy',name),b);
  }
  await fs.writeFile(join(dir,'program.json'),JSON.stringify(localProgram));await fs.writeFile(join(dir,'programs.json'),JSON.stringify([localProgram]));
  server.listen(0,'127.0.0.1');await once(server,'listening');const stderr=[];
  child=spawn(process.execPath,[resolve(HERE,'../local-session.mjs')],{cwd:dir,env:{...cleanEnvironment(dir),PILOT_RUN_DIR:dir,PILOT_CASE_ID:caseId,GOOGLE_CLOUD_PROJECT:project,FIRESTORE_EMULATOR_HOST:`127.0.0.1:${server.address().port}`},stdio:['ignore','ignore','pipe']});
  child.stderr.on('data',x=>stderr.push(x));const watchdog=setTimeout(()=>child.kill('SIGKILL'),12000);let exit;
  try{[exit]=await once(child,'close');}finally{clearTimeout(watchdog);}
  const read=n=>fs.readFile(join(dir,n),'utf8').then(JSON.parse).catch(()=>null);
  return {exit,requests,errors,session:await read('session-result.json'),local:await read('local.json'),localBytes:await fs.readFile(join(dir,'local.json')).catch(()=>null),stderr:Buffer.concat(stderr).toString()};
 }finally{
  if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await once(child,'close').catch(()=>{});}
  server.closeAllConnections();await new Promise(done=>server.close(done));await fs.rm(dir,{recursive:true,force:true});
 }
}

test('whole historical input reaches the real recorder; raw updateTime and generated cleanup survive',{timeout:15000},async()=>{
 const r=await wire();assert.equal(r.exit,0,r.stderr);assert.deepEqual(r.errors,[]);
 assert.equal(r.requests.length,46);assert.equal(r.session.requestCount,36);assert.equal(r.session.cleanup.requests,10);
 assert.equal(r.session.completed,true);assert.equal(r.session.productionRequests,0);assert.equal(r.session.cleanup.state,'confirmed');
 assert.equal(r.session.cleanup.absent.at(-1),'wr/AbCdEfGhIj0123456789');
 const steps=r.local[program.id].steps;assert.equal(steps['read-after-replace'].body.updateTime,'<now>');
 assert.equal(steps['create-document-with-generated-id'].body.name.endsWith('/<auto-id>'),true);
 const sent=r.requests.filter(q=>q.body?.writes?.[0]?.currentDocument?.updateTime===TIME1);assert.equal(sent.length,2);
 assert.equal(r.session.requests.find(q=>q.phase==='create-document-with-generated-id').generatedDocument,GENERIC_NAME);
 assert.equal(r.session.programDigest,entry.programDigest);
 verifySession(r.session,{entry,program},r.localBytes);
 assert.equal(r.session.localSha256,sha256(r.localBytes));
});
test('missing raw updateTime stops rather than using <now>, a constant, or sending a placeholder',{timeout:15000},async()=>{
 const r=await wire({missingTime:true});assert.notEqual(r.exit,0);assert.deepEqual(r.errors,[]);assert.equal(r.session.completed,false);
 assert.ok(!r.requests.some(q=>q.body?.writes?.[0]?.currentDocument?.updateTime===TIME1));assert.equal(r.session.cleanup.state,'confirmed');
});
test('malformed generated document never becomes an out-of-collection cleanup GET',{timeout:15000},async()=>{
 const r=await wire({badGenerated:true});assert.notEqual(r.exit,0);assert.deepEqual(r.errors,[]);assert.equal(r.session.cleanup.state,'unconfirmed');
 assert.ok(!r.requests.some(q=>q.path.includes('/foreign/')));
});
test('generated document remaining after reset makes cleanup unconfirmed',{timeout:15000},async()=>{
 const r=await wire({missingGeneratedCleanup:true});assert.notEqual(r.exit,0);assert.equal(r.session.cleanup.state,'unconfirmed');assert.equal(r.session.cleanup.failure,'cleanup-absence-unconfirmed');
});
test('historical input drift is rejected before the first HTTP request',{timeout:15000},async()=>{
 const r=await wire({drift:true});assert.notEqual(r.exit,0);assert.equal(r.requests.length,0);assert.equal(r.session,null);
});

for (const [label, changes] of [
 ['body hash',{responseSha256:'0'.repeat(64)}],
 ['body identity',{generatedDocument:GENERIC_NAME.replace('AbCdEfGhIj0123456789','ZbCdEfGhIj0123456789')}],
 ['missing body',{generatedResponseText:undefined}],
 ['changed body',{generatedResponseText:'{}'}],
]) test(`generated cleanup is bound to its raw acknowledgement: ${label}`,()=>{
 assert.throws(()=>expectedCleanupDocuments(entry,[generatedRow(changes)]),/generated-document-response-binding/);
});


test('public CLI selects the new case without changing the default',async()=>{
 assert.equal(parseArgs(['plan','--case',entry.id]).case,entry.id);
 assert.equal(parseArgs(['plan']).case,CASE.id);
 const prior=console.log;let output;
 try{console.log=s=>{output=s;};assert.equal(await main(['list']),0);}finally{console.log=prior;}
 assert.deepEqual(JSON.parse(output).cases.map(c=>c.id),[CASE.id,'fs.commit-transform-limits.saved-031c74bfe.v1','fs.g0.saved-68012694.v1',TRANSFORMS_CASE.id,entry.id,PROJECTION_CASE.id,AGGREGATIONS_CASE.id]);
});

test('actual parent verifier refuses missing or substituted generated cleanup',{timeout:15000},async()=>{
 const r=await wire();assert.equal(r.exit,0,r.stderr);
 const changed=structuredClone(r.session);changed.cleanup.absent.pop();changed.cleanup.requests--;
 assert.throws(()=>verifySession(changed,{entry,program},r.localBytes),/local-cleanup-binding/);
 const forged=structuredClone(r.session);
 forged.requests.find(q=>q.generatedDocument).generatedDocument=GENERIC_NAME.replace('AbCdEfGhIj0123456789','ZbCdEfGhIj0123456789');
 forged.cleanup.absent[forged.cleanup.absent.length-1]='wr/ZbCdEfGhIj0123456789';
 assert.throws(()=>verifySession(forged,{entry,program},r.localBytes),/generated-document-response-binding/);
 const stripped=structuredClone(r.session);delete stripped.requests.find(q=>q.generatedDocument).generatedResponseText;
 assert.throws(()=>verifySession(stripped,{entry,program},r.localBytes),/generated-document-response-binding/);
});
