// Actual runner process, framed IPC and loopback HTTP. SDK metadata follows
// firebase-functions@7.3.2; Express and the task wrappers here are test doubles.
// This is not an installed-SDK/native task dispatch test.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./index.mjs', import.meta.url));
const project = 'demo-generation', secret = 'fixture-proxy-secret';
const encode = value => {
  const body = Buffer.from(JSON.stringify(value));
  return Buffer.concat([Buffer.from(`${body.length}\n`), body]);
};
const expressDouble = `
module.exports = function() {
  const middleware = []; let route;
  const app = (req, res) => {
    res.status = code => { res.statusCode = code; return res; };
    res.send = body => { if (!res.writableEnded) res.end(body); return res; };
    res.json = body => { res.setHeader('Content-Type','application/json'); return res.send(JSON.stringify(body)); };
    const path = req.url.split('?')[0].split('/');
    req.params = { project: path[1], region: path[2], name: path[3] };
    let i = 0;
    const next = error => {
      if (res.writableEnded || res.destroyed) return;
      if (error) { res.statusCode=error.status || 400; res.end('parser error'); return; }
      if (i < middleware.length) middleware[i++](req,res,next);
      else route(req,res);
    };
    next();
  };
  app.use = fn => middleware.push(fn); app.all = (_path, fn) => { route = fn; }; return app;
};
module.exports.json = options => (req,res,next) => {
  const chunks=[];
  req.on('data',b=>chunks.push(b)); req.on('error',next);
  req.on('end',()=>{try{const raw=Buffer.concat(chunks);options.verify(req,res,raw);
    req.body=raw.length?JSON.parse(raw):{};next();}catch(error){next(error);}});
};
for(const name of ['text','urlencoded','raw'])module.exports[name]=()=> (_req,_res,next)=>next();
`;
const fixtureSource = `
const {appendFileSync} = require('node:fs');
const {join} = require('node:path');
const exports_ = Object.create(null);
const record = value => appendFileSync(join(__dirname,'calls.jsonl'),JSON.stringify(value)+'\\n');
const identity = () => ({ target: process.env.FUNCTION_TARGET, signature: process.env.FUNCTION_SIGNATURE_TYPE,
  service: process.env.K_SERVICE, secret: process.env.TASK_SECRET ?? null });
const retryConfig = { maxAttempts: 4, minBackoffSeconds: 0, maxBackoffSeconds: 60,
  maxRetrySeconds: null, maxDoublings: 3 };
const rateLimits = { maxConcurrentDispatches: 2, maxDispatchesPerSecond: 7 };
function metadata(fn, form, value) {
  if (form==='legacy') fn.__trigger=value;
  else fn.__endpoint={platform:form,...value};
}
function task(name,form,empty=false,dual=false) {
  const fn=async(req,res)=>{
    const entry={name,kind:'task-wrapper',data:req.body.data,raw:Buffer.isBuffer(req.rawBody),...identity()};
    record(entry);res.status(200).json(entry);
  };
  fn.run=()=>{throw Error('runner must use the SDK HTTP wrapper for Tasks');};
  metadata(fn,form,{taskQueueTrigger:empty?{}:{retryConfig,rateLimits,invoker:['private']},
    ...(form==='legacy'?{timeout:'37s',regions:['europe-west1']}:
      {timeoutSeconds:37,region:['europe-west1'],secretEnvironmentVariables:[{key:'TASK_SECRET'}]}),
    ...(dual?{httpsTrigger:{}}:{})});exports_[name]=fn;
}
for(const [name,form] of [['taskV1','gcfv1'],['taskLegacy','legacy'],['taskV2','gcfv2']])task(name,form);
task('taskEmpty','gcfv1',true);task('taskDual','gcfv1',false,true);
task('taskV2Dual','gcfv2',false,true);
// An empty endpoint is the supported fallback to legacy __trigger metadata.
exports_.taskLegacy.__endpoint={};
task('taskNull','gcfv1');exports_.taskNull.__endpoint.taskQueueTrigger={retryConfig:null,rateLimits:null};
for (const [name,queue] of [
 ['badTaskScalar',true],['badTaskArray',[]],['badRetryArray',{retryConfig:[]}],
 ['badRetryFalse',{retryConfig:false}],['badRateScalar',{rateLimits:3}],
]) {
 const fn=async()=>record({name,unexpected:true});fn.__endpoint={platform:'gcfv2',taskQueueTrigger:queue};exports_[name]=fn;
}
function blocking(name,form) {
  const fn=()=>{throw Error('blocking must call run');};
  fn.run=async(...args)=>{
    const one=args.length===1, user=one?args[0].data:args[0], context=one?args[0]:args[1];
    record({name,kind:'blocking',argc:args.length,user,tag:context.tag,...identity()});
    return {displayName:process.env.FUNCTION_SIGNATURE_TYPE};
  };
  metadata(fn,form,{blockingTrigger:{eventType:'beforeCreate'},secretEnvironmentVariables:[{key:'TASK_SECRET'}]});
  exports_[name]=fn;
}
blocking('blockV1','gcfv1');blocking('blockV2','gcfv2');blocking('blockLegacy','legacy');
const http=async(req,res)=>{const value={name:'http',...identity()};record(value);res.json(value);};
http.__endpoint={platform:'gcfv1',httpsTrigger:{}};exports_.http=http;
function event(name,form,type) {
  const fn=async(...args)=>record({name,kind:'event',argc:args.length,data:args[0],context:args[1],...identity()});
  fn.run=fn;
  if(type==='schedule')metadata(fn,form,form==='legacy'?{eventTrigger:{eventType:'google.pubsub.topic.publish',resource:'projects/demo-generation/topics/t'},schedule:{schedule:'every 5 minutes'}}:{scheduleTrigger:{schedule:'every 5 minutes'}});
  else if(type==='pubsub')metadata(fn,form,form==='gcfv2'?{eventTrigger:{eventType:'google.cloud.pubsub.topic.v1.messagePublished',eventFilters:{topic:'projects/demo-generation/topics/t'}}}:{eventTrigger:{eventType:'google.pubsub.topic.publish',...(form==='legacy'?{resource:'projects/demo-generation/topics/t'}:{eventFilters:{resource:'projects/demo-generation/topics/t'}})}});
  else if(type==='auth')metadata(fn,form,{eventTrigger:{eventType:'providers/firebase.auth/eventTypes/user.create',...(form==='legacy'?{resource:'projects/demo-generation'}:{eventFilters:{resource:'projects/demo-generation'}})}});
  exports_[name]=fn;
}
for(const [name,form,type] of [
 ['scheduleV1','gcfv1','schedule'],['scheduleV2','gcfv2','schedule'],['scheduleLegacy','legacy','schedule'],
 ['pubV1','gcfv1','pubsub'],['pubV2','gcfv2','pubsub'],['pubLegacy','legacy','pubsub'],['authV1','gcfv1','auth'],
]) event(name,form,type);
const mutate=async data=>{
  const fn=exports_[data.name];
  if(data.mode==='throw'){
    Object.defineProperty(fn,'__endpoint',{configurable:true,get(){throw Error('metadata re-read after hello');}});
    Object.defineProperty(fn,'__trigger',{configurable:true,get(){throw Error('legacy metadata re-read after hello');}});
  }else if(data.mode==='replace')fn.__endpoint={platform:data.platform,scheduleTrigger:{schedule:'every 5 minutes'}};
  else if(data.mode==='clear') {delete fn.__endpoint; delete fn.__trigger;}
  record({name:'mutate',changed:data.name});
};
mutate.run=mutate;mutate.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'}};exports_.mutate=mutate;
// Invalid endpoint generations must not produce an executable, contradictory manifest.
for(const [name,platform] of [['badMissing',undefined],['badNull',null],['badOther','gcfv3']]){
 const fn=async()=>record({name,unexpected:true});fn.__endpoint={platform,scheduleTrigger:{schedule:'every 5 minutes'}};fn.run=fn;exports_[name]=fn;
}
module.exports=exports_;
`;

async function start(t, {secrets=false}={}) {
  const dir=await mkdtemp(join(tmpdir(),'fireemu-generation-'));
  const put=async(p,content)=>{const path=join(dir,p);await mkdir(dirname(path),{recursive:true});await writeFile(path,content);};
  await put('package.json',JSON.stringify({private:true,main:'index.cjs'}));await put('index.cjs',fixtureSource);
  await put('node_modules/express/package.json',JSON.stringify({name:'express',version:'5.0.0',main:'index.cjs'}));
  await put('node_modules/express/index.cjs',expressDouble);
  await put('node_modules/firebase-functions/package.json',JSON.stringify({name:'firebase-functions',version:'7.3.2',main:'index.cjs',exports:{'.':'./index.cjs','./https':'./https.cjs','./v2/options':'./options.cjs'}}));
  await put('node_modules/firebase-functions/index.cjs','module.exports={};');
  await put('node_modules/firebase-functions/options.cjs','exports.getGlobalOptions=()=>({});');
  await put('node_modules/firebase-functions/https.cjs',`exports.HttpsError=class extends Error {constructor(code,message){super(message);this.code=code;this.httpErrorCode={canonicalName:'INVALID_ARGUMENT',status:400};}};`);
  const child=spawn(process.execPath,[runner,'--source',dir],{env:{PATH:process.env.PATH,GCLOUD_PROJECT:project,FIREEMU_RUNNER_SECRET:secret,
    ...(secrets?{FIREEMU_LOCAL_SECRETS_JSON:JSON.stringify({TASK_SECRET:'synthetic-task-secret'})}:{})},stdio:['pipe','pipe','pipe']});
  const frames=[];let pending=Buffer.alloc(0),stderr='',outcome,parseError;const clients=[];
  const exited=once(child,'exit').then(([code,signal])=>(outcome={code,signal}));
  child.stdin.on('error',()=>{});child.stderr.on('data',b=>{if(stderr.length<65536)stderr+=b.toString();});
  child.stdout.on('data',b=>{pending=Buffer.concat([pending,b]);for(;;){const nl=pending.indexOf(10);if(nl<0)return;
    const n=Number(pending.subarray(0,nl).toString());if(!Number.isSafeInteger(n)||n<=0||n>16*1024*1024){parseError=Error('invalid output');return;}
    if(pending.length<nl+1+n)return;try{frames.push(JSON.parse(pending.subarray(nl+1,nl+1+n).toString('utf8')));}catch(e){parseError=e;return;}pending=pending.subarray(nl+1+n);}});
  async function wait(predicate,label){const end=performance.now()+4000;while(performance.now()<end){if(parseError)throw parseError;const r=await predicate();if(r)return r;if(outcome)throw Error(`${label}: exit ${JSON.stringify(outcome)} ${stderr.slice(-1000)}`);await new Promise(r=>setTimeout(r,5));}throw Error(`timeout: ${label}`);}
  t.after(async()=>{for(const c of clients)c.destroy();if(!outcome)child.kill('SIGKILL');await exited;child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();await rm(dir,{recursive:true,force:true});});
  const hello=await wait(()=>frames.find(x=>x.type==='hello'),'hello');let seq=0;
  const calls=async()=>{try{return(await readFile(join(dir,'calls.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}catch(e){if(e.code==='ENOENT')return [];throw e;}};
  const invoke=async(name,trigger,event)=>{const invocationId=`g${++seq}`;child.stdin.write(encode({type:'invoke',invocationId,function:name,entryPoint:name,trigger,event}));return wait(()=>frames.find(x=>x.type==='result'&&x.invocationId===invocationId),'invocation');};
  const httpCall=(name,body,{key=secret,region='us-central1',namespace=project}={})=>new Promise((resolve,reject)=>{
    const data=JSON.stringify(body);const req=request({host:'127.0.0.1',port:hello.httpPort,path:`/${namespace}/${region}/${name}`,method:'POST',agent:false,
      headers:{'x-fireemu-runner-secret':key,'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}},res=>{
      const chunks=[];res.on('data',b=>chunks.push(b));res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,text:Buffer.concat(chunks).toString()}));});
    req.on('error',reject);req.setTimeout(3000,()=>req.destroy(Error('fixture HTTP deadline')));req.end(data);clients.push(req);
  });
  return {hello,child,frames,calls,invoke,httpCall,mutate:async(name,mode,platform)=>{const r=await invoke('mutate','schedule',{data:{name,mode,platform}});assert.equal(r.ok,true);}};
}

for(const [name,generation] of [['taskV1',1],['taskLegacy',1],['taskV2',2],['taskDual',1],['taskV2Dual',2]]) {
  test(`${name}: discover Task Queue, preserve retry/rate limits, call HTTP wrapper`,{timeout:10000},async t=>{
    const f=await start(t,{secrets:true});const spec=f.hello.manifest.functions.find(x=>x.name===name);
    assert.ok(spec,'Task Queue was incorrectly ignored');assert.equal(spec.trigger.type,'tasks');assert.equal(spec.generation,generation);
    assert.equal(spec.timeoutSeconds,37);assert.equal(spec.region,'europe-west1');
    assert.deepEqual(spec.trigger.retryConfig,{maxAttempts:4,minBackoffSeconds:0,maxBackoffSeconds:60,maxRetrySeconds:null,maxDoublings:3});
    assert.deepEqual(spec.trigger.rateLimits,{maxConcurrentDispatches:2,maxDispatchesPerSecond:7});
    const r=await f.httpCall(name,{data:{message:'タスク 😀'}},{region:'europe-west1'});assert.equal(r.status,200);
    const body=JSON.parse(r.text);assert.equal(body.kind,'task-wrapper');assert.deepEqual(body.data,{message:'タスク 😀'});assert.equal(body.raw,true);
    assert.equal(body.signature,'http');assert.equal(body.target,name);assert.equal(body.service,name);
    assert.equal(body.secret,name==='taskLegacy'?null:'synthetic-task-secret');
  });
}
test('v1 empty task options retain default retry/rate records and endpoint region',{timeout:10000},async t=>{
  const f=await start(t);const spec=f.hello.manifest.functions.find(x=>x.name==='taskEmpty');assert.ok(spec);
  assert.deepEqual(spec.trigger,{type:'tasks',retryConfig:{},rateLimits:{}});
  const r=await f.httpCall('taskEmpty',{data:null},{region:'europe-west1'});assert.equal(r.status,200);assert.equal(JSON.parse(r.text).data,null);
});
for(const [name,argc] of [['blockV1',2],['blockV2',1],['blockLegacy',2]]){
 test(`${name}: Blocking Auth uses HTTP signature and declared callback arity`,{timeout:10000},async t=>{
  const f=await start(t);const r=await f.httpCall(name,{data:{user:{uid:'owned'},context:{tag:'ctx'}}});
  assert.equal(r.status,200);assert.equal(JSON.parse(r.text).userRecord.displayName,'http');
  const c=(await f.calls()).find(x=>x.name===name);assert.equal(c.argc,argc);assert.equal(c.tag,'ctx');assert.deepEqual(c.user,{uid:'owned'});assert.equal(c.signature,'http');
 });
}
test('ordinary v1 HTTP keeps http identity',{timeout:10000},async t=>{
 const f=await start(t);const r=await f.httpCall('http',{});assert.equal(r.status,200);assert.equal(JSON.parse(r.text).signature,'http');
});
const eventCases=[
 ['scheduleV1','schedule','event',2],['scheduleV2','schedule','http',1],['scheduleLegacy','schedule','event',2],
 ['pubV1','pubsub','event',2],['pubV2','pubsub','cloudevent',1],['pubLegacy','pubsub','event',2],['authV1','auth','event',2],
];
const eventFor=trigger=>({id:'evt',time:'2026-01-02T03:04:05Z',source:trigger==='auth'?'//firebaseauth.googleapis.com/projects/demo-generation':'//pubsub.googleapis.com/projects/demo-generation/topics/t',
 type:trigger==='auth'?'google.firebase.auth.user.v1.created':'google.cloud.pubsub.topic.v1.messagePublished',data:{message:{text:'テスト'},uid:'owned',jobName:'job'}});
for(const [name,trigger,signature,argc] of eventCases){
 test(`${name}: unchanged event shape and function identity`,{timeout:10000},async t=>{
   const f=await start(t);const event=eventFor(trigger);assert.equal((await f.invoke(name,trigger,event)).ok,true);
   const c=(await f.calls()).find(x=>x.name===name);assert.equal(c.argc,argc);assert.equal(c.signature,signature);assert.equal(c.target,name);assert.equal(c.service,name);
   assert.deepEqual(c.data,argc===1?(trigger==='schedule'?event.data:event):trigger==='schedule'?{}:trigger==='pubsub'?event.data.message:event.data);
 });
}
for(const [name,trigger,signature,argc] of eventCases){
 test(`${name}: do not re-read endpoint/trigger metadata after hello`,{timeout:10000},async t=>{
   const f=await start(t);await f.mutate(name,'throw');const event=eventFor(trigger);
   const r=await f.invoke(name,trigger,event);assert.equal(r.ok,true,r.error);
   const c=(await f.calls()).find(x=>x.name===name);assert.equal(c.argc,argc);assert.equal(c.signature,signature);
 });
}
for(const [name,argc,platform] of [['blockV1',2,'gcfv2'],['blockV2',1,'gcfv1'],['blockLegacy',2,'gcfv2']]){
 test(`${name}: callback generation stays bound to announced manifest after mutation`,{timeout:10000},async t=>{
  const f=await start(t);await f.mutate(name,'replace',platform);
  const r=await f.httpCall(name,{data:{user:{uid:'owned'},context:{tag:'ctx'}}});assert.equal(r.status,200);
  const c=(await f.calls()).find(x=>x.name===name);assert.equal(c.argc,argc);assert.deepEqual(c.user,{uid:'owned'});assert.equal(c.tag,'ctx');
 });
}
for(const [name,trigger,argc,platform] of [['pubV1','pubsub',2,'gcfv2'],['pubV2','pubsub',1,'gcfv1'],['pubLegacy','pubsub',2,'gcfv2']]){
 test(`${name}: endpoint replacement cannot change invocation convention`,{timeout:10000},async t=>{
  const f=await start(t);await f.mutate(name,'replace',platform);const event=eventFor(trigger);
  const r=await f.invoke(name,trigger,event);assert.equal(r.ok,true,r.error);
  const c=(await f.calls()).find(x=>x.name===name);assert.equal(c.argc,argc);assert.deepEqual(c.data,argc===2?event.data.message:event);
 });
}
test('unknown endpoint generations are named ignored rather than contradictory executable manifests',{timeout:10000},async t=>{
 const f=await start(t);for(const name of ['badMissing','badNull','badOther']){
  assert.equal(f.hello.manifest.functions.some(x=>x.name===name),false);const ignored=f.hello.manifest.ignored.find(x=>x.name===name);
  assert.ok(ignored);assert.equal(ignored.scope,'unsupported');assert.match(ignored.reason,/platform/);
 }
 assert.equal((await f.invoke('scheduleV2','schedule',eventFor('schedule'))).ok,true);
});
test('Task Queue never falls through to unsupported IPC dispatch and retains HTTP auth/namespace checks',{timeout:10000},async t=>{
 const f=await start(t);const ipc=await f.invoke('taskV1','tasks',{});assert.equal(ipc.ok,false);
 assert.equal((await f.httpCall('taskV1',{data:1},{region:'europe-west1',key:'wrong'})).status,403);
 assert.equal((await f.httpCall('taskV1',{data:1},{region:'us-central1'})).status,404);
 assert.equal((await f.httpCall('taskV1',{data:1},{region:'europe-west1',namespace:'demo-other'})).status,404);
 assert.equal((await f.calls()).filter(x=>x.name==='taskV1').length,0);
 assert.equal((await f.httpCall('taskV1',{data:1},{region:'europe-west1'})).status,200);
});

test('null task queue options are defaults, malformed non-null records are named ignored',{timeout:10000},async t=>{
 const f=await start(t);const spec=f.hello.manifest.functions.find(x=>x.name==='taskNull');
 assert.ok(spec);assert.deepEqual(spec.trigger,{type:'tasks',retryConfig:{},rateLimits:{}});
 for(const name of ['badTaskScalar','badTaskArray','badRetryArray','badRetryFalse','badRateScalar']){
  assert.equal(f.hello.manifest.functions.some(x=>x.name===name),false);
  assert.equal(f.hello.manifest.ignored.find(x=>x.name===name)?.scope,'unsupported');
 }
 assert.equal((await f.httpCall('taskNull',{data:1},{region:'europe-west1'})).status,200);
});
