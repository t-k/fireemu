// Actual runner and IPC; parameter/SDK metadata is a fixture, not the installed SDK.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { request } from 'node:http';

const runner = fileURLToPath(new URL('./index.mjs', import.meta.url));
const encode = value => { const b=Buffer.from(JSON.stringify(value)); return Buffer.concat([Buffer.from(`${b.length}\n`),b]); };
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
const prelude = String.raw`
const fs = require('node:fs'), path = require('node:path');
const seen = { reads: {}, evaluations: {}, json: {} };
const reset = { [Symbol.for('firebase-functions:ResetValue:Tag')]: true };
function param(name, result) {
  const expression = { actual: result, [Symbol.for('firebase-functions:Expression:Tag')]: true,
    toJSON() { seen.json[name] = (seen.json[name] || 0) + 1; return 'params.' + name; } };
  Object.defineProperty(expression,'value',{ get() {
    seen.reads[name]=(seen.reads[name]||0)+1;
    if (seen.reads[name]>1) throw Error('value accessor was read again');
    return function() { seen.evaluations[name]=(seen.evaluations[name]||0)+1; return this.actual; };
  }});
  return expression;
}
function define(name, platform, trigger) {
  const fn=async(...args)=>{
    fs.writeFileSync(path.join(__dirname,'call.json'),JSON.stringify({name,argc:args.length,seen,
      target:process.env.FUNCTION_TARGET,signature:process.env.FUNCTION_SIGNATURE_TYPE}));
    if (args[1]?.json) args[1].json({ok:true,name});
  };
  fn.run=fn;
  if (platform === 'legacy') fn.__trigger=trigger;
  else fn.__endpoint={platform,...trigger};
  exports[name]=fn;
  return fn;
}
define('healthy','gcfv2',{eventTrigger:{eventType:'google.cloud.pubsub.topic.v1.messagePublished',eventFilters:{topic:'projects/demo-options/topics/t'}}});

`;

async function start(t, source, { http = false } = {}) {
  const dir=await mkdtemp(join(tmpdir(),'fireemu-options-'));
  await writeFile(join(dir,'package.json'),JSON.stringify({main:'index.cjs',type:'commonjs'}));
  await writeFile(join(dir,'index.cjs'),prelude+'\n'+source);
  if (http) {
    const express = join(dir,'node_modules/express'); await mkdir(express,{recursive:true});
    await writeFile(join(express,'package.json'),JSON.stringify({name:'express',version:'4.21.2',main:'index.cjs'}));
    await writeFile(join(express,'index.cjs'),expressDouble);
  }
  const env={ PATH:process.env.PATH, HOME:dir, GCLOUD_PROJECT:'demo-options', FIREBASE_CONFIG:'{"projectId":"demo-options"}', FIREEMU_RUNNER_SECRET:'fixture-proxy' };
  const child=spawn(process.execPath,[runner,'--source',dir],{env,stdio:['pipe','pipe','pipe']});
  let outcome, stderr='',pending=Buffer.alloc(0),error; const frames=[];
  const exited=once(child,'exit').then(([code,signal])=>{outcome={code,signal};});
  child.stdin.on('error',()=>{});
  child.stderr.on('data',b=>{if(stderr.length<65536)stderr+=b;});
  child.stdout.on('data',b=>{pending=Buffer.concat([pending,b]);for(;;){const nl=pending.indexOf(10);if(nl<0)return;
    const n=Number(pending.subarray(0,nl).toString());if(!Number.isSafeInteger(n)||n<1||n>16777216){error=Error('bad frame');return;}
    if(pending.length<nl+1+n)return;try{frames.push(JSON.parse(pending.subarray(nl+1,nl+1+n).toString()));}catch(e){error=e;return;}
    pending=pending.subarray(nl+1+n);
  }});
  t.after(async()=>{if(!outcome)child.kill('SIGKILL');await exited;child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();await rm(dir,{recursive:true,force:true});});
  async function wait(predicate) {
    const end=performance.now()+5000;
    for(;;){if(error)throw error;const value=predicate();if(value)return value;if(outcome)throw Error(`runner exit ${JSON.stringify(outcome)} ${stderr}`);
      if(performance.now()>end)throw Error(`runner fixture timed out ${stderr}`);await new Promise(r=>setTimeout(r,5));}
  }
  const hello=await wait(()=>frames.find(f=>f.type==='hello'));
  let seq=0;
  async function invoke(name, trigger = "pubsub") {
    const invocationId=`options-${++seq}`;
    child.stdin.write(encode({type:'invoke',invocationId,function:name,entryPoint:name,trigger,
      event:{id:'evt',time:'2026-09-20T00:00:00Z',type:'google.cloud.pubsub.topic.v1.messagePublished',source:'//pubsub.googleapis.com/projects/demo-options/topics/t',data:{message:{data:'eA=='}}}}));
    return wait(()=>frames.find(f=>f.type==='result'&&f.invocationId===invocationId));
  }
  const spec = name => hello.manifest.functions.find(f=>f.name===name);
  const ignored = name => hello.manifest.ignored.find(f=>f.name===name);
  const called=async()=>JSON.parse(await readFile(join(dir,'call.json'),'utf8'));
  return {hello,spec,ignored,invoke,called};
}

// The remaining tests intentionally share the existing runner protocol, not
// private resolver functions. They also run against the unmodified v36.
const v1fs = "providers/cloud.firestore/eventTypes/document.write";
const v2fs = "google.cloud.firestore.document.v1.written";
const v1storage = "google.storage.object.finalize";
const v2storage = "google.cloud.storage.object.v1.finalized";
const v2pubsub = "google.cloud.pubsub.topic.v1.messagePublished";

test('an empty projected Pub/Sub topic is isolated from healthy siblings', async t => {
  const f = await start(t, `define('subject','gcfv2',{eventTrigger:{eventType:'${v2pubsub}',eventFilters:{topic:'projects/demo-options/topics/'}}});`);
  assert.equal(f.spec('subject'), undefined);
  assert.equal(f.ignored('subject')?.scope, 'unsupported');
  assert.equal((await f.invoke('healthy')).ok, true);
});

test('rejected async trigger containers and unknown keys do not terminate siblings', async t => {
  const f = await start(t, `
    define('schedule','gcfv2',{scheduleTrigger:{schedule:'every 5 minutes',retryConfig:Promise.reject(Error('schedule'))}});
    define('task','gcfv2',{taskQueueTrigger:{retryConfig:Promise.reject(Error('task'))}});
    define('filters','gcfv2',{eventTrigger:{eventType:'com.example.changed',channel:'custom',eventFilters:Promise.reject(Error('filters'))}});
    define('unknown','gcfv2',{taskQueueTrigger:{retryConfig:{unsupported:Promise.reject(Error('unknown'))}}});
  `);
  for (const name of ['schedule','task','filters','unknown']) {
    assert.equal(f.spec(name), undefined);
    assert.equal(f.ignored(name)?.scope, 'unsupported');
  }
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal((await f.invoke('healthy')).ok, true);
});

for (const form of ["gcfv1", "legacy"]) {
  for (const [kind, type, resource, expected] of [
    ["firestore", v1fs, "projects/documents/databases/tenant-db/documents/注文/{id}", {type:"firestore",eventType:v2fs,database:"tenant-db",document:"注文/{id}"}],
    ["storage", v1storage, "projects/_/buckets/image-bucket", {type:"storage",eventType:v2storage,bucket:"image-bucket"}],
    ["pubsub", "google.pubsub.topic.publish", "projects/demo-options/topics/news", {type:"pubsub",topic:"news"}],
  ]) {
    test(`${form} ${kind}: resolve an SDK-style resource expression, preserve invocation`, async t => {
      const key = form === "legacy" ? "resource:param('resource'," + JSON.stringify(resource) + ")"
        : "eventFilters:{resource:param('resource'," + JSON.stringify(resource) + ")}";
      const f=await start(t, `define('subject','${form}',{eventTrigger:{eventType:${JSON.stringify(type)},${key}}});`);
      assert.deepEqual(f.spec('subject')?.trigger,expected);
      assert.equal((await f.invoke('subject',kind)).ok,true);
      const c=await f.called(); assert.equal(c.argc,2);
      assert.deepEqual(c.seen,{reads:{resource:1},evaluations:{resource:1},json:{}});
    });
  }
}

test('v2 Firestore: database and wildcard pattern resolve without JSON/CEL conversion',async t=>{
  const f=await start(t,`define('subject','gcfv2',{eventTrigger:{eventType:'${v2fs}',eventFilters:{database:param('database','tenant-db')},eventFilterPathPatterns:{document:param('document','注文/{id}/literal%2F/{child}')}}});`);
  assert.deepEqual(f.spec('subject')?.trigger,{type:'firestore',eventType:v2fs,database:'tenant-db',document:'注文/{id}/literal%2F/{child}'});
  assert.equal((await f.invoke('subject','firestore')).ok,true);
  assert.deepEqual((await f.called()).seen,{reads:{database:1,document:1},evaluations:{database:1,document:1},json:{}});
});

test('v2 Firestore: exact document filter and absent database keep the default',async t=>{
  const f=await start(t,`define('subject','gcfv2',{eventTrigger:{eventType:'${v2fs}',eventFilters:{document:param('document','docs/one')}}});`);
  assert.deepEqual(f.spec('subject')?.trigger,{type:'firestore',eventType:v2fs,database:'(default)',document:'docs/one'});
});

test('v2 Firestore: selected pattern takes precedence without evaluating fallback',async t=>{
  const f=await start(t,`const filters={database:'(default)'};Object.defineProperty(filters,'document',{get(){throw Error('unselected fallback');}});define('subject','gcfv2',{eventTrigger:{eventType:'${v2fs}',eventFilters:filters,eventFilterPathPatterns:{document:param('selected','docs/{id}')}}});`);
  assert.equal(f.spec('subject')?.trigger.document,'docs/{id}');
});

test('v2 Storage and Pub/Sub: real runtime bucket and topic, not parameter strings',async t=>{
  const f=await start(t,`define('storage','gcfv2',{eventTrigger:{eventType:'${v2storage}',eventFilters:{bucket:param('bucket','image-bucket')}}});define('pubsub','gcfv2',{eventTrigger:{eventType:'${v2pubsub}',eventFilters:{topic:param('topic','projects/demo-options/topics/news')}}});`);
  assert.equal(f.spec('storage')?.trigger.bucket,'image-bucket');assert.equal(f.spec('pubsub')?.trigger.topic,'news');
  assert.equal((await f.invoke('storage','storage')).ok,true);assert.equal((await f.invoke('pubsub')).ok,true);
  assert.deepEqual((await f.called()).seen.json,{});
});

test('v2 Eventarc: resolve own filter values, including empty and prototype-looking keys',async t=>{
  const f=await start(t,`const filters=Object.create({inherited:'must-not-copy'});filters.source=param('source','catalog');filters.empty=param('empty','');Object.defineProperty(filters,'__proto__',{value:param('proto','literal'),enumerable:true});filters.toJSON='literal-toJSON-filter';define('subject','gcfv2',{eventTrigger:{eventType:'com.example.changed',channel:param('channel','locations/asia-northeast1/channels/custom'),eventFilters:filters}});`);
  const trigger=f.spec('subject')?.trigger;assert.ok(trigger);
  assert.equal(trigger.channel,'locations/asia-northeast1/channels/custom');
  assert.deepEqual(trigger.filters,JSON.parse('{"source":"catalog","empty":"","__proto__":"literal","toJSON":"literal-toJSON-filter"}'));
  assert.equal((await f.invoke('subject','eventarc')).ok,true);assert.deepEqual((await f.called()).seen.json,{});
});

test('Firebase Alerts: parameterized filters retain the google sentinel channel',async t=>{
  const f=await start(t,`define('subject','gcfv2',{eventTrigger:{eventType:'google.firebase.firebasealerts.alerts.v1.published',eventFilters:{alerttype:param('type','billing'),appid:param('app','app-one')}}});`);
  assert.deepEqual(f.spec('subject')?.trigger,{type:'eventarc',eventType:'google.firebase.firebasealerts.alerts.v1.published',channel:'google',filters:{alerttype:'billing',appid:'app-one'}});
});

test('Eventarc filter metadata is detached before later exports can mutate it',async t=>{
  const f=await start(t,`const filters={tenant:'tenant-one'};define('subject','gcfv2',{eventTrigger:{eventType:'com.example.changed',channel:'custom',eventFilters:filters}});const later=define('later','gcfv2',{eventTrigger:{eventType:'${v2pubsub}',eventFilters:{topic:'t'}}});Object.defineProperty(later.__endpoint,'omit',{get(){filters.tenant='tenant-two';return false;}});`);
  assert.equal(f.spec('subject')?.trigger.filters.tenant,'tenant-one');
});

for(const [label,trigger] of [
  ['unresolved database',`{eventType:'${v2fs}',eventFilters:{database:param('bad',undefined)},eventFilterPathPatterns:{document:'docs/{id}'}}`],
  ['null database expression',`{eventType:'${v2fs}',eventFilters:{database:param('bad',null)},eventFilterPathPatterns:{document:'docs/{id}'}}`],
  ['object database',`{eventType:'${v2fs}',eventFilters:{database:{toJSON(){return 'db';}}},eventFilterPathPatterns:{document:'docs/{id}'}}`],
  ['invalid selected pattern',`{eventType:'${v2fs}',eventFilters:{document:'fallback/doc'},eventFilterPathPatterns:{document:param('bad',{})}}`],
  ['empty selected pattern',`{eventType:'${v2fs}',eventFilters:{document:'fallback/doc'},eventFilterPathPatterns:{document:''}}`],
  ['unresolved bucket',`{eventType:'${v2storage}',eventFilters:{bucket:param('bad',undefined)}}`],
  ['null bucket expression',`{eventType:'${v2storage}',eventFilters:{bucket:param('bad',null)}}`],
  ['numeric bucket',`{eventType:'${v2storage}',eventFilters:{bucket:7}}`],
  ['boolean topic',`{eventType:'${v2pubsub}',eventFilters:{topic:false}}`],
  ['async topic',`{eventType:'${v2pubsub}',eventFilters:{topic:{value(){return Promise.resolve('news');}}}}`],
  ['nested topic expression',`{eventType:'${v2pubsub}',eventFilters:{topic:param('outer',param('inner','news'))}}`],
  ['channel object',`{eventType:'com.example.changed',channel:{toJSON(){return 'custom';}}}`],
  ['boolean filter',`{eventType:'com.example.changed',channel:'custom',eventFilters:{tenant:false}}`],
  ['null exact filter',`{eventType:'com.example.changed',channel:'custom',eventFilters:{tenant:null}}`],
  ['async filter',`{eventType:'com.example.changed',channel:'custom',eventFilters:{tenant:{value(){return Promise.resolve('t');}}}}`],
  ['array filter container',`{eventType:'com.example.changed',channel:'custom',eventFilters:['oops']}`],
  ['false filter container',`{eventType:'com.example.changed',channel:'custom',eventFilters:false}`],
  ['filter container toJSON',`{eventType:'com.example.changed',channel:'custom',eventFilters:{tenant:'one',toJSON(){return {tenant:'two'};}}}`],
]) {
  test(`invalid ${label}: do not publish guessed routing metadata; keep healthy sibling`,async t=>{
    const f=await start(t,`define('subject','gcfv2',{eventTrigger:${trigger}});`);
    assert.equal(f.spec('subject'),undefined);assert.equal(f.ignored('subject')?.scope,'unsupported');
    assert.equal((await f.invoke('healthy')).ok,true);
    assert.deepEqual((await f.called()).seen.json,{});
  });
}

test('literal absent/reset database and bucket preserve preexisting defaults',async t=>{
  const f=await start(t,`for(const [name,value] of [['null',null],['reset',reset],['absent',undefined]]){define(name+'Fs','gcfv2',{eventTrigger:{eventType:'${v2fs}',eventFilters:{database:value,document:'docs/one'}}});define(name+'St','gcfv2',{eventTrigger:{eventType:'${v2storage}',eventFilters:{bucket:value}}});}`);
  for(const name of ['null','reset','absent']){assert.equal(f.spec(name+'Fs')?.trigger.database,'(default)');assert.equal(f.spec(name+'St')?.trigger.bucket,undefined);assert.ok(f.spec(name+'St'));}
});

for (const form of ['gcfv1','gcfv2','legacy']) {
  test(`${form} Schedule: resolve schedule/time zone/retry config before deriving retry`,async t=>{
    const schedule=`{schedule:param('schedule','every 5 minutes'),timeZone:param('zone','Asia/Tokyo'),retryConfig:{retryCount:param('count',3),maxRetrySeconds:param('seconds',300),minBackoffSeconds:0,maxBackoffSeconds:60,maxDoublings:2}}`;
    const definition=form==='legacy'?`{eventTrigger:{eventType:'google.pubsub.topic.publish',resource:'unused'},schedule:${schedule}}`:`{scheduleTrigger:${schedule}}`;
    const f=await start(t,`define('subject','${form}',${definition});`);
    assert.deepEqual(f.spec('subject')?.trigger,{type:'schedule',schedule:'every 5 minutes',timeZone:'Asia/Tokyo',retryConfig:{retryCount:3,maxRetrySeconds:300,minBackoffSeconds:0,maxBackoffSeconds:60,maxDoublings:2}});
    assert.equal(f.spec('subject').retry,true);assert.equal((await f.invoke('subject','schedule')).ok,true);
    assert.equal((await f.called()).argc,form==='gcfv2'?1:2);assert.deepEqual((await f.called()).seen.json,{});
  });
  test(`${form} Tasks: resolve retry and rate parameters, preserve null/zero/fractions`,async t=>{
    const f=await start(t,`define('subject','${form}',{taskQueueTrigger:{retryConfig:{maxAttempts:param('attempts',4),minBackoffSeconds:param('min',0.25),maxBackoffSeconds:60,maxRetrySeconds:null,maxDoublings:0},rateLimits:{maxConcurrentDispatches:param('concurrent',2),maxDispatchesPerSecond:param('rate',0.5)}}});`);
    assert.deepEqual(f.spec('subject')?.trigger,{type:'tasks',retryConfig:{maxAttempts:4,minBackoffSeconds:0.25,maxBackoffSeconds:60,maxRetrySeconds:null,maxDoublings:0},rateLimits:{maxConcurrentDispatches:2,maxDispatchesPerSecond:0.5}});
    assert.deepEqual(f.hello.manifest.ignored,[]);
  });
}

test('zero schedule retry expression is false and null/reset numeric options remain defaults',async t=>{
  const f=await start(t,`define('subject','gcfv2',{scheduleTrigger:{schedule:'every 5 minutes',timeZone:reset,retryConfig:{retryCount:param('count',0),maxRetrySeconds:null,minBackoffSeconds:reset}}});`);
  assert.equal(f.spec('subject')?.retry,false);assert.equal(f.spec('subject')?.trigger.timeZone,undefined);
  assert.deepEqual(f.spec('subject')?.trigger.retryConfig,{retryCount:0,maxRetrySeconds:null,minBackoffSeconds:null});
});

test('schedule/task retry metadata is detached and cannot replace its JSON envelope',async t=>{
  const f=await start(t,`const retry={retryCount:3};define('subject','gcfv2',{scheduleTrigger:{schedule:'every 5 minutes',retryConfig:retry}});const later=define('later','gcfv2',{taskQueueTrigger:{}});Object.defineProperty(later.__endpoint,'omit',{get(){retry.retryCount=0;return false;}});`);
  assert.equal(f.spec('subject')?.retry,true);assert.equal(f.spec('subject')?.trigger.retryConfig.retryCount,3);
});

for(const [label,definition] of [
  ['schedule async',`{scheduleTrigger:{schedule:{value(){return Promise.resolve('every 5 minutes');}}}}`],
  ['schedule empty',`{scheduleTrigger:{schedule:''}}`],
  ['schedule missing',`{scheduleTrigger:{}}`],
  ['schedule zone object',`{scheduleTrigger:{schedule:'every 5 minutes',timeZone:{toJSON(){return 'Asia/Tokyo';}}}}`],
  ['retry string',`{scheduleTrigger:{schedule:'every 5 minutes',retryConfig:{retryCount:'3'}}}`],
  ['retry NaN',`{scheduleTrigger:{schedule:'every 5 minutes',retryConfig:{retryCount:param('bad',NaN)}}}`],
  ['retry unresolved',`{scheduleTrigger:{schedule:'every 5 minutes',retryConfig:{retryCount:param('bad',undefined)}}}`],
  ['retry container toJSON',`{scheduleTrigger:{schedule:'every 5 minutes',retryConfig:{retryCount:1,toJSON(){return {retryCount:0};}}}}`],
  ['task boolean',`{taskQueueTrigger:{retryConfig:{maxAttempts:false}}}`],
  ['task infinity',`{taskQueueTrigger:{rateLimits:{maxDispatchesPerSecond:param('bad',Infinity)}}}`],
  ['task async',`{taskQueueTrigger:{rateLimits:{maxConcurrentDispatches:{value(){return Promise.resolve(3);}}}}}`],
  ['task array container',`{taskQueueTrigger:{rateLimits:[]}}`],
  ['unknown retry option',`{taskQueueTrigger:{retryConfig:{notSupported:2}}}`],
]) {
  test(`invalid ${label}: isolate rather than fall back to native defaults`,async t=>{
    const f=await start(t,`define('subject','gcfv2',${definition});`);
    assert.equal(f.spec('subject'),undefined);assert.equal(f.ignored('subject')?.scope,'unsupported');
    assert.equal((await f.invoke('healthy')).ok,true);assert.deepEqual((await f.called()).seen.json,{});
  });
}

for (const form of ['legacy', 'gcfv1']) {
  test(`${form} Schedule: translate SDK Duration aliases to native numeric seconds`, async t => {
    const options="{schedule:'every 5 minutes',retryConfig:{retryCount:param('count',2),maxRetryDuration:param('max','300s'),minBackoffDuration:param('min','0.125s'),maxBackoffDuration:'60.000000001s',maxDoublings:0}}";
    const config=form==='legacy'?`{eventTrigger:{eventType:'google.pubsub.topic.publish',resource:'unused'},schedule:${options}}`:`{scheduleTrigger:${options}}`;
    const f=await start(t,`define('subject','${form}',${config});`);
    assert.deepEqual(f.spec('subject')?.trigger.retryConfig,{retryCount:2,maxRetrySeconds:300,minBackoffSeconds:0.125,maxBackoffSeconds:60.000000001,maxDoublings:0});
    assert.equal((await f.invoke('subject','schedule')).ok,true);
    assert.deepEqual((await f.called()).seen.json,{});
  });
}

test('legacy Duration defaults stay null and the source map is never modified',async t=>{
  const f=await start(t,`const retry={maxRetryDuration:null,minBackoffDuration:reset,maxBackoffDuration:undefined};define('subject','legacy',{eventTrigger:{eventType:'google.pubsub.topic.publish'},schedule:{schedule:'every 5 minutes',retryConfig:retry}});const later=define('later','gcfv2',{taskQueueTrigger:{}});Object.defineProperty(later.__endpoint,'omit',{get(){if('maxRetrySeconds' in retry)throw Error('mutated input');return false;}});`);
  assert.deepEqual(f.spec('subject')?.trigger.retryConfig,{maxRetrySeconds:null,minBackoffSeconds:null});
  assert.ok(f.spec('later'));
});

for (const duration of ['"1.5sjunk"','"1e2s"','" 1s"','"-1s"','"1.0000000001s"','1','param("bad",undefined)']) {
  test(`legacy Duration rejects invalid ${duration} rather than dropping the setting`,async t=>{
    const f=await start(t,`define('subject','legacy',{eventTrigger:{eventType:'google.pubsub.topic.publish'},schedule:{schedule:'every 5 minutes',retryConfig:{maxRetryDuration:${duration}}}});`);
    assert.equal(f.spec('subject'),undefined);assert.equal(f.ignored('subject')?.scope,'unsupported');
    assert.equal((await f.invoke('healthy')).ok,true);
  });
}

test('legacy Duration plus seconds alias is ambiguous and must not choose an order',async t=>{
  const f=await start(t,`for(const [name,retry] of [['forward',{maxRetryDuration:'10s',maxRetrySeconds:20}],['reverse',{maxRetrySeconds:20,maxRetryDuration:'10s'}]])define(name,'legacy',{eventTrigger:{eventType:'google.pubsub.topic.publish'},schedule:{schedule:'every 5 minutes',retryConfig:retry}});`);
  for(const name of ['forward','reverse']){assert.equal(f.spec(name),undefined);assert.equal(f.ignored(name)?.scope,'unsupported');}
  assert.equal((await f.invoke('healthy')).ok,true);
});

for (const platform of ['gcfv1','gcfv2','legacy']) {
  test(`${platform} pre-rendered CEL schedule is explicitly unsupported, not announced as cron`,async t=>{
    const options="{schedule:'{{ params.SCHEDULE }}',timeZone:'Asia/Tokyo'}";
    const config=platform==='legacy'?`{eventTrigger:{eventType:'google.pubsub.topic.publish'},schedule:${options}}`:`{scheduleTrigger:${options}}`;
    const f=await start(t,`define('subject','${platform}',${config});`);
    assert.equal(f.spec('subject'),undefined);assert.equal(f.ignored('subject')?.scope,'unsupported');
    assert.equal((await f.invoke('healthy')).ok,true);
  });
}

for(const platform of ['gcfv1','gcfv2','legacy']) {
  test(`${platform} Tasks: resolved parameters retain the exported HTTP wrapper`,async t=>{
    const f=await start(t,`const fn=define('subject','${platform}',{taskQueueTrigger:{retryConfig:{maxAttempts:param('attempts',4)},rateLimits:{maxDispatchesPerSecond:param('rate',0.5)}}});fn.run=()=>{throw Error('must not bypass HTTP wrapper');};`,{http:true});
    assert.deepEqual(f.spec('subject')?.trigger,{type:'tasks',retryConfig:{maxAttempts:4},rateLimits:{maxDispatchesPerSecond:0.5}});
    const result=await new Promise((resolve,reject)=>{
      const req=request({host:'127.0.0.1',port:f.hello.httpPort,path:'/demo-options/us-central1/subject',method:'POST',headers:{'x-fireemu-runner-secret':'fixture-proxy','content-type':'application/json','content-length':2}},res=>{const chunks=[];res.on('data',b=>chunks.push(b));res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString()}));});
      req.setTimeout(3000,()=>req.destroy(Error('HTTP fixture timeout')));req.on('error',reject);req.end('{}');
    });
    assert.equal(result.status,200);assert.deepEqual(JSON.parse(result.body),{ok:true,name:'subject'});
    const called=await f.called();assert.equal(called.signature,'http');assert.deepEqual(called.seen,{reads:{attempts:1,rate:1},evaluations:{attempts:1,rate:1},json:{}});
  });
}
