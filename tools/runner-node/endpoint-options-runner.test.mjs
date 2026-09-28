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
function define(name, platform, options={}) {
  const fn=async(...args)=>{
    fs.writeFileSync(path.join(__dirname,'call.json'),JSON.stringify({name,argc:args.length,seen,
      target:process.env.FUNCTION_TARGET,signature:process.env.FUNCTION_SIGNATURE_TYPE}));
  };
  fn.__endpoint={platform,...options,eventTrigger:platform==='gcfv2'?
    {eventType:'google.cloud.pubsub.topic.v1.messagePublished',eventFilters:{topic:'projects/demo-options/topics/t'},...(options.eventTrigger||{})}:
    {eventType:'google.pubsub.topic.publish',eventFilters:{resource:'projects/demo-options/topics/t'},...(options.eventTrigger||{})}};
  exports[name]=fn;
  return fn;
}
define('healthy','gcfv2');
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
  async function invoke(name) {
    const invocationId=`options-${++seq}`;
    child.stdin.write(encode({type:'invoke',invocationId,function:name,entryPoint:name,trigger:'pubsub',
      event:{id:'evt',time:'2026-09-20T00:00:00Z',type:'google.cloud.pubsub.topic.v1.messagePublished',source:'//pubsub.googleapis.com/projects/demo-options/topics/t',data:{message:{data:'eA=='}}}}));
    return wait(()=>frames.find(f=>f.type==='result'&&f.invocationId===invocationId));
  }
  const spec = name => hello.manifest.functions.find(f=>f.name===name);
  const ignored = name => hello.manifest.ignored.find(f=>f.name===name);
  const called=async()=>JSON.parse(await readFile(join(dir,'call.json'),'utf8'));
  return {hello,spec,ignored,invoke,called};
}

for (const platform of ['gcfv1','gcfv2']) {
  test(`${platform}: omit expression true removes the function and prevents invocation`,async t=>{
    const f=await start(t,`define('subject','${platform}',{omit:param('omit',true)});`);
    assert.equal(f.spec('subject'),undefined); assert.equal(f.ignored('subject'),undefined);
    assert.equal((await f.invoke('subject')).ok,false); assert.equal((await f.invoke('healthy')).ok,true);
    assert.deepEqual((await f.called()).seen,{reads:{omit:1},evaluations:{omit:1},json:{}});
  });
  test(`${platform}: false omit/false retry and resolved region/timeout produce concrete metadata`,async t=>{
    const f=await start(t,`define('subject','${platform}',{omit:param('omit',false),region:param('region','asia-northeast1'),timeoutSeconds:param('timeout',37),eventTrigger:{retry:param('retry',false)}});`);
    const s=f.spec('subject');assert.ok(s);assert.equal(s.retry,false);assert.equal(s.region,'asia-northeast1');assert.equal(s.timeoutSeconds,37);
    assert.equal((await f.invoke('subject')).ok,true);
    const c=await f.called();assert.equal(c.argc,platform==='gcfv1'?2:1);
    assert.deepEqual(c.seen,{reads:{omit:1,region:1,timeout:1,retry:1},evaluations:{omit:1,region:1,timeout:1,retry:1},json:{}});
  });
  test(`${platform}: literal options remain unchanged`,async t=>{
    const f=await start(t,`define('subject','${platform}',{omit:false,region:['asia-northeast1'],timeoutSeconds:37,eventTrigger:{retry:true}});`);
    const s=f.spec('subject');assert.equal(s.region,'asia-northeast1');assert.equal(s.timeoutSeconds,37);assert.equal(s.retry,true);
    assert.equal((await f.invoke('subject')).ok,true);
  });
  test(`${platform}: true retry expression is resolved once, not serialized`,async t=>{
    const f=await start(t,`define('subject','${platform}',{eventTrigger:{retry:param('retry',true)}});`);
    assert.equal(f.spec('subject').retry,true);assert.equal((await f.invoke('subject')).ok,true);
    assert.deepEqual((await f.called()).seen,{reads:{retry:1},evaluations:{retry:1},json:{}});
  });
  test(`${platform}: zero timeout expression retains unset/default behavior`,async t=>{
    const f=await start(t,`define('subject','${platform}',{timeoutSeconds:param('zero',0)});`);
    assert.ok(f.spec('subject'));assert.equal(Object.hasOwn(f.spec('subject'),'timeoutSeconds'),false);
  });
  test(`${platform}: SDK reset/null and empty region list retain defaults`,async t=>{
    const f=await start(t,`define('subject','${platform}',{timeoutSeconds:reset,region:reset,eventTrigger:{retry:reset}});define('empty','${platform}',{region:[],timeoutSeconds:null});`);
    const s=f.spec('subject');assert.ok(s);assert.equal(s.region,undefined);assert.equal(s.timeoutSeconds,undefined);assert.equal(s.retry,false);
    assert.ok(f.spec('empty'));assert.equal(f.spec('empty').region,undefined);
  });
  test(`${platform}: omission is determined before unrelated option getters`,async t=>{
    const f=await start(t,`const fn=define('subject','${platform}',{omit:param('omit',true)});Object.defineProperty(fn.__endpoint,'timeoutSeconds',{enumerable:true,get(){throw Error('must not inspect omitted function');}});`);
    assert.equal(f.spec('subject'),undefined);assert.equal(f.ignored('subject'),undefined);assert.ok(f.spec('healthy'));
  });
}

for (const [label,options] of [
  ['omit string',`omit:'false'`],['omit integer',`omit:0`],['omit expression string',`omit:param('bad','true')`],
  ['omit unresolved',`omit:param('bad',undefined)`],['omit null result',`omit:param('bad',null)`],
  ['retry string',`eventTrigger:{retry:'false'}`],['retry expression object',`eventTrigger:{retry:param('bad',{})}`],
  ['retry boolean wrapper',`eventTrigger:{retry:new Boolean(false)}`],
  ['timeout string',`timeoutSeconds:'37'`],['timeout false',`timeoutSeconds:false`],
  ['timeout negative',`timeoutSeconds:-1`],['timeout fractional',`timeoutSeconds:param('bad',1.5)`],
  ['timeout infinite',`timeoutSeconds:param('bad',Infinity)`],['timeout NaN',`timeoutSeconds:NaN`],
  ['timeout unsafe',`timeoutSeconds:Number.MAX_SAFE_INTEGER+1`],
  ['timeout object',`timeoutSeconds:{toJSON(){return 37;}}`],
  ['region object',`region:{toJSON(){return 'us-central1';}}`],['region empty',`region:''`],
  ['region numeric',`region:param('bad',7)`],['region invalid array element',`region:['us-central1',3]`],
  ['region expression unresolved',`region:param('bad',undefined)`],
  ['expression is not a CEL interpreter',`omit:'{{ params.SKIP }}'`],
]) {
 test(`invalid ${label}: isolate as named ignored; healthy sibling runs`,async t=>{
  const f=await start(t,`define('subject','gcfv2',{${options}});`);
  assert.equal(f.spec('subject'),undefined);assert.equal(f.ignored('subject')?.scope,'unsupported');
  assert.equal((await f.invoke('subject')).ok,false);assert.equal((await f.invoke('healthy')).ok,true);
 });
}

test('Expression is evaluated with its receiver; existing numeric settings share single-read policy',async t=>{
 const f=await start(t,`define('subject','gcfv2',{availableMemoryMb:param('memory',256),minInstances:param('min',0),maxInstances:param('max',2),concurrency:param('concurrency',4)});`);
 const s=f.spec('subject');assert.ok(s);assert.equal(s.concurrency,4);
 assert.deepEqual(s.platformOptions,{availableMemoryMb:256,minInstances:0,maxInstances:2});
 assert.equal((await f.invoke('subject')).ok,true);
 assert.deepEqual((await f.called()).seen,{reads:{memory:1,min:1,max:1,concurrency:1},evaluations:{memory:1,min:1,max:1,concurrency:1},json:{}});
});
test('region array expressions resolve but do not add multi-region expansion',async t=>{
 const f=await start(t,`define('subject','gcfv2',{region:[param('r1','asia-northeast1'),param('r2','us-central1')]});`);
 assert.equal(f.spec('subject').region,'asia-northeast1');assert.equal(f.hello.manifest.functions.filter(f=>f.name==='subject').length,1);
 assert.equal((await f.invoke('subject')).ok,true);assert.deepEqual((await f.called()).seen.evaluations,{r1:1,r2:1});
});
test('throwing or asynchronous expressions are not guessed as default values',async t=>{
 const f=await start(t,`define('throws','gcfv2',{omit:{value(){throw Error('synthetic failure');}}});define('asyncValue','gcfv2',{timeoutSeconds:{value(){return Promise.resolve(3);}}});`);
 for(const name of ['throws','asyncValue']) { assert.equal(f.spec(name),undefined);assert.equal(f.ignored(name)?.scope,'unsupported'); }
 assert.equal((await f.invoke('healthy')).ok,true);
});
test('a rejecting asynchronous option does not terminate healthy sibling discovery',async t=>{
 const f=await start(t,`define('rejects','gcfv2',{timeoutSeconds:{value(){return Promise.reject(Error('synthetic rejection'));}}});`);
 assert.equal(f.spec('rejects'),undefined);
 assert.equal(f.ignored('rejects')?.scope,'unsupported');
 await new Promise(resolve=>setTimeout(resolve,50));
 assert.equal((await f.invoke('healthy')).ok,true);
});
test('a directly supplied rejected Promise does not terminate healthy siblings',async t=>{
 const f=await start(t,`define('rejects','gcfv2',{timeoutSeconds:Promise.reject(Error('direct rejection'))});`);
 assert.equal(f.spec('rejects'),undefined);
 assert.equal(f.ignored('rejects')?.scope,'unsupported');
 await new Promise(resolve=>setTimeout(resolve,50));
 assert.equal((await f.invoke('healthy')).ok,true);
});
test('a rejected Promise thrown by metadata evaluation does not terminate siblings',async t=>{
 const f=await start(t,`define('rejects','gcfv2',{timeoutSeconds:{value(){throw Promise.reject(Error('thrown rejection'));}}});`);
 assert.equal(f.spec('rejects'),undefined);
 assert.equal(f.ignored('rejects')?.scope,'unsupported');
 await new Promise(resolve=>setTimeout(resolve,50));
 assert.equal((await f.invoke('healthy')).ok,true);
});
test('zero literal timeout still means unspecified; reset numeric settings are omitted',async t=>{
 const f=await start(t,`define('subject','gcfv2',{timeoutSeconds:0,availableMemoryMb:reset,minInstances:null,maxInstances:reset,concurrency:reset});`);
 const s=f.spec('subject');assert.ok(s);assert.equal(s.timeoutSeconds,undefined);assert.equal(s.platformOptions,undefined);assert.equal(s.concurrency,undefined);
});


test('nested expression result is rejected without executing another evaluator',async t=>{
 const f=await start(t,`define('subject','gcfv2',{region:param('outer',param('inner','us-central1'))});`);
 assert.equal(f.spec('subject'),undefined);assert.equal(f.ignored('subject')?.scope,'unsupported');
 assert.equal((await f.invoke('healthy')).ok,true);
 const seen=(await f.called()).seen;assert.deepEqual(seen.evaluations,{outer:1});assert.deepEqual(seen.json,{});
});
test('SDK-style inherited value()/runtimeValue() methods resolve without toJSON',async t=>{
 const f=await start(t,`
 class RuntimeExpression { constructor(value){this.v=value;} value(){return this.runtimeValue();}
   runtimeValue(){return this.v;} toJSON(){throw Error('must not serialize deployment expressions');} }
 define('subject','gcfv2',{omit:new RuntimeExpression(false),region:new RuntimeExpression('europe-west1'),
   timeoutSeconds:new RuntimeExpression(37),eventTrigger:{retry:new RuntimeExpression(false)}});
 `);
 const s=f.spec('subject');assert.ok(s);assert.equal(s.retry,false);assert.equal(s.region,'europe-west1');assert.equal(s.timeoutSeconds,37);
 assert.equal((await f.invoke('subject')).ok,true);
});
for (const platform of ['gcfv1','gcfv2']) {
 test(`${platform}: resolved HTTP region is actually routable, not only JSON serializable`,{timeout:10000},async t=>{
  const f=await start(t,`
  const fn=async(req,res)=>res.json({target:process.env.FUNCTION_TARGET,signature:process.env.FUNCTION_SIGNATURE_TYPE});
  fn.__endpoint={platform:'${platform}',region:param('region','asia-northeast1'),omit:param('omit',false),
    timeoutSeconds:param('timeout',37),httpsTrigger:{}}; exports.web=fn;
  `,{http:true});
  const call = region => new Promise((resolve,reject)=>{
    const req=request({host:'127.0.0.1',port:f.hello.httpPort,path:'/demo-options/'+region+'/web',method:'GET',agent:false,
      headers:{'x-fireemu-runner-secret':'fixture-proxy'}},res=>{
      const chunks=[];res.on('data',b=>chunks.push(b));res.on('end',()=>resolve({status:res.statusCode,text:Buffer.concat(chunks).toString()}));res.on('error',reject);
    });
    req.on('error',reject);req.setTimeout(3000,()=>req.destroy(Error('test HTTP timeout')));req.end();
  });
  const result=await call('asia-northeast1');assert.equal(result.status,200);
  assert.deepEqual(JSON.parse(result.text),{target:'web',signature:'http'});
  assert.equal((await call('us-central1')).status,404);
 });
}
