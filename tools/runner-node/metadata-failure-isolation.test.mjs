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

// Error isolation applies even when the thrown value itself has hostile hooks.
for (const [name, thrown] of [
  ['revoked Proxy', `(()=>{const r=Proxy.revocable({},{});r.revoke();return r.proxy;})()`],
  ['throwing prototype', `new Proxy({}, {getPrototypeOf(){throw Error('prototype failure');}})`],
  ['throwing then', `{get then(){throw Error('then failure');},get message(){throw Error('message failure');}}`],
]) {
  test(`metadata throwing ${name} keeps a healthy sibling alive`,async t=>{
    const f=await start(t,`define('subject','gcfv2',{scheduleTrigger:{schedule:{value(){throw ${thrown};}}}});`);
    assert.equal(f.spec('subject'),undefined);
    assert.equal(f.ignored('subject')?.scope,'unsupported');
    assert.equal((await f.invoke('healthy')).ok,true);
  });
}

test('unsupported thenable reads then once and retains its receiver',async t=>{
  const f=await start(t,`
    const asyncValue={marker:42};
    Object.defineProperty(asyncValue,'then',{get(){seen.reads.then=(seen.reads.then||0)+1;
      return function(resolve,reject){seen.evaluations.receiver=this===asyncValue?1:0;reject(Error('unsupported asynchronous setting'));};}});
    define('subject','gcfv2',{scheduleTrigger:{schedule:asyncValue}});
  `);
  assert.equal(f.spec('subject'),undefined);
  await new Promise(resolve=>setTimeout(resolve,20));
  assert.equal((await f.invoke('healthy')).ok,true);
  const state=(await f.called()).seen;
  assert.equal(state.reads.then,1);
  assert.equal(state.evaluations.receiver,1);
});

for (const expression of [
 `Promise.reject(Error('direct rejection'))`,
 `{value(){return Promise.reject(Error('resolved rejection'));}}`,
 `{value(){throw Promise.reject(Error('thrown rejection'));}}`,
 `{value(){return require('node:vm').runInNewContext('Promise.reject(new Error("foreign rejection"))');}}`,
]) {
  test(`rejected asynchronous metadata remains isolated: ${expression}`,async t=>{
    const f=await start(t,`define('subject','gcfv2',{scheduleTrigger:{schedule:${expression}}});`);
    assert.equal(f.spec('subject'),undefined);
    await new Promise(resolve=>setTimeout(resolve,25));
    assert.equal((await f.invoke('healthy')).ok,true);
  });
}

for (const platform of ['gcfv1','gcfv2','legacy']) {
  test(`${platform} unresolved CEL timezone is not silently served`,async t=>{
    const schedule="{schedule:'every 5 minutes',timeZone:'{{ params.ZONE }}'}";
    const config=platform==='legacy'?`{eventTrigger:{eventType:'google.pubsub.topic.publish'},schedule:${schedule}}`:`{scheduleTrigger:${schedule}}`;
    const f=await start(t,`define('subject','${platform}',${config});`);
    assert.equal(f.spec('subject'),undefined);
    assert.equal((await f.invoke('healthy')).ok,true);
  });
}
