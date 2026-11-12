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
  app.use = fn => { if (fn.length !== 4) middleware.push(fn); }; app.all = (_path, fn) => { route = fn; }; return app;
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
const handler = async (req, res) => {
  const first = process.env.FUNCTIONS_EMULATOR;
  await Promise.resolve();
  const later = process.env.FUNCTIONS_EMULATOR;
  const timer = await new Promise(resolve => setTimeout(() => resolve(process.env.FUNCTIONS_EMULATOR), 1));
  res.json({first: first ?? null, later, timer, marker: 'x-fireemu-task-identity' in req.headers});
};
const task = (req, res) => handler(req, res);
task.__endpoint = {platform:'gcfv1', taskQueueTrigger:{}};
const http = (req, res) => handler(req, res);
http.__endpoint = {platform:'gcfv1', httpsTrigger:{}};
module.exports = {task, http};
`;

async function start(t, {profile}={}) {
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
    ...(profile ? {FIREEMU_HTTP_PROFILE:profile} : {})},stdio:['pipe','pipe','pipe']});
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
  const httpCall=(name,body,{key=secret,region='us-central1',namespace=project,headers={}}={})=>new Promise((resolve,reject)=>{
    const data=JSON.stringify(body);const req=request({host:'127.0.0.1',port:hello.httpPort,path:`/${namespace}/${region}/${name}`,method:'POST',agent:false,
      headers:{'x-fireemu-runner-secret':key,'Content-Type':'application/json','Content-Length':Buffer.byteLength(data),...headers}},res=>{
      const chunks=[];res.on('data',b=>chunks.push(b));res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode,text:Buffer.concat(chunks).toString()}));});
    req.on('error',reject);req.setTimeout(3000,()=>req.destroy(Error('fixture HTTP deadline')));req.end(data);clients.push(req);
  });
  return {hello,child,frames,calls,invoke,httpCall,mutate:async(name,mode,platform)=>{const r=await invoke('mutate','schedule',{data:{name,mode,platform}});assert.equal(r.ok,true);}};
}


test('strict dispatch hides only the first read for each marked task', {timeout:10000}, async t => {
  const f = await start(t, {profile:'strict'});
  for (let i = 0; i < 2; i++) {
    const response = await f.httpCall('task', {}, {headers:{'x-fireemu-task-identity':'1'}});
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.text), {first:null, later:'true', timer:'true', marker:false});
  }
  for (const headers of [{authorization:'Bearer a.b.c'}, {'x-fireemu-task-identity':'yes'}]) {
    const response = await f.httpCall('task', {}, {headers});
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.text), {first:'true', later:'true', timer:'true', marker:false});
  }
  const response = await f.httpCall('http', {}, {headers:{'x-fireemu-task-identity':'1'}});
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.text), {first:'true', later:'true', timer:'true', marker:false});
});

test('emulator profile removes the marker without hiding the flag', {timeout:10000}, async t => {
  const f = await start(t, {profile:'emulator'});
  const response = await f.httpCall('task', {}, {headers:{'x-fireemu-task-identity':'1'}});
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.text), {first:'true', later:'true', timer:'true', marker:false});
});
