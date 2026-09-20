// Real runner and Node HTTP sockets, with a deliberately small Express/HttpsError
// adapter. This is not Firebase/Express integration evidence.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

const runner=process.env.FIREEMU_TEST_RUNNER || fileURLToPath(new URL('./index.mjs',import.meta.url));
const project='demo-http-lifecycle',secret='test-runner-secret';
const expressSource=`
const fs=require('node:fs');const path=require('node:path');
const record=value=>fs.appendFileSync(path.join(__dirname,'../../events.jsonl'),JSON.stringify(value)+'\\n');
module.exports=function(){let handler;const app=(req,res)=>{
 const chunks=[];req.on('error',()=>{});
 req.on('data',c=>chunks.push(c));req.on('end',()=>{
  req.body=JSON.parse(Buffer.concat(chunks).toString()||'{}');
  const p=req.url.split('?')[0].split('/');req.params={project:p[1],region:p[2],name:p[3]};
  req.get=n=>req.headers[n.toLowerCase()];
  res.status=c=>{res.statusCode=c;return res;};
  res.send=b=>{res.end(String(b));return res;};
  res.json=b=>{res.setHeader('content-type','application/json');res.end(JSON.stringify(b));return res;};
  const tag=req.body.tag||req.body.data?.user?.tag||'';
  record({event:'routed',tag});res.on('close',()=>record({event:'closed',tag}));
  handler(req,res,()=>{record({event:'next',tag});if(!res.writableEnded&&!res.destroyed){res.statusCode=500;res.end('next called');}});
 });};app.use=()=>{};app.all=(_route,fn)=>handler=fn;return app;};
for(const k of ['json','text','raw','urlencoded'])module.exports[k]=()=>()=>{};
`;
const code=`
const fs=require('node:fs');
const record=v=>fs.appendFileSync(__dirname+'/events.jsonl',JSON.stringify(v)+'\\n');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const gate=tag=>new Promise(resolve=>{const timer=setInterval(()=>{
 if(fs.existsSync(__dirname+'/release-'+tag)){clearInterval(timer);resolve();}
},5);});
async function http(req,res){
 const {tag='',mode='normal'}=req.body;
 record({event:'started',tag,secret:process.env.ALPHA_SECRET||null,requestComplete:req.complete});
 if(mode==='destroy'){res.destroy();await sleep(30);record({event:'returned',tag});return;}
 if(mode==='wait-close'){await new Promise(r=>res.once('close',r));await sleep(30);record({event:'returned',tag});return;}
 if(mode==='hold'||mode==='hold-reject'){await gate(tag);record({event:'released',tag,secret:process.env.ALPHA_SECRET||null});}
 if(mode==='hold-reject')throw new Error('fixture failure');
 if(mode==='end-hold'){res.end('early-end');await gate(tag);record({event:'returned',tag,secret:process.env.ALPHA_SECRET||null});return;}
 if(mode==='async-response'){setTimeout(()=>res.end('late-response'),60);return;}
 if(mode==='partial-throw'){res.writeHead(200);res.write('prefix');await sleep(20);throw new Error('partial failure');}
 if(mode==='throw')throw new Error('expected failure');
 res.json({tag,secret:process.env.ALPHA_SECRET||null,requestComplete:req.complete,requestDestroyed:req.destroyed});
}
http.__endpoint={platform:'gcfv2',httpsTrigger:{},secretEnvironmentVariables:[{key:'ALPHA_SECRET'}]};
async function task(req,res){return http(req,res)};task.__endpoint={platform:'gcfv2',taskQueueTrigger:{},secretEnvironmentVariables:[{key:'ALPHA_SECRET'}]};
function blocking(){};blocking.__endpoint={platform:'gcfv2',blockingTrigger:{eventType:'beforeSignIn'},secretEnvironmentVariables:[{key:'ALPHA_SECRET'}]};
blocking.run=async event=>{
 const {tag='',mode='normal'}=event.data;
 record({event:'started',tag,secret:process.env.ALPHA_SECRET||null});
 if(mode==='hold'||mode==='hold-serialize')await gate(tag);
 if(mode==='serialize'||mode==='hold-serialize')return {customClaims:{toJSON(){record({event:'serialize',tag});return {secret:process.env.ALPHA_SECRET||null};}}};
 return {displayName:tag};
};
const probe=async data=>{record({event:'probe',tag:data.tag,secret:process.env.ALPHA_SECRET||null});};
probe.run=probe;probe.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 1 minutes'}};
module.exports={http,task,blocking,probe};
`;
async function start(t,{serialize=true}={}){
 const dir=await mkdtemp(join(tmpdir(),'fireemu-http-lifecycle-'));
 async function put(p,b){await mkdir(dirname(join(dir,p)),{recursive:true});await writeFile(join(dir,p),b);}
 await put('package.json',JSON.stringify({main:'index.cjs'}));await put('index.cjs',code);
 await put('node_modules/express/package.json',JSON.stringify({name:'express',version:'5.0.0',main:'index.cjs'}));
 await put('node_modules/express/index.cjs',expressSource);
 await put('node_modules/firebase-functions/package.json',JSON.stringify({name:'firebase-functions',version:'7.3.2',main:'index.cjs',exports:{'.':'./index.cjs','./https':'./https.cjs','./v2/options':'./options.cjs'}}));
 await put('node_modules/firebase-functions/index.cjs','module.exports={};');
 await put('node_modules/firebase-functions/options.cjs','exports.getGlobalOptions=()=>({});');
 await put('node_modules/firebase-functions/https.cjs',`exports.HttpsError=class extends Error{constructor(code,message){super(message);this.code=code;this.httpErrorCode={canonicalName:'INVALID_ARGUMENT',status:400};}};`);
 const child=spawn(process.execPath,[runner,'--source',dir],{stdio:['pipe','pipe','pipe'],env:{PATH:process.env.PATH,GCLOUD_PROJECT:project,FIREEMU_RUNNER_SECRET:secret,...(serialize?{FIREEMU_LOCAL_SECRETS_JSON:'{"ALPHA_SECRET":"only-alpha"}'}:{})}});
 const messages=[];let buffer=Buffer.alloc(0),stderr='',exit=null;
 const exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>{exit={code,signal};resolve(exit);});});
 child.stdin.on('error',()=>{});child.stderr.on('data',b=>{if(stderr.length<65536)stderr+=b.toString();});
 child.stdout.on('data',b=>{buffer=Buffer.concat([buffer,b]);for(;;){const n=buffer.indexOf(10);if(n<0)return;const len=Number(buffer.subarray(0,n));if(buffer.length<n+1+len)return;messages.push(JSON.parse(buffer.subarray(n+1,n+1+len).toString()));buffer=buffer.subarray(n+1+len);}});
 async function wait(f,label,timeout=2500){const end=performance.now()+timeout;while(performance.now()<end){if(await f())return;if(exit)throw Error('runner exited: '+JSON.stringify(exit)+' '+stderr);await delay(5);}throw Error('deadline: '+label);}
 async function events(){try{return (await readFile(join(dir,'events.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}catch(e){if(e.code==='ENOENT')return [];throw e;}}
 const clients=[];
 t.after(async()=>{for(const c of clients)c.destroy();if(!exit){child.kill('SIGKILL');await exited;}child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();await rm(dir,{recursive:true,force:true});});
 await wait(()=>messages.some(m=>m.type==='hello'),'hello');const port=messages.find(m=>m.type==='hello').httpPort;assert.ok(Number.isInteger(port));
 function call(name,body,{key=secret}={}){
  let settled=false;let finalize;const result=new Promise(r=>finalize=r);
  const done=v=>{if(!settled){settled=true;finalize(v);}};
  const req=request({host:'127.0.0.1',port,path:'/'+project+'/us-central1/'+name,method:'POST',agent:false,headers:{'content-type':'application/json','x-fireemu-runner-secret':key}},res=>{let text='';res.on('data',b=>text+=b);res.on('end',()=>done({status:res.statusCode,text,complete:res.complete}));res.on('error',e=>done({error:e.code,text,complete:false}));res.on('close',()=>{if(!res.complete)done({error:'closed',text,complete:false});});});
  req.on('error',e=>done({error:e.code,complete:false}));req.setTimeout(2000,()=>req.destroy(Error('fixture request timeout')));req.end(JSON.stringify(body));clients.push(req);return {req,result};
 }
 function probe(tag){const b=Buffer.from(JSON.stringify({type:'invoke',invocationId:tag,function:'probe',trigger:'schedule',event:{data:{tag}}}));child.stdin.write(Buffer.concat([Buffer.from(b.length+'\n'),b]));}
 async function seen(event,tag){return (await events()).some(e=>e.event===event&&e.tag===tag);}
 return {dir,child,messages,events,wait,call,probe,seen,release:tag=>writeFile(join(dir,'release-'+tag),'1'),get stderr(){return stderr;}};
}

for(const mode of ['destroy','wait-close'])test(`closed response before callback settles cannot strand the environment queue: ${mode}`,{timeout:8000},async t=>{
 const f=await start(t);const c=f.call('http',{tag:'first',mode});
 await f.wait(()=>f.seen('started','first'),'first start');if(mode==='wait-close')c.req.destroy();await c.result;
 await f.wait(()=>f.seen('returned','first'),'callback returned');f.probe('after-close');
 await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='after-close'),'next invocation');
 assert.equal(f.messages.find(m=>m.invocationId==='after-close'&&m.type==='result').ok,true);
 assert.equal((await f.events()).find(e=>e.event==='probe').secret,null);
});
for(const name of ['http','task','blocking'])test(`queued disconnected ${name} request is not invoked after earlier request releases`,{timeout:8000},async t=>{
 const f=await start(t),first=f.call('http',{tag:'held',mode:'hold'});
 await f.wait(()=>f.seen('started','held'),'held start');
 const next=f.call(name,name==='blocking'?{data:{user:{tag:'cancelled'},context:{}}}:{tag:'cancelled'});
 await f.wait(()=>f.seen('routed','cancelled'),'queued routing');next.req.destroy();await next.result;
 await f.wait(()=>f.seen('closed','cancelled'),'peer close observed');await f.release('held');assert.equal((await first.result).status,200);
 f.probe('barrier');await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='barrier'),'barrier');
 assert.equal(await f.seen('started','cancelled'),false,'closed queued callback executed');
});
for(const mode of ['hold','end-hold'])test(`response termination does not release secrets until running callback settles: ${mode}`,{timeout:8000},async t=>{
 const f=await start(t),first=f.call('http',{tag:'active',mode});await f.wait(()=>f.seen('started','active'),'active');
 if(mode==='hold'){first.req.destroy();await first.result;await f.wait(()=>f.seen('closed','active'),'closed');}
 else assert.equal((await first.result).text,'early-end');
 f.probe('queued');await delay(80);assert.equal(await f.seen('probe','queued'),false);
 await f.release('active');await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='queued'),'release');
 const e=(await f.events()).find(e=>e.tag==='active'&&['released','returned'].includes(e.event));assert.equal(e.secret,'only-alpha');
});
test('callback returns before end: environment queue waits for actual response finish',{timeout:8000},async t=>{
 const f=await start(t),c=f.call('http',{tag:'late',mode:'async-response'});await f.wait(()=>f.seen('started','late'),'started');
 f.probe('after-late');assert.equal((await c.result).text,'late-response');
 await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='after-late'),'probe');
 const events=await f.events();assert.ok(events.findIndex(e=>e.event==='closed'&&e.tag==='late')<events.findIndex(e=>e.event==='probe'));
});
test('Blocking result is serialized in its function environment, not after secret restoration',{timeout:8000},async t=>{
 const f=await start(t),reply=await f.call('blocking',{data:{user:{tag:'serialization',mode:'serialize'},context:{}}}).result;
 assert.equal(reply.status,200);assert.equal(JSON.parse(reply.text).userRecord.customClaims.secret,'only-alpha');
 f.probe('after-blocking');await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='after-blocking'),'probe');assert.equal((await f.events()).find(e=>e.event==='probe').secret,null);
});
test('request completion is not client abandonment; keep legitimate completed request data',{timeout:8000},async t=>{
 const f=await start(t),r=await f.call('http',{tag:'normal'}).result;
 assert.equal(r.status,200);assert.equal(JSON.parse(r.text).requestComplete,true);assert.equal(JSON.parse(r.text).secret,'only-alpha');
});
test('disconnected active rejection still frees queue after settlement',{timeout:8000},async t=>{
 const f=await start(t),c=f.call('http',{tag:'reject',mode:'hold-reject'});await f.wait(()=>f.seen('started','reject'),'started');
 c.req.destroy();await c.result;await f.wait(()=>f.seen('closed','reject'),'closed');await f.release('reject');
 f.probe('after-error');await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='after-error'),'probe');
 assert.equal(f.child.exitCode,null);
});
test('without local secrets distinct requests still run concurrently',{timeout:8000},async t=>{
 const f=await start(t,{serialize:false}),a=f.call('http',{tag:'a',mode:'hold'});await f.wait(()=>f.seen('started','a'),'a');
 const b=await f.call('http',{tag:'b'}).result;assert.equal(b.status,200);assert.equal(await f.seen('released','a'),false);
 await f.release('a');assert.equal((await a.result).status,200);
});
test('invalid proxy secret does not start a callback',{timeout:8000},async t=>{
 const f=await start(t);assert.equal((await f.call('http',{tag:'forbidden'},{key:'wrong'}).result).status,403);assert.equal(await f.seen('started','forbidden'),false);
});

test('disconnected Blocking callback may settle but its result getter is not executed', {timeout:8000},async t=>{
 const f=await start(t),c=f.call('blocking',{data:{user:{tag:'gone',mode:'hold-serialize'},context:{}}});
 await f.wait(()=>f.seen('started','gone'),'started');c.req.destroy();await c.result;
 await f.wait(()=>f.seen('closed','gone'),'closed');await f.release('gone');f.probe('after-gone');
 await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='after-gone'),'probe');
 assert.equal(await f.seen('serialize','gone'),false);
});
test('ordinary pre-header error is handled once, without fall-through', {timeout:8000},async t=>{
 const f=await start(t),r=await f.call('http',{tag:'failed',mode:'throw'}).result;
 assert.equal(r.status,500);assert.equal(r.text,'internal error');
 assert.equal(await f.seen('next','failed'),false);
 assert.equal((await f.call('http',{tag:'after-failed'}).result).status,200);
});
test('failure after response headers destroys the stream instead of appending another response', {timeout:8000},async t=>{
 const f=await start(t),r=await f.call('http',{tag:'partial',mode:'partial-throw'}).result;
 assert.equal(r.complete,false);assert.equal(r.text,'prefix');assert.equal(await f.seen('next','partial'),false);
 assert.equal((await f.call('http',{tag:'after-partial'}).result).status,200);
});
