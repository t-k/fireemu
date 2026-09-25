// Real runner, Node HTTP and sockets. A small instrumented body-parser/Express
// double exercises ordering and verify hooks; this is NOT installed Express/SDK.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {request} from 'node:http';
import {connect} from 'node:net';
import {gzipSync} from 'node:zlib';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import test from 'node:test';

const runner=process.env.FIREEMU_TEST_RUNNER || fileURLToPath(new URL('./index.mjs',import.meta.url));
const project='demo-http-admission',secret='local-proxy-secret';
const expressSource=`
const fs=require('node:fs'),path=require('node:path'),zlib=require('node:zlib');
const record=e=>fs.appendFileSync(path.join(__dirname,'../../events.jsonl'),JSON.stringify(e)+'\\n');
module.exports=function(){const middle=[];let route;const app=(req,res)=>{
 res.status=c=>{res.statusCode=c;return res;};res.send=x=>{res.end(String(x));return res;};res.json=x=>{res.setHeader('content-type','application/json');res.end(JSON.stringify(x));return res;};
 req.get=n=>req.headers[n.toLowerCase()];const p=req.url.split('?')[0].split('/');req.params={project:p[1],region:p[2],name:p[3]};
 let index=0;const next=err=>{if(res.destroyed||res.writableEnded)return;if(err){res.status(err.status||400).send('parser failed');return;}
  if(index<middle.length){const fn=middle[index++];try{fn(req,res,next);}catch(e){next(e);}return;}
  record({event:'route',name:req.params.name});route(req,res);
 };next();};app.use=fn=>middle.push(fn);app.all=(_r,fn)=>route=fn;return app;};
for(const kind of ['json','text','urlencoded','raw'])module.exports[kind]=opts=>(req,res,next)=>{
 if(req.parsed)return next();const ct=req.headers['content-type']||'';
 if(kind==='json'&&!ct.includes('application/json'))return next();if(kind==='text'&&!ct.includes('text/'))return next();
 if(kind==='urlencoded'&&!ct.includes('application/x-www-form-urlencoded'))return next();
 record({event:'parser',kind,secret:req.headers['x-fireemu-runner-secret']||null});const chunks=[];let size=0;
 req.on('error',()=>{});req.on('data',c=>{size+=c.length;chunks.push(c);});req.on('end',()=>{
  if(res.destroyed||res.writableEnded)return;
  try{let b=Buffer.concat(chunks);if(req.headers['content-encoding']==='gzip')b=zlib.gunzipSync(b);
   if(b.length>32*1024*1024)throw Object.assign(Error('too big'),{status:413});
   opts.verify(req,res,b);req.body=kind==='json'?JSON.parse(b.toString()||'{}'):kind==='text'?b.toString():kind==='urlencoded'?Object.fromEntries(new URLSearchParams(b.toString())):b;
   req.parsed=true;next();
  }catch(e){next(e);}
 });};
`;
const code=`
const fs=require('node:fs');const record=e=>fs.appendFileSync(__dirname+'/events.jsonl',JSON.stringify(e)+'\\n');
const pending=new Map();let timer;
function wait(tag){if(!timer)timer=setInterval(()=>{let tags=[];try{tags=JSON.parse(fs.readFileSync(__dirname+'/release.json','utf8'));}catch{}for(const [k,v] of pending)if(tags.includes('*')||tags.includes(k)){pending.delete(k);v();}if(!pending.size){clearInterval(timer);timer=undefined;}},10);
 return new Promise(r=>pending.set(tag,r));}
async function callback(req,res){const mode=req.headers['x-mode']||'normal',tag=req.headers['x-tag']||'tag';record({event:'start',tag,name:process.env.FUNCTION_TARGET});
 if(mode==='end-hold'){res.end('early');await wait(tag);record({event:'settled',tag});return;}
 if(mode==='hold')await wait(tag);
 if(mode==='throw')throw Error('fixture');
 if(mode==='return-open'){setTimeout(()=>res.end('later'),120);return;}
 if(!res.destroyed&&!res.writableEnded)res.json({tag,body:req.body,rawBytes:req.rawBody?.length,secret:req.headers['x-fireemu-runner-secret']||null,rawHeaders:req.rawHeaders});record({event:'settled',tag});}
callback.__endpoint={platform:'gcfv2',httpsTrigger:{},secretEnvironmentVariables:[{key:'LOCAL_ONLY'}]};
const task=async(req,res)=>callback(req,res);task.__endpoint={platform:'gcfv2',taskQueueTrigger:{},secretEnvironmentVariables:[{key:'LOCAL_ONLY'}]};
function blocking(){}blocking.__endpoint={platform:'gcfv2',blockingTrigger:{eventType:'beforeSignIn'},secretEnvironmentVariables:[{key:'LOCAL_ONLY'}]};blocking.run=async e=>{record({event:'start',tag:e.data.tag,name:'blocking'});return {displayName:e.data.tag};};
module.exports={http:callback,task,blocking};
`;
async function start(t,{serialize=false,configured=true}={}) {
 const dir=await mkdtemp(join(tmpdir(),'fireemu-http-admission-'));
 async function put(p,s){const f=join(dir,p);await mkdir(dirname(f),{recursive:true});await writeFile(f,s);}
 await put('package.json',JSON.stringify({main:'index.cjs'}));await put('index.cjs',code);
 await put('node_modules/express/package.json',JSON.stringify({name:'express',version:'5.1.0',main:'index.cjs'}));await put('node_modules/express/index.cjs',expressSource);
 await put('node_modules/firebase-functions/package.json',JSON.stringify({name:'firebase-functions',version:'7.3.2',main:'index.cjs',exports:{'.':'./index.cjs','./https':'./https.cjs','./v2/options':'./options.cjs'}}));
 await put('node_modules/firebase-functions/index.cjs','module.exports={};');await put('node_modules/firebase-functions/options.cjs','exports.getGlobalOptions=()=>({});');await put('node_modules/firebase-functions/https.cjs','exports.HttpsError=class extends Error{};');
 const child=spawn(process.execPath,[runner,'--source',dir],{stdio:['pipe','pipe','pipe'],env:{PATH:process.env.PATH,GCLOUD_PROJECT:project,...(configured?{FIREEMU_RUNNER_SECRET:secret}:{}),...(serialize?{FIREEMU_LOCAL_SECRETS_JSON:'{"LOCAL_ONLY":"fixture"}'}:{})}});
 let buffer=Buffer.alloc(0),stderr='',exit=null;const messages=[],clients=[];
 const exited=new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>{exit={code,signal};resolve(exit);});});
 child.stdin.on('error',()=>{});child.stderr.on('data',b=>{if(stderr.length<65536)stderr+=b;});
 child.stdout.on('data',b=>{buffer=Buffer.concat([buffer,b]);for(;;){const n=buffer.indexOf(10);if(n<0)return;const len=Number(buffer.subarray(0,n));if(buffer.length<n+1+len)return;messages.push(JSON.parse(buffer.subarray(n+1,n+1+len).toString()));buffer=buffer.subarray(n+1+len);}});
 async function events(){try{return (await readFile(join(dir,'events.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}catch(e){if(e.code==='ENOENT')return [];throw e;}}
 async function wait(fn,label,timeout=6000){const end=performance.now()+timeout;while(performance.now()<end){if(await fn())return;if(exit)throw Error('runner exited '+JSON.stringify(exit)+' '+stderr);await delay(10);}throw Error('timeout: '+label);}
 t.after(async()=>{for(const c of clients)c.destroy();if(!exit){child.kill('SIGKILL');await exited;}child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();await rm(dir,{recursive:true,force:true});});
 await wait(()=>messages.some(x=>x.type==='hello'),'hello');const port=messages.find(x=>x.type==='hello').httpPort;assert.ok(Number.isInteger(port));
 function call({name='http',headers={},body='{}',send=true,method='POST',path}={}) {
  let resolveResult;const result=new Promise(r=>resolveResult=r);let continued=false;
  const req=request({host:'127.0.0.1',port,path:path||'/'+project+'/us-central1/'+name,method,agent:false,headers:{'x-fireemu-runner-secret':secret,'content-type':'application/json',...headers}},res=>{let text='';res.on('data',b=>{text+=b;});res.once('end',()=>resolveResult({status:res.statusCode,text,complete:res.complete}));res.on('error',e=>resolveResult({error:e.code,text}));});
  req.on('continue',()=>continued=true);req.on('error',e=>resolveResult({error:e.code}));clients.push(req);if(send)req.end(body);else req.flushHeaders();
  return {req,result,get continued(){return continued;}};
 }
 async function bounded(p){return Promise.race([p,delay(1500).then(()=>({timeout:true}))]);}
 return {dir,port,events,wait,call,bounded,clients,release:tags=>writeFile(join(dir,'release.json'),JSON.stringify(tags)),alive:()=>exit===null};
}
for(const expect of [false,true])test(`reject wrong secret before body read${expect?' and 100 Continue':''}`,{timeout:10000},async t=>{
 const f=await start(t),c=f.call({headers:{'x-fireemu-runner-secret':'wrong','content-length':'999',...(expect?{Expect:'100-continue'}:{})},send:false});
 const r=await f.bounded(c.result);assert.equal(r.status,403,'must refuse without waiting for body');assert.equal(c.continued,false);assert.deepEqual(await f.events(),[]);assert.equal(f.alive(),true);
});
test('missing runner capability configuration refuses without body parsing',{timeout:10000},async t=>{
 const f=await start(t,{configured:false}),c=f.call({headers:{'content-length':'20'},send:false});assert.equal((await f.bounded(c.result)).status,500);assert.deepEqual(await f.events(),[]);
});
test('authorized Expect:100-continue authenticates and admits before signalling body',{timeout:10000},async t=>{
 const f=await start(t),c=f.call({headers:{Expect:'100-continue','content-length':'2'},send:false});await f.wait(()=>c.continued,'continue');c.req.end('{}');assert.equal((await c.result).status,200);const e=await f.events();assert.equal(e[0].event,'parser');assert.equal(e[0].secret,null);
});
test('Content-Length > parser limit is rejected before 100 Continue or body read',{timeout:10000},async t=>{
 const f=await start(t),c=f.call({headers:{'content-length':String(32*1024*1024+1),Expect:'100-continue'},send:false});assert.equal((await f.bounded(c.result)).status,413);assert.equal(c.continued,false);assert.deepEqual(await f.events(),[]);
});
for(const kind of ['sized','chunked','compressed'])test(`reserve full parser capacity for ${kind} before body; abort frees parser slot`,{timeout:10000},async t=>{
 const f=await start(t),headers=kind==='sized'?{'content-length':String(32*1024*1024)}:kind==='chunked'?{'transfer-encoding':'chunked'}:{'content-length':'10','content-encoding':'gzip'};
 const a=f.call({headers,send:false}),b=f.call({headers,send:false});await f.wait(async()=> (await f.events()).filter(x=>x.event==='parser').length===2,'two parsing requests');
 const reject=f.call({headers:{'content-length':'1',Expect:'100-continue'},send:false});assert.equal((await f.bounded(reject.result)).status,503);assert.equal(reject.continued,false);
 a.req.destroy();await a.result;await delay(30);const next=await f.call().result;assert.equal(next.status,200);assert.equal(f.alive(),true);b.req.destroy();
});
test('decoded gzip body is preserved and unused reservation is returned',{timeout:10000},async t=>{
 const f=await start(t),value={message:'日本語🦀',data:'x'.repeat(65536)},body=Buffer.from(JSON.stringify(value)),gz=gzipSync(body);
 const first=f.call({headers:{'content-encoding':'gzip','content-length':String(gz.length),'x-mode':'hold','x-tag':'gzip'},body:gz});
 await f.wait(async()=> (await f.events()).some(x=>x.event==='start'&&x.tag==='gzip'),'first');
 // Full 32 MiB second reservation fits only if first shrank to decoded size.
 const second=f.call({headers:{'content-length':String(32*1024*1024)},send:false});
 await f.wait(async()=> (await f.events()).filter(x=>x.event==='parser').length===2,'second');
 assert.equal((await f.call().result).status,200);await f.release(['gzip']);const r=await first.result;assert.equal(r.status,200);const actual=JSON.parse(r.text);assert.deepEqual(actual.body,value);assert.equal(actual.rawBytes,body.length);second.req.destroy();
});
for(const [ctype,body] of [['application/json','{"x":"日本語"}'],['text/plain','こんにちは'],['application/x-www-form-urlencoded','a=hello&b=1'],['application/octet-stream',Buffer.from([0,1,2,255])]]) {
 test(`valid ${ctype} preserves raw body and conceals capability`,{timeout:10000},async t=>{const f=await start(t),r=await f.call({headers:{'content-type':ctype},body}).result;assert.equal(r.status,200);const b=JSON.parse(r.text);assert.equal(b.rawBytes,Buffer.byteLength(body));assert.equal(b.secret,null);assert.ok(!b.rawHeaders.some(x=>String(x).toLowerCase()==='x-fireemu-runner-secret'));});
}
test('parser error and route mismatch do not strand reservations',{timeout:10000},async t=>{
 const f=await start(t);for(let i=0;i<8;i++){assert.equal((await f.call({body:'{'}).result).status,400);assert.equal((await f.call({name:'missing'}).result).status,404);}assert.equal((await f.call().result).status,200);
});
test('response closed while callback is running must not return count capacity',{timeout:30000},async t=>{
 const f=await start(t),held=[];for(let begin=0;begin<1024;begin+=64){for(let i=begin;i<begin+64;i++)held.push(f.call({headers:{'x-mode':'hold','x-tag':'r'+i},body:'{}'}));await f.wait(async()=> (await f.events()).filter(x=>x.event==='start').length>=begin+64,'batch');}
 assert.equal((await f.call({headers:{'x-tag':'overflow'}}).result).status,503);
 held[0].req.destroy();await held[0].result;await delay(25);assert.equal((await f.call({headers:{'x-tag':'still-overflow'}}).result).status,503);
 await f.release(['r0']);await f.wait(async()=> (await f.events()).some(x=>x.event==='settled'&&x.tag==='r0'),'settled');await delay(25);
 assert.equal((await f.call({headers:{'x-tag':'admitted'}}).result).status,200);assert.equal((await f.events()).some(x=>x.event==='start'&&x.tag==='overflow'),false);
 await f.release(['*']);const results=await Promise.all(held.slice(1).map(x=>x.result));assert.ok(results.every(x=>x.status===200));assert.equal((await f.call().result).status,200);
});
test('finished early response retains body bytes until callback settles',{timeout:12000},async t=>{
 const f=await start(t),body='x'.repeat(32*1024*1024);for(const tag of ['a','b']){const r=await f.call({headers:{'content-type':'text/plain','x-mode':'end-hold','x-tag':tag},body}).result;assert.equal(r.status,200);assert.equal(r.text,'early');}
 assert.equal((await f.call().result).status,503);await f.release(['a']);await f.wait(async()=> (await f.events()).some(x=>x.event==='settled'&&x.tag==='a'),'release');await delay(25);assert.equal((await f.call().result).status,200);await f.release(['*']);
});
test('secret queue retains disconnected pending request capacity until its turn',{timeout:12000},async t=>{
 const f=await start(t,{serialize:true}),first=f.call({headers:{'x-mode':'hold','x-tag':'first'}});await f.wait(async()=> (await f.events()).some(x=>x.event==='start'),'first');
 const body='x'.repeat(32*1024*1024),second=f.call({headers:{'content-type':'text/plain','x-tag':'queued'},body});await f.wait(async()=> (await f.events()).filter(x=>x.event==='route').length===2,'queued');second.req.destroy();await second.result;
 // Retained queued 32MiB plus first 2 bytes leaves less than a full next body.
 const rejected=f.call({headers:{'content-length':String(32*1024*1024)},send:false});assert.equal((await f.bounded(rejected.result)).status,503);
 await f.release(['first']);assert.equal((await first.result).status,200);await delay(50);assert.equal((await f.call().result).status,200);assert.equal((await f.events()).some(x=>x.event==='start'&&x.tag==='queued'),false);
});
