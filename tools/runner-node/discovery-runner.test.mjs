// The real runner and real framed stdin/stdout; no Firebase package is needed.
import assert from 'node:assert/strict';
import test from 'node:test';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {join,dirname,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';

const runner=resolve(dirname(fileURLToPath(import.meta.url)),'index.mjs');
const setup=`
const fs = require('node:fs');
const path = require('node:path');
function make(label) {
  const f=async()=>fs.appendFileSync(path.join(__dirname,'calls.jsonl'),JSON.stringify(label)+'\\n');
  f.run=f; f.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'}}; return f;
}
const healthy=make('healthy');
`;
const encode = value => {const bytes=Buffer.from(JSON.stringify(value));return Buffer.concat([Buffer.from(bytes.length+'\n'),bytes]);};

async function start(t,source,{esm=false,fatal=false}={}) {
  const dir=await mkdtemp(join(tmpdir(),'fireemu-discovery-'));
  const file=esm?'index.mjs':'index.cjs';
  await writeFile(join(dir,'package.json'),JSON.stringify({private:true,main:file}));
  await writeFile(join(dir,file),source);
  const child=spawn(process.execPath,[runner,'--source',dir],{
    env:{PATH:process.env.PATH,GCLOUD_PROJECT:'demo-discovery'},stdio:['pipe','pipe','pipe'],
  });
  let finished=null,error=null,buffer=Buffer.alloc(0),stderr=''; const frames=[];
  child.stdin.on('error',()=>{});
  const exit=once(child,'exit').then(([code,signal]) => (finished={code,signal}));
  child.stderr.on('data',chunk=>{if(stderr.length<65536)stderr+=chunk.toString();});
  child.stdout.on('data',chunk=>{
    buffer=Buffer.concat([buffer,chunk]);
    for(;;){
      const at=buffer.indexOf(10);if(at<0)return;
      const n=Number(buffer.subarray(0,at).toString());
      if(!Number.isSafeInteger(n)||n<1||n>16*1024*1024){error='bad output frame';return;}
      if(buffer.length<at+1+n)return;
      try{frames.push(JSON.parse(buffer.subarray(at+1,at+1+n).toString('utf8')));}
      catch{error='bad output JSON';return;}
      buffer=buffer.subarray(at+1+n);
    }
  });
  async function wait(predicate,label) {
    const deadline=Date.now()+5000;
    while(Date.now()<deadline){
      if(error)throw Error(error);
      const v=predicate();if(v)return v;
      if(finished)throw Error(`${label}: child exited ${JSON.stringify(finished)}; ${stderr.slice(-500)}`);
      await new Promise(r=>setTimeout(r,5));
    }
    throw Error(`${label}: timeout`);
  }
  async function exited(){
    if(finished)return finished;
    let timer;try{return await Promise.race([exit,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('exit timeout')),5000);})]);}
    finally{clearTimeout(timer);}
  }
  t.after(async()=>{
    if(!finished){child.kill('SIGKILL');await exited();}
    child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();await rm(dir,{recursive:true,force:true});
  });
  const hello=fatal?null:await wait(()=>frames.find(f=>f.type==='hello'),'hello');
  let id=0;
  return {child,frames,hello,exited,get stderr(){return stderr;},
    async call(name){const invocationId='call-'+(++id);child.stdin.write(encode({type:'invoke',invocationId,function:name,entryPoint:name,trigger:'schedule',event:{data:{}}}));return wait(()=>frames.find(f=>f.type==='result'&&f.invocationId===invocationId),'result');},
    async calls(){try{return (await readFile(join(dir,'calls.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}catch(e){if(e.code==='ENOENT')return [];throw e;}},
  };
}

for(const shape of ['self','mutual','root']){
  test(`real discovery: ${shape} cycle keeps healthy callbacks callable`,{timeout:10000},async t=>{
    const source=shape==='self'?`const group={leaf:make('leaf')};group.self=group;module.exports={healthy,group};`
      :shape==='mutual'?`const a={leaf:make('leaf')},b={back:a};a.next=b;module.exports={healthy,group:a};`
      :`module.exports={healthy};module.exports.self=module.exports;`;
    const f=await start(t,setup+source);
    const expected=shape==='root'?['healthy']:['healthy','group-leaf'];
    assert.deepEqual(f.hello.manifest.functions.map(x=>x.name),expected);
    assert.equal(f.hello.manifest.ignored.length,1);assert.match(f.hello.manifest.ignored[0].reason,/cyclic/);
    assert.equal((await f.call('healthy')).ok,true);
    if(shape!=='root')assert.equal((await f.call('group-leaf')).ok,true);
    assert.deepEqual(await f.calls(),shape==='root'?['healthy']:['healthy','leaf']);
  });
}

for(const place of ['root','nested','metadata','description','proxy-group']){
  test(`real discovery: ${place} getter/proxy failure does not terminate the runner`,{timeout:10000},async t=>{
    const thrown=`const thrown=Object.defineProperties({}, {message:{get(){throw null;}},stack:{get(){throw null;}},toString:{value(){throw null;}}});`;
    let source;
    if(place==='root') source=`module.exports={healthy};Object.defineProperty(module.exports,'broken',{enumerable:true,get(){throw thrown;}});`;
    if(place==='nested') source=`const group={ok:make('ok')};Object.defineProperty(group,'broken',{enumerable:true,get(){throw thrown;}});module.exports={healthy,group};`;
    if(place==='metadata') source=`const broken=()=>{};Object.defineProperty(broken,'__endpoint',{get(){throw thrown;}});module.exports={healthy,broken};`;
    if(place==='description') source=`const broken=()=>{};broken.__endpoint={platform:'gcfv2',scheduleTrigger:{}};Object.defineProperty(broken.__endpoint,'availableMemoryMb',{get(){throw thrown;}});module.exports={healthy,broken};`;
    if(place==='proxy-group') source=`const p=Proxy.revocable({},{});p.revoke();module.exports={healthy,broken:p.proxy};`;
    const f=await start(t,setup+thrown+source);
    assert.ok(f.hello.manifest.functions.some(x=>x.name==='healthy'));
    assert.equal(f.hello.manifest.ignored.length,1);
    assert.equal((await f.call(f.hello.manifest.ignored[0].name)).ok,false);
    assert.equal((await f.call('healthy')).ok,true);assert.deepEqual(await f.calls(),['healthy']);
  });
}

for(const reversed of [false,true]){
  test(`real discovery: flattened collision is ignored in either order (${reversed})`,{timeout:10000},async t=>{
    const a=`api:{user:make('nested')}`,b=`'api-user':make('flat')`;
    const f=await start(t,setup+`module.exports={${reversed?b+','+a:a+','+b},healthy};`);
    assert.deepEqual(f.hello.manifest.functions.map(x=>x.name),['healthy']);
    assert.equal(f.hello.manifest.ignored.length,1);assert.equal(f.hello.manifest.ignored[0].name,'api-user');
    assert.match(f.hello.manifest.ignored[0].reason,/ambiguous/);
    assert.equal((await f.call('api-user')).ok,false);assert.deepEqual(await f.calls(),[]);
    assert.equal((await f.call('healthy')).ok,true);assert.deepEqual(await f.calls(),['healthy']);
  });
}

test('real discovery: shared acyclic groups are registered and callable at both aliases',{timeout:10000},async t=>{
  const f=await start(t,setup+`const shared={task:make('task')};module.exports={left:shared,right:shared};`);
  assert.deepEqual(f.hello.manifest.functions.map(x=>x.name),['left-task','right-task']);
  assert.deepEqual(f.hello.manifest.ignored,[]);
  assert.equal((await f.call('left-task')).ok,true);assert.equal((await f.call('right-task')).ok,true);
  assert.deepEqual(await f.calls(),['task','task']);
});

test('real discovery: own CommonJS prototype-shaped names survive merging and dispatch',{timeout:10000},async t=>{
  const f=await start(t,setup+`module.exports={['__proto__']:make('proto'),constructor:make('constructor'),toString:make('string'),healthy};`);
  assert.deepEqual(f.hello.manifest.functions.map(x=>x.name),['__proto__','constructor','toString','healthy']);
  for(const name of ['__proto__','constructor','toString'])assert.equal((await f.call(name)).ok,true);
  assert.deepEqual(await f.calls(),['proto','constructor','string']);
});

test('real discovery: named ES prototype-shaped exports are not treated as inherited properties',{timeout:10000},async t=>{
  const f=await start(t,`const fn=async()=>{};fn.run=fn;fn.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'}};export {fn as __proto__,fn as constructor,fn as toString};`,{esm:true});
  assert.deepEqual(f.hello.manifest.functions.map(x=>x.name),['__proto__','constructor','toString']);
  for(const name of ['__proto__','constructor','toString'])assert.equal((await f.call(name)).ok,true);
});

test('real discovery: CommonJS insertion order and non-enumerable/inherited omissions remain stable',{timeout:10000},async t=>{
  const f=await start(t,setup+`const group=Object.create({inherited:healthy});group.z=make('z');group.a=make('a');Object.defineProperty(group,'hidden',{value:healthy});module.exports=group;`);
  assert.deepEqual(f.hello.manifest.functions.map(x=>x.name),['z','a']);assert.deepEqual(f.hello.manifest.ignored,[]);
});

for(const [reason,source] of [
  ['depth',`let group={leaf:healthy};for(let i=0;i<200;i++)group={g:group};module.exports={healthy,group};`],
  ['entry',`let group={leaf:healthy};for(let i=0;i<15;i++)group={left:group,right:group};module.exports={healthy,group};`],
  ['name',`module.exports={healthy,['x'.repeat(1025)]:healthy};`],
]){
  test(`real discovery: ${reason} overflow fails before publishing any partial manifest`,{timeout:10000},async t=>{
    const f=await start(t,setup+source,{fatal:true});
    // EOF also lets the old runner terminate normally during counterexample runs.
    f.child.stdin.end();
    assert.equal((await f.exited()).code,1);
    assert.equal(f.frames.some(x=>x.type==='hello'),false);
    assert.match(f.stderr,new RegExp(reason+' limit'));assert.doesNotMatch(f.stderr,/RangeError|UnhandledPromiseRejection/);
  });
}
