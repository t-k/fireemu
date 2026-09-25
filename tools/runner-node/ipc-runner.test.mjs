// Actual Node entry point and stdin/stdout pipes. The Functions exports are plain
// fixture callbacks with SDK-shaped metadata; no Firebase SDK or Express is used.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./index.mjs', import.meta.url));
const encode = value => {
  const bytes = Buffer.from(JSON.stringify(value));
  return Buffer.concat([Buffer.from(`${bytes.length}\n`), bytes]);
};
function invocation(overrides = {}) {
  return { type:'invoke', invocationId:'test-1', function:'alpha', entryPoint:'alpha',
    trigger:'schedule', event:{ data:{ value:'日本語' } }, ...overrides };
}
const source = `
const {appendFileSync} = require('node:fs');
const record = value => appendFileSync(__dirname+'/calls.jsonl',JSON.stringify(value)+'\\n');
function schedule(name, secret) {
  const fn = async data => {
    record({name,value:data?.value,identity:process.env.FUNCTION_TARGET,
      secret:process.env.ALPHA_SECRET ?? null});
    switch(data?.mode) {
      case 'wait': await new Promise(r=>setTimeout(r,180)); break;
      case 'error': throw new Error('ordinary error');
      case 'throwing-stack': {
        const e = new Error('ordinary message');
        Object.defineProperty(e,'stack',{get(){throw new Error('diagnostic failed');}}); throw e;
      }
      case 'throwing-message': {
        const e = {};
        Object.defineProperty(e,'message',{get(){throw new Error('getter failed');}}); throw e;
      }
      case 'changing-message': {
        let n=0; const e={stack:'test stack'};
        Object.defineProperty(e,'message',{get(){return ++n===1?'first message':'SECOND_READ';}}); throw e;
      }
      case 'revoked': {const p=Proxy.revocable({},{});p.revoke();throw p.proxy;}
      case 'null': throw null;
      case 'string': throw 'string error';
      case 'unpaired': throw new Error('before\\ud800after');
      case 'large': throw new Error('x'.repeat(17*1024*1024));
    }
  };
  fn.run=fn;
  fn.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'},
    secretEnvironmentVariables:secret?[{key:'ALPHA_SECRET'}]:[]};
  return fn;
}
const alpha=schedule('alpha',true), beta=schedule('beta',false);
const auth=async (data,context)=>record({name:'auth',uid:data.uid,eventType:context.eventType});
auth.__endpoint={platform:'gcfv1',eventTrigger:{eventType:'providers/firebase.auth/eventTypes/user.create',eventFilters:{resource:'projects/demo-ipc'}}};
module.exports={alpha,beta,auth};
`;

async function started(t, { secrets = false } = {}) {
  const dir = await mkdtemp(join(tmpdir(),'fireemu-ipc-'));
  await writeFile(join(dir,'package.json'),JSON.stringify({private:true,main:'index.cjs'}));
  await writeFile(join(dir,'index.cjs'),source);
  const env={PATH:process.env.PATH,GCLOUD_PROJECT:'demo-ipc'};
  if(secrets) env.FIREEMU_LOCAL_SECRETS_JSON=JSON.stringify({ALPHA_SECRET:'fixture-only-secret'});
  const child=spawn(process.execPath,[runner,'--source',dir],{env,stdio:['pipe','pipe','pipe']});
  let buffer=Buffer.alloc(0), issue=null, result=null, stderr='';
  const messages=[];
  const exit=once(child,'exit').then(([code,signal])=>(result={code,signal}));
  child.stdin.on('error',()=>{}); // closing an intentionally invalid channel may race a write
  child.stderr.on('data',c=>{if(stderr.length<65536)stderr+=c.toString();});
  child.stdout.on('data',c=>{
    buffer=Buffer.concat([buffer,c]);
    for(;;){
      const nl=buffer.indexOf(10); if(nl<0)return;
      const n=Number(buffer.subarray(0,nl).toString('ascii'));
      if(!Number.isSafeInteger(n)||n<0||n>20*1024*1024){issue='bad output frame';return;}
      if(buffer.length<nl+1+n)return;
      try{messages.push(JSON.parse(buffer.subarray(nl+1,nl+1+n).toString('utf8')));}
      catch{issue='bad output JSON';return;}
      buffer=buffer.subarray(nl+1+n);
    }
  });
  async function waitFor(predicate, label, timeout=4000){
    const end=Date.now()+timeout;
    while(Date.now()<end){
      if(issue)throw Error(issue);
      const value=predicate(); if(value)return value;
      if(result)throw Error(`${label}: runner exited ${JSON.stringify(result)}; ${stderr.slice(-300)}`);
      await new Promise(r=>setTimeout(r,5));
    }
    throw Error(`${label}: timeout`);
  }
  async function exited(timeout=4000){
    if(result)return result;
    let timer;
    try{return await Promise.race([exit,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('exit timeout')),timeout);})]);}
    finally{clearTimeout(timer);}
  }
  t.after(async()=>{
    if(!result){child.kill('SIGKILL');await exited();}
    child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();
    await rm(dir,{recursive:true,force:true});
  });
  const hello=await waitFor(()=>messages.find(m=>m.type==='hello'),'hello');
  assert.equal(hello.manifest.functions.length,3);
  return {child,messages,hello,exited,waitFor,
    async calls(){try{return (await readFile(join(dir,'calls.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}catch(e){if(e.code==='ENOENT')return [];throw e;}}
  };
}

const malformed=[
  ['decimal suffix',Buffer.from('19suffix\n{"type":"shutdown"}')],
  ['negative length',Buffer.from('-1\n{"type":"shutdown"}')],
  ['leading plus',Buffer.from('+19\n{"type":"shutdown"}')],
  ['leading whitespace',Buffer.from(' 19\n{"type":"shutdown"}')],
  ['empty header',Buffer.from('\n')],
  ['truncated header',Buffer.from('12')],
  ['truncated payload',Buffer.from('100\n{"type":"shutdown"}')],
  ['invalid JSON then valid frame',Buffer.concat([Buffer.from('1\n{'),encode(invocation())])],
  ['null message',encode(null)],
  ['array message',encode([])],
  ['unknown message type',encode({type:'invoke-other'})],
  ['missing invocation id',encode(invocation({invocationId:undefined}))],
  ['object invocation id',encode(invocation({invocationId:{id:'test'}}))],
  ['missing function',encode(invocation({function:undefined}))],
  ['missing event',encode(invocation({event:undefined}))],
  ['scalar event',encode(invocation({event:7}))],
];
for(const [name,bytes] of malformed){
  test(`IPC rejects ${name} without invoking a callback`,{timeout:7000},async t=>{
    const f=await started(t);f.child.stdin.end(bytes);
    const outcome=await f.exited();assert.equal(outcome.code,2);
    assert.deepEqual(await f.calls(),[]);
  });
}

test('IPC rejects malformed UTF-8 instead of delivering replacement data',{timeout:7000},async t=>{
  const f=await started(t);
  const body=Buffer.concat([Buffer.from(JSON.stringify(invocation()).replace('日本語','PLACEHOLDER').split('PLACEHOLDER')[0]),Buffer.from([0xff]),Buffer.from(JSON.stringify(invocation()).replace('日本語','PLACEHOLDER').split('PLACEHOLDER')[1])]);
  f.child.stdin.write(Buffer.concat([Buffer.from(`${body.length}\n`),body]));
  const outcome=await f.exited();assert.equal(outcome.code,2);assert.deepEqual(await f.calls(),[]);
});

test('IPC rejects an oversized length before waiting for a body or EOF',{timeout:7000},async t=>{
  const f=await started(t);f.child.stdin.write('16777217\n');
  assert.equal((await f.exited()).code,2);assert.deepEqual(await f.calls(),[]);
});

test('IPC handles split multibyte frames and coalesced invocations',{timeout:7000},async t=>{
  const f=await started(t);
  const frame=encode(invocation());
  for(let at=0;at<frame.length;at+=3)f.child.stdin.write(frame.subarray(at,at+3));
  f.child.stdin.write(Buffer.concat([encode(invocation({invocationId:'b',function:'beta',entryPoint:'beta'})),encode(invocation({invocationId:'c',entryPoint:undefined}))]));
  await f.waitFor(()=>f.messages.filter(m=>m.type==='result').length===3,'results');
  assert.equal(f.messages.filter(m=>m.type==='result'&&m.ok===true).length,3);
  assert.deepEqual((await f.calls()).map(x=>x.value),['日本語','日本語','日本語']);
  f.child.stdin.end();assert.equal((await f.exited()).code,0);
});

test('IPC retains v1 Auth user event delivery',{timeout:7000},async t=>{
  const f=await started(t);
  f.child.stdin.write(encode(invocation({function:'auth',entryPoint:'auth',trigger:'auth',event:{id:'evt',time:'2026-01-01T00:00:00Z',type:'google.firebase.auth.user.v1.created',data:{uid:'owned'}}})));
  const result=await f.waitFor(()=>f.messages.find(m=>m.type==='result'),'result');assert.equal(result.ok,true);
  assert.deepEqual(await f.calls(),[{name:'auth',uid:'owned',eventType:'providers/firebase.auth/eventTypes/user.create'}]);
});

for(const overrides of [
  {entryPoint:'beta'}, {function:'absent',entryPoint:'beta'}, {entryPoint:'missing'}, {trigger:'storage'},
]){
  test(`IPC binds dispatch to manifest ${JSON.stringify(overrides)}`,{timeout:7000},async t=>{
    const f=await started(t,{secrets:true});f.child.stdin.write(encode(invocation(overrides)));
    const rejected=await f.waitFor(()=>f.messages.find(m=>m.type==='result'),'result');
    assert.equal(rejected.ok,false);assert.deepEqual(await f.calls(),[]);
    f.child.stdin.write(encode(invocation({invocationId:'good'})));
    assert.equal((await f.waitFor(()=>f.messages.find(m=>m.invocationId==='good'&&m.type==='result'),'next result')).ok,true);
    const calls=await f.calls();assert.equal(calls.length,1);assert.equal(calls[0].name,'alpha');assert.equal(calls[0].secret,'fixture-only-secret');
  });
}

test('IPC rejects duplicate in-flight ids without a second callback',{timeout:7000},async t=>{
  const f=await started(t);
  // Both messages arrive in one chunk; the first must already be in-flight.
  f.child.stdin.write(Buffer.concat([encode(invocation({event:{data:{mode:'wait'}}})), encode(invocation())]));
  assert.equal((await f.exited()).code,2);assert.ok((await f.calls()).length<=1);
});

for(const mode of ['error','throwing-stack','throwing-message','changing-message','revoked','null','string','unpaired','large']){
  test(`IPC produces one failure result and remains usable after ${mode}`,{timeout:7000},async t=>{
    const f=await started(t);f.child.stdin.write(encode(invocation({event:{data:{mode}}})));
    const failed=await f.waitFor(()=>f.messages.find(m=>m.type==='result'),'failure result');
    assert.equal(failed.ok,false);assert.equal(typeof failed.error,'string');assert.ok(Buffer.byteLength(failed.error)<=4096);
    assert.equal(failed.error.includes('SECOND_READ'),false);
    assert.equal(failed.error.isWellFormed(),true);
    if(mode==='error')assert.equal(failed.error,'ordinary error');
    if(mode==='changing-message')assert.equal(failed.error,'first message');
    f.child.stdin.write(encode(invocation({invocationId:'next'})));
    assert.equal((await f.waitFor(()=>f.messages.find(m=>m.type==='result'&&m.invocationId==='next'),'success')).ok,true);
    assert.equal(f.messages.filter(m=>m.type==='result'&&m.invocationId==='test-1').length,1);
  });
}

test('explicit shutdown terminates and does not dispatch a trailing frame',{timeout:7000},async t=>{
  const f=await started(t);f.child.stdin.end(Buffer.concat([encode({type:'shutdown'}),encode(invocation())]));
  assert.equal((await f.exited()).code,0);assert.deepEqual(await f.calls(),[]);
});

test('distinct concurrent ids retain their outcomes and a completed id may be reused',{timeout:7000},async t=>{
  const f=await started(t);
  f.child.stdin.write(Buffer.concat([
    encode(invocation({invocationId:'slow',event:{data:{mode:'wait'}}})),
    encode(invocation({invocationId:'fast',function:'beta',entryPoint:'beta'})),
  ]));
  await f.waitFor(()=>f.messages.filter(m=>m.type==='result').length===2,'both results');
  assert.deepEqual(f.messages.filter(m=>m.type==='result').map(m=>m.invocationId),['fast','slow']);
  f.child.stdin.write(encode(invocation({invocationId:'fast',function:'beta',entryPoint:'beta'})));
  await f.waitFor(()=>f.messages.filter(m=>m.type==='result'&&m.invocationId==='fast').length===2,'reused completed id');
  assert.equal((await f.calls()).length,3);
});
