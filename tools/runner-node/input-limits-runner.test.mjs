// Actual runner, OS pipes and user callbacks. No Firebase/Express doubles are
// needed: these callbacks only expose SDK-shaped schedule metadata.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

const runner=process.env.FIREEMU_TEST_RUNNER || fileURLToPath(new URL('./index.mjs',import.meta.url));
const MAX_COUNT=4096;
const MAX_FRAME=16*1024*1024;
const source=`
const fs=require('node:fs');
const held=[];
const task=async data=>{
  fs.appendFileSync(__dirname+'/calls.jsonl',JSON.stringify({tag:data.tag,action:data.action})+'\\n');
  if(data.action==='hold')await new Promise(resolve=>held.push({resolve,data}));
  if(data.action==='release'){const batch=held.splice(0);for(const item of batch)item.resolve();}
  if(data.action==='throw')throw new Error('expected fixture failure');
  if(data.sleep)await new Promise(resolve=>setTimeout(resolve,data.sleep));
};
task.run=task;task.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'}};
module.exports={task};
`;
function invoke(id,data={},extra={}) {
  return {type:'invoke',invocationId:id,function:'task',entryPoint:'task',trigger:'schedule',
    event:{data},...extra};
}
function frame(msg) {
  const body=Buffer.from(JSON.stringify(msg));
  return Buffer.concat([Buffer.from(`${body.length}\n`),body]);
}
function exactFrame(id,bytes) {
  // A caller-provided payloadBytes must never replace the receiver's byte count.
  const msg=invoke(id,{action:'hold',tag:id,value:''},{payloadBytes:1});
  const overhead=Buffer.byteLength(JSON.stringify(msg));msg.event.data.value='x'.repeat(bytes-overhead);
  const raw=frame(msg);assert.equal(raw.length,bytes+String(bytes).length+1);return raw;
}

async function start(t,{secrets=false}={}) {
  const dir=await mkdtemp(join(tmpdir(),'fireemu-input-limits-'));
  await writeFile(join(dir,'package.json'),JSON.stringify({main:'index.cjs'}));
  await writeFile(join(dir,'index.cjs'),source);
  const child=spawn(process.execPath,[runner,'--source',dir],{stdio:['pipe','pipe','pipe'],
    env:{PATH:process.env.PATH,GCLOUD_PROJECT:'demo-input-limits',
      ...(secrets?{FIREEMU_LOCAL_SECRETS_JSON:'{"TEST_ONLY":"not-a-real-secret"}'}:{})}});
  let result=null,stderr='',buffer=Buffer.alloc(0),issue=null;
  const messages=[];
  const end=new Promise((resolve,reject)=>{
    child.on('error',reject);child.on('exit',(code,signal)=>{result={code,signal};resolve(result);});
  });
  child.stdin.on('error',()=>{});
  child.stderr.on('data',b=>{if(stderr.length<65536)stderr+=b.toString();});
  child.stdout.on('data',b=>{
    if(issue)return;buffer=Buffer.concat([buffer,b]);
    for(;;){
      const nl=buffer.indexOf(10);if(nl<0)return;
      const n=Number(buffer.subarray(0,nl));
      if(!Number.isSafeInteger(n)||n<=0||n>MAX_FRAME){issue='invalid output frame';return;}
      if(buffer.length<nl+1+n)return;
      try{messages.push(JSON.parse(buffer.subarray(nl+1,nl+1+n).toString('utf8')));}
      catch{issue='invalid output JSON';return;}
      buffer=buffer.subarray(nl+1+n);
    }
  });
  async function exited(timeout=6000){
    if(result)return result;let timer;
    try{return await Promise.race([end,new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(Error('test waiting for child exit')),timeout);
    })]);}finally{clearTimeout(timer);}
  }
  async function wait(check,label,timeout=6000){
    const deadline=performance.now()+timeout;
    while(performance.now()<deadline){
      if(issue)throw Error(issue);const value=await check();if(value)return value;
      if(result)throw Error(`unexpected exit waiting for ${label}: ${JSON.stringify(result)} ${stderr}`);
      await delay(5);
    }
    throw Error(`test deadline waiting for ${label}`);
  }
  async function calls(){
    try{return (await readFile(join(dir,'calls.jsonl'),'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}
    catch(e){if(e.code==='ENOENT')return [];throw e;}
  }
  t.after(async()=>{
    if(!result){child.kill('SIGKILL');await exited();}
    child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();
    await rm(dir,{recursive:true,force:true});
  });
  await wait(()=>messages.find(x=>x.type==='hello'),'hello');
  return {child,messages,calls,wait,exited,get result(){return result;},get stderr(){return stderr;},
    get trailing(){return buffer.length;},get issue(){return issue;},
    send(msg){child.stdin.write(frame(msg),()=>{});},
    write(raw){return new Promise((resolve,reject)=>child.stdin.write(raw,e=>e?reject(e):resolve()));}};
}

test('real 30-second policy: stalled header and slow body expire; idle/invoked runner stays alive',
  {timeout:42000},async t=>{
    const header=await start(t),body=await start(t),idle=await start(t);
    idle.send(invoke('long-running',{action:'hold',tag:'long-running'}));
    await idle.wait(async()=>(await idle.calls()).length===1,'long-running callback');
    const began=performance.now();header.child.stdin.write('1');
    body.child.stdin.write(`${MAX_FRAME}\n{"PRIVATE_INPUT_MARKER":`);
    const drip=setInterval(()=>{if(!body.result)body.child.stdin.write(' ',()=>{});},150);
    t.after(()=>clearInterval(drip));
    const outcomes=await Promise.all([header.exited(35000),body.exited(35000)]);
    clearInterval(drip);const elapsed=performance.now()-began;
    assert.ok(elapsed>=27_000&&elapsed<35_000,`observed interval ${elapsed}`);
    for(const [f,outcome] of [[header,outcomes[0]],[body,outcomes[1]]]){
      assert.equal(outcome.code,2);assert.equal(outcome.signal,null);
      assert.match(f.stderr,/input frame deadline/);assert.equal(f.stderr.includes('PRIVATE_INPUT_MARKER'),false);
      assert.deepEqual(await f.calls(),[]);assert.equal(f.messages.some(x=>x.type==='result'),false);
    }
    assert.equal(idle.result,null);assert.equal(idle.messages.some(x=>x.type==='result'),false);
    idle.send(invoke('release',{action:'release',tag:'release'}));
    await idle.wait(()=>idle.messages.filter(x=>x.type==='result').length===2,'two normal results');
    assert.ok(idle.messages.filter(x=>x.type==='result').every(x=>x.ok===true));
    idle.child.stdin.end();assert.equal((await idle.exited()).code,0);
  });

test('4,096 pending callbacks are admitted; 4,097th is retired before callback entry',
  {timeout:15000},async t=>{
    const f=await start(t);
    const chunks=Array.from({length:MAX_COUNT+1},(_,i)=>frame(invoke(String(i),{action:'hold',tag:i})));
    f.child.stdin.write(Buffer.concat(chunks),()=>{});
    assert.equal((await f.exited()).code,2);assert.match(f.stderr,/active invocation count/);
    const calls=await f.calls();assert.equal(calls.length,MAX_COUNT);
    assert.deepEqual(calls.map(x=>x.tag),Array.from({length:MAX_COUNT},(_,i)=>i));
    assert.equal(f.messages.some(x=>x.type==='result'),false);
  });

test('callbacks waiting in the secret environment queue are also counted',
  {timeout:15000},async t=>{
    const f=await start(t,{secrets:true});
    f.send(invoke('first',{action:'hold',tag:'first'}));
    await f.wait(async()=>(await f.calls()).length===1,'first secret callback');
    const queued=Array.from({length:MAX_COUNT},(_,i)=>frame(invoke(`queued-${i}`,{tag:i})));
    f.child.stdin.write(Buffer.concat(queued),()=>{});
    assert.equal((await f.exited()).code,2);assert.match(f.stderr,/active invocation count/);
    assert.deepEqual(await f.calls(),[{tag:'first',action:'hold'}]);
    assert.equal(f.messages.some(x=>x.type==='result'),false);
  });

test('64 MiB of actual pending payload bytes fits; the next small frame is not dispatched',
  {timeout:20000},async t=>{
    const f=await start(t);
    for(let i=0;i<4;i++){
      await f.write(exactFrame(`large-${i}`,MAX_FRAME));
      await f.wait(async()=>(await f.calls()).length===i+1,'large frame admitted');
      assert.equal(f.result,null);
    }
    // Still below the count cap. Actual header/body length defeats payloadBytes:1.
    f.send(invoke('overflow',{tag:'overflow'},{payloadBytes:1}));
    assert.equal((await f.exited()).code,2);assert.match(f.stderr,/active invocation bytes/);
    assert.equal((await f.calls()).length,4);assert.equal(f.messages.some(x=>x.type==='result'),false);
  });

for(const action of ['normal','throw']) {
  test(`slots and bytes are released after ${action}, without a process-lifetime count cap`,
    {timeout:20000},async t=>{
      const f=await start(t);let total=0;
      for(let batch=0;batch<17;batch++){
        const bytes=Buffer.concat(Array.from({length:256},(_,i)=>frame(invoke(`reuse-${i}`,{tag:i,action}))));
        await f.write(bytes);total+=256;
        await f.wait(()=>f.messages.filter(x=>x.type==='result').length===total,'batch results');
        assert.equal(f.result,null);
      }
      assert.ok(total>MAX_COUNT);assert.equal((await f.calls()).length,total);
      const results=f.messages.filter(x=>x.type==='result');
      assert.equal(results.every(x=>x.ok===(action==='normal')),true);
      f.child.stdin.end();assert.equal((await f.exited()).code,0);assert.equal(f.issue,null);
    });
}

test('large failed bindings release bytes; the next valid maximum-sized request still runs',
  {timeout:20000},async t=>{
    const f=await start(t);
    for(let i=0;i<6;i++){
      const msg=invoke(`bad-${i}`,{data:'x'.repeat(12*1024*1024)},{entryPoint:'wrong'});
      await f.write(frame(msg));
      await f.wait(()=>f.messages.some(x=>x.type==='result'&&x.invocationId===`bad-${i}`),'binding rejection');
      assert.equal(f.result,null);
    }
    assert.deepEqual(await f.calls(),[]);
    await f.write(exactFrame('large',MAX_FRAME));
    await f.wait(async()=>(await f.calls()).length===1,'large callback');
    f.send(invoke('release',{action:'release',tag:'release'}));
    await f.wait(()=>f.messages.filter(x=>x.type==='result'&&x.ok===true).length===2,'post-release results');
    f.child.stdin.end();assert.equal((await f.exited()).code,0);
  });

test('fragmented Unicode, sequential IDs and genuine parallel completion order are preserved',
  {timeout:10000},async t=>{
    const f=await start(t);const bytes=frame(invoke('split',{tag:'日本語😀'}));
    for(let i=0;i<bytes.length;i+=3)await f.write(bytes.subarray(i,i+3));
    await f.wait(()=>f.messages.some(x=>x.type==='result'),'split result');
    f.send(invoke('late',{tag:'late',sleep:80}));f.send(invoke('early',{tag:'early'}));
    await f.wait(()=>f.messages.filter(x=>x.type==='result').length===3,'parallel results');
    assert.deepEqual(f.messages.filter(x=>x.type==='result').map(x=>x.invocationId),['split','early','late']);
    f.child.stdin.end();assert.equal((await f.exited()).code,0);
  });
