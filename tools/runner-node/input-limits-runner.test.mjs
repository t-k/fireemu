// Actual runner, OS pipes and user callbacks. No Firebase/Express doubles are
// needed: these callbacks only expose SDK-shaped schedule metadata.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { HARD_BACKSTOP_MS, childCpuTime, deadlineWithLag, quietStallMs, sampled, untilExit, waitUntil } from './load-independent-wait.mjs';
import { MAX_INPUT_FRAME_WAIT_MS } from './protocol.mjs';
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
task.run=task;task.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'},secretEnvironmentVariables:[{key:'TEST_ONLY'}]};
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
  // Waiting gives up only when the child shows no progress for a whole stall window (calls made,
  // frames received, output, CPU used), never because a fixed wall-clock bound ran out.
  const cpu=sampled(()=>childCpuTime(child.pid));
  async function progress(){
    let size=0;
    try{size=(await stat(join(dir,'calls.jsonl'))).size;}catch(e){if(e.code!=='ENOENT')throw e;}
    return `${size}|${messages.length}|${stderr.length}|${cpu()}`;
  }
  // `options.stallMs` is for a child that is meant to be quiet for a whole product deadline.
  async function exited(options={}){
    return untilExit({end,result:()=>result,progress,label:'child',...options});
  }
  async function wait(check,label){
    return waitUntil({check,progress,label:`waiting for ${label}`,failFast:()=>{
      if(issue)throw Error(issue);
      if(result)throw Error(`unexpected exit waiting for ${label}: ${JSON.stringify(result)} ${stderr}`);
    }});
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
  {timeout:HARD_BACKSTOP_MS},async t=>{
    const header=await start(t),body=await start(t),idle=await start(t);
    idle.send(invoke('long-running',{action:'hold',tag:'long-running'}));
    await idle.wait(async()=>(await idle.calls()).length===1,'long-running callback');
    // The runner's 30 s policy is measured on a clock the loaded machine slows down too, so the
    // upper bound allows for the worst event-loop stall this process saw (zero when idle).
    const lag=monitorEventLoopDelay({resolution:10});lag.enable();
    const began=performance.now();header.child.stdin.write('1');
    body.child.stdin.write(`${MAX_FRAME}\n{"PRIVATE_INPUT_MARKER":`);
    const drip=setInterval(()=>{if(!body.result)body.child.stdin.write(' ',()=>{});},150);
    t.after(()=>clearInterval(drip));
    // Both children are meant to be silent until the product's input deadline, and exit just after it;
    // CPU time shows no progress at the one-second resolution Linux reports, so the window has to be
    // longer than the deadline, not equal to it.
    const quiet={stallMs:quietStallMs(MAX_INPUT_FRAME_WAIT_MS)};
    const outcomes=await Promise.all([header.exited(quiet),body.exited(quiet)]);
    clearInterval(drip);const elapsed=performance.now()-began;lag.disable();
    const {limit,tooLoaded}=deadlineWithLag(35_000,lag.max/1e6);
    assert.ok(!tooLoaded,`the machine is too loaded to judge the 30 s policy (event-loop stall ${lag.max/1e6} ms)`);
    assert.ok(elapsed>=27_000&&elapsed<limit,`observed interval ${elapsed} (limit ${limit})`);
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
  {timeout:HARD_BACKSTOP_MS},async t=>{
    const f=await start(t);
    const chunks=Array.from({length:MAX_COUNT+1},(_,i)=>frame(invoke(String(i),{action:'hold',tag:i})));
    f.child.stdin.write(Buffer.concat(chunks),()=>{});
    assert.equal((await f.exited()).code,2);assert.match(f.stderr,/active invocation count/);
    const calls=await f.calls();assert.equal(calls.length,MAX_COUNT);
    assert.deepEqual(calls.map(x=>x.tag),Array.from({length:MAX_COUNT},(_,i)=>i));
    assert.equal(f.messages.some(x=>x.type==='result'),false);
  });

test('callbacks waiting in the secret environment queue are also counted',
  {timeout:HARD_BACKSTOP_MS},async t=>{
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
  {timeout:HARD_BACKSTOP_MS},async t=>{
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
    {timeout:HARD_BACKSTOP_MS},async t=>{
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
  {timeout:HARD_BACKSTOP_MS},async t=>{
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
  {timeout:HARD_BACKSTOP_MS},async t=>{
    const f=await start(t);const bytes=frame(invoke('split',{tag:'日本語😀'}));
    for(let i=0;i<bytes.length;i+=3)await f.write(bytes.subarray(i,i+3));
    await f.wait(()=>f.messages.some(x=>x.type==='result'),'split result');
    f.send(invoke('late',{tag:'late',sleep:80}));f.send(invoke('early',{tag:'early'}));
    await f.wait(()=>f.messages.filter(x=>x.type==='result').length===3,'parallel results');
    assert.deepEqual(f.messages.filter(x=>x.type==='result').map(x=>x.invocationId),['split','early','late']);
    f.child.stdin.end();assert.equal((await f.exited()).code,0);
  });
