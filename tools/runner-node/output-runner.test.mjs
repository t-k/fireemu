import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

const runner=process.env.FIREEMU_TEST_RUNNER || fileURLToPath(new URL('./index.mjs',import.meta.url));
const MAX=16*1024*1024; // independently match native protocol.rs
function frame(value) {
  const b=Buffer.from(JSON.stringify(value));return Buffer.concat([Buffer.from(`${b.length}\n`),b]);
}
const source=`
const fs=require('node:fs');const path=require('node:path');
const marker=(name,value)=>fs.writeFileSync(path.join(__dirname,name),String(value));
const task=async data=>{
  marker('entered','yes');
  if(data?.label)marker('entered-'+data.label,'yes');
  if(data?.direct)process.stdout.write('direct-user-stdout\\n');
  if(data?.sleep)await new Promise(r=>setTimeout(r,data.sleep));
  const body='日'.repeat(Math.floor((data?.bytes||0)/3));
  for(let n=0;n<(data?.count||0);n++){
    console.log(String(n)+' '+body);
    if(n%16===0)marker('buffered',process.stdout.writableLength);
  }
  marker('logs-produced','yes');
  if(data?.afterSleep)await new Promise(r=>setTimeout(r,data.afterSleep));
  marker('callback-finished','yes');
};
task.run=task;task.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'},secretEnvironmentVariables:[{key:'LOCAL'}]};
const plain=async data=>task(data);plain.run=plain;plain.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'}};
module.exports={task,plain};
`;
async function start(t, customSource=source, secrets=false) {
  const dir=await mkdtemp(join(tmpdir(),'fireemu-output-'));
  await writeFile(join(dir,'package.json'),JSON.stringify({main:'index.cjs'}));
  await writeFile(join(dir,'index.cjs'),customSource);
  const child=spawn(process.execPath,[runner,'--source',dir],{
    env:{PATH:process.env.PATH,GCLOUD_PROJECT:'demo-output',...(secrets?{FIREEMU_LOCAL_SECRETS_JSON:'{"LOCAL":"fixture"}'}:{})},stdio:['pipe','pipe','pipe']});
  const messages=[];let bytes=Buffer.alloc(0), invalid=null, result=null,stderr='';
  child.on('exit',(code,signal)=>{result={code,signal};});
  child.stdin.on('error',()=>{});
  child.stderr.on('data',data=>{if(stderr.length<16384)stderr+=data.toString();});
  child.stdout.on('data',data=>{
    if(invalid)return;
    bytes=Buffer.concat([bytes,data]);
    for(;;){
      const nl=bytes.indexOf(10);if(nl<0)return;
      const len=Number(bytes.subarray(0,nl).toString('ascii'));
      if(!Number.isSafeInteger(len)||len<1||len>MAX){invalid='bad output length';return;}
      if(bytes.length<nl+1+len)return;
      try{messages.push(JSON.parse(bytes.subarray(nl+1,nl+1+len).toString('utf8')));}
      catch{invalid='bad output json';return;}
      bytes=bytes.subarray(nl+1+len);
    }
  });
  async function wait(predicate,label,ms=5000){
    const until=Date.now()+ms;
    while(Date.now()<until){const v=await predicate();if(v)return v;await delay(5);}
    throw Error(`${label} timeout; exit=${JSON.stringify(result)}; parse=${invalid}; stderr=${stderr.slice(-300)}`);
  }
  async function exited(ms=5000){return wait(()=>result,'exit',ms);}
  async function marked(name){try{return await readFile(join(dir,name),'utf8');}catch(e){if(e.code==='ENOENT')return '';throw e;}}
  t.after(async()=>{
    if(!result){child.kill('SIGKILL');await exited();}
    child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();
    await rm(dir,{recursive:true,force:true});
  });
  return {child,messages,wait,exited,marked,dir,
    get stderr(){return stderr;},get invalid(){return invalid;},get trailingBytes(){return bytes.length;},
    invoke(data={},id='output-test',name='task'){child.stdin.write(frame({type:'invoke',invocationId:id,function:name,entryPoint:name,trigger:'schedule',event:{data}}));},
    async ready(){await wait(()=>messages.find(m=>m.type==='hello'),'hello');}
  };
}

test('paused reader resumes all complete ordered frames exactly once',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.child.stdout.pause();f.invoke({count:100,bytes:8192});
  await f.wait(()=>f.marked('callback-finished'),'callback');await delay(80);f.child.stdout.resume();
  await f.wait(()=>f.messages.find(m=>m.type==='result'),'result');
  const logs=f.messages.filter(m=>m.type==='log'&&m.invocationId==='output-test');
  assert.equal(logs.length,100);assert.deepEqual(logs.map(m=>Number(m.message.split(' ')[0])),Array.from({length:100},(_,i)=>i));
  assert.equal(f.messages.filter(m=>m.type==='result').length,1);assert.equal(f.invalid,null);
  f.child.stdin.end();assert.equal((await f.exited()).code,0);
});

for(const termination of ['eof','shutdown']){
  test(`${termination} flushes already queued logs and result instead of truncating them`,{timeout:10000},async t=>{
    const f=await start(t);await f.ready();f.child.stdout.pause();f.invoke({count:20,bytes:200000});
    await f.wait(()=>f.marked('callback-finished'),'callback');await delay(30);
    if(termination==='eof')f.child.stdin.end();else f.child.stdin.write(frame({type:'shutdown'}));
    await delay(120);f.child.stdout.resume();
    assert.equal((await f.exited()).code,0);await delay(30);
    assert.equal(f.invalid,null);assert.equal(f.trailingBytes,0);
    assert.equal(f.messages.filter(m=>m.type==='log'&&m.invocationId==='output-test').length,20);
    assert.equal(f.messages.filter(m=>m.type==='result'&&m.ok===true).length,1);
  });
}

test('byte overflow retires runner instead of buffering a log flood indefinitely',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.child.stdout.pause();f.invoke({count:250,bytes:256*1024});
  assert.equal((await f.exited()).code,2);
  assert.equal(await f.marked('callback-finished'),'');
  assert.match(f.stderr,/runner output failed \(byte queue limit\)/);
  // The Node Writable itself has no growing queue: remaining frames are in the
  // explicitly bounded writer, and one admitted frame can be in-flight.
  assert.ok(Number(await f.marked('buffered'))<1024*1024);
});

test('frame-count overflow retires even when logs are too small to hit the byte cap',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.child.stdout.pause();f.invoke({count:2000,bytes:1});
  assert.equal((await f.exited()).code,2);assert.equal(await f.marked('callback-finished'),'');
  assert.match(f.stderr,/runner output failed \(frame queue limit\)/);
});

test('closed stdout fails with a fixed diagnostic rather than unhandled EPIPE',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.child.stdout.destroy();f.invoke({count:1,bytes:4096});
  assert.equal((await f.exited()).code,2);assert.match(f.stderr,/runner output failed/);
  assert.equal(f.stderr.includes("Unhandled 'error' event"),false);
});

test('oversized hello is rejected before its length or payload is emitted',{timeout:10000},async t=>{
  const f=await start(t,source+"task.__endpoint.labels={huge:'X'.repeat(17*1024*1024)};\n");
  assert.equal((await f.exited()).code,2);assert.equal(f.invalid,null);assert.equal(f.trailingBytes,0);
  assert.equal(f.messages.some(m=>m.type==='hello'),false);assert.match(f.stderr,/frame too large/);
});

test('clean EOF on an empty codebase still publishes one complete hello',{timeout:10000},async t=>{
  const f=await start(t,'module.exports={};\n');f.child.stdin.end();
  assert.equal((await f.exited()).code,0);await delay(20);
  assert.equal(f.invalid,null);assert.equal(f.trailingBytes,0);
  assert.equal(f.messages.filter(m=>m.type==='hello').length,1);
});

test('raw user stdout still goes to stderr and cannot corrupt framed output',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.invoke({direct:true,count:2,bytes:10});
  await f.wait(()=>f.messages.find(m=>m.type==='result'),'result');
  assert.match(f.stderr,/direct-user-stdout/);assert.equal(f.invalid,null);
  f.child.stdin.end();assert.equal((await f.exited()).code,0);
});

test('independent concurrent callbacks retain complete results during transient backpressure',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.child.stdout.pause();
  f.invoke({count:50,bytes:8192,sleep:30},'later');f.invoke({count:50,bytes:8192},'earlier');
  await delay(150);f.child.stdout.resume();
  await f.wait(()=>f.messages.filter(m=>m.type==='result').length===2,'both results');
  assert.deepEqual(f.messages.filter(m=>m.type==='result').map(m=>m.invocationId),['earlier','later']);
  for(const id of ['earlier','later'])assert.equal(f.messages.filter(m=>m.type==='log'&&m.invocationId===id).length,50);
  assert.equal(f.invalid,null);f.child.stdin.end();assert.equal((await f.exited()).code,0);
});

test('shutdown cannot turn blocked incomplete output into successful process exit',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.child.stdout.pause();f.invoke({count:10,bytes:256*1024});
  await f.wait(()=>f.marked('callback-finished'),'callback');f.child.stdin.write(frame({type:'shutdown'}));
  assert.equal((await f.exited(4000)).code,2);assert.match(f.stderr,/deadline/);
});

test('an idle open input cannot keep a blocked output frame forever',{timeout:38000},async t=>{
  const f=await start(t);await f.ready();f.child.stdout.pause();f.invoke({count:10,bytes:256*1024});
  await f.wait(()=>f.marked('callback-finished'),'callback');
  const started=Date.now();assert.equal((await f.exited(34000)).code,2);
  const elapsed=Date.now()-started;assert.ok(elapsed>25000&&elapsed<34000,`elapsed=${elapsed}`);
  assert.match(f.stderr,/deadline/);
});


test('shutdown drain does not start callbacks waiting for a different environment group',{timeout:10000},async t=>{
  const f=await start(t,source,true);await f.ready();f.child.stdout.pause();
  f.invoke({count:5,bytes:200000,label:'first',afterSleep:150},'first');
  f.invoke({label:'second'},'second','plain');
  await f.wait(()=>f.marked('logs-produced'),'logs buffered');
  f.child.stdin.write(frame({type:'shutdown'}));
  await delay(250);
  assert.equal(await f.marked('entered-first'),'yes');
  assert.equal(await f.marked('entered-second'),'');
  f.child.stdout.resume();assert.equal((await f.exited()).code,0);
  assert.equal(f.messages.some(m=>m.type==='result'&&m.invocationId==='second'&&m.ok===true),false);
});
