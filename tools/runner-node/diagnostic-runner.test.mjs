import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

const runner=process.env.FIREEMU_TEST_RUNNER || fileURLToPath(new URL('./index.mjs',import.meta.url));
const code=`
const fs=require('node:fs'),path=require('node:path');
const mark=(name,value='yes')=>fs.writeFileSync(path.join(__dirname,name),String(value));
const f=async data=>{
  mark('entered');
  if(data.mode==='normal'){
    process.stderr.write('日本😀\\n',()=>mark('callback'));
    process.stdout.write(Buffer.from([0,255,1]));
    const b=Buffer.from('frozen');process.stderr.write(b);b.fill(120);
    process.stderr.setDefaultEncoding('hex');process.stderr.write('4142');process.stderr.setDefaultEncoding('utf8');
    mark('returned');return;
  }
  if(data.mode==='respect'){
    for(let i=0;i<data.count;i++){
      if(!process.stderr.write(Buffer.alloc(data.bytes,65+i%26)))await new Promise(resolve=>process.stderr.once('drain',resolve));
    }
    mark('completed');return;
  }
  const stream=data.channel==='stdout'?process.stdout:process.stderr;
  const bytes=Buffer.alloc(data.bytes||0,120);
  for(let i=0;i<data.count;i++)stream.write(bytes);
  mark('buffered',process.stderr.writableLength);mark('completed');
};f.run=f;f.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 5 minutes'}};
module.exports={f};
`;
function frame(v){const b=Buffer.from(JSON.stringify(v));return Buffer.concat([Buffer.from(b.length+'\n'),b]);}
async function start(t,source=code){
  const dir=await mkdtemp(join(tmpdir(),'fireemu-diagnostics-'));
  await writeFile(join(dir,'package.json'),'{"main":"index.cjs"}');await writeFile(join(dir,'index.cjs'),source);
  const child=spawn(process.execPath,[runner,'--source',dir],{env:{PATH:process.env.PATH,GCLOUD_PROJECT:'demo-diagnostics'},stdio:['pipe','pipe','pipe']});
  const messages=[];let stdout=Buffer.alloc(0),bad=null,exit=null;const stderr=[];
  child.on('exit',(code,signal)=>{exit={code,signal};});child.stdin.on('error',()=>{});
  child.stdout.on('data',b=>{stdout=Buffer.concat([stdout,b]);for(;;){
    const nl=stdout.indexOf(10);if(nl<0)return;const n=Number(stdout.subarray(0,nl).toString());
    if(!Number.isSafeInteger(n)||n<=0||n>16*1024*1024){bad='invalid stdout length';return;}
    if(stdout.length<nl+1+n)return;
    try{messages.push(JSON.parse(stdout.subarray(nl+1,nl+1+n).toString()));}catch{bad='invalid stdout json';return;}
    stdout=stdout.subarray(nl+1+n);
  }});
  child.stderr.on('data',b=>stderr.push(b));
  async function wait(fn,label,ms=5000){const deadline=Date.now()+ms;while(Date.now()<deadline){const v=await fn();if(v)return v;await delay(5);}throw Error(`${label}; exit=${JSON.stringify(exit)} bad=${bad}`);}
  async function marked(name){try{return await readFile(join(dir,name),'utf8');}catch(e){if(e.code==='ENOENT')return '';throw e;}}
  t.after(async()=>{if(!exit){child.kill('SIGKILL');await wait(()=>exit,'kill');}child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();await rm(dir,{recursive:true,force:true});});
  return {child,messages,wait,marked,dir,get bytes(){return Buffer.concat(stderr);},get bad(){return bad;},get tail(){return stdout.length;},get exit(){return exit;},
    invoke(data,id='direct'){child.stdin.write(frame({type:'invoke',invocationId:id,function:'f',entryPoint:'f',trigger:'schedule',event:{data}}));},
    async ready(){await wait(()=>messages.find(v=>v.type==='hello'),'hello');},
    async done(ms=5000){return wait(()=>exit,'exit',ms);},
  };
}

test('raw bytes/encodings/callbacks are preserved without corrupting stdout framing',async t=>{
  const f=await start(t);await f.ready();f.invoke({mode:'normal'});
  await f.wait(()=>f.marked('callback'),'write callback');await f.wait(()=>f.messages.find(m=>m.type==='result'),'result');
  f.child.stdin.end();assert.equal((await f.done()).code,0);await delay(20);
  assert.deepEqual(f.bytes,Buffer.concat([Buffer.from('日本😀\n'),Buffer.from([0,255,1]),Buffer.from('frozenAB')]));assert.equal(f.bad,null);assert.equal(f.tail,0);
});
for(const channel of ['stderr','stdout']){
  test(`${channel} flood stops before callback completion when its pipe is not drained`,{timeout:10000},async t=>{
    const f=await start(t);await f.ready();f.child.stderr.pause();f.invoke({channel,count:256,bytes:256*1024});
    assert.equal((await f.done()).code,2);assert.equal(await f.marked('completed'),'');
    assert.equal(f.messages.some(m=>m.type==='result'&&m.ok),false);assert.equal(f.bad,null);
  });
}
test('one oversized raw write is rejected without partially publishing that chunk',async t=>{
  const f=await start(t);await f.ready();f.invoke({count:1,bytes:8*1024*1024+1});
  assert.equal((await f.done()).code,2);await delay(20);assert.equal(f.bytes.length,0);assert.equal(await f.marked('completed'),'');
});
test('an exact 8MiB raw chunk is accepted and its callback frees the reservation',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.invoke({count:1,bytes:8*1024*1024},'exact');
  await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='exact'),'result');
  await f.wait(()=>f.bytes.length===8*1024*1024,'stderr drain');
  f.invoke({count:1,bytes:256*1024},'again');await f.wait(()=>f.messages.some(m=>m.type==='result'&&m.invocationId==='again'),'second result');
  f.child.stdin.end();assert.equal((await f.done()).code,0);await delay(20);assert.equal(f.bytes.length,8*1024*1024+256*1024);
});
test('zero-byte callback flood is bounded by count even though it has no body bytes',async t=>{
  const f=await start(t);await f.ready();f.invoke({count:1025,bytes:0});
  assert.equal((await f.done()).code,2);assert.equal(await f.marked('completed'),'');
});
test('a cooperative producer can exceed lifetime limits using the native drain event',{timeout:10000},async t=>{
  const f=await start(t);await f.ready();f.child.stderr.pause();f.invoke({mode:'respect',count:80,bytes:256*1024});
  await delay(100);assert.equal(await f.marked('completed'),'');f.child.stderr.resume();
  await f.wait(()=>f.marked('completed'),'callback completion');await f.wait(()=>f.messages.some(m=>m.type==='result'),'result');
  f.child.stdin.end();assert.equal((await f.done()).code,0);await delay(20);
  assert.equal(f.bytes.length,80*256*1024);
  for(let i=0;i<80;i++)assert.deepEqual(f.bytes.subarray(i*256*1024,(i+1)*256*1024),Buffer.alloc(256*1024,65+i%26));
});
for(const mode of ['eof','shutdown']){
  test(`${mode} flushes admitted diagnostic bytes together with the protocol result`,{timeout:10000},async t=>{
    const f=await start(t);await f.ready();f.child.stderr.pause();f.invoke({count:16,bytes:256*1024});
    await f.wait(()=>f.marked('completed'),'writes admitted');await f.wait(()=>f.messages.some(m=>m.type==='result'),'result');
    if(mode==='eof')f.child.stdin.end();else f.child.stdin.write(frame({type:'shutdown'}));
    await delay(100);assert.equal(f.exit,null);f.child.stderr.resume();assert.equal((await f.done()).code,0);await delay(30);
    assert.equal(f.bytes.length,4*1024*1024);assert.equal(f.bad,null);assert.equal(f.tail,0);
  });
}
for(const mode of ['eof','shutdown']){
  test(`${mode} does not claim normal termination when the diagnostic pipe stays blocked`,{timeout:10000},async t=>{
    const f=await start(t);await f.ready();f.child.stderr.pause();f.invoke({count:16,bytes:256*1024});
    await f.wait(()=>f.marked('completed'),'admitted');await f.wait(()=>f.messages.some(m=>m.type==='result'),'result');
    if(mode==='eof')f.child.stdin.end();else f.child.stdin.write(frame({type:'shutdown'}));
    assert.equal((await f.done()).code,2);
  });
}
test('EPIPE on stderr retires with the runner failure code instead of an uncaught error',async t=>{
  const f=await start(t);await f.ready();f.child.stderr.destroy();await delay(20);f.invoke({count:2,bytes:256*1024});
  assert.equal((await f.done()).code,2);assert.equal(f.bad,null);
});
test('top-level diagnostics are bounded before user module initialization finishes',async t=>{
  const source=`const fs=require('node:fs');for(let i=0;i<256;i++)process.stderr.write(Buffer.alloc(262144));fs.writeFileSync(__dirname+'/completed','bad');module.exports={};`;
  const f=await start(t,source);f.child.stderr.pause();assert.equal((await f.done()).code,2);assert.equal(await f.marked('completed'),'');
  assert.equal(f.messages.some(m=>m.type==='hello'),false);
});
test('real 30-second diagnostic deadline retires a live runner with a stalled receiver',{timeout:40000},async t=>{
  const f=await start(t);await f.ready();f.child.stderr.pause();const started=Date.now();f.invoke({count:8,bytes:256*1024});
  await f.wait(()=>f.marked('completed'),'admitted');await f.wait(()=>f.messages.some(m=>m.type==='result'),'result');
  assert.equal((await f.done(35000)).code,2);const elapsed=Date.now()-started;assert.ok(elapsed>=29000&&elapsed<35000,`elapsed ${elapsed}`);
});
