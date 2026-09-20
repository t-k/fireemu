// Receiver-local safety contracts, with deterministic monotonic-clock unit tests.
// These are not Firebase quotas, producer authentication or native/SDK evidence.
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import {
  FrameDecoder, InvocationBudget, ProtocolError, readFrames,
  MAX_FRAME_BYTES, MAX_INPUT_FRAME_WAIT_MS,
  MAX_ACTIVE_INVOCATIONS, MAX_ACTIVE_INVOCATION_BYTES,
} from './protocol.mjs';

const msg = { type:'invoke', invocationId:'one', function:'task', trigger:'schedule',
  event:{data:{value:'日本語😀'}} };
const payload = Buffer.from(JSON.stringify(msg));
const header = Buffer.from(`${payload.length}\n`);
const frame = Buffer.concat([header,payload]);
const shutdown = Buffer.from('19\n{"type":"shutdown"}');

for (const value of [0,-1,0.5,NaN,Infinity,30_001,'30',true,null]) {
  test(`input duration rejects ${String(value)} instead of widening/rounding`, () => {
    assert.throws(() => new FrameDecoder(()=>{}, { frameWaitMs:value }), TypeError);
  });
}

test('idle decoder has no receive deadline and does not read an unused clock', () => {
  const p=new FrameDecoder(()=>assert.fail('no frames'), { now(){throw Error('unused');} });
  assert.equal(p.remainingTime(),null);p.push(Buffer.alloc(0));p.end();
  assert.equal(p.remainingTime(),null);
});

for (const prefix of [Buffer.from(String(payload.length).slice(0,1)), header,
                     Buffer.concat([header,payload.subarray(0,5)])]) {
  test(`partial input (${prefix.length} bytes) expires at the original boundary`, () => {
    let now=100;let called=0;
    const p=new FrameDecoder(()=>called++, {frameWaitMs:50,now:()=>now});
    p.push(prefix);now=125;assert.equal(p.remainingTime(),25);
    now=150;assert.throws(()=>p.remainingTime(),/input frame deadline/);
    now=126;assert.throws(()=>p.push(frame),/closed/);assert.equal(called,0);
  });
}

test('header completion, body progress and empty chunks do not renew time', () => {
  let now=0;const seen=[];
  const p=new FrameDecoder(v=>seen.push(v), {frameWaitMs:100,now:()=>now});
  p.push(header.subarray(0,1));now=40;p.push(header.subarray(1));
  now=70;p.push(payload.subarray(0,4));now=99;p.push(Buffer.alloc(0));
  assert.equal(p.remainingTime(),1);now=100;
  assert.throws(()=>p.push(payload.subarray(4)),/input frame deadline/);
  assert.deepEqual(seen,[]);
});

test('a complete frame before the deadline disarms and the next frame gets its own time', () => {
  let now=0;const seen=[];
  const p=new FrameDecoder((v,n)=>seen.push([v,n]),{frameWaitMs:100,now:()=>now});
  p.push(header);now=99;p.push(payload);assert.equal(p.remainingTime(),null);
  now=10_000;assert.equal(p.remainingTime(),null);p.push(header);now=10_099;p.push(payload);
  assert.deepEqual(seen,[[msg,payload.length],[msg,payload.length]]);
  p.end();assert.equal(p.remainingTime(),null);
});

test('late complete body is rejected even if the timer callback has not run', () => {
  let now=0;let calls=0;
  const p=new FrameDecoder(()=>calls++,{frameWaitMs:100,now:()=>now});
  p.push(header);now=101;
  assert.throws(()=>p.push(payload),/input frame deadline/);assert.equal(calls,0);
});

test('time is rechecked after JSON decoding, before the callback', () => {
  let reads=0,expireAt=Infinity,calls=0;
  const p=new FrameDecoder(()=>calls++,{frameWaitMs:100,now:()=>++reads>=expireAt?100:0});
  p.push(header);expireAt=reads+3; // arrival, pre-copy, post-decode
  assert.throws(()=>p.push(payload),/input frame deadline/);assert.equal(calls,0);
});

test('coalesced trailing frame cannot renew time spent in a synchronous callback', () => {
  let now=0;let called=0;
  const p=new FrameDecoder(()=>{called++;now=100;},{frameWaitMs:100,now:()=>now});
  assert.throws(()=>p.push(Buffer.concat([frame,frame])),/input frame deadline/);
  assert.equal(called,1);
});

test('a later chunk starts a fresh deadline, not the previous callback start time', () => {
  let now=0;let called=0;
  const p=new FrameDecoder(()=>{called++;now+=100;},{frameWaitMs:100,now:()=>now});
  p.push(frame);p.push(frame);p.end();assert.equal(called,2);
});

for (const bad of [NaN,Infinity,-1,true,'100',null,Number.MAX_VALUE]) {
  test(`invalid/overflow clock ${String(bad)} cannot admit a frame`, () => {
    let called=0;const p=new FrameDecoder(()=>called++,{now:()=>bad});
    assert.throws(()=>p.push(frame),ProtocolError);assert.equal(called,0);
    assert.throws(()=>p.push(frame),/closed/);
  });
}

test('clock exception is fixed, private and terminal', () => {
  let broken=false;
  const p=new FrameDecoder(()=>assert.fail('no callback'),{now(){if(broken)throw Error('PRIVATE');return 100;}});
  p.push(header);broken=true;assert.throws(()=>p.remainingTime(),e=>e.message==='invalid runner frame (input clock)');
  broken=false;assert.throws(()=>p.push(payload),/closed/);
});

test('a backwards clock is a permanent failure', () => {
  let now=100;
  const p=new FrameDecoder(()=>assert.fail('no callback'),{now:()=>now});p.push(header);
  now=99;assert.throws(()=>p.push(payload),/input clock/);
  now=101;assert.throws(()=>p.push(payload),/closed/);
});

test('framed byte accounting uses actual Unicode bytes including JSON whitespace', () => {
  const body=Buffer.from(JSON.stringify({...msg,payloadBytes:1},null,4));
  const seen=[];const p=new FrameDecoder((v,n)=>seen.push([v,n]));
  const all=Buffer.concat([Buffer.from(`${body.length}\n`),body]);
  for(let i=0;i<all.length;i+=3)p.push(all.subarray(i,i+3));p.end();
  assert.equal(seen.length,1);assert.equal(seen[0][1],body.length);
  assert.notEqual(body.length,JSON.stringify(seen[0][0]).length);
});

test('shutdown stops trailing bytes and drops its frame deadline', () => {
  let now=0;let called=0;
  const p=new FrameDecoder(()=>{called++;now=10_000;return false;},{frameWaitMs:10,now:()=>now});
  p.push(Buffer.concat([shutdown,header]));assert.equal(p.remainingTime(),null);
  p.push(payload);p.end();assert.equal(called,1);
});

for (const kind of ['partial-header','partial-body']) {
  test(`stream timer expires ${kind} once without EOF`, async t => {
    const input=new PassThrough();t.after(()=>input.destroy());const events=[];
    readFrames(input,()=>events.push('frame'),()=>events.push('end'),e=>events.push(e.message),{frameWaitMs:25});
    input.write(kind==='partial-header'?header.subarray(0,1):header);
    await delay(80);assert.deepEqual(events,['invalid runner frame (input frame deadline)']);
    input.emit('data',frame);input.emit('end');input.emit('close');input.emit('error',Error('late'));
    assert.equal(events.length,1);assert.equal(input.isPaused(),true);
  });
}

test('idle input and idle time after a complete frame do not terminate a runner', async t => {
  const input=new PassThrough();t.after(()=>input.destroy());const events=[];
  readFrames(input,(_,n)=>events.push(n),()=>events.push('end'),()=>events.push('error'),{frameWaitMs:15});
  await delay(50);assert.deepEqual(events,[]);input.write(frame);
  await delay(50);assert.deepEqual(events,[payload.length]);input.end();
  await delay(5);assert.deepEqual(events,[payload.length,'end']);
});

for (const reason of ['end','error','close','shutdown']) {
  test(`${reason} cancels the receive timer and cannot emit a later failure`, async t => {
    const input=new PassThrough();t.after(()=>input.destroy());const events=[];
    readFrames(input,v=>{events.push(v.type);return false;},()=>events.push('end'),e=>events.push(e.message),{frameWaitMs:20});
    input.write(reason==='shutdown'?shutdown:header);
    if(reason!=='shutdown')input.emit(reason,...(reason==='error'?[Error('private')]:[]));
    const before=[...events];await delay(70);assert.deepEqual(events,before);assert.equal(events.length,1);
    if(reason==='shutdown')assert.deepEqual(events,['shutdown']);
    else assert.match(events[0],/invalid runner frame/);
  });
}

test('a late data event cannot race a delayed stream timer into dispatch', async t => {
  const input=new PassThrough();t.after(()=>input.destroy());const events=[];
  readFrames(input,()=>events.push('frame'),()=>events.push('end'),e=>events.push(e.message),{frameWaitMs:15});
  input.write(header);
  const stop=performance.now()+30;while(performance.now()<stop){} // deliberately delay event-loop delivery
  input.emit('data',payload);
  assert.deepEqual(events,['invalid runner frame (input frame deadline)']);
  await delay(20);assert.equal(events.length,1);
});

test('receiver default policies are fixed, positive local limits', () => {
  assert.equal(MAX_INPUT_FRAME_WAIT_MS,30_000);
  assert.equal(MAX_ACTIVE_INVOCATIONS,4096);
  assert.equal(MAX_ACTIVE_INVOCATION_BYTES,64*1024*1024);
});

for (const name of ['maxCount','maxBytes']) for(const bad of [0,-1,1.5,NaN,Infinity,'1',true,null,Number.MAX_SAFE_INTEGER]) {
  test(`${name} rejects ${String(bad)}`,()=>assert.throws(()=>new InvocationBudget({[name]:bad}),TypeError));
}

for (const id of ['',1,true,null,{},[]]) {
  test(`invocation ID type ${JSON.stringify(id)} is rejected before counting`,()=>{
    const b=new InvocationBudget();assert.throws(()=>b.reserve(id,1),/invocation accounting/);
    assert.deepEqual(b.state,{count:0,payloadBytes:0,failed:true});
  });
}
for (const size of [0,-1,1.5,NaN,Infinity,'1',true,MAX_FRAME_BYTES+1]) {
  test(`payload count ${String(size)} is rejected before counting`,()=>{
    const b=new InvocationBudget();assert.throws(()=>b.reserve('one',size),/invocation accounting/);
    assert.deepEqual(b.state,{count:0,payloadBytes:0,failed:true});
  });
}

test('exact count limit succeeds; next request is not admitted; release cannot clear a failure', () => {
  const b=new InvocationBudget({maxCount:2});const a=b.reserve('a',1),c=b.reserve('c',2);
  assert.deepEqual(b.state,{count:2,payloadBytes:3,failed:false});
  assert.throws(()=>b.reserve('extra',1),/active invocation count/);
  assert.deepEqual(b.state,{count:2,payloadBytes:3,failed:true});
  a();c();assert.deepEqual(b.state,{count:0,payloadBytes:0,failed:true});
  assert.throws(()=>b.reserve('new',1),/closed/);
});

test('exact byte cap succeeds and one byte over does not leak an extra admission', () => {
  const b=new InvocationBudget({maxBytes:10});b.reserve('a',4);b.reserve('b',6);
  assert.deepEqual(b.state,{count:2,payloadBytes:10,failed:false});
  assert.throws(()=>b.reserve('c',1),/active invocation bytes/);
  assert.deepEqual(b.state,{count:2,payloadBytes:10,failed:true});
});

test('release is idempotent and an old lease cannot release a reused ID', () => {
  const b=new InvocationBudget({maxBytes:10,maxCount:1});const first=b.reserve('same',10);
  first();first();const second=b.reserve('same',10);first();
  assert.deepEqual(b.state,{count:1,payloadBytes:10,failed:false});
  second();assert.deepEqual(b.state,{count:0,payloadBytes:0,failed:false});
});

test('duplicate IDs fail closed without replacing or doubling their original charge', () => {
  const b=new InvocationBudget();const release=b.reserve('same',10);
  assert.throws(()=>b.reserve('same',20),/duplicate active invocation/);
  assert.deepEqual(b.state,{count:1,payloadBytes:10,failed:true});release();
  assert.deepEqual(b.state,{count:0,payloadBytes:0,failed:true});
});

test('multiple leases release out of order and preserve unrelated charges', () => {
  const b=new InvocationBudget();const a=b.reserve('a',10),c=b.reserve('c',30),d=b.reserve('d',20);
  c();assert.equal(b.state.payloadBytes,30);a();assert.equal(b.state.payloadBytes,20);
  d();assert.deepEqual(b.state,{count:0,payloadBytes:0,failed:false});
});

test('state is a detached immutable count-only snapshot', () => {
  const b=new InvocationBudget();const before=b.state;const release=b.reserve('PRIVATE-ID',7);
  assert.equal(Object.isFrozen(before),true);assert.equal(JSON.stringify(b.state).includes('PRIVATE'),false);
  assert.throws(()=>{before.count=100;},TypeError);release();
  assert.deepEqual(before,{count:0,payloadBytes:0,failed:false});
});

test('maximum frame length is valid and active bytes count the full frame body', () => {
  const b=new InvocationBudget();const leases=[];
  for(let i=0;i<4;i++)leases.push(b.reserve(String(i),MAX_FRAME_BYTES));
  assert.equal(b.state.payloadBytes,MAX_ACTIVE_INVOCATION_BYTES);
  leases[2]();leases[2]=b.reserve('replacement',MAX_FRAME_BYTES);
  for(const done of leases)done();assert.equal(b.state.payloadBytes,0);
});
