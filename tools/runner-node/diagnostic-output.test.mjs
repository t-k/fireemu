import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Writable } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { DiagnosticWriter, installDiagnosticOutput, MAX_DIAGNOSTIC_BYTES,
  MAX_DIAGNOSTIC_WRITES, MAX_DIAGNOSTIC_WAIT_MS, DIAGNOSTIC_FINISH_MS } from './diagnostic-output.mjs';

class Sink extends EventEmitter {
  calls = []; returns = true; sync = false; destroyed = false; writableEnded = false;
  write(chunk, callback) {
    this.calls.push({ chunk, callback });
    if (this.sync) callback();
    return this.returns;
  }
  ack(index=0,error) { this.calls[index].callback(error); }
}
function setup(options={}) {
  const stream = new Sink(), failures=[];
  const writer = new DiagnosticWriter(stream,{onError:e=>failures.push(e),...options});
  return {stream,writer,failures};
}
const tick=()=>new Promise(resolve=>process.nextTick(resolve));

test('fixed local limits and idle finish are explicit', async()=>{
  assert.equal(MAX_DIAGNOSTIC_BYTES,8*1024*1024);assert.equal(MAX_DIAGNOSTIC_WRITES,1024);
  assert.equal(MAX_DIAGNOSTIC_WAIT_MS,30000);assert.equal(DIAGNOSTIC_FINISH_MS,1000);
  const f=setup({waitMs:15});await delay(25);assert.deepEqual(f.writer.state,{pendingBytes:0,pendingWrites:0,failed:false,closing:false});
  assert.equal(await f.writer.finish(),true);assert.equal(f.failures.length,0);
});
for (const field of ['maxBytes','maxWrites','waitMs','finishMs']) {
  for (const bad of [0,-1,NaN,Infinity,true,1.5,'1',Number.MAX_SAFE_INTEGER]) {
    test(`${field} refuses ${String(bad)}`,()=>assert.throws(()=>setup({[field]:bad}),TypeError));
  }
}

test('byte admission includes all native-buffered writes; exact limit is allowed',async()=>{
  const f=setup({maxBytes:8});assert.equal(f.writer.write('abcd'),true);assert.equal(f.writer.write('efgh'),false);
  assert.equal(f.writer.state.pendingBytes,8);assert.equal(f.writer.state.pendingWrites,2);
  assert.equal(f.writer.write('i'),false);assert.equal(f.stream.calls.length,2);assert.equal(f.failures.length,1);
  assert.equal(await f.writer.finish(),false);
});
test('empty chunks retain callback slots and cannot bypass the pending-write limit',async()=>{
  const f=setup({maxWrites:2});f.writer.write('');f.writer.write(Buffer.alloc(0));
  assert.equal(f.writer.state.pendingBytes,0);assert.equal(f.writer.write(''),false);
  assert.equal(f.stream.calls.length,2);assert.equal(await f.writer.finish(),false);
});
test('successful writes return slots repeatedly, not just once per process lifetime',async()=>{
  const f=setup({maxWrites:1,maxBytes:2});
  for(let n=0;n<100;n++){assert.equal(f.writer.write('ab'),false);f.stream.ack(n);}
  assert.equal(f.writer.state.pendingBytes,0);assert.equal(await f.writer.finish(),true);
});

test('native false is returned; data is neither dropped nor resent on drain',async()=>{
  const f=setup();f.stream.returns=false;
  assert.equal(f.writer.write('A'),false);assert.equal(f.writer.write('B'),false);
  f.stream.emit('drain');assert.equal(f.stream.calls.length,2);assert.equal(f.writer.state.pendingBytes,2);
  f.stream.ack(0);f.stream.ack(1);assert.equal(await f.writer.finish(),true);
  assert.equal(Buffer.concat(f.stream.calls.map(x=>x.chunk)).toString(),'AB');
});
test('Buffer and nonzero-offset views are private snapshots, including DataView',async()=>{
  for (const make of [b=>b.subarray(1,3), b=>new Uint16Array(b.buffer,b.byteOffset,2),b=>new DataView(b.buffer,b.byteOffset+1,2)]) {
    const f=setup();const original=Buffer.from([1,2,3,4]);const view=make(original);
    const expected=Buffer.from(new Uint8Array(view.buffer,view.byteOffset,view.byteLength));
    f.writer.write(view);original.fill(9);assert.deepEqual(f.stream.calls[0].chunk,expected);
    f.stream.ack();assert.equal(await f.writer.finish(),true);
  }
});
test('shadowed view properties cannot replace counted bytes or invoke accessors',async()=>{
  const f=setup({maxBytes:4});const data=new Uint8Array([1,2,3,4]);
  for(const key of ['buffer','byteOffset','byteLength'])Object.defineProperty(data,key,{get(){assert.fail('shadow getter called');}});
  assert.equal(f.writer.write(data),false);assert.equal(f.writer.state.pendingBytes,4);
  assert.deepEqual(f.stream.calls[0].chunk,Buffer.from([1,2,3,4]));f.stream.ack();assert.equal(await f.writer.finish(),true);
});
for(const [value,encoding,expected] of [ ['日本😀',undefined,Buffer.from('日本😀')],['e38182','hex',Buffer.from('あ')],['8J+YgA==','base64',Buffer.from('😀')],['AB','utf16le',Buffer.from('AB','utf16le')] ]) {
  test(`encoded ${encoding||'utf8'} bytes and callbacks match`,async()=>{
    const f=setup();let calls=0;f.writer.write(value,encoding,error=>{assert.equal(error,undefined);calls++;});
    assert.deepEqual(f.stream.calls[0].chunk,expected);assert.equal(f.writer.state.pendingBytes,expected.length);
    f.stream.ack();f.stream.ack();await tick();assert.equal(calls,1);assert.equal(await f.writer.finish(),true);
  });
}
for(const invalid of [null,1,true,{},[],new ArrayBuffer(3)]) {
  test(`unsupported chunk ${String(invalid)} is an ordinary synchronous type error`,async()=>{
    const f=setup();assert.throws(()=>f.writer.write(invalid),TypeError);assert.equal(f.failures.length,0);
    assert.equal(await f.writer.finish(),true);
  });
}
test('bad callback or encoding is rejected before admission; standard overloads work',async()=>{
  const f=setup();assert.throws(()=>f.writer.write('x','bad-encoding'),TypeError);assert.throws(()=>f.writer.write('x','utf8',7),TypeError);
  assert.equal(f.stream.calls.length,0);let count=0;f.writer.write('ok',()=>count++);f.stream.ack();await tick();
  assert.equal(count,1);assert.equal(await f.writer.finish(),true);
});
test('even an inline sink completes user callbacks asynchronously and once',async()=>{
  const f=setup();f.stream.sync=true;let done=0;f.writer.write('x',()=>done++);
  assert.equal(done,0);assert.equal(f.writer.state.pendingWrites,0);await tick();assert.equal(done,1);
  assert.equal(await f.writer.finish(),true);
});
for(const fault of ['throw','callback','error-event','close','finish','destroyed','ended','bad-return']) {
  test(`${fault} retires once, hides arbitrary error text and settles callbacks once`,async()=>{
    const f=setup();let calls=[];
    if(fault==='destroyed')f.stream.destroyed=true;
    if(fault==='ended')f.stream.writableEnded=true;
    if(fault==='bad-return')f.stream.returns=undefined;
    if(fault==='throw')f.stream.calls={push(){throw Error('PRIVATE_TOKEN');}};
    f.writer.write('secret',e=>calls.push(e));
    if(fault==='callback')f.stream.ack(0,Error('PRIVATE_TOKEN'));
    if(fault==='error-event')f.stream.emit('error',Error('PRIVATE_TOKEN'));
    if(fault==='close')f.stream.emit('close');if(fault==='finish')f.stream.emit('finish');
    await tick();assert.equal(f.failures.length,1);assert.equal(calls.length,1);assert.match(calls[0].message,/diagnostic/);
    assert.equal(calls[0].message.includes('PRIVATE_TOKEN'),false);
    assert.equal(f.writer.write('late'),false);f.stream.emit('error',Error('LATE_PRIVATE'));assert.equal(f.failures.length,1);
    assert.equal(await f.writer.finish(),false);
  });
}
test('earlier outstanding write keeps its original deadline despite later writes and drains',async()=>{
  const f=setup({waitMs:35});f.writer.write('A');await delay(20);f.writer.write('B');f.stream.ack(1);f.stream.emit('drain');
  await delay(25);assert.equal(f.failures.length,1);assert.equal(await f.writer.finish(),false);
});
test('late callback cannot beat a delayed timer and report delivery',async()=>{
  const f=setup({waitMs:15});let err;f.writer.write('x',e=>err=e);
  const stop=performance.now()+25;while(performance.now()<stop){};f.stream.ack();await tick();
  assert.match(err.message,/deadline/);assert.equal(f.failures.length,1);assert.equal(await f.writer.finish(),false);
});
test('a new write does not renew an expired outstanding write before timer dispatch',async()=>{
  const f=setup({waitMs:15});f.writer.write('x');const stop=performance.now()+25;while(performance.now()<stop){};
  assert.equal(f.writer.write('y'),false);assert.equal(f.stream.calls.length,1);assert.equal(await f.writer.finish(),false);
});
test('finish flushes only admitted bytes and does not end the original stream',async()=>{
  const f=setup();f.writer.write('x');const first=f.writer.finish();assert.equal(first,f.writer.finish());
  let rejected;assert.equal(f.writer.write('late',e=>rejected=e),false);await tick();assert.match(rejected.message,/closing/);
  f.stream.ack();assert.equal(await first,true);assert.equal(f.stream.writableEnded,false);assert.equal(f.stream.calls.length,1);
});
test('finish has a separate bounded tail and cannot refresh it by reentry',async()=>{
  const f=setup({finishMs:20});f.writer.write('x');const first=f.writer.finish();await delay(12);assert.equal(first,f.writer.finish());
  assert.equal(await first,false);assert.equal(f.failures.length,1);
});
test('installed real Writable preserves default encoding, cork and native drain',async()=>{
  const chunks=[],failures=[];let pending=[];
  const stream=new Writable({highWaterMark:2,write(chunk,enc,cb){chunks.push(Buffer.from(chunk));pending.push(cb);}});
  const writer=installDiagnosticOutput(stream,{onError:e=>failures.push(e)});let drains=0;stream.on('drain',()=>drains++);
  assert.equal(stream.setDefaultEncoding('hex'),stream);
  stream.cork();assert.equal(stream.write('6162'),false);assert.equal(stream.write(new Uint8Array([99])),false);assert.equal(chunks.length,0);
  stream.uncork();assert.equal(chunks.length,1);pending.shift()();assert.equal(chunks.length,2);pending.shift()();await tick();
  assert.equal(drains,1);assert.equal(Buffer.concat(chunks).toString(),'abc');assert.equal(await writer.finish(),true);assert.equal(failures.length,0);
});

// Regression: native Writable can return true for synchronous _write even though
// our completion callback is deferred. A compliant producer must get a chance
// to yield before those callback reservations exhaust the hard cap.
test('synchronous native completion adds logical backpressure and lets a cooperative producer continue', async t => {
  const chunks = [], failures = [];
  const stream = new Writable({ highWaterMark: 4, write(chunk, encoding, done) {
    chunks.push(Buffer.from(chunk)); done();
  } });
  const writer = installDiagnosticOutput(stream, { onError: e => failures.push(e), maxBytes: 8 });
  t.after(() => writer.finish());
  let drains = 0;
  stream.on('drain', () => { drains++; assert.equal(writer.state.pendingBytes, 0); });
  assert.equal(stream.write('abc'), true);
  assert.equal(stream.write('abc'), false);
  await new Promise(resolve => stream.once('drain', resolve));
  for (let i = 0; i < 28; i++) {
    if (!stream.write('abc')) await new Promise(resolve => stream.once('drain', resolve));
  }
  assert.equal(await writer.finish(), true);
  assert.equal(Buffer.concat(chunks).toString(), 'abc'.repeat(30));
  assert.equal(drains, 15); assert.deepEqual(failures, []);
});

test('empty synchronous writes produce a drain when only the callback-count budget is full', async t => {
  const failures = [];
  const stream = new Writable({ write(chunk, encoding, done) { done(); } });
  const writer = installDiagnosticOutput(stream, { onError: e => failures.push(e), maxWrites: 2 });
  t.after(() => writer.finish());
  let drains = 0; stream.on('drain', () => drains++);
  for (let i = 0; i < 5; i++) {
    assert.equal(stream.write(''), true);
    assert.equal(stream.write(''), false);
    await new Promise(resolve => stream.once('drain', resolve));
  }
  assert.equal(drains, 5); assert.equal(await writer.finish(), true); assert.deepEqual(failures, []);
});

for (const order of ['native-first', 'callback-first']) {
  test(`native drain and callback both gate the notification (${order})`, async t => {
    const f = setup(); f.stream.returns = false;
    t.after(async () => { f.stream.ack(); f.stream.emit('drain'); await f.writer.finish(); });
    let drains = 0; f.stream.on('drain', () => drains++);
    assert.equal(f.writer.write('abc'), false);
    if (order === 'native-first') f.stream.emit('drain'); else f.stream.ack();
    await tick(); assert.equal(drains, 0);
    if (order === 'native-first') f.stream.ack(); else f.stream.emit('drain');
    await tick(); assert.equal(drains, 1);
    f.stream.emit('drain'); f.stream.ack(); await tick(); assert.equal(drains, 1);
    assert.equal(await f.writer.finish(), true);
  });
}

test('a synchronous drain listener can write a full-cap chunk after native backpressure', async t => {
  const callbacks = [], failures = [];
  const stream = new Writable({ highWaterMark: 2, write(chunk, encoding, done) { callbacks.push(done); } });
  const writer = installDiagnosticOutput(stream, { onError: e => failures.push(e), maxBytes: 8 });
  t.after(() => { stream.destroy(); return writer.finish(); });
  assert.equal(stream.write('ab'), false);
  let resumed = false;
  stream.once('drain', () => {
    assert.equal(writer.state.pendingBytes, 0);
    assert.equal(stream.write('12345678'), false); resumed = true;
  });
  callbacks.shift()(); await tick(); assert.equal(resumed, true);
  callbacks.shift()(); await tick();
  assert.equal(await writer.finish(), true); assert.deepEqual(failures, []);
});

test('new data enqueued by a user callback postpones a scheduled logical drain', async t => {
  const f = setup({ maxBytes: 2 }); let drains = 0;
  t.after(() => { f.stream.emit('error', Error('fixture teardown')); return f.writer.finish(); });
  f.stream.on('drain', () => drains++);
  assert.equal(f.writer.write('ab', () => f.writer.write('cd')), false);
  f.stream.ack(0); await tick(); assert.equal(drains, 0);
  assert.equal(f.writer.state.pendingBytes, 2);
  f.stream.ack(1); await tick(); assert.equal(drains, 1);
  assert.equal(await f.writer.finish(), true);
});

test('closing or failing before a scheduled logical drain never signals new admission', async () => {
  for (const action of ['finish', 'error']) {
    const f = setup({ maxBytes: 2 }); let drains = 0;
    f.stream.on('drain', () => drains++);
    f.writer.write('ab'); f.stream.ack();
    if (action === 'finish') assert.equal(await f.writer.finish(), true);
    else f.stream.emit('error', Error('private'));
    await tick(); assert.equal(drains, 0);
    assert.equal(await f.writer.finish(), action === 'finish');
  }
});
