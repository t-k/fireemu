import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Writable } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { FrameWriter, OutputError, MAX_PENDING_BYTES, MAX_PENDING_FRAMES, MAX_OUTPUT_WAIT_MS, OUTPUT_FINISH_MS } from './output.mjs';
import { MAX_FRAME_BYTES } from './protocol.mjs';

function decoded(buffer) {
  const newline=buffer.indexOf(10);
  assert.ok(newline>0);
  const length=Number(buffer.subarray(0,newline).toString('ascii'));
  assert.equal(length,buffer.length-newline-1);
  assert.ok(length<=MAX_FRAME_BYTES);
  return JSON.parse(buffer.subarray(newline+1).toString('utf8'));
}
class Sink extends EventEmitter {
  calls=[]; returns=false; callbacksSync=false;
  write(buffer, callback) {
    this.calls.push({buffer,callback});
    if(this.callbacksSync) callback();
    return this.returns;
  }
  ack(at=this.calls.length-1, error) { this.calls[at].callback(error); }
}
function setup(options={}) {
  const stream=new Sink(); const failures=[];
  const writer=new FrameWriter(stream,{...options,onError:error=>failures.push(error)});
  return {stream,writer,failures};
}
function finish(f) {
  for(let n=0;n<f.stream.calls.length;n++) {
    if(n>1000)assert.fail('unbounded retry');
    f.stream.ack(n); f.stream.emit('drain');
  }
  return f.writer.finish();
}

test('resource defaults are explicit finite local limits',()=>{
  assert.equal(MAX_PENDING_BYTES,32*1024*1024);assert.equal(MAX_PENDING_FRAMES,1024);
  assert.equal(MAX_OUTPUT_WAIT_MS,30000);assert.equal(OUTPUT_FINISH_MS,1000);
});
for(const [key,max] of [['maxBytes',MAX_PENDING_BYTES],['maxFrames',MAX_PENDING_FRAMES],['waitMs',MAX_OUTPUT_WAIT_MS],['finishMs',OUTPUT_FINISH_MS]]) {
  for(const value of [0,-1,true,1.5,NaN,Infinity,String(max),max+1]) {
    test(`rejects invalid ${key} ${String(value)} before adding stream listeners`,()=>{
      const stream=new Sink();assert.throws(()=>new FrameWriter(stream,{[key]:value,onError(){}}),TypeError);
      assert.equal(stream.eventNames().length,0);
    });
  }
}
test('requires a writable stream and a terminal error handler',()=>{
  assert.throws(()=>new FrameWriter(new Sink()),TypeError);
  assert.throws(()=>new FrameWriter(null,{onError(){}}),TypeError);
});

test('one complete UTF8 frame per write and no duplicate resend after drain',async()=>{
  const f=setup();const values=[{type:'hello',value:'日本語😀'},{type:'log',message:'次'},{type:'result',ok:true}];
  for(const value of values)assert.equal(f.writer.send(value),true);
  assert.equal(f.stream.calls.length,1);assert.equal(f.writer.state.pendingFrames,3);
  // drain alone is not completion of the outstanding write.
  f.stream.emit('drain');assert.equal(f.stream.calls.length,1);
  f.stream.ack(0);assert.equal(f.stream.calls.length,2);
  // callback alone does not allow bypassing a false write's drain signal.
  f.stream.ack(1);assert.equal(f.stream.calls.length,2);
  f.stream.emit('drain');assert.equal(f.stream.calls.length,3);
  f.stream.ack(2);f.stream.emit('drain');
  assert.deepEqual(f.stream.calls.map(call=>decoded(call.buffer)),values);
  assert.equal(f.writer.state.pendingBytes,0);assert.equal(await f.writer.finish(),true);
  assert.deepEqual(f.failures,[]);
});

test('true return is still pending until its write callback completes',async()=>{
  const f=setup();f.stream.returns=true;
  f.writer.send({id:1});f.writer.send({id:2});
  assert.equal(f.stream.calls.length,1);assert.equal(f.writer.state.pendingFrames,2);
  f.stream.ack(0);assert.equal(f.stream.calls.length,2);f.stream.ack(1);
  assert.equal(await f.writer.finish(),true);assert.equal(f.writer.state.pendingFrames,0);
});

test('synchronous callbacks are supported without recursive pumping or missed counters',async()=>{
  const f=setup();f.stream.returns=true;f.stream.callbacksSync=true;
  for(let n=0;n<2000;n++)assert.equal(f.writer.send({n}),true);
  assert.equal(f.stream.calls.length,2000);assert.equal(f.writer.state.pendingFrames,0);
  assert.equal(await f.writer.finish(),true);
});

test('the original write is captured before user stdout redirection',async()=>{
  const f=setup();f.stream.write=()=>assert.fail('redirected write');
  f.writer.send({ok:true});assert.equal(await finish(f),true);
  assert.deepEqual(decoded(f.stream.calls[0].buffer),{ok:true});
});

test('queued JSON is a private snapshot, evaluated only once',async()=>{
  const f=setup();f.writer.send({block:true});
  let reads=0;const state={get value(){reads++;return 'original';}};
  f.writer.send({toJSON(){return state;}});Object.defineProperty(state,'value',{value:'changed'});
  assert.equal(await finish(f),true);assert.equal(reads,1);
  assert.deepEqual(decoded(f.stream.calls[1].buffer),{value:'original'});
});

test('same-frame serialization reentrancy retires without emitting either frame',()=>{
  const f=setup();assert.equal(f.writer.send({toJSON(){f.writer.send({nested:true});return {outer:true};}}),false);
  assert.equal(f.stream.calls.length,0);assert.equal(f.failures.length,1);
  assert.match(f.failures[0].message,/reentrant/);
});

for(const [label,value] of [['undefined',undefined],['null',null],['array',[]],['scalar',5],['BigInt',{secret:1n}],['cycle',(()=>{const x={};x.x=x;return x;})()],['throwing getter',{get secret(){throw Error('DO_NOT_ECHO');}}],['scalar toJSON',{toJSON(){return 'secret';}}]]) {
  test(`serialization failure (${label}) cannot publish a header or leak content`,async()=>{
    const f=setup();assert.equal(f.writer.send(value),false);assert.equal(f.stream.calls.length,0);
    assert.equal(f.failures.length,1);assert.ok(f.failures[0] instanceof OutputError);
    assert.equal(f.failures[0].message.includes('DO_NOT_ECHO'),false);
    assert.equal(await f.writer.finish(),false);
  });
}

test('outbound 16MiB is allowed and 16MiB+1 fails before any part is written',async()=>{
  const overhead=Buffer.byteLength(JSON.stringify({data:''}));
  const at=setup();at.writer.send({data:'a'.repeat(MAX_FRAME_BYTES-overhead)});
  assert.equal(decoded(at.stream.calls[0].buffer).data.length,MAX_FRAME_BYTES-overhead);
  assert.equal(await finish(at),true);
  const over=setup();assert.equal(over.writer.send({data:'a'.repeat(MAX_FRAME_BYTES-overhead+1)}),false);
  assert.equal(over.stream.calls.length,0);assert.match(over.failures[0].message,/too large/);
});

test('frame count includes both the outstanding write and queued frames',async()=>{
  const f=setup({maxFrames:3});for(let n=0;n<3;n++)assert.equal(f.writer.send({n}),true);
  assert.equal(f.writer.state.pendingFrames,3);assert.equal(f.stream.calls.length,1);
  assert.equal(f.writer.send({n:3}),false);assert.match(f.failures[0].message,/frame queue limit/);
  assert.equal(await f.writer.finish(),false);
});

test('byte cap includes prefix and in-flight data; exact cap is accepted',async()=>{
  const msg={data:'abc'};const len=Buffer.byteLength(JSON.stringify(msg));const frame=Buffer.byteLength(`${len}\n`)+len;
  const f=setup({maxBytes:frame*2});assert.equal(f.writer.send(msg),true);assert.equal(f.writer.send(msg),true);
  assert.equal(f.writer.state.pendingBytes,frame*2);assert.equal(f.writer.send(msg),false);
  assert.equal(f.stream.calls.length,1);assert.match(f.failures[0].message,/byte queue limit/);
  assert.equal(await f.writer.finish(),false);
});

test('queue limits do not throttle lifetime totals after confirmed writes',async()=>{
  const f=setup({maxFrames:1});f.writer.send({id:1});f.stream.ack();f.stream.emit('drain');
  assert.equal(f.writer.send({id:2}),true);f.stream.ack();f.stream.emit('drain');
  assert.equal(await f.writer.finish(),true);assert.equal(f.failures.length,0);
});

for(const fault of ['throw','callback','error-event','close','finish','destroyed','ended','bad-return']) {
  test(`${fault} latches a single private diagnostic and accepts no more messages`,async()=>{
    const f=setup();
    if(fault==='throw')f.stream.write=undefined; // captured write is tested separately below
    if(fault==='destroyed')f.stream.destroyed=true;
    if(fault==='ended')f.stream.writableEnded=true;
    if(fault==='bad-return')f.stream.returns=undefined;
    if(fault==='throw') { f.stream.calls={push(){throw Error('PRIVATE');}}; }
    f.writer.send({id:1});
    if(fault==='callback')f.stream.ack(0,Error('PRIVATE'));
    if(fault==='error-event')f.stream.emit('error',Error('PRIVATE'));
    if(fault==='close')f.stream.emit('close');
    if(fault==='finish')f.stream.emit('finish');
    assert.equal(f.writer.state.failed,true);assert.equal(f.failures.length,1);
    f.stream.emit('error',Error('LATE_PRIVATE'));f.stream.emit('close');f.stream.emit('drain');
    assert.equal(f.writer.send({get secret(){assert.fail('must not evaluate after failure');}}),false);
    assert.equal(f.failures.length,1);assert.equal(f.failures[0].message.includes('PRIVATE'),false);
    assert.equal(await f.writer.finish(),false);
  });
}

test('idle output has no pending deadline',async()=>{
  const f=setup({waitMs:20});await delay(35);assert.equal(f.failures.length,0);assert.equal(await f.writer.finish(),true);
});
for(const phase of ['write-callback','drain','queued','closing']) {
  test(`deadline covers missing ${phase} without being renewed by more frames`,async()=>{
    const f=setup({waitMs:45,finishMs:20});
    f.writer.send({n:0});
    if(phase==='drain')f.stream.ack(0);
    if(phase==='queued') { await delay(20);f.writer.send({n:1}); }
    const finished=phase==='closing'?f.writer.finish():null;
    await delay(70);assert.equal(f.failures.length,1);assert.match(f.failures[0].message,/deadline/);
    if(finished)assert.equal(await finished,false);
    f.stream.emit('drain');assert.equal(f.stream.calls.length,1);
  });
}

test('expired write callback cannot win a race with the event-loop timer',()=>{
  const f=setup({waitMs:10});f.writer.send({ok:true});
  const until=performance.now()+20;while(performance.now()<until){};
  f.stream.ack();assert.equal(f.writer.state.failed,true);assert.match(f.failures[0].message,/deadline/);
});

test('finish is idempotent, flushes only admitted output, and never ends stdout',async()=>{
  const f=setup();f.stream.end=()=>assert.fail('must not end stdout');
  f.writer.send({a:1});f.writer.send({a:2});const ending=f.writer.finish();assert.equal(f.writer.finish(),ending);
  assert.equal(f.writer.send({get forbidden(){assert.fail('send after finish');}}),false);
  assert.equal(await finish(f),true);assert.equal(f.stream.calls.length,2);assert.equal(await ending,true);
});

test('actual Writable low highWaterMark preserves all frames through repeated drain events',async()=>{
  const chunks=[];
  const stream=new Writable({highWaterMark:1,write(chunk,_encoding,cb){chunks.push(Buffer.from(chunk));setTimeout(cb,1);}});
  const failures=[];const writer=new FrameWriter(stream,{onError:e=>failures.push(e)});
  for(let n=0;n<100;n++)assert.equal(writer.send({n,unicode:'日本語😀'}),true);
  assert.equal(await writer.finish(),true);assert.deepEqual(failures,[]);
  assert.deepEqual(chunks.map(decoded),Array.from({length:100},(_,n)=>({n,unicode:'日本語😀'})));
});

test('actual Writable errors do not produce unhandled stream errors',async()=>{
  const failures=[];const stream=new Writable({write(_chunk,_encoding,cb){cb(Error('SECRET'));}});
  const writer=new FrameWriter(stream,{onError:e=>failures.push(e)});writer.send({data:'private'});
  assert.equal(await writer.finish(),false);await delay(5);assert.equal(failures.length,1);
});

test('expired sub-highWaterMark callback cannot erase the last outstanding deadline',()=>{
  const f=setup({waitMs:10});f.stream.returns=true;f.writer.send({ok:true});
  // The stream never asks for drain here: only the per-write deadline can stop
  // a delayed callback from removing the last pending frame as a success.
  const until=performance.now()+20;while(performance.now()<until){};
  f.stream.ack();assert.equal(f.writer.state.failed,true);assert.match(f.failures[0].message,/deadline/);
});
