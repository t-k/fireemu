import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { FrameDecoder, MAX_FRAME_BYTES, ProtocolError, readFrames } from './protocol.mjs';
import { invocationFailure } from './invocation-error.mjs';

const message = {type:'invoke',invocationId:'a',function:'fn',entryPoint:'fn',trigger:'schedule',event:{data:{value:'日本語😀'}}};
function encode(value) {
  const body=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value));
  return Buffer.concat([Buffer.from(`${body.length}\n`),body]);
}

for(const width of [1,2,3,7,64,1024]) {
  test(`frames preserve Unicode and byte lengths in ${width}-byte chunks`,()=>{
    const values=[];const parser=new FrameDecoder(v=>values.push(v));
    const bytes=Buffer.concat([encode(message),encode({...message,invocationId:'b'}),encode({type:'shutdown'})]);
    for(let i=0;i<bytes.length;i+=width)parser.push(bytes.subarray(i,i+width));
    parser.end();assert.deepEqual(values,[message,{...message,invocationId:'b'},{type:'shutdown'}]);
  });
}

for(const header of ['','0','00','01','-1','+1',' 1','1 ','1\r','1x','1.5','1e2','0x10','16777217','999999999999999999999999','１２','\xff']) {
  test(`noncanonical or oversized header ${JSON.stringify(header)} is terminal`,()=>{
    let called=0;const parser=new FrameDecoder(()=>called++);
    assert.throws(()=>parser.push(Buffer.from(`${header}\n`)),ProtocolError);
    assert.throws(()=>parser.push(encode(message)),ProtocolError);
    assert.throws(()=>parser.end(),ProtocolError);assert.equal(called,0);
  });
}

test('header is bounded even without a newline',()=>{
  const parser=new FrameDecoder(()=>assert.fail('must not dispatch'));
  assert.throws(()=>parser.push(Buffer.from('1'.repeat(10000))),ProtocolError);
});

test('full 16 MiB frame is accepted, over-limit header is rejected before payload',()=>{
  const empty={...message,event:{data:''}};
  const overhead=Buffer.byteLength(JSON.stringify(empty));
  const msg={...empty,event:{data:'x'.repeat(MAX_FRAME_BYTES-overhead)}};
  const input=encode(msg);assert.equal(input.length,MAX_FRAME_BYTES+String(MAX_FRAME_BYTES).length+1);
  let count=0;const parser=new FrameDecoder(value=>{count++;assert.equal(value.event.data.length,MAX_FRAME_BYTES-overhead);});
  for(let i=0;i<input.length;i+=65536)parser.push(input.subarray(i,i+65536));
  parser.end();assert.equal(count,1);
});

for(const bytes of [Buffer.from('12'),Buffer.from('12\n'),Buffer.from('12\n{}')]) {
  test(`EOF rejects partial input ${JSON.stringify(bytes.toString())}`,()=>{
    const parser=new FrameDecoder(()=>assert.fail('must not dispatch'));
    parser.push(bytes);assert.throws(()=>parser.end(),/truncated/);
  });
}

test('clean empty EOF and EOF after a complete frame are accepted',()=>{
  const empty=new FrameDecoder(()=>{});empty.end();empty.end();
  const values=[];const parser=new FrameDecoder(v=>values.push(v));parser.push(encode(message));parser.end();assert.equal(values.length,1);
});

for(const value of [null,[],true,1,'invoke',{}, {type:'heartbeat'}, {...message,invocationId:''},{...message,function:3},{...message,entryPoint:null},{...message,trigger:''},{...message,event:[]}]) {
  test(`message envelope rejects ${JSON.stringify(value)}`,()=>{
    const parser=new FrameDecoder(()=>assert.fail('must not dispatch'));
    assert.throws(()=>parser.push(encode(value)),ProtocolError);
  });
}

for(const body of [Buffer.from('{'),Buffer.from('{"password":"NEVER_PRINT_ME",'),Buffer.from([0xff]),Buffer.concat([Buffer.from('{"type":"shutdown","value":"'),Buffer.from([0xff]),Buffer.from('"}')]),Buffer.from('\ufeff{"type":"shutdown"}')]) {
  test(`JSON decoding failure (${body.length} bytes) never echoes input`,()=>{
    const parser=new FrameDecoder(()=>assert.fail('must not dispatch'));
    assert.throws(()=>parser.push(encode(body)),e=>e instanceof ProtocolError&&!e.message.includes('NEVER_PRINT_ME'));
  });
}

test('payload remains private when caller reuses the partial chunk buffer',()=>{
  const values=[];const p=new FrameDecoder(v=>values.push(v));const bytes=encode(message);
  const prefix=Buffer.from(bytes.subarray(0,25));p.push(prefix);prefix.fill(0);p.push(bytes.subarray(25));p.end();assert.deepEqual(values,[message]);
});

test('stopping at shutdown does not dispatch the trailing frame',()=>{
  const values=[];const p=new FrameDecoder(v=>{values.push(v);return false;});
  p.push(Buffer.concat([encode({type:'shutdown'}),encode(message)]));p.end();assert.deepEqual(values,[{type:'shutdown'}]);
});

test('callback exception is terminal and later coalesced messages cannot run',()=>{
  let called=0;const p=new FrameDecoder(()=>{called++;throw Error('failure');});
  assert.throws(()=>p.push(Buffer.concat([encode(message),encode(message)])),/failure/);
  assert.equal(called,1);assert.throws(()=>p.push(encode(message)),ProtocolError);
});

test('stream error invokes only the failure path',()=>{
  const stream=new PassThrough();const result=[];
  readFrames(stream,()=>result.push('frame'),()=>result.push('end'),()=>result.push('error'));
  stream.emit('error',Error('private'));stream.emit('data',encode(message));stream.emit('end');stream.emit('close');
  assert.deepEqual(result,['error']);stream.destroy();
});

test('stream destroyed without EOF is not normal completion',()=>{
  const stream=new PassThrough();const result=[];
  readFrames(stream,()=>result.push('frame'),()=>result.push('end'),()=>result.push('error'));
  stream.emit('close');stream.emit('end');assert.deepEqual(result,['error']);stream.destroy();
});

test('truncated end cannot be followed by a normal completion callback',()=>{
  const stream=new PassThrough();const result=[];
  readFrames(stream,()=>result.push('frame'),()=>result.push('end'),()=>result.push('error'));
  stream.write(Buffer.from('123\n{}'));stream.emit('end');stream.emit('close');
  assert.deepEqual(result,['error']);stream.destroy();
});

test('normal streamed completion delivers frame and one end',()=>{
  const stream=new PassThrough();const result=[];
  readFrames(stream,()=>result.push('frame'),()=>result.push('end'),()=>result.push('error'));
  stream.write(encode(message));stream.emit('end');stream.emit('end');stream.emit('close');
  assert.deepEqual(result,['frame','end']);stream.destroy();
});

test('failure formatter snapshots each accessor once',()=>{
  let messages=0,stacks=0;
  const e={get message(){messages++;return 'original';},get stack(){stacks++;return 'stack';},toString(){throw Error('must not run');}};
  assert.deepEqual(invocationFailure(e),{message:'original',diagnostic:'stack'});assert.equal(messages,1);assert.equal(stacks,1);
});

test('failure formatter never invokes arbitrary stringification',()=>{
  const e={toString(){throw Error('must not run');},toJSON(){throw Error('must not run');}};
  assert.equal(invocationFailure(e).message,'Function invocation failed');
  const {proxy,revoke}=Proxy.revocable({},{});revoke();assert.equal(invocationFailure(proxy).message,'Function invocation failed');
});

test('failure results fit protocol strings and preserve normal errors',()=>{
  assert.equal(invocationFailure(new Error('normal')).message,'normal');
  assert.equal(invocationFailure('').message,'');
  const large=invocationFailure({message:'界'.repeat(10000),stack:'🙂'.repeat(100000)});
  assert.ok(Buffer.byteLength(large.message)<=4096);assert.ok(Buffer.byteLength(large.diagnostic)<=256*1024);
  assert.equal(large.message.isWellFormed(),true);assert.equal(large.diagnostic.isWellFormed(),true);
  assert.equal(invocationFailure(new Error('\ud800')).message,'�');
});
