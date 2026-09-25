import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { createHttpAdmission, HTTP_ADMISSION_LIMITS } from './http-admission.mjs';

const secret = 'test-capability';
function request(headers = {}) {
  return {headers:{'x-fireemu-runner-secret':secret,...headers},rawHeaders:['X-Fireemu-Runner-Secret',secret]};
}
function response() {
  const res = Object.assign(new EventEmitter(), {destroyed:false,writableEnded:false,writableFinished:false,headersSent:false,headers:{},continueCount:0});
  res.setHeader=(k,v)=>res.headers[k]=v;
  res.writeContinue=()=>res.continueCount++;
  res.end=body=>{res.body=body;res.writableEnded=true;res.writableFinished=true;res.emit('finish');};
  res.destroy=()=>{res.destroyed=true;res.emit('close');};
  return res;
}
function budget(limits={requests:2,bytes:10,bodyBytes:6}) {return createHttpAdmission({secret,limits});}
function enter(b,headers={},expect=false,callback=()=>{}) {
 const req=request(headers),res=response();let entered=false;
 b.handle(req,res,(q,s)=>{entered=true;callback(q,s);},expect);
 return {req,res,get entered(){return entered;}};
}
for(const value of [undefined,'','wrong',false,1,[],[secret],`${secret}, ${secret}`]) {
 test(`reject invalid capability before parser or 100 Continue: ${JSON.stringify(value)}`,()=>{
  const b=budget();const f=enter(b,{'x-fireemu-runner-secret':value,'content-length':'999999'},true,()=>assert.fail('parsed'));
  assert.equal(f.res.statusCode,403);assert.equal(f.res.continueCount,0);assert.equal(f.entered,false);assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
 });
}
for(const [key,val,status] of [['content-length','-1',400],['content-length','1x',400],['content-length',1,400],['content-length','',400],['content-length','7',413],['content-length','9999999999999999999999',413]]) {
 test(`reject bad/large ${key} ${JSON.stringify(val)} before parse`,()=>{const b=budget(),f=enter(b,{[key]:val},true);assert.equal(f.res.statusCode,status);assert.equal(f.res.continueCount,0);assert.equal(f.entered,false);assert.deepEqual(b.snapshot(),{requests:0,bytes:0});});
}
test('missing configuration and stopping runner reject before parse',()=>{
 for(const options of [{secret:''},{secret,isStopping:()=>true}]) {const b=createHttpAdmission(options);const f=enter(b,{},true);assert.equal(f.res.statusCode,options.secret?503:500);assert.equal(f.res.continueCount,0);assert.equal(f.entered,false);}
});
test('strip capability from normal and raw headers before invoking parser',()=>{
 const b=budget(),f=enter(b,{},true,(req,res)=>{assert.equal(req.headers['x-fireemu-runner-secret'],undefined);assert.deepEqual(req.rawHeaders,[]);assert.equal(res.continueCount,1);});
 assert.equal(f.entered,true);f.res.end('ok');assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
});
test('max request count is reserved before any parsing, with no queued overload',()=>{
 const b=budget(),a=enter(b),c=enter(b),d=enter(b,{},true);assert.equal(d.entered,false);assert.equal(d.res.statusCode,503);assert.equal(d.res.continueCount,0);
 a.res.end('a');const e=enter(b);assert.equal(e.entered,true);c.res.destroy();e.res.end('b');assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
});
test('Content-Length reserves bytes before reading the body',()=>{
 const b=budget(),a=enter(b,{'content-length':'6'}),c=enter(b,{'content-length':'4'}),d=enter(b,{'content-length':'1'},true);
 assert.equal(a.entered,true);assert.equal(c.entered,true);assert.equal(d.entered,false);assert.deepEqual(b.snapshot(),{requests:2,bytes:10});a.res.destroy();c.res.destroy();
});
for(const headers of [{'transfer-encoding':'chunked'},{'content-encoding':'gzip','content-length':'1'},{'content-encoding':'deflate','content-length':'2'},{'content-encoding':'br','content-length':'1'}]) {
 test(`unknown decoded size reserves full body limit then shrinks: ${JSON.stringify(headers)}`,()=>{
  const b=budget(),a=enter(b,headers);assert.deepEqual(b.snapshot(),{requests:1,bytes:6});
  const reject=enter(b,{'content-length':'5'});assert.equal(reject.res.statusCode,503);
  b.verify(a.req,a.res,Buffer.from('ok'));assert.deepEqual(b.snapshot(),{requests:1,bytes:2});
  const c=enter(b,{'content-length':'6'});assert.equal(c.entered,true);a.res.end('');c.res.end('');assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
 });
}
test('ambiguous length/transfer framing is rejected without reserving',()=>{const b=budget(),f=enter(b,{'content-length':'1','transfer-encoding':'chunked'});assert.equal(f.res.statusCode,400);assert.deepEqual(b.snapshot(),{requests:0,bytes:0});});
for(const terminal of ['close','finish','error']) {
 test(`queued/active Promise retains capacity after response ${terminal}`,()=>{
  const b=budget(),a=enter(b,{'content-length':'6'}),complete=b.begin(a.req);assert.equal(typeof complete,'function');a.res.emit(terminal);
  assert.deepEqual(b.snapshot(),{requests:1,bytes:6});assert.equal(enter(b,{'content-length':'5'}).res.statusCode,503);
  complete();complete();assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
  const c=enter(b,{'content-length':'6'});complete();assert.deepEqual(b.snapshot(),{requests:1,bytes:6});c.res.destroy();
 });
 test(`parser/404 failure response ${terminal} returns non-dispatched lease`,()=>{
  const b=budget(),f=enter(b,{'content-length':'6'});f.res.emit(terminal);assert.deepEqual(b.snapshot(),{requests:0,bytes:0});assert.equal(b.begin(f.req),null);
 });
}
test('Promise settlement before response end does not return capacity',()=>{
 const b=budget(),f=enter(b,{'content-length':'6'}),done=b.begin(f.req);done();assert.deepEqual(b.snapshot(),{requests:1,bytes:6});f.res.end('');assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
});
test('skip already closed requests, double dispatch, and duplicate begin',()=>{
 const b=budget(),f=enter(b);const complete=b.begin(f.req);assert.equal(b.begin(f.req),null);f.res.destroy();complete();assert.equal(b.begin(f.req),null);
 const req=request(),res=response();res.destroyed=true;let called=false;b.handle(req,res,()=>called=true);assert.equal(called,false);assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
});
test('unadmitted/closed or oversized decoded buffers cannot reach callback',()=>{
 const b=budget(),f=enter(b,{'content-length':'3'});for(const value of [null,'abc',Buffer.alloc(4)]) assert.throws(()=>b.verify(f.req,f.res,value));
 assert.throws(()=>b.verify(request(),response(),Buffer.alloc(0)));assert.deepEqual(b.snapshot(),{requests:1,bytes:3});f.res.destroy();assert.throws(()=>b.verify(f.req,f.res,Buffer.alloc(1)));
});
test('verify cannot mutate accounting after callback starts',()=>{
 const b=budget(),f=enter(b,{'content-length':'3'}),done=b.begin(f.req);assert.throws(()=>b.verify(f.req,f.res,Buffer.alloc(0)));assert.deepEqual(b.snapshot(),{requests:1,bytes:3});f.res.end('');done();
});
test('synchronous parser failure returns response and capacity',()=>{
 const b=budget(),f=enter(b,{'content-length':'4'},false,()=>{throw Error('do not publish secret');});assert.equal(f.res.statusCode,500);assert.equal(f.res.body,'internal error');assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
});
test('synchronous parser failure after headers destroys response',()=>{
 const b=budget(),f=enter(b,{},false,(_q,r)=>{r.headersSent=true;throw Error('secret');});assert.equal(f.res.destroyed,true);assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
});
test('closed flags are rechecked before enqueue, without waiting for missing event',()=>{
 const b=budget(),f=enter(b,{'content-length':'2'});f.res.destroyed=true;assert.equal(b.begin(f.req),null);assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
});
test('listener cleanup preserves unrelated listeners and no lifetime quota',()=>{
 const b=budget();for(let i=0;i<1100;i++){const f=enter(b,{'content-length':'1'});let calls=0;const external=()=>calls++;f.res.on('finish',external);const done=b.begin(f.req);f.res.end('');done();assert.equal(calls,1);assert.deepEqual(f.res.listeners('finish'),[external]);for(const k of ['close','error'])assert.equal(f.res.listenerCount(k),0);}
 assert.deepEqual(b.snapshot(),{requests:0,bytes:0});
});
test('limits are copied, snapshot is frozen, and configuration validates',()=>{
 const limits={requests:1,bytes:6,bodyBytes:6},b=budget(limits);limits.requests=100;limits.bytes=100;const f=enter(b);assert.equal(enter(b).res.statusCode,503);assert.ok(Object.isFrozen(b.snapshot()));f.res.end('');
 for(const v of [0,-1,true,1.5,NaN,Infinity,'2'])assert.throws(()=>budget({requests:v,bytes:10,bodyBytes:6}));
 assert.ok(Object.isFrozen(HTTP_ADMISSION_LIMITS));assert.throws(()=>budget({requests:1,bytes:1,bodyBytes:2}));
});
