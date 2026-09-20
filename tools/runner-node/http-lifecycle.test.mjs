import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { trackHttpResponse } from './http-lifecycle.mjs';

function response(extra={}) {
  return Object.assign(new EventEmitter(), {destroyed:false,writableEnded:false,writableFinished:false},extra);
}
async function isSettled(p) {
  let settled=false;p.then(()=>settled=true);await Promise.resolve();return settled;
}
for(const event of ['finish','close','error']) {
  test(`latches ${event} before wait, without removing user listeners`,async()=>{
    const res=response();let external=0;const listener=()=>external++;
    res.on(event,listener);const life=trackHttpResponse(res);
    assert.equal(life.canStart(),true);res.emit(event);
    assert.equal(life.canStart(),false);assert.equal(await isSettled(life.wait()),true);
    assert.equal(external,1);assert.deepEqual(res.listeners(event),[listener]);
    for(const other of ['finish','close','error'].filter(x=>x!==event))assert.equal(res.listenerCount(other),0);
    life.dispose();life.dispose();assert.deepEqual(res.listeners(event),[listener]);
  });
  test(`wait already pending resolves on ${event}`,async()=>{
    const res=response(),life=trackHttpResponse(res),wait=life.wait();
    assert.equal(await isSettled(wait),false);res.emit(event);await wait;
    assert.equal(life.canStart(),false);life.dispose();
  });
}
for(const field of ['destroyed','writableFinished']) {
  test(`already ${field} before observation does not await another event`,async()=>{
    const res=response({[field]:true}),life=trackHttpResponse(res);
    assert.equal(life.canStart(),false);assert.equal(await isSettled(life.wait()),true);
    for(const e of ['close','finish','error'])assert.equal(res.listenerCount(e),0);
  });
  test(`${field} set without event is rechecked before dispatch/wait`,async()=>{
    const res=response(),life=trackHttpResponse(res);res[field]=true;
    assert.equal(life.canStart(),false);assert.equal(await isSettled(life.wait()),true);
  });
}
test('end called is not finish: disallow a new callback but wait for flushed completion',async()=>{
  const res=response(),life=trackHttpResponse(res);res.writableEnded=true;
  assert.equal(life.canStart(),false);assert.equal(await isSettled(life.wait()),false);
  res.writableFinished=true;res.emit('finish');await life.wait();
});
test('ordinary request.complete/request.destroyed must not be used as response termination',async()=>{
  const res=response({req:{complete:true,destroyed:true,aborted:false}}),life=trackHttpResponse(res);
  res.req.emit=()=>{};assert.equal(life.canStart(),true);assert.equal(await isSettled(life.wait()),false);
  res.emit('finish');await life.wait();
});
test('termination is permanent even if object flags later change',async()=>{
  const res=response(),life=trackHttpResponse(res);res.emit('close');res.destroyed=false;res.writableFinished=false;
  assert.equal(life.canStart(),false);assert.equal(await isSettled(life.wait()),true);
});
test('all waiters share the same completion and dispose is idempotent',async()=>{
  const res=response(),life=trackHttpResponse(res),a=life.wait(),b=life.wait();assert.equal(a,b);
  life.dispose();life.dispose();await Promise.all([a,b]);assert.equal(life.canStart(),false);
  for(const e of ['finish','close','error'])assert.equal(res.listenerCount(e),0);
});
test('repeated observations do not accumulate event listeners',async()=>{
  const res=response();for(let i=0;i<256;i++){
    const life=trackHttpResponse(res);for(const e of ['finish','close','error'])assert.equal(res.listenerCount(e),1);
    life.dispose();await life.wait();for(const e of ['finish','close','error'])assert.equal(res.listenerCount(e),0);
  }
});
