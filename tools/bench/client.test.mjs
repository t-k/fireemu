import test from 'node:test';
import assert from 'node:assert/strict';
import {assertLocal,percentile,makeDoc,expectedIndices,closedLoop} from './client.mjs';

test('only disposable demo project and literal loopback endpoints are permitted',()=>{
  assertLocal('demo-bench-test','127.0.0.1:8080');
  for(const host of ['firestore.googleapis.com:443','localhost:8080','127.0.0.1:70000','https://127.0.0.1:8080'])
    assert.throws(()=>assertLocal('demo-bench-test',host));
  assert.throws(()=>assertLocal('production-project','127.0.0.1:8080'));
});
test('dataset is repeatable, exact payload length, and document-specific',()=>{
  for(const bytes of [1,63,64,65,1024,65536]) {
    const a=makeDoc(42,bytes);assert.equal(Buffer.byteLength(a.payload),bytes);
    assert.deepEqual(a,makeDoc(42,bytes));assert.notEqual(a.payload,makeDoc(43,bytes).payload);
    assert.equal(a.bucket,42);assert.equal(a.owner,'bench-user');
  }
});
test('percentile is nearest-rank and empty is missing, never zero',()=>{
  assert.equal(percentile([],0.99),null);
  assert.equal(percentile([4,1,3,2],.5),2);assert.equal(percentile([4,1,3,2],.99),4);
});
test('offset and cursor select the same half-range and ordering',()=>{
  for(const n of [1000,10000,100000]) {
    assert.deepEqual(expectedIndices('query-offset',n),expectedIndices('query-cursor',n));
    const e=expectedIndices('query-offset',n);assert.equal(e[0],n-Math.floor(n/2)-1);assert.equal(e.length,32);
  }
});
test('range fixture validates values, count and direction independently of engine',()=>{
  const v=expectedIndices('query-range',10000);
  assert.equal(v.length,32);assert.ok(v.every(x=>x%100===42&&x>=5000));
  assert.ok(v.every((x,i)=>i===0||v[i-1]>x));
});
test('scan and projection cover all documents',()=>{
  assert.deepEqual(expectedIndices('scan',1000),expectedIndices('projection',1000));
  assert.equal(expectedIndices('scan',1000).length,1000);
});
test('closed-loop has no missing/duplicate requests and respects concurrency',async()=>{
  const seen=new Set();let active=0,peak=0;
  await closedLoop(103,8,async i=>{
    assert.ok(!seen.has(i));seen.add(i);peak=Math.max(peak,++active);
    await new Promise(r=>setTimeout(r,i%3));active--;
  });
  assert.equal(seen.size,103);assert.equal(active,0);assert.ok(peak<=8&&peak>1);
});
test('zero-test and invalid concurrency cannot accidentally pass',async()=>{
  await assert.rejects(closedLoop(0,1,async()=>{}));
  await assert.rejects(closedLoop(10,0,async()=>{}));
});
