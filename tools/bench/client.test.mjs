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
test('close answers, then the process exits on its own so the harness never has to kill it',async()=>{
  const {spawn}=await import('node:child_process');
  const {fileURLToPath}=await import('node:url');
  const {dirname,resolve:resolvePath}=await import('node:path');
  const here=dirname(fileURLToPath(import.meta.url));
  const config={project:'demo-bench-test',host:'127.0.0.1:1',nonce:'test',
                sdkRoot:resolvePath(here,'../../conformance'),documents:1,payloadBytes:1};
  const child=spawn(process.execPath,[resolvePath(here,'client.mjs')],
                    {env:{...process.env,BENCH_CLIENT_CONFIG:JSON.stringify(config)},stdio:['pipe','pipe','inherit']});
  let out='';child.stdout.on('data',d=>{out+=d;});
  const exit=new Promise(r=>child.on('exit',(code,signal)=>r({code,signal})));
  await new Promise(r=>child.stdout.once('data',r));
  assert.equal(JSON.parse(out.split('\n')[0]).type,'boot');
  child.stdin.write(JSON.stringify({id:1,action:'close'})+'\n');
  const timeout=new Promise((_,reject)=>setTimeout(()=>{child.kill('SIGKILL');reject(new Error('client did not exit after close'));},8000));
  const result=await Promise.race([exit,timeout]);
  assert.deepEqual(result,{code:0,signal:null});
  assert.deepEqual(JSON.parse(out.trim().split('\n').at(-1)),{id:1,ok:true,data:{closed:true}});
});

test('named shapes retain oracle fields and deterministic bounded structures',()=>{
  const tiny=makeDoc(42,64,'tiny');assert.equal(tiny.payload,undefined);assert.equal(tiny.score,42);
  const wide=makeDoc(42,64,'wide-map');assert.equal(Object.keys(wide.fields).length,32);
  assert.deepEqual(wide,makeDoc(42,64,'wide-map'));
  assert.throws(()=>makeDoc(1,64,'unknown'));
});

test('mixed classes validate independently, overlap Storage with probes, and remain bounded',async()=>{
  const {mixedClasses}=await import('./client.mjs');
  const tasks=Object.fromEntries(['storage','auth','hub','firestore'].map(name=>[name,async()=>new Promise(r=>setTimeout(r,name==='storage'?8:1))]));
  const result=await mixedClasses(tasks,{ops:4,concurrency:2,seed:17,mixed:true});
  assert.equal(result.overlap,true);assert.equal(result.classes.length,4);
  for(const row of result.classes){assert.equal(row.completed,4);assert.equal(row.ok,true);assert.ok(row.peak_inflight<=2);assert.equal(row.latency_ms.length,4);}
  const isolated=await mixedClasses(tasks,{ops:4,concurrency:2,seed:17,mixed:false});
  assert.equal(isolated.overlap,false);
  await assert.rejects(mixedClasses({...tasks,auth:async()=>{throw Error('invalid result');}},{ops:2,concurrency:1,seed:17,mixed:true}),/invalid result/);
});

test('a failed mixed class drains all already started operations before returning',async()=>{
  const {mixedClasses}=await import('./client.mjs');let pending=0;
  const tasks=Object.fromEntries(['storage','auth','hub','firestore'].map(name=>[name,async i=>{
    pending++;try{if(name==='auth'&&i===0)throw Error('bad response');await new Promise(r=>setTimeout(r,20));}finally{pending--;}
  }]));
  await assert.rejects(mixedClasses(tasks,{ops:4,concurrency:2,seed:1,mixed:true}),/bad response/);
  assert.equal(pending,0);
});

test('fixture digests pin each shape without changing legacy data',async()=>{
  const {createHash}=await import('node:crypto');
  const hashes={default:'15b76c8305e24d970a85083c7e84a234c4c3f0c412c595081a0161c5ff724923',tiny:'f6708df54cc892c0b6dbd383ce49b49a3cbb1ca601a0f29679fc2e92accd910c','wide-map':'2f22a54b9171a67c753ced169d44c4ec0df576ca142acae8ded18b779fa469ca'};
  for(const [shape,hash] of Object.entries(hashes))assert.equal(createHash('sha256').update(JSON.stringify(Array.from({length:3},(_,i)=>makeDoc(i,64,shape)))).digest('hex'),hash);
});

test('mixed scheduler rejects malformed or unbounded configurations',async()=>{
  const {mixedClasses}=await import('./client.mjs');
  const tasks=Object.fromEntries(['storage','auth','hub','firestore'].map(name=>[name,async()=>{}]));
  for(const config of [{ops:0},{ops:101},{concurrency:0},{concurrency:5},{seed:NaN}])await assert.rejects(mixedClasses(tasks,{ops:4,concurrency:2,seed:1,mixed:false,...config}));
});

test('mixed semantic guards reject malformed metadata and the wrong service registry',async()=>{
  const {validateMixedResponse}=await import('./client.mjs');
  validateMixedResponse('auth',{signIn:{allowDuplicateEmails:false}});
  validateMixedResponse('storage',{name:'object',size:'64'},{name:'object',size:64});
  const hosts={auth:'127.0.0.1:1',storage:'127.0.0.1:2',firestore:'127.0.0.1:3'};
  const registry=Object.fromEntries(Object.entries(hosts).map(([service,host])=>[service,{host:'127.0.0.1',port:Number(host.split(':')[1])}]));
  validateMixedResponse('hub',registry,hosts);
  for(const [kind,data,expected] of [['auth',{}],['auth',{signIn:{allowDuplicateEmails:'false'}}],['storage',{name:'other',size:'64'},{name:'object',size:64}],['storage',{name:'object',size:'63'},{name:'object',size:64}],['hub',{...registry,storage:{host:'127.0.0.1',port:9}},hosts]])assert.throws(()=>validateMixedResponse(kind,data,expected));
});
