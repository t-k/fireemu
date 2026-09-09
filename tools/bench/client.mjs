#!/usr/bin/env node
/** One persistent, separately-accounted load generator. SDKs resolve from the repository's
 * frozen conformance installation. No Firebase credentials or public endpoints are accepted.
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createInterface} from 'node:readline';
import {performance, monitorEventLoopDelay} from 'node:perf_hooks';

export function assertLocal(project, host) {
  assert.match(project, /^demo-bench-[a-z0-9-]+$/);
  assert.match(host, /^127\.0\.0\.1:[1-9][0-9]{0,4}$/);
  assert.ok(Number(host.split(':')[1]) <= 65535);
}
export function percentile(xs, p) {
  if (!xs.length) return null;
  const a = [...xs].sort((x,y)=>x-y);
  return a[Math.min(a.length-1, Math.max(0, Math.ceil(a.length*p)-1))];
}
export function makeDoc(i, bytes) {
  let payload = '';
  for (let k=0; payload.length<bytes; ++k)
    payload += createHash('sha256').update(`${i}:${k}:fireemu-bench-v1`).digest('hex');
  return {i, bucket:i%100, score:i, owner:'bench-user', payload:payload.slice(0,bytes)};
}
export function expectedIndices(kind, n) {
  let ids = Array.from({length:n}, (_,i)=>i);
  if (kind === 'query-eq' || kind === 'query-range') ids = ids.filter(i=>i%100===42);
  if (kind === 'query-range') ids = ids.filter(i=>i>=Math.floor(n/2));
  if (kind !== 'scan' && kind !== 'projection') ids.reverse();
  if (kind === 'query-offset' || kind === 'query-cursor') ids = ids.slice(Math.floor(n/2));
  if (kind !== 'scan' && kind !== 'projection') ids = ids.slice(0,32);
  return ids;
}
export async function closedLoop(ops, concurrency, invoke) {
  assert.ok(Number.isInteger(ops) && ops>0 && Number.isInteger(concurrency) && concurrency>0);
  let next = 0;
  await Promise.all(Array.from({length:Math.min(ops,concurrency)}, async()=> {
    for (;;) { const i=next++; if(i>=ops) return; await invoke(i, null); }
  }));
}

let db, sdk, adminApp, webDb, webSdk, fixture=[], cfg, requireSdk;
const id = i => String(i).padStart(9,'0');
const delay = ms => new Promise(r=>setTimeout(r,ms));
const collection = () => db.collection('bench_items');

async function init() {
  cfg=JSON.parse(process.env.BENCH_CLIENT_CONFIG);
  assertLocal(cfg.project, cfg.host);
  process.env.FIRESTORE_EMULATOR_HOST=cfg.host;
  process.env.GCLOUD_PROJECT=cfg.project;
  delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
  delete process.env.FIREBASE_CONFIG;
  requireSdk=createRequire(resolve(cfg.sdkRoot,'package.json'));
  const {initializeApp}=requireSdk('firebase-admin/app');
  sdk=requireSdk('firebase-admin/firestore');
  adminApp=initializeApp({projectId:cfg.project}, 'benchmark');
  db=sdk.getFirestore(adminApp);
  // Leave SDK retry/channel defaults unchanged. Measurements are SDK-visible latency.
  db.settings({preferRest:false});
  return {node:process.version, admin:requireSdk('firebase-admin').SDK_VERSION,
          sdkRetryPolicy:'pinned SDK defaults; transaction maxAttempts=5', pid:process.pid};
}
async function ready() {
  const d=db.doc('_bench_ready/probe');
  await d.set({nonce:cfg.nonce});
  const got=await d.get(); assert.equal(got.get('nonce'),cfg.nonce);
  await d.delete();
  return {usable:true};
}
async function seed() {
  fixture=Array.from({length:cfg.documents}, (_,i)=>makeDoc(i,cfg.payloadBytes));
  const t=performance.now();
  for(let i=0;i<fixture.length;i+=100) {
    const b=db.batch();
    for(let j=i;j<Math.min(i+100,fixture.length);j++) b.set(collection().doc(id(j)),fixture[j]);
    await b.commit();
  }
  await db.doc('_bench_rules/allow').set({owner:'bench-user',value:42});
  await db.doc('_bench_rules/deny').set({owner:'other-user',value:43});
  // Full corpus digest is computed before timing, not inferred from a successful write.
  const got=await collection().orderBy(sdk.FieldPath.documentId()).get();
  assert.equal(got.size,fixture.length);
  const h=createHash('sha256');
  for(let i=0;i<got.size;i++) {
    assert.equal(got.docs[i].id,id(i));
    assert.deepEqual(got.docs[i].data(),fixture[i]);
    h.update(JSON.stringify([got.docs[i].id,fixture[i]])+'\n');
  }
  return {documents:got.size,payloadBytes:cfg.payloadBytes,seed_and_verify_ms:performance.now()-t,
          dataset_sha256:h.digest('hex')};
}
function validateRows(snapshot, indices, projected=false) {
  assert.equal(snapshot.size, indices.length);
  for(let j=0;j<indices.length;j++) {
    const i=indices[j], d=snapshot.docs[j];
    assert.equal(d.id,id(i));
    assert.deepEqual(d.data(),projected?{i,score:i}:fixture[i]);
  }
}
async function webSetup() {
  if(webDb) return;
  const {initializeApp}=requireSdk('firebase/app');
  webSdk=requireSdk('firebase/firestore');
  const app=initializeApp({projectId:cfg.project,apiKey:'benchmark-no-real-key',appId:'bench'},'rules');
  webDb=webSdk.initializeFirestore(app,{localCache:webSdk.memoryLocalCache()});
  webSdk.connectFirestoreEmulator(webDb,'127.0.0.1',Number(cfg.host.split(':')[1]),
                                  {mockUserToken:{sub:'bench-user',user_id:'bench-user'}});
}
async function prepare(spec, namespace) {
  const n=cfg.documents, expected=expectedIndices(spec.kind,n);
  const col=db.collection(`bench_work_${namespace}`);
  const context={col, expected, firstRows:[], attempts:0, returned:0};
  if(spec.kind.startsWith('query') || spec.kind==='projection' || spec.kind==='scan') {
    let q=collection();
    if(spec.kind==='query-eq' || spec.kind==='query-range') q=q.where('bucket','==',42);
    if(spec.kind==='query-range') q=q.where('score','>=',Math.floor(n/2));
    q=q.orderBy('score', (spec.kind==='scan'||spec.kind==='projection')?'asc':'desc');
    if(spec.kind==='query-offset') q=q.offset(Math.floor(n/2));
    if(spec.kind==='query-cursor') q=q.startAfter(n-Math.floor(n/2));
    if(spec.kind!=='scan' && spec.kind!=='projection') q=q.limit(32);
    if(spec.kind==='projection') q=q.select('i','score');
    context.query=q;
  }
  if(spec.kind==='merge') {
    for(let i=0;i<spec.ops;i+=100) {
      const b=db.batch();
      for(let j=i;j<Math.min(i+100,spec.ops);j++)
        b.set(col.doc(id(j)),{...fixture[(j*7919)%cfg.documents], value:-1,nested:{n:-1,keep:'retained'}});
      await b.commit();
    }
  }
  if(spec.kind.startsWith('transaction')) {
    const count=spec.kind==='transaction-hot'?1:spec.ops;
    for(let i=0;i<count;i+=100) {
      const b=db.batch();
      for(let j=i;j<Math.min(i+100,count);j++) b.set(col.doc(id(j)),{n:0});
      await b.commit();
    }
  }
  if(spec.kind.startsWith('rules')) await webSetup();
  return context;
}
async function operation(spec, ctx, i) {
  const index=(i*7919)%cfg.documents;
  const t=performance.now();
  let result, validate=()=>{}, first_ms=null, rows=0;
  switch(spec.kind) {
    case 'get':
      result=await collection().doc(id(index)).get(); rows=1;
      validate=()=>assert.deepEqual(result.data(),fixture[index]); break;
    case 'get-all': {
      const indexes=Array.from({length:10},(_,j)=>(index+j)%cfg.documents);
      result=await db.getAll(...indexes.map(j=>collection().doc(id(j)))); rows=result.length;
      validate=()=>{
        assert.equal(result.length,indexes.length);
        assert.deepEqual(result.map(d=>d.id).sort(),indexes.map(id).sort());
        for(const d of result) assert.deepEqual(d.data(),fixture[Number(d.id)]);
      }; break;
    }
    case 'set':
      result=await ctx.col.doc(id(i)).set(fixture[index]); break;
    case 'merge':
      result=await ctx.col.doc(id(i)).set({value:i, nested:{n:i}}, {merge:true}); break;
    case 'batch': {
      const b=db.batch();
      for(let j=0;j<100;j++) b.set(ctx.col.doc(id(i*100+j)),fixture[(i*100+j)%cfg.documents]);
      result=await b.commit(); validate=()=>assert.equal(result.length,100); break;
    }
    case 'query-eq': case 'query-range': case 'query-offset': case 'query-cursor':
      result=await ctx.query.get(); rows=result.size;
      validate=()=>validateRows(result,ctx.expected); break;
    case 'projection': case 'scan': {
      const documents=[];
      for await(const d of ctx.query.stream()) {
        if(first_ms===null) first_ms=performance.now()-t;
        documents.push(d);
      }
      rows=documents.length;
      validate=()=>validateRows({size:documents.length,docs:documents},ctx.expected,spec.kind==='projection');
      break;
    }
    case 'count':
      result=await collection().count().get();
      validate=()=>assert.equal(result.data().count,cfg.documents); break;
    case 'sum':
      result=await collection().aggregate({total:sdk.AggregateField.sum('score')}).get();
      validate=()=>assert.equal(result.data().total,cfg.documents*(cfg.documents-1)/2); break;
    case 'transaction': case 'transaction-hot': {
      const ref=ctx.col.doc(id(spec.kind==='transaction-hot'?0:i));
      result=await db.runTransaction(async tx=>{
        ctx.attempts++; const d=await tx.get(ref); const v=d.get('n');
        tx.update(ref,{n:v+1}); return v+1;
      },{maxAttempts:5});
      validate=()=>assert.ok(Number.isInteger(result)&&result>=1); break;
    }
    case 'rules-allow':
      result=await webSdk.getDocFromServer(webSdk.doc(webDb,'_bench_rules/allow')); rows=1;
      validate=()=>assert.deepEqual(result.data(),{owner:'bench-user',value:42}); break;
    case 'rules-deny': {
      let denied=false;
      try { await webSdk.getDocFromServer(webSdk.doc(webDb,'_bench_rules/deny')); }
      catch(e) { if(e.code==='permission-denied') denied=true; else throw e; }
      validate=()=>assert.ok(denied,'Rules deny was unexpectedly accepted'); break;
    }
    default: throw new Error(`Unsupported workload: ${spec.kind}`);
  }
  const elapsed=performance.now()-t; // RPC/SDK duration, validation deliberately outside.
  const vt=performance.now(); validate();
  return {latency_ms:elapsed,first_result_ms:first_ms,validation_ms:performance.now()-vt,rows};
}
async function verifyWrites(spec,ctx) {
  if(['set','merge','batch','transaction','transaction-hot'].includes(spec.kind)) {
    const s=await ctx.col.get();
    const count=spec.kind==='batch'?spec.ops*100:spec.kind==='transaction-hot'?1:spec.ops;
    assert.equal(s.size,count);
    for(const d of s.docs) {
      const i=Number(d.id);
      if(spec.kind==='transaction-hot') assert.equal(d.get('n'),spec.ops);
      else if(spec.kind==='transaction') assert.equal(d.get('n'),1);
      else if(spec.kind==='merge') assert.deepEqual(d.data(),{...fixture[(i*7919)%cfg.documents],value:i,nested:{n:i,keep:'retained'}});
      else assert.deepEqual(d.data(),fixture[spec.kind==='batch'?i%cfg.documents:(i*7919)%cfg.documents]);
    }
  }
}
async function run(spec, namespace) {
  const ctx=await prepare(spec,namespace);
  const samples=[], failures=[], first=[], adjusted=[];
  let validation_ms=0, returned=0, dropped=0;
  const histogram=monitorEventLoopDelay({resolution:10}); histogram.enable();
  const cpu0=process.cpuUsage(), t0=performance.now(), elu0=performance.eventLoopUtilization();
  const invoke=async(i,scheduled)=>{
    const start=performance.now();
    try {
      const r=await operation(spec,ctx,i);
      samples.push(r.latency_ms); validation_ms+=r.validation_ms; returned+=r.rows;
      if(r.first_result_ms!==null) first.push(r.first_result_ms);
      if(scheduled!==null) adjusted.push(start+r.latency_ms-scheduled);
    } catch(e) { failures.push({i,code:e.code??e.name,message:String(e.message).slice(0,500),
                               elapsed_ms:performance.now()-start}); }
  };
  if(spec.offeredRate) {
    assert.equal(spec.kind,'get','Open-loop is supported only for immutable point reads');
    const inflight=new Set();
    for(let i=0;i<spec.ops;i++) {
      const due=t0+i*1000/spec.offeredRate;
      await delay(Math.max(0,due-performance.now()));
      if(inflight.size>=spec.concurrency) {dropped++;continue;}
      const p=invoke(i,due); inflight.add(p); p.finally(()=>inflight.delete(p));
    }
    await Promise.all(inflight);
  } else await closedLoop(spec.ops,spec.concurrency,invoke);
  const wall=performance.now()-t0, cpu=process.cpuUsage(cpu0), elu=performance.eventLoopUtilization(elu0);
  histogram.disable();
  let postcheck=null;
  if(!failures.length&&!dropped) {
    try {await verifyWrites(spec,ctx); postcheck=true;}
    catch(e) {postcheck=false; failures.push({code:'POSTCHECK',message:e.message});}
  }
  return {spec,ok:failures.length===0&&dropped===0,logical_requests:spec.ops,
          completed:samples.length,errors:failures.length,dropped,failures,
          wall_ms:wall,throughput_rps:samples.length/(wall/1000),returned_documents:returned,
          latency_ms:samples,scheduled_latency_ms:adjusted,first_result_ms:first,
          p50_ms:percentile(samples,.5),p95_ms:percentile(samples,.95),p99_ms:percentile(samples,.99),
          transaction_attempts:ctx.attempts||null,validation_ms,postcheck,
          client:{cpu_user_ms:cpu.user/1000,cpu_system_ms:cpu.system/1000,
                  cpu_cores:(cpu.user+cpu.system)/(wall*1000),elu:elu.utilization,
                  event_loop_p99_ms:histogram.count?histogram.percentile(99)/1e6:null,
                  memory:process.memoryUsage()}};
}
async function listener(spec, namespace) {
  const ref=db.collection(`bench_work_${namespace}`).doc('watched');
  await ref.set({version:0});
  const seen=Array(spec.fanout).fill(-1), callbacks=Array(spec.fanout).fill(0);
  const unsub=[], latency=[]; let resolveBarrier=null,rejectBarrier=null,current=0,start=0;
  const barrier=()=>new Promise((res,rej)=>{
    const timer=setTimeout(()=>{resolveBarrier=null;rejectBarrier=null;rej(new Error('Listener barrier timeout'));},30000);
    resolveBarrier=()=>{clearTimeout(timer);res();}; rejectBarrier=e=>{clearTimeout(timer);rej(e);};
  });
  try {
    const initial=barrier();
    for(let j=0;j<spec.fanout;j++) unsub.push(ref.onSnapshot(s=>{
      const v=s.get('version');
      if(!Number.isInteger(v)) {rejectBarrier?.(new Error('Bad listener data'));return;}
      if(v===current && seen[j]!==v) {
        seen[j]=v;callbacks[j]++;
        if(v>0) latency.push(performance.now()-start);
        if(seen.every(x=>x===current)) resolveBarrier?.();
      }
    },e=>rejectBarrier?.(e)));
    await initial;
    const t0=performance.now();
    for(let i=1;i<=spec.ops;i++) {
      current=i; const wait=barrier();start=performance.now();
      await ref.update({version:i}); await wait;
    }
    const wall=performance.now()-t0;
    assert.deepEqual(seen,Array(spec.fanout).fill(spec.ops));
    assert.equal(latency.length,spec.ops*spec.fanout);
    return {ok:true,spec,logical_requests:spec.ops,completed:spec.ops,errors:0,dropped:0,
            wall_ms:wall,throughput_rps:spec.ops/(wall/1000),latency_ms:latency,
            p50_ms:percentile(latency,.5),p95_ms:percentile(latency,.95),p99_ms:percentile(latency,.99),
            deliveries:latency.length,latency_unit:'writer dispatch to each listener callback',callbacks};
  } finally {for(const stop of unsub) stop();}
}
async function clearData() {
  // Same SDK delete operations for both engines; no vendor-only reset endpoint.
  const cols=await db.listCollections();let deleted=0;
  for(const col of cols) {
    assert.ok(col.id.startsWith('bench_')||col.id.startsWith('_bench_'));
    for(;;) {
      const s=await col.limit(100).get();if(s.empty) break;
      const b=db.batch();for(const d of s.docs) b.delete(d.ref);await b.commit();deleted+=s.size;
    }
    assert.ok((await col.limit(1).get()).empty);
  }
  return {deleted,verified_empty:true};
}
async function main() {
  const metadata=await init();process.stdout.write(JSON.stringify({type:'boot',metadata})+'\n');
  for await(const line of createInterface({input:process.stdin,crlfDelay:Infinity})) {
    const req=JSON.parse(line);let response;
    try {
      if(req.action==='ready') response=await ready();
      else if(req.action==='seed') response=await seed();
      else if(req.action==='run') response= req.spec.kind==='listen'?await listener(req.spec,req.namespace):await run(req.spec,req.namespace);
      else if(req.action==='clear') response=await clearData();
      else if(req.action==='close') {
        if(webDb) await webSdk.terminate(webDb);
        await db.terminate();await requireSdk('firebase-admin/app').deleteApp(adminApp);
        // SDK channels and the resumed stdin reader can keep the event loop alive after
        // terminate(); exit explicitly once the answer is flushed so the harness never has to
        // SIGKILL the client (a forced kill invalidates the trial).
        process.stdout.write(JSON.stringify({id:req.id,ok:true,data:{closed:true}})+'\n',()=>process.exit(0));return;
      } else throw new Error(`Unknown action ${req.action}`);
      process.stdout.write(JSON.stringify({id:req.id,ok:true,data:response})+'\n');
    } catch(e) {process.stdout.write(JSON.stringify({id:req.id,ok:false,error:{code:e.code??e.name,message:e.message}})+'\n');}
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)
  main().then(()=>process.exit(process.exitCode??0),e=>{console.error(e);process.exit(1);});
