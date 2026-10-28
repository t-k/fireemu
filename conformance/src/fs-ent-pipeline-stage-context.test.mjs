import assert from 'node:assert/strict';
import { test } from 'node:test';



test('fixed corpus preserves 11 distinct cases and original nested ASTs', async () => {
  const { stageContextCases } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { O8A_PROGRAMS } = await import('./fs-ent-pipeline/o8a-corpus.mjs');
  const cases = stageContextCases();
  assert.equal(cases.length, 11);
  assert.equal(new Set(cases.map(x => x.id)).size, 11);
  assert.deepEqual(cases.filter(x => x.id.startsWith('replace-')).map(x => x.body.structuredPipeline.pipeline.stages[1].args[1].stringValue), ['full_replace', 'merge_overwrite_existing', 'merge_keep_existing', 'full_replace']);
  const original = O8A_PROGRAMS.find(x => x.id.endsWith('/nesting-main'));
  for (const depth of [48, 100]) assert.deepEqual(cases.find(x => x.id === `chain-${depth}-grpc`).body, original.steps.find(x => x.id === `chain-${depth}-grpc`).body);
});



test('new context is bound to the exact fresh database without widening generic targets', async () => {
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const { createContext } = await import('./fs-ent-pipeline/harness.mjs');
  const target = { kind: 'local', origin: 'http://127.0.0.1:1', grpcHost: '127.0.0.1', grpcPort: 1 };
  assert.throws(() => createContext({run: 1, target, database: 'entpipe2-20261029'}));
  const fresh = createStageContext({run: 1, target, database: 'entpipe2-20261029', approvedDatabase: 'entpipe2-20261029'});
  assert.equal(fresh.database, 'entpipe2-20261029');
  for (const database of ['entpipe1', '(default)', 'foreign']) assert.throws(() => createStageContext({run: 1, target, database, approvedDatabase: 'entpipe2-20261029'}));
});

test('owned seed includes distinct vector rankings and the original nesting seed', async () => {
  const { stageContextSeed } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const seed = stageContextSeed();
  assert.deepEqual(seed.map(([path]) => path), ['stage/a', 'stage/b', 'stage/c', 'other/a', 'ne/d1']);
  const vectors = seed.slice(0, 3).map(([, fields]) => fields.vec.mapValue.fields.value.arrayValue.values.map(x => x.doubleValue));
  const measures = [v => Math.hypot(v[0] - 1, v[1] - 2), v => (v[0] + 2 * v[1]) / (Math.hypot(...v) * Math.sqrt(5)), v => v[0] + 2 * v[1]];
  for (const f of measures) assert.equal(new Set(vectors.map(f)).size, 3);
  assert.deepEqual(seed.at(-1)[1], {i: {integerValue: '1'}});
});


test('isolated protobuf codec round-trips only original 48/100 nested requests', async () => {
  const { spawnSync } = await import('node:child_process');
  const script = new URL('./fs-ent-pipeline/stage-context-nesting-codec.mjs', import.meta.url);
  for (const depth of [48, 100]) {
    const out = spawnSync(process.execPath, [script.pathname, String(depth)], { encoding: 'utf8', timeout: 10000 });
    assert.equal(out.status, 0, out.stderr);
    const report = JSON.parse(out.stdout);
    assert.equal(report.depth, depth); assert.equal(report.roundTrip, true); assert.equal(report.recursionLimit, 1024);
  }
  const denied = spawnSync(process.execPath, [script.pathname, '47'], { encoding: 'utf8', timeout: 10000 });
  assert.notEqual(denied.status, 0);
});


test('two scoped rounds count observations and support separately', async () => {
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  const calls = [];
  const io = async (op, detail) => { calls.push([op, detail]); return { known: true, ok: true }; };
  const result = await runStageContextRounds(io);
  assert.equal(result.observations, 22); assert.equal(result.support, 10); assert.equal(calls.length, 32);
  assert.deepEqual(calls.map(x => x[0]).filter(x => x !== 'observe'), Array(2).fill(['baseline', 'seed', 'verify', 'delete-owned', 'verify-absence']).flat());
});

test('unknown seed and failed verification never trigger cleanup or mutation resend', async () => {
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  for (const bad of ['seed', 'verify']) {
    const calls = [];
    const io = async (op) => { calls.push(op); return op === bad ? { known: false, ok: false } : { known: true, ok: true }; };
    await assert.rejects(runStageContextRounds(io), /unknown/);
    assert.equal(calls.filter(x => x === bad).length, 1);
    assert.ok(!calls.includes('delete-owned'));
  }
});

test('unknown observation or cleanup stops immediately and never repeats mutations', async () => {
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  for (const failure of ['observe', 'delete-owned', 'verify-absence']) {
    const calls = [];
    await assert.rejects(runStageContextRounds(async (op) => {
      calls.push(op);
      return op === failure ? { known: false } : { known: true, ok: true };
    }), /unknown/);
    assert.equal(calls.at(-1), failure);
    assert.equal(calls.filter(x => x === 'seed').length, 1);
    assert.ok(calls.filter(x => x === 'delete-owned').length <= 1);
  }
});

test('generated phase/outcome/round table stops on every unknown without retry', async () => {
  const { readFileSync } = await import('node:fs');
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  const rows = readFileSync(new URL('./fs-ent-pipeline/fixtures/stage-context-rounds-pict.tsv', import.meta.url), 'utf8').trim().split('\n').slice(1);
  assert.equal(rows.length, 12);
  for (const row of rows) {
    const [phase, outcome, round] = row.split('\t');
    const calls = [];
    const run = () => runStageContextRounds(async (op, detail) => {
      calls.push([op, detail.round]);
      return op === phase && detail.round === Number(round) && outcome === 'unknown' ? { known: false } : { known: true, ok: true };
    });
    if (outcome === 'unknown') {
      await assert.rejects(run(), /unknown/);
      assert.deepEqual(calls.at(-1), [phase, Number(round)]);
      if (phase === 'seed' || phase === 'delete-owned') assert.equal(calls.filter(([op, n]) => op === phase && n === Number(round)).length, 1);
    } else {
      const result = await run(); assert.equal(result.observations + result.support, 32);
    }
  }
});

test('session scoped support uses one REST RPC per action and never wipes unrelated paths', async () => {
  const { createStageSupport } = await import('./fs-ent-pipeline/stage-context-support.mjs');
  const { stageContextSeed } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx = createStageContext({run: 1, database: 'entpipe2-20261029', approvedDatabase: 'entpipe2-20261029', target: {kind:'local', origin:'http://127.0.0.1:1', grpcHost:'127.0.0.1', grpcPort:1}});
  const base = `projects/${ctx.project}/databases/${ctx.database}/documents/`;
  const paths = stageContextSeed().map(([path]) => path);
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push({url, init});
    const names = calls.length === 3 ? paths : [];
    return {ok:true, status:200, text:async () => JSON.stringify(url.endsWith(':runQuery') ? names.map(name => ({document:{name:base+name}})) : {})};
  };
  const session = createStageSupport(ctx, {fetchFn, journal:async () => {}, claim:async () => {}});
  try {
    for (const [op, detail] of [['baseline',{}], ['seed',{documents:stageContextSeed()}], ['verify',{documents:stageContextSeed()}], ['delete-owned',{paths}], ['verify-absence',{paths}]]) {
      assert.deepEqual(await session.stageOperation(op, detail), {known:true,ok:true});
    }
    assert.equal(calls.length, 5);
    assert.ok(calls.every(x => !x.url.includes('/emulator/')));
    const deletes = JSON.parse(calls[3].init.body).writes.map(x => x.delete);
    assert.deepEqual(deletes, paths.map(path => base + path));
  } finally { await session.close(); }
});

test('scoped baseline rejects malformed successful query responses and extra resources', async () => {
  const { createStageSupport } = await import('./fs-ent-pipeline/stage-context-support.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx = createStageContext({run:1, database:'entpipe2-20261029', approvedDatabase:'entpipe2-20261029', target:{kind:'local', origin:'http://127.0.0.1:1', grpcHost:'127.0.0.1', grpcPort:1}});
  for (const response of [[{error:{message:'x'}}], [null], [{document:{name:'projects/foreign/databases/demo/documents/x/y'}}]]) {
    const session = createStageSupport(ctx, {fetchFn:async () => ({status:200, text:async () => JSON.stringify(response)}), journal:async () => {}, claim:async () => {}});
    try { await assert.rejects(session.stageOperation('baseline'), /scoped read/); } finally { await session.close(); }
  }
});

test('support journals response status before body failure and never records authorization', async () => {
  const { createStageSupport } = await import('./fs-ent-pipeline/stage-context-support.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx = createStageContext({run:1, database:'entpipe2-20261029', approvedDatabase:'entpipe2-20261029', target:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1}});
  const journal = [];
  const support = createStageSupport(ctx, {claim:async () => {}, journal:async x => journal.push(x), fetchFn:async () => ({status:403, text:async () => {throw Error('interrupted')}})});
  await assert.rejects(support.stageOperation('baseline'), /unknown/);
  assert.deepEqual(journal.map(x => x.phase), ['attempt','headers','unknown']);
  assert.equal(journal[1].status, 403);
  assert.ok(!JSON.stringify(journal).includes('Bearer owner'));
});

test('support refuses cleanup before verification and refuses retry after unknown mutation', async () => {
  const { createStageSupport } = await import('./fs-ent-pipeline/stage-context-support.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const { stageContextSeed } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const ctx = createStageContext({run:1, database:'entpipe2-20261029', approvedDatabase:'entpipe2-20261029', target:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1}});
  let calls = 0;
  const support = createStageSupport(ctx, {claim:async () => {}, journal:async () => {}, fetchFn:async () => {calls++; if (calls === 1) return {status:200,text:async () => '[]'}; throw Error('lost');}});
  const paths=stageContextSeed().map(([path])=>path);
  await assert.rejects(support.stageOperation('delete-owned',{paths}), /sequence/);
  await support.stageOperation('baseline');
  await assert.rejects(support.stageOperation('seed',{documents:stageContextSeed()}), /unknown/);
  await assert.rejects(support.stageOperation('seed',{documents:stageContextSeed()}), /sequence/);
  await assert.rejects(support.stageOperation('delete-owned',{paths}), /sequence/);
  assert.equal(calls,2);
});

test('observation rejects non-corpus bodies before any gRPC call', async () => {
  const { observeStage } = await import('./fs-ent-pipeline/stage-context-observation.mjs');
  const { stageContextCases } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx = createStageContext({run:1, database:'entpipe2-20261029', approvedDatabase:'entpipe2-20261029', target:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1}});
  let called = false;
  const altered = structuredClone(stageContextCases()[0]); altered.body.structuredPipeline.pipeline.stages.push({name:'delete'});
  await assert.rejects(observeStage(ctx, altered, {claim:async()=>{},journal:async()=>{},clientFactory:()=>{called=true;}}), /corpus/);
  assert.equal(called,false);
});

test('fixed gRPC observation records bounded raw frames without credential metadata', async () => {
  const { EventEmitter } = await import('node:events');
  const { observeStage } = await import('./fs-ent-pipeline/stage-context-observation.mjs');
  const { stageContextCases } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1}});
  const events=[]; let closed=false;
  const clientFactory=()=>({makeServerStreamRequest(_path,serialize,_deserialize,request) {const call=new EventEmitter();call.cancel=()=>{};assert.ok(serialize(request).length);queueMicrotask(()=>{call.emit('metadata',{});call.emit('data',Buffer.from([1,2,3]));call.emit('status',{code:0});});return call;},close(){closed=true;}});
  const result=await observeStage(ctx,stageContextCases()[0],{claim:async()=>events.push({phase:'claim'}),journal:async x=>events.push(x),clientFactory});
  assert.deepEqual(result.frames,['AQID']);assert.equal(result.code,0);
  assert.deepEqual(events.map(x=>x.phase),['claim','attempt','headers','status']);
  assert.ok(!JSON.stringify(events).includes('Bearer owner'));
  await new Promise(resolve=>setImmediate(resolve));assert.equal(closed,true);
  await assert.rejects(observeStage(ctx,stageContextCases().find(x=>x.id==='chain-48-grpc'),{claim:async()=>{},journal:async()=>{},clientFactory}),/isolated worker/);
});

test('gRPC UNKNOWN status is preserved but stops the run as unknown', async () => {
  const { EventEmitter } = await import('node:events');
  const { observeStage } = await import('./fs-ent-pipeline/stage-context-observation.mjs');
  const { stageContextCases } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1}});
  const events=[]; const clientFactory=()=>({makeServerStreamRequest(){const call=new EventEmitter();call.cancel=()=>{};queueMicrotask(()=>call.emit('status',{code:2}));return call;},close(){}});
  await assert.rejects(observeStage(ctx,stageContextCases()[0],{claim:async()=>{},journal:async x=>events.push(x),clientFactory}), /unknown/);
  assert.equal(events.at(-1).code,2);
});

test('worker client acknowledges claims and journals before accepting completion', async () => {
  const { EventEmitter } = await import('node:events');
  const { runObservationWorker } = await import('./fs-ent-pipeline/stage-context-worker-client.mjs');
  const { stageContextCases } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const events=[];
  const factory=() => {const w=new EventEmitter();let phase=0;w.postMessage=msg=>{events.push(`ack${msg.id}`);if(++phase===1) queueMicrotask(()=>w.emit('message',{kind:'journal',id:2,data:{phase:'attempt'}}));else if(phase===2) queueMicrotask(()=>w.emit('message',{kind:'journal',id:3,data:{phase:'status'}}));else queueMicrotask(()=>w.emit('message',{kind:'complete',result:{known:true,code:0}}));};w.terminate=async()=>0;queueMicrotask(()=>w.emit('message',{kind:'claim',id:1,data:{stepId:stageContextCases()[0].id}}));return w;};
  const result=await runObservationWorker({},stageContextCases()[0],{workerFactory:factory,claim:async()=>events.push('claim'),journal:async()=>events.push('journal')});
  assert.deepEqual(events,['claim','ack1','journal','ack2','journal','ack3']);assert.equal(result.known,true);
});

test('two rounds using scoped REST and worker handoff make exactly 32 fake transport calls', async () => {
  const { Worker } = await import('node:worker_threads');
  const { createStageBudget } = await import('./fs-ent-pipeline/stage-context-budget.mjs');
  const { createStageSupport } = await import('./fs-ent-pipeline/stage-context-support.mjs');
  const { runObservationWorker } = await import('./fs-ent-pipeline/stage-context-worker-client.mjs');
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  const { stageContextSeed } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1}});
  let seeded=false,rest=0,grpc=0; const base=`projects/${ctx.project}/databases/${ctx.database}/documents/`;
  const fetchFn=async (url,init)=>{rest++;let result={}; if(url.endsWith(':runQuery')) result=seeded?stageContextSeed().map(([path])=>({document:{name:base+path}})):[];else {const writes=JSON.parse(init.body).writes;seeded=Boolean(writes[0].update);}return {status:200,text:async()=>JSON.stringify(result)};};
  const budget=createStageBudget({maximum:32,cleanupReserve:2}); const journal=async()=>{},claim=budget.claim;
  const support=createStageSupport(ctx,{fetchFn,journal,claim});
  const workerFactory=(c,step)=>{grpc++;return new Worker(new URL('./fs-ent-pipeline/fixtures/stage-context-fake-worker.mjs',import.meta.url),{workerData:{ctx:c,stepId:step.id}});};
  const result=await runStageContextRounds((op,detail)=>op==='observe'?runObservationWorker(ctx,detail.step,{claim,journal,workerFactory}):support.stageOperation(op,detail));
  assert.deepEqual(result,{observations:22,support:10});assert.equal(rest,10);assert.equal(grpc,22);assert.equal(budget.used(),32);assert.equal(seeded,false);
});

test('original deep requests serialize and capture in isolated fake gRPC workers', async () => {
  const { Worker } = await import('node:worker_threads');
  const { runObservationWorker } = await import('./fs-ent-pipeline/stage-context-worker-client.mjs');
  const { stageContextCases } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1}});
  for(const depth of [48,100]) {
    const step=stageContextCases().find(x=>x.id===`chain-${depth}-grpc`), events=[];
    const result=await runObservationWorker(ctx,step,{claim:async()=>{},journal:async e=>events.push(e),workerFactory:(c,s)=>new Worker(new URL('./fs-ent-pipeline/fixtures/stage-context-fake-worker.mjs',import.meta.url),{workerData:{ctx:c,stepId:s.id}})});
    assert.deepEqual(result.frames,['AQI=']);assert.deepEqual(events.map(x=>x.phase),['attempt','headers','status']);
  }
});

test('request ceiling preserves cleanup slots and never refunds attempted calls', async () => {
  const { createStageBudget } = await import('./fs-ent-pipeline/stage-context-budget.mjs');
  const budget=createStageBudget({maximum:4,cleanupReserve:2});
  await budget.claim('baseline');await budget.claim('seed');
  await assert.rejects(budget.claim('observe'),/reserve/);
  await budget.claim('delete-owned');await budget.claim('verify-absence');
  await assert.rejects(budget.claim('delete-owned'),/ceiling/);
  assert.equal(budget.used(),4);
});

test('synchronous gRPC transport failure closes its owned client and stops', async () => {
  const { observeStage } = await import('./fs-ent-pipeline/stage-context-observation.mjs');
  const { stageContextCases } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1}});
  let closed=false;
  await assert.rejects(observeStage(ctx,stageContextCases()[0],{claim:async()=>{},journal:async()=>{},clientFactory:()=>({makeServerStreamRequest(){throw Error('failed');},close(){closed=true;}})}));
  assert.equal(closed,true);
});

test('lifecycle creates one owned target and stops after unknown create without retry', async () => {
  const { createStageLifecycle } = await import('./fs-ent-pipeline/stage-context-lifecycle.mjs');
  const ctx={project:'fireemu-oracle-query',database:'entpipe2-20261029',stageContextDatabase:'entpipe2-20261029',target:{token:'fake-token',quotaProject:'fireemu-oracle-query'}};
  const calls=[];
  const fetchFn=async (url,init)=>{calls.push([url,init.method]);if(init.method==='POST') throw Error('unknown');return {status:200,text:async()=>'{"databases":[]}'}};
  const lifecycle=createStageLifecycle(ctx,{fetchFn,claim:async()=>{},journal:async()=>{}});
  await assert.rejects(lifecycle.create(),/unknown/);
  await assert.rejects(lifecycle.create(),/sequence/);
  assert.deepEqual(calls.map(x=>x[1]),['GET','POST']);
});

test('lifecycle setup counts the worst successful four polls and uses bounded cadence', async () => {
  const { createStageLifecycle } = await import('./fs-ent-pipeline/stage-context-lifecycle.mjs');
  const ctx={project:'fireemu-oracle-query',database:'entpipe2-20261029',stageContextDatabase:'entpipe2-20261029',target:{token:'fake-token',quotaProject:'fireemu-oracle-query'}};
  const name=`projects/${ctx.project}/databases/${ctx.database}`;let polls=0,calls=0,sleeps=0;
  const fetchFn=async (url,init)=>{calls++;let obj;if(url.endsWith('/databases'))obj={databases:[]};else if(init.method==='POST')obj={name:`${name}/operations/a`};else if(url.includes('/operations/'))obj={done:++polls===4};else obj={name,uid:'fake-uid',locationId:'us-central1',type:'FIRESTORE_NATIVE',databaseEdition:'ENTERPRISE',firestoreDataAccessMode:'DATA_ACCESS_MODE_ENABLED',deleteProtectionState:'DELETE_PROTECTION_DISABLED'};return {status:200,text:async()=>JSON.stringify(obj)}};
  const lifecycle=createStageLifecycle(ctx,{fetchFn,claim:async()=>{},journal:async()=>{},sleepFn:async ms=>{assert.equal(ms,5000);sleeps++;}});
  assert.deepEqual(await lifecycle.create(),{name,uid:'fake-uid'});assert.equal(calls,7);assert.equal(sleeps,3);
});

test('END checks identity and empty data, sends one delete, then waits ten minutes for typed absence', async () => {
  const { createStageLifecycle } = await import('./fs-ent-pipeline/stage-context-lifecycle.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'production',token:'fake-token',quotaProject:'fireemu-oracle-query'}});
  const name=`projects/${ctx.project}/databases/${ctx.database}`;let now=0,calls=0,polls=0;
  const fetchFn=async (url,init)=>{calls++;let status=200,obj;if(url.endsWith(':runQuery'))obj=[];else if(init.method==='DELETE')obj={name:`${name}/operations/d`};else if(url.includes('/operations/'))obj={done:++polls===5};else if(url.endsWith('/databases'))obj={databases:[]};else if(polls===5){status=404;obj={error:{code:404,status:'NOT_FOUND',message:`${name} missing`}};}else obj={name,uid:'fake-uid'};return {status,text:async()=>JSON.stringify(obj)}};
  const lifecycle=createStageLifecycle(ctx,{knownUid:'fake-uid',fetchFn,claim:async()=>{},journal:async()=>{},sleepFn:async()=>{},nowFn:()=>now});
  await lifecycle.end();await assert.rejects(lifecycle.confirmEnd(),/ten minutes/);now=600000;await lifecycle.confirmEnd();
  assert.equal(calls,10);await assert.rejects(lifecycle.end(),/sequence/);
});

test('END unknown deletion is sticky and cannot be resent', async () => {
  const { createStageLifecycle } = await import('./fs-ent-pipeline/stage-context-lifecycle.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'production',token:'fake-token',quotaProject:'fireemu-oracle-query'}});
  const name=`projects/${ctx.project}/databases/${ctx.database}`;let deletes=0;
  const fetchFn=async (url,init)=>{if(init.method==='DELETE'){deletes++;throw Error('lost');}return {status:200,text:async()=>JSON.stringify(url.endsWith(':runQuery')?[]:{name,uid:'fake-uid'})}};
  const lifecycle=createStageLifecycle(ctx,{knownUid:'fake-uid',fetchFn,claim:async()=>{},journal:async()=>{}});
  await assert.rejects(lifecycle.end(),/unknown/);await assert.rejects(lifecycle.end(),/sequence/);assert.equal(deletes,1);
});

test('identity, setup, two rounds and END consume 51 of 53 bounded service attempts', async () => {
  const { Worker } = await import('node:worker_threads');
  const { verifyStageProject } = await import('./fs-ent-pipeline/stage-context-identity.mjs');
  const { createStageBudget } = await import('./fs-ent-pipeline/stage-context-budget.mjs');
  const { createStageLifecycle } = await import('./fs-ent-pipeline/stage-context-lifecycle.mjs');
  const { createStageSupport } = await import('./fs-ent-pipeline/stage-context-support.mjs');
  const { runObservationWorker } = await import('./fs-ent-pipeline/stage-context-worker-client.mjs');
  const { runStageContextRounds } = await import('./fs-ent-pipeline/stage-context-rounds.mjs');
  const { stageContextSeed } = await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'production',token:'fake-token',quotaProject:'fireemu-oracle-query'}});
  const name=`projects/${ctx.project}/databases/${ctx.database}`,base=`${name}/documents/`;let created=false,seeded=false,deleted=false,cp=0,dp=0,now=0,rest=0,grpc=0;
  const fetchFn=async (url,init)=>{rest++;let status=200,obj;
    if(url.includes('cloudresourcemanager'))obj={name:'projects/123456',projectId:'fireemu-oracle-query'};
    else if(url.endsWith(':runQuery'))obj=seeded?stageContextSeed().map(([path])=>({document:{name:base+path}})):[];
    else if(url.endsWith(':commit')){seeded=Boolean(JSON.parse(init.body).writes[0].update);obj={};}
    else if(url.endsWith('/databases'))obj={databases:created&&!deleted?[{name}]:[]};
    else if(init.method==='POST'){created=true;obj={name:`${name}/operations/create`};}
    else if(init.method==='DELETE'){deleted=true;obj={name:`${name}/operations/delete`};}
    else if(url.endsWith('/operations/create'))obj={done:++cp===4};
    else if(url.endsWith('/operations/delete'))obj={done:++dp===5};
    else if(deleted){status=404;obj={error:{code:404,status:'NOT_FOUND',message:`${name} missing`}};}
    else obj={name,uid:'fake-uid',locationId:'us-central1',type:'FIRESTORE_NATIVE',databaseEdition:'ENTERPRISE',firestoreDataAccessMode:'DATA_ACCESS_MODE_ENABLED',deleteProtectionState:'DELETE_PROTECTION_DISABLED'};
    return {status,text:async()=>JSON.stringify(obj)};};
  const budget=createStageBudget({maximum:53,cleanupReserve:14}),journal=async()=>{},claim=budget.claim;
  await verifyStageProject(ctx,'123456',{fetchFn,claim,journal});
  const lifecycle=createStageLifecycle(ctx,{fetchFn,claim,journal,sleepFn:async()=>{},nowFn:()=>now});await lifecycle.create();
  const support=createStageSupport(ctx,{fetchFn,claim,journal});
  const workerFactory=(c,step)=>{grpc++;return new Worker(new URL('./fs-ent-pipeline/fixtures/stage-context-fake-worker.mjs',import.meta.url),{workerData:{ctx:c,stepId:step.id}});};
  await runStageContextRounds((op,detail)=>op==='observe'?runObservationWorker(ctx,detail.step,{claim,journal,workerFactory}):support.stageOperation(op,detail));
  await lifecycle.end();now=600000;await lifecycle.confirmEnd();
  assert.equal(rest,29);assert.equal(grpc,22);assert.equal(budget.used(),51);
  await budget.claim('recovery-read');await budget.claim('recovery-read');assert.equal(budget.used(),53);await assert.rejects(budget.claim('recovery-read'),/ceiling/);
});

test('inventory rejects malformed 200 instead of creating a database', async () => {
  const { createStageLifecycle } = await import('./fs-ent-pipeline/stage-context-lifecycle.mjs');
  const ctx={project:'fireemu-oracle-query',database:'entpipe2-20261029',stageContextDatabase:'entpipe2-20261029',target:{token:'fake-token',quotaProject:'fireemu-oracle-query'}};
  for(const body of [{error:{message:'bad'}},[],{databases:'bad'},{nextPageToken:'more'}]) {
    let calls=0;const lifecycle=createStageLifecycle(ctx,{fetchFn:async()=>{calls++;return {status:200,text:async()=>JSON.stringify(body)}},claim:async()=>{},journal:async()=>{}});
    await assert.rejects(lifecycle.create(),/inventory/);assert.equal(calls,1);
  }
});

test('END refuses a changed database UID before any delete', async () => {
  const { createStageLifecycle } = await import('./fs-ent-pipeline/stage-context-lifecycle.mjs');
  const { createStageContext } = await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'production',token:'fake-token',quotaProject:'fireemu-oracle-query'}});
  const name=`projects/${ctx.project}/databases/${ctx.database}`;let calls=0;
  const lifecycle=createStageLifecycle(ctx,{knownUid:'expected',fetchFn:async()=>{calls++;return {status:200,text:async()=>JSON.stringify({name,uid:'different'})}},claim:async()=>{},journal:async()=>{}});
  await assert.rejects(lifecycle.end(),/identity/);assert.equal(calls,1);
});

test('private journal is exclusive, durable per event, and refuses credential material', async () => {
  const { mkdtempSync, readFileSync, statSync, rmSync }=await import('node:fs');
  const { tmpdir }=await import('node:os');const { join }=await import('node:path');
  const { createStageJournal }=await import('./fs-ent-pipeline/stage-context-journal.mjs');
  const dir=mkdtempSync(join(tmpdir(),'stage-journal-')),path=join(dir,'events.jsonl');
  try {
    const journal=createStageJournal(path,'fake-secret-token');
    await journal.write({phase:'attempt',op:'seed'});
    assert.equal(JSON.parse(readFileSync(path,'utf8')).phase,'attempt');assert.equal(statSync(path).mode & 0o777,0o600);
    await assert.rejects(journal.write({body:'fake-secret-token'}),/secret/);
    assert.throws(()=>createStageJournal(path,'fake-secret-token'));
    journal.close();
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('campaign stops after uncertain create without launching any observation worker', async () => {
  const { runStageCampaign }=await import('./fs-ent-pipeline/stage-context-campaign.mjs');
  const { createStageContext }=await import('./fs-ent-pipeline/stage-context-target.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'production',token:'fake-token',quotaProject:'fireemu-oracle-query'}});
  let calls=0,workers=0;
  const fetchFn=async (url,init)=>{calls++;if(url.includes('cloudresourcemanager'))return {status:200,text:async()=>JSON.stringify({name:'projects/123456',projectId:'fireemu-oracle-query'})};if(init.method==='POST')throw Error('lost');return {status:200,text:async()=>'{"databases":[]}'}};
  await assert.rejects(runStageCampaign(ctx,{fetchFn,journal:async()=>{},workerFactory:()=>{workers++},expectedProjectNumber:'123456'}),/unknown/);
  assert.equal(calls,4);assert.equal(workers,0);
});

test('campaign executes maximum setup and both rounds while retaining database', async () => {
  const { Worker }=await import('node:worker_threads');const { runStageCampaign }=await import('./fs-ent-pipeline/stage-context-campaign.mjs');
  const { createStageContext }=await import('./fs-ent-pipeline/stage-context-target.mjs');const { stageContextSeed }=await import('./fs-ent-pipeline/stage-context-corpus.mjs');
  const ctx=createStageContext({run:1,database:'entpipe2-20261029',approvedDatabase:'entpipe2-20261029',target:{kind:'production',token:'fake-token',quotaProject:'fireemu-oracle-query'}});
  const name=`projects/${ctx.project}/databases/${ctx.database}`,base=`${name}/documents/`;let seeded=false,polls=0,deletes=0,grpc=0;
  const fetchFn=async (url,init)=>{let obj;if(url.includes('cloudresourcemanager'))obj={name:'projects/123456',projectId:'fireemu-oracle-query'};else if(url.endsWith(':runQuery'))obj=seeded?stageContextSeed().map(([path])=>({document:{name:base+path}})):[];else if(url.endsWith(':commit')){seeded=Boolean(JSON.parse(init.body).writes[0].update);obj={};}else if(url.endsWith('/databases'))obj={databases:[]};else if(init.method==='POST')obj={name:`${name}/operations/create`};else if(init.method==='DELETE'){deletes++;throw Error('unexpected delete');}else if(url.endsWith('/operations/create'))obj={done:++polls===4};else obj={name,uid:'fake-uid',locationId:'us-central1',type:'FIRESTORE_NATIVE',databaseEdition:'ENTERPRISE',firestoreDataAccessMode:'DATA_ACCESS_MODE_ENABLED',deleteProtectionState:'DELETE_PROTECTION_DISABLED'};return {status:200,text:async()=>JSON.stringify(obj)};};
  const workerFactory=(c,step)=>{grpc++;return new Worker(new URL('./fs-ent-pipeline/fixtures/stage-context-fake-worker.mjs',import.meta.url),{workerData:{ctx:c,stepId:step.id}});};
  const result=await runStageCampaign(ctx,{fetchFn,workerFactory,journal:async()=>{},sleepFn:async()=>{},expectedProjectNumber:'123456'});
  assert.equal(result.used,41);assert.equal(grpc,22);assert.equal(deletes,0);assert.equal(seeded,false);assert.equal(result.database.uid,'fake-uid');
});

test('project identity checks are bounded twice and fail before database mutation on mismatch', async () => {
  const { verifyStageProject }=await import('./fs-ent-pipeline/stage-context-identity.mjs');
  const ctx={project:'fireemu-oracle-query',target:{token:'fake-token',quotaProject:'fireemu-oracle-query'}};
  let calls=0;
  const fetchFn=async()=>{calls++;return {status:200,text:async()=>JSON.stringify({name:'projects/123456',projectId:'fireemu-oracle-query'})}};
  await verifyStageProject(ctx,'123456',{fetchFn,claim:async()=>{},journal:async()=>{}});assert.equal(calls,2);
  calls=0;await assert.rejects(verifyStageProject(ctx,'999999',{fetchFn,claim:async()=>{},journal:async()=>{}}),/identity/);assert.equal(calls,1);
});

test('separately admitted END carries the previously journaled service count', async () => {
  const { createStageBudget }=await import('./fs-ent-pipeline/stage-context-budget.mjs');
  const budget=createStageBudget({maximum:53,cleanupReserve:14,initialUsed:41});
  for(let i=0;i<10;i++)await budget.claim('end-poll');
  assert.equal(budget.used(),51);
  await assert.rejects(budget.claim('observe'),/reserve/);
  assert.throws(()=>createStageBudget({maximum:53,cleanupReserve:14,initialUsed:54}));
});

test('ADC acquisition claim is durable and prevents a second mint after failure', async () => {
  const {mkdtempSync,rmSync}=await import('node:fs');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
  const { acquireStageToken }=await import('./fs-ent-pipeline/stage-context-adc.mjs');
  const dir=mkdtempSync(join(tmpdir(),'stage-adc-')),marker=join(dir,'spent');let mints=0;
  try {
    assert.throws(()=>acquireStageToken({marker,packetSha256:'a'.repeat(64),gcloud:'/fake',env:{},mint:()=>{mints++;throw Error('failed')}}),/acquisition/);
    assert.throws(()=>acquireStageToken({marker,packetSha256:'a'.repeat(64),gcloud:'/fake',env:{},mint:()=>{mints++;return 'x'.repeat(25)}}));
    assert.equal(mints,1);
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('concurrent ADC callers permit only one fake mint', async () => {
  const {mkdtempSync,readFileSync,rmSync}=await import('node:fs');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const {spawn}=await import('node:child_process');
  const dir=mkdtempSync(join(tmpdir(),'stage-adc-race-')),marker=join(dir,'spent'),counter=join(dir,'count');
  const moduleUrl=new URL('./fs-ent-pipeline/stage-context-adc.mjs',import.meta.url).href;
  const code=`import {acquireStageToken} from ${JSON.stringify(moduleUrl)};import {appendFileSync} from 'node:fs';try{acquireStageToken({marker:process.argv[1],packetSha256:'a'.repeat(64),gcloud:'/fake',env:{},mint:()=>{appendFileSync(process.argv[2],'x');return 'x'.repeat(25)}})}catch{process.exitCode=2}`;
  const run=()=>new Promise(resolve=>{const c=spawn(process.execPath,['--input-type=module','-e',code,marker,counter],{stdio:'ignore'});c.on('close',resolve)});
  try {const codes=await Promise.all([run(),run()]);assert.deepEqual(codes.sort(),[0,2]);assert.equal(readFileSync(counter,'utf8'),'x');}finally{rmSync(dir,{recursive:true,force:true});}
});

test('ADC provider refuses credential override before creating a claim', async () => {
  const {mkdtempSync,existsSync,rmSync}=await import('node:fs');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const {acquireStageToken}=await import('./fs-ent-pipeline/stage-context-adc.mjs');
  const dir=mkdtempSync(join(tmpdir(),'stage-adc-env-')),marker=join(dir,'spent');let mints=0;
  try {assert.throws(()=>acquireStageToken({marker,packetSha256:'a'.repeat(64),gcloud:'/fake',env:{GOOGLE_APPLICATION_CREDENTIALS:'private'},mint:()=>{mints++;return 'x'.repeat(25)}}),/environment/);assert.equal(mints,0);assert.equal(existsSync(marker),false);}finally{rmSync(dir,{recursive:true,force:true});}
});
