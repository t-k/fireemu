import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createTestWorld, withTestWorld } from '../fireemu/testing.mjs';

const binary = process.env.FIREEMU_TEST_BINARY;
const native = { skip: !binary, timeout: 30_000 };
const options = { binaryPath: binary, env:{...process.env,NODE_PATH:''}, projectId: 'demo-test-worlds', clockStart: '2026-01-31T23:59:00Z', services: ['auth','firestore'], config: { schemaVersion:1, firestore:{edition:'standard',backend:'native'} } };

test('startup failure removes private directories and leaves parent environment unchanged', async () => {
  const parent = {...process.env};
  const root = await mkdtemp(join(tmpdir(),'fireemu-world-failure-'));
  try {
    await assert.rejects(createTestWorld({...options,binaryPath:join(root,'missing'),tempRoot:root}), /start|ENOENT/);
    const {readdir} = await import('node:fs/promises');
    assert.deepEqual(await readdir(root),[]);
    assert.deepEqual({...process.env},parent);
  } finally { await rm(root,{recursive:true,force:true}); }
});

test('three worlds with one project isolate data, clock and reset generations', native, async (t) => {
  const parent = {...process.env};
  const worlds = await Promise.all([createTestWorld(options),createTestWorld(options),createTestWorld(options)]);
  t.after(async()=>{await Promise.all(worlds.map(w=>w.dispose()));});
  const [a,b,c]=worlds;
  assert.equal(new Set(worlds.map(w=>w.endpoints.control.port)).size,3);
  assert.equal(new Set(worlds.map(w=>w.id)).size,3);
  await Promise.all(worlds.map((world,index)=>world.run(process.execPath,['-e',`fetch('http://'+process.env.FIRESTORE_EMULATOR_HOST+'/v1/projects/'+process.env.GCLOUD_PROJECT+'/databases/(default)/documents/isolated/item',{method:'PATCH',headers:{'content-type':'application/json',authorization:'Bearer owner'},body:JSON.stringify({fields:{value:{integerValue:'${index}'}}})}).then(r=>{if(!r.ok)throw Error('write '+r.status)})`])));
  const read=async w=>(await (await fetch(`http://${w.endpoints.firestore.host}:${w.endpoints.firestore.port}/v1/projects/demo-test-worlds/databases/(default)/documents/isolated/item`,{headers:{authorization:'Bearer owner'}})).json()).fields?.value?.integerValue;
  assert.deepEqual(await Promise.all(worlds.map(read)),['0','1','2']);
  const before = await b.clock.get();
  const generation = c.generation;
  const oldEndpoint = c.endpoints.control;
  await Promise.all([a.clock.advance({seconds:86400}),c.reset()]);
  assert.deepEqual(await b.clock.get(),before);
  assert.equal(c.generation,generation+1);
  assert.notDeepEqual(c.endpoints.control,oldEndpoint);
  assert.deepEqual(await Promise.all(worlds.map(read)),['0','1',undefined]);
  assert.deepEqual({...process.env},parent);
  const roots=worlds.map(w=>w.directory);
  await Promise.all(worlds.map(w=>w.dispose()));
  await Promise.all(worlds.map(w=>w.dispose()));
  for(const root of roots)await assert.rejects(stat(root),{code:'ENOENT'});
});

test('withTestWorld disposes after callback failure', native, async()=>{
  let directory;
  await assert.rejects(withTestWorld(options,async world=>{directory=world.directory;throw Error('callback failed');}),/callback failed/);
  await assert.rejects(stat(directory),{code:'ENOENT'});
});

test('command options cannot override the owning world SDK routes', native, async()=>{
  await withTestWorld(options,async world=>{
    const result=await world.run(process.execPath,['-e',"console.log(JSON.stringify({host:process.env.FIRESTORE_EMULATOR_HOST,project:process.env.GCLOUD_PROJECT,id:process.env.FIREEMU_TEST_WORLD_ID}))"],{env:{FIRESTORE_EMULATOR_HOST:'wrong.invalid:1',GCLOUD_PROJECT:'wrong-project',FIREEMU_TEST_WORLD_ID:'wrong-world'}});
    assert.deepEqual(JSON.parse(result.stdout),{host:world.environment.FIRESTORE_EMULATOR_HOST,project:world.projectId,id:world.id});
  });
});

test('a successful command joins its child after the command leader exits', native, async()=>{
  await withTestWorld(options,async world=>{
    const result=await world.run(process.execPath,['-e',"const child=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});console.log(child.pid);process.exit(0)"]);
    const pid=Number(result.stdout.trim());
    assert.ok(Number.isSafeInteger(pid)&&pid>1);
    assert.throws(()=>process.kill(pid,0),{code:'ESRCH'});
  });
});

test('real Admin SDK children route identical project and user IDs to independent worlds', {skip:!binary||!process.env.FIREEMU_TEST_SDK_MODULES,timeout:30_000}, async(t)=>{
  const settings={...options,env:{...options.env,FIREBASE_CONFIG:JSON.stringify({projectId:'wrong-inherited-project',storageBucket:'wrong-bucket'})}};
  const worlds=await Promise.all([createTestWorld(settings),createTestWorld(settings)]);
  t.after(async()=>{await Promise.all(worlds.map(world=>world.dispose()));});
  await worlds[0].clock.advance({seconds:86400});
  const script=`
    const load=require('node:module').createRequire(require('node:path').join(process.env.SDK_MODULES,'../package.json'));
    const {initializeApp,deleteApp}=load('firebase-admin/app');
    const {getFirestore,FieldValue}=load('firebase-admin/firestore');
    const {getAuth}=load('firebase-admin/auth');
    (async()=>{
      const app=initializeApp(undefined,process.env.FIREEMU_TEST_WORLD_ID);
      if(app.options.projectId!==process.env.GCLOUD_PROJECT)throw Error('SDK app inherited another world configuration');
      const db=getFirestore(app),ref=db.doc('sdk/item');
      await getAuth(app).createUser({uid:'same-sdk-user'});
      await ref.set({marker:process.env.MARKER,at:FieldValue.serverTimestamp()});
      const value=(await ref.get()).data();
      console.log(JSON.stringify({marker:value.marker,at:value.at.toMillis()}));
      await deleteApp(app);
    })().catch(error=>{console.error(error);process.exitCode=1});
  `;
  const replies=await Promise.all(worlds.map((world,index)=>world.run(process.execPath,['-e',script],{env:{SDK_MODULES:process.env.FIREEMU_TEST_SDK_MODULES,MARKER:String(index),FIREBASE_CONFIG:settings.env.FIREBASE_CONFIG}})));
  const values=replies.map(reply=>JSON.parse(reply.stdout.trim()));
  assert.deepEqual(values.map(value=>value.marker),['0','1']);
  assert.equal(values[0].at-values[1].at,86400_000);
});

test('Functions snapshots own dependencies and reset keeps creation bytes', async()=>{
  const {snapshotInputs,prepareGeneration}=await import('../fireemu/testing-snapshot.mjs');
  const {mkdir,symlink}=await import('node:fs/promises');
  const root=await mkdtemp(join(tmpdir(),'fireemu-world-snapshot-'));
  try{
    const source=join(root,'source'),dependency=join(root,'dependency');
    await mkdir(join(source,'node_modules'),{recursive:true});await mkdir(dependency);
    await writeFile(join(source,'index.cjs'),'creation source');
    await writeFile(join(dependency,'index.cjs'),'creation dependency');
    await symlink(dependency,join(source,'node_modules','dependency'),process.platform==='win32'?'junction':'dir');
    const worldRoot=join(root,'world');await mkdir(worldRoot);
    const snapshot=await snapshotInputs({functionsSource:source},worldRoot);
    await writeFile(join(source,'index.cjs'),'caller mutation');
    await writeFile(join(dependency,'index.cjs'),'caller dependency mutation');
    const generation=await prepareGeneration(snapshot,join(worldRoot,'generation'));
    const config=JSON.parse(await readFile(generation.configPath,'utf8'));
    assert.equal(await readFile(join(config.functions.source,'index.cjs'),'utf8'),'creation source');
    assert.equal(await readFile(join(config.functions.source,'node_modules','dependency','index.cjs'),'utf8'),'creation dependency');
    await writeFile(join(config.functions.source,'node_modules','dependency','index.cjs'),'generation mutation');
    const reset=await prepareGeneration(snapshot,join(worldRoot,'reset'));
    const resetConfig=JSON.parse(await readFile(reset.configPath,'utf8'));
    assert.equal(await readFile(join(resetConfig.functions.source,'node_modules','dependency','index.cjs'),'utf8'),'creation dependency');
  }finally{await rm(root,{recursive:true,force:true});}
});

test('dispose joins a child command and its inherited-pipe grandchild', native, async()=>{
  const world=await createTestWorld(options);
  const command=world.run(process.execPath,['-e',`require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'});console.log('grandchild started');setInterval(()=>{},1000)`]);
  const settled=assert.rejects(command,/retired/);
  await new Promise(resolve=>setTimeout(resolve,100));
  await world.dispose();
  await settled;
});

test('snapshotted pnpm packages retain private sibling dependency resolution', async()=>{
  const {snapshotInputs,prepareGeneration}=await import('../fireemu/testing-snapshot.mjs');
  const {mkdir,symlink}=await import('node:fs/promises');
  const {createRequire}=await import('node:module');
  const root=await mkdtemp(join(tmpdir(),'fireemu-world-pnpm-'));
  try{
    const source=join(root,'source'),modules=join(root,'store','node_modules');
    await mkdir(join(source,'node_modules'),{recursive:true});
    for(const name of ['sdk','sibling']){
      await mkdir(join(modules,name),{recursive:true});
      await writeFile(join(modules,name,'package.json'),JSON.stringify({main:'index.cjs'}));
    }
    await writeFile(join(modules,'sdk','index.cjs'),"module.exports=require('sibling')");
    await writeFile(join(modules,'sibling','index.cjs'),"module.exports='creation dependency'");
    await symlink(join(modules,'sdk'),join(source,'node_modules','sdk'),process.platform==='win32'?'junction':'dir');
    const worldRoot=join(root,'world');await mkdir(worldRoot);
    const snapshot=await snapshotInputs({functionsSource:source},worldRoot);
    await writeFile(join(modules,'sibling','index.cjs'),"module.exports='caller mutation'");
    const prepared=await prepareGeneration(snapshot,join(worldRoot,'generation'));
    const config=JSON.parse(await readFile(prepared.configPath,'utf8'));
    const load=createRequire(join(config.functions.source,'package.json'));
    assert.equal(load('sdk'),'creation dependency');
    await writeFile(load.resolve('sibling',{paths:[load.resolve('sdk')]}),"module.exports='generation mutation'");
    const reset=await prepareGeneration(snapshot,join(worldRoot,'reset'));
    const resetConfig=JSON.parse(await readFile(reset.configPath,'utf8'));
    assert.equal(createRequire(join(resetConfig.functions.source,'package.json'))('sdk'),'creation dependency');
  }finally{await rm(root,{recursive:true,force:true});}
});

test('Functions snapshots retain ancestor node_modules without caller-owned paths', async()=>{
  const {snapshotInputs,prepareGeneration}=await import('../fireemu/testing-snapshot.mjs');
  const {mkdir}=await import('node:fs/promises');
  const {createRequire}=await import('node:module');
  const root=await mkdtemp(join(tmpdir(),'fireemu-world-workspace-'));
  try{
    const source=join(root,'workspace','functions'),dependency=join(root,'node_modules','dependency');
    await mkdir(source,{recursive:true});await mkdir(dependency,{recursive:true});
    await writeFile(join(source,'index.cjs'),"module.exports=require('dependency')");
    await writeFile(join(dependency,'package.json'),JSON.stringify({main:'index.cjs'}));
    await writeFile(join(dependency,'index.cjs'),"module.exports='creation dependency'");
    const worldRoot=join(root,'world');await mkdir(worldRoot);
    const snapshot=await snapshotInputs({functionsSource:source},worldRoot);
    await writeFile(join(dependency,'index.cjs'),"module.exports='caller mutation'");
    const prepared=await prepareGeneration(snapshot,join(worldRoot,'generation'));
    const config=JSON.parse(await readFile(prepared.configPath,'utf8'));
    assert.equal(createRequire(join(config.functions.source,'package.json'))('./index.cjs'),'creation dependency');
  }finally{await rm(root,{recursive:true,force:true});}
});

test('NODE_PATH dependencies are private and reset retains their creation bytes', async()=>{
  const {snapshotInputs,prepareGeneration}=await import('../fireemu/testing-snapshot.mjs');
  const {mkdir}=await import('node:fs/promises');
  const {promisify}=await import('node:util');
  const exec=promisify((await import('node:child_process')).execFile);
  const root=await mkdtemp(join(tmpdir(),'fireemu-world-node-path-'));
  try{
    const source=join(root,'source'),modules=join(root,'global-modules'),dependency=join(modules,'path-only');
    await mkdir(source);await mkdir(dependency,{recursive:true});
    await writeFile(join(source,'index.cjs'),"module.exports=require('path-only')");
    await writeFile(join(dependency,'package.json'),JSON.stringify({main:'index.cjs'}));
    await writeFile(join(dependency,'index.cjs'),"module.exports='creation dependency'");
    const worldRoot=join(root,'world');await mkdir(worldRoot);
    const snapshot=await snapshotInputs({functionsSource:source,env:{NODE_PATH:modules}},worldRoot);
    await writeFile(join(dependency,'index.cjs'),"module.exports='caller mutation'");
    for(const name of ['generation','reset']){
      const prepared=await prepareGeneration(snapshot,join(worldRoot,name));
      const config=JSON.parse(await readFile(prepared.configPath,'utf8'));
      const reply=await exec(process.execPath,['-e',`console.log(require(${JSON.stringify(join(config.functions.source,'index.cjs'))}))`],{env:{...process.env,NODE_PATH:prepared.nodePath??modules}});
      assert.equal(reply.stdout.trim(),'creation dependency');
    }
  }finally{await rm(root,{recursive:true,force:true});}
});

test('commands cannot inject emulator routes for unselected services', native, async()=>{
  await withTestWorld({...options,services:['auth']},async world=>{
    const result=await world.run(process.execPath,['-e',"if(process.env.FIRESTORE_EMULATOR_HOST)throw Error('unselected route escaped');if(JSON.parse(process.env.FIREBASE_CONFIG).projectId!==process.env.GCLOUD_PROJECT)throw Error('wrong config')"],{env:{FIRESTORE_EMULATOR_HOST:'wrong.invalid:1',FIREBASE_CONFIG:'{"projectId":"wrong"}'}});
    assert.equal(result.code,0);
  });
});

test('a command retirement failure still stops the daemon and permits cleanup retry', {...native,timeout:30_000}, async(t)=>{
  if(process.platform==='win32')return t.skip('Unix detached-pipe failure fixture');
  const {execFileSync}=await import('node:child_process');
  const root=await mkdtemp(join(tmpdir(),'fireemu-world-retirement-'));
  const world=await createTestWorld(options);
  const descriptor=JSON.parse(await readFile(join(world.directory,'generation-1','ready.json'),'utf8'));
  const pidFile=join(root,'pid');
  let escapedPid;
  const stopOwned=(pid,marker)=>{
    try{
      const identity=execFileSync('/bin/ps',['-o','comm=','-o','args=','-p',String(pid)],{encoding:'utf8'});
      assert.ok(identity.includes(marker));
      process.kill(pid,'SIGKILL');
    }catch(error){if(error.code!=='ESRCH'&&error.status!==1)throw error;}
  };
  t.after(async()=>{
    if(escapedPid)stopOwned(escapedPid,pidFile);
    try{await world.dispose();}finally{
      stopOwned(descriptor.pid,world.directory);
      await rm(root,{recursive:true,force:true});
    }
  });
  const script=`const child=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)',${JSON.stringify(pidFile)}],{detached:true,stdio:['ignore','inherit','inherit']});require('node:fs').writeFileSync(${JSON.stringify(pidFile)},String(child.pid));process.exit(0)`;
  const command=world.run(process.execPath,['-e',script]);
  const joined=assert.rejects(command,/retired/);
  for(let count=0;count<100;count++){
    try{escapedPid=Number(await readFile(pidFile,'utf8'));break;}catch(error){if(error.code!=='ENOENT')throw error;}
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  assert.ok(Number.isSafeInteger(escapedPid)&&escapedPid>1);
  await assert.rejects(world.dispose(),/close|retirement/);
  assert.throws(()=>process.kill(descriptor.pid,0),{code:'ESRCH'});
  stopOwned(escapedPid,pidFile);escapedPid=undefined;
  await joined;
  await world.dispose();
  await assert.rejects(stat(world.directory),{code:'ENOENT'});
});

test('real Functions imports, trial boundaries, Rules and module globals belong to each world', {...native,timeout:process.env.FIREEMU_TEST_SDK_MODULES?180_000:30_000}, async(t)=>{
  const {mkdir,symlink}=await import('node:fs/promises');
  const root=await mkdtemp(join(tmpdir(),'fireemu-functions-worlds-'));
  t.after(async()=>{await rm(root,{recursive:true,force:true});});
  const source=join(root,'functions');await mkdir(source);
  await writeFile(join(source,'package.json'),JSON.stringify({main:'index.cjs'}));
  if(process.env.FIREEMU_TEST_SDK_MODULES)await symlink(process.env.FIREEMU_TEST_SDK_MODULES,join(source,'node_modules'),process.platform==='win32'?'junction':'dir');
  else{
    // The default fixture isolates clock/lifecycle behavior from SDK installation.
    await mkdir(join(source,'node_modules','express'),{recursive:true});
    await writeFile(join(source,'node_modules','express','package.json'),JSON.stringify({name:'express',version:'5.0.0',main:'index.cjs'}));
    await writeFile(join(source,'node_modules','express','index.cjs'),`module.exports=function(){let handler;const app=(req,res)=>{let body='';req.on('data',c=>body+=c);req.on('end',()=>{req.body=JSON.parse(body||'{}');const p=req.url.split('?')[0].split('/');req.params={project:p[1],region:p[2],name:p[3]};req.get=name=>req.headers[name.toLowerCase()];res.status=code=>{res.statusCode=code;return res;};res.send=value=>res.end(String(value));res.json=value=>res.end(JSON.stringify(value));handler(req,res,()=>{});});};app.use=()=>{};app.all=(_path,fn)=>handler=fn;return app;};for(const name of ['json','text','urlencoded','raw'])module.exports[name]=()=>()=>{};`);
  }
  const expiry=Date.parse('2026-02-01T00:00:00Z');
  const code=marker=>`
    const imported=Date.now();let hits=0,scheduled=0,taskAttempts=0;
    const api=async(req,res)=>{res.setHeader('content-type','application/json');res.end(JSON.stringify({marker:${JSON.stringify(marker)},imported,now:Date.now(),date:+new Date(),usable:Date.now()<${expiry},hits:++hits,scheduled,taskAttempts,runnerPid:process.pid}));};
    api.__endpoint={platform:'gcfv2',httpsTrigger:{}};
    const schedule=async()=>{scheduled++;await fetch('http://'+process.env.FIRESTORE_EMULATOR_HOST+'/v1/projects/'+process.env.GCLOUD_PROJECT+'/databases/(default)/documents/scheduled/item',{method:'PATCH',headers:{'content-type':'application/json',authorization:'Bearer owner'},body:JSON.stringify({fields:{now:{integerValue:String(Date.now())}}})});};
    schedule.run=schedule;schedule.__endpoint={platform:'gcfv2',scheduleTrigger:{schedule:'every 1 minutes'}};
    const task=async(req,res)=>{taskAttempts++;res.statusCode=taskAttempts===1?503:200;res.end('task');};
    task.__endpoint={platform:'gcfv2',taskQueueTrigger:{retryConfig:{maxAttempts:3,minBackoffSeconds:2,maxBackoffSeconds:2,maxDoublings:0},rateLimits:{maxConcurrentDispatches:1,maxDispatchesPerSecond:100}}};
    const timer=async(req,res)=>{await new Promise(resolve=>setTimeout(resolve,100));res.end('done');};
    timer.__endpoint={platform:'gcfv2',httpsTrigger:{}};
    const blocked=()=>{while(true){}};blocked.__endpoint={platform:'gcfv2',httpsTrigger:{}};
    module.exports={api,schedule,task,timer,blocked};
  `;
  const worlds=[];
  t.after(async()=>{await Promise.all(worlds.map(w=>w.dispose()));});
  for(const marker of ['A','B','C']){
    await writeFile(join(source,'index.cjs'),code(marker));
    const world=await createTestWorld({...options,clockStart:'2026-01-31T23:59:59.999Z',functionsSource:source,services:['auth','firestore','functions'],clock:{timers:'virtual'},shutdownTimeoutMs:20,env:{...options.env,FIREEMU_RUNNER_NODE:new URL('../../tools/runner-node/index.mjs',import.meta.url).pathname}});
    worlds.push(world);
  }
  const [a,b,c]=worlds;
  const query=async world=>{
    const response=await fetch(`${world.endpoints.functions.url}/${world.projectId}/us-central1/api`);
    assert.equal(response.status,200,await response.clone().text());return response.json();
  };
  const initial=await Promise.all(worlds.map(query));
  assert.deepEqual(initial.map(value=>value.marker),['A','B','C']);
  assert.ok(initial.every(value=>value.usable&&value.now===expiry-1&&value.date===expiry-1&&value.imported===expiry-1));
  const allow="rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if true; } } }";
  const deny=allow.replace('if true','if false');
  await Promise.all([a.control('PUT','/v1/rules',{source:allow}),b.control('PUT','/v1/rules',{source:deny}),c.control('PUT','/v1/rules',{source:allow})]);
  await Promise.all([a.clock.advance(1),c.reset()]);
  const after=await Promise.all(worlds.map(query));
  assert.equal(after[0].now,expiry);assert.equal(after[0].usable,false);
  assert.equal(after[1].now,expiry-1);assert.equal(after[1].usable,true);
  assert.equal(after[1].hits,2);assert.equal(after[2].hits,1);assert.equal(after[2].marker,'C');
  await a.clock.advance(1);assert.equal((await query(a)).now,expiry+1);
  const rules=await Promise.all(worlds.map(world=>world.control('GET','/v1/rules')));
  assert.ok(JSON.stringify(rules[0]).includes('if true'));assert.ok(JSON.stringify(rules[1]).includes('if false'));assert.equal(rules[2].loaded,false);
  const readScheduled=async world=>fetch(`${world.endpoints.firestore.url}/v1/projects/${world.projectId}/databases/(default)/documents/scheduled/item`,{headers:{authorization:'Bearer owner'}});
  for(let count=0;count<100;count++){if((await readScheduled(a)).status===200)break;await new Promise(resolve=>setTimeout(resolve,10));}
  const written=await (await readScheduled(a)).json();assert.equal(written.fields.now.integerValue,String(expiry));
  assert.equal((await readScheduled(b)).status,404);
  assert.equal((await query(b)).scheduled,0);
  const start=(await query(a)).now;
  const taskResponse=await fetch(`${a.endpoints.tasks.url}/projects/${a.projectId}/locations/us-central1/queues/task/tasks`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({task:{name:'clock-boundary',scheduleTime:new Date(start+1000).toISOString(),httpRequest:{url:'',body:Buffer.from(JSON.stringify({data:{}})).toString('base64')}}})});
  assert.equal(taskResponse.status,200,await taskResponse.text());
  await a.clock.advance(999);await new Promise(resolve=>setTimeout(resolve,50));assert.equal((await query(a)).taskAttempts,0);
  await a.clock.advance(1);
  const attempts=async expected=>{for(let count=0;count<100;count++){if((await query(a)).taskAttempts===expected)return;await new Promise(resolve=>setTimeout(resolve,10));}assert.fail(`task attempts did not reach ${expected}`);};
  await attempts(1);await new Promise(resolve=>setTimeout(resolve,50));assert.equal((await query(a)).taskAttempts,1);
  await a.clock.advance(1999);assert.equal((await query(a)).taskAttempts,1);
  await a.clock.advance(1);await attempts(2);
  assert.equal((await query(b)).taskAttempts,0);
  const timerUrl=`${a.endpoints.functions.url}/${a.projectId}/us-central1/timer`;
  const timer=fetch(timerUrl);let timerFinished=false;
  timer.then(()=>{timerFinished=true;});
  await new Promise(resolve=>setTimeout(resolve,50));
  await a.clock.advance(99);await a.clock.runDue();assert.equal(timerFinished,false);
  await a.clock.advance(1);await a.clock.runDue();assert.equal(await (await timer).text(),'done');
  const pending=fetch(`${c.endpoints.functions.url}/${c.projectId}/us-central1/timer`);
  const retired=pending.then(response=>assert.ok(response.status>=500),()=>{});
  await new Promise(resolve=>setTimeout(resolve,50));
  await c.reset();await retired;
  assert.equal((await query(c)).hits,1);
  // Force daemon retirement while the runner cannot process shutdown or stdin closure.
  const runnerPid=(await query(a)).runnerPid;
  const blocked=fetch(`${a.endpoints.functions.url}/${a.projectId}/us-central1/blocked`);
  const closed=blocked.then(response=>assert.ok(response.status>=500),()=>{});
  await new Promise(resolve=>setTimeout(resolve,50));
  await a.dispose();await closed;
  for(let count=0;count<100;count++){
    try{process.kill(runnerPid,0);}catch(error){assert.equal(error.code,'ESRCH');return;}
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  assert.fail('blocked runner survived forced world retirement');
});
