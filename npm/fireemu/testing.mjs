// A test world owns a daemon, private input snapshots and generation-scoped clients.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { resolveBinary, ensureExecutable } from './binary.mjs';
import { snapshotInputs, prepareGeneration } from './testing-snapshot.mjs';

const endpointVariables = {firestore:'FIRESTORE_EMULATOR_HOST',auth:'FIREBASE_AUTH_EMULATOR_HOST',storage:'FIREBASE_STORAGE_EMULATOR_HOST',functions:'FIREEMU_FUNCTIONS_HOST',eventarc:'CLOUD_EVENTARC_EMULATOR_HOST',tasks:'CLOUD_TASKS_EMULATOR_HOST',pubsub:'PUBSUB_EMULATOR_HOST',hub:'FIREBASE_EMULATOR_HUB',logging:'FIREBASE_LOGGING_EMULATOR_HOST'};
const emulatorVariables = new Set([...Object.values(endpointVariables),'FIREBASE_CONFIG','NODE_PATH','FIREBASE_FIRESTORE_EMULATOR_ADDRESS','STORAGE_EMULATOR_HOST','FIREEMU_CONTROL_TOKEN','FIREEMU_CONTROL_URL','FIREEMU_APP_CHECK_EMULATOR_HOST','FIREEMU_APP_CHECK_JWKS_URL','FIREEMU_APP_CHECK_DEBUG_TOKEN_URL','FIREBASE_DATABASE_EMULATOR_HOST']);
const emptyEnvironment=base=>Object.fromEntries(Object.entries(base).filter(([name])=>!emulatorVariables.has(name)));

function supervise(command,args,options){
  const child=spawn(command,args,{...options,stdio:options.stdio??['ignore','pipe','pipe'],windowsHide:true,detached:process.platform!=='win32'});
  let output='',errorOutput='',result,commandResult;
  if(options.commandOwner)child.on('message',message=>{if(message?.type==='command-exit')commandResult=message;});
  child.stdin?.on('error',()=>{});
  child.stdout?.on('data',data=>{output=(output+data).slice(-65536);});
  child.stderr?.on('data',data=>{errorOutput=(errorOutput+data).slice(-65536);});
  const exited=new Promise(resolve=>{
    child.once('error',error=>{result={error};resolve(result);});
    child.once('close',(code,signal)=>{result??=commandResult?.error?{error:Error(commandResult.error)}:commandResult??{code,signal};resolve(result);});
  });
  return {child,exited,result:()=>result,output:()=>output,errorOutput:()=>errorOutput};
}
async function stop(process,timeout=5000){
  if(!process||process.result())return;
  const signal=kind=>{if(process.result())return;try{if(globalThis.process.platform==='win32')process.child.kill(kind);else globalThis.process.kill(-process.child.pid,kind);}catch(error){if(error.code!=='ESRCH')throw error;}};
  process.child.stdin?.end();
  signal('SIGTERM');
  let timer;
  const grace=new Promise(resolve=>{timer=setTimeout(()=>resolve(false),timeout);});
  const retired=await Promise.race([process.exited.then(()=>true),grace]);
  clearTimeout(timer);
  if(!retired){
    signal('SIGKILL');
    const forced=new Promise(resolve=>{timer=setTimeout(()=>resolve(false),5000);});
    const closed=await Promise.race([process.exited.then(()=>true),forced]);
    clearTimeout(timer);
    if(!closed)throw Error('test world process tree did not close after forced retirement');
  }
}
function endpoints(descriptor){
  const result={};
  const decode=value=>{const url=new URL(value.includes('://')?value:`http://${value}`);return Object.freeze({host:url.hostname,port:Number(url.port),url:`${url.protocol}//${url.host}`});};
  result.control=decode(descriptor.controlUrl);
  for(const [service,name] of Object.entries(endpointVariables))if(descriptor.environment[name])result[service]=decode(descriptor.environment[name]);
  return Object.freeze(result);
}

/** Create an independent emulator world; no method changes the parent's environment. */
export async function createTestWorld(options={}){
  options={...options,config:typeof options.config==='object'?structuredClone(options.config):options.config,services:options.services?[...options.services]:undefined,env:{...(options.env??process.env)},clock:options.clock?{...options.clock}:undefined};
  const binary=resolveBinary(options.binaryPath?resolve(options.binaryPath):undefined);
  if(!binary)throw Error('fireemu could not start a test world: install the platform package or supply binaryPath');
  const timeout=options.startupTimeoutMs??60_000;
  if(!Number.isSafeInteger(timeout)||timeout<=0)throw TypeError('startupTimeoutMs must be a positive integer');
  let services=options.services;
  if(services&&(!Array.isArray(services)||!services.length||services.some(name=>typeof name!=='string'||! /^(auth|firestore|storage|functions(?::[A-Za-z0-9_-]+)?|pubsub|appcheck)$/.test(name))))throw TypeError('services must name supported test-world services');
  const id=randomUUID();
  const directory=await mkdtemp(join(resolve(options.tempRoot??tmpdir()),'fireemu-world-'));
  let snapshot,current,tail=Promise.resolve(),closing=false,disposed=false,generation=0;
  const clients=new Set();
  const retiring=new Set();
  const enqueue=operation=>{const job=tail.then(operation);tail=job.catch(()=>{});return job;};
  const check=()=>{if(closing||disposed)throw Error('test world is disposed');if(!current?.descriptor||current.process.result())throw Error('test world generation is unavailable');};
  const retire=async()=>{
    if(current)retiring.add(current);
    current=undefined;
    const clientResults=await Promise.allSettled([...clients].map(async client=>{await stop(client);clients.delete(client);}));
    const daemonResults=await Promise.allSettled([...retiring].map(async active=>{
      await stop(active.process,options.shutdownTimeoutMs??5000);
      if(!clients.size){await rm(active.directory,{recursive:true,force:true});retiring.delete(active);}
    }));
    const failures=[...clientResults,...daemonResults].filter(result=>result.status==='rejected').map(result=>result.reason);
    if(failures.length)throw new AggregateError(failures,'test world retirement failed; cleanup can be retried');
  };
  const requestFor=async(active,method,path,body,signal)=>{
    const response=await fetch(`${active.descriptor.controlUrl}${path}`,{method,headers:{authorization:`Bearer ${active.descriptor.controlToken}`,...(body===undefined?{}:{'content-type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),signal:signal??AbortSignal.timeout(options.requestTimeoutMs??10_000)});
    const value=await response.json();
    if(!response.ok)throw Error(`test world control ${response.status}: ${value.error?.message??JSON.stringify(value)}`);
    return value;
  };
  const start=async()=>{
    options.signal?.throwIfAborted();
    const next=generation+1;
    const generationDirectory=join(directory,`generation-${next}`);
    const prepared=await prepareGeneration(snapshot,generationDirectory);
    const readyFile=join(generationDirectory,'ready.json');
    const args=['up','--config',prepared.configPath,'--project',snapshot.config.daemon.authProject,'--only',services.join(','),'--ready-file',readyFile,'--owner-stdin','--log-verbosity','quiet'];
    for(const name of ['firestore','http','storage','functions','eventarc','tasks','pubsub','hub','ui','logging'])args.push(`--${name}-port`,'0');
    if(prepared.seed)args.push('--import',prepared.seed);
    const temporary=join(generationDirectory,'tmp');
    const environment={...emptyEnvironment(options.env??process.env),NODE_PATH:prepared.nodePath,TMPDIR:temporary,TEMP:temporary,TMP:temporary,FIREEMU_TEST_WORLD_ID:id,FIREEMU_TEST_WORLD_GENERATION:String(next)};
    ensureExecutable(binary.path);
    const daemon=supervise(binary.path,args,{cwd:prepared.cwd,env:environment,stdio:['pipe','pipe','pipe']});
    const active={process:daemon,directory:generationDirectory};current=active;
    const deadline=Date.now()+timeout;
    try{
      while(Date.now()<deadline){
        options.signal?.throwIfAborted();
        if(daemon.result())throw Error(`fireemu could not start test world: ${daemon.result().error?.message??daemon.errorOutput()??'daemon exited'}`);
        try{
          const descriptor=JSON.parse(await readFile(readyFile,'utf8'));
          if(descriptor.schemaVersion!==1||descriptor.pid!==daemon.child.pid||descriptor.projectId!==snapshot.config.daemon.authProject)throw Error('invalid test-world readiness descriptor');
          active.descriptor=descriptor;
          await requestFor(active,'GET','/health/ready',undefined,AbortSignal.timeout(Math.min(1000,timeout)));
          if(daemon.result())throw Error('daemon exited during test-world readiness');
          active.endpoints=endpoints(descriptor);
          active.environment=Object.freeze({...descriptor.environment,NODE_PATH:prepared.nodePath,TMPDIR:temporary,TEMP:temporary,TMP:temporary,FIREEMU_TEST_WORLD_ID:id,FIREEMU_TEST_WORLD_GENERATION:String(next)});
          generation=next;
          return;
        }catch(error){if(error.code!=='ENOENT'&&!(error instanceof SyntaxError)&&error.name!=='TimeoutError'&&error.name!=='TypeError')throw error;}
        await delay(10);
      }
      throw Error('fireemu test-world startup timed out');
    }catch(error){await retire();throw error;}
  };
  const control=(method,path,body)=>enqueue(async()=>{check();return requestFor(current,method,path,body);});
  const world={
    get generation(){return generation;},
    get endpoints(){check();return current.endpoints;},
    get environment(){check();return current.environment;},
    get directory(){return directory;},
    control,
    clock:Object.freeze({
      get:()=>control('GET','/v1/sessions/default'),
      set:(instant,{allowBackwards=false}={})=>control('POST','/v1/sessions/default/clock:set',{instant,allowBackwards}),
      advance:duration=>control('POST','/v1/sessions/default/clock:advance',typeof duration==='number'?{millis:duration}:duration),
      advanceTo:instant=>control('POST','/v1/sessions/default/clock:advanceTo',{instant}),
      runDue:(budget=1000)=>control('POST','/v1/sessions/default/clock:runDue',{budget}),
    }),
    reset:()=>enqueue(async()=>{check();await retire();await start();return world;}),
    dispose:()=>{closing=true;return enqueue(async()=>{if(disposed)return;await retire();await rm(directory,{recursive:true,force:true});disposed=true;});},
    async run(command,args=[],runOptions={}){
      await tail;check();
      const active=current;
      const windows=process.platform==='win32';
      const stdio=runOptions.stdio==='inherit'?['pipe','inherit','inherit']:['pipe','pipe','pipe'];
      if(!windows)stdio.push('ipc');
      const client=supervise(windows?binary.path:process.execPath,windows?['__test-world-command',command,...args]:[fileURLToPath(new URL('./testing-process.mjs',import.meta.url)),command,...args],{cwd:runOptions.cwd??options.cwd??process.cwd(),env:{...emptyEnvironment(process.env),...emptyEnvironment(runOptions.env??{}),...active.environment},stdio,commandOwner:!windows});
      clients.add(client);
      const aborted=()=>{void stop(client).catch(()=>{});};
      runOptions.signal?.addEventListener('abort',aborted,{once:true});
      if(runOptions.signal?.aborted)aborted();
      try{
        const result=await client.exited;
        if(current!==active||closing)throw Error('test world command was retired with its generation');
        runOptions.signal?.throwIfAborted();
        if(result.error)throw result.error;
        if(result.code!==0)throw Error(`test world command exited ${result.code??result.signal}: ${client.errorOutput()}`);
        return {...result,stdout:client.output(),stderr:client.errorOutput()};
      }finally{clients.delete(client);runOptions.signal?.removeEventListener('abort',aborted);}
    },
  };
  Object.defineProperty(world,'id',{value:id,enumerable:true});
  Object.defineProperty(world,'projectId',{get:()=>snapshot?.config.daemon.authProject,enumerable:true});
  try{snapshot=await snapshotInputs(options,directory);services??=['auth','firestore','storage',...(snapshot.functionsConfigured?['functions']:[])];await start();return Object.freeze(world);}
  catch(error){await retire();await rm(directory,{recursive:true,force:true});throw error;}
}

/** Always join disposal, including when the test callback rejects. */
export async function withTestWorld(options,callback){
  const world=await createTestWorld(options);
  try{return await callback(world);}finally{await world.dispose();}
}
