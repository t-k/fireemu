import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { installSdkNextWsGuard, assertProductionSdkNextReady, runScenario } from './rtdb-residual.mjs';
import { readFileSync } from 'node:fs';

function setup(options = {}) {
  const c=vm.createContext({URL,TextEncoder,writes:[],options});
  vm.runInContext(`class Socket { static OPEN=1; constructor(){this.readyState=1;this.listeners={};} addEventListener(k,f){(this.listeners[k]??=[]).push(f);} send(x){writes.push(x);} fire(k,e={}){for(const f of this.listeners[k]??[])f(e);} } globalThis.WebSocket=Socket;`,c);
  vm.runInContext(`(${installSdkNextWsGuard.toString()})({host:'127.0.0.1:9000',namespace:'demo',base:'owned/sdk',noMutations:true,maxConnections:2,maxMessages:16,maxControls:options.maxControls ?? 4})`,c);
  return {c,run:(x)=>vm.runInContext(x,c)};
}
const open=(run,actor,id)=>run(`globalThis.${actor}=new WebSocket('ws://127.0.0.1:9000/.ws?ns=demo'); ${actor}.fire('message',{data:JSON.stringify({t:'c',d:{t:'h',d:{h:'127.0.0.1:9000',v:'5',s:'${id}'}}})})`);
const read=(run,actor,id)=>run(`__sdkNextWsGuard.beginOperation('startup-${actor}'); ${actor}.send(JSON.stringify({t:'d',d:{r:${id},a:'g',b:{p:'/owned/sdk'}}})); ${actor}.fire('message',{data:JSON.stringify({t:'d',d:{r:${id},b:{s:'ok',d:null}}})}); __sdkNextWsGuard.endOperation(); __sdkNextWsGuard.startupRead('${actor}',null)`);

test('two actor reads finish without arm or mutation and retain private controls',()=>{
 const {run,c}=setup();open(run,'w','s1');read(run,'w',1);open(run,'o','s2');read(run,'o',1);run('__sdkNextWsGuard.finishStartup()');
 const state=run('__sdkNextWsGuard.status()');assert.equal(state.terminal,true);assert.equal(state.armed,false);assert.equal(state.operationIndex,2);assert.equal(run('__sdkNextWsGuard.controls().length'),2);assert.equal(c.writes.length,2);
});

test('noMutation latch refuses arm and accidental writes before native send',()=>{
 {const {run,c}=setup();open(run,'w','s1');read(run,'w',1);open(run,'o','s2');read(run,'o',1);assert.throws(()=>run('__sdkNextWsGuard.arm()'),/mutation|startup.only/i);assert.equal(c.writes.length,2);}
 {const {run,c}=setup();open(run,'w','s1');assert.throws(()=>run(`w.send(JSON.stringify({t:'d',d:{r:2,a:'p',b:{p:'/owned/sdk',d:1}}}))`),/mutation/i);assert.equal(c.writes.length,0);}
});

test('unexpected h and r are retained before freeze; oversized control is not retained',()=>{
 for(const ctrl of [{t:'h',d:{h:'other.example',s:'private',v:'5'}},{t:'r',d:'other.example'}]){
  const {run,c}=setup();run(`globalThis.w=new WebSocket('ws://127.0.0.1:9000/.ws?ns=demo')`);c.raw=JSON.stringify({t:'c',d:ctrl});run(`w.fire('message',{data:raw})`);assert.equal(run('__sdkNextWsGuard.status().frozen'),true);assert.equal(run('__sdkNextWsGuard.controls()[0]'),c.raw);
 }
 const {run}=setup();run(`globalThis.w=new WebSocket('ws://127.0.0.1:9000/.ws?ns=demo'); w.fire('message',{data:JSON.stringify({t:'c',d:{t:'r',d:'x'.repeat(5000)}})})`);assert.equal(run('__sdkNextWsGuard.status().frozen'),true);assert.equal(run('__sdkNextWsGuard.controls().length'),0);
});

test('startup production remains blocked before any request',async()=>{
 assert.throws(()=>assertProductionSdkNextReady({scenario:'sdk-next-startup'}),/unverified|blocked/i);
 let calls=0;const fetchImpl=()=>{calls++;throw Error('sent');};
 for (const o of [{packet:{scenario:'sdk-next-startup'}},{scenarios:['sdk-next-startup']},{scenarios:['sdk-next']}]) await assert.rejects(runScenario({mode:'production',fetchImpl,...o}),/unverified|blocked/i);
 assert.equal(calls,0);
});

test('startup page has no write or feature continuation',()=>{
 const src=readFileSync(new URL('./rtdb-residual-page.js',import.meta.url),'utf8');const section=src.split('  async function sdkStartup() {')[1]?.split('  async function sdkNext() {')[0];
 assert.ok(section);assert.doesNotMatch(section,/D\.(set|update|runTransaction|onDisconnect|push)\s*\(/);assert.match(section,/finishStartup/);
});

test('startup validator rejects missing control, changed type, order and guard state', async () => {
 const { validateSdkStartup }=await import('./rtdb-residual-judge.mjs');
 const status={noMutations:true,armed:false,terminal:true,frozen:false,unknown:false,connections:2,messages:4,controlCount:2,operationIndex:2};
 const h=JSON.stringify({t:'c',d:{t:'h',d:{h:'127.0.0.1:9000',v:'5',s:'x'}}});
 const good=[{type:'operation',label:'startup-w',code:'1'},{type:'startup',label:'root-read',actor:'w',shape:'null'},{type:'operation',label:'startup-o',code:'2'},{type:'startup',label:'root-read',actor:'o',shape:'null'},{type:'guard',code:JSON.stringify(status)},{type:'done'},{type:'raw-control',shape:h},{type:'raw-control',shape:h}];
 assert.equal(validateSdkStartup(good).valid,true);
 for(const change of [a=>a.pop(),a=>{a[1].shape='0';},a=>{[a[1],a[2]]=[a[2],a[1]];},a=>{a[4].code=JSON.stringify({...status,armed:true});},a=>{a[6].shape='x'.repeat(4097);}]){const a=structuredClone(good);change(a);assert.equal(validateSdkStartup(a).valid,false);}
});

test('startup selector is exactly two WS profiles and startup Rules are read-only', async()=>{
 const {narrowing,rulesFor}=await import('./rtdb-residual.mjs');
 const selected=narrowing('sdk-next-startup',undefined);
 assert.deepEqual(selected.profiles.map((p)=>p.name),['r1-ws','r2-ws']);
 assert.throws(()=>narrowing('sdk-next-startup','lp'),/two WS/);
 assert.throws(()=>narrowing('sdk-next-startup,cv08','ws'),/two WS/);
 const startup=rulesFor('owned/run',{startup:true}).rules.owned.run;
 assert.deepEqual(Object.keys(startup),['sdk-next-startup']);
 assert.deepEqual(startup['sdk-next-startup'].$cell,{'.read':true,'.write':false});
 assert.equal(rulesFor('owned/run').rules.owned.run['sdk-next-startup'],undefined);
});

test('raw mismatch is persisted before both apps are deleted', async()=>{
 const events=[];let writes=0;
 const raw=JSON.stringify({t:'c',d:{t:'h',d:{h:'other.example',v:'5',s:'private'}}});
 const guard={beginOperation(){},freeze(){},status:()=>({frozen:true,noMutations:true}),controls:()=>[raw]};
 const D={forceWebSockets(){},getDatabase:()=>({}),ref:()=>({}),get:()=>Promise.reject(Error('host mismatch')),set(){writes++;}};
 const src=readFileSync(new URL('./rtdb-residual-page.js',import.meta.url),'utf8').replace(/^import .*firebase-app\.js';$/m,'').replace(/^import .*firebase-database\.js';$/m,'');
 const c={window:{__rrEvent:async(r)=>events.push(r)},D,initializeApp:()=>({}),deleteApp:async()=>events.push({type:'deleted'}),performance,setTimeout,clearTimeout,setInterval,clearInterval,Date,__sdkNextWsGuard:guard};
 vm.runInNewContext(src,c);
 await assert.rejects(c.window.__rrRun({scenario:'sdk-next-startup',transport:'ws',base:'owned/sdk',name:'r1-ws',wsGuardRequired:true}),/host mismatch/);
 const rawIndex=events.findIndex((r)=>r.type==='raw-control');
 assert.ok(rawIndex>=0);assert.equal(events[rawIndex].shape,raw);assert.ok(rawIndex<events.findIndex((r)=>r.type==='deleted'));assert.equal(events.filter((r)=>r.type==='deleted').length,2);assert.equal(writes,0);
});

test('control record uses UTF-8 byte bound and cap zero fails before retention',()=>{
 {const {run}=setup();run(`globalThis.w=new WebSocket('ws://127.0.0.1:9000/.ws?ns=demo'); w.fire('message',{data:JSON.stringify({t:'c',d:{t:'r',d:'é'.repeat(2200)}})})`);assert.equal(run('__sdkNextWsGuard.status().frozen'),true);assert.equal(run('__sdkNextWsGuard.controls().length'),0);}
 const c=vm.createContext({URL,TextEncoder});vm.runInContext(`class Socket {static OPEN=1;constructor(){this.readyState=1;this.listeners={};}addEventListener(k,f){(this.listeners[k]??=[]).push(f);}send(){}fire(k,e){for(const f of this.listeners[k]??[])f(e);}}globalThis.WebSocket=Socket;`,c);
 vm.runInContext(`(${installSdkNextWsGuard.toString()})({host:'127.0.0.1:9000',namespace:'demo',base:'owned/sdk',noMutations:true,maxControls:0});globalThis.w=new WebSocket('ws://127.0.0.1:9000/.ws?ns=demo');w.fire('message',{data:JSON.stringify({t:'c',d:{t:'h',d:{h:'127.0.0.1:9000',v:'5',s:'x'}}})});`,c);
 assert.equal(vm.runInContext('__sdkNextWsGuard.status().frozen',c),true);assert.equal(vm.runInContext('__sdkNextWsGuard.controls().length',c),0);
});

test('seeded PICT startup controls never put mutation on the wire',()=>{
 const file=process.env.STARTUP_PICT;if(!file)return;
 const lines=readFileSync(file,'utf8').trim().split(/\r?\n/),head=lines.shift().split('\t');
 for(const line of lines){
  const cells=line.split('\t'),axes=Object.fromEntries(head.map((k,i)=>[k,cells[i]]));
  const {run,c}=setup({maxControls:axes.Boundary==='cap'?0:4});
  if(axes.Phase==='terminal'){
   if(axes.Boundary==='cap'){open(run,'w','s1');assert.equal(run('__sdkNextWsGuard.status().frozen'),true,line);assert.throws(()=>run(`w.send('0')`));assert.equal(c.writes.length,0,line);continue;}
   open(run,'w','s1');read(run,'w',1);open(run,'o','s2');read(run,'o',1);run('__sdkNextWsGuard.finishStartup()');
   assert.throws(()=>run(`w.send(JSON.stringify({t:'d',d:{r:9,a:'p',b:{p:'/owned/sdk',d:1}}}))`));assert.equal(c.writes.length,2,line);continue;
  }
  const actor=axes.Actor;run(`globalThis.${actor}=new WebSocket('ws://127.0.0.1:9000/.ws?ns=demo')`);
  const control=axes.Phase==='frozen'||axes.Control==='mismatch'?{t:'h',d:{h:'foreign',v:'5',s:'private'}}:axes.Control==='reset'?{t:'r',d:'foreign'}:{t:'h',d:{h:'127.0.0.1:9000',v:'5',s:'private'}};
  if(axes.Boundary==='oversize')control.d.extra='é'.repeat(2200);
  c.raw=axes.Control==='fragment'?'2':JSON.stringify({t:'c',d:control});run(`${actor}.fire('message',{data:raw})`);
  assert.throws(()=>run(`${actor}.send(JSON.stringify({t:'d',d:{r:9,a:'p',b:{p:'/owned/sdk',d:1}}}))`),undefined,line);
  assert.equal(c.writes.length,0,line);
 }
});

test('startup permits only the exact owned root GET, not a child read',()=>{
 const {run,c}=setup();open(run,'w','s1');run(`__sdkNextWsGuard.beginOperation('startup-w')`);
 assert.throws(()=>run(`w.send(JSON.stringify({t:'d',d:{r:1,a:'g',b:{p:'/owned/sdk/child'}}}))`),/scope|root/i);
 assert.equal(c.writes.length,0);
});
