import { parentPort, workerData } from 'node:worker_threads';
import { EventEmitter } from 'node:events';
import { observeStage } from '../stage-context-observation.mjs';
import { stageContextCases } from '../stage-context-corpus.mjs';
let sequence=0; const waiting=new Map();
parentPort.on('message',m=>{const resolve=waiting.get(m.id);if(resolve){waiting.delete(m.id);resolve();}});
const handoff=(kind,data)=>new Promise(resolve=>{const id=++sequence;waiting.set(id,resolve);parentPort.postMessage({kind,id,data});});
const clientFactory=()=>({makeServerStreamRequest(_path,serialize,_deserialize,request){const c=new EventEmitter();c.cancel=()=>{};serialize(request);queueMicrotask(()=>{c.emit('metadata',{});c.emit('data',Buffer.from([1,2]));c.emit('status',{code:0});});return c;},close(){}});
const step=stageContextCases().find(x=>x.id===workerData.stepId);
observeStage(workerData.ctx,step,{claim:id=>handoff('claim',{stepId:id}),journal:entry=>handoff('journal',entry),clientFactory})
 .then(result=>parentPort.postMessage({kind:'complete',result}))
 .catch(()=>parentPort.postMessage({kind:'unknown'}))
 .finally(()=>parentPort.close());
