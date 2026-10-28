// The parent acknowledges every durable claim and journal write before this worker proceeds.
import { parentPort, workerData } from 'node:worker_threads';
import { observeStage } from './stage-context-observation.mjs';
import { stageContextCases } from './stage-context-corpus.mjs';

if (!parentPort) throw new Error('stage observation must run in an isolated worker');
let sequence=0;
const waiting=new Map();
parentPort.on('message', message => {
  const entry=waiting.get(message?.id);
  if (!entry) return;
  waiting.delete(message.id);
  clearTimeout(entry.timer);
  if (message.ok === true) entry.resolve(); else entry.reject(new Error('parent refused durable handoff'));
});
function handoff(kind, data) {
  const id=++sequence;
  return new Promise((resolve,reject) => {
    const timer=setTimeout(() => {waiting.delete(id); reject(new Error('parent handoff timeout'));}, 60000);
    waiting.set(id,{resolve,reject,timer});
    parentPort.postMessage({kind,id,data});
  });
}
const step=stageContextCases().find(x=>x.id===workerData?.stepId);
if (!step) throw new Error('unapproved worker case');
observeStage(workerData.ctx,step,{claim:id=>handoff('claim',{stepId:id}),journal:entry=>handoff('journal',entry)})
  .then(result=>parentPort.postMessage({kind:'complete',result}))
  .catch(()=>parentPort.postMessage({kind:'unknown'}))
  .finally(()=>parentPort.close());
