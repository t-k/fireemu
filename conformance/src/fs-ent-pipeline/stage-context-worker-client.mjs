import { Worker } from 'node:worker_threads';
import { isDeepStrictEqual } from 'node:util';
import { stageContextCases } from './stage-context-corpus.mjs';

// One fixed worker; acknowledgement follows the caller's durable claim or journal operation.
export async function runObservationWorker(ctx, step, {claim, journal, workerFactory, timeoutMs=120000} = {}) {
  const fixed=stageContextCases().find(x=>x.id===step?.id);
  if (!fixed || !isDeepStrictEqual(fixed,step) || typeof claim!=='function' || typeof journal!=='function') throw new Error('unapproved worker request');
  const worker=workerFactory ? workerFactory(ctx,step) : new Worker(new URL('./stage-context-worker.mjs',import.meta.url),{workerData:{ctx,stepId:step.id}});
  let phase='initial', finished=false, queue=Promise.resolve();
  return new Promise((resolve,reject) => {
    const timer=setTimeout(()=>finish(new Error('unknown worker timeout')),timeoutMs);
    async function finish(error,result) {
      if (finished) return;
      finished=true; clearTimeout(timer);
      try {await worker.terminate();} catch {error ||= new Error('unknown worker cleanup');}
      if (error) reject(error); else resolve(result);
    }
    worker.on('error',()=>finish(new Error('unknown worker error')));
    worker.on('exit',code=>{if (!finished) finish(new Error(`unknown worker exit ${code}`));});
    worker.on('message',message=>{
      queue=queue.then(async()=>{
        if (finished) return;
        if (message?.kind==='claim' && phase==='initial' && message.data?.stepId===step.id) {
          await claim(step.id); phase='claimed'; worker.postMessage({id:message.id,ok:true});
        } else if (message?.kind==='journal' && ((phase==='claimed' && message.data?.phase==='attempt') || (phase==='attempt' && ['headers','status'].includes(message.data?.phase)) || (phase==='headers' && message.data?.phase==='status'))) {
          await journal(message.data); phase=message.data.phase; worker.postMessage({id:message.id,ok:true});
        } else if (message?.kind==='complete' && phase==='status' && message.result?.known===true) {
          await finish(null,message.result);
        } else throw new Error('unknown worker protocol');
      }).catch(()=>finish(new Error('unknown worker handoff')));
    });
  });
}
