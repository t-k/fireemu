// Fixed first packet. The caller supplies reviewed admission and a durable journal.
import { verifyStageProject } from './stage-context-identity.mjs';
import { createStageBudget } from './stage-context-budget.mjs';
import { createStageLifecycle } from './stage-context-lifecycle.mjs';
import { createStageSupport } from './stage-context-support.mjs';
import { runObservationWorker } from './stage-context-worker-client.mjs';
import { runStageContextRounds } from './stage-context-rounds.mjs';

export async function runStageCampaign(ctx, {journal, fetchFn, workerFactory, sleepFn, expectedProjectNumber} = {}) {
  if(typeof journal!=='function')throw new Error('durable journal required');
  const budget=createStageBudget({maximum:53,cleanupReserve:14});
  const claim=budget.claim;
  await verifyStageProject(ctx,expectedProjectNumber,{claim,journal,...(fetchFn?{fetchFn}:{})});
  const lifecycle=createStageLifecycle(ctx,{claim,journal,...(fetchFn?{fetchFn}:{}),...(sleepFn?{sleepFn}:{})});
  const database=await lifecycle.create();
  const support=createStageSupport(ctx,{claim,journal,...(fetchFn?{fetchFn}:{})});
  const counts=await runStageContextRounds((op,detail)=>op==='observe'
    ? runObservationWorker(ctx,detail.step,{claim,journal,...(workerFactory?{workerFactory}:{})})
    : support.stageOperation(op,detail));
  return {database,counts,used:budget.used()};
}
