import {createStageBudget} from './stage-context-budget.mjs';
import {createNumericIdentity} from './numeric-batch-identity.mjs';
import {createStringSupport} from './string-batch-support.mjs';
import {observeString} from './string-batch-observation.mjs';
import {runStringBatch} from './string-batch.mjs';

// The campaign holds two separately admitted recovery reads and two cleanup calls.
export async function runStringAdapter(ctx,{uid,projectNumber,journal,fetchFn,clientFactory}={}) {
  if(typeof journal!=='function')throw Error('durable journal required');
  const budget=createStageBudget({maximum:37,cleanupReserve:4});
  const claim=budget.claim;
  const identity=createNumericIdentity(ctx,{uid,projectNumber,claim,journal,...(fetchFn?{fetchFn}:{})});
  const support=createStringSupport(ctx,{claim,journal,...(fetchFn?{fetchFn}:{})});
  const result=await runStringBatch({uid,io:async(op,detail)=>{
    if(op==='identity'||op==='describe')return identity(op);
    if(op==='observe')return observeString(ctx,detail.step,{claim,journal,...(clientFactory?{clientFactory}:{})});
    return support(op);
  }});
  if(result.directRequests!==budget.used())throw Error('direct request accounting mismatch');
  return result;
}
