import {createStageBudget} from './stage-context-budget.mjs';
import {createNumericIdentity} from './numeric-batch-identity.mjs';
import {createNumericSupport} from './numeric-batch-support.mjs';
import {observeNumeric} from './numeric-batch-observation.mjs';
import {runNumericBatch} from './numeric-batch.mjs';

// The campaign holds two separately admitted recovery reads and two cleanup calls.
export async function runNumericAdapter(ctx,{uid,projectNumber,journal,fetchFn,clientFactory}={}) {
  if(typeof journal!=='function')throw Error('durable journal required');
  const budget=createStageBudget({maximum:69,cleanupReserve:4});
  const claim=budget.claim;
  const identity=createNumericIdentity(ctx,{uid,projectNumber,claim,journal,...(fetchFn?{fetchFn}:{})});
  const support=createNumericSupport(ctx,{claim,journal,...(fetchFn?{fetchFn}:{})});
  const result=await runNumericBatch({uid,io:async(op,detail)=>{
    if(op==='identity'||op==='describe')return identity(op);
    if(op==='observe')return observeNumeric(ctx,detail.step,{claim,journal,...(clientFactory?{clientFactory}:{})});
    return support(op);
  }});
  if(result.directRequests!==budget.used())throw Error('direct request accounting mismatch');
  return result;
}
