import {createStageBudget} from './stage-context-budget.mjs';
import {createNumericIdentity} from './numeric-batch-identity.mjs';
import {createArraysControlSupport} from './arrays-control-support.mjs';
import {observeArraysControl} from './arrays-control-observation.mjs';
import {runArraysControlBatch} from './arrays-control-batch.mjs';

// The campaign holds two separately admitted recovery reads and two cleanup calls.
export async function runArraysControlAdapter(ctx,{uid,projectNumber,journal,fetchFn,clientFactory}={}) {
  if(typeof journal!=='function')throw Error('durable journal required');
  const budget=createStageBudget({maximum:57,cleanupReserve:4});
  const claim=budget.claim;
  const identity=createNumericIdentity(ctx,{uid,projectNumber,claim,journal,...(fetchFn?{fetchFn}:{})});
  const support=createArraysControlSupport(ctx,{claim,journal,...(fetchFn?{fetchFn}:{})});
  const result=await runArraysControlBatch({uid,io:async(op,detail)=>{
    if(op==='identity'||op==='describe')return identity(op);
    if(op==='observe')return observeArraysControl(ctx,detail.step,{claim,journal,...(clientFactory?{clientFactory}:{})});
    return support(op);
  }});
  if(result.directRequests!==budget.used())throw Error('direct request accounting mismatch');
  return result;
}
