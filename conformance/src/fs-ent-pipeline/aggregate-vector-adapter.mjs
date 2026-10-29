import {createStageBudget} from './stage-context-budget.mjs';
import {createNumericIdentity} from './numeric-batch-identity.mjs';
import {createAggregateVectorSupport} from './aggregate-vector-support.mjs';
import {observeAggregateVector} from './aggregate-vector-observation.mjs';
import {runAggregateVectorBatch} from './aggregate-vector-batch.mjs';

// The campaign holds two separately admitted recovery reads and four cleanup calls.
export async function runAggregateVectorAdapter(ctx,{uid,projectNumber,journal,fetchFn,clientFactory}={}) {
  if(typeof journal!=='function')throw Error('durable journal required');
  const budget=createStageBudget({maximum:47,cleanupReserve:6});
  const claim=budget.claim;
  const identity=createNumericIdentity(ctx,{uid,projectNumber,claim,journal,...(fetchFn?{fetchFn}:{})});
  const support=createAggregateVectorSupport(ctx,{claim,journal,...(fetchFn?{fetchFn}:{})});
  const result=await runAggregateVectorBatch({uid,io:async(op,detail)=>{
    if(op==='identity'||op==='describe')return identity(op);
    if(op==='observe')return observeAggregateVector(ctx,detail.step,{claim,journal,...(clientFactory?{clientFactory}:{})});
    return support(op,detail);
  }});
  if(result.directRequests!==budget.used())throw Error('direct request accounting mismatch');
  return result;
}
