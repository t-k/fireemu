import {createStageBudget} from './stage-context-budget.mjs';
import {createNumericIdentity} from './numeric-batch-identity.mjs';
import {createSourcePrecedenceSupport} from './source-precedence-support.mjs';
import {observeSourcePrecedence} from './source-precedence-observation.mjs';
import {runSourcePrecedenceBatch} from './source-precedence-batch.mjs';

// The campaign holds two separately admitted recovery reads and five cleanup calls.
export async function runSourcePrecedenceAdapter(ctx,{uid,projectNumber,journal,fetchFn,clientFactory}={}) {
  if(typeof journal!=='function')throw Error('durable journal required');
  const budget=createStageBudget({maximum:47,cleanupReserve:7});
  const claim=budget.claim;
  const identity=createNumericIdentity(ctx,{uid,projectNumber,claim,journal,...(fetchFn?{fetchFn}:{})});
  const support=createSourcePrecedenceSupport(ctx,{claim,journal,...(fetchFn?{fetchFn}:{})});
  const result=await runSourcePrecedenceBatch({uid,io:async(op,detail)=>{
    if(op==='identity'||op==='describe')return identity(op);
    if(op==='observe')return observeSourcePrecedence(ctx,detail.step,{claim,journal,...(clientFactory?{clientFactory}:{})});
    return support(op,detail);
  }});
  if(result.directRequests!==budget.used())throw Error('direct request accounting mismatch');
  return result;
}
