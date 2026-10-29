import {createSubqueryBudget} from './subquery-budget.mjs';
import {createNumericIdentity} from './numeric-batch-identity.mjs';
import {createSubquerySupport} from './subquery-support.mjs';
import {observeSubquery} from './subquery-observation.mjs';
import {runSubqueryBatch} from './subquery-batch.mjs';

// The campaign holds two separately admitted recovery reads and five cleanup calls.
export async function runSubqueryAdapter(ctx,{uid,projectNumber,journal,fetchFn,clientFactory}={}) {
  if(typeof journal!=='function')throw Error('durable journal required');
  const budget=createSubqueryBudget();
  const claim=budget.claim;
  const identity=createNumericIdentity(ctx,{uid,projectNumber,claim,journal,...(fetchFn?{fetchFn}:{})});
  const support=createSubquerySupport(ctx,{claim,journal,...(fetchFn?{fetchFn}:{})});
  const result=await runSubqueryBatch({uid,io:async(op,detail)=>{
    if(op==='identity'||op==='describe')return identity(op);
    if(op==='observe')return observeSubquery(ctx,detail.step,{claim,journal,...(clientFactory?{clientFactory}:{})});
    return support(op,detail);
  }});
  if(result.directRequests!==budget.used())throw Error('direct request accounting mismatch');
  return result;
}
