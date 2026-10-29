import {stringBatchRecipes} from './string-batch-corpus.mjs';

// This fixed sequence never performs database creation or deletion.
export async function runStringBatch({uid,io,maximum=35}) {
  if(typeof uid!=='string' || !uid || typeof io!=='function' || !Number.isInteger(maximum) || maximum<1 || maximum>35)throw Error('invalid admission');
  const recipes=stringBatchRecipes();if(recipes.length!==11)throw Error('invalid corpus');
  let used=0;
  async function call(op,detail={}) {
    if(used>=maximum)throw Error('request ceiling reached; retain claims');
    used++;
    let result;try{result=await io(op,detail);}catch{throw Error(`unknown ${op}; retain claims`);}
    if(!result || result.known!==true)throw Error(`unknown ${op}; retain claims`);
    if(op!=='observe' && op!=='describe' && result.ok!==true)throw Error(`failed ${op}; retain claims`);
    return result;
  }
  await call('identity');await call('identity');
  const db=await call('describe');if(db.uid!==uid || db.enterprise!==true)throw Error('database identity mismatch; retain claims');
  for(let round=1;round<=2;round++) {
    await call('baseline',{round});await call('seed',{round});await call('verify',{round});
    for(const recipe of recipes)await call('observe',{round,step:recipe.step});
    await call('delete-owned',{round});await call('verify-absence',{round});
  }
  return {directRequests:used,observations:22};
}
