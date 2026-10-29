import {createStageBudget} from './stage-context-budget.mjs';
import {createNumericIdentity} from './numeric-batch-identity.mjs';
import {recoverOwnedDocument} from './arrays-owned-recovery.mjs';

export async function runArraysOwnedRecovery(ctx,{uid,projectNumber,expectedUpdateTime,journal,fetchFn,maximum=8}={}){
 if(typeof journal!=='function'||!Number.isInteger(maximum)||maximum<4||maximum>8)throw Error('durable journal and bounded budget required');const budget=createStageBudget({maximum,cleanupReserve:4});const claim=op=>budget.claim(op==='owned-delete'?'delete-owned':op==='owned-absence'?'verify-absence':op);const options={claim,journal,...(fetchFn?{fetchFn}:{})};const identity=createNumericIdentity(ctx,{uid,projectNumber,...options});await identity('identity');await identity('identity');const db=await identity('describe');if(db.uid!==uid||!db.enterprise)throw Error('identity mismatch');const result=await recoverOwnedDocument(ctx,{expectedUpdateTime,...options});if(budget.used()!==6)throw Error('request accounting mismatch');return {...result,directRequests:budget.used()};
}
