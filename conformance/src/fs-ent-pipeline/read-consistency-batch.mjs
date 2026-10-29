// A lost response stops the sequence without cleanup or automatic retry.
export async function runReadConsistency({uid,io,maximum=31}){
 if(typeof uid!=='string'||!uid||typeof io!=='function'||!Number.isInteger(maximum)||maximum<1||maximum>31)throw Error('invalid admission');let used=0;
 async function call(op,detail={}){if(used>=maximum)throw Error('request ceiling; retain claims');used++;let result;try{result=await io(op,detail);}catch{throw Error(`unknown ${op}; retain claims`);}if(!result||result.known!==true)throw Error(`unknown ${op}; retain claims`);if(!['describe','strong','read-time','tx-snapshot'].includes(op)&&result.ok!==true)throw Error(`failed ${op}; retain claims`);return result;}
 await call('identity');await call('identity');const db=await call('describe');if(db.uid!==uid||db.enterprise!==true)throw Error('database identity mismatch');
 for(let round=1;round<=2;round++){
  await call('collection-baseline',{round});await call('baseline',{round});await call('seed',{round});const first=await call('verify',{round});if(typeof first.updateTime!=='string')throw Error('missing baseline time');
  const tx=await call('begin',{round});if(!Buffer.isBuffer(tx.token)||!tx.token.length)throw Error('missing transaction');
  const anchor=await call('tx-anchor',{round,token:tx.token});if(anchor.anchorVerified!==true)throw Error('transaction anchor not proven; retain claims');await call('update',{round,updateTime:first.updateTime});const second=await call('verify-updated',{round});if(typeof second.updateTime!=='string')throw Error('missing updated time');
  await call('strong',{round,token:tx.token});await call('read-time',{round,timestamp:first.updateTime,token:tx.token});await call('tx-snapshot',{round,token:tx.token});await call('rollback',{round,token:tx.token});await call('delete-owned',{round,updateTime:second.updateTime});await call('verify-absence',{round});
 }
 return {directRequests:used,observations:8};
}
