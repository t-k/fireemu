// Target-only setup; END is intentionally a separate, not-yet-implemented operation.
import { SANDBOX_PROJECT } from './harness.mjs';

export function createStageLifecycle(ctx, {fetchFn=fetch, claim, journal, timeoutMs=60000, sleepFn=ms=>new Promise(resolve=>setTimeout(resolve,ms))} = {}) {
  if (ctx.project !== SANDBOX_PROJECT || ctx.target?.quotaProject !== SANDBOX_PROJECT || ctx.stageContextDatabase !== ctx.database || !/^entpipe2-[0-9]{8}$/.test(ctx.database) || !ctx.target.token || typeof claim !== 'function' || typeof journal !== 'function') throw new Error('unbound lifecycle');
  const root=`https://firestore.googleapis.com/v1/projects/${ctx.project}/databases`;
  const resource=`projects/${ctx.project}/databases/${ctx.database}`;
  let phase='initial';
  async function request(op,url,method,body) {
    await claim(op);
    await journal({phase:'attempt',op,url,method,body:body ?? null});
    let response, bytes;
    try {
      response=await fetchFn(url,{method,redirect:'error',signal:AbortSignal.timeout(timeoutMs),headers:{authorization:`Bearer ${ctx.target.token}`,'x-goog-user-project':ctx.target.quotaProject,'content-type':'application/json'},...(body ? {body:JSON.stringify(body)} : {})});
      await journal({phase:'headers',op,status:response.status});
      if (response.body) {const parts=[];let n=0;for await(const part of response.body){n+=part.length;if(n>1048576)throw Error('body bound');parts.push(Buffer.from(part));}bytes=Buffer.concat(parts);}
      else {bytes=Buffer.from(await response.text());if(bytes.length>1048576)throw Error('body bound');}
    } catch {await journal({phase:'unknown',op});throw new Error(`unknown ${op}; retain claims`);}
    if (ctx.target.token && bytes.includes(Buffer.from(ctx.target.token))) throw new Error('secret in response; retain claims');
    await journal({phase:'response',op,status:response.status,bodyBase64:bytes.toString('base64')});
    if(response.status<200||response.status>=300)throw new Error(`known rejection ${op}; retain claims`);
    try{return JSON.parse(bytes.toString('utf8'));}catch{throw new Error(`invalid ${op} response; retain claims`);}
  }
  async function create() {
    if(phase!=='initial')throw new Error('invalid lifecycle sequence');
    phase='attempted';
    try {
      const listing=await request('inventory',root,'GET');
      if(!listing || typeof listing!=='object' || Array.isArray(listing) || (listing.nextPageToken ?? '')!=='' || (listing.databases!==undefined && !Array.isArray(listing.databases)) || (listing.databases ?? []).some(x=>!x || typeof x.name!=='string' || x.name===resource)) throw Error('inventory mismatch');
      const operation=await request('create',`${root}?databaseId=${encodeURIComponent(ctx.database)}`,'POST',{locationId:'us-central1',type:'FIRESTORE_NATIVE',databaseEdition:'ENTERPRISE',firestoreDataAccessMode:'DATA_ACCESS_MODE_ENABLED',deleteProtectionState:'DELETE_PROTECTION_DISABLED'});
      const prefix=`${resource}/operations/`;
      if(typeof operation?.name!=='string' || !operation.name.startsWith(prefix) || !/^[A-Za-z0-9_.-]+$/.test(operation.name.slice(prefix.length)))throw Error('unknown create operation');
      let done=false;
      for(let i=0;i<4;i++) {
        const result=await request('create-poll',`https://firestore.googleapis.com/v1/${operation.name}`,'GET');
        if(result?.error)throw Error('known create operation error');
        if(result?.done===true){done=true;break;}
        if(result?.done!==false)throw Error('unknown create operation state');
        if(i<3)await sleepFn(5000);
      }
      if(!done)throw Error('unknown create operation deadline');
      const db=await request('describe',`${root}/${ctx.database}`,'GET');
      if(db?.name!==resource || typeof db.uid!=='string' || !db.uid || db.locationId!=='us-central1' || db.type!=='FIRESTORE_NATIVE' || db.databaseEdition!=='ENTERPRISE' || db.firestoreDataAccessMode!=='DATA_ACCESS_MODE_ENABLED' || db.deleteProtectionState!=='DELETE_PROTECTION_DISABLED')throw Error('database identity mismatch');
      phase='created';return {name:resource,uid:db.uid};
    } catch(error){phase='unknown';throw error;}
  }
  return {create};
}
