// Target-only setup; END is intentionally a separate, not-yet-implemented operation.
import { SANDBOX_PROJECT } from './harness.mjs';
import { createStageSupport } from './stage-context-support.mjs';

// Operation is proto3 JSON: false may be omitted; results are a oneof only after completion.
export function classifyStageOperation(value, expectedName) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['name','metadata','done','error','response'].includes(key)) || value.name !== expectedName ||
      (Object.hasOwn(value, 'done') && typeof value.done !== 'boolean') ||
      (Object.hasOwn(value, 'metadata') && (!value.metadata || typeof value.metadata !== 'object' || Array.isArray(value.metadata)))) throw new Error('unknown operation shape or identity');
  const error=Object.hasOwn(value,'error'), response=Object.hasOwn(value,'response');
  if (value.done !== true) {
    if (error || response) throw new Error('unknown pending operation result');
    return 'pending';
  }
  if (error === response) throw new Error('unknown completed operation result');
  const result=error ? value.error : value.response;
  if (!result || typeof result !== 'object' || Array.isArray(result) || (error && (!Number.isInteger(result.code) || result.code <= 0))) throw new Error('unknown operation result shape');
  return error ? 'error' : 'success';
}

export function createStageLifecycle(ctx, {fetchFn=fetch, claim, journal, timeoutMs=60000, sleepFn=ms=>new Promise(resolve=>setTimeout(resolve,ms)), nowFn=()=>Date.now(), knownUid} = {}) {
  if (ctx.project !== SANDBOX_PROJECT || ctx.target?.quotaProject !== SANDBOX_PROJECT || ctx.stageContextDatabase !== ctx.database || !/^entpipe2-[0-9]{8}$/.test(ctx.database) || !ctx.target.token || typeof claim !== 'function' || typeof journal !== 'function') throw new Error('unbound lifecycle');
  const root=`https://firestore.googleapis.com/v1/projects/${ctx.project}/databases`;
  const resource=`projects/${ctx.project}/databases/${ctx.database}`;
  let phase=knownUid ? 'created' : 'initial';
  let uid=knownUid, deletedAt;
  async function request(op,url,method,body,allow404=false) {
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
    if((response.status<200||response.status>=300) && !(allow404 && response.status===404))throw new Error(`known rejection ${op}; retain claims`);
    try { const value=JSON.parse(bytes.toString('utf8')); return allow404 ? {status:response.status,value} : value; }catch{throw new Error(`invalid ${op} response; retain claims`);}
  }
  async function create() {
    if(phase!=='initial')throw new Error('invalid lifecycle sequence');
    phase='attempted';
    try {
      const listing=await request('inventory',root,'GET');
      if(!listing || typeof listing!=='object' || Array.isArray(listing) || Object.keys(listing).some(key=>!['databases','nextPageToken'].includes(key)) || (listing.nextPageToken ?? '')!=='' || (listing.databases!==undefined && !Array.isArray(listing.databases)) || (listing.databases ?? []).some(x=>!x || typeof x.name!=='string' || x.name===resource)) throw Error('inventory mismatch');
      const operation=await request('create',`${root}?databaseId=${encodeURIComponent(ctx.database)}`,'POST',{locationId:'us-central1',type:'FIRESTORE_NATIVE',databaseEdition:'ENTERPRISE',firestoreDataAccessMode:'DATA_ACCESS_MODE_ENABLED',deleteProtectionState:'DELETE_PROTECTION_DISABLED'});
      const prefix=`${resource}/operations/`;
      if(typeof operation?.name!=='string' || !operation.name.startsWith(prefix) || !/^[A-Za-z0-9_.-]+$/.test(operation.name.slice(prefix.length)))throw Error('unknown create operation');
      let done=false;
      for(let i=0;i<4;i++) {
        const result=await request('create-poll',`https://firestore.googleapis.com/v1/${operation.name}`,'GET');
        const state=classifyStageOperation(result,operation.name);
        if(state==='error')throw Error('known create operation error');
        if(state==='success'){done=true;break;}
        if(i<3)await sleepFn(5000);
      }
      if(!done)throw Error('unknown create operation deadline');
      const db=await request('describe',`${root}/${ctx.database}`,'GET');
      if(db?.name!==resource || typeof db.uid!=='string' || !db.uid || db.locationId!=='us-central1' || db.type!=='FIRESTORE_NATIVE' || db.databaseEdition!=='ENTERPRISE' || db.firestoreDataAccessMode!=='DATA_ACCESS_MODE_ENABLED' || db.deleteProtectionState!=='DELETE_PROTECTION_DISABLED')throw Error('database identity mismatch');
      uid=db.uid;phase='created';return {name:resource,uid};
    } catch(error){phase='unknown';throw error;}
  }
  async function end() {
    if(phase!=='created' || typeof uid!=='string' || !uid)throw new Error('invalid lifecycle sequence');
    phase='ending';
    try {
      const db=await request('end-describe',`${root}/${ctx.database}`,'GET');
      if(db?.name!==resource || db.uid!==uid)throw Error('END identity mismatch');
      const support=createStageSupport(ctx,{fetchFn,journal,claim:()=>claim('end-baseline'),timeoutMs});
      await support.stageOperation('baseline');
      const operation=await request('end-delete',`${root}/${ctx.database}`,'DELETE');
      const prefix=`${resource}/operations/`;
      if(typeof operation?.name!=='string' || !operation.name.startsWith(prefix) || !/^[A-Za-z0-9_.-]+$/.test(operation.name.slice(prefix.length)))throw Error('unknown delete operation');
      let done=false;
      for(let i=0;i<5;i++) {
        const result=await request('end-poll',`https://firestore.googleapis.com/v1/${operation.name}`,'GET');
        const state=classifyStageOperation(result,operation.name);
        if(state==='error')throw Error('known delete operation error');
        if(state==='success'){done=true;break;}
        if(i<4)await sleepFn(5000);
      }
      if(!done)throw Error('unknown delete operation deadline');
      deletedAt=nowFn();phase='awaiting-confirm';
    } catch(error){phase='unknown';throw error;}
  }
  async function confirmEnd() {
    if(phase!=='awaiting-confirm')throw Error('invalid lifecycle sequence');
    if(nowFn()-deletedAt<600000)throw Error('ten minutes required');
    phase='confirming';
    try {
      const listing=await request('end-list',root,'GET');
      if(!listing || typeof listing!=='object' || Array.isArray(listing) || Object.keys(listing).some(key=>!['databases','nextPageToken'].includes(key)) || (listing.nextPageToken ?? '')!=='' || (listing.databases!==undefined && !Array.isArray(listing.databases)) || (listing.databases ?? []).some(x=>!x || typeof x.name!=='string' || x.name===resource))throw Error('END inventory mismatch');
      const missing=await request('end-get',`${root}/${ctx.database}`,'GET',undefined,true);
      if(missing.status!==404 || missing.value?.error?.code!==404 || missing.value.error.status!=='NOT_FOUND' || typeof missing.value.error.message!=='string' || !missing.value.error.message.includes(resource))throw Error('END absence unknown');
      phase='closed';return {name:resource,uid};
    } catch(error){phase='unknown';throw error;}
  }
  return {create,end,confirmEnd};
}
