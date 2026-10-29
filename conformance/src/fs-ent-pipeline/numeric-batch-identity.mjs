import {SANDBOX_PROJECT} from './harness.mjs';

export function createNumericIdentity(ctx,{uid,projectNumber,claim,journal,fetchFn=fetch,timeoutMs=60000}={}) {
  if(ctx.project!==SANDBOX_PROJECT || !/^entpipe2-[0-9]{8}$/.test(ctx.database) || ctx.stageContextDatabase!==ctx.database || ctx.target?.kind!=='production' || ctx.target.quotaProject!==ctx.project || !ctx.target.token || typeof uid!=='string' || !uid || !/^[1-9]\d{5,}$/.test(projectNumber) || typeof claim!=='function' || typeof journal!=='function')throw Error('unbound identity');
  return async function identity(op) {
    if(!['identity','describe'].includes(op))throw Error('invalid identity operation');
    const url=op==='identity'?`https://cloudresourcemanager.googleapis.com/v3/projects/${projectNumber}`:`https://firestore.googleapis.com/v1/projects/${ctx.project}/databases/${ctx.database}`;
    await claim(op);await journal({phase:'attempt',op,url,method:'GET'});
    let response,bytes;try{response=await fetchFn(url,{method:'GET',redirect:'error',signal:AbortSignal.timeout(timeoutMs),headers:{authorization:`Bearer ${ctx.target.token}`,'x-goog-user-project':ctx.project}});await journal({phase:'headers',op,status:response.status});if(response.body){const parts=[];let n=0;for await(const part of response.body){n+=part.length;if(n>1048576)throw Error('body bound');parts.push(Buffer.from(part));}bytes=Buffer.concat(parts);}else{bytes=Buffer.from(await response.text());if(bytes.length>1048576)throw Error('body bound');}}catch{await journal({phase:'unknown',op});throw Error('unknown identity; retain claims');}
    if(bytes.includes(Buffer.from(ctx.target.token)))throw Error('secret in identity');await journal({phase:'response',op,status:response.status,bodyBase64:bytes.toString('base64')});if(response.status!==200)throw Error('identity rejected');let x;try{x=JSON.parse(bytes.toString('utf8'));}catch{throw Error('invalid identity');}
    if(op==='identity'){if(x?.name!==`projects/${projectNumber}` || x.projectId!==ctx.project)throw Error('project identity mismatch');return {known:true,ok:true};}
    if(x?.name!==`projects/${ctx.project}/databases/${ctx.database}` || x.uid!==uid || x.type!=='FIRESTORE_NATIVE' || x.databaseEdition!=='ENTERPRISE' || x.locationId!=='us-central1' || x.firestoreDataAccessMode!=='DATA_ACCESS_MODE_ENABLED' || x.deleteProtectionState!=='DELETE_PROTECTION_DISABLED')throw Error('database identity mismatch');return {known:true,uid,enterprise:true};
  };
}
