import { SANDBOX_PROJECT } from './harness.mjs';

// Two independent target identity reads; the numeric identifier comes from the reviewed packet.
export async function verifyStageProject(ctx, expectedNumber, {fetchFn=fetch,claim,journal,timeoutMs=60000} = {}) {
  if(ctx.project!==SANDBOX_PROJECT || ctx.target?.quotaProject!==SANDBOX_PROJECT || !ctx.target.token || !/^[1-9][0-9]{5,}$/.test(expectedNumber) || typeof claim!=='function' || typeof journal!=='function') throw new Error('unbound project identity');
  const url=`https://cloudresourcemanager.googleapis.com/v3/projects/${expectedNumber}`;
  for(let i=0;i<2;i++) {
    await claim('project-identity');await journal({phase:'attempt',op:'project-identity',url,method:'GET'});
    let response,bytes;
    try {
      response=await fetchFn(url,{method:'GET',redirect:'error',signal:AbortSignal.timeout(timeoutMs),headers:{authorization:`Bearer ${ctx.target.token}`,'x-goog-user-project':ctx.target.quotaProject}});
      await journal({phase:'headers',op:'project-identity',status:response.status});
      if(response.body){const parts=[];let size=0;for await(const part of response.body){size+=part.length;if(size>1048576)throw Error('body bound');parts.push(Buffer.from(part));}bytes=Buffer.concat(parts);}else {bytes=Buffer.from(await response.text());if(bytes.length>1048576)throw Error('body bound');}
    } catch {await journal({phase:'unknown',op:'project-identity'});throw new Error('unknown project identity');}
    if(bytes.includes(Buffer.from(ctx.target.token)))throw new Error('secret in identity response');
    await journal({phase:'response',op:'project-identity',status:response.status,bodyBase64:bytes.toString('base64')});
    if(response.status!==200)throw new Error('project identity rejected');
    let value;try{value=JSON.parse(bytes.toString('utf8'));}catch{throw new Error('invalid project identity');}
    if(value?.name!==`projects/${expectedNumber}` || value.projectId!==SANDBOX_PROJECT)throw new Error('project identity mismatch');
  }
}
