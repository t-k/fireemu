import {isDeepStrictEqual} from 'node:util';
import {buildRestRequest,documentsName,guardRestRequest,SANDBOX_PROJECT} from './harness.mjs';

// The only mutable resource is this fixed document inside the reviewed database.
export function createNumericSupport(ctx,{fetchFn=fetch,claim,journal,timeoutMs=60000}={}) {
  if(ctx.project!==SANDBOX_PROJECT || ctx.database!=='entpipe2-20261029' || ctx.stageContextDatabase!==ctx.database || ctx.target?.kind!=='production' || ctx.target.quotaProject!==ctx.project || !ctx.target.token || typeof claim!=='function' || typeof journal!=='function')throw Error('unbound numeric target');
  const name=`${documentsName(ctx)}/numeric-probe/d1`,fields={anchor:{integerValue:'1'}};let phase='initial',updateTime;
  return async function support(op) {
    const expected={baseline:'initial',seed:'baseline',verify:'seeded','delete-owned':'verified','verify-absence':'deleted'};
    if(phase!==expected[op] || !expected[op])throw Error('invalid support phase');
    try {
      const step=op==='seed'?{rpc:'commit',body:{writes:[{update:{name,fields},currentDocument:{exists:false}}]}}:op==='delete-owned'?{rpc:'commit',body:{writes:[{delete:name,currentDocument:{updateTime}}]}}:{rpc:'get',parent:'numeric-probe/d1'};
      const built=buildRestRequest({id:op,...step},ctx,new Map());guardRestRequest(built,ctx,{harness:true});
      await claim(op);await journal({phase:'attempt',op,method:built.init.method,url:built.url,body:built.init.body??null});
      let response,bytes;try{response=await fetchFn(built.url,{...built.init,redirect:'error',signal:AbortSignal.timeout(timeoutMs)});await journal({phase:'headers',op,status:response.status});if(response.body){let parts=[],size=0;for await(const part of response.body){size+=part.length;if(size>1048576)throw Error('body limit');parts.push(Buffer.from(part));}bytes=Buffer.concat(parts);}else{bytes=Buffer.from(await response.text());if(bytes.length>1048576)throw Error('body limit');}}catch{await journal({phase:'unknown',op});throw Error('unknown transport; retain claims');}
      if(bytes.includes(Buffer.from(ctx.target.token)))throw Error('secret in response');await journal({phase:'response',op,status:response.status,bodyBase64:bytes.toString('base64')});
      let body;try{body=JSON.parse(bytes.toString('utf8'));}catch{throw Error('invalid response');}
      if(op==='baseline'||op==='verify-absence'){if(response.status!==404 || body?.error?.code!==404 || body.error.status!=='NOT_FOUND')throw Error('absence not proven');}
      else if(response.status!==200)throw Error('known rejection; retain claims');
      else if(op==='verify'){if(body.name!==name || !isDeepStrictEqual(body.fields,fields) || typeof body.updateTime!=='string' || !/^\d{4}-\d{2}-\d{2}T/.test(body.updateTime))throw Error('typed document mismatch');updateTime=body.updateTime;}
      phase={baseline:'baseline',seed:'seeded',verify:'verified','delete-owned':'deleted','verify-absence':'initial'}[op];return {known:true,ok:true};
    }catch(error){phase='unknown';throw error;}
  };
}
