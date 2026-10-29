import {aggregateVectorFields} from './aggregate-vector-corpus.mjs';
import {isDeepStrictEqual} from 'node:util';
import {buildRestRequest,documentsName,guardRestRequest,SANDBOX_PROJECT} from './harness.mjs';

// Only these three documents in the verified empty collection can be mutated.
export function createAggregateVectorSupport(ctx,{fetchFn=fetch,claim,journal,timeoutMs=60000}={}) {
 if(ctx.project!==SANDBOX_PROJECT||!/^entpipe2-[0-9]{8}$/.test(ctx.database)||ctx.stageContextDatabase!==ctx.database||ctx.target?.kind!=='production'||ctx.target.quotaProject!==ctx.project||!ctx.target.token||typeof claim!=='function'||typeof journal!=='function')throw Error('unbound target');
 const names=[1,2,3].map(n=>`${documentsName(ctx)}/aggvec/d${n}`),fields=aggregateVectorFields(),updateTimes=[];let phase='collection-baseline',index=1;
 return async function support(op,detail={}){
  if(op!==phase||(['baseline','verify','verify-absence'].includes(op)&&detail.document!==index))throw Error('invalid support phase');
  try{
   const step=op==='collection-baseline'?{rpc:'listDocuments',collectionId:'aggvec',query:[['pageSize','1']]}:op==='seed'?{rpc:'commit',body:{writes:names.map((name,i)=>({update:{name,fields:fields[i]},currentDocument:{exists:false}}))}}:op==='delete-owned'?{rpc:'commit',body:{writes:names.map((name,i)=>({delete:name,currentDocument:{updateTime:updateTimes[i]}}))}}:{rpc:'get',parent:`aggvec/d${index}`};
   const built=buildRestRequest({id:op,...step},ctx,new Map());guardRestRequest(built,ctx,{harness:true});await claim(op);await journal({phase:'attempt',op,method:built.init.method,url:built.url,body:built.init.body??null});
   let response,bytes;try{response=await fetchFn(built.url,{...built.init,redirect:'error',signal:AbortSignal.timeout(timeoutMs)});await journal({phase:'headers',op,status:response.status});if(response.body){let parts=[],size=0;for await(const part of response.body){size+=part.length;if(size>1048576)throw Error('body limit');parts.push(Buffer.from(part));}bytes=Buffer.concat(parts);}else{bytes=Buffer.from(await response.text());if(bytes.length>1048576)throw Error('body limit');}}catch{await journal({phase:'unknown',op});throw Error('unknown transport; retain claims');}
   if(bytes.includes(Buffer.from(ctx.target.token)))throw Error('secret in response');await journal({phase:'response',op,status:response.status,bodyBase64:bytes.toString('base64')});let body;try{body=JSON.parse(bytes.toString('utf8'));}catch{throw Error('invalid response');}
   if(op==='collection-baseline'){if(response.status!==200||!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).some(k=>!['documents','nextPageToken'].includes(k))||(body.documents!==undefined&&(!Array.isArray(body.documents)||body.documents.length!==0))||(body.nextPageToken!==undefined&&body.nextPageToken!==''))throw Error('collection not proven empty');}
   else if(op==='baseline'||op==='verify-absence'){if(response.status!==404||body?.error?.code!==404||body.error.status!=='NOT_FOUND')throw Error('absence not proven');}
   else if(response.status!==200)throw Error('known rejection; retain claims');
   else if(op==='verify'){if(body.name!==names[index-1]||!isDeepStrictEqual(body.fields,fields[index-1])||typeof body.updateTime!=='string'||!/^\d{4}-\d{2}-\d{2}T/.test(body.updateTime))throw Error('typed document mismatch');updateTimes[index-1]=body.updateTime;}
   if(op==='collection-baseline'){phase='baseline';index=1;}else if(op==='baseline'){if(index===3){phase='seed';index=1;}else index++;}else if(op==='seed'){phase='verify';index=1;}else if(op==='verify'){if(index===3){phase='delete-owned';index=1;}else index++;}else if(op==='delete-owned'){phase='verify-absence';index=1;}else if(index===3){phase='collection-baseline';index=1;updateTimes.length=0;}else index++;
   return {known:true,ok:true};
  }catch(error){phase='unknown';throw error;}
 };
}
