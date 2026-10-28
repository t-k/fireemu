import {open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const SECRET = /(?:AIza[\w-]{15,}|ya29\.[\w.-]+|eyJ[\w-]{15,}\.[\w-]+|Bearer\s+\S+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/i;
export async function createTransport({file,max,reserve,wire}) {
 if (!Number.isInteger(max)||max<1||!Number.isInteger(reserve)||reserve<0||reserve>=max||typeof wire!=='function') throw Error('invalid transport config');
 const handle=await open(file,'wx',0o600); let used=0,unknown=false;
 const append=async row=>{const line=JSON.stringify(row);if(SECRET.test(line)) throw Error('secret-shaped output refused');await handle.write(`${line}\n`);await handle.sync();};
 const invoke=async request=>{
  if(unknown) throw Error('sticky unknown');
  if(used>=max || (request.phase!=='cleanup' && used>=max-reserve)) throw Error('budget');
  if(!['GET','PUT','PATCH','POST','DELETE'].includes(request.method)||typeof request.url!=='string'||SECRET.test(JSON.stringify(request))) throw Error('invalid request');
  used++; const id=used; await append({state:'before-send',id,method:request.method,url:request.url,phase:request.phase,body:request.body});
  let receipt=false, bodyCaptured=false; const onHeaders=async (status,headers)=>{if(receipt||!Number.isInteger(status))throw Error('invalid headers'); const safe={};for(const k of ['etag','content-type','content-length'])if(typeof headers[k]==='string'&&!SECRET.test(headers[k]))safe[k]=headers[k];await append({state:'response-headers',id,status,headers:safe});receipt=true;};
  onHeaders.body=async raw=>{if(!receipt||bodyCaptured||!Buffer.isBuffer(raw)||raw.length>1048576||SECRET.test(raw.toString('latin1')))throw Error('body refused');await append({state:'response-persisted',id,redacted:request.step==='auth-preflight',bodyBase64:raw.toString('base64'),bodyBytes:raw.length,bodySha256:createHash('sha256').update(raw).digest('hex')});bodyCaptured=true;};
  let response; try{response=await wire(request,onHeaders); if(!receipt)throw Error('missing headers'); if(!response||!Number.isInteger(response.status)||response.status<200||response.status>=300||!Buffer.isBuffer(response.raw)||response.raw.length>1048576||typeof response.body!=='string'||!response.headers||SECRET.test(response.body))throw Error('unknown response');if(!bodyCaptured)await onHeaders.body(response.raw);}catch{unknown=true;try{await append({state:'unknown',id});}catch{}throw Error('unknown response');}
  return response;
 };
 invoke.close=()=>handle.close(); return invoke;
}

export function makeWire({instance,token,fetchImpl=fetch,timeoutMs=25000}) {
 if(typeof instance!=='string'||!/^[a-z][a-z0-9-]{3,62}$/.test(instance)||typeof token!=='string'||!token||typeof fetchImpl!=='function'||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>25000)throw Error('invalid wire config');
 const hosts=new Set([`${instance}.firebaseio.com`,'firebasedatabase.googleapis.com','serviceusage.googleapis.com']);
 return async (request,onHeaders=async()=>{})=>{
  const u=new URL(request.url);if(u.protocol!=='https:'||!hosts.has(u.hostname)||u.port||u.username||u.password||u.hash)throw Error('host refused');
  const headers={};if(request.step!=='corpus')headers.authorization=`Bearer ${token}`;if(request.body!==undefined)headers['content-type']='application/json';
  const response=await fetchImpl(u,{method:request.method,headers,body:request.body,redirect:'manual',signal:AbortSignal.timeout(timeoutMs)});
  const out={};for(const k of ['etag','content-type','content-length']){const v=response.headers.get(k);if(v!==null&&!SECRET.test(v))out[k]=v;}
  await onHeaders(response.status,out);
  if(response.status<200||response.status>=300)throw Error('non-success response');
  const chunks=[];let total=0; if(response.body) { const reader=response.body.getReader(); try { for (;;) { const {done,value}=await reader.read(); if(done)break; total+=value.byteLength; if(total>1048576){await reader.cancel();throw Error('response too large');} chunks.push(value); } } finally { reader.releaseLock(); } }
  const raw=Buffer.concat(chunks,total);if(onHeaders.body)await onHeaders.body(raw);const body=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw);
  return {status:response.status,headers:out,body,raw};
 };
}
