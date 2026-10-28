import {open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
class KnownRejection extends Error { constructor(status){super('non-success response');this.status=status;} }
const SECRET = /(?:AIza[\w-]{15,}|ya29\.[\w.-]+|eyJ[\w-]{15,}\.[\w-]+|Bearer\s+\S+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/i;
export function knownPropagation(response,instance) {
 if(![401,403,423].includes(response?.status))return false;
 let v;try{v=JSON.parse(response.body);}catch{return false;}
 if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==1||typeof v.error!=='string')return false;
 return response.status===423?v.error===`The Firebase database '${instance}' has been disabled by a database owner.`:v.error==='Permission denied';
}
export function knownInstanceNotReady(response,project){
 if(response?.status!==403||typeof project!=='string'||!/^[a-z][a-z0-9-]{3,62}$/.test(project)||typeof response.body!=='string')return false;let doc;try{doc=JSON.parse(response.body);}catch{return false;}const e=doc?.error;if(e?.code!==403||e.status!=='PERMISSION_DENIED'||!Array.isArray(e.details))return false;const d=e.details.filter(x=>x?.['@type']==='type.googleapis.com/google.rpc.ErrorInfo');return d.length===1&&d[0].reason==='SERVICE_DISABLED'&&d[0].domain==='googleapis.com'&&d[0].metadata?.service==='firebasedatabase.googleapis.com'&&d[0].metadata?.consumer===`projects/${project}`;
}
function permittedInstanceReadiness(request,response){
 try{const u=new URL(request.url);return request.step==='instance-readiness'&&request.phase==='normal'&&request.method==='GET'&&typeof request.projectNumber==='string'&&/^[0-9]{1,20}$/.test(request.projectNumber)&&u.protocol==='https:'&&u.hostname==='firebasedatabase.googleapis.com'&&!u.port&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname===`/v1beta/projects/${request.projectNumber}/locations/-/instances`&&knownInstanceNotReady(response,request.expectedProject);}catch{return false;}
}
function permittedProbe(request,response){
 try{const u=new URL(request.url);const match=/^([a-z][a-z0-9-]{3,62})\.firebaseio\.com$/.exec(u.hostname);return (request.step==='rules-propagation'||(request.step==='baseline-propagation'&&response.status===423))&&request.method==='GET'&&u.protocol==='https:'&&!u.port&&!u.username&&!u.password&&!u.search&&!u.hash&&(request.step==='rules-propagation'?/^\/rnext1_[a-f0-9]{24}(?:\/ready)?\.json$/.test(u.pathname):/^\/rnext1_[a-f0-9]{24}\.json$/.test(u.pathname))&&!!match&&knownPropagation(response,match[1]);}catch{return false;}
}
function permittedRulesCase(request,response){
 try{const u=new URL(request.url);if(request.step!=='rules-case'||![401,403].includes(response?.status)||u.protocol!=='https:'||!/^([a-z][a-z0-9-]{3,62})\.firebaseio\.com$/.test(u.hostname)||u.port||u.username||u.password||u.search||u.hash)return false;const path=u.pathname;return request.method==='PUT'&&/^\/rnext1_[a-f0-9]{24}\/r[12]\/(?:cascade\/(?:parent|blocked)\/child|validation\/(?:number|negative)|snapshot\/(?:allow|newdeny|rootdeny)\/counter)\.json$/.test(path)||request.method==='DELETE'&&/^\/rnext1_[a-f0-9]{24}\/r[12]\/validation\/deletion\.json$/.test(path);}catch{return false;}
}
function permittedQueryCase(request,response){
 try{const u=new URL(request.url);return request.step==='query-case'&&request.method==='GET'&&[401,403].includes(response?.status)&&u.protocol==='https:'&&/^([a-z][a-z0-9-]{3,62})\.firebaseio\.com$/.test(u.hostname)&&!u.port&&!u.username&&!u.password&&!u.hash&&/^\/rnext1_[a-f0-9]{24}\/r[12]\/queryrule\.json$/.test(u.pathname)&&['?orderBy=%22h%22&limitToFirst=2','?orderBy=%22h%22&limitToFirst=3','?orderBy=%22h%22','?orderBy=%22%24key%22&limitToFirst=2'].includes(u.search);}catch{return false;}
}
function permittedBoundsCase(request,response){
 try{const u=new URL(request.url);return request.step==='bounds-case'&&request.method==='GET'&&[400,401,403].includes(response?.status)&&u.protocol==='https:'&&/^([a-z][a-z0-9-]{3,62})\.firebaseio\.com$/.test(u.hostname)&&!u.port&&!u.username&&!u.password&&!u.hash&&/^\/rnext1_[a-f0-9]{24}\/r[12]\/queryrule\.json$/.test(u.pathname)&&['?orderBy=%22h%22&equalTo=2','?orderBy=%22h%22&endAt=2','?orderBy=%22h%22&startAfter=2','?orderBy=%22h%22&endBefore=2'].includes(u.search);}catch{return false;}
}
function isLanguageCase(request) {
 try{const u=new URL(request.url);const m=/^\/rnext1_[a-f0-9]{24}\/r[12]\/(timestamp-valid|timestamp-negative|uid-allow|uid-deny|contains-allow|contains-deny|strict-allow|strict-deny)\.json$/.exec(u.pathname);if(request.step!=='language-case'||request.method!=='PUT'||u.protocol!=='https:'||!/^([a-z][a-z0-9-]{3,62})\.firebaseio\.com$/.test(u.hostname)||u.port||u.username||u.password||u.hash||!m)return false;const value=m[1].startsWith('uid-')?'{"uid":"sv-rule-user"}':'null';return u.search===`?auth_variable_override=${encodeURIComponent(value)}`;}catch{return false;}
}
function permittedLanguageCase(request,response){return isLanguageCase(request)&&[401,403].includes(response?.status);}
function isMethodsCase(request){
 try{const u=new URL(request.url),m=/^\/rnext1_[a-f0-9]{24}\/r[12]\/([A-Za-z-]+)(\/leaf)?\.json$/.exec(u.pathname);const ids=['exists-ok', 'exists-deny', 'hasChild-ok', 'hasChild-deny', 'hasChildren-any-ok', 'hasChildren-any-deny', 'hasChildren-list-ok', 'hasChildren-list-deny', 'getPriority-number', 'getPriority-string', 'getPriority-null', 'isString-ok', 'isString-deny', 'isBoolean-ok', 'isBoolean-deny', 'beginsWith-ok', 'beginsWith-deny', 'endsWith-ok', 'endsWith-deny', 'replace-all-ok', 'replace-first-only-deny', 'toLowerCase-ok', 'toLowerCase-deny', 'toUpperCase-ok', 'toUpperCase-deny', 'matches-ok', 'matches-deny'];return request.step==='methods-case'&&request.method==='GET'&&request.body===undefined&&u.protocol==='https:'&&/^([a-z][a-z0-9-]{3,62})\.firebaseio\.com$/.test(u.hostname)&&!u.port&&!u.username&&!u.password&&!u.hash&&u.search==='?auth_variable_override=null'&&!!m&&((['parent-ok','parent-deny'].includes(m[1])&&m[2]==='/leaf')||(ids.includes(m[1])&&!m[2]));}catch{return false;}
}
function permittedMethodsCase(request,response){return isMethodsCase(request)&&[401,403].includes(response?.status);}
export async function createTransport({file,max,reserve,wire}) {
 if (!Number.isInteger(max)||max<1||!Number.isInteger(reserve)||reserve<0||reserve>=max||typeof wire!=='function') throw Error('invalid transport config');
 const handle=await open(file,'wx',0o600); let used=0,unknown=false;
 const append=async row=>{const line=JSON.stringify(row);if(SECRET.test(line)) throw Error('secret-shaped output refused');await handle.write(`${line}\n`);await handle.sync();};
 const invoke=async request=>{
  if(unknown) throw Error('sticky unknown');
  if(used>=max || (request.phase!=='cleanup' && used>=max-reserve)) throw Error('budget');
  if(!['GET','PUT','PATCH','POST','DELETE'].includes(request.method)||typeof request.url!=='string'||SECRET.test(JSON.stringify(request))) throw Error('invalid request');
  used++; const id=used; await append({state:'before-send',id,method:request.method,url:request.url,phase:request.phase,body:request.body,...(request.step?.startsWith('sv-')?{step:request.step,atMillis:Date.now()}:{})});
  let receipt=false, bodyCaptured=false; const onHeaders=async (status,headers)=>{if(receipt||!Number.isInteger(status))throw Error('invalid headers'); const safe={};for(const k of ['etag','content-type','content-length'])if(typeof headers[k]==='string'&&!SECRET.test(headers[k]))safe[k]=headers[k];await append({state:'response-headers',id,status,headers:safe,...(request.step?.startsWith('sv-')?{atMillis:Date.now()}:{})});receipt=true;};
  onHeaders.body=async raw=>{if(!receipt||bodyCaptured||!Buffer.isBuffer(raw)||raw.length>1048576||SECRET.test(raw.toString('latin1')))throw Error('body refused');await append({state:'response-persisted',id,redacted:request.step==='auth-preflight',bodyBase64:raw.toString('base64'),bodyBytes:raw.length,bodySha256:createHash('sha256').update(raw).digest('hex')});bodyCaptured=true;};
  let response; try{response=await wire(request,onHeaders); if(!receipt)throw Error('missing headers'); if(!response||!Number.isInteger(response.status)||(response.status<200||response.status>=300)&&!permittedProbe(request,response)&&!permittedRulesCase(request,response)&&!permittedQueryCase(request,response)&&!permittedBoundsCase(request,response)&&!permittedLanguageCase(request,response)&&!permittedMethodsCase(request,response)&&!permittedInstanceReadiness(request,response)||!Buffer.isBuffer(response.raw)||response.raw.length>1048576||typeof response.body!=='string'||!response.headers||SECRET.test(response.body))throw Error('unknown response');if(!bodyCaptured)await onHeaders.body(response.raw);}catch(e){unknown=true;try{if(e instanceof KnownRejection && receipt && bodyCaptured){await append({state:'known-rejection',id,status:e.status});if(e.status<400||e.status>=500)await append({state:'unknown',id});}else await append({state:'unknown',id});}catch{}throw Error('request stopped');}
  return response;
 };
 invoke.observeServerValue=async observation=>{if(unknown)throw Error('sticky unknown');try{await append({state:'server-value-observation',observation});}catch{unknown=true;throw Error('observation stopped');}};
 invoke.observeRulesLanguage=async observation=>{if(unknown)throw Error('sticky unknown');try{await append({state:'rules-language-observation',observation});}catch{unknown=true;throw Error('observation stopped');}};
 invoke.observeRulesMethods=async observation=>{if(unknown)throw Error('sticky unknown');try{await append({state:'rules-methods-observation',observation});}catch{unknown=true;throw Error('observation stopped');}};
 invoke.close=()=>handle.close(); return invoke;
}

export function makeWire({instance,project,projectNumber,token,fetchImpl=fetch,timeoutMs=25000,serviceOnly=false,managementOnly=false}) {
 if(typeof project!=='string'||!/^[a-z][a-z0-9-]{3,62}$/.test(project)||typeof instance!=='string'||!/^[a-z][a-z0-9-]{3,62}$/.test(instance)||typeof token!=='string'||!token||typeof fetchImpl!=='function'||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>25000)throw Error('invalid wire config');
 const hosts=new Set(serviceOnly?['serviceusage.googleapis.com']:managementOnly?['firebasedatabase.googleapis.com','serviceusage.googleapis.com']:[`${instance}.firebaseio.com`,'firebasedatabase.googleapis.com','serviceusage.googleapis.com']);
 return async (request,onHeaders=async()=>{})=>{
  if(request.step==='instance-readiness'&&(request.expectedProject!==project||request.projectNumber!==projectNumber||!/^[0-9]{1,20}$/.test(projectNumber??'')))throw Error('readiness project refused');const u=new URL(request.url);if(u.protocol!=='https:'||!hosts.has(u.hostname)||u.port||u.username||u.password||u.hash)throw Error('host refused');
  if((u.searchParams.has('auth_variable_override')||['language-case','methods-case'].includes(request.step))&&!isLanguageCase(request)&&!isMethodsCase(request))throw Error('auth override refused');
  const headers={};if(request.step!=='corpus'&&request.step!=='rules-case'&&request.step!=='query-case'&&request.step!=='bounds-case'&&request.step!=='rules-anchor'&&request.step!=='rules-propagation'){headers.authorization=`Bearer ${token}`;headers['x-goog-user-project']=project;}if(request.body!==undefined)headers['content-type']='application/json';
  const response=await fetchImpl(u,{method:request.method,headers,body:request.body,redirect:'manual',signal:AbortSignal.timeout(timeoutMs)});
  const out={};for(const k of ['etag','content-type','content-length']){const v=response.headers.get(k);if(v!==null&&!SECRET.test(v))out[k]=v;}
  await onHeaders(response.status,out);
  const chunks=[];let total=0; if(response.body) { const reader=response.body.getReader(); try { for (;;) { const {done,value}=await reader.read(); if(done)break; total+=value.byteLength; if(total>1048576){await reader.cancel();throw Error('response too large');} chunks.push(value); } } finally { reader.releaseLock(); } }
  const raw=Buffer.concat(chunks,total);if(onHeaders.body)await onHeaders.body(raw);const body=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw);
  const result={status:response.status,headers:out,body,raw};if((response.status<200||response.status>=300)&&!permittedProbe(request,result)&&!permittedRulesCase(request,result)&&!permittedQueryCase(request,result)&&!permittedBoundsCase(request,result)&&!permittedLanguageCase(request,result)&&!permittedMethodsCase(request,result)&&!permittedInstanceReadiness(request,result))throw new KnownRejection(response.status);return result;
 };
}
