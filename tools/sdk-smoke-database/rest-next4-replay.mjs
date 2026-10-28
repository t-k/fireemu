// Offline local replay of the finite NEXT4 REST capture; no production access.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {isDeepStrictEqual} from 'node:util';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {FILTERED_QUERY_POLICY} from './rest-replay.mjs';

const data = value => Buffer.from(value,'base64');
export function bindPushKey(body) {
 let value;try{value=JSON.parse(body);}catch{throw Error('invalid POST body');}
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==1||typeof value.name!=='string'||!/^[-A-Za-z0-9_]{20}$/.test(value.name))throw Error('invalid push key');return value.name;
}
function safe(value){if(typeof value==='number')return Number.isSafeInteger(value);if(Array.isArray(value))return value.every(safe);if(value&&typeof value==='object')return Object.values(value).every(safe);return true;}
function queryPolicy(row){return row.id==='query-anchor'&&row.method==='GET'&&/^\/r[12]\/query\.json$/.test(row.path)&&row.query==='orderBy=%22h%22&startAt=2'&&row.status===200;}
export function judge(row,local,{placeholder,key}={}) {
 const differences=[],diagnostics=[];if(local.status!==row.status)differences.push('status');
 if((local.headers?.etag??null)!==(row.headers?.etag??null))differences.push('etag');
 let actual=data(local.bodyBase64),expected=data(row.bodyBase64);
 if(row.id==='post-child'&&row.method==='POST'&&key&&placeholder){const text=actual.toString('utf8');if(text.split(key).length!==2)differences.push('key-binding');else actual=Buffer.from(text.replace(key,placeholder));}
 if(queryPolicy(row)){
  let a,b;try{a=JSON.parse(actual.toString('utf8'));b=JSON.parse(expected.toString('utf8'));}catch{}
  if(!a||!b||typeof a!=='object'||typeof b!=='object'||Array.isArray(a)||Array.isArray(b)||!safe(a)||!safe(b)||!isDeepStrictEqual(a,b))differences.push('body');else if(!actual.equals(expected))diagnostics.push('raw-body-differs');
 }else if(!actual.equals(expected))differences.push('body');
 for(const n of ['content-type','content-length'])if((row.headers?.[n]??null)!==(local.headers?.[n]??null))diagnostics.push(`${n}-differs`);
 return {id:row.id,verdict:differences.length?'MISMATCH':'MATCH',differences,diagnostics,...(queryPolicy(row)?{policy:FILTERED_QUERY_POLICY.id}:{})};
}
export async function replayRound(round,send,{root='next4replay'}={}) {
 if(!/^[A-Za-z0-9_-]+$/.test(root)||![1,2].includes(round.round))throw Error('invalid replay scope');let key,stopped=false;const results=[];
 for(const row of round.rows){
  if(stopped){results.push({id:row.id,verdict:'BLOCKED',reason:'prior transport uncertainty'});continue;}
  const dependent=['read-child','delete-child','read-absence'].includes(row.id);if(dependent&&!key){results.push({id:row.id,verdict:'BLOCKED',reason:'unbound local push key'});continue;}
  const path=row.path.replace(round.generatedKeyPlaceholder,key??round.generatedKeyPlaceholder);const request={id:row.id,method:row.method,url:`/${root}${path}${row.query?'?'+row.query:''}`,body:row.requestBody??undefined};
  try {const local=await send(request);let bindingError;if(row.id==='post-child'){try{if(local.status!==200)throw Error('POST status');key=bindPushKey(data(local.bodyBase64).toString('utf8'));}catch{key=undefined;bindingError=true;}}
   const result=judge(row,local,{placeholder:round.generatedKeyPlaceholder,key});if(bindingError){result.verdict='MISMATCH';result.differences.push('invalid-local-push-key');}results.push({...result,...(row.id==='post-child'&&key?{binding:{placeholder:round.generatedKeyPlaceholder,localKey:key}}:{}),production:{status:row.status,headers:row.headers,bodyBase64:row.bodyBase64},local});
  }catch{stopped=true;if(row.id==='post-child')key=undefined;results.push({id:row.id,verdict:'ERROR',reason:'local transport failure'});}
 }
 return results;
}
export async function replayAll(rounds,send,options={}) {
 let stopped=false;const out=[];for(const round of rounds){const rows=stopped?round.rows.map(row=>({id:row.id,verdict:'BLOCKED',reason:'prior transport uncertainty'})):await replayRound(round,send,options);if(rows.some(row=>row.verdict==='ERROR'))stopped=true;out.push({round:round.round,rows});}return out;
}
export async function replay(origin,fixture,{root='next4replay'}={}) {
 const u=new URL(origin);if(u.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(u.hostname)||u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw Error('local origin required');
 const send=async r=>{const headers={};if(r.body!==undefined)headers['content-type']='application/json';const response=await fetch(`${u.origin}${r.url}`,{method:r.method,body:r.body,headers,signal:AbortSignal.timeout(10000)});const raw=Buffer.from(await response.arrayBuffer());return {status:response.status,headers:Object.fromEntries(['etag','content-type','content-length'].map(k=>[k,response.headers.get(k)]).filter(([,v])=>v!==null)),bodyBase64:raw.toString('base64')};};
 const rules={rules:{[root]:{'.read':true,'.write':true,r1:{query:{'.indexOn':['h']}},r2:{query:{'.indexOn':['h']}}}}};const setup=await fetch(`${u.origin}/.settings/rules.json`,{method:'PUT',headers:{authorization:'Bearer owner','content-type':'application/json'},body:JSON.stringify(rules),signal:AbortSignal.timeout(10000)});if(setup.status!==200)throw Error('local Rules setup failed');
 const rounds=await replayAll(fixture.rounds,send,{root});return {fixture:fixture.source,rounds};
}
async function main(args){const [mode,origin,out]=args;if(mode!=='local'||!origin||!out||args.length!==3)throw Error('usage: local <loopback-origin> <new-output-dir>');await mkdir(out);const fixture=JSON.parse(await readFile(new URL('./fixtures/production-rest-next4.json',import.meta.url),'utf8'));const result=await replay(origin,fixture);await writeFile(`${out}/comparison.json`,JSON.stringify(result,null,2)+'\n');const rows=result.rounds.flatMap(x=>x.rows),counts={};for(const r of rows)counts[r.verdict]=(counts[r.verdict]??0)+1;console.log(JSON.stringify({rows:rows.length,counts}));return rows.every(r=>r.verdict==='MATCH')?0:1;}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){main(process.argv.slice(2)).then(code=>{process.exitCode=code;},()=>{console.error('local NEXT4 replay stopped');process.exitCode=2;});}
