// Offline comparison of finite production query bounds observations.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import {judge} from './rest-next4-replay.mjs';
const queries=[['equalTo','orderBy=%22h%22&equalTo=2'],['endAt','orderBy=%22h%22&endAt=2'],['startAfter','orderBy=%22h%22&startAfter=2'],['endBefore','orderBy=%22h%22&endBefore=2']];
export function validateFixture(f){
 if(f?.version!==1||f.source?.requestCount!==47||f.source?.corpusSupportCount!==20||f.source?.otherCount!==27||f.source?.observationCount!==8||f.source?.anchorCount!==4||!Array.isArray(f.rounds)||f.rounds.length!==2||typeof f.rulesTemplate!=='string'||!f.rulesTemplate.includes('__ROOT__'))throw Error('fixture shape');
 const ids=new Set();for(const [i,round] of f.rounds.entries()){const r=i+1;if(round.round!==r||round.rows.length!==10)throw Error('round shape');let n=0;const expected=[['query-seed','support','PUT','queryrule',''],['query-readback','support','GET','queryrule',''],...queries.map(([id,q])=>[id,'observation','GET','queryrule',q]),['patch-anchor-seed','support','PUT','patch',''],['query-anchor-seed','support','PUT','query',''],['patch-anchor','anchor','PATCH','patch',''],['query-anchor','anchor','GET','query','orderBy=%22h%22&startAt=2']];
  for(const [id,role,verb,path,query] of expected){const row=round.rows[n++];if(row.id!==id||row.role!==role||row.method!==verb||row.path!==`/r${r}/${path}.json`||row.query!==query)throw Error('row shape');if(!Number.isSafeInteger(row.requestId)||ids.has(row.requestId)||!Number.isInteger(row.status)||typeof row.bodyBase64!=='string'||!row.headers||typeof row.headers!=='object'||!(row.requestBody===null||typeof row.requestBody==='string'))throw Error('row metadata');ids.add(row.requestId);}
 }
 return true;
}
function safe(value){if(typeof value==='number')return Number.isSafeInteger(value);if(Array.isArray(value))return value.every(safe);if(value&&typeof value==='object')return Object.values(value).every(safe);return true;}
export function judgeQuery(row,local){
 const exact=row.status===200&&row.role==='observation'&&row.method==='GET'&&/^\/r[12]\/queryrule\.json$/.test(row.path)&&queries.some(([id,q])=>id===row.id&&q===row.query);
 if(!exact)return judge(row,local);
 const differences=[],diagnostics=[];if(local.status!==row.status)differences.push('status');if((local.headers?.etag??null)!==(row.headers?.etag??null))differences.push('etag');const a=Buffer.from(local.bodyBase64,'base64'),b=Buffer.from(row.bodyBase64,'base64');let av,bv;try{av=JSON.parse(a.toString('utf8'));bv=JSON.parse(b.toString('utf8'));}catch{}if(!av||!bv||typeof av!=='object'||typeof bv!=='object'||Array.isArray(av)||Array.isArray(bv)||!safe(av)||!safe(bv)||!isDeepStrictEqual(av,bv))differences.push('body');else if(!a.equals(b))diagnostics.push('raw-body-differs');for(const n of ['content-type','content-length'])if((row.headers?.[n]??null)!==(local.headers?.[n]??null))diagnostics.push(`${n}-differs`);return {id:row.id,verdict:differences.length?'MISMATCH':'MATCH',differences,diagnostics,policy:'filtered-query-json-object'};
}
export function localOrigin(origin){const u=new URL(origin);if(u.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(u.hostname)||u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw Error('local origin required');return u;}
export async function replayRows(fixture,send,root='ruleslocal'){
 validateFixture(fixture);if(!/^[A-Za-z0-9_-]+$/.test(root))throw Error('invalid root');let stopped=false;const rounds=[];
 for(const round of fixture.rounds){const rows=[];for(const row of round.rows){if(stopped){rows.push({id:row.id,role:row.role,verdict:'BLOCKED'});continue;}const req={id:row.id,method:row.method,url:`/${root}${row.path}${row.query?'?'+row.query:''}`,body:row.requestBody??undefined,owner:row.role==='support'};try{const local=await send(req);rows.push({...judgeQuery(row,local),role:row.role,production:{status:row.status,headers:row.headers,bodyBase64:row.bodyBase64},local});}catch(e){stopped=true;rows.push({id:row.id,role:row.role,verdict:'ERROR',reason:String(e?.message??e)});}}rounds.push({round:round.round,rows});}return rounds;
}
export async function replay(origin,fixture,{root='ruleslocal'}={}){
 const u=localOrigin(origin);validateFixture(fixture);if(!/^[A-Za-z0-9_-]+$/.test(root))throw Error('invalid root');
 const owner={'authorization':'Bearer owner','content-type':'application/json'};const request=async(path,options)=>fetch(`${u.origin}${path}`,{...options,redirect:'error',signal:AbortSignal.timeout(10000)});
 const result={source:fixture.source,rounds:[],failure:null,cleanup:{prefix:{status:'not-attempted'},rules:{status:'not-attempted'}}};let original,owned=false,installAttempted=false;
 try{
  const baseline=await request('/.settings/rules.json',{headers:owner});if(baseline.status!==200)throw Error('baseline rules');original=await baseline.text();
  const before=await request(`/${root}.json`,{headers:owner});if(before.status!==200||JSON.parse(await before.text())!==null)throw Error('prefix not empty');owned=true;
  const rules=fixture.rulesTemplate.replaceAll('__ROOT__',root);JSON.parse(rules);installAttempted=true;const installed=await request('/.settings/rules.json',{method:'PUT',headers:owner,body:rules});if(installed.status!==200)throw Error('rules install');
  result.rounds=await replayRows(fixture,async r=>{const headers=r.owner?{...owner}:{};if(r.body!==undefined)headers['content-type']='application/json';const response=await request(r.url,{method:r.method,headers,body:r.body});const raw=Buffer.from(await response.arrayBuffer());return {status:response.status,headers:Object.fromEntries(['etag','content-type','content-length'].map(k=>[k,response.headers.get(k)]).filter(([,v])=>v!==null)),bodyBase64:raw.toString('base64')};},root);
  if(result.rounds.some(r=>r.rows.some(x=>x.verdict==='ERROR')))result.failure='local transport failure';
 }catch(e){result.failure=String(e?.message??e);}
 finally{
  if(owned&&installAttempted){try{const wipe=await request(`/${root}.json`,{method:'DELETE',headers:owner});if(wipe.status!==200)throw Error('local wipe');const check=await request(`/${root}.json`,{headers:owner});if(check.status!==200||JSON.parse(await check.text())!==null)throw Error('local wipe readback');result.cleanup.prefix={status:'restored'};}catch(e){result.cleanup.prefix={status:'failed',error:String(e?.message??e)};}}
  if(installAttempted&&original!==undefined){try{const restore=await request('/.settings/rules.json',{method:'PUT',headers:owner,body:original});if(restore.status!==200)throw Error('local rules restore');const check=await request('/.settings/rules.json',{headers:owner});if(check.status!==200||await check.text()!==original)throw Error('local rules restore readback');result.cleanup.rules={status:'restored'};}catch(e){result.cleanup.rules={status:'failed',error:String(e?.message??e)};}}
 }
 return result;
}
async function main(args){
 const [mode,origin,out]=args;if(mode!=='local'||!origin||!out||args.length!==3)throw Error('usage: local <loopback-origin> <new-output-dir>');
 await mkdir(out);const f=JSON.parse(await readFile(new URL('./fixtures/production-query-bounds.json',import.meta.url),'utf8'));const result=await replay(origin,f);await writeFile(`${out}/comparison.json`,JSON.stringify(result,null,2)+'\n');
 const rows=result.rounds.flatMap(r=>r.rows),counts={};for(const row of rows)counts[row.verdict]=(counts[row.verdict]??0)+1;console.log(JSON.stringify({rows:rows.length,observations:rows.filter(x=>x.role==='observation').length,counts}));return result.failure||result.cleanup.prefix.status!=='restored'||result.cleanup.rules.status!=='restored'?2:rows.every(x=>x.verdict==='MATCH')?0:1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){main(process.argv.slice(2)).then(code=>{process.exitCode=code;},()=>{console.error('local query bounds replay stopped');process.exitCode=2;});}
