import {createHash} from 'node:crypto';
import {recoverInstance} from './recovery.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function validateRulesRestore(p) {
 if(p?.mode!=='rules-restore'||!/^[a-z][a-z0-9-]{3,62}$/.test(p.project??'')||!/^[0-9]{1,20}$/.test(p.projectNumber??'')||!/^[a-z][a-z0-9-]{3,62}$/.test(p.instance??'')||!/^[a-z0-9-]{3,32}$/.test(p.location??'')||p.maxRequests!==24||p.cleanupReserve!==0||!/^rnext1_[a-f0-9]{24}$/.test(p.prefix??'')||typeof p.baselineRulesBase64!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(p.baselineRulesBase64)||p.baselineRulesBase64.length%4!==0)throw Error('restore contract');
 const raw=Buffer.from(p.baselineRulesBase64,'base64');if(raw.length<1||raw.length>1048576||raw.toString('base64')!==p.baselineRulesBase64||sha(raw)!==p.baselineRulesSha256)throw Error('restore Rules identity');
 const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw);if(!Buffer.from(text).equals(raw))throw Error('restore Rules encoding');
 return {raw,text};
}
export async function recoverRules(io,p,sleep) {
 const {raw,text}=validateRulesRestore(p);
 const root=`https://${p.instance}.firebaseio.com`;
 const call=async(step,method,url,body)=>{const r=await io({step,method,url,body,phase:'normal'});if(!r||r.status<200||r.status>=300||!Buffer.isBuffer(r.raw))throw Error(`${step}: incomplete`);return r;};
 await call('prefix-delete','DELETE',`${root}/${p.prefix}.json`);
 const empty=await call('prefix-read','GET',`${root}/${p.prefix}.json`);let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(empty.raw));}catch{throw Error('prefix unreadable');}if(value!==null)throw Error('prefix not empty');
 await call('rules-put','PUT',`${root}/.settings/rules.json`,text);
 const restored=await call('rules-read','GET',`${root}/.settings/rules.json`);if(!restored.raw.equals(raw))throw Error('Rules not restored');
 return recoverInstance(io,{...p,maxRequests:20},sleep);
}

// A restore packet admits only its four data/Rules requests and the exact recovery management route.
export function assertRestoreRequest(r,p,disableOperation) {
 const {text}=validateRulesRestore(p);const db=`https://${p.instance}.firebaseio.com`,management=`https://firebasedatabase.googleapis.com/v1beta/projects/${p.projectNumber}/locations`,instance=`${management}/${p.location}/instances/${p.instance}`,service=`https://serviceusage.googleapis.com/v1/projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`;
 const fixed={
  'prefix-delete':['DELETE',`${db}/${p.prefix}.json`], 'prefix-read':['GET',`${db}/${p.prefix}.json`],
  'rules-put':['PUT',`${db}/.settings/rules.json`,text], 'rules-read':['GET',`${db}/.settings/rules.json`],
  'instance-before':['GET',instance], 'instance-disable':['POST',`${instance}:disable`], 'instance-disabled':['GET',instance],
  'instance-delete':['DELETE',instance], 'instance-deleted':['GET',instance], 'active-after':['GET',`${management}/-/instances`],
  'service-before':['GET',service], 'api-disable':['POST',`${service}:disable`,'{}'], 'api-disabled':['GET',service],
 };
 let expected=fixed[r.step];if(/^api-disable-poll-[0-9]$/.test(r.step??'')&&typeof disableOperation==='string')expected=['GET',`https://serviceusage.googleapis.com/v1/${disableOperation}`];
 if(r.phase!=='normal'||!expected||r.method!==expected[0]||r.url!==expected[1]||r.body!==expected[2])throw Error('restore route refused');
}

// The old packet and journal are immutable private evidence, never authority for a new run.
export function validateRestoreEvidence(p,packetBytes,journalBytes) {
 validateRulesRestore(p);
 if(!Buffer.isBuffer(packetBytes)||!Buffer.isBuffer(journalBytes)||sha(packetBytes)!==p.originalPacketSha256||sha(journalBytes)!==p.originalJournalSha256||p.originalSourceCommit!=='8270dfd58ef553aad13096411785006123055eac')throw Error('restore provenance');
 let old,rows;try{old=JSON.parse(packetBytes.toString('utf8'));rows=journalBytes.toString('utf8').trim().split('\n').map(x=>JSON.parse(x));}catch{throw Error('restore provenance unreadable');}
 if(rows.some(x=>x.state==='unknown')||rows.at(-1)?.id!==128||rows.at(-1)?.state!=='known-rejection'||rows.at(-1)?.status!==400)throw Error('restore journal terminal mismatch');
 if(old?.mode!=='rules-operators'||old.sourceCommit!==p.originalSourceCommit||old.baselineRulesSha256!==p.baselineRulesSha256||['project','projectNumber','instance','location'].some(k=>old[k]!==p[k]))throw Error('restore old packet identity');
 const get=(id,status)=>{const list=rows.filter(x=>x.id===id),pick=state=>{const found=list.filter(x=>x.state===state);if(found.length!==1)throw Error('restore journal shape');return found[0];};const request=pick('before-send'),headers=pick('response-headers'),body=pick('response-persisted');if(headers.status!==status||typeof body.bodyBase64!=='string')throw Error('restore journal status');const raw=Buffer.from(body.bodyBase64,'base64');if(raw.toString('base64')!==body.bodyBase64||raw.length!==body.bodyBytes||sha(raw)!==body.bodySha256)throw Error('restore journal body');return {request,raw};};
 const apiBefore=get(2,200),enable=get(3,200),enableDone=get(4,200),apiAfter=get(5,200),instanceBefore=get(6,200);
 const serviceName=`projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`,service=`https://serviceusage.googleapis.com/v1/${serviceName}`,instanceName=`projects/${p.projectNumber}/locations/${p.location}/instances/${p.instance}`,instanceUrl=`https://firebasedatabase.googleapis.com/v1beta/${instanceName}`;
 let a,b,c,d,e;try{[a,b,c,d,e]=[apiBefore,enable,enableDone,apiAfter,instanceBefore].map(x=>JSON.parse(x.raw.toString('utf8')));}catch{throw Error('restore baseline unreadable');}
 if(apiBefore.request.method!=='GET'||apiBefore.request.url!==service||a?.name!==serviceName||a.state!=='DISABLED'||enable.request.method!=='POST'||enable.request.url!==`${service}:enable`||b?.name!==p.originalOperation||enableDone.request.method!=='GET'||enableDone.request.url!==`https://serviceusage.googleapis.com/v1/${p.originalOperation}`||c?.name!==p.originalOperation||c.done!==true||c.error!==undefined||apiAfter.request.method!=='GET'||apiAfter.request.url!==service||d?.name!==serviceName||d.state!=='ENABLED'||instanceBefore.request.method!=='GET'||instanceBefore.request.url!==instanceUrl||e?.name!==instanceName||e.type!=='USER_DATABASE'||e.state!=='DELETED')throw Error('restore baseline mismatch');
 const beforeRules=get(11,200),beforePrefix=get(12,200),failure=get(128,400),db=`https://${p.instance}.firebaseio.com`;
 if(beforeRules.request.method!=='GET'||beforeRules.request.url!==`${db}/.settings/rules.json`||!beforeRules.raw.equals(Buffer.from(p.baselineRulesBase64,'base64'))||beforePrefix.request.method!=='GET'||beforePrefix.request.url!==`${db}/${p.prefix}.json`||beforePrefix.raw.toString('utf8').trim()!=='null'||failure.request.method!=='GET'||sha(failure.raw)!==p.failureBodySha256)throw Error('restore journal mismatch');
}
export function validateFailureEvidence(p,packetBytes,spentBytes,indexBytes,rowBytes) {
 if(sha(spentBytes)!==p.originalSpentSha256||sha(indexBytes)!==p.failureIndexSha256||sha(rowBytes)!==p.failureLedgerRowSha256)throw Error('failure evidence hash');
 let old,spent,index,row;try{old=JSON.parse(packetBytes.toString('utf8'));spent=JSON.parse(spentBytes.toString('utf8'));index=JSON.parse(indexBytes.toString('utf8'));row=JSON.parse(rowBytes.toString('utf8'));}catch{throw Error('failure evidence unreadable');}
 if(spent.digest!==p.originalPacketSha256||!/^[a-f0-9]{64}$/.test(spent.nonceSha256??'')||index.outcome!=='needs-recovery-not-closed'||row.outcome!=='needs-recovery'||row.project!==p.project||row.packetId!==old.packetId||row.requests!==128||row.rawJournalSha256!==p.originalJournalSha256||row.taskRequests!==p.previousDirectRequests||row.taskAdcAcquisitions!==p.previousAdcAcquisitions||row.taskCarriedUsd!==p.previousReservationAccountingUsd||row.taskRequestCeiling!==p.currentAdmittedTaskRequestCap||row.projectLeaseRetained!==true||row.baselineRestorationVerified!==false||row.sandboxAtBaseline!==false)throw Error('failure evidence mismatch');
}
