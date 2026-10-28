import { verifyPacket } from './packet-gate.mjs';
import { createTransport } from './transport.mjs';
import { lifecycle } from './lifecycle.mjs';
import { runCorpus } from './runner.mjs';
import { validOperation } from './recovery.mjs';

export function routeAdmin(path,p,prefix) {
 const base=`https://${p.instance}.firebaseio.com`, mgmt=`https://firebasedatabase.googleapis.com/v1beta/projects/${p.projectNumber}/locations`, service=`https://serviceusage.googleapis.com/v1/projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`, instance=`${mgmt}/${p.location}/instances/${p.instance}`;
 if(validOperation(path))return `https://serviceusage.googleapis.com/v1/${path}`;
 if(path==='service')return service;if(path==='service:enable'||path==='service:disable')return `${service}:${path.slice(8)}`;
 if(path==='instances')return `${mgmt}/-/instances`;if(path==='instance')return instance;
 if(['instance:undelete','instance:reenable','instance:disable'].includes(path))return `${instance}:${path.slice(9)}`;
 if(path==='rules')return `${base}/.settings/rules.json`;if(path===prefix)return `${base}/${prefix}.json`;
 throw Error('administration route refused');
}

export function rulesRequest(base,prefix,req) {
 if(!/^rnext1_[a-f0-9]{24}$/.test(prefix)||!req||req.phase!=='normal'||typeof req.path!=='string'||!req.path.startsWith(`/${prefix}/`))throw Error('Rules request refused');
 const relative=req.path.slice(prefix.length+2);let ok=false;
 if(req.step==='rules-owner-seed')ok=req.method==='PATCH'&&/^r[12]\.json$/.test(relative)&&!req.query;
 if(req.step==='rules-owner-anchor-seed')ok=req.method==='PUT'&&/^r[12]\/(?:patch|query)\.json$/.test(relative)&&!req.query;
 if(req.step==='rules-owner-read')ok=req.method==='GET'&&/^r[12]\/(?:cascade\/(?:parent|blocked)\/child|validation\/(?:number|negative|deletion)|snapshot\/(?:allow|newdeny|rootdeny)\/counter)\.json$/.test(relative)&&!req.query;
 if(req.step==='rules-case')ok=(req.method==='PUT'&&/^r[12]\/(?:cascade\/(?:parent|blocked)\/child|validation\/(?:number|negative)|snapshot\/(?:allow|newdeny|rootdeny)\/counter)\.json$/.test(relative)||req.method==='DELETE'&&/^r[12]\/validation\/deletion\.json$/.test(relative))&&!req.query;
 if(req.step==='rules-anchor')ok=req.method==='PATCH'&&/^r[12]\/patch\.json$/.test(relative)&&!req.query||req.method==='GET'&&/^r[12]\/query\.json$/.test(relative)&&req.query==='orderBy=%22h%22&startAt=2';
 if(!ok)throw Error('Rules request refused');return {step:req.step,method:req.method,url:`${base}${req.path}${req.query?'?'+req.query:''}`,body:req.body,phase:'normal'};
}

export function queryRequest(base,prefix,req){
 if(req?.step==='rules-anchor'||req?.step==='rules-owner-anchor-seed')return rulesRequest(base,prefix,req);
 if(!/^rnext1_[a-f0-9]{24}$/.test(prefix)||req?.phase!=='normal'||!new RegExp(`^/${prefix}/r[12]/queryrule\\.json$`).test(req?.path??''))throw Error('query request refused');
 const queries=['orderBy=%22h%22&limitToFirst=2','orderBy=%22h%22&limitToFirst=3','orderBy=%22h%22','orderBy=%22%24key%22&limitToFirst=2'];
 const ok=req.step==='query-owner-seed'&&req.method==='PUT'&&!req.query||req.step==='query-owner-read'&&req.method==='GET'&&!req.query||req.step==='query-case'&&req.method==='GET'&&queries.includes(req.query);
 if(!ok)throw Error('query request refused');return {step:req.step,method:req.method,url:`${base}${req.path}${req.query?'?'+req.query:''}`,body:req.body,phase:'normal'};
}

export function boundsRequest(base,prefix,req){
 if(req?.step==='rules-anchor'||req?.step==='rules-owner-anchor-seed')return rulesRequest(base,prefix,req);
 if(!/^rnext1_[a-f0-9]{24}$/.test(prefix)||req?.phase!=='normal'||!new RegExp(`^/${prefix}/r[12]/queryrule\\.json$`).test(req?.path??''))throw Error('bounds request refused');
 const queries=['orderBy=%22h%22&equalTo=2','orderBy=%22h%22&endAt=2','orderBy=%22h%22&startAfter=2','orderBy=%22h%22&endBefore=2'];
 const ok=req.step==='query-owner-seed'&&req.method==='PUT'&&!req.query||req.step==='query-owner-read'&&req.method==='GET'&&!req.query||req.step==='bounds-case'&&req.method==='GET'&&queries.includes(req.query);
 if(!ok)throw Error('bounds request refused');return {step:req.step,method:req.method,url:`${base}${req.path}${req.query?'?'+req.query:''}`,body:req.body,phase:'normal'};
}

export function priorityReadbackRequest(base,item,leaf){
 if(!/^https:\/\/[a-z][a-z0-9-]{3,62}\.firebaseio\.com$/.test(base)||!/^rnext1_[a-f0-9]{24}$/.test(item?.prefix??'')||!['r1','r2'].includes(item?.round)||!['heal-reregister','nested-priority','string-priority'].includes(item?.id)||!['s','t'].includes(leaf))throw Error('priority readback refused');
 return {step:'priority-owner-read',method:'GET',url:`${base}/${item.prefix}/${item.round}/${item.id}/${leaf}.json?format=export`,phase:'normal'};
}

export async function priorityReadback(counted,base,item){
 if(typeof counted!=='function')throw Error('priority transport missing');const result={};
 for(const leaf of ['s','t']){const response=await counted(priorityReadbackRequest(base,item,leaf));if(response?.status!==200||typeof response.body!=='string')throw Error('priority readback unresolved');try{result[leaf]=JSON.parse(response.body);}catch{throw Error('priority readback unresolved');}}
 return result;
}

// wire is injected by the caller. This module never acquires credentials or starts network access.
export async function runPacket({packet,digest,wire,output,prefix,transport,sleep,priorityBrowser}) {
 const p=await verifyPacket(packet,digest);
 if(p.mode==='priority-observation'&&typeof priorityBrowser!=='function')throw Error('priority browser missing');
 if(!/^rnext1_[a-f0-9]{24}$/.test(prefix)) throw Error('invalid run prefix');
 const base=`https://${p.instance}.firebaseio.com`, mgmt=`https://firebasedatabase.googleapis.com/v1beta/projects/${p.projectNumber}/locations`, service=`https://serviceusage.googleapis.com/v1/projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`, instance=`${mgmt}/${p.location}/instances/${p.instance}`;
 const counted=transport ?? await createTransport({file:output,max:p.maxRequests,reserve:p.cleanupReserve,wire});
 const url=(path)=>routeAdmin(path,p,prefix);
 let cleanup=false;
 const io=async (step,method,path,body)=>{if(step==='prefix-delete') cleanup=true;const response=await counted({step,method,url:url(path),body:body===undefined?undefined:typeof body==='string'?body:JSON.stringify(body),phase:cleanup?'cleanup':'normal'});if(step==='rules-before'||step==='rules-restored')return response.body;try{return JSON.parse(response.body);}catch{throw Error(`${step}: unreadable response`);}};
 const state={used:0,max:p.maxRequests,cleanupReserve:0,unknown:false,journal:[]};
 const corpus=p.mode==='priority-observation'?async()=>{if(typeof priorityBrowser!=='function')throw Error('priority browser missing');const {runPriorityCorpus}=await import('./priority-corpus.mjs');const {capturePriorityCase}=await import('./priority-controller.mjs');const browser=await priorityBrowser(item=>priorityReadback(counted,base,item));let error;try{await runPriorityCorpus({prefix,runCase:item=>capturePriorityCase(browser,item)});}catch(e){error=e;}try{await browser.close();}catch(e){error??=e;}if(error){await (sleep??(ms=>new Promise(resolve=>setTimeout(resolve,ms))))(150000);throw error;}}:p.mode==='query-bounds'?async()=>{const {runBoundsCorpus}=await import('./query-bounds.mjs');return runBoundsCorpus(req=>counted(boundsRequest(base,prefix,req)),prefix,p.anchors);}:p.mode==='query-rules'?async()=>{const {runQueryCorpus}=await import('./query-rules.mjs');return runQueryCorpus(req=>counted(queryRequest(base,prefix,req)),prefix,p.anchors);}:p.mode==='rules-observation'?async()=>{const {runRulesCorpus}=await import('./rules-corpus.mjs');return runRulesCorpus(req=>counted(rulesRequest(base,prefix,req)),prefix,p.anchors);}:()=>runCorpus(state,async req=>counted({step:'corpus',method:req.method,url:`${base}${req.path}${req.query?'?'+req.query:''}`,body:req.body,phase:req.phase}),prefix,p.anchors);
 try{return await lifecycle(io,{mode:p.mode,prefix,instanceName:`projects/${p.projectNumber}/locations/${p.location}/instances/${p.instance}`,baselineHash:p.baselineRulesSha256,instance:p.instance,sleep,baselineProbe:()=>counted({step:'baseline-propagation',method:'GET',url:`${base}/${prefix}.json`,phase:'normal'}),probe:()=>counted({step:'rules-propagation',method:'GET',url:`${base}/${prefix}${['rules-observation','query-rules','query-bounds','priority-observation'].includes(p.mode)?'/ready':''}.json`,phase:'normal'}),serviceName:`projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`},corpus);}finally{if(!transport)await counted.close();}
}
