import { verifyPacket } from './packet-gate.mjs';
import { createTransport } from './transport.mjs';
import { lifecycle } from './lifecycle.mjs';
import { runCorpus } from './runner.mjs';

// wire is injected by the caller. This module never acquires credentials or starts network access.
export async function runPacket({packet,digest,wire,output,prefix,transport}) {
 const p=await verifyPacket(packet,digest);
 if(!/^rnext1_[a-f0-9]{24}$/.test(prefix)) throw Error('invalid run prefix');
 const base=`https://${p.instance}.firebaseio.com`, mgmt=`https://firebasedatabase.googleapis.com/v1beta/projects/${p.projectNumber}/locations`, service=`https://serviceusage.googleapis.com/v1/projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`, instance=`${mgmt}/${p.location}/instances/${p.instance}`;
 const counted=transport ?? await createTransport({file:output,max:p.maxRequests,reserve:p.cleanupReserve,wire});
 const url=(path)=>/^operations\/[A-Za-z0-9_-]+$/.test(path)?`https://serviceusage.googleapis.com/v1/${path}`:path==='service'?service:path==='service:enable'?`${service}:enable`:path==='service:disable'?`${service}:disable`:path==='instances'?`${mgmt}/-/instances`:path==='instance'?instance:path.startsWith('instance:')?`${instance}:${path.slice(9)}`:path==='rules'?`${base}/.settings/rules.json`:`${base}/${path}.json`;
 let cleanup=false;
 const io=async (step,method,path,body)=>{if(step==='prefix-delete') cleanup=true;const response=await counted({step,method,url:url(path),body:body===undefined?undefined:typeof body==='string'?body:JSON.stringify(body),phase:cleanup?'cleanup':'normal'});if(step==='rules-before'||step==='rules-restored')return response.body;try{return JSON.parse(response.body);}catch{throw Error(`${step}: unreadable response`);}};
 const state={used:0,max:p.maxRequests,cleanupReserve:0,unknown:false,journal:[]};
 const corpus=()=>runCorpus(state,async req=>counted({step:'corpus',method:req.method,url:`${base}${req.path}${req.query?'?'+req.query:''}`,body:req.body,phase:req.phase}),prefix,p.anchors);
 try{return await lifecycle(io,{prefix,instanceName:`projects/${p.projectNumber}/locations/${p.location}/instances/${p.instance}`,baselineHash:p.baselineRulesSha256,serviceName:`projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`},corpus);}finally{if(!transport)await counted.close();}
}
