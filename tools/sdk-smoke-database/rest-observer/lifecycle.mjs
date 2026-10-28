import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { validOperation } from './recovery.mjs';
import { knownPropagation,knownInstanceNotReady } from './transport.mjs';

export async function waitForRules(probe,sleep,instance) {
 const waits=[2000,4000,8000,16000,30000,30000,30000];
 for(let i=0;i<=waits.length;i++){const r=await probe();if(r.status===200){let v;try{v=JSON.parse(r.body);}catch{throw Error('propagation response');}if(v!==null)throw Error('propagation nonempty');return;}if(!knownPropagation(r,instance)||i===waits.length)throw Error('propagation unresolved');await sleep(waits[i]);}
}

export async function waitForBaseline(probe,sleep,instance) {
 const waits=[2000,4000,8000,16000,30000,30000,30000];
 for(let i=0;i<=waits.length;i++){const r=await probe();if(r.status===200){let v;try{v=JSON.parse(r.body);}catch{throw Error('baseline response');}if(v!==null)throw Error('baseline nonempty');return;}if(r.status!==423||!knownPropagation(r,instance)||i===waits.length)throw Error('baseline unresolved');await sleep(waits[i]);}
}

export async function waitForInstanceList(probe,sleep,project){
 for(let i=0;i<12;i++){const r=await probe();if(r?.status===200){let value;try{value=JSON.parse(r.body);}catch{throw Error('instance readiness body');}if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['instances','nextPageToken'].includes(k))||('instances' in value&&(!Array.isArray(value.instances)||value.instances.length!==0))||('nextPageToken' in value&&value.nextPageToken!==''))throw Error('instance readiness shape');return value;}if(!knownInstanceNotReady(r,project)||i===11)throw Error('instance readiness unresolved');await sleep(10000);}
}

// io must provide counted, durable and sticky-unknown request semantics.
export async function lifecycle(io, p, corpus) {
 if(['priority-observation','server-values','rules-language','rules-methods'].includes(p.mode)&&typeof p.listReadiness!=='function')throw Error('instance readiness missing');
 if (!/^[a-zA-Z0-9_-]{1,80}$/.test(p.prefix) || !/^[a-f0-9]{64}$/.test(p.baselineHash)) throw Error('invalid lifecycle packet');
 const instance = (v, state) => v?.name === p.instanceName && v.type === 'USER_DATABASE' && v.state === state;
 const read = async (step, path, accept) => { const v=await io(step,'GET',path); if (!accept(v)) throw Error(`${step}: guard`); return v; };
 const mutate = async (step, method, path, body, accept) => { const v=await io(step,method,path,body); if (!accept(v)) throw Error(`${step}: unknown mutation outcome`); return v; };
 const rules=p.mode==='rules-methods'?(await import('./rules-methods.mjs')).methodRules(p.prefix):p.mode==='rules-language'?(await import('./rules-language.mjs')).languageRules(p.prefix):p.mode==='server-values'?(await import('./server-values.mjs')).serverValueRules(p.prefix):p.mode==='priority-observation'?(await import('./priority-corpus.mjs')).priorityRules(p.prefix):p.mode==='query-bounds'?(await import('./query-bounds.mjs')).boundsRules(p.prefix):p.mode==='query-rules'?(await import('./query-rules.mjs')).queryRules(p.prefix):p.mode==='rules-observation'?(await import('./rules-corpus.mjs')).buildRules(p.prefix):{rules:{[p.prefix]:{'.read':true,'.write':true,r1:{query:{'.indexOn':['h']}},r2:{query:{'.indexOn':['h']}}}}};
 const state = (want) => v => v?.state === want && v?.name === p.serviceName;
 const op = v => validOperation(v?.name) && !v.error;
 const finishOp = async (step, initial) => { let current=initial; for(let i=0;i<10 && current.done!==true;i++) { await (p.sleep ?? (ms=>new Promise(resolve=>setTimeout(resolve,ms))))(5000); current=await read(`${step}-poll-${i}`,initial.name,v=>op(v)&&v.name===initial.name); } if(current.done!==true) throw Error(`${step}: operation unresolved`); };
 const empty = v => v && (v.instances === undefined || (Array.isArray(v.instances) && v.instances.length === 0)) && !v.nextPageToken;
 await read('api-before','service',state('DISABLED'));
 await finishOp('api-enable',await mutate('api-enable','POST','service:enable',{},op));
 await read('api-enabled','service',state('ENABLED'));
 await read('instance-before','instance',v=>instance(v,'DELETED'));
 if(['priority-observation','server-values','rules-language','rules-methods'].includes(p.mode)){const list=await waitForInstanceList(p.listReadiness,p.sleep ?? (ms=>new Promise(resolve=>setTimeout(resolve,ms))),p.project);if(!empty(list))throw Error('active-before: guard');}else await read('active-before','instances',empty);
 const restored=await mutate('undelete','POST','instance:undelete',undefined,v=>instance(v,'ACTIVE')||instance(v,'DISABLED'));
 if(instance(restored,'DISABLED')) await mutate('reenable','POST','instance:reenable',undefined,v=>instance(v,'ACTIVE'));
 await read('instance-active','instance',v=>instance(v,'ACTIVE'));
 const baseline=await read('rules-before','rules',v=>typeof v==='string' && createHash('sha256').update(v).digest('hex')===p.baselineHash);
 await waitForBaseline(p.baselineProbe,p.sleep ?? (ms=>new Promise(resolve=>setTimeout(resolve,ms))),p.instance);
 await mutate('rules-install','PUT','rules',rules,v=>v?.status==='ok');
 await read('rules-installed','rules',v=>isDeepStrictEqual(v,rules));
 await waitForRules(p.probe,p.sleep ?? (ms=>new Promise(resolve=>setTimeout(resolve,ms))),p.instance);
 await corpus();
 await mutate('prefix-delete','DELETE',p.prefix,undefined,v=>v===null);
 await read('prefix-after',p.prefix,v=>v===null);
 await mutate('rules-restore','PUT','rules',baseline,v=>v?.status==='ok');
 await read('rules-restored','rules',v=>v===baseline);
 await mutate('disable','POST','instance:disable',undefined,v=>instance(v,'DISABLED'));
 await read('instance-disabled','instance',v=>instance(v,'DISABLED'));
 await mutate('delete','DELETE','instance',undefined,v=>instance(v,'DELETED'));
 await read('instance-deleted','instance',v=>instance(v,'DELETED'));
 await read('active-after','instances',empty);
 await finishOp('api-disable',await mutate('api-disable','POST','service:disable',{},op));
 await read('api-disabled','service',state('DISABLED'));
 return 'closed';
}
