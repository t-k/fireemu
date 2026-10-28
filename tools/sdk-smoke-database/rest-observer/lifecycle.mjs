import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

// io must provide counted, durable and sticky-unknown request semantics.
export async function lifecycle(io, p, corpus) {
 if (!/^[a-zA-Z0-9_-]{1,80}$/.test(p.prefix) || !/^[a-f0-9]{64}$/.test(p.baselineHash)) throw Error('invalid lifecycle packet');
 const instance = (v, state) => v?.name === p.instanceName && v.type === 'USER_DATABASE' && v.state === state;
 const read = async (step, path, accept) => { const v=await io(step,'GET',path); if (!accept(v)) throw Error(`${step}: guard`); return v; };
 const mutate = async (step, method, path, body, accept) => { const v=await io(step,method,path,body); if (!accept(v)) throw Error(`${step}: unknown mutation outcome`); return v; };
 const rules={rules:{[p.prefix]:{'.read':true,'.write':true}}};
 const state = (want) => v => v?.state === want && v?.name === p.serviceName;
 const op = v => typeof v?.name === 'string' && /^operations\/[A-Za-z0-9_-]+$/.test(v.name) && !v.error;
 const finishOp = async (step, initial) => { let current=initial; for(let i=0;i<3 && current.done!==true;i++) { current=await read(`${step}-poll-${i}`,initial.name,v=>op(v)&&v.name===initial.name); } if(current.done!==true) throw Error(`${step}: operation unresolved`); };
 const empty = v => v && (v.instances === undefined || (Array.isArray(v.instances) && v.instances.length === 0)) && !v.nextPageToken;
 await read('api-before','service',state('DISABLED'));
 await finishOp('api-enable',await mutate('api-enable','POST','service:enable',{},op));
 await read('api-enabled','service',state('ENABLED'));
 await read('instance-before','instance',v=>instance(v,'DELETED'));
 await read('active-before','instances',empty);
 const restored=await mutate('undelete','POST','instance:undelete',undefined,v=>instance(v,'ACTIVE')||instance(v,'DISABLED'));
 if(instance(restored,'DISABLED')) await mutate('reenable','POST','instance:reenable',undefined,v=>instance(v,'ACTIVE'));
 await read('instance-active','instance',v=>instance(v,'ACTIVE'));
 const baseline=await read('rules-before','rules',v=>typeof v==='string' && createHash('sha256').update(v).digest('hex')===p.baselineHash);
 await read('prefix-before',p.prefix,v=>v===null);
 await mutate('rules-install','PUT','rules',rules,v=>v?.status==='ok');
 await read('rules-installed','rules',v=>isDeepStrictEqual(v,rules));
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
