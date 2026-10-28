const operationPattern=/^operations\/[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;
export function validOperation(name){return typeof name==='string'&&operationPattern.test(name);}
export async function recoverApi(io,p,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))) {
 if(!/^[0-9]{1,20}$/.test(p.projectNumber)||!validOperation(p.originalOperation)||p.maxRequests!==24)throw Error('invalid recovery packet');
 const root='https://serviceusage.googleapis.com/v1/';
 const serviceName=`projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`;
 const serviceUrl=`${root}${serviceName}`;
 const call=async(step,method,url,body)=>{const r=await io({step,method,url,body,phase:'normal'});try{return JSON.parse(r.body);}catch{throw Error(`${step}: unreadable`);}};
 const poll=async(step,name)=>{if(!validOperation(name))throw Error('invalid operation');for(let i=0;i<10;i++){await sleep(5000);const op=await call(`${step}-poll-${i}`,'GET',`${root}${name}`);if(op?.name!==name)throw Error(`${step}: identity`);if(op.done===true){if(op.error!==undefined)throw Error(`${step}: terminal error`);return;}if(op.done!==undefined&&op.done!==false)throw Error(`${step}: invalid completion`);}throw Error(`${step}: unresolved`);};
 await poll('original',p.originalOperation);
 const before=await call('service-before','GET',serviceUrl);if(before?.name!==serviceName)throw Error('service identity');
 if(before.state==='DISABLED')return 'closed';
 if(before.state!=='ENABLED')throw Error('unexpected service state');
 const op=await call('disable','POST',`${serviceUrl}:disable`,'{}');if(!validOperation(op?.name))throw Error('disable: invalid operation');if(op.error!==undefined)throw Error('disable: terminal error');
 if(op.done!==true){if(op.done!==undefined&&op.done!==false)throw Error('disable: invalid completion');await poll('disable',op.name);}
 const after=await call('service-after','GET',serviceUrl);if(after?.name!==serviceName||after.state!=='DISABLED')throw Error('baseline not verified');
 return 'closed';
}

export async function recoverInstance(io,p,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))) {
 if(!/^[0-9]{1,20}$/.test(p.projectNumber)||!/^[a-z][a-z0-9-]{3,62}$/.test(p.instance)||!/^[a-z0-9-]{3,32}$/.test(p.location)||p.maxRequests!==20)throw Error('invalid instance recovery packet');
 const management=`https://firebasedatabase.googleapis.com/v1beta/projects/${p.projectNumber}/locations`;
 const name=`projects/${p.projectNumber}/locations/${p.location}/instances/${p.instance}`, instance=`${management}/${p.location}/instances/${p.instance}`;
 const serviceName=`projects/${p.projectNumber}/services/firebasedatabase.googleapis.com`,service=`https://serviceusage.googleapis.com/v1/${serviceName}`;
 const call=async(step,method,url,body)=>{const r=await io({step,method,url,body,phase:'normal'});try{return JSON.parse(r.body);}catch{throw Error(`${step}: unreadable`);}};
 const validInstance=(v,state)=>v?.name===name&&v.type==='USER_DATABASE'&&v.state===state;
 const requireInstance=async(step,method,url,state)=>{const v=await call(step,method,url);if(!validInstance(v,state))throw Error(`${step}: identity or state`);};
 await requireInstance('instance-before','GET',instance,'ACTIVE');
 await requireInstance('instance-disable','POST',`${instance}:disable`,'DISABLED');
 await requireInstance('instance-disabled','GET',instance,'DISABLED');
 await requireInstance('instance-delete','DELETE',instance,'DELETED');
 await requireInstance('instance-deleted','GET',instance,'DELETED');
 const list=await call('active-after','GET',`${management}/-/instances`);if(!list||typeof list!=='object'||(list.instances!==undefined&&(!Array.isArray(list.instances)||list.instances.length!==0))||list.nextPageToken)throw Error('active instances');
 const before=await call('service-before','GET',service);if(before?.name!==serviceName||before.state!=='ENABLED')throw Error('service state');
 const op=await call('api-disable','POST',`${service}:disable`,'{}');if(!validOperation(op?.name)||op.error!==undefined)throw Error('api-disable: invalid operation');
 if(op.done!==true){if(op.done!==undefined&&op.done!==false)throw Error('api-disable: invalid completion');let done=false;for(let i=0;i<10;i++){await sleep(5000);const v=await call(`api-disable-poll-${i}`,'GET',`https://serviceusage.googleapis.com/v1/${op.name}`);if(v?.name!==op.name)throw Error('api-disable: identity');if(v.done===true){if(v.error!==undefined)throw Error('api-disable: terminal error');done=true;break;}if(v.done!==undefined&&v.done!==false)throw Error('api-disable: invalid completion');}if(!done)throw Error('api-disable: unresolved');}
 const after=await call('api-disabled','GET',service);if(after?.name!==serviceName||after.state!=='DISABLED')throw Error('baseline not verified');return 'closed';
}
