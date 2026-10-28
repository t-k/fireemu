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
