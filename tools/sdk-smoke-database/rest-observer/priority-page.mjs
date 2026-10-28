export async function registerPriorityCase(sdk,database,base,spec,emit){
 if(!sdk||!database||typeof base!=='string'||!spec||!Array.isArray(spec.operations)||typeof emit!=='function')throw Error('invalid priority registration');
 for(const [index,op] of spec.operations.entries()){
  const [method,path,value,priority]=op;if(!['set','priority','cancel'].includes(method)||typeof path!=='string'||!/^s(?:\/[a-z]+)*$|^t$/.test(path))throw Error('invalid priority operation');
  const handle=sdk.onDisconnect(sdk.ref(database,`${base}/${path}`));
  if(method==='set')await handle.set(value);else if(method==='priority')await handle.setWithPriority(value,priority);else await handle.cancel();
  await emit({type:'ack',id:spec.id,index,method,path});
 }
}
