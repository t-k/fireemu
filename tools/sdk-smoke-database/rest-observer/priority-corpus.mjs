const PREFIX=/^rnext1_[a-f0-9]{24}$/;
export function priorityRules(prefix){if(!PREFIX.test(prefix))throw Error('invalid prefix');return {rules:{'.read':false,'.write':false,[prefix]:{'.read':true,'.write':true}}};}
export function priorityCases(){return [
 {id:'heal-reregister',operations:[['priority','s',{b:1,c:2},1],['cancel','s/b'],['set','s',{z:1}],['set','t',1]]},
 {id:'nested-priority',operations:[['set','s',{a:{'.priority':1,x:1,y:2},k:1}],['cancel','s/a/x'],['set','t',1]]},
 {id:'string-priority',operations:[['priority','s',{b:1,c:2},'p'],['cancel','s/b'],['set','t',1]]}
];}
export async function runPriorityCorpus({prefix,runCase}){
 if(!PREFIX.test(prefix)||typeof runCase!=='function')throw Error('invalid priority corpus');const rows=[];
 for(const round of ['r1','r2'])for(const item of priorityCases()){
  const result=await runCase({prefix,round,...item});
  if(!result||result.acknowledged!==true||result.writerClosed!==true||result.observed!==true||!result.readback||!Object.hasOwn(result.readback,'s')||!Object.hasOwn(result.readback,'t'))throw Error('priority observation unresolved');
  rows.push({round,id:item.id,...result});
 }
 return rows;
}
