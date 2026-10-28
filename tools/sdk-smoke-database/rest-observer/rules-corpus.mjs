import {isDeepStrictEqual} from 'node:util';
import {checkAnchor} from './packet-gate.mjs';
const PREFIX=/^rnext1_[a-f0-9]{24}$/;
export function rulesCases(){
 return [
  {id:'cascade-ancestor',path:'cascade/parent/child',seed:{cascade:{parent:{child:0}}},method:'PUT',body:'1',expected:1},
  {id:'cascade-descendant',path:'cascade/blocked/child',seed:{cascade:{blocked:{child:0}}},method:'PUT',body:'1',expected:1},
  {id:'valid-number',path:'validation/number',seed:{validation:{number:1}},method:'PUT',body:'4',expected:4},
  {id:'valid-negative',path:'validation/negative',seed:{validation:{negative:1}},method:'PUT',body:'-1',expected:1,expectedDenied:true},
  {id:'valid-delete',path:'validation/deletion',seed:{validation:{deletion:4}},method:'DELETE',expected:null},
  {id:'snapshot-allow',path:'snapshot/allow/counter',seed:{control:7,snapshot:{allow:{counter:1}}},method:'PUT',body:'2',expected:2},
  {id:'snapshot-new-deny',path:'snapshot/newdeny/counter',seed:{control:7,snapshot:{newdeny:{counter:1}}},method:'PUT',body:'3',expected:1,expectedDenied:true},
  {id:'snapshot-root-deny',path:'snapshot/rootdeny/counter',seed:{control:8,snapshot:{rootdeny:{counter:1}}},method:'PUT',body:'2',expected:1,expectedDenied:true},
 ];
}
export function buildRules(prefix){
 if(!PREFIX.test(prefix))throw Error('invalid prefix');
 const round=r=>{const condition=`data.val() == 1 && newData.val() == 2 && root.child('${prefix}/${r}/control').val() == 7`;const validation={'.write':true,'.validate':'newData.isNumber() && newData.val() >= 0'};return {cascade:{parent:{'.write':true,child:{'.write':false}},blocked:{'.write':false,child:{'.write':true}}},validation:{number:validation,negative:validation,deletion:validation},snapshot:{allow:{counter:{'.write':condition}},newdeny:{counter:{'.write':condition}},rootdeny:{counter:{'.write':condition}}},patch:{'.write':true},query:{'.read':true,'.indexOn':['h']}};};
 return {rules:{'.read':false,'.write':false,[prefix]:{'.read':false,ready:{'.read':true},r1:round('r1'),r2:round('r2')}}};
}
export async function runRulesCorpus(transport,prefix,anchors){
 if(!PREFIX.test(prefix)||typeof transport!=='function')throw Error('invalid corpus');const results=[];
 for(const round of ['r1','r2']) { for(const item of rulesCases()){
  const path=`/${prefix}/${round}/${item.path}.json`;
  const seed=await transport({step:'rules-owner-seed',method:'PATCH',path:`/${prefix}/${round}.json`,body:JSON.stringify(item.seed),phase:'normal'});if(seed.status!==200)throw Error('seed rejected');
  const response=await transport({step:'rules-case',method:item.method,path,body:item.body,expectedDenied:!!item.expectedDenied,phase:'normal'});
  if(!response||!Number.isInteger(response.status)||typeof response.body!=='string')throw Error('case response');
  const accepted=response.status>=200&&response.status<300;if(!accepted&&![401,403].includes(response.status))throw Error('case status');const expected=accepted?(item.method==='DELETE'?null:JSON.parse(item.body)):item.id.startsWith('cascade-')?0:item.id==='valid-delete'?4:1;
  const read=await transport({step:'rules-owner-read',method:'GET',path,expected,phase:'normal'});let value;try{value=JSON.parse(read.body);}catch{throw Error('readback invalid');}
  if(read.status!==200||!isDeepStrictEqual(value,expected))throw Error('readback mismatch');results.push({id:item.id,round,status:response.status,body:response.body});
 }
 if(anchors){
  for(const [name,body] of [['patch','{"x":1,"y":{"z":"s"}}'],['query','{"a":{"h":3},"b":{"h":1},"c":{"h":2},"d":{},"10":{"h":5},"2":{"h":5}}']]){const seed=await transport({step:'rules-owner-anchor-seed',method:'PUT',path:`/${prefix}/${round}/${name}.json`,body,phase:'normal'});if(seed.status!==200)throw Error('anchor seed');}
  const patch={step:'rules-anchor',method:'PATCH',path:`/${prefix}/${round}/patch.json`,body:'{"y/z":"t","w":3}',phase:'normal'};checkAnchor(await transport(patch),anchors[round].patch);
  const query={step:'rules-anchor',method:'GET',path:`/${prefix}/${round}/query.json`,query:'orderBy=%22h%22&startAt=2',phase:'normal'};checkAnchor(await transport(query),anchors[round].query,query);
 }
 }
 return results;
}
