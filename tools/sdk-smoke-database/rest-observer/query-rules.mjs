import {isDeepStrictEqual} from 'node:util';
import {checkAnchor} from './packet-gate.mjs';
const PREFIX=/^rnext1_[a-f0-9]{24}$/;
const seed={a:{h:3},b:{h:1},c:{h:2}};
export function queryCases(){return [
 {id:'query-allow-2',query:'orderBy=%22h%22&limitToFirst=2'},
 {id:'query-deny-3',query:'orderBy=%22h%22&limitToFirst=3'},
 {id:'query-deny-nolimit',query:'orderBy=%22h%22'},
 {id:'query-deny-key',query:'orderBy=%22%24key%22&limitToFirst=2'},
];}
export function queryRules(prefix){
 if(!PREFIX.test(prefix))throw Error('invalid prefix');
 const round=()=>({queryrule:{'.read':"query.orderByChild == 'h' && query.limitToFirst <= 2",'.indexOn':['h']},patch:{'.write':true},query:{'.read':true,'.indexOn':['h']}});
 return {rules:{'.read':false,'.write':false,[prefix]:{'.read':false,ready:{'.read':true},r1:round(),r2:round()}}};
}
export async function runQueryCorpus(transport,prefix,anchors){
 if(!PREFIX.test(prefix)||typeof transport!=='function'||!anchors?.r1||!anchors?.r2)throw Error('invalid query corpus');const results=[];
 for(const round of ['r1','r2']){
  const path=`/${prefix}/${round}/queryrule.json`;
  const put=await transport({step:'query-owner-seed',method:'PUT',path,body:JSON.stringify(seed),phase:'normal'});if(put.status!==200)throw Error('query seed');
  const read=await transport({step:'query-owner-read',method:'GET',path,phase:'normal'});let value;try{value=JSON.parse(read.body);}catch{throw Error('query seed readback');}if(read.status!==200||!isDeepStrictEqual(value,seed))throw Error('query seed readback');
  for(const c of queryCases()){const response=await transport({step:'query-case',method:'GET',path,query:c.query,phase:'normal'});if(!response||!Number.isInteger(response.status)||typeof response.body!=='string'||!((response.status>=200&&response.status<300)||[401,403].includes(response.status)))throw Error('query response');results.push({id:c.id,round,status:response.status,body:response.body});}
  for(const [name,body] of [['patch','{"x":1,"y":{"z":"s"}}'],['query','{"a":{"h":3},"b":{"h":1},"c":{"h":2},"d":{},"10":{"h":5},"2":{"h":5}}']]){const r=await transport({step:'rules-owner-anchor-seed',method:'PUT',path:`/${prefix}/${round}/${name}.json`,body,phase:'normal'});if(r.status!==200)throw Error('anchor seed');}
  const patch={step:'rules-anchor',method:'PATCH',path:`/${prefix}/${round}/patch.json`,body:'{"y/z":"t","w":3}',phase:'normal'};checkAnchor(await transport(patch),anchors[round].patch);
  const query={step:'rules-anchor',method:'GET',path:`/${prefix}/${round}/query.json`,query:'orderBy=%22h%22&startAt=2',phase:'normal'};checkAnchor(await transport(query),anchors[round].query,query);
 }
 return results;
}
