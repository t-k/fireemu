import { isDeepStrictEqual } from 'node:util';
const PREFIX=/^rnext1_[a-f0-9]{24}$/;
const UID='sv-rule-user';
const OVERRIDE=Object.freeze({uid:UID});
export function languageCases(){return [
 {id:'timestamp-valid',seed:1,body:'{".sv":"timestamp"}',rule:{'.write':true,'.validate':'newData.isNumber() && newData.val() <= now && newData.val() >= 0'},override:null},
 {id:'timestamp-negative',seed:1,body:'-1',rule:{'.write':true,'.validate':'newData.isNumber() && newData.val() <= now && newData.val() >= 0'},override:null,deny:true},
 {id:'uid-allow',seed:0,body:'1',rule:{'.write':"auth.uid === 'sv-rule-user'"},override:OVERRIDE},
 {id:'uid-deny',seed:0,body:'1',rule:{'.write':"auth.uid === 'sv-other-user'"},override:OVERRIDE,deny:true},
 {id:'contains-allow',seed:'alphabet',body:'1',rule:{'.write':"data.val().contains('pha')"},override:null},
 {id:'contains-deny',seed:'alphabet',body:'1',rule:{'.write':"data.val().contains('xyz')"},override:null,deny:true},
 {id:'strict-allow',seed:'alpha',body:'1',rule:{'.write':"data.val() === 'alpha'"},override:null},
 {id:'strict-deny',seed:'alpha',body:'1',rule:{'.write':"data.val() === 'beta'"},override:null,deny:true},
];}
export function languageRules(prefix){if(!PREFIX.test(prefix))throw Error('invalid prefix');const round=()=>Object.fromEntries(languageCases().map(x=>[x.id,x.rule]));return {rules:{'.read':false,'.write':false,[prefix]:{'.read':false,ready:{'.read':true},r1:round(),r2:round()}}};}
export function languageRequest(base,prefix,req){
 if(!/^https:\/\/[a-z][a-z0-9-]{3,62}\.firebaseio\.com$/.test(base)||!PREFIX.test(prefix)||req?.phase!=='normal'||req.query)throw Error('language request refused');
 const match=new RegExp(`^/${prefix}/r[12]/([a-z-]+)\\.json$`).exec(req.path??''),item=languageCases().find(x=>x.id===match?.[1]);if(!item)throw Error('language request refused');
 let query='';if(req.step==='language-case'&&req.method==='PUT'&&req.body===item.body&&isDeepStrictEqual(req.override,item.override))query=`?auth_variable_override=${encodeURIComponent(JSON.stringify(item.override))}`;
 else if(req.step==='language-seed'&&req.method==='PUT'&&req.body===JSON.stringify(item.seed)&&req.override===undefined){}else if(req.step==='language-read'&&req.method==='GET'&&req.body===undefined&&req.override===undefined){}else throw Error('language request refused');
 return {step:req.step,method:req.method,url:`${base}${req.path}${query}`,body:req.body,phase:'normal'};
}
export async function runLanguageCorpus(transport,prefix,now=Date.now){
 if(!PREFIX.test(prefix)||typeof transport!=='function'||typeof now!=='function')throw Error('invalid language corpus');const rows=[];
 for(const round of ['r1','r2'])for(const item of languageCases()){
  const path=`/${prefix}/${round}/${item.id}.json`,request=(step,method,body,override)=>({step,method,path,...(body===undefined?{}:{body}),...(override===undefined?{}:{override}),phase:'normal'});
  const seed=await transport(request('language-seed','PUT',JSON.stringify(item.seed)));let preimage;try{preimage=JSON.parse(seed.body);}catch{throw Error('language seed unresolved');}if(seed?.status!==200||!isDeepStrictEqual(preimage,item.seed))throw Error('language seed unresolved');
  const write=request('language-case','PUT',item.body,item.override),startedAt=now(),response=await transport(write),endedAt=now();if(![200,401,403].includes(response?.status)||typeof response.body!=='string')throw Error('language case unresolved');
  const read=await transport(request('language-read','GET'));let readback;try{readback=JSON.parse(read.body);}catch{throw Error('language readback unresolved');}if(read.status!==200)throw Error('language readback unresolved');
  rows.push({id:item.id,round,seed:item.seed,request:write,startedAt,endedAt,status:response.status,body:response.body,etag:response.headers?.etag??null,readback,...(item.id==='timestamp-valid'?{timestampIsInteger:Number.isSafeInteger(readback)}:{})});
 }
 return rows;
}
