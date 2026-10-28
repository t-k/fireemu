import {isDeepStrictEqual} from 'node:util';
const PREFIX=/^rnext1_[a-f0-9]{24}$/;
export function methodCases(){return [
 {id:'parent-ok',predicate:"data.parent().child('marker').val() == 'ok'",seed:{marker:'ok',leaf:'value'},logical:'value',parent:true},
 {id:'parent-deny',predicate:"data.parent().child('marker').val() == 'ok'",seed:{marker:'no',leaf:'value'},logical:'value',parent:true,deny:true},
 {id:'exists-ok',predicate:"data.child('flag').exists()",seed:{flag:true,payload:'v'}},
 {id:'exists-deny',predicate:"data.child('flag').exists()",seed:{payload:'v'},deny:true},
 {id:'hasChild-ok',predicate:"data.hasChild('nested/leaf')",seed:{nested:{leaf:'v'}}},
 {id:'hasChild-deny',predicate:"data.hasChild('nested/leaf')",seed:{nested:{other:'v'}},deny:true},
 {id:'hasChildren-any-ok',predicate:'data.hasChildren()',seed:{a:1}},
 {id:'hasChildren-any-deny',predicate:'data.hasChildren()',seed:'leaf',deny:true},
 {id:'hasChildren-list-ok',predicate:"data.hasChildren(['a','b'])",seed:{a:1,b:2}},
 {id:'hasChildren-list-deny',predicate:"data.hasChildren(['a','b'])",seed:{a:1,c:2},deny:true},
 {id:'getPriority-number',predicate:'data.getPriority() == 7',seed:{'.value':'v','.priority':7},logical:'v',priority:true},
 {id:'getPriority-string',predicate:"data.getPriority() == 'high'",seed:{'.value':'v','.priority':'high'},logical:'v',priority:true},
 {id:'getPriority-null',predicate:'data.getPriority() == null',seed:'v',priority:true},
 {id:'isString-ok',predicate:'data.isString()',seed:'text'},
 {id:'isString-deny',predicate:'data.isString()',seed:7,deny:true},
 {id:'isBoolean-ok',predicate:'data.isBoolean()',seed:true},
 {id:'isBoolean-deny',predicate:'data.isBoolean()',seed:1,deny:true},
 {id:'beginsWith-ok',predicate:"data.val().beginsWith('pre-')",seed:'pre-item'},
 {id:'beginsWith-deny',predicate:"data.val().beginsWith('pre-')",seed:'item-pre',deny:true},
 {id:'endsWith-ok',predicate:"data.val().endsWith('.cfg')",seed:'app.cfg'},
 {id:'endsWith-deny',predicate:"data.val().endsWith('.cfg')",seed:'cfg.app',deny:true},
 {id:'replace-all-ok',predicate:"data.val().replace('.', '%') == 'a%a%a'",seed:'a.a.a'},
 {id:'replace-first-only-deny',predicate:"data.val().replace('.', '%') == 'a%a.a'",seed:'a.a.a',deny:true},
 {id:'toLowerCase-ok',predicate:"data.val().toLowerCase() == 'abc'",seed:'AbC'},
 {id:'toLowerCase-deny',predicate:"data.val().toLowerCase() == 'abC'",seed:'AbC',deny:true},
 {id:'toUpperCase-ok',predicate:"data.val().toUpperCase() == 'ABC'",seed:'AbC'},
 {id:'toUpperCase-deny',predicate:"data.val().toUpperCase() == 'ABc'",seed:'AbC',deny:true},
 {id:'matches-ok',predicate:'data.val().matches(/^abc$/)',seed:'abc'},
 {id:'matches-deny',predicate:'data.val().matches(/^abc$/)',seed:'xabc',deny:true},
].map(x=>({...x,logical:x.logical??x.seed}));}
export function methodRules(prefix){if(!PREFIX.test(prefix))throw Error('invalid prefix');const round=()=>Object.fromEntries(methodCases().map(c=>[c.id,c.parent?{leaf:{'.read':c.predicate}}:{'.read':c.predicate}]));return {rules:{'.read':false,'.write':false,[prefix]:{'.read':false,ready:{'.read':true},r1:round(),r2:round()}}};}
export function methodRequest(base,prefix,req){
 if(!/^https:\/\/[a-z][a-z0-9-]{3,62}\.firebaseio\.com$/.test(base)||!PREFIX.test(prefix)||req?.phase!=='normal'||req.override!==undefined)throw Error('methods request refused');
 const match=new RegExp(`^/${prefix}/r[12]/([A-Za-z-]+)(/leaf)?\\.json$`).exec(req.path??''),item=methodCases().find(x=>x.id===match?.[1]);if(!item)throw Error('methods request refused');const leaf=!!match[2],expectedLeaf=!!item.parent;
 let query='';if(req.step==='methods-seed'&&req.method==='PUT'&&!leaf&&!req.query&&req.body===JSON.stringify(item.seed)){}else if(req.step==='methods-case'&&req.method==='GET'&&leaf===expectedLeaf&&!req.query&&req.body===undefined)query='?auth_variable_override=null';else if(req.step==='methods-read'&&req.method==='GET'&&leaf===expectedLeaf&&!req.query&&req.body===undefined){}else if(req.step==='methods-export'&&req.method==='GET'&&item.priority&&!leaf&&req.query==='format=export'&&req.body===undefined)query='?format=export';else throw Error('methods request refused');
 return {step:req.step,method:req.method,url:`${base}${req.path}${query}`,body:req.body,phase:'normal'};
}
export async function runMethodCorpus(transport,prefix){
 if(!PREFIX.test(prefix)||typeof transport!=='function')throw Error('invalid methods corpus');const rows=[];
 for(const round of ['r1','r2'])for(const item of methodCases()){
  const root=`/${prefix}/${round}/${item.id}`,path=`${root}${item.parent?'/leaf':''}.json`,req=(step,method,p,body,query)=>({step,method,path:p,...(body===undefined?{}:{body}),...(query===undefined?{}:{query}),phase:'normal'}),seedBody=JSON.stringify(item.seed);
  const seed=await transport(req('methods-seed','PUT',`${root}.json`,seedBody));if(seed?.status!==200||typeof seed.body!=='string')throw Error('seed unresolved');
  const response=await transport(req('methods-case','GET',path));if(![200,401,403].includes(response?.status)||typeof response.body!=='string')throw Error('case unresolved');
  const read=await transport(req('methods-read','GET',path));let readback;try{readback=JSON.parse(read.body);}catch{throw Error('readback unresolved');}if(read.status!==200||!isDeepStrictEqual(readback,item.logical))throw Error('readback unresolved');
  let exportResponse,exportValue;if(item.priority){exportResponse=await transport(req('methods-export','GET',path,undefined,'format=export'));try{exportValue=JSON.parse(exportResponse.body);}catch{throw Error('export unresolved');}if(exportResponse.status!==200)throw Error('export unresolved');}
  rows.push({id:item.id,round,predicate:item.predicate,seedBody,seedResponse:{status:seed.status,body:seed.body,etag:seed.headers?.etag??null},status:response.status,body:response.body,etag:response.headers?.etag??null,readback,...(item.priority?{export:exportValue,exportBody:exportResponse.body}: {})});
 }
 return rows;
}
