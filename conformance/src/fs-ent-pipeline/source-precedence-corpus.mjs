import {documents,fn,readFromGrpc,select} from './builders.mjs';

// Only literal, same-database document sources are admitted.
export function sourcePrecedenceRecipes(){
 const cases=[['exp-existing-a',['aggvec/d1'],'exp',{stringValue:'not-a-number'}],['exp-existing-b',['aggvec/d2'],'exp',{stringValue:'not-a-number'}],['exp-missing',['aggvec/d4'],'exp',{stringValue:'not-a-number'}],['exp-existing-missing',['aggvec/d1','aggvec/d4'],'exp',{stringValue:'not-a-number'}],['exp-missing-existing',['aggvec/d4','aggvec/d1'],'exp',{stringValue:'not-a-number'}],['ln-existing-a',['aggvec/d1'],'ln',{integerValue:'0'}],['ln-existing-b',['aggvec/d2'],'ln',{integerValue:'0'}]];
 return cases.map(([id,paths,name,arg])=>({id,step:readFromGrpc(id,documents(...paths),select({v:fn(name,arg)}))}));
}
