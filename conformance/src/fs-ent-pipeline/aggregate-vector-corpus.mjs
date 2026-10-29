import {createRequire} from 'node:module';
import {readFromGrpc} from './builders.mjs';
const require=createRequire(import.meta.url);
const {Firestore,FieldValue}=require('@google-cloud/firestore');
const sdk=require('@google-cloud/firestore/pipelines');
const normalize=x=>Array.isArray(x)?x.map(normalize):x&&typeof x==='object'?Object.fromEntries(Object.entries(x).map(([k,v])=>[k,k==='integerValue'?String(v):normalize(v)])):x;

// Each function gets its own request so one server error cannot mask the others.
export function aggregateVectorRecipes(){
 const db=new Firestore({projectId:'demo-local'}),f=sdk.field;
 const aggregate=[['array-agg',f('v').arrayAgg()],['array-agg-distinct',f('v').arrayAggDistinct()],['first',f('v').first()],['last',f('v').last()],['count-if',f('active').equal(true).countIf()]];
 const vector=[['vector-length',f('a').vectorLength()],['cosine-distance',f('a').cosineDistance(f('b'))],['dot-product',f('a').dotProduct(f('b'))],['euclidean-distance',f('a').euclideanDistance(f('b'))]];
 return [...aggregate.map(([id,expr])=>[id,db.pipeline().collection('aggvec').sort(sdk.ascending(f('seq'))).aggregate({accumulators:[expr.as('out')]})]),...vector.map(([id,expr])=>[id,db.pipeline().documents(['aggvec/d1']).select(expr.as('out'))])].map(([id,query])=>({id,step:readFromGrpc(id,...normalize(query._toProto().stages))}));
}
export function aggregateVectorFields(){
 const db=new Firestore({projectId:'demo-local'});
 return [1,2,3].map((n)=>{const values={seq:n,v:n===3?3:1,active:n!==2};if(n===1){values.a=FieldValue.vector([1,2]);values.b=FieldValue.vector([3,4]);}return Object.fromEntries(Object.entries(values).map(([key,value])=>[key,normalize(db._serializer.encodeValue(value))]));});
}
