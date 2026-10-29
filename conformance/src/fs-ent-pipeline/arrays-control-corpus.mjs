import {createRequire} from 'node:module';import {collection,readFromGrpc,select} from './builders.mjs';
const require=createRequire(import.meta.url),{Firestore}=require('@google-cloud/firestore'),sdk=require('@google-cloud/firestore/pipelines');
const normalize=x=>Array.isArray(x)?x.map(normalize):x&&typeof x==='object'?Object.fromEntries(Object.entries(x).map(([k,v])=>[k,k==='integerValue'?String(v):normalize(v)])):x;
export function arraysControlRecipes(){
 const db=new Firestore({projectId:'demo-local'}),f=sdk.field,c=sdk.constant,v=sdk.variable;
 const entries=[
 ['array-filter-populated',f('itemsPop').arrayFilter('item',sdk.greaterThan(v('item'),c(1)))],['array-filter-empty',f('itemsEmpty').arrayFilter('item',sdk.greaterThan(v('item'),c(1)))],
 ['array-transform-populated',f('itemsPop').arrayTransform('item',sdk.multiply(v('item'),c(2)))],['array-transform-empty',f('itemsEmpty').arrayTransform('item',sdk.multiply(v('item'),c(2)))],
 ['array-index-of-all-repeated',f('indicesMatch').arrayIndexOfAll(2)],['array-index-of-all-absent',f('indicesMiss').arrayIndexOfAll(2)],
 ['conditional-true',sdk.conditional(f('flagTrue'),c('yes'),c('no'))],['conditional-false',sdk.conditional(f('flagFalse'),c('yes'),c('no'))],
 ['if-absent-missing',f('optionalAbsent').ifAbsent('fallback')],['if-absent-present',f('optionalPresent').ifAbsent('fallback')],
 ['if-error-empty-array',f('errorItems').arrayGet(0).ifError('fallback')],['if-error-control',f('okayItems').arrayGet(0).ifError('fallback')],
 ['if-null-explicit-null',f('nullableNull').ifNull('fallback')],['if-null-present',f('nullableValue').ifNull('fallback')],['if-null-absent',f('nullableAbsent').ifNull('fallback')],
 ['switch-on-match',sdk.switchOn(sdk.equal(f('tagMatch'),c('A')),c('yes'),c('no'))],['switch-on-default',sdk.switchOn(sdk.equal(f('tagDefault'),c('A')),c('yes'),c('no'))],
 ['like-positive',f('textPositive').like('%ap%')],['like-negative',f('textNegative').like('%ap%')],['rand',sdk.rand()],
 ];return entries.map(([id,expr])=>({id,step:readFromGrpc(id,collection('pipeline-next'),select({out:normalize(expr._toProto(db._serializer))}))}));
}
export function arraysControlFields(){const i=n=>({integerValue:String(n)}),a=values=>({arrayValue:values.length?{values:values.map(i)}:{}}),s=x=>({stringValue:x});return {itemsPop:a([0,2]),itemsEmpty:a([]),indicesMatch:a([2,1,2]),indicesMiss:a([1,3]),flagTrue:{booleanValue:true},flagFalse:{booleanValue:false},optionalPresent:s('ready'),errorItems:a([]),okayItems:a([7]),nullableNull:{nullValue:'NULL_VALUE'},nullableValue:s('ready'),tagMatch:s('A'),tagDefault:s('Z'),textPositive:s('apricot'),textNegative:s('berry')};}
