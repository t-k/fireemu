// Fixed offline proposal. Values and status classifications are not production observations.
import { documents, fn, readFromGrpc, select } from './builders.mjs';

const specifications = [
  ['exp','positive','one',[0]], ['exp','null','one',[null]], ['exp','wrong','one',['not-a-number']],
  ['ln','positive','one',[1]], ['ln','null','one',[null]], ['ln','wrong','one',['not-a-number']], ['ln','domain','one',[0]],
  ['log','positive','one',[1]], ['log','positive','two',[100,10]], ['log','null','one',[null]], ['log','wrong','one',['not-a-number']], ['log','domain','two',[10,1]],
  ['log10','positive','one',[100]], ['log10','null','one',[null]], ['log10','wrong','one',['not-a-number']], ['log10','domain','one',[0]],
  ['trunc','positive','one',[-15.5]], ['trunc','positive','two',[15.48924,2]], ['trunc','null','one',[null]], ['trunc','wrong','one',['not-a-number']],
  ['sqrt','positive','one',[25]], ['sqrt','null','one',[null]], ['sqrt','wrong','one',['not-a-number']], ['sqrt','domain','one',[-1]],
];

function value(x) {
  if (x===null) return {nullValue:'NULL_VALUE'};
  if (typeof x==='string') return {stringValue:x};
  if (Number.isInteger(x)) return {integerValue:String(x)};
  return {doubleValue:x};
}

export function numericPositiveRecipes() {
  const original=specifications.map(([name,partition,arity,args]) => {
    const id=`${name}-${partition}-${arity}`;
    return {id,name,partition,arity,args:[...args],step:readFromGrpc(id,documents('numeric-probe/d1'),select({v:fn(name,...args.map(value))}))};
  });
  const additional=[['trunc_029_p2','boundary029',[0.29,2]],['trunc_115_p2','boundary115',[1.15,2]],['trunc_min_subnormal_p309','subnormal',[Number.MIN_VALUE,309]]];
  return [...original,...additional.map(([id,partition,args]) => ({id,name:'trunc',partition,arity:'two',args:[...args],step:readFromGrpc(id,documents('numeric-probe/d1'),select({v:fn('trunc',...args.map(value))}))}))];
}
