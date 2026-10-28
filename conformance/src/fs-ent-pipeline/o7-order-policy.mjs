import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
import {pathToFileURL} from 'node:url';

const policy=JSON.parse(readFileSync(new URL('./o7-order-policy-data.json',import.meta.url)));
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const canonical=x=>Array.isArray(x)?x.map(canonical):x && typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])):x;
const key=x=>JSON.stringify(canonical(x));
export function compareBag(a,b) { return Array.isArray(a)&&Array.isArray(b)&&isDeepStrictEqual(a.map(key).sort(),b.map(key).sort()); }
export function subset(a,b,n) {
 if (!Array.isArray(a)||!Array.isArray(b)||a.length!==n) return false;
 const counts=new Map(); for(const item of b){const k=key(item);counts.set(k,(counts.get(k)??0)+1);}
 for(const item of a){const k=key(item), count=counts.get(k)??0;if(!count)return false;counts.set(k,count-1);}return true;
}
function unpack(step) {
 if(step?.status!==200 || !Array.isArray(step.body)||step.body.length!==1 || !Array.isArray(step.body[0].results)) throw Error('response shape');
 const copy=structuredClone(step);const results=copy.body[0].results;delete copy.body[0].results;return {shell:copy,results};
}
export function sorted(results){let last;for(const r of results){const v=r?.fields?.c?.integerValue;if(typeof v!=='string'||!/^(-?[1-9]\d*|0)$/.test(v))return false;const n=BigInt(v);if(last!==undefined&&last<n)return false;last=n;}return true;}
function alias(results, rename){return results.map(r=>{const x=structuredClone(r),f=x.fields;if(!f||!Object.hasOwn(f,rename.from)||Object.hasOwn(f,rename.to))throw Error('alias');f[rename.to]=f[rename.from];delete f[rename.from];return x;});}
export function evaluate({id,profile,rawStatus,request,seed,production,production2,local,companionRequest,companionProduction,companionProduction2,companionLocal}) {
 try {
  const p=policy.recipes.find(x=>x.id===id);if(!p||profile!=='strict'||rawStatus!=='MISMATCH'||!isDeepStrictEqual(production,production2)||hash(request)!==p.requestSha256||hash(seed)!==p.seedSha256||hash(production)!==p.fixtureStepSha256) return null;
  const values=[production,production2,local].map(unpack);if(!values.every(x=>isDeepStrictEqual(x.shell,values[0].shell)))return null;
  if(p.mode==='full'){
   if(!values.every(x=>compareBag(x.results,values[0].results))||(p.sort&&!values.every(x=>sorted(x.results))))return null;
   return {id,rawStatus:'MISMATCH',proofClassification:'FULL_TYPED_RESULT_MULTISET_EQUIVALENT',resultCount:values[0].results.length,requestSha256:p.requestSha256,seedSha256:p.seedSha256,dependencySha256:p.dependencySha256};
  }
  if(!isDeepStrictEqual(companionProduction,companionProduction2)||hash(companionRequest)!==p.companionRequestSha256||hash(companionProduction)!==p.companionFixtureStepSha256)return null;
  const all=[companionProduction,companionProduction2,companionLocal].map(unpack);
  if(!all.every(x=>isDeepStrictEqual(x.shell,all[0].shell))||!all.every(x=>compareBag(x.results,all[0].results))||all[0].results.length!==p.eligibleCount)return null;
  if(p.companionTrailingSort&&!all.every(x=>sorted(x.results)))return null;
  const eligible=p.companionAliasRename?alias(all[0].results,p.companionAliasRename):all[0].results;
  if(!values.every(x=>subset(x.results,eligible,p.expectedCardinality)))return null;
  return {id,rawStatus:'MISMATCH',proofClassification:'LEGAL_UNORDERED_SELECTION',eligibleCount:p.eligibleCount,selectedCount:p.expectedCardinality,requestSha256:p.requestSha256,seedSha256:p.seedSha256,dependencySha256:p.dependencySha256,companion:p.companion};
 } catch{return null;}
}
if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url) {
 const input=JSON.parse(readFileSync(process.argv[2],'utf8'));
 const result=evaluate(input);
 process.stdout.write(JSON.stringify({binding:'UNVERIFIED',result})+'\n');
 if(!result) process.exitCode=1;
}
