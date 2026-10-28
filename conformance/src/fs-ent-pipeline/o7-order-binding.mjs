import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {createContext,normalizeStep,resolveValue,sameRecording} from './harness.mjs';
import {evaluate} from './o7-order-policy.mjs';

const pins={config:'8b968a85304f87a7b21b5df604264edf1dc048c7280438b93ea4cc35102b4adf',launch:'3f93baac3450df2100d47d925126eca57f059e7f8c3bea6492545e06bfcede4a',native:'ca893ceae6f1eadb7eb8a524d0805863021b53aee29c2d2a3474617ebd4713f7',sessionReceipt:'b5bd3e6f47dc368e3f9c29cb9f0bcf7f664f91a5b5177d6f247011d270874cb6',programs:'2280e6535e73f49edb1d4a2320619a91e0ac85100b482acac8fe6c5610e58625',checklog:'f3bf4a19ed7b53955b490526ed1cebc22635441b08d378f072cffaa5129fd93f',index:'622691a41d139d58199b97df54518fb79ec911f311b68e65607b7e1c9de5b340',receipt:'a7d790ff399ce2cdfec54f6a975a580f334640e9ba4848133f73ac82ec9e015f',binary:'39c5825519174115b9cff3da75c0473deea5ed5f8c85e79d5fdf8cba580eda83',compact:'abf614076a420030008eba45182f5f58e9ba3566980b040bb094a7bf04e988a3',detail:'5d360419325309f1cb16835c3fba084ad3246d53dc3b548328c9e4b2872a6b73',local:'4c9b17e35e0a79f55b98df1a61b9cc220517dd68d359155598abdb8a8e340841',production1:'87b61dbb5fd519629557e91134fdb7921bc48692fa66c875a300482a75cb1b17',production2:'ebca6bfadb08b5493fe5eca5eb5708a3efc4675c64706d8bc6a5df3547ad158f',fixture:'8312d30849afcd19f06125ee5fdb2b05afa96a185efbc2982c982b44a663a27b',requests:'8e0591940bd2fb6f879ef02609dff2ab2285ef3f27729fec7092a0b1b4917a17',manifest:'f337e009f0e2c089d4e799e6fa8a6b83259f9e7b1ceeaeab5f2dbcb99ffe0994',policy:'d35013550cfc3a78fae2b9b158821d33042836281093575e2e4d6567fe368a09',evaluator:'392bad7fb9627842eab0795da229832da9c7ba8a4629778c7faab781dc72eb30',harness:'0f665a00e57ffd09fed301ac6d47cdf93b1d8633536c909eaf5ee06c24aa32d3'};
const source='18f77be8956cccb768adfe8b43cfd0f9a8dfff09';
const digest=b=>createHash('sha256').update(b).digest('hex');
export function verifyIdentity(rows,ids,summary){
 if(!Array.isArray(rows)||!Array.isArray(ids)||rows.length!==ids.length||new Set(ids).size!==ids.length)return false;
 const actual=new Map();for(const row of rows){if(actual.has(row.row)||!ids.includes(row.row))return false;actual.set(row.row,row.status);}
 const counts={};for(const status of actual.values())counts[status]=(counts[status]??0)+1;
 return isDeepStrictEqual(counts,summary);
}
export function verifyBytes(bytes,expected){return digest(bytes)===expected;}
function requireEqual(condition,message){if(!condition)throw Error(message);}
function parsed(bytes){return JSON.parse(bytes.toString('utf8'));}
export function descriptorMatches(policy,manifest){
 const full=manifest.outerOrderEquivalenceRecipes.map(x=>({id:x.recipeId,mode:'full',requestSha256:x.requestSha256,seedSha256:x.seedSha256,fixtureStepSha256:x.fixtureStepSha256,dependencySha256:x.dependencySha256,sort:x.recipeId.endsWith('#around-where-two-sort')}));
 const selection=manifest.selectionCompanionProofs.map(x=>({id:x.recipeId,mode:'selection',companion:x.companionRecipeId,requestSha256:x.requestSha256,companionRequestSha256:x.companionRequestSha256,seedSha256:x.seedSha256,fixtureStepSha256:x.selectedFixtureStepSha256,companionFixtureStepSha256:x.companionFixtureStepSha256,dependencySha256:x.dependencySha256,selector:x.selector,companionTrailingSort:x.companionTrailingSort,companionAliasRename:x.companionAliasRename,expectedCardinality:x.expectedCardinality,eligibleCount:x.eligibleCount}));
 return isDeepStrictEqual(policy,{fixtureSha256:manifest.bindings.fixtureSha256,requestExportSha256:manifest.bindings.requestExportSha256,recipes:[...full,...selection],unresolved:manifest.excludedUnresolvedErrorRecipeIds});
}
export function renormalize(recording,program,kind){
 const c=recording.context;
 const target=kind==='production'?{kind:'production',token:'offline',quotaProject:'fireemu-oracle-query'}:{kind:'local',origin:'http://127.0.0.1:1',grpcHost:'127.0.0.1',grpcPort:1};
 const ctx=createContext({run:c.run,startedMs:c.startedMs,database:'entpipe1',target});
 const saved=recording.results[program.id];requireEqual(Boolean(saved),'missing program');const anchors=new Map(),output={};
 for(const step of program.steps){const raw=saved.raw?.[step.id];if(!raw)continue;requireEqual(raw.transport==='rest','transport');requireEqual(isDeepStrictEqual(raw.request,resolveValue(step.body??{},ctx,new Map())),'request mapping');const result=normalizeStep(raw,ctx,anchors);requireEqual(sameRecording(result,saved.steps[step.id]),'saved normalization');output[step.id]=result;}
 return output;
}
export function verifyEvidence(bytes){
 for(const [name,file] of [['evaluator','./o7-order-policy.mjs'],['policy','./o7-order-policy-data.json'],['harness','./harness.mjs']]) requireEqual(verifyBytes(readFileSync(new URL(file,import.meta.url)),pins[name]),`loaded ${name}`);
 for(const [name,expected] of Object.entries(pins))requireEqual(bytes[name]&&verifyBytes(bytes[name],expected),`hash ${name}`);
 const [index,receipt,compact,detail,local,production1,production2,fixture,requests,manifest,policy]=['index','receipt','compact','detail','local','production1','production2','fixture','requests','manifest','policy'].map(k=>parsed(bytes[k]));
 const names={receipt:'receipt.json',binary:'fireemu',compact:'fs-strict/export.json',detail:'fs-strict/comparison.json',local:'fs-strict/fireemu.json',checklog:'fs-strict/check.log',launch:'fs-strict/launch.json',native:'fs-strict/native-processes.log',sessionReceipt:'fs-strict/receipt.json',programs:'fs-strict/programs.json'};
 requireEqual(Array.isArray(index.artifacts)&&new Set(index.artifacts.map(a=>a.path)).size===index.artifacts.length,'index uniqueness');
 for(const [key,path] of Object.entries(names)){const item=index.artifacts.find(a=>a.path===path);requireEqual(item&&item.sha256===pins[key]&&item.bytes===bytes[key].length,`index ${key}`);}
 const launch=parsed(bytes.launch),session=parsed(bytes.sessionReceipt),config=parsed(bytes.config),programs=parsed(bytes.programs);
 requireEqual(index.sourceCommit===source&&receipt.sourceCommit===source&&index.binarySha256===pins.binary&&receipt.binarySha256===pins.binary&&launch.source===source&&launch.binarySha256===pins.binary&&launch.configSha256===pins.config&&session.binarySha256===pins.binary&&session.rows===1951&&session.exit===1&&bytes.checklog.toString('utf8').includes('profile: strict')&&launch.environment.FIREEMU_SANDBOX_LANE==='fs-ent-pipeline'&&bytes.native.toString('utf8').includes(launch.environment.FIREEMU_BIN)&&config.profile==='strict'&&config.productionExact===true&&config.firestore?.edition==='enterprise'&&config.firestore?.apiMode==='native','build binding');
 for(const key of ['compact','detail','local','checklog','launch','native','programs'])requireEqual(session.outputs[names[key].split('/').at(-1)]===pins[key],`session ${key}`);
 requireEqual(isDeepStrictEqual(index.firestore.strict,session.summary),'indexed summary');
 requireEqual(descriptorMatches(policy,manifest),'descriptor');
 requireEqual(policy.recipes.length===23&&policy.unresolved.length===2,'policy count');
 const counts={MATCH:1740,MISMATCH:197,INDETERMINATE:12,UNKNOWN:2};
 const ids=compact.rows.map(x=>x.row);requireEqual(ids.length===1951&&verifyIdentity(compact.rows,ids,counts)&&verifyIdentity(detail.rows,ids,counts),'identity');
 requireEqual(compact.artifactSha256===pins.binary&&detail.artifactSha256===pins.binary&&compact.fixtureSha256===pins.fixture&&isDeepStrictEqual(compact.summary,counts)&&isDeepStrictEqual(detail.summary,counts)&&detail.failures.length===0&&detail.orphans.length===0,'comparison binding');
 const statuses=new Map(compact.rows.map(x=>[x.row,x.status]));requireEqual(detail.rows.every(x=>statuses.get(x.row)===x.status),'comparison statuses');
 const results=[];const cache=new Map();
 for(const p of policy.recipes){
  const [pid,sid]=p.id.split('#'),program=requests.programs.find(x=>x.id===pid);requireEqual(program&&Array.isArray(programs)&&programs.filter(x=>x.id===pid).length===1&&isDeepStrictEqual(programs.find(x=>x.id===pid),program),'program');
  if(!cache.has(pid))cache.set(pid,[renormalize(production1,program,'production'),renormalize(production2,program,'production'),renormalize(local,program,'local')]);
  const [first,second,localRows]=cache.get(pid);const row=detail.rows.find(x=>x.row===p.id);const step=program.steps.find(x=>x.id===sid);const prod=fixture.programs[pid].steps[sid];
  requireEqual(row?.status==='MISMATCH'&&first[sid]&&second[sid]&&localRows[sid]&&sameRecording(first[sid],prod)&&sameRecording(second[sid],prod)&&sameRecording(row.production,first[sid])&&sameRecording(row.fireemu,localRows[sid]),'row mapping');
  const args={id:p.id,profile:'strict',rawStatus:row.status,request:step,seed:program.seed,production:first[sid],production2:second[sid],local:localRows[sid]};
  if(p.companion){const [cp,cs]=p.companion.split('#');requireEqual(cp===pid,'companion program');const companionRow=detail.rows.find(x=>x.row===p.companion);requireEqual(companionRow&&first[cs]&&second[cs]&&localRows[cs]&&sameRecording(companionRow.production,first[cs])&&sameRecording(companionRow.fireemu,localRows[cs]),'companion mapping');Object.assign(args,{companionRequest:program.steps.find(x=>x.id===cs),companionProduction:first[cs],companionProduction2:second[cs],companionLocal:localRows[cs]});}
  const result=evaluate(args);requireEqual(Boolean(result),'policy rejection');results.push(result);
 }
 requireEqual(results.filter(x=>x.proofClassification==='FULL_TYPED_RESULT_MULTISET_EQUIVALENT').length===20&&results.filter(x=>x.proofClassification==='LEGAL_UNORDERED_SELECTION').length===3,'proof counts');
 return {kind:'fs-ent-pipeline-o7-order-contract-v1',binding:'PENDING_REVIEW',sourceCommit:source,binarySha256:pins.binary,profile:'strict',bindings:pins,rawSummary:counts,proofs:results,unresolved:policy.unresolved,ordinaryProfile:'unproved',captureCustody:'raw and detailed captures are indexed; strict session records native process command',scope:'decoded normalized shape; no raw byte equality or production variation claimed'};
}
if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){const paths=parsed(readFileSync(process.argv[2]));const bytes=Object.fromEntries(Object.keys(pins).map(k=>[k,readFileSync(paths[k])]));writeFileSync(process.argv[3],JSON.stringify(verifyEvidence(bytes),null,2)+'\n',{flag:'wx'});}
