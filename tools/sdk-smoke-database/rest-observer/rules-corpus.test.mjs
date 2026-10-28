import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRules, rulesCases, runRulesCorpus } from './rules-corpus.mjs';
const prefix='rnext1_0123456789abcdef01234567';
test('eight fixed cases in two rounds use owner seed, anonymous case, owner readback', async()=>{
 const calls=[]; const transport=async req=>{calls.push(req);if(req.step==='rules-owner-read')return {status:200,body:JSON.stringify(req.expected),headers:{}};return {status:req.step==='rules-case'&&req.expectedDenied?401:200,body:'null',headers:{}};};
 const result=await runRulesCorpus(transport,prefix);
 assert.equal(result.length,16);assert.equal(calls.length,48);
 for(let i=0;i<16;i++){const [seed,probe,read]=calls.slice(i*3,i*3+3);assert.equal(seed.step,'rules-owner-seed');assert.equal(probe.step,'rules-case');assert.equal(read.step,'rules-owner-read');assert.match(seed.path,new RegExp(`^/${prefix}/r[12]\\.json$`));assert.match(probe.path,new RegExp(`^/${prefix}/r[12]/`));}
 assert.deepEqual(rulesCases().map(x=>x.id),['cascade-ancestor','cascade-descendant','valid-number','valid-negative','valid-delete','snapshot-allow','snapshot-new-deny','snapshot-root-deny']);
});
test('temporary rules use isolated paths and bind root lookup to each round',()=>{
 const v=buildRules(prefix);assert.equal(v.rules['.read'],false);assert.equal(v.rules['.write'],false);assert.equal(v.rules[prefix]['.read'],false);assert.equal(v.rules[prefix].ready['.read'],true);assert.equal(v.rules[prefix].r1.cascade.parent['.write'],true);assert.equal(v.rules[prefix].r1.cascade.parent.child['.write'],false);assert.match(v.rules[prefix].r2.snapshot.allow.counter['.write'],new RegExp(`root\\.child\\('${prefix}/r2/control'\\)`));assert.equal(v.rules[prefix].r2.snapshot.allow.counter['.write'],`data.val() == 1 && newData.val() == 2 && root.child('${prefix}/r2/control').val() == 7`);assert.deepEqual(v.rules[prefix].r1.query['.indexOn'],['h']);
});
test('unexpected missing body or failed owner readback stops without further mutations',async()=>{
 let calls=0;await assert.rejects(runRulesCorpus(async req=>{calls++;return {status:200,body:req.step==='rules-owner-read'?'999':'null',headers:{}};},prefix),/readback/);assert.equal(calls,3);
});
test('unexpected allowed negative is captured with actual readback, not mistaken for denial',async()=>{
 const calls=[];let negative=false;const transport=async req=>{calls.push(req);if(req.step==='rules-case'&&req.path.endsWith('/validation/negative.json'))negative=true;if(req.step==='rules-owner-read')return {status:200,headers:{},body:JSON.stringify(negative&&req.path.endsWith('/validation/negative.json')?-1:req.expected)};return {status:200,headers:{},body:'null'};};
 const results=await runRulesCorpus(transport,prefix);assert.equal(results.find(x=>x.id==='valid-negative').status,200);
});
test('lifecycle chooses narrow Rules only for rules-observation mode',async()=>{
 const {lifecycle}=await import('./lifecycle.mjs');let installed;
 const io=async(step,method,path,body)=>{const states={'api-before':{name:'service',state:'DISABLED'},'api-enable':{name:'operations/a',done:true},'api-enabled':{name:'service',state:'ENABLED'},'instance-before':{name:'instance',type:'USER_DATABASE',state:'DELETED'},'active-before':{instances:[]},undelete:{name:'instance',type:'USER_DATABASE',state:'ACTIVE'},'instance-active':{name:'instance',type:'USER_DATABASE',state:'ACTIVE'},'rules-before':'BASELINE'};if(step==='rules-install'){installed=body;throw Error('stop after install');}return states[step];};
 await assert.rejects(lifecycle(io,{mode:'rules-observation',prefix,baselineProbe:async()=>({status:200,body:'null'}),probe:async()=>({status:200,body:'null'}),instanceName:'instance',serviceName:'service',baselineHash:'678bf03b47ad96012e4b7cf24f90a91aefc5c921863940998e65e28463f45cb0'},async()=>{}),/stop after install/);assert.deepEqual(installed,buildRules(prefix));
});
test('each round executes both independently seeded anchors',async()=>{
 const calls=[];const t=async req=>{calls.push(req);if(req.step==='rules-owner-read')return {status:200,body:JSON.stringify(req.expected),headers:{}};return {status:req.expectedDenied?401:200,body:req.step==='rules-anchor'&&req.method==='GET'?'{}':'null',headers:{}};};
 const anchor={patch:{status:200,etag:null,bodyText:'null'},query:{status:200,etag:null,bodyText:'{}'}};await runRulesCorpus(t,prefix,{r1:anchor,r2:anchor});assert.equal(calls.length,56);assert.equal(calls.filter(x=>x.step==='rules-anchor').length,4);assert.equal(calls.filter(x=>x.step==='rules-owner-anchor-seed').length,4);
});
test('generated combinations exercise each case, round and observed outcome',async()=>{
 const {readFile}=await import('node:fs/promises');const rows=(await readFile(new URL('./rules.generated.tsv',import.meta.url),'utf8')).trim().split('\n').slice(1);
 for(const row of rows){const [id,round,outcome]=row.split('\t');const item=rulesCases().find(x=>x.id===id);assert.ok(item);const target=`/${prefix}/${round}/${item.path}.json`;const transport=async req=>{if(req.step==='rules-owner-read')return {status:200,headers:{},body:JSON.stringify(req.expected)};const status=req.step==='rules-case'&&req.path===target?(outcome==='allowed'?200:401):req.expectedDenied?401:200;return {status,headers:{},body:'null'};};const results=await runRulesCorpus(transport,prefix);assert.equal(results.find(x=>x.round===round&&x.id===id).status,outcome==='allowed'?200:401);}
});
test('unknown mutation stops and never retries or reads after it',async()=>{const calls=[];await assert.rejects(runRulesCorpus(async r=>{calls.push(r);if(r.step==='rules-case')throw Error('unknown');return {status:200,body:'null',headers:{}};},prefix),/unknown/);assert.deepEqual(calls.map(x=>x.step),['rules-owner-seed','rules-case']);});
