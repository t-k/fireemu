import test from 'node:test';
import assert from 'node:assert/strict';
import { languageCases, languageRules, languageRequest, runLanguageCorpus } from './rules-language.mjs';
const prefix='rnext1_0123456789abcdef01234567',base='https://demo-observer.firebaseio.com';
test('eight bounded Rules cases per round preserve synthetic auth scope and outcomes',async()=>{
 const cases=languageCases();assert.equal(cases.length,8);const rules=languageRules(prefix);assert.ok(rules.rules[prefix].ready);const calls=[],values=new Map();
 const transport=async req=>{calls.push(req);if(req.step==='language-seed')values.set(req.path,JSON.parse(req.body));const item=cases.find(x=>req.path.endsWith(`/${x.id}.json`));if(req.step==='language-case'&&!item.deny)values.set(req.path,item.id==='timestamp-valid'?1700000000000:JSON.parse(req.body));const denied=req.step==='language-case'&&item.deny;return {status:denied?401:200,body:JSON.stringify(values.get(req.path)??null),headers:{}};};
 const rows=await runLanguageCorpus(transport,prefix);assert.equal(rows.length,16);assert.equal(calls.length,48);assert.equal(new Set(rows.map(x=>`${x.round}/${x.id}`)).size,16);assert.equal(rows.filter(x=>x.status===401).length,8);
 for(const c of calls){const routed=languageRequest(base,prefix,c);if(c.step==='language-case'){assert.ok(routed.url.includes('auth_variable_override='));assert.equal(routed.method,'PUT');}else assert.ok(!routed.url.includes('auth_variable_override'));}
});
test('query and body near misses cannot escape the scoped Rules context',()=>{
 const item=languageCases()[0],path=`/${prefix}/r1/${item.id}.json`;const req={step:'language-case',method:'PUT',path,body:item.body,phase:'normal',override:null};assert.ok(languageRequest(base,prefix,req));for(const change of [{override:{uid:'different'}},{override:{uid:'sv-rule-user',token:{admin:true}}},{body:'{}'},{path:`/${prefix}/r1/else.json`},{step:'language-seed',override:{uid:'sv-rule-user'}}])assert.throws(()=>languageRequest(base,prefix,{...req,...change}));
});

test('generated case, round, and outcome combinations reach their exact target',async()=>{const {readFile}=await import('node:fs/promises');const lines=(await readFile(new URL('./rules-language.generated.tsv',import.meta.url),'utf8')).trim().split('\n').slice(1);assert.equal(lines.length,48);for(const line of lines){const [id,round,outcome]=line.split('\t'),values=new Map();let selected=false;const wire=async req=>{if(req.step==='language-seed')values.set(req.path,JSON.parse(req.body));if(req.step==='language-case'&&req.path.endsWith(`/${round}/${id}.json`)){selected=true;if(outcome==='unknown')throw Error('unknown');return {status:outcome==='deny'?401:200,body:'null',headers:{}};}return {status:200,body:JSON.stringify(values.get(req.path)??null),headers:{}};};if(outcome==='unknown')await assert.rejects(runLanguageCorpus(wire,prefix),/unknown/);else assert.equal((await runLanguageCorpus(wire,prefix)).length,16);assert.equal(selected,true,line);}});

test('unknown stops before readback or subsequent cases',async()=>{const calls=[];await assert.rejects(runLanguageCorpus(async req=>{calls.push(req);if(req.step==='language-case')throw Error('unknown');return {status:200,body:'1',headers:{}};},prefix),/unknown/);assert.deepEqual(calls.map(x=>x.step),['language-seed','language-case']);});

test('unknown Rules language write never reaches cleanup in the existing lifecycle', async () => {
 const { lifecycle } = await import('./lifecycle.mjs'); const { createHash } = await import('node:crypto');
 const baseline = '{"rules":{}}', hash = createHash('sha256').update(baseline).digest('hex'), calls=[];
 const instanceName='projects/123/locations/us-central1/instances/demo-instance', serviceName='projects/123/services/firebasedatabase.googleapis.com';
 let rules=baseline;
 const io=async(step,method,path,body)=>{calls.push(step);if(step==='api-before')return {name:serviceName,state:'DISABLED'};if(step==='api-enable')return {name:'operations/a',done:true};if(step==='api-enabled')return {name:serviceName,state:'ENABLED'};if(step==='instance-before')return {name:instanceName,type:'USER_DATABASE',state:'DELETED'};if(step==='undelete'||step==='instance-active')return {name:instanceName,type:'USER_DATABASE',state:'ACTIVE'};if(step==='rules-before')return baseline;if(step==='rules-install'){rules=body;return {status:'ok'};}if(step==='rules-installed')return rules;throw Error(`unexpected ${step}`);};
 const p={mode:'rules-language',prefix,baselineHash:hash,instanceName,serviceName,instance:'demo-instance',project:'demo-project',listReadiness:async()=>({status:200,body:'{"instances":[]}'}),baselineProbe:async()=>({status:200,body:'null'}),probe:async()=>({status:200,body:'null'}),sleep:async()=>{}};
 await assert.rejects(lifecycle(io,p,async()=>{throw Error('unknown');}),/unknown/);
 assert.equal(calls.includes('prefix-delete'),false);assert.equal(calls.includes('rules-restore'),false);
});

test('unknown cleanup does not restore Rules or continue infrastructure mutation', async () => {
 const { lifecycle } = await import('./lifecycle.mjs'); const { createHash } = await import('node:crypto'); const baseline='{"rules":{}}',calls=[];let rules=baseline;
 const instanceName='projects/123/locations/us-central1/instances/demo-instance', serviceName='projects/123/services/firebasedatabase.googleapis.com';
 const io=async(step,method,path,body)=>{calls.push(step);if(step==='api-before')return {name:serviceName,state:'DISABLED'};if(step==='api-enable')return {name:'operations/a',done:true};if(step==='api-enabled')return {name:serviceName,state:'ENABLED'};if(step==='instance-before')return {name:instanceName,type:'USER_DATABASE',state:'DELETED'};if(step==='undelete'||step==='instance-active')return {name:instanceName,type:'USER_DATABASE',state:'ACTIVE'};if(step==='rules-before')return baseline;if(step==='rules-install'){rules=body;return {status:'ok'};}if(step==='rules-installed')return rules;if(step==='prefix-delete')throw Error('unknown cleanup');throw Error(`unexpected ${step}`);};
 const p={mode:'rules-language',prefix,baselineHash:createHash('sha256').update(baseline).digest('hex'),instanceName,serviceName,instance:'demo-instance',project:'demo-project',listReadiness:async()=>({status:200,body:'{"instances":[]}'}),baselineProbe:async()=>({status:200,body:'null'}),probe:async()=>({status:200,body:'null'}),sleep:async()=>{}};
 await assert.rejects(lifecycle(io,p,async()=>{}),/unknown cleanup/);assert.equal(calls.includes('rules-restore'),false);assert.equal(calls.includes('disable'),false);
});


test('Rules source carries exactly the proposed validation, uid, contains and strict equality predicates',()=>{const rules=languageRules(prefix).rules[prefix];for(const r of ['r1','r2']){const x=rules[r];assert.equal(x['timestamp-valid']['.validate'],'newData.isNumber() && newData.val() <= now && newData.val() >= 0');assert.equal(x['timestamp-negative']['.validate'],x['timestamp-valid']['.validate']);assert.equal(x['uid-allow']['.write'],"auth.uid === 'sv-rule-user'");assert.equal(x['uid-deny']['.write'],"auth.uid === 'sv-other-user'");assert.equal(x['contains-allow']['.write'],"data.val().contains('pha')");assert.equal(x['contains-deny']['.write'],"data.val().contains('xyz')");assert.equal(x['strict-allow']['.write'],"data.val() === 'alpha'");assert.equal(x['strict-deny']['.write'],"data.val() === 'beta'");}});

test('all synthetic UID near misses and extra claims are refused by the router',()=>{const item=languageCases().find(x=>x.id==='uid-allow'),path=`/${prefix}/r1/${item.id}.json`;for(let i=0;i<100;i++)for(const override of [{uid:`sv-rule-user-${i}`},{uid:'sv-rule-user',token:{n:i}}])assert.throws(()=>languageRequest(base,prefix,{step:'language-case',method:'PUT',path,body:item.body,override,phase:'normal'}));});

test('incorrect seed response stops before dispatching the Rules case',async()=>{const calls=[];await assert.rejects(runLanguageCorpus(async req=>{calls.push(req);return {status:200,body:'999',headers:{}};},prefix),/seed/);assert.deepEqual(calls.map(x=>x.step),['language-seed']);});
