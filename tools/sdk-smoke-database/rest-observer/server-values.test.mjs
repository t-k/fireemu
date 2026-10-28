import test from 'node:test';
import assert from 'node:assert/strict';
import { serverValueCases, runServerValueCorpus, serverValueRules } from './server-values.mjs';

const prefix = 'rnext1_0123456789abcdef01234567';
test('five cases and two rounds retain requests, preimages, results, and atomic timestamp relationship', async () => {
  assert.equal(serverValueCases().length, 5);
  assert.ok(serverValueRules(prefix).rules[prefix].ready);
  const db = new Map(), calls = [];
  const transport = async request => {
    calls.push(request);
    const key = request.path;
    if (request.method === 'PUT') {
      const input = JSON.parse(request.body);
      if (input && input['.sv']) {
        const prior = db.get(key);
        const value = input['.sv'] === 'timestamp' ? 1710000000000 : (typeof prior === 'number' ? prior : 0) + input['.sv'].increment;
        db.set(key, value);
      } else db.set(key, input);
    }
    if (request.method === 'PATCH') db.set(key, { first: 1710000000001, second: 1710000000001, counter: 12 });
    return { status: 200, body: JSON.stringify(db.get(key) ?? null), headers: { etag: '"v"' } };
  };
  const rows = await runServerValueCorpus(transport, prefix);
  assert.equal(rows.length, 10);
  assert.equal(new Set(rows.map(x => `${x.round}/${x.id}`)).size, 10);
  assert.equal(rows.find(x => x.id === 'increment-nonnumeric').preimage, 'old');
  assert.equal(rows.find(x => x.id === 'increment-absent').preimage, null);
  assert.equal(rows.find(x => x.id === 'multipath-one-clock').sameClock, true);
  assert.equal(rows.find(x => x.id === 'timestamp-single').timestampIsInteger, true);
  assert.ok(rows.every(x => x.responseMatchesReadback));
  assert.ok(calls.every(x => x.path.startsWith(`/${prefix}/`) && x.phase === 'normal'));
});

test('unreadable or unknown response cannot yield an observed case', async () => {
  await assert.rejects(runServerValueCorpus(async () => ({ status: 500, body: '' }), prefix));
  await assert.rejects(runServerValueCorpus(async () => ({ status: 200, body: 'not-json' }), prefix));
});

test('a seed readback that differs from the declared preimage stops before placeholder write',async()=>{const calls=[];await assert.rejects(runServerValueCorpus(async req=>{calls.push(req);return {status:200,body:req.step==='sv-before'?'99':'null',headers:{}};},prefix),/preimage/);assert.equal(calls.some(req=>req.step==='sv-write'),false);});

test('generated case, round and outcome combinations exercise each placeholder write', async () => {
 const { readFile } = await import('node:fs/promises');
 const table = await readFile(new URL('./server-values.generated.tsv',import.meta.url),'utf8');
 for (const line of table.trim().split('\n').slice(1)) {
  const [id,round,outcome] = line.split('\t'), db = new Map(); let selected = false;
  const transport = async req => {
   if (req.step==='sv-write' && req.path.endsWith(`/${round}/${id}.json`)) { selected = true; if (outcome==='unknown') throw Error('unknown'); }
   if (req.step==='sv-seed') db.set(req.path,JSON.parse(req.body));
   if (req.step==='sv-write') db.set(req.path,req.method==='PATCH'?{first:1,second:1,counter:12}:1);
   return {status:200,body:JSON.stringify(db.get(req.path)??null),headers:{}};
  };
  if (outcome==='unknown') await assert.rejects(runServerValueCorpus(transport,prefix),/unknown/);
  else assert.equal((await runServerValueCorpus(transport,prefix)).length,10);
  assert.equal(selected,true,`${id}/${round}/${outcome}`);
 }
});

test('unknown server-value write never reaches cleanup in the existing lifecycle', async () => {
 const { lifecycle } = await import('./lifecycle.mjs'); const { createHash } = await import('node:crypto');
 const baseline = '{"rules":{}}', hash = createHash('sha256').update(baseline).digest('hex'), calls=[];
 const instanceName='projects/123/locations/us-central1/instances/demo-instance', serviceName='projects/123/services/firebasedatabase.googleapis.com';
 let rules=baseline;
 const io=async(step,method,path,body)=>{calls.push(step);if(step==='api-before')return {name:serviceName,state:'DISABLED'};if(step==='api-enable')return {name:'operations/a',done:true};if(step==='api-enabled')return {name:serviceName,state:'ENABLED'};if(step==='instance-before')return {name:instanceName,type:'USER_DATABASE',state:'DELETED'};if(step==='undelete'||step==='instance-active')return {name:instanceName,type:'USER_DATABASE',state:'ACTIVE'};if(step==='rules-before')return baseline;if(step==='rules-install'){rules=body;return {status:'ok'};}if(step==='rules-installed')return rules;throw Error(`unexpected ${step}`);};
 const p={mode:'server-values',prefix,baselineHash:hash,instanceName,serviceName,instance:'demo-instance',project:'demo-project',listReadiness:async()=>({status:200,body:'{"instances":[]}'}),baselineProbe:async()=>({status:200,body:'null'}),probe:async()=>({status:200,body:'null'}),sleep:async()=>{}};
 await assert.rejects(lifecycle(io,p,async()=>{throw Error('unknown');}),/unknown/);
 assert.equal(calls.includes('prefix-delete'),false);assert.equal(calls.includes('rules-restore'),false);
});

test('unknown cleanup does not restore Rules or continue infrastructure mutation', async () => {
 const { lifecycle } = await import('./lifecycle.mjs'); const { createHash } = await import('node:crypto'); const baseline='{"rules":{}}',calls=[];let rules=baseline;
 const instanceName='projects/123/locations/us-central1/instances/demo-instance', serviceName='projects/123/services/firebasedatabase.googleapis.com';
 const io=async(step,method,path,body)=>{calls.push(step);if(step==='api-before')return {name:serviceName,state:'DISABLED'};if(step==='api-enable')return {name:'operations/a',done:true};if(step==='api-enabled')return {name:serviceName,state:'ENABLED'};if(step==='instance-before')return {name:instanceName,type:'USER_DATABASE',state:'DELETED'};if(step==='undelete'||step==='instance-active')return {name:instanceName,type:'USER_DATABASE',state:'ACTIVE'};if(step==='rules-before')return baseline;if(step==='rules-install'){rules=body;return {status:'ok'};}if(step==='rules-installed')return rules;if(step==='prefix-delete')throw Error('unknown cleanup');throw Error(`unexpected ${step}`);};
 const p={mode:'server-values',prefix,baselineHash:createHash('sha256').update(baseline).digest('hex'),instanceName,serviceName,instance:'demo-instance',project:'demo-project',listReadiness:async()=>({status:200,body:'{"instances":[]}'}),baselineProbe:async()=>({status:200,body:'null'}),probe:async()=>({status:200,body:'null'}),sleep:async()=>{}};
 await assert.rejects(lifecycle(io,p,async()=>{}),/unknown cleanup/);assert.equal(calls.includes('rules-restore'),false);assert.equal(calls.includes('disable'),false);
});

test('atomic timestamp relation reports equality across varied integer pairs',async()=>{
 for (let a=-3;a<=3;a++) for (let b=-3;b<=3;b++) {
  const db=new Map();const transport=async req=>{if(req.step==='sv-seed')db.set(req.path,JSON.parse(req.body));if(req.step==='sv-write')db.set(req.path,req.method==='PATCH'?{first:a,second:b,counter:12}:1);return {status:200,body:JSON.stringify(db.get(req.path)??null),headers:{}};};
  const rows=await runServerValueCorpus(transport,prefix,()=>42);assert.equal(rows.find(x=>x.id==='multipath-one-clock').sameClock,a===b);
 }
});
