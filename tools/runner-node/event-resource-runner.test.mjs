// Real runner/discovery and framed IPC, with metadata models and a required cached SDK gate.
// These local checks do not stand in for production trigger routing or recordings.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./index.mjs', import.meta.url));
const firestoreTypes = {
  create: 'created', update: 'updated', delete: 'deleted', write: 'written',
};
const storageTypes = {
  finalize: 'finalized', delete: 'deleted', metadataUpdate: 'metadataUpdated', archive: 'archived',
};
function entry(name, kind, resource, form = 'endpoint') {
  const metadata = form === 'endpoint'
    ? { __endpoint: { platform: 'gcfv1', eventTrigger: { eventType: kind, eventFilters: { resource }, retry: true } } }
    : { __trigger: { eventTrigger: { eventType: kind, resource, failurePolicy: { retry: {} } } } };
  return { name, ...metadata };
}
const fsEntry = (name, resource, form, kind = 'write') =>
  entry(name, `providers/cloud.firestore/eventTypes/document.${kind}`, resource, form);
const stEntry = (name, resource, form, kind = 'finalize') =>
  entry(name, `google.storage.object.${kind}`, resource, form);
const frame = value => {
  const data = Buffer.from(JSON.stringify(value));
  return Buffer.concat([Buffer.from(`${data.length}\n`), data]);
};

async function start(t, definitions, sdkSource) {
  const dir = await mkdtemp(join(tmpdir(), 'fireemu-event-resource-'));
  await writeFile(join(dir, 'package.json'), JSON.stringify({ private: true, main: 'index.cjs' }));
  await writeFile(join(dir, 'index.cjs'), sdkSource ?? `
const {appendFileSync} = require('node:fs');
const {join} = require('node:path');
module.exports = Object.create(null);
for (const {name, ...metadata} of ${JSON.stringify(definitions)}) {
  const callback = async (data, context) => appendFileSync(join(__dirname, 'calls.jsonl'), JSON.stringify({name, data, context})+'\\n');
  callback.run = callback;
  Object.assign(callback, metadata);
  module.exports[name] = callback;
}
`);
  const prefix = sdkSource && process.env.FE_SOURCE_RUNNER_PREFIX
    ? JSON.parse(process.env.FE_SOURCE_RUNNER_PREFIX) : [process.execPath];
  const child = spawn(prefix[0], [...prefix.slice(1), runner, '--source', dir], {
    detached: process.platform !== 'win32',
    env: { PATH: process.env.PATH, GCLOUD_PROJECT: 'demo-app', ...(sdkSource ? { NODE_PATH: join(sdkRoot, '..'), FE_SOURCE_RECEIPTS: process.env.FE_SOURCE_RECEIPTS } : {}) },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const frames = [];
  const identity = () => execFileSync('ps', ['-p', String(child.pid), '-o', 'pid=,comm=,lstart=,args='], { encoding: 'utf8' }).trim();
  const ownedIdentity = process.platform === 'win32' ? undefined : identity();
  let buffer = Buffer.alloc(0), stderr = '', outcome, parseError;
  child.stdin.on('error', () => {});
  const exited = once(child, 'exit').then(([code, signal]) => (outcome = { code, signal }));
  child.stderr.on('data', chunk => { if (stderr.length < 65536) stderr += chunk.toString(); });
  child.stdout.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    while (!parseError) {
      const at = buffer.indexOf(10);
      if (at < 0) break;
      const n = Number(buffer.subarray(0, at).toString());
      if (!Number.isSafeInteger(n) || n < 1 || n > 16 * 1024 * 1024) { parseError = Error('invalid output length'); break; }
      if (buffer.length < at + 1 + n) break;
      try { frames.push(JSON.parse(buffer.subarray(at + 1, at + 1 + n).toString('utf8'))); }
      catch { parseError = Error('invalid output JSON'); }
      buffer = buffer.subarray(at + 1 + n);
    }
  });
  async function wait(predicate) {
    const until = Date.now() + 5000;
    while (Date.now() < until) {
      if (parseError) throw parseError;
      const found = predicate();
      if (found) return found;
      if (outcome) throw Error(`runner exited ${JSON.stringify(outcome)}: ${stderr.slice(-500)}`);
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    throw Error('runner response timeout');
  }
  t.after(async () => {
    if (!outcome) {
      child.stdin.write(frame({ type: 'shutdown' }));
      await Promise.race([exited, new Promise(resolve => setTimeout(resolve, 3000).unref())]);
    }
    if (!outcome) {
      // The still-live ChildProcess owns this isolated group; never signal a discovered PID.
      if (process.platform === 'win32') child.kill('SIGKILL');
      else {
        assert.equal(identity(), ownedIdentity, 'verify owned PID, command and start time before group cleanup');
        assert(ownedIdentity.includes(runner));
        process.kill(-child.pid, 'SIGKILL');
      }
    }
    await exited;
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    await rm(dir, { recursive: true, force: true });
    assert.equal(outcome.code, 0, `runner shutdown failed: ${stderr.slice(-1000)}`);
  });
  const hello = await wait(() => frames.find(x => x.type === 'hello'));
  let sequence = 0;
  return {
    manifest: hello.manifest,
    async invoke(name, trigger, event, extra = {}) {
      const invocationId = `resource-${++sequence}`;
      child.stdin.write(frame({ type: 'invoke', invocationId, function: name, entryPoint: name, trigger, event, ...extra }));
      return wait(() => frames.find(x => x.type === 'result' && x.invocationId === invocationId));
    },
    async calls() {
      try { return (await readFile(join(dir, 'calls.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
      catch (error) { if (error.code === 'ENOENT') return []; throw error; }
    },
  };
}

const sdkRoot = process.env.FE_SOURCE_SDK_ROOT
  ?? fileURLToPath(new URL('../../conformance/node_modules/firebase-functions', import.meta.url));

test('real SDK Firestore generations preserve canonical Written source and missing snapshots', { timeout: 20000 }, async t => {
  const pkg = JSON.parse(await readFile(join(sdkRoot, 'package.json'), 'utf8'));
  assert.equal(pkg.version, '7.3.2', 'the real SDK gate requires its pinned cached dependency');
  const f = await start(t, [], `
const {appendFileSync} = require('node:fs');
const {join} = require('node:path');
const v1 = require(${JSON.stringify(join(sdkRoot, 'lib/v1/index.js'))});
const v2 = require(${JSON.stringify(join(sdkRoot, 'lib/v2/providers/firestore.js'))});
const snapshot = s => ({path:s.ref.path,id:s.id,exists:s.exists,data:s.data() ?? null,createTime:s.createTime?.toDate().toISOString() ?? null,updateTime:s.updateTime?.toDate().toISOString() ?? null});
const data = d => d.before ? {before:snapshot(d.before),after:snapshot(d.after)} : snapshot(d);
const report = (name,d,event) => {appendFileSync(join(__dirname,'calls.jsonl'),JSON.stringify({name,data:data(d),event})+'\\n');return Promise.resolve();};
for(const [kind,method] of Object.entries({created:'onCreate',updated:'onUpdate',deleted:'onDelete',written:'onWrite'})) {
  exports[kind+'V1']=v1.firestore.document('items/{id}')[method]((d,c)=>report(kind+'V1',d,c));
  const fn=v2[{created:'onDocumentCreated',updated:'onDocumentUpdated',deleted:'onDocumentDeleted',written:'onDocumentWritten'}[kind]]('items/{id}',e=>report(kind+'V2',e.data,{...e,data:undefined}));
  exports[kind+'V2']=Object.assign(async e=>{
    if(kind!=='written'&&(Buffer.isBuffer(e.data)||e.datacontenttype!=='application/json'))throw Error('C/U/D retain JSON transport');
    return fn(e);
  },fn);
}
`);
  const documentSource = 'projects/demo-app/databases/(default)/documents/items/one';
  const databaseSource = '//firestore.googleapis.com/projects/demo-app/databases/(default)';
  const value = n => ({ name: documentSource, fields: {v:{integerValue:String(n)}}, createTime:'2026-09-30T12:03:18.846431Z', updateTime:'2026-09-30T12:03:18.846431Z' });
  for (const [kind,old,newValue] of [['created',null,2],['updated',1,2],['deleted',1,null],['written',null,2],['written',1,null],['written',1,2]]) {
    const event = {id:'sdk-event',type:`google.cloud.firestore.document.v1.${kind}`,time:'2026-09-30T12:03:18.846431Z',source:databaseSource,subject:'documents/items/one',project:'demo-app',database:'(default)',document:'items/one',namespace:'(default)',params:{id:'one'},datacontenttype:'application/json',data:{...(old===null?{}:{oldValue:value(old)}),...(newValue===null?{}:{value:value(newValue)}),...(old!==null&&newValue!==null?{updateMask:{fieldPaths:['v']}}:{})}};
    for (const generation of [1,2]) {
      const name = `${kind}V${generation}`;
      assert.equal((await f.invoke(name,'firestore',event)).ok,true,`${name}: actual SDK decode`);
      const call=(await f.calls()).at(-1);
      const expected = n => ({path:'items/one',id:'one',exists:n!==null,data:n===null?null:{v:n},createTime:n===null?null:'2026-09-30T12:03:18.846Z',updateTime:n===null?null:'2026-09-30T12:03:18.846Z'});
      assert.deepEqual(call.data, ['updated','written'].includes(kind)?{before:expected(old),after:expected(newValue)}:expected(kind==='deleted'?old:newValue));
      assert.deepEqual(call.event.params,{id:'one'});
      if(generation===1) {
        assert.deepEqual(call.event.resource,{service:'firestore.googleapis.com',name:documentSource},'Gen1 SDK document resource');
        assert.equal(call.event.eventId,'sdk-event-0');
        assert.equal(call.event.timestamp,event.time);
      } else {
        assert.equal(call.event.source,event.source,'Gen2 SDK envelope source');
        assert.equal(call.event.subject,event.subject);
        assert.equal(call.event.time,event.time);
      }
    }
  }
});

test('real SDK Written protobuf preserves generated values, nanoseconds, side states, auth and replay', { timeout: 30000 }, async t => {
  assert.equal(JSON.parse(await readFile(join(sdkRoot,'package.json'),'utf8')).version,'7.3.2');
  const f = await start(t, [], `
const {appendFileSync}=require('node:fs');
const {join}=require('node:path');
const sdk=require(${JSON.stringify(join(sdkRoot, 'lib/v2/providers/firestore.js'))});
const admin=require('firebase-admin/app');
require('firebase-admin/firestore').getFirestore(admin.initializeApp({projectId:'demo-app'})).settings({useBigInt:true});
const codec=require(${JSON.stringify(join(sdkRoot, 'protos/compiledFirestore.js'))}).google.events.cloud.firestore.v1.DocumentEventData;
const normalize=v=>{
 if(typeof v==='bigint')return {integer:v.toString()};
 if(typeof v==='number'&&!Number.isFinite(v))return {double:String(v)};
 if(Object.is(v,-0))return {double:'-0'};
 if(Buffer.isBuffer(v))return {bytes:v.toString('base64')};
 if(v?.constructor.name==='Timestamp')return {seconds:v.seconds,nanoseconds:v.nanoseconds};
 if(v?.constructor.name==='DocumentReference')return {reference:v.path};
 if(v?.constructor.name==='GeoPoint')return {latitude:v.latitude,longitude:v.longitude};
 if(Array.isArray(v))return v.map(normalize);
 if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,normalize(x)]));
 return v;
};
const snap=s=>({exists:s.exists,path:s.ref.path,id:s.id,data:normalize(s.data()??null),createTime:normalize(s.createTime??null),updateTime:normalize(s.updateTime??null)});
let retry=false;
function declare(name,auth=false,retried=false){
 const fn=sdk[auth?'onDocumentWrittenWithAuthContext':'onDocumentWritten']({document:'items/{id}',retry:retried},async e=>{
  appendFileSync(join(__dirname,'calls.jsonl'),JSON.stringify({name,event:{...e,data:undefined},before:snap(e.data.before),after:snap(e.data.after)})+'\\n');
  if(retried&&!retry){retry=true;throw Error('intentional Written retry');}
 });
 // Observe the actual wire at entry, then delegate to the unmodified SDK function.
 exports[name]=Object.assign(async e=>{
  if(!Buffer.isBuffer(e.data)||e.datacontenttype!=='application/protobuf')throw Error('Written requires actual protobuf bytes');
  appendFileSync(join(__dirname,'calls.jsonl'),JSON.stringify({name,wire:codec.toObject(codec.decode(e.data),{longs:String,bytes:String})})+'\\n');
  return fn(e);
 },fn);
}
declare('written');declare('authWritten',true);declare('retryWritten',false,true);
`);
  const source = '//firestore.googleapis.com/projects/demo-app/databases/(default)';
  const document = 'projects/demo-app/databases/(default)/documents/items/one';
  // A deterministic generated corpus crosses value shapes with all meaningful side states.
  const values = [
    [{nullValue:'NULL_VALUE'},null], [{booleanValue:false},false],
    [{integerValue:'-9223372036854775808'},{integer:'-9223372036854775808'}],
    [{integerValue:'9223372036854775807'},{integer:'9223372036854775807'}],
    [{doubleValue:'NaN'},{double:'NaN'}], [{doubleValue:'Infinity'},{double:'Infinity'}],
    [{doubleValue:'-Infinity'},{double:'-Infinity'}], [{doubleValue:'-0'},{double:'-0'}],
    [{bytesValue:'AAH/'},{bytes:'AAH/'}], [{referenceValue:document},{reference:'items/one'}],
    [{geoPointValue:{latitude:-42.5,longitude:170.25}},{latitude:-42.5,longitude:170.25}],
    [{stringValue:'日本語/é'},'日本語/é'], [{arrayValue:{}},[]], [{mapValue:{}},{}],
  ];
  let random=0x6d2b79f5;
  const next=()=>{random^=random<<13;random^=random>>>17;random^=random<<5;return random>>>0;};
  for(let generated=0;generated<12;generated++) {
    const integer=((BigInt(next())<<32n)|BigInt(next()))-(1n<<63n);
    const bytes=Buffer.from(Array.from({length:generated+1},()=>next()&255)).toString('base64');
    values.push([{integerValue:String(integer)},{integer:String(integer)}],[{bytesValue:bytes},{bytes}]);
  }
  const second = Math.floor(Date.parse('2026-09-30T12:03:18Z') / 1000);
  const event = data => ({id:'written-replay',type:'google.cloud.firestore.document.v1.written',source,subject:'documents/items/one',time:'2026-09-30T12:03:18.846431Z',project:'demo-app',database:'(default)',document:'items/one',namespace:'(default)',params:{id:'one'},datacontenttype:'application/json',data});
  for (let seed=0; seed<values.length; seed++) {
    const nanos=(846431123+seed*9973)%1000000000;
    const stamp=`2026-09-30T12:03:18.${String(nanos).padStart(9,'0')}Z`;
    const [value,expected]=values[seed];
    const fields={v:value,nested:{mapValue:{fields:{arr:{arrayValue:{values:[value,{timestampValue:stamp}]}}}}}};
    const present={name:document,fields,createTime:stamp,updateTime:stamp};
    const expectedData={v:expected,nested:{arr:[expected,{seconds:second,nanoseconds:nanos}]}};
    for (const [old,newValue] of [[undefined,present],[present,undefined],[present,present]]) {
      const e=event({...(old?{oldValue:old}:{}),...(newValue?{value:newValue}:{}),...(old&&newValue?{updateMask:{fieldPaths:['v','nested']}}:{})});
      assert.equal((await f.invoke('written','firestore',e)).ok,true,'actual generated Written SDK callback');
      const [raw,call]=(await f.calls()).slice(-2);
      assert.equal(Object.hasOwn(raw.wire,'oldValue'),!!old,'missing before is omitted on the wire');
      assert.equal(Object.hasOwn(raw.wire,'value'),!!newValue,'missing after is omitted on the wire');
      assert.deepEqual(raw.wire.updateMask,old&&newValue?{fieldPaths:['v','nested']}:undefined,'updateMask wire values');
      for (const [side,exists] of [['before',!!old],['after',!!newValue]]) {
        assert.deepEqual(call[side],{exists,path:'items/one',id:'one',data:exists?expectedData:null,createTime:exists?{seconds:second,nanoseconds:nanos}:null,updateTime:exists?{seconds:second,nanoseconds:nanos}:null},'generated values and full timestamp precision');
      }
      assert.equal(call.event.source,source);assert.equal(call.event.subject,e.subject);assert.equal(call.event.time,e.time);assert.deepEqual(call.event.params,{id:'one'});
    }
  }
  const empty={name:document,fields:{},createTime:'1969-12-31T23:59:59.123456789Z',updateTime:'1969-12-31T23:59:59.123456789Z'};
  assert.equal((await f.invoke('written','firestore',event({value:empty}))).ok,true);
  const emptyCall=(await f.calls()).at(-1);
  assert.equal(emptyCall.before.exists,false);assert.equal(emptyCall.after.exists,true,'empty real document is present');
  assert.deepEqual(emptyCall.after.data,{});assert.deepEqual(emptyCall.after.createTime,{seconds:-1,nanoseconds:123456789});
  for (const [stamp,seconds,nanoseconds] of [
    ['0001-01-01T00:00:00Z',-62135596800,0],
    ['9999-12-31T23:59:59.999999999Z',253402300799,999999999],
    ['1970-01-01T01:00:00.1+01:00',0,100000000],
  ]) {
    assert.equal((await f.invoke('written','firestore',event({value:{...empty,createTime:stamp,updateTime:stamp}}))).ok,true,'timestamp boundary actual SDK callback');
    assert.deepEqual((await f.calls()).at(-1).after.createTime,{seconds,nanoseconds},'timestamp seconds/nanoseconds preserve ranges and offsets');
  }
  for (const stamp of ['invalid','2026-09-30T12:03:18.1234567890Z']) {
    const count=(await f.calls()).length;
    assert.equal((await f.invoke('written','firestore',event({value:{...empty,createTime:stamp}}))).ok,false,'invalid timestamp fails before the callback');
    assert.equal((await f.calls()).length,count,'invalid timestamp has no wire or handler side effects');
  }
  const auth={...event({oldValue:empty}),type:'google.cloud.firestore.document.v1.written.withAuthContext',authtype:'system',authid:'principal'};
  assert.equal((await f.invoke('authWritten','firestore',auth)).ok,true,'actual Written auth callback');
  const authCall=(await f.calls()).at(-1);
  assert.equal(authCall.after.exists,false);assert.equal(authCall.event.authType,'system');assert.equal(authCall.event.authId,'principal');assert.equal(authCall.event.source,source);
  const retry=event({value:empty});
  assert.equal((await f.invoke('retryWritten','firestore',retry)).ok,false,'first callback fails intentionally');
  const first=(await f.calls()).at(-1);
  assert.equal((await f.invoke('retryWritten','firestore',retry)).ok,true,'retry reaches the actual SDK callback');
  assert.deepEqual((await f.calls()).at(-1),first,'retry preserves identity, data and envelope');
});

for (const form of ['endpoint', 'legacy']) {
  test(`v1 ${form}: finite metadata model keeps legacy fallback and other product resources`, { timeout: 10000 }, async t => {
    const f = await start(t, [fsEntry('typed', 'projects/demo-app/databases/(default)/documents/items/{id}', form, 'create'), entry('topic', 'google.pubsub.topic.publish', 'projects/demo-app/topics/t', form)]);
    const base = {id:'finite',type:'google.cloud.firestore.document.v1.created',time:'2026-09-30T12:03:18.846431Z',source:'legacy-document-source',params:{id:'one'},data:{value:{name:'sentinel'}}};
    for(const project of [undefined, '', 1, 'projects']) {
      for(const database of [undefined, null, 'databases']) {
        for(const document of [undefined, false, 'documents/日本語']) {
          const event = {...base, project, database, document};
          assert.equal((await f.invoke('typed','firestore',event)).ok,true);
          const expected = typeof project==='string' && project!=='' && typeof database==='string' && typeof document==='string'
            ? `projects/${project}/databases/${database}/documents/${document}` : base.source;
          assert.equal((await f.calls()).at(-1).context.resource,expected,'independent finite metadata admission model');
        }
      }
    }
    const source='//pubsub.googleapis.com/projects/demo-app/topics/t';
    const event={...base,source,project:'demo-app',database:'(default)',document:'items/one',type:'google.cloud.pubsub.topic.v1.messagePublished',data:{message:{data:'',messageId:'m1'}}};
    assert.equal((await f.invoke('topic','pubsub',event)).ok,true);
    assert.deepEqual((await f.calls()).at(-1).context.resource,{service:'pubsub.googleapis.com',name:'projects/demo-app/topics/t',type:'type.googleapis.com/google.pubsub.v1.PubsubMessage'},'Firestore source projection must not apply to PubSub');
  });

  test(`v1 ${form}: typed Firestore metadata projects the document resource independently of Gen2 source`, { timeout: 10000 }, async t => {
    const f = await start(t, [fsEntry('typed', 'projects/documents/databases/databases/documents/orders/{id}', form, 'update')]);
    for (const document of ['orders/日本語', 'documents/one/databases/two']) {
      const event = { id: 'typed-id', type: 'google.cloud.firestore.document.v1.updated', time: '2026-09-30T12:03:18.846431Z', source: '//firestore.googleapis.com/projects/documents/databases/databases', project: 'documents', database: 'databases', document, subject: `documents/${document}`, params: { id: document }, data: { sentinel: document } };
      assert.equal((await f.invoke('typed', 'firestore', event)).ok, true);
      const call = (await f.calls()).at(-1);
      assert.equal(call.context.resource, `projects/documents/databases/databases/documents/${document}`, 'Gen1 document resource must not reuse the Gen2 database source');
      assert.equal(call.context.eventId, 'typed-id-0');
      assert.equal(call.context.timestamp, event.time);
      assert.deepEqual(call.data, event.data);
      assert.deepEqual(call.context.params, event.params);
    }
  });

  test(`v1 ${form}: Firestore namespace markers are values, not separators`, { timeout: 10000 }, async t => {
    const fixtures = [];
    for (const project of ['demo-resource', 'documents', 'databases', 'projects', '_']) {
      for (const database of ['(default)', 'documents', 'databases', 'tenant-db']) {
        for (const document of ['orders/{orderId}', 'documents/{doc}/databases/{nested}']) {
          const name = `f${fixtures.length}`;
          fixtures.push({ name, project, database, document });
        }
      }
    }
    const f = await start(t, fixtures.map(x => fsEntry(x.name,
      `projects/${x.project}/databases/${x.database}/documents/${x.document}`, form)));
    assert.deepEqual(f.manifest.ignored, []);
    assert.equal(f.manifest.functions.length, fixtures.length);
    for (const fixture of fixtures) {
      const spec = f.manifest.functions.find(x => x.name === fixture.name);
      assert.equal(spec.trigger.database, fixture.database, JSON.stringify(fixture));
      assert.equal(spec.trigger.document, fixture.document, JSON.stringify(fixture));
      assert.equal(spec.trigger.eventType, 'google.cloud.firestore.document.v1.written');
      assert.equal(spec.v1, true); assert.equal(spec.retry, true);
    }
  });

  test(`v1 ${form}: Firestore event kinds and literal pattern data survive extraction`, { timeout: 10000 }, async t => {
    const document = '注文/{注文ID}/literal%2Fdocs/{id}';
    const f = await start(t, Object.keys(firestoreTypes).map(kind =>
      fsEntry(kind, `projects/documents/databases/databases/documents/${document}`, form, kind)));
    assert.deepEqual(f.manifest.ignored, []);
    for (const spec of f.manifest.functions) {
      assert.equal(spec.trigger.database, 'databases');
      assert.equal(spec.trigger.document, document);
      assert.equal(spec.trigger.eventType, `google.cloud.firestore.document.v1.${firestoreTypes[spec.name]}`);
    }
  });

  test(`v1 ${form}: malformed Firestore prefixes never become a default/wrong database trigger`, { timeout: 10000 }, async t => {
    const invalid = [
      '', 'orders/{id}', 'projects/p/documents/orders/{id}',
      'projects/p/databases//documents/orders/{id}', 'projects//databases/db/documents/orders/{id}',
      'prefix/projects/p/databases/db/documents/orders/{id}',
      '//firestore.googleapis.com/projects/p/databases/db/documents/orders/{id}',
      'projects/p/databases/db/documents', 'projects/p/databases/db/documents/',
      'projects/p/databases/db/not-documents/orders/{id}',
      'projects/p/databases/db/documents@alternate/orders/{id}',
    ];
    const definitions = invalid.map((value, i) => fsEntry(`bad${i}`, value, form));
    definitions.push(fsEntry('healthy', 'projects/demo-resource/databases/(default)/documents/orders/{id}', form));
    const f = await start(t, definitions);
    assert.deepEqual(f.manifest.functions.map(x => x.name), ['healthy']);
    assert.equal(f.manifest.ignored.length, invalid.length);
    for (const ignored of f.manifest.ignored) {
      assert.equal(ignored.scope, 'unsupported'); assert.equal(ignored.triggerType, 'firestore');
      assert.match(ignored.reason, /resource/);
      assert.equal((await f.invoke(ignored.name, 'firestore', { data: {} })).ok, false);
    }
    assert.deepEqual(await f.calls(), []);
    const event = { id: 'event-1', type: 'google.cloud.firestore.document.v1.written', time: '2026-01-01T00:00:00Z', source: 'projects/demo-resource/databases/(default)/documents/orders/1', params: { id: '1' }, data: { value: { name: 'same' } } };
    assert.equal((await f.invoke('healthy', 'firestore', event)).ok, true);
    assert.equal((await f.calls()).length, 1);
  });

  test(`v1 ${form}: valid Firestore callback keeps the original resource, data and params`, { timeout: 10000 }, async t => {
    const f = await start(t, [fsEntry('onDocument', 'projects/documents/databases/documents/documents/orders/{id}', form, 'update')]);
    const source = 'projects/documents/databases/documents/documents/orders/日本語';
    const data = { oldValue: { fields: { x: { integerValue: '1' } } }, value: { fields: { x: { integerValue: '2' } } } };
    const event = { id: 'evt', type: 'google.cloud.firestore.document.v1.updated', time: '2026-01-01T00:00:00Z', source, params: { id: '日本語' }, data };
    assert.equal((await f.invoke('onDocument', 'firestore', event)).ok, true);
    assert.deepEqual(await f.calls(), [{ name: 'onDocument', data, context: { eventId: 'evt-0', timestamp: event.time, eventType: 'providers/cloud.firestore/eventTypes/document.update', resource: source, params: event.params, notSupported: {} } }]);
  });

  test(`v1 ${form}: a Firestore legacy event id is the event id plus the trigger index suffix`, { timeout: 10000 }, async t => {
    // Production (observed 2026-09-30): a Gen1 Firestore handler's context.eventId is `<uuid>-0`.
    const kinds = { created: 'create', updated: 'update', deleted: 'delete', written: 'write' };
    const f = await start(t, Object.values(kinds).map(kind => fsEntry(`on_${kind}`, 'projects/demo/databases/(default)/documents/orders/{id}', form, kind)));
    for (const [type, kind] of Object.entries(kinds)) {
      const event = { id: 'dc880941-8bb2-410f-9b10-51c47560a33a', type: `google.cloud.firestore.document.v1.${type}`, time: '2026-09-30T12:03:18.846431Z', source: 'projects/demo/databases/(default)/documents/orders/1', params: { id: '1' }, data: {} };
      assert.equal((await f.invoke(`on_${kind}`, 'firestore', event)).ok, true);
    }
    const calls = await f.calls();
    assert.deepEqual(calls.map(call => call.context.eventId), Object.values(kinds).map(() => 'dc880941-8bb2-410f-9b10-51c47560a33a-0'));
    assert.deepEqual(calls.map(call => call.context.timestamp), Object.values(kinds).map(() => '2026-09-30T12:03:18.846431Z'));
  });

  test(`v1 ${form}: the other legacy products keep the event id as it is`, { timeout: 10000 }, async t => {
    // Only Firestore was recorded with the `-0` suffix; nothing else changes.
    const id = 'dc880941-8bb2-410f-9b10-51c47560a33a';
    const time = '2026-09-30T12:03:18.846431Z';
    const f = await start(t, [
      stEntry('onFinalize', 'projects/_/buckets/assets.example', form),
      entry('onPublish', 'google.pubsub.topic.publish', 'projects/demo/topics/t', form),
      entry('onUserCreate', 'providers/firebase.auth/eventTypes/user.create', 'projects/demo', form),
    ]);
    const events = [
      ['onFinalize', 'storage', { id, type: 'google.cloud.storage.object.v1.finalized', time, source: '//storage.googleapis.com/projects/_/buckets/assets.example', data: { bucket: 'assets.example', name: 'a.txt' } }],
      ['onPublish', 'pubsub', { id, type: 'google.cloud.pubsub.topic.v1.messagePublished', time, source: '//pubsub.googleapis.com/projects/demo/topics/t', data: { message: { data: '', attributes: {}, messageId: 'm1' } } }],
      ['onUserCreate', 'auth', { id, type: 'google.firebase.auth.user.v1.created', time, source: '//firebaseauth.googleapis.com/projects/demo', data: { uid: 'u1' } }],
    ];
    for (const [name, trigger, event] of events) {
      assert.equal((await f.invoke(name, trigger, event)).ok, true, name);
    }
    const calls = await f.calls();
    assert.deepEqual(calls.map(call => call.name), events.map(([name]) => name));
    assert.deepEqual(calls.map(call => call.context.eventId), events.map(() => id));
    // Storage prints its legacy timestamp with exactly three fraction digits (observed 2026-10-01).
    assert.deepEqual(calls.map(call => call.context.timestamp), ['2026-09-30T12:03:18.846Z', '2026-09-30T12:03:18.846Z', time]);
  });

  test(`v1 ${form}: a Firestore and an Auth legacy context carry the empty notSupported member production sends, Storage and Pub/Sub do not`, { timeout: 10000 }, async t => {
    // Production (formal record functions-events-formal-20261004T182904Z-a9621bfae74fe9bc, production-run.json `frames`): every
    // Gen1 Firestore frame (fsCreatedV1 frame 1, fsWrittenV1 4, fsDeletedV1 7, fsUpdatedV1 29: 60 of 60) and every Gen1 Auth frame
    // (authCreatedV1 frame 55, authDeletedV1 66: 28 of 28) has `notSupported` among its context keys, an empty object; the 48
    // Gen1 Storage and Pub/Sub frames (storageFinalizedV1 79, storageDeletedV1 81, storageMetadataUpdatedV1 95, storageArchivedV1
    // 115, pubsubPublishedV1 133) have none.
    const time = '2026-09-30T12:03:18.846431Z';
    const kinds = { created: 'create', updated: 'update', deleted: 'delete', written: 'write' };
    const f = await start(t, [
      ...Object.values(kinds).map(kind => fsEntry(`on_${kind}`, 'projects/demo/databases/(default)/documents/orders/{id}', form, kind)),
      stEntry('onFinalize', 'projects/_/buckets/assets.example', form),
      entry('onPublish', 'google.pubsub.topic.publish', 'projects/demo/topics/t', form),
      entry('onUserCreate', 'providers/firebase.auth/eventTypes/user.create', 'projects/demo', form),
      entry('onUserDelete', 'providers/firebase.auth/eventTypes/user.delete', 'projects/demo', form),
    ]);
    const events = [
      ...Object.entries(kinds).map(([type, kind]) => [`on_${kind}`, 'firestore', { id: 'dc880941-8bb2-410f-9b10-51c47560a33a', type: `google.cloud.firestore.document.v1.${type}`, time, source: 'projects/demo/databases/(default)/documents/orders/1', params: { id: '1' }, data: {} }, true]),
      ['onFinalize', 'storage', { id: 'e1', type: 'google.cloud.storage.object.v1.finalized', time, source: '//storage.googleapis.com/projects/_/buckets/assets.example', data: { bucket: 'assets.example', name: 'a.txt' } }, false],
      ['onPublish', 'pubsub', { id: 'e2', type: 'google.cloud.pubsub.topic.v1.messagePublished', time, source: '//pubsub.googleapis.com/projects/demo/topics/t', data: { message: { data: '', attributes: {}, messageId: 'm1' } } }, false],
      ['onUserCreate', 'auth', { id: 'e3', type: 'google.firebase.auth.user.v1.created', time, source: '//firebaseauth.googleapis.com/projects/demo', data: { uid: 'u1' } }, true],
      ['onUserDelete', 'auth', { id: 'e4', type: 'google.firebase.auth.user.v1.deleted', time, source: '//firebaseauth.googleapis.com/projects/demo', data: { uid: 'u1' } }, true],
    ];
    for (const [name, trigger, event] of events) assert.equal((await f.invoke(name, trigger, event)).ok, true, name);
    const calls = await f.calls();
    assert.equal(calls.length, events.length);
    events.forEach(([name, , , carries], index) => {
      if (carries) assert.deepEqual(calls[index].context.notSupported, {}, name);
      else assert.equal(Object.hasOwn(calls[index].context, 'notSupported'), false, name);
    });
  });

  test(`v1 ${form}: a Storage legacy context has the members and forms of the recorded production context`, { timeout: 10000 }, async t => {
    // Production (observed 2026-10-01, crates/fireemu-adapter-functions/tests/fixtures/production-storage-finalize-frames.json):
    // eventId is a seventeen-digit decimal string without a suffix, the timestamp has exactly three fraction digits and
    // is later than the object's timeCreated (91 ms in the recording), the resource has no generation suffix and a `type`.
    const recorded = JSON.parse(await readFile(new URL('../../crates/fireemu-adapter-functions/tests/fixtures/production-storage-finalize-frames.json', import.meta.url), 'utf8'));
    const context = recorded.gen1.context;
    const bucket = recorded.gen1.data.bucket;
    const f = await start(t, [stEntry('onFinalize', `projects/_/buckets/${bucket}`, form)]);
    const admitted = '2026-10-01T08:49:26.577123456Z';
    const event = { id: '22201766561849599', type: 'google.cloud.storage.object.v1.finalized', time: recorded.gen2.time, source: recorded.gen2.source, data: recorded.gen1.data };
    assert.equal((await f.invoke('onFinalize', 'storage', event, { admittedAt: admitted })).ok, true);
    const [call] = await f.calls();
    // The recorded context's own members (`contextKeys` in the frame) are the ones the handler receives.
    assert.deepEqual(Object.keys(call.context).sort(), [...context.contextKeys].sort());
    assert.equal(call.context.eventType, context.eventType);
    assert.deepEqual(call.context.resource, context.resource);
    assert.deepEqual(call.context.params, context.params);
    assert.match(call.context.eventId, /^[0-9]{17}$/);
    assert.match(context.eventId, /^[0-9]{17}$/);
    assert.match(call.context.timestamp, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    assert.match(context.timestamp, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    // Both are later than the object's creation, and the local one is the admission instant cut to the millisecond.
    assert.ok(Date.parse(call.context.timestamp) >= Date.parse(recorded.gen1.data.timeCreated));
    assert.ok(Date.parse(context.timestamp) >= Date.parse(recorded.gen1.data.timeCreated));
    assert.equal(call.context.timestamp, '2026-10-01T08:49:26.577Z');
  });

  test(`v1 ${form}: a Storage legacy timestamp keeps a value that is not a time as it is, and cuts the fraction of one that is`, { timeout: 10000 }, async t => {
    const f = await start(t, [stEntry('onFinalize', 'projects/_/buckets/assets.example', form)]);
    const times = ['2026-10-01T08:49:26Z', '2026-10-01T08:49:26.5Z', '2026-10-01T08:49:26.123456789Z', 'not a time'];
    for (const time of times) {
      const event = { id: '1', type: 'google.cloud.storage.object.v1.finalized', time, source: '//storage.googleapis.com/projects/_/buckets/assets.example', data: { bucket: 'assets.example', name: 'a.txt' } };
      assert.equal((await f.invoke('onFinalize', 'storage', event)).ok, true);
    }
    assert.deepEqual((await f.calls()).map(call => call.context.timestamp), ['2026-10-01T08:49:26.000Z', '2026-10-01T08:49:26.500Z', '2026-10-01T08:49:26.123Z', 'not a time']);
    // The admission instant the frame carries wins over the event's own time, and one that is not a time passes through unchanged.
    const base = { id: '1', type: 'google.cloud.storage.object.v1.finalized', source: '//storage.googleapis.com/projects/_/buckets/assets.example', data: { bucket: 'assets.example', name: 'a.txt' } };
    assert.equal((await f.invoke('onFinalize', 'storage', { ...base, time: '2026-10-01T08:49:26.486927Z' }, { admittedAt: '2026-10-01T08:49:26.577999999Z' })).ok, true);
    assert.equal((await f.invoke('onFinalize', 'storage', { ...base, time: '2026-10-01T08:49:26.486927Z' }, { admittedAt: 'not a time' })).ok, true);
    assert.deepEqual((await f.calls()).slice(4).map(call => call.context.timestamp), ['2026-10-01T08:49:26.577Z', 'not a time']);
  });

  test(`v1 ${form}: Storage bucket selection does not consume the project named buckets`, { timeout: 10000 }, async t => {
    const definitions = [];
    for (const project of ['_', 'demo-resource', 'buckets']) {
      for (const [kind] of Object.entries(storageTypes)) {
        definitions.push(stEntry(`f${definitions.length}`, `projects/${project}/buckets/assets.example`, form, kind));
      }
    }
    const f = await start(t, definitions);
    assert.deepEqual(f.manifest.ignored, []);
    assert.equal(f.manifest.functions.length, definitions.length);
    for (let i = 0; i < definitions.length; i++) {
      const spec = f.manifest.functions[i];
      assert.equal(spec.trigger.bucket, 'assets.example');
      assert.equal(spec.trigger.eventType, `google.cloud.storage.object.v1.${Object.values(storageTypes)[i % 4]}`);
    }
  });

  test(`v1 ${form}: malformed Storage resources never widen into all-bucket triggers`, { timeout: 10000 }, async t => {
    const invalid = ['', 'assets.example', 'projects/_/buckets/', 'projects//buckets/other',
      'prefix/projects/_/buckets/other', 'projects/_/buckets/other/objects/object',
      'projects/_/not-buckets/other', '//storage.googleapis.com/projects/_/buckets/other'];
    const f = await start(t, [...invalid.map((resource, i) => stEntry(`bad${i}`, resource, form)),
      stEntry('healthy', 'projects/_/buckets/assets.example', form)]);
    assert.deepEqual(f.manifest.functions.map(x => x.name), ['healthy']);
    assert.equal(f.manifest.ignored.length, invalid.length);
    for (const item of f.manifest.ignored) { assert.equal(item.scope, 'unsupported'); assert.equal(item.triggerType, 'storage'); }
  });
}

test('v2 explicit database/document and bucket filters are not interpreted as v1 resource strings', { timeout: 10000 }, async t => {
  const document = 'documents/{doc}/databases/{id}';
  const f = await start(t, [
    { name: 'modern', __endpoint: { platform: 'gcfv2', eventTrigger: { eventType: 'google.cloud.firestore.document.v1.written', eventFilters: { database: 'documents' }, eventFilterPathPatterns: { document } } } },
    { name: 'object', __endpoint: { platform: 'gcfv2', eventTrigger: { eventType: 'google.cloud.storage.object.v1.finalized', eventFilters: { bucket: 'assets.example' } } } },
  ]);
  assert.deepEqual(f.manifest.ignored, []);
  assert.equal(f.manifest.functions[0].trigger.database, 'documents');
  assert.equal(f.manifest.functions[0].trigger.document, document);
  assert.equal(f.manifest.functions[1].trigger.bucket, 'assets.example');
  assert.equal(f.manifest.functions.every(x => x.generation === 2), true);
});

// Storage event shapes of the FE v5 production recording (run functions-events-formal-20261004T182904Z-a9621bfae74fe9bc,
// 2026-10-04): the handler prints what it receives, so the member order is the order the handler was handed.
const v5Storage = JSON.parse(await readFile(new URL('../../crates/fireemu-adapter-functions/tests/fixtures/production-storage-v5-frames.json', import.meta.url), 'utf8'));
const v5Frame = insertId => v5Storage.frames.find(f => f.insertId === insertId);
const alphabetical = value => Object.fromEntries(Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));

test('v1: a Storage legacy context lists its resource members in the order production hands them over: name, service, type (v5 frame 6ac29fb70006ad918ea2a73d)', { timeout: 10000 }, async t => {
  const recorded = v5Frame('6ac29fb70006ad918ea2a73d').frame;
  assert.deepEqual(Object.keys(recorded.context.resource), ['name', 'service', 'type']);
  const bucket = recorded.data.bucket;
  const f = await start(t, [stEntry('onFinalize', `projects/_/buckets/${bucket}`, 'endpoint')]);
  const event = { id: '22252774326123787', type: 'google.cloud.storage.object.v1.finalized', time: '2026-10-04T18:49:25.459311Z', source: `//storage.googleapis.com/projects/_/buckets/${bucket}`, data: alphabetical(recorded.data) };
  assert.equal((await f.invoke('onFinalize', 'storage', event, { admittedAt: '2026-10-04T18:49:25.526Z' })).ok, true);
  const [call] = await f.calls();
  assert.deepEqual(Object.keys(call.context.resource), ['name', 'service', 'type']);
  assert.deepEqual(call.context.resource, { ...recorded.context.resource, name: call.context.resource.name });
  assert.equal(call.context.resource.name, `projects/_/buckets/${bucket}/objects/${recorded.data.name}`);
});

for (const [handler, insertId, eventType] of [
  ['storageFinalizedV2', '6ac29fb7000987a59af4b7f6', 'finalized'],
  ['storageDeletedV2', '6ac29fd70001a0e4d85cfd12', 'deleted'],
  ['storageMetadataUpdatedV2', '6ac2a0a80000b3d27b4b1db3', 'metadataUpdated'],
]) {
  test(`v2: a Storage ${eventType} handler is handed the object members in the recorded order (v5 frame ${insertId})`, { timeout: 10000 }, async t => {
    const recorded = v5Frame(insertId).frame;
    assert.equal(v5Frame(insertId).handler, handler);
    const bucket = recorded.data.bucket;
    const f = await start(t, [{ name: 'object', __endpoint: { platform: 'gcfv2', eventTrigger: { eventType: `google.cloud.storage.object.v1.${eventType}`, eventFilters: { bucket } } } }]);
    // The runtime's JSON has its members sorted by name; the handler must see the recorded order.
    const event = { id: recorded.id, type: recorded.type, time: recorded.time, source: recorded.source, subject: recorded.subject, specversion: '1.0', bucket, data: alphabetical(recorded.data) };
    assert.equal((await f.invoke('object', 'storage', event)).ok, true);
    const [call] = await f.calls();
    assert.deepEqual(Object.keys(call.data.data), Object.keys(recorded.data));
    assert.deepEqual(call.data.data, recorded.data);
    // The envelope is not reordered or reshaped.
    assert.deepEqual(Object.keys(call.data).filter(key => key !== 'data').sort(), Object.keys(event).filter(key => key !== 'data').sort());
  });
}

test('v2: members of a Storage object that the recordings never showed follow the recorded ones in name order, and an unknown member is kept', { timeout: 10000 }, async t => {
  const recorded = v5Frame('6ac29fb7000987a59af4b7f6').frame;
  const bucket = recorded.data.bucket;
  const f = await start(t, [{ name: 'object', __endpoint: { platform: 'gcfv2', eventTrigger: { eventType: 'google.cloud.storage.object.v1.finalized', eventFilters: { bucket } } } }]);
  const extras = { cacheControl: 'no-cache', contentEncoding: 'gzip', zzz: 1, aaa: 2 };
  // The extras arrive in reverse name order: the rule is name order, not arrival order.
  const reversed = Object.fromEntries(Object.entries(alphabetical({ ...recorded.data, ...extras })).reverse());
  const event = { id: recorded.id, type: recorded.type, time: recorded.time, source: recorded.source, subject: recorded.subject, specversion: '1.0', bucket, data: reversed };
  assert.equal((await f.invoke('object', 'storage', event)).ok, true);
  const [call] = await f.calls();
  assert.deepEqual(Object.keys(call.data.data), [...Object.keys(recorded.data), 'aaa', 'cacheControl', 'contentEncoding', 'zzz']);
});

const v5Orders = JSON.parse(await readFile(new URL('../../crates/fireemu-adapter-functions/tests/fixtures/production-storage-v5-v2-member-orders.json', import.meta.url), 'utf8'));

test('v2: every one of the 44 recorded Storage frames is handed over in its recorded member order (FE v5, finalize, delete, metadataUpdate and archive, with timeDeleted and metadata)', { timeout: 30000 }, async t => {
  assert.equal(v5Orders.frames.length, 44);
  const bucket = 'fireemu-oracle-events.firebasestorage.app';
  const f = await start(t, [{ name: 'object', __endpoint: { platform: 'gcfv2', eventTrigger: { eventType: 'google.cloud.storage.object.v1.finalized', eventFilters: { bucket } } } }]);
  for (const { insertId, members } of v5Orders.frames) {
    // The runtime's JSON lists members by name, whatever production's order was.
    const data = Object.fromEntries([...members].sort().map(key => [key, key === 'metadata' ? { marker: 'm' } : 'x']));
    const event = { id: '1', type: 'google.cloud.storage.object.v1.finalized', time: '2026-10-04T18:49:25.459311Z', source: `//storage.googleapis.com/projects/_/buckets/${bucket}`, subject: 'objects/o', specversion: '1.0', bucket, data };
    assert.equal((await f.invoke('object', 'storage', event)).ok, true, insertId);
  }
  const calls = await f.calls();
  assert.equal(calls.length, 44);
  calls.forEach((call, index) => {
    assert.deepEqual(Object.keys(call.data.data), v5Orders.frames[index].members, v5Orders.frames[index].insertId);
  });
});
for (const form of ['endpoint', 'legacy']) {
  test(`v1 ${form}: a Pub/Sub legacy context has the members and forms of the recorded production context`, { timeout: 10000 }, async t => {
    // Production (functions-events-formal run a9621bfae74fe9bc, transport/responses/0282-capture.list.json, handler
    // pubsubPublishedV1): eventId is the message id (seventeen decimals), the timestamp has exactly three fraction
    // digits, and the resource carries the message type next to the topic and the service.
    const f = await start(t, [entry('onPublish', 'google.pubsub.topic.publish', 'projects/fireemu-oracle-events/topics/fe-events-primary', form)]);
    const event = { id: '22255693239595822', type: 'google.cloud.pubsub.topic.v1.messagePublished', time: '2026-10-04T19:48:48.931482Z', source: '//pubsub.googleapis.com/projects/fireemu-oracle-events/topics/fe-events-primary', data: { message: { data: '', attributes: {}, messageId: '22255693239595822' } } };
    assert.equal((await f.invoke('onPublish', 'pubsub', event)).ok, true);
    const context = (await f.calls()).at(-1).context;
    assert.equal(context.eventId, '22255693239595822');
    assert.equal(context.timestamp, '2026-10-04T19:48:48.931Z');
    assert.equal(context.eventType, 'google.pubsub.topic.publish');
    assert.deepEqual(context.resource, { name: 'projects/fireemu-oracle-events/topics/fe-events-primary', service: 'pubsub.googleapis.com', type: 'type.googleapis.com/google.pubsub.v1.PubsubMessage' });
    // The timestamp is the publish instant of the message, not the admission instant a Storage event carries.
    assert.equal((await f.invoke('onPublish', 'pubsub', event, { admittedAt: '2030-01-01T00:00:00.123Z' })).ok, true);
    assert.equal((await f.calls()).at(-1).context.timestamp, '2026-10-04T19:48:48.931Z');
  });
}
