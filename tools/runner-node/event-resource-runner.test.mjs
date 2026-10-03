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

test('real SDK Firestore generations preserve snapshot data and isolate Written fallback', { timeout: 20000 }, async t => {
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
  exports[kind+'V2']=v2[{created:'onDocumentCreated',updated:'onDocumentUpdated',deleted:'onDocumentDeleted',written:'onDocumentWritten'}[kind]]('items/{id}',e=>report(kind+'V2',e.data,{...e,data:undefined}));
}
`);
  const documentSource = 'projects/demo-app/databases/(default)/documents/items/one';
  const databaseSource = '//firestore.googleapis.com/projects/demo-app/databases/(default)';
  const value = n => ({ name: documentSource, fields: {v:{integerValue:String(n)}}, createTime:'2026-09-30T12:03:18.846431Z', updateTime:'2026-09-30T12:03:18.846431Z' });
  for (const [kind,old,newValue] of [['created',null,2],['updated',1,2],['deleted',1,null],['written',null,2],['written',1,null],['written',1,2]]) {
    const event = {id:'sdk-event',type:`google.cloud.firestore.document.v1.${kind}`,time:'2026-09-30T12:03:18.846431Z',source:kind==='written'?documentSource:databaseSource,subject:'documents/items/one',project:'demo-app',database:'(default)',document:'items/one',namespace:'(default)',params:{id:'one'},datacontenttype:'application/json',data:{...(old===null?{}:{oldValue:value(old)}),...(newValue===null?{}:{value:value(newValue)}),...(old!==null&&newValue!==null?{updateMask:{fieldPaths:['v']}}:{})}};
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
    assert.deepEqual((await f.calls()).at(-1).context.resource,{service:'pubsub.googleapis.com',name:'projects/demo-app/topics/t'},'Firestore source projection must not apply to PubSub');
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
    assert.deepEqual(await f.calls(), [{ name: 'onDocument', data, context: { eventId: 'evt-0', timestamp: event.time, eventType: 'providers/cloud.firestore/eventTypes/document.update', resource: source, params: event.params } }]);
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
    assert.deepEqual(calls.map(call => call.context.timestamp), ['2026-09-30T12:03:18.846Z', time, time]);
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
