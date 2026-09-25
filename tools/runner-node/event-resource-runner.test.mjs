// Real runner/discovery and framed IPC. Metadata models the two v1 SDK forms;
// this suite does not install Firebase or stand in for native trigger routing.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
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

async function start(t, definitions) {
  const dir = await mkdtemp(join(tmpdir(), 'fireemu-event-resource-'));
  await writeFile(join(dir, 'package.json'), JSON.stringify({ private: true, main: 'index.cjs' }));
  await writeFile(join(dir, 'index.cjs'), `
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
  const child = spawn(process.execPath, [runner, '--source', dir], {
    env: { PATH: process.env.PATH, GCLOUD_PROJECT: 'demo-resource' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const frames = [];
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
    if (!outcome) child.kill('SIGKILL');
    await exited;
    child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
    await rm(dir, { recursive: true, force: true });
  });
  const hello = await wait(() => frames.find(x => x.type === 'hello'));
  let sequence = 0;
  return {
    manifest: hello.manifest,
    async invoke(name, trigger, event) {
      const invocationId = `resource-${++sequence}`;
      child.stdin.write(frame({ type: 'invoke', invocationId, function: name, entryPoint: name, trigger, event }));
      return wait(() => frames.find(x => x.type === 'result' && x.invocationId === invocationId));
    },
    async calls() {
      try { return (await readFile(join(dir, 'calls.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse); }
      catch (error) { if (error.code === 'ENOENT') return []; throw error; }
    },
  };
}

for (const form of ['endpoint', 'legacy']) {
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
    assert.deepEqual(await f.calls(), [{ name: 'onDocument', data, context: { eventId: 'evt', timestamp: event.time, eventType: 'providers/cloud.firestore/eventTypes/document.update', resource: source, params: event.params } }]);
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
