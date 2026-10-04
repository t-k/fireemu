import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { runUnary, serviceDefinitions } from './txn_retry_grpc_transport.mjs';

const require = createRequire(new URL('../../../conformance/package.json', import.meta.url));
const grpc = require('@grpc/grpc-js');
const database = 'projects/demo-p09/databases/(default)';
const nonce = 'a'.repeat(32);
const ownerId = 'b'.repeat(32);
const name = `${database}/documents/oracle/${nonce}/txn-p09/control`;
const token = Buffer.from('issued-token').toString('base64');

async function fixture(handlers, fn) {
  const server = new grpc.Server();
  const received = [];
  server.addService(serviceDefinitions(), Object.fromEntries(Object.entries(handlers).map(([method, handler]) => [method, (call, callback) => {
    received.push({ method, request: call.request, metadata: call.metadata });
    handler(call, callback);
  }])));
  const port = await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, value) => error ? reject(error) : resolve(value)));
  const spec = (method, request, deadlineMs = 1000) => ({ kind: 'txn-p09-grpc-call-v1', target: { kind: 'local', host: '127.0.0.1', port }, projectId: 'demo-p09', nonce, ownerId, method, request, bearer: 'owner', deadlineMs });
  try { await fn(spec, received); } finally { server.forceShutdown(); }
}

test('five native RPCs have one accepted call and their exact response types', async () => {
  await fixture({
    BeginTransaction: (_call, done) => done(null, { transaction: Buffer.from('issued-token') }),
    GetDocument: (_call, done) => done(null, { name, fields: { state: { stringValue: 'outside' } }, updateTime: { seconds: '1788004860', nanos: 123 } }),
    Commit: (_call, done) => done(null, { writeResults: [{ updateTime: { seconds: '1788004860', nanos: 123 } }] }),
    Rollback: (_call, done) => done(null, {}),
    DeleteDocument: (_call, done) => done(null, {}),
  }, async (spec, received) => {
    const begun = await runUnary(spec('BeginTransaction', { database, options: { readWrite: {} } }));
    assert.equal(begun.response.transaction, token);
    const read = await runUnary(spec('GetDocument', { name, transaction: token }));
    assert.equal(read.response.name, name);
    assert.equal(read.response.updateTime.seconds, '1788004860');
    const fields = Object.fromEntries(Object.entries({ owner: ownerId, nonce, role: 'control', state: 'outside' }).map(([key, value]) => [key, { stringValue: value }]));
    const committed = await runUnary(spec('Commit', { database, writes: [{ update: { name, fields }, currentDocument: { exists: true } }], transaction: token }));
    assert.equal(committed.code, 0);
    for (const [method, request] of [['Rollback', { database, transaction: token }], ['DeleteDocument', { name, currentDocument: { updateTime: { seconds: '1788004860', nanos: 123 } } }]]) {
      const result = await runUnary(spec(method, request));
      assert.equal(result.complete, true);
      assert.equal(result.code, 0);
      assert.deepEqual(result.response, {});
    }
    assert.equal(received.length, 5);
    assert.deepEqual(received.map(row => row.method), ['BeginTransaction', 'GetDocument', 'Commit', 'Rollback', 'DeleteDocument']);
    assert.deepEqual(received[1].request.transaction, Buffer.from('issued-token'));
    assert.deepEqual(received[0].metadata.get('authorization'), ['Bearer owner']);
    assert.deepEqual(received[0].metadata.get('x-goog-user-project'), []);
  });
});

test('UNAVAILABLE is indeterminate and never retries the native request', async () => {
  await fixture({ BeginTransaction: (_call, done) => done({ code: grpc.status.UNAVAILABLE, details: 'local refusal' }) }, async (spec, received) => {
    const result = await runUnary(spec('BeginTransaction', { database, options: { readWrite: {} } }));
    assert.equal(result.complete, false);
    assert.equal(result.code, 14);
    assert.equal(result.details, 'local refusal');
    assert.equal(received.length, 1);
  });
});

test('NO_RETRY defeats an otherwise eligible service retry policy on the actual wire', async () => {
  await fixture({ BeginTransaction: (_call, done) => done({ code: grpc.status.UNAVAILABLE, details: 'eligible refusal' }) }, async (spec, received) => {
    let factories = 0;
    const factory = (endpoint, credentials, options) => {
      factories += 1;
      const service = { methodConfig: [{ name: [{ service: 'google.firestore.v1.Firestore', method: 'BeginTransaction' }], retryPolicy: { maxAttempts: 4, initialBackoff: '0.001s', maxBackoff: '0.001s', backoffMultiplier: 1, retryableStatusCodes: ['UNAVAILABLE'] } }] };
      return new grpc.Client(endpoint, credentials, { ...options, 'grpc.service_config': JSON.stringify(service) });
    };
    const result = await runUnary(spec('BeginTransaction', { database, options: { readWrite: {} } }), factory);
    assert.equal(factories, 1);
    assert.equal(result.code, 14);
    assert.equal(received.length, 1);
  });
});

test('deadline is indeterminate and cancels the single accepted call', async () => {
  await fixture({ BeginTransaction: () => {} }, async (spec, received) => {
    const result = await runUnary(spec('BeginTransaction', { database, options: { readWrite: {} } }, 100));
    assert.equal(result.complete, false);
    assert.equal(result.code, 4);
    assert.equal(received.length, 1);
  });
});

test('definitive application refusal retains raw details without a fabricated response', async () => {
  await fixture({ BeginTransaction: (_call, done) => done({ code: grpc.status.INVALID_ARGUMENT, details: 'Cannot retry a read-only transaction' }) }, async spec => {
    const result = await runUnary(spec('BeginTransaction', { database, options: { readWrite: { retryTransaction: token } } }));
    assert.equal(result.complete, true);
    assert.equal(result.code, 3);
    assert.equal(result.details, 'Cannot retry a read-only transaction');
    assert.equal(result.response, null);
  });
});

test('scope, schemas, bytes and credentials fail before the server receives a call', async () => {
  await fixture({ GetDocument: (_call, done) => done(null, {}) }, async (spec, received) => {
    const base = spec('GetDocument', { name });
    for (const changes of [
      { projectId: 'fireemu-oracle-idp' },
      { target: { kind: 'local', host: 'localhost', port: base.target.port } },
      { request: { name: `${database}/documents/foreign/doc` } },
      { request: { name, transaction: 'not-base64' } },
      { request: { name, extra: true } },
      { method: 'ListDocuments' },
      { bearer: 'owner\nAuthorization: injected' },
      { deadlineMs: 10001 },
    ]) await assert.rejects(runUnary({ ...base, ...changes }));
    assert.equal(received.length, 0);
  });
});

test('descriptor loading never initializes GAPIC or ADC', async () => {
  const { v1: { FirestoreClient } } = require('@google-cloud/firestore');
  const original = FirestoreClient.prototype.initialize;
  FirestoreClient.prototype.initialize = () => { throw new Error('ADC/GAPIC is forbidden'); };
  try {
    await fixture({ Rollback: (_call, done) => done(null, {}) }, async spec => {
      assert.equal((await runUnary(spec('Rollback', { database, transaction: token }))).code, 0);
    });
  } finally { FirestoreClient.prototype.initialize = original; }
});
