import assert from 'node:assert/strict';
import { test } from 'node:test';

const database = 'projects/demo-p10b/databases/(default)';
const nonce = 'a'.repeat(32);
const ownerId = 'b'.repeat(32);
const name = `${database}/documents/oracle/${nonce}/txn-p10b/control`;
const token = Buffer.from('issued-token').toString('base64');
const module = () => import('./txn_boundary_grpc_transport.mjs');
const spec = (method, request) => ({ kind: 'txn-p10b-grpc-call-v1', target: { kind: 'local', host: '127.0.0.1', port: 12345 }, projectId: 'demo-p10b', nonce, ownerId, method, request, bearer: 'owner', deadlineMs: 1000 });
const update = state => ({ database, writes: [{ update: { name, fields: Object.fromEntries(Object.entries({ owner: ownerId, nonce, role: 'control', state }).map(([key, value]) => [key, { stringValue: value }])) }, currentDocument: { exists: true } }], transaction: token });

test('only the seven P10-C boundary marker states and exact B resource are admitted', async () => {
  const { validateCall } = await module();
  for (const state of ['created', ...[75, 80, 90, 100, 110, 120].map(seconds => `accepted-idle-${seconds}`)]) validateCall(spec('Commit', update(state)));
  for (const state of ['committed-before-idle', 'after-get-first', 'accepted-idle-65', 'accepted-idle-70', 'accepted-idle-74', 'accepted-idle-121']) assert.throws(() => validateCall(spec('Commit', update(state))));
  const wrong = update('created'); wrong.writes[0].update.name = name.replace('txn-p10b', 'txn-p10');
  assert.throws(() => validateCall(spec('Commit', wrong)));
});

test('BeginTransaction is fresh and refuses retry or another mode before dispatch', async () => {
  const { validateCall } = await module();
  validateCall(spec('BeginTransaction', { database, options: { readWrite: {} } }));
  for (const options of [{ readWrite: { retryTransaction: token } }, { readOnly: {} }, { readWrite: {}, readOnly: {} }, { readWrite: { extra: true } }]) assert.throws(() => validateCall(spec('BeginTransaction', { database, options })));
});

test('owned update, native version delete and finite unary methods are required', async () => {
  const { validateCall } = await module();
  validateCall(spec('DeleteDocument', { name, currentDocument: { updateTime: { seconds: '1788004860', nanos: 123 } } }));
  for (const change of ['owner', 'nonce', 'role', 'extra', 'precondition', 'writes']) {
    const body = update('accepted-idle-75');
    if (['owner', 'nonce', 'role'].includes(change)) body.writes[0].update.fields[change].stringValue = 'foreign';
    else if (change === 'extra') body.writes[0].update.fields.extra = { stringValue: 'foreign' };
    else if (change === 'precondition') delete body.writes[0].currentDocument;
    else body.writes.push(body.writes[0]);
    assert.throws(() => validateCall(spec('Commit', body)));
  }
  for (const currentDocument of [{}, { exists: true }, { updateTime: { seconds: '1788004860', nanos: -1 } }]) assert.throws(() => validateCall(spec('DeleteDocument', { name, currentDocument })));
  assert.throws(() => validateCall(spec('ListDocuments', { name })));
});

test('protocol, project, token, credential and deadline changes are rejected', async () => {
  const { validateCall } = await module();
  const base = spec('GetDocument', { name });
  for (const changes of [
    { kind: 'txn-p10-grpc-call-v1' }, { projectId: 'fireemu-oracle-idp' },
    { target: { kind: 'local', host: 'localhost', port: 12345 } },
    { request: { name, transaction: 'bad-token' } }, { request: { name, extra: true } },
    { bearer: 'owner\nAuthorization: injected' }, { deadlineMs: 0 }, { deadlineMs: 10001 },
  ]) assert.throws(() => validateCall({ ...base, ...changes }));
});

test('one unary attempt disables retries and retains the raw native refusal', async () => {
  const { runUnary } = await module();
  let calls = 0; let closes = 0;
  const factory = (_endpoint, _credentials, options) => {
    assert.equal(options['grpc.enable_retries'], 0);
    assert.equal(options['grpc.max_send_message_length'], 16384);
    assert.equal(options['grpc.max_receive_message_length'], 65536);
    return {
      makeUnaryRequest(path, serialize, _deserialize, request, metadata, callOptions, callback) {
        calls += 1;
        assert.equal(path, '/google.firestore.v1.Firestore/Commit');
        assert.ok(serialize(request).length > 0);
        assert.deepEqual(metadata.get('authorization'), ['Bearer owner']);
        assert.ok(callOptions.deadline instanceof Date);
        queueMicrotask(() => callback({ code: 10, details: 'native refusal' }));
        return { cancel() {} };
      },
      close() { closes += 1; },
    };
  };
  const result = await runUnary(spec('Commit', update('accepted-idle-75')), factory);
  assert.deepEqual(result, { kind: 'txn-p10b-grpc-receipt-v1', complete: true, code: 10, details: 'native refusal', response: null, dispatchedRequests: 1 });
  assert.equal(calls, 1); assert.equal(closes, 1);
});

test('unknown results remain incomplete and credential text is redacted', async () => {
  const { runUnary } = await module();
  let calls = 0;
  const factory = () => ({ makeUnaryRequest(_path, _serialize, _deserialize, _request, _metadata, _options, callback) {
    calls += 1; queueMicrotask(() => callback({ code: 14, details: 'owner was unavailable' })); return { cancel() {} };
  }, close() {} });
  const result = await runUnary(spec('Rollback', { database, transaction: token }), factory);
  assert.equal(result.code, 14); assert.equal(result.complete, false);
  assert.equal(result.details, '[credential-redacted] was unavailable'); assert.equal(calls, 1);
});

test('invalid retry never reaches even the local factory', async () => {
  const { runUnary } = await module();
  let factories = 0;
  await assert.rejects(runUnary(spec('BeginTransaction', { database, options: { readWrite: { retryTransaction: token } } }), () => { factories += 1; throw new Error('must not dispatch'); }));
  assert.equal(factories, 0);
});
