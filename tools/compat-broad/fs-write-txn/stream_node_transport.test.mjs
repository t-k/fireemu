import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildUnaryRequest,
  databaseName,
  documentName,
  validateTransportOptions,
} from './stream_node_transport.mjs';

const options = {
  host: '127.0.0.1',
  port: 8080,
  projectId: 'fireemu-test',
  documentPrefix: 'compat/o3',
};

test('accepts bounded explicit loopback transport options', () => {
  assert.deepEqual(validateTransportOptions(options), {
    ...options,
    deadlineMs: 10_000,
    maxFrames: 32,
    maxMessageBytes: 1_048_576,
    metadata: {},
  });
});

for (const [name, change] of [
  ['rejects a remote endpoint', { host: 'firestore.googleapis.com' }],
  ['rejects a missing port', { port: undefined }],
  ['rejects an unbounded frame limit', { maxFrames: 257 }],
  ['rejects an absolute document prefix', { documentPrefix: '/compat/o3' }],
]) {
  test(name, () => assert.throws(() => validateTransportOptions({ ...options, ...change }), /invalid|loopback|port|frames|prefix/i));
}

test('builds explicit unary Firestore requests', () => {
  assert.equal(databaseName(options.projectId), 'projects/fireemu-test/databases/(default)');
  assert.equal(documentName(options.projectId, 'compat/o3/doc'), 'projects/fireemu-test/databases/(default)/documents/compat/o3/doc');
  assert.deepEqual(buildUnaryRequest('BeginTransaction', options, { options: { readWrite: {} } }), {
    database: databaseName(options.projectId),
    options: { readWrite: {} },
  });
  assert.deepEqual(buildUnaryRequest('GetDocument', options, { path: 'compat/o3/doc' }), {
    name: documentName(options.projectId, 'compat/o3/doc'),
  });
  assert.deepEqual(buildUnaryRequest('Rollback', options, { transaction: Buffer.from('txn') }), {
    database: databaseName(options.projectId),
    transaction: Buffer.from('txn'),
  });
});

test('accepts explicit local metadata without consulting environment credentials', () => {
  const validated = validateTransportOptions({ ...options, metadata: { authorization: 'Bearer owner' } });
  assert.deepEqual(validated.metadata, { authorization: 'Bearer owner' });
});

test('refuses unary reads outside the owned document prefix', () => {
  assert.throws(() => buildUnaryRequest('GetDocument', options, { path: 'compat/other/doc' }), /owned prefix/);
});
