import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import {
  buildUnaryRequest,
  classifyTerminal,
  databaseName,
  documentName,
  listWriteFrames,
  runWrite,
  runUnary,
  validateTransportOptions,
  validateWriteRequest,
} from './stream_node_transport.mjs';

const requireSdk = createRequire(new URL('../../sdk-smoke/package.json', import.meta.url));
const grpc = requireSdk('@grpc/grpc-js');
const { FirestoreClient } = requireSdk('@google-cloud/firestore').v1;

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
  assert.throws(() => validateTransportOptions({ ...options, metadata: { Authorization: 'Bearer owner' } }), /metadata/);
});

test('refuses unary reads outside the owned document prefix', () => {
  assert.throws(() => buildUnaryRequest('GetDocument', options, { path: 'compat/other/doc' }), /owned prefix/);
  for (const path of ['compat/o3/../other/doc', 'compat/o3//doc', 'compat/o3/./doc']) {
    assert.throws(() => buildUnaryRequest('GetDocument', options, { path }), /invalid path segment|relative path/);
  }
});

test('rejects traversal and duplicate segments in owned prefixes and write targets', () => {
  assert.throws(() => validateWriteRequest({}, { ...options, projectId: 'x' }), /projectId/);
  for (const documentPrefix of ['compat/../o3', 'compat//o3', 'compat/./o3']) {
    assert.throws(() => validateTransportOptions({ ...options, documentPrefix }), /invalid path segment|relative path/);
  }
  const otherProject = documentName('other-project', 'compat/o3/doc');
  const traversal = documentName(options.projectId, 'compat/o3/../other/doc');
  const duplicate = documentName(options.projectId, 'compat/o3//doc');
  for (const target of [otherProject, traversal, duplicate]) {
    assert.throws(() => validateWriteRequest({ writes: [{ delete: target }] }, options), /outside the owned prefix|invalid path segment|relative path/);
  }
});

test('refuses caller overrides of transport-owned request fields', () => {
  assert.throws(() => buildUnaryRequest('BeginTransaction', options, { database: 'projects/other/databases/(default)' }), /cannot be supplied/);
  assert.throws(() => buildUnaryRequest('GetDocument', options, { path: 'compat/o3/doc', name: 'projects/other/databases/(default)/documents/x' }), /cannot be supplied/);
  assert.throws(() => buildUnaryRequest('Rollback', options, { database: 'projects/other/databases/(default)' }), /cannot be supplied/);
});

test('feeds only the freshest server stream token into the next write frame', () => {
  const response = { streamToken: Buffer.from('fresh-token') };
  assert.deepEqual(listWriteFrames([{ writes: [{ delete: documentName(options.projectId, 'compat/o3/doc') }] }], response), [
    { streamToken: response.streamToken, writes: [{ delete: documentName(options.projectId, 'compat/o3/doc') }] },
  ]);
  assert.throws(() => listWriteFrames([{ streamToken: Buffer.from('caller-token') }], response), /transport-owned/);
  assert.throws(() => listWriteFrames([{ database: 'projects/other/databases/(default)' }], response), /transport-owned/);
});

test('waits for status after error and close, and keeps terminal values serializable', () => {
  const error = Object.assign(new Error('permission denied'), { code: 7, details: 'denied' });
  assert.equal(classifyTerminal({ error, sawClose: true, sawEnd: false }), undefined);
  const receipt = classifyTerminal({ error, status: { code: 7, details: 'denied' }, sawClose: true, sawEnd: false });
  assert.equal(receipt.kind, 'grpc_status');
  assert.equal(receipt.status.code, 7);
  assert.deepEqual(receipt.error, { name: 'Error', code: 7, details: 'denied', message: 'permission denied' });
  assert.match(JSON.stringify({ error: receipt.error }), /permission denied/);
});

test('classifies an accepted unanswered local RPC as an incomplete client deadline', async () => {
  let accepted = false;
  let server;
  let descriptorClient;
  try {
    server = new grpc.Server();
    descriptorClient = new FirestoreClient({
      servicePath: '127.0.0.1',
      port: 1,
      projectId: options.projectId,
      sslCreds: grpc.credentials.createInsecure(),
      fallback: false,
    });
    server.addService({
      GetDocument: descriptorClient._protos.google.firestore.v1.Firestore.service.GetDocument,
    }, {
      GetDocument: () => {
        accepted = true;
      },
    });
    const port = await new Promise((resolve, reject) => {
      server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, boundPort) => {
        if (error) reject(error);
        else {
          server.start();
          resolve(boundPort);
        }
      });
    });
    const receipt = await runUnary('GetDocument', { ...options, port, deadlineMs: 1_000 }, { path: 'compat/o3/doc' });
    assert.equal(accepted, true);
    assert.equal(receipt.kind, 'client_deadline');
    assert.equal(receipt.complete, false);
  } finally {
    server?.forceShutdown();
    descriptorClient?.close();
  }
});

test('cancels a bounded Write stream at the client deadline', async () => {
  const receipt = await runWrite([], { ...options, port: 1, deadlineMs: 100 });
  assert.ok(receipt.kind === 'client_deadline' || receipt.kind === 'grpc_status');
  if (receipt.kind === 'client_deadline') assert.equal(receipt.complete, false);
  else assert.equal(typeof receipt.status.code, 'number');
  assert.ok(receipt.events.some(event => event.type === 'error' || event.type === 'close'));
});

test('runs the local fireemu handshake, write, readback, transaction, and rollback', { skip: !process.env.FIREEMU_LIVE_PORT }, async () => {
  const liveOptions = { ...options, port: Number(process.env.FIREEMU_LIVE_PORT), metadata: { authorization: 'Bearer owner' } };
  const path = 'compat/o3/live/doc';
  const begin = await runUnary('BeginTransaction', liveOptions, { options: { readWrite: {} } });
  assert.equal(begin.kind, 'grpc_status');
  assert.equal(begin.complete, true);
  const write = await runWrite([{
    writes: [{ update: {
      name: documentName(liveOptions.projectId, path),
      fields: { value: { stringValue: 'local' } },
    } }],
  }], liveOptions);
  assert.equal(write.kind, 'grpc_status');
  assert.equal(write.complete, true);
  assert.ok(write.events.some(event => event.type === 'status'));
  const read = await runUnary('GetDocument', liveOptions, { path });
  assert.equal(read.kind, 'grpc_status');
  assert.equal(read.complete, true);
  assert.equal(read.response.fields.value.stringValue, 'local');
  const rollback = await runUnary('Rollback', liveOptions, { transaction: begin.response.transaction });
  assert.equal(rollback.kind, 'grpc_status');
  assert.equal(rollback.complete, true);
});
