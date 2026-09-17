import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyCollectorOutcome,
  collectWithApi,
  collectorPaths,
  isOwnedDocument,
  validateCollectorOptions,
} from './stream_collector.mjs';
import { buildUnaryRequest, documentName } from './stream_node_transport.mjs';

const options = {
  host: '127.0.0.1',
  port: 8080,
  projectId: 'fireemu-test',
  documentPrefix: 'compat/o3/nonce',
  nonce: 'nonce-12345678',
};

const ownerId = 'fresh-owner-12345678';
const fields = (owner, role, value) => ({
  owner: { stringValue: `o3-stream:${owner}` },
  role: { stringValue: role },
  ...(value === undefined ? {} : { value: { stringValue: value } }),
});
const doc = (path, owner, role, value = 'before') => ({
  name: documentName(options.projectId, path),
  fields: fields(owner, role, value),
  updateTime: { seconds: '1', nanos: 0 },
});
const absent = () => ({ kind: 'grpc_status', complete: true, operation: 'GetDocument', status: { code: 5 }, error: { code: 5, message: 'NOT_FOUND' } });
const unaryDoc = value => ({ kind: 'grpc_status', complete: true, operation: 'GetDocument', response: value });
const writeReceipt = (status = 0, updateTime = { seconds: '1', nanos: 0 }) => ({
  kind: 'grpc_status', complete: true, status: { code: status }, sentFrames: 2, receivedFrames: 2,
  events: [{ type: 'data', value: { writeResults: [{ updateTime }] } }, { type: 'status', value: { code: status } }],
});

test('validates a finite loopback collector budget', () => {
  assert.deepEqual(validateCollectorOptions(options), {
    ...options,
    deadlineMs: 30_000,
    maxFrames: 32,
    maxMessageBytes: 1_048_576,
    metadata: {},
  });
  assert.deepEqual(collectorPaths(options), {
    locked: 'compat/o3/nonce/locked',
    control: 'compat/o3/nonce/control',
    suffix: 'compat/o3/nonce/contended-tail',
  });
});

for (const [label, change] of [
  ['rejects a remote host', { host: 'firestore.googleapis.com' }],
  ['rejects an unbounded frame budget', { maxFrames: 257 }],
  ['rejects a traversal prefix', { documentPrefix: 'compat/../outside' }],
  ['rejects a short nonce', { nonce: 'short' }],
]) {
  test(label, () => assert.throws(() => validateCollectorOptions({ ...options, ...change }), /invalid|loopback|frames|relative|nonce/i));
}

test('requires the exact owner marker and a server update time', () => {
  const document = {
    fields: {
      owner: { stringValue: 'o3-stream:nonce-12345678' },
      role: { stringValue: 'control' },
    },
    updateTime: '2026-09-17T00:00:00Z',
  };
  assert.equal(isOwnedDocument(document, options.nonce, 'control'), true);
  assert.equal(isOwnedDocument({ ...document, updateTime: undefined }, options.nonce, 'control'), false);
  assert.equal(isOwnedDocument({ ...document, fields: { ...document.fields, owner: { stringValue: 'foreign' } } }, options.nonce, 'control'), false);
  assert.equal(isOwnedDocument(document, options.nonce, 'locked'), false);
});

test('encodes a transaction on the GetDocument top level', () => {
  const transaction = Buffer.from('transaction-token');
  assert.deepEqual(buildUnaryRequest('GetDocument', options, {
    path: 'compat/o3/nonce/locked',
    transaction,
  }), {
    name: documentName(options.projectId, 'compat/o3/nonce/locked'),
    transaction,
  });
});

test('keeps transport completion separate from semantic contention observations', () => {
  const outcome = classifyCollectorOutcome({
    contention: { complete: true, status: { code: 10 } },
    readback: { complete: true, lockedUnchanged: true, suffixAbsent: true, postRollbackWriteAccepted: true },
    cleanup: { complete: true },
    absence: [{ complete: true, absent: true }],
  });
  assert.equal(outcome.complete, true);
  assert.deepEqual(outcome.semantic, {
    contentionAborted: true,
    lockedUnchanged: true,
    suffixAbsent: true,
    postRollbackWriteAccepted: true,
    cleanupAbsent: true,
  });
});

test('records a complete API error as an observation without treating it as incomplete transport', () => {
  const outcome = classifyCollectorOutcome({
    contention: { complete: true, status: { code: 9 } },
    readback: { complete: true, lockedUnchanged: false, suffixAbsent: false, postRollbackWriteAccepted: true },
    cleanup: { complete: true },
    absence: [{ complete: true, absent: true }],
  });
  assert.equal(outcome.complete, true);
  assert.equal(outcome.semantic.contentionAborted, false);
});

test('does not delete a pre-existing candidate when the caller reuses a nonce', async () => {
  let writes = 0;
  const api = {
    runWrite: async () => { writes += 1; return writeReceipt(); },
    runUnary: async (operation, _options, input) => operation === 'GetDocument'
      ? unaryDoc(doc(input.path, 'old-owner-12345678', input.path.endsWith('locked') ? 'locked' : 'control'))
      : { kind: 'grpc_status', complete: true, response: { transaction: Buffer.from('txn') } },
  };
  const result = await collectWithApi(options, api, ownerId);
  assert.equal(writes, 0);
  assert.equal(result.cleanup.length, 0);
  assert.match(result.failure.message, /preflight/);
});

test('recovers an ambiguous setup write only for the fresh owner marker', async () => {
  let writes = 0;
  let controlReads = 0;
  const api = {
    runWrite: async () => {
      writes += 1;
      return writes === 1 ? { kind: 'client_deadline', complete: false, error: { code: 'client_deadline' } } : writeReceipt();
    },
    runUnary: async (operation, _options, input) => {
      if (operation !== 'GetDocument') return { kind: 'grpc_status', complete: true, response: { transaction: Buffer.from('txn') } };
      if (input.path.endsWith('control')) {
        controlReads += 1;
        return controlReads === 1 ? absent() : controlReads === 2 ? unaryDoc(doc(input.path, ownerId, 'control')) : absent();
      }
      return absent();
    },
  };
  const result = await collectWithApi(options, api, ownerId);
  assert.equal(writes, 2);
  assert.equal(result.cleanup.find(item => item.path.endsWith('control')).ownedRead?.response?.name, documentName(options.projectId, `${options.documentPrefix}/control`));
  assert.equal(result.cleanup.find(item => item.path.endsWith('control')).absent, true);
  assert.equal(result.observations.some(item => item.phase === 'positive-uncontended-stream'), false);
});

test('allows cleanup after a failed rollback retry proves release', async () => {
  let writes = 0;
  let rollbacks = 0;
  let controlReads = 0;
  let lockedReads = 0;
  const api = {
    runWrite: async () => {
      writes += 1;
      return writeReceipt(writes === 4 ? 10 : 0);
    },
    runUnary: async (operation, _options, input) => {
      if (operation === 'BeginTransaction') return { kind: 'grpc_status', complete: true, response: { transaction: Buffer.from('txn') } };
      if (operation === 'Rollback') {
        rollbacks += 1;
        return rollbacks === 1 ? { kind: 'grpc_status', complete: true, status: { code: 10 } } : { kind: 'grpc_status', complete: true, response: {} };
      }
      if (input.path.endsWith('contended-tail')) return absent();
      if (input.path.endsWith('control')) {
        controlReads += 1;
        return controlReads === 1 || controlReads >= 4 ? absent() : unaryDoc(doc(input.path, ownerId, 'control', 'accepted'));
      }
      lockedReads += 1;
      if (input.transaction || lockedReads === 2 || lockedReads === 3) return unaryDoc(doc(input.path, ownerId, 'locked', 'before'));
      return absent();
    },
  };
  const result = await collectWithApi(options, api, ownerId);
  assert.equal(rollbacks, 2);
  assert.ok(result.observations.some(item => item.phase === 'rollback-finally'));
  assert.ok(result.cleanup.every(item => item.absent === true));
});

test('live collection is opt-in and uses the actual local transport when enabled', { skip: !process.env.FIREEMU_LIVE_PORT }, async () => {
  const { collect } = await import('./stream_collector.mjs');
  const result = await collect({
    ...options,
    port: Number(process.env.FIREEMU_LIVE_PORT),
    metadata: { authorization: 'Bearer owner' },
  });
  assert.ok(Array.isArray(result.observations));
  assert.ok(result.observations.some(item => item.phase === 'contended-multiwrite-stream'));
  assert.ok(result.observations.some(item => item.phase === 'cleanup'));
});
