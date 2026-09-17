import test from 'node:test';
import assert from 'node:assert/strict';
import { compareStreamReceipts } from './stream_comparison.mjs';

const contract = {
  version: 1,
  projectId: 'fireemu-test',
  database: 'projects/fireemu-test/databases/(default)',
  documentPrefix: 'compat/o3/run-fixed',
  resources: [
    { path: 'compat/o3/run-fixed/control', role: 'control' },
    { path: 'compat/o3/run-fixed/locked', role: 'locked' },
    { path: 'compat/o3/run-fixed/contended-tail', role: 'suffix' },
  ],
  maxRpc: 24,
  maxFramesPerRpc: 32,
};

const phases = [
  ['preflight-create-absence', 'GetDocument'], ['preflight-create-absence', 'GetDocument'],
  ['setup-control', 'Write'], ['setup-locked', 'Write'], ['positive-uncontended-stream', 'Write'],
  ['readback-control', 'GetDocument'], ['begin-rw-transaction', 'BeginTransaction'],
  ['get-locked-with-transaction', 'GetDocument'], ['preflight-suffix-absence', 'GetDocument'],
  ['contended-multiwrite-stream', 'Write'], ['readback-contention', 'GetDocument'],
  ['rollback', 'Rollback'], ['post-rollback-positive-stream', 'Write'],
  ['readback-post-rollback', 'GetDocument'], ['cleanup', 'Write'],
];

const timestamp = value => ({ seconds: String(value), nanos: 0 });
const streamToken = value => ({ type: 'Buffer', data: [0, 0, 0, value] });
const transaction = value => ({ type: 'Buffer', data: [value, 1, 2, 3] });
const frame = (database, writes, token) => ({ database, ...(token ? { streamToken: token } : {}), ...(writes ? { writes } : {}) });
const name = path => `${contract.database}/documents/${path}`;
const fields = (owner, role, value) => ({ owner: { stringValue: `o3-stream:${owner}` }, role: { stringValue: role }, ...(value ? { value: { stringValue: value } } : {}) });
const doc = (path, owner, role, value, updateTime = 100) => ({ name: name(path), fields: fields(owner, role, value), updateTime: timestamp(updateTime) });
const status = code => ({ code, details: code === 0 ? '' : 'unexpected' });
const unary = (operation, request, response, code = 0) => ({ kind: 'grpc_status', operation, request, complete: true, ...(response ? { response } : {}), ...(code === 0 ? {} : { status: status(code), error: { code } }) });
const write = (writes, token, code = 0, moved = false) => {
  const responseToken = streamToken(token + 1);
  return {
    transportReceiptVersion: 2, kind: 'grpc_status', complete: true, status: status(code), sentFrames: 2, completedSendFrames: 2, receivedFrames: 2,
    events: [
      { type: 'send', value: frame(contract.database) },
      { type: 'data', value: { writeResults: [], streamToken: streamToken(token), streamId: `stream-${token}` } },
      { type: 'send', value: frame(contract.database, writes, streamToken(token)) },
      { type: 'data', value: { writeResults: [{ updateTime: moved ? timestamp(999) : timestamp(100 + token) }], streamToken: responseToken } },
      { type: 'status', value: status(code) },
      { type: code === 0 ? 'end' : 'close', value: { status: status(code) } },
    ],
  };
};
const deleteReceipt = (path, token) => write([{ delete: name(path), currentDocument: { updateTime: timestamp(105) } }], token);

const update = (path, owner, role, value, currentDocument) => ({ update: { name: name(path), fields: fields(owner, role, value) }, ...(currentDocument ? { currentDocument } : {}) });
const absent = path => unary('GetDocument', { name: name(path) }, undefined, 5);

const makeReceipt = ({ owner = 'owner-a', moved = false, old = false, omitSend = false, unexpected = false } = {}) => {
  const control = 'compat/o3/run-fixed/control';
  const locked = 'compat/o3/run-fixed/locked';
  const suffix = 'compat/o3/run-fixed/contended-tail';
  const ownerId = old ? 'old-owner' : owner;
  const observations = [];
  const add = (phase, receipt, extra = {}) => observations.push({ phase, receipt, complete: receipt.complete, ...extra });
  add('preflight-create-absence', absent(control));
  add('preflight-create-absence', absent(locked));
  const setupControl = write([update(control, ownerId, 'control', undefined, { exists: false })], 1);
  const setupLocked = write([update(locked, ownerId, 'locked', 'before', { exists: false })], 2);
  const positive = write([update(control, ownerId, 'control', 'accepted')], 3);
  const strip = receipt => omitSend ? { ...receipt, events: receipt.events.filter(event => event.type !== 'send') } : receipt;
  add('setup-control', strip(setupControl)); add('setup-locked', strip(setupLocked)); add('positive-uncontended-stream', strip(positive));
  add('readback-control', unary('GetDocument', { name: name(control) }, doc(control, ownerId, 'control', 'accepted', 103)));
  const beginToken = transaction(9);
  add('begin-rw-transaction', unary('BeginTransaction', { database: contract.database, options: { readWrite: {} } }, { transaction: beginToken }));
  add('get-locked-with-transaction', unary('GetDocument', { name: name(locked), transaction: beginToken }, doc(locked, ownerId, 'locked', 'before', 102)));
  add('preflight-suffix-absence', absent(suffix));
  const contention = write([
    update(locked, ownerId, 'locked', 'must-not-commit'),
    update(suffix, ownerId, 'suffix', 'must-not-commit', { exists: false }),
  ], 4, unexpected ? 0 : 10, moved);
  add('contended-multiwrite-stream', strip(contention));
  add('readback-contention', unary('GetDocument', { name: name(locked) }, doc(locked, ownerId, 'locked', moved ? 'must-not-commit' : 'before', 104)));
  add('rollback', unary('Rollback', { database: contract.database, transaction: beginToken }, {}));
  add('post-rollback-positive-stream', strip(write([update(locked, ownerId, 'locked', 'after-rollback')], 5)));
  add('readback-post-rollback', unary('GetDocument', { name: name(locked) }, doc(locked, ownerId, 'locked', 'after-rollback', 105)));
  const cleanup = [control, locked, suffix].map((path, index) => ({ path, skipped: path === suffix, complete: true, absent: true, receipt: path === suffix ? absent(path) : deleteReceipt(path, 6 + index), absence: absent(path) }));
  add('cleanup', { kind: 'grpc_status', complete: true, status: status(0), events: [], sentFrames: 0, receivedFrames: 0 }, { cleanup });
  return { observations, cleanup, ownerId, readback: { complete: true }, contention: observations[9].receipt };
};

test('accepts two complete receipts with opaque token and timestamp normalization', () => {
  const result = compareStreamReceipts({ production: makeReceipt({ owner: 'prod-owner' }), local: makeReceipt({ owner: 'local-owner' }), expected: contract });
  assert.equal(result.classification, 'EXPECTED_NONDETERMINISM');
  assert.equal(result.acquisitionValidated, false);
  assert.equal(result.promotionReady, false);
});

test('binds production and local resource identities independently', () => {
  const result = compareStreamReceipts({
    production: makeReceipt({ owner: 'prod-owner' }),
    local: makeReceipt({ owner: 'local-owner' }),
    expected: {
      version: 1,
      production: { projectId: 'fireemu-test', documentPrefix: 'compat/o3/run-fixed' },
      local: { projectId: 'fireemu-test', documentPrefix: 'compat/o3/run-fixed' },
      resources: [{ path: 'control', role: 'control' }, { path: 'locked', role: 'locked' }, { path: 'contended-tail', role: 'suffix' }],
    },
  });
  assert.equal(result.classification, 'EXPECTED_NONDETERMINISM');
});

test('matches an identical complete receipt', () => {
  const receipt = makeReceipt();
  const result = compareStreamReceipts({ production: receipt, local: structuredClone(receipt), expected: contract });
  assert.equal(result.classification, 'MATCH');
});

test('returns indeterminate when the historical receipt lacks outgoing send facts', () => {
  const result = compareStreamReceipts({ production: makeReceipt({ omitSend: true }), local: makeReceipt(), expected: contract });
  assert.equal(result.classification, 'INDETERMINATE');
});

test('returns semantic mismatch for complete unexpected contention and moved poststate', () => {
  const result = compareStreamReceipts({ production: makeReceipt(), local: makeReceipt({ unexpected: true, moved: true }), expected: contract });
  assert.equal(result.classification, 'SEMANTIC_MISMATCH');
});

test('rejects a stale stream version as indeterminate evidence', () => {
  const local = makeReceipt();
  const request = local.observations.find(item => item.phase === 'setup-control').receipt.events.find(event => event.type === 'send' && event.value.writes)?.value;
  request.streamToken = streamToken(99);
  const result = compareStreamReceipts({ production: makeReceipt(), local, expected: contract });
  assert.equal(result.classification, 'INDETERMINATE');
});

test('rejects a foreign cleanup owner marker as indeterminate evidence', () => {
  const local = makeReceipt();
  local.cleanup[0].ownedRead = doc('compat/o3/run-fixed/control', 'foreign-owner', 'control', 'accepted');
  const result = compareStreamReceipts({ production: makeReceipt(), local, expected: contract });
  assert.equal(result.classification, 'INDETERMINATE');
});

test('rejects a partial stream even when its peer is complete', () => {
  const local = makeReceipt();
  local.observations.find(item => item.phase === 'positive-uncontended-stream').receipt.complete = false;
  const result = compareStreamReceipts({ production: makeReceipt(), local, expected: contract });
  assert.equal(result.classification, 'INDETERMINATE');
});

test('rejects a transaction token sequence that does not reach rollback', () => {
  const local = makeReceipt();
  local.observations.find(item => item.phase === 'rollback').receipt.request.transaction = transaction(88);
  const result = compareStreamReceipts({ production: makeReceipt(), local, expected: contract });
  assert.equal(result.classification, 'INDETERMINATE');
});
