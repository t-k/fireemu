import test from 'node:test';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { localTarget, rpcRecorder, recordAdminRetries, projectAdminReceipt, compareAdminReceipts } from './admin_sdk_retry.mjs';

const require = createRequire(new URL('../../../conformance/package.json', import.meta.url));
const grpc = require('@grpc/grpc-js');
import { runtimeInfo } from './txn_program_transport.mjs';

test('local admission rejects remote hosts, malformed ports and non-demo projects', () => {
  assert.deepEqual(localTarget('127.0.0.1:1234', 'demo-admin-retry'), { host: '127.0.0.1', port: 1234 });
  for (const host of ['firestore.googleapis.com:443', 'localhost:1234', '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:12x']) {
    assert.throws(() => localTarget(host, 'demo-admin-retry'), /local/);
  }
  assert.throws(() => localTarget('127.0.0.1:1234', 'real-project'), /local/);
});

test('CLI rejects production before SDK construction and refuses output outside target', () => {
  for (const args of [['production', 'target/codex-out/unused.json'], ['local', '/tmp/unused.json']]) {
    const result = spawnSync(process.execPath, [new URL('./admin_sdk_retry.mjs', import.meta.url).pathname, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /local|target/);
  }
});

test('CLI refuses directory and receipt symlinks before creating files', () => {
  const directory = new URL('../../../target/codex-out/s5a-symlink-test/', import.meta.url).pathname;
  mkdirSync(directory, { recursive: true });
  try {
    symlinkSync('../../../tools', directory + 'escape');
    symlinkSync('../s5a-strict.json', directory + 'receipt.json');
    symlinkSync('../../../tools/must-not-create.json', directory + 'dangling.json');
    for (const output of [directory + 'escape/new-directory/receipt.json', directory + 'receipt.json', directory + 'dangling.json']) {
      const result = spawnSync(process.execPath, [new URL('./admin_sdk_retry.mjs', import.meta.url).pathname, 'local', output], { encoding: 'utf8' });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /symlink/);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('interceptor records dispatch order, native bytes and frames without metadata', async () => {
  const recorder = rpcRecorder(grpc);
  recorder.context = { site: 'retry/transaction', caseId: 'retry', attempt: 1, client: 'transaction', phase: 'observation' };
  let message, status;
  const fake = {
    start(_metadata, listener) { this.listener = listener; },
    sendMessageWithContext(_context, value) { message = value; },
  };
  const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/BatchGetDocuments' } }, () => fake);
  call.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus(value) { status = value; } });
  call.sendMessage({ newTransaction: { readWrite: { retryTransaction: Buffer.from('previous') } } });
  fake.listener.onReceiveMessage({ transaction: Buffer.from('current'), found: { name: 'owned' } });
  fake.listener.onReceiveStatus({ code: 0, details: '', metadata: new grpc.Metadata() });
  await recorder.drain();
  assert.ok(Buffer.isBuffer(message.newTransaction.readWrite.retryTransaction));
  assert.equal(status.code, 0);
  assert.equal(recorder.rows.length, 1);
  const row = recorder.rows[0];
  assert.equal(row.sequence, 0);
  assert.equal(row.rpc, 'BatchGetDocuments');
  assert.equal(row.attempt, 1);
  assert.equal(row.outcomeClass, 'OK');
  assert.equal(row.result.kind, 'txn-program-receipt-v1');
  assert.equal(row.result.dispatchedRequests, 1);
  assert.deepEqual(row.result.response, { responses: [{ transaction: 'Y3VycmVudA==', found: { name: 'owned' } }] });
  assert.equal(row.request.newTransaction.readWrite.retryTransaction, 'cHJldmlvdXM=');
  assert.ok(row.timing.responseMonotonic >= row.timing.dispatchMonotonic);
  assert.equal(Object.hasOwn(row.result, 'metadata'), false);
});

test('interceptor captures context at dispatch even when another client finishes first', async () => {
  const recorder = rpcRecorder(grpc);
  const calls = [];
  for (const [attempt, client] of [[1, 'transaction'], [0, 'writer']]) {
    recorder.context = { site: client, attempt, client, phase: 'observation', caseId: 'retry' };
    const fake = { start(_metadata, listener) { this.listener = listener; }, sendMessageWithContext() {} };
    const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Commit' } }, () => fake);
    call.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
    call.sendMessage({ database: 'owned' });
    calls.push(fake);
  }
  calls[1].listener.onReceiveStatus({ code: 0, details: '' });
  calls[0].listener.onReceiveStatus({ code: 14, details: 'unavailable' });
  await recorder.drain();
  assert.deepEqual(recorder.rows.map(row => [row.sequence, row.attempt, row.client, row.outcomeClass]), [[0, 1, 'transaction', 'UNKNOWN'], [1, 0, 'writer', 'OK']]);
});

test('strict rehearsal proves conflict, control, retry lineage, per-attempt state and cleanup', { skip: !process.env.FIRESTORE_EMULATOR_HOST }, async () => {
  const receipt = await recordAdminRetries({ host: process.env.FIRESTORE_EMULATOR_HOST, project: 'demo-admin-retry' });
  writeFileSync(new URL('../../../target/codex-out/s5a-step2/local.receipt.json', import.meta.url), JSON.stringify(receipt) + '\n');
  assert.equal(receipt.kind, 'txn-program-recording-v1');
  assert.equal(receipt.program, 'FS-TRANSACTION-P17-ADMIN-SDK-RETRY');
  assert.equal(receipt.complete, true);
  assert.equal(receipt.graphComplete, true);
  assert.equal(receipt.unrecovered, false);
  assert.deepEqual(receipt.openTokens, []);
  assert.equal(Object.keys(receipt.tokens).length, 8);
  assert.equal(Object.values(receipt.tokens).filter(token => token.state === 'committed').length, 5);
  assert.equal(Object.values(receipt.tokens).filter(token => token.state === 'rolled-back').length, 3);
  assert.equal(Object.values(receipt.tokens).filter(token => token.state === 'released-refused').length, 0);
  assert.deepEqual(receipt.cleanup, { absent: true });
  assert.deepEqual(receipt.phaseRequests, { observation: receipt.steps.length, tokenCleanup: 0, documentCleanup: receipt.cleanupSteps.length, management: 0, credential: 0 });
  assert.equal(receipt.sandboxRequests, receipt.steps.length + receipt.cleanupSteps.length);
  assert.deepEqual([...receipt.steps, ...receipt.cleanupSteps].map(row => row.sequence).sort((a, b) => a - b), Array.from({ length: receipt.sandboxRequests }, (_, i) => i));
  const [conflict, control, retry, older] = receipt.attempts;
  assert.equal(conflict.caseId, 'conflict');
  assert.equal(conflict.callbackCount, 1);
  assert.equal(conflict.refusalCode, 0);
  assert.equal(conflict.finalState.a.state, 'baseline');
  assert.equal(conflict.finalState.b.state, 'transaction-baseline');
  assert.equal(control.caseId, 'control');
  assert.equal(control.callbackCount, 1);
  assert.equal(control.refusalCode, 0);
  assert.equal(control.finalState.a.state, 'baseline');
  assert.equal(control.finalState.b.state, 'transaction-baseline');
  assert.equal(control.finalState.c.state, 'writer');
  assert.equal(retry.caseId, 'retry');
  assert.equal(retry.callbackCount, 1);
  assert.equal(retry.refusalCode, 0);
  assert.deepEqual(retry.attempts.map(attempt => [attempt.callbackCount, attempt.refusalCode, attempt.finalState.b.state]), [[1, 0, 'transaction-baseline']]);
  const firstRead = receipt.steps.find(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.rpc === 'BatchGetDocuments' && row.attempt === 1);
  const nextRead = receipt.steps.find(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.rpc === 'BatchGetDocuments' && row.attempt === 2);
  assert.equal(nextRead.request.newTransaction.readWrite.retryTransaction, firstRead.result.response.responses.find(frame => frame.transaction).transaction);
  assert.equal(older.caseId, 'retry-older');
  assert.equal(older.callbackCount, 2);
  for (const entry of receipt.attempts) {
    for (const attempt of entry.attempts) {
      assert.deepEqual(attempt.rpcSequence, receipt.steps.filter(row => row.caseId === entry.caseId && row.attempt === attempt.callbackCount && row.client === 'transaction').map(row => ({ sequence: row.sequence, rpc: row.rpc, code: row.result.code })));
    }
    if (entry.caseId !== 'control') {
      const read = receipt.steps.find(row => row.caseId === entry.caseId && row.client === 'transaction' && row.rpc === 'BatchGetDocuments');
      const writer = receipt.steps.find(row => row.caseId === entry.caseId && row.client === 'writer' && row.rpc === 'Commit');
      const commit = receipt.steps.find(row => row.caseId === entry.caseId && row.client === 'transaction' && row.rpc === 'Commit');
      assert.ok(read.timing.responseMonotonic <= writer.timing.dispatchMonotonic);
      assert.ok(writer.timing.dispatchMonotonic < commit.timing.dispatchMonotonic);
      assert.equal(writer.result.code, entry.caseId === 'retry-older' ? 0 : 10);
      assert.equal(commit.result.code, entry.caseId === 'retry-older' ? 10 : 0);
    }
  }
  assert.equal(receipt.cleanupSteps.filter(row => row.site.endsWith('/verify')).length, 12);
  assert.ok(receipt.cleanupSteps.filter(row => row.site.endsWith('/verify')).every(row => row.result.code === 0 && row.result.response.responses.every(frame => frame.missing)));
});


test('journal failure blocks dispatch and remains fail closed', () => {
  const recorder = rpcRecorder(grpc);
  let sent = 0, started = 0;
  recorder.journal = () => { throw new Error('journal failed'); };
  const fake = { start() { started++; }, sendMessageWithContext() { sent++; } };
  const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Commit' } }, () => fake);
  call.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
  assert.equal(started, 0);
  assert.throws(() => call.sendMessage({ database: 'owned' }), /journal/);
  recorder.journal = () => {};
  assert.throws(() => call.sendMessage({ database: 'owned' }), /blocked/);
  assert.equal(sent, 0);
  assert.equal(started, 0);
  assert.equal(recorder.journalFailure, true);
});

test('unknown native status is durable and blocks automatic redispatch', async () => {
  const recorder = rpcRecorder(grpc);
  const journal = [];
  recorder.journal = value => journal.push(structuredClone(value));
  const fake = { start(_metadata, listener) { this.listener = listener; }, sendMessageWithContext() {} };
  const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Commit' } }, () => fake);
  call.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
  call.sendMessage({ database: 'owned' });
  fake.listener.onReceiveStatus({ code: 14, details: 'unavailable' });
  await recorder.drain();
  assert.deepEqual(journal.map(value => value.event), ['dispatch', 'status']);
  assert.equal(journal[0].row.result, undefined);
  assert.equal(journal[1].row.outcomeClass, 'UNKNOWN');
  assert.throws(() => call.sendMessage({ database: 'owned' }), /blocked/);
});

test('expired campaign deadline prevents native dispatch', () => {
  const recorder = rpcRecorder(grpc);
  recorder.deadline = -1;
  const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Commit' } }, () => ({ sendMessageWithContext() { assert.fail('must not send'); } }));
  assert.throws(() => call.sendMessage({ database: 'owned' }), /deadline/);
  assert.equal(recorder.rows.length, 0);
});

test('SDK projection compares each attempt and explicitly excludes timing', { skip: !process.env.FIRESTORE_EMULATOR_HOST }, async () => {
  const local = await recordAdminRetries({ host: process.env.FIRESTORE_EMULATOR_HOST, project: 'demo-admin-retry' });
  const production = structuredClone(local);
  production.runtime.target = 'production';
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  const seal = value => { const bound = { ...value }; delete bound.receiptDigest; value.receiptDigest = createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex'); };
  seal(production);
  const comparison = compareAdminReceipts(production, local);
  assert.equal(comparison.mismatches, 0);
  assert.equal(comparison.attempts.length, 5);
  assert.ok(Object.values(comparison.timing).every(value => value === 'NOT_COMPARABLE'));
  const writer = production.steps.find(row => row.caseId === 'control' && row.client === 'writer' && row.rpc === 'Commit');
  writer.result.details = 'changed writer message';
  production.attempts[1].writer.message = writer.result.details;
  production.attempts[1].writer.rpcSequence.find(row => row.rpc === 'Commit').message = writer.result.details;
  seal(production);
  assert.equal(compareAdminReceipts(production, local).mismatches, 1);
  writer.result.details = local.steps.find(row => row.caseId === 'control' && row.client === 'writer' && row.rpc === 'Commit').result.details;
  production.attempts[1].writer.message = writer.result.details;
  production.attempts[1].writer.rpcSequence.find(row => row.rpc === 'Commit').message = writer.result.details;
  seal(production);
  production.attempts[2].attempts[0].refusalMessage = 'changed';
  assert.throws(() => projectAdminReceipt(production), /refusal|digest/);
  production.attempts[2].attempts[0].refusalMessage = local.attempts[2].attempts[0].refusalMessage;
  production.steps.find(row => row.caseId === 'retry' && row.rpc === 'Commit' && row.client === 'transaction').result.details = 'changed';
  production.attempts[2].attempts[0].refusalMessage = 'changed';
  seal(production);
  assert.equal(compareAdminReceipts(production, local).mismatches, 1);
  production.attempts[0].attempts[0].finalState.a.state = 'writer';
  production.attempts[0].finalState.a.state = 'writer';
  seal(production);
  assert.throws(() => projectAdminReceipt(production), /witness/);
  production.attempts[0].attempts[0].finalState.a.state = 'baseline';
  production.attempts[0].finalState.a.state = 'baseline';
  production.unknownCommits.push(1);
  seal(production);
  assert.throws(() => projectAdminReceipt(production), /complete/);
});


test('definite rollback refusal is observed without stopping acquisition', async () => {
  const recorder = rpcRecorder(grpc);
  const fake = { start(_metadata, listener) { this.listener = listener; }, sendMessageWithContext() {} };
  const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Rollback' } }, () => fake);
  call.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
  call.sendMessage({ database: 'owned', transaction: Buffer.from('issued') });
  fake.listener.onReceiveStatus({ code: 10, details: 'another refusal' });
  await recorder.drain();
  assert.equal(recorder.observationStopped, false);
  assert.equal(recorder.blocked, false);
  assert.throws(() => call.sendMessage({ database: 'owned', transaction: Buffer.from('issued') }), /redispatch/);
});

test('partial transaction stream preserves frames and classifies refusal as unknown', async () => {
  const recorder = rpcRecorder(grpc);
  const fake = { start(_metadata, listener) { this.listener = listener; }, sendMessageWithContext() {} };
  const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/BatchGetDocuments' } }, () => fake);
  call.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
  call.sendMessage({ newTransaction: { readWrite: {} } });
  fake.listener.onReceiveMessage({ transaction: Buffer.from('issued') });
  fake.listener.onReceiveStatus({ code: 10, details: 'stream refused' });
  await recorder.drain();
  assert.equal(recorder.rows[0].outcomeClass, 'UNKNOWN');
  assert.equal(recorder.rows[0].frames[0].transaction, Buffer.from('issued').toString('base64'));
  assert.equal(recorder.blocked, true);
});


test('definite refusal stops observation while allowing owned cleanup', async () => {
  const recorder = rpcRecorder(grpc);
  recorder.context = { phase: 'observation', site: 'transaction', client: 'transaction' };
  let sent = 0;
  const fake = { start(_metadata, listener) { this.listener = listener; }, sendMessageWithContext() { sent++; } };
  const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Commit' } }, () => fake);
  call.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
  call.sendMessage({ database: 'owned', writes: [] });
  fake.listener.onReceiveStatus({ code: 9, details: 'definite refusal' });
  await recorder.drain();
  assert.equal(recorder.observationStopped, true);
  assert.equal(recorder.blocked, false);
  recorder.context = { phase: 'documentCleanup', site: 'cleanup', client: 'witness' };
  const cleanup = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Commit' } }, () => fake);
  cleanup.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
  cleanup.sendMessage({ database: 'owned', writes: [{ delete: 'owned-document' }] });
  fake.listener.onReceiveStatus({ code: 0, details: '' });
  await recorder.drain();
  assert.equal(sent, 2);
});

for (const client of ['writer', 'transaction']) {
  test(`${client} ABORTED commit is an observation`, async () => {
    const recorder = rpcRecorder(grpc);
    recorder.context = { client, site: 'retry/transaction', phase: 'observation' };
    const fake = { start(_metadata, listener) { this.listener = listener; }, sendMessageWithContext() {} };
    const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Commit' } }, () => fake);
    const metadata = new grpc.Metadata();
    metadata.set('authorization', 'offline-parent');
    metadata.set('x-goog-user-project', 'fireemu-oracle-txn');
    call.start(metadata, { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
    call.sendMessage({ transaction: Buffer.from('issued') });
    fake.listener.onReceiveStatus({ code: 10, details: 'Too much contention on these documents. Please try again.' });
    await recorder.drain();
    assert.equal(recorder.observationStopped, false);
    assert.equal(recorder.blocked, false);
    assert.deepEqual(recorder.rows[0].metadataKeys, ['authorization', 'x-goog-user-project']);
    assert.equal(recorder.rows[0].quotaProject, 'fireemu-oracle-txn');
    assert.equal(JSON.stringify(recorder.rows).includes('offline-parent'), false);
  });
}

for (const code of [0, 3, 5, 7, 8, 9, 10, 16]) {
  test(`definite Rollback code ${code} never stops observation`, async () => {
    const recorder = rpcRecorder(grpc);
    const fake = { start(_metadata, listener) { this.listener = listener; }, sendMessageWithContext() {} };
    const call = recorder.interceptor({ method_definition: { path: '/google.firestore.v1.Firestore/Rollback' } }, () => fake);
    call.start(new grpc.Metadata(), { onReceiveMetadata() {}, onReceiveMessage() {}, onReceiveStatus() {} });
    call.sendMessage({ transaction: Buffer.from('issued') });
    fake.listener.onReceiveStatus({ code, details: 'Invalid transaction.' });
    await recorder.drain();
    assert.equal(recorder.observationStopped, false);
    assert.equal(recorder.blocked, false);
    assert.equal(recorder.rows[0].result.code, code);
  });
}

for (const outcome of ['writer-aborted', 'writer-late', 'older-retry', 'rollback-invalid', 'rollback-unknown']) {
  test(`local SDK stub observes ${outcome} with native evidence in every case`, async t => {
    const { v1: { FirestoreClient } } = require('@google-cloud/firestore');
    const descriptor = new FirestoreClient({ projectId: 'demo-descriptors' });
    const protos = descriptor._protos;
    const fs = protos.google.firestore.v1;
    const server = new grpc.Server();
    const docs = new Map(), transactions = new Map(), held = new Map();
    let token = 0, tick = 0;
    const timestamp = () => ({ seconds: '1788004860', nanos: ++tick });
    const apply = (request, done) => {
      const time = timestamp();
      for (const write of request.writes) {
        if (write.delete) {
          assert.deepEqual(write.currentDocument.updateTime, docs.get(write.delete).updateTime);
          docs.delete(write.delete);
        } else docs.set(write.update.name, { ...write.update, createTime: time, updateTime: time });
      }
      done(null, { writeResults: request.writes.map(() => ({ updateTime: time })), commitTime: time });
    };
    const handlers = {
      BatchGetDocuments(call) {
        if (call.request.newTransaction) {
          const identity = Buffer.from(`issued-${++token}`);
          transactions.set(identity.toString('base64'), call.request.documents[0]);
          call.write({ transaction: identity, readTime: timestamp() });
        }
        for (const name of call.request.documents) call.write(docs.has(name) ? { found: docs.get(name), readTime: timestamp() } : { missing: name, readTime: timestamp() });
        call.end();
      },
      Commit(call, done) {
        const request = call.request;
        const read = transactions.get(request.transaction?.toString('base64'));
        const caseId = read?.split('/').at(-2);
        const writer = read?.endsWith('/b');
        if (writer) {
          if (outcome === 'writer-aborted' || outcome.startsWith('rollback-')) done({ code: 10, details: 'Too much contention on these documents. Please try again.' });
          else held.set(caseId, () => apply(request, done));
        } else if (read) {
          if (outcome === 'older-retry' && caseId.endsWith('older') && held.has(caseId)) {
            held.get(caseId)(); held.delete(caseId);
            done({ code: 10, details: 'Too much contention on these documents. Please try again.' });
          } else {
            apply(request, done);
            if (held.has(caseId)) { held.get(caseId)(); held.delete(caseId); }
          }
        } else if (['writer-aborted', 'rollback-invalid'].includes(outcome) && request.writes[0].update?.name.endsWith('/txn-p17-control/c') && request.writes[0].update.fields.state?.stringValue === 'writer') done({ code: 10, details: 'Too much contention on these documents. Please try again.' });
        else apply(request, done);
      },
      Rollback(_call, done) {
        if (outcome === 'rollback-invalid') done({ code: 3, details: 'Invalid transaction.' });
        else if (outcome === 'rollback-unknown') done({ code: 14, details: 'offline unavailable' });
        else done(null, {});
      },
    };
    server.addService(Object.fromEntries(Object.keys(handlers).map(method => [method, { path: `/google.firestore.v1.Firestore/${method}`, requestStream: false, responseStream: method === 'BatchGetDocuments', requestSerialize: fs[`${method}Request`].serialize, requestDeserialize: fs[`${method}Request`].deserialize, responseSerialize: (method === 'Rollback' ? protos.google.protobuf.Empty : fs[`${method}Response`]).serialize, responseDeserialize: (method === 'Rollback' ? protos.google.protobuf.Empty : fs[`${method}Response`]).deserialize }])), handlers);
    const port = await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, value) => error ? reject(error) : resolve(value)));
    try {
      const receipt = await recordAdminRetries({ host: `127.0.0.1:${port}`, project: 'demo-admin-retry' });
      const rollbacks = receipt.steps.filter(row => row.rpc === 'Rollback');
      if (rollbacks.length) await t.test(`Rollback code ${rollbacks[0].result.code} records ${outcome === 'rollback-unknown' ? 'open/incomplete' : outcome === 'rollback-invalid' ? 'released-refused' : 'rolled-back'} tokens`, () => {
        for (const row of rollbacks) {
          const token = Object.values(receipt.tokens).find(value => value.value === row.request.transaction);
          assert.ok(token);
          assert.equal(token.state, row.result.code === 0 ? 'rolled-back' : row.result.code === 3 ? 'released-refused' : 'open');
        }
        if (outcome === 'rollback-unknown') assert.equal(receipt.complete, false);
      });
      if (outcome === 'rollback-unknown') {
        assert.equal(receipt.complete, false);
        assert.equal(receipt.attempts.length, 1);
        assert.ok(receipt.unknownRollbacks.length);
        assert.ok(receipt.openTokens.length);
        return;
      }
      assert.equal(receipt.complete, true);
      assert.deepEqual(receipt.openTokens, []);
      const projected = projectAdminReceipt(receipt);
      assert.deepEqual(projected.cases.map(entry => entry.caseId), ['conflict', 'control', 'retry', 'retry-older']);
      for (const entry of projected.cases) {
        assert.equal(entry.writer.code, ['writer-late', 'older-retry'].includes(outcome) ? 0 : 10);
        assert.ok(entry.writer.rpcSequence.some(row => row.rpc === 'Commit'));
        assert.equal(entry.callbackCount, outcome === 'older-retry' && entry.caseId === 'retry-older' ? 2 : 1);
        if (entry.caseId !== 'control' && outcome !== 'older-retry') assert.equal(entry.finalState.b, 'transaction-baseline');
      }
      const olderReads = receipt.steps.filter(row => row.caseId === 'retry-older' && row.rpc === 'BatchGetDocuments' && row.request.newTransaction);
      assert.equal(olderReads[0].client, 'writer');
      assert.equal(olderReads[1].client, 'transaction');
      if (outcome === 'rollback-invalid') assert.ok(projected.cases.some(entry => entry.writer.rpcSequence.some(row => row.rpc === 'Rollback' && row.code === 3)));
      assert.equal(docs.size, 0);
    } finally { server.forceShutdown(); await descriptor.close(); }
  });
}


test('production SDK TLS auth and custom headers reach the loopback server exactly once', { timeout: 30_000 }, async () => {
  const { Firestore } = require('@google-cloud/firestore');
  const { getApps, deleteApp } = require('firebase-admin/app');
  const originalApps = new Set(getApps());
  const clients = [];
  const { v1: { FirestoreClient } } = require('@google-cloud/firestore');
  const descriptor = new FirestoreClient({ projectId: 'demo-descriptors' });
  const fs = descriptor._protos.google.firestore.v1;
  const server = new grpc.Server();
  // Generate ephemeral TLS material in memory without reading or writing key files.
  const tls = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', '-', '-out', '-', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-days', '1'], { encoding: 'utf8' });
  assert.equal(tls.status, 0, 'offline TLS certificate generation must succeed');
  const privateKey = Buffer.from(tls.stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)[0]);
  const cert = Buffer.from(tls.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)[0]);
  const received = [];
  server.addService({ BatchGetDocuments: { path: '/google.firestore.v1.Firestore/BatchGetDocuments', requestStream: false, responseStream: true,
    requestSerialize: fs.BatchGetDocumentsRequest.serialize, requestDeserialize: fs.BatchGetDocumentsRequest.deserialize,
    responseSerialize: fs.BatchGetDocumentsResponse.serialize, responseDeserialize: fs.BatchGetDocumentsResponse.deserialize } }, {
    BatchGetDocuments(call) {
      received.push({ authorization: call.metadata.get('authorization'), quotaProject: call.metadata.get('x-goog-user-project') });
      // A pre-existing document stops the recorder after this successful read, before any write.
      call.write({ found: { name: call.request.documents[0], fields: {}, createTime: { seconds: '1' }, updateTime: { seconds: '1' } }, readTime: { seconds: '1' } });
      call.end();
    },
  });
  const settings = Firestore.prototype.settings;
  const createSsl = grpc.credentials.createSsl;
  let headers;
  const intercepted = [];
  let port;
  Firestore.prototype.settings = function (value) {
    clients.push(this);
    headers = value.auth.getClient().then(client => client.getRequestHeaders());
    const transform = value['grpc.callInvocationTransformer'];
    return settings.call(this, { ...value, host: `127.0.0.1:${port}`, 'grpc.ssl_target_name_override': 'localhost',
      'grpc.callInvocationTransformer': properties => {
        transform(properties);
        properties.callOptions.interceptors.unshift((options, nextCall) => new grpc.InterceptingCall(nextCall(options), {
          start(metadata, listener, next) { intercepted.push(metadata.get('x-goog-user-project')); next(metadata, listener); },
        }));
        return properties;
      },
    });
  };
  try {
    port = await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createSsl(null, [{ private_key: privateKey, cert_chain: cert }]), (error, value) => error ? reject(error) : resolve(value)));
    // Change only the trust root; GAX still combines TLS with its real auth metadata plugin.
    grpc.credentials.createSsl = () => createSsl(cert);
    const admission = { bearer: 'offline-parent', check: () => {}, journal: event => {
      if (event.event === 'dispatch' && (!event.row.metadataKeys.includes('x-goog-user-project') || event.row.quotaProject !== 'fireemu-oracle-txn')) throw new Error('SDK quota project metadata missing');
    } };
    const receipt = await recordAdminRetries({ project: 'fireemu-oracle-txn', admission });
    assert.equal(receipt.steps[0].result.code, 0);
    assert.equal(receipt.steps[0].result.response.responses[0].found.name, receipt.steps[0].request.documents[0]);
    assert.deepEqual(intercepted, [['fireemu-oracle-txn']]);
    assert.deepEqual(received, [{ authorization: ['Bearer offline-parent'], quotaProject: ['fireemu-oracle-txn'] }]);
    assert.equal(receipt.steps[0].quotaProject, 'fireemu-oracle-txn');
    assert.equal(receipt.steps[0].metadataKeys.filter(key => key === 'x-goog-user-project').length, 1);
    assert.equal((await headers).has('x-goog-user-project'), false);
    assert.equal((await headers).get('authorization'), 'Bearer offline-parent');
    assert.equal(receipt.sandboxRequests, 1);
    assert.equal(receipt.complete, false);
  } finally {
    Firestore.prototype.settings = settings;
    grpc.credentials.createSsl = createSsl;
    server.forceShutdown();
    await Promise.all(clients.map(client => client.terminate()));
    await Promise.all(getApps().filter(app => !originalApps.has(app)).map(app => deleteApp(app)));
    await descriptor.close();
  }
});


test('recorded production projections match and reject unsupported attempt and writer families', async t => {
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  const fixtures = [1, 2].map(index => JSON.parse(readFileSync(new URL(`./admin_sdk_retry.production-${index}.fixture.json`, import.meta.url), 'utf8')));
  const runtime = { node: process.version, nodeSha256: createHash('sha256').update(readFileSync(process.execPath)).digest('hex'), lockSha256: createHash('sha256').update(readFileSync(new URL('../../../conformance/pnpm-lock.yaml', import.meta.url))).digest('hex'), manifest: runtimeInfo() };
  const sourceDigest = createHash('sha256').update(readFileSync(new URL('./admin_sdk_retry.mjs', import.meta.url))).update(readFileSync(new URL('../fs-listen-resume/listen_sdk_adapter.mjs', import.meta.url))).digest('hex');
  const corpusDigest = createHash('sha256').update(JSON.stringify([{ caseId: 'conflict', maxAttempts: 1 }, { caseId: 'control', maxAttempts: 1 }, { caseId: 'retry', maxAttempts: 2 }, { caseId: 'retry-older', maxAttempts: 2 }])).digest('hex');
  for (const [index, fixture] of fixtures.entries()) {
    Object.assign(fixture.receipt.runtime, runtime);
    Object.assign(fixture.receipt, { sourceDigest, corpusDigest });
    const bound = { ...fixture.receipt }; delete bound.receiptDigest;
    fixture.receipt.receiptDigest = createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex');
    await t.test(`production recording ${index + 1} returns the recorded case projections`, () => {
      assert.deepEqual(projectAdminReceipt(fixture.receipt).cases, fixture.expectedCases);
    });
  }
  await t.test('two production recordings compare as a match', () => {
    const comparison = compareAdminReceipts(fixtures[0].receipt, fixtures[1].receipt);
    assert.equal(comparison.mismatches, 0);
    assert.equal(comparison.attempts.length, 5);
    assert.ok(comparison.attempts.every(row => row.match));
  });
  const faults = [
    ['unknown transaction code', receipt => { receipt.steps.find(row => row.caseId === 'conflict' && row.client === 'transaction' && row.rpc === 'Commit').result.code = 7; }, /refusal|sequence/],
    ['unknown writer code', receipt => { receipt.steps.find(row => row.caseId === 'control' && row.client === 'writer' && row.rpc === 'Commit').result.code = 7; }, /writer/],
    ['missing transaction rollback', receipt => { receipt.steps = receipt.steps.filter(row => !(row.caseId === 'retry-older' && row.client === 'transaction' && row.rpc === 'Rollback')); }, /sequence/],
    ['missing writer rollback', receipt => { receipt.steps = receipt.steps.filter(row => !(row.caseId === 'conflict' && row.client === 'writer' && row.rpc === 'Rollback')); }, /writer/],
    ['refused transaction rollback', receipt => { receipt.steps.find(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.rpc === 'Rollback').result.code = 10; }, /sequence/],
    ['refused writer rollback', receipt => { receipt.steps.find(row => row.caseId === 'conflict' && row.client === 'writer' && row.rpc === 'Rollback').result.code = 10; }, /writer/],
    ['unknown local transaction rollback', receipt => { receipt.runtime.target = 'local'; receipt.steps.find(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.rpc === 'Rollback').result.code = 7; }, /sequence/],
    ['unknown local writer rollback', receipt => { receipt.runtime.target = 'local'; receipt.steps.find(row => row.caseId === 'conflict' && row.client === 'writer' && row.rpc === 'Rollback').result.code = 7; }, /writer/],
    ['refused transaction read', receipt => { receipt.steps.find(row => row.caseId === 'conflict' && row.client === 'transaction' && row.rpc === 'BatchGetDocuments').result.code = 10; }, /sequence/],
    ['refused writer read', receipt => { receipt.steps.find(row => row.caseId === 'conflict' && row.client === 'writer' && row.rpc === 'BatchGetDocuments').result.code = 10; }, /writer/],
    ['extra transaction RPC', receipt => { receipt.steps.find(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.rpc === 'Rollback').rpc = 'GetDocument'; }, /sequence/],
    ['extra writer RPC', receipt => { receipt.steps.find(row => row.caseId === 'conflict' && row.client === 'writer' && row.rpc === 'Rollback').rpc = 'GetDocument'; }, /writer/],
    ['mismatched retry lineage', receipt => { receipt.steps.find(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.attempt === 2 && row.rpc === 'BatchGetDocuments').request.newTransaction.readWrite.retryTransaction = 'Zm9yZWlnbg=='; }, /lineage/],
    ['missing retry lineage', receipt => { delete receipt.steps.find(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.attempt === 2 && row.rpc === 'BatchGetDocuments').request.newTransaction.readWrite.retryTransaction; }, /lineage/],
    ['missing issued token and retry lineage', receipt => {
      for (const row of receipt.steps.filter(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.rpc === 'BatchGetDocuments')) {
        if (row.attempt === 1) row.result.response.responses = row.result.response.responses.filter(frame => !frame.transaction);
        else delete row.request.newTransaction.readWrite.retryTransaction;
      }
    }, /lineage/],
    ['more than two attempts', receipt => {
      const entry = receipt.attempts.find(value => value.caseId === 'retry-older');
      entry.callbackCount = 3;
      entry.attempts.push({ ...structuredClone(entry.attempts[1]), callbackCount: 3 });
      const extra = structuredClone(receipt.steps.filter(row => row.caseId === 'retry-older' && row.client === 'transaction' && row.attempt === 2));
      extra.push(structuredClone(receipt.steps.findLast(row => row.caseId === 'retry-older' && row.client === 'witness' && row.site === 'retry-older/post-state')));
      const read = extra.find(row => row.rpc === 'BatchGetDocuments' && row.client === 'transaction');
      read.request.newTransaction.readWrite.retryTransaction = read.result.response.responses.find(frame => frame.transaction).transaction;
      for (const row of extra) { row.attempt = 3; row.sequence += receipt.steps.length; }
      receipt.steps.push(...extra);
    }, /callback/],
  ];
  for (const [name, mutate, error] of faults) await t.test(name, () => {
    const receipt = structuredClone(fixtures[0].receipt);
    mutate(receipt);
    const rows = [...receipt.steps.sort((a, b) => a.sequence - b.sequence), ...receipt.cleanupSteps];
    rows.forEach((row, index) => { row.sequence = index; row.outcomeClass = row.result.code === 0 ? 'OK' : [3, 5, 9, 10].includes(row.result.code) ? 'REFUSED' : 'OTHER'; });
    receipt.phaseRequests.observation = receipt.steps.length;
    receipt.sandboxRequests = Object.values(receipt.phaseRequests).reduce((a, b) => a + b, 0);
    for (const entry of receipt.attempts) {
      for (const attempt of entry.attempts) {
        const native = receipt.steps.filter(row => row.caseId === entry.caseId && row.client === 'transaction' && row.attempt === attempt.callbackCount);
        const commit = native.find(row => row.rpc === 'Commit');
        attempt.refusalCode = commit.result.code;
        attempt.refusalMessage = commit.result.details;
        attempt.rpcSequence = native.map(row => ({ code: row.result.code, rpc: row.rpc, sequence: row.sequence }));
      }
      const writer = receipt.steps.filter(row => row.caseId === entry.caseId && row.client === 'writer');
      const commit = writer.find(row => row.rpc === 'Commit');
      entry.writer = { code: commit.result.code, message: commit.result.details, rpcSequence: writer.map(row => ({ code: row.result.code, message: row.result.details, rpc: row.rpc, sequence: row.sequence })) };
    }
    const bound = { ...receipt }; delete bound.receiptDigest;
    receipt.receiptDigest = createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex');
    assert.throws(() => projectAdminReceipt(receipt), error);
  });
  for (const client of ['transaction', 'writer']) await t.test(`inconsistent ${client} RPC summary is refused`, () => {
    const receipt = structuredClone(fixtures[0].receipt);
    const entry = receipt.attempts[0];
    const sequence = client === 'transaction' ? entry.attempts[0].rpcSequence : entry.writer.rpcSequence;
    sequence[0].sequence++;
    const bound = { ...receipt }; delete bound.receiptDigest;
    receipt.receiptDigest = createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex');
    assert.throws(() => projectAdminReceipt(receipt), /sequence|writer/);
  });
  const localPath = new URL('../../../target/codex-out/s5a-judge/local-reduced.json', import.meta.url);
  await t.test('recorded local conflict compares as a per-case mismatch', { skip: !existsSync(localPath) }, () => {
    const local = JSON.parse(readFileSync(localPath, 'utf8'));
    Object.assign(local.runtime, runtime);
    Object.assign(local, { sourceDigest, corpusDigest });
    const bound = { ...local }; delete bound.receiptDigest;
    local.receiptDigest = createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex');
    const comparison = compareAdminReceipts(fixtures[0].receipt, local);
    const conflict = comparison.attempts.find(row => row.caseId === 'conflict');
    assert.ok(comparison.mismatches > 0);
    assert.equal(conflict.match, false);
    assert.equal(conflict.production.refusalCode, 0);
    assert.equal(conflict.local.refusalCode, 10);
    assert.equal(conflict.production.writer.code, 10);
    assert.equal(conflict.local.writer.code, 0);
  });
});

// Exact archived producer bytes; compressed so tests do not depend on Git history.
const archivedProductionBytes = {
  "tools/compat-broad/fs-write-txn/admin_sdk_retry.mjs": "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",
  "tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs": "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",
  "tools/compat-broad/fs-write-txn/txn_program_transport.mjs": "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"
};

test('archived production binding refuses unpinned bytes, manifests and options', async t => {
  const directory = new URL('../../../target/codex-out/p17-binding-tests/', import.meta.url);
  mkdirSync(directory, { recursive: true });
  const sources = Object.fromEntries(Object.entries(archivedProductionBytes).map(([path, zipped], i) => {
    const destination = new URL(`producer-${i}.mjs`, directory);
    writeFileSync(destination, gunzipSync(Buffer.from(zipped, 'base64')));
    return [path, destination.pathname];
  }));
  const production = JSON.parse(readFileSync(new URL('./admin_sdk_retry.production-1.fixture.json', import.meta.url))).receipt;
  production.sourceManifest = Object.fromEntries(Object.entries(sources).map(([path, file]) => [path, createHash('sha256').update(readFileSync(file)).digest('hex')]));
  production.runtime.manifest = runtimeInfo();
  const local = structuredClone(production); local.runtime.target = 'local';
  const options = { archivedProductionSources: sources };
  try {
    await t.test('a synthetic current runtime cannot claim the pinned historical archive', () => {
      assert.throws(() => compareAdminReceipts(production, local, options), /archived production runtime manifest/);
    });
    for (const [name, transform] of [
      ['bare digest option', () => ({ sourceDigest: production.sourceDigest })],
      ['unused digest beside exact archive', () => ({ ...options, sourceDigest: production.sourceDigest })],
      ['unknown archive key', () => ({ archivedProductionSources: { ...sources, unknown: 'unused' } })],
      ['missing archive key', () => ({ archivedProductionSources: Object.fromEntries(Object.entries(sources).slice(0, 2)) })],
      ['swapped archive paths', () => ({ archivedProductionSources: Object.fromEntries(Object.keys(sources).map((key, i) => [key, Object.values(sources)[(i + 1) % 3]])) })],
    ]) await t.test(name, () => assert.throws(() => compareAdminReceipts(production, local, transform()), /archive|option|producer/));
    for (const path of Object.keys(sources)) await t.test(`the pinned source manifest requires ${path}`, () => {
      const changed = structuredClone(production); changed.sourceManifest[path] = '0'.repeat(64);
      assert.throws(() => compareAdminReceipts(changed, local, options), /source manifest/);
    });
    await t.test('changed archive bytes and matching forged manifests cannot establish authority', () => {
      for (const [path, file] of Object.entries(sources)) {
        const bytes = readFileSync(file);
        try {
          for (let n = 0; n < 8; n++) {
            const changed = Buffer.from(bytes); changed[Math.floor(n * (bytes.length - 1) / 7)] ^= 1 << (n % 8);
            writeFileSync(file, changed);
            assert.throws(() => compareAdminReceipts(production, local, options), /producer bytes/);
            const forged = structuredClone(production);
            forged.sourceManifest[path] = createHash('sha256').update(changed).digest('hex');
            assert.throws(() => compareAdminReceipts(forged, local, options), /producer bytes/);
          }
        } finally { writeFileSync(file, bytes); }
      }
    });
    await t.test('production role cannot be swapped onto current local', () => {
      assert.throws(() => compareAdminReceipts(local, production, options), /production/);
    });
  } finally { rmSync(directory, { recursive: true }); }
});


// Optional fixed archived inputs provide unchanged historical provenance without publishing private checkout paths.
const archivedRecordPaths = process.env.P17_ARCHIVED_PRODUCTION_RECORDINGS;
test('unchanged archived production records retain their native projections and historical runtime', { skip: !archivedRecordPaths }, async t => {
  const paths = JSON.parse(archivedRecordPaths);
  assert.equal(paths.length, 2);
  const hashes = ['e6e754055db0555a77d67faf79ffad97b564de56781c1640d6a666d62c9ed0d9', '50ec52e2c1f17f497928c2c6b75fe6931d31a70d96c54c10643872d254f5f227'];
  const sources = JSON.parse(process.env.P17_ARCHIVED_PRODUCTION_SOURCES);
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  for (const [index, path] of paths.entries()) {
    const bytes = readFileSync(path);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), hashes[index]);
    const production = JSON.parse(bytes);
    const before = JSON.stringify(production);
    // The current-side synthetic copy tests projection only; it is not a local acquisition witness.
    const current = structuredClone(production);
    current.runtime = { ...current.runtime, target: 'local', manifest: runtimeInfo() };
    current.sourceDigest = createHash('sha256').update(readFileSync(new URL('./admin_sdk_retry.mjs', import.meta.url))).update(readFileSync(new URL('../fs-listen-resume/listen_sdk_adapter.mjs', import.meta.url))).digest('hex');
    const bound = { ...current }; delete bound.receiptDigest;
    current.receiptDigest = createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex');
    const options = { archivedProductionSources: sources };
    const comparison = compareAdminReceipts(production, current, options);
    assert.equal(comparison.mismatches, 0);
    assert.equal(comparison.attempts.length, 5);
    assert.equal(JSON.stringify(production), before);
    assert.equal(createHash('sha256').update(readFileSync(path)).digest('hex'), hashes[index]);
    assert.equal(comparison.provenance.production.runtimeManifestSha256, '072bf56b670e8c6c8e2868f2b6e8de9646291ba84f41b7d51519cb5ee449be84');
    assert.equal(comparison.provenance.production.files['tools/compat-broad/fs-write-txn/txn_program_transport.mjs'], 'dea5c1f59b8054888cff5244975c894fa622a7787db64bce343fe10ead783f50');
    const bind = receipt => {
      const value = { ...receipt }; delete value.receiptDigest;
      receipt.receiptDigest = createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
      return receipt;
    };
    await t.test(`record ${index + 1}: default projection cannot claim archived authorship`, () => {
      assert.throws(() => projectAdminReceipt(production), /runtime|source binding/);
      assert.throws(() => compareAdminReceipts(production, current), /runtime|source binding/);
    });
    for (const [name, mutate, error] of [
      ['changed root', r => { Object.values(r.runtime.manifest.dependencies)[0].root += '-changed'; }, /runtime manifest/],
      ['uniformly relocated historical roots', r => { for (const [key, row] of Object.entries(r.runtime.manifest.dependencies)) row.root = '/unapproved/node_modules/' + key; }, /runtime manifest/],
      ['missing dependency', r => { delete r.runtime.manifest.dependencies[Object.keys(r.runtime.manifest.dependencies)[0]]; }, /runtime manifest/],
      ['changed requires graph', r => { Object.values(r.runtime.manifest.dependencies)[0].requires.extra = 'unapproved'; }, /runtime manifest/],
      ['changed content tree', r => { Object.values(r.runtime.manifest.dependencies)[0].treeSha256 = '0'.repeat(64); }, /runtime manifest/],
      ['changed file count', r => { Object.values(r.runtime.manifest.dependencies)[0].fileCount++; }, /runtime manifest/],
      ['changed dependency name', r => { Object.values(r.runtime.manifest.dependencies)[0].name += '-changed'; }, /runtime manifest/],
      ['changed dependency version', r => { Object.values(r.runtime.manifest.dependencies)[0].version = '0.0.0'; }, /runtime manifest/],
      ['changed Node manifest', r => { r.runtime.manifest.nodeVersion = 'v0.0.0'; }, /runtime manifest/],
      ['changed Node executable', r => { r.runtime.nodeSha256 = '0'.repeat(64); }, /runtime binding/],
      ['changed lock pin', r => { r.runtime.lockSha256 = '0'.repeat(64); }, /runtime binding/],
      ['changed transport provenance', r => { r.sourceManifest['tools/compat-broad/fs-write-txn/txn_program_transport.mjs'] = '0'.repeat(64); }, /source manifest/],
      ['changed receipt without resealing', r => { r.attempts[0].callbackCount++; }, /receipt digest/],
      ['native summary contradiction', r => { r.attempts[0].attempts[0].rpcSequence[0].code = 7; }, /sequence/],
      ['incomplete cleanup', r => { r.cleanup.absent = false; }, /acquisition/],
      ['unknown commit', r => { r.unknownCommits.push('unknown'); }, /acquisition/],
      ['forged source digest', r => { r.sourceDigest = current.sourceDigest; }, /source binding/],
      ['forged corpus digest', r => { r.corpusDigest = '0'.repeat(64); }, /source binding/],
    ]) await t.test(`record ${index + 1}: ${name} is refused`, () => {
      const changed = structuredClone(production); mutate(changed);
      if (name !== 'changed receipt without resealing') bind(changed);
      assert.throws(() => compareAdminReceipts(changed, current, options), error);
    });
    for (const [name, mutate] of [
      ['historical authorship', r => { r.sourceDigest = production.sourceDigest; }],
      ['historical runtime', r => { r.runtime.manifest = structuredClone(production.runtime.manifest); }],
      ['changed root', r => { Object.values(r.runtime.manifest.dependencies)[0].root += '-changed'; }],
      ['changed graph', r => { Object.values(r.runtime.manifest.dependencies)[0].requires.extra = 'unapproved'; }],
    ]) await t.test(`record ${index + 1}: current side rejects ${name}`, () => {
      const changed = structuredClone(current); mutate(changed); bind(changed);
      assert.throws(() => compareAdminReceipts(production, changed, options), /runtime|source binding/);
    });
    for (const field of ['lockSha256', 'corpusDigest']) await t.test(`record ${index + 1}: matching forged ${field} remains refused`, () => {
      const left = structuredClone(production), right = structuredClone(current);
      if (field === 'lockSha256') left.runtime[field] = right.runtime[field] = '0'.repeat(64);
      else left[field] = right[field] = '0'.repeat(64);
      bind(left); bind(right);
      assert.throws(() => compareAdminReceipts(left, right, options), /runtime|source binding/);
    });
    await t.test(`record ${index + 1}: CLI preserves archive authority and rejects unused input`, () => {
      const invoke = input => spawnSync(process.execPath, [new URL('./admin_sdk_retry.mjs', import.meta.url).pathname, 'compare'], { input: JSON.stringify(input), encoding: 'utf8' });
      const result = invoke({ production, local: current, options });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).mismatches, 0);
      assert.notEqual(invoke({ production, local: current, options, unused: true }).status, 0);
    });

  }
});
