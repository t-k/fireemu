import test from 'node:test';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { localTarget, rpcRecorder, recordAdminRetries, projectAdminReceipt, compareAdminReceipts } from './admin_sdk_retry.mjs';

const require = createRequire(new URL('../../../conformance/package.json', import.meta.url));
const grpc = require('@grpc/grpc-js');

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
  assert.equal(Object.keys(receipt.tokens).length, 9);
  assert.equal(Object.values(receipt.tokens).filter(token => token.state === 'committed').length, 6);
  assert.equal(Object.values(receipt.tokens).filter(token => token.state === 'released-refused').length, 3);
  assert.deepEqual(receipt.cleanup, { absent: true });
  assert.deepEqual(receipt.phaseRequests, { observation: receipt.steps.length, tokenCleanup: 0, documentCleanup: receipt.cleanupSteps.length, management: 0, credential: 0 });
  assert.equal(receipt.sandboxRequests, receipt.steps.length + receipt.cleanupSteps.length);
  assert.deepEqual([...receipt.steps, ...receipt.cleanupSteps].map(row => row.sequence).sort((a, b) => a - b), Array.from({ length: receipt.sandboxRequests }, (_, i) => i));
  const [conflict, control, retry, older] = receipt.attempts;
  assert.equal(conflict.caseId, 'conflict');
  assert.equal(conflict.callbackCount, 1);
  assert.equal(conflict.refusalCode, 10);
  assert.equal(conflict.finalState.a.state, 'writer');
  assert.equal(conflict.finalState.b.state, 'baseline');
  assert.equal(control.caseId, 'control');
  assert.equal(control.callbackCount, 1);
  assert.equal(control.refusalCode, 0);
  assert.equal(control.finalState.a.state, 'baseline');
  assert.equal(control.finalState.b.state, 'transaction-baseline');
  assert.equal(control.finalState.c.state, 'writer');
  assert.equal(retry.caseId, 'retry');
  assert.equal(retry.callbackCount, 2);
  assert.equal(retry.refusalCode, 0);
  assert.deepEqual(retry.attempts.map(attempt => [attempt.callbackCount, attempt.refusalCode, attempt.finalState.b.state]), [[1, 10, 'baseline'], [2, 0, 'transaction-writer']]);
  const firstRead = receipt.steps.find(row => row.caseId === 'retry' && row.client === 'transaction' && row.rpc === 'BatchGetDocuments' && row.attempt === 1);
  const nextRead = receipt.steps.find(row => row.caseId === 'retry' && row.client === 'transaction' && row.rpc === 'BatchGetDocuments' && row.attempt === 2);
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
      assert.equal(writer.result.code, 0);
      assert.equal(commit.result.code, 10);
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
  assert.equal(comparison.attempts.length, 6);
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
  production.attempts[0].attempts[0].finalState.a.state = 'baseline';
  production.attempts[0].finalState.a.state = 'baseline';
  seal(production);
  assert.throws(() => projectAdminReceipt(production), /witness/);
  production.attempts[0].attempts[0].finalState.a.state = 'writer';
  production.attempts[0].finalState.a.state = 'writer';
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
  test(`local SDK stub observes ${outcome} with native evidence in every case`, async () => {
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


test('production SDK TLS auth and custom headers reach the loopback server exactly once', async () => {
  const { Firestore } = require('@google-cloud/firestore');
  const { v1: { FirestoreClient } } = require('@google-cloud/firestore');
  const descriptor = new FirestoreClient({ projectId: 'demo-descriptors' });
  const fs = descriptor._protos.google.firestore.v1;
  const server = new grpc.Server();
  // Generate ephemeral TLS material in memory without reading or writing key files.
  const tls = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', '/dev/stdout', '-out', '/dev/stdout', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-days', '1'], { encoding: 'utf8' });
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
  } finally { Firestore.prototype.settings = settings; grpc.credentials.createSsl = createSsl; server.forceShutdown(); await descriptor.close(); }
});
