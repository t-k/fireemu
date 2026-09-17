import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import {
  assertReadyForWire,
  createLocalClient,
  createFixedTlsTransport,
  plainError,
  prepareFixedTlsTransport,
  runUnaryCore,
  runWriteCore,
} from './transport_internal.mjs';

const base = {
  projectId: 'fireemu-test',
  documentPrefix: 'compat/o3',
  deadlineMs: 100,
  metadata: { authorization: 'Bearer owner' },
  metadataExpiresAt: 2_000,
  phaseDeadlineAt: 3_000,
};

test('prepares a fixed TLS production configuration without accepting endpoint or ADC inputs', () => {
  const prepared = prepareFixedTlsTransport(base);
  assert.equal(prepared.servicePath, 'firestore.googleapis.com');
  assert.equal(prepared.port, 443);
  assert.equal(prepared.fallback, false);
  assert.equal(prepared.mode, 'production');
  assert.match(prepared.sslCreds.constructor.name, /Secure/);
  for (const field of ['endpoint', 'apiEndpoint', 'servicePath', 'host', 'port', 'keyFilename', 'credentials', 'sslCreds', 'useADC']) {
    assert.throws(() => prepareFixedTlsTransport({ ...base, [field]: field === 'port' ? 443 : 'override' }), /override|fixed/);
  }
  assert.throws(() => prepareFixedTlsTransport({ ...base, metadata: {} }), /authorization/);
});

test('local client factory rejects non-loopback options before channel construction', () => {
  assert.throws(() => createLocalClient({ host: 'firestore.googleapis.com', port: 443, projectId: 'fireemu-test' }), /loopback/);
});

test('checks metadata expiry and absolute phase deadline after asynchronous readiness', async () => {
  const prepared = prepareFixedTlsTransport(base);
  let released = false;
  const waitForReady = Promise.resolve().then(() => { released = true; });
  await assert.rejects(() => assertReadyForWire(prepared, { waitForReady, now: () => 2_000 }), /metadata expired/);
  assert.equal(released, true);
  const phaseExpired = prepareFixedTlsTransport({ ...base, metadataExpiresAt: 4_000 });
  let current = 1_000;
  const readiness = Promise.resolve().then(() => { current = 3_000; });
  await assert.rejects(() => assertReadyForWire(phaseExpired, { waitForReady: readiness, now: () => current }), /phase deadline/);
  assert.equal(await assertReadyForWire(prepared, { waitForReady: Promise.resolve(), now: () => 1_000 }), prepared);
  await assert.rejects(() => assertReadyForWire(prepared, { waitForReady: Promise.resolve(), now: () => 1_000, callDeadlineMs: 1_000 }), /metadata expired/);
  const phaseBoundary = prepareFixedTlsTransport({ ...base, metadataExpiresAt: 4_000, phaseDeadlineAt: 2_000 });
  await assert.rejects(() => assertReadyForWire(phaseBoundary, { waitForReady: Promise.resolve(), now: () => 1_000, callDeadlineMs: 1_000 }), /phase deadline/);
});

test('connects the readiness gate to the future fixed TLS entrypoints without executing production RPCs', async () => {
  const transport = createFixedTlsTransport(base, { admit: () => Promise.resolve() });
  await assert.rejects(() => transport.runUnary('GetDocument', { path: 'compat/o3/doc' }), /metadata expired/);
  await assert.rejects(() => transport.runWrite([], { deadlineMs: 0 }), /deadlineMs/);
});

test('prevalidates finite writes before admission or client construction', async () => {
  let admitted = false;
  const transport = createFixedTlsTransport(base, { admit: () => { admitted = true; return Promise.resolve(); } });
  await assert.rejects(() => transport.runWrite([{ writes: [{ delete: 'projects/other/databases/(default)/documents/compat/o3/doc' }] }]), /owned prefix/);
  assert.equal(admitted, false);
  for (const deadlineMs of [Number.NaN, -1, Infinity, 120_001]) {
    await assert.rejects(() => transport.runUnary('GetDocument', { path: 'compat/o3/doc' }, { deadlineMs }), /deadlineMs/);
  }
});

test('serializes terminal errors into comparator-safe fields', () => {
  const error = Object.assign(new Error('permission denied'), { code: 7, details: 'denied' });
  assert.deepEqual(plainError(error), {
    name: 'Error',
    code: 7,
    details: 'denied',
    message: 'permission denied',
  });
});

test('passes explicit no-retry call options to unary and Write RPCs', async () => {
  let unaryOptions;
  const unaryClient = {
    getDocument(request, callOptions) {
      unaryOptions = callOptions;
      return Promise.resolve([{ name: request.name }, {}]);
    },
    close() {},
  };
  const unary = await runUnaryCore('GetDocument', { name: 'documents/doc' }, {
    deadlineMs: 100,
    metadata: {},
  }, { createClient: () => unaryClient });
  assert.equal(unary.complete, true);
  assert.deepEqual(unaryOptions.retry, { retryCodes: [] });

  let writeOptions;
  const stream = new EventEmitter();
  stream.write = () => queueMicrotask(() => stream.emit('data', { streamToken: Buffer.from('token') }));
  stream.end = () => {
    queueMicrotask(() => {
      stream.emit('status', { code: 0, details: 'ok', message: '' });
      stream.emit('close');
    });
  };
  stream.destroy = error => queueMicrotask(() => stream.emit('error', error));
  const writeClient = {
    write(callOptions) {
      writeOptions = callOptions;
      return stream;
    },
    close() {},
  };
  const write = await runWriteCore([], {
    deadlineMs: 100,
    maxFrames: 4,
    maxMessageBytes: 4096,
    metadata: {},
  }, {
    createClient: () => writeClient,
    handshake: { database: 'projects/fireemu-test/databases/(default)' },
    buildNextFrame: Object.assign((request) => request, { validate() {} }),
  });
  assert.equal(write.complete, true);
  assert.deepEqual(writeOptions.retry, { retryCodes: [] });
});

test('returns immutable JSON-safe outbound frame snapshots with honest send counts', async () => {
  const sentFrames = [];
  const stream = new EventEmitter();
  stream.write = frame => {
    sentFrames.push(frame);
    const response = sentFrames.length === 1
      ? { streamToken: Buffer.from('fresh-token') }
      : { streamToken: Buffer.from('new-token') };
    if (sentFrames.length === 2) frame.streamToken = Buffer.from('mutated-after-capture');
    queueMicrotask(() => stream.emit('data', response));
  };
  stream.end = () => queueMicrotask(() => {
    stream.emit('status', { code: 0, details: 'ok', message: '' });
    stream.emit('close');
  });
  stream.destroy = error => queueMicrotask(() => stream.emit('error', error));
  const receipt = await runWriteCore([
    { writes: [{ delete: 'projects/fireemu-test/databases/(default)/documents/compat/o3/doc' }] },
  ], {
    deadlineMs: 100,
    maxFrames: 8,
    maxMessageBytes: 4096,
    metadata: {},
  }, {
    createClient: () => ({ write: () => stream, close() {} }),
    handshake: { database: 'projects/fireemu-test/databases/(default)' },
    buildNextFrame: Object.assign((request, response) => ({ ...request, streamToken: response.streamToken }), { validate() {} }),
  });

  assert.equal(receipt.transportReceiptVersion, 2);
  assert.equal(receipt.sentFrames, 2);
  assert.equal(receipt.completedSendFrames, 2);
  assert.equal(receipt.receivedFrames, 2);
  const sends = receipt.events.filter(event => event.type === 'send');
  assert.equal(sends.length, 2);
  assert.equal(sends[0].value.database, 'projects/fireemu-test/databases/(default)');
  assert.deepEqual(sends[1].value.streamToken, { type: 'Buffer', data: [...Buffer.from('fresh-token')] });
  assert.equal(Object.isFrozen(sends[1].value), true);
  assert.equal(JSON.stringify(receipt).includes('authorization'), false);
  assert.throws(() => { sends[1].value.streamToken = 'changed'; }, TypeError);
});

test('prevalidates every Write request before creating a client or writing a frame', async () => {
  let constructed = false;
  await assert.rejects(() => runWriteCore([{ invalid: true }], {
    deadlineMs: 100,
    maxFrames: 4,
    maxMessageBytes: 4096,
    metadata: {},
  }, {
    createClient: () => {
      constructed = true;
      throw new Error('client must not be created');
    },
    handshake: { database: 'projects/fireemu-test/databases/(default)' },
    buildNextFrame: Object.assign(request => request, {
      validate: request => {
        if (request.invalid) throw new TypeError('invalid request');
      },
    }),
  }), /invalid request/);
  assert.equal(constructed, false);
});
