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

const writeOptions = { deadlineMs: 25, maxFrames: 8, maxMessageBytes: 256, metadata: {} };
const handshake = { database: 'projects/fireemu-test/databases/(default)' };
const identityFrame = Object.assign((request) => request, { validate() {} });
const controlledWrite = (onWrite, options = writeOptions, onClose = () => {}) => {
  const stream = new EventEmitter();
  stream.write = frame => queueMicrotask(() => onWrite(stream, frame));
  stream.end = () => {};
  stream.destroy = error => queueMicrotask(() => {
    stream.emit('error', error);
    stream.emit('close');
  });
  return runWriteCore([], options, {
    createClient: () => ({ write: () => stream, close: onClose }),
    handshake,
    buildNextFrame: identityFrame,
  });
};

const bounded = promise => Promise.race([
  promise,
  new Promise((_, reject) => setTimeout(() => reject(new Error('test watchdog expired')), 300)),
]);

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

test('accepts clean status and terminal events in all supported orders', async () => {
  for (const order of ['status-end', 'end-status', 'close-status']) {
    const stream = new EventEmitter();
    stream.write = () => queueMicrotask(() => stream.emit('data', { streamToken: Buffer.from('token') }));
    stream.end = () => {
      const status = { code: 0, details: 'ok', message: '' };
      if (order === 'status-end') {
        stream.emit('status', status);
        stream.emit('end');
      } else if (order === 'end-status') {
        stream.emit('end');
        setTimeout(() => stream.emit('status', status), 10);
      } else {
        stream.emit('close');
        setTimeout(() => stream.emit('status', status), 10);
      }
    };
    stream.destroy = () => {};
    const receipt = await bounded(runWriteCore([], writeOptions, {
      createClient: () => ({ write: () => stream, close() {} }),
      handshake,
      buildNextFrame: identityFrame,
    }));
    assert.equal(receipt.kind, 'grpc_status', order);
    assert.equal(receipt.complete, true, order);
    assert.equal(receipt.status.code, 0, order);
    assert.equal(receipt.error, undefined, order);
  }
});

test('does not clear a real error when status follows end', async () => {
  const stream = new EventEmitter();
  stream.write = () => queueMicrotask(() => stream.emit('data', { streamToken: Buffer.from('token') }));
  stream.end = () => {
    stream.emit('end');
    queueMicrotask(() => stream.emit('error', Object.assign(new Error('aborted'), { code: 13, details: 'aborted' })));
    setTimeout(() => stream.emit('status', { code: 0, details: 'late', message: '' }), 10);
  };
  stream.destroy = () => {};
  const receipt = await bounded(runWriteCore([], writeOptions, {
    createClient: () => ({ write: () => stream, close() {} }),
    handshake,
    buildNextFrame: identityFrame,
  }));
  assert.equal(receipt.kind, 'incomplete_stream');
  assert.equal(receipt.complete, false);
  assert.equal(receipt.status.code, 0);
  assert.equal(receipt.error.code, 13);
});

test('accepts same-tick terminal ordering after the final ACK is queued', async () => {
  for (const order of ['status-end', 'end-status', 'close-status']) {
    const stream = new EventEmitter();
    let writes = 0;
    stream.write = () => queueMicrotask(() => {
      writes += 1;
      stream.emit('data', { streamToken: Buffer.from(`token-${writes}`) });
      if (writes === 2) {
        const status = { code: 0, details: 'ok', message: '' };
        if (order === 'status-end') {
          stream.emit('status', status);
          stream.emit('end');
        } else if (order === 'end-status') {
          stream.emit('end');
          stream.emit('status', status);
        } else {
          stream.emit('close');
          stream.emit('status', status);
        }
      }
    });
    stream.end = () => {};
    stream.destroy = () => {};
    const receipt = await bounded(runWriteCore([{ writes: [] }], writeOptions, {
      createClient: () => ({ write: () => stream, close() {} }),
      handshake,
      buildNextFrame: Object.assign((request, response) => ({ ...request, streamToken: response.streamToken }), { validate() {} }),
    }));
    assert.equal(receipt.kind, 'grpc_status', order);
    assert.equal(receipt.complete, true, order);
    assert.equal(receipt.status.code, 0, order);
    assert.equal(receipt.error, undefined, order);
    assert.equal(receipt.completedSendFrames, 2, order);
    assert.equal(receipt.receivedFrames, 2, order);
  }
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

test('returns a typed gRPC refusal when a Write stream is refused before handshake acknowledgement', async () => {
  let closes = 0;
  const receipt = await bounded(controlledWrite(stream => {
    stream.emit('error', Object.assign(new Error('refused'), { code: 14, details: 'unavailable' }));
    stream.emit('status', { code: 14, details: 'unavailable', message: '14 UNAVAILABLE' });
    stream.emit('close');
  }, writeOptions, () => { closes += 1; }));
  assert.equal(receipt.complete, true);
  assert.equal(receipt.kind, 'grpc_status');
  assert.equal(receipt.status.code, 14);
  assert.equal(closes, 1);
});

test('keeps an error-only numeric code incomplete without a status event', async () => {
  const receipt = await bounded(controlledWrite(stream => {
    stream.emit('error', Object.assign(new Error('aborted'), { code: 10, details: 'aborted' }));
    stream.emit('close');
  }));
  assert.equal(receipt.kind, 'incomplete_stream');
  assert.equal(receipt.complete, false);
  assert.equal(receipt.status, undefined);
  assert.equal(receipt.error.code, 10);
});

test('terminates a silent Write stream at the client deadline', async () => {
  const receipt = await bounded(controlledWrite(() => {}));
  assert.equal(receipt.kind, 'client_deadline');
  assert.equal(receipt.complete, false);
});

test('does not send after status and end arrive before the handshake acknowledgement', async () => {
  let writes = 0;
  const receipt = await bounded(controlledWrite(stream => {
    writes += 1;
    stream.emit('status', { code: 0, details: 'early', message: '' });
    stream.emit('end');
  }));
  assert.equal(receipt.complete, false);
  assert.equal(receipt.kind, 'incomplete_stream');
  assert.equal(writes, 1);
});

test('does not send a next Write after status and end arrive between response and continuation', async () => {
  let writes = 0;
  const stream = new EventEmitter();
  stream.write = () => {
    writes += 1;
    if (writes === 1) queueMicrotask(() => stream.emit('data', { streamToken: Buffer.from('token') }));
    else queueMicrotask(() => {
      stream.emit('status', { code: 0, details: 'early', message: '' });
      stream.emit('end');
    });
  };
  stream.end = () => {};
  stream.destroy = error => queueMicrotask(() => {
    stream.emit('error', error);
    stream.emit('close');
  });
  const receipt = await bounded(runWriteCore([{ writes: [] }], writeOptions, {
    createClient: () => ({ write: () => stream, close() {} }),
    handshake,
    buildNextFrame: Object.assign((request, response) => ({ ...request, streamToken: response.streamToken }), { validate() {} }),
  }));
  assert.equal(receipt.complete, false);
  assert.equal(receipt.kind, 'incomplete_stream');
  assert.equal(writes, 2);
});

test('keeps a statusless end and close incomplete', async () => {
  const receipt = await bounded(controlledWrite(stream => {
    stream.emit('end');
    stream.emit('close');
  }));
  assert.equal(receipt.kind, 'incomplete_stream');
  assert.equal(receipt.complete, false);
  assert.equal(receipt.status, undefined);
});

test('contains oversized status diagnostics without an uncaught event exception', async () => {
  const receipt = await bounded(controlledWrite(stream => {
    stream.emit('status', { code: 0, details: 'x'.repeat(2_000), message: 'x'.repeat(2_000) });
    stream.emit('close');
  }));
  assert.equal(receipt.kind, 'incomplete_stream');
  assert.equal(receipt.complete, false);
  assert.equal(receipt.status, undefined);
  assert.equal(receipt.error.code, 'message_limit');
  assert.ok(Buffer.byteLength(JSON.stringify(receipt.error)) <= writeOptions.maxMessageBytes);
  assert.ok(receipt.events.every(event => Buffer.byteLength(JSON.stringify(event.value)) <= writeOptions.maxMessageBytes));
});

test('contains oversized error diagnostics when error and close arrive immediately', async () => {
  const receipt = await bounded(controlledWrite(stream => {
    stream.emit('error', Object.assign(new Error('x'.repeat(2_000)), { code: 14, details: 'x'.repeat(2_000) }));
    stream.emit('close');
  }));
  assert.equal(receipt.kind, 'incomplete_stream');
  assert.equal(receipt.complete, false);
  assert.equal(receipt.status, undefined);
  assert.equal(receipt.error.code, 'message_limit');
  assert.ok(Buffer.byteLength(JSON.stringify(receipt.error)) <= writeOptions.maxMessageBytes);
  assert.ok(receipt.events.every(event => Buffer.byteLength(JSON.stringify(event.value)) <= writeOptions.maxMessageBytes));
});
