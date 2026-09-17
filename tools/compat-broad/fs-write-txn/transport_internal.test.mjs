import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertReadyForWire,
  createLocalClient,
  createFixedTlsTransport,
  plainError,
  prepareFixedTlsTransport,
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
