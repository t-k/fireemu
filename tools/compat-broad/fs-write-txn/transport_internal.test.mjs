import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertReadyForWire,
  plainError,
  prepareFixedTlsTransport,
} from './transport_internal.mjs';

const base = {
  projectId: 'fireemu-test',
  sslCreds: {},
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
  for (const field of ['endpoint', 'apiEndpoint', 'servicePath', 'host', 'port', 'keyFilename', 'credentials', 'useADC']) {
    assert.throws(() => prepareFixedTlsTransport({ ...base, [field]: field === 'port' ? 443 : 'override' }), /override|fixed/);
  }
  assert.throws(() => prepareFixedTlsTransport({ ...base, sslCreds: undefined }), /TLS/);
  assert.throws(() => prepareFixedTlsTransport({ ...base, metadata: {} }), /authorization/);
});

test('checks metadata expiry and absolute phase deadline after asynchronous readiness', async () => {
  const prepared = prepareFixedTlsTransport(base);
  let released = false;
  const waitForReady = Promise.resolve().then(() => { released = true; });
  await assert.rejects(() => assertReadyForWire(prepared, { waitForReady, now: () => 2_000 }), /metadata expired/);
  assert.equal(released, true);
  const phaseExpired = prepareFixedTlsTransport({ ...base, metadataExpiresAt: 4_000 });
  await assert.rejects(() => assertReadyForWire(phaseExpired, { waitForReady: Promise.resolve(), now: () => 3_000 }), /phase deadline/);
  assert.equal(await assertReadyForWire(prepared, { waitForReady: Promise.resolve(), now: () => 1_000 }), prepared);
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
