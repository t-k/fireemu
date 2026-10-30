// Local-only Admin SDK smoke test. The generated key is synthetic and never leaves this process.
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { cert, initializeApp, deleteApp } from 'firebase-admin/app';
import { getStorage } from 'firebase-admin/storage';

assert.ok(process.env.FIREBASE_STORAGE_EMULATOR_HOST || process.env.STORAGE_EMULATOR_HOST);
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const app = initializeApp({
  credential: cert({
    projectId: 'demo-signed-put',
    clientEmail: 'fixture@demo-signed-put.iam.gserviceaccount.com',
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  }),
  storageBucket: 'demo-signed-put.appspot.com',
});
try {
  const file = getStorage(app).bucket().file('signed put/a # image.png');
  const [url] = await file.getSignedUrl({
    version: 'v4', action: 'write', expires: Date.now() + 5 * 60 * 1000,
    contentType: 'image/png', extensionHeaders: { 'x-goog-content-length-range': '0,10485760' },
  });
  const target = new URL(url);
  const host = process.env.STORAGE_EMULATOR_HOST || `http://${process.env.FIREBASE_STORAGE_EMULATOR_HOST}`;
  assert.equal(target.origin, new URL(host).origin);
  const bytes = Uint8Array.from([137, 80, 78, 71]);
  const response = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'image/png', 'x-goog-content-length-range': '0,10485760' }, body: bytes });
  assert.equal(response.status, 200, await response.text());
  assert.equal((await file.exists())[0], true);
  assert.deepEqual((await file.download())[0], Buffer.from(bytes));
} finally {
  await deleteApp(app);
}
