// Tests for the SDK adapter boundary. They never import the firebase SDK, never
// open a socket and never read a credential.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  MODE_LOCAL,
  artifactDigest,
  MODE_PRODUCTION,
  admitMode,
  createDeps,
  readPasswordFromFd,
  sourceDigests,
} from './listen_sdk_adapter.mjs';

test('local mode is admitted and production mode is refused', () => {
  assert.deepEqual(admitMode(MODE_LOCAL), { ok: true, value: MODE_LOCAL });
  const blocked = admitMode(MODE_PRODUCTION);
  assert.equal(blocked.ok, false);
  assert.match(blocked.error, /BLOCKED_OWNER/);
});

test('production stays refused even when a permission is supplied', () => {
  const refused = admitMode(MODE_PRODUCTION, { permission: 'o6-listen-sdk-0f1e2d3c4b5a6978' });
  assert.equal(refused.ok, false);
  assert.match(refused.error, /not implemented/);
});

test('an unknown mode is refused by name', () => {
  assert.deepEqual(admitMode('oracle'), { ok: false, error: 'unknown-mode:oracle' });
});

test('a password is read from a private descriptor, never from argv', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'o6-adapter-'));
  const file = path.join(dir, 'secret');
  writeFileSync(file, 'hunter2\n', { mode: 0o600 });
  const fd = openSync(file, 'r');
  try {
    assert.equal(readPasswordFromFd(fd), 'hunter2');
  } finally {
    closeSync(fd);
    unlinkSync(file);
  }
  assert.equal(readPasswordFromFd(undefined), null);
  assert.equal(readPasswordFromFd(''), null);
  assert.throws(() => readPasswordFromFd(0), /private descriptor/);
  assert.throws(() => readPasswordFromFd('stdin'), /private descriptor/);
});

test('source digests are recomputed from disk and missing files are explicit', () => {
  const digests = sourceDigests(process.cwd(), [
    'tools/compat-broad/fs-listen-resume/listen_collector.mjs',
    'tools/compat-broad/fs-listen-resume/does-not-exist.mjs',
  ]);
  assert.match(digests['tools/compat-broad/fs-listen-resume/listen_collector.mjs'], /^[0-9a-f]{64}$/);
  assert.equal(digests['tools/compat-broad/fs-listen-resume/does-not-exist.mjs'], 'missing');
});

test('the adapter clock emits integer milliseconds for transport timelines', () => {
  const deps = createDeps(fakeSdk([]), { primary: { db: 'db', auth: 'auth' } });
  const atMs = deps.now();
  assert.equal(Number.isSafeInteger(atMs), true);
  assert.ok(atMs >= 0);
});

const fakeSdk = calls => ({
  doc: (db, docPath) => ({ db, docPath }),
  collection: (db, collectionPath) => ({ db, collectionPath }),
  query: (collection, ...constraints) => ({ collection, constraints }),
  where: (...args) => ({ kind: 'where', args }),
  orderBy: (...args) => ({ kind: 'orderBy', args }),
  limit: value => ({ kind: 'limit', value }),
  setDoc: async (ref, fields) => calls.push(['setDoc', ref.docPath, fields]),
  deleteDoc: async ref => calls.push(['deleteDoc', ref.docPath]),
  getDocFromServer: async ref => ({
    metadata: { fromCache: false, hasPendingWrites: false },
    exists: () => ref.docPath.endsWith('alpha'),
    data: () => ({ owner: 'o6-listen:x' }),
  }),
  onSnapshot: (target, options, handlers) => {
    calls.push(['onSnapshot', target, options]);
    return () => calls.push(['unsubscribe']);
  },
  disableNetwork: async () => calls.push(['disableNetwork']),
  enableNetwork: async () => calls.push(['enableNetwork']),
  signInWithEmailAndPassword: async (auth, email) => calls.push(['signIn', email]),
  signOut: async () => calls.push(['signOut']),
});

test('the query listener binds the declared filter, order and limit', () => {
  const calls = [];
  const deps = createDeps(fakeSdk(calls), { primary: { db: 'db', auth: 'auth' } });
  deps.firestore.onQuerySnapshot(
    'primary',
    { parent: 'o6_listen/abc', target: 'docs', where: ['rank', '<', 10], orderBy: ['rank', 'asc'], limit: 10 },
    { includeMetadataChanges: true },
    () => {},
    () => {},
  );
  const [, target, options] = calls.find(entry => entry[0] === 'onSnapshot');
  assert.equal(target.collection.collectionPath, 'o6_listen/abc/docs');
  assert.deepEqual(
    target.constraints.map(constraint => constraint.kind),
    ['where', 'orderBy', 'limit'],
  );
  assert.deepEqual(target.constraints[0].args, ['rank', '<', 10]);
  assert.equal(options.includeMetadataChanges, true);
});

test('getDoc reports absence without inventing fields', async () => {
  const deps = createDeps(fakeSdk([]), { primary: { db: 'db', auth: 'auth' } });
  const present = await deps.firestore.getDoc('primary', 'o6_listen/abc/docs/alpha');
  const absent = await deps.firestore.getDoc('primary', 'o6_listen/abc/docs/beta');
  assert.equal(present.exists, true);
  assert.deepEqual(absent, { exists: false, fields: null, updateTime: null });
});

test('the auth binding never returns the password it used', async () => {
  const calls = [];
  const deps = createDeps(fakeSdk(calls), {
    primary: { db: 'db', auth: 'auth', account: { email: 'o6@example.test', password: 'hunter2' } },
  });
  const result = await deps.auth.signIn('primary');
  assert.equal(result, undefined);
  assert.deepEqual(calls, [['signIn', 'o6@example.test']]);
});

test('the runtime artifact digest is computed from the binary, not declared', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'o6-artifact-'));
  const file = path.join(dir, 'fireemu');
  writeFileSync(file, 'not really a binary');
  try {
    const digest = artifactDigest(file);
    assert.match(digest, /^[0-9a-f]{64}$/);
    writeFileSync(file, 'a different binary');
    assert.notEqual(artifactDigest(file), digest);
  } finally {
    unlinkSync(file);
  }
  assert.equal(artifactDigest(null), null);
  assert.equal(artifactDigest(path.join(dir, 'absent')), 'unreadable');
});
