import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, readdirSync, writeFileSync,
  statSync, symlinkSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { createLifecycleJournal } from './listen_journal.mjs';
import { ownedPaths, secondaryPaths } from './listen_collector.mjs';

const context = { nonce: 'd'.repeat(32), projectId: 'demo-local' };
function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'listen-checkpoint-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, 'private'); mkdirSync(dir, { mode: 0o700 });
  return { root, dir };
}
const complete = { complete: true, accountCleanupComplete: true,
  clientsComplete: true, documentsCleanupComplete: true };

test('checkpoints bind the account scope and form a private immutable hash chain', t => {
  const { dir } = fixture(t);
  const checkpoint = createLifecycleJournal(dir, context);
  checkpoint('account-create-intent');
  checkpoint('account-created', { uid: 'owned-uid', paths: ownedPaths(context.nonce, 'owned-uid') });
  checkpoint('documents-at-risk');
  checkpoint('lifecycle-result', complete);
  let previous = null;
  for (const file of readdirSync(dir).sort()) {
    const raw = readFileSync(path.join(dir, file));
    const row = JSON.parse(raw);
    assert.equal(row.previousSha256, previous);
    assert.equal(row.nonce, context.nonce); assert.equal(row.projectId, context.projectId);
    assert.equal(row.authorizesCleanup, false);
    assert.equal(statSync(path.join(dir, file)).mode & 0o777, 0o600);
    previous = createHash('sha256').update(raw).digest('hex');
  }
  assert.equal(readdirSync(dir).length, 5);
  assert.throws(() => checkpoint('lifecycle-result', complete), /checkpoint/);
});

for (const kind of ['existing', 'symlink', 'public-mode', 'missing']) {
  test(`journal refuses ${kind} destination`, t => {
    const { root, dir } = fixture(t); let target = dir;
    if (kind === 'existing') writeFileSync(path.join(dir, 'original'), 'KEEP');
    if (kind === 'symlink') { target = path.join(root, 'link'); symlinkSync(dir, target); }
    if (kind === 'public-mode') chmodSync(dir, 0o755);
    if (kind === 'missing') target = path.join(root, 'missing');
    assert.throws(() => createLifecycleJournal(target, context));
    if (kind === 'existing') assert.equal(readFileSync(path.join(dir, 'original'), 'utf8'), 'KEEP');
  });
}
for (const [phase, value] of [
  ['account-create-intent', { password: 'DO-NOT-WRITE' }],
  ['documents-at-risk', {}],
  ['lifecycle-result', { ...complete, complete: 1 }],
  ['unknown-phase', {}],
]) {
  test(`invalid ${phase} checkpoint permanently latches the journal`, t => {
    const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
    assert.throws(() => write(phase, value), /checkpoint/);
    assert.throws(() => write('lifecycle-result', complete), /latched/);
    assert.deepEqual(readdirSync(dir), ['0-ready.json']);
    assert.ok(!readFileSync(path.join(dir, '0-ready.json'), 'utf8').includes('DO-NOT-WRITE'));
  });
}
for (const mutation of ['uid', 'paths', 'extra', 'foreign-run']) {
  test(`account checkpoint rejects ${mutation} drift`, t => {
    const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
    write('account-create-intent');
    const value = { uid: 'owned-uid', paths: ownedPaths(context.nonce, 'owned-uid') };
    if (mutation === 'uid') value.uid = '../other';
    if (mutation === 'paths') value.paths.alpha = 'unowned/doc';
    if (mutation === 'extra') value.paths.password = 'DO-NOT-WRITE';
    if (mutation === 'foreign-run') value.paths = ownedPaths('a'.repeat(32), value.uid);
    assert.throws(() => write('account-created', value));
    assert.equal(readdirSync(dir).length, 2);
  });
}

test('a publication collision cannot overwrite data or continue after failure', t => {
  const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
  const next = path.join(dir, '1-account-create-intent.json'); writeFileSync(next, 'KEEP');
  assert.throws(() => write('account-create-intent'));
  assert.equal(readFileSync(next, 'utf8'), 'KEEP');
  assert.throws(() => write('lifecycle-result', complete), /latched/);
});

test('incomplete lifecycle remains incomplete, without granting cleanup permission', t => {
  const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
  write('account-create-intent');
  write('lifecycle-result', { ...complete, complete: false, accountCleanupComplete: false });
  const value = JSON.parse(readFileSync(path.join(dir, '4-lifecycle-result.json')));
  assert.equal(value.value.complete, false); assert.equal(value.authorizesCleanup, false);
});

// Success requires the complete operation prefix and all three cleanup claims.
// Failure plus successful cleanup remains representable; observations can fail
// even when the resources and SDK clients were fully recovered.
for (let mask = 1; mask < 8; mask++) {
  test(`lifecycle success refuses incomplete cleanup mask ${mask}`, t => {
    const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
    write('account-create-intent');
    write('account-created', { uid: 'owned-uid', paths: ownedPaths(context.nonce, 'owned-uid') });
    write('documents-at-risk');
    const value = { ...complete };
    ['accountCleanupComplete', 'clientsComplete', 'documentsCleanupComplete']
      .forEach((key, index) => { if (mask & (1 << index)) value[key] = false; });
    assert.throws(() => write('lifecycle-result', value), /checkpoint/);
    assert.equal(readdirSync(dir).length, 4);
    assert.throws(() => write('lifecycle-result', complete), /latched/);
  });
}
for (const progress of [0, 1, 2]) {
  test(`successful lifecycle cannot skip operation prefix at ${progress}`, t => {
    const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
    if (progress >= 1) write('account-create-intent');
    if (progress >= 2) write('account-created', { uid: 'owned-uid', paths: ownedPaths(context.nonce, 'owned-uid') });
    assert.throws(() => write('lifecycle-result', complete), /checkpoint/);
    assert.equal(readdirSync(dir).length, progress + 1);
  });
  test(`failed observations can report cleanup after prefix ${progress}`, t => {
    const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
    if (progress >= 1) write('account-create-intent');
    if (progress >= 2) write('account-created', { uid: 'owned-uid', paths: ownedPaths(context.nonce, 'owned-uid') });
    write('lifecycle-result', { ...complete, complete: false });
    const record = JSON.parse(readFileSync(path.join(dir, '4-lifecycle-result.json')));
    assert.equal(record.value.complete, false);
    assert.equal(record.authorizesCleanup, false);
  });
}

test('the account checkpoint may record the second principal with its own path', t => {
  const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
  write('account-create-intent');
  write('account-created', { uid: 'owned-uid', paths: ownedPaths(context.nonce, 'owned-uid'),
    secondaryUid: 'second-uid', secondaryPaths: secondaryPaths(context.nonce, 'second-uid') });
  const record = JSON.parse(readFileSync(path.join(dir, '2-account-created.json'), 'utf8'));
  assert.equal(record.value.secondaryUid, 'second-uid');
  assert.deepEqual(record.value.secondaryPaths, { privateB: 'o6_listen_private/second-uid' });
});

for (const mutation of ['same-uid', 'wrong-path', 'missing-paths', 'unsafe-uid', 'foreign-run']) {
  test(`the second principal's checkpoint rejects ${mutation}`, t => {
    const { dir } = fixture(t); const write = createLifecycleJournal(dir, context);
    write('account-create-intent');
    const value = { uid: 'owned-uid', paths: ownedPaths(context.nonce, 'owned-uid'),
      secondaryUid: 'second-uid', secondaryPaths: secondaryPaths(context.nonce, 'second-uid') };
    if (mutation === 'same-uid') value.secondaryUid = 'owned-uid';
    if (mutation === 'wrong-path') value.secondaryPaths.privateB = 'o6_listen_private/owned-uid';
    if (mutation === 'missing-paths') delete value.secondaryPaths;
    if (mutation === 'unsafe-uid') value.secondaryUid = 'a/b';
    if (mutation === 'foreign-run') value.secondaryPaths = { privateB: 'other/second-uid' };
    assert.throws(() => write('account-created', value));
    assert.equal(readdirSync(dir).length, 2);
  });
}
