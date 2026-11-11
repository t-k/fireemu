import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { buildCombination, main, parseCombination, readInstalledVersions } from './sdk-latest-record.mjs';

const versions = { fireemu: '0.49.0', firebase: '13.2.0', firebaseAdmin: '14.5.0', firebaseFunctions: '7.4.0' };
const input = { suite: 'light', versions, recordedOn: '2026-11-12', runId: '1234567890', smokes: ['storage', 'client'] };

for (const suite of ['light', 'broad']) {
  test(`${suite} records round-trip through JSON`, () => {
    const record = buildCombination({ ...input, suite });
    assert.deepEqual(record, { schemaVersion: 1, ...input, suite });
    assert.deepEqual(parseCombination(JSON.parse(JSON.stringify(record))), record);
  });
}

test('invalid combination inputs are rejected', () => {
  const invalid = [
    { suite: 'nightly' }, { recordedOn: '2026-02-30' }, { recordedOn: '2026/11/12' },
    { recordedOn: '' }, { runId: '12a' }, { versions: { ...versions, firebase: '1.2' } },
    { smokes: ['pubsub'] }, { smokes: ['storage', 'storage'] }, { smokes: [] },
    { versions: { firebase: '13.2.0', firebaseAdmin: '14.5.0', firebaseFunctions: null } },
    { versions: { ...versions, firebaseFunctions: undefined } },
  ];
  for (const change of invalid) assert.throws(() => buildCombination({ ...input, ...change }));
});

test('an empty runId is refused', () => {
  assert.throws(() => buildCombination({ ...input, runId: '' }));
});

test('a version with trailing text is refused', () => {
  assert.throws(() => buildCombination({ ...input, versions: { ...versions, fireemu: '0.49.0abc' } }));
});

test('parsed records reject unknown keys and unsupported schema versions', () => {
  const record = buildCombination(input);
  for (const value of [
    { ...record, schemaVersion: 2 }, { ...record, extra: true },
    { ...record, versions: { ...record.versions, extra: true } },
  ]) assert.throws(() => parseCombination(value));
});

test('an unknown flag is refused wherever it appears', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'sdk-latest-record-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, version] of [['fireemu', versions.fireemu], ['firebase', versions.firebase], ['firebase-admin', versions.firebaseAdmin]]) {
    const packageDir = join(dir, 'node_modules', name);
    await mkdir(packageDir, { recursive: true });
    await writeFile(join(packageDir, 'package.json'), JSON.stringify({ version }));
  }
  const out = join(dir, 'record.json');
  await assert.rejects(main(['--bogus', '--suite', 'light', '--install-dir', dir, '--out', out, '--smoke', 'storage']), /Unknown flag: --bogus/);
  await assert.rejects(readFile(out), { code: 'ENOENT' });
});

test('reads installed versions and writes records without overwriting', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'sdk-latest-record-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const packageVersions = { fireemu: versions.fireemu, firebase: versions.firebase, 'firebase-admin': versions.firebaseAdmin, 'firebase-functions': versions.firebaseFunctions };
  for (const name of ['fireemu', 'firebase']) {
    const packageDir = join(dir, 'node_modules', name);
    await mkdir(packageDir, { recursive: true });
    await writeFile(join(packageDir, 'package.json'), JSON.stringify({ version: packageVersions[name] }));
  }
  await assert.rejects(readInstalledVersions(dir), /firebase-admin/);
  for (const name of ['firebase-admin', 'firebase-functions']) {
    const packageDir = join(dir, 'node_modules', name);
    await mkdir(packageDir, { recursive: true });
    await writeFile(join(packageDir, 'package.json'), JSON.stringify({ version: packageVersions[name] }));
    if (name === 'firebase-admin') {
      assert.deepEqual(await readInstalledVersions(dir), { ...versions, firebaseFunctions: null });
    }
  }
  assert.deepEqual(await readInstalledVersions(dir), versions);
  const out = join(dir, 'record.json');
  const args = ['--suite', 'broad', '--install-dir', dir, '--out', out, '--smoke', 'functions', '--run-id', '1234567890', '--date', '2026-11-12'];
  const record = await main(args);
  const contents = await readFile(out, 'utf8');
  assert.equal(contents, `${JSON.stringify(record, null, 2)}\n`);
  assert.deepEqual(record, buildCombination({ ...input, suite: 'broad', smokes: ['functions'] }));
  await assert.rejects(main(args));
  assert.equal(await readFile(out, 'utf8'), contents);
  await assert.rejects(main(['--unknown']));
  await assert.rejects(main(['--install-dir', dir, '--out', out, '--smoke', 'storage']));
});
