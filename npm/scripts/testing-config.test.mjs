import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { snapshotInputs, prepareGeneration } from '../fireemu/testing-snapshot.mjs';

const binaryPath = process.env.FIREEMU_TEST_BINARY;
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fireemu-config-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const cwd = join(root, 'project');
  const world = join(root, 'world');
  await mkdir(cwd);
  await mkdir(world);
  return { root, cwd, world };
}

for (const extension of ['toml', 'TOML', 'json']) {
  test(`snapshot reads ${extension} config and retains creation inputs`, { skip: extension !== 'json' && !binaryPath }, async t => {
    const { root, cwd, world } = await fixture(t);
    await mkdir(join(cwd, 'config'));
    await writeFile(join(cwd, 'rules.txt'), 'original rules');
    await writeFile(join(cwd, 'config', 'firebase.json'), '{"firestore":{"rules":"firebase.rules"}}');
    await writeFile(join(cwd, 'config', 'firebase.rules'), 'firebase rules');
    const path = join(cwd, 'config', `fireemu.${extension}`);
    const config = { schemaVersion: 1, profile: 'strict', firebaseJson: 'firebase.json', rules: { source: 'rules.txt' } };
    await writeFile(path, extension === 'json' ? JSON.stringify(config) : 'schemaVersion = 1\nprofile = "strict"\nfirebaseJson = "firebase.json"\n[rules]\nsource = "rules.txt"\n');
    const snapshot = await snapshotInputs({ cwd, config: path, binaryPath }, world);
    assert.equal(snapshot.config.profile, 'strict');
    assert.equal(await readFile(snapshot.config.rules.source, 'utf8'), 'original rules');
    const firebase = JSON.parse(await readFile(snapshot.config.firebaseJson, 'utf8'));
    assert.equal(await readFile(firebase.firestore.rules, 'utf8'), 'firebase rules');
    await writeFile(path, 'invalid replacement');
    await writeFile(join(cwd, 'rules.txt'), 'changed rules');
    for (const name of ['generation-1', 'generation-2']) {
      const generation = await prepareGeneration(snapshot, join(root, name));
      const copied = JSON.parse(await readFile(generation.configPath, 'utf8'));
      assert.equal(copied.schemaVersion, 1);
      assert.equal(await readFile(copied.rules.source, 'utf8'), 'original rules');
    }
  });
}

for (const [extension, text, reason] of [
  ['toml', 'schemaVersion = [', /./],
  ['toml', 'profile = "strict"', /schemaVersion/],
  ['toml', 'schemaVersion = 1\n[daemon]\nclockStart = 2026-01-01T00:00:00Z', /quoted string/],
  ['toml', 'schemaVersion = 1\nvalue = inf', /non-finite/],
  ['json', '{', /./],
]) {
  test(`config error identifies ${extension} path: ${text}`, { skip: extension === 'toml' && !binaryPath }, async t => {
    const { cwd, world } = await fixture(t);
    const path = join(cwd, `broken.${extension}`);
    await writeFile(path, text);
    await assert.rejects(snapshotInputs({ cwd, config: path, binaryPath }, world), error => {
      assert.ok(error.message.includes(path), error.message);
      assert.ok(error.message.includes(extension.toUpperCase()), error.message);
      assert.match(error.message, reason);
      return true;
    });
  });
}

test('firebase.json and in-memory canonical config remain supported', async t => {
  const { cwd, world, root } = await fixture(t);
  await writeFile(join(cwd, 'firebase.json'), '{"firestore":{"rules":"firestore.rules"}}');
  await writeFile(join(cwd, 'firestore.rules'), 'rules');
  const firebase = await snapshotInputs({ cwd, config: 'firebase.json' }, world);
  const document = JSON.parse(await readFile(firebase.config.firebaseJson, 'utf8'));
  assert.equal(await readFile(document.firestore.rules, 'utf8'), 'rules');
  const other = join(root, 'other');
  await mkdir(other);
  const input = { schemaVersion: 1, profile: 'strict' };
  const object = await snapshotInputs({ cwd, config: input }, other);
  assert.equal(object.config.profile, 'strict');
  assert.deepEqual(input, { schemaVersion: 1, profile: 'strict' });
});

test('TOML parser timeout retires its native child', { skip: process.platform === 'win32' }, async t => {
  const { root, cwd, world } = await fixture(t);
  const pidFile = join(root, 'parser.pid');
  const parser = join(root, 'slow-parser');
  await writeFile(parser, `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); setInterval(() => {}, 1000);\n`, { mode: 0o700 });
  await writeFile(join(cwd, 'fireemu.toml'), 'schemaVersion = 1');
  await assert.rejects(snapshotInputs({ cwd, config: 'fireemu.toml', binaryPath: parser, startupTimeoutMs: 500 }, world), error => {
    assert.ok(error.message.includes('TOML'));
    assert.equal(error.cause.signal, 'SIGKILL');
    return true;
  });
  const pid = Number(await readFile(pidFile, 'utf8'));
  assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
});
