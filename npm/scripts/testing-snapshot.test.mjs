import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, realpath, readdir, open, chmod, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, delimiter, relative, isAbsolute } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants as fsConstants } from 'node:fs';
import fsp from 'node:fs/promises';
import test from 'node:test';
import { snapshotInputs, prepareGeneration, readRegularFile, cloneSupport } from '../fireemu/testing-snapshot.mjs';
import { createTestWorld } from '../fireemu/testing.mjs';

const exec = promisify(execFile);
const directoryLink = process.platform === 'win32' ? 'junction' : 'dir';

test('configuration open cancellation closes a handle returned after abort', async t => {
  const root = await mkdtemp(join(tmpdir(), 'fireemu-world-open-cancel-'));
  let openHandle;
  t.after(async () => { if (openHandle) await openHandle.close().catch(() => {}); await rm(root, { recursive: true, force: true }); });
  const path = join(root, 'config.json');
  await writeFile(path, '{}');
  const controller = new AbortController();
  const reason = Error('cancel during configuration open');
  let releaseOpen, markStarted;
  const release = new Promise(resolve => { releaseOpen = resolve; });
  const started = new Promise(resolve => { markStarted = resolve; });
  const delayedOpen = async (file, flags) => {
    markStarted();
    await release;
    openHandle = await open(file, flags);
    return openHandle;
  };
  const pending = readRegularFile(path, controller.signal, delayedOpen);
  await started;
  controller.abort(reason);
  releaseOpen();
  await assert.rejects(pending, error => error === reason);
  assert.ok(openHandle, 'open resolved with an owned file handle');
  await assert.rejects(openHandle.stat(), { code: 'EBADF' });
});

for (const mode of ['implicit', 'explicit-without-node-path', 'explicit-empty', 'explicit-global']) {
  test(`test world NODE_PATH requires explicit environment selection: ${mode}`, async t => {
    const f = await fixture(t);
    await linkedRepository(f);
    const temporary = join(f.root, 'temporary');
    await mkdir(temporary);
    const settings = { cwd: f.root, functionsSource: f.source, services: ['auth', 'functions'], binaryPath: process.execPath, tempRoot: temporary };
    const script = `
      import assert from 'node:assert/strict';
      import { readdir } from 'node:fs/promises';
      import { createTestWorld } from ${JSON.stringify(new URL('../fireemu/testing.mjs', import.meta.url).href)};
      const settings = ${JSON.stringify(settings)};
      const mode = ${JSON.stringify(mode)};
      if (mode !== 'implicit') {
        settings.env = { ...process.env };
        if (mode === 'explicit-empty') settings.env.NODE_PATH = '';
        if (mode === 'explicit-without-node-path') delete settings.env.NODE_PATH;
      }
      // Node cannot act as the daemon: reaching its startup error proves snapshot completion.
      await assert.rejects(createTestWorld(settings), mode === 'explicit-global' ? /Cannot snapshot NODE_PATH/ : /fireemu could not start test world/);
      assert.deepEqual(await readdir(${JSON.stringify(temporary)}), []);
    `;
    await exec(process.execPath, ['--input-type=module', '-e', script], { env: { ...process.env, NODE_PATH: f.modules }, timeout: 10000 });
  });
}

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'fireemu-node-path-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, 'source'), modules = join(root, 'shared'), world = join(root, 'world');
  await Promise.all([source, modules, world].map(path => mkdir(path)));
  return { root, source, modules, world, options: { cwd: root, functionsSource: source, env: { NODE_PATH: 'shared' } } };
}
async function linkedRepository(f) {
  const repository = join(f.root, 'unrelated-repository');
  await mkdir(repository);
  await symlink(repository, join(f.modules, 'unused-tool'), directoryLink);
  await symlink(join(f.root, 'missing-directory'), join(repository, 'broken'), directoryLink);
  return repository;
}
async function packageAt(modules, name, value) {
  const path = join(modules, name);
  await mkdir(path, { recursive: true });
  await writeFile(join(path, 'index.js'), `module.exports=${JSON.stringify(value)};`);
  return path;
}

test('snapshot and reset own relative and absolute Storage signed URL key files', async t => {
  const f = await fixture(t);
  const relativeKey = join(f.root, 'keys', 'relative.pem');
  const absoluteKey = join(f.root, 'outside', 'absolute.pem');
  await mkdir(join(f.root, 'keys'));
  await mkdir(join(f.root, 'outside'));
  await writeFile(relativeKey, 'relative creation key');
  await writeFile(absoluteKey, 'absolute creation key');
  const config = {
    schemaVersion: 1,
    storage: { signedUrlKeys: ['keys/relative.pem', absoluteKey] },
  };
  const snapshot = await snapshotInputs({ ...f.options, config }, f.world);
  assert.deepEqual(config.storage.signedUrlKeys, ['keys/relative.pem', absoluteKey]);
  assert.equal(snapshot.config.storage.signedUrlKeys.length, 2);
  assert.equal(await readFile(snapshot.config.storage.signedUrlKeys[0], 'utf8'), 'relative creation key');
  assert.equal(await readFile(snapshot.config.storage.signedUrlKeys[1], 'utf8'), 'absolute creation key');
  assert.ok(snapshot.config.storage.signedUrlKeys.every(path => {
    const rel = relative(snapshot.baseline, path);
    return rel !== '..' && !rel.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(rel);
  }));

  await writeFile(relativeKey, 'caller changed relative key');
  await rm(absoluteKey);
  for (const name of ['generation', 'reset']) {
    const generation = await prepareGeneration(snapshot, join(f.world, name));
    const prepared = JSON.parse(await readFile(generation.configPath, 'utf8'));
    assert.equal(prepared.storage.signedUrlKeys.length, 2);
    assert.equal(await readFile(prepared.storage.signedUrlKeys[0], 'utf8'), 'relative creation key');
    assert.equal(await readFile(prepared.storage.signedUrlKeys[1], 'utf8'), 'absolute creation key');
    assert.ok(prepared.storage.signedUrlKeys.every(path => {
      const rel = relative(generation.cwd, path);
      return rel !== '..' && !rel.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(rel);
    }));
    if (name === 'generation') await writeFile(prepared.storage.signedUrlKeys[0], 'generation-local mutation');
  }
});

test('Storage signed URL key snapshots preserve an empty list and reject missing files', async t => {
  const f = await fixture(t);
  const empty = await snapshotInputs({ ...f.options, config: { schemaVersion: 1, storage: { signedUrlKeys: [] } } }, f.world);
  assert.deepEqual(empty.config.storage.signedUrlKeys, []);

  const missing = join(f.root, 'missing.pem');
  const missingWorld = join(f.root, 'missing-world');
  await mkdir(missingWorld);
  await assert.rejects(
    snapshotInputs({ ...f.options, config: { schemaVersion: 1, storage: { signedUrlKeys: [missing] } } }, missingWorld),
    error => error.message.includes(missing) && error.message.includes('ENOENT'),
  );
});

for (const explicit of [false, true]) {
  test(`native world preserves ordinary environment and isolates opted-in globals: ${explicit}`, { skip: !process.env.FIREEMU_TEST_BINARY }, async t => {
    const f = await fixture(t);
    await writeFile(join(f.source, 'index.js'), 'module.exports = {};');
    if (explicit) await packageAt(f.modules, 'needed', 'creation');
    else await linkedRepository(f);
    const settings = { cwd: f.root, functionsSource: f.source, services: ['auth', 'functions'], binaryPath: process.env.FIREEMU_TEST_BINARY };
    const script = `
      import assert from 'node:assert/strict';
      import { writeFile } from 'node:fs/promises';
      import { createTestWorld } from ${JSON.stringify(new URL('../fireemu/testing.mjs', import.meta.url).href)};
      const settings = ${JSON.stringify(settings)};
      if (${explicit}) settings.env = { ...process.env };
      const world = await createTestWorld(settings);
      try {
        if (${explicit}) await writeFile(${JSON.stringify(join(f.modules, 'needed', 'index.js'))}, "module.exports='caller mutation'");
        for (let generation = 0; generation < 2; generation++) {
          if (generation) await world.reset();
          const child = await world.run(process.execPath, ['-e', "console.log(process.env.FIREEMU_TEST_PARENT_MARKER)"]);
          assert.equal(child.stdout.trim(), 'inherited');
          if (${explicit}) {
            assert.ok(world.environment.NODE_PATH.includes('generation-' + (generation + 1)));
            const result = await world.run(process.execPath, ['-e', "console.log(require('needed'))"]);
            assert.equal(result.stdout.trim(), 'creation');
          } else assert.equal(world.environment.NODE_PATH, '');
        }
      } finally { await world.dispose(); }
    `;
    await exec(process.execPath, ['--input-type=module', '-e', script], { env: { ...process.env, NODE_PATH: f.modules, FIREEMU_TEST_PARENT_MARKER: 'inherited', FIREEMU_RUNNER_NODE: new URL('../../tools/runner-node/index.mjs', import.meta.url).pathname }, timeout: 30000 });
  });
}

test('NODE_PATH errors identify the original entry, copy root and complete external link chain', async t => {
  const f = await fixture(t), repository = await linkedRepository(f);
  await assert.rejects(snapshotInputs(f.options, f.world), error => {
    assert.ok(error.message.includes(`NODE_PATH entry \"shared\" (copy root ${JSON.stringify(f.modules)})`), error.message);
    for (const value of ['NODE_PATH', 'shared', f.modules, join(f.modules, 'unused-tool'), repository, join(repository, 'broken'), 'missing-directory', 'ENOENT']) {
      assert.ok(error.message.includes(value), `Missing ${value}: ${error.message}`);
    }
    let original = error;
    while (original.cause) original = original.cause;
    assert.equal(original.code, 'ENOENT');
    assert.ok(error.message.includes('nodePathExcludes'));
    return true;
  });
});

test('explicit NODE_PATH exclusions avoid unrelated repositories and retain private required globals across reset', async t => {
  const f = await fixture(t);
  await linkedRepository(f);
  const dependency = await packageAt(f.modules, 'needed', 'creation');
  const options = { ...f.options, nodePathExcludes: ['unused-tool'] };
  const snapshot = await snapshotInputs(options, f.world);
  assert.deepEqual(options.nodePathExcludes, ['unused-tool']);
  await writeFile(join(dependency, 'index.js'), "module.exports='caller mutation'");
  for (const name of ['generation', 'reset']) {
    const prepared = await prepareGeneration(snapshot, join(f.world, name));
    assert.deepEqual(await readdir(prepared.nodePath), ['needed']);
    const result = await exec(process.execPath, ['-e', "console.log(require('needed'))"], { env: { ...process.env, NODE_PATH: prepared.nodePath } });
    assert.equal(result.stdout.trim(), 'creation');
    await writeFile(join(prepared.nodePath, 'needed', 'index.js'), "module.exports='generation mutation'");
  }
});

test('NODE_PATH exclusions match exact scoped and unscoped package names, not prefixes', async t => {
  const f = await fixture(t);
  const names = ['tool', 'tool-extra', '@scope/tool', '@scope/tool-extra', '@other/tool', 'tool.js'];
  for (const name of names) await packageAt(f.modules, name, name);
  // Bounded generated subsets check exact matching independently of the filter implementation.
  for (let mask = 0; mask < 1 << names.length; mask++) {
    const exclusions = names.filter((_, index) => mask & (1 << index));
    const world = join(f.root, `world-${mask}`);
    await mkdir(world);
    const snapshot = await snapshotInputs({ ...f.options, nodePathExcludes: exclusions }, world);
    for (let index = 0; index < names.length; index++) {
      const path = join(snapshot.nodePaths[0], names[index], 'index.js');
      if (mask & (1 << index)) await assert.rejects(readFile(path), { code: 'ENOENT' });
      else assert.equal(await readFile(path, 'utf8'), `module.exports=${JSON.stringify(names[index])};`);
    }
  }
});

for (const invalid of [null, '', 'tool', {}, ['*'], ['@scope/*'], ['tool?'], ['tool[ab]'], ['tool{a,b}'], [' tool'], ['tool name'], ['@scope/ tool'], ['tool:stream'], [null], [1], [''], ['.'], ['..'], ['../tool'], ['/tool'], ['tool/nested'], ['@scope'], ['@scope/..'], ['@scope/tool/nested'], ['tool\\nested'], ['tool\0bad']]) {
  test(`invalid nodePathExcludes is rejected: ${JSON.stringify(invalid)}`, async t => {
    const f = await fixture(t);
    await assert.rejects(snapshotInputs({ ...f.options, nodePathExcludes: invalid }, f.world), error => {
      assert.ok(error instanceof TypeError);
      assert.match(error.message, /nodePathExcludes/);
      return true;
    });
  });
}

test('excluding one package does not suppress a different missing dependency', async t => {
  const f = await fixture(t);
  await linkedRepository(f);
  await symlink(join(f.root, 'other-missing'), join(f.modules, 'needed'), directoryLink);
  await assert.rejects(snapshotInputs({ ...f.options, nodePathExcludes: ['unused-tool'] }, f.world), error => {
    assert.ok(error.message.includes(join(f.modules, 'needed')));
    assert.ok(error.message.includes('ENOENT'));
    return true;
  });
});

test('retained links into an excluded directory fail explicitly instead of creating dangling snapshot links', async t => {
  const f = await fixture(t);
  const excluded = await packageAt(f.modules, 'excluded', 'needed');
  await symlink(excluded, join(f.modules, 'retained'), directoryLink);
  await assert.rejects(snapshotInputs({ ...f.options, nodePathExcludes: ['excluded'] }, f.world), /excluded.*retained|retained.*excluded/);
});

test('exclusions do not prune Functions sources or an already captured ancestor node_modules root', async t => {
  const f = await fixture(t);
  const modules = join(f.root, 'node_modules');
  await packageAt(modules, 'needed', 'local');
  const snapshot = await snapshotInputs({ ...f.options, env: { NODE_PATH: modules }, nodePathExcludes: ['needed'] }, f.world);
  assert.equal(await readFile(join(snapshot.nodePaths[0], 'needed', 'index.js'), 'utf8'), 'module.exports="local";');
});

test('worlds without Functions never traverse unrelated NODE_PATH roots', async t => {
  const f = await fixture(t);
  await linkedRepository(f);
  const snapshot = await snapshotInputs({ cwd: f.root, env: f.options.env }, f.world);
  assert.deepEqual(snapshot.nodePaths, []);
});

test('NODE_PATH search order and absent root handling survive explicit exclusions', async t => {
  const f = await fixture(t), second = join(f.root, 'second');
  await mkdir(second);
  for (const modules of [f.modules, second]) {
    await packageAt(modules, 'needed', modules);
    await symlink(join(f.root, 'missing'), join(modules, 'unused-tool'), directoryLink);
  }
  const snapshot = await snapshotInputs({ ...f.options, env: { NODE_PATH: ['absent', 'shared', 'second'].join(delimiter) }, nodePathExcludes: ['unused-tool'] }, f.world);
  assert.equal(snapshot.nodePaths.length, 2);
  for (const [index, original] of [f.modules, second].entries()) {
    assert.deepEqual(await readdir(snapshot.nodePaths[index]), ['needed']);
    assert.equal(await readFile(join(snapshot.nodePaths[index], 'needed', 'index.js'), 'utf8'), `module.exports=${JSON.stringify(original)};`);
  }
});

test('createTestWorld snapshots caller exclusions and cleans failed snapshot directories', async t => {
  const f = await fixture(t), temporary = join(f.root, 'temporary');
  await mkdir(temporary);
  await linkedRepository(f);
  const exclusions = [];
  const pending = createTestWorld({ ...f.options, binaryPath: process.execPath, tempRoot: temporary, nodePathExcludes: exclusions });
  exclusions.push('unused-tool');
  await assert.rejects(pending, /NODE_PATH/);
  assert.deepEqual(await readdir(temporary), []);
});

test('snapshot timeout names its phase, removes partial input and never starts the daemon', { timeout: 20_000 }, async t => {
  const f = await fixture(t), temporary = join(f.root, 'temporary');
  await mkdir(temporary);
  const source = join(f.root, 'slow-functions');
  await mkdir(source);
  const input = join(source, 'large.bin'), inputBytes = 96 * 1024 * 1024;
  const handle = await open(input, 'w');
  await handle.truncate(inputBytes);
  await handle.close();
  const marker = join(f.root, 'daemon-started');
  const daemon = join(f.root, 'marker-daemon');
  await writeFile(daemon, `#!/usr/bin/env node\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started');\n`);
  await chmod(daemon, 0o755);

  await assert.rejects(createTestWorld({
    cwd: f.root,
    functionsSource: source,
    services: ['auth', 'functions'],
    env: { ...process.env, NODE_PATH: '' },
    binaryPath: daemon,
    tempRoot: temporary,
    snapshotTimeoutMs: 5,
  }), /test world snapshot timed out/);
  await assert.rejects(readFile(marker), { code: 'ENOENT' });
  assert.deepEqual(await readdir(temporary), []);
});

test('Firebase JSON overrides preserve the alias file when both configurations are snapshotted', async t => {
  const f = await fixture(t);
  const aliases = JSON.stringify({ projects: { default: 'demo-test-worlds' } });
  await writeFile(join(f.root, 'firebase.json'), JSON.stringify({ emulators: { auth: { port: 9099 } } }));
  await writeFile(join(f.root, 'firebase.test.json'), JSON.stringify({ emulators: { firestore: { port: 8080 } } }));
  await writeFile(join(f.root, '.firebaserc'), aliases);
  const snapshot = await snapshotInputs({
    cwd: f.root,
    config: { schemaVersion: 1, firebaseJson: 'firebase.json' },
    firebaseJson: 'firebase.test.json',
  }, f.world);
  assert.deepEqual(JSON.parse(await readFile(snapshot.config.firebaseJson, 'utf8')), { emulators: { firestore: { host: '127.0.0.1', port: 0 } } });
  assert.equal(await readFile(join(snapshot.baseline, '.firebaserc'), 'utf8'), aliases);
  assert.equal(await readFile(join(f.root, '.firebaserc'), 'utf8'), aliases);
});

test('snapshotTimeoutMs must fit the timer range before creating a world directory', async t => {
  const f = await fixture(t), temporary = join(f.root, 'temporary');
  await mkdir(temporary);
  for (const snapshotTimeoutMs of [2147483648, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER + 1, 0, -1, 1.5, NaN]) {
    await assert.rejects(createTestWorld({
      ...f.options,
      binaryPath: process.execPath,
      tempRoot: temporary,
      snapshotTimeoutMs,
    }), /snapshotTimeoutMs must be a positive integer no greater than 2147483647/);
  }
  assert.deepEqual(await readdir(temporary), []);
});

test('snapshotTimeoutMs accepts the maximum timer delay', async t => {
  const f = await fixture(t);
  const reason = Error('cancel before snapshot');
  await assert.rejects(createTestWorld({
    ...f.options,
    binaryPath: process.execPath,
    tempRoot: f.world,
    snapshotTimeoutMs: 2147483647,
    signal: AbortSignal.abort(reason),
  }), error => error.cause === reason);
  assert.deepEqual(await readdir(f.world), []);
});

test('external abort during an active file copy settles I/O before removing the world directory', { timeout: 30_000 }, async t => {
  const f = await fixture(t), temporary = join(f.root, 'temporary');
  await mkdir(temporary);
  const source = join(f.root, 'slow-functions');
  await mkdir(source);
  const input = join(source, 'large.bin'), inputBytes = 512 * 1024 * 1024;
  const handle = await open(input, 'w');
  await handle.truncate(inputBytes);
  await handle.close();
  const controller = new AbortController();
  const pending = createTestWorld({
    cwd: f.root,
    functionsSource: source,
    services: ['auth', 'functions'],
    env: { ...process.env, NODE_PATH: '' },
    binaryPath: process.execPath,
    tempRoot: temporary,
    snapshotTimeoutMs: 30_000,
    signal: controller.signal,
  });
  let outcome;
  pending.then(world => { outcome = { world }; }, error => { outcome = { error }; });
  let partialCopyObserved = false;
  const observationDeadline = Date.now() + 20_000;
  while (Date.now() < observationDeadline && !partialCopyObserved) {
    if (outcome?.error) assert.fail(`construction finished before cancellation: ${outcome.error.message}`);
    const [worldName] = await readdir(temporary);
    if (worldName) {
      try {
        const copied = await stat(join(temporary, worldName, 'baseline', 'functions-0', 'large.bin'));
        partialCopyObserved = copied.size > 0 && copied.size < inputBytes;
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
    if (!partialCopyObserved) await delay(2);
  }
  if (!partialCopyObserved) {
    controller.abort(Error('cancelled because no partial copy was observed'));
    await pending;
    assert.fail('expected to observe an active partial file copy');
  }

  const reason = Error('caller cancelled the snapshot');
  controller.abort(reason);
  await pending.then(
    () => assert.fail('expected aborted construction to reject'),
    error => {
      assert.match(error.message, /test world snapshot aborted/);
      assert.equal(error.cause, reason);
    },
  );
  assert.deepEqual(await readdir(temporary), []);
  await delay(25);
  assert.deepEqual(await readdir(temporary), []);
});

test('generation preparation abort removes its partial copy after the stream settles', { timeout: 30_000 }, async t => {
  await withCloneSupport(t, {});
  const f = await fixture(t), baseline = join(f.root, 'baseline'), generation = join(f.root, 'generation');
  await mkdir(baseline);
  const input = join(baseline, 'large.bin'), inputBytes = 512 * 1024 * 1024;
  const handle = await open(input, 'w');
  await handle.truncate(inputBytes);
  await handle.close();
  const controller = new AbortController();
  const reason = Error('cancel generation preparation');
  const pending = prepareGeneration({ baseline, config: { daemon: {} }, nodePaths: [] }, generation, controller.signal);
  let outcome;
  pending.then(value => { outcome = { value }; }, error => { outcome = { error }; });
  let partialCopyObserved = false;
  const observationDeadline = Date.now() + 20_000;
  while (Date.now() < observationDeadline && !partialCopyObserved) {
    if (outcome?.error) assert.fail(`generation preparation finished before cancellation: ${outcome.error.message}`);
    try {
      const copied = await stat(join(generation, 'inputs', 'large.bin'));
      partialCopyObserved = copied.size > 0 && copied.size < inputBytes;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (!partialCopyObserved) await delay(2);
  }
  if (!partialCopyObserved) {
    controller.abort(Error('cancelled because no partial generation copy was observed'));
    await pending;
    assert.fail('expected to observe an active generation file copy');
  }

  controller.abort(reason);
  await pending.then(
    () => assert.fail('expected aborted generation preparation to reject'),
    error => {
      assert.equal(error.name, 'AbortError');
      assert.equal(error.cause, reason);
    },
  );
  await assert.rejects(stat(generation), { code: 'ENOENT' });
  await delay(25);
  await assert.rejects(stat(generation), { code: 'ENOENT' });
});


test('scoped exclusions follow an external scope directory link before visiting excluded packages', async t => {
  const f = await fixture(t), scope = join(f.root, 'external-scope');
  await mkdir(scope);
  await symlink(scope, join(f.modules, '@scope'), directoryLink);
  await symlink(join(f.root, 'missing'), join(scope, 'unused'), directoryLink);
  await packageAt(scope, 'needed', 'creation');
  const snapshot = await snapshotInputs({ ...f.options, nodePathExcludes: ['@scope/unused'] }, f.world);
  const generation = await prepareGeneration(snapshot, join(f.world, 'generation'));
  assert.deepEqual(await readdir(join(generation.nodePath, '@scope')), ['needed']);
  await writeFile(join(scope, 'needed', 'index.js'), "module.exports='caller mutation'");
  const result = await exec(process.execPath, ['-e', "console.log(require('@scope/needed'))"], { env: { ...process.env, NODE_PATH: generation.nodePath } });
  assert.equal(result.stdout.trim(), 'creation');
});

test('scoped exclusions reject a linked scope already captured through another directory', async t => {
  const f = await fixture(t), scope = join(f.modules, 'shared-scope');
  await packageAt(scope, 'unused', 'also reachable');
  await symlink(scope, join(f.modules, '@scope'), directoryLink);
  await assert.rejects(snapshotInputs({ ...f.options, nodePathExcludes: ['@scope/unused'] }, f.world), /nodePathExcludes.*already captured|already captured.*nodePathExcludes/);
});

// Functions sources and dependencies are snapshotted only when a selected service loads them
// (model: PICT services x source x NODE_PATH, full order-3 product).
const serviceSelections = {
  default: undefined,
  auth: ['auth'],
  functions: ['functions'],
  'functions-codebase': ['functions:default'],
  'auth-and-functions': ['auth', 'functions'],
  'firestore-storage': ['firestore', 'storage'],
};
const functionsSources = ['none', 'functionsSource', 'firebase-json', 'config-source', 'manifest'];

async function selectionFixture(t, kind) {
  const f = await fixture(t);
  await mkdir(join(f.source, 'node_modules', 'dependency'), { recursive: true });
  await writeFile(join(f.source, 'index.js'), 'exports.main = 1;');
  await writeFile(join(f.source, 'node_modules', 'dependency', 'index.js'), 'module.exports = 2;');
  await packageAt(f.modules, 'global', 'shared');
  await writeFile(join(f.root, 'manifest.json'), '{}');
  const options = { cwd: f.root };
  if (kind === 'functionsSource') options.functionsSource = f.source;
  if (kind === 'firebase-json') {
    await writeFile(join(f.root, 'firebase.json'), JSON.stringify({ functions: [{ source: 'source', codebase: 'default' }], firestore: { rules: 'firestore.rules' } }));
    await writeFile(join(f.root, 'firestore.rules'), 'rules');
    options.firebaseJson = 'firebase.json';
  }
  if (kind === 'config-source') options.config = { schemaVersion: 1, functions: { source: 'source' } };
  if (kind === 'manifest') options.config = { schemaVersion: 1, functions: { manifest: 'manifest.json' } };
  return { f, options };
}

for (const [selection, services] of Object.entries(serviceSelections)) {
  for (const kind of functionsSources) {
    for (const nodePath of ['unset', 'set']) {
      test(`Functions snapshot follows the selected services: ${selection} / ${kind} / NODE_PATH ${nodePath}`, async t => {
        const { f, options } = await selectionFixture(t, kind);
        const selected = services === undefined || services.some(name => name.startsWith('functions'));
        const configured = kind !== 'none';
        const snapshot = await snapshotInputs({ ...options, services, env: nodePath === 'set' ? { NODE_PATH: 'shared' } : {} }, f.world);
        const copiedSource = ['functionsSource', 'firebase-json', 'config-source'].includes(kind);
        const baseline = await readdir(snapshot.baseline);
        assert.equal(baseline.some(name => name.startsWith('functions-')), selected && copiedSource, `baseline ${baseline}`);
        assert.equal(baseline.some(name => name.startsWith('node-path-')), selected && configured && nodePath === 'set');
        assert.equal(snapshot.nodePaths.length, selected && configured && nodePath === 'set' ? 1 : 0);
        assert.equal(snapshot.functionsSkipped, !selected);
        assert.equal(snapshot.functionsConfigured, selected && configured);
        const files = await regularFiles(snapshot.baseline);
        assert.equal(snapshot.stats.files, files.length, 'statistics count every file the snapshot owns');
        assert.equal(snapshot.stats.bytes, files.reduce((sum, [, size]) => sum + size, 0));
        if (!selected) assert.equal(files.length, kind === 'firebase-json' ? 3 : 1, 'only the configuration and non-Functions inputs');
        const config = JSON.parse(await readFile(join(snapshot.baseline, 'fireemu.json'), 'utf8'));
        assert.equal(config.functions.clock.date, 'virtual', 'clock policy survives');
        if (!selected) {
          assert.equal(config.functions.source, undefined);
          assert.equal(config.functions.manifest, undefined);
          assert.ok(!JSON.stringify(config).includes(f.source), 'no caller Functions path in the snapshot');
          if (kind === 'firebase-json') {
            const firebase = JSON.parse(await readFile(config.firebaseJson, 'utf8'));
            assert.equal(firebase.functions, undefined);
            assert.ok(firebase.firestore.rules.startsWith(snapshot.baseline), 'other services are still snapshotted');
          }
        } else if (copiedSource) {
          assert.ok(snapshot.stats.files >= 2, 'source and dependency were copied');
        }
      });
    }
  }
}

test('selecting Functions in a codebase-qualified form snapshots every configured source', async t => {
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const snapshot = await snapshotInputs({ ...options, services: ['auth', 'functions:other'] }, f.world);
  assert.equal(snapshot.functionsSkipped, false);
  assert.ok((await readdir(snapshot.baseline)).some(name => name.startsWith('functions-')));
});

async function regularFiles(root) {
  const found = [];
  const visit = async directory => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) found.push([path, (await stat(path)).size]);
    }
  };
  await visit(root);
  return found;
}

test('snapshot and generation statistics count the copied files and bytes', async t => {
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  const configBytes = (await stat(join(snapshot.baseline, 'fireemu.json'))).size;
  assert.equal(snapshot.stats.files, 3, 'two source files and the configuration written beside them');
  assert.equal(snapshot.stats.bytes, 'exports.main = 1;'.length + 'module.exports = 2;'.length + configBytes);
  assert.ok(snapshot.stats.directories >= 3);
  assert.ok(Number.isInteger(snapshot.stats.elapsedMs) && snapshot.stats.elapsedMs >= 0);
  assert.ok(['copy', 'clone', 'mixed'].includes(snapshot.stats.method));
  const generation = await prepareGeneration(snapshot, join(f.world, 'generation-1'));
  const files = await regularFiles(join(f.world, 'generation-1', 'inputs'));
  assert.equal(generation.stats.files, files.length);
  assert.equal(generation.stats.bytes, files.reduce((sum, [, size]) => sum + size, 0));
  assert.ok(Number.isInteger(generation.stats.elapsedMs) && generation.stats.elapsedMs >= 0);
  assert.ok(Object.isFrozen(snapshot.stats) && Object.isFrozen(generation.stats));
});

test('statistics keep symbolic links apart from files and count rewritten Firebase files exactly', async t => {
  const { f, options } = await selectionFixture(t, 'firebase-json');
  await symlink(join(f.root, 'shared'), join(f.source, 'node_modules', 'linked'), directoryLink);
  const snapshot = await snapshotInputs({ ...options, services: ['functions', 'firestore'] }, f.world);
  const generation = await prepareGeneration(snapshot, join(f.world, 'generation-1'));
  assert.ok(generation.stats.symlinks >= 1);
  assert.equal(generation.stats.symlinks, snapshot.stats.symlinks);
  const files = await regularFiles(join(f.world, 'generation-1', 'inputs'));
  assert.equal(generation.stats.files, files.length, 'links are not files');
  assert.equal(generation.stats.bytes, files.reduce((sum, [, size]) => sum + size, 0), 'rewritten configuration bytes are included');
});

async function withCloneSupport(t, overrides) {
  const saved = { ...cloneSupport };
  Object.assign(cloneSupport, { file: false, tree: false }, overrides);
  t.after(() => Object.assign(cloneSupport, saved));
}

test('copy-on-write file clones are requested when enabled and generations stay independent', async t => {
  await withCloneSupport(t, { file: true });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const calls = [];
  const real = fsp.copyFile;
  t.mock.method(fsp, 'copyFile', async (source, destination, mode) => { calls.push(mode); return real(source, destination, fsConstants.COPYFILE_EXCL); });
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(mode => mode === (fsConstants.COPYFILE_FICLONE_FORCE | fsConstants.COPYFILE_EXCL)), 'only forced exclusive clones are requested');
  const first = await prepareGeneration(snapshot, join(f.world, 'generation-1'));
  const second = await prepareGeneration(snapshot, join(f.world, 'generation-2'));
  assert.equal(first.stats.method, 'clone');
  const config = JSON.parse(await readFile(first.configPath, 'utf8'));
  await writeFile(join(config.functions.source, 'index.js'), 'generation edit');
  assert.equal(await readFile(join(snapshot.baseline, 'functions-0', 'index.js'), 'utf8'), 'exports.main = 1;', 'the baseline keeps its bytes');
  const secondConfig = JSON.parse(await readFile(second.configPath, 'utf8'));
  assert.equal(await readFile(join(secondConfig.functions.source, 'index.js'), 'utf8'), 'exports.main = 1;');
  assert.equal(await readFile(join(f.source, 'index.js'), 'utf8'), 'exports.main = 1;', 'the caller keeps its bytes');
});

test('file clones are not attempted when the platform has none', async t => {
  await withCloneSupport(t, { file: false });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  let attempts = 0;
  t.mock.method(fsp, 'copyFile', async () => { attempts++; });
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  assert.equal(attempts, 0);
  assert.equal(snapshot.stats.method, 'copy');
});

test('a file system that refuses clones falls back to a real copy, once per source device', async t => {
  await withCloneSupport(t, { file: true });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  for (let index = 0; index < 4; index++) await writeFile(join(f.source, `extra-${index}.js`), `extra ${index}`);
  let attempts = 0;
  t.mock.method(fsp, 'copyFile', async () => { attempts++; throw Object.assign(Error('operation not supported'), { code: 'ENOTSUP' }); });
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  assert.equal(snapshot.stats.files, 7);
  assert.equal(snapshot.stats.method, 'copy');
  assert.equal(attempts, 1, 'the refusal disables clones for the rest of that device');
  const config = JSON.parse(await readFile(join(snapshot.baseline, 'fireemu.json'), 'utf8'));
  assert.equal(await readFile(join(config.functions.source, 'extra-3.js'), 'utf8'), 'extra 3');
  assert.equal(await readFile(join(config.functions.source, 'node_modules', 'dependency', 'index.js'), 'utf8'), 'module.exports = 2;');
});

test('a snapshot that clones some files and copies the rest reports a mixed method', async t => {
  await withCloneSupport(t, { file: true });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const real = fsp.copyFile;
  let calls = 0;
  t.mock.method(fsp, 'copyFile', async (source, destination) => {
    if (++calls === 1) return real(source, destination, fsConstants.COPYFILE_EXCL);
    throw Object.assign(Error('operation not supported'), { code: 'ENOTSUP' });
  });
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  assert.equal(snapshot.stats.method, 'mixed');
  assert.equal(calls, 2, 'one clone, then one refusal that disables clones');
  const config = JSON.parse(await readFile(join(snapshot.baseline, 'fireemu.json'), 'utf8'));
  assert.equal(await readFile(join(config.functions.source, 'index.js'), 'utf8'), 'exports.main = 1;');
});

test('a clone that leaves a partial file does not break the fallback copy', async t => {
  await withCloneSupport(t, { file: true });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  t.mock.method(fsp, 'copyFile', async (source, destination) => { await writeFile(destination, 'partial'); throw Object.assign(Error('cross-device'), { code: 'EXDEV' }); });
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  const config = JSON.parse(await readFile(join(snapshot.baseline, 'fireemu.json'), 'utf8'));
  assert.equal(await readFile(join(config.functions.source, 'index.js'), 'utf8'), 'exports.main = 1;');
});

test('a clone cancelled by the caller stops the snapshot instead of falling back', async t => {
  await withCloneSupport(t, { file: true });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const controller = new AbortController();
  t.mock.method(fsp, 'copyFile', async () => { controller.abort(Error('stop here')); throw Object.assign(Error('aborted'), { code: 'ECANCELED' }); });
  await assert.rejects(snapshotInputs({ ...options, services: ['functions'] }, f.world, controller.signal), /stop here/);
});

test('a source that cannot be read still fails when clones fall back to the real copy', async t => {
  if (process.getuid?.() === 0 || process.platform === 'win32') return t.skip('permissions are not enforced');
  await withCloneSupport(t, { file: true });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  t.mock.method(fsp, 'copyFile', async () => { throw Object.assign(Error('operation not supported'), { code: 'ENOTSUP' }); });
  await chmod(join(f.source, 'index.js'), 0o000);
  t.after(() => chmod(join(f.source, 'index.js'), 0o644).catch(() => {}));
  await assert.rejects(snapshotInputs({ ...options, services: ['functions'] }, f.world), /EACCES|permission denied/i);
});

test('the macOS tree clone preserves modes', () => {
  assert.deepEqual(cloneSupport.treeArguments('a', 'b'), ['-c', '-R', '-p', 'a', 'b']);
});

for (const platformClone of [false, true]) {
  test(`tree cloning preserves file and directory modes: ${platformClone ? 'macOS' : 'portable'}`, { skip: process.platform === 'win32' || (platformClone && process.platform !== 'darwin') }, async t => {
    let baseline, inputs;
    t.after(async () => {
      for (const root of [baseline, inputs]) if (root) await chmod(join(root, 'readonly'), 0o700).catch(() => {});
    });
    const f = await fixture(t);
    if (!platformClone) await withCloneSupport(t, { tree: true, treeCommand: 'cp', treeArguments: (source, destination) => ['-R', '-p', source, destination] });
    baseline = join(f.root, 'baseline');
    inputs = join(f.world, 'generation', 'inputs');
    await mkdir(baseline);
    const modes = { executable: 0o755, group: 0o640, file: 0o444, directory: 0o750, 'directory/inside': 0o640, readonly: 0o555, 'readonly/inside': 0o444 };
    for (const name of ['directory', 'readonly']) await mkdir(join(baseline, name));
    for (const name of ['executable', 'group', 'file', 'directory/inside', 'readonly/inside']) await writeFile(join(baseline, name), 'x');
    for (const [name, mode] of Object.entries(modes)) await chmod(join(baseline, name), mode);
    const previousUmask = process.umask(0o077);
    t.after(() => process.umask(previousUmask));
    try {
      const generation = await prepareGeneration({ baseline, config: { daemon: {} }, nodePaths: [], totals: { files: 5, directories: 3, symlinks: 0, bytes: 5 } }, join(f.world, 'generation'));
      assert.equal(generation.stats.method, 'clone');
      for (const name of Object.keys(modes)) assert.equal((await stat(join(inputs, name))).mode & 0o777, (await stat(join(baseline, name))).mode & 0o777, name);
    } finally {
      process.umask(previousUmask);
    }
  });
}

// The tree clone is the platform copy tool run over the whole baseline; plain `cp -R` stands in
// for `cp -c -R` so the path runs on every platform.
const plainCopy = { tree: true, treeCommand: 'cp', treeArguments: (source, destination) => ['-R', source, destination] };

test('a generation is cloned from the baseline as a tree with exact statistics, and stays independent', { skip: process.platform === 'win32' }, async t => {
  await withCloneSupport(t, plainCopy);
  const { f, options } = await selectionFixture(t, 'firebase-json');
  await symlink(join(f.root, 'shared'), join(f.source, 'node_modules', 'linked'), directoryLink);
  const snapshot = await snapshotInputs({ ...options, services: ['functions', 'firestore'] }, f.world);
  const first = await prepareGeneration(snapshot, join(f.world, 'generation-1'));
  assert.equal(first.stats.method, 'clone');
  const files = await regularFiles(join(f.world, 'generation-1', 'inputs'));
  assert.equal(first.stats.files, files.length);
  assert.equal(first.stats.bytes, files.reduce((sum, [, size]) => sum + size, 0));
  const sourceOf = async generation => JSON.parse(await readFile(JSON.parse(await readFile(generation.configPath, 'utf8')).firebaseJson, 'utf8')).functions[0].source;
  const source = await sourceOf(first);
  assert.ok(source.startsWith(join(f.world, 'generation-1')), 'paths point into the generation');
  assert.equal(await readFile(join(source, 'node_modules', 'dependency', 'index.js'), 'utf8'), 'module.exports = 2;');
  await writeFile(join(source, 'index.js'), 'generation edit');
  const second = await prepareGeneration(snapshot, join(f.world, 'generation-2'));
  assert.equal(await readFile(join(await sourceOf(second), 'index.js'), 'utf8'), 'exports.main = 1;');
});

test('a failing tree clone leaves nothing behind and the generation is copied file by file', { skip: process.platform === 'win32' }, async t => {
  await withCloneSupport(t, { tree: true, treeCommand: 'false', treeArguments: () => [] });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  const generation = await prepareGeneration(snapshot, join(f.world, 'generation-1'));
  assert.equal(generation.stats.method, 'copy');
  const files = await regularFiles(join(f.world, 'generation-1', 'inputs'));
  assert.equal(generation.stats.files, files.length);
  const config = JSON.parse(await readFile(generation.configPath, 'utf8'));
  assert.equal(await readFile(join(config.functions.source, 'index.js'), 'utf8'), 'exports.main = 1;');
});

test('a tree clone that leaves a partial directory is cleaned before the fallback', { skip: process.platform === 'win32' }, async t => {
  await withCloneSupport(t, { tree: true, treeCommand: process.execPath, treeArguments: (source, destination) => ['-e', "require('fs').mkdirSync(process.argv[1]+'/partial',{recursive:true});process.exit(1)", destination] });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  const generation = await prepareGeneration(snapshot, join(f.world, 'generation-1'));
  assert.equal(generation.stats.method, 'copy');
  assert.deepEqual((await readdir(join(f.world, 'generation-1', 'inputs'))).sort(), ['fireemu.json', 'functions-0']);
});

test('cancelling a tree clone stops the tool and removes the generation directory', { skip: process.platform === 'win32', timeout: 20_000 }, async t => {
  await withCloneSupport(t, { tree: true, treeCommand: process.execPath, treeArguments: () => ['-e', 'setTimeout(() => {}, 10000)'] });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  const controller = new AbortController();
  const pending = prepareGeneration(snapshot, join(f.world, 'generation-1'), controller.signal);
  await delay(100);
  controller.abort(Error('cancelled while cloning'));
  await assert.rejects(pending, /cancelled while cloning/);
  await assert.rejects(stat(join(f.world, 'generation-1')), { code: 'ENOENT' });
});

test('a Firebase file named by both the configuration and the option is counted once', async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, 'one.json'), JSON.stringify({ firestore: { rules: 'one.rules' } }));
  await writeFile(join(f.root, 'two.json'), JSON.stringify({ firestore: { rules: 'two.rules' } }));
  await writeFile(join(f.root, 'one.rules'), 'one');
  await writeFile(join(f.root, 'two.rules'), 'twelve bytes');
  const snapshot = await snapshotInputs({ cwd: f.root, services: ['firestore'], config: { schemaVersion: 1, firebaseJson: 'one.json' }, firebaseJson: 'two.json' }, f.world);
  const files = await regularFiles(snapshot.baseline);
  assert.equal(snapshot.stats.files, files.length);
  assert.equal(snapshot.stats.bytes, files.reduce((sum, [, size]) => sum + size, 0), 'the overwritten file counts once, at its final size');
  assert.equal(files.length, 4, 'firebase.json, the copied rules of the second file, fireemu.json and the first rules copy');
});

for (const tree of [false, true]) {
  test(`a generation counts configuration the baseline did not hold (tree clone ${tree})`, { skip: tree && process.platform === 'win32' }, async t => {
    await withCloneSupport(t, tree ? plainCopy : {});
    const f = await fixture(t);
    const baseline = join(f.root, 'baseline');
    await mkdir(baseline);
    await writeFile(join(baseline, 'data.txt'), 'twelve bytes');
    const generation = await prepareGeneration({ baseline, config: { daemon: {} }, nodePaths: [], totals: { files: 1, directories: 1, symlinks: 0, bytes: 12 } }, join(f.root, 'generation'));
    const files = await regularFiles(join(f.root, 'generation', 'inputs'));
    assert.deepEqual(files.map(([path]) => path.split('/').pop()).sort(), ['data.txt', 'fireemu.json']);
    assert.equal(generation.stats.files, 2, 'the newly written configuration is a file of the generation');
    assert.equal(generation.stats.bytes, files.reduce((sum, [, size]) => sum + size, 0));
  });
}

test('the elapsed time covers the copy', async t => {
  await withCloneSupport(t, { file: true });
  const { f, options } = await selectionFixture(t, 'functionsSource');
  const real = fsp.copyFile;
  t.mock.method(fsp, 'copyFile', async (source, destination) => { await delay(60); return real(source, destination, fsConstants.COPYFILE_EXCL); });
  const snapshot = await snapshotInputs({ ...options, services: ['functions'] }, f.world);
  assert.ok(snapshot.stats.elapsedMs >= 100, `two files at 60 ms each took ${snapshot.stats.elapsedMs} ms`);
  const generation = await prepareGeneration(snapshot, join(f.world, 'generation-1'));
  assert.ok(generation.stats.elapsedMs >= 150, `three clones at 60 ms each took ${generation.stats.elapsedMs} ms`);
});
