import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, realpath, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, delimiter } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';
import { snapshotInputs, prepareGeneration } from '../fireemu/testing-snapshot.mjs';
import { createTestWorld } from '../fireemu/testing.mjs';

const exec = promisify(execFile);
const directoryLink = process.platform === 'win32' ? 'junction' : 'dir';

for (const mode of ['implicit', 'explicit-without-node-path', 'explicit-empty', 'explicit-global']) {
  test(`test world NODE_PATH requires explicit environment selection: ${mode}`, async t => {
    const f = await fixture(t);
    await linkedRepository(f);
    const temporary = join(f.root, 'temporary');
    await mkdir(temporary);
    const settings = { cwd: f.root, functionsSource: f.source, services: ['auth'], binaryPath: process.execPath, tempRoot: temporary };
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

for (const explicit of [false, true]) {
  test(`native world preserves ordinary environment and isolates opted-in globals: ${explicit}`, { skip: !process.env.FIREEMU_TEST_BINARY }, async t => {
    const f = await fixture(t);
    if (explicit) await packageAt(f.modules, 'needed', 'creation');
    else await linkedRepository(f);
    const settings = { cwd: f.root, functionsSource: f.source, services: ['auth'], binaryPath: process.env.FIREEMU_TEST_BINARY };
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
    await exec(process.execPath, ['--input-type=module', '-e', script], { env: { ...process.env, NODE_PATH: f.modules, FIREEMU_TEST_PARENT_MARKER: 'inherited' }, timeout: 30000 });
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
