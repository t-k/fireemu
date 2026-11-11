import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

// Every value the package exports at runtime has a declaration, and every declared value exists at
// runtime, so a function added to (or dropped from) fireemu/testing or fireemu/control cannot leave
// the TypeScript surface behind. The comparison is made by the compiler the consumer test uses: the
// runtime export names are written into a probe that must equal the declared value exports.
const root = fileURLToPath(new URL('../../', import.meta.url));
const packageDirectory = join(root, 'npm/fireemu');
const compiler = process.env.FIREEMU_TYPESCRIPT_PATH ?? join(root, 'ui/node_modules/.bin/tsc');
const manifest = JSON.parse(readFileSync(join(packageDirectory, 'package.json'), 'utf8'));

export function compileProbe(name, runtimeNames, declarationDirectory = packageDirectory) {
  const directory = mkdtempSync(join(tmpdir(), 'fireemu types exports '));
  try {
    const union = runtimeNames.length === 0 ? 'never' : runtimeNames.map(item => JSON.stringify(item)).join(' | ');
    writeFileSync(join(directory, 'probe.mts'), `
import type * as declared from ${JSON.stringify(join(declarationDirectory, `${name}.mjs`).replaceAll('\\', '/'))};
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
export const exactlyTheRuntimeExports: Equal<keyof typeof declared, ${union}> = true;
`);
    writeFileSync(join(directory, 'tsconfig.json'), JSON.stringify({ compilerOptions: { strict: true, noEmit: true, target: 'ES2022', lib: ['ES2022', 'DOM'], types: [], module: 'NodeNext', moduleResolution: 'NodeNext', skipLibCheck: false }, files: ['probe.mts'] }));
    execFileSync(resolve(compiler), ['-p', join(directory, 'tsconfig.json')], { cwd: directory, stdio: 'pipe' });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

test('the package exposes exactly the declared subpaths, each with a shipped declaration', () => {
  assert.deepEqual(Object.keys(manifest.exports).sort(), ['./control', './package.json', './testing']);
  for (const name of ['testing', 'control']) {
    const entry = manifest.exports[`./${name}`];
    assert.equal(entry.types, `./${name}.d.mts`);
    assert.equal(entry.default, `./${name}.mjs`);
    for (const file of [`${name}.d.mts`, `${name}.mjs`]) assert(manifest.files.includes(file), `files must list ${file}`);
  }
});

for (const name of ['testing', 'control']) {
  test(`fireemu/${name}: runtime value exports and declared value exports are the same set`, async () => {
    const runtime = Object.keys(await import(join(packageDirectory, `${name}.mjs`))).sort();
    assert(runtime.length > 0);
    compileProbe(name, runtime);
  });

  test(`fireemu/${name}: the declaration never falls back to any`, () => {
    const code = stripComments(readFileSync(join(packageDirectory, `${name}.d.mts`), 'utf8'));
    assert.deepEqual(code.match(/\bany\b/g), null);
  });
}

test('the probe fails when a runtime export has no declaration or a declaration has no runtime export', () => {
  assert.throws(() => compileProbe('control', ['createControlClient', 'undeclaredExport']));
  assert.throws(() => compileProbe('control', []));
  assert.equal(stripComments('// any\n/** any */ export type A = any;').match(/\bany\b/g)?.length, 1);
});

test('a checkout path with spaces, percent signs and non-ASCII characters is read as the real path', () => {
  const base = mkdtempSync(join(tmpdir(), 'fireemu types '));
  try {
    const checkout = join(base, 'my checkout %20 100% 空白', 'npm', 'fireemu');
    mkdirSync(checkout, { recursive: true });
    for (const file of ['control.d.mts', 'control.mjs', 'testing.d.mts', 'testing.mjs']) copyFileSync(join(packageDirectory, file), join(checkout, file));
    compileProbe('control', ['createControlClient'], checkout);
    assert.throws(() => compileProbe('control', ['createControlClient', 'undeclaredExport'], checkout));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
