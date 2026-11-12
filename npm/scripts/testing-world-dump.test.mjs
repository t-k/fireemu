import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { dumpPaths } from '../fireemu/testing.mjs';

test('dump paths name both bundle files in the requested directory', () => {
  const directory = join('reports', 'diagnostics');
  assert.deepEqual(dumpPaths(directory), {
    json: join(directory, 'bundle.json'),
    html: join(directory, 'bundle.html'),
  });
});

import { mkdir, mkdtemp, readdir, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { writeDiagnosticsDump } from '../fireemu/testing.mjs';

const bundle = { schemaVersion: 1, generatedAt: 'virtual', rules: { denials: [], dropped: 0 } };
const page = '<!doctype html><title>bundle</title>';

function fakeControl(answers) {
  const calls = [];
  const control = async (method, path) => {
    calls.push([method, path]);
    return answers(path);
  };
  return { control, calls };
}

async function scratch(test) {
  const root = await mkdtemp(join(tmpdir(), 'fireemu-dump-test-'));
  try {
    await test(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('the dump writes bundle.json and bundle.html and asks the two control answers in order', () =>
  scratch(async (root) => {
    const directory = join(root, 'nested', 'dump');
    const { control, calls } = fakeControl((path) =>
      path.includes('format=html') ? { html: page } : bundle,
    );
    const paths = await writeDiagnosticsDump(directory, control);
    assert.deepEqual(paths, dumpPaths(directory));
    assert.deepEqual(calls, [
      ['GET', '/v1/sessions/default/diagnostics/bundle'],
      ['GET', '/v1/sessions/default/diagnostics/bundle?format=html'],
    ]);
    assert.equal(await readFile(paths.json, 'utf8'), JSON.stringify(bundle, null, 2));
    assert.equal(await readFile(paths.html, 'utf8'), page);
    assert.deepEqual(JSON.parse(await readFile(paths.json, 'utf8')), bundle);
  }));

test('no temporary file is left behind', () =>
  scratch(async (root) => {
    const { control } = fakeControl((path) => (path.includes('format=html') ? { html: page } : bundle));
    await writeDiagnosticsDump(root, control);
    assert.deepEqual((await readdir(root)).sort(), ['bundle.html', 'bundle.json']);
  }));

test('a bundle that is not a schema version 1 object writes nothing', () =>
  scratch(async (root) => {
    const { control } = fakeControl((path) =>
      path.includes('format=html') ? { html: page } : { schemaVersion: 2 },
    );
    await assert.rejects(writeDiagnosticsDump(root, control), /invalid diagnostics bundle/);
    assert.deepEqual(await readdir(root), []);
  }));

test('an answer that is not an array-free object is refused; an array is refused too', () =>
  scratch(async (root) => {
    const { control } = fakeControl(() => [bundle]);
    await assert.rejects(writeDiagnosticsDump(root, control), /invalid diagnostics bundle/);
  }));

test('an HTML answer that does not start with the doctype writes no HTML file', () =>
  scratch(async (root) => {
    const { control } = fakeControl((path) =>
      path.includes('format=html') ? { html: '<html>' } : bundle,
    );
    await assert.rejects(writeDiagnosticsDump(root, control), /invalid diagnostics HTML/);
    assert.deepEqual(await readdir(root), []);
  }));

test('a missing html field is refused', () =>
  scratch(async (root) => {
    const { control } = fakeControl((path) => (path.includes('format=html') ? {} : bundle));
    await assert.rejects(writeDiagnosticsDump(root, control), /invalid diagnostics HTML/);
  }));

test('a failed rename leaves no temporary file behind', () =>
  scratch(async (root) => {
    const { control } = fakeControl((path) => (path.includes('format=html') ? { html: page } : bundle));
    // A directory where bundle.html should go makes the final rename fail.
    await mkdir(join(root, 'bundle.html'));
    await assert.rejects(writeDiagnosticsDump(root, control));
    const names = await readdir(root);
    assert.equal(names.some((name) => name.endsWith('.tmp')), false, names.join(', '));
  }));
