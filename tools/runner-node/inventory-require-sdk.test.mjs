// The SDK inventory guard must not quietly stop running where the SDK is required.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const inventory = fileURLToPath(new URL('./inventory.test.mjs', import.meta.url));

function run(env) {
  const empty = mkdtempSync(join(tmpdir(), 'fireemu-no-sdk-'));
  try {
    const base = {PATH: process.env.PATH, FIREEMU_SDK_SMOKE_DIR: empty};
    const run = spawnSync(process.execPath, ['--test', inventory], {encoding: 'utf8', env: {...base, ...env}});
    const field = name => Number(run.stdout.match(new RegExp(`ℹ ${name} (\\d+)`))?.[1]);
    return {status: run.status, pass: field('pass'), fail: field('fail'), skipped: field('skipped'), out: run.stdout};
  } finally {
    rmSync(empty, {recursive: true, force: true});
  }
}

test('without the SDK and without the requirement the two SDK tests skip, with their reason', () => {
  const r = run({});
  assert.equal(r.status, 0, r.out);
  assert.equal(r.skipped, 2);
  assert.equal(r.fail, 0);
  assert.match(r.out, /firebase-functions is not installed under tools\/sdk-smoke/);
});

test('with FIREEMU_REQUIRE_SDK=1 and no SDK the two SDK tests fail instead of skipping', () => {
  const r = run({FIREEMU_REQUIRE_SDK: '1'});
  assert.notEqual(r.status, 0);
  assert.equal(r.fail, 2, r.out);
  assert.equal(r.skipped, 0);
  assert.match(r.out, /FIREEMU_REQUIRE_SDK=1/);
});

test('any other value of FIREEMU_REQUIRE_SDK is not the requirement', () => {
  for (const value of ['', '0', 'true', 'yes']) {
    const r = run({FIREEMU_REQUIRE_SDK: value});
    assert.equal(r.status, 0, `${JSON.stringify(value)}: ${r.out}`);
    assert.equal(r.skipped, 2);
  }
});
