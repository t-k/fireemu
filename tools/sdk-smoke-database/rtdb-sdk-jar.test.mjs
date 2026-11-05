// node --test rtdb-sdk-jar.test.mjs: the argument checks of the jar entry, and (with RTDB_JAR_LIVE=1, which needs java) the
// replay of the committed jar reductions: the plain-HTTP suites run against the pinned official emulator jar give them again.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SUITES, parse, run } from './rtdb-sdk-jar.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

test('parse: a known suite and --out are required; the timeout has a default', () => {
  assert.deepEqual(Object.keys(SUITES), ['rest', 'rules', 'tokens', 'rules-load']);
  assert.throws(() => parse([]), /usage/); assert.throws(() => parse(['nope', '--out', 'x']), /usage/); assert.throws(() => parse(['rest']), /--out is required/);
  const o = parse(['tokens', '--out', 'out', '--timeout', '1000']);
  assert.deepEqual([o.suite, o.timeout, path.isAbsolute(o.out)], ['tokens', 1000, true]);
  assert.equal(parse(['rest', '--out', 'x']).timeout, 9 * 60 * 1000);
});

test('the committed jar reductions are complete, clean runs of their suites', () => {
  for (const [suite, observed] of [['rest', 144], ['tokens', 54], ['rules-load', 14]]) {
    const doc = JSON.parse(readFileSync(path.join(here, 'fixtures', `jar-sdk-${suite}.json`), 'utf8'));
    assert.equal(doc.suite, suite);
    assert.deepEqual([doc.result.status, doc.result.observed, doc.result.exit, doc.faults], ['complete', observed, 0, []], suite);
    assert.deepEqual(doc.result.unverified, [], suite);
  }
});

test('live: each suite on the jar reproduces the committed reduction (RTDB_JAR_LIVE=1)', { skip: process.env.RTDB_JAR_LIVE !== '1', timeout: 30 * 60 * 1000 }, async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-jar-live-'));
  try {
    for (const suite of ['rest', 'tokens', 'rules-load']) {
      const out = path.join(dir, suite);
      assert.equal(await run({ suite, out, timeout: 9 * 60 * 1000 }), 0, suite);
      assert.ok(existsSync(path.join(out, 'journal.json')), suite);
      const again = JSON.parse(readFileSync(path.join(out, 'journal.json'), 'utf8')), committed = JSON.parse(readFileSync(path.join(here, 'fixtures', `jar-sdk-${suite}.json`), 'utf8'));
      assert.deepEqual(again.profiles.map(p => p.rows.map(r => [r.id, r.status, r.body])), committed.profiles.map(p => p.rows.map(r => [r.id, r.status, r.body])), suite);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
