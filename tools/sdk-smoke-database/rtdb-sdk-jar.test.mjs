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

function fakes({ status = 0, error, finish } = {}) {
  const calls = { spawn: [], finish: [], stop: 0, order: [] };
  const suites = { rest: async () => ({
    execPlan: (binary, config, observerOut, runId) => ['unused', 'exec', '--', 'node', 'observer.mjs', '--out', observerOut, '--run-id', runId],
    finish: out => { calls.order.push('finish'); calls.finish.push(out); if (finish) throw finish; },
  }) };
  const deps = { suites, startJar: async () => ({ host: '127.0.0.1:4321', stop: async () => { await new Promise(resolve => setTimeout(resolve, 20)); calls.order.push('stop'); calls.stop += 1; } }),
    spawnSync: (command, args, options) => { calls.order.push('spawn'); calls.spawn.push({ command, args, options }); return { status, error }; } };
  return { calls, deps };
}

test('run: the command of the suite entry runs against the jar, the answer is reduced after it, the status is the observer\'s and the jar is stopped', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-jar-run-'));
  try {
    const { calls, deps } = fakes({ status: 3 });
    const out = path.join(dir, 'out');
    assert.equal(await run({ suite: 'rest', out, timeout: 777 }, deps), 3);
    assert.equal(calls.spawn.length, 1);
    assert.deepEqual([calls.spawn[0].command, calls.spawn[0].args], ['node', ['observer.mjs', '--out', path.join(out, 'observer'), '--run-id', 'JAR-REST-01']]);
    assert.equal(calls.spawn[0].options.env.FIREBASE_DATABASE_EMULATOR_HOST, '127.0.0.1:4321'); assert.equal(calls.spawn[0].options.timeout, 777);
    assert.deepEqual(calls.finish, [out]); assert.deepEqual(calls.order, ['spawn', 'finish', 'stop'], 'the jar outlives the reduction');
    await assert.rejects(run({ suite: 'rest', out, timeout: 1 }, fakes().deps), /EEXIST/, 'an existing --out is refused');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('run: a failed child or reduction still stops the jar, and the failure is not hidden', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-jar-run-'));
  try {
    const spawnFailure = fakes({ error: new Error('spawn failed') });
    await assert.rejects(run({ suite: 'rest', out: path.join(dir, 'a'), timeout: 1 }, spawnFailure.deps), /spawn failed/);
    assert.equal(spawnFailure.calls.stop, 1); assert.deepEqual(spawnFailure.calls.finish, [], 'nothing is reduced after a failed spawn');
    const reduceFailure = fakes({ finish: new Error('no reduction') });
    await assert.rejects(run({ suite: 'rest', out: path.join(dir, 'b'), timeout: 1 }, reduceFailure.deps), /no reduction/);
    assert.equal(reduceFailure.calls.stop, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
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
