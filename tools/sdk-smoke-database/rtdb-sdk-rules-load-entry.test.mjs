// node --test rtdb-sdk-rules-load-entry.test.mjs: the local entry of the rules-load suite (the fireemu exec plan, the outputs it
// derives from the observer run) and, with FIREEMU_BIN, the replay of the production reduction on a real fireemu in both profiles.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { LOCAL_DIRECT_CAP, daemonConfig, execPlan, finish, localPrefix } from './rtdb-sdk-rules-load.mjs';
import { recordedJournal } from './rtdb-sdk-rules-load-fixture.mjs';

const here = path.dirname(fileURLToPath(import.meta.url)), script = path.join(here, 'rtdb-sdk-rules-load.mjs');
const FIXTURE = path.join(here, 'fixtures', 'production-sdk-rules-load.json');
const RECORDED = recordedJournal(JSON.parse(readFileSync(FIXTURE, 'utf8')));
const RESULT = { runId: 'LOCAL-X', suite: 'rules-load', target: 'emulator', prefix: '/sdkrulesload', ...RECORDED.result, counts: { direct: 25, reserve: 2, adc: 0 } };

function rawRows(doc) {
  const out = [{ kind: 'admin-req', label: 'rules-before' }];
  for (const p of doc.profiles) for (const r of p.rows) out.push({ t: new Date().toISOString(), kind: 'case', suite: 'rules-load', ...r, profile: p.name });
  return [...out, { kind: 'result' }];
}

test('the exec plan starts only the database and runs the observer rules-load suite on the production prefix with cap 60', () => {
  assert.equal(daemonConfig('emulator').profile, 'emulator'); assert.throws(() => daemonConfig('x'));
  const plan = execPlan('/bin/fireemu', '/out/config.json', '/out/observer', 'LOCAL-SDK-RULES-LOAD-1');
  const [daemon, command] = [plan.slice(1, plan.indexOf('--')), plan.slice(plan.indexOf('--') + 1)];
  assert.deepEqual(daemon, ['exec', '--no-config-discovery', '--config', '/out/config.json', '--only', 'database', '--database-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet']);
  const arg = n => command[command.indexOf(n) + 1];
  assert.deepEqual([arg('--target'), arg('--suite'), arg('--run-id'), arg('--direct-cap'), arg('--out'), arg('--prefix')], ['emulator', 'rules-load', 'LOCAL-SDK-RULES-LOAD-1', '60', '/out/observer', '/sdkrulesload']);
  assert.equal(LOCAL_DIRECT_CAP, 60); assert.equal(localPrefix(), '/sdkrulesload');
});

test('finish: the observer journal becomes journal.json; with a recorded reduction also comparison.json; outputs are never overwritten', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-rules-load-finish-'));
  try {
    mkdirSync(path.join(dir, 'observer'));
    writeFileSync(path.join(dir, 'observer', 'journal.jsonl'), rawRows(RECORDED).map(r => JSON.stringify(r)).join('\n') + '\n');
    writeFileSync(path.join(dir, 'observer', 'result.json'), JSON.stringify(RESULT));
    const s = finish(dir, RECORDED);
    assert.equal(s.match, true, JSON.stringify(s.problems)); assert.equal(s.counts.MATCH, 14);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, 'journal.json'), 'utf8')), RECORDED);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, 'comparison.json'), 'utf8')), s);
    assert.throws(() => finish(dir, RECORDED), /EEXIST/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the production reduction: seven documents in two rounds, five refused and two accepted answers per round as recorded', () => {
  assert.deepEqual(RECORDED.result, { status: 'complete', observed: 14, exit: 0, cleanup: { prefix: 'not-needed', rules: 'verified' }, unverified: [] });
  for (const p of RECORDED.profiles) {
    assert.deepEqual(p.rows.map(r => [r.id, r.status]), [['g-dup-key', 400], ['g-dup-read', 400], ['h-dup-indexOn', 400], ['e-index-root-dot', 400], ['e-index-root-dollar', 400], ['e-index-root-empty', 200], ['h-index:"a//b"', 200]]);
    for (const r of p.rows) assert.deepEqual([r.ok, r.outcome, r.utf8, r.clipped], [true, 'answered', true, false], r.id);
  }
  assert.deepEqual(RECORDED.profiles[0].rows, RECORDED.profiles[1].rows, 'two rounds agree');
});

test('live: both profiles on a real fireemu (FIREEMU_BIN) match the production reduction in all 14 observations', { skip: !process.env.FIREEMU_BIN, timeout: 10 * 60 * 1000 }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-rules-load-live-'));
  try {
    for (const profile of ['strict', 'emulator']) {
      const out = path.join(dir, profile);
      const r = spawnSync(process.execPath, [script, 'local', '--fireemu', process.env.FIREEMU_BIN, '--out', out, '--profile', profile, '--against', FIXTURE], { encoding: 'utf8', timeout: 5 * 60 * 1000 });
      assert.equal(r.status, 0, `${profile}: ${r.stdout}${r.stderr}`);
      const comparison = JSON.parse(readFileSync(path.join(out, 'comparison.json'), 'utf8'));
      assert.equal(comparison.match, true, profile); assert.deepEqual(comparison.counts, { MATCH: 14, MISMATCH: 0, NEEDS_REVIEW: 0 }, profile); assert.deepEqual(comparison.defects, [], profile);
      assert.ok(existsSync(path.join(out, 'journal.json')));
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
