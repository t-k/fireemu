// node --test rtdb-sdk-rules.test.mjs: the local entry of the rules suite (argument checks, the fireemu exec plan, the
// outputs it derives from the observer run, the comparison of two runs, the owned process group).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { LOCAL_DIRECT_CAP, daemonConfig, execPlan, finish, localPrefix, options } from './rtdb-sdk-rules.mjs';

import { recordedJournal } from './rtdb-sdk-rules-fixture.mjs';
import { summarize } from './rtdb-sdk-rules-judge.mjs';
const here = path.dirname(fileURLToPath(import.meta.url)), script = path.join(here, 'rtdb-sdk-rules.mjs');
const FIXTURE = JSON.parse(readFileSync(path.join(here, 'fixtures', 'local-sdk-rules.json'), 'utf8'));
const RESULT = { runId: 'LOCAL-X', suite: 'rules', target: 'emulator', prefix: '/sdkrules01234567', ...FIXTURE.result, counts: { direct: 162, reserve: 4, adc: 0 } };
delete RESULT.prefixLength;
function rawRows(doc) {
  const out = [{ kind: 'admin-req', label: 'rules-before' }];
  for (const p of doc.profiles) {
    const probe = after => ({ kind: 'probe', suite: 'rules', profile: p.name, after, attempt: 1, outcome: 'answered', ready: true });
    out.push(probe('start'));
    for (const r of p.rows) { out.push({ t: new Date().toISOString(), kind: 'case', suite: 'rules', ...r, profile: p.name }); const i = p.installs.find(x => x.after === r.id); if (i) out.push({ kind: 'install', suite: 'rules', profile: p.name, ...i }, probe(r.id)); }
  }
  return [...out, { kind: 'result' }];
}

test('options: local and compare only; --fireemu and --out required; the two profiles', () => {
  const o = options(['local', '--fireemu', '/bin/fireemu', '--out', '/tmp/o']);
  assert.deepEqual([o.mode, o.binary, o.out, o.profile, o.against, o.timeout], ['local', '/bin/fireemu', '/tmp/o', 'strict', undefined, 10 * 60 * 1000]);
  assert.deepEqual(options(['compare', 'a.json', 'b.json']), { mode: 'compare', recorded: path.resolve('a.json'), local: path.resolve('b.json') });
  for (const bad of [[], ['production', '--fireemu', 'f', '--out', 'o'], ['local', '--out', 'o'], ['local', '--fireemu', 'f'], ['local', '--fireemu', 'f', '--out', 'o', '--profile', 'production'], ['compare', 'a.json'], ['local', '--fireemu', 'f', '--out', 'o', '--exec-timeout-ms', '0']])
    assert.throws(() => options(bad), undefined, bad.join(' '));
});
test('the exec plan starts only the database and runs the observer rules suite with a production-length prefix and cap 210', () => {
  assert.deepEqual(daemonConfig('emulator').profile, 'emulator'); assert.throws(() => daemonConfig('x'));
  const plan = execPlan('/bin/fireemu', '/out/config.json', '/out/observer', 'LOCAL-SDK-RULES-1');
  const [daemon, command] = [plan.slice(1, plan.indexOf('--')), plan.slice(plan.indexOf('--') + 1)];
  assert.deepEqual(daemon, ['exec', '--no-config-discovery', '--config', '/out/config.json', '--only', 'database', '--database-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet']);
  const arg = n => command[command.indexOf(n) + 1];
  assert.deepEqual([arg('--target'), arg('--suite'), arg('--run-id'), arg('--direct-cap'), arg('--out')], ['emulator', 'rules', 'LOCAL-SDK-RULES-1', '210', '/out/observer']);
  assert.equal(LOCAL_DIRECT_CAP, 210);
  assert.match(arg('--prefix'), /^\/sdkrules[0-9a-f]{8}$/); assert.equal(arg('--prefix').length, '/sdkrules20261105'.length);
  for (let i = 0; i < 20; i++) assert.equal(localPrefix().length, 17);
});
test('finish: the observer journal becomes journal.json; with a recorded record also comparison.json; outputs are never overwritten', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-rules-finish-'));
  try {
    mkdirSync(path.join(dir, 'observer'));
    writeFileSync(path.join(dir, 'observer', 'journal.jsonl'), rawRows(FIXTURE).map(r => JSON.stringify(r)).join('\n') + '\n');
    writeFileSync(path.join(dir, 'observer', 'result.json'), JSON.stringify(RESULT));
    const s = finish(dir, FIXTURE);
    assert.equal(s.match, true, JSON.stringify(s.problems)); assert.equal(s.counts.MATCH, 140);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, 'journal.json'), 'utf8')), FIXTURE);
    assert.throws(() => finish(dir, FIXTURE), /EEXIST/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function fakeFireemu(dir, { exitCode = 0, hang = false } = {}) {
  writeFileSync(path.join(dir, 'raw.jsonl'), rawRows(FIXTURE).map(r => JSON.stringify(r)).join('\n') + '\n');
  const file = path.join(dir, 'fake-fireemu.mjs');
  writeFileSync(file, `#!${process.execPath}
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
const argv = process.argv.slice(2), cmd = argv.slice(argv.indexOf('--') + 1), out = cmd[cmd.indexOf('--out') + 1];
if (argv[0] !== 'exec' || cmd[cmd.indexOf('--target') + 1] !== 'emulator' || cmd[cmd.indexOf('--suite') + 1] !== 'rules') process.exit(9);
const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
writeFileSync(${JSON.stringify(path.join(dir, 'pids'))}, JSON.stringify([process.pid, child.pid]));
mkdirSync(out);
copyFileSync(${JSON.stringify(path.join(dir, 'raw.jsonl'))}, out + '/journal.jsonl');
writeFileSync(out + '/result.json', ${JSON.stringify(JSON.stringify({ ...RESULT, exit: exitCode, status: exitCode ? 'incomplete' : 'complete' }))});
${hang ? '' : `child.kill(); process.exit(${exitCode});`}
`);
  chmodSync(file, 0o755);
  return file;
}
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };

test('the entry runs the plan, judges against --against and exits with the observer status; compare names the differing cases; the process group is gone', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-rules-entry-'));
  try {
    const against = path.join(dir, 'recorded.json'); writeFileSync(against, JSON.stringify(FIXTURE));
    const out = path.join(dir, 'out'), r = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', out, '--profile', 'emulator', '--against', against], { encoding: 'utf8', timeout: 60000 });
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /140\/140 MATCH/);
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, String(pid));
    const changed = structuredClone(FIXTURE); changed.profiles[1].rows[5].status = 418; writeFileSync(path.join(dir, 'other.json'), JSON.stringify(changed));
    const c = spawnSync(process.execPath, [script, 'compare', path.join(dir, 'other.json'), path.join(out, 'journal.json')], { encoding: 'utf8' });
    assert.equal(c.status, 1, c.stderr); assert.match(c.stdout, /139\/140 MATCH, 1 MISMATCH/); assert.match(c.stdout, new RegExp(`r2-rules ${FIXTURE.profiles[1].rows[5].id}: MISMATCH .*\\(status\\)`));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('the entry refuses an existing --out, fails with the observer status, and ends a hanging producer with its group', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-rules-entry-'));
  try {
    const existing = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', dir], { encoding: 'utf8' });
    assert.equal(existing.status, 2); assert.equal(existsSync(path.join(dir, 'config.json')), false);
    assert.equal(spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { exitCode: 3 }), '--out', path.join(dir, 'f')], { encoding: 'utf8' }).status, 3);
    const h = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { hang: true }), '--out', path.join(dir, 'h'), '--exec-timeout-ms', '6000'], { encoding: 'utf8', timeout: 60000 });
    assert.equal(h.status, 3, h.stderr); assert.match(h.stderr, /timed out/);
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, String(pid));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});


// The closure replays of the recording on the release-profile build b2fd5b2c (fireemu 0.43.0, both profiles) are committed as
// reductions (fixtures/closure-sdk-rules-<profile>.json). The strict profile reproduces production in every observation; the emulator
// profile differs only in the cases named here, in each round, and the closure record declares them (knownDifferences).
const PRODUCTION = path.join(here, 'fixtures', 'production-sdk-rules.json');
const ROUNDS = ['r1-rules', 'r2-rules'];
const EMULATOR_DIFFERENCES = [];
const differing = (s) => s.rows.filter(r => r.verdict !== 'MATCH').map(r => `${r.profile} ${r.case}`).sort();
const declared = ROUNDS.flatMap(round => EMULATOR_DIFFERENCES.map(id => `${round} ${id}`)).sort();

test('offline: the committed closure reductions give strict all MATCH against production and the emulator profile exactly the declared differences', () => {
  const production = recordedJournal(JSON.parse(readFileSync(PRODUCTION, 'utf8')));
  const read = profile => JSON.parse(readFileSync(path.join(here, 'fixtures', `closure-sdk-rules-${profile}.json`), 'utf8'));
  const strict = summarize(production, read('strict')), emulator = summarize(production, read('emulator'));
  assert.deepEqual([strict.match, strict.problems, strict.counts], [true, [], { MATCH: 140, MISMATCH: 0, NEEDS_REVIEW: 0 }]);
  assert.deepEqual(emulator.problems, []); assert.deepEqual(differing(emulator), declared);
  assert.deepEqual(emulator.counts, { MATCH: 140 - declared.length, MISMATCH: declared.length, NEEDS_REVIEW: 0 });
  assert.equal(emulator.match, declared.length === 0);
  assert.deepEqual(emulator.defects, [], 'a local 5xx is a defect in any profile');
  // The comparison binds the recorded rows: a changed status in the strict reduction is a mismatch, a changed case id is not matched.
  const altered = structuredClone(read('strict')); altered.profiles[0].rows[1].status += 1;
  assert.equal(summarize(production, altered).match, false); assert.equal(summarize(production, altered).counts.MISMATCH, 1);
});

// Opt-in: FIREEMU_BIN=<fireemu binary> runs the suite locally in both profiles against the production reduction.
test('live: strict matches production and the emulator profile differs only in the declared cases (FIREEMU_BIN); a 5xx fails', { skip: !process.env.FIREEMU_BIN, timeout: 25 * 60 * 1000 }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-rules-live-'));
  try {
    for (const p of ['strict', 'emulator']) {
      const out = path.join(dir, p);
      const r = spawnSync(process.execPath, [script, 'local', '--fireemu', process.env.FIREEMU_BIN, '--out', out, '--profile', p, '--against', PRODUCTION], { encoding: 'utf8', timeout: 11 * 60 * 1000 });
      assert.equal(r.status, 0, `${p}: ${r.stdout}${r.stderr}`);
      const comparison = JSON.parse(readFileSync(path.join(out, 'comparison.json'), 'utf8'));
      assert.deepEqual(comparison.defects, [], `${p}: local 5xx`);
      assert.deepEqual(differing(comparison), p === 'strict' ? [] : declared, p);
      assert.equal(comparison.match, p === 'strict' || declared.length === 0, p);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
