// node --test rtdb-sdk-small.test.mjs: the local replay entry of the RTDB SDK small observer (argument checks, the
// fireemu exec plan, the outputs it derives from the observer run, and the owned process group).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { daemonConfig, execPlan, finish, options } from './rtdb-sdk-small.mjs';
import { journal, prng, rawRows } from './rtdb-sdk-small-testkit.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, 'rtdb-sdk-small.mjs');
const RESULT = { runId: 'LOCAL-X', target: 'emulator', status: 'complete', observed: 32, exit: 0, cleanup: { prefix: 'verified', rules: 'verified' }, counts: { direct: 76, reserve: 4, adc: 0 } };

test('options: local only, --fireemu and --out required, the two profiles, --modules only the package node_modules', () => {
  const o = options(['local', '--fireemu', '/bin/fireemu', '--out', '/tmp/o']);
  assert.deepEqual([o.binary, o.out, o.profile], ['/bin/fireemu', '/tmp/o', 'strict']);
  assert.equal(options(['local', '--fireemu', 'f', '--out', 'o', '--profile', 'emulator']).profile, 'emulator');
  assert.equal(options(['local', '--fireemu', 'f', '--out', 'o', '--modules', path.join(here, 'node_modules')]).profile, 'strict');
  for (const bad of [[], ['production', '--fireemu', 'f', '--out', 'o'], ['local', '--out', 'o'], ['local', '--fireemu', 'f'], ['local', '--fireemu', 'f', '--out', 'o', '--profile', 'production'], ['local', '--fireemu', 'f', '--out', 'o', '--modules', '/elsewhere/node_modules']])
    assert.throws(() => options(bad), undefined, bad.join(' '));
});

test('the daemon config carries the profile; the exec plan starts only the database on free ports and runs the observer in emulator mode', () => {
  assert.deepEqual(daemonConfig('emulator'), { schemaVersion: 1, profile: 'emulator', daemon: { authProject: 'demo-small-observer', hubPort: 0, uiPort: 0, loggingPort: 0 } });
  assert.throws(() => daemonConfig('lenient'));
  const plan = execPlan('/bin/fireemu', '/out/config.json', '/out/observer', 'LOCAL-SDK-SMALL-1');
  assert.equal(plan[0], '/bin/fireemu');
  const [daemon, command] = [plan.slice(1, plan.indexOf('--')), plan.slice(plan.indexOf('--') + 1)];
  assert.deepEqual(daemon, ['exec', '--no-config-discovery', '--config', '/out/config.json', '--only', 'database', '--database-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet']);
  assert.equal(command[0], process.execPath);
  assert.equal(command[1], '--max-old-space-size=1024');
  assert.equal(command[2], path.join(here, 'sdk-observer', 'observer.mjs'));
  const arg = (n) => command[command.indexOf(n) + 1];
  assert.deepEqual([arg('--target'), arg('--run-id'), arg('--out'), arg('--direct-cap')], ['emulator', 'LOCAL-SDK-SMALL-1', '/out/observer', '180']);
  assert.match(arg('--prefix'), /^\/[A-Za-z0-9_-]+$/);
  assert.equal(command.includes('--production-config'), false);
});

test('finish: the observer journal becomes the reduced journal.json and comparison.json, judged against the fixture', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-small-finish-'));
  try {
    mkdirSync(path.join(dir, 'observer'));
    writeFileSync(path.join(dir, 'observer', 'journal.jsonl'), rawRows(journal(prng(21))).map((r) => JSON.stringify(r)).join('\n') + '\n');
    writeFileSync(path.join(dir, 'observer', 'result.json'), JSON.stringify(RESULT));
    const s = finish(dir);
    assert.equal(s.match, true, JSON.stringify(s.problems));
    assert.deepEqual(s.counts, { MATCH: 32, MISMATCH: 0, NEEDS_REVIEW: 0 });
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, 'journal.json'), 'utf8')).profiles, journal(prng(21)).profiles);
    assert.equal(JSON.parse(readFileSync(path.join(dir, 'comparison.json'), 'utf8')).match, true);
    assert.throws(() => finish(dir), /EEXIST/); // outputs are never overwritten
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// A stand-in for `fireemu exec`: it checks the plan, writes the observer outputs and records its process group.
function fakeFireemu(dir, { exitCode = 0, mutate = (d) => d, hang = false } = {}) {
  const doc = mutate(journal(prng(22)));
  writeFileSync(path.join(dir, 'raw.jsonl'), rawRows(doc).map((r) => JSON.stringify(r)).join('\n') + '\n');
  const file = path.join(dir, 'fake-fireemu.mjs');
  writeFileSync(file, `#!${process.execPath}
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
const argv = process.argv.slice(2), cmd = argv.slice(argv.indexOf('--') + 1), out = cmd[cmd.indexOf('--out') + 1];
if (argv[0] !== 'exec' || cmd[cmd.indexOf('--target') + 1] !== 'emulator') process.exit(9);
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
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

test('the entry runs the plan, writes the outputs and exits 0 for a complete run; the owned process group is gone afterwards', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-small-entry-'));
  try {
    const out = path.join(dir, 'out'), r = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', out, '--profile', 'emulator'], { encoding: 'utf8', timeout: 60000 });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /32\/32 MATCH/);
    assert.equal(JSON.parse(readFileSync(path.join(out, 'config.json'), 'utf8')).profile, 'emulator');
    assert.equal(JSON.parse(readFileSync(path.join(out, 'comparison.json'), 'utf8')).match, true);
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, String(pid));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the entry refuses an existing --out, reports a mismatch, and fails when the observer run did not complete', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-small-entry-'));
  try {
    const existing = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', dir], { encoding: 'utf8' });
    assert.equal(existing.status, 2);
    assert.equal(existsSync(path.join(dir, 'config.json')), false);
    const frozen = fakeFireemu(dir, { mutate: (d) => { for (const p of d.profiles) { const st = p.rows[9].value; st.value = st.before - 300; p.rows[10].value.at = st.value; } return d; } });
    const mismatch = spawnSync(process.execPath, [script, 'local', '--fireemu', frozen, '--out', path.join(dir, 'm')], { encoding: 'utf8' });
    assert.equal(mismatch.status, 0, mismatch.stderr); // the recording completed; the judge says no
    assert.match(mismatch.stdout, /24\/32 MATCH/);
    assert.equal(JSON.parse(readFileSync(path.join(dir, 'm', 'comparison.json'), 'utf8')).match, false);
    const failed = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { exitCode: 3 }), '--out', path.join(dir, 'f')], { encoding: 'utf8' });
    assert.equal(failed.status, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a producer that leaves a child running is ended with its process group', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-small-entry-'));
  try {
    const r = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { hang: true }), '--out', path.join(dir, 'h'), '--exec-timeout-ms', '1500'], { encoding: 'utf8', timeout: 60000 });
    assert.equal(r.status, 3, r.stderr);
    assert.match(r.stderr, /timed out/);
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, String(pid));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
