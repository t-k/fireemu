// node --test rtdb-sdk-tokens.test.mjs: the local entry of the tokens suite (argument checks, the fireemu exec plan, the
// outputs it derives from the observer run, the comparison of two runs, the owned process group).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { LOCAL_DIRECT_CAP, daemonConfig, execPlan, finish, localPrefix } from './rtdb-sdk-tokens.mjs';

const here = path.dirname(fileURLToPath(import.meta.url)), script = path.join(here, 'rtdb-sdk-tokens.mjs');
const FIXTURE = JSON.parse(readFileSync(path.join(here, 'fixtures', 'local-sdk-tokens.json'), 'utf8'));
const RESULT = { runId: 'LOCAL-X', suite: 'tokens', target: 'emulator', prefix: '/sdktokens01234567', ...FIXTURE.result, counts: { direct: 60, reserve: 4, adc: 0 } };
delete RESULT.prefixLength;
function rawRows(doc) {
  const out = [{ kind: 'admin-req', label: 'rules-before' }];
  for (const p of doc.profiles) {
    out.push({ kind: 'probe', suite: 'tokens', profile: p.name, after: 'start', attempt: 1, outcome: 'answered', ready: true });
    for (const r of p.rows) out.push({ t: new Date().toISOString(), kind: 'case', suite: 'tokens', ...r, profile: p.name });
  }
  return [...out, { kind: 'result' }];
}

test('the exec plan starts only the database and runs the observer tokens suite with a production-length prefix and cap 80; the daemon project is the local target\'s', () => {
  assert.equal(daemonConfig('emulator').profile, 'emulator'); assert.throws(() => daemonConfig('x'));
  assert.equal(daemonConfig('strict').daemon.authProject, 'demo-tokens-observer');
  const plan = execPlan('/bin/fireemu', '/out/config.json', '/out/observer', 'LOCAL-SDK-TOKENS-1');
  const [daemon, command] = [plan.slice(1, plan.indexOf('--')), plan.slice(plan.indexOf('--') + 1)];
  assert.deepEqual(daemon, ['exec', '--no-config-discovery', '--config', '/out/config.json', '--only', 'database', '--database-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet']);
  const arg = n => command[command.indexOf(n) + 1];
  assert.deepEqual([arg('--target'), arg('--suite'), arg('--run-id'), arg('--direct-cap'), arg('--out')], ['emulator', 'tokens', 'LOCAL-SDK-TOKENS-1', '80', '/out/observer']);
  assert.equal(LOCAL_DIRECT_CAP, 80);
  assert.match(arg('--prefix'), /^\/sdktokens[0-9a-f]{8}$/); assert.equal(arg('--prefix').length, '/sdktokens20261105'.length);
  for (let i = 0; i < 20; i++) assert.equal(localPrefix().length, 18);
});
test('finish: the observer journal becomes journal.json; with a recorded record also comparison.json; outputs are never overwritten', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-tokens-finish-'));
  try {
    mkdirSync(path.join(dir, 'observer'));
    writeFileSync(path.join(dir, 'observer', 'journal.jsonl'), rawRows(FIXTURE).map(r => JSON.stringify(r)).join('\n') + '\n');
    writeFileSync(path.join(dir, 'observer', 'result.json'), JSON.stringify(RESULT));
    const s = finish(dir, FIXTURE);
    assert.equal(s.match, true, JSON.stringify(s.problems)); assert.equal(s.counts.MATCH, 54);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, 'journal.json'), 'utf8')), FIXTURE);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, 'comparison.json'), 'utf8')), s);
    assert.throws(() => finish(dir, FIXTURE), /EEXIST/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function fakeFireemu(dir, { exitCode = 0, hang = false, leaveChild = false } = {}) {
  writeFileSync(path.join(dir, 'raw.jsonl'), rawRows(FIXTURE).map(r => JSON.stringify(r)).join('\n') + '\n');
  const file = path.join(dir, 'fake-fireemu.mjs');
  writeFileSync(file, `#!${process.execPath}
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
const argv = process.argv.slice(2), cmd = argv.slice(argv.indexOf('--') + 1), out = cmd[cmd.indexOf('--out') + 1];
if (argv[0] !== 'exec' || cmd[cmd.indexOf('--target') + 1] !== 'emulator' || cmd[cmd.indexOf('--suite') + 1] !== 'tokens') process.exit(9);
const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
writeFileSync(${JSON.stringify(path.join(dir, 'pids'))}, JSON.stringify([process.pid, child.pid]));
mkdirSync(out);
copyFileSync(${JSON.stringify(path.join(dir, 'raw.jsonl'))}, out + '/journal.jsonl');
writeFileSync(out + '/result.json', ${JSON.stringify(JSON.stringify({ ...RESULT, exit: exitCode, status: exitCode ? 'incomplete' : 'complete' }))});
${hang ? '' : `${leaveChild ? '' : 'child.kill(); '}process.exit(${exitCode});`}
`);
  chmodSync(file, 0o755);
  return file;
}
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };

test('the entry runs the plan, judges against --against and exits with the observer status; compare names the differing cases; the process group is gone', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-tokens-entry-'));
  try {
    const against = path.join(dir, 'recorded.json'); writeFileSync(against, JSON.stringify(FIXTURE));
    const out = path.join(dir, 'out'), r = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', out, '--profile', 'emulator', '--against', against], { encoding: 'utf8', timeout: 60000 });
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /54\/54 MATCH/);
    assert.deepEqual(JSON.parse(readFileSync(path.join(out, 'config.json'), 'utf8')).daemon.authProject, 'demo-tokens-observer');
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, String(pid));
    const changed = structuredClone(FIXTURE); changed.profiles[1].rows[5].status = 418; writeFileSync(path.join(dir, 'other.json'), JSON.stringify(changed));
    const c = spawnSync(process.execPath, [script, 'compare', path.join(dir, 'other.json'), path.join(out, 'journal.json')], { encoding: 'utf8' });
    assert.equal(c.status, 1, c.stderr); assert.match(c.stdout, /53\/54 MATCH, 1 MISMATCH/); assert.match(c.stdout, new RegExp(`r2-tokens ${FIXTURE.profiles[1].rows[5].id}: MISMATCH .*\\(status\\)`));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('the entry refuses an existing --out, fails with the observer status, and ends a hanging producer with its group', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-tokens-entry-'));
  try {
    const existing = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', dir], { encoding: 'utf8' });
    assert.equal(existing.status, 2); assert.equal(existsSync(path.join(dir, 'config.json')), false);
    assert.equal(spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { exitCode: 3 }), '--out', path.join(dir, 'f')], { encoding: 'utf8' }).status, 3);
    assert.equal(spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { leaveChild: true }), '--out', path.join(dir, 'c')], { encoding: 'utf8', timeout: 60000 }).status, 0);
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, `a child the producer left behind is ended with its group (${pid})`);
    const h = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { hang: true }), '--out', path.join(dir, 'h'), '--exec-timeout-ms', '6000'], { encoding: 'utf8', timeout: 60000 });
    assert.equal(h.status, 3, h.stderr); assert.match(h.stderr, /timed out/);
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, String(pid));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// Opt-in: FIREEMU_BIN=<fireemu binary> runs the suite locally in both profiles, judges strict against the committed
// fixture and strict against emulator. Measured on fireemu v0.43.0 and on the parity line (rtdb-rules-load): strict
// refuses every credential that is not the owner's with 401 Permission denied; the emulator profile admits these 12 per
// round (unsigned tokens whatever their aud, any Bearer or access_token value but an empty Bearer).
const EXPECTED_DIFFERENCES = ['auth-none-other', 'auth-none-own', 'auth-random-pub', 'bearer-random', 'bearer-none-own', 'bearer-rs256', 'bearer-null', 'bearer-random-pub', 'at-empty', 'at-random', 'at-rs256', 'at-random-pub'];
test('live: strict against the fixture and against emulator on a real fireemu (FIREEMU_BIN); differences are listed, a 5xx fails', { skip: !process.env.FIREEMU_BIN, timeout: 25 * 60 * 1000 }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-tokens-live-'));
  try {
    const out = p => path.join(dir, p);
    for (const p of ['strict', 'emulator']) {
      const r = spawnSync(process.execPath, [script, 'local', '--fireemu', process.env.FIREEMU_BIN, '--out', out(p), '--profile', p, '--against', path.join(here, 'fixtures', 'local-sdk-tokens.json')], { encoding: 'utf8', timeout: 11 * 60 * 1000 });
      assert.equal(r.status, 0, `${p}: ${r.stdout}${r.stderr}`);
      assert.deepEqual(JSON.parse(readFileSync(path.join(out(p), 'comparison.json'), 'utf8')).defects, [], `${p}: local 5xx`);
    }
    assert.equal(JSON.parse(readFileSync(path.join(out('strict'), 'comparison.json'), 'utf8')).match, true, 'strict gives the committed fixture');
    const c = spawnSync(process.execPath, [script, 'compare', path.join(out('strict'), 'journal.json'), path.join(out('emulator'), 'journal.json')], { encoding: 'utf8' });
    const differing = c.stdout.split('\n').filter(l => /^ {2}r[12]-tokens /.test(l)).map(l => l.trim().split(' ').slice(0, 2).join(' '));
    assert.deepEqual(differing, ['r1-tokens', 'r2-tokens'].flatMap(p => EXPECTED_DIFFERENCES.map(id => `${p} ${id}:`)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
