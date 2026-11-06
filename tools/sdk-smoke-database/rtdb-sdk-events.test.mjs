// node --test rtdb-sdk-events.test.mjs: the local entry of the events and admin suites (argument checks, the fireemu
// exec plan, the outputs it derives from the observer run, the comparison of two local runs, the owned process group).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { FIXTURE as PRODUCTION_FIXTURE, daemonConfig, execPlan, finish, options } from './rtdb-sdk-events.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, 'rtdb-sdk-events.mjs');
const FIXTURE = JSON.parse(readFileSync(path.join(here, 'fixtures', 'local-sdk-events.json'), 'utf8'));
const RESULT = { runId: 'LOCAL-X', suite: 'events+admin', target: 'emulator', ...FIXTURE.result, counts: { direct: 158, reserve: 4, adc: 0 } };
/** The observer journal rows a reduced record came from (plus rows the reducer drops). */
const rawRows = doc => [{ kind: 'admin-req', label: 'rules-before' }, ...doc.profiles.flatMap(p => [{ kind: 'raw-ws', dir: 'in', conn: 1, data: '{}' }, ...p.rows.map(r => ({ t: new Date().toISOString(), kind: 'case', suite: p.suite, ...r, profile: p.name }))]), { kind: 'result' }];

test('options: local and compare only; --fireemu and --out required; the two profiles; the three suites', () => {
  const o = options(['local', '--fireemu', '/bin/fireemu', '--out', '/tmp/o']);
  assert.deepEqual([o.mode, o.binary, o.out, o.profile, o.suite, o.against], ['local', '/bin/fireemu', '/tmp/o', 'strict', 'events+admin', PRODUCTION_FIXTURE]);
  assert.equal(PRODUCTION_FIXTURE, path.join(here, 'fixtures', 'production-sdk-events.json'));
  assert.equal(options(['local', '--fireemu', 'f', '--out', 'o', '--suite', 'admin']).against, undefined, 'a single suite has no production fixture of its own');
  assert.equal(options(['local', '--fireemu', 'f', '--out', 'o', '--modules', path.join(here, 'node_modules')]).against, PRODUCTION_FIXTURE);
  assert.throws(() => options(['local', '--fireemu', 'f', '--out', 'o', '--modules', '/elsewhere/node_modules']), /--modules/);
  assert.equal(options(['local', '--fireemu', 'f', '--out', 'o', '--profile', 'emulator', '--suite', 'admin']).suite, 'admin');
  assert.equal(options(['local', '--fireemu', 'f', '--out', 'o', '--against', 'r.json']).against, path.resolve('r.json'));
  assert.deepEqual(options(['compare', 'a.json', 'b.json']), { mode: 'compare', recorded: path.resolve('a.json'), local: path.resolve('b.json') });
  for (const bad of [[], ['production', '--fireemu', 'f', '--out', 'o'], ['local', '--out', 'o'], ['local', '--fireemu', 'f'], ['local', '--fireemu', 'f', '--out', 'o', '--profile', 'production'], ['local', '--fireemu', 'f', '--out', 'o', '--suite', 'small'], ['compare', 'a.json']])
    assert.throws(() => options(bad), undefined, bad.join(' '));
});

test('the exec plan starts only the database on free ports and runs the observer in emulator mode with the suite and its cap', () => {
  assert.deepEqual(daemonConfig('emulator'), { schemaVersion: 1, profile: 'emulator', daemon: { authProject: 'demo-small-observer', hubPort: 0, uiPort: 0, loggingPort: 0 } });
  const plan = execPlan('/bin/fireemu', '/out/config.json', '/out/observer', 'LOCAL-SDK-EVENTS-1', 'admin');
  const [daemon, command] = [plan.slice(1, plan.indexOf('--')), plan.slice(plan.indexOf('--') + 1)];
  assert.deepEqual(daemon, ['exec', '--no-config-discovery', '--config', '/out/config.json', '--only', 'database', '--database-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet']);
  assert.deepEqual(command.slice(0, 3), [process.execPath, '--max-old-space-size=1024', path.join(here, 'sdk-observer', 'observer.mjs')]);
  const arg = n => command[command.indexOf(n) + 1];
  assert.deepEqual([arg('--target'), arg('--suite'), arg('--run-id'), arg('--out'), arg('--direct-cap')], ['emulator', 'admin', 'LOCAL-SDK-EVENTS-1', '/out/observer', '200']);
  assert.match(arg('--prefix'), /^\/[A-Za-z0-9_-]+$/); assert.ok(command.includes('--continue-on-failure')); assert.equal(command.includes('--production-config'), false);
});

test('finish: the observer journal becomes journal.json; with a recorded record also comparison.json; outputs are never overwritten', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-events-finish-'));
  try {
    mkdirSync(path.join(dir, 'observer'));
    writeFileSync(path.join(dir, 'observer', 'journal.jsonl'), rawRows(FIXTURE).map(r => JSON.stringify(r)).join('\n') + '\n');
    writeFileSync(path.join(dir, 'observer', 'result.json'), JSON.stringify(RESULT));
    const s = finish(dir, FIXTURE);
    assert.equal(s.match, true, JSON.stringify(s.problems)); assert.equal(s.counts.MATCH, 160);
    assert.deepEqual(JSON.parse(readFileSync(path.join(dir, 'journal.json'), 'utf8')), FIXTURE);
    assert.equal(JSON.parse(readFileSync(path.join(dir, 'comparison.json'), 'utf8')).match, true);
    assert.throws(() => finish(dir, FIXTURE), /EEXIST/);
    const lone = mkdtempSync(path.join(tmpdir(), 'sdk-events-finish-'));
    mkdirSync(path.join(lone, 'observer'));
    for (const f of ['journal.jsonl', 'result.json']) writeFileSync(path.join(lone, 'observer', f), readFileSync(path.join(dir, 'observer', f)));
    assert.equal(finish(lone), null); assert.equal(existsSync(path.join(lone, 'comparison.json')), false); assert.ok(existsSync(path.join(lone, 'journal.json')));
    rmSync(lone, { recursive: true, force: true });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// A stand-in for `fireemu exec`: it checks the plan, writes the observer outputs and records its process group.
function fakeFireemu(dir, { exitCode = 0, mutate = d => d, hang = false } = {}) {
  writeFileSync(path.join(dir, 'raw.jsonl'), rawRows(mutate(structuredClone(FIXTURE))).map(r => JSON.stringify(r)).join('\n') + '\n');
  const file = path.join(dir, 'fake-fireemu.mjs');
  writeFileSync(file, `#!${process.execPath}
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
const argv = process.argv.slice(2), cmd = argv.slice(argv.indexOf('--') + 1), out = cmd[cmd.indexOf('--out') + 1];
if (argv[0] !== 'exec' || cmd[cmd.indexOf('--target') + 1] !== 'emulator' || cmd[cmd.indexOf('--suite') + 1] !== 'events+admin') process.exit(9);
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

test('the entry runs the plan, judges against --against and exits with the observer status; the owned process group is gone afterwards', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-events-entry-'));
  try {
    const against = path.join(dir, 'recorded.json'); writeFileSync(against, JSON.stringify(FIXTURE));
    const out = path.join(dir, 'out'), r = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', out, '--profile', 'emulator', '--against', against], { encoding: 'utf8', timeout: 60000 });
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /160\/160 MATCH/);
    assert.equal(JSON.parse(readFileSync(path.join(out, 'config.json'), 'utf8')).profile, 'emulator');
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, String(pid));
    const other = path.join(dir, 'other.json'), changed = structuredClone(FIXTURE); changed.profiles[1].rows[3].steps[1].observer.reverse(); writeFileSync(other, JSON.stringify(changed));
    const c = spawnSync(process.execPath, [script, 'compare', other, path.join(out, 'journal.json')], { encoding: 'utf8' });
    assert.equal(c.status, 1, c.stderr); assert.match(c.stdout, /159\/160 MATCH, 1 MISMATCH/);
    assert.equal(spawnSync(process.execPath, [script, 'compare', against, path.join(out, 'journal.json')], { encoding: 'utf8' }).status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the entry refuses an existing --out and fails with the observer status when the run did not complete; a hanging producer is ended with its group', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-events-entry-'));
  try {
    const existing = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', dir], { encoding: 'utf8' });
    assert.equal(existing.status, 2); assert.equal(existsSync(path.join(dir, 'config.json')), false);
    assert.equal(spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { exitCode: 3 }), '--out', path.join(dir, 'f')], { encoding: 'utf8' }).status, 3);
    const h = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir, { hang: true }), '--out', path.join(dir, 'h'), '--exec-timeout-ms', '6000'], { encoding: 'utf8', timeout: 60000 });   // above the fake producer's start-up under load (1.5 s once failed during a mutation run)
    assert.equal(h.status, 3, h.stderr); assert.match(h.stderr, /timed out/);
    for (const pid of JSON.parse(readFileSync(path.join(dir, 'pids'), 'utf8'))) assert.equal(alive(pid), false, String(pid));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('compare and --against take the committed production fixture (its provenance is dropped) as well as a plain reduction', () => {
  const ok = spawnSync(process.execPath, [script, 'compare', PRODUCTION_FIXTURE, path.join(here, 'fixtures', 'local-sdk-events.json')], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr); assert.match(ok.stdout, /160\/160 MATCH, 0 MISMATCH, 0 NEEDS_REVIEW, match=true/);
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-events-fixture-'));
  try {
    const bad = JSON.parse(readFileSync(PRODUCTION_FIXTURE, 'utf8')); bad.provenance.target = 'emulator';
    writeFileSync(path.join(dir, 'bad.json'), JSON.stringify(bad));
    const refused = spawnSync(process.execPath, [script, 'compare', path.join(dir, 'bad.json'), path.join(here, 'fixtures', 'local-sdk-events.json')], { encoding: 'utf8' });
    assert.equal(refused.status, 2); assert.match(refused.stderr, /production/);
    const out = path.join(dir, 'out'), r = spawnSync(process.execPath, [script, 'local', '--fireemu', fakeFireemu(dir), '--out', out, '--modules', path.join(here, 'node_modules')], { encoding: 'utf8', timeout: 60000 });
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /160\/160 MATCH/);
    assert.equal(JSON.parse(readFileSync(path.join(out, 'comparison.json'), 'utf8')).match, true, 'the default comparison is with the committed fixture');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
