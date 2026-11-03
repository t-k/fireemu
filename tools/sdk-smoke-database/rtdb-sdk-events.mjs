// Local entry of the events (G6) and admin (G13) suites of the RTDB SDK observer (sdk-observer/ --suite): runs the
// suite against fireemu, reduces the journal (rtdb-sdk-events-fixture.mjs) and, when given a recorded reduction, judges
// it (rtdb-sdk-events-judge.mjs). There is no production fixture yet: `--against` takes another local reduction (the
// strict and emulator profiles are judged against each other), and `compare` judges two reductions.
//
//   node rtdb-sdk-events.mjs local --fireemu <bin> --out <new dir> [--profile strict|emulator] [--suite events|admin|events+admin] [--against <journal.json>]
//   node rtdb-sdk-events.mjs compare <recorded journal.json> <local journal.json>
//
// `local` runs `fireemu exec --only database` (own process group, ended on exit, timeout and signal) with the observer in
// emulator mode as the command; the observer installs its Rules, runs the profiles and restores everything itself.
// Outputs in <out>: config.json, observer/ (journal.jsonl, result.json), journal.json and, with --against, comparison.json.
// The exit status of `local` is the observer's; `compare` exits 0 on a match and 1 otherwise. Not registered in the
// release replay (no production fixture). The production entry is `sdk-observer/observer.mjs --target production --suite ...`.
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseJsonl } from './rtdb-sdk-small-fixture.mjs';
import { SUITE_PARTS, reduceEventsJournal } from './rtdb-sdk-events-fixture.mjs';
import { stepCount, summarize } from './rtdb-sdk-events-judge.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const OBSERVER = path.join(here, 'sdk-observer', 'observer.mjs');
// Above the observer's own backstop (runMs 15 min + 2 min) so that the observer, not this timer, ends a slow run.
const EXEC_TIMEOUT_MS = 19 * 60 * 1000;

export function options(argv) {
  const opt = n => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] === 'compare') {
    if (argv.length !== 3) throw Error('usage: compare <recorded journal.json> <local journal.json>');
    return { mode: 'compare', recorded: path.resolve(argv[1]), local: path.resolve(argv[2]) };
  }
  const binary = opt('--fireemu'), out = opt('--out'), profile = opt('--profile') ?? 'strict', suite = opt('--suite') ?? 'events+admin', against = opt('--against');
  if (argv[0] !== 'local' || !binary || !out) throw Error('usage: local --fireemu <bin> --out <new dir> [--profile strict|emulator] [--suite events|admin|events+admin] [--against <journal.json>]');
  if (!['strict', 'emulator'].includes(profile)) throw Error('--profile is strict or emulator');
  if (!Object.hasOwn(SUITE_PARTS, suite)) throw Error('--suite is events, admin or events+admin');
  const timeout = Number(opt('--exec-timeout-ms') ?? EXEC_TIMEOUT_MS);
  if (!Number.isSafeInteger(timeout) || timeout <= 0) throw Error('--exec-timeout-ms must be a positive integer');
  return { mode: 'local', binary, out: path.resolve(out), profile, suite, against: against === undefined ? undefined : path.resolve(against), timeout };
}

export function daemonConfig(profile) {
  if (!['strict', 'emulator'].includes(profile)) throw Error('--profile is strict or emulator');
  return { schemaVersion: 1, profile, daemon: { authProject: 'demo-small-observer', hubPort: 0, uiPort: 0, loggingPort: 0 } };
}

/** argv of `fireemu exec`: only the database, on a free port, then the observer in emulator mode. */
export function execPlan(binary, config, observerOut, runId, suite) {
  const prefix = `/sdkevents${randomBytes(5).toString('hex')}`;
  return [binary, 'exec', '--no-config-discovery', '--config', config, '--only', 'database', '--database-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet', '--',
    process.execPath, '--max-old-space-size=1024', OBSERVER, '--target', 'emulator', '--suite', suite, '--run-id', runId, '--prefix', prefix, '--direct-cap', '250', '--out', observerOut, '--continue-on-failure'];
}

/** Reduces the observer run in <out>/observer to journal.json; with a recorded reduction also writes comparison.json and returns it. */
export function finish(out, recorded = null) {
  const dir = path.join(out, 'observer');
  const reduced = reduceEventsJournal(parseJsonl(readFileSync(path.join(dir, 'journal.jsonl'), 'utf8')), JSON.parse(readFileSync(path.join(dir, 'result.json'), 'utf8')));
  writeFileSync(path.join(out, 'journal.json'), `${JSON.stringify(reduced, null, 1)}\n`, { flag: 'wx' });
  if (recorded === null) return null;
  const comparison = summarize(recorded, reduced);
  writeFileSync(path.join(out, 'comparison.json'), `${JSON.stringify(comparison, null, 1)}\n`, { flag: 'wx' });
  return comparison;
}
const line = (s, suite) => `${s.counts.MATCH}/${stepCount(suite)} MATCH, ${s.counts.MISMATCH} MISMATCH, ${s.counts.NEEDS_REVIEW} NEEDS_REVIEW, match=${s.match}${s.problems.length ? `; problems: ${s.problems.join('; ')}` : ''}`;

/** Runs the plan in its own process group; the group is ended when the run finishes, times out or we are signalled. */
function runExec(argv, timeout) {
  return new Promise(resolve => {
    const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'inherit', 'inherit'], detached: true });
    const end = signal => { try { process.kill(-child.pid, signal); } catch { /* group already gone */ } };
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; end('SIGTERM'); setTimeout(() => end('SIGKILL'), 5000).unref(); }, timeout);
    const onSignal = () => end('SIGTERM');
    for (const s of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(s, onSignal);
    child.on('error', error => { clearTimeout(timer); resolve({ code: null, error }); });
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      for (const s of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.off(s, onSignal);
      end('SIGKILL'); // anything the producer left behind in its group
      resolve({ code, signal, timedOut });
    });
  });
}

async function main(argv) {
  const o = options(argv);
  if (o.mode === 'compare') {
    const recorded = JSON.parse(readFileSync(o.recorded, 'utf8')), s = summarize(recorded, JSON.parse(readFileSync(o.local, 'utf8')));
    console.log(`rtdb-sdk-events compare: ${line(s, recorded.suite)}`);
    return s.match ? 0 : 1;
  }
  const recorded = o.against === undefined ? null : JSON.parse(readFileSync(o.against, 'utf8'));
  mkdirSync(o.out); // refuses an existing directory
  const config = path.join(o.out, 'config.json');
  writeFileSync(config, `${JSON.stringify(daemonConfig(o.profile))}\n`, { flag: 'wx' });
  const runId = `LOCAL-SDK-EVENTS-${o.profile}-${randomBytes(4).toString('hex')}`;
  const exec = await runExec(execPlan(o.binary, config, path.join(o.out, 'observer'), runId, o.suite), o.timeout);
  if (exec.timedOut) { console.error(`rtdb-sdk-events: fireemu exec timed out after ${o.timeout} ms`); return 3; }
  if (exec.code === null) { console.error(`rtdb-sdk-events: fireemu exec did not run: ${exec.error?.message ?? exec.signal}`); return 3; }
  let s;
  try { s = finish(o.out, recorded); } catch (error) { console.error(`rtdb-sdk-events: no reduction: ${error.message}`); return exec.code || 2; }
  console.log(`rtdb-sdk-events ${o.profile} ${o.suite}: observer exit ${exec.code}${s ? `, ${line(s, o.suite)}` : ''}`);
  return exec.code;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }, e => { console.error(`rtdb-sdk-events: ${e.message}`); process.exitCode = 2; });
}
