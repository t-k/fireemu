// Local replay of the RTDB SDK small observer (sdk-observer/): the 32 SDK observations of production run
// RTDB-SMALL-20261102-01 (4 profiles: round 1 and 2, WebSocket in Node and long polling in headless Chromium, x 8
// cases) against fireemu, judged against fixtures/production-sdk-small.json by rtdb-sdk-small-judge.mjs.
//
//   node rtdb-sdk-small.mjs local --fireemu <bin> --out <new dir> [--profile strict|emulator] [--modules <node_modules>]
//
// It runs `fireemu exec --only database` (own process group, ended on exit, timeout and signal) with the observer in
// emulator mode as the command; the observer installs its Rules, runs the profiles and restores everything itself.
// Outputs in <out>: config.json, observer/ (the observer's journal.jsonl and result.json), journal.json (the reduced
// journal) and comparison.json. The exit status is the observer's (0 = all 32 observed and the cleanup verified); the
// judge's answer is in comparison.json and is what the release replay adjudicates. The production entry of the
// observer is `sdk-observer/observer.mjs --target production` (packet-gated; never used by this replay).
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseJsonl, reduceJournal } from './rtdb-sdk-small-fixture.mjs';
import { summarize } from './rtdb-sdk-small-judge.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const OBSERVER = path.join(here, 'sdk-observer', 'observer.mjs');
export const FIXTURE = path.join(here, 'fixtures', 'production-sdk-small.json');
// Above the observer's own backstop (12 min) so that the observer, not this timer, ends a slow run.
const EXEC_TIMEOUT_MS = 14 * 60 * 1000;

export function options(argv) {
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  const binary = opt('--fireemu'), out = opt('--out'), profile = opt('--profile') ?? 'strict', modules = opt('--modules');
  if (argv[0] !== 'local' || !binary || !out) throw Error('usage: local --fireemu <bin> --out <new dir> [--profile strict|emulator] [--modules <node_modules>]');
  if (!['strict', 'emulator'].includes(profile)) throw Error('--profile is strict or emulator');
  // The Node WebSocket profile imports the SDK by package resolution, so only the package's own node_modules can be meant.
  if (modules !== undefined && path.resolve(modules) !== path.join(here, 'node_modules')) throw Error('--modules must be this package\'s node_modules (the observer resolves the SDK from there)');
  const timeout = Number(opt('--exec-timeout-ms') ?? EXEC_TIMEOUT_MS);
  if (!Number.isSafeInteger(timeout) || timeout <= 0) throw Error('--exec-timeout-ms must be a positive integer');
  return { binary, out: path.resolve(out), profile, timeout };
}

export function daemonConfig(profile) {
  if (!['strict', 'emulator'].includes(profile)) throw Error('--profile is strict or emulator');
  return { schemaVersion: 1, profile, daemon: { authProject: 'demo-small-observer', hubPort: 0, uiPort: 0, loggingPort: 0 } };
}

/** argv of `fireemu exec`: only the database, on a free port, then the observer in emulator mode. */
export function execPlan(binary, config, observerOut, runId) {
  const prefix = `/sdksmall${randomBytes(5).toString('hex')}`;
  return [binary, 'exec', '--no-config-discovery', '--config', config, '--only', 'database', '--database-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet', '--',
    process.execPath, '--max-old-space-size=1024', OBSERVER, '--target', 'emulator', '--run-id', runId, '--prefix', prefix, '--direct-cap', '180', '--out', observerOut];
}

/** Reduces the observer run in <out>/observer, judges it against the fixture and writes journal.json and comparison.json. */
export function finish(out, fixture = JSON.parse(readFileSync(FIXTURE, 'utf8'))) {
  const dir = path.join(out, 'observer');
  const reduced = reduceJournal(parseJsonl(readFileSync(path.join(dir, 'journal.jsonl'), 'utf8')), JSON.parse(readFileSync(path.join(dir, 'result.json'), 'utf8')));
  const comparison = summarize(fixture, reduced);
  writeFileSync(path.join(out, 'journal.json'), `${JSON.stringify(reduced, null, 1)}\n`, { flag: 'wx' });
  writeFileSync(path.join(out, 'comparison.json'), `${JSON.stringify(comparison, null, 1)}\n`, { flag: 'wx' });
  return comparison;
}

/** Runs the plan in its own process group; the group is ended when the run finishes, times out or we are signalled. */
function runExec(argv, timeout) {
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'inherit', 'inherit'], detached: true });
    const end = (signal) => { try { process.kill(-child.pid, signal); } catch { /* group already gone */ } };
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; end('SIGTERM'); setTimeout(() => end('SIGKILL'), 5000).unref(); }, timeout);
    const onSignal = () => end('SIGTERM');
    for (const s of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(s, onSignal);
    child.on('error', (error) => { clearTimeout(timer); resolve({ code: null, error }); });
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
  mkdirSync(o.out); // refuses an existing directory
  const config = path.join(o.out, 'config.json');
  writeFileSync(config, `${JSON.stringify(daemonConfig(o.profile))}\n`, { flag: 'wx' });
  const runId = `LOCAL-SDK-SMALL-${o.profile}-${randomBytes(4).toString('hex')}`;
  const exec = await runExec(execPlan(o.binary, config, path.join(o.out, 'observer'), runId), o.timeout);
  if (exec.timedOut) { console.error(`rtdb-sdk-small: fireemu exec timed out after ${o.timeout} ms`); return 3; }
  if (exec.code === null) { console.error(`rtdb-sdk-small: fireemu exec did not run: ${exec.error?.message ?? exec.signal}`); return 3; }
  let s;
  try { s = finish(o.out); } catch (error) { console.error(`rtdb-sdk-small: no comparison: ${error.message}`); return exec.code || 2; }
  console.log(`rtdb-sdk-small ${o.profile}: observer exit ${exec.code}, ${s.counts.MATCH}/32 MATCH, ${s.counts.MISMATCH} MISMATCH, ${s.counts.NEEDS_REVIEW} NEEDS_REVIEW, match=${s.match}`);
  return exec.code;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(`rtdb-sdk-small: ${e.message}`); process.exitCode = 2; });
}
