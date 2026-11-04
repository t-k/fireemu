// Local entry of the tokens suite (G10) of the RTDB SDK observer (sdk-observer/ --suite tokens): runs the suite against
// fireemu, reduces the journal (rtdb-sdk-tokens-fixture.mjs) and, with --against, judges it (rtdb-sdk-tokens-judge.mjs)
// against a recorded reduction (a production fixture or another local journal.json); `compare` judges two of them.
//
//   node rtdb-sdk-tokens.mjs local --fireemu <bin> --out <new dir> [--profile strict|emulator] [--against <fixture or journal.json>]
//   node rtdb-sdk-tokens.mjs compare <recorded fixture or journal.json> <local journal.json>
//
// `local` runs `fireemu exec --only database` (own process group, ended on exit, timeout and signal; the rules entry's
// options and runExec) with the observer in emulator mode as the command. The local prefix has the length of the
// production prefix form `/sdktokensYYYYMMDD` (18 characters) and the daemon's project is the observer's local tokens
// project `demo-tokens-observer` (the length of the production project id), so masked answers keep their byte length.
// Outputs in <out>: config.json, observer/ (journal.jsonl, result.json), journal.json and, with --against,
// comparison.json. The exit status of `local` is the observer's; `compare` exits 0 on a match and 1 otherwise. The
// production entry is `sdk-observer/observer.mjs --target production --suite tokens` (packet-gated; never used here).
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseJsonl } from './rtdb-sdk-small-fixture.mjs';
import { recordedJournal, reduceTokensJournal } from './rtdb-sdk-tokens-fixture.mjs';
import { caseCount, summarize } from './rtdb-sdk-tokens-judge.mjs';
import { OBSERVER, options, runExec } from './rtdb-sdk-rules.mjs';
import { localTarget } from './sdk-observer/observer.mjs';

export const LOCAL_DIRECT_CAP = 80;
const PROJECT = localTarget('tokens', '').projectId;

export function daemonConfig(profile) {
  if (!['strict', 'emulator'].includes(profile)) throw Error('--profile is strict or emulator');
  return { schemaVersion: 1, profile, daemon: { authProject: PROJECT, hubPort: 0, uiPort: 0, loggingPort: 0 } };
}

/** A local prefix of the production prefix's length: `/sdktokens` and eight hex digits. */
export const localPrefix = () => `/sdktokens${randomBytes(4).toString('hex')}`;

/** argv of `fireemu exec`: only the database, on a free port, then the observer in emulator mode. */
export function execPlan(binary, config, observerOut, runId, prefix = localPrefix()) {
  return [binary, 'exec', '--no-config-discovery', '--config', config, '--only', 'database', '--database-port', '0', '--hub-port', '0', '--logging-port', '0', '--log-verbosity', 'quiet', '--',
    process.execPath, '--max-old-space-size=1024', OBSERVER, '--target', 'emulator', '--suite', 'tokens', '--run-id', runId, '--prefix', prefix, '--direct-cap', String(LOCAL_DIRECT_CAP), '--out', observerOut, '--continue-on-failure'];
}

/** Reduces the observer run in <out>/observer to journal.json; with a recorded reduction also writes comparison.json and returns it. */
export function finish(out, recorded = null) {
  const dir = path.join(out, 'observer');
  const reduced = reduceTokensJournal(parseJsonl(readFileSync(path.join(dir, 'journal.jsonl'), 'utf8')), JSON.parse(readFileSync(path.join(dir, 'result.json'), 'utf8')));
  writeFileSync(path.join(out, 'journal.json'), `${JSON.stringify(reduced, null, 1)}\n`, { flag: 'wx' });
  if (recorded === null) return null;
  const comparison = summarize(recorded, reduced);
  writeFileSync(path.join(out, 'comparison.json'), `${JSON.stringify(comparison, null, 1)}\n`, { flag: 'wx' });
  return comparison;
}
const line = s => `${s.counts.MATCH}/${caseCount()} MATCH, ${s.counts.MISMATCH} MISMATCH, ${s.counts.NEEDS_REVIEW} NEEDS_REVIEW, match=${s.match}${s.problems.length ? `; problems: ${s.problems.join('; ')}` : ''}`;

async function main(argv) {
  const o = options(argv);
  if (o.mode === 'compare') {
    const s = summarize(recordedJournal(JSON.parse(readFileSync(o.recorded, 'utf8'))), JSON.parse(readFileSync(o.local, 'utf8')));
    console.log(`rtdb-sdk-tokens compare: ${line(s)}`);
    for (const r of s.rows.filter(x => x.verdict !== 'MATCH')) console.log(`  ${r.profile} ${r.case}: ${r.verdict} ${r.reason}${r.differences?.length ? ` (${r.differences.join(', ')})` : ''}`);
    return s.match ? 0 : 1;
  }
  const recorded = o.against === undefined ? null : recordedJournal(JSON.parse(readFileSync(o.against, 'utf8')));
  mkdirSync(o.out);   // refuses an existing directory
  const config = path.join(o.out, 'config.json');
  writeFileSync(config, `${JSON.stringify(daemonConfig(o.profile))}\n`, { flag: 'wx' });
  const runId = `LOCAL-SDK-TOKENS-${o.profile}-${randomBytes(4).toString('hex')}`;
  const exec = await runExec(execPlan(o.binary, config, path.join(o.out, 'observer'), runId), o.timeout);
  if (exec.timedOut) { console.error(`rtdb-sdk-tokens: fireemu exec timed out after ${o.timeout} ms`); return 3; }
  if (exec.code === null) { console.error(`rtdb-sdk-tokens: fireemu exec did not run: ${exec.error?.message ?? exec.signal}`); return 3; }
  let s;
  try { s = finish(o.out, recorded); } catch (error) { console.error(`rtdb-sdk-tokens: no reduction: ${error.message}`); return exec.code || 2; }
  console.log(`rtdb-sdk-tokens ${o.profile}: observer exit ${exec.code}${s ? `, ${line(s)}` : ''}`);
  return exec.code;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }, e => { console.error(`rtdb-sdk-tokens: ${e.message}`); process.exitCode = 2; });
}
