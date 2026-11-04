// The reduced journal of the tokens suite (G10) of the RTDB SDK observer (sdk-observer/ --suite tokens): per profile
// (r1-tokens, r2-tokens, in order) the case rows the suite wrote, in journal order, with every recorded field (the rules
// suite's row fields), and the ready probes (how many attempts, ready or not). Dropped: row timestamps, the admin request
// and answer rows. A row the reducer cannot place refuses the whole journal. A local run writes this reduction as
// journal.json; a production fixture is the reduction of a production run plus its provenance:
//
//   node rtdb-sdk-tokens-fixture.mjs fixture <journal.jsonl> <result.json> <fixture.json> --recorded-on <date> --booking-row <n> --close-row <n> --approvals <n,n> --requests <n> --packet-sha256 <hex> --source-head <sha>
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assertPublishable, parseJsonl } from './rtdb-sdk-small-fixture.mjs';
import { ROW_FIELDS as RULES_ROW_FIELDS, recordedJournal } from './rtdb-sdk-rules-fixture.mjs';
import { TOKENS_CASES, TOKENS_PROFILES } from './sdk-observer/tokens-suite.mjs';

export const KIND = 'rtdb-sdk-tokens-journal-v1';
export const ROW_FIELDS = [...RULES_ROW_FIELDS, 'unknownObservation'];   // a GET whose answer cannot be judged is listed, not counted
export { recordedJournal };
const FAULTS = ['abort', 'error', 'profile-error', 'timeout'];
const IGNORED = ['admin-req', 'admin-res', 'admin-unknown', 'result', 'cleanup'];

function profileOf(profiles, row, what) {
  const p = profiles.find(x => x.name === row.profile);
  if (!p) throw Error(`unknown profile ${row.profile} in a ${what} row`);
  if (row.suite !== 'tokens') throw Error(`${what} row of suite ${row.suite} in the tokens profile ${p.name}`);
  return p;
}

/** The reduced journal of one observer run of the tokens suite; `result` is its result.json. */
export function reduceTokensJournal(rows, result) {
  if (!Array.isArray(rows)) throw Error('journal rows must be an array');
  if (!result || typeof result !== 'object') throw Error('result.json is missing');
  if (result.suite !== 'tokens') throw Error(`result.json suite ${result.suite} is not the tokens suite`);
  if (typeof result.prefix !== 'string') throw Error('result.json has no prefix');
  const profiles = TOKENS_PROFILES.map(name => ({ name, rows: [], probes: [] })), faults = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw Error('journal row is not an object');
    if (row.kind === 'case') {
      const p = profileOf(profiles, row, 'case');
      if (!TOKENS_CASES.includes(row.id) || typeof row.ok !== 'boolean') throw Error(`unknown case row ${row.id}`);
      const extra = Object.keys(row).filter(k => !['t', 'kind', 'suite', 'profile', ...ROW_FIELDS].includes(k));
      if (extra.length) throw Error(`case row ${row.id} has unrecorded fields ${extra.join()}`);
      p.rows.push(Object.fromEntries(ROW_FIELDS.filter(k => Object.hasOwn(row, k)).map(k => [k, row[k]])));
    } else if (row.kind === 'probe') {
      const p = profileOf(profiles, row, 'probe');
      if (row.after !== 'start' || !Number.isSafeInteger(row.attempt) || row.attempt < 1 || typeof row.ready !== 'boolean') throw Error(`unknown probe row after ${row.after}`);
      const last = p.probes.at(-1);
      if (last && !last.ready) { if (row.attempt !== last.attempts + 1) throw Error('probe attempts out of order'); last.attempts = row.attempt; last.ready = row.ready; last.outcome = row.outcome; }
      else { if (row.attempt !== 1) throw Error('probe attempts out of order'); p.probes.push({ after: row.after, attempts: 1, ready: row.ready, outcome: row.outcome }); }
    } else if (FAULTS.includes(row.kind)) faults.push({ kind: row.kind, profile: profiles.some(x => x.name === row.profile) ? row.profile : null });
    else if (!IGNORED.includes(row.kind)) throw Error(`unknown journal row kind ${row.kind}`);
  }
  const { status, observed, exit, cleanup } = result;
  return { kind: KIND, suite: 'tokens', result: { status, observed, exit, cleanup, unverified: Array.isArray(result.unverified) ? result.unverified.map(String) : ['result.json has no unverified list'], prefixLength: result.prefix.length }, faults, profiles };
}

/** The case code of the suite that runs in production; a fixture pins it (the whole observer is pinned by scriptSha256). */
export const CASE_SOURCES = ['tokens-suite.mjs'];
const META_FIELDS = ['recordedOn', 'bookingRow', 'closeRow', 'approvals', 'requests', 'packetSha256', 'sourceHead', 'journalSha256', 'resultSha256'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const present = v => v !== undefined && v !== null && v !== '' && !Number.isNaN(v) && !(Array.isArray(v) && v.length === 0);

/** The production fixture: the reduction of a production journal and the provenance the closure quotes. */
export function buildTokensFixture(rows, result, meta) {
  if (result?.target !== 'production') throw Error('a fixture is made from a production run only');
  for (const field of META_FIELDS) if (!present(meta?.[field])) throw Error(`missing ${field}`);
  const { direct, reserve, adc, overflow = 0 } = result.counts ?? {};
  if (direct + reserve !== meta.requests) throw Error(`direct ${direct} + reserve ${reserve} is not the ledger's ${meta.requests} requests`);
  if (adc !== 1) throw Error('the run must have taken exactly one ADC token');
  if (overflow !== 0) throw Error(`the run counted ${overflow} requests over its cap (overflow)`);
  if (!Array.isArray(result.unverified) || result.unverified.length) throw Error('the run left unverified (unknown) writes');
  const reduced = reduceTokensJournal(rows, result);
  const caseSources = Object.fromEntries(CASE_SOURCES.map(name => [name, sha256(readFileSync(new URL(`./sdk-observer/${name}`, import.meta.url)))]));
  const provenance = {
    runId: result.runId, target: result.target, project: 'fireemu-oracle-query', instance: 'fireemu-q-rtdb2', suite: 'tokens', recordedOn: meta.recordedOn, startedAt: result.startedAt, endedAt: result.endedAt,
    scriptSha256: result.scriptSha256, sourceHead: meta.sourceHead, packetSha256: meta.packetSha256, caseSources,
    counts: { requests: meta.requests, direct, reserve, adc, overflow }, caps: result.caps, cleanup: result.cleanup, observations: result.observed,
    sandboxLedger: { booking: meta.bookingRow, close: meta.closeRow }, approvals: meta.approvals, journalSha256: meta.journalSha256, resultSha256: meta.resultSha256,
  };
  const doc = { ...reduced, provenance };
  assertPublishable(JSON.stringify(doc));
  return doc;
}

function main(argv) {
  const opt = n => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] !== 'fixture' || argv.length < 4) throw Error('usage: fixture <journal.jsonl> <result.json> <fixture.json> --recorded-on <date> --booking-row <n> --close-row <n> --approvals <n,n> --requests <n> --packet-sha256 <hex> --source-head <sha>');
  const [journalFile, resultFile, output] = argv.slice(1, 4), journalBytes = readFileSync(journalFile), resultBytes = readFileSync(resultFile);
  const meta = {
    recordedOn: opt('--recorded-on'), bookingRow: Number(opt('--booking-row')), closeRow: Number(opt('--close-row')), approvals: (opt('--approvals') ?? '').split(',').filter(Boolean).map(Number),
    requests: Number(opt('--requests')), packetSha256: opt('--packet-sha256'), sourceHead: opt('--source-head'), journalSha256: sha256(journalBytes), resultSha256: sha256(resultBytes),
  };
  const doc = buildTokensFixture(parseJsonl(journalBytes.toString('utf8')), JSON.parse(resultBytes), meta);
  writeFileSync(output, `${JSON.stringify(doc, null, 1)}\n`, { flag: 'wx' });
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); } catch (e) { console.error(`rtdb-sdk-tokens-fixture: ${e.message}`); process.exitCode = 2; }
}
