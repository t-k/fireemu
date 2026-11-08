// The reduced journals of the events (G6) and admin (G13) suites of the RTDB SDK observer (sdk-observer/ --suite
// events|admin|events+admin): the SDK-level facts the comparison reads, out of the observer's journal.jsonl.
//
// Kept: per profile (in the suite's fixed order) the case rows in journal order: id, ok, the recorded steps (ordered
// observer and writer callbacks, acknowledgements, results, the ready/quiet bounds) or the error. Dropped: row
// timestamps, admin requests and answers, raw WebSocket, long-polling and connect capture. A row the reducer cannot
// place refuses the whole journal. A local run writes this reduction as journal.json; the committed production fixture
// (fixtures/production-sdk-events.json) is the reduction of run RTDB-EVENTS-20261104-01 plus its provenance:
//
//   node rtdb-sdk-events-fixture.mjs fixture <journal.jsonl> <result.json> <fixture.json> --recorded-on <date> --booking-row <n> --close-row <n> --approvals <n,n> --requests <n> --packet-sha256 <hex> --source-head <sha>
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assertPublishable, parseJsonl } from './rtdb-sdk-small-fixture.mjs';
import { ADMIN_PROFILES, EVENTS_PROFILES } from './sdk-observer/events-rules.mjs';
import { EVENT_CASES } from './sdk-observer/events-actor.mjs';
import { ADMIN_CASES } from './sdk-observer/admin-suite.mjs';

export const KIND = 'rtdb-sdk-events-journal-v1';
export const SUITE_PARTS = { events: ['events'], admin: ['admin'], 'events+admin': ['events', 'admin'] };
/** Setup rows before the cases, per suite part. */
export const SETUP = { events: ['startup', 'startup-observer', 'seed'], admin: ['startup'] };
export const CASES = { events: EVENT_CASES, admin: ADMIN_CASES };
const NAMES = { events: EVENTS_PROFILES, admin: ADMIN_PROFILES };
const FAULTS = ['abort', 'error', 'profile-error', 'page-error', 'timeout'];
const IGNORED = ['lp-inflight', 'admin-req', 'admin-res', 'admin-unknown', 'raw-ws', 'raw-lp-request', 'raw-lp-response', 'raw-page-ws', 'raw-admin-connect', 'result', 'cleanup'];

/** The profiles of a suite, in the observer's order. */
export function profilesOf(suite) {
  if (!Object.hasOwn(SUITE_PARTS, suite)) throw Error(`unknown suite ${suite}`);
  return SUITE_PARTS[suite].flatMap(part => NAMES[part].map(name => ({ name, suite: part })));
}

/** The reduced journal of one observer run of these suites; `result` is its result.json. */
export function reduceEventsJournal(rows, result) {
  if (!Array.isArray(rows)) throw Error('journal rows must be an array');
  if (!result || typeof result !== 'object') throw Error('result.json is missing');
  if (!Object.hasOwn(SUITE_PARTS, result.suite)) throw Error(`result.json suite ${result.suite} is not an events or admin suite`);
  const profiles = profilesOf(result.suite).map(p => ({ ...p, rows: [] })), faults = [];
  const named = name => profiles.find(p => p.name === name);
  for (const row of rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw Error('journal row is not an object');
    if (row.kind === 'case') {
      const p = named(row.profile);
      if (!p) throw Error(`unknown profile ${row.profile} in a case row`);
      if (row.suite !== p.suite) throw Error(`case row of suite ${row.suite} in the ${p.suite} profile ${p.name}`);
      if (![...SETUP[p.suite], ...CASES[p.suite]].includes(row.id) || typeof row.ok !== 'boolean') throw Error(`unknown case row ${row.id}`);
      const setup = SETUP[p.suite].includes(row.id);
      if (!setup && !Array.isArray(row.steps)) throw Error(`case row ${row.id} has no steps`);
      const kept = { id: row.id, ok: row.ok };
      if (!row.ok) kept.error = String(row.error).slice(0, 200);
      if (!setup) kept.steps = row.steps;
      if (Array.isArray(row.unknown) && row.unknown.length) kept.unknown = row.unknown.map(String);   // a mutation that timed out: its outcome is unknown, the comparison must not call the case clean
      p.rows.push(kept);
    } else if (FAULTS.includes(row.kind)) faults.push({ kind: row.kind, profile: named(row.profile) ? row.profile : null });
    else if (!IGNORED.includes(row.kind)) throw Error(`unknown journal row kind ${row.kind}`);
  }
  const { status, observed, exit, cleanup, credentialOutcome } = result;   // credentialOutcome: the admin profiles whose Admin SDK credential was refused; kept so the judge never reads them as G13 evidence
  return { kind: KIND, suite: result.suite, result: { status, observed, exit, cleanup, ...(credentialOutcome === undefined ? {} : { credentialOutcome }) }, faults, profiles };
}

/** The case code of these suites that ran in production unchanged; the fixture pins it (the whole observer is pinned by scriptSha256). */
export const CASE_SOURCES = ['events-actor.mjs', 'events-sequence.mjs', 'events-rules.mjs', 'events-page.mjs', 'events-page.html', 'admin-suite.mjs'];
/** How the Admin SDK of the admin profiles authenticated in the recorded run. */
export const CREDENTIAL = 'the gcloud user OAuth access token of the operator, passed to firebase-admin 14.3.0 as a custom credential; not a service account';
const META_FIELDS = ['recordedOn', 'bookingRow', 'closeRow', 'approvals', 'requests', 'packetSha256', 'sourceHead', 'credential', 'journalSha256', 'resultSha256'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const present = v => v !== undefined && v !== null && v !== '' && !Number.isNaN(v) && !(Array.isArray(v) && v.length === 0);

/** The largest in-flight long-polling request count each long-polling profile measured (lp-inflight rows). */
export function maxInFlightOf(rows) {
  const out = {};
  for (const row of rows) {
    if (row?.kind !== 'lp-inflight') continue;
    if (!EVENTS_PROFILES.includes(row.profile) || !row.profile.endsWith('-lp') || !Number.isSafeInteger(row.maxInFlight)) throw Error('malformed in-flight measurement row');
    out[row.profile] = Math.max(out[row.profile] ?? 0, row.maxInFlight);
  }
  return out;
}

/** The production fixture: the reduction of a production journal and the provenance the closure quotes. */
export function buildEventsFixture(rows, result, meta) {
  if (result?.target !== 'production') throw Error('a fixture is made from a production run only');
  for (const field of META_FIELDS) if (!present(meta?.[field])) throw Error(`missing ${field}`);
  const { direct, reserve, adc, overflow = 0 } = result.counts ?? {};
  if (direct + reserve !== meta.requests) throw Error(`direct ${direct} + reserve ${reserve} is not the ledger's ${meta.requests} requests`);
  if (adc !== 1) throw Error('the run must have taken exactly one ADC token');
  if (overflow !== 0) throw Error(`the run counted ${overflow} requests over its cap (overflow)`);
  if (result.credentialOutcome !== undefined) throw Error('an Admin SDK credential was refused (credentialOutcome): not G13 evidence');
  if (!Array.isArray(result.unverified) || result.unverified.length) throw Error('the run left unverified (unknown) writes');
  const reduced = reduceEventsJournal(rows, result);
  const admins = reduced.profiles.filter(p => p.suite === 'admin').map(p => p.name), startup = result.adminStartup ?? {};
  if (admins.some(name => startup[name] !== true)) throw Error('an admin profile has no recorded startup');
  const caseSources = Object.fromEntries(CASE_SOURCES.map(name => [name, sha256(readFileSync(new URL(`./sdk-observer/${name}`, import.meta.url)))]));
  const provenance = {
    runId: result.runId, target: result.target, project: 'fireemu-oracle-query', instance: 'fireemu-q-rtdb2', suite: result.suite, recordedOn: meta.recordedOn, startedAt: result.startedAt, endedAt: result.endedAt,
    scriptSha256: result.scriptSha256, sourceHead: meta.sourceHead, packetSha256: meta.packetSha256, sdk: result.sdk, caseSources,
    counts: { requests: meta.requests, direct, reserve, adc, overflow }, caps: result.caps, maxInFlight: maxInFlightOf(rows),
    adminStartup: Object.fromEntries(admins.map(name => [name, true])), credential: meta.credential, cleanup: result.cleanup, observations: result.observed,
    sandboxLedger: { booking: meta.bookingRow, close: meta.closeRow }, approvals: meta.approvals, journalSha256: meta.journalSha256, resultSha256: meta.resultSha256,
  };
  const doc = { ...reduced, provenance };
  assertPublishable(JSON.stringify(doc));
  return doc;
}

/** The recorded side of a comparison: a production fixture without its provenance, or a plain reduced journal as it is. */
export function recordedJournal(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw Error('not a reduced SDK events journal');
  if (!Object.hasOwn(doc, 'provenance')) return doc;
  if (doc.provenance?.target !== 'production') throw Error('a fixture provenance must name a production run');
  const { provenance: _provenance, ...reduced } = doc;
  return reduced;
}

function main(argv) {
  const opt = n => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] !== 'fixture' || argv.length < 4) throw Error('usage: fixture <journal.jsonl> <result.json> <fixture.json> --recorded-on <date> --booking-row <n> --close-row <n> --approvals <n,n> --requests <n> --packet-sha256 <hex> --source-head <sha>');
  const [journalFile, resultFile, output] = argv.slice(1, 4), journalBytes = readFileSync(journalFile), resultBytes = readFileSync(resultFile);
  const meta = {
    recordedOn: opt('--recorded-on'), bookingRow: Number(opt('--booking-row')), closeRow: Number(opt('--close-row')), approvals: (opt('--approvals') ?? '').split(',').filter(Boolean).map(Number),
    requests: Number(opt('--requests')), packetSha256: opt('--packet-sha256'), sourceHead: opt('--source-head'), credential: CREDENTIAL, journalSha256: sha256(journalBytes), resultSha256: sha256(resultBytes),
  };
  const doc = buildEventsFixture(parseJsonl(journalBytes.toString('utf8')), JSON.parse(resultBytes), meta);
  writeFileSync(output, `${JSON.stringify(doc, null, 1)}\n`, { flag: 'wx' });
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); } catch (e) { console.error(`rtdb-sdk-events-fixture: ${e.message}`); process.exitCode = 2; }
}
