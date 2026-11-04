// The reduced journals of the RTDB SDK small observer (sdk-observer/): the SDK-level facts the comparison reads, out of
// the observer's journal.jsonl. The committed production fixture (fixtures/production-sdk-small.json) is the reduction
// of run RTDB-SMALL-20261102-01 plus its provenance; a local replay writes the same reduction as journal.json.
//
//   node rtdb-sdk-small-fixture.mjs fixture <journal.jsonl> <result.json> <fixture.json> --recorded-on <date> --ledger-row <n> --approval <n> --requests <n>
//
// Kept: per profile the case rows (role, id, ok, value or error) in journal order and the per-role connection events.
// Dropped: timestamps of rows, case timings, admin requests and answers, raw WebSocket and long-polling capture, the
// interleaving of the two roles' events. A row the reducer cannot place refuses the whole journal.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assertNoSecrets } from './cv11-genuine-auth.mjs';
import { CASES, KIND, PROFILE_NAMES, SETUP } from './rtdb-sdk-small-judge.mjs';

/** The case code that ran in production unchanged; the fixture pins it and the replay runs these bytes. */
export const CASE_SOURCES = ['actor.mjs', 'sequence.mjs', 'rules.mjs', 'page.mjs', 'page.html'];
const ROLES = ['writer', 'observer'];
const IDS = [...SETUP, ...CASES].map(([, id]) => id);
const FAULTS = ['abort', 'error', 'profile-error', 'page-error', 'timeout'];
const IGNORED = ['lp-inflight', 'admin-req', 'admin-res', 'admin-unknown', 'raw-ws', 'raw-lp-request', 'raw-lp-response', 'result', 'cleanup'];
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const own = (list, v) => typeof v === 'string' && list.includes(v);

export function parseJsonl(text) {
  return text.split('\n').filter((line) => line.trim()).map((line) => JSON.parse(line));
}

/** The reduced journal of one observer run; `result` is its result.json. */
export function reduceJournal(rows, result) {
  if (!Array.isArray(rows)) throw Error('journal rows must be an array');
  if (!result || typeof result !== 'object') throw Error('result.json is missing');
  const profiles = PROFILE_NAMES.map((name) => ({ name, events: { writer: [], observer: [] }, rows: [] }));
  const of = (row) => { if (!own(PROFILE_NAMES, row.profile)) throw Error(`unknown profile in a ${row.kind} row`); if (!own(ROLES, row.role)) throw Error(`unknown role in a ${row.kind} row`); return profiles[PROFILE_NAMES.indexOf(row.profile)]; };
  const faults = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object') throw Error('journal row is not an object');
    if (row.kind === 'case') {
      const p = of(row);
      if (!own(IDS, row.id) || typeof row.ok !== 'boolean') throw Error(`unknown case row ${row.id}`);
      p.rows.push(row.ok ? { role: row.role, id: row.id, ok: true, value: row.value } : { role: row.role, id: row.id, ok: false, error: String(row.error).slice(0, 200) });
    } else if (row.kind === 'sdk-event') {
      if (row.event !== 'connected' && row.event !== 'disconnected') throw Error(`unknown sdk event ${row.event}`);
      of(row).events[row.role].push(row.event);
    } else if (FAULTS.includes(row.kind)) faults.push({ kind: row.kind, profile: own(PROFILE_NAMES, row.profile) ? row.profile : null });
    else if (!IGNORED.includes(row.kind)) throw Error(`unknown journal row kind ${row.kind}`);
  }
  const { status, observed, exit, cleanup } = result;
  return { kind: KIND, result: { status, observed, exit, cleanup }, faults, profiles };
}

/** Refuses secret-shaped text and any standalone 12-digit number (the length of a project number). */
export function assertPublishable(text) {
  assertNoSecrets(text, []);
  if (/(?<![0-9])[0-9]{12}(?![0-9])/.test(text)) throw Error('refusing a 12-digit number (project number shape)');
  return text;
}

/** The production fixture: the reduction of the production journal and the provenance the closure quotes. */
export function buildFixture(rows, result, meta) {
  if (result?.target !== 'production') throw Error('a fixture is made from a production run only');
  for (const field of ['recordedOn', 'ledgerRow', 'approval', 'requests', 'journalSha256', 'resultSha256']) if (meta?.[field] === undefined || meta[field] === '') throw Error(`missing ${field}`);
  const { direct, reserve, adc } = result.counts ?? {};
  if (direct + reserve !== meta.requests) throw Error(`direct ${direct} + reserve ${reserve} is not the ledger's ${meta.requests} requests`);
  if (adc !== 1) throw Error('the run must have taken exactly one ADC token');
  const caseSources = Object.fromEntries(CASE_SOURCES.map((name) => [name, sha256(readFileSync(new URL(`./sdk-observer/${name}`, import.meta.url)))]));
  const provenance = {
    runId: result.runId, target: result.target, project: 'fireemu-oracle-query', instance: 'fireemu-q-rtdb2', recordedOn: meta.recordedOn, startedAt: result.startedAt, endedAt: result.endedAt,
    scriptSha256: result.scriptSha256, sdk: result.sdk, caseSources, counts: { requests: meta.requests, direct, reserve, adc }, cleanup: result.cleanup, observations: result.observed,
    ledgerRow: meta.ledgerRow, approval: meta.approval, journalSha256: meta.journalSha256, resultSha256: meta.resultSha256,
  };
  const doc = { ...reduceJournal(rows, result), provenance };
  assertPublishable(JSON.stringify(doc));
  return doc;
}

function main(argv) {
  const opt = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv[0] !== 'fixture') throw Error('usage: fixture <journal.jsonl> <result.json> <fixture.json> --recorded-on <date> --ledger-row <n> --approval <n> --requests <n>');
  const [journalFile, resultFile, output] = argv.slice(1, 4), journalBytes = readFileSync(journalFile), resultBytes = readFileSync(resultFile);
  const meta = { recordedOn: opt('--recorded-on'), ledgerRow: Number(opt('--ledger-row')), approval: Number(opt('--approval')), requests: Number(opt('--requests')), journalSha256: sha256(journalBytes), resultSha256: sha256(resultBytes) };
  const doc = buildFixture(parseJsonl(journalBytes.toString('utf8')), JSON.parse(resultBytes), meta);
  writeFileSync(output, `${JSON.stringify(doc, null, 1)}\n`, { flag: 'wx' });
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); } catch (e) { console.error(`rtdb-sdk-small-fixture: ${e.message}`); process.exitCode = 2; }
}
