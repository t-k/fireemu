// The reduced journal of the rest suite (G7) of the RTDB SDK observer (sdk-observer/ --suite rest): per profile (r1-rest,
// r2-rest, in order) the case rows the suite wrote, in journal order, with every recorded field (request, status, the
// allowlisted response headers, the masked body and its byte length). Dropped: row timestamps and the admin request and
// answer rows (the case rows carry what is judged). A row the reducer cannot place refuses the whole journal. A local run
// writes this reduction as journal.json; a production fixture is the reduction of a production run plus its provenance:
//
//   node rtdb-sdk-rest-fixture.mjs fixture <journal.jsonl> <result.json> <fixture.json> --recorded-on <date> --booking-row <n> --close-row <n> --approvals <n,n> --requests <n> --packet-sha256 <hex> --source-head <sha>
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { assertPublishable, parseJsonl } from './rtdb-sdk-small-fixture.mjs';
import { REST_CASES, REST_PROFILES } from './sdk-observer/rest-suite.mjs';

export const KIND = 'rtdb-sdk-rest-journal-v1';
const FAULTS = ['abort', 'error', 'profile-error', 'timeout'];
const IGNORED = ['admin-req', 'admin-res', 'admin-unknown', 'result', 'cleanup'];
/** The fields a case row of the suite may carry (rest-suite.mjs runRestProfile); `kind`, `suite`, `profile` and `t` are dropped. */
export const ROW_FIELDS = ['id', 'ok', 'outcome', 'method', 'path', 'query', 'requestHeaders', 'requestBody', 'status', 'responseHeaders', 'body', 'bodyBytes', 'utf8', 'clipped', 'pushIdShapeOk', 'unknown', 'error'];

/** The reduced journal of one observer run of the rest suite; `result` is its result.json. */
export function reduceRestJournal(rows, result) {
  if (!Array.isArray(rows)) throw Error('journal rows must be an array');
  if (!result || typeof result !== 'object') throw Error('result.json is missing');
  if (result.suite !== 'rest') throw Error(`result.json suite ${result.suite} is not the rest suite`);
  if (typeof result.prefix !== 'string') throw Error('result.json has no prefix');
  const profiles = REST_PROFILES.map(name => ({ name, rows: [] })), faults = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw Error('journal row is not an object');
    if (row.kind === 'case') {
      const p = profiles.find(x => x.name === row.profile);
      if (!p) throw Error(`unknown profile ${row.profile} in a case row`);
      if (row.suite !== 'rest') throw Error(`case row of suite ${row.suite} in the rest profile ${p.name}`);
      if (!REST_CASES.includes(row.id) || typeof row.ok !== 'boolean') throw Error(`unknown case row ${row.id}`);
      const extra = Object.keys(row).filter(k => !['t', 'kind', 'suite', 'profile', ...ROW_FIELDS].includes(k));
      if (extra.length) throw Error(`case row ${row.id} has unrecorded fields ${extra.join()}`);
      p.rows.push(Object.fromEntries(ROW_FIELDS.filter(k => Object.hasOwn(row, k)).map(k => [k, row[k]])));
    } else if (FAULTS.includes(row.kind)) faults.push({ kind: row.kind, profile: profiles.some(x => x.name === row.profile) ? row.profile : null });
    else if (!IGNORED.includes(row.kind)) throw Error(`unknown journal row kind ${row.kind}`);
  }
  const { status, observed, exit, cleanup } = result;
  return { kind: KIND, suite: 'rest', result: { status, observed, exit, cleanup, unverified: Array.isArray(result.unverified) ? result.unverified.map(String) : ['result.json has no unverified list'], prefixLength: result.prefix.length }, faults, profiles };
}

/** The case code of the suite that runs in production; a fixture pins it (the whole observer is pinned by scriptSha256). */
export const CASE_SOURCES = ['rest-suite.mjs'];
const META_FIELDS = ['recordedOn', 'bookingRow', 'closeRow', 'approvals', 'requests', 'packetSha256', 'sourceHead', 'journalSha256', 'resultSha256'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const present = v => v !== undefined && v !== null && v !== '' && !Number.isNaN(v) && !(Array.isArray(v) && v.length === 0);

/** The production fixture: the reduction of a production journal and the provenance the closure quotes. */
export function buildRestFixture(rows, result, meta) {
  if (result?.target !== 'production') throw Error('a fixture is made from a production run only');
  for (const field of META_FIELDS) if (!present(meta?.[field])) throw Error(`missing ${field}`);
  const { direct, reserve, adc, overflow = 0 } = result.counts ?? {};
  if (direct + reserve !== meta.requests) throw Error(`direct ${direct} + reserve ${reserve} is not the ledger's ${meta.requests} requests`);
  if (adc !== 1) throw Error('the run must have taken exactly one ADC token');
  if (overflow !== 0) throw Error(`the run counted ${overflow} requests over its cap (overflow)`);
  if (!Array.isArray(result.unverified) || result.unverified.length) throw Error('the run left unverified (unknown) writes');
  const reduced = reduceRestJournal(rows, result);
  const caseSources = Object.fromEntries(CASE_SOURCES.map(name => [name, sha256(readFileSync(new URL(`./sdk-observer/${name}`, import.meta.url)))]));
  const provenance = {
    runId: result.runId, target: result.target, project: 'fireemu-oracle-query', instance: 'fireemu-q-rtdb2', suite: 'rest', recordedOn: meta.recordedOn, startedAt: result.startedAt, endedAt: result.endedAt,
    scriptSha256: result.scriptSha256, sourceHead: meta.sourceHead, packetSha256: meta.packetSha256, caseSources,
    counts: { requests: meta.requests, direct, reserve, adc, overflow }, caps: result.caps, cleanup: result.cleanup, observations: result.observed,
    sandboxLedger: { booking: meta.bookingRow, close: meta.closeRow }, approvals: meta.approvals, journalSha256: meta.journalSha256, resultSha256: meta.resultSha256,
  };
  const doc = { ...reduced, provenance };
  assertPublishable(JSON.stringify(doc));
  return doc;
}

/** The recorded side of a comparison: a production fixture without its provenance, or a plain reduced journal as it is. */
export function recordedJournal(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw Error('not a reduced SDK rest journal');
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
    requests: Number(opt('--requests')), packetSha256: opt('--packet-sha256'), sourceHead: opt('--source-head'), journalSha256: sha256(journalBytes), resultSha256: sha256(resultBytes),
  };
  const doc = buildRestFixture(parseJsonl(journalBytes.toString('utf8')), JSON.parse(resultBytes), meta);
  writeFileSync(output, `${JSON.stringify(doc, null, 1)}\n`, { flag: 'wx' });
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.exitCode = main(process.argv.slice(2)); } catch (e) { console.error(`rtdb-sdk-rest-fixture: ${e.message}`); process.exitCode = 2; }
}
