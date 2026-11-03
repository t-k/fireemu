// The reduced journals of the events (G6) and admin (G13) suites of the RTDB SDK observer (sdk-observer/ --suite
// events|admin|events+admin): the SDK-level facts the comparison reads, out of the observer's journal.jsonl.
//
// Kept: per profile (in the suite's fixed order) the case rows in journal order: id, ok, the recorded steps (ordered
// observer and writer callbacks, acknowledgements, results, the ready/quiet bounds) or the error. Dropped: row
// timestamps, admin requests and answers, raw WebSocket, long-polling and connect capture. A row the reducer cannot
// place refuses the whole journal. There is no production fixture yet; a local run writes this reduction as journal.json.
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
const IGNORED = ['admin-req', 'admin-res', 'admin-unknown', 'raw-ws', 'raw-lp-request', 'raw-lp-response', 'raw-page-ws', 'raw-admin-connect', 'result', 'cleanup'];

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
      p.rows.push(kept);
    } else if (FAULTS.includes(row.kind)) faults.push({ kind: row.kind, profile: named(row.profile) ? row.profile : null });
    else if (!IGNORED.includes(row.kind)) throw Error(`unknown journal row kind ${row.kind}`);
  }
  const { status, observed, exit, cleanup } = result;
  return { kind: KIND, suite: result.suite, result: { status, observed, exit, cleanup }, faults, profiles };
}
