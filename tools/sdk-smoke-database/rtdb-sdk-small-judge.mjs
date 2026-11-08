// The comparison of the RTDB SDK small observer (sdk-observer/): 4 profiles (round 1 and 2, WebSocket and long polling)
// x 8 SDK cases, a local reduced journal against the recorded production one (fixtures/production-sdk-small.json,
// run RTDB-SMALL-20261102-01). Pure functions over the documents rtdb-sdk-small-fixture.mjs writes.
//
// Rules (recorded in that run; anything else fails closed):
// - key_range, value_equal, priority_range, update, multipath: identical values, member order included.
// - push: the two ids are SDK generated from the client clock, so only their format is compared (20 characters of the
//   push alphabet, the second greater than the first); `a` and `b` and the member order are identical.
// - server_timestamp: an integer inside the run's own inclusive before..after window, on each side (production also
//   recorded it inside its window); the member order {value, before, after} is identical.
// - increment: numeric 12, absent 5, string 5 identical; the carried-over `at` is the same profile's server_timestamp
//   value (so it follows the same window rule); member order identical.
// - per-role connection events identical; timings and the interleaving of the writer's and observer's events are not
//   compared (they are not in the reduced journal).
// A mask hides a value, never a format: masked fields keep their type, length and position.
import { CASE_ORDER } from './sdk-observer/sequence.mjs';

export const CASES = CASE_ORDER;
export const PROFILE_NAMES = ['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp'];
export const SETUP = [['writer', 'startup'], ['observer', 'startup'], ['writer', 'seed']];
export const KIND = 'rtdb-sdk-small-journal-v1';
const ROLES = ['writer', 'observer'];
const PUSH_ID = /^[-0-9A-Z_a-z]{20}$/;
const IDENTICAL = new Set(['key_range', 'value_equal', 'priority_range', 'update', 'multipath']);

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const keysAre = (v, keys) => isObject(v) && same(Object.keys(v), keys);
const verdict = (v, reason) => ({ verdict: v, reason });
/** A finished case row: exactly role, id, ok true and a value. */
const okRow = (row) => isObject(row) && keysAre(row, ['role', 'id', 'ok', 'value']) && row.ok === true;

/** The push format: exactly {keys: [id, id], a, b}, both ids push-shaped and ascending. */
function pushShape(v) {
  return keysAre(v, ['keys', 'a', 'b']) && Array.isArray(v.keys) && v.keys.length === 2 && v.keys.every((k) => typeof k === 'string' && PUSH_ID.test(k)) && v.keys[0] < v.keys[1];
}
/** A server timestamp inside its own window: {value, before, after}, integers, before <= value <= after. */
function inWindow(v) {
  return keysAre(v, ['value', 'before', 'after']) && [v.value, v.before, v.after].every(Number.isSafeInteger) && v.before <= v.value && v.value <= v.after;
}
/** `at` is the profile's server timestamp; the other members are compared as recorded. */
function incrementShape(v, st) {
  return isObject(v) && okRow(st) && inWindow(st.value) && Number.isSafeInteger(v.at) && v.at === st.value.value;
}

/**
 * One case. `st` holds the server_timestamp rows of the profile ({production, local}), which increment needs.
 * NEEDS_REVIEW: a row is missing, failed, or the production record is not in a recorded shape; MISMATCH: the local
 * value differs from the recorded one by these rules.
 */
export function judgeCase(id, production, local, st = {}) {
  if (!okRow(production)) return verdict('NEEDS_REVIEW', 'production row is not a finished case');
  if (!okRow(local)) return verdict('NEEDS_REVIEW', 'local row is missing or did not finish');
  const p = production.value, l = local.value;
  if (IDENTICAL.has(id)) return same(p, l) ? verdict('MATCH', 'identical values') : verdict('MISMATCH', 'values differ');
  if (id === 'push') {
    if (!pushShape(p)) return verdict('NEEDS_REVIEW', 'production push is not in the recorded shape');
    if (!pushShape(l)) return verdict('MISMATCH', 'local push ids are not two ascending 20-character push ids');
    return same({ ...p, keys: null }, { ...l, keys: null }) ? verdict('MATCH', 'same shape; push ids differ only by time') : verdict('MISMATCH', 'push values differ');
  }
  if (id === 'server_timestamp') {
    if (!inWindow(p)) return verdict('NEEDS_REVIEW', 'production timestamp is not inside its window');
    return inWindow(l) ? verdict('MATCH', 'integer inside the local before..after window') : verdict('MISMATCH', 'local timestamp is not an integer inside its window');
  }
  if (id === 'increment') {
    if (!incrementShape(p, st.production)) return verdict('NEEDS_REVIEW', 'production increment is not in the recorded shape');
    if (!incrementShape(l, st.local)) return verdict('MISMATCH', 'local at is not the local server timestamp');
    return same({ ...p, at: null }, { ...l, at: null }) ? verdict('MATCH', 'numeric, absent and string identical; at is the server timestamp') : verdict('MISMATCH', 'increment values differ');
  }
  return verdict('NEEDS_REVIEW', `unknown case ${id}`);
}

const rowAt = (rows, i, [role, id]) => (Array.isArray(rows) && rows[i]?.role === role && rows[i]?.id === id ? rows[i] : undefined);
function eventsOf(e) {
  return keysAre(e, ROLES) && ROLES.every((r) => Array.isArray(e[r]) && e[r].every((x) => x === 'connected' || x === 'disconnected')) ? e : null;
}

/** One profile: setup rows, the eight cases at their fixed positions, the per-role connection events. */
export function judgeProfile(production, local) {
  const rows = [], n = SETUP.length + CASES.length;
  const setupOk = (p) => Array.isArray(p?.rows) && SETUP.every((s, i) => { const r = rowAt(p.rows, i, s); return okRow(r) && r.value === null; });
  const setup = setupOk(production) && setupOk(local) ? verdict('MATCH', 'startup empty and seed written on both sides') : verdict('NEEDS_REVIEW', 'setup rows differ from startup, startup, seed');
  const extra = !Array.isArray(local?.rows) || local.rows.length !== n || !Array.isArray(production?.rows) || production.rows.length !== n;
  const st = { production: rowAt(production?.rows, n - 2, CASES[6]), local: rowAt(local?.rows, n - 2, CASES[6]) };
  for (const [i, c] of CASES.entries()) {
    const judged = judgeCase(c[1], rowAt(production?.rows, SETUP.length + i, c), rowAt(local?.rows, SETUP.length + i, c), st);
    rows.push({ profile: production?.name, case: c[1], ...judged });
  }
  const pe = eventsOf(production?.events), le = eventsOf(local?.events);
  const events = pe && le && same(pe, le) ? verdict('MATCH', 'per-role event order identical') : verdict(pe ? 'MISMATCH' : 'NEEDS_REVIEW', 'per-role connection events differ');
  return { name: production?.name, setup, events, rows, extra: extra ? verdict('NEEDS_REVIEW', 'a case row is missing or extra') : null };
}

const completeRun = (d) => isObject(d?.result) && d.result.status === 'complete' && d.result.observed === 32 && d.result.exit === 0 && same(d.result.cleanup, { prefix: 'verified', rules: 'verified' });

/** The whole comparison: a match only when every one of the 32 rows, every setup and every event list matches. */
export function summarize(production, local) {
  const counts = { MATCH: 0, MISMATCH: 0, NEEDS_REVIEW: 0 };
  try {
    const problems = [];
    for (const [side, d] of [['production', production], ['local', local]]) {
      if (!isObject(d) || d.kind !== KIND) problems.push(`${side}: not a reduced SDK small journal`);
      else {
        if (!Array.isArray(d.profiles) || !same(d.profiles.map((p) => p?.name), PROFILE_NAMES)) problems.push(`${side}: profiles are not ${PROFILE_NAMES.join(', ')}`);
        if (!completeRun(d)) problems.push(`${side}: the run is not complete with a verified cleanup`);
        if (!Array.isArray(d.faults) || d.faults.length) problems.push(`${side}: the journal records faults`);
      }
    }
    if (problems.length) return { match: false, counts, problems, rows: [], profiles: [] };
    const profiles = production.profiles.map((p, i) => judgeProfile(p, local.profiles[i]));
    const rows = profiles.flatMap((p) => p.rows);
    for (const r of rows) counts[r.verdict]++;
    for (const p of profiles) for (const part of ['setup', 'events', 'extra']) if (p[part] && p[part].verdict !== 'MATCH') problems.push(`${p.name}: ${part}: ${p[part].reason}`);
    return { match: rows.length === 32 && counts.MATCH === 32 && problems.length === 0, counts, problems, rows, profiles: profiles.map(({ name, setup, events }) => ({ name, setup: setup.verdict, events: events.verdict })) };
  } catch (error) {
    return { match: false, counts, problems: [`unreadable: ${error?.message}`], rows: [], profiles: [] };
  }
}
