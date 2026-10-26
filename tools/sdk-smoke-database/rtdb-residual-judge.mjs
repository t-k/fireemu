// The judge of the RTDB residual recorder (CV08 reconnect and ordering, CV10 onDisconnect cancel and
// re-register). It compares the journals of a local fireemu run with a production run, profile by
// profile (round 1 and 2 x WebSocket and long polling, per scenario). It never reads timings.
//
// A step is the unit of comparison. Production's own two rounds of the same transport decide how
// strictly a step is judged: equal in both rounds -> the local events must be in the recorded order;
// the same events in another order -> a race, compared sorted; different events -> unsettled, which
// is needs-review, never a match and never a guessed difference. A recorded `timeout` row (a wait
// that hit its bound) or `error` row makes that production profile needs-review for the same reason.
import { LP_TOLERANCE_SECONDS, WS_FIRE_MAX_SECONDS } from './cv07-ondisconnect.mjs';

export const KEPT = ['step', 'type', 'actor', 'label', 'key', 'prev', 'shape', 'code'];
export const UNKNOWN_TYPES = new Set(['timeout', 'error']);
export const SCENARIOS = ['cv08', 'cv10'];
export const ROUNDS_BY_TRANSPORT = { ws: ['r1-ws', 'r2-ws'], lp: ['r1-lp', 'r2-lp'] };

/** The comparison key of one row: the kept fields only, so timings and any extra field are ignored. */
export const rowKey = (row) => JSON.stringify(KEPT.map((k) => row[k] ?? null));

/**
 * Consecutive rows of one step form a group; a step that comes back later is a new group (`step#n`).
 * Inside a group the rows are kept in order per actor (writer `w`, observer `o`, host); the order
 * between two actors is a latency race of two connections and is not an observation.
 */
export function stepGroups(journal = []) {
  const groups = [], seen = new Map();
  for (const row of journal) {
    const last = groups.at(-1);
    if (last && last.step === row.step) { last.rows.push(row); continue; }
    const n = seen.get(row.step) ?? 0;
    seen.set(row.step, n + 1);
    groups.push({ id: n === 0 ? row.step : `${row.step}#${n}`, step: row.step, rows: [row] });
  }
  return groups.map((g) => ({ id: g.id, step: g.step, keys: g.rows.map((r, i) => [r.actor ?? '', i, rowKey(r)]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] - b[1])).map((x) => x[2]) }));
}

const sameOrdered = (a, b) => a.length === b.length && a.every((k, i) => k === b[i]);
const sameSorted = (a, b) => sameOrdered([...a].sort(), [...b].sort());

/** How strictly each step of a profile is judged, from production's two rounds of one transport. */
export function stepStrictness(round1, round2) {
  const a = stepGroups(round1), b = stepGroups(round2), out = new Map();
  for (const [i, g] of a.entries()) {
    const h = b[i];
    out.set(g.id, h && h.id === g.id ? (sameOrdered(g.keys, h.keys) ? 'ordered' : sameSorted(g.keys, h.keys) ? 'sorted' : 'unsettled') : 'unsettled');
  }
  if (b.length > a.length) for (const h of b.slice(a.length)) out.set(h.id, 'unsettled');
  return out;
}

const byName = (profiles, scenario) => new Map((profiles ?? []).filter((p) => p.scenario === scenario).map((p) => [p.name, p]));
const unknownRows = (journal = []) => journal.filter((r) => UNKNOWN_TYPES.has(r.type)).map((r) => ({ step: r.step, type: r.type, code: r.code ?? null }));

/**
 * Local against production for one profile, with the strictness production's rounds allow. `localHow`
 * is the strictness of local's own two rounds: where production was ordered and local raced (or
 * varied), the step is compared sorted at most and the profile is needs-review, never a match.
 */
export function judgeProfile(production, local, strictness, localHow = new Map()) {
  const p = stepGroups(production.journal), l = stepGroups(local?.journal);
  const differences = [], unsettled = [], localRaced = [];
  if (!local) return { name: production.name, verdict: 'differences', differences: [{ step: null, index: 0, left: 'profile', right: null }], unsettled, localRaced };
  const productionUnknown = unknownRows(production.journal);
  // From the first step where production itself recorded a timeout or error, nothing is judged.
  const cut = p.findIndex((g) => production.journal.some((r) => r.step === g.step && UNKNOWN_TYPES.has(r.type)));
  const judged = new Set(cut < 0 ? p.map((g) => g.id) : p.slice(0, cut).map((g) => g.id));
  const ids = new Set([...p.map((g) => g.id), ...l.map((g) => g.id)]);
  if (!sameOrdered(p.map((g) => g.id), l.map((g) => g.id))) {
    differences.push({ step: null, index: 0, left: p.map((g) => g.id).join('>'), right: l.map((g) => g.id).join('>') });
  }
  for (const id of ids) {
    const pg = p.find((g) => g.id === id), lg = l.find((g) => g.id === id);
    if (!pg || !lg) continue;
    let how = judged.has(id) ? strictness.get(id) ?? 'unsettled' : 'unsettled';
    if (how === 'unsettled') { unsettled.push(id); continue; }
    if (how === 'ordered' && localHow.get(id) && localHow.get(id) !== 'ordered') { how = 'sorted'; localRaced.push(id); }
    const same = how === 'ordered' ? sameOrdered(pg.keys, lg.keys) : sameSorted(pg.keys, lg.keys);
    if (!same) {
      const x = how === 'sorted' ? [...pg.keys].sort() : pg.keys, y = how === 'sorted' ? [...lg.keys].sort() : lg.keys;
      let n = x.findIndex((k, i) => k !== y[i]);
      if (n < 0) n = Math.min(x.length, y.length);
      differences.push({ step: id, index: n, left: x[n] ?? null, right: y[n] ?? null });
    }
  }
  const localUnknown = unknownRows(local.journal);
  if (localUnknown.length && !productionUnknown.length) differences.push({ step: null, index: 0, left: null, right: `local recorded ${localUnknown.map((u) => u.type).join()}` });
  const verdict = differences.length ? 'differences' : productionUnknown.length || unsettled.length || localRaced.length ? 'needs-review' : 'match';
  return { name: production.name, verdict, differences, unsettled, localRaced, productionUnknown };
}

/** The seconds from the writer going offline to the last fire marker, per cv10 profile (0.1 s). */
export function fireSeconds(journal = []) {
  const row = journal.find((r) => r.type === 'timing' && r.step === 'fire');
  return typeof row?.seconds === 'number' ? row.seconds : null;
}

/** WebSocket fires within WS_FIRE_MAX_SECONDS; long polling within the tolerance around production's range. */
export function judgeFireTiming(production, local) {
  const secs = (profiles) => Object.fromEntries([...byName(profiles, 'cv10')].map(([name, p]) => [name, fireSeconds(p.journal)]));
  const prod = secs(production), here = secs(local);
  const lp = Object.entries(prod).filter(([n, s]) => n.endsWith('-lp') && typeof s === 'number').map(([, s]) => s);
  const [low, high] = lp.length ? [Math.min(...lp) - LP_TOLERANCE_SECONDS, Math.max(...lp) + LP_TOLERANCE_SECONDS] : [NaN, NaN];
  const outside = [];
  for (const name of Object.keys(prod)) {
    const s = here[name];
    const ok = typeof s === 'number' && (name.endsWith('-ws') ? s >= 0 && s <= WS_FIRE_MAX_SECONDS : s >= low && s <= high);
    if (!ok) outside.push({ name, seconds: s ?? null });
  }
  return { within: outside.length === 0, outside, production: prod, local: here };
}

/** Transports of one scenario and round: informational, ws against lp in production. */
export function transportNotes(profiles, scenario) {
  const m = byName(profiles, scenario), notes = [];
  for (const round of ['r1', 'r2']) {
    const ws = m.get(`${round}-ws`), lp = m.get(`${round}-lp`);
    if (ws && lp) {
      const a = stepGroups(ws.journal).map((g) => g.keys.join('|')), b = stepGroups(lp.journal).map((g) => g.keys.join('|'));
      notes.push({ scenario, round, wsEqualsLp: sameOrdered(a, b) });
    }
  }
  return notes;
}

/**
 * The full verdict. `production` and `local` are arrays of {scenario, name, journal}. A production
 * scenario with fewer than the four profiles is needs-review: strictness cannot be derived.
 */
export function judgeRuns(production, local) {
  const profiles = [];
  let missing = false;
  for (const scenario of SCENARIOS) {
    const prod = byName(production, scenario), here = byName(local, scenario);
    if (!prod.size) continue;
    for (const transport of ['ws', 'lp']) {
      const [n1, n2] = ROUNDS_BY_TRANSPORT[transport], p1 = prod.get(n1), p2 = prod.get(n2);
      for (const name of [n1, n2]) {
        const p = prod.get(name);
        if (!p) { missing = true; continue; }
        const strictness = p1 && p2 ? stepStrictness(p1.journal, p2.journal) : new Map();
        const l1 = here.get(n1), l2 = here.get(n2);
        profiles.push({ scenario, ...judgeProfile(p, here.get(name), strictness, l1 && l2 ? stepStrictness(l1.journal, l2.journal) : new Map()) });
      }
    }
  }
  const verdict = profiles.some((p) => p.verdict === 'differences') ? 'differences' : missing || profiles.some((p) => p.verdict === 'needs-review') ? 'needs-review' : profiles.length ? 'match' : 'needs-review';
  return { verdict, profiles, timing: judgeFireTiming(production, local), transports: SCENARIOS.flatMap((s) => transportNotes(production, s)) };
}

/** The journal as kept in the repository: kept fields and timing seconds only, no milliseconds. */
export function sanitizeProfiles(profiles) {
  return profiles.map((p) => ({
    scenario: p.scenario,
    name: p.name,
    journal: p.journal.map((row) => Object.fromEntries([...KEPT, 'seconds'].filter((k) => k in row && row[k] !== undefined).map((k) => [k, row[k]]))),
  }));
}
