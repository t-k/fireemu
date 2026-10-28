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
export const SCENARIOS = ['cv08', 'cv10', 'sdk-next'];
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
    // A step name is part of every row key, so a different step at the same position is unsettled too.
    out.set(g.id, h ? (sameOrdered(g.keys, h.keys) ? 'ordered' : sameSorted(g.keys, h.keys) ? 'sorted' : 'unsettled') : 'unsettled');
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
  const verdict = differences.length ? 'differences' : unsettled.length || localRaced.length ? 'needs-review' : 'match';
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
    if (scenario === 'sdk-next' && prod.size) { missing = true; continue; }
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

/** Validate fixed SDK-next evidence without treating one run as parity or retry proof. */
export function validateSdkNext(journal) {
  const errors = [];
  const one = (type, label) => {
    const rows = journal.filter((r) => r.type === type && r.label === label);
    if (rows.length !== 1) errors.push(`missing or duplicate ${type}:${label}`);
    return rows[0];
  };
  const parse = (r) => { try { return JSON.parse(r?.shape); } catch { errors.push('invalid typed shape'); return undefined; } };
  const pushes = ['a', 'b'].map((label) => one('push', label));
  if (pushes.some((r) => typeof r?.key !== 'string' || !r.key) || pushes[0]?.key === pushes[1]?.key) errors.push('push keys');
  for (const [i, r] of pushes.entries()) if (JSON.stringify(parse(r)) !== JSON.stringify({ label: ['a', 'b'][i] })) errors.push('push readback');
  for (const [label, expected] of [['update-preserves-sibling', { keep: 1, edit: 2 }], ['set-replaces-node', { edit: 3 }], ['atomic-multipath-final', { x: 1, y: 2 }], ['server-values', { numeric: 12, absent: 5, string: 5 }]]) {
    const value = parse(one('get', label));
    if (!value || Object.entries(expected).some(([k, v]) => value[k] !== v) || (label !== 'server-values' && Object.keys(value).length !== Object.keys(expected).length)) errors.push(label);
  }
  const interval = parse(one('interval', 'server-timestamp'));
  if (!interval || !Number.isInteger(interval.value) || !Number.isFinite(interval.before) || !Number.isFinite(interval.after) || interval.before > interval.after || interval.value < interval.before - 600000 || interval.value > interval.after + 600000) errors.push('timestamp interval');
  const values = parse(one('get', 'server-values'));
  if (values?.at !== interval?.value || Object.keys(values ?? {}).length !== 4) errors.push('timestamp readback binding');
  const abort = parse(one('transaction', 'abort')), apply = parse(one('transaction', 'applyLocally-false'));
  const callbacks = (v) => Array.isArray(v) && v.length > 0 && v.every((x) => x === null || (typeof x === 'number' && Number.isFinite(x)));
  if (!abort || abort.committed !== false || abort.value !== 3 || !callbacks(abort.callbacks)) errors.push('transaction abort');
  if (!apply || apply.committed !== true || apply.value !== 5 || !callbacks(apply.callbacks)) errors.push('transaction apply');
  if (!journal.some((r) => r.type === 'value' && r.label === 'txn-abort' && r.actor === 'w' && r.shape === '3')) errors.push('writer abort cache');
  if (!journal.some((r) => r.type === 'value' && r.label === 'txn-apply' && r.actor === 'w')) errors.push('writer transaction listener');
  for (const type of ['child_added', 'child_changed', 'child_moved']) if (!journal.some((r) => r.type === type && typeof r.key === 'string' && (r.prev === null || typeof r.prev === 'string'))) errors.push(type);
  const initial = journal.filter((r) => r.step === 'attach' && r.type === 'child_added' && r.label === 'items');
  if (!initial.some((r) => r.key === 'b' && r.prev === 'a') || !initial.some((r) => r.key === 'c' && r.prev === 'b')) errors.push('query tie ordering');
  const ops = journal.filter((r) => r.type === 'operation');
  if (ops.length !== 21 || ops.some((r, i) => r.code !== String(i + 1)) || ops[0]?.label !== 'startup-w' || ops[1]?.label !== 'startup-o' || ops[2]?.label !== 'seed') errors.push('operation count/order');
  const seed = journal.indexOf(ops[2]);
  for (const actor of ['w', 'o']) {
    const reads = journal.filter((r) => r.type === 'startup' && r.label === 'root-read' && r.actor === actor && r.shape === 'null');
    if (reads.length !== 1 || journal.indexOf(reads[0]) >= seed) errors.push(`startup ${actor}`);
  }
  if (journal.some((r) => ['timeout', 'error', 'rejected'].includes(r.type))) errors.push('unknown outcome');
  if (!journal.some((r) => r.type === 'gap' && r.label === 'transaction-retry' && r.code === 'unobserved')) errors.push('retry gap');
  return { valid: errors.length === 0, errors, retry: 'unobserved', verdict: 'needs-review' };
}
