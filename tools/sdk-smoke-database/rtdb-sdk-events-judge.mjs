// The comparison of the events (G6) and admin (G13) suites of the RTDB SDK observer: a local reduced journal against
// a recorded one (rtdb-sdk-events-fixture.mjs writes both). There is no production fixture yet; until there is, two
// local runs (strict and emulator profile) are judged against each other. Pure functions.
//
// Verdict per (profile, case, step). Only recorded facts are compared, and exactly (member order included): the ordered
// observer callbacks {listener label, event, key, prevName, value}, the writer's ordered callbacks and transaction
// resolution, the acknowledgement, the get and transaction results. No timings are recorded. No masks: these suites
// record no time-derived value (the admin push records only the key's shape).
// Fail closed: NEEDS_REVIEW when the recorded (first) side is not a finished step in a recorded shape, when a bound was
// hit on either side (`ready: false`, `quiet: false`: the step's events are not known to be complete), and for every step
// of a case that is missing, extra, out of place or failed. MISMATCH when both sides are well formed and differ.
import { eventCases } from './sdk-observer/events-actor.mjs';
import { KIND, SETUP, profilesOf } from './rtdb-sdk-events-fixture.mjs';
import { ADMIN_LABELS, ADMIN_STEPS } from './rtdb-sdk-admin-judge.mjs';

const stubD = new Proxy({}, { get: () => () => null });   // the case table only: the query constructors are never called with a database
const eventSpecs = eventCases(stubD);
/** suite -> case id -> [{kind, label}] */
export const STEPS = { events: Object.fromEntries(eventSpecs.map(c => [c.id, c.steps.map(({ kind, label }) => ({ kind, label }))])), admin: ADMIN_STEPS };
const LABELS = { events: Object.fromEntries(eventSpecs.map(c => [c.id, { observer: c.listeners.map(l => l.label), writer: c.steps.some(s => s.kind === 'transaction') ? ['W', 'txn'] : [] }])), admin: ADMIN_LABELS };
/** Number of judged steps of a suite run. */
export const stepCount = suite => profilesOf(suite).reduce((n, p) => n + Object.values(STEPS[p.suite]).flat().length, 0);

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const keysAre = (v, keys) => isObject(v) && same(Object.keys(v), keys);
const verdict = (v, reason) => ({ verdict: v, reason });
const STEP_KEYS = { attach: ['step', 'observer', 'writer', 'ready', 'quiet'], write: ['step', 'observer', 'writer', 'ack', 'quiet'], get: ['step', 'observer', 'writer', 'result', 'quiet'], call: ['step', 'observer', 'writer', 'result', 'quiet'], transaction: ['step', 'observer', 'writer', 'ready', 'result', 'quiet'] };
const EVENT_KEYS = { value: ['l', 'e', 'k', 'v'], child_added: ['l', 'e', 'k', 'p', 'v'], child_changed: ['l', 'e', 'k', 'p', 'v'], child_moved: ['l', 'e', 'k', 'p', 'v'], child_removed: ['l', 'e', 'k', 'v'], cancel: ['l', 'e', 'code'] };
const keyOk = k => typeof k === 'string' || k === null;

function eventOk(ev, labels, role) {
  if (!isObject(ev) || !labels.includes(ev.l)) return false;
  if (role === 'writer' && ev.l === 'txn') return keysAre(ev, ['l', 'e']) && (ev.e === 'resolved' || ev.e === 'rejected');
  const keys = EVENT_KEYS[ev.e];
  if (!keys || !keysAre(ev, keys)) return false;
  if (ev.e === 'cancel') return typeof ev.code === 'string';
  return keyOk(ev.k) && (!keys.includes('p') || keyOk(ev.p)) && ev.v !== undefined;
}
const shapeOk = v => (keysAre(v, ['leaf']) || keysAre(v, ['children']) || keysAre(v, ['children', 'priority'])) && (!('children' in v) || (Array.isArray(v.children) && v.children.every(c => Array.isArray(c) && c.length === 2 && typeof c[0] === 'string')));
const errorOk = v => keysAre(v, ['error']) && typeof v.error === 'string';
function resultOk(kind, r) {
  if (kind === 'get') return errorOk(r) || (keysAre(r, ['exists', 'v']) && typeof r.exists === 'boolean' && shapeOk(r.v));
  if (kind === 'call') return errorOk(r) || isObject(r);
  if (kind === 'transaction') return isObject(r) && Array.isArray(r.inputs) && ((keysAre(r, ['inputs', 'committed', 'snapshot']) && typeof r.committed === 'boolean' && shapeOk(r.snapshot)) || (keysAre(r, ['inputs', 'error']) && typeof r.error === 'string'));
  return false;
}
/** A recorded step in the shape its kind writes, with labels of its case only; `settled` says whether no bound was hit. */
function stepShape(s, spec, labels) {
  if (!keysAre(s, STEP_KEYS[spec.kind] ?? []) || s.step !== spec.label) return { ok: false };
  if (!Array.isArray(s.observer) || !s.observer.every(ev => eventOk(ev, labels.observer, 'observer'))) return { ok: false };
  if (!Array.isArray(s.writer) || !s.writer.every(ev => eventOk(ev, spec.kind === 'transaction' ? labels.writer : [], 'writer'))) return { ok: false };
  if (typeof s.quiet !== 'boolean' || ('ready' in s && typeof s.ready !== 'boolean')) return { ok: false };
  if ('ack' in s && s.ack !== 'ok' && !errorOk(s.ack)) return { ok: false };
  if ('result' in s && !resultOk(spec.kind, s.result)) return { ok: false };
  return { ok: true, settled: s.quiet === true && s.ready !== false };
}

/** One step: `production` is the recorded side. */
export function judgeStep(production, local, spec, labels) {
  const p = stepShape(production, spec, labels);
  if (!p.ok) return verdict('NEEDS_REVIEW', 'recorded step is not in a recorded shape');
  if (!p.settled) return verdict('NEEDS_REVIEW', 'recorded step hit a bound (ready or quiet false)');
  const l = stepShape(local, spec, labels);
  if (!l.ok) return verdict('NEEDS_REVIEW', 'local step is missing or not in a recorded shape');
  if (!l.settled) return verdict('NEEDS_REVIEW', 'local step hit a bound (ready or quiet false)');
  return same(production, local) ? verdict('MATCH', 'identical events, order and values') : verdict('MISMATCH', 'events, order or values differ');
}

const finished = row => isObject(row) && keysAre(row, ['id', 'ok', 'steps']) && row.ok === true && Array.isArray(row.steps);
const setupRow = (row, id) => keysAre(row, ['id', 'ok']) && row.id === id && row.ok === true;

/** One profile: its setup rows, then every case at its fixed position, step by step. */
export function judgeProfile(production, local) {
  const suite = production?.suite, cases = Object.keys(STEPS[suite] ?? {}), setup = SETUP[suite] ?? [], rows = [];
  const setupOk = d => Array.isArray(d?.rows) && setup.every((id, i) => setupRow(d.rows[i], id));
  const n = setup.length + cases.length, extra = !Array.isArray(production?.rows) || production.rows.length !== n || !Array.isArray(local?.rows) || local.rows.length !== n;
  for (const [i, id] of cases.entries()) {
    const pr = production?.rows?.[setup.length + i], lr = Array.isArray(local?.rows) ? local.rows[setup.length + i] : undefined, labels = LABELS[suite][id];
    const pc = finished(pr) && pr.id === id && pr.steps.length === STEPS[suite][id].length, lc = finished(lr) && lr.id === id && lr.steps.length === STEPS[suite][id].length;
    for (const [j, spec] of STEPS[suite][id].entries()) {
      const judged = !pc ? verdict('NEEDS_REVIEW', 'recorded case is missing, failed or has other steps') : !lc ? verdict('NEEDS_REVIEW', 'local case is missing, failed or has other steps') : judgeStep(pr.steps[j], lr.steps[j], spec, labels);
      rows.push({ profile: production?.name, case: id, step: spec.label, ...judged });
    }
  }
  return {
    name: production?.name, suite,
    setup: setupOk(production) && setupOk(local) ? verdict('MATCH', 'setup rows finished on both sides') : verdict('NEEDS_REVIEW', `setup rows differ from ${setup.join(', ')}`),
    extra: extra ? verdict('NEEDS_REVIEW', 'a case row is missing or extra') : null, rows,
  };
}

const expectedObserved = suite => profilesOf(suite).reduce((n, p) => n + Object.keys(STEPS[p.suite]).length, 0);
const completeRun = d => isObject(d?.result) && d.result.status === 'complete' && d.result.observed === expectedObserved(d.suite) && d.result.exit === 0 && same(d.result.cleanup, { prefix: 'verified', rules: 'verified' });

/** The whole comparison: a match only when every step of every case of every profile, and every setup, matches. */
export function summarize(production, local) {
  const counts = { MATCH: 0, MISMATCH: 0, NEEDS_REVIEW: 0 }, credentialOutcome = [];
  try {
    const problems = [];
    for (const [side, d] of [['production', production], ['local', local]]) {
      if (!keysAre(d, ['kind', 'suite', 'result', 'faults', 'profiles']) || d.kind !== KIND) { problems.push(`${side}: not a reduced SDK events journal`); continue; }
      let plan;
      try { plan = profilesOf(d.suite); } catch { problems.push(`${side}: unknown suite ${d.suite}`); continue; }
      if (!Array.isArray(d.profiles) || !same(d.profiles.map(p => (keysAre(p, ['name', 'suite', 'rows']) ? [p.name, p.suite] : null)), plan.map(p => [p.name, p.suite]))) problems.push(`${side}: profiles are not the ${d.suite} profiles`);
      const outcome = d.result?.credentialOutcome;   // optional: the admin profiles whose Admin SDK credential was refused (startup failed)
      const outcomeOk = outcome === undefined || (Array.isArray(outcome) && outcome.length > 0 && outcome.every(name => typeof name === 'string' && plan.some(x => x.name === name && x.suite === 'admin')));
      if (!outcomeOk || !isObject(d.result) || !keysAre({ ...d.result, credentialOutcome: undefined }, ['status', 'observed', 'exit', 'cleanup', 'credentialOutcome'])) problems.push(`${side}: result is not in the reduced shape`);
      else if (outcome) { credentialOutcome.push(...outcome); problems.push(`${side}: credential outcome: ${outcome.join(', ')}: the Admin SDK did not authenticate; not G13 evidence`); }
      if (!completeRun(d)) problems.push(`${side}: the run is not complete with a verified cleanup`);
      if (!Array.isArray(d.faults) || d.faults.length) problems.push(`${side}: the journal records faults`);
    }
    if (!problems.length && production.suite !== local.suite) problems.push(`suites differ: ${production.suite} and ${local.suite}`);
    if (problems.length) return { match: false, counts, problems, rows: [], profiles: [], ...(credentialOutcome.length ? { credentialOutcome: [...new Set(credentialOutcome)] } : {}) };
    const profiles = production.profiles.map((p, i) => judgeProfile(p, local.profiles[i]));
    const rows = profiles.flatMap(p => p.rows);
    for (const r of rows) counts[r.verdict]++;
    for (const p of profiles) for (const part of ['setup', 'extra']) if (p[part] && p[part].verdict !== 'MATCH') problems.push(`${p.name}: ${part}: ${p[part].reason}`);
    const n = stepCount(production.suite);
    return { match: rows.length === n && counts.MATCH === n && problems.length === 0, counts, problems, rows, profiles: profiles.map(({ name, suite, setup }) => ({ name, suite, setup: setup.verdict })) };
  } catch (error) {
    return { match: false, counts, problems: [`unreadable: ${error?.message}`], rows: [], profiles: [] };
  }
}
