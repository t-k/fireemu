import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { STEPS, judgeStep, summarize, stepCount } from './rtdb-sdk-events-judge.mjs';

// A real local reduction (strict profile, fireemu v0.43.0, suite events+admin); the property tests perturb it.
const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/local-sdk-events.json', import.meta.url), 'utf8'));
const copy = v => structuredClone(v);
const seeded = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };

test('the fixture judged against itself: every step of every case of every profile matches', () => {
  const s = summarize(FIXTURE, copy(FIXTURE));
  assert.deepEqual(s.problems, []); assert.equal(s.match, true);
  assert.equal(stepCount('events+admin'), 4 * 32 + 2 * 16); assert.equal(s.rows.length, stepCount('events+admin')); assert.equal(s.counts.MATCH, s.rows.length);
});
test('the step tables are the recorder\'s: events 8 cases / 32 steps per profile, admin 10 cases / 16 steps', () => {
  assert.equal(Object.keys(STEPS.events).length, 8); assert.equal(Object.values(STEPS.events).flat().length, 32);
  assert.equal(Object.keys(STEPS.admin).length, 10); assert.equal(Object.values(STEPS.admin).flat().length, 16);
  assert.deepEqual(STEPS.events.key_window.map(s => s.label), ['attach', 'set-a', 'set-f', 'remove-a', 'set-b']);
  assert.deepEqual(STEPS.events.cursor_pair.map(s => s.kind), ['get', 'attach', 'write']);
});

// Leaves and containers of a JSON value with their paths.
function* nodes(value, path = []) {
  yield [path, value];
  if (value && typeof value === 'object') for (const key of Object.keys(value)) yield* nodes(value[key], [...path, Array.isArray(value) ? Number(key) : key]);
}
const at = (root, path) => path.reduce((v, k) => v[k], root);
/** Every single-field change of a node: a different value of the same type, another type, removal, an extra member, reordering. */
function perturbations(value) {
  const out = [];
  if (value === null) out.push(0, 'null', false);
  else if (typeof value === 'number') out.push(value + 1, String(value), value + 0.5);
  else if (typeof value === 'string') out.push(`${value}x`, value.slice(1), 1);
  else if (typeof value === 'boolean') out.push(!value, String(value));
  else if (Array.isArray(value)) { out.push([...value, value[0] ?? null]); if (value.length) out.push(value.slice(1)); if (value.length > 1 && JSON.stringify(value[0]) !== JSON.stringify(value[1])) out.push([value[1], value[0], ...value.slice(2)]); }
  else { const keys = Object.keys(value); out.push({ ...value, extra: 1 }); if (keys.length) out.push(Object.fromEntries(Object.entries(value).slice(1))); if (keys.length > 1) out.push(Object.fromEntries(Object.entries(value).reverse())); }
  return out;
}
function setAt(root, path, v) { const doc = copy(root); if (!path.length) return v; at(doc, path.slice(0, -1))[path.at(-1)] = v; return doc; }
const recordPaths = [...nodes(FIXTURE)].map(([p]) => p).filter(p => p.length && p[0] !== 'kind');

test('property: any single-field perturbation of the local record is never a match (seeded sample over every node)', () => {
  const rand = seeded(20261104); let tried = 0;
  for (const path of recordPaths) {
    const options = perturbations(at(FIXTURE, path));
    const pick = options[Math.floor(rand() * options.length)];
    const s = summarize(FIXTURE, setAt(FIXTURE, path, pick)); tried++;
    assert.equal(s.match, false, `accepted local ${JSON.stringify(path)} -> ${JSON.stringify(pick)}`);
  }
  assert.ok(tried > 1000, `only ${tried} nodes`);
});
test('property: the same holds on the production side (a perturbed recording never matches the original local one)', () => {
  const rand = seeded(7);
  for (const path of recordPaths) {
    if (rand() > 0.35) continue;
    const options = perturbations(at(FIXTURE, path));
    const pick = options[Math.floor(rand() * options.length)];
    assert.equal(summarize(setAt(FIXTURE, path, pick), FIXTURE).match, false, `accepted production ${JSON.stringify(path)} -> ${JSON.stringify(pick)}`);
  }
});
test('property: every perturbation kind of the event lists of one step is rejected and the verdict names that step', () => {
  const p = FIXTURE.profiles.findIndex(x => x.name === 'r2-lp'), c = FIXTURE.profiles[p].rows.findIndex(r => r.id === 'priority_window');
  for (const [path] of nodes(FIXTURE.profiles[p].rows[c].steps[1], ['profiles', p, 'rows', c, 'steps', 1])) {
    for (const pick of perturbations(at(FIXTURE, path))) {
      const s = summarize(FIXTURE, setAt(FIXTURE, path, pick));
      assert.equal(s.match, false, JSON.stringify([path, pick]));
      const row = s.rows.find(r => r.profile === 'r2-lp' && r.case === 'priority_window' && r.step === 'priority-z-0');
      if (row) assert.notEqual(row.verdict, 'MATCH', JSON.stringify([path, pick]));
    }
  }
});

// ---- the verdicts on hand-made steps -------------------------------------------------------------------------------------------------
const W = { step: 'set-a', observer: [{ l: 'Q1', e: 'child_added', k: 'a', p: null, v: 1 }, { l: 'Q1', e: 'value', k: 'kw', v: { children: [['a', 1]] } }], writer: [], ack: 'ok', quiet: true };
const spec = { kind: 'write', label: 'set-a' }, labels = { observer: ['Q1', 'Q2'], writer: [] };
test('step: identical records match; a different event list, order or value is a mismatch', () => {
  assert.equal(judgeStep(W, copy(W), spec, labels).verdict, 'MATCH');
  assert.equal(judgeStep(W, { ...W, observer: [...W.observer].reverse() }, spec, labels).verdict, 'MISMATCH');
  assert.equal(judgeStep(W, { ...W, observer: W.observer.slice(1) }, spec, labels).verdict, 'MISMATCH');
  assert.equal(judgeStep(W, { ...W, ack: { error: 'permission-denied' } }, spec, labels).verdict, 'MISMATCH');
});
test('step: a hit bound (quiet false, ready false) is never compared: NEEDS_REVIEW on either side', () => {
  assert.equal(judgeStep({ ...W, quiet: false }, W, spec, labels).verdict, 'NEEDS_REVIEW');
  assert.equal(judgeStep(W, { ...W, quiet: false }, spec, labels).verdict, 'NEEDS_REVIEW');
  const A = { step: 'attach', observer: [], writer: [], ready: false, quiet: true };
  assert.equal(judgeStep(A, { ...A, ready: true }, { kind: 'attach', label: 'attach' }, labels).verdict, 'NEEDS_REVIEW');
});
test('step: an unrecorded shape fails closed: unknown label, unknown event kind, extra member, recorder fault, writer events outside a transaction, wrong step label', () => {
  const bad = [
    { ...W, observer: [{ ...W.observer[0], l: 'Q9' }] },
    { ...W, observer: [{ ...W.observer[0], e: 'child_wobbled' }] },
    { ...W, observer: [{ ...W.observer[0], extra: 1 }] },
    { ...W, observer: [{ l: 'Q1', e: 'value', k: 'kw', p: null, v: 1 }] },
    { ...W, observer: [{ l: 'Q1', e: 'recorder-error', error: 'x' }] },
    { ...W, writer: [{ l: 'W', e: 'value', k: 'a', v: { leaf: 1 } }] },
    { ...W, step: 'set-b' },
    { ...W, ack: 'fine' },
    { ...W, result: { exists: true } },
    { step: 'set-a', writer: [], observer: W.observer, ack: 'ok', quiet: true },
    null,
  ];
  for (const b of bad) {
    assert.equal(judgeStep(b, W, spec, labels).verdict, 'NEEDS_REVIEW', `production ${JSON.stringify(b)}`);
    assert.notEqual(judgeStep(W, b, spec, labels).verdict, 'MATCH', `local ${JSON.stringify(b)}`);
  }
});
test('step: transactions carry writer events (W, txn) and a result of inputs, committed and snapshot', () => {
  const T = { step: 'absent', observer: [], writer: [{ l: 'W', e: 'value', k: 'ta', v: { leaf: null } }, { l: 'W', e: 'value', k: 'ta', v: { leaf: 1 } }, { l: 'txn', e: 'resolved' }], ready: true, result: { inputs: [null], committed: true, snapshot: { leaf: 1 } }, quiet: true };
  const s = { kind: 'transaction', label: 'absent' }, l = { observer: ['TA'], writer: ['W', 'txn'] };
  assert.equal(judgeStep(T, copy(T), s, l).verdict, 'MATCH');
  assert.equal(judgeStep(T, { ...T, writer: [T.writer[0], T.writer[2], T.writer[1]] }, s, l).verdict, 'MISMATCH');
  assert.equal(judgeStep(T, { ...T, result: { ...T.result, inputs: [null, null] } }, s, l).verdict, 'MISMATCH');
  assert.equal(judgeStep(T, { ...T, result: { inputs: [null], snapshot: { leaf: 1 }, committed: true } }, s, l).verdict, 'NEEDS_REVIEW');   // member order is part of the shape: not a recorded one
  assert.equal(judgeStep({ ...T, result: { inputs: [null], committed: 'yes', snapshot: null } }, T, s, l).verdict, 'NEEDS_REVIEW');
});

// ---- the document ---------------------------------------------------------------------------------------------------------------------
test('document: an incomplete run, faults, an unverified cleanup, another kind or suite or profile list never match', () => {
  const variants = [
    d => { d.result.status = 'incomplete'; }, d => { d.result.exit = 1; }, d => { d.result.observed -= 1; }, d => { d.result.cleanup.rules = 'unverified'; },
    d => { d.faults.push({ kind: 'abort', profile: null }); }, d => { d.kind = 'rtdb-sdk-small-journal-v1'; }, d => { d.suite = 'events'; },
    d => { d.profiles.reverse(); }, d => { d.profiles.pop(); }, d => { d.profiles[0].suite = 'admin'; },
  ];
  for (const change of variants) {
    const d = copy(FIXTURE); change(d);
    assert.equal(summarize(FIXTURE, d).match, false, change.toString()); assert.equal(summarize(d, FIXTURE).match, false, change.toString());
  }
  assert.equal(summarize(null, FIXTURE).match, false); assert.equal(summarize(FIXTURE, 'x').match, false);
});
test('document: a missing, extra, duplicated or failed case gives NEEDS_REVIEW rows for its steps, never a silent pass', () => {
  const cases = [
    d => { d.profiles[1].rows.splice(5, 1); }, d => { d.profiles[1].rows.push(copy(d.profiles[1].rows.at(-1))); },
    d => { d.profiles[1].rows[4].ok = false; d.profiles[1].rows[4].error = 'Error: x'; }, d => { d.profiles[1].rows[4].steps.pop(); },
    d => { d.profiles[1].rows[4].steps.push(copy(d.profiles[1].rows[4].steps[0])); }, d => { [d.profiles[1].rows[4], d.profiles[1].rows[5]] = [d.profiles[1].rows[5], d.profiles[1].rows[4]]; },
    d => { d.profiles[1].rows[0].ok = false; }, d => { d.profiles[5].rows.splice(0, 1); },
  ];
  for (const change of cases) {
    const d = copy(FIXTURE); change(d);
    const s = summarize(FIXTURE, d);
    assert.equal(s.match, false, change.toString()); assert.equal(s.rows.length, stepCount('events+admin'), change.toString());
    assert.ok(s.counts.NEEDS_REVIEW + s.counts.MISMATCH > 0 || s.problems.length > 0, change.toString());
  }
});
test('document: a single-suite run is judged on its own profiles and step count', () => {
  const only = suite => { const d = { ...copy(FIXTURE), suite, profiles: copy(FIXTURE.profiles.filter(p => p.suite === suite)) }; d.result.observed = suite === 'events' ? 32 : 20; return d; };
  for (const [suite, n] of [['events', 128], ['admin', 32]]) {
    const s = summarize(only(suite), only(suite));
    assert.equal(s.rows.length, n, suite); assert.equal(s.counts.MATCH, n, suite);
  }
  assert.equal(summarize(only('events'), FIXTURE).match, false);
});
test('a judge that throws on an unreadable record answers no match', () => {
  const d = copy(FIXTURE); d.profiles[0].rows = 'x';
  const s = summarize(FIXTURE, d); assert.equal(s.match, false);
});

// ---- mutation run 1 (2026-11-04): an unrecorded shape that is the same on both sides is still never a match ----
test('step: an unrecorded shape on both sides is NEEDS_REVIEW, not a match (event fields, get and transaction results, markers)', () => {
  const T = { step: 'absent', observer: [], writer: [{ l: 'W', e: 'value', k: 'ta', v: { leaf: null } }, { l: 'txn', e: 'resolved' }], ready: true, result: { inputs: [null], committed: true, snapshot: { leaf: 1 } }, quiet: true };
  const ts = { kind: 'transaction', label: 'absent' }, tl = { observer: ['TA'], writer: ['W', 'txn'] };
  const G = { step: 'get', observer: [], writer: [], result: { exists: true, v: { leaf: 1 } }, quiet: true }, gs = { kind: 'get', label: 'get' };
  const cases = [
    [{ ...T, writer: [T.writer[0], { l: 'txn', e: 'exploded' }] }, ts, tl],
    [{ ...T, result: { ...T.result, committed: 'yes' } }, ts, tl],
    [{ ...T, result: { inputs: [null], error: 3 } }, ts, tl],
    [{ ...W, observer: [{ l: 'Q1', e: 'cancel', code: 5 }] }, spec, labels],
    [{ ...W, observer: [{ ...W.observer[0], k: 5 }] }, spec, labels],
    [{ ...W, observer: [{ ...W.observer[0], p: 5 }] }, spec, labels],
    [{ ...G, result: { exists: true, v: { weird: 1 } } }, gs, labels],
    [{ ...G, result: { exists: true, v: { children: [['a']] } } }, gs, labels],
    [{ ...G, result: { exists: true, v: { children: [[1, 2]] } } }, gs, labels],
    [{ ...G, result: { exists: 'yes', v: { leaf: 1 } } }, gs, labels],
    [{ ...G, result: { exists: true } }, gs, labels],
  ];
  for (const [step, s, l] of cases) assert.equal(judgeStep(step, copy(step), s, l).verdict, 'NEEDS_REVIEW', JSON.stringify(step));
  assert.equal(judgeStep(G, copy(G), gs, labels).verdict, 'MATCH');
  assert.equal(judgeStep({ ...G, result: { error: 'permission-denied' } }, { ...G, result: { error: 'permission-denied' } }, gs, labels).verdict, 'MATCH');
});
test('document: an extra member of the document or of its result is never a match, even on both sides', () => {
  for (const change of [d => { d.extra = 1; }, d => { d.result.extra = 1; }]) { const d = copy(FIXTURE); change(d); assert.equal(summarize(d, copy(d)).match, false, change.toString()); }
});
test('a record that throws while it is read answers no match with the reason', () => {
  const d = copy(FIXTURE), p = d.profiles[0];
  d.profiles[0] = new Proxy(p, { get: (t, k) => { if (k === 'rows') throw new Error('poisoned'); return t[k]; } });
  const s = summarize(FIXTURE, d); assert.equal(s.match, false); assert.match(s.problems[0], /unreadable: poisoned/);
});
