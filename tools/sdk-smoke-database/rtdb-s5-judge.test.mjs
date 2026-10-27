// node --test rtdb-s5-judge.test.mjs: the S5 judge classifies the production answer to "an onDisconnect value with
// .priority, then a cancel of one of its children" as A, B, C or D and fails closed on everything else.
import test from 'node:test';
import assert from 'node:assert/strict';
import { CASES, OUTCOMES, REGISTRATIONS, classify, judgeRounds, sanitizeProfiles } from './rtdb-s5-judge.mjs';

const row = (fields) => ({ scenario: 's5', actor: 'o', ...fields });
const get = (label, value, priority = null) => row({ step: 'final', type: 'get', label, shape: JSON.stringify(value), priority });
const SPLIT = { 9: 3, 10: 2 }, WHOLE = { b: 1, 9: 3, 10: 2 };

/** A complete journal; `main` is [s, t, sPriority] as the observer read them after the writer's disconnect. */
function journal({ main = [SPLIT, 1, null], plain = [SPLIT, 1, null], whole = [WHOLE, 1, 1], drop = [], extra = [] } = {}) {
  const rows = [];
  for (const c of CASES) for (const label of REGISTRATIONS[c]) rows.push(row({ step: 'register', type: 'ack', actor: 'w', label }));
  for (const c of CASES) rows.push(row({ step: 'disconnect', type: 'offline', actor: 'w', label: c }));
  for (const [c, [s, t, p]] of Object.entries({ main, plain, whole })) rows.push(get(`${c}-s`, s, p), get(`${c}-t`, t));
  rows.push({ scenario: 's5', step: 'runner', type: 'transport', code: 'ws' });
  return [...rows.filter((r) => !drop.some((d) => Object.entries(d).every(([k, v]) => r[k] === v))), ...extra];
}

test('the four outcomes of the main case are classified, the controls being fine', () => {
  assert.equal(classify(journal({ main: [null, null, null] })).outcome, 'A');
  assert.equal(classify(journal({ main: [SPLIT, 1, null] })).outcome, 'B');
  assert.equal(classify(journal({ main: [SPLIT, 1, 1] })).outcome, 'B');
  assert.equal(classify(journal({ main: [WHOLE, 1, 1] })).outcome, 'C');
  assert.equal(classify(journal({ main: [null, 1, null] })).outcome, 'D');
  for (const o of ['A', 'B', 'C', 'D']) assert.ok(OUTCOMES[o]);
});

test('any other final state of the main case is unclassified, never the nearest letter', () => {
  for (const main of [[null, 2, null], [SPLIT, null, null], [WHOLE, null, null], [{ b: 1 }, 1, null], [{ 9: 3 }, 1, null], [7, 1, null], [{ ...WHOLE, extra: 1 }, 1, null], [SPLIT, 1.5, null], [SPLIT, '1', null]]) {
    const r = classify(journal({ main }));
    assert.equal(r.outcome, 'unclassified', JSON.stringify(main));
    assert.match(r.reason, /main/);
  }
});

test('a control that does not behave as recorded on the jar makes the answer unclassified', () => {
  assert.equal(classify(journal({ plain: [null, null, null] })).outcome, 'unclassified');
  assert.equal(classify(journal({ plain: [WHOLE, 1, null] })).outcome, 'unclassified');
  assert.equal(classify(journal({ whole: [SPLIT, 1, null] })).outcome, 'unclassified');
  assert.equal(classify(journal({ whole: [WHOLE, 1, null] })).outcome, 'unclassified', 'the priority must survive a cancel of a missing key');
  assert.equal(classify(journal({ whole: [null, null, null] })).outcome, 'unclassified');
  assert.match(classify(journal({ plain: [null, null, null] })).reason, /control plain/);
});

test('the key order of a shape does not matter, its values do', () => {
  const j = journal();
  j.find((r) => r.label === 'main-s').shape = '{"10":2,"9":3}';
  assert.equal(classify(j).outcome, 'B');
  j.find((r) => r.label === 'main-s').shape = '{"10":2,"9":4}';
  assert.equal(classify(j).outcome, 'unclassified');
});

test('a missing, duplicated or foreign row fails closed', () => {
  const base = journal();
  for (const drop of [{ label: 'main-s' }, { label: 'main-t' }, { label: 'plain-s' }, { label: 'whole-t' }, { type: 'offline', label: 'main' }, { type: 'offline', label: 'whole' }, { type: 'ack', label: REGISTRATIONS.main[1] }, { type: 'ack', label: REGISTRATIONS.whole[0] }, { type: 'transport' }]) {
    assert.equal(classify(journal({ drop: [drop] })).outcome, 'unclassified', JSON.stringify(drop));
  }
  assert.equal(classify([...base, base.find((r) => r.label === 'main-s')]).outcome, 'unclassified', 'a duplicated get');
  assert.equal(classify([...base, get('other-s', null)]).outcome, 'unclassified', 'a get of a label the scenario does not read');
  assert.equal(classify([]).outcome, 'unclassified');
  assert.equal(classify(undefined).outcome, 'unclassified');
});

test('timeouts, errors, rejections and a transport other than WebSocket fail closed', () => {
  for (const extra of [{ step: 'disconnect', type: 'timeout', label: 'x' }, { step: 'runner', type: 'error', code: 'profile timeout' }, { step: 'register', type: 'rejected', actor: 'w', label: REGISTRATIONS.main[0], code: 'permission_denied' }, { step: 'final', type: 'rejected', label: 'main-s', code: 'other' }, { step: 'x', type: 'cancel', label: 'main-s', code: 'permission_denied' }]) {
    assert.equal(classify(journal({ extra: [row(extra)] })).outcome, 'unclassified', JSON.stringify(extra));
  }
  const lp = journal({ drop: [{ type: 'transport' }], extra: [{ scenario: 's5', step: 'runner', type: 'transport', code: 'lp' }] });
  assert.equal(classify(lp).outcome, 'unclassified');
});

test('two rounds are judged together: equal letters give the letter, anything else is unsettled or unclassified', () => {
  const profile = (name, j) => ({ scenario: 's5', name, journal: j });
  const a = (name) => profile(name, journal({ main: [null, null, null] }));
  const b = (name) => profile(name, journal({ main: [SPLIT, 1, null] }));
  assert.deepEqual(judgeRounds([a('r1-ws'), a('r2-ws')]).verdict, 'A');
  assert.equal(judgeRounds([b('r1-ws'), b('r2-ws')]).verdict, 'B');
  assert.equal(judgeRounds([a('r1-ws'), b('r2-ws')]).verdict, 'unsettled');
  assert.equal(judgeRounds([a('r1-ws'), profile('r2-ws', journal({ main: [null, 2, null] }))]).verdict, 'unclassified');
  assert.equal(judgeRounds([a('r1-ws')]).verdict, 'unclassified', 'one round is not an answer');
  assert.equal(judgeRounds([a('r1-ws'), a('r1-ws')]).verdict, 'unclassified', 'the same round twice');
  assert.equal(judgeRounds([a('r1-ws'), a('r2-ws'), a('r3-ws')]).verdict, 'unclassified');
  assert.equal(judgeRounds([]).verdict, 'unclassified');
  assert.equal(judgeRounds(undefined).verdict, 'unclassified');
});

test('property: a random final state is classified exactly when it is one of the four recorded shapes', () => {
  let seed = 20261027;
  const rnd = (n) => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed % n; };
  const values = [null, SPLIT, WHOLE, { b: 1 }, { 9: 3 }, 5, { ...SPLIT, z: 0 }];
  const ts = [null, 1, 2, 0];
  const priorities = [null, 1];
  const want = (s, t) => (s === null && t === null ? 'A' : s === SPLIT && t === 1 ? 'B' : s === WHOLE && t === 1 ? 'C' : s === null && t === 1 ? 'D' : 'unclassified');
  for (let i = 0; i < 400; i++) {
    const s = values[rnd(values.length)], t = ts[rnd(ts.length)], p = priorities[rnd(2)];
    assert.equal(classify(journal({ main: [s, t, p] })).outcome, want(s, t), JSON.stringify([s, t, p]));
  }
});

test('the journal kept in the repository holds the kept fields only', () => {
  const kept = sanitizeProfiles([{ scenario: 's5', name: 'r1-ws', journal: [{ scenario: 's5', step: 'final', type: 'get', actor: 'o', label: 'main-s', shape: 'null', priority: null, ms: 1234, secret: 'x' }] }]);
  assert.deepEqual(kept[0].journal[0], { scenario: 's5', step: 'final', type: 'get', actor: 'o', label: 'main-s', shape: 'null', priority: null });
});
