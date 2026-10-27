// node --test rtdb-s5-fixture.test.mjs: the committed S5 fixtures and their comparison.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { CASES, REGISTRATIONS } from './rtdb-s5-judge.mjs';
import { buildFixture, summarize } from './rtdb-s5-fixture.mjs';

const META = { recording: 'production-1', envelope: 'RTDB-S5-20261027-01', recordedOn: '2026-10-27' };
const SPLIT = { 9: 3, 10: 2 }, WHOLE = { b: 1, 9: 3, 10: 2 };
const get = (label, value, priority = null) => ({ scenario: 's5', step: 'final', type: 'get', actor: 'o', label, shape: JSON.stringify(value), priority, ms: 5 });
/** A raw round: `main` is [s, t, priority] of the question case; the controls behave. */
function round(name, main) {
  const rows = [];
  for (const c of CASES) for (const label of REGISTRATIONS[c]) rows.push({ scenario: 's5', step: 'register', type: 'ack', actor: 'w', label, ms: 1 });
  for (const c of CASES) rows.push({ scenario: 's5', step: 'disconnect', type: 'offline', actor: 'w', label: c, ms: 2 });
  rows.push(get('plain-s', SPLIT), get('plain-t', 1), get('whole-s', WHOLE, 1), get('whole-t', 1), get('main-s', main[0], main[1] ?? null), get('main-t', main[2]));
  rows.push({ scenario: 's5', step: 'runner', type: 'transport', code: 'ws' });
  return { scenario: 's5', name, counts: { ws: 4 }, journal: rows };
}
const raw = (main = [null, null, null], second = main) => [round('r1-ws', main), round('r2-ws', second)];

test('a fixture keeps the judged fields only, in order, for the two rounds', () => {
  const doc = buildFixture(raw(), META);
  assert.deepEqual(doc.rows, [doc.profiles[0].journal.length, doc.profiles[1].journal.length]);
  assert.deepEqual(doc.profiles.map((p) => p.name), ['r1-ws', 'r2-ws']);
  const text = JSON.stringify(doc);
  assert.equal(text.includes('"ms"') || text.includes('counts'), false);
  assert.deepEqual([doc.project, doc.instance, doc.recording], ['fireemu-oracle-query', 'fireemu-q-rtdb2', 'production-1']);
});

test('a fixture refuses missing rounds, a wrong order, missing metadata and secret-shaped text', () => {
  assert.throws(() => buildFixture(raw().slice(0, 1), META), /two S5 rounds/);
  assert.throws(() => buildFixture([...raw()].reverse(), META), /two S5 rounds/);
  assert.throws(() => buildFixture(raw().map((p) => ({ ...p, scenario: 'cv10' })), META), /two S5 rounds/);
  for (const field of Object.keys(META)) assert.throws(() => buildFixture(raw(), { ...META, [field]: '' }), /missing --/);
  const leaky = raw();
  leaky[1].journal[0].label = 'AIzaSyA-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
  assert.throws(() => buildFixture(leaky, META), /secret/);
});

test('summarize: the same settled answer on both sides is a match, another answer is not', () => {
  const a = buildFixture(raw([null, null, null]), META), b = buildFixture(raw([SPLIT, null, 1]), META);
  const same = summarize(a, buildFixture(raw([null, null, null]), META));
  assert.deepEqual([same.production, same.local, same.match], ['A', 'A', true]);
  assert.deepEqual(same.rounds, [{ name: 'r1-ws', production: 'A', local: 'A' }, { name: 'r2-ws', production: 'A', local: 'A' }]);
  const differ = summarize(a, b);
  assert.deepEqual([differ.production, differ.local, differ.match], ['A', 'B', false]);
  assert.deepEqual(summarize(b, a).match, false);
  assert.equal(summarize(b, b).match, true);
});

test('summarize: unsettled and unclassified sides never match, even against themselves', () => {
  const unsettled = buildFixture(raw([null, null, null], [SPLIT, null, 1]), META);
  assert.deepEqual([summarize(unsettled, unsettled).production, summarize(unsettled, unsettled).match], ['unsettled', false]);
  const odd = buildFixture(raw([{ b: 1 }, null, 2]), META);
  assert.deepEqual([summarize(odd, odd).production, summarize(odd, odd).match], ['unclassified', false]);
  const good = buildFixture(raw([null, null, null]), META);
  assert.equal(summarize(good, odd).match, false);
  assert.equal(summarize(odd, good).match, false);
});

test('summarize: a control that misbehaves on the local side is not a match even with the same main answer', () => {
  const good = buildFixture(raw([null, null, null]), META);
  const broken = raw([null, null, null]);
  for (const p of broken) p.journal.find((r) => r.label === 'plain-s').shape = 'null';
  const out = summarize(good, buildFixture(broken, META));
  assert.deepEqual([out.local, out.match], ['unclassified', false]);
  assert.match(out.reason.local, /control plain/);
});

// The committed fixtures: production's answer (RTDB-S5-20261027-01) against fireemu's.
const read = (f) => JSON.parse(readFileSync(new URL(`./${f}`, import.meta.url), 'utf8'));
test('production answered A in both rounds, the controls behaving', () => {
  const out = summarize(read('fixtures/production-rtdb-s5.json'), read('fixtures/production-rtdb-s5.json'));
  assert.deepEqual([out.production, out.rounds.map((r) => r.production)], ['A', ['A', 'A']]);
  assert.equal(read('fixtures/production-rtdb-s5.json').envelope, 'RTDB-S5-20261027-01');
});
test('fireemu answers what production answered', () => {
  const out = summarize(read('fixtures/production-rtdb-s5.json'), read('fixtures/local-rtdb-s5.json'));
  assert.equal(out.match, true, JSON.stringify(out));
  assert.deepEqual(out.rounds, [{ name: 'r1-ws', production: 'A', local: 'A' }, { name: 'r2-ws', production: 'A', local: 'A' }]);
});
