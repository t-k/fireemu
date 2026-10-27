// node --test rtdb-residual-fixture.test.mjs: the committed residual fixtures and their comparison.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { PROFILE_NAMES, buildFixture, summarize } from './rtdb-residual-fixture.mjs';

const META = { recording: 'production-5', envelope: 'RTDB-RESIDUAL-20261026-05', recordedOn: '2026-10-27' };
const raw = () => ['cv08', 'cv10'].flatMap((scenario) => PROFILE_NAMES.map((name) => ({ scenario, name, counts: { http: 3 }, journal: [{ scenario, step: 's', type: 'value', actor: 'o', label: 'l', shape: '1', ms: 7 }, { scenario, step: 'fire', type: 'timing', actor: 'host', seconds: name.endsWith('ws') ? 0.1 : 104, ms: 9 }] })));

test('a fixture keeps the judged fields only, in order, for the eight profiles', () => {
  const doc = buildFixture(raw(), META);
  assert.deepEqual(doc.rows, Array(8).fill(2));
  assert.deepEqual(doc.profiles[0], { scenario: 'cv08', name: 'r1-ws', journal: [{ step: 's', type: 'value', actor: 'o', label: 'l', shape: '1' }, { step: 'fire', type: 'timing', actor: 'host', seconds: 0.1 }] });
  assert.equal(JSON.stringify(doc).includes('"ms"') || JSON.stringify(doc).includes('counts'), false);
  assert.deepEqual([doc.project, doc.instance], ['fireemu-oracle-query', 'fireemu-q-rtdb2']);
});

test('a fixture refuses missing profiles, a wrong order, missing metadata and secret-shaped text', () => {
  assert.throws(() => buildFixture(raw().slice(0, 7), META), /eight residual profiles/);
  assert.throws(() => buildFixture([...raw().slice(1), raw()[0]], META), /eight residual profiles/);
  for (const field of Object.keys(META)) assert.throws(() => buildFixture(raw(), { ...META, [field]: '' }), /missing --/);
  const leaky = raw();
  leaky[3].journal[0].shape = 'AIzaSyA-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
  assert.throws(() => buildFixture(leaky, META), /secret/);
});

test('summarize: equal journals match; one changed event is a difference in that profile only', () => {
  const production = buildFixture(raw(), META);
  const same = summarize(production, buildFixture(raw(), META));
  assert.deepEqual([same.verdict, same.match, same.rows], ['match', true, { MATCH: 8, DIFFERENCE: 0, NEEDS_REVIEW: 0 }]);
  const changed = raw();
  changed[5].journal[0].shape = '2';
  changed[7].journal[0].shape = '2';
  const out = summarize(production, buildFixture(changed, META));
  assert.deepEqual([out.verdict, out.match, out.rows], ['differences', false, { MATCH: 6, DIFFERENCE: 2, NEEDS_REVIEW: 0 }]);
  assert.deepEqual(out.profiles.filter((p) => p.verdict === 'differences').map((p) => `${p.scenario}:${p.name}`), ['cv10:r1-lp', 'cv10:r2-lp']);
});

test('summarize: a fire time outside the production range is not a match even when every event is', () => {
  const production = buildFixture(raw(), META);
  const slow = raw().map((p) => ({ ...p, journal: p.journal.map((r) => (r.type === 'timing' && p.name.endsWith('lp') ? { ...r, seconds: 150 } : r)) }));
  const out = summarize(production, buildFixture(slow, META));
  assert.deepEqual([out.verdict, out.match, out.timing.within], ['match', false, false]);
});

// The committed fixtures, once they exist: production-5 against the local journal the evidence quotes.
for (const [name, production, local] of [['production-5 against fireemu strict', 'fixtures/production-rtdb-residual.json', 'fixtures/local-rtdb-residual.json']]) {
  test(name, { skip: !existsBoth(production, local) }, () => {
    const read = (f) => JSON.parse(readFileSync(new URL(`./${f}`, import.meta.url), 'utf8'));
    const out = summarize(read(production), read(local));
    assert.equal(out.match, true, JSON.stringify(out.profiles.filter((p) => p.verdict !== 'match')));
    assert.deepEqual(out.rows, { MATCH: 8, DIFFERENCE: 0, NEEDS_REVIEW: 0 });
  });
}

function existsBoth(...files) {
  try { for (const f of files) readFileSync(new URL(`./${f}`, import.meta.url)); return true; } catch { return false; }
}
