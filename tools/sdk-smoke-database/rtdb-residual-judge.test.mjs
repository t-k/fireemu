// node --test rtdb-residual-judge.test.mjs: the residual judge on synthetic journals shaped like the
// recorded CV07 (sdk-* events, onDisconnect fire delays) and CV11 (step, type, shape as a JSON string,
// cancel codes) production journals, plus seeded property tests (no new dependency).
import test from 'node:test';
import assert from 'node:assert/strict';

import { ROUNDS_BY_TRANSPORT, fireSeconds, judgeFireTiming, judgeProfile, judgeRuns, rowKey, sanitizeProfiles, stepGroups, stepStrictness, transportNotes } from './rtdb-residual-judge.mjs';

const NAMES = ['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp'];
// CV11-shaped rows: kept fields only, a shape as the JSON text of our own seed value.
const row = (step, type, f = {}) => ({ step, type, ...f });
const value = (step, label, v) => row(step, 'value', { label, shape: JSON.stringify(v) });
const base = () => [
  value('attach', 'win', { a: 1, b: 2 }), row('attach', 'child_added', { label: 'win', key: 'a', prev: null }), row('attach', 'child_added', { label: 'win', key: 'b', prev: 'a' }),
  row('offline', 'child_added', { label: 'win', key: 'e', prev: null }),
  row('reconnect', 'ack', { label: 'queued-1' }), row('reconnect', 'cancel', { label: 'gated', code: 'permission_denied' }), value('reconnect', 'other', 2),
  row('after', 'absent', { label: 'top' }),
];
const profile = (scenario, name, journal) => ({ scenario, name, journal });
const runOf = (scenario, journals = {}) => NAMES.map((n) => profile(scenario, n, journals[n] ?? base()));
const clone = (x) => JSON.parse(JSON.stringify(x));
const ws = (journal) => ({ 'r1-ws': journal, 'r2-ws': journal }); // both rounds of one transport

// A seeded generator (mulberry32): the same seed gives the same cases.
const prng = (seed) => () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
function genJournal(rand) {
  const steps = ['s1', 's2', 's3', 's4'].slice(0, 2 + Math.floor(rand() * 3)), out = [];
  for (const step of steps) for (let i = 0, n = 1 + Math.floor(rand() * 4); i < n; i++) out.push(row(step, ['value', 'child_added', 'cancel'][Math.floor(rand() * 3)], { label: 'l', key: `k${i}`, shape: String(Math.floor(rand() * 5)) }));
  return out;
}
const forAll = (seed, n, body) => { const rand = prng(seed); for (let i = 0; i < n; i++) body(rand, i); };

test('rowKey keeps the compared fields and ignores timings and any other field', () => {
  assert.equal(rowKey(row('s', 'value', { label: 'l', ms: 5, seconds: 2, extra: 1 })), rowKey(row('s', 'value', { label: 'l' })));
  assert.notEqual(rowKey(row('s', 'value', { label: 'l', shape: '1' })), rowKey(row('s', 'value', { label: 'l', shape: '2' })));
  assert.notEqual(rowKey(row('s', 'value', { key: 'a' })), rowKey(row('s', 'value', { prev: 'a' })), 'key and prev are different fields');
  assert.notEqual(rowKey(row('s', 'value', { code: 'x' })), rowKey(row('s', 'value', { label: 'x' })));
});

test('stepGroups: consecutive rows of one step form a group, and a returning step is a new group', () => {
  const g = stepGroups([row('a', 'x'), row('a', 'y'), row('b', 'x'), row('a', 'z')]);
  assert.deepEqual(g.map((x) => x.id), ['a', 'b', 'a#1']);
  assert.deepEqual(g.map((x) => x.keys.length), [2, 1, 1]);
  assert.deepEqual(stepGroups(undefined), []);
});

test('strictness: equal rounds are ordered, reordered rounds sorted, different rounds unsettled', () => {
  const a = [row('s', 'x', { key: '1' }), row('s', 'x', { key: '2' }), row('t', 'x')];
  const swapped = [row('s', 'x', { key: '2' }), row('s', 'x', { key: '1' }), row('t', 'x')];
  const other = [row('s', 'x', { key: '1' }), row('s', 'x', { key: '3' }), row('t', 'x')];
  assert.deepEqual([...stepStrictness(a, a)], [['s', 'ordered'], ['t', 'ordered']]);
  assert.deepEqual([...stepStrictness(a, swapped)], [['s', 'sorted'], ['t', 'ordered']]);
  assert.deepEqual([...stepStrictness(a, other)], [['s', 'unsettled'], ['t', 'ordered']]);
  assert.equal(stepStrictness(a, a.slice(0, 2)).get('t'), 'unsettled', 'a step missing in the other round is unsettled');
  assert.equal(stepStrictness(a.slice(0, 2), a).get('t'), 'unsettled', 'a step only in the other round is unsettled');
  assert.equal(stepStrictness(a, [row('s', 'x', { key: '1' }), row('s', 'x', { key: '2' }), row('u', 'x')]).get('t'), 'unsettled', 'a different step name is unsettled');
});

test('identical journals match in all eight profiles', () => {
  const r = judgeRuns([...runOf('cv08'), ...runOf('cv10')], [...runOf('cv08'), ...runOf('cv10')]);
  assert.equal(r.verdict, 'match');
  assert.equal(r.profiles.length, 8);
  assert.ok(r.profiles.every((p) => p.verdict === 'match' && p.differences.length === 0));
});

test('one changed event, one dropped event and one added event are differences, with the step and index', () => {
  const changed = clone(base());
  changed[2].prev = 'b';
  const dropped = base().filter((_, i) => i !== 5);
  const added = [...base(), row('after', 'value', { label: 'extra', shape: '1' })];
  for (const [what, journal, step, index] of [['changed', changed, 'attach', 2], ['dropped', dropped, 'reconnect', 1], ['added', added, 'after', 1]]) {
    const r = judgeRuns(runOf('cv08'), runOf('cv08', ws(journal)));
    assert.equal(r.verdict, 'differences', what);
    for (const name of ['r1-ws', 'r2-ws']) {
      const d = r.profiles.find((p) => p.name === name).differences;
      assert.equal(d.length, 1, what);
      assert.deepEqual([d[0].step, d[0].index], [step, index], what);
    }
    assert.ok(r.profiles.filter((p) => p.name.endsWith('-lp')).every((p) => p.verdict === 'match'), 'only the changed transport differs');
  }
});

test('a step production itself delivered in both orders is compared sorted; a stable step stays ordered', () => {
  const swap = (j) => { const c = clone(j); [c[4], c[5]] = [c[5], c[4]]; return c; };
  const production = runOf('cv08', { 'r1-ws': base(), 'r2-ws': swap(base()) });
  assert.equal(judgeRuns(production, runOf('cv08')).verdict, 'match', 'local in the first order');
  assert.equal(judgeRuns(production, runOf('cv08', { 'r1-ws': swap(base()), 'r2-ws': swap(base()) })).verdict, 'match', 'local in the second order');
  const moved = clone(base());
  [moved[1], moved[2]] = [moved[2], moved[1]];
  assert.equal(judgeRuns(production, runOf('cv08', ws(moved))).verdict, 'differences', 'order still matters in the stable attach step');
  const different = clone(swap(base()));
  different[4].code = 'other';
  assert.equal(judgeRuns(production, runOf('cv08', ws(different))).verdict, 'differences', 'sorted still compares the events');
});

test('a step whose events differ between production rounds is needs-review, never a match or a difference', () => {
  const noisy = clone(base());
  noisy[6].shape = '3';
  const production = runOf('cv08', { 'r2-lp': noisy });
  const r = judgeRuns(production, runOf('cv08'));
  assert.equal(r.verdict, 'needs-review');
  assert.deepEqual(r.profiles.filter((p) => p.verdict !== 'match').map((p) => [p.name, p.unsettled]), [['r1-lp', ['reconnect']], ['r2-lp', ['reconnect']]]);
  assert.equal(r.profiles.find((p) => p.name === 'r1-ws').verdict, 'match', 'the other transport is judged');
  const otherDifference = clone(base());
  otherDifference[0].shape = '9';
  assert.equal(judgeRuns(production, runOf('cv08', { 'r1-lp': otherDifference })).verdict, 'differences', 'a real difference outranks needs-review');
});

test('a production timeout or error row is needs-review; a local one is a difference; an absent row is an observation', () => {
  const timeout = [...base(), row('after', 'timeout', { code: 'win' })];
  assert.equal(judgeRuns(runOf('cv08', { 'r1-ws': timeout, 'r2-ws': timeout }), runOf('cv08')).verdict, 'needs-review');
  assert.equal(judgeRuns(runOf('cv08', { 'r1-ws': timeout, 'r2-ws': timeout }), runOf('cv08', { 'r1-ws': timeout, 'r2-ws': timeout })).verdict, 'needs-review', 'a local timeout beside a production one is not a difference');
  const errored = [...base(), row('after', 'error', { code: 'x' })];
  assert.equal(judgeRuns(runOf('cv08', { 'r1-ws': errored, 'r2-ws': errored }), runOf('cv08')).profiles[0].verdict, 'needs-review', 'the clean local journal does not turn a production error into a difference');
  const early = clone(base());
  early.splice(3, 0, row('offline', 'timeout', { code: 'win' }));
  const beforeCut = clone(base());
  beforeCut[0].shape = '9';
  assert.equal(judgeRuns(runOf('cv08', { 'r1-ws': early, 'r2-ws': early }), runOf('cv08', { 'r1-ws': beforeCut })).verdict, 'differences', 'steps before the production timeout are still judged');
  const afterCut = clone(base());
  afterCut[6].shape = '9';
  assert.equal(judgeRuns(runOf('cv08', { 'r1-ws': early, 'r2-ws': early }), runOf('cv08', { 'r1-ws': afterCut })).verdict, 'needs-review', 'steps from the production timeout on are not judged');
  const local = judgeRuns(runOf('cv08'), runOf('cv08', ws(timeout)));
  assert.equal(local.verdict, 'differences');
  assert.ok(local.profiles[0].differences.some((d) => /local recorded timeout/.test(d.right)));
  assert.equal(judgeRuns(runOf('cv08'), runOf('cv08')).verdict, 'match', 'the base journal holds an absent row and matches');
});

test('a missing local profile, a missing production profile and a different step order are reported', () => {
  const local = runOf('cv08').filter((p) => p.name !== 'r2-lp');
  const r = judgeRuns(runOf('cv08'), local);
  assert.equal(r.verdict, 'differences');
  assert.equal(r.profiles.find((p) => p.name === 'r2-lp').differences[0].left, 'profile');
  assert.equal(judgeRuns(runOf('cv08').slice(0, 3), runOf('cv08')).verdict, 'needs-review', 'three production profiles cannot settle strictness');
  assert.equal(judgeRuns([], runOf('cv08')).verdict, 'needs-review');
  const reordered = clone(base()).sort((a, b) => (a.step === 'offline') - (b.step === 'offline'));
  const o = judgeRuns(runOf('cv08'), runOf('cv08', ws(reordered)));
  assert.equal(o.verdict, 'differences');
  assert.match(o.profiles[0].differences[0].right, /attach>reconnect>after>offline|reconnect/);
});

test('scenarios are judged separately and a profile name is not shared across them', () => {
  const production = [...runOf('cv08'), ...runOf('cv10')];
  const bad = clone(base());
  bad[0].shape = '9';
  const r = judgeRuns(production, [...runOf('cv08'), ...runOf('cv10', ws(bad))]);
  assert.deepEqual(r.profiles.filter((p) => p.verdict === 'differences').map((p) => [p.scenario, p.name]), [['cv10', 'r1-ws'], ['cv10', 'r2-ws']]);
});

// CV07-shaped timing: WebSocket fire within 2 s, long polling within production's range +-5 s.
const timed = (ws, lp) => NAMES.map((n) => profile('cv10', n, [...base(), { step: 'fire', type: 'timing', seconds: n.endsWith('ws') ? ws : lp }]));
test('fire timing: WebSocket within 2 s, long polling within the production range plus or minus 5 s', () => {
  const production = [profile('cv10', 'r1-ws', [{ step: 'fire', type: 'timing', seconds: 0.1 }]), profile('cv10', 'r1-lp', [{ step: 'fire', type: 'timing', seconds: 104 }]), profile('cv10', 'r2-ws', [{ step: 'fire', type: 'timing', seconds: 0.2 }]), profile('cv10', 'r2-lp', [{ step: 'fire', type: 'timing', seconds: 100.8 }])];
  const at = (ws, lp) => judgeFireTiming(production, timed(ws, lp));
  assert.equal(at(0.3, 102).within, true);
  assert.equal(at(2, 95.8).within, true, 'both edges are inclusive');
  assert.equal(at(2, 109).within, true);
  assert.equal(at(2.1, 102).within, false);
  assert.equal(at(0.3, 95.7).within, false);
  assert.equal(at(0.3, 109.1).within, false);
  assert.deepEqual(at(5, 102).outside.map((o) => o.name), ['r1-ws', 'r2-ws']);
  const none = judgeFireTiming(production, runOf('cv10'));
  assert.equal(none.within, false, 'no timing row is outside, not silently fine');
  assert.equal(fireSeconds([{ step: 'fire', type: 'timing', seconds: 3 }]), 3);
  assert.equal(fireSeconds([{ step: 'fire', type: 'timing' }]), null);
  assert.equal(fireSeconds(undefined), null);
});

test('transport notes compare WebSocket with long polling per round and are informational', () => {
  const diff = clone(base());
  diff[0].shape = '9';
  const notes = transportNotes(runOf('cv08', { 'r2-lp': diff }), 'cv08');
  assert.deepEqual(notes, [{ scenario: 'cv08', round: 'r1', wsEqualsLp: true }, { scenario: 'cv08', round: 'r2', wsEqualsLp: false }]);
});

test('sanitizeProfiles keeps the compared fields and the timing seconds, drops milliseconds and secrets-shaped extras', () => {
  const [p] = sanitizeProfiles([profile('cv08', 'r1-ws', [{ step: 's', type: 'value', label: 'l', shape: '1', ms: 12, token: 'x' }, { step: 'fire', type: 'timing', seconds: 0.1, ms: 99 }])]);
  assert.deepEqual(p.journal, [{ step: 's', type: 'value', label: 'l', shape: '1' }, { step: 'fire', type: 'timing', seconds: 0.1 }]);
  assert.equal(p.scenario, 'cv08');
});

// Properties (seeded, 200 cases each).
test('property: a journal matches itself, whatever the extra fields', () => {
  forAll(1, 200, (rand) => {
    const j = genJournal(rand), r = [...NAMES.map((n) => profile('cv08', n, j))];
    assert.equal(judgeRuns(r, r.map((p) => ({ ...p, journal: p.journal.map((x) => ({ ...x, ms: 1, seconds: 2 })) }))).verdict, 'match');
  });
});

test('property: swapping two distinct rows inside a stable step is a difference; inside a raced step it is not', () => {
  forAll(2, 200, (rand) => {
    const j = genJournal(rand), groups = stepGroups(j);
    const g = groups.find((x) => new Set(x.keys).size > 1);
    if (!g) return;
    const start = j.findIndex((x) => x.step === g.step), n = g.keys.length;
    const i = Array.from({ length: n - 1 }, (_, k) => k).find((k) => g.keys[k] !== g.keys[k + 1]);
    const swapped = clone(j);
    [swapped[start + i], swapped[start + i + 1]] = [swapped[start + i + 1], swapped[start + i]];
    const stable = NAMES.map((nm) => profile('cv08', nm, j));
    assert.equal(judgeRuns(stable, NAMES.map((nm) => profile('cv08', nm, nm.endsWith('ws') ? swapped : j))).verdict, 'differences');
    const raced = NAMES.map((nm) => profile('cv08', nm, nm.startsWith('r2') ? swapped : j));
    assert.equal(judgeRuns(raced, NAMES.map((nm) => profile('cv08', nm, swapped))).verdict, 'match');
    assert.equal(judgeRuns(raced, NAMES.map((nm) => profile('cv08', nm, j))).verdict, 'match');
  });
});

test('property: dropping any one row or adding one extra row of local is a difference', () => {
  forAll(3, 200, (rand) => {
    const j = genJournal(rand), r = NAMES.map((n) => profile('cv08', n, j));
    const k = Math.floor(rand() * j.length);
    const dropped = r.map((p, i) => (i === 0 ? { ...p, journal: j.filter((_, x) => x !== k) } : p));
    assert.equal(judgeRuns(r, dropped).verdict, 'differences');
    const added = r.map((p, i) => (i === 0 ? { ...p, journal: [...j.slice(0, k), row(j[k].step, 'value', { label: 'zz', shape: 'new' }), ...j.slice(k)] } : p));
    assert.equal(judgeRuns(r, added).verdict, 'differences');
  });
});

test('property: a step that differs between production rounds is never a match', () => {
  forAll(4, 200, (rand) => {
    const j = genJournal(rand), k = Math.floor(rand() * j.length), alt = clone(j);
    alt[k].shape = 'changed';
    const production = NAMES.map((n) => profile('cv08', n, n === 'r2-ws' ? alt : j));
    const r = judgeRuns(production, NAMES.map((n) => profile('cv08', n, j)));
    assert.notEqual(r.verdict, 'match');
    assert.ok(r.profiles.filter((p) => p.name.endsWith('-ws')).every((p) => p.unsettled.includes(j[k].step) || p.verdict === 'differences'));
  });
});

test('judgeProfile reports the first differing index inside a sorted step, and a prefix as the shorter length', () => {
  const p = { name: 'r1-ws', journal: [row('s', 'x', { key: 'a' }), row('s', 'x', { key: 'b' })] };
  const l = { name: 'r1-ws', journal: [row('s', 'x', { key: 'a' })] };
  const r = judgeProfile(p, l, new Map([['s', 'ordered']]));
  assert.deepEqual([r.verdict, r.differences[0].step, r.differences[0].index, r.differences[0].right], ['differences', 's', 1, null]);
  const s = judgeProfile(p, { name: 'r1-ws', journal: [row('s', 'x', { key: 'a' }), row('s', 'x', { key: 'c' })] }, new Map([['s', 'sorted']]));
  assert.equal(s.differences[0].index, 1);
});

test('actors: the order between writer and observer rows is a race and not compared; within one actor it is', () => {
  const j = [row('top-off', 'ack', { actor: 'w', label: 'w-a' }), row('top-off', 'value', { actor: 'o', label: 'items', shape: '1' }), row('top-off', 'child_added', { actor: 'o', label: 'win', key: 'c' })];
  const interleaved = [j[1], j[0], j[2]];
  assert.equal(judgeRuns(runOf('cv08', ws(j)), runOf('cv08', ws(interleaved))).verdict, 'match', 'the writer ack may arrive before or after the observer events');
  const sameActor = [j[0], j[2], j[1]];
  assert.equal(judgeRuns(runOf('cv08', ws(j)), runOf('cv08', ws(sameActor))).verdict, 'differences', 'the observer events keep their order');
  const otherActor = [{ ...j[0], actor: 'o' }, j[1], j[2]];
  assert.equal(judgeRuns(runOf('cv08', ws(j)), runOf('cv08', ws(otherActor))).verdict, 'differences', 'who produced a row is part of the row');
  assert.notEqual(rowKey(j[0]), rowKey({ ...j[0], actor: 'o' }));
});

test('a rejected row is an observation; a step where local raced but production did not is needs-review, sorted at most', () => {
  const rejected = [...base(), row('register-denied', 'rejected', { actor: 'w', label: 'e8-set', code: 'PERMISSION_DENIED', shape: 'permission_denied: permission denied' })];
  assert.equal(judgeRuns(runOf('cv10', ws(rejected)), runOf('cv10', ws(rejected))).verdict, 'match');
  const swap = (jn) => { const c = clone(jn); [c[4], c[5]] = [c[5], c[4]]; return c; };
  const raced = { 'r1-ws': base(), 'r2-ws': swap(base()) };
  const r = judgeRuns(runOf('cv08'), runOf('cv08', raced));
  assert.equal(r.verdict, 'needs-review');
  assert.deepEqual(r.profiles.filter((p) => p.name.endsWith('-ws')).map((p) => [p.verdict, p.localRaced]), [['needs-review', ['reconnect']], ['needs-review', ['reconnect']]]);
  assert.ok(r.profiles.filter((p) => p.name.endsWith('-lp')).every((p) => p.verdict === 'match' && p.localRaced.length === 0));
  const changed = clone(swap(base()));
  changed[4].code = 'other';
  const bad = judgeRuns(runOf('cv08'), runOf('cv08', { 'r1-ws': base(), 'r2-ws': changed }));
  assert.equal(bad.verdict, 'differences', 'a raced local step still has to hold the same events');
  assert.deepEqual(bad.profiles.filter((p) => p.verdict === 'differences').map((p) => p.name), ['r2-ws']);
  assert.equal(judgeRuns(runOf('cv08', raced), runOf('cv08', raced)).verdict, 'match', 'production raced as well: sorted and a match');
});

// The axes of the coverage ledger (PICT model work+rtdb-residual.pict), enumerated in full: how strictly
// production's rounds fix step S, what local does to S, and whether production recorded a timeout.
// Expected verdicts are written from the rules in the header of rtdb-residual-judge.mjs, not from its code.
const S_ROWS = [row('S', 'value', { label: 'a', shape: '1' }), row('S', 'value', { label: 'b', shape: '2' }), row('S', 'value', { label: 'c', shape: '3' })];
const T_ROW = row('T', 'ack', { label: 't' });
const swapped = [S_ROWS[1], S_ROWS[0], S_ROWS[2]], altered = [S_ROWS[0], S_ROWS[1], row('S', 'value', { label: 'c', shape: 'y' })];
const unsettledRound = [S_ROWS[0], S_ROWS[1], row('S', 'value', { label: 'c', shape: 'x' })];
const expectedVerdict = (strict, change, unknown) => {
  if (unknown === 'atS') return 'needs-review';
  let f;
  if (strict === 'unsettled') f = 'needs-review';
  else if (change === 'alterBoth') f = 'differences';
  else if (strict === 'ordered') f = change === 'none' ? 'match' : change === 'swapBoth' ? 'differences' : 'needs-review';
  else f = 'match';
  return f === 'match' && unknown === 'afterS' ? 'needs-review' : f;
};
test('axes: every strictness x local change x production timeout x transport gives the verdict the rules give', () => {
  let cases = 0;
  for (const strict of ['ordered', 'sorted', 'unsettled']) for (const change of ['none', 'swapBoth', 'alterBoth', 'racedLocal']) for (const unknown of ['none', 'atS', 'afterS']) for (const transport of ['ws', 'lp']) {
    const prodRound2 = strict === 'ordered' ? S_ROWS : strict === 'sorted' ? swapped : unsettledRound;
    const withUnknown = (rows) => (unknown === 'atS' ? [...rows, row('S', 'timeout', { label: 'x' }), T_ROW] : unknown === 'afterS' ? [...rows, T_ROW, row('T', 'timeout', { label: 'y' })] : [...rows, T_ROW]);
    const localRound = (round) => (change === 'none' ? S_ROWS : change === 'swapBoth' ? swapped : change === 'alterBoth' ? altered : round === 1 ? S_ROWS : swapped);
    const names = ROUNDS_BY_TRANSPORT[transport];
    const production = [...runOf('cv08', { ...Object.fromEntries(NAMES.map((n) => [n, [...S_ROWS, T_ROW]])), [names[0]]: withUnknown(S_ROWS), [names[1]]: withUnknown(prodRound2) })];
    const local = runOf('cv08', { ...Object.fromEntries(NAMES.map((n) => [n, [...S_ROWS, T_ROW]])), [names[0]]: [...localRound(1), T_ROW], [names[1]]: [...localRound(2), T_ROW] });
    const got = judgeRuns(production, local).verdict, want = expectedVerdict(strict, change, unknown);
    assert.equal(got, want, `${strict} ${change} ${unknown} ${transport}`);
    cases++;
  }
  assert.equal(cases, 72);
});

test('fire timing: a string, a row of another step, a negative or missing WebSocket value and a missing long-polling value are not fine', () => {
  assert.equal(fireSeconds([{ step: 'fire', type: 'timing', seconds: '3' }]), null);
  assert.equal(fireSeconds([{ step: 'other', type: 'timing', seconds: 3 }, { step: 'fire', type: 'timing', seconds: 4 }]), 4);
  assert.equal(fireSeconds([{ step: 'other', type: 'timing', seconds: 3 }]), null);
  const production = [profile('cv10', 'r1-ws', [{ step: 'fire', type: 'timing', seconds: 0.1 }]), profile('cv10', 'r1-lp', [{ step: 'fire', type: 'timing', seconds: 104 }]), profile('cv10', 'r2-ws', [{ step: 'fire', type: 'timing', seconds: 0.2 }]), profile('cv10', 'r2-lp', [{ step: 'fire', type: 'timing', seconds: 100.8 }])];
  const local = (ws, lp) => [profile('cv10', 'r1-ws', ws), profile('cv10', 'r1-lp', lp), profile('cv10', 'r2-ws', ws), profile('cv10', 'r2-lp', lp)];
  const t = (seconds) => [{ step: 'fire', type: 'timing', seconds }];
  assert.equal(judgeFireTiming(production, local(t(0.3), t(102))).within, true);
  assert.equal(judgeFireTiming(production, local(t(-0.1), t(102))).within, false, 'a negative WebSocket delay is outside');
  assert.equal(judgeFireTiming(production, local([], t(102))).within, false, 'a missing WebSocket timing is outside');
  assert.equal(judgeFireTiming(production, local(t('0.3'), t(102))).within, false, 'a string is not a delay');
  const lpMissing = production.map((p) => (p.name === 'r1-lp' ? { ...p, journal: [] } : p));
  assert.equal(judgeFireTiming(lpMissing, local(t(0.3), t(50))).within, false, 'a production profile without timing does not widen the range down to zero');
  assert.equal(judgeFireTiming(lpMissing, local(t(0.3), t(100.8))).within, true);
});

test('a production with one transport only, or with one round only, is never a match', () => {
  const wsOnly = runOf('cv08').filter((p) => p.name.endsWith('-ws'));
  const r = judgeRuns(wsOnly, runOf('cv08'));
  assert.equal(r.verdict, 'needs-review');
  assert.ok(r.profiles.every((p) => p.verdict === 'match'), 'what exists is judged');
  const oneRound = runOf('cv08').filter((p) => p.name !== 'r2-ws');
  const o = judgeRuns(oneRound, runOf('cv08'));
  assert.equal(o.profiles.find((p) => p.name === 'r1-ws').verdict, 'needs-review', 'strictness cannot be derived from one round');
  assert.ok(o.profiles.find((p) => p.name === 'r1-ws').unsettled.length > 0);
});

test('sanitizeProfiles drops fields that are undefined', () => {
  const [p] = sanitizeProfiles([profile('cv08', 'r1-ws', [{ step: 's', type: 'value', label: undefined, key: 'k' }])]);
  assert.deepEqual(Object.keys(p.journal[0]), ['step', 'type', 'key']);
});

test('rows without an actor (runner, transport) sort before the actors (which sort by name) and keep their order', () => {
  const a = [row('s', 'x'), row('s', 'ack', { actor: 'w' }), row('s', 'v', { actor: 'o' })];
  const b = [row('s', 'ack', { actor: 'w' }), row('s', 'v', { actor: 'o' }), row('s', 'x')];
  assert.deepEqual(stepGroups(a)[0].keys, stepGroups(b)[0].keys);
  assert.deepEqual(stepGroups(a)[0].keys, [rowKey(a[0]), rowKey(a[2]), rowKey(a[1])]);
  const c = [row('s', 'v', { actor: 'o' }), row('s', 'x'), row('s', 'ack', { actor: 'w' })];
  assert.deepEqual(stepGroups(c)[0].keys, stepGroups(a)[0].keys);
});
