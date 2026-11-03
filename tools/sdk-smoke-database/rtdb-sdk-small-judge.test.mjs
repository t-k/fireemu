// node --test rtdb-sdk-small-judge.test.mjs: the comparison rules of the RTDB SDK small observer (32 SDK observations).
import test from 'node:test';
import assert from 'node:assert/strict';

import { CASES, judgeCase, judgeProfile, summarize } from './rtdb-sdk-small-judge.mjs';
import { NAMES, clone, int, journal, profile, prng } from './rtdb-sdk-small-testkit.mjs';

const SEEDS = 200;
const caseRow = (doc, name, id) => doc.profiles.find((p) => p.name === name).rows.find((r) => r.id === id);
const local = (rand) => journal(rand);

// Every way to break one field of a case value. For a masked field (push ids, clock values) only format breaks count,
// since another valid push id or a later clock value is not a difference.
function perturbations(id, value) {
  const out = [];
  if (id === 'push') {
    const [a, b] = value.keys;
    for (const keys of [[b, a], [a, a], [a.slice(1), b], [a, `${b}x`], [`${a.slice(0, 19)}!`, b], [a], [a, b, `${b.slice(0, 19)}z`], [1, b], a]) out.push({ ...value, keys });
    out.push({ ...value, a: 'b' }, { ...value, b: 'a' }, { keys: value.keys, a: 'a' }, { ...value, c: 'c' }, { b: 'b', a: 'a', keys: value.keys }, { a: 'a', keys: value.keys, b: 'b' });
    return out;
  }
  if (id === 'server_timestamp') {
    const { value: v, before, after } = value;
    out.push({ value: before - 1, before, after }, { value: after + 1, before, after }, { value: v + 0.5, before, after }, { value: String(v), before, after }, { value: null, before, after });
    out.push({ value: v, before }, { value: v, before, after, extra: 1 }, { before, value: v, after }, { value: v, after, before });
    out.push({ value: v, before: String(before), after }, { value: v, before: v + 1, after: after + 2 }, { value: v, before: before - 2, after: v - 1 });
    return out;
  }
  if (id === 'increment') {
    out.push({ ...value, at: value.at + 1 }, { ...value, at: value.at - 1 }, { ...value, at: String(value.at) });
    for (const k of ['absent', 'numeric', 'string']) out.push({ ...value, [k]: value[k] + 1 }, { ...value, [k]: String(value[k]) });
    const { at, ...noAt } = value;
    out.push(noAt, { ...value, extra: 0 }, { at, absent: 5, numeric: 12, string: 5 }, Object.fromEntries(Object.entries(value).reverse()));
    return out;
  }
  // Values judged as identical: change, drop, add or reorder any single member.
  const walk = (v, set) => {
    if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, (y) => set(v.map((z, j) => (j === i ? y : z)))));
      if (v.length) { set(v.slice(1)); set([...v].reverse()); }
      set([...v, v[0] ?? 0]);
    } else if (v && typeof v === 'object') {
      const entries = Object.entries(v);
      for (const [k, x] of entries) walk(x, (y) => set(Object.fromEntries(entries.map(([kk, xx]) => [kk, kk === k ? y : xx]))));
      for (const [k] of entries) set(Object.fromEntries(entries.filter(([kk]) => kk !== k)));
      set({ ...v, extra: 1 });
      if (entries.length > 1) set(Object.fromEntries([...entries].reverse()));
    } else if (typeof v === 'number') { set(v + 1); set(String(v)); set(null); }
    else if (typeof v === 'string') { set(`${v}x`); set(v.toLowerCase() === v ? v.toUpperCase() : v.toLowerCase()); set(1); }
    else if (v === null) { set(0); set('null'); set(false); }
  };
  walk(value, (y) => out.push(y));
  return out;
}

test('the eight recorded cases, in the recorded order', () => {
  assert.deepEqual(CASES.map(([role, id]) => `${role}:${id}`), ['observer:key_range', 'observer:value_equal', 'observer:priority_range', 'writer:push', 'writer:update', 'writer:multipath', 'writer:server_timestamp', 'writer:increment']);
});

test('property: every generated journal in the recorded shape matches, 32 of 32', () => {
  for (let seed = 1; seed <= SEEDS; seed++) {
    const rand = prng(seed), production = local(rand), mine = local(rand);
    const s = summarize(production, mine);
    assert.equal(s.match, true, `seed ${seed}: ${JSON.stringify(s.rows.filter((r) => r.verdict !== 'MATCH'))}`);
    assert.deepEqual(s.counts, { MATCH: 32, MISMATCH: 0, NEEDS_REVIEW: 0 });
  }
});

test('property: any single-field perturbation of any recorded case is rejected', () => {
  let checked = 0;
  for (let seed = 1; seed <= 40; seed++) {
    const rand = prng(seed), production = local(rand), base = local(rand);
    for (const name of NAMES) for (const [, id] of CASES) {
      for (const bad of perturbations(id, caseRow(base, name, id).value)) {
        const mine = clone(base);
        caseRow(mine, name, id).value = bad;
        const s = summarize(production, mine);
        assert.equal(s.match, false, `seed ${seed} ${name} ${id} ${JSON.stringify(bad)}`);
        assert.notEqual(s.rows.find((r) => r.profile === name && r.case === id).verdict, 'MATCH', `${name} ${id} ${JSON.stringify(bad)}`);
        checked++;
      }
    }
  }
  assert.ok(checked > 5000, String(checked));
});

test('property: a perturbed production record is never accepted either (the fixture is judged by the same rules)', () => {
  for (let seed = 1; seed <= 20; seed++) {
    const rand = prng(seed), base = local(rand), mine = local(rand);
    for (const name of NAMES) for (const id of ['push', 'server_timestamp', 'increment']) {
      for (const bad of perturbations(id, caseRow(base, name, id).value)) {
        const production = clone(base);
        caseRow(production, name, id).value = bad;
        assert.equal(summarize(production, mine).match, false, `seed ${seed} ${name} ${id} ${JSON.stringify(bad)}`);
      }
    }
  }
});

test('server_timestamp: the local value is judged against the local window, not the production one', () => {
  const production = journal(prng(3)), mine = journal(prng(4));
  const st = caseRow(mine, 'r1-ws', 'server_timestamp').value;
  assert.notEqual(st.value, caseRow(production, 'r1-ws', 'server_timestamp').value);
  assert.equal(summarize(production, mine).match, true);
  // An inclusive window: equal ends are a valid recording (a fast local case).
  for (const v of [{ value: 5e12, before: 5e12, after: 5e12 }]) {
    const m = clone(mine);
    caseRow(m, 'r1-ws', 'server_timestamp').value = v;
    caseRow(m, 'r1-ws', 'increment').value.at = 5e12;
    assert.equal(summarize(production, m).match, true);
  }
});

test('the frozen-clock defect of v0.41.0 is a mismatch of server_timestamp and of increment', () => {
  const production = journal(prng(5)), mine = journal(prng(6));
  for (const name of NAMES) {
    const st = caseRow(mine, name, 'server_timestamp').value, frozen = st.before - 300;
    st.value = frozen;
    caseRow(mine, name, 'increment').value.at = frozen;
  }
  const s = summarize(production, mine);
  assert.equal(s.match, false);
  assert.deepEqual(s.counts, { MATCH: 24, MISMATCH: 8, NEEDS_REVIEW: 0 });
  assert.deepEqual(s.rows.filter((r) => r.verdict !== 'MATCH').map((r) => r.case).sort(), [...Array(4).fill('increment'), ...Array(4).fill('server_timestamp')]);
});

test('connection events: per-role order must be identical; the interleaving of the two roles is not compared', () => {
  const production = journal(prng(7));
  for (const events of [['connected', 'disconnected'], ['disconnected', 'connected'], ['disconnected', 'connected', 'connected', 'disconnected'], ['disconnected', 'disconnected', 'connected'], [], ['disconnected', 'connected', 'disconnected', 'connected'], ['disconnected', 'connected', 'offline']]) {
    for (const role of ['writer', 'observer']) {
      const mine = journal(prng(8));
      mine.profiles[int(prng(events.length + 1), 0, 3)].events[role] = events;
      assert.equal(summarize(production, mine).match, false, `${role} ${events}`);
    }
  }
  const extraRole = journal(prng(8));
  extraRole.profiles[0].events.third = ['connected'];
  assert.equal(summarize(production, extraRole).match, false);
  // A role the observer does not have is refused even when both sides carry it identically.
  const both = [journal(prng(7)), journal(prng(8))];
  for (const d of both) d.profiles[2].events.third = ['connected'];
  assert.equal(summarize(both[0], both[1]).match, false);
  const missingRole = journal(prng(8));
  delete missingRole.profiles[0].events.observer;
  assert.equal(summarize(production, missingRole).match, false);
});

test('a missing, extra, duplicated, reordered or failed case or setup row fails closed', () => {
  const production = journal(prng(9));
  const variants = [
    (p) => p.rows.pop(),
    (p) => p.rows.splice(4, 1),
    (p) => p.rows.push(clone(p.rows[10])),
    (p) => p.rows.splice(5, 0, clone(p.rows[5])),
    (p) => { [p.rows[3], p.rows[4]] = [p.rows[4], p.rows[3]]; },
    (p) => { p.rows[6] = { role: 'writer', id: 'push', ok: false, error: 'Timeout: writer:push timed out after 15000 ms' }; },
    (p) => { p.rows[6].role = 'observer'; },
    (p) => { p.rows[0].value = {}; },
    (p) => { p.rows[2].ok = false; },
    (p) => p.rows.shift(),
    (p) => { p.rows[7].ok = 'true'; },
    (p) => { p.rows[7].extra = 1; },
    (p) => { p.rows.push({ role: 'writer', id: 'transaction', ok: true, value: 1 }); },
  ];
  for (const [i, change] of variants.entries()) {
    for (const name of NAMES) {
      const mine = journal(prng(10));
      change(mine.profiles.find((p) => p.name === name));
      const s = summarize(production, mine);
      assert.equal(s.match, false, `variant ${i} ${name}`);
    }
  }
});

test('the whole document: profiles, run result and faults are part of the comparison', () => {
  const production = journal(prng(11));
  const variants = [
    (d) => d.profiles.pop(),
    (d) => d.profiles.reverse(),
    (d) => d.profiles.push(profile('r3-ws')),
    (d) => { d.profiles[1].name = 'r1-ws'; },
    (d) => { d.result.status = 'incomplete'; },
    (d) => { d.result.observed = 31; },
    (d) => { d.result.cleanup.rules = 'unverified'; },
    (d) => { d.result.exit = 3; },
    (d) => { d.faults.push({ kind: 'page-error', profile: 'r1-lp' }); },
    (d) => { d.kind = 'something-else'; },
    (d) => { delete d.profiles; },
    (d) => { d.profiles = {}; },
  ];
  for (const [i, change] of variants.entries()) {
    const mine = journal(prng(12));
    change(mine);
    assert.equal(summarize(production, mine).match, false, `local variant ${i}`);
    const p = journal(prng(12));
    change(p);
    assert.equal(summarize(p, journal(prng(13))).match, false, `production variant ${i}`);
  }
  assert.equal(summarize(null, journal()).match, false);
  assert.equal(summarize(journal(), undefined).match, false);
});

test('judgeCase and judgeProfile give a reason for each verdict', () => {
  const p = profile('r1-ws', prng(14)), l = profile('r1-ws', prng(15));
  const st = (x) => x.rows.find((r) => r.id === 'server_timestamp');
  assert.deepEqual(judgeCase('update', p.rows[7], l.rows[7], { production: st(p), local: st(l) }), { verdict: 'MATCH', reason: 'identical values' });
  assert.equal(judgeCase('push', p.rows[6], l.rows[6], {}).verdict, 'MATCH');
  assert.equal(judgeCase('update', p.rows[7], { ...l.rows[7], value: { edit: 1, keep: 1 } }, {}).verdict, 'MISMATCH');
  assert.equal(judgeCase('update', { ...p.rows[7], ok: false }, l.rows[7], {}).verdict, 'NEEDS_REVIEW');
  assert.equal(judgeCase('update', p.rows[7], undefined, {}).verdict, 'NEEDS_REVIEW');
  assert.equal(judgeCase('unknown', p.rows[7], l.rows[7], {}).verdict, 'NEEDS_REVIEW');
  const judged = judgeProfile(p, l);
  assert.equal(judged.rows.length, 8);
  assert.deepEqual([judged.setup.verdict, judged.events.verdict], ['MATCH', 'MATCH']);
});
