// node --test rtdb-sdk-tokens-judge.test.mjs: the comparison of the tokens suite (G10). The rules judge's per-case verdict
// (exact status, recorded headers, body and byte length after the masks); the ready probe only needs to end ready on both
// sides; fail closed on anything not in a recorded shape.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { caseCount, judgeProfile, probeProblems, summarize } from './rtdb-sdk-tokens-judge.mjs';
import { judgeCase } from './rtdb-sdk-rules-judge.mjs';
import { TABLE, TOKENS_CASES, TOKENS_PROFILES } from './sdk-observer/tokens-suite.mjs';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/local-sdk-tokens.json', import.meta.url), 'utf8'));
const copy = () => structuredClone(FIXTURE);
const seeded = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
const spec = id => TABLE.find(c => c.id === id);
const row = (doc, profile, id) => doc.profiles.find(p => p.name === profile).rows.find(r => r.id === id);

test('the committed local fixture against itself: 54 of 54 MATCH; it is the tokens reduction of a complete local run', () => {
  const s = summarize(copy(), copy());
  assert.equal(s.match, true, JSON.stringify(s.problems)); assert.deepEqual(s.counts, { MATCH: 54, MISMATCH: 0, NEEDS_REVIEW: 0 });
  assert.equal(caseCount(), 54); assert.deepEqual(s.defects, []);
  assert.deepEqual(s.rows.slice(0, 2).map(r => [r.profile, r.case]), [['r1-tokens', 'seed'], ['r1-tokens', 'ctl-anon-authreq']]);
  assert.equal(FIXTURE.kind, 'rtdb-sdk-tokens-journal-v1'); assert.equal(FIXTURE.result.prefixLength, '/sdktokens20261105'.length);
  for (const p of FIXTURE.profiles) assert.deepEqual(p.rows.map(r => r.id), TOKENS_CASES);
});
test('judgeCase (the rules judge) on a tokens row: status, headers, body and bytes each make a MISMATCH and are named; the template request is checked', () => {
  const p = row(copy(), 'r1-tokens', 'auth-hs256');
  for (const [difference, change] of [['status', l => { l.status += 1; }], ['header:+location', l => { l.responseHeaders.location = '/x'; }], ['body', l => { l.body = `${l.body} `; }], ['bodyBytes', l => { l.bodyBytes += 1; }]]) {
    const l = structuredClone(p); change(l);
    const v = judgeCase(p, l, spec('auth-hs256'));
    assert.equal(v.verdict, 'MISMATCH', difference); assert.ok(v.differences.includes(difference), `${difference}: ${v.differences}`);
  }
  for (const change of [r => { r.query = 'auth=x'; }, r => { r.requestHeaders = { authorization: 'Bearer x' }; }, r => { r.identity = 'anonymous'; }, r => { r.group = 'bearer'; }, r => { r.path = '{scope}/pub.json'; }]) {
    const l = structuredClone(p); change(l);
    assert.equal(judgeCase(p, l, spec('auth-hs256')).reason, 'local case: not the request of the case table');
  }
  const b = row(copy(), 'r1-tokens', 'bearer-rs256');
  assert.deepEqual(b.requestHeaders, { authorization: 'Bearer {cred}' }); assert.equal(judgeCase(b, structuredClone(b), spec('bearer-rs256')).verdict, 'MATCH');
});
test('probeProblems: exactly one start probe that ended ready after at least one attempt, on each side', () => {
  const p = copy().profiles[0];
  assert.deepEqual(probeProblems(p, 'local'), []);
  for (const probes of [[], [{ after: 'start', attempts: 3, ready: false, outcome: 'answered' }], [{ after: 'start', attempts: 0, ready: true }], [{ after: 'start', attempts: 1, ready: true }, { after: 'start', attempts: 1, ready: true }], [{ after: 'lex', attempts: 1, ready: true }], undefined])
    assert.equal(probeProblems({ ...p, probes }, 'local').length, 1, JSON.stringify(probes));
  assert.deepEqual(probeProblems({ ...p, probes: [{ after: 'start', attempts: 7, ready: true, outcome: 'answered' }] }, 'recorded'), [], 'the number of attempts is not compared');
});
test('summarize: a local ready probe that did not end ready is a problem even when every case matches', () => {
  for (const side of ['recorded', 'local']) {
    const p = copy(), l = copy(); (side === 'recorded' ? p : l).profiles[1].probes = [{ after: 'start', attempts: 20, ready: false, outcome: 'answered' }];
    const s = summarize(p, l);
    assert.equal(s.counts.MATCH, 54, side); assert.equal(s.match, false, side);
    assert.deepEqual(s.problems, [`${side} r2-tokens: the ready probe did not end ready`]);
  }
});
test('judgeProfile: a missing, extra or misplaced row and another profile name fail closed', () => {
  const d = copy(), l = copy();
  l.profiles[0].rows.splice(3, 1);
  const missing = judgeProfile(d.profiles[0], l.profiles[0]);
  assert.ok(missing.problems.some(x => /missing or extra/.test(x)));
  assert.ok(missing.rows.slice(3).every(r => r.verdict === 'NEEDS_REVIEW'));
  const swapped = copy(); [swapped.profiles[0].rows[5], swapped.profiles[0].rows[6]] = [swapped.profiles[0].rows[6], swapped.profiles[0].rows[5]];
  const s = judgeProfile(d.profiles[0], swapped.profiles[0]);
  assert.deepEqual(s.rows.filter(r => r.verdict !== 'MATCH').map(r => r.case), [TOKENS_CASES[5], TOKENS_CASES[6]]);
  const named = judgeProfile(d.profiles[0], { ...l.profiles[1], rows: d.profiles[0].rows });
  assert.ok(named.problems.some(x => /profile names differ/.test(x))); assert.ok(named.rows.every(r => r.verdict === 'NEEDS_REVIEW'));
});
test('judge: the recorded or local side fails closed on not answered, 5xx (a local 5xx is a defect), not UTF-8, clipped, an unrecorded field', () => {
  const id = 'auth-rs256';
  for (const [side, change, re] of [
    ['recorded', r => { r.outcome = 'unknown'; r.ok = false; }, /recorded case: not answered/],
    ['recorded', r => { r.status = 503; }, /recorded case answered 5xx/],
    ['local', r => { r.status = 500; }, /local case answered 5xx/],
    ['local', r => { r.utf8 = false; }, /not UTF-8/],
    ['local', r => { r.clipped = true; }, /clipped/],
    ['local', r => { r.extra = 1; }, /fields are not the recorded ones/],
    ['recorded', r => { delete r.bodyBytes; }, /fields are not the recorded ones/],
  ]) {
    const p = copy(), l = copy();
    change(row(side === 'recorded' ? p : l, 'r2-tokens', id));
    const s = summarize(p, l), r = s.rows.find(x => x.profile === 'r2-tokens' && x.case === id);
    assert.equal(r.verdict, 'NEEDS_REVIEW', `${side} ${re}`); assert.match(r.reason, re); assert.equal(s.match, false);
    if (/local case answered 5xx/.test(String(re))) assert.deepEqual(s.defects, [`r2-tokens/${id}: local 5xx`]);
  }
});
test('summarize: an incomplete run, unknown outcomes, faults, an unverified cleanup, another prefix length, other profiles or kind are problems; no rows are judged', () => {
  for (const change of [
    d => { d.result.status = 'incomplete'; }, d => { d.result.observed = 53; }, d => { d.result.exit = 3; }, d => { d.result.unverified = ['x']; },
    d => { d.result.cleanup.rules = 'unverified'; }, d => { d.faults = [{ kind: 'abort', profile: null }]; }, d => { d.result.prefixLength = 17; },
    d => { d.profiles = d.profiles.slice(0, 1); }, d => { d.kind = 'rtdb-sdk-rules-journal-v1'; }, d => { d.suite = 'rules'; }, d => { d.extra = 1; }, d => { d.profiles[0].installs = []; },
  ]) {
    const l = copy(); change(l);
    const s = summarize(copy(), l);
    assert.equal(s.match, false, change.toString()); assert.ok(s.problems.length >= 1, change.toString()); assert.equal(s.counts.MATCH, 0, change.toString());
  }
  assert.deepEqual(summarize(null, copy()).match, false);
  const unreadable = summarize(copy(), { ...copy(), profiles: [{ name: 'r1-tokens', rows: null, probes: [] }, { name: 'r2-tokens', rows: 7, probes: [] }] });
  assert.equal(unreadable.match, false);
});
test('property (seeded): any one changed answer field of any row makes that row not MATCH and the comparison not a match', () => {
  const rnd = seeded(20261105), fields = ['status', 'body', 'bodyBytes', 'responseHeaders', 'utf8', 'clipped', 'ok', 'outcome', 'query', 'requestHeaders', 'requestBody', 'identity', 'group', 'method', 'path', 'id'];
  for (let i = 0; i < 300; i++) {
    const p = copy(), l = copy(), profile = TOKENS_PROFILES[Math.floor(rnd() * 2)], at = Math.floor(rnd() * TOKENS_CASES.length), field = fields[Math.floor(rnd() * fields.length)];
    const r = l.profiles.find(x => x.name === profile).rows[at];
    const v = r[field];
    r[field] = typeof v === 'number' ? v + 1 + Math.floor(rnd() * 5) : typeof v === 'boolean' ? !v : typeof v === 'string' ? `${v}x` : v === null ? 'x' : { ...v, 'content-type': `${v['content-type'] ?? ''}x` };
    const s = summarize(p, l), judged = s.rows.find(x => x.profile === profile && x.case === TOKENS_CASES[at]);
    assert.equal(s.match, false, `${profile} ${TOKENS_CASES[at]} ${field}`);
    assert.notEqual(judged?.verdict, 'MATCH', `${profile} ${TOKENS_CASES[at]} ${field}`);
    assert.ok(s.counts.MATCH <= caseCount() - 1);
  }
});
