// node --test rtdb-sdk-rest-judge.test.mjs: the comparison of the rest suite (G7). Exact bytes after the masks, the
// recorded status and the allowlisted response headers; fail closed on anything not in a recorded shape.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { caseCount, judgeCase, judgeProfile, summarize } from './rtdb-sdk-rest-judge.mjs';
import { REST_CASES, TABLE } from './sdk-observer/rest-suite.mjs';
import { RECORDED_RESPONSE_HEADERS } from './sdk-observer/lib.mjs';

// A real local reduction (strict profile, fireemu v0.43.0, suite rest); strict and emulator gave the same bytes.
const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/local-sdk-rest.json', import.meta.url), 'utf8'));
const copy = () => structuredClone(FIXTURE);
const seeded = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
const spec = id => TABLE.find(c => c.id === id);
const row = (doc, profile, id) => doc.profiles.find(p => p.name === profile).rows.find(r => r.id === id);

test('the fixture against itself: 144 of 144 MATCH, no problem', () => {
  const s = summarize(copy(), copy());
  assert.equal(s.match, true, JSON.stringify(s.problems)); assert.deepEqual(s.counts, { MATCH: 144, MISMATCH: 0, NEEDS_REVIEW: 0 });
  assert.equal(caseCount(), 144); assert.equal(s.rows.length, 144);
  assert.deepEqual(s.rows.slice(0, 2).map(r => [r.profile, r.case]), [['r1-rest', 'setup-mix'], ['r1-rest', 'setup-ints']]);
});

// ---- single cases ----
test('judgeCase: status, a recorded header, a header only the local side sends, body bytes and length each make a MISMATCH and are named', () => {
  const p = row(copy(), 'r1-rest', 'etag-get'), cases = [
    ['status', l => { l.status = 201; }],
    ['header:etag', l => { l.responseHeaders.etag = 'other='; }],
    ['header:etag', l => { delete l.responseHeaders.etag; }],
    ['header:+location', l => { l.responseHeaders.location = '/x'; }],
    ['body', l => { l.body = '{"x":2}'; }],
    ['bodyBytes', l => { l.bodyBytes += 1; }],
  ];
  for (const [difference, change] of cases) {
    const l = structuredClone(p); change(l);
    const v = judgeCase(p, l, spec('etag-get'));
    assert.equal(v.verdict, 'MISMATCH', difference); assert.ok(v.differences.includes(difference), `${difference}: ${v.differences}`);
  }
  assert.deepEqual(judgeCase(p, structuredClone(p), spec('etag-get')), { verdict: 'MATCH', reason: 'status, recorded headers and body bytes equal', differences: [] });
});
test('judgeCase: member order is part of the body (orderBy answers are judged by exact order)', () => {
  const p = row(copy(), 'r1-rest', 'order-key-ints'), l = structuredClone(p);
  l.body = JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(p.body)).reverse()));
  assert.equal(l.body.length, p.body.length);
  assert.deepEqual(judgeCase(p, l, spec('order-key-ints')).differences, ['body']);
});
test('judgeCase: a push id whose shape failed on the local side is a MISMATCH; on the recorded side it is NEEDS_REVIEW', () => {
  const p = row(copy(), 'r1-rest', 'post-scalar'), l = structuredClone(p); l.pushIdShapeOk = false;
  assert.deepEqual(judgeCase(p, l, spec('post-scalar')).differences, ['pushIdShapeOk']);
  assert.equal(judgeCase(l, p, spec('post-scalar')).verdict, 'NEEDS_REVIEW');
});
test('judgeCase: the recorded side fails closed: not answered, unknown, 5xx, not UTF-8, clipped, an unrecorded field or header, another request', () => {
  const p = row(copy(), 'r1-rest', 'print-pretty-put'), id = 'print-pretty-put';
  const recordedBad = [
    r => { r.outcome = 'unknown-status'; r.ok = false; r.unknown = [id]; },
    r => { r.status = 503; },
    r => { r.utf8 = false; },
    r => { r.clipped = true; },
    r => { r.extra = 1; },
    r => { r.responseHeaders['set-cookie'] = 'a'; },
    r => { r.responseHeaders.etag = 5; },
    r => { r.query = 'print=silent'; },
    r => { r.requestBody = '{"a":2}'; },
    r => { r.path = '{scope}/other.json'; },
    r => { r.method = 'POST'; },
    r => { r.requestHeaders = { 'if-none-match': '"x"' }; },
    r => { r.bodyBytes = -1; },
    r => { r.body = null; },
    r => { r.pushIdShapeOk = true; },
    r => { delete r.status; },
  ];
  for (const [i, change] of recordedBad.entries()) {
    const bad = structuredClone(p); change(bad);
    assert.equal(judgeCase(bad, structuredClone(p), spec(id)).verdict, 'NEEDS_REVIEW', `recorded change ${i}`);
    assert.equal(judgeCase(structuredClone(p), bad, spec(id)).verdict, 'NEEDS_REVIEW', `local change ${i}`);
  }
});
test('judgeCase: a local 5xx is flagged as a defect, a local unknown or blocked case is NEEDS_REVIEW, a missing case too', () => {
  const p = row(copy(), 'r1-rest', 'timeout-5s'), l = structuredClone(p); l.status = 500;
  const v = judgeCase(p, l, spec('timeout-5s'));
  assert.equal(v.verdict, 'NEEDS_REVIEW'); assert.equal(v.defect, 'local 5xx');
  assert.equal(judgeCase(p, { id: 'timeout-5s', ok: false, outcome: 'unknown', error: 'x' }, spec('timeout-5s')).verdict, 'NEEDS_REVIEW');
  assert.equal(judgeCase(p, undefined, spec('timeout-5s')).verdict, 'NEEDS_REVIEW');
  const etag = row(copy(), 'r1-rest', 'etag-inm-match');
  assert.equal(judgeCase(etag, { id: 'etag-inm-match', ok: false, outcome: 'blocked', error: 'no ETag in the answer of etag-get' }, spec('etag-inm-match')).verdict, 'NEEDS_REVIEW');
  assert.equal(judgeCase({ id: 'etag-inm-match', ok: false, outcome: 'blocked', error: 'no ETag in the answer of etag-get' }, etag, spec('etag-inm-match')).verdict, 'NEEDS_REVIEW');
});

// ---- whole runs ----
test('a missing, extra or swapped case row is NEEDS_REVIEW at its position and the run does not match', () => {
  const variants = [
    d => { d.profiles[0].rows.splice(10, 1); },
    d => { d.profiles[1].rows.push(structuredClone(d.profiles[1].rows[0])); },
    d => { const r = d.profiles[0].rows; [r[20], r[21]] = [r[21], r[20]]; },
  ];
  for (const [i, change] of variants.entries()) for (const side of ['production', 'local']) {
    const p = copy(), l = copy(); change(side === 'production' ? p : l);
    const s = summarize(p, l);
    assert.equal(s.match, false, `${side} ${i}`); assert.ok(s.counts.NEEDS_REVIEW >= 1 || s.problems.length >= 1, `${side} ${i}`);
  }
  const p = copy(), l = copy(); l.profiles[0].rows.splice(10, 1);
  const s = summarize(p, l);
  assert.equal(s.rows.find(r => r.profile === 'r1-rest' && r.case === REST_CASES[10]).verdict, 'NEEDS_REVIEW');
  assert.ok(s.problems.some(x => /r1-rest: a case row is missing or extra/.test(x)));
});
test('the run level fails closed: an unverified (unknown) mutation, an incomplete run, faults, a cleanup not verified, another prefix length, another kind or suite', () => {
  const variants = [
    ['unverified', d => { d.result.unverified = ['unknown REST mutation outcome: r1-rest/sv-bogus']; }],
    ['incomplete', d => { d.result.status = 'incomplete'; d.result.exit = 1; }],
    ['observed', d => { d.result.observed = 143; }],
    ['faults', d => { d.faults = [{ kind: 'abort', profile: null }]; }],
    ['cleanup', d => { d.result.cleanup.rules = 'unverified'; }],
    ['prefix', d => { d.result.prefixLength = 17; }],
    ['kind', d => { d.kind = 'rtdb-sdk-events-journal-v1'; }],
    ['suite', d => { d.suite = 'events'; }],
    ['profiles', d => { d.profiles.reverse(); }],
    ['result shape', d => { d.result.extra = 1; }],
  ];
  for (const [name, change] of variants) for (const side of ['production', 'local']) {
    const p = copy(), l = copy(); change(side === 'production' ? p : l);
    const s = summarize(p, l);
    assert.equal(s.match, false, `${name} on ${side}`); assert.ok(s.problems.length >= 1, `${name} on ${side}`);
  }
  assert.equal(summarize(null, copy()).match, false); assert.equal(summarize(copy(), 'x').match, false);
});
test('local defects (5xx) are listed in the summary', () => {
  const l = copy(); row(l, 'r2-rest', 'shallow-leaf').status = 502;
  const s = summarize(copy(), l);
  assert.equal(s.match, false); assert.deepEqual(s.defects, ['r2-rest/shallow-leaf: local 5xx']);
});

// ---- properties (seeded) ----
const paths = (value, at = []) => (value !== null && typeof value === 'object' ? Object.entries(value).flatMap(([k, v]) => paths(v, [...at, k])) : [at]);
const get = (doc, p) => p.reduce((v, k) => v[k], doc);
const set = (doc, p, v) => { get(doc, p.slice(0, -1))[p.at(-1)] = v; };
function perturb(value, rand) {
  if (typeof value === 'number') return value + 1 + Math.floor(rand() * 3);
  if (typeof value === 'boolean') return !value;
  if (typeof value === 'string') return value.length && rand() < 0.5 ? value.slice(0, -1) : `${value}x`;
  return 'x';
}
test('property: any single leaf perturbation of a case row on either side is never a MATCH of that case, and the run never matches (seeded, 600 samples)', () => {
  const rand = seeded(20261105), leaves = FIXTURE.profiles.flatMap((p, i) => paths(p.rows).map(at => ['profiles', i, 'rows', ...at]));
  for (let n = 0; n < 600; n++) {
    const at = leaves[Math.floor(rand() * leaves.length)], side = rand() < 0.5 ? 'production' : 'local';
    const p = copy(), l = copy(), target = side === 'production' ? p : l;
    set(target, at, perturb(get(target, at), rand));
    const s = summarize(p, l), profile = FIXTURE.profiles[at[1]].name, id = FIXTURE.profiles[at[1]].rows[at[3]].id;
    assert.equal(s.match, false, `${side} ${at.join('.')}`);
    const v = s.rows.find(r => r.profile === profile && r.case === id);
    assert.ok(!v || v.verdict !== 'MATCH', `${side} ${at.join('.')} judged ${v?.verdict}`);
  }
});
test('property: adding an allowlisted response header on the local side only, or removing a recorded one, is a MISMATCH naming it (seeded over every case)', () => {
  const rand = seeded(11);
  for (const [i, p] of FIXTURE.profiles.entries()) for (const r of p.rows) {
    const absent = RECORDED_RESPONSE_HEADERS.filter(h => !Object.hasOwn(r.responseHeaders, h)), present = Object.keys(r.responseHeaders);
    const add = absent[Math.floor(rand() * absent.length)], drop = present[Math.floor(rand() * present.length)];
    for (const [name, change] of [[`header:+${add}`, l => { l.responseHeaders[add] = 'v'; }], [`header:${drop}`, l => { delete l.responseHeaders[drop]; }]]) {
      if (name.endsWith('undefined')) continue;
      const l = structuredClone(r); change(l);
      const v = judgeCase(r, l, spec(r.id));
      assert.equal(v.verdict, 'MISMATCH', `${p.name}/${r.id} ${name}`); assert.ok(v.differences.includes(name), `${p.name}/${r.id} ${name}: ${v.differences}`);
    }
    void i;
  }
});
test('judgeProfile: each profile is judged at fixed positions; a profile of another name is not judged against it', () => {
  const p = copy().profiles[0], l = copy().profiles[0];
  const j = judgeProfile(p, l);
  assert.equal(j.rows.length, 72); assert.equal(j.extra, null); assert.ok(j.rows.every(r => r.verdict === 'MATCH'));
  const other = copy().profiles[1];
  assert.ok(judgeProfile(p, other).problems.some(x => /profile names differ/.test(x)));
});
