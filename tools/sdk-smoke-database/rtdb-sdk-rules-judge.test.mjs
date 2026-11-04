// node --test rtdb-sdk-rules-judge.test.mjs: the comparison of the rules suite (G8). Exact bytes after the {scope}
// mask, the recorded status and the allowlisted response headers; probes and reinstalls only need to succeed on both
// sides; fail closed on anything not in a recorded shape.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { caseCount, installProblems, judgeCase, judgeProfile, summarize } from './rtdb-sdk-rules-judge.mjs';
import { RULES_CASES, TABLE } from './sdk-observer/rules-suite.mjs';
import { RECORDED_RESPONSE_HEADERS } from './sdk-observer/lib.mjs';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/local-sdk-rules.json', import.meta.url), 'utf8'));
const copy = () => structuredClone(FIXTURE);
const seeded = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
const spec = id => TABLE.find(c => c.id === id);
const row = (doc, profile, id) => doc.profiles.find(p => p.name === profile).rows.find(r => r.id === id);

test('the fixture against itself: 140 of 140 MATCH, no problem', () => {
  const s = summarize(copy(), copy());
  assert.equal(s.match, true, JSON.stringify(s.problems)); assert.deepEqual(s.counts, { MATCH: 140, MISMATCH: 0, NEEDS_REVIEW: 0 });
  assert.equal(caseCount(), 140); assert.equal(s.rows.length, 140);
  assert.deepEqual(s.rows.slice(0, 2).map(r => [r.profile, r.case]), [['r1-rules', 'seed'], ['r1-rules', 'tok-admin-allow']]);
});
test('judgeCase: status, a recorded header, a header only the local side sends, body bytes and length each make a MISMATCH and are named', () => {
  const p = row(copy(), 'r1-rules', 'cw-etag'), cases = [
    ['status', l => { l.status = 201; }],
    ['header:etag', l => { l.responseHeaders.etag = 'other='; }],
    ['header:etag', l => { delete l.responseHeaders.etag; }],
    ['header:+location', l => { l.responseHeaders.location = '/x'; }],
    ['body', l => { l.body = '{"v":2}'; }],
    ['bodyBytes', l => { l.bodyBytes += 1; }],
  ];
  assert.equal(typeof p.responseHeaders.etag, 'string', 'the recorded answer has its ETag');
  for (const [difference, change] of cases) {
    const l = structuredClone(p); change(l);
    const v = judgeCase(p, l, spec('cw-etag'));
    assert.equal(v.verdict, 'MISMATCH', difference); assert.ok(v.differences.includes(difference), `${difference}: ${v.differences}`);
  }
  assert.deepEqual(judgeCase(p, structuredClone(p), spec('cw-etag')), { verdict: 'MATCH', reason: 'status, recorded headers and body bytes equal', differences: [] });
});
test('judgeCase: a Rules load answer is judged as bytes: another error text or column is a MISMATCH', () => {
  const p = row(copy(), 'r1-rules', 'load-two-paths');
  assert.equal(p.status, 400); assert.match(p.body, /^\{\n {2}"error" : "1:\d+: /);
  const column = structuredClone(p); column.body = p.body.replace(/1:(\d+):/, (m, n) => `1:${Number(n) + 1}:`);
  assert.ok(judgeCase(p, column, spec('load-two-paths')).differences.includes('body'));
  const first = structuredClone(p); first.body = `${p.body.split('\\n')[0]}\\n"\n}\n`; first.bodyBytes = Buffer.byteLength(first.body);
  assert.deepEqual(judgeCase(p, first, spec('load-two-paths')).differences, ['body', 'bodyBytes']);
});
test('judgeCase: member order is part of the body (orderBy answers are judged by exact order)', () => {
  const p = row(copy(), 'r1-rules', 'nb-range'), l = structuredClone(p);
  l.body = JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(p.body)).reverse()));
  assert.equal(l.body.length, p.body.length); assert.notEqual(l.body, p.body);
  assert.deepEqual(judgeCase(p, l, spec('nb-range')).differences, ['body']);
});
test('judgeCase: the recorded side fails closed: not answered, unknown, 5xx, not UTF-8, clipped, an unrecorded field or header, another request or identity', () => {
  const id = 'wv-allow', p = row(copy(), 'r1-rules', id);
  const recordedBad = [
    r => { r.outcome = 'unknown-status'; r.ok = false; r.unknown = [id]; },
    r => { r.outcome = 'unknown-body'; r.ok = false; r.unknown = [id]; r.utf8 = false; },
    r => { r.outcome = 'blocked'; },
    r => { r.status = 503; },
    r => { r.utf8 = false; },
    r => { r.clipped = true; },
    r => { r.extra = 1; },
    r => { r.responseHeaders['set-cookie'] = 'x'; },
    r => { r.identity = 'admin'; },
    r => { r.group = 'query'; },
    r => { r.query = 'auth_variable_override=null'; },
    r => { r.requestBody = '{"a":1}'; },
    r => { r.path = '/wv/p1.json'; },
    r => { r.requestHeaders = { 'if-match': '{etag}' }; },
    r => { delete r.bodyBytes; },
  ];
  for (const [i, change] of recordedBad.entries()) {
    const r = structuredClone(p); change(r);
    assert.equal(judgeCase(r, structuredClone(p), spec(id)).verdict, 'NEEDS_REVIEW', `recorded change ${i}`);
    const v = judgeCase(structuredClone(p), r, spec(id));
    assert.notEqual(v.verdict, 'MATCH', `local change ${i}`);
  }
});
test('judgeCase: a local 5xx is flagged as a defect, a local unknown or blocked case is NEEDS_REVIEW', () => {
  const p = row(copy(), 'r1-rules', 'ix-a'), l = structuredClone(p); l.status = 500;
  assert.deepEqual(judgeCase(p, l, spec('ix-a')), { verdict: 'NEEDS_REVIEW', reason: 'local case answered 5xx', differences: [], defect: 'local 5xx' });
  const u = structuredClone(p); u.outcome = 'unknown'; u.ok = false;
  assert.equal(judgeCase(p, u, spec('ix-a')).verdict, 'NEEDS_REVIEW');
});
test('installProblems: every probe ready, every reinstall 200, the reinstalls exactly after the accepted load documents', () => {
  const p = () => structuredClone(FIXTURE.profiles[0]);
  assert.deepEqual(installProblems(p(), 'local'), []);
  const changes = [
    x => { x.probes[0].ready = false; },
    x => { x.probes[2].attempts = 0; },
    x => { x.probes.splice(1, 1); },
    x => { x.installs[1].ok = false; },
    x => { x.installs[1].status = 400; },
    x => { x.installs.pop(); },
    x => { x.rows.find(r => r.id === 'load-paren').status = 200; },
    x => { x.rows.find(r => r.id === 'lex-nel').status = 400; },
    x => { delete x.installs; },
  ];
  for (const [i, change] of changes.entries()) { const x = p(); change(x); assert.ok(installProblems(x, 'local').length > 0, `change ${i}`); }
  const refused = p(); refused.rows.find(r => r.id === 'lex-nel').status = 400; refused.installs = refused.installs.filter(i => i.after !== 'lex-nel'); refused.probes = refused.probes.filter(i => i.after !== 'lex-nel');
  assert.deepEqual(installProblems(refused, 'recorded'), [], 'a refused lexing document has no reinstall: consistent');
  const slow = p(); slow.probes[0].attempts = 5;
  assert.deepEqual(installProblems(slow, 'recorded'), [], 'the attempt count is not judged');
});
test('a refused lexing document on one side only is a MISMATCH of that case, not a run problem', () => {
  const recorded = copy(); for (const p of recorded.profiles) { const r = p.rows.find(x => x.id === 'lex-nel'); r.status = 400; r.body = '{\n  "error" : "1:40: x\\n"\n}\n'; r.bodyBytes = Buffer.byteLength(r.body); r.responseHeaders['content-length'] = String(r.bodyBytes); p.installs = p.installs.filter(i => i.after !== 'lex-nel'); p.probes = p.probes.filter(i => i.after !== 'lex-nel'); }
  const s = summarize(recorded, copy());
  assert.deepEqual(s.problems, []); assert.equal(s.counts.MISMATCH, 2); assert.equal(s.match, false);
  assert.deepEqual(s.rows.filter(r => r.verdict === 'MISMATCH').map(r => `${r.profile}/${r.case}`), ['r1-rules/lex-nel', 'r2-rules/lex-nel']);
});
test('a missing, extra or swapped case row is NEEDS_REVIEW at its position and the run does not match', () => {
  const missing = copy(); missing.profiles[0].rows.splice(3, 1);
  const s = summarize(copy(), missing); assert.equal(s.match, false); assert.ok(s.counts.NEEDS_REVIEW > 0); assert.ok(s.problems.some(x => /missing or extra/.test(x)));
  const swapped = copy(); [swapped.profiles[1].rows[4], swapped.profiles[1].rows[5]] = [swapped.profiles[1].rows[5], swapped.profiles[1].rows[4]];
  const t = summarize(copy(), swapped); assert.equal(t.match, false); assert.equal(t.counts.NEEDS_REVIEW, 2);
});
test('the run level fails closed: an unverified (unknown) mutation, an incomplete run, faults, a cleanup not verified, another prefix length, another kind or suite, a profile without probes', () => {
  const changes = [
    d => { d.result.unverified = ['unknown REST mutation outcome: r1-rules/wv-allow']; },
    d => { d.result.status = 'incomplete'; },
    d => { d.result.observed = 139; },
    d => { d.result.exit = 3; },
    d => { d.faults = [{ kind: 'abort', profile: null }]; },
    d => { d.result.cleanup.rules = 'unverified'; },
    d => { d.result.prefixLength = 16; },
    d => { d.kind = 'rtdb-sdk-rest-journal-v1'; },
    d => { d.suite = 'rest'; },
    d => { delete d.profiles[1].probes; },
    d => { d.profiles.reverse(); },
  ];
  for (const [i, change] of changes.entries()) {
    for (const side of [0, 1]) {
      const pair = [copy(), copy()]; change(pair[side]);
      const s = summarize(...pair);
      assert.equal(s.match, false, `change ${i} on side ${side}`); assert.ok(s.problems.length > 0, `change ${i} on side ${side}`);
    }
  }
  assert.equal(summarize(null, copy()).match, false);
});
test('local defects (5xx) are listed in the summary', () => {
  const local = copy(); row(local, 'r2-rules', 'q-end').status = 502;
  const s = summarize(copy(), local); assert.deepEqual(s.defects, ['r2-rules/q-end: local 5xx']);
});
test('property: any single leaf perturbation of a case row on either side is never a MATCH of that case, and the run never matches (seeded, 600 samples)', () => {
  const rand = seeded(11);
  const leaves = r => Object.entries(r).flatMap(([k, v]) => (v && typeof v === 'object' ? Object.keys(v).map(k2 => [k, k2]) : [[k]]));
  for (let n = 0; n < 600; n++) {
    const side = Math.floor(rand() * 2), pi = Math.floor(rand() * 2), ri = Math.floor(rand() * RULES_CASES.length);
    const pair = [copy(), copy()], target = pair[side].profiles[pi].rows[ri], all = leaves(target), [k, k2] = all[Math.floor(rand() * all.length)];
    const bump = v => (typeof v === 'number' ? v + 1 : typeof v === 'boolean' ? !v : v === null ? 'x' : `${v}!`);
    if (k2 === undefined) target[k] = bump(target[k]); else target[k][k2] = bump(target[k][k2]);
    const s = summarize(...pair), r = s.rows.find(x => x.profile === pair[0].profiles[pi].name && x.case === RULES_CASES[ri]);
    assert.equal(s.match, false, `sample ${n}: ${k}/${k2}`);
    if (r) assert.notEqual(r.verdict, 'MATCH', `sample ${n}: ${k}/${k2}`);
  }
});
test('property: adding an allowlisted response header on the local side only, or removing a recorded one, is a MISMATCH naming it (seeded over every case)', () => {
  const rand = seeded(13);
  for (const id of RULES_CASES) {
    const p = row(copy(), 'r1-rules', id), absent = RECORDED_RESPONSE_HEADERS.filter(h => !Object.hasOwn(p.responseHeaders, h));
    const add = structuredClone(p), name = absent[Math.floor(rand() * absent.length)]; add.responseHeaders[name] = 'x';
    assert.deepEqual(judgeCase(p, add, spec(id)).differences, [`header:+${name}`], id);
    const present = Object.keys(p.responseHeaders);
    if (present.length) { const del = structuredClone(p), gone = present[Math.floor(rand() * present.length)]; delete del.responseHeaders[gone]; assert.deepEqual(judgeCase(p, del, spec(id)).differences, [`header:${gone}`], id); }
  }
});
test('judgeProfile: each profile is judged at fixed positions; a profile of another name is not judged against it', () => {
  const d = copy(), j = judgeProfile(d.profiles[0], d.profiles[1]);
  assert.ok(j.problems.some(x => /profile names differ/.test(x))); assert.ok(j.rows.every(r => r.verdict === 'NEEDS_REVIEW'));
  const ok = judgeProfile(copy().profiles[1], copy().profiles[1]);
  assert.deepEqual(ok.problems, []); assert.ok(ok.rows.every(r => r.verdict === 'MATCH'));
});
