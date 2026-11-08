// node --test rtdb-sdk-rules-syntax-judge.test.mjs: the rules-syntax judge, the reduction and the local entry. The answer shapes are
// replayed from recorded production bodies (fixtures/production-sdk-rules.json, RTDB-RULES-20261104-01); every other shape is unknown.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ACCEPTED_BODY, DENIED_BODY, PREFIX, RECORDED_SHAPES, caseCount, jsonHeaders, shapeOf, summarize } from './rtdb-sdk-rules-syntax-judge.mjs';
import { KIND, buildRulesSyntaxFixture, recordedJournal, reduceRulesSyntaxJournal } from './rtdb-sdk-rules-syntax-fixture.mjs';
import { LOCAL_DIRECT_CAP, daemonConfig, execPlan, finish, localPrefix } from './rtdb-sdk-rules-syntax.mjs';
import { DOCUMENTS, RULES_SYNTAX_PROFILES, TABLE, syntaxRules } from './sdk-observer/rules-syntax-suite.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const RULES = JSON.parse(readFileSync(path.join(here, 'fixtures', 'production-sdk-rules.json'), 'utf8'));
const recorded = id => RULES.profiles[0].rows.find(r => r.id === id);
const HEADERS = n => ({ 'content-type': 'application/json; charset=utf-8', 'content-length': String(n), 'cache-control': 'no-cache', 'access-control-allow-origin': '*' });

/** A row of the table answered with a recorded production body: `shape` picks which. */
function row(spec, shape) {
  const base = { id: spec.id, doc: spec.doc, identity: spec.identity };
  if (shape === 'not-loaded') return { ...base, ok: true, outcome: 'not-loaded' };
  const source = { 'load-accepted': recorded('lex-feff'), 'load-refused': recorded('load-paren'), allowed: recorded('tok-admin-allow'), denied: recorded('tok-admin-deny'), 'index-required': recorded('ix-c') }[shape];
  const body = spec.id.startsWith('load-') ? JSON.stringify(syntaxRules(PREFIX, spec.doc)) : (spec.body ?? null);
  return { ...base, ok: true, outcome: 'answered', method: spec.method, path: spec.path, query: spec.query, requestBody: body, status: source.status, body: source.body, bodyBytes: source.bodyBytes, utf8: true, clipped: false, responseHeaders: { ...source.responseHeaders } };
}
/** A complete reduced run: every document `load` (accepted or refused), every case of an accepted document `caseShape(spec)`. */
function run({ load = () => 'load-accepted', caseShape = () => 'allowed', tweak = r => r } = {}) {
  const profiles = RULES_SYNTAX_PROFILES.map(name => {
    let accepted = null;
    const rows = TABLE.map(spec => {
      if (spec.id === 'seed') return tweak(row(spec, 'allowed'), name);
      if (spec.id.startsWith('load-')) { const s = load(spec.doc); accepted = s === 'load-accepted' ? spec.doc : null; return tweak(row(spec, s), name); }
      return tweak(row(spec, accepted === spec.doc ? caseShape(spec) : 'not-loaded'), name);
    });
    return { name, rows, probes: {} };
  });
  return { kind: KIND, suite: 'rules-syntax', prefix: PREFIX, result: { status: 'complete', observed: caseCount(), exit: 0, cleanup: { prefix: 'verified', rules: 'verified' }, unverified: [] }, faults: [], profiles };
}

test('the recorded production shapes classify as recorded, with the byte counts production sent', () => {
  assert.equal(shapeOf({ ...recorded('lex-feff'), id: 'load-eb' }), 'load-accepted');
  assert.equal(shapeOf({ ...recorded('load-paren'), id: 'load-eb' }), 'load-refused');
  assert.equal(shapeOf({ ...recorded('load-long'), id: 'load-eb' }), 'load-refused');
  assert.equal(shapeOf(recorded('tok-admin-allow')), 'allowed');
  assert.equal(shapeOf(recorded('wv-allow')), 'allowed');
  assert.equal(shapeOf(recorded('tok-admin-deny')), 'denied');
  assert.equal(shapeOf(recorded('ix-c')), 'index-required');
  assert.equal(recorded('tok-admin-deny').body, DENIED_BODY); assert.equal(recorded('lex-feff').body, ACCEPTED_BODY);
  assert.equal(recorded('tok-admin-deny').bodyBytes, RECORDED_SHAPES.denied.bodyBytes); assert.equal(recorded('lex-feff').bodyBytes, RECORDED_SHAPES['load-accepted'].bodyBytes);
  // every answered recorded row with the four JSON headers is a recorded shape (cw-etag carries an ETag header: unknown here)
  for (const r of RULES.profiles.flatMap(p => p.rows)) if (r.ok) assert.equal(shapeOf({ ...r, id: r.id.startsWith('load-') || r.id.startsWith('lex-') ? `load-${r.id}` : r.id }) === 'unknown', r.id === 'cw-etag', r.id);
});

test('near misses are unknown: other statuses, byte counts, headers, bodies, clipped, unreadable, not answered', () => {
  const deny = recorded('tok-admin-deny'), ok = { ...recorded('lex-feff'), id: 'load-eb' };
  const unknown = [
    { ...deny, status: 403 }, { ...deny, status: 429 }, { ...deny, status: 500 }, { ...deny, bodyBytes: 35 }, { ...deny, body: deny.body.replace('denied', 'Denied') },
    { ...deny, responseHeaders: { ...deny.responseHeaders, 'content-length': '37' } }, { ...deny, responseHeaders: { ...deny.responseHeaders, 'content-type': 'application/json' } },
    { ...deny, responseHeaders: { ...deny.responseHeaders, etag: 'x' } }, { ...deny, responseHeaders: {} }, { ...deny, responseHeaders: undefined },
    { ...deny, clipped: true }, { ...deny, utf8: false }, { ...deny, ok: false }, { ...deny, outcome: 'unknown-status' }, { ...deny, status: undefined },
    { ...ok, body: '{"status":"OK"}' }, { ...ok, status: 201 }, { ...ok, bodyBytes: 16, responseHeaders: HEADERS(16) }, { ...recorded('tok-admin-allow'), status: 204 }, { ...recorded('tok-admin-allow'), status: 201 }, { ...ok, id: 'load-eb', status: 400, body: 'x' }, { ...ok, status: 401 },
    { ...recorded('ix-c'), body: recorded('ix-c').body.replace('Index', 'index') }, { id: 'x', ok: true, outcome: 'not-loaded', status: 200 }, null,
  ];
  for (const [i, r] of unknown.entries()) assert.equal(shapeOf(r), 'unknown', `near miss ${i}`);
  assert.equal(shapeOf({ id: 'eb-allow', ok: true, outcome: 'not-loaded' }), 'not-loaded');
  assert.equal(jsonHeaders(HEADERS(3), 3), true); assert.equal(jsonHeaders(HEADERS(3), 4), false);
});

test('property: any change to the status or byte count of a recorded denial is unknown or another recorded class, never denied', () => {
  const deny = recorded('tok-admin-deny');
  for (let status = 100; status < 600; status++) {
    const s = shapeOf({ ...deny, status });
    if (status === 401) assert.equal(s, 'denied'); else assert.ok(s === 'unknown' || s === 'allowed', `${status} ${s}`);
    if (status === 200) assert.equal(s, 'allowed');
  }
  for (let n = 0; n < 80; n++) if (n !== 36) assert.equal(shapeOf({ ...deny, bodyBytes: n, responseHeaders: HEADERS(n) }), 'unknown', String(n));
});

test('the jar pattern against fireemu today: refused documents and their not-loaded cases are MISMATCH, equal answers MATCH', () => {
  const jar = run({ caseShape: spec => (/deny/.test(spec.id) ? 'denied' : 'allowed') });
  const fe = run({ load: doc => (doc === 'mnc' || doc === 'mnt' ? 'load-accepted' : 'load-refused'), caseShape: spec => (/deny/.test(spec.id) ? 'denied' : 'allowed') });
  const s = summarize(jar, fe);
  assert.deepEqual(s.problems, []);
  assert.equal(s.counts.NEEDS_REVIEW, 0);
  assert.equal(s.counts.MATCH, 2 * (1 + 2 + 4 + 2)); // the seed, two loads and the mnc and mnt cases in each round
  assert.equal(s.counts.MISMATCH, caseCount() - s.counts.MATCH);
  assert.deepEqual(s.documents.find(d => d.doc === 'eb'), { doc: 'eb', construct: 'query.endBefore', production: ['load-accepted', 'load-accepted'], local: ['load-refused', 'load-refused'] });
  assert.equal(summarize(jar, jar).match, true);
});

test('an unknown production answer and differing production rounds are NEEDS_REVIEW, never MATCH', () => {
  const base = run();
  const odd = run({ tweak: (r, p) => (r.id === 'eb-allow' && p === 'r2-rules-syntax' ? { ...r, status: 403 } : r) });
  let s = summarize(odd, base);
  assert.deepEqual(s.rows.filter(r => r.verdict !== 'MATCH').map(r => [r.profile, r.case, r.verdict]), [['r1-rules-syntax', 'eb-allow', 'NEEDS_REVIEW'], ['r2-rules-syntax', 'eb-allow', 'NEEDS_REVIEW']]);
  assert.equal(s.counts.MISMATCH, 0); assert.equal(s.match, false, 'a NEEDS_REVIEW case is not a match');
  const differ = run({ tweak: (r, p) => (r.id === 'obk-plain' && p === 'r2-rules-syntax' ? row(TABLE.find(t => t.id === 'obk-plain'), 'denied') : r) });
  s = summarize(differ, base);
  assert.deepEqual(s.rows.filter(r => r.verdict !== 'MATCH').map(r => [r.case, r.verdict, r.reason]), [['obk-plain', 'NEEDS_REVIEW', 'production rounds differ'], ['obk-plain', 'NEEDS_REVIEW', 'production rounds differ']]);
  const localOdd = run({ tweak: r => (r.id === 'enc-write' ? { ...r, clipped: true } : r) });
  s = summarize(base, localOdd);
  assert.deepEqual(s.rows.filter(r => r.verdict !== 'MATCH').map(r => [r.case, r.verdict]), [['enc-write', 'NEEDS_REVIEW'], ['enc-write', 'NEEDS_REVIEW']]);
});

test('a row whose request is not the table one is NEEDS_REVIEW; a load body for another prefix too', () => {
  const base = run();
  const s = summarize(run({ tweak: r => (r.id === 'load-obv' ? { ...r, requestBody: JSON.stringify(syntaxRules('/other', 'obv')) } : r.id === 'ioc-allow' ? { ...r, query: '' } : r) }), base);
  assert.deepEqual([...new Set(s.rows.filter(r => r.verdict !== 'MATCH').map(r => `${r.case}:${r.verdict}:${r.reason}`))], ['ioc-allow:NEEDS_REVIEW:request differs from the table', 'load-obv:NEEDS_REVIEW:request differs from the table']);
});

test('MISMATCH needs a recorded shape on both sides and agreeing rounds; the body bytes and headers count', () => {
  const base = run({ caseShape: () => 'denied' });
  const other = run({ caseShape: () => 'denied', tweak: r => (r.id === 'tcl-deny' ? { ...r, ...{ status: 200, body: '1', bodyBytes: 1, responseHeaders: HEADERS(1) } } : r) });
  const s = summarize(base, other);
  assert.deepEqual(s.rows.filter(r => r.verdict !== 'MATCH').map(r => [r.case, r.verdict, r.reason]), [['tcl-deny', 'MISMATCH', 'production denied 401, local allowed 200'], ['tcl-deny', 'MISMATCH', 'production denied 401, local allowed 200']]);
  const longer = run({ tweak: r => (r.id === 'seed' ? { ...r, body: `${r.body} `, bodyBytes: r.bodyBytes + 1, responseHeaders: HEADERS(r.bodyBytes + 1) } : r) });
  assert.equal(summarize(run(), longer).rows.filter(r => r.verdict === 'MISMATCH').length, 2);
  const bytes = run({ tweak: r => (r.id === 'seed' ? { ...r, bodyBytes: r.bodyBytes + 1, responseHeaders: HEADERS(r.bodyBytes + 1) } : r) });
  assert.equal(summarize(run(), bytes).rows.filter(r => r.verdict === 'MISMATCH').length, 2, 'the byte count is judged, not only the stored text');
});

test('an incomplete, unverified or faulted run, another prefix or a missing case is a problem, nothing is judged', () => {
  const ok = run();
  const bad = [
    d => { d.result.status = 'incomplete'; }, d => { d.result.exit = 1; }, d => { d.result.observed = 85; }, d => { d.result.cleanup.prefix = 'unverified'; }, d => { d.result.cleanup.rules = 'unverified'; },
    d => { d.result.unverified = ['cleanup']; }, d => { d.faults = [{ kind: 'abort' }]; }, d => { d.prefix = '/other'; }, d => { d.kind = 'x'; }, d => { d.suite = 'rules'; },
    d => { d.profiles.reverse(); }, d => { d.profiles[0].rows.pop(); },
  ];
  for (const [i, change] of bad.entries()) {
    for (const side of [0, 1]) {
      const docs = [structuredClone(ok), structuredClone(ok)]; change(docs[side]);
      const s = summarize(docs[0], docs[1]);
      assert.equal(s.match, false, `${i}/${side}`); assert.equal(s.rows.length, 0, `${i}/${side}`); assert.ok(s.problems.length, `${i}/${side}`);
    }
  }
});

// ---- reduction and local entry ----------------------------------------------------------------------------------------------------------------
const RESULT = { runId: 'LOCAL-X', suite: 'rules-syntax', target: 'emulator', prefix: PREFIX, status: 'complete', observed: caseCount(), exit: 0, cleanup: { prefix: 'verified', rules: 'verified' }, unverified: [], counts: { direct: 38, reserve: 4, adc: 0 } };
function rawRows(doc) {
  const out = [{ kind: 'admin-req', label: 'rules-before' }];
  for (const p of doc.profiles) for (const r of p.rows) out.push({ t: 'x', kind: 'case', suite: 'rules-syntax', ...r, profile: p.name });
  out.push({ kind: 'probe', suite: 'rules-syntax', profile: RULES_SYNTAX_PROFILES[0], after: 'eb', attempt: 1, outcome: 'answered', status: 200, ready: true });
  return [...out, { kind: 'result' }];
}

test('the reduction keeps the table fields and the probes per document, and refuses unknown rows', () => {
  const doc = run(), reduced = reduceRulesSyntaxJournal(rawRows(doc), RESULT);
  assert.deepEqual(reduced.profiles[0].rows, doc.profiles[0].rows);
  assert.deepEqual(reduced.profiles[0].probes, { eb: [200] });
  assert.equal(reduced.prefix, PREFIX);
  assert.throws(() => reduceRulesSyntaxJournal([{ kind: 'case', suite: 'rules-syntax', profile: 'r1-rules-syntax', id: 'zz', ok: true }], RESULT), /unknown case row/);
  assert.throws(() => reduceRulesSyntaxJournal([{ kind: 'case', suite: 'rules-syntax', profile: 'r1-rules-syntax', id: 'eb-allow', ok: true, extra: 1 }], RESULT), /unrecorded fields/);
  assert.throws(() => reduceRulesSyntaxJournal([{ kind: 'case', suite: 'rules', profile: 'r1-rules-syntax', id: 'eb-allow', ok: true }], RESULT), /suite rules/);
  assert.throws(() => reduceRulesSyntaxJournal([{ kind: 'mystery' }], RESULT), /unknown journal row kind/);
  assert.throws(() => reduceRulesSyntaxJournal([], { ...RESULT, suite: 'rules-load' }), /not the rules-syntax suite/);
  assert.deepEqual(reduceRulesSyntaxJournal([{ kind: 'abort', reason: 'x' }], RESULT).faults, [{ kind: 'abort', profile: null }]);
});

test('the production fixture needs the provenance, one ADC, no overflow and no unverified write', () => {
  const doc = run(), meta = { recordedOn: '2026-11-09', bookingRow: 1, closeRow: 2, approvals: [1, 2], requests: 42, packetSha256: 'a'.repeat(64), sourceHead: 'b'.repeat(40), journalSha256: 'c'.repeat(64), resultSha256: 'd'.repeat(64) };
  const prod = { ...RESULT, target: 'production', counts: { direct: 38, reserve: 4, adc: 1 } };
  const fixture = buildRulesSyntaxFixture(rawRows(doc), prod, meta);
  assert.equal(fixture.provenance.suite, 'rules-syntax'); assert.deepEqual(Object.keys(fixture.provenance.caseSources), ['rules-syntax-suite.mjs']);
  assert.deepEqual(recordedJournal(fixture).profiles, reduceRulesSyntaxJournal(rawRows(doc), prod).profiles);
  assert.throws(() => buildRulesSyntaxFixture(rawRows(doc), RESULT, meta), /production run only/);
  assert.ok(buildRulesSyntaxFixture(rawRows(doc), prod, { ...meta, journalSha256: `${'1'.repeat(12)}${'a'.repeat(52)}` }), 'a digest with twelve decimal digits is not a project number');
  const leaky = run({ tweak: r => (r.id === 'seed' ? { ...r, body: '{"n":123456789012}' } : r) });
  assert.throws(() => buildRulesSyntaxFixture(rawRows(leaky), prod, meta), /12-digit number/);
  assert.throws(() => buildRulesSyntaxFixture(rawRows(doc), prod, { ...meta, sourceHead: `x${'1'.repeat(12)}` }), /12-digit number/);
  assert.throws(() => buildRulesSyntaxFixture(rawRows(doc), { ...prod, counts: { direct: 38, reserve: 4, adc: 2 } }, meta), /exactly one ADC/);
  assert.throws(() => buildRulesSyntaxFixture(rawRows(doc), { ...prod, counts: { direct: 38, reserve: 4, adc: 1, overflow: 1 } }, meta), /overflow/);
  assert.throws(() => buildRulesSyntaxFixture(rawRows(doc), { ...prod, unverified: ['x'] }, meta), /unverified/);
  assert.throws(() => buildRulesSyntaxFixture(rawRows(doc), prod, { ...meta, requests: 41 }), /ledger's 41/);
  assert.throws(() => buildRulesSyntaxFixture(rawRows(doc), prod, { ...meta, closeRow: undefined }), /missing closeRow/);
});

test('the exec plan runs the observer rules-syntax suite on the production prefix with cap 160; finish writes once', () => {
  assert.equal(daemonConfig('strict').profile, 'strict'); assert.throws(() => daemonConfig('x'));
  const plan = execPlan('/bin/fireemu', '/out/config.json', '/out/observer', 'LOCAL-SDK-RULES-SYNTAX-1'), command = plan.slice(plan.indexOf('--') + 1);
  const arg = n => command[command.indexOf(n) + 1];
  assert.deepEqual([arg('--target'), arg('--suite'), arg('--direct-cap'), arg('--prefix'), arg('--out')], ['emulator', 'rules-syntax', '160', '/sdkrulesyntax', '/out/observer']);
  assert.equal(LOCAL_DIRECT_CAP, 160); assert.equal(localPrefix(), PREFIX);
  const dir = mkdtempSync(path.join(tmpdir(), 'syntax-finish-'));
  try {
    mkdirSync(path.join(dir, 'observer'));
    const doc = run();
    writeFileSync(path.join(dir, 'observer', 'journal.jsonl'), rawRows(doc).map(r => JSON.stringify(r)).join('\n') + '\n');
    writeFileSync(path.join(dir, 'observer', 'result.json'), JSON.stringify(RESULT));
    const s = finish(dir, reduceRulesSyntaxJournal(rawRows(doc), RESULT));
    assert.equal(s.match, true, JSON.stringify(s.problems));
    assert.throws(() => finish(dir), /EEXIST/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  assert.equal(DOCUMENTS.length, 9);
});

// ---- the production recording (RTDB-RULES-SYNTAX-20261108-01) --------------------------------------------------------------------------------
const PRODUCTION = recordedJournal(JSON.parse(readFileSync(path.join(here, 'fixtures', 'production-sdk-rules-syntax.json'), 'utf8')));
const JAR = JSON.parse(readFileSync(path.join(here, 'fixtures', 'jar-sdk-rules-syntax.json'), 'utf8'));

test('the production reduction: a clean run, nine documents loaded in both rounds, the rounds agree, every answer a recorded shape', () => {
  assert.deepEqual(PRODUCTION.result, { status: 'complete', observed: 86, exit: 0, cleanup: { prefix: 'verified', rules: 'verified' }, unverified: [] });
  assert.equal(PRODUCTION.prefix, PREFIX);
  for (const p of PRODUCTION.profiles) {
    assert.deepEqual(p.rows.filter(r => r.id.startsWith('load-')).map(r => [r.id, r.status]), DOCUMENTS.map(d => [`load-${d.id}`, 200]));
    for (const r of p.rows) assert.notEqual(shapeOf(r), 'unknown', r.id);
    assert.deepEqual(Object.values(p.probes), DOCUMENTS.map(() => [200]));
  }
  assert.deepEqual(PRODUCTION.profiles[0].rows, PRODUCTION.profiles[1].rows, 'two rounds agree');
});

test('production answered every row as the official emulator 4.11.2 did', () => {
  const s = summarize(PRODUCTION, JAR);
  assert.deepEqual(s.problems, []); assert.deepEqual(s.counts, { MATCH: 86, MISMATCH: 0, NEEDS_REVIEW: 0 }); assert.equal(s.match, true);
});

test('live: both profiles on a real fireemu (FIREEMU_BIN) match the production reduction in all 86 rows', { skip: !process.env.FIREEMU_BIN, timeout: 10 * 60 * 1000 }, async () => {
  const { spawnSync } = await import('node:child_process');
  const dir = mkdtempSync(path.join(tmpdir(), 'sdk-rules-syntax-live-'));
  try {
    for (const profile of ['strict', 'emulator']) {
      const out = path.join(dir, profile);
      const r = spawnSync(process.execPath, [path.join(here, 'rtdb-sdk-rules-syntax.mjs'), 'local', '--fireemu', process.env.FIREEMU_BIN, '--out', out, '--profile', profile, '--against', path.join(here, 'fixtures', 'production-sdk-rules-syntax.json')], { encoding: 'utf8', timeout: 5 * 60 * 1000 });
      assert.equal(r.status, 0, `${profile}: ${r.stdout}${r.stderr}`);
      const comparison = JSON.parse(readFileSync(path.join(out, 'comparison.json'), 'utf8'));
      assert.deepEqual(comparison.counts, { MATCH: 86, MISMATCH: 0, NEEDS_REVIEW: 0 }, profile);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
