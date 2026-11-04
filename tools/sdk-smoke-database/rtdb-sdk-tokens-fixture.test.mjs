// node --test rtdb-sdk-tokens-fixture.test.mjs: the reduced journal of the tokens suite (G10) and its production fixture.
import test from 'node:test';
import assert from 'node:assert/strict';

import { CASE_SOURCES, KIND, buildTokensFixture, recordedJournal, reduceTokensJournal } from './rtdb-sdk-tokens-fixture.mjs';
import { TABLE, TOKENS_CASES, TOKENS_PROFILES } from './sdk-observer/tokens-suite.mjs';

const RESULT = { runId: 'LOCAL-X', suite: 'tokens', target: 'emulator', prefix: '/sdktokens01234567', status: 'complete', observed: 54, exit: 0, cleanup: { prefix: 'verified', rules: 'verified' }, unverified: [], counts: { direct: 60, reserve: 4, adc: 0 } };
const caseRow = (profile, spec) => ({ t: '2026-11-05T00:00:00.000Z', kind: 'case', suite: 'tokens', id: spec.id, group: spec.group, identity: spec.identity, ok: true, outcome: 'answered', method: spec.method, path: `{scope}${spec.path}`, query: spec.query, requestHeaders: spec.headers ?? {}, requestBody: spec.body ?? null, status: 401, responseHeaders: { 'content-type': 'application/json; charset=utf-8' }, body: '{\n  "error" : "Permission denied"\n}\n', bodyBytes: 35, utf8: true, clipped: false, profile });
const probe = (profile, attempt, ready) => ({ kind: 'probe', suite: 'tokens', profile, after: 'start', attempt, outcome: 'answered', status: ready ? 200 : 401, ready });
const raw = () => [{ kind: 'admin-req', label: 'rules-before' }, { kind: 'admin-res', label: 'rules-before' }, ...TOKENS_PROFILES.flatMap(p => [probe(p, 1, false), probe(p, 2, true), ...TABLE.map(s => caseRow(p, s))]), { kind: 'result' }];

test('reduce: per profile the case rows in journal order without kind/suite/profile/t, the probes grouped, the prefix length', () => {
  const d = reduceTokensJournal(raw(), RESULT);
  assert.equal(d.kind, KIND); assert.equal(KIND, 'rtdb-sdk-tokens-journal-v1'); assert.equal(d.suite, 'tokens');
  assert.deepEqual(d.result, { status: 'complete', observed: 54, exit: 0, cleanup: { prefix: 'verified', rules: 'verified' }, unverified: [], prefixLength: 18 });
  assert.deepEqual(d.faults, []);
  assert.deepEqual(d.profiles.map(p => p.name), TOKENS_PROFILES);
  for (const p of d.profiles) {
    assert.deepEqual(Object.keys(p), ['name', 'rows', 'probes']);
    assert.deepEqual(p.rows.map(r => r.id), TOKENS_CASES);
    assert.deepEqual(p.probes, [{ after: 'start', attempts: 2, ready: true, outcome: 'answered' }]);
    for (const r of p.rows) for (const k of ['t', 'kind', 'suite', 'profile']) assert.equal(Object.hasOwn(r, k), false, k);
  }
  const faulted = reduceTokensJournal([...raw(), { kind: 'abort', reason: 'x' }, { kind: 'profile-error', profile: 'r2-tokens' }], { ...RESULT, unverified: 'x' });
  assert.deepEqual(faulted.faults, [{ kind: 'abort', profile: null }, { kind: 'profile-error', profile: 'r2-tokens' }]);
  assert.deepEqual(faulted.result.unverified, ['result.json has no unverified list']);
});
test('reduce: refuses a row it cannot place', () => {
  const bad = [
    [rows => rows.push({ kind: 'mystery' }), /unknown journal row kind/],
    [rows => rows.push({ ...caseRow('r9-tokens', TABLE[1]) }), /unknown profile/],
    [rows => rows.push({ ...caseRow('r1-tokens', TABLE[1]), suite: 'rules' }), /suite rules/],
    [rows => rows.push({ ...caseRow('r1-tokens', TABLE[1]), id: 'nope' }), /unknown case row/],
    [rows => rows.push({ ...caseRow('r1-tokens', TABLE[1]), extra: 1 }), /unrecorded fields extra/],
    [rows => rows.push({ ...caseRow('r1-tokens', TABLE[1]), ok: 'yes' }), /unknown case row/],
    [rows => rows.push(probe('r1-tokens', 3, true)), /probe attempts out of order/],
    [rows => rows.push({ ...probe('r1-tokens', 1, true), after: 'lex-feff' }), /unknown probe row/],
    [rows => rows.push({ kind: 'install', suite: 'tokens', profile: 'r1-tokens', after: 'x', ok: true }), /unknown journal row kind install/],
    [rows => rows.push([]), /not an object/],
  ];
  for (const [change, re] of bad) { const rows = raw(); change(rows); assert.throws(() => reduceTokensJournal(rows, RESULT), re, String(re)); }
  const skipped = raw().filter(r => !(r.kind === 'probe' && r.attempt === 1 && r.profile === 'r1-tokens'));
  assert.throws(() => reduceTokensJournal(skipped, RESULT), /probe attempts out of order/);
  assert.throws(() => reduceTokensJournal(raw(), { ...RESULT, suite: 'rules' }), /not the tokens suite/);
  assert.throws(() => reduceTokensJournal(raw(), { ...RESULT, prefix: undefined }), /no prefix/);
  assert.throws(() => reduceTokensJournal('x', RESULT), /must be an array/);
  assert.throws(() => reduceTokensJournal(raw(), null), /result.json is missing/);
});
test('build: only a production run with one ADC token, no overflow, no unknown outcome and the ledger\'s request count; every provenance field required; publishable only', () => {
  const prod = { ...RESULT, runId: 'RTDB-TOKENS-20261105-01', target: 'production', scriptSha256: 'a'.repeat(64), startedAt: 's', endedAt: 'e', caps: { direct: 80, reserve: 12, adc: 1 }, counts: { direct: 62, reserve: 4, adc: 1 } };
  const meta = { recordedOn: '2026-11-05', bookingRow: 1, closeRow: 2, approvals: [3], requests: 66, packetSha256: 'b'.repeat(64), sourceHead: 'c'.repeat(40), journalSha256: 'd'.repeat(64), resultSha256: 'e'.repeat(64) };
  const doc = buildTokensFixture(raw(), prod, meta);
  assert.equal(doc.provenance.suite, 'tokens'); assert.deepEqual(doc.provenance.counts, { requests: 66, direct: 62, reserve: 4, adc: 1, overflow: 0 });
  assert.deepEqual(Object.keys(doc.provenance.caseSources), CASE_SOURCES); assert.deepEqual(CASE_SOURCES, ['tokens-suite.mjs']);
  assert.match(doc.provenance.caseSources['tokens-suite.mjs'], /^[0-9a-f]{64}$/);
  assert.deepEqual(recordedJournal(doc), reduceTokensJournal(raw(), prod));
  assert.throws(() => buildTokensFixture(raw(), { ...prod, target: 'emulator' }, meta), /production run only/);
  for (const field of Object.keys(meta)) assert.throws(() => buildTokensFixture(raw(), prod, { ...meta, [field]: undefined }), new RegExp(`missing ${field}`));
  assert.throws(() => buildTokensFixture(raw(), prod, { ...meta, requests: 65 }), /not the ledger's 65/);
  assert.throws(() => buildTokensFixture(raw(), { ...prod, counts: { ...prod.counts, adc: 2 } }, meta), /exactly one ADC/);
  assert.throws(() => buildTokensFixture(raw(), { ...prod, counts: { ...prod.counts, overflow: 1 } }, meta), /overflow/);
  assert.throws(() => buildTokensFixture(raw(), { ...prod, unverified: ['x'] }, meta), /unverified/);
  const leaky = raw(); leaky[4].body = '{"n":"123456789012"}';
  assert.throws(() => buildTokensFixture(leaky, prod, meta));
  assert.throws(() => recordedJournal({ ...doc, provenance: { target: 'emulator' } }), /production run/);
  assert.throws(() => recordedJournal([]), /not a reduced/);
});
