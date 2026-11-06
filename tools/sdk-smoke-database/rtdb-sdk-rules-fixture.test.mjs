// node --test rtdb-sdk-rules-fixture.test.mjs: the reduced journal of the rules suite (G8) and the production fixture builder.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { CASE_SOURCES, KIND, buildRulesFixture, recordedJournal, reduceRulesJournal } from './rtdb-sdk-rules-fixture.mjs';

// A real local reduction (fireemu v0.43.0, strict, suite rules).
const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/local-sdk-rules.json', import.meta.url), 'utf8'));
const RESULT = { runId: 'LOCAL-X', suite: 'rules', target: 'emulator', prefix: '/sdkrules01234567', ...FIXTURE.result, counts: { direct: 162, reserve: 4, adc: 0 } };
delete RESULT.prefixLength;
const seeded = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
/** The observer journal rows a reduced record came from, in the order the runner writes them, with dropped rows between them. */
function rawRows(doc) {
  const out = [{ kind: 'admin-req', label: 'rules-before', method: 'GET' }, { kind: 'admin-res', label: 'rules-before', status: 200 }];
  for (const p of doc.profiles) {
    const probeRows = after => { const x = p.probes.find(q => q.after === after); return Array.from({ length: x.attempts }, (_, i) => ({ kind: 'probe', suite: 'rules', profile: p.name, after, attempt: i + 1, outcome: x.outcome, ready: i + 1 === x.attempts ? x.ready : false })); };
    out.push(...probeRows('start'));
    for (const r of p.rows) {
      out.push({ kind: 'admin-req', label: r.id }, { t: '2026-11-05T00:00:00.000Z', kind: 'case', suite: 'rules', ...r, profile: p.name });
      const install = p.installs.find(i => i.after === r.id);
      if (install) out.push({ kind: 'install', suite: 'rules', profile: p.name, ...install }, ...probeRows(r.id));
    }
  }
  return [...out, { kind: 'result' }];
}

test('the local fixture: 2 x 70 case rows, four reinstalls and five ready probes per profile, the 17-character prefix', () => {
  assert.equal(FIXTURE.kind, KIND); assert.equal(FIXTURE.result.prefixLength, 17);
  for (const p of FIXTURE.profiles) {
    assert.equal(p.rows.length, 70);
    assert.deepEqual(p.installs.map(i => i.after), ['lex-feff', 'lex-nel', 'lex-lazy', 'lex-number']);
    assert.deepEqual(p.probes.map(x => [x.after, x.attempts, x.ready]), [['start', 1, true], ['lex-feff', 1, true], ['lex-nel', 1, true], ['lex-lazy', 1, true], ['lex-number', 1, true]]);
  }
});
test('the reduction of the observer rows is the recorded reduction; admin rows and timestamps are dropped', () => {
  assert.deepEqual(reduceRulesJournal(rawRows(FIXTURE), RESULT), FIXTURE);
});
test('property: interleaving any number of dropped rows anywhere does not change the reduction (seeded)', () => {
  const rand = seeded(7), base = rawRows(FIXTURE), dropped = [{ kind: 'admin-req', label: 'x' }, { kind: 'admin-res', label: 'x', status: 200 }, { kind: 'admin-unknown', label: 'x' }, { kind: 'cleanup' }];
  for (let n = 0; n < 50; n++) {
    const rows = [...base];
    for (let k = 0; k < 20; k++) rows.splice(Math.floor(rand() * (rows.length + 1)), 0, dropped[Math.floor(rand() * dropped.length)]);
    assert.deepEqual(reduceRulesJournal(rows, RESULT), FIXTURE);
  }
});
test('probes: repeated attempts of one install collapse into one entry with the attempt count and the last answer', () => {
  const p = 'r1-rules', probe = (after, attempt, ready) => ({ kind: 'probe', suite: 'rules', profile: p, after, attempt, outcome: 'answered', ready });
  const d = reduceRulesJournal([probe('start', 1, false), probe('start', 2, false), probe('start', 3, true), { kind: 'install', suite: 'rules', profile: p, after: 'lex-nel', ok: true, outcome: 'answered', status: 200 }, probe('lex-nel', 1, false)], RESULT);
  assert.deepEqual(d.profiles[0].probes, [{ after: 'start', attempts: 3, ready: true, outcome: 'answered' }, { after: 'lex-nel', attempts: 1, ready: false, outcome: 'answered' }]);
  assert.deepEqual(d.profiles[0].installs, [{ after: 'lex-nel', ok: true, outcome: 'answered', status: 200 }]);
  for (const rows of [[probe('start', 2, false)], [probe('start', 1, false), probe('start', 3, true)], [probe('start', 1, true), probe('start', 2, true)]]) assert.throws(() => reduceRulesJournal(rows, RESULT), /out of order/);
});
test('the reducer refuses what it cannot place: unknown row kind, profile, case id, field, suite, probe or install anchor; a result of another suite or without a prefix', () => {
  const caseRow = { kind: 'case', suite: 'rules', profile: 'r1-rules', id: 'seed', ok: true };
  const bad = [
    [[{ kind: 'raw-ws' }], RESULT, /unknown journal row kind raw-ws/],
    [[{ ...caseRow, profile: 'r3-rules' }], RESULT, /unknown profile r3-rules/],
    [[{ ...caseRow, id: 'end-get' }], RESULT, /unknown case row end-get/],
    [[{ ...caseRow, ok: 'yes' }], RESULT, /unknown case row/],
    [[{ ...caseRow, secret: 'x' }], RESULT, /unrecorded fields secret/],
    [[{ ...caseRow, suite: 'rest' }], RESULT, /case row of suite rest/],
    [[{ kind: 'probe', suite: 'rules', profile: 'r1-rules', after: 'tok-admin-allow', attempt: 1, ready: true }], RESULT, /unknown probe row/],
    [[{ kind: 'probe', suite: 'rules', profile: 'r1-rules', after: 'start', attempt: 0, ready: true }], RESULT, /unknown probe row/],
    [[{ kind: 'probe', suite: 'rules', profile: 'r1-rules', after: 'start', attempt: 1, ready: 'y' }], RESULT, /unknown probe row/],
    [[{ kind: 'probe', suite: 'rest', profile: 'r1-rules', after: 'start', attempt: 1, ready: true }], RESULT, /probe row of suite rest/],
    [[{ kind: 'install', suite: 'rules', profile: 'r1-rules', after: 'start', ok: true }], RESULT, /unknown install row/],
    [[{ kind: 'install', suite: 'rules', profile: 'r1-rules', after: 'lex-nel', ok: 1 }], RESULT, /unknown install row/],
    [[{ kind: 'install', suite: 'rules', profile: 'r9-rules', after: 'lex-nel', ok: true }], RESULT, /unknown profile r9-rules/],
    [[null], RESULT, /not an object/],
    [[], { ...RESULT, suite: 'rest' }, /not the rules suite/],
    [[], { ...RESULT, prefix: undefined }, /no prefix/],
    [[], null, /result.json is missing/],
    ['x', RESULT, /must be an array/],
  ];
  for (const [rows, result, message] of bad) assert.throws(() => reduceRulesJournal(rows, result), message);
});
test('faults are kept with their profile, and unverified (unknown) outcomes are carried into the reduction', () => {
  const d = reduceRulesJournal([{ kind: 'abort', reason: 'x' }, { kind: 'profile-error', profile: 'r2-rules' }], { ...RESULT, unverified: ['unknown REST mutation outcome: r1-rules/install-lex-nel'] });
  assert.deepEqual(d.faults, [{ kind: 'abort', profile: null }, { kind: 'profile-error', profile: 'r2-rules' }]);
  assert.deepEqual(d.result.unverified, ['unknown REST mutation outcome: r1-rules/install-lex-nel']);
  assert.deepEqual(reduceRulesJournal([], { ...RESULT, unverified: undefined }).result.unverified, ['result.json has no unverified list']);
});

const sha = b => createHash('sha256').update(b).digest('hex');
const META = { recordedOn: '2026-11-05', bookingRow: 1, closeRow: 2, approvals: [3, 4], requests: 172, packetSha256: 'a'.repeat(64), sourceHead: 'b'.repeat(40), journalSha256: 'c'.repeat(64), resultSha256: 'd'.repeat(64) };
const PRODUCTION = { ...RESULT, runId: 'RTDB-RULES-20261105-01', target: 'production', unverified: [], counts: { direct: 168, reserve: 4, adc: 1, overflow: 0 }, caps: { direct: 210, reserve: 12, adc: 1 }, scriptSha256: 'e'.repeat(64) };
test('the production fixture: the reduction plus provenance, the case code pinned', () => {
  const doc = buildRulesFixture(rawRows(FIXTURE), PRODUCTION, META);
  assert.deepEqual(recordedJournal(doc), FIXTURE);
  assert.deepEqual(doc.provenance.caseSources, Object.fromEntries(CASE_SOURCES.map(n => [n, sha(readFileSync(new URL(`./sdk-observer/${n}`, import.meta.url)))])));
  assert.deepEqual(CASE_SOURCES, ['rules-suite.mjs']);
  assert.deepEqual(doc.provenance.counts, { requests: 172, direct: 168, reserve: 4, adc: 1, overflow: 0 });
  assert.deepEqual([doc.provenance.runId, doc.provenance.suite, doc.provenance.target], ['RTDB-RULES-20261105-01', 'rules', 'production']);
});
test('the fixture builder refuses a local run, missing provenance, a request count off the ledger, another ADC count, overflow, unknown outcomes and a 12-digit number', () => {
  const bad = [
    [{ ...PRODUCTION, target: 'emulator' }, META, /production run only/],
    [PRODUCTION, { ...META, closeRow: undefined }, /missing closeRow/],
    [PRODUCTION, { ...META, approvals: [] }, /missing approvals/],
    [PRODUCTION, { ...META, requests: 171 }, /not the ledger's 171/],
    [{ ...PRODUCTION, counts: { ...PRODUCTION.counts, adc: 2 } }, META, /exactly one ADC/],
    [{ ...PRODUCTION, counts: { ...PRODUCTION.counts, adc: 0 } }, META, /exactly one ADC/],
    [{ ...PRODUCTION, counts: { ...PRODUCTION.counts, overflow: 1 } }, META, /overflow/],
    [{ ...PRODUCTION, unverified: ['in-flight admin request'] }, META, /unverified/],
    [{ ...PRODUCTION, runId: 'RTDB-RULES-123456789012' }, META, /12-digit/],
  ];
  for (const [result, meta, message] of bad) assert.throws(() => buildRulesFixture(rawRows(FIXTURE), result, meta), message);
});
test('recordedJournal: a plain reduction as it is; a provenance must name a production run', () => {
  assert.equal(recordedJournal(FIXTURE), FIXTURE);
  assert.throws(() => recordedJournal({ ...FIXTURE, provenance: { target: 'emulator' } }), /production run/);
  assert.throws(() => recordedJournal([]), /not a reduced/);
});
