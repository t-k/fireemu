// node --test rtdb-sdk-rest-fixture.test.mjs: the reduced journal of the rest suite (G7) and the production fixture builder.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { CASE_SOURCES, KIND, buildRestFixture, recordedJournal, reduceRestJournal } from './rtdb-sdk-rest-fixture.mjs';

const FIXTURE = JSON.parse(readFileSync(new URL('./fixtures/local-sdk-rest.json', import.meta.url), 'utf8'));
const RESULT = { runId: 'LOCAL-X', suite: 'rest', target: 'emulator', prefix: '/sdkrest01234567', ...FIXTURE.result, counts: { direct: 148, reserve: 4, adc: 0 } };
delete RESULT.prefixLength;
const seeded = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
/** The observer journal rows a reduced record came from, with rows the reducer drops between them. */
const rawRows = doc => [{ kind: 'admin-req', label: 'rules-before', method: 'GET' }, { kind: 'admin-res', label: 'rules-before', status: 200 }, ...doc.profiles.flatMap(p => p.rows.flatMap(r => [{ kind: 'admin-req', label: r.id }, { t: '2026-11-05T00:00:00.000Z', kind: 'case', suite: 'rest', ...r, profile: p.name }])), { kind: 'result' }];

test('the reduction of the observer rows is the recorded reduction; admin rows and timestamps are dropped', () => {
  assert.deepEqual(reduceRestJournal(rawRows(FIXTURE), RESULT), FIXTURE);
  assert.equal(FIXTURE.kind, KIND); assert.equal(FIXTURE.result.prefixLength, 16);
});
test('property: interleaving any number of dropped rows anywhere does not change the reduction (seeded)', () => {
  const rand = seeded(5), base = rawRows(FIXTURE), dropped = [{ kind: 'admin-req', label: 'x' }, { kind: 'admin-res', label: 'x', status: 200 }, { kind: 'admin-unknown', label: 'x' }, { kind: 'cleanup' }];
  for (let n = 0; n < 50; n++) {
    const rows = [...base];
    for (let k = 0; k < 20; k++) rows.splice(Math.floor(rand() * (rows.length + 1)), 0, dropped[Math.floor(rand() * dropped.length)]);
    assert.deepEqual(reduceRestJournal(rows, RESULT), FIXTURE);
  }
});
test('the reducer refuses what it cannot place: unknown row kind, profile, case id, field, suite; a result of another suite or without a prefix', () => {
  const caseRow = { kind: 'case', suite: 'rest', profile: 'r1-rest', id: 'setup-mix', ok: true };
  const bad = [
    [[{ kind: 'raw-ws' }], RESULT, /unknown journal row kind raw-ws/],
    [[{ ...caseRow, profile: 'r3-rest' }], RESULT, /unknown profile r3-rest/],
    [[{ ...caseRow, id: 'end-get' }], RESULT, /unknown case row end-get/],
    [[{ ...caseRow, ok: 'yes' }], RESULT, /unknown case row/],
    [[{ ...caseRow, secret: 'x' }], RESULT, /unrecorded fields secret/],
    [[{ ...caseRow, suite: 'events' }], RESULT, /case row of suite events/],
    [[null], RESULT, /not an object/],
    [[], { ...RESULT, suite: 'events' }, /not the rest suite/],
    [[], { ...RESULT, prefix: undefined }, /no prefix/],
    [[], null, /result.json is missing/],
    ['x', RESULT, /must be an array/],
  ];
  for (const [rows, result, message] of bad) assert.throws(() => reduceRestJournal(rows, result), message);
});
test('faults are kept with their profile, and unverified (unknown) outcomes are carried into the reduction', () => {
  const d = reduceRestJournal([{ kind: 'abort', reason: 'x' }, { kind: 'profile-error', profile: 'r2-rest' }], { ...RESULT, unverified: ['unknown REST mutation outcome: r1-rest/sv-bogus'] });
  assert.deepEqual(d.faults, [{ kind: 'abort', profile: null }, { kind: 'profile-error', profile: 'r2-rest' }]);
  assert.deepEqual(d.result.unverified, ['unknown REST mutation outcome: r1-rest/sv-bogus']);
  assert.deepEqual(reduceRestJournal([], { ...RESULT, unverified: undefined }).result.unverified, ['result.json has no unverified list'], 'a result without the list never reads as clean');
});

const sha = b => createHash('sha256').update(b).digest('hex');
const META = { recordedOn: '2026-11-05', bookingRow: 1, closeRow: 2, approvals: [3, 4], requests: 152, packetSha256: 'a'.repeat(64), sourceHead: 'b'.repeat(40), journalSha256: 'c'.repeat(64), resultSha256: 'd'.repeat(64) };
const PRODUCTION = { ...RESULT, runId: 'RTDB-REST-20261105-01', target: 'production', unverified: [], counts: { direct: 148, reserve: 4, adc: 1, overflow: 0 }, caps: { direct: 190, reserve: 12, adc: 1 }, scriptSha256: 'e'.repeat(64) };
test('the production fixture: the reduction plus provenance, the case code pinned', () => {
  const doc = buildRestFixture(rawRows(FIXTURE), PRODUCTION, META);
  assert.deepEqual(recordedJournal(doc), FIXTURE);
  assert.deepEqual(doc.provenance.caseSources, Object.fromEntries(CASE_SOURCES.map(n => [n, sha(readFileSync(new URL(`./sdk-observer/${n}`, import.meta.url)))])));
  assert.deepEqual(doc.provenance.counts, { requests: 152, direct: 148, reserve: 4, adc: 1, overflow: 0 });
  assert.deepEqual([doc.provenance.runId, doc.provenance.suite, doc.provenance.target], ['RTDB-REST-20261105-01', 'rest', 'production']);
});
test('the fixture builder refuses a local run, missing provenance, a request count off the ledger, another ADC count, overflow, unknown outcomes and a 12-digit number', () => {
  const bad = [
    [{ ...PRODUCTION, target: 'emulator' }, META, /production run only/],
    [PRODUCTION, { ...META, closeRow: undefined }, /missing closeRow/],
    [PRODUCTION, { ...META, approvals: [] }, /missing approvals/],
    [PRODUCTION, { ...META, requests: 151 }, /not the ledger's 151/],
    [{ ...PRODUCTION, counts: { ...PRODUCTION.counts, adc: 2 } }, META, /exactly one ADC/],
    [{ ...PRODUCTION, counts: { ...PRODUCTION.counts, overflow: 1 } }, META, /overflow/],
    [{ ...PRODUCTION, unverified: ['in-flight admin request'] }, META, /unverified/],
    [{ ...PRODUCTION, runId: 'RTDB-REST-123456789012' }, META, /12-digit/],
  ];
  for (const [result, meta, message] of bad) assert.throws(() => buildRestFixture(rawRows(FIXTURE), result, meta), message);
});
test('recordedJournal: a plain reduction as it is; a provenance must name a production run', () => {
  assert.equal(recordedJournal(FIXTURE), FIXTURE);
  assert.throws(() => recordedJournal({ ...FIXTURE, provenance: { target: 'emulator' } }), /production run/);
  assert.throws(() => recordedJournal([]), /not a reduced/);
});
