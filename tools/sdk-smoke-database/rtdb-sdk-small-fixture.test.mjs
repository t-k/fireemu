// node --test rtdb-sdk-small-fixture.test.mjs: the journal reducer, the committed production fixture and its provenance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { buildFixture, CASE_SOURCES, parseJsonl, reduceJournal } from './rtdb-sdk-small-fixture.mjs';
import { summarize } from './rtdb-sdk-small-judge.mjs';
import { NAMES, journal, prng, rawRows } from './rtdb-sdk-small-testkit.mjs';

const fixtureUrl = new URL('./fixtures/production-sdk-small.json', import.meta.url);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const RESULT = { runId: 'RTDB-SMALL-20261102-01', target: 'production', scriptSha256: 'e'.repeat(64), sdk: { firebase: '12.18.0', database: '1.1.5', playwright: '1.62.1' }, startedAt: '2026-11-01T16:55:58.685Z', endedAt: '2026-11-01T16:56:19.834Z', status: 'complete', observed: 32, exit: 0, cleanup: { prefix: 'verified', rules: 'verified' }, counts: { direct: 78, reserve: 4, adc: 1 }, cases: [] };
const META = { recordedOn: '2026-11-02', ledgerRow: 1249, approval: 2202, requests: 82, journalSha256: 'a'.repeat(64), resultSha256: 'b'.repeat(64) };

test('reduce: keeps case values and per-role events, drops timings, admin and raw rows, in the profile order', () => {
  const doc = journal(prng(1));
  const reduced = reduceJournal(rawRows(doc), { ...RESULT, target: 'emulator' });
  assert.deepEqual(reduced, doc);
  const text = JSON.stringify(reduced);
  for (const dropped of ['"ms"', '"t"', 'admin', 'raw-', 'rules-before', 'firebaseio']) assert.equal(text.includes(dropped), false, dropped);
  assert.equal(summarize(doc, reduced).match, true);
});

test('reduce: a failed case keeps its error, faults are listed, and a missing profile stays empty', () => {
  const doc = journal(prng(2)), rows = rawRows(doc).filter((r) => r.profile !== 'r2-lp');
  const i = rows.findIndex((r) => r.kind === 'case' && r.id === 'push');
  rows[i] = { kind: 'case', profile: 'r1-ws', role: 'writer', id: 'push', ok: false, error: 'Timeout: writer:push timed out after 15000 ms', ms: 15000 };
  rows.push({ kind: 'page-error', profile: 'r1-lp', error: 'TypeError: x' }, { kind: 'abort', reason: 'run deadline' }, { kind: 'profile-error', profile: 'r1-lp', error: 'boom' }, { kind: 'error', status: 'failed', error: 'x' }, { kind: 'timeout', label: 'y' });
  const reduced = reduceJournal(rows, RESULT);
  assert.deepEqual(reduced.profiles.find((p) => p.name === 'r1-ws').rows.find((r) => r.id === 'push'), { role: 'writer', id: 'push', ok: false, error: 'Timeout: writer:push timed out after 15000 ms' });
  assert.deepEqual(reduced.faults, [{ kind: 'page-error', profile: 'r1-lp' }, { kind: 'abort', profile: null }, { kind: 'profile-error', profile: 'r1-lp' }, { kind: 'error', profile: null }, { kind: 'timeout', profile: null }]);
  assert.deepEqual(reduced.profiles.map((p) => p.name), NAMES);
  assert.deepEqual(reduced.profiles[3], { name: 'r2-lp', events: { writer: [], observer: [] }, rows: [] });
  assert.equal(summarize(doc, reduced).match, false);
});

test('reduce: rows it cannot place refuse the whole journal', () => {
  const good = rawRows(journal(prng(3)));
  const bad = [
    { kind: 'case', profile: 'r3-ws', role: 'writer', id: 'push', ok: true, value: 1 },
    { kind: 'case', profile: 'r1-ws', role: 'reader', id: 'push', ok: true, value: 1 },
    { kind: 'case', profile: 'r1-ws', role: 'writer', id: 'transaction', ok: true, value: 1 },
    { kind: 'case', profile: 'r1-ws', role: 'writer', id: 'push', ok: 'yes', value: 1 },
    { kind: 'sdk-event', profile: 'r1-ws', role: 'writer', event: 'offline' },
    { kind: 'sdk-event', profile: '__proto__', role: 'writer', event: 'connected' },
    { kind: 'sdk-event', profile: 'r1-ws', role: 'constructor', event: 'connected' },
    { kind: 'something-new' },
    null,
  ];
  for (const row of bad) assert.throws(() => reduceJournal([...good, row], RESULT), /^Error: (unknown|journal row is not an object)/, JSON.stringify(row));
  assert.throws(() => reduceJournal(good, null));
  assert.throws(() => reduceJournal('x', RESULT));
  assert.throws(() => parseJsonl('{"kind":"case"}\nnot json\n'));
  assert.deepEqual(parseJsonl('{"a":1}\n\n{"b":2}\n'), [{ a: 1 }, { b: 2 }]);
});

test('fixture: provenance from the production result and the ledger, the counts must add up, only production', () => {
  const rows = rawRows(journal(prng(4))), doc = buildFixture(rows, RESULT, META);
  assert.deepEqual(doc.provenance.counts, { requests: 82, direct: 78, reserve: 4, adc: 1 });
  assert.deepEqual([doc.provenance.runId, doc.provenance.ledgerRow, doc.provenance.approval, doc.provenance.project, doc.provenance.instance], ['RTDB-SMALL-20261102-01', 1249, 2202, 'fireemu-oracle-query', 'fireemu-q-rtdb2']);
  assert.deepEqual(Object.keys(doc.provenance.caseSources), CASE_SOURCES);
  assert.equal(summarize(doc, journal(prng(5))).match, true);
  assert.throws(() => buildFixture(rows, { ...RESULT, target: 'emulator' }, META), /production/);
  assert.throws(() => buildFixture(rows, RESULT, { ...META, requests: 81 }), /requests/);
  assert.throws(() => buildFixture(rows, { ...RESULT, counts: { ...RESULT.counts, adc: 2 } }, META), /ADC/);
  for (const field of ['recordedOn', 'ledgerRow', 'approval', 'journalSha256', 'resultSha256']) assert.throws(() => buildFixture(rows, RESULT, { ...META, [field]: undefined }), /missing/);
});

test('fixture: secret-shaped text and 12-digit numbers are refused', () => {
  const doc = journal(prng(6));
  for (const leak of ['AIzaSyA-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'ya29.a0Af', 'eyJhbGciOiJSUzI1NiJ9', 'see 123456789012 here']) {
    const d = structuredClone(doc);
    d.profiles[0].rows[7].value = { edit: leak, keep: 1 };
    assert.throws(() => buildFixture(rawRows(d), RESULT, META), /secret|number/, leak);
  }
  const d = structuredClone(doc);
  d.profiles[0].rows[7].value = { edit: 123456789012, keep: 1 };
  assert.throws(() => buildFixture(rawRows(d), RESULT, META), /number/);
});

test('the committed fixture: 4 profiles x 8 cases recorded in production, accepted against itself, bound to the replayed case code', () => {
  const fixture = JSON.parse(readFileSync(fixtureUrl, 'utf8'));
  assert.equal(fixture.provenance.runId, 'RTDB-SMALL-20261102-01');
  assert.equal(fixture.provenance.target, 'production');
  assert.deepEqual(fixture.provenance.counts, { requests: 82, direct: 78, reserve: 4, adc: 1 });
  assert.equal(fixture.provenance.observations, 32);
  assert.deepEqual(fixture.provenance.cleanup, { prefix: 'verified', rules: 'verified' });
  assert.deepEqual(fixture.profiles.map((p) => [p.name, p.rows.length]), NAMES.map((n) => [n, 11]));
  const s = summarize(fixture, fixture);
  assert.equal(s.match, true, JSON.stringify(s.problems));
  for (const name of CASE_SOURCES) assert.equal(sha(readFileSync(new URL(`./sdk-observer/${name}`, import.meta.url))), fixture.provenance.caseSources[name], name);
  assert.doesNotThrow(() => buildFixture([], { ...RESULT }, META)); // the reducer accepts an empty journal; the judge then refuses it
  assert.equal(summarize(fixture, buildFixture([], RESULT, META)).match, false);
});
