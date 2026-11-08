// node --test rtdb-sdk-rules-load-fixture.test.mjs: the production fixture of the rules-load suite is built only from a clean production run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { CASE_SOURCES, KIND, buildRulesLoadFixture, recordedJournal, reduceRulesLoadJournal } from './rtdb-sdk-rules-load-fixture.mjs';

const FIXTURE = JSON.parse(readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'production-sdk-rules-load.json'), 'utf8'));
const recorded = recordedJournal(FIXTURE);
const rows = [{ kind: 'admin-req', label: 'rules-before' }, ...recorded.profiles.flatMap(p => p.rows.map(r => ({ kind: 'case', suite: 'rules-load', profile: p.name, ...r }))), { kind: 'result' }];
const result = { runId: 'RTDB-RULES-LOAD-X', suite: 'rules-load', target: 'production', startedAt: '2026-11-05T15:55:22.668Z', endedAt: '2026-11-05T15:55:36.921Z', scriptSha256: 'a'.repeat(64), ...recorded.result, counts: { direct: 25, reserve: 2, adc: 1 }, caps: { direct: 60, reserve: 12, adc: 1 } };
const meta = { recordedOn: '2026-11-05', bookingRow: 1268, closeRow: 1269, approvals: [2266, 2267], requests: 27, packetSha256: 'b'.repeat(64), sourceHead: 'c'.repeat(40), journalSha256: 'd'.repeat(64), resultSha256: 'e'.repeat(64) };

test('the committed fixture is the reduction of a clean production run of the seven documents, with provenance', () => {
  assert.equal(FIXTURE.kind, KIND); assert.equal(FIXTURE.suite, 'rules-load');
  assert.equal(FIXTURE.provenance.counts.requests, 27); assert.equal(FIXTURE.provenance.counts.adc, 1); assert.equal(FIXTURE.provenance.counts.overflow, 0);
  assert.deepEqual(FIXTURE.provenance.sandboxLedger, { booking: 1268, close: 1269 }); assert.deepEqual(FIXTURE.provenance.approvals, [2266, 2267]);
  assert.deepEqual(Object.keys(FIXTURE.provenance.caseSources), CASE_SOURCES);
  assert.doesNotMatch(JSON.stringify(FIXTURE), /ya29\.|AIza/);
});

test('build: a reduction with provenance, and the same reduction as the one that is rebuilt from its rows', () => {
  const doc = buildRulesLoadFixture(rows, result, meta);
  assert.deepEqual({ kind: doc.kind, suite: doc.suite, result: doc.result, faults: doc.faults, profiles: doc.profiles }, { ...reduceRulesLoadJournal(rows, result) });
  assert.deepEqual(doc.profiles, FIXTURE.profiles);
});

test('build refuses: a local run, a missing field, the wrong request count, no or two ADC tokens, an overflow, an unknown outcome, a row it cannot place', () => {
  const refuse = (change, pattern, rowChange = r => r) => assert.throws(() => buildRulesLoadFixture(rowChange(rows), { ...result, ...change.result }, { ...meta, ...change.meta }), pattern);
  refuse({ result: { target: 'emulator' } }, /production run/);
  refuse({ meta: { sourceHead: '' } }, /missing sourceHead/);
  refuse({ meta: { requests: 30 } }, /ledger's 30 requests/);
  refuse({ result: { counts: { direct: 25, reserve: 2, adc: 0 } } }, /exactly one ADC/);
  refuse({ result: { counts: { direct: 25, reserve: 2, adc: 1, overflow: 1 } } }, /over its cap/);
  refuse({ result: { unverified: ['g-dup-key'] } }, /unverified/);
  refuse({}, /unknown case row/, r => [...r, { kind: 'case', suite: 'rules-load', profile: 'r1-rules-load', id: 'nope', ok: true }]);
  refuse({}, /unknown journal row kind/, r => [...r, { kind: 'mystery' }]);
  refuse({}, /unknown profile/, r => [...r, { kind: 'case', suite: 'rules-load', profile: 'r9', id: 'g-dup-key', ok: true }]);
});
