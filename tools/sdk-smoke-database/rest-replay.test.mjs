import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { DATA_ROOT, judgeM14, pythonJsonDumps, judgeRow, KNOWN_RAW_ORDER, localRequests, m14Rules, RULES, summarize } from './rest-replay.mjs';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/production-rest.json', import.meta.url), 'utf8'));
const row = (id, round = 1) => fixture.rounds[round - 1].rows.find((r) => r.id === id);
const answer = (r, overrides = {}) => ({ status: r.status, bodyText: r.bodyText, etag: r.etag, ...overrides });

test('the replay sends the 124 corpus requests under the recorded data root', () => {
  const requests = localRequests(fixture);
  assert.equal(requests.length, 124);
  assert.deepEqual(requests.map((r) => r.id), fixture.rounds.flatMap((round) => round.rows.map((x) => x.id)));
  const query = requests.find((r) => r.id === 'query-get-1');
  assert.equal(query.url, `/${DATA_ROOT}/raw/round1/query.json?orderBy="h"&startAt=2`);
  const etag = requests.find((r) => r.id === 'etag-put-if-match-wrong');
  assert.deepEqual(etag.headers, { 'if-match': 'wrong' });
  assert.equal(etag.body, '2');
  assert.equal(requests.find((r) => r.id === 'fresh-number-0-get').body, undefined);
});

test('the Rules are the recorded production Rules with the query index', () => {
  assert.deepEqual(RULES.rules[DATA_ROOT].raw.$round.query, { '.indexOn': ['h'] });
  assert.deepEqual(RULES.rules[DATA_ROOT].protected, { '.read': false, '.write': false });
  assert.deepEqual(m14Rules('auth != null', 'validate').rules[DATA_ROOT].regex.probe, { '.read': true, '.write': true, '.validate': 'auth != null' });
});

test('a row equal in status, bytes and ETag is MATCH; any other difference is a MISMATCH', () => {
  const r = row('etag-get-value');
  assert.equal(judgeRow(1, r, answer(r)).verdict, 'MATCH');
  assert.equal(judgeRow(1, r, answer(r, { status: 201 })).verdict, 'MISMATCH');
  assert.equal(judgeRow(1, r, answer(r, { etag: 'other' })).verdict, 'MISMATCH');
  assert.equal(judgeRow(1, r, answer(r, { etag: null })).verdict, 'MISMATCH');
  assert.equal(judgeRow(1, r, answer(r, { bodyText: '{"x":2}' })).verdict, 'MISMATCH');
  assert.equal(judgeRow(1, r, answer(r, { bodyText: '{"x": 1}' })).verdict, 'MISMATCH');
});

test('only the two recorded key-order rows may differ in bytes, and only in key order', () => {
  assert.deepEqual([...KNOWN_RAW_ORDER].toSorted(), ['patch-update-nested-and-add', 'query-get-1']);
  for (const round of [1, 2]) {
    const patch = row('patch-update-nested-and-add', round);
    const reordered = answer(patch, { bodyText: '{"w":3,"y":{"z":"t"}}' });
    assert.equal(patch.bodyText, '{"y":{"z":"t"},"w":3}');
    const judged = judgeRow(round, patch, reordered);
    assert.equal(judged.verdict, 'KNOWN_DIFFERENCE');
    assert.deepEqual(judged.differences, ['raw-key-order']);
    assert.equal(judgeRow(round, patch, answer(patch, { bodyText: '{"w":4,"y":{"z":"t"}}' })).verdict, 'MISMATCH');
    assert.equal(judgeRow(round, patch, answer(patch)).verdict, 'MATCH');
  }
  const other = row('patch-get-after-update');
  assert.equal(judgeRow(1, other, answer(other, { bodyText: JSON.stringify(JSON.parse(other.bodyText), Object.keys(JSON.parse(other.bodyText)).toReversed()) })).verdict, 'MISMATCH');
});

test('the masked data root in a production error body is compared as the local root', () => {
  const r = row('query-get-3');
  assert.match(r.bodyText, /\{root\}/);
  assert.equal(judgeRow(1, r, answer(r, { bodyText: r.bodyText.replace('{root}', DATA_ROOT) })).verdict, 'MATCH');
  assert.equal(judgeRow(1, r, answer(r, { bodyText: r.bodyText.replace('{root}', 'elsewhere') })).verdict, 'MISMATCH');
});

test('M14 rows match on status and bytes', () => {
  const [m] = fixture.m14;
  assert.equal(judgeM14(m, { status: m.status, bodyText: m.bodyText }).verdict, 'MATCH');
  assert.equal(judgeM14(m, { status: 200, bodyText: m.bodyText }).verdict, 'MISMATCH');
  assert.equal(judgeM14(m, { status: m.status, bodyText: m.bodyText.trim() }).verdict, 'MISMATCH');
});

test('summarize counts verdicts and passes only without a mismatch', () => {
  assert.deepEqual(summarize([{ verdict: 'MATCH' }, { verdict: 'KNOWN_DIFFERENCE' }], [{ verdict: 'MATCH' }]), { rows: 2, m14Rows: 1, verdicts: { MATCH: 1, KNOWN_DIFFERENCE: 1 }, m14Verdicts: { MATCH: 1 }, pass: true });
  assert.equal(summarize([{ verdict: 'MISMATCH' }], []).pass, false);
  assert.equal(summarize([], [{ verdict: 'MISMATCH' }]).pass, false);
  assert.equal(summarize([], []).pass, false);
});

test('pythonJsonDumps writes the bytes the recorder sent (Python json.dumps defaults)', () => {
  assert.equal(pythonJsonDumps({ a: [1, '\uff41"\n'], b: { c: true, d: null } }), '{"a": [1, "\\uff41\\"\\n"], "b": {"c": true, "d": null}}');
  assert.equal(pythonJsonDumps('\u{1F600}\u007f\u0080'), '"\\ud83d\\ude00\u007f\\u0080"');
  assert.equal(pythonJsonDumps({}), '{}');
  assert.equal(pythonJsonDumps([]), '[]');
  assert.equal(pythonJsonDumps(m14Rules('x', 'read')), '{"rules": {".read": false, ".write": false, "parity20261023": {"regex": {"probe": {".read": "x", ".write": true}}}}}');
});
