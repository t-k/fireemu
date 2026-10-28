import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { DATA_ROOT, judgeM14, pythonJsonDumps, judgeRow, localRequests, m14Rules, RULES, summarize } from './rest-replay.mjs';

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
  const text = row('validation-put-bad-json');
  assert.equal(judgeRow(1, text, answer(text, { bodyText: 'not json' })).verdict, 'MISMATCH');
  const plain = { id: 'patch-update-nested-and-add', status: 200, bodyText: 'plain a', etag: null };
  assert.deepEqual(judgeRow(1, plain, answer(plain, { bodyText: 'plain b' })).differences, ['body']);
  assert.equal(judgeRow(1, plain, answer(plain, { bodyText: 'plain b' })).verdict, 'MISMATCH');
});

test('PATCH remains byte exact in both recorded rounds', () => {
  for (const round of [1, 2]) {
    const patch = row('patch-update-nested-and-add', round);
    const reordered = answer(patch, { bodyText: '{"w":3,"y":{"z":"t"}}' });
    assert.equal(patch.bodyText, '{"y":{"z":"t"},"w":3}');
    const judged = judgeRow(round, patch, reordered);
    assert.equal(judged.verdict, 'MISMATCH');
    assert.deepEqual(judged.differences, ['body']);
    assert.equal(judgeRow(round, patch, answer(patch, { bodyText: '{"w":4,"y":{"z":"t"}}' })).verdict, 'MISMATCH');
    assert.equal(judgeRow(round, patch, answer(patch)).verdict, 'MATCH');
  }
  const other = row('patch-get-after-update');
  assert.equal(judgeRow(1, other, answer(other, { bodyText: JSON.stringify(JSON.parse(other.bodyText), Object.keys(JSON.parse(other.bodyText)).toReversed()) })).verdict, 'MISMATCH');
});

test('recorded filtered GET uses semantic JSON with retained raw evidence', () => {
  for (const round of [1, 2]) {
    const expected = row('query-get-1', round);
    const request = localRequests(fixture).find((r) => r.round === round && r.id === expected.id);
    const local = answer(expected, { bodyText: '{"2":{"h":5},"10":{"h":5},"a":{"h":3},"c":{"h":2}}' });
    const result = judgeRow(round, expected, local, request);
    assert.equal(result.verdict, 'MATCH');
    assert.deepEqual(result.differences, []);
    assert.deepEqual(result.diagnostics, ['raw-body-differs']);
    assert.equal(result.policy, 'filtered-get-semantic-json-v1');
    assert.equal(result.production.bodyText, expected.bodyText);
    assert.equal(result.local.bodyText, local.bodyText);
    for (const body of [
      '{"a":{"h":3},"2":{"h":5},"10":{"h":5}}',
      '{"c":{"h":2},"a":{"h":3},"2":{"h":5},"10":{"h":5},"b":{"h":1}}',
      '{"c":{"h":2},"a":{"h":3},"2":{"h":5},"10":{"h":5},"d":null}',
      '{"c":{"h":3},"a":{"h":3},"2":{"h":5},"10":{"h":5}}',
      '{"c":{"h":"2"},"a":{"h":3},"2":{"h":5},"10":{"h":5}}',
      '[]', '{', 'null',
    ]) assert.equal(judgeRow(round, expected, answer(expected, { bodyText: body }), request).verdict, 'MISMATCH', body);
    for (const changed of [{ status: 201 }, { etag: 'unexpected' }])
      assert.equal(judgeRow(round, expected, { ...local, ...changed }, request).verdict, 'MISMATCH');
    const tagged = { ...expected, etag: 'expected-tag' };
    for (const etag of [null, 'different-tag'])
      assert.equal(judgeRow(round, tagged, { ...local, etag }, request).verdict, 'MISMATCH');
    for (const spoof of [{ ...request, method: 'PATCH' }, { ...request, url: request.url.replace('startAt=2', 'startAt=3') }, { ...request, id: 'other' }, undefined])
      assert.equal(judgeRow(round, expected, local, spoof).verdict, 'MISMATCH');
    assert.equal(judgeRow(round, { ...expected, method: 'PATCH' }, local, request).verdict, 'MISMATCH');
    assert.equal(judgeRow(round, { ...expected, path: 'other.json' }, local, request).verdict, 'MISMATCH');
    assert.equal(judgeRow(round, { ...expected, status: 400 }, { ...local, status: 400 }, request).verdict, 'MISMATCH');
  }
});

test('filtered semantic JSON preserves arrays, values, types and explicitly allows JSON serialization variants', () => {
  const expected = { ...row('query-get-1'), bodyText: '{"a":[1,2,2],"b":{"v":true},"n":null}' };
  const request = localRequests(fixture).find((r) => r.round === 1 && r.id === expected.id);
  const compare = (bodyText) => judgeRow(1, expected, answer(expected, { bodyText }), request);
  for (const text of ['{"b":{"v":true},"n":null,"a":[1,2,2]}', '{ "a": [1.0,2,2], "b": {"v":true}, "n": null }', '{"\\u0061":[1,2,2],"b":{"v":true},"n":null}', '{"a":[0],"a":[1,2,2],"b":{"v":true},"n":null}'])
    assert.equal(compare(text).verdict, 'MATCH', text);
  for (const text of ['{"a":[2,1,2],"b":{"v":true},"n":null}', '{"a":[1,2],"b":{"v":true},"n":null}', '{"a":[1,2,1],"b":{"v":true},"n":null}', '{"a":[1,2,2],"b":{"v":1},"n":null}', '{"a":[1,2,2],"b":{"v":true}}', '{"a":[1,2,2],"b":{"v":true},"n":false}'])
    assert.equal(compare(text).verdict, 'MISMATCH', text);
});

test('filtered semantic JSON rejects numbers outside the safe integer domain', () => {
  const expected = { ...row('query-get-1'), bodyText: '{"n":9007199254740992}' };
  const request = localRequests(fixture).find((r) => r.round === 1 && r.id === expected.id);
  const result = judgeRow(1, expected, answer(expected, { bodyText: '{"n":9007199254740993}' }), request);
  assert.equal(result.verdict, 'MISMATCH');
  assert.deepEqual(result.diagnostics, ['raw-body-differs']);
  const small = { ...expected, bodyText: '{"n":2}' };
  assert.equal(judgeRow(1, small, answer(small, { bodyText: '{"n":2.5}' }), request).verdict, 'MISMATCH');
});

test('PICT filtered-query request, body and ETag combinations', () => {
  const expected = row('query-get-1');
  const request = localRequests(fixture).find((r) => r.round === 1 && r.id === expected.id);
  // Exact rows generated by work+rtdb-query-judge.pict, including mandatory seeds.
  for (const [bound, permutation, sameEtag] of [[true, true, true], [false, true, true], [true, false, true], [true, true, false], [false, false, false]]) {
    const bodyText = permutation ? '{"2":{"h":5},"10":{"h":5},"a":{"h":3},"c":{"h":2}}' : '{"c":{"h":3}}';
    const actualRequest = bound ? request : { ...request, method: 'PATCH' };
    const result = judgeRow(1, expected, answer(expected, { bodyText, etag: sameEtag ? expected.etag : 'changed' }), actualRequest);
    assert.equal(result.verdict, bound && permutation && sameEtag ? 'MATCH' : 'MISMATCH');
  }
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
  assert.equal(summarize([{ verdict: 'MATCH' }, { verdict: 'MISMATCH' }], [{ verdict: 'MATCH' }]).pass, false);
  assert.equal(summarize([{ verdict: 'MATCH' }], [{ verdict: 'MATCH' }, { verdict: 'MISMATCH' }]).pass, false);
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
