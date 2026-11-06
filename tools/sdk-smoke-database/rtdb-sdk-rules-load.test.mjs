import test from 'node:test';
import assert from 'node:assert/strict';
import { reduceRulesLoadJournal } from './rtdb-sdk-rules-load-fixture.mjs';
import { summarize } from './rtdb-sdk-rules-load-judge.mjs';
import { TABLE, RULES_LOAD_PROFILES } from './sdk-observer/rules-load-suite.mjs';

test('reduction and comparison preserve observed answers without guessing production', () => {
  const rows = RULES_LOAD_PROFILES.flatMap(profile => TABLE.map(c => ({ kind: 'case', suite: 'rules-load', profile, id: c.id, ok: true, outcome: 'answered', requestBody: c.body, status: 418, body: 'observed', bodyBytes: 8, utf8: true, clipped: false, responseHeaders: {} })));
  const result = { suite: 'rules-load', status: 'complete', observed: 14, exit: 0, cleanup: { prefix: 'not-needed', rules: 'verified' }, unverified: [] };
  const reduced = reduceRulesLoadJournal(rows, result);
  assert.equal(summarize(reduced, reduced).counts.MATCH, 14);
  const changed = structuredClone(reduced); changed.profiles[0].rows[0].status = 400;
  assert.equal(summarize(reduced, changed).counts.MISMATCH, 1);
});
