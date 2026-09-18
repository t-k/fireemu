import test from 'node:test';
import assert from 'node:assert/strict';
import { compareStreamReceipts } from './stream_comparison.mjs';
import { classifyStreamRows, flattenStreamProjection, streamRowSlots, STREAM_ROW_CLASSIFICATIONS } from './stream_row_counts.mjs';
import { base, bytes, contract, fixture } from './stream_row_fixture.mjs';

// Public synthetic journals only. No credentials or private receipt fixtures.
const classify = (production, local = structuredClone(production), expected = contract) => classifyStreamRows({ production, local, expected });
const sum = counts => STREAM_ROW_CLASSIFICATIONS.reduce((total, name) => total + counts[name], 0);

// The synthetic journal is fifteen phase RPCs plus seven cleanup RPCs: two
// roles read, delete and re-read, and the skipped role only reads once.
const ROWS = 22;
// The retained September 17 journal adds a distinct final absence read for the
// skipped role, which is the twenty-third data RPC.
const withSkippedAbsence = () => {
  const receipt = fixture();
  for (const list of [receipt.cleanup, receipt.observations[14].cleanup]) {
    const item = list.find(entry => entry.skipped);
    item.absence = structuredClone(item.receipt);
  }
  return receipt;
};

test('enumerates one row per data RPC of the finite journal', () => {
  const rows = streamRowSlots(fixture(), contract);
  assert.equal(rows.length, ROWS);
  assert.deepEqual(rows.map(row => row.index), [...Array(ROWS).keys()]);
});

test('row order follows the comparator phase order and ends in cleanup', () => {
  const rows = streamRowSlots(fixture(), contract);
  assert.deepEqual(rows.slice(0, 3).map(row => row.phase), ['preflight-create-absence', 'preflight-create-absence', 'setup-control']);
  assert.deepEqual(rows.slice(10, 12).map(row => [row.phase, row.role]), [['readback-contention', 'locked'], ['readback-contention', 'suffix']]);
  assert.deepEqual(rows.slice(15).map(row => row.role), ['control', 'control', 'control', 'locked', 'locked', 'locked', 'suffix']);
});

test('the projection splits into exactly the enumerated rows', () => {
  const production = fixture();
  const local = fixture({ contentionCode: 0 });
  const comparison = compareStreamReceipts({ production, local, expected: contract });
  assert.equal(comparison.classification, 'SEMANTIC_MISMATCH');
  assert.equal(flattenStreamProjection(comparison.differences.production).length, streamRowSlots(production, contract).length);
});

test('an identical pair reports every row as MATCH', () => {
  const result = classify(fixture());
  assert.equal(result.classification, 'MATCH');
  assert.equal(result.counts.MATCH, ROWS);
  assert.equal(result.positiveAgreement, ROWS);
});

test('a renamed, re-owned and re-timed pair agrees on every row without matching identity', () => {
  const side = { projectId: 'other-project', documentPrefix: 'compat/o3/other-run' };
  const production = fixture();
  const local = fixture({ ...side, owner: 'other-owner', shift: 1000, tokenShift: 10 });
  const expected = { ...contract, production: base, local: side };
  const result = classifyStreamRows({ production, local, expected });
  assert.equal(result.classification, 'EXPECTED_NONDETERMINISM');
  assert.equal(result.counts.EXPECTED_NONDETERMINISM, ROWS);
  assert.equal(result.counts.MATCH, 0);
  assert.equal(result.counts.SEMANTIC_MISMATCH, 0);
  assert.equal(result.positiveAgreement, ROWS);
});

test('counts always total the enumerated row count', () => {
  for (const result of [classify(fixture()), classify(fixture(), fixture({ contentionCode: 0 })), classify(fixture(), fixture({ shift: 5 }))]) {
    assert.equal(sum(result.counts), result.rowCount);
    assert.equal(result.rowCount, ROWS);
  }
});

test('a skipped role with a distinct final absence read adds one row', () => {
  const production = withSkippedAbsence();
  assert.equal(streamRowSlots(production, contract).length, ROWS + 1);
  const result = classify(production);
  assert.equal(result.classification, 'MATCH');
  assert.equal(result.rowCount, ROWS + 1);
  assert.equal(result.counts.MATCH, ROWS + 1);
  assert.equal(sum(result.counts), ROWS + 1);
});

// The difference cluster the campaign actually hit: absence diagnostics whose
// wording differs while every other projected field agrees.
const reword = (slot, text) => { slot.status.details = text; slot.error.details = text; slot.error.message = text; };

test('a semantic mismatch is attributed to the rows that actually differ', () => {
  const production = fixture();
  const local = structuredClone(production);
  reword(local.observations[0].receipt, 'Document not found: control');
  const result = classify(production, local);
  assert.equal(result.classification, 'SEMANTIC_MISMATCH');
  assert.equal(result.counts.SEMANTIC_MISMATCH, 1);
  assert.equal(result.rows[0].classification, 'SEMANTIC_MISMATCH');
  assert.equal(result.positiveAgreement, ROWS - 1);
  assert.equal(sum(result.counts), ROWS);
});

test('a cleanup-only mismatch is attributed to the cleanup row', () => {
  const production = fixture();
  const local = structuredClone(production);
  const index = local.cleanup.findIndex(item => !item.skipped);
  for (const list of [local.cleanup, local.observations[14].cleanup]) reword(list[index].absence, 'Document not found: control');
  const result = classify(production, local);
  assert.equal(result.classification, 'SEMANTIC_MISMATCH');
  assert.equal(result.counts.SEMANTIC_MISMATCH, 1);
  assert.equal(result.rows.find(row => row.classification === 'SEMANTIC_MISMATCH').phase, 'cleanup');
});

test('classifications are stable across repeated runs and clones of the same pair', () => {
  const production = fixture();
  const local = fixture({ shift: 7, tokenShift: 3 });
  const first = classifyStreamRows({ production, local, expected: contract });
  for (let i = 0; i < 3; i += 1) {
    const repeat = classifyStreamRows({ production: structuredClone(production), local: structuredClone(local), expected: contract });
    assert.deepEqual(repeat, first);
  }
});

test('row order does not depend on the order cleanup records are stored in', () => {
  const production = fixture();
  const local = structuredClone(production);
  local.observations[14].cleanup.reverse();
  local.cleanup.reverse();
  const result = classify(production, local);
  assert.equal(result.classification, 'MATCH');
  assert.equal(result.counts.MATCH, ROWS);
});

test('a failed proof on either side yields only INDETERMINATE rows', () => {
  const production = fixture();
  const local = structuredClone(production);
  delete local.observations[0].receipt.request;
  const result = classify(production, local);
  assert.equal(result.classification, 'INDETERMINATE');
  assert.equal(result.counts.INDETERMINATE, ROWS);
  assert.equal(result.positiveAgreement, 0);
});

test('an unusable receipt yields INDETERMINATE with no rows rather than a count', () => {
  const result = classifyStreamRows({ production: {}, local: fixture(), expected: contract });
  assert.equal(result.classification, 'INDETERMINATE');
  assert.equal(result.rowCount, 0);
  assert.equal(result.positiveAgreement, 0);
});

test('unattributable semantic deviations do not become row agreement', () => {
  // Both peers agree that contention unexpectedly succeeded: a deviation with
  // no projection difference to attribute it to.
  const production = fixture({ contentionCode: 0 });
  const result = classify(production);
  const comparison = compareStreamReceipts({ production, local: structuredClone(production), expected: contract });
  assert.equal(comparison.classification, 'SEMANTIC_MISMATCH');
  assert.ok(comparison.reasons.production.length > 0);
  assert.equal(result.classification, 'INDETERMINATE');
  assert.equal(result.positiveAgreement, 0);
  assert.ok(result.unattributedDeviations > 0);
});

test('a caller-supplied comparison is used for content and the receipts for identity', () => {
  const production = fixture();
  const local = fixture({ tokenShift: 40 });
  const comparison = compareStreamReceipts({ production, local, expected: contract });
  assert.equal(comparison.classification, 'EXPECTED_NONDETERMINISM');
  const result = classifyStreamRows({ production, local, expected: contract, comparison });
  assert.equal(result.classification, 'EXPECTED_NONDETERMINISM');
  assert.equal(result.positiveAgreement, ROWS);
  assert.ok(result.counts.EXPECTED_NONDETERMINISM > 0);
});

test('row verdicts never contradict the whole-comparison classification', () => {
  const production = fixture();
  const local = structuredClone(production);
  const forged = { ...compareStreamReceipts({ production, local, expected: contract }), classification: 'SEMANTIC_MISMATCH' };
  const result = classifyStreamRows({ production, local, expected: contract, comparison: forged });
  assert.equal(result.classification, 'INDETERMINATE');
});

test('the comparison never gains acquisition or promotion authority from counting rows', () => {
  const result = classify(fixture());
  assert.equal(result.acquisitionValidated, undefined);
  assert.equal(result.promotionReady, undefined);
});

test('a contract that does not declare three distinct roles is refused', () => {
  const production = fixture();
  for (const resources of [['control', 'locked'], ['control', 'locked', 'locked'], ['control', 'locked', 'other']]) {
    assert.throws(() => streamRowSlots(production, { ...contract, resources }));
  }
});

test('a transaction token difference alone is expected nondeterminism on every row', () => {
  const production = fixture();
  const local = fixture({ tokenShift: 1 });
  const result = classify(production, local);
  assert.equal(result.classification, 'EXPECTED_NONDETERMINISM');
  assert.equal(result.counts.SEMANTIC_MISMATCH, 0);
  assert.equal(result.positiveAgreement, ROWS);
  assert.notDeepEqual(local.observations[6].receipt.response.transaction, bytes(200));
});
