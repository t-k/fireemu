import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { ANCHOR, summarizeStreamRowCounts } from './stream_row_counts_summary.mjs';
import { STREAM_ROW_CLASSIFICATIONS } from './stream_row_counts.mjs';

const repository = resolve(fileURLToPath(new URL('.', import.meta.url)), '../../..');
const read = relative => JSON.parse(readFileSync(resolve(repository, relative), 'utf8'));
const SUMMARY = 'spec/compatibility/broad-runs/fs-write-txn-567565bdd-saved-result-rows.json';
const SAVED = 'spec/compatibility/broad-runs/fs-write-txn-567565bdd-saved-result.json';

const summary = read(SUMMARY);
const saved = read(SAVED);
const sides = [summary.originalComparison, summary.repairedComparison];
const sum = counts => STREAM_ROW_CLASSIFICATIONS.reduce((total, name) => total + counts[name], 0);

test('the summary describes the saved result it was derived from', () => {
  assert.equal(summary.describes, SAVED);
  assert.equal(summary.campaignId, saved.campaignId);
});

test('the summary is anchored to the commits and receipts the saved result names', () => {
  assert.equal(summary.anchor.productionSourceCommit, saved.productionSourceCommit);
  assert.equal(summary.anchor.repairedArtifactSourceCommit, saved.repairedArtifactSourceCommit);
  assert.equal(summary.anchor.comparatorSourceCommit, saved.comparatorSourceCommit);
  assert.equal(summary.anchor.repairedArtifactSha256, saved.repairedArtifactSha256);
  assert.equal(summary.anchor.productionReceiptSha256, saved.privateEvidenceSha256.originalProductionReceipt);
  assert.equal(summary.anchor.repairedLocalReceiptSha256, saved.privateEvidenceSha256.repairedLocalReceipt);
});

test('the summary is never bound to the current HEAD and claims no new work', () => {
  assert.equal(summary.anchor.boundToCurrentHead, false);
  assert.equal(summary.anchor.comparatorRebuilt, false);
  assert.equal(summary.anchor.repairedArtifactReExecuted, false);
  assert.equal(summary.newProductionRequests, 0);
  assert.equal(summary.newBuilds, 0);
  assert.equal(summary.acquisitionValidated, false);
  assert.equal(summary.promotionReady, false);
});

test('the comparator on disk is byte-identical to the one the campaign bound', () => {
  assert.equal(summary.anchor.comparatorSha256, ANCHOR.comparatorSha256);
});

test('the summary repeats the whole-comparison verdicts the saved result records', () => {
  assert.equal(summary.originalComparison.classification, saved.originalClassification);
  assert.equal(summary.repairedComparison.classification, saved.repairedClassification);
});

test('each side totals the data-request count of the production receipt', () => {
  for (const side of sides) {
    assert.equal(side.rowCount, summary.recordedDataRequests);
    assert.equal(sum(side.counts), summary.recordedDataRequests);
    assert.equal(side.rows.length, summary.recordedDataRequests);
  }
});

test('positive agreement is exactly the semantically equal rows', () => {
  for (const side of sides) assert.equal(side.positiveAgreement, side.counts.MATCH + side.counts.EXPECTED_NONDETERMINISM);
});

test('the repaired comparison agrees on every row', () => {
  assert.equal(summary.repairedComparison.positiveAgreement, summary.recordedDataRequests);
  assert.equal(summary.repairedComparison.counts.SEMANTIC_MISMATCH, 0);
  assert.equal(summary.repairedComparison.counts.INDETERMINATE, 0);
});

test('the original mismatch falls only on the absence reads the difference cluster names', () => {
  const mismatched = summary.originalComparison.rows.filter(row => row.classification === 'SEMANTIC_MISMATCH');
  assert.equal(mismatched.length, summary.originalComparison.counts.SEMANTIC_MISMATCH);
  const absencePhases = ['preflight-create-absence', 'preflight-suffix-absence', 'readback-contention', 'cleanup'];
  for (const row of mismatched) assert.ok(absencePhases.includes(row.phase), `unexpected mismatch phase ${row.phase}`);
});

test('every row carries an index, a phase and a declared classification', () => {
  for (const side of sides) {
    side.rows.forEach((row, index) => {
      assert.equal(row.index, index);
      assert.equal(typeof row.phase, 'string');
      assert.ok(STREAM_ROW_CLASSIFICATIONS.includes(row.classification));
    });
  }
});

test('normalization only moves rows towards agreement, never away from it', () => {
  summary.originalComparison.rows.forEach((row, index) => {
    const repaired = summary.repairedComparison.rows[index];
    assert.equal(repaired.phase, row.phase);
    if (row.classification !== 'SEMANTIC_MISMATCH') assert.notEqual(repaired.classification, 'SEMANTIC_MISMATCH');
  });
});

// The retained receipts live outside the repository. Point STREAM_ROW_COUNTS_ROOT
// at the checkout that holds them to prove the summary still regenerates byte for byte.
test('regenerating from the retained receipts reproduces the checked-in summary', { skip: process.env.STREAM_ROW_COUNTS_ROOT ? false : 'STREAM_ROW_COUNTS_ROOT is not set' }, async () => {
  const regenerated = await summarizeStreamRowCounts({ root: process.env.STREAM_ROW_COUNTS_ROOT });
  assert.deepEqual(regenerated, summary);
});
