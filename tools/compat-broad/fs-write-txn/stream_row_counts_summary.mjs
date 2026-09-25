// Offline per-row summary for the retained September 17 Write-stream pair.
//
// This entry performs no credential access, network request, new observation,
// or new build. It re-reads the immutable retained receipts, reproduces the
// whole-comparison verdict the saved result already records, and adds the
// per-row classification counts that result omits.
//
// It is NOT acquisition authority. `tools/compat-broad/fs-write-txn-recompare-v2`
// remains the only entry that can validate acquisition, and it requires the two
// frozen source worktrees. This entry states its anchor instead: the retained
// receipts and the comparator bytes are verified against the digests the
// campaign recorded, and nothing is rebuilt from the current HEAD.
import { createHash } from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { compareStreamReceipts } from './stream_comparison.mjs';
import { compareStreamReceiptsV2, v2Digest, v2TextDigest } from '../fs-write-txn-recompare-v2/stream_recompare_v2.mjs';
import { classifyStreamRows } from './stream_row_counts.mjs';

// Trust roots: reviewed commits and independently recorded byte hashes.
export const ANCHOR = Object.freeze({
  campaignId: 'FS-WRITE-TXN-PRECEDENCE-01',
  productionSourceCommit: 'dee737c14e68eb4f546b7ca4c827871fc48a2503',
  repairedArtifactSourceCommit: '567565bdd654cab00dbb84101edcc7bdc628e230',
  comparatorSourceCommit: '6dff3192a6b8b23ea462730bfc105747849a7788',
  comparatorSha256: 'd0d2c818c086c4770d4a724a6f83059cbc522a898d992a252e48c45d3ef946af',
  productionReceiptSha256: '12956fbe82acefc106093eb2cd913ede9092f74aa98bd29f39e795492754b3f3',
  preparedInputsSha256: 'b43dbf0bffb4ea575467d12fa49727c78d15a34900401bbb9b3d0ebbc29d65d5',
  repairedLocalReceiptSha256: '34724f3881f0920c6a3afc14cd735066d5f07e0b25411684e4552c284da142ab',
  repairedArtifactSha256: 'e792e0bc1947bbd227b3ee9778eca093cda94fbde767911dd6139a6cbfd90be4',
});

const BASE = 'docs.local/logs/2026-09-17';
const PRODUCTION_RECEIPT = `${BASE}/stream-production-preflight/execution-dee737c14/receipt.json`;
const PREPARED_INPUTS = `${BASE}/stream-production-preflight/approved-prepared-inputs-dee.json`;
const REPAIRED_RECEIPT = `${BASE}/stream-repair-shadow-567565bdd/owned-run/receipt.json`;
const REPAIRED_ARTIFACT = `${BASE}/stream-repair-shadow-567565bdd/fireemu-567565bdd`;
const HERE = fileURLToPath(new URL('.', import.meta.url));

const fail = detail => { throw new Error(detail); };
const sha256 = buffer => createHash('sha256').update(buffer).digest('hex');

const readVerified = async (path, expected) => {
  const raw = await readFile(path);
  const actual = sha256(raw);
  if (expected !== undefined && actual !== expected) fail(`${path} digest differs`);
  return { raw, sha256: actual };
};

// Every RPC of the finite journal is a data request, so the enumerated row
// count must equal the data-request count the collector recorded.
const requireRowCount = (result, receipt, label) => {
  if (result.rowCount !== receipt.dataRequests) fail(`${label} row count ${result.rowCount} differs from recorded dataRequests ${receipt.dataRequests}`);
};

export const summarizeStreamRowCounts = async ({ root }) => {
  if (typeof root !== 'string' || root.length === 0) fail('repository root is required');
  const at = relative => resolve(root, relative);

  const comparator = await readVerified(resolve(HERE, 'stream_comparison.mjs'), ANCHOR.comparatorSha256);
  const production = await readVerified(at(PRODUCTION_RECEIPT), ANCHOR.productionReceiptSha256);
  const prepared = await readVerified(at(PREPARED_INPUTS), ANCHOR.preparedInputsSha256);
  const local = await readVerified(at(REPAIRED_RECEIPT), ANCHOR.repairedLocalReceiptSha256);

  const productionReceipt = JSON.parse(production.raw);
  const localReceipt = JSON.parse(local.raw);
  const preparedInputs = JSON.parse(prepared.raw);
  const plan = preparedInputs.plan;
  if (preparedInputs.bindings?.comparatorSha256 !== ANCHOR.comparatorSha256) fail('prepared inputs bind a different comparator');

  // The declared comparison contract, rebuilt exactly as the campaign built it.
  const expected = {
    version: 1,
    projectId: plan.projectId,
    documentPrefix: plan.documentPrefix,
    resources: [
      { role: 'control', suffix: 'control' },
      { role: 'locked', suffix: 'locked' },
      { role: 'suffix', suffix: 'contended-tail' },
    ],
    maxRpc: 25,
    maxFramesPerRpc: 32,
    local: { projectId: localReceipt.gate.plan.projectId, documentPrefix: localReceipt.gate.plan.documentPrefix },
  };

  const pair = { production: productionReceipt.collection, local: localReceipt.collection, expected };
  const rawComparison = compareStreamReceipts(pair);

  const permission = JSON.parse(await readFile(preparedInputs.permissionPath, 'utf8'));
  const v2Sources = { 'stream_row_counts_summary.mjs': await readFile(fileURLToPath(import.meta.url), 'utf8') };
  const artifact = { sha256: ANCHOR.repairedArtifactSha256 };
  const binding = {
    permission,
    v1Source: comparator.raw.toString('utf8'),
    v1Comparison: rawComparison,
    v2Sources,
    artifact,
    permissionSha256: v2Digest(permission),
    v1SourceSha256: v2TextDigest(comparator.raw.toString('utf8')),
    v1ComparisonSha256: v2Digest(rawComparison),
    v2SourcesSha256: v2Digest(v2Sources),
    artifactSha256: v2Digest(artifact),
    productionReceiptSha256: v2Digest(pair.production),
    localReceiptSha256: v2Digest(pair.local),
  };
  const normalized = compareStreamReceiptsV2({ ...pair, binding });
  if (normalized.classification === 'INDETERMINATE') fail('normalized re-comparison did not complete');

  const rawRows = classifyStreamRows(pair);
  const repairedRows = classifyStreamRows({ ...pair, comparison: normalized.normalizedComparison });
  requireRowCount(rawRows, productionReceipt, 'raw comparison');
  requireRowCount(repairedRows, productionReceipt, 'repaired comparison');
  if (productionReceipt.dataRequests !== localReceipt.dataRequests) fail('the two sides recorded a different data-request count');

  // The whole-comparison verdicts must still be the ones the saved result names.
  if (rawComparison.classification !== 'SEMANTIC_MISMATCH') fail('raw verdict is no longer SEMANTIC_MISMATCH');
  if (normalized.classification !== 'EXPECTED_NONDETERMINISM') fail('repaired verdict is no longer EXPECTED_NONDETERMINISM');

  // The artifact binary is recorded when it is still retained; it is never rebuilt.
  let artifactRetained = false;
  try {
    await readVerified(at(REPAIRED_ARTIFACT), ANCHOR.repairedArtifactSha256);
    artifactRetained = true;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const strip = result => ({
    classification: result.classification,
    rowCount: result.rowCount,
    counts: result.counts,
    positiveAgreement: result.positiveAgreement,
    unattributedDeviations: result.unattributedDeviations,
    rows: result.rows,
  });

  return {
    kind: 'fs-write-transaction-saved-comparison-rows-v1',
    campaignId: ANCHOR.campaignId,
    evidenceCategory: 'saved-production-reference-row-counts',
    describes: 'spec/compatibility/broad-runs/fs-write-txn-567565bdd-saved-result.json',
    acquisitionValidated: false,
    promotionReady: false,
    newProductionRequests: 0,
    newBuilds: 0,
    anchor: {
      ...ANCHOR,
      productionReceiptPath: PRODUCTION_RECEIPT,
      preparedInputsPath: PREPARED_INPUTS,
      repairedLocalReceiptPath: REPAIRED_RECEIPT,
      repairedArtifactPath: REPAIRED_ARTIFACT,
      repairedArtifactRetained: artifactRetained,
      repairedArtifactReExecuted: false,
      comparatorRebuilt: false,
      boundToCurrentHead: false,
    },
    rowDefinition: 'One row is one data RPC, enumerated in the order the comparator ticks its finite RPC budget. The row count equals the data-request count both receipts record.',
    positiveAgreementDefinition: 'Rows whose normalized semantic content is equal: MATCH plus EXPECTED_NONDETERMINISM.',
    recordedDataRequests: productionReceipt.dataRequests,
    originalComparison: strip(rawRows),
    repairedComparison: strip(repairedRows),
    limitations: [
      'Row counts are derived from the unmodified comparator; no classification rule was changed to produce them.',
      'Raw-slot equality is a stricter test than the comparator identity relation, so the MATCH share is a lower bound and the positive-agreement total is unaffected.',
      'This entry is not acquisition authority: only the recompare-v2 file entry can validate acquisition, and it needs the two frozen source worktrees.',
      'The comparison still covers one finite stream and transaction case group, not all Write or transaction behavior.',
    ],
  };
};

export const writeStreamRowCountsSummary = async (path, summary) => {
  const handle = await open(path, 'wx');
  try {
    await handle.writeFile(`${JSON.stringify(summary, null, 2)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [root, output] = process.argv.slice(2);
  const summary = await summarizeStreamRowCounts({ root });
  await writeStreamRowCountsSummary(output, summary);
  process.stdout.write(`${JSON.stringify({ raw: summary.originalComparison.counts, repaired: summary.repairedComparison.counts, positiveAgreement: summary.repairedComparison.positiveAgreement })}\n`);
}
