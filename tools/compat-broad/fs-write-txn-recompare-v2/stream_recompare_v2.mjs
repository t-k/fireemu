// Narrow re-comparison for the validated v1 stream receipt pair.
import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import { compareStreamReceipts } from '../fs-write-txn/stream_comparison.mjs';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const stable = value => Array.isArray(value)
  ? value.map(stable)
  : object(value)
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]))
    : value;
const bytes = value => Buffer.from(JSON.stringify(stable(value)), 'utf8');
const sha256 = value => createHash('sha256').update(bytes(value)).digest('hex');
const textSha256 = value => createHash('sha256').update(value, 'utf8').digest('hex');
const equal = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));
const fail = detail => { throw new Error(detail); };
const RESOURCE_SLOT = '\u0000fireemu:v2:not-found:resource-slot\u0000';

const v1Slots = receipt => {
  if (!object(receipt) || !Array.isArray(receipt.observations)) return [];
  const slots = [];
  for (const observation of receipt.observations) {
    if (!object(observation)) continue;
    if (observation.receipt !== undefined) slots.push(observation.receipt);
    if (observation.phase === 'cleanup' && Array.isArray(observation.cleanup)) {
      for (const item of observation.cleanup) for (const key of ['receipt', 'ownedRead', 'absence']) {
        if (object(item) && item[key] !== undefined) slots.push(item[key]);
      }
    }
    if (observation.phase === 'readback-contention' && object(observation.receipt)) {
      for (const role of ['locked', 'suffix']) if (observation.receipt[role] !== undefined) slots.push(observation.receipt[role]);
    }
  }
  if (Array.isArray(receipt.cleanup)) {
    for (const item of receipt.cleanup) {
      if (!object(item)) continue;
      for (const key of ['receipt', 'ownedRead', 'absence']) if (item[key] !== undefined) slots.push(item[key]);
    }
  }
  if (Array.isArray(receipt.recoveryObservations)) {
    for (const item of receipt.recoveryObservations) if (object(item) && item.receipt !== undefined) slots.push(item.receipt);
  }
  return slots;
};

const diagnostic = (value, resource) => {
  if (typeof value !== 'string') return value;
  for (const prefix of ['', '5 NOT_FOUND: ']) {
    for (const [before, after] of [['Document "', '" not found.'], ['Document not found: ', '']]) {
      if (value === `${prefix}${before}${resource}${after}`) return `${prefix}${before}${RESOURCE_SLOT}${after}`;
    }
  }
  return value;
};

const normalizeReceipt = receipt => {
  if (!object(receipt) || receipt.operation !== 'GetDocument' || !object(receipt.request) || typeof receipt.request.name !== 'string') return receipt;
  if (!object(receipt.status) || receipt.status.code !== 5 || !object(receipt.error) || receipt.error.code !== 5) return receipt;
  const copy = structuredClone(receipt);
  for (const container of [copy.status, copy.error]) {
    for (const key of ['details', 'message']) if (container[key] !== undefined) container[key] = diagnostic(container[key], copy.request.name);
  }
  return copy;
};

const containsReservedTag = value => {
  if (typeof value === 'string') return value.includes(RESOURCE_SLOT);
  if (Array.isArray(value)) return value.some(containsReservedTag);
  if (object(value)) return Object.entries(value).some(([key, child]) => key.includes(RESOURCE_SLOT) || containsReservedTag(child));
  return false;
};

const normalize = receipt => {
  const copy = structuredClone(receipt);
  if (containsReservedTag(copy)) fail('reserved diagnostic tag appears in input');
  for (const slot of v1Slots(copy)) {
    const normalized = normalizeReceipt(slot);
    if (normalized !== slot) {
      for (const key of Object.keys(slot)) delete slot[key];
      Object.assign(slot, normalized);
    }
  }
  return copy;
};

const requireDigest = (actual, expected, label) => {
  if (typeof expected !== 'string' || !/^[0-9a-f]{64}$/.test(expected) || actual !== expected) fail(`${label} digest mismatch`);
};

const bind = ({ production, local, binding }) => {
  if (!object(binding)) fail('binding is required');
  requireDigest(sha256(production), binding.productionReceiptSha256, 'production receipt');
  requireDigest(sha256(local), binding.localReceiptSha256, 'local receipt');
  requireDigest(sha256(binding.permission), binding.permissionSha256, 'permission');
  requireDigest(textSha256(binding.v1Source), binding.v1SourceSha256, 'v1 source');
  requireDigest(sha256(binding.v1Comparison), binding.v1ComparisonSha256, 'v1 comparison');
  if (!object(binding.v2Sources) || Object.keys(binding.v2Sources).length === 0) fail('v2 sources are required');
  requireDigest(sha256(binding.v2Sources), binding.v2SourcesSha256, 'v2 sources');
  requireDigest(sha256(binding.artifact), binding.artifactSha256, 'artifact');
};

export const compareStreamReceiptsV2 = input => {
  try {
    if (!object(input) || !object(input.expected)) fail('input and expected contract are required');
    const { production, local, expected, binding } = input;
    bind({ production, local, binding });
    const v1 = compareStreamReceipts({ production, local, expected });
    if (!equal(v1, binding.v1Comparison)) fail('v1 comparison result mismatch');
    if (v1.classification === 'INDETERMINATE') return { acquisitionValidated: false, promotionReady: false, classification: 'INDETERMINATE', reason: 'v1 validation failed' };
    const normalizedProduction = normalize(production);
    const normalizedLocal = normalize(local);
    const normalized = compareStreamReceipts({ production: normalizedProduction, local: normalizedLocal, expected });
    return {
      acquisitionValidated: false,
      promotionReady: false,
      classification: normalized.classification,
      v1Classification: v1.classification,
      normalizedComparison: normalized,
      bindings: {
        productionReceiptSha256: binding.productionReceiptSha256,
        localReceiptSha256: binding.localReceiptSha256,
        v1ComparisonSha256: binding.v1ComparisonSha256,
        v2SourcesSha256: binding.v2SourcesSha256,
        artifactSha256: binding.artifactSha256,
      },
    };
  } catch (error) {
    return { acquisitionValidated: false, promotionReady: false, classification: 'INDETERMINATE', reasons: [{ code: 'v2-proof', detail: error.message }] };
  }
};

export const writeComparisonArtifact = async (path, artifact) => {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(JSON.stringify(stable(artifact)) + '\n', 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
};

export const v2Digest = sha256;
export const v2TextDigest = textSha256;
