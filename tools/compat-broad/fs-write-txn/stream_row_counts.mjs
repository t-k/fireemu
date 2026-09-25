// Per-row classification counts for the finite Write-stream/transaction comparison.
//
// This module derives row-level counts from the unmodified comparator in
// `stream_comparison.mjs`. It defines no new agreement rule and can never
// contradict the whole-comparison verdict: every row verdict is read out of the
// comparator's own projection, and any disagreement with the whole-comparison
// classification fails closed to INDETERMINATE.
//
// A row is one data RPC. Rows are enumerated in the exact order the comparator
// ticks its finite RPC budget, so the row count equals the data-request count
// recorded on the receipt.
//
// Row verdicts:
//   MATCH                    normalized semantic content equal and raw slot equal
//   EXPECTED_NONDETERMINISM  normalized semantic content equal, raw slot differs
//   SEMANTIC_MISMATCH        normalized semantic content differs
//   INDETERMINATE            a side failed proof, or the difference cannot be
//                            attributed to a single row
//
// Positive agreement is MATCH + EXPECTED_NONDETERMINISM: the rows whose
// normalized semantic content is equal. Raw-slot equality is a strictly
// stronger test than the comparator's own identity equality, so a row reported
// MATCH here is MATCH under the comparator too; the reverse need not hold, and
// the split therefore never overstates identity agreement.
import { compareStreamReceipts, streamComparisonPhases } from './stream_comparison.mjs';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const stable = value => Array.isArray(value)
  ? value.map(stable)
  : object(value)
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]))
    : value;
const equal = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));
const fail = detail => { throw new Error(detail); };

const ROLES = ['control', 'locked', 'suffix'];
const CLEANUP_SLOTS = ['ownedRead', 'receipt', 'absence'];
const CONTENTION_ROLES = ['locked', 'suffix'];
export const STREAM_ROW_CLASSIFICATIONS = Object.freeze(['MATCH', 'EXPECTED_NONDETERMINISM', 'SEMANTIC_MISMATCH', 'INDETERMINATE']);

// Role suffixes come from the declared comparison contract, never from the receipt.
const roleSuffixes = expected => {
  if (!object(expected) || !Array.isArray(expected.resources) || expected.resources.length !== 3) fail('contract must declare exactly three resources');
  const suffixes = {};
  for (const resource of expected.resources) {
    const role = typeof resource === 'string' ? resource : resource?.role;
    const suffix = typeof resource === 'string' ? resource : resource?.suffix ?? resource?.path;
    if (!ROLES.includes(role) || Object.hasOwn(suffixes, role) || typeof suffix !== 'string' || suffix.length === 0) fail('invalid contract resource role or suffix');
    suffixes[role] = suffix;
  }
  return suffixes;
};

const cleanupItem = (cleanup, role, suffixes) => {
  const matches = cleanup.filter(item => object(item) && typeof item.path === 'string' && item.path.endsWith(`/${suffixes[role]}`));
  if (matches.length !== 1) fail(`cleanup does not name exactly one ${role} resource`);
  return matches[0];
};

// One entry per data RPC, in comparator tick order, carrying the raw receipt slot.
export const streamRowSlots = (receipt, expected) => {
  if (!object(receipt) || !Array.isArray(receipt.observations) || receipt.observations.length !== streamComparisonPhases.length) fail('receipt has no finite observation sequence');
  const suffixes = roleSuffixes(expected);
  const rows = [];
  const push = (phase, slot, role) => {
    if (!object(slot)) fail(`missing receipt slot in phase ${phase}`);
    rows.push({ index: rows.length, phase, ...(role === undefined ? {} : { role }), slot });
  };
  receipt.observations.forEach((observation, i) => {
    const phase = streamComparisonPhases[i][0];
    if (!object(observation) || observation.phase !== phase) fail(`unexpected observation ${i}`);
    if (phase === 'readback-contention') {
      for (const role of CONTENTION_ROLES) push(phase, observation.receipt?.[role], role);
    } else if (phase === 'cleanup') {
      if (!Array.isArray(observation.cleanup) || observation.cleanup.length !== ROLES.length) fail('cleanup must cover three resources');
      for (const role of ROLES) {
        const item = cleanupItem(observation.cleanup, role, suffixes);
        for (const key of CLEANUP_SLOTS) if (item[key] !== undefined) push(phase, item[key], role);
      }
    } else push(phase, observation.receipt);
  });
  return rows;
};

// The comparator's projection, split into the same one-entry-per-RPC order.
export const flattenStreamProjection = projection => {
  if (!Array.isArray(projection) || projection.length !== streamComparisonPhases.length) fail('projection is not the finite phase sequence');
  const flat = [];
  projection.forEach((entry, i) => {
    const phase = streamComparisonPhases[i][0];
    if (phase === 'readback-contention') {
      for (const role of CONTENTION_ROLES) flat.push(entry?.[role]);
    } else if (phase === 'cleanup') {
      if (!Array.isArray(entry)) fail('cleanup projection is not a list');
      for (const item of entry) for (const key of CLEANUP_SLOTS) if (item?.[key] !== undefined) flat.push(item[key]);
    } else flat.push(entry);
  });
  return flat;
};

const tally = rows => {
  const counts = Object.fromEntries(STREAM_ROW_CLASSIFICATIONS.map(name => [name, 0]));
  for (const row of rows) counts[row.classification] += 1;
  return counts;
};

const indeterminate = (slots, reason) => {
  const rows = slots.map(({ index, phase, role }) => ({ index, phase, ...(role === undefined ? {} : { role }), classification: 'INDETERMINATE' }));
  return { classification: 'INDETERMINATE', rowCount: rows.length, counts: tally(rows), positiveAgreement: 0, unattributedDeviations: 0, reason, rows };
};

/**
 * Count how many data rows of a finite Write-stream comparison agree.
 *
 * `comparison` lets a caller pass a comparison the same comparator already
 * produced over normalized receipts; the raw receipts still supply row slots.
 */
export const classifyStreamRows = ({ production, local, expected, comparison } = {}) => {
  let slots;
  let localSlots;
  let result;
  try {
    slots = streamRowSlots(production, expected);
    localSlots = streamRowSlots(local, expected);
    result = comparison ?? compareStreamReceipts({ production, local, expected });
    if (!object(result) || !STREAM_ROW_CLASSIFICATIONS.includes(result.classification)) fail('comparison has no classification');
  } catch (error) {
    return { classification: 'INDETERMINATE', rowCount: 0, counts: tally([]), positiveAgreement: 0, unattributedDeviations: 0, reason: error.message, rows: [] };
  }
  if (slots.length !== localSlots.length) return indeterminate(slots, 'sides enumerate a different number of data rows');
  if (result.classification === 'INDETERMINATE') return indeterminate(slots, 'a side failed the comparator proof');

  const deviations = (result.reasons?.production?.length ?? 0) + (result.reasons?.local?.length ?? 0);
  let contentDiffers = () => false;
  if (result.classification === 'SEMANTIC_MISMATCH') {
    if (deviations > 0) return { ...indeterminate(slots, 'semantic deviations are not attributable to a single row'), unattributedDeviations: deviations };
    let flatProduction;
    let flatLocal;
    try {
      flatProduction = flattenStreamProjection(result.differences?.production);
      flatLocal = flattenStreamProjection(result.differences?.local);
    } catch (error) {
      return indeterminate(slots, error.message);
    }
    if (flatProduction.length !== slots.length || flatLocal.length !== slots.length) return indeterminate(slots, 'projection rows do not align with receipt rows');
    contentDiffers = i => !equal(flatProduction[i], flatLocal[i]);
  }

  const rows = slots.map(({ index, phase, role, slot }) => ({
    index,
    phase,
    ...(role === undefined ? {} : { role }),
    classification: contentDiffers(index)
      ? 'SEMANTIC_MISMATCH'
      : equal(slot, localSlots[index].slot) ? 'MATCH' : 'EXPECTED_NONDETERMINISM',
  }));
  const counts = tally(rows);

  // Fail closed rather than report counts that contradict the comparator.
  const consistent = result.classification === 'MATCH'
    ? counts.MATCH === rows.length
    : result.classification === 'EXPECTED_NONDETERMINISM'
      ? counts.SEMANTIC_MISMATCH === 0 && counts.EXPECTED_NONDETERMINISM > 0
      : counts.SEMANTIC_MISMATCH > 0;
  if (!consistent) return indeterminate(slots, 'row verdicts contradict the whole-comparison classification');

  return {
    classification: result.classification,
    rowCount: rows.length,
    counts,
    positiveAgreement: counts.MATCH + counts.EXPECTED_NONDETERMINISM,
    unattributedDeviations: deviations,
    rows,
  };
};
