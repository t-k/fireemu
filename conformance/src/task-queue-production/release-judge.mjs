// The judge of the task queue release run (R38 of release-strict-regression.mjs): the comparisons the binary under test produced
// against the committed ones. Pure.
//
// Timing is never equal twice, so unlike the Hosting judge this one does not demand equal documents. For a strict comparison it
// demands the same cases, the same structure verdict and parts (the known-difference ids included) in every row, no mismatch, no
// unknown and no timing outside the tolerance it was computed at (the release replay computes at twice the committed tolerance,
// as strict-replay.test.mjs does, because a loaded runner delays a process start by more than a second), and both concurrency
// properties MATCH. The comparison of the two production runs does not depend on the binary and must equal the committed one.
import { isDeepStrictEqual } from "node:util";

export const EXPORT_KIND = "task-queue-comparison-v1-export";
/** The factor of the committed tolerance the release replay computes at. */
export const TOLERANCE_FACTOR = 2;

const isRunComparison = (path) => path.endsWith("-run-comparison.json");

/**
 * @param {string} path the repository path of the committed comparison
 * @param {object} expected the committed comparison
 * @param {object|undefined} observed the export of `release-replay.mjs`
 * @param {{ binarySha256: string }} context
 * @returns {string[]} the differences, empty when the binary reproduces the committed document
 */
export function judgeTaskQueue(path, expected, observed, context) {
  if (observed === undefined) return [`${path}: R38 produced no export`];
  const differences = [];
  if (observed.kind !== EXPORT_KIND) differences.push("the export kind differs");
  if (observed.binarySha256 !== context.binarySha256) {
    differences.push("the export names another binary than the one under test");
  }
  const actual = observed.documents?.[path];
  if (actual === undefined) return [...differences, `${path}: not in the export`];
  if (isRunComparison(path)) {
    if (!isDeepStrictEqual(actual, expected)) {
      differences.push(
        `${path}: the comparison of the two recordings differs from the committed one`,
      );
    }
    return differences;
  }
  if (actual.kind !== expected.kind) differences.push(`${path}: the document kind differs`);
  if (actual.summary?.structure?.MISMATCH || actual.summary?.structure?.UNKNOWN) {
    differences.push(`${path}: the replay has a mismatch or an unknown row`);
  }
  if (actual.summary?.timing?.OUTSIDE)
    differences.push(`${path}: the replay has a timing outside the tolerance`);
  const tolerance = expected.tolerance;
  if (
    !tolerance ||
    actual.tolerance?.firstMs !== tolerance.firstMs * TOLERANCE_FACTOR ||
    actual.tolerance?.gapMs !== tolerance.gapMs * TOLERANCE_FACTOR
  ) {
    differences.push(
      `${path}: the replay was not computed at ${TOLERANCE_FACTOR} times the committed tolerance`,
    );
  }
  if (
    !Array.isArray(actual.properties) ||
    actual.properties.length !== expected.properties.length ||
    actual.properties.some((p) => p.verdict !== "MATCH")
  ) {
    differences.push(`${path}: a concurrency property differs`);
  }
  if (
    !isDeepStrictEqual(actual.left, expected.left) ||
    !isDeepStrictEqual(actual.right?.corpusSha256, expected.right?.corpusSha256)
  ) {
    differences.push(`${path}: the replay compares other recordings or another corpus`);
  }
  const cases = (document) => document.rows?.map((row) => row.case) ?? [];
  if (!isDeepStrictEqual(cases(actual), cases(expected))) {
    differences.push(`${path}: the cases differ from the committed ones`);
    return differences;
  }
  for (const [index, row] of expected.rows.entries()) {
    const seen = actual.rows[index];
    if (seen.structure !== row.structure)
      differences.push(
        `${path}: ${row.case}: structure ${seen.structure}, committed ${row.structure}`,
      );
    else if (!isDeepStrictEqual(seen.parts, row.parts))
      differences.push(`${path}: ${row.case}: the parts differ from the committed ones`);
  }
  return differences;
}
