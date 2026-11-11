// The judge of the Hosting release run (R37 of release-strict-regression.mjs): the comparison the
// binary under test produced against the committed one. Pure.
import { isDeepStrictEqual } from "node:util";

/**
 * @param {string} path the repository path of the committed comparison
 * @param {object} expected the committed comparison
 * @param {object|undefined} observed the export of `release-replay.mjs`
 * @param {{ binarySha256: string }} context
 * @returns {string[]} the differences, empty when the binary reproduces the committed document
 */
export function judgeHosting(path, expected, observed, context) {
  if (observed === undefined) return [`${path}: R37 produced no export`];
  const differences = [];
  if (observed.kind !== "hosting-comparison-v1-export") differences.push("the export kind differs");
  if (observed.binarySha256 !== context.binarySha256) {
    differences.push("the export names another binary than the one under test");
  }
  const actual = observed.documents?.[path];
  if (actual === undefined) return [...differences, `${path}: not in the export`];
  if (actual.summary?.MISMATCH !== 0 || actual.summary?.UNKNOWN !== 0) {
    differences.push(`${path}: the replay has a mismatch or an unknown row`);
  }
  if (!isDeepStrictEqual(actual, expected)) {
    differences.push(`${path}: differs from the committed comparison`);
  }
  return differences;
}
