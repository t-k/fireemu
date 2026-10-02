// Temporary directories for node:test files that are removed when the test (or, at module level,
// the file) ends, also when it fails. Tests used to call mkdtemp and leave the directory behind;
// the selftest alone left about 190 entries in the temp directory per run.

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after } from "node:test";
import { removeTree } from "./remove-tree.mjs";

export { removeTree };

/**
 * Creates `<temp dir>/<prefix>XXXXXX` and registers its removal with node:test's `after`: called
 * inside a test, the directory is removed when that test ends; at module level, when the file
 * ends.
 */
export function tempDir(prefix) {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  after(() => removeTree(directory));
  return directory;
}
