// Removes a temporary tree, also one a test made read-only. Shared by test-tmpdir.mjs and
// selftest-tmpdir.mjs; it does not import node:test, so a plain script can use it.

import { chmodSync, lstatSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

/**
 * Removes `path` and everything under it. Directories a test made read-only are made writable
 * again first; symbolic links are removed, never followed.
 */
export function removeTree(path) {
  try {
    rmSync(path, { recursive: true, force: true });
    return;
  } catch {
    // A read-only directory refused the removal of its entries.
  }
  makeOwnerWritable(path);
  rmSync(path, { recursive: true, force: true });
}

function makeOwnerWritable(path) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    return;
  }
  if (!stat.isDirectory()) return;
  chmodSync(path, stat.mode | 0o700);
  for (const name of readdirSync(path)) makeOwnerWritable(join(path, name));
}
