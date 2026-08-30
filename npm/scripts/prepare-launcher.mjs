#!/usr/bin/env node
// Puts the files the `fireemu` package publishes but does not own into `npm/fireemu/`.
//
//   node npm/scripts/prepare-launcher.mjs
//
// The package page (`npm/README.md`) and the licence live once in the repository and are
// copied in at pack time rather than duplicated, so there is no second copy to forget. Both
// copies are ignored by git; `npm pack` needs them on disk because `files` names them.

import { copyFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Copies the shared files into the launcher package. Returns what it wrote. */
export function prepareLauncher(root = repoRoot) {
  const launcher = join(root, "npm", "fireemu");
  const written = [];
  for (const [from, to] of [
    [join(root, "npm", "README.md"), join(launcher, "README.md")],
    [join(root, "LICENSE"), join(launcher, "LICENSE")],
  ]) {
    copyFileSync(from, to);
    written.push(to);
  }
  return written;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const path of prepareLauncher()) process.stdout.write(`${path}\n`);
}
