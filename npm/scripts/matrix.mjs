#!/usr/bin/env node
// Prints the release build matrix as one line of JSON, for a GitHub Actions job output.
//
//   node npm/scripts/matrix.mjs
//
// The workflow reads its matrix from here rather than repeating the platform list in YAML, so
// `platforms.mjs` stays the only place a platform is declared. Adding one is a single row.

import { PLATFORMS, packageName } from "../platforms/platforms.mjs";

const matrix = PLATFORMS.map((platform) => ({
  name: platform.name,
  package: packageName(platform),
  os: platform.os,
  cpu: platform.cpu,
  target: platform.target,
  exe: platform.exe,
  runner: platform.runner,
  // A cross-compiled target cannot run its own tests; the host it is built on runs them for
  // the same source. Only `darwin-x64` is in this position today.
  cross: platform.cross,
}));

process.stdout.write(`${JSON.stringify(matrix)}\n`);
