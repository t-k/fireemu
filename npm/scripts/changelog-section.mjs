#!/usr/bin/env node
// Extracts one version's section from CHANGELOG.md, to be the notes of its GitHub Release.
//
//   node npm/scripts/changelog-section.mjs 1.2.3 --out notes.md
//   node npm/scripts/changelog-section.mjs v1.2.3 --changelog CHANGELOG.md --out notes.md
//
// The section is what follows the `## [1.2.3]` heading, up to the next second-level heading
// or the link reference definitions at the end of the file. The release workflow runs this
// after the npm publish and refuses to create the Release when the section is missing or
// empty, so a version cannot be published with nothing written about it.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { versionFromTag } from "./stamp-version.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const HEADING = /^## \[([^\]]+)\](?:\s.*)?$/;
const SECOND_LEVEL = /^## /;
const LINK_DEFINITION = /^\[[^\]]+\]:\s/;
const FENCE = /^\s*(```|~~~)/;

/**
 * The notes for `version`: the section's body without its heading, ending in one newline.
 * Throws when the section is missing, duplicated or empty. The version is compared as text
 * against the heading's label, never used as a pattern.
 */
export function changelogSection(changelog, version) {
  const lines = changelog.replace(/\r\n/g, "\n").split("\n");
  const starts = [];
  let inFence = false;
  for (const [index, line] of lines.entries()) {
    if (FENCE.test(line)) inFence = !inFence;
    if (!inFence && HEADING.exec(line)?.[1] === version) starts.push(index);
  }
  if (starts.length === 0) throw new Error(`CHANGELOG.md has no section for ${version}`);
  if (starts.length > 1) throw new Error(`CHANGELOG.md has more than one section for ${version}`);

  const body = [];
  inFence = false;
  for (const line of lines.slice(starts[0] + 1)) {
    if (FENCE.test(line)) inFence = !inFence;
    if (!inFence && (SECOND_LEVEL.test(line) || LINK_DEFINITION.test(line))) break;
    body.push(line);
  }
  const text = body.join("\n").trim();
  if (text === "") throw new Error(`the section for ${version} in CHANGELOG.md is empty`);
  return `${text}\n`;
}

function parseArgs(argv) {
  const out = { changelog: resolve(repoRoot, "CHANGELOG.md") };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--changelog") out.changelog = resolve(argv[++i] ?? "");
    else if (arg === "--out") out.out = resolve(argv[++i] ?? "");
    else if (arg.startsWith("--")) throw new Error(`unknown flag ${arg}`);
    else out.version = versionFromTag(arg);
  }
  if (!out.version || !out.out) {
    throw new Error("usage: changelog-section.mjs <version> --out <file> [--changelog <file>]");
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const notes = changelogSection(readFileSync(args.changelog, "utf8"), args.version);
  writeFileSync(args.out, notes);
  process.stdout.write(`wrote the ${args.version} section (${notes.split("\n").length - 1} lines) to ${args.out}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    process.stderr.write(`changelog-section: ${e.message}\n`);
    process.exit(1);
  }
}
