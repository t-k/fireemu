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
const LINK_DEFINITION = /^\[([^\]]+)\]:\s/;
const FENCE_OPENER = /^ {0,3}(`{3,}|~{3,})(.*)$/;

/**
 * Whether each line is inside a fenced code block, fence lines included. A fence closes on the
 * same character with at least as many characters as its opener (CommonMark), so a longer fence
 * may contain a shorter one and a backtick fence may contain tildes.
 *
 * @throws when a fence is still open at the end of the file, since everything after it would
 * be read as code.
 */
function fencedLines(lines) {
  const fenced = [];
  let open = null;
  for (const line of lines) {
    if (open === null) {
      const opener = FENCE_OPENER.exec(line);
      if (opener && !(opener[1][0] === "`" && opener[2].includes("`"))) {
        open = { character: opener[1][0], length: opener[1].length };
        fenced.push(true);
      } else {
        fenced.push(false);
      }
    } else {
      fenced.push(true);
      const closer = /^ {0,3}(`{3,}|~{3,})\s*$/.exec(line);
      if (closer && closer[1][0] === open.character && closer[1].length >= open.length) open = null;
    }
  }
  if (open !== null) throw new Error("CHANGELOG.md has a code fence that is never closed");
  return fenced;
}

/**
 * The notes for `version`: the section's body without its heading, ending in one newline.
 * Throws when the section is missing, duplicated or empty, or when a code fence is never closed.
 * The version is compared as text against the heading's label, never used as a pattern.
 *
 * The section runs to the next second-level heading. The link reference definitions that end
 * it (Keep a Changelog puts them after the last section) are not part of the notes; a
 * definition the notes use, from anywhere in the file, is appended so the link still renders on
 * the Release page. A definition in the middle of a section stays where it is.
 */
export function changelogSection(changelog, version) {
  const lines = changelog.replace(/\r\n/g, "\n").split("\n");
  const fenced = fencedLines(lines);
  const starts = [];
  for (const [index, line] of lines.entries()) {
    if (!fenced[index] && HEADING.exec(line)?.[1] === version) starts.push(index);
  }
  if (starts.length === 0) throw new Error(`CHANGELOG.md has no section for ${version}`);
  if (starts.length > 1) throw new Error(`CHANGELOG.md has more than one section for ${version}`);

  let end = lines.length;
  for (let index = starts[0] + 1; index < lines.length; index++) {
    if (!fenced[index] && SECOND_LEVEL.test(lines[index])) {
      end = index;
      break;
    }
  }
  const body = lines.slice(starts[0] + 1, end);
  while (body.length > 0 && (body.at(-1).trim() === "" || LINK_DEFINITION.test(body.at(-1)))) {
    body.pop();
  }
  while (body.length > 0 && body[0].trim() === "") body.shift();
  if (body.length === 0) throw new Error(`the section for ${version} in CHANGELOG.md is empty`);
  const text = body.join("\n").trimEnd();

  const definitions = lines.filter((line, index) => !fenced[index] && LINK_DEFINITION.test(line));
  const used = definitions.filter((line) => {
    if (body.includes(line)) return false;
    const label = LINK_DEFINITION.exec(line)[1].toLowerCase();
    return body.some((bodyLine) => !LINK_DEFINITION.test(bodyLine) && bodyLine.toLowerCase().includes(`[${label}]`));
  });
  return used.length === 0 ? `${text}\n` : `${text}\n\n${used.join("\n")}\n`;
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
