import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { changelogSection } from "./changelog-section.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..", "..");
const script = join(scriptDir, "changelog-section.mjs");

const CHANGELOG = `# Changelog

Intro text.

## [Unreleased]

## [1.2.0] - 2026-01-02

### Added

- Feature A.

### Fixed

- Bug B.

## [1.10.0-rc.1] - 2026-01-01

- A prerelease.

## [1.1.0] - 2025-12-31

- Older.

## [1.0.0] - 2025-12-30

- The last section.

[Unreleased]: https://example.invalid/compare/v1.2.0...HEAD
[1.2.0]: https://example.invalid/compare/v1.1.0...v1.2.0
`;

test("extracts the body of a version's section without its heading", () => {
  assert.equal(changelogSection(CHANGELOG, "1.2.0"), "### Added\n\n- Feature A.\n\n### Fixed\n\n- Bug B.\n");
});

test("stops at the next second-level heading, not at a third-level one", () => {
  const section = changelogSection(CHANGELOG, "1.2.0");
  assert.ok(section.includes("### Fixed"));
  assert.ok(!section.includes("1.10.0-rc.1"));
});

test("a version is matched exactly, so 1.1.0 is not confused with 1.10.0-rc.1", () => {
  assert.equal(changelogSection(CHANGELOG, "1.1.0"), "- Older.\n");
  assert.equal(changelogSection(CHANGELOG, "1.10.0-rc.1"), "- A prerelease.\n");
});

test("a version that is only a prefix of another heading's label does not match", () => {
  const changelog = "## [1.1.0-rc.1] - 2026-01-01\n\n- Candidate.\n";
  assert.throws(() => changelogSection(changelog, "1.1.0"), /no section/);
  assert.throws(() => changelogSection("## [1.0.0]junk\n\n- Body.\n", "1.0.0"), /no section/);
});

test("the last section stops before the link reference definitions", () => {
  assert.equal(changelogSection(CHANGELOG, "1.0.0"), "- The last section.\n");
});

test("the version is not a pattern: dots do not match other characters", () => {
  const changelog = "## [1x2x0] - 2026-01-01\n\n- Wrong.\n";
  assert.throws(() => changelogSection(changelog, "1.2.0"), /no section/);
});

test("a missing section is an error naming the version", () => {
  assert.throws(() => changelogSection(CHANGELOG, "9.9.9"), /no section for 9\.9\.9/);
});

test("an empty section is an error", () => {
  assert.throws(() => changelogSection(CHANGELOG, "unreleased"), /no section/);
  const empty = "## [1.0.0] - 2026-01-01\n\n\n## [0.9.0] - 2026-01-01\n\n- Body.\n";
  assert.throws(() => changelogSection(empty, "1.0.0"), /section for 1\.0\.0 in CHANGELOG\.md is empty/);
  const onlyLinks = "## [1.0.0] - 2026-01-01\n\n[1.0.0]: https://example.invalid\n";
  assert.throws(() => changelogSection(onlyLinks, "1.0.0"), /section for 1\.0\.0 in CHANGELOG\.md is empty/);
});

test("a duplicated heading is an error rather than a silent first match", () => {
  const duplicated = "## [1.0.0] - 2026-01-01\n\n- One.\n\n## [1.0.0] - 2026-01-02\n\n- Two.\n";
  assert.throws(() => changelogSection(duplicated, "1.0.0"), /more than one section for 1\.0\.0/);
});

test("a heading without a date still matches, and one inside a code fence does not", () => {
  assert.equal(changelogSection("## [2.0.0]\n\n- Body.\n", "2.0.0"), "- Body.\n");
  const fenced = "## [2.0.0] - 2026-01-01\n\n```\n## [3.0.0] - 2026-01-02\n```\n\n- Body.\n";
  assert.equal(changelogSection(fenced, "2.0.0"), "```\n## [3.0.0] - 2026-01-02\n```\n\n- Body.\n");
  assert.throws(() => changelogSection(fenced, "3.0.0"), /no section/);
});

test("CRLF line endings yield LF notes", () => {
  assert.equal(changelogSection("## [1.0.0] - 2026-01-01\r\n\r\n- Body.\r\n", "1.0.0"), "- Body.\n");
});

test("the command line writes the section to a file and exits 0", () => {
  const dir = mkdtempSync(join(tmpdir(), "changelog-section-"));
  try {
    const changelog = join(dir, "CHANGELOG.md");
    const out = join(dir, "notes.md");
    writeFileSync(changelog, CHANGELOG);
    const run = spawnSync("node", [script, "1.2.0", "--changelog", changelog, "--out", out], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(readFileSync(out, "utf8"), "### Added\n\n- Feature A.\n\n### Fixed\n\n- Bug B.\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the command line fails, writing no file, when the section is missing or empty", () => {
  const dir = mkdtempSync(join(tmpdir(), "changelog-section-"));
  try {
    const changelog = join(dir, "CHANGELOG.md");
    const out = join(dir, "notes.md");
    writeFileSync(changelog, `${CHANGELOG}`);
    const missing = spawnSync("node", [script, "9.9.9", "--changelog", changelog, "--out", out], { encoding: "utf8" });
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /no section for 9\.9\.9/);
    writeFileSync(changelog, "## [1.0.0] - 2026-01-01\n\n\n## [0.9.0] - 2026-01-01\n\n- Body.\n");
    const empty = spawnSync("node", [script, "1.0.0", "--changelog", changelog, "--out", out], { encoding: "utf8" });
    assert.notEqual(empty.status, 0);
    assert.match(empty.stderr, /is empty/);
    assert.throws(() => readFileSync(out), /ENOENT/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the command line accepts a tag and rejects anything that is not a release version", () => {
  const dir = mkdtempSync(join(tmpdir(), "changelog-section-"));
  try {
    const changelog = join(dir, "CHANGELOG.md");
    const out = join(dir, "notes.md");
    writeFileSync(changelog, CHANGELOG);
    const tag = spawnSync("node", [script, "v1.2.0", "--changelog", changelog, "--out", out], { encoding: "utf8" });
    assert.equal(tag.status, 0, tag.stderr);
    const bad = spawnSync("node", [script, "main", "--changelog", changelog, "--out", out], { encoding: "utf8" });
    assert.notEqual(bad.status, 0);
    assert.match(bad.stderr, /not a release/);
    const none = spawnSync("node", [script], { encoding: "utf8" });
    assert.notEqual(none.status, 0);
    assert.match(none.stderr, /usage/);
    const versionOnly = spawnSync("node", [script, "1.2.0", "--changelog", changelog], { encoding: "utf8" });
    assert.match(versionOnly.stderr, /usage/);
    const outOnly = spawnSync("node", [script, "--out", out], { encoding: "utf8" });
    assert.match(outOnly.stderr, /usage/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the repository's own CHANGELOG has a non-empty section for every released version", () => {
  const changelog = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8");
  const versions = [...changelog.matchAll(/^## \[(\d+\.\d+\.\d+)\]/gm)].map(match => match[1]);
  assert.ok(versions.length > 0);
  for (const version of versions) {
    assert.ok(changelogSection(changelog, version).trim().length > 0, version);
  }
});
