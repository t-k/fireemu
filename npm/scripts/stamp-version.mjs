#!/usr/bin/env node
// Stamps a release version over the `0.0.0-dev` placeholders.
//
//   node npm/scripts/stamp-version.mjs 1.2.3
//   node npm/scripts/stamp-version.mjs --from-tag v1.2.3
//   node npm/scripts/stamp-version.mjs --from-tag v1.2.3 --print   # say what it would do
//
// The repository never carries a real version: `npm/fireemu/package.json` and every generated
// platform manifest say `0.0.0-dev`, so nothing in the tree can drift out of step with a tag
// and no commit is needed to cut a release. The release workflow runs this once, after the
// platform packages are assembled, and every manifest it touches -- the launcher, its
// `optionalDependencies` pins, and each platform package -- comes out carrying the same
// version. Pinning the optional dependencies exactly is what makes an install reproducible:
// `fireemu@1.2.3` can only ever pull `@fireemu/linux-x64@1.2.3`.

import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { PLATFORMS, packageName } from "../platforms/platforms.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** A release version: `1.2.3`, optionally with a prerelease and build suffix. */
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** The version a tag names, with the leading `v` removed. Rejects anything that is not semver. */
export function versionFromTag(tag) {
  const version = tag.startsWith("v") ? tag.slice(1) : tag;
  if (!SEMVER.test(version)) {
    throw new Error(`${tag} is not a release tag; expected something like v1.2.3`);
  }
  return version;
}

function parseArgs(argv) {
  const out = { print: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--print") out.print = true;
    else if (arg === "--from-tag") out.version = versionFromTag(argv[++i] ?? "");
    else if (arg.startsWith("--")) throw new Error(`unknown flag ${arg}`);
    else out.version = versionFromTag(arg);
  }
  if (!out.version) throw new Error("a version is required: stamp-version.mjs 1.2.3");
  return out;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, undefined, 2)}\n`);
}

/** Every generated platform manifest under `npm/platforms/build/`, if any were assembled. */
function builtPlatformManifests(buildDir) {
  if (!statSync(buildDir, { throwIfNoEntry: false })?.isDirectory()) return [];
  const names = new Set(PLATFORMS.map((p) => p.name));
  return readdirSync(buildDir)
    .filter((entry) => names.has(entry))
    .map((entry) => join(buildDir, entry, "package.json"))
    .filter((path) => statSync(path, { throwIfNoEntry: false })?.isFile());
}

/** Stamps `version` everywhere. Returns the paths it changed. */
export function stamp(version, { print = false, root = repoRoot } = {}) {
  const changed = [];
  const launcherPath = join(root, "npm", "fireemu", "package.json");
  const launcher = readJson(launcherPath);
  launcher.version = version;
  // Rewritten from the platform table rather than edited in place, so adding a platform to
  // `platforms.mjs` cannot leave the launcher advertising the old set.
  launcher.optionalDependencies = Object.fromEntries(
    PLATFORMS.map((platform) => [packageName(platform), version]),
  );
  if (!print) writeJson(launcherPath, launcher);
  changed.push(launcherPath);

  for (const path of builtPlatformManifests(join(root, "npm", "platforms", "build"))) {
    const manifest = readJson(path);
    manifest.version = version;
    if (!print) writeJson(path, manifest);
    changed.push(path);
  }
  return changed;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const changed = stamp(args.version, { print: args.print });
  const verb = args.print ? "would stamp" : "stamped";
  for (const path of changed) {
    process.stdout.write(`${verb} ${args.version}: ${path}\n`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
