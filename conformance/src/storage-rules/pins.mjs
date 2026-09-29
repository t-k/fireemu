import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { open, readdir } from "node:fs/promises";
import { constants } from "node:fs";
import { join, posix } from "node:path";
import { buildRunManifest, manifestParams, TEMPLATE_RUN_ID } from "./run-manifest.mjs";

// What an approval's pins mean, recomputed from what is about to run. The ledger records five pins; the entry point refuses
// to start unless the running code and manifest reproduce the three that can be recomputed here and the checkout is at the
// pinned commit:
//   runnerSha256         every *.mjs file under conformance/src/storage-rules (recursively) plus the closure spec
//   fixtureSchemaSha256  the fixture, corpus and private-input definitions plus the closure spec
//   manifestSha256       the full request manifest of this run's bucket, projects, keys and commit built with a fixed template
//                        run ID, so both recordings an approval allows (which have different run IDs) reproduce the same pin
// A digest is sha256 over the lines `<path>\0<sha256 of the file>\n`, sorted by path. Paths are relative to the checkout root.
export const CLOSURE_SPEC = "spec/compatibility/closure/STORAGE-RULES.json";
export const RUNNER_DIR = "conformance/src/storage-rules";
export const FIXTURE_FILES = Object.freeze(["corpus.mjs", "rulesets.mjs", "fixture-proof.mjs", "private-inputs.mjs"].map((name) => `${RUNNER_DIR}/${name}`));
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const sha256 = (data) => createHash("sha256").update(data).digest("hex");

async function fileDigest(root, relative) {
  const handle = await open(join(root, relative), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new Error("pin source refused");
    return sha256(await handle.readFile());
  } finally { await handle.close(); }
}

async function listModules(root, relative) {
  const found = [];
  for (const entry of await readdir(join(root, relative), { withFileTypes: true })) {
    const path = posix.join(relative, entry.name);
    if (entry.isSymbolicLink()) throw new Error("pin source refused");
    if (entry.isDirectory()) found.push(...await listModules(root, path));
    else if (entry.isFile() && entry.name.endsWith(".mjs")) found.push(path);
  }
  return found;
}

async function digestOf(root, paths) {
  const lines = [];
  for (const path of [...paths].sort()) lines.push(`${path}\0${await fileDigest(root, path)}\n`);
  return sha256(lines.join(""));
}

/** The runner and fixture-schema pins of the code checked out at `root`. */
export async function codeDigests(root) {
  const modules = await listModules(root, RUNNER_DIR);
  if (modules.length === 0) throw new Error("pin source refused");
  return Object.freeze({
    runnerSha256: await digestOf(root, [...modules, CLOSURE_SPEC]),
    fixtureSchemaSha256: await digestOf(root, [...FIXTURE_FILES, CLOSURE_SPEC]),
  });
}

/**
 * The manifest pin: the digest of the manifest built from this run's own bucket, project numbers, key IDs and source commit
 * with a fixed template run ID, so both recordings an approval allows reproduce the same pin. The run's real manifest must
 * also rebuild to itself from the parameters its binding echoes.
 */
export function manifestPin(manifest, closure) {
  const params = manifestParams(manifest);
  if (buildRunManifest(closure, params).sha256 !== manifest.sha256) throw new Error("manifest does not rebuild from its binding");
  return buildRunManifest(closure, { ...params, runId: TEMPLATE_RUN_ID }).sha256;
}

/** The real git reader: `git -C <root> <args>` with a fixed environment, output capped. */
export function gitOutput(root, args) {
  return new Promise((resolve, reject) => {
    execFile("git", ["-C", root, ...args], { env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LC_ALL: "C", GIT_OPTIONAL_LOCKS: "0" }, maxBuffer: 1024 * 1024, timeout: 30_000 }, (error, stdout) => (error ? reject(new Error("git refused")) : resolve(stdout)));
  });
}

/** The checkout must be at the pinned commit with no change to a tracked file. */
export async function checkoutMatches({ root, sourceCommit, git = gitOutput }) {
  const head = (await git(root, ["rev-parse", "HEAD"])).trim();
  if (head !== sourceCommit) return { ok: false, reason: "source commit mismatch" };
  const changes = await git(root, ["status", "--porcelain", "--untracked-files=no"]);
  if (changes.trim() !== "") return { ok: false, reason: "working tree not clean" };
  return { ok: true };
}

