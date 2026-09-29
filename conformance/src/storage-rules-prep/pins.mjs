import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readdir } from "node:fs/promises";
import { join, posix } from "node:path";

// The approval's pins for stage 2a, recomputed from what is about to run (the counterpart of storage-rules/pins.mjs; a copy so
// that module, which the stage 3 pins hash, stays untouched):
//   runnerSha256         every *.mjs file under conformance/src/storage-rules and conformance/src/storage-rules-prep, plus the closure spec
//   fixtureSchemaSha256  the private-input, preflight-classifier and plan modules, plus the closure spec
//   manifestSha256       the digest of the thirteen-request corpus (plan.mjs `prepCorpus`)
// A digest is sha256 over the lines `<path>\0<sha256 of the file>\n`, sorted by path, paths relative to the checkout root.
export const CLOSURE_SPEC = "spec/compatibility/closure/STORAGE-RULES.json";
export const RUNNER_DIRS = Object.freeze(["conformance/src/storage-rules", "conformance/src/storage-rules-prep"]);
export const SCHEMA_FILES = Object.freeze(["conformance/src/storage-rules/private-inputs.mjs", "conformance/src/storage-rules/acceptance-preflight.mjs", "conformance/src/storage-rules/acceptance-core.mjs", "conformance/src/storage-rules-prep/plan.mjs"]);
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const refused = () => new Error("pin source refused");

async function fileDigest(root, relative) {
  const handle = await open(join(root, relative), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw refused();
    return sha256(await handle.readFile());
  } finally { await handle.close(); }
}

async function listModules(root, relative) {
  const found = [];
  for (const entry of await readdir(join(root, relative), { withFileTypes: true })) {
    const path = posix.join(relative, entry.name);
    if (entry.isSymbolicLink()) throw refused();
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
export async function prepCodeDigests(root) {
  const modules = [];
  for (const dir of RUNNER_DIRS) {
    const found = await listModules(root, dir);
    if (found.length === 0) throw refused();
    modules.push(...found);
  }
  return Object.freeze({ runnerSha256: await digestOf(root, [...modules, CLOSURE_SPEC]), fixtureSchemaSha256: await digestOf(root, [...SCHEMA_FILES, CLOSURE_SPEC]) });
}
