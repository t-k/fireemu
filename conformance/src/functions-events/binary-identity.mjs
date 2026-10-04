// The identity of the fireemu binary a local event run executed. run.mjs hashes the file it spawns, the child session writes the
// identity into session.json, and compare-cli refuses sessions that name different binaries or a binary other than the artifact
// it is asked to compare: no digest is typed in without a check.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const ENV = {
  binarySha256: "FE_EVENTS_BINARY_SHA256",
  sourceCommit: "FE_EVENTS_SOURCE_COMMIT",
  dirty: "FE_EVENTS_TREE_DIRTY",
  runnerPath: "FE_EVENTS_RUNNER_PATH",
  runnerSha256: "FE_EVENTS_RUNNER_SHA256",
  runnerTree: "FE_EVENTS_RUNNER_TREE",
};
const RUNNER_DIR = "tools/runner-node";

const refuse = (message) => {
  throw new Error(`binary identity: ${message}`);
};

const defaultGit = (args, cwd) => execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8" });

/**
 * What a local event run executed: the sha256 of the binary file, the commit of the checkout the harness runs from, whether that
 * tree has uncommitted changes, and the Node runner that runs the functions: its path and the sha256 of its `index.mjs` and the
 * git tree id of `tools/runner-node` at that commit. The daemon finds its runner by walking up from the binary (a binary kept
 * under another checkout finds that checkout's runner), so run.mjs pins it to this checkout's runner with FIREEMU_RUNNER_NODE.
 */
export function identityOf({ binary, repoRoot, git = (args) => defaultGit(args, repoRoot) }) {
  const binarySha256 = createHash("sha256").update(readFileSync(binary)).digest("hex");
  const sourceCommit = git(["rev-parse", "HEAD"]).trim();
  if (!HEX40.test(sourceCommit))
    throw new Error("binary identity: the source commit is not a commit");
  const dirty = git(["status", "--porcelain", "--ignored=no"]).trim() !== "";
  const runnerPath = join(repoRoot, RUNNER_DIR, "index.mjs");
  const runnerSha256 = createHash("sha256").update(readFileSync(runnerPath)).digest("hex");
  const runnerTree = git(["rev-parse", `HEAD:${RUNNER_DIR}`]).trim();
  if (!HEX40.test(runnerTree))
    throw new Error("binary identity: the runner tree is not a git tree");
  return { binarySha256, sourceCommit, dirty, runnerPath, runnerSha256, runnerTree };
}

export function identityEnv({
  binarySha256,
  sourceCommit,
  dirty,
  runnerPath,
  runnerSha256,
  runnerTree,
}) {
  return {
    [ENV.binarySha256]: binarySha256,
    [ENV.sourceCommit]: sourceCommit,
    [ENV.dirty]: dirty ? "1" : "0",
    [ENV.runnerPath]: runnerPath,
    [ENV.runnerSha256]: runnerSha256,
    [ENV.runnerTree]: runnerTree,
  };
}

/** The identity run.mjs put into the environment, or a refusal: a session never runs without knowing its binary. */
export function identityFromEnv(env) {
  const binarySha256 = env[ENV.binarySha256];
  const sourceCommit = env[ENV.sourceCommit];
  const dirty = env[ENV.dirty];
  const runnerPath = env[ENV.runnerPath];
  const runnerSha256 = env[ENV.runnerSha256];
  const runnerTree = env[ENV.runnerTree];
  if (!HEX64.test(binarySha256 ?? "")) refuse("the binary sha256 is missing or not lowercase hex");
  if (!HEX40.test(sourceCommit ?? "")) refuse("the source commit is missing or not a commit");
  if (dirty !== "0" && dirty !== "1") refuse("the tree state is missing");
  if (typeof runnerPath !== "string" || !isAbsolute(runnerPath))
    refuse("the runner path is missing or not absolute");
  if (!HEX64.test(runnerSha256 ?? "")) refuse("the runner sha256 is missing or not lowercase hex");
  if (!HEX40.test(runnerTree ?? "")) refuse("the runner tree is missing or not a git tree");
  return { binarySha256, sourceCommit, dirty: dirty === "1", runnerPath, runnerSha256, runnerTree };
}

function ownIdentity(session, profile) {
  const found = session?.fireemu;
  if (found === null || typeof found !== "object" || Array.isArray(found))
    throw new Error(
      `binary identity: the ${profile} session names no binary (rerun it with run.mjs)`,
    );
  if (!HEX64.test(found.binarySha256 ?? ""))
    refuse(`the ${profile} session's binary sha256 is not lowercase hex`);
  if (!HEX40.test(found.sourceCommit ?? ""))
    refuse(`the ${profile} session's source commit is not a commit`);
  if (typeof found.dirty !== "boolean")
    refuse(`the ${profile} session's tree state is not a boolean`);
  return found;
}

/**
 * Both sessions' identities, or a refusal: each names its binary, the two name the same binary, the same harness commit and the
 * same tree state, and that binary is `artifactSha256`.
 */
export function checkSessionIdentities({ emulator, strict }, artifactSha256) {
  const a = ownIdentity(emulator, "emulator");
  const b = ownIdentity(strict, "strict");
  if (a.binarySha256 !== b.binarySha256)
    refuse("the emulator and strict sessions ran different binaries");
  if (a.sourceCommit !== b.sourceCommit)
    refuse("the emulator and strict sessions ran from different harness commits");
  if (a.dirty !== b.dirty)
    refuse("the emulator and strict sessions ran from different tree states");
  if (
    a.runnerPath !== b.runnerPath ||
    a.runnerSha256 !== b.runnerSha256 ||
    a.runnerTree !== b.runnerTree
  )
    refuse("the emulator and strict sessions ran different runners");
  if (a.binarySha256 !== artifactSha256)
    refuse("the binary the sessions ran is not the artifact the comparison names");
  return {
    sha256: a.binarySha256,
    sourceCommit: a.sourceCommit,
    dirty: a.dirty,
    runnerPath: a.runnerPath,
    runnerSha256: a.runnerSha256,
    runnerTree: a.runnerTree,
  };
}
