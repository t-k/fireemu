// The identity of the fireemu binary a local event run executed. run.mjs hashes the file it spawns, the child session writes the
// identity into session.json, and compare-cli refuses sessions that name different binaries or a binary other than the artifact
// it is asked to compare: no digest is typed in without a check.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const ENV = {
  binarySha256: "FE_EVENTS_BINARY_SHA256",
  sourceCommit: "FE_EVENTS_SOURCE_COMMIT",
  dirty: "FE_EVENTS_TREE_DIRTY",
};

const refuse = (message) => {
  throw new Error(`binary identity: ${message}`);
};

const defaultGit = (args, cwd) => execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8" });

/** sha256 of the binary file, the commit of the checkout the harness runs from, and whether that tree has uncommitted changes. */
export function identityOf({ binary, repoRoot, git = (args) => defaultGit(args, repoRoot) }) {
  const binarySha256 = createHash("sha256").update(readFileSync(binary)).digest("hex");
  const sourceCommit = git(["rev-parse", "HEAD"]).trim();
  if (!HEX40.test(sourceCommit))
    throw new Error("binary identity: the source commit is not a commit");
  const dirty = git(["status", "--porcelain", "--ignored=no"]).trim() !== "";
  return { binarySha256, sourceCommit, dirty };
}

export function identityEnv({ binarySha256, sourceCommit, dirty }) {
  return {
    [ENV.binarySha256]: binarySha256,
    [ENV.sourceCommit]: sourceCommit,
    [ENV.dirty]: dirty ? "1" : "0",
  };
}

/** The identity run.mjs put into the environment, or a refusal: a session never runs without knowing its binary. */
export function identityFromEnv(env) {
  const binarySha256 = env[ENV.binarySha256];
  const sourceCommit = env[ENV.sourceCommit];
  const dirty = env[ENV.dirty];
  if (!HEX64.test(binarySha256 ?? "")) refuse("the binary sha256 is missing or not lowercase hex");
  if (!HEX40.test(sourceCommit ?? "")) refuse("the source commit is missing or not a commit");
  if (dirty !== "0" && dirty !== "1") refuse("the tree state is missing");
  return { binarySha256, sourceCommit, dirty: dirty === "1" };
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
  if (a.binarySha256 !== artifactSha256)
    refuse("the binary the sessions ran is not the artifact the comparison names");
  return { sha256: a.binarySha256, sourceCommit: a.sourceCommit, dirty: a.dirty };
}
