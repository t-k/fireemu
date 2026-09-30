import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkoutMatches, gitOutput } from "../storage-rules/pins.mjs";
import { MODES } from "./plan.mjs";
import { releaseCodeDigests } from "./pins.mjs";
import { corpusOf, readLocalInputs } from "./release-entry.mjs";

// Prints the pins the stage 2c approval must record for the code checked out here (a clean tree at its commit, with no untracked or
// ignored runner file) and the operator's local inputs file: sourceCommit, runnerSha256, manifestSha256 (the corpus digest) and
// fixtureSchemaSha256, as JSON on stdout. It reads local files and runs `git` for reads only; nothing is sent.
// Usage: node print-pins.mjs <pre|post> <absolute path of the local inputs file>
const RELEASE_DIR = "conformance/src/storage-rules-release";

/** The command, with its collaborators injected; returns the exit code. */
export async function runReleasePrintPins({ args, codeRoot, git = gitOutput, out, err }) {
  const [mode, localPath, ...extra] = args;
  if (!MODES.includes(mode) || typeof localPath !== "string" || extra.length > 0) { err("usage: node print-pins.mjs <pre|post> <local inputs file>\n"); return 2; }
  try {
    const local = await readLocalInputs(localPath, mode);
    const sourceCommit = (await git(codeRoot, ["rev-parse", "HEAD"])).trim();
    const state = await checkoutMatches({ root: codeRoot, sourceCommit, git });
    if (!state.ok) throw new Error(state.reason);
    if ((await git(codeRoot, ["status", "--porcelain", "--untracked-files=all", "--ignored", "--", RELEASE_DIR])).trim() !== "") throw new Error("untracked or ignored runner files");
    const digests = await releaseCodeDigests(codeRoot);
    const corpus = corpusOf(local);
    out(`${JSON.stringify({ sourceCommit, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256 }, null, 2)}\n`);
    return 0;
  } catch (error) {
    err(`${error?.message ?? "failed"}\n`);
    return 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const codeRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  process.exitCode = await runReleasePrintPins({ args: process.argv.slice(2), codeRoot, out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) });
}
