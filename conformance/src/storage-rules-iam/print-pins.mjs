import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkoutMatches, gitOutput } from "../storage-rules/pins.mjs";
import { readLocalInputs } from "./iam-grant.mjs";
import { iamCorpus } from "./plan.mjs";
import { iamCodeDigests } from "./pins.mjs";

// Prints the pins the stage 2b approval must record for the code checked out here (a clean tree at its commit, with no untracked or
// ignored runner file) and the operator's local inputs file: sourceCommit, runnerSha256, manifestSha256 (the corpus digest) and
// fixtureSchemaSha256, as JSON on stdout. It reads local files and runs `git` for reads only; nothing is sent.
// Usage: node print-pins.mjs <absolute path of the local inputs file>
const IAM_DIR = "conformance/src/storage-rules-iam";

/** The command, with its collaborators injected; returns the exit code. */
export async function runIamPrintPins({ args, codeRoot, git = gitOutput, out, err }) {
  const [localPath, ...extra] = args;
  if (typeof localPath !== "string" || extra.length > 0) { err("usage: node print-pins.mjs <local inputs file>\n"); return 2; }
  try {
    const local = await readLocalInputs(localPath);
    const sourceCommit = (await git(codeRoot, ["rev-parse", "HEAD"])).trim();
    const state = await checkoutMatches({ root: codeRoot, sourceCommit, git });
    if (!state.ok) throw new Error(state.reason);
    if ((await git(codeRoot, ["status", "--porcelain", "--untracked-files=all", "--ignored", "--", IAM_DIR])).trim() !== "") throw new Error("untracked or ignored runner files");
    const digests = await iamCodeDigests(codeRoot);
    const corpus = iamCorpus({ projectNumber: local.projectNumber, ownerEmailSha256: local.ownerEmailSha256 });
    out(`${JSON.stringify({ sourceCommit, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256 }, null, 2)}\n`);
    return 0;
  } catch (error) {
    err(`${error?.message ?? "failed"}\n`);
    return 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const codeRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  process.exitCode = await runIamPrintPins({ args: process.argv.slice(2), codeRoot, out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) });
}
