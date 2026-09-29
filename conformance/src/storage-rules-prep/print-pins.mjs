import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkoutMatches, gitOutput } from "../storage-rules/pins.mjs";
import { prepCorpus } from "./plan.mjs";
import { prepCodeDigests } from "./pins.mjs";
import { readLocalInputs } from "./prep-reads.mjs";

// Prints the pins the stage 2a approval must record for the code checked out here (a clean tree at its commit, with no untracked or
// ignored runner file) and the operator's local inputs file: sourceCommit, runnerSha256, manifestSha256 (the corpus digest) and
// fixtureSchemaSha256, as JSON on stdout. It reads local files and runs `git` for reads only; nothing is sent.
// Usage: node print-pins.mjs <absolute path of the local inputs file>
const CLOSURE_SPEC = "spec/compatibility/closure/STORAGE-RULES.json";
const PREP_DIR = "conformance/src/storage-rules-prep";

/** The command, with its collaborators injected; returns the exit code. */
export async function runPrepPrintPins({ args, codeRoot, git = gitOutput, out, err }) {
  const [localPath, ...extra] = args;
  if (typeof localPath !== "string" || extra.length > 0) { err("usage: node print-pins.mjs <local inputs file>\n"); return 2; }
  try {
    const local = await readLocalInputs(localPath);
    const closure = JSON.parse(readFileSync(resolve(codeRoot, CLOSURE_SPEC), "utf8"));
    const sourceCommit = (await git(codeRoot, ["rev-parse", "HEAD"])).trim();
    const state = await checkoutMatches({ root: codeRoot, sourceCommit, git });
    if (!state.ok) throw new Error(state.reason);
    if ((await git(codeRoot, ["status", "--porcelain", "--untracked-files=all", "--ignored", "--", PREP_DIR])).trim() !== "") throw new Error("untracked or ignored runner files");
    const digests = await prepCodeDigests(codeRoot);
    const corpus = prepCorpus(closure, { bucket: local.bucket, queryProjectNumber: local.numbers.query, idpProjectNumber: local.numbers.idp, sourceCommit, expectedKeyIds: local.keyIds });
    out(`${JSON.stringify({ sourceCommit, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256 }, null, 2)}\n`);
    return 0;
  } catch (error) {
    err(`${error?.message ?? "failed"}\n`);
    return 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const codeRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  process.exitCode = await runPrepPrintPins({ args: process.argv.slice(2), codeRoot, out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) });
}
