import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { checkoutMatches, computePins, gitOutput, CLOSURE_SPEC } from "./pins.mjs";
import { loadPrivateInputs } from "./private-inputs.mjs";

// Prints the pins an approval must record for the code checked out here (a clean tree at its commit, with no untracked or ignored
// runner file) and one private inputs file: sourceCommit, runnerSha256, manifestSha256 and fixtureSchemaSha256, as JSON on stdout.
// It reads local files and runs `git` for reads only; nothing is sent.
// Usage: node print-pins.mjs <absolute path of the private inputs file>

/** The command, with its collaborators injected; returns the exit code. */
export async function runPrintPins({ args, codeRoot, git = gitOutput, out, err }) {
  const [inputsPath, ...extra] = args;
  if (typeof inputsPath !== "string" || extra.length > 0) { err("usage: node print-pins.mjs <private inputs file>\n"); return 2; }
  try {
    const inputs = await loadPrivateInputs({ path: inputsPath });
    const closure = JSON.parse(readFileSync(resolve(codeRoot, CLOSURE_SPEC), "utf8"));
    const sourceCommit = (await git(codeRoot, ["rev-parse", "HEAD"])).trim();
    // The pins of a tree that has a change, an untracked module or an ignored file could not be recomputed from the commit: refuse.
    const state = await checkoutMatches({ root: codeRoot, sourceCommit, git });
    if (!state.ok) throw new Error(state.reason);
    out(`${JSON.stringify(await computePins({ inputs, closure, sourceCommit, codeRoot }), null, 2)}\n`);
    return 0;
  } catch (error) {
    err(`${error?.message ?? "failed"}\n`);
    return 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const codeRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  process.exitCode = await runPrintPins({ args: process.argv.slice(2), codeRoot, out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text) });
}
