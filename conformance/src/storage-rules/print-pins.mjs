import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { computePins, gitOutput, CLOSURE_SPEC } from "./pins.mjs";
import { loadPrivateInputs } from "./private-inputs.mjs";

// Prints the pins an approval must record for the code checked out here and one private inputs file: sourceCommit, runnerSha256,
// manifestSha256 and fixtureSchemaSha256, as JSON on stdout. It reads local files and runs `git rev-parse` only; nothing is sent.
// Usage: node print-pins.mjs <absolute path of the private inputs file>
const codeRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const [inputsPath, ...extra] = process.argv.slice(2);
if (typeof inputsPath !== "string" || extra.length > 0) { process.stderr.write("usage: node print-pins.mjs <private inputs file>\n"); process.exit(2); }
try {
  const inputs = await loadPrivateInputs({ path: inputsPath });
  const closure = JSON.parse(readFileSync(resolve(codeRoot, CLOSURE_SPEC), "utf8"));
  const sourceCommit = (await gitOutput(codeRoot, ["rev-parse", "HEAD"])).trim();
  process.stdout.write(`${JSON.stringify(await computePins({ inputs, closure, sourceCommit, codeRoot }), null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${error?.message ?? "failed"}\n`);
  process.exit(1);
}
