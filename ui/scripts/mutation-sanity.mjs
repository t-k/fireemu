import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Stryker } from "@stryker-mutator/core";
import { assessSanity } from "./mutation-sanity-result.mjs";

// Use the normal runner/configuration but a bounded, known behavior-changing selection.
process.chdir(fileURLToPath(new URL("../", import.meta.url)));
const source = readFileSync("src/lib/unsaved.tsx", "utf8");
const anchor = "if (guard) guard.request(() => next(index + 1));";
const lines = source.split("\n");
const matches = lines.flatMap((line, index) => (line.trim() === anchor ? [index] : []));
if (matches.length !== 1) {
  throw new Error("Scope-transition sanity anchor changed; review the mutant selection.");
}
const line = matches[0] + 1;
const mutants = await new Stryker({
  mutate: [`src/lib/unsaved.tsx:${line}:0-${line}:${lines[line - 1].length}`],
  concurrency: 1,
  reporters: ["clear-text", "json"],
  jsonReporter: { fileName: "test-results/mutation-sanity.json" },
  tempDirName: "test-results/.stryker-sanity-tmp",
}).runMutationTest();
const result = assessSanity(mutants);
if (result.isErr()) {
  console.error(result.error);
  process.exitCode = 1;
} else {
  console.log(`Mutation sanity passed: ${result.value} scope-transition mutants killed.`);
}
