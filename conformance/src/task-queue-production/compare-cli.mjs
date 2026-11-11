// Builds the committed comparisons from the masked recordings:
//   node compare-cli.mjs runs <out>                       the two recordings against each other
//   node compare-cli.mjs strict <local.json> <pass> <out> a local replay (local.mjs) against one recording
// An output file that exists is never overwritten.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compareProjections } from "./compare.mjs";
import { KNOWN_DIFFERENCES, NO_TIMING_CLAIM } from "./known-differences.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
export const RECORDINGS = Object.freeze({
  "pass-1": root + "task-queue-production-pass-1.json",
  "pass-2": root + "task-queue-production-pass-2.json",
});
const load = (path) => JSON.parse(readFileSync(path, "utf8"));

/** Two production runs against each other: only the layouts that vary between runs are hidden, no known difference applies. */
export const compareRuns = (a, b) => compareProjections(a, b, { noTimingClaim: NO_TIMING_CLAIM });

/** fireemu against a recording: the known differences apply. */
export const compareStrict = (local, recording, { tolerance } = {}) =>
  compareProjections(recording, local, {
    noTimingClaim: NO_TIMING_CLAIM,
    knownDifferences: KNOWN_DIFFERENCES,
    // A queue with maxAttempts 100 keeps retrying until the run ends: the attempts compared are the first ones both sides made.
    attemptJitter: { "window-six": 100 },
    ...(tolerance ? { tolerance } : {}),
  });

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  if (command === "runs") {
    const [out] = args;
    writeFileSync(
      out,
      JSON.stringify(compareRuns(load(RECORDINGS["pass-1"]), load(RECORDINGS["pass-2"])), null, 2) +
        "\n",
      { flag: "wx" },
    );
  } else if (command === "strict") {
    const [localPath, pass, out] = args;
    writeFileSync(
      out,
      JSON.stringify(compareStrict(load(localPath), load(RECORDINGS[pass])), null, 2) + "\n",
      { flag: "wx" },
    );
  } else throw new Error("runs <out> | strict <local.json> <pass-1|pass-2> <out>");
}
