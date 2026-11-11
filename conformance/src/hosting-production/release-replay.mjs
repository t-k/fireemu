// The release rerun of the Hosting comparisons (R37 of release-strict-regression.mjs).
//
//   FIREEMU_BIN=<installed fireemu> node release-replay.mjs local --fireemu <fireemu> --export <new file>
//
// Serves the production corpus and the follow-up corpus with the strict profile under `productionExact` on the binary under
// test (a real fireemu process on loopback, nothing else), compares the answers with the committed
// production recordings (two of each corpus) and writes the six comparison documents it produced, keyed by the
// path of the committed file each one must equal, with the digest of the binary. It reads no
// credential and sends nothing to production.
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { comparisons, followupComparisons } from "./closure-evidence.mjs";
import { buildFollowupCorpus } from "./followup.mjs";
import { runLocal } from "./local.mjs";

/** The paths of the exported documents that have a mismatch or an unknown row. */
export function failedPaths(result) {
  return Object.entries(result.documents)
    .filter(([, document]) => document.summary.MISMATCH > 0 || document.summary.UNKNOWN > 0)
    .map(([path]) => path);
}

/** The exit code of the replay: nonzero when any exported document has a mismatch or an unknown row. */
export function exitCodeOf(result) {
  return failedPaths(result).length === 0 ? 0 : 1;
}

/** The value after `name` in `argv`, or `undefined` when the flag is absent or has no value. */
export function optionValue(argv, name) {
  const at = argv.indexOf(name);
  const value = at < 0 ? undefined : argv[at + 1];
  return value === undefined || value.startsWith("--") ? undefined : value;
}

/** Whether the command line is `local --fireemu <binary> --export <file>`. */
export function usageOk(argv) {
  return (
    argv[0] === "local" &&
    optionValue(argv, "--fireemu") !== undefined &&
    optionValue(argv, "--export") !== undefined
  );
}

/** The committed comparison documents, keyed by their repository path. */
export async function replay(binary) {
  const local = await runLocal({ binary, profile: "strict" });
  const followupLocal = await runLocal({
    binary,
    profile: "strict",
    corpus: buildFollowupCorpus(),
  });
  const directory = await mkdtemp(join(tmpdir(), "hosting-release-replay-"));
  try {
    const path = join(directory, "local.json");
    await writeFile(path, JSON.stringify(local));
    const followupPath = join(directory, "followup-local.json");
    await writeFile(followupPath, JSON.stringify(followupLocal));
    const documents = {
      ...(await comparisons(path)),
      ...(await followupComparisons(followupPath)),
    };
    return {
      kind: "hosting-comparison-v1-export",
      binarySha256: createHash("sha256")
        .update(await readFile(binary))
        .digest("hex"),
      documents: Object.fromEntries(
        Object.entries(documents).map(([name, document]) => [`conformance/${name}`, document]),
      ),
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const option = (name) => optionValue(process.argv, name);
  if (!usageOk(process.argv.slice(2))) {
    throw new Error("usage: release-replay.mjs local --fireemu <binary> --export <new file>");
  }
  const result = await replay(resolve(option("--fireemu")));
  await writeFile(resolve(option("--export")), `${JSON.stringify(result, null, 2)}\n`, {
    flag: "wx",
  });
  const failures = failedPaths(result);
  console.log(
    JSON.stringify({
      kind: result.kind,
      documents: Object.keys(result.documents),
      mismatched: failures,
    }),
  );
  process.exitCode = exitCodeOf(result);
}
