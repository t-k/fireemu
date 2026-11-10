// The release rerun of the Hosting comparisons (R37 of release-strict-regression.mjs).
//
//   FIREEMU_BIN=<installed fireemu> node release-replay.mjs local --fireemu <fireemu> --export <new file>
//
// Serves the production corpus with the strict profile under `productionExact` on the binary under
// test (a real fireemu process on loopback, nothing else), compares the answers with the two
// committed production recordings and writes the three comparison documents it produced, keyed by the
// path of the committed file each one must equal, with the digest of the binary. It reads no
// credential and sends nothing to production.
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { comparisons } from "./closure-evidence.mjs";
import { runLocal } from "./local.mjs";

/** The committed comparison documents, keyed by their repository path. */
export async function replay(binary) {
  const local = await runLocal({ binary, profile: "strict" });
  const directory = await mkdtemp(join(tmpdir(), "hosting-release-replay-"));
  try {
    const path = join(directory, "local.json");
    await writeFile(path, JSON.stringify(local));
    const documents = await comparisons(path);
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
  const option = (name) => process.argv[process.argv.indexOf(name) + 1];
  if (process.argv[2] !== "local" || !option("--fireemu") || !option("--export")) {
    throw new Error("usage: release-replay.mjs local --fireemu <binary> --export <new file>");
  }
  const result = await replay(resolve(option("--fireemu")));
  await writeFile(resolve(option("--export")), `${JSON.stringify(result, null, 2)}\n`, {
    flag: "wx",
  });
  const failures = Object.entries(result.documents).filter(
    ([, document]) => document.summary.MISMATCH > 0 || document.summary.UNKNOWN > 0,
  );
  console.log(
    JSON.stringify({
      kind: result.kind,
      documents: Object.keys(result.documents),
      mismatched: failures.map(([path]) => path),
    }),
  );
  process.exitCode = failures.length === 0 ? 0 : 1;
}
