// The committed comparison files of the Hosting parent and their recomputation.
//
//   node closure-evidence.mjs write <strict local.json> <strict follow-up local.json>   writes the six comparison files (new files only)
//   node closure-evidence.mjs check <strict local.json> <strict follow-up local.json>   recomputes them and requires them to equal the committed ones
//
// The recordings `conformance/hosting-production-pass-1.json` and `-pass-2.json` are the rows of the
// two production runs. The local rows (`local.mjs --profile strict`, a real fireemu process) change
// their `Last-Modified` values from run to run but never their form, so the committed comparisons name
// only the digest of the production side: the comparison itself is what is compared.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { compareFiles, loadKnownDifferences } from "./compare.mjs";
import { buildFollowupCorpus } from "./followup.mjs";

const ROOT = new URL("../../", import.meta.url);
export const FILES = {
  pass1: "hosting-production-pass-1.json",
  pass2: "hosting-production-pass-2.json",
  runs: "hosting-production-run-comparison.json",
  strict1: "hosting-production-strict-vs-pass-1.json",
  strict2: "hosting-production-strict-vs-pass-2.json",
};

/** The follow-up recordings (packet v1, runs 11ae6c and 1c6a4c) and the comparison files made from them. */
export const FOLLOWUP_FILES = {
  run1: "hosting-production-followup-1.json",
  run2: "hosting-production-followup-2.json",
  runs: "hosting-followup-run-comparison.json",
  strict1: "hosting-followup-strict-vs-run-1.json",
  strict2: "hosting-followup-strict-vs-run-2.json",
};

async function load(name) {
  const bytes = await readFile(new URL(name, ROOT));
  return {
    name,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    value: JSON.parse(bytes),
  };
}

/** The three comparison documents, from the committed recordings and one local rows file. */
export async function comparisons(localPath) {
  const pass1 = await load(FILES.pass1);
  const pass2 = await load(FILES.pass2);
  const local = {
    name: "local",
    sha256: "",
    value: JSON.parse(await readFile(localPath)),
  };
  const stable = (document) => ({ ...document, inputs: { ...document.inputs, b: null } });
  return {
    [FILES.runs]: compareFiles({ kind: "run-vs-run", left: pass1, right: pass2 }),
    [FILES.strict1]: stable(
      compareFiles({ kind: "production-vs-local", left: pass1, right: local }),
    ),
    [FILES.strict2]: stable(
      compareFiles({ kind: "production-vs-local", left: pass2, right: local }),
    ),
  };
}

/** The three follow-up comparison documents, from the committed recordings and one local rows file. */
export async function followupComparisons(localPath) {
  const run1 = await load(FOLLOWUP_FILES.run1);
  const run2 = await load(FOLLOWUP_FILES.run2);
  const local = {
    name: "local",
    sha256: "",
    value: JSON.parse(await readFile(localPath)),
  };
  const corpus = buildFollowupCorpus();
  const known = loadKnownDifferences(corpus, "followup-known-differences.json");
  const stable = (document) => ({ ...document, inputs: { ...document.inputs, b: null } });
  return {
    [FOLLOWUP_FILES.runs]: compareFiles({
      kind: "run-vs-run",
      left: run1,
      right: run2,
      corpus,
      known,
    }),
    [FOLLOWUP_FILES.strict1]: stable(
      compareFiles({ kind: "production-vs-local", left: run1, right: local, corpus, known }),
    ),
    [FOLLOWUP_FILES.strict2]: stable(
      compareFiles({ kind: "production-vs-local", left: run2, right: local, corpus, known }),
    ),
  };
}

const text = (document) => `${JSON.stringify(document, null, 2)}\n`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, local, followupLocal] = process.argv.slice(2);
  if (!["write", "check"].includes(mode) || !local || !followupLocal) {
    throw new Error(
      "usage: closure-evidence.mjs write|check <strict local rows.json> <strict follow-up local rows.json>",
    );
  }
  const documents = {
    ...(await comparisons(local)),
    ...(await followupComparisons(followupLocal)),
  };
  for (const [name, document] of Object.entries(documents)) {
    if (mode === "write") {
      await writeFile(new URL(name, ROOT), text(document), { flag: "wx" });
    } else {
      const committed = JSON.parse(await readFile(new URL(name, ROOT), "utf8"));
      if (JSON.stringify(committed) !== JSON.stringify(document)) {
        throw new Error(`${name} differs from the recomputed comparison`);
      }
    }
    console.log(JSON.stringify({ mode, name, summary: document.summary }));
  }
}
