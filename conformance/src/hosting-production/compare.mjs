// Compares two row files of the Hosting observation and writes a comparison file.
//
//   node compare.mjs production-vs-local <production rows.json> <local.json> <new out file>
//   node compare.mjs run-vs-run <rows.json of run 1> <rows.json of run 2> <new out file>
//
// Production rows are `{ rows }` from the recorder (`rows.json`); local rows are `{ rows }` from
// `local.mjs`. Both must be rows of the pinned corpus. The output names the digests of its inputs.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { buildCorpus, corpusManifest } from "./corpus.mjs";
import { buildFollowupCorpus } from "./followup.mjs";
import { compareRuns, conditionVerdicts } from "./judge.mjs";

/** The known differences of a production recording: `known-differences.json` (the parent's corpus) or `followup-known-differences.json`. */
export function loadKnownDifferences(corpus = buildCorpus(), file = "known-differences.json") {
  const document = JSON.parse(readFileSync(new URL(`./${file}`, import.meta.url), "utf8"));
  const ids = new Set(corpus.versions.flatMap((v) => v.requests.map((r) => r.id)));
  for (const entry of document.entries) {
    for (const id of entry.rows) {
      if (!ids.has(id)) throw new Error(`${entry.id} names ${id}, which is not a corpus request`);
    }
  }
  return document.entries;
}

export function compareFiles({
  kind,
  left,
  right,
  corpus = buildCorpus(),
  known = loadKnownDifferences(corpus),
}) {
  const requests = corpus.versions.flatMap((v) => v.requests);
  const ids = requests.map((r) => r.id);
  const digest = corpusManifest(corpus).corpusSha256;
  for (const side of [left, right]) {
    if (side.value.corpusSha256 !== undefined && side.value.corpusSha256 !== digest) {
      throw new Error(`${side.name} is not a row file of the pinned corpus`);
    }
  }
  const results = compareRuns(ids, left.value.rows, right.value.rows, {
    compareInitJs: kind === "run-vs-run",
    known: { entries: known, kind },
  });
  return {
    kind: "hosting-comparison-v1",
    comparison: kind,
    corpusSha256: digest,
    inputs: { a: left.sha256, b: right.sha256 },
    knownDifferences: known
      .filter((entry) => entry.appliesTo.includes(kind))
      .map((entry) => ({ id: entry.id, rows: entry.rows.length })),
    summary: results.summary,
    unclassifiedHeaders: results.unclassifiedHeaders,
    conditions: conditionVerdicts(requests, results),
    rows: results.rows,
  };
}

async function load(path, name) {
  const bytes = await readFile(path);
  return {
    name,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    value: JSON.parse(bytes),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [kind, a, b, out, corpusName] = process.argv.slice(2);
  if (
    !["production-vs-local", "run-vs-run"].includes(kind) ||
    !a ||
    !b ||
    !out ||
    ![undefined, "followup"].includes(corpusName)
  ) {
    throw new Error(
      "usage: compare.mjs production-vs-local|run-vs-run <a.json> <b.json> <new out file> [followup]",
    );
  }
  const followup = buildFollowupCorpus();
  const corpus =
    corpusName === "followup"
      ? {
          corpus: followup,
          known: loadKnownDifferences(followup, "followup-known-differences.json"),
        }
      : {};
  const result = compareFiles({
    kind,
    left: await load(a, "a"),
    right: await load(b, "b"),
    ...corpus,
  });
  await writeFile(out, `${JSON.stringify(result, null, 2)}\n`, { flag: "wx" });
  console.log(JSON.stringify({ kind, summary: result.summary }));
}
