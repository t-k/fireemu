#!/usr/bin/env node
// Thin CLI over compareRuns: reads the frozen corpus/programs, one production run record and the
// two local sessions, checks the run was recorded against this corpus, and writes the comparison
// deterministically (sorted keys, 2-space indent, trailing newline). Offline; no network.
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { compareRuns } from "./compare.mjs";

const repoFile = (path) => fileURLToPath(new URL(`../../../${path}`, import.meta.url));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
        .map((key) => [key, sortKeys(value[key])]),
    );
  }
  return value;
}

/** JSON with keys sorted at every depth, 2-space indent and a trailing newline. */
export function stableJson(value) {
  return `${JSON.stringify(sortKeys(value), null, 2)}\n`;
}

const REQUIRED = [
  "production-run",
  "emulator-session",
  "strict-session",
  "local-project",
  "artifact-sha256",
  "execution",
  "out",
];

/** Run the comparison for argv (without the node and script paths); returns the written document. */
export async function runCli(argv) {
  const { values } = parseArgs({
    args: argv,
    strict: true,
    allowPositionals: false,
    options: {
      ...Object.fromEntries(REQUIRED.map((name) => [name, { type: "string" }])),
      corpus: { type: "string", default: repoFile("functions-events/corpus.json") },
      programs: { type: "string", default: repoFile("functions-events/programs.json") },
      fixture: { type: "string", default: repoFile("functions-events/fixtures/index.js") },
    },
  });
  for (const name of REQUIRED) {
    if (typeof values[name] !== "string" || values[name].length === 0) {
      throw new Error(`--${name} is required`);
    }
  }
  if (!/^[0-9a-f]{64}$/.test(values["artifact-sha256"])) {
    throw new Error("--artifact-sha256 must be a lowercase sha256 hex digest");
  }
  const corpusBytes = await readFile(values.corpus);
  const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
  const productionRun = await readJson(values["production-run"]);
  const corpusSha256 = sha256(corpusBytes);
  if (productionRun?.corpusDigest !== corpusSha256) {
    throw new Error("production run corpusDigest does not match the corpus file");
  }
  const comparison = compareRuns({
    corpus: JSON.parse(corpusBytes.toString("utf8")),
    programs: await readJson(values.programs),
    productionRun,
    localSessions: {
      emulator: await readJson(values["emulator-session"]),
      strict: await readJson(values["strict-session"]),
    },
    localProject: values["local-project"],
  });
  const document = {
    kind: "functions-events-comparison",
    artifactSha256: values["artifact-sha256"],
    execution: values.execution,
    fixtureSha256: sha256(await readFile(values.fixture)),
    corpusSha256,
    productionRun: {
      project: productionRun.project,
      recordedAt: productionRun.recordedAt,
      corpusDigest: productionRun.corpusDigest,
    },
    ...comparison,
  };
  await writeFile(values.out, stableJson(document));
  return document;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCli(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
