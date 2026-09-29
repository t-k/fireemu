// AUTH-FEDERATION comparison of a local run with the saved production fixture, and its public
// export for the closure evidence. It reads what `run.mjs local` wrote and is not part of the
// recorded harness (record.mjs digests the modules a recording runs; this one only reads).
//
//   node src/auth-federation/compare.mjs check [record-saml|record-followup|record-strict-safety]
//   node src/auth-federation/compare.mjs export [record-saml|record-followup|record-strict-safety] <output.json>
//
// `check` runs `run.mjs local` with FIREEMU_BIN (or the workspace build), classifies each
// recorded row and writes `.runs/auth-federation/comparison[-record-saml].json`.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { PROGRAMS } from "./corpus.mjs";
import { SAML_PROGRAMS } from "./corpus-saml.mjs";
import { FOLLOWUP_PROGRAMS } from "./corpus-followup.mjs";
import { STRICT_SAFETY_PROGRAMS } from "./corpus-strict-safety.mjs";
import { programDigests } from "./record.mjs";

const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-federation");

/** Each corpus: its programs, fixture, local results, comparison and evidence kind. */
export const COMPARISONS = {
  "record-oidc": {
    programs: PROGRAMS,
    fixture: "auth-federation-production.json",
    results: "fireemu-results.json",
    comparison: "comparison.json",
    kind: "auth-federation-comparison-v1",
  },
  "record-saml": {
    programs: SAML_PROGRAMS,
    fixture: "auth-federation-saml-production.json",
    results: "fireemu-record-saml-results.json",
    comparison: "comparison-record-saml.json",
    kind: "auth-federation-saml-comparison-v1",
  },
  "record-followup": {
    programs: FOLLOWUP_PROGRAMS,
    fixture: "auth-federation-followup-production.json",
    results: "fireemu-record-followup-results.json",
    comparison: "comparison-record-followup.json",
    kind: "auth-federation-followup-comparison-v1",
  },
  "record-strict-safety": {
    programs: STRICT_SAFETY_PROGRAMS,
    fixture: "auth-federation-strict-safety-production.json",
    results: "fireemu-record-strict-safety-results.json",
    comparison: "comparison-record-strict-safety.json",
    kind: "auth-federation-strict-safety-comparison-v1",
  },
};

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const same = (a, b) => JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((key) => [key, sortKeys(value[key])]),
    );
  }
  return value;
}

/**
 * A row's status: `STALE` when the program changed since it was recorded, `MISSING` when
 * either side has no row, `MATCH` when fireemu's row is production's first recording,
 * `MATCH_NONDETERMINISTIC` when it is the second recording (a row the passes recorded
 * differently), and `MISMATCH` otherwise.
 */
export function classify({ stale, production, alternative, fireemu }) {
  if (stale) return "STALE";
  if (production === undefined || fireemu === undefined) return "MISSING";
  if (same(production, fireemu)) return "MATCH";
  if (alternative !== undefined && same(alternative, fireemu)) return "MATCH_NONDETERMINISTIC";
  return "MISMATCH";
}

/** The compared rows of one corpus, in corpus order, and the fixture programs it has no program for. */
export function compareRows(corpus, fixture, results) {
  const digests = programDigests(corpus.programs);
  const rows = [];
  for (const program of corpus.programs) {
    const saved = fixture.programs[program.id];
    const stale = saved !== undefined && saved.corpusDigest !== digests[program.id];
    for (const step of program.steps) {
      const production = saved?.steps?.[step.id];
      const alternative = saved?.second?.[step.id];
      const fireemu = results[program.id]?.steps?.[step.id];
      rows.push({
        row: `${program.id}#${step.id}`,
        status: classify({ stale, production, alternative, fireemu }),
        production,
        ...(alternative === undefined ? {} : { alternative }),
        fireemu,
      });
    }
  }
  const known = new Set(corpus.programs.map(({ id }) => id));
  const orphans = Object.keys(fixture.programs).filter((id) => !known.has(id));
  return { rows, orphans };
}

export function summarize(rows) {
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  return summary;
}

/** The member paths where fireemu's row differs from production's. */
export function differences(production, fireemu) {
  const out = [];
  const walk = (a, b, path) => {
    if (same(a, b)) return;
    if (
      a &&
      b &&
      typeof a === "object" &&
      typeof b === "object" &&
      Array.isArray(a) === Array.isArray(b)
    ) {
      for (const key of new Set([...Object.keys(a), ...Object.keys(b)]))
        walk(a[key], b[key], `${path}.${key}`);
      return;
    }
    out.push(path.slice(1));
  };
  walk(production, fireemu, "");
  return out.toSorted();
}

/** The public evidence of a comparison: statuses, and for a differing row the member paths only. */
export function evidenceOf(corpus, comparison, fixtureText) {
  return {
    kind: corpus.kind,
    artifactSha256: comparison.artifactSha256,
    fixtureSha256: sha256(fixtureText),
    summary: comparison.summary,
    rows: comparison.rows.map(({ row, status, production, fireemu }) =>
      status === "MISMATCH"
        ? { row, status, differences: differences(production, fireemu) }
        : { row, status },
    ),
  };
}

const corpusOf = (packet = "record-oidc") => {
  const corpus = COMPARISONS[packet];
  if (!corpus) throw new Error(`no corpus ${packet}`);
  return corpus;
};

async function check(packet) {
  const corpus = corpusOf(packet);
  const binary = resolveFireemuBinary();
  await promisify(execFile)(
    process.execPath,
    ["src/auth-federation/run.mjs", "local", ...(packet ? [packet] : [])],
    { cwd: CONFORMANCE_DIR, env: process.env, maxBuffer: 64 * 1024 * 1024 },
  );
  const fixture = JSON.parse(await readFile(join(CONFORMANCE_DIR, corpus.fixture), "utf8"));
  const local = JSON.parse(await readFile(join(RUN_DIR, corpus.results), "utf8"));
  const { rows, orphans } = compareRows(corpus, fixture, local.results);
  const summary = summarize(rows);
  const artifactSha256 = sha256(await readFile(binary));
  const comparison = {
    artifact: binary,
    artifactSha256,
    summary,
    orphans,
    failures: local.failures,
    rows,
  };
  await writeFile(join(RUN_DIR, corpus.comparison), `${JSON.stringify(comparison, null, 2)}\n`);
  for (const row of rows.filter(({ status }) => status !== "MATCH")) {
    console.log(`${row.status} ${row.row} ${differences(row.production, row.fireemu).join(" ")}`);
  }
  console.log(
    JSON.stringify({ artifactSha256, summary, orphans, failures: local.failures }, null, 2),
  );
  if (
    orphans.length ||
    local.failures.length ||
    rows.some(({ status }) => status === "STALE" || status === "MISSING")
  ) {
    process.exitCode = 1;
  }
}

async function exportComparison(packet, out) {
  if (!out) throw new Error("usage: export [record-saml] <output.json>");
  const corpus = corpusOf(packet);
  const path = join(RUN_DIR, corpus.comparison);
  if (!existsSync(path)) throw new Error(`run check ${packet ?? ""} first`);
  const comparison = JSON.parse(await readFile(path, "utf8"));
  const fixtureText = await readFile(join(CONFORMANCE_DIR, corpus.fixture), "utf8");
  const evidence = evidenceOf(corpus, comparison, fixtureText);
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(
    JSON.stringify(
      { out, summary: evidence.summary, fixtureSha256: evidence.fixtureSha256 },
      null,
      2,
    ),
  );
}

const mode = process.argv[1] === fileURLToPath(import.meta.url) ? process.argv[2] : undefined;
const args = process.argv.slice(3);
const packetArg = args[0] && COMPARISONS[args[0]] ? args.shift() : undefined;
if (mode === "check") await check(packetArg);
else if (mode === "export") await exportComparison(packetArg, args[0]);
else if (mode !== undefined) throw new Error(`unknown mode ${mode}`);
