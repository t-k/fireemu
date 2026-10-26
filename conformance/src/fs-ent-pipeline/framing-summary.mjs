// The framing summary of the large-answer programs of O-8A. Their answers are too big to keep in
// the committed production fixture (up to 5000 documents, and 4.8 MB of documents), and what
// they decide is how a response is cut, not what it holds. So the committed record is, per step,
// the number of response units (REST array elements, gRPC messages) with the number of results
// and the JSON size of each, and the program's digest; the raw recordings stay in the run's
// private directory.
//
//   node framing-summary.mjs <fixture-after.json> <summary-out.json> <fixture-out.json>
//     writes the summary of the summary-only programs and the fixture without them

import { readFileSync, writeFileSync } from "node:fs";

import { isMainModule } from "../fs-query-index/main-module.mjs";
import { SUMMARY_ONLY } from "./o8a-corpus.mjs";

const units = (row) => {
  if (row.transport === "grpc") return row.messages ?? [];
  if (row.status !== 200) return [];
  return Array.isArray(row.body) ? row.body : [row.body];
};

/** One recorded step: the transport, the outcome, the results in all and each response unit. */
export function summarizeStep(row) {
  const grpc = row.transport === "grpc";
  const list = units(row);
  const summary = {
    transport: grpc ? "grpc" : "rest",
    ...(grpc ? { code: row.code } : { status: row.status }),
    results: 0,
    units: [],
  };
  for (const entry of list) {
    const results = Array.isArray(entry?.results) ? entry.results.length : 0;
    summary.results += results;
    summary.units.push({ results, jsonBytes: Buffer.byteLength(JSON.stringify(entry)) });
  }
  return summary;
}

/** The summary of every summary-only program of a fixture; each one must be in it. */
export function summarizeFixture(fixture) {
  const programs = {};
  for (const id of SUMMARY_ONLY) {
    const program = fixture.programs?.[id];
    if (!program) throw new Error(`the fixture has no summary-only program ${id}`);
    programs[id] = {
      corpusDigest: program.corpusDigest,
      steps: Object.fromEntries(
        Object.entries(program.steps).map(([step, row]) => [step, summarizeStep(row)]),
      ),
    };
  }
  return { version: 1, source: "FS-ENT-ORACLE O-8A framing", programs };
}

/** The fixture without the summary-only programs (the input is not changed). */
export function stripSummaryOnly(fixture) {
  return {
    ...fixture,
    programs: Object.fromEntries(
      Object.entries(fixture.programs).filter(([id]) => !SUMMARY_ONLY.has(id)),
    ),
  };
}

if (isMainModule(import.meta)) {
  const [input, summaryOut, fixtureOut] = process.argv.slice(2);
  if (!input || !summaryOut || !fixtureOut) {
    console.error("usage: framing-summary.mjs <fixture-after> <summary-out> <fixture-out>");
    process.exit(2);
  }
  const fixture = JSON.parse(readFileSync(input, "utf8"));
  writeFileSync(summaryOut, `${JSON.stringify(summarizeFixture(fixture), null, 2)}\n`);
  writeFileSync(fixtureOut, `${JSON.stringify(stripSummaryOnly(fixture), null, 2)}\n`);
}
