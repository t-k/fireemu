// The framing summary of the large-answer programs of O-8A. Their answers are too big to keep in
// the committed production fixture (up to 5000 documents, and 4.8 MB of documents), and what
// the legacy summary records the number of response units (REST array elements, gRPC messages),
// result counts and normalized JSON size per unit, with a second profile where the captures differ.
// Compact production fixture entries also bind ordered result content and metadata. The full raw
// recordings stay in the run's private directory.
//
//   node framing-summary.mjs <fixture-after.json> <summary-out.json> <fixture-out.json>
//     writes the summary of the summary-only programs and the fixture without them

import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

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

// This limit bounds one normalized JSON unit in the fixture comparison; it is not a wire limit.
export const MAX_NORMALIZED_UNIT_BYTES = 2 * 1024 * 1024;

function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && !Object.is(value, -0))
    return value;
  if (Array.isArray(value)) {
    if (
      Object.getPrototypeOf(value) !== Array.prototype ||
      Object.getOwnPropertySymbols(value).length ||
      Object.getOwnPropertyNames(value).length !== value.length + 1
    )
      throw new Error("unsupported framing array properties");
    for (let index = 0; index < value.length; index++)
      if (!Object.hasOwn(value, index)) throw new Error("unsupported sparse framing array");
    return value.map(canonical);
  }
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    if (
      Object.getOwnPropertySymbols(value).length ||
      Object.getOwnPropertyNames(value).length !== Object.keys(value).length
    )
      throw new Error("unsupported framing object properties");
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  throw new Error("unsupported framing value");
}

function digest(value) {
  const text = JSON.stringify(canonical(value));
  if (Buffer.byteLength(text) > MAX_NORMALIZED_UNIT_BYTES)
    throw new Error("oversized normalized framing value");
  return createHash("sha256").update(text).digest("hex");
}

/** A bounded normalized response, preserving ordered results and the observed unit profile. */
export function compactFramingStep(row, kind) {
  if (!row || !["read", "seed"].includes(kind)) throw new Error("unsupported framing row");
  const grpc = row.transport === "grpc";
  if ((grpc && row.code !== 0) || (!grpc && row.status !== 200))
    throw new Error("unsuccessful framing row");
  if (kind === "seed") return { kind, wholeDigest: digest(row) };
  const list = grpc ? row.messages : row.body;
  if (!Array.isArray(list) || list.length === 0) throw new Error("malformed framing units");
  const head = Object.fromEntries(
    Object.entries(row).filter(([key]) => key !== (grpc ? "messages" : "body")),
  );
  const resultsHash = createHash("sha256").update("fireemu-framing-results-v1\0");
  const profile = [];
  let results = 0;
  for (const entry of list) {
    if (
      !entry ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      !Array.isArray(entry.results) ||
      entry.results.length === 0
    )
      throw new Error("malformed framing unit");
    const bytes = Buffer.byteLength(JSON.stringify(canonical(entry)));
    if (bytes > MAX_NORMALIZED_UNIT_BYTES) throw new Error("oversized normalized framing unit");
    const metadata = Object.fromEntries(Object.entries(entry).filter(([key]) => key !== "results"));
    profile.push({
      results: entry.results.length,
      jsonBytes: bytes,
      metadataDigest: digest(metadata),
    });
    for (const result of entry.results) {
      const data = Buffer.from(JSON.stringify(canonical(result)));
      const length = Buffer.alloc(8);
      length.writeBigUInt64BE(BigInt(data.length));
      resultsHash.update(length).update(data);
      results++;
    }
  }
  return {
    kind,
    headDigest: digest(head),
    results,
    contentDigest: resultsHash.digest("hex"),
    profile,
  };
}

function validCompactStep(step) {
  const sha = (value) => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  if (!step || !["seed", "read"].includes(step.kind)) return false;
  if (step.kind === "seed") return sha(step.wholeDigest);
  return (
    sha(step.headDigest) &&
    sha(step.contentDigest) &&
    Number.isSafeInteger(step.results) &&
    step.results > 0 &&
    Array.isArray(step.profile) &&
    step.profile.length > 0 &&
    step.profile.every(
      (unit) =>
        Number.isSafeInteger(unit.results) &&
        unit.results > 0 &&
        Number.isSafeInteger(unit.jsonBytes) &&
        unit.jsonBytes > 0 &&
        unit.jsonBytes <= MAX_NORMALIZED_UNIT_BYTES &&
        sha(unit.metadataDigest),
    ) &&
    step.profile.reduce((sum, unit) => sum + unit.results, 0) === step.results
  );
}

/** Compare normalized successful responses; a variable batch partition is not wire equality. */
export function classifyCompactFraming(expected, alternative, row) {
  if (
    !validCompactStep(expected) ||
    (alternative !== undefined &&
      (!validCompactStep(alternative) || alternative.kind !== expected.kind))
  )
    return { status: "MISMATCH", diagnostic: "invalid-fixture" };
  let actual;
  try {
    actual = compactFramingStep(row, expected.kind);
  } catch {
    return { status: "MISMATCH", diagnostic: "invalid-local-response" };
  }
  const candidates = [expected, alternative].filter(Boolean);
  if (expected.kind === "seed")
    return candidates.some((item) => item.wholeDigest === actual.wholeDigest)
      ? { status: alternative ? "MATCH_NONDETERMINISTIC" : "MATCH" }
      : { status: "MISMATCH", diagnostic: "seed-response" };
  const content = candidates.filter(
    (item) =>
      item.kind === "read" &&
      item.headDigest === actual.headDigest &&
      item.results === actual.results &&
      item.contentDigest === actual.contentDigest,
  );
  if (!content.length) return { status: "MISMATCH", diagnostic: "status-or-content" };
  const allowedMetadata = new Set(
    content.flatMap((item) => item.profile.map((unit) => unit.metadataDigest)),
  );
  if (actual.profile.some((unit) => !allowedMetadata.has(unit.metadataDigest)))
    return { status: "MISMATCH", diagnostic: "unit-metadata" };
  const profile = (items) =>
    items.map(({ results, metadataDigest }) => ({ results, metadataDigest }));
  if (content.some((item) => isDeepStrictEqual(profile(item.profile), profile(actual.profile))))
    return { status: alternative ? "MATCH_NONDETERMINISTIC" : "MATCH", framing: actual.profile };
  // Firestore defines result batches as variable-sized; it does not promise identical cuts.
  // Restrict this equivalence to uniform execution-time-only metadata, since transaction and
  // explain metadata have position-dependent semantics. This does not compare raw wire bytes.
  // https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/executePipeline
  const units = row.transport === "grpc" ? row.messages : row.body;
  const metadata = actual.profile[0].metadataDigest;
  const uniform = (item) => item.profile.every((unit) => unit.metadataDigest === metadata);
  if (
    content.some(uniform) &&
    uniform(actual) &&
    units.every(
      (unit) =>
        Object.keys(unit).filter((key) => key !== "results").length === 1 &&
        Object.hasOwn(unit, "executionTime"),
    )
  ) {
    return {
      status: "MATCH_NONDETERMINISTIC",
      diagnostic: "variable-framing",
      framing: actual.profile,
    };
  }
  return { status: "INDETERMINATE", diagnostic: "unobserved-framing", framing: actual.profile };
}

/** The summary of every summary-only program of a fixture; each one must be in it. */
export function summarizeFixture(fixture) {
  const programs = {};
  for (const id of SUMMARY_ONLY) {
    const program = fixture.programs?.[id];
    if (!program) throw new Error(`the fixture has no summary-only program ${id}`);
    for (const step of Object.keys(program.second ?? {})) {
      if (!(step in program.steps)) throw new Error(`${id}#${step}: a second row without a first`);
    }
    programs[id] = {
      corpusDigest: program.corpusDigest,
      steps: Object.fromEntries(
        Object.entries(program.steps).map(([step, row]) => [
          step,
          {
            ...summarizeStep(row),
            // The other recording of a step whose two recordings differed.
            ...(program.second?.[step] ? { second: summarizeStep(program.second[step]) } : {}),
          },
        ]),
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
