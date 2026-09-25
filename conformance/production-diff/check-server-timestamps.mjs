#!/usr/bin/env node
// FS-SERVER-TIME-EVIDENCE-025. Raw local diagnostics, NOT a production oracle.
// REQUEST_TIME has a documented millisecond precision; ordinary Timestamp,
// createTime, updateTime and commitTime must NOT be rounded by this checker.
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { TRANSFORMS_CASE } from "./registry.mjs";
import { equal, object, requireThat, safeCode, sha256 } from "./core.mjs";
import { publishJson, readSource } from "./io.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MAX_WITNESS_BYTES = 128 * 1024;
const SECOND = 1_000_000_000n;
const MILLISECOND = 1_000_000n;
const MIN_TIMESTAMP = -62135596800n * SECOND;
const MAX_TIMESTAMP = 253402300800n * SECOND - 1n;
const GENERATIONS = Object.freeze([
  Object.freeze({ id: "server-timestamp-and-increments", index: 0, document: "tf/doc" }),
  Object.freeze({ id: "transform-only-write-creates", index: 1, document: "tf/created" }),
]);
const READBACKS = Object.freeze([
  ["read-after-increments", 0],
  ["read-after-max-min", 0],
  ["read-after-array-transforms", 0],
  ["read-transform-created", 1],
  ["read-set-and-transform", 0],
].map(Object.freeze));
const WITNESS_IDS = Object.freeze(TRANSFORMS_CASE.stepIds.filter(id =>
  GENERATIONS.some(g => g.id === id) || READBACKS.some(([read]) => read === id)));

/** Parse a protobuf/RFC3339 timestamp without losing sub-millisecond digits.
 * Date is used ONLY to validate an integral UTC second, never the fraction.
 * Leap-second spellings are refused: protobuf timestamps use smeared seconds.
 */
export function parseTimestamp(value) {
  requireThat(typeof value === "string" && value.length <= 40, "timestamp-shape");
  const match = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2})$/.exec(value);
  requireThat(match, "timestamp-shape");
  const [, ys, mos, ds, hs, mis, ss, fraction = "", zone] = match;
  const [year, month, day, hour, minute, second] = [ys, mos, ds, hs, mis, ss].map(Number);
  requireThat(year >= 1 && year <= 9999 && month >= 1 && month <= 12 &&
    day >= 1 && day <= 31 && hour <= 23 && minute <= 59 && second <= 59, "timestamp-range");
  const date = new Date(`${ys}-${mos}-${ds}T${hs}:${mis}:${ss}Z`);
  requireThat(Number.isFinite(date.getTime()) && date.getUTCFullYear() === year &&
    date.getUTCMonth() + 1 === month && date.getUTCDate() === day, "timestamp-range");
  let offset = 0;
  if (zone.toUpperCase() !== "Z") {
    const zh = Number(zone.slice(1, 3)), zm = Number(zone.slice(4, 6));
    requireThat(zh <= 23 && zm <= 59 && zone !== "-00:00", "timestamp-offset");
    offset = (zh * 60 + zm) * 60 * (zone[0] === "+" ? 1 : -1);
  }
  const nanos = (BigInt(date.getTime() / 1000) - BigInt(offset)) * SECOND +
    BigInt(fraction.padEnd(9, "0"));
  requireThat(nanos >= MIN_TIMESTAMP && nanos <= MAX_TIMESTAMP, "timestamp-range");
  return { unixNanos: nanos.toString(), millisecondAligned: nanos % MILLISECOND === 0n };
}

function rawBody(row, phase) {
  requireThat(row?.phase === phase && row.status === 200, "timestamp-response-not-observed");
  const text = row.rawResponseText;
  requireThat(typeof text === "string" && Buffer.byteLength(text) <= MAX_WITNESS_BYTES,
    "timestamp-raw-response-missing");
  requireThat(sha256(text) === row.responseSha256, "timestamp-response-hash-mismatch");
  let body;
  try { body = JSON.parse(text); } catch { throw new Error("timestamp-response-json"); }
  requireThat(object(body) && !Object.hasOwn(body, "error"), "timestamp-response-json");
  return body;
}

/** Inspect source-selected raw replies. This pure function authenticates neither
 * their origin nor their acquisition: the CLI first runs the existing pilot's
 * saved comparison and keeps that result separate from these local diagnostics.
 */
export function inspectTimestampSession(session) {
  const evidenceIssues = [];
  const values = new Map();
  const precision = [], readbacks = [];
  let requests = [];
  try {
    requireThat(object(session) && session.schema === "fireemu-production-diff-session-v1" &&
      session.caseId === TRANSFORMS_CASE.id && session.programDigest === TRANSFORMS_CASE.programDigest &&
      session.productionRequests === 0, "timestamp-session-binding");
    requireThat(equal(TRANSFORMS_CASE.rawTimestampResponseSteps, WITNESS_IDS), "timestamp-witness-set-drift");
    requests = session.requests;
    requireThat(Array.isArray(requests) && session.requestCount === 20 && requests.length === 20 &&
      equal(requests.map(r => r?.phase), ["reset", "seed", ...TRANSFORMS_CASE.stepIds]),
      "timestamp-request-sequence");
    requireThat(session.completed === true && session.failure === null &&
      session.cleanup?.state === "confirmed" && session.cleanup.requests === 7 &&
      equal(session.cleanup.absent, TRANSFORMS_CASE.ownedDocuments), "timestamp-session-incomplete");
  } catch (error) {
    evidenceIssues.push({ stepId: null, reason: safeCode(error) });
    requests = [];
  }
  for (const id of WITNESS_IDS) {
    try {
      const row = requests.find(r => r.phase === id);
      const body = rawBody(row, id);
      const generation = GENERATIONS.find(g => g.id === id);
      const read = READBACKS.find(([readId]) => readId === id);
      let timestamp;
      if (generation) {
        requireThat(row.method === "POST" &&
          row.path === `/v1/projects/${TRANSFORMS_CASE.project}/databases/(default)/documents:commit`,
          "timestamp-route-mismatch");
        timestamp = body.writeResults?.[0]?.transformResults?.[generation.index]?.timestampValue;
      } else {
        const doc = GENERATIONS[read[1]].document;
        const resource = `projects/${TRANSFORMS_CASE.project}/databases/(default)/documents/${doc}`;
        requireThat(row.method === "GET" && row.path === `/v1/${resource}` && body.name === resource,
          "timestamp-document-mismatch");
        timestamp = body.fields?.at?.timestampValue;
      }
      values.set(id, { raw: timestamp, ...parseTimestamp(timestamp) });
    } catch (error) {
      evidenceIssues.push({ stepId: id, reason: safeCode(error) });
    }
  }
  for (const g of GENERATIONS) {
    const value = values.get(g.id);
    precision.push({ stepId: g.id, timestamp: value?.raw ?? null,
      verdict: !value ? "INDETERMINATE" : value.millisecondAligned ? "CONFORMS" : "VIOLATES" });
  }
  for (const [id, source] of READBACKS) {
    const read = values.get(id), produced = values.get(GENERATIONS[source].id);
    readbacks.push({ stepId: id, sourceStepId: GENERATIONS[source].id,
      timestamp: read?.raw ?? null,
      verdict: !read || !produced ? "INDETERMINATE" :
        read.unixNanos === produced.unixNanos ? "CONFORMS" : "VIOLATES" });
  }
  const results = [...precision, ...readbacks];
  const counts = { conforms: 0, violates: 0, indeterminate: 0 };
  for (const result of results) counts[result.verdict.toLowerCase()]++;
  const verdict = evidenceIssues.length || counts.indeterminate ? "INDETERMINATE" :
    counts.violates ? "VIOLATES" : "CONFORMS";
  return {
    schema: "fireemu-server-timestamp-diagnostic-v1",
    caseId: TRANSFORMS_CASE.id,
    evidenceKind: "local-raw-response-contract-diagnostic",
    verdict, counts, precision, readbacks, evidenceIssues,
    rawResponsesExpected: WITNESS_IDS.length, rawResponsesParsed: values.size,
    productionExecuted: false, productionComparison: "NOT_PERFORMED",
    compatibilityVerified: false, parentPromotion: false,
    limitations: [
      "The historical <now> projection cannot supply raw production timestamp evidence.",
      "CONFORMS means only these local precision/readback checks; not production compatibility.",
      "No precision rule is imposed on ordinary timestamp fields or commit/create/update metadata.",
      "No commitTime equality, cross-commit strict ordering, Rules request.time or cross-document timestamp equality is established.",
      "Source-built executable provenance and independent review remain separate obligations.",
    ],
  };
}

export function diagnosticExitCode(primaryCode, report) {
  requireThat([0, 1, 2].includes(primaryCode), "timestamp-primary-exit");
  requireThat(["CONFORMS", "VIOLATES", "INDETERMINATE"].includes(report?.verdict), "timestamp-diagnostic-verdict");
  if (primaryCode === 2 || report.verdict === "INDETERMINATE") return 2;
  return primaryCode === 1 || report.verdict === "VIOLATES" ? 1 : 0;
}

export function parseArgs(argv) {
  const options = { repo: resolve(HERE, "../..") };
  const names = new Map([["--repo", "repo"], ["--run-dir", "runDir"], ["--out", "out"]]);
  const seen = new Set();
  for (let i = 0; i < argv.length; i += 2) {
    requireThat(names.has(argv[i]) && !seen.has(argv[i]) && typeof argv[i + 1] === "string" &&
      argv[i + 1] && !argv[i + 1].startsWith("--"), "timestamp-arguments");
    seen.add(argv[i]); options[names.get(argv[i])] = resolve(argv[i + 1]);
  }
  requireThat(options.runDir && options.out && options.runDir !== options.out, "timestamp-arguments");
  return options;
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const names = ["recording.json", "session-result.json", "local.json"];
  const original = await Promise.all(names.map(name => readSource(options.runDir, name, 4 * 1024 * 1024)));
  const self = await readSource(HERE, "check-server-timestamps.mjs");
  // Reuse, do not replace, the existing source/oracle/recording/cleanup validation.
  const { main: pilot } = await import("./pilot.mjs");
  const primaryCode = await pilot(["compare", "--repo", options.repo, "--case", TRANSFORMS_CASE.id,
    "--run-dir", options.runDir, "--out", options.out]);
  if (primaryCode === 2) return 2; // No valid primary result: never produce a standalone success.
  for (let i = 0; i < names.length; i++)
    requireThat(sha256(await readSource(options.runDir, names[i], 4 * 1024 * 1024)) === sha256(original[i]),
      "timestamp-input-changed");
  requireThat(sha256(await readSource(HERE, "check-server-timestamps.mjs")) === sha256(self),
    "timestamp-validator-changed");
  const primaryBytes = await readSource(options.out, "result.json");
  const primary = JSON.parse(primaryBytes);
  requireThat(primary.caseId === TRANSFORMS_CASE.id && primary.complete === true, "timestamp-primary-incomplete");
  const recording = JSON.parse(original[0]);
  requireThat(recording.sessionSha256 === sha256(original[1]) &&
    recording.execution?.localSha256 === sha256(original[2]), "timestamp-record-binding");
  const report = {
    ...inspectTimestampSession(JSON.parse(original[1])),
    primary: { verdict: primary.comparison.verdict, exitCode: primaryCode,
      resultSha256: sha256(primaryBytes), artifact: primary.execution.artifact },
    source: { sessionSha256: sha256(original[1]), recordingSha256: sha256(original[0]),
      validatorSha256: sha256(self) },
  };
  await publishJson(join(options.out, "timestamp-report.json"), report);
  console.log(JSON.stringify({ timestampDiagnostic: report.verdict,
    primaryComparison: report.primary.verdict, productionComparison: "NOT_PERFORMED", parentPromotion: false }));
  return diagnosticExitCode(primaryCode, report);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().then(code => { process.exitCode = code; }, error => {
    console.error(JSON.stringify({ timestampDiagnostic: "INDETERMINATE", code: safeCode(error),
      productionComparison: "NOT_PERFORMED", parentPromotion: false }));
    process.exitCode = 2;
  });
}
