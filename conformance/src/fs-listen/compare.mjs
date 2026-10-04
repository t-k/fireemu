// The offline comparison of Listen recordings (FS-LISTEN-SDK packet L1): two production
// recordings against one local one. Nothing here talks to a network. A row is compared only on
// what the recorder wrote; a row whose wait ran out, or whose stream hit the frame cap, is
// INDETERMINATE and never a match or a difference.
//
//   node src/fs-listen/compare.mjs --production A.json B.json --local L.json [--divergences D.json]

import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

const DOCUMENT_ROWS = new Set(["documentChange", "documentDelete", "documentRemove"]);
const text = (value) => JSON.stringify(value);
const byText = (a, b) => (text(a) < text(b) ? -1 : text(a) > text(b) ? 1 : 0);

/**
 * Documents delivered between two boundaries are one snapshot, and Listen does not order them: a
 * run of document rows compares as a set. Everything else keeps its order.
 */
function sortDocumentRuns(rows) {
  const out = [];
  let run = [];
  const flush = () => {
    out.push(...run.toSorted(byText));
    run = [];
  };
  for (const row of rows) {
    if (DOCUMENT_ROWS.has(row.kind)) run.push(row);
    else {
      flush();
      out.push(row);
    }
  }
  flush();
  return out;
}

/** What a row says when compared: no conditions, no timings, document runs as sets. */
export function canonicalRow(row) {
  return {
    ...(row.rows ? { rows: sortDocumentRuns(row.rows) } : {}),
    ...(row.groups ? { groups: row.groups.map((g) => ({ ...g, docs: g.docs.toSorted() })) } : {}),
    ...(row.observed ? { observed: row.observed } : {}),
    ...(row.failures ? { failures: row.failures } : {}),
    ...(row.invariantViolations ? { invariantViolations: row.invariantViolations } : {}),
    end: row.end ? { reason: row.end.reason, code: row.end.code ?? null } : null,
  };
}

/** MATCH, DIFFER or INDETERMINATE for two rows. */
export function classifyRow(a, b) {
  const unfinished = (row) => row.timedOut === true || row.end?.reason === "frame-cap";
  if (unfinished(a) || unfinished(b)) return "INDETERMINATE";
  return isDeepStrictEqual(canonicalRow(a), canonicalRow(b)) ? "MATCH" : "DIFFER";
}

/** What makes a recording unfit to compare: the version, an unfinished cleanup, a program error. */
export function recordingProblems(recording) {
  const problems = [];
  if (recording.version !== 1) problems.push(`unknown recording version ${recording.version}`);
  if (recording.cleanup?.complete !== true) problems.push("cleanup was not complete");
  for (const [program, message] of Object.entries(recording.errors ?? {}))
    problems.push(`${program}: ${message}`);
  return problems;
}

const GOOD = new Set(["MATCH", "KNOWN_DIVERGENCE"]);

/**
 * `productions` are the two recordings of production, `local` the one of fireemu. A production
 * pair that disagrees is NONDETERMINISTIC (the row proves nothing about local); a divergence is
 * accepted only for a row that differs, and only with a reason.
 */
export function compareRecordings({ productions, local, divergences = {} }) {
  if (productions.length !== 2) throw new Error("two production recordings are required");
  for (const production of productions) {
    const problems = recordingProblems(production);
    if (problems.length)
      throw new Error(`a production recording is not clean: ${problems.join("; ")}`);
  }
  for (const [id, reason] of Object.entries(divergences))
    if (typeof reason !== "string" || reason.trim() === "")
      throw new Error(`divergence ${id} needs a reason`);
  const [first, second] = productions;
  const ids = new Set([
    ...Object.keys(first.rows),
    ...Object.keys(second.rows),
    ...Object.keys(local.rows),
  ]);
  const rows = {};
  for (const id of [...ids].toSorted()) {
    const p1 = first.rows[id];
    const p2 = second.rows[id];
    const l = local.rows[id];
    if (!p1 || !p2) {
      rows[id] = { status: l ? "EXTRA" : "PRODUCTION_MISSING" };
      continue;
    }
    const pair = classifyRow(p1, p2);
    if (pair === "INDETERMINATE") rows[id] = { status: "INDETERMINATE" };
    else if (pair === "DIFFER") rows[id] = { status: "NONDETERMINISTIC" };
    else if (!l) rows[id] = { status: "MISSING" };
    else {
      const verdict = classifyRow(p1, l);
      if (verdict === "DIFFER" && Object.hasOwn(divergences, id))
        rows[id] = { status: "KNOWN_DIVERGENCE", reason: divergences[id] };
      else rows[id] = { status: verdict === "DIFFER" ? "MISMATCH" : verdict };
    }
  }
  const summary = {};
  for (const { status } of Object.values(rows)) summary[status] = (summary[status] ?? 0) + 1;
  const localProblems = recordingProblems(local);
  return {
    rows,
    summary,
    localProblems,
    ok: Object.values(rows).every(({ status }) => GOOD.has(status)) && localProblems.length === 0,
  };
}

function main(argv) {
  const args = { production: [] };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--production") args.production.push(argv[(i += 1)], argv[(i += 1)]);
    else if (argv[i] === "--local") args.local = argv[(i += 1)];
    else if (argv[i] === "--divergences") args.divergences = argv[(i += 1)];
    else throw new Error(`unexpected argument ${argv[i]}`);
  }
  const read = (file) => JSON.parse(readFileSync(file, "utf8"));
  const report = compareRecordings({
    productions: args.production.map(read),
    local: read(args.local),
    divergences: args.divergences ? read(args.divergences) : {},
  });
  for (const [id, { status, reason }] of Object.entries(report.rows))
    console.log(`${status.padEnd(18)} ${id}${reason ? `  (${reason})` : ""}`);
  console.log(JSON.stringify(report.summary), report.ok ? "OK" : "NOT OK");
  for (const problem of report.localProblems) console.log(`local: ${problem}`);
  process.exitCode = report.ok ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
