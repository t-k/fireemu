// The offline comparison of Listen recordings (FS-LISTEN-SDK packet L1): two production
// recordings against one local one. Nothing here talks to a network. A row is compared only on
// what the recorder wrote; a row whose wait ran out, or whose stream hit the frame cap, is
// INDETERMINATE and never a match or a difference.
//
//   node src/fs-listen/compare.mjs --production A.json B.json --local L.json [--divergences D.json]
//        [--settlements S.json]
// S.json: a list of the coordinator's A2 read-backs (the output of `record.mjs readback`), one per
// recording whose own cleanup was not complete.

import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";

const DOCUMENT_ROWS = new Set(["documentChange", "documentDelete", "documentRemove"]);

/**
 * Documents delivered between two boundaries are one snapshot, and Listen does not order them: a
 * run of document rows compares as a set. Everything else keeps its order.
 */
function sortDocumentRuns(rows) {
  const out = [];
  let run = [];
  // A run is ordered by the text of its rows, so equal sets give equal rows.
  const flush = () => {
    out.push(
      ...run
        .map((row) => JSON.stringify(row))
        .toSorted()
        .map((json) => JSON.parse(json)),
    );
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

/**
 * Production sends an ExistenceFilter (with a bloom filter of unchanged names) unprompted, and not
 * every time: two recordings of the same native program differ only by a `filter` row, and by the
 * boundary run it splits, in 7 rows (FS-LISTEN-SDK L1, runs nmuuicyas and nmuukwo6n:
 * existence-filter/no-change, resume-token-expired/first, resume-token/first, fresh-control,
 * unchanged, other-query, target-protocol/equality-only-query). Its presence is therefore not
 * compared; its content is (see `filterKeys`). Removing it leaves the boundaries around it side by
 * side, and those merge into one, as the recorder merges a run of boundaries.
 */
function withoutFilters(rows) {
  const out = [];
  let dropped = false;
  for (const row of rows) {
    if (row.kind === "filter") {
      dropped = true;
      continue;
    }
    const last = out.at(-1);
    // Only the boundaries a dropped filter left side by side merge; others stay as recorded.
    if (dropped && row.kind === "boundary" && last?.kind === "boundary")
      out[out.length - 1] = { ...last, resumeToken: last.resumeToken || row.resumeToken };
    else out.push(row);
    dropped = false;
  }
  return out;
}

/** The existence filters of a row, as the sorted set of `targetId:count`. */
export function filterKeys(row) {
  const keys = (row.rows ?? [])
    .filter((item) => item.kind === "filter")
    .map((item) => `${item.targetId}:${item.count}`);
  return [...new Set(keys)].toSorted();
}

/** What a row says when compared: no conditions, no timings, document runs as sets. */
export function canonicalRow(row) {
  return {
    ...(row.rows ? { rows: sortDocumentRuns(withoutFilters(row.rows)) } : {}),
    ...(row.groups ? { groups: row.groups.map((g) => ({ ...g, docs: g.docs.toSorted() })) } : {}),
    ...(row.observed ? { observed: row.observed } : {}),
    ...(row.failures ? { failures: row.failures } : {}),
    ...(row.invariantViolations ? { invariantViolations: row.invariantViolations } : {}),
    end: row.end ? { reason: row.end.reason, code: row.end.code ?? null } : null,
  };
}

/**
 * Whether the last thing a row recorded is a REMOVE of the target(s) it added, with no CURRENT
 * after it: a wait for CURRENT then ran out because the target is gone, which is the answer, not
 * a missing one.
 */
function endsRemoved(row) {
  const changes = (row.rows ?? []).filter((item) => item.kind === "targetChange");
  const last = changes.at(-1);
  return (
    last?.type === "REMOVE" &&
    last.cause !== null &&
    !changes.some((item) => item.type === "CURRENT") &&
    row.rows.at(-1) === last
  );
}

/** MATCH, DIFFER or INDETERMINATE for two rows. */
export function classifyRow(a, b) {
  // A row is unfinished when its wait ran out, its stream hit the frame cap or ended with no
  // status, or its program threw (the rest of that program never ran).
  const unfinished = (row) =>
    (row.timedOut === true && !endsRemoved(row)) ||
    row.programError === true ||
    row.end?.reason === "frame-cap" ||
    row.end?.reason === "ended-without-status";
  if (unfinished(a) || unfinished(b)) return "INDETERMINATE";
  if (!isDeepStrictEqual(canonicalRow(a), canonicalRow(b))) return "DIFFER";
  // Filters are optional, but two that came must say the same.
  const [keysA, keysB] = [filterKeys(a), filterKeys(b)];
  const comparable = keysA.length > 0 && keysB.length > 0;
  return comparable && !isDeepStrictEqual(keysA, keysB) ? "DIFFER" : "MATCH";
}

const SETTLEMENT_MIN_AGE_MS = 10 * 60_000;

/**
 * Why a coordinator's A2 read-back does not settle the incomplete cleanup of `recording`: it must
 * name the run, be clean, have been read at least ten minutes after the run ended, and show every
 * name the run issued (and every account it made) absent with a complete answer.
 */
export function settlementProblems(recording, settlement) {
  if (!settlement) return ["no A2 read-back settles the cleanup"];
  const problems = [];
  if (typeof recording.run !== "string" || settlement.run !== recording.run)
    problems.push("the read-back is for another run");
  if (settlement.clean !== true) problems.push("the read-back is not clean");
  const age = Date.parse(settlement.readAt) - Date.parse(recording.endedAt);
  if (!Number.isFinite(age) || age < SETTLEMENT_MIN_AGE_MS)
    problems.push("the read-back is not at least 10 minutes after the run ended");
  if (!Array.isArray(recording.issued)) problems.push("the recording lists no issued names");
  const absent = new Set(
    (settlement.names ?? []).filter((n) => n.exists === false).map((n) => n.name),
  );
  for (const name of recording.issued ?? [])
    if (!absent.has(name)) problems.push(`the read-back does not show ${name} absent`);
  for (const row of recording.cleanup?.accounts?.rows ?? []) {
    const read = (settlement.accounts ?? []).find((a) => a.email === row.email);
    const empty = (value) => Array.isArray(value) && value.length === 0;
    if (!read || !empty(read.foundByEmail) || !empty(read.foundByUid))
      problems.push(`the read-back does not show account ${row.email} absent`);
  }
  return problems;
}

/** The programs that threw in `recording` (native error keys are program ids). */
export const erroredPrograms = (recording) =>
  new Set(Object.keys(recording.errors ?? {}).filter((key) => key.startsWith("native/")));

/**
 * What makes a recording unfit to compare: the version, an unfinished cleanup that no A2 read-back
 * settles, an error that is not one program's. A program's own error only voids that program's
 * rows (see `withProgramErrors`).
 */
export function recordingProblems(recording, settlement) {
  const problems = [];
  if (recording.version !== 1) problems.push(`unknown recording version ${recording.version}`);
  if (recording.cleanup?.complete !== true) {
    const unsettled = settlement ? settlementProblems(recording, settlement) : [];
    if (!settlement || unsettled.length) problems.push("cleanup was not complete", ...unsettled);
  }
  const programs = erroredPrograms(recording);
  for (const [program, message] of Object.entries(recording.errors ?? {}))
    if (!programs.has(program)) problems.push(`${program}: ${message}`);
  return problems;
}

/** `rows` with those of an errored program marked, so they compare as INDETERMINATE. */
function withProgramErrors(recording) {
  const errored = erroredPrograms(recording);
  if (errored.size === 0) return recording.rows;
  return Object.fromEntries(
    Object.entries(recording.rows).map(([id, row]) => [
      id,
      errored.has(row.program) ? { ...row, programError: true } : row,
    ]),
  );
}

/**
 * Whether a declared divergence may cover this row: it differs, or the local wait ran out for an
 * answer that production gave (the production rows are finished, the local stream is a loopback
 * port, and the rows differ), which the divergence's reason then has to explain.
 */
function isKnownDivergence(verdict, production, local) {
  if (verdict === "DIFFER") return true;
  return (
    verdict === "INDETERMINATE" &&
    local.timedOut === true &&
    !isDeepStrictEqual(canonicalRow(production), canonicalRow(local))
  );
}

const GOOD = new Set(["MATCH", "KNOWN_DIVERGENCE"]);

/**
 * `productions` are the two recordings of production, `local` the one of fireemu. A production
 * pair that disagrees is NONDETERMINISTIC (the row proves nothing about local); a divergence is
 * accepted only for a row that differs, and only with a reason.
 */
export function compareRecordings({ productions, local, divergences = {}, settlements = [] }) {
  if (productions.length !== 2) throw new Error("two production recordings are required");
  const settlementOf = (recording) => settlements.find((s) => s.run === recording.run);
  for (const production of productions) {
    const problems = recordingProblems(production, settlementOf(production));
    if (problems.length)
      throw new Error(`a production recording is not clean: ${problems.join("; ")}`);
  }
  for (const [id, reason] of Object.entries(divergences))
    if (typeof reason !== "string" || reason.trim() === "")
      throw new Error(`divergence ${id} needs a reason`);
  const [firstRows, secondRows, localRows] = [...productions, local].map(withProgramErrors);
  const ids = new Set([
    ...Object.keys(firstRows),
    ...Object.keys(secondRows),
    ...Object.keys(localRows),
  ]);
  const rows = {};
  for (const id of [...ids].toSorted()) {
    const p1 = firstRows[id];
    const p2 = secondRows[id];
    const l = localRows[id];
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
      if (isKnownDivergence(verdict, p1, l) && Object.hasOwn(divergences, id))
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
    else if (argv[i] === "--settlements") args.settlements = argv[(i += 1)];
    else throw new Error(`unexpected argument ${argv[i]}`);
  }
  const read = (file) => JSON.parse(readFileSync(file, "utf8"));
  const report = compareRecordings({
    productions: args.production.map(read),
    local: read(args.local),
    divergences: args.divergences ? read(args.divergences) : {},
    settlements: args.settlements ? read(args.settlements) : [],
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
