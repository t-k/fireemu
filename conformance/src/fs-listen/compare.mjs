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
const isOptionalFilter = (row) => row.kind === "filter" && row.unchangedNames != null;

function withoutFilters(rows) {
  const out = [];
  let dropped = false;
  for (const row of rows) {
    if (isOptionalFilter(row)) {
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

/**
 * The existence filters of a row (those with a bloom filter of unchanged names), as the sorted set
 * of what they say: the target, the count and the shape of the bloom filter. A filter without that
 * bloom filter stays in the row and is compared there.
 */
export function filterKeys(row) {
  const keys = (row.rows ?? [])
    .filter(isOptionalFilter)
    .map(
      ({ targetId, count, unchangedNames: bloom }) =>
        `${targetId}:${count}:${bloom.hashCount}:${bloom.bitmapBytes}:${bloom.padding}`,
    );
  return [...new Set(keys)].toSorted();
}

const keyOf = ({ targetId, count, unchangedNames: bloom }) =>
  `${targetId}:${count}:${bloom.hashCount}:${bloom.bitmapBytes}:${bloom.padding}`;

/**
 * Where each existence filter of a row is, what it says, and whether it carries information.
 *
 * A place is the number of frames (filters dropped, boundaries they left side by side merged)
 * before the filter, and the frame that follows it: `targetChange:CURRENT`, `boundary`, `end`...
 * so a filter before CURRENT and one after the last boundary are different places.
 *
 * A filter after the target's CURRENT carries no information when its count equals what the row
 * already says that target holds: the count of an earlier filter of the same target, or, for a
 * target the row added fresh (the frame after its ADD is not a boundary), the number of documents
 * the row delivered to it and did not take back. All of it is kept per target: another target's
 * count, documents or CURRENT excuse nothing, and a filter for a target the row never added is
 * information. The server then only repeats the count; it can disagree with
 * the client only when the count differs. Every other filter is information: a client holding
 * documents from before a resume compares its set with the count.
 */
export function filterSites(row) {
  const frames = row.rows ?? [];
  const sites = [];
  let kept = 0;
  let dropped = false;
  let lastKind;
  // What the row says about each target it added, by target id: whether the target started empty
  // (the frame after its ADD is not a boundary), whether it is CURRENT, the documents it holds
  // from what the row delivered and the counts of the filters it already carried. A filter for a
  // target the row never added, or one still before that target's CURRENT, is never redundant.
  const targets = new Map();
  let justAdded = [];
  const everyTarget = () => [...targets.values()];
  const named = (ids) => (ids?.length > 0 ? ids.map((id) => targets.get(id)).filter(Boolean) : []);
  for (const [index, item] of frames.entries()) {
    for (const id of justAdded) targets.get(id).fresh = item.kind !== "boundary";
    justAdded = [];
    if (item.kind === "targetChange" && item.type === "ADD") {
      for (const id of item.targetIds ?? []) {
        targets.set(id, { fresh: false, current: false, held: new Set(), counts: [] });
        justAdded.push(id);
      }
    }
    if (item.kind === "targetChange" && item.type === "CURRENT")
      for (const target of named(item.targetIds)) target.current = true;
    if (item.kind === "documentChange") {
      for (const target of named(item.targetIds)) target.held.add(item.doc);
      for (const target of named(item.removedTargetIds)) target.held.delete(item.doc);
    }
    if (item.kind === "documentDelete" || item.kind === "documentRemove") {
      const leaving =
        item.removedTargetIds?.length > 0 ? named(item.removedTargetIds) : everyTarget();
      for (const target of leaving) target.held.delete(item.doc);
    }
    if (isOptionalFilter(item)) {
      const next = frames.slice(index + 1).find((later) => !isOptionalFilter(later));
      const following = next
        ? next.kind === "targetChange"
          ? `targetChange:${next.type}`
          : next.kind
        : "end";
      const target = targets.get(item.targetId);
      const redundant =
        target !== undefined &&
        target.current &&
        (target.counts.includes(item.count) || (target.fresh && target.held.size === item.count));
      sites.push({ key: keyOf(item), place: `${kept}|${following}`, redundant });
      target?.counts.push(item.count);
      dropped = true;
      continue;
    }
    if (!(dropped && item.kind === "boundary" && lastKind === "boundary")) kept += 1;
    lastKind = item.kind;
    dropped = false;
  }
  return sites;
}

/** The informative filters of a row, as `place#key` strings. */
const informative = (row) =>
  filterSites(row)
    .filter((site) => !site.redundant)
    .map((site) => `${site.place}#${site.key}`);

/** The informative filters of a row by place: place to the set of keys said there. */
function byPlace(row) {
  const places = new Map();
  for (const site of filterSites(row))
    if (!site.redundant)
      places.set(site.place, new Set([...(places.get(site.place) ?? []), site.key]));
  return places;
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
 * A row as one line: its frames in order (documents as a set where the comparer treats them so)
 * and the existence filters it carries (target, count, shape of the bloom filter). Used to quote
 * what a run recorded.
 */
export function describeRow(row) {
  const frames = (canonicalRow(row).rows ?? []).map((item) => {
    if (item.kind === "targetChange") {
      const ids = item.targetIds.length ? `[${item.targetIds}]` : "";
      const cause = item.cause ? `(code ${item.cause.code})` : "";
      return `${item.type}${ids}${cause}${item.resumeToken ? "+token" : ""}`;
    }
    if (item.kind === "boundary") return item.resumeToken ? "boundary+token" : "boundary";
    if (item.kind === "documentChange")
      return `change ${item.doc}${item.removedTargetIds.length ? " (removed target ids)" : ""}`;
    if (item.kind === "filter") return `filter(${item.targetId},${item.count})`;
    return item.doc === undefined ? item.kind : `${item.kind} ${item.doc}`;
  });
  const filters = filterKeys(row);
  return `${frames.join(", ")}${filters.length ? ` | filters ${filters.join(" ")}` : ""}`;
}

/**
 * Whether the last thing a row recorded is a REMOVE, with a cause that carries a status code, of
 * targets the row added (or the row's only target change), and no CURRENT after it: a wait for CURRENT then ran out because the
 * target is gone, which is the answer, not a missing one.
 */
function endsRemoved(row) {
  const changes = (row.rows ?? []).filter((item) => item.kind === "targetChange");
  const last = changes.at(-1);
  if (last?.type !== "REMOVE" || row.rows.at(-1) !== last) return false;
  if (typeof last.cause?.code !== "number") return false;
  if (changes.some((item) => item.type === "CURRENT")) return false;
  const added = new Set(
    changes.filter((item) => item.type === "ADD").flatMap((item) => item.targetIds ?? []),
  );
  const removed = last.targetIds ?? [];
  if (removed.length === 0) return false;
  // Production removes a target whose token is junk without acknowledging it first: a REMOVE
  // that is the row's only target change (resume-token/invalid, both runs).
  if (added.size === 0) return changes.length === 1;
  return removed.every((id) => added.has(id));
}

/**
 * A row is unfinished when its wait ran out (unless the target was removed with a cause: that is
 * the answer), its stream hit the frame cap or ended with no status, or its program threw (the
 * rest of that program never ran).
 */
export function isUnfinished(row) {
  return (
    (row.timedOut === true && !endsRemoved(row)) ||
    row.programError === true ||
    row.end?.reason === "frame-cap" ||
    row.end?.reason === "ended-without-status"
  );
}

/** MATCH, DIFFER or INDETERMINATE for two rows. */
export function classifyRow(a, b) {
  if (isUnfinished(a) || isUnfinished(b)) return "INDETERMINATE";
  if (!isDeepStrictEqual(canonicalRow(a), canonicalRow(b))) return "DIFFER";
  // A filter only one of the rows has is optional (production shows it both ways); two rows that
  // both have a filter in the same place must say the same.
  const [placesA, placesB] = [byPlace(a), byPlace(b)];
  for (const [place, keys] of placesA) {
    const other = placesB.get(place);
    if (other && !isDeepStrictEqual([...keys].toSorted(), [...other].toSorted())) return "DIFFER";
  }
  return "MATCH";
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
  // Absence never settles an unknown create: any create the journal left unconfirmed stays open.
  if (!Array.isArray(settlement.unconfirmed))
    problems.push("the read-back does not say which creates are unconfirmed");
  else if (settlement.unconfirmed.length > 0)
    problems.push(`the read-back leaves unconfirmed creates: ${settlement.unconfirmed.join(", ")}`);
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
 * A divergence entry is a reason, or `{ reason, coversLocalTimeout: true }`. Only the second form
 * may cover a local wait that ran out (see `isKnownDivergence`).
 */
function divergenceOf(entry) {
  return typeof entry === "string"
    ? { reason: entry, coversLocalTimeout: false }
    : { reason: entry.reason, coversLocalTimeout: entry.coversLocalTimeout === true };
}

/**
 * MATCH, DIFFER or INDETERMINATE for a local row against the two production rows of the same id
 * (which agree, `classifyRow`). The frames compare as in `classifyRow`. An existence filter that
 * both production runs sent in the same place (see `filterSites`) and that carries information is
 * required of the local row, in that place: it carries what the client acts on. A filter only one
 * run sent is optional, and a filter that repeats a count the row already says (`redundant`) is
 * ignored. An informative filter the local row sends that neither production run sent there is a
 * difference.
 */
export function classifyLocal(first, second, local) {
  if (isUnfinished(first) || isUnfinished(second) || isUnfinished(local)) return "INDETERMINATE";
  if (!isDeepStrictEqual(canonicalRow(first), canonicalRow(local))) return "DIFFER";
  const [sitesFirst, sitesSecond, sitesLocal] = [first, second, local].map(informative);
  const required = sitesFirst.filter((site) => sitesSecond.includes(site));
  const allowed = new Set([...sitesFirst, ...sitesSecond]);
  const complete = required.every((site) => sitesLocal.includes(site));
  return complete && sitesLocal.every((site) => allowed.has(site)) ? "MATCH" : "DIFFER";
}

/**
 * Whether a declared divergence may cover this row: the rows differ, or (only for an entry that
 * says `coversLocalTimeout`) the local wait ran out for an answer that production gave: the
 * production rows are finished, the local stream is a loopback port, and the rows differ.
 */
function isKnownDivergence(verdict, production, local, entry) {
  if (verdict === "DIFFER") return true;
  return (
    verdict === "INDETERMINATE" &&
    entry.coversLocalTimeout &&
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
  for (const [id, entry] of Object.entries(divergences)) {
    const reason = typeof entry === "string" ? entry : entry?.reason;
    if (typeof reason !== "string" || reason.trim() === "")
      throw new Error(`divergence ${id} needs a reason`);
  }
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
      const verdict = classifyLocal(p1, p2, l);
      const entry = Object.hasOwn(divergences, id) ? divergenceOf(divergences[id]) : undefined;
      if (entry && isKnownDivergence(verdict, p1, l, entry))
        rows[id] = { status: "KNOWN_DIVERGENCE", reason: entry.reason };
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
