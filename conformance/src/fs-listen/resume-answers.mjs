// What kind of answer production gave to a Listen resume, read off a recorded row. Packet L1b
// records the same resume under varied conditions (native-resume-variants.mjs); this reads each
// recorded row as one of a few answer kinds, so two production runs can be compared kind by kind
// and a table of kind against condition can be drawn. It classifies recorded shapes only: a shape
// that is none of them is "mixed", never forced into one.
//
// The kinds, from what comes between a target's ADD and its CURRENT (the boundary right after the
// ADD aside):
//   empty        nothing: no document and no filter
//   filter-only  an existence filter and no document (the client finds the changes by its count)
//   replay       every run of documents is followed by a global boundary (a boundary per commit)
//   diff         documents with no boundary after the first of them and no filter
//   diff+filter  documents with no boundary after the first of them, and an existence filter
//   mixed        any other mix of documents, boundaries and filters
//   reset        the target was reset
//   removed      the target was removed
//   unfinished   the wait ran out, the stream hit its cap or ended without a status, or no ADD/CURRENT

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { isUnfinished, recordingProblems } from "./compare.mjs";

export const ANSWER_KINDS = [
  "empty",
  "filter-only",
  "replay",
  "diff",
  "diff+filter",
  "mixed",
  "reset",
  "removed",
  "unfinished",
];

const isDocument = (item) =>
  item.kind === "documentChange" ||
  item.kind === "documentDelete" ||
  item.kind === "documentRemove";

/** The answer kind of one recorded row. */
export function answerKind(row) {
  if (isUnfinished(row)) return "unfinished";
  const frames = row.rows ?? [];
  const changes = frames.filter((item) => item.kind === "targetChange");
  if (changes.some((item) => item.type === "RESET")) return "reset";
  if (changes.some((item) => item.type === "REMOVE")) return "removed";
  const addAt = frames.findIndex((item) => item.kind === "targetChange" && item.type === "ADD");
  const currentAt = frames.findIndex(
    (item) => item.kind === "targetChange" && item.type === "CURRENT",
  );
  if (addAt < 0 || currentAt < addAt) return "unfinished";
  // The boundary right after the ADD is a boundary before any document; the reading below looks
  // from the first document on, so it needs no special case.
  const letters = frames
    .slice(addAt + 1, currentAt)
    .map((item) => (isDocument(item) ? "D" : item.kind === "boundary" ? "B" : "F"))
    .join("");
  const hasFilter = letters.includes("F");
  if (!letters.includes("D")) return hasFilter ? "filter-only" : "empty";
  const boundariesAfter = (letters.slice(letters.indexOf("D")).match(/B/g) ?? []).length;
  if (boundariesAfter === 0) return hasFilter ? "diff+filter" : "diff";
  if (hasFilter) return "mixed";
  // Every maximal run of documents is closed by a boundary.
  return /D([^DB]|$)/.test(letters) ? "mixed" : "replay";
}

const VARIANT_ROW = /^native\/resume-(?:grid-[a-z0-9]+|kinds|age)\//;

/** The answer kind of each resume-variant row of a recording, by row id (a program that errored answers nothing). */
export function answerTable(recording) {
  return Object.fromEntries(
    Object.entries(recording.rows ?? {})
      .filter(([id]) => VARIANT_ROW.test(id))
      .map(([id, row]) => [
        id,
        Object.hasOwn(recording.errors ?? {}, row.program) ? "unfinished" : answerKind(row),
      ]),
  );
}

/** Row by row: the kind each of two runs gave, and whether they agree (a finished answer, the same in both). */
export function answerAgreement(first, second) {
  const [a, b] = [answerTable(first), answerTable(second)];
  return Object.fromEntries(
    [...new Set([...Object.keys(a), ...Object.keys(b)])].toSorted().map((id) => {
      const [x, y] = [a[id] ?? null, b[id] ?? null];
      return [id, { first: x, second: y, agree: x !== null && x === y && x !== "unfinished" }];
    }),
  );
}

const GRIDS = ["g0", "tc", "gc"];
const GRID_ROWS = [
  "first",
  "k0",
  "k1",
  "k1-repeat",
  "k1-expected",
  "k2",
  "k2-expected",
  "k2-wrong",
  "k3",
];

/** A markdown table: the grids as row against token kind, the other programs row by row. */
export function renderAnswerTable(first, second) {
  const agreement = answerAgreement(first, second);
  const cell = (id) => {
    const entry = agreement[id];
    if (!entry) return "-";
    const [x, y] = [entry.first ?? "-", entry.second ?? "-"];
    return x === y ? x : `${x} / ${y} (runs differ)`;
  };
  const lines = [
    `| row | ${GRIDS.join(" | ")} |`,
    `|---|${GRIDS.map(() => "---").join("|")}|`,
    ...GRID_ROWS.map(
      (name) =>
        `| ${name} | ${GRIDS.map((g) => cell(`native/resume-grid-${g}/${name}`)).join(" | ")} |`,
    ),
    "",
    "| row | answer |",
    "|---|---|",
    ...Object.keys(agreement)
      .filter((id) => !id.startsWith("native/resume-grid-"))
      .map((id) => `| ${id} | ${cell(id)} |`),
  ];
  return lines.join("\n");
}

/**
 * The tokens the programs resume are saved by `save` steps, and a recording says which frame each
 * one came from (`saves`). The grids differ only in the kind of token, so a recording whose tokens
 * are not of the kind the design names would be read as a variant it is not. What each program's
 * saves must be:
 *   resume-grid-g0   T: a global boundary of the initial snapshot (no document change after CURRENT)
 *   resume-grid-tc   T: the target's CURRENT frame
 *   resume-grid-gc   T: a global boundary after a document change that came after CURRENT
 *   resume-kinds     T0..T3: global boundaries
 *   resume-age       Ta, Tb, Tc: global boundaries of the initial snapshot
 */
const TOKEN_SPEC = {
  "native/resume-grid-g0": { T: { frame: "global", before: "none" } },
  "native/resume-grid-tc": { T: { frame: "current", before: "none" } },
  "native/resume-grid-gc": { T: { frame: "global", before: "some" } },
  "native/resume-kinds": {
    T0: { frame: "global" },
    T1: { frame: "global" },
    T2: { frame: "global" },
    T3: { frame: "global" },
  },
  "native/resume-age": {
    Ta: { frame: "global", before: "none" },
    Tb: { frame: "global", before: "none" },
    Tc: { frame: "global", before: "none" },
  },
};

/** What is wrong with the saved tokens of a recording against `TOKEN_SPEC` (empty when nothing is). */
export function tokenProblems(recording) {
  if (!Array.isArray(recording.saves)) return ["the recording records no saved tokens"];
  const problems = [];
  for (const [program, names] of Object.entries(TOKEN_SPEC))
    for (const [name, want] of Object.entries(names)) {
      const entries = recording.saves.filter((e) => e.program === program && e.name === name);
      if (entries.length === 0) {
        problems.push(`${program}: no save ${name}`);
        continue;
      }
      if (entries.length > 1) {
        problems.push(`${program}: ${entries.length} saves of ${name}`);
        continue;
      }
      const [entry] = entries;
      const where = `${program} ${name}`;
      if (entry.token === null) {
        problems.push(`${where}: found no token`);
        continue;
      }
      const isGlobal = entry.token.type === "NO_CHANGE" && entry.token.targetIds.length === 0;
      const isCurrent = entry.token.type === "CURRENT" && entry.token.targetIds.length > 0;
      if (want.frame === "global" && !(entry.kind === "global" && isGlobal))
        problems.push(
          `${where}: not a global boundary (asked ${entry.kind}, frame ${entry.token.type})`,
        );
      if (want.frame === "current" && !(entry.kind === "current" && isCurrent))
        problems.push(
          `${where}: not the target's CURRENT frame (asked ${entry.kind}, frame ${entry.token.type})`,
        );
      if (want.before && typeof entry.documentChangesAfterCurrent !== "number") {
        problems.push(`${where}: the recording does not count the document changes after CURRENT`);
        continue;
      }
      if (want.before === "none" && entry.documentChangesAfterCurrent !== 0)
        problems.push(
          `${where}: ${entry.documentChangesAfterCurrent} document changes after the initial snapshot before the token, expected none (a token of the initial snapshot)`,
        );
      if (want.before === "some" && !(entry.documentChangesAfterCurrent > 0))
        problems.push(
          `${where}: no document change after the initial snapshot before the token, expected one (a token after a document change)`,
        );
    }
  return problems;
}

/** A markdown table of the saved tokens: which frame each came from. */
export function renderTokenTable(recording) {
  if (!Array.isArray(recording.saves)) return "no saved tokens recorded";
  const cell = (value) => (value === null || value === undefined ? "-" : String(value));
  return [
    "| program | save | asked | frame | type | target ids | documents before | after CURRENT |",
    "|---|---|---|---|---|---|---|---|",
    ...recording.saves.map((e) =>
      [
        e.program,
        e.name,
        e.kind,
        cell(e.token?.frameIndex),
        cell(e.token?.type),
        e.token === null ? "-" : e.token.targetIds.length ? e.token.targetIds.join(",") : "-",
        cell(e.documentChangesBefore),
        cell(e.documentChangesAfterCurrent),
      ].reduce((line, value) => `${line} ${value} |`, "|"),
    ),
  ].join("\n");
}

function main(argv) {
  if (argv.length < 1 || argv.length > 2)
    throw new Error("usage: resume-answers.mjs <recording.json> [<second recording.json>]");
  const recordings = argv.map((file) => JSON.parse(readFileSync(file, "utf8")));
  for (const recording of recordings) {
    const problems = recordingProblems(recording);
    if (problems.length) throw new Error(`a recording is not clean: ${problems.join("; ")}`);
  }
  console.log(renderAnswerTable(recordings[0], recordings[1] ?? recordings[0]));
  let flagged = false;
  recordings.forEach((recording, i) => {
    console.log(`\ntokens of run ${i + 1}:\n${renderTokenTable(recording)}`);
    const problems = tokenProblems(recording);
    if (problems.length) {
      flagged = true;
      console.log(`\ntoken problems in run ${i + 1}:\n${problems.map((p) => `- ${p}`).join("\n")}`);
    }
  });
  if (flagged) process.exitCode = 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
