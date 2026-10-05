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

import { isUnfinished } from "./compare.mjs";

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
  item.kind === "documentChange" || item.kind === "documentDelete" || item.kind === "documentRemove";

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
  const segment = frames.slice(addAt + 1, currentAt);
  if (segment[0]?.kind === "boundary") segment.shift();
  const letters = segment
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

/** The answer kind of each resume-variant row of a recording, by row id. */
export function answerTable(recording) {
  return Object.fromEntries(
    Object.entries(recording.rows ?? {})
      .filter(([id]) => VARIANT_ROW.test(id))
      .map(([id, row]) => [id, answerKind(row)]),
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
const GRID_ROWS = ["first", "k0", "k1", "k1-repeat", "k1-expected", "k2", "k2-expected", "k2-wrong", "k3"];

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
      (name) => `| ${name} | ${GRIDS.map((g) => cell(`native/resume-grid-${g}/${name}`)).join(" | ")} |`,
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
