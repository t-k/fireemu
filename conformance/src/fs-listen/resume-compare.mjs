// Compares a local recording of the L1b resume variants with what two production runs answered.
//
// Production gave two valid answers to a one-commit modify or enter in the L1b runs (a replay from
// a change log, or a diff with the count), in some runs and not in others, so a row is compared
// with every answer a production run gave, not with one: a local answer that is any of them
// matches (MATCH_EITHER when the two runs differed, MATCH when they agreed). An answer is its
// kind (resume-answers.mjs) and the existence filters sent before CURRENT (a bloom filter's size
// and count, or the count-only one); a filter after CURRENT is optional in production and is not
// part of it. A row whose answer is none of those is DIFFER unless it is declared, with its
// reason, in a register (KNOWN_DIVERGENCE).

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { answerKind } from "./resume-answers.mjs";

const VARIANT_ROW = /^native\/resume-(?:grid-[a-z0-9]+|kinds|age)\//;
const isFilter = (item) => item.kind === "filter";

/** The filters a row sent before its first CURRENT, as `target:count:hashCount:bytes:padding`. */
export function filtersBeforeCurrent(row) {
  const frames = row.rows ?? [];
  const currentAt = frames.findIndex((f) => f.kind === "targetChange" && f.type === "CURRENT");
  const before = currentAt < 0 ? frames : frames.slice(0, currentAt);
  return before
    .filter(isFilter)
    .map((f) => {
      const bloom = f.unchangedNames ?? { hashCount: 0, bitmapBytes: 0, padding: 0 };
      return `${f.targetId}:${f.count}:${bloom.hashCount}:${bloom.bitmapBytes}:${bloom.padding}`;
    })
    .toSorted();
}

/** What a row answered: its kind and its filters before CURRENT. */
export const answerSignature = (row) => ({
  kind: answerKind(row),
  filters: filtersBeforeCurrent(row),
});

const same = (a, b) => a.kind === b.kind && a.filters.join(" ") === b.filters.join(" ");
const describe = ({ kind, filters }) => (filters.length ? `${kind} [${filters.join(" ")}]` : kind);

/**
 * The answers of the production runs, row by row: `{ runs: [run ids], rows: { id: { run: signature } } }`.
 * A row a run lacks, or did not finish, is left out of that run (and a row no run finished is out).
 */
export function allowedAnswers(recordings) {
  const rows = {};
  for (const recording of recordings) {
    for (const [id, row] of Object.entries(recording.rows ?? {})) {
      if (!VARIANT_ROW.test(id) || id.endsWith("/first")) continue;
      const signature = answerSignature(row);
      if (signature.kind === "unfinished") continue;
      rows[id] = { ...rows[id], [recording.run]: signature };
    }
  }
  return { runs: recordings.map((r) => r.run), rows };
}

/**
 * The comparison. `allowed` is `allowedAnswers` of the production runs (or the committed fixture of
 * it), `local` a local recording, `divergences` a register `{ rowId: reason | { reason } }`.
 */
export function compareResumeVariants({ allowed, local, divergences = {} }) {
  const rows = {};
  const counts = {};
  for (const [id, byRun] of Object.entries(allowed.rows)) {
    const observed = Object.entries(byRun);
    const signatures = observed.map(([, signature]) => signature);
    const localRow = local.rows?.[id];
    const mine = localRow ? answerSignature(localRow) : null;
    let status;
    if (!mine || mine.kind === "unfinished") status = "INDETERMINATE";
    else if (signatures.some((s) => same(s, mine))) {
      const agreed = signatures.every((s) => same(s, signatures[0]));
      status = agreed ? "MATCH" : "MATCH_EITHER";
    } else if (Object.hasOwn(divergences, id)) status = "KNOWN_DIVERGENCE";
    else status = "DIFFER";
    rows[id] = {
      status,
      observed: observed.map(([run, signature]) => `${run}: ${describe(signature)}`),
      local: mine ? describe(mine) : null,
      ...(status === "KNOWN_DIVERGENCE"
        ? { reason: divergences[id].reason ?? divergences[id] }
        : {}),
    };
    counts[status] = (counts[status] ?? 0) + 1;
  }
  const missing = Object.keys(local.rows ?? {}).filter(
    (id) => VARIANT_ROW.test(id) && !id.endsWith("/first") && !Object.hasOwn(allowed.rows, id),
  );
  const ok = Object.values(rows).every(
    (r) => r.status !== "DIFFER" && r.status !== "INDETERMINATE",
  );
  return { rows, summary: counts, ok, localRowsNotObserved: missing.toSorted() };
}

/** A markdown table of a comparison. */
export function renderComparison(report) {
  const lines = ["| row | status | production | local |", "|---|---|---|---|"];
  for (const [id, row] of Object.entries(report.rows))
    lines.push(
      `| ${id.replace("native/resume-", "")} | ${row.status} | ${row.observed.join("; ")} | ${row.local ?? "-"} |`,
    );
  lines.push("", JSON.stringify(report.summary), report.ok ? "OK" : "NOT OK");
  return lines.join("\n");
}

function main(argv) {
  const [mode, ...rest] = argv;
  const read = (file) => JSON.parse(readFileSync(file, "utf8"));
  if (mode === "build" && rest.length >= 3) {
    // build <production 1> <production 2> <out>
    const [first, second, out] = rest;
    writeFileSync(out, `${JSON.stringify(allowedAnswers([read(first), read(second)]), null, 2)}\n`);
    return;
  }
  if (mode === "compare" && (rest.length === 2 || rest.length === 3)) {
    // compare <allowed.json> <local.json> [register.json]
    const report = compareResumeVariants({
      allowed: read(rest[0]),
      local: read(rest[1]),
      divergences: rest[2] ? read(rest[2]) : {},
    });
    console.log(renderComparison(report));
    process.exitCode = report.ok ? 0 : 1;
    return;
  }
  throw new Error(
    "usage: resume-compare.mjs build <production 1> <production 2> <out> | compare <allowed.json> <local.json> [<register.json>]",
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}
