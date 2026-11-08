// The judge of the FS-RULES shapes recording: what a recorded production answer means for a row,
// compared with what the official Firestore emulator answered and with what fireemu answers after
// the fixes that decided these shapes without a production row.
//
// A row counts only as a bare recorded answer: exactly `{status, body}` (or `{status, unresolved}`
// for a row whose ruleset did not compile), classified by the differences judge, which accepts
// only shapes production was recorded sending. A row the recorder annotated (`publication:
// "unsettled"`, because the ruleset was no longer in force after the rows; a transport failure)
// or any other key makes the answer `unknown`, as does a publication that is not a bare
// `{compiled}` flag. Rows whose two recordings differ are `unknown`.

import { sameRecording } from "../fs-rules/harness.mjs";
import { SHAPES_PROGRAMS } from "./corpus.mjs";
import { classifyAnswer } from "./diffs.mjs";

const hasExactKeys = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join() === keys.toSorted().join();

/**
 * The one runQuery 200 form beyond the differences judge's: the answer to a query with an offset
 * that skipped something. Recorded in fs-rules-production.json
 * fs-rules/query/constraints#offset-1-le-1 (`[{readTime, skippedResults: 1}]`) and in
 * fs-query-index-production.json fs-query-index/cursors/values#cursor-with-offset and
 * fs-query-index/collection-group/queries#limit-and-offset (the same first entry, then
 * `{document, readTime}` entries). The first entry has exactly `readTime` (a string) and
 * `skippedResults` (a positive integer); everything after it is a document entry. Anything else
 * is not this form.
 */
function classifySkippedAnswer(recorded) {
  const { status, body } = recorded;
  if (status !== 200 || !Array.isArray(body) || body.length === 0) return undefined;
  const [first, ...documents] = body;
  if (
    !hasExactKeys(first, ["readTime", "skippedResults"]) ||
    typeof first.readTime !== "string" ||
    !Number.isInteger(first.skippedResults) ||
    first.skippedResults < 1
  )
    return undefined;
  if (documents.length === 0) return { kind: "allowed", documents: 0 };
  if (!documents.every((entry) => hasExactKeys(entry, ["document", "readTime"]))) return undefined;
  const tail = classifyAnswer("runQuery", { status, body: documents });
  return tail.kind === "allowed" ? { kind: "allowed", documents: documents.length } : undefined;
}

/** What a recorded row answer says: `allowed`, `denied`, `not-evaluated` or `unknown`. */
export function classifyShapesAnswer(rpc, recorded) {
  if (recorded === undefined) return { kind: "unknown", detail: "no recording" };
  if (hasExactKeys(recorded, ["status", "body"])) {
    const skipped = rpc === "runQuery" ? classifySkippedAnswer(recorded) : undefined;
    if (skipped) return skipped;
    return classifyAnswer(rpc, recorded);
  }
  if (hasExactKeys(recorded, ["status", "unresolved"])) return classifyAnswer(rpc, recorded);
  const keys =
    recorded !== null && typeof recorded === "object" ? Object.keys(recorded).toSorted() : [];
  return { kind: "unknown", detail: `the answer is not bare (${keys.join(", ")})` };
}

/** What a recorded publication says: `compiled`, `refused` or `unknown`. */
export function judgeShapesPublication(recorded) {
  if (hasExactKeys(recorded, ["compiled"]) && recorded.compiled === true)
    return { answer: "compiled" };
  if (hasExactKeys(recorded, ["compiled"]) && recorded.compiled === false)
    return { answer: "refused" };
  return { answer: "unknown", detail: "no bare publication answer" };
}

/**
 * What the official emulator (firebase-tools 15.28.2, Firestore emulator jar 1.22.0) answered to
 * each row, by `<program>#<row>`, measured by `FS3_CORPUS=shapes run.mjs official`.
 */
export const OFFICIAL = {
  "queries#publishes": "compiled",
  "queries#owner-alone": "allowed",
  "queries#name-foreign-alone": "denied",
  "queries#name-own-alone": "allowed",
  "queries#two-names-own": "denied",
  "queries#two-names-mixed": "denied",
  "queries#or-named-unnamed": "allowed",
  "queries#or-foreign-unnamed": "denied",
  "queries#own-plus-unproven": "allowed",
  "queries#name-own-range": "denied",
  "queries#name-own-limit": "allowed",
  "queries#name-own-cursor": "allowed",
  "queries#nested-neg-nofilter": "denied",
  "queries#nested-neg-filtered": "allowed",
  "queries#nested-pos-nofilter": "denied",
  "queries#nested-pos-filtered": "allowed",
  "queries#keys-neg-nofilter": "allowed",
  "queries#keys-neg-filtered": "allowed",
  "queries#keys-pos-nofilter": "denied",
  "queries#keys-pos-filtered": "allowed",
  "queries#size-nofilter": "denied",
  "queries#size-filtered": "allowed",
  "queries#get-neg-nofilter": "allowed",
  "queries#get-neg-filtered": "allowed",
  "queries#get-pos-nofilter": "denied",
  "queries#get-pos-filtered": "allowed",
  "queries#cg-blocked-group": "allowed",
  "queries#cg-has-group": "denied",
  "queries#cg-blocked-single": "allowed",
  "queries#blk-stored-nofilter": "allowed",
  "queries#blk-not-null": "denied",
  "queries#blk-stored-group": "allowed",
  "queries#blk-eq-true": "denied",
  "queries#sec-list-owner": "denied",
  "queries#sec-map-owner": "denied",
  "queries#sec-bare-owner": "denied",
  "queries#sec-owner-owner": "allowed",
  "strings#publishes": "compiled",
  "strings#rng-ctl-true": "allowed",
  "strings#rng-ctl-false": "denied",
  "strings#rng-02": "denied",
  "strings#rng-03": "allowed",
  "strings#rng-13": "allowed",
  "strings#rng-34": "allowed",
  "strings#rng-12-size": "allowed",
  "strings#rng-hi": "allowed",
  "strings#low-ctl-true": "allowed",
  "strings#low-ctl-false": "denied",
  "strings#low-fire": "allowed",
  "strings#low-fire-size": "allowed",
  "strings#low-hi": "allowed",
  "strings#low-hi-size": "allowed",
  "strings#up-ctl-true": "allowed",
  "strings#up-ctl-false": "denied",
  "strings#up-fire": "allowed",
  "strings#up-hi": "allowed",
  "strings#hi-size": "allowed",
  "strings#hi-self": "allowed",
  "strings#hi-fffd": "denied",
  "regex#publishes": "compiled",
  "regex#split-ctl-true": "allowed",
  "regex#split-ctl-false": "denied",
  "regex#split-fire": "allowed",
  "regex#split-fire-by-hi": "denied",
  "regex#split-fire-by-hi-1": "allowed",
  "regex#split-hi": "allowed",
  "regex#rep-ctl-true": "allowed",
  "regex#rep-ctl-false": "denied",
  "regex#rep-fire": "allowed",
  "regex#rep-dot-fire": "allowed",
  "regex#rep-dot-fire-xx": "denied",
  "regex#rep-hi": "allowed",
  "regex#m-ctl-true": "allowed",
  "regex#m-ctl-false": "denied",
  "regex#m-dot-fire": "allowed",
  "regex#m-dotdot-fire": "denied",
  "regex#m-hi-dot": "allowed",
  "regex#m-hi-lit": "allowed",
  "fn-shadow#publishes": "compiled",
  "fn-shadow#fn-shadow-pick": "allowed",
  "fn-shadow#fn-shadow-top-only": "allowed",
  "fn-shadow#fn-shadow-inner-only": "denied",
  "fn-after#publishes": "compiled",
  "fn-after#fn-after-true": "allowed",
  "fn-after#fn-after-false": "denied",
};

/**
 * What fireemu answers after the two fixes (work/rules-query-fix 159e71576 merged with
 * work/rules-string-fix feb69c926), measured by `FS3_CORPUS=shapes run.mjs local` in the strict
 * and emulator profiles, which answered the same.
 */
export const FIXES = {
  "queries#publishes": "compiled",
  "queries#owner-alone": "allowed",
  "queries#name-foreign-alone": "denied",
  "queries#name-own-alone": "allowed",
  "queries#two-names-own": "denied",
  "queries#two-names-mixed": "denied",
  "queries#or-named-unnamed": "denied",
  "queries#or-foreign-unnamed": "denied",
  "queries#own-plus-unproven": "denied",
  "queries#name-own-range": "denied",
  "queries#name-own-limit": "denied",
  "queries#name-own-cursor": "denied",
  "queries#nested-neg-nofilter": "denied",
  "queries#nested-neg-filtered": "denied",
  "queries#nested-pos-nofilter": "denied",
  "queries#nested-pos-filtered": "allowed",
  "queries#keys-neg-nofilter": "denied",
  "queries#keys-neg-filtered": "denied",
  "queries#keys-pos-nofilter": "denied",
  "queries#keys-pos-filtered": "denied",
  "queries#size-nofilter": "denied",
  "queries#size-filtered": "denied",
  "queries#get-neg-nofilter": "denied",
  "queries#get-neg-filtered": "denied",
  "queries#get-pos-nofilter": "denied",
  "queries#get-pos-filtered": "allowed",
  "queries#cg-blocked-group": "allowed",
  "queries#cg-has-group": "denied",
  "queries#cg-blocked-single": "allowed",
  "queries#blk-stored-nofilter": "allowed",
  "queries#blk-not-null": "allowed",
  "queries#blk-stored-group": "allowed",
  "queries#blk-eq-true": "denied",
  "queries#sec-list-owner": "allowed",
  "queries#sec-map-owner": "allowed",
  "queries#sec-bare-owner": "denied",
  "queries#sec-owner-owner": "allowed",
  "strings#publishes": "compiled",
  "strings#rng-ctl-true": "allowed",
  "strings#rng-ctl-false": "denied",
  "strings#rng-02": "allowed",
  "strings#rng-03": "denied",
  "strings#rng-13": "denied",
  "strings#rng-34": "denied",
  "strings#rng-12-size": "denied",
  "strings#rng-hi": "allowed",
  "strings#low-ctl-true": "allowed",
  "strings#low-ctl-false": "denied",
  "strings#low-fire": "allowed",
  "strings#low-fire-size": "allowed",
  "strings#low-hi": "allowed",
  "strings#low-hi-size": "allowed",
  "strings#up-ctl-true": "allowed",
  "strings#up-ctl-false": "denied",
  "strings#up-fire": "allowed",
  "strings#up-hi": "allowed",
  "strings#hi-size": "allowed",
  "strings#hi-self": "allowed",
  "strings#hi-fffd": "allowed",
  "regex#publishes": "compiled",
  "regex#split-ctl-true": "allowed",
  "regex#split-ctl-false": "denied",
  "regex#split-fire": "allowed",
  "regex#split-fire-by-hi": "denied",
  "regex#split-fire-by-hi-1": "allowed",
  "regex#split-hi": "allowed",
  "regex#rep-ctl-true": "allowed",
  "regex#rep-ctl-false": "denied",
  "regex#rep-fire": "allowed",
  "regex#rep-dot-fire": "allowed",
  "regex#rep-dot-fire-xx": "denied",
  "regex#rep-hi": "allowed",
  "regex#m-ctl-true": "allowed",
  "regex#m-ctl-false": "denied",
  "regex#m-dot-fire": "allowed",
  "regex#m-dotdot-fire": "denied",
  "regex#m-hi-dot": "allowed",
  "regex#m-hi-lit": "allowed",
  "fn-shadow#publishes": "compiled",
  "fn-shadow#fn-shadow-pick": "allowed",
  "fn-shadow#fn-shadow-top-only": "allowed",
  "fn-shadow#fn-shadow-inner-only": "denied",
  "fn-after#publishes": "compiled",
  "fn-after#fn-after-true": "allowed",
  "fn-after#fn-after-false": "denied",
};

function verdictOf(answer, claim) {
  if (answer === "not-evaluated") return "not-evaluated";
  if (!["allowed", "denied", "compiled", "refused"].includes(answer)) return "unknown";
  if (claim === undefined) return "no-claim";
  return answer === claim ? "agrees" : "differs";
}

const refusalDetail = (diagnostics) =>
  diagnostics ? `${diagnostics.stage} ${diagnostics.status}: ${diagnostics.message}` : undefined;

/** Every row of the corpus: the recorded answer, its meaning and the two comparisons. */
export function shapesReport(
  fixture,
  { official = OFFICIAL, fixes = FIXES, programs = SHAPES_PROGRAMS } = {},
) {
  const rows = [];
  for (const program of programs) {
    const name = program.id.split("/").at(-1);
    const saved = fixture.programs?.[program.id];
    for (const step of program.steps) {
      const row = `${name}#${step.id}`;
      const recorded = saved?.steps?.[step.id];
      const other = saved?.second?.[step.id];
      let judged;
      if (recorded === undefined) judged = { answer: "missing", detail: "not recorded" };
      else if (other !== undefined && !sameRecording(recorded, other))
        judged = { answer: "unknown", detail: "the two recordings differ" };
      else if (step.publish) {
        judged = judgeShapesPublication(recorded);
        const detail = judged.answer === "refused" ? refusalDetail(saved.diagnostics) : undefined;
        if (detail) judged = { ...judged, detail };
      } else {
        const { kind, detail, documents } = classifyShapesAnswer(step.rpc, recorded);
        judged = {
          answer: kind,
          ...(detail ? { detail } : {}),
          ...(documents === undefined ? {} : { documents }),
        };
      }
      rows.push({
        row,
        ...(official[row] === undefined ? {} : { official: official[row] }),
        ...(fixes[row] === undefined ? {} : { fixes: fixes[row] }),
        ...judged,
        verdict: verdictOf(judged.answer, official[row]),
        fixesVerdict: verdictOf(judged.answer, fixes[row]),
      });
    }
  }
  return rows;
}

/** One printed report line: both verdicts, the row, the answer, the two expectations, the reason. */
export const shapesReportLine = (r) =>
  `${r.verdict.padEnd(14)} ${r.fixesVerdict.padEnd(14)} ${r.row.padEnd(34)} ${r.answer}${r.documents === undefined ? "" : ` docs=${r.documents}`} (official: ${r.official ?? "-"}, fixes: ${r.fixes ?? "-"})${r.detail ? ` [${r.detail}]` : ""}`;
