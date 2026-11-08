// The report of the FS-RULES Unicode recording: what a recorded production answer means for a row,
// beside what the official Firestore emulator answered and what fireemu answers after the string
// fixes. The judge is the one of the first shapes family (shapes.mjs): only bare recorded answers
// count, anything else is `unknown`. A stored list row also reports how many documents it returned.

import { UNICODE_PROGRAMS } from "./corpus.mjs";
import { shapesReport } from "./shapes.mjs";

/**
 * What the official emulator (firebase-tools 15.28.2, Firestore emulator jar 1.22.0) answered to
 * each row, by `<program>#<row>`, measured by `FS3_CORPUS=unicode run.mjs official`.
 */
export const OFFICIAL = {
  "units#publishes": "compiled",
  "units#ctl-true": "allowed",
  "units#ctl-false": "denied",
  "units#hfish-2": "allowed",
  "units#hfish-1": "denied",
  "units#kana-2": "allowed",
  "units#ivs-3": "allowed",
  "units#zwj-8": "allowed",
  "units#zwj-5": "denied",
  "units#skin-4": "allowed",
  "units#e-eq": "denied",
  "units#e-nfd-size": "allowed",
  "units#ga-eq": "denied",
  "case#publishes": "compiled",
  "case#ctl-true": "allowed",
  "case#ctl-false": "denied",
  "case#sharp-eq": "denied",
  "case#sharp-size": "denied",
  "case#dotted-size": "denied",
  "case#fi-size": "denied",
  "case#lower-i": "allowed",
  "case#sigma": "denied",
  "regex#publishes": "compiled",
  "regex#ctl-true": "allowed",
  "regex#ctl-false": "denied",
  "regex#fire-dot": "allowed",
  "regex#fire-dotdot": "denied",
  "regex#fire-two": "denied",
  "regex#e-nfd-dot": "denied",
  "regex#zwj-dot": "denied",
  "regex#zwj-five": "allowed",
  "stored#publishes": "compiled",
  "stored#ctl-true": "allowed",
  "stored#ctl-false": "denied",
  "stored#nfc-size": "allowed",
  "stored#nfd-size": "allowed",
  "stored#nfd-lit-eq": "allowed",
  "stored#nfd-nfc-lit-eq": "denied",
  "stored#nfd-nfc-field-eq": "denied",
  "stored#hfish-size": "allowed",
  "stored#ivs-size": "allowed",
  "stored#zwj-size": "allowed",
  "stored#skin-size": "allowed",
  "stored#sharp-upper-size": "denied",
  "stored#dotted-lower-size": "denied",
  "stored#q-nfd": "allowed",
  "stored#q-nfc": "allowed",
  "stored#lq-nfd": "allowed",
  "stored#lq-nfc": "denied",
};

/**
 * What fireemu answers after the string fixes (work/rules-string-fix ba283ccf5, on main 23f09d83d),
 * measured by `FS3_CORPUS=unicode run.mjs local` in the strict and emulator profiles, which answered
 * the same. Main alone counts a supplementary character as one unit (hfish-2, ivs-3, zwj-8, skin-4
 * and their stored rows are refused there).
 */
export const FIXES = {
  "units#publishes": "compiled",
  "units#ctl-true": "allowed",
  "units#ctl-false": "denied",
  "units#hfish-2": "allowed",
  "units#hfish-1": "denied",
  "units#kana-2": "allowed",
  "units#ivs-3": "allowed",
  "units#zwj-8": "allowed",
  "units#zwj-5": "denied",
  "units#skin-4": "allowed",
  "units#e-eq": "denied",
  "units#e-nfd-size": "allowed",
  "units#ga-eq": "denied",
  "case#publishes": "compiled",
  "case#ctl-true": "allowed",
  "case#ctl-false": "denied",
  "case#sharp-eq": "allowed",
  "case#sharp-size": "allowed",
  "case#dotted-size": "allowed",
  "case#fi-size": "allowed",
  "case#lower-i": "allowed",
  "case#sigma": "allowed",
  "regex#publishes": "compiled",
  "regex#ctl-true": "allowed",
  "regex#ctl-false": "denied",
  "regex#fire-dot": "allowed",
  "regex#fire-dotdot": "denied",
  "regex#fire-two": "denied",
  "regex#e-nfd-dot": "denied",
  "regex#zwj-dot": "denied",
  "regex#zwj-five": "allowed",
  "stored#publishes": "compiled",
  "stored#ctl-true": "allowed",
  "stored#ctl-false": "denied",
  "stored#nfc-size": "allowed",
  "stored#nfd-size": "allowed",
  "stored#nfd-lit-eq": "allowed",
  "stored#nfd-nfc-lit-eq": "denied",
  "stored#nfd-nfc-field-eq": "denied",
  "stored#hfish-size": "allowed",
  "stored#ivs-size": "allowed",
  "stored#zwj-size": "allowed",
  "stored#skin-size": "allowed",
  "stored#sharp-upper-size": "allowed",
  "stored#dotted-lower-size": "allowed",
  "stored#q-nfd": "allowed",
  "stored#q-nfc": "allowed",
  "stored#lq-nfd": "allowed",
  "stored#lq-nfc": "denied",
};

/**
 * How many documents the stored list rows returned in the dry runs (the official emulator and fireemu
 * after the string fixes agree): Firestore matches the decomposed spelling only with the decomposed
 * filter, and a list rule over resource.data reads the stored spelling. A production allow with another
 * count is a difference even though both answers are allows.
 */
export const DOCUMENTS = { "stored#q-nfd": 1, "stored#q-nfc": 0, "stored#lq-nfd": 1 };

/** Every row of the family: the recorded answer, its meaning and the two comparisons. */
export function unicodeReport(fixture, { official = OFFICIAL, fixes = FIXES } = {}) {
  const rows = shapesReport(fixture, { official, fixes, programs: UNICODE_PROGRAMS });
  for (const r of rows) {
    const expected = DOCUMENTS[r.row];
    if (expected === undefined || r.answer !== "allowed" || r.documents === expected) continue;
    r.detail = `returned ${r.documents} documents, official and fixes ${expected}`;
    r.verdict = "differs";
    r.fixesVerdict = "differs";
  }
  return rows;
}
