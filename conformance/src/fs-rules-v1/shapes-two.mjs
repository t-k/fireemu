// The report of the second FS-RULES shapes recording: what a recorded production answer means for a
// row, beside what the official Firestore emulator answered and what fireemu answers after the
// Rules fixes. The judge is the one of the first family (shapes.mjs): only bare recorded answers
// count, anything else is `unknown`.

import { SHAPES_TWO_PROGRAMS } from "./corpus.mjs";
import { shapesReport } from "./shapes.mjs";

/**
 * What the official emulator (firebase-tools 15.28.2, Firestore emulator jar 1.22.0) answered to
 * each row, by `<program>#<row>`, measured by `FS3_CORPUS=shapes2 run.mjs official`.
 */
export const OFFICIAL = {
  "queries#publishes": "compiled",
  "queries#ctl-allow": "allowed",
  "queries#ctl-deny": "denied",
  "queries#get-stored": "allowed",
  "queries#get-absent": "allowed",
  "queries#get-allow": "allowed",
  "queries#get-deny": "denied",
  "queries#keys-stored": "allowed",
  "queries#keys-absent": "allowed",
  "queries#keys-deny": "denied",
  "queries#meta-stored": "allowed",
  "queries#meta-absent": "allowed",
  "queries#meta-deny": "denied",
  "queries#only-plain": "allowed",
  "queries#only-extra": "allowed",
  "queries#only-b-deny": "denied",
  "queries#size-plain": "allowed",
  "queries#size-extra": "allowed",
  "queries#size-zero-deny": "denied",
  "queries#name-offset": "allowed",
  "queries#owner-offset": "allowed",
  "queries#foreign-offset": "denied",
  "fn#publishes": "compiled",
  "fn#fn-resource": "allowed",
  "fn#fn-null-deny": "denied",
  "fn#fn-arg-allow": "allowed",
};

/**
 * What fireemu answers after the Rules fixes, measured by `FS3_CORPUS=shapes2 run.mjs local` in
 * the strict and emulator profiles.
 */
export const FIXES = {
  "queries#publishes": "compiled",
  "queries#ctl-allow": "allowed",
  "queries#ctl-deny": "denied",
  "queries#get-stored": "allowed",
  "queries#get-absent": "allowed",
  "queries#get-allow": "allowed",
  "queries#get-deny": "denied",
  "queries#keys-stored": "allowed",
  "queries#keys-absent": "allowed",
  "queries#keys-deny": "denied",
  "queries#meta-stored": "allowed",
  "queries#meta-absent": "allowed",
  "queries#meta-deny": "denied",
  "queries#only-plain": "denied",
  "queries#only-extra": "denied",
  "queries#only-b-deny": "denied",
  "queries#size-plain": "denied",
  "queries#size-extra": "denied",
  "queries#size-zero-deny": "denied",
  "queries#name-offset": "denied",
  "queries#owner-offset": "allowed",
  "queries#foreign-offset": "denied",
  "fn#publishes": "compiled",
  "fn#fn-resource": "denied",
  "fn#fn-null-deny": "denied",
  "fn#fn-arg-allow": "allowed",
};

/** Every row of the second family: the recorded answer, its meaning and the two comparisons. */
export const shapesTwoReport = (fixture, { official = OFFICIAL, fixes = FIXES } = {}) =>
  shapesReport(fixture, { official, fixes, programs: SHAPES_TWO_PROGRAMS });
