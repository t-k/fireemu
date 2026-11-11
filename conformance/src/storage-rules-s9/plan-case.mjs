// Family `case` of the Storage Rules observation: what `lower()` and `upper()` do to letters that
// are not ASCII. This file holds only ASCII: every probe character is built from its code point
// here and is a raw character in the rule source that is sent, so no editor or tool can normalize
// a probe.
//
// One released program holds one rule per row. A row is a Firebase v0 metadata GET of its own
// object: 200 means the rule allowed, 403 means it denied (a rule that errors also denies, which is
// why every concept has a reading that is true and one that is false under each candidate).
//
// Three candidate answers are compared with what production says:
//   ascii   only A-Z and a-z change (the official Storage runtime, and Firestore Rules in production)
//   full    the full Unicode default mapping (sharp s to SS, dotted I to i + U+0307, final sigma)
//   simple  the one-character-to-one-character mapping (no SS, dotted I to i, sigma always sigma)

import { buildPlan } from "./plan.mjs";

export const CANDIDATES = ["ascii", "full", "simple"];

const SAMPLE_PREFIX = "storage-rules-case/sr-00000000/rec1";

const asciiMap = (text, fn) =>
  fn === "lower"
    ? text.replace(/[A-Z]/g, (c) => c.toLowerCase())
    : text.replace(/[a-z]/g, (c) => c.toUpperCase());
const fullMap = (text, fn) => (fn === "lower" ? text.toLowerCase() : text.toUpperCase());
const simpleMap = (text, fn) =>
  [...text]
    .map((ch) => {
      const mapped = fn === "lower" ? ch.toLowerCase() : ch.toUpperCase();
      if ([...mapped].length === 1) return mapped;
      // The one simple lowercase mapping that the per-character default mapping spells with two characters.
      return fn === "lower" && ch === DOTTED ? "i" : ch;
    })
    .join("");
const MAPS = { ascii: asciiMap, full: fullMap, simple: simpleMap };

const objectNameOf = (row, P) =>
  row.kind === "literal" ? `${P}/${row.id}/x` : `${P}/${row.id}/${row.objectName}`;

/** Whether the rule of `row` is true under `candidate`, by evaluating the expression the row sends. */
export function predictRow(row, candidate, P = SAMPLE_PREFIX) {
  const map = MAPS[candidate];
  const applied = (text) => (row.fn ? map(text, row.fn) : text);
  if (row.kind === "literal")
    return row.rel === "size"
      ? applied(row.input).length === row.operand
      : applied(row.input) === row.operand;
  if (row.kind === "capture") return applied(row.objectName) === row.operand;
  const name = objectNameOf(row, P);
  return row.rel === "same" ? applied(name) === name : applied(name) !== name;
}

const q = (text) => `'${text}'`;

/** The condition of a row, with the raw characters: what follows `allow read: if` in the rule source. */
export function conditionOf(row) {
  if (row.kind === "literal") {
    const receiver = row.fn ? `${q(row.input)}.${row.fn}()` : q(row.input);
    return row.rel === "size"
      ? `${receiver}.size() == ${row.operand}`
      : `${receiver} == ${q(row.operand)}`;
  }
  if (row.kind === "capture") return `n.${row.fn}() == ${q(row.operand)}`;
  return row.rel === "same"
    ? `resource.name.${row.fn}() == resource.name`
    : `resource.name.${row.fn}() != resource.name`;
}

const literal = (group, id, fn, input, operand, rel = "eq", control = false) => ({
  kind: "literal",
  group,
  id,
  fn,
  input,
  rel,
  operand,
  control,
});
const capture = (group, id, objectName, fn, operand) => ({
  kind: "capture",
  group,
  id,
  objectName,
  fn,
  operand,
  rel: "eq",
  control: false,
});
const resource = (group, id, objectName, rel) => ({
  kind: "resource",
  group,
  id,
  objectName,
  fn: "lower",
  rel,
  control: false,
});

// Code points, never raw characters: nothing between this file and production may normalize them.
const cp = (...points) => String.fromCodePoint(...points);
const E_UP = cp(0x00c9); // E with acute
const E_LOW = cp(0x00e9);
const SHARP = cp(0x00df); // sharp s
const SHARP_CAP = cp(0x1e9e); // capital sharp s
const DOTTED = cp(0x0130); // I with dot above
const DOTLESS = cp(0x0131); // i without dot
const ALPHA_UP = cp(0x0391); // Greek capital alpha
const ALPHA_LOW = cp(0x03b1);
const SIGMA_UP = cp(0x03a3);
const SIGMA_FINAL = cp(0x03c2);
const SIGMA_LOW = cp(0x03c3);
const COMBINING = cp(0x0301); // combining acute
const FIRE = cp(0x1f525);
const FULL_A_LOW = cp(0xff41); // fullwidth a
const FULL_A_UP = cp(0xff21);

const RAW_ROWS = [
  // Controls: ASCII, and probes that only prove the non-ASCII literal itself parses and is counted.
  literal("ctl", "ctl-upper-true", "upper", "abc", "ABC", "eq", true),
  literal("ctl", "ctl-upper-false", "upper", "abc", "abc", "eq", true),
  literal("ctl", "ctl-lower-true", "lower", "ABC", "abc", "eq", true),
  literal("ctl", "ctl-ascii-other", "upper", "aB1-_ z", "AB1-_ Z", "eq", true),
  literal("ctl", "ctl-lower-i", "lower", "I", "i", "eq", true),
  literal("ctl", "ctl-size-nonascii", null, E_UP, 1, "size", true),
  literal("ctl", "ctl-size-emoji", null, FIRE, 2, "size", true),
  // E with acute.
  literal("acute", "acute-lower-same", "lower", E_UP, E_UP),
  literal("acute", "acute-lower-mapped", "lower", E_UP, E_LOW),
  literal("acute", "acute-upper-mapped", "upper", E_LOW, E_UP),
  literal("acute", "acute-upper-same", "upper", E_LOW, E_LOW),
  // Sharp s: SS under the full mapping, itself under the simple mapping.
  literal("sharp", "sharp-upper-full", "upper", SHARP, "SS"),
  literal("sharp", "sharp-upper-same", "upper", SHARP, SHARP),
  literal("capsharp", "capsharp-lower-mapped", "lower", SHARP_CAP, SHARP),
  literal("capsharp", "capsharp-lower-same", "lower", SHARP_CAP, SHARP_CAP),
  // Dotted I: two characters under the full mapping, i under the simple mapping.
  literal("dotted", "dotted-lower-full", "lower", DOTTED, 2, "size"),
  literal("dotted", "dotted-lower-simple", "lower", DOTTED, "i"),
  literal("dotted", "dotted-lower-same", "lower", DOTTED, DOTTED),
  literal("dotless", "dotless-upper-mapped", "upper", DOTLESS, "I"),
  literal("dotless", "dotless-upper-same", "upper", DOTLESS, DOTLESS),
  // Sigma at the end of a word: final sigma under the full mapping, plain sigma under the simple one.
  literal("sigma", "sigma-final", "lower", ALPHA_UP + SIGMA_UP, ALPHA_LOW + SIGMA_FINAL),
  literal("sigma", "sigma-plain", "lower", ALPHA_UP + SIGMA_UP, ALPHA_LOW + SIGMA_LOW),
  literal("sigma", "sigma-same", "lower", ALPHA_UP + SIGMA_UP, ALPHA_UP + SIGMA_UP),
  literal("alpha", "alpha-lower-mapped", "lower", ALPHA_UP, ALPHA_LOW),
  literal("alpha", "alpha-lower-same", "lower", ALPHA_UP, ALPHA_UP),
  // A combining sequence is two characters: the base letter changes, the mark stays, nothing composes.
  literal("comb", "comb-upper", "upper", `e${COMBINING}`, `E${COMBINING}`),
  literal("comb", "comb-upper-composed", "upper", `e${COMBINING}`, E_UP),
  // An emoji is a surrogate pair: letters around it change, it does not.
  literal("emoji", "emoji-upper", "upper", `${FIRE}a`, `${FIRE}A`),
  literal("emoji", "emoji-upper-unchanged", "upper", `${FIRE}a`, `${FIRE}a`),
  literal("emoji", "emoji-lower-size", "lower", `A${FIRE}B`, 4, "size"),
  // Fullwidth letters.
  literal("fullwidth", "fullwidth-upper-mapped", "upper", FULL_A_LOW, FULL_A_UP),
  literal("fullwidth", "fullwidth-upper-same", "upper", FULL_A_LOW, FULL_A_LOW),
  literal("fullwidth", "fullwidth-lower-mapped", "lower", FULL_A_UP, FULL_A_LOW),
  // The same calls on values that arrive with the request: a captured name and resource.name.
  capture("rt-lower", "rt-lower-same", E_UP, "lower", E_UP),
  capture("rt-lower", "rt-lower-mapped", E_UP, "lower", E_LOW),
  capture("rt-sharp", "rt-upper-sharp-full", SHARP, "upper", "SS"),
  capture("rt-sharp", "rt-upper-sharp-same", SHARP, "upper", SHARP),
  resource("rt-res", "rt-res-lower-same", E_UP, "same"),
  resource("rt-res", "rt-res-lower-differs", E_UP, "differs"),
];

/** The rows with their predictions under every candidate. */
export const CASE_ROWS = RAW_ROWS.map((row) => {
  const candidates = Object.fromEntries(CANDIDATES.map((c) => [c, predictRow(row, c)]));
  return { ...row, object: row.id, candidates };
});

const wrap = (body) =>
  `rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n${body}  }\n}\n`;
const allow = (path, condition_) =>
  `    match /${path} {\n      allow read: if ${condition_};\n    }\n`;

/** The one released ruleset of a recording. */
export function ruleSource(P) {
  let body = allow(`${P}/mk/a`, "true");
  for (const row of CASE_ROWS)
    body += allow(
      row.kind === "literal" ? `${P}/${row.id}/x` : `${P}/${row.id}/{n}`,
      conditionOf(row),
    );
  return wrap(body);
}

const objects = { mkA: { name: (P) => `${P}/mk/a`, body: "a" } };
for (const row of CASE_ROWS)
  objects[row.object] = { name: (P) => objectNameOf(row, P), body: row.id };

export const CASE_PLAN = buildPlan({
  id: "case",
  taskId: "STORAGE-RULES-CASE",
  prefixRoot: "storage-rules-case",
  estimatedUsd: 0.05,
  localBucket: "demo-storage-case.appspot.com",
  objects,
  programs: [
    {
      id: "case",
      marker: "mkA",
      objects: Object.keys(objects),
      source: ruleSource,
    },
  ],
  loadOnly: [],
  rows: CASE_ROWS.map((row) => ({
    program: "case",
    id: row.id,
    op: "meta",
    object: row.object,
    plan: row.candidates.ascii ? "allow" : "deny",
    group: row.group,
    control: row.control,
    candidates: row.candidates,
  })),
});
