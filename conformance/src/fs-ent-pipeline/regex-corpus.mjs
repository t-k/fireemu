// The pipeline regex observation (owner decision 2404, issue "Pipeline regex RE2 Unicode
// observations"): what production answers when the four regex functions meet Unicode subjects,
// the shorthand classes and word boundaries, inline flags, escaped backslashes, ASCII controls
// and captures. The strict guard keeps patterns holding \d \D \w \W \s \S \b \B unobserved until
// this is recorded.
//
// Every case is one call of one function over one probe document, `select({v: call})` with the
// subject as a field reference and the pattern as a string, as FS-ENT-ORACLE O-8B asked the
// function families. One pair (a subject field and a pattern) is asked of all four functions.
// Programs are `fs-ent-pipeline-regex/rx/<group>`; each seeds the one document `rx/d1`.
//
// This file is ASCII: every non-ASCII code point is built by cp(), because the formatter turns
// \u escapes in string literals back into raw characters.

import { str } from "../fs-query-index/values.mjs";
import { fld, read, select, fn } from "./builders.mjs";

export const REGEX_LANE = "fs-ent-pipeline-regex";
export const REGEX_PREFIX = `${REGEX_LANE}/`;
export const REGEX_FUNCTIONS = ["regex_contains", "regex_match", "regex_find", "regex_find_all"];

/** The subjects: string fields of the probe document `rx/d1`. */
const cp = (...codes) => String.fromCodePoint(...codes);
const SUBJECTS = {
  ad: cp(0x661, 0x662, 0x663), // ARABIC-INDIC DIGIT ONE TWO THREE
  n123: "123",
  ead: cp(0xe9), // e with acute, precomposed
  cafe: `caf${cp(0xe9)}`,
  edec: `e${cp(0x301)}`, // e then COMBINING ACUTE ACCENT
  eup: cp(0xc9),
  nbsp: `a${cp(0xa0)}b`,
  sp: "a b",
  vt: `a${cp(0xb)}b`, // vertical tab
  nel: `a${cp(0x85)}b`, // NEXT LINE
  em: `a${cp(0x2003)}b`, // EM SPACE
  nl: "a\nb",
  tab: "a\tb",
  ctl: `a${cp(1)}b`,
  del: `a${cp(0x7f)}b`,
  sigma: cp(0x3c2), // GREEK SMALL LETTER FINAL SIGMA
  kelvin: cp(0x212a), // KELVIN SIGN
  bs: "a\\b", // a, one backslash, b
  bsd: "\\d", // one backslash, d
  ab: "ab",
  b1: "b",
  abab: "abab",
  ac: "ac",
  ab2: "Ab",
  aaa: "aaa",
};
export const PROBE = Object.fromEntries(Object.entries(SUBJECTS).map(([k, v]) => [k, str(v)]));

const p = (group, label, subject, pattern) => ({ group, label, subject, pattern });

/** The pairs, by group. Patterns are JavaScript strings: "\\d" is the four characters \d. */
export const PAIRS = [
  // Shorthand digit classes against Arabic-Indic digits.
  p("digit", "d-arabic", "ad", "\\d"),
  p("digit", "d-arabic-run", "ad", "\\d+"),
  p("digit", "nd-arabic", "ad", "\\D"),
  p("digit", "d-ascii-ctl", "n123", "\\d+"),
  p("digit", "d-bracket", "ad", "[\\d]"),
  p("digit", "pnd-arabic", "ad", "\\p{Nd}+"),
  p("digit", "posix-digit", "ad", "[[:digit:]]"),
  p("digit", "range-ctl", "ad", "[0-9]"),
  // Word classes and word boundaries against e with acute.
  p("word", "w-eacute", "ead", "\\w"),
  p("word", "nw-eacute", "ead", "\\W"),
  p("word", "w-cafe-run", "cafe", "\\w+"),
  p("word", "nw-cafe", "cafe", "\\W"),
  p("word", "b-cafe-edge", "cafe", "\\bcaf\\b"),
  p("word", "b-cafe-whole", "cafe", `\\bcaf${cp(0xe9)}\\b`),
  p("word", "b-eacute", "ead", "\\b"),
  p("word", "nb-eacute", "ead", "\\B"),
  p("word", "w-decomposed", "edec", "\\w+"),
  p("word", "pl-eacute", "ead", "\\pL"),
  p("word", "w-bracket", "ead", "[\\w]"),
  p("word", "posix-word", "ead", "[[:word:]]"),
  // Space classes against no-break space and its neighbours.
  p("space", "s-nbsp", "nbsp", "a\\sb"),
  p("space", "ns-nbsp", "nbsp", "a\\Sb"),
  p("space", "s-nbsp-only", "nbsp", "\\s"),
  p("space", "s-vt", "vt", "a\\sb"),
  p("space", "s-nel", "nel", "a\\sb"),
  p("space", "s-em", "em", "a\\sb"),
  p("space", "s-space-ctl", "sp", "a\\sb"),
  p("space", "posix-nbsp", "nbsp", "a[[:space:]]b"),
  p("space", "posix-vt", "vt", "a[[:space:]]b"),
  p("space", "hex-nbsp", "nbsp", "a\\x{a0}b"),
  // Inline flags.
  p("flag", "i-eacute", "eup", `(?i)${cp(0xe9)}`),
  p("flag", "i-sigma", "sigma", `(?i)${cp(0x3c3)}`),
  p("flag", "i-kelvin", "kelvin", "(?i)k"),
  p("flag", "i-ascii-ctl", "ab2", "(?i)ab"),
  p("flag", "i-group", "ab2", "(?i:a)b"),
  p("flag", "i-off", "ab2", "(?i)a(?-i)b"),
  p("flag", "s-dot", "nl", "a.b"),
  p("flag", "s-dotall", "nl", "(?s)a.b"),
  p("flag", "m-anchor", "nl", "(?m)^b$"),
  p("flag", "m-off", "nl", "^b$"),
  p("flag", "u-flag", "ead", "(?u)\\w"),
  p("flag", "nu-flag", "ead", "(?-u)\\w"),
  p("flag", "ungreedy", "aaa", "(?U)a+"),
  // Escaped backslashes.
  p("backslash", "bs-lit", "bs", "\\\\"),
  p("backslash", "bs-lit-run", "bs", "a\\\\b"),
  p("backslash", "bs-in-class", "bs", "[\\\\]"),
  p("backslash", "bs-hex", "bs", "\\x{5c}"),
  p("backslash", "bsd-pair", "bsd", "\\\\d"),
  p("backslash", "bsd-digit", "bsd", "\\d"),
  p("backslash", "bs-trailing", "bs", "\\"),
  // ASCII controls.
  p("control", "ctl-hex", "ctl", "a\\x01b"),
  p("control", "ctl-class", "ctl", "[[:cntrl:]]"),
  p("control", "ctl-range", "ctl", "[\\x00-\\x1f]"),
  p("control", "ctl-dot", "ctl", "a.b"),
  p("control", "del-class", "del", "[[:cntrl:]]"),
  p("control", "tab-s", "tab", "a\\sb"),
  p("control", "tab-lit", "tab", "a\\tb"),
  // Captures: optional, alternative, several, named, nested and empty.
  p("capture", "cap-alt-first", "ab", "(a)|(b)"),
  p("capture", "cap-alt-second", "b1", "(a)|(b)"),
  p("capture", "cap-opt-unmatched", "b1", "(a)?b"),
  p("capture", "cap-alt-one", "b1", "(a)|b"),
  p("capture", "cap-two", "ab", "(a)(b)"),
  p("capture", "cap-noncapturing", "ab", "a(?:b)"),
  p("capture", "cap-named", "ab", "(?P<x>a)b"),
  p("capture", "cap-nested", "ab", "((a))b"),
  p("capture", "cap-empty", "b1", "(a*)"),
  p("capture", "cap-all-alt", "abab", "(a)|b"),
  p("capture", "cap-all-opt", "ac", "(a)(b)?"),
];

export const stepIdOf = (name, label) => `${name.replaceAll("_", "-")}-${label}`;

// The programs whose subjects hold control characters (vertical tab, NEL, U+0001, U+007F) come
// last: if production refused to store such a string, the seed would fail and end the recording,
// and only these two programs would be lost.
const GROUPS = ["digit", "word", "flag", "backslash", "capture", "space", "control"];

/** The probe document of one group: only the subjects its pairs read, in the order of PROBE. */
const seedOf = (group) => {
  const used = new Set(PAIRS.filter((pair) => pair.group === group).map((pair) => pair.subject));
  return Object.fromEntries(Object.entries(PROBE).filter(([name]) => used.has(name)));
};

export const PROGRAMS = GROUPS.map((group) => ({
  id: `${REGEX_PREFIX}rx/${group}`,
  seed: [["rx/d1", seedOf(group)]],
  steps: PAIRS.filter((pair) => pair.group === group).flatMap((pair) =>
    REGEX_FUNCTIONS.map((name) =>
      read(
        stepIdOf(name, pair.label),
        "rx",
        select({ v: fn(name, fld(pair.subject), str(pair.pattern)) }),
      ),
    ),
  ),
}));
