// The FS-ENT-ORACLE O-9 corpus (the last residual observation before the retirement of the
// kept database): the shapes the strict pipeline stages are gated on for lack of a recording.
// Program ids are `fs-ent-pipeline/o9/<area>-main`.
//
//   reps    which of -0 and 0, and of 1 and 1.0, a group or distinct key shows, over collections
//           whose ids, values and write order differ, each read bare in the same program (the
//           scan order) next to the aggregate and the distinct
//   fields  `add_fields` with a nested alias of a missing value, an alias equal to an existing
//           scalar parent, overlapping aliases
//   types   `is_type` of a missing value for each of the twenty type names, read as the value,
//           its negation, `is_error` and `is_absent`
//   ops     `or`, `xor`, `nor` (and `and` as the control) with three, four and five operands over
//           true, false, null and a missing field; boolean functions given a non-boolean after a
//           decisive operand; `equal_any`, `not_equal_any` and `array_contains` over a list or
//           array that is not an array
//   cg      `collection_group` with an ancestor that is a collection path, an unrelated or
//           missing document, a full resource name of the database itself, and other forms
//   order   the order of a bare read as a function of the document id: 50 ids written in two
//           orders, a different collection holding the same ids, and unrelated ids
//
// Reads only: every document is written by the harness seed and wiped by the harness.

import { arr, bool, dbl, int, map, nul, str } from "../fs-query-index/values.mjs";
import {
  addFields,
  aggregate,
  distinct,
  eq,
  fld,
  fn,
  limit,
  offset,
  read,
  readFrom,
  select,
  sort,
  asc,
  desc,
  stage,
  where,
} from "./builders.mjs";
import { defineArea } from "./o6-corpus.mjs";

export const O9_PREFIX = "fs-ent-pipeline/o9/";

const define = (area, groups) => defineArea(area, groups, O9_PREFIX);

const countAll = () => fn("count");
const minimum = (path) => fn("minimum", fld(path));
const maximum = (path) => fn("maximum", fld(path));

const MISSING = fld("zz");
const n = fld("n");

// --- reps ---

const NEG_ZERO = dbl("-0");
const POS_ZERO = dbl(0);
const ONE_INT = int(1);
const ONE_DBL = dbl(1);

/** `[[coll/id, {v, n}], ...]` for `[id, value]` pairs, `n` being the id's number in `ids`. */
const valued = (coll, pairs, { reverse = false } = {}) => {
  const docs = pairs.map(([id, v], i) => [`${coll}/${id}`, { v, n: int(i + 1) }]);
  return reverse ? docs.toReversed() : docs;
};
const IDS6 = ["z1", "z2", "z3", "z4", "z5", "z6"];
const ODD_IDS6 = ["m9", "b3", "x1", "c7", "a2", "q5"];
const alternate = (ids, first, second) => ids.map((id, i) => [id, i % 2 === 0 ? first : second]);

/** The collections of the group-key experiment: name, seed documents. */
export const REPS_COLLECTIONS = [
  ["zs", valued("zs", alternate(IDS6, NEG_ZERO, POS_ZERO))],
  ["zt", valued("zt", alternate(IDS6, POS_ZERO, NEG_ZERO))],
  ["zr", valued("zr", alternate(IDS6, NEG_ZERO, POS_ZERO), { reverse: true })],
  ["zu", valued("zu", alternate(ODD_IDS6, NEG_ZERO, POS_ZERO))],
  [
    "zp",
    valued("zp", [
      ["a", NEG_ZERO],
      ["b", POS_ZERO],
    ]),
  ],
  [
    "zq",
    valued("zq", [
      ["a", POS_ZERO],
      ["b", NEG_ZERO],
    ]),
  ],
  ["os", valued("os", alternate(IDS6, ONE_INT, ONE_DBL))],
  ["ot", valued("ot", alternate(IDS6, ONE_DBL, ONE_INT))],
  ["ou", valued("ou", alternate(IDS6, ONE_INT, ONE_DBL), { reverse: true })],
];

const reps = {
  id: "main",
  seed: REPS_COLLECTIONS.flatMap(([, docs]) => docs),
  steps: REPS_COLLECTIONS.flatMap(([coll]) => [
    read(`bare-${coll}`, coll),
    read(
      `agg-${coll}`,
      coll,
      aggregate({ c: countAll(), lo: minimum("n"), hi: maximum("n") }, { v: fld("v") }),
    ),
    read(`dist-${coll}`, coll, distinct({ v: fld("v") })),
  ]),
};

// --- fields ---

const FA = "fa";
const faDocs = [
  [`${FA}/a`, { n: int(1), m: map({ k: int(1) }) }],
  [`${FA}/b`, { n: int(2), m: int(5) }],
  [`${FA}/c`, { n: int(3) }],
  [`${FA}/d`, { n: int(4), m: map({ k: int(1), j: int(2) }) }],
];
const faStep = (id, num, aliases) => read(id, FA, where(eq(n, int(num))), addFields(aliases));

const fields = {
  id: "main",
  seed: faDocs,
  steps: [
    faStep("nested-missing-into-map", 1, { "m.r": MISSING }),
    faStep("nested-missing-scalar-parent", 2, { "m.r": MISSING }),
    faStep("nested-missing-absent-parent", 3, { "m.r": MISSING }),
    faStep("nested-missing-new-parent", 1, { "nm.r": MISSING }),
    faStep("nested-missing-deep-new-parent", 1, { "nm.p.q": MISSING }),
    faStep("top-missing-over-scalar", 2, { m: MISSING }),
    faStep("top-missing-over-map", 1, { m: MISSING }),
    faStep("nested-null-over-scalar", 2, { "m.r": nul() }),
    faStep("nested-value-sibling", 4, { "m.r": int(9) }),
    faStep("overlap-parent-child", 1, { p: int(1), "p.q": int(2) }),
    faStep("overlap-child-parent", 1, { "p.q": int(2), p: int(1) }),
    faStep("overlap-existing-parent-child", 1, { m: int(7), "m.k": int(8) }),
    faStep("siblings", 4, { "s.a": int(1), "s.b": int(2) }),
    faStep("siblings-one-missing", 1, { "s.a": MISSING, "s.b": int(2) }),
    faStep("overlap-missing-parent-child", 1, { s: MISSING, "s.b": int(2) }),
  ],
};

// --- types ---

/** The type names `is_type` takes, in the order production lists them (the O-5 refusal text). */
export const TYPE_NAMES = [
  "null",
  "array",
  "boolean",
  "bytes",
  "timestamp",
  "geo_point",
  "number",
  "int32",
  "int64",
  "float64",
  "decimal128",
  "map",
  "reference",
  "string",
  "vector",
  "max_key",
  "min_key",
  "object_id",
  "regex",
  "bson_timestamp",
];

const types = {
  id: "main",
  seed: [["ty/a", { v: int(1), n: int(1) }]],
  steps: TYPE_NAMES.map((name) => {
    const call = () => fn("is_type", MISSING, str(name));
    return read(
      `missing-${name.replaceAll("_", "-")}`,
      "ty",
      select({
        a: call(),
        b: fn("not", call()),
        c: fn("is_error", call()),
        d: fn("is_absent", call()),
      }),
    );
  }),
};

// --- ops ---

const TOKENS = { t: bool(true), f: bool(false), n: nul(), m: MISSING };

/** Every string of `length` characters over `alphabet`, in lexicographic order. */
export function words(alphabet, length) {
  let out = [""];
  for (let i = 0; i < length; i++) out = out.flatMap((w) => [...alphabet].map((ch) => w + ch));
  return out;
}

/** A select of one call of `name` per word over the operand tokens, aliased `<word>`. */
const table = (id, name, alphabet, length) =>
  read(
    id,
    "ob",
    select(
      Object.fromEntries(
        words(alphabet, length).map((w) => [w, fn(name, ...[...w].map((ch) => TOKENS[ch]))]),
      ),
    ),
  );
const one = (id, call) => read(id, "ob", select({ v: call }));

const ops = {
  id: "main",
  seed: [["ob/a", { n: int(1), nu: nul() }]],
  steps: [
    table("or3-tfn", "or", "tfn", 3),
    table("and3-tfn", "and", "tfn", 3),
    table("or3-tfm", "or", "tfm", 3),
    table("and3-tfm", "and", "tfm", 3),
    table("or4-tf", "or", "tf", 4),
    table("and4-tf", "and", "tf", 4),
    // xor and nor take booleans only (`xor(x: boolean*)`, where or and and take `boolean?*`):
    // their tables hold true and false, and a null or missing operand is asked one call at a time
    // so that a refusal costs one answer, not a whole table.
    table("xor3-tf", "xor", "tf", 3),
    table("nor3-tf", "nor", "tf", 3),
    table("xor4-tf", "xor", "tf", 4),
    table("nor4-tf", "nor", "tf", 4),
    table("xor5-tf", "xor", "tf", 5),
    one("xor2-null", fn("xor", bool(true), nul())),
    one("nor2-null", fn("nor", bool(false), nul())),
    one("xor3-null-last", fn("xor", bool(true), bool(false), nul())),
    one("xor3-null-first", fn("xor", nul(), bool(true), bool(false))),
    one("xor3-missing", fn("xor", bool(true), bool(false), MISSING)),
    one("nor3-null-last", fn("nor", bool(false), bool(false), nul())),
    one("nor3-null-first", fn("nor", nul(), bool(false), bool(false))),
    one("nor3-missing", fn("nor", bool(false), bool(false), MISSING)),
    one("and-false-int", fn("and", bool(false), int(1))),
    one("and-int-false", fn("and", int(1), bool(false))),
    one("and-true-int", fn("and", bool(true), int(1))),
    one("and-null-int", fn("and", nul(), int(1))),
    one("or-true-int", fn("or", bool(true), int(1))),
    one("or-int-true", fn("or", int(1), bool(true))),
    one("or-false-int", fn("or", bool(false), int(1))),
    one("or-null-int", fn("or", nul(), int(1))),
    one("nor-true-int", fn("nor", bool(true), int(1))),
    one("nor-false-int", fn("nor", bool(false), int(1))),
    one("xor-true-int", fn("xor", bool(true), int(1))),
    one("equal-any-not-array", fn("equal_any", n, int(1))),
    one("not-equal-any-not-array", fn("not_equal_any", n, int(1))),
    one("not-equal-any-string", fn("not_equal_any", n, str("a"))),
    one("not-equal-any-null", fn("not_equal_any", n, nul())),
    one("array-contains-null-array", fn("array_contains", nul(), int(1))),
    one("array-contains-missing-array", fn("array_contains", MISSING, int(1))),
    one("array-contains-not-array", fn("array_contains", n, int(1))),
    one("array-contains-any-null-list", fn("array_contains_any", arr(int(1)), nul())),
  ],
};

// --- cg ---

const CG_DOCS = [
  ["cg/a/items/x", { n: int(1) }],
  ["cg/b/items/y", { n: int(2) }],
  ["items/z", { n: int(3) }],
  ["cg/a/items/x/items/w", { n: int(4) }],
  ["cg/a/other/o", { n: int(5) }],
  ["oth/p/items/q", { n: int(6) }],
];
const fromAncestor = (id, ancestor) =>
  readFrom(id, stage("collection_group", ancestor, str("items")));

const cg = {
  id: "main",
  seed: CG_DOCS,
  steps: [
    fromAncestor("anc-root-empty", { referenceValue: "" }),
    fromAncestor("anc-root-slash", { referenceValue: "/" }),
    fromAncestor("anc-collection-path", { referenceValue: "/cg" }),
    fromAncestor("anc-collection-path-nested", { referenceValue: "/cg/a/items" }),
    fromAncestor("anc-unrelated-doc", { referenceValue: "/zz/q" }),
    fromAncestor("anc-missing-doc-under", { referenceValue: "/cg/zzz" }),
    fromAncestor("anc-deep-doc", { referenceValue: "/cg/a/items/x" }),
    fromAncestor("anc-trailing-slash", { referenceValue: "/cg/a/" }),
    fromAncestor("anc-no-leading-slash", { referenceValue: "cg/a" }),
    fromAncestor("anc-full-name", { referenceValue: "{docs}/cg/a" }),
    fromAncestor("anc-full-name-root", { referenceValue: "{docs}" }),
    fromAncestor("anc-string", str("cg/a")),
    fromAncestor("anc-null", nul()),
    fromAncestor("anc-int", int(1)),
  ],
};

// --- order ---

/** Fifty ids "k01" to "k50". */
export const KEYS_50 = Array.from({ length: 50 }, (_, i) => `k${String(i + 1).padStart(2, "0")}`);

/**
 * Fifty ids that look unrelated to each other: eight characters from a fixed linear congruential
 * generator (so the corpus, and its digest, never change).
 */
export const HASHED_50 = (() => {
  let state = 20261026;
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  const ids = new Set();
  while (ids.size < 50) {
    let id = "";
    for (let i = 0; i < 8; i++) {
      state = (state * 1103515245 + 12345) % 2147483648;
      id += alphabet[Math.floor(state / 65536) % alphabet.length];
    }
    ids.add(id);
  }
  return [...ids];
})();

const numbered50 = (coll, ids) => ids.map((id, i) => [`${coll}/${id}`, { n: int(i + 1) }]);

const orderMain = {
  id: "main",
  seed: [
    ...numbered50("so1", KEYS_50),
    ...numbered50("so2", KEYS_50.toReversed()),
    ...numbered50("so3", HASHED_50),
    ...numbered50("so4", KEYS_50),
  ],
  steps: [
    read("so1-bare", "so1"),
    read("so1-bare-again", "so1"),
    read("so2-bare", "so2"),
    read("so2-bare-again", "so2"),
    read("so3-bare", "so3"),
    read("so3-bare-again", "so3"),
    read("so4-bare", "so4"),
    read("so4-bare-again", "so4"),
    read("so3-sort-name", "so3", sort(asc(fld("__name__")))),
    read("so3-sort-name-desc", "so3", sort(desc(fld("__name__")))),
    read("so3-limit5", "so3", limit(5)),
    read("so3-offset45", "so3", offset(45)),
  ],
};

export const O9_AREAS = {
  reps: define("reps", [reps]),
  fields: define("fields", [fields]),
  types: define("types", [types]),
  ops: define("ops", [ops]),
  cg: define("cg", [cg]),
  order: define("order", [orderMain]),
};

export const O9_PROGRAMS = Object.values(O9_AREAS).flat();
