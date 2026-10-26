// The FS-ENT-ORACLE O-7 corpus (packet v2): what production does with `aggregate` (with and
// without groups), `distinct`, `add_fields`, `remove_fields`, and the `collection_group` and
// `documents` inputs. Program ids are `fs-ent-pipeline/o7/<area>-<group>`; the areas and the
// helper shapes are those of the O-6 corpus (o6-corpus.mjs), whose programs are untouched.
//
// Every group is one program with a seed in its own collections. A collection that is read
// and never written (an empty input) is named in EMPTY_COLLECTIONS, which no program writes.

import { arr, bool, dbl, inf, int, map, nan, nul, str, ts } from "../fs-query-index/values.mjs";
import {
  addFields,
  aggregate,
  asc,
  collection,
  collectionGroup,
  desc,
  distinct,
  documents,
  eq,
  fld,
  fn,
  gt,
  limit,
  mapOf,
  offset,
  read,
  readFrom,
  readFromGrpc,
  removeFields,
  select,
  sort,
  stage,
  where,
} from "./builders.mjs";
import { defineArea, kindDocs } from "./o6-corpus.mjs";

export const O7_PREFIX = "fs-ent-pipeline/o7/";

/** Collections some step reads and no program writes: empty inputs. */
export const EMPTY_COLLECTIONS = new Set(["ae", "de", "nogroup"]);

const define = (area, groups) => defineArea(area, groups, O7_PREFIX);

// --- accumulators ---

/**
 * The aggregate functions of the SDK, by output alias: `n` is countAll (no argument), the others
 * take one field. Wire names are those of stage.js and expression.js (`count_distinct`, not
 * `countDistinct`).
 */
export const ACCUMULATORS = [
  ["n", "count", false],
  ["c", "count", true],
  ["s", "sum", true],
  ["a", "average", true],
  ["mn", "minimum", true],
  ["mx", "maximum", true],
  ["d", "count_distinct", true],
];

/** The seven accumulators over one field, as an accumulators map. */
export const accumulatorMap = (field) =>
  Object.fromEntries(
    ACCUMULATORS.map(([alias, name, takesField]) => [
      alias,
      fn(name, ...(takesField ? [fld(field)] : [])),
    ]),
  );

const pad = (i) => String(i + 1).padStart(2, "0");

/**
 * A program of number scenarios: each scenario is a collection of documents holding one value
 * (or none) in `v`, aggregated with all seven accumulators in one step. A scenario marked `split`
 * also runs `sum` and `average` alone, because those are the two that can refuse a value and
 * would hide the other five.
 */
export function numberScenarios(id, scenarios) {
  const seed = [];
  const steps = [];
  for (const { collection: name, values, split } of scenarios) {
    values.forEach((value, i) => {
      seed.push([`${name}/d${pad(i)}`, value === undefined ? {} : { v: value }]);
    });
    steps.push(read(`${name}-all`, name, aggregate(accumulatorMap("v"))));
    if (split) {
      for (const [alias, label] of [
        ["s", "sum"],
        ["a", "average"],
      ]) {
        steps.push(
          read(`${name}-${label}`, name, aggregate({ [alias]: accumulatorMap("v")[alias] })),
        );
      }
    }
  }
  return { id, seed, steps };
}

const n = fld("n");
const g = fld("g");
const count = (field) => fn("count", fld(field));
const countAll = () => fn("count");
const sum = (field) => fn("sum", fld(field));

// --- aggregate ---

const empty = {
  id: "empty",
  seed: [],
  steps: [
    read("count-all", "ae", aggregate({ n: countAll() })),
    read("count", "ae", aggregate({ c: count("x") })),
    read("sum", "ae", aggregate({ s: sum("x") })),
    read("average", "ae", aggregate({ a: fn("average", fld("x")) })),
    read("minimum", "ae", aggregate({ mn: fn("minimum", fld("x")) })),
    read("maximum", "ae", aggregate({ mx: fn("maximum", fld("x")) })),
    read("count-distinct", "ae", aggregate({ d: fn("count_distinct", fld("x")) })),
    read("all", "ae", aggregate(accumulatorMap("x"))),
    read("grouped-count", "ae", aggregate({ n: countAll() }, { g: fld("x") })),
    read("grouped-all", "ae", aggregate(accumulatorMap("x"), { g: fld("x") })),
  ],
};

const basic = {
  id: "basic",
  seed: [
    ["ab/a1", { n: int(1), d: dbl(0.5), g: str("a") }],
    ["ab/a2", { n: int(2), d: dbl(1.5), g: str("b") }],
    ["ab/a3", { n: int(3), d: dbl(2.5), g: str("a") }],
    ["ab/a4", { n: int(4), d: dbl(3.5), g: str("b") }],
    ["ab/a5", { n: int(5), d: dbl(4.5), g: str("a") }],
    ["ab/a6", { n: int(6), d: dbl(5.5), g: str("c") }],
  ],
  steps: [
    read("all", "ab", aggregate(accumulatorMap("n"))),
    read("count-all-only", "ab", aggregate({ n: countAll() })),
    read("sum-only", "ab", aggregate({ s: sum("n") })),
    read("average-only", "ab", aggregate({ a: fn("average", n) })),
    read("grouped-all", "ab", aggregate(accumulatorMap("n"), { g })),
    read("grouped-count-all", "ab", aggregate({ n: countAll() }, { g })),
    read("grouped-sum", "ab", aggregate({ s: sum("n") }, { g })),
    read("doubles-all", "ab", aggregate(accumulatorMap("d"))),
    read("doubles-grouped", "ab", aggregate(accumulatorMap("d"), { g })),
    read("two-sums", "ab", aggregate({ s1: sum("n"), s2: sum("d") })),
    read("where-then-aggregate", "ab", where(gt(n, int(2))), aggregate({ n: countAll() })),
    read(
      "aggregate-then-where",
      "ab",
      aggregate({ c: countAll() }, { g }),
      where(gt(fld("c"), int(1))),
    ),
    read("aggregate-then-sort", "ab", aggregate({ c: countAll() }, { g }), sort(asc(g))),
    read("aggregate-then-sort-desc", "ab", aggregate({ c: countAll() }, { g }), sort(desc(g))),
    read("aggregate-then-limit", "ab", aggregate({ c: countAll() }, { g }), limit(2)),
    read("aggregate-then-offset", "ab", aggregate({ c: countAll() }, { g }), offset(1)),
    read(
      "aggregate-then-select",
      "ab",
      aggregate({ c: countAll() }, { g }),
      select({ c: fld("c") }),
    ),
    read("limit-then-aggregate", "ab", limit(3), aggregate({ n: countAll() })),
    read("sort-then-aggregate", "ab", sort(desc(n)), aggregate({ n: countAll() })),
    read(
      "aggregate-then-aggregate",
      "ab",
      aggregate({ c: countAll() }, { g }),
      aggregate({ n: countAll() }),
    ),
  ],
};

const NUMBER_SCENARIOS = [
  { collection: "nint", values: [int(1), int(2), int(3)] },
  { collection: "nmixed", values: [int(1), dbl(2.5), int(3)] },
  { collection: "nzero", values: [dbl("-0"), dbl(0)] },
  { collection: "nsame", values: [int(1), dbl(1), int(1)] },
  { collection: "nprec", values: [int("9007199254740993"), dbl(9007199254740992)] },
  { collection: "nfrac", values: [dbl(0.1), dbl(0.2)] },
  { collection: "nnan", values: [int(1), nan(), int(2)] },
  { collection: "ninf", values: [int(1), inf(1), inf(-1)] },
  { collection: "nmax", values: [int("9223372036854775807"), int(1)], split: true },
  {
    collection: "nhalf",
    values: [int("4611686018427387904"), int("4611686018427387904")],
    split: true,
  },
  { collection: "nnear", values: [int("9223372036854775806"), int(1)] },
  { collection: "xstr", values: [str("a"), str("b")], split: true },
  { collection: "xnull", values: [nul(), nul()], split: true },
  { collection: "xmixed", values: [int(1), str("a")], split: true },
  { collection: "xmixnull", values: [int(1), nul(), int(2)], split: true },
  { collection: "xmissing", values: [int(1), undefined, int(2)], split: true },
  { collection: "xbool", values: [bool(true), int(1)], split: true },
  { collection: "xarray", values: [arr(int(1)), arr(int(2))], split: true },
  { collection: "xmap", values: [map({ a: int(1) }), map({ a: int(2) })], split: true },
  {
    collection: "xtime",
    values: [ts("2020-01-01T00:00:00Z"), ts("2021-01-01T00:00:00Z")],
    split: true,
  },
];
const numbers = numberScenarios("numbers", NUMBER_SCENARIOS);

const KIND_ACCUMULATORS = [
  ["all", accumulatorMap("v")],
  ["count", { c: count("v") }],
  ["sum", { s: sum("v") }],
  ["average", { a: fn("average", fld("v")) }],
  ["minimum", { mn: fn("minimum", fld("v")) }],
  ["maximum", { mx: fn("maximum", fld("v")) }],
  ["count-distinct", { d: fn("count_distinct", fld("v")) }],
];
const kinds = {
  id: "kinds",
  seed: kindDocs("ak"),
  steps: [
    ...KIND_ACCUMULATORS.map(([label, accumulators]) => read(label, "ak", aggregate(accumulators))),
    read("count-all", "ak", aggregate({ n: countAll() })),
    read("group-by-v", "ak", aggregate({ n: countAll() }, { k: fld("v") })),
    read("group-by-v-over-w", "ak", aggregate(accumulatorMap("w"), { k: fld("v") })),
  ],
};

const GROUP_DOCS = [
  { g: str("x"), h: int(1), n: int(1) },
  { g: str("x"), h: int(2), n: int(2) },
  { g: str("y"), h: int(1), n: int(3) },
  { g: nul(), h: int(1), n: int(4) },
  { h: int(1), n: int(5) },
  { g: int(1), n: int(6) },
  { g: dbl(1), n: int(7) },
  { g: nan(), n: int(8) },
  { g: nan(), n: int(9) },
  { g: dbl("-0"), n: int(10) },
  { g: dbl(0), n: int(11) },
  { g: arr(int(1)), n: int(12) },
  { g: arr(int(1)), n: int(13) },
  { g: map({ a: int(1) }), n: int(14) },
  { g: map({ a: int(1) }), n: int(15) },
  { g: bool(true), n: int(16) },
  { m: map({ k: int(1) }), n: int(17) },
  { m: map({ k: int(1) }), n: int(18) },
];
const groupDocs = (from) => GROUP_DOCS.map((fields, i) => [`${from}/g${pad(i)}`, fields]);
const CS = { c: countAll(), s: sum("n") };
const groupKeys = {
  id: "group-keys",
  seed: groupDocs("ag"),
  steps: [
    read("by-g", "ag", aggregate(CS, { g })),
    read("by-g-count-only", "ag", aggregate({ c: countAll() }, { g })),
    read("by-g-h", "ag", aggregate(CS, { g, h: fld("h") })),
    read("by-h-g", "ag", aggregate(CS, { h: fld("h"), g })),
    read("by-g-h-n", "ag", aggregate({ c: countAll() }, { g, h: fld("h"), n })),
    read("by-nested", "ag", aggregate(CS, { k: fld("m.k") })),
    read("by-expression", "ag", aggregate(CS, { e: eq(n, int(2)) })),
    read(
      "by-document-id",
      "ag",
      aggregate({ c: countAll() }, { id: fn("document_id", fld("__name__")) }),
    ),
    read("by-name", "ag", aggregate({ c: countAll() }, { name: fld("__name__") })),
    read("by-literal", "ag", aggregate(CS, { k: int(1) })),
    read("by-missing-field", "ag", aggregate(CS, { z: fld("zz") })),
    read("alias-overlap", "ag", aggregate({ g: countAll() }, { g })),
    read("alias-is-field", "ag", aggregate({ c: countAll() }, { n: g })),
  ],
};

const ALIASES = [
  ["dotted", "a.b"],
  ["quoted", "`q.r`"],
  ["hyphen", "total-count"],
  ["leading-digit", "1st"],
  ["non-ascii", "名前"],
  ["reserved", "__x__"],
  ["document-name", "__name__"],
  ["long-1500", "a".repeat(1500)],
];
const aliases = {
  id: "aliases",
  seed: [1, 2, 3].map((v, i) => [`ao/o${i + 1}`, { v: int(v) }]),
  steps: [
    ...ALIASES.map(([label, alias]) =>
      read(`acc-${label}`, "ao", aggregate({ [alias]: countAll() })),
    ),
    read("group-dotted", "ao", aggregate({ c: countAll() }, { "a.b": fld("v") })),
    read("group-reserved", "ao", aggregate({ c: countAll() }, { __x__: fld("v") })),
    read("group-overlap-nested", "ao", aggregate({ "a.b": countAll() }, { a: fld("v") })),
  ],
};

const args = {
  id: "args",
  seed: [1, 2, 3].map((v, i) => [`aa/r${i + 1}`, { n: int(v), s: str("x") }]),
  steps: [
    read("three-args", "aa", stage("aggregate", mapOf({ c: countAll() }), mapOf({}), mapOf({}))),
    read("zero-args", "aa", stage("aggregate")),
    read("accumulators-int", "aa", stage("aggregate", int(1), mapOf({}))),
    read("groups-int", "aa", stage("aggregate", mapOf({ c: countAll() }), int(1))),
    read("accumulator-field", "aa", aggregate({ c: n })),
    read("accumulator-comparison", "aa", aggregate({ c: eq(n, int(1)) })),
    read("accumulator-unknown", "aa", aggregate({ c: fn("nope", n) })),
    read("count-two-args", "aa", aggregate({ c: fn("count", n, n) })),
    read("sum-no-args", "aa", aggregate({ s: fn("sum") })),
    read("sum-two-args", "aa", aggregate({ s: fn("sum", n, n) })),
    read("minimum-no-args", "aa", aggregate({ mn: fn("minimum") })),
    read("count-distinct-no-args", "aa", aggregate({ d: fn("count_distinct") })),
    read("sum-literal", "aa", aggregate({ s: fn("sum", int(1)) })),
    read("sum-string-literal", "aa", aggregate({ s: fn("sum", str("a")) })),
    read("count-null-literal", "aa", aggregate({ c: fn("count", nul()) })),
    read("nested-aggregate", "aa", aggregate({ s: fn("sum", fn("sum", n)) })),
    read("count-of-expression", "aa", aggregate({ c: fn("count", eq(n, int(1))) })),
    read("sum-of-add", "aa", aggregate({ s: fn("sum", fn("add", n, n)) })),
    read("after-select", "aa", select({ a: n }), aggregate({ s: fn("sum", fld("a")) })),
  ],
};

// --- distinct ---

const distinctMain = {
  id: "main",
  seed: [...kindDocs("dk"), ...groupDocs("dg")],
  steps: [
    read("kinds", "dk", distinct({ k: fld("v") })),
    read("by-g", "dg", distinct({ g })),
    read("by-g-h", "dg", distinct({ g, h: fld("h") })),
    read("by-h-g", "dg", distinct({ h: fld("h"), g })),
    read("by-nested", "dg", distinct({ k: fld("m.k") })),
    read("by-expression", "dg", distinct({ e: eq(n, int(2)) })),
    read("by-document-id", "dg", distinct({ id: fn("document_id", fld("__name__")) })),
    read("by-name", "dg", distinct({ name: fld("__name__") })),
    read("by-literal", "dg", distinct({ k: int(1) })),
    read("by-missing-field", "dg", distinct({ z: fld("zz") })),
    read("two-aliases-one-field", "dg", distinct({ a: g, b: g })),
    read("alias-is-field", "dg", distinct({ n: g })),
    read("alias-dotted", "dg", distinct({ "a.b": g })),
    read("alias-reserved", "dg", distinct({ __x__: g })),
    read("empty-input", "de", distinct({ g })),
    read("where-then-distinct", "dg", where(gt(n, int(5))), distinct({ g })),
    read("distinct-then-where", "dg", distinct({ k: g }), where(eq(fld("k"), str("x")))),
    read("distinct-then-sort", "dg", distinct({ k: g }), sort(asc(fld("k")))),
    read("distinct-then-limit", "dg", distinct({ k: g }), limit(2)),
    read("distinct-then-offset", "dg", distinct({ k: g }), offset(2)),
    read("distinct-then-select", "dg", distinct({ k: g, h: fld("h") }), select({ k: fld("k") })),
    read("distinct-then-distinct", "dg", distinct({ k: g }), distinct({ j: fld("k") })),
    read("limit-then-distinct", "dg", limit(4), distinct({ k: g })),
    read("sort-then-distinct", "dg", sort(desc(n)), distinct({ k: g })),
    read("distinct-then-aggregate", "dg", distinct({ k: g }), aggregate({ c: countAll() })),
    read("no-args", "dg", stage("distinct")),
    read("two-maps", "dg", stage("distinct", mapOf({ k: g }), mapOf({ j: g }))),
    read("int-arg", "dg", stage("distinct", int(1))),
    read("field-arg", "dg", stage("distinct", g)),
  ],
};

// --- add_fields and remove_fields ---

const fa = fld("a");
const fieldDocs = {
  id: "main",
  seed: [
    [
      "fa/f1",
      { a: int(1), b: str("x"), m: map({ p: int(1), q: int(2) }), arr: arr(int(1), int(2)) },
    ],
    ["fa/f2", { a: int(2), b: nul(), m: map({}) }],
    ["fa/f3", { a: int(3), m: int(5) }],
    ["fa/f4", { b: str("y") }],
  ],
  steps: [
    read("add-literal", "fa", addFields({ k: int(7) })),
    read("add-copy", "fa", addFields({ k: fa })),
    read("add-expression", "fa", addFields({ k: eq(fa, int(1)) })),
    read(
      "add-array-map",
      "fa",
      addFields({ k: fn("array", fa, fld("b")), j: fn("map", str("z"), fa) }),
    ),
    read("add-overwrite", "fa", addFields({ a: str("new") })),
    read("add-nested", "fa", addFields({ "m.r": int(9) })),
    read("add-nested-new-parent", "fa", addFields({ "nm.r": int(9) })),
    read("add-missing-source", "fa", addFields({ k: fld("zz") })),
    read("add-refers-to-sibling", "fa", addFields({ k1: fa, k2: fld("k1") })),
    read("add-name", "fa", addFields({ __name__: int(1) })),
    read("add-error-value", "fa", addFields({ k: fn("not", fa) })),
    read("add-then-select", "fa", addFields({ k: fa }), select({ k: fld("k"), a: fa })),
    read("add-then-where", "fa", addFields({ k: fa }), where(gt(fld("k"), int(1)))),
    read("add-then-sort", "fa", addFields({ k: fa }), sort(desc(fld("k")))),
    read("add-twice", "fa", addFields({ k: fa }), addFields({ k: fn("array", fld("k")) })),
    read("remove-one", "fa", removeFields("a")),
    read("remove-two", "fa", removeFields("a", "b")),
    read("remove-nested", "fa", removeFields("m.p")),
    read("remove-missing", "fa", removeFields("zz")),
    read("remove-all", "fa", removeFields("a", "b", "m", "arr")),
    read("remove-name", "fa", removeFields("__name__")),
    read("remove-duplicate", "fa", removeFields("a", "a")),
    read("remove-quoted", "fa", removeFields("`a`")),
    read("remove-then-where", "fa", removeFields("a"), where(gt(fa, int(1)))),
    read("remove-then-select", "fa", removeFields("a"), select({ b: fld("b") })),
    read("remove-then-add", "fa", removeFields("a"), addFields({ a: str("again") })),
    read("add-then-remove", "fa", addFields({ k: fa }), removeFields("k")),
    read("remove-no-args", "fa", stage("remove_fields")),
    read("remove-string-arg", "fa", stage("remove_fields", str("a"))),
    read("remove-int-arg", "fa", stage("remove_fields", int(1))),
    read("remove-expression-arg", "fa", stage("remove_fields", fn("array", fa))),
  ],
};

// --- collection_group and documents ---

const cgDocs = [
  ["cg/a/items/x", { n: int(1) }],
  ["cg/b/items/y", { n: int(2) }],
  ["items/z", { n: int(3) }],
  ["cg/a/items/x/items/w", { n: int(4) }],
  ["cg/a/other/o", { n: int(5) }],
  ["oth/p/items/q", { n: int(6) }],
];
const group = {
  id: "collection-group",
  seed: cgDocs,
  steps: [
    readFrom("bare", collectionGroup("items")),
    readFrom("sort-name", collectionGroup("items"), sort(asc(fld("__name__")))),
    readFrom("where", collectionGroup("items"), where(gt(n, int(1)))),
    readFrom("limit", collectionGroup("items"), limit(2)),
    readFrom("other", collectionGroup("other")),
    readFrom("parent-only", collectionGroup("cg")),
    readFrom("missing-group", collectionGroup("nogroup")),
    readFrom("invalid-empty", collectionGroup("")),
    readFrom("invalid-slash", collectionGroup("a/b")),
    readFrom("invalid-reserved", collectionGroup("__items__")),
    readFrom("invalid-no-args", stage("collection_group")),
    readFrom("one-arg", stage("collection_group", str("items"))),
    readFrom("invalid-id-int", stage("collection_group", { referenceValue: "" }, int(1))),
    readFrom("nested-parent", stage("collection_group", { referenceValue: "/cg/a" }, str("items"))),
    readFrom("invalid-after-collection", collection("items"), collectionGroup("items")),
    readFromGrpc("bare-grpc", collectionGroup("items")),
  ],
};

const docs = {
  id: "documents",
  seed: [
    ["dc/d1", { n: int(1) }],
    ["dc/d2", { n: int(2) }],
    ["dc/d3", { n: int(3) }],
    ["dc/d1/sub/s1", { n: int(4) }],
    ["dx/e1", { n: int(5) }],
  ],
  steps: [
    readFrom("one", documents("dc/d1")),
    readFrom("two", documents("dc/d1", "dc/d2")),
    readFrom("argument-order", documents("dc/d3", "dc/d1", "dc/d2")),
    readFrom("missing", documents("dc/nope")),
    readFrom("one-missing-between", documents("dc/d1", "dc/nope", "dc/d2")),
    readFrom("duplicate", documents("dc/d1", "dc/d1")),
    readFrom("two-collections", documents("dc/d1", "dx/e1")),
    readFrom("sort", documents("dc/d1", "dc/d2", "dc/d3"), sort(desc(n))),
    readFrom("invalid-no-args", stage("documents")),
    readFrom("invalid-collection-path", documents("dc")),
    readFrom("invalid-string", stage("documents", str("/dc/d1"))),
    readFrom("invalid-root", stage("documents", { referenceValue: "/" })),
    readFromGrpc("two-grpc", documents("dc/d1", "dc/d2")),
  ],
};

export const O7_AREAS = {
  aggregate: define("aggregate", [empty, basic, numbers, kinds, groupKeys, aliases, args]),
  distinct: define("distinct", [distinctMain]),
  fields: define("fields", [fieldDocs]),
  inputs: define("inputs", [group, docs]),
};

export const O7_PROGRAMS = Object.values(O7_AREAS).flat();
