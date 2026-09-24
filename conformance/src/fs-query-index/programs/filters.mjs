// Filter programs: field filters across value classes, unary filters, composite filters, filter
// validation and the query-plan limits (each limit as an accepted/refused pair one unit apart).

import { NUMBERS_SEED, VALUES_SEED } from "../datasets.mjs";
import {
  and,
  arr,
  asc,
  bool,
  bytes,
  dbl,
  f,
  field,
  from,
  geo,
  inf,
  int,
  map,
  nan,
  nul,
  or,
  query,
  ref,
  str,
  ts,
  u,
  vec,
} from "../values.mjs";

/** A query on `qv` that returns only the document names and `n`. */
const onValues = (id, where, extra = {}) =>
  query(id, { from: from("qv"), where, select: { fields: [field("n")] }, ...extra });
const onNumbers = (id, where, extra = {}) =>
  query(id, { from: from("qn"), where, select: { fields: [field("n")] }, ...extra });

const equality = [
  ["eq-false", bool(false)],
  ["eq-true", bool(true)],
  ["eq-int-one", int(1)],
  ["eq-double-one", dbl(1)],
  ["eq-double-zero", dbl(0)],
  ["eq-negative-zero", dbl("-0")],
  ["eq-int-beyond-double", int("9007199254740993")],
  ["eq-double-two-53", dbl(9007199254740992)],
  ["eq-min-int", int("-9223372036854775808")],
  ["eq-infinity", inf(1)],
  ["eq-timestamp", ts("2020-01-01T00:00:00Z")],
  ["eq-timestamp-micro", ts("2020-01-01T00:00:00.000001Z")],
  ["eq-string", str("a")],
  ["eq-string-empty", str("")],
  ["eq-string-upper", str("B")],
  ["eq-string-unicode", str("é")],
  ["eq-bytes", bytes("AQ==")],
  ["eq-bytes-empty", bytes("")],
  ["eq-reference", ref("qv/str-a")],
  ["eq-geo", geo(1, -1)],
  ["eq-array", arr(int(1))],
  ["eq-array-empty", arr()],
  ["eq-map", map({ a: int(1) })],
  ["eq-map-empty", map({})],
  ["eq-vector", vec(1, 2)],
  ["eq-null", nul()],
  ["eq-nan", nan()],
];

const ranges = [
  ["gt-int-zero", "GREATER_THAN", int(0)],
  ["gte-double-negative-infinity", "GREATER_THAN_OR_EQUAL", inf(-1)],
  ["lt-int-one", "LESS_THAN", int(1)],
  ["lte-double-half", "LESS_THAN_OR_EQUAL", dbl(0.5)],
  ["gt-false", "GREATER_THAN", bool(false)],
  ["gt-timestamp", "GREATER_THAN", ts("2019-12-31T23:59:59Z")],
  ["gte-string-a", "GREATER_THAN_OR_EQUAL", str("a")],
  ["lt-string-b", "LESS_THAN", str("b")],
  ["gt-bytes", "GREATER_THAN", bytes("AQ==")],
  ["gt-reference", "GREATER_THAN", ref("qv/str-a")],
  ["gt-geo", "GREATER_THAN", geo(0, 0)],
  ["gt-array", "GREATER_THAN", arr(int(1))],
  ["lt-map", "LESS_THAN", map({ a: int(2) })],
  ["gte-vector", "GREATER_THAN_OR_EQUAL", vec(1, 2)],
  ["gt-null", "GREATER_THAN", nul()],
  ["lt-nan", "LESS_THAN", nan()],
  ["gt-nan", "GREATER_THAN", nan()],
];

export const FILTER_PROGRAMS = [
  {
    id: "fs-query-index/field-filters/equality",
    seed: VALUES_SEED,
    steps: [
      query("eq-full-documents", { from: from("qv"), where: f("v", "EQUAL", str("a")) }),
      ...equality.map(([id, value]) => onValues(id, f("v", "EQUAL", value))),
      onValues("not-equal-int-one", f("v", "NOT_EQUAL", int(1))),
      onValues("not-equal-string", f("v", "NOT_EQUAL", str("a"))),
      onValues("not-equal-null", f("v", "NOT_EQUAL", nul())),
      onValues("not-equal-nan", f("v", "NOT_EQUAL", nan())),
    ],
  },
  {
    id: "fs-query-index/field-filters/range",
    seed: VALUES_SEED,
    steps: ranges.map(([id, op, value]) => onValues(id, f("v", op, value))),
  },
  {
    id: "fs-query-index/field-filters/array-and-membership",
    seed: VALUES_SEED,
    steps: [
      onValues("array-contains-int", f("v", "ARRAY_CONTAINS", int(1))),
      onValues("array-contains-double-for-int", f("v", "ARRAY_CONTAINS", dbl(1))),
      onValues("array-contains-null", f("v", "ARRAY_CONTAINS", nul())),
      onValues("array-contains-nan", f("v", "ARRAY_CONTAINS", nan())),
      onValues("array-contains-map", f("v", "ARRAY_CONTAINS", map({ a: int(1) }))),
      onValues("array-contains-array-operand", f("v", "ARRAY_CONTAINS", arr(int(1)))),
      onValues("array-contains-tag", f("tags", "ARRAY_CONTAINS", str("odd"))),
      onValues("array-contains-any-tags", f("tags", "ARRAY_CONTAINS_ANY", arr(str("odd"), int(2)))),
      onValues("array-contains-any-null", f("v", "ARRAY_CONTAINS_ANY", arr(nul(), int(2)))),
      onValues("array-contains-any-nan", f("v", "ARRAY_CONTAINS_ANY", arr(nan()))),
      onValues("in-mixed-types", f("v", "IN", arr(int(1), str("a"), bool(true)))),
      onValues("in-double-for-int", f("v", "IN", arr(dbl(1)))),
      onValues("in-null", f("v", "IN", arr(nul()))),
      onValues("in-nan", f("v", "IN", arr(nan()))),
      onValues("in-array-candidate", f("v", "IN", arr(arr(int(1)), arr()))),
      onValues("in-duplicate-values", f("v", "IN", arr(int(1), int(1), dbl(1)))),
      onValues("not-in-mixed-types", f("v", "NOT_IN", arr(int(1), str("a")))),
      onValues("not-in-null", f("v", "NOT_IN", arr(nul()))),
      onValues("not-in-nan", f("v", "NOT_IN", arr(nan()))),
      onValues("not-in-null-and-value", f("v", "NOT_IN", arr(nul(), int(1)))),
    ],
  },
  {
    id: "fs-query-index/field-filters/paths-and-names",
    seed: VALUES_SEED,
    steps: [
      onValues("nested-map-field", f("m.k", "EQUAL", int(1))),
      onValues("nested-map-deep", f("m.deep.x", "EQUAL", str("x"))),
      onValues("quoted-dotted-field", f("`a.b`", "EQUAL", int(1))),
      onValues("quoted-space-field", f("`x y`", "EQUAL", str("s0"))),
      onValues("unquoted-dotted-is-nested", f("a.b", "EQUAL", int(1))),
      onValues("missing-field", f("absent", "EQUAL", int(1))),
      onValues("name-equal", f("__name__", "EQUAL", ref("qv/str-a"))),
      onValues("name-greater-than", f("__name__", "GREATER_THAN", ref("qv/s"))),
      onValues(
        "name-in",
        f("__name__", "IN", arr(ref("qv/str-a"), ref("qv/one"), ref("qv/absent"))),
      ),
      onValues("name-not-in", f("__name__", "NOT_IN", arr(ref("qv/str-a")))),
      onValues("name-not-equal", f("__name__", "NOT_EQUAL", ref("qv/str-a"))),
      onValues("name-other-collection", f("__name__", "GREATER_THAN", ref("qn/d0"))),
      onValues("name-subcollection-document", f("__name__", "EQUAL", ref("qv/str-a/sub/x"))),
      onValues("name-quoted", f("`__name__`", "EQUAL", ref("qv/str-a"))),
    ],
  },
  {
    id: "fs-query-index/unary-filters/all",
    seed: VALUES_SEED,
    steps: [
      onValues("is-null", u("v", "IS_NULL")),
      onValues("is-not-null", u("v", "IS_NOT_NULL")),
      onValues("is-nan", u("v", "IS_NAN")),
      onValues("is-not-nan", u("v", "IS_NOT_NAN")),
      onValues("is-null-missing-field", u("absent", "IS_NULL")),
      onValues("is-not-null-missing-field", u("absent", "IS_NOT_NULL")),
      onValues("is-nan-nested", u("m.r", "IS_NAN")),
      onValues("is-not-nan-nested", u("m.r", "IS_NOT_NAN")),
      onValues("is-null-name", u("__name__", "IS_NULL")),
      onValues("is-not-null-name", u("__name__", "IS_NOT_NULL")),
      onValues("is-not-null-ordered", u("v", "IS_NOT_NULL"), { orderBy: [asc("v")] }),
      onValues("is-not-nan-ordered", u("v", "IS_NOT_NAN"), { orderBy: [asc("v")] }),
    ],
  },
  {
    id: "fs-query-index/composite-filters/all",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("and-two-equalities", and(f("g", "EQUAL", str("odd")), f("h", "EQUAL", int(1)))),
      onNumbers(
        "and-equality-and-range",
        and(f("g", "EQUAL", str("odd")), f("n", "GREATER_THAN", int(3))),
      ),
      onNumbers(
        "and-two-ranges-same-field",
        and(f("n", "GREATER_THAN", int(2)), f("n", "LESS_THAN", int(6))),
      ),
      onNumbers("and-contradiction", and(f("n", "EQUAL", int(1)), f("n", "EQUAL", int(2)))),
      onNumbers("and-duplicate-filter", and(f("n", "EQUAL", int(1)), f("n", "EQUAL", int(1)))),
      onNumbers("and-single-child", and(f("n", "EQUAL", int(1)))),
      onNumbers("and-with-unary", and(u("opt", "IS_NOT_NULL"), f("g", "EQUAL", str("even")))),
      onNumbers("or-two-fields", or(f("g", "EQUAL", str("odd")), f("h", "EQUAL", int(0)))),
      onNumbers("or-overlapping", or(f("n", "LESS_THAN", int(5)), f("n", "GREATER_THAN", int(2)))),
      onNumbers("or-single-child", or(f("n", "EQUAL", int(1)))),
      onNumbers("or-with-in", or(f("n", "IN", arr(int(1), int(2))), f("h", "EQUAL", int(0)))),
      onNumbers(
        "or-ranges-different-fields",
        or(f("n", "GREATER_THAN", int(7)), f("h", "LESS_THAN", int(1))),
      ),
      onNumbers("or-with-not-equal", or(f("n", "NOT_EQUAL", int(1)), f("h", "EQUAL", int(0)))),
      onNumbers(
        "or-with-array-contains",
        or(f("n", "EQUAL", int(1)), f("tags", "ARRAY_CONTAINS", int(2))),
      ),
      onNumbers(
        "and-of-or",
        and(
          or(f("g", "EQUAL", str("odd")), f("h", "EQUAL", int(0))),
          f("n", "GREATER_THAN", int(2)),
        ),
      ),
      onNumbers(
        "or-of-and",
        or(
          and(f("g", "EQUAL", str("odd")), f("h", "EQUAL", int(1))),
          and(f("g", "EQUAL", str("even")), f("h", "EQUAL", int(2))),
        ),
      ),
      onNumbers(
        "nested-three-levels",
        or(
          and(f("g", "EQUAL", str("odd")), or(f("h", "EQUAL", int(0)), f("h", "EQUAL", int(1)))),
          f("n", "EQUAL", int(0)),
        ),
      ),
      onNumbers("or-ordered", or(f("g", "EQUAL", str("odd")), f("h", "EQUAL", int(0))), {
        orderBy: [asc("n")],
      }),
      onNumbers("or-limited", or(f("g", "EQUAL", str("odd")), f("h", "EQUAL", int(0))), {
        limit: 2,
      }),
    ],
  },
  {
    id: "fs-query-index/filter-validation/operators-and-values",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("operator-unspecified", f("n", "OPERATOR_UNSPECIFIED", int(1))),
      onNumbers("operator-unknown", f("n", "SIMILAR_TO", int(1))),
      onNumbers("operator-unknown-number", f("n", 99, int(1))),
      onNumbers("unary-operator-unspecified", u("n", "OPERATOR_UNSPECIFIED")),
      onNumbers("field-filter-without-value", { fieldFilter: { field: field("n"), op: "EQUAL" } }),
      onNumbers("field-filter-without-field", { fieldFilter: { op: "EQUAL", value: int(1) } }),
      onNumbers("unary-filter-without-field", { unaryFilter: { op: "IS_NULL" } }),
      onNumbers("filter-without-kind", {}),
      onNumbers("value-unknown-kind", f("n", "EQUAL", { futureValue: 1 })),
      onNumbers("value-two-kinds", f("n", "EQUAL", { integerValue: "1", stringValue: "a" })),
      onNumbers("integer-out-of-range", f("n", "EQUAL", { integerValue: "9223372036854775808" })),
      onNumbers("timestamp-out-of-range", f("t", "EQUAL", ts("10000-01-01T00:00:00Z"))),
      onNumbers("in-non-array", f("n", "IN", int(1))),
      onNumbers("in-empty-array", f("n", "IN", arr())),
      onNumbers("not-in-non-array", f("n", "NOT_IN", int(1))),
      onNumbers("not-in-empty-array", f("n", "NOT_IN", arr())),
      onNumbers("array-contains-any-non-array", f("n", "ARRAY_CONTAINS_ANY", int(1))),
      onNumbers("array-contains-any-empty-array", f("n", "ARRAY_CONTAINS_ANY", arr())),
      onNumbers("composite-empty", and()),
      onNumbers("composite-operator-unspecified", {
        compositeFilter: { op: "OPERATOR_UNSPECIFIED", filters: [f("n", "EQUAL", int(1))] },
      }),
      onNumbers("composite-without-operator", {
        compositeFilter: { filters: [f("n", "EQUAL", int(1))] },
      }),
      onNumbers("or-empty", or()),
    ],
  },
  {
    id: "fs-query-index/filter-validation/combinations",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("two-not-in", and(f("n", "NOT_IN", arr(int(1))), f("h", "NOT_IN", arr(int(1))))),
      onNumbers(
        "not-in-and-not-equal",
        and(f("n", "NOT_IN", arr(int(1))), f("h", "NOT_EQUAL", int(1))),
      ),
      onNumbers("not-in-and-in", and(f("n", "NOT_IN", arr(int(1))), f("h", "IN", arr(int(1))))),
      onNumbers(
        "not-in-and-array-contains-any",
        and(f("n", "NOT_IN", arr(int(1))), f("h", "ARRAY_CONTAINS_ANY", arr(int(1)))),
      ),
      onNumbers("not-in-inside-or", or(f("n", "NOT_IN", arr(int(1))), f("h", "EQUAL", int(1)))),
      onNumbers(
        "two-not-equal-different-fields",
        and(f("n", "NOT_EQUAL", int(1)), f("h", "NOT_EQUAL", int(1))),
      ),
      onNumbers(
        "two-not-equal-same-field",
        and(f("n", "NOT_EQUAL", int(1)), f("n", "NOT_EQUAL", int(2))),
      ),
      onNumbers(
        "not-equal-and-is-not-null",
        and(f("n", "NOT_EQUAL", int(1)), u("h", "IS_NOT_NULL")),
      ),
      onNumbers("is-not-null-and-is-not-nan", and(u("n", "IS_NOT_NULL"), u("h", "IS_NOT_NAN"))),
      onNumbers("two-is-not-null", and(u("n", "IS_NOT_NULL"), u("h", "IS_NOT_NULL"))),
      onNumbers(
        "not-equal-and-range-same-field",
        and(f("n", "NOT_EQUAL", int(1)), f("n", "GREATER_THAN", int(0))),
      ),
      onNumbers(
        "two-array-contains",
        and(f("tags", "ARRAY_CONTAINS", int(1)), f("tags", "ARRAY_CONTAINS", int(2))),
      ),
      onNumbers(
        "array-contains-and-any",
        and(f("tags", "ARRAY_CONTAINS", int(1)), f("h", "ARRAY_CONTAINS_ANY", arr(int(2)))),
      ),
      onNumbers(
        "two-array-contains-any",
        and(
          f("tags", "ARRAY_CONTAINS_ANY", arr(int(1))),
          f("h", "ARRAY_CONTAINS_ANY", arr(int(2))),
        ),
      ),
      onNumbers(
        "array-contains-per-disjunct",
        or(f("tags", "ARRAY_CONTAINS", int(1)), f("h", "ARRAY_CONTAINS", int(2))),
      ),
      onNumbers(
        "array-contains-any-and-in",
        and(f("tags", "ARRAY_CONTAINS_ANY", arr(int(1))), f("h", "IN", arr(int(2)))),
      ),
      onNumbers(
        "in-and-in",
        and(f("n", "IN", arr(int(1), int(2))), f("h", "IN", arr(int(1), int(2)))),
      ),
      onNumbers(
        "in-and-equal-same-field",
        and(f("n", "IN", arr(int(1), int(2))), f("n", "EQUAL", int(1))),
      ),
    ],
  },
  {
    id: "fs-query-index/filter-validation/paths-and-names",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("field-path-empty", f("", "EQUAL", int(1))),
      onNumbers("field-path-double-dot", f("a..b", "EQUAL", int(1))),
      onNumbers("field-path-trailing-dot", f("a.", "EQUAL", int(1))),
      onNumbers("field-path-unterminated-quote", f("`a", "EQUAL", int(1))),
      onNumbers("field-path-reserved", f("__x__", "EQUAL", int(1))),
      onNumbers("field-path-nested-reserved", f("a.__x__", "EQUAL", int(1))),
      onNumbers("field-path-bracket", f("a[0]", "EQUAL", int(1))),
      onNumbers("field-path-quoted-empty", f("``", "EQUAL", int(1))),
      onNumbers("field-path-hyphen", f("a-b", "EQUAL", int(1))),
      onNumbers("field-path-leading-digit", f("1a", "EQUAL", int(1))),
      onNumbers("field-path-space", f("a b", "EQUAL", int(1))),
      onNumbers("field-path-tilde", f("a~b", "EQUAL", int(1))),
      onNumbers("field-path-star", f("a*b", "EQUAL", int(1))),
      onNumbers("field-path-slash", f("a/b", "EQUAL", int(1))),
      onNumbers("field-path-quoted-escaped-backtick", f("`a\\`b`", "EQUAL", int(1))),
      onNumbers("field-path-quoted-literal-backslash", f("`a\\\\b`", "EQUAL", int(1))),
      onNumbers("name-with-string", f("__name__", "EQUAL", str("qn/d1"))),
      onNumbers("name-range-with-string", f("__name__", "GREATER_THAN", str("d1"))),
      onNumbers("name-in-with-string", f("__name__", "IN", arr(str("d1")))),
      onNumbers("name-in-with-mixed", f("__name__", "IN", arr(ref("qn/d1"), int(1)))),
      onNumbers("name-array-contains", f("__name__", "ARRAY_CONTAINS", ref("qn/d1"))),
      onNumbers("name-collection-reference", f("__name__", "EQUAL", ref("qn"))),
      onNumbers(
        "name-other-database",
        f("__name__", "EQUAL", {
          referenceValue: "projects/{project}/databases/other-db/documents/qn/d1",
        }),
      ),
      onNumbers("name-null", f("__name__", "EQUAL", nul())),
      onNumbers(
        "name-equal-with-other-inequality",
        and(f("__name__", "EQUAL", ref("qn/d1")), f("n", "GREATER_THAN", int(0))),
      ),
      onNumbers(
        "name-equal-with-name-inequality",
        and(f("__name__", "EQUAL", ref("qn/d1")), f("__name__", "GREATER_THAN", ref("qn/d0"))),
      ),
      onNumbers(
        "name-in-with-other-inequality",
        and(f("__name__", "IN", arr(ref("qn/d1"))), f("n", "GREATER_THAN", int(0))),
      ),
    ],
  },
];

/** `count` equality values on distinct fields `f0`… as one OR, for the DNF bound. */
const orOfEqualities = (count) =>
  or(...Array.from({ length: count }, (_, i) => f(`f${i}`, "EQUAL", int(i))));
const andOfEqualities = (count) =>
  and(...Array.from({ length: count }, (_, i) => f(`e${i}`, "EQUAL", int(i))));
const values = (count, make = int) => arr(...Array.from({ length: count }, (_, i) => make(i)));
const inequalities = (count) =>
  and(...Array.from({ length: count }, (_, i) => f(`f${i}`, "GREATER_THAN", int(0))));
const references = (count) => arr(...Array.from({ length: count }, (_, i) => ref(`ql/d${i}`)));

const onLimits = (id, where, { parent, ...extra } = {}) =>
  query(id, { from: from("ql"), where, ...extra }, parent ? { parent } : {});
/** An OR of `disjuncts` equality conjunctions of `width` filters; `wider` makes one wider by 1. */
const orOfConjunctions = (disjuncts, width, wider = false) =>
  or(
    ...Array.from({ length: disjuncts }, (_disjunct, d) =>
      and(
        ...Array.from({ length: width + (wider && d === 0 ? 1 : 0) }, (_, i) =>
          f(`c${i}`, "EQUAL", int(d)),
        ),
      ),
    ),
  );

export const LIMIT_PROGRAMS = [
  {
    id: "fs-query-index/query-limits/disjunctions",
    seed: [
      ["ql/d0", { n: int(0), f0: int(0), tags: arr(int(0)) }],
      ["ql/d29", { n: int(29), f29: int(29), tags: arr(int(29)) }],
    ],
    steps: [
      onLimits("in-30", f("n", "IN", values(30))),
      onLimits("in-31", f("n", "IN", values(31))),
      onLimits("array-contains-any-30", f("tags", "ARRAY_CONTAINS_ANY", values(30))),
      onLimits("array-contains-any-31", f("tags", "ARRAY_CONTAINS_ANY", values(31))),
      onLimits("name-in-30", f("__name__", "IN", references(30))),
      onLimits("name-in-31", f("__name__", "IN", references(31))),
      onLimits("or-30", orOfEqualities(30)),
      onLimits("or-31", orOfEqualities(31)),
      onLimits("in-29-or-one", or(f("n", "IN", values(29)), f("f0", "EQUAL", int(0)))),
      onLimits("in-30-or-one", or(f("n", "IN", values(30)), f("f0", "EQUAL", int(0)))),
      onLimits("in-15-and-in-2", and(f("n", "IN", values(15)), f("f0", "IN", values(2)))),
      onLimits("in-16-and-in-2", and(f("n", "IN", values(16)), f("f0", "IN", values(2)))),
      onLimits(
        "in-10-and-any-3",
        and(f("n", "IN", values(10)), f("tags", "ARRAY_CONTAINS_ANY", values(3))),
      ),
      onLimits(
        "in-11-and-any-3",
        and(f("n", "IN", values(11)), f("tags", "ARRAY_CONTAINS_ANY", values(3))),
      ),
    ],
  },
  {
    id: "fs-query-index/query-limits/not-in-and-inequalities",
    seed: [["ql/d0", { n: int(0) }]],
    steps: [
      onLimits("not-in-10", f("n", "NOT_IN", values(10))),
      onLimits("not-in-11", f("n", "NOT_IN", values(11))),
      onLimits("name-not-in-10", f("__name__", "NOT_IN", references(10))),
      onLimits("name-not-in-11", f("__name__", "NOT_IN", references(11))),
      onLimits("inequality-fields-10", inequalities(10)),
      onLimits(
        "inequality-fields-11-letters",
        and(..."abcdefghijk".split("").map((name) => f(name, "GREATER_THAN", int(0)))),
      ),
      onLimits(
        "inequality-fields-12-reversed",
        and(...Array.from({ length: 12 }, (_, i) => f(`g${11 - i}`, "LESS_THAN", int(0)))),
      ),
      onLimits("inequality-fields-11", inequalities(11)),
      onLimits(
        "inequality-fields-9-and-not-equal",
        and(inequalities(9), f("f9", "NOT_EQUAL", int(0))),
      ),
      onLimits(
        "inequality-fields-10-and-not-equal",
        and(inequalities(10), f("f10", "NOT_EQUAL", int(0))),
      ),
    ],
  },
  {
    id: "fs-query-index/query-limits/components",
    seed: [["ql/d0", { n: int(0) }]],
    steps: [
      onLimits("equalities-100", andOfEqualities(100)),
      onLimits("equalities-101", andOfEqualities(101)),
      onLimits("equalities-99-and-order", andOfEqualities(99), { orderBy: [asc("e0")] }),
      onLimits("equalities-100-and-order", andOfEqualities(100), { orderBy: [asc("e0")] }),
      onLimits("subcollection-equalities-99", andOfEqualities(99), { parent: "qlp/p" }),
      onLimits("subcollection-equalities-100", andOfEqualities(100), { parent: "qlp/p" }),
      onLimits("or-components-100", orOfConjunctions(20, 5)),
      onLimits("or-components-101", orOfConjunctions(20, 5, true)),
    ],
  },
];
