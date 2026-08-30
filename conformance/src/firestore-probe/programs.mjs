// The Firestore semantics programs (FS-PARITY-02 / FS-PARITY-03 / FS-PARITY-01).
//
// Each program seeds documents and runs REST requests against them; the recorded answers are
// compared between the official Firestore emulator and fireemu by `run.mjs`. The corpus is
// hand-written rather than generated because every row is meant to name one documented
// behaviour -- the type order, a cursor edge, a precondition code, a transform on a missing
// field -- so a disagreement points at a sentence of the documentation, not at a random
// expression.
//
// Paths and bodies write `PROJECT` where the project id goes; the session substitutes it.
// Seeded timestamps are dated before 2025 on purpose: `session.mjs` treats later instants
// as server-generated and replaces them with a placeholder.

const DB = "/v1/projects/PROJECT/databases/(default)";
const DOCS = `${DB}/documents`;
const REF_PREFIX = "projects/PROJECT/databases/(default)/documents";

// ---------------------------------------------------------------------------------------
// Value builders (the REST JSON encoding of google.firestore.v1.Value)
// ---------------------------------------------------------------------------------------

export const nul = () => ({ nullValue: null });
export const bool = (b) => ({ booleanValue: b });
export const int = (n) => ({ integerValue: String(n) });
export const dbl = (d) => ({ doubleValue: d });
export const str = (s) => ({ stringValue: s });
export const ts = (iso) => ({ timestampValue: iso });
export const bytes = (b64) => ({ bytesValue: b64 });
export const ref = (path) => ({ referenceValue: `${REF_PREFIX}/${path}` });
export const geo = (latitude, longitude) => ({ geoPointValue: { latitude, longitude } });
export const arr = (...values) => ({ arrayValue: { values } });
export const map = (fields) => ({ mapValue: { fields } });
export const nan = () => ({ doubleValue: "NaN" });

// ---------------------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------------------

const seedDoc = (path, fields) => ({ path: `${DOCS}/${path}`, fields });

const field = (path, op, value) => ({ fieldFilter: { field: { fieldPath: path }, op, value } });
const unary = (path, op) => ({ unaryFilter: { field: { fieldPath: path }, op } });
const and = (...filters) => ({ compositeFilter: { op: "AND", filters } });
const or = (...filters) => ({ compositeFilter: { op: "OR", filters } });
const asc = (path) => ({ field: { fieldPath: path }, direction: "ASCENDING" });
const desc = (path) => ({ field: { fieldPath: path }, direction: "DESCENDING" });
const cursor = (values, before) => ({ values, before });

/** A `runQuery` step. `parent` is a document path for a subcollection query. */
function runQuery(id, structuredQuery, { parent, extra } = {}) {
  const base = parent ? `${DOCS}/${parent}` : DOCS;
  return {
    id,
    method: "POST",
    path: `${base}:runQuery`,
    body: { structuredQuery, ...extra },
  };
}

function runAggregation(id, structuredQuery, aggregations, { extra } = {}) {
  return {
    id,
    method: "POST",
    path: `${DOCS}:runAggregationQuery`,
    body: { structuredAggregationQuery: { structuredQuery, aggregations }, ...extra },
  };
}

const from = (collectionId, allDescendants = false) => [
  allDescendants ? { collectionId, allDescendants: true } : { collectionId },
];

const commit = (id, writes, extra = {}) => ({
  id,
  method: "POST",
  path: `${DOCS}:commit`,
  body: { writes, ...extra },
});

const update = (path, fields, extra = {}) => ({
  update: { name: `${REF_PREFIX}/${path}`, fields },
  ...extra,
});

const del = (path, extra = {}) => ({ delete: `${REF_PREFIX}/${path}`, ...extra });

const transform = (path, fieldTransforms, extra = {}) => ({
  transform: { document: `${REF_PREFIX}/${path}`, fieldTransforms },
  ...extra,
});

const get = (id, path, query = "") => ({ id, method: "GET", path: `${DOCS}/${path}${query}` });

// ---------------------------------------------------------------------------------------
// Corpora
// ---------------------------------------------------------------------------------------

/** One document per value kind, plus in-kind samples, for the ordering rows. */
const ORDER_SEED = [
  seedDoc("ord/null", { v: nul() }),
  seedDoc("ord/false", { v: bool(false) }),
  seedDoc("ord/true", { v: bool(true) }),
  seedDoc("ord/nan", { v: nan() }),
  seedDoc("ord/int-neg", { v: int(-3) }),
  seedDoc("ord/dbl-neg", { v: dbl(-2.5) }),
  seedDoc("ord/int-zero", { v: int(0) }),
  seedDoc("ord/dbl-zero", { v: dbl(0) }),
  seedDoc("ord/dbl-small", { v: dbl(1.5) }),
  seedDoc("ord/int-two", { v: int(2) }),
  seedDoc("ord/int-big", { v: int("9007199254740993") }),
  seedDoc("ord/dbl-inf", { v: dbl("Infinity") }),
  seedDoc("ord/ts-early", { v: ts("2001-02-03T04:05:06Z") }),
  seedDoc("ord/ts-late", { v: ts("2001-02-03T04:05:06.000001Z") }),
  seedDoc("ord/str-empty", { v: str("") }),
  seedDoc("ord/str-a", { v: str("a") }),
  seedDoc("ord/str-B", { v: str("B") }),
  seedDoc("ord/str-aa", { v: str("aa") }),
  seedDoc("ord/str-e-acute", { v: str("é") }),
  seedDoc("ord/str-kanji", { v: str("日") }),
  seedDoc("ord/str-emoji", { v: str("\u{1F600}") }),
  seedDoc("ord/bytes-empty", { v: bytes("") }),
  seedDoc("ord/bytes-01", { v: bytes("AQ==") }),
  seedDoc("ord/bytes-0102", { v: bytes("AQI=") }),
  seedDoc("ord/bytes-ff", { v: bytes("/w==") }),
  seedDoc("ord/ref-a", { v: ref("ord/a") }),
  seedDoc("ord/ref-b-sub", { v: ref("ord/b/sub/x") }),
  seedDoc("ord/ref-c", { v: ref("ord/c") }),
  seedDoc("ord/ref-other-col", { v: ref("aaa/z") }),
  seedDoc("ord/geo-south", { v: geo(-1, 5) }),
  seedDoc("ord/geo-north-west", { v: geo(1, -5) }),
  seedDoc("ord/geo-north-east", { v: geo(1, 5) }),
  seedDoc("ord/arr-empty", { v: arr() }),
  seedDoc("ord/arr-1", { v: arr(int(1)) }),
  seedDoc("ord/arr-1-2", { v: arr(int(1), int(2)) }),
  seedDoc("ord/arr-2", { v: arr(int(2)) }),
  seedDoc("ord/arr-str", { v: arr(str("a")) }),
  seedDoc("ord/map-empty", { v: map({}) }),
  seedDoc("ord/map-a1", { v: map({ a: int(1) }) }),
  seedDoc("ord/map-a2", { v: map({ a: int(2) }) }),
  seedDoc("ord/map-b0", { v: map({ b: int(0) }) }),
  seedDoc("ord/map-a1-b0", { v: map({ a: int(1), b: int(0) }) }),
  seedDoc("ord/missing", { other: int(1) }),
];

const valueOrdering = {
  id: "values/type-order",
  area: "values",
  seed: ORDER_SEED,
  steps: [
    runQuery("ascending", { from: from("ord"), orderBy: [asc("v")] }),
    runQuery("descending", { from: from("ord"), orderBy: [desc("v")] }),
    runQuery("ascending-name-only", { from: from("ord"), orderBy: [asc("__name__")], limit: 5 }),
    runQuery("descending-name-only", { from: from("ord"), orderBy: [desc("__name__")], limit: 5 }),
    runQuery("no-order-is-name-order", { from: from("ord"), limit: 6 }),
    runQuery("select-name-only", {
      from: from("ord"),
      select: { fields: [{ fieldPath: "__name__" }] },
      orderBy: [asc("v")],
      limit: 4,
    }),
  ],
};

/** Numbers of both kinds interleave; ties break on the document name. */
const numericTies = {
  id: "values/numeric-ties",
  area: "values",
  seed: [
    seedDoc("num/b", { v: int(1) }),
    seedDoc("num/a", { v: dbl(1) }),
    seedDoc("num/c", { v: dbl(1.0000000000000002) }),
    seedDoc("num/d", { v: int(-0) }),
    seedDoc("num/e", { v: dbl(-0.0) }),
    seedDoc("num/f", { v: dbl(0.0) }),
    seedDoc("num/g", { v: dbl("-Infinity") }),
    seedDoc("num/h", { v: nan() }),
    seedDoc("num/i", { v: int("9223372036854775807") }),
    // i64::MAX as the nearest double (2^63); written in float form so no precision is lost
    // silently in the source.
    seedDoc("num/j", { v: dbl(9.223372036854776e18) }),
  ],
  steps: [
    runQuery("ascending", { from: from("num"), orderBy: [asc("v")] }),
    runQuery("equal-int-matches-double", { from: from("num"), where: field("v", "EQUAL", int(1)) }),
    runQuery("equal-double-matches-int", {
      from: from("num"),
      where: field("v", "EQUAL", dbl(1.0)),
    }),
    runQuery("zero-equals-negative-zero", {
      from: from("num"),
      where: field("v", "EQUAL", dbl(-0.0)),
    }),
    runQuery("nan-equals-nothing", { from: from("num"), where: field("v", "EQUAL", nan()) }),
    runQuery("is-nan", { from: from("num"), where: unary("v", "IS_NAN") }),
    runQuery("is-not-nan", { from: from("num"), where: unary("v", "IS_NOT_NAN") }),
    runQuery("greater-than-negative-infinity", {
      from: from("num"),
      where: field("v", "GREATER_THAN", dbl("-Infinity")),
    }),
    runQuery("less-than-nan", { from: from("num"), where: field("v", "LESS_THAN", nan()) }),
    runQuery("not-equal-one", { from: from("num"), where: field("v", "NOT_EQUAL", int(1)) }),
  ],
};

const FILTER_SEED = [
  seedDoc("flt/a", {
    s: str("x"),
    n: int(1),
    tags: arr(str("red"), str("blue")),
    m: map({ k: int(1) }),
  }),
  seedDoc("flt/b", { s: str("y"), n: int(2), tags: arr(str("blue")), m: map({ k: int(2) }) }),
  seedDoc("flt/c", { s: str("x"), n: int(3), tags: arr(), m: map({ k: nul() }) }),
  seedDoc("flt/d", { s: nul(), n: dbl(2.5), tags: arr(nul(), nan()) }),
  seedDoc("flt/e", { n: str("2"), tags: str("red") }),
  seedDoc("flt/f", { s: str("z"), n: nan(), tags: arr(str("red"), int(1), map({ a: int(1) })) }),
  seedDoc("flt/g", { s: str("x"), n: int(1), nested: map({ deep: map({ v: bool(true) }) }) }),
];

const filters = {
  id: "queries/filters",
  area: "queries",
  seed: FILTER_SEED,
  steps: [
    runQuery("equal-string", { from: from("flt"), where: field("s", "EQUAL", str("x")) }),
    runQuery("equal-null", { from: from("flt"), where: field("s", "EQUAL", nul()) }),
    runQuery("is-null", { from: from("flt"), where: unary("s", "IS_NULL") }),
    runQuery("is-not-null", { from: from("flt"), where: unary("s", "IS_NOT_NULL") }),
    runQuery("not-equal-excludes-null-and-missing", {
      from: from("flt"),
      where: field("s", "NOT_EQUAL", str("x")),
    }),
    runQuery("not-equal-null", { from: from("flt"), where: field("s", "NOT_EQUAL", nul()) }),
    runQuery("range-is-type-restricted", {
      from: from("flt"),
      where: field("n", "GREATER_THAN_OR_EQUAL", int(2)),
    }),
    runQuery("range-on-string", { from: from("flt"), where: field("n", "GREATER_THAN", str("1")) }),
    runQuery("range-implies-order", {
      from: from("flt"),
      where: field("n", "LESS_THAN", int(3)),
      orderBy: [desc("__name__")],
    }),
    runQuery("array-contains", {
      from: from("flt"),
      where: field("tags", "ARRAY_CONTAINS", str("red")),
    }),
    runQuery("array-contains-null", {
      from: from("flt"),
      where: field("tags", "ARRAY_CONTAINS", nul()),
    }),
    runQuery("array-contains-nan", {
      from: from("flt"),
      where: field("tags", "ARRAY_CONTAINS", nan()),
    }),
    runQuery("array-contains-array", {
      from: from("flt"),
      where: field("tags", "ARRAY_CONTAINS", arr(int(1))),
    }),
    runQuery("array-contains-any", {
      from: from("flt"),
      where: field("tags", "ARRAY_CONTAINS_ANY", arr(str("blue"), int(1))),
    }),
    runQuery("in", { from: from("flt"), where: field("s", "IN", arr(str("y"), str("z"), nul())) }),
    runQuery("in-with-double-for-int", {
      from: from("flt"),
      where: field("n", "IN", arr(dbl(1.0), str("2"))),
    }),
    runQuery("not-in", { from: from("flt"), where: field("s", "NOT_IN", arr(str("x"))) }),
    runQuery("not-in-with-null-candidate", {
      from: from("flt"),
      where: field("s", "NOT_IN", arr(str("x"), nul())),
    }),
    runQuery("equal-on-array-value", {
      from: from("flt"),
      where: field("tags", "EQUAL", arr(str("blue"))),
    }),
    runQuery("equal-on-map-value", {
      from: from("flt"),
      where: field("m", "EQUAL", map({ k: int(2) })),
    }),
    runQuery("nested-field-path", {
      from: from("flt"),
      where: field("nested.deep.v", "EQUAL", bool(true)),
    }),
    runQuery("nested-field-path-on-map", {
      from: from("flt"),
      where: field("m.k", "EQUAL", int(1)),
    }),
    runQuery("or-filter", {
      from: from("flt"),
      where: or(field("s", "EQUAL", str("y")), field("n", "EQUAL", int(3))),
    }),
    runQuery("and-of-or", {
      from: from("flt"),
      where: and(
        or(field("s", "EQUAL", str("x")), field("s", "EQUAL", str("y"))),
        field("n", "LESS_THAN_OR_EQUAL", int(2)),
      ),
    }),
    runQuery("two-equalities", {
      from: from("flt"),
      where: and(field("s", "EQUAL", str("x")), field("n", "EQUAL", int(1))),
    }),
    runQuery("two-inequalities-on-different-fields", {
      from: from("flt"),
      where: and(field("s", "GREATER_THAN", str("w")), field("n", "LESS_THAN", int(3))),
    }),
    runQuery("inequality-and-order-on-another-field", {
      from: from("flt"),
      where: field("n", "GREATER_THAN", int(0)),
      orderBy: [asc("s")],
    }),
    runQuery("inequality-then-order-on-it-explicitly-second", {
      from: from("flt"),
      where: field("n", "GREATER_THAN", int(0)),
      orderBy: [asc("s"), asc("n")],
    }),
    runQuery("order-by-missing-field-excludes", { from: from("flt"), orderBy: [asc("m")] }),
    runQuery("order-by-two-fields", { from: from("flt"), orderBy: [asc("s"), desc("n")] }),
  ],
};

const CURSOR_SEED = [
  seedDoc("cur/a", { n: int(1), g: str("p") }),
  seedDoc("cur/b", { n: int(2), g: str("p") }),
  seedDoc("cur/c", { n: int(2), g: str("q") }),
  seedDoc("cur/d", { n: int(3), g: str("q") }),
  seedDoc("cur/e", { n: int(4), g: str("p") }),
  seedDoc("cur/f", { g: str("r") }),
];

const cursors = {
  id: "queries/cursors",
  area: "queries",
  seed: CURSOR_SEED,
  steps: [
    runQuery("start-at-inclusive", {
      from: from("cur"),
      orderBy: [asc("n")],
      startAt: cursor([int(2)], true),
    }),
    runQuery("start-after", {
      from: from("cur"),
      orderBy: [asc("n")],
      startAt: cursor([int(2)], false),
    }),
    runQuery("end-before", {
      from: from("cur"),
      orderBy: [asc("n")],
      endAt: cursor([int(3)], true),
    }),
    runQuery("end-at-inclusive", {
      from: from("cur"),
      orderBy: [asc("n")],
      endAt: cursor([int(3)], false),
    }),
    runQuery("start-at-with-name-tiebreak", {
      from: from("cur"),
      orderBy: [asc("n"), asc("__name__")],
      startAt: cursor([int(2), ref("cur/c")], true),
    }),
    runQuery("start-at-prefix-of-order", {
      from: from("cur"),
      orderBy: [asc("g"), asc("n")],
      startAt: cursor([str("q")], true),
    }),
    runQuery("descending-start-after", {
      from: from("cur"),
      orderBy: [desc("n")],
      startAt: cursor([int(3)], false),
    }),
    runQuery("cursor-of-another-type", {
      from: from("cur"),
      orderBy: [asc("n")],
      startAt: cursor([str("2")], true),
    }),
    runQuery("cursor-on-name-only", {
      from: from("cur"),
      orderBy: [asc("__name__")],
      startAt: cursor([ref("cur/c")], false),
    }),
    runQuery("cursor-with-too-many-values", {
      from: from("cur"),
      orderBy: [asc("n")],
      startAt: cursor([int(2), int(3), int(4)], true),
    }),
    runQuery("offset-and-limit", { from: from("cur"), orderBy: [asc("n")], offset: 2, limit: 2 }),
    runQuery("offset-past-the-end", { from: from("cur"), orderBy: [asc("n")], offset: 10 }),
    runQuery("limit-zero", { from: from("cur"), orderBy: [asc("n")], limit: 0 }),
    runQuery("limit-to-last-shape", {
      from: from("cur"),
      orderBy: [desc("n"), desc("__name__")],
      limit: 2,
    }),
    runQuery("start-at-with-empty-values", {
      from: from("cur"),
      orderBy: [asc("n")],
      startAt: cursor([], true),
    }),
  ],
};

const GROUP_SEED = [
  seedDoc("cg/a", { t: str("root-a") }),
  seedDoc("cg/a/items/1", { t: str("a1"), n: int(1) }),
  seedDoc("cg/a/items/2", { t: str("a2"), n: int(2) }),
  seedDoc("cg/b/items/1", { t: str("b1"), n: int(3) }),
  seedDoc("cg/b/items/1/items/deep", { t: str("deep"), n: int(4) }),
  seedDoc("items/root", { t: str("root"), n: int(0) }),
  seedDoc("cg/b/other/1", { t: str("other") }),
];

const collectionGroup = {
  id: "queries/collection-group",
  area: "queries",
  seed: GROUP_SEED,
  steps: [
    runQuery("all-descendants", { from: from("items", true), orderBy: [asc("__name__")] }),
    runQuery("all-descendants-by-field", { from: from("items", true), orderBy: [asc("n")] }),
    runQuery(
      "all-descendants-under-a-parent",
      {
        from: from("items", true),
        orderBy: [asc("__name__")],
      },
      { parent: "cg/b" },
    ),
    runQuery(
      "subcollection-query",
      { from: from("items"), orderBy: [asc("__name__")] },
      { parent: "cg/a" },
    ),
    runQuery("group-start-at-a-full-reference", {
      from: from("items", true),
      orderBy: [asc("__name__")],
      startAt: cursor([ref("cg/b/items/1")], true),
    }),
    runQuery("group-with-name-range", {
      from: from("items", true),
      where: and(
        field("__name__", "GREATER_THAN_OR_EQUAL", ref("cg/b/items/1")),
        field("__name__", "LESS_THAN", ref("cg/b/items/2")),
      ),
    }),
    runQuery("name-equality", {
      from: from("items", true),
      where: field("__name__", "EQUAL", ref("cg/a/items/2")),
    }),
    runQuery("name-in", {
      from: from("items", true),
      where: field("__name__", "IN", arr(ref("cg/a/items/2"), ref("items/root"))),
    }),
    runQuery("missing-collection", { from: from("nothing"), orderBy: [asc("__name__")] }),
    {
      id: "partition-query",
      method: "POST",
      path: `${DOCS}:partitionQuery`,
      body: {
        structuredQuery: { from: from("items", true), orderBy: [asc("__name__")] },
        partitionCount: "2",
        pageSize: 10,
      },
    },
  ],
};

const AGG_SEED = [
  seedDoc("agg/a", { n: int(1), d: dbl(1.5), k: str("x") }),
  seedDoc("agg/b", { n: int(2), d: dbl(2.5), k: str("x") }),
  seedDoc("agg/c", { n: int(3), d: nan(), k: str("y") }),
  seedDoc("agg/d", { n: str("4"), d: int(4), k: str("y") }),
  seedDoc("agg/e", { n: int("9223372036854775807"), k: str("z") }),
  seedDoc("agg/f", { n: int(1), k: str("z") }),
];

const count = (alias = "count", upTo) => ({
  alias,
  count: upTo === undefined ? {} : { upTo: String(upTo) },
});
const sum = (path, alias = "sum") => ({ alias, sum: { field: { fieldPath: path } } });
const avg = (path, alias = "avg") => ({ alias, avg: { field: { fieldPath: path } } });

const aggregations = {
  id: "queries/aggregations",
  area: "queries",
  seed: AGG_SEED,
  steps: [
    runAggregation("count-all", { from: from("agg") }, [count()]),
    runAggregation("count-up-to", { from: from("agg") }, [count("c", 2)]),
    runAggregation(
      "count-with-filter",
      { from: from("agg"), where: field("k", "EQUAL", str("x")) },
      [count()],
    ),
    runAggregation("count-with-limit", { from: from("agg"), limit: 3 }, [count()]),
    runAggregation("count-with-offset", { from: from("agg"), offset: 4 }, [count()]),
    runAggregation("count-empty", { from: from("agg"), where: field("k", "EQUAL", str("none")) }, [
      count(),
    ]),
    runAggregation(
      "sum-integers",
      { from: from("agg"), where: field("k", "IN", arr(str("x"), str("z"))) },
      [sum("n")],
    ),
    runAggregation("sum-mixed-numbers", { from: from("agg") }, [sum("d")]),
    runAggregation(
      "sum-doubles-only",
      { from: from("agg"), where: field("k", "EQUAL", str("x")) },
      [sum("d")],
    ),
    runAggregation("sum-empty", { from: from("agg"), where: field("k", "EQUAL", str("none")) }, [
      sum("n"),
    ]),
    runAggregation("sum-missing-field", { from: from("agg") }, [sum("nothing")]),
    runAggregation("sum-overflow-saturates-or-promotes", { from: from("agg") }, [sum("n")]),
    runAggregation(
      "avg-integers",
      { from: from("agg"), where: field("k", "IN", arr(str("x"), str("f"))) },
      [avg("n")],
    ),
    runAggregation("avg-with-nan", { from: from("agg") }, [avg("d")]),
    runAggregation("avg-empty", { from: from("agg"), where: field("k", "EQUAL", str("none")) }, [
      avg("n"),
    ]),
    runAggregation("several-aggregations", { from: from("agg") }, [
      count("total"),
      sum("n", "sum_n"),
      avg("d", "avg_d"),
      count("capped", 1),
    ]),
    runAggregation("count-collection-group", { from: from("agg", true) }, [count()]),
    runAggregation(
      "count-with-cursor",
      {
        from: from("agg"),
        orderBy: [asc("__name__")],
        startAt: cursor([ref("agg/c")], true),
      },
      [count()],
    ),
    // Whether a count is affected by a sibling aggregation over a field some documents lack.
    runAggregation("count-beside-a-sum-over-a-missing-field", { from: from("agg") }, [
      count("total"),
      sum("d", "sum_d"),
    ]),
    runAggregation("count-beside-an-avg-over-a-missing-field", { from: from("agg") }, [
      count("total"),
      avg("d", "avg_d"),
    ]),
    runAggregation("duplicate-alias", { from: from("agg") }, [count("x"), count("x")]),
    runAggregation("no-aggregations", { from: from("agg") }, []),
    runAggregation("sum-on-name", { from: from("agg") }, [sum("__name__")]),
  ],
};

const PROJECTION_SEED = [
  seedDoc("prj/a", { a: int(1), b: map({ c: int(2), d: int(3) }), e: arr(int(1)) }),
  seedDoc("prj/b", { a: int(2) }),
  seedDoc("prj/missing-parent/sub/x", { z: int(1) }),
];

const projectionAndListing = {
  id: "queries/projection-and-listing",
  area: "queries",
  seed: PROJECTION_SEED,
  steps: [
    runQuery("select-fields", {
      from: from("prj"),
      select: { fields: [{ fieldPath: "a" }, { fieldPath: "b.c" }] },
      orderBy: [asc("__name__")],
    }),
    runQuery("select-missing-field", {
      from: from("prj"),
      select: { fields: [{ fieldPath: "nothing" }] },
      orderBy: [asc("__name__")],
    }),
    runQuery("select-with-empty-list", {
      from: from("prj"),
      select: { fields: [] },
      orderBy: [asc("__name__")],
    }),
    { id: "list-documents", method: "GET", path: `${DOCS}/prj` },
    { id: "list-documents-page-size-one", method: "GET", path: `${DOCS}/prj?pageSize=1` },
    {
      id: "list-documents-next-page",
      method: "GET",
      path: `${DOCS}/prj?pageSize=1&pageToken={{list-documents-page-size-one.nextPageToken}}`,
    },
    { id: "list-documents-with-mask", method: "GET", path: `${DOCS}/prj?mask.fieldPaths=a` },
    { id: "list-documents-descending", method: "GET", path: `${DOCS}/prj?orderBy=a%20desc` },
    { id: "list-documents-show-missing", method: "GET", path: `${DOCS}/prj?showMissing=true` },
    { id: "list-missing-parents", method: "GET", path: `${DOCS}/prj?showMissing=true&pageSize=10` },
    {
      id: "list-subcollection-of-missing-parent",
      method: "GET",
      path: `${DOCS}/prj/missing-parent/sub`,
    },
    { id: "list-empty-collection", method: "GET", path: `${DOCS}/nothing` },
    {
      id: "list-collection-ids-root",
      method: "POST",
      path: `${DOCS}:listCollectionIds`,
      body: {},
    },
    {
      id: "list-collection-ids-of-a-missing-document",
      method: "POST",
      path: `${DOCS}/prj/missing-parent:listCollectionIds`,
      body: {},
    },
    {
      id: "list-collection-ids-paged",
      method: "POST",
      path: `${DOCS}:listCollectionIds`,
      body: { pageSize: 1 },
    },
    get("get-with-mask", "prj/a", "?mask.fieldPaths=b.d&mask.fieldPaths=e"),
    get("get-missing-parent-document", "prj/missing-parent"),
    {
      id: "batch-get-mixed",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: {
        documents: [`${REF_PREFIX}/prj/b`, `${REF_PREFIX}/prj/none`, `${REF_PREFIX}/prj/a`],
        mask: { fieldPaths: ["a"] },
      },
    },
  ],
};

const WRITE_SEED = [
  seedDoc("wr/existing", { a: int(1), nested: map({ keep: str("k"), drop: str("d") }) }),
];

const writes = {
  id: "writes/preconditions-and-masks",
  area: "writes",
  seed: WRITE_SEED,
  steps: [
    commit("create-with-exists-false", [
      update("wr/new", { a: int(1) }, { currentDocument: { exists: false } }),
    ]),
    commit("create-again-is-already-exists", [
      update("wr/new", { a: int(2) }, { currentDocument: { exists: false } }),
    ]),
    commit("update-missing-with-exists-true", [
      update("wr/none", { a: int(1) }, { currentDocument: { exists: true } }),
    ]),
    commit("mask-sets-and-deletes", [
      update(
        "wr/existing",
        { b: int(2), nested: map({ keep: str("k2") }) },
        { updateMask: { fieldPaths: ["b", "nested.drop", "nested.keep"] } },
      ),
    ]),
    get("read-after-mask", "wr/existing"),
    commit("mask-on-missing-document-creates-it", [
      update("wr/masked-new", { a: int(1) }, { updateMask: { fieldPaths: ["a"] } }),
    ]),
    get("read-masked-new", "wr/masked-new"),
    commit("mask-naming-an-absent-field-deletes-it", [
      update("wr/existing", {}, { updateMask: { fieldPaths: ["b"] } }),
    ]),
    get("read-after-delete-by-mask", "wr/existing"),
    commit("replace-without-mask", [update("wr/existing", { only: bool(true) })]),
    get("read-after-replace", "wr/existing"),
    commit("update-time-precondition-matches", [
      update(
        "wr/existing",
        { only: bool(false) },
        { currentDocument: { updateTime: { $from: "read-after-replace", path: "updateTime" } } },
      ),
    ]),
    commit("update-time-precondition-is-stale", [
      update(
        "wr/existing",
        { only: str("stale") },
        { currentDocument: { updateTime: { $from: "read-after-replace", path: "updateTime" } } },
      ),
    ]),
    commit("update-time-precondition-on-a-missing-document", [
      update("wr/none", { a: int(1) }, { currentDocument: { updateTime: "2020-01-01T00:00:00Z" } }),
    ]),
    commit("delete-missing-is-ok", [del("wr/none")]),
    commit("delete-missing-with-exists-true", [
      del("wr/none", { currentDocument: { exists: true } }),
    ]),
    commit("atomic-failure-writes-nothing", [
      update("wr/atomic-1", { a: int(1) }),
      update("wr/none", { a: int(1) }, { currentDocument: { exists: true } }),
    ]),
    get("atomic-1-is-absent", "wr/atomic-1"),
    commit("same-document-twice-in-one-commit", [
      update("wr/twice", { a: int(1), b: int(1) }),
      update("wr/twice", { a: int(2) }, { updateMask: { fieldPaths: ["a"] } }),
    ]),
    get("read-twice", "wr/twice"),
    commit("empty-commit", []),
    commit("verify-write", [
      { verify: `${REF_PREFIX}/wr/twice`, currentDocument: { exists: true } },
    ]),
    commit("verify-missing", [
      { verify: `${REF_PREFIX}/wr/none`, currentDocument: { exists: true } },
    ]),
    commit("no-op-set-keeps-update-time", [update("wr/twice", { a: int(2), b: int(1) })]),
    get("read-after-no-op", "wr/twice"),
    {
      id: "patch-with-mask-and-exists-precondition-on-missing",
      method: "PATCH",
      path: `${DOCS}/wr/patched?updateMask.fieldPaths=a&currentDocument.exists=true`,
      body: { fields: { a: int(1) } },
    },
    {
      id: "patch-creates",
      method: "PATCH",
      path: `${DOCS}/wr/patched?updateMask.fieldPaths=a`,
      body: { fields: { a: int(1), ignored: int(9) } },
    },
    get("read-patched", "wr/patched"),
    {
      id: "create-document",
      method: "POST",
      path: `${DOCS}/wr?documentId=created`,
      body: { fields: { a: int(1) } },
    },
    {
      id: "create-document-again",
      method: "POST",
      path: `${DOCS}/wr?documentId=created`,
      body: { fields: { a: int(2) } },
    },
    {
      id: "create-document-with-generated-id",
      method: "POST",
      path: `${DOCS}/wr`,
      body: { fields: { a: int(1) } },
    },
    { id: "delete-document", method: "DELETE", path: `${DOCS}/wr/created` },
    { id: "delete-document-again", method: "DELETE", path: `${DOCS}/wr/created` },
    {
      id: "delete-with-exists-precondition",
      method: "DELETE",
      path: `${DOCS}/wr/created?currentDocument.exists=true`,
    },
  ],
};

const TRANSFORM_SEED = [
  seedDoc("tf/doc", {
    n: int(1),
    d: dbl(1.5),
    s: str("not a number"),
    tags: arr(str("a"), int(1)),
    m: map({ inner: int(5) }),
  }),
];

const fieldTransform = (fieldPath, kind) => ({ fieldPath, ...kind });

const transforms = {
  id: "writes/transforms",
  area: "writes",
  seed: TRANSFORM_SEED,
  steps: [
    commit("server-timestamp-and-increments", [
      update(
        "tf/doc",
        {},
        {
          updateMask: { fieldPaths: [] },
          updateTransforms: [
            fieldTransform("at", { setToServerValue: "REQUEST_TIME" }),
            fieldTransform("n", { increment: int(2) }),
            fieldTransform("d", { increment: int(1) }),
            fieldTransform("s", { increment: int(1) }),
            fieldTransform("missing", { increment: dbl(0.5) }),
            fieldTransform("m.inner", { increment: int(-10) }),
          ],
        },
      ),
    ]),
    get("read-after-increments", "tf/doc"),
    commit("maximum-and-minimum", [
      update(
        "tf/doc",
        {},
        {
          updateMask: { fieldPaths: [] },
          updateTransforms: [
            fieldTransform("n", { maximum: int(100) }),
            fieldTransform("d", { minimum: dbl(-1) }),
            fieldTransform("s", { maximum: int(7) }),
            fieldTransform("max-missing", { maximum: int(3) }),
            fieldTransform("n", { minimum: dbl(50.5) }),
          ],
        },
      ),
    ]),
    get("read-after-max-min", "tf/doc"),
    commit("array-transforms", [
      update(
        "tf/doc",
        {},
        {
          updateMask: { fieldPaths: [] },
          updateTransforms: [
            fieldTransform("tags", {
              appendMissingElements: { values: [str("a"), str("b"), dbl(1.0), int(1)] },
            }),
            fieldTransform("s", { appendMissingElements: { values: [str("x")] } }),
            fieldTransform("tags", { removeAllFromArray: { values: [int(1)] } }),
          ],
        },
      ),
    ]),
    get("read-after-array-transforms", "tf/doc"),
    commit("transform-only-write-creates", [
      transform("tf/created", [
        fieldTransform("count", { increment: int(1) }),
        fieldTransform("at", { setToServerValue: "REQUEST_TIME" }),
      ]),
    ]),
    get("read-transform-created", "tf/created"),
    commit("transform-write-with-exists-precondition", [
      transform("tf/none", [fieldTransform("count", { increment: int(1) })], {
        currentDocument: { exists: true },
      }),
    ]),
    commit("increment-with-non-numeric-operand", [
      update(
        "tf/doc",
        {},
        {
          updateMask: { fieldPaths: [] },
          updateTransforms: [fieldTransform("n", { increment: str("1") })],
        },
      ),
    ]),
    commit("server-timestamp-on-a-delete", [
      del("tf/doc", {
        updateTransforms: [fieldTransform("at", { setToServerValue: "REQUEST_TIME" })],
      }),
    ]),
    commit("set-and-transform-same-field", [
      update(
        "tf/doc",
        { n: int(1000) },
        {
          updateMask: { fieldPaths: ["n"] },
          updateTransforms: [fieldTransform("n", { increment: int(1) })],
        },
      ),
    ]),
    get("read-set-and-transform", "tf/doc"),
    commit("integer-increment-saturates", [
      update(
        "tf/sat",
        { n: int("9223372036854775807") },
        { updateTransforms: [fieldTransform("n", { increment: int(1) })] },
      ),
    ]),
    get("read-saturated", "tf/sat"),
    commit("increment-on-nan", [
      update(
        "tf/nan",
        { n: nan() },
        { updateTransforms: [fieldTransform("n", { increment: int(1) })] },
      ),
    ]),
    commit("two-transforms-on-one-field-in-one-write", [
      update(
        "tf/dup",
        { n: int(1) },
        {
          updateTransforms: [
            fieldTransform("n", { increment: int(1) }),
            fieldTransform("n", { increment: int(1) }),
          ],
        },
      ),
    ]),
    get("read-dup", "tf/dup"),
  ],
};

const batchWrite = {
  id: "writes/batch-write",
  area: "writes",
  seed: [seedDoc("bw/existing", { a: int(1) })],
  steps: [
    {
      id: "non-atomic-batch",
      method: "POST",
      path: `${DOCS}:batchWrite`,
      body: {
        writes: [
          update("bw/one", { a: int(1) }),
          update("bw/none", { a: int(1) }, { currentDocument: { exists: true } }),
          update("bw/existing", { a: int(2) }, { currentDocument: { exists: false } }),
          del("bw/existing"),
          transform("bw/one", [fieldTransform("n", { increment: int(5) })]),
        ],
      },
    },
    get("one-was-written", "bw/one"),
    get("existing-was-deleted", "bw/existing"),
    {
      id: "empty-batch",
      method: "POST",
      path: `${DOCS}:batchWrite`,
      body: { writes: [] },
    },
    {
      id: "batch-with-transaction-is-refused",
      method: "POST",
      path: `${DOCS}:batchWrite`,
      body: { writes: [update("bw/two", { a: int(1) })], transaction: "AA==" },
    },
  ],
};

const transactions = {
  id: "transactions/lifecycle",
  area: "transactions",
  seed: [
    seedDoc("tx/counter", { value: int(0) }),
    seedDoc("tx/other", { value: int(0) }),
    seedDoc("tx/third", { value: int(0) }),
  ],
  steps: [
    { id: "begin", method: "POST", path: `${DOCS}:beginTransaction`, body: {} },
    {
      id: "read-in-transaction",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: {
        documents: [`${REF_PREFIX}/tx/counter`],
        transaction: { $from: "begin", path: "transaction" },
      },
    },
    // The official emulator's REST adapter cannot decode a bytes-typed query parameter: it
    // logs `Unmapped JavaType: BYTE_STRING` and never answers, so the session records a
    // timeout for it. Every other transaction read in this corpus goes through a JSON body.
    get("get-with-transaction-query-parameter", "tx/counter", "?transaction={{begin}}"),
    commit("commit-in-transaction", [update("tx/counter", { value: int(1) })], {
      transaction: { $from: "begin", path: "transaction" },
    }),
    commit("commit-finished-transaction-again", [update("tx/counter", { value: int(2) })], {
      transaction: { $from: "begin", path: "transaction" },
    }),
    { id: "begin-contended", method: "POST", path: `${DOCS}:beginTransaction`, body: {} },
    {
      id: "read-contended",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: {
        documents: [`${REF_PREFIX}/tx/counter`],
        transaction: { $from: "begin-contended", path: "transaction" },
      },
    },
    commit("out-of-band-write", [update("tx/counter", { value: int(100) })]),
    commit("contended-commit-is-aborted", [update("tx/counter", { value: int(3) })], {
      transaction: { $from: "begin-contended", path: "transaction" },
    }),
    get("counter-keeps-the-out-of-band-value", "tx/counter"),
    { id: "begin-unread", method: "POST", path: `${DOCS}:beginTransaction`, body: {} },
    commit("out-of-band-write-2", [update("tx/counter", { value: int(200) })]),
    commit("blind-write-in-a-transaction-commits", [update("tx/counter", { value: int(4) })], {
      transaction: { $from: "begin-unread", path: "transaction" },
    }),
    { id: "begin-query", method: "POST", path: `${DOCS}:beginTransaction`, body: {} },
    runQuery(
      "query-in-transaction",
      { from: from("tx"), orderBy: [asc("__name__")] },
      { extra: { transaction: { $from: "begin-query", path: "transaction" } } },
    ),
    commit("phantom-write", [update("tx/phantom", { value: int(1) })]),
    commit("commit-after-a-phantom-row", [update("tx/other", { value: int(1) })], {
      transaction: { $from: "begin-query", path: "transaction" },
    }),
    {
      id: "begin-read-only",
      method: "POST",
      path: `${DOCS}:beginTransaction`,
      body: { options: { readOnly: {} } },
    },
    commit("read-only-commit-with-writes", [update("tx/third", { value: int(2) })], {
      transaction: { $from: "begin-read-only", path: "transaction" },
    }),
    commit("read-only-commit-without-writes", [], {
      transaction: { $from: "begin-read-only", path: "transaction" },
    }),
    { id: "begin-rolled-back", method: "POST", path: `${DOCS}:beginTransaction`, body: {} },
    {
      id: "rollback",
      method: "POST",
      path: `${DOCS}:rollback`,
      body: { transaction: { $from: "begin-rolled-back", path: "transaction" } },
    },
    commit("commit-after-rollback", [update("tx/third", { value: int(3) })], {
      transaction: { $from: "begin-rolled-back", path: "transaction" },
    }),
    {
      id: "rollback-unknown",
      method: "POST",
      path: `${DOCS}:rollback`,
      body: { transaction: "AAAAAAAAAAA=" },
    },
    commit("commit-with-unknown-transaction", [update("tx/third", { value: int(4) })], {
      transaction: "AAAAAAAAAAA=",
    }),
    commit("commit-with-malformed-transaction", [update("tx/third", { value: int(4) })], {
      transaction: "not base64!",
    }),
    {
      id: "batch-get-with-new-transaction",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: { documents: [`${REF_PREFIX}/tx/third`], newTransaction: {} },
    },
    commit("commit-the-new-transaction", [update("tx/third", { value: int(5) })], {
      transaction: { $from: "batch-get-with-new-transaction", path: "0.transaction" },
    }),
    runQuery(
      "run-query-with-new-transaction",
      { from: from("tx"), orderBy: [asc("__name__")], limit: 1 },
      { extra: { newTransaction: { readOnly: {} } } },
    ),
    {
      id: "begin-with-read-time-in-the-past",
      method: "POST",
      path: `${DOCS}:beginTransaction`,
      body: { options: { readOnly: { readTime: "2020-01-01T00:00:00Z" } } },
    },
    {
      id: "begin-read-write-with-retry-transaction",
      method: "POST",
      path: `${DOCS}:beginTransaction`,
      body: {
        options: {
          readWrite: { retryTransaction: { $from: "begin-rolled-back", path: "transaction" } },
        },
      },
    },
    {
      id: "batch-get-with-both-transaction-and-read-time",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: {
        documents: [`${REF_PREFIX}/tx/third`],
        transaction: "AAAAAAAAAAA=",
        readTime: "2020-01-01T00:00:00Z",
      },
    },
  ],
};

const errors = {
  id: "errors/rest-shapes",
  area: "errors",
  seed: [seedDoc("err/a", { a: int(1) })],
  steps: [
    get("get-missing-document", "err/none"),
    { id: "get-collection-path-as-document", method: "GET", path: `${DOCS}/err/a/sub` },
    { id: "get-odd-path", method: "GET", path: `${DOCS}/err/a/sub/x/y` },
    { id: "get-with-invalid-mask", method: "GET", path: `${DOCS}/err/a?mask.fieldPaths=a..b` },
    { id: "unknown-custom-method", method: "POST", path: `${DOCS}:doSomething`, body: {} },
    {
      id: "wrong-database",
      method: "GET",
      path: `/v1/projects/PROJECT/databases/nope/documents/err/a`,
    },
    {
      id: "wrong-project",
      method: "GET",
      path: `/v1/projects/other-project/databases/(default)/documents/err/a`,
    },
    { id: "not-json", method: "POST", path: `${DOCS}:runQuery`, body: "{not json" },
    {
      id: "run-query-without-from",
      method: "POST",
      path: `${DOCS}:runQuery`,
      body: { structuredQuery: {} },
    },
    { id: "run-query-empty-body", method: "POST", path: `${DOCS}:runQuery`, body: {} },
    runQuery("unknown-operator", { from: from("err"), where: field("a", "NOT_AN_OP", int(1)) }),
    runQuery("unknown-unary-operator", { from: from("err"), where: unary("a", "IS_SOMETHING") }),
    runQuery("operator-unspecified", {
      from: from("err"),
      where: field("a", "OPERATOR_UNSPECIFIED", int(1)),
    }),
    runQuery("in-with-empty-array", { from: from("err"), where: field("a", "IN", arr()) }),
    runQuery("in-with-non-array", { from: from("err"), where: field("a", "IN", int(1)) }),
    runQuery("in-with-thirty-one-values", {
      from: from("err"),
      where: field("a", "IN", arr(...Array.from({ length: 31 }, (_, i) => int(i)))),
    }),
    runQuery("in-with-thirty-values", {
      from: from("err"),
      where: field("a", "IN", arr(...Array.from({ length: 30 }, (_, i) => int(i)))),
    }),
    runQuery("array-contains-with-array-operand-and-any", {
      from: from("err"),
      where: field("a", "ARRAY_CONTAINS_ANY", arr(arr(int(1)))),
    }),
    runQuery("two-not-in", {
      from: from("err"),
      where: and(field("a", "NOT_IN", arr(int(1))), field("a", "NOT_IN", arr(int(2)))),
    }),
    runQuery("not-in-with-in", {
      from: from("err"),
      where: and(field("a", "NOT_IN", arr(int(1))), field("a", "IN", arr(int(2)))),
    }),
    runQuery("two-array-contains", {
      from: from("err"),
      where: and(field("a", "ARRAY_CONTAINS", int(1)), field("a", "ARRAY_CONTAINS", int(2))),
    }),
    runQuery("not-equal-with-not-in", {
      from: from("err"),
      where: and(field("a", "NOT_EQUAL", int(1)), field("a", "NOT_IN", arr(int(2)))),
    }),
    runQuery("empty-composite", {
      from: from("err"),
      where: { compositeFilter: { op: "AND", filters: [] } },
    }),
    runQuery("composite-without-op", {
      from: from("err"),
      where: { compositeFilter: { filters: [field("a", "EQUAL", int(1))] } },
    }),
    runQuery("invalid-field-path", { from: from("err"), where: field("a..b", "EQUAL", int(1)) }),
    runQuery("empty-field-path", { from: from("err"), where: field("", "EQUAL", int(1)) }),
    runQuery("order-by-empty-field", { from: from("err"), orderBy: [asc("")] }),
    runQuery("order-by-without-direction", {
      from: from("err"),
      orderBy: [{ field: { fieldPath: "a" } }],
    }),
    runQuery("cursor-arity-mismatch", {
      from: from("err"),
      orderBy: [asc("a")],
      startAt: cursor([int(1), int(2), int(3)], true),
    }),
    runQuery("negative-limit", { from: from("err"), limit: -1 }),
    runQuery("negative-offset", { from: from("err"), offset: -1 }),
    runQuery("two-from-clauses", { from: [{ collectionId: "err" }, { collectionId: "other" }] }),
    runQuery("from-with-empty-collection-id", { from: [{ collectionId: "" }] }),
    runQuery("from-with-slash-in-collection-id", { from: [{ collectionId: "a/b" }] }),
    runQuery("inequality-on-name-with-non-reference", {
      from: from("err"),
      where: field("__name__", "GREATER_THAN", str("err/a")),
    }),
    runQuery("name-equality-with-a-string", {
      from: from("err"),
      where: field("__name__", "EQUAL", str("err/a")),
    }),
    runQuery("reference-to-another-database", {
      from: from("err"),
      where: field("__name__", "EQUAL", {
        referenceValue: "projects/PROJECT/databases/other/documents/err/a",
      }),
    }),
    runQuery("unknown-value-kind", {
      from: from("err"),
      where: field("a", "EQUAL", { fooValue: 1 }),
    }),
    runQuery("integer-value-out-of-range", {
      from: from("err"),
      where: field("a", "EQUAL", int("99999999999999999999")),
    }),
    runQuery("timestamp-out-of-range", {
      from: from("err"),
      where: field("a", "EQUAL", ts("0000-01-01T00:00:00Z")),
    }),
    runQuery(
      "read-time-in-the-future",
      { from: from("err") },
      {
        extra: { readTime: "2999-01-01T00:00:00Z" },
      },
    ),
    runQuery(
      "read-time-in-the-distant-past",
      { from: from("err") },
      {
        extra: { readTime: "2000-01-01T00:00:00Z" },
      },
    ),
    commit("write-with-invalid-document-name", [
      { update: { name: `${REF_PREFIX}/err`, fields: { a: int(1) } } },
    ]),
    commit("write-to-another-database", [
      {
        update: { name: "projects/PROJECT/databases/other/documents/err/x", fields: { a: int(1) } },
      },
    ]),
    commit("write-with-empty-field-name", [update("err/x", { "": int(1) })]),
    commit("write-with-reserved-field-name", [update("err/x", { __id__: int(1) })]),
    commit("write-with-dotted-field-name", [update("err/x", { "a.b": int(1) })]),
    get("read-dotted-field-name", "err/x"),
    commit("write-nested-arrays", [update("err/x", { a: arr(arr(int(1))) })]),
    commit("write-array-of-maps-with-arrays", [
      update("err/x", { a: arr(map({ b: arr(int(1)) })) }),
    ]),
    commit("write-integer-out-of-range", [update("err/x", { a: int("99999999999999999999") })]),
    commit("write-integer-as-number", [
      { update: { name: `${REF_PREFIX}/err/x`, fields: { a: { integerValue: 5 } } } },
    ]),
    commit("write-double-as-string", [
      { update: { name: `${REF_PREFIX}/err/x`, fields: { a: { doubleValue: "1.5" } } } },
    ]),
    commit("write-unknown-value-kind", [update("err/x", { a: { fooValue: 1 } })]),
    commit("write-empty-value", [update("err/x", { a: {} })]),
    commit("write-bad-timestamp", [update("err/x", { a: ts("not a time") })]),
    commit("write-bad-base64", [update("err/x", { a: bytes("!!!") })]),
    commit("write-geopoint-out-of-range", [update("err/x", { a: geo(91, 0) })]),
    commit("write-reference-to-another-project", [
      update("err/x", {
        a: { referenceValue: "projects/other/databases/(default)/documents/x/y" },
      }),
    ]),
    commit("write-reference-to-a-collection", [
      update("err/x", { a: { referenceValue: `${REF_PREFIX}/x` } }),
    ]),
    commit("write-without-fields", [{ update: { name: `${REF_PREFIX}/err/nofields` } }]),
    get("read-without-fields", "err/nofields"),
    commit("write-with-two-operations", [
      { update: { name: `${REF_PREFIX}/err/x`, fields: {} }, delete: `${REF_PREFIX}/err/x` },
    ]),
    commit("write-with-no-operation", [{ currentDocument: { exists: true } }]),
    commit("mask-with-invalid-path", [
      update("err/x", { a: int(1) }, { updateMask: { fieldPaths: ["a..b"] } }),
    ]),
    commit("mask-with-backticks", [
      update("err/x", { "a.b": map({ c: int(1) }) }, { updateMask: { fieldPaths: ["`a.b`.c"] } }),
    ]),
    get("read-mask-with-backticks", "err/x"),
    commit("mask-on-a-delete", [del("err/x", { updateMask: { fieldPaths: ["a"] } })]),
    commit("precondition-with-both-fields", [
      update(
        "err/x",
        { a: int(1) },
        { currentDocument: { exists: true, updateTime: "2020-01-01T00:00:00Z" } },
      ),
    ]),
    commit("document-over-one-mebibyte", [update("err/big", { blob: str("x".repeat(1_048_600)) })]),
    commit("document-just-under-one-mebibyte", [
      update("err/big", { blob: str("x".repeat(1_048_000)) }),
    ]),
    commit("nesting-depth-twenty-one", [
      update("err/deep", {
        a: Array.from({ length: 21 }).reduce((inner) => map({ a: inner }), int(1)),
      }),
    ]),
    commit("nesting-depth-twenty", [
      update("err/deep", {
        a: Array.from({ length: 19 }).reduce((inner) => map({ a: inner }), int(1)),
      }),
    ]),
    commit("field-name-of-1500-bytes", [update("err/x", { ["f".repeat(1500)]: int(1) })]),
    commit("field-name-of-1501-bytes", [update("err/x", { ["f".repeat(1501)]: int(1) })]),
    commit("document-id-of-1500-bytes", [update(`err/${"i".repeat(1500)}`, { a: int(1) })]),
    commit("document-id-of-1501-bytes", [update(`err/${"i".repeat(1501)}`, { a: int(1) })]),
    commit("document-id-double-dot", [update("err/..", { a: int(1) })]),
    commit("document-id-single-dot", [update("err/.", { a: int(1) })]),
    commit("document-id-with-slash-encoded", [update("err/a%2Fb", { a: int(1) })]),
    commit("document-id-with-double-underscore", [update("err/__x__", { a: int(1) })]),
    commit("collection-id-with-double-underscore", [update("__err__/x", { a: int(1) })]),
    commit("five-hundred-and-one-transforms", [
      update(
        "err/tf",
        { n: int(0) },
        {
          updateTransforms: Array.from({ length: 501 }, (_, i) =>
            fieldTransform(`f${i}`, { increment: int(1) }),
          ),
        },
      ),
    ]),
    commit("five-hundred-transforms", [
      update(
        "err/tf",
        { n: int(0) },
        {
          updateTransforms: Array.from({ length: 500 }, (_, i) =>
            fieldTransform(`f${i}`, { increment: int(1) }),
          ),
        },
      ),
    ]),
    {
      id: "batch-get-with-a-bad-name",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: { documents: ["not/a/valid/name/at/all/x"] },
    },
    {
      id: "batch-get-with-a-collection-name",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: { documents: [`${REF_PREFIX}/err`] },
    },
    {
      id: "batch-get-with-no-documents",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: {},
    },
    {
      id: "list-with-negative-page-size",
      method: "GET",
      path: `${DOCS}/err?pageSize=-1`,
    },
    {
      id: "list-with-bad-page-token",
      method: "GET",
      path: `${DOCS}/err?pageToken=not-a-token`,
    },
    {
      id: "list-with-bad-order-by",
      method: "GET",
      path: `${DOCS}/err?orderBy=a%20sideways`,
    },
    {
      id: "method-not-allowed",
      method: "PUT",
      path: `${DOCS}/err/a`,
      body: { fields: {} },
    },
    {
      id: "delete-collection-path",
      method: "DELETE",
      path: `${DOCS}/err`,
    },
  ],
};

const emulatorRoutes = {
  id: "emulator/routes",
  area: "emulator",
  seed: [seedDoc("em/a", { a: int(1) }), seedDoc("em/a/sub/b", { b: int(1) })],
  steps: [
    {
      id: "clear-database",
      method: "DELETE",
      path: `/emulator/v1/projects/PROJECT/databases/(default)/documents`,
    },
    { id: "cleared-document-is-gone", method: "GET", path: `${DOCS}/em/a` },
    { id: "cleared-subcollection-is-gone", method: "GET", path: `${DOCS}/em/a/sub/b` },
    {
      id: "clear-unknown-database",
      method: "DELETE",
      path: `/emulator/v1/projects/PROJECT/databases/nope/documents`,
    },
    {
      id: "clear-with-get",
      method: "GET",
      path: `/emulator/v1/projects/PROJECT/databases/(default)/documents`,
    },
    {
      id: "put-rules-that-do-not-compile",
      method: "PUT",
      path: `/emulator/v1/projects/PROJECT:securityRules`,
      body: {
        rules: {
          files: [
            {
              name: "firestore.rules",
              content:
                "service cloud.firestore { match /databases/{d}/documents { match /{x=**} { allow read: if ; } } }",
            },
          ],
        },
      },
    },
    {
      id: "put-rules-with-a-warning",
      method: "PUT",
      path: `/emulator/v1/projects/PROJECT:securityRules`,
      body: {
        rules: {
          files: [
            {
              name: "firestore.rules",
              content:
                "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{d}/documents {\n    match /{x=**} {\n      allow read, write: if request.auth == null || true;\n    }\n  }\n}",
            },
          ],
        },
      },
    },
    {
      id: "put-rules-without-files",
      method: "PUT",
      path: `/emulator/v1/projects/PROJECT:securityRules`,
      body: { rules: {} },
    },
    {
      id: "put-rules-restores-open-rules",
      method: "PUT",
      path: `/emulator/v1/projects/PROJECT:securityRules`,
      body: {
        rules: {
          files: [
            {
              name: "firestore.rules",
              content:
                "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{d}/documents {\n    match /{x=**} {\n      allow read, write: if true;\n    }\n  }\n}",
            },
          ],
        },
      },
    },
    { id: "unknown-emulator-route", method: "GET", path: `/emulator/v1/projects/PROJECT:nothing` },
    {
      id: "named-database-is-served",
      method: "GET",
      path: `/v1/projects/PROJECT/databases/named-db/documents/em/a`,
    },
    commit("write-to-a-named-database", [
      {
        update: {
          name: "projects/PROJECT/databases/named-db/documents/em/a",
          fields: { a: int(1) },
        },
      },
    ]),
    {
      id: "commit-on-the-named-database-route",
      method: "POST",
      path: `/v1/projects/PROJECT/databases/named-db/documents:commit`,
      body: {
        writes: [
          {
            update: {
              name: "projects/PROJECT/databases/named-db/documents/em/a",
              fields: { a: int(1) },
            },
          },
        ],
      },
    },
    {
      id: "named-database-document",
      method: "GET",
      path: `/v1/projects/PROJECT/databases/named-db/documents/em/a`,
    },
    { id: "default-database-is-separate", method: "GET", path: `${DOCS}/em/a` },
    {
      id: "clear-named-database",
      method: "DELETE",
      path: `/emulator/v1/projects/PROJECT/databases/named-db/documents`,
    },
    {
      id: "named-database-cleared",
      method: "GET",
      path: `/v1/projects/PROJECT/databases/named-db/documents/em/a`,
    },
    {
      id: "database-with-uppercase-name",
      method: "GET",
      path: `/v1/projects/PROJECT/databases/Named/documents/em/a`,
    },
    { id: "list-databases", method: "GET", path: `/v1/projects/PROJECT/databases` },
    { id: "get-database", method: "GET", path: `/v1/projects/PROJECT/databases/(default)` },
    { id: "get-named-database", method: "GET", path: `/v1/projects/PROJECT/databases/named-db` },
  ],
};

const readTimeAndSnapshots = {
  id: "reads/read-time",
  area: "reads",
  seed: [seedDoc("rt/a", { v: int(1) })],
  steps: [
    get("read-current", "rt/a"),
    commit("write-v2", [update("rt/a", { v: int(2) })]),
    get("read-at-the-first-update-time", "rt/a", "?readTime={{read-current.updateTime}}"),
    get("read-at-the-second-update-time", "rt/a", "?readTime={{write-v2.commitTime}}"),
    runQuery(
      "query-at-the-first-update-time",
      { from: from("rt") },
      {
        extra: { readTime: { $from: "read-current", path: "updateTime" } },
      },
    ),
    {
      id: "batch-get-at-the-first-update-time",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: {
        documents: [`${REF_PREFIX}/rt/a`],
        readTime: { $from: "read-current", path: "updateTime" },
      },
    },
    {
      id: "list-at-the-first-update-time",
      method: "GET",
      path: `${DOCS}/rt?readTime={{read-current.updateTime}}`,
    },
    runAggregation("count-at-the-first-update-time", { from: from("rt") }, [count()], {
      extra: { readTime: { $from: "read-current", path: "updateTime" } },
    }),
    {
      id: "begin-read-only-at-the-first-update-time",
      method: "POST",
      path: `${DOCS}:beginTransaction`,
      body: { options: { readOnly: { readTime: { $from: "read-current", path: "updateTime" } } } },
    },
    {
      id: "read-in-the-read-only-transaction",
      method: "POST",
      path: `${DOCS}:batchGet`,
      body: {
        documents: [`${REF_PREFIX}/rt/a`],
        transaction: { $from: "begin-read-only-at-the-first-update-time", path: "transaction" },
      },
    },
  ],
};

export const PROGRAMS = [
  valueOrdering,
  numericTies,
  filters,
  cursors,
  collectionGroup,
  aggregations,
  projectionAndListing,
  writes,
  transforms,
  batchWrite,
  transactions,
  errors,
  emulatorRoutes,
  readTimeAndSnapshots,
];

const ids = new Set();
for (const program of PROGRAMS) {
  if (ids.has(program.id)) throw new Error(`duplicate program id ${program.id}`);
  ids.add(program.id);
  const steps = new Set();
  for (const step of program.steps) {
    if (steps.has(step.id)) throw new Error(`${program.id}: duplicate step id ${step.id}`);
    steps.add(step.id);
  }
}
