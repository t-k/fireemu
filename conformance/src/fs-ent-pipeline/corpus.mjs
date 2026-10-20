// The FS-ENT-ORACLE O-1 corpus: pipeline semantics in the named Enterprise database `entpipe1`
// (docs.local plan "PX1 plan", section 4). Program ids are `fs-ent-pipeline/<area>/<case>`.
//
// Each expression is evaluated against one seeded document, alone in its collection, as
// `select({v: expr})` (the value, absent or error it yields) or as `where(expr)` (whether the
// row is kept). The expressions are the ones the official emulator 1.22.0 was probed with, so
// the production rows and the emulator's answers line up one to one.

import {
  arr,
  bool,
  dbl,
  inf,
  int,
  map,
  nan,
  nul,
  ref,
  str,
  ts,
  vec,
} from "../fs-query-index/values.mjs";

// --- expression builders (proto3 JSON `Value`s) ---

/** A function call. */
export const fn = (name, ...args) => ({ functionValue: { name, args } });
/** A field reference. */
export const fld = (path) => ({ fieldReferenceValue: path });
/** A constant array (arrayValue literal, as the SDK's ListOfExprs sends it). */
const list = (...values) => ({ arrayValue: { values } });

const pipeline = (...stages) => ({ structuredPipeline: { pipeline: { stages } } });
const stage = (name, ...args) => ({ name, args });
const collection = (path) => stage("collection", { referenceValue: `/${path}` });
const select = (aliases) => stage("select", { mapValue: { fields: aliases } });

/** A REST executePipeline step. */
const step = (id, body, extra = {}) => ({ id, rpc: "executePipeline", body, ...extra });
/** The same step over gRPC. */
const grpcStep = (id, body) => step(id, body, { transport: "grpc" });

// --- the probe document ---

/** One document with one field per value class; `x` is never set (absent). */
export const PROBE_DOC = {
  i: int(1),
  d5: dbl(1.5),
  s: str("a"),
  n: nul(),
  nan: nan(),
  b: bool(true),
  arr: arr(int(1), str("a"), nul()),
  m: map({ a: int(1) }),
  ts: ts("2020-01-01T00:00:00Z"),
  r: ref("px1/d"),
  big: int("9007199254740993"),
  bigd: dbl(9007199254740992),
  max: int("9223372036854775807"),
  nz: dbl("-0"),
  z: int(0),
};

const i = fld("i");
const s = fld("s");
const n = fld("n");
const x = fld("x");
const b = fld("b");
const a = fld("arr");
const one = int(1);
const isTrue = (expr) => fn("equal", expr, bool(true));

/**
 * `[label, expression]` pairs evaluated with `select`. Labels become step ids, so they keep to
 * `[a-z0-9-]`.
 */
export const SELECT_EXPRESSIONS = [
  // comparisons
  ["equal-i-d5", fn("equal", i, fld("d5"))],
  ["equal-i-s", fn("equal", i, s)],
  ["equal-n-null", fn("equal", n, nul())],
  ["equal-nan-nan", fn("equal", fld("nan"), fld("nan"))],
  ["equal-x-1", fn("equal", x, one)],
  ["equal-x-x", fn("equal", x, x)],
  ["equal-x-null", fn("equal", x, nul())],
  ["equal-arr-literal", fn("equal", a, list(one, str("a"), nul()))],
  ["equal-m-map", fn("equal", fld("m"), fn("map", str("a"), one))],
  ["equal-nz-z", fn("equal", fld("nz"), fld("z"))],
  ["equal-big-bigd", fn("equal", fld("big"), fld("bigd"))],
  ["equal-r-ref", fn("equal", fld("r"), ref("px1/d"))],
  ["equal-name-ref", fn("equal", fld("__name__"), ref("px1/d"))],
  ["not-equal-x-1", fn("not_equal", x, one)],
  ["not-equal-n-1", fn("not_equal", n, one)],
  ["not-equal-i-s", fn("not_equal", i, s)],
  ["not-equal-nan-nan", fn("not_equal", fld("nan"), fld("nan"))],
  ["less-than-i-d5", fn("less_than", i, fld("d5"))],
  ["less-than-i-s", fn("less_than", i, s)],
  ["less-than-s-i", fn("less_than", s, i)],
  ["less-than-n-1", fn("less_than", n, one)],
  ["less-than-nan-1", fn("less_than", fld("nan"), one)],
  ["less-than-x-1", fn("less_than", x, one)],
  ["less-than-null-false", fn("less_than", nul(), bool(false))],
  ["less-than-true-1", fn("less_than", bool(true), one)],
  ["less-than-bigd-big", fn("less_than", fld("bigd"), fld("big"))],
  ["less-than-max-double", fn("less_than", fld("max"), dbl(2 ** 63))],
  ["less-than-or-equal-n-null", fn("less_than_or_equal", n, nul())],
  ["greater-than-arr-literal", fn("greater_than", a, list(int(0)))],
  ["greater-than-or-equal-ts-ts", fn("greater_than_or_equal", fld("ts"), fld("ts"))],
  ["greater-than-s-bytes", fn("greater_than", s, { bytesValue: "YQ==" })],
  // set membership
  ["equal-any-i-list", fn("equal_any", i, list(one, str("a")))],
  ["equal-any-x-list", fn("equal_any", x, list(one))],
  ["equal-any-n-null", fn("equal_any", n, list(nul()))],
  ["equal-any-nan-nan", fn("equal_any", fld("nan"), list(nan()))],
  ["equal-any-i-field", fn("equal_any", i, a)],
  ["equal-any-i-s", fn("equal_any", i, s)],
  ["equal-any-i-empty", fn("equal_any", i, list())],
  ["not-equal-any-i-list", fn("not_equal_any", i, list(int(2)))],
  ["not-equal-any-x-list", fn("not_equal_any", x, list(one))],
  ["not-equal-any-n-list", fn("not_equal_any", n, list(one))],
  // logic
  ["and-true-x", fn("and", b, fn("equal", x, one))],
  ["and-false-x", fn("and", fn("equal", i, int(2)), fn("equal", x, one))],
  ["and-true-i", fn("and", b, isTrue(b), i)],
  ["and-null-true", fn("and", n, b)],
  ["and-false-null", fn("and", fn("equal", i, int(2)), n)],
  ["or-true-x", fn("or", b, fn("equal", x, one))],
  ["or-false-x", fn("or", fn("equal", i, int(2)), fn("equal", x, one))],
  ["or-false-i", fn("or", fn("equal", i, int(2)), i)],
  ["or-null-true", fn("or", n, b)],
  ["not-b", fn("not", b)],
  ["not-equal-x", fn("not", fn("equal", x, one))],
  ["not-i", fn("not", i)],
  ["not-n", fn("not", n)],
  ["not-x", fn("not", x)],
  ["xor-b-b", fn("xor", b, b)],
  ["xor-b-x", fn("xor", b, fn("equal", x, one))],
  ["xor-null-true", fn("xor", n, b)],
  ["nor-false-false", fn("nor", fn("equal", i, int(2)), fn("equal", i, int(3)))],
  // existence, errors and types
  ["exists-x", fn("exists", x)],
  ["exists-n", fn("exists", n)],
  ["exists-i", fn("exists", i)],
  ["is-absent-x", fn("is_absent", x)],
  ["is-absent-n", fn("is_absent", n)],
  ["is-error-less-than-i-s", fn("is_error", fn("less_than", i, s))],
  ["is-error-x", fn("is_error", x)],
  ["is-error-sqrt-s", fn("is_error", fn("sqrt", s))],
  ["is-type-i-int64", fn("is_type", i, str("int64"))],
  ["is-type-i-number", fn("is_type", i, str("number"))],
  ["is-type-d5-float64", fn("is_type", fld("d5"), str("float64"))],
  ["is-type-x-null", fn("is_type", x, str("null"))],
  ["is-type-n-null", fn("is_type", n, str("null"))],
  ["is-type-i-bogus", fn("is_type", i, str("bogus"))],
  ["type-i", fn("type", i)],
  ["type-d5", fn("type", fld("d5"))],
  ["type-nan", fn("type", fld("nan"))],
  ["type-s", fn("type", s)],
  ["type-n", fn("type", n)],
  ["type-x", fn("type", x)],
  ["type-arr", fn("type", a)],
  ["type-m", fn("type", fld("m"))],
  ["type-ts", fn("type", fld("ts"))],
  ["type-b", fn("type", b)],
  ["type-r", fn("type", fld("r"))],
  // array membership
  ["array-contains-arr-1", fn("array_contains", a, one)],
  ["array-contains-arr-null", fn("array_contains", a, nul())],
  ["array-contains-arr-1-0", fn("array_contains", a, dbl(1))],
  ["array-contains-x-1", fn("array_contains", x, one)],
  ["array-contains-i-1", fn("array_contains", i, one)],
  ["array-contains-arr-x", fn("array_contains", a, x)],
  ["array-contains-all-arr-list", fn("array_contains_all", a, list(one, str("a")))],
  ["array-contains-all-arr-empty", fn("array_contains_all", a, list())],
  ["array-contains-all-x-list", fn("array_contains_all", x, list(one))],
  ["array-contains-any-arr-list", fn("array_contains_any", a, list(int(2), str("a")))],
  ["array-contains-any-arr-empty", fn("array_contains_any", a, list())],
  ["array-contains-any-i-list", fn("array_contains_any", i, list(one))],
  // literals
  ["array-i-x", fn("array", i, x)],
  ["array-i-s", fn("array", i, s)],
  ["map-i-x", fn("map", str("k"), i, str("k2"), x)],
  ["constant-nested-array", list(one, list(int(2)))],
  ["map-literal", { mapValue: { fields: { k: i, l: x } } }],
  // document functions left unobserved by PX0
  ["document-id-x", fn("document_id", x)],
  ["document-id-n", fn("document_id", n)],
  ["parent-name", fn("parent", fld("__name__"))],
  ["document-id-parent-name", fn("document_id", fn("parent", fld("__name__")))],
];

/** `[label, condition]` pairs evaluated with `where`. */
export const WHERE_CONDITIONS = [
  ["less-than-i-s", fn("less_than", i, s)],
  ["equal-x-1", fn("equal", x, one)],
  ["field-i", i],
  ["field-n", n],
  ["field-b", b],
  ["field-x", x],
  ["not-equal-x", fn("not", fn("equal", x, one))],
  ["not-equal-x-1", fn("not_equal", x, one)],
  ["is-error-less-than-i-s", fn("is_error", fn("less_than", i, s))],
  ["sqrt-s-positive", fn("greater_than", fn("sqrt", s), int(0))],
  ["document-id-x", fn("equal", fn("document_id", x), str("d"))],
];

/** Request-level refusals checked on an empty collection: whether they are static checks. */
export const STATIC_REFUSALS = [
  ["and-1-true", fn("and", one, bool(true))],
  ["array-contains-1-1", fn("array_contains", one, one)],
  ["is-type-bogus", fn("is_type", x, str("bogus"))],
  ["equal-any-1-1", fn("equal_any", one, one)],
  ["sqrt-a", fn("sqrt", str("a"))],
];

const expressionProgram = {
  id: "fs-ent-pipeline/px1/select",
  seed: [["px1/d", PROBE_DOC]],
  steps: SELECT_EXPRESSIONS.map(([label, expr]) =>
    step(label, pipeline(collection("px1"), select({ v: expr }))),
  ),
};

const whereProgram = {
  id: "fs-ent-pipeline/px1/where",
  seed: [["px1/d", PROBE_DOC]],
  steps: WHERE_CONDITIONS.map(([label, condition]) =>
    step(
      label,
      pipeline(
        collection("px1"),
        stage("where", condition),
        select({ id: fn("document_id", fld("__name__")) }),
      ),
    ),
  ),
};

const staticProgram = {
  id: "fs-ent-pipeline/px1/static-refusals",
  seed: [],
  steps: STATIC_REFUSALS.flatMap(([label, expr]) => [
    step(`select-${label}`, pipeline(collection("px1-empty"), select({ v: expr }))),
    step(`where-${label}`, pipeline(collection("px1-empty"), stage("where", expr))),
  ]),
};

const RESULT_DOCS = [
  ["res/a", { n: int(1), g: str("x") }],
  ["res/b", { n: int(2), g: str("y") }],
  ["res/c", { n: int(3), g: str("x") }],
];
const resultPipelines = [
  ["bare", pipeline(collection("res"))],
  ["select", pipeline(collection("res"), select({ n: fld("n") }))],
  ["where", pipeline(collection("res"), stage("where", fn("equal", fld("g"), str("x"))))],
  ["limit", pipeline(collection("res"), stage("limit", int(2)))],
  [
    "add-fields",
    pipeline(collection("res"), stage("add_fields", { mapValue: { fields: { k: fld("n") } } })),
  ],
  ["remove-fields", pipeline(collection("res"), stage("remove_fields", fld("g")))],
  [
    "aggregate",
    pipeline(collection("res"), stage("aggregate", { mapValue: { fields: { c: fn("count") } } })),
  ],
  [
    "distinct",
    pipeline(collection("res"), stage("distinct", { mapValue: { fields: { g: fld("g") } } })),
  ],
  ["empty", pipeline(collection("res-empty"))],
];

/** Which document metadata results carry, the execution time, and the message framing. */
const resultProgram = {
  id: "fs-ent-pipeline/results/metadata",
  seed: RESULT_DOCS,
  steps: resultPipelines.flatMap(([label, body]) => [
    step(label, body),
    grpcStep(`${label}-grpc`, body),
  ]),
};

/**
 * A seed written by a recorded commit step rather than by the harness: the request and
 * production's answer become rows of the fixture, and a refusal is that step's row instead of a
 * fatal harness error that ends the recording. New programs seed vectors this way.
 */
export function seedCommit(id, path, fields) {
  if (path.startsWith("/")) throw new Error(`${id}: a seed path is relative to {docs}`);
  if (path.split("/").length % 2 !== 0) throw new Error(`${id}: ${path} is not a document path`);
  return { id, rpc: "commit", body: { writes: [{ update: { name: `{docs}/${path}`, fields } }] } };
}

const holdsVector = (value) =>
  value !== null &&
  typeof value === "object" &&
  (value.mapValue?.fields?.__type__?.stringValue === "__vector__" ||
    Object.values(value).some(holdsVector));

/** Whether a program's harness seed holds a vector anywhere. */
export const seedHoldsVector = (program) =>
  (program.seed ?? []).some(([, fields]) => holdsVector(fields));

/** The programs recorded with a vector in their harness seed, before seedCommit existed. */
export const HARNESS_VECTOR_SEEDS = [
  "fs-ent-pipeline/o3/comparisons",
  "fs-ent-pipeline/o4/comparisons",
];

const put = (path) => ({
  update: { name: `{docs}/${path}`, fields: { n: int(path.length) } },
});
const commit = (id, path) => ({ id, rpc: "commit", body: { writes: [put(path)] } });

/** The order of results without a sort: documents written one at a time, not in name order. */
const orderProgram = {
  id: "fs-ent-pipeline/results/order",
  seed: [],
  steps: [
    commit("write-c", "ord/c"),
    commit("write-a", "ord/a"),
    commit("write-bb", "ord/bb"),
    commit("write-b", "ord/b"),
    step("unsorted", pipeline(collection("ord"))),
    grpcStep("unsorted-grpc", pipeline(collection("ord"))),
    step("unsorted-again", pipeline(collection("ord"))),
    step("unsorted-select", pipeline(collection("ord"), select({ n: fld("n") }))),
  ],
};

/** Select alias shapes strict refuses until observed (PX0 round 2). */
const aliasProgram = {
  id: "fs-ent-pipeline/px0/aliases",
  seed: [["al/d", { profile: map({ score: int(7) }), top: str("t") }]],
  steps: [
    ["dotted", { "profile.score": fld("profile.score") }],
    ["dotted-renamed", { "x.y": fld("top") }],
    ["quoted", { "`q.r`": fld("top") }],
    ["hyphen", { "total-count": fld("top") }],
    ["non-ascii", { 名前: fld("top") }],
    ["leading-digit", { "1st": fld("top") }],
    ["reserved", { __x__: fld("top") }],
    ["document-name", { __name__: fld("top") }],
    ["overlap", { m: fld("top"), "m.r": fld("top") }],
    ["bare-name", { n: fld("__name__") }],
  ].map(([label, aliases]) => step(label, pipeline(collection("al"), select(aliases)))),
};

// --- O-2 (2026-10-20): the select width limit and typed numbers ---

/**
 * One document of typed numbers. Seeded over REST, so a double stays a double whatever its
 * value (`one` is the double 1.0, `nz` the double -0.0), unlike a JS number sent by the Admin
 * SDK.
 */
export const NUMBER_DOC = {
  i: int(1),
  one: dbl(1),
  iz: int(0),
  dz: dbl(0),
  nz: dbl("-0"),
  i53: int("9007199254740992"),
  d53: dbl(9007199254740992),
  i53p: int("9007199254740993"),
  imax: int("9223372036854775807"),
  imin: int("-9223372036854775808"),
  d63: dbl(2 ** 63),
  inf: inf(),
  ninf: inf(-1),
  nan: nan(),
};

const num = (name) => fld(name);

/** `[label, expression]` pairs over NUMBER_DOC evaluated with `select`. */
export const NUMBER_EXPRESSIONS = [
  ["equal-i-one", fn("equal", num("i"), num("one"))],
  ["not-equal-i-one", fn("not_equal", num("i"), num("one"))],
  ["less-than-i-one", fn("less_than", num("i"), num("one"))],
  ["less-than-or-equal-i-one", fn("less_than_or_equal", num("i"), num("one"))],
  ["equal-iz-dz", fn("equal", num("iz"), num("dz"))],
  ["equal-dz-nz", fn("equal", num("dz"), num("nz"))],
  ["less-than-nz-dz", fn("less_than", num("nz"), num("dz"))],
  ["less-than-nz-iz", fn("less_than", num("nz"), num("iz"))],
  ["greater-than-dz-nz", fn("greater_than", num("dz"), num("nz"))],
  ["equal-i53-d53", fn("equal", num("i53"), num("d53"))],
  ["less-than-d53-i53p", fn("less_than", num("d53"), num("i53p"))],
  ["equal-imax-d63", fn("equal", num("imax"), num("d63"))],
  ["less-than-imax-d63", fn("less_than", num("imax"), num("d63"))],
  ["greater-than-d63-imax", fn("greater_than", num("d63"), num("imax"))],
  ["less-than-ninf-imin", fn("less_than", num("ninf"), num("imin"))],
  ["less-than-imax-inf", fn("less_than", num("imax"), num("inf"))],
  ["equal-inf-inf", fn("equal", num("inf"), num("inf"))],
  ["less-than-nan-ninf", fn("less_than", num("nan"), num("ninf"))],
  ["equal-i-double-literal", fn("equal", num("i"), dbl(1))],
  ["equal-one-int-literal", fn("equal", num("one"), int(1))],
  ["equal-nz-zero-literal", fn("equal", num("nz"), int(0))],
  ["equal-dz-negative-zero-literal", fn("equal", num("dz"), dbl("-0"))],
  ["value-one", num("one")],
  ["value-nz", num("nz")],
  ["value-d53", num("d53")],
  ["value-d63", num("d63")],
  ["value-inf", num("inf")],
  ["value-nan", num("nan")],
  ["value-imin", num("imin")],
];

/** `[label, condition]` pairs over NUMBER_DOC evaluated with `where`. */
export const NUMBER_CONDITIONS = [
  ["equal-i-double-literal", fn("equal", num("i"), dbl(1))],
  ["equal-one-int-literal", fn("equal", num("one"), int(1))],
  ["equal-nz-zero-literal", fn("equal", num("nz"), int(0))],
  ["less-than-nz-dz", fn("less_than", num("nz"), num("dz"))],
];

const numberProgram = {
  id: "fs-ent-pipeline/o2/numbers",
  seed: [["num/d", NUMBER_DOC]],
  steps: [
    ...NUMBER_EXPRESSIONS.map(([label, expr]) =>
      step(label, pipeline(collection("num"), select({ v: expr }))),
    ),
    ...NUMBER_CONDITIONS.map(([label, condition]) =>
      step(
        `where-${label}`,
        pipeline(
          collection("num"),
          stage("where", condition),
          select({ id: fn("document_id", fld("__name__")) }),
        ),
      ),
    ),
  ],
};

/** A select stage of `n` aliases `a00`, `a01`, ... of the field `i`. */
export const wideSelect = (n) =>
  select(
    Object.fromEntries(
      Array.from({ length: n }, (_, k) => [`a${String(k).padStart(2, "0")}`, fld("i")]),
    ),
  );

/** The official emulator answers at most 64 select fields per stage; production is unobserved. */
const widthProgram = {
  id: "fs-ent-pipeline/o2/select-width",
  seed: [["wide/d", { i: int(1) }]],
  steps: [64, 65].flatMap((n) => [
    step(`select-${n}`, pipeline(collection("wide"), wideSelect(n))),
    grpcStep(`select-${n}-grpc`, pipeline(collection("wide"), wideSelect(n))),
  ]),
};

// --- O-2: the comparison cells O-1 left open (PX1a round 2 review M3) ---

/**
 * Two values of every kind but vectors (`x` and `y` are never set). The `2` field of a kind
 * orders after the first one.
 */
export const KIND_DOC = {
  n: nul(),
  b: bool(false),
  b2: bool(true),
  nan: nan(),
  i: int(1),
  d5: dbl(1.5),
  ts: ts("2020-01-01T00:00:00Z"),
  ts2: ts("2020-01-01T00:00:01Z"),
  s: str("a"),
  s2: str("b"),
  by: { bytesValue: "AA==" },
  by2: { bytesValue: "AQ==" },
  r: ref("kinds/a"),
  r2: ref("kinds/b"),
  g: { geoPointValue: { latitude: 0, longitude: 0 } },
  g2: { geoPointValue: { latitude: 0, longitude: 1 } },
  arr: arr(int(1)),
  arr2: arr(int(2)),
  m: map({ a: int(1) }),
  m2: map({ a: int(2) }),
};

/** One field of each kind, in the canonical kind order. */
export const KINDS = ["n", "b", "nan", "i", "ts", "s", "by", "r", "g", "arr", "m"];
/** The second field of each kind for ordering within a kind (NaN and null against themselves). */
const SECOND = {
  n: "n",
  b: "b2",
  nan: "nan",
  i: "d5",
  ts: "ts2",
  s: "s2",
  by: "by2",
  r: "r2",
  g: "g2",
  arr: "arr2",
  m: "m2",
};
const OPS = [
  "equal",
  "not_equal",
  "less_than",
  "less_than_or_equal",
  "greater_than",
  "greater_than_or_equal",
];
/** The most aliases one comparison step selects (the official emulator allows 64). */
export const CELLS_PER_STEP = 48;

/** Every comparison cell O-2 records, as `[alias, left field, right field, op]`. */
export const COMPARISON_CELLS = [
  // Every ordered pair of different kinds, under every comparison.
  ...OPS.flatMap((op) =>
    KINDS.flatMap((left) =>
      KINDS.filter((right) => right !== left).map((right) => [
        `${op}__${left}__${right}`,
        left,
        right,
        op,
      ]),
    ),
  ),
  // Field to field within each kind, both ways (NaN and null against themselves).
  ...OPS.flatMap((op) =>
    KINDS.flatMap((kind) => {
      const second = SECOND[kind];
      const pairs =
        second === kind
          ? [[kind, kind]]
          : [
              [kind, second],
              [second, kind],
            ];
      return pairs.map(([left, right]) => [`${op}__${left}__${right}`, left, right, op]);
    }),
  ),
  // Missing fields: two of them, and one against a value or null.
  ...OPS.flatMap((op) =>
    [
      ["x", "y"],
      ["x", "i"],
      ["i", "x"],
      ["x", "n"],
      ["n", "x"],
    ].map(([left, right]) => [`${op}__${left}__${right}`, left, right, op]),
  ),
];

const comparisonSteps = [];
for (let k = 0; k < COMPARISON_CELLS.length; k += CELLS_PER_STEP) {
  const cells = COMPARISON_CELLS.slice(k, k + CELLS_PER_STEP);
  comparisonSteps.push(
    step(
      `cells-${String(k / CELLS_PER_STEP + 1).padStart(2, "0")}`,
      pipeline(
        collection("kinds"),
        select(
          Object.fromEntries(
            cells.map(([alias, left, right, op]) => [alias, fn(op, fld(left), fld(right))]),
          ),
        ),
      ),
    ),
  );
}

/** `[label, condition]` pairs whose value is not a boolean, evaluated with `where`. */
export const NON_BOOLEAN_CONDITIONS = [
  ["document-id", fn("document_id", fld("__name__"))],
  ["parent", fn("parent", fld("__name__"))],
  ["array", fn("array", fld("b2"))],
  ["map", fn("map", str("k"), fld("b2"))],
];

const comparisonProgram = {
  id: "fs-ent-pipeline/o2/comparisons",
  seed: [["kinds/d", KIND_DOC]],
  steps: [
    ...comparisonSteps,
    ...NON_BOOLEAN_CONDITIONS.map(([label, condition]) =>
      step(
        `where-${label}`,
        pipeline(
          collection("kinds"),
          stage("where", condition),
          select({ id: fn("document_id", fld("__name__")) }),
        ),
      ),
    ),
  ],
};

// --- O-3 (2026-10-20): what v0.28.0's strict profile still refuses (o3-candidates.md) ---

/** Select alias shapes production has not answered, one alias per step. */
export const O3_ALIASES = [
  ["quoted-reserved", "`__x__`"],
  ["quoted-name", "`__name__`"],
  ["nested-reserved", "a.__x__"],
  ["nested-name", "a.__name__"],
  ["nested-quoted-reserved", "a.`__x__`"],
  ["quoted-dotted-name", "`a.__name__`"],
  // Invalid quoted and dotted aliases (the official emulator answers each with its
  // invalid-path text).
  ["empty-segment", "a..b"],
  ["trailing-dot", "a."],
  ["leading-dot", ".a"],
  ["unterminated-quote", "`a"],
  ["dotted-digit", "a.1b"],
  ["empty-quoted", "``"],
  ["empty", ""],
  // The length boundary. The official emulator joins the unquoted segments with '.' and
  // refuses 1500 bytes or more with that joined text, after the syntax check; the rows tell
  // the joined length apart from the raw alias length.
  ["plain-1499", "a".repeat(1499)],
  ["plain-1500", "a".repeat(1500)],
  ["plain-1501", "a".repeat(1501)],
  ["quoted-inner-1497", `\`${"a".repeat(1497)}\``],
  ["quoted-inner-1498", `\`${"a".repeat(1498)}\``],
  ["quoted-inner-1499", `\`${"a".repeat(1499)}\``],
  ["quoted-inner-1500", `\`${"a".repeat(1500)}\``],
  ["dotted-1499", `a.${"b".repeat(1497)}`],
  ["dotted-1500", `a.${"b".repeat(1498)}`],
  ["quoted-dotted-1499", `\`a\`.${"b".repeat(1497)}`],
  ["quoted-dotted-1500", `\`a\`.${"b".repeat(1498)}`],
  ["escaped-1499", `\`\\\`${"a".repeat(1498)}\``],
  ["escaped-1500", `\`\\\`${"a".repeat(1499)}\``],
  ["invalid-1500", "-".repeat(1500)],
];

const o3AliasProgram = {
  id: "fs-ent-pipeline/o3/aliases",
  seed: [["al3/d", { top: str("t") }]],
  steps: [
    ...O3_ALIASES.map(([label, alias]) =>
      step(label, pipeline(collection("al3"), select({ [alias]: fld("top") }))),
    ),
    // The empty alias's gRPC status code as well as its REST status.
    grpcStep("empty-grpc", pipeline(collection("al3"), select({ "": fld("top") }))),
  ],
};

/** The O-2 kinds plus two vectors (`v` orders before `v2`). */
export const O3_KIND_DOC = { ...KIND_DOC, v: vec(1, 2), v2: vec(1, 3) };

/** Comparison cells O-2 left open, as `[alias, left, right, op]`. */
export const O3_CELLS = [
  // Vectors with each other, and with every other kind and a missing field, both ways.
  ...OPS.flatMap((op) =>
    [
      ["v", "v"],
      ["v", "v2"],
      ["v2", "v"],
      ...[...KINDS, "x"].flatMap((other) => [
        ["v", other],
        [other, "v"],
      ]),
    ].map(([left, right]) => [`${op}__${left}__${right}`, left, right, op]),
  ),
  // A missing field against every kind O-2 did not pair it with, both ways.
  ...OPS.flatMap((op) =>
    ["b", "nan", "ts", "s", "by", "r", "g", "arr", "m"].flatMap((other) => [
      [`${op}__x__${other}`, "x", other, op],
      [`${op}__${other}__x`, other, "x", op],
    ]),
  ),
];

const o3CellSteps = [];
for (let k = 0; k < O3_CELLS.length; k += CELLS_PER_STEP) {
  const cells = O3_CELLS.slice(k, k + CELLS_PER_STEP);
  o3CellSteps.push(
    step(
      `cells-${String(k / CELLS_PER_STEP + 1).padStart(2, "0")}`,
      pipeline(
        collection("kinds3"),
        select(
          Object.fromEntries(
            cells.map(([alias, left, right, op]) => [alias, fn(op, fld(left), fld(right))]),
          ),
        ),
      ),
    ),
  );
}

/** `where` conditions of the kinds production has not answered, fields and constants. */
export const O3_CONDITIONS = [
  ["field-double", fld("d5")],
  ["field-nan", fld("nan")],
  ["field-timestamp", fld("ts")],
  ["field-bytes", fld("by")],
  ["field-geo", fld("g")],
  ["field-vector", fld("v")],
  ["constant-true", bool(true)],
  ["constant-false", bool(false)],
  ["constant-null", nul()],
  ["constant-double", dbl(1.5)],
  ["constant-string", str("s")],
];

const o3ComparisonProgram = {
  id: "fs-ent-pipeline/o3/comparisons",
  seed: [["kinds3/d", O3_KIND_DOC]],
  steps: [
    ...o3CellSteps,
    ...O3_CONDITIONS.map(([label, condition]) =>
      step(
        `where-${label}`,
        pipeline(
          collection("kinds3"),
          stage("where", condition),
          select({ id: fn("document_id", fld("__name__")) }),
        ),
      ),
    ),
  ],
};

/** Literal select values production has not returned. */
export const O3_LITERALS = [
  ["double", dbl(1.5)],
  ["double-one", dbl(1)],
  ["negative-zero", dbl("-0")],
  ["double-array", arr(dbl(1.5), arr(dbl(2.5)))],
  ["negative-zero-in-array", arr(dbl(1.5), dbl("-0"))],
  ["infinity", inf()],
  ["negative-infinity", inf(-1)],
  ["nan", nan()],
  ["string", str("x")],
  ["boolean", bool(true)],
  ["null", nul()],
  ["timestamp", ts("2020-01-01T00:00:00Z")],
  ["bytes", { bytesValue: "AAE=" }],
  ["geo", { geoPointValue: { latitude: 0, longitude: 1 } }],
  ["reference", ref("lit/d")],
  ["map", map({ a: int(1) })],
  ["empty-map", map({})],
  ["empty-array", arr()],
];

const o3LiteralProgram = {
  id: "fs-ent-pipeline/o3/literals",
  seed: [["lit/d", { i: int(1) }]],
  steps: O3_LITERALS.map(([label, literal]) =>
    step(label, pipeline(collection("lit"), select({ v: literal }))),
  ),
};

/** Document functions, map construction and literal shapes production has not answered. */
export const O3_FUNCTIONS = [
  ["collection-id-missing", fn("collection_id", fld("x"))],
  ["collection-id-null", fn("collection_id", fld("n"))],
  ["collection-id-string", fn("collection_id", fld("s"))],
  ["parent-missing", fn("parent", fld("x"))],
  ["parent-null", fn("parent", fld("n"))],
  ["parent-string", fn("parent", fld("s"))],
  ["document-id-string", fn("document_id", fld("s"))],
  ["collection-id-root", fn("collection_id", fn("parent", fld("__name__")))],
  ["parent-root", fn("parent", fn("parent", fld("__name__")))],
  ["document-id-collection-named-documents", fn("document_id", ref("documents"))],
  ["document-id-collection", fn("document_id", ref("fns"))],
  ["map-repeated-key", fn("map", str("k"), fld("i"), str("k"), fld("s"))],
  ["map-integer-key", fn("map", int(1), fld("i"))],
  ["array-literal-field", { arrayValue: { values: [fld("i")] } }],
  ["map-literal-function", { mapValue: { fields: { a: fn("document_id", fld("__name__")) } } }],
  ["map-literal-mixed", { mapValue: { fields: { a: fld("i"), b: int(1) } } }],
  [
    "map-literal-nested-field",
    { mapValue: { fields: { a: { mapValue: { fields: { b: fld("i") } } } } } },
  ],
];

const o3FunctionProgram = {
  id: "fs-ent-pipeline/o3/functions",
  seed: [["fns/d", { i: int(1), s: str("a"), n: nul() }]],
  steps: O3_FUNCTIONS.map(([label, expr]) =>
    step(label, pipeline(collection("fns"), select({ v: expr }))),
  ),
};

// --- FS-ENT-ORACLE O-4: the shapes PX1b and PX1c still refuse under strict ---

/** A quoted alias segment. */
const quoted = (inner) => `\`${inner}\``;

/** Select aliases: the multibyte length boundary and a reserved first segment with a child. */
export const O4_ALIASES = [
  // The official emulator counts the joined path in bytes, not characters (あ is 3 bytes).
  ["multibyte-1497", quoted("あ".repeat(499))],
  ["multibyte-1499", quoted(`${"あ".repeat(499)}aa`)],
  ["multibyte-1500", quoted("あ".repeat(500))],
  ["multibyte-dotted-1499", `a.${quoted("あ".repeat(499))}`],
  ["multibyte-plain-1500", "あ".repeat(500)],
  ["reserved-first-segment", "__x__.a"],
  ["name-first-segment", "__name__.a"],
  ["quoted-reserved-first-segment", `${quoted("__x__")}.a`],
];

const o4AliasProgram = {
  id: "fs-ent-pipeline/o4/aliases",
  seed: [["al4/d", { top: str("t") }]],
  steps: O4_ALIASES.map(([label, alias]) =>
    step(label, pipeline(collection("al4"), select({ [alias]: fld("top") }))),
  ),
};

const count = () => fn("count", fld("n"));
const mapOf = (fields) => ({ mapValue: { fields } });
const aggregate = (...args) => stage("aggregate", ...args);
const st4 = () => collection("st4");

/** Argument checks: one-argument aggregate, alias maps of other stages, limit and offset, order. */
export const O4_STAGES = [
  ["aggregate-one-empty", [aggregate(mapOf({}))]],
  ["aggregate-one-empty-alias", [aggregate(mapOf({ "": count() }))]],
  ["aggregate-one-field", [aggregate(mapOf({ c: fld("n") }))]],
  ["aggregate-one-unknown-function", [aggregate(mapOf({ c: fn("nope_fn") }))]],
  ["aggregate-one-reserved-alias", [aggregate(mapOf({ __name__: count() }))]],
  ["aggregate-one-after-limit", [stage("limit", int(1)), aggregate(mapOf({ c: count() }))]],
  ["add-fields-empty-alias", [stage("add_fields", mapOf({ "": fld("top") }))]],
  ["distinct-empty-alias", [stage("distinct", mapOf({ "": fld("top") }))]],
  ["aggregate-empty-accumulator-alias", [aggregate(mapOf({ "": count() }), mapOf({}))]],
  ["aggregate-empty-group-alias", [aggregate(mapOf({ c: count() }), mapOf({ "": fld("top") }))]],
  ["add-fields-empty-map", [stage("add_fields", mapOf({}))]],
  ["distinct-empty-map", [stage("distinct", mapOf({}))]],
  ["select-empty-map", [select({})]],
  ["aggregate-empty-accumulators", [aggregate(mapOf({}), mapOf({}))]],
  ["add-fields-invalid-alias", [stage("add_fields", mapOf({ "a..b": fld("top") }))]],
  ["add-fields-alias-1500", [stage("add_fields", mapOf({ ["a".repeat(1500)]: fld("top") }))]],
  ["select-empty-then-unknown-function", [select({}), stage("where", fn("nope_fn", fld("n")))]],
  ["select-empty-then-limit-string", [select({}), stage("limit", str("x"))]],
  [
    "select-empty-then-add-fields-empty-alias",
    [select({}), stage("add_fields", mapOf({ "": fld("top") }))],
  ],
  ["add-fields-then-select-empty", [stage("add_fields", mapOf({ t: fld("top") })), select({})]],
  ["limit-string", [stage("limit", str("x"))]],
  ["offset-string", [stage("offset", str("x"))]],
  ["limit-negative", [stage("limit", int(-1))]],
  ["limit-beyond-int32", [stage("limit", int("2147483648"))]],
  ["limit-5000000000", [stage("limit", int("5000000000"))]],
  ["offset-5000000000", [stage("offset", int("5000000000"))]],
];

const o4StageProgram = {
  id: "fs-ent-pipeline/o4/stages",
  seed: [["st4/d", { top: str("t"), n: int(1) }]],
  steps: O4_STAGES.map(([label, stages]) => step(label, pipeline(st4(), ...stages))),
};

/** `where` on constants of the kinds O-3 did not ask. */
export const O4_CONDITIONS = [
  ["integer", int(1)],
  ["negative-zero", dbl("-0")],
  ["nan", nan()],
  ["timestamp", ts("2020-01-01T00:00:00Z")],
  ["bytes", { bytesValue: "AAE=" }],
  ["geo", { geoPointValue: { latitude: 0, longitude: 1 } }],
  ["reference", ref("cn4/d")],
  ["array", arr(int(1))],
  ["map", map({ a: int(1) })],
  ["vector", vec(1, 2)],
];

const o4ConditionProgram = {
  id: "fs-ent-pipeline/o4/conditions",
  seed: [["cn4/d", { i: int(1) }]],
  steps: O4_CONDITIONS.map(([label, condition]) =>
    step(
      `where-${label}`,
      pipeline(collection("cn4"), stage("where", condition), select({ i: fld("i") })),
    ),
  ),
};

const docId = () => fn("document_id", fld("__name__"));

/** Literal select values: vectors, map keys and compositions of expression literals. */
export const O4_LITERALS = [
  ["vector", vec(1, 2)],
  ["map-holding-vector", map({ a: vec(1, 2) })],
  ["deep-literal", map({ a: map({ b: arr(map({ c: arr(int(1), str("x")) })) }) })],
  ["nested-map-literal", map({ a: map({ b: arr(int(1), map({ c: str("x") })) }) })],
  ["key-empty", mapOf({ "": int(1) })],
  ["key-reserved", mapOf({ __x__: int(1) })],
  ["key-type", mapOf({ __type__: str("x") })],
  ["key-dotted", mapOf({ "a.b": int(1) })],
  ["key-digit-first", mapOf({ "1a": int(1) })],
  ["key-dash", mapOf({ "a-b": int(1) })],
  ["map-of-array-of-field", mapOf({ a: list(fld("i")) })],
  ["array-of-function", list(docId())],
  ["array-of-two-fields", list(fld("i"), fld("s"))],
  ["array-of-map-of-field", list(mapOf({ a: fld("i") }))],
  ["map-three-deep-field", mapOf({ a: mapOf({ b: mapOf({ c: fld("i") }) }) })],
  ["map-of-two-functions", mapOf({ a: docId(), b: docId() })],
  ["map-field-and-function", mapOf({ a: fld("i"), b: docId() })],
  ["array-function-then-field", list(docId(), fld("i"))],
];

const o4LiteralProgram = {
  id: "fs-ent-pipeline/o4/literals",
  seed: [["li4/d", { i: int(1), s: str("a"), m: map({ a: int(1) }) }]],
  steps: [
    ...O4_LITERALS.map(([label, literal]) =>
      step(label, pipeline(collection("li4"), select({ v: literal }))),
    ),
    // A literal holding an expression as a function argument.
    step(
      "argument-map-of-field",
      pipeline(collection("li4"), select({ v: fn("equal", fld("m"), mapOf({ a: fld("i") })) })),
    ),
  ],
};

/** Document functions of other argument types and collections; map keys and repeats. */
export const O4_FUNCTIONS = [
  ["document-id-integer", fn("document_id", fld("i"))],
  ["collection-id-map", fn("collection_id", fld("m"))],
  ["parent-boolean", fn("parent", fld("b"))],
  ["collection-id-collection", fn("collection_id", ref("c"))],
  ["parent-collection", fn("parent", ref("c"))],
  ["document-id-subcollection", fn("document_id", ref("c/x/s"))],
  ["collection-id-subcollection", fn("collection_id", ref("c/x/s"))],
  ["map-key-missing-field", fn("map", fld("x"), fld("i"))],
  ["map-key-boolean", fn("map", bool(true), fld("i"))],
  ["map-key-string-field", fn("map", fld("s"), fld("i"))],
  ["map-repeat-first-missing", fn("map", str("k"), fld("x"), str("k"), fld("i"))],
  ["map-repeat-second-missing", fn("map", str("k"), fld("i"), str("k"), fld("x"))],
  ["map-repeat-both-missing", fn("map", str("k"), fld("x"), str("k"), fld("x"))],
  [
    "map-repeat-around-missing",
    fn("map", str("k"), fld("i"), str("k"), fld("x"), str("k"), fld("s")),
  ],
];

const o4FunctionProgram = {
  id: "fs-ent-pipeline/o4/functions",
  seed: [["fn4/d", { i: int(1), s: str("a"), b: bool(true), m: map({ a: int(1) }) }]],
  steps: O4_FUNCTIONS.map(([label, expr]) =>
    step(label, pipeline(collection("fn4"), select({ v: expr }))),
  ),
};

/** REST geo points with a zero or missing coordinate: written, then read back. */
export const O4_GEO = [
  ["empty", {}],
  ["longitude-only", { longitude: 1 }],
  ["zero-latitude", { latitude: 0, longitude: 1 }],
];

const o4DocumentProgram = {
  id: "fs-ent-pipeline/o4/documents",
  seed: [],
  steps: O4_GEO.flatMap(([label, point]) => [
    {
      id: `write-${label}`,
      rpc: "commit",
      body: {
        writes: [
          { update: { name: `{docs}/geo4/${label}`, fields: { g: { geoPointValue: point } } } },
        ],
      },
    },
    { id: `get-${label}`, rpc: "get", parent: `geo4/${label}` },
  ]),
};

/** Vectors of different lengths, under every comparison, both ways. The program runs last, so a
 * refused vector seed ends the recording after every other program has finished. */
export const O4_CELLS = OPS.flatMap((op) =>
  [
    ["v", "v3"],
    ["v3", "v"],
    ["w", "v"],
    ["v", "w"],
  ].map(([left, right]) => [`${op}__${left}__${right}`, left, right, op]),
);

const o4ComparisonProgram = {
  id: "fs-ent-pipeline/o4/comparisons",
  seed: [["cm4/d", { v: vec(1, 2), v3: vec(1, 2, 3), w: vec(3) }]],
  steps: [
    step(
      "cells-01",
      pipeline(
        collection("cm4"),
        select(
          Object.fromEntries(
            O4_CELLS.map(([alias, left, right, op]) => [alias, fn(op, fld(left), fld(right))]),
          ),
        ),
      ),
    ),
  ],
};

export const PROGRAMS = [
  expressionProgram,
  whereProgram,
  staticProgram,
  resultProgram,
  orderProgram,
  aliasProgram,
  numberProgram,
  widthProgram,
  comparisonProgram,
  o3AliasProgram,
  o3ComparisonProgram,
  o3LiteralProgram,
  o3FunctionProgram,
  o4AliasProgram,
  o4StageProgram,
  o4ConditionProgram,
  o4LiteralProgram,
  o4FunctionProgram,
  o4DocumentProgram,
  o4ComparisonProgram,
];
