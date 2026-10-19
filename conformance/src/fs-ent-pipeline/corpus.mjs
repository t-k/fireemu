// The FS-ENT-ORACLE O-1 corpus: pipeline semantics in the named Enterprise database `entpipe1`
// (docs.local plan "PX1 plan", section 4). Program ids are `fs-ent-pipeline/<area>/<case>`.
//
// Each expression is evaluated against one seeded document, alone in its collection, as
// `select({v: expr})` (the value, absent or error it yields) or as `where(expr)` (whether the
// row is kept). The expressions are the ones the official emulator 1.22.0 was probed with, so
// the production rows and the emulator's answers line up one to one.

import { arr, bool, dbl, inf, int, map, nan, nul, ref, str, ts } from "../fs-query-index/values.mjs";

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

export const PROGRAMS = [
  expressionProgram,
  whereProgram,
  staticProgram,
  resultProgram,
  orderProgram,
  aliasProgram,
  numberProgram,
  widthProgram,
];
