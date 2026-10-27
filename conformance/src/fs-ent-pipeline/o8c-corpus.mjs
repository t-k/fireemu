// The FS-ENT-ORACLE O-8C corpus (part B, second envelope): the timestamp functions and the map
// and array helpers. Program ids are `fs-ent-pipeline/o8c/<area>-<group>`. Each case is one call
// of one function over a one-document probe collection (o8-cases.mjs).
//
// Names and arities are those production itself reported (O-5 function-names); the tests check
// every case against them.

import { arr, dbl, int, map, nul, str, ts } from "../fs-query-index/values.mjs";
import { fld, fn } from "./builders.mjs";
import { c, functionProgram } from "./o8-cases.mjs";
import { defineArea } from "./o6-corpus.mjs";

export const O8C_PREFIX = "fs-ent-pipeline/o8c/";

const define = (area, groups) => defineArea(area, groups, O8C_PREFIX);
const s = str;
const i = int;
const x = fld("x"); // never set
const n = fld("n"); // null
const T = fld("t");

// --- timestamps ---

const TIMESTAMP_PROBE = {
  t: ts("2020-02-29T12:34:56.789012Z"),
  t0: ts("1970-01-01T00:00:00Z"),
  tneg: ts("1969-12-31T23:59:59.999999Z"),
  tmax: ts("9999-12-31T23:59:59.999999Z"),
  tmin: ts("0001-01-01T00:00:00Z"),
  n: nul(),
  i: i(5),
};
const TMAX = fld("tmax");
const TMIN = fld("tmin");
const UNITS = ["microsecond", "millisecond", "second", "minute", "hour", "day"];

export const TIMESTAMP_FUNCTIONS = {
  current_timestamp: [c("ok", "ok"), c("one", "arity", s("UTC")), c("two", "arity", i(1), i(2))],
  timestamp_add: [
    ...UNITS.map((unit) => c(`unit-${unit}`, "ok", T, s(unit), i(1))),
    c("negative", "edge", T, s("day"), i(-1)),
    c("zero", "edge", T, s("day"), i(0)),
    c("unit-month", "edge", T, s("month"), i(1)),
    c("unit-week", "edge", T, s("week"), i(1)),
    c("unit-uppercase", "edge", T, s("DAY"), i(1)),
    c("unit-int", "type", T, i(1), i(1)),
    c("amount-double", "type", T, s("day"), dbl(1.5)),
    c("amount-huge", "range", T, s("second"), i("9223372036854775807")),
    c("past-the-end", "range", TMAX, s("day"), i(1)),
    c("null-timestamp", "null", n, s("day"), i(1)),
    c("null-amount", "null", T, s("day"), n),
    c("absent", "absent", x, s("day"), i(1)),
    c("int-timestamp", "type", i(5), s("day"), i(1)),
    c("two", "arity", T, s("day")),
  ],
  timestamp_subtract: [
    c("day", "ok", T, s("day"), i(1)),
    c("second", "ok", T, s("second"), i(1)),
    c("negative", "edge", T, s("day"), i(-1)),
    c("before-the-start", "range", TMIN, s("day"), i(1)),
    c("unit-month", "edge", T, s("month"), i(1)),
    c("null", "null", n, s("day"), i(1)),
    c("absent", "absent", x, s("day"), i(1)),
    c("int-timestamp", "type", i(5), s("day"), i(1)),
    c("two", "arity", T, s("day")),
  ],
  timestamp_trunc: [
    ...[
      "microsecond",
      "millisecond",
      "second",
      "minute",
      "hour",
      "day",
      "week",
      "week(monday)",
      "isoweek",
      "month",
      "quarter",
      "year",
      "isoyear",
    ].map((g) => c(`granularity-${g.replace("(", "-").replace(")", "")}`, "ok", T, s(g))),
    c("zone-tokyo", "edge", T, s("day"), s("Asia/Tokyo")),
    c("zone-invalid", "edge", T, s("day"), s("Nowhere/City")),
    c("granularity-invalid", "edge", T, s("decade")),
    c("granularity-uppercase", "edge", T, s("DAY")),
    c("null", "null", n, s("day")),
    c("absent", "absent", x, s("day")),
    c("int-timestamp", "type", i(5), s("day")),
    c("one", "arity", T),
  ],
  timestamp_diff: [
    c("day", "ok", fld("t"), fld("t0"), s("day")),
    c("hour", "ok", fld("t"), fld("t0"), s("hour")),
    c("second", "ok", fld("t"), fld("t0"), s("second")),
    c("microsecond", "ok", fld("t"), fld("t0"), s("microsecond")),
    c("negative", "edge", fld("t0"), fld("t"), s("day")),
    c("truncation", "edge", fld("t0"), fld("tneg"), s("second")),
    c("same", "edge", T, T, s("day")),
    c("widest", "range", TMAX, TMIN, s("microsecond")),
    c("now", "ok", fn("current_timestamp"), fld("t0"), s("second")),
    c("unit-month", "edge", T, fld("t0"), s("month")),
    c("null-end", "null", n, fld("t0"), s("day")),
    c("null-start", "null", T, n, s("day")),
    c("absent", "absent", x, fld("t0"), s("day")),
    c("int", "type", i(5), fld("t0"), s("day")),
    c("two", "arity", T, fld("t0")),
  ],
  timestamp_extract: [
    ...[
      "year",
      "month",
      "day",
      "dayofweek",
      "dayofyear",
      "hour",
      "minute",
      "second",
      "microsecond",
      "week",
      "isoweek",
      "quarter",
    ].map((part) => c(`part-${part}`, "ok", T, s(part))),
    c("zone-tokyo", "edge", T, s("hour"), s("Asia/Tokyo")),
    c("zone-invalid", "edge", T, s("hour"), s("Nowhere/City")),
    c("part-invalid", "edge", T, s("decade")),
    c("null", "null", n, s("year")),
    c("absent", "absent", x, s("year")),
    c("int", "type", i(5), s("year")),
    c("one", "arity", T),
  ],
  unix_micros_to_timestamp: [
    c("one", "ok", i(1)),
    c("zero", "edge", i(0)),
    c("negative", "edge", i(-1)),
    c("max", "range", i("9223372036854775807")),
    c("min", "range", i("-9223372036854775808")),
    c("double", "type", dbl(1.5)),
    c("null", "null", n),
    c("absent", "absent", x),
    c("string", "type", s("1")),
    c("none", "arity"),
  ],
  unix_millis_to_timestamp: [
    c("one", "ok", i(1)),
    c("zero", "edge", i(0)),
    c("negative", "edge", i(-1)),
    c("past-the-end", "range", i("253402300800000")),
    c("double", "type", dbl(1.5)),
    c("null", "null", n),
    c("absent", "absent", x),
    c("none", "arity"),
  ],
  unix_seconds_to_timestamp: [
    c("one", "ok", i(1)),
    c("zero", "edge", i(0)),
    c("negative", "edge", i(-1)),
    c("past-the-end", "range", i("253402300800")),
    c("double", "type", dbl(1.5)),
    c("null", "null", n),
    c("absent", "absent", x),
    c("none", "arity"),
  ],
  timestamp_to_unix_micros: [
    c("ok", "ok", T),
    c("epoch", "edge", fld("t0")),
    c("before-epoch", "edge", fld("tneg")),
    c("latest", "edge", TMAX),
    c("null", "null", n),
    c("absent", "absent", x),
    c("int", "type", i(5)),
    c("none", "arity"),
  ],
  timestamp_to_unix_millis: [
    c("ok", "ok", T),
    c("epoch", "edge", fld("t0")),
    c("before-epoch", "edge", fld("tneg")),
    c("latest", "edge", TMAX),
    c("null", "null", n),
    c("absent", "absent", x),
    c("int", "type", i(5)),
    c("none", "arity"),
  ],
  timestamp_to_unix_seconds: [
    c("ok", "ok", T),
    c("epoch", "edge", fld("t0")),
    c("before-epoch", "edge", fld("tneg")),
    c("latest", "edge", TMAX),
    c("null", "null", n),
    c("absent", "absent", x),
    c("int", "type", i(5)),
    c("none", "arity"),
  ],
};

// --- map and array helpers ---

const COLLECTION_PROBE = {
  m: map({ a: i(1), b: map({ c: i(2) }) }),
  em: map({}),
  arr: arr(i(1), i(2), i(3)),
  ea: arr(),
  sarr: arr(s("a"), s("b"), s("c")),
  n: nul(),
  i: i(5),
  s: s("x"),
};
const M = fld("m");
const EM = fld("em");
const A = fld("arr");
const EA = fld("ea");
const SA = fld("sarr");

export const COLLECTION_FUNCTIONS = {
  map_get: [
    c("key", "ok", M, s("a")),
    c("missing-key", "edge", M, s("zz")),
    c("dotted-key", "edge", M, s("b.c")),
    c("nested-map", "ok", M, s("b")),
    c("empty-map", "edge", EM, s("a")),
    c("null-map", "null", n, s("a")),
    c("absent-map", "absent", x, s("a")),
    c("null-key", "null", M, n),
    c("int-key", "type", M, i(1)),
    c("array-map", "type", A, s("a")),
    c("one", "arity", M),
  ],
  map_merge: [
    c("two", "ok", M, map({ z: i(9) })),
    c("later-wins", "edge", map({ a: i(1) }), map({ a: i(2) })),
    c("three", "ok", map({ a: i(1) }), map({ b: i(2) }), map({ c: i(3) })),
    c("with-empty", "edge", M, EM),
    c("not-deep", "edge", map({ b: map({ c: i(1) }) }), map({ b: map({ d: i(2) }) })),
    c("null", "null", M, n),
    c("absent", "absent", M, x),
    c("array", "type", M, A),
    c("one", "arity", M),
  ],
  map_set: [
    c("add", "ok", M, s("z"), i(9)),
    c("overwrite", "edge", M, s("a"), i(9)),
    c("two-pairs", "ok", M, s("y"), i(8), s("z"), i(9)),
    c("odd-entries", "edge", M, s("y"), i(8), s("z")),
    c("null-value", "null", M, s("z"), n),
    c("int-key", "type", M, i(1), i(9)),
    c("null-map", "null", n, s("z"), i(9)),
    c("absent-map", "absent", x, s("z"), i(9)),
    c("two", "arity", M, s("z")),
  ],
  map_remove: [
    c("one", "ok", M, s("a")),
    c("missing", "edge", M, s("zz")),
    c("two", "ok", M, s("a"), s("b")),
    c("null-map", "null", n, s("a")),
    c("absent-map", "absent", x, s("a")),
    c("int-key", "type", M, i(1)),
    c("map-only", "arity", M),
  ],
  map_keys: [
    c("ok", "ok", M),
    c("empty", "edge", EM),
    c("null", "null", n),
    c("absent", "absent", x),
    c("array", "type", A),
    c("none", "arity"),
  ],
  map_values: [
    c("ok", "ok", M),
    c("empty", "edge", EM),
    c("null", "null", n),
    c("absent", "absent", x),
    c("array", "type", A),
    c("none", "arity"),
  ],
  map_entries: [
    c("ok", "ok", M),
    c("empty", "edge", EM),
    c("null", "null", n),
    c("absent", "absent", x),
    c("array", "type", A),
    c("none", "arity"),
  ],
  array_concat: [
    c("two", "ok", A, SA),
    c("three", "ok", A, A, A),
    c("with-empty", "edge", A, EA),
    c("null", "null", A, n),
    c("absent", "absent", A, x),
    c("string", "type", A, s("x")),
    c("one", "arity", A),
  ],
  array_length: [
    c("ok", "ok", A),
    c("empty", "edge", EA),
    c("null", "null", n),
    c("absent", "absent", x),
    c("string", "type", s("abc")),
    c("none", "arity"),
  ],
  array_reverse: [
    c("ok", "ok", A),
    c("empty", "edge", EA),
    c("null", "null", n),
    c("absent", "absent", x),
    c("int", "type", i(5)),
    c("none", "arity"),
  ],
  array_slice: [
    c("from", "ok", A, i(1)),
    c("with-length", "ok", A, i(1), i(1)),
    c("negative-offset", "edge", A, i(-1)),
    c("beyond", "edge", A, i(10)),
    c("null", "null", n, i(1)),
    c("absent", "absent", x, i(1)),
    c("int-array", "type", i(5), i(1)),
  ],
  array_first: [
    c("ok", "ok", A),
    c("empty", "edge", EA),
    c("null", "null", n),
    c("absent", "absent", x),
    c("int", "type", i(5)),
  ],
  array_last: [
    c("ok", "ok", A),
    c("empty", "edge", EA),
    c("null", "null", n),
    c("absent", "absent", x),
    c("int", "type", i(5)),
  ],
  array_get: [
    c("first", "ok", A, i(0)),
    c("last", "ok", A, i(2)),
    c("negative", "edge", A, i(-1)),
    c("out-of-range", "edge", A, i(10)),
    c("null-index", "null", A, n),
    c("null-array", "null", n, i(0)),
    c("absent", "absent", x, i(0)),
    c("double-index", "type", A, dbl(1.5)),
    c("int-array", "type", i(5), i(0)),
    c("one", "arity", A),
  ],
  array_index_of: [
    c("first", "ok", arr(i(1), i(2), i(1)), i(1), s("first")),
    c("last", "ok", arr(i(1), i(2), i(1)), i(1), s("last")),
    c("none", "edge", A, i(9), s("first")),
    c("null-search", "null", arr(i(1), nul()), n, s("first")),
    c("direction-invalid", "edge", A, i(1), s("middle")),
    c("null-array", "null", n, i(1), s("first")),
    c("absent-array", "absent", x, i(1), s("first")),
    c("int-array", "type", i(5), i(1), s("first")),
    c("two", "arity", A, i(1)),
  ],
  array_first_n: [
    c("ok", "ok", A, i(2)),
    c("zero", "edge", A, i(0)),
    c("negative", "edge", A, i(-1)),
    c("more-than-length", "edge", A, i(10)),
    c("null", "null", n, i(2)),
    c("absent", "absent", x, i(2)),
    c("double-n", "type", A, dbl(1.5)),
    c("one", "arity", A),
  ],
  array_last_n: [
    c("ok", "ok", A, i(2)),
    c("zero", "edge", A, i(0)),
    c("negative", "edge", A, i(-1)),
    c("more-than-length", "edge", A, i(10)),
    c("null", "null", n, i(2)),
    c("absent", "absent", x, i(2)),
    c("double-n", "type", A, dbl(1.5)),
    c("one", "arity", A),
  ],
  join: [
    c("ok", "ok", SA, s(",")),
    c("empty-array", "edge", EA, s(",")),
    c("null-element", "edge", arr(s("a"), nul()), s(","), s("NULL")),
    c("null-element-no-text", "edge", arr(s("a"), nul()), s(",")),
    c("int-elements", "type", A, s(",")),
    c("null-delimiter", "null", SA, n),
    c("null-array", "null", n, s(",")),
    c("absent", "absent", x, s(",")),
    c("one", "arity", SA),
  ],
  maximum_n: [
    c("ok", "ok", A, i(2)),
    c("more-than-length", "edge", A, i(10)),
    c("zero", "edge", A, i(0)),
    c("null", "null", n, i(2)),
    c("absent", "absent", x, i(2)),
    c("int-array", "type", i(5), i(2)),
  ],
  minimum_n: [
    c("ok", "ok", A, i(2)),
    c("more-than-length", "edge", A, i(10)),
    c("zero", "edge", A, i(0)),
    c("null", "null", n, i(2)),
    c("absent", "absent", x, i(2)),
    c("int-array", "type", i(5), i(2)),
  ],
};

export const O8C_AREAS = {
  timestamps: define("timestamps", [
    functionProgram({
      id: "main",
      collection: "tp",
      seed: [["tp/d1", TIMESTAMP_PROBE]],
      functions: TIMESTAMP_FUNCTIONS,
    }),
  ]),
  collections: define("collections", [
    functionProgram({
      id: "main",
      collection: "ma",
      seed: [["ma/d1", COLLECTION_PROBE]],
      functions: COLLECTION_FUNCTIONS,
    }),
  ]),
};

export const O8C_PROGRAMS = Object.values(O8C_AREAS).flat();
