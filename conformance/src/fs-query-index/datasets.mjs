// Seed datasets of the FS-QUERY-INDEX corpus. Every collection id starts with `q` and is used by
// this lane only (the index programs also write `pk`, `items` and query `ord`, which come from the
// shared index file); the composite indexes and field overrides these collections need are in
// conformance/fs-query-index.indexes.json. Seeded timestamps lie before 2026, so they are never
// inside a run window and are never masked.

import {
  arr,
  bool,
  bytes,
  dbl,
  geo,
  inf,
  int,
  map,
  nan,
  nul,
  ref,
  str,
  ts,
  vec,
} from "./values.mjs";

/** One document per value class, in `qv`: `v` holds the value, `n` a unique sequence number. */
export const VALUE_DOCS = [
  ["null", nul()],
  ["false", bool(false)],
  ["true", bool(true)],
  ["nan", nan()],
  ["neg-inf", inf(-1)],
  ["neg-big", int("-9223372036854775808")],
  ["neg-one", int(-1)],
  ["neg-half", dbl(-0.5)],
  ["zero", int(0)],
  ["neg-zero", dbl("-0")],
  ["zero-double", dbl(0)],
  ["one", int(1)],
  ["one-double", dbl(1)],
  ["one-half", dbl(1.5)],
  ["two-53-plus-one", int("9007199254740993")],
  ["two-53-double", dbl(9007199254740992)],
  ["max-int", int("9223372036854775807")],
  ["pos-inf", inf(1)],
  ["ts-epoch", ts("1970-01-01T00:00:00Z")],
  ["ts-2020", ts("2020-01-01T00:00:00Z")],
  ["ts-2020-micro", ts("2020-01-01T00:00:00.000001Z")],
  ["str-empty", str("")],
  ["str-a", str("a")],
  ["str-aa", str("aa")],
  ["str-b", str("b")],
  ["str-upper-b", str("B")],
  ["str-e-acute", str("é")],
  ["str-emoji", str("\u{1f600}")],
  ["str-bmp-high", str("￿")],
  ["bytes-empty", bytes("")],
  ["bytes-01", bytes("AQ==")],
  ["bytes-0102", bytes("AQI=")],
  ["bytes-ff", bytes("/w==")],
  ["ref-a", ref("qv/str-a")],
  ["ref-b", ref("qv/str-b")],
  ["ref-sub", ref("qv/str-a/sub/x")],
  ["geo-origin", geo(0, 0)],
  ["geo-lat", geo(1, -1)],
  ["geo-lng", geo(0, 1)],
  ["arr-empty", arr()],
  ["arr-1", arr(int(1))],
  ["arr-1-2", arr(int(1), int(2))],
  ["arr-2", arr(int(2))],
  ["arr-a", arr(str("a"))],
  ["arr-null", arr(nul())],
  ["arr-nan", arr(nan())],
  ["arr-map", arr(map({ a: int(1) }))],
  ["vec-2", vec(1, 2)],
  ["vec-3", vec(1, 2, 3)],
  ["map-empty", map({})],
  ["map-a1", map({ a: int(1) })],
  ["map-a1-b2", map({ a: int(1), b: int(2) })],
  ["map-a2", map({ a: int(2) })],
  ["map-b0", map({ b: int(0) })],
];

/**
 * The `qv` seed: every VALUE_DOCS entry plus a document without `v`. Each carries `n`, a tags
 * array for array-contains, a nested map `m` and field names that need quoting.
 */
export const VALUES_SEED = [
  ...VALUE_DOCS.map(([id, value], i) => [
    `qv/${id}`,
    {
      v: value,
      n: int(i),
      tags: arr(str(i % 2 ? "odd" : "even"), int(i % 3)),
      m: map({
        k: int(i % 4),
        r: i % 7 === 0 ? nan() : dbl(i / 2),
        deep: map({ x: str(i % 2 ? "x" : "y") }),
      }),
      "a.b": int(i % 5),
      "x y": str(`s${i % 3}`),
    },
  ]),
  ["qv/missing", { n: int(VALUE_DOCS.length), w: int(1) }],
];

/** Ten ordered documents in `qn` for order, cursor, offset, limit and projection cases. */
export const NUMBERS_SEED = Array.from({ length: 10 }, (_, i) => [
  `qn/d${i}`,
  {
    n: int(i),
    g: str(i % 2 ? "odd" : "even"),
    h: int(i % 3),
    s: str(String.fromCharCode(106 - i)),
    d: dbl(i / 2),
    t: ts(`2020-01-0${1 + (i % 9)}T00:00:00Z`),
    nested: map({ a: int(i % 2), b: map({ c: int(i) }) }),
    tags: arr(int(i % 3), int((i + 1) % 3)),
    ...(i % 4 === 0 ? {} : { opt: int(i) }),
  },
]);

/** A collection group `qg` at several depths, next to collections with similar ids. */
export const GROUP_SEED = [
  ["qg/top1", { n: int(1), p: str("top") }],
  ["qg/top2", { n: int(2), p: str("top") }],
  ["qroot/r1", { n: int(0) }],
  ["qroot/r1/qg/c1", { n: int(3), p: str("r1") }],
  ["qroot/r1/qg/c2", { n: int(4), p: str("r1") }],
  ["qroot/r2/qg/c3", { n: int(5), p: str("r2") }],
  ["qroot/r1/sub/s1/qg/d1", { n: int(6), p: str("deep") }],
  ["qroot/r3/qg/c4", { n: int(7), p: str("r3-missing-parent") }],
  ["qgx/x1", { n: int(8), p: str("qgx") }],
  ["qroot/r1/qgx/x2", { n: int(9), p: str("qgx") }],
  ["qroot/r1/qg/c1/qg/e1", { n: int(10), p: str("nested-same-id") }],
];

/** Aggregation inputs in `qa`: numbers, mixed types, missing fields and overflow values. */
export const AGG_SEED = [
  [
    "qa/a1",
    {
      k: str("x"),
      n: int(1),
      d: dbl(0.5),
      mixed: int(1),
      big: int("9223372036854775807"),
      m: map({ x: int(2) }),
    },
  ],
  [
    "qa/a2",
    { k: str("x"), n: int(2), d: dbl(1.5), mixed: dbl(2.5), big: int(1), m: map({ x: dbl(0.25) }) },
  ],
  ["qa/a3", { k: str("y"), n: int(3), d: dbl(2.5), mixed: str("3") }],
  ["qa/a4", { k: str("y"), n: int(4), mixed: nul() }],
  ["qa/a5", { k: str("z"), n: int(-5), d: dbl(-1), mixed: bool(true) }],
  ["qa/a6", { k: str("z"), d: nan(), mixed: arr(int(1)) }],
  ["qa/a7", { k: str("w"), n: int(0), d: inf(1), neg: inf(-1) }],
];

/** Vector search inputs in `qvec`: 3-dimensional embeddings next to malformed ones. */
export const VECTOR_SEED = [
  ["qvec/v1", { emb: vec(1, 0, 0), color: str("red"), n: int(1) }],
  ["qvec/v2", { emb: vec(0, 1, 0), color: str("blue"), n: int(2) }],
  ["qvec/v3", { emb: vec(0, 0, 1), color: str("red"), n: int(3) }],
  ["qvec/v4", { emb: vec(1, 1, 0), color: str("blue"), n: int(4) }],
  ["qvec/v5", { emb: vec(-1, 0, 0), color: str("red"), n: int(5) }],
  ["qvec/v6", { emb: vec(1, 2), color: str("red"), n: int(6) }],
  ["qvec/v7", { emb: arr(dbl(1), dbl(2), dbl(3)), color: str("red"), n: int(7) }],
  ["qvec/v8", { color: str("red"), n: int(8) }],
  ["qvec/v9", { emb: vec(0, 0, 0), color: str("blue"), n: int(9) }],
  ["qvec/v10", { emb: vec(2, 0, 0), color: str("green"), n: int(10), dist: int(99) }],
  ["qvec/v11", { emb: vec(0.5, 0.5, 0.5), color: str("green"), n: int(11), emb2: vec(1, 1, 1) }],
];
