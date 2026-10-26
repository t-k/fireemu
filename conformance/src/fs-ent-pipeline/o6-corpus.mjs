// The FS-ENT-ORACLE O-6 corpus: what production does with `sort`, with the stage orders the SDKs
// produce, with the logical and recorded functions in a `where`, and with the order of results
// when no `sort` asks for one. Program ids are `fs-ent-pipeline/o6/<area>-<group>`.
//
// Every group is one program: a seed in its own collections and steps that read them. A group
// that needs vectors writes them with a recorded commit step, because a refused harness seed
// ends the recording. The table is built by `defineArea`, so a later packet (aggregate,
// distinct, add_fields, remove_fields, collection_group, documents) adds an area without
// touching the programs here.

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
} from "../fs-query-index/values.mjs";
import {
  asc,
  del,
  desc,
  eq,
  fld,
  fn,
  gt,
  limit,
  list,
  lt,
  numbered,
  offset,
  ordering,
  read,
  readGrpc,
  seedBatch,
  select,
  sort,
  stage,
  where,
} from "./builders.mjs";

export { ordering };

export const O6_PREFIX = "fs-ent-pipeline/o6/";

const COMMIT_BATCH = 500;

/**
 * A program that reads each collection sorted by `v`, ascending and then descending. Specs
 * marked `commit` write their documents with a commit step first (vectors).
 */
export function withinKindsProgram(id, specs) {
  const seed = [];
  const writes = [];
  const reads = [];
  for (const { collection: name, docs, commit } of specs) {
    const entries = docs.map(([doc, fields]) => [`${name}/${doc}`, fields]);
    if (commit) writes.push(seedBatch(`seed-${name}`, entries));
    else seed.push(...entries);
    reads.push(
      read(`${name}-asc`, name, sort(asc(fld("v")))),
      read(`${name}-desc`, name, sort(desc(fld("v")))),
    );
  }
  return { id, seed, steps: [...writes, ...reads] };
}

/**
 * The documents of a two-field truth table: one per ordered pair of the domain, named by the ids
 * of its two values. A domain value of `undefined` leaves the field absent.
 */
export function truthTableDocs(from, domain) {
  return domain.flatMap((first) =>
    domain.map((second) => [
      `${from}/${first.id}${second.id}`,
      {
        ...(first.value === undefined ? {} : { a: first.value }),
        ...(second.value === undefined ? {} : { b: second.value }),
      },
    ]),
  );
}

// --- the table ---

/** Checks one area and returns its programs. */
export function defineArea(area, groups, prefix = O6_PREFIX) {
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(area)) throw new Error(`area ${area} is not a name`);
  const seen = new Set();
  return groups.map(({ id, seed = [], steps }) => {
    if (seen.has(id)) throw new Error(`duplicate group ${area}-${id}`);
    seen.add(id);
    return { id: `${prefix}${area}-${id}`, seed, steps };
  });
}

/** One document per value kind in a field `v`, and one without it. */
const KIND_DOCS = [
  ["d01", { v: nul() }],
  ["d02", { v: bool(false) }],
  ["d03", { v: bool(true) }],
  ["d04", { v: nan() }],
  ["d05", { v: int(-1) }],
  ["d06", { v: dbl(0.5) }],
  ["d07", { v: int(2) }],
  ["d08", { v: ts("2020-01-01T00:00:00Z") }],
  ["d09", { v: str("a") }],
  ["d10", { v: bytes("AQ==") }],
  ["d11", { v: ref("{c}/d01") }],
  ["d12", { v: geo(1, 2) }],
  ["d13", { v: arr(int(1)) }],
  ["d14", { v: map({ a: int(1) }) }],
  ["d15", { w: int(1) }],
];
export const kindDocs = (from) =>
  KIND_DOCS.map(([doc, fields]) => [
    `${from}/${doc}`,
    JSON.parse(JSON.stringify(fields).replaceAll("{c}", from)),
  ]);

// sort

const kindsCross = {
  id: "kinds-cross",
  seed: kindDocs("sk"),
  steps: [
    seedBatch("seed-vector", [["sk/d16", { v: vec(1, 2) }]]),
    read("v-asc", "sk", sort(asc(fld("v")))),
    read("v-desc", "sk", sort(desc(fld("v")))),
    read("name-asc", "sk", sort(asc(fld("__name__")))),
    readGrpc("v-asc-grpc", "sk", sort(asc(fld("v")))),
    readGrpc("v-desc-limit2-grpc", "sk", sort(desc(fld("v"))), limit(2)),
  ],
};

const KINDS_WITHIN = [
  {
    collection: "sn",
    docs: numbered("n", [
      int(-5),
      int(0),
      dbl("-0"),
      dbl(0),
      int(1),
      dbl(1),
      dbl(1.5),
      int(2),
      int("9007199254740993"),
      dbl(9007199254740992),
      nan(),
      inf(-1),
      inf(1),
      int("9223372036854775807"),
      dbl(-1.5),
    ]),
  },
  {
    collection: "ss",
    docs: numbered(
      "s",
      ["", "a", "A", "aa", "b", "é", "z", "日本", "～", "\u{1f600}", "Z", "10", "9", " "].map(str),
    ),
  },
  {
    collection: "sb",
    docs: numbered("b", ["", "AA==", "AQ==", "/w==", "AAE=", "AQA="].map(bytes)),
  },
  {
    collection: "st",
    docs: numbered(
      "t",
      [
        "1969-12-31T23:59:59Z",
        "1970-01-01T00:00:00Z",
        "2020-01-01T00:00:00Z",
        "2020-01-01T00:00:00.000001Z",
        "2020-01-01T00:00:00.5Z",
        "2020-01-01T00:00:01Z",
        "0001-01-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
      ].map(ts),
    ),
  },
  {
    collection: "sr",
    docs: numbered("r", ["sr/a", "sr/b", "sr/a/c/d", "zz/a", "sr/aa", "sr/B"].map(ref)),
  },
  {
    collection: "sg",
    docs: numbered(
      "g",
      [
        [0, 0],
        [0, 1],
        [1, 0],
        [-1, 5],
        [90, 180],
        [-90, -180],
        [0, -1],
      ].map(([latitude, longitude]) => geo(latitude, longitude)),
    ),
  },
  {
    collection: "sa",
    docs: numbered("a", [
      arr(),
      arr(int(1)),
      arr(int(1), int(2)),
      arr(int(2)),
      arr(int(1), str("a")),
      arr(str("a")),
      arr(map({ a: int(1) })),
      arr(nul()),
      arr(int(1), int(2), int(3)),
      arr(bool(true)),
      arr(dbl(1.5)),
    ]),
  },
  {
    collection: "sm",
    docs: numbered("m", [
      map({}),
      map({ a: int(1) }),
      map({ a: int(2) }),
      map({ b: int(1) }),
      map({ a: int(1), b: int(1) }),
      map({ aa: int(1) }),
      map({ a: str("x") }),
      map({ a: map({ b: int(1) }) }),
      map({ a: nul() }),
    ]),
  },
  {
    collection: "sv",
    commit: true,
    docs: numbered("v", [vec(1), vec(1, 2), vec(2, 1), vec(1, 3), vec(0, 5), vec(1, 2, 3)]),
  },
];

const missingNull = {
  id: "missing-null",
  seed: [
    ["mn/a", { v: int(1), w: map({ x: int(1) }) }],
    ["mn/b", { v: nul() }],
    ["mn/c", {}],
    ["mn/d", { v: int(2), w: map({}) }],
    ["mn/e", { w: map({ x: nul() }) }],
    ["mn/f", { v: int(1), w: map({ x: int(2) }) }],
  ],
  steps: [
    read("v-asc", "mn", sort(asc(fld("v")))),
    read("v-desc", "mn", sort(desc(fld("v")))),
    read("wx-asc", "mn", sort(asc(fld("w.x")))),
    read("wx-desc", "mn", sort(desc(fld("w.x")))),
    read("through-scalar-asc", "mn", sort(asc(fld("v.x")))),
    read("v-asc-limit2", "mn", sort(asc(fld("v"))), limit(2)),
  ],
};

const TIE_GROUPS = [1, 2, 1, 3, 2, 1, 3, 2];
const ties = {
  id: "ties",
  seed: TIE_GROUPS.map((g, i) => [`ti/t${i + 1}`, { g: int(g), n: int((i * 5) % 8) }]),
  steps: [
    read("g-asc", "ti", sort(asc(fld("g")))),
    read("g-desc", "ti", sort(desc(fld("g")))),
    read("g-asc-limit2", "ti", sort(asc(fld("g"))), limit(2)),
    read("g-asc-limit4", "ti", sort(asc(fld("g"))), limit(4)),
    read("g-asc-offset1-limit2", "ti", sort(asc(fld("g"))), offset(1), limit(2)),
    read("g-asc-offset2-limit2", "ti", sort(asc(fld("g"))), offset(2), limit(2)),
    read("g-desc-limit3", "ti", sort(desc(fld("g"))), limit(3)),
    read("g-asc-offset7", "ti", sort(asc(fld("g"))), offset(7)),
  ],
};

const multiKey = {
  id: "multi-key",
  seed: [
    ["mk/m1", { a: int(1), b: str("x"), c: int(5) }],
    ["mk/m2", { a: int(1), b: str("y"), c: int(3) }],
    ["mk/m3", { a: int(1), b: str("x"), c: int(1) }],
    ["mk/m4", { a: int(2), b: str("y"), c: int(4) }],
    ["mk/m5", { a: int(2), b: str("x"), c: int(2) }],
    ["mk/m6", { a: int(2), b: str("y"), c: int(6) }],
    ["mk/m7", { a: int(3), b: int(5), c: int(7) }],
    ["mk/m8", { a: int(3), c: int(8) }],
  ],
  steps: [
    read("ab-asc-asc", "mk", sort(asc(fld("a")), asc(fld("b")))),
    read("ab-asc-desc", "mk", sort(asc(fld("a")), desc(fld("b")))),
    read("ab-desc-asc", "mk", sort(desc(fld("a")), asc(fld("b")))),
    read("ab-desc-desc", "mk", sort(desc(fld("a")), desc(fld("b")))),
    read("abc", "mk", sort(asc(fld("a")), asc(fld("b")), desc(fld("c")))),
    read("same-key-twice", "mk", sort(asc(fld("a")), desc(fld("a")))),
    read("a-then-name-desc", "mk", sort(asc(fld("a")), desc(fld("__name__")))),
    read("b-asc-a-asc", "mk", sort(asc(fld("b")), asc(fld("a")))),
  ],
};

const exprKeys = {
  id: "expr-keys",
  seed: [
    ["ek/e1", { a: int(1), b: int(4) }],
    ["ek/e2", { a: int(2), b: int(3) }],
    ["ek/e3", { a: int(1), b: int(2) }],
    ["ek/e4", { a: nul(), b: int(1) }],
  ],
  steps: [
    read("equal-asc", "ek", sort(asc(eq(fld("a"), int(1))))),
    read("equal-desc", "ek", sort(desc(eq(fld("a"), int(1))))),
    read("document-id-asc", "ek", sort(asc(fn("document_id", fld("__name__"))))),
    read("array-asc", "ek", sort(asc(fn("array", fld("a"), fld("b"))))),
    read("constant-asc", "ek", sort(asc(int(1)))),
  ],
};

/** The wire forms of a sort stage that the SDKs never send, one at a time. */
const orderingMap = (fields) => ({ mapValue: { fields } });
const goodKey = asc(fld("v"));
const WIRE_ERRORS = [
  ["no-args", []],
  ["int-arg", [int(1)]],
  ["string-arg", [str("v")]],
  ["field-arg", [fld("v")]],
  ["empty-map", [orderingMap({})]],
  ["direction-only", [orderingMap({ direction: str("ascending") })]],
  ["expression-only", [orderingMap({ expression: fld("v") })]],
  ["direction-up", [ordering(fld("v"), "up")]],
  ["direction-upper", [ordering(fld("v"), "ASCENDING")]],
  ["direction-int", [orderingMap({ direction: int(1), expression: fld("v") })]],
  ["direction-null", [orderingMap({ direction: nul(), expression: fld("v") })]],
  [
    "extra-key",
    [orderingMap({ direction: str("ascending"), expression: fld("v"), extra: int(1) })],
  ],
  ["second-arg-bad", [goodKey, int(1)]],
  ["expression-unknown-fn", [asc(fn("nope", fld("v")))]],
  ["expression-string", [orderingMap({ direction: str("ascending"), expression: str("v") })]],
];
const wireErrors = {
  id: "wire-errors",
  seed: [1, 2, 3].map((n) => [`we/w${n}`, { v: int(n) }]),
  steps: WIRE_ERRORS.map(([label, args]) => read(label, "we", stage("sort", ...args))),
};

/**
 * The pairwise rows (a PICT model of four factors, Pre 4 x Direction 2 x Key 3 x Post 4, with the
 * four rows the packet must contain given as seeds): the stage before the sort, the direction,
 * the key and the stages after it.
 */
export const SORT_COMBOS = [
  ["none", "asc", "tied", "offset-limit"],
  ["where", "desc", "unique", "limit"],
  ["select-alias", "asc", "unique", "none"],
  ["select-drop", "desc", "name", "select"],
  ["where", "asc", "name", "offset-limit"],
  ["none", "asc", "name", "limit"],
  ["select-drop", "desc", "tied", "none"],
  ["where", "asc", "tied", "select"],
  ["where", "asc", "name", "none"],
  ["select-alias", "desc", "unique", "select"],
  ["none", "desc", "unique", "none"],
  ["select-alias", "desc", "tied", "limit"],
  ["select-alias", "desc", "name", "offset-limit"],
  ["select-drop", "asc", "unique", "offset-limit"],
  ["none", "desc", "tied", "select"],
  ["select-drop", "desc", "unique", "limit"],
];
const comboStep = ([pre, direction, key, post]) => {
  const aliased = pre === "select-alias";
  const keyPath = { tied: aliased ? "g2" : "g", unique: aliased ? "n2" : "n", name: "__name__" }[
    key
  ];
  const order = (direction === "asc" ? asc : desc)(fld(keyPath));
  const before = {
    none: [],
    where: [where(gt(fld("n"), int(1)))],
    "select-alias": [select({ n2: fld("n"), g2: fld("g") })],
    "select-drop": [select({ tag: fld("tag") })],
  }[pre];
  const after = {
    none: [],
    limit: [limit(3)],
    "offset-limit": [offset(1), limit(3)],
    select: [select({ k: fld(keyPath) })],
  }[post];
  return read([pre, direction, key, post].join("-"), "cb", ...before, sort(order), ...after);
};
const combos = {
  id: "combos",
  seed: [
    ["cb/c1", { n: int(3), g: str("x"), tag: str("p") }],
    ["cb/c2", { n: int(1), g: str("y"), tag: str("q") }],
    ["cb/c3", { n: int(4), g: str("x"), tag: str("r") }],
    ["cb/c4", { n: int(2), g: str("y"), tag: str("s") }],
    ["cb/c5", { n: int(6), g: str("x"), tag: str("t") }],
    ["cb/c6", { n: int(5), g: str("x"), tag: str("u") }],
  ],
  steps: SORT_COMBOS.map(comboStep),
};

// stage order

const n = fld("n");
const a = fld("a");
const stageOrder = {
  id: "relaxed",
  seed: ["x", "y", "x", "y", "x"].map((g, i) => [`so/s${i + 1}`, { n: int(i + 1), g: str(g) }]),
  steps: [
    read("select-where-alias", "so", select({ a: n }), where(gt(a, int(2)))),
    read("select-where-dropped", "so", select({ a: n }), where(eq(fld("g"), str("x")))),
    read("where-where", "so", where(gt(n, int(1))), where(lt(n, int(5)))),
    read(
      "where-three",
      "so",
      where(gt(n, int(1))),
      where(lt(n, int(5))),
      where(eq(fld("g"), str("x"))),
    ),
    read("where-select-where", "so", where(gt(n, int(1))), select({ a: n }), where(lt(a, int(5)))),
    read("limit-sort", "so", limit(3), sort(desc(n))),
    read("limit-where", "so", limit(3), where(gt(n, int(1)))),
    read("offset-where", "so", offset(1), where(gt(n, int(1)))),
    read("limit-offset", "so", limit(4), offset(1)),
    read("limit-limit", "so", limit(4), limit(2)),
    read("offset-offset", "so", offset(1), offset(2)),
    read("select-select", "so", select({ a: n }), select({ b: a })),
    read("select-select-dropped", "so", select({ a: n }), select({ b: n })),
    read("offset-select-limit", "so", offset(1), select({ a: n }), limit(2)),
    read("where-limit-where", "so", where(gt(n, int(1))), limit(3), where(lt(n, int(5)))),
    read("sort-sort", "so", sort(asc(fld("g"))), sort(desc(n))),
    read("sort-where-sort", "so", sort(asc(n)), where(gt(n, int(1))), sort(desc(n))),
    read("limit-select-offset", "so", limit(4), select({ a: n }), offset(1)),
    readGrpc("where-where-grpc", "so", where(gt(n, int(1))), where(lt(n, int(5)))),
  ],
};

// logical and recorded functions in a where

const TRUTH_DOMAIN = [
  { id: "t", value: bool(true) },
  { id: "f", value: bool(false) },
  { id: "n", value: nul() },
  { id: "m", value: undefined },
];
const A = fld("a");
const B = fld("b");
const truth = {
  id: "truth",
  seed: truthTableDocs("lg", TRUTH_DOMAIN),
  steps: [
    ["and2", fn("and", A, B)],
    ["or2", fn("or", A, B)],
    ["xor2", fn("xor", A, B)],
    ["nor2", fn("nor", A, B)],
    ["not1", fn("not", A)],
    ["and1", fn("and", A)],
    ["or1", fn("or", A)],
    ["and3", fn("and", A, B, fn("not", A))],
    ["and0", fn("and")],
    ["not2", fn("not", A, B)],
    ["not-and", fn("not", fn("and", A, B))],
    ["and-or-not", fn("and", fn("or", A, B), fn("not", B))],
  ].map(([label, condition]) => read(label, "lg", where(condition))),
};

const nonBoolean = {
  id: "non-boolean",
  seed: [
    ["le/ok", { a: bool(true), b: bool(true) }],
    ["le/bad", { a: int(1), b: bool(true) }],
  ],
  steps: [
    ["and", fn("and", A, B)],
    ["or", fn("or", A, B)],
    ["not", fn("not", A)],
    ["is-error-and", fn("is_error", fn("and", A, B))],
  ].map(([label, condition]) => read(label, "le", where(condition))),
};

const V = fld("v");
const kinds = {
  id: "kinds",
  seed: kindDocs("lk"),
  steps: [
    ["exists", fn("exists", V)],
    ["is-absent", fn("is_absent", V)],
    ["not-exists", fn("not", fn("exists", V))],
    ["is-error-not", fn("is_error", fn("not", V))],
    ["type-string", eq(fn("type", V), str("string"))],
    ["type-int64", eq(fn("type", V), str("int64"))],
    ["is-type-string", fn("is_type", V, str("string"))],
    ["is-type-int64", fn("is_type", V, str("int64"))],
    ["is-type-float64", fn("is_type", V, str("float64"))],
    ["is-type-number", fn("is_type", V, str("number"))],
    ["is-type-array", fn("is_type", V, str("array"))],
  ].map(([label, condition]) => read(label, "lk", where(condition))),
};

const arrays = {
  id: "arrays",
  seed: [
    ["la/a1", { arr: arr(int(1), int(2)) }],
    ["la/a2", { arr: arr(int(2), str("a")) }],
    ["la/a3", { arr: arr() }],
    ["la/a4", { arr: arr(nul()) }],
    ["la/a5", { arr: arr(map({ a: int(1) })) }],
    ["la/a6", {}],
  ],
  steps: [
    ["contains-1", fn("array_contains", fld("arr"), int(1))],
    ["contains-string", fn("array_contains", fld("arr"), str("a"))],
    ["contains-null", fn("array_contains", fld("arr"), nul())],
    ["contains-nested", fn("array_contains", fld("arr"), list(int(1)))],
    ["contains-all-12", fn("array_contains_all", fld("arr"), list(int(1), int(2)))],
    ["contains-any-1a", fn("array_contains_any", fld("arr"), list(int(1), str("a")))],
    ["contains-all-empty", fn("array_contains_all", fld("arr"), list())],
  ].map(([label, condition]) => read(label, "la", where(condition))),
};

const equalAny = {
  id: "equal-any",
  seed: [
    ["ea/e1", { v: int(1) }],
    ["ea/e2", { v: dbl(1) }],
    ["ea/e3", { v: str("a") }],
    ["ea/e4", { v: nul() }],
    ["ea/e5", { v: nan() }],
    ["ea/e6", {}],
    ["ea/e7", { v: arr(int(1)) }],
  ],
  steps: [
    ["equal-any-1a", fn("equal_any", V, list(int(1), str("a")))],
    ["equal-any-null", fn("equal_any", V, list(nul()))],
    ["equal-any-nan", fn("equal_any", V, list(nan()))],
    ["not-equal-any-1", fn("not_equal_any", V, list(int(1)))],
    ["not-equal-any-null", fn("not_equal_any", V, list(nul()))],
    ["equal-any-empty", fn("equal_any", V, list())],
  ].map(([label, condition]) => read(label, "ea", where(condition))),
};

// result order without a sort

const ORDER_IDS = ["d10", "d2", "d1", "D1", "a", "z", "b9", "x_y"];
const writeDoc = (id, path, value) => seedBatch(id, [[path, { n: int(value) }]]);
const orderWrites = {
  id: "writes",
  seed: [],
  steps: [
    ...ORDER_IDS.map((doc, i) =>
      writeDoc(`write-${i + 1}-${doc.toLowerCase().replaceAll("_", "-")}`, `ow/${doc}`, i + 1),
    ),
    read("bare", "ow"),
    read("bare-again", "ow"),
    read("select", "ow", select({ n: fld("n") })),
    read("where", "ow", where(gt(fld("n"), int(0)))),
    read("limit3", "ow", limit(3)),
    read("limit3-offset2", "ow", offset(2), limit(3)),
    read("offset5", "ow", offset(5)),
    writeDoc("rewrite-d10", "ow/d10", 99),
    read("bare-after-rewrite", "ow"),
    del("delete-d2", "ow/d2"),
    writeDoc("recreate-d2", "ow/d2", 100),
    read("bare-after-recreate", "ow"),
    readGrpc("bare-grpc", "ow"),
  ],
};

const BATCH_IDS = [
  "k07",
  "k02",
  "k11",
  "k05",
  "k01",
  "k09",
  "k12",
  "k03",
  "k08",
  "k04",
  "k10",
  "k06",
];
const orderBatch = {
  id: "batch",
  seed: BATCH_IDS.map((doc, i) => [`ob/${doc}`, { n: int(i + 1) }]),
  steps: [
    read("bare", "ob"),
    read("bare-again", "ob"),
    read("limit5", "ob", limit(5)),
    read("name-asc", "ob", sort(asc(fld("__name__")))),
  ],
};

export const O6_AREAS = {
  sort: defineArea("sort", [
    kindsCross,
    withinKindsProgramGroup("kinds-within", KINDS_WITHIN),
    missingNull,
    ties,
    multiKey,
    exprKeys,
    wireErrors,
    combos,
  ]),
  "stage-order": defineArea("stage-order", [stageOrder]),
  "where-functions": defineArea("where-functions", [truth, nonBoolean, kinds, arrays, equalAny]),
  order: defineArea("order", [orderWrites, orderBatch]),
};

function withinKindsProgramGroup(id, specs) {
  const { seed, steps } = withinKindsProgram(id, specs);
  return { id, seed, steps };
}

export const O6_PROGRAMS = Object.values(O6_AREAS).flat();

// --- the plan ---

const count = (program, predicate) => program.steps.filter(predicate).length;
const isGrpc = (s) => (s.transport ?? "rest") === "grpc";

/** The documents a program has left after its steps, from its seed and its commit steps. */
function survivors(program) {
  const names = new Set((program.seed ?? []).map(([name]) => name));
  for (const { rpc, body, rawBody } of program.steps) {
    if (rpc !== "commit") continue;
    for (const write of (body ?? JSON.parse(rawBody)).writes) {
      if (write.update) names.add(write.update.name.replace(/^\{docs\}\//, ""));
      else names.delete(write.delete.replace(/^\{docs\}\//, ""));
    }
  }
  return names.size;
}

/**
 * The harness side of one program, as session.mjs runs it against an empty database: a wipe
 * (one read), the seed in batches of 500, the steps, and a wipe that reads, deletes and reads
 * again until the database is empty.
 */
export function seedWipePlan(program) {
  const seedDocs = (program.seed ?? []).length;
  const batches = Math.ceil(seedDocs / COMMIT_BATCH);
  const rounds = Math.ceil(survivors(program) / COMMIT_BATCH);
  return {
    id: program.id,
    seedDocs,
    operations: ["wipe", ...Array(batches).fill("seed"), "steps", "wipe"].filter(
      (operation) => operation !== "steps" || program.steps.length > 0,
    ),
    harnessRequests: 1 + batches + 2 * rounds + 1,
  };
}

/**
 * Request counts of a set of programs: the steps, the harness ceiling the runner applies, the
 * requests one recording is expected to take, the worst case of a whole packet (one describe,
 * the preflight's two reads, two recordings, two read-backs) and a deliberate cost estimate.
 */
export function o6Plan(programs) {
  const steps = programs.reduce((total, program) => total + program.steps.length, 0);
  const seedDocs = programs.reduce((total, program) => total + (program.seed ?? []).length, 0);
  const stepCeiling = steps;
  const harnessCeiling = programs.reduce(
    (total, program) => total + 8 + 2 * Math.ceil((program.seed?.length ?? 0) / COMMIT_BATCH),
    20,
  );
  const harness = programs.reduce(
    (total, program) => total + seedWipePlan(program).harnessRequests,
    1,
  );
  const grpc = programs.reduce((total, program) => total + count(program, isGrpc), 0);
  const perRecording = steps + harness;
  return {
    programs: programs.length,
    steps,
    rest: steps - grpc,
    grpc,
    commits: programs.reduce(
      (total, program) => total + count(program, (s) => s.rpc === "commit"),
      0,
    ),
    seedDocs,
    stepCeiling,
    harnessCeiling,
    harnessExpected: harness,
    expectedRequests: 1 + 2 + 2 * perRecording + 2,
    worstRequests: 1 + 2 + 2 * (stepCeiling + harnessCeiling) + 2,
    estimatedUsd:
      Math.ceil(((steps * 100 * 0.03 + seedDocs * 0.1) / 100_000) * 2 * 10_000) / 10_000,
  };
}
