// FS-RULES/query-proofs and FS-RULES/access-budgets.
//
// Queries use equality and IN filters only, which need no composite index, so an index refusal
// never stands in for a Rules decision.

import {
  allow,
  and,
  bool,
  commit,
  equal,
  FRESH,
  get,
  integer,
  runQuery,
  seedDocs,
  string,
  within,
} from "./common.mjs";

const DB = "/databases/$(database)/documents";

const QUERY_RULES = [
  allow("/fsr-q/{d}", "list", "request.auth != null && resource.data.owner == request.auth.uid"),
  allow("/fsr-q/{d}", "get", "true"),
  allow("/fsr-ql/{d}", "list", "request.query.limit <= 2"),
  allow("/fsr-qo/{d}", "list", "request.query.offset == 0"),
  allow("/fsr-qo2/{d}", "list", "request.query.offset <= 1"),
  allow("/fsr-qob/{d}", "list", "request.query.orderBy == null"),
  allow("/fsr-qp/{d}", "list", "resource.data.public == true"),
  allow("/fsr-qget/{d}", "get", "true"),
  allow("/fsr-qid/{d}", "list", "d == 'one'"),
  allow(
    "/{path=**}/fsr-cg/{d}",
    "list",
    "request.auth != null && resource.data.owner == request.auth.uid",
  ),
  allow("/fsr-cgx/{x}/fsr-cgn/{d}", "list", "true"),
  allow("/fsr-qlim/{d}", "list", "request.query.limit == null"),
];

/** `[collection, predicate]`: the shape of `request.query`, each queried with and without an order. */
const QUERY_SHAPE_CASES = [
  ["fsr-qs-map", "request.query is map"],
  ["fsr-qs-keys", "request.query.keys().hasOnly(['limit', 'offset', 'orderBy'])"],
  ["fsr-qs-keys-all", "request.query.keys().hasAll(['limit', 'offset', 'orderBy'])"],
  ["fsr-qs-order-in", "'orderBy' in request.query"],
  ["fsr-qs-order-map", "request.query.orderBy is map"],
  ["fsr-qs-order-list", "request.query.orderBy is list"],
  ["fsr-qs-order-string", "request.query.orderBy is string"],
  ["fsr-qs-order-empty", "request.query.orderBy.size() == 0"],
  ["fsr-qs-order-n-asc", "request.query.orderBy.n == 'ASC'"],
  ["fsr-qs-order-name", "request.query.orderBy.size() == 1"],
  ["fsr-qs-limit-int", "request.query.limit is int"],
  ["fsr-qs-offset-int", "request.query.offset is int"],
  ["fsr-qs-offset-zero", "request.query.offset == 0"],
];

/** List rules making `count` distinct get() calls, on an empty and on a one-document collection. */
const LIST_BUDGETS = [10, 11, 15, 20, 21];

/** A rule making `count` get() calls on distinct seeded documents (`fsr-bd/<start..>`). */
const gets = (count, start = 0, call = "get") =>
  Array.from({ length: count }, (_, i) => `${call}(${DB}/fsr-bd/d${start + i}).data.n == 1`).join(
    " && ",
  );

/** Write cases: each row creates documents no other row creates. */
const WRITE_CASES = {
  "write-10": gets(10),
  "write-11": gets(11),
  "write-get-and-get-after-same-path": `${gets(10)} && getAfter(${DB}/fsr-bd/d0).data.n == 1`,
  "pair-10-a": gets(10, 0),
  "pair-10-b": gets(10, 10),
  "c7-a": gets(7, 0),
  "c7-b": gets(7, 7),
  "c7-c": gets(7, 14),
  "s7-a": gets(7, 0),
  "s7-b": gets(7, 0),
  "s7-c": gets(7, 7),
  "bw7-a": gets(7, 0),
  "bw7-b": gets(7, 7),
  "bw7-c": gets(7, 14),
  "g7-a": gets(7, 0),
  "g7-b": gets(7, 7),
  "g7-c": gets(7, 14),
};

const BUDGET_CASES = [
  ["get-10", "get", gets(10)],
  ["get-11", "get", gets(11)],
  [
    "same-path-11",
    "get",
    Array.from({ length: 11 }, () => `get(${DB}/fsr-bd/d0).data.n == 1`).join(" && "),
  ],
  [
    "exists-10",
    "get",
    Array.from({ length: 10 }, (_, i) => `exists(${DB}/fsr-bd/d${i})`).join(" && "),
  ],
  [
    "exists-11",
    "get",
    Array.from({ length: 11 }, (_, i) => `exists(${DB}/fsr-bd/d${i})`).join(" && "),
  ],
  ["get-and-exists-same-path", "get", `${gets(10)} && exists(${DB}/fsr-bd/d0)`],
  ["read-6-a", "get", gets(6, 0)],
  ["read-6-b", "get", gets(6, 6)],
  ["read-6-c", "get", gets(6, 12)],
  ["read-7-d", "get", gets(7, 18)],
  ["read-6-shared", "get", gets(6, 0)],
  ...Object.entries(WRITE_CASES).map(([name, predicate]) => [name, "create", predicate]),
];

export const FRAGMENTS = [
  [
    ...QUERY_RULES,
    ...BUDGET_CASES.map(([name, method, predicate]) => allow(`/fsr-b/${name}`, method, predicate)),
    allow("/fsr-bl/{d}", "list", gets(10)),
    allow("/fsr-bl11/{d}", "list", gets(11)),
    ...QUERY_SHAPE_CASES.map(([collection, predicate]) =>
      allow(`/${collection}/{d}`, "list", predicate),
    ),
    ...LIST_BUDGETS.flatMap((calls) => [
      allow(`/fsr-lb${calls}/{d}`, "list", gets(calls)),
      allow(`/fsr-lbd${calls}/{d}`, "list", gets(calls)),
    ]),
  ].join("\n"),
];

const OWNED = (n, owner, extra = {}) => ({
  owner: string(`UID(${owner})`),
  n: integer(n),
  ...extra,
});

const QUERY_SEED = seedDocs([
  ["fsr-q/1", OWNED(1, "a")],
  ["fsr-q/2", OWNED(2, "a")],
  ["fsr-q/3", OWNED(3, "b")],
  ["fsr-ql/1", { n: integer(1) }],
  ["fsr-ql/2", { n: integer(2) }],
  ["fsr-ql/3", { n: integer(3) }],
  ["fsr-qo/1", { n: integer(1) }],
  ["fsr-qo2/1", { n: integer(1) }],
  ["fsr-qob/1", { n: integer(1) }],
  ["fsr-qp/1", { public: bool(true) }],
  ["fsr-qp/2", { public: bool(false) }],
  ["fsr-qget/1", { n: integer(1) }],
  ["fsr-qid/one", { n: integer(1) }],
  ["fsr-qid/two", { n: integer(2) }],
  ["fsr-cgx/p/fsr-cg/1", OWNED(1, "a")],
  ["fsr-cgx/p/fsr-cg/2", OWNED(2, "b")],
  ["fsr-cgx/p/fsr-cgn/1", { n: integer(1) }],
  ["fsr-qlim/1", { n: integer(1) }],
  ...QUERY_SHAPE_CASES.map(([collection]) => [`${collection}/1`, { n: integer(1) }]),
]);

const byName = (collection, id) => ({
  fieldFilter: {
    field: { fieldPath: "__name__" },
    op: "EQUAL",
    value: { referenceValue: `{docs}/${collection}/${id}` },
  },
});

const count = (id, as, collection, where) => ({
  id,
  as,
  rpc: "runAggregationQuery",
  body: {
    structuredAggregationQuery: {
      structuredQuery: { from: [{ collectionId: collection }], ...(where ? { where } : {}) },
      aggregations: [{ alias: "n", count: {} }],
    },
  },
});

const list = (id, as, collection, params = {}) => ({
  id,
  as,
  rpc: "listDocuments",
  collection,
  params,
});

const BUDGET_SEED = seedDocs([
  ...Array.from({ length: 25 }, (_, i) => [`fsr-bd/d${i}`, { n: integer(1) }]),
  ...LIST_BUDGETS.map((calls) => [`fsr-lbd${calls}/1`, { n: integer(1) }]),
]);

const createAt = (name) => ({
  update: { name: `{docs}/fsr-b/${name}`, fields: {} },
  currentDocument: { exists: false },
});

export const PROGRAMS = [
  {
    id: "fs-rules/query/constraints",
    ruleset: "main",
    refresh: FRESH,
    seed: QUERY_SEED,
    steps: [
      runQuery("owner-filter-own", "a", "fsr-q", { where: equal("owner", string("UID(a)")) }),
      runQuery("owner-filter-other", "a", "fsr-q", { where: equal("owner", string("UID(b)")) }),
      runQuery("no-filter", "a", "fsr-q"),
      runQuery("owner-filter-unauthenticated", "none", "fsr-q", {
        where: equal("owner", string("UID(a)")),
      }),
      runQuery("owner-in-own", "a", "fsr-q", { where: within("owner", [string("UID(a)")]) }),
      runQuery("owner-in-mixed", "a", "fsr-q", {
        where: within("owner", [string("UID(a)"), string("UID(b)")]),
      }),
      runQuery("owner-and-n", "a", "fsr-q", {
        where: and(equal("owner", string("UID(a)")), equal("n", integer(1))),
      }),
      runQuery("limit-2", "a", "fsr-ql", { limit: 2 }),
      runQuery("limit-3", "a", "fsr-ql", { limit: 3 }),
      runQuery("limit-absent", "a", "fsr-ql"),
      runQuery("limit-absent-rule-null", "a", "fsr-qlim"),
      runQuery("limit-present-rule-null", "a", "fsr-qlim", { limit: 1 }),
      runQuery("offset-absent", "a", "fsr-qo"),
      runQuery("offset-0", "a", "fsr-qo", { offset: 0 }),
      runQuery("offset-1", "a", "fsr-qo", { offset: 1 }),
      runQuery("offset-1-le-1", "a", "fsr-qo2", { offset: 1 }),
      runQuery("offset-2-le-1", "a", "fsr-qo2", { offset: 2 }),
      runQuery("order-absent", "a", "fsr-qob"),
      runQuery("order-by-n", "a", "fsr-qob", {
        orderBy: [{ field: { fieldPath: "n" }, direction: "ASCENDING" }],
      }),
      runQuery("public-filter", "none", "fsr-qp", { where: equal("public", bool(true)) }),
      runQuery("public-filter-false", "none", "fsr-qp", { where: equal("public", bool(false)) }),
      runQuery("public-in", "none", "fsr-qp", { where: within("public", [bool(true)]) }),
      runQuery("public-no-filter", "none", "fsr-qp"),
      runQuery("get-only-collection", "a", "fsr-qget"),
      get("get-only-collection-get", "a", "fsr-qget/1"),
      runQuery("name-equal-allowed-id", "a", "fsr-qid", { where: byName("fsr-qid", "one") }),
      runQuery("name-equal-other-id", "a", "fsr-qid", { where: byName("fsr-qid", "two") }),
      runQuery("name-equal-owned", "a", "fsr-q", { where: byName("fsr-q", "1") }),
      runQuery("name-equal-foreign", "a", "fsr-q", { where: byName("fsr-q", "3") }),
      runQuery("no-filter-id-rule", "a", "fsr-qid"),
      runQuery("group-owner-filter", "a", "fsr-cg", {
        allDescendants: true,
        where: equal("owner", string("UID(a)")),
      }),
      runQuery("group-no-filter", "a", "fsr-cg", { allDescendants: true }),
      runQuery("group-without-recursive-rule", "a", "fsr-cgn", { allDescendants: true }),
      runQuery("group-scoped-to-parent", "a", "fsr-cgn", { parent: "fsr-cgx/p" }),
      count("count-owner-filter", "a", "fsr-q", equal("owner", string("UID(a)"))),
      count("count-no-filter", "a", "fsr-q"),
      count("count-limit-rule", "a", "fsr-ql"),
      list("list-documents-owned-rule", "a", "fsr-q"),
      list("list-documents-limit-rule", "a", "fsr-ql", { pageSize: 2 }),
      list("list-documents-limit-rule-3", "a", "fsr-ql", { pageSize: 3 }),
      list("list-documents-limit-rule-default", "a", "fsr-ql"),
      list("list-documents-open", "a", "fsr-open"),
      runQuery("owner-filter-own-grpc", "a", "fsr-q", {
        where: equal("owner", string("UID(a)")),
        transport: "grpc",
      }),
      runQuery("no-filter-grpc", "a", "fsr-q", { transport: "grpc" }),
      { ...count("count-no-filter-grpc", "a", "fsr-q"), transport: "grpc" },
      { ...list("list-documents-owned-rule-grpc", "a", "fsr-q"), transport: "grpc" },
      ...QUERY_SHAPE_CASES.flatMap(([collection]) => [
        runQuery(`shape-${collection.slice(7)}`, "a", collection),
        runQuery(`shape-${collection.slice(7)}-ordered`, "a", collection, {
          orderBy: [{ field: { fieldPath: "n" }, direction: "ASCENDING" }],
        }),
        runQuery(`shape-${collection.slice(7)}-limited`, "a", collection, { limit: 5, offset: 0 }),
      ]),
    ],
  },
  {
    id: "fs-rules/budgets/access-calls",
    ruleset: "main",
    refresh: FRESH,
    seed: BUDGET_SEED,
    steps: [
      get("get-10", "a", "fsr-b/get-10"),
      get("get-11", "a", "fsr-b/get-11"),
      get("same-path-11", "a", "fsr-b/same-path-11"),
      get("exists-10", "a", "fsr-b/exists-10"),
      get("exists-11", "a", "fsr-b/exists-11"),
      get("get-and-exists-same-path", "a", "fsr-b/get-and-exists-same-path"),
      runQuery("list-10", "a", "fsr-bl"),
      runQuery("list-11", "a", "fsr-bl11"),
      ...LIST_BUDGETS.flatMap((calls) => [
        runQuery(`list-empty-${calls}`, "a", `fsr-lb${calls}`),
        runQuery(`list-one-document-${calls}`, "a", `fsr-lbd${calls}`),
      ]),
      commit("write-10", "a", [createAt("write-10")]),
      commit("write-11", "a", [createAt("write-11")]),
      commit("write-get-and-get-after-same-path", "a", [
        createAt("write-get-and-get-after-same-path"),
      ]),
      commit("commit-10-and-10", "a", [createAt("pair-10-a"), createAt("pair-10-b")]),
      commit("commit-7-7-7", "a", [createAt("c7-a"), createAt("c7-b"), createAt("c7-c")]),
      commit("commit-7-7-shared-paths", "a", [
        createAt("s7-a"),
        createAt("s7-b"),
        createAt("s7-c"),
      ]),
      {
        id: "batch-get-6-6-6",
        as: "a",
        rpc: "batchGet",
        body: {
          documents: ["{docs}/fsr-b/read-6-a", "{docs}/fsr-b/read-6-b", "{docs}/fsr-b/read-6-c"],
        },
      },
      {
        id: "batch-get-6-6-6-7",
        as: "a",
        rpc: "batchGet",
        body: {
          documents: [
            "{docs}/fsr-b/read-6-a",
            "{docs}/fsr-b/read-6-b",
            "{docs}/fsr-b/read-6-c",
            "{docs}/fsr-b/read-7-d",
          ],
        },
      },
      {
        id: "batch-get-6-shared-twice",
        as: "a",
        rpc: "batchGet",
        body: { documents: ["{docs}/fsr-b/read-6-a", "{docs}/fsr-b/read-6-shared"] },
      },
      {
        id: "batch-write-7-7-7",
        as: "a",
        rpc: "batchWrite",
        body: { writes: [createAt("bw7-a"), createAt("bw7-b"), createAt("bw7-c")] },
      },
      get("get-11-grpc", "a", "fsr-b/get-11", { transport: "grpc" }),
      commit("commit-7-7-7-grpc", "a", [createAt("g7-a"), createAt("g7-b"), createAt("g7-c")], {
        transport: "grpc",
      }),
    ],
  },
];
