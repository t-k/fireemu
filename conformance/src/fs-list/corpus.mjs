// The FS-DATA-WRITE-LIST corpus: listDocuments and listCollectionIds against the query sandbox
// `(default)` database, recorded with the shared harness (src/fs-query-index, lane
// `fs-data-write-list`). Program ids are `fs-data-write-list/<area>/<case>`; the area is the
// proposed FS-DATA-WRITE condition that owns the program.
//
// The REST surface is covered in full (every request field, paging chains, invalid values);
// gRPC repeats representative cases and the request shapes REST cannot send (an empty
// collection id).

import { bool, int, map, str } from "../fs-query-index/values.mjs";

/** Seeded documents: present ones, documents with only subcollections, and nested ones. */
const LIST_SEED = [
  ["lst/d01", { a: int(1), b: str("x"), m: map({ p: int(1), q: int(2) }) }],
  ["lst/d02", { a: int(3), b: str("y") }],
  ["lst/d03", { a: int(2) }],
  ["lst/d04", { b: str("z"), m: map({ p: int(5) }) }],
  ["lst/d05", {}],
  ["lst/d06", { a: int(2), c: bool(true) }],
  ["lst/d01/sub/s1", { n: int(1) }],
  ["lst/d01/sub/s2", { n: int(2) }],
  ["lst/d01/other/o1", {}],
  ["lst/missing1/sub/s3", { n: int(3) }],
  ["lst/missing2/deep/x/more/y1", {}],
  ["Lst/u1", {}],
  ["lst-a/a1", {}],
  ["lst_b/b1", {}],
  ["lstx/x1", { a: int(9) }],
];

/** A REST listDocuments step: `query` is a list of [parameter, value] pairs. */
const list = (id, collectionId, query = [], extra = {}) => ({
  id,
  rpc: "listDocuments",
  collectionId,
  ...(query.length ? { query } : {}),
  ...extra,
});
/** A REST listCollectionIds step. */
const ids = (id, body = {}, extra = {}) => ({ id, rpc: "listCollectionIds", body, ...extra });
const next = (step) => ({ $from: step, path: "nextPageToken" });
const commit = (id, writes) => ({ id, rpc: "commit", body: { writes } });
const put = (path, n) => ({ update: { name: `{docs}/${path}`, fields: { n: int(n) } } });
const remove = (path) => ({ delete: `{docs}/${path}` });
const atWrite = (step) => ({ $from: step, path: "commitTime" });
const shifted = (step, shift) => ({ $time: { $from: step, path: "commitTime", ...shift } });
/** A gRPC step with the request message fields in `body`. */
const grpc = (id, rpc, body = {}, extra = {}) => ({ id, rpc, transport: "grpc", body, ...extra });

export const PROGRAMS = [
  {
    id: "fs-data-write-list/list-documents/paging",
    seed: LIST_SEED,
    steps: [
      list("default", "lst"),
      list("page-size-2", "lst", [["pageSize", "2"]]),
      list("page-2", "lst", [
        ["pageSize", "2"],
        ["pageToken", next("page-size-2")],
      ]),
      list("page-3", "lst", [
        ["pageSize", "2"],
        ["pageToken", next("page-2")],
      ]),
      list("page-4", "lst", [
        ["pageSize", "2"],
        ["pageToken", next("page-3")],
      ]),
      list("page-size-5", "lst", [["pageSize", "5"]]),
      list("page-size-5-then-other-size", "lst", [
        ["pageSize", "1"],
        ["pageToken", next("page-size-5")],
      ]),
      list("token-with-other-collection", "lstx", [["pageToken", next("page-size-2")]]),
      list("token-with-order-by", "lst", [
        ["orderBy", "a"],
        ["pageToken", next("page-size-2")],
      ]),
      list("page-size-0", "lst", [["pageSize", "0"]]),
      list("page-size-negative", "lst", [["pageSize", "-1"]]),
      list("page-size-max-int32", "lst", [["pageSize", "2147483647"]]),
      list("page-size-overflow", "lst", [["pageSize", "2147483648"]]),
      list("page-size-not-a-number", "lst", [["pageSize", "abc"]]),
      list("page-size-fraction", "lst", [["pageSize", "1.5"]]),
      list("page-size-twice", "lst", [
        ["pageSize", "1"],
        ["pageSize", "2"],
      ]),
      list("page-token-garbage", "lst", [["pageToken", "garbage"]]),
      list("page-token-base64", "lst", [["pageToken", "AAAA"]]),
      list("page-token-empty", "lst", [["pageToken", ""]]),
    ],
  },
  {
    id: "fs-data-write-list/list-documents/order-and-mask",
    seed: LIST_SEED,
    steps: [
      list("order-by-field", "lst", [["orderBy", "a"]]),
      list("order-by-field-asc", "lst", [["orderBy", "a asc"]]),
      list("order-by-field-desc", "lst", [["orderBy", "a desc"]]),
      list("order-by-field-desc-upper", "lst", [["orderBy", "a DESC"]]),
      list("order-by-two-fields", "lst", [["orderBy", "a desc, b"]]),
      list("order-by-two-fields-no-space", "lst", [["orderBy", "b,a"]]),
      list("order-by-name", "lst", [["orderBy", "__name__"]]),
      list("order-by-name-desc", "lst", [["orderBy", "__name__ desc"]]),
      list("order-by-field-then-name-desc", "lst", [["orderBy", "a, __name__ desc"]]),
      list("order-by-nested", "lst", [["orderBy", "m.p"]]),
      list("order-by-quoted", "lst", [["orderBy", "`a`"]]),
      list("order-by-missing-field", "lst", [["orderBy", "zz"]]),
      list("order-by-invalid-path", "lst", [["orderBy", "a..b"]]),
      list("order-by-invalid-direction", "lst", [["orderBy", "a sideways"]]),
      list("order-by-trailing-comma", "lst", [["orderBy", "a,"]]),
      list("order-by-duplicate", "lst", [["orderBy", "a, a"]]),
      list("order-by-empty", "lst", [["orderBy", ""]]),
      list("order-by-paged", "lst", [
        ["orderBy", "a desc"],
        ["pageSize", "2"],
      ]),
      list("order-by-paged-next", "lst", [
        ["orderBy", "a desc"],
        ["pageSize", "2"],
        ["pageToken", next("order-by-paged")],
      ]),
      list("mask-one", "lst", [["mask.fieldPaths", "a"]]),
      list("mask-two", "lst", [
        ["mask.fieldPaths", "a"],
        ["mask.fieldPaths", "m.p"],
      ]),
      list("mask-map", "lst", [["mask.fieldPaths", "m"]]),
      list("mask-name", "lst", [["mask.fieldPaths", "__name__"]]),
      list("mask-missing", "lst", [["mask.fieldPaths", "zz"]]),
      list("mask-invalid", "lst", [["mask.fieldPaths", "a..b"]]),
      list("mask-empty", "lst", [["mask.fieldPaths", ""]]),
      list("mask-and-order", "lst", [
        ["mask.fieldPaths", "b"],
        ["orderBy", "a"],
      ]),
    ],
  },
  {
    id: "fs-data-write-list/list-documents/show-missing",
    seed: LIST_SEED,
    steps: [
      list("show-missing", "lst", [["showMissing", "true"]]),
      list("show-missing-false", "lst", [["showMissing", "false"]]),
      list("show-missing-not-a-bool", "lst", [["showMissing", "yes"]]),
      list("show-missing-number", "lst", [["showMissing", "1"]]),
      list("show-missing-paged", "lst", [
        ["showMissing", "true"],
        ["pageSize", "3"],
      ]),
      list("show-missing-paged-next", "lst", [
        ["showMissing", "true"],
        ["pageSize", "3"],
        ["pageToken", next("show-missing-paged")],
      ]),
      list("show-missing-paged-next-2", "lst", [
        ["showMissing", "true"],
        ["pageSize", "3"],
        ["pageToken", next("show-missing-paged-next")],
      ]),
      list("show-missing-with-order-by", "lst", [
        ["showMissing", "true"],
        ["orderBy", "a"],
      ]),
      list("show-missing-with-order-by-name", "lst", [
        ["showMissing", "true"],
        ["orderBy", "__name__"],
      ]),
      list("show-missing-with-mask", "lst", [
        ["showMissing", "true"],
        ["mask.fieldPaths", "a"],
      ]),
      list("show-missing-deep", "deep", [["showMissing", "true"]], { parent: "lst/missing2" }),
      list("show-missing-empty-collection", "nothing", [["showMissing", "true"]]),
    ],
  },
  {
    id: "fs-data-write-list/list-documents/scope",
    seed: LIST_SEED,
    steps: [
      list("subcollection", "sub", [], { parent: "lst/d01" }),
      list("subcollection-of-missing-document", "sub", [], { parent: "lst/missing1" }),
      list("subcollection-of-absent-document", "sub", [], { parent: "lst/none" }),
      list("deep-subcollection", "more", [], { parent: "lst/missing2/deep/x" }),
      list("empty-collection", "nothing"),
      list("case-differs", "Lst"),
      list("reserved-collection-id", "__bad__"),
      list("dotted-collection-id", "a.b"),
      list("unknown-parameter", "lst", [["unknownParameter", "1"]]),
      list("transaction-invalid", "lst", [["transaction", "AAAA"]]),
      list("transaction-and-read-time", "lst", [
        ["transaction", "AAAA"],
        ["readTime", "2099-01-01T00:00:00Z"],
      ]),
    ],
  },
  {
    id: "fs-data-write-list/list-documents/read-time",
    seed: [],
    steps: [
      commit("write-1", [put("lsr/r1", 1), put("lsr/r2", 2)]),
      commit("write-2", [put("lsr/r1", 10), put("lsr/r3", 3), remove("lsr/r2")]),
      list("current", "lsr"),
      list("at-write-1", "lsr", [["readTime", atWrite("write-1")]]),
      list("at-write-2", "lsr", [["readTime", atWrite("write-2")]]),
      list("nanosecond-before-write-1", "lsr", [
        ["readTime", shifted("write-1", { addNanos: -1 })],
      ]),
      list("microsecond-before-write-1", "lsr", [
        ["readTime", shifted("write-1", { addNanos: -1000 })],
      ]),
      list("microsecond-before-write-2", "lsr", [
        ["readTime", shifted("write-2", { addNanos: -1000 })],
      ]),
      list("61-minutes-before-write-1", "lsr", [
        ["readTime", shifted("write-1", { addSeconds: -3660 })],
      ]),
      list("future", "lsr", [["readTime", "2099-01-01T00:00:00Z"]]),
      list("not-a-time", "lsr", [["readTime", "yesterday"]]),
      list("paged-at-write-1", "lsr", [
        ["readTime", atWrite("write-1")],
        ["pageSize", "1"],
      ]),
      list("paged-at-write-1-next", "lsr", [
        ["readTime", atWrite("write-1")],
        ["pageSize", "1"],
        ["pageToken", next("paged-at-write-1")],
      ]),
      list("paged-at-write-1-next-without-read-time", "lsr", [
        ["pageSize", "1"],
        ["pageToken", next("paged-at-write-1")],
      ]),
      list("show-missing-at-write-1", "lsr", [
        ["readTime", atWrite("write-1")],
        ["showMissing", "true"],
      ]),
      ids("collection-ids-at-write-1", { readTime: atWrite("write-1") }),
      ids("collection-ids-nanosecond-before-write-1", {
        readTime: shifted("write-1", { addNanos: -1 }),
      }),
      ids("collection-ids-future", { readTime: "2099-01-01T00:00:00Z" }),
      ids("collection-ids-not-a-time", { readTime: "yesterday" }),
    ],
  },
  {
    id: "fs-data-write-list/list-collection-ids/rest",
    seed: LIST_SEED,
    steps: [
      ids("root"),
      ids("document", {}, { parent: "lst/d01" }),
      ids("missing-document", {}, { parent: "lst/missing1" }),
      ids("absent-document", {}, { parent: "lst/none" }),
      ids("deep-missing-document", {}, { parent: "lst/missing2/deep/x" }),
      ids("root-page-size-2", { pageSize: 2 }),
      ids("root-page-2", { pageSize: 2, pageToken: next("root-page-size-2") }),
      ids("root-page-3", { pageSize: 2, pageToken: next("root-page-2") }),
      ids("root-page-size-2-as-text", { pageSize: "2" }),
      ids("page-size-0", { pageSize: 0 }),
      ids("page-size-negative", { pageSize: -1 }),
      ids("page-size-not-a-number", { pageSize: "abc" }),
      ids("page-token-garbage", { pageToken: "garbage" }),
      ids(
        "page-token-from-other-parent",
        { pageToken: next("root-page-size-2") },
        {
          parent: "lst/d01",
        },
      ),
      ids("unknown-field", { unknownField: 1 }),
      ids("collection-parent", {}, { path: "v1/{docs}/lst:listCollectionIds" }),
      ids("empty-body-text", undefined, { rawBody: "" }),
    ],
  },
  {
    id: "fs-data-write-list/grpc/list-documents",
    seed: LIST_SEED,
    steps: [
      grpc("default", "listDocuments", { collectionId: "lst" }),
      grpc("page-size-2", "listDocuments", { collectionId: "lst", pageSize: 2 }),
      grpc("page-2", "listDocuments", {
        collectionId: "lst",
        pageSize: 2,
        pageToken: next("page-size-2"),
      }),
      grpc("order-by-desc", "listDocuments", { collectionId: "lst", orderBy: "a desc" }),
      grpc("order-by-invalid", "listDocuments", { collectionId: "lst", orderBy: "a sideways" }),
      grpc("mask", "listDocuments", { collectionId: "lst", mask: { fieldPaths: ["a", "m.p"] } }),
      grpc("show-missing", "listDocuments", { collectionId: "lst", showMissing: true }),
      grpc("show-missing-with-order-by", "listDocuments", {
        collectionId: "lst",
        showMissing: true,
        orderBy: "a",
      }),
      grpc("page-size-negative", "listDocuments", { collectionId: "lst", pageSize: -1 }),
      grpc("page-token-garbage", "listDocuments", { collectionId: "lst", pageToken: "garbage" }),
      grpc("subcollection", "listDocuments", { collectionId: "sub" }, { parent: "lst/d01" }),
      grpc("every-collection-of-document", "listDocuments", {}, { parent: "lst/d01" }),
      grpc(
        "every-collection-of-missing-document",
        "listDocuments",
        { showMissing: true },
        { parent: "lst/missing2" },
      ),
      grpc("every-collection-at-root", "listDocuments", {}),
      grpc("collection-id-with-slash", "listDocuments", { collectionId: "lst/d01/sub" }),
      grpc("read-time-future", "listDocuments", {
        collectionId: "lst",
        readTime: "2099-01-01T00:00:00Z",
      }),
    ],
  },
  {
    id: "fs-data-write-list/grpc/list-collection-ids",
    seed: LIST_SEED,
    steps: [
      grpc("root", "listCollectionIds"),
      grpc("document", "listCollectionIds", {}, { parent: "lst/d01" }),
      grpc("missing-document", "listCollectionIds", {}, { parent: "lst/missing1" }),
      grpc("page-size-2", "listCollectionIds", { pageSize: 2 }),
      grpc("page-2", "listCollectionIds", { pageSize: 2, pageToken: next("page-size-2") }),
      grpc("page-size-negative", "listCollectionIds", { pageSize: -1 }),
      grpc("page-token-garbage", "listCollectionIds", { pageToken: "garbage" }),
      grpc("collection-parent", "listCollectionIds", {}, { parent: "lst" }),
    ],
  },
];
