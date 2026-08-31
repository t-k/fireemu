// Rows where fireemu deliberately answers something else, keyed `<program id>#<step id>`.
//
// Each entry names the answer fireemu gives (`fireemu`, in the recorded step shape, or with
// `bodyDigest` in place of `body` to pin a result set by its document names) and why;
// `check` gates those rows against it, so the divergence is pinned rather than merely
// tolerated, and an unlisted difference still fails. Every entry is also published as an
// `officialEmulatorDivergences` item of `spec/compatibility/contract.json` and in the
// README ("Firestore: measured divergences from the official emulator"), which is what
// makes it a documented divergence rather than debt.

const DOCS = "projects/demo-firestore-probe/databases/(default)/documents";

const document = (path, fields) => ({
  name: `${DOCS}/${path}`,
  fields,
  createTime: "<now>",
  updateTime: "<now>",
});

export const DIVERGENCES = {
  "values/type-order#descending-name-only": {
    fireemu: {
      status: 200,
      code: "OK",
      bodyDigest: "5 documents: ord/ts-late, ord/ts-early, ord/true, ord/str-kanji, ord/str-empty",
    },
    reason:
      "The official emulator refuses a query whose first order is `__name__` descending " +
      "(FAILED_PRECONDITION 'Firestore does not support descending key scans'); fireemu " +
      "serves it, in reverse name order, which is the ordering the SDKs' " +
      "`orderBy(documentId(), 'desc')` asks for.",
  },
  "queries/collection-group#partition-query": {
    fireemu: {
      status: 200,
      code: "OK",
      body: {
        partitions: [
          { before: true, values: [{ referenceValue: `${DOCS}/cg/a/items/2` }] },
          { before: true, values: [{ referenceValue: `${DOCS}/cg/b/items/1/items/deep` }] },
        ],
      },
    },
    reason:
      "The official emulator does not implement PartitionQuery (UNIMPLEMENTED); fireemu " +
      "splits a collection group ordered by `__name__` into cursors, for parallel readers.",
  },
  "queries/aggregations#several-aggregations": {
    fireemu: {
      status: 200,
      code: "OK",
      body: [
        {
          done: true,
          readTime: "<now>",
          result: {
            aggregateFields: {
              avg_d: { doubleValue: "NaN" },
              capped: { integerValue: "1" },
              sum_n: { doubleValue: 9223372036854776000 },
              total: { integerValue: "6" },
            },
          },
        },
      ],
    },
    reason:
      "When one request carries several aggregations, the official emulator restricts every " +
      "aggregation to the documents that hold each aggregated field (a count next to " +
      "`avg(d)` counts only the documents with `d`). fireemu counts every matching document " +
      "and sums over the documents that hold the summed field, as each aggregation is " +
      "documented on its own.",
  },
  "queries/aggregations#count-beside-a-sum-over-a-missing-field": {
    fireemu: {
      status: 200,
      code: "OK",
      body: [
        {
          done: true,
          readTime: "<now>",
          result: {
            aggregateFields: { sum_d: { doubleValue: "NaN" }, total: { integerValue: "6" } },
          },
        },
      ],
    },
    reason: "The isolated form of the several-aggregations row: the count is 6, not 4.",
  },
  "queries/aggregations#count-beside-an-avg-over-a-missing-field": {
    fireemu: {
      status: 200,
      code: "OK",
      body: [
        {
          done: true,
          readTime: "<now>",
          result: {
            aggregateFields: { avg_d: { doubleValue: "NaN" }, total: { integerValue: "6" } },
          },
        },
      ],
    },
    reason: "The isolated form of the several-aggregations row, with an average.",
  },
  "transactions/lifecycle#get-with-transaction-query-parameter": {
    fireemu: {
      status: 200,
      code: "OK",
      body: document("tx/counter", { value: { integerValue: "0" } }),
    },
    reason:
      "The official emulator's REST adapter cannot decode a bytes-typed query parameter " +
      "(`?transaction=`): it logs 'Unmapped JavaType: BYTE_STRING' and never answers the " +
      "request. fireemu serves the read at the transaction's snapshot.",
  },
  // The transaction contention family (`out-of-band-write`, `contended-commit-is-aborted`,
  // `counter-keeps-the-out-of-band-value`, `phantom-write`, `commit-after-a-phantom-row`)
  // is no longer a divergence: fireemu now takes pessimistic locks like the official
  // emulator, so a write against a document a live read-write transaction has read (or a
  // collection its query scanned) waits and is refused with ABORTED "Transaction lock
  // timeout.", and the transaction commits. Those rows are gated directly against the oracle.
  "errors/rest-shapes#run-query-without-from": {
    fireemu: { status: 400, code: "INVALID_ARGUMENT" },
    reason:
      "A StructuredQuery without a collection selector scans every collection under the " +
      "parent on the official emulator; fireemu requires the selector (INVALID_ARGUMENT), " +
      "the shape every SDK sends.",
  },
  "errors/rest-shapes#from-with-empty-collection-id": {
    fireemu: { status: 400, code: "INVALID_ARGUMENT" },
    reason:
      "An empty collection id is the selector-less query above on the official emulator; " +
      "fireemu refuses the empty identifier.",
  },
  "errors/rest-shapes#write-to-another-database": {
    fireemu: { status: 400, code: "INVALID_ARGUMENT" },
    reason:
      "The official emulator commits a write whose document name belongs to another " +
      "database than the request's route (and creates that database). fireemu keeps a " +
      "commit inside the database it was addressed to, the tenancy boundary that its " +
      "sessions, snapshots and Security Rules are scoped by.",
  },
  "errors/rest-shapes#list-with-bad-page-token": {
    fireemu: { status: 400, code: "INVALID_ARGUMENT" },
    reason:
      "A page token that is not one the listing issued is INVALID_ARGUMENT on fireemu; the " +
      "official emulator fails with an internal error (HTTP 500 UNKNOWN).",
  },
  "emulator/routes#put-rules-without-files": {
    fireemu: { status: 400, code: "INVALID_ARGUMENT" },
    reason:
      "A `:securityRules` body without `rules.files` is refused as INVALID_ARGUMENT; the " +
      "official emulator fails with an internal error (HTTP 500).",
  },
  "emulator/routes#write-to-a-named-database": {
    fireemu: { status: 400, code: "INVALID_ARGUMENT" },
    reason: "The same database boundary as errors/rest-shapes#write-to-another-database.",
  },
  "emulator/routes#database-with-uppercase-name": {
    fireemu: { status: 400, code: "INVALID_ARGUMENT" },
    reason:
      "fireemu validates the database id in the route (lowercase letters, digits and " +
      "hyphens, as production names databases) and refuses `Named`; the official emulator " +
      "serves any database name and answers NOT_FOUND for the document.",
  },
  "reads/read-time#read-at-the-first-update-time": {
    fireemu: {
      status: 200,
      code: "OK",
      body: document("rt/a", { v: { integerValue: "1" } }),
    },
    reason:
      "The official emulator's REST adapter cannot decode a `?readTime=` query parameter " +
      "('Only timestamps past epoch are supported'); fireemu serves the document as of that " +
      "instant from its retained history.",
  },
  "reads/read-time#list-at-the-first-update-time": {
    fireemu: {
      status: 200,
      code: "OK",
      body: { documents: [document("rt/a", { v: { integerValue: "1" } })] },
    },
    reason: "The listing form of the `?readTime=` row above.",
  },
};
