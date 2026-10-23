# Local Enterprise text search

Text search is an unreleased Firestore Enterprise Native feature after fireemu 0.29. It is owner-only while Security Rules are configured. This guide describes the current emulator behavior; it does not claim exact production parity.

## Configure a text index

Enable Enterprise Native mode and point `indexFile` at the Firebase CLI index file:

```json
{
  "schemaVersion": 1,
  "firestore": {
    "edition": "enterprise",
    "apiMode": "native",
    "indexFile": "firestore.indexes.json"
  }
}
```

A text index entry lists its searchable fields using `TOKENIZED` and `MATCH_GLOBALLY`:

```json
{
  "indexes": [{
    "collectionGroup": "products",
    "queryScope": "COLLECTION",
    "fields": [
      { "fieldPath": "title", "searchConfig": { "textSpec": { "indexSpecs": [{ "indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY" }] } } },
      { "fieldPath": "body", "searchConfig": { "textSpec": { "indexSpecs": [{ "indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY" }] } } }
    ]
  }]
}
```

Each supported text definition becomes a READY index named `file-text-<entry>` (the zero-based index-file position) for the daemon's project and database. These indexes serve text search only; ordinary query planning does not use them.

## Run a search

Keep text search options inside `.search(...)`. For the Admin SDK, import `documentMatches` and `score` from `@google-cloud/firestore/pipelines`; the Web Lite SDK exports them from `firebase/firestore/lite/pipelines` and executes with `execute(pipeline)`. For example:

```js
const results = await db.pipeline()
  .collection("products")
  .search({
    query: documentMatches("waffles -coffee"),
    sort: score().descending(),
    addFields: [score().as("rank")],
  })
  .execute();
```

The search stage accepts its own score sort and score projection. General pipeline `.sort(...)` and `.addFields(...)` after `.search(...)` are not supported. Search currently supports collection pipelines only.

Text indexes can also be managed through the session control API. A manual definition can set `xFirebaseTestd.buildPolicy` to `"manual"`; it starts in CREATING by default. An explicit state can override that default. Definitions with no build policy, synchronous builds, and legacy `validation-only` definitions default to READY. A READY index reconstructs postings from the query's captured source snapshot. CREATING and NEEDS_REPAIR indexes never serve queries, even when partial posting data exists.

Manual lifecycle operations are available on `/v1/sessions/default/firestore/text-indexes/{id}`:

- `POST :failBuild` accepts an optional `reason` and `generation`.
- `POST :repair` accepts an optional `generation` and allocates a new generation in CREATING state.
- `POST :advanceBackfill` accepts `batchSize` from 1 through 10,000 and an optional `generation`. Each advance adds partial postings from the build's frozen initial snapshot; the index remains CREATING.
- `POST :completeBackfill` accepts an optional `generation`. It reconciles against current data and changes the index to READY.

`GET /v1/sessions/default/firestore/text-indexes/{id}` reports the build generation, processed document count, total document count, indexed document count, and failure when present. Build counts describe the last explicit backfill snapshot; fresh READY query execution does not update these counters. Invalid or stale lifecycle requests leave state unchanged. A session reset clears that session's owned builds. Session snapshots clone and restore owned build state while preserving other sessions' state.

## Query behavior

Local search selects the first READY definition in catalog load order that covers every field restriction created by the retained legacy qualified-quoted form, such as `body:"fox"`. It searches only that definition's fields. This qualified-quoted form is an unobserved native behavior retained as a development approximation. Unquoted colon forms are ordinary conjunctive terms and do not restrict fields. Use one definition containing all intended fields when a collection has several text indexes. This is a local planning policy, not a claim about production index selection.

Backfill advances only through explicit control calls; advancing the virtual clock alone does not schedule background builds.

A query is limited to 8,192 UTF-8 bytes and 64 clauses. The current query language supports AND terms, quoted phrases that must occur in the same field, and exclusions using `-term` or `-phrase`. Queries with no positive searchable terms, including exclusions-only queries, match no documents. The retained legacy qualified-quoted development form applies field restrictions; unquoted colons delimit ordinary conjunctive terms.

Only string values are indexed. Development analysis applies NFKC normalization and retains full default case folding. A scalar whose canonical decomposition consists of one ASCII Latin base followed only by combining marks folds to that base, before case folding for indexed text and after case folding for queries. Standalone marks and non-Latin bases are retained. This purpose-dependent rule is a bounded approximation, not a reconstruction of the native analyzer. The existing UAX #29 token boundaries and individual CJK ideographs remain unchanged; native CJK segmentation is still unverified. Language codes and tags receive syntactic validation, but analysis remains language-neutral. The score is an approximate BM25 score. Results use creation time descending and document path ascending to break ties. `retrievalDepth` chooses the newest matching documents before ranking; offset and limit apply afterward.

REST and gRPC capture the immutable source and catalog together. A later search rebuilds from a new snapshot and sees committed writes. This behavior makes no incremental-index performance claim.

## Fidelity and limitations

The emulator's ordinary strict profile works by default. Setting `productionExact: true` refuses every text search with `FS_TEXT_UNOBSERVED` until the search behavior has been compared with actual production observations. The lexical matching behavior is approximate and does not claim production parity.

The current implementation does not support stemming, synonyms, typo tolerance, morphology, or language autodetection. It also does not support geospatial stages, general boolean-expression trees, search-stage select, nested score aliases, non-score sort, transactions, `readTime`, proxy mode, or full Admin index management.

For the managed service's text-search concepts and query syntax, see [Cloud Firestore Enterprise text search](https://firebase.google.com/docs/firestore/enterprise/text-search). That documentation describes the product; this emulator's lexical behavior remains approximate and should not be treated as proof of parity.


## Verify SDK interoperability locally

After installing the pinned conformance dependencies and building fireemu, run `FIREEMU_BINARY=/absolute/path/to/fireemu pnpm -C conformance text-search:local`. The check creates a disposable Enterprise world, compares Admin gRPC and Web Lite searches, exercises backfill failure and repair, and verifies updates and deletes. It refuses non-loopback endpoints and never selects a production project. This is a local interoperability check, not a production-equivalence observation.

The adapter helper `tokenize` retains the legacy symmetric lexical-v1 behavior for compatibility. Runtime query and index paths use `tokenize_query` and `tokenize_index`; their term and position encodings must remain compatible even though normalization purpose differs.
