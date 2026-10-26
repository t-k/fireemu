# Local Enterprise text search

Text search is an unreleased Firestore Enterprise Native feature after fireemu 0.29. It is owner-only while Security Rules are configured. Its membership and result order are compared with every recorded production search response and match production for Latin-script text; the known differences are listed under [Production comparison](#production-comparison), and numeric `score()` values are approximate.

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

Each supported text definition becomes a READY index named `file-text-<entry>` (the zero-based index-file position) for the daemon's project and database. These indexes serve text search only; ordinary query planning does not use them. Editing the index file replaces these definitions while the daemon runs; definitions added through the control or Admin API stay. The `*_UNSPECIFIED` enum values read as `TOKENIZED` and `MATCH_GLOBALLY`. An entry that `firebase deploy` accepts but local search cannot serve (an empty or repeated `indexSpecs`, or a field with both `textSpec` and `geoSpec`) is skipped with a note; with `productionExact: true` it stops the daemon instead.

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

A Native Admin build reads each document's language override value. A malformed tag fails the build with `Invalid text language: <value>`, as recorded in production. Any valid tag builds the index, with the same language-neutral analysis; a non-string value fails the build like a malformed tag (a development approximation). With `productionExact: true`, only `en` and `ja`, whose search production has recorded, complete a build. Another valid tag or a non-string value leaves that one build pending: a request that names the index or its operation answers `FS_TEXT_ADMIN_UNVERIFIED`, while index and operation listings and other builds are unaffected. A finished operation can be deleted without reading it first. Under `productionExact`, a pending build of that kind stays CREATING in listings, and a listing leaves out a definition whose view production has not been observed to give (one without `searchIndexOptions`, for example from the index file); a request that names such a definition answers `FS_TEXT_ADMIN_UNVERIFIED`. Search is refused under `productionExact` in any case. Editing the index file resets the state of the file's text indexes to READY with a new build.

For the observed Native Admin invalid-language failure, correcting the same source document to a valid language left the same index in NEEDS_REPAIR and its original operation in FAILED throughout the recorded polling window. Source correction alone does not restart that failed local Native-compatible index. This finite observation does not establish behavior for every failure or an unlimited waiting period.

Deleting and recreating a Native Admin index is a separate lifecycle from the Fireemu session control API's `:repair`. The control operation explicitly allocates a new local build generation in CREATING; it does not revive the failed generation or rewrite the original failed Native operation, and it does not imply that the managed service exposes an equivalent repair API.

Manual lifecycle operations are available on `/v1/sessions/default/firestore/text-indexes/{id}`:

- `POST :failBuild` accepts an optional `reason` and `generation`.
- `POST :repair` accepts an optional `generation` and allocates a new generation in CREATING state.
- `POST :advanceBackfill` accepts `batchSize` from 1 through 10,000 and an optional `generation`. Each advance adds partial postings from the build's frozen initial snapshot; the index remains CREATING.
- `POST :completeBackfill` accepts an optional `generation`. It reconciles against current data and changes the index to READY.

`GET /v1/sessions/default/firestore/text-indexes/{id}` reports the build generation, processed document count, total document count, indexed document count, and failure when present. Build counts describe the last explicit backfill snapshot; fresh READY query execution does not update these counters. Invalid or stale lifecycle requests leave state unchanged. A session reset clears that session's owned builds. Session snapshots clone and restore owned build state while preserving other sessions' state.

## Query behavior

Local search selects the first READY definition in catalog load order that covers every field restriction created by the retained legacy qualified-quoted form, such as `body:"fox"`. It searches only that definition's fields. This qualified-quoted form is an unobserved native behavior retained as a development approximation. Unquoted colon forms are ordinary conjunctive terms and do not restrict fields. Use one definition containing all intended fields when a collection has several text indexes. This is a local planning policy, not a claim about production index selection.

Control-managed backfill advances only through explicit control calls; advancing the virtual clock alone does not schedule those builds.

A query is limited to 8,192 UTF-8 bytes and 64 clauses. The current query language supports AND terms, quoted phrases that must occur in the same field, and exclusions using `-term` or `-phrase`. Queries with no positive searchable terms, including exclusions-only queries, match no documents. The retained legacy qualified-quoted development form applies field restrictions; unquoted colons delimit ordinary conjunctive terms.

Only string values are indexed. Development analysis applies NFKC normalization and retains full default case folding. A scalar whose canonical decomposition consists of one ASCII Latin base followed only by combining marks folds to that base, before case folding for indexed text and after case folding for queries. The query side therefore keeps the mark that case folding splits off `İ`: as recorded in production, the query `İzmir` matches neither `İzmir` nor `izmir`, while `izmir` matches both. Standalone marks and non-Latin bases are retained. This purpose-dependent rule is a bounded approximation, not a reconstruction of the native analyzer. Token boundaries follow UAX #29, except that a colon always separates words (production matched a document holding `title:fox` for the query `fox`). Each CJK ideograph is its own token. Production segments unspaced Han and kana text with a dictionary (`京都` does not match `東京都`), which this analysis does not reproduce, so some recorded CJK and kana memberships still differ (22 of the 223 distinct recorded cases, including the query `İpek`, are known differences). Language codes and tags receive syntactic validation, but analysis remains language-neutral. `retrievalDepth` chooses the newest matching documents before ranking; offset and limit apply afterward.

REST and gRPC capture the immutable source and catalog together. A later search rebuilds from a new snapshot and sees committed writes. This behavior makes no incremental-index performance claim.

### Result order and `score()`

Without a sort, results are ordered newest creation time first. With `sort: score().descending()`, results are ordered by a relevance score, and equal scores keep the newest creation time first, then ascending document path. The relevance score follows the result orders recorded from production:

- Each positive query token contributes more as it occurs more often across the searched fields, with diminishing increments. Occurrences in different fields count together.
- Each pair of consecutive positive query tokens (`a b`) adds a bonus when `a` is immediately followed by `b` in the same field, growing with the number of such adjacencies. One adjacency outweighs one extra occurrence of a token. The reverse order (`b a`), a gap of any size, or the two tokens in different fields earn no bonus. An excluded clause ends the sequence.
- Quoted phrases are scored like the same unquoted tokens; the quotes only restrict which documents match.
- Document length and the rest of the corpus do not affect a document's score: padding words, other documents, other collections and other databases leave it unchanged, as observed in production.

The numeric `score()` values are an approximation (`0.6 × occurrences^(1/3)` per token and `0.3 × adjacencies^(3/4)` per consecutive pair) and may differ from production's values. Production also weighs different terms differently by a term-specific factor that the emulator does not reproduce, so the order of documents that differ only in which query term they repeat is unverified.

## Fidelity and limitations

The emulator's ordinary strict profile works by default. Setting `productionExact: true` still refuses every text search with `FS_TEXT_UNOBSERVED`. Membership matches every recorded production response apart from the cases listed under Production comparison, and score ordering reproduces every recorded production order (see Result order and `score()`), but numeric scores are not production values and analysis beyond the recorded cases is a language-neutral approximation.

The current implementation does not support stemming, synonyms, typo tolerance, morphology, or language autodetection. It also does not support geospatial stages, general boolean-expression trees, search-stage select, nested score aliases, non-score sort, transactions, `readTime`, proxy mode, or full Admin index management.

For the managed service's text-search concepts and query syntax, see [Cloud Firestore Enterprise text search](https://firebase.google.com/docs/firestore/enterprise/text-search). That documentation describes the product; this emulator's lexical behavior remains approximate and should not be treated as proof of parity.


## Production comparison

Every recorded production search response is replayed through the local engine (the FS-TEXT-SEARCH closure, [`spec/compatibility/closure/FS-TEXT-SEARCH.json`](../spec/compatibility/closure/FS-TEXT-SEARCH.json)): 531 responses, 223 distinct queries on their recorded corpora, and both rounds of the Boundary03 cells. Result order matches production on all 64 score-sorted cases and on all 104 unsorted cases (in 8 of them for the documents both sides return). The 22 membership differences that remain (20 CJK/kana plus 2 `İpek`) are known differences, and Japanese/CJK segmentation and dotted capital I handling are future work; they are listed by name in `crates/fireemu-core-firestore/tests/text_membership_replay.rs`:

- Unspaced Han and Katakana text. Production segments it with a dictionary: `京` does not match `京都` or `東京`, `都` and `東京都` do not match `京都東京駅東京都京都東京駅`, `吉` does not match `吉野家`, and `ネムラ・ﾈﾑﾗ` matches only `ネムラネムラ`. Local analysis makes each Han ideograph a token and keeps a Katakana run whole (20 recorded cases).
- `İpek`. Production matched it against both `İpek` and `ipek`, while `İstanbul`, `İzmir`, `İnci` and `İzunex` matched nothing; the local query analysis follows the second group (2 recorded cases).

The Native Admin lifecycle and the recorded refusals are compared over REST. Production answered 409 `ALREADY_EXISTS` for a short time when a deleted text index was created again; local creates it at once.

## Verify SDK interoperability locally

After installing the pinned conformance dependencies and building fireemu, run `FIREEMU_BINARY=/absolute/path/to/fireemu pnpm -C conformance text-search:local`. The check creates a disposable Enterprise world, compares Admin gRPC and Web Lite searches, exercises backfill failure and repair, and verifies updates and deletes. It refuses non-loopback endpoints and never selects a production project. This is a local interoperability check, not a production-equivalence observation.

The adapter helper `tokenize` retains the legacy lexical-v1 behavior for compatibility. Runtime query and index paths use `tokenize_query` and `tokenize_index`; their term and position encodings stay compatible although the fold order differs.
