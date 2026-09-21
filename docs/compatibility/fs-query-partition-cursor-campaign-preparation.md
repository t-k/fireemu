# FS-QUERY-INDEX PartitionQuery and cursor campaign preparation

Status: `IMPLEMENTING`

Campaign ID: `FS-QUERY-PARTITION-CURSOR-04`

This record prepares a bounded production observation of Firestore `PartitionQuery`
and query cursors for the [FS-QUERY-INDEX row](ip-fs-production-compatibility.md)
of the Identity Platform and Firestore Standard production-compatibility goal. It
is preparation only. No production operation, Cloud read, credential use or index
deployment occurred, and production-unobserved conditions are reduced by zero.
Vector and index-merge conditions are owned elsewhere and are out of scope here.

## What the blocking condition asks for

The FS-QUERY-INDEX row records that partitions and several filter, cursor and
Explain conditions still need representative production comparison. Searching the
retained evidence confirms the gap for this lane: `partitionCount` appears in the
API denominators and in the local-only run
[`a12183a0-partition.json`](../../spec/compatibility/broad-runs/a12183a0-partition.json),
which records `productionExecuted: false`, and in no production run. The only
production queries carrying `offset` are the Explain cases with `limit: 0` and
`offset: 0` on collection `items`. No production run carries `startAt`, `endAt`,
`startAfter`, `endBefore` or a partition request. The bare descending `__name__`
ordering and the index-merge acceptance rules were already observed in production
on 2026-09-08 and are deliberately not re-observed.

## Two structural facts that shaped the case set

The first draft placed every partition operation under the owned document parent
so the campaign would touch nothing else. The local runtime refused all of them
with `INVALID_ARGUMENT` and the message that the parent must be the database,
which matches the REST reference: `PartitionQuery` takes a database resource
name, not a document resource name. Owned isolation therefore cannot come from
the parent. It comes instead from a nonce-unique collection group named
`o4pc<nonce>`, so a database-wide partition query still matches only this run's
own twelve documents. The document-parent refusal is kept as a negative control
rather than removed, because confirming it in production is worth one request.

The second draft expected at most `partitionCount - 1` split points. The local
runtime returned two cursors for `partitionCount: 2`, which again matches the
reference: `partitionCount` is the desired maximum number of partition points, so
`n` split points describe `n + 1` ranges. The reconstruction slots are therefore
bound to the single-split-point response, which needs at most two ranges and
keeps the collector bounded by construction.

## Case set

One root marker document, twelve collection-group documents below `part/p0..p2`
and eight `cur` documents are created under
`oracle/{nonce}/o4-query-partition-cursor/root`. Every document carries an
integer `n` and a string `g`.

Setup and baseline, five slots: typed absence of the root, conditional creation,
one commit of twenty documents, the database-wide collection-group query ordered
by `__name__`, and the `cur` collection ordered by `n`.

Partitions, thirteen slots: `partitionCount` one and four, a paged request with
`pageSize` two, a continuation bound to the returned page token, six negative
controls (document parent, no `allDescendants`, a filter, `partitionCount` zero, a
limit, an offset), one ordering control on an indexed field, and two
reconstruction ranges derived from the single-split-point response.

Cursors, twelve slots: `startAt` and `startAfter` on a value, `endAt` and
`endBefore` on a value, `startAt` on a document reference under a `__name__`
order, `offset` with `limit`, `startAt` combined with `offset` and `limit`, a
descending order with a limit as the wire form of `limitToLast(3)`, and four
negative controls (a cursor with more values than order clauses, a string value
against a `__name__` order, a reference outside the query's collection, and a
negative offset).

One post-state readback closes the observation phase. Recovery is six slots: an
ownership read, one version-bound batch delete of the twenty seeded documents, a
version-bound delete of the root, and three absence verifications.

Each accepted case names its exact expected documents. Each negative case expects
a typed `INVALID_ARGUMENT` refusal, except the ordering control on an indexed
field, whose typed code is recorded rather than pinned: locally that request
fails index admission with `FAILED_PRECONDITION` before any partition-shape
check, and which check answers first in production is itself the observation.

## Budget and cost

| Bound | Value |
| --- | --- |
| Wire requests in one run | 37 |
| Owned documents | 21 |
| Document writes including deletes | 42 |
| Concurrency | 1 |
| Cost ceiling | under US$0.01 |

## Owner preconditions

No change to `conformance/firestore.indexes.json` is required and none should be
made. Partition queries order by `__name__` only, which needs no index. Cursor
cases use single-field orders at collection scope, which automatic single-field
indexes already cover. The ordering control is deliberately left unindexed. The
nonce-unique collection group must have no field override, exemption or
time-to-live policy.

The remaining owner inputs are unresolved and are named in the manifest: owner
identity and permission reference, execution window and nonce reservation,
current pricing acceptance and a retention bound for the retained bundle, a typed
production collector with its raw retention boundary, and a named recovery owner
for an interrupted run. `admission_status` reports these as blockers and its gate
always refuses; `validate_permission` accepts no permission while they stand.

## Local shadow

The plan was driven against a `fireemu` built in the lane worktree. The runner
records that binding itself and refuses a binary from another checkout.
The historical run remains immutable at
[`fs-query-partition-cursor-local-shadow.json`](../../spec/compatibility/broad-runs/fs-query-partition-cursor-local-shadow.json).
The current native run is published separately at
[`fs-query-partition-cursor-current-v2-local-shadow.json`](../../spec/compatibility/broad-runs/fs-query-partition-cursor-current-v2-local-shadow.json).
A debug build is not bit-reproducible, so the digest identifies one build
instance rather than the source.

| Binding | Value |
| --- | --- |
| Artifact source commit | `905ede564c6d40498b615183db9f4103756585ba` |
| Rust sources | unchanged from base `3d0e56bdf` |
| Artifact SHA-256 | `3c486cee6cd842039f114bc5d154d71e2b242b18381960716f4e1433e134a9e5` |

The record also carries the SHA-256 of every lane module it was produced by, so
the withdrawal of `O4-REPAIR-001` and every other recorded result can be
reproduced from the recorded commit and those digests rather than taken on
trust. A lane edit that is not followed by a regeneration fails its binding test.

All 37 slots were dispatched and all 37 raw sidecars were published and verified,
cleanup completed, and an independent residual scan proved zero owned documents
with an explicit typed absence. The owned process stopped and its listener
closed. A run that retains no wire bytes, or whose residual scan cannot prove
absence, is reported as indeterminate rather than as a match.

The reconstruction check is made by the tooling, not by hand: the collector
concatenates the dispatched ranges and compares them to the recorded baseline in
order. The run derived two ranges from one split point and their concatenation
reproduced all twelve baseline documents. A range set that fails to rebuild the
baseline fails the run.

Four interrupted-run rehearsals failed the transport at the creation, at the
first baseline query, at a partition query and at a cursor query. Each ended with
zero residual owned documents. The run that lost its creation receipt skipped its
deletions with `no-current-run-ownership` rather than issuing an unproven delete.

## Historical local differences, both unobserved in production

The immutable historical run recorded two cursor-validation conditions that
differed from the documented REST contract. They remain attached to the
historical receipt and were not production observations. The fresh current run
matches all planned local expectations, so these historical differences are no
longer present in the current native shadow.

- `O4-REPAIR-002`, `cursor-reference-type-mismatch`: a string value against a
  `__name__` order is accepted and returns the whole collection.
- `O4-REPAIR-003`, `cursor-foreign-reference`: a reference outside the query's
  collection is accepted and returns an empty result.

A third ticket was withdrawn. `O4-REPAIR-001` claimed that a cursor carrying more
values than its order clauses was accepted, but the case sent only two values
against an order that Firestore normalizes to `[n, __name__]`, so it never tested
cardinality; the second value was a type mismatch in the `__name__` position,
which is `O4-REPAIR-002`. With the case corrected to three values, the runtime
refuses it with `INVALID_ARGUMENT` and the condition holds.

A fourth observation carries no ticket: a `PartitionQuery` whose query orders by a
filtered field is refused locally for a missing index rather than for its shape,
so the two admission checks are ordered differently from what a shape-first
reading would predict.

## What this record does not claim

No production observation occurred, so no FS-QUERY-INDEX condition moves and no
parent promotion is claimed. The expectations for the negative cases rest on the
REST reference and on local behavior, not on observed production responses; the
campaign exists to replace that reasoning with receipts. The comparator
canonicalizes server timestamps to a placeholder because no case in this set
asserts a time relation, and a future case that does must compare them exactly.
