# FS-QUERY-INDEX PartitionQuery and cursor campaign preparation

Status: `IMPLEMENTING`

Campaign ID: `FS-QUERY-PARTITION-CURSOR-04`

This record prepares a bounded production observation of Firestore `PartitionQuery`
and query cursors for the [FS-QUERY-INDEX row](ip-fs-production-compatibility.md)
of the Identity Platform and Firestore Standard production-compatibility goal. It
is preparation only. No production operation, Cloud read, credential use or index
deployment occurred, and production-unobserved conditions are reduced by zero.
Vector and index-merge conditions are owned elsewhere and are out of scope for the
campaign; the [finite condition list](#finite-condition-list) at the end names
them alongside the campaign's own conditions, as facts, without promoting any.

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
| Compiled slots in one run | 37 (31 observation, 6 recovery) |
| Gate-charged requests, completed run | 88 (37 slots, 42 ladder reads, 2 residual scans, 7 management) |
| Gate-charged requests, upper bound | 109 (adds 21 ladder deletes taken only when a read finds a document) |
| Owned documents | 21 |
| Document writes including deletes | 42 |
| Concurrency | 1 |
| Cost ceiling | 10,000 micro-USD (US$0.01), reserved in full against the shared Ledger |
| Wall and recovery reserve | 840 s and 520 s; approval window 1360 s |

The compiled case set is unchanged at 37 slots. The additional requests are the
shared Gate's own cleanup contract: a typed-absence read per owned document, and
a read plus a version-bound delete per document that only send when a document
is still present, which on a completed run is never. They are described under
[Production path](#production-path-o8).

## Owner preconditions

No change to `conformance/firestore.indexes.json` is required and none should be
made. Partition queries order by `__name__` only, which needs no index. Cursor
cases use single-field orders at collection scope, which automatic single-field
indexes already cover. The ordering control is deliberately left unindexed. The
nonce-unique collection group must have no field override, exemption or
time-to-live policy.

The remaining owner inputs are named in the manifest: owner identity and
permission reference, execution window and nonce reservation, current pricing
acceptance and a retention bound for the retained bundle, a named recovery owner
for an interrupted run, and an independent O7 review of the frozen packet. They
enter through the frozen owner permission and the approval of the O8 path below;
the manifest's own `admission_status` still reports them as blockers and its gate
always refuses, and `validate_permission` accepts no permission while they stand.
The typed production collector that the earlier revision listed as missing exists
now; see the next section.

## Production path (O8)

The production path is the same O8 boundary the request-byte campaign uses: an
independently frozen owner permission, an approval minted outside the packet
after an independent review, a private bearer-token handoff on a file descriptor,
and a reservation in the shared Ledger. The launcher is
`tools/compat-broad/fs-query-partition-cursor/partition_cursor_o8.py`; the
descriptor is `tools/compat-broad/o8-core/o4_partition_cursor_descriptor.py`,
and every member the shared admission core requires is real. The only production
origin the lane's wire module can address is `https://firestore.googleapis.com`;
a loopback origin is refused there, and the local collector refuses anything but
a numeric loopback origin, so neither entry point can be steered at the other's
target.

The compiled 37-slot plan is driven unchanged by the lane's own collector. What
the shared Gate adds, in `partition_cursor_gate.py`, is a projection of those
slots onto one Gate job in a frozen schedule, plus a Gate-native recovery ladder:
one read, one version-bound delete and one typed-absence read for each of the 21
owned documents, the root last. The ladder exists for two reasons. The shared
Ledger releases a reservation only when every assigned resource ends with a typed
`NOT_FOUND` read journaled by the Gate, and the compiled plan proves absence with
two queries instead. And the compiled cleanup is one Commit of twenty deletes,
which the Gate cannot host as a recovery slot because a recovery slot must
address a single assigned resource; when a run stops mid-observation, that Commit
is refused by name and the ladder deletes what the seed Commit created, each
delete bound to the version the Gate's own creation proof recorded. On a
completed run the ladder's reads find every document already absent and its
deletes are consumed without a send. Two residual-scan queries run after the
ladder on a completed observation.

Two facts a reviewer should hold before an execution:

- The Gate contract is `shared-local-v1`. The compiled documents carry no
  `_sharedOwner` reference and no nonce field, so no ownership-marker convention
  applies; ownership is the plan's own `conditional-create-plus-exact-fields`
  under the nonce-scoped owned path, which the projection checks.
- The shared Gate does not recognize `partitionQuery` as a read-only RPC, so its
  eleven slots are declared as able to create and the facade settles their
  creation outcome from the typed response. The one consequence is that the
  page-token continuation slot, which the collector skips when the paged
  response carried no token, cannot be consumed without a send. A production
  response without a page token would therefore end the observation at that
  slot; the ladder would still recover every document, and the run would be
  incomplete rather than unsafe. With twelve documents, production is likely
  to return no partition cursors and no page token, so this is the expected
  first production outcome until the shared-Gate change lands; the lane should
  not be scheduled before it. The remedy is a shared-Gate change outside this lane,
  recognizing `partitionQuery` with the closed keys `structuredQuery`,
  `partitionCount`, `pageSize`, `pageToken` as a non-creating read; the
  descriptor's `creatingDeclarationGap` names the affected slots on the record
  until then.

Exit codes: 0, cleanup verified and the reservation released; 1, the run did
not complete and the reservation is still held with a receipt whose
`stopPoint` names the disposition (`aborted-no-data`, `abandoned-cleanup-close`
or `owner-escalation`); 2, admission refused before anything was created. Only
a stop during the management preflight, before any data slot, is retirable as
no data. A stop at the typed-absence read of the root creates nothing, but the
receipt then carries a collector bundle and `productionExecuted` is true, which
the shared no-data contract refuses, so that stop is the owner's; it is named
`preflight-absence` and never claimed as retirable. A lost answer to the root
create or to the seed Commit is never retirable as no data. A later stop closes
through the abandoned-cleanup exit only when every owned document carries a
creation proof and every one is proven absent by the ladder; a partial
creation, the seed Commit refused after the root was created, is proven absent
too but has proofs for one resource, and the shared Ledger refuses the
abandoned close for it, so that stop is the owner's as well. One more shared
rule to know: a run-created document that was modified before the ladder
reached it is never deleted (its version no longer matches the creation
proof), and because a proven resource cannot be skipped, the ladder stalls
there and the documents behind it stay in place for the owner. The receipt
records the first stall as `scheduleStall` with the slot and its cause.

Offline integration proof, executed against a temporary Ledger and an injected
oracle, never the canonical Ledger and never the wire
(`test_partition_cursor_production.py`): all 37 slots dispatched and the
reservation released; an early stop before any create retired as no data; a
transport failure at a cursor slot recovered all 21 documents through the ladder
and closed after abandon; a binding drift refused before any wire; a credential
refusal named and sent nothing. These are local results and not production
evidence.

Launch command line, credential never on the command line:

```text
uv run --python 3.12 python $FROZEN/tools/compat-broad/fs-query-partition-cursor/partition_cursor_o8.py \
  --inputs <pkg>/partition-cursor-frozen-inputs-v1.json \
  --approval $APPROVAL_DIR/partition-cursor-o8-approval-v1.json \
  --manifest <pkg>/partition-cursor-o8-manifest-v1.json \
  --permission <pkg>/partition-cursor-owner-execution-permission-v1.json \
  --source $FROZEN --artifact <retained fireemu> \
  --ledger <canonical shared Ledger root> \
  --output <fresh private directory> --credential-fd 3  3< <private handoff>
```

The handoff is `{"kind": "partition-cursor-bearer-token-v1", "permissionDigest":
<permissionDigest>, "token": <bearer>}`, at most 16 KiB, read only after the
Ledger reservation and the Gate claim.

## Local shadow

The plan was driven against a `fireemu` built in the lane worktree. The runner
records that binding itself and refuses a binary from another checkout.
The historical run remains immutable at
[`fs-query-partition-cursor-local-shadow.json`](../../spec/compatibility/broad-runs/fs-query-partition-cursor-local-shadow.json),
as does the v2 run at
[`fs-query-partition-cursor-current-v2-local-shadow.json`](../../spec/compatibility/broad-runs/fs-query-partition-cursor-current-v2-local-shadow.json)
(source commit `905ede564c6d40498b615183db9f4103756585ba`, artifact SHA-256
`3c486cee6cd842039f114bc5d154d71e2b242b18381960716f4e1433e134a9e5`, `MATCHED`).
The current native run, made after the production path landed so that the
record binds those lane modules too, is published at
[`fs-query-partition-cursor-current-v3-local-shadow.json`](../../spec/compatibility/broad-runs/fs-query-partition-cursor-current-v3-local-shadow.json).
A debug build is not bit-reproducible, so the digest identifies one build
instance rather than the source.

| Binding | Value |
| --- | --- |
| Artifact source commit | `75d2aba93400d34c7afce301be90a49c2751e836` |
| Rust sources | unchanged from the integration head `24b8d0a6e` the branch is rebased onto |
| Artifact SHA-256 | `d6484c7157a94a02d3e3cb42cecef97a29490ee1f6cee3f4bd4c6db604d60607` |
| Result | `MATCHED`, 37 of 37 raw sidecars, reconstruction matches, zero residual documents |

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

## Finite condition list

The FS-QUERY-INDEX row's closure sentence is not a finite list. This section
names every condition the row declares, with what exists for each. It states
facts about evidence classes and promotes nothing; the acceptance table itself
lives in the [row](ip-fs-production-compatibility.md) and is not edited here.
Evidence classes: `immutable receipt` is a live production observation with a
retained receipt under `spec/compatibility`; `saved-reference replay` is a local
artifact compared against an unchanged production receipt; `check without
receipt` is a production comparison whose output was not retained as an
immutable receipt; `unobserved` means no production observation exists.

| Condition | Implemented | Local test | Production evidence class | Campaign |
| --- | --- | --- | --- | --- |
| Filter and order combinations on missing fields and mixed types (`orderBy` on a missing field excludes documents, type-restricted range filters, `values/type-order`) | `crates/fireemu-core-firestore/src/query.rs` | conformance matrix against the official emulator (`conformance/firestore-matrix.json`) | immutable receipt: the live 2026-09-07 corpus `conformance/firestore-production-matrix.json` covers the named cases; the full missing-type matrix beyond them is unobserved | none prepared |
| Aggregation (`count`, `sum`, `avg`, intersection, boundary controls) | runtime ordering and validation fixed at `fe37fe0` (2026-09-10) | local corpus, [aggregation evidence](aggregation-evidence.md): revised corpus 14/14 locally | immutable receipt: the revised corpus matched 14/14 in a fresh production run with scoped approval (2026-09-10), and 23/23 saved production aggregation observations replay on the current artifact; the historical 9/10 receipt for `count + sum(x)` with `limit: 2`, missing and non-numeric `x` and no explicit order (old local `sum=10`, production `sum=30.5`) is retained in history unchanged, not rewritten; the local issue `aggregation-limit-default-order-production-divergence` stays open for its bounded follow-up (explicit `__name__ ASC` and `x ASC` variants with document-ID comparison), not for a current divergence | none prepared beyond that follow-up |
| Explain (`explainOptions`, plan and execution stats) | Explain v5/v9 | 117-test Explain suite | saved-reference replay: [current Explain v5 replay](query-explain-current-saved-reference-v5.md), 12/12 on `cce4a4f9b` against the unchanged receipt; the original observation is immutable | `prod-campaign-explain-01` v9 (executed historically) |
| Index merge and exemption acceptance (equality merge, `__name__` under wildcard exclusion, bare `orderBy(__name__, desc)`) | `index.rs`, `index_usage.rs`, `crates/fireemu/src/control.rs` (indexes file including `vectorConfig`) | `244dc525-index-merge-local.json` 20-case strict SDK regression; `tests/index.rs` | check without receipt: `tools/sdk-smoke/index-merge-oracle.mjs` on 2026-09-08 (equality merge accepted, `__name__` unaffected by wildcard exclusion, bare descending `__name__` refused without an explicit index); no immutable receipt under `spec/compatibility` | none prepared |
| Vector `findNearest` (euclidean, cosine, dot product, dimension and non-vector exclusion, limit and threshold) | Standard local execution, REST and gRPC | `crates/fireemu-core-firestore/tests/execute.rs` nearest-vector tests | unobserved; the official emulator refuses `findNearest` on REST while fireemu serves it, a documented non-parity claim | none prepared |
| PartitionQuery (database parent, `partitionCount`, `pageSize` and page token, refusals for document parent, non-group query, filter, zero count, limit, offset, non-`__name__` order; range reconstruction) | `crates/fireemu-adapter-grpc/src/local.rs` partition path, `query.rs` | `local.rs` partition reconstruction test; this lane's 37-slot shadow v3 `MATCHED` | unobserved | `FS-QUERY-PARTITION-CURSOR-04`, production path prepared (this record); execution not performed |
| Cursor validation (`startAt`, `startAfter`, `endAt`, `endBefore`, reference cursor under `__name__`, offset with limit, `limitToLast` wire form, too many values, reference type mismatch, foreign reference, negative offset) | `query.rs` cursor rules, strict-only via `IndexValidationPolicy::Production` | `crates/fireemu-core-firestore/tests/query.rs` cursor suite; shadow v3 `MATCHED` | unobserved | `FS-QUERY-PARTITION-CURSOR-04`, as above |
| Projection, offset, limit and collection-group queries outside the cases above | `query.rs` | conformance matrix | immutable receipt for the cases the 2026-09-07 corpus and the Explain setup queries carry; other shapes unobserved | none prepared |

No condition moves on this list. The partition and cursor rows are the only
ones with a prepared production path, and that path has not been executed.
