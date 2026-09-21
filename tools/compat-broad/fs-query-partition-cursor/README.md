# O4 PartitionQuery and cursor preparation

This directory contains the preparation and the typed production path for a
bounded production observation of Firestore `PartitionQuery` and query cursors.
Nothing here claims production compatibility, mutates an index or Rules, or
discovers a credential. The only way to the production wire is the O8 launcher
described below, which takes an independently frozen owner permission, an
approval minted outside the packet, a private credential handoff and a shared
Ledger reservation; no test in this directory reaches it.

## Modules

`partition_cursor_case.py` compiles a fixed plan of 31 observation and 6 recovery
operations for one project, database and 32-character nonce. It owns 21
documents: one root marker, twelve documents in a nonce-unique collection group
below `part/p0..p2`, and eight documents in a `cur` collection. `validate_plan`
rejects a changed request, scope, fixture, budget or digest.

Two structural facts shape the plan. Production requires a database parent for
`PartitionQuery`, so every accepted partition operation is database-wide and
isolation comes from the nonce-unique collection group rather than from a
document parent. `partitionCount` bounds the number of split points, so a request
for `n` may return `n` cursors and `n + 1` ranges.

`partition_cursor_collector.py` drives the plan through one injected transport.
`collect_local` refuses any origin outside the numeric loopback set and
`collect_production` refuses any origin other than the fixed production host,
each before creating its output directory or sending a single request. Two
operations are bound at run time: the continuation request takes its
`pageToken` from the recorded paging response, and two reconstruction slots take
their range cursors from the recorded single-split-point response. A response
that would need more than two ranges sends nothing and records
`reconstruction-slots-exceeded`. Cleanup deletions carry the `updateTime` values
recorded in the same run; a missing creation receipt or an unbound write version
skips the delete instead of issuing it.

Each dispatched row publishes an immutable JSON file with an exclusive link and
`fsync`, and, when the transport supplies complete response bytes, one immutable
`.raw` sidecar below `raw/` with its SHA-256 digest in `raw/manifest.json`.
Absent, partial or oversized transport bytes stay compact evidence and set
`raw.complete` false; the collector never reconstructs raw bytes from the decoded
body.

`partition_cursor_shadow.py` states the expected local answer for every slot,
validates a collected bundle against that table, and can drive one owned local
artifact end to end. `KNOWN_LOCAL_DIFFERENCES` names the open repair tickets, so
a run whose only differences are ticketed is `DIFFERENT_KNOWN` and a repair moves
it to `MATCHED`.

`partition_cursor_comparator.py` compares two retained bundles. Each side is
validated against a plan recompiled from its own recorded identity, so runs with
different nonces can be compared. Owned identities, opaque pagination tokens,
server-assigned timestamps, response byte counts and content-type parameters are
canonicalized; Firestore Value types, query shapes, document order and typed
error objects stay exact. The result is semantic only and always keeps
`acquisitionValidated` and `promotionReady` false.

`partition_cursor_manifest.py` freezes the lane source digests, the wire and
resource budget, the owner preconditions and the reasons admission stays closed.
It contains no transport and no credential handling.

`partition_cursor_offline_fixture.py` is test support: an offline transport that
answers the compiled plan without any socket.

## Production path (O8)

| Module | Role |
| --- | --- |
| `partition_cursor_wire.py` | one fixed child for both modes; the production mode addresses `https://firestore.googleapis.com` only, with the bearer on stdin, and a loopback origin is refused there |
| `partition_cursor_gate.py` | projection of the 37 compiled slots onto one shared-Gate job with a frozen schedule; a Gate-native recovery ladder (read, version-bound delete, typed-absence read per owned document, 63 slots); two residual-scan slots; the `PartitionCursorGate` facade that maps each collector request onto its frozen slot after verifying run-time bound values (page token, partition cursors, delete versions) against this run's own journal |
| `partition_cursor_preflight.py` | the request-byte lane's reviewed management preflight (tokeninfo, project, database, auth) driven for this campaign's Gate and Ledger ticket |
| `partition_cursor_admission.py` | frozen inputs over a clean source snapshot, owner permission binding, Gate reservations, Ledger claim, stop-point classification |
| `partition_cursor_production.py` | one admitted acquisition: reserve, claim, credential, preflight, collector through the Gate, ladder, residual scans, postflight, receipt, release; `verify_saved` re-validates the whole chain offline |
| `partition_cursor_o8.py` | the launcher; exit 0 released, 1 held with a receipt naming the disposition, 2 refused before anything was created |
| `../o8-core/o4_partition_cursor_descriptor.py` | every member the shared admission core requires, real |

The shared Gate's closed scenario model is per-document, and the compiled
plan's cleanup is one Commit of twenty deletes plus two absence queries. The
projection keeps the plan as it is and adds the ladder so that every owned
document ends with the typed absence the Ledger requires and so that a run that
stops after the seed Commit still has an admissible way to delete what it
created. On a completed run the ladder's deletes are consumed without a send
because its reads find every document already absent. One run charges at most
109 requests (37 plan slots, 63 ladder slots, 2 residual scans, 7 management);
a completed run sends 88.

Two facts a reviewer should read before an execution:

- The Gate contract is `shared-local-v1`: the compiled documents carry no
  `_sharedOwner` reference and no nonce field, so no ownership-marker
  convention applies. Ownership is the plan's own
  `conditional-create-plus-exact-fields` under the nonce-scoped owned path.
- The shared Gate does not recognize `partitionQuery` as a read-only RPC, so
  its eleven slots are declared as able to create. The facade settles their
  creation outcome from the typed response. The one consequence is that the
  page-token continuation slot, which the collector skips when the paged
  response carried no token, cannot be consumed zero-wire; a production
  response without a page token, likely for twelve documents, ends the
  observation at that slot, the ladder cleans up, and the run is incomplete
  (`test_the_slot_eight_early_end_is_recorded_incomplete_and_recovered` pins
  this). `creating_declaration_gap` names the slots, and the fix is a
  shared-Gate change outside this lane; do not schedule the run before it.

Run the focused checks with:

```text
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/fs-query-partition-cursor
```

## Historical local shadow

The runner records the artifact it executes, refuses a binary built outside this
worktree, and publishes the committed record at
`spec/compatibility/broad-runs/fs-query-partition-cursor-local-shadow.json`. This
record is immutable historical evidence. A
debug build is not bit-reproducible, so the digest identifies one build instance
while the commit identifies its source.

| Binding | Value |
| --- | --- |
| Artifact source commit | `0d1477487` |
| Rust sources | unchanged from base `3d0e56bdf` |
| Artifact SHA-256 | `47b2b5bb3833235704f851c647a85c2343dd92422753593313cbe83c785b4e91` |

The record also carries the SHA-256 of every lane module it was produced by, so
the withdrawal of `O4-REPAIR-001` and every other recorded result can be
reproduced from the recorded commit and those digests rather than taken on
trust. A lane edit that is not followed by a regeneration fails its binding test.

All 31 observation and 6 recovery slots were dispatched, all 37 raw sidecars were
published and verified, the concatenated partition ranges reproduced the baseline,
cleanup completed and an independent residual scan proved zero owned documents.
The owned process stopped and its listener closed.

`validate_shadow` refuses to read a verdict out of a run that retained no wire
bytes, and the residual scan reports an unknown rather than zero when the root
read neither succeeds nor returns a typed absence.

Two cursor-validation differences remain, each an open repair ticket under
`docs.local/issues/open/`: `cursor-reference-type-mismatch` and
`cursor-foreign-reference`. Four interrupted-run rehearsals, failing at the
creation, at the first baseline query, at a partition query and at a cursor
query, each ended with zero residual owned documents; the run that lost its
creation receipt skipped its deletions rather than issuing them.

This verifies the local observation tooling and the local runtime answers. It is
not a production observation, a saved-production comparison or a parent
compatibility promotion.

## Current local shadow and integrity revision (offline v23)

The old local-shadow record above is **historical**, not execution evidence for
this revision. It is left byte-for-byte unchanged, as is the `current-v2` record
(source commit `905ede564c6d40498b615183db9f4103756585ba`, artifact SHA-256
`3c486cee6cd842039f114bc5d154d71e2b242b18381960716f4e1433e134a9e5`, `MATCHED`).
The current native run is published at
`spec/compatibility/broad-runs/fs-query-partition-cursor-current-v3-local-shadow.json`
and binds the lane modules of the production path as well; its artifact
commit and digest are in the record. Current preparation lives in
`spec/compatibility/broad-runs/fs-query-partition-cursor-preparation-v3.json`
(v2 is historical); preparation is non-authorizing. Its source closure includes the fixed HTTP
worker and the shared `batch_wire.py` decoder.

The collector now requires explicit-port numeric loopback origins, not DNS names
(including localhost), URL credentials, query strings or fragments. The fixed
worker disables redirects and proxy inheritance and retains exact response bytes.
One existing 20-second post-spawn deadline covers headers, body and worker exit;
no retries are added. Process creation/kill/reap or a stalled OS are not bounded.
The HTTP response cap remains 64 KiB and is a local defensive limit, not a service
quota. Invalid/incomplete worker responses are failures, not typed API evidence.

Before using a response for control, versions, query comparison or typed absence,
its complete UTF-8 JSON bytes must match the decoded body, including nested types.
Diagnostic raw sidecars are not themselves proof that a response is usable. A
bad preflight, root-create or seed acknowledgement stops further observation;
recovery still follows the existing same-run ownership/version checks. Ordinary
query semantic mismatches remain recorded and do not grant cleanup authority.
Publication errors do not grant ownership, and short writes are completed or
reported as failures rather than published as success.

Partition reconstruction compares document names **and fields**, preserving
Firestore Value types but not requiring server-time metadata equality. Returned
cursors must fit the finite `__name__`-only lane, and reconstruction accepts only
references in that operation's already-frozen target set. Query error objects are
never counted as an empty result. The independent residual scan also requires
complete, byte-bound query/404 responses; an unknown result is not zero.

The new tests use artificial API responses, including real local TCP and fixed
worker processes. They do not run the Rust emulator or Firebase SDK. A new native
shadow, source/artifact binding and independent review remain required; the old
shadow's digests must not be relabelled to satisfy current-source checks.

Invalid or incomplete byte-bound observations remain INDETERMINATE even when their diagnostic raw sidecars were fully retained. They are not semantic differences.
