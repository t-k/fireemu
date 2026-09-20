# O4 PartitionQuery and cursor preparation

This directory contains credential-free preparation for a bounded production
observation of Firestore `PartitionQuery` and query cursors. Nothing here opens a
production connection, reads a credential, mutates an index or Rules, or claims
production compatibility. Production admission is closed and cannot be opened.

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

`partition_cursor_collector.py` drives the plan against a loopback origin. It
refuses any other origin before creating its output directory or sending a single
request, which is what keeps it from being usable as a production entry point.
Two operations are bound at run time: the continuation request takes its
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
this revision. It is left byte-for-byte unchanged. The fresh native run is
published at
`spec/compatibility/broad-runs/fs-query-partition-cursor-current-v2-local-shadow.json`.
It was generated from source commit `4130d105b0e157f6a807594c761a3fac84a19819`
using `target/debug/fireemu`, retained all 37 raw sidecars, completed cleanup,
proved zero residual documents and returned `MATCHED`. Its artifact SHA-256 is
`bccacc0a7d3f8a42dba9b4c6b6a0c693082f600690dd5d337a02f56287fd42b1`.
Current preparation also lives in
`spec/compatibility/broad-runs/fs-query-partition-cursor-preparation-v2.json`;
preparation is non-authorizing. Its source closure includes the fixed HTTP
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
