# Non-production recovery integrity — offline v11

This is local preparation, not production authorization or native/SDK parity.
All historical production permissions, receipts and parent acceptance states are
unchanged. The v10 AUTH-ACTION recovery/HTTP checks are retained. This update
addresses the remaining local FS-RULES and FS-LISTEN-SDK driver boundaries.

## FS-RULES setup rollback

Setup keeps a private append-only, fsynced intent/acknowledgement journal.
Fixture writes use `currentDocument.exists=false`; acknowledgements must name
the exact document, preserve its fields and carry a valid version. Incomplete
setup rolls back only attempted resources. It deletes confirmed creations at
their acknowledged version, then requires typed final absence. Confirmed account
UIDs are similarly read, deleted and read again. A changed version, missing UID,
lost acknowledgement or ambiguous result stays outstanding. A rejected
conditional create never grants ownership of the pre-existing document.

Each rollback is single-use, with at most three requests per attempted resource
and a separate, at most 600-second admission window. Failure of one resource
does not prevent recovery attempts on unrelated resources within that reserve.
A tenant creation without a valid returned resource name cannot become "no
creation". Tenant deletion requires its final GET to report typed
TENANT_NOT_FOUND. Deletion's 200 alone is not proof. Successful rollback does
not make the failed observation complete.

## FS-RULES parent and evidence

The parent requires a fresh output directory and launches a new owned process
group. Timeout or exception attempts bounded teardown. A reaped leader alone
does not prove the group empty. The parent does not signal a different group,
nor blindly signal a group after its leader has been reaped. Missing endpoints,
connection timeouts and permission errors are not proof of closed listeners;
only connection refusal at an explicit numeric-loopback address is accepted.

A bounded, regular, non-symlink child receipt must match the nonce and strict
typed acceptance flags. Exit zero by itself is insufficient. Duplicate JSON
keys and non-finite constants are refused. Child bytes remain unchanged;
`parent-result.json` names their SHA-256 and independently records artifact,
exit, stop, closure and validation outcomes. Both reports use exclusive fsynced
publication. File conflicts and publication errors cannot produce CLI success.
The child cannot reuse a previous result or setup/observation journal.

Remaining: observation-phase journal/publication exceptions still need a full
recovery envelope after the collector has started. A setup journal is evidence
for responsible recovery, not a restart/recovery authority. No missing creation
acknowledgement is fabricated. Surviving orphan groups whose leader has already
been reaped stay unconfirmed rather than being blindly killed. Python socket
timeouts do not provide OS-wide cancellation. Native execution remains pending.

## FS-LISTEN-SDK lifecycle

The local main owns partial app/client construction in try/finally. Each app is
registered immediately so failure in the next initializer cannot hide it from
finalization. A nonce-derived disposable email is preflighted through a bounded
local-only Auth management request. Successful signup binds the returned UID
and email to currentUser. Witness and cleanup sign-ins must retain that UID.
Observation deadlines are rechecked before later setup effects.

After document cleanup the known account is read by UID, deleted and read again.
At most four additional local-management requests (one preflight and three
recovery requests) are recorded separately from SDK calls. The transport accepts
only numeric loopback and a fixed local owner credential, enforces a whole-call
deadline and 64 KiB response bound, and rejects framing/UTF-8/JSON/media errors.
These are local operational bounds, not production quotas. A missing signup
acknowledgement does not confer deletion authority over an account found later,
and a single absent lookup cannot settle a potentially still-running creation.
Unconfirmed document cleanup retains the account for responsible recovery.

All recovery phases share counters and accumulated active time. Observation and
idle time do not consume the recovery reserve. Clock regression is latched;
expired phases cannot start hooks. The final recovery pass independently restores
a principal. SDK terminate/deleteApp failures remain visible and cannot skip the
other client's finalizers. Receipt publication occurs only after cleanup; failure
to publish cannot bypass finalization. The main result includes `lifecycle` and
requires all case IDs plus account/client cleanup before returning success.
A fully recorded semantic difference remains eligible for comparison, not parity.
Raw SDK exception messages are not copied into failure records.

The v10 server-read and single-attempt ownership-checking transaction deletion
remain in place. Cleanup never falls back to unconditional SDK deletion, cached
absence, or a silently ignored updateTime precondition. Additional transaction
reads are reserved. Final read errors do not stop unrelated resource attempts.

Remaining: the actual Firebase SDK and fireemu daemon have not run here. SDK
promises/finalizers are awaited, not safely cancellable; an unending operation
still needs external supervision. The management transport's timer does not
cancel an SDK request. Lost signup acknowledgements with surviving accounts
remain unconfirmed. There is no durable SDK-side orphan replay journal. Stdout
receipt persistence still belongs to the parent. SDK wire costs, browser/mobile
lanes and new artifact bindings require actual execution.

## Evidence and remaining acceptance

Python tests use actual modules, synthetic API responses and local sockets or
owned subprocesses where stated. Node tests exercise the full main/lifecycle and
actual collector/adapter using an instrumented SDK interface, not Firebase SDK.
Fault injections and negative controls are not independent correctness review.

Old Listen/Rules/action receipts stay immutable. Their old source digests are
not rewritten to match new code. New native/SDK shadows and fresh bindings are
required. The inherited AUTH-ACCOUNT/AUTH-FEDERATION and FS-DATA-WRITE Rust
changes remain uncompiled. Workspace, streaming/SDK/E2E/formal/resource lanes,
saved-reference replay and independent review remain non-production obligations.
Existing owner exclusions for managed infrastructure are unchanged.


## v12: persistence failures, raw response binding and finite clocks

The document-limit collector treats its optional row/wire sidecars separately
from the authoritative Gate journal. A received acknowledgement can still be
journaled by the Gate after a sidecar write failure, permitting only the
existing request/version-bound cleanup. Such a run retains recording failures
and cannot become complete acquisition evidence. A failing Gate journal still
retains inflight/unknown ownership; no recovery bypass was added. An unconfirmed
Gate stop does not invoke the before-recovery credential callback. Final result
publication failures propagate after bounded cleanup, not before it.

The request-byte collector now compares recursively typed JSON decoded from
UTF-8 raw bytes. Boolean/integer/float substitutions, non-finite values,
duplicate keys and conflicting retained-byte counts cannot authorize a write
or typed absence. Object-key order is not significant; original response bytes
remain separately retained and hashed. Malformed diagnostic text is not typed
cleanup evidence. The shared local limits HTTP reader rejects ambiguous or
incomplete Content-Length/Transfer-Encoding framing without raising the cap or
relaxing the existing timeout. Structurally valid document names with a project
or database called documents are measured using only their document-path suffix.

The Rules collector latches journal open/write/flush/fsync/close failure,
prevents further observation and attempts its already-reserved typed cleanup.
Processing failures enter cleanup; a recovery normalization failure leaves its
resource outstanding and does not stop unrelated requests. No failed journal
is presented as complete evidence or a durable restart authorization. Invalid,
non-finite or regressing clock readings latch both phases off: no later healthy
reading refills the budget, and all unconfirmed resources remain outstanding.
A missing trustworthy clock cannot authorize supposedly bounded cleanup.

These changes are verified with actual Python modules, injected API responses
and selected real loopback HTTP/worker tests. They do not establish execution
of the Rust daemon, actual Firebase SDK, full native acceptance or independent
security review. Prior native/SDK receipts and their source hashes stay unchanged.

## v13: unambiguous JSON and explicit local expectation checks

Both standalone HTTP workers (`batch_wire.py` and the shared limits transport)
now decode UTF-8 explicitly, reject duplicate decoded object keys at any depth,
and reject NaN, infinities and overflowing float literals. Invalid JSON remains
diagnostic data, never a typed document acknowledgement or absence. A complete
HTTP body is still recorded as complete transport reception; JSON validity is
represented separately as `non-json` / `nonJson`. Status, finite value types,
raw receipt digests and the existing size/time limits are preserved. Gate and
Ledger retain uncertainty when malformed creation or final-absence bodies pass
through the real loopback workers. This is not a new production permission.

The helpers intentionally remain self-contained in the two worker closures:
adding a checkout-only import to the inherited O8 archive would change its
execution boundary. Tests apply identical byte vectors to both implementations
and exercise the worker/Gate/Ledger hand-off. Real Firebase/native execution is
still a separate obligation.

`local_shadow_check.mjs` no longer succeeds for an empty or duplicated subset,
failed cases, open listeners, invariant failures, missing compared fields,
unproven cleanup, contradictory counters, or exhausted budgets. It checks the
complete ordered case catalog and its digest, all cleanup passes and resources,
and the local lifecycle flags. Input files are bounded regular non-symlink UTF-8
JSON; duplicate keys and non-finite values are refused. Output contains only
validation issues, not token-bearing event bodies.

Current receipts require lifecycle evidence by default. To compare an immutable
old receipt which predates that evidence, supply `--legacy-lifecycle` explicitly.
That option cannot override an explicitly failed lifecycle. Such a comparison
only says whether the stored projection matches the catalog: it does not verify
current source/binary identity, execution, SDK behavior, or production parity.
The result always reports `currentArtifactVerified:false` and
`productionCompatibilityVerified:false`. The source-bound Python observation
checks and their existing drift failures remain unchanged.

## Firestore response-envelope integrity and supervisor finalization

The current REST ownership Gate requires a top-level error-only envelope for
`NOT_FOUND` absence and the narrow `INVALID_ARGUMENT` creation refusal. Error
`message`, `details` and legacy diagnostics inside `error` remain intact. A
resource/write result alongside `error`, or an unknown extra top-level field,
is not enough to prove absence or that no write occurred. This is a closed
collector evidence contract: it is not a claim that a future API cannot add an
extension. Such a response requires review instead of automatically releasing
ownership. The HTTP error shape is described by Google AIP-193, section
HTTP/1.1+JSON representation (`https://google.aip.dev/193`).

A 200 response containing a top-level `error` cannot supply conditional-creation
proofs or a recovery read capture. PATCH, Commit and BatchWrite success evidence
must not coexist with an API error. BatchWrite's legitimate per-write `status`
array is unchanged. A contradictory creating request remains unconfirmed even
if a later read is a typed 404; no conditional delete or reservation release is
inferred from the contradictory acknowledgement. Ledger retirement independently
revalidates the final absence body, including when its recorded digest matches.

Regressions in `production-admission/test_response_envelope_integrity.py` use the
actual file-backed Gate/Ledger. `fs-write-limits/test_response_envelope_wire.py`
adds real numeric-loopback TCP and both standalone worker variants. These tests
use explicit HTTP fixtures, not Firebase or the Rust daemon.

The local Listen supervisor records possible recovery responsibility immediately
before submitting its SDK process to the capture primitive. If that call raises
without returning a spawn receipt, it cannot establish that no process started;
`recoveryRequired` remains true. A returned `started:false` still distinguishes a
confirmed pre-spawn failure, and an accepted fully recovered completion may clear
the flag. This conservative marker does not assert that resources actually exist
and does not authorize cleanup.

Pipe and selector close exceptions are recorded independently, and do not skip
the remaining descriptors/output files or discard the already-known process
stop result. The run remains incomplete. Tests use real owned Python children
and injected finalizer failures; they do not run the Firebase SDK. This change
adds no orphan-delete/restart permission and does not solve OS/power-loss,
kernel/filesystem hangs, or missing native/SDK qualification.
