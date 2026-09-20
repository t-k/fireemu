# MFA local creation responsibility and atomic checkpoints

This is a non-authorizing local collector contract. It is not a new production
admission, restart cleanup capability, Firebase compatibility claim, or native
execution receipt. The MFA API request budget and phase deadlines are unchanged.

## Files and lifecycle

The owned parent creates its output directory with mode 0700. A sequence requires
no pre-existing `checkpoint.json` or `responsibility/`. Reusing an old run, including
through those paths' symbolic links, is refused before any service request.

`responsibility/` is created with mode 0700. The writer records a launch followed by
numbered, immutable `create-intent`, `create-ack`, and final `recovery` JSON files.
Each file is mode 0600, contains the nonce digest and plan digest, and binds the
previous file's bytes by SHA-256. This self-hash chain is not a producer signature.
The writer and checkpoint publisher use directory descriptors and refuse changed,
non-regular, multi-link, or non-private checkpoint destinations.

Before either a named or anonymous signup, the intent file and directory are
fsynced. Only after that call returns may signup be dispatched. Named email
addresses now use the frozen plan's full nonce-derived addresses, rather than an
unrelated shortened random suffix. Anonymous signup records a null address and
uses the same creation/ACK path; it never invents an email address for discovery.

After an exact successful signup ACK, the UID is registered in the in-process
owned-resource list before persisting the ACK or parsing the ID token. If ACK or
checkpoint publication fails, the existing finally may still clean up that
confirmed UID. Invalid/lost ACKs do not confer ownership, including a refusal
that cannot establish a successful creation. They remain unresolved intents.
No follow-up lookup by email, speculative delete, retry, or new network call was
added. The journal omits password, ID/refresh tokens, MFA credentials and assertions;
UIDs and generated email addresses remain private identifiers, not public output.

## What interruption means

An intent with no durable ACK is **unknown**, not absent. This also holds if a
crash occurred after intent publication but before dispatch: that conservative
false positive is preferable to erasing a possible create. A later typed 404 or
an empty list of known accounts does not resolve an unknown create in this tool.

Checkpoint replacement writes a new file in the same directory, checks the full
state and current run binding, fsyncs it, atomically replaces the old filename,
and fsyncs the directory. Interrupted writes do not truncate the previous valid
checkpoint. Before replacement the old complete bytes remain; after replacement
the new complete bytes may be visible. If the final directory fsync fails, the
operation is reported failed even though those new bytes can be readable.

Finalization first publishes a provisional non-complete checkpoint. Only after the
recovery event is durably published may a one-time outcome publication replace it
with successful state. A missing/failed recovery event leaves the provisional abort;
an unresolved intent cannot be finalized as DONE, including when a caller swallowed
an earlier observation exception. A failed final directory fsync still has the
post-replace ambiguity described above, and no successful shadow is emitted.

Persistence failures latch the run: no further observations are allowed. The
sequence still attempts existing authorized in-process cleanup and final
checkpoint/recovery publication independently, and then rethrows the original
failure. Secondary persistence errors never turn failed observations into success.
A clean final recovery record does not repair a broken earlier publication.

The final public `recovery.creationResponsibility` contains only counts, flags
and the final record hash. Unknown creations, untracked known UIDs, incomplete
known-account cleanup, or persistence faults keep cleanup unconfirmed. An explicit
contradictory summary is refused by the local parent and comparator even when
broad recording/cleanup flags have been flipped to true. The original checkpoint
schema remains unchanged; old historical receipts are not rewritten or implicitly
bound to the new writer. Newly generated reports always carry the summary.

## Limits and evidence

This implementation uses local POSIX file/descriptor semantics. Process-kill
experiments cover interruption before/after replacement and during signup waiting;
they do **not** simulate power loss, a malicious filesystem, a hung kernel, all
network cancellation behavior, or arbitrary mutation by the same OS user. Orphaned
`.pending-*` files may remain after process death; they are private diagnostic
files, never checkpoints or cleanup grants. Hard kernel/FS failures can defeat
attempted cleanup or publication. The journal contains no reusable control token
and does not authenticate the current emulator instance or a stopped producer.

To inspect a failed run, preserve the original directory and treat missing, partial,
or duplicate sequence events as incomplete. No reader, automatic replay, or deletion
command is introduced here. Before implementing restart cleanup, instance identity,
producer termination, current authority, UID/marker/version and unresolved creation
races must be independently revalidated. A self-consistent JSON file alone is not
sufficient permission to delete anything.

Local tests: `test_mfa_durable_responsibility.py` uses real files, fsync fault
injection, child processes and a fake API backend. The full MFA case walk and its
native backend/SDK remain separate obligations. Python checks do not execute Rust.

Implementation reference: Python `os.replace`, descriptor-relative operations and
`os.fsync`: https://docs.python.org/3/library/os.html . Atomic publication and
successful synchronization calls must not be presented as a general power-loss
or independent evidence-authentication proof.
