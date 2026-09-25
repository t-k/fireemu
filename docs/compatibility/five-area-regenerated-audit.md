# Five-area non-production regeneration: finite audit and deliverable

This work is based on the supplied v37 source snapshot, with the Node runner's
preimage reconciled byte-for-byte with upstream `973a6d6db3c4d7b3b40a09339d49a42d02cbc02f`.
Every modified pre-existing file is separately checked against that upstream
commit. This is NOT a full checkout of that commit. In particular, later
request-byte O8 code and refreshed local observations must not be overwritten
with this snapshot. Use only the incremental patch after checking its preimages.

No production request, credential acquisition, configuration mutation, remote
write, CI dispatch, push, merge or main modification is included. No parent is
promoted to `COMPAT_VERIFIED`. Independent review is still required.

## 1. Functions / Node

Upstream v36/v37 parameter resolution and async-Promise isolation are retained.
The error reporter could itself throw on a revoked Proxy, a throwing prototype
trap, or a throwing `then` accessor. Unsupported thenable detection also read
`then` twice before invocation. The reporter now isolates these failures and
captures `then` once, preserving its receiver and asynchronous scheduling.
Native/cross-realm Promise rejection tests and actual runner calls cover the
healthy-sibling path. No global unhandled-rejection suppression is installed.

Existing schedule/task/filter, HTTP admission, input limits, IPC output,
shutdown, stderr backpressure and export-discovery regressions are re-run.
Pre-rendered CEL remains explicitly unsupported rather than executable cron;
this audit does not add a general CEL interpreter, multi-region deployment or
native scheduler precision. Arbitrary synchronous user code is not sandboxed.

## 2. Auth non-native

Credential comparisons require exact JSON types, finite values, valid counters,
boolean flags and assertions. `false`, `0`, and `0.0` are distinct. Cycles,
non-string object keys, non-JSON values and oversized integer representations
are rejected without causing a comparison exception. An optional creation-
responsibility summary must be consistent with cleanup and have no unknown ACK.
Legacy receipts without that summary retain their prior schema and are not
silently labeled as durably journaled.

The CLI creates a fresh private write-ahead journal before starting its owned
emulator. A signup/custom-signin intent is synchronized before a request is
sent. Valid ACKs register an actual owned UID before token processing. Custom
sign-in requires a strictly boolean `isNewUser`: a pre-existing account is
neither mutated by later setup nor registered for deletion. A requested UID is
not creation proof. Unknown ACKs retain responsibility even after later absence.

The journal binds nonce, artifact digest, actual collector module digests and
the operator-supplied source commit (explicitly NOT independently authenticated).
Records are bounded, hash chained and private, published with no replacement.
Recording failure is latched. A recovery-record failure does not prevent cleanup
of another already confirmed account. Tests include real filesystem I/O and
killing a child after its intent is persisted. This is not a power-loss proof or
authorization to recover after restart.

Adding the journal to collector bindings deliberately changes current bindings.
Historical receipts are not re-hashed to look like executions of the new code.
A fresh native/SDK run is still necessary for acceptance of the new collector.

## 3. Firestore local campaigns

Query comparison now reopens sidecars through private pinned directory file
descriptors. Absolute/traversing paths, symlinks, hardlinks, FIFO, excessive size,
partial reads and changed files cannot support a retained comparison. Both byte
lengths are strict integers and match the actual bytes; SHA-256 and strict UTF-8
JSON (including duplicate keys and finite numbers) are checked against the
receipt. Phase/index/kind must identify the compiled slot. JSON types remain
exact after permitted identity/time normalization.

`retainedBytesVerified` is true only when both directories were supplied and
successfully reread. Projection-only comparison remains available but is
explicitly not retained-byte verification. No semantic verdict is acquisition
validation or cleanup permission. Transaction/Listen/Rules selected local
regressions are separately reported; old snapshot evidence failures are not
reported as current-upstream failures.

The recovery review model in `tools/compat-broad/offline-closure/recovery_review.py`
is executable but read-only. It checks *proposed evidence* for exact instance
boot/project/database, stopped producer and descendants, zero pending operations,
current run/input-bound permission, acknowledged creation and current owner/UID/
version. Even the all-positive state is only a candidate for independent
validation, with `authorizesCleanup=false` and `executionImplemented=false`.
It neither collects nor authenticates these assertions. Implementing the live
adapters/executor remains separate work. Unknown creation cannot be settled by
an unrelated later 404. Account deletion must occur only after dependent document
recovery, and every attempted delete must retain uncertainty until typed absence.

## 4. FS-DATA-WRITE closure preparation

`offline-closure/preparation.py` reuses actual compilers, creating 42 below/exact/
over boundary inputs with input digests and the existing finite Commit plan:
11 observation + 6 recovery slots for two resources. It explicitly distinguishes
500/501 **field transforms on one document** from the number of writes. Each
Commit in that case contains two writes, split 250+250 or 250+251. This boundary
already has a stored production receipt; no repetition is requested.

The report pins compiler/catalog/Rust-boundary inputs and historical receipt
bytes, rechecks them after compilation, and never rewrites historical evidence.
It can be regenerated and validated against the source. Recomputing a digest
cannot turn its false authorization/native/promotion flags into true ones.
Payload compilation is not actual Rust, CLI, SDK, wire, timing or quota evidence.

Remaining non-production closure: build and test the final native/locked-SDK
artifact; bind source/config/collector/comparator; replay immutable references;
run required cross-service and formal/resource lanes; independently review the
closure. Request-byte O8 integration was added upstream after the supplied
snapshot, and is retained by the incremental-patch delivery, not replaced here.
Index configuration decisions remain explicit inputs, not guessed approvals.

## 5. Latest HEAD audit

Read-only GitHub checks at `973a6d6...` found v36/v37 and the upstream rejected-
Promise guard already integrated. `80815a5...` to `973a6d6...` adds request-byte
O8/Gate recovery and refreshes its local evidence. Earlier upstream updates also
replace current Listen/Query/Transaction local shadows while retaining historical
records. Previous counts of stale evidence failures must not be carried forward
as latest-HEAD defects without a latest-HEAD run.

The delivered preimage inventory specifies each modified file's actual Git blob.
No claim is made that a matching subset equals a complete latest source tree or
that CI success alone proves runtime, SDK or whole-parent compatibility.

## Reproduction and evidence

The outer deliverable contains the incremental patch, complete changed files,
source snapshot, exact test commands/logs, source/tree checks and a checksum
manifest. Test counts come from final fixed-source runs only. Intermediate,
old-version contrast, mutation and fresh-extraction runs are separate.

Run the included `reproduce.py` in a clean non-main worktree. It does not install
packages or dispatch CI. Source snapshot does not include Rust, SDK dependencies,
private artifacts or historical Git objects. Test doubles are explicit and not
production parity. The final remaining-work table is in the outer Japanese
handoff, and distinguishes implemented, reviewed-only and unexecuted work.
