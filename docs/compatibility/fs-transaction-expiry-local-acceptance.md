# FS-TRANSACTION: expiry/retry local integrity — v24

Status: **non-production acceptance incomplete**. These changes exercise Python
collection, control-clock measurement, recovery responsibility and comparison.
They do not implement or verify the native transaction engine or a real SDK.
No production permission, credential lookup or cloud configuration is added.

## Closed, finite defects

* A conditional create with a transient result (including DEADLINE_EXCEEDED), or
  with an incomplete acknowledgement, remains potentially applied. A later
  absent read does not rule out a delayed apply. It remains unrecovered and no
  speculative delete is granted. An owned positive readback after same-run
  preflight absence may still provide the existing conditional-cleanup proof.
* BeginTransaction without a confirmed token remains in
  `unconfirmedTransactionStarts`. A transaction with a known token is not
  retired on an incomplete Commit/Rollback acknowledgement. Unknown tokens
  are never invented or silently reported as released.
* Normalized RPC codes, status names, explicit completion and optional HTTP
  status/error body must agree. Success/error mixtures, malformed write
  acknowledgements and invalid document versions are not recovery proofs.
  Normalized fixtures may omit `complete` and a REST error body, as before;
  this contract is not raw-byte authentication of an arbitrary producer.
* Local REST reception uses the shared bounded framing and UTF-8/JSON decoder.
  Duplicate keys, non-finite values, conflicting HTTP/canonical status and
  missing/ambiguous JSON media types do not become typed API evidence. A raw
  401/403 still latches authority refusal even when its body cannot be decoded.
* The virtual clock is measured with GET of the current default session clock,
  followed by the existing advance POST, and the returned actual instants are
  subtracted at nanosecond precision. Missing measurements are not replaced by
  requested seconds. Changed `backwardsSets`, reverse clocks and invalid times
  are rejected. An unconfirmed virtual advance cannot establish expiry.
* Wall-clock faults latch permanently. Every send rechecks the active phase's
  remaining time, including after a wait and during recovery; the timeout
  passed to the transport is bounded by that remaining time. Recovery retains
  its existing independent tail, not a replenished observation budget.
* The parent requires normal child exit, exact boolean completion, and clean
  local resource recovery. Missing process identity is not proof of shutdown;
  an executable's path appearing only as an argument is not ownership. An
  interrupt while waiting still attempts the existing guarded shutdown.

## Local control accounting

Each simulated wait now has **two** local control requests (GET and POST).
The standard two waits therefore have four clock-control requests rather than
only two POSTs. `localControlRequestCount` records this separately from
`requestCount` for Firestore data RPCs. Two initial identity checks are separate.
This does not claim transport-wide fee accounting or a new production budget.

## Preparation and history

`fs-transaction-expiry-retry-04-manifest-v3.json` is generated from current
source. It is BLOCKED_OWNER, permissionGranted=false, authorizesProduction=false,
productionExecuted=false and requiresFreshPermissionBinding=true.
The original manifest, v2 preparation and original native local-shadow remain byte-for-byte
unchanged. The original local-shadow is retained at
`spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-local-shadow-v2.json`; the
current generated rehearsal is published at the canonical local-shadow path. Their
current-source checks intentionally remain nonpassing until a new real-artifact rehearsal
and saved-input comparison exist. Do not replace old source hashes with this version's
hashes.

## Non-production work still required

1. Run this transaction collector through a newly built, owned native artifact
   and fixed SDK/CLI, then test snapshot/conflict/retry/expiry/rollback semantics.
2. Validate the fixed unary worker with a real native artifact. Its post-spawn
   timeout now covers initial identity probes, data RPCs and clock GET/POSTs,
   including slow-drip body reception. Each operation keeps the timeout it had;
   there are no additional requests/retries. Kernel process creation, kill/reap,
   parent SIGKILL and server work continuing after disconnect are not covered.
3. Broaden independently authenticated current-instance, escaped-descendant and
   restart recovery handling. Parent publication and child-result validation are
   now fail-closed (see below), but a matching nonce/PID/hash is not independent
   executable attestation or restart-time deletion authority.
4. Build current native/SDK evidence with source/artifact/config/collector and
   comparator binding, replay immutable saved references and obtain independent
   correctness/security review. Python tests and self-comparison are not that
   independent review.

Representative focused checks (use the repository's pinned Python environment):

```sh
python -m pytest tools/compat-broad/fs-write-txn/test_txn_expiry_integrity.py \
  tools/compat-broad/fs-write-txn/test_txn_expiry_clock_and_exit.py \
  tools/compat-broad/fs-write-txn/test_txn_expiry_collector.py \
  tools/compat-broad/fs-write-txn/test_txn_expiry_comparison.py \
  tools/compat-broad/fs-write-txn/test_txn_expiry_shadow.py
```

Actual execution counts, source tree and unexecuted native lanes are recorded
in the round25 handoff/validation, not inferred from the existence of tests.

## v25 bounded local transport and parent publication

`txn_wire.py` is a fixed `-I -S -B` standard-library worker. It accepts only the
closed local Transaction/control routes at explicit numeric loopback ports.
Credentials travel on stdin, not argv/environment. Limits remain 8192 request
bytes, 65536 response bytes, 10 seconds for ordinary data calls (up to the
existing 120-second contended call), and 15 seconds per control call. The
collector's shorter remaining timeout takes precedence. No transport retry is
added. Two initial identity GETs and two GET/POST virtual-clock pairs are counted
as before.

The worker writes a small status frame before body reception. A received HTTP
401/403 survives even when body parsing fails or the parent kills the worker at
its deadline, so the collector still latches authority refusal. A partial status
frame is not accepted. Complete reception is separate from usable JSON and
ownership/release evidence; timeout never means the server did not apply a write.
The fixed worker bounds what it can emit. It is not an arbitrary-command sandbox.

Parent result publication writes and fsyncs a private temporary file, links it
exclusively into place, then syncs the directory. An existing file, link or race
is not overwritten. Failure after publication is still returned as failure even
if complete bytes are visible. The parent stops the child before reading its
bounded regular private files, rejects duplicate/nonfinite JSON and read-time
changes, binds nonce/project/database/source/case-set/prefix/parent PID/origins,
and independently recomputes the local self-contract instead of trusting a
child-supplied MATCH. Invalid child files stay unchanged and the parent publishes
an incomplete diagnostic with their usable input digests where available.
Launch metadata is recorded before data-capable execution and public CLI errors
contain exception types only. The final `publication` field is new local metadata;
a historical record is not silently regenerated to look like a current run.

The new tests include actual worker/TCP slow-drip, authority refusal before body
timeout, local control deadlines, a complete fixture-based collector through
real HTTP, short writes, exclusive publication races, parent run-binding,
self-contract recomputation, special files and save failure after shutdown.
API semantics are supplied by fixtures, not a native runtime or production.
