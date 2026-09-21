# FS-LISTEN-SDK campaign preparation

This document describes a bounded production campaign for the `FS-LISTEN-SDK`
row of the Firestore production-compatibility inventory. The campaign is
prepared, not executed. Nothing here contacted Firebase production, read a
production credential, or consumed a permission. The row stays `WAITING_ORACLE`
and the count of production-unobserved conditions it reduces is zero.

What this preparation adds is the part that was missing: a finite catalog of
observation cases with controls, a bounded collector that actually runs them
through the declared Node client SDK, a comparator that can reach `MATCH` only
on acquisition evidence, a frozen campaign manifest with a permission envelope
and owner preconditions, and a local shadow that ran the whole catalog against
`fireemu` and agreed with every expected local result.

## Observation Cases

Eighteen cases live in `tools/compat-broad/fs-listen-resume/cases.py` and are
published for the Node collector as `spec/compatibility/fs-listen-sdk-cases.json`.
Nine are observation cases; each has a control or negative counterpart, so a run
cannot report agreement from a listener that never delivered anything. Two
principals take part: the case client and a witness client are signed in as the
first throwaway account, and a `secondary` client is signed in as the second
one, whose only owned document is `privateB`.

| Case | Dimension | What it observes | Counterpart |
| --- | --- | --- | --- |
| `FS-LISTEN-SDK-101` | Document event order | One server snapshot for an existing document | `101C` listens to an absent document and still gets a non-existent snapshot |
| `FS-LISTEN-SDK-102` | Pending writes | A local write raises `hasPendingWrites` before the acknowledged snapshot | `102C` writes from a second client, where the flag must never rise |
| `FS-LISTEN-SDK-103` | Query change order | `added`, `modified` with reordering, and `removed`, with old and new index | `103C` writes a document outside the predicate and expects silence |
| `FS-LISTEN-SDK-104` | Resume after a break | Which changes arrive after a forced stream break and reconnect | `104C` applies the same mutations with no break |
| `FS-LISTEN-SDK-105` | Unsubscribe | Callbacks stop while a witness listener still sees the write | `105C` keeps the listener and sees the same write on both |
| `FS-LISTEN-SDK-106` | Auth switching | Signing out mid-listen terminates a Rules-protected listener | `106N` starts the listener signed out and never reaches the server |
| `FS-LISTEN-SDK-107` | Default subscription | A listener that does not request metadata changes raises one callback per data change | `107C` writes the same data again and expects no callback |
| `FS-LISTEN-SDK-108` | Cross-identity | The first principal's listener on the second principal's private document ends in `permission-denied` with no server snapshot before the error | `108C` has the second principal listen to the same document and receive the server snapshot |
| `FS-LISTEN-SDK-109` | Token revocation | The first principal's sessions are revoked (`validSince`) while its listener is attached; an unrelated commit by the second principal follows. Locally the listener ends with `unauthenticated` | `109C` applies the same commits without revoking and expects the listener to stay silent for the other principal's write and to see its own |

`FS-LISTEN-SDK-109` records what `fireemu` does: it re-verifies the credential on
every commit-triggered refresh, so the Listen stream ends with `UNAUTHENTICATED`
("token revoked") at the next commit and the SDK surfaces that as a terminal
listener error. The production hypothesis is different and is deliberately not
asserted: Firestore does not consult revocation for an already-issued ID token,
so a production listener is expected to keep working until the token expires.
The comparator will report that as a mismatch to be judged, not as a defect on
either side.

Each case declares the fields it compares. A listener that does not treat
metadata as a signal drops `fromCache` and `hasPendingWrites` from the compared
projection and keeps them in the raw receipt, because their value there
reflects delivery timing rather than a semantic difference.

Most listeners subscribe with metadata changes so the collector can tell when a
listener has reached the server, and metadata-only events are collapsed back out
afterwards. That reconstruction is symmetric, so it cannot manufacture a match,
but it would hide a runtime that raised or suppressed a default-mode callback
differently. `FS-LISTEN-SDK-107` and its control therefore subscribe in the real
default mode, skip the collapse entirely and compare the raw callback sequence.

Resume is compared as an aggregate rather than event by event, because the SDK
is free to batch deliveries differently between runs. The aggregate collapses
the delta sequence into one row and is checked against three invariants: a
document that did not change is never re-delivered as `added`, the listener
reports a cache-served window that recovers, and the terminal document set is
complete. The control asserts the mirror image, that no cache-served window
appears without a break.

## Bounded collector

`listen_collector.mjs` holds the step machine, the budget, the invariant checks
and the cleanup contract. It imports no Firebase code and opens no socket: every
effect arrives through an injected dependency object, so its behaviour is
tested against an in-memory fake. `listen_sdk_adapter.mjs` is the only file that
touches the SDK.

Bounds and ownership:

- Every chargeable operation goes through one budget. A charge past a cap or
  past the deadline fails and is recorded; it is never retried around.
- Cleanup runs on a separate reserve, so an exhausted observation budget or an
  expired observation deadline can never leave an owned document behind. A
  rehearsal with a four second deadline produced an incomplete receipt whose
  cleanup still completed.
- Cleanup reads each owned path, deletes it only when the owner marker still
  names this run, then reads again to prove absence. A document that is absent,
  not owned, or still present after its delete is recorded as such. Those
  outcomes make the receipt incomplete rather than passing.
- Listener shutdown is tracked per case. A failed unsubscribe is a failure, not
  a silent success.
- The cleanup reserve checks elapsed active time and operations. It cannot cancel
  an unresolved SDK Promise. The local supervisor described below bounds the SDK
  process separately and records uncertain resources when it has to stop it.
- Ordinary step, per-case cleanup and between-case errors enter the recovery
  path. An unresolved SDK Promise, process death or output failure can still
  prevent a receipt; the supervisor's pre-spawn responsibility record is not
  replaced by a fabricated successful receipt. A rehearsal against a
  deny-all ruleset, the most likely production failure, produced a receipt whose
  every case carried `step-threw:permission-denied`, whose listeners were all
  closed, and whose cleanup honestly reported `read-failed` rather than success.
- Cleanup rows name the resource and bind its path by SHA-256 rather than
  publishing the path, so a production receipt exposes neither the run nonce nor
  the account identifier.
- The receipt keeps every cleanup pass, not only the final one. Most documents
  are deleted by the pass that follows the case which created them, so the final
  pass alone understates the run; it reports `already-deleted-earlier` rather
  than `not-created` for those. The session is restored before each pass, because
  a case can end signed out and cleanup has to read under Rules that require a
  principal.

Secrets:

- The collector refuses to start when a secret-shaped value appears in argv.
- The throwaway account password is read from a private file descriptor and is
  held in a local binding in the adapter. It never reaches the collector, a log
  line, or the receipt.
- Everything written to a receipt passes through a redactor that strips
  secret-named keys and bearer-shaped strings.

## Campaign manifest

`campaign.py` compiles the frozen manifest for one run nonce. Compiling it
performs no network call and grants nothing: the manifest carries
`status = BLOCKED_OWNER` until an owner supplies a campaign-scoped permission,
and even then it only reaches `PREPARED`. Execution is a separate step that this
lane does not implement, and the adapter refuses production mode outright.

Frozen inputs are the resolved SDK identities and their npm integrity digests
for `firebase`, `@firebase/firestore`, `@firebase/auth` and
`@firebase/webchannel-wrapper`, taken from the pinned lockfile, plus the
lockfile digest and the case catalog digest.

Planned operations and the frozen caps:

| Quantity | Planned | Cap |
| --- | --- | --- |
| Writes | 32 | 60 |
| Deletes (observation) | 1 | 80 |
| Reads (observation) | 29 | 600 |
| Raw snapshot deliveries | 92 | 120 |
| Listener registrations | 21 | 40 |
| Cleanup reads (reserve) | 228 | 300 |
| Cleanup deletes (reserve) | 114 | 150 |
| Wall clock | one run | 600 s plus a 180 s cleanup reserve |

The estimated cost at published Firestore list prices is USD 0.000235, against a
hard ceiling of USD 0.50. That is a planning ceiling, not an observed bill.

The permission envelope inherits from nothing. It allows one run of the declared
catalog, sign-in, sign-out and session revocation of at most two throwaway
accounts, and creation plus conditional deletion of the declared owned
documents. It forbids reuse of any
earlier compat-broad permission, any write outside the owned prefixes, any retry
past the deadline or the cost ceiling, and recording an identity token, refresh
token or password anywhere in the output.

## Owner preconditions

1. **Rules.** Merge the additive fragment into the oracle project and publish it.
   It grants nothing to unauthenticated callers and contains no catch-all deny,
   because the oracle project is shared with other lanes. The manifest carries
   its digest so a deployed fragment can be checked against the plan.

   The run prefix is keyed by the calling principal, so a principal can reach
   only its own runs even though the fragment names no nonce.

   ```
   match /o6_listen/{uid}/runs/{runId}/docs/{docId} {
     allow read, write: if request.auth != null && uid == request.auth.uid;
   }
   match /o6_listen_private/{uid} {
     allow read, write: if request.auth != null && request.auth.uid == uid;
   }
   ```

2. **Throwaway accounts.** Two email and password accounts owned by the campaign
   operator: the principal every case signs in as, and the second principal of
   the cross-identity and revocation cases. Each password is supplied through
   its own private file descriptor (`O6_LISTEN_PASSWORD_FD`,
   `O6_LISTEN_SECONDARY_PASSWORD_FD`).
3. **Index.** None. The query filters and orders on the same field, which the
   automatic single-field index serves.
4. **Clean prefix.** The nonce-scoped run document and both private documents
   must not exist before the run.

## Comparator contract

`observation.py` is a separate schema and API from the offline preparation
comparator, which still always answers `PREPARATION_ONLY`. The observation
comparator can answer `MATCH`, but only after both receipts pass admission:

- the receipt binds the frozen campaign digest and the case catalog digest;
- the bound sources are recomputed from the files on disk and compared against
  the digests the receipt declares, so a copied digest does not pass;
- the production receipt names the campaign permission, its campaign is
  `PREPARED`, its resolved SDK identities match the manifest, and it carries an
  ordered transport timeline with connect, disconnect and reconnect entries.
  The Node SDK does not surface wire frames, so the collector derives that
  timeline from what it can observe: the first server-backed snapshot, a
  listener falling back to the local cache, and its recovery. Each entry records
  what it was derived from and which case produced it, so it is never read as a
  transport frame;
- both receipts report an unexhausted budget, a complete cleanup, closed
  listeners and no invariant violations;
- neither receipt carries secret material.

A missing or unproven element yields `INDETERMINATE`. A local receipt alone
never reaches `MATCH`. The same receipt submitted on both sides is rejected as a
production claim, and flipping a production marker on a local receipt fails on
the permission and transport bindings.

## Local shadow

The current shadow receipt was regenerated from commit `b691969d997a34319f5b6fa87c01eea6a498cb05`
with the pinned Firebase SDK `12.18.0`. All eighteen cases agreed with their
expected local result, both throwaway accounts were deleted and proved absent,
and the revocation case ended the listener with `unauthenticated` as recorded. The collector ran
the full catalog against an owned local `fireemu` instance
started by `fireemu exec` with the Firestore and Auth emulators on OS-assigned
ports. The runtime was built from this worktree with `cargo build -p fireemu`,
never taken from another checkout: a prebuilt binary elsewhere can predate
branch-only fixes and describe a different commit. The receipt therefore names
the binary it ran, its SHA-256 and the commit it was built from. Every listener
closed, no invariant was violated, and cleanup proved absence for every owned
path.

The current receipt is checked in at `spec/compatibility/fs-listen-sdk-local-shadow.json`,
with the campaign it ran under at `fs-listen-sdk-local-shadow-campaign.json`. The
prior lifecycle-free receipt remains byte-for-byte preserved at
`spec/compatibility/fs-listen-sdk-local-shadow-historical.json`; it is admitted
only through the explicit legacy checker mode. The
campaign record publishes the run nonce because a reader cannot recompile the
campaign, and so cannot verify the receipt, without it; a production campaign
record stays private and only its digest is published.

Two test files bind it. `test_o6_listen_sdk_local_shadow.py` recomputes the
source digests, the catalog digest, the ruleset digest, the runtime digest and
every case comparison. `test_o6_listen_sdk_round_trip.py` feeds the shipped
receipt to the shipped comparator and requires admission with no errors,
iterating the contract's required inputs rather than the receipt's own keys, so
widening the contract without widening the collector breaks the build.

Reproduce it with:

```sh
cargo build -p fireemu
npm install --prefix <scratch> firebase@12.18.0
O6_FIREBASE_MODULE_DIR=<scratch> O6_REPO_ROOT="$PWD" \
  O6_LISTEN_CAMPAIGN_PATH="$PWD/spec/compatibility/fs-listen-sdk-local-shadow-campaign.json" \
  O6_LISTEN_SDK_VERSION=12.18.0 GOOGLE_CLOUD_PROJECT=demo-o6 \
  O6_LISTEN_FIREEMU_BINARY="$PWD/target/debug/fireemu" \
  O6_LISTEN_FIREEMU_COMMIT="$(git rev-parse HEAD)" \
  O6_LISTEN_SOURCE_COMMIT="$(git rev-parse HEAD)" \
  target/debug/fireemu exec \
  --firebase-json tools/compat-broad/fs-listen-resume/fs-listen-sdk.firebase.json \
  --project demo-o6 --only firestore,auth \
  --firestore-port 0 --http-port 0 --hub-port 0 --ui-port 0 --logging-port 0 \
  --log-verbosity silent -- \
  node tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs > receipt.json
node tools/compat-broad/fs-listen-resume/local_shadow_check.mjs receipt.json
rm -rf target
```

This is local evidence only. It shows that the catalog is executable, finite and
deterministic, and that `fireemu` produces the expected local result. It does
not show that production produces the same result; that is the campaign's whole
purpose.

## Browser WebChannel local shadow

The Node build of the firebase JS SDK speaks gRPC, so the receipt above says
nothing about WebChannel. A second shadow runs the same eighteen cases through
the browser build of release `12.18.0` in a headless Chromium that
`tools/compat-broad/fs-listen-resume/listen_browser_adapter.mjs` owns, against
an owned `fireemu exec` child on OS-assigned loopback ports. The page loads
`listen_collector.mjs` byte-identical from the lane directory (an import map
supplies a browser SHA-256 for its single `node:crypto` import), so the
normalised event rows have the Node receipt's shape by construction rather than
by translation. The catalog runs twice, one throwaway account each: with
`experimentalForceLongPolling` (every backchannel response closes at once,
`CI=1`) and with auto-detection and long polling both off (one streamed
backchannel per session, `CI=0`). Each per-mode receipt records
`transport: browser-webchannel`, the mode, the Chromium version, the SHA-256 of
the three gstatic bundles the browser executed, the `SDK_VERSION` the bundle
reported, and the WebChannel request log taken from the page's own network view
(stream, role, `CI` and status per request; never a session id, header or body).

The checked-in result is `spec/compatibility/fs-listen-sdk-browser-local-shadow.json`,
with its campaign record at `fs-listen-sdk-browser-local-shadow-campaign.json`.
`test_o6_listen_sdk_browser_local_shadow.py` recomputes the bound source
digests, the catalog digest, the ruleset and binary digests and every case
comparison in both modes, and requires that the long-polling receipt saw only
`CI=1` backchannels and the streaming receipt only `CI=0`. Each per-mode receipt
also passes `local_shadow_check.mjs` unchanged. The two hand-written smoke pages
(`listen-reconnect.html`, `listener-lifecycle.html`) are driven by
`tools/sdk-smoke-browser/run-browser.mjs`; their result is
`spec/compatibility/fs-listen-sdk-browser-smoke-pages.json`.

All eighteen cases agreed with their expected local result in both modes,
including the cross-identity denial and the revocation outcome, which the
WebChannel transport reproduces exactly as gRPC does. This removes "browser
WebChannel path not executed" from the local side of the `FS-LISTEN-SDK`
closure condition; production remains unobserved for every transport.

## What this preparation established about the SDK

Three expectations written before the shadow ran turned out to be wrong about
the client SDK, and the cases were corrected rather than the runtime:

- A listener's first callback is frequently served from the local cache. The
  initial snapshot is therefore defined as the first server-backed snapshot, and
  cached deliveries before it are the same initial snapshot.
- A listener that does not request metadata changes cannot be waited on for a
  server-backed snapshot, because the SDK raises no second callback when the
  content is unchanged. The collector always subscribes with metadata changes so
  it can tell when a listener is ready, and collapses metadata-only events back
  out for cases that do not compare them.
- A listener on a denied path may still raise a cached snapshot before its
  terminal error. The negative auth case therefore asserts that no server
  snapshot preceded the error, not that no snapshot did.

None of these is a `fireemu` defect, and no Repair Ticket was opened.

## What remains unobserved

Five paths cannot be observed from this lane. Each is recorded in the catalog
and repeated in every comparison result, so a future `MATCH` cannot be read as
covering them.

| Path | Why it is unobserved | Plan |
| --- | --- | --- |
| Tenant isolation | Cases `108`/`108C` now observe one principal being refused another principal's private document within one project, but both accounts live in the default tenant. A `MATCH` says nothing about cross-tenant isolation under Rules. | A tenant-scoped throwaway account and a listener case whose principal carries a tenant claim, expecting `permission-denied` across the tenant boundary, once the oracle project has a second tenant. |
| Browser WebChannel | The Node SDK build selects the gRPC transport. WebChannel framing, long polling and the streamed backchannel are exercised only by the browser shadow above, which is local evidence; tab lifecycle is not exercised by any lane. | The browser adapter now exists and runs the same catalog locally. A production browser campaign would drive it against the oracle project with the same page-side request log. |
| Android SDK | No Android runtime, Gradle toolchain or device is available here. | An instrumented Android test module replaying the same catalog and emitting the same normalized event rows. |
| Apple SDK | No iOS or macOS SDK harness exists in this repository. | An XCTest target replaying the same catalog and emitting the same normalized event rows. |
| Raw resume token | The Node client SDK owns the resume token and does not expose it, so `RESET`, stale tokens and compacted tokens cannot be driven from application code. | A direct gRPC Listen probe that supplies a chosen resume token and records the `TargetChange` response, kept as a separate case from SDK-level resume. |

Because all five remain open, `FS-LISTEN-SDK` keeps its blocking condition and
its `WAITING_ORACLE` status. Running this campaign would reduce that condition
to the browser, Android and Apple paths, tenant isolation and raw token
behaviour; it would not clear it.

## Supervised local SDK execution (non-authorizing)

`local_supervisor.py` is an opt-in POSIX launcher for the fixed Node SDK adapter.
Use it **inside an already owned `fireemu exec`**; it supervises the Node client,
not the emulator daemon. Both emulator endpoints must be explicit numeric
loopback addresses and the runtime project must start with `demo-`. There is no
arbitrary-command or production flag. Production permission, externally supplied
nonce/campaign/journal and inherited password descriptors are rejected. The
launcher creates its own fresh nonce and unapproved local campaign inputs.

```sh
# Build/locked SDK installation are prerequisites, not performed by the wrapper.
# The output parent must exist and the final run directory must be unused.
O6_FIREBASE_MODULE_DIR="$PWD/tools/sdk-smoke" GOOGLE_CLOUD_PROJECT=demo-o6 \
O6_LISTEN_FIREEMU_BINARY="$PWD/target/debug/fireemu" \
O6_LISTEN_FIREEMU_COMMIT="$(git rev-parse HEAD)" \
O6_LISTEN_SOURCE_COMMIT="$(git rev-parse HEAD)" \
O6_LISTEN_RULES_PATH="$PWD/tools/compat-broad/fs-listen-resume/fs-listen-sdk.rules" \
  target/debug/fireemu exec \
  --firebase-json tools/compat-broad/fs-listen-resume/fs-listen-sdk.firebase.json \
  --project demo-o6 --only firestore,auth \
  --firestore-port 0 --http-port 0 --hub-port 0 --ui-port 0 --logging-port 0 \
  --log-verbosity silent -- \
  python3 -I -S tools/compat-broad/fs-listen-resume/local_supervisor.py \
    --output /tmp/new-private-listen-run --timeout-seconds 820
```

The default SDK process allowance is 820 seconds (600 observation, 180 cleanup,
40 startup/finalization). The SDK's existing shorter phase/operation budgets are
not extended. The wrapper then allows at most two seconds after SIGTERM and two
after SIGKILL while waiting for its owned leader. An exited leader's inherited
pipes have a one-second drain limit. The local expectation checker has a separate
ten-second process allowance. Filesystem/kernel stalls and an externally killed
supervisor are not a hard-real-time or OS-wide termination guarantee.

Before spawn, `launch.json` records the nonce, local namespace/endpoints and
source/input hashes with fsync. The adapter writes a private hash-linked checkpoint
before signup, after a bound UID is known, and before document operations; a final
checkpoint records the actual lifecycle outcome. UID/path data is private; no
password, token, assertion or arbitrary payload is accepted by the checkpoint
schema. A checkpoint failure stops further data work, still attempts known
in-process cleanup, and cannot be cleared by a later checkpoint. A process cut
off during signup retains a creation intent, not a false absence claim.

The parent bounds stdout to 8 MiB and stderr to 64 KiB, stores them privately,
and prints only completion flags. It never prints raw SDK diagnostics. Exit zero
requires the live process/pipe checks, same-run source/input/nonce/UID-path binding,
and the full local expectation checker. A complete-looking receipt after timeout,
nonzero exit, source drift or partial pipe capture cannot restore success.
`currentArtifactVerified` and `productionCompatibilityVerified` remain false;
these local process/expectation checks are not independent artifact attestation.

`processCleanupComplete` and `resourceCleanupComplete` are independent. A forced
stop can confirm the former while leaving `recoveryRequired=true`. Never delete
`launch.json` or the checkpoints just because the PID exited. If no final result
exists, treat the launch as unresolved. The journal grants **no automatic cleanup
authority**, has no resume/delete command, and cannot prove account or document
absence. Review the exact same-run markers and versions before recovery; never
replay a PID or blindly delete a recorded namespace. Parent SIGKILL, descendants
escaping their process group, durable automatic orphan recovery and actual SDK
wire-request accounting remain separate obligations.

Tests use actual local processes, pipes and sockets and instrumented SDK methods.
The current Rust binary, real Firebase SDK and browser/mobile paths remain to be
executed; compiling inputs or passing these tests does not create that evidence.

### Read-only recovery inspection

An interrupted supervised run can be inspected with
`local_recovery_inspect.py --run ... --output ...` without starting an SDK or
contacting its old endpoints. It preserves a validated responsibility prefix
and does not grant cleanup authority. See
[the inspection contract](fs-listen-recovery-inspection.md) for output privacy,
exit codes, limits, drift handling, and the live checks still required before
any resumed cleanup.
