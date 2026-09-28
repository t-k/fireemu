# AUTH-CREDENTIAL local runtime integrity

This is a local collection contract, not an assertion of native/SDK or production
compatibility. The campaign budget, declared case list and production admission are
unchanged. Historical receipts remain bound to the modules that produced them.

## HTTP and accounting

`credential_wire.py` is a fixed standard-library worker using the bound
`../batch_wire.py` framing and strict JSON decoders. Each call launches it exactly
once with `-I -S -B`, an allowlisted environment, and request data on stdin. No proxy,
redirect, DNS name, URL userinfo, fragment or inherited Cloud credentials is used.
Targets must be numeric `127.0.0.1` or `[::1]` with an explicit port. `localhost` is
intentionally no longer accepted. Existing local host-prefixed Identity Toolkit,
Secure Token, and `:createSessionCookie` routes still work. Body encoding remains
JSON; this change does not assert real Secure Token wire parity.

The existing five-second request cap is intersected with the current phase's
remaining time. It bounds post-spawn worker execution, headers/body reception and
worker exit. Process creation, kill/reap, a stalled kernel, and parent SIGKILL are
not hard-bounded by `subprocess.run`. There are no retries. The 64 KiB request and
response caps, input envelope cap and startup log caps are local defensive limits,
not Google quotas. Complete reception alone is insufficient: one JSON Content-Type,
UTF-8, an object, no duplicate decoded keys and finite numeric values are required.
Raw bytes are preserved through the worker. Injected senders are subject to the
same parent-side typed status/body validation, but do not prove HTTP headers.

Reservations are made before sending and elapsed time is charged afterwards. A
valid received ACK still reaches its caller when elapsed accounting latches a
budget fault; subsequent reservations fail. Invalid or ambiguous ACKs remain
unusable; this runtime does not solve signup-ACK loss or grant orphan cleanup.

## Owned daemon lifecycle

Startup uses nonblocking, bounded line scanning with a 60-second startup window.
Silence, partial lines, oversized output, invalid addresses, or early exit cannot
trap the caller in `readline`. An output thread continues draining after readiness,
without retaining daemon output, so pipe capacity cannot stall a running daemon.
The process is placed in a new session and inherits only the explicit environment.
Readiness is still a claim made by the supplied executable, not independent instance
identity, binary authentication, or a proof that the advertised port is owned.

Every exception after spawn and before ownership transfer attempts leader stop.
Child census errors do not bypass shutdown; they leave `remainingChildren` unknown.
Census uses a separate two-second subprocess cap. TERM/KILL waits retain their
20-second bounds. A group is signalled only while its owned leader is alive. The
pre-stop sample contains direct children only; this is not a transitive OS-wide
census and does not prove the absence of escaped/reparented descendants. An unknown
child state, output-monitor error or close failure prevents successful completion.

## Resource cleanup and result publication

Each registered account gets the existing delete, UID lookup, and (when applicable)
email lookup. A normal exception for one UID does not skip other owned UIDs. The
same remaining request/time reserve is shared; there is no reset or retry grant.
Delete requires a typed success body (`{}` or the known DeleteAccountResponse kind).
Absence requires explicit empty `users` or the exact GetAccountInfoResponse kind,
with no conflicting fields. A bare `{}`, null/false users, errors, unknown kind or
pagination cannot establish absence. An addressless account makes no email-readback
claim. Unknown or unregistered created accounts remain outside this cleanup path.

CLI success requires complete case recording, local expected-result agreement,
resource cleanup, sound budget accounting, and typed process-shutdown evidence.
Unexpected errors and cleanup interrupts still reach daemon shutdown. Ordinary
exception diagnostics carry type names, never raw server/exception text. Output and
per-run work directories must be fresh; final output is exclusive and written after
cleanup/shutdown with file/directory fsync. Concurrent output is not overwritten.
A partial write or fsync failure remains a publication failure, not an accepted
result. This is not a restartable write-ahead journal or power-loss-safe recovery.

The binary hash and caller's source-commit assertion are recorded. This does not
independently prove which source built the binary, or protect against same-user
modification during launch. The new process/worker/shared-code digests are included
in the collector binding; old receipt hashes must not be relabelled as new runs.

## Validation and remaining acceptance

Regression fixtures exercise real loopback sockets, fixed HTTP worker processes,
executable startup fixtures, pipe draining and process stops. SDK/native behavior
is not substituted by these fixtures. Run the new `test_credential_local_http.py`,
`test_credential_process_lifecycle.py` and `test_credential_cleanup_completion.py`
together with the existing credential domain. Real Rust artifacts, fixed SDKs,
current local shadow/replay, full workspace, history inputs and independent review
remain necessary. All pre-existing first-party scope exclusions remain unchanged.
