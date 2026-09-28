# Local Auth transport, acquisition ownership and budget integrity

This is a **local-only** acquisition change, not production authorization or an
assertion of Identity Platform parity. Historical observations and permissions
remain unchanged. Rust/runtime, real Firebase SDK, latest-artifact replay and
independent review are not established by these Python tests.

## MFA HTTP acquisition

`mfa_wire.py` executes exactly one HTTP request in a fixed Python worker started
with `-I -S -B`. Request/authorization values travel on stdin, not command-line
arguments. Only explicit numeric loopback origins (`127.0.0.1` or `::1`) with an
unprivileged port are allowed. The Instance additionally checks that the target
is one of its two configured Auth/control origins. No redirect or ambient proxy,
Python hook, or cloud credential is inherited. Emulator inspection calls now
use the same attempt counter as control, public and administrative calls.

The caller applies the existing 20-second limit to the worker communication,
body receipt and exit, and kills/waits for its direct child on timeout. Slow but
continuous body bytes cannot keep resetting that parent deadline. **OS process
creation and kill/reap, a stopped kernel/filesystem, parent SIGKILL and power loss
are not hard-bounded by this mechanism.** The worker spawns no descendants. The
parent's 900-second campaign supervision remains separate and unchanged.

The worker requires a complete, at most 64-KiB, object-shaped UTF-8 JSON response
and a single JSON content type. The shared `batch_wire` implementation rejects
ambiguous framing, truncated Content-Length bodies, duplicate decoded JSON keys,
non-finite numbers and overflows. Both the new worker and its shared dependency
are included in MFA source provenance. Invalid replies become fixed, non-secret
errors, not an empty-object response. Normal typed API rejections keep their
HTTP status and body, so an API refusal can still be observed rather than
replaced with a network error. Close-delimited HTTP cannot distinguish every
premature close from a legitimate end; this change does not claim otherwise.

The per-call request and private input limits are local defensive caps, **not
Google quotas**. The attempt count can conservatively include an input rejected
before a request reaches a socket. It is not an invoice or exact packet count.
This change does not add an enforced transport-level aggregate request budget.

## Signup ACK before further setup

The actual MFA walk registers a same-run typed signup UID in the in-memory
account map and collector state and writes its checkpoint **before** parsing the
returned ID token, verifying email or signing in again. A failure in any later
step therefore still reaches the ordinary per-account finally cleanup. Even a
checkpoint-write failure leaves the confirmed in-process owner available to
finally. An error-bearing ACK, wrong returned email or malformed UID does not
grant ownership. A subsequent sign-in carrying a different UID is rejected.

**Unacknowledged signup is still unresolved.** A lost response, missing UID or
malformed ACK is not converted to successful creation, absence, or permission to
delete an account discovered later. This patch does not implement a durable
pre-signup intent journal, restart recovery, or current-instance attestation.
Existing checkpoint publication is not upgraded to crash-safe atomic storage.

## AUTH-CREDENTIAL budgets

The no-network budget helper validates finite non-negative time/cost parameters
and strict integer request counts. The first recovery entry grants the already
declared recovery window; re-entry does not refill time or requests. A delayed
first entry still receives the full existing recovery tail, preserving the
campaign's bounded-observation-plus-bounded-recovery contract.

Invalid/backward monotonic readings latch an integrity failure. Invalid elapsed
charges never subtract time, write NaN, or throw away a received signup ACK:
`charge_elapsed` records a fixed fault instead of raising, and later reservations
fail closed in either phase. Entering recovery is non-throwing on that fault so
the caller can still stop its owned daemon in finally. It grants no network
allowance. Receipt creation and comparison reject an explicit budget integrity
failure even if `recordingComplete` is forced to true. This is an in-process
contract, not authentication of a caller-writable dictionary or a trusted clock.

## Local verification

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q \
  tools/compat-broad/auth-totp-enroll \
  tools/compat-broad/auth-credential-tokens
```

The transport tests use actual loopback sockets and worker processes, while API
responses are synthetic. The signup tests run the real MFA walk/finally with a
bounded fake backend. Credential post tests retain a received ACK across a
negative elapsed-time reading. They do not run the Rust daemon or Firebase SDK.
Two legacy timing fixtures now use independent budget instances / an explicit
clock origin; production deadlines and recovery allowance are not enlarged.
