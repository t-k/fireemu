# MFA pending credential lifetime (AUTH-U03)

One production flow answers the AUTH-U03 lifetime and experiment-feasibility question: as a
valid MFA pending credential ages, at what age does `mfaSignIn:start` (and, on an
acceptance, `mfaSignIn:finalize` of a freshly opened SMS session) still succeed? This is a
lower-bound probe, not a pinned TTL and not an error precedence. "Still usable at every
sampled age within the budget" is a valid outcome that establishes a lower bound, never an
infinite lifetime.

Each sampled age uses an independent owned account. All three pending credentials are
obtained near a common origin and left untouched until their own diagnostic, so no
intermediate access can extend one. The SMS session is opened fresh at the diagnostic, so
the recorded session age is near zero while only the pending age grows; the pending age and
the session age are recorded as separate intervals. Two fresh completions (before any aging
and after all of it) are controls, so a refused aged row reflects the pending age and not a
broken run or exhausted quota.

Production ages by real waiting within a declared observation budget; the owned local run
ages by advancing the shared virtual clock through the control API, so it can sample past
the local pending lifetime deterministically. The oracle project has MFA disabled, no phone
sign-in and an empty SMS region allowlist, so the recorder reuses the configuration change,
PATCH transport, restore and recovery of `tools/auth-pending-revocation`: phone MFA, one
test phone number with a fixed code and the default SMS region policy are enabled for the
run and restored in `finally`, with the restore readback and whole-configuration digest
comparison part of the report. SIGTERM and SIGHUP unwind through the same `finally`, and a
production run refuses to start from a checkout with uncommitted changes in any probe tree.

Rows (revision 1 samples 2, 120 and 300 seconds), in run order:

| Row | Basis | What is sent |
| --- | --- | --- |
| `baseline-fresh-finalize` | control | A fresh pending credential completes the phone second factor before any aging. |
| `age-2s-start` | diagnostic | A pending held about 2 s is presented to `mfaSignIn:start` with a fresh session. Accepted or refused are both valid; no TTL is pinned. |
| `age-2s-finalize` | diagnostic | If the 2 s start returned a session, that fresh session is finalized; skipped otherwise. |
| `age-120s-start` | diagnostic | A pending held about 120 s is presented to `mfaSignIn:start` with a fresh session. |
| `age-120s-finalize` | diagnostic | If the 120 s start returned a session, it is finalized; skipped otherwise. |
| `age-300s-start` | diagnostic | A pending held about 300 s is presented to `mfaSignIn:start` with a fresh session. |
| `age-300s-finalize` | diagnostic | If the 300 s start returned a session, it is finalized; skipped otherwise. |
| `final-fresh-finalize` | control | A fresh sign-in completes the second factor after all aging. |

The observation budget is declared in the report (`budget`) and enforced, not merely
recorded. It names a maximum account count; a maximum request count split into an
observation share and a recovery reserve; a total wall-time budget; a maximum
configuration-hold time; and a cleanup reserve. Two clocks are kept apart: the aging clock
measures a pending credential's age (real monotonic time in production, the virtual clock
locally), while the wall clock (always real monotonic time) enforces the budget, so a local
run's instant virtual aging never trips a wall-time budget and a production run's real
waiting does. The guard is on every request path, not only the aging wait: each request
(preflight and the configuration change included) reserves the transport's worst-case
timeout before it is sent, so a request that starts always finishes before its phase
deadline, and configuration is never enabled once the deadline has passed. Observation must
finish by the total-time or configuration-hold deadline minus the cleanup reserve, and its
request counter is capped at the total minus the recovery reserve, so cleanup (five admin
calls per account) is always affordable even when observation is exhausted. Recovery runs
under its own deadline (it may spend the cleanup reserve) and its own request reserve, and
each recovery request is time-guarded too. Reaching any guard is a clean early stop recorded
in `stopReason` (`time-budget` / `config-hold-budget` / `request-budget`), not a crash, and
the run still restores configuration and deletes accounts in `finally`. The report records
the request counts (observation, recovery, configuration, each counted per attempt so a
failed request still counts), the total wall elapsed and the configuration-hold seconds, and
`complete()` checks all of them against the declared budget. Restore and deletion are always
attempted; success is confirmed by the restore readback, the whole-configuration digest, and
per-account UID and email absence, and a failure is reported (`configRestoreFailure` /
`cleanupFailure`) rather than assumed from reaching `finally`. Whatever recovery cannot
confirm within budget is left with its recovery journal for a later `--recover`, recorded as
`recoveryIncomplete` with an `unrecoveredCount`, so the run never silently exceeds the total.

Every row carries a `timing` region measured on the aging clock, saved on acceptance and
refusal alike, so a refused start keeps its measured pending age. It records the pending
acquisition send and receive times and the start and finalize send and receive times, and
derives the pending age and session age as intervals from those raw timestamps. The pending
credential is issued between its acquisition request's send and receive, so its age at start
is `[startSent - pendingReceived, startReceived - pendingSent]`: the lower bound divides by
the latest possible birth and the upper by the earliest, so the interval always covers the
pending's true age including the acquisition latency. The session is minted during the start
request, so its age at finalize is `[finalizeSent - startReceived, finalizeReceived -
startSent]`, and the fresh-session condition (`<= 30 s`) is judged on that finalize-time
interval, not on a start round-trip. `validate_timing` checks every derived interval against
its raw timestamps and the timestamps against their program order, so an interval that
disagrees with its own times is rejected; `complete()` also requires a finalize row to share
its start row's acquisition and start timestamps, so the two rows describe one credential.
Raw send and receive times are kept so second rounding never loses a boundary. A diagnostic
row records any refusal, including an unlisted class, a throttle or a server error, and the
run continues; a transient throttle or quota answer never completes a run. Only the two
fresh finalizes are controls that must fully succeed; a finalize whose own start was refused
is skipped, not sent. Pending credentials, session identifiers, codes, tokens and passwords
stay in memory; an aborted run keeps only the last request's step (named before the
request), its status and error class, plus the failure's exception class. The timing region
and the elapsed milliseconds are excluded from semantic equality, since they vary across
runs and clocks. Every account is deleted with UID and email absence confirmation.

The lifetime summary classifies each sampled age from its observation, never beyond it. An
age is `usable` only on a fully-verified success: the start returned a session and the
finalize both succeeded and passed every identity check (token present, claims match, second
factor, derived lookup). An HTTP 200 without a usable token is recorded but counted
`indeterminate`, never as a lower-bound success. The largest usable age is a lower bound on
the lifetime, never an infinite lifetime. A refusal records the age and its error, but this
revision does not prove a refusal is due to expiry (that needs an aged pending against an
independently valid code, a later corpus), so `upperBoundEstablished` is always false and no
lifetime upper bound is asserted from a refusal alone.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-pending-lifetime -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime/lifetime_recorder.py --production --output /absolute/private/new-production
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime/lifetime_recorder.py --production --recover /absolute/private/run/<account>/recovery.json
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime/lifetime_recorder.py --production --restore-config /absolute/private/run/config-recovery.json
```

## Local run of the same corpus

`lifetime_owned.py` builds and owns the strict fireemu artifact and runs the same
`observe()` against it with no configuration change, codes read from the emulator inspection
route, and pendings aged by advancing the owned instance's virtual clock. On 2026-09-12 the
owned local run accepted `mfaSignIn:start` and `mfaSignIn:finalize` at all three sampled
ages, with the pending age at start recorded as an interval whose lower bound is at least
the sampled age (2.001, 120.000, 300.000 s) and the session age at finalize near zero,
establishing a verified local lower bound of 300 s with no upper bound (every sampled age is
below the 3600 s fireemu-local pending lifetime). The wall budget was untouched by the
virtual aging, and all five accounts were deleted with absence confirmation. This is the
local behavior, not evidence of
production. The production run, its publication, comparison and approval are separate steps.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime/lifetime_owned.py --output /absolute/private/new-local
```
