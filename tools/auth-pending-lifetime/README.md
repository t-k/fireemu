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

The observation budget is declared in the report (`budget`): a maximum account count, a
maximum request count, a total time budget, a maximum configuration-hold time and a cleanup
reserve. Reaching a budget guard aborts the run (an incomplete report), and the run still
restores configuration and deletes every account in `finally`. A diagnostic row records any
refusal, including an unlisted class, a throttle or a server error, and the run continues;
a transient throttle or quota answer never completes a run. Only the two fresh finalizes
are controls that must fully succeed; a finalize whose own start was refused is skipped, not
sent. Pending credentials, session identifiers, codes, tokens and passwords stay in memory;
an aborted run keeps only the last request's step (named before the request), its status and
error class, plus the failure's exception class. The measured pending and session ages and
the elapsed milliseconds are excluded from semantic equality, since they vary across runs
and clocks. Every account is deleted with UID and email absence confirmation.

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
ages (2, 120, 300 s), with the SMS session age near zero at each, establishing a local lower
bound of 300 s with no upper bound (every sampled age is below the 3600 s fireemu-local
pending lifetime). This is the local behavior, not evidence of production. The production
run, its publication, comparison and approval are separate steps.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime/lifetime_owned.py --output /absolute/private/new-local
```
