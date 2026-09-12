# MFA pending credential lifetime: boundary probe (AUTH-U03, revision 2)

Revision 2 of `auth-pending-lifetime`. Revision 1 confirmed a 300-second survival lower
bound; this revision extends the sampled ages to straddle the boundary where a pending
credential stops being usable, so a run can observe a refusal at a large age and record the
usability window as an interval rather than only a lower bound. It is a separate corpus:
revision 1's contract, recorder and receipt stay pinned and untouched.

Sampled ages (revision 2): 600, 1800, 3300 and 3900 seconds. The first three re-confirm
usability well past revision 1's 300 seconds; the last two straddle the 3600-second
fireemu-local pending lifetime, so an owned local run observes a refusal at 3900 seconds and
the window's upper bound. Everything else follows revision 1: one independent owned account
per age, each pending obtained near a common origin and left untouched until its diagnostic,
a fresh SMS session opened at each diagnostic, the pending age at start and the session age
at finalize recorded as separate intervals, and a wall-clock observation budget that a long
run cannot silently exceed (a guard on every request path, a recovery reserve, and
`recoveryIncomplete` when deletion cannot be confirmed within budget).

Two things are new because a production run ages by real waiting to about 3900 seconds (~65
minutes), which outlives a single admin access token:

- **Admin-credential refresh.** The ADC access token used for the privileged account
  requests (setup and cleanup) is refreshed once it is older than 40 minutes, comfortably
  under both its ~1-hour lifetime and the budget's `adminTokenMaxAgeSeconds` (50 minutes).
  The recorder records each token age at use in `adminTokenAges`, and `complete()` requires
  every one to be within the budget, so a long run never issues an admin request with a
  token older than allowed. The owned local run uses the fixed strict-profile token, so it
  records no token ages.
- **Long-run budget.** `totalBudgetSeconds` and `configHoldMaxSeconds` cover the largest age
  plus setup and a larger cleanup reserve; `maxRequests` and the recovery reserve are raised
  for six accounts.

## What it establishes

The largest age at which a fully-verified MFA completion still succeeds is a lower bound on
the usability window. An upper bound is established only when an expiry-class refusal
(`INVALID_MFA_PENDING_CREDENTIAL`, `MISSING_MFA_PENDING_CREDENTIAL`, `MFA_ENROLLMENT_NOT_FOUND`)
is observed at an age strictly above a verified success; it is then the interval between
them. That upper bound is on the start-acceptance / usability window for this configuration,
method and single run, not the exact TTL, and not the AUTH-U03 residual (an expired pending
against an independently valid code, a later corpus). A refusal with any other error, or
below every success, leaves the upper bound undetermined.

## Offline verification

On 2026-09-12 the owned local run (strict profile, `--only auth`, virtual-clock aging)
accepted 600, 1800 and 3300 seconds and refused 3900 seconds with
`INVALID_MFA_PENDING_CREDENTIAL`, giving `lowerBoundSeconds=3300` and an upper bound of
(3300, 3900] -- capturing the 3600-second fireemu-local pending lifetime. The scripted
two-clock safety suite additionally covers: all-ages-usable as a lower bound only; a
non-expiry refusal (or a refusal below a later success) not establishing the upper bound;
the admin token being refreshed with every recorded age within budget; timing intervals
checked against their raw timestamps; a dirty checkout refused; and no credential in any
file. This is the local behavior; the production run is a separate pre-review.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-pending-lifetime-boundary -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime-boundary/boundary_owned.py --output /absolute/private/new-local
# Production is a separate pre-review; when approved:
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime-boundary/boundary_recorder.py --production --output /absolute/private/new-production
```
