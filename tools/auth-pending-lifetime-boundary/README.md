# MFA pending credential lifetime: boundary probe (AUTH-U03, revision 2)

Revision 2 samples 600, 1800, 3300 and 3900 seconds using six independent owned accounts (four age samples and two fresh controls). It is a separate corpus; revision 1's contract, recorder and published receipt stay pinned. The project owner authorized one production run on 2026-09-12; its results remain candidate. Any additional production experiment requires separate approval.

Each pending credential stays untouched until its diagnostic. Start obtains a fresh SMS session; finalize verifies the returned identity through claims and lookup. Pending acquisition, start and finalize record request/response timing intervals. Production uses real waiting; the owned local run advances its instance's virtual clock.

## Interpretation

`lowerBoundSeconds` is the largest target age with fully verified MFA completion. The validator checks that the measured pending age at start is at least that target. This is an observed survival point for the recorded method and configuration, not a universal guarantee across accounts.

`refusalObservations` preserves every refused stage, error and actual pending-age interval. `startAcceptedAges` stays separate from complete MFA success. `MISSING_MFA_PENDING_CREDENTIAL` and `MFA_ENROLLMENT_NOT_FOUND` are classified as possible input/account-state problems and never generate expiry candidates.

A later `INVALID_MFA_PENDING_CREDENTIAL` can produce a `boundaryCandidates` entry, with the fully verified success point as `lowerSeconds` and the refused request's measured interval upper endpoint as `upperSeconds`. Start refusal uses `pendingAgeAtStart`; finalize refusal uses `pendingAgeAtFinalize`. A target of 3900 seconds observed at [3900, 3903] therefore yields a candidate endpoint of 3903, not 3900. Candidates do not establish causality: equivalent account conditions, unchanged inputs/enrollment and monotonic usability remain unproven assumptions. Refusal followed by a later verified success sets `nonMonotonic=true` and suppresses single-boundary candidates.

`upperBoundEstablished` and `ageCausedExpiryEstablished` always remain false; `upperBoundSeconds` remains null. Neither a refusal's error name nor one run proves a shared TTL. Start acceptance and MFA completion are different observations. AUTH-U03's expired-pending/fresh-valid-code residual remains outside this corpus.

## Credential and recovery budget

The wall budget is 4800 seconds, including a 300-second recovery reserve. HTTP operations reserve 20 seconds under the inherited trusted-oracle socket-timeout model; this is not a hard total-response deadline. Credential refresh reserves the command's 60-second timeout, tokeninfo's 20 seconds and the following request's 20 seconds before starting. Every operation checks its phase deadline again before sending.

The preflight token and each newly acquired token are checked using the documented [Google tokeninfo request](https://docs.cloud.google.com/sdk/gcloud/reference/auth/application-default/print-access-token). `expires_in` is converted to a conservative monotonic expiry from the tokeninfo request's send time, subtracting one second for precision. Tokens need at least the next request's reserved time remaining. Acquisition age is only an additional refresh trigger (2400 seconds), not a lifetime assumption. Token values and raw tokeninfo responses are never recorded.

At most two refresh attempts are allowed per phase. Any refresh or expiry-verification failure latches authentication unavailable for the rest of the run: there is no automatic retry and no fallback to an old token. Configuration operations and account operations use the same credential path. `privilegedRequests` associates each request with phase, operation, sequence, acquisition age, verified expiry and remaining time; `complete()` checks this evidence against request counts and deadlines. Preflight project/config reads also use this path; its three CLI discovery commands each reserve 60 seconds before starting. Revision 2 keeps the existing project identity, baseline configuration, empty-functions and API-key ownership checks in its own preflight implementation.

Recovery restores configuration with readback/digest checks, then verifies ownership before account deletion. Missing credentials or exhausted time leave configuration recovery unconfirmed, count unrecovered accounts and retain their journals. The corpus remains incomplete until recovery is confirmed.

## Verification

The offline safety suite drives the actual `observe()` and contract against an executable two-clock backend, including real expiry metadata, delayed/failed refresh, tokeninfo failure, insufficient reserve, malformed initial expiry, evidence deletion/tampering, nonmonotonic observations and issuance latency. Its production-mode fixtures perform no network or gcloud operation. The owned runner separately exercises the real strict Auth artifact and verifies child-process cleanup.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 python -m pytest tools/auth-pending-lifetime-boundary -q -p no:cacheprovider
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime-boundary/boundary_owned.py --output /absolute/private/new-local
```

The pre-review local run at `cea9e674` observed success at 600/1800/3300 and rejection at 3900. Its earlier upper-bound interpretation is superseded by the candidate-only interpretation above; it is not evidence of production behavior or approval to run in production.


## Recorded production result (2026-09-12)

The authorized run at `267b10f5a1edf70a2da1a7dff7260e9945f2bd05` completed in 3970.37 seconds with `complete=true`. All four aged starts (600/1800/3300/3900 seconds) returned `INVALID_MFA_PENDING_CREDENTIAL`; their finalizes were skipped. Both fresh controls completed with every identity check. This run has no verified aged success, no sampled survival lower bound and no boundary candidate. It does not prove expiry causality or a lifetime upper bound. In particular, do not combine revision 1's separate 300-second success with this run's 600-second refusal into a certified (300, 600] interval.

The owned local artifact at the same execution commit accepted and fully verified 600/1800/3300 seconds, then refused 3900 seconds. Six semantic rows differ; the two controls and the 3900-second start/skipped-finalize pair agree. This is recorded as the open mismatch `GAP-AUTH-007`, not an implementation fix. AUTH-U03's expired-pending/independently-valid-code residual remains unobserved.

Recovery refreshed the administrative token successfully; all privileged requests retained verified expiry evidence. Configuration readback and digest matched the baseline, and every account was confirmed absent by UID and email. A separate read-only post-run check reconfirmed the configuration digest and all six accounts' absence. Raw reports and recovery journals remain private.

[Production receipt and measured intervals](../../docs/compatibility/auth-pending-lifetime-boundary.md) and [owned local comparison](../../docs/compatibility/auth-pending-lifetime-boundary-comparison.md) are candidate records, not result approvals. Revision 1's published subjects are unchanged.

See the [session clarification](../../docs/compatibility/auth-pending-lifetime-boundary-clarification.md): the design finalizes a fresh session only after an accepted start. In the recorded production aged rows, no session was returned and every finalize was skipped. The pinned production page and receipt remain unchanged.
