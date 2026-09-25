# MFA pending credential short window (AUTH-U03, revision 3)

This separate corpus investigates GAP-AUTH-007 at 300, 450 and 600 seconds, with an independent account per age and fresh controls before and after the diagnostics: five accounts and seventeen result rows. Revision 1/2 sources and published subjects stay pinned. This directory contains the design and offline verification for the next observation; it does not publish a new production result, alter the emulator's TTL, or resolve GAP-AUTH-007.

## Protocol and evidence

After setup and the baseline fresh control, acquire one pending credential per age account. Leave each credential untouched until its own target age, measured conservatively from its acquisition response. Record the old start response and actual pending-age interval. Only an accepted start with a session proceeds to finalize, recording a separate pending-age interval and session-age interval. Verify returned identity using token claims and a derived account lookup.

After an old start or finalize refusal, perform these steps on that same account:

1. Read back the known UID through the privileged account API. Record request/response times and booleans for UID, email, ownership marker, enabled state, verified email, exactly one matching enrollment and matching phone. Setup requires the same enabled/verified state and enrollment/phone. Missing or changed state suppresses the fresh flow; the observer never repairs the account to make the control succeed.
2. Repeat first-factor sign-in only after that readback. Require the expected enrollment and a nonempty pending credential different from the refused credential. Acquire a fresh session and finalize it; retain identity checks separately from the old diagnostic.
3. Preserve a classified fresh start/finalize refusal as its own row. HTTP 200 without a session retains `sessionInfoPresent=false`, skips finalize and is not verified success. Missing identity tokens or failed identity checks are retained as unsuccessful verification. An acquisition exception, malformed acquisition or repeated old credential stops collection as incomplete with sanitized failure metadata and recovery, rather than claiming a successful control.

If the old diagnostic did not refuse, skip all three post-refusal rows. The contract rejects missing rows, fresh operations after failed state checks, readback before the old refusal response, or fresh acquisition before readback completion. Fresh start must occur within a measured 30-second upper age; accepted finalize requires a session-age upper endpoint no greater than 30 seconds. Token values, pending credentials, sessions, SMS codes and raw account records are not result fields.

`complete()` means the required observations were collected and recovery was confirmed. It does not mean every diagnostic or same-account fresh control succeeded. Unclassified/transient failures, failed global controls, incomplete acquisition and unconfirmed recovery remain incomplete.

## Interpretation

`lifetime_summary()` retains the revision-2 distinction between start acceptance, fully verified MFA completion and stage-specific measured refusals. It additionally reports `sameAccountControls`: the target age, whether account state matched, and whether fresh completion was fully verified. These are separate facts; a healthy readback alone is not fresh success.

An old refusal with matching account state and verified fresh completion narrows the explanation toward the held credential. It still does not prove age causality, equivalence across accounts or a shared TTL. `ageCausedExpiryEstablished=false`, `upperBoundEstablished=false` and `upperBoundSeconds=null` remain unconditional. Candidate endpoints use the refused request's measured interval upper endpoint, never its target age. Nonmonotonic observations suppress single-boundary candidates. Missing-pending and missing-enrollment errors remain input/account-state signals, not automatic expiry evidence.

The experiment creates a session only after an accepted aged start. It does not exercise an independently aged SMS session with expired pending and independently valid code. That AUTH-U03 residual stays unobserved. Results from earlier runs do not establish a certified 300–600 second interval.

## Budget and recovery

The declared wall/configuration budget is 1500 seconds, with a 300-second recovery reserve, at most five accounts and 300 Auth requests including 60 reserved for recovery. The revision-2 credential safety path is retained: actual tokeninfo expiry verification, phase guards before refresh/HTTP operations, a 60-second command reserve, 20-second tokeninfo and following-request reserves, at most two refresh attempts per phase, and a failure latch that invalidates the credential and prevents per-account retries or stale-token fallback. Each privileged request records verified expiry evidence, including configuration requests.

The inherited 20-second HTTP reservation assumes a trusted, responsive oracle and bounds individual socket operations; it is not a hard total-response deadline. Recovery restores configuration with digest/readback confirmation, then verifies ownership before deletion and confirms UID/email absence. Exhausted budgets or credentials leave unconfirmed recovery and private journals intact. No automatic retries enlarge the declared budget.

## Coverage ledger

The offline suite executes the real recorder and contract against a deterministic account/session/token service with two clocks; it never contacts Firebase or gcloud.

| Obligation | Verification |
| --- | --- |
| Five independent accounts and 300/450/600 schedule | Short schedule and healthy same-account controls |
| No fresh pending before old diagnosis/readback | Per-UID event sequence and timestamp tampering tests |
| Account, ownership, enabled/verified and enrollment/phone drift | Eight drift cases suppress fresh acquisition |
| Different pending on the same account | Reused-credential negative test |
| Fresh refusal, missing session, missing identity and finalize refusal | Dedicated tests and bounded outcome model |
| Start acceptance separate from finalize refusal | Finalize-refusal scenario |
| Measured candidate contains known model boundary | Model TTL 451 seconds with 3-second acquisition latency yields [450,453] refusal |
| Nonmonotonic outcomes and no causal/upper-bound promotion | All 27 aged outcome combinations × six control outcomes: 162 finite executions |
| Invalid expiry, failed refresh and insufficient reserve | Initial tokeninfo, failure latch, deadline and retained-journal tests |
| Complete privileged evidence | Missing/altered requests, expiry and counter mutations |
| Secret-free artifacts and signal restoration | Every service-backed scenario checks saved files and restored SIGTERM handler |
| Real local behavior and process lifecycle | Owned strict artifact runner, virtual clock, verified process/listener shutdown |
| Future regression detection | Compatibility CI runs this suite alongside pinned revision 1/2 suites and all four existing publisher checks |

Source mutation verification independently runs an unchanged copied baseline before each campaign. Seven selected changes to credential distinction, state gating, operation ordering, measured endpoints, causal claims and refresh latching must fail the suite. This is bounded targeted verification, not exhaustive proof of production behavior.

## Commands and current status

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/auth-pending-lifetime-window -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/auth-pending-lifetime-window/window_owned.py --output /absolute/private/new-window-local
```

The owned runner builds and copies its strict artifact, uses OS-assigned ports, advances only its own virtual clock and confirms the child and listeners stopped. It never attaches to another daemon. The local verification on 2026-09-12 accepted and fully verified all three sampled ages; therefore its post-refusal rows were skipped. Same-account refusal controls were exercised by the offline service, not claimed as real local or production observations.

A production observation must use a reviewed, frozen recorder with a private output directory and the designated oracle project. No revision-3 production observation or publisher is included in this milestone. Review the design and offline evidence before the next acquisition; the earlier revision-2 execution is not a revision-3 result.
