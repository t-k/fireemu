# AUTH-MFA next campaign preparation: age causality and TOTP

Status: `WAITING_ORACLE`. `productionExecuted=false`, `productionAllowed=false`. Nothing here is a production observation, an approval, or a parity claim. Production-unobserved conditions reduced by this work: 0.

The AUTH-MFA row is blocked on five things: age causality, controls at 300, 450 and 600 seconds, a fresh same-account control, a TOTP matrix and an interaction matrix. This page describes the campaign that would observe them, what `fireemu` already answers for every one of those cases, and what an owner would have to grant before the campaign could run. It supersedes nothing: revisions 1 and 2 of the pending-lifetime corpus, `GAP-AUTH-006` and `GAP-AUTH-007` keep their receipts and their candidate status.

## What is still missing, and why the earlier package could not supply it

Revision 1 recorded a verified MFA completion with a pending credential aged 300 seconds. Revision 2 recorded refusals at 600, 1800, 3300 and 3900 seconds, each `INVALID_MFA_PENDING_CREDENTIAL`, using six independent accounts. Neither run establishes that age caused the refusal. Every aged sample used its own account and its own enrollment, so an account-state or configuration explanation was never excluded, and the two runs must not be combined into a certified interval.

The earlier TOTP package, `AUTH-MFA-TOTP-ENROLL-RETRY-01`, was reduced to a non-executable preparation because it had no validated request contracts, no enforced limits, no real cleanup finalizer and no provenance. Its comparator returned `INDETERMINATE` for every input because a receipt's source binding was whatever string the caller wrote into it. That package stays as it is; this campaign is the executable successor and inherits its one distinct obligation, the wrong-code-then-retry question, as a single case.

## Design

**Age causality.** Each sampled age gets one account. That account acquires a pending credential, leaves it untouched for the age, and offers it. Immediately afterwards, the same account signs in again and completes MFA with a newly acquired pending credential. A refusal on the aged credential paired with a success on the fresh one, at the same moment, on the same account, with the same enrollment and the same project configuration, leaves pending age as the only remaining explanation. It still assumes the aged credential was untouched and that usability is monotonic in age, and it holds for the observed account rather than universally.

**Sampled ages.** 300, 450 and 600 seconds. Production is known to have survived 300 seconds once and to have refused at 600 seconds once, in separate runs; 450 seconds bisects that interval and has never been sampled. Each sample is taken just past its target, so a refusal is attributed to the measured interval's upper endpoint rather than to the target.

**TOTP.** Enrollment start returns the shared secret; the campaign computes RFC 6238 codes locally, so no device and no third-party application is involved. The lifecycle walks start, a deterministically wrong code, a correct code in the same session, a replay of the finalized session, factor readback, sign-in start, sign-in finalize, a replay of the consumed code, withdrawal, readback after withdrawal, and withdrawal of an identifier that no longer exists. A separate family ages the enrollment session itself at the same three points.

**Interaction.** Unverified email, an ineligible first factor, a missing ID token, a second factor on an account that already has one, and a project-configuration readback before and after the run.

Thirty cases in all: eleven for pending age, eleven for the TOTP lifecycle, three for enrollment-session age, and five interaction cases.

## Bounded, resumable collection

The collector is a state machine, not a loop that sleeps. A step that has to wait returns the instant it becomes due; the caller writes a checkpoint and stops. Any later process loads the checkpoint and reaches the same decision, so a ten-minute wait is a file rather than a blocked process. The checkpoint carries a digest of its own contents and is refused if it was altered.

Budgets are enforced rather than described. Exceeding the request budget or the wall-clock deadline latches an abort, and an aborted run still has to finish its cleanup contract: every account it created deleted, and absence proved separately from deletion. A run reports completion only when every case is resolved, nothing is left over and no abort latched. Observations that would carry a shared secret, a one-time code, a token, a pending credential or a session identifier are refused before they can be stored, rather than redacted afterwards.

## Budget and permission envelope

| Bound | Value |
| --- | --- |
| Requests | 180 |
| Wall clock | 1800 s, including a 300 s recovery reserve |
| Owned accounts | 12 |
| Estimated cost | US$0.10 |
| Hard cost ceiling | US$0.50 |

The estimate is low because nothing in the campaign is metered per message. TOTP verification sends nothing, and the pending-age family uses a test phone number with a fixed code, so no SMS is delivered. The ceiling exists to stop a run that somehow starts billing, not because the expected cost approaches it.

The envelope allows only Identity Platform account and project-configuration endpoints. Firestore, Storage, Functions and Pub/Sub are out of scope, as is any account the run did not create, any tenant operation and any blocking-function deployment. Configuration may be changed only for multi-factor state, enabled providers and test phone numbers, and must be restored with a readback and a whole-configuration digest equal to the pre-run baseline.

## Owner preconditions

1. Identity Platform is enabled on the project, because the multi-factor configuration lives there.
2. Multi-factor authentication is `ENABLED` with TOTP among the enabled providers, and the pre-run configuration is captured and digested first.
3. Phone multi-factor is enabled with one test phone number and a fixed code, so the pending-age rows send no SMS.
4. The SMS region policy allows that number's region for the duration of the run.
5. No tenant, blocking function or identity-provider change happens during the run.
6. The executing principal may create, read, update and delete the accounts it created, and may read and restore the project configuration.
7. A named owner approves one run, bound to the manifest digest and a fresh nonce, acknowledging that up to twelve accounts are created and deleted.

## Provenance

The earlier review found that the comparator accepted any forty-character commit and any sixty-four-character digest a caller supplied, so the binding proved nothing. The binding is now recomputed rather than trusted: the comparator hashes the campaign definition, the collector, the code computation, the comparator itself and the environment lockfiles from the worktree it is running in, and accepts a receipt only when the receipt's binding equals what it just computed. A forged or stale binding fails verification instead of unlocking a comparison. The receipt also records the commit the run was taken at and whether that worktree was clean; an unresolved or dirty worktree is treated as unbound.

Agreement additionally requires a production side that says it was executed. Preparation receipts say `productionExecuted=false`, so no preparation input can reach agreement no matter how well it is bound. A pair that is fully bound but has no production observation classifies as `PREPARATION_ONLY`.

## Local shadow against fireemu

All thirty cases were run against an owned local `fireemu` instance: one strict Auth artifact with TOTP configured, on OS-assigned ports, aged by advancing that instance's own virtual clock, with every account deleted and its absence confirmed afterwards. Every row's observed status and error code matched the expectation read from the sources, and the ledger contains no secret material.

Three predictions were corrected by that run and the corrections are in the case definitions:

- A second TOTP enrollment on an account that already has one is refused at `mfaEnrollment:start`, not at finalize.
- A TOTP enrollment session sampled just past 300 seconds answers `SESSION_EXPIRED`; the boundary instant itself is accepted, so a sample taken at the target plus a millisecond is already expired.
- The same session sampled just past 600 seconds answers `INVALID_SESSION_INFO`, because the expired session has been reaped after one further lifetime.

The local answers that matter for the production comparison:

| Case | fireemu | Production |
| --- | --- | --- |
| Pending credential at 300 s | accepted, MFA completes | survived once, revision 1 |
| Pending credential at 450 s | accepted, MFA completes | never sampled |
| Pending credential at 600 s | accepted, MFA completes | refused once, revision 2 |
| TOTP `mfaSignIn:start` | `INVALID_ARGUMENT`, no start step | unobserved |
| Project multi-factor configuration | not modelled | unobserved |

`fireemu`'s pending lifetime is a declared 3600-second local policy that the source itself marks as not a claimed production value, so the 600-second row is the already-recorded `GAP-AUTH-007` divergence rather than a new one. The 450-second row is the one the campaign would add.

## What this campaign still would not establish

An exact production lifetime, an error-precedence rule, tenant-scoped behaviour, blocking-function interaction, SDK and Rules paths, and the expired-pending-with-independently-valid-code residual that `AUTH-U03` tracks. A refusal's error name is not a TTL, and three ages on one account in one run are not a universal guarantee.

## Reproduction

```sh
uv run --project tools/compat-inventory --locked --python 3.12 pytest -q tools/compat-broad/auth-totp-enroll
uv run --project tools/compat-inventory --locked --python 3.12 \
  tools/compat-broad/auth-totp-enroll/mfa_local_shadow.py --output /absolute/private/o2-mfa-shadow
```

The shadow builds or reuses the local artifact, owns one instance, and reaps it; it contacts nothing but loopback and reads no ambient Google credentials.
