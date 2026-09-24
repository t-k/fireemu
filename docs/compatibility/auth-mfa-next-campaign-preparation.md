# AUTH-MFA next campaign preparation: age causality and TOTP

Status: `WAITING_ORACLE`. `productionExecuted=false`, `productionAllowed=false`. Nothing here is a production observation, an approval, or a parity claim. Production-unobserved conditions reduced by this work: 0.

The AUTH-MFA row is blocked on five things: age causality, controls at 300, 450 and 600 seconds, a fresh same-account control, a TOTP matrix and an interaction matrix. This page describes the campaign that would observe them, what `fireemu` already answers for every one of those cases, and what an owner would have to grant before the campaign could run. It supersedes nothing: revisions 1 and 2 of the pending-lifetime corpus, `GAP-AUTH-006` and `GAP-AUTH-007` keep their receipts and their candidate status.

## What is still missing, and why the earlier package could not supply it

Revision 1 recorded a verified MFA completion with a pending credential aged 300 seconds. Revision 2 recorded refusals at 600, 1800, 3300 and 3900 seconds, each `INVALID_MFA_PENDING_CREDENTIAL`, using six independent accounts. Neither run establishes that age caused the refusal. Every aged sample used its own account and its own enrollment, so an account-state or configuration explanation was never excluded, and the two runs must not be combined into a certified interval.

The earlier TOTP package, `AUTH-MFA-TOTP-ENROLL-RETRY-01`, was reduced to a non-executable preparation because it had no validated request contracts, no enforced limits, no real cleanup finalizer and no provenance. Its comparator returned `INDETERMINATE` for every input because a receipt's source binding was whatever string the caller wrote into it. That package stays as it is; this campaign is the executable successor and inherits its one distinct obligation, the wrong-code-then-retry question, as a single case.

## Design

**Age causality.** Each sampled age gets one account. That account acquires a pending credential, leaves it untouched for the age, and offers it. Immediately afterwards, the same account signs in again and completes MFA with a newly acquired pending credential. A refusal on the aged credential paired with a success on the fresh one, at the same moment, on the same account, with the same enrollment and the same project configuration, leaves pending age as the only remaining explanation. It still assumes the aged credential was untouched and that usability is monotonic in age, and it holds for the observed account rather than universally.

**Sampled ages.** 300, 450 and 600 seconds. Production is known to have survived 300 seconds once and to have refused at 600 seconds once, in separate runs; 450 seconds bisects that interval and has never been sampled. Each sample is taken just past its target, so a refusal is attributed to the measured interval's upper endpoint rather than to the target.

Google publishes no lifetime for `mfaPendingCredential` and none for the TOTP enrollment `sessionInfo` that `mfaEnrollment:start` returns. None of the eight reference sources the campaign cites states one. These ages therefore bracket an empirical boundary rather than test a documented one, and under the monotonicity assumption they can localise it to (300, 450] or (450, 600], or report that it is greater than 600.

**A control for the refusal direction.** A fourth age, 1800 seconds, is carried as a control rather than as a sample, because production has already refused it. Without it, a run in which all three sampled ages are accepted cannot distinguish a lifetime longer than believed from a sampler that never aged anything. It costs no extra requests and no extra accounts beyond its own, but it is not free: it is the longest age in the run, so it raises the critical path from 630 seconds to 1830 and is the reason the wall budget is 2700 seconds rather than roughly 1400. That is the price of being able to read the other three samples at all.

**TOTP.** Enrollment start returns the shared secret; the campaign computes RFC 6238 codes locally, so no device and no third-party application is involved. The lifecycle walks start, a deterministically wrong code, a correct code in the same session, a replay of the finalized session, factor readback, sign-in start, sign-in finalize, a replay of the consumed code, withdrawal, readback after withdrawal, and withdrawal of an identifier that no longer exists. A separate family ages the enrollment session itself at the same three points.

**Interaction.** Unverified email, an ineligible first factor, a missing ID token, a second factor on an account that already has one, and a project-configuration readback before and after the run.

Thirty-three cases in all: fourteen for pending age including the refusal-direction control, eleven for the TOTP lifecycle, three for enrollment-session age, and five interaction cases.

**The acquisition schedule is contractual.** Every aged pending credential and every aged enrollment session is acquired at one common origin before any wait begins, and each aged row is scheduled at that origin plus its own age. The ages therefore elapse concurrently and the run's critical path is the largest age, 1800 seconds, plus one TOTP step rollover. The obvious alternative, acquiring each resource immediately before its own wait, costs the sum of the ages instead: 4530 seconds, counting each aged resource once rather than once per row that reads it, which does not fit any sensible budget. The manifest declares the schedule and the per-case due offsets, the case list is ordered so those offsets never decrease, and a test walks the collector through both readings to show that one fits the budget and the other exhausts it.

## Bounded, resumable collection

The collector is a state machine, not a loop that sleeps. A step that has to wait returns the instant it becomes due; the caller writes a checkpoint and stops. Any later process loads the checkpoint and reaches the same decision, so a ten-minute wait is a file rather than a blocked process. The checkpoint carries a digest of its own contents and is refused if it was altered.

Budgets are enforced rather than described. Exceeding the request budget or the wall-clock deadline latches an abort, and an aborted run still has to finish its cleanup contract: every account it created deleted, and absence proved separately from deletion. A run reports completion only when every case is resolved, nothing is left over and no abort latched. Observations that would carry a shared secret, a one-time code, a token, a pending credential or a session identifier are refused before they can be stored, rather than redacted afterwards.

## Budget and permission envelope

| Bound | Value |
| --- | --- |
| Requests | 400 |
| Wall clock | 2700 s |
| Critical path | 1830 s |
| Serial cost of the same aging | 4530 s |
| Provisioning allowance | 420 s |
| Recovery reserve | 300 s |
| Owned accounts | 14 |
| Estimated cost | US$0.10 |
| Hard cost ceiling | US$0.50 |

The request bound counts calls at the transport, not one notional call per case, so it covers the acquisition before the first row and the deletions after the last. The local shadow charges 132 against it; the headroom covers production's preflight, configuration read and restore, and credential refreshes.

The estimate is low because nothing in the campaign is metered per message. TOTP verification sends nothing, and the pending-age family uses a test phone number with a fixed code, so no SMS is delivered. The ceiling exists to stop a run that somehow starts billing, not because the expected cost approaches it.

The envelope allows only Identity Platform account and project-configuration endpoints. Firestore, Storage, Functions and Pub/Sub are out of scope, as is any account the run did not create, any tenant operation and any blocking-function deployment. Configuration may be changed only for multi-factor state, enabled providers and test phone numbers, and must be restored with a readback and a whole-configuration digest equal to the pre-run baseline.

## Owner preconditions

1. Identity Platform is enabled on the project, because the multi-factor configuration lives there.
2. Multi-factor authentication is `ENABLED` with TOTP among the enabled providers, and the pre-run configuration is captured and digested first.
3. Phone multi-factor is enabled with one test phone number and a fixed code, so the pending-age rows send no SMS.
4. The SMS region policy allows that number's region for the duration of the run.
5. No tenant, blocking function or identity-provider change happens during the run.
6. The executing principal may create, read, update and delete the accounts it created, and may read and restore the project configuration.
7. A named owner approves one run, bound to the manifest digest and a fresh nonce, acknowledging that up to fourteen accounts are created and deleted.

## Provenance

The earlier review found that the comparator accepted any forty-character commit and any sixty-four-character digest a caller supplied, so the binding proved nothing. The binding is now recomputed rather than trusted: the comparator hashes every non-test module in the package, the recorder that issues the requests included, together with the environment lockfiles, from the worktree it is running in, and accepts a receipt only when the receipt's binding equals what it just computed. Binding the case list without the recorder would have proved which observations were planned while leaving the program that made them free to differ, so the bound set is derived from the package rather than hand-picked, and a test fails if a new module is added without binding it. A forged or stale binding fails verification instead of unlocking a comparison. The receipt also records the commit the run was taken at and whether that worktree was clean; an unresolved or dirty worktree is treated as unbound.

Each receipt also carries the manifest it ran, and the comparator recompiles that manifest from the code before it will compare anything. A receipt whose manifest does not recompile, whose rows do not match its manifest's cases in order, or whose manifest differs from the other side's outside the per-run owner block, is indeterminate. The two sides may hold different nonces, because each owns its own accounts.

Agreement additionally requires a production side that says it was executed and carries owner approval bound to that receipt's own manifest digest and nonce digest, naming an approver and granting exactly one run. Preparation receipts say `productionExecuted=false` and carry no approval, so no preparation input can reach agreement no matter how well it is bound; a bound pair with no production observation classifies as `PREPARATION_ONLY`. The honest limit of this check is worth stating: it raises forgery from editing one boolean to reproducing a validated manifest and an approval bound to its digests. It is not a signature, and a JSON receipt cannot be one.

## Local shadow against fireemu

All thirty-three cases were run against an owned local `fireemu` instance: one strict Auth artifact with TOTP configured, on OS-assigned ports, aged by advancing that instance's own virtual clock, with every account deleted and its absence confirmed afterwards. Every row's observed status and error code matched the expectation read from the sources, and the ledger contains no secret material.

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
| Pending credential at 1800 s | accepted, MFA completes | refused once, revision 2 |
| TOTP `mfaSignIn:start` | `INVALID_ARGUMENT`, no start step | unobserved |
| Project multi-factor configuration | not modelled | unobserved |

`fireemu`'s pending lifetime is a declared 3600-second local policy that the source itself marks as not a claimed production value, so the 600-second row is the already-recorded `GAP-AUTH-007` divergence rather than a new one. The 450-second row is the one the campaign would add.

## Token claims moved from AUTH-CREDENTIAL

AUTH-CREDENTIAL scope decision C7 (owner, 2026-09-24) moves these token-claim conditions here; they are required conditions of this parent and are not verified anywhere else:

- The ID token after a second-factor sign-in carries `firebase.sign_in_second_factor` and `firebase.second_factor_identifier` as production issues them, for SMS and TOTP.
- A refresh of that session keeps both claims, and a session cookie made from it carries them.
- A session revoked or a factor withdrawn afterwards is answered as production answers it.

AUTH-CREDENTIAL's harness (`conformance/src/auth-credential/`) records a token as its header shape and every claim, and can be reused for these rows.

## What this campaign still would not establish

An exact production lifetime, an error-precedence rule, tenant-scoped behaviour, blocking-function interaction, SDK and Rules paths, and the expired-pending-with-independently-valid-code residual that `AUTH-U03` tracks. A refusal's error name is not a TTL, and three ages on one account in one run are not a universal guarantee.

## Artifacts

The frozen manifest is `spec/compatibility/broad-runs/o2-mfa-next-campaign-manifest.json`, compiled with a fixed documentation nonce; a run requires a fresh one. The local ledger is `spec/compatibility/broad-runs/o2-mfa-local-shadow.json`, recorded at the commit and clean worktree its own receipt names. Neither file is a production receipt.

## O8 descriptor and the shadow at HEAD

The campaign now has an O8 descriptor, admission and launcher under `tools/compat-broad/auth-totp-enroll` (`mfa_descriptor.py`, `mfa_admission.py`, `mfa_o8.py`). The budget is re-derived slot by slot against the 400-request bound: 160 data requests, 21 management slots (tokeninfo, configuration readback, apply and readback, restore and readback, three resumes), 33 recovery requests (each of the 11 owned accounts deleted and proven absent by UID and by email), 186 headroom; wall 2700 s = 420 s provisioning + 30 s configuration enforcement lag + 1830 s critical path + 300 s recovery + 120 s slack; Ledger claim 400 requests, 14 accounts, 14 resources, 100021 micro-USD (US$0.10 estimate plus one micro-USD per management slot, US$0.50 ceiling). The Ledger locks are WRITE on the nonce-scoped account namespace, EXCLUSIVE on `project/fireemu-35fe6/auth/config`, READ on identity.

The configuration change is a locked step. The permission freezes `authConfigBaselineDigest`, the whole-configuration digest of an owner readback; the launcher refuses to start unless the live readback equals it. The pre-value is saved in the private run directory before the change is attempted, the change (MFA `ENABLED` with TOTP and phone, the test phone number, SMS regions allow-by-default, mask `mfa,signIn.phoneNumber,smsRegionConfig`) is verified by readback, and the pre-value is restored and verified at the end and on every stop path. The receipt records the pre and post digests, a redacted reference to the baseline (field names and byte length, no values) and the restore status; an absent phone block reads back as its disabled object, which is reported as `restored-verified-normalized` with the differing field named rather than folded into the exact status.

Production time is wall-clock time. The descriptor refuses a simulated sleeper, the plan reference carries its timing mode, and the launcher refuses a rehearsal's frozen inputs. The 300, 450, 600 and 1800 second controls are real waits, checkpointed so a stopped process resumes for the remainder under the same Ledger reservation, which bounds the resume: it is admitted only while the reservation still holds the critical path that is left plus the recovery reserve. A paused run keeps the configuration applied under the held exclusive lock and every terminal path restores it; an abandon is recovery only and does not consult the reservation deadline. Each aged resource is sampled from its own acquisition instant and every aged row records the observed age beside the target, so a refusal is attributed to the measured interval rather than to the target. The run is hosted on the shared Gate through a lane facade (`mfa_gate.py`): every request is a frozen slot with run-time placeholders, and the rehearsal drives all 93 observation, 32 recovery and 6 management slots through it to `Gate.finish`. Production execution is blocked on one thing outside the lane: the shared Ledger admits only Firestore document resources and a claim of at most 1200 s, and the shared Gate caps a wall at 1200 s. The launcher names that refusal (`HostingRefused`) before reading a credential.

The local shadow was regenerated at HEAD as `spec/compatibility/broad-runs/auth-totp-enroll-local-shadow-v2.json`, bound to every lane module including the new ones; `test_mfa_shadow_binding.py` fails by module name when a bound module changes after the record was taken. The historical `o2-mfa-local-shadow.json` keeps its bytes and its `3ad5dd048` binding as history. Production-unobserved conditions reduced by this work: 0.

## Reproduction

```sh
uv run --project tools/compat-inventory --locked --python 3.12 pytest -q tools/compat-broad/auth-totp-enroll
uv run --project tools/compat-inventory --locked --python 3.12 \
  tools/compat-broad/auth-totp-enroll/mfa_local_shadow.py --output /absolute/private/o2-mfa-shadow
```

The shadow builds or reuses the local artifact, owns one instance, and reaps it; it contacts nothing but loopback and reads no ambient Google credentials.

## Local responsibility persistence

The local recorder now writes signup intent before dispatch (including anonymous
signup), immutable ACK records, and atomic private checkpoints. Unknown creation
is separate from cleanup of confirmed UIDs. See
[mfa-local-responsibility.md](mfa-local-responsibility.md) for ordering, failure
semantics, tests and the non-authorizing boundary. This changes local provenance;
no historical MFA receipt is rebound or treated as a new execution.
