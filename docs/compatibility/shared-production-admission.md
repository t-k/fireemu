# Shared two-scenario production admission

Implementation and local execution are frozen at `a35f85b464743d62344a3a58763d382b5b3838ce`. The [execution input package](../../spec/compatibility/broad-runs/a35f85b4-shared-execution-inputs.json) binds the manifest, observer, comparison contract and [new local reference](../../spec/compatibility/broad-runs/a35f85b4-shared-local-reference.json). The executable production connection and offline review are complete. No production authentication, read or data operation was performed. The later report commit is not the execution commit.

## Implemented boundary

`shared_production.py` explicitly admits the existing `partial` and `transaction-field` recipes. One coordinator executes two disjoint scenario slots with one HTTP request in flight. The original local-only gate remains local-only. Production uses the existing ADC command, tokeninfo expiry validation, quota headers, independent API-key membership lookup, Auth digest and Database settings v2 preflight. All four metadata reads run again in postflight. No credential refresh occurs inside a data callback or in an independently managed worker.

The execution function checks the owner permission, current observer, fixed clean checkout, complete bound local record and unused nonce before authentication. The permission template intentionally has no owner, period, nonce or cost acceptance. Preflight must match the expressly accepted historical candidate baseline; live values never become the baseline automatically. Initial verified credentials must cover 1200seconds. A coordinator-owned recovery acquisition, if needed, must cover 300seconds and uses the same reserved budget; at most two credential commands are possible across the entire run.

The P2operation comparison now uses canonical typed JSON at the actual gate entry. Nested `false`, 0 and 0.0 are different, as are `true` and 1. Missing/added fields and different targets are refused before callback or debit. The historical26-request observation is unchanged.

## Observation and comparison

Whole BatchWrite refusal, individual failure and unexpected success remain actual responses. Local expected field values are retained only as a local invariant. Collection, readable state, cleanup, configuration continuity and compatibility have separate fields. Unverified final state or incomplete cleanup stops later observation. Cancellation retains an uncertain in-flight marker, resources and partial receipts; it cannot silently continue another scenario.

The new comparison contract independently validates the observation recipe, typed requests, response/event digests, cleanup sequence, conditional DELETE's same-run readback version, final absence and counters. Production metadata receipts must contain the exact eight pre/postflight identities and match the preserved permission baseline. The permission digest is bound to the gate and local reference. Missing evidence is indeterminate, not a match. Existing comparison contracts and historical results are not rewritten. Normal comparison accepts a fully recorded semantic mismatch;`--check` requires a match. The comparison CLI refuses an existing output path, including either input file.

## Fixed validation

- The owned local artifact `babe0222de91fcbf35993592799196cab7fca37da129dfa8c7adbf8249660f03` completed both scenarios:26total reservations,12recovery requests, four documents confirmed absent,6.984seconds for the scenario phase. Gate/transport receipts agree; parent and listeners stopped.
- First46local regression completed all46rows, with its separately recorded artifact `486b434135f54502161d6e55b1dd5b7cebebaa9dc254bba6fe3653704b0e6763`. It is not a new production comparison. No runtime source changed; historical45/46and other corpora remain intact.
- All 272 `tools/compat-broad` tests passed in70.48seconds, with zero failures/skips. The 27new production-fixture cases cover complete and differing responses, command/auth rejection, settings drift, invalid readback, timeout, observation budget exhaustion, interruption, unrecovered resources, admission failures, bounded credential recovery, corrupted evidence and the actual comparison CLI. Fixtures are not production observations.
- The 14typed-gate controls exercise both`dispatch`and `adapter_request`. Six controls failed before the P2fix. Three isolated mutations were killed: restoring Python equality, omitting management debit and removing cleanup-version comparison. A separate worktree and marked target/build directories were admitted; no Cargo mutation build or mutation artifact was used for normal validation. The mutation worktree was removed.
- Ruff and ty passed. Independent security review found and closed credential-coverage, cancellation, callable-admission, state-eligibility and comparison-evidence defects. No Must Fix remains in the reviewed delta. The configured security specialist profile was unavailable; the independent reviewer used that security perspective rather than claiming to have loaded the missing profile.

Commands and exact artifact identities are in the input package. The existing compatibility CI already includes the new pytest files. Start time was measured at2026-09-13T14:35:06+09:00; build output reports3.81seconds for the shared artifact and1.79seconds for first46. Other phase durations were not separately instrumented and are not estimated.

## One owner decision remains

The proposal covers authorized authentication/read preflight, then one execution of each mapped recipe only if the fixed conditions hold, followed by recovery, postflight and comparison. It allows four owned documents, zero accounts, zero setting changes and no retries/reobservations. Both scenarios are ordinary administrator REST data operations; they do not establish Rules, SDK, Listen or Enterprise compatibility.

The new maximum is36 operations:24 data requests, eight metadata reads and up to two command/tokeninfo pairs. Recovery 18 is included in 36, not added again. The normal no-refresh fixture consumes34. The old 34-operation proposal remains historical: it did not include the unchanged preflight helper's project and API-key postflight reads. Global spacing is at least 250ms after completion, with 1200 seconds overall and 300 reserved for recovery; the worst reserved recovery calculation is 285.5 seconds.

The planning model charges16 document reads, six writes and four deletes, no query scans/index reads, bounded network traffic, and four documents plus index storage for a conservative month. The public Standard pricing page lists document operations, storage/index overhead and network charges; the input package records the consulted us-central1 rates and conservative ceiling calculation. The gate reservesUSD 0.0436; the proposed owner budget isUSD 1. These are conditional planning assumptions, not an invoice hard cap. No free quota is deducted. See [official pricing](https://cloud.google.com/firestore/pricing) and [index limits](https://firebase.google.com/docs/firestore/quotas).

Owner identity/reference, a window with 1200 seconds available, a fresh nonce, explicit acceptance of the proposed Database/Auth baseline and location/tariff/cost conditions, and a named 24-hour manual recovery owner remain unset. No separate technical activation or per-case approval is required once these exact inputs are authorized. Unrecovered resources retain their private journals; recovery outside the authorized frame requires applicable separate authority. Do not reuse an old approval or nonce.

Until that decision, retain this frozen version and its local reference. Independent local exploration can continue; no new production operation is authorized by this report. Revision3, GAP-AUTH-007 and  AUTH-U03 remain separate work.

Final frozen verification and package binding check:2026-09-13T15:07:07+09:00. Both owned PIDs were absent, listeners were closed, and the mutation worktree was removed. There are no unrecovered task resources.
