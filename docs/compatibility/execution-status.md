# Execution status: compatibility program

Plan: [execution-plan.md](execution-plan.md). Scope: [emulator-scope.md](emulator-scope.md). This page records the latest verified checkpoint, what was executed, what was pushed and what remains. Counts are not compatibility percentages.

## Checkpoint 1 (2026-09-21, pushed `475175e88`)

- Base of this execution: `2dd6d9d9d`. G0 baseline at that commit: `cargo nextest run --workspace --profile pr` 3062 run, 3054 passed, 8 failed, 81 skipped; workspace clippy `-D warnings` failed on six pre-existing lints in `fireemu-core-auth`; `pytest tools/compat-broad` 6048 passed, 2 failed (the known `test_local_supervisor.py` volta-shim pair), 20 skipped; compat-check, traceability-check, config-schema-check and the Quint evidence contract passed. The 8 failures shared one cause (runner discovery under the session target layout) and the clippy failure was lint-only; both were fixed in this checkpoint.
- Merged and independently reviewed: TP-AUTH-D-02 lifetime matrix (11 tests), FS-WRITE-002 duplicate-document wording, FS-WRITE-006 parity test, FS-TXN-002 transaction regressions, AUTH-CLIPPY-TIDY-001, RUNNER-DISCOVERY-001.
- Gate at `b30d0ff36`: local regression gate 3080 run, 3080 passed, 0 failed, 81 skipped (profile `pr`, clean tree); workspace clippy clean; compat-check ok; traceability ok with 3 pending artifacts; the Rust-bound shadow records (`fs-transaction-expiry-retry-04-local-shadow.json`, `fs-request-bytes-local-shadow.json`) regenerated on the same tree.
- Remote CI for `475175e88`: `ci` and `compatibility-inventory` in progress at the time of writing.

## After checkpoint 1

- Merged, reviewed, not yet pushed: TP-AUTH-E-01 tenant isolation matrix and TP-AUTH-E-01-FIX (`44e02c183`). The fix removes an application-visible mismatch: a tenant user's refresh token in the pinned Web SDK request shape (securetoken `v1/token` with an API key and no `tenantId`) was refused with `INVALID_REFRESH_TOKEN`; it now renews the tenant session, while every cross-tenant refusal is unchanged. Local evidence only; production tenant observation remains a campaign.
- Ledger corrections (FS-LEDGER-001): the four write-path limits are `implemented`, not `unsupported`; the cursor tickets are repaired or withdrawn; the Rules comparator statement names the v2 acquisition comparator.

## History rewrite (2026-09-21)

One commit of checkpoint 1 (`ec1707dbe`, runner discovery fix) carried an attribution trailer the owner does not permit. It was replaced by `a3d20ed18` (identical tree, author and parent) and every later commit was re-created with `git rebase --rebase-merges`; the resulting tree at the rewritten head is byte-identical to the pre-rewrite head `02265eda4`, all commits are signed, and the branch was force-updated with the owner's explicit instruction. Old commit ids therefore no longer exist on the branch: `b30d0ff36` is now `4e83c6d2b`, `e2d0a18e8` is `4c5c71c6f`, `475175e88` is `77a06ef68`, `44e02c183` is `d292dd161`, `0cd79d3f4` is `3273ec98f`, `02265eda4` is `d622c413a`. The two Rust-bound shadow records were regenerated on the rewritten history because their evidence tests resolve `runtime.sourceCommit` through git; the Listen shadow records cite lane commits that were not rewritten. A pre-rewrite mirror is retained privately. Gate reports recorded above for `b30d0ff36` apply to the identical tree at `4e83c6d2b`.

## Production observation frame

- Authorization (owner, 2026-09-21, corrected the same day): US$10 per production observation task. A task is identified by its stable `observationTaskId` (the campaign id, for example `FS-LIMIT-API-REQUEST-BYTES`); preparation, failed attempts, retries, post-repair re-checks and recovery of that task all count against its US$10. Independent tasks each carry their own US$10 (A at US$8 and B at US$8 are both admitted; A at US$8 followed by a retry of A at US$3 is refused). The earlier reading of one cumulative US$10 for the whole program was wrong and is withdrawn; the program-wide total is still reported below for transparency but is not a stop condition.
- Enforcement: the shared Ledger's `reserve` sums every allocation of the same task (held, released, aborted or closed) with the new claim and refuses beyond the cap (`task-budget-exceeded:<task>`), in addition to the per-envelope limits; landing through the single-writer shared lane.
- Per-task allocations to date (micro-USD, conservative ceilings): FS-DATA-WRITE-LIMITS-02 44,000; FS-WRITE-TXN-PRECEDENCE-01 1,303,500; FS-DATA-WRITE-COMMIT-TRANSFORMS-03 397,110 (three reservations, two aborted before data); broad batch `0cbedb4b` 305,127 (planning estimate); Auth probes `e4d34ccc`, `97dd49dc` unpriced (allowance 10,000 each). Program-wide total of these: about US$2.09. No invoice has been measured anywhere.
- Next observation: `FS-LIMIT-API-REQUEST-BYTES`, task allocation so far 0; its claim is 303 micro-USD with a hard ceiling of US$0.50. The packet built at `2dd6d9d9d` was blocked by its independent O7 review (a no-data stop after reservation could not be retired); the fix is in the shared lane and a new packet is built at the next bind. No approval minted, no reservation, no request sent.

## Parent state

`COMPAT_VERIFIED 0 / 14`. Nearest closure: FS-DATA-WRITE, waiting on the request-byte and limits-03 observations, a current-artifact saved-reference replay and the closure review. No parent is promoted by the local work above.
