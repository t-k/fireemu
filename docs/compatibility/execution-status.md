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

## Production observation frame

- Authorization: cumulative US$10 for every production observation of this program (owner, 2026-09-21), not per campaign or per session.
- Conservative consumed `C` at the start of this execution: US$2.09 (shared Ledger allocations 1,744,610 micro-USD across five terminal reservations, the `0cbedb4b` planning estimate 0.3051, and allowances for two unpriced Auth probes and read-only preflights). Pre-frame September observations (first46 0.30513, second45 0.084) are recorded separately; no invoice has been measured anywhere.
- Invariant `C + R + N + S + M <= 10.00` with `S = M = 1.00`, `R = 0`: `N` available 5.91 (internal cap 8.00 not binding).
- Next observation: `FS-LIMIT-API-REQUEST-BYTES`, packet frozen at `2dd6d9d9d` (265 HTTP requests including 7 management calls, 51 owned documents, Ledger claim 303 micro-USD, hard ceiling US$0.50), independent O7 review in progress; no approval minted, no reservation, no request sent.

## Parent state

`COMPAT_VERIFIED 0 / 14`. Nearest closure: FS-DATA-WRITE, waiting on the request-byte and limits-03 observations, a current-artifact saved-reference replay and the closure review. No parent is promoted by the local work above.
