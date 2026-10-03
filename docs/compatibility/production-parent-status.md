# Production parent status

Status: `IN_PROGRESS`

This deterministic report covers the fixed 21-parent production scope. Original approvals and observations remain historical; this source integrity checkpoint issues no new production acceptance.

## Resolved production gaps

None newly accepted by this checkpoint.

## Remaining production gaps or unobserved conditions

| Parent              | Current production state | Original conditions |
| ------------------- | ------------------------ | ------------------: |
| EVENTARC            | `UNKNOWN_PUBLICATION`    |                  11 |
| FS-LISTEN-SDK       | `UNKNOWN_PUBLICATION`    |                  15 |
| FS-TRANSACTION      | `PARTIAL_RECORDED`       |                  18 |
| FUNCTIONS-EVENTS    | `UNKNOWN_PUBLICATION`    |                  22 |
| PUBSUB              | `UNKNOWN_PUBLICATION`    |                  18 |
| SCHEDULED-FUNCTIONS | `UNOBSERVED`             |                  25 |
| STORAGE-OBJECT      | `UNOBSERVED`             |                  28 |
| STORAGE-RULES       | `PARTIAL_RECORDED`       |                  24 |

The four published pending inventories retain 95 original conditions. The four unpublished frozen inventories retain 66 condition and case bindings with UNKNOWN publication. Their immutable source references are provenance, not public adoption.

## Production verification completed

The following 13 parent approvals are preserved from the immutable integration baseline; they are not reissued for a new final artifact:

- AUTH-ACCOUNT
- AUTH-ACTION
- AUTH-CONFIG-SDK
- AUTH-CREDENTIAL
- AUTH-FEDERATION
- AUTH-FS-CROSS
- AUTH-MFA
- AUTH-TENANT-BLOCKING
- FS-CONFIG-LIFECYCLE
- FS-DATA-WRITE
- FS-QUERY-INDEX
- FS-RULES
- FUNCTIONS-HTTP

Current final-product gate: `PENDING`. Saved partial equality, synthetic fixtures and source-only checks do not complete original conditions.

| Parent              | Actual retained records | Mandatory missing evidence |
| ------------------- | ----------------------: | -------------------------: |
| FS-TRANSACTION      |                       2 |                         24 |
| SCHEDULED-FUNCTIONS |                       0 |                         28 |
| STORAGE-OBJECT      |                       0 |                         31 |
| STORAGE-RULES       |                       1 |                         29 |

### FS-TRANSACTION current evidence

- `fs-transaction-recorded-comparison-preparation-v1`: `PARTIAL`; 0 retained cases or replays.
- `fs-transaction-recorded-observations-v1`: `PARTIAL`; 8 retained cases or replays.
- Bound public source input: `tools/compat-broad/fs-write-txn/fs_txn_compare_local.py`; SHA-256 `9fab208ef9e30a0332d78e061a12563355bc519611d7ed9e8ae0e1685493848f`.
- Bound public source input: `tools/compat-broad/fs-write-txn/fs_txn_table_p13b.py`; SHA-256 `c15dcba233334b5dd437aa4fad955fcc6af41089973d1a1bce083769910d5c3a`.
- Missing: FS-TRANSACTION/admin-sdk-server-retry::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/closure-review::clean_review: complete clean_review evidence missing
- Missing: FS-TRANSACTION/commit-atomic-visibility::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/failed-commit-and-rollback::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/final-artifact-regression::final_product: complete final_product evidence missing
- Missing: FS-TRANSACTION/idle-expiry::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/paging-and-cancellation::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/query-range-lock::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/read-only-snapshot::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/read-set-conflict::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/read-time-retention::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/read-time-snapshot::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/read-write-lifecycle::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/retry-token-lifecycle::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/token-validation-and-ownership::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/total-lifetime-expiry::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/web-sdk-optimistic-retry::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION/write-set-atomicity::production_behavior: complete production_behavior evidence missing
- Missing: FS-TRANSACTION::emulator-profile-contract: complete emulator_profile_contract evidence missing
- Missing: P13b current source-bound comparisons: 0/4
- Missing: P13b historical installed runtime currency: UNKNOWN
- Missing: P13b raw REST wire and representative gRPC remain unobserved
- Missing: current final product receipt missing
- Missing: current independent review receipt missing

### SCHEDULED-FUNCTIONS current evidence

- Missing: SCHEDULED-FUNCTIONS/capacity-cursor::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/catch-up-policy::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/clock-config::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/clock-forward-boundaries::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/closure-review::clean_review: complete clean_review evidence missing
- Missing: SCHEDULED-FUNCTIONS/cron-grammar::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/deadline-and-overlap::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/declarations-v1-v2::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/dst-calendar::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/final-artifact-regression::final_product: complete final_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/forced-and-natural-invocation::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/groc-grammar::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/manual-schedule::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/next-occurrence::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/overlap-policy::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/retry-config-validation::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/retry-delay-fairness::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/rewind-and-token-policy::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/state-lifecycle::local_product: complete local_product evidence missing
- Missing: SCHEDULED-FUNCTIONS/timezone-validation-defaults::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/v1-pubsub-delivery::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/v1-two-stage-retry::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/v2-backoff::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/v2-http-delivery::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS/v2-retry-limits::production_behavior: complete production_behavior evidence missing
- Missing: SCHEDULED-FUNCTIONS::emulator-profile-contract: complete emulator_profile_contract evidence missing
- Missing: current final product receipt missing
- Missing: current independent review receipt missing

### STORAGE-OBJECT current evidence

- Missing: STORAGE-OBJECT/admin-credential::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/authorization-errors::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/checksums::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/closure-review::clean_review: complete clean_review evidence missing
- Missing: STORAGE-OBJECT/cross-dialect-state::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/final-artifact-regression::final_product: complete final_product evidence missing
- Missing: STORAGE-OBJECT/firebase-delete::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-download-tokens::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-download::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-id-token::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-list::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-metadata::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-multipart-upload::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-overwrite::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-resumable-upload::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/firebase-simple-upload::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/gcs-copy-rewrite::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/gcs-delete::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/gcs-download::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/gcs-list::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/gcs-metadata::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/gcs-resumable-upload::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/gcs-simple-multipart-upload::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/generation-preconditions::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/invalid-object-name-errors::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/invalid-range-errors::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/metageneration-preconditions::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT/missing-object-errors::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-OBJECT::emulator-profile-contract: complete emulator_profile_contract evidence missing
- Missing: current final product receipt missing
- Missing: current independent review receipt missing

### STORAGE-RULES current evidence

- `storage-rules-comparison-v1`: `HISTORICAL_ROWS`; 3641 retained cases or replays.
- Missing: Rules management compile/release/no-release witnesses require current actual comparisons
- Missing: Rules rows lack current source, runner, build, native lifecycle and review binding
- Missing: STORAGE-RULES/anonymous-and-id-token::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/closure-review::clean_review: complete clean_review evidence missing
- Missing: STORAGE-RULES/create-update-delete-state::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/denial-precedence::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/download-token-boundary::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/final-artifact-regression::final_product: complete final_product evidence missing
- Missing: STORAGE-RULES/firebase-denial-shape::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/firestore-access-budget::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/firestore-exists::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/firestore-get::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/gcs-admin-boundary::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/list-v2::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/metadata-request-resource::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/method-grants::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/no-release::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/path-variables::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/recursive-wildcard::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/release-switch::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/request-time::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/storage-service-compile::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/stored-resource::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/token-claims::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/token-refusal::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES/upload-request-resource::production_behavior: complete production_behavior evidence missing
- Missing: STORAGE-RULES::emulator-profile-contract: complete emulator_profile_contract evidence missing
- Missing: current final product receipt missing
- Missing: current independent review receipt missing

## Official-only remaining work

| Independent official comparison                               | Current state | Preserved original status   |
| ------------------------------------------------------------- | ------------- | --------------------------- |
| FS-TRANSACTION::official-profile-comparison                   | `OPEN`        | `PENDING_LOCAL_OBSERVATION` |
| STORAGE-OBJECT/final-artifact-regression::official_comparison | `OPEN`        | `PENDING_CORPUS`            |
| STORAGE-RULES/final-artifact-regression::official_comparison  | `OPEN`        | `VERIFIED`                  |

An official comparison may remain OPEN independently of production closure. Mixed production obligations, local product checks, final artifact and independent review requirements, and the emulator profile contract remain mandatory. Shared original text is retained in full rather than rewritten.

## Integration conditions

- Canonical projection record pins: `PENDING_ROOT_GENERATION`; the full `closure_records.py --check` gate remains required.
- Existing Node consumer migration: `COMPLETE`.
- Evidence evaluation: `FILE_BACKED_TYPED_RECORDS`; partial and historical facts are not new production acceptance.
- Same final product and independent review: `PENDING`.
- `--check` validates honest integrity; `--require-all` currently refuses incomplete production obligations.

Original closure inventories, frozen history and the historical 13 approvals are preserved. All four Node consumers and this CLI use the actual record validator. The coordinator must regenerate canonical pins and repeat checks on the resulting tree before accepting new current evidence.
