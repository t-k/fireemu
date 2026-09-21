# Execution plan: compatibility program, 2026-09-21

Scope version: [`compat-scope-2026-09-21.v3`](emulator-scope.md) (production first; the official emulator is an auxiliary oracle). Status: [execution-status.md](execution-status.md). Base commit of this execution: `2dd6d9d9ddfc4f8408cae149caf92514a68e645c`.

Every task below is a finite packet: an owner lane, owned files, dependencies and acceptance conditions. A task removes a named remaining condition of a parent group in the [acceptance table](ip-fs-production-compatibility.md) or fixes a reachable mismatch; tasks that do neither are hygiene and say so. Production observations run only from frozen packets through the O7/O8 gates and the shared Ledger, under a US$10 frame per observation task (campaign id), covering that task's preparation, attempts, retries and recovery; independent tasks do not share a frame.

## Lanes

| Lane | Area | Owned paths (writes serialized by the integrator) |
| --- | --- | --- |
| A | ledger, regression, evidence hygiene | `docs/compatibility/ip-fs-production-compatibility.md`, `emulator-scope.md`, `execution-*.md`, gate reports |
| B | Auth accounts and configuration | `crates/fireemu-core-auth/src/store.rs`, `crates/fireemu-adapter-http/src/identity_toolkit.rs` (one writer at a time) |
| C | Auth credentials and claims | `crates/fireemu-core-auth/src/{jwt,claims,signing}.rs`, `tools/compat-broad/auth-credential-tokens/` |
| D | MFA and action codes | `crates/fireemu-core-auth/src/{mfa,totp}.rs`, `tools/compat-broad/auth-totp-enroll/`, `tools/compat-broad/auth-action-codes/` |
| E | tenants, federation, blocking | `crates/fireemu-core-auth/src/{federation,oidc}.rs`, hook runner, tenant routes |
| F | Firestore writes and limits | `crates/fireemu-core-firestore/src/{limits,size,field_path}.rs`, `crates/fireemu-adapter-grpc/src/serve.rs`, `tools/compat-broad/fs-write-limits/`, `tools/compat-broad/fs-request-bytes-boundary/` |
| G | queries and indexes | `crates/fireemu-core-firestore/src/{query,index}.rs`, `tools/compat-broad/fs-query-partition-cursor/` |
| H | transactions | `crates/fireemu-core-firestore/src/store.rs`, `crates/fireemu-adapter-grpc/src/local.rs` (one writer at a time), `tools/compat-broad/fs-write-txn/` |
| I | Security Rules | `crates/fireemu-core-rules/`, `crates/fireemu-adapter-grpc/src/rules.rs`, `tools/compat-broad/fs-rules-publication/` |
| J | Listen and SDK | `crates/fireemu-adapter-grpc/src/streams.rs`, `webchannel.rs`, `tools/sdk-smoke/`, `tools/compat-broad/fs-listen-resume/` |
| K | lifecycle and local safety | session, control, `fireemu-core-export`, `tools/compat-broad/fs-config-lifecycle/` |
| R | saved comparison, independent review | immutable receipts, comparators, final regression |

Shared files (`store.rs`, `identity_toolkit.rs`, `local.rs`, `service.rs`, `streams.rs`, `requirements.json`, generated inventories, top-level `tools/compat-broad/*.py`, `shared_gate.py`, `reservations.py`) have exactly one writer at a time. Quint-bound files are regenerated in the same commit; the two Rust-bound shadow records are regenerated at every checkpoint that changes `crates/`.

## Tasks

| Task | Lane | Parent | Removes | Depends on | Acceptance (finite) | State |
| --- | --- | --- | --- | --- | --- | --- |
| RUNNER-DISCOVERY-001 | A | hygiene | local regression gate failing under the session target layout | none | 8 `fireemu` tests pass; layouts unit-tested | merged `524edd4b9` |
| AUTH-CLIPPY-TIDY-001 | A | hygiene | workspace clippy `-D warnings` failure | none | clippy clean, 694/694 | merged `85f911cd3` |
| FS-LEDGER-001 | A | FS-DATA-WRITE, FS-QUERY-INDEX, FS-RULES | stale limit/cursor/comparator statements | scouts | every corrected sentence cites a commit or record | this commit |
| FS-WRITE-002 | F | FS-DATA-WRITE | duplicate-document BatchWrite wording mismatch | none | production wording on REST and gRPC, both profiles, nothing published | merged `42202eb9f` |
| FS-WRITE-006 | F | FS-DATA-WRITE | REST/gRPC item-shape divergence undetected | none | parity test fails on divergence | merged `42202eb9f` |
| FS-TXN-002 | H | FS-TRANSACTION | total-time expiry unpinned locally | none | 269 s commits, 271 s refused | merged `42202eb9f` |
| TP-AUTH-D-02 | D | AUTH-MFA | separate lifetimes unproven locally | none | each lifetime crossed alone; concurrent finalize one success | merged `1621bb179` |
| TP-AUTH-E-01 | E | AUTH-TENANT-BLOCKING | cross-tenant refusal and inheritance unproven locally | none | typed refusals, no mutation, positive controls | merged `44e02c183` |
| TP-AUTH-E-01-FIX | B/E | AUTH-TENANT-BLOCKING, AUTH-CREDENTIAL | SDK-shaped tenant refresh refused (app-visible) | E-01 | 200 with tenant claim; refusals unchanged | merged `44e02c183` |
| REQ-BYTES-O7/O8 | F | FS-DATA-WRITE | `FS-LIMIT-API-REQUEST-BYTES` unobserved | packet at `2dd6d9d9d`, independent O7 review | receipt released, 3 body sizes compared | packet built, review in progress |
| FS-LIMITS-03-REBASE / -O8 | F | FS-DATA-WRITE | malformed-item continuation, COLLECTION-ID, SUBCOLLECTION-DEPTH, DOCUMENT-NAME-BYTES, three INDEX-ENTRY limits, FIELD-PATH / aggregate FIELD-VALUE / INDEXED-FIELD-VALUE bytes unobserved | request-bytes run, `nx` exemption deployment | descriptor, launcher, HEAD shadow | in progress |
| FS-TXN-001 | H | FS-TRANSACTION | 13 expiry/retry cases unobserved | none | descriptor, launcher, temporary-Ledger proof | in progress |
| RULES-CMP-002 / COLLECT-003 / O8-004 / REVOKE-005 (phase 1) | I | FS-RULES, AUTH-FS-CROSS | comparator cannot classify; no descriptor; revoked/disabled tokens on the Rules path unobserved | none | v2 MATCH only on bound bundles, nine negatives, HEAD shadow | merged `00208350e` after two review rounds |
| RULES-CMP-006 / RULES-SEMANTIC-REPAIR-006 | I | FS-RULES | principal slots compared by presence; rows compared with untyped equality; label-only mapping accepted a label-shaped literal | none | logical-principal mapping with two witnesses (readback label and pre-redaction `principalFieldBindings`), typed bounded JSON, negatives for unbound / mis-bound / duplicate readbacks, HEAD shadow | merged `aa9e5dfe4` (owner review d7f7ce184 findings 1, 3) and `5f9b39710` + shadow `da322f8c1` (external deliverable adopted by hand; its patch predates RULES-CMP-006) |
| LISTEN-SUPERVISOR-012 / LISTEN-BROWSER-009 / LISTEN-CROSS-010 | J | FS-LISTEN-SDK, AUTH-FS-CROSS | browser WebChannel path not executed; cross-identity listener uncovered | none | scripted Chromium runner, receipt, no orphan processes | merged `d622c413a`; owner review found three harness defects (symlink escape, URL-path derivation, control token in URL): BROWSER-HARNESS-FIXES-001 in progress |
| TP-AUTH-C-03 (+C-02, C-04) | C | AUTH-CREDENTIAL | 17+2 credential cases unobserved | shared Auth-scope lane | descriptor, transport, proof | merged `dd1813f4f`; launch blocked on Ledger Auth scopes |
| TP-AUTH-D-01 | D | AUTH-MFA | age causality and 300/450/600 controls unobserved | shared Auth-scope lane | HEAD shadow, descriptor with config lock and restore | in progress; blocked on Ledger Auth scopes |
| SHARED-LEDGER-NODATA-001 | R | all O8 campaigns | a real no-data stop after reservation cannot be retired (O7 Must Fix) | none | real-launcher stop points retirable; per-task US$10 check in `reserve` | in progress |
| SHARED-CORE-002 | R | AUTH-*, FS-CONFIG-LIFECYCLE, FS-QUERY-INDEX | shared Gate and Ledger model only Firestore document campaigns | proposals from C-03, D-01, LIFE-002, QUERY-001 | Auth account/config scopes and absence proofs, 2700 s wall for resumable Auth runs, configuration-only plans with management skips, partitionQuery as a non-creating read, partial-recovery close; negative tests; explain binding regenerated | queued after SHARED-LEDGER-NODATA-001 |
| FS-QUERY-001 / FS-QUERY-002 | G | FS-QUERY-INDEX | no production collector; no finite condition list | none | typed collector, descriptor | queued |
| FS-LIFE-002 | K | FS-CONFIG-LIFECYCLE | campaign includes out-of-scope database create/delete | none | 12 in-scope cases, typed collector | queued |
| TP-AUTH-B-03 | D | AUTH-ACTION | 26 stages unobserved | shared Auth-scope lane | shadow rebind, descriptor | queued |
| PROD-DIFF-PILOT-001 | R (independent agent, owner-assigned) | FS-DATA-WRITE | no production-first differential replay runner | none | offline replay of saved production receipts (first target: Commit field-transform 500/501) through a thin adapter over existing conformance/compat-broad assets, new files only, no production traffic; delivered as a patch, independently reviewed, then integrated. No other worker implements a pilot runner, registry or adapter while it runs. | assigned |
| FS-EVID-001 | R | FS-DATA-WRITE | no saved-reference replay on the current artifact | PROD-DIFF-PILOT-001 | first46, second45, G0, limits-02, write-txn, Commit replays bound to the final artifact, run through the pilot runner once it lands | pilot native replay repeated at `da322f8c1` (binary 5524494b...): MATCH 5/5 for `fs.batch-write.saved-20260907.v1`, the earlier INDETERMINATE was the sec-fetch-mode guard fixed in `323245a3d`. The six references are not in the pilot registry (each has its own recompare tooling under tools/compat-broad); wiring them needs a registry case, a pinned recorder program and a saved historical artifact per reference: FS-EVID-002, queued |
| SCOPE-PROD-FIRST-001 | A | all | official-emulator parity treated as a co-equal goal | none | scope v3 recorded; CI required/advisory classification and case-registry labels follow as separate small changes | scope recorded this commit; CI/registry follow-up queued |
| LOCAL-ASSIST-001 / -002 | A | (token economy) | none | none | read-only `tools/local-assist` CLI against a loopback llama-server, one inference at a time, evaluated on real tasks before adoption; never a wait condition for other lanes | 001 merged `17450ea7e` (reviewed; first real runs recorded privately); 002 ports the useful behaviours of an external parallel deliverable (not applied as a patch: same file names, already covered) |

Production runs are executed by the integrator from frozen packets, in this order, one at a time: request bytes (US$0.50 ceiling), limits-03 (after the `nx` exemption is deployed and its projection digest bound), transaction expiry, Rules user token, then the Auth campaigns once the shared Auth scopes exist. Each run records the campaign, counts, reservation, the task's conservative allocation to date, recovery reserve and the task's remaining frame in the status page; the program-wide total is reported but is not a stop condition.
