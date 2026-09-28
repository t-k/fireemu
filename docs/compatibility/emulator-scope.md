# Emulator scope for the Identity Platform / Firestore compatibility program

Version: `compat-scope-2026-09-21.v3` (v3 adds the production-first ordering of oracles)

This page fixes the application-facing scope used by the 2026-09-21 execution of the compatibility program. It does not replace the [acceptance table](ip-fs-production-compatibility.md): the fourteen parent feature groups and their denominators stay as they are. It maps each parent to the finite conditions this execution works on, records what is deliberately replaced by a lightweight local mechanism, and records what is excluded and why. Scope changes are dated and attributed; nothing here rewrites an earlier owner decision.

## Standard

The standard is zero application-visible gap with production Firebase for the pinned API and SDK versions: same responses, side effects, authorization, errors and notification order for equivalent logical inputs and state transitions. Reproducing Google's managed infrastructure (regions, replication, billing, delivery networks, abuse systems) is not the goal. Start-up speed, resource use, parallel-test stability, offline use and reproducibility of the emulator are preserved.

Owner authorization in force (reconfirmed 2026-09-22): production observations on the dedicated oracle project may be executed autonomously up to US$10 per stable observation task. Preparation, failed attempts, retries, reduced cases, post-repair checks, recovery and required retention for the same task share that limit, regardless of session, nonce or packet. Independent tasks have independent limits; the program total is reporting information, not a shared cap. A smaller packet limit also applies. This corrects the earlier program-wide US$10 wording. Every campaign still passes the frozen-manifest, fresh-nonce, budget, lock, cleanup and independent O7/O8 review gates, with reservations enforced by the existing Ledger. See [execution-status.md](execution-status.md) for the running budget.

## Production first (2026-09-21)

The ordering of oracles is fixed by the owner: (1) production observation on the dedicated oracle project and applicable saved production evidence, (2) the official specification with its version and applicability stated. The official Local Emulator Suite is an auxiliary oracle for cheap candidate exploration, fixture reuse and difference triage; it is not a substitute for production and matching it is not a product goal of this program. Consequences:

- A production mismatch is never left in place because the official emulator behaves the same way, and a result that differs only from the official emulator is not a regression for the production path and does not block G1/G2.
- New work whose only purpose is to reproduce an official-emulator bug, lax authorization, unchecked limit or peculiar error is stopped; the general invariants, positive controls and real-SDK assets already built on that path are reused.
- The `strict` profile is the production-compatibility path and the subject of G1/G2. The `emulator` profile stays available as a legacy/testing profile; keeping its expectations is never a reason to refuse a production-gap fix. When a production-driven change alters a legacy expectation, the change is recorded with its evidence, scope and user impact and published as a versioned update; historical production evidence stays untouched and tests are not deleted to go green.
- Profile consolidation, default-profile changes and setting renames are separate small changes, each with its own impact check.
- Declared local replacements (local signing trust root, mail/SMS sinks, controllable clock) stay explicit and do not require byte identity with Google's infrastructure.
- The exclusions above (PITR, managed backups, billing and regional infrastructure, the full management API) stay; unimplemented in-scope behaviour is not reclassified as out of scope.

## Profiles and SDKs

- Profiles: `strict` (production shape, the G1/G2 subject) and `emulator` (official-emulator shape, legacy/testing). Their existing contract differences are kept distinct and never unified silently. A defensive local ceiling is never presented as a Google limit.
- Required SDK matrix, from the locked `tools/sdk-smoke` versions: firebase 12.18.0 (Web SDK in Node and in a real browser over WebChannel), firebase-admin 14.3.0, firebase-functions 7.3.2, @firebase/rules-unit-testing 5.0.2. Loaded versions are recorded per run. Mobile SDKs are not declared and stay out of scope; they are not substituted by Node results.

## In scope: application-facing contracts

| Area | Finite conditions worked in this execution | Parent |
| --- | --- | --- |
| Auth accounts | create/get/search/list/update/delete, disable/re-enable, email/password/anonymous/phone, link/unlink, duplicates and collisions, Admin vs client privileges, declared import/export hash formats, administrator query sorting and multi-expression filters | AUTH-ACCOUNT |
| Auth credentials | ID/refresh/custom tokens, session cookies, signature/issuer/audience/project/tenant/expiry/revocation, claim composition, `auth_time`/`iat`/`exp`/revocation-time relationships per verification path (REST, refresh, Admin `checkRevoked`, Rules) | AUTH-CREDENTIAL |
| Action codes and MFA | verification, reset, email link/change, code ownership, consumption, reuse, expiry, resend; SMS/TOTP local flows with separate pending/session/code/TOTP lifetimes | AUTH-ACTION, AUTH-MFA |
| Identity Platform | tenant isolation and inheritance, password policy, email privacy, provider configuration effects, blocking functions (targets, order, claims, refusal, timeout, rollback) | AUTH-TENANT-BLOCKING, AUTH-CONFIG-SDK, AUTH-FEDERATION |
| Firestore data | CRUD, List/BatchGet, Commit/BatchWrite/Write stream, value types, masks, preconditions, transforms, errors, atomicity, post-state after refusal, the write-path limits including the four previously mislabelled ones | FS-DATA-WRITE |
| Firestore queries | declared filters/order/cursor/offset/limit, collection group, aggregation, Standard vector, PartitionQuery, index acceptance/refusal and exemptions | FS-QUERY-INDEX |
| Consistency | transactions, readTime/snapshots, contention, retry, expiry, rollback, write-to-notification ordering | FS-TRANSACTION |
| Security Rules | real-user principals/claims/tenants, request/resource/get/exists/getAfter, query proofs, multi-write budgets, declared language features and limits, atomic ruleset updates, user-token production comparison | FS-RULES |
| Listen and SDK | gRPC and WebChannel listen, connect/disconnect/resume, event order, pending-write and cache metadata, unsubscribe, auth switching, declared SDK execution including a real browser | FS-LISTEN-SDK, AUTH-FS-CROSS |
| Limits | document, field/path/value, request, index-entry, query, Rules and transaction limits that change a result; refusal and truncation are kept distinct | FS-DATA-WRITE, FS-QUERY-INDEX, FS-RULES |
| Namespaces and local operation | project/default/named database separation, reset, local snapshot/import/export, atomic refusal of corrupt input, reliable reclamation of processes, ports and children | FS-CONFIG-LIFECYCLE |

## Lightweight local replacements (declared, not disguised)

- Email and SMS delivery: local sinks and retrieval endpoints; code ownership, target operation, expiry, reuse and input rejection are tested, delivery networks are not reproduced.
- External identity providers: JSON fixtures and a controllable local issuer; the fixture path and the signature-verifying OIDC path are separate and named. SAML remains a JSON fixture contract, not XML interoperability.
- Indexes and exemptions: configuration files plus the minimal local application path; queries must be accepted or refused exactly as the configuration implies, but Google's asynchronous build infrastructure is not reproduced.
- TTL: the existing local sweep on a controllable clock; post-deletion data and notifications are tested, Google's deletion schedule is not.
- Quotas and rate limits: not reproduced; application failure handling uses the existing explicit fault injection and local simulation.
- Query Explain: the existing support is preserved; estimates are labelled as estimates.

A replacement never returns success for an operation it did not perform. Unsupported management operations answer with an explicit unsupported response and are documented.

## Out of scope for this execution

| Excluded | Adjacent obligation kept |
| --- | --- |
| PITR, managed backups, backup schedules, clone/restore (owner decision 2026-09-18) | transaction snapshots and readTime, local snapshot/import/export, namespace isolation |
| Regions, replication, SLA, CMEK/KMS, billing and quota reproduction | configuration projections must not be false; the target profile is named |
| Full Firestore Admin API, generic LRO infrastructure, managed GCS import/export jobs | local format compatibility, refusal of corrupt data, static index/field configuration |
| Real email/SMS delivery, real reCAPTCHA, undisclosed abuse detection, external IdPs themselves | protocol boundary, local refusal injection, correctness of the named signature-verifying path |
| Full OAuth code exchange and SAML XML interoperability | fixture boundary stays explicit; no unverified path is presented as signature verification |
| Enterprise Pipeline/full-text, MongoDB compatibility, Datastore-mode extensions | existing code kept; shared regressions prevented |
| New Functions/Tasks/Pub/Sub/Storage/UI features | only the Blocking Functions, Auth-to-Rules and Firestore dependencies needed here |

Exclusion criteria are "value of reproducing it in application development and CI" versus "reproducing managed infrastructure operations". Being unimplemented is not a criterion.

## Mapping to the fourteen parents

The parents and their `COMPAT_VERIFIED` rule are unchanged. This execution treats a parent as progressed only when a named remaining condition in the acceptance table is removed by an implemented and executed change, a saved-reference comparison on the current artifact, or a new bounded production observation. Counts of documents, agents, tests, listed APIs, local shadows, approval files or self-declared matches are not success criteria.
