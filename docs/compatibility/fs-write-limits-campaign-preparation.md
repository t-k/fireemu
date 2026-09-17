# Firestore write limits campaign preparation

`FS-DATA-WRITE-LIMITS-02` is an independent, owned-data campaign for the `FS-DATA-WRITE` parent. It covers four minimal cases: an accepted document-byte boundary, an immediately oversized document, an accepted nested boundary, and an immediately oversized nested document. The negative cases require typed refusal, typed absence readback, and unchanged accepted controls, so a transport status alone cannot complete the campaign.

The campaign uses a fresh nonce below `oracle/{freshNonce}/limits-02/` and does not mutate Rules, indexes, databases or shared settings. Its locks are a write lock for that owned document prefix and read locks for the default database indexes and ruleset. It can run beside unrelated campaigns when the nonce and resource lock checks pass. The original v1 proposal reserved 24 requests, 180 seconds wall time, and 90 seconds recovery. Those historical numbers are insufficient for the compiled operation sequence and must not be used for admission. The current local plan declares 16 observation operations and 12 recovery stages, four owned documents, one in-flight request, 420 seconds wall time, and 180 seconds recovery. Environment/credential preflight requests require a separate production allocation. The original proposed USD 1.00 planning ceiling is not tariff acceptance or a frozen permission envelope.

The machine-readable package is [`fs-write-limits-02.json`](../../spec/compatibility/broad-runs/fs-write-limits-02.json). Its immutable companion binding is [`fs-write-limits-02-binding.json`](../../spec/compatibility/broad-runs/fs-write-limits-02-binding.json), and the local-only shadow is [`fs-write-limits-02-local-shadow.json`](../../spec/compatibility/broad-runs/fs-write-limits-02-local-shadow.json). These v1 files are retained historical preparation inputs; their old source and null artifact bindings are not the current local execution evidence. The current local execution record is [the reviewed artifact shadow](fs-write-limits-local-shadow-20260917.md). Production remains `BLOCKED_TECHNICAL`; the owner has granted general permission in the development conversation, but concrete campaign admission still requires a frozen envelope.

The implemented `tools/compat-broad/fs-write-limits/shadow.py` reuses the shared Gate, owned artifact builder/supervisor, and limit catalog. Its dedicated local transport handles explicit request/response caps up to 2 MiB and does not change legacy transport limits. The reviewed real artifact accepted both boundary controls, refused both immediately oversized requests, preserved control versions, and completed marker/version-bound recovery. The compiler catalog and collector source are bound before, during, and after execution. No command in the shadow sends a production request. Before O7 admission, the current artifact digest, production collector, versioned comparator, owner permission reference, target project and database, execution window, fresh nonce, recovery owner and tariff acceptance must be frozen. The production evidence boundary remains `unobserved`. The catalog is documentation/spec evidence; the successful run is local-artifact evidence. Neither substitutes for production comparison.

Cleanup is fail-closed. Each resource is read, its ownership marker and exact update version are bound, and only a matching conditional delete is issued. Uncertain reads, marker mismatches, binding drift or incomplete receipts preserve the recovery journal and prevent unconditional deletion. The campaign has no production receipt and does not promote the parent group.

## Next technical work

1. The bounded real-artifact stop-after-controls recovery rehearsal is complete (see the linked execution record). Its interrupted campaign remains incomplete; ambiguous production transport/crash recovery is not inferred from that rehearsal.
2. Add a limits-specific production plan and runner using the existing `shared_production.approve`, `Coordinator`, and `ProductionGate` authorization/ownership primitives. Existing hard-coded shared-campaign dispatch cannot execute this campaign unchanged.
3. Provide a bounded large-body production transport; the new local transport deliberately refuses non-loopback origins.
4. Bind a versioned limits comparator covering ordered requests, typed refusals/readbacks, unchanged controls, cleanup, and integrity failures separately from semantic mismatches.
5. Freeze a new manifest, environmental preflight allocation, resource locks, artifact/collector/comparator identities, and the concrete permission envelope through O7. Historical v1 files are not rewritten to appear newly approved.

These four limits cases overlap the limits portion of the prepared stream/transaction campaign. O3 must remove duplicate scheduling at freeze time; no new production observation is needed for conditions already covered by an eligible saved receipt. The remaining stream/transaction-precedence conditions are still separate.

## Production integration checkpoint (2026-09-17)

Source `3883f3717` adds the offline 40-request allocation (22 observation, 18 recovery including management), derives Coordinator phase limits from the frozen Gate plan, and supplies an exact-request semantic comparison kernel. The kernel deliberately does not certify acquisition, cleanup, or promotion. Broad offline checks: 752 passed, 10 skipped. Independent review found no required fix within this scope.

The local recovery preparation condition is complete as recorded above. Production transport/collector, full comparison admission, current executable artifact binding, and concrete O7 envelope admission remain incomplete. No production operation or production-unobserved condition reduction occurred. `FS-DATA-WRITE` remains `IMPLEMENTING`; production-ready queue size remains zero.

The follow-up at `4019af0b8` implements the fixed-target bounded wire worker and reuses the local transport's tested exchange mechanics. Offline rejection, large-body loopback tests, and a fresh normal real-artifact shadow pass; independent review has no required fix for the wire layer. This completes wire implementation preparation, not admitted production execution. Production Gate/collector integration, acquisition validation and O7 bindings remain required. No production observation was performed.

## Shared collector checkpoint

Source `517c346ad55bc612a5dfb467cb1b74a124a91084` supplies the shared claimed-Gate collection lifecycle; test-only follow-up `2f1b64ea2` verifies recovery admission failure and immutable output refusal. The normal and fixed-interruption real artifact runs completed their declared cleanup and process reclamation. The [collector record](../../tools/compat-broad/fs-write-limits/README.md#shared-gate-collection-lifecycle) separates acquisition completeness from expectation agreement. Independent review found no required fix in this slice.

This closes the reusable collection-lifecycle preparation item, not production admission. The outer Coordinator, permission/configuration bindings, production receipt validation, and comparison handoff still require integration. Production-unobserved conditions reduced: **0**. Next parent remains `FS-DATA-WRITE`; `COMPAT_VERIFIED` remains **0 / 14**.

## Coordinator bridge checkpoint

Source `251610b5a` connects the limits wire callback to the existing Coordinator and a limits-specific Gate subtype without adding another request budget. The charged callback is one-shot and verifies binding/credential state after waiting. Offline actual-Gate checks cover normal collection, complete unexpected outcomes, recovery outside the lock, and refusal of drift or callback reuse (32 focused checks passed).

This addresses the data-wire/Coordinator connection only. The outer O7 admission and frozen envelope/lock/nonce lifecycle, production metadata acquisition, final receipt validation, and comparison handoff remain incomplete. No executable production campaign was approved, no production request was made, and production-unobserved conditions decreased by **0**.

The initial bridge review required preservation of legacy credential and service-failure stops. Source `f8f5a9e6e` supersedes the initial bridge: complete 401/403 responses are retained but permanently fail that credential; 429/5xx are infrastructure failures, with bounded cleanup still available. Focused checks now pass 36 tests. These local safety corrections are not production comparison results.

An executable reuse audit found that the existing Gate reserves requests and cost per campaign but does not arbitrate the proposal's cross-campaign resource locks or approval-envelope reservations. The declarations alone therefore cannot admit parallel production work. Extending existing admission with an atomic shared reservation remains a technical prerequisite; this is not a request to increase campaign scope or build a new orchestration platform.

Independent re-review approved `f8f5a9e6e` within internal-component scope. No Must Fix remains. The suite also retains the requested after-controls 429/503 continuation regression. This review does not approve O7 execution or parent promotion.

## Shared reservation integration checkpoint

Source `3428b399f` implements the bounded [shared reservation library](../../tools/compat-broad/production-admission/README.md), reusing the existing private flock and atomic Gate state-save protocol. Full campaign request/account/resource/cost upper bounds are reserved atomically with ancestor-aware resource locks; allocation is not refunded. Nonce reuse, envelope multiplication under the same permission, expired dispatch, and incomplete cleanup are refused. Worker interruption retains ownership. A closing state avoids Gate/ledger lock inversion during final cleanup.

`ReservedCoordinator` and `bind_reserved_wire` connect metadata and data attempts to this lease after rate waiting, and the reservation code is source-bound. Focused filesystem/process/bridge checks passed 61 tests. These are local admission and failure tests, not production observations. O7 permission validation, the canonical shared-root selection, immutable run inputs/artifact/environment binding, and final production acquisition/comparison remain unconnected in the outer runner. No production worker is eligible yet and no parent was promoted.

Independent review of this initial reservation implementation found three required fixes: time checks preceding flock waits, declared scopes not covering actual Gate resources, and mutable Coordinator lease substitution. The 61 passing checks did not establish those properties. The checkpoint is not approved for production, and the corrections require focused regressions and a new fixed-source review.
