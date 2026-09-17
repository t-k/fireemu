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

Source `723c18e0f` closes those three findings. The default clock is read after acquiring the ledger lock; actual Firestore resources must be covered by WRITE/EXCLUSIVE scopes; metadata and data attempts reject replacement of the original ledger/ticket. New regressions produced eight failures against the original implementation. Focused checks passed 73 tests, with all 37 affected checks rerun after the final type cleanup. Independent review also ran those 37 tests and approved the bounded component with no Must Fix or Should Fix. Full broad offline verification at this source passed **823 tests, 10 skipped**; Ruff, ty and diff checks passed.

The parallel Auth test-only change `b0fbf2981` captures the old revision before its synchronization notification. The normal test passes, and removing the commit-time guard in an isolated mutation causes HTTP 200 instead of the required 409. Runtime code and formal bindings are unchanged by this follow-up.

Shared admission is now a reviewed reusable component, but the limits-specific outer runner still must connect owner/manifest approval, canonical ledger selection, frozen artifact/environment inputs, complete immutable acquisition validation and comparison handoff. Production-unobserved conditions reduced this cycle: **0**. Parent promotions: **0**. No production request or credential acquisition occurred.

## Limits-specific outer entry

The limits `production.py` now connects exact permission validation, canonical shared-ledger reservation, Coordinator preflight, bounded collection/recovery, immutable production receipts, acquisition validation, and separate credential-free comparison. A complete unexpected API outcome is eligible for semantic comparison; transport, ownership, cleanup, binding, and configuration failures remain indeterminate. Saved-production recompare deliberately admits a newly verified local artifact after repair without changing the original production permission or receipt.

The shadow now retains its exact executable as `fireemu` inside its output directory. Pass that retained file to `--artifact`; a later Cargo build can replace `target/debug/fireemu` with different bytes even when runtime source inputs match. The original shadow without a retained binary remains historical local evidence, not a newly admitted artifact. Admission failures before network access receive an exclusive sanitized journal; shared reservations remain held for explicit recovery. If that journal cannot be written, the original exception is preserved and the shared ledger remains authoritative.

The shared supervisor source change requires a new prepared Explain observer binding. `prod-campaign-explain-01-v3.json` is the new preparation manifest; v2 and all historical receipts remain unchanged. This is not new production authorization.

This implementation remains under local end-to-end verification and O7 preparation. No production campaign is approved by these code changes. Parent count remains **0 / 14**, and production-unobserved conditions reduced remain **0**.

## Typed cleanup and post-wait deadline repair

The shared Gate now records each final typed Firestore NOT_FOUND response together with its event index. The shared-ledger release validates the resource's final declared recovery GET, exact request/response digests, typed status, completion, and phase. Generic Gate completion retains its existing mixed Auth/Firestore facade contract; it does not substitute for this production release validation. An `absent` list or completion boolean alone cannot release a lease. HTML404, a mismatched error status, non-integer error codes, and incomplete transport preserve ownership. Raw observations are retained.

The limits wire carries its immutable phase deadline into the charged callback without reacquiring the Gate lock. After shared admission waiting and request preparation, it rechecks the complete transfer reservation against that phase deadline. Metadata uses the state already held by `manage` and rechecks phase and permission deadlines after shared admission. Observation cannot consume recovery-reserved time through ledger contention; recovery also remains bounded by its own deadline.

New local regressions cover real Gate/collector/ledger cleanup after owned creations and deterministic shared waiting across data/metadata and observation/recovery. Normal absence fixtures now contain genuine typed NOT_FOUND responses; malformed response cases remain explicit negative tests. The changed shared source has a new prepared Explain manifest, `prod-campaign-explain-01-v4.json`; earlier preparation manifests and historical receipts are preserved. These are execution-safety repairs, not new Firebase compatibility gaps or production evidence.


### Fixed-source verification

Source `a7e182d933a641d35e62f4bca7e84e4cf1dc0f4d` passed the full broad offline suite: **868 passed, 10 skipped**. Targeted safety checks passed 97 cases, the existing shared suite passed 163 with 10 skipped, and the actual Auth shadow plus Explain/campaign checks passed 190. Removing the previous unsafe behavior was tested against the original implementation: four delayed-phase checks and five absence-proof checks fail there. Ruff, ty and diff checks passed for the changed safety components. Independent review found no remaining Must Fix or Should Fix after correcting the generic Auth/Firestore Gate boundary.

The final limits shadow recorded 16 observations with complete cleanup and verified termination of its owned process and listeners. Its exact retained executable has SHA-256 `dd98f35b2c8284f923e68a81712878dc2907242546f17df8ff9f627ea0c69780`; the validated local bundle digest is `f2fe6423eaa4046f7214b5ecd2964d97ca960b2c7a47d45d198bfc5dc2b31311`. The outer entry accepted the bundle's source, artifact, observation and cleanup bindings. These are local observations, not a production receipt.

The historical Write/Transaction v1 preparation package remains byte-for-byte unchanged. Its source digests are now verified against its declared source `d813c811945e262296b16fce7609f4d0a8698909`, rather than against the mutable current checkout. The new, unapproved Explain v4 preparation binds the current observer; earlier versions and receipts remain unchanged.

Current closure remains **COMPAT_VERIFIED 0/14** (7 IMPLEMENTING, 7 WAITING_ORACLE). This cycle closed two production-execution safety defects and reduced production-unobserved conditions by **0**. `FS-DATA-WRITE` remains next: its required limits and Write-stream/transaction-precedence production comparisons, actual O7 permission/environment bindings, immutable receipts and final promotion evaluation remain outstanding. Production requests, credential acquisition, approved campaigns and active production workers in this cycle: **0**. No additional coverage-only observation was added to the backlog.


### Concrete O7 review candidate

`spec/compatibility/broad-runs/fs-write-limits-02-40dfc0da3-review.json` records a concrete candidate for source `40dfc0da3a03968928fa1906cdee409b703a0bb1`, including the exact retained artifact, validated local bundle, manifest, collector and comparison-contract digests. The canonical shared ledger has been initialized without admitting a campaign or reserving any budget. Public records contain only the ledger identity and fresh nonce digests; their raw values are retained privately.

This candidate assigns document-byte and nesting-boundary cases exclusively to `FS-DATA-WRITE-LIMITS-02`; stream/transaction precedence and other request/operation limits remain separate. The referenced historical baseline is only a candidate for explicit acceptance and subsequent drift checks. Its previous permission is not reused, and it is not evidence of current configuration. The candidate remains BLOCKED_OWNER and BLOCKED_TECHNICAL until actual key, baseline, permission, window and recovery bindings pass admission.

The prior source's local broad suite passed, but its CI exposed a test-clock-origin rounding difference in the no-wait metadata boundary control. The same failure was reproduced with a fixed fractional monotonic origin. Source `40dfc0da3` freezes the origin before Gate creation; all 12 boundary cases and all 23 reservation-bridge cases pass, including the reproduced origin. Runtime deadline guards are unchanged, and independent review found no Must Fix or Should Fix. A fresh actual-artifact shadow at this source recorded 16 observations, completed cleanup and closed its process/listeners. CI for this follow-up is tracked separately; earlier CI success is not substituted for it.


## Approved production observation and fixed-artifact comparison

The repository owner explicitly accepted the concrete 24-hour, single-iteration envelope. O7 admitted the frozen `40dfc0da3` source and retained artifact after independent review and successful CI. The historical review candidate above remains unchanged; the new immutable [production result](../../spec/compatibility/broad-runs/fs-write-limits-02-40dfc0da3-production-result.json) supersedes its unapproved preparation status for this one execution only.

O8 completed one production iteration against `fireemu-35fe6/(default)`: 16 complete observations, 36 of 40 requests, complete typed resource cleanup, unchanged configuration, no infrastructure failure, and released shared resource locks. No account or configuration was created or changed. Budget accounting recorded 43,600 of 44,000 micro-USD; this is not an invoice measurement. The single authorized iteration is consumed; the remaining request allocation does not authorize another iteration.

A separate credential-free comparison against retained artifact `11c7f71225dad2cba9e2c8636256d36b51c8b3ed59dee1a6fb79c639f40e98b1` classified eight rows as `SEMANTIC_MISMATCH` and eight as `EXPECTED_NONDETERMINISM`. Acquisition and cleanup validation passed. The initial comparison command used an invalid artifact path, produced an immutable `INDETERMINATE` record, and made no production request; a separate corrected output records the actual comparison. Neither output is overwritten.

The byte/depth campaign has reduced the production-unobserved finite case groups by two, but has closed zero compatibility conditions while mismatches remain. Repair must preserve the production receipt and pre-fix local observations, then use saved-reference recompare. `FS-DATA-WRITE` remains open, with stream/transaction precedence and other request/operation limits still outstanding. No parent promotion is claimed.

### Versioned diagnostic comparison correction

The original v1 comparison remains immutable. Its literal diagnostic comparison includes project/nonce resource identity, although equivalent local and production requests intentionally use different resource names. The separately versioned offline tool in `tools/compat-broad/fs-write-limits-recompare/` normalizes only the exact current request's quoted resource slot in the two declared document diagnostic grammars. Wording, punctuation, numeric values, other resources, status/code/details and non-message fields remain significant. The frozen v1 implementation and acquisition contract are unchanged.

The entrypoint first runs the existing acquisition-validating v1 comparison into a new exclusive output, then validates private byte snapshots of the local bundle and artifact before deriving v2. The binding retains validated evidence digests and identifies both v2 source files, the new v1 output, the v2 output and the optional original comparison. Independent review approved the corrected snapshot and source-binding implementation. Integrated focused checks passed 26 tests. Applying only the v2 kernel to the original pre-fix observations still yields eight semantic mismatches and eight expected nondeterminism rows, with all original evidence bytes unchanged; normalization alone does not repair runtime wording.

The Write transport preparation checkpoint `f6a5641e9` passed both standard CI and compatibility-inventory CI. No new production request was made during these fixes. Saved-reference comparison with a newly repaired runtime remains pending.
