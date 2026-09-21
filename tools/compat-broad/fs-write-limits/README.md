# FS-DATA-WRITE-LIMITS-02 offline payload compiler

`compiler.py` produces a deterministic, finite description of the four named document byte and nesting boundary cases. It reads the checked-in Firestore limit catalog and applies the storage-size formula used by `crates/fireemu-core-firestore/src/size.rs`: document name bytes, the fixed document charge, field-name bytes, and typed value bytes.

The exact document case is controlled to 1,048,576 logical bytes. The oversized case is exactly one logical byte larger. Each byte-boundary document uses one bytes field below 1,048,487 bytes; generation fails if metadata prevents that layout. Nested maps have depth 20 and 21, using the catalog identifier `FS-LIMIT-NESTED-MAP-ARRAY-DEPTH`. Every document includes the Gate-compatible `_sharedOwner` reference marker and the nonce is validated as 32 lowercase hexadecimal characters.

The output is an offline request plan only. It contains typed `GET` absence preflights, shared-Gate-compatible create-only `PATCH` requests with `currentDocument.exists=false` in the query and `{name, fields}` bodies, typed readbacks, unchanged-control reads after each negative case, and ownership-conditional read/delete/verify cleanup lifecycles with recovery-relative `versionFrom` references. The separate `localGatePlan` has the existing shared Gate operation shape and is tested through real Gate initialization. Expected semantic outcomes remain outside those operation objects. Its 16 observation and 12 recovery requests total 28. Every potential document-bearing GET/PATCH response, including unexpected success, has a serialized-body cap with metadata allowance; the aggregate is larger than the old 8 MiB estimate. The local allocation reserves 180 seconds for recovery and 420 seconds total. These are proposed local planning budgets, not an expansion of production permission.

The compiler has no credentials or network access. The adjacent `transport.py` and `shadow.py` implement bounded local-only execution against a newly built owned artifact. They do not authorize production execution or claim production conformance. Remaining work before production Gate admission is to bind the target and configuration readback, current artifact SHA-256, collector and comparator digests, owner permission envelope, fresh nonce reservation, tariff/recovery acceptance, transport-size validation, production observation, comparison, and marker-checked cleanup. The manifest's 90-second recovery reserve is insufficient for the shared Gate's current 13-second-per-request cleanup/readback schedule and must be re-approved with a sufficient reserve.

Run the focused checks with `uv run --project tools/compat-inventory --locked pytest tools/compat-broad/fs-write-limits`. The legacy transport still accepts only 16 KiB request bodies and 64 KiB responses, so `legacyTransportCompatible` and `productionReady` remain false. The local-only transport accepts explicit integer request/response byte caps up to 2 MiB, sends only to a numeric loopback origin, uses a fixed local Owner principal for privileged operations, and enforces a whole-request deadline with a child process. Redirects and proxies are disabled. Complete API errors remain observations; truncated, interrupted, and timed-out responses are incomplete. This plan omits environment/configuration/credential preflight requests; the production collector must separately budget and bind those before O7 approval. Historical manifests and receipts are not changed by this compiler.

## Real artifact shadow

From a clean fixed checkout, run `uv run --project tools/compat-inventory --locked python tools/compat-broad/fs-write-limits/shadow.py --output <new-private-directory>`. The existing artifact builder and supervisor own the daemon and its listeners. The child uses the shared Gate plan, exact typed document and unchanged-version checks, conditional ownership-bound cleanup, and immutable per-operation receipts. The parent verifies process/listener termination. `shadow-binding.json` binds this subdirectory in addition to the supervisor's existing source bindings. Existing output files are refused.

A complete response is not necessarily an expected result. `result.json` retains `recordingComplete`, `stateValidation`, `semanticMismatches`, `infrastructureFailures`, and `cleanupComplete` separately. A violated state invariant stops subsequent writes while permitting the current readback group and ownership-checked recovery. The wrapper deliberately refuses successful shadow admission when state validation is false; it retains the original responses for triage. These local expectation checks are not a production-reference comparator.

See [the fixed-source execution record](../../../docs/compatibility/fs-write-limits-local-shadow-20260917.md). Production collector/comparator bindings, environment preflight budgets, failure/recovery rehearsals, and O7 frozen admission remain required.

## Fixed local recovery rehearsal

Run `uv run --project tools/compat-inventory --locked python tools/compat-broad/fs-write-limits/rehearsal.py --output <new-private-directory>` from a clean fixed checkout. The fixed entrypoint stops after both controls are created and validated (observation index 7), then uses normal Gate recovery. It retains the incomplete campaign and writes a separate `rehearsal.json`; rehearsal success must never be used as a completed production/local campaign receipt. The injected-fault provenance and entrypoint source are bound with the compiler catalog. The normal shadow remains available through `shadow.py` and still requires all 16 observations.

## Production allocation and semantic kernel

`production_plan.py` creates an inert proposal for the fixed Oracle project and default database. It reserves 16 data plus six management observation calls and 12 data plus six management recovery calls: 40 maximum requests, 960 seconds total, and 360 seconds reserved for recovery. It declares the nonce-scoped write lock and shared configuration read locks. The storage/network cost reserve remains subject to owner acceptance. This is not an approved manifest, and its transport identifier is deliberately not executable by the existing ProductionGate.

The existing production Coordinator derives its phase allocation from the frozen Gate plan, retaining the Adapter's conservative secondary ceilings. Legacy shared campaign allocations are unchanged. The currently prepared Explain manifest receives a new observer binding; historical execution receipts remain unchanged.

`comparator.compare_rows` is a semantic kernel, not acquisition admission. It regenerates each input plan, checks every ordered request including its typed body, and requires a complete response journal. Complete API errors are compared; incomplete journals yield `INDETERMINATE`. Exact mapped document metadata may differ as `EXPECTED_NONDETERMINISM`; raw document values and error payloads are retained. Timestamp normalization preserves per-resource equality and ordering across readbacks, not absolute dates or elapsed durations. Results always retain `acquisitionValidated=false` and `promotionReady=false`. The production collector must still validate provenance, cleanup, permissions, and all frozen bindings before using this kernel.

At source `3883f3717`, the broad offline suite passed 752 tests with 10 skips. Focused shared production/new kernel/Explain binding checks passed 116 tests with 10 skips; Ruff and type checks passed. A saved actual local shadow receipt self-control produced 16 semantic matches; this is not a production comparison. Independent security/correctness review approved the bounded slice with limitations and no required fixes.

## Fixed-target wire layer

`remote_transport.py` supplies the low-level Firestore wire edge. Both parent and worker regenerate the fixed project/default-database compiler plan and compare the complete operation, including the conditional cleanup version. Response caps come from the corresponding compiler row. The worker receives credentials through stdin under Python isolated mode with an empty environment; redirects and proxies are disabled. The parent enforces a 12-second process deadline, and the worker uses a bounded socket timeout. The worker does not acquire credentials or approve a campaign: it must be called inside the admitted production Gate/collector lifecycle. No production execution CLI or campaign approval is added by this module.

At source `4019af0b8`, offline remote-input rejection and real-loopback shared transport checks passed 25 tests; the broader limits checks passed 87 tests (the 14 remote-input checks overlap). The shared transport covers large request/response payloads and retains complete API refusals. The normal real artifact shadow completed all 16 observations and 12 recovery stages, with 26 Gate-accounted requests, no semantic/infrastructure failures, and process/listener cleanup. Artifact SHA-256: `bfdba55daefeabf82490e457dabe511de559d3f5f154250e34bae2f3ecd6d820`. Independent security/correctness review found no required fix in this bounded layer. These checks do not exercise production TLS or production credentials.

The next integration is the admitted collector: management preflight, Gate-protected wire calls, complete-response persistence, recovery credentials, exact cleanup validation, immutable receipt binding, and comparison admission. Production-ready campaign count remains zero.

## Shared Gate collection lifecycle

At runtime source `517c346ad55bc612a5dfb467cb1b74a124a91084`, `collector.py` centralizes the already-claimed Gate lifecycle used by the local shadow. It checks the exact compiled job, persists bounded wire observations before validation, and executes ownership/version-checked recovery through Gate dispatch. Complete unexpected API outcomes remain recorded separately from expectation mismatches. `collectionComplete` requires complete acquisition and cleanup without infrastructure failure; it does not mean semantic agreement. The local shadow additionally requires state validation. Journals are create-only under `collection/`. Failed recovery admission sends no recovery requests and leaves the Gate incomplete.

The normal artifact (`d8b70df9fb78f0042fd4db8ead8ad08039a0c994804ec8a99770695333af4759`) completed 16 observations and 12 recovery stages with 26 Gate requests. The separately built interruption artifact (`9a37b4252a21c6bdb709a8b60dc7090766780cb62e346ba060115eb5d15dc912`) completed the eight-observation prefix and 12 recovery stages with 18 Gate requests; only its rehearsal is successful, not the full campaign. Both owned processes and listeners were closed. These are distinct binaries and local evidence only.

With test-only follow-up `2f1b64ea2`, the focused limits suite passed 90 tests. Independent security/correctness review reported no Must Fix or Should Fix findings for this bounded slice. Production Coordinator admission, frozen permission/environment bindings, production receipt validation, and comparison admission remain outstanding. No production requests were sent and no parent was promoted.

## Coordinator wire bridge

Source `251610b5a` adds `production_bridge.py` as an internal component for an already admitted campaign. `LimitsGate` reuses the existing dispatch and accounting implementation and exposes one wire attempt only inside its charged callback. The bridge rechecks the exact plan, collector/shared source digest, permission digest and expiry, API key binding, nonce, phase, Coordinator readiness, and credential lifetime. The send-time checks run after Gate rate waiting. Direct callback invocation and repeated sends within one charged callback are refused.

The recovery callback uses `Coordinator.recover_credentials()` outside the Gate lock. The outer runner must still acquire credentials, complete metadata preflight, freeze O7 approval and all executable/artifact/comparator bindings, consume the fresh nonce, reserve envelope budget and resource locks, and validate final metadata/receipt acquisition before comparison. `execution_plan()` only constructs an inert plan; neither it nor this bridge grants permission. There is no production execution CLI in this module. The production entrypoint must use the fixed wire implementation; injected transports in tests are offline fixtures only.

Focused bridge, collector, allocation, and remote-input tests passed 32 checks. They use the actual Gate and Coordinator bookkeeping with synthetic credential/metadata/response fixtures, not real production acquisition. Both expected API refusal and complete unexpected success finish collection/recovery; only the latter retains expectation mismatches. These paths charge 26 and 28 requests respectively. Permission changes at the post-wait callback boundary prevent transport. Ruff and type checks pass. No production-unobserved condition was removed by these tests.

Independent review found that the initial bridge bypassed the legacy Adapter's HTTP failure stops. Follow-up source `f8f5a9e6e` latches credential rejection for 401/403 and marks 429/5xx as infrastructure failures. In both cases the collector saves the complete original response before stopping observation. Rejected credentials cannot be reused or refreshed implicitly; transient service errors retain bounded cleanup eligibility. Regression tests failed before each correction; the focused suite now passes 36 tests. The initial bridge source is superseded for execution.

Independent security/correctness re-review approved `f8f5a9e6e` within internal-component scope, with no Must Fix findings. The recommended after-controls 429/503 regression is retained in the suite: the first negative PATCH fails after both controls are created, later observation writes are absent, the original error is preserved as infrastructure failure, and all owned controls are reclaimed. This replaces the weaker preflight-only transient-service fixture rather than adding duplicate coverage.


## Final acquisition bindings and historical comparison

New executions emit `fs-write-limits-production-receipt-v2`. Finalization records independently observed checkout commit, dirty state, artifact SHA-256, collector source digest and per-field capture failures. The validator compares these facts with the admitted inputs. Missing measurements or any recorded `acquisitionFailure` prevent acquisition validation, including when a later checkout or binary has been restored. Cleanup completion and shared-lock release remain independent of acquisition validity.

Saved comparison never uses today's clean checkout to reconstruct yesterday's final binding. The credential-free historical adapter recognizes only the explicitly retained production receipt and repaired local bundle by exact byte hashes and fixed audited Git commits. It executes the original read-only validators in an isolated temporary tree, with a minimal environment and network calls disabled. This preserves the normal repaired-artifact recompare path without rewriting the original receipt, approval, inputs or comparison. Historical v1 receipts do not gain retrospective final-observation fields; all newly executed acquisitions require v2 facts.

The repair was independently reviewed at `0f56b3d0ddfa614666306a14909eba978487c89f`. The focused production and recompare suite passed 69 tests without skips. The retained original production receipt remains SHA-256 `ca418bcf1eed6d906baebc7d22090161752071c7d845ab19a10bd3b6ddc429a7`, with no recorded acquisition failure. A new derived comparison against the retained repaired artifact validated acquisition and reported expected nondeterminism. These are offline validation and saved-production-reference comparison results; no new production request or parent promotion occurred.

## FS-WRITE-LIMITS-03 campaign and O8 boundary

`FS-WRITE-LIMITS-03` lives beside the limits-02 modules and leaves them untouched. Its package and its rationale are in `docs/compatibility/fs-write-limits-campaign-preparation.md`.

| File | Role |
| --- | --- |
| `compiler_03.py`, `expectations_03.py` | the compiled plan, its expectations, the per-slot reservations and the closed management contract |
| `collector_03.py`, `comparator_03.py` | Gate-owned collection and the row comparator |
| `shadow_03.py`, `shadow_03b.py` | the owned-artifact shadow on loopback |
| `limits_03_descriptor.py` | the o8-core `CampaignDescriptor`, the budget and Ledger figures, the lock scopes and the index-exemption precondition |
| `limits_03_admission.py` | frozen inputs, the O7 check set, the Ledger claim, stop-point classification and the receipt |
| `limits_03_preflight.py` | the charged management preflight and postflight, including the index-exemption readback |
| `limits_03_remote_transport.py`, `limits_03_https_worker.py` | the fixed-origin transport bound to the recompiled plan slot, and its digest-pinned worker |
| `limits_03_production.py` | one admitted acquisition and the saved-evidence verifier |
| `limits_03_o8.py` | the launcher: `--inputs --approval --manifest --permission --source --artifact --ledger --output --credential-fd/--credential-file`; exit 0 released, 1 held with possible or created data, 2 refused or no data |
| `limits_03_indexes.py` | `--write-after`, `--verify before|after`, `--verify-deployed <readback>`, `--verify-restored <readback> --record <file>`, `--precondition` for the index-exemption step; the after state is never committed |
| `package_03.py` | `freeze --shadow-run <dir>` or `freeze --keep-shadow-record`, plus `--restore-record <file>` once the restore is verified: regenerates the three published records over HEAD |

```
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest -q -p no:cacheprovider tools/compat-broad/fs-write-limits
uv run --project tools/compat-inventory --locked --python 3.12 python tools/compat-broad/fs-write-limits/shadow_03.py --output <new-private-directory>
uv run --project tools/compat-inventory --locked --python 3.12 python tools/compat-broad/fs-write-limits/package_03.py freeze --shadow-run <that-directory>
```

No test here uses a credential, a network origin, a production project or the canonical Ledger. The `gate_accounts_the_empty_batch_item` fixture in `conftest.py` applies, to the test process only, the shared-Gate accounting rule the R3 malformed-item BatchWrite needs; the shared module is not changed by this lane.
