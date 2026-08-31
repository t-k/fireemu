# TLA+ verification

The models in this directory are checked with TLA+ Tools 1.8.0. The pinned JAR has SHA-256 `eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a`.

## Run every model

Set `TLA2TOOLS_JAR` if the JAR is not available at `.tools/tla2tools-1.8.0.jar`, then run:

```sh
verification/tla/run-tlc.sh
```

The script copies each same-stem `.tla` and `.cfg` pair into a temporary directory before invoking TLC.

## Mutation manifests and evidence

`mutations/<Model>.json` contains semantic, operator-local source replacements. Every `from` span must occur exactly once in the original module. The runner materializes each mutant in a fresh temporary directory and copies the original cfg unchanged.

Generate evidence for one model manually:

```sh
cargo run -p tla-verification -- mutate \
  --module verification/tla/EventDelivery.tla \
  --config verification/tla/EventDelivery.cfg \
  --manifest verification/tla/mutations/EventDelivery.json \
  --jar .tools/tla2tools-1.8.0.jar \
  --evidence verification/tla/evidence/EventDelivery.json
```

The command exits nonzero if any mutant survives, times out, or cannot be executed. Only a TLC safety counterexample (`killed_safety`) or temporal counterexample (`killed_temporal`) is a kill. A timeout or tool error is never evidence that a property detected the defect.

Evidence records SHA-256 digests of the original module, cfg, manifest, and TLA+ Tools JAR. Verify all checked-in evidence after any input changes:

```sh
cargo run -p tla-verification -- verify-evidence --jar .tools/tla2tools-1.8.0.jar
cargo run -p traceability-check
```

`traceability-check` also requires each referenced property to be defined by its module, registered by the same-stem cfg under `INVARIANT(S)` or `PROPERTY/PROPERTIES`, and connected to at least one referenced killed semantic mutation for that property. Requirements without a TLA+ reference retain the global Rust mutation-catalog check.

These commands are intentionally manual. This workflow does not add a new CI job; the existing fast traceability gate validates checked-in metadata and digest-bound evidence.

## Full-property triage

`triage/2026-08-31-full-property.json` freezes the four original models after running every exact-span mutant with each model's complete cfg, including temporal properties. The older observation reported 17 gaps but did not persist candidate identifiers or a result artifact, so the report records that individual historical mapping is unreproducible instead of inventing one. The regenerated cohort contains 22 candidates: 10 were already covered and 12 required new history or boundary properties. Every candidate is now killed.

Validate that every frozen manifest mutation has an exact triage row and matching killed evidence:

```sh
cargo run -p tla-verification -- verify-triage
```

`AwaitIdleIgnoreTextIndex.cfg` is an additional policy configuration. Regenerate its evidence with the same `AwaitIdle.json` manifest when `AwaitIdle.tla` changes; the default same-stem cfg remains the traceability contract.

## Planned logical-time model

`SessionEpoch.tla` verifies session epoch freshness and reset ordering; it is not evidence that the virtual clock is monotonic. `INV-TIME-001` therefore relies on its Rust property, Kani harness, and semantic mutation until a dedicated Scheduler/logical-time model is added.
