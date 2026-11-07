# Rules function scope baseline

The evaluator at `485597bc09899fc4f55efa0d1768abbb42dfc551` already retains compiled lexical scope plans in each parsed ruleset. It does not rebuild every function environment before matching a request. This report records the current implementation and measurements from 2026-11-07; it introduces no evaluator change and claims no before/after improvement.

## Current behavior

[`parse_ruleset`](../../crates/fireemu-core-rules/src/parse.rs) prepares one `ServiceScopes` plan per service. [`Ruleset`](../../crates/fireemu-core-rules/src/ast.rs) owns those plans through `Arc`. The plans contain structural paths and declaration offsets, rather than retained AST addresses or request bindings.

[`FunctionScopes`](../../crates/fireemu-core-rules/src/scope.rs) resolves its plan on the first declaration lookup. A request that calls no function avoids the agreement walk. A request that calls a function checks the plan against the live AST once, because callers can mutate public AST fields after parsing. An incompatible shape triggers a replacement plan for that evaluation. Names and bodies are read from the live AST.

[`walk_match`](../../crates/fireemu-core-rules/src/eval.rs) builds a capture table only for an entered block that declares functions. Captures and function-call bindings remain local to the evaluation. Capture creation is not yet deferred until the first call: entering a block with unused declarations still creates its capture table.

## Measurement

The existing [`function_scopes` benchmark](../../crates/fireemu-core-rules/benches/function_scopes.rs) appends unrelated match blocks after an allowing block; each unrelated block declares one function. It evaluates a Firestore get request using either a literal `true` condition or a function that calls an enclosing function. Parsing and the initial decision assertion occur before each timed loop. Each row averages 2,000 evaluations.

The same release binary was executed five times in separate processes, with serialized samples. The runtime was Linux/arm64 in a local virtual machine, using Rust 1.94.0, a four-CPU container limit, a 6GiB memory limit, and zero container swap allowance. These short measurements describe this fixture and environment, not general request latency.

| Allow condition | Unrelated blocks | Median µs/evaluation | Range across five samples |
| --- | ---: | ---: | ---: |
| Literal | 0 | 1.71 | 1.68–1.75 |
| Literal | 100 | 2.10 | 2.08–2.13 |
| Literal | 1,000 | 4.98 | 4.91–5.24 |
| Function | 0 | 1.83 | 1.78–1.85 |
| Function | 100 | 2.33 | 2.31–2.44 |
| Function | 1,000 | 9.04 | 9.01–9.24 |

Commands, run from the checkout root with `CARGO_BUILD_JOBS=2`, `RUSTC_WRAPPER=` and no `RUSTFLAGS` override:

```sh
cargo bench -p fireemu-core-rules --bench function_scopes --no-run --locked --offline
for sample in 1 2 3 4 5; do
  target/release/deps/function_scopes-27b4eaecaedc2862
done
cargo nextest run -p fireemu-core-rules --profile pr --locked --offline
```

The executable suffix above is the one reported by this build; use the executable path printed by Cargo for another build. Offline reproduction requires the locked dependencies and cargo-nextest to be installed first. The timed binary's SHA-256 was `3bbdee9aa8639879f81f459c0a8880c3c20cf45e730ef5baef30f84a56150180`.

## Existing regression coverage

The full Rules crate test run passed: 284 tests passed and four were skipped by the existing configuration. This was a baseline replay, not a failing-first test for a new implementation. Relevant passing tests included:

- `unrelated_blocks_add_no_per_request_scope_setup_to_an_early_allow`: at 0, 100 and 1,000 unrelated blocks, three literal-allow evaluations perform zero agreement walks, capture-table builds or plan builds. Three function-allow evaluations perform three agreement walks, zero capture-table builds and zero plan builds in that test's fixture.
- `static_function_plans_do_not_rebuild_per_request_or_share_captures`: alternating captured path values retain the expected allow/deny decisions without rebuilding plans.
- `lazy_scope_setup_matches_eager_setup_on_generated_corpus`: compares decisions, expression counts, maximum call depth and full traced reports against eager setup across generated captures, shadowing, recursion, method/query variations and AST mutations; concurrent evaluations are also compared.
- `lexical_evaluation_matches_preoptimization_reference_after_ast_mutations` and `parsed_scopes_are_shared_but_mutated_items_are_replanned`: preserve lexical lookup and public AST mutation behavior.
- `evaluation_snapshot_remains_on_v1_after_v2_activation` and `clear_and_restore_publish_fresh_generations`: retain old snapshots and publish fresh generation identifiers.

## Limits and disposition

The proposed whole-service reconstruction optimization is already present, so this change stops at measurement and documentation. The residual agreement walk and capture creation remain potential optimization targets. The function/literal timing difference includes function execution and other work; it is not an isolated measurement of the agreement walk. No allocation profile or percentage attribution was measured, and the data do not establish whether further scope optimization is worthwhile.

The setup tests demonstrate zero plan rebuilding during repeated evaluation. They do not count exactly one build across every possible generation publication path. The activation tests above use function-free fixtures, so they do not independently establish function-capture behavior during hot reload. No new production observation was performed.

No runtime code or tests changed. Mutation testing, new PICT combinations and a new TLA+ model are therefore not applicable to this documentation change. No checked-in verification evidence becomes stale.
