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

The 2026-11-07 baseline Rules crate test run passed: 284 tests passed and four were skipped by the existing configuration. This was a baseline replay, not a failing-first test for a new implementation. Relevant passing tests included:

- `unrelated_blocks_add_no_per_request_scope_setup_to_an_early_allow`: at 0, 100 and 1,000 unrelated blocks, three literal-allow evaluations perform zero agreement walks, capture-table builds or plan builds. Three function-allow evaluations perform three agreement walks, zero capture-table builds and zero plan builds in that test's fixture.
- `static_function_plans_do_not_rebuild_per_request_or_share_captures`: alternating captured path values retain the expected allow/deny decisions without rebuilding plans.
- `lazy_scope_setup_matches_eager_setup_on_generated_corpus`: compares decisions, expression counts, maximum call depth and full traced reports against eager setup across generated captures, shadowing, recursion, method/query variations and AST mutations; concurrent evaluations are also compared.
- `lexical_evaluation_matches_preoptimization_reference_after_ast_mutations` and `parsed_scopes_are_shared_but_mutated_items_are_replanned`: preserve lexical lookup and public AST mutation behavior.
- `evaluation_snapshot_remains_on_v1_after_v2_activation` and `clear_and_restore_publish_fresh_generations`: retain old snapshots and publish fresh generation identifiers.

### Generation and capture follow-up

On 2026-11-08, three new unit tests closed the build-count and function-bearing reload gaps:

- `scope_build_observation_crosses_parser_thread_and_counts_services` checks one plan per service in a fresh parse, including a two-service source, and zero additional builds for publication of an existing parsed tree or clearing the slot. Its first execution failed with zero observed parser builds instead of one, after the same-thread control passed. Test-only propagation of the observation into the parser thread made the test pass.
- `scope_build_observers_are_scoped_and_isolated` checks nested observations, restoration after a panic and independent concurrent observers.
- `function_captures_and_scope_plans_stay_with_retained_generations` checks retained and newly published function-bearing rules, lexical shadowing, Firestore and Storage, restoration and clearing, and concurrent requests with different captured values. Decisions and complete traced reports match eager and legacy evaluation references. Repeated evaluations build no additional plans.

A fresh parse builds once per service; a fresh publication generation does not necessarily build anything. Restoring an already compiled `Arc` reuses its metadata. The tests keep those cases distinct.

The updated full suite passed 287 tests with six skipped, including two new opt-in measurement tests. All-target/all-feature clippy passed. A no-op control passed, and four hand mutants were detected: missing parser observation propagation, per-request rebuilding, discarded captures and publication of stale rules. No compile failure was counted as a killed mutant. The reload test uses seven pairwise-generated cases, including six mandatory combinations; a bounded two-request generation model explored 208 distinct states without invariant violations. The model supplements the native tests and does not prove the evaluator correct for all programs.

## Residual setup measurements under concurrent load

The follow-up at `342022267e06141060576898d3064e2e5d75999a` used the same Linux/arm64 runtime, compiler and 6GiB/no-swap, four-CPU container limits. The host had 18 logical CPUs and concurrent Rust mutation, Python mutation and nextest jobs. Heavy-slot holders and host load averages were recorded before and after each measurement process. The observed one-minute load average ranged from 10.62 to 20.40. This was deliberately a loaded-host measurement, not a quiet comparison with the previous day.

Five runs of the unchanged release benchmark produced these medians and ranges, in µs/evaluation:

| Allow condition | Unrelated blocks | Median | Range |
| --- | ---: | ---: | ---: |
| Literal | 0 | 3.65 | 3.39–3.92 |
| Literal | 100 | 4.20 | 3.94–4.57 |
| Literal | 1,000 | 12.12 | 11.14–12.84 |
| Function | 0 | 3.92 | 3.74–4.42 |
| Function | 100 | 5.40 | 5.07–5.56 |
| Function | 1,000 | 20.77 | 20.02–22.33 |

The opt-in `measure_residual_scope_resolution` test separately times complete evaluation, resolution of a fresh `FunctionScopes` wrapper, direct `agrees` traversal and access to an already resolved wrapper. Parsing and assertions stay outside timing. A bounded pilot selects iterations for approximately 200ms batches, capped at 1,048,576 iterations, followed by five samples. The cached-wrapper control reaches that cap before 200ms; its optimized subnanosecond loop floor is not a production function-lookup latency estimate.

For the function-allow fixture, the release test binary produced the following µs/operation medians and ranges:

| Unrelated blocks | Complete evaluation | First plan resolution | Direct agreement walk |
| ---: | ---: | ---: | ---: |
| 0 | 3.762 (3.452–5.068) | 0.0195 (0.0189–0.0198) | 0.0082 (0.0081–0.0082) |
| 100 | 5.387 (5.209–6.244) | 0.294 (0.259–0.318) | 0.271 (0.231–0.299) |
| 1,000 | 17.065 (16.941–18.874) | 6.264 (6.233–6.411) | 6.651 (6.429–6.888) |

These operations run in separate batches and the test binary contains observation hooks. First resolution includes an agreement walk, yet the separately timed walk sometimes takes longer: the batches cannot be subtracted or divided to obtain an isolated end-to-end contribution. Growth with the number of blocks is visible, and the results do not establish that the remaining agreement walk is negligible. A literal-allow evaluation does not perform this walk; directly invoking it on that fixture is a measurement control, not its request path.

`measure_unused_declaration_capture_setup` compares identical literal-allow requests with and without an unused function in the entered block. It checks equal full traced reports and zero versus one capture-table construction, then alternates pair order over five samples. The difference includes declaration registration and capture setup together. Results are µs/evaluation; byte length is per wildcard value:

| Entered match depth | Value bytes | No declaration: median (range) | Unused declaration: median (range) |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 1.179 (0.971–1.215) | 1.284 (1.211–1.314) |
| 1 | 256 | 1.909 (0.969–2.947) | 1.516 (1.079–2.755) |
| 4 | 1 | 17.213 (11.516–19.861) | 18.397 (7.850–30.332) |
| 4 | 256 | 18.248 (8.937–23.346) | 20.427 (11.950–22.110) |

The broad ranges and reversed ordering for the shallow 256-byte case prevent attributing a reliable capture cost or improvement percentage. No quiet retry was used to select a more favorable result.

The two measurement commands were run separately, after release compilation:

```sh
cargo test -p fireemu-core-rules --release --lib --locked --offline --no-run
cargo test -p fireemu-core-rules --release --lib --locked --offline scope::scope_plan_tests::measure_residual_scope_resolution -- --exact --ignored --nocapture
cargo test -p fireemu-core-rules --release --lib --locked --offline eval::tests::measure_unused_declaration_capture_setup -- --exact --ignored --nocapture
```

The ordinary benchmark used the earlier `cargo bench` command and five executions at the follow-up source revision. Its binary SHA-256 was `0895154ec4dff253419a070be2ee4cfeb70d5644691c463d1302c132b5448725`.

## Limits and next step

The original whole-service reconstruction optimization is already present. The measured residual agreement walk warrants further investigation while preserving public AST mutation semantics. This report does not justify stopping on a claim that setup cost is negligible, and it does not establish a speedup or an isolated contribution percentage. Capture creation remains inconclusive under the observed load. No allocation profile was measured.

The generation follow-up now covers function captures across retained snapshots, fresh parsing and reuse of existing plans. Its finite cases do not cover every possible program or publication sequence. No new production observation was performed.

The follow-up adds tests, test-only observation and opt-in measurements. It does not change production evaluator behavior or claim a performance improvement.
