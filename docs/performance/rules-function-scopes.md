# Rules function scope setup

The evaluator already retained compiled lexical scope plans in each parsed ruleset, but its first function lookup still checked the entire service against the live AST. The follow-up replaces that global check with checked declaration paths and lexical ancestry. Public AST mutations remain supported through live name/order lookup and a request-local replacement plan when needed. The measurements below distinguish the original baseline, residual-cost investigation and implementation comparison; loaded-host timings do not establish a fixed end-to-end speedup.

## Baseline behavior before the follow-up

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

## Checked declaration lookup

The implementation at `4b69e9bbb374dc6c0e64351e1a56ec7e0ebdc028` searches every candidate for a declaration offset, checks its live path and pointer identity, and verifies that each stored parent is the corresponding live structural prefix. An offset collision does not discard later candidates. A miss or invalid structure triggers one replacement plan per evaluation, followed by the same complete candidate search. Previously returned environments keep their own plan and the immutable AST borrow.

Function names and declaration order are read from the live AST in reverse order at each lexical scope. This preserves shadowing when an ancestor or sibling gains, loses, renames or reorders a same-name declaration while the called declaration keeps its path and offset. Match patterns and request captures continue through the existing evaluator. The live sibling scan remains linear in the number of items in the scopes searched; this change removes the separate whole-service agreement walk.

`canonical_function_calls_skip_global_scope_agreement_walks` first failed because three requests performed three agreement walks at each of 0, 100 and 1,000 unrelated blocks. It now passes with zero agreement walks, rebuilds and capture-table constructions in that fixture. A 42-row pairwise table, including 22 mandatory combinations and both capture values per row, covers 19 mutation variants across service and concrete/query requests. A 128-case property varies live ancestor names and ordering. These cases compare complete traced reports, including expression counts and maximum call depth, with legacy and eager references. Direct tests cover later declarations with duplicate offsets, foreign declaration pointers and truncated paths.

The full Rules suite passed 292 tests with six skipped; all-target/all-feature clippy passed. An unchanged mutation control passed, and five compiling semantic mutants were detected: inspecting only the first offset candidate, omitting pointer identity, omitting fallback rebuilding, reversing shadow precedence and restoring the global agreement check. A restored focused run passed all eight selected tests. A separate bounded ancestry model explored 16,128 distinct states without invariant violations; it abstracts paths and reuse, rather than proving the Rust implementation.

### Paired release comparison

The saved release baseline from `342022267e06141060576898d3064e2e5d75999a` and the candidate used the unchanged benchmark fixture and 2,000 evaluations per row. Both builds finished before measurement. Five samples of each executable ran serially, alternating which version ran first. The Linux/arm64 container limits remained four CPUs, 6GiB memory and zero swap. Concurrent host work included two Rust mutation jobs and a Python mutation harness; the one-minute host load average ranged from 21.11 to 23.88 on 18 logical CPUs. Holders and load were recorded before and after every process.

Results are µs/evaluation, with the full range of five samples:

| Condition | Unrelated blocks | Baseline median (range) | Candidate median (range) |
| --- | ---: | ---: | ---: |
| Literal | 0 | 3.94 (2.48–4.56) | 3.23 (2.13–3.37) |
| Literal | 100 | 4.42 (2.72–5.18) | 3.80 (2.58–4.07) |
| Literal | 1,000 | 11.71 (6.46–13.90) | 10.62 (8.80–13.20) |
| Function | 0 | 4.11 (2.45–4.56) | 3.63 (3.03–4.64) |
| Function | 100 | 5.12 (2.93–6.18) | 4.27 (3.66–5.07) |
| Function | 1,000 | 19.25 (12.52–24.61) | 13.69 (10.31–16.25) |

All medians decreased, but the ranges overlap and individual pairs reverse. In the fifth pair, the 1,000-block function row changed from 12.52 to 16.25µs, while the literal control also changed from 6.46 to 10.92µs. These data cannot distinguish a reliable end-to-end improvement or regression from the concurrent-load variation. No quiet retry or favorable-sample selection was performed. The candidate benchmark binary SHA-256 was `98b2754b1e98a1640ee6deea32eed253acc42dbec99ef04d60f5c0fc3bda7c18`; the baseline hash is recorded above. Reproduction uses the same benchmark build command at each revision, then runs the printed executable paths in alternating order for five samples.

### Direct lookup and remaining sibling scan

The existing opt-in scope measurement additionally times a fresh checked declaration lookup and an outer-function name lookup from the resulting environment. It uses the same function fixture and retains the old first-plan and agreement operations as test-only controls. Parsing, fixture checks and compilation remain outside timing. Five samples follow the existing bounded pilot; the short checked lookup reaches the iteration cap before 200ms.

Results are µs/operation, with all five samples' ranges:

| Unrelated blocks | Legacy first-plan control | Current checked lookup | Live outer-function lookup |
| ---: | ---: | ---: | ---: |
| 0 | 0.0244 (0.0231–0.0498) | 0.0304 (0.0293–0.0305) | 0.0081 (0.0074–0.0087) |
| 100 | 0.4529 (0.4269–0.4697) | 0.0337 (0.0301–0.0367) | 0.0634 (0.0578–0.0647) |
| 1,000 | 6.6867 (6.3451–16.1481) | 0.0294 (0.0288–0.0310) | 0.9357 (0.7647–1.5302) |

Checked lookup stayed approximately constant in this fixed-depth fixture, while the retained live sibling scan grew with block count. The legacy control includes the global agreement walk but excludes declaration search; these are distinct operations, timed in separate batches, so their ratio is not an end-to-end speedup. The direct agreement control at 1,000 blocks measured 6.3230µs (5.9319–6.5252). Host load rose from 21.57 before the process to 30.99 afterward; even complete evaluation of the zero-block fixture ranged from 6.60 to 22.32µs within this run. The direct results support removal of the global setup work and identify the remaining scan, while preserving the uncertainty of the paired request timings. This additional run was planned separately and was not a retry of the paired comparison.

The command is the same `scope::scope_plan_tests::measure_residual_scope_resolution` release command shown above. The two added output labels are `checked-get` and `live-outer-lookup`; `first-plan` is now a test-only legacy control.

## Remaining limits

The original whole-service reconstruction optimization was already present; the new change targets the residual agreement walk identified by measurement. Request-local capture creation remains unchanged, and the earlier capture timing remains inconclusive. No allocation profile was measured. The finite mutation cases, models and properties do not cover every possible rules program, extreme call depth or publication sequence. In particular, the constant checked-lookup measurements hold depth and call count fixed; they do not establish constant cost as either grows. No new production observation was performed.
