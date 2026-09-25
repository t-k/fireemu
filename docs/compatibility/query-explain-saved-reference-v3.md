# Query Explain repaired saved-reference comparison v3

V3 compares the immutable production campaign collected at `109a9b459b94d59eec541be579e305437cdfaa30` with the independently collected local shadow at `aad1a41de926fae244b42ac1bd2baa57bf2bcdde`. It performs no network requests, acquires no credentials, and does not execute production or change the production permission. Original result, original comparison, execution inputs, original local artifacts and every repaired local artifact are byte-hashed in a committed input anchor. Missing, added, changed or symlinked input files fail closed.

The historical collector and repaired collector run in separate isolated Python subprocesses from clean checkouts at those exact commits. V3 explicitly compiles the v2 evaluator and every repository-local collector dependency from source bytes. Its import loader never reads or writes bytecode caches and refuses sourceless repository imports. Setting `sys.dont_write_bytecode` alone is not treated as sufficient, because Python may otherwise execute a forged cache with a valid timestamp and source size. Regression tests demonstrate ordinary cache execution, then verify that the real evaluator/worker ignores the same forged caches and still rejects invalid receipts. The unchanged v2 evaluator validates the original collection with its two narrowly scoped ProtoJSON defaults and its previously documented completion bridge. The original production `completed=false` and `indeterminate` diagnostic are preserved. V3 reproduces and binds the original v2 `mismatch` rows before comparing the repaired local. The repaired local is validated by its own unmodified collector, including source, runtime inputs, build, artifact digest, configuration, index, observer, manifest, request/principal, dispatch, post-state, ownership, cleanup, process exit and listener shutdown. Saved artifact and process files must also match their embedded receipts.

Only successful analyze response `explainMetrics.executionStats.executionDuration` receives new equivalence. It must exist exactly once in the metrics row, be a JSON string in protobuf Duration notation with at most nine fractional digits, and parse as a nonnegative duration within the protobuf range. Missing, negative, malformed or out-of-range durations are indeterminate, never a match. Valid values become `{"type":"google.protobuf.Duration","nondeterministic":true}`. Plan-only responses receive no duration projection. V2's absent-default projection remains restricted to zero-limit runQuery analyze responses, requiring both parent message objects.

V3 retains the frozen response normalizer's existing absolute-time, campaign-namespace and error-prose projections. In particular, setup and final-absence 404 prose is compared under the existing machine-code projection; this is not a new error-message equivalence. Original raw body digests preserve the prose. Every other index, execution statistic, debug statistic, read count, status, document and body field remains exact after those established projections. Observation operations must match after campaign nonce substitution. Cleanup DELETE version preconditions are independently validated against their respective successful creations by each collector before their absolute timestamps are projected with the frozen timestamp normalizer. Cleanup operations and normalized responses must match. Each collector validates administrator authentication under its own evidence basis; principal and quota project must also agree across receipts. Both post-state readback observations participate in the twelve-row exact comparison.

Evidence is committed in three stages: evaluator/tests/documentation/input hashes; an anchor binding that implementation commit and the complete v2/v3 source closure; then a generated public summary binding the full private comparison artifact. The source commit must be an ancestor of the execution commit, every source file must match that commit, and the anchor must be committed unchanged. Inputs and evaluator identity are checked again after evaluation. The original v2 files and frozen collector files are never rewritten.

Prepare the two frozen checkouts with `git worktree add --detach` at the exact commits above. Run from the committed evaluator checkout:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 python -I tools/compat-explain-reference-v3/evaluate.py --collector-root /absolute/repo/.worktree/campaign-explain-reference-109a9b45 --repaired-collector-root /absolute/repo/.worktree/campaign-explain-reference-aad1a41d --production-dir /absolute/private/campaign-explain-production-109a9b45 --original-local /absolute/private/campaign-explain-shadow-109a9b45/result.json --local /absolute/private/campaign-explain-shadow-aad1a41d/result.json --output /absolute/private/query-explain-reevaluation-v3.json
```

Output must be new and outside all frozen input/checkouts. Match and mismatch return zero; indeterminate returns two. The internal `--worker` protocol produces intermediate validation or comparison material only; only the public CLI verifies the complete source/input anchor and emits a versioned final evaluation.

The committed evaluator also provides deterministic public-summary generation and verification:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 python -I tools/compat-explain-reference-v3/evaluate.py --project-summary /absolute/private/query-explain-reevaluation-v3.json --output /absolute/new/query-explain-reference-summary-v3.json
uv run --project tools/compat-inventory --locked --python 3.12 python -I tools/compat-explain-reference-v3/evaluate.py --check-summary /absolute/private/query-explain-reevaluation-v3.json --summary spec/compatibility/broad-runs/query-explain-reference-summary-v3.json
```

Both commands require the committed evaluator source anchor. Projection creates a new file exclusively, binds the exact private comparison bytes, and retains the established summary field order and formatting. Checking requires byte-for-byte equality with the generated projection. This verifies that the summary represents the supplied comparison; collection validity comes from the full evaluator command. A regression locates the published comparison by its recorded digest, regenerates the actual published summary, and rejects changes to either artifact. The CLI is tested through an isolated committed source checkout.

The executable was copied into a temporary owned runtime directory and removed by successful collection cleanup. This offline evaluation binds the recorded build artifact digest and saved source/build/process receipts; it does not claim to rehash the removed executable. It also cannot establish new production behavior after the original collection. A result covers the six saved Explain cases, four setup observations and two post-state readbacks, not arbitrary query/index shapes or IAM-user behavior. Private-input integration tests skip explicitly when those artifacts or fixed checkouts are unavailable; pure normalization/hash tests remain runnable.

## Coverage obligations

| Obligation | Verification | Status |
| --- | --- | --- |
| Duration field presence, lexical validity, sign, range and precision | Parameterized invalid and valid boundary tests | Covered |
| Scoped defaults and input immutability | Default/duration projection test plus unchanged v2 suite | Covered with overlap |
| Metrics, debug counts, body, status, operation, principal, state and cleanup differences | Semantic counterexample tests and saved-validator mutations | Covered with overlap |
| Production, original comparison/execution/local and repaired artifact/process/ownership/manifest byte integrity | Directory hash tampering tests and anchored clean CLI | Covered with overlap |
| Repaired source, observer, manifest, artifact, process, principal, operation, state and cleanup evidence | Exact repaired collector mutation tests | Covered |
| Original indeterminate and v2 mismatch remain immutable | Reproduction of historical v2 summary and frozen collector integration | Covered |
| Forged valid bytecode caches for v2 and repository-local collector dependencies | Actual CLI/worker cache-injection regressions with normal-loader execution controls | Covered |
| Reproducible public summary and artifact integrity | Actual published-artifact projection and isolated CLI tampering tests | Covered with overlap |
| Evaluator source, source commit, anchor and contract integrity | Isolated committed-source tampering tests | Covered |
| Saved campaign result | Exact clean collector CLI with twelve output rows | Covered when private artifacts are available |

Additional combinatorial/formal/fuzzing tools are not applied: this evaluator has fixed immutable inputs and small bounded projection rules; direct boundary, tampering and independently executed historical/current validator tests cover the current ledger. Broader Firebase compatibility remains outside this artifact's scope.
