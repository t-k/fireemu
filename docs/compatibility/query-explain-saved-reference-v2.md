# Query Explain saved-reference comparison v2

This offline evaluator reuses the immutable Query Explain production collection and local shadow recorded by collector commit `109a9b459b94d59eec541be579e305437cdfaa30`. It does not acquire credentials, send requests, rerun production, overwrite the original result, or change the original `indeterminate` comparison.

The old typed-response predicate rejected `explain/query/empty-analyze` because production omitted `planSummary.indexesUsed` and `executionStats.resultsReturned`. The [pinned Firestore protobuf schema](https://raw.githubusercontent.com/googleapis/googleapis/efc9e8f560a5f1b9b08b62823bfa7955c656cb74/google/firestore/v1/query_profile.proto) defines these as a repeated Struct and an implicit-presence int64. Under the [ProtoJSON presence/default rules](https://protobuf.dev/programming-guides/json/#presence-and-default-values), their empty and zero defaults may be omitted. A present int64 uses a JSON string. This supports treating those two absent fields as `[]` and `"0"` within this specific response; it does not justify discarding metrics or accepting missing message objects.

The v2 normalization applies only to HTTP 200 POST `runQuery`, with integer `structuredQuery.limit=0`, `explainOptions.analyze=true`, and exactly one `readTime`/`explainMetrics` response row. Both `planSummary` and `executionStats` must be objects. Only absent fields receive defaults. Nulls, incorrect types, a missing parent object, nonempty queries, aggregation queries and plan-only requests receive no additional acceptance. The frozen typed predicate is called after this narrow projection. All execution duration, read operation, debug statistic, status, document, state and other body differences remain visible in the comparison.

The old execution function overwrote its top-level `completed` flag with the comparison verdict, leaving it false after a complete collection was classified indeterminate. V2 explicitly bridges only that conflated flag: the input anchor must match the exact original result, comparison and execution-input bytes; the original result must retain `completed=false` and `compatibility=indeterminate`; and the exact original diagnostic must be `campaign envelope: typed Explain response incomplete`. Recording, state, cleanup and unchanged configuration must be literal true, failure must be explicitly null, and every receipt, gate, ownership, credential, metadata and permission check must pass. The evaluator reports derived `collectionComplete` separately from its new compatibility verdict. It never constructs or persists a substitute production receipt marked completed.

Evidence follows three stages. Stage A commits the new evaluator, tests, this contract description and a hash-only input anchor. Stage B pins that evaluator source commit and exact source closure in `query-explain-reference-evaluator-v2.json`. An evaluation requires this committed anchor, unchanged source files and the Stage A ancestor relationship. Stage C records the separate reevaluation artifact. The report binds the old collector/observer/manifest/comparison identity independently from the new evaluator source/contract/anchor identity. It also retains the original diagnostic and raw response digests alongside the normalized comparison rows.

Prepare an isolated frozen source checkout at the repository root, keeping the current evaluator in its own checkout:

```sh
git worktree add --detach .worktree/campaign-explain-reference-109a9b45 109a9b459b94d59eec541be579e305437cdfaa30
```

Then run the new evaluator from its committed checkout, using private immutable artifact locations:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 python -I tools/compat-explain-reference/evaluate.py --collector-root /absolute/repository/.worktree/campaign-explain-reference-109a9b45 --production-dir /absolute/private/campaign-explain-production-109a9b45 --local /absolute/private/campaign-explain-shadow-109a9b45/result.json --output /absolute/private/query-explain-reevaluation-v2.json
```

The output must be new and outside every frozen input directory. Match and mismatch both return zero; indeterminate returns nonzero. The frozen validator code is loaded only from the clean old checkout, with two explicit evaluator dependencies: the scoped response predicate and the independently established completion bridge. Its original request, principal, dispatch, plan, permission, configuration, successful-creation journal, version-bound DELETE and final-404 checks remain in force. Neither the old collector source nor its observer identity is rewritten. Remove an evaluator-created reference worktree with `git worktree remove` when finished.
