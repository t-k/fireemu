# Current Query Explain saved-reference replay v5

The credential-free replay matches all twelve recorded observations: six Explain cases, four setup observations, and two post-state readbacks. Cleanup is independently validated. Production was not executed again. This finite result does not establish general Firestore query compatibility.

The current local source is `cce4a4f9b7369938c89bd32a5106e8d3cab59f83`. Its ordinary clean-checkout build produced artifact SHA-256 `26a0e9a2623073616dd0ce6e8554946f697ff5e919b34c98ef94e6eb0f38c8c6`. The artifact was retained and rehashed separately from the immutable local observation directory. The source matches the retained Auth replay source; this is an independent Explain build and observation, not reuse of that Auth receipt or artifact identity.

`tools/compat-explain-reference-v5/evaluate.py` is the sole entrypoint for this contract. It retains the unchanged v3 historical worker, original v2 completion bridge, production permission/acquisition validation, original directory hashes, and v3 comparison normalization. The exact current collector independently validates the current local envelope, runtime/source inputs, artifact, configuration, historical index, observer, operation/state/cleanup evidence, and stopped process. Companion `artifact.json` and `process.json` must equal the validated envelope. The current directory and validator result are separately anchored. Missing or changed evidence yields an indeterminate result.

The existing v4 `recompare_saved_explain.py` remains unchanged. Its receipt validation and current normalization differ from this immutable v3-derived contract; it does not produce v5 evidence. Historical v1–v4 results and the original v2 mismatch remain preserved. Private shadow filenames containing `v4` are immutable acquisition names, not the comparison contract version.

The public result is `spec/compatibility/broad-runs/query-explain-current-saved-reference-summary-v5.json`. It binds the complete private comparison by SHA-256 while exposing only identities, hashes, completion flags, normalization projections, and row verdicts. Inputs and evaluator source are separately sealed in `query-explain-reference-inputs-v5.json` and `query-explain-reference-evaluator-v5.json`.

Run the evaluator from its committed source with exact clean historical and current collector checkouts:

```sh
uv run --offline --project tools/compat-inventory --locked python -I tools/compat-explain-reference-v5/evaluate.py \
  --production-dir "$PRODUCTION_DIRECTORY" \
  --original-local-dir "$ORIGINAL_LOCAL_DIRECTORY" \
  --current-local-dir "$CURRENT_LOCAL_DIRECTORY" \
  --collector-root "$HISTORICAL_COLLECTOR_CHECKOUT" \
  --current-collector-root "$CURRENT_COLLECTOR_CHECKOUT" \
  --output "$NEW_COMPARISON_FILE"
```

The output must be a new file outside every frozen input and is exclusively created with mode `0600`, independent of the process umask. No production credentials are required. The existing local acquisition supervisor binds all services to OS-assigned port zero and verifies process termination and listener closure.

Validation: ten v5 tests passed against the actual private inputs, including byte tampering of each operand and independent artifact/process/cleanup mutations. The unchanged v2/v3 suites passed 115 tests. Private-input integration tests require `EXPLAIN_V5_PRIVATE_ROOT`; without it, seven integration cases skip explicitly. No Rust runtime behavior changed.
