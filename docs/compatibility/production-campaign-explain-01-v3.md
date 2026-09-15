# Query Explain campaign comparison contract v3

This contract is a follow-up to the frozen Query Explain campaign evidence.
The original production receipt and comparison remain unchanged. The checked-in
prepared manifest is [prod-campaign-explain-01-v2.json](../../spec/compatibility/broad-runs/prod-campaign-explain-01-v2.json); its observer binding was refreshed after the collector source changed, while the comparison binding is v3.

The campaign still requires a complete request, response, readback and cleanup
receipt. A response is complete when it is either a valid Explain success or a
single structured API rejection whose status is a stable semantic outcome.
Authentication failures, quota exhaustion, transient service failures,
malformed bodies and interrupted transport remain incomplete.

Successful Analyze responses contain an execution duration that is measured by
the service. The v3 comparison contract validates the protobuf Duration shape
and projects only `explainMetrics.executionStats.executionDuration` to a typed
`google.protobuf.Duration` nondeterminism marker. Plans, indexes, result values,
other statistics, statuses, errors, operation identity, post-state and cleanup
responses remain exact comparisons. This projection does not change runtime
behavior or erase the raw response and its digest.

## Current local shadow

The current local shadow is recorded in
[b971b2a4-explain-local-shadow-v3.json](../../spec/compatibility/broad-runs/b971b2a4-explain-local-shadow-v3.json).
The earlier `1d4dd0af` and `2cee4f0e` shadow summaries remain preserved. This run
completed the six bounded Explain cases, setup/readback, owned cleanup and process
shutdown from commit `b971b2a4c0851b2081705a7b8f367b5dd7b898c8`. The
artifact, observer, comparison binding and lifecycle hashes are recorded in the
summary. No production request is implied by this record.

A fresh shadow from feature commit `9371199fabccfdc60f1ffc1f39ac9f151b3de2b3`
is recorded separately in
[9371199f-explain-local-shadow.json](../../spec/compatibility/broad-runs/9371199f-explain-local-shadow.json).
It completed the same six cases with twelve observation rows and six recovery rows,
including state verification, cleanup and process shutdown. Its artifact and
lifecycle hashes are distinct from earlier shadows; this record remains local-only
and does not alter any saved production receipt.

The current feature head `5fe5972c5b754454641edcebc9b965767751e105` has a further
local shadow recorded in
[5fe5972c-explain-local-shadow.json](../../spec/compatibility/broad-runs/5fe5972c-explain-local-shadow.json).
It completed the same six cases with twelve observation rows and six recovery rows;
state verification, cleanup, configuration preservation and process/listener shutdown
all completed. The artifact, observer, comparison-contract and lifecycle hashes are
bound to this run. `productionExecuted` remains false, so this record is local evidence
for the prepared campaign and is not a production compatibility result.

The current feature head `b51430aec743b4fc78dbd32396e7ba66b1be616a` was shadowed with
the same six cases and is recorded in
[b51430ae-explain-local-shadow.json](../../spec/compatibility/broad-runs/b51430ae-explain-local-shadow.json).
The run completed twelve observation rows and six recovery rows with state verification,
cleanup, configuration preservation and process/listener shutdown complete. Its artifact,
observer, comparison-contract and lifecycle hashes are bound to this run. No production
request was made and the record remains local-only.

## Saved production re-evaluation

The original production receipt and its original local shadow were validated
with the historical collector at commit
`a1daa779b546816d2022e9e0119bb41d51d1718a`. The historical comparison remains
recorded as a mismatch because four Analyze rows differed only in measured
execution duration. The current local shadow was validated independently under
the v3 contract. The saved re-evaluation is recorded in
[b971b2a4-explain-saved-recomparison-v1.json](../../spec/compatibility/broad-runs/b971b2a4-explain-saved-recomparison-v1.json).
The earlier `1d4dd0af` and `2cee4f0e` re-evaluation summaries remain preserved.

That record reports twelve matching observation rows. Four rows are classified
as expected nondeterminism under the duration projection; the remaining rows
are exact. The original production receipt, source identities, raw response
digests and old comparison are retained. This is a saved-reference comparison,
not a new production run, and it does not claim compatibility for Explain
conditions outside the six declared cases.

The re-evaluation command is offline and requires the original production
receipt, its originally bound local shadow and a current local shadow:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 \
  python tools/compat-explain-reference-v4/recompare_saved_explain.py \
  --production /absolute/private/production/result.json \
  --original-local /absolute/private/original-shadow/result.json \
  --current-local /absolute/private/current-shadow/result.json \
  --historical-commit a1daa779b546816d2022e9e0119bb41d51d1718a \
  --output /absolute/private/recomparison.json
```
