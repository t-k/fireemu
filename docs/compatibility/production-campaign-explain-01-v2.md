# Query Explain campaign comparison contract v2

This contract is the offline follow-up to `production-campaign-explain-01`.
The v1 manifest, collector, receipts and comparison results remain frozen. The
v2 manifest is [prod-campaign-explain-01-v2.json](../../spec/compatibility/broad-runs/prod-campaign-explain-01-v2.json)
and uses a new comparison contract digest.

The collector still requires a complete request, response, readback and
cleanup receipt. A response is complete when it is either a valid Explain
success or a single structured API rejection whose status is a stable semantic
outcome (`INVALID_ARGUMENT`, `FAILED_PRECONDITION`, `OUT_OF_RANGE`, `NOT_FOUND`,
`ALREADY_EXISTS`, or `UNIMPLEMENTED` with its corresponding HTTP status).
Authentication failures, quota exhaustion, transient service failures, malformed
bodies and interrupted transport remain incomplete.

Complete structured rejections reach the typed production/local comparator.
For example, a production HTTP 200 Explain response paired with a local HTTP
501 `UNIMPLEMENTED` response is recorded as a semantic mismatch, provided the
rest of the envelope is complete. This change only revises the comparison
contract; it does not change runtime behavior or rewrite the frozen v1
evidence.

## Current local shadow

A fresh local shadow was completed from the pushed source `5dfa8fc03f8c4951d21a72eb7d666d6d5c551cdd`. It dispatched the six bounded Explain cases plus setup/readback through the existing shared gate, recorded 12 observation rows and 6 recovery rows, verified the owned state, and stopped its process and listeners. The redacted binding summary is [5dfa8fc0-explain-local-shadow.json](../../spec/compatibility/broad-runs/5dfa8fc0-explain-local-shadow.json). Its artifact, input, process and cleanup hashes are recorded there. This is local shadow evidence only; it does not promote the campaign to production compatibility and does not alter the frozen v1/v2 receipts.

The local command was:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/campaign_explain_shadow.py --output /absolute/private/explain-shadow
```
