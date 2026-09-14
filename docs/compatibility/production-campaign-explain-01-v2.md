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
