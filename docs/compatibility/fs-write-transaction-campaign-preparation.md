# Firestore Write and transaction campaign preparation

The current package prepares the next bounded Oracle campaign for `FS-DATA-WRITE` and `FS-TRANSACTION` at feature head `27c07e041c3ee5bf21eff9beff2cfc62131c6ab3`. It is preparation and local-shadow evidence only. It does not contain a production receipt, does not authorize a Cloud request and does not promote either parent group. The earlier `FS-WRITE-TXN-PRECEDENCE-01` package remains preserved as an immutable historical binding to the earlier source and artifact.

The current machine-readable package is [`fs-write-txn-precedence-01-v8.json`](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v8.json). Its companion binding is [`fs-write-txn-precedence-01-v8-binding.json`](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v8-binding.json), and the local-only shadow plan is [`fs-write-txn-precedence-01-v8-local-shadow.json`](../../spec/compatibility/broad-runs/fs-write-txn-precedence-01-v8-local-shadow.json). The historical package and v2/v3/v4/v5/v6/v7 packages remain preserved as immutable bindings; v8 is the current-head package after the Auth settings integration. The `codeSourceHead` in the package identifies the repository revision used to build the artifact; the package/evidence commit that adds this rebind is tracked separately in Git and is intentionally not embedded in its own digest-bound JSON.

## Current, next and backlog

| Queue position | Campaign | Scope | State |
| --- | --- | --- | --- |
| CURRENT | `FS-WRITE-TXN-PRECEDENCE-01-V8` | A Write stream request contending with an active read-write transaction, followed by owned document-size and nesting controls | `BLOCKED_OWNER` and `BLOCKED_TECHNICAL` |
| NEXT | `FS-DATA-WRITE-LIMITS-02` | Representative Commit operation-count and field-transform boundaries through the existing REST adapter | Preparation only; duplicate coverage and the current artifact must be checked before freezing |
| BACKLOG | `FS-TRANSACTION-SDK-RETRY-01` | SDK `retryTransaction` and conflict recovery | Requires a fixed SDK and a separate SDK collector |
| BACKLOG | `FS-DATA-WRITE-LIMITS-03` | Index-entry and total request-size boundaries | Deferred because the request, response and cost envelope is larger |
| BACKLOG | `FS-TRANSACTION-RETENTION-01` | Read-time retention and long-running transaction expiry | Requires a separate time-budget campaign |

The current campaign keeps the stream lock case and the representative limit case in one exclusive `OWNED_DATA` envelope because both use only a fresh, run-owned namespace and neither changes configuration. The stream and limit observations remain separate cases with separate comparators and post-state assertions.

## Current campaign cases

`stream-transaction-contention` uses two owned documents. It establishes absence, creates one guard document, begins a read-write transaction, reads the guard to hold the lock, opens a Write stream and sends an update to the guard followed by a tail write. The stream response is fully consumed and classified. The guard must retain its setup value and the tail must remain absent. After rollback, a fresh stream writes the guard and a final readback verifies recovery. An uncontended stream write is a required control.

`document-limit-boundaries` uses four owned documents. It compares an exact document boundary with an immediately over-boundary request and repeats the same distinction for a nested value. The refusal is a complete observation when the response is received, but it is valid only when the refusal readback proves the target absent and the previously accepted control unchanged. The local limit catalog is bound as an input; its constants are not treated as a production observation.

Both cases require a typed preflight of the project, database, edition, API mode, location and concurrency mode. The target is Standard Native `(default)` with pessimistic concurrency. No Rules, index, database or Auth configuration operation is in scope. The resource names contain a fresh 32-hex nonce and are never shared with another campaign.

The campaign envelope is bounded to six possible owned documents, 22 observation requests, 18 recovery requests, two coordinator requests, one in-flight request, two starts per second, 300 seconds total, 120 seconds reserved for recovery and a proposed USD1 planning ceiling. Each case's `maxRequestsIncludingGate` is a standalone case envelope that includes those two coordinator requests; the campaign envelope counts the shared coordinator work once. The estimate is not a billing measurement. The owner must accept the applicable location and tariff assumptions before Gatekeeper admission.

Cleanup is conditional and fail-closed. The collector records an attempt before dispatch, reads the target, checks the ownership marker, binds the exact `updateTime`, deletes only that version and verifies typed absence. An uncertain read, marker mismatch, configuration drift or incomplete stream leaves the journal for the named recovery owner and prevents an unconditional delete. No automatic retry or reobservation is included.

## Local shadow and collector boundary

The local shadow reuses the existing shared gate and the current Rust gRPC and REST integration harnesses. The declared local controls are `write_stream_refuses_active_transaction_contention_without_mutation`, `write_stream_handshake_then_sequential_commits`, `rest_document_size_and_nesting_boundaries_refuse_without_publishing` and `rest_oversized_nested_values_report_canonical_paths_without_publishing`. The shadow commands are recorded in the JSON package and use loopback-only runtime processes.

The existing [`batch_adapter.py`](../../tools/compat-broad/batch_adapter.py) is frozen for REST document-limit cases. The checked-in Rust stream test is frozen as a local harness. There is currently no production gRPC Write collector in the repository, and the existing REST adapter cannot collect a bidirectional Write stream. The current shared comparator also does not bind stream events or transaction-token lifecycle. These are technical blockers, not reasons to weaken the adapter, add a production backdoor or treat local test output as production evidence.

The current binding freezes the source head, local artifact SHA-256 `ff9b92d745fb919bd2af9478d6b09a886335919ad64e75daf7021171ffaef368` (built with `CARGO_TARGET_DIR=target/o3-fs-write-v8 cargo build --locked --release -p fireemu`), shared gate digest, REST adapter digest, stream harness digest, limit catalog digest and current comparator digest. A production collector and a versioned stream comparator must be added or explicitly supplied before the campaign can become `READY_FOR_GATE`.

## Gate state and evidence boundary

The Gate envelope is intentionally incomplete. Owner identity, explicit permission reference, execution window, fresh nonce, accepted configuration digest, recovery owner and tariff acceptance are unset. The companion binding records `productionAuthorization: false`, `productionExecuted: false` and every blocking input. A prepared package is not an approval and cannot be passed to a production runner.

A future production receipt must be compared as ordered typed observations, including the complete stream response, terminal status, write-result cardinality, transaction binding, document state and cleanup. Results must be classified as `MATCH`, `SEMANTIC_MISMATCH`, `INDETERMINATE` or `EXPECTED_NONDETERMINISM`. A complete semantic difference must remain comparable; transport interruption, configuration drift and cleanup failure must remain indeterminate.

The parent groups remain below `COMPAT_VERIFIED` until their declared production observations, repaired mismatches, current and final artifact regression, immutable evidence binding, cleanup and independent review are complete. Existing local stream, transaction and saved-reference results remain unchanged and are not relabeled by this preparation.
