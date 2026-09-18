# Finite local Write-stream transaction collector

`stream_collector.mjs` runs one bounded, loopback-only observation of the Standard/Native gRPC Write stream while a read-write transaction holds a document read lock. It records transport completion separately from semantic observations, including the actual contention status and readback state. A local API error is retained in the receipt; it is not converted into a manufactured expected result.

The collector creates only documents below its nonce-specific prefix with an owner marker. Cleanup reads each created document, deletes it only when the marker is still owned, and uses the observed update time as a conditional precondition before checking typed absence. It never restores or deletes a document without an ownership proof.

The existing owned Firestore fixture can invoke it with OS-assigned service ports:

```sh
target/debug/fireemu exec --config tools/sdk-smoke/fireemu.smoke.json \
  --project fireemu-test --only firestore --firestore-port 0 --http-port 0 \
  --hub-port 0 --ui-port 0 --logging-port 0 --log-verbosity silent -- \
  node tools/compat-broad/fs-write-txn/stream_collector.mjs
```

The collector consumes `FIRESTORE_EMULATOR_HOST` and `GOOGLE_CLOUD_PROJECT` from the owned child environment. It does not contact Firebase production or use ADC credentials.

## Reviewed production preparation

`stream_shadow.py` runs an owned local rehearsal using a retained, validated artifact. `stream_production.py prepare` binds that receipt, collector sources, SDK evidence, and artifact into a proposal. Without a campaign-specific permission, the proposal remains `BLOCKED_OWNER`. `execute` accepts only a frozen prepared input and a private credential file descriptor; production remains subject to O7 review and a new explicit permission. The earlier document-size/depth permission does not authorize this campaign.

The original reviewed `c5cfc7e50` preparation was integrated at `c53f92510`; shared read locks were subsequently frozen at `a4577c97f`. The retained `a4577c97f` local rehearsal completed 31 requests, typed cleanup for three resources, reservation release, and process/listener shutdown. The plan reserves at most 33 requests, three resources, zero accounts, 1100 seconds, concurrency one, and USD1.3033. The cost is a conservative planning ceiling, not an observed bill: it includes 5483 MiB of bounded encoded responses and allowances at USD0.23/GiB, rounded into a USD1.30 fixed reserve plus request charges. Installed Firestore SDK 8.7.1 source and lockfile evidence bind the encoded receive cap; the smaller decoded-message cap does not reduce that network allowance.

Terminal events settle outstanding response waits, prevent further sends, and release the client in `finally`. Oversized status/error events become bounded incomplete receipts. A successful terminal status without a required acknowledgement does not establish successful acquisition.

## Bounded credential preparation component

`credential_prep.py` adds a separate, reviewed preparation contract for an authorized-user credential supplied through a private file descriptor. It does not discover or read ADC files. The caller must reserve the complete outer allowance before any OAuth request: 35 requests, three resources, zero accounts, 1200 seconds, and USD1.3035. This includes the unchanged 33-request/1100-second observation and recovery allowance and at most 100 seconds for credential preparation. It is a proposed envelope, not an existing owner permission.

The component durably charges one refresh request followed by one tokeninfo request, validates typed token/client/scope/lifetime results, and binds the sealed preparation journal to the permission, plan, reservation and collector source. Its transport uses fixed endpoints without redirects, proxies, retries or fallback, bounded responses, and an absolute deadline. Failed or unproven cleanup is retained rather than reported as successful.

The fixed component `964e49a96`, integrated at `3388b0e2c`, passed independent review and 22 synthetic tests. The prepared CLI, final acquisition/recovery connection, and a renewed combined local rehearsal remain required before production execution. The older `a4577c97f` rehearsal does not verify this added credential path. Neither component tests nor a private credential binding establish production observation or owner approval.

## Next campaign preparation: transaction expiry, finished tokens and retry tokens

`txn_expiry_cases.py` freezes the observation cases for
`FS-TRANSACTION-EXPIRY-RETRY-04`, the conditions inside `FS-TRANSACTION` that no
recorded production observation covers: a transaction that ran out of idle time
rather than being finished by its client, the state of a token after a rollback
rather than a commit, and every refusal path of `readWrite.retryTransaction`. A
condition that a recorded production observation already established may appear
only as a control, and must name the evidence it repeats.

`txn_expiry_plan.py` compiles that table into the bounded plan, the budget, the
resource locks and the owner proposal. Without an owner permission the proposal
stays `BLOCKED_OWNER`; it binds no credential and no endpoint.

`txn_expiry_collector.py` executes the plan through an injected transport. It
creates only documents below its own nonce prefix, stops at an absolute
deadline, and always attempts the cleanup contract: roll back every transaction
still open, then per document an owned read, a delete conditional on the
observed update time, and a typed absence check. Releasing the transactions
first is what makes the deletes possible, since a conditional delete is an
out-of-band write that a live lock refuses. It never deletes what it cannot
prove it owns and never turns a transport failure into a semantic result.

Elapsed time is measured, never copied from the plan. Each wait records the
interval observed, and each elapsed-dependent case records the measured idle
time of the transaction it uses. A wall-clock wait is served in five-second
checkpointed steps; it blocks, and records progress, but does not make a killed
run resumable.

`txn_expiry_comparison.py` is the credential-free comparator. It reports
`MATCH`, `EXPECTED_NONDETERMINISM`, `SEMANTIC_MISMATCH` or `INDETERMINATE`, and
refuses a production receipt whose elapsed time was simulated.

`txn_expiry_shadow.py` runs the owned local rehearsal:

```sh
uv run --python 3.12 python tools/compat-broad/fs-write-txn/txn_expiry_shadow.py \
  --artifact target/debug/fireemu --output /tmp/txn-expiry-shadow
```

The local emulator runs a virtual clock that does not follow wall time, so the
rehearsal reaches the idle limit through the control endpoint `clock:advance`
while production would wait real seconds. Every row records which mechanism
produced its elapsed time.

The published rehearsal is exactly what `run_shadow` writes, with no hand
editing. `test_txn_expiry_evidence.py` rebuilds the record from the generator and
requires equality, and with `FIREEMU_O3_FRESH_SHADOW` set to an independently
produced `shadow.json` it requires the committed file to equal that fresh run
once per-run identities, instants and the per-build artifact digest are
scrubbed. No published record carries an absolute filesystem path.

The frozen proposal and the recorded rehearsal are
`spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-manifest.json` and
`spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-local-shadow.json`.
The reasoning, the budget and the conditions this campaign deliberately does not
prepare are in
[`docs/compatibility/fs-transaction-next-campaign-preparation.md`](../../../docs/compatibility/fs-transaction-next-campaign-preparation.md).
