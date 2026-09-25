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

`_http_request`'s failures are a labeled, non-credential-bearing taxonomy (`connect-timeout`, `connect-failed`, `headers-timeout`, `body-truncated`, `body-oversize`, `read-timeout`, `transport-error`, `json-invalid`), each carrying received/declared byte counts, elapsed time and the phase (`connect`, `headers`, `body`) it failed in, so a stopped campaign is diagnosable instead of collapsing into one generic reason. `_private_request` derives the worker's overall socket-timeout budget from the caller's actual deadline (`_bounded_socket_timeout`, with a fixed margin below the coordinator's own kill deadline and a small floor) instead of a hardcoded `REQUEST_SECONDS`, so a stalled connection is caught and labeled by the worker itself before the coordinator has to SIGKILL it.

Inside `_http_request` that budget is one absolute monotonic deadline for the whole exchange, not a fixed timeout reused for every blocking call. The remaining time to the deadline is recomputed (minus a small `PHASE_MARGIN_SECONDS`, with a `PHASE_TIMEOUT_FLOOR_SECONDS` floor so a socket call is never handed a zero timeout) before connecting, before reading headers, and before every body read, so a slow phase narrows what is left for the next one instead of each phase getting its own fresh full-length timeout that could add past the deadline in total (delayed headers used to be able to consume the whole budget on their own, then let a fresh body-read timeout run past the coordinator's kill deadline before the worker could report anything). The body is also read in bounded pieces rather than one call for the whole response, updating `receivedBytes` after every piece, so a mid-body timeout or a truncated chunked stream (caught as `http.client.IncompleteRead`, reported as `body-truncated`) still reports the bytes already received instead of losing them inside one large, all-or-nothing read. Response-body bytes and exception messages are never included in any field; only counts and exception class names are.

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

A setup step is judged on its own terms, apart from any case result. If the
create-only commit for a role is refused, that role is never established, no
later commit naming it is sent, and recovery skips it: the only write a foreign
document ever receives is that refused create, and no delete follows. Recovery
binds to this run's creation record rather than to the marker the document
currently carries.

Every `BeginTransaction` registers whatever token came back, including one
issued against the case table's expectation, so recovery releases it. A
success-shaped reply without a usable token is an incomplete acquisition, not a
transaction the run holds.

A readback follows every case that names a document, placed before anything can
overwrite it, and its body is kept in the receipt with resource names, instants
and this run's identities replaced by fixed slots. The comparator compares those
bodies, so a commit that returns `OK` without writing and a refusal that writes
anyway are both caught even though their codes are correct.

Recovery keeps going. An exception from one document's read becomes that
document's result, the remaining documents are still attempted within the
recovery deadline, and a receipt naming the outstanding documents, the open
transactions and the failure sites is always produced. A refusal that says the
caller may not act stops further sends while keeping every document this run
created on the unrecovered list.

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

## O8 descriptor and launcher for `FS-TRANSACTION-EXPIRY-RETRY-04`

`txn_expiry_descriptor.py` declares the campaign to the shared O8 core
(`tools/compat-broad/o8-core`): a 1200-second Gate wall plus the plan's
180-second recovery window (a 1380-second owner window), 95 Ledger request
slots, five owned documents, a 16,688 micro-USD planning ceiling, one
`EXCLUSIVE` lock on
`project/fireemu-35fe6/firestore/(default)/documents/oracle/<nonce>/txn-expiry-04/*`
and `READ` locks on the indexes, the ruleset, the database configuration, the
Auth configuration and the API-key binding. The nonce is 32 lowercase hex
characters and the owner marker identity is derived from it, so a frozen plan
reference names exactly one compiled plan. Timing is wall-clock only: the
collector member refuses the rehearsal's clock advance outright, and the one
documented switch that shortens the real sleeper, `Rehearsal(sleep_scale)` on
`txn_expiry_production.rehearse`, is refused on the production wire and
produces a receipt the comparator rejects (`wait-shorter-than-requested`).

The frozen plan is projected onto the shared Gate with `$binding:` placeholders
where a request carries a transaction token or the update time an ownership read
observed. `txn_expiry_gate.py` resolves them the way the Auth-list Gate does: a
value the Gate itself journaled in a response may be installed, and a request is
normalized to its placeholder only where it carries exactly that value. The
facade also settles the creation outcome of begins, rollbacks and transactional
updates against typed answers, and admits the recovery rollbacks and
delete-carrying Commits the shared recovery phase cannot host, under the same
rules. Every recovery slot the run has nothing to send for is consumed as a
journaled zero-wire skip; a skipped absence read leaves its document unproven
and the run unreleasable.

`txn_expiry_remote_transport.py` and `txn_expiry_https_worker.py` are the fixed
production wire: one digest-pinned worker process per request, only this
campaign's routes, a 120-second maximum for the two contended commits and the
same normalizer the rehearsal transport uses. `txn_expiry_preflight.py` drives
the request-byte lane's tokeninfo and metadata attestations through this
campaign's Gate and Ledger. `txn_expiry_admission.py` freezes the inputs, runs
the shared O7 check set, compiles the Gate plan and the Ledger claim, and
classifies a stopped run: `abort_no_data` for a stop before any create,
`close_after_abandon` for a stop that created and then proved every document
absent again, owner escalation otherwise.

The launcher is `txn_expiry_o8.py`. It reads the bearer token only on a private
descriptor and only after the Ledger reservation and the Gate claim exist:

```sh
uv run --python 3.12 python tools/compat-broad/fs-write-txn/txn_expiry_o8.py \
  --inputs <pkg>/txn-expiry-frozen-inputs-v1.json \
  --approval <private>/txn-expiry-o8-approval-v1.json \
  --manifest <pkg>/txn-expiry-o8-manifest-v1.json \
  --permission <pkg>/txn-expiry-owner-execution-permission-v1.json \
  --source <frozen clean checkout> --artifact <retained fireemu> \
  --ledger ~/.local/state/fireemu-broad/production-admission-v1 \
  --output <fresh directory> --credential-fd 3  3< <private handoff>
```

Exit 0: complete and released. Exit 1: a reservation is held;
`<output>/receipt.json` carries `stopPoint` and `retirement.disposition`, one
of `aborted-no-data` (retire with `txn_expiry_admission.build_abort_record` and
`Ledger.abort_no_data` once the launcher process is gone), `closed-after-abandon`
(`build_abandon_record` and `Ledger.close_after_abandon`) or `owner-escalation`
(the owner removes any residue, collects typed absence for all five documents
and calls `Ledger.close_after_escalation`); the same classification is
`txn_expiry_admission.classify_stop(receipt)`. Exit 2: refused before any
reservation existed. The handoff on the descriptor is
`{"kind": "txn-expiry-bearer-token-v1", "permissionDigest": ..., "token": ...}`.

The credential-free integration proof (`test_txn_expiry_production.py`) drives
the real Ledger, Gate and receipt path against an offline backend: all 13 cases
with the shortened real sleeper, a stop before any create retired through
`abort_no_data`, and a stop after the first case whose four open transactions
are rolled back and whose five documents are recovered and closed through
`close_after_abandon`. No test uses a credential, a network origin, a production
project or the canonical Ledger.
