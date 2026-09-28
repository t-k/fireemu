# FS-LIMIT-API-REQUEST-BYTES bounded compiler

`request_bytes_compiler.py` is an offline compiler for a finite strict-profile REST-only boundary plan. It emits three canonical Firestore REST `Commit` bodies whose compact UTF-8 JSON lengths are exactly 11,534,335, 11,534,336, and 11,534,337 bytes: immediately below, exactly at, and one byte above the 11 MiB strict REST `Commit` boundary. Each body contains a disjoint 16-payload plus one-control document set; the three sets use equal-length scope labels and total 51 distinct resources. Padding is distributed across each set so every document remains below the 900 KiB preparation safety margin. Every write carries `currentDocument: {"exists": false}`, preventing an intervening document from being overwritten.

`validate_request_bytes_plan` independently checks the compiled artifact's endpoint, owned-resource scope, write identities, payload relationships, canonical byte lengths, and finite operation counts. It does not rebuild a replacement plan to make those checks pass.

The compiler also emits bounded preflight, commit, readback, and cleanup operations. The explicit `executionSchedule` interleaves each probe with its complete cleanup before the next probe may start. It is bounded at 258 data calls with at most 17 live documents; production adds seven separately charged management calls for 265 total calls, while the local shadow remains data-only. Failure to establish typed absence stops progression. The separate observation/recovery arrays are indexed operation tables, not an instruction to execute all observations before cleanup. Resources are scoped to the supplied nonce. Cleanup is described as ownership and version bound; this module does not execute it or provide a production authority. Expected field snapshots are SHA-256 references to sorted-key compact UTF-8 logical field maps from the exact probe payload (not raw response map order), avoiding repeated multi-megabyte field copies in every readback expectation. The plan serializes below 70 MiB; a later collector must implement the declared ownership and phase contract before this preparation can run.

The measured quantity is raw REST HTTP body bytes, including compact JSON syntax and UTF-8 encoding; URL and header bytes are outside that quantity. Saved production comparison evidence records acceptance at 11,534,336 bytes and typed refusal at 11,534,337 bytes for its concrete REST recipes. It does not establish decoded request-byte behavior, preservation of an earlier accepted document after refusal, or other transport behavior. This lane is strict REST `Commit` only; the 10 MiB `API_REQUEST_BYTES` bound remains in force on other surfaces. gRPC protobuf message encoding requires a separate compiler and receipt. The plan makes no claims about document, nested-depth, transform, or Commit operation-count limits.

The catalog context is the Firestore quotas page ([quotas](https://firebase.google.com/docs/firestore/quotas)) and the REST Commit reference ([Commit](https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/commit)). Those sources describe the limits and Commit shape; they do not establish that raw REST body bytes are the production enforcement metric.

Run the independent tests offline with:

```text
uv run --offline --project tools/compat-inventory --locked pytest -q tools/compat-broad/fs-request-bytes-boundary/test_request_bytes_compiler.py
```

No credentials, network request, emulator, or production runner is used.

`request_bytes_remote_transport.py` prepares exact frozen-plan REST slots and provides a fixed-origin HTTPS exchange with a 2 MiB response cap. The total deadline is 60 seconds for a boundary Commit and 2.5 seconds for a small GET or DELETE; an earlier slot or phase deadline takes precedence. Its public `request()` needs a bearer token, but the module does not acquire credentials, hold shared reservations, or authorize production execution. The O8 runner binds the unchanged 258-slot data schedule plus seven closed management slots, permission, budget, resource locks, and cleanup contract after O7 approval. Management transport is bearer-only and closed to tokeninfo, project, database and Auth routes. Transport tests use an injected exchange and send no production requests.

`management_transport`'s `oauth-tokeninfo` branch calls `credential_prep._private_request`, whose worker now returns a labeled failure kind (`connect-timeout`, `connect-failed`, `headers-timeout`, `body-truncated`, `body-oversize`, `read-timeout`, `transport-error`, `json-invalid`) plus non-credential-bearing diagnostics (received/declared byte counts, elapsed time, the phase it failed in, the effective socket-timeout budget) instead of only ever collapsing into "response-limit"/"transport-or-json". The Gate's management receipt schema in `shared_gate.py` admits exactly `{status, complete, workerReaped, bodyKind, body}` with `body` required to be `null` when `complete` is `False`, so these diagnostics cannot travel inside the charged receipt without a Gate schema change; until that lands, an incomplete `oauth-tokeninfo` result (including `phase`) is logged to stderr instead. The worker's own HTTP-layer timeout is now one absolute deadline for the whole call (`credential_prep._bounded_socket_timeout` derives the overall budget from the call's actual deadline; inside the worker, `_http_request` recomputes the time remaining to that deadline before connecting, before reading headers and before every body read, rather than handing each phase a fresh full-length timeout), so a stalled connection -- including one where headers arrive late and only the body then stalls -- is diagnosed with a labeled timeout receipt before the coordinator's own kill deadline fires, and a mid-body timeout or truncated chunked stream still reports the bytes already received.

## Local collector and transport

`request_bytes_local_transport.py` is a campaign-specific loopback adapter. It
accepts only numeric loopback origins, the compiled Firestore REST operation
shape, request caps through 11,534,337 bytes, and the fixed 2 MiB response cap.
It reuses the existing bounded exchange implementation without widening the
shared transport used by other campaigns. The transport records the canonical
request byte count and digest passed to HTTP; this remains a local observation
hypothesis and is not a wire-level metric.

`request_bytes_collector.py` validates the independent compiler plan before dispatch and follows `executionSchedule`. Every preflight must return a typed `NOT_FOUND` before its Commit can be sent. Cleanup DELETE requires both a successful positional Commit response from this run and a matching ownership read with the same update time; uncertain Commit responses leave the run incomplete and do not authorize a DELETE. Each probe must establish typed absence before the next probe starts.

The collector writes create-only bounded per-operation rows and exact raw HTTP response bodies as separate sidecars. `result.json` is a compact summary with row counts, failure reasons, and the typed resource-absence conclusion; individual receipts are in `row-*.json`. Response byte counts and hashes derive from the captured body bytes, not reconstructed JSON. This remains a local observation hypothesis, with no production credentials or production execution. The owning runner must still account for supervisor process cleanup.

## Campaign artifact and local shadow

`request_bytes_campaign.py` composes the compiler plan into the bounded campaign
artifact: the three boundary cases, the typed refusal expectation, the
post-state readback obligation, version-bound cleanup with absence proofs, the
owner preconditions, the request accounting, the cost estimate and a budget with
an explicit recovery window. It performs no I/O and holds no credentials.
`validate_request_bytes_campaign` checks a supplied artifact independently and
never repairs it. The published artifact is `spec/compatibility/fs-request-bytes-campaign.json`,
with its budget and case views alongside it.

Scope is the REST `Commit` endpoint only. `BatchWrite` is excluded because the
compiler emits only the Commit endpoint and the transport admits only
`documents:commit`; a BatchWrite boundary needs its own compiler, transport
admission and receipt shape. gRPC remains a separate case.

The refusal expectation is a typed Firestore error with an integer HTTP status
of 400 (expected) or 413 (typed but a semantic discrepancy), an integer error
code equal to that status, and `INVALID_ARGUMENT`. An untyped transport refusal,
such as a front-end HTML 413 or a connection reset, is **not** a refusal proof:
the collector records it as `untyped-transport-refusal` under the separate result
key `untypedOverRefusal`, with the status, content type and response bytes
verbatim. It grants no cleanup ownership, keeps recovery read-only and leaves the
refusal shape unproven. The post-state readback and the recovery absence proofs
still establish that the refused request wrote nothing.

Every probe runs inside one 60-second total wire deadline, derived in
`request_bytes_campaign.TRANSPORT_DEADLINE` from the boundary upload size and
enforced independently by the transport and the worker. A missed deadline yields
an uncertain Commit whose residue cleanup detects but cannot remove.

`request_bytes_shadow.py` runs the plan and collector against an owned local
fireemu artifact built from this checkout, through the existing `broad.run`
artifact builder and process supervisor.

The current local expectation is strict-profile REST `Commit` accepting the
exact 11,534,336-byte body and refusing the 11,534,337-byte body with HTTP 400,
code 400, `INVALID_ARGUMENT`, and message
`Request payload size exceeds the limit: 11534336 bytes.` The strict REST
`:commit` handler uses `MAX_STRICT_COMMIT_RAW_BYTES` in
`crates/fireemu-adapter-grpc/src/serve.rs`; `API_REQUEST_BYTES` remains 10 MiB
for other surfaces. The current local observation is published in the
source-bound 11 MiB shadow receipt described below; it is a local result, not a
new production observation.

The saved production comparison establishes acceptance and typed refusal for
its concrete 11 MiB adjacent pair, but does not establish preservation of the
previously accepted document after refusal. The existing published local shadow
receipt records the older 10 MiB behavior and remains historical; it is not a
receipt for the current 11 MiB campaign. The current local shadow is published
separately and must prove the exact adjacent pair before O8 accepts it. A legacy 413 from a strict-profile build is
`local-boundary-enforced-shape-differs`. An accepted over probe is
`local-boundary-not-enforced`. A refusal without a typed envelope is
`local-untyped-transport-refusal`, which covers every complete refusal that is
not the typed over-boundary envelope, including a status outside 400 and 413
such as 500, 429 or 403. Those report `recordingComplete` false and
`stateValidation` true, because nothing was written but the boundary question is
unanswered. `shadow-failure` is not the bucket for an unfamiliar status: it is
reached only by a result the collector could not have produced.

The current receipt keeps the complete row journal private to the local run and
publishes its digest, schedule/request counts, request-body bindings and a
bounded skip summary. The summary must show exactly 17 skips, all over-probe
`cleanup-version-bound-delete` operations whose creation and current version
were not proven; skipped commits and readbacks are never permitted.

The refusal message is bounded in the final result. The response cap is 2 MiB
and the result is published under a 128 KiB row limit, so a long message copied
verbatim used to complete every request, prove every resource absent and then
lose the whole run when `result.json` could not be written. The full text stays
in the response sidecar; the result carries `messageBytes`, `messageSha256`, a
`messageTruncated` flag and the sidecar reference, plus either the whole
`message` or a bounded `messageExcerpt`, never both. A partial value is never
published under the `message` key.

The comparison follows the text rather than the excerpt: when the message was
truncated the verdict compares `messageSha256` against the digest of the
expected message, so a message whose first bytes match exactly is still a
difference. `refusalFieldMismatches` records which field was compared and how.

The comparison is field by field. `BASELINE_COMPARISON_FIELDS` names the HTTP
status, the error code, the error status and the message, and a verdict claiming
a match has compared all four; the collector records the message with the
response byte count and digest so the verdict rests on the bytes that arrived. A
mismatch lists the differing fields in `refusalFieldMismatches` and sets only
`matchesBaseline` false, leaving the recording and recovery facts intact.

The budget separates the forecast from the maximum. The maxima cover every probe
being accepted, 51 writes and 51 deletes, because an unexpectedly accepted
over-boundary Commit is the outcome the campaign exists to detect and must be
affordable. Peak coexisting documents and the 258-request bound do not rise with
the outcome.
Neither module authorizes production execution.

Run the offline tests with:

```text
uv run --offline --project tools/compat-inventory --locked pytest -q tools/compat-broad/fs-request-bytes-boundary
```


## Exit codes and retiring a held reservation

`request_bytes_o8.py` exits with the Ledger's state, not the data outcome:

- **0**: the run completed, cleanup was verified, `release.json` was written and
  the Ledger row is `released`.
- **2**: the run was refused before any reservation existed. Nothing is held,
  nothing is charged, `<output>/reservation.json` does not exist. A rebuilt
  packet may reuse the nonce.
- **1**: a reservation was taken and is still held. `<output>/reservation.json`
  names the ticket and was written the moment the row existed, before the Gate,
  the handoff or any wire activity. Do not retry and do not relaunch; retire the
  row.

The operator rule is therefore: **if `<output>/reservation.json` exists, a
reservation was taken and must be retired**, whatever the exit code and whether
or not `receipt.json` was written. Two rows of the Commit lane were stranded by
reading an exit code as a refusal, and the codes used to be ambiguous: a
no-data stop after the reservation exited 2, the same as a refusal.

Which terminal transition retires the row is decided by the receipt, never by
the stop's label:

1. `classify_stop(receipt)` names the disposition. A stop before the first
   Commit (invalid handoff, tokeninfo principal mismatch, project, database or
   Auth baseline drift, or a probe preflight that failed in transport or did not
   find the scope empty) is `aborted-no-data` when `mayHaveCreated` is false and
   the route journal shows only ownership reads. A stop at a Commit's transport
   deadline is `owner-escalation`, however few documents it may have left,
   because the Commit may have applied while its answer was lost.
2. For a no-data stop, `build_no_data_abort_record(<output>/receipt.json)`
   derives the shared Ledger's `shared-no-data-abort-v1` record from the
   receipt alone, generation included, and `Ledger.abort_no_data(ticket,
   record)` retires the row as `aborted-no-data`. The Ledger reads the
   registered Gate itself and accepts only when the Gate journal proves no
   creating slot was dispatched, the receipt's management rows and route rows
   reproduce the Gate's charged slots and data events one for one, and the
   coordinator and job PIDs are gone. The allocation stays charged; only the
   conflict locks and the concurrency slot are released.
3. Otherwise a Commit was dispatched. If the run itself went on to delete
   every document it created and proved each one absent (a stop after a
   probe's cleanup, such as a recording failure once the deletes had run),
   the Gate journal carries the typed absence for every created document and
   `Ledger.close_after_abandon` retires the row without an owner statement:
   this is the recoverable branch. If a Commit's answer was lost, or a
   created document is not proven absent, the recovery owner removes any
   residue, collects a typed `NOT_FOUND` for every owned resource, writes the
   owner attestation and calls `Ledger.close_after_escalation`. The three
   exits are disjoint by evidence: the no-data abort refuses a row with a
   dispatched Commit, the abandoned close refuses one whose cleanup is
   incomplete or whose Gate proves no creation, and the escalation close
   refuses both of those.

`test_request_bytes_production.py` drives the real launcher to each of these
stops against a temporary Ledger, in a forked child so its PIDs are genuinely
gone, and retires the row through the real path.

## Published evidence

`spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json` is a
historical local shadow receipt for the earlier 10 MiB boundary. It is
preserved as history and must not be treated as evidence for the current 11 MiB
campaign. The current receipt is
`spec/compatibility/broad-runs/fs-request-bytes-local-shadow-11mib.json` and
must prove the exact three current body sizes before O8 accepts it.
`build_shadow_document` is the only place a record's shape is decided, and
`test_request_bytes_evidence.py` rebuilds the current record from its own parts,
so a hand-edited record fails. The current record is bound to the modules that
produced it, so editing one of those means rerunning the shadow and republishing.

`request_bytes_run_fixture.py` drives the real collector through its full
258-slot schedule with an injected executor, so tests assert on results the
collector actually produced rather than on hand-written literals.


## Per-slot timings

Both transports record `elapsedSeconds` on every receipt, and the collector
copies it into each row, so a run measures what each schedule slot cost. On the
production transport the figure spans the whole slot: request preparation, the
worker process, the connection, the upload and the bounded response read, which
is the boundary a per-slot reservation has to pay for. The wrapper is additive
and never inspects the receipt, so it cannot change a refusal classification or
the deadline.

`slot_timings` summarises a run's rows into the published record, separately for
the three boundary Commits and the small reads and deletes, with the median, p95,
p99 and maximum. Zero-wire skips are excluded: they send nothing, and counting
them would drag every percentile toward zero.

**These are a floor, not an estimate.** A local shadow runs over loopback
against an emulator on the same machine, so its figures exclude the network
round trip, TLS and production server time. A production per-slot reservation
needs a production measurement, which the production transport can now supply.
The record carries that disclaimer beside the numbers and
`validate_slot_timings` refuses a block that drops it or claims to be a
production estimate.


## Rebinding after a runtime change

The published record and the preparation document's evidence citation are
rebound together, by one command, because they drifted apart when they were two
steps. Run the shadow into a fresh directory and publish:

```text
uv run --offline --project tools/compat-inventory --locked python tools/compat-broad/fs-request-bytes-boundary/request_bytes_shadow.py --output <fresh-directory> --publish
```

That runs the shadow against an artifact built from the current checkout, writes
`spec/compatibility/broad-runs/fs-request-bytes-local-shadow-11mib.json`, and
regenerates the block between the citation markers in
`docs/compatibility/fs-request-bytes-campaign-preparation.md` from it. Everything
outside those markers is hand-written and is left alone.

The tree must be committed first: `broad.run` refuses a dirty checkout so the
record binds to a reachable commit. That is why a rebind lands one commit after
the change it describes.

The two files are replaced as one generation, or not at all. Every input is read
and validated and both outputs are built in memory before any existing file is
touched, so a document missing its markers is refused while the tree is still
intact. A failure part way through the replacement restores what it had already
replaced, and if a restore itself fails the error names the files to check out
again rather than leaving a silent half-generation. Publishers of the same target
serialize on `spec/compatibility/broad-runs/.fireemu-request-bytes-publication.lock`,
which is gitignored for the same reason the Quint lane's is: a lock file showing
up in `git status` would make the next run refuse the checkout as dirty.

A publisher killed between writing a side file and replacing its target leaves
that `.publish-tmp` behind, which would dirty the checkout the same way, so the
suffix is gitignored too and each publisher sweeps stale side files while holding
the lock, where nothing being swept can belong to a publication still running.
Pre-images are restored as the bytes they were read as, never decoded: decoding
one could raise out of the handler doing the restoring and skip the restores
still to come.
