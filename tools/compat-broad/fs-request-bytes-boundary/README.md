# FS-LIMIT-API-REQUEST-BYTES bounded compiler

`request_bytes_compiler.py` is an offline compiler for a finite REST-only boundary plan. It emits three canonical Firestore REST `Commit` bodies whose compact UTF-8 JSON lengths are exactly 10,485,759, 10,485,760, and 10,485,761 bytes. Each body contains a disjoint 16-payload plus one-control document set; the three sets use equal-length scope labels and total 51 distinct resources. Padding is distributed across each set so every document remains below the 900 KiB preparation safety margin. Every write carries `currentDocument: {"exists": false}`, preventing an intervening document from being overwritten.

`validate_request_bytes_plan` independently checks the compiled artifact's endpoint, owned-resource scope, write identities, payload relationships, canonical byte lengths, and finite operation counts. It does not rebuild a replacement plan to make those checks pass.

The compiler also emits bounded preflight, commit, readback, and cleanup operations. The explicit `executionSchedule` interleaves each probe with its complete cleanup before the next probe may start. It is bounded at 258 calls with at most 17 live documents; failure to establish typed absence stops progression. The separate observation/recovery arrays are indexed operation tables, not an instruction to execute all observations before cleanup. Resources are scoped to the supplied nonce. Cleanup is described as ownership and version bound; this module does not execute it or provide a production authority. Expected field snapshots are SHA-256 references to sorted-key compact UTF-8 logical field maps from the exact probe payload (not raw response map order), avoiding repeated multi-megabyte field copies in every readback expectation. The plan serializes below 70 MiB; a later collector must implement the declared ownership and phase contract before this preparation can run.

The measured quantity is recorded as an observation hypothesis for the raw REST HTTP body bytes, including compact JSON syntax and UTF-8 encoding. URL and header bytes are outside that quantity. This is not established production semantics and does not cover gRPC: protobuf message encoding would require a separate compiler and receipt. The plan makes no claims about document, nested-depth, transform, or Commit operation-count limits.

The catalog context is the Firestore quotas page ([quotas](https://firebase.google.com/docs/firestore/quotas)) and the REST Commit reference ([Commit](https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/commit)). Those sources describe the limits and Commit shape; they do not establish that raw REST body bytes are the production enforcement metric.

Run the independent tests offline with:

```text
uv run --offline --project tools/compat-inventory --locked pytest -q tools/compat-broad/fs-request-bytes-boundary/test_request_bytes_compiler.py
```

No credentials, network request, emulator, or production runner is used.

`request_bytes_remote_transport.py` separately prepares exact frozen-plan REST slots and provides a fixed-origin HTTPS exchange with a 12-second total deadline and a 2 MiB response cap. Its public `request()` needs a bearer token, but the module does not acquire credentials, enforce the 258-slot execution schedule, hold shared reservations, or authorize production execution. It must be called only through a future O7-approved runner that binds the schedule, permission, budget, resource locks, and cleanup contract. Its tests use an injected exchange and send no production requests.

## Local collector and transport

`request_bytes_local_transport.py` is a campaign-specific loopback adapter. It
accepts only numeric loopback origins, the compiled Firestore REST operation
shape, request caps through 10,485,761 bytes, and the fixed 2 MiB response cap.
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

The observed local baseline is that the boundary **is** enforced and the strict
profile's refusal carries the same status, code and message this campaign
expects of production: HTTP 400 with
`{"error":{"code":400,"message":"Request payload size exceeds the limit: 10485760 bytes.","status":"INVALID_ARGUMENT"}}`.
The bound is applied at each transport's decode boundary from
`API_REQUEST_BYTES` in `crates/fireemu-adapter-grpc/src/serve.rs`, before the
request is parsed. The `emulator` profile keeps the legacy HTTP 413
`request body too large`; the boundary is identical under both and only the
shape differs.

That agreement is not confirmation. The expected production shape is documented
rather than observed, which is what this campaign exists to settle, so
`classify_local_result` reports
`local-shape-matches-production-expectation` and says so in its summary. A
legacy 413 from a strict-profile build is `local-boundary-enforced-shape-differs`
and now means the implemented shape was lost. An accepted over probe is
`local-boundary-not-enforced`. A refusal without a typed envelope is
`local-untyped-transport-refusal`, which covers every complete refusal that is
not the typed over-boundary envelope, including a status outside 400 and 413
such as 500, 429 or 403. Those report `recordingComplete` false and
`stateValidation` true, because nothing was written but the boundary question is
unanswered. `shadow-failure` is not the bucket for an unfamiliar status: it is
reached only by a result the collector could not have produced.

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


## Published evidence

`spec/compatibility/broad-runs/fs-request-bytes-local-shadow.json` is the
completed local shadow run. `build_shadow_document` is the only place its shape
is decided, and `test_request_bytes_evidence.py` rebuilds it from its own parts,
so a hand-edited record fails. The record is bound to the modules that produced
it, so editing one of those means rerunning the shadow and republishing.

`request_bytes_run_fixture.py` drives the real collector through its full
258-slot schedule with an injected executor, so tests assert on results the
collector actually produced rather than on hand-written literals.
