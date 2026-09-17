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
