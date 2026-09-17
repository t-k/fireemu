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