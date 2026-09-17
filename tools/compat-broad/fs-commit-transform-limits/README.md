# O3 Commit transform limit compiler

This directory contains a credential-free compiler and semantic comparison contract for the next finite Firestore Commit observation. It is preparation for `FS-DATA-WRITE-COMMIT-TRANSFORMS-03`; it does not acquire credentials, open a network connection, create a Gate, execute production requests, or grant compatibility approval.

`transform_compiler.py` emits two nonce-scoped owned document resources and 17 ordered data operations. The observation sequence creates both documents, submits exactly 500 transforms to one document as two writes of 250 each, submits exactly 501 transforms to the other as writes of 250 and 251, and verifies accepted and unchanged post-state. Six recovery operations read ownership, perform version-bound conditional deletes, and prove typed absence. The compiler does not encode a 500-operation-per-Commit limit.

`transform_comparator.py` validates compiler-plan binding, exact request journals, typed boundary outcomes, transformed fields, unchanged negative post-state, and cleanup version/marker binding. Requests are compared to their own compiler plan before any normalization, including JSON scalar types. Resolved cleanup requests must use the exact relative path and one encoded update-time predicate. It validates calendar timestamps and version relations from creation through baseline, accepted Commit write results, rejected Commit readback, control readback, and recovery. Per-resource timestamp relation signatures retain equality and ordering across all declared metadata slots without comparing absolute clock values. Readbacks bind to the final write result, and commitTime may be later than that updateTime. It normalizes only declared metadata timestamps and resource/owner identity slots using an internal tagged projection; nested user fields and error details remain exact. Both complete journals are shape-validated before semantic classification. Invalid or incomplete journals are `INDETERMINATE`; complete journals with an unexpected typed response or post-state difference are `SEMANTIC_MISMATCH`. It always reports acquisition and promotion as false.

The future transport must adapt the Commit POST target containment and mutation-aware cleanup checks to the existing shared Gate before an executable campaign can be considered. This package intentionally leaves that integration out of scope.

Run the focused checks with:

```text
uv run --project tools/compat-inventory --locked pytest tools/compat-broad/fs-commit-transform-limits
```

The timestamp contract follows the [Commit response](https://firebase.google.com/docs/firestore/reference/rest/v1/projects.databases.documents/commit) and [WriteResult](https://firebase.google.com/docs/firestore/reference/rest/v1/WriteResult) definitions: write results correspond to request writes, and commitTime bounds when reads can observe their effects; it is not assumed equal to each write updateTime.
