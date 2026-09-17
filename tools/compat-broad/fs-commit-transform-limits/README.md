# O3 Commit transform limit compiler

This directory contains a credential-free compiler and semantic comparison contract for the next finite Firestore Commit observation. It is preparation for `FS-DATA-WRITE-COMMIT-TRANSFORMS-03`; it does not acquire credentials, open a network connection, create a Gate, execute production requests, or grant compatibility approval.

`compiler.py` emits two nonce-scoped owned document resources and 17 ordered data operations. The observation sequence creates both documents, submits exactly 500 transforms to one document as two writes of 250 each, submits exactly 501 transforms to the other as writes of 250 and 251, and verifies accepted and unchanged post-state. Six recovery operations read ownership, perform version-bound conditional deletes, and prove typed absence. The compiler does not encode a 500-operation-per-Commit limit.

`comparator.py` validates compiler/source binding, exact request journals, typed boundary outcomes, transformed fields, unchanged negative post-state, and timestamp-only response nondeterminism. It always reports acquisition and promotion as false. Invalid or incomplete journals are `INDETERMINATE`; complete journals with a post-state difference are `SEMANTIC_MISMATCH`.

The future transport must adapt the Commit POST target containment and mutation-aware cleanup checks to the existing shared Gate before an executable campaign can be considered. This package intentionally leaves that integration out of scope.

Run the focused checks with:

```text
uv run --project tools/compat-inventory --locked pytest tools/compat-broad/fs-commit-transform-limits
```
