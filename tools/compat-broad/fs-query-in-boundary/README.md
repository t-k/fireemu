# O4 bounded IN query compiler

This directory contains a credential-free compiler for the finite `second/filters/in-30-31-state` query boundary. It does not open a network connection, read credentials, execute production, mutate indexes or Rules, or claim production compatibility.

`query_in_compiler.py` emits exactly nine data-plane operations for one nonce-scoped document: six observations and three recovery operations. The observation sequence performs typed absence, conditional creation, a parent-scoped collection query with 30 integer `IN` operands, a before-state read, the same query with 31 operands, and an after-state read. Both queries use `limit: 1`; the only query difference is the operand cardinality. The query has no `allDescendants`, order, cursor, pagination, additional filter, aggregation, Enterprise mode, or index mutation. The owned query parent is a document path ending in `/o4-query-in-boundary/root`; the relative `cur/c` collection/document path is validated independently for even document-path segment structure and scope.

The fixture fields are retained exactly from `second/filters/in-30-31-state`: `n=2`, `g=q`, and nested `a.b=7`. Ownership is represented by a successful conditional creation in this run plus exact fields and identity readback, so no marker field is added to the saved fixture. A preexisting document with matching fields, an explicit creation refusal, or a lost/oversized creation response never authorizes deletion. Cleanup is a separate ownership read, version-bound conditional delete, and typed absence verification. `validate_plan` rejects foreign parents, changed collection scope, added query members, operand edits, nonce drift, unowned cleanup paths, and digest changes.

The `expect` entries describe the finite local comparison contract: the 30-operand query is accepted with one expected document, while the 31-operand diagnostic is expected to be a typed `INVALID_ARGUMENT` refusal under the reviewed local contract. A future production collector must retain the complete actual response and classify any complete unexpected outcome as a semantic difference; these entries do not fabricate a production receipt.

The collector publishes each row with an exclusive link and fsync. The final `collection.json` publication is reported in the returned result when its link or fsync fails, without overwriting an older file or retrying observation. The returned cleanup fact remains separate, so a successful cleanup is preserved even when recording is incomplete. If journal directory initialization fails, the collector sends no wire operations and retains the initialization failure.

Run the focused checks with:

```text
uv run --project tools/compat-inventory --locked pytest tools/compat-broad/fs-query-in-boundary
```
