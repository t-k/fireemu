# O4 bounded IN query compiler

This directory contains a credential-free compiler for the finite `second/filters/in-30-31-state` query boundary. It does not open a network connection, read credentials, execute production, mutate indexes or Rules, or claim production compatibility.

`query_in_compiler.py` emits exactly nine data-plane operations for one nonce-scoped document: six observations and three recovery operations. The observation sequence performs typed absence, conditional creation, a parent-scoped collection query with 30 integer `IN` operands, a before-state read, the same query with 31 operands, and an after-state read. Both queries use `limit: 1`; the only query difference is the operand cardinality. The query has no `allDescendants`, order, cursor, pagination, additional filter, aggregation, Enterprise mode, or index mutation. The owned query parent is a document path ending in `/o4-query-in-boundary/root`; the relative `cur/c` collection/document path is validated independently for even document-path segment structure and scope.

The fixture fields are retained exactly from `second/filters/in-30-31-state`: `n=2`, `g=q`, and nested `a.b=7`. Ownership is represented by a successful conditional creation in this run plus exact fields and identity readback, so no marker field is added to the saved fixture. Cleanup additionally requires the readback `updateTime` to equal the successful create response; when the API supplies `createTime`, that value must match too. A preexisting document with matching fields, an explicit creation refusal, a lost/oversized creation response, or a replacement with a newer version never authorizes deletion. Cleanup is a separate ownership read, version-bound conditional delete, and typed absence verification. `validate_plan` rejects foreign parents, changed collection scope, added query members, operand edits, nonce drift, unowned cleanup paths, and digest changes.

The `expect` entries describe the finite local comparison contract: the 30-operand query is accepted with one expected document, while the 31-operand diagnostic is expected to be a typed `INVALID_ARGUMENT` refusal under the reviewed local contract. A future production collector must retain the complete actual response and classify any complete unexpected outcome as a semantic difference; these entries do not fabricate a production receipt.

The collector publishes each row with an exclusive link and fsync. The final `collection.json` publication is reported in the returned result when its link or fsync fails, without overwriting an older file or retrying observation. The returned cleanup fact remains separate, so a successful cleanup is preserved even when recording is incomplete. If journal directory initialization fails, the collector sends no wire operations and retains the initialization failure.

When a local transport supplies `rawBody` bytes (or strict `rawBodyBase64`) together with the typed HTTP status, content type, completion flag, and byte count, the collector publishes one immutable `.raw` sidecar per dispatched observation or recovery slot below `raw/`. `raw/manifest.json` records each binding's phase, index, path, byte count, and SHA-256 digest. The collector reloads this manifest through `RawJournal` before returning the result and exposes the hash-checked semantic view on each bound row. Missing, partial, or invalid transport bytes remain compact evidence only and set `rawComplete` false; the collector never reconstructs raw bytes from the decoded JSON body.

Run the focused checks with:

```text
uv run --project tools/compat-inventory --locked pytest tools/compat-broad/fs-query-in-boundary
```

## Reviewed local verification

Collector source `8b0f12166a0115a9ad32edd6efaf986a609ef7da` was exercised against retained fireemu artifact SHA-256 `be2771b9f2093cced55e8158d8d5a72ed35e6ac5e32edddb068daa45511e12ae` using an owned loopback process. The nine responses were: typed absence 404, conditional creation 200, IN30 query 200, readback 200, IN31 query 400/INVALID_ARGUMENT, unchanged readback 200, ownership read 200, conditional deletion 200, and typed absence 404. Recording and cleanup completed; the process stopped and its port reservation was released.

The final test-only follow-up `c0a41b55c87dcbc092d3fcbc9e41de0da53c6b13` passed 40 focused tests and Ruff. Independent review approved the final change with no remaining blocker or high finding. The regression set includes preexisting matching and nonmatching documents, refused and ambiguous creation, replacement-version rejection, and final write/fsync/link/collision failures. Directory-fsync failure can leave an already-linked file with optimistic flags; callers must use the returned publication failure and must not promote that file alone as validated acquisition evidence.

This verifies the local observation tooling and the finite local API controls. It is not a production observation, saved-production comparison, or parent compatibility promotion.

## Offline comparator

`query_in_comparator.py` compares two retained bundles after validating each plan digest, every ordered operation request, typed receipt envelope, and ownership/cleanup evidence. It canonicalizes only the compiled owned document/parent identities and bounded timestamps; Firestore Value types, error objects, query shapes, and invalid path refusals remain exact. Complete differing responses are `SEMANTIC_MISMATCH`, equivalent semantics with run-specific values are `EXPECTED_NONDETERMINISM`, and missing or unbound evidence is `INDETERMINATE`. The result is semantic-only and always keeps `acquisitionValidated` and `promotionReady` false. Raw sidecar projections may be supplied as typed views; malformed or unbound views are indeterminate.

## Production bridge preparation

`query_in_production.py` contains offline preparation only. Its attempt ledger models the fixed two OAuth, four preflight metadata, six observation, three recovery, and four postflight metadata slots. A skipped conditional delete consumes its recovery position without counting a wire send. The compact journal limits each row to 8,192 serialized bytes and its envelope to 32,768 bytes. Raw data responses have separate, exclusive 65,536-byte sidecars; a positive-query semantic view is derived only from a complete successful observation slot 2 response after verifying its raw hash and JSON content type. Duplicate JSON keys, malformed row metadata, invalid document or field names, malformed Firestore Value objects, and response fields outside the compiled query shape remain raw evidence with an indeterminate projection. The bounded recursive Value validator rejects numeric overflow and arrays directly nested in arrays while accepting well-formed unexpected documents for later comparison. The original response bytes remain the comparison authority.

This validator covers the Standard RunQuery Value shape used by the compiled case. Enterprise and pipeline Value variants, including `fieldReferenceValue`, `variableReferenceValue`, `functionValue`, and `pipelineValue`, remain raw-only and cannot produce a document projection.

Production admission intentionally remains unavailable. The shared Gate currently accepts only its registered contracts. Its `shared-local-v2` conditional-create proof requires a `_sharedOwner` field, while this case's fixed fixture has no such field. Adopting that contract would change the case under test. The live index policy, exclusive query namespace, complete cost and retention bound, and owner permission also remain unresolved. `admission_status` names these blockers, and `validate_permission` accepts no production permission while they remain unbound. There is no production transport or credential entry point in this module.
