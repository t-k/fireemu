# Stream comparison v2

This offline entry re-compares the retained September 17 production acquisition at `dee737c14` with the owned repaired local acquisition at `567565bdd`. It performs no credential access, network request, or new observation. It does not promote results.

Run from a checkout with the inventory Python environment installed:

```sh
uv run --offline --project tools/compat-inventory --locked python tools/compat-broad/fs-write-txn-recompare-v2/saved_authority.py --root /path/to/main/repository --output /path/to/new-comparison.json
```

`compare_stream_receipts_v2.mjs` provides the equivalent file-based entry with positional root and output arguments. Its Python interpreter must have the inventory dependencies installed. The output is created exclusively with mode `0600`. Verification failure produces `INDETERMINATE`, never a semantic verdict with acquisition authority.

`saved_authority.py` is deliberately campaign-specific. Reviewed commit identities and independently recorded production, prepared-input, original comparison, repaired receipt, artifact, and build-manifest byte hashes are trust roots in source. Callers cannot substitute permission objects or self-attested hashes. The entry checks frozen validator source, permission and acquisition-time bounds, persisted execution inputs, metadata, complete data events bound to collection objects, typed cleanup absence, sealed OAuth journal, released ledger claim/envelope/final-gate bindings, and the repaired owned artifact/build validator against its actual historical source tree. It never uses a current lease or a substituted wall clock to authorize historical acquisition.

The output binds the exact input snapshots, original v1 comparison, imported historical validator sources, repaired runtime build inputs, and every v2 source file. All snapshots are rechecked before output. The original v1 files and receipts remain unchanged. Missing retained campaign files or changed historical trees fail closed.

`stream_recompare_v2.mjs` is only a semantic kernel: its object digests are consistency checks, not acquisition authority. Its result always has `acquisitionValidated: false`. Only the file-based authority entry can validate acquisition.

Normalization applies solely to validated code-5 `GetDocument` diagnostics in declared top-level status/error fields, including independently deserialized duplicate cleanup records. It replaces the exact request resource slot while preserving wording, quotes, punctuation, and the `5 NOT_FOUND: ` prefix. Consequently, `Document "RESOURCE" not found.` and `Document not found: RESOURCE` remain different. Unknown grammar, other fields, partial references, and user strings remain literal. An `INDETERMINATE` v1 result is never rescued.

The synthetic Node suite runs without private data. `test_saved_authority.py` additionally uses the retained real JSON files and rejects forged root bytes. Set `STREAM_RECOMPARE_ROOT` to the main repository for that private integration test.
