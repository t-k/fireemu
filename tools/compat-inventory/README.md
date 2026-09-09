# Compatibility acquisition tools

These explicit tools enumerate official sources and record bounded, candidate-only observations. They do not modify the runtime, promote feature evidence, overwrite accepted conformance matrices or attest a release. Python tools use `uv`; protobuf extraction additionally requires `protoc`.

## Offline checks

```sh
uv run --project tools/compat-inventory --locked -m pytest tools/compat-inventory -q
uv run --project tools/compat-inventory --locked tools/compat-inventory/publish.py --check
```

The gate checks snapshot component hashes, the pinned protobuf sources, candidate receipt assertions and cleanup, and deterministic Markdown. Checks do not contact Google or start fireemu. A deliberately edited manifest can still redefine the baseline: hashes are integrity checks, not signed authenticity or approval. Code review is required for baseline changes.

The automatic compatibility workflow also runs `cargo run --locked -p compat-check` and `cargo test --locked -p compat-check` to protect requirement/capability references and all generated feature tables. Python dependencies are resolved by the committed `uv.lock`; the workflow pins uv itself. These checks run on PRs, main pushes and manual dispatch, not on feature-branch pushes alone.

Historical receipts retain their original harness bytes and digest through the index's `historicalTools` mapping. The 2026-09-09 aggregation harness had an incomplete stream validator; its stored extracted values cannot prove the original full response was well-formed. It is archived solely as provenance, not as a recommended executable. The fixed probe inspects every response element and permits only a result and valid `readTime` progress metadata for this corpus, which requests neither transactions nor explain metrics. Historical observations are not relabeled as executions of the new validator.

## Explicit source acquisition

```sh
uv run tools/compat-inventory/capture.py --output spec/compatibility/upstream/NEW-SNAPSHOT --cache /absolute/ignored/source-cache
uv run tools/compat-inventory/protobuf_inventory.py --output spec/compatibility/upstream/NEW-PROTOBUF.json
```

Acquisition traverses the Firebase, Cloud and Cloud Docs sitemap indexes, deduplicates English canonical URLs within the declared Auth/Firestore/Rules and related SDK scope, enumerates four REST Discovery documents, and extracts only the configured seed articles. Every other page remains discovered, not read. Sitemap omissions, failed acquisitions, unreviewed bodies and unknown requirement mappings remain debt. All Firestore v1 protobuf files are enumerated, including request/response roles, streaming flags, fields, nested types, enums and oneofs. Imported protobuf files are hash-bound but are not counted as Firestore API items.

Raw response bodies and extracted article text remain in the caller-selected ignored cache, not in the public repository. Gzip decoding has a 64MiB expanded-response budget. Cached bytes are hash-verified and preserve their original retrieval date; reusing a cache is not a fresh retrieval. Use a new cache to intentionally refresh upstream content. Snapshot creation refuses an existing output directory. Acquisition failure remains visible in the catalog.

## Explicit production observations

### Bounded compound-aggregation evidence

The newer [bounded evidence page](../../docs/compatibility/aggregation-evidence.md) is independent of the historical probes below. Its corpus fixes eight typed query expectations and two refusal/state controls before measurement. `owned_runner.py --build` invokes Cargo, copies its exact artifact and strict configuration into a private directory, launches only Firestore on OS-assigned ports, checks the inherited process/control-token/profile identity, and verifies shutdown. `--binary` remains useful for diagnostics, but without a recorder-owned build its observation cannot pass the evidence validator. External-daemon observations cannot acquire artifact identity.

```sh
uv run --project tools/compat-inventory --locked tools/compat-inventory/owned_runner.py --build --output /absolute/new-owned-run
uv run --project tools/compat-inventory --locked tools/compat-inventory/aggregation_probe.py --target production --output /absolute/new-production.json
uv run --project tools/compat-inventory --locked tools/compat-inventory/publish.py --check
```

The production corpus additionally owns one composite index in its fresh UUID collection group. It requires an empty baseline for that exact namespace, journals the create before sending it, waits for the exact long-running operation and READY index, deletes only matching owned indexes, and confirms absence only after creation has resolved. The operation wait is bounded at 15 minutes, with five-second polls; this is not a service SLA. Firebase documents a [several-minute minimum index build time even for empty databases](https://firebase.google.com/docs/firestore/query-data/indexing#index_build_time). Broader Admin API list results are filtered by the exact parent path; pagination is rejected. A lost create response with no operation identity remains unresolved, never certified clean. No existing documents or foreign indexes are deleted.

`aggregation_package.py` stages and validates the selected source capsule, separate source-review record, corpus and two full-response candidates before publishing the bundle. It refuses replacement of an existing bundle and always starts with empty approvals. The source capsule is the exception to the private-cache policy above: its original raw bytes are preserved compressed for offline body-hash/extractor verification. Only selected sections are reviewed; derived boundary and state controls are explicitly distinguished from source claims.

Approval is repository-reviewed metadata, not a signature. A reviewer must inspect the exact subject and explicitly approve case IDs. The offline publisher rechecks all bound source/tool/runtime inputs, raw cases and identities before generating labels. Editing an input invalidates the bundle and any approval; refresh candidates deliberately rather than rewriting historical receipts. Broad schema1 feature labels remain unverified. Run the real-process integration test with `FIREEMU_EVIDENCE_BINARY=/absolute/fireemu`; without that opt-in, offline CI reports it as skipped.

The source `commit` fields record checkout HEAD at measurement time; the per-file manifests are the measured identities and can include not-yet-committed additions. Do not infer the complete measured tree from HEAD alone. The validator compares those complete manifests with the current inputs, and the build receipt binds runtime inputs to the copied artifact separately from probe sources.

A complete, structurally valid query mismatch may be published as a mismatch, not a success. The validator checks every response element, expected alias and typed aggregate Value before comparing values, then recomputes the case and summary verdicts. Only the intersection of cases matching on both targets can be approved. Malformed responses, incomplete execution, failed ownership/state controls or failed cleanup reject the entire bundle. Keep unexpected values and original expectations unchanged while investigating divergence.

### Historical candidate probes

Production access is restricted to `fireemu-35fe6`, project number `592603257417`. The focused Firestore probe verifies the live project number and Standard/Native database configuration before exclusively creating four documents in a random root collection. It never enumerates or clears existing collections. Tokens remain in memory; redirects are refused. Each attempted create is journaled and flushed before the request. Cleanup checks uncertain-create ownership markers, deletes only owned fixture paths, and confirms absence. A cleanup failure prevents success and leaves an exact-path recovery receipt. A hard process kill can still interrupt cleanup: inspect that receipt and verify ownership before recovering its named resources; never clear the database.

```sh
uv run tools/compat-inventory/probe.py --target production --output /absolute/new-aggregation-candidate.json --binary target/debug/fireemu
uv run tools/compat-inventory/auth_probe.py --target production --output /absolute/new-auth-candidate.json
```

The Auth probe requires project-bound API key lookup and configuration readback before four rejection-only requests. It creates no accounts and sends no email or SMS. Missing configuration access produces an inconclusive receipt before cases; it is not an Auth failure or pass. Positive controls and actual MFA/IdP flows require separate corpus design and review.

For local runs, start the worktree's built binary using `fireemu exec` and an available port managed by the local port registry. The child commands accept `FIRESTORE_EMULATOR_HOST` or `FIREBASE_AUTH_EMULATOR_HOST` from that runner. End the runner when finished; do not leave a development server behind.

The current probe does not establish that this daemon is the supplied `--binary`, or that its profile is strict. Its binary/profile fields are operator assertions, not process identity evidence. Likewise, `sourceCommit` identifies the probe working directory's HEAD, not a proved runtime build. Before any formal evidence promotion, a runner must own the artifact launch and configuration, verify the instance, record separate probe/runtime/artifact identities, and stop its owned process. Attaching to an external daemon must remain an explicitly unverified observation path.

```sh
uv run tools/compat-inventory/probe.py --target local --origin http://127.0.0.1:PORT --output /absolute/new-local-candidate.json --binary target/debug/fireemu
```

The historical timestamp-array harness in `tools/sdk-smoke/timestamp-array-oracle.mjs` was run separately for the initial snapshot. Its six UUID fixtures and sixty steps are not sixty independent features. Its receipt omits binary/configuration metadata and its cleanup only records successful DELETE requests, not absence confirmation. These limitations are retained in the candidate report.

`publish.py --record LOCAL-RECEIPT-DIRECTORY --snapshot SNAPSHOT-PATH --write` packages the initial 2026-09-09 candidate set and refuses an existing index. It is intentionally specific to this reviewed corpus, not a general evidence-acceptance command. Subsequent captures should use new immutable artifact paths and explicitly review index updates. Use `publish.py --write` to regenerate the report after such a reviewed update.
