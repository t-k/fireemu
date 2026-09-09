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
