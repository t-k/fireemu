# firebase-testd

A deterministic, test-only local runtime for Firebase SDK and Functions code, written in Rust.

`firebase-testd` is not a faster re-implementation of the Firebase Emulator Suite. Its core is a
deterministic state machine that:

- detects missing Firestore indexes, production limit violations and inefficient queries locally;
- isolates state, events, time and Function execution per project / session so that parallel
  tests are deterministic;
- runs scheduled Functions against a virtual clock and offers `await-idle` instead of `sleep`;
- reproduces retries, duplicate delivery, delays and conflicts as seeded fault injection;
- treats Firestore, Security Rules and Enterprise / Text Search limits as versioned,
  boundary-exact specifications rather than documentation values;
- never claims compatibility it cannot show: every feature is declared in a Capability
  Manifest with an explicit precision (`exact`, `boundary-conformance`, `estimated`,
  `oracle-only`, `unsupported`).

## Status

Implemented: Milestone A (verification-ready core), Milestone B (strict Firestore gateway: query / index / limit validation), Milestone D core (`ST-OBJ-1`: Cloud Storage objects with generations, listing, resumable uploads on both the Firebase and the JSON API protocols; Storage Security Rules evaluated at upload finalization against the received bytes), Milestone E (local Firestore execution: versioned documents, atomic commits with preconditions / masks / transforms, MVCC transactions with read-set and query re-validation, queries, aggregations, `Write` and `Listen` streams), `FS-REST-1` (the Firestore REST API on the same port as gRPC), Milestone H0 (Auth core + TOTP over the Identity Toolkit REST subset, Admin SDK account endpoints, custom token sign-in) native Security Rules enforcement on every Firestore surface (`Bearer owner` bypass, ID tokens verified against the Auth store, reads checked against the returned snapshot, writes checked inside the commit, queries proven from their constraints; see `RULES-QUERY-CONSTRAINTS` in `crates/ftd-adapter-grpc/src/rules.rs`), and Milestone C (Cloud Functions: a `firebase-functions` v2 codebase runs in the bundled Node runner; Firestore document triggers, Storage object triggers, `onSchedule` driven by the virtual clock, `onRequest` / `onCall` over an HTTP port, retries with virtual-time backoff, `await-idle`).

The real `firebase-admin`, `firebase` (Node: gRPC streams; browser: the WebChannel transport on the same port), and `firebase/firestore/lite` (REST) SDKs run against the daemon; `tools/sdk-smoke` holds the smoke scripts and a browser page. Not implemented yet: `PartitionQuery`, `ExecutePipeline`, signed ID tokens, inequality constraints in query rules proofs, Storage object versioning / signed URLs / compose, `firebase-functions/v1` event functions, daylight-saving time zones for schedules.

## Run

```sh
cargo run -p firebase-testd -- up --firestore-port 8080 --http-port 9099 --storage-port 9199
#   optional: --config firebase-testd.json  (see spec/config/firebase-testd.schema.json)
#   optional: --functions ./functions --functions-port 5001   (a firebase-functions v2 codebase)
```

The daemon prints the environment variables SDKs need (`FIRESTORE_EMULATOR_HOST`, `FIREBASE_AUTH_EMULATOR_HOST`, `FIREBASE_STORAGE_EMULATOR_HOST` / `STORAGE_EMULATOR_HOST`). Storage rules load from `storage.rules` in the config or `PUT /v1/storage/rules`. Security Rules come from `rules.source` in the config file or at runtime:

```sh
curl -X PUT http://127.0.0.1:9099/v1/rules -H 'content-type: application/json' \
  -d "$(jq -n --rawfile s firestore.rules '{source: $s}')"
curl -X POST http://127.0.0.1:9099/v1/sessions/default/clock:advance -d '{"seconds": 60}'
curl -X POST http://127.0.0.1:9099/v1/sessions/default/reset   # drop Firestore + Auth state
```

Without rules every request is allowed (the daemon says so at start). `firebase-testd doctor` prints versions and catalogs; `firebase-testd capabilities` prints the Capability Manifest.

### Storage

An object is at most 256 MiB; a request body is at most 260 MiB (the object boundary plus multipart framing) and is refused with `413` beyond that. Upload bytes are never duplicated on the way in: the request buffer is handed to the object store as it is, and a multipart data part is carved out of the same allocation, so a near-limit upload costs one payload-sized buffer, not two or three.

The request bodies buffered at the same time are admitted against a process-wide budget of 1 GiB (`ftd_adapter_http::storage_server::DEFAULT_BODY_BUDGET_BYTES`, about four near-limit uploads). An upload that does not fit is refused with `503` and `Retry-After: 1` before its buffer is allocated; a body without a `Content-Length` is charged as it grows. Every charge is released as soon as the request ends, including when the upload fails on rules, a checksum or a precondition. A failed upload publishes no object.

### Functions

`--functions <dir>` (or `functions.source` in the config) starts `tools/runner-node/index.mjs` (Node, needs the codebase's own `node_modules` with `firebase-functions` and `firebase-admin`; `express` comes with `firebase-functions`). The runner discovers the exported v2 functions and reports them; the daemon then delivers Firestore document events (`onDocumentCreated` / `Updated` / `Deleted` / `Written` with path parameters), Storage object events (`onObjectFinalized` / `Deleted` / `MetadataUpdated`) and `onSchedule` runs as JSON CloudEvents, and serves `onRequest` / `onCall` at `http://127.0.0.1:5001/{project}/{region}/{function}`. Functions declared with `retry: true` are retried with exponential backoff in virtual time; other failures are dead-lettered.

```sh
curl -X POST http://127.0.0.1:9099/v1/sessions/default:awaitIdle -d '{"timeoutSeconds": 30}'   # wait for triggers
curl -X POST http://127.0.0.1:9099/v1/sessions/default/clock:advance -d '{"seconds": 600}'     # runs due schedules (and due retries)
curl -X POST http://127.0.0.1:9099/v1/sessions/default/functions/nightly:run                  # run a schedule now
curl http://127.0.0.1:9099/v1/sessions/default/functions                                      # queue status
```

Invocations have a real-time deadline (`timeoutSeconds`); a handler that overruns it is dead-lettered (or retried) but keeps its concurrency slot, and `await-idle` keeps waiting, until it actually finishes. The runner inherits only an allowlisted environment (no cloud credentials; Application Default Credentials are blocked) plus the emulator hosts. Reset while functions are running or writes are in flight is not atomic across Firestore, Storage and the functions runtime: reset between test cases, when the app is quiescent.

Browser pages on a loopback origin must send `Authorization: Bearer <control token>` (printed at start as `FTD_CONTROL_TOKEN`) to privileged control routes (reset, clock, rules, functions, `awaitIdle`); command-line clients need no token.

`tools/sdk-smoke/functions.mjs` with `tools/sdk-smoke/functions-project/` exercises all of it. `firebase-functions/v1` event and schedule functions, other trigger families and DST time zones are declared unsupported in the Capability Manifest.

Browser apps point the web SDK at the same ports (`connectFirestoreEmulator(db, "127.0.0.1", 8080)`, `connectAuthEmulator(auth, "http://127.0.0.1:9099")`); the Firestore port serves gRPC, REST and the WebChannel transport, and both ports answer CORS preflights. `FTD_TRACE_WEBCHANNEL=1` traces the channel protocol on stderr.

| Crate | Purpose | Dependencies |
|---|---|---|
| `ftd-core-types` | validated identifiers, logical time, edition capabilities, deterministic adapters | none |
| `ftd-core-limits` | versioned limit catalogs and the warning / rejection engine | none |
| `ftd-core-session` | session lifecycle, epoch isolation, virtual clock, idle ledger | none |
| `ftd-core-events` | event state machine, retry policy, outbox | none |
| `ftd-core-firestore` | field paths, value ordering, storage-size formula, query AST + Standard limits, conservative index validator, local execution store (MVCC, transactions, queries, aggregations) | none |
| `ftd-core-rules` | Security Rules parser, static limit linter (`RULES-LINT-1`) and evaluator subset with runtime budgets | none |
| `ftd-core-auth` | users, custom claims, ID token claims, unsigned emulator tokens, TOTP second factor (RFC 6238) | none |
| `ftd-core-storage` | Cloud Storage objects: opaque UTF-8 names, generations, metadata, listing, resumable uploads, MD5 / CRC32C | none |
| `ftd-core-functions` | function manifest, document path patterns, cron / App Engine schedules, CloudEvents attributes | none |
| `ftd-proto-firestore` | vendored Firestore v1 protos and checked-in generated code | prost, prost-types, tonic |
| `ftd-adapter-grpc` | Firestore v1 service: strict gateway, local backend, `Write` / `Listen` streams, Rules enforcement, optional upstream proxy | tonic, tokio |
| `ftd-adapter-http` | Identity Toolkit REST subset (sign-up, password sign-in, custom claims, TOTP MFA, refresh, Admin SDK accounts), the Storage surface and the control API (clock, rules, capabilities, await-idle) | hyper, tokio, serde_json |
| `ftd-adapter-functions` | runner process protocol, event dispatch with retries, scheduler, await-idle, HTTP function proxy | tokio, hyper, serde_json |
| `firebase-testd` | the daemon binary (`up`, `doctor`, `capabilities`) | tokio, serde_json |

`ftd-core-*` crates are `std`-only and forbid `unsafe` (ADR-001, ADR-007).

## Layout

```text
crates/            core crates (std-only) and, later, protocol / runtime shells
spec/limits/       versioned limit catalogs (single source of truth for limit values)
tools/             development tools; never linked into the release binary
verification/      TLA+ models, Loom scenarios, Kani harnesses, mutant and requirement catalogs
docs/adr/          architecture decision records
```

## Verify

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
scripts/check-core-deps.sh
cargo nextest run --workspace --profile pr
cargo run -p limit-catalog-gen -- check
cargo run -p traceability-check
cargo run -p config-schema-check
cargo run -p proto-gen -- check            # needs protoc
RUSTFLAGS="--cfg loom" cargo test -p ftd-verification-loom --release
TLA2TOOLS_JAR=/path/to/tla2tools.jar verification/tla/run-tlc.sh
```

TLC needs Java 21 and TLA+ Tools 1.8.0
(`sha256 eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a`).
Kani harnesses live in `verification/kani` and run with `cargo kani`. Harnesses that allocate
on the heap currently fail on macOS with Kani 0.67 ("Function `malloc` with missing definition
is unreachable"); the allocation-free harnesses verify. Tracked as a known environment issue.

## Protobuf

`crates/ftd-proto-firestore/proto/` vendors the Firestore v1 protos from googleapis at the commit
in `proto/UPSTREAM_COMMIT`; `tools/proto-gen` regenerates the checked-in Rust code (ADR-008).
A normal build never runs `protoc`.

## Limit catalogs

Limit values are declared once in `spec/limits/<catalog-id>.json` and rendered into
`crates/ftd-core-limits/src/generated/` by `tools/limit-catalog-gen`. Catalogs are immutable:
when an official document changes, add a new catalog ID instead of editing an existing one.

```sh
cargo run -p limit-catalog-gen -- generate   # after editing spec/limits
cargo run -p limit-catalog-gen -- check      # CI
```

## Requirement traceability

`verification/requirements/requirements.json` maps every critical requirement to its TLA+
property, Loom scenario, Kani harness, property test, semantic mutants and integration tests.
`verification/mutants/catalog.json` and `verification/loom/scenarios.json` are the single
sources of truth for mutant IDs and Loom scenario names; `tools/traceability-check` rejects
duplicates, undefined references and critical requirements without a formal and a dynamic
artifact.

## License

Apache-2.0 (see `Cargo.toml`). A `LICENSE` file will be added before the first public release.
