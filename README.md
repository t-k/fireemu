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

Implemented: Milestone A (verification-ready core), Milestone B (strict Firestore gateway: query / index / limit validation), Milestone E (local Firestore execution: versioned documents, atomic commits with preconditions / masks / transforms, MVCC transactions with read-set and query re-validation, queries, aggregations, `Write` and `Listen` streams), `FS-REST-1` (the Firestore REST API on the same port as gRPC), Milestone H0 (Auth core + TOTP over the Identity Toolkit REST subset, Admin SDK account endpoints, custom token sign-in) and native Security Rules enforcement on every Firestore surface (`Bearer owner` bypass, ID tokens verified against the Auth store, reads checked against the returned snapshot, writes checked inside the commit, queries proven from their constraints; see `RULES-QUERY-CONSTRAINTS` in `crates/ftd-adapter-grpc/src/rules.rs`).

The real `firebase-admin`, `firebase` (Node: gRPC streams; browser: the WebChannel transport on the same port), and `firebase/firestore/lite` (REST) SDKs run against the daemon; `tools/sdk-smoke` holds the smoke scripts and a browser page. Not implemented yet: `read_time` snapshots, `PartitionQuery`, `ExecutePipeline`, Storage / Functions / Scheduler (Milestones C / D), signed ID tokens, inequality constraints in query rules proofs.

## Run

```sh
cargo run -p firebase-testd -- up --firestore-port 8080 --http-port 9099
#   optional: --config firebase-testd.json  (see spec/config/firebase-testd.schema.json)
```

The daemon prints the environment variables SDKs need (`FIRESTORE_EMULATOR_HOST`, `FIREBASE_AUTH_EMULATOR_HOST`). Security Rules come from `rules.source` in the config file or at runtime:

```sh
curl -X PUT http://127.0.0.1:9099/v1/rules -H 'content-type: application/json' \
  -d "$(jq -n --rawfile s firestore.rules '{source: $s}')"
curl -X POST http://127.0.0.1:9099/v1/sessions/default/clock:advance -d '{"seconds": 60}'
curl -X POST http://127.0.0.1:9099/v1/sessions/default/reset   # drop Firestore + Auth state
```

Without rules every request is allowed (the daemon says so at start). `firebase-testd doctor` prints versions and catalogs; `firebase-testd capabilities` prints the Capability Manifest.

| Crate | Purpose | Dependencies |
|---|---|---|
| `ftd-core-types` | validated identifiers, logical time, edition capabilities, deterministic adapters | none |
| `ftd-core-limits` | versioned limit catalogs and the warning / rejection engine | none |
| `ftd-core-session` | session lifecycle, epoch isolation, virtual clock, idle ledger | none |
| `ftd-core-events` | event state machine, retry policy, outbox | none |
| `ftd-core-firestore` | field paths, value ordering, storage-size formula, query AST + Standard limits, conservative index validator, local execution store (MVCC, transactions, queries, aggregations) | none |
| `ftd-core-rules` | Security Rules parser, static limit linter (`RULES-LINT-1`) and evaluator subset with runtime budgets | none |
| `ftd-core-auth` | users, custom claims, ID token claims, unsigned emulator tokens, TOTP second factor (RFC 6238) | none |
| `ftd-proto-firestore` | vendored Firestore v1 protos and checked-in generated code | prost, prost-types, tonic |
| `ftd-adapter-grpc` | Firestore v1 service: strict gateway, local backend, `Write` / `Listen` streams, Rules enforcement, optional upstream proxy | tonic, tokio |
| `ftd-adapter-http` | Identity Toolkit REST subset (sign-up, password sign-in, custom claims, TOTP MFA, refresh, Admin SDK accounts) and the control API (clock, rules, capabilities) | hyper, tokio, serde_json |
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
