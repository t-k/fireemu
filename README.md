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

Milestone A (verification-ready core) is in progress. Nothing here serves network traffic yet.

| Crate | Purpose | Dependencies |
|---|---|---|
| `ftd-core-types` | validated identifiers, logical time, edition capabilities, deterministic adapters | none |
| `ftd-core-limits` | versioned limit catalogs and the warning / rejection engine | none |
| `ftd-core-session` | session lifecycle, epoch isolation, virtual clock, idle ledger | none |
| `ftd-core-events` | event state machine, retry policy, outbox | none |

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
RUSTFLAGS="--cfg loom" cargo test -p ftd-verification-loom --release
TLA2TOOLS_JAR=/path/to/tla2tools.jar verification/tla/run-tlc.sh
```

TLC needs Java 21 and TLA+ Tools 1.8.0
(`sha256 eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a`).
Kani harnesses live in `verification/kani` and run with `cargo kani`.

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
