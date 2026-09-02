# Quint formal verification authority

This directory is the repository's formal verification authority. Twelve bounded Quint models define the checked safety and liveness properties, and Quint Connect replays deterministic and generated traces against the production Rust state machines.

## Pinned tools

`package.json` pins Quint 0.32.0 and pnpm 10.32.1. `Cargo.toml` pins Quint Connect 0.1.2. `apalache.lock.json` pins the release URL and reviewed archive, launcher, and JAR digests for Apalache 0.56.1. The verification runner also requires Java for Quint's TLC backend and Python 3 to install the backend safely, serialize the fixed translation endpoint, and create owned process groups.

Install the JavaScript dependency with:

```sh
pnpm -C verification/quint install --frozen-lockfile
QUINT_HOME="$HOME/.quint" verification/quint/bin/install-apalache
```

The CI path invokes `bin/quint`, which requires an absolute `QUINT_REAL_BIN` and GNU `timeout`. The wrapper terminates the owned checker process group after the configured limit and maps timeout exits to status 124. Install GNU Coreutils and make its `timeout` command available on `PATH` before running the complete authority pass. Individual development tests may invoke the pinned real CLI directly, but the complete authority pass must use the guarded wrapper.

Run one complete authority pass with:

```sh
QUINT_REAL_BIN="$PWD/verification/quint/node_modules/.bin/quint" PATH="$PWD/verification/quint/bin:$PATH" VERIFICATION_PASSES=1 verification/quint/run-verification.sh
```

## Models and production conformance

The registry in `src/model.rs` is the single inventory for these authority models:

- `AtomicCommitOutbox`
- `AtomicExportPublication`
- `AuthTotp`
- `AwaitIdle`
- `CompatibilitySelection`
- `EventDelivery`
- `RegexAuthorization`
- `RegexLinearRepeat`
- `RulesetActivation`
- `SessionEpoch`
- `StorageGeneration`
- `TransactionConditionalLock`

Every descriptor binds its Quint specification, checker configuration, properties, semantic mutations, production sources, deterministic scenarios, and projection fields. Its Quint Connect driver dispatches model actions through production Rust APIs and compares the resulting production-derived projection after every action. Independent projection faults prove that each declared field can detect drift.

Generated conformance campaigns use the checked-in seeds `0x1`, `0x2`, `0x3`, and `0x4`. Deterministic scenarios cover the complete modeled action inventory. These traces supplement exhaustive bounded checking; neither replaces the other.

## Semantic mutations and evidence

Mutation manifests under `mutations/` use tool-neutral `M-FORMAL-*` identifiers. Each exact source replacement must match once, and every mutant must produce the expected safety or temporal counterexample. Parser, typechecker, translator, launch, timeout, and other tool failures never count as mutation kills.

Evidence under `evidence/` binds the model, checker configuration, mutation manifest, package manifests, lockfiles, tool versions, properties, scenarios, action coverage, projection negative checks, seeds, bounds, and production sources. Regenerate a model only after its baseline, deterministic scenarios, generated campaigns, projection negative checks, and real mutation campaign pass:

```sh
cargo run -p fireemu-verification-quint -- mutate-model --model EventDelivery --evidence verification/quint/evidence/EventDelivery.json
cargo run -p fireemu-verification-quint -- verify-evidence --model EventDelivery
```

The JSON stores stable bounded classifications rather than checker timestamps or temporary paths. Any bound input change requires deliberate regeneration and review.
