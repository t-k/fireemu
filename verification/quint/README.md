# Quint formal verification authority

This directory is the repository's formal verification authority. Fourteen bounded Quint models define the checked safety and liveness properties, and Quint Connect replays deterministic and generated traces against the production Rust state machines.

## Pinned tools

`package.json` pins Quint 0.32.0 and pnpm 10.32.1. `Cargo.toml` pins Quint Connect 0.1.2. `apalache.lock.json` pins the release URL and reviewed archive, launcher, and JAR digests for Apalache 0.56.1. Each Rust baseline or mutation command copies the verified Apalache JAR into a private directory, compiles the evidence-bound gRPC provider agent with a root-owned JDK, starts one OS-assigned IPv4 loopback endpoint, verifies that the child process owns exactly that listener, and retains an owner pipe until shutdown. The Java process clears inherited loader and Java injection variables and exits if its Rust owner disappears. The Python utilities use the fixed system interpreter in isolated mode only for installation and checker process-group cleanup; they do not select or attest the backend endpoint.

The authority trust boundary includes the native program loader, the fixed system shell and Python interpreter, the selected Rust toolchain, and the same-UID repository owner. Variables such as `LD_PRELOAD` and `LD_AUDIT` can execute native code before any script or Rust process can sanitize its environment; callers that do not trust their inherited native-loader environment must start the authority from an externally established clean environment. Backend isolation begins when the Rust verifier constructs its Java child with a cleared environment. The publication lock coordinates trusted same-UID repository processes and is not intended to defend evidence from the repository owner, who can already modify the bound sources.

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
- `FirestoreListenRefresh`
- `RegexAuthorization`
- `RegexEvaluationCache`
- `RegexLinearRepeat`
- `RulesetActivation`
- `SessionEpoch`
- `StorageGeneration`
- `TransactionConditionalLock`

Every descriptor binds its Quint specification, checker configuration, properties, semantic mutations, production sources, deterministic scenarios, and projection fields. Its Quint Connect driver dispatches model actions through production Rust APIs and compares the resulting production-derived projection after every action. Independent projection faults prove that each declared field can detect drift.

Generated conformance campaigns use the checked-in seeds `0x1`, `0x2`, `0x3`, and `0x4`. Deterministic scenarios cover the complete modeled action inventory. These traces supplement exhaustive bounded checking; neither replaces the other.

## Semantic mutations and evidence

Mutation manifests under `mutations/` use tool-neutral `M-FORMAL-*` identifiers. Each exact source replacement must match once, and every mutant must produce the expected safety or temporal counterexample. Parser, typechecker, translator, launch, timeout, and other tool failures never count as mutation kills.

Evidence under `evidence/` binds the model, checker configuration, mutation manifest, pinned toolchain, loopback provider source, Rust-owned server and publication policy, dedicated CI workflow, tool versions, properties, scenarios, action coverage, projection negative checks, seeds, bounds, and production sources. `cargo-authority.json` records only the locked normal dependency graph reachable from `fireemu-verification-quint`, with repository-relative workspace paths. Unrelated workspace dependencies, Cargo profiles, and CI jobs are intentionally outside this authority.

Refresh the complete evidence set only after every baseline, deterministic scenario, generated campaign, projection negative check, and real mutation campaign passes:

```sh
QUINT_REAL_BIN="$PWD/verification/quint/node_modules/.bin/quint" PATH="$PWD/verification/quint/bin:$PATH" VERIFICATION_PASSES=1 verification/quint/run-verification.sh --refresh
```

The refresh command generates the Cargo authority and all fourteen model documents in staging, validates traceability against that complete staged set, and replaces the checked-in evidence directory only after every gate passes. A failure or signal preserves the previous complete set. The JSON stores stable bounded classifications rather than checker timestamps or temporary paths. Any bound input change requires deliberate regeneration and review. When extracting or moving production semantics into a helper file, update every affected model's `production_sources` (or additional bound inputs) to include that helper and add a copied-input tamper regression. The inventory is explicit: it does not automatically follow Rust calls or imports. In particular, the Firestore commit, listener, and transaction models bind `value.rs` because storage normalization and stored-value equality determine document contents and change publication.
