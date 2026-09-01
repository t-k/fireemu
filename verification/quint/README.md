# EventDelivery Quint pilot

This directory is an additive pilot for replacing the EventDelivery TLA+ specification with Quint and Quint Connect. During the pilot, the existing files under `verification/tla` remain the sole formal authority. A successful Quint run is supporting evidence, not permission to remove or weaken the TLA+ checks.

## Pinned tools

`package.json` pins Quint 0.32.0 and pnpm 10.32.1. `Cargo.toml` pins Quint Connect 0.1.2. The pilot runner also requires Python 3 from the host to create an owned process group without third-party packages. Install the JavaScript dependency with:

```sh
pnpm -C verification/quint install --frozen-lockfile
```

The CI path invokes `bin/quint`, which requires an absolute `QUINT_REAL_BIN` and GNU `timeout`. The wrapper terminates the owned checker process group after the configured limit and maps timeout exits to status 124. On systems without GNU `timeout`, individual development tests may put `verification/quint/node_modules/.bin` directly on `PATH`; the CI evidence still uses the guarded wrapper.

Run one complete developer pass with:

```sh
QUINT_REAL_BIN="$PWD/verification/quint/node_modules/.bin/quint" PATH="$PWD/verification/quint/node_modules/.bin:$PATH" PILOT_PASSES=1 verification/quint/run-pilot.sh
```

## Model instances

`specs/EventDelivery.qnt` defines one parameterized model and three instances:

- `EventDeliveryProof` uses two events, three attempts, two epochs, and bounded logical time for exhaustive TLC checking.
- `EventDeliveryScenarios` uses one event and two attempts to replay success, retry timing, interruption, stale discard, and cancellation deterministically.
- `EventDeliveryConnect` uses two events and three attempts for generated implementation-conformance traces.

Quint Connect dispatches `Lease`, `Start`, `Succeed`, `Fail`, `RetryDue`, `Interrupt`, `Cancel`, `Tick`, `Reset`, and `DiscardStale` to the real Rust `EventRecord` API. After every action it compares lifecycle, attempts, maximum attempts, captured epoch, current epoch, terminal, cancelled, stale, logical time, retry deadline, base backoff, and maximum backoff. `Interrupt` gives the in-flight attempt back through the production API. The model independently checks the retry deadline, exponential delay, and maximum-delay cap against the real `RetryPolicy` result.

## Generated traces and mutations

CI replays 100 traces for each checked-in seed `0x1`, `0x2`, `0x3`, and `0x4`, with at most 20 actions per trace. A failure reports its seed. These generated traces supplement the five deterministic scenarios and TLC; they do not replace either.

Ten semantic source mutations use tool-neutral formal-verification IDs and cover lifecycle safety, liveness, interruption accounting, retry eligibility, exponential backoff, the delay cap, and monotonic time. Every replacement must match exactly once, and every mutant must produce the expected pinned TLC safety or temporal counterexample. Timeout, parser, typechecker, translator, launch, and other tool failures are not mutation kills.

## Evidence and regeneration

`evidence/EventDelivery.json` binds the model, TLC configuration, mutation manifest, package manifests, lockfiles, tool versions, properties, scenarios, action coverage, projection negative checks, seeds, bounds, and killed mutations. Regenerate it only after the baseline, deterministic scenarios, generated campaigns, projection negative checks, and real mutation campaign all pass:

```sh
cargo run -p fireemu-verification-quint -- mutate-model --model EventDelivery --evidence verification/quint/evidence/EventDelivery.json
cargo run -p fireemu-verification-quint -- verify-evidence --model EventDelivery
```

The JSON deliberately stores stable bounded classifications rather than checker timestamps or temporary paths. Any bound input change requires deliberate regeneration and review.

## Rollback

The pilot does not change the existing TLA+ model, trace fixtures, mutation evidence, or CI job. Rollback consists of removing `verification/quint`, its workspace member, and the dedicated `quint` CI job. Do not remove any `verification/tla` artifact as part of pilot rollback.
