# Development

## Isolated Cargo builds

Concurrent agent sessions in the same checkout must not share Cargo artifacts. Run Cargo through the session wrapper with a short stable identifier:

```sh
scripts/cargo-session --session parser-fix -- cargo check -p fireemu-core-rules
scripts/cargo-session --session parser-fix -- cargo nextest run -p fireemu-core-rules
```

The wrapper places artifacts in `target/agent/<session>/normal`. It rejects an existing `CARGO_TARGET_DIR` so an inherited environment cannot silently redirect several sessions into one directory. Worktrees already have independent repository-local `target` directories, but the wrapper also protects two writers using the same checkout.

Modes that change compiler flags use independent artifacts. Loom runs use the dedicated mode:

```sh
scripts/cargo-session --session concurrency --mode loom -- cargo test -p fireemu-verification-loom --release
```

The wrapper preserves existing `RUSTFLAGS` and appends `--cfg loom`. Do not use CI's `RUSTFLAGS=-D warnings` in local commands; workspace lint configuration already enforces repository warnings.

Use the default nextest profile for a focused inner loop. It stops after the first failure and does not pay the pull-request profile's process-leak observation period:

```sh
scripts/cargo-session --session parser-fix -- cargo nextest run -p fireemu-core-rules
```

Use `cargo nextest run --workspace --profile pr` as the full local gate. Do not add `--test-threads=1`; tests that require serialization must declare a nextest test group instead of disabling parallelism for the suite.

## Local regression gate

The automatic pull-request job formats and compiles every target with `cargo check`; it runs no test, so a green pull-request status is not evidence that the runtime behaves. Runtime tests run locally and on the manual `workflow_dispatch` jobs. To record a local run as evidence, run nextest through the gate:

```sh
scripts/local-regression-gate --session compat --report docs.local/gates/compat.json -- -p fireemu-core-firestore -p fireemu-adapter-grpc
```

The gate runs `cargo nextest run --profile pr` (choose another profile with `--profile`) through `scripts/cargo-session` and writes a JSON report naming the commit, whether the tree was dirty, the profile, the arguments, the nextest and rustc versions, and the counts of tests run, passed, failed and skipped. It exits non-zero when a test fails, when cargo-nextest is not installed (`missing-dependency`) and when no test ran (`no-tests`), so an empty filter or a missing tool is never recorded as a pass. Cite the report, not the exit status, in work logs and issue closures. `scripts/local-regression-gate.test.sh` is its self-test.

## Post-pressure recovery harness

`crates/fireemu/tests/recovery.rs` drives a real daemon through four phases (baseline, saturate, release, reuse) and samples what it retains after each: the logical Firestore charge and version count from `GET /v1/sessions/default/resources`, the retained snapshot bytes, the session count, and the process RSS, open file descriptors and child processes. The verdict is about retention, not speed: every logical gauge must return to its baseline after the release, and the reuse phase must be fully admitted and charge the store again. RSS is recorded but never asserted, because an allocator cache keeps it high after the logical charge is gone. A measurement that fails is recorded as missing with its reason and fails the verdict; it is never written as zero. The test also holds a snapshot across one release on purpose and checks that the verdict names it as a leak.

```sh
cargo nextest run -p fireemu --test recovery
FIREEMU_RECOVERY_LONG=1 FIREEMU_RECOVERY_REPORT=docs.local/recovery/$(git rev-parse --short HEAD).json cargo nextest run -p fireemu --test recovery
```

Every run writes a JSON artifact (under the target tmpdir unless `FIREEMU_RECOVERY_REPORT` names a file) with the commit, dirty state, machine, toolchain, build profile, dataset, per-phase samples, verdict and the cleanup result. Compare runs only when the profile, dataset and machine match. The long dataset is opt-in and not part of any automatic job.

## Inspecting a running daemon

`fireemu doctor` stays offline. `fireemu doctor --connect http://127.0.0.1:<control port>` adds what the running daemon retains for the default session, read from `GET /v1/sessions/default/resources`: every gauge with its measure (`logical`, `estimate` or `process`), current value, limit and reclaimable part, the refused admissions, and the outstanding retention roots. Only a loopback control URL is accepted. The same report drives the Runtime page of the UI and the `resources:assertQuiescent` assertion tests use.

## Removing stale artifacts

After renaming a crate, clean every session target that built the old name before continuing. Resolve and clean one exact target at a time:

```sh
target_dir=$(scripts/cargo-session --session parser-fix --print-target-dir)
cargo clean --target-dir "$target_dir"
```

For periodic pruning, `cargo-sweep` may be used as an optional local maintenance tool. Always inspect the selected files first, run it only from the intended worktree, and use a bounded age:

```sh
cargo sweep --dry-run --time 7
cargo sweep --time 7
```

Do not run recursive pruning over a parent that contains active worktrees. The repository does not install or invoke `cargo-sweep` automatically.

If an unexpectedly warm build spends more system CPU time than user CPU time, first inspect free disk space, count the directories under the exact target's `debug/incremental` directory, and check for another Cargo process using that target. On macOS, a stalled security assessment process can also delay newly linked binaries; inspect the process state before attributing the delay to the compiler.

The default Cargo development profile retains line tables for workspace crates while omitting dependency debug information. Use `--profile debugging` when full debug information is required; it has a separate artifact identity.

## Emulator UI size report

`pnpm -C ui build` writes Vite's build manifest to `ui/dist/.vite/manifest.json`; the daemon does not embed that directory. The size report reads it to separate the initial bundle (the entry and its static imports) from route chunks loaded on demand and chunks several routes share, counts every emitted file once, and compresses with fixed gzip and Brotli settings:

```sh
pnpm -C ui build
pnpm -C ui size --out .runs/size-report.json
pnpm -C ui size --out .runs/size-report.json --baseline .runs/previous.json
```

The report records the commit (with a `-dirty` suffix when `ui/` has uncommitted changes), the Node and Vite versions and the host platform, and never an absolute path or environment variable. Record a release binary next to the bundle with `--binary <path> --target <triple> --profile <name> [--features a,b]`; a comparison refuses reports whose compression settings, binary target, profile or features differ, so a number measured on another platform is never shown as a trend. `ui/.runs/` is ignored by git; keep baselines you want to compare against under `docs.local/`.

