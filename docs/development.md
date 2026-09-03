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
