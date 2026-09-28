# Mutation build isolation

Use the existing Cargo verification commands through `tools/compat-inventory/mutation_cargo.py` before compiling a changed source tree. Separate worktrees alone do not isolate Cargo's final or intermediate outputs.

```sh
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-inventory/mutation_cargo.py \
  --normal-workspace /absolute/normal-checkout \
  --mutation-workspace /absolute/mutation-checkout \
  --output-root /absolute/private-mutation-output \
  -- nextest run -p fireemu-adapter-http --test identity_toolkit
```

The entry resolves Cargo metadata for both normal shell builds and sanitized owned builds. It binds `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR` to separate directories under the mutation output root and checks the effective metadata again. Equal, nested, cross-purpose or symlink-resolved overlap is refused before compilation. User-supplied Cargo configuration/output/manifest overrides and aliases are refused. An older Cargo that cannot report both directories is not admitted. The distinction follows [Cargo's build-cache model](https://doc.rust-lang.org/cargo/reference/build-cache.html) and [metadata fields](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html).

Mutation outputs are marked `.fireemu-mutation-output`. Existing nonempty unmarked output is not adopted as a mutation cache. Normal `build_artifact()` checks both effective directories before invoking the compiler and checks the returned executable before adoption. The explicit `run_owned`/`--binary` path also rejects a marked artifact before creating a receipt or launching it. Markers and source restoration do not make a mutation binary a normal artifact: rebuild in normal output paths instead. Do not copy mutation binaries out of their marked tree or bypass the entry with raw Cargo commands.

Tests use real dependency-free Cargo workspaces to check configured intermediate directories, overlap, symlinks, overrides, executable rejection and a successful isolated compile. The shared guard is connected to the existing compatibility CI. These are local tool tests, not production observations. The historical failed build-cache result and all prior artifact identifiers remain unchanged.
