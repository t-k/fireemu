# ADR-001: Core crates are std-only

- Status: accepted (2026-08-29)

## Decision

Every `ftd-core-*` crate has zero normal external dependencies, forbids `unsafe`, exposes no
async runtime types, never reads wall-clock time, thread-local RNGs or environment variables,
and returns typed errors instead of panicking on input. `HashMap` iteration order carries no
meaning; canonical output uses `BTreeMap` or explicit sorting.

## Consequences

- The core can be checked by Kani, Proptest, cargo-fuzz and mutation testing without I/O stubs.
- Anything that needs a dependency (JSON, protobuf, time zones, networking) lives in an
  adapter crate. `scripts/check-core-deps.sh` enforces the rule in CI.
- Convenience crates (error boxing, derive helpers, global singletons) are not admitted.
