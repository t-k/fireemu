# ADR-002: Async is used only in the runtime shell

- Status: accepted (2026-08-29)

## Decision

State transitions are synchronous functions on the core. Async I/O tasks never mutate state
directly; they call a synchronous command boundary. This keeps Loom and TLA+ models small and
lets the same core run under Kani and in-process fuzzers.
