//! std-only session, epoch, virtual clock and idle fence state machine.
//!
//! This crate owns the concurrency-critical invariants `INV-EPOCH-001`, `INV-IDLE-001` and
//! `INV-TIME-001`. It is deliberately small so that Loom scenarios (`verification/loom`) and
//! the TLA+ models `SessionEpoch.tla` / `AwaitIdle.tla` can cover it completely.

pub mod clock;
pub mod idle;
pub mod session;
