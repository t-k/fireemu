//! std-only logical event state machine and outbox (spec 10).
//!
//! Owns `INV-EVENT-001` (no terminal regression) and the deterministic dispatch order. The
//! atomic commit + outbox publication (`INV-OUTBOX-001`) is composed by the Firestore and
//! Storage cores on top of this crate.

pub mod event;
pub mod outbox;
pub mod retry;
pub mod state;
