//! std-only value types shared by every `firebase-testd` core crate.
//!
//! Rules for this crate (spec 6.1):
//!
//! - no normal dependencies;
//! - `unsafe` is forbidden;
//! - no wall-clock, thread-local RNG or environment access;
//! - errors are typed enums, never panics on input.

pub mod determinism;
pub mod edition;
pub mod ids;
pub mod time;
