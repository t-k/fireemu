//! std-only value types shared by every `fireemu` core crate.
//!
//! Rules for this crate (spec 6.1):
//!
//! - no normal dependencies;
//! - `unsafe` is forbidden;
//! - no wall-clock, thread-local RNG or environment access;
//! - errors are typed enums, never panics on input.

pub mod codec;
pub mod determinism;
pub mod edition;
pub mod hash;
pub mod ids;
pub mod json;
pub mod time;
