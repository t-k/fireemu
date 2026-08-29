//! std-only Firebase Auth / Identity Platform core (spec 12A, Milestone H0).
//!
//! Users, custom claims, ID token claims and the TOTP second factor with replay protection on
//! the virtual clock. SHA-1 / HMAC / base32 are implemented in-crate with RFC vectors so that
//! the core stays dependency-free (ADR-001). Token signing is an adapter concern.

pub mod base32;
pub mod claims;
pub mod mfa;
pub mod sha1;
pub mod store;
pub mod totp;
