//! std-only Firebase App Check core (specification `docs/specifications/firebase-app-check.md`).
//!
//! This crate owns every deterministic App Check decision and nothing else. Following ADR-001
//! it has no external dependencies, no I/O, no wall clock and no cryptographic primitive of its
//! own: SHA-256, constant-time comparison and RS256 signing are core-defined traits
//! ([`crypto`]) that the runtime shell implements with `sha2`, `subtle` and `rsa`.
//!
//! The pieces are:
//!
//! - [`registry`]: the project-scoped app registry, project epochs and debug-token digests;
//! - [`claims`]: the production-shaped token claims and their canonical JSON;
//! - [`jwt`]: compact-JWT encoding and splitting (base64url comes from `fireemu_core_auth::jwt`);
//! - [`verify`]: the verifier, the credential states and the admission decision;
//! - [`exchange`]: the debug-token exchange decision (constant-time, no early exit);
//! - [`header`]: the canonical, transport-neutral `X-Firebase-AppCheck` classification;
//! - [`observe`]: secret-free observations of classified requests.
//!
//! Milestone AC0 delivers `APPCHECK-CORE-1`, `APPCHECK-DEBUG-EXCHANGE-1` and
//! `APPCHECK-JWKS-1`. No Firebase product enforces App Check yet.

pub mod admission;
pub mod claims;
pub mod crypto;
pub mod exchange;
pub mod header;
pub mod jwt;
pub mod limits;
pub mod observe;
pub mod registry;
pub mod verify;

pub use admission::{AdmissionRequest, AppCheckGate, PrivilegedBypass, ServiceAdmission};
pub use claims::AppCheckClaims;
pub use crypto::{AppCheckSigner, ConstantTimeEq, DebugTokenHasher};
pub use exchange::{canonical_debug_token, ExchangeOutcome, ExchangeRequest};
pub use header::{classify_app_check_header, HeaderClassification, APP_CHECK_HEADER};
pub use observe::{CredentialCategory, Observation, ObservationCounterKey};
pub use registry::{
    AppCheckRegistry, AppRegistration, DebugTokenDigest, DebugTokenRecord, DynamicDebugTokens,
    ProjectEpoch, RegisteredApp, RegistryError,
};
pub use verify::{
    AdmissionDecision, AppCheckCredentialState, AppCheckFailure, AppIdentity, BaselineMode,
    TokenClass,
};
