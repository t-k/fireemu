//! The debug-token exchange decision (specification section 10.1).
//!
//! The decision is deterministic and secret-free at the boundary: an unknown project, an
//! unknown app and an unknown secret all produce the same [`ExchangeOutcome::AttestationFailed`],
//! so the response body is not an enumeration oracle. The digest set is scanned to its fixed
//! capacity without an early exit, and an unknown app performs the equivalent dummy work. This
//! limits timing differences; it does not claim resistance to a local process-level side
//! channel.

use ftd_core_types::time::LogicalInstant;

use crate::claims::AppCheckClaims;
use crate::crypto::{ConstantTimeEq, DebugTokenHasher};
use crate::limits::MAX_DEBUG_TOKENS_PER_APP;
use crate::registry::{AppCheckRegistry, DebugTokenDigest};

/// One exchange request, already extracted from the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeRequest<'a> {
    /// The `{project}` path segment: the project ID or the project number.
    pub project_selector: &'a str,
    /// The `{appId}` path segment.
    pub app_id: &'a str,
    /// The `debugToken` body field, exactly as the client sent it.
    pub debug_token: &'a str,
    /// The `limitedUse` body field.
    pub limited_use: bool,
}

/// What the exchange decided (`Debug` goes through the claims' redaction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeOutcome {
    /// The secret matched a registered digest: these claims may be signed and returned.
    Issued(Box<AppCheckClaims>),
    /// Unknown project, unknown app, disabled app or unknown secret. One public error.
    AttestationFailed,
    /// `limitedUse: true`; replay protection is a separate capability.
    ReplayUnsupported,
}

/// Canonicalizes debug-token text to the lowercase hyphenated form that is hashed.
///
/// The input must be a `UUIDv4` in the canonical `8-4-4-4-12` form: hexadecimal case does not
/// change the credential, but nothing else is accepted. Registration and exchange share this
/// function, so a digest registered from `AB…` matches a secret presented as `ab…`.
#[must_use]
pub fn canonical_debug_token(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    for (i, b) in bytes.iter().enumerate() {
        let expect_hyphen = matches!(i, 8 | 13 | 18 | 23);
        if expect_hyphen {
            if *b != b'-' {
                return None;
            }
        } else if !b.is_ascii_hexdigit() {
            return None;
        }
    }
    // Version 4 and the RFC 4122 variant: a debug token is a UUIDv4.
    if bytes[14] != b'4' || !matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b') {
        return None;
    }
    Some(text.to_ascii_lowercase())
}

/// A digest that never matches, used for the dummy work of an unknown app.
const DUMMY_DIGEST: DebugTokenDigest = DebugTokenDigest::from_bytes([0u8; 32]);

/// Decides one exchange.
///
/// The work is the same shape whether or not the app exists: the presented secret is always
/// canonicalized and hashed, and the comparison always runs [`MAX_DEBUG_TOKENS_PER_APP`]
/// times.
#[must_use]
pub fn exchange(
    registry: &AppCheckRegistry,
    request: &ExchangeRequest<'_>,
    hasher: &dyn DebugTokenHasher,
    constant_time: &dyn ConstantTimeEq,
    now: LogicalInstant,
) -> ExchangeOutcome {
    if request.limited_use {
        return ExchangeOutcome::ReplayUnsupported;
    }
    let canonical = canonical_debug_token(request.debug_token);
    let presented = hasher.sha256(canonical.as_deref().unwrap_or("").as_bytes());

    let project = registry.resolve_project(request.project_selector);
    let app = project.and_then(|p| registry.app(p, request.app_id));
    let usable = app.is_some_and(crate::registry::RegisteredApp::enabled);
    let digests = app
        .map(crate::registry::RegisteredApp::digests)
        .unwrap_or_default();

    // Fixed-capacity scan without an early exit; an unknown app compares against the dummy.
    let mut matched = false;
    for slot in 0..MAX_DEBUG_TOKENS_PER_APP {
        let candidate = digests.get(slot).copied().unwrap_or(DUMMY_DIGEST);
        let equal = constant_time.eq(&presented, candidate.as_bytes());
        matched |= equal && slot < digests.len();
    }
    if !matched || !usable || canonical.is_none() {
        return ExchangeOutcome::AttestationFailed;
    }
    let Some(project) = project else {
        return ExchangeOutcome::AttestationFailed;
    };
    match registry.issue_claims(project, request.app_id, now) {
        Ok(claims) => ExchangeOutcome::Issued(Box::new(claims)),
        Err(_) => ExchangeOutcome::AttestationFailed,
    }
}
