//! Compact-JWT encoding and splitting for App Check tokens (specification section 11.1-11.3).
//!
//! Base64url is not reimplemented here: `ftd_core_auth::jwt` already carries the unpadded
//! RFC 7515 codec that the Auth tokens use, and one codec with one set of tests is better than
//! two. Everything above it (the header, the three-segment split, the strict order of checks)
//! is App Check specific and lives here.

pub use ftd_core_auth::jwt::base64url_encode;

use crate::claims::AppCheckClaims;
use crate::crypto::AppCheckSigner;
use crate::verify::AppCheckFailure;

/// Decodes unpadded base64url, mapping every rejection to [`AppCheckFailure::Malformed`].
pub fn base64url_decode(text: &str) -> Result<Vec<u8>, AppCheckFailure> {
    ftd_core_auth::jwt::base64url_decode(text).map_err(|_| AppCheckFailure::Malformed)
}

/// The three segments of a compact JWT, still encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactJwt<'a> {
    /// Encoded JOSE header.
    pub header: &'a str,
    /// Encoded payload.
    pub payload: &'a str,
    /// Encoded signature.
    pub signature: &'a str,
}

impl CompactJwt<'_> {
    /// The bytes the signature covers: `header.payload`.
    #[must_use]
    pub fn signing_input(&self) -> String {
        format!("{}.{}", self.header, self.payload)
    }
}

/// Splits a compact JWT into exactly three non-empty segments.
///
/// Two segments, four segments, an empty segment and a trailing dot are all
/// [`AppCheckFailure::Malformed`]; a local App Check token is always signed, so an empty
/// signature never reaches signature verification.
pub fn split_compact(token: &str) -> Result<CompactJwt<'_>, AppCheckFailure> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else {
        return Err(AppCheckFailure::Malformed);
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(AppCheckFailure::Malformed);
    }
    Ok(CompactJwt {
        header,
        payload,
        signature,
    })
}

/// Encodes signed claims: `{"alg":"RS256","kid":"...","typ":"JWT"}` and the canonical payload.
#[must_use]
pub fn encode(claims: &AppCheckClaims, signer: &dyn AppCheckSigner) -> String {
    let header = format!(
        r#"{{"alg":"{}","kid":"{}","typ":"JWT"}}"#,
        signer.alg(),
        signer.kid()
    );
    let signing_input = format!(
        "{}.{}",
        base64url_encode(header.as_bytes()),
        base64url_encode(claims.canonical_json().as_bytes())
    );
    let signature = signer.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", base64url_encode(&signature))
}
