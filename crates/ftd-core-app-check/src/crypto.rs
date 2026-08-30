//! The cryptographic seams (specification sections 7.1 and 25.2).
//!
//! No primitive is implemented here. The core defines what it needs and the runtime shell
//! supplies it: `sha2` for [`DebugTokenHasher`], `subtle` for [`ConstantTimeEq`] and `rsa` for
//! [`AppCheckSigner`]. The Rules `hashing` namespace is deliberately not reused: it declares
//! itself unsuitable for runtime collision resistance.

use core::fmt;

/// SHA-256 over the canonical debug-token text.
///
/// The input is always the lowercase hyphenated `UUIDv4` produced by
/// [`crate::exchange::canonical_debug_token`], so hexadecimal case never changes the
/// credential.
pub trait DebugTokenHasher: Send + Sync {
    /// The SHA-256 digest of `input`.
    fn sha256(&self, input: &[u8]) -> [u8; 32];
}

/// Constant-time equality of two byte strings.
///
/// The implementation must not return early on the first differing byte, and must not leak the
/// comparison result through a branch. Lengths may differ; unequal lengths compare unequal.
pub trait ConstantTimeEq: Send + Sync {
    /// Whether `a` and `b` are equal, compared in constant time for equal lengths.
    fn eq(&self, a: &[u8], b: &[u8]) -> bool;
}

/// Signs and verifies App Check session tokens (`RS256`).
///
/// This mirrors `ftd_core_auth::jwt::IdTokenSigner` on purpose, but it is a separate trait for
/// a separate key: the App Check key belongs to the daemon instance and must never be the Auth
/// session key (section 7.2).
pub trait AppCheckSigner: Send + Sync {
    /// JOSE algorithm name (`RS256`).
    fn alg(&self) -> &'static str;
    /// Key ID carried in the token header. It begins with `ftd-app-check-`.
    fn kid(&self) -> &str;
    /// Signature over `header.payload`.
    fn sign(&self, signing_input: &[u8]) -> Vec<u8>;
    /// Whether `signature` is valid for `signing_input`.
    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool;
    /// The public key as a JWK (JSON text) for the local JWKS endpoint. Never private material.
    fn public_jwk_json(&self) -> String;
}

impl fmt::Debug for dyn AppCheckSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppCheckSigner({} kid {})", self.alg(), self.kid())
    }
}

/// The prefix every local App Check key ID carries.
pub const KEY_ID_PREFIX: &str = "ftd-app-check-";
