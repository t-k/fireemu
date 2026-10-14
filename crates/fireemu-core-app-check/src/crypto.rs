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
/// This mirrors `fireemu_core_auth::jwt::IdTokenSigner` on purpose, but it is a separate trait for
/// a separate key: the App Check key belongs to the daemon instance and must never be the Auth
/// session key (section 7.2).
pub trait AppCheckSigner: Send + Sync {
    /// JOSE algorithm name (`RS256`).
    fn alg(&self) -> &'static str;
    /// Key ID carried in the token header. It begins with `fireemu-app-check-`.
    fn kid(&self) -> &str;
    /// The key ID if it is known without doing any work: a signer that generates its key on
    /// first use answers `None` until then. Showing a key ID must not be what generates it.
    fn kid_if_ready(&self) -> Option<&str> {
        Some(self.kid())
    }
    /// Signature over `header.payload`.
    fn sign(&self, signing_input: &[u8]) -> Vec<u8>;
    /// Whether `signature` is valid for `signing_input`.
    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool;
    /// The public key as a JWK (JSON text) for the local JWKS endpoint. Never private material.
    fn public_jwk_json(&self) -> String;
    /// Cached public-key fields, when the signer exposes a structured representation.
    #[must_use]
    fn public_jwk(&self) -> Option<&fireemu_core_auth::jwt::PublicJwk> {
        None
    }
}

impl fmt::Debug for dyn AppCheckSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppCheckSigner({} kid {})", self.alg(), self.kid())
    }
}

/// The prefix every local App Check key ID carries.
pub const KEY_ID_PREFIX: &str = "fireemu-app-check-";

#[cfg(test)]
mod tests {
    use super::AppCheckSigner;

    struct FixedKey;

    impl AppCheckSigner for FixedKey {
        fn alg(&self) -> &'static str {
            "RS256"
        }
        fn kid(&self) -> &'static str {
            "fireemu-app-check-0000000000000000"
        }
        fn sign(&self, _: &[u8]) -> Vec<u8> {
            Vec::new()
        }
        fn verify(&self, _: &[u8], _: &[u8]) -> bool {
            true
        }
        fn public_jwk_json(&self) -> String {
            "{}".to_owned()
        }
    }

    /// A signer that has its key at hand (every signer but the lazy one) answers its key ID
    /// without being asked to do any work.
    #[test]
    fn a_signer_that_does_not_override_kid_if_ready_has_its_key_ready() {
        assert_eq!(
            FixedKey.kid_if_ready(),
            Some("fireemu-app-check-0000000000000000")
        );
        assert_eq!(FixedKey.kid_if_ready(), Some(FixedKey.kid()));
    }
}
