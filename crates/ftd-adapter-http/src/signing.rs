//! RS256 ID token signing with a session key (`auth.idTokenSigning = "session-rsa"`): a
//! 2048-bit RSA key derived deterministically from the session seed, `kid` from the public
//! modulus, and the JWKS the Admin SDK and JOSE libraries verify against.

use std::sync::Arc;

use ftd_core_auth::jwt::{base64url_encode, IdTokenSigner};
use rand_core::SeedableRng;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{Keypair, SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// The session signer.
pub struct RsaSigner {
    signing: SigningKey<Sha256>,
    verifying: VerifyingKey<Sha256>,
    kid: String,
    n: Vec<u8>,
    e: Vec<u8>,
}

impl RsaSigner {
    /// Derives the key from `seed` (the same seed gives the same key, so tokens stay
    /// reproducible across runs; a seed never identifies a production key).
    pub fn from_seed(seed: u64) -> Result<Arc<Self>, String> {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let key = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("RSA key: {e}"))?;
        let n = key.n().to_bytes_be();
        let e = key.e().to_bytes_be();
        let digest = Sha256::digest(&n);
        let kid = digest.iter().take(8).fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        let signing = SigningKey::<Sha256>::new(key);
        let verifying = signing.verifying_key();
        Ok(Arc::new(Self {
            signing,
            verifying,
            kid,
            n,
            e,
        }))
    }

    /// The JWKS document (`{"keys": [...]}`).
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        let key: serde_json::Value =
            serde_json::from_str(&self.public_jwk_json()).unwrap_or_default();
        serde_json::json!({"keys": [key]})
    }
}

impl IdTokenSigner for RsaSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        self.signing.sign(signing_input).to_vec()
    }

    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        Signature::try_from(signature)
            .map(|s| self.verifying.verify(signing_input, &s).is_ok())
            .unwrap_or(false)
    }

    fn public_jwk_json(&self) -> String {
        serde_json::json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": self.kid,
            "n": base64url_encode(&self.n),
            "e": base64url_encode(&self.e),
        })
        .to_string()
    }
}
