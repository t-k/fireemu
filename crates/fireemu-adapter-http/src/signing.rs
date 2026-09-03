//! RS256 ID token signing with a session key (`auth.idTokenSigning = "session-rsa"`): a
//! 2048-bit RSA key derived deterministically from the session seed, `kid` from the public
//! modulus, and the JWKS the Admin SDK and JOSE libraries verify against.

use std::sync::Arc;

use fireemu_core_auth::jwt::{base64url_encode, IdTokenSigner, PublicJwk};
use rand_core::SeedableRng;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, SecretDocument};
use rsa::signature::{Keypair, SignatureEncoding, Signer, Verifier};
use rsa::traits::{PrivateKeyParts as _, PublicKeyParts};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// The session signer.
pub struct RsaSigner {
    signing: SigningKey<Sha256>,
    verifying: VerifyingKey<Sha256>,
    kid: String,
    jwk: PublicJwk,
}

impl RsaSigner {
    /// Derives the key from `seed` (the same seed gives the same key, so tokens stay
    /// reproducible across runs; a seed never identifies a production key).
    pub fn from_seed(seed: u64) -> Result<Arc<Self>, String> {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let key = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("RSA key: {e}"))?;
        Ok(Self::from_private_key(key))
    }

    /// Restores a deterministic session key from validated PKCS#8 DER cache material.
    ///
    /// The caller must keep the bytes owner-only and clear them after use. App Check keys never
    /// use this path.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Arc<Self>, String> {
        let key = RsaPrivateKey::from_pkcs8_der(der).map_err(|_| "invalid RSA key".to_owned())?;
        key.validate().map_err(|_| "invalid RSA key".to_owned())?;
        if key.n().bits() != 2048
            || key.e() != &rsa::BigUint::from(65_537_u32)
            || key.primes().len() != 2
        {
            return Err("invalid RSA key parameters".to_owned());
        }
        Ok(Self::from_private_key(key))
    }

    /// Serialises the session key for the owner-only cache.
    ///
    /// The returned document zeroizes its secret bytes when dropped. It must never be logged,
    /// exported, or committed. App Check keys deliberately expose no equivalent method.
    pub fn to_pkcs8_der(&self) -> Result<SecretDocument, String> {
        self.signing
            .to_pkcs8_der()
            .map_err(|_| "cannot encode RSA key".to_owned())
    }

    fn from_private_key(key: RsaPrivateKey) -> Arc<Self> {
        let n = key.n().to_bytes_be();
        let e = key.e().to_bytes_be();
        let digest = Sha256::digest(&n);
        let kid = digest.iter().take(8).fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        let jwk = PublicJwk {
            kty: "RSA",
            alg: "RS256",
            usage: "sig",
            kid: kid.clone(),
            modulus: base64url_encode(&n),
            exponent: base64url_encode(&e),
        };
        let signing = SigningKey::<Sha256>::new(key);
        let verifying = signing.verifying_key();
        Arc::new(Self {
            signing,
            verifying,
            kid,
            jwk,
        })
    }

    /// The JWKS document (`{"keys": [...]}`).
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({"keys": [jwk_value(&self.jwk)]})
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
        jwk_value(&self.jwk).to_string()
    }

    fn public_jwk(&self) -> Option<&PublicJwk> {
        Some(&self.jwk)
    }
}

// ------------------------------------------------------------------------------------------
// App Check (specification section 7.2): a dedicated key per daemon instance
// ------------------------------------------------------------------------------------------

/// Where the App Check signing key comes from.
///
/// The daemon always uses [`AppCheckKeySource::OperatingSystem`]:
/// `appCheck.tokenSigning = "instance-rsa"` means the key belongs to the instance, not to the
/// reproducible session seed, so two normally started daemons never accept each other's
/// tokens. [`AppCheckKeySource::Seed`] exists only so that focused tests can reproduce a key;
/// it is unreachable from canonical configuration and from production-like CLI startup, and is
/// injected through the constructor instead of a `RuntimeConfig` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppCheckKeySource {
    /// The operating system CSPRNG.
    OperatingSystem,
    /// A fixed seed. Tests only.
    Seed(u64),
}

/// Domain separator for the seeded variant, so one seed never derives both the Auth session
/// key and the App Check key.
const APP_CHECK_DOMAIN: u64 = 0x4150_5043_4845_434B; // "APPCHECK"

/// The private half of the App Check key.
///
/// There is no derived `Debug`: the wrapper prints a redaction, so private material cannot
/// reach a trace, a log, a panic message or a snapshot (`INV-APPCHECK-004`). The `rsa` crate
/// zeroizes the key material itself when the value is dropped.
struct AppCheckPrivateKey(SigningKey<Sha256>);

impl std::fmt::Debug for AppCheckPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppCheckPrivateKey([redacted])")
    }
}

/// The daemon instance's App Check signer.
pub struct AppCheckRsaSigner {
    signing: AppCheckPrivateKey,
    verifying: VerifyingKey<Sha256>,
    kid: String,
    jwk: PublicJwk,
}

impl std::fmt::Debug for AppCheckRsaSigner {
    // The public modulus and exponent are deliberately not rendered: the key ID identifies the
    // key, and everything else belongs in the JWKS response, not in a debug line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppCheckRsaSigner")
            .field("kid", &self.kid)
            .field("signing", &self.signing)
            .finish_non_exhaustive()
    }
}

impl AppCheckRsaSigner {
    /// Generates the instance key. Key generation is CPU-bound, so the daemon runs it on a
    /// blocking task, concurrently with the Auth session key when both are enabled.
    pub fn generate(source: AppCheckKeySource) -> Result<Arc<Self>, String> {
        let seed = match source {
            AppCheckKeySource::OperatingSystem => os_entropy()?,
            AppCheckKeySource::Seed(seed) => derived_seed(seed),
        };
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("App Check RSA key: {e}"))?;
        let n = key.n().to_bytes_be();
        let e = key.e().to_bytes_be();
        let digest = Sha256::digest(&n);
        let kid = digest.iter().take(8).fold(
            String::from(fireemu_core_app_check::crypto::KEY_ID_PREFIX),
            |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{b:02x}");
                acc
            },
        );
        let signing = SigningKey::<Sha256>::new(key);
        let verifying = signing.verifying_key();
        let jwk = PublicJwk {
            kty: "RSA",
            alg: "RS256",
            usage: "sig",
            kid: kid.clone(),
            modulus: base64url_encode(&n),
            exponent: base64url_encode(&e),
        };
        Ok(Arc::new(Self {
            signing: AppCheckPrivateKey(signing),
            verifying,
            kid,
            jwk,
        }))
    }

    /// The JWKS document (`{"keys": [...]}`) served at `/v1/jwks`. Public material only.
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({"keys": [jwk_value(&self.jwk)]})
    }
}

impl fireemu_core_app_check::crypto::AppCheckSigner for AppCheckRsaSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        self.signing.0.sign(signing_input).to_vec()
    }

    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        Signature::try_from(signature)
            .map(|s| self.verifying.verify(signing_input, &s).is_ok())
            .unwrap_or(false)
    }

    fn public_jwk_json(&self) -> String {
        jwk_value(&self.jwk).to_string()
    }

    fn public_jwk(&self) -> Option<&PublicJwk> {
        Some(&self.jwk)
    }
}

pub(crate) fn jwk_value(jwk: &PublicJwk) -> serde_json::Value {
    serde_json::json!({
        "kty": jwk.kty,
        "alg": jwk.alg,
        "use": jwk.usage,
        "kid": jwk.kid,
        "n": jwk.modulus,
        "e": jwk.exponent,
    })
}

/// 32 bytes from the operating system's entropy source. The daemon refuses to start without
/// one rather than falling back to a predictable key.
fn os_entropy() -> Result<[u8; 32], String> {
    use std::io::Read as _;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("cannot read /dev/urandom for the App Check key: {e}"))?;
    Ok(bytes)
}

/// The seeded variant, mixed with the App Check domain separator.
fn derived_seed(seed: u64) -> [u8; 32] {
    use fireemu_core_types::determinism::DeterministicRng as _;
    let mut rng = fireemu_core_types::determinism::SplitMix64::new(seed ^ APP_CHECK_DOMAIN);
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_be_bytes());
    }
    bytes
}

/// SHA-256 for debug-token digests.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256DebugTokenHasher;

impl fireemu_core_app_check::crypto::DebugTokenHasher for Sha256DebugTokenHasher {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        Sha256::digest(input).into()
    }
}

/// Constant-time byte comparison from `subtle`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SubtleConstantTimeEq;

impl fireemu_core_app_check::crypto::ConstantTimeEq for SubtleConstantTimeEq {
    fn eq(&self, a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq as _;
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }
}

/// A source of raw debug secrets for the privileged management routes.
pub trait DebugSecretSource: Send + Sync {
    /// A fresh canonical lowercase hyphenated `UUIDv4`.
    fn new_uuid_v4(&self) -> Result<String, String>;
}

/// Debug secrets from the operating system CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsDebugSecrets;

impl DebugSecretSource for OsDebugSecrets {
    fn new_uuid_v4(&self) -> Result<String, String> {
        let bytes = os_entropy()?;
        Ok(uuid_v4_from(&bytes[..16]))
    }
}

/// Formats 16 random bytes as a canonical `UUIDv4` (version 4, RFC 4122 variant).
fn uuid_v4_from(bytes: &[u8]) -> String {
    let mut b = [0u8; 16];
    b.copy_from_slice(&bytes[..16]);
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let hex = |slice: &[u8]| {
        slice.iter().fold(String::new(), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}
