//! Verification of signed custom tokens against configured service-account keys
//! (`auth.customTokenSigners`).
//!
//! Production accepts a custom token only when it is an RS256 JWT signed by a service account
//! whose Google-held key verifies the signature, and refuses a correctly signed token of a
//! service account that belongs to another project with `CREDENTIAL_MISMATCH`. fireemu cannot
//! hold Google's keys, so the public keys a deployment trusts are supplied in configuration.
//! With no signer configured this module is not consulted and the unsigned tokens the Admin SDK
//! mints in emulator mode keep working.

use std::collections::BTreeMap;

use fireemu_core_auth::jwt::base64url_decode;
use fireemu_core_types::json::{self as ejson, JsonValue};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use sha2::Sha256;

/// Production's refusal of a token that is not a compact JWT (sandbox recording 2026-09-24).
pub const INVALID_ASSERTION_FORMAT: &str =
    "INVALID_CUSTOM_TOKEN : Invalid assertion format. 3 dot separated segments required.";

/// Why a custom token was refused before its claims were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomTokenRefusal {
    /// Not three dot-separated segments.
    Format,
    /// No signature segment.
    MissingSignature,
    /// Not a signed RS256 JWT of a trusted signer, or the signature does not verify.
    Invalid,
    /// Correctly signed by a service account of another project.
    CredentialMismatch,
}

impl CustomTokenRefusal {
    /// The Identity Toolkit error message.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Format => INVALID_ASSERTION_FORMAT,
            Self::MissingSignature => "INVALID_CUSTOM_TOKEN : Missing signature.",
            Self::Invalid => "INVALID_CUSTOM_TOKEN",
            Self::CredentialMismatch => "CREDENTIAL_MISMATCH",
        }
    }
}

struct TrustedKey {
    kid: Option<String>,
    key: VerifyingKey<Sha256>,
}

/// The service accounts whose custom tokens this project accepts, with their public keys.
pub struct CustomTokenTrust {
    signers: BTreeMap<String, Vec<TrustedKey>>,
}

impl std::fmt::Debug for CustomTokenTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomTokenTrust")
            .field("signers", &self.signers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The project a service-account address belongs to: `name@<project>.iam.gserviceaccount.com`
/// or the App Engine default `<project>@appspot.gserviceaccount.com`.
#[must_use]
pub fn service_account_project(address: &str) -> Option<&str> {
    let (local, domain) = address.split_once('@')?;
    if let Some(project) = domain.strip_suffix(".iam.gserviceaccount.com") {
        return (!project.is_empty()).then_some(project);
    }
    (domain == "appspot.gserviceaccount.com" && !local.is_empty()).then_some(local)
}

impl CustomTokenTrust {
    /// Builds the trust from `{ "<service account>": { "keys": [<RSA JWK>, ...] } }`, the shape
    /// Google publishes at `service_accounts/v1/jwk/<service account>`.
    ///
    /// # Errors
    /// A message naming the first entry that is not a service-account address or not a JWK set
    /// of RS256 RSA public keys.
    pub fn from_jwks(signers: &serde_json::Map<String, serde_json::Value>) -> Result<Self, String> {
        let mut out = BTreeMap::new();
        for (account, jwks) in signers {
            if service_account_project(account).is_none() {
                return Err(format!("{account:?} is not a service-account address"));
            }
            let keys = jwks
                .get("keys")
                .and_then(serde_json::Value::as_array)
                .filter(|keys| !keys.is_empty())
                .ok_or_else(|| format!("{account}: expected a JWK set with at least one key"))?;
            let mut trusted = Vec::with_capacity(keys.len());
            for key in keys {
                trusted.push(parse_jwk(key).map_err(|e| format!("{account}: {e}"))?);
            }
            out.insert(account.clone(), trusted);
        }
        Ok(Self { signers: out })
    }

    /// Verifies `token` for `project` and returns its claims.
    ///
    /// # Errors
    /// [`CustomTokenRefusal::Invalid`] for anything but a verifying RS256 token of a trusted
    /// signer; [`CustomTokenRefusal::CredentialMismatch`] for a verifying token of a service
    /// account of another project.
    pub fn verify(&self, token: &str, project: &str) -> Result<JsonValue, CustomTokenRefusal> {
        let parts: Vec<&str> = token.split('.').collect();
        let [header_b64, payload_b64, signature_b64] = parts.as_slice() else {
            return Err(CustomTokenRefusal::Format);
        };
        // The algorithm is judged before the signature's presence: an `alg: none` token is
        // plainly invalid, an RS256 one without a signature is missing it (sandbox recording
        // 2026-09-24).
        let header = decode_object(header_b64)?;
        if header.get("alg").and_then(JsonValue::as_str) != Some("RS256") {
            return Err(CustomTokenRefusal::Invalid);
        }
        if signature_b64.is_empty() {
            return Err(CustomTokenRefusal::MissingSignature);
        }
        let claims = decode_object(payload_b64)?;
        let issuer = claims
            .get("iss")
            .and_then(JsonValue::as_str)
            .ok_or(CustomTokenRefusal::Invalid)?;
        let keys = self
            .signers
            .get(issuer)
            .ok_or(CustomTokenRefusal::Invalid)?;
        let signature = base64url_decode(signature_b64)
            .ok()
            .and_then(|bytes| Signature::try_from(bytes.as_slice()).ok())
            .ok_or(CustomTokenRefusal::Invalid)?;
        let kid = header.get("kid").and_then(JsonValue::as_str);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let verified = keys
            .iter()
            .filter(|k| kid.is_none() || k.kid.is_none() || k.kid.as_deref() == kid)
            .any(|k| k.key.verify(signing_input.as_bytes(), &signature).is_ok());
        if !verified {
            return Err(CustomTokenRefusal::Invalid);
        }
        if service_account_project(issuer) != Some(project) {
            return Err(CustomTokenRefusal::CredentialMismatch);
        }
        Ok(claims)
    }
}

fn decode_object(part: &str) -> Result<JsonValue, CustomTokenRefusal> {
    let bytes = base64url_decode(part).map_err(|_| CustomTokenRefusal::Invalid)?;
    let text = String::from_utf8(bytes).map_err(|_| CustomTokenRefusal::Invalid)?;
    match ejson::parse(&text) {
        Ok(value @ JsonValue::Object(_)) => Ok(value),
        _ => Err(CustomTokenRefusal::Invalid),
    }
}

fn parse_jwk(key: &serde_json::Value) -> Result<TrustedKey, String> {
    let field = |name: &str| key.get(name).and_then(serde_json::Value::as_str);
    if field("kty") != Some("RSA") {
        return Err("every key must have kty RSA".to_owned());
    }
    if field("alg").is_some_and(|alg| alg != "RS256") {
        return Err("every key must be an RS256 key".to_owned());
    }
    let component = |name: &str| {
        field(name)
            .and_then(|text| base64url_decode(text).ok())
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| BigUint::from_bytes_be(&bytes))
            .ok_or_else(|| format!("every key needs a base64url {name}"))
    };
    let public = RsaPublicKey::new(component("n")?, component("e")?)
        .map_err(|_| "an RSA public key is not valid".to_owned())?;
    // Google signs custom tokens with 2048-bit keys; a shorter key is a configuration mistake.
    if public.n().bits() < 2048 {
        return Err("every RSA key must be at least 2048 bits".to_owned());
    }
    Ok(TrustedKey {
        kid: field("kid").map(str::to_owned),
        key: VerifyingKey::<Sha256>::new(public),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_core_auth::jwt::base64url_encode;
    use rand_core::SeedableRng;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;

    const PROJECT: &str = "demo-project";
    const OWN: &str = "firebase-adminsdk-x@demo-project.iam.gserviceaccount.com";
    const OTHER: &str = "robot@other-project.iam.gserviceaccount.com";

    fn key(seed: u64) -> RsaPrivateKey {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        RsaPrivateKey::new(&mut rng, 2048).expect("key")
    }

    fn jwk(private: &RsaPrivateKey, kid: &str) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": kid,
            "n": base64url_encode(&private.n().to_bytes_be()),
            "e": base64url_encode(&private.e().to_bytes_be()),
        })
    }

    fn sign(
        private: &RsaPrivateKey,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> String {
        let input = format!(
            "{}.{}",
            base64url_encode(header.to_string().as_bytes()),
            base64url_encode(claims.to_string().as_bytes())
        );
        let signature = SigningKey::<Sha256>::new(private.clone()).sign(input.as_bytes());
        format!("{input}.{}", base64url_encode(&signature.to_vec()))
    }

    fn claims(issuer: &str) -> serde_json::Value {
        serde_json::json!({"iss": issuer, "sub": issuer, "uid": "u1", "iat": 1, "exp": 2})
    }

    fn trust(entries: &[(&str, &RsaPrivateKey)]) -> CustomTokenTrust {
        let map: serde_json::Map<String, serde_json::Value> = entries
            .iter()
            .map(|(account, private)| {
                (
                    (*account).to_owned(),
                    serde_json::json!({"keys": [jwk(private, "k1")]}),
                )
            })
            .collect();
        CustomTokenTrust::from_jwks(&map).expect("trust")
    }

    fn rs256() -> serde_json::Value {
        serde_json::json!({"alg": "RS256", "kid": "k1", "typ": "JWT"})
    }

    #[test]
    fn a_token_of_a_trusted_signer_of_this_project_verifies() {
        let own = key(1);
        let token = sign(&own, &rs256(), &claims(OWN));
        let verified = trust(&[(OWN, &own)])
            .verify(&token, PROJECT)
            .expect("verifies");
        assert_eq!(verified.get("uid").and_then(JsonValue::as_str), Some("u1"));
    }

    #[test]
    fn a_verifying_token_of_another_projects_service_account_is_a_credential_mismatch() {
        let (own, other) = (key(1), key(2));
        let token = sign(&other, &rs256(), &claims(OTHER));
        assert_eq!(
            trust(&[(OWN, &own), (OTHER, &other)]).verify(&token, PROJECT),
            Err(CustomTokenRefusal::CredentialMismatch)
        );
    }

    #[test]
    fn damaged_unsigned_unknown_or_misattributed_tokens_are_invalid() {
        let (own, other) = (key(1), key(2));
        let trust = trust(&[(OWN, &own)]);
        let token = sign(&own, &rs256(), &claims(OWN));
        let (input, signature) = token.rsplit_once('.').expect("three parts");
        let mut bytes = base64url_decode(signature).expect("signature");
        bytes[10] ^= 0xff;
        assert_eq!(
            trust.verify(&format!("{input}."), PROJECT),
            Err(CustomTokenRefusal::MissingSignature)
        );
        for malformed in ["not-a-jwt", "", "a.b", "a.b.c.d"] {
            assert_eq!(
                trust.verify(malformed, PROJECT),
                Err(CustomTokenRefusal::Format)
            );
        }
        let refused = [
            format!("{input}.{}", base64url_encode(&bytes)),
            sign(&own, &serde_json::json!({"alg": "none"}), &claims(OWN)),
            sign(&own, &serde_json::json!({"alg": "RS512"}), &claims(OWN)),
            // Signed by a key that is not the issuer's.
            sign(&other, &rs256(), &claims(OWN)),
            // An issuer nobody configured.
            sign(&other, &rs256(), &claims(OTHER)),
        ];
        for token in refused {
            assert_eq!(
                trust.verify(&token, PROJECT),
                Err(CustomTokenRefusal::Invalid),
                "{token}"
            );
        }
    }

    #[test]
    fn a_key_id_that_names_another_configured_key_is_not_tried() {
        let own = key(1);
        let token = sign(
            &own,
            &serde_json::json!({"alg": "RS256", "kid": "other"}),
            &claims(OWN),
        );
        assert_eq!(
            trust(&[(OWN, &own)]).verify(&token, PROJECT),
            Err(CustomTokenRefusal::Invalid)
        );
        let no_kid = sign(&own, &serde_json::json!({"alg": "RS256"}), &claims(OWN));
        assert!(trust(&[(OWN, &own)]).verify(&no_kid, PROJECT).is_ok());
    }

    #[test]
    fn configuration_names_service_accounts_and_rsa_keys_only() {
        let own = key(1);
        let bad = |value: serde_json::Value| {
            let map = value.as_object().expect("object").clone();
            CustomTokenTrust::from_jwks(&map).expect_err("refused")
        };
        assert!(
            bad(serde_json::json!({"someone@example.com": {"keys": [jwk(&own, "k")]}}))
                .contains("not a service-account address")
        );
        assert!(bad(serde_json::json!({OWN: {"keys": []}})).contains("at least one key"));
        assert!(bad(serde_json::json!({OWN: {"keys": [{"kty": "EC"}]}})).contains("kty RSA"));
        assert!(
            bad(serde_json::json!({OWN: {"keys": [{"kty": "RSA", "n": "AQAB"}]}}))
                .contains("base64url e")
        );
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(5);
        let short = RsaPrivateKey::new(&mut rng, 1024).expect("key");
        assert!(bad(serde_json::json!({OWN: {"keys": [jwk(&short, "k")]}})).contains("2048"));
    }

    #[test]
    fn debug_output_names_signers_and_never_key_material() {
        let own = key(1);
        let shown = format!("{:?}", trust(&[(OWN, &own)]));
        assert!(shown.contains(OWN), "{shown}");
        let modulus = base64url_encode(&own.n().to_bytes_be());
        assert!(!shown.contains(&modulus[..16]), "{shown}");
    }

    #[test]
    fn service_account_projects() {
        assert_eq!(service_account_project(OWN), Some("demo-project"));
        assert_eq!(
            service_account_project("p1@appspot.gserviceaccount.com"),
            Some("p1")
        );
        assert_eq!(service_account_project("a@example.com"), None);
        assert_eq!(service_account_project("a@.iam.gserviceaccount.com"), None);
        assert_eq!(service_account_project("no-at"), None);
    }
}
