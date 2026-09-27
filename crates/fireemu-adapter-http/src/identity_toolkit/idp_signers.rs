//! The OIDC issuers whose signed ID tokens the strict profile verifies (`auth.idpSigners`,
//! owner decision O4 of AUTH-FEDERATION): each issuer's public JWK set, given at startup. No
//! key is ever fetched from an issuer.

use std::collections::BTreeMap;

use serde_json::Value;

/// Private members a JWK must not carry: a signer set holds public keys only.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Issuers and their RS256 public keys, by `kid`.
#[derive(Debug, Clone, Default)]
pub struct IdpSignerTrust {
    issuers: BTreeMap<String, BTreeMap<String, Value>>,
}

impl IdpSignerTrust {
    /// Reads `{"<issuer>": {"keys": [<RS256 RSA public JWK with a kid>, …]}}`.
    ///
    /// # Errors
    /// A message naming the first issuer that is not an https URL without a query or fragment,
    /// or whose set is empty, holds a key that is not an RS256 RSA public key of at least 2048
    /// bits, carries private members, or lacks a unique `kid`.
    pub fn from_jwks(signers: &serde_json::Map<String, Value>) -> Result<Self, String> {
        let mut issuers = BTreeMap::new();
        for (issuer, jwks) in signers {
            if !valid_issuer(issuer) {
                return Err(format!(
                    "{issuer:?} is not an https issuer URL without a query or fragment"
                ));
            }
            let keys = jwks
                .get("keys")
                .and_then(Value::as_array)
                .filter(|keys| !keys.is_empty())
                .ok_or_else(|| format!("{issuer}: expected a JWK set with at least one key"))?;
            let mut by_kid = BTreeMap::new();
            for key in keys {
                if PRIVATE_MEMBERS
                    .iter()
                    .any(|member| key.get(*member).is_some())
                {
                    return Err(format!("{issuer}: a key carries private members"));
                }
                check_signing_key(key).map_err(|e| format!("{issuer}: {e}"))?;
                let kid = key
                    .get("kid")
                    .and_then(Value::as_str)
                    .filter(|kid| !kid.is_empty())
                    .ok_or_else(|| format!("{issuer}: every key needs a kid"))?;
                if by_kid.insert(kid.to_owned(), key.clone()).is_some() {
                    return Err(format!("{issuer}: the kid {kid} is repeated"));
                }
            }
            issuers.insert(issuer.clone(), by_kid);
        }
        Ok(Self { issuers })
    }

    /// The public JWK of `issuer` named `kid`.
    #[must_use]
    pub fn key(&self, issuer: &str, kid: &str) -> Option<&Value> {
        self.issuers.get(issuer)?.get(kid)
    }

    /// Whether any key of `issuer` is configured.
    #[must_use]
    pub fn knows(&self, issuer: &str) -> bool {
        self.issuers.contains_key(issuer)
    }
}

/// The same key requirements `LocalOidcTrust::verify` applies, checked when the configuration
/// is read so that a key strict could never verify with is refused at startup.
fn check_signing_key(key: &Value) -> Result<(), String> {
    let field = |name: &str| key.get(name).and_then(Value::as_str);
    if field("kty") != Some("RSA") {
        return Err("every key must have kty RSA".to_owned());
    }
    if field("alg") != Some("RS256") {
        return Err("every key must have alg RS256".to_owned());
    }
    if field("use") != Some("sig") {
        return Err("every key must have use sig".to_owned());
    }
    if field("n").is_some_and(|n| n.len() > 1_366) || field("e").is_some_and(|e| e.len() > 8) {
        return Err("a key's modulus or exponent is too long".to_owned());
    }
    // A modulus of at most 1366 base64url characters is at most 8192 bits, verify's upper bound.
    super::custom_token::validate_public_jwk(key)
}

fn valid_issuer(issuer: &str) -> bool {
    issuer.strip_prefix("https://").is_some_and(|rest| {
        let host = rest.split('/').next().unwrap_or_default();
        !host.is_empty() && !rest.contains(['?', '#']) && !rest.contains(char::is_whitespace)
    })
}

#[cfg(test)]
mod tests {
    use super::IdpSignerTrust;
    use fireemu_core_auth::jwt::base64url_encode;
    use rand_core::SeedableRng;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde_json::{json, Map, Value};

    fn public_jwk(seed: u64, kid: &str) -> Value {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("key");
        json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": kid,
            "n": base64url_encode(&key.n().to_bytes_be()),
            "e": base64url_encode(&key.e().to_bytes_be()),
        })
    }

    fn signers(entries: &[(&str, Value)]) -> Map<String, Value> {
        entries
            .iter()
            .map(|(issuer, jwks)| ((*issuer).to_owned(), jwks.clone()))
            .collect()
    }

    #[test]
    fn issuers_hold_public_keys_by_kid() {
        let issuer = "https://idp.example/oidc/run";
        let key = public_jwk(1, "k1");
        let trust =
            IdpSignerTrust::from_jwks(&signers(&[(issuer, json!({"keys": [key.clone()]}))]))
                .expect("trust");
        assert!(trust.knows(issuer));
        assert_eq!(trust.key(issuer, "k1"), Some(&key));
        assert_eq!(trust.key(issuer, "k2"), None);
        assert_eq!(trust.key("https://other.example", "k1"), None);
    }

    #[test]
    fn a_signer_set_that_is_not_public_rs256_keys_by_https_issuer_is_refused() {
        let key = public_jwk(2, "k1");
        let mut private = key.clone();
        private["d"] = json!("AQAB");
        let mut no_kid = key.clone();
        no_kid.as_object_mut().unwrap().remove("kid");
        let mut no_alg = key.clone();
        no_alg.as_object_mut().unwrap().remove("alg");
        let mut no_use = key.clone();
        no_use.as_object_mut().unwrap().remove("use");
        let mut encryption = key.clone();
        encryption["use"] = json!("enc");
        let mut long_exponent = key.clone();
        long_exponent["e"] = json!("AQABAQABAQAB");
        let mut long_modulus = key.clone();
        long_modulus["n"] = json!("A".repeat(1_367));
        for (issuer, jwks, message) in [
            (
                "http://idp.example",
                json!({"keys": [key.clone()]}),
                "https issuer",
            ),
            (
                "https://idp.example?x=1",
                json!({"keys": [key.clone()]}),
                "https issuer",
            ),
            ("https://", json!({"keys": [key.clone()]}), "https issuer"),
            (
                "https://idp.example",
                json!({"keys": []}),
                "at least one key",
            ),
            ("https://idp.example", json!({}), "at least one key"),
            (
                "https://idp.example",
                json!({"keys": [private]}),
                "private members",
            ),
            (
                "https://idp.example",
                json!({"keys": [no_kid]}),
                "needs a kid",
            ),
            (
                "https://idp.example",
                json!({"keys": [no_alg]}),
                "alg RS256",
            ),
            ("https://idp.example", json!({"keys": [no_use]}), "use sig"),
            (
                "https://idp.example",
                json!({"keys": [encryption]}),
                "use sig",
            ),
            (
                "https://idp.example",
                json!({"keys": [long_exponent]}),
                "too long",
            ),
            (
                "https://idp.example",
                json!({"keys": [long_modulus]}),
                "too long",
            ),
            (
                "https://idp.example",
                json!({"keys": [key.clone(), key.clone()]}),
                "is repeated",
            ),
            (
                "https://idp.example",
                json!({"keys": [{"kty": "EC", "kid": "e"}]}),
                "kty RSA",
            ),
        ] {
            let error = IdpSignerTrust::from_jwks(&signers(&[(issuer, jwks)])).expect_err(message);
            assert!(error.contains(message), "{issuer}: {error}");
        }
    }
}
