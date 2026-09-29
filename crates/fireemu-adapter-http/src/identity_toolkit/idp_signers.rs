//! The OIDC issuers whose signed ID tokens the strict profile verifies (`auth.idpSigners`,
//! owner decision O4 of AUTH-FEDERATION): each issuer's public JWK set, given at startup. No
//! key is ever fetched from an issuer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;

/// Private members a JWK must not carry: a signer set holds public keys only.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Issuers and their RS256 public keys, by `kid`, the nonce-bearing credentials strict
/// sign-ins used (production refuses one used again), and the SAML `AuthnRequest` IDs strict
/// `createAuthUri` issued, by session (production refuses a response to another request).
#[derive(Debug, Clone, Default)]
pub struct IdpSignerTrust {
    issuers: BTreeMap<String, BTreeMap<String, Value>>,
    /// Each issuer's `authorization_endpoint`, as its discovery document gives it.
    authorization_endpoints: BTreeMap<String, String>,
    /// Each issuer's `scopes_supported`, as its discovery document gives it.
    scopes_supported: BTreeMap<String, Vec<String>>,
    used: Arc<Mutex<UsedCredentials>>,
    saml_requests: Arc<Mutex<Expiring<String>>>,
}

impl IdpSignerTrust {
    /// Reads `{"<issuer>": {"keys": [<RS256 RSA public JWK with a kid>, …],
    /// "authorization_endpoint"?: "<https URL>", "scopes_supported"?: ["<scope>", …]}}` (the
    /// endpoint and scopes as the issuer's discovery document names them, for `createAuthUri`).
    ///
    /// # Errors
    /// A message naming the first issuer that is not an https URL without a query or fragment,
    /// or whose set is empty, holds a key that is not an RS256 RSA public key of at least 2048
    /// bits, carries private members, or lacks a unique `kid`, or whose
    /// `authorization_endpoint` is not an https URL without a query or fragment, or whose
    /// `scopes_supported` is not a list of 1 to 32 scope tokens of 1 to 128 letters, digits and
    /// `._:/-`.
    pub fn from_jwks(signers: &serde_json::Map<String, Value>) -> Result<Self, String> {
        let mut issuers = BTreeMap::new();
        let mut authorization_endpoints = BTreeMap::new();
        let mut scopes_supported = BTreeMap::new();
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
            if let Some(endpoint) = jwks.get("authorization_endpoint") {
                let endpoint = endpoint
                    .as_str()
                    .filter(|endpoint| valid_issuer(endpoint))
                    .ok_or_else(|| {
                        format!(
                            "{issuer}: authorization_endpoint must be an https URL without a query or fragment"
                        )
                    })?;
                authorization_endpoints.insert(issuer.clone(), endpoint.to_owned());
            }
            if let Some(scopes) = jwks.get("scopes_supported") {
                scopes_supported.insert(issuer.clone(), valid_scopes(scopes).ok_or_else(|| {
                    format!(
                        "{issuer}: scopes_supported must list 1 to 32 scopes of 1 to 128 letters, digits and ._:/-"
                    )
                })?);
            }
        }
        Ok(Self {
            issuers,
            authorization_endpoints,
            scopes_supported,
            used: Arc::default(),
            saml_requests: Arc::default(),
        })
    }

    /// The public JWK of `issuer` named `kid`.
    #[must_use]
    pub fn key(&self, issuer: &str, kid: &str) -> Option<&Value> {
        self.issuers.get(issuer)?.get(kid)
    }

    /// The authorization endpoint configured for `issuer`, if any.
    #[must_use]
    pub fn authorization_endpoint(&self, issuer: &str) -> Option<&str> {
        self.authorization_endpoints.get(issuer).map(String::as_str)
    }

    /// The scopes configured as `issuer`'s `scopes_supported`, if any.
    #[must_use]
    pub fn scopes_supported(&self, issuer: &str) -> Option<&[String]> {
        self.scopes_supported.get(issuer).map(Vec::as_slice)
    }

    /// Whether any key of `issuer` is configured.
    #[must_use]
    pub fn knows(&self, issuer: &str) -> bool {
        self.issuers.contains_key(issuer)
    }

    /// Whether a sign-in already used the credential `key` (still unexpired at `now`).
    pub(crate) fn credential_used(&self, key: &str, now: i64) -> bool {
        self.used
            .lock()
            .map_or(true, |mut used| used.contains(key, now))
    }

    /// Reserves the credential `key` for a sign-in, valid until `expires`: `false` when a sign-in
    /// already used or reserved it. The check and the reservation are one step, so two
    /// concurrent sign-ins cannot both pass (closure review SF4).
    pub(crate) fn reserve_credential(&self, key: &str, expires: i64, now: i64) -> bool {
        self.used
            .lock()
            .is_ok_and(|mut used| used.insert_if_absent(key, (), expires, now))
    }

    /// Forgets the reservation of `key`: the sign-in that reserved it did not succeed.
    pub(crate) fn release_credential(&self, key: &str) {
        if let Ok(mut used) = self.used.lock() {
            used.remove(key);
        }
    }

    /// Records the `AuthnRequest` ID a strict `createAuthUri` issued for the session `key`,
    /// remembered until `expires`.
    pub(crate) fn record_saml_request(
        &self,
        key: String,
        request_id: String,
        expires: i64,
        now: i64,
    ) {
        if let Ok(mut requests) = self.saml_requests.lock() {
            requests.insert(key, request_id, expires, now);
        }
    }

    /// The `AuthnRequest` ID issued for the session `key`, if it is still remembered.
    pub(crate) fn saml_request(&self, key: &str, now: i64) -> Option<String> {
        self.saml_requests
            .lock()
            .ok()
            .and_then(|mut requests| requests.get(key, now).cloned())
    }
}

/// The most entries (used credentials, issued SAML requests) remembered in a daemon session.
/// Past it, the one expiring first is forgotten (an emulator bound, not production's).
const USED_CREDENTIALS_CAPACITY: usize = 10_000;

/// Used credentials by key, each until its token's expiry (a later use is refused as expired
/// anyway), within a fixed capacity.
pub(crate) type UsedCredentials = Expiring<()>;

/// Entries by key, each until an expiry, within a fixed capacity.
#[derive(Debug)]
pub(crate) struct Expiring<V> {
    entries: BTreeMap<String, (V, i64)>,
    capacity: usize,
}

impl<V> Default for Expiring<V> {
    fn default() -> Self {
        Self::with_capacity(USED_CREDENTIALS_CAPACITY)
    }
}

impl<V> Expiring<V> {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
        }
    }

    fn sweep(&mut self, now: i64) {
        self.entries.retain(|_, (_, expires)| *expires > now);
    }

    fn get(&mut self, key: &str, now: i64) -> Option<&V> {
        self.sweep(now);
        self.entries.get(key).map(|(value, _)| value)
    }

    fn contains(&mut self, key: &str, now: i64) -> bool {
        self.get(key, now).is_some()
    }

    /// Inserts `key` unless it is present: whether it was absent. An entry already expired at
    /// `now` is never remembered, so it counts as inserted.
    fn insert_if_absent(&mut self, key: &str, value: V, expires: i64, now: i64) -> bool {
        if self.contains(key, now) {
            return false;
        }
        self.insert(key.to_owned(), value, expires, now);
        true
    }

    fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }

    fn insert(&mut self, key: String, value: V, expires: i64, now: i64) {
        self.sweep(now);
        if expires <= now {
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            let first = self
                .entries
                .iter()
                .min_by_key(|(_, (_, expires))| *expires)
                .map(|(key, _)| key.clone());
            if let Some(first) = first {
                self.entries.remove(&first);
            }
        }
        self.entries.insert(key, (value, expires));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Expiring<()> {
    #[cfg(test)]
    fn record(&mut self, key: String, expires: i64, now: i64) {
        self.insert(key, (), expires, now);
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
    // The rsa crate refuses a modulus over `RsaPublicKey::MAX_SIZE` (4096 bits), so a longer key
    // is refused here rather than accepted and never verifying. Production's own limit is unobserved.
    super::custom_token::validate_public_jwk(key)
}

/// Scope tokens that go into an authorization URL unescaped.
fn valid_scopes(value: &Value) -> Option<Vec<String>> {
    let scopes = value
        .as_array()
        .filter(|scopes| (1..=32).contains(&scopes.len()))?;
    scopes
        .iter()
        .map(|scope| {
            scope
                .as_str()
                .filter(|scope| {
                    (1..=128).contains(&scope.len())
                        && scope
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || "._:/-".contains(c))
                })
                .map(str::to_owned)
        })
        .collect()
}

fn valid_issuer(issuer: &str) -> bool {
    issuer.strip_prefix("https://").is_some_and(|rest| {
        let host = rest.split('/').next().unwrap_or_default();
        !host.is_empty() && !rest.contains(['?', '#']) && !rest.contains(char::is_whitespace)
    })
}

#[cfg(test)]
mod used_credentials_tests {
    use super::{Expiring, UsedCredentials};

    #[test]
    fn a_credential_is_reserved_once_and_released_on_failure() {
        let mut used: UsedCredentials = Expiring::with_capacity(4);
        assert!(used.insert_if_absent("k", (), 100, 10));
        assert!(!used.insert_if_absent("k", (), 100, 11), "reserved once");
        assert!(used.contains("k", 12));
        used.remove("k");
        assert!(!used.contains("k", 12));
        assert!(
            used.insert_if_absent("k", (), 100, 13),
            "released, reserved again"
        );
        // An already expired credential is not remembered: there is nothing to reserve.
        assert!(used.insert_if_absent("old", (), 5, 10));
        assert!(!used.contains("old", 10));
    }

    #[test]
    fn an_issued_request_is_read_back_until_it_expires() {
        let mut requests = Expiring::with_capacity(2);
        requests.insert("s1".into(), "_r1".to_owned(), 100, 0);
        requests.insert("s1".into(), "_r2".to_owned(), 100, 0);
        assert_eq!(requests.get("s1", 99).map(String::as_str), Some("_r2"));
        assert_eq!(requests.get("s1", 100), None);
        assert_eq!(requests.get("s2", 0), None);
    }

    #[test]
    fn a_credential_is_remembered_until_its_token_expires() {
        let mut used = UsedCredentials::with_capacity(4);
        used.record("a".into(), 100, 10);
        assert!(used.contains("a", 99));
        assert!(!used.contains("a", 100));
        assert_eq!(used.len(), 0, "an expired credential is dropped");
        // One already expired is not recorded.
        used.record("b".into(), 50, 50);
        assert_eq!(used.len(), 0);
        assert!(!used.contains("b", 49));
    }

    #[test]
    fn the_capacity_bounds_what_is_remembered() {
        let mut used = UsedCredentials::with_capacity(3);
        used.record("late".into(), 300, 0);
        used.record("first".into(), 100, 0);
        used.record("middle".into(), 200, 0);
        used.record("late".into(), 400, 0);
        assert_eq!(used.len(), 3, "recording a key again does not grow it");
        used.record("new".into(), 500, 0);
        assert_eq!(used.len(), 3);
        assert!(
            !used.contains("first", 1),
            "the one expiring first is forgotten"
        );
        for key in ["middle", "late", "new"] {
            assert!(used.contains(key, 1), "{key}");
        }
        assert_eq!(
            UsedCredentials::default().capacity,
            super::USED_CREDENTIALS_CAPACITY
        );
    }
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
    fn an_issuer_may_name_its_authorization_endpoint() {
        // What the issuer's discovery document says, for createAuthUri (never fetched).
        let issuer = "https://idp.example/oidc/run";
        let key = public_jwk(3, "k1");
        let endpoint = "https://idp.example/oidc/run/authorize";
        let trust = IdpSignerTrust::from_jwks(&signers(&[(
            issuer,
            json!({"keys": [key.clone()], "authorization_endpoint": endpoint}),
        )]))
        .expect("trust");
        assert_eq!(trust.authorization_endpoint(issuer), Some(endpoint));
        let without =
            IdpSignerTrust::from_jwks(&signers(&[(issuer, json!({"keys": [key.clone()]}))]))
                .expect("trust");
        assert_eq!(without.authorization_endpoint(issuer), None);
        for bad in [
            json!("http://idp.example/authorize"),
            json!("https://idp.example/authorize?x=1"),
            json!("https://idp.example/authorize#f"),
            json!(""),
            json!(7),
        ] {
            let error = IdpSignerTrust::from_jwks(&signers(&[(
                issuer,
                json!({"keys": [key.clone()], "authorization_endpoint": bad}),
            )]))
            .expect_err("refused");
            assert!(error.contains("authorization_endpoint"), "{error}");
        }
    }

    #[test]
    fn an_issuer_may_name_its_supported_scopes() {
        // What the issuer's discovery document lists as `scopes_supported` (never fetched).
        let issuer = "https://idp.example/oidc/run";
        let key = public_jwk(4, "k1");
        let trust = IdpSignerTrust::from_jwks(&signers(&[(
            issuer,
            json!({"keys": [key.clone()], "scopes_supported": ["openid", "email", "profile"]}),
        )]))
        .expect("trust");
        assert_eq!(
            trust.scopes_supported(issuer),
            Some(
                &[
                    "openid".to_owned(),
                    "email".to_owned(),
                    "profile".to_owned()
                ][..]
            )
        );
        let without =
            IdpSignerTrust::from_jwks(&signers(&[(issuer, json!({"keys": [key.clone()]}))]))
                .expect("trust");
        assert_eq!(without.scopes_supported(issuer), None);
        // Only scope tokens that need no escaping in the authorization URL.
        for bad in [
            json!("openid"),
            json!([]),
            json!([""]),
            json!(["openid", 7]),
            json!(["open id"]),
            json!(["openid&x=1"]),
            json!(["openid+email"]),
            json!(["a".repeat(129)]),
            json!(vec!["openid"; 33]),
        ] {
            let error = IdpSignerTrust::from_jwks(&signers(&[(
                issuer,
                json!({"keys": [key.clone()], "scopes_supported": bad}),
            )]))
            .expect_err("refused");
            assert!(error.contains("scopes_supported"), "{error}");
        }
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
