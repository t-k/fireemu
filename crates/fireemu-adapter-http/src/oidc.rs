//! Explicit local public-key trust for the bounded OIDC assertion adapter.
use serde_json::Value;
/// Caller-pinned trust. Not loaded from an assertion, HTTP request or discovery URL.
pub struct LocalOidcTrust {
    /// Selected project.
    pub project_id: String,
    /// Selected tenant; `None` binds the parent namespace.
    pub tenant_id: Option<String>,
    /// Exact custom OIDC provider ID.
    pub provider_id: String,
    /// Exact issuer.
    pub issuer: String,
    /// Exact client audience.
    pub client_id: String,
    /// Pinned RSA verification JWK (public material only).
    pub jwk: Value,
}

use fireemu_core_auth::{jwt::base64url_decode, store::AuthStore};
use fireemu_core_types::time::LogicalInstant;
use rsa::traits::PublicKeyParts;
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    signature::Verifier,
    BigUint, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Production's refusals of an OIDC ID token (AUTH-FEDERATION record-oidc, run 39209e,
/// 2026-09-28).
pub(crate) const SIGNATURE_REFUSAL: &str =
    "INVALID_IDP_RESPONSE : Unable to verify the ID Token signature.";
pub(crate) const UNPARSABLE_REFUSAL: &str = "INVALID_IDP_RESPONSE : Unable to parse the ID Token.";
pub(crate) const NOT_FOUND_REFUSAL: &str =
    "OPERATION_NOT_ALLOWED : The identity provider configuration is not found.";
pub(crate) const DISABLED_REFUSAL: &str =
    "OPERATION_NOT_ALLOWED : The identity provider configuration is disabled.";
pub(crate) const NONCE_MISSING_REFUSAL: &str =
    "MISSING_OR_INVALID_NONCE : Nonce is missing in the request.";
pub(crate) const DUPLICATE_REFUSAL: &str =
    "MISSING_OR_INVALID_NONCE : Duplicate credential received. Please try again with a new credential.";
/// A refusal whose production message is unobserved.
const UNOBSERVED_REFUSAL: &str = "INVALID_IDP_RESPONSE";

/// What a verified ID token says about the credential it is: whose it is, the nonce it
/// carries, and until when it is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedIdToken {
    pub(crate) subject: String,
    pub(crate) nonce: Option<String>,
    pub(crate) expires: i64,
}

impl LocalOidcTrust {
    pub(crate) fn accepts(
        &self,
        store: &AuthStore,
        params: &BTreeMap<String, String>,
        at: LogicalInstant,
    ) -> bool {
        self.check(store, params, at, &|_| false).is_ok()
    }

    /// Verifies the request's ID token against this trust and the live configuration.
    /// `used(credential)` says whether a nonce-bearing credential already signed in.
    ///
    /// # Errors
    /// Production's message for the refusal, or `INVALID_IDP_RESPONSE` where it is unobserved.
    pub(crate) fn check(
        &self,
        store: &AuthStore,
        params: &BTreeMap<String, String>,
        at: LogicalInstant,
        used: &dyn Fn(&VerifiedIdToken) -> bool,
    ) -> Result<VerifiedIdToken, String> {
        let Some(config) = store.oidc_config(&self.provider_id) else {
            return Err(NOT_FOUND_REFUSAL.to_owned());
        };
        if self.project_id != store.project_id()
            || self.tenant_id.as_deref() != store.tenant_id()
            || !self.provider_id.starts_with("oidc.")
            || params.get("providerId") != Some(&self.provider_id)
            || config.issuer != self.issuer
            || config.client_id != self.client_id
            || self.client_id.is_empty()
            || self.issuer.is_empty()
        {
            return Err(UNOBSERVED_REFUSAL.to_owned());
        }
        if !config.enabled {
            return Err(DISABLED_REFUSAL.to_owned());
        }
        // This bounded mode authenticates only an ID token; other OAuth credentials are unverified.
        if ["access_token", "refresh_token"]
            .iter()
            .any(|field| params.get(*field).is_some_and(|token| !token.is_empty()))
        {
            return Err(UNOBSERVED_REFUSAL.to_owned());
        }
        let Some(token) = params.get("id_token") else {
            return Err(UNOBSERVED_REFUSAL.to_owned());
        };
        self.verify(token, params.get("nonce").map(String::as_str), at, used)
    }

    fn verify(
        &self,
        token: &str,
        raw_nonce: Option<&str>,
        at: LogicalInstant,
        used: &dyn Fn(&VerifiedIdToken) -> bool,
    ) -> Result<VerifiedIdToken, String> {
        let unparsable = || UNPARSABLE_REFUSAL.to_owned();
        let signature_refused = || SIGNATURE_REFUSAL.to_owned();
        // This local slice permits only compact RS256 JWS and a bounded pinned RSA key.
        if token.len() > 65_536 {
            return Err(unparsable());
        }
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(unparsable());
        };
        let header: Value = base64url_decode(header)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(unparsable)?;
        let text =
            |value: &Value, name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
        if text(&header, "alg").as_deref() != Some("RS256")
            || header.get("crit").is_some()
            || header.get("b64").is_some()
            || text(&header, "kid").is_none()
            || text(&header, "kid") != text(&self.jwk, "kid")
            || text(&self.jwk, "kty").as_deref() != Some("RSA")
            || text(&self.jwk, "alg").as_deref() != Some("RS256")
            || text(&self.jwk, "use").as_deref() != Some("sig")
        {
            return Err(signature_refused());
        }
        self.verify_signature(token, signature)
            .ok_or_else(signature_refused)?;
        let claims: Value = base64url_decode(payload)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(Value::is_object)
            .ok_or_else(unparsable)?;
        let verified = self.verified_claims(&claims, at)?;
        // A request nonce without one in the token is accepted (39209e). With one in the
        // token: missing in the request, then a credential already used, then a mismatch.
        if let Some(nonce) = &verified.nonce {
            let Some(raw) = raw_nonce.filter(|raw| !raw.is_empty()) else {
                return Err(NONCE_MISSING_REFUSAL.to_owned());
            };
            if used(&verified) {
                return Err(DUPLICATE_REFUSAL.to_owned());
            }
            if *nonce != format!("{:x}", Sha256::digest(raw.as_bytes())) {
                return Err(UNOBSERVED_REFUSAL.to_owned());
            }
        }
        Ok(verified)
    }

    /// The checks of a signed token's claims: issuer, audience, subject and times.
    fn verified_claims(
        &self,
        claims: &Value,
        at: LogicalInstant,
    ) -> Result<VerifiedIdToken, String> {
        let unobserved = || UNOBSERVED_REFUSAL.to_owned();
        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if issuer != self.issuer {
            return Err(format!(
                "INVALID_IDP_RESPONSE : The issuer in ID Token {issuer} does not match the expected one in config: {}.",
                self.issuer
            ));
        }
        // Production accepts a token for several audiences that include the client, with or
        // without `azp` (record-oidc 39209e); an `azp` naming another party is refused.
        let audiences: Vec<&str> = match claims.get("aud") {
            Some(Value::String(aud)) => vec![aud.as_str()],
            Some(Value::Array(aud)) => aud.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !audiences.contains(&self.client_id.as_str()) {
            return Err(format!(
                "INVALID_IDP_RESPONSE : The audience in ID Token [{}] does not match the expected audience {}.",
                audiences.join(", "),
                self.client_id
            ));
        }
        if claims
            .get("azp")
            .is_some_and(|azp| azp.as_str() != Some(self.client_id.as_str()))
        {
            return Err(unobserved());
        }
        let Some(subject) = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|sub| !sub.is_empty())
        else {
            // Production quotes the claims, their members in order.
            let sorted: BTreeMap<&String, &Value> =
                claims.as_object().into_iter().flatten().collect();
            return Err(format!(
                "INVALID_IDP_RESPONSE : ID Token does not contain user's identity in 'sub' claim: {}",
                serde_json::to_string(&sorted).unwrap_or_default()
            ));
        };
        let (Some(issued_at), Some(expires_at)) = (
            claims.get("iat").and_then(Value::as_i64),
            claims.get("exp").and_then(Value::as_i64),
        ) else {
            return Err(unobserved());
        };
        let issue_time = LogicalInstant::from_unix_seconds(issued_at);
        let expiry = LogicalInstant::from_unix_seconds(expires_at);
        if issue_time > at || expiry <= at || expiry <= issue_time {
            return Err(format!(
                "INVALID_IDP_RESPONSE : ID Token issued at {issued_at} is stale to sign-in."
            ));
        }
        // `nbf` is not checked: production signs in with a token not yet valid (39209e).
        let nonce = match claims.get("nonce") {
            None => None,
            Some(Value::String(nonce)) => Some(nonce.clone()),
            Some(_) => return Err(unobserved()),
        };
        Ok(VerifiedIdToken {
            subject: subject.to_owned(),
            nonce,
            expires: expires_at,
        })
    }

    /// Whether `signature` verifies the token's signing input with the pinned key.
    fn verify_signature(&self, token: &str, signature: &str) -> Option<()> {
        let modulus = self.jwk.get("n")?.as_str()?;
        let exponent = self.jwk.get("e")?.as_str()?;
        if modulus.len() > 1_366 || exponent.len() > 8 {
            return None;
        }
        let key = RsaPublicKey::new(
            BigUint::from_bytes_be(&base64url_decode(modulus).ok()?),
            BigUint::from_bytes_be(&base64url_decode(exponent).ok()?),
        )
        .ok()?;
        if !(2048..=8192).contains(&key.n().bits()) {
            return None;
        }
        let signature = base64url_decode(signature).ok()?;
        let signature = Signature::try_from(signature.as_slice()).ok()?;
        let signing_input = token.rsplit_once('.')?.0;
        VerifyingKey::<Sha256>::new(key)
            .verify(signing_input.as_bytes(), &signature)
            .ok()
    }
}
