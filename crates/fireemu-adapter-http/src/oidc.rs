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

impl LocalOidcTrust {
    pub(crate) fn accepts(
        &self,
        store: &AuthStore,
        params: &BTreeMap<String, String>,
        at: LogicalInstant,
    ) -> bool {
        let Some(config) = store.oidc_config(&self.provider_id) else {
            return false;
        };
        if self.project_id != store.project_id()
            || self.tenant_id.as_deref() != store.tenant_id()
            || !self.provider_id.starts_with("oidc.")
            || params.get("providerId") != Some(&self.provider_id)
            || !config.enabled
            || config.issuer != self.issuer
            || config.client_id != self.client_id
            || self.client_id.is_empty()
            || self.issuer.is_empty()
        {
            return false;
        }
        // This bounded mode authenticates only an ID token; other OAuth credentials are unverified.
        if ["access_token", "refresh_token"]
            .iter()
            .any(|field| params.get(*field).is_some_and(|token| !token.is_empty()))
        {
            return false;
        }
        let Some(token) = params.get("id_token") else {
            return false;
        };
        self.verify(token, params.get("nonce").map(String::as_str), at)
            .is_some()
    }

    fn verify(&self, token: &str, raw_nonce: Option<&str>, at: LogicalInstant) -> Option<()> {
        // This local slice permits only compact RS256 JWS and a bounded pinned RSA key.
        if token.len() > 65_536 {
            return None;
        }
        let mut parts = token.split('.');
        let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let header: Value = serde_json::from_slice(&base64url_decode(header).ok()?).ok()?;
        if header.get("alg")?.as_str()? != "RS256"
            || header.get("crit").is_some()
            || header.get("b64").is_some()
            || header.get("kid")?.as_str()? != self.jwk.get("kid")?.as_str()?
            || self.jwk.get("kty")?.as_str()? != "RSA"
            || self.jwk.get("alg")?.as_str()? != "RS256"
            || self.jwk.get("use")?.as_str()? != "sig"
        {
            return None;
        }
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
            .ok()?;
        let claims: Value = serde_json::from_slice(&base64url_decode(payload).ok()?).ok()?;
        if claims.get("iss")?.as_str()? != self.issuer || claims.get("sub")?.as_str()?.is_empty() {
            return None;
        }
        let audience = claims.get("aud")?;
        let multiple = match audience {
            Value::String(aud) if aud == &self.client_id => false,
            Value::Array(aud)
                if !aud.is_empty()
                    && aud.iter().all(Value::is_string)
                    && aud.iter().any(|a| a.as_str() == Some(&self.client_id)) =>
            {
                aud.len() > 1
            }
            _ => return None,
        };
        if (multiple || claims.get("azp").is_some())
            && claims.get("azp")?.as_str()? != self.client_id
        {
            return None;
        }
        let issued = LogicalInstant::from_unix_seconds(claims.get("iat")?.as_i64()?);
        let expires = LogicalInstant::from_unix_seconds(claims.get("exp")?.as_i64()?);
        if issued > at || expires <= at || expires <= issued {
            return None;
        }
        if let Some(nbf) = claims.get("nbf") {
            if LogicalInstant::from_unix_seconds(nbf.as_i64()?) > at {
                return None;
            }
        }
        match (claims.get("nonce"), raw_nonce) {
            (None, None) => (),
            (Some(nonce), Some(raw)) if !raw.is_empty() => {
                if nonce.as_str()? != format!("{:x}", Sha256::digest(raw.as_bytes())) {
                    return None;
                }
            }
            _ => return None,
        }
        Some(())
    }
}
