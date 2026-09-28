//! Strict SAML sign-in (AUTH-FEDERATION, owner decision O5 stage B): the signed `SAMLResponse`
//! of a `saml.*` provider is verified with the provider's configured certificates before any
//! mutation, and only what the verified assertion says reaches the sign-in.
//!
//! Refusals rest on production evidence or the public documentation only (the coordinator's
//! condition): a signature that does not verify, or none (production's
//! `INVALID_IDP_RESPONSE : Failed to verify the signature in SAMLResponse`, saml-smoke run
//! efe0ef, 2026-09-27; "If verification fails, the response will be rejected"), and a
//! missing `NameID` ("Identity Platform expects the <saml:Subject> and <saml:NameID>
//! elements"). Audience, destination, recipient, time windows, `InResponseTo` and issuer are
//! not enforced: production's handling of them is unobserved (the list U1-U18 of
//! `docs.local/instructions/2026-09-28-auth-federation-saml-unobserved.md`).

use std::collections::BTreeMap;

use fireemu_core_auth::store::AuthStore;
use serde_json::{json, Value};

use super::{error, form_encode, normalized_idp_params, str_field, uri_is_absolute, JsonResponse};
use crate::saml::{verify_saml_response, SamlError, VerifiedSaml};

/// Production's refusal of a response whose signature does not verify (saml-smoke).
pub(super) const SIGNATURE_REFUSAL: &str =
    "INVALID_IDP_RESPONSE : Failed to verify the signature in SAMLResponse";

/// The largest `SAMLResponse` read, as sent (base64 of at most 256 KiB of XML).
const MAX_ENCODED: usize = crate::saml::MAX_RESPONSE_BYTES / 3 * 4 + 4;

/// A response the strict daemon verified, kept to verify again against the live
/// configuration when a blocking function commits (the hook runs unlocked).
#[derive(Debug, Clone)]
pub(super) struct StrictSaml {
    provider_id: String,
    xml: String,
    name_id: String,
}

impl StrictSaml {
    /// Production's shape of a SAML sign-in answer: `federatedId` is the provider and the
    /// `NameID` (`saml.x/<NameID>`, saml-smoke 2026-09-27), where the emulator's fixture path
    /// answers the raw ID alone.
    pub(super) fn shape_answer(&self, response: &mut JsonResponse) {
        if response.status == 200 && response.body.get("federatedId").is_some() {
            response.body["federatedId"] = json!(format!("{}/{}", self.provider_id, self.name_id));
        }
    }

    /// Whether the provider still exists and is enabled and its certificates still verify the
    /// response (the same document names the same subject).
    pub(super) fn accepts(&self, store: &AuthStore) -> bool {
        verified_against(store, &self.provider_id, &self.xml).is_ok()
    }
}

/// Whether a `signInWithIdp` names a `saml.*` provider (in any case).
pub(super) fn names_saml_provider(body: &Value) -> bool {
    let params = normalized_idp_params(
        str_field(body, "requestUri").unwrap_or_default(),
        str_field(body, "postBody"),
    );
    params
        .get("providerId")
        .is_some_and(|id| id.to_lowercase().starts_with("saml."))
}

/// Verifies a strict `saml.*` sign-in and returns the trust to re-check and the body the
/// credential parser reads: the verified `NameID` and attributes in the internal form the
/// emulator's SAML path already maps (federated ID, email, `emailVerified`, sign-in
/// attributes). `Ok(None)` leaves a request without an absolute `requestUri` or a
/// `providerId` to the credential parser, which refuses it as before.
///
/// # Errors
/// `INVALID_IDP_RESPONSE : Failed to verify the signature in SAMLResponse` when no configured
/// certificate verifies a signature covering the assertion; `INVALID_IDP_RESPONSE` for a
/// provider that is missing, disabled or named in another case, a missing or unreadable
/// response, one without a `NameID`, or a form this verifier does not implement (codes
/// unobserved).
pub(super) fn strict_saml(
    store: &AuthStore,
    body: &Value,
) -> Result<Option<(StrictSaml, Value)>, JsonResponse> {
    let refused = || error(400, "INVALID_IDP_RESPONSE");
    let Some(request_uri) = str_field(body, "requestUri").filter(|uri| uri_is_absolute(uri)) else {
        return Ok(None);
    };
    let params = normalized_idp_params(request_uri, str_field(body, "postBody"));
    let Some(provider_id) = params.get("providerId").filter(|id| !id.is_empty()) else {
        return Ok(None);
    };
    // The credential parser lowercases the provider; the verified one must be the recorded one.
    if *provider_id != provider_id.to_lowercase() {
        return Err(refused());
    }
    let encoded = params
        .get("SAMLResponse")
        .filter(|value| !value.is_empty() && value.len() <= MAX_ENCODED)
        .ok_or_else(refused)?;
    let xml = decode_response(encoded).ok_or_else(refused)?;
    let verified = verified_against(store, provider_id, &xml).map_err(|failure| match failure {
        Some(SamlError::Signature) => error(400, SIGNATURE_REFUSAL),
        _ => refused(),
    })?;
    let name_id = verified
        .name_id
        .clone()
        .filter(|name| !name.chars().any(char::is_control))
        .ok_or_else(refused)?;
    let rewritten = credential_body(body, provider_id, &name_id, &verified);
    Ok(Some((
        StrictSaml {
            provider_id: provider_id.clone(),
            xml,
            name_id,
        },
        rewritten,
    )))
}

/// The response verified with the provider's certificates, or why not (`None`: the provider
/// is missing or disabled).
fn verified_against(
    store: &AuthStore,
    provider_id: &str,
    xml: &str,
) -> Result<VerifiedSaml, Option<SamlError>> {
    let config = store
        .saml_config(provider_id)
        .filter(|config| config.enabled)
        .ok_or(None)?;
    verify_saml_response(xml, &config.idp_certificates).map_err(Some)
}

/// A `SAMLResponse` as sent: standard base64 of UTF-8 XML (whitespace ignored).
fn decode_response(encoded: &str) -> Option<String> {
    let compact: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let unpadded = compact.trim_end_matches('=');
    if unpadded.contains(['-', '_', '=']) {
        return None;
    }
    let bytes =
        fireemu_core_auth::jwt::base64url_decode(&unpadded.replace('+', "-").replace('/', "_"))
            .ok()?;
    String::from_utf8(bytes).ok()
}

/// The body the credential parser reads for a verified response: the same request with its
/// `postBody` replaced by the provider, the `NameID` as the subject, and the assertion's
/// subject and attributes as the emulator's SAML form. Nothing of the original `postBody`
/// is kept (the response was the only credential it carried), and the `requestUri` loses its
/// query and fragment, which the parser reads as parameters too (the fragment over the
/// `postBody`): a subject or email there would replace the verified `NameID`.
fn credential_body(
    body: &Value,
    provider_id: &str,
    name_id: &str,
    verified: &VerifiedSaml,
) -> Value {
    let attributes: BTreeMap<&str, Value> = verified
        .attributes
        .iter()
        .map(|(name, values)| {
            let value = match values.as_slice() {
                [single] => json!(single),
                many => json!(many),
            };
            (name.as_str(), value)
        })
        .collect();
    let assertion = json!({
        "assertion": {
            "subject": { "nameId": name_id },
            "attributeStatements": if attributes.is_empty() { Value::Null } else { json!(attributes) },
        }
    });
    let claims = json!({ "sub": name_id });
    let post_body = format!(
        "providerId={}&id_token={}&SAMLResponse={}",
        form_encode(provider_id),
        form_encode(&claims.to_string()),
        form_encode(&assertion.to_string()),
    );
    let request_uri = str_field(body, "requestUri").unwrap_or_default();
    let bare_uri = request_uri.split(['?', '#']).next().unwrap_or_default();
    let mut rewritten = body.clone();
    if let Some(object) = rewritten.as_object_mut() {
        object.insert("requestUri".to_owned(), json!(bare_uri));
        object.insert("postBody".to_owned(), json!(post_body));
    }
    rewritten
}
