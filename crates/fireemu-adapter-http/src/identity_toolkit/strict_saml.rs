//! Strict SAML sign-in (AUTH-FEDERATION, owner decision O5 stage B): the signed `SAMLResponse`
//! of a `saml.*` provider is verified with the provider's configured certificates before any
//! mutation, and only what the verified assertion says reaches the sign-in.
//!
//! Refusals rest on production evidence or the public documentation only (the coordinator's
//! condition): a signature that does not verify, or none (production's
//! `INVALID_IDP_RESPONSE : Failed to verify the signature in SAMLResponse`, saml-smoke run
//! efe0ef, 2026-09-27; "If verification fails, the response will be rejected"), and a
//! missing `NameID` ("Identity Platform expects the <saml:Subject> and <saml:NameID>
//! elements"). The response's status, destination, assertion issuer, audience, time windows
//! and `InResponseTo` are checked with production's messages (record-saml 7789f0,
//! 2026-09-28); the `Recipient` and the certificate's validity period are not (production
//! accepted both).

use std::collections::BTreeMap;

use fireemu_core_auth::store::AuthStore;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

use super::{
    error, form_encode, normalized_idp_params, str_field, uri_is_absolute, IdpSignerTrust,
    JsonResponse,
};
use crate::saml::{verify_saml_response, SamlError, VerifiedSaml};

/// Production's refusal of a response whose signature does not verify (saml-smoke).
pub(super) const SIGNATURE_REFUSAL: &str =
    "INVALID_IDP_RESPONSE : Failed to verify the signature in SAMLResponse";

/// How long a strict `createAuthUri`'s `AuthnRequest` ID is remembered for its session, in
/// seconds (an emulator bound: past it, a response is not checked against the request).
const REQUEST_LIFETIME: i64 = 3_600;

/// Production's refusal of a response with no signature at all (record-followup b72af6).
pub(super) const UNSIGNED_REFUSAL: &str =
    "INVALID_IDP_RESPONSE : Missing signature in Assertion and Response enclosing it (if present).";

/// The largest `SAMLResponse` read, as sent (base64 of at most 256 KiB of XML).
const MAX_ENCODED: usize = crate::saml::MAX_RESPONSE_BYTES / 3 * 4 + 4;

/// A response the strict daemon verified, kept to verify again against the live
/// configuration when a blocking function commits (the hook runs unlocked).
#[derive(Debug, Clone)]
pub(super) struct StrictSaml {
    provider_id: String,
    xml: String,
    name_id: String,
    /// The instant the request was verified at. The commit checks the provider's live
    /// configuration against the response at this instant, so the time windows are read once,
    /// when the request starts.
    at: LogicalInstant,
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

    /// Whether the provider still exists and is enabled, its certificates still verify the
    /// response (the same document names the same subject), and the response still names the
    /// provider's callback URL, identity provider and SP entity IDs (closure review N10, N-d).
    /// The time windows are evaluated at the instant the request was verified, and `InResponseTo`
    /// was checked then, so a slow blocking function never turns a valid sign-in into a refusal
    /// on its own; only a configuration that changed while it ran does.
    pub(super) fn accepts(&self, store: &AuthStore) -> bool {
        let Ok(verified) = verified_against(store, &self.provider_id, &self.xml) else {
            return false;
        };
        let Some(config) = store.saml_config(&self.provider_id) else {
            return false;
        };
        let expected = Expected {
            callback_uri: &config.callback_uri,
            idp_entity_id: &config.idp_entity_id,
            sp_entity_id: &config.sp_entity_id,
            request_id: None,
        };
        check_conditions(&verified, &expected, self.at).is_ok()
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
/// certificate verifies a signature covering the assertion; production's configuration
/// messages for a provider that is missing, named in another case or disabled;
/// `INVALID_IDP_RESPONSE` for a missing or unreadable response, one without a `NameID`, or a
/// form this verifier does not implement (codes unobserved); and production's messages for
/// the conditions of [`check_conditions`]. A resumed continuation checks them again against the
/// live configuration, all but `InResponseTo` (closure review SF5: production's continuation is
/// unobserved, and a response past its window or for another SP is not honoured).
pub(super) fn strict_saml(
    store: &AuthStore,
    body: &Value,
    signers: &IdpSignerTrust,
    at: LogicalInstant,
    resumed: bool,
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
    // A provider without a configuration, or disabled, is refused with production's
    // configuration messages (record-oidc 39209e, as for OIDC and built-in providers).
    if *provider_id != provider_id.to_lowercase() {
        return Err(error(400, crate::oidc::NOT_FOUND_REFUSAL));
    }
    match store.saml_config(provider_id) {
        None => return Err(error(400, crate::oidc::NOT_FOUND_REFUSAL)),
        Some(config) if !config.enabled => {
            return Err(error(400, crate::oidc::DISABLED_REFUSAL));
        }
        Some(_) => {}
    }
    let encoded = params
        .get("SAMLResponse")
        .filter(|value| !value.is_empty() && value.len() <= MAX_ENCODED)
        .ok_or_else(refused)?;
    let xml = decode_response(encoded).ok_or_else(refused)?;
    let verified = verified_against(store, provider_id, &xml).map_err(|failure| match failure {
        Some(SamlError::Signature) => error(400, SIGNATURE_REFUSAL),
        Some(SamlError::Unsigned) => error(400, UNSIGNED_REFUSAL),
        _ => refused(),
    })?;
    let name_id = verified
        .name_id
        .clone()
        .filter(|name| !name.chars().any(char::is_control))
        .ok_or_else(refused)?;
    if let Some(config) = store.saml_config(provider_id) {
        let now = at.as_nanos().div_euclid(1_000_000_000);
        // A resumed continuation checks everything again against the live configuration but
        // InResponseTo, which the sign-in that made it checked (closure review SF5).
        let request_id = str_field(body, "sessionId")
            .filter(|id| !resumed && !id.is_empty())
            .and_then(|id| signers.saml_request(&session_key(store, id), i64::try_from(now).ok()?));
        let expected = Expected {
            callback_uri: &config.callback_uri,
            idp_entity_id: &config.idp_entity_id,
            sp_entity_id: &config.sp_entity_id,
            request_id: request_id.as_deref(),
        };
        if let Err(message) = check_conditions(&verified, &expected, at) {
            return Err(error(400, &message));
        }
    }
    let rewritten = credential_body(body, provider_id, &name_id, &verified);
    Ok(Some((
        StrictSaml {
            provider_id: provider_id.clone(),
            xml,
            name_id,
            at,
        },
        rewritten,
    )))
}

/// What a response must name: the provider's configuration and, for a session this daemon
/// issued, its `AuthnRequest` ID.
struct Expected<'a> {
    callback_uri: &'a str,
    idp_entity_id: &'a str,
    sp_entity_id: &'a str,
    request_id: Option<&'a str>,
}

/// Production's checks of a verified response (record-saml 7789f0), each only when the
/// element is present (a response without it is unobserved): a status other than success,
/// a `Destination` other than the callback URL, an assertion `Issuer` other than the identity
/// provider's entity ID, audience restrictions without the SP entity ID, `Conditions` not yet valid or
/// expired, an expired bearer confirmation, and, for a session whose request this daemon
/// issued, `InResponseTo` missing from or other than the request in the response or the
/// confirmation. A time that does not parse is not checked (unobserved).
///
/// # Errors
/// Production's `INVALID_IDP_RESPONSE : …` message of the first failing check.
fn check_conditions(
    verified: &VerifiedSaml,
    expected: &Expected<'_>,
    at: LogicalInstant,
) -> Result<(), String> {
    const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
    if let Some(status) = verified
        .status
        .as_deref()
        .filter(|status| *status != SUCCESS)
    {
        return Err(format!(
            "INVALID_IDP_RESPONSE : SAMLResponse status code not SUCCESS, instead it is: {status}"
        ));
    }
    if let Some(destination) = verified
        .destination
        .as_deref()
        .filter(|destination| *destination != expected.callback_uri)
    {
        return Err(format!(
            "INVALID_IDP_RESPONSE : SAMLResponse destination {destination} does not match RP callback URL {}.",
            expected.callback_uri
        ));
    }
    if let Some(issuer) = verified
        .issuer
        .as_deref()
        .filter(|issuer| *issuer != expected.idp_entity_id)
    {
        return Err(format!(
            "INVALID_IDP_RESPONSE : Assertion has Issuer {issuer} which is different from expected Issuer {}.",
            expected.idp_entity_id
        ));
    }
    if !verified.audiences.is_empty()
        && !verified
            .audiences
            .iter()
            .any(|audience| audience == expected.sp_entity_id)
    {
        return Err(format!(
            "INVALID_IDP_RESPONSE : All <AudienceRestriction>s should contain the SAML RP entity ID: '{}'.",
            expected.sp_entity_id
        ));
    }
    let now = issue_instant(at).unwrap_or_default();
    if let Some(not_before) = parsed_time(verified.not_before.as_deref()) {
        if at < not_before {
            return Err(format!(
                "INVALID_IDP_RESPONSE : Current instant, {now}, is before NotBefore attribute, {}",
                issue_instant(not_before).unwrap_or_default()
            ));
        }
    }
    for not_on_or_after in [
        verified.not_on_or_after.as_deref(),
        verified.confirmation_not_on_or_after.as_deref(),
    ] {
        if let Some(not_on_or_after) = parsed_time(not_on_or_after) {
            if at >= not_on_or_after {
                return Err(format!(
                    "INVALID_IDP_RESPONSE : Current instant, {now}, is on or after NotOnOrAfter attribute, {}",
                    issue_instant(not_on_or_after).unwrap_or_default()
                ));
            }
        }
    }
    if let Some(request_id) = expected.request_id {
        let answered = [
            verified.in_response_to.as_deref(),
            verified.confirmation_in_response_to.as_deref(),
        ];
        if answered.iter().any(Option::is_none) {
            return Err("INVALID_IDP_RESPONSE : InResponseTo attribute must be present in both Response and SubjectConfirmationData.".to_owned());
        }
        if answered.iter().any(|id| *id != Some(request_id)) {
            return Err("INVALID_IDP_RESPONSE : InResponseTo in both Response and SubjectConfirmationData must match the request ID.".to_owned());
        }
    }
    Ok(())
}

fn parsed_time(value: Option<&str>) -> Option<LogicalInstant> {
    LogicalInstant::parse_rfc3339(value?).ok()
}

/// The key a session's `AuthnRequest` ID is remembered by: the namespace (and its reset
/// generation) and the session ID `createAuthUri` answered.
fn session_key(store: &AuthStore, session_id: &str) -> String {
    json!([
        store.project_id(),
        store.tenant_id(),
        store.reset_generation(),
        session_id,
    ])
    .to_string()
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

/// Production's `createAuthUri` for a SAML provider (saml-smoke, run efe0ef): the provider's
/// SSO URL with an unsigned `AuthnRequest` for the HTTP-POST binding (to the continue URI,
/// as production's names it (record-saml 7789f0), from the provider's SP entity ID), raw-deflated and base64-encoded, and a relay state;
/// and a session ID. `None` for a provider whose requests are signed (fireemu makes no SP key;
/// not implemented).
pub(super) fn strict_saml_auth_uri(
    store: &mut AuthStore,
    provider_id: &str,
    body: &Value,
    at: LogicalInstant,
    signers: Option<&IdpSignerTrust>,
) -> Option<JsonResponse> {
    let config = store.saml_config(provider_id)?.clone();
    let Some(continue_uri) = str_field(body, "continueUri").filter(|uri| !uri.is_empty()) else {
        return Some(error(400, "MISSING_CONTINUE_URI"));
    };
    if !uri_is_absolute(continue_uri) {
        return Some(error(400, "INVALID_CONTINUE_URI"));
    }
    if !config.enabled {
        return Some(error(400, crate::oidc::DISABLED_REFUSAL));
    }
    if config.sign_request {
        return None;
    }
    let id = fireemu_core_types::hash::hex_lower(&fireemu_core_types::hash::sha256(
        store.next_opaque_value().as_bytes(),
    ));
    let request = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:AuthnRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"{}\" Destination=\"{}\" ID=\"_{}\" IssueInstant=\"{}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">{}</saml2:Issuer></saml2p:AuthnRequest>",
        xml_escape(continue_uri),
        xml_escape(&config.sso_url),
        &id[..32],
        issue_instant(at)?,
        xml_escape(&config.sp_entity_id),
    );
    let encoded = fireemu_core_types::hash::base64_standard(&deflate_stored(request.as_bytes()));
    let relay_state = store.next_opaque_value();
    let session_id = store.next_opaque_value();
    if let Some(signers) = signers {
        let now = i64::try_from(at.as_nanos().div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
        signers.record_saml_request(
            session_key(store, &session_id),
            format!("_{}", &id[..32]),
            now.saturating_add(REQUEST_LIFETIME),
            now,
        );
    }
    Some(JsonResponse {
        status: 200,
        body: json!({
            "kind": "identitytoolkit#CreateAuthUriResponse",
            "authUri": format!(
                "{}?SAMLRequest={}&RelayState={relay_state}",
                config.sso_url,
                encoded.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"),
            ),
            "providerId": provider_id,
            "sessionId": session_id,
        }),
    })
}

/// An `IssueInstant` as production writes it: UTC with milliseconds.
fn issue_instant(at: LogicalInstant) -> Option<String> {
    let nanos = at.as_nanos();
    let seconds = LogicalInstant::from_nanos(nanos - nanos.rem_euclid(1_000_000_000));
    let whole = seconds.to_rfc3339().ok()?;
    let millis = nanos.rem_euclid(1_000_000_000) / 1_000_000;
    Some(format!("{}.{millis:03}Z", whole.strip_suffix('Z')?))
}

/// XML text or attribute content with the markup characters escaped.
fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// Raw DEFLATE (RFC 1951) of `data` in stored blocks: valid for any inflater, with no
/// compression library (the SAML verifier's dependencies stay roxmltree only).
fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5 * (data.len() / 65_535 + 1));
    let mut chunks = data.chunks(65_535).peekable();
    if chunks.peek().is_none() {
        return vec![0x01, 0x00, 0x00, 0xff, 0xff];
    }
    while let Some(chunk) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        let len = u16::try_from(chunk.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::deflate_stored;

    #[test]
    fn stored_deflate_blocks_are_what_zlib_inflates() {
        // Vectors checked with an independent inflater (Python's zlib, raw window).
        assert_eq!(deflate_stored(b""), [0x01, 0x00, 0x00, 0xff, 0xff]);
        assert_eq!(
            deflate_stored(b"abc"),
            [0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c']
        );
        let long: Vec<u8> = (0..300).flat_map(|_| 0..=255_u8).collect();
        let encoded = deflate_stored(&long);
        assert_eq!(encoded.len(), 76_810);
        assert_eq!(encoded[..5], [0x00, 0xff, 0xff, 0x00, 0x00]);
        assert_eq!(encoded[65_540..65_545], [0x01, 0x01, 0x2c, 0xfe, 0xd3]);
        assert_eq!(encoded[5..65_540], long[..65_535]);
        assert_eq!(encoded[65_545..], long[65_535..]);
    }
}
