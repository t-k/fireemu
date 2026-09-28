//! The strict profile verifies a `saml.*` provider's signed `SAMLResponse` with the provider's
//! configured certificates (AUTH-FEDERATION, owner decision O5 stage B); the emulator profile
//! keeps the official emulator's JSON fixture. Refusals rest on production evidence or the
//! public documentation only: a signature that does not verify (production's message, the
//! saml-smoke run of 2026-09-27) and a missing `NameID`. Conditions whose production handling is
//! unobserved (audience, destination, time windows, `InResponseTo`) are not enforced, and the
//! tests fix that.
use fireemu_adapter_http::identity_toolkit::{
    handle, AuthState, IdpAssertionPolicy, IdpContinuationPolicy, IdpSignerTrust, JsonResponse,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, InboundSamlProviderConfig, UserRecord};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::hash::base64_standard;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const PROVIDER: &str = "saml.strict";
const SIGNATURE_REFUSAL: &str =
    "INVALID_IDP_RESPONSE : Failed to verify the signature in SAMLResponse";
const CALLBACK: &str = "https://demo-app.firebaseapp.com/__/auth/handler";
// Production's configuration refusals (record-oidc 39209e, the same for every provider type).
const NOT_FOUND: &str = "OPERATION_NOT_ALLOWED : The identity provider configuration is not found.";
const DISABLED: &str = "OPERATION_NOT_ALLOWED : The identity provider configuration is disabled.";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/data/saml/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn provider(enabled: bool, certificate: &str) -> InboundSamlProviderConfig {
    InboundSamlProviderConfig {
        id: PROVIDER.into(),
        display_name: None,
        enabled,
        idp_entity_id: "https://idp.example.test/saml/fixture".into(),
        sso_url: "https://idp.example.test/saml/fixture/sso".into(),
        idp_certificates: vec![fixture(certificate)],
        sign_request: false,
        // Neither the audience nor the callback of the vectors: production's checks of them
        // are unobserved, so strict does not refuse on them.
        sp_entity_id: "another-sp".into(),
        callback_uri: "https://another.example.test/__/auth/handler".into(),
    }
}

fn state(strict: bool) -> AuthState {
    let s = AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        notices: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: !strict,
        idp_continuations: IdpContinuationPolicy::Disabled,
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        // Strict with no OIDC issuer keys: SAML needs none (its certificates are the provider's).
        idp_assertions: if strict {
            IdpAssertionPolicy::SignedOidc(Arc::new(IdpSignerTrust::default()))
        } else {
            IdpAssertionPolicy::Fixture
        },
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    assert!(s
        .store
        .lock()
        .unwrap()
        .create_saml_config(provider(true, "idp.cert.pem")));
    s
}

fn request_for(provider: &str, saml_response: &str) -> Value {
    json!({
        "requestUri": CALLBACK,
        "postBody": format!(
            "providerId={provider}&SAMLResponse={}",
            saml_response.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
        ),
        "returnSecureToken": true,
    })
}

fn request(xml: &str) -> Value {
    request_for(PROVIDER, &base64_standard(xml.as_bytes()))
}

fn sign_in(s: &AuthState, body: &Value) -> JsonResponse {
    handle(s, "POST", &format!("{V1}/accounts:signInWithIdp"), body)
}

fn claims(id_token: &Value) -> Value {
    let payload = id_token.as_str().unwrap().split('.').nth(1).unwrap();
    serde_json::from_slice(&fireemu_core_auth::jwt::base64url_decode(payload).unwrap()).unwrap()
}

fn assert_refused(s: &AuthState, body: &Value, message: &str, case: &str) {
    let response = sign_in(s, body);
    assert_eq!(response.status, 400, "{case}: {}", response.body);
    assert_eq!(response.body["error"]["message"], message, "{case}");
    assert!(response.body.get("idToken").is_none(), "{case}");
    assert_eq!(s.store.lock().unwrap().user_count(), 0, "{case}");
}

#[test]
fn a_response_signed_in_each_position_signs_in_as_production_answers() {
    for position in ["assertion", "response", "both"] {
        let s = state(true);
        let first = sign_in(&s, &request(&fixture(&format!("{position}-signed.xml"))));
        assert_eq!(first.status, 200, "{position}: {}", first.body);
        assert_eq!(first.body["providerId"], PROVIDER);
        assert_eq!(
            first.body["federatedId"],
            format!("{PROVIDER}/fixture-user@example.com")
        );
        assert_eq!(first.body["email"], "fixture-user@example.com");
        assert_eq!(first.body["emailVerified"], true);
        assert_eq!(first.body["isNewUser"], true);
        let firebase = &claims(&first.body["idToken"])["firebase"];
        assert_eq!(firebase["sign_in_provider"], PROVIDER);
        assert_eq!(
            firebase["identities"][PROVIDER],
            json!(["fixture-user@example.com"])
        );
        let again = sign_in(
            &s,
            &request(&fixture(&format!("{position}-signed-noisy.xml"))),
        );
        assert_eq!(again.status, 200, "{position}: {}", again.body);
        assert_eq!(again.body["localId"], first.body["localId"]);
        assert_eq!(s.store.lock().unwrap().user_count(), 1);
    }
}

#[test]
fn the_attributes_of_a_verified_assertion_are_its_sign_in_attributes() {
    let s = state(true);
    let response = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        claims(&response.body["idToken"])["firebase"]["sign_in_attributes"],
        json!({"display name": "Fixture \"User\"", "role": "reader & <writer>"})
    );
}

#[test]
fn a_signature_that_does_not_verify_is_refused_with_productions_message() {
    for name in [
        "tampered-signature.xml",
        "tampered-content.xml",
        "other-key.xml",
        "unsigned.xml",
        "wrapped.xml",
    ] {
        let s = state(true);
        let response = sign_in(&s, &request(&fixture(name)));
        if name == "wrapped.xml" {
            // The unsigned assertion beside the signed one is never read.
            assert_eq!(response.status, 200, "{}", response.body);
            assert_eq!(response.body["email"], "fixture-user@example.com");
            continue;
        }
        assert_refused(&s, &request(&fixture(name)), SIGNATURE_REFUSAL, name);
    }
}

#[test]
fn strict_refuses_what_it_cannot_verify() {
    let s = state(true);
    let fixture_json =
        json!({"assertion": {"subject": {"nameId": "fixture@example.com"}}}).to_string();
    let cases = [
        (
            "the emulator's JSON fixture",
            request_for(PROVIDER, &fixture_json),
        ),
        (
            "no SAMLResponse",
            json!({"requestUri": CALLBACK, "postBody": format!("providerId={PROVIDER}&id_token=%7B%22sub%22%3A%22x%22%7D"), "returnSecureToken": true}),
        ),
        ("not base64", request_for(PROVIDER, "%%%")),
        ("no NameID", request(&fixture("no-name-id.xml"))),
    ];
    for (case, body) in cases {
        assert_refused(&s, &body, "INVALID_IDP_RESPONSE", case);
    }
    for (case, provider) in [
        ("a provider named in another case", "saml.Strict"),
        ("an unconfigured provider", "saml.unconfigured"),
    ] {
        assert_refused(
            &s,
            &request_for(
                provider,
                &base64_standard(fixture("assertion-signed.xml").as_bytes()),
            ),
            NOT_FOUND,
            case,
        );
    }
    // Even with a configuration stored under the mixed-case ID: the credential parser
    // lowercases the provider, so the verified provider would not be the one recorded.
    let mut mixed = provider(true, "idp.cert.pem");
    mixed.id = "saml.Strict".into();
    assert!(s.store.lock().unwrap().create_saml_config(mixed));
    assert_refused(
        &s,
        &request_for(
            "saml.Strict",
            &base64_standard(fixture("assertion-signed.xml").as_bytes()),
        ),
        NOT_FOUND,
        "a mixed-case provider with a configuration",
    );
    s.store
        .lock()
        .unwrap()
        .replace_saml_config(provider(false, "idp.cert.pem"));
    assert_refused(
        &s,
        &request(&fixture("assertion-signed.xml")),
        DISABLED,
        "a disabled provider",
    );
    // Another provider's certificate: the signature does not verify.
    s.store
        .lock()
        .unwrap()
        .replace_saml_config(provider(true, "other.cert.pem"));
    assert_refused(
        &s,
        &request(&fixture("assertion-signed.xml")),
        SIGNATURE_REFUSAL,
        "another certificate",
    );
}

#[test]
fn the_emulator_profile_keeps_the_official_emulators_json_fixture() {
    let s = state(false);
    let body = json!({
        "requestUri": CALLBACK,
        "postBody": format!(
            "providerId={PROVIDER}&id_token=%7B%22sub%22%3A%22fixture%22%7D&SAMLResponse={}",
            "%7B%22assertion%22%3A%7B%22subject%22%3A%7B%22nameId%22%3A%22fixture%40example.com%22%7D%7D%7D"
        ),
        "returnSecureToken": true,
    });
    let response = sign_in(&s, &body);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["email"], "fixture@example.com");
}

fn continuation(value: &Value) -> Value {
    json!({"requestUri": CALLBACK, "pendingToken": value, "returnSecureToken": true})
}

#[test]
fn a_continuation_verifies_the_signed_response_again() {
    let mut s = state(true);
    s.idp_continuations = IdpContinuationPolicy::LocalBounded;
    let first = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(first.status, 200, "{}", first.body);
    let pending = first.body["pendingToken"].clone();
    assert!(pending.is_string());
    let resumed = sign_in(&s, &continuation(&pending));
    assert_eq!(resumed.status, 200, "{}", resumed.body);
    assert_eq!(resumed.body["localId"], first.body["localId"]);
    // The provider's certificate rotated: the stored response no longer verifies.
    s.store
        .lock()
        .unwrap()
        .replace_saml_config(provider(true, "other.cert.pem"));
    let refused = sign_in(&s, &continuation(&pending));
    assert_eq!(refused.status, 400);
    assert_eq!(refused.body["error"]["message"], SIGNATURE_REFUSAL);
}

/// A blocking hook that disables the provider while it runs, as a concurrent Admin PATCH would.
struct DisableProviderDuringHook {
    store: Arc<Mutex<AuthStore>>,
}

impl fireemu_adapter_http::identity_toolkit::AuthBlockingHook for DisableProviderDuringHook {
    fn invoke(
        &self,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
        _user: &UserRecord,
    ) -> Result<Value, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
        Ok(json!({}))
    }

    fn invoke_for_with_context(
        &self,
        _project: &str,
        _tenant: Option<&str>,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
        _user: &UserRecord,
        _context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    ) -> Result<Option<Value>, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure>
    {
        self.store
            .lock()
            .unwrap()
            .replace_saml_config(provider(false, "idp.cert.pem"));
        Ok(Some(json!({})))
    }
}

#[test]
fn a_blocking_function_commit_verifies_the_response_against_the_live_provider() {
    let mut s = state(true);
    s.blocking = Some(Arc::new(DisableProviderDuringHook {
        store: s.store.clone(),
    }));
    let response = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(response.status, 400, "{}", response.body);
    assert_eq!(response.body["error"]["message"], "INVALID_IDP_RESPONSE");
    assert_eq!(s.store.lock().unwrap().user_count(), 0);
}

#[test]
fn a_saml_sign_up_counts_toward_the_sign_up_quota() {
    let s = state(true);
    s.store
        .lock()
        .unwrap()
        .set_signup_quota_config(fireemu_core_auth::signup_quota::SignupQuotaConfig {
            mode: fireemu_core_auth::signup_quota::QuotaMode::Enforce,
            default_quota_per_hour: 1,
            ..Default::default()
        })
        .unwrap();
    let signup = handle(
        &s,
        "POST",
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "first@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(signup.status, 200, "{}", signup.body);
    // The verified response would create a second account: the quota refuses it.
    let response = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(response.status, 400, "{}", response.body);
    assert_eq!(response.body["error"]["message"], "SIGNUP_QUOTA_EXCEEDED");
    assert!(
        response.body.get("federatedId").is_none(),
        "{}",
        response.body
    );
    assert_eq!(s.store.lock().unwrap().user_count(), 1);
}

#[test]
fn nothing_outside_the_verified_response_names_the_subject() {
    // The credential parser reads the `requestUri` query and fragment too (the fragment over
    // `postBody`): a subject or email there must not replace the verified `NameID`.
    let injected =
        "%7B%22sub%22%3A%22victim-subject%22%2C%22email%22%3A%22victim%40example.com%22%7D";
    let mut s = state(true);
    s.idp_continuations = IdpContinuationPolicy::LocalBounded;
    let genuine = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(genuine.status, 200, "{}", genuine.body);
    for suffix in [
        format!("#id_token={injected}"),
        format!("?id_token={injected}"),
        format!("#id_token=x&access_token={injected}"),
        format!("?access_token={injected}#id_token={injected}"),
    ] {
        let mut body = request(&fixture("assertion-signed.xml"));
        body["requestUri"] = json!(format!("{CALLBACK}{suffix}"));
        for (step, response) in [
            ("sign-in", sign_in(&s, &body)),
            ("continuation", {
                let first = sign_in(&s, &body);
                assert_eq!(first.status, 200, "{suffix}: {}", first.body);
                let mut resume = continuation(&first.body["pendingToken"]);
                resume["requestUri"] = body["requestUri"].clone();
                sign_in(&s, &resume)
            }),
        ] {
            assert_eq!(response.status, 200, "{suffix} {step}: {}", response.body);
            assert_eq!(
                response.body["localId"], genuine.body["localId"],
                "{suffix} {step}"
            );
            assert_eq!(
                response.body["email"], "fixture-user@example.com",
                "{suffix} {step}"
            );
            assert_eq!(
                claims(&response.body["idToken"])["firebase"]["identities"][PROVIDER],
                json!(["fixture-user@example.com"]),
                "{suffix} {step}"
            );
        }
    }
    assert_eq!(s.store.lock().unwrap().user_count(), 1);
}

#[test]
fn a_blocking_function_that_leaves_the_provider_alone_commits_the_sign_in() {
    let mut s = state(true);
    s.blocking = Some(Arc::new(LeaveProviderAlone));
    let response = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(s.store.lock().unwrap().user_count(), 1);
}

/// A blocking hook that allows the sign-in and changes nothing.
struct LeaveProviderAlone;

impl fireemu_adapter_http::identity_toolkit::AuthBlockingHook for LeaveProviderAlone {
    fn invoke(
        &self,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
        _user: &UserRecord,
    ) -> Result<Value, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
        Ok(json!({}))
    }

    fn invoke_for_with_context(
        &self,
        _project: &str,
        _tenant: Option<&str>,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
        _user: &UserRecord,
        _context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    ) -> Result<Option<Value>, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure>
    {
        Ok(Some(json!({})))
    }
}

#[test]
fn the_encoded_response_limit_counts_what_is_sent() {
    // Whitespace in the encoded response (line breaks of a MIME encoder) is ignored when
    // decoding but counts toward the limit of what is read.
    const MAX_ENCODED: usize = fireemu_adapter_http::saml::MAX_RESPONSE_BYTES / 3 * 4 + 4;
    let encoded = base64_standard(fixture("assertion-signed.xml").as_bytes());
    let padded = |length: usize| {
        let body = request_for(PROVIDER, "");
        let post_body = body["postBody"].as_str().unwrap().to_owned();
        let mut body = body.clone();
        body["postBody"] = json!(format!(
            "{post_body}{}{}",
            encoded
                .replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D"),
            "%0A".repeat(length - encoded.len())
        ));
        body
    };
    let s = state(true);
    let response = sign_in(&s, &padded(MAX_ENCODED));
    assert_eq!(response.status, 200, "{}", response.body);
    let s = state(true);
    assert_refused(
        &s,
        &padded(MAX_ENCODED + 1),
        "INVALID_IDP_RESPONSE",
        "one character over",
    );
}

#[test]
fn no_other_field_or_parameter_names_the_subject() {
    let injected = "%7B%22sub%22%3A%22victim-subject%22%7D";
    let encoded = base64_standard(fixture("assertion-signed.xml").as_bytes())
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    let s = state(true);
    let genuine = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(genuine.status, 200, "{}", genuine.body);
    let cases = [
        (
            "id_token after the response",
            json!({"requestUri": CALLBACK, "postBody": format!("providerId={PROVIDER}&SAMLResponse={encoded}&id_token={injected}"), "returnSecureToken": true}),
        ),
        (
            "access and refresh tokens",
            json!({"requestUri": CALLBACK, "postBody": format!("providerId={PROVIDER}&SAMLResponse={encoded}&access_token={injected}&refresh_token=r"), "returnSecureToken": true}),
        ),
        (
            "an encoded fragment and query in the path",
            json!({"requestUri": format!("{CALLBACK}%23id_token={injected}%3Fid_token={injected}"), "postBody": format!("providerId={PROVIDER}&SAMLResponse={encoded}"), "returnSecureToken": true}),
        ),
        (
            "the response in the fragment, a token in the query",
            json!({"requestUri": format!("{CALLBACK}?id_token={injected}#providerId={PROVIDER}&SAMLResponse={encoded}"), "postBody": "", "returnSecureToken": true}),
        ),
        (
            "top-level fields",
            json!({"requestUri": CALLBACK, "postBody": format!("providerId={PROVIDER}&SAMLResponse={encoded}"), "id_token": {"sub": "victim-subject"}, "email": "victim@example.com", "sessionId": "victim", "returnSecureToken": true}),
        ),
    ];
    for (case, body) in cases {
        let response = sign_in(&s, &body);
        assert_eq!(response.status, 200, "{case}: {}", response.body);
        assert_eq!(response.body["localId"], genuine.body["localId"], "{case}");
        assert_eq!(response.body["email"], "fixture-user@example.com", "{case}");
        assert_eq!(
            claims(&response.body["idToken"])["firebase"]["identities"][PROVIDER],
            json!(["fixture-user@example.com"]),
            "{case}"
        );
    }
    assert_eq!(s.store.lock().unwrap().user_count(), 1);
}

/// The data of raw DEFLATE stored blocks (what fireemu's SAML requests use).
fn inflate_stored(mut bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let (header, rest) = bytes.split_first().unwrap();
        assert_eq!(header & 0b110, 0, "a stored block");
        let len = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
        let nlen = u16::from_le_bytes([rest[2], rest[3]]);
        assert_eq!(!nlen, u16::try_from(len).unwrap());
        out.extend_from_slice(&rest[4..4 + len]);
        bytes = &rest[4 + len..];
        if header & 1 == 1 {
            assert!(bytes.is_empty());
            return out;
        }
    }
}

fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn create_auth_uri(s: &AuthState, body: &Value) -> JsonResponse {
    handle(s, "POST", &format!("{V1}/accounts:createAuthUri"), body)
}

#[test]
fn strict_answers_create_auth_uri_for_a_saml_provider_as_production_does() {
    // saml-smoke (run efe0ef, 2026-09-27): the provider's SSO URL with a deflated, base64
    // AuthnRequest for the HTTP-POST binding and a relay state, and a session ID.
    let s = state(true);
    let answer = create_auth_uri(
        &s,
        &json!({"providerId": PROVIDER, "continueUri": CALLBACK}),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    let mut keys: Vec<&str> = answer
        .body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["authUri", "kind", "providerId", "sessionId"]);
    assert_eq!(answer.body["kind"], "identitytoolkit#CreateAuthUriResponse");
    assert_eq!(answer.body["providerId"], PROVIDER);
    let uri = answer.body["authUri"].as_str().unwrap();
    let query = uri
        .strip_prefix("https://idp.example.test/saml/fixture/sso?SAMLRequest=")
        .unwrap_or_else(|| panic!("{uri}"));
    let (request, relay) = query.split_once("&RelayState=").unwrap();
    assert!(!relay.is_empty() && !relay.contains('&'), "{uri}");
    assert!(
        !request.contains(['+', '/', '=']),
        "percent-encoded: {request}"
    );
    let deflated = fireemu_core_auth::jwt::base64url_decode(
        percent_decoded(request)
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('='),
    )
    .unwrap();
    let xml = String::from_utf8(inflate_stored(&deflated)).unwrap();
    let (head, rest) = xml.split_once(" ID=\"_").unwrap_or_else(|| panic!("{xml}"));
    assert_eq!(
        head,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:AuthnRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"https://another.example.test/__/auth/handler\" Destination=\"https://idp.example.test/saml/fixture/sso\""
    );
    let (id, rest) = rest.split_once('"').unwrap();
    assert_eq!(id.len(), 32, "{xml}");
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "{xml}"
    );
    assert_eq!(
        rest,
        " IssueInstant=\"2026-08-29T12:01:00.000Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">another-sp</saml2:Issuer></saml2p:AuthnRequest>"
    );
    let again = create_auth_uri(
        &s,
        &json!({"providerId": PROVIDER, "continueUri": CALLBACK}),
    );
    assert_ne!(again.body["sessionId"], answer.body["sessionId"]);
    assert_ne!(again.body["authUri"], answer.body["authUri"]);
}

#[test]
fn strict_create_auth_uri_for_a_saml_provider_refuses_as_for_oidc() {
    let s = state(true);
    let missing = create_auth_uri(&s, &json!({"providerId": PROVIDER}));
    assert_eq!(missing.status, 400, "{}", missing.body);
    assert_eq!(missing.body["error"]["message"], "MISSING_CONTINUE_URI");
    s.store
        .lock()
        .unwrap()
        .replace_saml_config(provider(false, "idp.cert.pem"));
    let disabled = create_auth_uri(
        &s,
        &json!({"providerId": PROVIDER, "continueUri": CALLBACK}),
    );
    assert_eq!(disabled.status, 400, "{}", disabled.body);
    assert_eq!(disabled.body["error"]["message"], DISABLED);
    // A signed request needs the SP's key, which fireemu does not make: not implemented.
    let mut signing = provider(true, "idp.cert.pem");
    signing.sign_request = true;
    s.store.lock().unwrap().replace_saml_config(signing);
    let signed = create_auth_uri(
        &s,
        &json!({"providerId": PROVIDER, "continueUri": CALLBACK}),
    );
    assert_eq!(signed.status, 501, "{}", signed.body);
    // The emulator profile answers as the official emulator does.
    let emulator = state(false);
    let answer = create_auth_uri(
        &emulator,
        &json!({"providerId": PROVIDER, "continueUri": CALLBACK}),
    );
    assert_eq!(answer.status, 501, "{}", answer.body);
}
