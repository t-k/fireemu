//! The strict profile verifies a `saml.*` provider's signed `SAMLResponse` with the provider's
//! configured certificates (AUTH-FEDERATION, owner decision O5 stage B); the emulator profile
//! keeps the official emulator's JSON fixture. Refusals rest on production evidence or the
//! public documentation only: a signature that does not verify (production's message, the
//! saml-smoke run of 2026-09-27), a missing `NameID`, and the conditions production refused
//! with its messages (record-saml 7789f0: status, destination, issuer, audience, time windows,
//! `InResponseTo`). The `Recipient` and an expired certificate are accepted, as production did.
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
/// 2027-01-15T08:00:30Z: within the signed vectors' validity (07:59 to 08:05).
const VECTOR_NOW: i64 = 1_800_000_030;
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
        // The audience and destination the signed vectors name.
        sp_entity_id: "fireemu-fixture-sp".into(),
        callback_uri: "https://demo-project.firebaseapp.com/__/auth/handler".into(),
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
            LogicalInstant::from_unix_seconds(VECTOR_NOW),
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
    // AuthnRequest for the HTTP-POST binding and a relay state, and a session ID. The ACS is the
    // continue URI, not the provider's callback URI (record-saml 7789f0).
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
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:AuthnRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"https://demo-app.firebaseapp.com/__/auth/handler\" Destination=\"https://idp.example.test/saml/fixture/sso\""
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
        " IssueInstant=\"2027-01-15T08:00:30.000Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">fireemu-fixture-sp</saml2:Issuer></saml2p:AuthnRequest>"
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

fn answer_keys(response: &JsonResponse) -> Vec<String> {
    let mut keys: Vec<String> = response.body.as_object().unwrap().keys().cloned().collect();
    keys.sort_unstable();
    keys
}

#[test]
fn strict_answers_a_saml_sign_in_in_productions_shape() {
    // record-saml 7789f0: the answer keeps an empty context and carries no OAuth token or raw
    // ID; `isNewUser` only when true.
    let s = state(true);
    let first = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(
        answer_keys(&first),
        [
            "context",
            "email",
            "emailVerified",
            "expiresIn",
            "federatedId",
            "idToken",
            "isNewUser",
            "kind",
            "localId",
            "providerId",
            "rawUserInfo",
            "refreshToken",
        ]
    );
    assert_eq!(first.body["context"], "");
    let again = sign_in(&s, &request(&fixture("assertion-signed-noisy.xml")));
    assert_eq!(again.status, 200, "{}", again.body);
    assert!(again.body.get("isNewUser").is_none(), "{}", again.body);
    // The attributes survive a refresh, as production's did.
    let refreshed = handle(
        &s,
        "POST",
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": first.body["refreshToken"]}),
    );
    assert_eq!(refreshed.status, 200, "{}", refreshed.body);
    assert_eq!(
        claims(&refreshed.body["id_token"])["firebase"]["sign_in_attributes"],
        json!({"display name": "Fixture \"User\"", "role": "reader & <writer>"})
    );
    // The account an SAML sign-in created reports its validSince.
    let lookup = handle(
        &s,
        "POST",
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": first.body["idToken"]}),
    );
    assert_eq!(lookup.status, 200, "{}", lookup.body);
    assert!(
        lookup.body["users"][0]["validSince"].is_string(),
        "{}",
        lookup.body
    );
}

// ---- SAML conditions (record-saml 7789f0): responses signed at the test ----------------------

const DYNAMIC: &str = "saml.dynamic";
const IDP: &str = "https://idp.example.test/saml/dynamic";
const SP: &str = "https://demo-app.firebaseapp.com/saml/dynamic";
const NOW: i64 = 1_788_004_860;

/// A DER element: tag, definite length, content.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap());
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// The test identity provider's key, and a certificate carrying its public key (the verifier reads only the
/// subjectPublicKeyInfo, so the rest is minimal and unsigned).
fn idp_key() -> (rsa::RsaPrivateKey, String) {
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
    let signer = fireemu_adapter_http::signing::RsaSigner::from_seed(7101).unwrap();
    let key =
        rsa::RsaPrivateKey::from_pkcs8_der(signer.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    let spki = key.to_public_key().to_public_key_der().unwrap();
    let tbs = [
        der(0xa0, &der(0x02, &[2])),
        der(0x02, &[1]),
        der(0x30, &[]),
        der(0x30, &[]),
        der(0x30, &[]),
        der(0x30, &[]),
        spki.as_bytes().to_vec(),
    ]
    .concat();
    let certificate = der(
        0x30,
        &[der(0x30, &tbs), der(0x30, &[]), der(0x03, &[0])].concat(),
    );
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_standard(&certificate)
    );
    (key, pem)
}

/// What a response says; each field departs from a valid answer to the request only when set.
#[derive(Clone)]
struct Conditions {
    in_response_to: Option<String>,
    /// Whether the `SubjectConfirmationData` names the request too.
    confirmation_answers: bool,
    destination: String,
    recipient: String,
    issuer: String,
    audience: String,
    not_before: i64,
    not_on_or_after: i64,
    confirmation_not_on_or_after: i64,
    status: String,
}

impl Conditions {
    fn answering(request: Option<&str>) -> Self {
        Self {
            in_response_to: request.map(str::to_owned),
            confirmation_answers: true,
            destination: CALLBACK.into(),
            recipient: CALLBACK.into(),
            issuer: IDP.into(),
            audience: SP.into(),
            not_before: NOW - 60,
            not_on_or_after: NOW + 300,
            confirmation_not_on_or_after: NOW + 300,
            status: "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
        }
    }
}

fn iso(seconds: i64) -> String {
    LogicalInstant::from_unix_seconds(seconds)
        .to_rfc3339()
        .unwrap()
}

/// A response with an assertion signed (enveloped, exclusive canonicalization, RSA-SHA256).
fn signed_response(key: &rsa::RsaPrivateKey, c: &Conditions) -> String {
    use rsa::signature::{SignatureEncoding, Signer};
    use sha2::{Digest, Sha256};
    let reply_to = |name: &str| {
        c.in_response_to
            .as_deref()
            .map_or_else(String::new, |id| format!(" {name}=\"{id}\""))
    };
    let unsigned = format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Destination=\"{dest}\" ID=\"_r1\"{irt} IssueInstant=\"{now}\" Version=\"2.0\"><saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{status}\"></samlp:StatusCode></samlp:Status><saml:Assertion ID=\"_a1\" IssueInstant=\"{now}\" Version=\"2.0\"><saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID>dynamic@example.com</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData{cirt} NotOnOrAfter=\"{cnoa}\" Recipient=\"{recipient}\"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{nb}\" NotOnOrAfter=\"{noa}\"><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>",
        dest = c.destination,
        irt = reply_to("InResponseTo"),
        cirt = if c.confirmation_answers { reply_to("InResponseTo") } else { String::new() },
        now = iso(NOW),
        status = c.status,
        issuer = c.issuer,
        cnoa = iso(c.confirmation_not_on_or_after),
        recipient = c.recipient,
        nb = iso(c.not_before),
        noa = iso(c.not_on_or_after),
        aud = c.audience,
    );
    let doc = roxmltree::Document::parse(&unsigned).unwrap();
    let assertion = doc
        .descendants()
        .find(|n| n.has_tag_name(("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")))
        .unwrap();
    let canonical =
        fireemu_adapter_http::saml::canonicalize(&unsigned, assertion, None, &[], false).unwrap();
    let digest = base64_standard(&Sha256::digest(canonical.as_bytes()));
    let signed_info_body = format!(
        "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#_a1\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"
    );
    let canonical_signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{signed_info_body}</ds:SignedInfo>"
    );
    let signature = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone())
        .sign(canonical_signed_info.as_bytes())
        .to_vec();
    let element = format!(
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>{signed_info_body}</ds:SignedInfo><ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>",
        base64_standard(&signature)
    );
    let marker = format!("<saml:Issuer>{}</saml:Issuer><saml:Subject>", c.issuer);
    unsigned.replacen(
        &marker,
        &format!(
            "<saml:Issuer>{}</saml:Issuer>{element}<saml:Subject>",
            c.issuer
        ),
        1,
    )
}

/// A strict state with the dynamic provider (the test identity provider's certificate and names).
fn dynamic_state() -> (AuthState, rsa::RsaPrivateKey) {
    let (key, pem) = idp_key();
    let s = state(true);
    *s.clock.lock().unwrap() = VirtualClock::new(LogicalInstant::from_unix_seconds(NOW));
    assert!(s
        .store
        .lock()
        .unwrap()
        .create_saml_config(InboundSamlProviderConfig {
            id: DYNAMIC.into(),
            display_name: None,
            enabled: true,
            idp_entity_id: IDP.into(),
            sso_url: "https://idp.example.test/saml/dynamic/sso".into(),
            idp_certificates: vec![pem],
            sign_request: false,
            sp_entity_id: SP.into(),
            callback_uri: CALLBACK.into(),
        }));
    (s, key)
}

/// A `createAuthUri` of the dynamic provider: its session ID and its `AuthnRequest` ID.
fn session(s: &AuthState) -> (String, String) {
    let answer = create_auth_uri(s, &json!({"providerId": DYNAMIC, "continueUri": CALLBACK}));
    assert_eq!(answer.status, 200, "{}", answer.body);
    let uri = answer.body["authUri"].as_str().unwrap();
    let request = uri
        .split("SAMLRequest=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let deflated = fireemu_core_auth::jwt::base64url_decode(
        percent_decoded(request)
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('='),
    )
    .unwrap();
    let xml = String::from_utf8(inflate_stored(&deflated)).unwrap();
    let id = xml
        .split(" ID=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    (answer.body["sessionId"].as_str().unwrap().to_owned(), id)
}

fn dynamic_request(xml: &str, session_id: Option<&str>) -> Value {
    let mut body = request_for(DYNAMIC, &base64_standard(xml.as_bytes()));
    if let Some(session_id) = session_id {
        body["sessionId"] = json!(session_id);
    }
    body
}

#[test]
fn strict_refuses_the_saml_conditions_production_refuses() {
    let (s, key) = dynamic_state();
    let (session_id, request_id) = session(&s);
    let valid = Conditions::answering(Some(&request_id));
    let ok = sign_in(
        &s,
        &dynamic_request(&signed_response(&key, &valid), Some(&session_id)),
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
    let now = "2026-08-29T12:01:00.000Z";
    let cases: Vec<(&str, Conditions, String)> = vec![
        (
            "audience",
            Conditions { audience: "https://other.example.test/sp".into(), ..valid.clone() },
            format!("INVALID_IDP_RESPONSE : All <AudienceRestriction>s should contain the SAML RP entity ID: '{SP}'."),
        ),
        (
            "destination",
            Conditions { destination: "https://demo-app.firebaseapp.com/__/auth/other".into(), ..valid.clone() },
            format!("INVALID_IDP_RESPONSE : SAMLResponse destination https://demo-app.firebaseapp.com/__/auth/other does not match RP callback URL {CALLBACK}."),
        ),
        (
            "not yet valid",
            Conditions { not_before: NOW + 600, ..valid.clone() },
            format!("INVALID_IDP_RESPONSE : Current instant, {now}, is before NotBefore attribute, 2026-08-29T12:11:00.000Z"),
        ),
        (
            "conditions expired",
            Conditions { not_before: NOW - 1200, not_on_or_after: NOW - 600, ..valid.clone() },
            format!("INVALID_IDP_RESPONSE : Current instant, {now}, is on or after NotOnOrAfter attribute, 2026-08-29T11:51:00.000Z"),
        ),
        (
            "confirmation expired",
            Conditions { confirmation_not_on_or_after: NOW - 600, ..valid.clone() },
            format!("INVALID_IDP_RESPONSE : Current instant, {now}, is on or after NotOnOrAfter attribute, 2026-08-29T11:51:00.000Z"),
        ),
        (
            "another request",
            Conditions { in_response_to: Some("_fireemu-other-request".into()), ..valid.clone() },
            "INVALID_IDP_RESPONSE : InResponseTo in both Response and SubjectConfirmationData must match the request ID.".into(),
        ),
        (
            "no request",
            Conditions { in_response_to: None, ..valid.clone() },
            "INVALID_IDP_RESPONSE : InResponseTo attribute must be present in both Response and SubjectConfirmationData.".into(),
        ),
        (
            "another issuer",
            Conditions { issuer: "https://idp.example.test/saml/other".into(), ..valid.clone() },
            format!("INVALID_IDP_RESPONSE : Assertion has Issuer https://idp.example.test/saml/other which is different from expected Issuer {IDP}."),
        ),
        (
            "status",
            Conditions { status: "urn:oasis:names:tc:SAML:2.0:status:Requester".into(), ..valid.clone() },
            "INVALID_IDP_RESPONSE : SAMLResponse status code not SUCCESS, instead it is: urn:oasis:names:tc:SAML:2.0:status:Requester".into(),
        ),
    ];
    for (case, conditions, message) in cases {
        let users = s.store.lock().unwrap().user_count();
        let answer = sign_in(
            &s,
            &dynamic_request(&signed_response(&key, &conditions), Some(&session_id)),
        );
        assert_eq!(answer.status, 400, "{case}: {}", answer.body);
        assert_eq!(answer.body["error"]["message"], message, "{case}");
        assert_eq!(s.store.lock().unwrap().user_count(), users, "{case}");
    }
    // Production does not check the Recipient.
    let recipient = Conditions {
        recipient: "https://demo-app.firebaseapp.com/__/auth/other".into(),
        ..valid
    };
    let answer = sign_in(
        &s,
        &dynamic_request(&signed_response(&key, &recipient), Some(&session_id)),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
}

#[test]
fn the_request_id_is_checked_only_for_a_session_this_daemon_issued() {
    // A sign-in naming no session, or one fireemu never issued, is unobserved: not refused.
    let (s, key) = dynamic_state();
    let unsolicited = Conditions::answering(Some("_whatever"));
    for session_id in [None, Some("fireemu-unknown-session")] {
        let answer = sign_in(
            &s,
            &dynamic_request(&signed_response(&key, &unsolicited), session_id),
        );
        assert_eq!(answer.status, 200, "{session_id:?}: {}", answer.body);
    }
}

#[test]
fn the_time_windows_include_not_before_and_exclude_not_on_or_after() {
    // Production's messages name the bounds: refused "before NotBefore" and "on or after
    // NotOnOrAfter".
    let (s, key) = dynamic_state();
    let (session_id, request_id) = session(&s);
    let valid = Conditions::answering(Some(&request_id));
    let at_start = Conditions {
        not_before: NOW,
        ..valid.clone()
    };
    let answer = sign_in(
        &s,
        &dynamic_request(&signed_response(&key, &at_start), Some(&session_id)),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    for (case, conditions) in [
        (
            "conditions",
            Conditions {
                not_on_or_after: NOW,
                ..valid.clone()
            },
        ),
        (
            "confirmation",
            Conditions {
                confirmation_not_on_or_after: NOW,
                ..valid.clone()
            },
        ),
    ] {
        let answer = sign_in(
            &s,
            &dynamic_request(&signed_response(&key, &conditions), Some(&session_id)),
        );
        assert_eq!(answer.status, 400, "{case}: {}", answer.body);
        assert_eq!(
            answer.body["error"]["message"],
            "INVALID_IDP_RESPONSE : Current instant, 2026-08-29T12:01:00.000Z, is on or after NotOnOrAfter attribute, 2026-08-29T12:01:00.000Z",
            "{case}"
        );
    }
}

#[test]
fn a_response_answers_the_request_of_its_own_session() {
    let (s, key) = dynamic_state();
    let (first, first_request) = session(&s);
    let (second, second_request) = session(&s);
    assert_ne!(first_request, second_request);
    let answer = sign_in(
        &s,
        &dynamic_request(
            &signed_response(&key, &Conditions::answering(Some(&first_request))),
            Some(&second),
        ),
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert_eq!(
        answer.body["error"]["message"],
        "INVALID_IDP_RESPONSE : InResponseTo in both Response and SubjectConfirmationData must match the request ID."
    );
    // Naming the request in the response alone is refused as absent ("in both").
    let partial = Conditions {
        confirmation_answers: false,
        ..Conditions::answering(Some(&first_request))
    };
    let answer = sign_in(
        &s,
        &dynamic_request(&signed_response(&key, &partial), Some(&first)),
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert_eq!(
        answer.body["error"]["message"],
        "INVALID_IDP_RESPONSE : InResponseTo attribute must be present in both Response and SubjectConfirmationData."
    );
}

#[test]
fn a_remembered_request_is_forgotten_after_an_hour() {
    // An emulator bound: past it, a response is not checked against the request.
    let (s, key) = dynamic_state();
    let (session_id, _) = session(&s);
    let later = NOW + 3_600;
    *s.clock.lock().unwrap() = VirtualClock::new(LogicalInstant::from_unix_seconds(later));
    let conditions = Conditions {
        in_response_to: Some("_another".into()),
        not_before: later - 60,
        not_on_or_after: later + 300,
        confirmation_not_on_or_after: later + 300,
        ..Conditions::answering(None)
    };
    let answer = sign_in(
        &s,
        &dynamic_request(&signed_response(&key, &conditions), Some(&session_id)),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
}

#[test]
fn the_emulator_profile_does_not_check_the_conditions() {
    // The official emulator reads a JSON fixture and checks none of them: a response failing
    // every check gets the same answer as a valid one.
    let (_, key) = dynamic_state();
    let s = state(false);
    let failing = Conditions {
        in_response_to: Some("_another".into()),
        destination: "https://other.example.test/".into(),
        issuer: "https://other.example.test/idp".into(),
        audience: "https://other.example.test/sp".into(),
        not_before: NOW + 600,
        not_on_or_after: NOW - 600,
        confirmation_not_on_or_after: NOW - 600,
        status: "urn:oasis:names:tc:SAML:2.0:status:Requester".into(),
        ..Conditions::answering(None)
    };
    let valid = sign_in(
        &s,
        &request_for(
            PROVIDER,
            &base64_standard(signed_response(&key, &Conditions::answering(None)).as_bytes()),
        ),
    );
    let refused = sign_in(
        &s,
        &request_for(
            PROVIDER,
            &base64_standard(signed_response(&key, &failing).as_bytes()),
        ),
    );
    assert_eq!(
        valid.status, refused.status,
        "{} {}",
        valid.body, refused.body
    );
    assert_eq!(valid.body["error"], refused.body["error"]);
}

#[test]
fn a_refresh_keeps_the_sign_in_auth_time() {
    // record-saml 7789f0: production's refreshed token carried `auth_time` one second before its
    // `iat`, because the refresh came a second after the sign-in. A refresh keeps the sign-in's
    // `auth_time` and issues a new `iat`, so the row differs only by when it was sent.
    let s = state(true);
    let first = sign_in(&s, &request(&fixture("assertion-signed.xml")));
    assert_eq!(first.status, 200, "{}", first.body);
    let signed_in = claims(&first.body["idToken"]);
    assert_eq!(signed_in["auth_time"], VECTOR_NOW);
    assert_eq!(signed_in["iat"], VECTOR_NOW);
    *s.clock.lock().unwrap() = VirtualClock::new(LogicalInstant::from_unix_seconds(VECTOR_NOW + 2));
    let refreshed = handle(
        &s,
        "POST",
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": first.body["refreshToken"]}),
    );
    assert_eq!(refreshed.status, 200, "{}", refreshed.body);
    for token in ["id_token", "access_token"] {
        let refreshed = claims(&refreshed.body[token]);
        assert_eq!(refreshed["auth_time"], VECTOR_NOW, "{token}");
        assert_eq!(refreshed["iat"], VECTOR_NOW + 2, "{token}");
    }
}

#[test]
fn a_continuation_checks_the_response_conditions_again() {
    // A resumed continuation runs the conditions again against the live configuration, all but
    // InResponseTo (closure review SF5; production's continuation is unobserved, so this is
    // the strict profile's own safety choice).
    let resume_at = |seconds: i64, change: &dyn Fn(&mut InboundSamlProviderConfig)| {
        let mut s = state(true);
        s.idp_continuations = IdpContinuationPolicy::LocalBounded;
        let first = sign_in(&s, &request(&fixture("assertion-signed.xml")));
        assert_eq!(first.status, 200, "{}", first.body);
        let pending = first.body["pendingToken"].clone();
        let mut config = provider(true, "idp.cert.pem");
        change(&mut config);
        s.store.lock().unwrap().replace_saml_config(config);
        *s.clock.lock().unwrap() = VirtualClock::new(LogicalInstant::from_unix_seconds(seconds));
        sign_in(&s, &continuation(&pending))
    };
    let unchanged = resume_at(VECTOR_NOW + 60, &|_| {});
    assert_eq!(unchanged.status, 200, "{}", unchanged.body);
    // The vectors' NotOnOrAfter is 2027-01-15T08:05:00Z.
    let expired = resume_at(VECTOR_NOW + 275, &|_| {});
    assert_eq!(expired.status, 400, "{}", expired.body);
    assert_eq!(
        expired.body["error"]["message"],
        "INVALID_IDP_RESPONSE : Current instant, 2027-01-15T08:05:05.000Z, is on or after NotOnOrAfter attribute, 2027-01-15T08:05:00.000Z"
    );
    let audience = resume_at(VECTOR_NOW + 60, &|config| {
        config.sp_entity_id = "another-sp".into();
    });
    assert_eq!(audience.status, 400, "{}", audience.body);
    assert_eq!(
        audience.body["error"]["message"],
        "INVALID_IDP_RESPONSE : All <AudienceRestriction>s should contain the SAML RP entity ID: 'another-sp'."
    );
    let issuer = resume_at(VECTOR_NOW + 60, &|config| {
        config.idp_entity_id = "https://idp.example.test/saml/other".into();
    });
    assert_eq!(issuer.status, 400, "{}", issuer.body);
    assert_eq!(
        issuer.body["error"]["message"],
        "INVALID_IDP_RESPONSE : Assertion has Issuer https://idp.example.test/saml/fixture which is different from expected Issuer https://idp.example.test/saml/other."
    );
}

#[test]
fn a_continuation_does_not_check_the_request_it_answered_again() {
    // InResponseTo is the one condition a resumed continuation leaves out: the sign-in that
    // made the continuation checked it, and the resumed request carries no session.
    let (mut s, key) = dynamic_state();
    s.idp_continuations = IdpContinuationPolicy::LocalBounded;
    let (session_id, request_id) = session(&s);
    let first = sign_in(
        &s,
        &dynamic_request(
            &signed_response(&key, &Conditions::answering(Some(&request_id))),
            Some(&session_id),
        ),
    );
    assert_eq!(first.status, 200, "{}", first.body);
    let resumed = sign_in(&s, &continuation(&first.body["pendingToken"]));
    assert_eq!(resumed.status, 200, "{}", resumed.body);
}

#[test]
fn a_continuation_resumed_with_another_session_is_not_checked_against_it() {
    // A resume request may name any sessionId: InResponseTo is the one condition a resumed
    // continuation leaves out, whatever session the resume names (closure re-review S1). No
    // new refusal: a resume naming another live session, or a session where the sign-in named
    // none, is accepted.
    let (mut s, key) = dynamic_state();
    s.idp_continuations = IdpContinuationPolicy::LocalBounded;
    let (first_session, first_request) = session(&s);
    let first = sign_in(
        &s,
        &dynamic_request(
            &signed_response(&key, &Conditions::answering(Some(&first_request))),
            Some(&first_session),
        ),
    );
    assert_eq!(first.status, 200, "{}", first.body);
    let (other_session, _) = session(&s);
    let mut resume = continuation(&first.body["pendingToken"]);
    resume["sessionId"] = json!(other_session);
    let resumed = sign_in(&s, &resume);
    assert_eq!(resumed.status, 200, "{}", resumed.body);
    // A sign-in that named no session, resumed with one.
    let unsolicited = sign_in(
        &s,
        &dynamic_request(
            &signed_response(&key, &Conditions::answering(Some("_unsolicited"))),
            None,
        ),
    );
    assert_eq!(unsolicited.status, 200, "{}", unsolicited.body);
    let (named_session, _) = session(&s);
    let mut resume = continuation(&unsolicited.body["pendingToken"]);
    resume["sessionId"] = json!(named_session);
    let resumed = sign_in(&s, &resume);
    assert_eq!(resumed.status, 200, "{}", resumed.body);
}
