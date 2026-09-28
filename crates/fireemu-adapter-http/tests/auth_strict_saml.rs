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
        (
            "a provider named in another case",
            request_for(
                "saml.Strict",
                &base64_standard(fixture("assertion-signed.xml").as_bytes()),
            ),
        ),
        (
            "an unconfigured provider",
            request_for(
                "saml.unconfigured",
                &base64_standard(fixture("assertion-signed.xml").as_bytes()),
            ),
        ),
        ("no NameID", request(&fixture("no-name-id.xml"))),
    ];
    for (case, body) in cases {
        assert_refused(&s, &body, "INVALID_IDP_RESPONSE", case);
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
        "INVALID_IDP_RESPONSE",
        "a mixed-case provider with a configuration",
    );
    s.store
        .lock()
        .unwrap()
        .replace_saml_config(provider(false, "idp.cert.pem"));
    assert_refused(
        &s,
        &request(&fixture("assertion-signed.xml")),
        "INVALID_IDP_RESPONSE",
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
