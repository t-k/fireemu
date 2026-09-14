//! Real signed OIDC assertions with an explicitly pinned public local trust root.
use fireemu_adapter_http::identity_toolkit::{handle_with_oidc_trust, AuthState, RequestHeaders};
use fireemu_adapter_http::oidc::LocalOidcTrust;
use fireemu_adapter_http::signing::RsaSigner;
use fireemu_core_auth::jwt::encode_payload_with;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};
const V1: &str = "/identitytoolkit.googleapis.com/v1";
const NOW: i64 = 1_788_004_860;
// Public deterministic test fixture only; this seed is not a deployment signing key.
fn signer() -> &'static Arc<RsaSigner> {
    static SIGNER: OnceLock<Arc<RsaSigner>> = OnceLock::new();
    SIGNER.get_or_init(|| RsaSigner::from_seed(7331).unwrap())
}
fn trust() -> LocalOidcTrust {
    LocalOidcTrust {
        project_id: "demo-app".into(),
        tenant_id: None,
        provider_id: "oidc.local".into(),
        issuer: "https://issuer.example.test".into(),
        client_id: "local-client".into(),
        jwk: signer().jwks()["keys"][0].clone(),
    }
}
fn claims() -> Value {
    json!({"sub":"signed-subject", "iss":"https://issuer.example.test", "aud":"local-client", "iat":NOW, "exp":NOW+60})
}
fn token(claims: &Value) -> String {
    encode_payload_with(&claims.to_string(), Some(signer().as_ref()))
}
fn request(token: &str) -> Value {
    json!({"requestUri":"http://localhost", "postBody":format!("providerId=oidc.local&id_token={token}"), "returnSecureToken":true})
}
fn signed_post(
    s: &AuthState,
    trust: &LocalOidcTrust,
    body: &Value,
) -> fireemu_adapter_http::identity_toolkit::JsonResponse {
    handle_with_oidc_trust(
        s,
        "POST",
        &format!("{V1}/accounts:signInWithIdp"),
        &RequestHeaders::default(),
        body,
        trust,
    )
}
fn state() -> AuthState {
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
        stateless_refresh_tokens: true,
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    s.store
        .lock()
        .unwrap()
        .create_oidc_config(fireemu_core_auth::store::OidcProviderConfig {
            id: "oidc.local".into(),
            display_name: None,
            enabled: true,
            client_id: "local-client".into(),
            issuer: "https://issuer.example.test".into(),
            client_secret: None,
            response_type: fireemu_core_auth::store::OAuthResponseType {
                id_token: true,
                code: false,
                token: false,
            },
        });
    s
}

#[test]
fn signed_oidc_refuses_bad_signature_before_account_creation() {
    let s = state();
    let mut jwt = token(&claims());
    let start = jwt.rfind('.').unwrap() + 1;
    jwt.replace_range(
        start..=start,
        if &jwt[start..=start] == "A" { "B" } else { "A" },
    );
    let response = signed_post(&s, &trust(), &request(&jwt));
    assert_eq!(response.status, 400);
    assert_eq!(response.body["error"]["message"], "INVALID_IDP_RESPONSE");
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_federated("oidc.local", "signed-subject")
        .is_none());
}

#[test]
fn signed_oidc_creates_then_signs_in_to_the_same_account() {
    let s = state();
    let body = request(&token(&claims()));
    let first = signed_post(&s, &trust(), &body);
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(first.body["isNewUser"], true);
    let second = signed_post(&s, &trust(), &body);
    assert_eq!(second.status, 200);
    assert_eq!(second.body["isNewUser"], false);
    assert_eq!(second.body["localId"], first.body["localId"]);
    assert_eq!(s.store.lock().unwrap().users_by_creation().len(), 1);
}

#[test]
fn signed_oidc_refuses_claim_boundaries_without_mutating_existing_accounts() {
    let s = state();
    assert_eq!(
        signed_post(&s, &trust(), &request(&token(&claims()))).status,
        200
    );
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    for (name, value) in [
        ("iss", json!("https://wrong.test")),
        ("aud", json!("wrong")),
        ("exp", json!(NOW)),
        ("exp", json!(NOW - 1)),
        ("nbf", json!(NOW + 1)),
        ("iat", json!(NOW + 1)),
        ("iat", Value::Null),
        ("exp", json!("9999999999")),
        ("nbf", Value::Null),
        ("sub", json!("")),
        ("nonce", json!("unbound")),
        ("azp", json!("wrong")),
        ("aud", json!(["local-client", "other"])),
    ] {
        let mut c = claims();
        c[name] = value;
        let response = signed_post(&s, &trust(), &request(&token(&c)));
        assert_eq!(response.status, 400, "accepted {name}: {c}");
        assert!(response.body.get("idToken").is_none());
        assert_eq!(
            before,
            format!("{:?}", s.store.lock().unwrap().users_by_creation())
        );
    }
}

#[test]
fn signed_oidc_nonce_matches_the_sdk_raw_nonce_hash() {
    use sha2::{Digest, Sha256};
    let s = state();
    let mut c = claims();
    c["nonce"] = json!(format!("{:x}", Sha256::digest(b"public-local-nonce")));
    c["nbf"] = json!(NOW);
    c["aud"] = json!(["local-client", "other"]);
    c["azp"] = json!("local-client");
    let mut body = request(&token(&c));
    assert_eq!(signed_post(&s, &trust(), &body).status, 400);
    body["postBody"] = json!(format!(
        "{}&nonce=wrong",
        body["postBody"].as_str().unwrap()
    ));
    assert_eq!(signed_post(&s, &trust(), &body).status, 400);
    body = request(&token(&c));
    body["postBody"] = json!(format!(
        "{}&nonce=public-local-nonce",
        body["postBody"].as_str().unwrap()
    ));
    assert_eq!(signed_post(&s, &trust(), &body).status, 200);
}

#[test]
fn signed_oidc_links_and_refuses_cross_account_identity_collision_atomically() {
    let s = state();
    let signup = |email: &str| {
        fireemu_adapter_http::identity_toolkit::handle(
            &s,
            "POST",
            &format!("{V1}/accounts:signUp"),
            &json!({"email":email,"password":"password"}),
        )
    };
    let first = signup("first@example.test");
    let second = signup("second@example.test");
    let mut body = request(&token(&claims()));
    body["idToken"] = first.body["idToken"].clone();
    let linked = signed_post(&s, &trust(), &body);
    assert_eq!(linked.status, 200);
    assert_eq!(linked.body["localId"], first.body["localId"]);
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    body["idToken"] = second.body["idToken"].clone();
    let refused = signed_post(&s, &trust(), &body);
    assert_eq!(refused.status, 400);
    assert_eq!(
        refused.body["error"]["message"],
        "FEDERATED_USER_ID_ALREADY_LINKED"
    );
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );
}

#[test]
fn signed_oidc_rejects_fixture_downgrades_and_wrong_trust_scope() {
    let s = state();
    let body = request(&token(&claims()));
    for field in ["project", "tenant", "provider", "issuer", "client", "kid"] {
        let mut pin = trust();
        match field {
            "project" => pin.project_id = "other".into(),
            "tenant" => pin.tenant_id = Some("other".into()),
            "provider" => pin.provider_id = "oidc.other".into(),
            "issuer" => pin.issuer = "https://other.test".into(),
            "client" => pin.client_id = "other".into(),
            _ => pin.jwk["kid"] = json!("other"),
        }
        assert_eq!(signed_post(&s, &pin, &body).status, 400, "{field}");
    }
    for jwt in [
        claims().to_string(),
        encode_payload_with(&claims().to_string(), None),
    ] {
        assert_eq!(signed_post(&s, &trust(), &request(&jwt)).status, 400);
    }
    let mut config = s
        .store
        .lock()
        .unwrap()
        .oidc_config("oidc.local")
        .unwrap()
        .clone();
    config.enabled = false;
    s.store.lock().unwrap().replace_oidc_config(config);
    assert_eq!(signed_post(&s, &trust(), &body).status, 400);
    assert!(s.store.lock().unwrap().users_by_creation().is_empty());
}

#[test]
fn signed_oidc_rejects_untrusted_headers_and_access_token_fallback() {
    use fireemu_core_auth::jwt::{base64url_encode, IdTokenSigner};
    let s = state();
    for extra in [
        json!({"alg":"HS256"}),
        json!({"kid":"unknown"}),
        json!({"crit":["unknown"]}),
        json!({"b64":false}),
    ] {
        let mut header = json!({"alg":"RS256", "kid":signer().kid()});
        header
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let input = format!(
            "{}.{}",
            base64url_encode(header.to_string().as_bytes()),
            base64url_encode(claims().to_string().as_bytes())
        );
        let jwt = format!(
            "{}.{}",
            input,
            base64url_encode(&signer().sign(input.as_bytes()))
        );
        assert_eq!(signed_post(&s, &trust(), &request(&jwt)).status, 400);
    }
    for body in [
        json!({"requestUri":"http://localhost", "postBody":format!("providerId=oidc.local&access_token={}",token(&claims()))}),
        json!({"requestUri":"http://localhost", "postBody":format!("providerId=saml.local&id_token={}",token(&claims()))}),
    ] {
        assert_eq!(signed_post(&s, &trust(), &body).status, 400);
    }
    assert!(s.store.lock().unwrap().users_by_creation().is_empty());
}

#[test]
fn signed_oidc_email_collision_requires_confirmation_without_tokens_or_mutation() {
    let s = state();
    let signup = fireemu_adapter_http::identity_toolkit::handle(
        &s,
        "POST",
        &format!("{V1}/accounts:signUp"),
        &json!({"email":"collision@example.test", "password":"password"}),
    );
    assert_eq!(signup.status, 200);
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    let mut c = claims();
    c["email"] = json!("collision@example.test");
    c["email_verified"] = json!(false);
    let response = signed_post(&s, &trust(), &request(&token(&c)));
    assert_eq!(response.status, 200);
    assert_eq!(response.body["needConfirmation"], true);
    assert!(response.body.get("idToken").is_none());
    assert!(response.body.get("refreshToken").is_none());
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );
}
