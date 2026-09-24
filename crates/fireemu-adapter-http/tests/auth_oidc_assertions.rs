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
        idp_continuations: fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::Disabled,
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
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

struct CredentialObserver {
    contexts: Arc<Mutex<Vec<fireemu_adapter_http::identity_toolkit::AuthBlockingContext>>>,
}

impl fireemu_adapter_http::identity_toolkit::AuthBlockingHook for CredentialObserver {
    fn forward_inbound_credentials(&self) -> bool {
        true
    }

    fn invoke(
        &self,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
        Ok(json!({}))
    }

    fn invoke_for_with_context(
        &self,
        _project: &str,
        _tenant: Option<&str>,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
        context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    ) -> Result<Option<Value>, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure>
    {
        self.contexts.lock().unwrap().push(context.clone());
        Ok(Some(json!({})))
    }
}

#[test]
fn signed_oidc_mixed_access_token_is_refused_before_mutation_or_credential_forwarding() {
    let mut s = state();
    let contexts = Arc::new(Mutex::new(Vec::new()));
    s.blocking = Some(Arc::new(CredentialObserver {
        contexts: contexts.clone(),
    }));
    let mut body = request(&token(&claims()));
    body["postBody"] = json!(format!(
        "{}&access_token=unverified-access-sentinel",
        body["postBody"].as_str().unwrap()
    ));
    let response = signed_post(&s, &trust(), &body);
    assert_eq!(response.status, 400);
    assert_eq!(response.body["error"]["message"], "INVALID_IDP_RESPONSE");
    assert!(response.body.get("oauthAccessToken").is_none());
    assert!(response.body.get("idToken").is_none());
    assert!(s.store.lock().unwrap().users_by_creation().is_empty());
    assert!(contexts.lock().unwrap().is_empty());
    // The observer is active and receives genuine ID-token credentials on the allowed path.
    let mut allowed = request(&token(&claims()));
    allowed["postBody"] = json!(format!(
        "{}&access_token=",
        allowed["postBody"].as_str().unwrap()
    ));
    assert_eq!(signed_post(&s, &trust(), &allowed).status, 200);
    let recorded = contexts.lock().unwrap();
    assert!(!recorded.is_empty());
    for context in recorded.iter() {
        let credential = context.credential.as_ref().unwrap();
        assert!(credential.access_token.is_none());
        assert!(credential.id_token.is_some());
    }
}

#[test]
fn signed_oidc_tenant_routing_succeeds_only_with_the_selected_namespace_pin() {
    use fireemu_core_auth::store::AuthRegistry;
    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    let config = s
        .store
        .lock()
        .unwrap()
        .oidc_config("oidc.local")
        .unwrap()
        .clone();
    for tenant in ["customer-a", "customer-b"] {
        let store = registry.ensure_tenant("demo-app", tenant).unwrap();
        assert!(store.lock().unwrap().create_oidc_config(config.clone()));
    }
    s.registry = Some(registry.clone());
    let mut body = request(&token(&claims()));
    body["tenantId"] = json!("customer-a");
    let mut tenant_pin = trust();
    tenant_pin.tenant_id = Some("customer-a".into());
    let mut other_pin = trust();
    other_pin.tenant_id = Some("customer-b".into());
    for pin in [&trust(), &other_pin] {
        assert_eq!(signed_post(&s, pin, &body).status, 400);
    }
    let signed = signed_post(&s, &tenant_pin, &body);
    assert_eq!(signed.status, 200, "{}", signed.body);
    let jwt =
        fireemu_core_auth::jwt::decode_unsigned(signed.body["idToken"].as_str().unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&jwt.payload_json).unwrap()["firebase"]["tenant"],
        "customer-a"
    );
    assert_eq!(
        registry
            .tenant_store("demo-app", "customer-a")
            .unwrap()
            .lock()
            .unwrap()
            .users_by_creation()
            .len(),
        1
    );
    assert!(registry
        .tenant_store("demo-app", "customer-b")
        .unwrap()
        .lock()
        .unwrap()
        .users_by_creation()
        .is_empty());
    assert!(s.store.lock().unwrap().users_by_creation().is_empty());
    // The same valid assertion cannot use A's pin against either B or the parent namespace.
    body["tenantId"] = json!("customer-b");
    assert_eq!(signed_post(&s, &tenant_pin, &body).status, 400);
    body.as_object_mut().unwrap().remove("tenantId");
    assert_eq!(signed_post(&s, &tenant_pin, &body).status, 400);
    assert!(registry
        .tenant_store("demo-app", "customer-b")
        .unwrap()
        .lock()
        .unwrap()
        .users_by_creation()
        .is_empty());
    assert!(s.store.lock().unwrap().users_by_creation().is_empty());
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the populated refusal and its post-state observations together.
fn signed_oidc_bad_signature_preserves_populated_sessions_transients_and_allocation() {
    use fireemu_core_auth::store::{NewUser, OobRequestType, VerificationPurpose};
    let mut s = state();
    let events = Arc::new(Mutex::new(Vec::new()));
    let notices = Arc::new(Mutex::new(Vec::new()));
    let event_log = events.clone();
    let notice_log = notices.clone();
    s.events = Some(Arc::new(move |event| {
        event_log.lock().unwrap().push(event.clone());
    }));
    s.notices = Some(Arc::new(move |notice| {
        notice_log.lock().unwrap().push(notice.clone());
    }));
    let mut initial = claims();
    initial["name"] = json!("Original profile");
    initial["email"] = json!("owner@example.test");
    let signed = signed_post(&s, &trust(), &request(&token(&initial)));
    assert_eq!(signed.status, 200);
    let sms = fireemu_adapter_http::identity_toolkit::handle(
        &s,
        "POST",
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber":"+15555550123"}),
    );
    assert_eq!(sms.status, 200);
    assert!(!events.lock().unwrap().is_empty());
    assert!(!notices.lock().unwrap().is_empty());
    let at = LogicalInstant::from_unix_seconds(NOW);
    let (uid, pending, oob, mut baseline) = {
        let mut store = s.store.lock().unwrap();
        let uid = store
            .user_by_id(signed.body["localId"].as_str().unwrap())
            .unwrap()
            .local_id
            .clone();
        store
            .enroll_phone_factor(&uid, "+15555550124", Some("Saved factor".into()), at)
            .unwrap();
        let pending = store.start_mfa_sign_in(&uid, at).unwrap();
        let oob = store
            .create_oob_code(
                OobRequestType::VerifyEmail,
                "owner@example.test",
                Some(uid.clone()),
                None,
                at,
            )
            .unwrap();
        assert_eq!(store.pending_sign_in_count(), 1);
        assert_eq!(store.oob_codes().len(), 1);
        assert_eq!(store.verification_codes().len(), 1);
        (uid, pending, oob, store.clone())
    };
    let event_count = events.lock().unwrap().len();
    let notice_count = notices.lock().unwrap().len();
    // All old transient credentials are now sweepable. Only the bad signature must cause refusal.
    let later = LogicalInstant::from_unix_seconds(NOW + 7200);
    s.clock.lock().unwrap().advance_to(later).unwrap();
    let mut c = initial;
    c["iat"] = json!(NOW + 7200);
    c["exp"] = json!(NOW + 7260);
    c["name"] = json!("Untrusted replacement");
    let mut jwt = token(&c);
    let start = jwt.rfind('.').unwrap() + 1;
    jwt.replace_range(
        start..=start,
        if &jwt[start..=start] == "A" { "B" } else { "A" },
    );
    let response = signed_post(&s, &trust(), &request(&jwt));
    assert_eq!(response.status, 400);
    assert_eq!(response.body["error"]["message"], "INVALID_IDP_RESPONSE");
    assert!(response.body.get("idToken").is_none());
    assert!(response.body.get("refreshToken").is_none());
    assert_eq!(events.lock().unwrap().len(), event_count);
    assert_eq!(notices.lock().unwrap().len(), notice_count);
    let mut store = s.store.lock().unwrap();
    assert_eq!(
        store.users_shared_with(&baseline),
        baseline.retained_user_bytes()
    );
    assert_eq!(
        format!("{:?}", store.users_by_creation()),
        format!("{:?}", baseline.users_by_creation())
    );
    assert_eq!(store.transient_registries_shared_with(&baseline), 7);
    assert_eq!(store.transient_bytes(), baseline.transient_bytes());
    assert_eq!(
        store.pending_sign_in_count(),
        baseline.pending_sign_in_count()
    );
    assert_eq!(store.pending_sign_in_user(&pending), Some(uid.clone()));
    assert_eq!(
        format!("{:?}", store.pending_sign_in_context(&pending)),
        format!("{:?}", baseline.pending_sign_in_context(&pending))
    );
    assert!(store.oob_code(&oob).is_some());
    assert_eq!(store.verification_codes(), baseline.verification_codes());
    let refresh = signed.body["refreshToken"].as_str().unwrap();
    assert_eq!(
        format!("{:?}", store.refresh_session(refresh).unwrap()),
        format!("{:?}", baseline.refresh_session(refresh).unwrap())
    );
    assert_eq!(store.redeem_refresh_token(refresh).unwrap(), uid);
    assert!(store.take_user_events().is_empty());
    assert!(store.take_credential_notices().is_empty());
    // Equal subsequent public outputs constrain the RNG, UID sequence and refresh allocation.
    let allocated = store.create_user(NewUser::anonymous(), later).unwrap();
    let expected = baseline.create_user(NewUser::anonymous(), later).unwrap();
    assert_eq!(allocated, expected);
    assert_eq!(
        store.issue_refresh_token(&allocated, later).unwrap(),
        baseline.issue_refresh_token(&expected, later).unwrap()
    );
    assert_eq!(
        store
            .send_verification_code("+15555550125", VerificationPurpose::SignIn, later)
            .unwrap(),
        baseline
            .send_verification_code("+15555550125", VerificationPurpose::SignIn, later)
            .unwrap()
    );
}

#[test]
fn signed_oidc_mixed_refresh_token_never_reaches_hooks_or_pending_credentials() {
    use fireemu_core_auth::store::PendingSignInId;
    for require_mfa in [false, true] {
        let mut s = state();
        let contexts = Arc::new(Mutex::new(Vec::new()));
        s.blocking = Some(Arc::new(CredentialObserver {
            contexts: contexts.clone(),
        }));
        let body = request(&token(&claims()));
        let created = signed_post(&s, &trust(), &body);
        assert_eq!(created.status, 200);
        assert!(!contexts.lock().unwrap().is_empty());
        contexts.lock().unwrap().clear();
        if require_mfa {
            let mut store = s.store.lock().unwrap();
            let uid = store
                .user_by_id(created.body["localId"].as_str().unwrap())
                .unwrap()
                .local_id
                .clone();
            store
                .enroll_phone_factor(
                    &uid,
                    "+15555550126",
                    None,
                    LogicalInstant::from_unix_seconds(NOW),
                )
                .unwrap();
        }
        let baseline = s.store.lock().unwrap().clone();
        let mut mixed = body.clone();
        mixed["postBody"] = json!(format!(
            "{}&refresh_token=unverified-refresh-sentinel",
            body["postBody"].as_str().unwrap()
        ));
        let response = signed_post(&s, &trust(), &mixed);
        assert_eq!(response.status, 400, "require_mfa={require_mfa}");
        assert_eq!(response.body["error"]["message"], "INVALID_IDP_RESPONSE");
        assert!(response.body.get("idToken").is_none());
        assert!(response.body.get("refreshToken").is_none());
        assert!(response.body.get("mfaPendingCredential").is_none());
        assert!(contexts.lock().unwrap().is_empty());
        {
            let store = s.store.lock().unwrap();
            assert_eq!(
                store.users_shared_with(&baseline),
                baseline.retained_user_bytes()
            );
            assert_eq!(store.transient_registries_shared_with(&baseline), 7);
            assert_eq!(store.pending_sign_in_count(), 0);
        }
        let mut empty = body.clone();
        empty["postBody"] = json!(format!(
            "{}&refresh_token=",
            body["postBody"].as_str().unwrap()
        ));
        let allowed = signed_post(&s, &trust(), &empty);
        assert_eq!(allowed.status, 200);
        if require_mfa {
            let pending =
                PendingSignInId::parse(allowed.body["mfaPendingCredential"].as_str().unwrap())
                    .unwrap();
            let store = s.store.lock().unwrap();
            assert_eq!(store.pending_sign_in_count(), 1);
            let credentials = store
                .pending_sign_in_context(&pending)
                .unwrap()
                .inbound_credentials()
                .unwrap();
            assert!(credentials.refresh_token().is_none());
            assert!(credentials.id_token().is_some());
        } else {
            let recorded = contexts.lock().unwrap();
            assert!(!recorded.is_empty());
            for context in recorded.iter() {
                let credential = context.credential.as_ref().unwrap();
                assert!(credential.refresh_token.is_none());
                assert!(credential.id_token.is_some());
            }
        }
    }
}

fn continuation_request(value: &Value) -> Value {
    json!({"requestUri":"http://localhost", "pendingToken":value, "returnSecureToken":true})
}

#[test]
fn signed_continuation_reverifies_assertion_expiry_before_its_local_handle_expires() {
    let mut s = state();
    s.idp_continuations =
        fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::LocalBounded;
    let first = signed_post(&s, &trust(), &request(&token(&claims())));
    assert_eq!(first.status, 200, "{}", first.body);
    assert!(first.body["pendingToken"].is_string());
    let next = continuation_request(&first.body["pendingToken"]);
    s.clock
        .lock()
        .unwrap()
        .advance_to(LogicalInstant::from_unix_seconds(NOW + 59))
        .unwrap();
    let repeated = signed_post(&s, &trust(), &next);
    assert_eq!(repeated.status, 200, "{}", repeated.body);
    assert_eq!(repeated.body["localId"], first.body["localId"]);
    assert_eq!(repeated.body["pendingToken"], first.body["pendingToken"]);
    s.clock
        .lock()
        .unwrap()
        .advance_to(LogicalInstant::from_unix_seconds(NOW + 60))
        .unwrap();
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    let rejected = signed_post(&s, &trust(), &next);
    assert_eq!(rejected.status, 400);
    assert_eq!(rejected.body["error"]["message"], "INVALID_IDP_RESPONSE");
    assert!(rejected.body.get("idToken").is_none());
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );
}

#[test]
fn signed_and_fixture_pending_tokens_cannot_cross_verification_authorities() {
    let mut s = state();
    s.idp_continuations =
        fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::LocalBounded;
    let body = request(&token(&claims()));
    let signed = signed_post(&s, &trust(), &body);
    assert_eq!(signed.status, 200);
    let path = format!("{V1}/accounts:signInWithIdp");
    let rejected = fireemu_adapter_http::identity_toolkit::handle(
        &s,
        "POST",
        &path,
        &continuation_request(&signed.body["pendingToken"]),
    );
    assert_eq!(rejected.status, 400);
    let fixture = fireemu_adapter_http::identity_toolkit::handle(&s, "POST", &path, &body);
    assert_eq!(fixture.status, 200, "{}", fixture.body);
    assert!(fixture.body["pendingToken"].is_string());
    assert_eq!(
        signed_post(
            &s,
            &trust(),
            &continuation_request(&fixture.body["pendingToken"])
        )
        .status,
        400
    );
    let mut changed_pin = trust();
    changed_pin.jwk["kid"] = json!("rotated-kid");
    assert_eq!(
        signed_post(
            &s,
            &changed_pin,
            &continuation_request(&signed.body["pendingToken"])
        )
        .status,
        400
    );
    assert_eq!(
        signed_post(
            &s,
            &trust(),
            &continuation_request(&signed.body["pendingToken"])
        )
        .status,
        200
    );
    assert_eq!(s.store.lock().unwrap().user_count(), 1);
}

#[test]
fn signed_continuation_checks_current_provider_configuration_not_cached_acceptance() {
    let mut s = state();
    s.idp_continuations =
        fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::LocalBounded;
    let first = signed_post(&s, &trust(), &request(&token(&claims())));
    assert_eq!(first.status, 200, "{}", first.body);
    let original = s
        .store
        .lock()
        .unwrap()
        .oidc_config("oidc.local")
        .unwrap()
        .clone();
    let mut disabled = original.clone();
    disabled.enabled = false;
    s.store.lock().unwrap().replace_oidc_config(disabled);
    let body = continuation_request(&first.body["pendingToken"]);
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    assert_eq!(signed_post(&s, &trust(), &body).status, 400);
    let mut changed = original.clone();
    changed.issuer = "https://changed.invalid".into();
    s.store.lock().unwrap().replace_oidc_config(changed);
    let issuer_changed = signed_post(&s, &trust(), &body);
    assert_eq!(issuer_changed.status, 400);
    assert_eq!(
        issuer_changed.body["error"]["message"],
        "INVALID_IDP_RESPONSE"
    );
    assert!(issuer_changed.body.get("idToken").is_none());
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );

    let mut client_changed = original.clone();
    client_changed.client_id = "changed-client".into();
    s.store.lock().unwrap().replace_oidc_config(client_changed);
    let client_changed = signed_post(&s, &trust(), &body);
    assert_eq!(client_changed.status, 400);
    assert_eq!(
        client_changed.body["error"]["message"],
        "INVALID_IDP_RESPONSE"
    );
    assert!(client_changed.body.get("idToken").is_none());
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );

    s.store.lock().unwrap().replace_oidc_config(original);
    let restored = signed_post(&s, &trust(), &body);
    assert_eq!(restored.status, 200, "{}", restored.body);
    assert_eq!(restored.body["pendingToken"], first.body["pendingToken"]);
}

#[test]
fn unsigned_forgery_cannot_mint_a_signed_continuation_or_link_an_account() {
    let mut s = state();
    s.idp_continuations =
        fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::LocalBounded;
    let mut forged = token(&claims());
    let start = forged.rfind('.').unwrap() + 1;
    forged.replace_range(
        start..=start,
        if &forged[start..=start] == "A" {
            "B"
        } else {
            "A"
        },
    );
    let response = signed_post(&s, &trust(), &request(&forged));
    assert_eq!(response.status, 400);
    assert!(response.body.get("pendingToken").is_none());
    assert_eq!(s.store.lock().unwrap().pending_idp_count(), 0);
    assert_eq!(s.store.lock().unwrap().user_count(), 0);
}
