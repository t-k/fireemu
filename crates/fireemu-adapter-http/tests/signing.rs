//! RS256 session signing: token tokens verify, forgeries and unsigned tokens do not, and
//! the JWKS endpoint publishes the key.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthBlockingHook, AuthState, BlockingFunctionFailure, RequestHeaders,
    JWKS_PATHS, OWNER_CREDENTIAL,
};
use fireemu_adapter_http::signing::{AppCheckKeySource, AppCheckRsaSigner, RsaSigner};
use fireemu_core_auth::jwt::{
    decode_token, encode_unsigned, encode_with, verify_id_token, IdTokenSigner, JwtError, PublicJwk,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_functions::manifest::BlockingAuthEvent;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

struct LockCheckingSigner {
    store: Weak<Mutex<AuthStore>>,
    calls: AtomicUsize,
}

struct PassthroughBlockingHook;

struct StructuredJwkSigner(PublicJwk);

impl IdTokenSigner for StructuredJwkSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn kid(&self) -> &str {
        &self.0.kid
    }

    fn sign(&self, _signing_input: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    fn verify(&self, _signing_input: &[u8], _signature: &[u8]) -> bool {
        false
    }

    fn public_jwk_json(&self) -> String {
        panic!("the structured JWK path must not stringify and reparse JSON")
    }

    fn public_jwk(&self) -> Option<&PublicJwk> {
        Some(&self.0)
    }
}

impl AuthBlockingHook for PassthroughBlockingHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<serde_json::Value, BlockingFunctionFailure> {
        Ok(json!({}))
    }
}

#[test]
fn auth_jwks_uses_the_signers_precomputed_structured_key() {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(42), TotpPolicy::default());
    store.set_signer(Arc::new(StructuredJwkSigner(PublicJwk {
        kty: "RSA",
        alg: "RS256",
        usage: "sig",
        kid: "structured".to_owned(),
        modulus: "AQID".to_owned(),
        exponent: "AQAB".to_owned(),
    })));
    let state = AuthState {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };

    let response = handle(&state, "GET", JWKS_PATHS[0], &json!({}));
    assert_eq!(response.status, 200);
    assert_eq!(response.body["keys"][0]["kid"], "structured");
    assert_eq!(response.body["keys"][0]["n"], "AQID");
}

impl IdTokenSigner for LockCheckingSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn kid(&self) -> &'static str {
        "outside-lock"
    }

    fn sign(&self, _signing_input: &[u8]) -> Vec<u8> {
        let store = self.store.upgrade().expect("the store is alive");
        assert!(
            store.try_lock().is_ok(),
            "RSA signing ran while the AuthStore mutex was held"
        );
        self.calls.fetch_add(1, Ordering::Relaxed);
        vec![1, 2, 3]
    }

    fn verify(&self, _signing_input: &[u8], signature: &[u8]) -> bool {
        signature == [1, 2, 3]
    }

    fn public_jwk_json(&self) -> String {
        r#"{"kty":"RSA","kid":"outside-lock"}"#.to_owned()
    }
}

#[test]
fn auth_response_tokens_are_signed_after_releasing_the_store_mutex() {
    let store = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(41),
        TotpPolicy::default(),
    )));
    let signer = Arc::new(LockCheckingSigner {
        store: Arc::downgrade(&store),
        calls: AtomicUsize::new(0),
    });
    store.lock().unwrap().set_signer(signer.clone());
    let mut state = AuthState {
        store,
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };

    let response = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k",
        &json!({"email": "outside-lock@example.com", "password": "password1"}),
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(signer.calls.load(Ordering::Relaxed), 1);

    let refresh = response.body["refreshToken"].as_str().unwrap();
    let refreshed = handle(
        &state,
        "POST",
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(refreshed.status, 200, "{}", refreshed.body);
    assert_eq!(signer.calls.load(Ordering::Relaxed), 3);

    let cookie = handle_with(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/projects/demo-app:createSessionCookie",
        &RequestHeaders {
            authorization: Some(OWNER_CREDENTIAL.to_owned()),
            ..RequestHeaders::default()
        },
        &json!({"idToken": response.body["idToken"], "validDuration": "3600"}),
    );
    assert_eq!(cookie.status, 200, "{}", cookie.body);
    assert_eq!(signer.calls.load(Ordering::Relaxed), 4);

    state.blocking = Some(Arc::new(PassthroughBlockingHook));
    let blocked = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k",
        &json!({"email": "outside-lock-blocking@example.com", "password": "password1"}),
    );
    assert_eq!(blocked.status, 200, "{}", blocked.body);
    assert_eq!(signer.calls.load(Ordering::Relaxed), 5);
}

#[test]
fn blocking_auth_with_fifty_thousand_sessions_copies_only_changed_registries() {
    let store = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(43),
        TotpPolicy::default(),
    )));
    let mut state = AuthState {
        store: Arc::clone(&store),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    let created = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k",
        &json!({"email": "cow@example.com", "password": "password1"}),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let before = {
        let mut store = store.lock().unwrap();
        let uid = store
            .user_by_email("cow@example.com")
            .unwrap()
            .local_id
            .clone();
        for _ in 0..50_000 {
            store.issue_refresh_token(&uid, START).unwrap();
        }
        store.clone()
    };
    state.blocking = Some(Arc::new(PassthroughBlockingHook));

    let signed_in = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=k",
        &json!({
            "email": "cow@example.com",
            "password": "password1",
            "returnSecureToken": true,
        }),
    );

    assert_eq!(signed_in.status, 200, "{}", signed_in.body);
    assert_eq!(
        store
            .lock()
            .unwrap()
            .transient_registries_shared_with(&before),
        3,
        "the blocking request may detach only refresh sessions and their owner index"
    );
}

#[test]
fn session_rsa_tokens_round_trip_and_forgeries_are_refused() {
    let signer = RsaSigner::from_seed(7).unwrap();
    assert_eq!(signer.alg(), "RS256");
    assert_eq!(signer.kid().len(), 16);
    let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let uid = store
        .create_user(NewUser::email("a@example.com"), START)
        .unwrap();
    let claims = store.id_token_claims(&uid, None, START).unwrap();
    // Before the signer is installed the store issues and accepts unsigned tokens.
    let unsigned = encode_with(&claims, store.signer());
    assert!(unsigned.ends_with('.'));
    assert!(verify_id_token(&unsigned, &store, START).is_ok());
    store.set_signer(signer.clone());
    let token = encode_with(&claims, store.signer());
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert!(!parts[2].is_empty());
    let header: serde_json::Value =
        serde_json::from_slice(&fireemu_core_auth::jwt::base64url_decode(parts[0]).unwrap())
            .unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["kid"], signer.kid());
    assert_eq!(
        verify_id_token(&token, &store, START).unwrap().uid,
        uid.as_str()
    );
    // Same seed, same key: tokens are reproducible; another seed does not verify.
    let again = RsaSigner::from_seed(7).unwrap();
    assert_eq!(again.kid(), signer.kid());
    let other = RsaSigner::from_seed(8).unwrap();
    assert_ne!(other.kid(), signer.kid());
    assert!(!other.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &fireemu_core_auth::jwt::base64url_decode(parts[2]).unwrap()
    ));
    // Forgeries: a tampered payload, a foreign signature, and an unsigned token.
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        fireemu_core_auth::jwt::base64url_encode(
            claims
                .canonical_json()
                .replace(uid.as_str(), "someone")
                .as_bytes()
        ),
        parts[2]
    );
    assert!(matches!(
        verify_id_token(&tampered, &store, START),
        Err(JwtError::BadSignature)
    ));
    let foreign = encode_with(&claims, Some(other.as_ref()));
    assert!(matches!(
        verify_id_token(&foreign, &store, START),
        Err(JwtError::UnknownKeyId)
    ));
    let foreign_parts: Vec<&str> = foreign.split('.').collect();
    let relabeled = format!("{}.{}.{}", parts[0], foreign_parts[1], foreign_parts[2]);
    assert!(matches!(
        verify_id_token(&relabeled, &store, START),
        Err(JwtError::BadSignature)
    ));
    assert!(matches!(
        verify_id_token(&encode_unsigned(&claims), &store, START),
        Err(JwtError::UnsupportedAlgorithm(_))
    ));
    assert!(matches!(
        decode_token(&token, None),
        Err(JwtError::UnsupportedAlgorithm(_))
    ));
    // A third party verifies against the published JWK (n / e round trip).
    let jwk = signer.jwks()["keys"][0].clone();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&signer.public_jwk_json()).unwrap(),
        jwk
    );
    assert_eq!(
        jwk.as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        ["alg", "e", "kid", "kty", "n", "use"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["kid"], signer.kid());
    assert!(jwk["n"].as_str().unwrap().len() > 300);
    assert_eq!(jwk["e"], "AQAB");
}

#[test]
fn session_rsa_cache_material_round_trips_and_rejects_wrong_key_parameters() {
    use rand_core::SeedableRng as _;
    use rsa::pkcs8::EncodePrivateKey as _;

    let signer = RsaSigner::from_seed(71).unwrap();
    let document = signer.to_pkcs8_der().unwrap();
    let restored = RsaSigner::from_pkcs8_der(document.as_bytes()).unwrap();
    assert_eq!(restored.kid(), signer.kid());

    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(71);
    let weak = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let weak = weak.to_pkcs8_der().unwrap();
    assert!(RsaSigner::from_pkcs8_der(weak.as_bytes()).is_err());
}

#[test]
fn app_check_operating_system_keys_remain_instance_specific() {
    use fireemu_core_app_check::crypto::AppCheckSigner as _;

    let first = AppCheckRsaSigner::generate(AppCheckKeySource::OperatingSystem).unwrap();
    let second = AppCheckRsaSigner::generate(AppCheckKeySource::OperatingSystem).unwrap();
    assert_ne!(first.kid(), second.kid());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&first.public_jwk_json()).unwrap(),
        first.jwks()["keys"][0]
    );
}

#[test]
fn the_auth_surface_issues_signed_tokens_and_serves_the_jwks() {
    let signer = RsaSigner::from_seed(9).unwrap();
    let mut store = AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default());
    store.set_signer(signer.clone());
    let state = AuthState {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    let r = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k",
        &json!({"email": "s@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let token = r.body["idToken"].as_str().unwrap().to_owned();
    assert!(!token.ends_with('.'), "token");
    let store = state.store.lock().unwrap();
    assert!(verify_id_token(&token, &store, START).is_ok());
    let uid = store
        .user_by_id(r.body["localId"].as_str().unwrap())
        .unwrap()
        .local_id
        .clone();
    let claims = store.id_token_claims(&uid, None, START).unwrap();
    assert_eq!(
        token,
        encode_with(&claims, Some(signer.as_ref())),
        "moving signing outside the mutex must not change token bytes"
    );
    drop(store);
    // Lookup accepts it; a forged unsigned token with the same claims does not.
    let ok = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:lookup?key=k",
        &json!({"idToken": token}),
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
    let unsigned = {
        let parts: Vec<&str> = token.split('.').collect();
        format!(
            "{}.{}.",
            fireemu_core_auth::jwt::base64url_encode(br#"{"alg":"none","typ":"JWT"}"#),
            parts[1]
        )
    };
    let forged = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:lookup?key=k",
        &json!({"idToken": unsigned}),
    );
    assert_eq!(forged.status, 400, "{}", forged.body);
    for path in JWKS_PATHS {
        let r = handle(&state, "GET", path, &json!({}));
        assert_eq!(r.status, 200);
        assert_eq!(r.body["keys"][0]["kid"], signer.kid(), "{path}");
    }
    // Without a signer the JWKS is empty.
    let plain = AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        ))),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    let r = handle(&plain, "GET", JWKS_PATHS[0], &json!({}));
    assert_eq!(r.body, json!({"keys": []}));
}
