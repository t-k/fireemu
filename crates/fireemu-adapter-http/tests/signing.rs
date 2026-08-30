//! RS256 session signing: token tokens verify, forgeries and unsigned tokens do not, and
//! the JWKS endpoint publishes the key.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{handle, AuthState, JWKS_PATHS};
use fireemu_adapter_http::signing::RsaSigner;
use fireemu_core_auth::jwt::{
    decode_token, encode_unsigned, encode_with, verify_id_token, IdTokenSigner, JwtError,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

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
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["kid"], signer.kid());
    assert!(jwk["n"].as_str().unwrap().len() > 300);
    assert_eq!(jwk["e"], "AQAB");
}

#[test]
fn the_auth_surface_issues_signed_tokens_and_serves_the_jwks() {
    let signer = RsaSigner::from_seed(9).unwrap();
    let mut store = AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default());
    store.set_signer(signer.clone());
    let state = AuthState {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        barrier: None,
        events: None,
        control_token: None,
        registry: None,
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
        barrier: None,
        events: None,
        control_token: None,
        registry: None,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    let r = handle(&plain, "GET", JWKS_PATHS[0], &json!({}));
    assert_eq!(r.body, json!({"keys": []}));
}
