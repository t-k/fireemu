//! Time-claim validation through the Auth adapter using the existing public test RSA key.
//! These tests invoke the real HTTP handler in-process, not a listening server or Google.

use std::sync::{Arc, Mutex, OnceLock};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthState, RequestHeaders, OWNER_CREDENTIAL,
};
use fireemu_adapter_http::signing::RsaSigner;
use fireemu_core_auth::jwt::{
    base64url_decode, base64url_encode, decode_token, encode_payload_with, verify_rules_token,
    JwtError, TokenAcceptance,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::codec::hex_decode;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const NOW: i64 = 1_788_004_860;
const AT: LogicalInstant = LogicalInstant::from_unix_seconds(NOW);
const SIGN_UP: &str = "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k";
const LOOKUP: &str = "/identitytoolkit.googleapis.com/v1/accounts:lookup?key=k";
const UPDATE: &str = "/identitytoolkit.googleapis.com/v1/accounts:update?key=k";

fn signer() -> Arc<RsaSigner> {
    static SIGNER: OnceLock<Arc<RsaSigner>> = OnceLock::new();
    Arc::clone(SIGNER.get_or_init(|| {
        // Reuse a deliberately public, insecure fixture; never put this key in a release.
        let bytes = include_bytes!("fixtures/INSECURE_TEST_ONLY_RSA_A.der.hex");
        let digits: String = bytes
            .iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(|byte| char::from(*byte))
            .collect();
        let der = hex_decode(&digits).expect("existing test key is hexadecimal");
        RsaSigner::from_pkcs8_der(&der).expect("existing test key is PKCS#8")
    }))
}

fn setup() -> (AuthState, Arc<RsaSigner>, String, String) {
    let signer = signer();
    let mut store = AuthStore::new("demo-app", SplitMix64::new(11), TotpPolicy::default());
    store.set_signer(signer.clone());
    let state = AuthState {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(Mutex::new(VirtualClock::new(AT))),
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
    let response = handle(
        &state,
        "POST",
        SIGN_UP,
        &json!({"email": "temporal@example.invalid", "password": "password1"}),
    );
    assert_eq!(response.status, 200, "signup is the positive route control");
    let token = response.body["idToken"].as_str().unwrap().to_owned();
    let refresh = response.body["refreshToken"].as_str().unwrap().to_owned();
    (state, signer, token, refresh)
}

fn revised_token(original: &str, signer: &RsaSigner, key: &str, value: Option<Value>) -> String {
    let decoded = decode_token(original, Some(signer)).unwrap();
    let mut payload: Value = serde_json::from_str(&decoded.payload_json).unwrap();
    let object = payload.as_object_mut().unwrap();
    match value {
        Some(value) => {
            object.insert(key.to_owned(), value);
        }
        None => {
            object.remove(key);
        }
    }
    let token = encode_payload_with(&payload.to_string(), Some(signer));
    // A temporal rejection must not pass simply because the RSA signature is wrong.
    assert!(decode_token(&token, Some(signer)).is_ok());
    token
}

#[test]
fn signed_bad_time_claims_cannot_change_an_account() {
    let (state, signer, original, _) = setup();
    let before = handle(&state, "POST", LOOKUP, &json!({"idToken": original}));
    assert_eq!(before.status, 200);
    let before_user = before.body["users"][0].clone();
    for (key, value) in [
        ("iat", None),
        ("iat", Some(Value::Null)),
        ("iat", Some(json!(true))),
        ("iat", Some(json!(NOW.to_string()))),
        ("iat", Some(json!(NOW + 600))),
        ("auth_time", Some(json!(NOW + 600))),
    ] {
        let bad = revised_token(&original, signer.as_ref(), key, value);
        let response = handle(
            &state,
            "POST",
            UPDATE,
            &json!({"idToken": bad, "displayName": "must-not-be-committed"}),
        );
        assert_eq!(
            response.status, 400,
            "a well-signed, invalid-time token is refused"
        );
        assert!(response.body.get("idToken").is_none());
        let after = handle(&state, "POST", LOOKUP, &json!({"idToken": original}));
        assert_eq!(
            after.status, 200,
            "the valid token remains usable after refusal"
        );
        assert_eq!(
            after.body["users"][0], before_user,
            "no partial account update"
        );
    }
}

#[test]
fn a_current_second_signed_token_can_update_and_refresh() {
    let (state, signer, original, refresh) = setup();
    let updated = handle(
        &state,
        "POST",
        UPDATE,
        &json!({"idToken": original, "displayName": "valid-change"}),
    );
    assert_eq!(updated.status, 200);
    let looked_up = handle(&state, "POST", LOOKUP, &json!({"idToken": original}));
    assert_eq!(looked_up.status, 200);
    assert_eq!(looked_up.body["users"][0]["displayName"], "valid-change");
    let refreshed = handle(
        &state,
        "POST",
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(refreshed.status, 200);
    let id_token = refreshed.body["id_token"].as_str().unwrap();
    let store = state.store.lock().unwrap();
    assert!(verify_rules_token(id_token, &store, AT, TokenAcceptance::Verified).is_ok());
    assert!(decode_token(id_token, Some(signer.as_ref())).is_ok());
}

#[test]
fn a_signed_temporal_failure_never_enters_the_unsigned_mock_fallback() {
    let (state, signer, original, _) = setup();
    for key in ["iat", "auth_time"] {
        let bad = revised_token(&original, signer.as_ref(), key, Some(json!(NOW + 600)));
        let store = state.store.lock().unwrap();
        for acceptance in [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock] {
            assert_eq!(
                verify_rules_token(&bad, &store, AT, acceptance),
                Err(JwtError::Malformed)
            );
        }
    }
}

#[test]
fn signature_rejection_still_precedes_temporal_rejection() {
    let (state, signer, original, _) = setup();
    let bad_time = revised_token(&original, signer.as_ref(), "iat", Some(json!(NOW + 600)));
    let mut parts: Vec<String> = bad_time.split('.').map(str::to_owned).collect();
    let mut signature = base64url_decode(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = base64url_encode(&signature);
    let corrupted = parts.join(".");
    assert_eq!(
        decode_token(&corrupted, Some(signer.as_ref())),
        Err(JwtError::BadSignature)
    );
    let store = state.store.lock().unwrap();
    assert_eq!(
        verify_rules_token(&corrupted, &store, AT, TokenAcceptance::Verified),
        Err(JwtError::BadSignature)
    );
}

#[test]
fn session_cookie_creation_refuses_future_time_claims_and_accepts_the_original() {
    let (state, signer, original, _) = setup();
    let headers = RequestHeaders {
        authorization: Some(OWNER_CREDENTIAL.to_owned()),
        ..RequestHeaders::default()
    };
    let route = "/identitytoolkit.googleapis.com/v1/projects/demo-app:createSessionCookie";
    let good = handle_with(
        &state,
        "POST",
        route,
        &headers,
        &json!({"idToken": original, "validDuration": "3600"}),
    );
    assert_eq!(
        good.status, 200,
        "positive control for the same route and credential"
    );
    for key in ["iat", "auth_time"] {
        let bad = revised_token(&original, signer.as_ref(), key, Some(json!(NOW + 600)));
        let rejected = handle_with(
            &state,
            "POST",
            route,
            &headers,
            &json!({"idToken": bad, "validDuration": "3600"}),
        );
        assert_eq!(rejected.status, 400);
        assert!(rejected.body.get("sessionCookie").is_none());
    }
}
