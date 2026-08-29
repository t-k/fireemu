//! Identity Toolkit flows through the pure handlers, plus one socket-level smoke test.

use std::sync::{Arc, Mutex};

use ftd_adapter_http::identity_toolkit::{handle, AuthState};
use ftd_core_auth::base32;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::AuthStore;
use ftd_core_auth::totp::{totp_at, TotpParams};
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::SplitMix64;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";

fn state() -> AuthState {
    AuthState {
        store: Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        )),
        clock: Mutex::new(VirtualClock::new(LogicalInstant::from_unix_seconds(
            1_788_004_860,
        ))),
    }
}

fn post(state: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let r = handle(state, "POST", path, body);
    (r.status, r.body)
}

fn advance(state: &AuthState, seconds: i64) -> LogicalInstant {
    state
        .clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(seconds))
        .unwrap()
}

#[test]
fn sign_up_sign_in_lookup_and_refresh() {
    let s = state();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    let id_token = body["idToken"].as_str().unwrap().to_owned();
    assert_eq!(id_token.split('.').count(), 3);
    assert_eq!(body["expiresIn"], "3600");
    let (status, dup) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400);
    assert_eq!(dup["error"]["message"], "EMAIL_EXISTS");
    let (status, weak) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "b@example.com", "password": "12345"}),
    );
    assert_eq!(status, 400);
    assert!(weak["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("WEAK_PASSWORD"));

    let (status, wrong) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "nope"}),
    );
    assert_eq!(status, 400);
    assert_eq!(wrong["error"]["message"], "INVALID_LOGIN_CREDENTIALS");
    let (status, ok) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{ok}");
    let refresh = ok["refreshToken"].as_str().unwrap().to_owned();

    let (status, users) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": id_token}),
    );
    assert_eq!(status, 200);
    assert_eq!(users["users"][0]["email"], "a@example.com");

    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(refreshed["project_id"], "demo-app");
    assert!(refreshed["id_token"].as_str().unwrap().split('.').count() == 3);
    let (status, bad) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": "rt-bogus"}),
    );
    assert_eq!(status, 400);
    assert_eq!(bad["error"]["message"], "INVALID_REFRESH_TOKEN");
}

#[test]
fn custom_claims_via_accounts_update_show_up_in_tokens() {
    let s = state();
    let (_, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let uid = body["localId"].as_str().unwrap().to_owned();
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"localId": uid, "customAttributes": "{\"role\":\"admin\"}"}),
    );
    assert_eq!(status, 200);
    let (status, bad) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"localId": uid, "customAttributes": "{\"sub\":\"x\"}"}),
    );
    assert_eq!(status, 400);
    assert!(bad["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("FORBIDDEN_CLAIM"));
    let (_, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let token = signed_in["idToken"].as_str().unwrap();
    let decoded = ftd_core_auth::jwt::decode_unsigned(token).unwrap();
    assert_eq!(
        decoded.payload.get("role").and_then(|v| v.as_str()),
        Some("admin")
    );
    let (_, users) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"localId": uid}),
    );
    assert_eq!(
        users["users"][0]["customAttributes"],
        "{\"role\":\"admin\"}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn totp_enrollment_and_second_factor_sign_in_on_the_virtual_clock() {
    let s = state();
    let (_, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let id_token = body["idToken"].as_str().unwrap().to_owned();

    let (status, start) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": id_token, "totpEnrollmentInfo": {}}),
    );
    assert_eq!(status, 200, "{start}");
    let info = &start["totpSessionInfo"];
    assert_eq!(info["hashingAlgorithm"], "HMAC_SHA1");
    assert_eq!(info["periodSec"], 30);
    assert_eq!(info["verificationCodeLength"], 6);
    let secret = base32::decode(info["sharedSecretKey"].as_str().unwrap()).unwrap();
    let session = info["sessionInfo"].as_str().unwrap().to_owned();
    let params = TotpParams {
        period_seconds: 30,
        digits: 6,
    };

    // Wrong code first, then the right one.
    let now = s.clock.lock().unwrap().now_for_test();
    let good = totp_at(&secret, &params, now);
    let (status, bad) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "totpVerificationInfo": {"sessionInfo": session, "verificationCode": format!("{:06}", (good + 1) % 1_000_000)}}),
    );
    assert_eq!(status, 400);
    assert_eq!(bad["error"]["message"], "INVALID_CODE");
    let (status, done) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "totpVerificationInfo": {"sessionInfo": session, "verificationCode": format!("{good:06}")}}),
    );
    assert_eq!(status, 200, "{done}");
    let enrollment_id = done["mfaEnrollmentId"].as_str().unwrap().to_owned();
    let decoded = ftd_core_auth::jwt::decode_unsigned(done["idToken"].as_str().unwrap()).unwrap();
    assert_eq!(
        decoded
            .payload
            .get("firebase")
            .and_then(|f| f.get("sign_in_second_factor"))
            .and_then(|v| v.as_str()),
        Some("totp")
    );

    // Password sign-in now returns a pending credential instead of a token.
    let later = advance(&s, 120);
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none());
    assert_eq!(pending["mfaInfo"][0]["mfaEnrollmentId"], enrollment_id);
    let credential = pending["mfaPendingCredential"].as_str().unwrap().to_owned();

    let code = totp_at(&secret, &params, later);
    let (status, signed) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential, "mfaEnrollmentId": enrollment_id, "totpVerificationInfo": {"verificationCode": format!("{code:06}")}}),
    );
    assert_eq!(status, 200, "{signed}");
    let decoded = ftd_core_auth::jwt::decode_unsigned(signed["idToken"].as_str().unwrap()).unwrap();
    assert_eq!(
        decoded
            .payload
            .get("firebase")
            .and_then(|f| f.get("second_factor_identifier"))
            .and_then(|v| v.as_str()),
        Some(enrollment_id.as_str())
    );

    // Replaying the same code is refused; a code from the next step works.
    let (_, pending2) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let credential2 = pending2["mfaPendingCredential"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, replay) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential2, "totpVerificationInfo": {"verificationCode": format!("{code:06}")}}),
    );
    assert_eq!(status, 400);
    assert!(replay["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("INVALID_CODE"));
    let next = advance(&s, 30);
    let (_, pending3) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let credential3 = pending3["mfaPendingCredential"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential3, "totpVerificationInfo": {"verificationCode": format!("{:06}", totp_at(&secret, &params, next))}}),
    );
    assert_eq!(status, 200);

    // A second enrollment is refused.
    let (status, again) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": id_token, "totpEnrollmentInfo": {}}),
    );
    assert_eq!(status, 400);
    assert_eq!(again["error"]["message"], "SECOND_FACTOR_EXISTS");
}

#[test]
fn expired_enrollment_session_and_disabled_user() {
    let s = state();
    let (_, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let id_token = body["idToken"].as_str().unwrap().to_owned();
    let uid = body["localId"].as_str().unwrap().to_owned();
    let (_, start) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": id_token, "totpEnrollmentInfo": {}}),
    );
    let secret = base32::decode(
        start["totpSessionInfo"]["sharedSecretKey"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let session = start["totpSessionInfo"]["sessionInfo"]
        .as_str()
        .unwrap()
        .to_owned();
    let late = advance(&s, 301);
    let code = totp_at(
        &secret,
        &TotpParams {
            period_seconds: 30,
            digits: 6,
        },
        late,
    );
    let (status, expired) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "totpVerificationInfo": {"sessionInfo": session, "verificationCode": format!("{code:06}")}}),
    );
    assert_eq!(status, 400);
    assert_eq!(expired["error"]["message"], "SESSION_EXPIRED");

    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"localId": uid, "disableUser": true}),
    );
    assert_eq!(status, 200);
    let (status, disabled) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400);
    assert_eq!(disabled["error"]["message"], "USER_DISABLED");
    let (status, revoked) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": id_token}),
    );
    assert_eq!(status, 400);
    assert!(revoked["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("TOKEN_EXPIRED"));
}

#[test]
fn unknown_paths_and_methods() {
    let s = state();
    assert_eq!(
        handle(&s, "GET", &format!("{V1}/accounts:signUp"), &json!({})).status,
        405
    );
    assert_eq!(handle(&s, "POST", "/nope", &json!({})).status, 404);
    assert_eq!(
        handle(
            &s,
            "POST",
            &format!("{V2}/accounts/mfaSignIn:start"),
            &json!({})
        )
        .status,
        400
    );
}

#[tokio::test]
async fn serves_over_a_real_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(state());
    let server = tokio::spawn(ftd_adapter_http::server::serve(listener, shared.clone()));
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = r#"{"email":"s@example.com","password":"hunter22"}"#;
    let request = format!(
        "POST {V1}/accounts:signUp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8(response).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    let json_start = text.find("\r\n\r\n").unwrap() + 4;
    let parsed: Value = serde_json::from_str(&text[json_start..]).unwrap();
    assert_eq!(parsed["email"], "s@example.com");
    server.abort();
}
