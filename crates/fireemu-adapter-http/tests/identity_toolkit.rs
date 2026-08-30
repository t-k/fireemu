//! Identity Toolkit flows through the pure handlers, plus one socket-level smoke test.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{handle, AuthState};
use fireemu_core_auth::base32;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_auth::totp::{totp_at, TotpParams};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";

fn state() -> AuthState {
    AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        barrier: None,
        events: None,
        control_token: None,
        registry: None,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
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
    // The default (non-private) mode distinguishes a wrong password from an unknown email,
    // as the pinned official emulator does (auth/identity-toolkit-error-shapes).
    assert_eq!(wrong["error"]["message"], "INVALID_PASSWORD");
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
    let decoded = fireemu_core_auth::jwt::decode_unsigned(token).unwrap();
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
    let decoded =
        fireemu_core_auth::jwt::decode_unsigned(done["idToken"].as_str().unwrap()).unwrap();
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
    let decoded =
        fireemu_core_auth::jwt::decode_unsigned(signed["idToken"].as_str().unwrap()).unwrap();
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
    let server = tokio::spawn(fireemu_adapter_http::server::serve(
        listener,
        shared.clone(),
    ));
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

// ------------------------------------------------------------------------------------------
// Admin SDK (project-scoped) routes
// ------------------------------------------------------------------------------------------

use fireemu_adapter_http::identity_toolkit::{handle_with, RequestHeaders};

const ADMIN: &str = "/identitytoolkit.googleapis.com/v1/projects/demo-app";

fn owner() -> RequestHeaders {
    RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        content_type: Some("application/json".to_owned()),
        host: None,
        app_check: Vec::new(),
    }
}
fn admin(state: &AuthState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let r = handle_with(state, method, path, &owner(), body);
    (r.status, r.body)
}

#[test]
fn admin_routes_require_the_owner_credential_a_local_origin_and_the_right_project() {
    let s = state();
    let body = json!({"email": "a@example.com", "password": "password1"});
    let anon = handle_with(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &RequestHeaders::default(),
        &body,
    );
    assert_eq!(anon.status, 401);
    let mut foreign = owner();
    foreign.origin = Some("https://evil.example".to_owned());
    assert_eq!(
        handle_with(&s, "POST", &format!("{ADMIN}/accounts"), &foreign, &body).status,
        403
    );
    let mut local = owner();
    local.origin = Some("http://localhost:5173".to_owned());
    let mut text = owner();
    text.content_type = Some("text/plain".to_owned());
    assert_eq!(
        handle_with(&s, "POST", &format!("{ADMIN}/accounts"), &text, &body).status,
        415
    );
    let (status, _) = admin(
        &s,
        "POST",
        "/identitytoolkit.googleapis.com/v1/projects/other/accounts",
        &body,
    );
    assert_eq!(status, 400);
    let (status, _) = admin(
        &s,
        "POST",
        "/identitytoolkit.googleapis.com/v1/projects//accounts:delete",
        &json!({"localId": "x"}),
    );
    // An empty project segment is no route at all.
    assert_eq!(status, 404);
    assert_eq!(
        handle_with(&s, "POST", &format!("{ADMIN}/accounts"), &local, &body).status,
        200
    );
    assert_eq!(
        admin(&s, "GET", &format!("{ADMIN}/accounts:lookup"), &json!({})).0,
        405
    );
}

#[test]
fn admin_create_is_atomic_and_typed() {
    let s = state();
    // Weak password: nothing is created (the email / uid are not squatted).
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "u-alice", "email": "alice@example.com", "password": "short"}),
    );
    assert_eq!(status, 400);
    let (status, body) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["u-alice"]}),
    );
    assert_eq!(status, 200);
    assert!(
        body.get("users").is_none(),
        "no match is an absent users, as the official emulator answers"
    );
    // Wrong JSON types are rejected instead of being treated as absent.
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": 42, "email": "alice@example.com"}),
    );
    assert_eq!(status, 400);
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"email": "alice@example.com", "disabled": "yes"}),
    );
    assert_eq!(status, 400);
    let (status, body) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "u-alice", "email": "alice@example.com", "password": "password1", "displayName": "Alice"}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["localId"], "u-alice");
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "u-alice", "email": "other@example.com"}),
    );
    assert_eq!(status, 400, "duplicate uid");
    // A generated ID never replaces a caller-chosen one.
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "gen@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200);
    assert_ne!(body["localId"], "u-alice");
}

#[test]
fn admin_lookup_resolves_every_identifier_and_batch_get_pages_over_get() {
    let s = state();
    for i in 0..5 {
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": format!("u{i}"), "email": format!("u{i}@example.com")}),
        );
        assert_eq!(status, 200);
    }
    let (status, body) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["u1", "u3", "u1"], "email": ["u4@example.com", "nobody@example.com"]}),
    );
    assert_eq!(status, 200);
    let ids: Vec<&str> = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["localId"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["u1", "u3", "u4"]);
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [1]}),
    );
    assert_eq!(status, 400);

    let (status, page1) = admin(
        &s,
        "GET",
        &format!("{ADMIN}/accounts:batchGet?maxResults=2"),
        &json!({}),
    );
    assert_eq!(status, 200, "{page1}");
    assert_eq!(page1["users"].as_array().map(Vec::len), Some(2));
    let token = page1["nextPageToken"].as_str().unwrap().to_owned();
    let (status, page2) = admin(
        &s,
        "GET",
        &format!("{ADMIN}/accounts:batchGet?maxResults=2&nextPageToken={token}"),
        &json!({}),
    );
    assert_eq!(status, 200);
    let token2 = page2["nextPageToken"].as_str().unwrap().to_owned();
    let (_, page3) = admin(
        &s,
        "GET",
        &format!("{ADMIN}/accounts:batchGet?maxResults=2&nextPageToken={token2}"),
        &json!({}),
    );
    assert_eq!(page3["users"].as_array().map(Vec::len), Some(1));
    assert!(page3.get("nextPageToken").is_none());
    let (status, _) = admin(
        &s,
        "GET",
        &format!("{ADMIN}/accounts:batchGet?maxResults=0"),
        &json!({}),
    );
    assert_eq!(status, 400);
}

#[test]
fn admin_password_change_revokes_sessions_and_update_is_atomic() {
    let s = state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "p@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200);
    let uid = signed["localId"].as_str().unwrap().to_owned();
    let refresh = signed["refreshToken"].as_str().unwrap().to_owned();
    // Weak new password: the claims in the same request are not applied either.
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "password": "x", "customAttributes": "{\"role\":\"admin\"}"}),
    );
    assert_eq!(status, 400);
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": uid}),
    );
    assert_eq!(looked["users"][0]["customAttributes"], "{}");
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "password": "password2"}),
    );
    assert_eq!(status, 200);
    let (status, _) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(
        status, 400,
        "old refresh tokens are revoked by a password change"
    );
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "p@example.com", "password": "password2", "returnSecureToken": true}),
    );
    assert_eq!(status, 200);
}

// ------------------------------------------------------------------------------------------
// Custom token sign-in
// ------------------------------------------------------------------------------------------

fn custom_token(uid: &str, claims: &Value, exp: i64) -> String {
    use fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE;
    use fireemu_core_auth::jwt::base64url_encode;
    let header = base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = json!({
        "aud": CUSTOM_TOKEN_AUDIENCE,
        "iss": "firebase-auth-emulator@example.com",
        "sub": "firebase-auth-emulator@example.com",
        "uid": uid,
        "claims": claims,
        "iat": exp - 3600,
        "exp": exp,
    });
    let payload = base64url_encode(payload.to_string().as_bytes());
    format!("{header}.{payload}.")
}

#[test]
fn custom_tokens_sign_in_creating_the_user_and_carry_developer_claims() {
    let s = state();
    let now_secs = 1_788_004_860;
    let token = custom_token("custom-1", &json!({"role": "tester"}), now_secs + 3600);
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": token, "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["isNewUser"], true);
    assert_eq!(body["localId"], "custom-1");
    let id_token = body["idToken"].as_str().unwrap();
    let decoded = fireemu_core_auth::jwt::decode_unsigned(id_token).unwrap();
    assert_eq!(
        decoded.payload.get("role").and_then(|v| v.as_str()),
        Some("tester")
    );
    assert_eq!(
        decoded.payload.get("sub").and_then(|v| v.as_str()),
        Some("custom-1")
    );
    // Second sign-in: same user, not new; claims are per token, not stored.
    let again = custom_token("custom-1", &json!({}), now_secs + 3600);
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": again}),
    );
    assert_eq!(status, 200);
    assert_eq!(body["isNewUser"], false);
    let decoded =
        fireemu_core_auth::jwt::decode_unsigned(body["idToken"].as_str().unwrap()).unwrap();
    assert!(decoded.payload.get("role").is_none());
    // Reserved claims, wrong audience and expired tokens are rejected.
    let reserved = custom_token("custom-2", &json!({"sub": "x"}), now_secs + 3600);
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": reserved})
        )
        .0,
        400
    );
    let expired = custom_token("custom-3", &json!({}), now_secs - 1);
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": expired})
        )
        .0,
        400
    );
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": "nope"})
        )
        .0,
        400
    );
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["custom-2", "custom-3"]}),
    );
    assert_eq!(
        looked.get("users").map(|u| u.as_array().map(Vec::len)),
        None,
        "rejected tokens create nobody"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn admin_update_applies_every_supported_field_and_refuses_the_rest() {
    let s = state();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "u-a", "email": "a@example.com", "phoneNumber": "+15550000001", "photoUrl": "https://x/a.png", "displayName": "A"}),
    );
    assert_eq!(status, 200);
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "u-b", "email": "b@example.com"}),
    );
    assert_eq!(status, 200);
    // Uniqueness of email and phone number across users.
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "u-b", "email": "a@example.com"})
        )
        .0,
        400
    );
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "u-b", "phoneNumber": "+15550000001"})
        )
        .0,
        400
    );
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": "u-c", "phoneNumber": "+15550000001"})
        )
        .0,
        400
    );
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "u-b", "phoneNumber": "12345"})
        )
        .0,
        400,
        "not E.164"
    );
    // Provider links, unlinks and admin-enrolled phone factors are applied.
    assert_eq!(admin(&s, "POST", &format!("{ADMIN}/accounts:update"), &json!({"localId": "u-b", "linkProviderUserInfo": {"providerId": "google.com", "rawId": "1"}})).0, 200);
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "u-b", "deleteProvider": ["google.com"]})
        )
        .0,
        200
    );
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": "u-m", "mfaInfo": [{"phoneInfo": "+15550000009"}]})
        )
        .0,
        200
    );
    // A malformed link and a TOTP admin enrollment are refused.
    assert_eq!(admin(&s, "POST", &format!("{ADMIN}/accounts:update"), &json!({"localId": "u-b", "linkProviderUserInfo": {"providerId": "password", "rawId": "x"}})).0, 400);
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "u-b", "mfa": {"enrollments": [{"totpInfo": {}}]}})
        )
        .0,
        400
    );
    // Applied fields.
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "u-a", "email": "a2@example.com", "phoneNumber": "+15550000002", "deleteAttribute": ["DISPLAY_NAME"], "photoUrl": "https://x/a2.png"}),
    );
    assert_eq!(status, 200);
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"phoneNumber": ["+15550000002"]}),
    );
    let u = &looked["users"][0];
    assert_eq!(u["localId"], "u-a");
    assert_eq!(u["email"], "a2@example.com");
    assert_eq!(u["photoUrl"], "https://x/a2.png");
    assert!(u["displayName"].is_null());
    assert!(
        u["validSince"].as_str().is_some(),
        "tokensValidAfterTime source"
    );
    assert_eq!(u["providerUserInfo"].as_array().map(Vec::len), Some(2));
    // deleteProvider phone clears the number; federated lookups match nobody; an admin
    // lookup without identifiers is an error rather than an ID-token lookup.
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "u-a", "deleteProvider": ["phone"]})
        )
        .0,
        200
    );
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"phoneNumber": ["+15550000002"], "federatedUserId": [{"providerId": "google.com", "rawId": "1"}]}),
    );
    assert_eq!(
        looked.get("users").map(|u| u.as_array().map(Vec::len)),
        None
    );
    assert_eq!(
        admin(&s, "POST", &format!("{ADMIN}/accounts:lookup"), &json!({})).0,
        400
    );
    // Page tokens are validated.
    assert_eq!(
        admin(
            &s,
            "GET",
            &format!("{ADMIN}/accounts:batchGet?nextPageToken=u-a"),
            &json!({})
        )
        .0,
        400
    );
}

#[test]
fn form_encoded_token_refresh_is_accepted_by_the_server_layer() {
    // The JS SDK posts the refresh as application/x-www-form-urlencoded; the server layer
    // turns it into the JSON object the handler expects. Covered here at the handler level
    // with the decoded shape, and end to end by tools/sdk-smoke/web.
    let s = state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "f@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200);
    let refresh = signed["refreshToken"].as_str().unwrap();
    let (status, body) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["id_token"].as_str().is_some());
}

#[test]
fn refreshed_tokens_keep_the_custom_token_provider_and_claims() {
    let s = state();
    let now_secs = 1_788_004_860;
    let token = custom_token("custom-r", &json!({"role": "tester"}), now_secs + 3600);
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": token, "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    let refresh = body["refreshToken"].as_str().unwrap();
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{refreshed}");
    let decoded =
        fireemu_core_auth::jwt::decode_unsigned(refreshed["id_token"].as_str().unwrap()).unwrap();
    assert_eq!(
        decoded.payload.get("role").and_then(|v| v.as_str()),
        Some("tester")
    );
    assert_eq!(
        decoded
            .payload
            .get("firebase")
            .and_then(|f| f.get("sign_in_provider"))
            .and_then(|v| v.as_str()),
        Some("custom")
    );
    // A password user signing in with a custom token also gets a custom-provider session.
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "pw@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200);
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"email": ["pw@example.com"]}),
    );
    let uid = looked["users"][0]["localId"].as_str().unwrap().to_owned();
    let token = custom_token(&uid, &json!({}), now_secs + 3600);
    let (_, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": token}),
    );
    let decoded =
        fireemu_core_auth::jwt::decode_unsigned(body["idToken"].as_str().unwrap()).unwrap();
    assert_eq!(
        decoded
            .payload
            .get("firebase")
            .and_then(|f| f.get("sign_in_provider"))
            .and_then(|v| v.as_str()),
        Some("custom")
    );
    assert!(looked["users"][0]["lastLoginAt"].is_string() || body["localId"] == uid);
}
