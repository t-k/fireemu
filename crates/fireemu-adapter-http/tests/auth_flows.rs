//! Email actions (oob codes), email link and phone sign-in, fixture identity providers,
//! phone second factors and the emulator inspection routes.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{handle, handle_with, AuthState, RequestHeaders};
use fireemu_core_auth::jwt::{base64url_encode, decode_unsigned};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const EMU: &str = "/emulator/v1/projects/demo-app";

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
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    }
}

fn post(state: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let r = handle(state, "POST", path, body);
    (r.status, r.body)
}

fn get(state: &AuthState, path: &str) -> (u16, Value) {
    let r = handle(state, "GET", path, &json!({}));
    (r.status, r.body)
}

fn owner() -> RequestHeaders {
    RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        content_type: Some("application/json".to_owned()),
        host: Some("127.0.0.1:9099".to_owned()),
        app_check: Vec::new(),
    }
}

fn admin(state: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let r = handle_with(state, "POST", path, &owner(), body);
    (r.status, r.body)
}

fn sign_up(state: &AuthState, email: &str) -> Value {
    let (status, body) = post(
        state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": email, "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{body}");
    body
}

fn claims(id_token: &str) -> Value {
    serde_json::from_str(&decode_unsigned(id_token).unwrap().payload_json).unwrap()
}

/// Marks the address verified through the Admin route: the pinned official emulator refuses
/// phone-factor enrollment for an unverified password user (`UNVERIFIED_EMAIL`).
fn verify_email(state: &AuthState, local_id: &str) {
    let (status, body) = admin(
        state,
        "/identitytoolkit.googleapis.com/v1/projects/demo-app/accounts:update",
        &json!({"localId": local_id, "emailVerified": true}),
    );
    assert_eq!(status, 200, "{body}");
}

#[test]
fn password_reset_goes_through_an_oob_code_the_test_can_read() {
    let s = state();
    sign_up(&s, "a@example.com");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "a@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["email"], "a@example.com");
    assert!(body.get("oobCode").is_none(), "clients never see the code");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "nobody@example.com"}),
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"]["message"], "EMAIL_NOT_FOUND");
    // The inspection route lists it with its link.
    let (status, codes) = get(&s, &format!("{EMU}/oobCodes"));
    assert_eq!(status, 200);
    let entry = &codes["oobCodes"][0];
    assert_eq!(entry["email"], "a@example.com");
    assert_eq!(entry["requestType"], "PASSWORD_RESET");
    let code = entry["oobCode"].as_str().unwrap().to_owned();
    assert!(entry["oobLink"]
        .as_str()
        .unwrap()
        .contains(&format!("mode=resetPassword&lang=en&oobCode={code}")));
    // verifyPasswordResetCode, then confirmPasswordReset.
    let (status, verified) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code}),
    );
    assert_eq!(status, 200, "{verified}");
    assert_eq!(verified["email"], "a@example.com");
    let (status, weak) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code, "newPassword": "short"}),
    );
    assert_eq!(status, 400, "{weak}");
    let (status, done) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code, "newPassword": "newpassword1"}),
    );
    assert_eq!(status, 200, "{done}");
    // Consumed: a second use fails; the new password signs in, the old one does not.
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code, "newPassword": "another1"}),
    );
    assert_eq!(status, 400);
    assert!(get(&s, &format!("{EMU}/oobCodes")).1["oobCodes"]
        .as_array()
        .unwrap()
        .is_empty());
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400);
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "newpassword1"}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(
        claims(signed["idToken"].as_str().unwrap())["email_verified"],
        true
    );
}

#[test]
fn email_verification_and_email_change_apply_action_codes() {
    let s = state();
    let user = sign_up(&s, "v@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    assert_eq!(claims(&id_token)["email_verified"], false);
    // sendEmailVerification (with the session) and the Admin link generator (returnOobLink).
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": id_token}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, link) = admin(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "email": "v@example.com", "returnOobLink": true, "continueUrl": "https://app.example/x?y=1"}),
    );
    assert_eq!(status, 200, "{link}");
    let code = link["oobCode"].as_str().unwrap().to_owned();
    assert!(link["oobLink"]
        .as_str()
        .unwrap()
        .ends_with("&continueUrl=https%3A%2F%2Fapp.example%2Fx%3Fy%3D1"));
    // applyActionCode: accounts:update with the code.
    let (status, applied) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": code}),
    );
    assert_eq!(status, 200, "{applied}");
    assert_eq!(applied["emailVerified"], true);
    let (status, again) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": code}),
    );
    assert_eq!(status, 400);
    assert_eq!(again["error"]["message"], "INVALID_OOB_CODE");
    let (_, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": id_token}),
    );
    assert_eq!(lookup["users"][0]["emailVerified"], true);
    // verifyBeforeUpdateEmail.
    let (status, change) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "idToken": id_token, "newEmail": "new@example.com", "returnOobLink": true}),
    );
    assert_eq!(status, 200, "{change}");
    let code = change["oobCode"].as_str().unwrap().to_owned();
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": code}),
    );
    assert_eq!(status, 200);
    let (_, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": id_token}),
    );
    assert_eq!(lookup["users"][0]["email"], "new@example.com");
}

#[test]
fn email_link_sign_in_creates_a_verified_passwordless_user() {
    let s = state();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "link@example.com", "continueUrl": "https://app.example/finish"}),
    );
    assert_eq!(status, 200, "{body}");
    let (_, codes) = get(&s, &format!("{EMU}/oobCodes"));
    let code = codes["oobCodes"][0]["oobCode"].as_str().unwrap().to_owned();
    assert_eq!(codes["oobCodes"][0]["requestType"], "EMAIL_SIGNIN");
    // The email must match the code.
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "other@example.com", "oobCode": code}),
    );
    assert_eq!(status, 400);
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "link@example.com", "oobCode": code}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["isNewUser"], true);
    let c = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(c["email_verified"], true);
    assert_eq!(c["firebase"]["sign_in_provider"], "emailLink");
    // fetchSignInMethodsForEmail sees a passwordless user.
    let (_, methods) = post(
        &s,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "link@example.com", "continueUri": "http://localhost"}),
    );
    assert_eq!(methods["registered"], true);
    assert_eq!(methods["signinMethods"], json!(["emailLink"]));
    let (_, unknown) = post(
        &s,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "nobody@example.com", "continueUri": "http://localhost"}),
    );
    assert_eq!(unknown["registered"], false);
}

#[test]
fn phone_sign_in_uses_a_deterministic_code_from_the_inspection_route() {
    let s = state();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15551234567", "recaptchaToken": "ignored"}),
    );
    assert_eq!(status, 200, "{body}");
    let session = body["sessionInfo"].as_str().unwrap().to_owned();
    let (status, bad) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "555"}),
    );
    assert_eq!(status, 400);
    assert_eq!(bad["error"]["message"], "INVALID_PHONE_NUMBER");
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let entry = &codes["verificationCodes"][0];
    assert_eq!(entry["phoneNumber"], "+15551234567");
    assert_eq!(entry["sessionInfo"], session);
    let code = entry["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 6);
    let (status, wrong) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": session, "code": "000000"}),
    );
    assert!(status == 400 || code == "000000", "{wrong}");
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": session, "code": code}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["isNewUser"], true);
    assert_eq!(signed["phoneNumber"], "+15551234567");
    let c = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(c["phone_number"], "+15551234567");
    assert_eq!(c["firebase"]["sign_in_provider"], "phone");
    assert_eq!(
        c["firebase"]["identities"]["phone"],
        json!(["+15551234567"])
    );
    // A consumed code cannot be replayed; a second sign-in finds the same user.
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": session, "code": code}),
    );
    assert_eq!(status, 400);
    let (_, again) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15551234567"}),
    );
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"][0]["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, second) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": again["sessionInfo"], "code": code}),
    );
    assert_eq!(second["isNewUser"], false);
    assert_eq!(second["localId"], signed["localId"]);
    // Linking a number to a password user.
    let user = sign_up(&s, "p@example.com");
    let (_, sent) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15550000001"}),
    );
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"][0]["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, linked) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"], "code": code, "idToken": user["idToken"]}),
    );
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["localId"], user["localId"]);
    let (_, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"phoneNumber": ["+15550000001"]}),
    );
    assert_eq!(lookup["users"][0]["localId"], user["localId"]);
}

fn idp_jwt(payload: &Value) -> String {
    format!(
        "{}.{}.",
        base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#),
        base64url_encode(payload.to_string().as_bytes())
    )
}

#[test]
#[allow(clippy::too_many_lines)]
fn fixture_identity_providers_sign_in_link_and_show_up_as_provider_info() {
    let s = state();
    let google = json!({"sub": "g-123", "email": "g@example.com", "name": "G User", "picture": "https://p/x.png", "email_verified": true});
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}&providerId=google.com", idp_jwt(&google)), "requestUri": "http://localhost", "returnIdpCredential": true}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["isNewUser"], true);
    assert_eq!(signed["providerId"], "google.com");
    // google.com reports the account URL as the federatedId (the official fakeFetchUserInfoFromIdp).
    assert_eq!(signed["federatedId"], "https://accounts.google.com/g-123");
    assert_eq!(signed["rawId"], "g-123");
    assert_eq!(signed["displayName"], "G User");
    assert_eq!(signed["emailVerified"], true);
    let c = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(c["firebase"]["sign_in_provider"], "google.com");
    assert_eq!(c["firebase"]["identities"]["google.com"], json!(["g-123"]));
    assert_eq!(c["email"], "g@example.com");
    // A bare JSON assertion works too, and finds the same user.
    let (status, again) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}&providerId=google.com", percent(&google.to_string())), "requestUri": "http://localhost"}),
    );
    assert_eq!(status, 200, "{again}");
    assert_eq!(again["isNewUser"], false);
    assert_eq!(again["localId"], signed["localId"]);
    // The provider shows in lookups (by federatedUserId too) and in sign-in methods.
    let (_, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"federatedUserId": [{"providerId": "google.com", "rawId": "g-123"}]}),
    );
    let info = &lookup["users"][0]["providerUserInfo"];
    assert!(info
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["providerId"] == "google.com" && p["rawId"] == "g-123"));
    let (_, methods) = post(
        &s,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "g@example.com", "continueUri": "http://localhost"}),
    );
    assert_eq!(methods["signinMethods"], json!(["google.com"]));
    // A password user with the same email gets the identity linked; the sub cannot be
    // linked to a second user.
    let user = sign_up(&s, "pw@example.com");
    let apple = json!({"sub": "a-1", "email": "pw@example.com", "email_verified": true});
    let (status, linked) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}&providerId=apple.com", idp_jwt(&apple)), "requestUri": "http://localhost"}),
    );
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["localId"], user["localId"]);
    assert_eq!(linked["isNewUser"], false);
    let other = sign_up(&s, "other@example.com");
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}&providerId=apple.com", idp_jwt(&apple)), "requestUri": "http://localhost", "idToken": other["idToken"]}),
    );
    assert_eq!(status, 400);
    assert_eq!(
        refused["error"]["message"],
        "FEDERATED_USER_ID_ALREADY_LINKED"
    );
    // Malformed assertions. A request with no credential at all is a NotImplementedError (501,
    // as the official emulator raises it); an unparseable or sub-less id_token is a 400.
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": "providerId=google.com", "requestUri": "http://localhost"}),
    );
    assert_eq!(status, 501);
    for post_body in [
        "id_token=notjson&providerId=google.com".to_owned(),
        format!(
            "id_token={}&providerId=google.com",
            percent(r#"{"email":"x@y"}"#)
        ),
    ] {
        let (status, _) = post(
            &s,
            &format!("{V1}/accounts:signInWithIdp"),
            &json!({"postBody": post_body, "requestUri": "http://localhost"}),
        );
        assert_eq!(status, 400, "{post_body}");
    }
    // A providerId is required (the official INVALID_CREDENTIAL_OR_PROVIDER_ID).
    let (status, no_provider) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}", idp_jwt(&json!({"sub": "x"}))), "requestUri": "http://localhost"}),
    );
    assert_eq!(status, 400);
    assert!(no_provider["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("INVALID_CREDENTIAL_OR_PROVIDER_ID"));
    // A missing requestUri is MISSING_REQUEST_URI.
    let (status, no_uri) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": "providerId=google.com&id_token=x"}),
    );
    assert_eq!(status, 400);
    assert_eq!(no_uri["error"]["message"], "MISSING_REQUEST_URI");
    // Admin: link and unlink providers.
    let (status, _) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": other["localId"], "linkProviderUserInfo": {"providerId": "github.com", "rawId": "gh-9", "email": "gh@example.com"}}),
    );
    assert_eq!(status, 200);
    let (_, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [other["localId"]]}),
    );
    assert!(lookup["users"][0]["providerUserInfo"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["providerId"] == "github.com"));
    let (status, _) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": other["localId"], "deleteProvider": ["github.com"]}),
    );
    assert_eq!(status, 200);
    let (_, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [other["localId"]]}),
    );
    assert!(!lookup["users"][0]["providerUserInfo"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["providerId"] == "github.com"));
}

fn percent(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Measured against the pinned official emulator (`auth/mfa-error-shapes` and
/// `auth/mfa-enrollment-eligibility`): an unverified password user is refused with
/// `UNVERIFIED_EMAIL`, an anonymous session with `UNSUPPORTED_FIRST_FACTOR`, and neither
/// refusal creates a verification code (`AUTH-MFA-EMAIL-01`, `-02`, `-04`).
#[test]
fn phone_enrollment_needs_a_verified_eligible_first_factor_and_refuses_without_side_effect() {
    let s = state();
    let user = sign_up(&s, "unverified@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    let enrol = |token: &str| {
        post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+15559876543", "recaptchaToken": "x"}}),
        )
    };
    let (status, refused) = enrol(&id_token);
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "UNVERIFIED_EMAIL : Need to verify email first before enrolling second factors."
    );
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    assert_eq!(codes["verificationCodes"].as_array().map(Vec::len), Some(0));
    // The finalize step checks the session before anything about the account (measured:
    // auth/mfa-error-shapes#finalize-enrolment-with-an-unknown-session), and consumes no code.
    let (status, refused) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "phoneVerificationInfo": {"sessionInfo": "x", "code": "000000"}}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
    // An anonymous first factor cannot carry a second factor at all.
    let (_, anonymous) = post(&s, &format!("{V1}/accounts:signUp"), &json!({}));
    let (status, refused) = enrol(anonymous["idToken"].as_str().unwrap());
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "UNSUPPORTED_FIRST_FACTOR : MFA is not available for the given first factor."
    );
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    assert_eq!(codes["verificationCodes"].as_array().map(Vec::len), Some(0));
    // Verified, the same user can start enrollment.
    verify_email(&s, user["localId"].as_str().unwrap());
    let (status, started) = enrol(&id_token);
    assert_eq!(status, 200, "{started}");
    assert!(started["phoneSessionInfo"]["sessionInfo"].is_string());
    // The same number cannot be enrolled twice on one account.
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"][0]["code"].as_str().unwrap();
    let (status, _) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "phoneVerificationInfo": {"sessionInfo": started["phoneSessionInfo"]["sessionInfo"], "code": code}}),
    );
    assert_eq!(status, 200);
    let (status, again) = enrol(&id_token);
    assert_eq!(status, 400, "{again}");
    assert!(again["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("SECOND_FACTOR_EXISTS"));
}

#[test]
fn phone_second_factor_enrollment_and_sign_in() {
    let s = state();
    let user = sign_up(&s, "mfa@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    verify_email(&s, user["localId"].as_str().unwrap());
    let (status, start) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": id_token, "phoneEnrollmentInfo": {"phoneNumber": "+15559876543", "recaptchaToken": "x"}}),
    );
    assert_eq!(status, 200, "{start}");
    let session = start["phoneSessionInfo"]["sessionInfo"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"][0]["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, done) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "displayName": "my phone", "phoneVerificationInfo": {"sessionInfo": session, "code": code}}),
    );
    assert_eq!(status, 200, "{done}");
    let c = claims(done["idToken"].as_str().unwrap());
    assert_eq!(c["firebase"]["sign_in_second_factor"], "phone");
    // The finalize response carries only the tokens (measured against the pinned official
    // emulator); the enrollment id is read from the second-factor claim.
    let enrollment_id = c["firebase"]["second_factor_identifier"]
        .as_str()
        .unwrap()
        .to_owned();
    // Password sign-in now stops at the second factor.
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "mfa@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none());
    // Before the second factor is verified the number is obfuscated to its last four
    // digits, as the official emulator's pending-credential response does.
    assert_eq!(pending["mfaInfo"][0]["phoneInfo"], "+*******6543");
    assert_eq!(pending["mfaInfo"][0]["displayName"], "my phone");
    let credential = pending["mfaPendingCredential"].as_str().unwrap().to_owned();
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": credential, "mfaEnrollmentId": enrollment_id, "phoneSignInInfo": {"recaptchaToken": "x"}}),
    );
    assert_eq!(status, 200, "{started}");
    let session = started["phoneResponseInfo"]["sessionInfo"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"][0]["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, wrong) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential, "phoneVerificationInfo": {"sessionInfo": session, "code": "999999"}}),
    );
    assert!(status == 400 || code == "999999", "{wrong}");
    // Wrong code consumed nothing: the session is still there if the code differed.
    if code != "999999" {
        let (status, signed) = post(
            &s,
            &format!("{V2}/accounts/mfaSignIn:finalize"),
            &json!({"mfaPendingCredential": credential, "phoneVerificationInfo": {"sessionInfo": session, "code": code}}),
        );
        assert_eq!(status, 200, "{signed}");
        let c = claims(signed["idToken"].as_str().unwrap());
        assert_eq!(c["firebase"]["sign_in_second_factor"], "phone");
    }
    // Admin: users created with phone factors, listed in mfaInfo; withdraw removes them.
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({"email": "admin-mfa@example.com", "password": "hunter22", "mfaInfo": [{"phoneInfo": "+15550001111", "displayName": "work"}]}),
    );
    assert_eq!(status, 200, "{created}");
    let (_, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [created["localId"]]}),
    );
    assert_eq!(
        lookup["users"][0]["mfaInfo"][0]["phoneInfo"],
        "+15550001111"
    );
    let (status, withdrawn) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:withdraw"),
        &json!({"idToken": done["idToken"], "mfaEnrollmentId": enrollment_id}),
    );
    assert_eq!(status, 200, "{withdrawn}");
    let (status, direct) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "mfa@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200);
    assert!(direct.get("idToken").is_some());
}

#[test]
fn the_inspection_routes_are_project_scoped_and_can_wipe_accounts() {
    let s = state();
    sign_up(&s, "w@example.com");
    assert_eq!(get(&s, "/emulator/v1/projects/other/oobCodes").0, 400);
    assert_eq!(get(&s, &format!("{EMU}/nothing")).0, 404);
    assert_eq!(post(&s, &format!("{EMU}/oobCodes"), &json!({})).0, 405);
    let foreign = RequestHeaders {
        origin: Some("https://evil.example".to_owned()),
        ..RequestHeaders::default()
    };
    assert_eq!(
        handle_with(&s, "GET", &format!("{EMU}/oobCodes"), &foreign, &json!({})).status,
        403
    );
    assert_eq!(
        get(&s, &format!("{EMU}/config")).1["signIn"]["allowDuplicateEmails"],
        false
    );
    let r = handle(&s, "DELETE", &format!("{EMU}/accounts"), &json!({}));
    assert_eq!(r.status, 200);
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "w@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400);
}

#[test]
fn an_unverified_provider_email_never_claims_an_existing_account() {
    let s = state();
    let victim = sign_up(&s, "victim@example.com");
    // An unverified email that belongs to someone else: the account is not taken over, no
    // token is issued and no second account is created. The official emulator answers
    // needConfirmation (the SDKs surface it as account-exists-with-different-credential), not
    // a signed-in session.
    let forged = json!({"sub": "attacker", "email": "victim@example.com", "email_verified": false});
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}&providerId=google.com", idp_jwt(&forged)), "requestUri": "http://localhost"}),
    );
    assert_eq!(status, 200, "{refused}");
    assert_eq!(refused["needConfirmation"], true);
    assert_eq!(refused["localId"], victim["localId"]);
    assert!(refused.get("idToken").is_none());
    assert!(refused.get("refreshToken").is_none());
    // Without the claim at all the email is treated as unverified too.
    let silent = json!({"sub": "attacker-2", "email": "victim@example.com"});
    let (status, silent_refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}&providerId=github.com", idp_jwt(&silent)), "requestUri": "http://localhost"}),
    );
    assert_eq!(status, 200);
    assert_eq!(silent_refused["needConfirmation"], true);
    assert!(silent_refused.get("idToken").is_none());
    let (_, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"email": ["victim@example.com"]}),
    );
    assert_eq!(lookup["users"].as_array().unwrap().len(), 1);
    assert_eq!(lookup["users"][0]["localId"], victim["localId"]);
    assert!(lookup["users"][0]["providerUserInfo"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["providerId"] == "password"));
    // A fresh unverified email creates an unverified user.
    let fresh = json!({"sub": "fresh-1", "email": "fresh@example.com"});
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}&providerId=github.com", idp_jwt(&fresh)), "requestUri": "http://localhost"}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["isNewUser"], true);
    assert_eq!(signed["emailVerified"], false);
}

#[test]
fn second_factors_gate_every_sign_in_route() {
    let s = state();
    let user = sign_up(&s, "gated@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    verify_email(&s, user["localId"].as_str().unwrap());
    let (_, start) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": id_token, "phoneEnrollmentInfo": {"phoneNumber": "+15550009999"}}),
    );
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"][0]["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "phoneVerificationInfo": {"sessionInfo": start["phoneSessionInfo"]["sessionInfo"], "code": code}}),
    );
    assert_eq!(status, 200);
    // Email link for the same address: pending credential, no token.
    post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "gated@example.com"}),
    );
    let (_, oob) = get(&s, &format!("{EMU}/oobCodes"));
    let link_code = oob["oobCodes"][0]["oobCode"].as_str().unwrap().to_owned();
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "gated@example.com", "oobCode": link_code}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none());
    assert!(pending["mfaPendingCredential"].is_string());
    // A verified provider email matching the account: same gate.
    let google = json!({"sub": "g-gated", "email": "gated@example.com", "email_verified": true});
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("id_token={}&providerId=google.com", idp_jwt(&google)), "requestUri": "http://localhost"}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none());
    assert_eq!(pending["localId"], user["localId"]);
    // Phone sign-in on a number linked to the gated user: same gate.
    let (_, linked) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": user["localId"], "phoneNumber": "+15550001234"}),
    );
    assert!(linked["localId"].is_string());
    let (_, sent) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15550001234"}),
    );
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"], "code": code}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none());
    assert!(pending["mfaPendingCredential"].is_string());
}

#[test]
fn inspection_routes_need_the_control_token_from_browser_pages_and_codes_expire() {
    let mut s = state();
    sign_up(&s, "x@example.com");
    post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "x@example.com"}),
    );
    let page = RequestHeaders {
        origin: Some("http://localhost:5173".to_owned()),
        ..RequestHeaders::default()
    };
    // No token configured: pages are refused; command-line clients are not.
    assert_eq!(
        handle_with(&s, "GET", &format!("{EMU}/oobCodes"), &page, &json!({})).status,
        403
    );
    assert_eq!(get(&s, &format!("{EMU}/oobCodes")).0, 200);
    s.control_token = Some("secret-token".to_owned());
    assert_eq!(
        handle_with(&s, "GET", &format!("{EMU}/oobCodes"), &page, &json!({})).status,
        403
    );
    let with_token = RequestHeaders {
        origin: Some("http://localhost:5173".to_owned()),
        authorization: Some("Bearer secret-token".to_owned()),
        ..RequestHeaders::default()
    };
    let r = handle_with(
        &s,
        "GET",
        &format!("{EMU}/oobCodes"),
        &with_token,
        &json!({}),
    );
    assert_eq!(r.status, 200);
    let code = r.body["oobCodes"][0]["oobCode"]
        .as_str()
        .unwrap()
        .to_owned();
    // Codes expire on the virtual clock: an hour later the reset code is refused.
    s.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(
            3601,
        ))
        .unwrap();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code, "newPassword": "newpassword1"}),
    );
    assert_eq!(status, 400, "{body}");
    let (_, sent) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15550007777"}),
    );
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let sms = codes["verificationCodes"][0]["code"]
        .as_str()
        .unwrap()
        .to_owned();
    s.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(601))
        .unwrap();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"], "code": sms}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], "INVALID_SESSION_INFO");
}

#[test]
fn a_registered_project_has_its_own_users_behind_the_project_scoped_routes() {
    use fireemu_core_auth::store::AuthRegistry;
    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    assert!(registry.register(
        "demo-b",
        AuthStore::new("demo-b", SplitMix64::new(9), TotpPolicy::default())
    ));
    assert!(!registry.register(
        "demo-app",
        AuthStore::new("demo-app", SplitMix64::new(9), TotpPolicy::default())
    ));
    s.registry = Some(registry.clone());
    sign_up(&s, "default@example.com");
    // The other project's admin routes see an empty store and create there.
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-b/accounts"),
        &json!({"email": "b@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let (_, in_b) = admin(
        &s,
        &format!("{V1}/projects/demo-b/accounts:lookup"),
        &json!({"email": ["default@example.com", "b@example.com"]}),
    );
    assert_eq!(in_b["users"].as_array().unwrap().len(), 1);
    assert_eq!(in_b["users"][0]["email"], "b@example.com");
    let (_, in_default) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"email": ["default@example.com", "b@example.com"]}),
    );
    assert_eq!(in_default["users"].as_array().unwrap().len(), 1);
    assert_eq!(in_default["users"][0]["email"], "default@example.com");
    // Tokens issued for demo-b name it as their audience.
    let store_b = registry.store_for("demo-b").unwrap();
    let store_b = store_b.lock().unwrap();
    let uid = store_b
        .user_by_id(created["localId"].as_str().unwrap())
        .unwrap()
        .local_id
        .clone();
    let token = store_b
        .id_token_claims(&uid, None, LogicalInstant::from_unix_seconds(1_788_004_860))
        .unwrap();
    assert_eq!(token.aud, "demo-b");
    drop(store_b);
    // An unregistered project is refused as before.
    let (status, _) = admin(
        &s,
        &format!("{V1}/projects/demo-c/accounts:lookup"),
        &json!({"email": ["x@example.com"]}),
    );
    assert_eq!(status, 400);
    assert_eq!(
        registry.projects(),
        vec!["demo-app".to_owned(), "demo-b".to_owned()]
    );
    assert!(registry.remove("demo-b"));
    assert!(!registry.remove("demo-b"));
}

#[test]
fn compatibility_profile_routes_unregistered_admin_projects_without_leaking_state() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    s.registry = Some(registry.clone());
    s.allow_routed_projects = true;
    sign_up(&s, "default@example.com");

    let (status, _) = admin(
        &s,
        &format!("{V1}/projects/isolated-a/accounts"),
        &json!({"email": "invalid@example.com", "password": "short"}),
    );
    assert_eq!(status, 400);
    assert_eq!(
        registry.routed_count(),
        0,
        "a rejected write is not retained"
    );

    let (status, empty) = admin(
        &s,
        &format!("{V1}/projects/isolated-a/accounts:lookup"),
        &json!({"email": ["missing@example.com"]}),
    );
    assert_eq!(status, 200, "{empty}");
    assert!(
        empty
            .get("users")
            .is_none_or(|users| users.as_array().is_some_and(Vec::is_empty)),
        "{empty}"
    );
    assert_eq!(
        registry.routed_count(),
        0,
        "a read-only miss is not retained"
    );

    for (project, email) in [
        ("isolated-a", "a@example.com"),
        ("isolated-b", "b@example.com"),
    ] {
        let (status, created) = admin(
            &s,
            &format!("{V1}/projects/{project}/accounts"),
            &json!({"email": email, "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{created}");
    }
    assert_eq!(registry.routed_count(), 2);

    for (project, expected, absent) in [
        ("isolated-a", "a@example.com", "b@example.com"),
        ("isolated-b", "b@example.com", "a@example.com"),
    ] {
        let (status, found) = admin(
            &s,
            &format!("{V1}/projects/{project}/accounts:lookup"),
            &json!({"email": [expected, absent, "default@example.com"]}),
        );
        assert_eq!(status, 200, "{found}");
        let users = found["users"].as_array().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["email"], expected);
    }

    assert_eq!(
        registry.projects(),
        vec!["demo-app".to_owned()],
        "compatibility namespaces are not control-plane sessions"
    );
    assert!(!registry.register(
        "isolated-a",
        AuthStore::new("isolated-a", SplitMix64::new(11), TotpPolicy::default())
    ));
    registry.clear_routed();
    assert_eq!(registry.routed_count(), 0);
}

#[test]
fn compatibility_profile_rejects_noncanonical_projects_without_default_fallback() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    s.registry = Some(registry.clone());
    s.allow_routed_projects = true;
    sign_up(&s, "default@example.com");

    for project in [
        "Uppercase",
        "has_underscore",
        "has.dot",
        "-leading",
        "trailing-",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let (status, _) = admin(
            &s,
            &format!("{V1}/projects/{project}/accounts"),
            &json!({"email": "routed@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 400, "project {project}");
    }

    assert_eq!(registry.routed_count(), 0);
    let default = s.store.lock().unwrap();
    assert!(default.user_by_email("default@example.com").is_some());
    assert!(default.user_by_email("routed@example.com").is_none());
}

#[test]
fn tenant_admin_routes_use_an_isolated_namespace_and_issue_tenant_tokens() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer-a").unwrap();
    registry.ensure_tenant("demo-app", "customer-b").unwrap();
    s.registry = Some(registry.clone());
    let tenant = format!("{V1}/projects/demo-app/tenants/customer-a");
    let other_tenant = format!("{V1}/projects/demo-app/tenants/customer-b");

    let (status, created) = admin(
        &s,
        &format!("{tenant}/accounts"),
        &json!({"localId": "same-uid", "email": "tenant@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["tenantId"], "customer-a");
    let (status, other_created) = admin(
        &s,
        &format!("{other_tenant}/accounts"),
        &json!({"localId": "same-uid", "email": "other@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{other_created}");
    assert_eq!(other_created["tenantId"], "customer-b");
    let (status, default_created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({"localId": "same-uid", "email": "default@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{default_created}");
    assert!(default_created.get("tenantId").is_none());

    let (_, tenant_users) = admin(
        &s,
        &format!("{tenant}/accounts:lookup"),
        &json!({"localId": ["same-uid"]}),
    );
    assert_eq!(tenant_users["users"][0]["email"], "tenant@example.com");
    assert_eq!(tenant_users["users"][0]["tenantId"], "customer-a");
    let (_, tenant_users_by_email) = admin(
        &s,
        &format!("{tenant}/accounts:lookup"),
        &json!({"email": ["tenant@example.com"]}),
    );
    assert_eq!(tenant_users_by_email["users"][0]["tenantId"], "customer-a");
    let listed = handle_with(
        &s,
        "GET",
        &format!("{tenant}/accounts:batchGet?maxResults=1000"),
        &owner(),
        &json!({}),
    );
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_eq!(listed.body["users"][0]["tenantId"], "customer-a");
    let (_, other_users) = admin(
        &s,
        &format!("{other_tenant}/accounts:lookup"),
        &json!({"localId": ["same-uid"]}),
    );
    assert_eq!(other_users["users"][0]["email"], "other@example.com");
    assert_eq!(other_users["users"][0]["tenantId"], "customer-b");
    let (_, default_users) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": ["same-uid"]}),
    );
    assert_eq!(default_users["users"][0]["email"], "default@example.com");
    assert!(default_users["users"][0].get("tenantId").is_none());

    let (status, mismatch) = admin(
        &s,
        &format!("{tenant}/accounts"),
        &json!({"tenantId": "customer-b", "email": "mismatch@example.com"}),
    );
    assert_eq!(status, 400, "{mismatch}");
    assert_eq!(mismatch["error"]["message"], "TENANT_ID_MISMATCH");

    let tenant_store = registry.tenant_store("demo-app", "customer-a").unwrap();
    let tenant_store = tenant_store.lock().unwrap();
    let uid = tenant_store
        .user_by_id("same-uid")
        .unwrap()
        .local_id
        .clone();
    let token = tenant_store
        .id_token_claims(&uid, None, LogicalInstant::from_unix_seconds(1_788_004_860))
        .unwrap();
    assert_eq!(token.firebase.tenant.as_deref(), Some("customer-a"));
}

#[test]
fn client_tenant_id_selects_the_namespace_and_must_match_the_id_token() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer-a").unwrap();
    registry.ensure_tenant("demo-app", "customer-b").unwrap();
    s.registry = Some(registry);
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "customer-a", "email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let token = created["idToken"].as_str().unwrap();
    assert_eq!(claims(token)["firebase"]["tenant"], "customer-a");

    let (status, mismatch) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"tenantId": "customer-b", "idToken": token}),
    );
    assert_eq!(status, 400, "{mismatch}");
    assert_eq!(mismatch["error"]["message"], "TENANT_ID_MISMATCH");
}

#[test]
fn tenant_manager_crud_lists_and_removes_explicit_tenants() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    s.registry = Some(Arc::new(AuthRegistry::new("demo-app", s.store.clone())));
    let collection = format!("{V2}/projects/demo-app/tenants");
    let created = handle_with(
        &s,
        "POST",
        &collection,
        &owner(),
        &json!({"displayName": "Customer A", "allowPasswordSignup": true, "disableAuth": true}),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let name = created.body["name"].as_str().unwrap();
    let tenant_id = name.rsplit('/').next().unwrap();

    let listed = handle_with(&s, "GET", &collection, &owner(), &json!({}));
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_eq!(listed.body["tenants"][0]["name"], name);
    assert_eq!(listed.body["tenants"][0]["displayName"], "Customer A");

    let item = format!("{collection}/{tenant_id}");
    let updated = handle_with(
        &s,
        "PATCH",
        &format!("{item}?updateMask=displayName,enableAnonymousUser"),
        &owner(),
        &json!({"displayName": "Customer B", "enableAnonymousUser": true}),
    );
    assert_eq!(updated.status, 200, "{}", updated.body);
    assert_eq!(updated.body["displayName"], "Customer B");
    assert_eq!(updated.body["enableAnonymousUser"], true);
    assert_eq!(updated.body["allowPasswordSignup"], true);
    assert_eq!(updated.body["disableAuth"], true);

    let deleted = handle_with(&s, "DELETE", &item, &owner(), &json!({}));
    assert_eq!(deleted.status, 200, "{}", deleted.body);
    let listed = handle_with(&s, "GET", &collection, &owner(), &json!({}));
    assert_eq!(listed.body["tenants"].as_array().unwrap().len(), 0);
    let implicit = handle_with(&s, "GET", &item, &owner(), &json!({}));
    assert_eq!(implicit.status, 404, "{}", implicit.body);
    assert_eq!(implicit.body["error"]["message"], "TENANT_NOT_FOUND");
}

#[test]
fn untrusted_requests_cannot_create_or_use_an_unknown_tenant() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    s.registry = Some(registry.clone());

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "attacker", "email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert!(registry.tenant_store("demo-app", "attacker").is_none());

    let (status, refused) = admin(
        &s,
        &format!("{V1}/projects/demo-app/tenants/attacker/accounts"),
        &json!({"localId": "u1", "email": "a@example.com"}),
    );
    assert_eq!(status, 404, "{refused}");
    assert!(registry.tenant_store("demo-app", "attacker").is_none());
}

#[test]
fn tenant_authentication_flags_are_enforced() {
    use fireemu_core_auth::store::{AuthRegistry, TenantMetadata};

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "restricted").unwrap();
    assert!(registry.update_tenant("demo-app", "restricted", TenantMetadata::default(),));
    s.registry = Some(registry.clone());

    for body in [
        json!({"tenantId": "restricted", "email": "a@example.com", "password": "hunter22"}),
        json!({"tenantId": "restricted"}),
    ] {
        let (status, refused) = post(&s, &format!("{V1}/accounts:signUp"), &body);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "OPERATION_NOT_ALLOWED");
    }

    assert!(registry.update_tenant(
        "demo-app",
        "restricted",
        TenantMetadata {
            allow_password_signup: true,
            enable_email_link_signin: true,
            enable_anonymous_user: true,
            ..TenantMetadata::default()
        },
    ));
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "restricted", "email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let refresh_token = created["refreshToken"].as_str().unwrap().to_owned();
    assert!(registry.update_tenant(
        "demo-app",
        "restricted",
        TenantMetadata {
            allow_password_signup: true,
            enable_email_link_signin: true,
            enable_anonymous_user: true,
            disable_auth: true,
            ..TenantMetadata::default()
        },
    ));
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "restricted", "email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "PROJECT_DISABLED");

    let (status, refused) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh_token}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "PROJECT_DISABLED");
}

#[test]
fn admin_v2_config_toggles_email_enumeration_protection_and_propagates_to_tenants() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer-a").unwrap();
    s.registry = Some(registry.clone());
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=emailPrivacyConfig";
    let enabled = handle_with(
        &s,
        "PATCH",
        path,
        &owner(),
        &json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}}),
    );
    assert_eq!(enabled.status, 200, "{}", enabled.body);
    assert_eq!(
        enabled.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );
    assert!(
        registry
            .tenant_store("demo-app", "customer-a")
            .unwrap()
            .lock()
            .unwrap()
            .config()
            .enable_improved_email_privacy
    );

    let (status, hidden) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "missing@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400);
    assert_eq!(hidden["error"]["message"], "INVALID_LOGIN_CREDENTIALS");
    let (status, reset) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "missing@example.com"}),
    );
    assert_eq!(status, 200, "{reset}");

    let disabled = handle_with(
        &s,
        "PATCH",
        path,
        &owner(),
        &json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": false}}),
    );
    assert_eq!(disabled.status, 200, "{}", disabled.body);
    let (status, revealed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "missing@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400);
    assert_eq!(revealed["error"]["message"], "EMAIL_NOT_FOUND");
}

#[test]
fn email_enumeration_protection_requires_verified_email_changes_but_keeps_signup_linking() {
    let s = state();
    let enabled = handle_with(
        &s,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=emailPrivacyConfig",
        &owner(),
        &json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}}),
    );
    assert_eq!(enabled.status, 200, "{}", enabled.body);
    let signed = sign_up(&s, "before@example.com");
    let id_token = signed["idToken"].as_str().unwrap();
    let local_id = signed["localId"].as_str().unwrap();

    let (status, rejected) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": id_token, "email": "direct@example.com"}),
    );
    assert_eq!(status, 400, "{rejected}");
    assert_eq!(rejected["error"]["message"], "OPERATION_NOT_ALLOWED");
    assert_eq!(
        s.store
            .lock()
            .unwrap()
            .user_by_id(local_id)
            .and_then(|user| user.email.as_deref()),
        Some("before@example.com")
    );

    let anonymous = post(&s, &format!("{V1}/accounts:signUp"), &json!({})).1;
    let (status, linked) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "idToken": anonymous["idToken"],
            "email": "linked@example.com",
            "password": "hunter22"
        }),
    );
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["email"], "linked@example.com");

    let (status, admin_update) = admin(
        &s,
        "/identitytoolkit.googleapis.com/v1/projects/demo-app/accounts:update",
        &json!({"localId": local_id, "email": "admin@example.com"}),
    );
    assert_eq!(status, 200, "{admin_update}");
    assert_eq!(admin_update["email"], "admin@example.com");
}

// ---- SAML / OIDC federated sign-in and the identity-provider widget pages ---------------------

/// A `postBody`-only request URI (the Node SDK's `signInWithCredential` sends a dummy one).
const DUMMY_URI: &str = "http://localhost";

#[test]
fn a_saml_assertion_signs_in_and_carries_the_attribute_statements() {
    let s = state();
    // The SAML flow sends a fake id_token (for the sub) plus a JSON SAMLResponse; the email
    // comes from the assertion subject nameId and is always trusted (emailVerified is true),
    // and the attributeStatements become the rawUserInfo.
    let saml = json!({
        "assertion": {
            "subject": {"nameId": "person@saml.example.com"},
            "attributeStatements": {"department": ["eng"], "role": ["admin"]}
        }
    });
    let post_body = format!(
        "providerId=saml.myidp&id_token={}&SAMLResponse={}",
        percent(&json!({"sub": "saml-user-1"}).to_string()),
        percent(&saml.to_string())
    );
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": post_body, "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["providerId"], "saml.myidp");
    assert_eq!(signed["isNewUser"], true);
    assert_eq!(signed["email"], "person@saml.example.com");
    assert_eq!(signed["emailVerified"], true);
    assert_eq!(signed["rawId"], "saml-user-1");
    assert_eq!(signed["federatedId"], "saml-user-1");
    let raw: Value = serde_json::from_str(signed["rawUserInfo"].as_str().unwrap()).unwrap();
    assert_eq!(raw["department"], json!(["eng"]));
    let c = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(c["firebase"]["sign_in_provider"], "saml.myidp");
    assert_eq!(
        c["firebase"]["identities"]["saml.myidp"],
        json!(["saml-user-1"])
    );
}

#[test]
fn a_saml_response_missing_its_assertion_parts_is_refused_precisely() {
    let s = state();
    let id_token = percent(&json!({"sub": "u"}).to_string());
    let cases = [
        (
            json!({}),
            "INVALID_IDP_RESPONSE ((Missing assertion in SAMLResponse.))",
        ),
        (
            json!({"assertion": {}}),
            "INVALID_IDP_RESPONSE ((Missing assertion.subject in SAMLResponse.))",
        ),
        (
            json!({"assertion": {"subject": {}}}),
            "INVALID_IDP_RESPONSE ((Missing assertion.subject.nameId in SAMLResponse.))",
        ),
    ];
    for (saml, message) in cases {
        let post_body = format!(
            "providerId=saml.x&id_token={id_token}&SAMLResponse={}",
            percent(&saml.to_string())
        );
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:signInWithIdp"),
            &json!({"postBody": post_body, "requestUri": DUMMY_URI}),
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["message"], message);
    }
}

#[test]
fn an_oidc_assertion_keeps_the_claims_as_raw_user_info() {
    let s = state();
    let oidc =
        json!({"sub": "oidc-9", "email": "o@example.com", "email_verified": true, "name": "O"});
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=oidc.corp&id_token={}", percent(&oidc.to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["providerId"], "oidc.corp");
    // oidc.* keeps the whole claims blob as rawUserInfo (unlike google.com's shaped blob).
    let raw: Value = serde_json::from_str(signed["rawUserInfo"].as_str().unwrap()).unwrap();
    assert_eq!(raw["sub"], "oidc-9");
    assert_eq!(raw["email"], "o@example.com");
    // federatedId is the raw id for a non-google provider.
    assert_eq!(signed["federatedId"], "oidc-9");
}

#[test]
fn the_provider_id_is_lowercased_and_credentials_can_arrive_in_the_uri_fragment() {
    let s = state();
    // A popup handoff puts the credential in the request URI (query and/or fragment); the
    // provider id is matched case-insensitively.
    let id_token = percent(
        &json!({"sub": "frag-1", "email": "f@example.com", "email_verified": true}).to_string(),
    );
    let request_uri = format!("http://localhost/handler?providerId=OIDC.Corp#id_token={id_token}");
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"requestUri": request_uri}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["providerId"], "oidc.corp");
    assert_eq!(signed["rawId"], "frag-1");
}

#[test]
fn an_access_token_credential_is_not_implemented() {
    let s = state();
    // The emulator supports id_token, not access_token: google.com/apple.com and any other
    // provider each get a NotImplementedError (501).
    for provider in ["google.com", "apple.com", "oidc.corp"] {
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:signInWithIdp"),
            &json!({"postBody": format!("providerId={provider}&access_token=opaque-token"), "requestUri": DUMMY_URI}),
        );
        assert_eq!(status, 501, "{provider}: {body}");
        assert_eq!(body["error"]["status"], "NOT_IMPLEMENTED");
    }
    // A JSON access_token that parses as claims IS accepted (the emulator parses either token),
    // and the supplied token is echoed back as oauthAccessToken.
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=oidc.corp&access_token={}", percent(&json!({"sub": "at-1"}).to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["rawId"], "at-1");
    assert_eq!(signed["oauthAccessToken"], "{\"sub\":\"at-1\"}");
}

#[test]
fn create_auth_uri_with_a_provider_is_not_implemented() {
    let s = state();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"providerId": "google.com", "continueUri": "http://localhost", "identifier": "a@b.com"}),
    );
    assert_eq!(status, 501, "{body}");
    assert_eq!(
        body["error"]["message"],
        "Sign-in with IDP is not yet supported."
    );
    // Missing continueUri / malformed identifier are their own 400s.
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "a@b.com"}),
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"]["message"], "MISSING_CONTINUE_URI");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "no-at-sign", "continueUri": "http://localhost"}),
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"]["message"], "INVALID_IDENTIFIER");
}

#[test]
fn a_provider_id_with_control_characters_is_refused() {
    let s = state();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId={}&id_token={}", percent("saml.\u{0000}evil"), percent(&json!({"sub": "x"}).to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 400, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("INVALID_CREDENTIAL_OR_PROVIDER_ID"));
}

#[test]
fn the_idp_widget_handler_lists_accounts_and_escapes_them() {
    use fireemu_adapter_http::identity_toolkit::widget;
    let s = state();
    // Seed an account at a provider whose display name carries markup.
    let oidc = json!({"sub": "w-1", "email": "w@example.com", "name": "<script>alert(1)</script>", "email_verified": true});
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=oidc.corp&id_token={}", percent(&oidc.to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 200);
    let rendered = widget::render(
        &s,
        "/emulator/auth/handler",
        Some("apiKey=fake-api-key&providerId=oidc.corp"),
    );
    assert_eq!(rendered.status, 200);
    assert!(rendered.content_type.starts_with("text/html"));
    assert!(rendered.body.contains("Sign-in with"));
    assert!(rendered.body.contains("w@example.com"));
    // The injected display name is escaped: no raw <script> reaches the page.
    assert!(!rendered.body.contains("<script>alert(1)</script>"));
    assert!(rendered.body.contains("&lt;script&gt;"));
    // Missing apiKey / providerId is a 400 JSON envelope.
    let bad = widget::render(&s, "/emulator/auth/handler", Some("providerId=oidc.corp"));
    assert_eq!(bad.status, 400);
    assert!(bad.body.contains("missing apiKey or providerId"));
    // The iframe helper page is static HTML.
    let iframe = widget::render(&s, "/emulator/auth/iframe", None);
    assert_eq!(iframe.status, 200);
    assert!(iframe.body.contains("Auth Emulator Helper Iframe"));
}
