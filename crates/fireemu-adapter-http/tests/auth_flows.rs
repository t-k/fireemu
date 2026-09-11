//! Email actions (oob codes), email link and phone sign-in, fixture identity providers,
//! phone second factors and the emulator inspection routes.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthBlockingContext, AuthBlockingHook, AuthState, BlockingFunctionFailure,
    RequestHeaders,
};
use fireemu_core_auth::jwt::{base64url_encode, decode_unsigned};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, PendingSignInId};
use fireemu_core_auth::{base32, totp::totp_at};
use fireemu_core_functions::manifest::{BlockingAuthEvent, BlockingAuthTokenPolicy};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const EMU: &str = "/emulator/v1/projects/demo-app";

struct PassThroughBlockingHook;

impl AuthBlockingHook for PassThroughBlockingHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(json!({}))
    }
}

struct FilteringIdpBlockingHook {
    contexts: Arc<Mutex<Vec<(BlockingAuthEvent, AuthBlockingContext)>>>,
}

struct RawCredentialBlockingHook {
    contexts: Arc<Mutex<Vec<(BlockingAuthEvent, AuthBlockingContext)>>>,
    forward_inbound_credentials: bool,
    token_policy: Option<BlockingAuthTokenPolicy>,
}

struct FixedBeforeSignInHook {
    response: Value,
}

struct RejectBeforeSignInHook {
    timeout: bool,
}

impl AuthBlockingHook for FixedBeforeSignInHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(if event == BlockingAuthEvent::BeforeSignIn {
            self.response.clone()
        } else {
            json!({})
        })
    }
}

impl AuthBlockingHook for RejectBeforeSignInHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if event == BlockingAuthEvent::BeforeSignIn {
            Err(if self.timeout {
                BlockingFunctionFailure::timeout()
            } else {
                BlockingFunctionFailure::unhandled()
            })
        } else {
            Ok(json!({}))
        }
    }
}

impl AuthBlockingHook for FilteringIdpBlockingHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(json!({}))
    }

    fn invoke_for_with_context(
        &self,
        _project: &str,
        _tenant: Option<&str>,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
        context: &AuthBlockingContext,
    ) -> Result<Option<Value>, BlockingFunctionFailure> {
        self.contexts.lock().unwrap().push((event, context.clone()));
        let response = if event == BlockingAuthEvent::BeforeSignIn {
            let role = context
                .credential
                .as_ref()
                .and_then(|credential| credential.claims.as_ref())
                .and_then(|claims| claims.get("roles"))
                .and_then(Value::as_array)
                .and_then(|roles| roles.first())
                .cloned()
                .unwrap_or(Value::Null);
            json!({
                "userRecord": {
                    "updateMask": "sessionClaims",
                    "sessionClaims": {"selectedRole": role}
                }
            })
        } else {
            json!({})
        };
        Ok(Some(response))
    }
}

impl AuthBlockingHook for RawCredentialBlockingHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(json!({}))
    }

    fn forward_inbound_credentials(&self) -> bool {
        self.forward_inbound_credentials
    }

    fn inbound_credential_policy(&self, _event: BlockingAuthEvent) -> BlockingAuthTokenPolicy {
        if !self.forward_inbound_credentials {
            return BlockingAuthTokenPolicy::default();
        }
        self.token_policy.unwrap_or(BlockingAuthTokenPolicy::ALL)
    }

    fn invoke_for_with_context(
        &self,
        _project: &str,
        _tenant: Option<&str>,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
        context: &AuthBlockingContext,
    ) -> Result<Option<Value>, BlockingFunctionFailure> {
        self.contexts.lock().unwrap().push((event, context.clone()));
        Ok(Some(json!({})))
    }
}

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
    }
}

fn post(state: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let r = handle(state, "POST", path, body);
    (r.status, r.body)
}

fn finalize_mfa(state: &AuthState, body: &Value) -> (u16, Value) {
    post(state, &format!("{V2}/accounts/mfaSignIn:finalize"), body)
}

fn assert_mfa_finalize_refused(
    state: &mut AuthState,
    body: &Value,
    hook: Arc<dyn AuthBlockingHook>,
    expected_status: u16,
) {
    state.blocking = Some(hook);
    let (status, response) = finalize_mfa(state, body);
    assert_eq!(status, expected_status, "{response}");
    assert_eq!(state.store.lock().unwrap().pending_sign_in_count(), 1);
}

fn assert_phone_mfa_failures_roll_back(state: &mut AuthState, body: &Value) {
    for hook in [
        Arc::new(RejectBeforeSignInHook { timeout: false }) as Arc<dyn AuthBlockingHook>,
        Arc::new(RejectBeforeSignInHook { timeout: true }),
    ] {
        assert_mfa_finalize_refused(state, body, hook, 503);
    }
    for response in [
        json!({"userRecord": {"updateMask": "sessionClaims", "sessionClaims": {"firebase": "reserved"}}}),
        json!({"userRecord": {"updateMask": "sessionClaims", "sessionClaims": {"value": "x".repeat(1_001)}}}),
    ] {
        assert_mfa_finalize_refused(
            state,
            body,
            Arc::new(FixedBeforeSignInHook { response }),
            400,
        );
    }
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

fn custom_token(uid: &str) -> String {
    let header = base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = json!({
        "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
        "iss": "firebase-auth-emulator@example.com",
        "sub": "firebase-auth-emulator@example.com",
        "uid": uid,
        "iat": 1_788_004_860,
        "exp": 1_788_008_460,
    });
    let payload = base64url_encode(payload.to_string().as_bytes());
    format!("{header}.{payload}.")
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
    let signed_up = sign_up(&s, "a@example.com");
    let refresh_token = signed_up["refreshToken"].as_str().unwrap().to_owned();
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
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh_token}),
    );
    assert_eq!(status, 200, "{refreshed}");
}

#[test]
fn strict_profile_password_reset_revokes_the_existing_refresh_token() {
    let s = AuthState {
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::ProductionBounded,
        stateless_refresh_tokens: false,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Reject,
        ..state()
    };
    let signed_up = sign_up(&s, "strict-reset@example.com");
    let refresh_token = signed_up["refreshToken"].as_str().unwrap().to_owned();
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "strict-reset@example.com"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (_, codes) = get(&s, &format!("{EMU}/oobCodes"));
    let code = codes["oobCodes"][0]["oobCode"].as_str().unwrap();
    let (status, reset) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code, "newPassword": "newpassword1"}),
    );
    assert_eq!(status, 200, "{reset}");

    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh_token}),
    );
    assert_eq!(status, 400, "{refreshed}");
    assert_eq!(refreshed["error"]["message"], "INVALID_REFRESH_TOKEN");
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
        &format!("{V1}/projects/demo-app/accounts:sendOobCode"),
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
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "idToken": id_token, "newEmail": "new@example.com"}),
    );
    assert_eq!(status, 200, "{change}");
    assert!(change.get("oobCode").is_none());
    let (_, codes) = get(&s, &format!("{EMU}/oobCodes"));
    let code = codes["oobCodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["requestType"] == "VERIFY_AND_CHANGE_EMAIL")
        .unwrap()["oobCode"]
        .as_str()
        .unwrap()
        .to_owned();
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
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"phoneNumber": ["+15550000001"]}),
    );
    assert_eq!(status, 200);
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
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"federatedUserId": [{"providerId": "google.com", "rawId": "g-123"}]}),
    );
    assert_eq!(status, 200);
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
fn totp_enrollment_checks_first_factor_and_email_before_allocating_state() {
    let mut s = state();
    s.totp_extension_enabled = true;

    let assert_refused_without_pending = |state: &AuthState, token: &str, message: &str| {
        let (status, body) = post(
            state,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": token, "totpEnrollmentInfo": {}}),
        );
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"]["message"], message);
        let claims = claims(token);
        let uid = claims["user_id"]
            .as_str()
            .expect("the token names its user");
        assert_eq!(
            state
                .store
                .lock()
                .unwrap()
                .user_by_id(uid)
                .expect("the user remains present")
                .mfa
                .pending_count(),
            0,
            "TOTP refusal must not allocate a pending enrollment"
        );
    };

    let unverified = sign_up(&s, "totp-unverified@example.com");
    assert_refused_without_pending(
        &s,
        unverified["idToken"].as_str().unwrap(),
        "UNVERIFIED_EMAIL : Need to verify email first before enrolling second factors.",
    );

    let (_, anonymous) = post(&s, &format!("{V1}/accounts:signUp"), &json!({}));
    assert_refused_without_pending(
        &s,
        anonymous["idToken"].as_str().unwrap(),
        "UNSUPPORTED_FIRST_FACTOR : MFA is not available for the given first factor.",
    );

    let (_, sent) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15550007771"}),
    );
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let phone_code = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["sessionInfo"] == sent["sessionInfo"])
        .and_then(|entry| entry["code"].as_str())
        .unwrap()
        .to_owned();
    let (_, phone) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"], "code": phone_code}),
    );
    assert_refused_without_pending(
        &s,
        phone["idToken"].as_str().unwrap(),
        "UNSUPPORTED_FIRST_FACTOR : MFA is not available for the given first factor.",
    );

    let (_, custom) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": "{\"uid\":\"totp-custom\"}"}),
    );
    assert_refused_without_pending(
        &s,
        custom["idToken"].as_str().unwrap(),
        "UNSUPPORTED_FIRST_FACTOR : MFA is not available for the given first factor.",
    );

    let game = json!({
        "sub": "totp-game-center",
        "email": "totp-game-center@example.com",
        "email_verified": true
    });
    let (_, game) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=gc.apple.com&id_token={}", idp_jwt(&game)), "requestUri": DUMMY_URI}),
    );
    assert_refused_without_pending(
        &s,
        game["idToken"].as_str().unwrap(),
        "UNSUPPORTED_FIRST_FACTOR : MFA is not available for the given first factor.",
    );
}

#[test]
fn totp_finalize_rechecks_email_eligibility_before_consuming_state() {
    let mut s = state();
    s.totp_extension_enabled = true;
    let user = sign_up(&s, "totp-finalize-eligibility@example.com");
    let local_id = user["localId"].as_str().unwrap().to_owned();
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    verify_email(&s, &local_id);

    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": id_token, "totpEnrollmentInfo": {}}),
    );
    assert_eq!(status, 200, "{started}");
    let info = &started["totpSessionInfo"];
    let session_info = info["sessionInfo"].as_str().unwrap().to_owned();

    let uid = s
        .store
        .lock()
        .unwrap()
        .user_by_id(&local_id)
        .expect("the user remains present")
        .local_id
        .clone();
    s.store
        .lock()
        .unwrap()
        .user_mut(&uid)
        .expect("the user remains present")
        .email_verified = false;
    let (status, refused) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({
            "idToken": id_token,
            "totpVerificationInfo": {
                "sessionInfo": session_info,
                "verificationCode": "000000"
            }
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "UNVERIFIED_EMAIL : Need to verify email first before enrolling second factors."
    );
    assert_eq!(s.store.lock().unwrap().pending_mfa_user_count(), 1);
}

#[test]
#[allow(clippy::too_many_lines)]
fn phone_second_factor_enrollment_and_sign_in() {
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let mut s = state();
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
    s.blocking = Some(Arc::new(FilteringIdpBlockingHook {
        contexts: Arc::clone(&contexts),
    }));
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
    let recorded = contexts.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, BlockingAuthEvent::BeforeSignIn);
    assert_eq!(recorded[0].1.sign_in_method.as_deref(), Some("password"));
    drop(recorded);
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
fn allow_duplicate_emails_applies_to_password_accounts_and_active_lookup() {
    let s = state();
    let config_path = format!("{EMU}/config");
    let (status, enabled) = {
        let response = handle_with(
            &s,
            "PATCH",
            &config_path,
            &owner(),
            &json!({"signIn": {"allowDuplicateEmails": true}}),
        );
        (response.status, response.body)
    };
    assert_eq!(status, 200, "{enabled}");
    assert_eq!(enabled["signIn"]["allowDuplicateEmails"], true);

    let first = sign_up(&s, "duplicate@example.com");
    let second = sign_up(&s, "duplicate@example.com");
    assert_ne!(first["localId"], second["localId"]);

    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"email": ["duplicate@example.com"]}),
    );
    assert_eq!(status, 200);
    assert_eq!(lookup["users"][0]["localId"], second["localId"]);

    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "duplicate@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{signed_in}");
    assert_eq!(
        claims(signed_in["idToken"].as_str().unwrap())["sub"],
        second["localId"]
    );

    let (status, updated) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": first["localId"], "email": "duplicate@example.com"}),
    );
    assert_eq!(status, 200, "{updated}");

    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:delete"),
        &json!({"idToken": second["idToken"]}),
    );
    assert_eq!(status, 200);
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "duplicate@example.com", "password": "hunter22"}),
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
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"email": ["victim@example.com"]}),
    );
    assert_eq!(status, 200);
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
fn compatibility_profile_routes_custom_token_exchanges_to_the_unique_existing_project() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    s.registry = Some(registry);
    s.allow_routed_projects = true;

    for (project, uid, email) in [
        ("worker-alpha", "user-alpha", "alpha@example.com"),
        ("worker-beta", "user-beta", "beta@example.com"),
    ] {
        let (status, created) = admin(
            &s,
            &format!("{V1}/projects/{project}/accounts"),
            &json!({"localId": uid, "email": email}),
        );
        assert_eq!(status, 200, "{created}");

        let (status, exchanged) = post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": custom_token(uid), "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{exchanged}");
        assert_eq!(
            claims(exchanged["idToken"].as_str().unwrap())["aud"],
            project
        );
    }
}

#[test]
fn compatibility_profile_rejects_ambiguous_custom_token_projects() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    s.registry = Some(registry);
    s.allow_routed_projects = true;

    for project in ["worker-alpha", "worker-beta"] {
        let (status, created) = admin(
            &s,
            &format!("{V1}/projects/{project}/accounts"),
            &json!({"localId": "shared-user", "email": format!("{project}@example.com")}),
        );
        assert_eq!(status, 200, "{created}");
    }

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": custom_token("shared-user")}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], "INVALID_CUSTOM_TOKEN");
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
    let tenant = registry
        .create_tenant("demo-app", TenantMetadata::default())
        .unwrap();
    s.registry = Some(registry.clone());

    for body in [
        json!({"tenantId": tenant, "email": "a@example.com", "password": "hunter22"}),
        json!({"tenantId": tenant}),
    ] {
        let (status, refused) = post(&s, &format!("{V1}/accounts:signUp"), &body);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "OPERATION_NOT_ALLOWED");
    }

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({
            "tenantId": tenant,
            "email": "link@example.com",
            "oobCode": "missing-code"
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "OPERATION_NOT_ALLOWED");

    assert!(registry.update_tenant(
        "demo-app",
        &tenant,
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
        &json!({"tenantId": tenant, "email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let refresh_token = created["refreshToken"].as_str().unwrap().to_owned();
    assert!(registry.update_tenant(
        "demo-app",
        &tenant,
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
        &json!({"tenantId": tenant, "email": "a@example.com", "password": "hunter22"}),
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
fn implicit_tenant_defaults_admit_password_anonymous_and_email_link_flows() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    s.registry = Some(registry);

    let (status, password) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "tenantId": "customer",
            "email": "password@example.com",
            "password": "hunter22"
        }),
    );
    assert_eq!(status, 200, "{password}");

    let (status, anonymous) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "customer"}),
    );
    assert_eq!(status, 200, "{anonymous}");

    let (status, email_link) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({
            "tenantId": "customer",
            "email": "link@example.com",
            "oobCode": "missing-code"
        }),
    );
    assert_eq!(status, 400, "{email_link}");
    assert_eq!(email_link["error"]["message"], "INVALID_OOB_CODE");
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
            "attributeStatements": {
                "active": true,
                "department": ["eng"],
                "level": 3,
                "nested": {"region": "west"},
                "role": ["admin"]
            }
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
    assert_eq!(
        c["firebase"]["sign_in_attributes"],
        saml["assertion"]["attributeStatements"]
    );
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({
            "grant_type": "refresh_token",
            "refresh_token": signed["refreshToken"]
        }),
    );
    assert_eq!(status, 200, "{refreshed}");
    let refreshed_claims = claims(refreshed["id_token"].as_str().unwrap());
    assert!(
        refreshed_claims["firebase"]
            .get("sign_in_attributes")
            .is_none(),
        "the official refresh session does not retain one-time IdP attributes: {refreshed_claims}"
    );
}

#[test]
fn a_saml_assertion_without_attribute_statements_omits_sign_in_attributes() {
    let s = state();
    let saml = json!({
        "assertion": {"subject": {"nameId": "without-attributes@saml.example.com"}}
    });
    let post_body = format!(
        "providerId=saml.myidp&id_token={}&SAMLResponse={}",
        percent(&json!({"sub": "saml-user-without-attributes"}).to_string()),
        percent(&saml.to_string())
    );

    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": post_body, "requestUri": DUMMY_URI}),
    );

    assert_eq!(status, 200, "{signed}");
    let token = claims(signed["idToken"].as_str().unwrap());
    assert!(token["firebase"].get("sign_in_attributes").is_none());
}

#[test]
fn blocking_auth_reissue_preserves_saml_sign_in_attributes() {
    let mut s = state();
    s.blocking = Some(Arc::new(PassThroughBlockingHook));
    let saml = json!({
        "assertion": {
            "subject": {"nameId": "blocking@saml.example.com"},
            "attributeStatements": {"access": ["billing"]}
        }
    });
    let post_body = format!(
        "providerId=saml.myidp&id_token={}&SAMLResponse={}",
        percent(&json!({"sub": "saml-blocking-user"}).to_string()),
        percent(&saml.to_string())
    );

    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": post_body, "requestUri": DUMMY_URI}),
    );

    assert_eq!(status, 200, "{signed}");
    let token = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(
        token["firebase"]["sign_in_attributes"],
        saml["assertion"]["attributeStatements"]
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
    let token = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(token["firebase"]["sign_in_attributes"], oidc);
}

#[test]
fn blocking_auth_receives_idp_context_and_can_select_session_claims() {
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let mut s = state();
    s.blocking = Some(Arc::new(FilteringIdpBlockingHook {
        contexts: Arc::clone(&contexts),
    }));
    let oidc = json!({
        "sub": "oidc-blocking",
        "email": "blocking-oidc@example.com",
        "email_verified": true,
        "roles": ["billing", "discarded"],
        "privateGroup": "must-not-become-a-session-claim"
    });

    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=oidc.corp&id_token={}", percent(&oidc.to_string())), "requestUri": DUMMY_URI}),
    );

    assert_eq!(status, 200, "{signed}");
    let token = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(token["firebase"]["sign_in_attributes"], oidc);
    assert_eq!(token["selectedRole"], "billing");
    assert!(token.get("privateGroup").is_none());

    let recorded = contexts.lock().unwrap();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].0, BlockingAuthEvent::BeforeCreate);
    assert_eq!(recorded[1].0, BlockingAuthEvent::BeforeSignIn);
    for (index, (_, context)) in recorded.iter().enumerate() {
        let credential = context.credential.as_ref().unwrap();
        assert_eq!(credential.provider_id, "oidc.corp");
        assert_eq!(credential.sign_in_method, "oidc.corp");
        assert_eq!(credential.claims.as_ref(), Some(&oidc));
        let info = context.additional_user_info.as_ref().unwrap();
        assert_eq!(info.provider_id, "oidc.corp");
        assert_eq!(info.profile.as_ref(), Some(&oidc));
        assert_eq!(info.is_new_user, index == 0);
    }
}

#[test]
fn blocking_auth_forwards_raw_idp_credentials_only_when_opted_in() {
    let oidc = json!({
        "sub": "oidc-raw-credentials",
        "email": "raw-credentials@example.com",
        "email_verified": true
    });
    let id_token = oidc.to_string();
    let post_body = format!(
        "providerId=oidc.corp&id_token={}&access_token=access-sentinel&refresh_token=refresh-sentinel",
        percent(&id_token)
    );

    for forward_inbound_credentials in [false, true] {
        let contexts = Arc::new(Mutex::new(Vec::new()));
        let mut s = state();
        s.blocking = Some(Arc::new(RawCredentialBlockingHook {
            contexts: Arc::clone(&contexts),
            forward_inbound_credentials,
            token_policy: None,
        }));
        let (status, response) = post(
            &s,
            &format!("{V1}/accounts:signInWithIdp"),
            &json!({"postBody": post_body, "requestUri": DUMMY_URI}),
        );
        assert_eq!(status, 200, "{response}");

        let recorded = contexts.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        for (_, context) in recorded.iter() {
            let credential = context.credential.as_ref().unwrap();
            assert_eq!(credential.provider_id, "oidc.corp");
            assert_eq!(
                credential.id_token.as_deref(),
                forward_inbound_credentials.then_some(id_token.as_str())
            );
            assert_eq!(
                credential.access_token.as_deref(),
                forward_inbound_credentials.then_some("access-sentinel")
            );
            assert_eq!(
                credential.refresh_token.as_deref(),
                forward_inbound_credentials.then_some("refresh-sentinel")
            );
            let debug = format!("{context:?}");
            assert!(!debug.contains("access-sentinel"));
            assert!(!debug.contains("refresh-sentinel"));
        }
    }
}

#[test]
fn blocking_auth_retains_and_forwards_only_each_targets_requested_tokens() {
    let id_token = json!({
        "sub": "oidc-token-policy",
        "email": "token-policy@example.com",
        "email_verified": true
    })
    .to_string();
    for bits in 0_u8..8 {
        let contexts = Arc::new(Mutex::new(Vec::new()));
        let mut s = state();
        s.blocking = Some(Arc::new(RawCredentialBlockingHook {
            contexts: Arc::clone(&contexts),
            forward_inbound_credentials: true,
            token_policy: Some(BlockingAuthTokenPolicy {
                access_token: bits & 1 != 0,
                id_token: bits & 2 != 0,
                refresh_token: bits & 4 != 0,
            }),
        }));
        let (status, response) = post(
            &s,
            &format!("{V1}/accounts:signInWithIdp"),
            &json!({
                "postBody": format!(
                    "providerId=oidc.corp&id_token={}&access_token=access-sentinel&refresh_token=refresh-sentinel",
                    percent(&id_token)
                ),
                "requestUri": DUMMY_URI
            }),
        );
        assert_eq!(status, 200, "policy {bits}: {response}");

        let recorded = contexts.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        for (_, context) in recorded.iter() {
            let credential = context.credential.as_ref().unwrap();
            assert_eq!(credential.access_token.is_some(), bits & 1 != 0);
            assert_eq!(credential.id_token.is_some(), bits & 2 != 0);
            assert_eq!(credential.refresh_token.is_some(), bits & 4 != 0);
        }
    }
}

#[test]
fn blocking_auth_receives_every_non_idp_sign_in_method() {
    fn recorded_method(
        state: &mut AuthState,
        contexts: &Arc<Mutex<Vec<(BlockingAuthEvent, AuthBlockingContext)>>>,
        path: &str,
        body: &Value,
    ) -> String {
        state.blocking = Some(Arc::new(FilteringIdpBlockingHook {
            contexts: Arc::clone(contexts),
        }));
        let (status, response) = post(state, path, body);
        assert_eq!(status, 200, "{response}");
        let recorded = contexts.lock().unwrap();
        let context = recorded
            .iter()
            .rev()
            .find(|(event, _)| *event == BlockingAuthEvent::BeforeSignIn)
            .map(|(_, context)| context)
            .unwrap();
        assert!(context.credential.is_none());
        assert!(context.additional_user_info.is_none());
        context.sign_in_method.clone().unwrap()
    }

    let contexts = Arc::new(Mutex::new(Vec::new()));

    let mut password = state();
    sign_up(&password, "blocking-password@example.com");
    assert_eq!(
        recorded_method(
            &mut password,
            &contexts,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "blocking-password@example.com", "password": "hunter22"}),
        ),
        "password"
    );

    contexts.lock().unwrap().clear();
    let mut custom = state();
    assert_eq!(
        recorded_method(
            &mut custom,
            &contexts,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": custom_token("blocking-custom")}),
        ),
        "custom"
    );

    contexts.lock().unwrap().clear();
    let mut email_link = state();
    let (status, sent) = post(
        &email_link,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "blocking-link@example.com"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (_, codes) = get(&email_link, &format!("{EMU}/oobCodes"));
    assert_eq!(
        recorded_method(
            &mut email_link,
            &contexts,
            &format!("{V1}/accounts:signInWithEmailLink"),
            &json!({"email": "blocking-link@example.com", "oobCode": codes["oobCodes"][0]["oobCode"]}),
        ),
        "emailLink"
    );

    contexts.lock().unwrap().clear();
    let mut phone = state();
    let (status, sent) = post(
        &phone,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15550001234", "recaptchaToken": "ignored"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (_, codes) = get(&phone, &format!("{EMU}/verificationCodes"));
    assert_eq!(
        recorded_method(
            &mut phone,
            &contexts,
            &format!("{V1}/accounts:signInWithPhoneNumber"),
            &json!({"sessionInfo": sent["sessionInfo"], "code": codes["verificationCodes"][0]["code"]}),
        ),
        "phone"
    );

    contexts.lock().unwrap().clear();
    let mut anonymous = state();
    assert_eq!(
        recorded_method(
            &mut anonymous,
            &contexts,
            &format!("{V1}/accounts:signUp"),
            &json!({}),
        ),
        "anonymous"
    );
}

#[test]
fn blocking_auth_receives_saml_attribute_context() {
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let mut s = state();
    s.blocking = Some(Arc::new(FilteringIdpBlockingHook {
        contexts: Arc::clone(&contexts),
    }));
    let attributes = json!({"roles": ["auditor"], "costCenter": 42});
    let saml = json!({
        "assertion": {
            "subject": {"nameId": "blocking-context@saml.example.com"},
            "attributeStatements": attributes
        }
    });
    let post_body = format!(
        "providerId=saml.corp&id_token={}&SAMLResponse={}",
        percent(&json!({"sub": "saml-blocking-context"}).to_string()),
        percent(&saml.to_string())
    );

    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": post_body, "requestUri": DUMMY_URI}),
    );

    assert_eq!(status, 200, "{signed}");
    let token = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(token["firebase"]["sign_in_attributes"], attributes);
    assert_eq!(token["selectedRole"], "auditor");
    let recorded = contexts.lock().unwrap();
    assert_eq!(recorded.len(), 2);
    for (_, context) in recorded.iter() {
        let credential = context.credential.as_ref().unwrap();
        assert_eq!(credential.provider_id, "saml.corp");
        assert_eq!(credential.claims.as_ref(), Some(&attributes));
    }
}

#[test]
fn federated_mfa_finalize_preserves_attributes_and_invokes_blocking_auth_once() {
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let mut s = state();
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({
            "email": "federated-mfa@example.com",
            "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+15550007777", "displayName": "security key"}]
        }),
    );
    assert_eq!(status, 200, "{created}");
    let (_, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [created["localId"]]}),
    );
    let enrollment_id = lookup["users"][0]["mfaInfo"][0]["mfaEnrollmentId"]
        .as_str()
        .unwrap()
        .to_owned();
    s.blocking = Some(Arc::new(RejectBeforeSignInHook { timeout: false }));
    let oidc = json!({
        "sub": "oidc-mfa",
        "email": "federated-mfa@example.com",
        "email_verified": true,
        "roles": ["operator", "discarded"]
    });

    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=oidc.corp&id_token={}", percent(&oidc.to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none());
    assert!(contexts.lock().unwrap().is_empty());
    let credential = pending["mfaPendingCredential"].as_str().unwrap().to_owned();
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": credential, "mfaEnrollmentId": enrollment_id, "phoneSignInInfo": {"recaptchaToken": "x"}}),
    );
    assert_eq!(status, 200, "{started}");
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["code"]
        .as_str()
        .unwrap();
    let finalize = json!({"mfaPendingCredential": credential, "phoneVerificationInfo": {"sessionInfo": started["phoneResponseInfo"]["sessionInfo"], "code": code}});
    assert_phone_mfa_failures_roll_back(&mut s, &finalize);

    s.blocking = Some(Arc::new(FilteringIdpBlockingHook {
        contexts: Arc::clone(&contexts),
    }));
    let (status, signed) = finalize_mfa(&s, &finalize);

    assert_eq!(status, 200, "{signed}");
    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
    assert_eq!(
        signed
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["idToken", "refreshToken"]
    );
    let token = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(token["firebase"]["sign_in_provider"], "oidc.corp");
    assert_eq!(token["firebase"]["sign_in_attributes"], oidc);
    assert_eq!(token["selectedRole"], "operator");
    let recorded = contexts.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, BlockingAuthEvent::BeforeSignIn);
    let context = &recorded[0].1;
    let debug = format!("{context:?}");
    assert!(!debug.contains("operator"));
    assert!(debug.contains("[redacted]"));
    assert_eq!(context.sign_in_method.as_deref(), Some("oidc.corp"));
    assert_eq!(
        context
            .credential
            .as_ref()
            .and_then(|credential| credential.claims.as_ref()),
        Some(&oidc)
    );
}

#[test]
fn blocking_auth_forwards_idp_credentials_only_after_mfa_continuation() {
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let mut s = state();
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({
            "email": "raw-mfa@example.com",
            "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+15550008888"}]
        }),
    );
    assert_eq!(status, 200, "{created}");
    let (_, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [created["localId"]]}),
    );
    let enrollment_id = lookup["users"][0]["mfaInfo"][0]["mfaEnrollmentId"]
        .as_str()
        .unwrap()
        .to_owned();
    s.blocking = Some(Arc::new(RawCredentialBlockingHook {
        contexts: Arc::clone(&contexts),
        forward_inbound_credentials: true,
        token_policy: None,
    }));
    let oidc = json!({
        "sub": "oidc-raw-mfa",
        "email": "raw-mfa@example.com",
        "email_verified": true
    });
    let id_token = oidc.to_string();
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({
            "postBody": format!(
                "providerId=oidc.corp&id_token={}&access_token=access-mfa-sentinel&refresh_token=refresh-mfa-sentinel",
                percent(&id_token)
            ),
            "requestUri": DUMMY_URI
        }),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none());
    assert!(contexts.lock().unwrap().is_empty());

    let credential = pending["mfaPendingCredential"].as_str().unwrap().to_owned();
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({
            "mfaPendingCredential": credential,
            "mfaEnrollmentId": enrollment_id,
            "phoneSignInInfo": {"recaptchaToken": "x"}
        }),
    );
    assert_eq!(status, 200, "{started}");
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["code"]
        .as_str()
        .unwrap();
    s.blocking = Some(Arc::new(RawCredentialBlockingHook {
        contexts: Arc::clone(&contexts),
        forward_inbound_credentials: false,
        token_policy: Some(BlockingAuthTokenPolicy::ALL),
    }));
    let (status, signed) = finalize_mfa(
        &s,
        &json!({
            "mfaPendingCredential": credential,
            "phoneVerificationInfo": {
                "sessionInfo": started["phoneResponseInfo"]["sessionInfo"],
                "code": code
            }
        }),
    );
    assert_eq!(status, 200, "{signed}");
    let recorded = contexts.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    let context = &recorded[0].1;
    let credential = context.credential.as_ref().unwrap();
    assert_eq!(credential.id_token, None);
    assert_eq!(credential.access_token, None);
    assert_eq!(credential.refresh_token, None);
    let debug = format!("{context:?}");
    assert!(!debug.contains("access-mfa-sentinel"));
    assert!(!debug.contains("refresh-mfa-sentinel"));
}

fn assert_rejected_mfa_hook_drops_raw_credentials(
    hook: Arc<dyn AuthBlockingHook>,
    expected_status: u16,
) {
    let mut s = state();
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({
            "email": "rejected-raw-mfa@example.com",
            "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+15550007777"}]
        }),
    );
    assert_eq!(status, 200, "{created}");
    let (_, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [created["localId"]]}),
    );
    let enrollment_id = lookup["users"][0]["mfaInfo"][0]["mfaEnrollmentId"]
        .as_str()
        .unwrap();
    s.blocking = Some(Arc::new(RawCredentialBlockingHook {
        contexts: Arc::new(Mutex::new(Vec::new())),
        forward_inbound_credentials: true,
        token_policy: None,
    }));
    let id_token = json!({
        "sub": "oidc-rejected-raw-mfa",
        "email": "rejected-raw-mfa@example.com",
        "email_verified": true
    })
    .to_string();
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({
            "postBody": format!(
                "providerId=oidc.corp&id_token={}&access_token=reject-access-sentinel&refresh_token=reject-refresh-sentinel",
                percent(&id_token)
            ),
            "requestUri": DUMMY_URI
        }),
    );
    assert_eq!(status, 200, "{pending}");
    let credential = pending["mfaPendingCredential"].as_str().unwrap();
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({
            "mfaPendingCredential": credential,
            "mfaEnrollmentId": enrollment_id,
            "phoneSignInInfo": {"recaptchaToken": "x"}
        }),
    );
    assert_eq!(status, 200, "{started}");
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["code"]
        .as_str()
        .unwrap();
    s.blocking = Some(hook);
    let (status, refused) = finalize_mfa(
        &s,
        &json!({
            "mfaPendingCredential": credential,
            "phoneVerificationInfo": {
                "sessionInfo": started["phoneResponseInfo"]["sessionInfo"],
                "code": code
            }
        }),
    );
    assert_eq!(status, expected_status, "{refused}");

    let pending_id = PendingSignInId::parse(credential).unwrap();
    let store = s.store.lock().unwrap();
    let context = store.pending_sign_in_context(&pending_id).unwrap();
    assert_eq!(context.inbound_credentials(), None);
    assert_eq!(context.sign_in_provider(), Some("oidc.corp"));
    assert_eq!(store.pending_sign_in_count(), 1);
}

#[test]
fn rejected_mfa_hooks_drop_raw_credentials_but_keep_retry_provenance() {
    for (hook, expected_status) in [
        (
            Arc::new(RejectBeforeSignInHook { timeout: false }) as Arc<dyn AuthBlockingHook>,
            503,
        ),
        (Arc::new(RejectBeforeSignInHook { timeout: true }), 503),
        (
            Arc::new(FixedBeforeSignInHook {
                response: json!({
                    "userRecord": {
                        "updateMask": "sessionClaims",
                        "sessionClaims": {"firebase": "reserved"}
                    }
                }),
            }),
            400,
        ),
    ] {
        assert_rejected_mfa_hook_drops_raw_credentials(hook, expected_status);
    }
}

#[test]
fn federated_totp_finalize_preserves_attributes_and_blocking_context() {
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let mut s = state();
    s.totp_extension_enabled = true;
    let user = sign_up(&s, "federated-totp@example.com");
    verify_email(&s, user["localId"].as_str().unwrap());
    let (status, enrollment) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": user["idToken"], "totpEnrollmentInfo": {}}),
    );
    assert_eq!(status, 200, "{enrollment}");
    let secret = base32::decode(
        enrollment["totpSessionInfo"]["sharedSecretKey"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let first = LogicalInstant::from_unix_seconds(1_788_004_860);
    let code = totp_at(&secret, &TotpPolicy::default().params(), first);
    let (status, enrolled) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({
            "idToken": user["idToken"],
            "totpVerificationInfo": {
                "sessionInfo": enrollment["totpSessionInfo"]["sessionInfo"],
                "verificationCode": code
            }
        }),
    );
    assert_eq!(status, 200, "{enrolled}");
    let enrollment_id = claims(enrolled["idToken"].as_str().unwrap())["firebase"]
        ["second_factor_identifier"]
        .as_str()
        .unwrap()
        .to_owned();
    s.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(30))
        .unwrap();
    s.blocking = Some(Arc::new(FilteringIdpBlockingHook {
        contexts: Arc::clone(&contexts),
    }));
    let oidc = json!({
        "sub": "oidc-totp",
        "email": "federated-totp@example.com",
        "email_verified": true,
        "roles": ["auditor"]
    });
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=oidc.corp&id_token={}", percent(&oidc.to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(contexts.lock().unwrap().is_empty());
    let second = first
        .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(30))
        .unwrap();
    let code = totp_at(&secret, &TotpPolicy::default().params(), second);
    let finalize = json!({
        "mfaPendingCredential": pending["mfaPendingCredential"],
        "mfaEnrollmentId": enrollment_id,
        "totpVerificationInfo": {"verificationCode": code}
    });
    assert_mfa_finalize_refused(
        &mut s,
        &finalize,
        Arc::new(RejectBeforeSignInHook { timeout: false }),
        503,
    );
    s.blocking = Some(Arc::new(FilteringIdpBlockingHook {
        contexts: Arc::clone(&contexts),
    }));
    let (status, signed) = finalize_mfa(&s, &finalize);

    assert_eq!(status, 200, "{signed}");
    let token = claims(signed["idToken"].as_str().unwrap());
    assert_eq!(token["firebase"]["sign_in_provider"], "oidc.corp");
    assert_eq!(token["firebase"]["sign_in_attributes"], oidc);
    assert_eq!(token["selectedRole"], "auditor");
    let recorded = contexts.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, BlockingAuthEvent::BeforeSignIn);
    assert_eq!(
        recorded[0]
            .1
            .credential
            .as_ref()
            .and_then(|credential| credential.claims.as_ref()),
        Some(&oidc)
    );
}

#[test]
fn blocking_auth_enforces_the_functions_sdk_claim_payload_boundaries() {
    fn sign_in(response: Value) -> (u16, Value) {
        let mut s = state();
        sign_up(&s, "claim-limit@example.com");
        s.blocking = Some(Arc::new(FixedBeforeSignInHook { response }));
        post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "claim-limit@example.com", "password": "hunter22"}),
        )
    }

    let exactly_one_thousand = json!({"value": "a".repeat(988)});
    assert_eq!(
        exactly_one_thousand.to_string().encode_utf16().count(),
        1000
    );
    let (status, allowed) = sign_in(json!({
        "userRecord": {"updateMask": "sessionClaims", "sessionClaims": exactly_one_thousand}
    }));
    assert_eq!(status, 200, "{allowed}");

    let over_in_utf16 = json!({"value": "😀".repeat(495)});
    assert!(over_in_utf16.to_string().chars().count() <= 1000);
    assert!(over_in_utf16.to_string().encode_utf16().count() > 1000);
    let (status, refused) = sign_in(json!({
        "userRecord": {"updateMask": "sessionClaims", "sessionClaims": over_in_utf16}
    }));
    assert_eq!(status, 400, "{refused}");

    let (status, refused) = sign_in(json!({
        "userRecord": {
            "updateMask": "customClaims,sessionClaims",
            "customClaims": {"custom": "a".repeat(600)},
            "sessionClaims": {"session": "b".repeat(600)}
        }
    }));
    assert_eq!(status, 400, "{refused}");

    // The Functions SDK permits names such as `sub` that the Admin SDK refuses. The
    // Identity token encoder still gives the protocol-owned subject precedence.
    let (status, allowed) = sign_in(json!({
        "userRecord": {"updateMask": "sessionClaims", "sessionClaims": {"sub": "not-the-token-subject"}}
    }));
    assert_eq!(status, 200, "{allowed}");
    let token = claims(allowed["idToken"].as_str().unwrap());
    assert_ne!(token["sub"], "not-the-token-subject");

    let (status, refused) = sign_in(json!({
        "userRecord": {"updateMask": "sessionClaims", "sessionClaims": {"firebase": "reserved"}}
    }));
    assert_eq!(status, 400, "{refused}");

    // JSON.stringify uses the two-character escapes `\\b` and `\\f`; the canonical token
    // encoder deliberately uses six-character Unicode escapes and must not define this limit.
    for escaped in ['\u{0008}', '\u{000c}'] {
        let exactly_one_thousand = json!({"v": escaped.to_string().repeat(496)});
        let (status, allowed) = sign_in(json!({
            "userRecord": {"updateMask": "sessionClaims", "sessionClaims": exactly_one_thousand}
        }));
        assert_eq!(status, 200, "{allowed}");
    }

    // JavaScript expands 1e20 to decimal notation. The padding makes the SDK representation
    // exactly 1,001 UTF-16 code units, while a Rust exponent spelling would appear shorter.
    let exponent_boundary = json!({"n": 1e20, "v": "a".repeat(967)});
    let (status, refused) = sign_in(json!({
        "userRecord": {"updateMask": "sessionClaims", "sessionClaims": exponent_boundary}
    }));
    assert_eq!(status, 400, "{refused}");
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

// ------------------------------------------------------------------------------------------
// The console lines the official emulator prints instead of sending mail or SMS. The shell
// receives one notice per issued code, after the request, through `AuthState::notices`.
// ------------------------------------------------------------------------------------------

fn recording_state() -> (AuthState, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let mut s = state();
    s.notices = Some(Arc::new(move |notice| {
        sink.lock().unwrap().push(notice.message());
    }));
    (s, lines)
}

fn drain(lines: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    std::mem::take(&mut *lines.lock().unwrap())
}

fn oob_authorization_state(strict: bool) -> (AuthState, Arc<Mutex<Vec<String>>>) {
    let (mut s, lines) = recording_state();
    if strict {
        s.stateless_refresh_tokens = false;
        s.query_limits = fireemu_adapter_http::identity_toolkit::AuthQueryLimits::ProductionBounded;
        s.fake_custom_token_expiry =
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Reject;
    }
    (s, lines)
}

fn two_party_accounts(s: &AuthState, a: &Value, b: &Value) -> Value {
    let (status, response) = admin(
        s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [a["localId"], b["localId"]]}),
    );
    assert_eq!(status, 200);
    assert_eq!(response["users"].as_array().unwrap().len(), 2);
    response
}

#[test]
fn pending_retry_preserves_sms_after_a_mismatched_pending_credential() {
    for strict in [false, true] {
        let (s, lines) = oob_authorization_state(strict);
        let user = sign_up(&s, "pending-retry@example.com");
        let (status, seeded) = admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:update"),
            &json!({"localId": user["localId"], "emailVerified": true,
                "mfa": {"enrollments": [{"phoneInfo": "+15559876543"}]}}),
        );
        assert_eq!(status, 200, "{seeded}");
        let login = || {
            let (status, response) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": "pending-retry@example.com", "password": "hunter22"}),
            );
            assert_eq!(status, 200, "{response}");
            assert!(response.get("idToken").is_none());
            response
        };
        let a = login();
        let b = login();
        assert_ne!(a["mfaPendingCredential"], b["mfaPendingCredential"]);
        let (status, started) = post(
            &s,
            &format!("{V2}/accounts/mfaSignIn:start"),
            &json!({"mfaPendingCredential": a["mfaPendingCredential"],
                "mfaEnrollmentId": a["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {}}),
        );
        assert_eq!(status, 200, "{started}");
        let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
        let phone = json!({"sessionInfo": started["phoneResponseInfo"]["sessionInfo"], "code": codes["verificationCodes"][0]["code"]});
        let notices = lines.lock().unwrap().clone();
        let count = s.store.lock().unwrap().pending_sign_in_count();
        let (status, refused) = finalize_mfa(
            &s,
            &json!({"mfaPendingCredential": b["mfaPendingCredential"], "phoneVerificationInfo": phone}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(
            refused["error"]["message"],
            "INVALID_MFA_PENDING_CREDENTIAL"
        );
        assert!(refused.get("idToken").is_none());
        assert_eq!(get(&s, &format!("{EMU}/verificationCodes")).1, codes);
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count);
        assert_eq!(*lines.lock().unwrap(), notices);
        let (status, signed) = finalize_mfa(
            &s,
            &json!({"mfaPendingCredential": a["mfaPendingCredential"], "phoneVerificationInfo": phone}),
        );
        assert_eq!(status, 200, "{signed}");
        assert!(s.store.lock().unwrap().verification_codes().is_empty());
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"][0]["localId"], user["localId"]);
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count - 1);
        assert_ne!(finalize_mfa(&s, &json!({"mfaPendingCredential": a["mfaPendingCredential"], "phoneVerificationInfo": phone})).0, 200);
    }
}

#[test]
fn pending_retry_preserves_sms_codes_across_purpose_mismatches() {
    for strict in [false, true] {
        let (s, lines) = oob_authorization_state(strict);
        let user = sign_up(&s, "purpose-mismatch@example.com");
        let (status, seeded) = admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:update"),
            &json!({"localId": user["localId"], "emailVerified": true,
                "mfa": {"enrollments": [{"phoneInfo": "+15559876543"}]}}),
        );
        assert_eq!(status, 200, "{seeded}");
        let (status, pending) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "purpose-mismatch@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{pending}");
        assert!(pending.get("idToken").is_none());
        let (status, started) = post(
            &s,
            &format!("{V2}/accounts/mfaSignIn:start"),
            &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
                "mfaEnrollmentId": pending["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {}}),
        );
        assert_eq!(status, 200, "{started}");
        // A plain phone sign-in code for an unrelated number, issued after the MFA code.
        let (status, sent) = post(
            &s,
            &format!("{V1}/accounts:sendVerificationCode"),
            &json!({"phoneNumber": "+15550001111"}),
        );
        assert_eq!(status, 200, "{sent}");
        let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
        let list = codes["verificationCodes"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        let mfa_session = started["phoneResponseInfo"]["sessionInfo"].as_str().unwrap();
        let plain_session = sent["sessionInfo"].as_str().unwrap();
        let code_for = |session: &str| {
            list.iter()
                .find(|c| c["sessionInfo"] == session)
                .map(|c| c["code"].clone())
                .unwrap()
        };
        let mfa_code = json!({"sessionInfo": mfa_session, "code": code_for(mfa_session)});
        let plain_code = json!({"sessionInfo": plain_session, "code": code_for(plain_session)});
        let notices = lines.lock().unwrap().clone();
        let count = s.store.lock().unwrap().pending_sign_in_count();

        // The plain sign-in code is refused by the MFA finalizer and kept.
        let (status, refused) = finalize_mfa(
            &s,
            &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": plain_code}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
        assert!(refused.get("idToken").is_none());
        // The MFA code is refused by the plain phone sign-in and kept.
        let (status, refused) = post(&s, &format!("{V1}/accounts:signInWithPhoneNumber"), &mfa_code);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
        assert!(refused.get("idToken").is_none());
        assert_eq!(get(&s, &format!("{EMU}/verificationCodes")).1, codes);
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count);
        assert_eq!(*lines.lock().unwrap(), notices);

        // Both codes still work for their own purpose, and each is consumed exactly once.
        let (status, signed) = finalize_mfa(
            &s,
            &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": mfa_code}),
        );
        assert_eq!(status, 200, "{signed}");
        {
            let store = s.store.lock().unwrap();
            let remaining = store.verification_codes();
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].session_info, plain_session);
            assert_eq!(store.pending_sign_in_count(), count - 1);
        }
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"][0]["localId"], user["localId"]);
        let (status, phone_user) =
            post(&s, &format!("{V1}/accounts:signInWithPhoneNumber"), &plain_code);
        assert_eq!(status, 200, "{phone_user}");
        assert_eq!(phone_user["phoneNumber"], "+15550001111");
        assert_ne!(phone_user["localId"], user["localId"]);
        assert!(s.store.lock().unwrap().verification_codes().is_empty());
        assert_ne!(post(&s, &format!("{V1}/accounts:signInWithPhoneNumber"), &plain_code).0, 200);
        assert_ne!(
            finalize_mfa(&s, &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": mfa_code})).0,
            200
        );
    }
}

/// A verified user with one phone factor, plus closures that sign in (pending), start the
/// phone step and finalize it against the shared state.
fn pending_expiry_state(
    strict: bool,
    email: &str,
) -> (AuthState, Value) {
    let (s, _) = oob_authorization_state(strict);
    let user = sign_up(&s, email);
    let (status, seeded) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": user["localId"], "emailVerified": true,
            "mfa": {"enrollments": [{"phoneInfo": "+15559876543"}]}}),
    );
    assert_eq!(status, 200, "{seeded}");
    (s, user)
}

fn advance_clock(s: &AuthState, seconds: i64) {
    s.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(seconds))
        .unwrap();
}

fn pending_login(s: &AuthState, email: &str) -> Value {
    let (status, response) = post(
        s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{response}");
    assert!(response.get("idToken").is_none());
    response
}

fn start_phone_step(s: &AuthState, pending: &Value) -> (u16, Value) {
    post(
        s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
            "mfaEnrollmentId": pending["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {}}),
    )
}

/// Starts the phone step and returns its `phoneVerificationInfo` from the code listing.
fn start_phone_code(s: &AuthState, pending: &Value) -> Value {
    let (status, started) = start_phone_step(s, pending);
    assert_eq!(status, 200, "{started}");
    let session = started["phoneResponseInfo"]["sessionInfo"].clone();
    let (_, codes) = get(s, &format!("{EMU}/verificationCodes"));
    let code = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["sessionInfo"] == session)
        .map(|c| c["code"].clone())
        .unwrap();
    json!({"sessionInfo": session, "code": code})
}

fn finalize_phone_step(s: &AuthState, pending: &Value, phone: &Value) -> (u16, Value) {
    finalize_mfa(
        s,
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": phone}),
    )
}

#[test]
fn pending_retry_survives_sms_expiry_while_the_pending_credential_lives() {
    use fireemu_core_auth::store::SMS_CODE_TTL_SECONDS;
    for strict in [false, true] {
        let email = "pending-expiry@example.com";
        let (s, user) = pending_expiry_state(strict, email);

        // Exactly at the SMS lifetime the code is still accepted.
        let pending = pending_login(&s, email);
        let phone = start_phone_code(&s, &pending);
        advance_clock(&s, SMS_CODE_TTL_SECONDS);
        let (status, signed) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 200, "{signed}");
        assert!(s.store.lock().unwrap().verification_codes().is_empty());
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);

        // One second past it the code is refused, but the pending credential is kept: the
        // same pending credential can start a fresh code and finalize with it.
        let pending = pending_login(&s, email);
        let phone = start_phone_code(&s, &pending);
        advance_clock(&s, SMS_CODE_TTL_SECONDS + 1);
        let (status, refused) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
        assert!(refused.get("idToken").is_none());
        assert!(s.store.lock().unwrap().verification_codes().is_empty());
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 1);
        let fresh = start_phone_code(&s, &pending);
        assert_ne!(fresh["sessionInfo"], phone["sessionInfo"]);
        assert_ne!(finalize_phone_step(&s, &pending, &phone).0, 200, "the expired code stays dead");
        let (status, signed) = finalize_phone_step(&s, &pending, &fresh);
        assert_eq!(status, 200, "{signed}");
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"][0]["localId"], user["localId"]);
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
    }
}

#[test]
fn pending_retry_ends_when_the_pending_credential_expires() {
    use fireemu_core_auth::store::PENDING_SIGN_IN_TTL_SECONDS;
    for strict in [false, true] {
        let email = "pending-lifetime@example.com";
        let (s, _) = pending_expiry_state(strict, email);
        // At the pending lifetime a fresh code still finalizes; one second past it the
        // pending credential is gone, its code with it, and start is refused as well.
        let pending = pending_login(&s, email);
        advance_clock(&s, PENDING_SIGN_IN_TTL_SECONDS);
        let phone = start_phone_code(&s, &pending);
        let (status, signed) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 200, "{signed}");
        let pending = pending_login(&s, email);
        let phone = start_phone_code(&s, &pending);
        advance_clock(&s, PENDING_SIGN_IN_TTL_SECONDS + 1);
        let (status, refused) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
        assert!(s.store.lock().unwrap().verification_codes().is_empty());
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
        let (status, refused) = start_phone_step(&s, &pending);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_MFA_PENDING_CREDENTIAL");
    }
}

#[test]
fn two_party_mfa_refusal_preserves_owner_code_and_factor() {
    for strict in [false, true] {
        let (s, lines) = oob_authorization_state(strict);
        let a = sign_up(&s, "factor-a@example.com");
        let b = sign_up(&s, "factor-b@example.com");
        for user in [&a, &b] {
            verify_email(&s, user["localId"].as_str().unwrap());
        }
        let (status, started) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": a["idToken"], "phoneEnrollmentInfo": {"phoneNumber": "+15559876543"}}),
        );
        assert_eq!(status, 200, "{started}");
        let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
        let verification = json!({"sessionInfo": started["phoneSessionInfo"]["sessionInfo"], "code": codes["verificationCodes"][0]["code"]});
        let before = two_party_accounts(&s, &a, &b);
        let notices = lines.lock().unwrap().clone();
        let (status, refused) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:finalize"),
            &json!({"idToken": b["idToken"], "phoneVerificationInfo": verification}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
        assert_eq!(get(&s, &format!("{EMU}/verificationCodes")).1, codes);
        assert_eq!(two_party_accounts(&s, &a, &b), before);
        assert_eq!(*lines.lock().unwrap(), notices);
        let (status, enrolled) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:finalize"),
            &json!({"idToken": a["idToken"], "phoneVerificationInfo": verification}),
        );
        assert_eq!(status, 200, "{enrolled}");
        let factor = claims(enrolled["idToken"].as_str().unwrap())["firebase"]
            ["second_factor_identifier"]
            .clone();
        assert!(factor.is_string());
        let before = two_party_accounts(&s, &a, &b);
        let (status, refused) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:withdraw"),
            &json!({"idToken": b["idToken"], "mfaEnrollmentId": factor}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "MFA_ENROLLMENT_NOT_FOUND");
        assert_eq!(two_party_accounts(&s, &a, &b), before);
        let (status, withdrawn) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:withdraw"),
            &json!({"idToken": enrolled["idToken"], "mfaEnrollmentId": factor}),
        );
        assert_eq!(status, 200, "{withdrawn}");
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": withdrawn["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"].as_array().unwrap().len(), 1);
        assert_eq!(lookup["users"][0]["localId"], a["localId"]);
        assert!(lookup["users"][0].get("mfaInfo").is_none());
    }
}

#[test]
fn two_party_idp_fixture_refusal_preserves_both_accounts_and_owner_sign_in() {
    for strict in [false, true] {
        let (s, _) = oob_authorization_state(strict);
        let a = sign_up(&s, "fixture-a@example.com");
        let b = sign_up(&s, "fixture-b@example.com");
        let assertion = idp_jwt(
            &json!({"sub": "owned-identity", "email": "fixture-a@example.com", "email_verified": true}),
        );
        let mut request = json!({"postBody": format!("id_token={assertion}&providerId=google.com"), "requestUri": "http://localhost", "idToken": a["idToken"]});
        let (status, linked) = post(&s, &format!("{V1}/accounts:signInWithIdp"), &request);
        assert_eq!(status, 200, "{linked}");
        assert_eq!(linked["localId"], a["localId"]);
        let before = two_party_accounts(&s, &a, &b);
        request["idToken"] = b["idToken"].clone();
        let (status, refused) = post(&s, &format!("{V1}/accounts:signInWithIdp"), &request);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(
            refused["error"]["message"],
            "FEDERATED_USER_ID_ALREADY_LINKED"
        );
        assert!(refused.get("idToken").is_none());
        assert_eq!(two_party_accounts(&s, &a, &b), before);
        request.as_object_mut().unwrap().remove("idToken");
        let (status, signed) = post(&s, &format!("{V1}/accounts:signInWithIdp"), &request);
        assert_eq!(status, 200, "{signed}");
        assert_eq!(signed["localId"], a["localId"]);
        let (status, own) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200);
        assert_eq!(own["users"][0]["localId"], a["localId"]);
    }
}

fn assert_oob_denial_unchanged(s: &AuthState, lines: &Arc<Mutex<Vec<String>>>, body: &Value) {
    let selection = json!({"email": ["oob-owner@example.com", "oob-other@example.com"]});
    let users = admin(
        s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &selection,
    );
    assert_eq!(users.0, 200);
    let codes = get(s, &format!("{EMU}/oobCodes"));
    let notices = lines.lock().unwrap().clone();
    let (status, response) = post(s, &format!("{V1}/accounts:sendOobCode"), body);
    assert_eq!(status, 400, "{response}");
    assert!(response.get("oobCode").is_none());
    assert!(response.get("oobLink").is_none());
    assert_eq!(get(s, &format!("{EMU}/oobCodes")), codes);
    assert_eq!(*lines.lock().unwrap(), notices);
    assert_eq!(
        admin(
            s,
            &format!("{V1}/projects/demo-app/accounts:lookup"),
            &selection
        ),
        users
    );
}

#[test]
fn oob_authorization_rejects_end_user_link_generation_without_side_effects() {
    for strict in [false, true] {
        let (s, lines) = oob_authorization_state(strict);
        let user = sign_up(&s, "oob-owner@example.com");
        sign_up(&s, "oob-other@example.com");
        for request_type in [
            "PASSWORD_RESET",
            "EMAIL_SIGNIN",
            "VERIFY_EMAIL",
            "VERIFY_AND_CHANGE_EMAIL",
        ] {
            for token in [
                None,
                Some(json!("malformed")),
                Some(user["idToken"].clone()),
            ] {
                let mut body = json!({"requestType": request_type, "email": "oob-other@example.com",
                    "newEmail": "oob-new@example.com", "returnOobLink": true, "admin": true});
                if let Some(token) = token {
                    body["idToken"] = token;
                }
                assert_oob_denial_unchanged(&s, &lines, &body);
            }
        }
    }
}

#[test]
fn oob_authorization_requires_verified_identity_for_email_actions() {
    for strict in [false, true] {
        let (s, lines) = oob_authorization_state(strict);
        sign_up(&s, "oob-owner@example.com");
        sign_up(&s, "oob-other@example.com");
        for request_type in ["VERIFY_EMAIL", "VERIFY_AND_CHANGE_EMAIL"] {
            for token in [
                None,
                Some(Value::Null),
                Some(json!(false)),
                Some(json!("malformed")),
            ] {
                let mut body = json!({"requestType": request_type, "email": "oob-other@example.com",
                    "newEmail": "oob-new@example.com"});
                if let Some(token) = token {
                    body["idToken"] = token;
                }
                assert_oob_denial_unchanged(&s, &lines, &body);
            }
        }
    }
}

#[test]
fn oob_authorization_preserves_delivery_and_authenticated_admin_generation() {
    for strict in [false, true] {
        let (s, lines) = oob_authorization_state(strict);
        let user = sign_up(&s, "oob-owner@example.com");
        sign_up(&s, "oob-other@example.com");
        for request_type in [
            "PASSWORD_RESET",
            "EMAIL_SIGNIN",
            "VERIFY_EMAIL",
            "VERIFY_AND_CHANGE_EMAIL",
        ] {
            let mut body = json!({"requestType": request_type, "email": "oob-other@example.com",
                "newEmail": "oob-new@example.com", "returnOobLink": false});
            let verification = matches!(request_type, "VERIFY_EMAIL" | "VERIFY_AND_CHANGE_EMAIL");
            if verification {
                body["idToken"] = user["idToken"].clone();
            }
            let (status, response) = post(&s, &format!("{V1}/accounts:sendOobCode"), &body);
            assert_eq!(status, 200, "{response}");
            assert!(response.get("oobCode").is_none());
            assert!(response.get("oobLink").is_none());
            assert_eq!(
                response["email"],
                if verification {
                    "oob-owner@example.com"
                } else {
                    "oob-other@example.com"
                }
            );
            assert_eq!(drain(&lines).len(), 1);
            body.as_object_mut().unwrap().remove("idToken");
            body["returnOobLink"] = json!(true);
            let path = format!("{V1}/projects/demo-app/accounts:sendOobCode");
            assert_ne!(post(&s, &path, &body).0, 200);
            let headers = RequestHeaders {
                authorization: Some(format!("Bearer {}", user["idToken"].as_str().unwrap())),
                ..owner()
            };
            assert_ne!(handle_with(&s, "POST", &path, &headers, &body).status, 200);
            let (status, response) = admin(&s, &path, &body);
            assert_eq!(status, 200, "{response}");
            assert!(response["oobCode"].is_string());
            assert!(response["oobLink"].is_string());
            assert_eq!(response["email"], "oob-other@example.com");
            assert!(drain(&lines).is_empty());
            let result = handle_with(
                &s,
                "POST",
                &format!("{V1}/accounts:sendOobCode"),
                &owner(),
                &body,
            );
            assert_eq!(result.status, 400, "owner header cannot change route class");
        }
    }
}

#[test]
fn email_action_links_are_announced_once_unless_the_link_is_returned() {
    let (s, lines) = recording_state();
    let user = sign_up(&s, "notice@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    assert!(drain(&lines).is_empty(), "sign-up issues no code");

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": id_token}),
    );
    assert_eq!(status, 200, "{body}");
    let (_, codes) = get(&s, &format!("{EMU}/oobCodes"));
    let code = codes["oobCodes"][0]["oobCode"].as_str().unwrap().to_owned();
    assert_eq!(
        drain(&lines),
        vec![format!(
            "To verify the email address notice@example.com, follow this link: http://127.0.0.1:9099/emulator/action?mode=verifyEmail&lang=en&oobCode={code}&apiKey=fake-api-key"
        )]
    );
    // Reading the inspection route announces nothing, and neither does a second read.
    let _ = get(&s, &format!("{EMU}/oobCodes"));
    assert!(drain(&lines).is_empty());

    // The Admin link generators receive the link in the response and print nothing.
    let (status, link) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "email": "notice@example.com", "returnOobLink": true}),
    );
    assert_eq!(status, 200, "{link}");
    assert!(link["oobLink"].is_string());
    assert!(drain(&lines).is_empty());

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "notice@example.com", "continueUrl": "https://app.example/x?y=1"}),
    );
    assert_eq!(status, 200, "{body}");
    let (_, codes) = get(&s, &format!("{EMU}/oobCodes"));
    let reset = codes["oobCodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["requestType"] == "PASSWORD_RESET")
        .unwrap()["oobCode"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        drain(&lines),
        vec![format!(
            "To reset the password for notice@example.com, follow this link: http://127.0.0.1:9099/emulator/action?mode=resetPassword&lang=en&oobCode={reset}&apiKey=fake-api-key&continueUrl=https%3A%2F%2Fapp.example%2Fx%3Fy%3D1&newPassword=NEW_PASSWORD_HERE"
        )]
    );

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "link@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    let lines_now = drain(&lines);
    assert_eq!(lines_now.len(), 1);
    assert!(
        lines_now[0].starts_with("To sign in as link@example.com, follow this link: http://127.0.0.1:9099/emulator/action?mode=signIn&"),
        "{}",
        lines_now[0]
    );

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "idToken": id_token, "newEmail": "next@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    let lines_now = drain(&lines);
    assert_eq!(lines_now.len(), 1);
    assert!(
        lines_now[0].starts_with("To verify and change the email address from notice@example.com to next@example.com, follow this link: http://127.0.0.1:9099/emulator/action?mode=verifyAndChangeEmail&"),
        "{}",
        lines_now[0]
    );

    // A refused request issues nothing and announces nothing.
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "nobody@example.com"}),
    );
    assert_eq!(status, 400);
    assert!(drain(&lines).is_empty());
}

/// The outstanding SMS code whose `field` (`phoneNumber`, `sessionInfo`) is `value`.
fn outstanding_sms_code(state: &AuthState, field: &str, value: &Value) -> String {
    let (_, codes) = get(state, &format!("{EMU}/verificationCodes"));
    codes["verificationCodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| &c[field] == value)
        .unwrap_or_else(|| panic!("no outstanding code with {field} = {value}"))["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn sms_codes_are_announced_per_number_for_sign_in_enrollment_and_mfa_sign_in() {
    let (s, lines) = recording_state();
    let (status, bad) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "555"}),
    );
    assert_eq!(status, 400, "{bad}");
    assert!(
        drain(&lines).is_empty(),
        "a refused request announces nothing"
    );

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15551234567", "recaptchaToken": "ignored"}),
    );
    assert_eq!(status, 200, "{body}");
    let code = outstanding_sms_code(&s, "phoneNumber", &json!("+15551234567"));
    assert_eq!(
        drain(&lines),
        vec![format!(
            "To verify the phone number +15551234567, use the code {code}."
        )]
    );

    // Two users enrol at the same time: each line names its own number and code.
    let mut sessions = Vec::new();
    for (email, phone) in [
        ("one@example.com", "+15550000001"),
        ("two@example.com", "+15550000002"),
    ] {
        let user = sign_up(&s, email);
        verify_email(&s, user["localId"].as_str().unwrap());
        let (status, start) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": user["idToken"], "phoneEnrollmentInfo": {"phoneNumber": phone, "recaptchaToken": "x"}}),
        );
        assert_eq!(status, 200, "{start}");
        sessions.push((
            user,
            phone,
            start["phoneSessionInfo"]["sessionInfo"]
                .as_str()
                .unwrap()
                .to_owned(),
        ));
    }
    let expected: Vec<String> = sessions
        .iter()
        .map(|(_, phone, _)| {
            let code = outstanding_sms_code(&s, "phoneNumber", &json!(phone));
            format!("To enroll MFA with {phone}, use the code {code}.")
        })
        .collect();
    assert_eq!(drain(&lines), expected);

    // Finalizing consumes the codes without announcing anything more.
    for (user, _, session) in &sessions {
        let code = outstanding_sms_code(&s, "sessionInfo", &json!(session));
        let (status, done) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:finalize"),
            &json!({"idToken": user["idToken"], "phoneVerificationInfo": {"sessionInfo": session, "code": code}}),
        );
        assert_eq!(status, 200, "{done}");
    }
    assert!(drain(&lines).is_empty());

    // The second factor step of a sign-in.
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "two@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(drain(&lines).is_empty());
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "mfaEnrollmentId": pending["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {"recaptchaToken": "x"}}),
    );
    assert_eq!(status, 200, "{started}");
    // The unconsumed first-factor code from above is still outstanding: the line names the
    // code of this session, not the oldest one.
    let code = outstanding_sms_code(
        &s,
        "sessionInfo",
        &started["phoneResponseInfo"]["sessionInfo"],
    );
    assert_eq!(
        drain(&lines),
        vec![format!(
            "To sign in with MFA using +15550000002, use the code {code}."
        )]
    );
}

/// A tenant's action links carry `tenantId`, as the official emulator's `TenantProjectState`
/// appends it: in the Admin link generator response, in the console line and on the
/// inspection route. The default project's links carry none.
#[test]
fn tenant_action_links_name_the_tenant() {
    use fireemu_core_auth::store::AuthRegistry;

    let (mut s, lines) = recording_state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer-a").unwrap();
    s.registry = Some(registry);
    let tenant = format!("{V1}/projects/demo-app/tenants/customer-a");
    let (status, created) = admin(
        &s,
        &format!("{tenant}/accounts"),
        &json!({"email": "tenant@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");

    let (status, link) = admin(
        &s,
        &format!("{tenant}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "tenant@example.com", "returnOobLink": true, "continueUrl": "https://app.example/x"}),
    );
    assert_eq!(status, 200, "{link}");
    let admin_link = link["oobLink"].as_str().unwrap();
    assert!(
        admin_link.ends_with("&continueUrl=https%3A%2F%2Fapp.example%2Fx&tenantId=customer-a"),
        "{admin_link}"
    );
    assert!(drain(&lines).is_empty());

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "tenant@example.com", "tenantId": "customer-a"}),
    );
    assert_eq!(status, 200, "{body}");
    let printed = drain(&lines);
    assert_eq!(printed.len(), 1);
    assert!(
        printed[0]
            .contains("&apiKey=fake-api-key&tenantId=customer-a&newPassword=NEW_PASSWORD_HERE"),
        "{}",
        printed[0]
    );

    let (status, codes) = get(
        &s,
        "/emulator/v1/projects/demo-app/tenants/customer-a/oobCodes",
    );
    assert_eq!(status, 200, "{codes}");
    let codes = codes["oobCodes"].as_array().unwrap();
    assert_eq!(codes.len(), 2, "{codes:?}");
    for code in codes {
        assert!(
            code["oobLink"]
                .as_str()
                .unwrap()
                .contains("&tenantId=customer-a"),
            "{code}"
        );
    }
    // The default project's list does not show the tenant's codes.
    let (_, codes) = get(&s, &format!("{EMU}/oobCodes"));
    assert_eq!(codes["oobCodes"].as_array().map(Vec::len), Some(0));

    // The tenant's SMS codes and account wipe are scoped the same way.
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+15550009999", "recaptchaToken": "x", "tenantId": "customer-a"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (status, codes) = get(
        &s,
        "/emulator/v1/projects/demo-app/tenants/customer-a/verificationCodes",
    );
    assert_eq!(status, 200, "{codes}");
    assert_eq!(codes["verificationCodes"][0]["phoneNumber"], "+15550009999");
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    assert_eq!(codes["verificationCodes"].as_array().map(Vec::len), Some(0));
    let wiped = handle(
        &s,
        "DELETE",
        "/emulator/v1/projects/demo-app/tenants/customer-a/accounts",
        &json!({}),
    );
    assert_eq!(wiped.status, 200, "{}", wiped.body);
    let (status, users) = admin(&s, &format!("{tenant}/accounts:query"), &json!({}));
    assert_eq!(status, 200, "{users}");
    assert_eq!(users["recordsCount"], "0", "{users}");
    drain(&lines);

    // The default project's links carry no tenant.
    let user = sign_up(&s, "plain@example.com");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": user["idToken"]}),
    );
    assert_eq!(status, 200, "{body}");
    let printed = drain(&lines);
    assert!(!printed[0].contains("tenantId"), "{}", printed[0]);
}

/// `GET /emulator/action?...` as a browser opens it: no Origin, no credential, JSON body.
fn follow(state: &AuthState, link: &str) -> (u16, Value) {
    let path = link
        .strip_prefix("http://127.0.0.1:9099")
        .unwrap_or_else(|| panic!("link is not on the emulator host: {link}"));
    let headers = RequestHeaders {
        authorization: None,
        origin: None,
        content_type: None,
        host: Some("127.0.0.1:9099".to_owned()),
        app_check: Vec::new(),
    };
    let r = handle_with(state, "GET", path, &headers, &json!({}));
    (r.status, r.body)
}

fn issued_code(state: &AuthState, request_type: &str) -> String {
    let (_, codes) = get(state, &format!("{EMU}/oobCodes"));
    codes["oobCodes"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|c| c["requestType"] == request_type)
        .unwrap()["oobCode"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn the_announced_verify_email_link_verifies_the_address_when_opened() {
    let (s, lines) = recording_state();
    let user = sign_up(&s, "opened@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": id_token}),
    );
    assert_eq!(status, 200, "{body}");
    let announced = drain(&lines).remove(0);
    let link = announced
        .split("follow this link: ")
        .nth(1)
        .unwrap()
        .to_owned();

    let (status, body) = follow(&s, &link);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"authEmulator": {"success": "The email has been successfully verified.", "email": "opened@example.com"}})
    );
    let (_, looked) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": id_token}),
    );
    assert_eq!(looked["users"][0]["emailVerified"], json!(true));

    // The code is consumed: the same link reports the official wording.
    let (status, body) = follow(&s, &link);
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body,
        json!({"authEmulator": {"error": "Your request to verify your email has expired or the link has already been used.", "instructions": "Try verifying your email again."}})
    );
}

#[test]
fn action_links_refuse_missing_parameters_and_unknown_modes_like_the_official_emulator() {
    let s = state();
    let (status, body) = follow(
        &s,
        "http://127.0.0.1:9099/emulator/action?mode=verifyEmail&oobCode=x",
    );
    assert_eq!(status, 400);
    assert_eq!(
        body["authEmulator"]["error"],
        "missing apiKey query parameter"
    );
    let (status, body) = follow(
        &s,
        "http://127.0.0.1:9099/emulator/action?mode=verifyEmail&apiKey=fake-api-key",
    );
    assert_eq!(status, 400);
    assert_eq!(
        body["authEmulator"]["error"],
        "missing oobCode query parameter"
    );
    let (status, body) = follow(
        &s,
        "http://127.0.0.1:9099/emulator/action?mode=dance&oobCode=x&apiKey=fake-api-key",
    );
    assert_eq!(status, 400);
    assert_eq!(body, json!({"authEmulator": {"error": "Invalid mode"}}));
    // A mode this runtime has no request type for is refused by the code check.
    let (status, body) = follow(
        &s,
        "http://127.0.0.1:9099/emulator/action?mode=recoverEmail&oobCode=x&apiKey=fake-api-key",
    );
    assert_eq!(status, 400);
    assert_eq!(
        body["authEmulator"]["error"],
        "Requested mode does not match the OOB code provided."
    );
    // The route accepts GET only, and the path stays known for other methods.
    let r = handle(
        &s,
        "POST",
        "/emulator/action?mode=verifyEmail&oobCode=x&apiKey=k",
        &json!({}),
    );
    assert_eq!(r.status, 405, "{}", r.body);
}

#[test]
fn a_verify_email_link_with_a_wrong_code_kind_is_expired_wording() {
    let s = state();
    sign_up(&s, "kind@example.com");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "kind@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    let code = issued_code(&s, "PASSWORD_RESET");
    let (status, body) = follow(
        &s,
        &format!("http://127.0.0.1:9099/emulator/action?mode=verifyEmail&oobCode={code}&apiKey=fake-api-key"),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["authEmulator"]["error"],
        "Your request to verify your email has expired or the link has already been used."
    );
    // The reset code is untouched.
    assert_eq!(issued_code(&s, "PASSWORD_RESET"), code);
}

#[test]
fn the_reset_password_link_needs_a_real_new_password_and_then_sets_it() {
    let s = state();
    sign_up(&s, "reset@example.com");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "reset@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    let code = issued_code(&s, "PASSWORD_RESET");
    let link = format!(
        "http://127.0.0.1:9099/emulator/action?mode=resetPassword&lang=en&oobCode={code}&apiKey=fake-api-key"
    );

    let (status, body) = follow(&s, &link);
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body,
        json!({"authEmulator": {
            "error": "missing newPassword query parameter",
            "instructions": "To reset the password for reset@example.com, send an HTTP GET request to the following URL.",
            "instructions2": "You may use a web browser or any HTTP client, such as curl.",
            "urlTemplate": format!("{link}&newPassword=NEW_PASSWORD_HERE"),
        }})
    );
    let (status, body) = follow(&s, &format!("{link}&newPassword=NEW_PASSWORD_HERE"));
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["authEmulator"]["error"],
        "newPassword must be something other than 'NEW_PASSWORD_HERE'"
    );
    assert_eq!(
        body["authEmulator"]["urlTemplate"],
        json!(format!("{link}&newPassword=NEW_PASSWORD_HERE"))
    );
    // A refused password is the ordinary API error.
    let (status, body) = follow(&s, &format!("{link}&newPassword=short"));
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("WEAK_PASSWORD"),
        "{body}"
    );

    let (status, body) = follow(&s, &format!("{link}&newPassword=fresh%20pass1"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"authEmulator": {"success": "The password has been successfully updated.", "email": "reset@example.com"}})
    );
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "reset@example.com", "password": "fresh pass1"}),
    );
    assert_eq!(status, 200, "{body}");

    // Used up: the official wording for a stale reset link.
    let (status, body) = follow(&s, &format!("{link}&newPassword=another1"));
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body,
        json!({"authEmulator": {"error": "Your request to reset your password has expired or the link has already been used.", "instructions": "Try resetting your password again."}})
    );
}

#[test]
fn action_links_with_a_continue_url_redirect_after_acting() {
    let s = state();
    let user = sign_up(&s, "redirect@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": id_token, "continueUrl": "https://app.example/done?x=1"}),
    );
    assert_eq!(status, 200, "{body}");
    let code = issued_code(&s, "VERIFY_EMAIL");
    let (status, body) = follow(
        &s,
        &format!("http://127.0.0.1:9099/emulator/action?mode=verifyEmail&oobCode={code}&apiKey=fake-api-key&continueUrl=https%3A%2F%2Fapp.example%2Fdone%3Fx%3D1"),
    );
    assert_eq!(status, 303, "{body}");
    assert_eq!(
        fireemu_adapter_http::identity_toolkit::redirect_location(&body),
        Some("https://app.example/done?x=1")
    );
    let (_, looked) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": id_token}),
    );
    assert_eq!(looked["users"][0]["emailVerified"], json!(true));

    // Password reset with continueUrl redirects too.
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "redirect@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    let code = issued_code(&s, "PASSWORD_RESET");
    let (status, body) = follow(
        &s,
        &format!("http://127.0.0.1:9099/emulator/action?mode=resetPassword&oobCode={code}&apiKey=fake-api-key&continueUrl=https%3A%2F%2Fapp.example%2Fback&newPassword=newpass99"),
    );
    assert_eq!(status, 303, "{body}");
    assert_eq!(
        fireemu_adapter_http::identity_toolkit::redirect_location(&body),
        Some("https://app.example/back")
    );
}

#[test]
fn the_sign_in_link_forwards_its_parameters_to_the_continue_url() {
    let s = state();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "link@example.com", "continueUrl": "https://app.example/finish?keep=1&mode=old"}),
    );
    assert_eq!(status, 200, "{body}");
    let code = issued_code(&s, "EMAIL_SIGNIN");
    // Without continueUrl the link cannot complete the sign-in.
    let (status, body) = follow(
        &s,
        &format!(
            "http://127.0.0.1:9099/emulator/action?mode=signIn&oobCode={code}&apiKey=fake-api-key"
        ),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["authEmulator"]["error"],
        "Missing continueUrl query parameter"
    );

    let (status, body) = follow(
        &s,
        &format!("http://127.0.0.1:9099/emulator/action?mode=signIn&lang=en&oobCode={code}&apiKey=fake-api-key&continueUrl=https%3A%2F%2Fapp.example%2Ffinish%3Fkeep%3D1%26mode%3Dold"),
    );
    assert_eq!(status, 303, "{body}");
    // `URLSearchParams.set`: an existing name is replaced in place, new names are appended.
    assert_eq!(
        fireemu_adapter_http::identity_toolkit::redirect_location(&body),
        Some(format!("https://app.example/finish?keep=1&mode=signIn&lang=en&oobCode={code}&apiKey=fake-api-key").as_str())
    );
    // The code is not consumed by the redirect; the SDK consumes it.
    assert_eq!(issued_code(&s, "EMAIL_SIGNIN"), code);
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "link@example.com", "oobCode": code}),
    );
    assert_eq!(status, 200, "{body}");
}

#[test]
fn the_verify_and_change_email_link_switches_the_address() {
    let s = state();
    let user = sign_up(&s, "before@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "idToken": id_token, "newEmail": "after@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    let code = issued_code(&s, "VERIFY_AND_CHANGE_EMAIL");
    let link = format!(
        "http://127.0.0.1:9099/emulator/action?mode=verifyAndChangeEmail&oobCode={code}&apiKey=fake-api-key"
    );
    let (status, body) = follow(&s, &link);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"authEmulator": {"success": "The email has been successfully changed.", "newEmail": "after@example.com"}})
    );
    let (status, body) = follow(&s, &link);
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body,
        json!({"authEmulator": {"error": "Your request to change your email has expired or the link has already been used.", "instructions": "Try changing your email again."}})
    );
}
