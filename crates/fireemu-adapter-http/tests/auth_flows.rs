//! Email actions (oob codes), email link and phone sign-in, fixture identity providers,
//! phone second factors and the emulator inspection routes.

use std::sync::{Arc, Mutex, RwLock};

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
use fireemu_core_types::determinism::{Clock, SplitMix64};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
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
        idp_continuations: fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::Disabled,
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    }
}

fn post(state: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let path = with_client_key(state, path, "fake-api-key");
    let r = handle(state, "POST", &path, body);
    (r.status, r.body)
}

/// Client SDKs always send their API key. Under a profile that refuses keyless client calls,
/// the plain helper adds it to client routes that do not carry one, as an SDK would.
fn with_client_key(state: &AuthState, path: &str, key: &str) -> String {
    let project_scoped = path.contains("/projects/") || path.starts_with("/emulator");
    let keyed = path.contains("key=") || path.contains("apiKey=");
    if state.client_api_key != fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Required
        || project_scoped
        || keyed
    {
        return path.to_owned();
    }
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}key={key}")
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
        peer_ip: None,
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

#[test]
fn password_routes_canonicalize_email_case_and_reject_case_variant_duplicates() {
    let s = state();
    let created = sign_up(&s, "MixedCase@example.com");
    assert_eq!(created["email"], "mixedcase@example.com");

    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "MIXEDCASE@EXAMPLE.COM",
            "password": "hunter22",
            "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200, "{signed_in}");
    assert_eq!(signed_in["email"], "mixedcase@example.com");
    assert_eq!(signed_in["localId"], created["localId"]);

    let (status, reset) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "MIXEDCASE@EXAMPLE.COM"}),
    );
    assert_eq!(status, 200, "{reset}");
    assert_eq!(reset["email"], "mixedcase@example.com");

    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"email": ["MIXEDCASE@EXAMPLE.COM"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"][0]["localId"], created["localId"]);

    let (status, duplicate) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "mixedcase@example.com", "password": "hunter23"}),
    );
    assert_eq!(status, 400, "{duplicate}");
    assert_eq!(duplicate["error"]["message"], "EMAIL_EXISTS");
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

fn custom_token_with_claims(uid: &str, claims: &Value) -> String {
    let header = base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = json!({
        "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
        "uid": uid,
        "claims": claims,
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
        &json!({"email": "a@example.com", "password": "newpassword1", "returnSecureToken": true}),
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

/// RPCHK-1/RPCHK-2. `accounts:resetPassword` without `newPassword` is `checkActionCode`:
/// production describes the code without consuming it, whatever its type, and only the
/// `newPassword` branch is restricted to `PASSWORD_RESET`
/// (<https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/resetPassword>).
#[test]
fn reset_password_check_mode_describes_every_out_of_band_code_type() {
    let s = state();
    let user = sign_up(&s, "check-mode@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    for body in [
        json!({"requestType": "VERIFY_EMAIL", "idToken": id_token}),
        json!({"requestType": "EMAIL_SIGNIN", "email": "check-link@example.com"}),
        json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "idToken": id_token, "newEmail": "check-new@example.com"}),
    ] {
        let (status, sent) = post(&s, &format!("{V1}/accounts:sendOobCode"), &body);
        assert_eq!(status, 200, "{sent}");
    }
    let verify_code = issued_code(&s, "VERIFY_EMAIL");
    let link_code = issued_code(&s, "EMAIL_SIGNIN");
    let change_code = issued_code(&s, "VERIFY_AND_CHANGE_EMAIL");

    let (status, checked) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": verify_code}),
    );
    assert_eq!(status, 200, "{checked}");
    assert_eq!(checked["requestType"], "VERIFY_EMAIL");
    assert_eq!(checked["email"], "check-mode@example.com");
    assert!(checked.get("newEmail").is_none(), "{checked}");

    // An email-link code has no account yet, and production omits the address for it.
    let (status, checked) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": link_code}),
    );
    assert_eq!(status, 200, "{checked}");
    assert_eq!(checked["requestType"], "EMAIL_SIGNIN");
    assert!(checked.get("email").is_none(), "{checked}");

    let (status, checked) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": change_code}),
    );
    assert_eq!(status, 200, "{checked}");
    assert_eq!(checked["requestType"], "VERIFY_AND_CHANGE_EMAIL");
    assert_eq!(checked["email"], "check-mode@example.com");
    assert_eq!(checked["newEmail"], "check-new@example.com");

    // RPCHK-2. The type check still guards the reset itself, and checking never consumed
    // the codes: the verification code still applies.
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": verify_code, "newPassword": "newpassword1"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "INVALID_OOB_CODE");
    let (status, applied) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": verify_code}),
    );
    assert_eq!(status, 200, "{applied}");
    assert_eq!(applied["emailVerified"], true);
    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "check-link@example.com", "oobCode": link_code}),
    );
    assert_eq!(status, 200, "{signed_in}");
}

/// ITKM-2. The end-user profile routes took whatever string arrived, so a NUL or another
/// control character reached the store and every later rendering of it. `import_user`
/// already refuses those at its own boundary; the request boundary now agrees. Production's
/// refusal shape for this input is unobserved, and the length bounds it applies are not
/// recorded either, so only the control-character check is made here.
#[test]
fn profile_strings_reject_control_characters_on_every_route_that_stores_them() {
    let s = state();
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "control@example.com", "password": "hunter22", "displayName": "na\u{0000}me"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : displayName must not contain control characters"
    );
    // The refused sign-up left no account behind.
    let (_, methods) = post(
        &s,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "control@example.com", "continueUri": "http://localhost"}),
    );
    assert_eq!(methods["registered"], false);

    let user = sign_up(&s, "control@example.com");
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    // Production stores a control character in displayName on update (sandbox recording
    // 2026-09-23, auth-account/values); photoUrl on update stays refused until observed.
    let (status, stored) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": id_token, "displayName": "na\u{0007}me"}),
    );
    assert_eq!(status, 200, "{stored}");
    {
        let (field, value) = ("photoUrl", "https://p.example/a.png\u{0000}");
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": id_token, field: value}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(
            refused["error"]["message"],
            format!("INVALID_ARGUMENT : {field} must not contain control characters")
        );
    }

    // The Admin link route reaches the same parser.
    let (status, refused) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({
            "localId": user["localId"],
            "linkProviderUserInfo": {
                "providerId": "github.com",
                "rawId": "gh-1",
                "displayName": "gh\u{0001}user"
            }
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : displayName must not contain control characters"
    );

    // The Admin create route reaches the same guard: what cannot be imported cannot be
    // created through a request either.
    let (status, refused) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({"email": "admin-control@example.com", "photoUrl": "https://p.example/a.png\u{0000}"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : photoUrl must not contain control characters"
    );

    // A non-string displayName keeps the sign-up route's existing lenient handling: the
    // control-character guard adds no new type refusal.
    let (status, numeric) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "numeric-name@example.com", "password": "hunter22", "displayName": 123}),
    );
    assert_eq!(status, 200, "{numeric}");

    // Ordinary values still pass.
    let (status, updated) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": id_token, "displayName": "Ada Lovelace", "photoUrl": "https://p.example/a.png"}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["displayName"], "Ada Lovelace");
}

fn password_with_utf16_units(units: usize) -> String {
    assert!(units >= 2);
    let mut password = "a".repeat(units - 2);
    password.push('\u{10400}');
    assert_eq!(password.encode_utf16().count(), units);
    password
}

#[test]
fn password_reset_rejects_oversize_and_malformed_passwords_without_consuming_oob_code() {
    for (new_password, expected_status) in [
        (password_with_utf16_units(4095), 200),
        (password_with_utf16_units(4096), 200),
        (password_with_utf16_units(4097), 400),
        ("12345".to_owned(), 400),
        ("12345\u{0000}".to_owned(), 400),
    ] {
        let s = state();
        let user = sign_up(
            &s,
            &format!("reset-policy-{}@example.com", new_password.len()),
        );
        let (status, sent) = post(
            &s,
            &format!("{V1}/accounts:sendOobCode"),
            &json!({"requestType": "PASSWORD_RESET", "email": user["email"]}),
        );
        assert_eq!(status, 200, "{sent}");
        let code = issued_code(&s, "PASSWORD_RESET");
        let (status, response) = post(
            &s,
            &format!("{V1}/accounts:resetPassword"),
            &json!({"oobCode": code, "newPassword": new_password}),
        );
        assert_eq!(status, expected_status, "{response}");
        if expected_status == 400 {
            assert_eq!(
                response["error"]["message"],
                // The sign-up, update and Admin routes name the limit in production (sandbox
                // recording 2026-09-23); the reset route shares that validation.
                if new_password.encode_utf16().count() > AuthStore::MAX_PASSWORD_UTF16_UNITS {
                    "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Password cannot be longer than 4096 characters"
                } else {
                    "WEAK_PASSWORD : Password should be at least 6 characters"
                },
                "{response}"
            );
            let (status, unchanged) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": user["email"], "password": "hunter22"}),
            );
            assert_eq!(status, 200, "{unchanged}");
            assert_eq!(issued_code(&s, "PASSWORD_RESET"), code);
            let (status, applied) = post(
                &s,
                &format!("{V1}/accounts:resetPassword"),
                &json!({"oobCode": code, "newPassword": "recovered-password"}),
            );
            assert_eq!(status, 200, "{applied}");
            let (status, old) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": user["email"], "password": "hunter22"}),
            );
            assert_eq!(status, 400, "{old}");
            let (status, recovered) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": user["email"], "password": "recovered-password"}),
            );
            assert_eq!(status, 200, "{recovered}");
        }
    }

    let s = state();
    let user = sign_up(&s, "reset-policy-malformed@example.com");
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": user["email"]}),
    );
    assert_eq!(status, 200, "{sent}");
    let code = issued_code(&s, "PASSWORD_RESET");
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code, "newPassword": 42}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"],
        "INVALID_ARGUMENT : newPassword must be a string"
    );
    assert_eq!(issued_code(&s, "PASSWORD_RESET"), code);
    let (status, unchanged) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": user["email"], "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{unchanged}");
    let (status, applied) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code, "newPassword": "recovered-password"}),
    );
    assert_eq!(status, 200, "{applied}");
    let (status, recovered) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": user["email"], "password": "recovered-password"}),
    );
    assert_eq!(status, 200, "{recovered}");
}

/// Strict: a password reset refuses the sessions before it as `TOKEN_EXPIRED`; the refresh
/// record is kept and judged against the new `validSince` (sandbox recording 2026-09-24,
/// auth-action/password-reset#refresh-token-before-reset).
#[test]
fn strict_profile_password_reset_revokes_the_existing_refresh_token() {
    let s = AuthState {
        idp_continuations:
            fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::LocalBounded,
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::ProductionBounded,
        stateless_refresh_tokens: false,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Required,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Reject,
        custom_token_trust: None,
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
    s.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(2))
        .unwrap();
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
    assert_eq!(refreshed["error"]["message"], "TOKEN_EXPIRED");
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
fn rejected_email_change_preserves_oob_code_and_account_state() {
    let s = state();
    let owner = sign_up(&s, "oob-change-owner@example.com");
    let other = sign_up(&s, "oob-change-other@example.com");
    let target = "oob-change-target@example.com";
    let (status, verified) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": owner["localId"], "emailVerified": true}),
    );
    assert_eq!(status, 200, "{verified}");

    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({
            "requestType": "VERIFY_AND_CHANGE_EMAIL",
            "idToken": owner["idToken"],
            "newEmail": target,
        }),
    );
    assert_eq!(status, 200, "{sent}");
    let code = get(&s, &format!("{EMU}/oobCodes")).1["oobCodes"][0]["oobCode"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, claimed) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": other["localId"], "email": target}),
    );
    assert_eq!(status, 200, "{claimed}");

    let (status, rejected) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": code}),
    );
    assert_eq!(status, 400, "{rejected}");
    assert_eq!(rejected["error"]["message"], "EMAIL_EXISTS");
    assert_eq!(issued_code(&s, "VERIFY_AND_CHANGE_EMAIL"), code);

    let (_, owner_lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": owner["idToken"]}),
    );
    assert_eq!(
        owner_lookup["users"][0]["email"],
        "oob-change-owner@example.com"
    );
    assert_eq!(owner_lookup["users"][0]["emailVerified"], true);
}

#[test]
fn rejected_email_change_preserves_code_for_an_inactive_duplicate_owner() {
    let s = state();
    let config_path = format!("{EMU}/config");
    let enabled = handle_with(
        &s,
        "PATCH",
        &config_path,
        &owner(),
        &json!({"signIn": {"allowDuplicateEmails": true}}),
    );
    assert_eq!(enabled.status, 200, "{}", enabled.body);

    let owner_user = sign_up(&s, "oob-inactive-owner@example.com");
    let target_a = sign_up(&s, "oob-inactive-target@example.com");
    // A second owner of the address can only be imported: production refuses a second
    // password account even in duplicate-email mode.
    let (status, imported) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:batchCreate"),
        &json!({"users": [{"localId": "oob-inactive-target-b", "email": "oob-inactive-target@example.com"}]}),
    );
    assert_eq!(status, 200, "{imported}");
    assert!(imported.get("error").is_none(), "{imported}");
    let target_b = json!({"localId": "oob-inactive-target-b"});
    let (status, verified) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": owner_user["localId"], "emailVerified": true}),
    );
    assert_eq!(status, 200, "{verified}");

    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({
            "requestType": "VERIFY_AND_CHANGE_EMAIL",
            "idToken": owner_user["idToken"],
            "newEmail": "oob-inactive-target@example.com",
        }),
    );
    assert_eq!(status, 200, "{sent}");
    let code = get(&s, &format!("{EMU}/oobCodes")).1["oobCodes"][0]["oobCode"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, deleted) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:delete"),
        &json!({"localId": target_b["localId"]}),
    );
    assert_eq!(status, 200, "{deleted}");
    let disabled = handle_with(
        &s,
        "PATCH",
        &config_path,
        &owner(),
        &json!({"signIn": {"allowDuplicateEmails": false}}),
    );
    assert_eq!(disabled.status, 200, "{}", disabled.body);

    let (status, rejected) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": code}),
    );
    assert_eq!(status, 400, "{rejected}");
    assert_eq!(rejected["error"]["message"], "EMAIL_EXISTS");
    assert_eq!(
        get(&s, &format!("{EMU}/oobCodes")).1["oobCodes"][0]["oobCode"],
        code
    );

    let (_, owner_lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": owner_user["idToken"]}),
    );
    assert_eq!(
        owner_lookup["users"][0]["email"],
        "oob-inactive-owner@example.com"
    );
    let (_, target_lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [target_a["localId"]]}),
    );
    assert_eq!(
        target_lookup["users"][0]["email"],
        "oob-inactive-target@example.com"
    );

    let (status, deleted) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:delete"),
        &json!({"localId": target_a["localId"]}),
    );
    assert_eq!(status, 200, "{deleted}");
    let (status, applied) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": code}),
    );
    assert_eq!(status, 200, "{applied}");
    assert_eq!(applied["email"], "oob-inactive-target@example.com");
    assert!(get(&s, &format!("{EMU}/oobCodes")).1["oobCodes"]
        .as_array()
        .is_some_and(Vec::is_empty));
}

/// ELPROV-1. Email-link sign-in is a `password` sign-in as far as the token is concerned:
/// `firebase.sign_in_provider` is one of the values Rules documents
/// (<https://firebase.google.com/docs/rules/rules-and-auth#identifying_users>), and
/// `emailLink` is not among them. It stays the sign-in method reported to Blocking
/// Functions and the `createAuthUri` sign-in method.
#[test]
#[allow(clippy::too_many_lines)]
fn email_link_sign_in_issues_password_provider_tokens_through_the_second_factor() {
    let mut s = state();
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "link-provider@example.com"}),
    );
    assert_eq!(status, 200, "{sent}");
    let code = issued_code(&s, "EMAIL_SIGNIN");
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "link-provider@example.com", "oobCode": code}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["isNewUser"], true);
    assert_eq!(
        claims(signed["idToken"].as_str().unwrap())["firebase"]["sign_in_provider"],
        "password"
    );
    // The refresh session carries the same provider.
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": signed["refreshToken"]}),
    );
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(
        claims(refreshed["id_token"].as_str().unwrap())["firebase"]["sign_in_provider"],
        "password"
    );
    // The account is still a passwordless one for fetchSignInMethodsForEmail.
    let (_, methods) = post(
        &s,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "link-provider@example.com", "continueUri": "http://localhost"}),
    );
    assert_eq!(methods["signinMethods"], json!(["emailLink"]));

    // An existing account with a second factor: the pending credential and the token minted
    // after the second factor report the same provider.
    let user = sign_up(&s, "link-mfa@example.com");
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
    let sms = codes["verificationCodes"][0]["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, enrolled) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "displayName": "my phone", "phoneVerificationInfo": {"sessionInfo": session, "code": sms}}),
    );
    assert_eq!(status, 200, "{enrolled}");
    let enrollment_id = claims(enrolled["idToken"].as_str().unwrap())["firebase"]
        ["second_factor_identifier"]
        .as_str()
        .unwrap()
        .to_owned();

    let contexts = Arc::new(Mutex::new(Vec::new()));
    s.blocking = Some(Arc::new(FilteringIdpBlockingHook {
        contexts: Arc::clone(&contexts),
    }));
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "link-mfa@example.com"}),
    );
    assert_eq!(status, 200, "{sent}");
    let code = issued_code(&s, "EMAIL_SIGNIN");
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "link-mfa@example.com", "oobCode": code}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none(), "{pending}");
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
    let sms = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, done) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential, "phoneVerificationInfo": {"sessionInfo": session, "code": sms}}),
    );
    assert_eq!(status, 200, "{done}");
    let c = claims(done["idToken"].as_str().unwrap());
    assert_eq!(c["firebase"]["sign_in_provider"], "password");
    assert_eq!(c["firebase"]["sign_in_second_factor"], "phone");
    // Blocking Functions still see the email-link sign-in method.
    let recorded = contexts.lock().unwrap();
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(recorded[0].1.sign_in_method.as_deref(), Some("emailLink"));
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
    assert_eq!(c["firebase"]["sign_in_provider"], "password");
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
fn email_link_codes_match_case_insensitively_and_store_canonical_email() {
    let s = state();
    let (status, issued) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:sendOobCode"),
        &json!({
            "requestType": "EMAIL_SIGNIN",
            "email": "mixedlink@example.com",
            "returnOobLink": true
        }),
    );
    assert_eq!(status, 200, "{issued}");
    let code = issued["oobCode"].as_str().unwrap();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "MixedLink@example.com", "oobCode": code}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["email"], "mixedlink@example.com");
}

#[test]
fn email_link_sign_in_consumes_the_code_once() {
    let s = state();
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "single-use@example.com"}),
    );
    assert_eq!(status, 200);
    let code = issued_code(&s, "EMAIL_SIGNIN");

    let (status, first) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "single-use@example.com", "oobCode": code}),
    );
    assert_eq!(status, 200, "{first}");
    let (status, reused) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "single-use@example.com", "oobCode": code}),
    );
    assert_eq!(status, 400, "{reused}");
    assert_eq!(reused["error"]["message"], "INVALID_OOB_CODE");
}

#[test]
#[allow(clippy::too_many_lines)]
fn all_oob_kinds_are_usable_at_the_exact_virtual_expiry_boundary() {
    let s = state();
    let _reset = sign_up(&s, "boundary-reset@example.com");
    let verify = sign_up(&s, "boundary-verify@example.com");
    let change = sign_up(&s, "boundary-change@example.com");

    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:sendOobCode"),
            &json!({"requestType": "PASSWORD_RESET", "email": "boundary-reset@example.com"}),
        )
        .0,
        200
    );
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:sendOobCode"),
            &json!({"requestType": "VERIFY_EMAIL", "idToken": verify["idToken"]}),
        )
        .0,
        200
    );
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:sendOobCode"),
            &json!({"requestType": "EMAIL_SIGNIN", "email": "boundary-link@example.com"}),
        )
        .0,
        200
    );
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:sendOobCode"),
            &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "idToken": change["idToken"], "newEmail": "boundary-new@example.com"}),
        )
        .0,
        200
    );

    advance_clock(&s, 3_600);
    let reset_code = issued_code(&s, "PASSWORD_RESET");
    let verify_code = issued_code(&s, "VERIFY_EMAIL");
    let link_code = issued_code(&s, "EMAIL_SIGNIN");
    let change_code = issued_code(&s, "VERIFY_AND_CHANGE_EMAIL");

    let (status, reset_result) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": reset_code, "newPassword": "boundary-password1"}),
    );
    assert_eq!(status, 200, "{reset_result}");
    let (status, verify_result) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": verify_code}),
    );
    assert_eq!(status, 200, "{verify_result}");
    let (status, link_result) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "boundary-link@example.com", "oobCode": link_code}),
    );
    assert_eq!(status, 200, "{link_result}");
    let (status, change_result) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": change_code}),
    );
    assert_eq!(status, 200, "{change_result}");
    assert_eq!(change_result["email"], "boundary-new@example.com");

    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "boundary-reset@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400);
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "boundary-reset@example.com", "password": "boundary-password1"}),
    );
    assert_eq!(status, 200, "{signed}");
    let (_, verified_lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [verify["localId"]]}),
    );
    assert_eq!(
        verified_lookup["users"][0]["emailVerified"], true,
        "{verified_lookup}"
    );
    let (_, link_lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": link_result["idToken"]}),
    );
    assert_eq!(
        link_lookup["users"][0]["email"],
        "boundary-link@example.com"
    );
    assert_eq!(link_lookup["users"][0]["emailVerified"], true);
    let (_, changed_lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [change["localId"]]}),
    );
    assert_eq!(
        changed_lookup["users"][0]["email"],
        "boundary-new@example.com"
    );
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "boundary-change@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400);
    let (status, changed_sign_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "boundary-new@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{changed_sign_in}");

    let (_, remaining) = get(&s, &format!("{EMU}/oobCodes"));
    let remaining = remaining["oobCodes"].as_array().unwrap();
    for code in [&reset_code, &verify_code, &link_code, &change_code] {
        assert!(!remaining.iter().any(|row| row["oobCode"] == *code));
    }
    for (path, body) in [
        (
            format!("{V1}/accounts:resetPassword"),
            json!({"oobCode": reset_code, "newPassword": "another-password1"}),
        ),
        (
            format!("{V1}/accounts:update"),
            json!({"oobCode": verify_code}),
        ),
        (
            format!("{V1}/accounts:signInWithEmailLink"),
            json!({"email": "boundary-link@example.com", "oobCode": link_code}),
        ),
        (
            format!("{V1}/accounts:update"),
            json!({"oobCode": change_code}),
        ),
    ] {
        assert_eq!(post(&s, &path, &body).0, 400, "{path}: {body}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn malformed_oob_inputs_do_not_consume_or_mutate_action_codes() {
    let s = state();
    let user = sign_up(&s, "malformed-oob@example.com");
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": user["idToken"]}),
    );
    assert_eq!(status, 200);
    let code = issued_code(&s, "VERIFY_EMAIL");
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "malformed-link@example.com"}),
    );
    assert_eq!(status, 200);
    let link_code = issued_code(&s, "EMAIL_SIGNIN");

    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "malformed-oob@example.com"}),
    );
    assert_eq!(status, 200);
    let reset_code = issued_code(&s, "PASSWORD_RESET");
    for body in [
        json!({}),
        json!({"oobCode": Value::Null}),
        json!({"oobCode": 42}),
    ] {
        let (status, response) = post(&s, &format!("{V1}/accounts:resetPassword"), &body);
        assert_eq!(status, 400, "{body}: {response}");
        assert_eq!(issued_code(&s, "PASSWORD_RESET"), reset_code);
    }
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": reset_code, "newPassword": Value::Null}),
    );
    assert_eq!(status, 200, "{response}");
    assert_eq!(issued_code(&s, "PASSWORD_RESET"), reset_code);

    for body in [
        json!({}),
        json!({"oobCode": Value::Null}),
        json!({"oobCode": 42}),
        json!({"oobCode": code, "emailVerified": Value::Null}),
    ] {
        let (status, response) = post(&s, &format!("{V1}/accounts:update"), &body);
        assert_eq!(status, 400, "{body}: {response}");
        assert_eq!(issued_code(&s, "VERIFY_EMAIL"), code);
    }

    for body in [
        json!({"email": Value::Null, "oobCode": link_code}),
        json!({"email": "malformed-link@example.com", "oobCode": Value::Null}),
        json!({"email": "malformed-link@example.com", "oobCode": 42}),
    ] {
        let (status, response) = post(&s, &format!("{V1}/accounts:signInWithEmailLink"), &body);
        assert_eq!(status, 400, "{body}: {response}");
        assert_eq!(issued_code(&s, "EMAIL_SIGNIN"), link_code);
    }

    let owner = sign_up(&s, "session-owner@example.com");
    let other = sign_up(&s, "session-other@example.com");
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "session-owner@example.com"}),
    );
    assert_eq!(status, 200);
    let session_code = issued_code(&s, "EMAIL_SIGNIN");
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "session-owner@example.com", "oobCode": session_code, "idToken": "malformed"}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(response["error"]["message"], "INVALID_ID_TOKEN");
    assert_eq!(issued_code(&s, "EMAIL_SIGNIN"), session_code);
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "session-owner@example.com", "oobCode": session_code, "idToken": other["idToken"]}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(response["error"]["message"], "EMAIL_EXISTS");
    assert_eq!(issued_code(&s, "EMAIL_SIGNIN"), session_code);
    let (_, owner_lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": owner["idToken"]}),
    );
    let (_, other_lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": other["idToken"]}),
    );
    assert_eq!(
        owner_lookup["users"][0]["email"],
        "session-owner@example.com"
    );
    assert_eq!(
        other_lookup["users"][0]["email"],
        "session-other@example.com"
    );
    assert_eq!(owner_lookup["users"][0]["emailVerified"], false);
    assert_eq!(other_lookup["users"][0]["emailVerified"], false);
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

/// ITKM-2 follow-up. Control characters are refused on every path that stores a federated
/// identity, not only on the one that states it directly: an identity-provider assertion
/// and an import row reach the same store fields. The check lives in the store, so the three
/// writers cannot drift. Production's refusal shape for this input is unobserved.
#[test]
fn federated_identities_reject_control_characters_from_every_writer() {
    let s = state();
    // 1. A sign-in assertion whose profile claims carry a control character.
    let assertion = json!({
        "sub": "ctrl-1",
        "email": "ctrl@example.com",
        "name": "na\u{0000}me",
        "email_verified": true
    });
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=google.com&id_token={}", percent(&assertion.to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : displayName must not contain control characters"
    );
    // Nothing was created for the refused assertion.
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"federatedUserId": [{"providerId": "google.com", "rawId": "ctrl-1"}]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert!(lookup.get("users").is_none(), "{lookup}");

    // 2. The same assertion without the control character signs in, and a later assertion
    // that carries one does not overwrite the stored profile.
    let clean = json!({
        "sub": "ctrl-1",
        "email": "ctrl@example.com",
        "name": "Ada",
        "email_verified": true
    });
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=google.com&id_token={}", percent(&clean.to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 200, "{signed}");
    let local_id = signed["localId"].as_str().unwrap().to_owned();
    let dirty = json!({
        "sub": "ctrl-1",
        "email": "ctrl@example.com",
        "picture": "https://p.example/a.png\u{0007}",
        "email_verified": true
    });
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=google.com&id_token={}", percent(&dirty.to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : photoUrl must not contain control characters"
    );
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [local_id]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"][0]["displayName"], "Ada");

    // 3. An import row carrying one is refused by index, and the neighbouring row lands.
    let (status, imported) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:batchCreate"),
        &json!({"users": [
            {
                "localId": "import-ctrl",
                "providerUserInfo": [{"providerId": "github.com", "rawId": "gh-ctrl", "displayName": "gh\u{0001}user"}]
            },
            {
                "localId": "import-clean",
                "providerUserInfo": [{"providerId": "github.com", "rawId": "gh-clean", "displayName": "Grace"}]
            }
        ]}),
    );
    assert_eq!(status, 200, "{imported}");
    assert_eq!(imported["error"].as_array().map(Vec::len), Some(1));
    assert_eq!(imported["error"][0]["index"], 0);
    let store = s.store.lock().unwrap();
    assert!(store.user_by_id("import-ctrl").is_none());
    assert!(store.user_by_id("import-clean").is_some());
}

/// ITKM-2 follow-up. A second factor's display name is stored text like any other, so the
/// same rule applies at every writer: phone enrollment, the Admin enrollment list and an
/// import row. Documented behavior; production's refusal shape for this input is unobserved.
#[test]
#[allow(clippy::too_many_lines)]
fn second_factor_display_names_reject_control_characters_from_every_writer() {
    let s = state();
    let user = sign_up(&s, "factor-ctrl@example.com");
    let local_id = user["localId"].as_str().unwrap().to_owned();
    let id_token = user["idToken"].as_str().unwrap().to_owned();
    verify_email(&s, &local_id);

    // 1. Phone enrollment through the end-user route.
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
    let (status, refused) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "displayName": "my\u{0000}phone", "phoneVerificationInfo": {"sessionInfo": session, "code": code}}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : displayName must not contain control characters"
    );
    // Nothing was enrolled.
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [local_id.clone()]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert!(lookup["users"][0].get("mfaInfo").is_none(), "{lookup}");

    // 2. The Admin enrollment list on account creation.
    let (status, refused) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({
            "email": "factor-admin@example.com",
            "password": "hunter22",
            "mfaInfo": [{"phoneInfo": "+15550001111", "displayName": "wo\u{0001}rk"}]
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : displayName must not contain control characters"
    );
    // The refused creation left no account behind.
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"email": ["factor-admin@example.com"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert!(lookup.get("users").is_none(), "{lookup}");

    // 3. An import row, refused by index while its neighbour lands.
    let (status, imported) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:batchCreate"),
        &json!({"users": [
            {
                "localId": "factor-import-ctrl",
                "email": "factor-import-ctrl@example.com",
                "emailVerified": true,
                "mfaInfo": [{"phoneInfo": "+15550002222", "displayName": "ph\u{001f}one", "mfaEnrollmentId": "e-1"}]
            },
            {
                "localId": "factor-import-clean",
                "email": "factor-import-clean@example.com",
                "emailVerified": true,
                "mfaInfo": [{"phoneInfo": "+15550003333", "displayName": "phone", "mfaEnrollmentId": "e-2"}]
            }
        ]}),
    );
    assert_eq!(status, 200, "{imported}");
    assert_eq!(
        imported["error"].as_array().map(Vec::len),
        Some(1),
        "{imported}"
    );
    assert_eq!(imported["error"][0]["index"], 0);
    let store = s.store.lock().unwrap();
    assert!(store.user_by_id("factor-import-ctrl").is_none());
    assert!(store.user_by_id("factor-import-clean").is_some());
    drop(store);

    // An ordinary display name still enrolls.
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
    let code = codes["verificationCodes"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, enrolled) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": id_token, "displayName": "my phone", "phoneVerificationInfo": {"sessionInfo": session, "code": code}}),
    );
    assert_eq!(status, 200, "{enrolled}");
}

/// M-2. A refused request changes nothing. Moving the control-character check into the store
/// put it after the earlier writes of the same request: custom claims are set before the
/// identity is linked, and the Admin enrollment list clears the existing factors before it
/// enrolls the new ones. Both are now validated before the first write.
#[test]
fn a_refused_control_character_leaves_the_rest_of_the_request_unapplied() {
    let s = state();
    let user = sign_up(&s, "partial@example.com");
    let local_id = user["localId"].as_str().unwrap().to_owned();

    // A claim the request must not persist when its federated identity is refused.
    let (status, refused) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({
            "localId": local_id,
            "customAttributes": "{\"admin\":true}",
            "linkProviderUserInfo": {
                "providerId": "github.com",
                "rawId": "gh-partial",
                "displayName": "gh\u{0001}user"
            }
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : displayName must not contain control characters"
    );
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [local_id.clone()]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert!(
        lookup["users"][0].get("customAttributes").is_none(),
        "the refused request must not have persisted the claim: {lookup}"
    );
    assert!(
        !lookup["users"][0]["providerUserInfo"]
            .as_array()
            .is_some_and(|providers| providers
                .iter()
                .any(|provider| provider["providerId"] == "github.com")),
        "{lookup}"
    );

    // An enrolled factor the request must not drop when a later entry is refused.
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({
            "email": "partial-factors@example.com",
            "password": "hunter22",
            "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+15550004444", "displayName": "original"}]
        }),
    );
    assert_eq!(status, 200, "{created}");
    let factor_owner = created["localId"].as_str().unwrap().to_owned();
    let (status, refused) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({
            "localId": factor_owner,
            "mfa": {"enrollments": [
                {"phoneInfo": "+15550005555", "displayName": "kept"},
                {"phoneInfo": "+15550006666", "displayName": "dro\u{0000}pped"}
            ]}
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "INVALID_ARGUMENT : displayName must not contain control characters"
    );
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [factor_owner]}),
    );
    assert_eq!(status, 200, "{lookup}");
    let factors = lookup["users"][0]["mfaInfo"]
        .as_array()
        .expect("the original factor survives");
    assert_eq!(factors.len(), 1, "{lookup}");
    assert_eq!(factors[0]["displayName"], "original");
    assert_eq!(factors[0]["phoneInfo"], "+15550004444");

    // The same invariant for the other refusal the list can hit: a list over the per-user
    // budget is refused before the existing factors are dropped.
    let over_budget: Vec<Value> = (0..6)
        .map(|n| json!({"phoneInfo": format!("+1555000{:04}", 7000 + n), "displayName": "extra"}))
        .collect();
    let (status, refused) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": factor_owner, "mfa": {"enrollments": over_budget}}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "SECOND_FACTOR_LIMIT_EXCEEDED");
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [factor_owner]}),
    );
    assert_eq!(status, 200, "{lookup}");
    let factors = lookup["users"][0]["mfaInfo"]
        .as_array()
        .expect("the original factor survives");
    assert_eq!(factors.len(), 1, "{lookup}");
    assert_eq!(factors[0]["phoneInfo"], "+15550004444");
}

/// M-2 follow-up. `enroll_phone_factor` refuses a disabled account, and that refusal came
/// after the replacement had already dropped the existing factors. Every refusal it can
/// raise is now decided before the clear, so a rejected replacement leaves the account as it
/// was.
#[test]
fn a_disabled_account_keeps_its_second_factor_when_a_replacement_is_refused() {
    let s = state();
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({
            "email": "disabled-factors@example.com",
            "password": "hunter22",
            "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+15550008888", "displayName": "original"}]
        }),
    );
    assert_eq!(status, 200, "{created}");
    let local_id = created["localId"].as_str().unwrap().to_owned();
    let (status, disabled) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": local_id, "disableUser": true}),
    );
    assert_eq!(status, 200, "{disabled}");

    let (status, refused) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({
            "localId": local_id,
            "mfa": {"enrollments": [{"phoneInfo": "+15550009999", "displayName": "replacement"}]}
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [local_id]}),
    );
    assert_eq!(status, 200, "{lookup}");
    let factors = lookup["users"][0]["mfaInfo"]
        .as_array()
        .expect("the original factor survives");
    assert_eq!(factors.len(), 1, "{lookup}");
    assert_eq!(factors[0]["phoneInfo"], "+15550008888");
    assert_eq!(factors[0]["displayName"], "original");
}

/// Creating a disabled account carries no enrollment list, so nothing is refused: the empty
/// replacement is not an enrollment and must not become one.
#[test]
fn a_disabled_account_can_be_created_without_second_factors() {
    let s = state();
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({
            "email": "disabled-plain@example.com",
            "password": "hunter22",
            "disabled": true
        }),
    );
    assert_eq!(status, 200, "{created}");
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"email": ["disabled-plain@example.com"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"][0]["disabled"], true);
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
fn allow_duplicate_emails_still_refuses_a_second_password_account() {
    let s = state();
    let config_path = format!("{EMU}/config");
    let enabled = handle_with(
        &s,
        "PATCH",
        &config_path,
        &owner(),
        &json!({"signIn": {"allowDuplicateEmails": true}}),
    );
    assert_eq!(enabled.status, 200, "{}", enabled.body);
    assert_eq!(enabled.body["signIn"]["allowDuplicateEmails"], true);

    // Sandbox recording 2026-09-23, `config/duplicate-email#sign-up-duplicate`.
    let first = sign_up(&s, "duplicate@example.com");
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "duplicate@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "EMAIL_EXISTS");
    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "duplicate@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed_in}");
    assert_eq!(
        claims(signed_in["idToken"].as_str().unwrap())["sub"],
        first["localId"]
    );
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
    registry.clear_routed().unwrap();
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
fn custom_token_claims_over_the_size_limit_are_rejected_before_account_creation() {
    let s = state();
    let claims = json!({"role": "x".repeat(995)});
    let token = custom_token_with_claims("oversized-claims", &claims);

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": token}),
    );
    assert_eq!(status, 400, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .is_some_and(|message| message.starts_with("INVALID_CUSTOM_TOKEN :")));
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("oversized-claims")
        .is_none());
}

#[test]
fn custom_token_claims_must_be_an_object() {
    let s = state();
    let claims = json!(["admin"]);
    let token = custom_token_with_claims("malformed-claims", &claims);

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": token}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "INVALID_CUSTOM_TOKEN : claims must be an object"
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("malformed-claims")
        .is_none());
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
fn custom_token_tenant_id_must_match_the_target_tenant() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer-a").unwrap();
    s.registry = Some(registry);
    let token = json!({"uid": "tenant-custom-user", "tenant_id": "customer-b"}).to_string();

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"tenantId": "customer-a", "token": token}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], "TENANT_ID_MISMATCH");
}

#[test]
fn cross_tenant_update_credentials_leave_both_namespaces_unchanged() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    for tenant in ["customer-a", "customer-b"] {
        registry.ensure_tenant("demo-app", tenant).unwrap();
    }
    s.registry = Some(registry);
    let mut tokens = Vec::new();
    for tenant in ["customer-a", "customer-b"] {
        let (status, created) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"tenantId": tenant, "email": "same@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{created}");
        tokens.push(created["idToken"].as_str().unwrap().to_owned());
    }
    let snapshot = |tenant: &str| {
        let response = handle_with(
            &s,
            "GET",
            &format!("{V1}/projects/demo-app/tenants/{tenant}/accounts:batchGet?maxResults=1000"),
            &owner(),
            &json!({}),
        );
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(response.body["users"].as_array().unwrap().len(), 1);
        response.body
    };
    let before_a = snapshot("customer-a");
    let before_b = snapshot("customer-b");
    // Local namespace safety; this does not establish production error precedence.
    for (token, destination) in [(&tokens[0], "customer-b"), (&tokens[1], "customer-a")] {
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"tenantId": destination, "idToken": token,
                "displayName": "crossed", "password": "changed-password"}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(snapshot("customer-a"), before_a);
        assert_eq!(snapshot("customer-b"), before_b);
    }
    for (token, tenant) in tokens.iter().zip(["customer-a", "customer-b"]) {
        let (status, account) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"tenantId": tenant, "idToken": token}),
        );
        assert_eq!(status, 200, "{account}");
        assert_eq!(account["users"][0]["email"], "same@example.com");
        assert_eq!(account["users"][0]["tenantId"], tenant);
    }
}

#[test]
fn cross_tenant_refresh_credentials_are_refused_without_namespace_mutation() {
    use fireemu_core_auth::store::AuthRegistry;
    use fireemu_core_session::tenancy::Tenancy;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    assert!(registry.register(
        "worker-alpha",
        AuthStore::new("worker-alpha", SplitMix64::new(7), TotpPolicy::default()),
    ));
    for tenant in ["customer-a", "customer-b"] {
        registry.ensure_tenant("worker-alpha", tenant).unwrap();
    }
    s.registry = Some(registry);
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-alpha", &[], &["worker-key".to_owned()])
        .unwrap();
    s.tenancy = Some(Arc::new(RwLock::new(tenancy)));

    let mut credentials = Vec::new();
    let mut identities = std::collections::BTreeMap::new();
    for tenant in ["customer-a", "customer-b"] {
        let (status, created) = post(
            &s,
            &format!("{V1}/accounts:signUp?key=worker-key"),
            &json!({"tenantId": tenant, "email": format!("{tenant}@example.com"), "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{created}");
        identities.insert(tenant, created["localId"].as_str().unwrap().to_owned());
        credentials.push(created["refreshToken"].as_str().unwrap().to_owned());
    }
    let snapshot = |tenant: &str| {
        let response = handle_with(
            &s,
            "GET",
            &format!("/identitytoolkit.googleapis.com/v1/projects/worker-alpha/tenants/{tenant}/accounts:batchGet?maxResults=1000"),
            &owner(),
            &json!({}),
        );
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(response.body["users"].as_array().unwrap().len(), 1);
        assert_eq!(response.body["users"][0]["localId"], identities[tenant]);
        response.body
    };
    let before_a = snapshot("customer-a");
    let before_b = snapshot("customer-b");

    for (refresh, destination) in [
        (&credentials[0], "customer-b"),
        (&credentials[1], "customer-a"),
    ] {
        let (status, refused) = post(
            &s,
            "/securetoken.googleapis.com/v1/token?key=worker-key",
            &json!({"grant_type": "refresh_token", "refresh_token": refresh, "tenantId": destination}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_REFRESH_TOKEN");
        assert_eq!(snapshot("customer-a"), before_a);
        assert_eq!(snapshot("customer-b"), before_b);
    }

    for (refresh, tenant) in credentials.iter().zip(["customer-a", "customer-b"]) {
        let (status, renewed) = post(
            &s,
            "/securetoken.googleapis.com/v1/token?key=worker-key",
            &json!({"grant_type": "refresh_token", "refresh_token": refresh, "tenantId": tenant}),
        );
        assert_eq!(status, 200, "{renewed}");
        assert_eq!(
            claims(renewed["id_token"].as_str().unwrap())["firebase"]["tenant"],
            tenant
        );
    }
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
#[allow(clippy::too_many_lines)] // Keep the tenant policy matrix and credential lifecycle together.
fn tenant_authentication_flags_cover_lookup_oob_and_password_reset() {
    use fireemu_core_auth::store::{AuthRegistry, TenantMetadata};

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    let tenant = registry
        .create_tenant(
            "demo-app",
            TenantMetadata {
                allow_password_signup: true,
                enable_email_link_signin: true,
                ..TenantMetadata::default()
            },
        )
        .unwrap();
    s.registry = Some(registry.clone());

    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": tenant, "email": "flags@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let id_token = created["idToken"].as_str().unwrap();

    let (status, issued) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"tenantId": tenant, "requestType": "PASSWORD_RESET", "email": "flags@example.com"}),
    );
    assert_eq!(status, 200, "{issued}");
    let tenant_oob_codes = format!("{EMU}/tenants/{tenant}/oobCodes");
    let codes_before = handle_with(&s, "GET", &tenant_oob_codes, &owner(), &json!({})).body;
    let reset_code = codes_before["oobCodes"][0]["oobCode"]
        .as_str()
        .unwrap()
        .to_owned();

    assert!(registry.update_tenant(
        "demo-app",
        &tenant,
        TenantMetadata {
            allow_password_signup: false,
            enable_email_link_signin: false,
            ..TenantMetadata::default()
        },
    ));
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"tenantId": tenant, "requestType": "EMAIL_SIGNIN", "email": "flags@example.com"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "OPERATION_NOT_ALLOWED");
    assert_eq!(
        handle_with(&s, "GET", &tenant_oob_codes, &owner(), &json!({})).body,
        codes_before
    );

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"tenantId": tenant, "oobCode": reset_code}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "OPERATION_NOT_ALLOWED");
    assert_eq!(
        handle_with(&s, "GET", &tenant_oob_codes, &owner(), &json!({})).body,
        codes_before
    );

    assert!(registry.update_tenant(
        "demo-app",
        &tenant,
        TenantMetadata {
            allow_password_signup: true,
            enable_email_link_signin: true,
            ..TenantMetadata::default()
        },
    ));
    let (status, verified) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"tenantId": tenant, "oobCode": reset_code}),
    );
    assert_eq!(status, 200, "{verified}");

    assert!(registry.update_tenant(
        "demo-app",
        &tenant,
        TenantMetadata {
            allow_password_signup: false,
            enable_email_link_signin: true,
            ..TenantMetadata::default()
        },
    ));
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"tenantId": tenant, "requestType": "PASSWORD_RESET", "email": "flags@example.com"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "OPERATION_NOT_ALLOWED");

    assert!(registry.update_tenant(
        "demo-app",
        &tenant,
        TenantMetadata {
            allow_password_signup: true,
            enable_email_link_signin: true,
            disable_auth: true,
            ..TenantMetadata::default()
        },
    ));
    for (path, body) in [
        (
            format!("{V1}/accounts:lookup"),
            json!({"tenantId": tenant, "idToken": id_token}),
        ),
        (
            format!("{V1}/accounts:resetPassword"),
            json!({"tenantId": tenant, "oobCode": "missing-code"}),
        ),
    ] {
        let (status, refused) = post(&s, &path, &body);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "PROJECT_DISABLED");
    }

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"tenantId": tenant, "requestType": "PASSWORD_RESET", "email": "flags@example.com"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "PROJECT_DISABLED");

    let admin_view = handle_with(
        &s,
        "GET",
        &format!("{V1}/projects/demo-app/tenants/{tenant}/accounts:batchGet"),
        &owner(),
        &json!({}),
    );
    assert_eq!(admin_view.status, 200, "{}", admin_view.body);
    assert_eq!(admin_view.body["users"].as_array().unwrap().len(), 1);
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
fn fixture_idp_refresh_token_is_returned_only_when_requested() {
    let s = state();
    let claims = json!({
        "sub": "refresh-token-subject",
        "email": "refresh-token@example.com",
        "email_verified": true
    });
    let id_token = idp_jwt(&claims);
    let post_body = format!(
        "id_token={}&providerId=oidc.local&refresh_token={}",
        id_token, "provider-refresh-token"
    );
    let base = json!({
        "requestUri": "http://localhost",
        "postBody": post_body,
        "returnSecureToken": true
    });

    let (status, without_request) = post(&s, &format!("{V1}/accounts:signInWithIdp"), &base);
    assert_eq!(status, 200, "{without_request}");
    assert!(without_request.get("oauthRefreshToken").is_none());

    let mut requested = base;
    requested["returnRefreshToken"] = json!(true);
    let (status, with_request) = post(&s, &format!("{V1}/accounts:signInWithIdp"), &requested);
    assert_eq!(status, 200, "{with_request}");
    assert_eq!(with_request["oauthRefreshToken"], "provider-refresh-token");

    let users_before_malformed = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    let mut malformed = requested;
    malformed["returnRefreshToken"] = json!("true");
    let (status, refused) = post(&s, &format!("{V1}/accounts:signInWithIdp"), &malformed);
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "INVALID_ARGUMENT");
    assert_eq!(
        format!("{:?}", s.store.lock().unwrap().users_by_creation()),
        users_before_malformed
    );
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
#[allow(clippy::too_many_lines)]
fn admin_v2_config_update_mask_is_typed_atomic_and_scoped() {
    let s = state();
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let read = || handle_with(&s, "GET", path, &owner(), &json!({}));

    let initial = handle_with(
        &s,
        "PATCH",
        &format!("{path}?updateMask=signIn.allowDuplicateEmails,emailPrivacyConfig.enableImprovedEmailPrivacy"),
        &owner(),
        &json!({
            "signIn": {"allowDuplicateEmails": true},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}
        }),
    );
    assert_eq!(initial.status, 200, "{}", initial.body);

    for body in [json!("wrong shape"), json!([]), Value::Null] {
        let refused = handle_with(
            &s,
            "PATCH",
            &format!("{path}?updateMask=signIn.allowDuplicateEmails"),
            &owner(),
            &body,
        );
        assert_eq!(refused.status, 400, "{body}");
        let unchanged = read();
        assert_eq!(unchanged.status, 200, "{}", unchanged.body);
        assert_eq!(unchanged.body["signIn"]["allowDuplicateEmails"], true);
        assert_eq!(
            unchanged.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
            true
        );
    }

    for (mask, body) in [
        (
            "%73ignIn%2EallowDuplicateEmails",
            json!({"signIn": {"allowDuplicateEmails": true}}),
        ),
        (
            "signIn.allowDuplicateEmails%2CemailPrivacyConfig.enableImprovedEmailPrivacy",
            json!({
                "signIn": {"allowDuplicateEmails": true},
                "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}
            }),
        ),
    ] {
        let accepted = handle_with(
            &s,
            "PATCH",
            &format!("{path}?updateMask={mask}"),
            &owner(),
            &body,
        );
        assert_eq!(accepted.status, 200, "mask={mask}: {}", accepted.body);
    }

    let outside_mask = handle_with(
        &s,
        "PATCH",
        &format!("{path}?updateMask=signIn.allowDuplicateEmails"),
        &owner(),
        &json!({
            "signIn": {"allowDuplicateEmails": false},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": "wrong type"}
        }),
    );
    assert_eq!(outside_mask.status, 400, "{}", outside_mask.body);
    assert_eq!(outside_mask.body["error"]["message"], "INVALID_ARGUMENT");
    let after_outside_mask = read();
    assert_eq!(
        after_outside_mask.status, 200,
        "{}",
        after_outside_mask.body
    );
    assert_eq!(
        after_outside_mask.body["signIn"]["allowDuplicateEmails"],
        true
    );
    assert_eq!(
        after_outside_mask.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );

    let invalid = handle_with(
        &s,
        "PATCH",
        &format!("{path}?updateMask=signIn.allowDuplicateEmails,emailPrivacyConfig.enableImprovedEmailPrivacy"),
        &owner(),
        &json!({
            "signIn": {"allowDuplicateEmails": true},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": "wrong type"}
        }),
    );
    assert_eq!(invalid.status, 400, "{}", invalid.body);
    let after_invalid = read();
    assert_eq!(after_invalid.status, 200, "{}", after_invalid.body);
    assert_eq!(after_invalid.body["signIn"]["allowDuplicateEmails"], true);
    assert_eq!(
        after_invalid.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );

    let reset = handle_with(
        &s,
        "PATCH",
        &format!("{path}?updateMask=signIn.allowDuplicateEmails,emailPrivacyConfig.enableImprovedEmailPrivacy"),
        &owner(),
        &json!({
            "signIn": {"allowDuplicateEmails": false},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": false}
        }),
    );
    assert_eq!(reset.status, 200, "{}", reset.body);
    assert_eq!(reset.body["signIn"]["allowDuplicateEmails"], false);
    assert_eq!(
        reset.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        false
    );

    let omitted_mask = handle_with(
        &s,
        "PATCH",
        path,
        &owner(),
        &json!({
            "signIn": {"allowDuplicateEmails": true}
        }),
    );
    assert_eq!(omitted_mask.status, 200, "{}", omitted_mask.body);
    assert_eq!(omitted_mask.body["signIn"]["allowDuplicateEmails"], true);
    assert_eq!(
        omitted_mask.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        false
    );

    for mask in [
        "signIn.unknown",
        "signIn.allowDuplicateEmails,signIn.allowDuplicateEmails",
        "signIn.allowDuplicateEmails,,emailPrivacyConfig.enableImprovedEmailPrivacy",
        "signIn.allowDuplicateEmails%2CsignIn.allowDuplicateEmails",
        "signIn.allowDuplicateEmails&updateMask=emailPrivacyConfig.enableImprovedEmailPrivacy",
        "%ZZ",
    ] {
        let refused = handle_with(
            &s,
            "PATCH",
            &format!("{path}?updateMask={mask}"),
            &owner(),
            &json!({
                "signIn": {"allowDuplicateEmails": true},
                "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}
            }),
        );
        assert_eq!(refused.status, 400, "mask={mask}: {}", refused.body);
    }
    for query in [
        "up%ZZdateMask=signIn.allowDuplicateEmails",
        "updateMask=signIn.allowDuplicateEmails%ZZ",
    ] {
        let refused = handle_with(
            &s,
            "PATCH",
            &format!("{path}?{query}"),
            &owner(),
            &json!({"signIn": {"allowDuplicateEmails": false}}),
        );
        assert_eq!(refused.status, 400, "query={query}: {}", refused.body);
    }
    let after_bad_masks = read();
    assert_eq!(after_bad_masks.status, 200, "{}", after_bad_masks.body);
    assert_eq!(after_bad_masks.body["signIn"]["allowDuplicateEmails"], true);
    assert_eq!(
        after_bad_masks.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        false
    );

    let empty = handle_with(
        &s,
        "PATCH",
        &format!("{path}?updateMask="),
        &owner(),
        &json!({
            "signIn": {"allowDuplicateEmails": true},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}
        }),
    );
    assert_eq!(empty.status, 200, "{}", empty.body);
    assert_eq!(empty.body["signIn"]["allowDuplicateEmails"], true);
    assert_eq!(
        empty.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        false
    );
}

#[test]
fn admin_v2_config_disjoint_masks_commit_without_lost_updates() {
    let mut base = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        base.store.clone(),
    ));
    base.registry = Some(registry);
    let state = Arc::new(base);
    let start = Arc::new(std::sync::Barrier::new(3));
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    std::thread::scope(|scope| {
        let left = Arc::clone(&state);
        let left_start = Arc::clone(&start);
        scope.spawn(move || {
            left_start.wait();
            handle_with(
                &left,
                "PATCH",
                &format!("{path}?updateMask=signIn.allowDuplicateEmails"),
                &owner(),
                &json!({"signIn": {"allowDuplicateEmails": true}}),
            )
        });
        let right = Arc::clone(&state);
        let right_start = Arc::clone(&start);
        scope.spawn(move || {
            right_start.wait();
            handle_with(
                &right,
                "PATCH",
                &format!("{path}?updateMask=emailPrivacyConfig.enableImprovedEmailPrivacy"),
                &owner(),
                &json!({
                    "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}
                }),
            )
        });
        start.wait();
    });
    let result = handle_with(&state, "GET", path, &owner(), &json!({}));
    assert_eq!(result.status, 200, "{}", result.body);
    assert_eq!(result.body["signIn"]["allowDuplicateEmails"], true);
    assert_eq!(
        result.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );
}

#[test]
fn admin_v2_config_empty_mask_does_not_revert_a_concurrent_update() {
    let state = Arc::new(state());
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let start = Arc::new(std::sync::Barrier::new(3));
    std::thread::scope(|scope| {
        let update_state = Arc::clone(&state);
        let update_start = Arc::clone(&start);
        scope.spawn(move || {
            update_start.wait();
            handle_with(
                &update_state,
                "PATCH",
                &format!("{path}?updateMask=signIn.allowDuplicateEmails"),
                &owner(),
                &json!({"signIn": {"allowDuplicateEmails": true}}),
            )
        });
        let empty_state = Arc::clone(&state);
        let empty_start = Arc::clone(&start);
        scope.spawn(move || {
            empty_start.wait();
            handle_with(
                &empty_state,
                "PATCH",
                &format!("{path}?updateMask="),
                &owner(),
                &json!({"signIn": {"allowDuplicateEmails": false}}),
            )
        });
        start.wait();
    });
    let result = handle_with(&state, "GET", path, &owner(), &json!({}));
    assert_eq!(result.status, 200, "{}", result.body);
    assert_eq!(result.body["signIn"]["allowDuplicateEmails"], true);
}

#[test]
fn admin_v2_config_racing_tenant_publication_keeps_inherited_config_current() {
    let mut base = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        base.store.clone(),
    ));
    base.registry = Some(registry.clone());
    let state = Arc::new(base);
    let start = Arc::new(std::sync::Barrier::new(3));
    let config_path =
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=emailPrivacyConfig.enableImprovedEmailPrivacy";
    let tenants_path = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants";
    std::thread::scope(|scope| {
        let config_state = Arc::clone(&state);
        let config_start = Arc::clone(&start);
        scope.spawn(move || {
            config_start.wait();
            handle_with(
                &config_state,
                "PATCH",
                config_path,
                &owner(),
                &json!({
                    "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}
                }),
            )
        });
        let tenant_state = Arc::clone(&state);
        let tenant_start = Arc::clone(&start);
        scope.spawn(move || {
            tenant_start.wait();
            handle_with(
                &tenant_state,
                "POST",
                tenants_path,
                &owner(),
                &json!({"displayName": "racing tenant"}),
            )
        });
        start.wait();
    });
    assert!(registry.tenants("demo-app").iter().any(|tenant| {
        registry
            .tenant_store("demo-app", tenant)
            .and_then(|store| store.lock().ok().map(|store| store.config()))
            .is_some_and(|config| config.enable_improved_email_privacy)
    }));
}

#[test]
fn admin_v2_tenant_create_does_not_reset_omitted_inherited_config() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut base = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", base.store.clone()));
    base.registry = Some(registry.clone());
    let state = base;
    let config_path =
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=emailPrivacyConfig.enableImprovedEmailPrivacy,client.permissions.disabledUserSignup";
    let enabled = handle_with(
        &state,
        "PATCH",
        config_path,
        &owner(),
        &json!({
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true},
            "client": {"permissions": {"disabledUserSignup": true}}
        }),
    );
    assert_eq!(enabled.status, 200, "{}", enabled.body);

    let created = handle_with(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants",
        &owner(),
        &json!({"displayName": "inherited config tenant"}),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    assert_eq!(
        created.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );
    assert_eq!(
        created.body["client"]["permissions"]["disabledUserSignup"],
        true
    );
    let tenant = created.body["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    assert!(registry
        .tenant_store("demo-app", tenant)
        .and_then(|store| store.lock().ok().map(|store| store.config()))
        .is_some_and(|config| {
            config.enable_improved_email_privacy && config.disabled_user_signup
        }));
    assert!(registry
        .tenant_metadata("demo-app", tenant)
        .is_some_and(|metadata| {
            metadata.enable_improved_email_privacy && metadata.disabled_user_signup
        }));
    let read = handle_with(
        &state,
        "GET",
        &format!("/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/{tenant}"),
        &owner(),
        &json!({}),
    );
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(
        read.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );
    assert_eq!(
        read.body["client"]["permissions"]["disabledUserSignup"],
        true
    );

    let explicit_false = handle_with(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants",
        &owner(),
        &json!({
            "client": {"permissions": {"disabledUserSignup": false}},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": false}
        }),
    );
    assert_eq!(explicit_false.status, 200, "{}", explicit_false.body);
    assert_eq!(
        explicit_false.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        false
    );
    assert_eq!(
        explicit_false.body["client"]["permissions"]["disabledUserSignup"],
        false
    );
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
    assert_eq!(
        rejected["error"]["message"],
        "OPERATION_NOT_ALLOWED : Please verify the new email before changing email."
    );
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

/// ITKM-1. The photo URL is injected into a CSS `url('...')` string, so HTML escaping alone
/// does not contain it: the HTML parser turns `&#39;` back into `'` before the CSS parser
/// sees the attribute, which closes the string and lets the account declare its own style.
#[test]
fn the_idp_widget_escapes_a_photo_url_for_its_css_string_context() {
    use fireemu_adapter_http::identity_toolkit::widget;
    let s = state();
    let photo = "https://p.example/a.png'); display: none; background-image: url('x";
    let oidc = json!({"sub": "css-1", "email": "css@example.com", "picture": photo, "email_verified": true});
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithIdp"),
        &json!({"postBody": format!("providerId=oidc.corp&id_token={}", percent(&oidc.to_string())), "requestUri": DUMMY_URI}),
    );
    assert_eq!(status, 200, "{signed}");
    let rendered = widget::render(
        &s,
        "/emulator/auth/handler",
        Some("apiKey=fake-api-key&providerId=oidc.corp"),
    );
    assert_eq!(rendered.status, 200);
    // Neither a raw quote nor an HTML character reference that decodes to one survives in
    // the style attribute: the quote is a CSS escape.
    let style = rendered
        .body
        .split("style=\"background-image: url('")
        .nth(1)
        .expect("the account renders its photo")
        .split("')\"")
        .next()
        .expect("the CSS string is closed by the template")
        .to_owned();
    assert!(!style.contains('\''), "{style}");
    assert!(!style.contains("&#39;"), "{style}");
    assert!(style.contains("\\27"), "{style}");
    assert!(style.contains("display"), "{style}");
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
        enable_project_sms_mfa(&s);
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
        assert_eq!(
            s.store.lock().unwrap().pending_sign_in_count(),
            count - 1 + usize::from(strict)
        );
        assert_ne!(finalize_mfa(&s, &json!({"mfaPendingCredential": a["mfaPendingCredential"], "phoneVerificationInfo": phone})).0, 200);
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the stateful MFA sequence together.
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
        let mfa_session = started["phoneResponseInfo"]["sessionInfo"]
            .as_str()
            .unwrap();
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
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:signInWithPhoneNumber"),
            &mfa_code,
        );
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
            let kept = usize::from(strict);
            assert_eq!(store.pending_sign_in_count(), count - 1 + kept);
        }
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"][0]["localId"], user["localId"]);
        let (status, phone_user) = post(
            &s,
            &format!("{V1}/accounts:signInWithPhoneNumber"),
            &plain_code,
        );
        assert_eq!(status, 200, "{phone_user}");
        assert_eq!(phone_user["phoneNumber"], "+15550001111");
        assert_ne!(phone_user["localId"], user["localId"]);
        assert!(s.store.lock().unwrap().verification_codes().is_empty());
        assert_ne!(
            post(
                &s,
                &format!("{V1}/accounts:signInWithPhoneNumber"),
                &plain_code
            )
            .0,
            200
        );
        assert_ne!(
            finalize_mfa(&s, &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": mfa_code})).0,
            200
        );
    }
}

/// A verified user with one phone factor, plus closures that sign in (pending), start the
/// phone step and finalize it against the shared state.
fn pending_expiry_state(strict: bool, email: &str) -> (AuthState, Value) {
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
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(
            seconds,
        ))
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
        // Production keeps the pending credential after success (auth-mfa/sms).
        assert_eq!(
            s.store.lock().unwrap().pending_sign_in_count(),
            usize::from(strict)
        );

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
        // The pending credential of the first sign-in above is kept under production's rules.
        assert_eq!(
            s.store.lock().unwrap().pending_sign_in_count(),
            1 + usize::from(strict)
        );
        let fresh = start_phone_code(&s, &pending);
        assert_ne!(fresh["sessionInfo"], phone["sessionInfo"]);
        assert_ne!(
            finalize_phone_step(&s, &pending, &phone).0,
            200,
            "the expired code stays dead"
        );
        let (status, signed) = finalize_phone_step(&s, &pending, &fresh);
        assert_eq!(status, 200, "{signed}");
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"][0]["localId"], user["localId"]);
        // Both pending credentials of this test are kept under production's rules.
        assert_eq!(
            s.store.lock().unwrap().pending_sign_in_count(),
            2 * usize::from(strict)
        );
    }
}

#[test]
fn pending_retry_ends_when_the_pending_credential_expires() {
    use fireemu_core_auth::store::{
        OBSERVED_SMS_PENDING_START_SECONDS, PENDING_SIGN_IN_TTL_SECONDS,
    };
    // Under production's rules the SMS step starts only before the observed limit (sandbox
    // recording 2026-09-25, auth-mfa/lifetime-sms), and after the hour the swept credential is
    // unknown.
    {
        let email = "pending-lifetime@example.com";
        let (s, _) = pending_expiry_state(true, email);
        let pending = pending_login(&s, email);
        advance_clock(&s, OBSERVED_SMS_PENDING_START_SECONDS - 1);
        let phone = start_phone_code(&s, &pending);
        let (status, signed) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 200, "{signed}");
        let pending = pending_login(&s, email);
        advance_clock(&s, OBSERVED_SMS_PENDING_START_SECONDS);
        let (status, refused) = start_phone_step(&s, &pending);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(
            refused["error"]["message"],
            "INVALID_MFA_PENDING_CREDENTIAL : MFA pending credential is expired."
        );
        advance_clock(&s, PENDING_SIGN_IN_TTL_SECONDS);
        let (status, refused) = start_phone_step(&s, &pending);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_PENDING_TOKEN");
    }
    // The official emulator's rules: the pending credential's hour.
    {
        let email = "pending-lifetime@example.com";
        let (s, _) = pending_expiry_state(false, email);
        // At the pending lifetime a fresh code still finalizes; one second past it the
        // pending credential is gone, its code with it, and start is refused as well.
        let pending = pending_login(&s, email);
        advance_clock(&s, PENDING_SIGN_IN_TTL_SECONDS);
        let phone = start_phone_code(&s, &pending);
        let (status, signed) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 200, "{signed}");
        // The code is issued just before the pending credential expires, so at the request
        // it is two seconds old and valid on its own: only the pending sweep can remove it.
        let pending = pending_login(&s, email);
        advance_clock(&s, PENDING_SIGN_IN_TTL_SECONDS - 1);
        let phone = start_phone_code(&s, &pending);
        advance_clock(&s, 2);
        // Checked in the store directly: an inspection request would sweep first.
        let at = s.clock.lock().unwrap().now_for_test();
        assert!(s
            .store
            .lock()
            .unwrap()
            .check_phone_code(
                phone["sessionInfo"].as_str().unwrap(),
                phone["code"].as_str().unwrap(),
                at,
            )
            .is_ok());
        let (status, refused) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
        assert!(refused.get("idToken").is_none());
        assert!(s.store.lock().unwrap().verification_codes().is_empty());
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
        let (status, refused) = start_phone_step(&s, &pending);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(
            refused["error"]["message"],
            "INVALID_MFA_PENDING_CREDENTIAL"
        );
    }
}

#[test]
fn pending_and_sms_expiry_matrix_keeps_expiry_causes_separate() {
    use fireemu_core_auth::store::{PENDING_SIGN_IN_TTL_SECONDS, SMS_CODE_TTL_SECONDS};

    for strict in [false, true] {
        let (s, user) = pending_expiry_state(strict, "expiry-matrix-fresh@example.com");
        let pending = pending_login(&s, "expiry-matrix-fresh@example.com");
        let phone = start_phone_code(&s, &pending);
        let (status, signed) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 200, "{signed}");
        assert!(signed["idToken"].is_string());
        // Production keeps the pending credential after success (auth-mfa/sms).
        assert_eq!(
            s.store.lock().unwrap().pending_sign_in_count(),
            usize::from(strict)
        );
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"][0]["localId"], user["localId"]);

        let (s, _) = pending_expiry_state(strict, "expiry-matrix-code@example.com");
        let pending = pending_login(&s, "expiry-matrix-code@example.com");
        let phone = start_phone_code(&s, &pending);
        advance_clock(&s, SMS_CODE_TTL_SECONDS + 1);
        let (status, refused) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
        assert!(refused.get("idToken").is_none());
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 1);
        let fresh = start_phone_code(&s, &pending);
        let (status, signed) = finalize_phone_step(&s, &pending, &fresh);
        assert_eq!(status, 200, "{signed}");
        assert_eq!(
            s.store.lock().unwrap().pending_sign_in_count(),
            usize::from(strict)
        );

        let (s, _) = pending_expiry_state(strict, "expiry-matrix-pending@example.com");
        let pending = pending_login(&s, "expiry-matrix-pending@example.com");
        advance_clock(&s, PENDING_SIGN_IN_TTL_SECONDS - 1);
        if strict {
            // Production refuses the SMS step of a pending credential from about 603 seconds
            // (sandbox recording 2026-09-25, auth-mfa/lifetime-sms), so under its rules a
            // pending credential cannot outlive a code started for it.
            let (status, refused) = start_phone_step(&s, &pending);
            assert_eq!(status, 400, "{refused}");
            assert_eq!(
                refused["error"]["message"],
                "INVALID_MFA_PENDING_CREDENTIAL : MFA pending credential is expired."
            );
        } else {
            let phone = start_phone_code(&s, &pending);
            advance_clock(&s, 2);
            let at = s.clock.lock().unwrap().now_for_test();
            assert!(s
                .store
                .lock()
                .unwrap()
                .check_phone_code(
                    phone["sessionInfo"].as_str().unwrap(),
                    phone["code"].as_str().unwrap(),
                    at,
                )
                .is_ok());
            let (status, refused) = finalize_phone_step(&s, &pending, &phone);
            assert_eq!(status, 400, "{refused}");
            assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
            assert!(refused.get("idToken").is_none());
            assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
            assert!(s.store.lock().unwrap().verification_codes().is_empty());
        }

        let (s, _) = pending_expiry_state(strict, "expiry-matrix-both@example.com");
        let pending = pending_login(&s, "expiry-matrix-both@example.com");
        let phone = start_phone_code(&s, &pending);
        advance_clock(&s, PENDING_SIGN_IN_TTL_SECONDS + 1);
        let (status, refused) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_SESSION_INFO");
        assert!(refused.get("idToken").is_none());
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
        assert!(s.store.lock().unwrap().verification_codes().is_empty());
    }
}

/// GAP-AUTH-005 (auth-mfa-start-disabled, recorded and approved 2026-09-12): production
/// accepts `mfaSignIn:start` on an account disabled after its pending credential and issues
/// the code, enforcing `USER_DISABLED` at finalize; the held pending survives re-enablement.
/// This pins accept-at-start then refuse-at-finalize, so restoring the start refusal fails.
#[test]
fn pending_retry_start_is_accepted_on_a_disabled_account_and_refused_at_finalize() {
    for strict in [false, true] {
        let email = "start-disabled@example.com";
        let (s, user) = pending_expiry_state(strict, email);
        let pending = pending_login(&s, email);
        let (status, _) = admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:update"),
            &json!({"localId": user["localId"], "disableUser": true}),
        );
        assert_eq!(status, 200);
        // Start is accepted while disabled and returns a session and a code.
        let (status, started) = start_phone_step(&s, &pending);
        assert_eq!(status, 200, "{started}");
        assert!(
            started["phoneResponseInfo"]["sessionInfo"].is_string(),
            "{started}"
        );
        let phone = start_phone_code(&s, &pending);
        // Finalizing that session is refused USER_DISABLED, and issues no tokens.
        let (status, refused) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "USER_DISABLED");
        assert!(refused.get("idToken").is_none());
        // Re-enabled: the same held pending credential starts and finalizes.
        let (status, _) = admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:update"),
            &json!({"localId": user["localId"], "disableUser": false}),
        );
        assert_eq!(status, 200);
        let phone = start_phone_code(&s, &pending);
        let (status, signed) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 200, "{signed}");
        // mfaSignIn:finalize returns tokens without localId; confirm identity by lookup.
        assert!(signed["idToken"].is_string(), "{signed}");
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"][0]["localId"], user["localId"]);
    }
}

#[test]
fn pending_retry_refuses_finalize_after_the_account_is_disabled() {
    for strict in [false, true] {
        let email = "pending-disabled@example.com";
        let (s, user) = pending_expiry_state(strict, email);
        let pending = pending_login(&s, email);
        let phone = start_phone_code(&s, &pending);
        // Later than the first factor, so a refusal that wrote the current time into the
        // last sign-in would be visible below.
        advance_clock(&s, 5);
        let account = |disabled: bool| {
            let (status, updated) = admin(
                &s,
                &format!("{V1}/projects/demo-app/accounts:update"),
                &json!({"localId": user["localId"], "disableUser": disabled}),
            );
            assert_eq!(status, 200, "{updated}");
            let (status, lookup) = admin(
                &s,
                &format!("{V1}/projects/demo-app/accounts:lookup"),
                &json!({"localId": [user["localId"]]}),
            );
            assert_eq!(status, 200, "{lookup}");
            lookup["users"][0].clone()
        };
        let before = account(true);
        let count = s.store.lock().unwrap().pending_sign_in_count();
        // Finalize is refused before anything is consumed.
        let (status, refused) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "USER_DISABLED");
        assert!(refused.get("idToken").is_none());
        assert!(refused.get("refreshToken").is_none());
        // A disabled account still starts a new phone step: production accepts
        // mfaSignIn:start on a disabled account and enforces USER_DISABLED at finalize
        // (auth-mfa-start-disabled, GAP-AUTH-005). The start returns a session and issues
        // a code, but finalizing it is refused USER_DISABLED, so the sign-in cannot
        // complete while disabled.
        let (status, started) = start_phone_step(&s, &pending);
        assert_eq!(status, 200, "{started}");
        assert!(
            started["phoneResponseInfo"]["sessionInfo"].is_string(),
            "{started}"
        );
        assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count);
        let disabled_phone = start_phone_code(&s, &pending);
        let (status, refused) = finalize_phone_step(&s, &pending, &disabled_phone);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "USER_DISABLED");
        assert!(refused.get("idToken").is_none());
        // Re-enabled: the same pending credential and the original code complete the sign-in.
        let after = account(false);
        assert_eq!(after["lastLoginAt"], before["lastLoginAt"]);
        let (status, signed) = finalize_phone_step(&s, &pending, &phone);
        assert_eq!(status, 200, "{signed}");
        let (status, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(status, 200, "{lookup}");
        assert_eq!(lookup["users"][0]["localId"], user["localId"]);
        // Production keeps the pending credential after success, and with it the codes it
        // started (auth-mfa/sms#sign-in-finalize-again).
        if !strict {
            assert!(s.store.lock().unwrap().verification_codes().is_empty());
        }
        assert_eq!(
            s.store.lock().unwrap().pending_sign_in_count(),
            count - 1 + usize::from(strict)
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the stateful MFA sequence together.
fn pending_retry_refuses_totp_finalize_and_enrollment_after_the_account_is_disabled() {
    let mut s = state();
    s.totp_extension_enabled = true;
    let email = "totp-disabled@example.com";
    let user = sign_up(&s, email);
    verify_email(&s, user["localId"].as_str().unwrap());
    let enroll_start = |token: &Value| {
        let (status, enrollment) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": token, "totpEnrollmentInfo": {}}),
        );
        assert_eq!(status, 200, "{enrollment}");
        enrollment
    };
    let enroll_finalize = |token: &Value, enrollment: &Value, at: LogicalInstant| {
        let secret = base32::decode(
            enrollment["totpSessionInfo"]["sharedSecretKey"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let code = totp_at(&secret, &TotpPolicy::default().params(), at);
        post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:finalize"),
            &json!({"idToken": token, "totpVerificationInfo": {
                "sessionInfo": enrollment["totpSessionInfo"]["sessionInfo"], "verificationCode": code}}),
        )
    };
    let set_disabled = |disabled: bool| {
        let (status, updated) = admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:update"),
            &json!({"localId": user["localId"], "disableUser": disabled}),
        );
        assert_eq!(status, 200, "{updated}");
    };
    let t0 = LogicalInstant::from_unix_seconds(1_788_004_860);
    let enrollment = enroll_start(&user["idToken"]);
    let secret = base32::decode(
        enrollment["totpSessionInfo"]["sharedSecretKey"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let (status, enrolled) = enroll_finalize(&user["idToken"], &enrollment, t0);
    assert_eq!(status, 200, "{enrolled}");
    let enrollment_id = claims(enrolled["idToken"].as_str().unwrap())["firebase"]
        ["second_factor_identifier"]
        .clone();

    // Second factor pending, then disabled: the TOTP finalize has no adapter-level guard and
    // rests on the core check.
    let pending = pending_login(&s, email);
    // A phone enrollment is left unfinished before the disable (only one TOTP factor is
    // allowed per account, so the second session is a phone one).
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": enrolled["idToken"], "phoneEnrollmentInfo": {"phoneNumber": "+15559876543"}}),
    );
    assert_eq!(status, 200, "{started}");
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let unfinished = json!({"sessionInfo": started["phoneSessionInfo"]["sessionInfo"], "code": codes["verificationCodes"][0]["code"]});
    let phone_finalize = |token: &Value| {
        post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:finalize"),
            &json!({"idToken": token, "phoneVerificationInfo": unfinished}),
        )
    };
    set_disabled(true);
    let step = fireemu_core_types::time::LogicalDuration::from_seconds(30);
    let t1 = t0.checked_add(step).unwrap();
    let code = totp_at(&secret, &TotpPolicy::default().params(), t1);
    let finalize = json!({"mfaPendingCredential": pending["mfaPendingCredential"],
        "mfaEnrollmentId": enrollment_id, "totpVerificationInfo": {"verificationCode": code}});
    let (status, refused) = finalize_mfa(&s, &finalize);
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    assert!(refused.get("idToken").is_none());
    // Enrollment of a further factor is refused while disabled (the ID token check), and
    // the enrollment session started earlier cannot be finalized either.
    let (status, refused) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": enrolled["idToken"], "totpEnrollmentInfo": {}}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    let (status, refused) = phone_finalize(&enrolled["idToken"]);
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    assert_eq!(
        get(&s, &format!("{EMU}/verificationCodes")).1,
        codes,
        "the unfinished enrollment code survives"
    );
    // Re-enabled: the same pending credential and the same code complete the sign-in, and
    // the unfinished enrollment session still finalizes.
    set_disabled(false);
    s.clock.lock().unwrap().advance(step).unwrap();
    let (status, signed) = finalize_mfa(&s, &finalize);
    assert_eq!(status, 200, "{signed}");
    assert_eq!(
        claims(signed["idToken"].as_str().unwrap())["firebase"]["sign_in_second_factor"],
        "totp"
    );
    let (status, enrolled_again) = phone_finalize(&signed["idToken"]);
    assert_eq!(status, 200, "{enrolled_again}");
    assert!(s.store.lock().unwrap().verification_codes().is_empty());
}

/// A `beforeSignIn` hook during which an administrator disables the account: the live
/// store changes while the request holds no lock, as an Admin SDK call would do.
struct DisableDuringHook {
    store: Arc<Mutex<AuthStore>>,
    uid: String,
}

#[derive(Clone, Debug)]
enum HookMutation {
    Delete,
    Revoke,
    ReplaceFactor { phone: String },
}

struct MutateDuringHook {
    store: Arc<Mutex<AuthStore>>,
    uid: String,
    mutation: HookMutation,
}

impl AuthBlockingHook for MutateDuringHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if event != BlockingAuthEvent::BeforeSignIn {
            return Ok(json!({}));
        }
        let mut store = self.store.lock().unwrap();
        let uid = store.user_by_id(&self.uid).unwrap().local_id.clone();
        match &self.mutation {
            HookMutation::Delete => {
                store.delete_user_by_id(&self.uid).unwrap();
            }
            HookMutation::Revoke => {
                let now = store
                    .user(&uid)
                    .unwrap()
                    .created_at
                    .checked_add(LogicalDuration::from_seconds(2))
                    .unwrap();
                store.revoke_tokens(&uid, now).unwrap();
            }
            HookMutation::ReplaceFactor { phone } => {
                let now = store.user(&uid).unwrap().created_at;
                store
                    .set_phone_factors(
                        &uid,
                        vec![(phone.clone(), Some("replacement".to_owned()))],
                        now,
                    )
                    .unwrap();
            }
        }
        Ok(json!({}))
    }
}

impl AuthBlockingHook for DisableDuringHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if event == BlockingAuthEvent::BeforeSignIn {
            let mut store = self.store.lock().unwrap();
            let user = store.user_by_id(&self.uid).unwrap().local_id.clone();
            store.user_mut(&user).unwrap().disabled = true;
        }
        Ok(json!({}))
    }
}

#[test]
fn pending_retry_survives_a_rejecting_hook_and_honors_a_disable_during_the_hook() {
    let email = "pending-hook@example.com";
    let (mut s, user) = pending_expiry_state(false, email);
    let uid = user["localId"].as_str().unwrap().to_owned();
    let pending = pending_login(&s, email);
    let phone = start_phone_code(&s, &pending);
    advance_clock(&s, 5);
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    let count = s.store.lock().unwrap().pending_sign_in_count();
    let last_login = |s: &AuthState| {
        let (status, lookup) = admin(
            s,
            &format!("{V1}/projects/demo-app/accounts:lookup"),
            &json!({"localId": [uid]}),
        );
        assert_eq!(status, 200, "{lookup}");
        lookup["users"][0]["lastLoginAt"].clone()
    };
    let login_before = last_login(&s);

    // The hook rejects: the candidate that consumed the code is discarded, so the code and
    // the pending credential are still there for a retry.
    s.blocking = Some(Arc::new(RejectBeforeSignInHook { timeout: false }));
    let (status, refused) = finalize_phone_step(&s, &pending, &phone);
    assert_eq!(status, 503, "{refused}");
    assert!(refused.get("idToken").is_none());
    assert_eq!(get(&s, &format!("{EMU}/verificationCodes")).1, codes);
    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count);
    assert_eq!(last_login(&s), login_before);

    // The account is disabled while the hook runs: the commit re-runs the finalize on the
    // live store and refuses, and nothing is consumed or issued.
    s.blocking = Some(Arc::new(DisableDuringHook {
        store: Arc::clone(&s.store),
        uid: uid.clone(),
    }));
    let (status, refused) = finalize_phone_step(&s, &pending, &phone);
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    assert!(refused.get("idToken").is_none());
    assert!(refused.get("refreshToken").is_none());
    assert_eq!(get(&s, &format!("{EMU}/verificationCodes")).1, codes);
    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count);
    assert_eq!(last_login(&s), login_before);

    // Re-enabled with a passing hook, the same pending credential and code succeed once.
    let (status, updated) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:update"),
        &json!({"localId": uid, "disableUser": false}),
    );
    assert_eq!(status, 200, "{updated}");
    s.blocking = Some(Arc::new(PassThroughBlockingHook));
    let (status, signed) = finalize_phone_step(&s, &pending, &phone);
    assert_eq!(status, 200, "{signed}");
    // Consumption is checked before any further request could sweep for it.
    assert!(s.store.lock().unwrap().verification_codes().is_empty());
    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count - 1);
    let (status, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": signed["idToken"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"][0]["localId"], user["localId"]);
    assert_ne!(finalize_phone_step(&s, &pending, &phone).0, 200);
}

#[test]
#[allow(clippy::too_many_lines)]
fn pending_retry_observes_hook_time_delete_revoke_and_factor_changes() {
    for mutation in [
        HookMutation::Delete,
        HookMutation::Revoke,
        HookMutation::ReplaceFactor {
            phone: "+15559876544".to_owned(),
        },
    ] {
        let (mut s, user) = pending_expiry_state(false, "hook-mutation@example.com");
        let uid = user["localId"].as_str().unwrap().to_owned();
        let pending = pending_login(&s, "hook-mutation@example.com");
        let phone = start_phone_code(&s, &pending);
        let original_id_token = user["idToken"].as_str().unwrap().to_owned();
        let original_refresh_token = user["refreshToken"].as_str().unwrap().to_owned();
        assert_eq!(
            post(
                &s,
                &format!("{V1}/accounts:lookup"),
                &json!({"idToken": original_id_token.clone()})
            )
            .0,
            200,
            "the original ID token is valid before the hook mutation"
        );
        assert_eq!(
            post(
                &s,
                "/securetoken.googleapis.com/v1/token",
                &json!({
                    "grant_type": "refresh_token",
                    "refresh_token": original_refresh_token.clone()
                })
            )
            .0,
            200,
            "the original refresh token is valid before the hook mutation"
        );
        let before_codes = get(&s, &format!("{EMU}/verificationCodes")).1;
        let before_pending = s.store.lock().unwrap().pending_sign_in_count();
        if matches!(&mutation, HookMutation::Revoke) {
            // The default fixture uses the stateless refresh compatibility profile. Switch this
            // mutation to the strict profile so the same hook-time revocation also covers the
            // refresh-session cutoff without changing the documented default behavior.
            s.stateless_refresh_tokens = false;
            advance_clock(&s, 2);
        }
        s.blocking = Some(Arc::new(MutateDuringHook {
            store: Arc::clone(&s.store),
            uid: uid.clone(),
            mutation: mutation.clone(),
        }));

        let (status, response) = finalize_phone_step(&s, &pending, &phone);
        match mutation {
            HookMutation::Delete => {
                assert_ne!(status, 200, "deleted account unexpectedly issued tokens");
                assert!(response.get("idToken").is_none(), "{response}");
                assert!(response.get("refreshToken").is_none(), "{response}");
                assert!(s.store.lock().unwrap().user_by_id(&uid).is_none());
                assert_eq!(
                    s.store.lock().unwrap().pending_sign_in_count(),
                    0,
                    "deleting the account must remove its pending credential"
                );
                assert_eq!(
                    get(&s, &format!("{EMU}/verificationCodes")).1["verificationCodes"],
                    json!([]),
                    "deleting the account must remove its verification code"
                );
                assert_ne!(
                    post(
                        &s,
                        &format!("{V1}/accounts:lookup"),
                        &json!({"idToken": original_id_token})
                    )
                    .0,
                    200,
                    "an ID token from a deleted account must be rejected"
                );
                assert_ne!(
                    post(
                        &s,
                        "/securetoken.googleapis.com/v1/token",
                        &json!({
                            "grant_type": "refresh_token",
                            "refresh_token": original_refresh_token
                        })
                    )
                    .0,
                    200,
                    "a refresh token from a deleted account must be rejected"
                );
            }
            HookMutation::Revoke => {
                // Revocation invalidates prior sessions but does not block a fresh sign-in.
                // The pending MFA credential remains usable, matching the saved local and
                // production pending-revocation observations.
                assert_eq!(status, 200, "{response}");
                assert!(response["idToken"].is_string(), "{response}");
                assert!(response["refreshToken"].is_string(), "{response}");
                // This mutation runs under production's rules, which keep the pending
                // credential after success (auth-mfa/sms#sign-in-finalize-again).
                assert_eq!(
                    s.store.lock().unwrap().pending_sign_in_count(),
                    before_pending
                );
                assert_eq!(
                    get(&s, &format!("{EMU}/verificationCodes")).1["verificationCodes"],
                    json!([]),
                    "a successful finalize consumes its verification code"
                );
                assert!(
                    s.store
                        .lock()
                        .unwrap()
                        .user_by_id(&uid)
                        .unwrap()
                        .tokens_revoked
                );
                assert_ne!(
                    post(
                        &s,
                        &format!("{V1}/accounts:lookup"),
                        &json!({"idToken": original_id_token})
                    )
                    .0,
                    200,
                    "an ID token issued before revocation must be rejected"
                );
                assert_ne!(
                    post(
                        &s,
                        "/securetoken.googleapis.com/v1/token",
                        &json!({
                            "grant_type": "refresh_token",
                            "refresh_token": original_refresh_token
                        })
                    )
                    .0,
                    200,
                    "the strict refresh profile must reject a pre-revocation refresh token"
                );
            }
            HookMutation::ReplaceFactor { .. } => {
                assert_ne!(status, 200, "replaced factor unexpectedly issued tokens");
                assert!(response.get("idToken").is_none(), "{response}");
                assert!(response.get("refreshToken").is_none(), "{response}");
                assert_eq!(
                    s.store.lock().unwrap().pending_sign_in_count(),
                    before_pending,
                    "factor replacement must not consume the pending credential"
                );
                assert_eq!(
                    get(&s, &format!("{EMU}/verificationCodes")).1,
                    before_codes,
                    "factor replacement must not consume the verification code"
                );
                let store = s.store.lock().unwrap();
                assert_eq!(
                    store.user_by_id(&uid).unwrap().mfa.phone_factors()[0].phone_number,
                    "+15559876544"
                );
            }
        }
    }
}

#[test]
fn pending_retry_two_party_totp_refusal_keeps_both_pendings_and_the_owners_step() {
    let mut s = state();
    s.totp_extension_enabled = true;
    let t0 = LogicalInstant::from_unix_seconds(1_788_004_860);
    let enroll = |email: &str| {
        let user = sign_up(&s, email);
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
        let (status, enrolled) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:finalize"),
            &json!({"idToken": user["idToken"], "totpVerificationInfo": {
                "sessionInfo": enrollment["totpSessionInfo"]["sessionInfo"],
                "verificationCode": totp_at(&secret, &TotpPolicy::default().params(), t0)}}),
        );
        assert_eq!(status, 200, "{enrolled}");
        let factor = claims(enrolled["idToken"].as_str().unwrap())["firebase"]
            ["second_factor_identifier"]
            .clone();
        (user, secret, factor)
    };
    let (a, secret_a, factor_a) = enroll("totp-a@example.com");
    let (b, _, _) = enroll("totp-b@example.com");
    let pending_a = pending_login(&s, "totp-a@example.com");
    let pending_b = pending_login(&s, "totp-b@example.com");
    let b_before = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [b["localId"]]}),
    )
    .1;
    let count = s.store.lock().unwrap().pending_sign_in_count();
    let t1 = t0
        .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(30))
        .unwrap();
    s.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(30))
        .unwrap();
    let code_a = totp_at(&secret_a, &TotpPolicy::default().params(), t1);
    // B's pending credential with A's factor and A's valid code: A's factor is not on B.
    let (status, refused) = finalize_mfa(
        &s,
        &json!({"mfaPendingCredential": pending_b["mfaPendingCredential"],
            "mfaEnrollmentId": factor_a, "totpVerificationInfo": {"verificationCode": code_a}}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "MFA_ENROLLMENT_NOT_FOUND");
    assert!(refused.get("idToken").is_none());
    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count);
    // A's own pending credential accepts the very same code: the refusal did not record
    // A's step as used.
    let (status, signed) = finalize_mfa(
        &s,
        &json!({"mfaPendingCredential": pending_a["mfaPendingCredential"],
            "mfaEnrollmentId": factor_a, "totpVerificationInfo": {"verificationCode": code_a}}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), count - 1);
    let (status, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": signed["idToken"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"][0]["localId"], a["localId"]);
    // B's pending credential is intact and B is not signed in.
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [b["localId"]]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(
        lookup["users"][0]["lastLoginAt"],
        b_before["users"][0]["lastLoginAt"]
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .pending_sign_in_user(&PendingSignId_parse(&pending_b))
        .is_some());
}

#[allow(non_snake_case)]
fn PendingSignId_parse(pending: &Value) -> PendingSignInId {
    PendingSignInId::parse(pending["mfaPendingCredential"].as_str().unwrap()).unwrap()
}

#[test]
fn pending_retry_tenant_pending_credentials_do_not_cross_namespaces() {
    use fireemu_core_auth::store::AuthRegistry;
    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer-a").unwrap();
    registry.ensure_tenant("demo-app", "customer-b").unwrap();
    s.registry = Some(registry);
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/tenants/customer-a/accounts"),
        &json!({"email": "tenant-mfa@example.com", "password": "hunter22", "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+15559876543"}]}),
    );
    assert_eq!(status, 200, "{created}");
    let (status, pending) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"tenantId": "customer-a", "email": "tenant-mfa@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{pending}");
    assert!(pending.get("idToken").is_none());
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"tenantId": "customer-a", "mfaPendingCredential": pending["mfaPendingCredential"],
            "mfaEnrollmentId": pending["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {}}),
    );
    assert_eq!(status, 200, "{started}");
    let tenant_codes = || {
        get(
            &s,
            "/emulator/v1/projects/demo-app/tenants/customer-a/verificationCodes",
        )
        .1
    };
    let codes = tenant_codes();
    assert_eq!(
        codes["verificationCodes"].as_array().map(Vec::len),
        Some(1),
        "{codes}"
    );
    let phone = json!({"sessionInfo": started["phoneResponseInfo"]["sessionInfo"], "code": codes["verificationCodes"][0]["code"]});
    let tenant_store = s
        .registry
        .as_ref()
        .unwrap()
        .tenant_store("demo-app", "customer-a")
        .unwrap();
    let count = tenant_store.lock().unwrap().pending_sign_in_count();
    assert_eq!(count, 1);
    // The valid credentials of tenant A are refused in tenant B and in the default
    // namespace, and neither refusal touches tenant A's pending credential or code.
    for other in [json!("customer-b"), Value::Null] {
        let mut body = json!({"mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": phone});
        if !other.is_null() {
            body["tenantId"] = other;
        }
        let (status, refused) = finalize_mfa(&s, &body);
        assert_eq!(status, 400, "{refused}");
        // The other namespace knows neither the code nor the pending credential; the phone
        // finalizer checks the code first, so the session refusal is what is seen. The
        // production precedence between the two is unobserved and not pinned here.
        assert!(
            ["INVALID_SESSION_INFO", "INVALID_MFA_PENDING_CREDENTIAL"]
                .contains(&refused["error"]["message"].as_str().unwrap_or_default()),
            "{refused}"
        );
        assert!(refused.get("idToken").is_none());
        assert_eq!(tenant_codes(), codes);
        assert_eq!(tenant_store.lock().unwrap().pending_sign_in_count(), count);
    }
    // Tenant A still completes with the same credentials, and the token names the tenant.
    let (status, signed) = finalize_mfa(
        &s,
        &json!({"tenantId": "customer-a", "mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": phone}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(
        claims(signed["idToken"].as_str().unwrap())["firebase"]["tenant"],
        "customer-a"
    );
    assert_ne!(
        finalize_mfa(&s, &json!({"tenantId": "customer-a", "mfaPendingCredential": pending["mfaPendingCredential"], "phoneVerificationInfo": phone})).0,
        200
    );
}

#[test]
fn pending_retry_concurrent_finalizes_of_one_credential_succeed_exactly_once() {
    let email = "pending-race@example.com";
    let (s, user) = pending_expiry_state(false, email);
    let pending = pending_login(&s, email);
    let phone = start_phone_code(&s, &pending);
    let results: Vec<(u16, Value)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| finalize_phone_step(&s, &pending, &phone)))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let successes: Vec<&Value> = results
        .iter()
        .filter(|(status, _)| *status == 200)
        .map(|(_, body)| body)
        .collect();
    assert_eq!(successes.len(), 1, "{results:?}");
    assert!(results
        .iter()
        .filter(|(status, _)| *status != 200)
        .all(|(_, body)| body.get("idToken").is_none() && body.get("refreshToken").is_none()));
    let (status, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": successes[0]["idToken"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"][0]["localId"], user["localId"]);
    assert!(s.store.lock().unwrap().verification_codes().is_empty());
    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 0);
}

/// Production (recorded 2026-09-11, `tools/auth-blocking-disable`): when a `beforeSignIn`
/// function answers `disabled: true`, the same request is refused with `USER_DISABLED`
/// and no tokens are issued, for a first-factor sign-in and for an MFA finalize alike.
#[test]
fn pending_retry_hook_that_disables_the_account_refuses_the_same_request() {
    let disabling = || -> Arc<dyn AuthBlockingHook> {
        Arc::new(FixedBeforeSignInHook {
            response: json!({"userRecord": {"updateMask": "disabled", "disabled": true}}),
        })
    };
    // First factor only.
    let mut s = state();
    let user = sign_up(&s, "hook-disable@example.com");
    s.blocking = Some(disabling());
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "hook-disable@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    assert!(refused.get("idToken").is_none() && refused.get("refreshToken").is_none());
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [user["localId"]]}),
    );
    assert_eq!(status, 200, "{lookup}");
    // Production (readback timing, 2026-09-12): the flag is not persisted for a refused
    // first-factor sign-in of an existing account; the sign-in stays refused only while
    // the function is registered.
    assert_ne!(lookup["users"][0]["disabled"], true, "{lookup}");
    let (status, again) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "hook-disable@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400, "{again}");
    assert_eq!(again["error"]["message"], "USER_DISABLED");
    s.blocking = None;
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "hook-disable@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{signed}");

    // Phone MFA finalize: the hook runs after the second factor; the refusal keeps the
    // pending credential and code (pre-finalization policy) and persists the flag.
    let email = "hook-disable-mfa@example.com";
    let (mut s, user) = pending_expiry_state(false, email);
    let pending = pending_login(&s, email);
    let phone = start_phone_code(&s, &pending);
    let (_, codes) = get(&s, &format!("{EMU}/verificationCodes"));
    s.blocking = Some(disabling());
    let (status, refused) = finalize_phone_step(&s, &pending, &phone);
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    assert!(refused.get("idToken").is_none() && refused.get("refreshToken").is_none());
    assert_eq!(get(&s, &format!("{EMU}/verificationCodes")).1, codes);
    assert_eq!(s.store.lock().unwrap().pending_sign_in_count(), 1);
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [user["localId"]]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"][0]["disabled"], true);
    s.blocking = Some(Arc::new(PassThroughBlockingHook));
    assert_eq!(
        finalize_phone_step(&s, &pending, &phone).1["error"]["message"],
        "USER_DISABLED"
    );
}

/// The whole hook response persists as one record update, and an account created by the
/// very request the hook disables is kept as a disabled record without a session.
#[test]
fn pending_retry_hook_disable_persists_the_whole_response_and_created_accounts() {
    let disabling = || -> Arc<dyn AuthBlockingHook> {
        Arc::new(FixedBeforeSignInHook {
            response: json!({"userRecord": {"updateMask": "disabled", "disabled": true}}),
        })
    };
    // Claims set by the same response are on the record, not only the flag, and the
    // refused attempt records no sign-in time.
    let mut s = state();
    let user = sign_up(&s, "hook-disable-claims@example.com");
    advance_clock(&s, 5);
    let before = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [user["localId"]]}),
    )
    .1;
    s.blocking = Some(Arc::new(FixedBeforeSignInHook {
        response: json!({"userRecord": {"updateMask": "disabled,customClaims",
            "disabled": true, "customClaims": {"role": "auditor"}}}),
    }));
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "hook-disable-claims@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    let (_, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [user["localId"]]}),
    );
    // An existing account's first-factor sign-in persists none of the response: neither
    // the flag nor the claims, and no sign-in time.
    assert_ne!(lookup["users"][0]["disabled"], true, "{lookup}");
    assert_eq!(
        lookup["users"][0]["lastLoginAt"],
        before["users"][0]["lastLoginAt"]
    );
    assert!(
        lookup["users"][0].get("customAttributes").is_none(),
        "{lookup}"
    );
    s.blocking = None;
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "hook-disable-claims@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{signed}");

    // An account created by the very request the hook disables is kept, disabled, with
    // no tokens and no session (production behavior for this case is not yet observed).
    let mut s = state();
    s.blocking = Some(disabling());
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "hook-disable-new@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_DISABLED");
    assert!(refused.get("idToken").is_none() && refused.get("refreshToken").is_none());
    let (status, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"email": ["hook-disable-new@example.com"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"].as_array().map(Vec::len), Some(1));
    assert_eq!(lookup["users"][0]["disabled"], true);
    s.blocking = None;
    let (status, again) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "hook-disable-new@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400, "{again}");
    assert_eq!(again["error"]["message"], "USER_DISABLED");
}

/// Production (recorded 2026-09-12, `tools/auth-disabled-admin-update`): an administrative
/// password replacement of an already disabled account is accepted and applied but
/// returns no tokens; the account still refuses its own sign-in until re-enabled.
#[test]
fn pending_retry_admin_password_update_of_a_disabled_account_returns_no_tokens() {
    for strict in [false, true] {
        let (s, _) = oob_authorization_state(strict);
        let user = sign_up(&s, "admin-update-disabled@example.com");
        let uid = user["localId"].clone();
        let (status, disabled) = admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:update"),
            &json!({"localId": uid, "disableUser": true}),
        );
        assert_eq!(status, 200, "{disabled}");
        let (status, updated) = admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:update"),
            &json!({"localId": uid, "password": "replaced-22"}),
        );
        assert_eq!(status, 200, "{updated}");
        assert!(updated.get("idToken").is_none(), "{updated}");
        assert!(updated.get("refreshToken").is_none(), "{updated}");
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "admin-update-disabled@example.com", "password": "replaced-22"}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "USER_DISABLED");
        let (status, enabled) = admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:update"),
            &json!({"localId": uid, "disableUser": false}),
        );
        assert_eq!(status, 200, "{enabled}");
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "admin-update-disabled@example.com", "password": "replaced-22"}),
        );
        assert_eq!(status, 200, "{signed}");
        assert_eq!(signed["localId"], uid);
    }
}

/// Production (recorded and approved 2026-09-12, `tools/auth-pending-triggers`
/// admin-password-update, GAP-AUTH-004): a privileged administrative `accounts:update`
/// that changes the password returns no tokens, whether the account is enabled or
/// disabled after the update, because it acts on a `localId` with no session to re-issue
/// for. The self-service password change over a session still returns tokens (see
/// `strict_password_change_distinguishes_revoked_refresh` and the client update tests).
#[test]
fn pending_retry_admin_password_update_never_returns_tokens_regardless_of_enabled_state() {
    for strict in [false, true] {
        let (s, _) = oob_authorization_state(strict);
        let user = sign_up(&s, "admin-update-toggle@example.com");
        let uid = user["localId"].clone();
        let update = |body: Value| {
            admin(
                &s,
                &format!("{V1}/projects/demo-app/accounts:update"),
                &body,
            )
        };
        // Enabled account, then re-enabled account: neither administrative password
        // update returns tokens; sign-in still reflects the enabled/disabled state.
        let (status, response) =
            update(json!({"localId": uid, "password": "toggle-22", "disableUser": true}));
        assert_eq!(status, 200, "{response}");
        for key in ["idToken", "refreshToken", "expiresIn"] {
            assert!(response.get(key).is_none(), "{key}: {response}");
        }
        assert_eq!(
            post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": "admin-update-toggle@example.com", "password": "toggle-22"})
            )
            .1["error"]["message"],
            "USER_DISABLED"
        );
        let (status, response) =
            update(json!({"localId": uid, "password": "toggle-33", "disableUser": false}));
        assert_eq!(status, 200, "{response}");
        for key in ["idToken", "refreshToken", "expiresIn"] {
            assert!(response.get(key).is_none(), "{key}: {response}");
        }
        // Re-enabled: the account is usable again, but the update itself issued no tokens.
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "admin-update-toggle@example.com", "password": "toggle-33"}),
        );
        assert_eq!(status, 200, "{signed}");
        // A self-service password change over the session still returns tokens.
        let session = signed["idToken"].clone();
        let (status, changed) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": session, "password": "toggle-44", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{changed}");
        assert!(
            changed["idToken"].is_string() && changed["refreshToken"].is_string(),
            "{changed}"
        );
    }
}

/// Production (recorded 2026-09-12, `tools/auth-blocking-create-disable`): a `photoUrl` sent
/// with `accounts:signUp` is not persisted; it is absent on lookup and a blocking hook on
/// the creating request does not see it. fireemu keeps ignoring it.
#[test]
fn pending_retry_sign_up_does_not_persist_a_photo_url() {
    struct PhotoHook(Arc<Mutex<Vec<Option<String>>>>);
    impl AuthBlockingHook for PhotoHook {
        fn invoke(
            &self,
            event: BlockingAuthEvent,
            user: &fireemu_core_auth::store::UserRecord,
        ) -> Result<Value, BlockingFunctionFailure> {
            if event == BlockingAuthEvent::BeforeSignIn {
                self.0.lock().unwrap().push(user.photo_url.clone());
            }
            Ok(json!({}))
        }
    }
    let mut s = state();
    let seen = Arc::new(Mutex::new(Vec::new()));
    s.blocking = Some(Arc::new(PhotoHook(Arc::clone(&seen))));
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "signup-photo@example.com", "password": "hunter22",
            "displayName": "Photo", "photoUrl": "https://example.test/signup.png", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{created}");
    let (_, lookup) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [created["localId"]]}),
    );
    assert!(lookup["users"][0].get("photoUrl").is_none(), "{lookup}");
    assert_eq!(lookup["users"][0]["displayName"], "Photo");
    assert_eq!(seen.lock().unwrap().as_slice(), [None]);
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
            // Strict needs a continue URL for a sign-in link (sandbox recording 2026-09-24).
            let mut body = json!({"requestType": request_type, "email": "oob-other@example.com",
                "newEmail": "oob-new@example.com", "returnOobLink": false,
                "continueUrl": "http://localhost/"});
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
fn oob_link_flag_rejects_non_boolean_values_without_issuing_a_code() {
    for strict in [false, true] {
        let (s, lines) = oob_authorization_state(strict);
        sign_up(&s, "oob-type@example.com");
        for value in [json!("true"), json!(1), json!([]), json!({})] {
            let body = json!({
                "requestType": "PASSWORD_RESET",
                "email": "oob-type@example.com",
                "returnOobLink": value,
            });
            let before_codes = get(&s, &format!("{EMU}/oobCodes"));
            let before_notices = drain(&lines);
            let (status, response) = post(&s, &format!("{V1}/accounts:sendOobCode"), &body);
            assert_eq!(status, 400, "{response}");
            assert_eq!(
                response["error"]["message"],
                "INVALID_ARGUMENT : returnOobLink must be a boolean"
            );
            assert_eq!(get(&s, &format!("{EMU}/oobCodes")), before_codes);
            assert_eq!(drain(&lines), before_notices);
        }
    }
}

#[test]
fn oob_link_flag_type_errors_are_atomic_on_project_and_tenant_admin_routes() {
    use fireemu_core_auth::store::AuthRegistry;

    let (mut s, lines) = recording_state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer-a").unwrap();
    s.registry = Some(registry);
    let project_path = format!("{V1}/projects/demo-app/accounts:sendOobCode");
    let tenant_path = format!("{V1}/projects/demo-app/tenants/customer-a/accounts:sendOobCode");
    let project_email = "oob-project-type@example.com";
    let tenant_email = "oob-tenant-type@example.com";
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        &json!({"email": project_email, "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let (status, created) = admin(
        &s,
        &format!("{V1}/projects/demo-app/tenants/customer-a/accounts"),
        &json!({"email": tenant_email, "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    assert!(drain(&lines).is_empty());

    for (path, email) in [(project_path, project_email), (tenant_path, tenant_email)] {
        for value in [json!("true"), json!(1), json!([]), json!({})] {
            let body = json!({
                "requestType": "PASSWORD_RESET",
                "email": email,
                "returnOobLink": value,
            });
            let before_codes = get(&s, &format!("{EMU}/oobCodes"));
            let before_notices = drain(&lines);
            let (status, response) = admin(&s, &path, &body);
            assert_eq!(status, 400, "{response}");
            assert_eq!(
                response["error"]["message"],
                "INVALID_ARGUMENT : returnOobLink must be a boolean"
            );
            assert_eq!(get(&s, &format!("{EMU}/oobCodes")), before_codes);
            assert_eq!(drain(&lines), before_notices);
        }
    }
}

#[test]
fn oob_link_flag_null_keeps_client_delivery_behavior() {
    let (s, lines) = recording_state();
    sign_up(&s, "oob-null@example.com");
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({
            "requestType": "PASSWORD_RESET",
            "email": "oob-null@example.com",
            "returnOobLink": null,
        }),
    );
    assert_eq!(status, 200, "{response}");
    assert!(response.get("oobCode").is_none());
    assert!(response.get("oobLink").is_none());
    assert_eq!(
        get(&s, &format!("{EMU}/oobCodes")).1["oobCodes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(drain(&lines).len(), 1);
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
        peer_ip: None,
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

/// PCT-1. `%` followed by anything but two hexadecimal digits is not an escape. The
/// hand-rolled decoder accepted `from_str_radix` extensions, so `%+f` became U+000F and the
/// password below was refused as a control character.
#[test]
fn action_link_query_decoding_rejects_non_hexadecimal_percent_escapes() {
    let s = state();
    sign_up(&s, "percent@example.com");
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "percent@example.com"}),
    );
    assert_eq!(status, 200, "{sent}");
    let code = issued_code(&s, "PASSWORD_RESET");
    let (status, done) = follow(
        &s,
        &format!(
            "http://127.0.0.1:9099/emulator/action?mode=resetPassword&oobCode={code}&apiKey=fake-api-key&newPassword=one%+ftwo%2Gthree%zz"
        ),
    );
    assert_eq!(status, 200, "{done}");
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        // `+` is still a form-encoded space; `%` keeps its literal self.
        &json!({"email": "percent@example.com", "password": "one% ftwo%2Gthree%zz"}),
    );
    assert_eq!(status, 200, "{signed}");
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
fn action_mode_must_match_the_email_action_code_kind() {
    let s = state();
    let user = sign_up(&s, "mode-owner@example.com");
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "idToken": user["idToken"], "newEmail": "mode-new@example.com"}),
    );
    assert_eq!(status, 200);
    let code = issued_code(&s, "VERIFY_AND_CHANGE_EMAIL");
    let (status, response) = get(
        &s,
        &format!("/emulator/action?mode=verifyEmail&oobCode={code}&apiKey=fake-api-key"),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["authEmulator"]["error"],
        "Your request to verify your email has expired or the link has already been used."
    );
    assert_eq!(issued_code(&s, "VERIFY_AND_CHANGE_EMAIL"), code);
}

#[test]
fn verify_and_change_mode_rejects_a_verify_email_code_without_mutation() {
    let s = state();
    let user = sign_up(&s, "mode-verify-owner@example.com");
    let local_id = user["localId"].as_str().unwrap().to_owned();
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": user["idToken"]}),
    );
    assert_eq!(status, 200);
    let code = issued_code(&s, "VERIFY_EMAIL");
    let before = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [local_id]}),
    )
    .1;
    let (status, response) = get(
        &s,
        &format!(
            "/emulator/action?mode=verifyAndChangeEmail&oobCode={code}&apiKey=fake-api-key&continueUrl=https%3A%2F%2Fapp.example%2Fdone"
        ),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["authEmulator"]["error"],
        "Your request to change your email has expired or the link has already been used."
    );
    assert_eq!(issued_code(&s, "VERIFY_EMAIL"), code);
    let after = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [local_id]}),
    )
    .1;
    assert_eq!(after, before);
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
fn sign_in_action_rejects_a_code_owned_by_another_action_kind() {
    let s = state();
    sign_up(&s, "sign-in-kind@example.com");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "sign-in-kind@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    let code = issued_code(&s, "PASSWORD_RESET");
    let (status, response) = follow(
        &s,
        &format!(
            "http://127.0.0.1:9099/emulator/action?mode=signIn&oobCode={code}&apiKey=fake-api-key&continueUrl=https%3A%2F%2Fapp.example%2Fdone"
        ),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response,
        json!({"authEmulator": {
            "error": "Your request to sign in has expired or the link has already been used.",
            "instructions": "Try signing in again."
        }})
    );
    assert_eq!(issued_code(&s, "PASSWORD_RESET"), code);
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

/// Saved production batch ab7bd698: client selectors never select another account.
#[test]
fn broad_client_update_uses_verified_owner_and_ignores_observed_admin_fields() {
    let (s, _) = oob_authorization_state(true);
    let a = sign_up(&s, "broad-owner-a@example.com");
    let b = sign_up(&s, "broad-owner-b@example.com");
    let update = format!("{V1}/accounts:update");
    let admin_update = format!("{V1}/projects/demo-app/accounts:update");
    assert_eq!(
        admin(
            &s,
            &admin_update,
            &json!({"localId": a["localId"], "displayName": "A-original"})
        )
        .0,
        200
    );
    let (status, changed) = post(
        &s,
        &update,
        &json!({"idToken": b["idToken"], "localId": a["localId"], "emailVerified": true, "displayName": "B-self"}),
    );
    assert_eq!(status, 200, "{changed}");
    assert_eq!(changed["localId"], b["localId"]);
    assert_eq!(changed["emailVerified"], false);
    let lookup = |uid: &Value| {
        admin(
            &s,
            &format!("{V1}/projects/demo-app/accounts:lookup"),
            &json!({"localId": [uid]}),
        )
        .1["users"][0]
            .clone()
    };
    assert_eq!(lookup(&a["localId"])["displayName"], "A-original");
    assert_eq!(lookup(&b["localId"])["displayName"], "B-self");
    assert_eq!(lookup(&b["localId"])["emailVerified"], false);
    // Ignored selector must not turn a self-service password change into an Admin plan.
    let (status, changed) = post(
        &s,
        &update,
        &json!({"idToken": b["idToken"], "localId": a["localId"], "password": "replacement-22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{changed}");
    assert!(changed["idToken"].is_string() && changed["refreshToken"].is_string());
    assert_eq!(changed["localId"], b["localId"]);
    assert_eq!(
        admin(
            &s,
            &admin_update,
            &json!({"localId": a["localId"], "emailVerified": true})
        )
        .0,
        200
    );
    assert_eq!(lookup(&a["localId"])["emailVerified"], true);
}

#[test]
fn broad_client_update_failed_credentials_never_apply_regular_attributes() {
    for failure in ["invalid", "expired", "revoked", "disabled"] {
        let (s, _) = oob_authorization_state(true);
        let a = sign_up(&s, "broad-failed-a@example.com");
        let b = sign_up(&s, "broad-failed-b@example.com");
        let token = if failure == "invalid" {
            json!("invalid-token")
        } else {
            b["idToken"].clone()
        };
        if failure == "expired" {
            s.clock
                .lock()
                .unwrap()
                // Past the five-minute allowance (sandbox recording 2026-09-24).
                .advance(fireemu_core_types::time::LogicalDuration::from_seconds(
                    3901,
                ))
                .unwrap();
        } else if failure == "disabled" {
            assert_eq!(
                admin(
                    &s,
                    &format!("{V1}/projects/demo-app/accounts:update"),
                    &json!({"localId": b["localId"], "disableUser": true})
                )
                .0,
                200
            );
        } else if failure == "revoked" {
            s.clock
                .lock()
                .unwrap()
                .advance(fireemu_core_types::time::LogicalDuration::from_seconds(2))
                .unwrap();
            assert_eq!(
                admin(
                    &s,
                    &format!("{V1}/projects/demo-app/accounts:update"),
                    &json!({"localId": b["localId"], "password": "revoke-22"})
                )
                .0,
                200
            );
        }
        let (status, result) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": token, "localId": a["localId"], "emailVerified": true, "displayName": "forbidden"}),
        );
        assert_eq!(status, 400, "{failure}: {result}");
        for uid in [&a["localId"], &b["localId"]] {
            let row = admin(
                &s,
                &format!("{V1}/projects/demo-app/accounts:lookup"),
                &json!({"localId": [uid]}),
            )
            .1["users"][0]
                .clone();
            assert!(row.get("displayName").is_none(), "{failure}: {row}");
            assert_eq!(row["emailVerified"], false);
        }
    }
}

#[test]
fn broad_display_name_only_update_preserves_production_error_code() {
    let (s, _) = oob_authorization_state(true);
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"displayName": "must-not-apply"}),
    );
    assert_eq!(status, 400);
    assert_eq!(response["error"]["message"], "INVALID_REQ_TYPE");
}

#[test]
fn broad_last_refresh_tracks_successful_token_issuance_not_reads_or_failures() {
    let (mut s, _) = oob_authorization_state(true);
    let user = sign_up(&s, "mint-clock@example.com");
    let lookup = |s: &AuthState| {
        admin(
            s,
            &format!("{V1}/projects/demo-app/accounts:lookup"),
            &json!({"localId": [user["localId"]]}),
        )
        .1["users"][0]["lastRefreshAt"]
            .clone()
    };
    let expected =
        |s: &AuthState| LogicalInstant::to_rfc3339(s.clock.lock().unwrap().now()).unwrap();
    let first = lookup(&s);
    assert_eq!(first, expected(&s));
    s.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(30))
        .unwrap();
    assert_eq!(lookup(&s), first);
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "mint-clock@example.com", "password": "wrong"})
        )
        .0,
        400
    );
    assert_eq!(lookup(&s), first);
    assert_eq!(
        post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type":"refresh_token", "refresh_token":"invalid"})
        )
        .0,
        400
    );
    assert_eq!(lookup(&s), first);
    assert_eq!(
        post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type":"refresh_token", "refresh_token":user["refreshToken"]})
        )
        .0,
        200
    );
    let refreshed = lookup(&s);
    assert_eq!(refreshed, expected(&s));
    assert_ne!(refreshed, first);
    s.clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(30))
        .unwrap();
    s.blocking = Some(Arc::new(RejectBeforeSignInHook { timeout: false }));
    assert_ne!(
        post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "mint-clock@example.com", "password": "hunter22"})
        )
        .0,
        200
    );
    assert_eq!(lookup(&s), refreshed);
}

#[test]
fn broad_refresh_project_number_is_separate_from_jwt_project_identity() {
    for (project, number) in [
        ("demo-one", Some(111_111_111_111_u64)),
        ("demo-two", Some(222_222_222_222_u64)),
        ("demo-unset", None),
    ] {
        let mut s = state();
        s.stateless_refresh_tokens = false;
        let mut store = AuthStore::new(project, SplitMix64::new(8), TotpPolicy::default());
        store.set_project_number(number);
        s.store = Arc::new(Mutex::new(store));
        let user = sign_up(&s, "project-mapping@example.com");
        let (status, response) = post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type":"refresh_token", "refresh_token":user["refreshToken"]}),
        );
        assert_eq!(status, 200, "{response}");
        assert_eq!(
            response["project_id"],
            number.map_or_else(|| project.to_owned(), |n| n.to_string())
        );
        let token_claims = claims(response["id_token"].as_str().unwrap());
        assert_eq!(token_claims["aud"], project);
        assert_eq!(
            token_claims["iss"],
            format!("https://securetoken.google.com/{project}")
        );
    }
}

#[test]
fn admin_v2_config_poisoned_registry_or_tenant_refuses_without_partial_propagation() {
    for poison_membership in [false, true] {
        let mut state = state();
        let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            state.store.clone(),
        ));
        let sibling = registry.ensure_tenant("demo-app", "alpha").unwrap();
        let tenant = registry.ensure_tenant("demo-app", "zulu").unwrap();
        state.registry = Some(registry.clone());
        let poison = tenant.clone();
        assert!(std::thread::spawn(move || {
            if poison_membership {
                registry.with_existing_tenant_metadata("demo-app", "zulu", |_| {
                    panic!("poison tenant membership")
                });
            } else {
                let _guard = poison.lock().unwrap();
                panic!("poison tenant");
            }
        })
        .join()
        .is_err());
        let response = handle_with(
            &state,
            "PATCH",
            "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config",
            &owner(),
            &json!({"signIn":{"allowDuplicateEmails":true},"emailPrivacyConfig":{"enableImprovedEmailPrivacy":true}}),
        );
        assert_eq!(response.status, 500, "{}", response.body);
        for namespace in [&state.store, &sibling, &tenant] {
            assert_eq!(
                namespace
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .config(),
                fireemu_core_auth::store::ProjectAuthConfig::default()
            );
        }
    }
}

#[test]
fn routed_project_config_uses_selected_store_and_publishes_only_successful_writes() {
    for existing in [false, true] {
        let mut state = state();
        let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            state.store.clone(),
        ));
        state.registry = Some(registry.clone());
        state.allow_routed_projects = true;
        let project = "worker-config";
        if existing {
            let candidate = Arc::new(Mutex::new(registry.routed_candidate(project).unwrap()));
            assert!(matches!(
                registry.install_routed(project, candidate),
                fireemu_core_auth::store::RoutedStoreInstall::Installed(_)
            ));
        }
        let path = format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/config");
        let read = handle_with(&state, "GET", &path, &owner(), &json!({}));
        assert_eq!(read.status, 200, "{}", read.body);
        assert_eq!(registry.routed_store_for(project).is_some(), existing);
        for (mask, body, status) in [
            ("", json!({}), 200),
            ("unknown", json!({}), 400),
            (
                "signIn.allowDuplicateEmails",
                json!({"signIn":{"allowDuplicateEmails":"invalid"}}),
                400,
            ),
        ] {
            let result = handle_with(
                &state,
                "PATCH",
                &format!("{path}?updateMask={mask}"),
                &owner(),
                &body,
            );
            assert_eq!(result.status, status, "{}", result.body);
            assert_eq!(registry.routed_store_for(project).is_some(), existing);
        }
        let updated = handle_with(
            &state,
            "PATCH",
            &format!("{path}?updateMask=emailPrivacyConfig.enableImprovedEmailPrivacy"),
            &owner(),
            &json!({"emailPrivacyConfig":{"enableImprovedEmailPrivacy":true}}),
        );
        assert_eq!(updated.status, 200, "{}", updated.body);
        assert!(
            registry
                .routed_store_for(project)
                .unwrap()
                .lock()
                .unwrap()
                .config()
                .enable_improved_email_privacy
        );
        let read = handle_with(&state, "GET", &path, &owner(), &json!({}));
        assert_eq!(
            read.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
            true
        );
        assert!(
            !state
                .store
                .lock()
                .unwrap()
                .config()
                .enable_improved_email_privacy
        );
        let policy_only = handle_with(
            &state,
            "PATCH",
            &format!("{path}?updateMask=passwordPolicyConfig"),
            &owner(),
            &json!({
                "passwordPolicyConfig": {
                    "passwordPolicyEnforcementState": "ENFORCE",
                    "passwordPolicyVersions": [{
                        "customStrengthOptions": {"minPasswordLength": 12}
                    }]
                }
            }),
        );
        assert_eq!(policy_only.status, 200, "{}", policy_only.body);
        assert_eq!(
            policy_only.body["passwordPolicyConfig"]["passwordPolicyVersions"][0]
                ["customStrengthOptions"]["minPasswordLength"],
            12
        );
        let routed = registry.routed_store_for(project).unwrap();
        assert_eq!(routed.lock().unwrap().password_policy().min_length, 12);
    }
}

/// ITKM-5. Email enumeration protection hides an unknown address from every caller, the Admin
/// link generator included: production answers its request with 200 and no code (sandbox
/// recording 2026-09-24, `auth-action/generate/admin#reset-link-unknown`), as the official
/// emulator does.
#[test]
fn improved_email_privacy_hides_an_unknown_address_from_an_admin_link_generator() {
    let s = state();
    let enabled = handle_with(
        &s,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=emailPrivacyConfig",
        &owner(),
        &json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}}),
    );
    assert_eq!(enabled.status, 200, "{}", enabled.body);

    // The end-user route still answers as if a mail had been sent, and creates no code.
    let (status, hidden) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "nobody@example.com"}),
    );
    assert_eq!(status, 200, "{hidden}");
    assert_eq!(hidden["email"], "nobody@example.com");
    assert!(hidden.get("oobLink").is_none(), "{hidden}");

    let (status, hidden) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "nobody@example.com", "returnOobLink": true}),
    );
    assert_eq!(status, 200, "{hidden}");
    assert_eq!(
        hidden,
        json!({"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": "nobody@example.com"})
    );
    assert!(get(&s, &format!("{EMU}/oobCodes")).1["oobCodes"]
        .as_array()
        .is_some_and(Vec::is_empty));

    // A known address still yields the link.
    sign_up(&s, "known@example.com");
    let (status, generated) = admin(
        &s,
        &format!("{V1}/projects/demo-app/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "known@example.com", "returnOobLink": true}),
    );
    assert_eq!(status, 200, "{generated}");
    assert!(generated["oobLink"].as_str().is_some_and(|l| !l.is_empty()));
    assert!(get(&s, &format!("{EMU}/oobCodes")).1["oobCodes"]
        .as_array()
        .is_some_and(|codes| codes.len() == 1));
}

#[test]
fn routed_project_saml_uses_selected_store_for_first_and_existing_requests() {
    for existing in [false, true] {
        let mut state = state();
        let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            state.store.clone(),
        ));
        state.registry = Some(registry.clone());
        state.allow_routed_projects = true;
        let project = "worker-saml";
        if existing {
            let candidate = Arc::new(Mutex::new(registry.routed_candidate(project).unwrap()));
            assert!(matches!(
                registry.install_routed(project, candidate),
                fireemu_core_auth::store::RoutedStoreInstall::Installed(_)
            ));
        }
        let path = format!(
            "/identitytoolkit.googleapis.com/admin/v2/projects/{project}/inboundSamlConfigs"
        );
        let read = handle_with(&state, "GET", &path, &owner(), &json!({}));
        assert_eq!(read.status, 200, "{}", read.body);
        assert_eq!(registry.routed_store_for(project).is_some(), existing);
        let invalid = handle_with(
            &state,
            "POST",
            &format!("{path}?inboundSamlConfigId=saml.test"),
            &owner(),
            &json!({}),
        );
        assert_eq!(invalid.status, 400, "{}", invalid.body);
        assert_eq!(registry.routed_store_for(project).is_some(), existing);
        let created = handle_with(
            &state,
            "POST",
            &format!("{path}?inboundSamlConfigId=saml.test"),
            &owner(),
            &json!({"idpConfig":{"idpEntityId":"idp","ssoUrl":"https://idp.example.test/sso","idpCertificates":[{"x509Certificate":"test-certificate"}],"signRequest":true},"spConfig":{"spEntityId":"sp","callbackUri":"https://sp.example.test/callback"}}),
        );
        assert_eq!(created.status, 200, "{}", created.body);
        assert!(registry.routed_store_for(project).is_some());
        let patched = handle_with(
            &state,
            "PATCH",
            &format!("{path}/saml.test?updateMask=idpConfig.signRequest"),
            &owner(),
            &json!({}),
        );
        assert_eq!(patched.status, 200, "{}", patched.body);
        assert_eq!(patched.body["idpConfig"]["signRequest"], false);
        let read = handle_with(
            &state,
            "GET",
            &format!("{path}/saml.test"),
            &owner(),
            &json!({}),
        );
        assert_eq!(read.status, 200, "{}", read.body);
        assert_eq!(read.body["idpConfig"]["signRequest"], false);
        assert!(state
            .store
            .lock()
            .unwrap()
            .saml_config("saml.test")
            .is_none());
    }
}

// Process-local pendingToken contract. The fixture policy is explicit, not signed SAML.
fn continuation_state() -> AuthState {
    let mut s = state();
    s.idp_continuations =
        fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::LocalBounded;
    s
}

fn continuation_assertion(subject: &str) -> Value {
    json!({"requestUri":"http://localhost", "returnSecureToken":true,
        "postBody":format!("providerId=github.com&id_token={}",
            idp_jwt(&json!({"sub":subject, "email":format!("{subject}@example.test")})))})
}

fn resume_request(token: &Value) -> Value {
    json!({"requestUri":"http://localhost", "pendingToken":token, "returnSecureToken":true})
}

#[test]
fn pending_token_repeats_sign_in_without_creating_a_second_account_or_extending_ttl() {
    let s = continuation_state();
    let path = format!("{V1}/accounts:signInWithIdp");
    let (status, first) = post(&s, &path, &continuation_assertion("repeat"));
    assert_eq!(status, 200, "{first}");
    assert!(first["pendingToken"].is_string());
    let resume = resume_request(&first["pendingToken"]);
    let (status, next) = post(&s, &path, &resume);
    assert_eq!(status, 200, "{next}");
    assert_eq!(next["localId"], first["localId"]);
    assert_eq!(next["isNewUser"], false);
    assert_eq!(next["pendingToken"], first["pendingToken"]);
    s.clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(299))
        .unwrap();
    assert_eq!(post(&s, &path, &resume).0, 200);
    s.clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(1))
        .unwrap();
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    assert_eq!(post(&s, &path, &resume).0, 400);
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );
    assert_eq!(s.store.lock().unwrap().user_count(), 1);
}

#[test]
fn pending_token_cannot_replace_current_account_authorization_with_cached_linking_token() {
    let s = continuation_state();
    let path = format!("{V1}/accounts:signInWithIdp");
    let victim = sign_up(&s, "victim-cont@example.test");
    let outsider = sign_up(&s, "outsider-cont@example.test");
    let claims =
        json!({"sub":"not-authorized", "email":"victim-cont@example.test", "email_verified":false});
    let body = json!({"requestUri":"http://localhost", "postBody":format!("providerId=github.com&id_token={}", idp_jwt(&claims))});
    let (status, confirmation) = post(&s, &path, &body);
    assert_eq!(status, 200, "{confirmation}");
    assert_eq!(confirmation["needConfirmation"], true);
    assert!(confirmation.get("idToken").is_none());
    assert!(confirmation["pendingToken"].is_string());
    let mut resume = resume_request(&confirmation["pendingToken"]);
    let (status, again) = post(&s, &path, &resume);
    assert_eq!(status, 200);
    assert_eq!(again["needConfirmation"], true);
    assert!(again.get("idToken").is_none());
    resume["idToken"] = victim["idToken"].clone();
    let (status, linked) = post(&s, &path, &resume);
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["localId"], victim["localId"]);
    {
        let store = s.store.lock().unwrap();
        let now = s.clock.lock().unwrap().now();
        let raw = store
            .pending_idp_sign_in(
                linked["pendingToken"].as_str().unwrap(),
                "fixture-idp-v1",
                now,
            )
            .unwrap();
        let cached: Value = serde_json::from_str(raw).unwrap();
        assert!(cached.get("idToken").is_none());
        assert!(cached.get("pendingToken").is_none());
        assert!(!raw.contains(victim["idToken"].as_str().unwrap()));
    }
    // The credential belongs to this provider identity, never to a cached link session.
    resume["idToken"] = outsider["idToken"].clone();
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    let (status, refused) = post(&s, &path, &resume);
    assert_eq!(status, 400, "{refused}");
    assert!(refused.get("idToken").is_none());
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );
    resume["idToken"] = json!("invalid-link-session");
    assert_eq!(post(&s, &path, &resume).0, 400);
}

#[test]
fn pending_token_refuses_ambiguous_inputs_and_never_falls_back_to_fresh_credentials() {
    let s = continuation_state();
    let path = format!("{V1}/accounts:signInWithIdp");
    let assertion = continuation_assertion("input-shape");
    let (status, first) = post(&s, &path, &assertion);
    assert_eq!(status, 200, "{first}");
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    for token in [
        json!(""),
        json!("arbitrary"),
        json!(false),
        json!(1),
        json!([]),
        json!({}),
        json!("x".repeat(257)),
    ] {
        let mut fresh = assertion.clone();
        fresh["pendingToken"] = token;
        assert_eq!(post(&s, &path, &fresh).0, 400);
    }
    for (key, value) in [
        ("postBody", assertion["postBody"].clone()),
        ("pendingIdToken", json!("legacy")),
        ("requestUri", json!("https://different.invalid")),
        ("requestUri", Value::Null),
    ] {
        let mut body = resume_request(&first["pendingToken"]);
        body[key] = value;
        assert_eq!(post(&s, &path, &body).0, 400, "{key}");
    }
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );
}

#[test]
fn pending_token_is_local_to_project_tenant_and_current_reset_generation() {
    use fireemu_core_auth::store::{AuthRegistry, AuthSnapshot};
    let mut s = continuation_state();
    let path = format!("{V1}/accounts:signInWithIdp");
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    s.registry = Some(registry);
    let (_, signed) = post(&s, &path, &continuation_assertion("scope"));
    let request = resume_request(&signed["pendingToken"]);
    let mut tenant_request = request.clone();
    tenant_request["tenantId"] = json!("customer");
    assert_eq!(post(&s, &path, &tenant_request).0, 400);
    let snapshot = AuthSnapshot::capture(&s.store.lock().unwrap());
    snapshot.restore_into(&mut s.store.lock().unwrap());
    assert_eq!(post(&s, &path, &request).0, 400);
    let (_, fresh) = post(&s, &path, &continuation_assertion("scope"));
    assert_ne!(fresh["pendingToken"], signed["pendingToken"]);
    s.store.lock().unwrap().clear();
    assert_eq!(
        post(&s, &path, &resume_request(&fresh["pendingToken"])).0,
        400
    );
}

#[test]
fn default_fixture_mode_does_not_silently_accept_or_issue_continuations() {
    let s = state();
    let path = format!("{V1}/accounts:signInWithIdp");
    let body = continuation_assertion("legacy-shape");
    let (status, first) = post(&s, &path, &body);
    assert_eq!(status, 200, "{first}");
    assert!(first.get("pendingToken").is_none());
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    let mut forged = body;
    forged["pendingToken"] = json!("unverified");
    assert_eq!(post(&s, &path, &forged).0, 501);
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );
}

#[test]
fn replayed_assertions_still_run_current_blocking_hooks() {
    let mut s = continuation_state();
    let path = format!("{V1}/accounts:signInWithIdp");
    let (_, first) = post(&s, &path, &continuation_assertion("blocking-repeat"));
    s.blocking = Some(Arc::new(RejectBeforeSignInHook { timeout: true }));
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    let (status, response) = post(&s, &path, &resume_request(&first["pendingToken"]));
    assert_ne!(status, 200, "{response}");
    assert!(response.get("idToken").is_none());
    assert_eq!(
        before,
        format!("{:?}", s.store.lock().unwrap().users_by_creation())
    );
}

#[test]
fn local_saml_fixture_rejects_non_string_subjects_and_non_object_attributes() {
    let s = continuation_state();
    let path = format!("{V1}/accounts:signInWithIdp");
    for saml in [
        json!({"assertion":false}),
        json!({"assertion":{"subject":1}}),
        json!({"assertion":{"subject":{"nameId":false}}}),
        json!({"assertion":{"subject":{"nameId":1}}}),
        json!({"assertion":{"subject":{"nameId":[]}}}),
        json!({"assertion":{"subject":{"nameId":""}}}),
        json!({"assertion":{"subject":{"nameId":"bad\nname"}}}),
        json!({"assertion":{"subject":{"nameId":"test@example.com"}, "attributeStatements":[]}}),
    ] {
        let body = json!({"requestUri":"http://localhost", "postBody":format!(
            "providerId=saml.fixture&id_token={}&SAMLResponse={}",
            percent(&json!({"sub":"saml-sub"}).to_string()), percent(&saml.to_string()))});
        let (status, response) = post(&s, &path, &body);
        assert_eq!(status, 400, "{response}");
        assert!(response.get("pendingToken").is_none());
        assert_eq!(s.store.lock().unwrap().user_count(), 0);
    }
    let saml = json!({"assertion":{"subject":{"nameId":"test@example.com"}}});
    let body = json!({"requestUri":"http://localhost", "postBody":format!(
        "providerId=saml.fixture&id_token={}&SAMLResponse={}",
        percent(&json!({"sub":"saml-sub"}).to_string()), percent(&saml.to_string()))});
    assert_eq!(post(&s, &path, &body).0, 200);
}

#[test]
fn generated_saml_json_shape_corpus_is_executed_by_the_native_fixture_handler() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../spec/compatibility/auth-account-federation-local-v1.json"
    ))
    .unwrap();
    assert_eq!(corpus["productionAllowed"], false);
    for case in corpus["federation"]["samlFixtureCases"].as_array().unwrap() {
        let s = continuation_state();
        let request = json!({"requestUri":"http://localhost", "postBody":format!(
            "providerId=saml.fixture&id_token={}&SAMLResponse={}",
            percent(&json!({"sub":"fixture-corpus"}).to_string()), percent(&case["response"].to_string()))});
        let (status, body) = post(&s, &format!("{V1}/accounts:signInWithIdp"), &request);
        assert_eq!(json!(status), case["status"], "{}: {body}", case["id"]);
        assert_eq!(
            s.store.lock().unwrap().user_count(),
            usize::from(status == 200)
        );
        if status != 200 {
            assert!(body.get("pendingToken").is_none());
        }
    }
}

/// Switches the project's SMS second factors on: under production's rules (the strict
/// profile) an enrolled factor is asked for only while the project enables MFA.
fn enable_project_sms_mfa(s: &AuthState) {
    let r = handle_with(
        s,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=mfa",
        &owner(),
        &json!({"mfa": {"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
}

/// A routed project's store is installed by any successful kind of config update: the password
/// policy, the sign-in config, the sign-up quota and the multi-factor config each on their own
/// (mutation follow-up, docs.local/mutation/auth-mfa/20260925).
#[test]
fn routed_project_config_installs_its_store_for_each_kind_of_update() {
    for (mask, body) in [
        (
            "passwordPolicyConfig",
            json!({"passwordPolicyConfig": {"passwordPolicyEnforcementState": "ENFORCE",
                "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 12}}]}}),
        ),
        (
            "signIn.allowDuplicateEmails",
            json!({"signIn": {"allowDuplicateEmails": true}}),
        ),
        (
            "quota.signUpQuotaConfig",
            json!({"quota": {"signUpQuotaConfig": {"quota": "10", "startTime": "2026-09-25T00:00:00Z", "quotaDuration": "3600s"}}}),
        ),
        (
            "mfa",
            json!({"mfa": {"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}}),
        ),
    ] {
        let mut state = state();
        let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            state.store.clone(),
        ));
        state.registry = Some(registry.clone());
        state.allow_routed_projects = true;
        let project = "worker-config";
        let path = format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/config");
        let updated = handle_with(
            &state,
            "PATCH",
            &format!("{path}?updateMask={mask}"),
            &owner(),
            &body,
        );
        assert_eq!(updated.status, 200, "{mask}: {}", updated.body);
        assert!(registry.routed_store_for(project).is_some(), "{mask}");
    }
}
