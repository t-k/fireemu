//! Identity Toolkit flows through the pure handlers, plus one socket-level smoke test.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle, AuthBlockingHook, AuthQueryLimits, AuthState, BlockingFunctionCode,
    BlockingFunctionFailure,
};
use fireemu_adapter_http::signing::RsaSigner;
use fireemu_core_auth::base32;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_auth::totp::{totp_at, TotpParams};
use fireemu_core_functions::manifest::BlockingAuthEvent;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";

struct RecordingBlockingHook {
    events: Arc<Mutex<Vec<BlockingAuthEvent>>>,
    reject: Option<BlockingAuthEvent>,
}

struct UpdatingBlockingHook;

struct UnhandledBlockingHook;

struct BeforeSignInTimeoutHook;

struct FixtureFailureHook(BlockingFunctionFailure);

struct ClearingClaimsHook;

struct MalformedBeforeSignInHook;

type BlockingNamespaceCall = (String, Option<String>, BlockingAuthEvent);

struct NamespaceRecordingHook {
    calls: Arc<Mutex<Vec<BlockingNamespaceCall>>>,
}

struct DelayedBlockingHook {
    entered: AtomicUsize,
    active: AtomicUsize,
    limit: usize,
    release: AtomicBool,
}

struct BeforeCreateOnlyRejectingHook;

struct BeforeCreateOnlySuccessfulHook(Arc<Mutex<Vec<BlockingAuthEvent>>>);

struct DelayedHookRelease(Arc<DelayedBlockingHook>);

impl Drop for DelayedHookRelease {
    fn drop(&mut self) {
        self.0.release.store(true, Ordering::SeqCst);
    }
}

impl AuthBlockingHook for DelayedBlockingHook {
    fn request_concurrency_limit(&self) -> usize {
        self.limit
    }

    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        if active > self.limit {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return Err(BlockingFunctionFailure::unhandled());
        }
        self.entered.fetch_add(1, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(json!({}))
    }
}

impl AuthBlockingHook for BeforeCreateOnlyRejectingHook {
    fn handles(&self, event: BlockingAuthEvent) -> bool {
        event == BlockingAuthEvent::BeforeCreate
    }

    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        assert_eq!(event, BlockingAuthEvent::BeforeCreate);
        Err(BlockingFunctionFailure::from_function(
            BlockingFunctionCode::PermissionDenied,
            "new identities are disabled",
        )
        .unwrap())
    }
}

impl AuthBlockingHook for BeforeCreateOnlySuccessfulHook {
    fn handles(&self, event: BlockingAuthEvent) -> bool {
        event == BlockingAuthEvent::BeforeCreate
    }

    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        self.0.lock().unwrap().push(event);
        Ok(json!({}))
    }
}

impl AuthBlockingHook for NamespaceRecordingHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        panic!("namespace-aware dispatch must use invoke_for")
    }

    fn invoke_for(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Option<Value>, BlockingFunctionFailure> {
        self.calls
            .lock()
            .unwrap()
            .push((project.to_owned(), tenant.map(str::to_owned), event));
        Ok(Some(json!({})))
    }
}

impl AuthBlockingHook for MalformedBeforeSignInHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(match event {
            BlockingAuthEvent::BeforeCreate => json!({
                "userRecord": {
                    "updateMask": "displayName",
                    "displayName": "Must not be committed"
                }
            }),
            BlockingAuthEvent::BeforeSignIn => json!({"userRecord": []}),
        })
    }
}

impl AuthBlockingHook for ClearingClaimsHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(match event {
            BlockingAuthEvent::BeforeCreate => json!({}),
            BlockingAuthEvent::BeforeSignIn => json!({
                "userRecord": {"updateMask": "customClaims", "customClaims": {}}
            }),
        })
    }
}

impl AuthBlockingHook for UpdatingBlockingHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        match event {
            BlockingAuthEvent::BeforeCreate => Ok(json!({
                "userRecord": {
                    "updateMask": "displayName,photoUrl,emailVerified,customClaims",
                    "displayName": "Created by hook",
                    "photoUrl": "https://example.test/avatar.png",
                    "emailVerified": true,
                    "customClaims": {"plan": "pro"}
                }
            })),
            BlockingAuthEvent::BeforeSignIn => {
                assert_eq!(user.display_name.as_deref(), Some("Created by hook"));
                Ok(json!({
                    "userRecord": {
                        "updateMask": "sessionClaims",
                        "sessionClaims": {"risk": "low"}
                    }
                }))
            }
        }
    }
}

impl AuthBlockingHook for UnhandledBlockingHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Err(BlockingFunctionFailure::unhandled())
    }
}

impl AuthBlockingHook for BeforeSignInTimeoutHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        match event {
            BlockingAuthEvent::BeforeCreate => Ok(json!({})),
            BlockingAuthEvent::BeforeSignIn => Err(BlockingFunctionFailure::timeout()),
        }
    }
}

impl AuthBlockingHook for FixtureFailureHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Err(self.0.clone())
    }
}

impl AuthBlockingHook for RecordingBlockingHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        self.events.lock().unwrap().push(event);
        if self.reject == Some(event) {
            Err(BlockingFunctionFailure::from_function(
                BlockingFunctionCode::PermissionDenied,
                "denied by test",
            )
            .unwrap())
        } else {
            Ok(json!({}))
        }
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
        query_limits: AuthQueryLimits::EmulatorUnbounded,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    }
}

fn state_with_totp_extension() -> AuthState {
    AuthState {
        totp_extension_enabled: true,
        ..state()
    }
}

fn strict_state() -> AuthState {
    AuthState {
        query_limits: AuthQueryLimits::ProductionBounded,
        stateless_refresh_tokens: false,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Reject,
        ..state()
    }
}

fn post(state: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let r = handle(state, "POST", path, body);
    (r.status, r.body)
}

#[test]
fn blocking_auth_rejection_rolls_back_user_creation() {
    let mut s = state();
    let events = Arc::new(Mutex::new(Vec::new()));
    s.blocking = Some(Arc::new(RecordingBlockingHook {
        events: events.clone(),
        reject: Some(BlockingAuthEvent::BeforeCreate),
    }));

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "blocked@example.com", "password": "hunter22"}),
    );

    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "BLOCKING_FUNCTION_ERROR_RESPONSE : HTTP Cloud Function returned an error. Code: 403, Status: \"PERMISSION_DENIED\", Message: \"denied by test\""
    );
    assert_eq!(
        *events.lock().unwrap(),
        vec![BlockingAuthEvent::BeforeCreate]
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("blocked@example.com")
        .is_none());
}

#[test]
fn unhandled_blocking_auth_failure_is_unavailable_and_rolls_back_creation() {
    let mut s = state();
    s.blocking = Some(Arc::new(UnhandledBlockingHook));

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "unavailable@example.com", "password": "hunter22"}),
    );

    assert_eq!(status, 503, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .is_some_and(|message| message.starts_with("BLOCKING_FUNCTION_ERROR_RESPONSE")));
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("unavailable@example.com")
        .is_none());
}

#[test]
fn blocking_before_sign_in_timeout_issues_no_token_and_preserves_the_user() {
    let mut s = state();
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "timeout@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let before = s
        .store
        .lock()
        .unwrap()
        .user_by_email("timeout@example.com")
        .unwrap()
        .clone();
    s.blocking = Some(Arc::new(BeforeSignInTimeoutHook));

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "timeout@example.com", "password": "hunter22"}),
    );

    assert_eq!(status, 503, "{body}");
    assert_eq!(body["error"]["message"], "Error code: 47");
    assert!(body.get("idToken").is_none(), "{body}");
    assert!(body.get("refreshToken").is_none(), "{body}");
    assert_eq!(
        s.store
            .lock()
            .unwrap()
            .user_by_email("timeout@example.com")
            .unwrap(),
        &before
    );
}

#[test]
fn production_blocking_failure_fixture_matches_identity_toolkit() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../conformance/fixtures/auth/blocking-function-error-status.json"
    ))
    .unwrap();
    let failures = [
        BlockingFunctionFailure::from_function(
            BlockingFunctionCode::PermissionDenied,
            "Registration rejected",
        )
        .unwrap(),
        BlockingFunctionFailure::unhandled(),
        BlockingFunctionFailure::timeout(),
    ];
    let steps = fixture["steps"].as_array().unwrap();
    assert_eq!(steps.len(), failures.len());
    for (step, failure) in steps.iter().zip(failures) {
        let expected = &step["value"];
        let mut s = state();
        s.blocking = Some(Arc::new(FixtureFailureHook(failure)));
        let email = format!("{}@example.com", step["id"].as_str().unwrap());
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": email, "password": "hunter22"}),
        );
        assert_eq!(
            status,
            u16::try_from(expected["status"].as_u64().unwrap()).unwrap(),
            "{step}"
        );
        let message = body["error"]["message"].as_str().unwrap();
        if let Some(expected_message) = expected.get("message").and_then(Value::as_str) {
            assert_eq!(message, expected_message, "{step}");
        }
        for marker in expected["messageContains"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            assert!(message.contains(marker), "{message}");
        }
        for marker in expected["messageExcludes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            assert!(!message.contains(marker), "{message}");
        }
        assert!(s.store.lock().unwrap().user_by_email(&email).is_none());
    }
}

#[test]
fn blocking_auth_malformed_before_sign_in_rolls_back_user_creation() {
    let mut s = state();
    s.blocking = Some(Arc::new(MalformedBeforeSignInHook));

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "malformed@example.com", "password": "hunter22"}),
    );

    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"]["message"],
        "BLOCKING_FUNCTION_ERROR_RESPONSE : ((Response userRecord must be an object.))"
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("malformed@example.com")
        .is_none());
}

#[test]
fn blocking_auth_runs_before_create_then_before_sign_in() {
    let mut s = state();
    let events = Arc::new(Mutex::new(Vec::new()));
    s.blocking = Some(Arc::new(RecordingBlockingHook {
        events: events.clone(),
        reject: None,
    }));

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "allowed@example.com", "password": "hunter22"}),
    );

    assert_eq!(status, 200, "{body}");
    assert!(
        body.get("emailVerified").is_none(),
        "blocking hooks must not change the official signUp response shape: {body}"
    );
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            BlockingAuthEvent::BeforeCreate,
            BlockingAuthEvent::BeforeSignIn
        ]
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("allowed@example.com")
        .is_some());
}

#[test]
fn blocking_auth_applies_user_and_session_claim_updates_before_issuing_tokens() {
    let mut s = state();
    let signer = RsaSigner::from_seed(44).unwrap();
    s.store.lock().unwrap().set_signer(signer.clone());
    s.blocking = Some(Arc::new(UpdatingBlockingHook));

    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "updated@example.com", "password": "hunter22"}),
    );

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["displayName"], "Created by hook");
    let claims = fireemu_core_auth::jwt::decode_token(
        body["idToken"].as_str().unwrap(),
        Some(signer.as_ref()),
    )
    .unwrap()
    .payload;
    assert_eq!(
        claims
            .get("name")
            .and_then(fireemu_core_types::json::JsonValue::as_str),
        Some("Created by hook")
    );
    assert_eq!(
        claims
            .get("email_verified")
            .and_then(fireemu_core_types::json::JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        claims
            .get("plan")
            .and_then(fireemu_core_types::json::JsonValue::as_str),
        Some("pro")
    );
    assert_eq!(
        claims
            .get("risk")
            .and_then(fireemu_core_types::json::JsonValue::as_str),
        Some("low")
    );
    let refresh = body["refreshToken"].as_str().unwrap();
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{refreshed}");
    let refreshed_claims = fireemu_core_auth::jwt::decode_token(
        refreshed["id_token"].as_str().unwrap(),
        Some(signer.as_ref()),
    )
    .unwrap()
    .payload;
    assert_eq!(
        refreshed_claims
            .get("risk")
            .and_then(fireemu_core_types::json::JsonValue::as_str),
        Some("low")
    );
    let store = s.store.lock().unwrap();
    let user = store.user_by_email("updated@example.com").unwrap();
    assert_eq!(user.display_name.as_deref(), Some("Created by hook"));
    assert_eq!(
        user.photo_url.as_deref(),
        Some("https://example.test/avatar.png")
    );
    assert!(user.email_verified);
    assert_eq!(
        user.custom_claims.get("plan"),
        Some(&fireemu_core_auth::claims::ClaimValue::String(
            "pro".to_owned()
        ))
    );
    assert!(user.custom_claims.get("risk").is_none());
}

#[test]
fn blocking_auth_does_not_reissue_a_removed_persistent_claim() {
    let mut s = state();
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "claims@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let uid = created["localId"].as_str().unwrap();
    let mut store = s.store.lock().unwrap();
    let uid = store.user_by_id(uid).unwrap().local_id.clone();
    store
        .set_custom_claims(
            &uid,
            fireemu_core_auth::claims::CustomClaims::parse_attributes("{\"admin\":true}").unwrap(),
        )
        .unwrap();
    drop(store);
    s.blocking = Some(Arc::new(ClearingClaimsHook));

    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "claims@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{signed_in}");
    let claims =
        fireemu_core_auth::jwt::decode_unsigned(signed_in["idToken"].as_str().unwrap()).unwrap();
    assert!(claims.payload.get("admin").is_none());
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
    assert!(
        body.get("emailVerified").is_none(),
        "the official signUp response omits account verification state: {body}"
    );
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
fn totp_enrollment_matches_the_official_emulator_unless_the_extension_is_enabled() {
    let s = state();
    let (_, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "totp-default@example.com", "password": "hunter22"}),
    );

    let (status, rejected) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": signed_up["idToken"], "totpEnrollmentInfo": {}}),
    );

    assert_eq!(status, 400, "{rejected}");
    assert_eq!(
        rejected["error"]["message"],
        "INVALID_ARGUMENT : ((Missing phoneEnrollmentInfo.))"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn totp_enrollment_and_second_factor_sign_in_on_the_virtual_clock() {
    let s = state_with_totp_extension();
    let (_, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let id_token = body["idToken"].as_str().unwrap().to_owned();
    let uid = body["localId"].as_str().unwrap().to_owned();
    let (status, verified) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "emailVerified": true}),
    );
    assert_eq!(status, 200, "{verified}");

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
    // The finalize response carries only the tokens (measured against the pinned official
    // emulator); the enrollment id is read from the second-factor claim.
    let enrollment_id = decoded
        .payload
        .get("firebase")
        .and_then(|f| f.get("second_factor_identifier"))
        .and_then(|v| v.as_str())
        .unwrap()
        .to_owned();

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
    let wrong = (code + 1) % 1_000_000;
    let (status, missing_id) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential2, "totpVerificationInfo": {"verificationCode": format!("{wrong:06}")}}),
    );
    assert_eq!(status, 400);
    assert!(missing_id["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("MISSING_MFA_ENROLLMENT_ID"));
    let (status, unknown_id) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential2, "mfaEnrollmentId": "not-enrolled", "totpVerificationInfo": {"verificationCode": format!("{code:06}")}}),
    );
    assert_eq!(status, 400);
    assert_eq!(unknown_id["error"]["message"], "MFA_ENROLLMENT_NOT_FOUND");
    let (status, bad) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential2, "mfaEnrollmentId": enrollment_id, "totpVerificationInfo": {"verificationCode": format!("{wrong:06}")}}),
    );
    assert_eq!(status, 400);
    assert_eq!(bad["error"]["message"], "INVALID_CODE");
    let next = advance(&s, 30);
    let next_code = totp_at(&secret, &params, next);
    let (status, signed2) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential2, "mfaEnrollmentId": enrollment_id, "totpVerificationInfo": {"verificationCode": format!("{next_code:06}")}}),
    );
    assert_eq!(status, 200, "{signed2}");

    let (_, pending3) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let credential3 = pending3["mfaPendingCredential"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, replay) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential3, "mfaEnrollmentId": enrollment_id, "totpVerificationInfo": {"verificationCode": format!("{next_code:06}")}}),
    );
    assert_eq!(status, 400);
    assert!(replay["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("INVALID_CODE"));
    let following = advance(&s, 30);
    let (status, signed3) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": credential3, "mfaEnrollmentId": enrollment_id, "totpVerificationInfo": {"verificationCode": format!("{:06}", totp_at(&secret, &params, following))}}),
    );
    assert_eq!(status, 200, "{signed3}");

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
    let s = state_with_totp_extension();
    let (_, body) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    let id_token = body["idToken"].as_str().unwrap().to_owned();
    let uid = body["localId"].as_str().unwrap().to_owned();
    let (status, verified) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "emailVerified": true}),
    );
    assert_eq!(status, 200, "{verified}");
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

#[tokio::test]
async fn auth_root_is_a_bounded_readiness_route() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn request(addr: std::net::SocketAddr, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(fireemu_adapter_http::server::serve(
        listener,
        Arc::new(state()),
    ));

    let ready = request(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");
    assert!(ready.contains("cache-control: no-store"), "{ready}");

    let unknown = request(
        addr,
        "GET /unknown HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");
    let unknown_method = request(
        addr,
        "POST /identitytoolkit.googleapis.com/v1/accounts:definitelyNotAMethod HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    ).await;
    assert!(
        unknown_method.starts_with("HTTP/1.1 404"),
        "{unknown_method}"
    );
    assert!(
        unknown_method.contains("content-type: text/html"),
        "{unknown_method}"
    );
    let (_, body) = unknown_method.split_once("\r\n\r\n").unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(body).is_err());
    let api_missing = request(
        addr,
        "POST /v1/projects/demo-app/apps/missing:exchangeDebugToken HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    ).await;
    assert!(api_missing.starts_with("HTTP/1.1 404"), "{api_missing}");
    assert!(
        api_missing.contains("content-type: application/json"),
        "{api_missing}"
    );
    let (_, body) = api_missing.split_once("\r\n\r\n").unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(body).is_ok());

    let foreign = request(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");
    server.abort();
}

#[test]
#[allow(clippy::too_many_lines)]
fn delayed_blocking_auth_requests_do_not_exhaust_tokio_workers() {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::{Duration, Instant};

    fn request(addr: SocketAddr, request: &str, timeout: Duration) -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    fn signup_request(email: &str) -> String {
        let body = json!({"email": email, "password": "hunter22"}).to_string();
        format!(
            "POST {V1}/accounts:signUp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let hook = Arc::new(DelayedBlockingHook {
        entered: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        limit: 2,
        release: AtomicBool::new(false),
    });
    let _release = DelayedHookRelease(hook.clone());
    let mut auth = state();
    auth.blocking = Some(hook.clone());
    let store = auth.store.clone();
    let server = runtime.spawn(fireemu_adapter_http::server::serve(
        listener,
        Arc::new(auth),
    ));

    let first = std::thread::spawn(move || {
        request(
            addr,
            &signup_request("first@example.test"),
            Duration::from_secs(2),
        )
    });
    let entered_deadline = Instant::now() + Duration::from_secs(1);
    while hook.entered.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < entered_deadline,
            "the first request did not enter the blocking hook"
        );
        std::thread::yield_now();
    }

    let (written_tx, written_rx) = std::sync::mpsc::sync_channel(1);
    let second = std::thread::spawn(move || {
        let request = signup_request("second@example.test");
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        written_tx.send(()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).map(|_| response)
    });
    written_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(25));

    let overloaded = request(
        addr,
        &signup_request("overloaded@example.test"),
        Duration::from_millis(100),
    );

    let readiness = request(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        Duration::from_millis(100),
    );
    let lookup = request(
        addr,
        &format!(
            "POST {V1}/accounts:lookup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
        Duration::from_millis(100),
    );

    hook.release.store(true, Ordering::SeqCst);
    let first = first.join().unwrap().unwrap();
    let second = second.join().unwrap().unwrap();
    server.abort();
    runtime.block_on(async {
        let _ = server.await;
    });

    let readiness = readiness.expect("readiness must remain responsive during blocking hooks");
    assert!(readiness.starts_with("HTTP/1.1 200"), "{readiness}");
    let lookup = lookup.expect("non-hooking Auth routes must remain responsive");
    assert!(lookup.starts_with("HTTP/1.1 400"), "{lookup}");
    let overloaded = overloaded.expect("surplus Blocking Auth work must fail immediately");
    assert!(overloaded.starts_with("HTTP/1.1 503"), "{overloaded}");
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    assert!(second.starts_with("HTTP/1.1 200"), "{second}");
    let store = store.lock().unwrap();
    assert!(store.user_by_email("first@example.test").is_some());
    assert!(store.user_by_email("second@example.test").is_some());
}

#[test]
fn a_disconnected_blocking_request_retains_its_ingress_slot_until_the_hook_finishes() {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::{Duration, Instant};

    fn request(addr: SocketAddr, request: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    fn signup_request(email: &str) -> String {
        let body = json!({"email": email, "password": "hunter22"}).to_string();
        format!(
            "POST {V1}/accounts:signUp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let hook = Arc::new(DelayedBlockingHook {
        entered: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        limit: 1,
        release: AtomicBool::new(false),
    });
    let _release = DelayedHookRelease(hook.clone());
    let mut auth = state();
    auth.blocking = Some(hook.clone());
    let store = auth.store.clone();
    let server = runtime.spawn(fireemu_adapter_http::server::serve(
        listener,
        Arc::new(auth),
    ));

    let mut abandoned = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    abandoned
        .write_all(signup_request("disconnected@example.test").as_bytes())
        .unwrap();
    let entered_deadline = Instant::now() + Duration::from_secs(1);
    while hook.entered.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < entered_deadline,
            "the disconnected request did not enter the blocking hook"
        );
        std::thread::yield_now();
    }
    drop(abandoned);

    let overloaded = request(addr, &signup_request("overloaded@example.test")).unwrap();
    assert!(overloaded.starts_with("HTTP/1.1 503"), "{overloaded}");
    assert!(store
        .lock()
        .unwrap()
        .user_by_email("overloaded@example.test")
        .is_none());

    hook.release.store(true, Ordering::SeqCst);
    let completion_deadline = Instant::now() + Duration::from_secs(1);
    while hook.active.load(Ordering::SeqCst) != 0 {
        assert!(
            Instant::now() < completion_deadline,
            "the disconnected hook did not release its slot"
        );
        std::thread::yield_now();
    }
    let admitted = loop {
        let response = request(addr, &signup_request("readmitted@example.test")).unwrap();
        if response.starts_with("HTTP/1.1 200") {
            break response;
        }
        assert!(
            Instant::now() < completion_deadline,
            "the disconnected request did not release its ingress slot: {response}"
        );
        std::thread::yield_now();
    };
    assert!(admitted.starts_with("HTTP/1.1 200"), "{admitted}");
    assert!(store
        .lock()
        .unwrap()
        .user_by_email("readmitted@example.test")
        .is_some());

    server.abort();
    runtime.block_on(async {
        let _ = server.await;
    });
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

struct ReentrantAdminHook {
    state: std::sync::Weak<AuthState>,
    mutate: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone, Copy)]
enum TenantMutation {
    Disable,
    Delete,
}

struct TenantMutatingHook {
    registry: Arc<fireemu_core_auth::store::AuthRegistry>,
    mutation: TenantMutation,
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl AuthBlockingHook for TenantMutatingHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if event == BlockingAuthEvent::BeforeSignIn
            && self.enabled.load(std::sync::atomic::Ordering::SeqCst)
        {
            match self.mutation {
                TenantMutation::Disable => {
                    let mut metadata = self
                        .registry
                        .tenant_metadata("demo-app", "customer")
                        .ok_or_else(BlockingFunctionFailure::unhandled)?;
                    metadata.disable_auth = true;
                    if !self
                        .registry
                        .update_tenant("demo-app", "customer", metadata)
                    {
                        return Err(BlockingFunctionFailure::unhandled());
                    }
                }
                TenantMutation::Delete => {
                    if !self.registry.delete_tenant("demo-app", "customer") {
                        return Err(BlockingFunctionFailure::unhandled());
                    }
                }
            }
        }
        Ok(json!({}))
    }
}

struct CreatingAdminHook {
    state: std::sync::Weak<AuthState>,
}

impl AuthBlockingHook for CreatingAdminHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if event == BlockingAuthEvent::BeforeCreate {
            let state = self
                .state
                .upgrade()
                .ok_or_else(BlockingFunctionFailure::unhandled)?;
            let response = handle_with(
                &state,
                "POST",
                &format!("{ADMIN}/accounts"),
                &owner(),
                &json!({"email": "admin-created@example.com", "password": "hunter22"}),
            );
            if response.status != 200 {
                return Err(BlockingFunctionFailure::unhandled());
            }
        }
        Ok(json!({}))
    }
}

impl AuthBlockingHook for ReentrantAdminHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if event == BlockingAuthEvent::BeforeSignIn
            && self.mutate.load(std::sync::atomic::Ordering::SeqCst)
        {
            let state = self
                .state
                .upgrade()
                .ok_or_else(BlockingFunctionFailure::unhandled)?;
            let response = handle_with(
                &state,
                "POST",
                &format!("{ADMIN}/accounts:update"),
                &owner(),
                &json!({"localId": user.local_id.as_str(), "disableUser": true}),
            );
            if response.status != 200 {
                return Err(BlockingFunctionFailure::unhandled());
            }
        }
        Ok(json!({}))
    }
}

#[test]
fn blocking_auth_rebases_on_admin_mutations_without_deadlocking_or_losing_them() {
    let mutate = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_mutate = mutate.clone();
    let state = Arc::new_cyclic(|weak| {
        let mut state = state();
        state.blocking = Some(Arc::new(ReentrantAdminHook {
            state: weak.clone(),
            mutate: hook_mutate.clone(),
        }));
        state
    });
    let (status, created) = post(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "callback@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    mutate.store(true, std::sync::atomic::Ordering::SeqCst);
    let request_state = state.clone();
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = post(
            &request_state,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "callback@example.com", "password": "hunter22"}),
        );
        let _ = sent.send(result);
    });

    let (status, body) = received
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("blocking Auth must not hold the gate needed by Admin Auth");
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], "USER_DISABLED");
    assert!(
        state
            .store
            .lock()
            .unwrap()
            .user_by_email("callback@example.com")
            .unwrap()
            .disabled
    );
}

#[test]
fn blocking_auth_rechecks_tenant_disablement_and_deletion_before_commit() {
    use fireemu_core_auth::store::AuthRegistry;

    for (mutation, expected) in [
        (TenantMutation::Disable, "PROJECT_DISABLED"),
        (TenantMutation::Delete, "TENANT_NOT_FOUND"),
    ] {
        let enabled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut state = state();
        let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
        registry.ensure_tenant("demo-app", "customer").unwrap();
        state.registry = Some(registry.clone());
        state.blocking = Some(Arc::new(TenantMutatingHook {
            registry,
            mutation,
            enabled: enabled.clone(),
        }));
        let (status, created) = post(
            &state,
            &format!("{V1}/accounts:signUp"),
            &json!({"tenantId": "customer", "email": "tenant@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{created}");
        enabled.store(true, std::sync::atomic::Ordering::SeqCst);

        let (status, refused) = post(
            &state,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"tenantId": "customer", "email": "tenant@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], expected);
    }
}

#[test]
fn a_poisoned_tenant_operation_gate_fails_closed_before_authentication() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut state = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    let gate = registry
        .operation_gate("demo-app", Some("customer"))
        .unwrap();
    let poison = gate.clone();
    let _ = std::thread::spawn(move || {
        let _guard = poison.lock().unwrap();
        panic!("poison the tenant operation gate");
    })
    .join();
    state.registry = Some(registry);
    state.blocking = Some(Arc::new(UpdatingBlockingHook));

    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "customer", "email": "blocked@example.test", "password": "hunter22"}),
    );

    assert_eq!(status, 500, "{body}");
}

#[test]
fn blocking_auth_dispatch_carries_the_selected_project_and_tenant_namespace() {
    use fireemu_core_auth::store::AuthRegistry;
    use fireemu_core_session::tenancy::Tenancy;
    use std::sync::RwLock;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut state = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    assert!(registry.register(
        "demo-worker",
        AuthStore::new("demo-worker", SplitMix64::new(6), TotpPolicy::default())
    ));
    state.registry = Some(registry);
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("demo-worker", &[], &["worker-key".to_owned()])
        .unwrap();
    state.tenancy = Some(Arc::new(RwLock::new(tenancy)));
    state.blocking = Some(Arc::new(NamespaceRecordingHook {
        calls: calls.clone(),
    }));

    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "tenantId": "customer",
            "email": "namespace@example.com",
            "password": "hunter22"
        }),
    );

    assert_eq!(status, 200, "{body}");
    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signUp?key=worker-key"),
        &json!({
            "email": "worker@example.com",
            "password": "hunter22"
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            (
                "demo-app".to_owned(),
                Some("customer".to_owned()),
                BlockingAuthEvent::BeforeCreate,
            ),
            (
                "demo-app".to_owned(),
                Some("customer".to_owned()),
                BlockingAuthEvent::BeforeSignIn,
            ),
            (
                "demo-worker".to_owned(),
                None,
                BlockingAuthEvent::BeforeCreate,
            ),
            (
                "demo-worker".to_owned(),
                None,
                BlockingAuthEvent::BeforeSignIn,
            ),
        ]
    );
}

#[test]
fn blocking_auth_never_replays_a_response_onto_a_different_generated_user() {
    let state = Arc::new_cyclic(|weak| {
        let mut state = state();
        state.blocking = Some(Arc::new(CreatingAdminHook {
            state: weak.clone(),
        }));
        state
    });

    let (status, refused) = post(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "original@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 400, "{refused}");
    let store = state.store.lock().unwrap();
    assert!(store.user_by_email("admin-created@example.com").is_some());
    assert!(store.user_by_email("original@example.com").is_none());
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

    let (status, count) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"returnUserInfo": false}),
    );
    assert_eq!(status, 200);
    assert_eq!(count["recordsCount"], "5");
    assert!(count.get("userInfo").is_none());
}

#[test]
#[allow(clippy::too_many_lines)]
fn strict_admin_query_applies_the_production_page_contract() {
    let strict = strict_state();
    for index in 0..503 {
        let (status, body) = admin(
            &strict,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": format!("user-{index:03}")}),
        );
        assert_eq!(status, 200, "{body}");
    }

    let (status, first) = admin(
        &strict,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({}),
    );
    assert_eq!(status, 200, "{first}");
    assert_eq!(first["recordsCount"], "500");
    assert_eq!(first["userInfo"].as_array().map(Vec::len), Some(500));
    assert_eq!(first["userInfo"][0]["localId"], "user-000");

    let (status, page) = admin(
        &strict,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"limit": "2", "offset": "500", "order": "ASC"}),
    );
    assert_eq!(status, 200, "{page}");
    assert_eq!(page["recordsCount"], "2");
    assert_eq!(page["userInfo"][0]["localId"], "user-500");
    assert_eq!(page["userInfo"][1]["localId"], "user-501");

    let (status, descending) = admin(
        &strict,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"limit": "2", "offset": "1", "order": "DESC"}),
    );
    assert_eq!(status, 200, "{descending}");
    assert_eq!(descending["userInfo"][0]["localId"], "user-501");

    let (status, numeric_page) = admin(
        &strict,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"limit": 2, "offset": 500, "sortBy": "USER_ID"}),
    );
    assert_eq!(status, 200, "{numeric_page}");
    assert_eq!(numeric_page["userInfo"].as_array().map(Vec::len), Some(2));

    let (status, count) = admin(
        &strict,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"returnUserInfo": false, "limit": null, "offset": null}),
    );
    assert_eq!(status, 200, "{count}");
    assert_eq!(count["recordsCount"], "503");

    let (status, unsupported_sort) = admin(
        &strict,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"sortBy": "NAME"}),
    );
    assert_eq!(status, 501, "{unsupported_sort}");

    for invalid in [
        json!({"limit": "501"}),
        json!({"limit": "-1"}),
        json!({"offset": "-1"}),
        json!({"returnUserInfo": "true"}),
        json!({"order": "SIDEWAYS"}),
        json!({"order": 1}),
        json!({"sortBy": "SIDEWAYS"}),
        json!({"sortBy": 1}),
        json!({"returnUserInfo": false, "order": "SIDEWAYS"}),
        json!({"returnUserInfo": false, "sortBy": "SIDEWAYS"}),
        json!({"returnUserInfo": false, "limit": "2"}),
    ] {
        let (status, _) = admin(
            &strict,
            "POST",
            &format!("{ADMIN}/accounts:query"),
            &invalid,
        );
        assert_eq!(status, 400, "{invalid}");
    }

    let firebase = state();
    for index in 0..501 {
        let (status, _) = admin(
            &firebase,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": format!("firebase-{index:03}")}),
        );
        assert_eq!(status, 200);
    }
    let (status, unbounded) = admin(
        &firebase,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"limit": "2"}),
    );
    assert_eq!(status, 200, "{unbounded}");
    assert_eq!(unbounded["recordsCount"], "501");
    assert_eq!(unbounded["userInfo"].as_array().map(Vec::len), Some(501));
}

#[test]
fn firebase_profile_admin_password_change_preserves_refresh_and_update_is_atomic() {
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
    // No claims is an absent customAttributes, as the official record has it.
    assert!(looked["users"][0]["customAttributes"].is_null());
    advance(&s, 1);
    let (status, refreshed_before_update) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{refreshed_before_update}");
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "password": "password2"}),
    );
    assert_eq!(status, 200);
    let (status, looked_up_after_update) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": refreshed_before_update["id_token"]}),
    );
    assert_eq!(status, 200, "{looked_up_after_update}");
    let (status, _) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({
            "grant_type": "refresh_token",
            "refresh_token": refreshed_before_update["refresh_token"]
        }),
    );
    assert_eq!(
        status, 200,
        "the official emulator keeps refresh tokens usable after an Admin password change"
    );
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "p@example.com", "password": "password2", "returnSecureToken": true}),
    );
    assert_eq!(status, 200);
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "disableUser": true}),
    );
    assert_eq!(status, 200);
    let (status, disabled) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 400, "{disabled}");
    assert_eq!(disabled["error"]["message"], "USER_DISABLED");
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:delete"),
        &json!({"localId": uid}),
    );
    assert_eq!(status, 200);
    let (status, deleted) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 400, "{deleted}");
    assert_eq!(deleted["error"]["message"], "INVALID_REFRESH_TOKEN");
}

#[test]
fn strict_password_change_distinguishes_revoked_refresh() {
    let s = strict_state();
    let (status, a) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "email": "revoked@example.com", "password": "password1", "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200);
    advance(&s, 2);
    let (status, b) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "revoked@example.com", "password": "password1", "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200);
    let refresh_path = "/securetoken.googleapis.com/v1/token";
    for token in [&a["refreshToken"], &b["refreshToken"]] {
        let (status, response) = post(
            &s,
            refresh_path,
            &json!({
                "grant_type": "refresh_token", "refresh_token": token
            }),
        );
        assert_eq!(status, 200, "{response}");
    }
    advance(&s, 3);
    let (status, changed) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({
            "idToken": a["idToken"], "password": "password2", "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200, "{changed}");
    let lookup = |token: &Value| {
        post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": token}),
        )
    };
    let baseline = lookup(&changed["idToken"]);
    assert_eq!(baseline.0, 200);
    for token in [&a["refreshToken"], &b["refreshToken"]] {
        let (status, response) = post(
            &s,
            refresh_path,
            &json!({
                "grant_type": "refresh_token", "refresh_token": token
            }),
        );
        assert_eq!(status, 400);
        assert_eq!(response["error"]["message"], "TOKEN_EXPIRED");
    }
    for token in ["", "rt-unknown", "malformed.token"] {
        let (status, response) = post(
            &s,
            refresh_path,
            &json!({
                "grant_type": "refresh_token", "refresh_token": token
            }),
        );
        assert_eq!(status, 400);
        assert_eq!(response["error"]["message"], "INVALID_REFRESH_TOKEN");
    }
    assert_eq!(lookup(&changed["idToken"]), baseline);
    let (status, fresh) = post(
        &s,
        refresh_path,
        &json!({
            "grant_type": "refresh_token", "refresh_token": changed["refreshToken"]
        }),
    );
    assert_eq!(status, 200, "{fresh}");
    assert_eq!(lookup(&fresh["id_token"]), baseline);
}

#[test]
fn strict_profile_admin_password_change_revokes_refresh_tokens() {
    let s = strict_state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "strict@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let (status, changed) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": signed["localId"], "password": "password2"}),
    );
    assert_eq!(status, 200, "{changed}");

    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({
            "grant_type": "refresh_token",
            "refresh_token": signed["refreshToken"]
        }),
    );
    assert_eq!(status, 400, "{refreshed}");
    assert_eq!(refreshed["error"]["message"], "INVALID_REFRESH_TOKEN");
}

#[test]
fn self_service_password_change_invalidates_an_existing_session_cookie() {
    let s = state();
    let (status, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "email": "session-cookie@example.com",
            "password": "password1",
            "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200, "{signed_up}");
    let uid = signed_up["localId"].as_str().unwrap().to_owned();
    let old_id_token = signed_up["idToken"].as_str().unwrap().to_owned();
    let (status, old_cookie) = admin(
        &s,
        "POST",
        &format!("{ADMIN}:createSessionCookie"),
        &json!({"idToken": old_id_token, "validDuration": "3600"}),
    );
    assert_eq!(status, 200, "{old_cookie}");

    let changed_at = advance(&s, 1);
    let (status, changed) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({
            "idToken": old_id_token,
            "password": "password2",
            "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200, "{changed}");
    let old_auth_time =
        fireemu_core_auth::jwt::decode_unsigned(old_cookie["sessionCookie"].as_str().unwrap())
            .unwrap()
            .payload
            .get("auth_time")
            .and_then(fireemu_core_types::json::JsonValue::as_i64)
            .unwrap();
    let (status, lookup) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid.clone()]}),
    );
    assert_eq!(status, 200, "{lookup}");
    let valid_since = lookup["users"][0]["validSince"]
        .as_str()
        .unwrap()
        .parse::<i64>()
        .unwrap();
    assert!(
        old_auth_time < valid_since,
        "the Admin SDK compares cookie auth_time={old_auth_time} with lookup validSince={valid_since}"
    );
    let (status, new_cookie) = admin(
        &s,
        "POST",
        &format!("{ADMIN}:createSessionCookie"),
        &json!({"idToken": changed["idToken"], "validDuration": "3600"}),
    );
    assert_eq!(status, 200, "{new_cookie}");

    let valid = |encoded: &str| {
        let decoded = fireemu_core_auth::jwt::decode_unsigned(encoded).unwrap();
        let auth_time = decoded
            .payload
            .get("auth_time")
            .and_then(fireemu_core_types::json::JsonValue::as_i64)
            .map(LogicalInstant::from_unix_seconds)
            .unwrap();
        let exp = decoded
            .payload
            .get("exp")
            .and_then(fireemu_core_types::json::JsonValue::as_i64)
            .map(LogicalInstant::from_unix_seconds)
            .unwrap();
        let store = s.store.lock().unwrap();
        let local_id = store.user_by_id(&uid).unwrap().local_id.clone();
        store.token_is_valid(&local_id, auth_time, exp, changed_at)
    };
    assert!(!valid(old_cookie["sessionCookie"].as_str().unwrap()));
    assert!(valid(new_cookie["sessionCookie"].as_str().unwrap()));
}

#[test]
fn admin_valid_since_is_parsed_before_mutation_and_applied_monotonically() {
    let s = state();
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": "revoked-user", "email": "before@example.com"}),
        )
        .0,
        200
    );

    let (status, body) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": "revoked-user",
            "validSince": "1788005000",
            "displayName": "applied"
        }),
    );
    assert_eq!(status, 200, "{body}");
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["revoked-user"]}),
    );
    assert_eq!(looked["users"][0]["validSince"], "1788005000");
    assert_eq!(looked["users"][0]["displayName"], "applied");

    let (status, body) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": "revoked-user",
            "validSince": 1_788_005_001_i64,
            "displayName": "numeric-applied"
        }),
    );
    assert_eq!(status, 200, "{body}");
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["revoked-user"]}),
    );
    assert_eq!(looked["users"][0]["validSince"], "1788005001");
    assert_eq!(looked["users"][0]["displayName"], "numeric-applied");

    for invalid in [
        json!("-1"),
        json!("1.5"),
        json!("9223372036854775808"),
        json!(-1_i64),
        json!(1.5_f64),
        json!(u64::MAX),
        Value::Null,
    ] {
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({
                "localId": "revoked-user",
                "validSince": invalid,
                "displayName": "must-not-apply"
            }),
        );
        assert_eq!(status, 400, "{invalid}");
    }
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "revoked-user", "validSince": "1788004900"}),
    );
    assert_eq!(status, 200);
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["revoked-user"]}),
    );
    assert_eq!(looked["users"][0]["validSince"], "1788005001");
    assert_eq!(looked["users"][0]["displayName"], "numeric-applied");
}

#[test]
fn admin_numeric_valid_since_accepts_the_i64_boundaries() {
    let s = state();
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": "boundary-user"}),
        )
        .0,
        200
    );
    for boundary in [0_i64, i64::MAX] {
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "boundary-user", "validSince": boundary}),
        );
        assert_eq!(status, 200, "{body}");
    }
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["boundary-user"]}),
    );
    assert_eq!(looked["users"][0]["validSince"], i64::MAX.to_string());
}

// ------------------------------------------------------------------------------------------
// Custom token sign-in
// ------------------------------------------------------------------------------------------

fn custom_token(uid: &str, claims: &Value, exp: i64) -> String {
    use fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE;
    custom_token_from_payload(&json!({
        "aud": CUSTOM_TOKEN_AUDIENCE,
        "iss": "firebase-auth-emulator@example.com",
        "sub": "firebase-auth-emulator@example.com",
        "uid": uid,
        "claims": claims,
        "iat": exp - 3600,
        "exp": exp,
    }))
}

fn custom_token_from_payload(payload: &Value) -> String {
    use fireemu_core_auth::jwt::base64url_encode;
    let header = base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
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
    // Reserved claims and a wrong audience are rejected. The Firebase Auth Emulator accepts
    // expired fake custom tokens; strict profile retains expiry validation.
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
        200,
        "the Firebase Auth Emulator accepts expired fake custom tokens"
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
        &json!({"localId": ["custom-2"]}),
    );
    assert_eq!(
        looked.get("users").map(|u| u.as_array().map(Vec::len)),
        None,
        "rejected tokens create nobody"
    );
}

#[test]
fn a_before_create_only_hook_rejects_a_new_custom_token_identity() {
    let mut state = state();
    state.blocking = Some(Arc::new(BeforeCreateOnlyRejectingHook));
    let token = custom_token("blocked-custom", &json!({}), 1_788_008_460);

    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": token, "returnSecureToken": true}),
    );

    assert_eq!(status, 400, "{body}");
    assert!(state
        .store
        .lock()
        .unwrap()
        .user_by_id("blocked-custom")
        .is_none());
}

#[test]
fn a_before_create_only_hook_is_not_called_for_before_sign_in_after_success() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut state = state();
    state.blocking = Some(Arc::new(BeforeCreateOnlySuccessfulHook(events.clone())));
    let token = custom_token("one-hook", &json!({}), 1_788_008_460);

    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": token, "returnSecureToken": true}),
    );

    assert_eq!(status, 200, "{body}");
    assert_eq!(*events.lock().unwrap(), [BlockingAuthEvent::BeforeCreate]);

    events.lock().unwrap().clear();
    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": token, "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn legacy_v3_custom_token_exchange_matches_v1() {
    use fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE;

    let s = state();
    let now_secs = 1_788_004_860;
    let token = custom_token("legacy-custom", &json!({"role": "tester"}), now_secs + 3600);
    let (status, body) = post(
        &s,
        "/www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=demo-key",
        &json!({"token": token, "returnSecureToken": true}),
    );

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["localId"], "legacy-custom");
    assert_eq!(body["isNewUser"], true);
    let decoded =
        fireemu_core_auth::jwt::decode_unsigned(body["idToken"].as_str().unwrap()).unwrap();
    assert_eq!(
        decoded.payload.get("role").and_then(|value| value.as_str()),
        Some("tester")
    );

    let expired = custom_token("legacy-expired", &json!({}), now_secs - 1);
    let (status, body) = post(
        &s,
        "/www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=demo-key",
        &json!({"token": expired}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["localId"], "legacy-expired");

    for invalid in [
        "not-a-token".to_owned(),
        custom_token_from_payload(&json!({
            "aud": "another-audience",
            "uid": "wrong-audience",
        })),
    ] {
        let (status, body) = post(
            &s,
            "/www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=demo-key",
            &json!({"token": invalid}),
        );
        assert_eq!(status, 400, "{body}");
    }

    let other_issuer = custom_token_from_payload(&json!({
        "aud": CUSTOM_TOKEN_AUDIENCE,
        "iss": "firebase-adminsdk@other-project.iam.gserviceaccount.com",
        "sub": "firebase-adminsdk@other-project.iam.gserviceaccount.com",
        "uid": "legacy-other-issuer",
        "iat": now_secs,
        "exp": now_secs + 3600,
    }));
    let (status, body) = post(
        &s,
        "/www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=demo-key",
        &json!({"token": other_issuer}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["localId"], "legacy-other-issuer");
}

#[test]
fn strict_profile_rejects_an_expired_custom_token() {
    let s = strict_state();
    let expired = custom_token("strict-expired", &json!({}), 1_788_004_859);
    let (status, body) = post(
        &s,
        "/www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=demo-key",
        &json!({"token": expired}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], "TOKEN_EXPIRED");
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
    // An address without a password credential lists no `password` provider (the official
    // record's rule), so only the phone entry remains.
    assert_eq!(u["providerUserInfo"].as_array().map(Vec::len), Some(1));
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

/// Account records and sign-in bodies follow production's field omissions and additions
/// (conformance/auth-production-matrix.json): a fresh anonymous record is `localId` and its
/// timestamps alone, a password record carries the redacted hash, its update time and
/// `validSince`, and a password sign-in always carries `displayName`.
#[test]
fn account_records_follow_production_field_omissions() {
    let s = state();
    let (status, anonymous) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{anonymous}");
    let (status, looked) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": anonymous["idToken"]}),
    );
    assert_eq!(status, 200, "{looked}");
    let record = looked["users"][0].as_object().unwrap();
    let mut keys: Vec<&str> = record.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["createdAt", "lastLoginAt", "localId"], "{looked}");

    let (status, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "record@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed_up}");
    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "record@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed_in}");
    assert_eq!(signed_in["displayName"], "", "{signed_in}");
    assert_eq!(signed_in["registered"], true);

    let (_, looked) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": signed_in["idToken"]}),
    );
    let record = &looked["users"][0];
    assert_eq!(record["passwordHash"], "UkVEQUNURUQ=", "{looked}");
    assert!(record["passwordUpdatedAt"].is_u64(), "{looked}");
    assert!(record["validSince"].is_string(), "{looked}");
    assert_eq!(record["emailVerified"], false);
    assert!(record.get("disabled").is_none(), "{looked}");
    assert!(record.get("mfaInfo").is_none(), "{looked}");
    assert_eq!(record["providerUserInfo"][0]["providerId"], "password");

    let (status, updated) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": signed_in["idToken"], "displayName": "Probe User", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["passwordHash"], "UkVEQUNURUQ=", "{updated}");
    assert_eq!(updated["displayName"], "Probe User");
    let (_, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "record@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(signed_in["displayName"], "Probe User", "{signed_in}");

    // A disabled account says so; a fresh one did not.
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": record["localId"], "disableUser": true}),
    );
    assert_eq!(status, 200);
    let (_, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [record["localId"]]}),
    );
    assert_eq!(looked["users"][0]["disabled"], true, "{looked}");
}

/// The v2 MFA enrollment routes answer a missing `idToken` with `INVALID_ID_TOKEN`, as
/// production does; the v1 routes keep `MISSING_ID_TOKEN`.
#[test]
fn mfa_enrollment_without_an_id_token_is_an_invalid_token() {
    let s = state_with_totp_extension();
    for route in ["mfaEnrollment:start", "mfaEnrollment:finalize"] {
        let (status, body) = post(
            &s,
            &format!("{V2}/accounts/{route}"),
            &json!({"totpEnrollmentInfo": {}}),
        );
        assert_eq!(status, 400, "{route}: {body}");
        assert_eq!(
            body["error"]["message"], "INVALID_ID_TOKEN",
            "{route}: {body}"
        );
    }
    let (status, body) = post(&s, &format!("{V1}/accounts:lookup"), &json!({}));
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], "MISSING_ID_TOKEN", "{body}");
}
