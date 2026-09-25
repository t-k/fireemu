//! Identity Toolkit flows through the pure handlers, plus one socket-level smoke test.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};

use fireemu_adapter_http::identity_toolkit::{
    handle, AuthBlockingHook, AuthQueryLimits, AuthState, BlockingFunctionCode,
    BlockingFunctionFailure,
};
use fireemu_adapter_http::signing::RsaSigner;
use fireemu_core_auth::base32;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::password_policy::{
    default_allowed_non_alphanumeric, EnforcementState, PasswordPolicy,
};
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_auth::totp::{totp_at, TotpParams};
use fireemu_core_functions::manifest::BlockingAuthEvent;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::tenancy::Tenancy;
use fireemu_core_types::determinism::{Clock as _, SplitMix64};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";

struct RecordingBlockingHook {
    events: Arc<Mutex<Vec<BlockingAuthEvent>>>,
    reject: Option<BlockingAuthEvent>,
}

struct ConfigurableBlockingHook {
    settings: Arc<Mutex<Value>>,
}

struct InterveningBlockingSettingsWriter {
    settings: Arc<Mutex<Value>>,
    intervene: AtomicBool,
}

struct BlockingSettingsGateProbe {
    settings: Arc<Mutex<Value>>,
    entered: Arc<AtomicBool>,
    updates: Arc<AtomicUsize>,
    release: Arc<AtomicBool>,
}

impl AuthBlockingHook for ConfigurableBlockingHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        unreachable!("settings regression hook is not used for Auth requests")
    }

    fn blocking_auth_settings(&self) -> Option<Value> {
        Some(self.settings.lock().unwrap().clone())
    }

    fn blocking_auth_project(&self) -> Option<&str> {
        Some("demo-app")
    }

    fn validate_blocking_auth_settings(&self, settings: &Value) -> Result<(), String> {
        let has_external_uri = settings
            .get("triggers")
            .and_then(|triggers| triggers.as_object())
            .into_iter()
            .flat_map(|triggers| triggers.values())
            .filter_map(Value::as_object)
            .filter_map(|trigger| trigger.get("functionUri"))
            .filter_map(Value::as_str)
            .any(|uri| uri.starts_with("https://"));
        if has_external_uri {
            Err("external function URI".to_owned())
        } else {
            Ok(())
        }
    }

    fn update_blocking_auth_settings(&self, settings: &Value) -> Result<(), String> {
        self.validate_blocking_auth_settings(settings)?;
        *self.settings.lock().unwrap() = settings.clone();
        Ok(())
    }
}

impl AuthBlockingHook for InterveningBlockingSettingsWriter {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        unreachable!("settings regression hook is not used for Auth requests")
    }

    fn blocking_auth_settings(&self) -> Option<Value> {
        Some(self.settings.lock().unwrap().clone())
    }

    fn blocking_auth_project(&self) -> Option<&str> {
        Some("demo-app")
    }

    fn validate_blocking_auth_settings(&self, _settings: &Value) -> Result<(), String> {
        Ok(())
    }

    fn update_blocking_auth_settings(&self, settings: &Value) -> Result<(), String> {
        *self.settings.lock().unwrap() = settings.clone();
        if self.intervene.swap(false, Ordering::SeqCst) {
            // Model a writer that commits after this request publishes its blocking candidate
            // but before the paired Auth update reports failure.
            *self.settings.lock().unwrap() = json!({
                "triggers": {
                    "beforeCreate": null,
                    "beforeSignIn": null,
                }
            });
        }
        Ok(())
    }
}

impl AuthBlockingHook for BlockingSettingsGateProbe {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        unreachable!("settings regression hook is not used for Auth requests")
    }

    fn blocking_auth_settings(&self) -> Option<Value> {
        Some(self.settings.lock().unwrap().clone())
    }

    fn blocking_auth_project(&self) -> Option<&str> {
        Some("demo-app")
    }

    fn validate_blocking_auth_settings(&self, _settings: &Value) -> Result<(), String> {
        Ok(())
    }

    fn update_blocking_auth_settings(&self, settings: &Value) -> Result<(), String> {
        let update = self.updates.fetch_add(1, Ordering::SeqCst);
        if update == 0 {
            self.entered.store(true, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        *self.settings.lock().unwrap() = settings.clone();
        Ok(())
    }
}

struct UpdatingBlockingHook;

struct UnhandledBlockingHook;

struct BeforeSignInTimeoutHook;

struct FixtureFailureHook(BlockingFunctionFailure);

struct ClearingClaimsHook;

struct OverlappingClaimHook;

impl AuthBlockingHook for OverlappingClaimHook {
    fn blocking_auth_project(&self) -> Option<&str> {
        Some("worker-alpha")
    }

    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(match event {
            BlockingAuthEvent::BeforeCreate => json!({
                "userRecord": {
                    "updateMask": "customClaims",
                    "customClaims": {"role": "persistent", "persistedOnly": true}
                }
            }),
            BlockingAuthEvent::BeforeSignIn => json!({
                "userRecord": {
                    "updateMask": "sessionClaims",
                    "sessionClaims": {"role": "session", "sessionOnly": true}
                }
            }),
        })
    }
}

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

struct ToggleHandlesHook {
    calls: AtomicUsize,
    enabled_after_initial: bool,
}

struct RevisionBumpBeforeDispatchHook {
    revision: AtomicUsize,
    revision_calls: AtomicUsize,
}

struct RevisionChangeAfterPostCallbackHook {
    revision: AtomicUsize,
    revision_calls: AtomicUsize,
    post_callback_checked: AtomicBool,
}

struct BeforeCreateOnlyRejectingHook;

struct BeforeCreateOnlySuccessfulHook(Arc<Mutex<Vec<BlockingAuthEvent>>>);

struct DelayedHookRelease(Arc<DelayedBlockingHook>);

struct ConcurrentBeforeCreateHook {
    state: Mutex<ConcurrentBeforeCreateState>,
    ready: Condvar,
}

struct ConcurrentBeforeCreateState {
    observed_uids: Vec<String>,
    release: bool,
}

struct AdvancingQuotaHook {
    clock: Arc<Mutex<VirtualClock>>,
    advance: LogicalDuration,
    advanced: AtomicBool,
}

struct DeletingUnrelatedUserHook {
    store: Arc<Mutex<AuthStore>>,
    uid: String,
    deleted: AtomicBool,
}

impl ConcurrentBeforeCreateHook {
    fn wait_for_both(&self) -> Vec<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut state = self.state.lock().unwrap();
        while state.observed_uids.len() < 2 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "both signups must reach BeforeCreate");
            state = self.ready.wait_timeout(state, remaining).unwrap().0;
        }
        state.observed_uids.clone()
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.release = true;
        self.ready.notify_all();
    }
}

impl AuthBlockingHook for ConcurrentBeforeCreateHook {
    fn handles(&self, event: BlockingAuthEvent) -> bool {
        event == BlockingAuthEvent::BeforeCreate
    }

    fn invoke(
        &self,
        event: BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        assert_eq!(event, BlockingAuthEvent::BeforeCreate);
        let mut state = self.state.lock().unwrap();
        state.observed_uids.push(user.local_id.to_string());
        self.ready.notify_all();
        while !state.release {
            state = self.ready.wait(state).unwrap();
        }
        Ok(json!({}))
    }
}

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

impl AuthBlockingHook for ToggleHandlesHook {
    fn handles(&self, event: BlockingAuthEvent) -> bool {
        assert!(matches!(
            event,
            BlockingAuthEvent::BeforeCreate | BlockingAuthEvent::BeforeSignIn
        ));
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.enabled_after_initial {
            call >= 2
        } else {
            call == 0
        }
    }

    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        unreachable!("toggle barrier regression must reject before hook dispatch")
    }
}

impl AuthBlockingHook for RevisionBumpBeforeDispatchHook {
    fn blocking_auth_revision(&self) -> u64 {
        let call = self.revision_calls.fetch_add(1, Ordering::SeqCst);
        if call >= 3 {
            self.revision.store(1, Ordering::SeqCst);
        }
        self.revision.load(Ordering::SeqCst) as u64
    }

    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        unreachable!("revision drift must be rejected before hook dispatch")
    }
}

impl AuthBlockingHook for RevisionChangeAfterPostCallbackHook {
    fn blocking_auth_revision(&self) -> u64 {
        let call = self.revision_calls.fetch_add(1, Ordering::SeqCst);
        let revision = self.revision.load(Ordering::SeqCst);
        if call == 4 {
            self.post_callback_checked.store(true, Ordering::SeqCst);
        }
        revision as u64
    }

    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(json!({}))
    }
}

impl AuthBlockingHook for AdvancingQuotaHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if !self.advanced.swap(true, Ordering::SeqCst) {
            self.clock.lock().unwrap().advance(self.advance).unwrap();
        }
        Ok(json!({}))
    }
}

impl AuthBlockingHook for DeletingUnrelatedUserHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if event == BlockingAuthEvent::BeforeCreate && !self.deleted.swap(true, Ordering::SeqCst) {
            let _ = self.store.lock().unwrap().delete_user_by_id(&self.uid);
        }
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
        idp_continuations: fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::Disabled,
        query_limits: AuthQueryLimits::EmulatorUnbounded,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
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
        idp_continuations:
            fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::LocalBounded,
        query_limits: AuthQueryLimits::ProductionBounded,
        stateless_refresh_tokens: false,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Required,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Reject,
        ..state()
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

#[test]
fn blocking_auth_rejection_rolls_back_user_creation() {
    let mut s = state();
    s.store
        .lock()
        .unwrap()
        .set_signup_quota_config(fireemu_core_auth::signup_quota::SignupQuotaConfig {
            mode: fireemu_core_auth::signup_quota::QuotaMode::Enforce,
            default_quota_per_hour: 1,
            ..Default::default()
        })
        .unwrap();
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
    assert_eq!(
        s.store.lock().unwrap().signup_quota().usage(
            "demo-app",
            "127.0.0.1",
            LogicalInstant::from_unix_seconds(1_788_004_860)
        ),
        (0, 0)
    );
}

#[test]
fn concurrent_signups_assign_distinct_uids_before_create_commits() {
    let mut auth = state();
    let hook = Arc::new(ConcurrentBeforeCreateHook {
        state: Mutex::new(ConcurrentBeforeCreateState {
            observed_uids: Vec::new(),
            release: false,
        }),
        ready: Condvar::new(),
    });
    auth.blocking = Some(hook.clone());
    let auth = Arc::new(auth);

    let first_auth = auth.clone();
    let first = std::thread::spawn(move || {
        post(
            &first_auth,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "concurrent-first@example.com", "password": "hunter22"}),
        )
    });
    let second_auth = auth.clone();
    let second = std::thread::spawn(move || {
        post(
            &second_auth,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "concurrent-second@example.com", "password": "hunter22"}),
        )
    });

    let observed_uids = hook.wait_for_both();
    assert_eq!(observed_uids.len(), 2);
    assert_ne!(observed_uids[0], observed_uids[1]);
    hook.release();

    let (first_status, first_body) = first.join().unwrap();
    let (second_status, second_body) = second.join().unwrap();
    assert_eq!(first_status, 200, "{first_body}");
    assert_eq!(second_status, 200, "{second_body}");

    let first_uid = first_body["localId"].as_str().unwrap();
    let second_uid = second_body["localId"].as_str().unwrap();
    assert_ne!(first_uid, second_uid);
    assert_eq!(
        observed_uids
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>(),
        [first_uid, second_uid].into_iter().collect()
    );

    let store = auth.store.lock().unwrap();
    assert_eq!(
        store
            .user_by_email("concurrent-first@example.com")
            .unwrap()
            .local_id
            .to_string(),
        first_uid
    );
    assert_eq!(
        store
            .user_by_email("concurrent-second@example.com")
            .unwrap()
            .local_id
            .to_string(),
        second_uid
    );
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
    // Secure Token errors have their own shape in production (sandbox recording 2026-09-23):
    // a gRPC status name and no `errors` list.
    assert_eq!(
        bad,
        json!({"error": {"code": 400, "message": "INVALID_REFRESH_TOKEN", "status": "INVALID_ARGUMENT"}})
    );
}

#[test]
fn secure_token_refresh_preserves_authentication_time() {
    let s = state();
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "auth-time@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");

    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "auth-time@example.com",
            "password": "hunter22",
            "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200, "{signed_in}");
    let initial = fireemu_core_auth::jwt::decode_unsigned(signed_in["idToken"].as_str().unwrap())
        .unwrap()
        .payload;
    let initial_iat = initial
        .get("iat")
        .and_then(fireemu_core_types::json::JsonValue::as_i64)
        .unwrap();
    assert_eq!(
        initial
            .get("auth_time")
            .and_then(fireemu_core_types::json::JsonValue::as_i64),
        Some(initial_iat)
    );

    let refresh = signed_in["refreshToken"].as_str().unwrap();
    advance(&s, 1);
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{refreshed}");
    let refreshed_claims =
        fireemu_core_auth::jwt::decode_unsigned(refreshed["id_token"].as_str().unwrap())
            .unwrap()
            .payload;
    assert_eq!(
        refreshed_claims
            .get("auth_time")
            .and_then(fireemu_core_types::json::JsonValue::as_i64),
        Some(initial_iat)
    );
    assert_eq!(
        refreshed_claims
            .get("iat")
            .and_then(fireemu_core_types::json::JsonValue::as_i64),
        Some(initial_iat + 1)
    );
    assert_eq!(
        refreshed_claims
            .get("exp")
            .and_then(fireemu_core_types::json::JsonValue::as_i64),
        Some(initial_iat + 1 + 3600)
    );
}

#[test]
fn strict_profile_token_expiration_matrix_preserves_account_state() {
    // Identity Toolkit honours a token for five minutes past `exp` and then refuses it as
    // invalid (sandbox recording 2026-09-24, auth-credential/expiry/one-hour).
    for elapsed in [0, 3_600, 3_899, 3_900, 3_901] {
        let s = strict_state();
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({
                "email": format!("token-expiration-{elapsed}@example.com"),
                "password": "hunter22",
                "returnSecureToken": true
            }),
        );
        assert_eq!(status, 200, "elapsed={elapsed}: {signed}");
        let uid = signed["localId"].as_str().unwrap();
        let id_token = signed["idToken"].clone();
        let refresh_token = signed["refreshToken"].clone();
        let account = || {
            admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:lookup"),
                &json!({"localId": [uid]}),
            )
        };
        let (status, before) = account();
        assert_eq!(status, 200, "elapsed={elapsed}: {before}");

        advance(&s, elapsed);
        let (lookup_status, lookup_response) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": id_token}),
        );
        if elapsed < 3_900 {
            assert_eq!(lookup_status, 200, "elapsed={elapsed}: {lookup_response}");
        } else {
            assert_eq!(lookup_status, 400, "elapsed={elapsed}: {lookup_response}");
            assert_eq!(lookup_response["error"]["message"], "INVALID_ID_TOKEN");
            let (status, after) = account();
            assert_eq!(status, 200, "elapsed={elapsed}: {after}");
            assert_eq!(
                after, before,
                "expired lookup mutated account at elapsed={elapsed}"
            );
        }

        let (refresh_status, refreshed) = post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({
                "grant_type": "refresh_token",
                "refresh_token": refresh_token
            }),
        );
        assert_eq!(refresh_status, 200, "elapsed={elapsed}: {refreshed}");
        let (refreshed_lookup_status, refreshed_lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": refreshed["id_token"]}),
        );
        assert_eq!(
            refreshed_lookup_status, 200,
            "elapsed={elapsed}: {refreshed_lookup}"
        );
        assert_eq!(refreshed_lookup["users"][0]["localId"], uid);
    }
}

/// Production evaluates `validSince` against each session's `auth_time` when the session is
/// used, and lets an administrator move it back: equal is accepted, one second later refuses
/// the ID token and the refresh token with `TOKEN_EXPIRED`, and moving it back before `auth_time`
/// honours both again (sandbox recording 2026-09-24, auth-credential/revocation/valid-since).
#[test]
fn strict_valid_since_is_evaluated_live_and_may_move_back() {
    let s = strict_state();
    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=k"),
        &json!({"email": "live-valid-since@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed_in}");
    let id_token = signed_in["idToken"].clone();
    let refresh = signed_in["refreshToken"].clone();
    let auth_time = fireemu_core_auth::jwt::decode_unsigned(id_token.as_str().unwrap())
        .unwrap()
        .payload
        .get("auth_time")
        .and_then(fireemu_core_types::json::JsonValue::as_i64)
        .unwrap();
    advance(&s, 2);
    let set_valid_since = |seconds: i64| {
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": signed_in["localId"], "validSince": seconds.to_string()}),
        );
        assert_eq!(status, 200, "{body}");
    };
    let use_session = || {
        let (lookup, looked_up) = post(
            &s,
            &format!("{V1}/accounts:lookup?key=k"),
            &json!({"idToken": id_token}),
        );
        let (refresh_status, refreshed) = post(
            &s,
            "/securetoken.googleapis.com/v1/token?key=k",
            &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
        );
        let code = |body: &Value| body["error"]["message"].as_str().unwrap_or("").to_owned();
        (lookup, code(&looked_up), refresh_status, code(&refreshed))
    };
    set_valid_since(auth_time);
    assert_eq!(
        use_session(),
        (200, String::new(), 200, String::new()),
        "equal is accepted"
    );
    set_valid_since(auth_time + 1);
    assert_eq!(
        use_session(),
        (
            400,
            "TOKEN_EXPIRED".to_owned(),
            400,
            "TOKEN_EXPIRED".to_owned()
        ),
        "a session older than validSince"
    );
    set_valid_since(auth_time - 1);
    assert_eq!(
        use_session(),
        (200, String::new(), 200, String::new()),
        "validSince moved back honours the session again"
    );
    let (_, account) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [signed_in["localId"]]}),
    );
    assert_eq!(
        account["users"][0]["validSince"],
        (auth_time - 1).to_string()
    );
}

/// An anonymous session's ID token names its provider at the top level as well as under
/// `firebase`, on sign-up and on every refresh; other accounts carry no `provider_id`
/// (sandbox recording 2026-09-24, auth-credential/id-token/methods#anonymous-sign-up).
/// A client update's `validSince` changes nothing; only an administrator sets it
/// (AUTH-ACCOUNT recording 2026-09-23, privilege/valid-token-admin-fields).
#[test]
fn a_client_update_cannot_move_valid_since() {
    let s = strict_state();
    let (status, signed_in) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "client-valid-since@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed_in}");
    let read = || {
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [signed_in["localId"]]}),
        )
        .1["users"][0]["validSince"]
            .clone()
    };
    let before = read();
    let (status, updated) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": signed_in["idToken"], "validSince": "1700000000"}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(read(), before);
}

/// The service account the strict test states trust for custom tokens.
const TEST_SIGNER: &str = "firebase-adminsdk-x@demo-app.iam.gserviceaccount.com";

fn test_signer_key() -> &'static rsa::RsaPrivateKey {
    use rand_core::SeedableRng;
    static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        rsa::RsaPrivateKey::new(&mut rand_chacha::ChaCha20Rng::seed_from_u64(31), 2048).unwrap()
    })
}

/// The strict profile with `auth.customTokenSigners` naming [`TEST_SIGNER`].
fn strict_state_with_signer() -> AuthState {
    use fireemu_adapter_http::identity_toolkit::CustomTokenTrust;
    use fireemu_core_auth::jwt::base64url_encode;
    use rsa::traits::PublicKeyParts;
    let key = test_signer_key();
    let jwks = json!({"keys": [{"kty": "RSA", "alg": "RS256", "kid": "k1",
        "n": base64url_encode(&key.n().to_bytes_be()), "e": base64url_encode(&key.e().to_bytes_be())}]});
    let trust =
        CustomTokenTrust::from_jwks(json!({TEST_SIGNER: jwks}).as_object().unwrap()).unwrap();
    AuthState {
        custom_token_trust: Some(Arc::new(trust)),
        ..strict_state()
    }
}

/// A custom token [`TEST_SIGNER`] signed, issued at `iat` and valid for an hour.
fn trusted_custom_token(uid: &str, claims: &Value, iat: i64) -> String {
    signed_custom_token(test_signer_key(), TEST_SIGNER, uid, claims, iat)
}

/// Identity Toolkit honours an ID token for five minutes past `exp` and then refuses it as
/// invalid, not as expired, in both profiles: production accepted it ten seconds past `exp` and
/// refused it 330 seconds past (sandbox recording 2026-09-24, auth-credential/expiry/one-hour).
/// A strict custom token follows the same allowance; the emulator profile keeps the official
/// emulator's disregard of a fake custom token's `exp`.
#[test]
fn expired_tokens_have_a_skew_allowance_and_are_then_invalid() {
    for strict in [true, false] {
        let s = if strict {
            strict_state_with_signer()
        } else {
            state()
        };
        let (status, signed_in) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "expiry@example.com", "password": "hunter22", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{signed_in}");
        let now = 1_788_004_860;
        let custom = if strict {
            trusted_custom_token("expiring-custom", &json!({}), now)
        } else {
            custom_token("expiring-custom", &json!({}), now + 3600)
        };
        let attempt = || {
            let code = |(status, body): (u16, Value)| {
                (
                    status,
                    body["error"]["message"].as_str().unwrap_or("").to_owned(),
                )
            };
            (
                code(post(
                    &s,
                    &format!("{V1}/accounts:lookup"),
                    &json!({"idToken": signed_in["idToken"]}),
                )),
                code(admin(
                    &s,
                    "POST",
                    &format!("{ADMIN}:createSessionCookie"),
                    &json!({"idToken": signed_in["idToken"], "validDuration": 3600}),
                )),
                code(post(
                    &s,
                    &format!("{V1}/accounts:signInWithCustomToken"),
                    &json!({"token": custom, "returnSecureToken": true}),
                )),
            )
        };
        advance(&s, 3610);
        let ok = (200, String::new());
        assert_eq!(
            attempt(),
            (ok.clone(), ok.clone(), ok.clone()),
            "strict={strict}"
        );
        advance(&s, 320);
        let custom_expected = if strict {
            (400, "INVALID_CUSTOM_TOKEN".to_owned())
        } else {
            ok
        };
        assert_eq!(
            attempt(),
            (
                (400, "INVALID_ID_TOKEN".to_owned()),
                (400, "INVALID_ID_TOKEN".to_owned()),
                custom_expected,
            ),
            "strict={strict}"
        );
    }
}

/// An administrator's email change revokes the account's sessions and retires its refresh
/// tokens; a profile-only change does not. Production has not been observed for this; the test
/// pins fireemu's contract.
#[test]
fn an_administrative_email_change_revokes_sessions_and_a_profile_change_does_not() {
    let s = strict_state();
    let sign_up = |email: &str| {
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": email, "password": "hunter22", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{body}");
        body
    };
    let changed = sign_up("before-change@example.com");
    let profiled = sign_up("profile-only@example.com");
    advance(&s, 2);
    for (account, change) in [
        (&changed, json!({"email": "after-change@example.com"})),
        (&profiled, json!({"displayName": "Renamed"})),
    ] {
        let mut request = change;
        request["localId"] = account["localId"].clone();
        let (status, body) = admin(&s, "POST", &format!("{ADMIN}/accounts:update"), &request);
        assert_eq!(status, 200, "{body}");
    }
    let use_session = |account: &Value| {
        let (lookup, looked) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": account["idToken"]}),
        );
        let (refresh, refreshed) = post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type": "refresh_token", "refresh_token": account["refreshToken"]}),
        );
        let code = |body: &Value| body["error"]["message"].as_str().unwrap_or("").to_owned();
        (lookup, code(&looked), refresh, code(&refreshed))
    };
    assert_eq!(
        use_session(&changed),
        (
            400,
            "TOKEN_EXPIRED".to_owned(),
            400,
            "INVALID_REFRESH_TOKEN".to_owned()
        )
    );
    assert_eq!(
        use_session(&profiled),
        (200, String::new(), 200, String::new())
    );
}

/// Disabling and re-enabling an account keeps its sessions in the strict profile, as production
/// does (AUTH-ACCOUNT recording 2026-09-23, admin/disable), while the emulator profile revokes
/// them as the official emulator does.
#[test]
fn disable_and_re_enable_keeps_sessions_only_in_the_strict_profile() {
    for strict in [true, false] {
        let s = if strict { strict_state() } else { state() };
        let (status, account) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "toggle@example.com", "password": "hunter22", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{account}");
        advance(&s, 2);
        // A profile-only update keeps the session in either profile.
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": account["localId"], "displayName": "Still Signed In"}),
        );
        assert_eq!(status, 200, "{body}");
        let (status, looked) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": account["idToken"]}),
        );
        assert_eq!(status, 200, "strict={strict}: {looked}");
        for disable in [true, false] {
            let (status, body) = admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:update"),
                &json!({"localId": account["localId"], "disableUser": disable}),
            );
            assert_eq!(status, 200, "{body}");
        }
        let (status, looked) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": account["idToken"]}),
        );
        if strict {
            assert_eq!(status, 200, "{looked}");
        } else {
            assert_eq!(
                (status, looked["error"]["message"].clone()),
                (400, json!("TOKEN_EXPIRED"))
            );
        }
    }
}

/// The emulator profile keeps the official emulator's answer to an empty custom token, and a
/// numeric uid names its account as a string (sandbox recording 2026-09-24,
/// custom-token/validation#numeric-uid).
#[test]
fn custom_token_empty_and_numeric_uid_answers() {
    let s = state();
    let (status, empty) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": ""}),
    );
    assert_eq!(
        (status, empty["error"]["message"].clone()),
        (400, json!("MISSING_CUSTOM_TOKEN"))
    );
    for strict in [false, true] {
        let s = if strict {
            strict_state_with_signer()
        } else {
            state()
        };
        let now = 1_788_004_860;
        let issuer = if strict {
            TEST_SIGNER
        } else {
            "firebase-auth-emulator@example.com"
        };
        let payload = json!({
            "aud": fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE,
            "iss": issuer,
            "sub": issuer,
            "iat": now,
            "exp": now + 3600,
            "uid": 12345,
        });
        let token = if strict {
            signed_payload(test_signer_key(), &payload)
        } else {
            custom_token_from_payload(&payload)
        };
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": token, "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(token_parts(&body["idToken"]).1["sub"], "12345");
    }
}

/// The emulator profile never issues legacy tokens, so it keeps refusing a token that claims
/// the legacy issuer (closure review S3).
#[test]
fn the_emulator_profile_refuses_a_forged_legacy_token() {
    let s = state();
    let (status, account) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "forged-legacy@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{account}");
    let now = 1_788_004_860;
    let forged = fireemu_core_auth::jwt::encode_payload_shaped(
        &json!({
            "iss": "https://identitytoolkit.google.com/",
            "aud": "demo-app",
            "iat": now,
            "exp": now + 1_209_600,
            "user_id": account["localId"],
            "sign_in_provider": "password",
        })
        .to_string(),
        None,
        fireemu_core_auth::jwt::HeaderShape::Untyped,
    );
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": forged}),
    );
    assert_eq!(
        (status, refused["error"]["message"].clone()),
        (400, json!("INVALID_ID_TOKEN"))
    );
}

/// Without `returnSecureToken` the emulator profile keeps the official emulator's secure tokens,
/// while strict answers with production's legacy token (sandbox recording 2026-09-24).
#[test]
fn only_the_strict_profile_answers_without_secure_tokens_with_a_legacy_token() {
    for strict in [false, true] {
        let s = if strict {
            strict_state_with_signer()
        } else {
            state()
        };
        let (status, _) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "profile-legacy@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200);
        let now = 1_788_004_860;
        let custom = if strict {
            trusted_custom_token("profile-custom", &json!({}), now)
        } else {
            custom_token("profile-custom", &json!({}), now + 3600)
        };
        for (path, body) in [
            (
                "accounts:signInWithPassword",
                json!({"email": "profile-legacy@example.com", "password": "hunter22"}),
            ),
            ("accounts:signInWithCustomToken", json!({"token": custom})),
        ] {
            let (status, answer) = post(&s, &format!("{V1}/{path}"), &body);
            assert_eq!(status, 200, "{answer}");
            let issuer = token_parts(&answer["idToken"]).1["iss"].clone();
            if strict {
                assert_eq!(issuer, "https://identitytoolkit.google.com/", "{path}");
                assert!(answer.get("refreshToken").is_none(), "{path}: {answer}");
            } else {
                assert_eq!(issuer, "https://securetoken.google.com/demo-app", "{path}");
                assert!(answer.get("refreshToken").is_some(), "{path}: {answer}");
            }
        }
    }
}

/// A strict project keeps legacy tokens unless a blocking trigger is selected for the sign-in:
/// a beforeCreate-only function does not stop a password sign-in's legacy token, a
/// beforeSignIn function does.
#[test]
fn legacy_tokens_stop_only_where_a_blocking_trigger_is_selected() {
    for (label, hook, legacy) in [
        (
            "beforeCreate only",
            Arc::new(BeforeCreateOnlySuccessfulHook(Arc::new(Mutex::new(
                Vec::new(),
            )))) as Arc<dyn AuthBlockingHook>,
            true,
        ),
        (
            "beforeSignIn",
            Arc::new(RecordingBlockingHook {
                events: Arc::new(Mutex::new(Vec::new())),
                reject: None,
            }) as Arc<dyn AuthBlockingHook>,
            false,
        ),
    ] {
        let mut s = strict_state();
        let (status, _) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "blocking-legacy@example.com", "password": "hunter22", "returnSecureToken": true}),
        );
        assert_eq!(status, 200);
        s.blocking = Some(hook);
        let (status, answer) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "blocking-legacy@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{label}: {answer}");
        assert_eq!(
            answer.get("refreshToken").is_none(),
            legacy,
            "{label}: {answer}"
        );
    }
}

/// Production accepts only signed custom tokens: without `auth.customTokenSigners` the strict
/// profile refuses unsigned and JSON fake tokens as production refuses an unsigned one, and the
/// emulator profile keeps accepting them as the official emulator does.
#[test]
fn strict_refuses_unsigned_custom_tokens_without_configured_signers() {
    let now = 1_788_004_860;
    for (strict, expected) in [(true, 400), (false, 200)] {
        let s = if strict { strict_state() } else { state() };
        for token in [
            custom_token("unsigned-user", &json!({}), now + 3600),
            r#"{"uid":"json-user"}"#.to_owned(),
        ] {
            let (status, body) = post(
                &s,
                &format!("{V1}/accounts:signInWithCustomToken"),
                &json!({"token": token, "returnSecureToken": true}),
            );
            assert_eq!(status, expected, "strict={strict}: {body}");
            if strict {
                assert_eq!(body["error"]["message"], "INVALID_CUSTOM_TOKEN");
            }
        }
    }
}

/// Production honours a legacy token on account lookup, update and delete, a verification
/// mail, phone linking, a sign-up upgrade and MFA enrollment (sandbox recording 2026-09-24,
/// id-token/without-return-secure-token). Email-link and identity-provider linking, not yet
/// observed, keep refusing it; separate tests pin both.
#[test]
fn legacy_tokens_are_honoured_where_production_honours_them() {
    let s = strict_state_with_signer();
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "legacy-routes@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200);
    let (status, legacy) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "legacy-routes@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{legacy}");
    let token = legacy["idToken"].clone();
    let code = |(status, body): (u16, Value)| {
        (
            status,
            body["error"]["message"].as_str().unwrap_or("").to_owned(),
        )
    };
    let v2 = "/identitytoolkit.googleapis.com/v2";
    assert_eq!(
        code(post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": token})
        )),
        (200, String::new())
    );
    assert_eq!(
        code(post(
            &s,
            &format!("{V1}/accounts:sendOobCode"),
            &json!({"idToken": token, "requestType": "VERIFY_EMAIL"}),
        )),
        (200, String::new())
    );
    let (status, started) = post(
        &s,
        &format!("{v2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "totpEnrollmentInfo": {}}),
    );
    assert_eq!(
        (status, started.clone()),
        (
            400,
            json!({"error": {"code": 400, "message": "OPERATION_NOT_ALLOWED : TOTP based MFA not enabled.", "status": "INVALID_ARGUMENT"}})
        )
    );
    let (status, withdrawn) = post(
        &s,
        &format!("{v2}/accounts/mfaEnrollment:withdraw"),
        &json!({"idToken": token, "mfaEnrollmentId": "unknown"}),
    );
    assert_eq!(
        (status, withdrawn),
        (
            400,
            json!({"error": {"code": 400, "message": "MFA_ENROLLMENT_NOT_FOUND", "status": "INVALID_ARGUMENT"}})
        )
    );
    // A sign-up upgrade with a legacy token of a custom account adds the address.
    let (status, custom) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": trusted_custom_token("legacy-upgrade", &json!({}), 1_788_004_860)}),
    );
    assert_eq!(status, 200, "{custom}");
    let (status, upgraded) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"idToken": custom["idToken"], "email": "upgraded@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{upgraded}");
    assert_eq!(upgraded["email"], "upgraded@example.com");
}

/// `validDuration` follows the official emulator's `Number(v) || two weeks` in the emulator
/// profile and production's int64 decoding in strict (sandbox recording 2026-09-24).
#[test]
fn session_cookie_durations_follow_each_profile() {
    for strict in [false, true] {
        let s = if strict { strict_state() } else { state() };
        let (status, signed_up) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "duration-profile@example.com", "password": "hunter22", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{signed_up}");
        for (duration, lifetime) in [
            (json!(0), 1_209_600),
            (json!(3600.5), 3600),
            (json!("an hour"), 1_209_600),
            (json!("3600"), 3600),
        ] {
            let (status, answer) = admin(
                &s,
                "POST",
                &format!("{ADMIN}:createSessionCookie"),
                &json!({"idToken": signed_up["idToken"], "validDuration": duration}),
            );
            if strict && duration != json!("3600") {
                assert_eq!(status, 400, "{duration}: {answer}");
            } else {
                assert_eq!(status, 200, "strict={strict} {duration}: {answer}");
                let claims = token_parts(&answer["sessionCookie"]).1;
                assert_eq!(
                    claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
                    lifetime,
                    "strict={strict} {duration}"
                );
            }
        }
    }
}

/// Strict: an email-link sign-in that links to a session honours a legacy token, as
/// production does (sandbox recording 2026-09-24, legacy-token#sign-in-link-legacy-token).
#[test]
fn an_email_link_honours_a_legacy_token() {
    let s = strict_state_with_signer();
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "legacy-link@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200);
    let (status, legacy) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "legacy-link@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{legacy}");
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "legacy-link@example.com", "continueUrl": "http://localhost/"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (status, codes) = admin(
        &s,
        "GET",
        "/emulator/v1/projects/demo-app/oobCodes",
        &Value::Null,
    );
    assert_eq!(status, 200, "{codes}");
    let code = codes["oobCodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["requestType"] == "EMAIL_SIGNIN")
        .unwrap()["oobCode"]
        .clone();
    let (status, linked) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"email": "legacy-link@example.com", "oobCode": code, "idToken": legacy["idToken"]}),
    );
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["kind"], "identitytoolkit#EmailLinkSigninResponse");
    assert_eq!(linked["isNewUser"], false);
}

/// Linking an identity provider refuses a legacy token (not yet observed with one in
/// production) where a secure token of the same account links.
#[test]
fn an_identity_provider_link_refuses_a_legacy_token() {
    let s = strict_state_with_signer();
    let (status, secure) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "legacy-idp@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{secure}");
    let (status, legacy) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "legacy-idp@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{legacy}");
    let link = |token: &Value, subject: &str| {
        let assertion =
            json!({"sub": subject, "email": format!("{subject}@example.com")}).to_string();
        let encoded: String = assertion
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        post(
            &s,
            &format!("{V1}/accounts:signInWithIdp"),
            &json!({
                "idToken": token,
                "postBody": format!("id_token={encoded}&providerId=google.com"),
                "requestUri": "http://localhost",
                "returnSecureToken": true,
            }),
        )
    };
    let (status, refused) = link(&legacy["idToken"], "g-legacy");
    assert_eq!(
        (status, refused["error"]["message"].clone()),
        (400, json!("INVALID_ID_TOKEN"))
    );
    let (status, linked) = link(&secure["idToken"], "g-secure");
    assert_eq!(status, 200, "{linked}");
}

/// Configured signers bring production's custom-token rules to the emulator profile too.
#[test]
fn configured_signers_apply_production_rules_in_the_emulator_profile() {
    let trusted = strict_state_with_signer();
    let s = AuthState {
        custom_token_trust: trusted.custom_token_trust.clone(),
        ..state()
    };
    let now = 1_788_004_860;
    let wrong_audience = signed_payload(
        test_signer_key(),
        &json!({"iss": TEST_SIGNER, "sub": TEST_SIGNER, "aud": "https://example.com", "iat": now, "exp": now + 3600, "uid": "u"}),
    );
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": wrong_audience, "returnSecureToken": true}),
    );
    assert_eq!(
        (status, refused["error"]["message"].clone()),
        (400, json!("INVALID_CUSTOM_TOKEN"))
    );
}

/// A strict custom token is honoured through exp+299 and refused from exp+300, the edge
/// production showed (exploration 2026-09-24, skew-1790210153.json).
#[test]
fn a_custom_token_is_refused_from_exactly_five_minutes_past_exp() {
    let s = strict_state_with_signer();
    let now = 1_788_004_860;
    let token = trusted_custom_token("edge", &json!({}), now);
    let sign_in = || {
        post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": token, "returnSecureToken": true}),
        )
    };
    advance(&s, 3600 + 299);
    assert_eq!(sign_in().0, 200);
    advance(&s, 1);
    let (status, refused) = sign_in();
    assert_eq!(
        (status, refused["error"]["message"].clone()),
        (400, json!("INVALID_CUSTOM_TOKEN"))
    );
}

/// The emulator profile keeps the official emulator's error shape on MFA enrollment.
#[test]
fn the_emulator_profile_keeps_the_official_mfa_error_shape() {
    let s = state();
    let (status, account) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "mfa-shape@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{account}");
    let (status, refused) = post(
        &s,
        "/identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:withdraw",
        &json!({"idToken": account["idToken"], "mfaEnrollmentId": "unknown"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert!(refused["error"].get("errors").is_some(), "{refused}");
    assert!(refused["error"].get("status").is_none(), "{refused}");
}

/// `Number(true)` is one second, below the minimum; `Number(false)` is zero, the maximum.
#[test]
fn the_emulator_profile_reads_a_boolean_duration_as_a_number() {
    let s = state();
    let (status, account) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "bool-duration@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{account}");
    let cookie = |duration: Value| {
        admin(
            &s,
            "POST",
            &format!("{ADMIN}:createSessionCookie"),
            &json!({"idToken": account["idToken"], "validDuration": duration}),
        )
    };
    let (status, refused) = cookie(json!(true));
    assert_eq!(
        (status, refused["error"]["message"].clone()),
        (400, json!("INVALID_DURATION"))
    );
    let (status, accepted) = cookie(json!(false));
    assert_eq!(status, 200, "{accepted}");
    let claims = token_parts(&accepted["sessionCookie"]).1;
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        1_209_600
    );
}

#[test]
fn anonymous_id_tokens_carry_a_top_level_provider_id() {
    let s = strict_state();
    let claim = |token: &Value| {
        fireemu_core_auth::jwt::decode_unsigned(token.as_str().unwrap())
            .unwrap()
            .payload
            .get("provider_id")
            .and_then(|v| v.as_str().map(str::to_owned))
    };
    let (status, anonymous) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=k"),
        &json!({"returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{anonymous}");
    assert_eq!(claim(&anonymous["idToken"]).as_deref(), Some("anonymous"));
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token?key=k",
        &json!({"grant_type": "refresh_token", "refresh_token": anonymous["refreshToken"]}),
    );
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(claim(&refreshed["id_token"]).as_deref(), Some("anonymous"));
    let (status, password) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=k"),
        &json!({"email": "not-anonymous@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{password}");
    assert_eq!(claim(&password["idToken"]), None);
}

/// Secure Token treats an absent or empty `grant_type` or `refresh_token` as missing, and its
/// front end refuses a caller without identity without an `errors` list (sandbox recording
/// 2026-09-24, auth-credential/refresh/refusals).
#[test]
fn secure_token_missing_fields_and_unregistered_callers_have_production_shapes() {
    let s = strict_state();
    let token = "/securetoken.googleapis.com/v1/token";
    let message = |body: &Value| body["error"]["message"].as_str().unwrap_or("").to_owned();
    for (body, expected) in [
        (json!({"refresh_token": "anything"}), "MISSING_GRANT_TYPE"),
        (json!({}), "MISSING_GRANT_TYPE"),
        (
            json!({"grant_type": "", "refresh_token": "anything"}),
            "MISSING_GRANT_TYPE",
        ),
        (
            json!({"grant_type": "refresh_token", "refresh_token": ""}),
            "MISSING_REFRESH_TOKEN",
        ),
        (
            json!({"grant_type": "refresh_token"}),
            "MISSING_REFRESH_TOKEN",
        ),
        (
            json!({"grant_type": "password", "refresh_token": "x"}),
            "INVALID_GRANT_TYPE",
        ),
    ] {
        let (status, refused) = post(&s, &format!("{token}?key=k"), &body);
        assert_eq!(
            (status, message(&refused)),
            (400, expected.to_owned()),
            "{body}"
        );
        assert!(refused["error"].get("errors").is_none(), "{refused}");
    }
    // `post` adds the key an SDK would send; this caller sends none.
    let refused = handle(
        &s,
        "POST",
        token,
        &json!({"grant_type": "refresh_token", "refresh_token": "x"}),
    );
    assert_eq!(refused.status, 403);
    assert_eq!(
        refused.body,
        json!({"error": {
            "code": 403,
            "message": "Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.",
            "status": "PERMISSION_DENIED",
        }})
    );
}

#[test]
fn refresh_authentication_time_remains_revocable_in_both_profiles() {
    for strict in [false, true] {
        let s = if strict { strict_state() } else { state() };
        let (status, signed_in) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "revocable-auth-time@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{signed_in}");
        let refresh = signed_in["refreshToken"].as_str().unwrap();
        let initial =
            fireemu_core_auth::jwt::decode_unsigned(signed_in["idToken"].as_str().unwrap())
                .unwrap()
                .payload;
        let initial_auth_time = initial
            .get("auth_time")
            .and_then(fireemu_core_types::json::JsonValue::as_i64)
            .unwrap();

        advance(&s, 1);
        let (status, revoked) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({
                "localId": signed_in["localId"],
                "validSince": (initial_auth_time + 1).to_string()
            }),
        );
        assert_eq!(status, 200, "{revoked}");

        let (status, refreshed) = post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
        );
        if strict {
            assert_eq!(status, 400, "{refreshed}");
            assert!(
                refreshed["error"]["message"]
                    .as_str()
                    .is_some_and(|message| {
                        message.starts_with("TOKEN_EXPIRED") || message == "INVALID_REFRESH_TOKEN"
                    }),
                "{refreshed}"
            );
        } else {
            assert_eq!(status, 200, "{refreshed}");
            let claims =
                fireemu_core_auth::jwt::decode_unsigned(refreshed["id_token"].as_str().unwrap())
                    .unwrap()
                    .payload;
            assert_eq!(
                claims
                    .get("auth_time")
                    .and_then(fireemu_core_types::json::JsonValue::as_i64),
                Some(initial_auth_time)
            );
            let (status, looked_up) = post(
                &s,
                &format!("{V1}/accounts:lookup"),
                &json!({"idToken": refreshed["id_token"]}),
            );
            assert_eq!(status, 400, "{looked_up}");
            assert!(
                looked_up["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with("TOKEN_EXPIRED")),
                "{looked_up}"
            );
        }
    }
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
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "customAttributes": "{\"role\":\"admin\"}"}),
    );
    assert_eq!(status, 200);
    let (status, bad) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
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
    let (status, users) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": uid}),
    );
    assert_eq!(status, 200);
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
    assert_eq!(info["hashingAlgorithm"], "SHA1");
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
    // Production's lifetime is 900 s.
    let late = advance(&s, 901);
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

    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
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
    assert_eq!(revoked["error"]["message"], "USER_DISABLED");
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

/// PCT-1. The form decoder in the server layer took `%+f` through `u8::from_str_radix`,
/// which accepts a leading sign, and produced U+000F. The shared codec takes two ASCII
/// hexadecimal digits and nothing else, so the sequence stays literal and only `+` is a
/// space.
#[tokio::test]
async fn a_form_encoded_body_decodes_percent_escapes_strictly() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shared = Arc::new(state());
    let server = tokio::spawn(fireemu_adapter_http::server::serve(
        listener,
        shared.clone(),
    ));
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = "email=form@example.com&password=hunter22&displayName=na%+fme";
    let request = format!(
        "POST {V1}/accounts:signUp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8(response).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    let json_start = text.find("\r\n\r\n").unwrap() + 4;
    let parsed: Value = serde_json::from_str(&text[json_start..]).unwrap();
    assert_eq!(parsed["email"], "form@example.com");
    // `+` is still a form-encoded space; `%` keeps its literal self, so no control
    // character reaches the profile guard.
    assert_eq!(parsed["displayName"], "na% fme");
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
        peer_ip: None,
    }
}
fn admin(state: &AuthState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let r = handle_with(state, method, path, &owner(), body);
    (r.status, r.body)
}

/// Holds a namespace gate while a signup starts, then races the signup with a settings PATCH.
/// The store must remain available while the signup waits for the gate; otherwise the old
/// store-before-gate order can deadlock the PATCH's gate-before-store path.
fn concurrent_signup_and_patch(
    state: Arc<AuthState>,
    gate: &Arc<Mutex<()>>,
    store: &Arc<Mutex<AuthStore>>,
    signup_body: Value,
    patch_path: String,
    patch_body: Value,
) -> ((u16, Value), (u16, Value)) {
    use std::sync::mpsc::channel;
    use std::time::Duration;

    let held = gate.lock().unwrap();
    let signup_started = Arc::new(std::sync::Barrier::new(2));
    let (signup_tx, signup_rx) = channel();
    let signup_state = state.clone();
    let signup_started_thread = signup_started.clone();
    let signup = std::thread::spawn(move || {
        signup_started_thread.wait();
        signup_tx
            .send(handle_with(
                &signup_state,
                "POST",
                &format!("{V1}/accounts:signUp"),
                &RequestHeaders::default(),
                &signup_body,
            ))
            .unwrap();
    });
    signup_started.wait();

    // Give the signup a bounded opportunity to reach its namespace gate. The corrected order
    // may briefly read the store to resolve its namespace, but it must release that guard while
    // waiting for the gate. Requiring an available store here catches the old store-before-gate
    // inversion without depending on a sleep-based scheduling assumption.
    let mut store_available = false;
    for _ in 0..10_000 {
        if store.try_lock().is_ok() {
            store_available = true;
            break;
        }
        std::thread::yield_now();
    }
    assert!(
        store_available,
        "signup held the store while waiting for the namespace gate"
    );

    let (patch_tx, patch_rx) = channel();
    let patch_state = state;
    let patch = std::thread::spawn(move || {
        patch_tx
            .send(handle_with(
                &patch_state,
                "PATCH",
                &patch_path,
                &owner(),
                &patch_body,
            ))
            .unwrap();
    });
    drop(held);

    let signup_response = signup_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("signup did not complete after releasing the namespace gate");
    let patch_response = patch_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("settings PATCH did not complete after releasing the namespace gate");
    signup.join().unwrap();
    patch.join().unwrap();
    (
        (signup_response.status, signup_response.body),
        (patch_response.status, patch_response.body),
    )
}

#[test]
fn signup_and_project_patch_have_a_bounded_shared_gate() {
    use fireemu_core_auth::signup_quota::{QuotaMode, SignupQuotaConfig};
    use fireemu_core_auth::store::AuthRegistry;

    let mut initial = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", initial.store.clone()));
    initial
        .store
        .lock()
        .unwrap()
        .set_signup_quota_config(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 1,
            ..SignupQuotaConfig::default()
        })
        .unwrap();
    initial.registry = Some(registry.clone());
    let store = initial.store.clone();
    let state = Arc::new(initial);
    let gate = registry.operation_gate("demo-app", None).unwrap();
    let ((signup_status, signup_body), (patch_status, patch_body)) = concurrent_signup_and_patch(
        state.clone(),
        &gate,
        &store,
        json!({
            "email": "concurrent-project@example.com",
            "password": "password1",
        }),
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=client.permissions.disabledUserSignup"
            .to_owned(),
        json!({"client": {"permissions": {"disabledUserSignup": true}}}),
    );
    assert_eq!(patch_status, 200, "{patch_body}");
    assert!(
        signup_status == 200 || signup_status == 400,
        "unexpected signup response: {signup_status} {signup_body}"
    );
    let store_guard = store.lock().unwrap();
    if signup_status == 200 {
        assert!(store_guard
            .user_by_email("concurrent-project@example.com")
            .is_some());
        assert_eq!(
            store_guard.signup_quota().usage(
                "demo-app",
                "127.0.0.1",
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ),
            (1, 0)
        );
    } else {
        assert_eq!(signup_body["error"]["message"], "ADMIN_ONLY_OPERATION");
        assert!(store_guard
            .user_by_email("concurrent-project@example.com")
            .is_none());
        assert_eq!(
            store_guard.signup_quota().usage(
                "demo-app",
                "127.0.0.1",
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ),
            (0, 0)
        );
    }
    drop(store_guard);
    let final_config = admin(
        &state,
        "GET",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config",
        &Value::Null,
    );
    assert_eq!(final_config.0, 200, "{}", final_config.1);
    assert_eq!(
        final_config.1["client"]["permissions"]["disabledUserSignup"],
        true
    );
}

#[test]
fn signup_and_tenant_patch_have_a_bounded_shared_gate() {
    use fireemu_core_auth::signup_quota::{QuotaMode, SignupQuotaConfig};
    use fireemu_core_auth::store::AuthRegistry;

    let mut initial = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", initial.store.clone()));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    let tenant = registry.tenant_store("demo-app", "tenant-a").unwrap();
    tenant
        .lock()
        .unwrap()
        .set_signup_quota_config(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 1,
            ..SignupQuotaConfig::default()
        })
        .unwrap();
    initial.registry = Some(registry.clone());
    let state = Arc::new(initial);
    // Tenant management uses the project gate for metadata/store publication, so tenant
    // end-user admission must share that parent gate as well.
    let gate = registry.operation_gate("demo-app", None).unwrap();
    let ((signup_status, signup_body), (patch_status, patch_body)) = concurrent_signup_and_patch(
        state.clone(),
        &gate,
        &tenant,
        json!({
            "tenantId": "tenant-a",
            "email": "concurrent-tenant@example.com",
            "password": "password1",
        }),
        "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/tenant-a?updateMask=client.permissions.disabledUserSignup"
            .to_owned(),
        json!({
            "client": {"permissions": {"disabledUserSignup": true}},
        }),
    );
    assert_eq!(patch_status, 200, "{patch_body}");
    assert!(
        signup_status == 200 || signup_status == 400,
        "unexpected signup response: {signup_status} {signup_body}"
    );
    let store_guard = tenant.lock().unwrap();
    if signup_status == 200 {
        assert!(store_guard
            .user_by_email("concurrent-tenant@example.com")
            .is_some());
        assert_eq!(
            store_guard.signup_quota().usage(
                "demo-app",
                "127.0.0.1",
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ),
            (1, 0)
        );
    } else {
        assert_eq!(signup_body["error"]["message"], "ADMIN_ONLY_OPERATION");
        assert!(store_guard
            .user_by_email("concurrent-tenant@example.com")
            .is_none());
        assert_eq!(
            store_guard.signup_quota().usage(
                "demo-app",
                "127.0.0.1",
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ),
            (0, 0)
        );
    }
    drop(store_guard);
    let final_config = admin(
        &state,
        "GET",
        "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/tenant-a",
        &Value::Null,
    );
    assert_eq!(final_config.0, 200, "{}", final_config.1);
    assert_eq!(
        final_config.1["client"]["permissions"]["disabledUserSignup"],
        true
    );
}

#[test]
fn project_blocking_settings_get_patch_preserves_masked_values_and_rejects_atomically() {
    let settings = Arc::new(Mutex::new(json!({
        "triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/checkRegistration"},
            "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
        },
        "forwardInboundCredentials": {
            "idToken": false,
            "accessToken": true,
            "refreshToken": false
        }
    })));
    let mut s = state();
    s.blocking = Some(Arc::new(ConfigurableBlockingHook {
        settings: settings.clone(),
    }));
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";

    let (status, before) = admin(&s, "GET", path, &Value::Null);
    assert_eq!(status, 200, "{before}");
    assert_eq!(
        before["blockingFunctions"],
        settings.lock().unwrap().clone()
    );

    let (status, updated) = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=blockingFunctions.triggers.beforeCreate"),
        &json!({"blockingFunctions": {"triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/renamedCreate"}
        }}}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        updated["blockingFunctions"]["triggers"]["beforeCreate"]["functionUri"],
        "fireemu://functions/demo-app/us-central1/renamedCreate"
    );
    assert_eq!(
        updated["blockingFunctions"]["triggers"]["beforeSignIn"],
        before["blockingFunctions"]["triggers"]["beforeSignIn"]
    );
    assert_eq!(
        updated["blockingFunctions"]["forwardInboundCredentials"],
        before["blockingFunctions"]["forwardInboundCredentials"]
    );

    let (status, rejected) = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=blockingFunctions,client.permissions.disabledUserSignup"),
        &json!({
            "blockingFunctions": {"triggers": {
                "beforeCreate": {"functionUri": "https://example.invalid/hook"}
            }},
            "client": {"permissions": {"disabledUserSignup": true}}
        }),
    );
    assert_eq!(status, 400, "{rejected}");
    let (status, after) = admin(&s, "GET", path, &Value::Null);
    assert_eq!(status, 200, "{after}");
    assert_eq!(after["blockingFunctions"], updated["blockingFunctions"]);
    assert_eq!(after["client"]["permissions"]["disabledUserSignup"], false);

    let cleared = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=blockingFunctions"),
        &json!({"blockingFunctions": null}),
    );
    assert_eq!(cleared.0, 200, "{}", cleared.1);
    assert_eq!(cleared.1["blockingFunctions"], json!({}));
}

#[test]
fn project_blocking_complete_update_treats_nested_null_messages_as_absent_atomically() {
    let settings = Arc::new(Mutex::new(json!({
        "triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/checkRegistration"},
            "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
        },
        "forwardInboundCredentials": {
            "idToken": true,
            "accessToken": true,
            "refreshToken": true
        }
    })));
    let mut s = state();
    s.blocking = Some(Arc::new(ConfigurableBlockingHook {
        settings: settings.clone(),
    }));
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";

    let (status, before) = admin(&s, "GET", path, &Value::Null);
    assert_eq!(status, 200, "{before}");

    // A malformed non-null sibling must fail before the candidate is committed, leaving the
    // explicit configuration untouched.
    let (status, rejected) = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=blockingFunctions"),
        &json!({
            "blockingFunctions": {
                "triggers": null,
                "forwardInboundCredentials": {"idToken": "yes"}
            }
        }),
    );
    assert_eq!(status, 400, "{rejected}");
    let (status, unchanged) = admin(&s, "GET", path, &Value::Null);
    assert_eq!(status, 200, "{unchanged}");
    assert_eq!(unchanged["blockingFunctions"], before["blockingFunctions"]);
    assert_eq!(
        settings.lock().unwrap().clone(),
        before["blockingFunctions"]
    );

    // A complete ProtoJSON message treats null nested messages as absent. The replacement must
    // therefore select the default blocking state and disable all inbound credential forwarding.
    let (status, cleared) = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=blockingFunctions"),
        &json!({
            "blockingFunctions": {
                "triggers": null,
                "forwardInboundCredentials": null
            }
        }),
    );
    assert_eq!(status, 200, "{cleared}");
    assert_eq!(cleared["blockingFunctions"], json!({}));
    let (status, after) = admin(&s, "GET", path, &Value::Null);
    assert_eq!(status, 200, "{after}");
    assert_eq!(after["blockingFunctions"], json!({}));
    assert_eq!(settings.lock().unwrap().clone(), json!({}));
}

#[test]
fn project_blocking_settings_are_isolated_to_the_bridge_project() {
    let settings = Arc::new(Mutex::new(json!({
        "triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/checkRegistration"},
            "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
        }
    })));
    let mut s = state();
    s.blocking = Some(Arc::new(ConfigurableBlockingHook {
        settings: settings.clone(),
    }));
    s.allow_routed_projects = true;
    let other_store = Arc::new(Mutex::new(AuthStore::new(
        "other-app",
        SplitMix64::new(17),
        TotpPolicy::default(),
    )));
    s.registry = Some(Arc::new(AuthRegistry::new("other-app", other_store)));
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/other-app/config";

    let (status, before) = admin(&s, "GET", path, &Value::Null);
    assert_eq!(status, 200, "{before}");
    assert!(before.get("blockingFunctions").is_none());

    let (status, rejected) = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=blockingFunctions"),
        &json!({"blockingFunctions": {"triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/other-app/us-central1/other"},
            "beforeSignIn": null
        }}}),
    );
    assert_eq!(status, 400, "{rejected}");
    assert_eq!(rejected["error"]["message"], "FAILED_PRECONDITION");
    assert_eq!(
        settings.lock().unwrap()["triggers"]["beforeSignIn"],
        json!({"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"})
    );
}

#[test]
fn project_blocking_update_rolls_back_when_auth_namespace_commit_fails() {
    let settings = Arc::new(Mutex::new(json!({
        "triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/checkRegistration"},
            "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
        }
    })));
    let before = settings.lock().unwrap().clone();
    let mut s = state();
    s.blocking = Some(Arc::new(ConfigurableBlockingHook {
        settings: settings.clone(),
    }));

    // An Auth registry that does not contain the routed project forces the Auth-side commit to
    // fail after the blocking candidate has been accepted. The project-level blocking setting
    // must be restored as part of the failed cross-store update.
    let other_store = Arc::new(Mutex::new(AuthStore::new(
        "other-app",
        SplitMix64::new(19),
        TotpPolicy::default(),
    )));
    s.registry = Some(Arc::new(AuthRegistry::new("other-app", other_store)));
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let (status, rejected) = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=blockingFunctions"),
        &json!({"blockingFunctions": {"triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/changed"},
            "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
        }}}),
    );
    assert_eq!(status, 500, "{rejected}");
    assert_eq!(settings.lock().unwrap().clone(), before);
}

#[test]
fn project_blocking_rollback_does_not_overwrite_an_intervening_writer() {
    let settings = Arc::new(Mutex::new(json!({
        "triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/checkRegistration"},
            "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
        }
    })));
    let hook = Arc::new(InterveningBlockingSettingsWriter {
        settings: settings.clone(),
        intervene: AtomicBool::new(true),
    });
    let mut s = state();
    s.blocking = Some(hook);

    // An Auth registry that does not contain demo-app forces the paired Auth update to fail.
    // The hook has already committed a different setting in the configured writer's
    // interleaving. Rollback must leave that newer value intact.
    let other_store = Arc::new(Mutex::new(AuthStore::new(
        "other-app",
        SplitMix64::new(23),
        TotpPolicy::default(),
    )));
    s.registry = Some(Arc::new(AuthRegistry::new("other-app", other_store)));
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let (status, rejected) = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=blockingFunctions"),
        &json!({"blockingFunctions": {"triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/changed"},
            "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
        }}}),
    );
    assert_eq!(status, 500, "{rejected}");
    assert_eq!(
        settings.lock().unwrap().clone(),
        json!({
            "triggers": {
                "beforeCreate": null,
                "beforeSignIn": null,
            }
        })
    );
}

#[test]
fn project_blocking_updates_are_serialized_before_the_candidate_is_published() {
    let settings = Arc::new(Mutex::new(json!({
        "triggers": {
            "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/checkRegistration"},
            "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
        }
    })));
    let probe = Arc::new(BlockingSettingsGateProbe {
        settings,
        entered: Arc::new(AtomicBool::new(false)),
        updates: Arc::new(AtomicUsize::new(0)),
        release: Arc::new(AtomicBool::new(false)),
    });
    let mut base = state();
    base.blocking = Some(probe.clone());
    base.registry = Some(Arc::new(AuthRegistry::new("demo-app", base.store.clone())));
    let state = Arc::new(base);
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let entered = probe.entered.clone();
    let release = probe.release.clone();
    let updates = probe.updates.clone();

    std::thread::scope(|scope| {
        let first_state = Arc::clone(&state);
        scope.spawn(move || {
            let response = admin(
                &first_state,
                "PATCH",
                &format!("{path}?updateMask=blockingFunctions"),
                &json!({"blockingFunctions": {"triggers": {
                    "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/first"},
                    "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
                }}}),
            );
            assert_eq!(response.0, 200, "{}", response.1);
        });

        let entered_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !entered.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < entered_deadline,
                "the first blocking settings update did not reach the probe"
            );
            std::thread::yield_now();
        }

        let second_state = Arc::clone(&state);
        let second = scope.spawn(move || {
            admin(
                &second_state,
                "PATCH",
                &format!("{path}?updateMask=blockingFunctions"),
                &json!({"blockingFunctions": {"triggers": {
                    "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/second"},
                    "beforeSignIn": {"functionUri": "fireemu://functions/demo-app/us-central1/checkSignIn"}
                }}}),
            )
        });

        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(
            updates.load(Ordering::SeqCst),
            1,
            "a second PATCH reached the blocking writer before the first committed"
        );
        release.store(true, Ordering::SeqCst);
        let response = second.join().unwrap();
        assert_eq!(response.0, 200, "{}", response.1);
    });
}

struct ReentrantAdminHook {
    state: std::sync::Weak<AuthState>,
    mutate: Arc<std::sync::atomic::AtomicBool>,
}

struct ReentrantProjectConfigHook {
    state: std::sync::Weak<AuthState>,
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

impl AuthBlockingHook for ReentrantProjectConfigHook {
    fn invoke(
        &self,
        event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        if event != BlockingAuthEvent::BeforeCreate {
            return Ok(json!({}));
        }
        let state = self
            .state
            .upgrade()
            .ok_or_else(BlockingFunctionFailure::unhandled)?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let nested_state = state.clone();
        std::thread::spawn(move || {
            let response = handle_with(
                &nested_state,
                "PATCH",
                "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=signIn.allowDuplicateEmails",
                &owner(),
                &json!({"signIn": {"allowDuplicateEmails": true}}),
            );
            let _ = sender.send(response);
        });
        let response = receiver
            .recv_timeout(std::time::Duration::from_millis(250))
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        if response.status != 200 {
            return Err(BlockingFunctionFailure::unhandled());
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
fn blocking_auth_can_reenter_project_config_without_deadlocking() {
    let state = Arc::new_cyclic(|weak| {
        let mut state = state();
        state.blocking = Some(Arc::new(ReentrantProjectConfigHook {
            state: weak.clone(),
        }));
        state
    });

    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "config-callback@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{body}");

    let (status, config) = admin(
        &state,
        "GET",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config",
        &Value::Null,
    );
    assert_eq!(status, 200, "{config}");
    assert_eq!(config["signIn"]["allowDuplicateEmails"], true);
}

#[test]
fn an_unbound_blocking_hook_with_a_registry_default_store_does_not_deadlock() {
    use std::sync::mpsc::sync_channel;
    use std::time::Duration;

    let mut auth = state();
    auth.registry = Some(Arc::new(AuthRegistry::new("demo-app", auth.store.clone())));
    auth.blocking = Some(Arc::new(BeforeCreateOnlySuccessfulHook(Arc::new(
        Mutex::new(Vec::new()),
    ))));
    let auth = Arc::new(auth);
    let (sender, receiver) = sync_channel(1);
    let request_state = auth.clone();
    std::thread::spawn(move || {
        sender
            .send(post(
                &request_state,
                &format!("{V1}/accounts:signUp"),
                &json!({"email": "registry-default@example.com", "password": "hunter22"}),
            ))
            .unwrap();
    });

    let (status, body) = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("an unbound hook must not re-lock the selected default store");
    assert_eq!(status, 200, "{body}");
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
fn a_poisoned_namespace_operation_gate_fails_closed_before_authentication() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut state = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    // Tenant management and tenant authentication share the project namespace gate.
    let gate = registry.operation_gate("demo-app", None).unwrap();
    let poison = gate.clone();
    let _ = std::thread::spawn(move || {
        let _guard = poison.lock().unwrap();
        panic!("poison the tenant operation gate");
    })
    .join();
    state.registry = Some(registry.clone());
    state.blocking = Some(Arc::new(UpdatingBlockingHook));

    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "customer", "email": "blocked@example.test", "password": "hunter22"}),
    );

    assert_eq!(status, 500, "{body}");
}

#[test]
fn unbound_blocking_auth_runs_for_default_but_not_routed_projects() {
    use fireemu_core_auth::store::AuthRegistry;

    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut state = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    assert!(registry.register(
        "demo-worker",
        AuthStore::new("demo-worker", SplitMix64::new(6), TotpPolicy::default())
    ));
    state.registry = Some(registry.clone());
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
        ]
    );
    assert!(registry
        .store_for("demo-worker")
        .unwrap()
        .lock()
        .unwrap()
        .user_by_email("worker@example.com")
        .is_some());
}

#[test]
fn blocking_auth_revision_drift_between_plan_and_dispatch_is_rejected() {
    let auth = Arc::new({
        let mut auth = state();
        auth.blocking = Some(Arc::new(RevisionBumpBeforeDispatchHook {
            revision: AtomicUsize::new(0),
            revision_calls: AtomicUsize::new(0),
        }));
        auth
    });
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let request_auth = auth.clone();
    std::thread::spawn(move || {
        sender
            .send(post(
                &request_auth,
                &format!("{V1}/accounts:signUp"),
                &json!({"email": "revision-drift@example.com", "password": "hunter22"}),
            ))
            .unwrap();
    });
    let (status, body) = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("candidate revision drift must not deadlock reservation cleanup");
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["error"]["message"],
        "BLOCKING_FUNCTION_CONFIGURATION_CHANGED"
    );
    assert_eq!(auth.store.lock().unwrap().user_count(), 0);
    let mut store = auth.store.lock().unwrap().clone();
    let fresh_id = store.reserve_next_generated_local_id();
    let mut clean = AuthStore::new("demo-app", SplitMix64::new(5), TotpPolicy::default());
    assert_eq!(fresh_id, clean.reserve_next_generated_local_id());
}

#[test]
fn blocking_auth_revision_drift_after_callback_before_commit_is_rejected() {
    let hook = Arc::new(RevisionChangeAfterPostCallbackHook {
        revision: AtomicUsize::new(0),
        revision_calls: AtomicUsize::new(0),
        post_callback_checked: AtomicBool::new(false),
    });
    let auth = Arc::new({
        let mut auth = state();
        auth.blocking = Some(hook.clone());
        auth
    });
    let commit_gate = auth.operation_gate.lock().unwrap();
    let request_auth = auth.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        sender
            .send(post(
                &request_auth,
                &format!("{V1}/accounts:signUp"),
                &json!({"email": "commit-revision-drift@example.com", "password": "hunter22"}),
            ))
            .unwrap();
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while !hook.post_callback_checked.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "blocking request did not reach its post-callback revision check"
        );
        std::thread::yield_now();
    }
    hook.revision.store(1, Ordering::SeqCst);
    drop(commit_gate);
    let (status, body) = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("commit revision drift must not leave the request waiting");
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["error"]["message"],
        "BLOCKING_FUNCTION_CONFIGURATION_CHANGED"
    );
    assert_eq!(auth.store.lock().unwrap().user_count(), 0);
    let mut store = auth.store.lock().unwrap().clone();
    let fresh_id = store.reserve_next_generated_local_id();
    let mut clean = AuthStore::new("demo-app", SplitMix64::new(5), TotpPolicy::default());
    assert_eq!(fresh_id, clean.reserve_next_generated_local_id());
}

#[test]
fn emulator_clear_rejects_a_paused_blocking_candidate_and_allows_a_fresh_id() {
    use std::sync::mpsc::sync_channel;
    use std::time::Duration;

    let hook = Arc::new(DelayedBlockingHook {
        entered: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        limit: 1,
        release: AtomicBool::new(false),
    });
    let mut auth = state();
    auth.blocking = Some(hook.clone());
    let state = Arc::new(auth);
    let (sender, receiver) = sync_channel(1);
    let request_state = state.clone();
    std::thread::spawn(move || {
        sender
            .send(post(
                &request_state,
                &format!("{V1}/accounts:signUp"),
                &json!({"email": "stale@example.com", "password": "hunter22"}),
            ))
            .unwrap();
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while hook.entered.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "blocking hook did not pause the candidate"
        );
        std::thread::yield_now();
    }

    let cleared = handle(
        &state,
        "DELETE",
        "/emulator/v1/projects/demo-app/accounts",
        &Value::Null,
    );
    assert_eq!(cleared.status, 200, "{}", cleared.body);
    hook.release.store(true, Ordering::SeqCst);
    let (status, body) = receiver
        .recv_timeout(Duration::from_secs(1))
        .expect("paused candidate must finish after clear");
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["error"]["message"], "AUTH_STATE_RESET");
    assert_eq!(state.store.lock().unwrap().user_count(), 0);

    let (status, body) = post(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "fresh@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(state.store.lock().unwrap().user_count(), 1);
}

#[test]
fn blocking_auth_disabled_to_enabled_transition_returns_a_retryable_conflict() {
    let hook = Arc::new(ToggleHandlesHook {
        calls: AtomicUsize::new(0),
        enabled_after_initial: true,
    });
    let mut auth = state();
    auth.blocking = Some(hook);
    let (status, body) = post(
        &auth,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "toggle-on@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["error"]["message"],
        "BLOCKING_FUNCTION_CONFIGURATION_CHANGED"
    );
    assert_eq!(auth.store.lock().unwrap().user_count(), 0);
}

#[test]
fn blocking_auth_enabled_to_disabled_transition_returns_a_retryable_conflict() {
    let hook = Arc::new(ToggleHandlesHook {
        calls: AtomicUsize::new(0),
        enabled_after_initial: false,
    });
    let mut auth = state();
    auth.blocking = Some(hook);
    let (status, body) = post(
        &auth,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "toggle-off@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["error"]["message"],
        "BLOCKING_FUNCTION_CONFIGURATION_CHANGED"
    );
    assert_eq!(auth.store.lock().unwrap().user_count(), 0);
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

const UNREGISTERED_CALLER: &str = "Method doesn't allow unregistered callers (callers without established identity). Please use API Key or other form of API consumer identity to call this API.";

/// Production refuses an Admin route called without an `Authorization` header by whether the
/// request still carries an API key, and a strict-profile client route called with neither
/// (sandbox recording 2026-09-23, `auth-account/privilege/credentials`).
#[test]
fn requests_without_credentials_are_refused_with_production_shapes() {
    for s in [state(), strict_state()] {
        let keyed = post(
            &s,
            &format!("{ADMIN}/accounts:lookup?key=fake-api-key"),
            &json!({"localId": ["x"]}),
        );
        let insufficient =
            "INSUFFICIENT_PERMISSION : Only authenticated requests can specify target_project_id.";
        assert_eq!(keyed.0, 400, "{}", keyed.1);
        assert_eq!(
            keyed.1,
            json!({"error": {"code": 400, "message": insufficient, "errors": [
                {"message": insufficient, "domain": "global", "reason": "invalid"}
            ]}})
        );
        let bare = post(
            &s,
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": ["x"]}),
        );
        assert_eq!(bare.0, 403, "{}", bare.1);
        assert_eq!(
            bare.1,
            json!({"error": {"code": 403, "message": UNREGISTERED_CALLER, "errors": [
                {"message": UNREGISTERED_CALLER, "domain": "global", "reason": "forbidden"}
            ], "status": "PERMISSION_DENIED"}})
        );
    }
    let strict = strict_state();
    let keyless = handle(
        &strict,
        "POST",
        &format!("{V1}/accounts:signUp"),
        &json!({"returnSecureToken": true}),
    );
    assert_eq!(keyless.status, 403, "{}", keyless.body);
    assert_eq!(keyless.body["error"]["message"], UNREGISTERED_CALLER);
    assert_eq!(keyless.body["error"]["status"], "PERMISSION_DENIED");
    let keyed = post(
        &strict,
        &format!("{V1}/accounts:signUp?key=fake-api-key"),
        &json!({"returnSecureToken": true}),
    );
    assert_eq!(keyed.0, 200, "{}", keyed.1);
    let owner_call = handle_with(
        &strict,
        "POST",
        &format!("{V1}/accounts:lookup"),
        &owner(),
        &json!({"localId": ["x"]}),
    );
    assert_ne!(owner_call.status, 403, "{}", owner_call.body);
    let emulator = post(
        &state(),
        &format!("{V1}/accounts:signUp"),
        &json!({"returnSecureToken": true}),
    );
    assert_eq!(emulator.0, 200, "{}", emulator.1);
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
    assert_eq!(anon.status, 403);
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
#[allow(clippy::too_many_lines)]
fn oidc_provider_config_crud_is_namespaced_and_refusals_do_not_mutate() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    s.registry = Some(registry);
    let project_collection =
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/oauthIdpConfigs";
    let project_item = |id: &str| format!("{project_collection}/{id}");
    let config = json!({
        "clientId": "project-client",
        "issuer": "https://issuer.project.example",
        "displayName": "Project OIDC",
        "enabled": true,
        "responseType": {"idToken": true}
    });

    let created = handle_with(
        &s,
        "POST",
        &format!("{project_collection}?oauthIdpConfigId=oidc.shared"),
        &owner(),
        &config,
    );
    assert_eq!(created.status, 200, "{}", created.body);
    assert_eq!(
        created.body["name"],
        "projects/demo-app/oauthIdpConfigs/oidc.shared"
    );
    assert_eq!(created.body["enabled"], true);

    let refused = handle_with(
        &s,
        "PATCH",
        &format!("{}?updateMask=responseType", project_item("oidc.shared")),
        &owner(),
        &json!({"responseType": {"idToken": true, "code": true}}),
    );
    assert_eq!(refused.status, 400, "{}", refused.body);
    let unchanged = handle_with(
        &s,
        "GET",
        &project_item("oidc.shared"),
        &owner(),
        &json!({}),
    );
    assert_eq!(unchanged.status, 200, "{}", unchanged.body);
    assert_eq!(unchanged.body["responseType"]["idToken"], true);
    assert_eq!(unchanged.body["responseType"]["code"], false);

    let tenant_collection =
        "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/customer/oauthIdpConfigs";
    let tenant_created = handle_with(
        &s,
        "POST",
        &format!("{tenant_collection}?oauthIdpConfigId=oidc.shared"),
        &owner(),
        &json!({
            "clientId": "tenant-client",
            "issuer": "https://issuer.tenant.example",
            "enabled": false
        }),
    );
    assert_eq!(tenant_created.status, 200, "{}", tenant_created.body);
    assert_eq!(
        tenant_created.body["name"],
        "projects/demo-app/tenants/customer/oauthIdpConfigs/oidc.shared"
    );
    let tenant_read = handle_with(
        &s,
        "GET",
        &format!("{tenant_collection}/oidc.shared"),
        &owner(),
        &json!({}),
    );
    assert_eq!(tenant_read.status, 200, "{}", tenant_read.body);
    assert_eq!(tenant_read.body["clientId"], "tenant-client");
    let second = handle_with(
        &s,
        "POST",
        &format!("{project_collection}?oauthIdpConfigId=oidc.second"),
        &owner(),
        &json!({"clientId": "second", "issuer": "https://issuer.second.example"}),
    );
    assert_eq!(second.status, 200, "{}", second.body);
    let listed = handle_with(&s, "GET", project_collection, &owner(), &json!({}));
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_eq!(listed.body["oauthIdpConfigs"].as_array().unwrap().len(), 2);
    let first_page = handle_with(
        &s,
        "GET",
        &format!("{project_collection}?pageSize=1"),
        &owner(),
        &json!({}),
    );
    assert_eq!(first_page.status, 200, "{}", first_page.body);
    assert_eq!(
        first_page.body["oauthIdpConfigs"].as_array().unwrap().len(),
        1
    );
    let next_page = handle_with(
        &s,
        "GET",
        &format!(
            "{project_collection}?pageSize=1&pageToken={}",
            first_page.body["nextPageToken"].as_str().unwrap()
        ),
        &owner(),
        &json!({}),
    );
    assert_eq!(next_page.status, 200, "{}", next_page.body);
    assert_eq!(
        next_page.body["oauthIdpConfigs"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        first_page.body["oauthIdpConfigs"][0]["name"],
        "projects/demo-app/oauthIdpConfigs/oidc.shared"
    );
    assert_eq!(
        next_page.body["oauthIdpConfigs"][0]["name"],
        "projects/demo-app/oauthIdpConfigs/oidc.second"
    );
    assert_ne!(
        first_page.body["oauthIdpConfigs"][0]["name"],
        next_page.body["oauthIdpConfigs"][0]["name"]
    );
    let deleted = handle_with(
        &s,
        "DELETE",
        &project_item("oidc.shared"),
        &owner(),
        &json!({}),
    );
    assert_eq!(deleted.status, 200, "{}", deleted.body);
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &project_item("oidc.shared"),
            &owner(),
            &json!({})
        )
        .status,
        404
    );
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &project_item("oidc.missing"),
            &owner(),
            &json!({})
        )
        .status,
        404
    );
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &format!("{tenant_collection}/oidc.missing"),
            &owner(),
            &json!({})
        )
        .status,
        404
    );
    assert_eq!(
        handle_with(
            &s,
            "GET",
            "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/missing/oauthIdpConfigs",
            &owner(),
            &json!({})
        )
        .status,
        404
    );
}

#[test]
fn oidc_provider_update_rejects_ambiguous_update_masks_atomically() {
    let s = state();
    let collection = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/oauthIdpConfigs";
    let item = format!("{collection}/oidc.ambiguous");
    let created = handle_with(
        &s,
        "POST",
        &format!("{collection}?oauthIdpConfigId=oidc.ambiguous"),
        &owner(),
        &json!({
            "clientId": "client",
            "issuer": "https://issuer.example",
            "displayName": "Original",
            "enabled": true
        }),
    );
    assert_eq!(created.status, 200, "{}", created.body);

    for query in [
        "updateMask=enabled&updateMask=displayName",
        "updateMask=enabled,enabled",
    ] {
        let refused = handle_with(
            &s,
            "PATCH",
            &format!("{item}?{query}"),
            &owner(),
            &json!({"displayName": "Changed", "enabled": false}),
        );
        assert_eq!(refused.status, 400, "{}", refused.body);
        let unchanged = handle_with(&s, "GET", &item, &owner(), &json!({}));
        assert_eq!(unchanged.status, 200, "{}", unchanged.body);
        assert_eq!(unchanged.body["displayName"], "Original");
        assert_eq!(unchanged.body["enabled"], true);
    }
}

#[test]
fn project_provider_configs_accept_client_v2_paths() {
    let s = state();
    let oidc = "/identitytoolkit.googleapis.com/v2/projects/demo-app/oauthIdpConfigs";
    let saml = "/identitytoolkit.googleapis.com/v2/projects/demo-app/inboundSamlConfigs";
    let created_oidc = handle_with(
        &s,
        "POST",
        &format!("{oidc}?oauthIdpConfigId=oidc.client"),
        &owner(),
        &json!({"clientId": "client", "issuer": "https://issuer.example"}),
    );
    assert_eq!(created_oidc.status, 200, "{}", created_oidc.body);
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &format!("{oidc}/oidc.client"),
            &owner(),
            &json!({})
        )
        .status,
        200
    );
    assert_eq!(
        handle_with(&s, "GET", oidc, &owner(), &json!({})).body["oauthIdpConfigs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let created_saml = handle_with(
        &s,
        "POST",
        &format!("{saml}?inboundSamlConfigId=saml.client"),
        &owner(),
        &json!({
            "idpConfig": {
                "idpEntityId": "entity",
                "ssoUrl": "https://idp.example/sso",
                "idpCertificates": [{"x509Certificate": "CERT"}]
            },
            "spConfig": {
                "spEntityId": "sp",
                "callbackUri": "https://sp.example/callback"
            }
        }),
    );
    assert_eq!(created_saml.status, 200, "{}", created_saml.body);
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &format!("{saml}/saml.client"),
            &owner(),
            &json!({})
        )
        .status,
        200
    );
}

#[test]
fn inbound_saml_provider_config_crud_preserves_configuration_and_rejects_bad_ids() {
    let s = state();
    let collection =
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/inboundSamlConfigs";
    let item = |id: &str| format!("{collection}/{id}");
    let created = handle_with(
        &s,
        "POST",
        &format!("{collection}?inboundSamlConfigId=saml.corp"),
        &owner(),
        &json!({
            "displayName": "Corporate SAML",
            "enabled": true,
            "idpConfig": {
                "idpEntityId": "https://idp.example/entity",
                "ssoUrl": "https://idp.example/sso",
                "idpCertificates": [{"x509Certificate": "CERT"}],
                "signRequest": true
            },
            "spConfig": {
                "spEntityId": "https://sp.example/entity",
                "callbackUri": "https://sp.example/callback"
            }
        }),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    assert_eq!(
        created.body["name"],
        "projects/demo-app/inboundSamlConfigs/saml.corp"
    );
    assert_eq!(
        created.body["idpConfig"]["idpEntityId"],
        "https://idp.example/entity"
    );
    assert_eq!(
        created.body["spConfig"]["callbackUri"],
        "https://sp.example/callback"
    );

    let malformed = handle_with(
        &s,
        "GET",
        &format!("{collection}/bad/id"),
        &owner(),
        &json!({}),
    );
    assert_eq!(malformed.status, 404);
    let still_there = handle_with(&s, "GET", &item("saml.corp"), &owner(), &json!({}));
    assert_eq!(still_there.status, 200, "{}", still_there.body);
}

#[test]
#[allow(clippy::too_many_lines)]
fn inbound_saml_sign_request_mask_defaults_and_is_atomic_for_project_and_tenant() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    s.registry = Some(registry);
    let collections = [
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/inboundSamlConfigs",
        "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/customer/inboundSamlConfigs",
    ];
    for (index, collection) in collections.into_iter().enumerate() {
        let id = if index == 0 {
            "saml.project"
        } else {
            "saml.tenant"
        };
        let item = format!("{collection}/{id}");
        let create = handle_with(
            &s,
            "POST",
            &format!("{collection}?inboundSamlConfigId={id}"),
            &owner(),
            &json!({
                "displayName": "Original",
                "idpConfig": {
                    "idpEntityId": "entity",
                    "ssoUrl": "https://idp.example/sso",
                    "idpCertificates": [{"x509Certificate": "CERT"}],
                    "signRequest": true
                },
                "spConfig": {
                    "spEntityId": "sp",
                    "callbackUri": "https://sp.example/callback"
                }
            }),
        );
        assert_eq!(create.status, 200, "{}", create.body);

        for body in [json!("wrong shape"), json!([]), Value::Null] {
            let refused = handle_with(
                &s,
                "PATCH",
                &format!("{item}?updateMask=idpConfig.signRequest"),
                &owner(),
                &body,
            );
            assert_eq!(refused.status, 400, "{body}");
            let unchanged = handle_with(&s, "GET", &item, &owner(), &json!({}));
            assert_eq!(unchanged.status, 200, "{}", unchanged.body);
            assert_eq!(unchanged.body["idpConfig"]["signRequest"], true);
        }

        let encoded = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask=%69dpConfig%2EsignRequest"),
            &owner(),
            &json!({"idpConfig": {"signRequest": true}}),
        );
        assert_eq!(encoded.status, 200, "{}", encoded.body);
        for mask in [
            "%69dpConfig%2EsignRequest%2C%69dpConfig%2EsignRequest",
            "%ZZ",
        ] {
            let refused = handle_with(
                &s,
                "PATCH",
                &format!("{item}?updateMask={mask}"),
                &owner(),
                &json!({"idpConfig": {"signRequest": false}}),
            );
            assert_eq!(refused.status, 400, "mask={mask}: {}", refused.body);
            let unchanged = handle_with(&s, "GET", &item, &owner(), &json!({}));
            assert_eq!(unchanged.status, 200, "{}", unchanged.body);
            assert_eq!(unchanged.body["idpConfig"]["signRequest"], true);
        }
        let repeated = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask=idpConfig.signRequest&updateMask=displayName"),
            &owner(),
            &json!({
                "displayName": "Changed",
                "idpConfig": {"signRequest": false}
            }),
        );
        assert_eq!(repeated.status, 400, "{}", repeated.body);
        let unchanged = handle_with(&s, "GET", &item, &owner(), &json!({}));
        assert_eq!(unchanged.status, 200, "{}", unchanged.body);
        assert_eq!(unchanged.body["displayName"], "Original");
        assert_eq!(unchanged.body["idpConfig"]["signRequest"], true);

        let parent_no_presence = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask=idpConfig"),
            &owner(),
            &json!({"idpConfig": {}}),
        );
        assert_eq!(
            parent_no_presence.status, 200,
            "{}",
            parent_no_presence.body
        );
        assert_eq!(parent_no_presence.body["idpConfig"]["signRequest"], true);

        let omitted_leaf = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask=idpConfig.signRequest"),
            &owner(),
            &json!({"idpConfig": {}}),
        );
        assert_eq!(omitted_leaf.status, 200, "{}", omitted_leaf.body);
        assert_eq!(omitted_leaf.body["idpConfig"]["signRequest"], false);

        let explicit_true = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask=idpConfig.signRequest"),
            &owner(),
            &json!({"idpConfig": {"signRequest": true}}),
        );
        assert_eq!(explicit_true.status, 200, "{}", explicit_true.body);

        let outside_mask = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask=idpConfig.signRequest"),
            &owner(),
            &json!({
                "displayName": "Changed",
                "idpConfig": {"signRequest": true, "idpEntityId": "changed"}
            }),
        );
        assert_eq!(outside_mask.status, 200, "{}", outside_mask.body);
        assert_eq!(outside_mask.body["displayName"], "Original");
        assert_eq!(outside_mask.body["idpConfig"]["idpEntityId"], "entity");
        assert_eq!(outside_mask.body["idpConfig"]["signRequest"], true);

        let invalid = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask=idpConfig.signRequest"),
            &owner(),
            &json!({"idpConfig": {"signRequest": "wrong type"}}),
        );
        assert_eq!(invalid.status, 400, "{}", invalid.body);
        let unchanged = handle_with(&s, "GET", &item, &owner(), &json!({}));
        assert_eq!(unchanged.status, 200, "{}", unchanged.body);
        assert_eq!(unchanged.body["displayName"], "Original");
        assert_eq!(unchanged.body["idpConfig"]["idpEntityId"], "entity");
        assert_eq!(unchanged.body["idpConfig"]["signRequest"], true);

        let explicit_false = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask=idpConfig.signRequest"),
            &owner(),
            &json!({"idpConfig": {"signRequest": false}}),
        );
        assert_eq!(explicit_false.status, 200, "{}", explicit_false.body);
        assert_eq!(explicit_false.body["idpConfig"]["signRequest"], false);

        let empty = handle_with(
            &s,
            "PATCH",
            &format!("{item}?updateMask="),
            &owner(),
            &json!({"idpConfig": {"signRequest": true}}),
        );
        assert_eq!(empty.status, 200, "{}", empty.body);
        assert_eq!(empty.body["idpConfig"]["signRequest"], false);

        for mask in [
            "idpConfig.unknown",
            "idpConfig.signRequest,idpConfig.signRequest",
            "idpConfig.signRequest,,displayName",
        ] {
            let refused = handle_with(
                &s,
                "PATCH",
                &format!("{item}?updateMask={mask}"),
                &owner(),
                &json!({
                    "displayName": "Changed",
                    "idpConfig": {"signRequest": true}
                }),
            );
            assert_eq!(refused.status, 400, "mask={mask}: {}", refused.body);
        }
        let after_bad_masks = handle_with(&s, "GET", &item, &owner(), &json!({}));
        assert_eq!(after_bad_masks.status, 200, "{}", after_bad_masks.body);
        assert_eq!(after_bad_masks.body["displayName"], "Original");
        assert_eq!(after_bad_masks.body["idpConfig"]["signRequest"], false);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn provider_ids_and_semantic_validation_are_kind_specific_and_atomic() {
    let s = state();
    let oidc = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/oauthIdpConfigs";
    let saml = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/inboundSamlConfigs";
    assert_eq!(
        handle_with(&s, "GET", oidc, &RequestHeaders::default(), &json!({})).status,
        403
    );
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &oidc.replace("demo-app", "other-project"),
            &owner(),
            &json!({})
        )
        .status,
        400
    );
    let invalid_ids = [
        (
            "oauthIdpConfigId=shared",
            json!({"clientId": "c", "issuer": "https://idp.example"}),
        ),
        (
            "oauthIdpConfigId=saml.wrong",
            json!({"clientId": "c", "issuer": "https://idp.example"}),
        ),
        (
            "oauthIdpConfigId=oidc.",
            json!({"clientId": "c", "issuer": "https://idp.example"}),
        ),
        ("inboundSamlConfigId=oidc.wrong", json!({})),
        ("inboundSamlConfigId=saml.", json!({})),
    ];
    for (query, body) in invalid_ids {
        let path = if query.starts_with("inbound") {
            saml
        } else {
            oidc
        };
        assert_eq!(
            handle_with(&s, "POST", &format!("{path}?{query}"), &owner(), &body).status,
            400
        );
    }
    let valid = handle_with(
        &s,
        "POST",
        &format!("{oidc}?oauthIdpConfigId=oidc.defaults"),
        &owner(),
        &json!({"clientId": "c", "issuer": "https://idp.example", "clientSecret": "secret-value"}),
    );
    assert_eq!(valid.status, 200, "{}", valid.body);
    assert_eq!(valid.body["responseType"]["idToken"], true);
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &format!("{oidc}/saml.wrong"),
            &owner(),
            &json!({})
        )
        .status,
        400
    );
    assert_eq!(
        handle_with(
            &s,
            "GET",
            &format!("{oidc}/oidc.%2Fencoded"),
            &owner(),
            &json!({})
        )
        .status,
        400
    );

    let no_mask = handle_with(
        &s,
        "PATCH",
        &format!("{oidc}/oidc.defaults"),
        &owner(),
        &json!({"issuer": "not-a-url"}),
    );
    assert_eq!(no_mask.status, 200, "{}", no_mask.body);
    for (mask, body) in [
        ("responseType", json!({"responseType": {"token": true}})),
        (
            "responseType",
            json!({"responseType": {"idToken": false, "code": false}}),
        ),
        (
            "responseType",
            json!({"responseType": {"idToken": true, "code": true}}),
        ),
        (
            "responseType,clientSecret",
            json!({"responseType": {"code": true}, "clientSecret": ""}),
        ),
        ("issuer", json!({"issuer": "not-a-url"})),
    ] {
        let refused = handle_with(
            &s,
            "PATCH",
            &format!("{oidc}/oidc.defaults?updateMask={mask}"),
            &owner(),
            &body,
        );
        assert_eq!(refused.status, 400, "{}", refused.body);
    }
    let nested_token = handle_with(
        &s,
        "PATCH",
        &format!("{oidc}/oidc.defaults?updateMask=responseType.token"),
        &owner(),
        &json!({"responseType": {"token": true}}),
    );
    assert_eq!(nested_token.status, 400, "{}", nested_token.body);
    let nested_all_false = handle_with(
        &s,
        "PATCH",
        &format!("{oidc}/oidc.defaults?updateMask=responseType.idToken"),
        &owner(),
        &json!({"responseType": {"idToken": false}}),
    );
    assert_eq!(nested_all_false.status, 400, "{}", nested_all_false.body);
    let valid_partial = handle_with(
        &s,
        "PATCH",
        &format!("{oidc}/oidc.defaults?updateMask=responseType.code"),
        &owner(),
        &json!({"responseType": {"code": false}}),
    );
    assert_eq!(valid_partial.status, 200, "{}", valid_partial.body);
    let unchanged = handle_with(
        &s,
        "GET",
        &format!("{oidc}/oidc.defaults"),
        &owner(),
        &json!({}),
    );
    assert_eq!(unchanged.status, 200, "{}", unchanged.body);
    assert_eq!(unchanged.body["issuer"], "https://idp.example");
    assert!(!format!("{:?}", s.store.lock().unwrap()).contains("secret-value"));

    let saml_refused = handle_with(
        &s,
        "POST",
        &format!("{saml}?inboundSamlConfigId=saml.empty"),
        &owner(),
        &json!({
            "idpConfig": {"idpEntityId": "entity", "ssoUrl": "not-a-url", "idpCertificates": []},
            "spConfig": {"spEntityId": "sp", "callbackUri": "not-a-url"}
        }),
    );
    assert_eq!(saml_refused.status, 400, "{}", saml_refused.body);
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
        &json!({"localId": "u-alice", "email": "Alice@example.com", "password": "password1", "displayName": "Alice"}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["localId"], "u-alice");
    let (status, duplicate) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "u-alice-duplicate", "email": "alice@example.com"}),
    );
    assert_eq!(status, 400, "{duplicate}");
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
#[allow(clippy::too_many_lines)]
fn batch_import_rejects_malformed_typed_fields_without_creating_rows() {
    let s = state();
    for (local_id, field, value) in [
        ("batch-bad-mfa", "mfaInfo", json!("not-an-array")),
        ("batch-bad-provider", "providerUserInfo", json!({})),
        ("batch-bad-mfa-entry", "mfaInfo", json!([null])),
        (
            "batch-bad-mfa-string-entry",
            "mfaInfo",
            json!(["not-an-object"]),
        ),
        (
            "batch-bad-mfa-array-entry",
            "mfaInfo",
            json!([["not-an-object"]]),
        ),
        (
            "batch-bad-provider-entry",
            "providerUserInfo",
            json!([null]),
        ),
        (
            "batch-bad-provider-string-entry",
            "providerUserInfo",
            json!(["not-an-object"]),
        ),
        (
            "batch-bad-provider-array-entry",
            "providerUserInfo",
            json!([["not-an-object"]]),
        ),
    ] {
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:batchCreate"),
            &json!({"users": [{"localId": local_id, field: value}]}),
        );
        assert_eq!(status, 200, "{response}");
        assert_eq!(
            response["error"].as_array().map(Vec::len),
            Some(1),
            "{response}"
        );
        assert!(s.store.lock().unwrap().user_by_id(local_id).is_none());
    }
    // Timestamps are int64 fields of the request: a malformed one refuses the whole request
    // (sandbox recording 2026-09-23, `values#import-created-at-invalid`).
    for (local_id, field, value) in [
        ("batch-bad-created", "createdAt", json!("not-a-timestamp")),
        ("batch-bad-login", "lastLoginAt", json!(false)),
    ] {
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:batchCreate"),
            &json!({"users": [{"localId": local_id, field: value}]}),
        );
        assert_eq!(status, 400, "{response}");
        assert_eq!(
            response["error"]["status"], "INVALID_ARGUMENT",
            "{response}"
        );
        assert!(s.store.lock().unwrap().user_by_id(local_id).is_none());
    }

    let (status, response) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"allowOverwrite": "yes", "users": [{"localId": "batch-bad-overwrite"}]}),
    );
    assert_eq!(status, 400, "{response}");
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("batch-bad-overwrite")
        .is_none());

    // A malformed row is reported by index while neighboring valid rows are still imported.
    let (status, response) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({
            "users": [
                {"localId": "batch-partial-valid", "email": "partial-valid@example.com"},
                {"localId": "batch-partial-invalid", "mfaInfo": ["not-an-object"]},
                {"localId": "batch-partial-valid-after", "email": "partial-valid-after@example.com"}
            ]
        }),
    );
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        response["error"].as_array().map(Vec::len),
        Some(1),
        "{response}"
    );
    assert_eq!(response["error"][0]["index"], 1, "{response}");
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("batch-partial-valid")
        .is_some());
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("batch-partial-invalid")
        .is_none());
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("batch-partial-valid-after")
        .is_some());
}

#[test]
fn batch_import_treats_null_optional_fields_as_unset() {
    let s = state();
    let (status, response) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({
            "allowOverwrite": null,
            "users": [{
                "localId": "batch-null-fields",
                "email": "batch-null-fields@example.com",
                "providerUserInfo": null,
                "mfaInfo": null,
                "createdAt": null,
                "lastLoginAt": null
            }]
        }),
    );
    assert_eq!(status, 200, "{response}");
    assert!(response.get("error").is_none(), "{response}");

    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("batch-null-fields")
        .is_some());
    let (status, lookup) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["batch-null-fields"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    let imported = &lookup["users"][0];
    assert!(imported.get("providerUserInfo").is_none());
    assert!(imported.get("mfaInfo").is_none());
    assert!(imported.get("lastLoginAt").is_none());

    // `allowOverwrite: null` follows the omitted/default false path, and production replaces an
    // existing localId on that path too (sandbox recording 2026-09-23).
    let (status, response) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({
            "allowOverwrite": null,
            "users": [{
                "localId": "batch-null-fields",
                "email": "replacement@example.com",
                "displayName": "must-not-replace"
            }]
        }),
    );
    assert_eq!(status, 200, "{response}");
    assert!(response.get("error").is_none(), "{response}");
    let (status, lookup) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["batch-null-fields"]}),
    );
    assert_eq!(status, 200, "{lookup}");
    assert_eq!(lookup["users"][0]["email"], "replacement@example.com");
    assert_eq!(lookup["users"][0]["displayName"], "must-not-replace");
}

#[test]
fn batch_import_reports_each_missing_local_id_without_blocking_neighbors() {
    let s = state();
    let (status, response) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({
            "users": [
                {"localId": null},
                {},
                {"localId": "batch-valid-after-missing-ids", "email": "after@example.com"}
            ]
        }),
    );
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        response["error"].as_array().map(Vec::len),
        Some(2),
        "{response}"
    );
    assert_eq!(response["error"][0]["index"], 0, "{response}");
    assert_eq!(response["error"][1]["index"], 1, "{response}");
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("batch-valid-after-missing-ids")
        .is_some());
}

#[test]
fn batch_import_treats_omitted_null_and_empty_repeated_fields_consistently() {
    let s = state();
    for (local_id, extra) in [
        ("batch-omitted-fields", json!({})),
        (
            "batch-null-fields-controls",
            json!({"providerUserInfo": null, "mfaInfo": null, "createdAt": null, "lastLoginAt": null}),
        ),
        (
            "batch-empty-fields-controls",
            json!({"providerUserInfo": [], "mfaInfo": [], "createdAt": null, "lastLoginAt": null}),
        ),
    ] {
        let mut row = json!({"localId": local_id, "email": format!("{local_id}@example.com")});
        row.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:batchCreate"),
            &json!({"users": [row]}),
        );
        assert_eq!(status, 200, "{response}");
        assert!(response.get("error").is_none(), "{response}");
    }

    let (status, lookup) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [
            "batch-omitted-fields",
            "batch-null-fields-controls",
            "batch-empty-fields-controls"
        ]}),
    );
    assert_eq!(status, 200, "{lookup}");
    for user in lookup["users"].as_array().unwrap() {
        assert!(user.get("providerUserInfo").is_none(), "{user}");
        assert!(user.get("mfaInfo").is_none(), "{user}");
        assert!(user.get("lastLoginAt").is_none(), "{user}");
        assert!(
            user.get("createdAt").and_then(Value::as_str).is_some(),
            "{user}"
        );
    }
}

#[test]
fn password_policy_admin_create_covers_maximum_and_invalid_password_inputs_atomically() {
    for (units, expected_status) in [(4095, 200), (4096, 200), (4097, 400)] {
        let s = state();
        let uid = format!("admin-create-password-{units}");
        let email = format!("admin-create-password-{units}@example.com");
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({
                "localId": uid,
                "email": email,
                "password": password_with_utf16_units(units),
                "displayName": "must-not-apply"
            }),
        );
        assert_eq!(status, expected_status, "{response}");
        if expected_status == 400 {
            assert_eq!(
                response["error"]["message"], "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Password cannot be longer than 4096 characters",
                "{response}"
            );
            assert!(s.store.lock().unwrap().user_by_id(&uid).is_none());
        } else {
            let (_, lookup) = admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:lookup"),
                &json!({"localId": [uid]}),
            );
            assert_eq!(lookup["users"][0]["displayName"], "must-not-apply");
        }
    }

    for (uid, password) in [
        ("admin-create-control", json!("12345\u{0000}")),
        ("admin-create-short", json!("12345")),
        ("admin-create-wrong-type", json!(42)),
    ] {
        let s = state();
        let email = format!("{uid}@example.com");
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": uid, "email": email, "password": password}),
        );
        assert_eq!(status, 400, "{response}");
        if uid == "admin-create-wrong-type" {
            assert_eq!(
                response["error"]["message"],
                "INVALID_ARGUMENT : password must be a string"
            );
        } else {
            assert_eq!(
                response["error"]["message"],
                "WEAK_PASSWORD : Password should be at least 6 characters"
            );
        }
        assert!(s.store.lock().unwrap().user_by_id(uid).is_none());
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn account_lifecycle_keeps_admin_and_client_post_state_consistent() {
    let s = strict_state();
    let uid = "lifecycle-user";
    let email = "lifecycle@example.test";
    let (status, created) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": uid, "email": email, "password": "lifecycle-password"}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["localId"], uid);

    let (status, duplicate) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "other-user", "email": email, "password": "other-password"}),
    );
    assert_eq!(status, 400, "{duplicate}");
    assert_eq!(duplicate["error"]["message"], "EMAIL_EXISTS");
    let (_, after_duplicate) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid, "other-user"]}),
    );
    assert_eq!(after_duplicate["users"].as_array().map(Vec::len), Some(1));

    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "lifecycle-password", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let (status, updated) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "displayName": "Lifecycle User", "disableUser": true}),
    );
    assert_eq!(status, 200, "{updated}");
    let (_, disabled_view) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid]}),
    );
    assert_eq!(disabled_view["users"][0]["disabled"], true);
    let (status, disabled) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "lifecycle-password"}),
    );
    assert_eq!(status, 400, "{disabled}");
    assert_eq!(disabled["error"]["message"], "USER_DISABLED");
    let (status, reenabled) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "disableUser": false}),
    );
    assert_eq!(status, 200, "{reenabled}");
    let (_, reenabled_view) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid]}),
    );
    // An Admin-created account keeps `disabled: false` after re-enable (sandbox recording
    // 2026-09-23, auth-account/admin/disable#admin-lookup-after).
    assert_eq!(reenabled_view["users"][0]["disabled"], false);
    let (status, client_signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "lifecycle-password"}),
    );
    assert_eq!(status, 200, "{client_signed}");
    let (_, client_view) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": client_signed["idToken"]}),
    );
    assert_eq!(client_view["users"][0]["localId"], uid);
    assert_eq!(client_view["users"][0]["displayName"], "Lifecycle User");

    let (status, listed) = admin(
        &s,
        "GET",
        &format!("{ADMIN}/accounts:batchGet?maxResults=10"),
        &json!({}),
    );
    assert_eq!(status, 200, "{listed}");
    assert!(listed["users"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["localId"] == uid));

    let (status, deleted) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:delete"),
        &json!({"localId": uid}),
    );
    assert_eq!(status, 200, "{deleted}");
    let (_, missing) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid]}),
    );
    assert!(missing.get("users").is_none(), "{missing}");

    let (status, recreated) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": uid, "email": "recreated@example.test", "password": "recreated-password"}),
    );
    assert_eq!(status, 200, "{recreated}");
    assert_eq!(recreated["localId"], uid);
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
    // Production reads a numeric identifier as a string (sandbox recording 2026-09-23).
    assert_eq!(status, 200);

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
    // maxResults 0 is an empty page in production (sandbox recording 2026-09-23).
    let (status, empty) = admin(
        &s,
        "GET",
        &format!("{ADMIN}/accounts:batchGet?maxResults=0"),
        &json!({}),
    );
    assert_eq!(
        (status, empty.get("users").is_none()),
        (200, true),
        "{empty}"
    );

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

    let (status, name_page) = admin(
        &strict,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"sortBy": "NAME", "limit": 2}),
    );
    assert_eq!(status, 200, "{name_page}");
    assert_eq!(name_page["recordsCount"], "2");
    // All display names are missing: the local deterministic tie-breaker is UID.
    assert_eq!(name_page["userInfo"][0]["localId"], "user-000");
    assert_eq!(name_page["userInfo"][1]["localId"], "user-001");

    // Production accepts a limit above 500 (sandbox recording 2026-09-23).
    assert_eq!(
        admin(
            &strict,
            "POST",
            &format!("{ADMIN}/accounts:query"),
            &json!({"limit": "501"})
        )
        .0,
        200
    );
    // A negative offset is production's internal error instead
    // (`strict_admin_query_negative_offset_is_a_backend_failure`).
    for invalid in [
        json!({"limit": "-1"}),
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
fn admin_lookup_rejects_malformed_federated_identifiers_without_lookup_results() {
    let s = state();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({
            "localId": "federated-lookup",
            "email": "federated-lookup@example.test"
        }),
    );
    assert_eq!(status, 200);

    for identifier in [
        json!({"rawId": "provider-user"}),
        json!({"providerId": "google.com"}),
        json!({"providerId": 7, "rawId": "provider-user"}),
        json!({"providerId": "google.com", "rawId": false}),
    ] {
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"federatedUserId": [identifier]}),
        );
        assert_eq!(status, 400, "{response}");
        assert_eq!(
            response["error"]["message"],
            "INVALID_ARGUMENT : federatedUserId items require string providerId and rawId",
            "{response}"
        );
        assert!(response.get("users").is_none(), "{response}");
    }
}

#[test]
#[allow(clippy::too_many_lines)]
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
    assert_eq!(status, 400, "{looked_up_after_update}");
    assert!(
        looked_up_after_update["error"]["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("TOKEN_EXPIRED")),
        "{looked_up_after_update}"
    );
    let (status, refreshed_after_update) = post(
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
    let (status, looked_up_after_refresh) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": refreshed_after_update["id_token"]}),
    );
    assert_eq!(status, 400, "{looked_up_after_refresh}");
    assert!(
        looked_up_after_refresh["error"]["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("TOKEN_EXPIRED")),
        "{looked_up_after_refresh}"
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
    assert_eq!(deleted["error"]["message"], "USER_NOT_FOUND");
}

#[test]
#[allow(clippy::too_many_lines)] // The finite authorization matrix shares real account setup.
fn lookup_authorization_separates_end_user_identity_from_admin_selectors() {
    for s in [state(), strict_state()] {
        let mut signed = Vec::new();
        for email in ["lookup-caller@example.test", "lookup-target@example.test"] {
            let (status, account) = post(
                &s,
                &format!("{V1}/accounts:signUp"),
                &json!({"email": email, "password": "lookup-password", "returnSecureToken": true}),
            );
            assert_eq!(status, 200);
            signed.push(account);
        }
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({
                "localId": signed[1]["localId"], "phoneNumber": "+16505550123",
                "linkProviderUserInfo": {"providerId": "google.com", "rawId": "lookup-target-provider"}
            }),
        );
        assert_eq!(status, 200);
        for account in &signed {
            let (status, own) = post(
                &s,
                &format!("{V1}/accounts:lookup"),
                &json!({"idToken": account["idToken"]}),
            );
            assert_eq!(status, 200);
            assert_eq!(own["users"].as_array().unwrap().len(), 1);
            assert_eq!(own["users"][0]["localId"], account["localId"]);
        }
        for (field, selector) in [
            ("localId", json!([signed[1]["localId"]])),
            ("email", json!(["lookup-target@example.test"])),
            ("phoneNumber", json!(["+16505550123"])),
            (
                "federatedUserId",
                json!([{"providerId": "google.com", "rawId": "lookup-target-provider"}]),
            ),
        ] {
            let mut query = json!({});
            query[field] = selector.clone();
            let (status, found) = admin(&s, "POST", &format!("{ADMIN}/accounts:lookup"), &query);
            assert_eq!(status, 200);
            assert_eq!(found["users"].as_array().unwrap().len(), 1);
            assert_eq!(found["users"][0]["localId"], signed[1]["localId"]);
            // Neither a missing Admin credential nor an end-user bearer grants Admin lookup.
            for authorization in [
                None,
                Some(format!("Bearer {}", signed[0]["idToken"].as_str().unwrap())),
            ] {
                let headers = RequestHeaders {
                    authorization,
                    ..RequestHeaders::default()
                };
                let response = handle_with(
                    &s,
                    "POST",
                    &format!("{ADMIN}/accounts:lookup"),
                    &headers,
                    &query,
                );
                assert_ne!(response.status, 200);
                assert!(response.body.get("users").is_none());
            }
            for value in [selector, json!([]), Value::Null, json!(false)] {
                for token in [
                    None,
                    Some(json!("malformed")),
                    Some(signed[0]["idToken"].clone()),
                    Some(signed[1]["idToken"].clone()),
                ] {
                    // A verified session answers with its own subject and ignores every
                    // Admin selector, as production does (sandbox recording 2026-09-23,
                    // `client-lookup-with-admin-selectors`).
                    let subject = token.as_ref().and_then(|token| {
                        signed
                            .iter()
                            .find(|account| &account["idToken"] == token)
                            .map(|account| account["localId"].clone())
                    });
                    let expected_error = match token.as_ref().and_then(Value::as_str) {
                        None => Some("MISSING_ID_TOKEN"),
                        Some("malformed") => Some("INVALID_ID_TOKEN"),
                        Some(_) => None,
                    };
                    let mut request = json!({"admin": true});
                    request[field] = value.clone();
                    if let Some(token) = token {
                        request["idToken"] = token;
                    }
                    let (status, answered) = post(&s, &format!("{V1}/accounts:lookup"), &request);
                    if let Some(expected_error) = expected_error {
                        assert_eq!(
                            status, 400,
                            "selector {field} must not bypass end-user identity"
                        );
                        assert!(answered.get("users").is_none());
                        assert_eq!(answered["error"]["message"], expected_error);
                    } else {
                        assert_eq!(status, 200, "{answered}");
                        assert_eq!(answered["users"].as_array().unwrap().len(), 1);
                        assert_eq!(answered["users"][0]["localId"], subject.unwrap());
                    }
                }
            }
            // Even the emulator owner header cannot change an end-user handler's role: the
            // session's subject is the only account answered.
            query["idToken"] = signed[0]["idToken"].clone();
            let response = handle_with(
                &s,
                "POST",
                &format!("{V1}/accounts:lookup"),
                &owner(),
                &query,
            );
            assert_eq!(response.status, 200, "{}", response.body);
            assert_eq!(response.body["users"].as_array().unwrap().len(), 1);
            assert_eq!(response.body["users"][0]["localId"], signed[0]["localId"]);
        }
        assert_eq!(
            post(
                &s,
                &format!("{V1}/accounts:delete"),
                &json!({"idToken": signed[0]["idToken"]})
            )
            .0,
            200
        );
        let (status, missing) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed[0]["idToken"]}),
        );
        assert_eq!(status, 400);
        assert_eq!(missing["error"]["message"], "USER_NOT_FOUND");
    }
}

#[test]
fn deleted_account_credentials_are_distinct_from_unknown_inputs() {
    let s = strict_state();
    let mut accounts = Vec::new();
    for email in ["deleted-target@example.com", "deleted-control@example.com"] {
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": email, "password": "original-password", "returnSecureToken": true}),
        );
        assert_eq!(status, 200);
        accounts.push(signed);
    }
    for deleted in [false, true] {
        if deleted {
            assert_eq!(
                post(
                    &s,
                    &format!("{V1}/accounts:delete"),
                    &json!({"idToken": accounts[0]["idToken"]})
                )
                .0,
                200
            );
        }
        for (index, fixed) in accounts.iter().enumerate() {
            for (path, request) in [
                (
                    format!("{V1}/accounts:lookup"),
                    json!({"idToken": fixed["idToken"]}),
                ),
                (
                    "/securetoken.googleapis.com/v1/token".to_owned(),
                    json!({"grant_type": "refresh_token", "refresh_token": fixed["refreshToken"]}),
                ),
            ] {
                let (status, response) = post(&s, &path, &request);
                if deleted && index == 0 {
                    assert_eq!(status, 400);
                    assert_eq!(response["error"]["message"], "USER_NOT_FOUND", "{path}");
                } else {
                    assert_eq!(status, 200);
                    if path.ends_with("/token") {
                        assert_eq!(
                            post(
                                &s,
                                &format!("{V1}/accounts:lookup"),
                                &json!({"idToken": response["id_token"]})
                            )
                            .0,
                            200
                        );
                    }
                }
            }
        }
    }
    for token in [
        "unknown-token".to_owned(),
        format!("{}x", accounts[0]["refreshToken"].as_str().unwrap()),
    ] {
        let (status, response) = post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type": "refresh_token", "refresh_token": token}),
        );
        assert_eq!(status, 400);
        assert_eq!(response["error"]["message"], "INVALID_REFRESH_TOKEN");
    }
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": "malformed"}),
    );
    assert_eq!(status, 400);
    assert_eq!(response["error"]["message"], "INVALID_ID_TOKEN");
    // Past the five-minute allowance an expired token is invalid (sandbox recording 2026-09-24).
    advance(&s, 3901);
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": accounts[0]["idToken"]}),
    );
    assert_eq!(status, 400);
    assert_eq!(response["error"]["message"], "INVALID_ID_TOKEN");
}

#[test]
#[allow(clippy::too_many_lines)] // Keep disable, re-enable and revocation controls in one lifecycle.
fn disabled_account_preserves_fixed_credentials_for_reenable_in_strict_profile() {
    let s = strict_state();
    let mut accounts = Vec::new();
    for email in [
        "disabled-target@example.com",
        "disabled-control@example.com",
    ] {
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({
                "email": email, "password": "original-password", "returnSecureToken": true
            }),
        );
        assert_eq!(status, 200);
        accounts.push((email, signed));
    }
    for disabled in [false, true, false] {
        advance(&s, 2);
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({
                "localId": accounts[0].1["localId"], "disableUser": disabled
            }),
        );
        assert_eq!(status, 200);
        for (index, (email, fixed)) in accounts.iter().enumerate() {
            for (path, request) in [
                (
                    format!("{V1}/accounts:signInWithPassword"),
                    json!({"email": email, "password": "original-password", "returnSecureToken": true}),
                ),
                (
                    format!("{V1}/accounts:lookup"),
                    json!({"idToken": fixed["idToken"]}),
                ),
                (
                    "/securetoken.googleapis.com/v1/token".to_owned(),
                    json!({"grant_type":"refresh_token", "refresh_token": fixed["refreshToken"]}),
                ),
            ] {
                let (status, response) = post(&s, &path, &request);
                if disabled && index == 0 {
                    assert_eq!(status, 400, "{path}");
                    assert_eq!(response["error"]["message"], "USER_DISABLED", "{path}");
                } else {
                    assert_eq!(status, 200, "{path}: {response}");
                    if path.ends_with("/token") {
                        let (status, looked) = post(
                            &s,
                            &format!("{V1}/accounts:lookup"),
                            &json!({"idToken": response["id_token"]}),
                        );
                        assert_eq!(status, 200);
                        assert_eq!(looked["users"][0]["localId"], fixed["localId"]);
                    }
                }
            }
        }
    }
    // Re-enabling must not undo a simultaneous password change.
    advance(&s, 2);
    for request in [
        json!({"localId": accounts[1].1["localId"], "disableUser": true, "password": "replacement-password"}),
        json!({"localId": accounts[1].1["localId"], "disableUser": false}),
    ] {
        assert_eq!(
            admin(&s, "POST", &format!("{ADMIN}/accounts:update"), &request).0,
            200
        );
    }
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": accounts[1].1["idToken"]})
        )
        .0,
        400
    );
    assert_eq!(
        post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type": "refresh_token", "refresh_token": accounts[1].1["refreshToken"]})
        )
        .0,
        400
    );
    assert_eq!(post(&s, &format!("{V1}/accounts:signInWithPassword"), &json!({"email": accounts[1].0, "password": "replacement-password", "returnSecureToken": true})).0, 200);
    // Re-enabling must not undo a separate explicit revocation.
    advance(&s, 2);
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": accounts[0].1["localId"], "validSince": "9999999999", "disableUser": true
        }),
    );
    assert_eq!(status, 200);
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": accounts[0].1["localId"], "disableUser": false}),
    );
    assert_eq!(status, 200);
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": accounts[0].1["idToken"]}),
    );
    assert_eq!(status, 400);
    assert_eq!(
        post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type": "refresh_token", "refresh_token": accounts[0].1["refreshToken"]})
        )
        .0,
        400
    );
}

#[test]
fn password_maximum_update_counts_utf16_units_and_preserves_rejected_state() {
    for (suffix, count, accepted) in [
        ("a", 4064, true),
        ("a", 4065, false),
        ("é", 2032, true),
        ("é", 2033, true),
        ("\u{10400}", 2032, true),
        ("\u{10400}", 2033, false),
        ("é", 4064, true),
        ("é", 4065, false),
    ] {
        let s = strict_state();
        let email = "unicode-maximum@example.com";
        let original = "original-password";
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({
                "email": email, "password": original, "returnSecureToken": true
            }),
        );
        assert_eq!(status, 200);
        let (_, before) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        let password = format!("{}{}", "a".repeat(32), suffix.repeat(count));
        advance(&s, 2);
        let (status, changed) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({
                "idToken": signed["idToken"], "password": password,
                "displayName": "changed", "returnSecureToken": true
            }),
        );
        assert_eq!(
            status,
            if accepted { 200 } else { 400 },
            "suffix={suffix:?}, count={count}"
        );
        let credentials = if accepted { &changed } else { &signed };
        if !accepted {
            assert_eq!(
                changed["error"]["message"],
                "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Password cannot be longer than 4096 characters"
            );
        }
        let (status, after) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": credentials["idToken"]}),
        );
        assert_eq!(status, 200);
        if accepted {
            assert_eq!(after["users"][0]["displayName"], "changed");
        } else {
            assert_eq!(after, before);
        }
        let (status, refreshed) = post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({
                "grant_type": "refresh_token", "refresh_token": credentials["refreshToken"]
            }),
        );
        assert_eq!(status, 200);
        let (status, looked) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": refreshed["id_token"]}),
        );
        assert_eq!(status, 200);
        assert_eq!(looked["users"][0]["localId"], signed["localId"]);
        let (status, logged) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({
                "email": email, "password": if accepted { password.as_str() } else { original }, "returnSecureToken": true
            }),
        );
        assert_eq!(status, 200);
        assert_eq!(logged["localId"], signed["localId"]);
    }
}

#[test]
fn password_maximum_update_preserves_credentials_and_full_suffix() {
    let s = strict_state();
    let (_, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "email": "maximum@example.com", "password": "original-password", "returnSecureToken": true
        }),
    );
    advance(&s, 2);
    let maximum = "a".repeat(4096);
    let (status, changed) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({
            "idToken": signed["idToken"], "password": maximum, "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200, "{changed}");
    for password in [
        maximum.clone(),
        format!("{}b", "a".repeat(4095)),
        "a".repeat(4095),
    ] {
        let (status, response) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({
                "email": "maximum@example.com", "password": password, "returnSecureToken": true
            }),
        );
        assert_eq!(
            status,
            if password == maximum { 200 } else { 400 },
            "{response}"
        );
    }
    advance(&s, 2);
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({
            "idToken": changed["idToken"], "password": "a".repeat(4097), "displayName": "must-not-apply"
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Password cannot be longer than 4096 characters"
    );
    let (status, looked) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": changed["idToken"]}),
    );
    assert_eq!(status, 200, "{looked}");
    assert_ne!(looked["users"][0]["displayName"], "must-not-apply");
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({
            "grant_type": "refresh_token", "refresh_token": changed["refreshToken"]
        }),
    );
    assert_eq!(status, 200, "{refreshed}");
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "maximum@example.com", "password": maximum, "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200, "{response}");
}

fn password_with_utf16_units(units: usize) -> String {
    assert!(units >= 2);
    let mut password = "a".repeat(units - 2);
    password.push('\u{10400}');
    assert_eq!(password.encode_utf16().count(), units);
    password
}

#[test]
fn password_policy_boundaries_apply_to_sign_up_without_creating_rejected_accounts() {
    for (units, expected_status) in [(4095, 200), (4096, 200), (4097, 400)] {
        let s = state();
        let email = format!("signup-password-{units}@example.com");
        let password = password_with_utf16_units(units);
        let (status, response) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": email, "password": password, "returnSecureToken": true}),
        );
        assert_eq!(status, expected_status, "{response}");
        if expected_status == 400 {
            // The detail after " : " is pinned in password_rules_answer_like_production.
            assert!(
                response["error"]["message"]
                    .as_str()
                    .is_some_and(|m| m.starts_with("PASSWORD_DOES_NOT_MEET_REQUIREMENTS")),
                "{response}"
            );
        }
        assert_eq!(
            s.store.lock().unwrap().user_by_email(&email).is_some(),
            expected_status == 200
        );
    }

    for password in ["12345\u{0000}".to_owned(), "12345".to_owned()] {
        let s = state();
        let email = format!("signup-invalid-{}@example.com", password.len());
        let (status, response) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": email, "password": password}),
        );
        assert_eq!(status, 400, "{response}");
        assert_eq!(
            response["error"]["message"],
            "WEAK_PASSWORD : Password should be at least 6 characters",
            "{response}"
        );
        assert!(s.store.lock().unwrap().user_by_email(&email).is_none());
    }

    let s = state();
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "signup-malformed@example.com", "password": 42}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"], "INVALID_ARGUMENT : password must be a string",
        "{response}"
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("signup-malformed@example.com")
        .is_none());
}

#[test]
fn password_policy_boundaries_apply_to_admin_update_before_any_profile_mutation() {
    for (units, expected_status) in [(4095, 200), (4096, 200), (4097, 400)] {
        let s = state();
        let email = format!("admin-password-{units}@example.com");
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": email, "password": "original-password"}),
        );
        assert_eq!(status, 200, "{signed}");
        let password = password_with_utf16_units(units);
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({
                "localId": signed["localId"],
                "password": password,
                "displayName": "must-not-apply"
            }),
        );
        assert_eq!(status, expected_status, "{response}");
        if expected_status == 400 {
            // The detail after " : " is pinned in password_rules_answer_like_production.
            assert!(
                response["error"]["message"]
                    .as_str()
                    .is_some_and(|m| m.starts_with("PASSWORD_DOES_NOT_MEET_REQUIREMENTS")),
                "{response}"
            );
        }
        let (_, lookup) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [signed["localId"]]}),
        );
        if expected_status == 400 {
            assert_ne!(lookup["users"][0]["displayName"], "must-not-apply");
            let (status, _) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": email, "password": "original-password"}),
            );
            assert_eq!(status, 200);
        } else {
            assert_eq!(lookup["users"][0]["displayName"], "must-not-apply");
        }
    }

    let s = state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "admin-control@example.com", "password": "original-password"}),
    );
    assert_eq!(status, 200, "{signed}");
    let (status, response) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": signed["localId"], "password": "12345\u{0000}", "displayName": "must-not-apply"}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"],
        "WEAK_PASSWORD : Password should be at least 6 characters"
    );
    let (_, lookup) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [signed["localId"]]}),
    );
    assert_ne!(lookup["users"][0]["displayName"], "must-not-apply");

    let (status, response) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": signed["localId"], "password": "12345"}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"], "WEAK_PASSWORD : Password should be at least 6 characters",
        "{response}"
    );
    let (status, response) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": signed["localId"], "password": 42}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"], "INVALID_ARGUMENT : password must be a string",
        "{response}"
    );
}

#[test]
fn password_policy_client_update_rejects_invalid_values_before_profile_mutation() {
    for units in [4095, 4096] {
        let s = state();
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "client-password-boundary@example.com", "password": "original-password"}),
        );
        assert_eq!(status, 200, "{signed}");
        let (status, response) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({
                "idToken": signed["idToken"],
                "password": password_with_utf16_units(units),
                "returnSecureToken": true
            }),
        );
        assert_eq!(status, 200, "{response}");
    }

    for password in [
        password_with_utf16_units(4097),
        "12345".to_owned(),
        "12345\u{0000}".to_owned(),
    ] {
        let s = state();
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "client-password-policy@example.com", "password": "original-password"}),
        );
        assert_eq!(status, 200, "{signed}");
        let (status, response) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({
                "idToken": signed["idToken"],
                "password": password,
                "displayName": "must-not-apply",
                "returnSecureToken": true
            }),
        );
        assert_eq!(status, 400, "{response}");
        assert_eq!(
            response["error"]["message"],
            if password.encode_utf16().count() > AuthStore::MAX_PASSWORD_UTF16_UNITS {
                "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Password cannot be longer than 4096 characters"
            } else {
                "WEAK_PASSWORD : Password should be at least 6 characters"
            },
            "{response}"
        );
        let (_, lookup) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_ne!(lookup["users"][0]["displayName"], "must-not-apply");
        let (status, unchanged) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "client-password-policy@example.com", "password": "original-password"}),
        );
        assert_eq!(status, 200, "{unchanged}");
    }

    let s = state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "client-password-malformed@example.com", "password": "original-password"}),
    );
    assert_eq!(status, 200, "{signed}");
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": signed["idToken"], "password": 42, "displayName": "must-not-apply"}),
    );
    assert_eq!(status, 400, "{response}");
    assert_eq!(
        response["error"]["message"],
        "INVALID_ARGUMENT : password must be a string"
    );
    let (_, lookup) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": signed["idToken"]}),
    );
    assert_ne!(lookup["users"][0]["displayName"], "must-not-apply");
}

#[test]
#[allow(clippy::too_many_lines)]
fn password_policy_batch_import_validates_raw_password_and_preserves_hash_semantics() {
    let s = state();
    for units in [4095, 4096] {
        let local_id = format!("raw-password-{units}");
        let email = format!("raw-password-{units}@example.com");
        let (status, imported) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:batchCreate"),
            &json!({"users": [{
                "localId": local_id,
                "email": email,
                "rawPassword": password_with_utf16_units(units)
            }]}),
        );
        assert_eq!(status, 200, "{imported}");
        assert!(imported.get("error").is_none());
    }
    for units in [4095, 4096] {
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({
                "email": format!("raw-password-{units}@example.com"),
                "password": password_with_utf16_units(units)
            }),
        );
        assert_eq!(status, 200, "{signed}");
    }

    let (status, rejected) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{
            "localId": "raw-password-too-long",
            "email": "raw-password-too-long@example.com",
            "rawPassword": password_with_utf16_units(4097)
        }]}),
    );
    assert_eq!(status, 200, "{rejected}");
    assert_eq!(rejected["error"].as_array().unwrap().len(), 1, "{rejected}");
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("raw-password-too-long")
        .is_none());

    let (status, imported) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{
            "localId": "fake-hash-user",
            "email": "fake-hash-user@example.com",
            "passwordHash": "fakeHash:salt=fakeSalt:password=imported-password"
        }]}),
    );
    assert_eq!(status, 200, "{imported}");
    assert!(imported.get("error").is_none());
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "fake-hash-user@example.com", "password": "imported-password"}),
    );
    assert_eq!(status, 200, "{signed}");

    let (status, unsupported) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{
            "localId": "unsupported-hash-user",
            "email": "unsupported-hash-user@example.com",
            // Well-formed bytes that no algorithm was named for: production keeps them as the
            // credential and no password matches (a malformed base64 value is refused).
            "passwordHash": "c2NyeXB0LXVucmVhZGFibGU="
        }]}),
    );
    assert_eq!(status, 200, "{unsupported}");
    assert!(unsupported.get("error").is_none());
    let (status, sign_in) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "unsupported-hash-user@example.com", "password": "anything-valid"}),
    );
    assert_eq!(status, 400, "{sign_in}");

    let (status, malformed) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{
            "localId": "raw-password-malformed",
            "email": "raw-password-malformed@example.com",
            "rawPassword": 42
        }]}),
    );
    assert_eq!(status, 200, "{malformed}");
    assert_eq!(
        malformed["error"].as_array().unwrap().len(),
        1,
        "{malformed}"
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("raw-password-malformed")
        .is_none());

    let (status, control) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{
            "localId": "raw-password-control",
            "email": "raw-password-control@example.com",
            "rawPassword": "12345\u{0000}"
        }]}),
    );
    assert_eq!(status, 200, "{control}");
    assert_eq!(control["error"].as_array().unwrap().len(), 1, "{control}");
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id("raw-password-control")
        .is_none());
}

#[test]
#[allow(clippy::too_many_lines)]
fn password_policy_batch_import_validates_supported_fake_hashes_before_overwrite() {
    let s = state();
    for units in [4095, 4096, 4097] {
        let local_id = format!("fake-hash-boundary-{units}");
        let email = format!("fake-hash-boundary-{units}@example.com");
        let password = password_with_utf16_units(units);
        let (status, imported) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:batchCreate"),
            &json!({"users": [{
                "localId": local_id,
                "email": email,
                "passwordHash": format!("fakeHash:salt=fakeSalt:password={password}")
            }]}),
        );
        assert_eq!(status, 200, "{imported}");
        if units == 4097 {
            assert_eq!(imported["error"].as_array().unwrap().len(), 1, "{imported}");
            assert_eq!(imported["error"][0]["index"], 0, "{imported}");
            assert!(
                imported["error"][0]["message"]
                    .as_str()
                    .is_some_and(|m| m.starts_with("PASSWORD_DOES_NOT_MEET_REQUIREMENTS")),
                "{imported}"
            );
            assert!(s.store.lock().unwrap().user_by_id(&local_id).is_none());
        } else {
            assert!(imported.get("error").is_none());
            let (status, signed) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": email, "password": password}),
            );
            assert_eq!(status, 200, "{signed}");
        }
    }

    let (status, existing) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "fake-hash-overwrite@example.com", "password": "original-password"}),
    );
    assert_eq!(status, 200, "{existing}");
    let oversized = password_with_utf16_units(4097);
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"allowOverwrite": true, "users": [{
            "localId": existing["localId"],
            "email": "fake-hash-overwrite@example.com",
            "displayName": "must-not-apply",
            "passwordHash": format!("fakeHash:salt=fakeSalt:password={oversized}")
        }]}),
    );
    assert_eq!(status, 200, "{refused}");
    assert_eq!(refused["error"].as_array().unwrap().len(), 1, "{refused}");
    assert!(
        refused["error"][0]["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("PASSWORD_DOES_NOT_MEET_REQUIREMENTS")),
        "{refused}"
    );
    let (status, unchanged) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "fake-hash-overwrite@example.com", "password": "original-password"}),
    );
    assert_eq!(status, 200, "{unchanged}");
    let (_, lookup) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [existing["localId"]]}),
    );
    assert_ne!(lookup["users"][0]["displayName"], "must-not-apply");

    let mixed = state();
    let (status, response) = admin(
        &mixed,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [
            {
                "localId": "fake-hash-mixed-invalid",
                "email": "fake-hash-mixed-invalid@example.com",
                "passwordHash": format!("fakeHash:salt=fakeSalt:password={}", password_with_utf16_units(4097))
            },
            {
                "localId": "fake-hash-mixed-valid",
                "email": "fake-hash-mixed-valid@example.com",
                "passwordHash": format!("fakeHash:salt=fakeSalt:password={}", password_with_utf16_units(4096))
            }
        ]}),
    );
    assert_eq!(status, 200, "{response}");
    assert_eq!(response["error"].as_array().unwrap().len(), 1, "{response}");
    assert_eq!(response["error"][0]["index"], 0, "{response}");
    assert!(
        response["error"][0]["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("PASSWORD_DOES_NOT_MEET_REQUIREMENTS")),
        "{response}"
    );
    let (status, signed) = post(
        &mixed,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "fake-hash-mixed-valid@example.com",
            "password": password_with_utf16_units(4096)
        }),
    );
    assert_eq!(status, 200, "{signed}");
}

#[test]
#[allow(clippy::too_many_lines)]
fn batch_import_failed_overwrite_keeps_the_existing_account() {
    let s = state();
    let (status, existing) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "email": "existing-overwrite@example.com",
            "password": "original-password",
            "returnSecureToken": true,
        }),
    );
    assert_eq!(
        status, 200,
        "initial account creation failed: status {status}"
    );
    let uid = existing["localId"].as_str().unwrap();
    let refresh = existing["refreshToken"].as_str().unwrap().to_owned();

    let (status, _seeded) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": uid,
            "emailVerified": true,
            "linkProviderUserInfo": {"providerId": "google.com", "rawId": "existing-google"},
            "mfa": {"enrollments": [{
                "mfaEnrollmentId": "existing-factor",
                "phoneInfo": "+16505550101"
            }]}
        }),
    );
    assert_eq!(status, 200, "account state setup failed: status {status}");
    let (_, before) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid]}),
    );

    let (status, other) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"email": "other-overwrite@example.com"}),
    );
    assert_eq!(
        status, 200,
        "neighbor account creation failed: status {status}"
    );

    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({
            "allowOverwrite": true,
            "users": [{
                "localId": uid,
                // A malformed address is a row refusal in production; an address owned by
                // another account is not (sandbox recording 2026-09-23).
                "email": "not-an-email",
                "passwordHash": "fakeHash:salt=fakeSalt:password=replacement-password",
            }],
        }),
    );
    assert_eq!(
        status, 200,
        "failed overwrite request failed: status {status}"
    );
    assert!(
        refused["error"]
            .as_array()
            .is_some_and(|errors| errors.len() == 1),
        "failed overwrite did not return one row error"
    );
    assert!(
        refused["error"][0]["index"] == 0,
        "failed overwrite error did not identify row zero"
    );

    let (status, _refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(
        status, 200,
        "existing refresh token was rejected: status {status}"
    );
    let (_, after) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid]}),
    );
    assert!(
        after == before,
        "a failed overwrite preserves every account index"
    );

    let (status, unchanged) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "existing-overwrite@example.com",
            "password": "original-password",
        }),
    );
    assert_eq!(
        status, 200,
        "unchanged password sign-in failed: status {status}"
    );
    assert!(
        unchanged["localId"] == uid,
        "existing UID changed after failed overwrite"
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_id(other["localId"].as_str().unwrap())
        .is_some());

    let (status, replaced) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({
            "allowOverwrite": true,
            "users": [{
                "localId": uid,
                "email": "replacement-overwrite@example.com",
                "passwordHash": "fakeHash:salt=fakeSalt:password=replacement-password",
            }],
        }),
    );
    assert_eq!(
        status, 200,
        "successful overwrite request failed: status {status}"
    );
    assert!(
        replaced.get("error").is_none(),
        "successful overwrite returned row errors"
    );
    let (status, _signed_replacement) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "replacement-overwrite@example.com",
            "password": "replacement-password",
        }),
    );
    assert_eq!(
        status, 200,
        "replacement password sign-in failed: status {status}"
    );
    let (status, _old_email) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "existing-overwrite@example.com",
            "password": "original-password",
        }),
    );
    assert_eq!(
        status, 400,
        "old email remained indexed after overwrite: status {status}"
    );
}

#[test]
fn end_user_update_cannot_select_an_account_by_local_id() {
    let s = strict_state();
    let (_, victim) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "email": "victim@example.com", "password": "original-password", "returnSecureToken": true
        }),
    );
    let (_, other) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "email": "other@example.com", "password": "other-password", "returnSecureToken": true
        }),
    );
    for token in [Value::Null, other["idToken"].clone()] {
        for password in ["replacement".to_owned(), "a".repeat(4097)] {
            let (status, _) = post(
                &s,
                &format!("{V1}/accounts:update"),
                &json!({
                    "localId": victim["localId"], "idToken": token, "password": password
                }),
            );
            assert_eq!(
                status,
                if token.is_string() && password.len() <= 4096 {
                    200
                } else {
                    400
                }
            );
        }
    }
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({
            "email": "victim@example.com", "password": "original-password", "returnSecureToken": true
        }),
    );
    assert_eq!(status, 200);
    // The authenticated Admin route is a distinct, explicitly privileged operation.
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": victim["localId"], "displayName": "admin-updated"
        }),
    );
    assert_eq!(status, 200);
}

#[test]
#[allow(clippy::too_many_lines)]
fn end_user_update_rejects_admin_fields_atomically_by_presence() {
    for s in [state(), strict_state()] {
        let (_, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({
                "email": "field-owner@example.com", "password": "password1", "returnSecureToken": true
            }),
        );
        let uid = &signed["localId"];
        let (status, seeded) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({
                "localId": uid, "displayName": "original", "customAttributes": "{\"role\":\"member\"}",
                "emailVerified": true, "mfa": {"enrollments": [{"phoneInfo": "+16505550101"}]},
                "linkProviderUserInfo": {"providerId": "google.com", "rawId": "field-owner-google"}
            }),
        );
        assert_eq!(status, 200, "{seeded}");
        let (_, before) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [uid]}),
        );
        assert_eq!(
            before["users"][0]["customAttributes"],
            "{\"role\":\"member\"}"
        );
        assert_eq!(before["users"][0]["emailVerified"], true);
        assert_eq!(
            before["users"][0]["mfaInfo"][0]["phoneInfo"],
            "+16505550101"
        );
        assert!(before["users"][0]["providerUserInfo"]
            .as_array()
            .unwrap()
            .iter()
            .any(|provider| {
                provider["providerId"] == "google.com" && provider["rawId"] == "field-owner-google"
            }));
        let attempts = [
            ("customAttributes", json!("{\"role\":\"admin\"}")),
            ("customAttributes", json!("{}")),
            ("customAttributes", json!("")),
            ("mfa", json!({"enrollments": []})),
            ("mfa", json!({})),
            (
                "linkProviderUserInfo",
                json!({"providerId": "google.com", "rawId": "attacker"}),
            ),
            ("linkProviderUserInfo", json!({})),
            ("mfa", Value::Null),
            ("linkProviderUserInfo", Value::Null),
        ];
        for (field, value) in attempts {
            let mut request =
                json!({"idToken": signed["idToken"], "displayName": "must-not-apply"});
            request[field] = value;
            let (status, rejected) = post(&s, &format!("{V1}/accounts:update"), &request);
            assert_eq!(status, 400, "{field}: {rejected}");
            assert_eq!(
                rejected["error"]["message"],
                if field == "customAttributes" {
                    "INSUFFICIENT_PERMISSION"
                } else if field == "linkProviderUserInfo" {
                    "UNEXPECTED_PARAMETER : link_provider_user_info is not allowed with ID token."
                } else {
                    "OPERATION_NOT_ALLOWED"
                },
                "{field}"
            );
            let (_, after) = admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:lookup"),
                &json!({"localId": [uid]}),
            );
            assert_eq!(
                before, after,
                "{field} rejection must preserve the entire lookup projection"
            );
        }
        // Production second45 row21: null is absent, never a request to clear claims.
        let (status, accepted) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": signed["idToken"], "displayName": "null-allowed", "customAttributes": null}),
        );
        assert_eq!(status, 200, "{accepted}");
        let (_, after_null) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [uid]}),
        );
        assert_eq!(
            after_null["users"][0]["customAttributes"],
            before["users"][0]["customAttributes"]
        );
        assert_eq!(after_null["users"][0]["emailVerified"], true);
        assert_eq!(
            after_null["users"][0]["mfaInfo"],
            before["users"][0]["mfaInfo"]
        );
        let (status, normal) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({
                "idToken": signed["idToken"], "displayName": "allowed"
            }),
        );
        assert_eq!(status, 200, "{normal}");
        assert_eq!(normal["displayName"], "allowed");
    }
}

/// AUTH-U03: production refuses a client accounts:update carrying a tampered ID token and
/// an administrator-only field with `INVALID_ID_TOKEN`, verifying the session before the
/// field is judged (auth-refusal-precedence revision 1, approved 2026-09-12). The
/// end-user route now authenticates first. A valid session with customAttributes, mfa or
/// linkProviderUserInfo is refused by field authorization (second45 observes
/// `INSUFFICIENT_PERMISSION` for customAttributes strings); emailVerified is ignored
/// while ordinary displayName changes apply. The OOB route still rejects these fields
/// before consuming the code, and refusals do not mutate.
/// AUTH-U03 / GAP-AUTH-003 invariant fence: the end-user accounts:update route
/// authenticates before it authorizes for EVERY session-failure class, not only the
/// tampered signature production observed. An expired, revoked, disabled or deleted
/// session carrying an administrator-only field (or a disableUser flag) is refused with
/// its own session error, never `OPERATION_NOT_ALLOWED`, and changes nothing. Only the
/// tampered-signature row is production-observed; the other classes pin local behavior so
/// a partial revert that moves the field check back before `verify_session` is caught.
#[test]
fn end_user_update_session_failure_precedes_admin_field_authorization() {
    let admin_field = ("customAttributes", json!("{\"role\":\"admin\"}"));
    // (label, expected error) for a session that fails verification before authorization.
    for s in [state(), strict_state()] {
        let lookup = |uid: &str| {
            admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:lookup"),
                &json!({"localId": [uid]}),
            )
            .1
        };
        let fresh = |email: &str| {
            let (_, signed) = post(
                &s,
                &format!("{V1}/accounts:signUp"),
                &json!({"email": email, "password": "password1", "returnSecureToken": true}),
            );
            (
                signed["localId"].as_str().unwrap().to_string(),
                signed["idToken"].as_str().unwrap().to_string(),
            )
        };

        // Expired: the token outlives its one-hour lifetime before the update.
        let (expired_uid, expired_token) = fresh("expired-field@example.com");
        // Past the five-minute allowance (sandbox recording 2026-09-24).
        advance(&s, 3901);
        // Revoked: a fresh token, then a privileged password change advances validSince.
        let (revoked_uid, revoked_token) = fresh("revoked-field@example.com");
        advance(&s, 2);
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": revoked_uid, "password": "password2"}),
        );
        assert_eq!(status, 200);
        // Disabled: the account is disabled after the token is issued.
        let (disabled_uid, disabled_token) = fresh("disabled-field@example.com");
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": disabled_uid, "disableUser": true}),
        );
        assert_eq!(status, 200);
        // Deleted: the account is removed after the token is issued.
        let (deleted_uid, deleted_token) = fresh("deleted-field@example.com");
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:delete"),
            &json!({"localId": deleted_uid}),
        );
        assert_eq!(status, 200);

        let cases = [
            (
                "expired",
                &expired_token,
                Some(&expired_uid),
                "INVALID_ID_TOKEN",
            ),
            (
                "revoked",
                &revoked_token,
                Some(&revoked_uid),
                // Production has no detail for a revoked token (sandbox recording 2026-09-23).
                "TOKEN_EXPIRED",
            ),
            (
                "disabled",
                &disabled_token,
                Some(&disabled_uid),
                "USER_DISABLED",
            ),
            // A deleted account's token fails verification as an unknown user (INVALID_ID_TOKEN),
            // not the trailing USER_NOT_FOUND, since the verifier checks the user first.
            ("deleted", &deleted_token, None, "INVALID_ID_TOKEN"),
        ];
        for (label, token, uid, expected) in cases {
            let before = uid.map(|u| lookup(u));
            // The administrator-only field and the disableUser flag both come after the
            // session check, so both must surface the session error, not OPERATION_NOT_ALLOWED.
            for extra in [admin_field.clone(), ("disableUser", json!(true))] {
                let mut request = json!({"idToken": token, "displayName": "must-not-apply"});
                request[extra.0] = extra.1;
                let (status, refused) = post(&s, &format!("{V1}/accounts:update"), &request);
                assert_eq!(status, 400, "{label}/{}: {refused}", extra.0);
                assert_eq!(
                    refused["error"]["message"], expected,
                    "{label}/{} must surface the session error, not OPERATION_NOT_ALLOWED",
                    extra.0
                );
            }
            if let (Some(u), Some(b)) = (uid, before) {
                assert_eq!(
                    lookup(u),
                    b,
                    "{label}: no rejected update may mutate the account"
                );
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn end_user_update_authenticates_before_authorizing_admin_fields() {
    let admin_fields = [
        ("customAttributes", json!("{\"role\":\"admin\"}")),
        (
            "mfa",
            json!({"enrollments": [{"phoneInfo": "+16505550111"}]}),
        ),
        (
            "linkProviderUserInfo",
            json!({"providerId": "google.com", "rawId": "attacker"}),
        ),
    ];
    for s in [state(), strict_state()] {
        let (_, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "precedence@example.com", "password": "password1", "displayName": "precedence-marker", "returnSecureToken": true}),
        );
        let uid = &signed["localId"];
        let token = signed["idToken"].as_str().unwrap();
        // A structurally intact JWT whose signature cannot verify. The local emulator
        // issues unsigned tokens (`alg: none`, empty signature); appending a signature
        // segment makes verification fail, matching how the production recorder alters a
        // signed token's signature.
        let parts: Vec<&str> = token.split('.').collect();
        let signature = parts[2];
        let flipped = if signature.is_empty() {
            "AAAA".to_string()
        } else {
            let last = signature.chars().last().unwrap();
            format!(
                "{}{}",
                &signature[..signature.len() - 1],
                if last == 'A' { 'B' } else { 'A' }
            )
        };
        let tampered = format!("{}.{}.{}", parts[0], parts[1], flipped);
        let lookup = |s: &AuthState| {
            admin(
                s,
                "POST",
                &format!("{ADMIN}/accounts:lookup"),
                &json!({"localId": [uid]}),
            )
            .1
        };
        let before = lookup(&s);

        // The action-code route rejects the field before consuming a session.
        let (_, link) = admin(
            &s,
            "POST",
            &format!("{V1}/projects/demo-app/accounts:sendOobCode"),
            &json!({"requestType": "VERIFY_EMAIL", "idToken": signed["idToken"], "returnOobLink": true}),
        );
        let baseline = lookup(&s);

        for (field, value) in &admin_fields {
            // Tampered session plus an administrator-only field: the token is verified
            // first, so the refusal names the token, and nothing is applied.
            let mut request = json!({"idToken": tampered, "displayName": "must-not-apply"});
            request[*field] = value.clone();
            let (status, refused) = post(&s, &format!("{V1}/accounts:update"), &request);
            assert_eq!(status, 400, "{field}: {refused}");
            assert_eq!(refused["error"]["message"], "INVALID_ID_TOKEN", "{field}");
            assert_eq!(
                lookup(&s),
                baseline,
                "{field}: tampered update must not mutate"
            );

            // Valid session plus the same field: authenticated, then refused on the field.
            let mut request =
                json!({"idToken": signed["idToken"], "displayName": "must-not-apply"});
            request[*field] = value.clone();
            let (status, refused) = post(&s, &format!("{V1}/accounts:update"), &request);
            assert_eq!(status, 400, "{field}: {refused}");
            assert_eq!(
                refused["error"]["message"],
                if *field == "customAttributes" {
                    "INSUFFICIENT_PERMISSION"
                } else if *field == "linkProviderUserInfo" {
                    "UNEXPECTED_PARAMETER : link_provider_user_info is not allowed with ID token."
                } else {
                    "OPERATION_NOT_ALLOWED"
                },
                "{field}"
            );
            assert_eq!(
                lookup(&s),
                baseline,
                "{field}: valid-token update must not mutate"
            );

            // OOB code plus the same field: refused on the field, code not consumed.
            let mut request = json!({"oobCode": link["oobCode"], "displayName": "must-not-apply"});
            request[*field] = value.clone();
            let (status, refused) = post(&s, &format!("{V1}/accounts:update"), &request);
            assert_eq!(status, 400, "{field}: {refused}");
            assert_eq!(
                refused["error"]["message"], "OPERATION_NOT_ALLOWED",
                "{field}"
            );
        }

        // Production's valid-token client behavior ignores emailVerified while applying
        // the permitted displayName change. Restore the display name before the remaining
        // refusal checks so every later state comparison has the original baseline.
        let (status, applied) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({
                "idToken": signed["idToken"],
                "emailVerified": false,
                "displayName": "email-verified-ignored"
            }),
        );
        assert_eq!(status, 200, "{applied}");
        assert_eq!(applied["displayName"], "email-verified-ignored");
        assert_eq!(lookup(&s)["emailVerified"], baseline["emailVerified"]);
        let (status, restored) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": signed["idToken"], "displayName": "precedence-marker"}),
        );
        assert_eq!(status, 200, "{restored}");
        assert_eq!(lookup(&s), baseline);

        // disableUser is symmetric with the administrator-only fields: a tampered session
        // is refused on the token, a valid session on the flag, and neither mutates.
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": tampered, "disableUser": true}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_ID_TOKEN");
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": signed["idToken"], "disableUser": true}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "OPERATION_NOT_ALLOWED");

        assert_eq!(
            lookup(&s),
            before,
            "no rejected update may change the account"
        );

        // The unconsumed OOB code still verifies the email on its own.
        let (status, applied) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"oobCode": link["oobCode"]}),
        );
        assert_eq!(status, 200, "{applied}");
        assert_eq!(applied["emailVerified"], true);

        // A normal profile update over the valid session still succeeds.
        let (status, normal) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": signed["idToken"], "displayName": "allowed"}),
        );
        assert_eq!(status, 200, "{normal}");
        assert_eq!(normal["displayName"], "allowed");

        // An unprivileged localId selector is still refused, not promoted by a body flag.
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"localId": uid, "displayName": "x", "customAttributes": "{}"}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "MISSING_ID_TOKEN");
    }
}

#[test]
fn unauthenticated_local_id_update_cannot_select_an_account_for_privileged_fields() {
    let s = state();
    let (_, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "selector-owner@example.com", "password": "password1", "returnSecureToken": true}),
    );
    let uid = signed["localId"].as_str().unwrap();
    let (_, seeded) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": uid,
            "displayName": "before",
            "customAttributes": "{\"role\":\"member\"}",
            "emailVerified": true,
            "disableUser": false
        }),
    );
    assert_eq!(seeded["displayName"], "before", "{seeded}");
    let (_, before) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid]}),
    );

    let attempts = [
        ("customAttributes", json!("{\"role\":\"attacker\"}")),
        ("emailVerified", json!(false)),
        ("disableUser", json!(true)),
        (
            "mfa",
            json!({"enrollments": [{"phoneInfo": "+16505550111"}]}),
        ),
        (
            "linkProviderUserInfo",
            json!({"providerId": "google.com", "rawId": "selector-attacker"}),
        ),
    ];
    for (field, value) in attempts {
        let mut request = json!({"localId": uid, "displayName": "must-not-apply"});
        request[field] = value;
        let (status, refused) = post(&s, &format!("{V1}/accounts:update"), &request);
        assert_eq!(status, 400, "{field}: {refused}");
        assert_eq!(refused["error"]["message"], "MISSING_ID_TOKEN", "{field}");
        assert!(refused.get("idToken").is_none(), "{field}: {refused}");
        assert!(refused.get("refreshToken").is_none(), "{field}: {refused}");
        let (_, after) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [uid]}),
        );
        assert_eq!(after, before, "{field}: rejected selector must not mutate");
    }

    let (status, updated) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "customAttributes": "{\"role\":\"admin\"}"}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["localId"], uid);
    let (_, after_admin) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [uid]}),
    );
    assert_eq!(
        after_admin["users"][0]["customAttributes"],
        "{\"role\":\"admin\"}"
    );
}

#[test]
fn admin_fields_rejection_does_not_consume_an_oob_code() {
    let s = state();
    let (_, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "email": "oob-field@example.com", "password": "password1", "returnSecureToken": true
        }),
    );
    let (status, link) = admin(
        &s,
        "POST",
        &format!("{V1}/projects/demo-app/accounts:sendOobCode"),
        &json!({
            "requestType": "VERIFY_EMAIL", "idToken": signed["idToken"], "returnOobLink": true
        }),
    );
    assert_eq!(status, 200, "{link}");
    for field in [
        "customAttributes",
        "emailVerified",
        "mfa",
        "linkProviderUserInfo",
    ] {
        let mut request = json!({"oobCode": link["oobCode"], "displayName": "must-not-apply"});
        request[field] = Value::Null;
        assert_eq!(post(&s, &format!("{V1}/accounts:update"), &request).0, 400);
    }
    let (_, before) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": signed["idToken"]}),
    );
    assert_eq!(before["users"][0]["emailVerified"], false);
    let (status, applied) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": link["oobCode"]}),
    );
    assert_eq!(status, 200, "{applied}");
    assert_eq!(applied["emailVerified"], true);
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
    // An empty refresh token is a missing one (sandbox recording 2026-09-24,
    // auth-credential/refresh/refusals#empty-refresh-token).
    for token in ["rt-unknown", "malformed.token"] {
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
fn strict_profile_admin_password_change_rejects_older_refresh_tokens() {
    let s = strict_state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "strict@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let refresh = signed["refreshToken"].clone();
    advance(&s, 1);
    let (status, changed) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": signed["localId"], "password": "password2"}),
    );
    assert_eq!(status, 200, "{changed}");
    assert!(changed.get("idToken").is_none(), "{changed}");
    assert!(changed.get("refreshToken").is_none(), "{changed}");

    let (status, expired) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 400, "{expired}");
    assert_eq!(expired["error"]["message"], "TOKEN_EXPIRED");
}

#[test]
fn strict_admin_password_change_keeps_a_same_second_refresh_usable() {
    let s = strict_state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "same-second@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let uid = signed["localId"].as_str().unwrap();
    let refresh = signed["refreshToken"].clone();

    let (status, changed) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "password": "password2"}),
    );
    assert_eq!(status, 200, "{changed}");

    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{refreshed}");
}

#[test]
fn strict_admin_password_change_preserves_account_and_credential_side_effects() {
    let s = strict_state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "admin-password-side-effects@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let uid = signed["localId"].as_str().unwrap().to_owned();

    let (status, changed) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "password": "password2"}),
    );
    assert_eq!(status, 200, "{changed}");
    assert!(changed.get("idToken").is_none(), "{changed}");
    assert!(changed.get("refreshToken").is_none(), "{changed}");

    let (status, looked) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [&uid]}),
    );
    assert_eq!(status, 200, "{looked}");
    let user = &looked["users"][0];
    assert_eq!(user["localId"], uid);
    assert_eq!(user["passwordHash"], "UkVEQUNURUQ=");
    assert!(user["passwordUpdatedAt"].is_u64(), "{user}");
    assert_eq!(user["validSince"], "1788004860");

    let (status, old_password) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "admin-password-side-effects@example.com", "password": "password1"}),
    );
    assert_eq!(status, 400, "{old_password}");
    let (status, new_password) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "admin-password-side-effects@example.com", "password": "password2", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{new_password}");
    assert_eq!(new_password["localId"], uid);
}

#[test]
fn strict_admin_password_change_retained_refresh_reports_disabled_then_deleted() {
    let s = strict_state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "admin-password-terminal@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let uid = signed["localId"].as_str().unwrap().to_owned();
    let refresh = signed["refreshToken"].clone();

    let (status, changed) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "password": "password2"}),
    );
    assert_eq!(status, 200, "{changed}");

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
        &json!({"grant_type": "refresh_token", "refresh_token": signed["refreshToken"]}),
    );
    assert_eq!(status, 400, "{deleted}");
    assert_eq!(deleted["error"]["message"], "USER_NOT_FOUND");
}

#[test]
fn strict_admin_credential_removal_keeps_refresh_and_returns_no_replacement_tokens() {
    let s = strict_state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "admin-credential-removal@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let refresh = signed["refreshToken"].clone();

    let (status, removed) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": signed["localId"], "deleteAttribute": ["PASSWORD"]}),
    );
    assert_eq!(status, 200, "{removed}");
    for field in ["idToken", "refreshToken", "expiresIn"] {
        assert!(removed.get(field).is_none(), "{field}: {removed}");
    }

    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{refreshed}");
}

#[test]
fn strict_self_service_credential_removal_keeps_refresh_and_returns_no_replacement_tokens() {
    let s = strict_state();
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "client-credential-removal@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let refresh = signed["refreshToken"].clone();

    let (status, removed) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": signed["idToken"], "deleteAttribute": ["PASSWORD"]}),
    );
    assert_eq!(status, 200, "{removed}");
    for field in ["idToken", "refreshToken", "expiresIn"] {
        assert!(removed.get(field).is_none(), "{field}: {removed}");
    }

    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 200, "{refreshed}");
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

/// Session-cookie creation as production answers it (sandbox recording 2026-09-24,
/// auth-credential/session-cookie): a zero duration is refused, a duration that is not an
/// int64 is a proto decoding error, an API key cannot stand in for the owner credential, and a
/// deleted account's token is `USER_NOT_FOUND`.
#[test]
fn session_cookie_requests_are_decoded_and_authorized_as_production_does() {
    let s = strict_state();
    let (status, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "cookie-decode@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed_up}");
    let cookie = |duration: Value| {
        admin(
            &s,
            "POST",
            &format!("{ADMIN}:createSessionCookie"),
            &json!({"idToken": signed_up["idToken"], "validDuration": duration}),
        )
    };
    let (status, zero) = cookie(json!(0));
    assert_eq!(
        (status, zero["error"]["message"].clone()),
        (400, json!("INVALID_DURATION"))
    );
    for (duration, rendered) in [(json!(3600.5), "3600.5"), (json!("an hour"), "\"an hour\"")] {
        let description = format!("Invalid value at 'valid_duration' (TYPE_INT64), {rendered}");
        let (status, refused) = cookie(duration);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(
            refused,
            json!({"error": {
                "code": 400,
                "message": description,
                "errors": [{"message": description, "reason": "invalid"}],
                "status": "INVALID_ARGUMENT",
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.BadRequest",
                    "fieldViolations": [{"field": "valid_duration", "description": description}],
                }],
            }})
        );
    }
    assert_eq!(cookie(json!("3600")).0, 200);
    let keyed = handle(
        &s,
        "POST",
        &format!("{ADMIN}:createSessionCookie?key=fake-api-key"),
        &json!({"idToken": signed_up["idToken"], "validDuration": 3600}),
    );
    assert_eq!(keyed.status, 401, "{}", keyed.body);
    assert_eq!(
        keyed.body,
        json!({"error": {
            "code": 401,
            "message": "API keys are not supported by this API. Expected OAuth2 access token or other authentication credentials that assert a principal. See https://cloud.google.com/docs/authentication",
            "errors": [{
                "message": "Login Required.",
                "domain": "global",
                "reason": "required",
                "location": "Authorization",
                "locationType": "header",
            }],
            "status": "UNAUTHENTICATED",
            "details": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "CREDENTIALS_MISSING",
                "domain": "googleapis.com",
                "metadata": {
                    "method": "google.cloud.identitytoolkit.v1.SessionManagementService.CreateSessionCookie",
                    "service": "identitytoolkit.googleapis.com",
                },
            }],
        }})
    );
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:delete"),
            &json!({"localId": signed_up["localId"]})
        )
        .0,
        200
    );
    let (status, deleted) = cookie(json!(3600));
    assert_eq!(
        (status, deleted["error"]["message"].clone()),
        (400, json!("USER_NOT_FOUND"))
    );
}

#[test]
fn session_cookie_rejects_invalid_expired_revoked_deleted_and_disabled_id_tokens() {
    for transition in ["invalid", "expired", "revoked", "deleted", "disabled"] {
        let s = state();
        let (status, signed_up) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "cookie-state@example.com", "password": "password1"}),
        );
        assert_eq!(status, 200);
        let uid = signed_up["localId"].as_str().unwrap();
        let mut token = signed_up["idToken"].clone();
        match transition {
            "invalid" => token = json!("not-a-token"),
            "expired" => {
                // Past the five-minute allowance (sandbox recording 2026-09-24).
                advance(&s, 3900);
            }
            "revoked" => {
                advance(&s, 1);
                assert_eq!(
                    admin(
                        &s,
                        "POST",
                        &format!("{ADMIN}/accounts:update"),
                        &json!({"localId": uid, "validSince": "1788004861"})
                    )
                    .0,
                    200
                );
            }
            "deleted" => assert_eq!(
                admin(
                    &s,
                    "POST",
                    &format!("{ADMIN}/accounts:delete"),
                    &json!({"localId": uid})
                )
                .0,
                200
            ),
            "disabled" => assert_eq!(
                admin(
                    &s,
                    "POST",
                    &format!("{ADMIN}/accounts:update"),
                    &json!({"localId": uid, "disableUser": true})
                )
                .0,
                200
            ),
            _ => unreachable!(),
        }
        let before = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [uid]}),
        );
        let (status, rejected) = admin(
            &s,
            "POST",
            &format!("{ADMIN}:createSessionCookie"),
            &json!({"idToken": token, "validDuration": "300"}),
        );
        assert_eq!(status, 400, "case {transition}");
        assert!(rejected.get("sessionCookie").is_none());
        let after = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [uid]}),
        );
        assert_eq!(before, after, "cookie refusal must preserve account state");
        if transition == "deleted" {
            assert!(after.1.get("users").is_none());
        }
        if transition == "disabled" {
            assert_eq!(after.1["users"][0]["disabled"], true);
        }
    }
}

#[test]
fn session_cookie_rejects_wrong_project_tenant_issuer_and_audience_without_mutation() {
    let s = state();
    let (status, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "cookie-isolation@example.com", "password": "password1"}),
    );
    assert_eq!(status, 200);
    let decoded =
        fireemu_core_auth::jwt::decode_unsigned(signed_up["idToken"].as_str().unwrap()).unwrap();
    let original: Value = serde_json::from_str(&decoded.payload_json).unwrap();
    let before = s
        .store
        .lock()
        .unwrap()
        .user_by_email("cookie-isolation@example.com")
        .unwrap()
        .clone();
    for field in ["project", "tenant", "issuer", "audience"] {
        let mut payload = original.clone();
        let mut path = format!("{ADMIN}:createSessionCookie");
        match field {
            "project" => path = path.replace("demo-app", "other-project"),
            "tenant" => payload["firebase"]["tenant"] = json!("other-tenant"),
            "issuer" => payload["iss"] = json!("https://session.firebase.google.com/demo-app"),
            "audience" => payload["aud"] = json!("other-project"),
            _ => unreachable!(),
        }
        let token = fireemu_core_auth::jwt::encode_payload_with(&payload.to_string(), None);
        let (status, refused) = admin(
            &s,
            "POST",
            &path,
            &json!({"idToken": token, "validDuration": "300"}),
        );
        assert_eq!(status, 400, "case {field}");
        assert!(refused.get("sessionCookie").is_none());
        assert_eq!(
            s.store
                .lock()
                .unwrap()
                .user_by_email("cookie-isolation@example.com")
                .unwrap(),
            &before
        );
    }
}

#[test]
fn admin_valid_since_is_parsed_before_mutation_and_applied_as_given() {
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
    // Production stores an earlier validSince as given (sandbox recording 2026-09-24,
    // auth-credential/revocation/valid-since#valid-since-before).
    assert_eq!(looked["users"][0]["validSince"], "1788004900");
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

fn assert_custom_token_claims(body: &Value, tenant: &str, uid: &str) {
    use fireemu_core_types::json::JsonValue as CoreJsonValue;

    let claims = fireemu_core_auth::jwt::decode_unsigned(body["idToken"].as_str().unwrap())
        .unwrap()
        .payload;
    assert_eq!(
        claims.get("role").and_then(CoreJsonValue::as_str),
        Some("session")
    );
    assert_eq!(
        claims.get("tokenOnly").and_then(CoreJsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        claims.get("persistedOnly").and_then(CoreJsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        claims.get("sessionOnly").and_then(CoreJsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        claims
            .get("firebase")
            .and_then(|v| v.get("tenant"))
            .and_then(CoreJsonValue::as_str),
        Some(tenant)
    );
    assert_eq!(claims.get("sub").and_then(CoreJsonValue::as_str), Some(uid));
    assert_eq!(
        claims.get("user_id").and_then(CoreJsonValue::as_str),
        Some(uid)
    );
    assert_eq!(
        claims.get("aud").and_then(CoreJsonValue::as_str),
        Some("worker-alpha")
    );
    assert_eq!(
        claims.get("iss").and_then(CoreJsonValue::as_str),
        Some("https://securetoken.google.com/worker-alpha")
    );
    assert_eq!(
        claims
            .get("firebase")
            .and_then(|v| v.get("sign_in_provider"))
            .and_then(CoreJsonValue::as_str),
        Some("custom")
    );
}

fn sign_in_custom_token(state: &AuthState, tenant: &str, uid: &str) -> Value {
    let token = custom_token_from_payload(&json!({
        "aud": fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE,
        "iss": "firebase-auth-emulator@example.com",
        "sub": "firebase-auth-emulator@example.com",
        "uid": uid,
        "claims": {"role": "token", "tokenOnly": true},
        "tenant_id": tenant,
        "iat": 1_788_004_860,
        "exp": 1_788_008_460,
    }));
    let (status, body) = post(
        state,
        &format!("{V1}/accounts:signInWithCustomToken?key=worker-key"),
        &json!({"tenantId": tenant, "token": token, "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    assert_custom_token_claims(&body, tenant, uid);
    body
}

fn assert_refreshed_claims(body: &Value, tenant: &str, uid: &str) {
    use fireemu_core_types::json::JsonValue as CoreJsonValue;

    let claims = fireemu_core_auth::jwt::decode_unsigned(body["id_token"].as_str().unwrap())
        .unwrap()
        .payload;
    assert_eq!(
        claims.get("role").and_then(CoreJsonValue::as_str),
        Some("session")
    );
    assert_eq!(
        claims.get("persistedOnly").and_then(CoreJsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        claims.get("sessionOnly").and_then(CoreJsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        claims
            .get("firebase")
            .and_then(|v| v.get("tenant"))
            .and_then(CoreJsonValue::as_str),
        Some(tenant)
    );
    assert_eq!(
        claims.get("tokenOnly").and_then(CoreJsonValue::as_bool),
        Some(true)
    );
    assert_eq!(claims.get("sub").and_then(CoreJsonValue::as_str), Some(uid));
    assert_eq!(
        claims.get("user_id").and_then(CoreJsonValue::as_str),
        Some(uid)
    );
    assert_eq!(
        claims.get("aud").and_then(CoreJsonValue::as_str),
        Some("worker-alpha")
    );
    assert_eq!(
        claims.get("iss").and_then(CoreJsonValue::as_str),
        Some("https://securetoken.google.com/worker-alpha")
    );
    assert_eq!(
        claims
            .get("firebase")
            .and_then(|v| v.get("sign_in_provider"))
            .and_then(CoreJsonValue::as_str),
        Some("custom")
    );
}

fn refresh_custom_token(state: &AuthState, body: &Value, tenant: &str) -> Value {
    let (status, refreshed) = post(
        state,
        "/securetoken.googleapis.com/v1/token?key=worker-key",
        &json!({"grant_type": "refresh_token", "refresh_token": body["refreshToken"], "tenantId": tenant}),
    );
    assert_eq!(status, 200, "{refreshed}");
    // The custom-token answer names its account only inside the token.
    let uid = token_parts(&body["idToken"]).1["sub"].clone();
    assert_refreshed_claims(&refreshed, tenant, uid.as_str().unwrap());
    refreshed
}

fn assert_custom_session_cookie_handoff(state: &AuthState, tenant: &str, token: &Value) {
    let namespace = format!("{V1}/projects/worker-alpha/tenants/{tenant}");
    let decoded = fireemu_core_auth::jwt::decode_unsigned(token.as_str().unwrap()).unwrap();
    let mut expected: Value = serde_json::from_str(&decoded.payload_json).unwrap();
    let uid = expected["sub"].clone();
    let (status, cookie) = admin(
        state,
        "POST",
        &format!("{namespace}:createSessionCookie"),
        &json!({"idToken": token, "validDuration": "300"}),
    );
    assert_eq!(status, 200);
    let cookie =
        fireemu_core_auth::jwt::decode_unsigned(cookie["sessionCookie"].as_str().unwrap()).unwrap();
    let actual: Value = serde_json::from_str(&cookie.payload_json).unwrap();
    expected["iss"] = json!("https://session.firebase.google.com/worker-alpha");
    expected["exp"] = json!(1_788_005_160);
    assert_eq!(actual, expected);
    let (status, looked_up) = post(
        state,
        &format!("{V1}/accounts:lookup?key=worker-key"),
        &json!({"tenantId": tenant, "idToken": token}),
    );
    assert_eq!(status, 200);
    assert_eq!(looked_up["users"][0]["localId"], uid);
    let (status, stored) = admin(
        state,
        "POST",
        &format!("{namespace}/accounts:lookup"),
        &json!({"localId": [uid]}),
    );
    assert_eq!(status, 200);
    let persisted: Value =
        serde_json::from_str(stored["users"][0]["customAttributes"].as_str().unwrap()).unwrap();
    assert_eq!(
        persisted,
        json!({"role": "persistent", "persistedOnly": true})
    );
    for other in [
        format!("{V1}/projects/worker-alpha:createSessionCookie"),
        format!(
            "{V1}/projects/worker-alpha/tenants/{}:createSessionCookie",
            if tenant == "customer-a" {
                "customer-b"
            } else {
                "customer-a"
            }
        ),
    ] {
        let (status, refused) = admin(
            state,
            "POST",
            &other,
            &json!({"idToken": token, "validDuration": "300"}),
        );
        assert_eq!(status, 400);
        assert!(refused.get("sessionCookie").is_none());
    }
}

fn assert_tenant_stores_after_sign_in(
    registry: &std::sync::Arc<fireemu_core_auth::store::AuthRegistry>,
) {
    let stored_a = registry
        .tenant_store("worker-alpha", "customer-a")
        .unwrap()
        .lock()
        .unwrap()
        .user_by_id("custom-a")
        .unwrap()
        .custom_claims
        .clone();
    assert!(stored_a.entries().contains_key("role"));
    assert!(stored_a.entries().contains_key("persistedOnly"));
    assert!(!stored_a.entries().contains_key("tokenOnly"));
    assert!(!stored_a.entries().contains_key("sessionOnly"));
    for tenant in ["customer-a", "customer-b"] {
        assert_eq!(
            registry
                .tenant_store("worker-alpha", tenant)
                .unwrap()
                .lock()
                .unwrap()
                .user_count(),
            1
        );
    }
}

/// A token the configured service account signed, as the Admin SDK with a real credential does.
fn signed_custom_token(
    key: &rsa::RsaPrivateKey,
    issuer: &str,
    uid: &str,
    claims: &Value,
    iat: i64,
) -> String {
    use fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE;
    use fireemu_core_auth::jwt::base64url_encode;
    use rsa::signature::{SignatureEncoding, Signer};
    let header = base64url_encode(br#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#);
    let payload = json!({
        "aud": CUSTOM_TOKEN_AUDIENCE,
        "iss": issuer,
        "sub": issuer,
        "uid": uid,
        "claims": claims,
        "iat": iat,
        "exp": iat + 3600,
    });
    let input = format!(
        "{header}.{}",
        base64url_encode(payload.to_string().as_bytes())
    );
    let signature =
        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone()).sign(input.as_bytes());
    format!("{input}.{}", base64url_encode(&signature.to_vec()))
}

fn signed_payload(key: &rsa::RsaPrivateKey, payload: &Value) -> String {
    use fireemu_core_auth::jwt::base64url_encode;
    use rsa::signature::{SignatureEncoding, Signer};
    let header = base64url_encode(br#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#);
    let input = format!(
        "{header}.{}",
        base64url_encode(payload.to_string().as_bytes())
    );
    let signature =
        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone()).sign(input.as_bytes());
    format!("{input}.{}", base64url_encode(&signature.to_vec()))
}

/// The claim rules production applies to a verified custom token (sandbox recording
/// 2026-09-24, auth-credential/custom-token/sign-in and validation).
#[test]
#[allow(clippy::too_many_lines)]
fn signed_custom_tokens_follow_production_claim_rules() {
    use fireemu_adapter_http::identity_toolkit::{CustomTokenTrust, CUSTOM_TOKEN_AUDIENCE};
    use fireemu_core_auth::jwt::base64url_encode;
    use rand_core::SeedableRng;
    use rsa::traits::PublicKeyParts;
    let account = "firebase-adminsdk-x@demo-app.iam.gserviceaccount.com";
    let key =
        rsa::RsaPrivateKey::new(&mut rand_chacha::ChaCha20Rng::seed_from_u64(21), 2048).unwrap();
    let jwks = json!({"keys": [{"kty": "RSA", "alg": "RS256", "kid": "k1",
        "n": base64url_encode(&key.n().to_bytes_be()), "e": base64url_encode(&key.e().to_bytes_be())}]});
    let trust = CustomTokenTrust::from_jwks(json!({account: jwks}).as_object().unwrap()).unwrap();
    let s = AuthState {
        custom_token_trust: Some(Arc::new(trust)),
        ..strict_state()
    };
    let now = 1_788_004_860_i64;
    let base = |uid: &str| {
        json!({"iss": account, "sub": account, "aud": CUSTOM_TOKEN_AUDIENCE,
            "iat": now, "exp": now + 3600, "uid": uid})
    };
    let with = |uid: &str, changes: &[(&str, Value)], removed: &[&str]| {
        let mut payload = base(uid);
        for (name, value) in changes {
            payload[*name] = value.clone();
        }
        for name in removed {
            payload.as_object_mut().unwrap().remove(*name);
        }
        signed_payload(&key, &payload)
    };
    let sign_in = |token: Value| {
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": token, "returnSecureToken": true}),
        );
        (
            status,
            body["error"]["message"].as_str().unwrap_or("").to_owned(),
        )
    };
    let invalid = (400, "INVALID_CUSTOM_TOKEN".to_owned());
    let length = (
        400,
        "INVALID_IDENTIFIER : Invalid user ID length. Expect to have length between 1 and 128."
            .to_owned(),
    );
    let ok = (200, String::new());
    let format = (
        400,
        "INVALID_CUSTOM_TOKEN : Invalid assertion format. 3 dot separated segments required."
            .to_owned(),
    );
    let signed = with("stripped", &[], &[]);
    let stripped = format!("{}.", signed.rsplit_once('.').unwrap().0);
    for (label, token, expected) in [
        (
            "wrong audience",
            json!(with("aud", &[("aud", json!("https://example.com"))], &[])),
            invalid.clone(),
        ),
        (
            "iss not sub",
            json!(with("iss", &[("sub", json!("someone@example.com"))], &[])),
            invalid.clone(),
        ),
        (
            "no exp",
            json!(with("no-exp", &[], &["exp"])),
            invalid.clone(),
        ),
        (
            "no iat",
            json!(with("no-iat", &[], &["iat"])),
            invalid.clone(),
        ),
        (
            "two hours",
            json!(with("long", &[("exp", json!(now + 7200))], &[])),
            invalid.clone(),
        ),
        (
            "iat ahead",
            json!(with(
                "ahead",
                &[("iat", json!(now + 600)), ("exp", json!(now + 4200))],
                &[]
            )),
            invalid.clone(),
        ),
        ("empty uid", json!(with("", &[], &[])), length.clone()),
        ("129", json!(with(&"u".repeat(129), &[], &[])), length),
        ("128", json!(with(&"u".repeat(128), &[], &[])), ok.clone()),
        (
            "claims string",
            json!(with("c1", &[("claims", json!("role=admin"))], &[])),
            (400, "INVALID_CLAIMS".to_owned()),
        ),
        (
            "claims array",
            json!(with("c2", &[("claims", json!(["role"]))], &[])),
            (400, "INVALID_CLAIMS".to_owned()),
        ),
        (
            "reserved",
            json!(with("c3", &[("claims", json!({"sub": "x"}))], &[])),
            (400, "FORBIDDEN_CLAIM : sub".to_owned()),
        ),
        (
            "1001 bytes",
            json!(with(
                "c4",
                &[("claims", json!({"k": "x".repeat(993)}))],
                &[]
            )),
            ok.clone(),
        ),
        (
            "stripped",
            json!(stripped),
            (400, "INVALID_CUSTOM_TOKEN : Missing signature.".to_owned()),
        ),
        ("garbage", json!("not-a-jwt"), format.clone()),
        ("empty", json!(""), format),
    ] {
        assert_eq!(sign_in(token), expected, "{label}");
    }
    let (status, missing) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"returnSecureToken": true}),
    );
    assert_eq!(
        (status, missing["error"]["message"].clone()),
        (400, json!("MISSING_CUSTOM_TOKEN"))
    );
    // A custom sign-in into an account created otherwise marks it as custom-authenticated.
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": "made-by-admin", "email": "admin-made@example.com"})
        )
        .0,
        200
    );
    assert_eq!(sign_in(json!(with("made-by-admin", &[], &[]))), ok);
    let (_, account) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["made-by-admin"]}),
    );
    assert_eq!(account["users"][0]["customAuth"], true, "{account}");
}

#[test]
fn configured_signers_admit_only_the_tokens_they_signed() {
    use fireemu_adapter_http::identity_toolkit::CustomTokenTrust;
    use fireemu_core_auth::jwt::base64url_encode;
    use rand_core::SeedableRng;
    use rsa::traits::PublicKeyParts;
    let own_account = "firebase-adminsdk-x@demo-app.iam.gserviceaccount.com";
    let other_account = "robot@other-project.iam.gserviceaccount.com";
    let key = |seed| {
        rsa::RsaPrivateKey::new(&mut rand_chacha::ChaCha20Rng::seed_from_u64(seed), 2048).unwrap()
    };
    let (own, other) = (key(11), key(12));
    let jwks = |k: &rsa::RsaPrivateKey| {
        json!({"keys": [{"kty": "RSA", "alg": "RS256", "kid": "k1",
            "n": base64url_encode(&k.n().to_bytes_be()), "e": base64url_encode(&k.e().to_bytes_be())}]})
    };
    let trust = CustomTokenTrust::from_jwks(
        json!({own_account: jwks(&own), other_account: jwks(&other)})
            .as_object()
            .unwrap(),
    )
    .unwrap();
    let s = AuthState {
        custom_token_trust: Some(Arc::new(trust)),
        ..strict_state()
    };
    let now = 1_788_004_860;
    let sign_in = |token: &str| {
        post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken?key=k"),
            &json!({"token": token, "returnSecureToken": true}),
        )
    };
    let (status, body) = sign_in(&signed_custom_token(
        &own,
        own_account,
        "signed-1",
        &json!({"role": "r"}),
        now,
    ));
    assert_eq!(status, 200, "{body}");
    let claims = fireemu_core_auth::jwt::decode_unsigned(body["idToken"].as_str().unwrap())
        .unwrap()
        .payload;
    assert_eq!(claims.get("role").and_then(|v| v.as_str()), Some("r"));
    assert_eq!(claims.get("sub").and_then(|v| v.as_str()), Some("signed-1"));
    let refused = |token: String| {
        let (status, body) = sign_in(&token);
        (
            status,
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    };
    assert_eq!(
        refused(signed_custom_token(
            &other,
            other_account,
            "signed-2",
            &json!({}),
            now
        )),
        (400, "CREDENTIAL_MISMATCH".to_owned())
    );
    assert_eq!(
        refused(custom_token("signed-3", &json!({}), now + 3600)),
        (400, "INVALID_CUSTOM_TOKEN".to_owned()),
        "an unsigned token is refused once signers are configured"
    );
    assert_eq!(
        refused(signed_custom_token(
            &other,
            own_account,
            "signed-4",
            &json!({}),
            now
        )),
        (400, "INVALID_CUSTOM_TOKEN".to_owned()),
        "a signature by another key than the issuer's"
    );
    assert_eq!(
        refused(r#"{"uid":"json-token"}"#.to_owned()),
        (
            400,
            "INVALID_CUSTOM_TOKEN : Invalid assertion format. 3 dot separated segments required."
                .to_owned()
        ),
        "the emulator's JSON fake token is not a signed token"
    );
}

fn token_parts(token: &Value) -> (Value, Value) {
    let mut parts = token.as_str().unwrap().split('.');
    let mut part = || {
        serde_json::from_slice::<Value>(
            &fireemu_core_auth::jwt::base64url_decode(parts.next().unwrap()).unwrap(),
        )
        .unwrap()
    };
    (part(), part())
}

fn keys(body: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

/// Without `returnSecureToken`, password and custom-token sign-in answer with the legacy
/// Identity Toolkit token and no refresh token; account lookup honours it and session-cookie
/// creation refuses it. Custom-token answers never carry `localId` (sandbox recording
/// 2026-09-24, auth-credential/id-token/without-return-secure-token and methods).
#[test]
fn sign_in_without_secure_tokens_answers_with_the_legacy_identity_toolkit_token() {
    let s = strict_state_with_signer();
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "legacy@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{created}");
    for request in [
        json!({"email": "legacy@example.com", "password": "password1"}),
        json!({"email": "legacy@example.com", "password": "password1", "returnSecureToken": false}),
    ] {
        let (status, body) = post(&s, &format!("{V1}/accounts:signInWithPassword"), &request);
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            keys(&body),
            [
                "displayName",
                "email",
                "idToken",
                "kind",
                "localId",
                "registered"
            ]
        );
        let (header, claims) = token_parts(&body["idToken"]);
        assert_eq!(header, json!({"alg": "none"}));
        assert_eq!(claims["iss"], "https://identitytoolkit.google.com/");
        assert_eq!(claims["aud"], "demo-app");
        assert_eq!(claims["user_id"], created["localId"]);
        assert_eq!(claims["email"], "legacy@example.com");
        assert_eq!(claims["verified"], false);
        assert_eq!(claims["sign_in_provider"], "password");
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            1_209_600
        );
        for absent in ["sub", "auth_time", "firebase", "email_verified"] {
            assert!(claims.get(absent).is_none(), "{absent}: {claims}");
        }
        let (status, looked_up) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": body["idToken"]}),
        );
        assert_eq!(status, 200, "{looked_up}");
        assert_eq!(looked_up["users"][0]["localId"], created["localId"]);
        let (status, refused) = admin(
            &s,
            "POST",
            &format!("{ADMIN}:createSessionCookie"),
            &json!({"idToken": body["idToken"], "validDuration": 3600}),
        );
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "INVALID_ID_TOKEN");
    }
    let now = 1_788_004_860;
    let (status, legacy) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({"token": trusted_custom_token("legacy-custom", &json!({"role": "r"}), now)}),
    );
    assert_eq!(status, 200, "{legacy}");
    assert_eq!(keys(&legacy), ["idToken", "isNewUser", "kind"]);
    let (header, claims) = token_parts(&legacy["idToken"]);
    assert_eq!(header, json!({"alg": "none"}));
    assert_eq!(claims["sign_in_provider"], "custom");
    assert_eq!(claims["user_id"], "legacy-custom");
    assert_eq!(claims["extra_claims"], json!({"role": "r"}));
    assert!(claims.get("role").is_none());
    let (_, account) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["legacy-custom"]}),
    );
    let user = &account["users"][0];
    assert_eq!(user["customAuth"], true, "{account}");
    assert!(user.get("validSince").is_some(), "{user}");
    assert!(user.get("lastRefreshAt").is_none(), "{user}");
    assert!(user.get("disabled").is_none(), "{user}");
    let (status, secure) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken"),
        &json!({
            "token": trusted_custom_token("legacy-custom", &json!({}), now),
            "returnSecureToken": true,
        }),
    );
    assert_eq!(status, 200, "{secure}");
    assert_eq!(
        keys(&secure),
        ["expiresIn", "idToken", "isNewUser", "kind", "refreshToken"]
    );
}

/// An Admin update answers `emailVerified` only for an account with an address (sandbox
/// recording 2026-09-24, auth-credential/revocation/valid-since#custom-valid-since-after).
#[test]
fn admin_update_reports_email_verified_only_with_an_address() {
    let s = strict_state();
    for (id, email) in [
        ("no-address", None),
        ("with-address", Some("with-address@example.com")),
    ] {
        let mut create = json!({"localId": id});
        if let Some(email) = email {
            create["email"] = json!(email);
        }
        assert_eq!(
            admin(&s, "POST", &format!("{ADMIN}/accounts"), &create).0,
            200
        );
        let (status, updated) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": id, "validSince": "1788004000"}),
        );
        assert_eq!(status, 200, "{updated}");
        assert_eq!(
            updated.get("emailVerified").is_some(),
            email.is_some(),
            "{updated}"
        );
    }
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
    // Production's answer names the account only inside the token.
    assert!(body.get("localId").is_none(), "{body}");
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
    let (status, account) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["custom-1"]}),
    );
    assert_eq!(status, 200, "{account}");
    assert_eq!(account["users"].as_array().unwrap().len(), 1);
    assert_eq!(account["users"][0]["localId"], "custom-1");
    assert!(
        account["users"][0]["customAttributes"].is_null(),
        "custom-token claims must not become Admin customAttributes"
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
#[allow(clippy::too_many_lines)]
fn custom_token_claims_compose_with_tenant_session_claims_and_refresh_stays_in_namespace() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    assert!(registry.register(
        "worker-alpha",
        AuthStore::new("worker-alpha", SplitMix64::new(7), TotpPolicy::default()),
    ));
    for tenant in ["customer-a", "customer-b"] {
        registry.ensure_tenant("worker-alpha", tenant).unwrap();
    }
    s.registry = Some(registry.clone());
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-alpha", &[], &["worker-key".to_owned()])
        .unwrap();
    s.tenancy = Some(Arc::new(RwLock::new(tenancy)));
    s.blocking = Some(Arc::new(OverlappingClaimHook));

    let a = sign_in_custom_token(&s, "customer-a", "custom-a");
    let b = sign_in_custom_token(&s, "customer-b", "custom-b");
    assert_tenant_stores_after_sign_in(&registry);

    for (tenant, signed_in) in [("customer-a", &a), ("customer-b", &b)] {
        assert_custom_session_cookie_handoff(&s, tenant, &signed_in["idToken"]);
        let refreshed = refresh_custom_token(&s, signed_in, tenant);
        assert_custom_session_cookie_handoff(&s, tenant, &refreshed["id_token"]);
    }
    assert_tenant_stores_after_sign_in(&registry);

    // A tenant-scoped ID token must not be accepted when the client selects a
    // different tenant, even though both tenants use the same project API key.
    // Keep this separate from refresh-token routing: it verifies the subject's
    // namespace binding at the user-facing lookup boundary.
    let (status, refused_lookup) = post(
        &s,
        "/identitytoolkit.googleapis.com/v1/accounts:lookup?key=worker-key",
        &json!({
            "tenantId": "customer-b",
            "idToken": a["idToken"],
        }),
    );
    assert_eq!(status, 400, "{refused_lookup}");
    assert_eq!(refused_lookup["error"]["message"], "INVALID_ID_TOKEN");
    assert_tenant_stores_after_sign_in(&registry);

    let before_a = registry
        .tenant_store("worker-alpha", "customer-a")
        .unwrap()
        .lock()
        .unwrap()
        .user_count();
    let before_b = registry
        .tenant_store("worker-alpha", "customer-b")
        .unwrap()
        .lock()
        .unwrap()
        .user_count();
    let before_user_a = registry
        .tenant_store("worker-alpha", "customer-a")
        .unwrap()
        .lock()
        .unwrap()
        .user_by_id("custom-a")
        .unwrap()
        .clone();
    let before_user_b = registry
        .tenant_store("worker-alpha", "customer-b")
        .unwrap()
        .lock()
        .unwrap()
        .user_by_id("custom-b")
        .unwrap()
        .clone();
    let (status, refused) = post(
        &s,
        "/securetoken.googleapis.com/v1/token?key=worker-key",
        &json!({"grant_type": "refresh_token", "refresh_token": a["refreshToken"], "tenantId": "customer-b"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "INVALID_REFRESH_TOKEN");
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-a")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_a
    );
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-a")
            .unwrap()
            .lock()
            .unwrap()
            .user_by_id("custom-a")
            .unwrap(),
        &before_user_a
    );
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-b")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_b
    );
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-b")
            .unwrap()
            .lock()
            .unwrap()
            .user_by_id("custom-b")
            .unwrap(),
        &before_user_b
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
    assert!(body.get("localId").is_none(), "{body}");
    assert_eq!(token_parts(&body["idToken"]).1["sub"], "legacy-custom");
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
    assert_eq!(token_parts(&body["idToken"]).1["sub"], "legacy-expired");

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
    assert_eq!(
        token_parts(&body["idToken"]).1["sub"],
        "legacy-other-issuer"
    );
}

#[test]
fn strict_profile_rejects_an_expired_custom_token() {
    let s = strict_state();
    // Past the five-minute allowance production refuses it as invalid (sandbox recording
    // 2026-09-24, auth-credential/expiry/one-hour#custom-token-expired-later).
    let expired = custom_token("strict-expired", &json!({}), 1_788_004_860 - 300);
    let (status, body) = post(
        &s,
        "/www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=demo-key",
        &json!({"token": expired}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], "INVALID_CUSTOM_TOKEN");
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
    // A page token is the user id the next page starts after, so the last account's id is an
    // empty page (sandbox recording 2026-09-23).
    let (status, page) = admin(
        &s,
        "GET",
        &format!("{ADMIN}/accounts:batchGet?nextPageToken=u-m"),
        &json!({}),
    );
    assert_eq!((status, page.get("users").is_none()), (200, true), "{page}");
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
    assert_eq!(
        keys,
        ["createdAt", "lastLoginAt", "lastRefreshAt", "localId"],
        "{looked}"
    );

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

/// Saved second45 production candidate: malformed inputs never select another user.
#[test]
#[allow(clippy::too_many_lines)]
fn second45_observed_update_shapes_preserve_ownership_and_atomicity() {
    for s in [state(), strict_state()] {
        for (index, (field, value, expected_status, expected_name, machine)) in [
            ("localId", json!({}), 400, "baseline-b", "INVALID_ARGUMENT"),
            ("localId", json!([]), 400, "baseline-b", "INVALID_ARGUMENT"),
            ("displayName", json!(0), 200, "0", ""),
            (
                "displayName",
                json!(false),
                400,
                "baseline-b",
                "INVALID_ARGUMENT",
            ),
            (
                "displayName",
                json!([]),
                400,
                "baseline-b",
                "INVALID_ARGUMENT",
            ),
            (
                "displayName",
                json!({}),
                400,
                "baseline-b",
                "INVALID_ARGUMENT",
            ),
            (
                "emailVerified",
                json!({}),
                400,
                "baseline-b",
                "INVALID_ARGUMENT",
            ),
            (
                "customAttributes",
                json!("{\"admin\":true}"),
                400,
                "baseline-b",
                "INSUFFICIENT_PERMISSION",
            ),
            (
                "customAttributes",
                json!(""),
                400,
                "baseline-b",
                "INSUFFICIENT_PERMISSION",
            ),
            ("customAttributes", Value::Null, 200, "sentinel", ""),
            (
                "customAttributes",
                json!({}),
                400,
                "baseline-b",
                "INVALID_ARGUMENT",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let (_, a) = post(
                &s,
                &format!("{V1}/accounts:signUp"),
                &json!({"email":format!("a-{index}@example.com"),"password":"password1","returnSecureToken":true}),
            );
            let (_, b) = post(
                &s,
                &format!("{V1}/accounts:signUp"),
                &json!({"email":format!("b-{index}@example.com"),"password":"password1","returnSecureToken":true}),
            );
            for (u, name) in [(&a, "baseline-a"), (&b, "baseline-b")] {
                let (status, response) = admin(
                    &s,
                    "POST",
                    &format!("{ADMIN}/accounts:update"),
                    &json!({"localId":u["localId"],"displayName":name,"emailVerified":false}),
                );
                assert_eq!(status, 200, "{response}");
            }
            let mut request = json!({"idToken":b["idToken"],"localId":a["localId"],"displayName":"sentinel","emailVerified":true});
            request[field] = value;
            let (status, response) = post(&s, &format!("{V1}/accounts:update"), &request);
            assert_eq!(status, expected_status, "{field}: {response}");
            if machine == "INVALID_ARGUMENT" {
                assert_eq!(response["error"]["status"], machine, "{response}");
                assert_eq!(
                    response["error"]["details"][0]["@type"],
                    "type.googleapis.com/google.rpc.BadRequest"
                );
                assert!(
                    response["error"]["details"][0]["fieldViolations"][0]["description"]
                        .is_string()
                );
                assert!(response["error"]["errors"][0].get("domain").is_none());
            } else if !machine.is_empty() {
                assert_eq!(response["error"]["message"], machine);
            }
            for (u, name) in [(&a, "baseline-a"), (&b, expected_name)] {
                let (status, after) = admin(
                    &s,
                    "POST",
                    &format!("{ADMIN}/accounts:lookup"),
                    &json!({"localId":[u["localId"]]}),
                );
                assert_eq!(status, 200);
                assert_eq!(after["users"][0]["displayName"], name, "{field}");
                assert_eq!(after["users"][0]["emailVerified"], false);
                assert!(after["users"][0].get("customAttributes").is_none());
            }
        }
    }
}

#[test]
fn second45_missing_or_null_token_update_classifies_observed_input() {
    let s = state();
    for token in [None, Some(Value::Null)] {
        let mut request = json!({"displayName":"sentinel","localId":"unowned"});
        if let Some(token) = token {
            request["idToken"] = token;
        }
        let (status, response) = post(&s, &format!("{V1}/accounts:update"), &request);
        assert_eq!(status, 400);
        assert_eq!(response["error"]["message"], "INVALID_REQ_TYPE");
    }
}

/// Local safety contract: decoder errors do not bypass session authentication.
#[test]
fn second45_invalid_token_precedes_new_shape_validation_without_mutation() {
    for s in [state(), strict_state()] {
        let (_, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email":"precedence@example.com","password":"password1","returnSecureToken":true}),
        );
        let lookup = || {
            admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:lookup"),
                &json!({"localId":[signed["localId"]]}),
            )
            .1
        };
        let before = lookup();
        for (field, value) in [
            ("localId", json!({})),
            ("displayName", json!(false)),
            ("emailVerified", json!({})),
            ("customAttributes", json!({})),
        ] {
            let mut request = json!({"idToken":"invalid","displayName":"must-not-apply"});
            request[field] = value;
            let (status, response) = post(&s, &format!("{V1}/accounts:update"), &request);
            assert_eq!(status, 400);
            assert_eq!(response["error"]["message"], "INVALID_ID_TOKEN", "{field}");
            assert_eq!(lookup(), before, "{field}");
        }
    }
}

fn enforce_custom_password_policy(s: &AuthState) {
    let (status, body) = admin(
        s,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=passwordPolicyConfig",
        &json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "ENFORCE",
            "passwordPolicyVersions": [{"customStrengthOptions": {
                "minPasswordLength": 8,
                "maxPasswordLength": 20,
                "containsUppercaseCharacter": true,
                "containsLowercaseCharacter": true,
                "containsNumericCharacter": true,
                "containsNonAlphanumericCharacter": true
            }}]
        }}),
    );
    assert_eq!(status, 200, "{body}");
}

/// `batchCreate` stores a raw password without the minimum length or the project's policy,
/// and signs in with it (sandbox recording 2026-09-23, `policy/*#import-raw-weak`).
#[test]
fn batch_import_stores_raw_passwords_below_the_policy() {
    let default_policy = state();
    let enforced = state();
    enforce_custom_password_policy(&enforced);
    for (s, password) in [(&default_policy, "12345"), (&enforced, "password")] {
        let (status, imported) = admin(
            s,
            "POST",
            &format!("{ADMIN}/accounts:batchCreate"),
            &json!({"users": [{"localId": "weak", "email": "weak@example.com", "rawPassword": password}]}),
        );
        assert_eq!(status, 200, "{imported}");
        assert!(imported.get("error").is_none(), "{imported}");
        let (status, signed) = post(
            s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "weak@example.com", "password": password}),
        );
        assert_eq!(status, 200, "{signed}");
    }
}

/// Under an enforced custom policy, an Admin update names the unmet requirements before it
/// looks the account up; the default minimum is checked after (sandbox recording 2026-09-23,
/// `policy/enforce-custom#admin-update-weak` and `policy/default/routes#admin-update-weak`).
#[test]
fn admin_password_update_checks_a_custom_policy_before_the_account() {
    let enforced = state();
    enforce_custom_password_policy(&enforced);
    let (status, refused) = admin(
        &enforced,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "nobody", "password": "password"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Missing password requirements: ["),
        "{refused}"
    );
    let (status, refused) = admin(
        &state(),
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "nobody", "password": "12345"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_NOT_FOUND");
}

#[test]
fn admin_v2_password_policy_leaf_masks_preserve_unselected_fields() {
    let s = state();
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let policy = json!({
        "passwordPolicyEnforcementState": "ENFORCE",
        "forceUpgradeOnSignin": true,
        "passwordPolicyVersions": [{"customStrengthOptions": {
            "minPasswordLength": 12,
            "maxPasswordLength": 100,
            "containsUppercaseCharacter": true,
            "containsLowercaseCharacter": true,
            "containsNumericCharacter": true,
            "containsNonAlphanumericCharacter": true
        }}]
    });
    let initial = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig"),
        &json!({"passwordPolicyConfig": policy}),
    );
    assert_eq!(initial.0, 200, "{}", initial.1);

    let state_only = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig.passwordPolicyEnforcementState"),
        &json!({
            "passwordPolicyConfig": {
                "passwordPolicyEnforcementState": "OFF",
                "forceUpgradeOnSignin": false,
                "passwordPolicyVersions": [{"customStrengthOptions": {
                    "minPasswordLength": 6,
                    "maxPasswordLength": 8
                }}]
            }
        }),
    );
    assert_eq!(state_only.0, 200, "{}", state_only.1);
    assert_eq!(
        state_only.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "OFF"
    );
    assert_eq!(
        state_only.1["passwordPolicyConfig"]["forceUpgradeOnSignin"],
        true
    );
    assert_eq!(
        state_only.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );
    assert_eq!(
        state_only.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["maxPasswordLength"],
        100
    );

    let force_and_state = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig.passwordPolicyEnforcementState,passwordPolicyConfig.forceUpgradeOnSignin"),
        &json!({
            "passwordPolicyConfig": {
                "passwordPolicyEnforcementState": "ENFORCE",
                "forceUpgradeOnSignin": false,
                "passwordPolicyVersions": [{"customStrengthOptions": {
                    "minPasswordLength": 6
                }}]
            }
        }),
    );
    assert_eq!(force_and_state.0, 200, "{}", force_and_state.1);
    assert_eq!(
        force_and_state.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "ENFORCE"
    );
    assert_eq!(
        force_and_state.1["passwordPolicyConfig"]["forceUpgradeOnSignin"],
        false
    );
    assert_eq!(
        force_and_state.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]
            ["customStrengthOptions"]["minPasswordLength"],
        12
    );
}

#[test]
fn admin_v2_project_quota_settings_patch_and_readback_are_atomic() {
    let s = state();
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let quota = json!({
        "signUpQuotaConfig": {
            "quota": "2",
            "startTime": "2030-01-01T00:00:00Z",
            "quotaDuration": "3600s"
        },
        "quotaSimulation": {
            "mode": "enforce",
            "algorithm": "fixed-window-v1",
            "defaultQuotaPerHour": 17,
            "maxTrackedBuckets": 8
        }
    });

    let updated = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=quota.signUpQuotaConfig,quota.quotaSimulation"),
        &json!({"quota": quota}),
    );
    assert_eq!(updated.0, 200, "{}", updated.1);
    assert_eq!(updated.1["quota"], quota);

    let read = admin(&s, "GET", path, &json!({}));
    assert_eq!(read.0, 200, "{}", read.1);
    assert_eq!(read.1["quota"], quota);

    let mixed = admin(
        &s,
        "PATCH",
        &format!(
            "{path}?updateMask=passwordPolicyConfig.passwordPolicyEnforcementState,client.permissions.disabledUserSignup,quota.quotaSimulation.mode"
        ),
        &json!({
            "passwordPolicyConfig": {
                "passwordPolicyEnforcementState": "ENFORCE"
            },
            "client": {"permissions": {"disabledUserSignup": true}},
            "quota": {"quotaSimulation": {"mode": "observe"}}
        }),
    );
    assert_eq!(mixed.0, 200, "{}", mixed.1);
    assert_eq!(
        mixed.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "ENFORCE"
    );
    assert_eq!(mixed.1["client"]["permissions"]["disabledUserSignup"], true);
    assert_eq!(mixed.1["quota"]["quotaSimulation"]["mode"], "observe");
    assert_eq!(
        mixed.1["quota"]["signUpQuotaConfig"],
        quota["signUpQuotaConfig"]
    );
    let mut quota_after_mixed = quota.clone();
    quota_after_mixed["quotaSimulation"]["mode"] = json!("observe");

    let rejected = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=quota.signUpQuotaConfig,quota.quotaSimulation"),
        &json!({
            "quota": {
                "signUpQuotaConfig": {
                    "quota": "not-a-number",
                    "startTime": "2030-01-01T00:00:00Z",
                    "quotaDuration": "3600s"
                },
                "quotaSimulation": {
                    "mode": "observe",
                    "algorithm": "fixed-window-v1",
                    "defaultQuotaPerHour": 21,
                    "maxTrackedBuckets": 9
                }
            }
        }),
    );
    assert_eq!(rejected.0, 400, "{}", rejected.1);

    let unchanged = admin(&s, "GET", path, &json!({}));
    assert_eq!(unchanged.0, 200, "{}", unchanged.1);
    assert_eq!(unchanged.1["quota"], quota_after_mixed);

    let unsupported_mask = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=quota.signUpQuotaConfig.quota"),
        &json!({
            "quota": {
                "signUpQuotaConfig": {
                    "quota": "3",
                    "startTime": "2030-01-01T00:00:00Z",
                    "quotaDuration": "3600s"
                }
            }
        }),
    );
    assert_eq!(unsupported_mask.0, 400, "{}", unsupported_mask.1);

    let after_unsupported_mask = admin(&s, "GET", path, &json!({}));
    assert_eq!(
        after_unsupported_mask.0, 200,
        "{}",
        after_unsupported_mask.1
    );
    assert_eq!(after_unsupported_mask.1["quota"], quota_after_mixed);
}

#[test]
fn admin_v2_password_policy_and_quota_patches_preserve_disjoint_updates() {
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
        let policy_state = Arc::clone(&state);
        let policy_start = Arc::clone(&start);
        scope.spawn(move || {
            policy_start.wait();
            let response = admin(
                &policy_state,
                "PATCH",
                &format!(
                    "{path}?updateMask=passwordPolicyConfig.passwordPolicyEnforcementState"
                ),
                &json!({
                    "passwordPolicyConfig": {
                        "passwordPolicyEnforcementState": "ENFORCE",
                        "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 12}}]
                    }
                }),
            );
            assert_eq!(response.0, 200, "{}", response.1);
        });
        let quota_state = Arc::clone(&state);
        let quota_start = Arc::clone(&start);
        scope.spawn(move || {
            quota_start.wait();
            let response = admin(
                &quota_state,
                "PATCH",
                &format!("{path}?updateMask=quota.quotaSimulation.mode"),
                &json!({"quota": {"quotaSimulation": {"mode": "enforce"}}}),
            );
            assert_eq!(response.0, 200, "{}", response.1);
        });
        start.wait();
    });

    let read = admin(&state, "GET", path, &json!({}));
    assert_eq!(read.0, 200, "{}", read.1);
    assert_eq!(
        read.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "ENFORCE"
    );
    assert_eq!(read.1["quota"]["quotaSimulation"]["mode"], "enforce");
}

#[test]
fn admin_v2_concurrent_password_policy_leaf_patches_preserve_disjoint_updates() {
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
        let enforcement_state = Arc::clone(&state);
        let enforcement_start = Arc::clone(&start);
        scope.spawn(move || {
            enforcement_start.wait();
            let response = admin(
                &enforcement_state,
                "PATCH",
                &format!(
                    "{path}?updateMask=passwordPolicyConfig.passwordPolicyEnforcementState"
                ),
                &json!({
                    "passwordPolicyConfig": {
                        "passwordPolicyEnforcementState": "ENFORCE",
                        "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 12}}]
                    }
                }),
            );
            assert_eq!(response.0, 200, "{}", response.1);
        });
        let force_state = Arc::clone(&state);
        let force_start = Arc::clone(&start);
        scope.spawn(move || {
            force_start.wait();
            let response = admin(
                &force_state,
                "PATCH",
                &format!("{path}?updateMask=passwordPolicyConfig.forceUpgradeOnSignin"),
                &json!({
                    "passwordPolicyConfig": {
                        "forceUpgradeOnSignin": true,
                        "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 6}}]
                    }
                }),
            );
            assert_eq!(response.0, 200, "{}", response.1);
        });
        start.wait();
    });

    let read = admin(&state, "GET", path, &Value::Null);
    assert_eq!(read.0, 200, "{}", read.1);
    assert_eq!(
        read.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "ENFORCE"
    );
    assert_eq!(read.1["passwordPolicyConfig"]["forceUpgradeOnSignin"], true);
}

#[test]
fn admin_v2_password_policy_invalid_selected_update_is_atomic() {
    let s = state();
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let initial = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig"),
        &json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "ENFORCE",
            "forceUpgradeOnSignin": true,
            "passwordPolicyVersions": [{"customStrengthOptions": {
                "minPasswordLength": 12,
                "containsNumericCharacter": true
            }}]
        }}),
    );
    assert_eq!(initial.0, 200, "{}", initial.1);

    for body in [
        json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "OFF",
            "passwordPolicyVersions": [{}]
        }}),
        json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "OFF",
            "passwordPolicyVersions": [{"customStrengthOptions": {
                "minPasswordLength": 5
            }}]
        }}),
        json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "OFF",
            "unexpected": true
        }}),
    ] {
        let refused = admin(
            &s,
            "PATCH",
            &format!("{path}?updateMask=passwordPolicyConfig.passwordPolicyVersions,passwordPolicyConfig.passwordPolicyEnforcementState"),
            &body,
        );
        assert_eq!(refused.0, 400, "{}", refused.1);
        let after = admin(&s, "GET", path, &Value::Null);
        assert_eq!(after.0, 200, "{}", after.1);
        assert_eq!(
            after.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
            "ENFORCE"
        );
        assert_eq!(
            after.1["passwordPolicyConfig"]["forceUpgradeOnSignin"],
            true
        );
        assert_eq!(
            after.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
                ["minPasswordLength"],
            12
        );
        assert_eq!(
            after.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
                ["containsNumericCharacter"],
            true
        );
    }
}

/// The SDK policy lists production's 30 non-alphanumeric characters in production's order
/// (sandbox recording 2026-09-23, `policy/enforce-custom#password-policy`).
#[test]
fn password_policy_lists_production_symbols_in_production_order() {
    let s = state();
    enforce_custom_password_policy(&s);
    let (status, policy) = admin(
        &s,
        "GET",
        "/identitytoolkit.googleapis.com/v2/passwordPolicy?key=fake-api-key",
        &Value::Null,
    );
    assert_eq!(status, 200, "{policy}");
    let listed: String = policy["allowedNonAlphanumericCharacters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert_eq!(listed, r#"^$*.[]{}()?"!@#%&/\,><':;|_~`-"#);
}

#[test]
fn password_policy_projections_omit_unset_custom_maximum() {
    let s = state();
    let config_path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let config = admin(&s, "GET", config_path, &Value::Null);
    assert_eq!(config.0, 200, "{}", config.1);
    assert!(
        config.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            .get("maxPasswordLength")
            .is_none()
    );

    let sdk = admin(
        &s,
        "GET",
        "/identitytoolkit.googleapis.com/v2/passwordPolicy?key=fake-api-key",
        &Value::Null,
    );
    assert_eq!(sdk.0, 200, "{}", sdk.1);
    assert!(sdk.1["customStrengthOptions"]
        .get("maxPasswordLength")
        .is_none());
}

#[test]
fn tenant_password_policy_leaf_mask_preserves_unselected_fields() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    s.registry = Some(registry);
    let path = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/tenant-a";
    let initial = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig"),
        &json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "ENFORCE",
            "forceUpgradeOnSignin": true,
            "passwordPolicyVersions": [{"customStrengthOptions": {
                "minPasswordLength": 12,
                "maxPasswordLength": 100
            }}]
        }}),
    );
    assert_eq!(initial.0, 200, "{}", initial.1);
    let state_only = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig.passwordPolicyEnforcementState"),
        &json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "OFF",
            "forceUpgradeOnSignin": false,
            "passwordPolicyVersions": [{"customStrengthOptions": {
                "minPasswordLength": 6
            }}]
        }}),
    );
    assert_eq!(state_only.0, 200, "{}", state_only.1);
    assert_eq!(
        state_only.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "OFF"
    );
    assert_eq!(
        state_only.1["passwordPolicyConfig"]["forceUpgradeOnSignin"],
        true
    );
    assert_eq!(
        state_only.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );
    assert_eq!(
        state_only.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["maxPasswordLength"],
        100
    );
}

#[test]
fn tenant_password_policy_null_without_mask_is_absent_and_list_projects_policy() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    s.registry = Some(registry);
    let path = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/tenant-a";
    let configured = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig"),
        &json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "ENFORCE",
            "forceUpgradeOnSignin": true,
            "passwordPolicyVersions": [{"customStrengthOptions": {
                "minPasswordLength": 12
            }}]
        }}),
    );
    assert_eq!(configured.0, 200, "{}", configured.1);

    let before = admin(&s, "GET", path, &Value::Null);
    assert_eq!(before.0, 200, "{}", before.1);

    // A message-level ProtoJSON null without an update mask is absent and preserves the policy.
    let absent = admin(&s, "PATCH", path, &json!({"passwordPolicyConfig": null}));
    assert_eq!(absent.0, 200, "{}", absent.1);
    assert_eq!(absent.1, before.1);

    // A selected null explicitly clears the message to the default policy.
    let cleared = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig"),
        &json!({"passwordPolicyConfig": null}),
    );
    assert_eq!(cleared.0, 200, "{}", cleared.1);
    assert_eq!(
        cleared.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "OFF"
    );

    let restored = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=passwordPolicyConfig"),
        &json!({"passwordPolicyConfig": {
            "passwordPolicyEnforcementState": "ENFORCE",
            "forceUpgradeOnSignin": true,
            "passwordPolicyVersions": [{"customStrengthOptions": {
                "minPasswordLength": 12
            }}]
        }}),
    );
    assert_eq!(restored.0, 200, "{}", restored.1);

    let listed = admin(
        &s,
        "GET",
        "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants",
        &Value::Null,
    );
    assert_eq!(listed.0, 200, "{}", listed.1);
    let listed_tenant = listed.1["tenants"]
        .as_array()
        .and_then(|tenants| {
            tenants
                .iter()
                .find(|tenant| tenant["name"] == "projects/demo-app/tenants/tenant-a")
        })
        .expect("tenant is listed");
    assert_eq!(
        listed_tenant["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "ENFORCE"
    );
    assert_eq!(
        listed_tenant["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );
}

/// Client permissions refuse the end-user operation with `ADMIN_ONLY_OPERATION` (sandbox
/// recording 2026-09-23, `auth-account/config/client-permissions`).
/// Password sign-in reports the account's photo as `profilePicture` (sandbox recording
/// 2026-09-23, `auth-account/admin/create#sign-in-created`).
#[test]
fn password_sign_in_reports_the_profile_picture() {
    let s = state();
    let (status, created) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"email": "pic@example.com", "password": "password1", "photoUrl": "https://example.com/p.png"}),
    );
    assert_eq!(status, 200, "{created}");
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"email": "nopic@example.com", "password": "password1"}),
    );
    assert_eq!(status, 200);
    let sign_in = |email: &str| {
        post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": email, "password": "password1", "returnSecureToken": true}),
        )
    };
    let (status, signed) = sign_in("pic@example.com");
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["profilePicture"], "https://example.com/p.png");
    let (status, signed) = sign_in("nopic@example.com");
    assert_eq!(status, 200, "{signed}");
    assert!(signed.get("profilePicture").is_none(), "{signed}");
}

/// An Admin email change answers without `newEmail` (sandbox recording 2026-09-23,
/// `auth-account/admin/update#change-email`).
#[test]
fn admin_email_change_answers_without_new_email() {
    let s = state();
    let (status, created) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "mail", "email": "before@example.com"}),
    );
    assert_eq!(status, 200, "{created}");
    let (status, updated) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "mail", "email": "after@example.com"}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["email"], "after@example.com");
    assert!(updated.get("newEmail").is_none(), "{updated}");
}

/// `accounts:batchGet` lists in user-id order and its page token is the last user id of the
/// page; any other string is read as a user id (sandbox recording 2026-09-23,
/// `auth-account/admin/batch-get`).
#[test]
fn admin_batch_get_pages_by_user_id() {
    let s = state();
    for uid in ["m", "b", "x", "a"] {
        let (status, created) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": uid}),
        );
        assert_eq!(status, 200, "{created}");
    }
    let page = |query: &str| {
        let (status, body) = admin(
            &s,
            "GET",
            &format!("{ADMIN}/accounts:batchGet?{query}"),
            &json!({}),
        );
        assert_eq!(status, 200, "{body}");
        let ids: Vec<String> = body
            .get("users")
            .map_or(&[][..], |users| users.as_array().unwrap())
            .iter()
            .map(|user| user["localId"].as_str().unwrap().to_owned())
            .collect();
        (ids, body.get("nextPageToken").cloned())
    };
    assert_eq!(
        page("maxResults=2"),
        (vec!["a".to_owned(), "b".to_owned()], Some(json!("b")))
    );
    assert_eq!(
        page("maxResults=2&nextPageToken=b"),
        (vec!["m".to_owned(), "x".to_owned()], None)
    );
    assert_eq!(
        page("maxResults=2&nextPageToken=c"),
        (vec!["m".to_owned(), "x".to_owned()], None)
    );
    assert_eq!(
        page("maxResults=2&nextPageToken=not-a-token"),
        (vec!["x".to_owned()], None)
    );
}

/// Value classes production answers differently from the bare format rules (sandbox recording
/// 2026-09-23, `auth-account/values`).
#[test]
fn value_classes_follow_production() {
    let s = state();
    // A formatted E.164 number is stored normalized; letters map through the phone keypad;
    // a zero country code is refused.
    for (uid, phone, stored) in [
        ("formatted", "+1 650-555-0104", Some("+16505550104")),
        ("letters", "+1650555ABCD", Some("+16505552223")),
        ("zero", "+0 650 555 0104", None),
    ] {
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": uid, "phoneNumber": phone}),
        );
        if let Some(stored) = stored {
            assert_eq!(status, 200, "{phone}: {body}");
            let (_, found) = admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:lookup"),
                &json!({"localId": [uid]}),
            );
            assert_eq!(found["users"][0]["phoneNumber"], stored, "{found}");
        } else {
            assert_eq!(status, 400, "{phone}: {body}");
            assert_eq!(
                body["error"]["message"],
                "INVALID_PHONE_NUMBER : Invalid format."
            );
        }
    }
    let (status, body) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "space", "email": " space@example.com"}),
    );
    assert_eq!(
        (status, body["error"]["message"].as_str()),
        (400, Some("INVALID_EMAIL")),
        "{body}"
    );

    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "values@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    for (length, refused) in [(256, false), (257, true)] {
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": signed["idToken"], "displayName": "n".repeat(length)}),
        );
        if refused {
            assert_eq!(status, 400, "{body}");
            assert_eq!(
                body["error"]["message"],
                "INVALID_PROFILE_ATTRIBUTE : Display name too long."
            );
        } else {
            assert_eq!(status, 200, "{body}");
        }
    }

    let (status, body) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{"localId": "ts", "createdAt": "yesterday"}]}),
    );
    let description = r#"Invalid value at 'users[0].created_at' (TYPE_INT64), "yesterday""#;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], description);
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        body["error"]["details"][0]["fieldViolations"][0]["field"],
        "users[0].created_at"
    );
    let (status, body) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{"localId": "ts", "createdAt": "1600000000000", "lastLoginAt": 1_600_000_100_000_i64}]}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "{body}");
}

/// Custom attributes read back as the text they were set with, key order included, an
/// explicit `{}` stays visible, and `user_id` is not a reserved name; the ID token still
/// carries the account's own `user_id` (sandbox recording 2026-09-23,
/// `auth-account/admin/custom-attributes`).
#[test]
fn custom_attributes_read_back_as_set() {
    let s = state();
    let (status, created) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "ca", "email": "ca@example.com", "password": "password1"}),
    );
    assert_eq!(status, 200, "{created}");
    let readback = || {
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": ["ca"]}),
        )
        .1["users"][0]
            .get("customAttributes")
            .cloned()
    };
    assert_eq!(readback(), None);
    for text in [r#"{"role":"editor","level":3}"#, "{}", r#"{"user_id":"x"}"#] {
        let (status, updated) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "ca", "customAttributes": text}),
        );
        assert_eq!(status, 200, "{text}: {updated}");
        assert_eq!(readback(), Some(json!(text)));
    }
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "ca@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    let token =
        fireemu_core_auth::jwt::decode_unsigned(signed["idToken"].as_str().unwrap()).unwrap();
    let claims: Value = serde_json::from_str(&token.payload_json).unwrap();
    assert_eq!(claims["user_id"], "ca");
    assert_eq!(claims["sub"], "ca");
}

/// `allowDuplicateEmails` does not let a password sign-up or an Admin create take an address
/// in use; an import may share it, a lookup by the address answers every owner, and a
/// password sign-in reaches the owner holding the password (sandbox recording 2026-09-23,
/// `auth-account/config/duplicate-email`).
#[test]
fn duplicate_email_mode_keeps_password_accounts_unique() {
    let s = state();
    let (status, body) = admin(
        &s,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=signIn.allowDuplicateEmails",
        &json!({"signIn": {"allowDuplicateEmails": true}}),
    );
    assert_eq!(status, 200, "{body}");
    let sign_up = |password: &str| {
        post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "dup@example.com", "password": password, "returnSecureToken": true}),
        )
    };
    let (status, first) = sign_up("password123");
    assert_eq!(status, 200, "{first}");
    let (status, refused) = sign_up("password456");
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (400, Some("EMAIL_EXISTS"))
    );
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "dup-admin", "email": "dup@example.com"}),
    );
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (400, Some("EMAIL_EXISTS"))
    );
    let (status, imported) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{"localId": "dup-import", "email": "dup@example.com"}]}),
    );
    assert_eq!(status, 200, "{imported}");
    assert!(imported.get("error").is_none(), "{imported}");
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "dup@example.com", "password": "password123", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["localId"], first["localId"]);
    let (status, found) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"email": ["dup@example.com"]}),
    );
    assert_eq!(status, 200, "{found}");
    let ids: Vec<&Value> = found["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| &u["localId"])
        .collect();
    assert_eq!(ids, [&first["localId"], &json!("dup-import")]);
}

const PROJECT_CONFIG: &str = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";

fn patch_sign_in(s: &AuthState, mask: &str, body: &Value) -> (u16, Value) {
    admin(
        s,
        "PATCH",
        &format!("{PROJECT_CONFIG}?updateMask={mask}"),
        body,
    )
}

/// Linking a phone number to a signed-in account answers with a session whose provider is the
/// phone sign-in (sandbox recording 2026-09-24,
/// id-token/without-return-secure-token#phone-link-with-legacy-token).
#[test]
fn a_phone_link_answers_with_a_phone_session() {
    let s = state();
    let (status, config) = patch_sign_in(
        &s,
        "signIn.email.enabled,signIn.phoneNumber.enabled,signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {
            "email": {"enabled": true},
            "phoneNumber": {"enabled": true, "testPhoneNumbers": {"+16505550105": "123456"}},
        }}),
    );
    assert_eq!(status, 200, "{config}");
    let (status, account) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "phone-link@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{account}");
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+16505550105", "recaptchaToken": "x"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (status, linked) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"idToken": account["idToken"], "sessionInfo": sent["sessionInfo"], "code": "123456"}),
    );
    assert_eq!(status, 200, "{linked}");
    assert_eq!(
        token_parts(&linked["idToken"]).1["firebase"]["sign_in_provider"],
        "phone"
    );
}

/// The Admin config sets the sign-in providers and test phone numbers the sandbox baseline
/// uses, reads them back in production's shape, and a test number signs in with its fixed
/// code (sandbox recording 2026-09-23, `auth-account/phone`).
#[test]
#[allow(clippy::too_many_lines)]
fn test_phone_numbers_sign_in_with_their_fixed_code() {
    let s = state();
    let (status, config) = patch_sign_in(
        &s,
        "signIn.email.enabled,signIn.email.passwordRequired,signIn.anonymous.enabled,signIn.phoneNumber.enabled,signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {
            "email": {"enabled": true, "passwordRequired": true},
            "anonymous": {"enabled": true},
            "phoneNumber": {"enabled": true, "testPhoneNumbers": {"+16505550101": "123456"}},
        }}),
    );
    assert_eq!(status, 200, "{config}");
    let (status, read) = admin(&s, "GET", PROJECT_CONFIG, &Value::Null);
    assert_eq!(status, 200, "{read}");
    assert_eq!(
        read["signIn"]["email"],
        json!({"enabled": true, "passwordRequired": true})
    );
    assert_eq!(read["signIn"]["anonymous"], json!({"enabled": true}));
    assert_eq!(
        read["signIn"]["phoneNumber"],
        json!({"enabled": true, "testPhoneNumbers": {"+16505550101": "123456"}})
    );
    let send_code = || {
        post(
            &s,
            &format!("{V1}/accounts:sendVerificationCode"),
            &json!({"phoneNumber": "+16505550101", "recaptchaToken": "x"}),
        )
    };
    let (status, sent) = send_code();
    assert_eq!(status, 200, "{sent}");
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"], "code": "000000"}),
    );
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (400, Some("INVALID_CODE"))
    );
    let (status, missing) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"]}),
    );
    assert_eq!(
        (status, missing["error"]["message"].as_str()),
        (400, Some("MISSING_CODE"))
    );
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"], "code": "123456"}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["isNewUser"], true);
    assert_eq!(signed["phoneNumber"], "+16505550101");

    // A taken number linked to another account answers a temporary proof instead of an
    // error; the proof signs in to the number's owner once.
    let (status, other) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "linker@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{other}");
    let (_, sent) = send_code();
    let (status, proof) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"], "code": "123456", "idToken": other["idToken"]}),
    );
    assert_eq!(status, 200, "{proof}");
    assert_eq!(proof["phoneNumber"], "+16505550101");
    assert_eq!(proof["temporaryProofExpiresIn"], "3600");
    assert!(proof.get("idToken").is_none(), "{proof}");
    let proof_body =
        json!({"temporaryProof": proof["temporaryProof"], "phoneNumber": "+16505550101"});
    // The proof is reusable within its lifetime (corpus v2 recording 2026-09-24,
    // `phone#sign-in-with-temporary-proof-again`).
    for _ in 0..2 {
        let (status, owner) = post(
            &s,
            &format!("{V1}/accounts:signInWithPhoneNumber"),
            &proof_body,
        );
        assert_eq!(status, 200, "{owner}");
        assert_eq!(owner["localId"], signed["localId"]);
        assert_eq!(owner["isNewUser"], false);
    }
    let wrong_number =
        json!({"temporaryProof": proof["temporaryProof"], "phoneNumber": "+16505550102"});
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &wrong_number,
    );
    assert_eq!(status, 400);

    // Invalid test numbers are refused and change nothing.
    for numbers in [
        json!({"6505550101": "123456"}),
        json!({"+16505550101": "12345"}),
        json!({"+16505550101": 123_456}),
    ] {
        let (status, refused) = patch_sign_in(
            &s,
            "signIn.phoneNumber.testPhoneNumbers",
            &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": numbers}}}),
        );
        assert_eq!(status, 400, "{refused}");
    }
    let (_, read) = admin(&s, "GET", PROJECT_CONFIG, &Value::Null);
    assert_eq!(
        read["signIn"]["phoneNumber"]["testPhoneNumbers"],
        json!({"+16505550101": "123456"})
    );
}

/// Linking a free number answers the session's tokens and the number, without the account's
/// email (sandbox recording 2026-09-23, `auth-account/phone#link-phone`).
#[test]
fn phone_link_answers_without_the_email() {
    let s = state();
    let (status, account) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "linkme@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{account}");
    let (status, sent) = post(
        &s,
        &format!("{V1}/accounts:sendVerificationCode"),
        &json!({"phoneNumber": "+16505550104", "recaptchaToken": "x"}),
    );
    assert_eq!(status, 200, "{sent}");
    let code = s.store.lock().unwrap().verification_codes()[0].code.clone();
    let (status, linked) = post(
        &s,
        &format!("{V1}/accounts:signInWithPhoneNumber"),
        &json!({"sessionInfo": sent["sessionInfo"], "code": code, "idToken": account["idToken"]}),
    );
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["phoneNumber"], "+16505550104");
    assert_eq!(linked["isNewUser"], false);
    assert!(linked.get("email").is_none(), "{linked}");
}

/// An imported raw password is stamped with the import time like an imported hash (sandbox
/// recording 2026-09-23, `import-hash/errors#lookup-all`).
#[test]
fn imported_raw_passwords_report_their_update_time() {
    let s = state();
    let (status, imported) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [{"localId": "raw", "email": "raw@example.com", "rawPassword": "password123"}]}),
    );
    assert_eq!(status, 200, "{imported}");
    let (_, found) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["raw"]}),
    );
    assert_eq!(
        found["users"][0]["passwordUpdatedAt"], 1_788_004_860_000_i64,
        "{found}"
    );
}

/// An Admin create takes a `localId` of 0 to 256 characters, the empty one included, and
/// answers a longer one with production's internal error without creating anything
/// (sandbox exploration 2026-09-24, `docs.local/runs/auth-localid-explore-20260924`;
/// recording 2026-09-23, `values#local-id-empty`, `admin/create#local-id-129`).
#[test]
fn admin_create_local_id_lengths_follow_production() {
    let s = state();
    for uid in [String::new(), "b".repeat(129), "c".repeat(256)] {
        let (status, created) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": uid}),
        );
        assert_eq!(status, 200, "{}: {created}", uid.len());
        assert_eq!(created["localId"], uid);
    }
    let (_, found) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [""]}),
    );
    assert_eq!(found["users"][0]["localId"], "", "{found}");
    let (status, deleted) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:delete"),
        &json!({"localId": ""}),
    );
    assert_eq!(status, 200, "{deleted}");
    let long = "d".repeat(257);
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": long}),
    );
    assert_eq!(status, 500, "{refused}");
    assert_eq!(
        refused,
        json!({"error": {"code": 500, "message": "Internal error encountered.", "errors": [
            {"message": "Internal error encountered.", "domain": "global", "reason": "backendError"}
        ], "status": "INTERNAL"}})
    );
    assert!(s.store.lock().unwrap().user_by_id(&long).is_none());
}

/// `HMAC_SHA512` imports without a key, and a sign-in against it is production's internal
/// error rather than a credential refusal (sandbox recording 2026-09-23,
/// `import-hash/errors#sign-in-hmac-sha512-without-key`).
#[test]
fn keyless_hmac_sha512_sign_in_is_a_backend_failure() {
    let s = state();
    let (status, imported) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"hashAlgorithm": "HMAC_SHA512", "users": [{
            "localId": "hmac", "email": "hmac@example.com",
            "passwordHash": "AAAAAAAAAAAAAAAAAAAAAA==", "salt": "c2FsdA=="
        }]}),
    );
    assert_eq!(status, 200, "{imported}");
    assert!(imported.get("error").is_none(), "{imported}");
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "hmac@example.com", "password": "password123"}),
    );
    assert_eq!(status, 500, "{refused}");
    assert_eq!(refused["error"]["status"], "INTERNAL");
    assert_eq!(refused["error"]["message"], "Internal error encountered.");
}

/// A negative query offset is production's internal error (corpus v2 recording 2026-09-24,
/// `admin/query#negative-offset`, the same in both recordings).
#[test]
fn strict_admin_query_negative_offset_is_a_backend_failure() {
    let s = strict_state();
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"offset": "-1"}),
    );
    assert_eq!(status, 500, "{refused}");
    assert_eq!(refused["error"]["status"], "INTERNAL");
}

/// Imported hash parameters are held to local work bounds: an oversized standard scrypt is
/// refused at import and a bcrypt cost above the bound fails the sign-in quickly instead of
/// exhausting memory or CPU (closure security review 2026-09-24).
#[test]
fn imported_hash_work_is_bounded() {
    let b64 = fireemu_core_types::hash::base64_standard;
    let s = state();
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"hashAlgorithm": "STANDARD_SCRYPT", "cpuMemCost": 1_u64 << 40, "blockSize": 8,
            "parallelization": 1, "dkLen": 64,
            "users": [{"localId": "huge", "email": "huge@example.com", "passwordHash": b64(&[0; 64]), "salt": b64(b"salt")}]}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "INVALID_HASH_PARAMETER");
    let bcrypt = format!("$2b$31${}", "a".repeat(53));
    let (status, imported) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"hashAlgorithm": "BCRYPT",
            "users": [{"localId": "slow", "email": "slow@example.com", "passwordHash": b64(bcrypt.as_bytes())}]}),
    );
    assert_eq!(status, 200, "{imported}");
    let started = std::time::Instant::now();
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "slow@example.com", "password": "password123"}),
    );
    assert_eq!(status, 500, "{refused}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// The custom-attribute size limit applies to the stored text, so whitespace cannot carry an
/// oversized value (closure security review 2026-09-24).
#[test]
fn custom_attribute_padding_counts_toward_the_size_limit() {
    let s = state();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "pad"}),
    );
    assert_eq!(status, 200);
    let padded = format!("{{\"a\":1{}}}", " ".repeat(2_000));
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "pad", "customAttributes": padded}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "CLAIMS_TOO_LARGE");
}

/// In duplicate-email mode a password account cannot move onto an address another password
/// account holds, so the holder cannot be locked out of password sign-in (closure security
/// review 2026-09-24; production refuses a second password account for an address).
#[test]
fn duplicate_email_mode_keeps_one_password_account_per_address_on_change() {
    let s = state();
    let (status, body) = admin(
        &s,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=signIn.allowDuplicateEmails,emailPrivacyConfig.enableImprovedEmailPrivacy",
        &json!({"signIn": {"allowDuplicateEmails": true}, "emailPrivacyConfig": {"enableImprovedEmailPrivacy": false}}),
    );
    assert_eq!(status, 200, "{body}");
    let sign_up = |email: &str| {
        post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": email, "password": "password123", "returnSecureToken": true}),
        )
    };
    let (_, owner) = sign_up("owner@example.com");
    let (_, mover) = sign_up("mover@example.com");
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": mover["idToken"], "email": "owner@example.com"}),
    );
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (400, Some("EMAIL_EXISTS")),
        "{refused}"
    );
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": mover["localId"], "email": "owner@example.com"}),
    );
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (400, Some("EMAIL_EXISTS")),
        "{refused}"
    );
    // An account without a password cannot reach the same state by taking the address and a
    // password in one update or in two (closure re-review 2026-09-24).
    for two_steps in [false, true] {
        let (_, anonymous) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"returnSecureToken": true}),
        );
        let update = |body: Value| post(&s, &format!("{V1}/accounts:update"), &body);
        let refused = if two_steps {
            let (status, relocated) = update(
                json!({"idToken": anonymous["idToken"], "email": "owner@example.com", "returnSecureToken": true}),
            );
            assert_eq!(status, 200, "{relocated}");
            update(json!({"idToken": relocated["idToken"], "password": "password456"}))
        } else {
            update(
                json!({"idToken": anonymous["idToken"], "email": "owner@example.com", "password": "password456"}),
            )
        };
        assert_eq!(
            (refused.0, refused.1["error"]["message"].as_str()),
            (400, Some("EMAIL_EXISTS")),
            "two_steps={two_steps}: {}",
            refused.1
        );
    }
    let (_, anonymous) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"returnSecureToken": true}),
    );
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"idToken": anonymous["idToken"], "email": "owner@example.com", "password": "password456"}),
    );
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (400, Some("EMAIL_EXISTS")),
        "upgrade: {refused}"
    );
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "owner@example.com", "password": "password123"}),
    );
    assert_eq!(status, 200, "{signed}");
    assert_eq!(signed["localId"], owner["localId"]);
}

/// An empty imported hash is no credential: no password signs in with it, whatever the
/// algorithm derives (external review 2026-09-24; proto3 reads empty bytes as unset).
#[test]
fn an_empty_imported_hash_never_matches() {
    for options in [
        json!({"hashAlgorithm": "PBKDF_SHA1", "rounds": 1000}),
        json!({"hashAlgorithm": "PBKDF2_SHA256", "rounds": 1000}),
        json!({"hashAlgorithm": "SHA256", "rounds": 1}),
        json!({"hashAlgorithm": "MD5", "rounds": 0}),
    ] {
        let s = state();
        let mut body = options.clone();
        body["users"] =
            json!([{"localId": "empty", "email": "empty@example.com", "passwordHash": ""}]);
        let (status, imported) = admin(&s, "POST", &format!("{ADMIN}/accounts:batchCreate"), &body);
        assert_eq!(status, 200, "{options}: {imported}");
        for password in ["anything1", "password123"] {
            let (status, refused) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": "empty@example.com", "password": password}),
            );
            assert_eq!(status, 400, "{options}: {refused}");
        }
        let store = s.store.lock().unwrap();
        let uid = store.user_by_id("empty").map(|user| user.local_id.clone());
        assert!(uid.is_some_and(|uid| store.password_digest(&uid).is_none()));
    }
}

/// Disabled project providers refuse their client flows with `OPERATION_NOT_ALLOWED`, and
/// `passwordRequired` turns email-link sign-in off.
#[test]
fn project_sign_in_providers_gate_client_flows() {
    let s = state();
    let (status, body) = patch_sign_in(
        &s,
        "signIn.email.enabled,signIn.anonymous.enabled,signIn.phoneNumber.enabled",
        &json!({"signIn": {"email": {"enabled": false}, "anonymous": {"enabled": false}, "phoneNumber": {"enabled": false}}}),
    );
    assert_eq!(status, 200, "{body}");
    for (route, body) in [
        (
            "signUp",
            json!({"email": "off@example.com", "password": "password1"}),
        ),
        ("signUp", json!({"returnSecureToken": true})),
        (
            "signInWithPassword",
            json!({"email": "off@example.com", "password": "password1"}),
        ),
        (
            "sendVerificationCode",
            json!({"phoneNumber": "+16505550101", "recaptchaToken": "x"}),
        ),
    ] {
        let (status, refused) = post(&s, &format!("{V1}/accounts:{route}"), &body);
        assert_eq!(
            (status, refused["error"]["message"].as_str()),
            (400, Some("OPERATION_NOT_ALLOWED")),
            "{route}"
        );
    }
    let (_, read) = admin(&s, "GET", PROJECT_CONFIG, &Value::Null);
    assert!(read["signIn"].get("email").is_none(), "{read}");
    assert!(read["signIn"].get("anonymous").is_none(), "{read}");
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"email": "admin@example.com", "password": "password1"}),
    );
    assert_eq!(status, 200);

    let s = state();
    let (status, body) = patch_sign_in(
        &s,
        "signIn.email.passwordRequired",
        &json!({"signIn": {"email": {"passwordRequired": true}}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "link@example.com", "continueUrl": "http://localhost/"}),
    );
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (400, Some("OPERATION_NOT_ALLOWED"))
    );
}

#[test]
fn client_permissions_refuse_end_users_as_admin_only_operations() {
    let s = state();
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "perm@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{created}");
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let updated = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=client.permissions.disabledUserSignup,client.permissions.disabledUserDeletion"),
        &json!({"client": {"permissions": {
            "disabledUserSignup": true,
            "disabledUserDeletion": true
        }}}),
    );
    assert_eq!(updated.0, 200, "{}", updated.1);
    for body in [
        json!({"email": "perm2@example.com", "password": "password1"}),
        json!({"returnSecureToken": true}),
    ] {
        let (status, refused) = post(&s, &format!("{V1}/accounts:signUp"), &body);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"]["message"], "ADMIN_ONLY_OPERATION");
    }
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:delete"),
        &json!({"idToken": created["idToken"]}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "ADMIN_ONLY_OPERATION");
}

#[test]
fn project_client_permissions_are_exposed_and_applied_atomically() {
    let s = state();
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let before = admin(&s, "GET", path, &Value::Null);
    assert_eq!(before.0, 200, "{}", before.1);
    assert_eq!(
        before.1["client"]["permissions"]["disabledUserSignup"],
        false
    );
    assert_eq!(
        before.1["client"]["permissions"]["disabledUserDeletion"],
        false
    );

    let updated = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=client.permissions.disabledUserSignup,client.permissions.disabledUserDeletion"),
        &json!({"client": {"permissions": {
            "disabledUserSignup": true,
            "disabledUserDeletion": true
        }}}),
    );
    assert_eq!(updated.0, 200, "{}", updated.1);
    assert_eq!(
        updated.1["client"]["permissions"]["disabledUserSignup"],
        true
    );
    assert_eq!(
        updated.1["client"]["permissions"]["disabledUserDeletion"],
        true
    );

    let refused = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=client.permissions.disabledUserSignup"),
        &json!({"client": {"permissions": {"disabledUserSignup": "true"}}}),
    );
    assert_eq!(refused.0, 400, "{}", refused.1);
    let after = admin(&s, "GET", path, &Value::Null);
    assert_eq!(after.0, 200, "{}", after.1);
    assert_eq!(after.1["client"]["permissions"]["disabledUserSignup"], true);
    assert_eq!(
        after.1["client"]["permissions"]["disabledUserDeletion"],
        true
    );

    let mixed_refused = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=client.permissions.disabledUserSignup,passwordPolicyConfig"),
        &json!({
            "client": {"permissions": {"disabledUserSignup": false}},
            "passwordPolicyConfig": {"passwordPolicyEnforcementState": "NOTIFY"}
        }),
    );
    assert_eq!(mixed_refused.0, 400, "{}", mixed_refused.1);
    let after_mixed = admin(&s, "GET", path, &Value::Null);
    assert_eq!(after_mixed.0, 200, "{}", after_mixed.1);
    assert_eq!(
        after_mixed.1["client"]["permissions"]["disabledUserSignup"],
        true
    );
    assert_eq!(
        after_mixed.1["passwordPolicyConfig"],
        updated.1["passwordPolicyConfig"]
    );

    let denied = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "client-permission@example.com", "password": "password1"}),
    );
    assert_eq!(denied.0, 400, "{}", denied.1);
    let admin_created = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "client-permission-admin", "email": "client-permission@example.com", "password": "password1"}),
    );
    assert_eq!(admin_created.0, 200, "{}", admin_created.1);
}

#[test]
fn project_config_rejects_malformed_unmasked_fields_without_mutation() {
    let s = state();
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let before = admin(&s, "GET", path, &Value::Null);
    assert_eq!(before.0, 200, "{}", before.1);
    let before_bytes = serde_json::to_vec(&before.1).unwrap();

    for (label, body) in [
        (
            "sign-in",
            json!({
                "client": {"permissions": {"disabledUserSignup": true}},
                "signIn": {"allowDuplicateEmails": "true"}
            }),
        ),
        (
            "password-policy",
            json!({
                "client": {"permissions": {"disabledUserSignup": true}},
                "passwordPolicyConfig": {"passwordPolicyEnforcementState": "NOTIFY"}
            }),
        ),
        (
            "quota",
            json!({
                "client": {"permissions": {"disabledUserSignup": true}},
                "quota": {"quotaSimulation": {"mode": "invalid"}}
            }),
        ),
    ] {
        let refused = admin(
            &s,
            "PATCH",
            &format!("{path}?updateMask=client.permissions.disabledUserSignup"),
            &body,
        );
        assert_eq!(refused.0, 400, "{label}: {}", refused.1);

        let after = admin(&s, "GET", path, &Value::Null);
        assert_eq!(after.0, 200, "{label}: {}", after.1);
        assert_eq!(
            serde_json::to_vec(&after.1).unwrap(),
            before_bytes,
            "{label}"
        );
    }
}

#[test]
fn tenant_signup_policy_treats_null_id_token_as_a_new_account() {
    use fireemu_core_auth::signup_quota::{QuotaMode, SignupQuotaConfig};
    use fireemu_core_auth::store::{AuthRegistry, TenantMetadataPatch};

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    s.registry = Some(registry.clone());

    // Create a pre-existing anonymous account while the tenant still permits anonymous signup.
    // A later non-null session token must continue to support credential linking after policy
    // changes disable new account creation.
    let (status, anonymous) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "tenant-a"}),
    );
    assert_eq!(status, 200, "{anonymous}");
    let link_token = anonymous["idToken"].clone();

    registry
        .patch_tenant(
            "demo-app",
            "tenant-a",
            TenantMetadataPatch {
                allow_password_signup: Some(false),
                enable_anonymous_user: Some(false),
                ..TenantMetadataPatch::default()
            },
        )
        .unwrap();
    let tenant = registry.tenant_store("demo-app", "tenant-a").unwrap();
    tenant
        .lock()
        .unwrap()
        .set_signup_quota_config(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 10,
            ..SignupQuotaConfig::default()
        })
        .unwrap();

    let before_count = tenant.lock().unwrap().user_count();
    let before_usage = tenant.lock().unwrap().signup_quota().usage(
        "demo-app",
        "127.0.0.1",
        LogicalInstant::from_unix_seconds(1_788_004_860),
    );
    for (label, body) in [
        (
            "omitted password session",
            json!({
                "tenantId": "tenant-a",
                "email": "blocked-omitted@example.com",
                "password": "password1",
            }),
        ),
        (
            "null password session",
            json!({
                "tenantId": "tenant-a",
                "idToken": null,
                "email": "blocked-null@example.com",
                "password": "password1",
            }),
        ),
        (
            "null anonymous session",
            json!({"tenantId": "tenant-a", "idToken": null}),
        ),
    ] {
        let (status, refused) = post(&s, &format!("{V1}/accounts:signUp"), &body);
        assert_eq!(status, 400, "{label}: {refused}");
        assert_eq!(refused["error"]["message"], "OPERATION_NOT_ALLOWED");
        assert!(refused.get("idToken").is_none(), "{label}: {refused}");
        assert!(refused.get("refreshToken").is_none(), "{label}: {refused}");
        let store = tenant.lock().unwrap();
        assert_eq!(store.user_count(), before_count, "{label}");
        assert!(store
            .user_by_email(body["email"].as_str().unwrap_or_default())
            .is_none());
        assert_eq!(
            store.signup_quota().usage(
                "demo-app",
                "127.0.0.1",
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ),
            before_usage,
            "{label}"
        );
    }

    let (status, linked) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "tenantId": "tenant-a",
            "idToken": link_token,
            "email": "linked-after-policy@example.com",
            "password": "password1",
        }),
    );
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["localId"], anonymous["localId"]);
}

#[test]
fn tenant_client_permissions_and_privacy_are_namespaced_and_atomic_with_password_policy() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    s.registry = Some(registry);
    let path = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/tenant-a";
    let updated = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=client.permissions.disabledUserSignup,client.permissions.disabledUserDeletion,emailPrivacyConfig.enableImprovedEmailPrivacy,passwordPolicyConfig"),
        &json!({
            "client": {"permissions": {
                "disabledUserSignup": true,
                "disabledUserDeletion": true
            }},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true},
            "passwordPolicyConfig": {
                "passwordPolicyEnforcementState": "ENFORCE",
                "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 12}}]
            }
        }),
    );
    assert_eq!(updated.0, 200, "{}", updated.1);
    assert_eq!(
        updated.1["client"]["permissions"]["disabledUserSignup"],
        true
    );
    assert_eq!(
        updated.1["client"]["permissions"]["disabledUserDeletion"],
        true
    );
    assert_eq!(
        updated.1["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );
    assert_eq!(
        updated.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );

    let refused = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=client.permissions.disabledUserSignup,passwordPolicyConfig"),
        &json!({
            "client": {"permissions": {"disabledUserSignup": false}},
            "passwordPolicyConfig": {"passwordPolicyEnforcementState": "NOTIFY"}
        }),
    );
    assert_eq!(refused.0, 400, "{}", refused.1);
    let after = admin(&s, "GET", path, &Value::Null);
    assert_eq!(after.0, 200, "{}", after.1);
    assert_eq!(after.1["client"]["permissions"]["disabledUserSignup"], true);
    assert_eq!(
        after.1["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );
    assert_eq!(
        after.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );

    let denied = handle_with(
        &s,
        "POST",
        &format!("{V1}/accounts:signUp"),
        &RequestHeaders::default(),
        &json!({"tenantId": "tenant-a", "email": "tenant-a@example.com", "password": "password1"}),
    );
    assert_eq!(denied.status, 400, "{}", denied.body);
}

#[test]
fn tenant_config_rejects_malformed_unmasked_fields_without_mutation() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    s.registry = Some(registry);
    let path = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/tenant-a";
    let before = admin(&s, "GET", path, &Value::Null);
    assert_eq!(before.0, 200, "{}", before.1);
    let before_bytes = serde_json::to_vec(&before.1).unwrap();

    for (label, body) in [
        (
            "client-permissions",
            json!({
                "displayName": "must-not-apply",
                "client": {"permissions": {"disabledUserSignup": "true"}}
            }),
        ),
        (
            "password-policy",
            json!({
                "displayName": "must-not-apply",
                "passwordPolicyConfig": {"passwordPolicyEnforcementState": "NOTIFY"}
            }),
        ),
    ] {
        let refused = admin(
            &s,
            "PATCH",
            &format!("{path}?updateMask=displayName"),
            &body,
        );
        assert_eq!(refused.0, 400, "{label}: {}", refused.1);

        let after = admin(&s, "GET", path, &Value::Null);
        assert_eq!(after.0, 200, "{label}: {}", after.1);
        assert_eq!(
            serde_json::to_vec(&after.1).unwrap(),
            before_bytes,
            "{label}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn project_config_patch_treats_protojson_null_messages_as_absent_or_clear() {
    let s = state();
    let path = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
    let initial = admin(
        &s,
        "PATCH",
        &format!(
            "{path}?updateMask=signIn,emailPrivacyConfig,client.permissions,passwordPolicyConfig,quota"
        ),
        &json!({
            "signIn": {"allowDuplicateEmails": true},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true},
            "client": {"permissions": {
                "disabledUserSignup": true,
                "disabledUserDeletion": true
            }},
            "passwordPolicyConfig": {
                "passwordPolicyEnforcementState": "ENFORCE",
                "passwordPolicyVersions": [{"customStrengthOptions": {
                    "minPasswordLength": 12
                }}]
            },
            "quota": {
                "signUpQuotaConfig": {
                    "quota": "2",
                    "startTime": "2030-01-01T00:00:00Z",
                    "quotaDuration": "3600s"
                },
                "quotaSimulation": {
                    "mode": "enforce",
                    "algorithm": "fixed-window-v1",
                    "defaultQuotaPerHour": 17,
                    "maxTrackedBuckets": 8
                }
            }
        }),
    );
    assert_eq!(initial.0, 200, "{}", initial.1);
    let before = admin(&s, "GET", path, &Value::Null);
    assert_eq!(before.0, 200, "{}", before.1);

    // ProtoJSON null message values are absent when no update mask selects them. They must not
    // be rejected or reset unrelated settings.
    let omitted = admin(
        &s,
        "PATCH",
        path,
        &json!({
            "signIn": null,
            "emailPrivacyConfig": null,
            "client": null,
            "quota": null,
            "passwordPolicyConfig": null,
            "blockingFunctions": null
        }),
    );
    assert_eq!(omitted.0, 200, "{}", omitted.1);
    assert_eq!(omitted.1, before.1);

    let nested_nulls = admin(
        &s,
        "PATCH",
        path,
        &json!({
            "signIn": {"allowDuplicateEmails": null},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": null},
            "client": {"permissions": {
                "disabledUserSignup": null,
                "disabledUserDeletion": null
            }},
            "passwordPolicyConfig": {"forceUpgradeOnSignin": null},
            "quota": {"quotaSimulation": {
                "mode": null,
                "algorithm": null
            }},
            "blockingFunctions": {
                "triggers": {"beforeCreate": null},
                "forwardInboundCredentials": {"idToken": null}
            }
        }),
    );
    assert_eq!(nested_nulls.0, 200, "{}", nested_nulls.1);
    assert_eq!(nested_nulls.1, before.1);

    // A selected null clears the corresponding message to its default value.
    let cleared = admin(
        &s,
        "PATCH",
        &format!(
            "{path}?updateMask=signIn,emailPrivacyConfig,client.permissions,passwordPolicyConfig,quota"
        ),
        &json!({
            "signIn": null,
            "emailPrivacyConfig": null,
            "client": null,
            "passwordPolicyConfig": null,
            "quota": null
        }),
    );
    assert_eq!(cleared.0, 200, "{}", cleared.1);
    assert_eq!(cleared.1["signIn"]["allowDuplicateEmails"], false);
    assert_eq!(
        cleared.1["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        false
    );
    assert_eq!(
        cleared.1["client"]["permissions"]["disabledUserSignup"],
        false
    );
    assert_eq!(
        cleared.1["client"]["permissions"]["disabledUserDeletion"],
        false
    );
    assert_eq!(
        cleared.1["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
        "OFF"
    );
    assert!(cleared.1["quota"].get("signUpQuotaConfig").is_none());
    assert_eq!(cleared.1["quota"]["quotaSimulation"]["mode"], "off");
}

#[test]
fn tenant_config_patch_treats_protojson_null_messages_as_absent_or_clear() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    s.registry = Some(registry);
    let path = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/tenant-a";
    let initial = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=client.permissions,emailPrivacyConfig,displayName"),
        &json!({
            "displayName": "Configured",
            "client": {"permissions": {
                "disabledUserSignup": true,
                "disabledUserDeletion": true
            }},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}
        }),
    );
    assert_eq!(initial.0, 200, "{}", initial.1);
    let before = admin(&s, "GET", path, &Value::Null);
    assert_eq!(before.0, 200, "{}", before.1);

    let omitted = admin(
        &s,
        "PATCH",
        path,
        &json!({
            "displayName": null,
            "client": null,
            "emailPrivacyConfig": null,
            "passwordPolicyConfig": null
        }),
    );
    assert_eq!(omitted.0, 200, "{}", omitted.1);
    assert_eq!(omitted.1, before.1);

    let nested_nulls = admin(
        &s,
        "PATCH",
        path,
        &json!({
            "displayName": null,
            "client": {"permissions": {
                "disabledUserSignup": null,
                "disabledUserDeletion": null
            }},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": null}
        }),
    );
    assert_eq!(nested_nulls.0, 200, "{}", nested_nulls.1);
    assert_eq!(nested_nulls.1, before.1);

    let cleared = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=client.permissions,emailPrivacyConfig,displayName"),
        &json!({
            "displayName": null,
            "client": null,
            "emailPrivacyConfig": null
        }),
    );
    assert_eq!(cleared.0, 200, "{}", cleared.1);
    assert!(cleared.1["displayName"].is_null());
    assert_eq!(
        cleared.1["client"]["permissions"]["disabledUserSignup"],
        false
    );
    assert_eq!(
        cleared.1["client"]["permissions"]["disabledUserDeletion"],
        false
    );
    assert_eq!(
        cleared.1["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        false
    );
}

#[test]
fn tenant_create_rejects_malformed_settings_before_publishing_and_reads_back_supported_values() {
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    s.registry = Some(registry.clone());
    let collection = format!("{V2}/projects/demo-app/tenants");
    let malformed = [
        json!({"client": true}),
        json!({"client": null}),
        json!({"client": {"permissions": "invalid"}}),
        json!({"client": {"permissions": null}}),
        json!({"client": {"permissions": {"disabledUserSignup": null}}}),
        json!({"client": {"permissions": {"unknown": true}}}),
        json!({"emailPrivacyConfig": []}),
        json!({"emailPrivacyConfig": null}),
        json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": null}}),
        json!({"emailPrivacyConfig": {"unknown": true}}),
        json!({"allowPasswordSignup": "true"}),
        json!({"unknownField": true}),
        json!({"passwordPolicyConfig": null}),
    ];
    for body in malformed {
        let refused = handle_with(&s, "POST", &collection, &owner(), &body);
        assert_eq!(refused.status, 400, "{}", refused.body);
        assert!(registry.tenants("demo-app").is_empty(), "{body}");
    }

    let created = handle_with(
        &s,
        "POST",
        &collection,
        &owner(),
        &json!({
            "displayName": "Configured tenant",
            "allowPasswordSignup": true,
            "client": {"permissions": {
                "disabledUserSignup": true,
                "disabledUserDeletion": true
            }},
            "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true},
            "passwordPolicyConfig": {
                "passwordPolicyEnforcementState": "ENFORCE",
                "passwordPolicyVersions": [{
                    "customStrengthOptions": {"minPasswordLength": 12}
                }]
            }
        }),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let tenant = created.body["name"].as_str().unwrap().to_owned();
    assert_eq!(
        created.body["client"]["permissions"]["disabledUserSignup"],
        true
    );
    assert_eq!(
        created.body["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
        true
    );
    assert_eq!(
        created.body["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );
    let read_path = format!("{V2}/{tenant}");
    let read = handle_with(&s, "GET", &read_path, &owner(), &json!({}));
    assert_eq!(read.status, 200, "{}", read.body);
    assert_eq!(
        read.body["client"]["permissions"]["disabledUserDeletion"],
        true
    );
    assert_eq!(
        read.body["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );
}

#[test]
fn signup_quota_is_enforced_for_end_user_creation_without_trusting_forwarded_headers() {
    use fireemu_core_auth::signup_quota::{QuotaMode, SignupQuotaConfig};

    let s = state();
    s.store
        .lock()
        .unwrap()
        .set_signup_quota_config(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 1,
            ..SignupQuotaConfig::default()
        })
        .unwrap();
    let headers = RequestHeaders {
        peer_ip: Some("192.0.2.20".to_owned()),
        ..RequestHeaders::default()
    };
    let first = handle_with(
        &s,
        "POST",
        &format!("{V1}/accounts:signUp?X-Forwarded-For=198.51.100.99"),
        &headers,
        &json!({"email": "quota-one@example.com", "password": "password1"}),
    );
    assert_eq!(first.status, 200, "{}", first.body);
    let second = handle_with(
        &s,
        "POST",
        &format!("{V1}/accounts:signUp?X-Forwarded-For=198.51.100.99"),
        &headers,
        &json!({"email": "quota-two@example.com", "password": "password1"}),
    );
    assert_eq!(second.status, 400, "{}", second.body);
    assert_eq!(second.body["error"]["message"], "SIGNUP_QUOTA_EXCEEDED");
    let store = s.store.lock().unwrap();
    assert!(store.user_by_email("quota-one@example.com").is_some());
    assert!(store.user_by_email("quota-two@example.com").is_none());
    assert_eq!(
        store.signup_quota().usage(
            "demo-app",
            "192.0.2.20",
            LogicalInstant::from_unix_seconds(1_788_004_860)
        ),
        (1, 0)
    );
}

#[test]
fn stale_signup_quota_commit_does_not_publish_the_account_or_tokens() {
    use fireemu_core_auth::signup_quota::{QuotaMode, SignupQuotaConfig};

    let mut s = state();
    s.store
        .lock()
        .unwrap()
        .set_signup_quota_config(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 2,
            ..SignupQuotaConfig::default()
        })
        .unwrap();
    s.blocking = Some(Arc::new(AdvancingQuotaHook {
        clock: s.clock.clone(),
        advance: LogicalDuration::from_seconds(3_540),
        advanced: AtomicBool::new(false),
    }));

    let response = handle_with(
        &s,
        "POST",
        &format!("{V1}/accounts:signUp"),
        &RequestHeaders::default(),
        &json!({"email": "stale-quota@example.com", "password": "password1"}),
    );
    assert_eq!(response.status, 500, "{}", response.body);
    assert_eq!(
        response.body["error"]["message"],
        "SIGNUP_QUOTA_UNAVAILABLE"
    );

    let store = s.store.lock().unwrap();
    assert!(store.user_by_email("stale-quota@example.com").is_none());
    assert_eq!(
        store.signup_quota().usage(
            "demo-app",
            "127.0.0.1",
            LogicalInstant::from_unix_seconds(1_788_004_860)
        ),
        (0, 0)
    );
}

#[test]
fn signup_quota_commit_survives_unrelated_deletion_during_blocking_hook() {
    use fireemu_core_auth::signup_quota::{QuotaMode, SignupQuotaConfig};
    use fireemu_core_auth::store::{AuthPrincipal, NewUser};

    let mut s = state();
    let unrelated_uid = s
        .store
        .lock()
        .unwrap()
        .create_user_with_password_as(
            AuthPrincipal::Admin,
            NewUser::email("unrelated-quota-user@example.com"),
            "password1",
            LogicalInstant::from_unix_seconds(1_788_004_860),
        )
        .unwrap()
        .to_string();
    s.store
        .lock()
        .unwrap()
        .set_signup_quota_config(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 1,
            ..SignupQuotaConfig::default()
        })
        .unwrap();
    s.blocking = Some(Arc::new(DeletingUnrelatedUserHook {
        store: s.store.clone(),
        uid: unrelated_uid,
        deleted: AtomicBool::new(false),
    }));

    let first = handle_with(
        &s,
        "POST",
        &format!("{V1}/accounts:signUp"),
        &RequestHeaders::default(),
        &json!({"email": "quota-during-hook-one@example.com", "password": "password1"}),
    );
    assert_eq!(first.status, 200, "{}", first.body);

    let second = handle_with(
        &s,
        "POST",
        &format!("{V1}/accounts:signUp"),
        &RequestHeaders::default(),
        &json!({"email": "quota-during-hook-two@example.com", "password": "password1"}),
    );
    assert_eq!(second.status, 400, "{}", second.body);
    assert_eq!(second.body["error"]["message"], "SIGNUP_QUOTA_EXCEEDED");

    let store = s.store.lock().unwrap();
    assert!(store
        .user_by_email("unrelated-quota-user@example.com")
        .is_none());
    assert!(store
        .user_by_email("quota-during-hook-one@example.com")
        .is_some());
    assert!(store
        .user_by_email("quota-during-hook-two@example.com")
        .is_none());
    assert_eq!(
        store.signup_quota().usage(
            "demo-app",
            "127.0.0.1",
            LogicalInstant::from_unix_seconds(1_788_004_860)
        ),
        (1, 0)
    );
}

#[test]
fn self_deletion_permission_denies_end_user_but_admin_delete_still_succeeds() {
    let s = state();
    s.store
        .lock()
        .unwrap()
        .set_config(fireemu_core_auth::store::ProjectAuthConfig {
            disabled_user_deletion: true,
            ..fireemu_core_auth::store::ProjectAuthConfig::default()
        });
    let (_, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "delete-permission@example.com", "password": "password1"}),
    );
    let denied = post(
        &s,
        &format!("{V1}/accounts:delete"),
        &json!({"idToken": signed["idToken"]}),
    );
    assert_eq!(denied.0, 400, "{}", denied.1);
    assert_eq!(denied.1["error"]["message"], "ADMIN_ONLY_OPERATION");
    let lookup = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [signed["localId"]]}),
    );
    assert_eq!(lookup.0, 200, "{}", lookup.1);
    assert_eq!(lookup.1["users"].as_array().map(Vec::len), Some(1));

    let deleted = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:delete"),
        &json!({"localId": signed["localId"]}),
    );
    assert_eq!(deleted.0, 200, "{}", deleted.1);
    let after = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [signed["localId"]]}),
    );
    assert_eq!(after.0, 200, "{}", after.1);
    assert!(after.1["users"].as_array().is_none_or(Vec::is_empty));
}

#[test]
fn password_sign_in_notify_returns_each_policy_notification() {
    let s = state();
    let email = "password-policy-notify@example.com";
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": email, "password": "password", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{created}");

    let notify_policy = PasswordPolicy::try_new(
        EnforcementState::Enforce,
        false,
        12,
        Some(20),
        true,
        true,
        true,
        true,
        default_allowed_non_alphanumeric(),
    )
    .unwrap();
    s.store.lock().unwrap().set_password_policy(notify_policy);

    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "password", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{response}");
    assert_eq!(response["localId"], created["localId"]);
    assert!(response["idToken"].is_string(), "{response}");
    assert_eq!(
        response["userNotifications"],
        json!([
            {
                "notificationCode": "MINIMUM_PASSWORD_LENGTH",
                "notificationMessage": "Password must be at least 12 characters"
            },
            {
                "notificationCode": "MISSING_UPPERCASE_CHARACTER",
                "notificationMessage": "Password must contain an uppercase character"
            },
            {
                "notificationCode": "MISSING_NUMERIC_CHARACTER",
                "notificationMessage": "Password must contain a numeric character"
            },
            {
                "notificationCode": "MISSING_NON_ALPHANUMERIC_CHARACTER",
                "notificationMessage": "Password must contain a non-alphanumeric character"
            }
        ])
    );

    // The maximum-length notification is independently exercised because a valid policy
    // cannot have a maximum shorter than its minimum.
    let maximum_policy = PasswordPolicy::try_new(
        EnforcementState::Enforce,
        false,
        6,
        Some(7),
        false,
        false,
        false,
        false,
        default_allowed_non_alphanumeric(),
    )
    .unwrap();
    s.store.lock().unwrap().set_password_policy(maximum_policy);
    let (status, response) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "password", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        response["userNotifications"],
        json!([{
            "notificationCode": "MAXIMUM_PASSWORD_LENGTH",
            "notificationMessage": "Password must be at most 7 characters"
        }])
    );
}

#[test]
fn forced_password_policy_rejection_preserves_auth_error_precedence_and_state() {
    let s = state();
    let email = "password-policy-forced@example.com";
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": email, "password": "password", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{created}");
    let uid = created["localId"].as_str().unwrap();
    let before = s
        .store
        .lock()
        .unwrap()
        .user_by_id(uid)
        .map(|user| user.last_sign_in_at);

    let forced_policy = PasswordPolicy::try_new(
        EnforcementState::Enforce,
        true,
        12,
        Some(20),
        true,
        true,
        true,
        true,
        default_allowed_non_alphanumeric(),
    )
    .unwrap();
    s.store.lock().unwrap().set_password_policy(forced_policy);

    let (status, wrong_password) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "wrong-password", "returnSecureToken": true}),
    );
    assert_eq!(status, 400, "{wrong_password}");
    assert_eq!(
        wrong_password["error"]["message"], "INVALID_PASSWORD",
        "policy evaluation must not precede credential verification"
    );
    assert!(wrong_password.get("idToken").is_none());

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "password", "returnSecureToken": true}),
    );
    assert_eq!(status, 400, "{refused}");
    assert!(refused.get("idToken").is_none(), "{refused}");
    assert!(refused.get("refreshToken").is_none(), "{refused}");
    let after = s
        .store
        .lock()
        .unwrap()
        .user_by_id(uid)
        .map(|user| user.last_sign_in_at);
    assert_eq!(
        after, before,
        "forced rejection must not mutate the account"
    );
}

#[test]
fn sign_up_link_authenticates_before_password_policy_and_preserves_state() {
    let policy = || {
        PasswordPolicy::try_new(
            EnforcementState::Enforce,
            false,
            12,
            None,
            false,
            false,
            false,
            false,
            default_allowed_non_alphanumeric(),
        )
        .unwrap()
    };

    for (label, expected_error) in [
        ("invalid", "INVALID_ID_TOKEN"),
        // Past the five-minute allowance an expired token is invalid (2026-09-24).
        ("expired", "INVALID_ID_TOKEN"),
        ("mismatched-audience", "INVALID_ID_TOKEN"),
    ] {
        let s = state();
        let (_, anonymous) = post(&s, &format!("{V1}/accounts:signUp"), &json!({}));
        assert_eq!(anonymous["kind"], "identitytoolkit#SignupNewUserResponse");
        let valid_token = anonymous["idToken"].as_str().unwrap().to_owned();
        let token = match label {
            "invalid" => "not-a-token".to_owned(),
            "expired" => {
                advance(&s, 3_901);
                valid_token
            }
            "mismatched-audience" => {
                let payload = fireemu_core_auth::jwt::decode_unsigned(&valid_token)
                    .unwrap()
                    .payload_json
                    .replace("\"aud\":\"demo-app\"", "\"aud\":\"other-app\"");
                fireemu_core_auth::jwt::encode_payload_with(&payload, None)
            }
            _ => unreachable!(),
        };
        s.store.lock().unwrap().set_password_policy(policy());

        let email = format!("link-{label}@example.com");
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({
                "idToken": token,
                "email": email,
                "password": "weakpass",
                "returnSecureToken": true
            }),
        );
        assert_eq!(status, 400, "{label}: {refused}");
        assert_eq!(refused["error"]["message"], expected_error, "{label}");
        assert!(refused.get("idToken").is_none(), "{label}: {refused}");
        let store = s.store.lock().unwrap();
        assert!(store.user_by_email(&email).is_none(), "{label}");
        assert_eq!(
            store.user_count(),
            1,
            "{label}: invalid link must not create a user"
        );
    }

    let s = state();
    let (_, anonymous) = post(&s, &format!("{V1}/accounts:signUp"), &json!({}));
    s.store.lock().unwrap().set_password_policy(policy());
    let email = "valid-session-weak-link@example.com";
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "idToken": anonymous["idToken"],
            "email": email,
            "password": "weakpass",
            "returnSecureToken": true
        }),
    );
    assert_eq!(status, 400, "{refused}");
    // The detail after " : " is pinned in password_rules_answer_like_production.
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("PASSWORD_DOES_NOT_MEET_REQUIREMENTS")),
        "a valid session reaches policy evaluation after authentication"
    );
    assert!(s.store.lock().unwrap().user_by_email(email).is_none());
}

/// With the project's API keys declared (`auth.apiKeys`), any other key is refused by the API
/// front end before the service reads the request, on Identity Toolkit and Secure Token alike
/// (sandbox recording 2026-09-24, auth-credential/refresh/refusals#invalid-api-key).
#[test]
fn undeclared_api_keys_are_refused_as_the_api_front_end_does() {
    let mut s = strict_state();
    let mut tenancy = Tenancy::new("demo-app");
    tenancy.declare_default_api_keys(&["declared-key".to_owned()]);
    s.tenancy = Some(Arc::new(RwLock::new(tenancy)));
    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=declared-key"),
        &json!({"email": "declared-key@example.com", "password": "password1", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{created}");
    let invalid = |service: &str| {
        let message = "API key not valid. Please pass a valid API key.";
        let mut body = json!({"error": {
            "code": 400,
            "message": message,
            "status": "INVALID_ARGUMENT",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "API_KEY_INVALID",
                    "domain": "googleapis.com",
                    "metadata": {"service": service},
                },
                {
                    "@type": "type.googleapis.com/google.rpc.LocalizedMessage",
                    "locale": "en-US",
                    "message": message,
                },
            ],
        }});
        // Identity Toolkit adds its `errors` list; Secure Token does not (2026-09-24).
        if service == "identitytoolkit.googleapis.com" {
            body["error"]["errors"] =
                json!([{"message": message, "domain": "global", "reason": "badRequest"}]);
        }
        body
    };
    assert_eq!(
        post(
            &s,
            &format!("{V1}/accounts:signUp?key=other-key"),
            &json!({"email": "other-key@example.com", "password": "password1"}),
        ),
        (400, invalid("identitytoolkit.googleapis.com"))
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("other-key@example.com")
        .is_none());
    assert_eq!(
        post(
            &s,
            "/securetoken.googleapis.com/v1/token?key=other-key",
            &json!({"grant_type": "refresh_token", "refresh_token": created["refreshToken"]}),
        ),
        (400, invalid("securetoken.googleapis.com"))
    );
    let (status, refreshed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token?key=declared-key",
        &json!({"grant_type": "refresh_token", "refresh_token": created["refreshToken"]}),
    );
    assert_eq!(status, 200, "{refreshed}");
}

#[test]
fn client_namespace_selectors_fail_closed_without_default_fallback() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    assert!(registry.register(
        "worker-auth",
        AuthStore::new("worker-auth", SplitMix64::new(17), TotpPolicy::default()),
    ));
    registry.ensure_tenant("worker-auth", "tenant-a").unwrap();
    s.registry = Some(registry.clone());
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-auth", &[], &["worker-key".to_owned()])
        .unwrap();
    s.tenancy = Some(Arc::new(RwLock::new(tenancy)));

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=unknown-key"),
        &json!({"email": "unknown-key@example.com", "password": "password1"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "API key not valid. Please pass a valid API key."
    );
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("unknown-key@example.com")
        .is_none());

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=worker-key"),
        &json!({
            "tenantId": "missing-tenant",
            "email": "missing-tenant@example.com",
            "password": "password1"
        }),
    );
    assert_eq!(status, 404, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_NOT_FOUND");
    assert!(registry
        .store_for("worker-auth")
        .unwrap()
        .lock()
        .unwrap()
        .user_by_email("missing-tenant@example.com")
        .is_none());

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp?tenantId=missing-tenant"),
        &json!({"email": "missing-query-tenant@example.com", "password": "password1"}),
    );
    assert_eq!(status, 404, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_NOT_FOUND");
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("missing-query-tenant@example.com")
        .is_none());

    let (status, worker) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=worker-key"),
        &json!({"email": "worker-auth@example.com", "password": "password1"}),
    );
    assert_eq!(status, 200, "{worker}");
    assert_eq!(worker["tenantId"], Value::Null);
    assert!(registry
        .store_for("worker-auth")
        .unwrap()
        .lock()
        .unwrap()
        .user_by_email("worker-auth@example.com")
        .is_some());
}

#[test]
fn explicit_api_key_keeps_default_namespace_compatibility_without_tenancy_registry() {
    let mut s = state();
    s.registry = Some(Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    )));

    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=fake-api-key"),
        &json!({"email": "legacy-api-key@example.com", "password": "password1"}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["email"], "legacy-api-key@example.com");
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("legacy-api-key@example.com")
        .is_some());
}

#[test]
fn explicit_tenant_never_falls_back_when_tenancy_selector_is_unavailable() {
    for (label, tenancy) in [
        ("missing", None),
        (
            "empty",
            Some(Arc::new(RwLock::new(Tenancy::new("demo-app")))),
        ),
    ] {
        let mut s = state();
        let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            s.store.clone(),
        ));
        registry.ensure_tenant("demo-app", "tenant-a").unwrap();
        s.registry = Some(registry.clone());
        s.tenancy = tenancy;

        let (status, created) = post(
            &s,
            &format!("{V1}/accounts:signUp?key=fake-api-key&tenantId=tenant-a"),
            &json!({
                "email": format!("explicit-{label}@example.com"),
                "password": "password1",
            }),
        );
        assert_eq!(status, 200, "{label}: {created}");
        assert!(registry
            .tenant_store("demo-app", "tenant-a")
            .unwrap()
            .lock()
            .unwrap()
            .user_by_email(format!("explicit-{label}@example.com").as_str())
            .is_some());
        assert!(
            s.store
                .lock()
                .unwrap()
                .user_by_email(format!("explicit-{label}@example.com").as_str())
                .is_none(),
            "{label}: explicit tenant must not use default store"
        );

        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:signUp?key=fake-api-key&tenantId=missing-tenant"),
            &json!({
                "email": format!("missing-{label}@example.com"),
                "password": "password1",
            }),
        );
        assert_eq!(status, 404, "{label}: {refused}");
        assert_eq!(refused["error"]["message"], "TENANT_NOT_FOUND");
        assert!(
            s.store
                .lock()
                .unwrap()
                .user_by_email(format!("missing-{label}@example.com").as_str())
                .is_none(),
            "{label}: unknown tenant must not mutate default store"
        );

        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:signUp?key=fake-api-key&tenantId=tenant-a"),
            &json!({
                "tenantId": "tenant-b",
                "email": format!("mismatch-{label}@example.com"),
                "password": "password1",
            }),
        );
        assert_eq!(status, 400, "{label}: {refused}");
        assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
        assert!(registry
            .tenant_store("demo-app", "tenant-a")
            .unwrap()
            .lock()
            .unwrap()
            .user_by_email(format!("mismatch-{label}@example.com").as_str())
            .is_none());
    }
}

#[test]
fn explicit_tenant_policy_query_uses_the_registered_tenant_without_tenancy_selector() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    let tenant = registry.tenant_store("demo-app", "tenant-a").unwrap();
    tenant.lock().unwrap().set_password_policy(
        PasswordPolicy::try_new(
            EnforcementState::Enforce,
            false,
            12,
            None,
            false,
            false,
            false,
            false,
            default_allowed_non_alphanumeric(),
        )
        .unwrap(),
    );
    s.registry = Some(registry);

    let tenant_policy = admin(
        &s,
        "GET",
        &format!("{V2}/passwordPolicy?key=fake-api-key&tenantId=tenant-a"),
        &Value::Null,
    );
    assert_eq!(tenant_policy.0, 200, "{}", tenant_policy.1);
    assert_eq!(
        tenant_policy.1["customStrengthOptions"]["minPasswordLength"], 12,
        "tenant policy must be read from the selected tenant store"
    );

    let unknown = admin(
        &s,
        "GET",
        &format!("{V2}/passwordPolicy?key=fake-api-key&tenantId=missing-tenant"),
        &Value::Null,
    );
    assert_eq!(unknown.0, 404, "{}", unknown.1);
    assert_eq!(unknown.1["error"]["message"], "TENANT_NOT_FOUND");
}

#[test]
#[allow(clippy::too_many_lines)]
fn scoped_tenant_selectors_must_match_body_and_query_before_auth_work() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    for tenant in ["tenant-a", "tenant-b"] {
        registry.ensure_tenant("demo-app", tenant).unwrap();
    }
    let tenant_a = registry.tenant_store("demo-app", "tenant-a").unwrap();
    tenant_a.lock().unwrap().set_password_policy(
        PasswordPolicy::try_new(
            EnforcementState::Enforce,
            false,
            12,
            None,
            false,
            false,
            false,
            false,
            default_allowed_non_alphanumeric(),
        )
        .unwrap(),
    );
    s.registry = Some(registry.clone());
    let path = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/tenant-a";

    let before = admin(&s, "GET", path, &Value::Null);
    assert_eq!(before.0, 200, "{}", before.1);
    assert_eq!(
        before.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );

    let query_mismatch = admin(
        &s,
        "GET",
        &format!("{path}?tenantId=tenant-b"),
        &Value::Null,
    );
    assert_eq!(query_mismatch.0, 400, "{}", query_mismatch.1);
    assert_eq!(query_mismatch.1["error"]["message"], "TENANT_ID_MISMATCH");

    let patch_query_mismatch = admin(
        &s,
        "PATCH",
        &format!("{path}?tenantId=tenant-b&updateMask=displayName"),
        &json!({"displayName": "must-not-commit"}),
    );
    assert_eq!(patch_query_mismatch.0, 400, "{}", patch_query_mismatch.1);
    assert_eq!(
        patch_query_mismatch.1["error"]["message"],
        "TENANT_ID_MISMATCH"
    );

    let patch_body_mismatch = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=displayName"),
        &json!({"tenantId": "tenant-b", "displayName": "must-not-commit"}),
    );
    assert_eq!(patch_body_mismatch.0, 400, "{}", patch_body_mismatch.1);
    assert_eq!(
        patch_body_mismatch.1["error"]["message"],
        "TENANT_ID_MISMATCH"
    );

    let account_query_mismatch = admin(
        &s,
        "POST",
        "/identitytoolkit.googleapis.com/v1/projects/demo-app/tenants/tenant-a/accounts?tenantId=tenant-b",
        &json!({"email": "must-not-create@example.com", "password": "password1"}),
    );
    assert_eq!(
        account_query_mismatch.0, 400,
        "{}",
        account_query_mismatch.1
    );
    assert_eq!(
        account_query_mismatch.1["error"]["message"],
        "TENANT_ID_MISMATCH"
    );
    assert!(tenant_a
        .lock()
        .unwrap()
        .user_by_email("must-not-create@example.com")
        .is_none());
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_email("must-not-create@example.com")
        .is_none());

    let same_query = admin(
        &s,
        "GET",
        &format!("{path}?tenantId=tenant-a"),
        &Value::Null,
    );
    assert_eq!(same_query.0, 200, "{}", same_query.1);
    assert_eq!(
        same_query.1["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
            ["minPasswordLength"],
        12
    );

    let same_body = admin(
        &s,
        "PATCH",
        &format!("{path}?updateMask=displayName"),
        &json!({"tenantId": "tenant-a", "displayName": "accepted"}),
    );
    assert_eq!(same_body.0, 200, "{}", same_body.1);
    assert_eq!(same_body.1["displayName"], "accepted");
}

#[test]
fn body_tenant_mismatch_preserves_invalid_id_token_precedence() {
    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    for tenant in ["tenant-a", "tenant-b"] {
        registry.ensure_tenant("demo-app", tenant).unwrap();
    }
    let tenant_a = registry.tenant_store("demo-app", "tenant-a").unwrap();
    let tenant_b = registry.tenant_store("demo-app", "tenant-b").unwrap();
    s.registry = Some(registry);

    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "tenantId": "tenant-a",
            "email": "body-tenant-precedence@example.com",
            "password": "password1"
        }),
    );
    assert_eq!(status, 200, "{created}");

    // A body tenant is validated as part of the authenticated operation. Preserve the
    // existing INVALID_ID_TOKEN precedence instead of treating it like an explicit query
    // namespace assertion.
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:lookup?key=fake-api-key"),
        &json!({
            "tenantId": "tenant-b",
            "idToken": created["idToken"]
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "INVALID_ID_TOKEN");
    assert_eq!(tenant_a.lock().unwrap().user_count(), 1);
    assert_eq!(tenant_b.lock().unwrap().user_count(), 0);
}

#[test]
#[allow(clippy::too_many_lines)]
fn query_tenant_binds_custom_token_namespace_before_auth_work() {
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
    s.registry = Some(registry.clone());
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-alpha", &[], &["worker-key".to_owned()])
        .unwrap();
    s.tenancy = Some(Arc::new(RwLock::new(tenancy)));

    let token = custom_token_from_payload(&json!({
        "aud": fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE,
        "uid": "query-custom-user",
        "tenant_id": "customer-a",
    }));
    let before_a = registry
        .tenant_store("worker-alpha", "customer-a")
        .unwrap()
        .lock()
        .unwrap()
        .user_count();
    let before_b = registry
        .tenant_store("worker-alpha", "customer-b")
        .unwrap()
        .lock()
        .unwrap()
        .user_count();

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken?key=worker-key&tenantId=customer-b"),
        &json!({"token": token}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-a")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_a
    );
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-b")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_b
    );

    // A project-scoped custom token has no tenant claim and cannot be rebound to a tenant by
    // an explicit query selector.
    let project_token = custom_token_from_payload(&json!({
        "aud": fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE,
        "uid": "project-scoped-custom-user",
    }));
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken?key=worker-key&tenantId=customer-b"),
        &json!({"token": project_token}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-a")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_a
    );
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-b")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_b
    );

    let (status, accepted) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken?key=worker-key&tenantId=customer-a"),
        &json!({
            "token": custom_token_from_payload(&json!({
                "aud": fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE,
                "uid": "query-custom-user",
                "tenant_id": "customer-a",
            })),
        }),
    );
    assert_eq!(status, 200, "{accepted}");
    assert_eq!(
        token_parts(&accepted["idToken"]).1["sub"],
        "query-custom-user"
    );
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-b")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_b
    );
}

#[test]
fn body_tenant_rejects_project_custom_token_before_routing_or_mutation() {
    use fireemu_core_auth::signup_quota::{QuotaMode, SignupQuotaConfig};
    use fireemu_core_auth::store::AuthRegistry;

    let mut s = state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    assert!(registry.register(
        "worker-alpha",
        AuthStore::new("worker-alpha", SplitMix64::new(8), TotpPolicy::default()),
    ));
    for tenant in ["customer-a", "customer-b"] {
        registry.ensure_tenant("worker-alpha", tenant).unwrap();
    }
    s.registry = Some(registry.clone());
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-alpha", &[], &["worker-key".to_owned()])
        .unwrap();
    s.tenancy = Some(Arc::new(RwLock::new(tenancy)));

    let customer_b = registry.tenant_store("worker-alpha", "customer-b").unwrap();
    customer_b
        .lock()
        .unwrap()
        .set_signup_quota_config(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 1,
            ..Default::default()
        })
        .unwrap();
    let before_count = customer_b.lock().unwrap().user_count();
    let before_usage = customer_b.lock().unwrap().signup_quota().usage(
        "worker-alpha",
        "127.0.0.1",
        LogicalInstant::from_unix_seconds(1_788_004_860),
    );

    let project_token = custom_token_from_payload(&json!({
        "aud": fireemu_adapter_http::identity_toolkit::CUSTOM_TOKEN_AUDIENCE,
        "uid": "body-project-scoped-custom-user",
    }));
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithCustomToken?key=worker-key"),
        &json!({
            "tenantId": "customer-b",
            "token": project_token,
            "returnSecureToken": true,
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    assert!(refused.get("idToken").is_none());
    assert!(refused.get("refreshToken").is_none());

    let store = customer_b.lock().unwrap();
    assert_eq!(store.user_count(), before_count);
    assert!(store
        .user_by_id("body-project-scoped-custom-user")
        .is_none());
    assert_eq!(
        store.signup_quota().usage(
            "worker-alpha",
            "127.0.0.1",
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ),
        before_usage
    );
}

#[test]
fn query_tenant_binds_refresh_token_namespace_before_auth_work() {
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
    s.registry = Some(registry.clone());
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-alpha", &[], &["worker-key".to_owned()])
        .unwrap();
    s.tenancy = Some(Arc::new(RwLock::new(tenancy)));

    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=worker-key"),
        &json!({
            "tenantId": "customer-a",
            "email": "query-refresh-user@example.com",
            "password": "password1",
        }),
    );
    assert_eq!(status, 200, "{created}");
    let refresh = created["refreshToken"].clone();
    let before_a = registry
        .tenant_store("worker-alpha", "customer-a")
        .unwrap()
        .lock()
        .unwrap()
        .user_count();
    let before_b = registry
        .tenant_store("worker-alpha", "customer-b")
        .unwrap()
        .lock()
        .unwrap()
        .user_count();

    let (status, project_created) = post(
        &s,
        &format!("{V1}/accounts:signUp?key=worker-key"),
        &json!({
            "email": "query-refresh-project-user@example.com",
            "password": "password1",
        }),
    );
    assert_eq!(status, 200, "{project_created}");
    let project_store = registry.store_for("worker-alpha").unwrap();
    let project_before = project_store.lock().unwrap().user_count();
    let (status, refused_project) = post(
        &s,
        "/securetoken.googleapis.com/v1/token?key=worker-key&tenantId=customer-a",
        &json!({
            "grant_type": "refresh_token",
            "refresh_token": project_created["refreshToken"],
        }),
    );
    assert_eq!(status, 400, "{refused_project}");
    assert_eq!(refused_project["error"]["message"], "TENANT_ID_MISMATCH");
    assert_eq!(project_store.lock().unwrap().user_count(), project_before);

    let (status, refused) = post(
        &s,
        "/securetoken.googleapis.com/v1/token?key=worker-key&tenantId=customer-b",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-a")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_a
    );
    assert_eq!(
        registry
            .tenant_store("worker-alpha", "customer-b")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_b
    );

    let (status, renewed) = post(
        &s,
        "/securetoken.googleapis.com/v1/token?key=worker-key&tenantId=customer-a",
        &json!({"grant_type": "refresh_token", "refresh_token": created["refreshToken"]}),
    );
    assert_eq!(status, 200, "{renewed}");
    assert_eq!(renewed["user_id"], created["localId"]);
}

#[test]
fn query_tenant_selector_must_match_id_token_before_auth_work() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    for tenant in ["tenant-a", "tenant-b"] {
        registry.ensure_tenant("demo-app", tenant).unwrap();
    }
    s.registry = Some(registry.clone());

    let (status, created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "tenantId": "tenant-a",
            "email": "query-tenant-owner@example.com",
            "password": "password1"
        }),
    );
    assert_eq!(status, 200, "{created}");
    let id_token = created["idToken"].as_str().unwrap();

    let (status, default_created) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({
            "email": "query-tenant-project-owner@example.com",
            "password": "password1"
        }),
    );
    assert_eq!(status, 200, "{default_created}");
    let project_id_token = default_created["idToken"].as_str().unwrap();

    let before = admin(
        &s,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/tenant-a/accounts:lookup"),
        &json!({"localId": [created["localId"].clone()]}),
    );
    assert_eq!(before.0, 200, "{}", before.1);

    let default_before = admin(
        &s,
        "POST",
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [default_created["localId"].clone()]}),
    );
    assert_eq!(default_before.0, 200, "{}", default_before.1);

    let (status, project_refused) = post(
        &s,
        &format!("{V1}/accounts:update?key=fake-api-key&tenantId=tenant-a"),
        &json!({
            "idToken": project_id_token,
            "displayName": "must-not-apply",
            "returnSecureToken": true
        }),
    );
    assert_eq!(status, 400, "{project_refused}");
    assert_eq!(project_refused["error"]["message"], "TENANT_ID_MISMATCH");
    assert!(project_refused.get("idToken").is_none());
    assert!(project_refused.get("refreshToken").is_none());

    let default_after = admin(
        &s,
        "POST",
        &format!("{V1}/projects/demo-app/accounts:lookup"),
        &json!({"localId": [default_created["localId"].clone()]}),
    );
    assert_eq!(default_after.0, 200, "{}", default_after.1);
    assert_eq!(default_after.1, default_before.1);

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:update?tenantId=tenant-b"),
        &json!({
            "idToken": id_token,
            "displayName": "must-not-apply",
            "returnSecureToken": true
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    assert!(refused.get("idToken").is_none());
    assert!(refused.get("refreshToken").is_none());

    let after = admin(
        &s,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/tenant-a/accounts:lookup"),
        &json!({"localId": [created["localId"].clone()]}),
    );
    assert_eq!(after.0, 200, "{}", after.1);
    assert_eq!(after.1, before.1);
    assert!(registry
        .tenant_store("demo-app", "tenant-b")
        .unwrap()
        .lock()
        .unwrap()
        .user_by_email("query-tenant-owner@example.com")
        .is_none());

    let (status, same_tenant) = post(
        &s,
        &format!("{V1}/accounts:lookup?tenantId=tenant-a"),
        &json!({"idToken": id_token}),
    );
    assert_eq!(status, 200, "{same_tenant}");
    assert_eq!(same_tenant["users"][0]["localId"], created["localId"]);
}

#[test]
fn conflicting_body_and_query_tenants_fail_without_mutation() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    registry.ensure_tenant("demo-app", "tenant-b").unwrap();
    s.registry = Some(registry.clone());

    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signUp?tenantId=tenant-b"),
        &json!({
            "tenantId": "tenant-a",
            "email": "conflicting-tenant@example.com",
            "password": "password1"
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    for store in [
        s.store.clone(),
        registry.tenant_store("demo-app", "tenant-a").unwrap(),
        registry.tenant_store("demo-app", "tenant-b").unwrap(),
    ] {
        assert!(
            store
                .lock()
                .unwrap()
                .user_by_email("conflicting-tenant@example.com")
                .is_none(),
            "conflicting tenant selector must not mutate any namespace"
        );
    }
}

#[test]
fn duplicate_query_selectors_fail_closed_without_mutation() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    let tenant = registry.tenant_store("demo-app", "tenant-a").unwrap();
    s.registry = Some(registry.clone());

    for query in [
        "tenantId=tenant-a&tenantId=tenant-a",
        "tenantId=tenant-a&tenantId=tenant-b",
        "tenantId=tenant-b&tenantId=tenant-a",
    ] {
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:signUp?{query}"),
            &json!({
                "email": "duplicate-query-tenant@example.com",
                "password": "password1",
            }),
        );
        assert_eq!(status, 400, "{query}: {refused}");
        assert_eq!(refused["error"]["message"], "INVALID_ARGUMENT", "{query}");
        assert!(s
            .store
            .lock()
            .unwrap()
            .user_by_email("duplicate-query-tenant@example.com")
            .is_none());
        assert!(tenant
            .lock()
            .unwrap()
            .user_by_email("duplicate-query-tenant@example.com")
            .is_none());
    }

    for (index, query) in [
        "key=fake-api-key&key=fake-api-key",
        "key=fake-api-key&apiKey=fake-api-key",
        "apiKey=fake-api-key&key=fake-api-key",
        "key=fake-api-key&%61piKey=fake-api-key",
        "%6bey=fake-api-key&apiKey=fake-api-key",
        "key=first-key&apiKey=second-key",
        "apiKey=second-key&key=first-key",
    ]
    .into_iter()
    .enumerate()
    {
        let email = format!("duplicate-query-key-{index}@example.com");
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:signUp?{query}"),
            &json!({"email": email, "password": "password1"}),
        );
        assert_eq!(status, 400, "{query}: {refused}");
        assert_eq!(refused["error"]["message"], "INVALID_ARGUMENT", "{query}");
        assert!(s.store.lock().unwrap().user_by_email(&email).is_none());
        assert!(tenant.lock().unwrap().user_by_email(&email).is_none());
    }

    let policy = admin(
        &s,
        "GET",
        &format!("{V2}/passwordPolicy?tenantId=tenant-a"),
        &Value::Null,
    );
    assert_eq!(policy.0, 200, "{}", policy.1);
}

#[test]
fn malformed_query_selectors_fail_closed_without_mutation() {
    let mut s = state();
    let registry = Arc::new(fireemu_core_auth::store::AuthRegistry::new(
        "demo-app",
        s.store.clone(),
    ));
    registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    let tenant = registry.tenant_store("demo-app", "tenant-a").unwrap();
    s.registry = Some(registry);

    for (index, query) in [
        "tenantId",
        "%74enantId",
        "key",
        "apiKey",
        "key=valid-key&tenantId",
        "tenantId&key=valid-key",
        "tenantId=",
        "%74enantId=",
        "key=",
        "apiKey=",
        "%6bey=",
        "%61piKey=%ZZ",
        "tenantId=%ZZ",
        "key=valid%ZZ",
        "apiKey=%A",
    ]
    .into_iter()
    .enumerate()
    {
        let email = format!("malformed-selector-{index}@example.com");
        let (status, refused) = post(
            &s,
            &format!("{V1}/accounts:signUp?{query}"),
            &json!({"email": email, "password": "password1"}),
        );
        assert_eq!(status, 400, "{query}: {refused}");
        assert_eq!(refused["error"]["message"], "INVALID_ARGUMENT", "{query}");
        assert!(s.store.lock().unwrap().user_by_email(&email).is_none());
        assert!(tenant.lock().unwrap().user_by_email(&email).is_none());
    }

    for (index, query) in [
        "ignored&%74enantId=tenant%2Da",
        "ignored=%ZZ&tenantId=tenant-a",
    ]
    .into_iter()
    .enumerate()
    {
        let email = format!("valid-selector-with-unrelated-query-{index}@example.com");
        let (status, created) = post(
            &s,
            &format!("{V1}/accounts:signUp?{query}"),
            &json!({"email": email, "password": "password1"}),
        );
        assert_eq!(status, 200, "{query}: {created}");
        assert!(tenant.lock().unwrap().user_by_email(&email).is_some());
    }
}

/// Reads back one account through the Admin lookup route.
fn admin_lookup(state: &AuthState, uid: &str) -> Value {
    let (status, users) = admin(
        state,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": uid}),
    );
    assert_eq!(status, 200, "{users}");
    users["users"][0].clone()
}

/// The provider ids an account record carries.
fn provider_ids(record: &Value) -> Vec<String> {
    record["providerUserInfo"]
        .as_array()
        .map(|providers| {
            providers
                .iter()
                .filter_map(|p| p["providerId"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// An Admin `accounts:update` applies every part of the request or none of it. The MFA list
/// is written after the custom claims and the provider links, so each condition that can
/// refuse the list has to be decided before the first write; otherwise a 400 leaves the
/// claims and the providers changed.
#[test]
fn admin_update_refused_for_a_bad_mfa_display_name_changes_nothing() {
    let s = state();
    let (_, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "atomic-mfa@example.com", "password": "hunter22"}),
    );
    let uid = signed_up["localId"].as_str().unwrap().to_owned();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "customAttributes": "{\"tier\":\"gold\"}"}),
    );
    assert_eq!(status, 200);

    let request = |display_name: &str| {
        json!({
            "localId": uid,
            "customAttributes": "{\"tier\":\"platinum\"}",
            "linkProviderUserInfo": {"providerId": "oidc.acme", "rawId": "raw-acme-1"},
            "mfa": {"enrollments": [{"phoneInfo": "+15550001111", "displayName": display_name}]},
        })
    };

    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &request("work\u{1}phone"),
    );
    assert_eq!(status, 400, "{refused}");
    let record = admin_lookup(&s, &uid);
    assert_eq!(
        record["customAttributes"], "{\"tier\":\"gold\"}",
        "{record}"
    );
    assert!(
        !provider_ids(&record).iter().any(|id| id == "oidc.acme"),
        "{record}"
    );
    assert!(record.get("mfaInfo").is_none(), "{record}");

    let (status, applied) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &request("work phone"),
    );
    assert_eq!(status, 200, "{applied}");
    let record = admin_lookup(&s, &uid);
    assert_eq!(
        record["customAttributes"], "{\"tier\":\"platinum\"}",
        "{record}"
    );
    assert!(
        provider_ids(&record).iter().any(|id| id == "oidc.acme"),
        "{record}"
    );
    assert_eq!(
        record["mfaInfo"][0]["phoneInfo"], "+15550001111",
        "{record}"
    );
    assert_eq!(
        record["mfaInfo"][0]["displayName"], "work phone",
        "{record}"
    );
}

/// The per-user factor budget is a second condition the MFA list can fail on, and it is
/// decided from the account the request would not otherwise have changed.
#[test]
fn admin_update_refused_for_an_over_budget_mfa_list_changes_nothing() {
    let s = state();
    let (_, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "atomic-budget@example.com", "password": "hunter22"}),
    );
    let uid = signed_up["localId"].as_str().unwrap().to_owned();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "customAttributes": "{\"tier\":\"gold\"}"}),
    );
    assert_eq!(status, 200);

    let enrollments: Vec<Value> = (0..=fireemu_core_auth::mfa::MAX_FACTORS_PER_USER)
        .map(|i| json!({"phoneInfo": format!("+1555000{i:04}")}))
        .collect();
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": uid,
            "customAttributes": "{\"tier\":\"platinum\"}",
            "mfa": {"enrollments": enrollments},
        }),
    );
    assert_eq!(status, 400, "{refused}");
    let record = admin_lookup(&s, &uid);
    assert_eq!(
        record["customAttributes"], "{\"tier\":\"gold\"}",
        "{record}"
    );
    assert!(record.get("mfaInfo").is_none(), "{record}");
}

/// A disabled account refuses the enrollment, and that refusal has to be decided before the
/// claims are written too.
#[test]
fn admin_update_refused_for_a_disabled_account_mfa_list_changes_nothing() {
    let s = state();
    let (_, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "atomic-disabled@example.com", "password": "hunter22"}),
    );
    let uid = signed_up["localId"].as_str().unwrap().to_owned();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "customAttributes": "{\"tier\":\"gold\"}", "disableUser": true}),
    );
    assert_eq!(status, 200);

    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": uid,
            "customAttributes": "{\"tier\":\"platinum\"}",
            "mfa": {"enrollments": [{"phoneInfo": "+15550002222"}]},
        }),
    );
    assert_eq!(status, 400, "{refused}");
    let record = admin_lookup(&s, &uid);
    assert_eq!(
        record["customAttributes"], "{\"tier\":\"gold\"}",
        "{record}"
    );
    assert!(record.get("mfaInfo").is_none(), "{record}");
}

/// The mirror order: the provider link is refused while the MFA list is valid. The link is
/// parsed before any write, so the accepted list is not written either.
#[test]
fn admin_update_refused_for_a_bad_provider_link_leaves_the_mfa_list_unchanged() {
    let s = state();
    let (_, signed_up) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "atomic-mirror@example.com", "password": "hunter22"}),
    );
    let uid = signed_up["localId"].as_str().unwrap().to_owned();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": uid, "customAttributes": "{\"tier\":\"gold\"}"}),
    );
    assert_eq!(status, 200);

    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({
            "localId": uid,
            "customAttributes": "{\"tier\":\"platinum\"}",
            "linkProviderUserInfo": {"providerId": "oidc.acme", "rawId": "raw\u{1}acme"},
            "mfa": {"enrollments": [{"phoneInfo": "+15550003333", "displayName": "work phone"}]},
        }),
    );
    assert_eq!(status, 400, "{refused}");
    let record = admin_lookup(&s, &uid);
    assert_eq!(
        record["customAttributes"], "{\"tier\":\"gold\"}",
        "{record}"
    );
    assert!(
        !provider_ids(&record).iter().any(|id| id == "oidc.acme"),
        "{record}"
    );
    assert!(record.get("mfaInfo").is_none(), "{record}");
}

// -----------------------------------------------------------------------------
// Strict administrator field ordering. These are local contract tests, not a
// replacement for final-artifact execution or production comparison.
// -----------------------------------------------------------------------------

fn query_sort_fixture() -> AuthState {
    let s = strict_state();
    for (uid, email, name, created, last_login) in [
        ("c", "z@example.com", "Z", 10, Some(3)),
        ("a", "a@example.com", "B", 9, None),
        ("d", "d@example.com", "C", 20, Some(10)),
        ("b", "b@example.com", "A", 2, Some(2)),
    ] {
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": uid, "email": email, "displayName": name}),
        );
        assert_eq!(status, 200, "{body}");
        let mut store = s.store.lock().unwrap();
        let local_id = store
            .all_user_ids()
            .into_iter()
            .find(|id| id.as_str() == uid)
            .unwrap();
        let record = store.user_mut(&local_id).unwrap();
        record.created_at = LogicalInstant::from_unix_seconds(created);
        record.last_sign_in_at = last_login.map(LogicalInstant::from_unix_seconds);
    }
    s
}

fn query_result_ids(body: &Value) -> Vec<&str> {
    // An empty page omits `userInfo`.
    assert!(body.get("recordsCount").is_some(), "{body}");
    body.get("userInfo")
        .map_or(&[][..], |rows| rows.as_array().unwrap())
        .iter()
        .map(|row| row["localId"].as_str().unwrap())
        .collect()
}

/// Descending sorts keep ties in ascending user-id order, and an empty page carries no
/// `userInfo` (sandbox recording 2026-09-23, `auth-account/admin/query`).
#[test]
fn strict_admin_query_descending_ties_stay_in_user_id_order() {
    let s = strict_state();
    for (uid, name) in [
        ("q1", Some("Carol")),
        ("q2", Some("alice")),
        ("q3", Some("Bob")),
        ("q4", None),
        ("q5", Some("Bob")),
    ] {
        let mut body = json!({"localId": uid});
        if let Some(name) = name {
            body["displayName"] = json!(name);
        }
        assert_eq!(
            admin(&s, "POST", &format!("{ADMIN}/accounts"), &body).0,
            200
        );
    }
    let path = format!("{ADMIN}/accounts:query");
    for (sort, order, expected) in [
        ("NAME", "ASC", ["q4", "q3", "q5", "q1", "q2"]),
        ("NAME", "DESC", ["q2", "q1", "q3", "q5", "q4"]),
        ("LAST_LOGIN_AT", "DESC", ["q1", "q2", "q3", "q4", "q5"]),
        ("USER_ID", "DESC", ["q5", "q4", "q3", "q2", "q1"]),
    ] {
        let (status, page) = admin(&s, "POST", &path, &json!({"sortBy": sort, "order": order}));
        assert_eq!(status, 200, "{page}");
        assert_eq!(query_result_ids(&page), expected, "{sort} {order}");
    }
    for body in [
        json!({"limit": "0"}),
        json!({"expression": [{"email": "nobody@example.com"}]}),
    ] {
        let (status, page) = admin(&s, "POST", &path, &body);
        assert_eq!(status, 200, "{page}");
        assert_eq!(page, json!({"recordsCount": "0"}));
    }
}

#[test]
fn strict_admin_query_all_documented_sorts_apply_before_paging_on_both_routes() {
    let s = query_sort_fixture();
    let before = admin(&s, "POST", &format!("{ADMIN}/accounts:query"), &json!({})).1;
    for (sort, expected) in [
        ("USER_ID", ["a", "b", "c", "d"]),
        ("NAME", ["b", "a", "d", "c"]),
        ("CREATED_AT", ["b", "a", "c", "d"]),
        ("LAST_LOGIN_AT", ["a", "b", "c", "d"]),
        ("USER_EMAIL", ["a", "b", "d", "c"]),
    ] {
        for route in [
            format!("{ADMIN}/accounts:query"),
            format!("{ADMIN}:queryAccounts"),
        ] {
            for descending in [false, true] {
                let mut order = expected.to_vec();
                if descending {
                    order.reverse();
                }
                let (status, page) = admin(
                    &s,
                    "POST",
                    &route,
                    &json!({
                        "sortBy": sort, "order": if descending { "DESC" } else { "ASC" },
                        "limit": "2", "offset": "1"
                    }),
                );
                assert_eq!(status, 200, "{sort} {route}: {page}");
                assert_eq!(query_result_ids(&page), order[1..3]);
                assert_eq!(page["recordsCount"], "2");
            }
        }
    }
    let after = admin(&s, "POST", &format!("{ADMIN}/accounts:query"), &json!({})).1;
    assert_eq!(
        before, after,
        "queries must not update accounts or timestamps"
    );
}

#[test]
fn strict_admin_query_count_and_empty_pages_answer_only_the_count() {
    let s = query_sort_fixture();
    for sort in ["NAME", "CREATED_AT", "LAST_LOGIN_AT", "USER_EMAIL"] {
        let (status, count) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:query"),
            &json!({"sortBy": sort, "returnUserInfo": false}),
        );
        assert_eq!(status, 200, "{count}");
        assert_eq!(count["recordsCount"], "4");
        assert!(count.get("userInfo").is_none());
        for boundary in [json!({"limit": 0}), json!({"offset": "4"})] {
            let mut request = boundary;
            request["sortBy"] = json!(sort);
            let (status, page) = admin(&s, "POST", &format!("{ADMIN}/accounts:query"), &request);
            assert_eq!(status, 200, "{page}");
            // Production omits an empty page (sandbox recording 2026-09-23, limit-0).
            assert_eq!(page, json!({"recordsCount": "0"}));
        }
    }
}

#[test]
fn strict_admin_query_never_silently_ignores_a_malformed_or_unsupported_filter() {
    let s = query_sort_fixture();
    for malformed in [json!({}), json!("uid-a"), json!(false), json!(1)] {
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:query"),
            &json!({"expression": malformed, "sortBy": "NAME"}),
        );
        assert_eq!(status, 400, "{body}");
        assert!(body.get("userInfo").is_none());
    }
    let (status, filtered) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"expression": [{"email": "a@example.com"}], "sortBy": "USER_EMAIL"}),
    );
    assert_eq!(status, 200, "{filtered}");
    assert_eq!(query_result_ids(&filtered), ["a"]);
    for expression in [Value::Null, json!([])] {
        let (status, page) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:query"),
            &json!({"expression": expression, "sortBy": "NAME"}),
        );
        assert_eq!(status, 200, "{page}");
        assert_eq!(query_result_ids(&page), ["b", "a", "d", "c"]);
    }
}

#[test]
fn firebase_admin_query_keeps_its_legacy_uid_order_and_ignored_paging() {
    let s = state();
    for (uid, name) in [("a", "Z"), ("b", "A")] {
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": uid, "displayName": name}),
        );
        assert_eq!(status, 200, "{body}");
    }
    let (status, page) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"sortBy": "NAME", "limit": 1, "offset": 1}),
    );
    assert_eq!(status, 200, "{page}");
    assert_eq!(query_result_ids(&page), ["a", "b"]);
    assert_eq!(page["recordsCount"], "2");
}

#[test]
fn sorted_admin_query_does_not_admit_an_end_user_or_a_wrong_project() {
    let s = query_sort_fixture();
    let request = json!({"sortBy": "NAME"});
    for suffix in ["/accounts:query", ":queryAccounts"] {
        let path = format!("{ADMIN}{suffix}");
        let (status, _) = post(&s, &path, &request);
        assert_eq!(status, 403);
        let (status, _) = admin(
            &s,
            "POST",
            &format!("/identitytoolkit.googleapis.com/v1/projects/wrong-project{suffix}"),
            &request,
        );
        assert_eq!(status, 400);
        assert_eq!(admin(&s, "GET", &path, &request).0, 405);
        let mut foreign_origin = owner();
        foreign_origin.origin = Some("https://foreign.invalid".to_owned());
        assert_eq!(
            handle_with(&s, "POST", &path, &foreign_origin, &request).status,
            403
        );
    }
}

#[test]
fn sorted_admin_query_remains_scoped_to_the_selected_tenant() {
    let mut s = query_sort_fixture();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    s.registry = Some(registry);
    let tenant = format!("{ADMIN}/tenants/customer");
    for (uid, name) in [("a", "Z"), ("b", "A")] {
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{tenant}/accounts"),
            &json!({"localId": uid, "displayName": name}),
        );
        assert_eq!(status, 200, "{body}");
    }
    let (status, tenant_page) = admin(
        &s,
        "POST",
        &format!("{tenant}/accounts:query"),
        &json!({"sortBy": "NAME"}),
    );
    assert_eq!(status, 200, "{tenant_page}");
    assert_eq!(query_result_ids(&tenant_page), ["b", "a"]);
    assert_eq!(tenant_page["recordsCount"], "2");
    let (status, default_page) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:query"),
        &json!({"sortBy": "NAME"}),
    );
    assert_eq!(status, 200, "{default_page}");
    assert_eq!(query_result_ids(&default_page), ["b", "a", "d", "c"]);
    assert_eq!(default_page["recordsCount"], "4");
}

#[test]
fn strict_admin_query_body_tenant_is_scoped_and_never_silently_ignored() {
    let mut s = query_sort_fixture();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    s.registry = Some(registry);
    let tenant = format!("{ADMIN}/tenants/customer");
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{tenant}/accounts"),
            &json!({"localId": "tenant-only", "displayName": "A"}),
        )
        .0,
        200
    );
    for suffix in ["/accounts:query", ":queryAccounts"] {
        let path = format!("{ADMIN}{suffix}");
        let body = json!({"tenantId": "customer", "sortBy": "NAME"});
        let (status, page) = admin(&s, "POST", &path, &body);
        assert_eq!(status, 200, "{page}");
        assert_eq!(query_result_ids(&page), ["tenant-only"]);
        assert_eq!(page["recordsCount"], "1");
        let (status, count) = admin(
            &s,
            "POST",
            &path,
            &json!({"tenantId": "customer", "returnUserInfo": false}),
        );
        assert_eq!(status, 200, "{count}");
        assert_eq!(count["recordsCount"], "1");
        assert_eq!(post(&s, &path, &body).0, 403);
        for malformed in [json!(false), json!(7), json!([]), json!({})] {
            let (status, refused) = admin(
                &s,
                "POST",
                &path,
                &json!({"tenantId": malformed, "sortBy": "NAME"}),
            );
            assert_eq!(status, 400, "{refused}");
            assert!(refused.get("userInfo").is_none());
        }
        let (status, refused) = admin(
            &s,
            "POST",
            &path,
            &json!({"tenantId": "not-a-tenant", "sortBy": "NAME"}),
        );
        assert_eq!(status, 404, "{refused}");
        assert!(refused.get("userInfo").is_none());
        assert_eq!(
            admin(&s, "POST", &format!("{path}?tenantId=other"), &body).0,
            400
        );
    }
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{tenant}/accounts:query"),
            &json!({"tenantId": "other", "sortBy": "NAME"}),
        )
        .0,
        400
    );
    let (status, default_page) = admin(
        &s,
        "POST",
        &format!("{ADMIN}:queryAccounts"),
        &json!({"sortBy": "NAME"}),
    );
    assert_eq!(status, 200, "{default_page}");
    assert_eq!(default_page["recordsCount"], "4");
}

// Typed query expression tests. OR/exact matching and local parser limits are local policy.
#[test]
fn strict_query_expression_priorities_exact_union_and_duplicates_are_explicit() {
    let s = query_sort_fixture();
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId":"b", "phoneNumber":"+15550000002"})
        )
        .0,
        200
    );
    for (expression, expected) in [
        (json!([{"email":"A@EXAMPLE.COM"}]), vec!["a"]),
        (json!([{"phoneNumber":"+15550000002"}]), vec!["b"]),
        (json!([{"userId":"c"}]), vec!["c"]),
        (
            json!([{"email":"a@example.com", "phoneNumber":"+15550000002", "userId":"c"}]),
            vec!["a"],
        ),
        (
            json!([{"email":null, "phoneNumber":"+15550000002", "userId":"c"}]),
            vec!["b"],
        ),
        (
            json!([{"email":null, "phoneNumber":null, "userId":"c"}]),
            vec!["c"],
        ),
        // Production evaluates only the first expression and treats an empty selector as
        // unset (sandbox recording 2026-09-23, auth-account/admin/query).
        (
            json!([{"email":"a@example.com"}, {"userId":"a"}, {"userId":"c"}, {"userId":"c"}]),
            vec!["a"],
        ),
        (json!([{"email":"", "userId":"a"}]), vec!["a"]),
        (json!([{"email":"%@example.com"}]), vec![]),
        (json!([{"email":"a@"}]), vec![]),
        (json!([{"userId":"A"}]), vec![]),
    ] {
        let (status, page) = admin(
            &s,
            "POST",
            &format!("{ADMIN}:queryAccounts"),
            &json!({"expression": expression}),
        );
        assert_eq!(status, 200, "{page}");
        assert_eq!(query_result_ids(&page), expected, "{expression}");
        assert_eq!(page["recordsCount"], expected.len().to_string());
    }
}

#[test]
fn strict_expression_filters_before_sort_paging_and_count_only() {
    let s = query_sort_fixture();
    let expression = json!([{"userId":"a"}, {"userId":"c"}, {"userId":"d"}]);
    let before = format!("{:?}", s.store.lock().unwrap());
    let (status, count) = admin(
        &s,
        "POST",
        &format!("{ADMIN}:queryAccounts"),
        &json!({"expression":expression, "returnUserInfo":false, "sortBy":"NAME"}),
    );
    assert_eq!(status, 200, "{count}");
    // Only the first expression is evaluated in production (sandbox recording 2026-09-23).
    assert_eq!(count, json!({"recordsCount":"1"}));
    for (order, expected) in [("ASC", Vec::<&str>::new()), ("DESC", Vec::new())] {
        let (status, page) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:query"),
            &json!({"expression":expression, "sortBy":"NAME", "order":order, "offset":1, "limit":2}),
        );
        assert_eq!(status, 200, "{page}");
        assert_eq!(query_result_ids(&page), expected);
        assert_eq!(page["recordsCount"], "0");
    }
    for body in [
        json!({"expression":expression, "limit":0}),
        json!({"expression":expression, "offset":"9223372036854775807"}),
    ] {
        let (status, page) = admin(&s, "POST", &format!("{ADMIN}:queryAccounts"), &body);
        assert_eq!(status, 200, "{page}");
        assert!(page.get("userInfo").is_none(), "{page}");
    }
    assert_eq!(before, format!("{:?}", s.store.lock().unwrap()));
}

#[test]
fn malformed_expression_never_falls_back_to_an_unfiltered_response() {
    let s = query_sort_fixture();
    let before = format!("{:?}", s.store.lock().unwrap());
    for expression in [
        json!({}),
        json!("SQL"),
        json!([null]),
        json!([[]]),
        json!([{"email":true}]),
        json!([{"userId":4}]),
        json!([{"phoneNumber":{}}]),
        json!([{"name":"A"}]),
        json!([{"email":"a@example.com", "userId":false}]),
        json!([{"email":"a@example.com", "unknown":null}]),
        json!([{"userId":"a\n"}]),
        json!([{"email":"a@example.com"}, null]),
    ] {
        for count_only in [false, true] {
            let (status, body) = admin(
                &s,
                "POST",
                &format!("{ADMIN}:queryAccounts"),
                &json!({"expression":expression, "returnUserInfo":!count_only}),
            );
            assert_eq!(status, 400, "{expression}: {body}");
            assert!(body.get("userInfo").is_none());
            assert!(body.get("recordsCount").is_none());
        }
    }
    // An item without a selector (or with a null one) is well-formed and unconstrained in
    // production (sandbox recording 2026-09-23, auth-account/admin/query#expression-empty-item).
    let (_, all) = admin(
        &s,
        "POST",
        &format!("{ADMIN}:queryAccounts"),
        &json!({"returnUserInfo": false}),
    );
    for expression in [json!([{}]), json!([{"userId": null}])] {
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}:queryAccounts"),
            &json!({"expression": expression, "returnUserInfo": false}),
        );
        assert_eq!(status, 200, "{expression}: {body}");
        assert_eq!(body["recordsCount"], all["recordsCount"], "{expression}");
    }
    assert_eq!(before, format!("{:?}", s.store.lock().unwrap()));
}

#[test]
fn expression_count_and_utf8_byte_limits_are_local_and_fail_closed() {
    let s = query_sort_fixture();
    for (size, accepted) in [(128, true), (129, false)] {
        let expression = vec![json!({"userId":"a"}); size];
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}:queryAccounts"),
            &json!({"expression":expression}),
        );
        assert_eq!(status, if accepted { 200 } else { 400 });
    }
    for (value, accepted) in [
        ("x".repeat(4096), true),
        ("x".repeat(4097), false),
        ("あ".repeat(1365), true),
        ("あ".repeat(1366), false),
    ] {
        let (status, page) = admin(
            &s,
            "POST",
            &format!("{ADMIN}:queryAccounts"),
            &json!({"expression":[{"userId":value}]}),
        );
        assert_eq!(status, if accepted { 200 } else { 400 }, "{page}");
        if accepted {
            assert!(query_result_ids(&page).is_empty());
        }
    }
}

#[test]
fn account_expression_is_namespace_scoped_and_keeps_management_authorization() {
    let mut s = query_sort_fixture();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", "customer").unwrap();
    s.registry = Some(registry);
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/tenants/customer/accounts"),
            &json!({"localId":"a", "email":"tenant@example.com"})
        )
        .0,
        200
    );
    for (selector, expected) in [
        (json!({"userId":"a"}), vec!["a"]),
        (json!({"email":"a@example.com"}), vec![]),
    ] {
        let body = json!({"tenantId":"customer", "expression":[selector]});
        let path = format!("{ADMIN}:queryAccounts");
        let (status, page) = admin(&s, "POST", &path, &body);
        assert_eq!(status, 200, "{page}");
        assert_eq!(query_result_ids(&page), expected);
        assert_eq!(post(&s, &path, &body).0, 403);
        let mut foreign = owner();
        foreign.origin = Some("https://external.invalid".into());
        assert_eq!(handle_with(&s, "POST", &path, &foreign, &body).status, 403);
    }
    let (status, page) = admin(
        &s,
        "POST",
        &format!("{ADMIN}:queryAccounts"),
        &json!({"expression":[{"email":"tenant@example.com"}]}),
    );
    assert_eq!(status, 200, "{page}");
    assert!(query_result_ids(&page).is_empty());
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}:queryAccounts"),
            &json!({"tenantId":"unknown", "expression":[{"userId":"a"}]})
        )
        .0,
        404
    );
}

#[test]
fn firebase_query_profile_still_reports_expression_as_unsupported() {
    let s = state();
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:query"),
            &json!({"expression":[{"userId":"a"}]})
        )
        .0,
        501
    );
}

#[test]
fn generated_account_expression_corpus_runs_through_the_native_handler() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../spec/compatibility/auth-account-federation-local-v1.json"
    ))
    .unwrap();
    assert_eq!(corpus["productionAllowed"], false);
    let s = strict_state();
    for user in corpus["account"]["fixture"].as_array().unwrap() {
        let (status, body) = admin(&s, "POST", &format!("{ADMIN}/accounts"), user);
        assert_eq!(status, 200, "{body}");
    }
    let before = format!("{:?}", s.store.lock().unwrap().users_by_creation());
    for case in corpus["account"]["cases"].as_array().unwrap() {
        for suffix in ["/accounts:query", ":queryAccounts"] {
            let (status, body) = admin(&s, "POST", &format!("{ADMIN}{suffix}"), &case["request"]);
            assert_eq!(
                json!(status),
                case["expected"]["status"],
                "{}: {body}",
                case["id"]
            );
            if status == 200 {
                assert_eq!(body["recordsCount"], case["expected"]["count"]);
                if case["expected"]["ids"].is_null() {
                    assert!(body.get("userInfo").is_none());
                } else {
                    assert_eq!(
                        json!(query_result_ids(&body)),
                        case["expected"]["ids"],
                        "{}",
                        case["id"]
                    );
                }
            } else {
                assert!(body.get("userInfo").is_none());
                assert!(body.get("recordsCount").is_none());
            }
            assert_eq!(
                before,
                format!("{:?}", s.store.lock().unwrap().users_by_creation())
            );
        }
    }
}

/// Every hash vector production accepted (conformance/src/auth-account/hash-vectors.json)
/// imports through `accounts:batchCreate` and signs in with its password only.
#[test]
fn imported_production_hash_formats_sign_in_with_their_password_only() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/src/auth-account/hash-vectors.json"
    );
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let s = state();
    for (index, (name, vector)) in vectors.as_object().unwrap().iter().enumerate() {
        let email = format!("hash-{index}@example.com");
        let mut request = vector["options"].clone();
        let mut user = vector["user"].clone();
        user["localId"] = json!(format!("hash-{index}"));
        user["email"] = json!(email);
        request["users"] = json!([user]);
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:batchCreate"),
            &request,
        );
        assert_eq!(status, 200, "{name}: {response}");
        assert!(response.get("error").is_none(), "{name}: {response}");
        let sign_in = |password: &str| {
            post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": email, "password": password, "returnSecureToken": true}),
            )
            .0
        };
        assert_eq!(
            sign_in("password124"),
            400,
            "{name} refuses another password"
        );
        assert_eq!(sign_in("password123"), 200, "{name} accepts its password");
        assert_eq!(
            sign_in("password123"),
            200,
            "{name} still signs in after the rehash"
        );
    }
}

#[test]
fn invalid_hash_parameters_refuse_the_whole_import() {
    let s = state();
    let argon = |overrides: Value| {
        let mut params = json!({"hashType": "ARGON2_ID", "iterations": 2, "memoryCostKib": 1024, "parallelism": 1, "hashLengthBytes": 32});
        for (k, v) in overrides.as_object().unwrap() {
            params[k] = v.clone();
        }
        json!({"hashAlgorithm": "ARGON2", "argon2Parameters": params})
    };
    let scrypt = |rounds: u32, memory: u32| json!({"hashAlgorithm": "SCRYPT", "signerKey": "AAAA", "rounds": rounds, "memoryCost": memory});
    // Every code the Identity Platform sandbox answered (recording 2026-09-23).
    for (options, code) in [
        (json!({"hashAlgorithm": "NOT_AN_ALGORITHM"}), "INVALID_HASH_ALGORITHM"),
        (json!({"hashAlgorithm": "PBKDF_SHA1"}), "INVALID_HASH_ROUNDS"),
        (json!({"hashAlgorithm": "PBKDF_SHA1", "rounds": 0}), "INVALID_HASH_ROUNDS"),
        (json!({"hashAlgorithm": "PBKDF_SHA1", "rounds": 120_001}), "INVALID_HASH_ROUNDS"),
        (json!({"hashAlgorithm": "SHA256", "rounds": 8193}), "INVALID_HASH_ROUNDS"),
        (json!({"hashAlgorithm": "MD5", "rounds": 8193}), "INVALID_HASH_ROUNDS"),
        (json!({"hashAlgorithm": "HMAC_SHA256"}), "EMPTY_HASH_KEY"),
        (scrypt(8, 15), "INVALID_HASH_MEMORY_COSTS"),
        (scrypt(8, 0), "INVALID_HASH_MEMORY_COSTS"),
        (scrypt(9, 14), "INVALID_HASH_ROUNDS"),
        (scrypt(0, 14), "INVALID_HASH_ROUNDS"),
        (json!({"hashAlgorithm": "STANDARD_SCRYPT", "blockSize": 8, "parallelization": 1, "dkLen": 64}), "INVALID_HASH_PARAMETER"),
        (json!({"hashAlgorithm": "STANDARD_SCRYPT", "cpuMemCost": 1024, "blockSize": 8, "parallelization": 1, "dkLen": 0}), "INVALID_HASH_PARAMETER"),
        (json!({"hashAlgorithm": "ARGON2"}), "INVALID_ARGON2_MEMORY_COST"),
        (argon(json!({"memoryCostKib": 32769})), "INVALID_ARGON2_MEMORY_COST"),
        (argon(json!({"iterations": 17})), "INVALID_ARGON2_ITERATIONS"),
        (argon(json!({"parallelism": 0})), "INVALID_ARGON2_PARALLELISM"),
        (argon(json!({"hashType": "HASH_TYPE_UNSPECIFIED"})), "INVALID_ARGON2_HASH_TYPE"),
        (
            json!({"hashAlgorithm": "SHA256", "users": [{"localId": "refused", "passwordHash": "not base64!"}]}),
            "Invalid value at 'users[0].password' (TYPE_BYTES), Base64 decoding failed for \"not base64!\"",
        ),
    ] {
        let mut request = options.clone();
        if request.get("users").is_none() {
            request["users"] = json!([{"localId": "refused", "passwordHash": "AAAA", "salt": "AAAA"}]);
        }
        let (status, response) = admin(&s, "POST", &format!("{ADMIN}/accounts:batchCreate"), &request);
        assert_eq!(status, 400, "{options}: {response}");
        assert_eq!(response["error"]["message"], code, "{options}");
        assert!(s.store.lock().unwrap().user_by_id("refused").is_none());
    }
}

/// Production (sandbox recording 2026-09-23): an account created through the Admin API carries
/// `disabled` and `validSince` in every read, a client-created anonymous account neither, and
/// the Admin create response always carries `email`, empty when none was given.
#[test]
fn admin_created_accounts_report_disabled_and_valid_since_like_production() {
    let s = state();
    let (status, created) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "admin-made"}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["email"], json!(""));
    let (_, found) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["admin-made"]}),
    );
    assert_eq!(found["users"][0]["disabled"], json!(false), "{found}");
    assert!(found["users"][0]["validSince"].is_string(), "{found}");

    let (_, anonymous) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"returnSecureToken": true}),
    );
    let (_, looked) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": anonymous["idToken"]}),
    );
    assert!(looked["users"][0].get("disabled").is_none(), "{looked}");
    assert!(looked["users"][0].get("validSince").is_none(), "{looked}");
}

/// Error messages the Identity Platform sandbox returned for account operations (recording
/// of 2026-09-23, conformance/auth-account-production.json), exact to the detail after " : ".
#[test]
fn account_operation_errors_carry_production_messages() {
    let s = strict_state();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "m1", "email": "m1@example.com", "password": "password123"}),
    );
    assert_eq!(status, 200);
    let update = |body: Value| {
        admin(&s, "POST", &format!("{ADMIN}/accounts:update"), &body).1["error"]["message"].clone()
    };
    assert_eq!(
        update(json!({"localId": "m1", "customAttributes": "{\"sub\":\"x\"}"})),
        "FORBIDDEN_CLAIM : sub"
    );
    let big = format!("{{\"k\":\"{}\"}}", "v".repeat(993));
    assert_eq!(
        update(json!({"localId": "m1", "customAttributes": big})),
        "CLAIMS_TOO_LARGE"
    );
    assert_eq!(
        update(json!({"localId": "m1", "customAttributes": "[1,2]"})),
        "INVALID_CLAIMS : Not a JSON Object: [1,2]"
    );
    assert_eq!(
        update(json!({"localId": "m1", "customAttributes": "\"text\""})),
        "INVALID_CLAIMS : Not a JSON Object: \"text\""
    );
    assert_eq!(
        update(json!({"localId": "m1", "customAttributes": "null"})),
        "INVALID_CLAIMS : Not a JSON Object: null"
    );
    assert_eq!(update(json!({"displayName": "x"})), "MISSING_LOCAL_ID");
    assert_eq!(
        update(json!({"localId": "m1", "deleteAttribute": ["NOT_A_FIELD"]})),
        "Invalid value at 'delete_attribute[0]' (type.googleapis.com/google.cloud.identitytoolkit.v1.SetAccountInfoRequest.UserAttributeName), \"NOT_A_FIELD\""
    );
    let created = |body: Value| {
        admin(&s, "POST", &format!("{ADMIN}/accounts"), &body).1["error"]["message"].clone()
    };
    assert_eq!(
        created(json!({"localId": "m2", "phoneNumber": "6505550101"})),
        "INVALID_PHONE_NUMBER : Invalid format."
    );
    let lookup = |body: Value| {
        admin(&s, "POST", &format!("{ADMIN}/accounts:lookup"), &body).1["error"]["message"].clone()
    };
    assert_eq!(lookup(json!({})), "MISSING_ID_TOKEN");
    assert_eq!(lookup(json!({"localId": []})), "MISSING_ID_TOKEN");

    {
        let mut store = s.store.lock().unwrap();
        let mut config = store.config();
        config.enable_improved_email_privacy = true;
        store.set_config(config);
    }
    let (_, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "m1@example.com", "password": "password123", "returnSecureToken": true}),
    );
    let client_update = |body: Value| {
        post(&s, &format!("{V1}/accounts:update"), &body).1["error"]["message"].clone()
    };
    assert_eq!(
        client_update(json!({"idToken": signed["idToken"], "email": "m1-new@example.com"})),
        "OPERATION_NOT_ALLOWED : Please verify the new email before changing email."
    );
    assert_eq!(
        client_update(json!({"idToken": signed["idToken"], "email": "not-an-email"})),
        "INVALID_EMAIL"
    );
}

/// Production keeps a hash imported without `hashAlgorithm`, or with a three-byte Argon2
/// length, as a password credential with `passwordUpdatedAt` (it just never matches).
#[test]
fn imported_hashes_production_accepts_are_password_credentials() {
    let s = state();
    for (id, request) in [
        (
            "no-algorithm",
            json!({"users": [{"localId": "no-algorithm", "email": "na@example.com", "passwordHash": "AAAA", "salt": "AAAA"}]}),
        ),
        (
            "argon-short",
            json!({"hashAlgorithm": "ARGON2", "argon2Parameters": {"hashType": "ARGON2_ID", "iterations": 2, "memoryCostKib": 1024, "parallelism": 1, "hashLengthBytes": 3}, "users": [{"localId": "argon-short", "email": "as@example.com", "passwordHash": "AAAA", "salt": "AAAA"}]}),
        ),
    ] {
        let (status, response) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:batchCreate"),
            &request,
        );
        assert_eq!(status, 200, "{id}: {response}");
        assert!(response.get("error").is_none(), "{id}: {response}");
        let (_, found) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [id]}),
        );
        let user = &found["users"][0];
        assert_eq!(user["passwordHash"], "UkVEQUNURUQ=", "{id}: {found}");
        assert!(user["passwordUpdatedAt"].is_number(), "{id}: {found}");
        assert_eq!(
            user["providerUserInfo"][0]["providerId"], "password",
            "{id}: {found}"
        );
    }
}

/// A client delete with the token of an account that no longer exists is `USER_NOT_FOUND` in
/// production (sandbox recording 2026-09-23, auth-account/client/delete-effects#delete-again).
#[test]
fn deleting_again_with_a_deleted_accounts_token_is_user_not_found() {
    let s = state();
    let (_, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "gone@example.com", "password": "password123", "returnSecureToken": true}),
    );
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:delete"),
        &json!({"idToken": signed["idToken"]}),
    );
    assert_eq!(status, 200);
    let (status, again) = post(
        &s,
        &format!("{V1}/accounts:delete"),
        &json!({"idToken": signed["idToken"]}),
    );
    assert_eq!(status, 400, "{again}");
    assert_eq!(again["error"]["message"], "USER_NOT_FOUND");
}

/// A password change moves validSince to the change's second: tokens issued in an earlier
/// second are `TOKEN_EXPIRED` for lookup, update and refresh, in production (sandbox recording
/// 2026-09-23: auth-account/admin/disable#refresh-after-re-enable after an Admin password
/// update, auth-account/policy/default/client-update after client password updates).
#[test]
fn a_password_change_expires_tokens_from_earlier_seconds() {
    for admin_change in [false, true] {
        let s = strict_state();
        let (_, signed) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "pw@example.com", "password": "password123", "returnSecureToken": true}),
        );
        advance(&s, 2);
        let (status, changed) = if admin_change {
            admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:update"),
                &json!({"localId": signed["localId"], "password": "password456"}),
            )
        } else {
            let (_, fresh) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": "pw@example.com", "password": "password123", "returnSecureToken": true}),
            );
            post(
                &s,
                &format!("{V1}/accounts:update"),
                &json!({"idToken": fresh["idToken"], "password": "password456", "returnSecureToken": true}),
            )
        };
        assert_eq!(status, 200, "{changed}");
        advance(&s, 1);
        let (status, looked) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(
            (status, looked["error"]["message"].as_str()),
            (400, Some("TOKEN_EXPIRED")),
            "admin={admin_change}: {looked}"
        );
        if admin_change {
            // Observed for an Admin change only; the client-change refresh is re-recorded
            // with a second boundary before it is pinned.
            let (status, refreshed) = post(
                &s,
                "/securetoken.googleapis.com/v1/token",
                &json!({"grant_type": "refresh_token", "refresh_token": signed["refreshToken"]}),
            );
            assert_eq!(
                (status, refreshed["error"]["message"].as_str()),
                (400, Some("TOKEN_EXPIRED")),
                "{refreshed}"
            );
        }
    }
}

/// After an Admin deletes an account and creates a new one with the same UID, the old refresh
/// token is `TOKEN_EXPIRED`, not `USER_NOT_FOUND`, in production (sandbox recording 2026-09-23,
/// auth-account/admin/uid-reuse#first-refresh-token-after-reuse); without reuse it stays
/// `USER_NOT_FOUND`.
#[test]
fn a_reused_uids_old_refresh_token_is_expired() {
    let s = strict_state();
    for (id, reuse, expected) in [
        ("reused", true, "TOKEN_EXPIRED"),
        ("gone", false, "USER_NOT_FOUND"),
    ] {
        let email = format!("{id}@example.com");
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"localId": id, "email": email, "password": "password123"}),
        );
        let (_, signed) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": email, "password": "password123", "returnSecureToken": true}),
        );
        advance(&s, 2);
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:delete"),
            &json!({"localId": id}),
        );
        if reuse {
            admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts"),
                &json!({"localId": id, "email": format!("{id}-2@example.com")}),
            );
        }
        let (status, refreshed) = post(
            &s,
            "/securetoken.googleapis.com/v1/token",
            &json!({"grant_type": "refresh_token", "refresh_token": signed["refreshToken"]}),
        );
        assert_eq!(
            (status, refreshed["error"]["message"].as_str()),
            (400, Some(expected)),
            "{id}: {refreshed}"
        );
        let (status, looked) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": signed["idToken"]}),
        );
        assert_eq!(
            status, 400,
            "{id}: the old ID token never reads the new account: {looked}"
        );
    }
}

/// Proto3 JSON decoding refusals have their own body in production: a status name, an
/// `errors` entry without a domain, and a `BadRequest` field violation (sandbox recording
/// 2026-09-23).
#[test]
fn proto_decoding_refusals_carry_production_bad_request_details() {
    let s = state();
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "p1"}),
    );
    let (status, refused) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "p1", "deleteAttribute": ["NOT_A_FIELD"]}),
    );
    assert_eq!(status, 400);
    let message = "Invalid value at 'delete_attribute[0]' (type.googleapis.com/google.cloud.identitytoolkit.v1.SetAccountInfoRequest.UserAttributeName), \"NOT_A_FIELD\"";
    assert_eq!(
        refused,
        json!({"error": {
            "code": 400,
            "message": message,
            "errors": [{"message": message, "reason": "invalid"}],
            "status": "INVALID_ARGUMENT",
            "details": [{
                "@type": "type.googleapis.com/google.rpc.BadRequest",
                "fieldViolations": [{"field": "delete_attribute[0]", "description": message}],
            }],
        }})
    );
}

/// An Admin email change or email removal keeps `emailVerified` in production, and a read
/// reports it while it is true even without an address (sandbox recording 2026-09-23,
/// auth-account/admin/update).
#[test]
fn admin_email_changes_keep_email_verified() {
    let s = state();
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "ev", "email": "ev@example.com", "emailVerified": true}),
    );
    let (_, changed) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "ev", "email": "ev-new@example.com"}),
    );
    assert_eq!(changed["emailVerified"], true, "{changed}");
    let (_, cleared) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "ev", "deleteAttribute": ["EMAIL"]}),
    );
    assert_eq!(cleared["emailVerified"], true, "{cleared}");
    let (_, found) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["ev"]}),
    );
    assert_eq!(found["users"][0]["emailVerified"], true, "{found}");
    assert!(found["users"][0].get("email").is_none(), "{found}");
}

/// Production's Admin read routes are lenient where fireemu used to refuse (sandbox
/// recording 2026-09-23): lookups beyond 100 identifiers, numeric identifiers and
/// `initialEmail` answer 200; batchGet with `maxResults` 0, above 1000 or a malformed page
/// token answers 200; a POST to batchGet is a plain 404; queries accept `limit` above 500 and
/// an empty expression; and batchGet returns the password hash material.
#[test]
fn admin_read_routes_are_as_lenient_as_production() {
    let s = strict_state();
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "r1", "email": "r1@example.com", "password": "password123"}),
    );
    let lookup = |body: Value| admin(&s, "POST", &format!("{ADMIN}/accounts:lookup"), &body);
    let many: Vec<String> = (0..101).map(|i| format!("nobody-{i}")).collect();
    for body in [
        json!({"localId": many}),
        json!({"localId": [42]}),
        json!({"initialEmail": ["r1@example.com"]}),
    ] {
        let (status, found) = lookup(body.clone());
        assert_eq!(status, 200, "{body}: {found}");
    }
    let batch_get = |query: &str| {
        admin(
            &s,
            "GET",
            &format!("{ADMIN}/accounts:batchGet?{query}"),
            &Value::Null,
        )
    };
    let (status, none) = batch_get("maxResults=0");
    assert_eq!((status, none.get("users").is_none()), (200, true), "{none}");
    let (status, all) = batch_get("maxResults=1001");
    assert_eq!(status, 200, "{all}");
    let user = &all["users"][0];
    assert!(
        user["passwordHash"].is_string() && user["passwordHash"] != "UkVEQUNURUQ=",
        "{all}"
    );
    assert!(user["salt"].is_string(), "{all}");
    assert_eq!(user["version"], 0, "{all}");
    // A token is read as the user id to start after; nothing sorts after this one.
    let (status, bad) = batch_get("maxResults=2&nextPageToken=zz-not-a-token");
    assert_eq!((status, bad.get("users").is_none()), (200, true), "{bad}");
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:batchGet"),
        &json!({"maxResults": 2}),
    );
    assert_eq!(status, 404);
    for body in [json!({"limit": "501"}), json!({"expression": [{}]})] {
        let (status, queried) = admin(&s, "POST", &format!("{ADMIN}/accounts:query"), &body);
        assert_eq!(status, 200, "{body}: {queried}");
        assert_eq!(queried["recordsCount"], "1", "{body}: {queried}");
    }
}

/// Production stores a displayName carrying control characters, NUL included, on update
/// (sandbox recording 2026-09-23, `auth-account/values`).
#[test]
fn a_client_update_stores_control_characters_in_the_display_name() {
    let s = strict_state();
    let (_, signed) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "cc@example.com", "password": "password123", "returnSecureToken": true}),
    );
    for name in ["a\u{0007}b", "a\u{0000}b"] {
        let (status, updated) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": signed["idToken"], "displayName": name}),
        );
        assert_eq!(status, 200, "{updated}");
        assert_eq!(updated["displayName"], name);
    }
}

/// Password rules as the Identity Platform sandbox answered them (recording 2026-09-23):
/// lengths count UTF-16 units, an overlong password names the 4096 limit, a custom policy lists
/// every missing requirement in a fixed order, and a client password change returns only the
/// ID token unless `returnSecureToken` asks for the rest.
#[test]
fn password_rules_answer_like_production() {
    let s = strict_state();
    let (status, astral) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "astral@example.com", "password": "\u{1F600}\u{1F600}\u{1F600}", "returnSecureToken": true}),
    );
    assert_eq!(
        status, 200,
        "three astral characters are six UTF-16 units: {astral}"
    );
    let (status, long) = post(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "long@example.com", "password": "a".repeat(4097)}),
    );
    assert_eq!(status, 400);
    assert_eq!(
        long["error"]["message"],
        "PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Password cannot be longer than 4096 characters"
    );

    let (_, fresh) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "astral@example.com", "password": "\u{1F600}\u{1F600}\u{1F600}", "returnSecureToken": true}),
    );
    let (status, changed) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"idToken": fresh["idToken"], "password": "password456", "returnSecureToken": false}),
    );
    assert_eq!(status, 200, "{changed}");
    assert!(changed["idToken"].is_string(), "{changed}");
    assert!(
        changed.get("refreshToken").is_none() && changed.get("expiresIn").is_none(),
        "{changed}"
    );

    {
        let mut store = s.store.lock().unwrap();
        store.set_password_policy(fireemu_core_auth::password_policy::PasswordPolicy {
            enforcement_state: fireemu_core_auth::password_policy::EnforcementState::Enforce,
            min_length: 8,
            max_length: Some(20),
            require_uppercase: true,
            require_lowercase: true,
            require_numeric: true,
            require_non_alphanumeric: true,
            ..Default::default()
        });
    }
    for (password, missing) in [
        ("password", "Password must contain an upper case character, Password must contain a numeric character, Password must contain a non-alphanumeric character"),
        ("Passw0rd!Passw0rd!Pas", "Password may contain at most 20 characters"),
        ("passw0rd!", "Password must contain an upper case character"),
        ("Passw0rdx", "Password must contain a non-alphanumeric character"),
    ] {
        let (status, refused) = post(&s, &format!("{V1}/accounts:signUp"), &json!({"email": format!("{password}@example.com"), "password": password}));
        assert_eq!(status, 400, "{password}");
        assert_eq!(refused["error"]["message"], format!("PASSWORD_DOES_NOT_MEET_REQUIREMENTS : Missing password requirements: [{missing}]"), "{password}");
    }
}

/// providerUserInfo lists phone first, then federated identities in link order, then password
/// (sandbox recording 2026-09-23: auth-account/provider#lookup-linked, admin/create).
#[test]
fn provider_user_info_follows_production_order() {
    let s = state();
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "ord", "email": "ord@example.com", "password": "password123"}),
    );
    for (provider, raw) in [("google.com", "g-1"), ("oidc.test", "o-1")] {
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "ord", "linkProviderUserInfo": {"providerId": provider, "rawId": raw}}),
        );
    }
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "ord", "phoneNumber": "+15550000009"}),
    );
    let (_, found) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["ord"]}),
    );
    let order: Vec<&str> = found["users"][0]["providerUserInfo"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["providerId"].as_str().unwrap())
        .collect();
    assert_eq!(order, ["phone", "google.com", "oidc.test", "password"]);
}

/// Unlinking providers as production answered it (sandbox recording 2026-09-23,
/// auth-account/provider): removing the password provider keeps the address and
/// passwordUpdatedAt, removing the last provider keeps the account, an unknown provider is a
/// no-op, and link refusals carry production's codes.
#[test]
fn provider_unlinking_and_link_refusals_follow_production() {
    let s = strict_state();
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts"),
        &json!({"localId": "un", "email": "un@example.com", "password": "password123"}),
    );
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "un", "linkProviderUserInfo": {"providerId": "oidc.test", "rawId": "o-1"}}),
    );
    let (_, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "un@example.com", "password": "password123", "returnSecureToken": true}),
    );
    let unlink = |providers: Value| {
        post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"idToken": signed["idToken"], "deleteProvider": providers}),
        )
    };
    let (status, unlinked) = unlink(json!(["password"]));
    assert_eq!(status, 200, "{unlinked}");
    assert_eq!(unlinked["email"], "un@example.com");
    assert!(unlinked.get("passwordHash").is_none(), "{unlinked}");
    let (_, found) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["un"]}),
    );
    assert_eq!(found["users"][0]["email"], "un@example.com");
    assert!(
        found["users"][0]["passwordUpdatedAt"].is_number(),
        "{found}"
    );
    let (status, last) = unlink(json!(["oidc.test"]));
    assert_eq!(status, 200, "{last}");
    assert!(last.get("providerUserInfo").is_none(), "{last}");
    let (status, unknown) = unlink(json!(["facebook.com"]));
    assert_eq!(status, 200, "{unknown}");

    let link = |identity: Value| {
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "un", "linkProviderUserInfo": identity}),
        )
        .1["error"]["message"]
            .clone()
    };
    assert_eq!(
        link(json!({"providerId": "google.com"})),
        "MISSING_IDENTIFIER : providerId & rawId are both required for provider linking"
    );
    assert_eq!(
        link(json!({"providerId": "password", "rawId": "x"})),
        "INVALID_PROVIDER_ID"
    );
}

/// batchCreate as production answered it (sandbox recording 2026-09-23,
/// auth-account/admin/import): rows upsert by localId (a later duplicate in the request wins,
/// an existing account is replaced without an error), an address owned by another account is
/// accepted, sanityCheck refuses an address repeated inside the request, and an imported row
/// always records emailVerified.
#[test]
fn batch_create_upserts_and_checks_duplicates_like_production() {
    let s = strict_state();
    let import = |body: Value| admin(&s, "POST", &format!("{ADMIN}/accounts:batchCreate"), &body);
    let lookup = |id: &str| {
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [id]}),
        )
        .1["users"][0]
            .clone()
    };
    let (status, body) = import(
        json!({"users": [{"localId": "i1", "email": "i1@example.com"}, {"localId": "i2", "phoneNumber": "+15550000021"}]}),
    );
    assert_eq!((status, body.get("error").is_none()), (200, true), "{body}");
    assert_eq!(lookup("i2")["emailVerified"], false);
    let (status, body) =
        import(json!({"users": [{"localId": "i1", "email": "i1-new@example.com"}]}));
    assert_eq!((status, body.get("error").is_none()), (200, true), "{body}");
    assert_eq!(lookup("i1")["email"], "i1-new@example.com");
    let (status, body) = import(
        json!({"users": [{"localId": "i6", "email": "i6@example.com"}, {"localId": "i6", "email": "i6b@example.com"}]}),
    );
    assert_eq!((status, body.get("error").is_none()), (200, true), "{body}");
    assert_eq!(lookup("i6")["email"], "i6b@example.com");
    let (status, body) =
        import(json!({"users": [{"localId": "i7", "email": "i1-new@example.com"}]}));
    assert_eq!((status, body.get("error").is_none()), (200, true), "{body}");
    assert_eq!(lookup("i7")["email"], "i1-new@example.com");
    let (status, body) = import(
        json!({"sanityCheck": true, "users": [{"localId": "i8", "email": "i8@example.com"}, {"localId": "i9", "email": "i8@example.com"}]}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["message"], "DUPLICATE_EMAIL : i8@example.com");
    assert!(lookup("i8").is_null());
}

/// The project config carries its authorized domains: the domains a new Firebase project
/// starts with, replaced by a masked PATCH and read back in production's shape (the sandbox
/// answers with its two Firebase Hosting domains, AUTH-ACTION scope decision E6).
#[test]
fn authorized_domains_round_trip_through_the_admin_config() {
    let s = state();
    let (status, read) = admin(&s, "GET", PROJECT_CONFIG, &Value::Null);
    assert_eq!(status, 200, "{read}");
    assert_eq!(
        read["authorizedDomains"],
        json!(["localhost", "demo-app.firebaseapp.com", "demo-app.web.app"])
    );
    let domains = json!(["demo-app.firebaseapp.com", "demo-app.web.app"]);
    let (status, patched) = admin(
        &s,
        "PATCH",
        &format!("{PROJECT_CONFIG}?updateMask=authorizedDomains"),
        &json!({"authorizedDomains": domains}),
    );
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["authorizedDomains"], domains);
    let (_, read) = admin(&s, "GET", PROJECT_CONFIG, &Value::Null);
    assert_eq!(read["authorizedDomains"], domains);
    for invalid in [json!([1]), json!("demo-app.web.app"), json!([""])] {
        let (status, refused) = admin(
            &s,
            "PATCH",
            &format!("{PROJECT_CONFIG}?updateMask=authorizedDomains"),
            &json!({"authorizedDomains": invalid}),
        );
        assert_eq!(
            (status, refused["error"]["message"].as_str()),
            (400, Some("INVALID_ARGUMENT")),
            "{invalid}"
        );
    }
    let (_, read) = admin(&s, "GET", PROJECT_CONFIG, &Value::Null);
    assert_eq!(read["authorizedDomains"], domains);
}

/// Strict: a continue URL whose host is not an authorized domain is refused before a code is
/// made (sandbox exploration 2026-09-24, to be recorded in auth-action/generate/admin). The
/// emulator profile keeps the official emulator's answer, which does not check the domain.
#[test]
fn strict_link_generation_refuses_a_continue_url_outside_the_authorized_domains() {
    for (s, strict) in [(strict_state(), true), (state(), false)] {
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"email": "domains@example.com", "password": "password1"}),
        );
        assert_eq!(status, 200);
        let generate = |url: &str| {
            admin(
                &s,
                "POST",
                &format!("{ADMIN}/accounts:sendOobCode"),
                &json!({"requestType": "PASSWORD_RESET", "email": "domains@example.com", "returnOobLink": true, "continueUrl": url}),
            )
        };
        let (status, body) = generate("https://demo-app.firebaseapp.com/done?x=1");
        assert_eq!(status, 200, "{body}");
        let (status, body) = generate("http://localhost:5000/done");
        assert_eq!(status, 200, "{body}");
        let (status, body) = generate("https://unauthorized.example.com/done");
        if strict {
            assert_eq!(
                (status, body["error"]["message"].as_str()),
                (
                    400,
                    Some("UNAUTHORIZED_DOMAIN : Domain not allowlisted by project")
                ),
            );
            // A refused request makes no code; the second link retired the first.
            assert_eq!(s.store.lock().unwrap().oob_codes().len(), 1);
        } else {
            assert_eq!(status, 200, "{body}");
        }
    }
}

/// Strict: an Admin email-link generator is refused while password sign-in is required
/// (sandbox, 2026-09-24, `auth-action/generate/admin#sign-in-link-password-required`). The
/// official emulator always reports email links as enabled (firebase-tools `state.js`
/// `enableEmailLinkSignin`), so the emulator profile generates the link, adding no rejection.
#[test]
fn admin_email_link_generation_needs_email_link_sign_in_in_strict() {
    for (strict, s) in [(true, strict_state()), (false, state())] {
        let (status, body) = patch_sign_in(
            &s,
            "signIn.email.passwordRequired",
            &json!({"signIn": {"email": {"enabled": true, "passwordRequired": true}}}),
        );
        assert_eq!(status, 200, "{body}");
        let (status, answer) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:sendOobCode"),
            &json!({"requestType": "EMAIL_SIGNIN", "email": "link@example.com", "returnOobLink": true, "continueUrl": "https://demo-app.firebaseapp.com/finish", "canHandleCodeInApp": true}),
        );
        if strict {
            assert_eq!(
                (status, answer["error"]["message"].as_str()),
                (400, Some("OPERATION_NOT_ALLOWED"))
            );
            assert!(s.store.lock().unwrap().oob_codes().is_empty());
        } else {
            assert_eq!(status, 200, "{answer}");
            assert!(answer["oobCode"].is_string(), "{answer}");
            assert_eq!(s.store.lock().unwrap().oob_codes().len(), 1);
        }
    }
}

/// An email link used with another address names the mismatch (sandbox exploration
/// 2026-09-24; the official emulator answers the same) and leaves the code usable.
#[test]
fn an_email_link_for_another_address_is_refused_as_a_mismatch() {
    let s = state();
    let (status, sent) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "link@example.com", "returnOobLink": true, "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (status, refused) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"oobCode": sent["oobCode"], "email": "other@example.com"}),
    );
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (
            400,
            Some("INVALID_EMAIL : The email provided does not match the sign-in email address.")
        )
    );
    let (status, signed) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"oobCode": sent["oobCode"], "email": "link@example.com"}),
    );
    assert_eq!(status, 200, "{signed}");
}

// ---- AUTH-ACTION (sandbox recording 2026-09-24, conformance/auth-action-production.json) ----

fn with_email_privacy(s: &AuthState) {
    let (status, body) = admin(
        s,
        "PATCH",
        &format!("{PROJECT_CONFIG}?updateMask=emailPrivacyConfig"),
        &json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}}),
    );
    assert_eq!(status, 200, "{body}");
}

fn email_links_on(s: &AuthState) {
    let (status, body) = patch_sign_in(
        s,
        "signIn.email.passwordRequired",
        &json!({"signIn": {"email": {"passwordRequired": false}}}),
    );
    assert_eq!(status, 200, "{body}");
}

fn create(s: &AuthState, body: &Value) -> Value {
    let (status, created) = admin(s, "POST", &format!("{ADMIN}/accounts"), body);
    assert_eq!(status, 200, "{created}");
    created
}

fn oob(s: &AuthState, body: &Value) -> (u16, Value) {
    let mut body = body.clone();
    body["returnOobLink"] = json!(true);
    admin(s, "POST", &format!("{ADMIN}/accounts:sendOobCode"), &body)
}

fn message(body: &Value) -> Option<&str> {
    body["error"]["message"].as_str()
}

fn password_sign_in(s: &AuthState, email: &str, password: &str) -> (u16, Value) {
    post(
        s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": password, "returnSecureToken": true}),
    )
}

/// Strict: the generation answers production gave that the official emulator does not.
#[test]
#[allow(clippy::too_many_lines)]
fn strict_link_generation_follows_the_sandbox() {
    let s = strict_state();
    with_email_privacy(&s);
    create(
        &s,
        &json!({"email": "a@example.com", "password": "password123"}),
    );
    create(
        &s,
        &json!({"email": "d@example.com", "password": "password123", "disabled": true}),
    );
    let reset = |extra: Value| {
        let mut body = json!({"requestType": "PASSWORD_RESET", "email": "a@example.com"});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        oob(&s, &body)
    };
    for url in ["not a url", ""] {
        let (status, body) = reset(json!({"continueUrl": url}));
        assert_eq!(
            (status, message(&body)),
            (
                400,
                Some("INVALID_CONTINUE_URI : Missing domain in continue url")
            ),
            "{url}"
        );
    }
    let (status, body) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "not-an-email"}),
    );
    assert_eq!((status, message(&body)), (400, Some("INVALID_EMAIL")));
    let (status, body) = oob(
        &s,
        &json!({"requestType": "NOT_A_REQUEST_TYPE", "email": "a@example.com"}),
    );
    let text = "Invalid value at 'req_type' (type.googleapis.com/google.cloud.identitytoolkit.v1.OobReqType), \"NOT_A_REQUEST_TYPE\"";
    assert_eq!((status, message(&body)), (400, Some(text)));
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        body["error"]["details"][0]["fieldViolations"][0]["field"],
        "req_type"
    );
    let (status, body) = oob(
        &s,
        &json!({"requestType": "OOB_REQ_TYPE_UNSPECIFIED", "email": "a@example.com"}),
    );
    assert_eq!((status, message(&body)), (400, Some("INVALID_REQ_TYPE")));
    // Improved email privacy hides a taken or unchanged new address.
    for new_email in ["d@example.com", "a@example.com"] {
        let (status, body) = oob(
            &s,
            &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "a@example.com", "newEmail": new_email}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body,
            json!({"kind": "identitytoolkit#GetOobConfirmationCodeResponse", "email": "a@example.com"})
        );
    }
    let (status, body) = oob(
        &s,
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "a@example.com", "newEmail": "not-an-email"}),
    );
    assert_eq!((status, message(&body)), (400, Some("INVALID_NEW_EMAIL")));
    // The Admin generator of an address change reads the address, never an ID token.
    let (_, signed) = password_sign_in(&s, "a@example.com", "password123");
    let (status, body) = oob(
        &s,
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "idToken": signed["idToken"], "newEmail": "a-new@example.com"}),
    );
    assert_eq!((status, message(&body)), (400, Some("MISSING_EMAIL")));
    email_links_on(&s);
    let (status, body) = oob(
        &s,
        &json!({"requestType": "EMAIL_SIGNIN", "email": "n@example.com"}),
    );
    assert_eq!(
        (status, message(&body)),
        (400, Some("MISSING_CONTINUE_URI"))
    );
    let (status, body) = oob(
        &s,
        &json!({"requestType": "EMAIL_SIGNIN", "email": "d@example.com", "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
    );
    assert_eq!((status, message(&body)), (400, Some("USER_DISABLED")));
    // An unknown address is answered before its continue URL is looked at.
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "nobody@example.com", "continueUrl": "https://unauthorized.example.com/x"}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(s.store.lock().unwrap().oob_codes().is_empty());
}

/// Both profiles: generation answers production and the official emulator share.
#[test]
fn link_generation_errors_follow_the_sandbox_and_the_official_emulator() {
    for (s, strict) in [(strict_state(), true), (state(), false)] {
        with_email_privacy(&s);
        for request_type in ["VERIFY_EMAIL", "VERIFY_AND_CHANGE_EMAIL"] {
            let (status, body) = oob(
                &s,
                &json!({"requestType": request_type, "email": "nobody@example.com", "newEmail": "x@example.com"}),
            );
            assert_eq!(
                (status, message(&body)),
                (400, Some("USER_NOT_FOUND")),
                "{request_type}"
            );
        }
        let (status, body) = oob(&s, &json!({"requestType": "VERIFY_EMAIL"}));
        assert_eq!((status, message(&body)), (400, Some("MISSING_EMAIL")));
        create(
            &s,
            &json!({"localId": "phone-only", "phoneNumber": "+16505550101"}),
        );
        let code = s.store.lock().unwrap().send_verification_code(
            "+16505550101",
            fireemu_core_auth::store::VerificationPurpose::SignIn,
            LogicalInstant::from_unix_seconds(1_788_004_860),
        );
        let session = code.unwrap();
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signInWithPhoneNumber"),
            &json!({"sessionInfo": session.session_info, "code": session.code}),
        );
        assert_eq!(status, 200, "{signed}");
        assert!(
            token_parts(&signed["idToken"])
                .1
                .get("provider_id")
                .is_none(),
            "{signed}"
        );
        let (status, body) = oob(
            &s,
            &json!({"requestType": "VERIFY_EMAIL", "idToken": signed["idToken"]}),
        );
        assert_eq!((status, message(&body)), (400, Some("MISSING_EMAIL")));
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:sendOobCode"),
            &json!({"requestType": "PASSWORD_RESET", "email": "nobody@example.com", "returnOobLink": true}),
        );
        assert_eq!(
            (status, message(&body)),
            (400, Some("INSUFFICIENT_PERMISSION"))
        );
        if !strict {
            let (status, body) = oob(
                &s,
                &json!({"requestType": "EMAIL_SIGNIN", "email": "n@example.com", "continueUrl": "not a url"}),
            );
            assert_eq!(
                (status, message(&body)),
                (400, Some("INVALID_CONTINUE_URI : ((expected an absolute URI with valid scheme and host))"))
            );
        }
    }
}

/// Strict: a newer code of the same type for the same address retires the older one. The
/// emulator profile keeps every code, as the official emulator does.
#[test]
fn strict_newer_codes_retire_older_ones() {
    for (s, strict) in [(strict_state(), true), (state(), false)] {
        create(
            &s,
            &json!({"email": "a@example.com", "password": "password123"}),
        );
        email_links_on(&s);
        for body in [
            json!({"requestType": "PASSWORD_RESET", "email": "a@example.com"}),
            json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "a@example.com", "newEmail": "a-first@example.com"}),
            json!({"requestType": "EMAIL_SIGNIN", "email": "q@example.com", "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
        ] {
            let (_, first) = oob(&s, &body);
            let mut second_body = body.clone();
            if second_body.get("newEmail").is_some() {
                second_body["newEmail"] = json!("a-second@example.com");
            }
            let (_, second) = oob(&s, &second_body);
            let check = |code: &Value| {
                post(
                    &s,
                    &format!("{V1}/accounts:resetPassword"),
                    &json!({"oobCode": code}),
                )
            };
            let (status, _) = check(&first["oobCode"]);
            assert_eq!(status, if strict { 400 } else { 200 }, "{body}");
            let (status, _) = check(&second["oobCode"]);
            assert_eq!(status, 200, "{body}");
        }
    }
}

fn check_code(s: &AuthState, code: &Value) -> (u16, Value) {
    post(
        s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code}),
    )
}

fn reset_with(s: &AuthState, code: &Value, password: &str) -> (u16, Value) {
    post(
        s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": code, "newPassword": password}),
    )
}

fn refresh_with(s: &AuthState, token: &Value) -> (u16, Value) {
    post(
        s,
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": token}),
    )
}

/// Strict: password reset answers of the sandbox recording.
#[test]
#[allow(clippy::too_many_lines)]
fn strict_password_reset_follows_the_sandbox() {
    let s = strict_state();
    create(
        &s,
        &json!({"email": "a@example.com", "password": "password123"}),
    );
    let (_, before) = password_sign_in(&s, "a@example.com", "password123");
    advance(&s, 2);
    let (_, link) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "a@example.com"}),
    );
    let (status, body) = reset_with(&s, &link["oobCode"], "");
    assert_eq!((status, message(&body)), (400, Some("WEAK_PASSWORD")));
    let (status, body) = reset_with(&s, &link["oobCode"], "password456");
    assert_eq!(status, 200, "{body}");
    // The reset revokes the sessions before it; the refresh token is refused, not forgotten.
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": before["idToken"]}),
    );
    assert_eq!((status, message(&body)), (400, Some("TOKEN_EXPIRED")));
    let (status, body) = refresh_with(&s, &before["refreshToken"]);
    assert_eq!((status, message(&body)), (400, Some("TOKEN_EXPIRED")));

    // The code names an address: once the account has another, the reset finds nobody.
    create(
        &s,
        &json!({"localId": "e", "email": "e@example.com", "password": "password123"}),
    );
    let (_, link) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "e@example.com"}),
    );
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "e", "email": "e-moved@example.com"}),
    );
    assert_eq!(status, 200);
    let (status, body) = check_code(&s, &link["oobCode"]);
    assert_eq!(
        (status, body["email"].as_str()),
        (200, Some("e@example.com"))
    );
    let (status, body) = reset_with(&s, &link["oobCode"], "password456");
    assert_eq!((status, message(&body)), (400, Some("USER_NOT_FOUND")));

    // Deleting an account voids its codes.
    create(
        &s,
        &json!({"localId": "g", "email": "g@example.com", "password": "password123"}),
    );
    let (_, link) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "g@example.com"}),
    );
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:delete"),
        &json!({"localId": "g"}),
    );
    assert_eq!(status, 200);
    let (status, body) = check_code(&s, &link["oobCode"]);
    assert_eq!((status, message(&body)), (400, Some("INVALID_OOB_CODE")));
    let (status, body) = reset_with(&s, &link["oobCode"], "password456");
    assert_eq!((status, message(&body)), (400, Some("INVALID_OOB_CODE")));

    // A sign-in link offered with a new password is only inspected.
    email_links_on(&s);
    let (_, link) = oob(
        &s,
        &json!({"requestType": "EMAIL_SIGNIN", "email": "z@example.com", "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
    );
    let (status, body) = reset_with(&s, &link["oobCode"], "password456");
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body,
        json!({"kind": "identitytoolkit#ResetPasswordResponse", "requestType": "EMAIL_SIGNIN"})
    );
    assert_eq!(check_code(&s, &link["oobCode"]).0, 200);
}

/// The emulator profile inspects a code offered with an empty password, as the official
/// emulator does.
#[test]
fn an_empty_new_password_only_inspects_the_code_in_the_emulator_profile() {
    let s = state();
    create(
        &s,
        &json!({"email": "a@example.com", "password": "password123"}),
    );
    let (_, link) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "a@example.com"}),
    );
    let (status, body) = reset_with(&s, &link["oobCode"], "");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["requestType"], "PASSWORD_RESET");
    assert_eq!(reset_with(&s, &link["oobCode"], "password456").0, 200);
}

/// Strict: applying verification and change codes as the sandbox answered.
#[test]
#[allow(clippy::too_many_lines)]
fn strict_action_code_application_follows_the_sandbox() {
    let s = strict_state();
    let apply = |body: Value| post(&s, &format!("{V1}/accounts:update"), &body);
    // A verification code of an address that no longer has an account.
    create(
        &s,
        &json!({"localId": "vb", "email": "vb@example.com", "password": "password123"}),
    );
    let (_, link) = oob(
        &s,
        &json!({"requestType": "VERIFY_EMAIL", "email": "vb@example.com"}),
    );
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "vb", "email": "vb-moved@example.com"}),
    );
    let (status, body) = apply(json!({"oobCode": link["oobCode"]}));
    assert_eq!((status, message(&body)), (400, Some("EMAIL_NOT_FOUND")));
    // Disabled accounts refuse both kinds of code.
    create(
        &s,
        &json!({"localId": "vc", "email": "vc@example.com", "password": "password123"}),
    );
    let (_, verify) = oob(
        &s,
        &json!({"requestType": "VERIFY_EMAIL", "email": "vc@example.com"}),
    );
    let (_, change) = oob(
        &s,
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "vc@example.com", "newEmail": "vc-new@example.com"}),
    );
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "vc", "disableUser": true}),
    );
    for code in [&verify["oobCode"], &change["oobCode"]] {
        let (status, body) = apply(json!({"oobCode": code}));
        assert_eq!((status, message(&body)), (400, Some("USER_DISABLED")));
    }
    // With an ID token the request is that account's own update: the code is not applied.
    create(
        &s,
        &json!({"localId": "oa", "email": "oa@example.com", "password": "password123"}),
    );
    create(
        &s,
        &json!({"localId": "ob", "email": "ob@example.com", "password": "password123"}),
    );
    let (_, ob) = password_sign_in(&s, "ob@example.com", "password123");
    let (_, change) = oob(
        &s,
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "oa@example.com", "newEmail": "oa-new@example.com"}),
    );
    let (status, body) = apply(json!({"oobCode": change["oobCode"], "idToken": ob["idToken"]}));
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        (body["localId"].as_str(), body["email"].as_str()),
        (Some("ob"), Some("ob@example.com"))
    );
    assert_eq!(
        s.store
            .lock()
            .unwrap()
            .user_by_email("oa@example.com")
            .map(|u| u.local_id.as_str().to_owned()),
        Some("oa".to_owned())
    );
    let (status, body) = apply(json!({"oobCode": change["oobCode"], "idToken": "not-a-token"}));
    assert_eq!((status, message(&body)), (400, Some("INVALID_ID_TOKEN")));
    // An applied change answers with the new address, records the replaced one and revokes
    // the sessions before it.
    let (_, before) = password_sign_in(&s, "oa@example.com", "password123");
    advance(&s, 2);
    let (status, body) = apply(json!({"oobCode": change["oobCode"]}));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["newEmail"], "oa-new@example.com");
    assert_eq!(body["email"], "oa-new@example.com");
    assert_eq!(body["passwordHash"], "UkVEQUNURUQ=");
    assert_eq!(
        body["providerUserInfo"][0]["federatedId"],
        "oa-new@example.com"
    );
    let (_, users) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": ["oa"]}),
    );
    assert_eq!(users["users"][0]["initialEmail"], "oa@example.com");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": before["idToken"]}),
    );
    assert_eq!((status, message(&body)), (400, Some("TOKEN_EXPIRED")));
    let (status, body) = refresh_with(&s, &before["refreshToken"]);
    assert_eq!((status, message(&body)), (400, Some("TOKEN_EXPIRED")));
    // An applied verification answers with the account's providers and redacted hash.
    create(
        &s,
        &json!({"localId": "va", "email": "va@example.com", "password": "password123"}),
    );
    let (_, verify) = oob(
        &s,
        &json!({"requestType": "VERIFY_EMAIL", "email": "va@example.com"}),
    );
    let (status, body) = apply(json!({"oobCode": verify["oobCode"]}));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["passwordHash"], "UkVEQUNURUQ=");
    assert_eq!(body["providerUserInfo"][0]["providerId"], "password");
}

/// Email-link sign-in answers of the sandbox recording.
#[test]
#[allow(clippy::too_many_lines)]
fn email_link_sign_in_follows_the_sandbox() {
    for (s, strict) in [(strict_state(), true), (state(), false)] {
        email_links_on(&s);
        with_email_privacy(&s);
        let link_for = |email: &str| {
            let (status, link) = oob(
                &s,
                &json!({"requestType": "EMAIL_SIGNIN", "email": email, "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
            );
            assert_eq!(status, 200, "{link}");
            link
        };
        let sign_in = |body: Value| post(&s, &format!("{V1}/accounts:signInWithEmailLink"), &body);
        let link = link_for("n@example.com");
        let (status, body) = sign_in(json!({"oobCode": link["oobCode"]}));
        assert_eq!((status, message(&body)), (400, Some("MISSING_EMAIL")));
        let (status, body) = sign_in(json!({"oobCode": link["oobCode"], "email": "n@example.com"}));
        assert_eq!(status, 200, "{body}");
        let (_, users) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"email": ["n@example.com"]}),
        );
        assert_eq!(users["users"][0]["emailLinkSignin"], true, "{users}");
        assert!(users["users"][0]["validSince"].is_string(), "{users}");
        // Linking the address to an anonymous session makes it a password-provider session.
        let (_, anonymous) = post(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"returnSecureToken": true}),
        );
        let link = link_for("anon@example.com");
        let (status, body) = sign_in(
            json!({"oobCode": link["oobCode"], "email": "anon@example.com", "idToken": anonymous["idToken"]}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["kind"], "identitytoolkit#EmailLinkSigninResponse");
        assert_eq!(body["localId"], anonymous["localId"]);
        let claims = token_parts(&body["idToken"]).1;
        assert_eq!(claims["firebase"]["sign_in_provider"], "password");
        assert!(claims.get("provider_id").is_none(), "{claims}");
        let (_, users) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [anonymous["localId"]]}),
        );
        assert_eq!(
            users["users"][0]["providerUserInfo"][0]["providerId"], "password",
            "{users}"
        );
        assert_eq!(users["users"][0]["emailLinkSignin"], true);
        // An existing account whose address was never verified loses its password.
        create(
            &s,
            &json!({"localId": "p", "email": "p@example.com", "password": "password123"}),
        );
        let link = link_for("p@example.com");
        let (status, body) = sign_in(json!({"oobCode": link["oobCode"], "email": "p@example.com"}));
        assert_eq!(status, 200, "{body}");
        let (status, body) = password_sign_in(&s, "p@example.com", "password123");
        if strict {
            assert_eq!(
                (status, message(&body)),
                (400, Some("INVALID_LOGIN_CREDENTIALS"))
            );
        } else {
            assert_eq!(status, 200, "{body}");
        }
        // Strict honours a legacy ID token for the link, as production does.
        if strict {
            create(
                &s,
                &json!({"localId": "lr", "email": "lr@example.com", "password": "password123"}),
            );
            let (_, legacy) = post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": "lr@example.com", "password": "password123"}),
            );
            let link = link_for("lr-legacy@example.com");
            let (status, body) = sign_in(
                json!({"oobCode": link["oobCode"], "email": "lr-legacy@example.com", "idToken": legacy["idToken"]}),
            );
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["localId"], "lr");
        }
    }
}

/// Strict: a password reset code lives an hour and is then refused as expired; the other kinds
/// outlive the hour (sandbox recording 2026-09-24, auth-action/expiry). The emulator profile
/// keeps its one-hour local policy for every kind.
#[test]
fn strict_action_codes_follow_the_sandbox_lifetimes() {
    for (s, strict) in [(strict_state(), true), (state(), false)] {
        email_links_on(&s);
        create(
            &s,
            &json!({"localId": "a", "email": "a@example.com", "password": "password123"}),
        );
        let (_, verify) = oob(
            &s,
            &json!({"requestType": "VERIFY_EMAIL", "email": "a@example.com"}),
        );
        let (_, link) = oob(
            &s,
            &json!({"requestType": "EMAIL_SIGNIN", "email": "n@example.com", "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
        );
        let (_, reset) = oob(
            &s,
            &json!({"requestType": "PASSWORD_RESET", "email": "a@example.com"}),
        );
        advance(&s, 3_599);
        assert_eq!(check_code(&s, &reset["oobCode"]).0, 200);
        advance(&s, 2);
        let expired = if strict {
            "EXPIRED_OOB_CODE"
        } else {
            "INVALID_OOB_CODE"
        };
        let (status, body) = check_code(&s, &reset["oobCode"]);
        assert_eq!((status, message(&body)), (400, Some(expired)));
        let (status, body) = reset_with(&s, &reset["oobCode"], "password456");
        assert_eq!((status, message(&body)), (400, Some(expired)));
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"oobCode": verify["oobCode"]}),
        );
        assert_eq!(status, if strict { 200 } else { 400 }, "{body}");
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:signInWithEmailLink"),
            &json!({"oobCode": link["oobCode"], "email": "n@example.com"}),
        );
        assert_eq!(status, if strict { 200 } else { 400 }, "{body}");
    }
}

/// Deleting an account voids its codes in strict only, through each delete route; the
/// emulator profile keeps them, as the official emulator does.
#[test]
fn only_strict_deletion_voids_an_accounts_codes() {
    for strict in [true, false] {
        let s = if strict { strict_state() } else { state() };
        for (id, route) in [("client", "client"), ("batch", "batch")] {
            let email = format!("{id}@example.com");
            create(
                &s,
                &json!({"localId": id, "email": email, "password": "password123"}),
            );
            let (_, link) = oob(
                &s,
                &json!({"requestType": "PASSWORD_RESET", "email": email}),
            );
            if route == "client" {
                let (_, signed) = password_sign_in(&s, &email, "password123");
                let (status, body) = post(
                    &s,
                    &format!("{V1}/accounts:delete"),
                    &json!({"idToken": signed["idToken"]}),
                );
                assert_eq!(status, 200, "{body}");
            } else {
                let (status, body) = admin(
                    &s,
                    "POST",
                    &format!("{ADMIN}/accounts:batchDelete"),
                    &json!({"localIds": [id], "force": true}),
                );
                assert_eq!(status, 200, "{body}");
            }
            let (status, _) = check_code(&s, &link["oobCode"]);
            assert_eq!(
                status,
                if strict { 400 } else { 200 },
                "{route} strict={strict}"
            );
        }
    }
}

/// The emulator profile keeps the official emulator's answers to request types.
#[test]
fn the_emulator_profile_keeps_the_official_request_type_answers() {
    let s = state();
    create(
        &s,
        &json!({"email": "a@example.com", "password": "password123"}),
    );
    let (status, body) = oob(
        &s,
        &json!({"requestType": "OOB_REQ_TYPE_UNSPECIFIED", "email": "a@example.com"}),
    );
    assert_eq!((status, message(&body)), (400, Some("MISSING_REQ_TYPE")));
    let (status, _) = oob(
        &s,
        &json!({"requestType": "NOT_A_REQUEST_TYPE", "email": "a@example.com"}),
    );
    assert_eq!(status, 501);
}

/// Without an update mask, a present list replaces the authorized domains and a null one is
/// no field at all.
#[test]
fn an_unmasked_config_patch_reads_authorized_domains_by_presence() {
    let s = state();
    let (status, _) = admin(
        &s,
        "PATCH",
        PROJECT_CONFIG,
        &json!({"authorizedDomains": ["demo-app.web.app"]}),
    );
    assert_eq!(status, 200);
    let (status, body) = admin(
        &s,
        "PATCH",
        PROJECT_CONFIG,
        &json!({"authorizedDomains": null, "signIn": {"anonymous": {"enabled": true}}}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["authorizedDomains"], json!(["demo-app.web.app"]));
}

/// An Admin-created account with neither address nor number stays anonymous: a custom-token
/// session of it carries the anonymous `provider_id`, a phone-only one does not.
#[test]
fn an_admin_created_account_is_anonymous_only_without_a_number() {
    let s = state();
    create(&s, &json!({"localId": "empty"}));
    create(
        &s,
        &json!({"localId": "phone", "phoneNumber": "+16505550102"}),
    );
    for (uid, anonymous) in [("empty", true), ("phone", false)] {
        let (status, signed) = post(
            &s,
            &format!("{V1}/accounts:signInWithCustomToken"),
            &json!({"token": json!({"uid": uid}).to_string(), "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{signed}");
        let claims = token_parts(&signed["idToken"]).1;
        assert_eq!(
            claims.get("provider_id").is_some(),
            anonymous,
            "{uid}: {claims}"
        );
    }
}

/// A change code keeps its account when the account's address changed before it is applied
/// (sandbox recording 2026-09-24, change-email#apply-c-after-admin-change); a verification
/// code finds no owner of its address then: production's `EMAIL_NOT_FOUND`, or the official
/// emulator's `INVALID_OOB_CODE` (`setAccountInfo` looks the address up).
#[test]
fn codes_applied_after_an_administrative_address_change() {
    for strict in [true, false] {
        let s = if strict { strict_state() } else { state() };
        create(
            &s,
            &json!({"localId": "c", "email": "c@example.com", "password": "password123"}),
        );
        let (_, change) = oob(
            &s,
            &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "c@example.com", "newEmail": "c-new@example.com"}),
        );
        let (_, verify) = oob(
            &s,
            &json!({"requestType": "VERIFY_EMAIL", "email": "c@example.com"}),
        );
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "c", "email": "c-admin@example.com"}),
        );
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"oobCode": verify["oobCode"]}),
        );
        let refusal = if strict {
            "EMAIL_NOT_FOUND"
        } else {
            "INVALID_OOB_CODE"
        };
        assert_eq!((status, message(&body)), (400, Some(refusal)));
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"oobCode": change["oobCode"]}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["email"], "c-new@example.com");
        let (_, users) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": ["c"]}),
        );
        if strict {
            assert_eq!(users["users"][0]["initialEmail"], "c-admin@example.com");
        }
    }
}

/// The email-link route checks a code's kind before its address, as the official emulator
/// does: another kind of code for another address is still `INVALID_OOB_CODE`.
#[test]
fn an_email_link_checks_the_code_kind_before_the_address() {
    let s = state();
    email_links_on(&s);
    create(
        &s,
        &json!({"email": "p@example.com", "password": "password123"}),
    );
    let (_, reset) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "p@example.com"}),
    );
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"oobCode": reset["oobCode"], "email": "other@example.com"}),
    );
    assert_eq!((status, message(&body)), (400, Some("INVALID_OOB_CODE")));
}

/// Strict removes the password only of an account whose address was never verified; a verified
/// account keeps it (inferred: production was observed only for an unverified address).
#[test]
fn strict_email_link_keeps_the_password_of_a_verified_address() {
    let s = strict_state();
    email_links_on(&s);
    with_email_privacy(&s);
    create(
        &s,
        &json!({"email": "v@example.com", "password": "password123", "emailVerified": true}),
    );
    let (_, link) = oob(
        &s,
        &json!({"requestType": "EMAIL_SIGNIN", "email": "v@example.com", "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
    );
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"oobCode": link["oobCode"], "email": "v@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(password_sign_in(&s, "v@example.com", "password123").0, 200);
}

/// Strict: a reset refused for a disabled account spends its code, while a refused
/// verification keeps its own (sandbox recording 2026-09-24, password-reset and
/// verify-email#check-*-after-refused-*).
#[test]
fn strict_a_refused_reset_spends_its_code_and_a_refused_verification_does_not() {
    let s = strict_state();
    create(
        &s,
        &json!({"localId": "f", "email": "f@example.com", "password": "password123"}),
    );
    let (_, reset) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "f@example.com"}),
    );
    let (_, verify) = oob(
        &s,
        &json!({"requestType": "VERIFY_EMAIL", "email": "f@example.com"}),
    );
    admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": "f", "disableUser": true}),
    );
    let (status, body) = reset_with(&s, &reset["oobCode"], "password456");
    assert_eq!((status, message(&body)), (400, Some("USER_DISABLED")));
    let (status, body) = check_code(&s, &reset["oobCode"]);
    assert_eq!((status, message(&body)), (400, Some("INVALID_OOB_CODE")));
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": verify["oobCode"]}),
    );
    assert_eq!((status, message(&body)), (400, Some("USER_DISABLED")));
    assert_eq!(check_code(&s, &verify["oobCode"]).0, 200);
}

/// Strict: an applied email change voids the old address's verification code (sandbox
/// recording 2026-09-24, change-email#apply-old-verify-ch).
#[test]
fn strict_an_applied_change_voids_the_old_addresses_verification() {
    let s = strict_state();
    create(
        &s,
        &json!({"localId": "ch", "email": "ch@example.com", "password": "password123"}),
    );
    let (_, verify) = oob(
        &s,
        &json!({"requestType": "VERIFY_EMAIL", "email": "ch@example.com"}),
    );
    let (_, change) = oob(
        &s,
        &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "ch@example.com", "newEmail": "ch-new@example.com"}),
    );
    let (status, _) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": change["oobCode"]}),
    );
    assert_eq!(status, 200);
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:update"),
        &json!({"oobCode": verify["oobCode"]}),
    );
    assert_eq!((status, message(&body)), (400, Some("INVALID_OOB_CODE")));
}

/// Strict: an account whose password an email link removed is an email-link account: its
/// sessions carry no anonymous `provider_id` (sandbox recording 2026-09-24,
/// email-link/session#sign-in-p).
#[test]
fn strict_an_email_link_account_without_a_password_is_not_anonymous() {
    let s = strict_state();
    email_links_on(&s);
    create(
        &s,
        &json!({"email": "p@example.com", "password": "password123"}),
    );
    let (_, link) = oob(
        &s,
        &json!({"requestType": "EMAIL_SIGNIN", "email": "p@example.com", "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
    );
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithEmailLink"),
        &json!({"oobCode": link["oobCode"], "email": "p@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    let claims = token_parts(&body["idToken"]).1;
    assert!(claims.get("provider_id").is_none(), "{claims}");
    let (_, refreshed) = refresh_with(&s, &body["refreshToken"]);
    assert!(
        token_parts(&refreshed["id_token"])
            .1
            .get("provider_id")
            .is_none(),
        "{refreshed}"
    );
}

/// Strict: a continue URL whose authority a backslash ends names the host before it, as a
/// browser reads it, so it cannot pass as an authorized domain (closure security review).
#[test]
fn strict_a_backslash_ends_the_continue_url_authority() {
    let s = strict_state();
    create(
        &s,
        &json!({"email": "a@example.com", "password": "password123"}),
    );
    let (status, body) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "a@example.com", "continueUrl": "https://evil.example\\@demo-app.firebaseapp.com/x"}),
    );
    assert_eq!(
        (status, message(&body)),
        (
            400,
            Some("UNAUTHORIZED_DOMAIN : Domain not allowlisted by project")
        )
    );
}

/// Strict: only the Admin generator is told an address belongs to a disabled account; a client
/// under improved email privacy gets the sent-mail answer (the client route is unobserved).
#[test]
fn strict_a_client_email_link_request_does_not_reveal_a_disabled_account() {
    let s = strict_state();
    with_email_privacy(&s);
    email_links_on(&s);
    create(
        &s,
        &json!({"email": "dl@example.com", "password": "password123", "disabled": true}),
    );
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "EMAIL_SIGNIN", "email": "dl@example.com", "continueUrl": "https://demo-app.firebaseapp.com/finish"}),
    );
    assert_eq!(status, 200, "{body}");
}

/// Only strict records the address an applied change replaced; the official emulator records
/// `initialEmail` on a direct update only.
#[test]
fn only_strict_records_the_initial_email_of_an_applied_change() {
    for strict in [true, false] {
        let s = if strict { strict_state() } else { state() };
        create(
            &s,
            &json!({"localId": "c", "email": "c@example.com", "password": "password123"}),
        );
        let (_, change) = oob(
            &s,
            &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "c@example.com", "newEmail": "c-new@example.com"}),
        );
        let (status, _) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"oobCode": change["oobCode"]}),
        );
        assert_eq!(status, 200);
        let (_, users) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": ["c"]}),
        );
        assert_eq!(
            users["users"][0].get("initialEmail").is_some(),
            strict,
            "strict={strict}"
        );
    }
}

/// Strict: the emulator's action page treats a reset code past its lifetime as gone, like one
/// that never existed, while the API refuses it as expired.
#[test]
fn strict_the_action_page_treats_an_expired_code_as_gone() {
    let s = strict_state();
    create(
        &s,
        &json!({"email": "a@example.com", "password": "password123"}),
    );
    let (_, reset) = oob(
        &s,
        &json!({"requestType": "PASSWORD_RESET", "email": "a@example.com"}),
    );
    advance(&s, 3_601);
    let code = reset["oobCode"].as_str().unwrap();
    let r = handle(
        &s,
        "GET",
        &format!("/emulator/action?mode=resetPassword&oobCode={code}&apiKey=fake-api-key&newPassword=password456"),
        &Value::Null,
    );
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(
        r.body["authEmulator"]["error"]
            .as_str()
            .unwrap()
            .contains("has expired"),
        "{}",
        r.body
    );
}

// ---- AUTH-MFA: the project's `mfa` config (conformance/auth-mfa-production.json) ----

/// The Admin config API reads back a new project's MFA as disabled, replaces it with a masked
/// PATCH, and changes nothing on a refused value (sandbox exploration 2026-09-24).
#[test]
fn the_project_mfa_config_is_read_back_and_replaced_whole() {
    for s in [strict_state(), state()] {
        let read = |s: &AuthState| admin(s, "GET", PROJECT_CONFIG, &Value::Null).1["mfa"].clone();
        assert_eq!(read(&s), json!({"state": "DISABLED"}));
        let enabled = json!({
            "state": "ENABLED",
            "enabledProviders": ["PHONE_SMS"],
            "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 5}}],
        });
        let (status, body) = admin(
            &s,
            "PATCH",
            &format!("{PROJECT_CONFIG}?updateMask=mfa"),
            &json!({"mfa": enabled}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["mfa"], enabled);
        assert_eq!(read(&s), enabled);
        let (status, _) = admin(
            &s,
            "PATCH",
            &format!("{PROJECT_CONFIG}?updateMask=mfa"),
            &json!({"mfa": {"state": "NOT_A_STATE"}}),
        );
        assert_eq!(status, 400);
        assert_eq!(read(&s), enabled, "a refused value changes nothing");
        let (status, body) = admin(
            &s,
            "PATCH",
            &format!("{PROJECT_CONFIG}?updateMask=mfa"),
            &json!({"mfa": {"state": "DISABLED"}}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(read(&s), json!({"state": "DISABLED"}));
    }
}

/// Strict: an email change applied from the emulator's action page follows the same rules as
/// `accounts:update` with the code: earlier sessions are revoked, the replaced address is
/// recorded as `initialEmail`, and the replaced address's verification codes are void. The
/// emulator profile keeps the official emulator's answers on both routes.
#[test]
fn strict_the_action_page_applies_an_email_change_like_the_api() {
    for (strict, via_page) in [(true, true), (true, false), (false, true), (false, false)] {
        let label = format!("strict={strict} page={via_page}");
        let s = if strict { strict_state() } else { state() };
        create(
            &s,
            &json!({"localId": "c", "email": "c@example.com", "password": "password123"}),
        );
        let (status, session) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "c@example.com", "password": "password123", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{label} {session}");
        let (_, verify) = oob(
            &s,
            &json!({"requestType": "VERIFY_EMAIL", "email": "c@example.com"}),
        );
        let (_, change) = oob(
            &s,
            &json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "email": "c@example.com", "newEmail": "c-new@example.com"}),
        );
        advance(&s, 2);
        let code = change["oobCode"].as_str().unwrap();
        if via_page {
            let r = handle(
                &s,
                "GET",
                &format!(
                    "/emulator/action?mode=verifyAndChangeEmail&oobCode={code}&apiKey=fake-api-key"
                ),
                &Value::Null,
            );
            assert_eq!(r.status, 200, "{label} {}", r.body);
        } else {
            let (status, body) = post(
                &s,
                &format!("{V1}/accounts:update"),
                &json!({"oobCode": code}),
            );
            assert_eq!(status, 200, "{label} {body}");
        }
        let (_, users) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": ["c"]}),
        );
        assert_eq!(users["users"][0]["email"], "c-new@example.com", "{label}");
        assert_eq!(
            users["users"][0].get("initialEmail").is_some(),
            strict,
            "{label}"
        );
        let (status, _) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": session["idToken"]}),
        );
        assert_eq!(status == 400, strict, "{label}: earlier session revoked");
        let old_verify = verify["oobCode"].as_str().unwrap();
        assert_eq!(
            s.store.lock().unwrap().oob_code(old_verify).is_none(),
            strict,
            "{label}: the replaced address's verification code is void"
        );
    }
}

fn set_project_mfa(s: &AuthState, mfa: &Value) {
    let (status, body) = admin(
        s,
        "PATCH",
        &format!("{PROJECT_CONFIG}?updateMask=mfa"),
        &json!({ "mfa": mfa }),
    );
    assert_eq!(status, 200, "{body}");
}

/// A verified password account's ID token.
fn verified_session(s: &AuthState, email: &str) -> String {
    create(
        s,
        &json!({"email": email, "password": "password123", "emailVerified": true}),
    );
    let (status, body) = post(
        s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "password123", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    body["idToken"].as_str().unwrap().to_owned()
}

/// The project's `mfa` config enables TOTP enrollment without the `auth.totp` extension, in
/// either profile (the emulator profile accepts more than the official emulator here, a
/// fireemu-only extension; it refuses nothing new). Switched off again, it refuses as before.
#[test]
fn the_project_mfa_config_enables_totp_enrollment() {
    for (strict, s) in [(true, strict_state()), (false, state())] {
        assert!(!s.totp_extension_enabled);
        let start = |token: &str| {
            post(
                &s,
                &format!("{V2}/accounts/mfaEnrollment:start"),
                &json!({"idToken": token, "totpEnrollmentInfo": {}}),
            )
        };
        let token = verified_session(&s, "totp@example.com");
        let (status, _) = start(&token);
        assert_eq!(status, 400, "strict={strict}: TOTP is off by default");
        set_project_mfa(
            &s,
            &json!({"state": "ENABLED", "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 5}}]}),
        );
        let (status, body) = start(&token);
        assert_eq!(status, 200, "strict={strict} {body}");
        assert!(
            body["totpSessionInfo"]["sharedSecretKey"].is_string(),
            "{body}"
        );
        set_project_mfa(&s, &json!({"state": "DISABLED"}));
        let other = verified_session(&s, "totp-off@example.com");
        let (status, _) = start(&other);
        assert_eq!(status, 400, "strict={strict}: switched off again");
    }
}

/// A verification applied from the action page finds its account by the address, as
/// `accounts:update` does: strict answers production's `EMAIL_NOT_FOUND` once nobody owns it,
/// the emulator profile the official handler's expired-link page.
#[test]
fn strict_the_action_page_verifies_by_address_like_the_api() {
    for strict in [true, false] {
        let s = if strict { strict_state() } else { state() };
        create(
            &s,
            &json!({"localId": "v", "email": "v@example.com", "password": "password123"}),
        );
        let (_, verify) = oob(
            &s,
            &json!({"requestType": "VERIFY_EMAIL", "email": "v@example.com"}),
        );
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": "v", "email": "v-moved@example.com"}),
        );
        assert_eq!(status, 200);
        let code = verify["oobCode"].as_str().unwrap();
        let r = handle(
            &s,
            "GET",
            &format!("/emulator/action?mode=verifyEmail&oobCode={code}&apiKey=fake-api-key"),
            &Value::Null,
        );
        assert_eq!(r.status, 400, "{}", r.body);
        if strict {
            assert_eq!(r.body["error"]["message"], "EMAIL_NOT_FOUND", "{}", r.body);
        } else {
            // The official handler's INVALID_OOB_CODE, in the page's own words.
            assert!(
                r.body["authEmulator"]["error"]
                    .as_str()
                    .is_some_and(|e| e.contains("has expired")),
                "{}",
                r.body
            );
        }
    }
}

/// Four accounts with a code each (reset and verification for `rr`/`rv`, the same for `gone-*`);
/// every account moves to another address, and new accounts take over `rr` and `rv`. Answers
/// the codes as `(reset, verify, reset_gone, verify_gone)`.
fn codes_whose_addresses_moved(s: &AuthState) -> (String, String, String, String) {
    for name in ["rr", "rv", "gone-r", "gone-v"] {
        create(
            s,
            &json!({"localId": name, "email": format!("{name}@example.com"), "password": "password123"}),
        );
    }
    let code = |request_type: &str, name: &str| {
        let (status, body) = oob(
            s,
            &json!({"requestType": request_type, "email": format!("{name}@example.com")}),
        );
        assert_eq!(status, 200, "{body}");
        body["oobCode"].as_str().unwrap().to_owned()
    };
    let reset = code("PASSWORD_RESET", "rr");
    let verify = code("VERIFY_EMAIL", "rv");
    let reset_gone = code("PASSWORD_RESET", "gone-r");
    let verify_gone = code("VERIFY_EMAIL", "gone-v");
    for name in ["rr", "rv", "gone-r", "gone-v"] {
        let (status, _) = admin(
            s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": name, "email": format!("{name}-moved@example.com")}),
        );
        assert_eq!(status, 200);
    }
    for name in ["rr", "rv"] {
        create(
            s,
            &json!({"localId": format!("{name}-b"), "email": format!("{name}@example.com"), "password": "password123"}),
        );
    }
    (reset, verify, reset_gone, verify_gone)
}

/// Both profiles: a reset or verification code acts on the account that owns its address now,
/// as production does (sandbox recording 2026-09-24, `auth-action/address-reuse`) and as the
/// official emulator does (`resetPassword` and `setAccountInfo` look the address up). Once
/// nobody owns it, strict answers production's error and the emulator profile the official
/// emulator's `INVALID_OOB_CODE`.
#[test]
fn a_code_acts_on_the_account_that_owns_its_address_now() {
    for strict in [true, false] {
        let s = if strict { strict_state() } else { state() };
        let label = format!("strict={strict}");
        let (reset, verify, reset_gone, verify_gone) = codes_whose_addresses_moved(&s);
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:resetPassword"),
            &json!({"oobCode": reset, "newPassword": "password456"}),
        );
        assert_eq!(status, 200, "{label} {body}");
        let sign_in = |email: &str, password: &str| {
            post(
                &s,
                &format!("{V1}/accounts:signInWithPassword"),
                &json!({"email": email, "password": password, "returnSecureToken": true}),
            )
            .0
        };
        assert_eq!(
            sign_in("rr@example.com", "password456"),
            200,
            "{label}: B was reset"
        );
        assert_eq!(
            sign_in("rr-moved@example.com", "password456"),
            400,
            "{label}: A was not"
        );
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"oobCode": verify}),
        );
        assert_eq!(status, 200, "{label} {body}");
        assert_eq!(body["localId"], "rv-b", "{label}");
        let expected_gone = |strict_error: &str| {
            if strict {
                strict_error.to_owned()
            } else {
                "INVALID_OOB_CODE".to_owned()
            }
        };
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:resetPassword"),
            &json!({"oobCode": reset_gone, "newPassword": "password456"}),
        );
        assert_eq!(
            (
                status,
                body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            ),
            (400, expected_gone("USER_NOT_FOUND")),
            "{label}"
        );
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:update"),
            &json!({"oobCode": verify_gone}),
        );
        assert_eq!(
            (
                status,
                body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned()
            ),
            (400, expected_gone("EMAIL_NOT_FOUND")),
            "{label}"
        );
    }
}

/// Emulator profile, as the official `resetPassword` and `setAccountInfo` do: a code whose
/// address nobody owns is spent with `INVALID_OOB_CODE`, and a reset checks the new password's
/// length before anything else, keeping the code (confirmation review 2026-09-25, S1 and S2).
#[test]
fn the_emulator_profile_spends_an_unowned_code_after_checking_the_password() {
    let s = state();
    let (_, _, reset_gone, verify_gone) = codes_whose_addresses_moved(&s);
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:resetPassword"),
        &json!({"oobCode": reset_gone, "newPassword": "12345"}),
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        message(&body).is_some_and(|m| m.starts_with("WEAK_PASSWORD")),
        "{body}"
    );
    assert!(
        s.store.lock().unwrap().oob_code(&reset_gone).is_some(),
        "kept"
    );
    for (path, body) in [
        (
            "accounts:resetPassword",
            json!({"oobCode": reset_gone, "newPassword": "password456"}),
        ),
        ("accounts:update", json!({"oobCode": verify_gone})),
    ] {
        let (status, answer) = post(&s, &format!("{V1}/{path}"), &body);
        assert_eq!((status, message(&answer)), (400, Some("INVALID_OOB_CODE")));
    }
    let store = s.store.lock().unwrap();
    assert!(
        store.oob_code(&reset_gone).is_none(),
        "the reset code is spent"
    );
    assert!(
        store.oob_code(&verify_gone).is_none(),
        "the verification code is spent"
    );
}

/// Strict: with the project's MFA switched off, a phone enrollment is refused and an account
/// that holds a factor (written by the Admin API) signs in without a second factor (sandbox
/// recording 2026-09-24, `auth-mfa/disabled`). The emulator profile keeps the official
/// emulator's answers: it enrolls phones and always asks for the second factor.
#[test]
fn a_project_with_mfa_off_asks_for_no_second_factor_in_strict() {
    for strict in [true, false] {
        let s = if strict { strict_state() } else { state() };
        let token = verified_session(&s, "off@example.com");
        let (status, body) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
        );
        if strict {
            assert_eq!(
                (status, message(&body)),
                (
                    400,
                    Some("OPERATION_NOT_ALLOWED : SMS based MFA not enabled.")
                )
            );
        } else {
            assert_eq!(status, 200, "{body}");
        }
        let (_, user) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": token}),
        );
        let uid = user["users"][0]["localId"].clone();
        let (status, _) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": uid, "mfa": {"enrollments": [{"phoneInfo": "+16505550102", "displayName": "Admin"}]}}),
        );
        assert_eq!(status, 200);
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"email": "off@example.com", "password": "password123", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["idToken"].is_string(),
            strict,
            "strict={strict} {body}"
        );
        assert_eq!(body["mfaPendingCredential"].is_string(), !strict, "{body}");
    }
}

/// Strict: the answer that asks for a second factor has production's members: a password
/// sign-in keeps `displayName` and `registered` (sandbox recording 2026-09-24,
/// `auth-mfa/totp/sign-in#pending-1`).
#[test]
fn strict_the_pending_answer_has_production_members() {
    let s = strict_state();
    set_project_mfa(
        &s,
        &json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}),
    );
    let token = verified_session(&s, "pending@example.com");
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
    );
    assert_eq!(status, 200, "{started}");
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": token, "displayName": "Phone", "phoneVerificationInfo": {"sessionInfo": started["phoneSessionInfo"]["sessionInfo"], "code": phone_code(&s)}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "pending@example.com", "password": "password123", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    let mut members: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "displayName",
            "email",
            "kind",
            "localId",
            "mfaInfo",
            "mfaPendingCredential",
            "registered"
        ]
    );
    assert_eq!(body["displayName"], "");
}

/// The code of the newest outstanding phone verification.
fn phone_code(s: &AuthState) -> String {
    s.store
        .lock()
        .unwrap()
        .verification_codes()
        .last()
        .expect("a code was sent")
        .code
        .clone()
}

// ---- AUTH-MFA strict: TOTP enrollment (sandbox recording 2026-09-24, auth-mfa/totp/enroll) ----

const MFA_ON: &str = r#"{"state": "ENABLED", "enabledProviders": ["PHONE_SMS"], "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 5}}]}"#;

fn strict_mfa_state() -> AuthState {
    let s = strict_state();
    set_project_mfa(&s, &serde_json::from_str(MFA_ON).unwrap());
    s
}

fn start_totp(s: &AuthState, token: &str) -> Value {
    let (status, body) = post(
        s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "totpEnrollmentInfo": {}}),
    );
    assert_eq!(status, 200, "{body}");
    body
}

/// The code of an enrollment start's secret at the store's clock, `offset` steps away.
fn totp_code_of(s: &AuthState, started: &Value, offset: i64) -> String {
    let secret = base32::decode(
        started["totpSessionInfo"]["sharedSecretKey"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let now = s.clock.lock().unwrap().now();
    let at = now
        .checked_add(LogicalDuration::from_seconds(30 * offset))
        .unwrap();
    let params = TotpParams {
        period_seconds: 30,
        digits: 6,
    };
    format!("{:06}", totp_at(&secret, &params, at))
}

fn finalize_totp(
    s: &AuthState,
    token: &str,
    started: &Value,
    code: &str,
    name: Option<&str>,
) -> (u16, Value) {
    let mut body = json!({"idToken": token, "totpVerificationInfo": {"sessionInfo": started["totpSessionInfo"]["sessionInfo"], "verificationCode": code}});
    if let Some(name) = name {
        body["displayName"] = json!(name);
    }
    post(s, &format!("{V2}/accounts/mfaEnrollment:finalize"), &body)
}

fn v2_refusal(body: &Value) -> (&str, bool) {
    (
        body["error"]["message"].as_str().unwrap_or_default(),
        body["error"].get("errors").is_none() && body["error"]["status"] == "INVALID_ARGUMENT",
    )
}

#[test]
fn strict_totp_enrollment_answers_as_production() {
    let s = strict_mfa_state();
    // Production's clock has a fraction; microsecond precision shows as six digits.
    s.clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_nanos(123_456_789))
        .unwrap();
    let token = verified_session(&s, "enroll@example.com");
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token}),
    );
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("Request contains an invalid argument.", true))
    );
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "totpEnrollmentInfo": {}, "phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
    );
    assert_eq!(status, 400);
    assert_eq!(
        body["error"]["message"],
        "Invalid value (oneof), oneof field 'enrollment_info' is already set. Cannot set 'phoneEnrollmentInfo'"
    );
    assert_eq!(
        body["error"]["details"][0]["@type"],
        "type.googleapis.com/google.rpc.BadRequest"
    );
    let started = start_totp(&s, &token);
    let info = &started["totpSessionInfo"];
    assert_eq!(info["hashingAlgorithm"], "SHA1");
    let deadline = info["finalizeEnrollmentTime"].as_str().unwrap();
    let fraction = deadline.rsplit('.').next().unwrap().trim_end_matches('Z');
    assert_eq!(fraction.len(), 6, "{deadline}");
    let now = s.clock.lock().unwrap().now();
    let expected = now.checked_add(LogicalDuration::from_seconds(900)).unwrap();
    assert_eq!(
        &deadline[..19],
        &LogicalInstant::to_rfc3339(expected).unwrap()[..19]
    );
}

#[test]
fn strict_totp_enrollment_finalize_answers_as_production() {
    let s = strict_mfa_state();
    s.clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_nanos(123_456_789))
        .unwrap();
    let token = verified_session(&s, "finalize@example.com");
    let started = start_totp(&s, &token);
    // The session first, then the display name, then the code.
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": token, "totpVerificationInfo": {"verificationCode": "123456"}}),
    );
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("INVALID_SESSION_INFO", true))
    );
    let good = totp_code_of(&s, &started, 0);
    let (status, body) = finalize_totp(&s, &token, &started, &good, None);
    assert_eq!(
        (status, v2_refusal(&body)),
        (
            400,
            ("MISSING_DISPLAY_NAME : display name cannot be empty", true)
        )
    );
    let (status, body) = finalize_totp(&s, &token, &started, &good, Some("Authenticator"));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["totpAuthInfo"], json!({}));
    let mut members: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(members, ["idToken", "refreshToken", "totpAuthInfo"]);
    // A refused display name is not an attempt (production accepted the code after it and
    // two wrong ones); the finalized session offered again is complete.
    let again = totp_code_of(&s, &started, 1);
    let fresh = body["idToken"].as_str().unwrap().to_owned();
    let (status, body) = finalize_totp(&s, &fresh, &started, &again, Some("A"));
    assert_eq!(
        (status, v2_refusal(&body)),
        (
            400,
            (
                "MFA_ENROLLMENT_ALREADY_COMPLETE : This MFA enrollment has already been completed.",
                true
            )
        )
    );
    let (_, user) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": token}),
    );
    let factor = &user["users"][0]["mfaInfo"][0];
    assert_eq!(factor["displayName"], "Authenticator");
    let enrolled = factor["enrolledAt"].as_str().unwrap();
    assert_eq!(
        enrolled
            .rsplit('.')
            .next()
            .unwrap()
            .trim_end_matches('Z')
            .len(),
        6,
        "{enrolled}"
    );
    assert_eq!(factor["mfaEnrollmentId"].as_str().unwrap().len(), 36);
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "totpEnrollmentInfo": {}}),
    );
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("SECOND_FACTOR_LIMIT_EXCEEDED : Too many TOTP based second factors enrolled for this account.", true))
    );
}

#[test]
fn strict_an_enrollment_session_used_three_times_must_be_restarted() {
    let s = strict_mfa_state();
    let token = verified_session(&s, "attempts@example.com");
    let started = start_totp(&s, &token);
    for _ in 0..2 {
        let (status, body) = finalize_totp(&s, &token, &started, "000000", Some("A"));
        assert_eq!(
            (status, v2_refusal(&body)),
            (400, ("INVALID_CODE", true)),
            "{body}"
        );
    }
    let (status, body) = finalize_totp(
        &s,
        &token,
        &started,
        &totp_code_of(&s, &started, 0),
        Some("A"),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = finalize_totp(
        &s,
        &token,
        &started,
        &totp_code_of(&s, &started, 1),
        Some("A"),
    );
    assert_eq!(
        (status, v2_refusal(&body)),
        (
            400,
            ("TOO_MANY_ENROLLMENT_ATTEMPTS : restart enrollment", true)
        )
    );
}

#[test]
fn strict_a_phone_start_beyond_five_factors_is_refused() {
    let s = strict_mfa_state();
    let token = verified_session(&s, "limit@example.com");
    let (_, user) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": token}),
    );
    let enrollments: Vec<Value> = (1..=5)
        .map(|n| json!({"phoneInfo": format!("+1650555010{n}"), "displayName": format!("Phone {n}")}))
        .collect();
    let (status, _) = admin(
        &s,
        "POST",
        &format!("{ADMIN}/accounts:update"),
        &json!({"localId": user["users"][0]["localId"], "mfa": {"enrollments": enrollments}}),
    );
    assert_eq!(status, 200);
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+16505550106"}}),
    );
    assert_eq!(
        (status, v2_refusal(&body)),
        (
            400,
            (
                "SECOND_FACTOR_LIMIT_EXCEEDED : Too many second factors enrolled for this account.",
                true
            )
        )
    );
}

// ---- AUTH-MFA strict: second-factor sign-in (auth-mfa/totp/sign-in, sms, interactions) ----

/// A verified account with one TOTP factor; answers `(started, first-factor token, uid)`.
fn totp_enrolled(s: &AuthState, email: &str) -> (Value, String, Value) {
    let token = verified_session(s, email);
    let started = start_totp(s, &token);
    let (status, body) = finalize_totp(
        s,
        &token,
        &started,
        &totp_code_of(s, &started, 0),
        Some("Authenticator"),
    );
    assert_eq!(status, 200, "{body}");
    let (_, user) = post(
        s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": token}),
    );
    (started, token, user["users"][0]["localId"].clone())
}

fn pending_of(s: &AuthState, email: &str) -> Value {
    let (status, body) = post(
        s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": email, "password": "password123", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["mfaPendingCredential"].is_string(), "{body}");
    body
}

fn totp_sign_in(s: &AuthState, pending: &Value, enrollment: &Value, code: &str) -> (u16, Value) {
    post(
        s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "mfaEnrollmentId": enrollment, "totpVerificationInfo": {"verificationCode": code}}),
    )
}

#[test]
fn strict_totp_sign_in_answers_as_production() {
    let s = strict_mfa_state();
    let (started, _, _) = totp_enrolled(&s, "sign@example.com");
    let pending = pending_of(&s, "sign@example.com");
    let factor = pending["mfaInfo"][0]["mfaEnrollmentId"].clone();
    let invalid = ("Request contains an invalid argument.", true);
    let start = |extra: Value| {
        let mut body = json!({"mfaPendingCredential": pending["mfaPendingCredential"], "mfaEnrollmentId": factor});
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        post(&s, &format!("{V2}/accounts/mfaSignIn:start"), &body)
    };
    let (status, body) = start(json!({}));
    assert_eq!((status, v2_refusal(&body)), (400, invalid));
    let (status, body) = start(json!({"phoneSignInInfo": {}}));
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("INVALID_PHONE_NUMBER : Invalid format.", true))
    );
    let finalize = |body: Value| post(&s, &format!("{V2}/accounts/mfaSignIn:finalize"), &body);
    let code = totp_code_of(&s, &started, 1);
    let (status, body) = finalize(
        json!({"mfaEnrollmentId": factor, "totpVerificationInfo": {"verificationCode": code}}),
    );
    assert_eq!((status, v2_refusal(&body)), (400, invalid));
    let (status, body) = finalize(
        json!({"mfaPendingCredential": "not-a-pending-credential", "mfaEnrollmentId": factor, "totpVerificationInfo": {"verificationCode": code}}),
    );
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("INVALID_PENDING_TOKEN", true))
    );
    let (status, body) = finalize(
        json!({"mfaPendingCredential": pending["mfaPendingCredential"], "mfaEnrollmentId": factor, "totpVerificationInfo": {}}),
    );
    assert_eq!((status, v2_refusal(&body)), (400, invalid));
    let (status, body) = finalize(
        json!({"mfaPendingCredential": pending["mfaPendingCredential"], "totpVerificationInfo": {"verificationCode": code}}),
    );
    assert_eq!((status, v2_refusal(&body)), (400, invalid));
    let (status, body) = totp_sign_in(&s, &pending, &json!("not-an-enrollment"), &code);
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("INVALID_MFA_ENROLLMENT_ID", true))
    );
    let (status, body) = totp_sign_in(&s, &pending, &factor, &code);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.as_object().unwrap().len(), 2, "{body}");
    // The pending credential stays usable after it succeeded; a code already used is refused.
    let (status, body) = totp_sign_in(&s, &pending, &factor, &code);
    assert_eq!((status, v2_refusal(&body)), (400, ("INVALID_CODE", true)));
    let (status, body) = totp_sign_in(&s, &pending, &factor, &totp_code_of(&s, &started, 2));
    assert_eq!(status, 200, "{body}");
}

#[test]
fn strict_a_pending_credential_across_account_changes() {
    let s = strict_mfa_state();
    // Disabled after the first factor: production still completes the sign-in.
    let (started, _, uid) = totp_enrolled(&s, "disabled@example.com");
    let pending = pending_of(&s, "disabled@example.com");
    let factor = pending["mfaInfo"][0]["mfaEnrollmentId"].clone();
    let update = |fields: Value| {
        let mut body = json!({"localId": uid});
        for (k, v) in fields.as_object().unwrap() {
            body[k] = v.clone();
        }
        assert_eq!(
            admin(&s, "POST", &format!("{ADMIN}/accounts:update"), &body).0,
            200
        );
    };
    update(json!({"disableUser": true}));
    let (status, body) = totp_sign_in(&s, &pending, &factor, &totp_code_of(&s, &started, 1));
    assert_eq!(status, 200, "{body}");
    update(json!({"disableUser": false}));
    // Its factors cleared: the factor is no longer the account's.
    let pending = pending_of(&s, "disabled@example.com");
    update(json!({"mfa": {}}));
    let (status, body) = totp_sign_in(&s, &pending, &factor, &totp_code_of(&s, &started, 2));
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("INVALID_MFA_ENROLLMENT_ID", true))
    );
    // Deleted: the pending credential names an account that is gone.
    let (started, _, uid) = totp_enrolled(&s, "deleted@example.com");
    let pending = pending_of(&s, "deleted@example.com");
    let factor = pending["mfaInfo"][0]["mfaEnrollmentId"].clone();
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:delete"),
            &json!({"localId": uid})
        )
        .0,
        200
    );
    let (status, body) = totp_sign_in(&s, &pending, &factor, &totp_code_of(&s, &started, 1));
    assert_eq!((status, v2_refusal(&body)), (400, ("USER_NOT_FOUND", true)));
}

#[test]
fn strict_an_sms_sign_in_to_a_test_number_can_be_repeated() {
    let s = strict_mfa_state();
    let (status, body) = patch_sign_in(
        &s,
        "signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505550101": "123456"}}}}),
    );
    assert_eq!(status, 200, "{body}");
    let token = verified_session(&s, "sms@example.com");
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
    );
    assert_eq!(status, 200, "{started}");
    let enroll = json!({"idToken": token, "displayName": "Phone", "phoneVerificationInfo": {"sessionInfo": started["phoneSessionInfo"]["sessionInfo"], "code": "123456"}});
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &enroll,
    );
    assert_eq!(status, 200, "{body}");
    // The enrollment session again: the number is enrolled now.
    let fresh = body["idToken"].as_str().unwrap();
    let mut again = enroll.clone();
    again["idToken"] = json!(fresh);
    let (status, body) = post(&s, &format!("{V2}/accounts/mfaEnrollment:finalize"), &again);
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("SECOND_FACTOR_EXISTS : Phone number already enrolled as second factor for this account.", true))
    );
    let pending = pending_of(&s, "sms@example.com");
    let factor = pending["mfaInfo"][0]["mfaEnrollmentId"].clone();
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "mfaEnrollmentId": factor}),
    );
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("Request contains an invalid argument.", true))
    );
    let (status, sent) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"], "mfaEnrollmentId": factor, "phoneSignInInfo": {}}),
    );
    assert_eq!(status, 200, "{sent}");
    let finalize = json!({"mfaPendingCredential": pending["mfaPendingCredential"], "mfaEnrollmentId": factor, "phoneVerificationInfo": {"sessionInfo": sent["phoneResponseInfo"]["sessionInfo"], "code": "123456"}});
    for attempt in 0..2 {
        let (status, body) = post(&s, &format!("{V2}/accounts/mfaSignIn:finalize"), &finalize);
        assert_eq!(status, 200, "attempt {attempt}: {body}");
    }
}

// ---- AUTH-MFA strict: withdrawal and what it revokes (auth-mfa/totp/withdraw, sms) ----

/// The `firebase` claims of a token, whatever signs it (the payload segment, unverified).
fn second_factor_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).unwrap();
    let payload = fireemu_core_auth::jwt::base64url_decode(payload).unwrap();
    serde_json::from_slice::<Value>(&payload).unwrap()["firebase"].clone()
}

/// Under RS256 (session-rsa, as `fireemu` runs strict) too: the kept factor is read from the
/// signed token (sandbox recording, `auth-mfa/sms#withdraw-first-phone`).
#[test]
fn strict_a_withdrawal_revokes_earlier_sessions_and_keeps_the_other_factor() {
    let s = strict_mfa_state();
    s.store
        .lock()
        .unwrap()
        .set_signer(RsaSigner::from_seed(45).unwrap());
    let (status, body) = patch_sign_in(
        &s,
        "signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505550101": "123456", "+16505550102": "123456"}}}}),
    );
    assert_eq!(status, 200, "{body}");
    let (started, first_factor_token, _) = totp_enrolled(&s, "withdraw@example.com");
    let pending = pending_of(&s, "withdraw@example.com");
    let totp_factor = pending["mfaInfo"][0]["mfaEnrollmentId"].clone();
    let (status, signed) = totp_sign_in(&s, &pending, &totp_factor, &totp_code_of(&s, &started, 1));
    assert_eq!(status, 200, "{signed}");
    let session = signed["idToken"].as_str().unwrap().to_owned();
    let withdraw = |body: Value| post(&s, &format!("{V2}/accounts/mfaEnrollment:withdraw"), &body);
    let (status, body) = withdraw(json!({"mfaEnrollmentId": totp_factor}));
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("INVALID_ID_TOKEN", true))
    );
    let (status, body) = withdraw(json!({"idToken": session}));
    assert_eq!(
        (status, v2_refusal(&body)),
        (400, ("MFA_ENROLLMENT_NOT_FOUND", true))
    );
    // A phone factor next to the TOTP one; the session signed in with TOTP withdraws the phone.
    let (status, phone) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": session, "phoneEnrollmentInfo": {"phoneNumber": "+16505550102"}}),
    );
    assert_eq!(status, 200, "{phone}");
    advance(&s, 2);
    let (status, enrolled) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": session, "displayName": "Phone", "phoneVerificationInfo": {"sessionInfo": phone["phoneSessionInfo"]["sessionInfo"], "code": "123456"}}),
    );
    assert_eq!(status, 200, "{enrolled}");
    // A phone enrollment ends the sessions before it (production: validSince later).
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": session}),
    );
    assert_eq!((status, message(&body)), (400, Some("TOKEN_EXPIRED")));
    let session = enrolled["idToken"].as_str().unwrap().to_owned();
    let phone_factor = second_factor_claims(&session)["second_factor_identifier"].clone();
    // The enrollment token names the phone; withdraw the TOTP factor with it.
    advance(&s, 2);
    let (status, body) = withdraw(json!({"idToken": session, "mfaEnrollmentId": totp_factor}));
    assert_eq!(status, 200, "{body}");
    let mut members: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(members, ["idToken", "refreshToken"]);
    let fresh = body["idToken"].as_str().unwrap();
    assert_eq!(
        second_factor_claims(fresh)["sign_in_second_factor"],
        "phone"
    );
    assert_eq!(
        second_factor_claims(fresh)["second_factor_identifier"],
        phone_factor
    );
    for token in [&session, &first_factor_token] {
        let (status, body) = post(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": token}),
        );
        assert_eq!((status, message(&body)), (400, Some("TOKEN_EXPIRED")));
    }
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": fresh}),
    );
    assert_eq!(status, 200, "{body}");
    // Withdrawing the factor the session used leaves no second factor in the new token.
    advance(&s, 2);
    let (status, body) = withdraw(json!({"idToken": fresh, "mfaEnrollmentId": phone_factor}));
    assert_eq!(status, 200, "{body}");
    assert!(second_factor_claims(body["idToken"].as_str().unwrap())
        .get("sign_in_second_factor")
        .is_none());
}

// ---- AUTH-MFA strict: second factors imported by batchCreate (auth-mfa/admin-factors) ----

fn import_factors(s: &AuthState) -> Value {
    let (status, body) = admin(
        s,
        "POST",
        &format!("{ADMIN}/accounts:batchCreate"),
        &json!({"users": [
            {"localId": "ia", "email": "ia@example.com", "emailVerified": true,
             "mfaInfo": [{"phoneInfo": "+16505550101", "displayName": "Imported", "enrolledAt": "2020-01-02T03:04:05Z"}]},
            {"localId": "ib", "email": "ib@example.com", "emailVerified": true,
             "mfaInfo": [{"phoneInfo": "+16505550102", "displayName": "Imported with id", "mfaEnrollmentId": "imported-factor-1"}]},
            {"localId": "it", "email": "it@example.com", "emailVerified": true,
             "mfaInfo": [{"totpInfo": {}, "displayName": "Imported TOTP"}]},
            {"localId": "iu", "email": "iu@example.com", "emailVerified": true,
             "mfaInfo": [{"totpInfo": {"sharedSecretKey": "JBSWY3DPEHPK3PXP"}, "displayName": "Imported TOTP"}]},
        ]}),
    );
    assert_eq!(status, 200, "{body}");
    body
}

fn imported_factor(s: &AuthState, local_id: &str) -> Value {
    let (status, body) = admin(
        s,
        "POST",
        &format!("{ADMIN}/accounts:lookup"),
        &json!({"localId": [local_id]}),
    );
    assert_eq!(status, 200, "{body}");
    body["users"][0]["mfaInfo"][0].clone()
}

/// Production refuses every imported TOTP factor, names a factor without an id with a UUID and
/// stamps one without a time with the import time in milliseconds (sandbox recording
/// 2026-09-24, `#batch-create` and `#admin-lookup-imported`).
#[test]
fn strict_batch_create_imports_phone_factors_as_production_does() {
    let s = strict_mfa_state();
    s.clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_nanos(123_456_789))
        .unwrap();
    let body = import_factors(&s);
    assert_eq!(
        body["error"],
        json!([
            {"index": 2, "message": "Importing TOTP MFA is not supported."},
            {"index": 3, "message": "Importing TOTP MFA is not supported."},
        ])
    );
    let ia = imported_factor(&s, "ia");
    let id = ia["mfaEnrollmentId"].as_str().unwrap();
    assert_eq!((id.len(), &id[14..15]), (36, "4"), "a version-4 UUID: {id}");
    assert_eq!(ia["enrolledAt"], "2020-01-02T03:04:05Z");
    let ib = imported_factor(&s, "ib");
    assert_eq!(ib["mfaEnrollmentId"], "imported-factor-1");
    let at = ib["enrolledAt"].as_str().unwrap();
    assert_eq!(at.rsplit('.').next(), Some("123Z"), "milliseconds: {at}");
}

/// The emulator profile keeps its ids, times and the TOTP export shape.
#[test]
fn emulator_batch_create_keeps_its_own_factor_import() {
    let s = state();
    let body = import_factors(&s);
    assert_eq!(
        body["error"],
        json!([{"index": 2, "message": "Second factor not supported."}])
    );
    assert_eq!(imported_factor(&s, "ia")["mfaEnrollmentId"], "ia-mfa-0");
    assert_eq!(imported_factor(&s, "iu")["mfaEnrollmentId"], "iu-mfa-0");
}

/// A phone enrollment moves `validSince` to its own second, so a session signed in that same
/// second survives it and one from an earlier second does not; production answered a later
/// start both ways by the timing alone (sandbox recordings 2026-09-24,
/// `auth-mfa/lifetime#control-start-s600`).
#[test]
fn strict_a_phone_enrollment_revokes_only_sessions_from_earlier_seconds() {
    for (gap, survives) in [(0, true), (1, false)] {
        let s = strict_mfa_state();
        let (status, body) = patch_sign_in(
            &s,
            "signIn.phoneNumber.testPhoneNumbers",
            &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505550101": "123456"}}}}),
        );
        assert_eq!(status, 200, "{body}");
        let session = verified_session(&s, "same-second@example.com");
        let (status, started) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": session, "phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
        );
        assert_eq!(status, 200, "{started}");
        advance(&s, gap);
        let (status, enrolled) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:finalize"),
            &json!({"idToken": session, "phoneVerificationInfo": {"sessionInfo": started["phoneSessionInfo"]["sessionInfo"], "code": "123456"}}),
        );
        assert_eq!(status, 200, "{enrolled}");
        let (status, body) = post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": session, "phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
        );
        let expected = if survives {
            "SECOND_FACTOR_EXISTS : Phone number already enrolled as second factor for this account."
        } else {
            "TOKEN_EXPIRED"
        };
        assert_eq!((status, message(&body)), (400, Some(expected)), "gap {gap}");
    }
}

// ---- AUTH-MFA strict: short lifetimes (auth-mfa/lifetime, auth-mfa/lifetime-short) ----------

/// A TOTP sign-in finalized `age` seconds after its pending credential was issued.
fn totp_sign_in_aged(s: &AuthState, email: &str, age: i64) -> (u16, Value) {
    let (started, _, _) = totp_enrolled(s, email);
    advance(s, 60);
    let pending = pending_of(s, email);
    let factor = pending["mfaInfo"][0]["mfaEnrollmentId"].clone();
    advance(s, age);
    totp_sign_in(s, &pending, &factor, &totp_code_of(s, &started, 0))
}

/// Production accepted a TOTP pending credential 293 seconds old and refused one 303 seconds
/// old with `TOTP_CHALLENGE_TIMEOUT`, both measured from send to send. Strict refuses from 302
/// seconds, one second below the refusal to absorb the two requests' differing latencies; the
/// ages below stay accepted.
#[test]
fn strict_a_totp_pending_credential_times_out_where_production_refused() {
    for (age, refused) in [
        (293, false),
        (301, false),
        (302, true),
        (303, true),
        (1_800, true),
    ] {
        let s = strict_mfa_state();
        let (status, body) = totp_sign_in_aged(&s, "pending-age@example.com", age);
        if refused {
            assert_eq!(
                (status, v2_refusal(&body)),
                (
                    400,
                    (
                        "TOTP_CHALLENGE_TIMEOUT : TOTP challenge timeout, provide first factor again.",
                        true
                    )
                ),
                "{age}"
            );
        } else {
            assert_eq!(status, 200, "{age} {body}");
        }
    }
    // The emulator profile keeps its hour.
    let s = state_with_totp_extension();
    let (status, body) = totp_sign_in_aged(&s, "pending-age@example.com", 1_800);
    assert_eq!(status, 200, "{body}");
}

/// A TOTP enrollment started with a session signed in `age` seconds earlier.
fn totp_start_aged(s: &AuthState, email: &str, age: i64) -> (u16, Value) {
    let token = verified_session(s, email);
    advance(s, age);
    post(
        s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "totpEnrollmentInfo": {}}),
    )
}

/// Production started a TOTP enrollment with a sign-in 244 seconds old and refused one 333
/// seconds old with `CREDENTIAL_TOO_OLD_LOGIN_AGAIN`. Strict refuses from the youngest refused
/// age only. A phone enrollment's need for a recent sign-in is unobserved, so it is not asked.
#[test]
fn strict_a_totp_enrollment_needs_a_sign_in_as_recent_as_production_asked() {
    for (age, refused) in [(244, false), (332, false), (333, true), (1_800, true)] {
        let s = strict_mfa_state();
        let (status, body) = totp_start_aged(&s, "recent@example.com", age);
        if refused {
            assert_eq!(
                (status, v2_refusal(&body)),
                (400, ("CREDENTIAL_TOO_OLD_LOGIN_AGAIN", true)),
                "{age}"
            );
        } else {
            assert_eq!(status, 200, "{age} {body}");
        }
    }
    let s = strict_mfa_state();
    let (status, body) = patch_sign_in(
        &s,
        "signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505550101": "123456"}}}}),
    );
    assert_eq!(status, 200, "{body}");
    let token = verified_session(&s, "recent-phone@example.com");
    advance(&s, 1_800);
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
    );
    assert_eq!(status, 200, "{body}");
    // The emulator profile asks for no recent sign-in.
    let s = state_with_totp_extension();
    let (status, body) = totp_start_aged(&s, "recent@example.com", 1_800);
    assert_eq!(status, 200, "{body}");
}

// ---- AUTH-MFA strict: the per-user pending budget (safety review 2026-09-25, MF-2) ---------

/// Production keeps a pending credential after it succeeds, but a user signing in again and
/// again is never refused for it: a credential that succeeded makes room at the budget.
#[test]
fn strict_repeated_mfa_sign_ins_are_not_refused_by_the_pending_budget() {
    let s = strict_mfa_state();
    let (status, body) = patch_sign_in(
        &s,
        "signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505550101": "123456"}}}}),
    );
    assert_eq!(status, 200, "{body}");
    create(
        &s,
        &json!({"email": "again@example.com", "password": "password123", "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+16505550101"}]}),
    );
    let budget = fireemu_core_auth::mfa::MAX_PENDING_PER_USER;
    for round in 0..budget + 8 {
        let pending = pending_of(&s, "again@example.com");
        let (status, started) = post(
            &s,
            &format!("{V2}/accounts/mfaSignIn:start"),
            &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
                "mfaEnrollmentId": pending["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {}}),
        );
        assert_eq!(status, 200, "round {round}: {started}");
        let (status, signed_in) = post(
            &s,
            &format!("{V2}/accounts/mfaSignIn:finalize"),
            &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
                "phoneVerificationInfo": {"sessionInfo": started["phoneResponseInfo"]["sessionInfo"], "code": "123456"}}),
        );
        assert_eq!(status, 200, "round {round}: {signed_in}");
    }
}

/// Expired enrollment sessions, which production's rules keep for a day so a late finalize is
/// `SESSION_EXPIRED`, make room at the budget; live ones still fill it.
#[test]
fn strict_expired_enrollment_sessions_do_not_hold_the_pending_budget() {
    let s = strict_mfa_state();
    let token = verified_session(&s, "sessions@example.com");
    let budget = fireemu_core_auth::mfa::MAX_PENDING_PER_USER;
    let start = |token: &str| {
        post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": token, "totpEnrollmentInfo": {}}),
        )
    };
    for _ in 0..budget {
        let (status, body) = start(&token);
        assert_eq!(status, 200, "{body}");
    }
    let (status, body) = start(&token);
    assert_eq!(status, 400, "live sessions fill the budget: {body}");
    // At exactly its deadline a session is still live (it still finalizes), so none makes room.
    advance(&s, 900);
    let (status, signed_in) = password_sign_in(&s, "sessions@example.com", "password123");
    assert_eq!(status, 200, "{signed_in}");
    let (status, body) = start(signed_in["idToken"].as_str().unwrap());
    assert_eq!(status, 400, "at the deadline: {body}");
    advance(&s, 1);
    let (status, signed_in) = password_sign_in(&s, "sessions@example.com", "password123");
    assert_eq!(status, 200, "{signed_in}");
    let (status, body) = start(signed_in["idToken"].as_str().unwrap());
    assert_eq!(status, 200, "{body}");
}

/// An Admin factor entry with `phoneInfo` is a phone factor whatever else it carries, as the
/// official emulator reads it (`getMfaEnrollmentsFromRequest` checks `phoneInfo` only).
/// Production refused an entry with only `totpInfo`; one with both is unobserved, so neither
/// profile refuses it (safety review 2026-09-25, SF-2).
#[test]
fn an_admin_factor_entry_with_phone_info_is_a_phone_factor_in_both_profiles() {
    for s in [state(), strict_mfa_state()] {
        let (status, created) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts"),
            &json!({"email": "both@example.com", "emailVerified": true}),
        );
        assert_eq!(status, 200, "{created}");
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": created["localId"], "mfa": {"enrollments": [
                {"phoneInfo": "+16505550101", "totpInfo": {}, "displayName": "Both"}]}}),
        );
        assert_eq!(status, 200, "{body}");
        let (status, body) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:update"),
            &json!({"localId": created["localId"], "mfa": {"enrollments": [
                {"totpInfo": {}, "displayName": "TOTP only"}]}}),
        );
        assert_eq!(
            (status, message(&body)),
            (
                400,
                Some("UNSUPPORTED_SECOND_FACTOR : attempting to add a new TOTP enrollment")
            )
        );
        let (_, found) = admin(
            &s,
            "POST",
            &format!("{ADMIN}/accounts:lookup"),
            &json!({"localId": [created["localId"]]}),
        );
        assert_eq!(found["users"][0]["mfaInfo"][0]["phoneInfo"], "+16505550101");
    }
}

// ---- AUTH-MFA strict: where the widened acceptance stops (safety review 2026-09-25, SF-3) ----

/// Enrolls a phone factor on a non-test number and returns the account's email.
fn real_number_phone_account(s: &AuthState, email: &str) -> (u16, Value) {
    let token = verified_session(s, email);
    let (status, started) = post(
        s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+16505550199"}}),
    );
    assert_eq!(status, 200, "{started}");
    let finalize = json!({"idToken": token, "phoneVerificationInfo": {
        "sessionInfo": started["phoneSessionInfo"]["sessionInfo"], "code": phone_code(s)}});
    let (status, enrolled) = post(
        s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &finalize,
    );
    assert_eq!(status, 200, "{enrolled}");
    post(
        s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &finalize,
    )
}

/// Only a configured test number's SMS session can be used again: a real number's enrollment
/// and sign-in sessions are spent by their success (SF-3 a).
#[test]
fn strict_a_real_numbers_sms_session_is_single_use() {
    let s = strict_mfa_state();
    let (status, again) = real_number_phone_account(&s, "real@example.com");
    assert_eq!(
        (status, v2_refusal(&again).0),
        (400, "INVALID_SESSION_INFO"),
        "enrollment session again: {again}"
    );
    let pending = pending_of(&s, "real@example.com");
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
            "mfaEnrollmentId": pending["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {}}),
    );
    assert_eq!(status, 200, "{started}");
    let finalize = json!({"mfaPendingCredential": pending["mfaPendingCredential"],
        "phoneVerificationInfo": {"sessionInfo": started["phoneResponseInfo"]["sessionInfo"], "code": phone_code(&s)}});
    let (status, body) = post(&s, &format!("{V2}/accounts/mfaSignIn:finalize"), &finalize);
    assert_eq!(status, 200, "{body}");
    let (status, body) = post(&s, &format!("{V2}/accounts/mfaSignIn:finalize"), &finalize);
    assert_eq!(status, 400, "sign-in session again: {body}");
}

/// The TOTP challenge timeout is TOTP's: a phone second factor completes a pending credential
/// 303 and 1800 seconds old (auth-mfa/lifetime-short#aged-pending-m300; SF-3 c).
#[test]
fn strict_an_sms_pending_credential_has_no_totp_challenge_timeout() {
    for age in [303, 1_800] {
        let s = strict_mfa_state();
        let (status, _) = real_number_phone_account(&s, "sms-pending@example.com");
        assert_eq!(status, 400);
        let pending = pending_of(&s, "sms-pending@example.com");
        advance(&s, age);
        let (status, started) = post(
            &s,
            &format!("{V2}/accounts/mfaSignIn:start"),
            &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
                "mfaEnrollmentId": pending["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {}}),
        );
        assert_eq!(status, 200, "{age}: {started}");
        let (status, body) = post(
            &s,
            &format!("{V2}/accounts/mfaSignIn:finalize"),
            &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
                "phoneVerificationInfo": {"sessionInfo": started["phoneResponseInfo"]["sessionInfo"], "code": phone_code(&s)}}),
        );
        assert_eq!(status, 200, "{age}: {body}");
    }
}

// ---- AUTH-MFA: mutation follow-ups (docs.local/mutation/auth-mfa/20260925) --------------------

/// Without an update mask a non-null `mfa` member is part of the update and a null one is not.
#[test]
fn a_maskless_config_update_reads_a_non_null_mfa_member_only() {
    let s = state();
    let mfa: Value = serde_json::from_str(MFA_ON).unwrap();
    let (status, body) = admin(&s, "PATCH", PROJECT_CONFIG, &json!({ "mfa": mfa }));
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["mfa"]["state"], "ENABLED", "{body}");
    let (status, body) = admin(
        &s,
        "PATCH",
        PROJECT_CONFIG,
        &json!({"mfa": null, "signIn": {"allowDuplicateEmails": true}}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["mfa"]["state"], "ENABLED", "{body}");
}

/// Strict: the answer that asks for a second factor keeps a password sign-in's display name.
#[test]
fn strict_the_pending_answer_keeps_the_display_name() {
    let s = strict_mfa_state();
    create(
        &s,
        &json!({"email": "named@example.com", "password": "password123", "emailVerified": true,
            "displayName": "Named", "mfaInfo": [{"phoneInfo": "+16505550101"}]}),
    );
    let pending = pending_of(&s, "named@example.com");
    assert_eq!(pending["displayName"], "Named", "{pending}");
    assert!(pending.get("isNewUser").is_none(), "{pending}");
}

/// Strict with a test-number phone factor on `email`.
fn strict_phone_account(email: &str) -> AuthState {
    let s = strict_mfa_state();
    let (status, body) = patch_sign_in(
        &s,
        "signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505550101": "123456"}}}}),
    );
    assert_eq!(status, 200, "{body}");
    create(
        &s,
        &json!({"email": email, "password": "password123", "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+16505550101"}]}),
    );
    s
}

/// Completes a pending credential with the test number's code.
fn complete_phone(s: &AuthState, pending: &Value) -> (u16, Value) {
    let (status, started) = post(
        s,
        &format!("{V2}/accounts/mfaSignIn:start"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
            "mfaEnrollmentId": pending["mfaInfo"][0]["mfaEnrollmentId"], "phoneSignInInfo": {}}),
    );
    if status != 200 {
        return (status, started);
    }
    post(
        s,
        &format!("{V2}/accounts/mfaSignIn:finalize"),
        &json!({"mfaPendingCredential": pending["mfaPendingCredential"],
            "phoneVerificationInfo": {"sessionInfo": started["phoneResponseInfo"]["sessionInfo"], "code": "123456"}}),
    )
}

/// Unfinished pending credentials still fill the budget: none is dropped to make room, the
/// next first factor is refused and the oldest one still completes (safety confirmation
/// review 2026-09-25, SF-2).
#[test]
fn strict_unfinished_pending_credentials_still_fill_the_budget() {
    let s = strict_phone_account("unfinished@example.com");
    let budget = fireemu_core_auth::mfa::MAX_PENDING_PER_USER;
    let first = pending_of(&s, "unfinished@example.com");
    for _ in 1..budget {
        pending_of(&s, "unfinished@example.com");
    }
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "unfinished@example.com", "password": "password123"}),
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        message(&body).is_some_and(|m| m.starts_with("QUOTA_EXCEEDED")),
        "{body}"
    );
    let (status, body) = complete_phone(&s, &first);
    assert_eq!(status, 200, "{body}");
}

/// What a dropped entry answers (CHANGELOG): a completed pending credential dropped at the
/// budget is `INVALID_PENDING_TOKEN`, and an expired enrollment session dropped at the budget
/// is `INVALID_SESSION_INFO`.
#[test]
fn strict_entries_dropped_at_the_budget_answer_as_unknown() {
    let s = strict_phone_account("dropped@example.com");
    let budget = fireemu_core_auth::mfa::MAX_PENDING_PER_USER;
    let completed = pending_of(&s, "dropped@example.com");
    let (status, body) = complete_phone(&s, &completed);
    assert_eq!(status, 200, "{body}");
    for _ in 1..=budget {
        pending_of(&s, "dropped@example.com");
    }
    let (status, body) = complete_phone(&s, &completed);
    assert_eq!(status, 400, "{body}");
    assert_eq!(v2_refusal(&body).0, "INVALID_PENDING_TOKEN", "{body}");

    let s = strict_mfa_state();
    let token = verified_session(&s, "dropped-session@example.com");
    let start = |token: &str| {
        post(
            &s,
            &format!("{V2}/accounts/mfaEnrollment:start"),
            &json!({"idToken": token, "totpEnrollmentInfo": {}}),
        )
    };
    let (status, oldest) = start(&token);
    assert_eq!(status, 200, "{oldest}");
    // The oldest session expires first, so it is the one dropped.
    advance(&s, 1);
    for _ in 1..budget {
        assert_eq!(start(&token).0, 200);
    }
    advance(&s, 901);
    let (status, signed_in) = password_sign_in(&s, "dropped-session@example.com", "password123");
    assert_eq!(status, 200, "{signed_in}");
    let fresh = signed_in["idToken"].as_str().unwrap();
    assert_eq!(start(fresh).0, 200);
    let (status, body) =
        finalize_totp(&s, fresh, &oldest, &totp_code_of(&s, &oldest, 0), Some("A"));
    assert_eq!(status, 400, "{body}");
    assert_eq!(v2_refusal(&body).0, "INVALID_SESSION_INFO", "{body}");
}

/// The emulator profile spends a test number's enrollment session too, as the official
/// emulator spends every session (mutation follow-up, docs.local/mutation/auth-mfa/20260925).
#[test]
fn emulator_a_test_numbers_enrollment_session_is_single_use() {
    let s = state();
    let (status, body) = patch_sign_in(
        &s,
        "signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505550101": "123456"}}}}),
    );
    assert_eq!(status, 200, "{body}");
    let token = verified_session(&s, "emulator-test-number@example.com");
    let (status, started) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
    );
    assert_eq!(status, 200, "{started}");
    let finalize = json!({"idToken": token, "phoneVerificationInfo": {
        "sessionInfo": started["phoneSessionInfo"]["sessionInfo"], "code": "123456"}});
    let (status, enrolled) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &finalize,
    );
    assert_eq!(status, 200, "{enrolled}");
    let (status, again) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &finalize,
    );
    assert_eq!(status, 400, "{again}");
    assert!(
        message(&again).is_some_and(|m| m.starts_with("INVALID_SESSION_INFO")),
        "{again}"
    );
}

/// A masked `mfa` update without a value resets the project's multi-factor config to its
/// default, as a field mask clears a field the request leaves out (mutation follow-up,
/// docs.local/mutation/auth-mfa/20260925).
#[test]
fn a_masked_mfa_update_without_a_value_resets_the_config() {
    for body in [json!({"mfa": null}), json!({})] {
        let s = strict_mfa_state();
        let (status, body) = admin(
            &s,
            "PATCH",
            &format!("{PROJECT_CONFIG}?updateMask=mfa"),
            &body,
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["mfa"], json!({"state": "DISABLED"}), "{body}");
    }
}

/// Strict checks the session before the display name: an unknown session without a display
/// name is `INVALID_SESSION_INFO` (auth-mfa/totp/enroll#finalize-missing-session; mutation
/// follow-up, docs.local/mutation/auth-mfa/20260925).
#[test]
fn strict_an_unknown_enrollment_session_is_refused_before_the_display_name() {
    let s = strict_mfa_state();
    let token = verified_session(&s, "unknown-session@example.com");
    start_totp(&s, &token);
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &json!({"idToken": token, "totpVerificationInfo": {"sessionInfo": "enroll-not-a-session", "verificationCode": "123456"}}),
    );
    assert_eq!(
        (status, v2_refusal(&body).0),
        (400, "INVALID_SESSION_INFO"),
        "{body}"
    );
}

/// A deleted account's pending credential answers `USER_NOT_FOUND` for the hour a pending
/// credential lives and is unknown after it; the sweep drops only the expired ones (mutation
/// follow-up, docs.local/mutation/auth-mfa/20260925).
#[test]
fn strict_a_deleted_accounts_pending_credential_is_known_for_its_hour() {
    let refusal = |s: &AuthState, pending: &Value| {
        let (status, body) = totp_sign_in(s, pending, &json!("any-factor"), "123456");
        assert_eq!(status, 400, "{body}");
        v2_refusal(&body).0.to_owned()
    };
    let delete = |s: &AuthState, pending: &Value| {
        let (status, body) = admin(
            s,
            "POST",
            &format!("{ADMIN}/accounts:delete"),
            &json!({"localId": pending["localId"]}),
        );
        assert_eq!(status, 200, "{body}");
    };
    // One orphan, past its hour: swept.
    let s = strict_phone_account("orphan@example.com");
    let pending = pending_of(&s, "orphan@example.com");
    delete(&s, &pending);
    advance(&s, 3_600);
    assert_eq!(refusal(&s, &pending), "USER_NOT_FOUND");
    advance(&s, 1);
    assert_eq!(refusal(&s, &pending), "INVALID_PENDING_TOKEN");
    // Two orphans half an hour apart: when the first is swept the second stays.
    let s = strict_phone_account("first-orphan@example.com");
    create(
        &s,
        &json!({"email": "second-orphan@example.com", "password": "password123", "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+16505550101"}]}),
    );
    let first = pending_of(&s, "first-orphan@example.com");
    delete(&s, &first);
    advance(&s, 1_800);
    let second = pending_of(&s, "second-orphan@example.com");
    delete(&s, &second);
    advance(&s, 1_801);
    assert_eq!(refusal(&s, &first), "INVALID_PENDING_TOKEN");
    assert_eq!(refusal(&s, &second), "USER_NOT_FOUND");
}

/// Emulator profile: a pending sign-in is reaped after its hour, also when another pending
/// sign-in of the same user succeeded with its phone factor first (mutation follow-up,
/// docs.local/mutation/auth-mfa/20260925).
#[test]
fn emulator_a_pending_sign_in_is_reaped_after_its_sibling_succeeds_by_phone() {
    let s = state();
    let (status, body) = patch_sign_in(
        &s,
        "signIn.phoneNumber.testPhoneNumbers",
        &json!({"signIn": {"phoneNumber": {"testPhoneNumbers": {"+16505550101": "123456"}}}}),
    );
    assert_eq!(status, 200, "{body}");
    create(
        &s,
        &json!({"email": "siblings@example.com", "password": "password123", "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+16505550101"}]}),
    );
    let first = pending_of(&s, "siblings@example.com");
    let second = pending_of(&s, "siblings@example.com");
    let (status, body) = complete_phone(&s, &first);
    assert_eq!(status, 200, "{body}");
    advance(&s, 3_601);
    let (status, body) = complete_phone(&s, &second);
    assert_eq!(status, 400, "{body}");
}

// ---- AUTH-MFA follow-up directive (2026-09-25), Must 1: strict with auth.totp fails closed ----

/// Strict: the fireemu-only `auth.totp` extension alone does not turn TOTP on; production
/// refuses a TOTP start while the project's `mfa` config does not enable it
/// (`auth-mfa/disabled#totp-start`).
#[test]
fn strict_auth_totp_alone_does_not_enable_totp_enrollment() {
    let s = AuthState {
        totp_extension_enabled: true,
        ..strict_state()
    };
    let token = verified_session(&s, "extension-only@example.com");
    let (status, body) = post(
        &s,
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": token, "totpEnrollmentInfo": {}}),
    );
    assert_eq!(
        (status, v2_refusal(&body).0),
        (400, "OPERATION_NOT_ALLOWED : TOTP based MFA not enabled."),
        "{body}"
    );
}

/// Strict fails closed: an account with a TOTP factor is asked for it even while the project's
/// `mfa` config is off. Production skips an enrolled factor only in the observed case, a phone
/// factor under an off config (`auth-mfa/disabled#sign-in-a-with-factor`).
#[test]
fn strict_an_enrolled_totp_factor_is_asked_for_while_mfa_is_off() {
    let s = strict_mfa_state();
    let (_, _, _) = totp_enrolled(&s, "totp-then-off@example.com");
    set_project_mfa(&s, &json!({"state": "DISABLED"}));
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "totp-then-off@example.com", "password": "password123", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["mfaPendingCredential"].is_string(), "{body}");
    assert!(body.get("idToken").is_none(), "{body}");
    // The observed case stays: a phone factor alone is not asked for while MFA is off.
    create(
        &s,
        &json!({"email": "phone-while-off@example.com", "password": "password123", "emailVerified": true,
            "mfaInfo": [{"phoneInfo": "+16505550101"}]}),
    );
    let (status, body) = post(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "phone-while-off@example.com", "password": "password123", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["idToken"].is_string(), "{body}");
}
