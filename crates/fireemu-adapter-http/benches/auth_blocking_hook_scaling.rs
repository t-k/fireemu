//! Measures how a sign-in that runs a blocking function scales with the size of the Auth
//! store: the speculative candidate and the commit must not copy every user, index entry or
//! refresh session the store holds.

use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fireemu_adapter_http::identity_toolkit::{
    handle, AuthBlockingHook, AuthQueryLimits, AuthState, BlockingFunctionFailure,
    ClientApiKeyPolicy, FakeCustomTokenExpiry, IdpAssertionPolicy, IdpContinuationPolicy,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser, UserRecord};
use fireemu_core_functions::manifest::BlockingAuthEvent;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;

const NOW: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const SAMPLES: usize = 15;

struct Passthrough;

impl AuthBlockingHook for Passthrough {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &UserRecord,
    ) -> Result<serde_json::Value, BlockingFunctionFailure> {
        Ok(json!({}))
    }
}

/// A store of `users` email accounts (each with a distinct email and phone, so the indexes
/// grow with the store) plus `sessions` refresh sessions, and the signing-in account.
fn state(users: usize, sessions: usize) -> AuthState {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
    for index in 0..users {
        let uid = store
            .create_user(
                NewUser::email(&format!("fixture-{index:06}@example.com")),
                NOW,
            )
            .expect("unique fixture user");
        store
            .set_phone_number(&uid, Some(&format!("+1555{index:07}")))
            .expect("unique fixture phone");
    }
    let target = store
        .create_user(NewUser::email("target@example.com"), NOW)
        .expect("target user");
    store.set_password(&target, "password1", NOW).unwrap();
    for _ in 0..sessions {
        store.issue_refresh_token(&target, NOW).unwrap();
    }
    AuthState {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(Mutex::new(VirtualClock::new(NOW))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        notices: None,
        blocking: Some(Arc::new(Passthrough)),
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        tenancy: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        idp_continuations: IdpContinuationPolicy::Disabled,
        query_limits: AuthQueryLimits::EmulatorUnbounded,
        client_api_key: ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        allow_unsigned_custom_tokens: true,
        idp_assertions: IdpAssertionPolicy::Fixture,
        app_check: None,
        app_check_policy: None,
    }
}

fn sign_in(state: &AuthState) -> Duration {
    let started = Instant::now();
    let response = handle(
        state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=k",
        &json!({
            "email": "target@example.com",
            "password": "password1",
            "returnSecureToken": true,
        }),
    );
    let elapsed = started.elapsed();
    assert_eq!(response.status, 200, "{}", response.body);
    black_box(response);
    elapsed
}

fn median(users: usize, sessions: usize, hooked: bool) -> Duration {
    let mut state = state(users, sessions);
    if !hooked {
        state.blocking = None;
    }
    sign_in(&state);
    let mut samples: Vec<Duration> = (0..SAMPLES).map(|_| sign_in(&state)).collect();
    samples.sort_unstable();
    samples[SAMPLES / 2]
}

fn main() {
    for (users, sessions) in [(10, 0), (10_000, 0), (10, 50_000), (10_000, 50_000)] {
        println!(
            "auth_blocking_hook_scaling: {users:>6} users {sessions:>6} sessions: hooked sign-in median {:?}, without a hook {:?}",
            median(users, sessions, true),
            median(users, sessions, false)
        );
    }
}
