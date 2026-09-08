//! Guards Auth request latency against accidental full-user-store scans.

use std::hint::black_box;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthQueryLimits, AuthState, FakeCustomTokenExpiry, RequestHeaders,
    OWNER_CREDENTIAL,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;

const SMALL_USERS: usize = 1_000;
const LARGE_USERS: usize = 100_000;
const SAMPLES: usize = 9;

fn state(users: usize) -> AuthState {
    let now = LogicalInstant::from_unix_seconds(1_788_004_860);
    let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
    let mut target = None;
    for index in 0..users {
        let id = format!("user-{index:06}");
        target = Some(
            store
                .create_user_with_id(NewUser::anonymous(), Some(&id), now)
                .expect("unique fixture user"),
        );
    }
    // Keep the targets at the end of BTreeMap iteration so this benchmark catches a
    // regression to the previous `values().find(...)` implementation.
    let target = target.expect("benchmark has at least one user");
    store.set_email(&target, "target@example.com").unwrap();
    store.set_password(&target, "password1", now).unwrap();
    store
        .set_phone_number(&target, Some("+15550000001"))
        .unwrap();
    let _ = store.take_user_events();
    AuthState {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(Mutex::new(VirtualClock::new(now))),
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
        fake_custom_token_expiry: FakeCustomTokenExpiry::Ignore,
        query_limits: AuthQueryLimits::EmulatorUnbounded,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    }
}

fn median_per_call(mut samples: Vec<Duration>, calls: u32) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2] / calls
}

fn elapsed(mut operation: impl FnMut(), calls: u32) -> Duration {
    let started = Instant::now();
    for _ in 0..calls {
        operation();
    }
    started.elapsed()
}

fn measure_pair(
    mut small: impl FnMut(),
    mut large: impl FnMut(),
    calls: u32,
) -> (Duration, Duration, f64) {
    for _ in 0..64 {
        small();
        large();
    }
    let mut small_samples = Vec::with_capacity(SAMPLES);
    let mut large_samples = Vec::with_capacity(SAMPLES);
    let mut ratios = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let (small_elapsed, large_elapsed) = if sample % 2 == 0 {
            (elapsed(&mut small, calls), elapsed(&mut large, calls))
        } else {
            let large_elapsed = elapsed(&mut large, calls);
            (elapsed(&mut small, calls), large_elapsed)
        };
        ratios.push(ratio(large_elapsed, small_elapsed));
        small_samples.push(small_elapsed);
        large_samples.push(large_elapsed);
    }
    ratios.sort_by(f64::total_cmp);
    (
        median_per_call(small_samples, calls),
        median_per_call(large_samples, calls),
        ratios[ratios.len() / 2],
    )
}

fn sign_in(state: &AuthState) {
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
    assert_eq!(response.status, 200, "{}", response.body);
    black_box(response);
}

fn phone_lookup(state: &AuthState, expected_local_id: &str) {
    let response = handle_with(
        state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/projects/demo-app/accounts:lookup",
        &RequestHeaders {
            authorization: Some(OWNER_CREDENTIAL.to_owned()),
            ..RequestHeaders::default()
        },
        &json!({"phoneNumber": ["+15550000001"]}),
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["users"][0]["localId"], expected_local_id);
    black_box(response);
}

fn first_user_page(state: &AuthState) {
    let response = handle_with(
        state,
        "GET",
        "/identitytoolkit.googleapis.com/v1/projects/demo-app/accounts:batchGet?maxResults=1000",
        &RequestHeaders {
            authorization: Some(OWNER_CREDENTIAL.to_owned()),
            ..RequestHeaders::default()
        },
        &json!({}),
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body["users"].as_array().map(Vec::len), Some(1000));
    black_box(response);
}

fn ratio(large: Duration, small: Duration) -> f64 {
    large.as_secs_f64() / small.as_secs_f64()
}

fn main() {
    let small = state(SMALL_USERS);
    let large = state(LARGE_USERS);
    let small_target = format!("user-{:06}", SMALL_USERS - 1);
    let large_target = format!("user-{:06}", LARGE_USERS - 1);
    let (small_sign_in, large_sign_in, sign_in_ratio) =
        measure_pair(|| sign_in(&small), || sign_in(&large), 8_192);
    let (small_lookup, large_lookup, lookup_ratio) = measure_pair(
        || phone_lookup(&small, &small_target),
        || phone_lookup(&large, &large_target),
        8_192,
    );
    let (small_page, large_page, page_ratio) =
        measure_pair(|| first_user_page(&small), || first_user_page(&large), 16);
    println!(
        "auth_index_scaling (100k/1k): sign-in {large_sign_in:?}/{small_sign_in:?} ({sign_in_ratio:.2}x), phone lookup {large_lookup:?}/{small_lookup:?} ({lookup_ratio:.2}x), 1000-user page {large_page:?}/{small_page:?} ({page_ratio:.2}x)",
    );
    for (name, measured_ratio) in [
        ("sign-in", sign_in_ratio),
        ("phone lookup", lookup_ratio),
        ("batchGet page", page_ratio),
    ] {
        assert!(
            measured_ratio <= 1.20,
            "{name} latency grew by more than 20% from 1,000 to 100,000 users"
        );
    }
}
