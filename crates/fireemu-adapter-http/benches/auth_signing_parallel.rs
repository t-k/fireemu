//! Measures whether RS256 response signing scales after the Auth store lock is released.

use std::hint::black_box;
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use fireemu_adapter_http::identity_toolkit::{handle, AuthState, FakeCustomTokenExpiry};
use fireemu_adapter_http::signing::RsaSigner;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::json;

const REQUESTS: usize = 64;
const SAMPLES: usize = 5;

fn state() -> Arc<AuthState> {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    store.set_signer(RsaSigner::from_seed(42).expect("RSA key"));
    let state = Arc::new(AuthState {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        tenancy: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Ignore,
        app_check: None,
        app_check_policy: None,
    });
    for index in 0..REQUESTS {
        let response = handle(
            &state,
            "POST",
            "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k",
            &json!({
                "email": format!("parallel-{index}@example.com"),
                "password": "password1",
            }),
        );
        assert_eq!(response.status, 200, "{}", response.body);
    }
    state
}

fn timed_sign_ins(state: &Arc<AuthState>, workers: usize) -> Duration {
    let barrier = Arc::new(Barrier::new(workers));
    let started = Instant::now();
    std::thread::scope(|scope| {
        for worker in 0..workers {
            let state = Arc::clone(state);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                for index in (worker..REQUESTS).step_by(workers) {
                    let response = handle(
                        &state,
                        "POST",
                        "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=k",
                        &json!({
                            "email": format!("parallel-{index}@example.com"),
                            "password": "password1",
                            "returnSecureToken": true,
                        }),
                    );
                    assert_eq!(response.status, 200, "{}", response.body);
                    black_box(response);
                }
            });
        }
    });
    started.elapsed()
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn main() {
    let sequential_state = state();
    let parallel_state = state();
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(8);
    let sequential = median(
        (0..SAMPLES)
            .map(|_| timed_sign_ins(&sequential_state, 1))
            .collect(),
    );
    let parallel = median(
        (0..SAMPLES)
            .map(|_| timed_sign_ins(&parallel_state, workers))
            .collect(),
    );
    println!(
        "auth_signing_parallel: {REQUESTS} sign-ins; 1 worker {sequential:?}; {workers} workers {parallel:?}; speedup {:.2}x",
        sequential.as_secs_f64() / parallel.as_secs_f64()
    );
}
