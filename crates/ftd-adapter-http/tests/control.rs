//! Control API: rules hot reload, session reset hooks, origin guard.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_http::control::{handle, handle_with, ControlState};
use ftd_adapter_http::identity_toolkit::RequestHeaders;
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::edition::FirestoreEdition;
use ftd_core_types::time::LogicalInstant;
use serde_json::json;

fn state(counter: Arc<AtomicUsize>) -> ControlState {
    ControlState {
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        require_demo_prefix: true,
        edition: FirestoreEdition::Standard,
        capabilities: json!({"schemaVersion": 1}),
        rules: Arc::new(RwLock::new(LoadedRules::default())),
        storage_rules: Arc::new(RwLock::new(LoadedRules::default())),
        reset_hooks: vec![Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })],
        functions: None,
    }
}

#[test]
fn rules_can_be_loaded_replaced_and_dropped_at_runtime() {
    let s = state(Arc::new(AtomicUsize::new(0)));
    let r = handle(&s, "GET", "/v1/rules", &json!({}));
    assert_eq!(r.body["loaded"], false);
    let bad = handle(
        &s,
        "PUT",
        "/v1/rules",
        &json!({"source": "service cloud.firestore { match"}),
    );
    assert_eq!(bad.status, 400);
    let good = handle(
        &s,
        "PUT",
        "/v1/rules",
        &json!({"source": "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /{doc=**} { allow read: if true; } } }"}),
    );
    assert_eq!(good.status, 200, "{}", good.body);
    assert!(s.rules.read().unwrap().is_loaded());
    assert_eq!(
        handle(&s, "GET", "/v1/rules", &json!({})).body["loaded"],
        true
    );
    assert_eq!(handle(&s, "DELETE", "/v1/rules", &json!({})).status, 200);
    assert!(!s.rules.read().unwrap().is_loaded());
}

#[test]
fn session_reset_runs_every_hook_and_foreign_origins_are_refused() {
    let counter = Arc::new(AtomicUsize::new(0));
    let s = state(counter.clone());
    let r = handle(&s, "POST", "/v1/sessions/default/reset", &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    let foreign = RequestHeaders {
        origin: Some("https://evil.example".to_owned()),
        ..RequestHeaders::default()
    };
    assert_eq!(
        handle_with(
            &s,
            "POST",
            "/v1/sessions/default/reset",
            &foreign,
            &json!({})
        )
        .status,
        403
    );
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    let local = RequestHeaders {
        origin: Some("http://127.0.0.1:5173".to_owned()),
        ..RequestHeaders::default()
    };
    assert_eq!(
        handle_with(&s, "GET", "/health/live", &local, &json!({})).status,
        200
    );
}
