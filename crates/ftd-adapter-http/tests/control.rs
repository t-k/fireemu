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
        control_token: "test-token".to_owned(),
        barrier: None,
        snapshot_hooks: Vec::new(),
        snapshots: Mutex::new(std::collections::BTreeMap::new()),
        faults: Some(Arc::new(Mutex::new(
            ftd_core_session::fault::FaultState::default(),
        ))),
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

#[test]
fn browser_requests_need_the_control_token_on_privileged_routes() {
    let counter = Arc::new(AtomicUsize::new(0));
    let s = state(counter.clone());
    let page = RequestHeaders {
        origin: Some("http://localhost:5173".to_owned()),
        ..RequestHeaders::default()
    };
    // A page on localhost cannot reset or move the clock without the token.
    let r = handle_with(&s, "POST", "/v1/sessions/default/reset", &page, &json!({}));
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    let r = handle_with(
        &s,
        "POST",
        "/v1/sessions/default/clock:advance",
        &page,
        &json!({"seconds": 1}),
    );
    assert_eq!(r.status, 403);
    // Reads stay open to pages; the token unlocks the rest.
    assert_eq!(
        handle_with(&s, "GET", "/v1/sessions/default", &page, &json!({})).status,
        200
    );
    let with_token = RequestHeaders {
        origin: Some("http://localhost:5173".to_owned()),
        authorization: Some("Bearer test-token".to_owned()),
        ..RequestHeaders::default()
    };
    let r = handle_with(
        &s,
        "POST",
        "/v1/sessions/default/reset",
        &with_token,
        &json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    // Command-line clients on loopback (no Origin) are not asked for it.
    assert_eq!(
        handle(&s, "POST", "/v1/sessions/default/reset", &json!({})).status,
        200
    );
}

/// A hook whose state is a string; restore reports what it was given.
struct Slot(Mutex<String>);

impl ftd_adapter_http::control::SnapshotHook for Slot {
    fn name(&self) -> &'static str {
        "slot"
    }
    fn capture(&self) -> ftd_adapter_http::control::SnapshotPart {
        Arc::new(self.0.lock().unwrap().clone())
    }
    fn restore(&self, part: &ftd_adapter_http::control::SnapshotPart) -> Result<(), String> {
        let value = part.downcast_ref::<String>().ok_or("not a string")?;
        self.0.lock().unwrap().clone_from(value);
        Ok(())
    }
}

#[test]
fn snapshots_capture_every_part_and_restore_them_atomically() {
    let slot = Arc::new(Slot(Mutex::new("one".to_owned())));
    let mut s = state(Arc::new(AtomicUsize::new(0)));
    s.snapshot_hooks = vec![slot.clone()];
    let bad = handle(&s, "POST", "/v1/sessions/default/snapshots", &json!({}));
    assert_eq!(bad.status, 400);
    let bad = handle(
        &s,
        "POST",
        "/v1/sessions/default/snapshots",
        &json!({"name": "no spaces here"}),
    );
    assert_eq!(bad.status, 400);
    let r = handle(
        &s,
        "POST",
        "/v1/sessions/default/snapshots",
        &json!({"name": "base"}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["parts"], json!(["slot"]));
    assert_eq!(r.body["replaced"], false);
    *slot.0.lock().unwrap() = "two".to_owned();
    let list = handle(&s, "GET", "/v1/sessions/default/snapshots", &json!({}));
    assert_eq!(list.body["snapshots"][0]["name"], "base");
    let r = handle(
        &s,
        "POST",
        "/v1/sessions/default/snapshots/base:restore",
        &json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(*slot.0.lock().unwrap(), "one");
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots/nothing:restore",
            &json!({})
        )
        .status,
        404
    );
    // Overwriting keeps one entry; deleting removes it.
    *slot.0.lock().unwrap() = "three".to_owned();
    let r = handle(
        &s,
        "POST",
        "/v1/sessions/default/snapshots",
        &json!({"name": "base"}),
    );
    assert_eq!(r.body["replaced"], true);
    assert_eq!(
        handle(
            &s,
            "DELETE",
            "/v1/sessions/default/snapshots/base",
            &json!({})
        )
        .status,
        200
    );
    assert_eq!(
        handle(
            &s,
            "DELETE",
            "/v1/sessions/default/snapshots/base",
            &json!({})
        )
        .status,
        404
    );
    assert!(
        handle(&s, "GET", "/v1/sessions/default/snapshots", &json!({})).body["snapshots"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn fault_plans_are_validated_installed_reported_and_removed() {
    let s = state(Arc::new(AtomicUsize::new(0)));
    for bad in [
        json!({}),
        json!({"rules": [{"match": {"operation": "firestore.nothing"}, "action": {"type": "timeout"}}]}),
        json!({"rules": [{"match": {"operation": "firestore.commit", "nth": 0}, "action": {"type": "timeout"}}]}),
        json!({"rules": [{"match": {"operation": "firestore.commit"}, "action": {"type": "returnError"}}]}),
        json!({"rules": [{"match": {"operation": "functions.invoke"}, "action": {"type": "explode"}}]}),
        json!({"rules": [{"match": {"operation": "functions.deliver"}, "action": {"type": "duplicate", "count": 1000}}]}),
    ] {
        let r = handle(&s, "PUT", "/v1/sessions/default/faultPlan", &bad);
        assert_eq!(r.status, 400, "{bad}");
    }
    let plan = json!({"seed": 7, "rules": [
        {"match": {"operation": "firestore.commit", "nth": 3}, "action": {"type": "returnError", "code": "ABORTED"}},
        {"match": {"operation": "functions.invoke", "function": "flaky"}, "action": {"type": "crashRunner"}},
        {"match": {"operation": "functions.deliver", "eventType": "google.cloud.storage.object.v1.finalized"}, "action": {"type": "duplicate", "count": 2}}
    ]});
    let r = handle(&s, "PUT", "/v1/sessions/default/faultPlan", &plan);
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["rules"], 3);
    // Something fires: the adapters would call decide; here through the shared state.
    s.faults
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .decide("firestore.commit", None, None);
    let r = handle(&s, "GET", "/v1/sessions/default/faultPlan", &json!({}));
    assert_eq!(r.body["plan"]["seed"], 7);
    assert_eq!(r.body["plan"]["rules"][0]["match"]["nth"], 3);
    assert_eq!(r.body["plan"]["rules"][2]["action"]["count"], 2);
    assert_eq!(r.body["counters"]["firestore.commit"], 1);
    assert!(r.body["fired"].as_array().unwrap().is_empty());
    let r = handle(&s, "DELETE", "/v1/sessions/default/faultPlan", &json!({}));
    assert_eq!(r.status, 200);
    let r = handle(&s, "GET", "/v1/sessions/default/faultPlan", &json!({}));
    assert!(r.body["plan"].is_null());
}
