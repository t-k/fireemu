//! Control API: rules hot reload, session reset hooks, origin guard.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_http::control::{handle, handle_with, ControlState};
use ftd_adapter_http::identity_toolkit::RequestHeaders;
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::edition::FirestoreEdition;
use ftd_core_types::time::LogicalInstant;
use serde_json::{json, Value};

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
        text_indexes: Arc::new(Mutex::new(
            ftd_core_firestore::text_index::TextIndexSet::default(),
        )),
        default_project: "demo-app".to_owned(),
        sessions: Mutex::new(std::collections::BTreeMap::from([(
            "default".to_owned(),
            "demo-app".to_owned(),
        )])),
        project_hooks: None,
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

struct FakeFunctions(Mutex<Vec<(String, Vec<Value>)>>);

impl ftd_adapter_http::control::FunctionsHook for FakeFunctions {
    fn on_clock_changed(&self) {}
    fn run_schedule(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn is_idle(&self) -> bool {
        true
    }
    fn idle_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::new(tokio::sync::Notify::new())
    }
    fn status(&self) -> Value {
        json!({})
    }
    fn publish(&self, topic: &str, messages: &[Value]) -> Result<Vec<String>, String> {
        self.0
            .lock()
            .unwrap()
            .push((topic.to_owned(), messages.to_vec()));
        Ok(messages.iter().map(|_| "m".to_owned()).collect())
    }
    fn project(&self) -> String {
        "demo-app".to_owned()
    }
}

#[test]
fn pubsub_publish_routes_check_the_project_and_the_message_shape() {
    let published = Arc::new(FakeFunctions(Mutex::new(Vec::new())));
    let mut s = state(Arc::new(AtomicUsize::new(0)));
    s.functions = Some(published.clone());
    let ok =
        json!({"messages": [{"data": "aGVsbG8=", "attributes": {"k": "v"}, "orderingKey": "k1"}]});
    assert_eq!(
        handle(&s, "POST", "/v1/projects/demo-app/topics/jobs:publish", &ok).status,
        200
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/projects/other-app/topics/jobs:publish",
            &ok
        )
        .status,
        404
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/default/pubsub/topics/jobs:publish",
            &ok
        )
        .status,
        200
    );
    for bad in [
        json!({"messages": [{"data": "not base64!"}]}),
        json!({"messages": [{"data": "aGVsbG8=", "orderingKey": 5}]}),
        json!({"messages": [{"data": "aGVsbG8=", "attributes": {"k": 1}}]}),
        json!({"messages": "x"}),
    ] {
        assert_eq!(
            handle(
                &s,
                "POST",
                "/v1/projects/demo-app/topics/jobs:publish",
                &bad
            )
            .status,
            400,
            "{bad}"
        );
    }
    // A `json` value is encoded for the function.
    let r = handle(
        &s,
        "POST",
        "/v1/projects/demo-app/topics/jobs:publish",
        &json!({"messages": [{"json": {"a": 1}}]}),
    );
    assert_eq!(r.status, 200);
    let calls = published.0.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].1[0]["data"], "eyJhIjoxfQ==");
}

#[test]
fn text_index_definitions_are_loaded_listed_and_lifecycle_actions_are_unimplemented() {
    let mut s = state(Arc::new(AtomicUsize::new(0)));
    let entry = |id: &str, field: &str, language: &str| {
        json!({
            "index": {
                "name": format!("projects/demo-app/databases/(default)/collectionGroups/products/indexes/{id}"),
                "queryScope": "COLLECTION",
                "apiScope": "ANY_API",
                "fields": [{"fieldPath": field, "searchConfig": {"textSpec": {"indexSpecs": [{"indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"}]}}}],
                "searchIndexOptions": {"textLanguage": language, "textLanguageOverrideFieldPath": "language"}
            },
            "xFirebaseTestd": {"state": "READY", "buildPolicy": "validation-only"}
        })
    };
    let base = "/v1/sessions/default/firestore/text-indexes";
    // Standard edition: refused.
    let r = handle(
        &s,
        "POST",
        &format!("{base}:load"),
        &json!({"indexes": [entry("t1", "title", "ja")]}),
    );
    assert_eq!(r.status, 400, "{}", r.body);
    s.edition = FirestoreEdition::Enterprise;
    // A bad entry rejects the whole file; nothing is kept.
    let r = handle(
        &s,
        "POST",
        &format!("{base}:load"),
        &json!({"indexes": [entry("t1", "title", "ja"), entry("t2", "title", "japanese")]}),
    );
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(r.body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("indexes[1]"));
    assert!(handle(&s, "GET", base, &json!({})).body["indexes"]
        .as_array()
        .unwrap()
        .is_empty());
    let r = handle(
        &s,
        "POST",
        &format!("{base}:load"),
        &json!({"indexes": [entry("t1", "title", "ja"), entry("t2", "body", "en-US")]}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["total"], 2);
    // One more through POST; a duplicate id and a duplicate shape.
    let r = handle(&s, "POST", base, &entry("t1", "other", "ja"));
    assert_eq!(r.status, 400);
    let r = handle(&s, "POST", base, &entry("t3", "title", "ja"));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.body["warnings"],
        json!(["FS_TEXT_DUPLICATE_INDEX_DEFINITION"])
    );
    // Unsupported options are refused rather than ignored; unknown local keys too.
    let mut unique = entry("t4", "title", "ja");
    unique["index"]["unique"] = json!(true);
    assert_eq!(handle(&s, "POST", base, &unique).status, 400);
    let mut local = entry("t5", "title", "ja");
    local["xFirebaseTestd"]["shards"] = json!(3);
    assert_eq!(handle(&s, "POST", base, &local).status, 400);
    let one = handle(&s, "GET", &format!("{base}/t2"), &json!({}));
    assert_eq!(one.status, 200);
    assert_eq!(one.body["textLanguage"], "en-US");
    assert_eq!(one.body["languageOverride"]["field"], "language");
    assert_eq!(one.body["fidelity"], "strict-validation-only");
    for action in ["advanceBackfill", "completeBackfill", "failBuild", "repair"] {
        let r = handle(&s, "POST", &format!("{base}/t2:{action}"), &json!({}));
        assert_eq!(r.status, 501, "{action}");
    }
    assert_eq!(
        handle(&s, "GET", &format!("{base}/t2"), &json!({})).body["state"],
        "READY"
    );
    assert_eq!(
        handle(&s, "DELETE", &format!("{base}/t2"), &json!({})).status,
        200
    );
    assert_eq!(
        handle(&s, "GET", &format!("{base}/t2"), &json!({})).status,
        404
    );
    assert_eq!(
        handle(&s, "GET", base, &json!({})).body["indexes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

struct ProjectLog(Mutex<Vec<String>>);

impl ftd_adapter_http::control::ProjectHooks for ProjectLog {
    fn create(&self, project: &str) -> Result<(), String> {
        self.0.lock().unwrap().push(format!("create {project}"));
        Ok(())
    }
    fn reset(&self, project: &str) {
        self.0.lock().unwrap().push(format!("reset {project}"));
    }
    fn remove(&self, project: &str) {
        self.0.lock().unwrap().push(format!("remove {project}"));
    }
}

#[test]
fn sessions_are_created_listed_reset_and_deleted_per_project() {
    let log = Arc::new(ProjectLog(Mutex::new(Vec::new())));
    let counter = Arc::new(AtomicUsize::new(0));
    let mut s = state(counter.clone());
    s.project_hooks = Some(log.clone());
    // Validation: project shape, demo- prefix, duplicates.
    for bad in [
        json!({}),
        json!({"project": "Bad_Project"}),
        json!({"project": "other-app"}),
    ] {
        assert_eq!(
            handle(&s, "POST", "/v1/sessions", &bad).status,
            400,
            "{bad}"
        );
    }
    let r = handle(&s, "POST", "/v1/sessions", &json!({"project": "demo-b"}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["name"], "demo-b");
    assert_eq!(
        handle(&s, "POST", "/v1/sessions", &json!({"project": "demo-b"})).status,
        409
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions",
            &json!({"name": "second", "project": "demo-b"})
        )
        .status,
        409
    );
    let list = handle(&s, "GET", "/v1/sessions", &json!({}));
    assert_eq!(
        list.body["sessions"],
        json!([{"name": "default", "project": "demo-app"}, {"name": "demo-b", "project": "demo-b"}])
    );
    let info = handle(&s, "GET", "/v1/sessions/demo-b", &json!({}));
    assert_eq!(info.status, 200, "{}", info.body);
    assert_eq!(
        handle(&s, "GET", "/v1/sessions/nothing", &json!({})).status,
        404
    );
    // Reset of the extra session wipes only its project; the default reset runs the hooks.
    let r = handle(&s, "POST", "/v1/sessions/demo-b/reset", &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["scope"], "project");
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert_eq!(
        handle(&s, "POST", "/v1/sessions/default/reset", &json!({})).status,
        200
    );
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        handle(&s, "DELETE", "/v1/sessions/default", &json!({})).status,
        400
    );
    assert_eq!(
        handle(&s, "DELETE", "/v1/sessions/demo-b", &json!({})).status,
        200
    );
    assert_eq!(
        handle(&s, "GET", "/v1/sessions/demo-b", &json!({})).status,
        404
    );
    assert_eq!(
        *log.0.lock().unwrap(),
        vec!["create demo-b", "reset demo-b", "remove demo-b"]
    );
}
