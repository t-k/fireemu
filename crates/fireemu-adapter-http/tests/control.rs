//! Control API: rules hot reload, session reset hooks, origin guard.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_http::control::{
    handle, handle_with, ControlState, SnapshotHook, SnapshotPart, TransitionFailure,
    MAX_SNAPSHOTS_PER_SESSION,
};
use fireemu_adapter_http::identity_toolkit::RequestHeaders;
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::tenancy::Scope;
use fireemu_core_types::edition::FirestoreEdition;
use fireemu_core_types::time::LogicalInstant;
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
        app_check: None,
        barrier: None,
        snapshot_hooks: Vec::new(),
        snapshots: Mutex::new(std::collections::BTreeMap::new()),
        faults: Some(Arc::new(fireemu_core_session::fault::FaultRegistry::new())),
        text_indexes: Arc::new(Mutex::new(
            fireemu_core_firestore::text_index::TextIndexCatalog::default(),
        )),
        default_project: "demo-app".to_owned(),
        tenancy: Arc::new(RwLock::new(fireemu_core_session::tenancy::Tenancy::new(
            "demo-app",
        ))),
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

impl fireemu_adapter_http::control::SnapshotHook for Slot {
    fn name(&self) -> &'static str {
        "slot"
    }
    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        Ok(Arc::new(self.0.lock().unwrap().clone()))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<String>()
            .map(|_| ())
            .ok_or_else(|| TransitionFailure::new("slot", "not a string"))
    }
    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        let value = part
            .downcast_ref::<String>()
            .ok_or_else(|| TransitionFailure::new("slot", "not a string"))?;
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
        .for_project("demo-app")
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

impl fireemu_adapter_http::control::FunctionsHook for FakeFunctions {
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

/// A part only the default session carries.
struct SharedSlot;

impl SnapshotHook for SharedSlot {
    fn name(&self) -> &'static str {
        "shared"
    }
    fn shared(&self) -> bool {
        true
    }
    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        Ok(Arc::new(()))
    }
    fn validate(&self, _: &Scope, _: &SnapshotPart) -> Result<(), TransitionFailure> {
        Ok(())
    }
    fn restore(&self, _: &Scope, _: &SnapshotPart) -> Result<(), TransitionFailure> {
        Ok(())
    }
}

/// Records what the control routes asked of the project hooks; `fails` makes the next
/// `reset_scope` or `remove` report the named store instead of doing the work.
struct ProjectLog(Mutex<Vec<String>>, Mutex<Option<&'static str>>);

impl ProjectLog {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()), Mutex::new(None))
    }

    /// Every store transition asked of it, in order.
    fn entries(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    /// Makes every later lifecycle call report `part` and change nothing.
    fn fail_on(&self, part: &'static str) {
        *self.1.lock().unwrap() = Some(part);
    }

    /// Lets the lifecycle calls work again.
    fn recover(&self) {
        *self.1.lock().unwrap() = None;
    }

    fn failure(&self) -> Result<(), TransitionFailure> {
        match *self.1.lock().unwrap() {
            Some(part) => Err(TransitionFailure::new(part, "the store is poisoned")),
            None => Ok(()),
        }
    }
}

impl fireemu_adapter_http::control::ProjectHooks for ProjectLog {
    fn create(&self, project: &str) -> Result<(), String> {
        self.0.lock().unwrap().push(format!("create {project}"));
        Ok(())
    }
    fn reset_scope(&self, scope: &Scope) -> Result<(), TransitionFailure> {
        // A store that refuses the wipe is reported before anything is wiped, so the log
        // records nothing.
        self.failure()?;
        let what = scope.project().map_or("default".to_owned(), str::to_owned);
        self.0.lock().unwrap().push(format!("reset {what}"));
        Ok(())
    }
    fn remove(&self, project: &str) -> Result<(), TransitionFailure> {
        self.failure()?;
        self.0.lock().unwrap().push(format!("remove {project}"));
        Ok(())
    }
}

#[test]
fn sessions_are_created_listed_reset_and_deleted_per_project() {
    let log = Arc::new(ProjectLog::new());
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
        json!([{"name": "default", "project": "demo-app", "buckets": []}, {"name": "demo-b", "project": "demo-b", "buckets": []}])
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
        log.entries(),
        vec![
            "create demo-b",
            "reset demo-b",
            "reset demo-b",
            "reset default",
            "remove demo-b"
        ]
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn sessions_scope_resets_snapshots_fault_plans_and_text_indexes_per_project() {
    let log = Arc::new(ProjectLog::new());
    let mut s = state(Arc::new(AtomicUsize::new(0)));
    s.project_hooks = Some(log.clone());
    s.edition = FirestoreEdition::Enterprise;
    let slot = Arc::new(Slot(Mutex::new("owned".to_owned())));
    s.snapshot_hooks = vec![slot.clone(), Arc::new(SharedSlot)];
    // Buckets and API keys are registered with the session; conflicts are refused.
    let r = handle(
        &s,
        "POST",
        "/v1/sessions",
        &json!({"project": "demo-b", "buckets": ["shared-b"], "apiKeys": ["key-b"]}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["buckets"], json!(["shared-b"]));
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions",
            &json!({"project": "demo-c", "buckets": ["shared-b"]})
        )
        .status,
        409
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions",
            &json!({"project": "demo-c", "apiKeys": ["key-b"]})
        )
        .status,
        409
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions",
            &json!({"project": "demo-c", "buckets": ["Bad Bucket"]})
        )
        .status,
        400
    );
    assert!(s.tenancy.read().unwrap().is_registered("demo-b"));
    // Creation wipes what the default session held under the project; the default reset
    // wipes everything except the registered projects.
    assert_eq!(
        handle(&s, "POST", "/v1/sessions/default/reset", &json!({})).status,
        200
    );
    assert_eq!(
        handle(&s, "POST", "/v1/sessions/demo-b/reset", &json!({})).status,
        200
    );
    assert_eq!(
        log.entries().as_slice(),
        [
            "create demo-b",
            "reset demo-b",
            "reset default",
            "reset demo-b"
        ]
    );
    // Fault plans: one state per session; B's counters are not A's.
    let plan = json!({"rules": [{"match": {"operation": "firestore.commit", "nth": 1}, "action": {"type": "timeout"}}]});
    assert_eq!(
        handle(&s, "PUT", "/v1/sessions/demo-b/faultPlan", &plan).status,
        200
    );
    let registry = s.faults.as_ref().unwrap();
    assert!(registry
        .for_project("demo-app")
        .lock()
        .unwrap()
        .decide("firestore.commit", None, None)
        .is_empty());
    assert_eq!(
        registry
            .for_project("demo-b")
            .lock()
            .unwrap()
            .decide("firestore.commit", None, None)
            .len(),
        1
    );
    let r = handle(&s, "GET", "/v1/sessions/default/faultPlan", &json!({}));
    assert!(r.body["plan"].is_null(), "{}", r.body);
    let r = handle(&s, "GET", "/v1/sessions/demo-b/faultPlan", &json!({}));
    assert_eq!(r.body["fired"][0]["operation"], "firestore.commit");
    // A rule naming only an event type is a delivery rule; an action that does not apply
    // to its operation is refused.
    let r = handle(
        &s,
        "PUT",
        "/v1/sessions/default/faultPlan",
        &json!({"rules": [{"match": {"eventType": "google.cloud.firestore.document.v1.created"}, "action": {"type": "duplicate", "count": 1}}]}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let r = handle(&s, "GET", "/v1/sessions/default/faultPlan", &json!({}));
    assert_eq!(
        r.body["plan"]["rules"][0]["match"]["operation"],
        "functions.deliver"
    );
    let r = handle(
        &s,
        "PUT",
        "/v1/sessions/default/faultPlan",
        &json!({"rules": [{"match": {"operation": "firestore.read"}, "action": {"type": "crashRunner"}}]}),
    );
    assert_eq!(r.status, 400, "{}", r.body);
    // Snapshots belong to their session; a project session skips the shared parts.
    let r = handle(
        &s,
        "POST",
        "/v1/sessions/demo-b/snapshots",
        &json!({"name": "b1"}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["parts"], json!(["slot"]));
    assert_eq!(
        handle(&s, "GET", "/v1/sessions/default/snapshots", &json!({})).body["snapshots"],
        json!([])
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots/b1:restore",
            &json!({})
        )
        .status,
        404
    );
    let r = handle(
        &s,
        "POST",
        "/v1/sessions/default/snapshots",
        &json!({"name": "a1"}),
    );
    assert_eq!(r.body["parts"], json!(["slot", "shared"]));
    // Text indexes: a session defines only its own projects' and lists only those.
    let base = "/v1/sessions/demo-b/firestore/text-indexes";
    let def = |project: &str| {
        json!({"index": {
            "name": format!("projects/{project}/databases/(default)/collectionGroups/posts/indexes/t1"),
            "fields": [{"fieldPath": "body", "searchConfig": {"textSpec": {"indexSpecs": [{"indexType": "TOKENIZED"}]}}}]
        }})
    };
    assert_eq!(handle(&s, "POST", base, &def("demo-app")).status, 400);
    let r = handle(&s, "POST", base, &def("demo-b"));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        handle(
            &s,
            "GET",
            "/v1/sessions/default/firestore/text-indexes",
            &json!({})
        )
        .body["indexes"],
        json!([])
    );
    let listed = handle(&s, "GET", base, &json!({}));
    assert_eq!(listed.body["indexes"][0]["project"], "demo-b");
    // Strict validation: output-only and misspelled fields are refused.
    let mut with_state = def("demo-b");
    with_state["index"]["state"] = json!("NEEDS_REPAIR");
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/default/firestore/text-indexes",
            &with_state
        )
        .status,
        400
    );
    let mut misspelled = def("demo-app");
    misspelled["index"]["searchIndexOptions"] = json!({"textLangauge": "ja"});
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/default/firestore/text-indexes",
            &misspelled
        )
        .status,
        400
    );
    // Deleting the session drops its snapshots, fault plan, text indexes and tenancy.
    assert_eq!(
        handle(&s, "DELETE", "/v1/sessions/demo-b", &json!({})).status,
        200
    );
    assert!(!s.tenancy.read().unwrap().is_registered("demo-b"));
    assert!(s.text_indexes.lock().unwrap().is_empty());
    // Its fault state is gone: demo-b falls back to the default session's.
    assert!(Arc::ptr_eq(
        &registry.for_project("demo-b"),
        &registry.default_state()
    ));
}

#[test]
fn functions_routes_belong_to_the_default_session() {
    let mut s = state(Arc::new(AtomicUsize::new(0)));
    s.project_hooks = Some(Arc::new(ProjectLog::new()));
    assert_eq!(
        handle(&s, "POST", "/v1/sessions", &json!({"project": "demo-b"})).status,
        200
    );
    for (method, path) in [
        ("GET", "/v1/sessions/demo-b/functions"),
        ("POST", "/v1/sessions/demo-b/functions/tick:run"),
        ("POST", "/v1/sessions/demo-b/pubsub/topics/jobs:publish"),
    ] {
        let r = handle(&s, method, path, &json!({"messages": [{"data": ""}]}));
        assert_eq!(r.status, 400, "{path}: {}", r.body);
        assert!(r.body["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("FAILED_PRECONDITION"));
    }
}

/// Which phase of a session-state transition a hook refuses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refuse {
    /// Nothing: the hook works.
    Nothing,
    /// The capture (also the pre-image a restore takes).
    Capture,
    /// The validation that runs before any hook applies.
    Validate,
    /// The apply itself.
    Apply,
}

/// A hook whose state is a string, that refuses one phase deterministically, and that
/// records every value it applied. Several of them stand in for the adapters at the
/// multi-adapter seam of a snapshot restore.
struct Injected {
    name: &'static str,
    value: Mutex<String>,
    refuse: Mutex<Refuse>,
    applied: Arc<Mutex<Vec<String>>>,
}

impl Injected {
    fn new(name: &'static str, value: &str, applied: &Arc<Mutex<Vec<String>>>) -> Arc<Self> {
        Arc::new(Self {
            name,
            value: Mutex::new(value.to_owned()),
            refuse: Mutex::new(Refuse::Nothing),
            applied: applied.clone(),
        })
    }

    fn value(&self) -> String {
        self.value.lock().unwrap().clone()
    }

    fn set(&self, value: &str) {
        value.clone_into(&mut self.value.lock().unwrap());
    }

    fn refuse(&self, what: Refuse) {
        *self.refuse.lock().unwrap() = what;
    }

    fn refuses(&self, what: Refuse) -> Result<(), TransitionFailure> {
        if *self.refuse.lock().unwrap() == what {
            return Err(TransitionFailure::new(self.name, "the store refused"));
        }
        Ok(())
    }
}

impl SnapshotHook for Injected {
    fn name(&self) -> &'static str {
        self.name
    }
    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        self.refuses(Refuse::Capture)?;
        Ok(Arc::new(self.value()))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<String>()
            .ok_or_else(|| TransitionFailure::new(self.name, "not a string"))?;
        self.refuses(Refuse::Validate)
    }
    fn restore(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        self.refuses(Refuse::Apply)?;
        let value = part
            .downcast_ref::<String>()
            .ok_or_else(|| TransitionFailure::new(self.name, "not a string"))?;
        self.applied
            .lock()
            .unwrap()
            .push(format!("{}={value}", self.name));
        self.set(value);
        Ok(())
    }
}

/// A control state whose snapshot hooks can be made to refuse a phase, the hooks
/// themselves, and the log of every value they applied.
type InjectedState = (ControlState, Vec<Arc<Injected>>, Arc<Mutex<Vec<String>>>);

/// Three hooks standing in for three adapters, seeded with their first values.
fn injected_state() -> InjectedState {
    let applied = Arc::new(Mutex::new(Vec::new()));
    let hooks: Vec<Arc<Injected>> = ["first", "second", "third"]
        .iter()
        .enumerate()
        .map(|(i, name)| Injected::new(name, &format!("{name}-{i}"), &applied))
        .collect();
    let mut s = state(Arc::new(AtomicUsize::new(0)));
    s.snapshot_hooks = hooks
        .iter()
        .map(|h| h.clone() as Arc<dyn SnapshotHook>)
        .collect();
    (s, hooks, applied)
}

/// SESSION-ATOMIC-01: a store that cannot be copied refuses the whole capture, at every
/// position, and the snapshot the session already retains is untouched.
#[test]
fn a_capture_that_fails_at_any_position_retains_no_snapshot() {
    for position in 0..3 {
        let (s, hooks, _) = injected_state();
        let base = handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots",
            &json!({"name": "base"}),
        );
        assert_eq!(base.status, 200, "{}", base.body);
        for h in &hooks {
            h.set("moved");
        }
        hooks[position].refuse(Refuse::Capture);
        let r = handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots",
            &json!({"name": "later"}),
        );
        assert_eq!(r.status, 500, "position {position}: {}", r.body);
        let message = r.body["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(hooks[position].name) && message.contains("was not taken"),
            "position {position}: {message}"
        );
        // Only the snapshot taken before the failure is retained, and it still holds the
        // values it captured.
        let list = handle(&s, "GET", "/v1/sessions/default/snapshots", &json!({}));
        assert_eq!(list.body["retained"], 1, "position {position}");
        assert_eq!(list.body["snapshots"][0]["name"], "base");
        hooks[position].refuse(Refuse::Nothing);
        let r = handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots/base:restore",
            &json!({}),
        );
        assert_eq!(r.status, 200, "{}", r.body);
        for (i, h) in hooks.iter().enumerate() {
            assert_eq!(h.value(), format!("{}-{i}", h.name), "position {position}");
        }
    }
}

/// SESSION-ATOMIC-02: every hook is validated before any hook applies, so a part that the
/// last adapter rejects leaves the first ones alone.
#[test]
fn restore_validation_completes_before_any_hook_applies() {
    for position in 0..3 {
        let (s, hooks, applied) = injected_state();
        assert_eq!(
            handle(
                &s,
                "POST",
                "/v1/sessions/default/snapshots",
                &json!({"name": "base"})
            )
            .status,
            200
        );
        for h in &hooks {
            h.set("moved");
        }
        applied.lock().unwrap().clear();
        hooks[position].refuse(Refuse::Validate);
        let r = handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots/base:restore",
            &json!({}),
        );
        assert_eq!(r.status, 500, "position {position}: {}", r.body);
        let message = r.body["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(hooks[position].name) && message.contains("nothing was restored"),
            "position {position}: {message}"
        );
        assert!(
            applied.lock().unwrap().is_empty(),
            "position {position}: a hook applied before validation finished"
        );
        for h in &hooks {
            assert_eq!(h.value(), "moved", "position {position}");
        }
    }
}

/// SESSION-ATOMIC-02 / SESSION-ATOMIC-05: a hook that refuses the apply rolls the hooks
/// before it back to the pre-image, at every position, so no request sees a session that
/// is half of one snapshot and half of another.
#[test]
fn a_restore_that_fails_at_any_position_rolls_the_earlier_hooks_back() {
    for position in 0..3 {
        let (s, hooks, applied) = injected_state();
        assert_eq!(
            handle(
                &s,
                "POST",
                "/v1/sessions/default/snapshots",
                &json!({"name": "base"})
            )
            .status,
            200
        );
        for (i, h) in hooks.iter().enumerate() {
            h.set(&format!("live-{i}"));
        }
        applied.lock().unwrap().clear();
        hooks[position].refuse(Refuse::Apply);
        let r = handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots/base:restore",
            &json!({}),
        );
        assert_eq!(r.status, 500, "position {position}: {}", r.body);
        let message = r.body["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(hooks[position].name) && message.contains("rolled back"),
            "position {position}: {message}"
        );
        // Every hook holds the value it had when the restore started, whether it was
        // applied and rolled back or never reached.
        for (i, h) in hooks.iter().enumerate() {
            assert_eq!(h.value(), format!("live-{i}"), "position {position}");
        }
        // The hooks before the failure were applied and then put back; the ones after it
        // were never touched.
        let log = applied.lock().unwrap().clone();
        assert_eq!(log.len(), position * 2, "position {position}: {log:?}");
        // The snapshot survives the failed restore and can still be applied.
        hooks[position].refuse(Refuse::Nothing);
        let r = handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots/base:restore",
            &json!({}),
        );
        assert_eq!(r.status, 200, "position {position}: {}", r.body);
        for (i, h) in hooks.iter().enumerate() {
            assert_eq!(h.value(), format!("{}-{i}", h.name), "position {position}");
        }
    }
}

/// SESSION-ATOMIC-03 / SESSION-ATOMIC-05: a Storage or Auth store that refuses the wipe is
/// reported, and the session keeps its registration, its snapshots and its data.
#[test]
fn session_reset_and_deletion_report_the_store_that_refused() {
    let log = Arc::new(ProjectLog::new());
    let counter = Arc::new(AtomicUsize::new(0));
    let mut s = state(counter.clone());
    s.project_hooks = Some(log.clone());
    s.snapshot_hooks = vec![Arc::new(Slot(Mutex::new("kept".to_owned())))];
    assert_eq!(
        handle(&s, "POST", "/v1/sessions", &json!({"project": "demo-b"})).status,
        200
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/demo-b/snapshots",
            &json!({"name": "b1"})
        )
        .status,
        200
    );
    let before = log.entries();
    log.fail_on("storage");
    // A reset that a store refuses is a failure, not a success with a note.
    for session in ["default", "demo-b"] {
        let r = handle(
            &s,
            "POST",
            &format!("/v1/sessions/{session}/reset"),
            &json!({}),
        );
        assert_eq!(r.status, 500, "{session}: {}", r.body);
        let message = r.body["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("storage") && message.contains("no store was wiped"),
            "{session}: {message}"
        );
    }
    // The default session's shared hooks belong to the same transition: a refused wipe
    // does not run them.
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    // The deletion is refused too, and the session is still there with its snapshot.
    let r = handle(&s, "DELETE", "/v1/sessions/demo-b", &json!({}));
    assert_eq!(r.status, 500, "{}", r.body);
    assert!(r.body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("the session is unchanged"));
    assert_eq!(log.entries(), before);
    assert_eq!(
        handle(&s, "GET", "/v1/sessions/demo-b", &json!({})).status,
        200
    );
    assert!(s.tenancy.read().unwrap().is_registered("demo-b"));
    assert_eq!(
        handle(&s, "GET", "/v1/sessions/demo-b/snapshots", &json!({})).body["retained"],
        1
    );
    // A creation whose wipe is refused registers nothing.
    let r = handle(&s, "POST", "/v1/sessions", &json!({"project": "demo-c"}));
    assert_eq!(r.status, 500, "{}", r.body);
    assert!(!s.tenancy.read().unwrap().is_registered("demo-c"));
    assert_eq!(
        handle(&s, "GET", "/v1/sessions/demo-c", &json!({})).status,
        404
    );
    // Once the store takes part again the session deletes normally.
    log.recover();
    let r = handle(&s, "DELETE", "/v1/sessions/demo-b", &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(!s.tenancy.read().unwrap().is_registered("demo-b"));
    assert_eq!(
        handle(&s, "GET", "/v1/sessions/default/snapshots", &json!({})).body["retained"],
        0
    );
}

/// A captured part that counts its own drops.
struct Tracked(Arc<AtomicUsize>);

impl Drop for Tracked {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A hook whose parts count their drops, so a test can prove that replacing or deleting a
/// snapshot releases what it retained.
struct Counted(Arc<AtomicUsize>);

impl SnapshotHook for Counted {
    fn name(&self) -> &'static str {
        "counted"
    }
    fn capture(&self, _: &Scope) -> Result<SnapshotPart, TransitionFailure> {
        Ok(Arc::new(Tracked(self.0.clone())))
    }
    fn validate(&self, _: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure> {
        part.downcast_ref::<Tracked>()
            .map(|_| ())
            .ok_or_else(|| TransitionFailure::new("counted", "not a tracked part"))
    }
    fn restore(&self, _: &Scope, _: &SnapshotPart) -> Result<(), TransitionFailure> {
        Ok(())
    }
}

/// SNAP-MEM-01 / SNAP-MEM-04: unique names are bounded per session, the refusal is stable
/// and leaves the retained set alone, and a name the session already holds is still
/// admitted.
#[test]
fn snapshot_names_are_bounded_per_session() {
    let mut s = state(Arc::new(AtomicUsize::new(0)));
    s.snapshot_hooks = vec![Arc::new(Slot(Mutex::new("value".to_owned())))];
    for i in 0..MAX_SNAPSHOTS_PER_SESSION {
        let r = handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots",
            &json!({"name": format!("s{i}")}),
        );
        assert_eq!(r.status, 200, "{i}: {}", r.body);
        assert_eq!(r.body["retained"], i + 1);
        assert_eq!(r.body["limit"], MAX_SNAPSHOTS_PER_SESSION);
    }
    // The budget is a stable refusal, not an out-of-memory: the same request is refused
    // the same way twice and changes nothing.
    for _ in 0..2 {
        let r = handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots",
            &json!({"name": "one-too-many"}),
        );
        assert_eq!(r.status, 429, "{}", r.body);
        assert!(r.body["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("RESOURCE_EXHAUSTED"));
    }
    let list = handle(&s, "GET", "/v1/sessions/default/snapshots", &json!({}));
    assert_eq!(list.body["retained"], MAX_SNAPSHOTS_PER_SESSION);
    assert_eq!(list.body["remaining"], 0);
    assert_eq!(
        list.body["snapshots"].as_array().unwrap().len(),
        MAX_SNAPSHOTS_PER_SESSION
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots/one-too-many:restore",
            &json!({})
        )
        .status,
        404
    );
    // A name the session already holds is a replacement, not an admission.
    let r = handle(
        &s,
        "POST",
        "/v1/sessions/default/snapshots",
        &json!({"name": "s0"}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["replaced"], true);
    assert_eq!(r.body["retained"], MAX_SNAPSHOTS_PER_SESSION);
    // Deleting one makes room again.
    let r = handle(
        &s,
        "DELETE",
        "/v1/sessions/default/snapshots/s0",
        &json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["retained"], MAX_SNAPSHOTS_PER_SESSION - 1);
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots",
            &json!({"name": "one-too-many"})
        )
        .status,
        200
    );
}

/// SNAP-MEM-02: replacing a name releases what it held, and so do deleting it and deleting
/// the session that took it.
#[test]
fn replacing_and_deleting_a_snapshot_release_what_it_retained() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut s = state(Arc::new(AtomicUsize::new(0)));
    s.snapshot_hooks = vec![Arc::new(Counted(dropped.clone()))];
    let capture = |name: &str| {
        handle(
            &s,
            "POST",
            "/v1/sessions/default/snapshots",
            &json!({"name": name}),
        )
    };
    assert_eq!(capture("base").status, 200);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    // Capturing over the name drops the part the previous capture held.
    assert_eq!(capture("base").body["replaced"], true);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(capture("other").status, 200);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
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
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    // Deleting the session that took a snapshot drops what it retained.
    s.project_hooks = Some(Arc::new(ProjectLog::new()));
    assert_eq!(
        handle(&s, "POST", "/v1/sessions", &json!({"project": "demo-b"})).status,
        200
    );
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/demo-b/snapshots",
            &json!({"name": "b1"})
        )
        .status,
        200
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert_eq!(
        handle(&s, "DELETE", "/v1/sessions/demo-b", &json!({})).status,
        200
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 3);
}

#[test]
fn the_rules_request_trace_lists_decided_requests_newest_first_with_their_expressions() {
    use fireemu_core_rules::coverage::RequestTrace;
    use fireemu_core_rules::eval::{evaluate_request_traced, Method, RequestContext, RulesService};
    use fireemu_core_rules::parse::parse_ruleset;

    let s = state(Arc::new(AtomicUsize::new(0)));
    let source = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /notes/{id} { allow get: if id != 'secret'; } } }";
    assert_eq!(
        handle(&s, "PUT", "/v1/rules", &json!({"source": source})).status,
        200
    );

    // Empty until something is decided, and only GET is served.
    let empty = handle(&s, "GET", "/v1/sessions/default/rules/requests", &json!({}));
    assert_eq!(empty.status, 200, "{}", empty.body);
    assert_eq!(empty.body["requests"], json!([]));
    assert_eq!(empty.body["loaded"], true);
    assert_eq!(
        handle(
            &s,
            "POST",
            "/v1/sessions/default/rules/requests",
            &json!({})
        )
        .status,
        400
    );

    // Decide two requests through the evaluator and record them where the Firestore
    // adapter records them: the diagnostics that travel with the loaded ruleset.
    let ruleset = parse_ruleset(source).unwrap();
    for (id, allowed) in [("a", true), ("secret", false)] {
        let ctx = RequestContext {
            service: RulesService::Firestore,
            method: Method::Get,
            path: format!("/databases/(default)/documents/notes/{id}"),
            auth: None,
            resource: None,
            request_resource: None,
            time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
            abstract_path: false,
            request_query: None,
        };
        let (_, coverage) = evaluate_request_traced(&ruleset, &ctx, None);
        let expressions = coverage.entries().into_iter().cloned().collect();
        let rules = s.rules.read().unwrap();
        rules
            .diagnostics
            .lock()
            .unwrap()
            .push(&coverage, |sequence| RequestTrace {
                sequence,
                method: "get",
                path: format!("notes/{id}"),
                allowed,
                reason: if allowed {
                    String::new()
                } else {
                    "denied".to_owned()
                },
                uid: None,
                expressions,
            });
    }

    let r = handle(&s, "GET", "/v1/sessions/default/rules/requests", &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    let requests = r.body["requests"].as_array().cloned().unwrap_or_default();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["path"], "notes/secret", "newest first");
    assert_eq!(requests[0]["allowed"], false);
    assert_eq!(requests[0]["sequence"], 2);
    assert_eq!(requests[1]["path"], "notes/a");
    assert_eq!(requests[1]["allowed"], true);
    assert_eq!(requests[0]["service"], "firestore");
    assert_eq!(requests[0]["uid"], Value::Null);

    // Every expression of the decided request is there, keyed by its source position.
    let expressions = requests[0]["expressions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!expressions.is_empty());
    let condition_at = source.find("id != 'secret'").unwrap();
    let condition = expressions
        .iter()
        .find(|e| {
            e["currentOffset"] == json!(condition_at)
                && e["endOffset"] == json!(condition_at + "id != 'secret'".len())
        })
        .expect("the allow condition is traced");
    assert_eq!(
        condition["values"],
        json!([{"value": {"kind": "bool", "bool": false}, "count": 1}])
    );

    // Loading another ruleset drops the trace with the source it described.
    assert_eq!(
        handle(&s, "PUT", "/v1/rules", &json!({"source": source})).status,
        200
    );
    let after = handle(&s, "GET", "/v1/sessions/default/rules/requests", &json!({}));
    assert_eq!(after.body["requests"], json!([]));
}
