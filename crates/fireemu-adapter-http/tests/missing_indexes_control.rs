//! `GET`/`DELETE /v1/firestore/missingIndexes` and the per-session route: the list of composite
//! indexes the strict profile served under `firestore.missingIndexes: "report"`, readable and
//! clearable from outside the daemon so a CI job can fail on any of them.

use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_http::control::{
    browser_guard, handle, handle_with, is_no_store_path, ControlState, MissingIndexEntry,
    MissingIndexHook,
};
use fireemu_adapter_http::identity_toolkit::RequestHeaders;
use fireemu_core_rules::runtime::RulesetSlot;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::FirestoreEdition;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use serde_json::{json, Value};

/// A list standing in for the gateway's process-wide one: it removes by the same rule.
struct Fake {
    enabled: bool,
    entries: Mutex<Vec<MissingIndexEntry>>,
    cleared_with: Mutex<Vec<Option<String>>>,
}

impl Fake {
    fn new(enabled: bool, entries: Vec<MissingIndexEntry>) -> Arc<Self> {
        Arc::new(Self {
            enabled,
            entries: Mutex::new(entries),
            cleared_with: Mutex::new(Vec::new()),
        })
    }
}

impl MissingIndexHook for Fake {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn reports(&self) -> Vec<MissingIndexEntry> {
        self.entries.lock().unwrap().clone()
    }

    fn clear(&self, project: Option<&str>) -> usize {
        self.cleared_with
            .lock()
            .unwrap()
            .push(project.map(str::to_owned));
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        match project {
            Some(project) => {
                let prefix = format!("projects/{project}/databases/");
                entries.retain(|e| !e.database.starts_with(&prefix));
            }
            None => entries.clear(),
        }
        before - entries.len()
    }
}

fn entry(database: &str, fragment: &Value) -> MissingIndexEntry {
    MissingIndexEntry {
        database: database.to_owned(),
        fragment: serde_json::to_string_pretty(fragment).unwrap(),
        message: format!("The query requires an index for {database}."),
    }
}

fn index(group: &str, field: &str) -> Value {
    json!({
        "collectionGroup": group,
        "queryScope": "COLLECTION",
        "fields": [
            {"fieldPath": field, "order": "ASCENDING"},
            {"fieldPath": "created", "order": "DESCENDING"},
        ],
    })
}

fn state(hook: Option<Arc<dyn MissingIndexHook>>) -> ControlState {
    ControlState {
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        require_demo_prefix: true,
        edition: FirestoreEdition::Standard,
        capabilities: json!({"schemaVersion": 1}).into(),
        rules: Arc::new(RulesetSlot::default()),
        storage_rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
        reset_hooks: Vec::new(),
        functions: None,
        control_token: "test-token".to_owned(),
        app_check: None,
        firestore_listen_expiry: None,
        firestore_missing_indexes: hook,
        require_control_token: false,
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
        sessions: Mutex::new(std::collections::BTreeMap::from([
            ("default".to_owned(), "demo-app".to_owned()),
            ("other".to_owned(), "demo-other".to_owned()),
        ])),
        project_hooks: None,
        resource_hooks: Vec::new(),
    }
}

fn hooked(entries: Vec<MissingIndexEntry>) -> (ControlState, Arc<Fake>) {
    let fake = Fake::new(true, entries);
    (state(Some(fake.clone())), fake)
}

fn sample() -> Vec<MissingIndexEntry> {
    vec![
        entry(
            "projects/demo-app/databases/(default)",
            &index("notes", "owner"),
        ),
        entry(
            "projects/demo-other/databases/(default)",
            &index("tasks", "state"),
        ),
        entry(
            "projects/demo-app/databases/archive",
            &index("notes", "owner"),
        ),
        entry(
            "projects/demo-app/databases/(default)",
            &index("tasks", "done"),
        ),
    ]
}

#[test]
fn the_list_names_each_index_with_its_project_database_and_production_text() {
    let (s, _) = hooked(sample());
    let r = handle(&s, "GET", "/v1/firestore/missingIndexes", &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["count"], 4);
    let first = &r.body["missingIndexes"][0];
    assert_eq!(first["project"], "demo-app");
    assert_eq!(first["database"], "(default)");
    assert_eq!(first["name"], "projects/demo-app/databases/(default)");
    assert_eq!(first["index"], index("notes", "owner"));
    assert_eq!(
        first["message"],
        "The query requires an index for projects/demo-app/databases/(default)."
    );
    assert_eq!(r.body["missingIndexes"][2]["database"], "archive");
}

#[test]
fn indexes_json_groups_the_entries_per_database_ready_to_paste() {
    let (s, _) = hooked(sample());
    let r = handle(&s, "GET", "/v1/firestore/missingIndexes", &json!({}));
    assert_eq!(
        r.body["indexesJson"],
        json!({
            "projects/demo-app/databases/(default)": {
                "indexes": [index("notes", "owner"), index("tasks", "done")]
            },
            "projects/demo-app/databases/archive": {"indexes": [index("notes", "owner")]},
            "projects/demo-other/databases/(default)": {"indexes": [index("tasks", "state")]},
        })
    );
}

#[test]
fn an_empty_list_is_a_successful_answer_a_ci_job_can_test_for() {
    let (s, _) = hooked(Vec::new());
    let r = handle(&s, "GET", "/v1/firestore/missingIndexes", &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.body,
        json!({"count": 0, "missingIndexes": [], "indexesJson": {}})
    );
}

#[test]
fn a_session_sees_only_its_own_project() {
    let (s, _) = hooked(sample());
    let r = handle(
        &s,
        "GET",
        "/v1/sessions/default/firestore/missingIndexes",
        &json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["count"], 3);
    assert!(r.body["missingIndexes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["project"] == "demo-app"));
    assert!(r.body["indexesJson"]
        .as_object()
        .unwrap()
        .keys()
        .all(|k| k.starts_with("projects/demo-app/")));

    let r = handle(
        &s,
        "GET",
        "/v1/sessions/other/firestore/missingIndexes",
        &json!({}),
    );
    assert_eq!(r.body["count"], 1);
    let r = handle(
        &s,
        "GET",
        "/v1/sessions/nobody/firestore/missingIndexes",
        &json!({}),
    );
    assert_eq!(r.status, 404, "{}", r.body);
}

#[test]
fn a_project_whose_id_starts_a_longer_one_is_not_that_project() {
    let (s, _) = hooked(vec![
        entry("projects/demo-app-2/databases/(default)", &index("a", "x")),
        entry("projects/demo-app/databases/(default)", &index("b", "y")),
    ]);
    let r = handle(
        &s,
        "GET",
        "/v1/sessions/default/firestore/missingIndexes",
        &json!({}),
    );
    assert_eq!(r.body["count"], 1);
    assert_eq!(r.body["missingIndexes"][0]["index"]["collectionGroup"], "b");
    s.sessions
        .lock()
        .unwrap()
        .insert("two".to_owned(), "demo-app-2".to_owned());
    let r = handle(
        &s,
        "DELETE",
        "/v1/sessions/two/firestore/missingIndexes",
        &json!({}),
    );
    assert_eq!(r.body, json!({"cleared": 1}));
}

#[test]
fn delete_clears_everything_or_one_session_and_says_how_many() {
    let (s, fake) = hooked(sample());
    let r = handle(
        &s,
        "DELETE",
        "/v1/sessions/default/firestore/missingIndexes",
        &json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body, json!({"cleared": 3}));
    assert_eq!(
        *fake.cleared_with.lock().unwrap(),
        vec![Some("demo-app".to_owned())]
    );
    assert_eq!(fake.reports().len(), 1);

    let r = handle(&s, "DELETE", "/v1/firestore/missingIndexes", &json!({}));
    assert_eq!(r.body, json!({"cleared": 1}));
    assert_eq!(fake.cleared_with.lock().unwrap().last(), Some(&None));
    let r = handle(&s, "GET", "/v1/firestore/missingIndexes", &json!({}));
    assert_eq!(r.body["count"], 0);
}

#[test]
fn only_get_and_delete_are_routes() {
    let (s, fake) = hooked(sample());
    for method in ["POST", "PUT", "PATCH"] {
        let r = handle(&s, method, "/v1/firestore/missingIndexes", &json!({}));
        assert_eq!(r.status, 404, "{method}: {}", r.body);
        let r = handle(
            &s,
            method,
            "/v1/sessions/default/firestore/missingIndexes",
            &json!({}),
        );
        assert_eq!(r.status, 400, "{method}: {}", r.body);
    }
    assert!(fake.cleared_with.lock().unwrap().is_empty());
    assert_eq!(fake.reports().len(), 4);
}

/// An empty answer from a profile that never reports would pass a CI check it cannot support:
/// the read refuses instead and says what turns the report on.
#[test]
fn reading_is_refused_where_nothing_is_reported() {
    for hook in [
        None,
        Some(Fake::new(false, Vec::new()) as Arc<dyn MissingIndexHook>),
    ] {
        let s = state(hook);
        for path in [
            "/v1/firestore/missingIndexes",
            "/v1/sessions/default/firestore/missingIndexes",
        ] {
            let r = handle(&s, "GET", path, &json!({}));
            assert_eq!(r.status, 409, "{path}: {}", r.body);
            let text = r.body.to_string();
            assert!(
                text.contains("FAILED_PRECONDITION")
                    && text.contains("strict")
                    && text.contains("missingIndexes"),
                "{text}"
            );
            // Clearing an empty list is harmless and needs no precondition.
            let r = handle(&s, "DELETE", path, &json!({}));
            assert_eq!(r.body, json!({"cleared": 0}), "{path}");
        }
    }
}

/// A page on another origin must not read query shapes or clear the list without the token, and
/// the answer is never cached.
#[test]
fn a_page_needs_the_control_token_to_read_or_clear_the_list() {
    let (s, fake) = hooked(sample());
    let page = RequestHeaders {
        origin: Some("http://localhost:5173".to_owned()),
        ..RequestHeaders::default()
    };
    for (method, path) in [
        ("GET", "/v1/firestore/missingIndexes"),
        ("GET", "/v1/sessions/default/firestore/missingIndexes"),
        ("DELETE", "/v1/firestore/missingIndexes"),
        (
            "DELETE",
            "/v1/sessions/default/firestore/missingIndexes?x=1",
        ),
    ] {
        let r = handle_with(&s, method, path, &page, &json!({}));
        assert_eq!(r.status, 403, "{method} {path}: {}", r.body);
        assert!(
            r.body.to_string().contains("CONTROL_TOKEN_REQUIRED"),
            "{}",
            r.body
        );
        assert!(is_no_store_path(path), "{path}");
    }
    assert_eq!(fake.reports().len(), 4);
    let with_token = RequestHeaders {
        authorization: Some("Bearer test-token".to_owned()),
        ..page
    };
    let r = handle_with(
        &s,
        "GET",
        "/v1/firestore/missingIndexes",
        &with_token,
        &json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
}

/// The privileged diagnostics routes are told apart exactly: each of them (and only them) needs the
/// token for a read and is never cached, and a neighbouring route is neither.
#[test]
fn the_guards_and_cache_rule_cover_exactly_the_diagnostics_routes() {
    let s = state(None);
    let page = RequestHeaders {
        origin: Some("http://localhost:5173".to_owned()),
        ..RequestHeaders::default()
    };
    let privileged = [
        "/v1/firestore/missingIndexes",
        "/v1/sessions/default/firestore/missingIndexes",
        "/v1/sessions/default/resources",
        "/v1/sessions/default/resources:assertQuiescent",
        "/v1/sessions/default/rules/requests",
    ];
    for path in privileged {
        assert!(is_no_store_path(path), "{path}");
        let refusal = browser_guard(&s, "GET", path, &page).expect(path);
        assert_eq!(refusal.status, 403, "{path}");
    }
    assert!(is_no_store_path(
        "/v1/sessions/default/appCheck/observations"
    ));
    let neighbours = [
        "/v1/capabilities",
        "/v1/sessions/default",
        "/v1/sessions/default/firestore/missingIndexesX",
        "/v1/sessions/default/firestore/ttl:sweep",
        "/v1/firestore/missingIndexesX",
        "/v1/firestore/listen:expire",
        "/other/firestore/missingIndexes",
        "/v1/projects/p/firestore/missingIndexes",
    ];
    for path in neighbours {
        assert!(!is_no_store_path(path), "{path}");
        assert!(browser_guard(&s, "GET", path, &page).is_none(), "{path}");
    }
    // A write is privileged whatever the route, and a process (no Origin) never needs the token.
    assert!(browser_guard(&s, "DELETE", "/v1/firestore/missingIndexes", &page).is_some());
    assert!(browser_guard(
        &s,
        "GET",
        "/v1/firestore/missingIndexes",
        &RequestHeaders::default()
    )
    .is_none());
    let with_token = RequestHeaders {
        authorization: Some("Bearer test-token".to_owned()),
        ..page
    };
    for path in privileged {
        assert!(
            browser_guard(&s, "GET", path, &with_token).is_none(),
            "{path}"
        );
    }
}

/// A reset restores data; it is not a statement about which indexes the code under test needs,
/// so a suite that resets between cases still reports every index it ever missed.
#[test]
fn a_session_reset_keeps_the_list() {
    let (s, fake) = hooked(sample());
    let r = handle(&s, "POST", "/v1/sessions/default/reset", &json!({}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(fake.reports().len(), 4);
    assert!(fake.cleared_with.lock().unwrap().is_empty());
}

fn arb_entry() -> impl Strategy<Value = MissingIndexEntry> {
    (
        prop::sample::select(vec!["demo-a", "demo-b", "demo-a-2", "p"]),
        prop::sample::select(vec!["(default)", "db1", "db-two"]),
        "[a-zA-Z0-9_ \u{e9}\"\\\\\n\u{0}]{0,12}",
        "[a-z]{1,6}",
    )
        .prop_map(|(project, database, field, group)| {
            let mut e = entry(
                &format!("projects/{project}/databases/{database}"),
                &index(&group, &field),
            );
            // The text is production's, free of any structure the route could rely on.
            e.message = format!("m {field:?}");
            e
        })
}

proptest! {
    /// Whatever was reported, the read lists every entry once in order, groups exactly those
    /// indexes per database, and a session sees exactly its project's.
    #[test]
    fn the_read_lists_every_entry_once_and_scopes_by_project(
        entries in prop::collection::vec(arb_entry(), 0..12),
        session_project in prop::sample::select(vec!["demo-app", "demo-a", "demo-b", "demo-a-2", "p"]),
    ) {
        let fake = Fake::new(true, entries.clone());
        let s = state(Some(fake));
        s.sessions.lock().unwrap().insert("s".to_owned(), session_project.to_owned());

        let r = handle(&s, "GET", "/v1/firestore/missingIndexes", &json!({}));
        prop_assert_eq!(r.status, 200);
        prop_assert_eq!(&r.body["count"], &json!(entries.len()));
        let listed = r.body["missingIndexes"].as_array().unwrap();
        for (shown, original) in listed.iter().zip(&entries) {
            prop_assert_eq!(shown["name"].as_str().unwrap(), original.database.as_str());
            prop_assert_eq!(shown["message"].as_str().unwrap(), original.message.as_str());
            prop_assert_eq!(
                shown["index"].clone(),
                serde_json::from_str::<Value>(&original.fragment).unwrap()
            );
        }
        let mut grouped = 0;
        for (database, indexes) in r.body["indexesJson"].as_object().unwrap() {
            let expected: Vec<Value> = entries
                .iter()
                .filter(|e| &e.database == database)
                .map(|e| serde_json::from_str(&e.fragment).unwrap())
                .collect();
            prop_assert_eq!(indexes["indexes"].as_array().unwrap(), &expected);
            grouped += expected.len();
        }
        prop_assert_eq!(grouped, entries.len());

        let prefix = format!("projects/{session_project}/databases/");
        let mine: Vec<&MissingIndexEntry> =
            entries.iter().filter(|e| e.database.starts_with(&prefix)).collect();
        let r = handle(&s, "GET", "/v1/sessions/s/firestore/missingIndexes", &json!({}));
        prop_assert_eq!(&r.body["count"], &json!(mine.len()));
        for (shown, original) in r.body["missingIndexes"].as_array().unwrap().iter().zip(&mine) {
            prop_assert_eq!(shown["name"].as_str().unwrap(), original.database.as_str());
        }
        let r = handle(&s, "DELETE", "/v1/sessions/s/firestore/missingIndexes", &json!({}));
        prop_assert_eq!(&r.body["cleared"], &json!(mine.len()));
    }
}
