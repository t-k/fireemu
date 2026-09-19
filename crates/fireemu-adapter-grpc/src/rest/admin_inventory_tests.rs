use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

use super::{RestRequest, RestState};
use crate::decode::parse_parent;
use crate::gateway::Gateway;
use crate::local::LocalBackend;

fn state_with(edition: FirestoreEdition, api_mode: FirestoreApiMode) -> RestState {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition,
            api_mode,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    RestState {
        local: Arc::new(LocalBackend::new(
            gateway.clone(),
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
            7,
        )),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    }
}

fn state() -> RestState {
    state_with(FirestoreEdition::Standard, FirestoreApiMode::Native)
}

fn call(state: &RestState, authorization: Option<&str>, path: &str) -> (u16, Value) {
    call_request(state, authorization, "GET", path, Value::Null)
}

fn call_request(
    state: &RestState,
    authorization: Option<&str>,
    method: &str,
    path: &str,
    body: Value,
) -> (u16, Value) {
    let (path, query) = path.split_once('?').map_or((path, ""), |parts| parts);
    let response = state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization: authorization.map(str::to_owned),
        app_check: Vec::new(),
        body,
        origin: None,
        browser_metadata: false,
    });
    (response.status, response.body)
}

#[test]
fn admin_inventory_coexists_with_document_crud_commit_and_query_routes() {
    let state = state();
    let documents = "/v1/projects/demo/databases/(default)/documents";
    let (status, created) = call_request(
        &state,
        Some("Bearer owner"),
        "POST",
        &format!("{documents}/users?documentId=alice"),
        json!({"fields": {"name": {"stringValue": "Alice"}}}),
    );
    assert_eq!(status, 200, "{created}");

    let (status, committed) = call_request(
        &state,
        Some("Bearer owner"),
        "POST",
        &format!("{documents}:commit"),
        json!({"writes": []}),
    );
    assert_eq!(status, 200, "{committed}");

    let (status, queried) = call_request(
        &state,
        Some("Bearer owner"),
        "POST",
        &format!("{documents}:runQuery"),
        json!({"structuredQuery": {"from": [{"collectionId": "users"}]}}),
    );
    assert_eq!(status, 200, "{queried}");
    assert!(queried.as_array().is_some());

    let (status, listed) = call(&state, Some("Bearer owner"), "/v1/projects/demo/databases");
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["databases"].as_array().map(Vec::len), Some(1));

    let (status, database) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/(default)",
    );
    assert_eq!(status, 200, "{database}");
}

#[test]
fn document_routes_preserve_database_ids_containing_documents() {
    let state = state();
    for (project, database) in [("demo", "documents-db"), ("documents-project", "documents")] {
        create_database(&state, project, database);
        let documents = format!("/v1/projects/{project}/databases/{database}/documents");
        let (status, created) = call_request(
            &state,
            Some("Bearer owner"),
            "POST",
            &format!("{documents}/users?documentId=alice"),
            json!({"fields": {"name": {"stringValue": "Alice"}}}),
        );
        assert_eq!(status, 200, "{created}");
        assert_eq!(
            created["name"],
            format!("projects/{project}/databases/{database}/documents/users/alice")
        );

        let (status, fetched) = call_request(
            &state,
            Some("Bearer owner"),
            "GET",
            &format!("{documents}/users/alice"),
            Value::Null,
        );
        assert_eq!(status, 200, "{fetched}");
        assert_eq!(fetched["fields"]["name"]["stringValue"], "Alice");

        let (status, listed) = call_request(
            &state,
            Some("Bearer owner"),
            "GET",
            &format!("{documents}/users"),
            Value::Null,
        );
        assert_eq!(status, 200, "{listed}");
        assert_eq!(listed["documents"].as_array().map(Vec::len), Some(1));

        let (status, committed) = call_request(
            &state,
            Some("Bearer owner"),
            "POST",
            &format!("{documents}:commit"),
            json!({"writes": []}),
        );
        assert_eq!(status, 200, "{committed}");
    }
}

#[test]
fn document_routes_reject_empty_path_segments() {
    let state = state();
    for path in [
        "/v1/projects/demo/databases/(default)/documents//items",
        "/v1/projects/demo/databases/(default)/documents/items/",
    ] {
        let (status, body) = call(&state, Some("Bearer owner"), path);
        assert_eq!(status, 400, "{path}: {body}");
    }
}

#[test]
fn admin_inventory_does_not_claim_non_get_database_routes() {
    let state = state();
    for authorization in [None, Some("Bearer owner")] {
        for method in ["POST", "PATCH", "DELETE"] {
            for path in [
                "/v1/projects/demo/databases",
                "/v1/projects/demo/databases/(default)",
            ] {
                let (status, body) = call_request(&state, authorization, method, path, Value::Null);
                assert_eq!(status, 404, "{method} {path}: {body}");
            }
        }
    }
}

fn create_database(state: &RestState, project: &str, database: &str) {
    state
        .local
        .ensure_database(
            &parse_parent(&format!(
                "projects/{project}/databases/{database}/documents"
            ))
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn admin_requires_owner_before_lookup_and_rejects_foreign_names() {
    let state = state();
    let (status, body) = call(&state, None, "/v1/projects/foreign/databases/(default)");
    assert_eq!(status, 403);
    assert_eq!(body["error"]["status"], "PERMISSION_DENIED");
    let (status, body) = call(
        &state,
        Some("Bearer user"),
        "/v1/projects/foreign/databases",
    );
    assert_eq!(status, 403);
    assert_eq!(body["error"]["status"], "PERMISSION_DENIED");
}

#[test]
fn admin_lists_sorted_databases_and_validates_discovery_query() {
    let state = state();
    create_database(&state, "demo", "zeta");
    create_database(&state, "demo", "(default)");
    create_database(&state, "demo", "alpha");
    let (status, body) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases?showDeleted=true",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["databases"].as_array().unwrap().len(), 3);
    assert_eq!(
        body["databases"][0]["name"],
        "projects/demo/databases/(default)"
    );
    let (status, _) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases?pageSize=2",
    );
    assert_eq!(status, 400);
    let (status, _) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases?showDeleted=true&showDeleted=false",
    );
    assert_eq!(status, 400);
}

#[test]
fn admin_get_is_read_only_and_unknown_database_is_not_found() {
    let state = state();
    create_database(&state, "demo", "(default)");
    let before = state.local.database_catalog().unwrap();
    let (status, body) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/(default)",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["type"], "FIRESTORE_NATIVE");
    assert_eq!(body["databaseEdition"], "STANDARD");
    // Every field the saved production response for `(default)` carries
    // (`conformance/firestore-production-matrix.json`, `emulator/routes#get-database`).
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "appEngineIntegrationMode",
            "concurrencyMode",
            "createTime",
            "databaseEdition",
            "deleteProtectionState",
            "earliestVersionTime",
            "enhancedTextSearchQueryMode",
            "etag",
            "freeTier",
            "locationId",
            "name",
            "pointInTimeRecoveryEnablement",
            "realtimeUpdatesMode",
            "type",
            "uid",
            "updateTime",
            "versionRetentionPeriod",
        ],
        "{body}"
    );
    assert_eq!(body["freeTier"], true, "{body}");
    // A uid is a UUID and an etag is opaque; both are stable for one database.
    let uid = body["uid"].as_str().unwrap().to_owned();
    assert_eq!(uid.len(), 36, "{uid}");
    assert!(body["etag"].as_str().unwrap().len() >= 16, "{body}");
    assert_eq!(state.local.database_catalog().unwrap(), before);
    let (status, body) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/missing",
    );
    assert_eq!(status, 404, "{body}");
}

#[test]
fn admin_inventory_survives_clear_and_preserves_project_isolation() {
    let state = state();
    create_database(&state, "demo", "(default)");
    create_database(&state, "demo", "analytics");
    create_database(&state, "other", "(default)");

    let before_list = call(&state, Some("Bearer owner"), "/v1/projects/demo/databases").1;
    let before_default = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/(default)",
    )
    .1;
    let (status, body) = call_request(
        &state,
        Some("Bearer owner"),
        "POST",
        "/v1/projects/demo/databases/(default)/documents/users?documentId=alice",
        json!({"fields": {"name": {"stringValue": "Alice"}}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = call_request(
        &state,
        Some("Bearer owner"),
        "POST",
        "/v1/projects/demo/databases/analytics/documents/users?documentId=carol",
        json!({"fields": {"name": {"stringValue": "Carol"}}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = call_request(
        &state,
        Some("Bearer owner"),
        "POST",
        "/v1/projects/other/databases/(default)/documents/users?documentId=bob",
        json!({"fields": {"name": {"stringValue": "Bob"}}}),
    );
    assert_eq!(status, 200, "{body}");

    let (status, body) = call_request(
        &state,
        None,
        "DELETE",
        "/emulator/v1/projects/demo/databases/(default)/documents",
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");

    assert_eq!(
        call(&state, Some("Bearer owner"), "/v1/projects/demo/databases").1,
        before_list
    );
    assert_eq!(
        call(
            &state,
            Some("Bearer owner"),
            "/v1/projects/demo/databases/(default)",
        )
        .1,
        before_default
    );
    let (status, body) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/missing",
    );
    assert_eq!(status, 404, "{body}");
    for database in ["(default)", "analytics"] {
        let (status, body) = call_request(
            &state,
            Some("Bearer owner"),
            "GET",
            &format!(
                "/v1/projects/demo/databases/{database}/documents/users/{}",
                if database == "(default)" {
                    "alice"
                } else {
                    "carol"
                }
            ),
            Value::Null,
        );
        assert_eq!(status, 404, "{body}");
    }
    let (status, body) = call_request(
        &state,
        Some("Bearer owner"),
        "GET",
        "/v1/projects/other/databases/(default)/documents/users/bob",
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
}

#[test]
fn admin_inventory_survives_snapshot_restore_with_standard_native_metadata() {
    let state = state();
    create_database(&state, "demo", "(default)");
    let before_list = call(&state, Some("Bearer owner"), "/v1/projects/demo/databases").1;
    let before_database = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/(default)",
    )
    .1;
    let snapshot = state.local.snapshot_databases();

    create_database(&state, "demo", "temporary");
    state.local.restore_databases(snapshot).unwrap();

    assert_eq!(
        call(&state, Some("Bearer owner"), "/v1/projects/demo/databases").1,
        before_list
    );
    assert_eq!(
        call(
            &state,
            Some("Bearer owner"),
            "/v1/projects/demo/databases/(default)",
        )
        .1,
        before_database
    );
    assert_eq!(before_database["type"], "FIRESTORE_NATIVE");
    assert_eq!(before_database["databaseEdition"], "STANDARD");
    let (status, body) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/temporary",
    );
    assert_eq!(status, 404, "{body}");
}

#[test]
fn clear_waits_for_an_admitted_operation_before_replacing_the_project_catalog() {
    let state = state();
    create_database(&state, "demo", "(default)");
    create_database(&state, "other", "(default)");
    let barrier = state.local.barrier();
    let admitted = barrier.admit();
    let finished = Arc::new(AtomicBool::new(false));
    let backend = Arc::clone(&state.local);
    let finished_by_thread = Arc::clone(&finished);
    let clearing = std::thread::spawn(move || {
        backend.clear_project_documents("demo").unwrap();
        finished_by_thread.store(true, Ordering::Release);
    });
    std::thread::yield_now();
    assert!(!finished.load(Ordering::Acquire));
    drop(admitted);
    clearing.join().unwrap();
    assert!(finished.load(Ordering::Acquire));
    assert_eq!(state.local.database_catalog().unwrap().len(), 2);
}

#[test]
fn admin_rejects_malformed_and_unsupported_routes() {
    let state = state();
    let (status, _) = call(&state, Some("Bearer owner"), "/v1/projects//databases");
    assert_eq!(status, 400);
    let (status, _) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases?pageToken=forged",
    );
    assert_eq!(status, 400);
}

#[test]
fn admin_refuses_enterprise_and_mongodb_configurations() {
    for (edition, api_mode) in [
        (FirestoreEdition::Enterprise, FirestoreApiMode::Native),
        (
            FirestoreEdition::Enterprise,
            FirestoreApiMode::MongoDbCompatible,
        ),
    ] {
        let state = state_with(edition, api_mode);
        create_database(&state, "demo", "(default)");
        let (status, body) = call(&state, Some("Bearer owner"), "/v1/projects/demo/databases");
        assert_eq!(status, 501, "{body}");
        assert_eq!(body["error"]["status"], "UNIMPLEMENTED");
        let (status, body) = call(
            &state,
            Some("Bearer owner"),
            "/v1/projects/demo/databases/(default)",
        );
        assert_eq!(status, 501, "{body}");
    }
}

#[test]
fn the_inventory_answers_what_the_data_plane_answers_about_existence() {
    // Production lists `(default)` in a project nothing has written to, and a database the
    // configuration declares is reachable before any request touches it. Everything else is
    // NOT_FOUND on both surfaces, with each surface's own production message.
    let state = state();
    state
        .local
        .replace_declared_databases(["analytics".to_owned()]);

    let (status, body) = call(&state, Some("Bearer owner"), "/v1/projects/demo/databases");
    assert_eq!(status, 200, "{body}");
    let listed: Vec<&str> = body["databases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|database| database["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        [
            "projects/demo/databases/(default)",
            "projects/demo/databases/analytics",
        ],
        "{body}"
    );
    // Listing creates nothing: the databases are declared, not materialized.
    assert!(state.local.database_catalog().unwrap().is_empty());

    for database in ["(default)", "analytics"] {
        let (status, body) = call(
            &state,
            Some("Bearer owner"),
            &format!("/v1/projects/demo/databases/{database}"),
        );
        assert_eq!(status, 200, "{database}: {body}");
        assert_eq!(
            body["name"],
            format!("projects/demo/databases/{database}"),
            "{body}"
        );
        let (status, body) = call_request(
            &state,
            Some("Bearer owner"),
            "POST",
            &format!("/v1/projects/demo/databases/{database}/documents/c?documentId=d"),
            json!({"fields": {}}),
        );
        assert_eq!(status, 200, "{database}: {body}");
    }

    let (status, body) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/reporting",
    );
    assert_eq!(status, 404, "{body}");
    assert_eq!(
        body["error"]["message"], "Project 'demo' or database 'reporting' does not exist.",
        "{body}"
    );
    let (status, body) = call_request(
        &state,
        Some("Bearer owner"),
        "GET",
        "/v1/projects/demo/databases/reporting/documents/c/d",
        Value::Null,
    );
    assert_eq!(status, 404, "{body}");
    assert_eq!(
        body["error"]["message"],
        "The database reporting does not exist for project demo Please visit \
         https://console.cloud.google.com/datastore/setup?project=demo to add a Cloud \
         Datastore or Cloud Firestore database. ",
        "{body}"
    );
}

#[test]
fn the_projection_reports_the_configured_edition() {
    // The route already refuses non-Standard Native traffic a few lines earlier, so the only
    // edition it can report is the configured one, not a constant.
    let enterprise = state_with(FirestoreEdition::Enterprise, FirestoreApiMode::Native);
    let (status, body) = call(
        &enterprise,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/(default)",
    );
    assert_eq!(status, 501, "{body}");

    let standard = state();
    let (status, body) = call(
        &standard,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/(default)",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["databaseEdition"], "STANDARD", "{body}");
}
