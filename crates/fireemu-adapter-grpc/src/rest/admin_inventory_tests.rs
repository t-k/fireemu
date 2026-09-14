use std::sync::{Arc, Mutex};

use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::Value;

use super::{RestRequest, RestState};
use crate::decode::parse_parent;
use crate::gateway::Gateway;
use crate::local::LocalBackend;

fn state() -> RestState {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
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
    }
}

fn call(state: &RestState, authorization: Option<&str>, path: &str) -> (u16, Value) {
    let (path, query) = path.split_once('?').map_or((path, ""), |parts| parts);
    let response = state.handle(&RestRequest {
        method: "GET".to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization: authorization.map(str::to_owned),
        app_check: Vec::new(),
        body: Value::Null,
    });
    (response.status, response.body)
}

fn create_database(state: &RestState, project: &str, database: &str) {
    state
        .local
        .database_handle(
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
    assert_eq!(status, 401);
    assert_eq!(body["error"]["status"], "UNAUTHENTICATED");
    let (status, body) = call(
        &state,
        Some("Bearer user"),
        "/v1/projects/foreign/databases",
    );
    assert_eq!(status, 401);
    assert_eq!(body["error"]["status"], "UNAUTHENTICATED");
}

#[test]
fn admin_lists_sorted_databases_with_bound_page_tokens() {
    let state = state();
    create_database(&state, "demo", "zeta");
    create_database(&state, "demo", "(default)");
    create_database(&state, "demo", "alpha");
    let (status, body) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases?pageSize=2",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["databases"].as_array().unwrap().len(), 2);
    assert_eq!(
        body["databases"][0]["name"],
        "projects/demo/databases/(default)"
    );
    let token = body["nextPageToken"].as_str().unwrap();
    let (status, next) = call(
        &state,
        Some("Bearer owner"),
        &format!("/v1/projects/demo/databases?pageSize=2&pageToken={token}"),
    );
    assert_eq!(status, 200, "{next}");
    assert_eq!(next["databases"][0]["name"], "projects/demo/databases/zeta");
    let (status, _) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/other/databases?pageSize=2&pageToken=fireemu-admin-v1%7Cdemo%7C2%7C2",
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
    assert_eq!(state.local.database_catalog().unwrap(), before);
    let (status, body) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases/missing",
    );
    assert_eq!(status, 404, "{body}");
}

#[test]
fn admin_rejects_malformed_and_unsupported_routes() {
    let state = state();
    let (status, _) = call(&state, Some("Bearer owner"), "/v1/projects//databases");
    assert_eq!(status, 400);
    let (status, _) = call(
        &state,
        Some("Bearer owner"),
        "/v1/projects/demo/databases?pageSize=0",
    );
    assert_eq!(status, 400);
}
