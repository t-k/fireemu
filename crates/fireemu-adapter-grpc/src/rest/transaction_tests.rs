use std::sync::{Arc, Mutex};

use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

use super::{RestRequest, RestState};
use crate::gateway::Gateway;
use crate::local::LocalBackend;

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";

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
    let local = Arc::new(LocalBackend::new(
        gateway.clone(),
        Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
        7,
    ));
    RestState {
        local,
        gateway: Arc::new(gateway),
        rules: None,
        control_token: None,
        app_check: None,
    }
}

fn call(state: &RestState, method: &str, path: &str, body: Value) -> (u16, Value) {
    let (path, query) = path.split_once('?').map_or((path, ""), |parts| parts);
    let response = state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
    });
    (response.status, response.body)
}

#[test]
fn transaction_token_cannot_be_replayed_against_another_database_over_rest() {
    let state = state();
    let (status, begun) = call(
        &state,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let transaction = begun["transaction"]
        .as_str()
        .expect("transaction token")
        .to_owned();

    let other_docs = "/v1/projects/demo-app/databases/other/documents";
    let target = "projects/demo-app/databases/other/documents/guard/should-not-write".to_owned();
    let (status, refused) = call(
        &state,
        "POST",
        &format!("{other_docs}:commit"),
        json!({
            "transaction": transaction,
            "writes": [{"update": {"name": target}}]
        }),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        refused["error"]["message"],
        "transaction token does not belong to this database"
    );

    let (status, absent) = call(
        &state,
        "GET",
        &format!("{other_docs}/guard/should-not-write"),
        Value::Null,
    );
    assert_eq!(
        status, 404,
        "foreign transaction refusal must not write: {absent}"
    );

    let (status, rolled_back) = call(
        &state,
        "POST",
        &format!("{DOCS}:rollback"),
        json!({"transaction": transaction}),
    );
    assert_eq!(
        status, 200,
        "issuing database must retain ownership: {rolled_back}"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn failed_rest_commit_requires_rollback_before_exact_subsequent_poststate() {
    let state = state();
    let original = format!("{DOCS}/locked/doc");
    let valid_target = format!("{DOCS}/atomic/valid");
    let invalid_target = format!("{DOCS}/atomic/invalid");
    let original_fields = json!({"value": {"integerValue": "1"}});
    let (status, body) = call(
        &state,
        "PATCH",
        &original,
        json!({"fields": original_fields.clone()}),
    );
    assert_eq!(status, 200, "{body}");

    let (status, begun) = call(
        &state,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(status, 200, "{begun}");
    let transaction = begun["transaction"]
        .as_str()
        .expect("transaction token")
        .to_owned();
    let (status, read) = call(
        &state,
        "GET",
        &format!("{original}?transaction={transaction}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["fields"], original_fields);

    let oversized = "x".repeat(1_048_488);
    let (status, failed) = call(
        &state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "transaction": transaction,
            "writes": [
                {"update": {"name": "projects/demo-app/databases/(default)/documents/atomic/valid"}},
                {"update": {"name": "projects/demo-app/databases/(default)/documents/atomic/invalid", "fields": {"value": {"stringValue": oversized}}}}
            ]
        }),
    );
    assert_eq!(status, 400, "{failed}");
    assert_eq!(failed["error"]["status"], "INVALID_ARGUMENT");

    let (status, absent) = call(&state, "GET", &valid_target, Value::Null);
    assert_eq!(
        status, 404,
        "failed Commit must publish no valid write: {absent}"
    );
    let (status, absent) = call(&state, "GET", &invalid_target, Value::Null);
    assert_eq!(
        status, 404,
        "failed Commit must publish no invalid write: {absent}"
    );
    let (status, still_usable) = call(
        &state,
        "GET",
        &format!("{original}?transaction={transaction}"),
        Value::Null,
    );
    assert_eq!(
        status, 200,
        "failed Commit leaves transaction usable: {still_usable}"
    );
    assert_eq!(still_usable["fields"], original_fields);

    let control = format!("{DOCS}/atomic/control");
    let (status, control_commit) = call(
        &state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/atomic/control"}}]}),
    );
    assert_eq!(status, 200, "{control_commit}");
    let (status, control_document) = call(&state, "GET", &control, Value::Null);
    assert_eq!(status, 200, "{control_document}");
    assert_eq!(
        control_document["name"],
        "projects/demo-app/databases/(default)/documents/atomic/control"
    );
    assert!(
        control_document.get("fields").is_none(),
        "an empty update writes the document without a fields member: {control_document}"
    );

    let (status, contended) = call(
        &state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/locked/doc", "fields": {"value": {"integerValue": "9"}}}}]}),
    );
    assert_eq!(status, 409, "{contended}");
    assert_eq!(contended["error"]["status"], "ABORTED");

    let (status, rolled_back) = call(
        &state,
        "POST",
        &format!("{DOCS}:rollback"),
        json!({"transaction": transaction}),
    );
    assert_eq!(status, 200, "{rolled_back}");
    let (status, committed) = call(
        &state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/locked/doc", "fields": {"value": {"integerValue": "2"}}}}]}),
    );
    assert_eq!(status, 200, "{committed}");
    let (status, poststate) = call(&state, "GET", &original, Value::Null);
    assert_eq!(status, 200, "{poststate}");
    assert_eq!(
        poststate["name"],
        "projects/demo-app/databases/(default)/documents/locked/doc"
    );
    assert_eq!(
        poststate["fields"],
        json!({"value": {"integerValue": "2"}}),
        "rollback must permit the exact subsequent write poststate"
    );
}
