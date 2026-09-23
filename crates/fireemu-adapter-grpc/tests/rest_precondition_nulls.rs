//! FS-WRITE-PRECONDITION-NULL-045: null oneof members must not mask real conditions.
//! Local regressions only; these tests are not production observations.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::encode::decode_precondition;
use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::json::precondition_from_json;
use fireemu_adapter_grpc::rest::{RestRequest, RestResponse, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";
const RESOURCE: &str = "projects/demo-app/databases/(default)/documents";
const TIME: &str = "2026-01-01T00:00:00.123456Z";

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
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), clock, 7)),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    }
}

fn call(state: &RestState, method: &str, path: &str, body: Value) -> RestResponse {
    state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
    })
}

fn write(relative: &str, n: i64, condition: &Value) -> Value {
    json!({
        "update": {
            "name": format!("{RESOURCE}/{relative}"),
            "fields": {"v": {"integerValue": n.to_string()}}
        },
        "currentDocument": condition
    })
}

fn read(state: &RestState, relative: &str) -> RestResponse {
    call(state, "GET", &format!("{DOCS}/{relative}"), Value::Null)
}

fn seed(state: &RestState, relative: &str) -> Value {
    let response = call(
        state,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [write(relative, 7, &json!({"exists": false}))]}),
    );
    assert_eq!(response.status, 200, "{:?}", response.body);
    let response = read(state, relative);
    assert_eq!(response.status, 200, "{:?}", response.body);
    response.body
}

#[test]
fn null_sibling_preserves_both_boolean_preconditions() {
    for exists in [false, true] {
        let canonical = precondition_from_json(Some(&json!({"exists": exists}))).unwrap();
        let padded = precondition_from_json(Some(&json!({
            "exists": exists, "updateTime": null
        })))
        .unwrap();
        assert_eq!(padded, canonical);
        assert!(decode_precondition(padded.as_ref()).unwrap().is_some());
    }
}

#[test]
fn null_exists_preserves_update_time_exactly() {
    let canonical = precondition_from_json(Some(&json!({"updateTime": TIME}))).unwrap();
    let padded =
        precondition_from_json(Some(&json!({"exists": null, "updateTime": TIME}))).unwrap();
    assert_eq!(padded, canonical);
    assert!(decode_precondition(padded.as_ref()).unwrap().is_some());
}

#[test]
fn null_only_members_do_not_erase_an_empty_enclosing_precondition() {
    assert!(precondition_from_json(None).unwrap().is_none());
    assert!(precondition_from_json(Some(&Value::Null))
        .unwrap()
        .is_none());
    for input in [
        json!({}),
        json!({"exists": null}),
        json!({"updateTime": null}),
        json!({"exists": null, "updateTime": null}),
    ] {
        let parsed = precondition_from_json(Some(&input)).unwrap();
        assert!(parsed.is_some(), "empty message disappeared: {input}");
        assert!(parsed.as_ref().unwrap().condition_type.is_none());
        // Keep the established backend validation; this is NOT an unconditional write.
        assert!(decode_precondition(parsed.as_ref()).is_err());
    }
}

#[test]
fn two_non_null_members_unknown_keys_and_bad_types_still_fail() {
    for exists in [false, true] {
        assert!(precondition_from_json(Some(&json!({
            "exists": exists, "updateTime": TIME
        })))
        .is_err());
    }
    for input in [
        json!({"exists": 0, "updateTime": null}),
        json!({"exists": "false", "updateTime": null}),
        json!({"exists": [], "updateTime": null}),
        json!({"exists": {}, "updateTime": null}),
        json!({"exists": null, "updateTime": "bad-timestamp"}),
        json!({"exists": null, "updateTime": 0}),
        json!({"exists": false, "unknown": null}),
        json!({"unknown": null}),
        json!([]),
        json!(false),
    ] {
        assert!(precondition_from_json(Some(&input)).is_err(), "{input}");
    }
}

#[test]
fn commit_create_only_with_null_sibling_creates_but_never_overwrites() {
    let s = state();
    let condition = json!({"exists": false, "updateTime": null});
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [write("null-precondition/new", 7, &condition)]}),
    );
    assert_eq!(response.status, 200, "{:?}", response.body);
    let before = read(&s, "null-precondition/new").body;
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [write("null-precondition/new", 9, &condition)]}),
    );
    assert_eq!(response.status, 409, "{:?}", response.body);
    assert_eq!(response.body["error"]["status"], "ALREADY_EXISTS");
    assert_eq!(read(&s, "null-precondition/new").body, before);
}

#[test]
fn commit_exists_true_with_null_sibling_updates_only_existing_documents() {
    let s = state();
    seed(&s, "null-precondition/existing");
    let condition = json!({"exists": true, "updateTime": null});
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [write("null-precondition/existing", 9, &condition)]}),
    );
    assert_eq!(response.status, 200, "{:?}", response.body);
    assert_eq!(
        read(&s, "null-precondition/existing").body["fields"]["v"]["integerValue"],
        "9"
    );
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [
            write("null-precondition/neighbour", 1, &json!({"exists": false})),
            write("null-precondition/missing", 2, &condition)
        ]}),
    );
    assert_eq!(response.status, 404, "{:?}", response.body);
    assert_eq!(response.body["error"]["status"], "NOT_FOUND");
    assert_eq!(read(&s, "null-precondition/neighbour").status, 404);
    assert_eq!(read(&s, "null-precondition/missing").status, 404);
}

#[test]
fn commit_null_exists_keeps_exact_version_check() {
    let s = state();
    let before = seed(&s, "null-precondition/versioned");
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [write("null-precondition/versioned", 8, &json!({
            "exists": null, "updateTime": before["updateTime"]
        }))]}),
    );
    assert_eq!(response.status, 200, "{:?}", response.body);
    let before_refusal = read(&s, "null-precondition/versioned").body;
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [write("null-precondition/versioned", 9, &json!({
            "exists": null, "updateTime": "2000-01-01T00:00:00Z"
        }))]}),
    );
    assert_eq!(response.status, 400, "{:?}", response.body);
    assert_eq!(response.body["error"]["status"], "FAILED_PRECONDITION");
    assert_eq!(read(&s, "null-precondition/versioned").body, before_refusal);
}

#[test]
fn empty_or_invalid_conditions_do_not_publish_commit_neighbours() {
    for condition in [
        json!({}),
        json!({"exists": null}),
        json!({"updateTime": null}),
        json!({"exists": null, "updateTime": null}),
        json!({"exists": false, "updateTime": TIME}),
        json!({"exists": 0, "updateTime": null}),
        json!({"exists": false, "unknown": null}),
    ] {
        let s = state();
        let before = seed(&s, "null-precondition/protected");
        let response = call(
            &s,
            "POST",
            &format!("{DOCS}:commit"),
            json!({"writes": [
                write("null-precondition/neighbour", 1, &json!({"exists": false})),
                write("null-precondition/protected", 9, &condition)
            ]}),
        );
        assert_eq!(response.status, 400, "{:?}", response.body);
        assert_eq!(response.body["error"]["status"], "INVALID_ARGUMENT");
        assert_eq!(read(&s, "null-precondition/neighbour").status, 404);
        assert_eq!(read(&s, "null-precondition/protected").body, before);
    }
}

#[test]
fn batchwrite_null_sibling_refuses_request_before_precondition() {
    let s = state();
    let before = seed(&s, "null-precondition/protected");
    let condition = json!({"exists": false, "updateTime": null});
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({"writes": [
            write("null-precondition/protected", 9, &condition),
            {},
            write("null-precondition/after", 1, &condition)
        ]}),
    );
    assert_eq!(response.status, 400, "{:?}", response.body);
    assert_eq!(response.body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(read(&s, "null-precondition/protected").body, before);
    let after = read(&s, "null-precondition/after");
    assert_eq!(after.status, 404, "{:?}", after.body);
}
