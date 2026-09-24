//! The database lifecycle over REST, against the shapes production answered on 2026-09-24
//! (`conformance/fs-config-lifecycle-production.json`).

use std::sync::{Arc, Mutex};

use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

use crate::gateway::Gateway;
use crate::local::LocalBackend;
use crate::rest::{RestRequest, RestState};

fn state() -> (RestState, Arc<Mutex<VirtualClock>>) {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(
        1_790_000_000_000_000_000,
    ))));
    let state = RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), Arc::clone(&clock), 7)),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    };
    (state, clock)
}

fn call(state: &RestState, method: &str, path: &str, body: Value) -> (u16, Value) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let response = state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization: Some("Bearer owner".to_owned()),
        app_check: Vec::new(),
        body,
        origin: None,
        browser_metadata: false,
    });
    (response.status, response.body)
}

fn advance(clock: &Arc<Mutex<VirtualClock>>, seconds: i64) {
    clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_nanos(
            i128::from(seconds) * 1_000_000_000,
        ))
        .unwrap();
}

const NATIVE: &str = r#"{"locationId": "us-central1", "type": "FIRESTORE_NATIVE"}"#;

fn native() -> Value {
    serde_json::from_str(NATIVE).unwrap()
}

#[test]
fn create_answers_a_finished_operation_and_the_database_serves_the_data_plane() {
    let (state, _clock) = state();
    let (status, operation) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=named-one",
        native(),
    );
    assert_eq!(status, 200, "{operation}");
    assert_eq!(operation["done"], json!(true));
    assert_eq!(
        operation["metadata"],
        json!({"@type": "type.googleapis.com/google.firestore.admin.v1.CreateDatabaseMetadata"})
    );
    let database = &operation["response"];
    assert_eq!(
        database["@type"],
        "type.googleapis.com/google.firestore.admin.v1.Database"
    );
    assert_eq!(database["name"], "projects/p/databases/named-one");
    assert_eq!(database["freeTier"], json!(false));
    assert_eq!(database["earliestVersionTime"], database["createTime"]);
    let name = operation["name"].as_str().unwrap();
    assert!(
        name.starts_with("projects/p/databases/named-one/operations/"),
        "{name}"
    );
    let (status, polled) = call(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(status, 200);
    assert_eq!(polled, operation);

    let (status, body) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/named-one/documents/c?documentId=d",
        json!({"fields": {}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, listed) = call(&state, "GET", "/v1/projects/p/databases", Value::Null);
    assert_eq!(status, 200);
    let names: Vec<&str> = listed["databases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "projects/p/databases/(default)",
            "projects/p/databases/named-one"
        ]
    );
    assert_eq!(listed["databases"][0]["freeTier"], json!(true));
}

#[test]
fn create_refuses_what_production_refuses() {
    let (state, _clock) = state();
    let id_message =
        "database_id should be 4-63 characters, and valid characters are /[a-z][0-9]-/";
    for query in [
        "databaseId=Bad_Id",
        "databaseId=ab",
        "databaseId=-leading",
        "",
    ] {
        let (status, body) = call(
            &state,
            "POST",
            &format!("/v1/projects/p/databases?{query}"),
            native(),
        );
        assert_eq!(
            (status, body["error"]["message"].as_str()),
            (400, Some(id_message)),
            "{query}"
        );
    }
    let (status, body) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=abcd",
        json!({"type": "FIRESTORE_NATIVE"}),
    );
    assert_eq!(
        (status, body["error"]["message"].as_str()),
        (
            400,
            Some("location_id must be specified when creating a database.")
        )
    );
    let (status, body) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=abcd",
        json!({"locationId": "us-central1"}),
    );
    assert_eq!(
        (status, body["error"]["message"].as_str()),
        (400, Some("database type must be set."))
    );
    let (status, body) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=abcd",
        json!({"locationId": "nowhere-1", "type": "FIRESTORE_NATIVE"}),
    );
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        body["error"]["message"],
        "Permission denied on 'locations/nowhere-1' (or it may not exist)."
    );
    let (status, body) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=abcd",
        json!({"locationId": "us-central1", "type": "FIRESTORE_NATIVE", "databaseEdition": "PREMIUM"}),
    );
    assert_eq!(status, 400);
    assert_eq!(
        body["error"]["details"][0]["fieldViolations"][0]["field"],
        "database.database_edition"
    );
    let (status, body) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=(default)",
        native(),
    );
    assert_eq!(
        (status, body["error"]["status"].as_str()),
        (409, Some("ALREADY_EXISTS"))
    );
}

#[test]
fn delete_leaves_a_tombstone_and_the_id_cools_down() {
    let (state, clock) = state();
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=gone-soon",
        native(),
    );
    let (status, operation) = call(
        &state,
        "DELETE",
        "/v1/projects/p/databases/gone-soon",
        Value::Null,
    );
    assert_eq!(status, 200, "{operation}");
    assert!(operation.get("done").is_none(), "{operation}");
    let tombstone = &operation["response"];
    let uid = tombstone["uid"].as_str().unwrap();
    assert_eq!(tombstone["name"], format!("projects/p/databases/{uid}"));
    assert_eq!(tombstone["previousId"], "gone-soon");
    assert_eq!(tombstone["earliestVersionTime"], tombstone["deleteTime"]);
    // Polling answers under a shorter name and without the database body, and never finishes.
    let (_, polled) = call(
        &state,
        "GET",
        &format!("/v1/{}", operation["name"].as_str().unwrap()),
        Value::Null,
    );
    assert_ne!(polled["name"], operation["name"]);
    assert_eq!(
        polled["response"],
        json!({"@type": "type.googleapis.com/google.firestore.admin.v1.Database"})
    );
    assert!(polled.get("done").is_none());

    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/gone-soon",
        Value::Null,
    );
    assert_eq!(
        (status, body["error"]["message"].as_str()),
        (404, Some("Requested database was not found."))
    );
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/gone-soon/documents/c/d",
        Value::Null,
    );
    assert_eq!(status, 404, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("The database gone-soon does not exist"));
    let (_, listed) = call(
        &state,
        "GET",
        "/v1/projects/p/databases?showDeleted=true",
        Value::Null,
    );
    assert!(listed["databases"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["previousId"] == "gone-soon"));

    advance(&clock, 38);
    let (status, body) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=gone-soon",
        native(),
    );
    assert_eq!(status, 400);
    assert_eq!(
        body["error"]["message"],
        "Database ID 'gone-soon' is not available in project 'p'. Please retry in 262 seconds."
    );
    advance(&clock, 262);
    let (status, _) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=gone-soon",
        native(),
    );
    assert_eq!(status, 200);
}

#[test]
fn delete_protection_is_honoured_and_can_be_patched_away() {
    let (state, _clock) = state();
    let mut body = native();
    body["deleteProtectionState"] = json!("DELETE_PROTECTION_ENABLED");
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=kept",
        body,
    );
    let (status, refused) = call(
        &state,
        "DELETE",
        "/v1/projects/p/databases/kept",
        Value::Null,
    );
    assert_eq!(status, 400);
    assert_eq!(refused["error"]["status"], "FAILED_PRECONDITION");
    let (status, patched) = call(
        &state,
        "PATCH",
        "/v1/projects/p/databases/kept?updateMask=deleteProtectionState",
        json!({"deleteProtectionState": "DELETE_PROTECTION_DISABLED"}),
    );
    assert_eq!(status, 200, "{patched}");
    assert_eq!(patched["done"], json!(true));
    assert_eq!(
        patched["response"]["deleteProtectionState"],
        "DELETE_PROTECTION_DISABLED"
    );
    let (status, body) = call(
        &state,
        "PATCH",
        "/v1/projects/p/databases/kept?updateMask=locationId",
        json!({"locationId": "us-east1"}),
    );
    assert_eq!(
        (status, body["error"]["message"].as_str()),
        (400, Some("Changing database location is not supported."))
    );
    let (status, _) = call(
        &state,
        "DELETE",
        "/v1/projects/p/databases/kept",
        Value::Null,
    );
    assert_eq!(status, 200);
}

#[test]
fn datastore_mode_and_enterprise_databases_refuse_the_native_data_plane() {
    let (state, _clock) = state();
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=dsmode",
        json!({"locationId": "us-central1", "type": "DATASTORE_MODE"}),
    );
    let mut enterprise = native();
    enterprise["databaseEdition"] = json!("ENTERPRISE");
    let (_, created) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=entdb",
        enterprise,
    );
    assert_eq!(created["response"]["concurrencyMode"], "OPTIMISTIC");
    assert_eq!(
        created["response"]["mongodbCompatibleDataAccessMode"],
        "DATA_ACCESS_MODE_ENABLED"
    );
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/dsmode/documents/c/d",
        Value::Null,
    );
    assert_eq!(status, 400);
    assert_eq!(
        body["error"]["message"],
        "The Cloud Firestore API is not available for Firestore in Datastore Mode database projects/p/databases/dsmode."
    );
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/entdb/documents/c/d",
        Value::Null,
    );
    assert_eq!(
        (status, body["error"]["status"].as_str()),
        (400, Some("FAILED_PRECONDITION"))
    );
}

#[test]
fn enterprise_only_collections_and_locations_answer_like_production() {
    let (state, _clock) = state();
    for path in ["changeStreams", "userCreds", "userCreds/u1"] {
        let (status, body) = call(
            &state,
            "GET",
            &format!("/v1/projects/p/databases/(default)/{path}"),
            Value::Null,
        );
        assert_eq!(status, 400, "{path}");
        assert_eq!(
            body["error"]["message"],
            "This operation requires an Enterprise database."
        );
    }
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/p/locations/us-central1",
        Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(body["name"], "projects/p/locations/us-central1");
    assert_eq!(body["displayName"], "Iowa");
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/p/locations/nowhere-1",
        Value::Null,
    );
    assert_eq!(
        (status, body["error"]["message"].as_str()),
        (404, Some("Requested entity was not found."))
    );
    let (_, listed) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/(default)/operations",
        Value::Null,
    );
    assert_eq!(listed, json!({}));
}

#[test]
fn an_index_is_creating_then_ready_and_queries_follow_its_state() {
    let (state, clock) = state();
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::from_secs(3600));
    call(&state, "POST", "/v1/projects/p/databases?databaseId=idxdb", native());
    let docs = "/v1/projects/p/databases/idxdb/documents";
    for (id, b) in [("x", 2), ("y", 3)] {
        call(&state, "POST", &format!("{docs}/items?documentId={id}"), json!({"fields": {"a": {"integerValue": "1"}, "b": {"integerValue": b.to_string()}}}));
    }
    let query = json!({"structuredQuery": {
        "from": [{"collectionId": "items"}],
        "where": {"fieldFilter": {"field": {"fieldPath": "a"}, "op": "EQUAL", "value": {"integerValue": "1"}}},
        "orderBy": [{"field": {"fieldPath": "b"}, "direction": "DESCENDING"}]
    }});
    let (status, before) = call(&state, "POST", &format!("{docs}:runQuery"), query.clone());
    assert_eq!(status, 400, "{before}");
    let index = json!({"queryScope": "COLLECTION", "fields": [
        {"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "DESCENDING"}]});
    let group = "/v1/projects/p/databases/idxdb/collectionGroups/items/indexes";
    let (status, operation) = call(&state, "POST", group, index.clone());
    assert_eq!(status, 200, "{operation}");
    assert!(operation.get("done").is_none());
    assert_eq!(operation["metadata"]["state"], "INITIALIZING");
    let name = operation["metadata"]["index"].as_str().unwrap().to_owned();
    let (_, created) = call(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(created["state"], "CREATING");
    assert_eq!(created["density"], "SPARSE_ALL");
    assert_eq!(created["fields"][2], json!({"fieldPath": "__name__", "order": "DESCENDING"}));
    let (status, building) = call(&state, "POST", &format!("{docs}:runQuery"), query.clone());
    assert_eq!(status, 400);
    let message = building[0]["error"]["message"].as_str().unwrap_or_else(|| building["error"]["message"].as_str().unwrap());
    assert!(message.contains("That index is currently building"), "{message}");
    let (status, duplicate) = call(&state, "POST", group, index.clone());
    assert_eq!(status, 409, "{duplicate}");
    let id = name.rsplit('/').next().unwrap();
    assert_eq!(duplicate["error"]["message"], format!("index already exists with index ID = {id}"));

    advance(&clock, 3600);
    let (_, ready) = call(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(ready["state"], "READY");
    let (_, done) = call(&state, "GET", &format!("/v1/{}", operation["name"].as_str().unwrap()), Value::Null);
    assert_eq!(done["done"], json!(true));
    let (status, answer) = call(&state, "POST", &format!("{docs}:runQuery"), query.clone());
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer.as_array().unwrap().len(), 2);

    let (status, deleted) = call(&state, "DELETE", &format!("/v1/{name}"), Value::Null);
    assert_eq!((status, deleted), (200, json!({})));
    let (status, _) = call(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(status, 404);
    let (status, again) = call(&state, "DELETE", &format!("/v1/{name}"), Value::Null);
    assert_eq!((status, again), (200, json!({})));
    let (status, _) = call(&state, "POST", &format!("{docs}:runQuery"), query);
    assert_eq!(status, 400, "a deleted index no longer serves");
}

#[test]
fn an_index_definition_is_refused_as_production_refuses_it() {
    let (state, _clock) = state();
    call(&state, "POST", "/v1/projects/p/databases?databaseId=idxdb", native());
    let group = "/v1/projects/p/databases/idxdb/collectionGroups/items/indexes";
    let cases = [
        (json!({"fields": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "ASCENDING"}]}), "query_scope must be specified."),
        (json!({"queryScope": "COLLECTION", "fields": [{"fieldPath": "a", "order": "ASCENDING"}]}), "this index is not necessary, configure using single field index controls"),
        (json!({"queryScope": "COLLECTION", "fields": [{"fieldPath": "a", "order": "ASCENDING", "arrayConfig": "CONTAINS"}, {"fieldPath": "b", "order": "ASCENDING"}]}), "Invalid value at 'index.fields[0]' (oneof), oneof field 'value_mode' is already set. Cannot set 'arrayConfig'"),
    ];
    for (body, message) in cases {
        let (status, answer) = call(&state, "POST", group, body);
        assert_eq!((status, answer["error"]["message"].as_str()), (400, Some(message)));
    }
    let (status, _) = call(&state, "GET", "/v1/projects/p/databases/nonexist-cfg/collectionGroups/-/indexes", Value::Null);
    assert_eq!(status, 404);
}
