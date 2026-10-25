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
    state_with_limits(true)
}

/// The strict profile (`true`) or the emulator profile (`false`): the profile decides the
/// limits on writes, `firestore.enforceLimits` only the query limits.
fn state_with_limits(strict: bool) -> (RestState, Arc<Mutex<VirtualClock>>) {
    state_with(
        strict,
        if strict {
            IndexValidationPolicy::Production
        } else {
            IndexValidationPolicy::Emulator
        },
    )
}

fn state_with(
    enforce_limits: bool,
    policy: IndexValidationPolicy,
) -> (RestState, Arc<Mutex<VirtualClock>>) {
    state_with_context(
        enforce_limits,
        policy,
        FirestoreEdition::Standard,
        FirestoreApiMode::Native,
    )
}

fn state_with_context(
    enforce_limits: bool,
    policy: IndexValidationPolicy,
    edition: FirestoreEdition,
    api_mode: FirestoreApiMode,
) -> (RestState, Arc<Mutex<VirtualClock>>) {
    let gateway = Gateway {
        enforce_limits,
        ctx: PlanningContext {
            edition,
            api_mode,
            policy,
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
        remote_peer: false,
        browser_metadata: false,
        batch_field_order: Vec::new(),
        key_order: crate::rest::json_syntax::KeyOrder::default(),
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
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=idxdb",
        native(),
    );
    let docs = "/v1/projects/p/databases/idxdb/documents";
    for (id, b) in [("x", 2), ("y", 3)] {
        call(
            &state,
            "POST",
            &format!("{docs}/items?documentId={id}"),
            json!({"fields": {"a": {"integerValue": "1"}, "b": {"integerValue": b.to_string()}}}),
        );
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
    assert_eq!(
        created["fields"][2],
        json!({"fieldPath": "__name__", "order": "DESCENDING"})
    );
    let (status, building) = call(&state, "POST", &format!("{docs}:runQuery"), query.clone());
    assert_eq!(status, 400);
    let message = building[0]["error"]["message"]
        .as_str()
        .unwrap_or_else(|| building["error"]["message"].as_str().unwrap());
    assert!(
        message.contains("That index is currently building"),
        "{message}"
    );
    let (status, duplicate) = call(&state, "POST", group, index.clone());
    assert_eq!(status, 409, "{duplicate}");
    let id = name.rsplit('/').next().unwrap();
    assert_eq!(
        duplicate["error"]["message"],
        format!("index already exists with index ID = {id}")
    );

    advance(&clock, 3600);
    let (_, ready) = call(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(ready["state"], "READY");
    let (_, done) = call(
        &state,
        "GET",
        &format!("/v1/{}", operation["name"].as_str().unwrap()),
        Value::Null,
    );
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
    let (status, refused) = call(&state, "POST", &format!("{docs}:runQuery"), query);
    assert_eq!(status, 400, "a deleted index no longer serves");
    // Production's link to create the index again names the deleted index (2026-09-24).
    let message = refused[0]["error"]["message"]
        .as_str()
        .unwrap_or_else(|| refused["error"]["message"].as_str().unwrap())
        .to_owned();
    assert!(
        message.starts_with("The query requires an index. You can create it here: "),
        "{message}"
    );
    let blob = message.rsplit("create_composite=").next().unwrap();
    let decoded = crate::rest::json::base64_decode(blob).unwrap();
    let text = String::from_utf8_lossy(&decoded);
    assert!(text.contains(&format!("/indexes/{id}")), "{text}");
}

#[test]
fn report_mode_serves_a_building_or_deleted_index_and_reports_it_in_production_words() {
    // firestore.missingIndexes "report": a missing index never blocks a query, but the report
    // says what production answers in that state: "currently building", or the link naming
    // the deleted index.
    let (state, clock) = state_with(true, IndexValidationPolicy::ProductionReport);
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::from_secs(3600));
    let query = json!({"structuredQuery": {
        "from": [{"collectionId": "items"}],
        "where": {"fieldFilter": {"field": {"fieldPath": "a"}, "op": "EQUAL", "value": {"integerValue": "1"}}},
        "orderBy": [{"field": {"fieldPath": "b"}, "direction": "DESCENDING"}]
    }});
    let index = json!({"queryScope": "COLLECTION", "fields": [
        {"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "DESCENDING"}]});
    let report_of = |database: &str| {
        crate::gateway::missing_index_reports()
            .into_iter()
            .find(|r| r.database == format!("projects/p/databases/{database}"))
            .map(|r| r.message)
    };

    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=building",
        native(),
    );
    let (status, _) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/building/collectionGroups/items/indexes",
        index.clone(),
    );
    assert_eq!(status, 200);
    let (status, answer) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/building/documents:runQuery",
        query.clone(),
    );
    assert_eq!(status, 200, "{answer}");
    let building = report_of("building").expect("the building index is reported");
    assert!(
        building.starts_with(
            "The query requires an index. That index is currently building and cannot be used yet."
        ),
        "{building}"
    );

    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=deleted",
        native(),
    );
    let (_, operation) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/deleted/collectionGroups/items/indexes",
        index,
    );
    let name = operation["metadata"]["index"].as_str().unwrap().to_owned();
    advance(&clock, 3600);
    let (status, _) = call(&state, "DELETE", &format!("/v1/{name}"), Value::Null);
    assert_eq!(status, 200);
    let (status, answer) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/deleted/documents:runQuery",
        query,
    );
    assert_eq!(status, 200, "{answer}");
    let deleted = report_of("deleted").expect("the deleted index is reported");
    let blob = deleted.rsplit("create_composite=").next().unwrap();
    let decoded = crate::rest::json::base64_decode(blob).unwrap();
    let id = name.rsplit('/').next().unwrap();
    assert!(
        String::from_utf8_lossy(&decoded).contains(&format!("/indexes/{id}")),
        "{deleted}"
    );
}

#[test]
fn an_index_definition_is_refused_as_production_refuses_it() {
    let (state, _clock) = state();
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=idxdb",
        native(),
    );
    let group = "/v1/projects/p/databases/idxdb/collectionGroups/items/indexes";
    let cases = [
        (json!({"fields": [{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "ASCENDING"}]}), "query_scope must be specified."),
        (json!({"queryScope": "COLLECTION", "fields": [{"fieldPath": "a", "order": "ASCENDING"}]}), "this index is not necessary, configure using single field index controls"),
        (json!({"queryScope": "COLLECTION", "fields": [{"fieldPath": "a", "order": "ASCENDING", "arrayConfig": "CONTAINS"}, {"fieldPath": "b", "order": "ASCENDING"}]}), "Invalid value at 'index.fields[0]' (oneof), oneof field 'value_mode' is already set. Cannot set 'arrayConfig'"),
    ];
    for (body, message) in cases {
        let (status, answer) = call(&state, "POST", group, body);
        assert_eq!(
            (status, answer["error"]["message"].as_str()),
            (400, Some(message))
        );
    }
    let (status, _) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/nonexist-cfg/collectionGroups/-/indexes",
        Value::Null,
    );
    assert_eq!(status, 404);
}

/// The shape rules of the index file apply to `indexes.create` too (FS-11), and the shapes
/// production deployed (`conformance/fs-query-index.indexes.json`) are accepted (FS-1).
#[test]
fn an_index_create_applies_the_index_file_shape_rules() {
    let (state, _clock) = state();
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=idxdb",
        native(),
    );
    let group = "/v1/projects/p/databases/idxdb/collectionGroups/items/indexes";
    let asc = |path: &str| json!({"fieldPath": path, "order": "ASCENDING"});
    let contains = |path: &str| json!({"fieldPath": path, "arrayConfig": "CONTAINS"});
    let name_desc = json!({"fieldPath": "__name__", "order": "DESCENDING"});
    for (label, fields) in [
        (
            "a field and a descending name",
            json!([asc("n"), name_desc.clone()]),
        ),
        ("a descending name alone", json!([name_desc.clone()])),
        (
            "a single vector",
            json!([{"fieldPath": "emb", "vectorConfig": {"dimension": 3, "flat": {}}}]),
        ),
    ] {
        let (status, answer) = call(
            &state,
            "POST",
            group,
            json!({"queryScope": "COLLECTION", "fields": fields}),
        );
        assert_eq!(status, 200, "{label}: {answer}");
    }
    let too_many = (0..101).map(|i| asc(&format!("f{i}"))).collect::<Vec<_>>();
    for (label, fields, message) in [
        (
            "two array fields",
            json!([contains("a"), contains("b")]),
            "a composite index may contain only one array field",
        ),
        (
            "101 fields",
            json!(too_many),
            "FS-LIMIT-FIELDS-PER-COMPOSITE-INDEX: maximum 100 fields",
        ),
        (
            "a single field",
            json!([asc("a")]),
            "this index is not necessary, configure using single field index controls",
        ),
    ] {
        let (status, answer) = call(
            &state,
            "POST",
            group,
            json!({"queryScope": "COLLECTION_GROUP", "fields": fields}),
        );
        assert_eq!(
            (status, answer["error"]["message"].as_str()),
            (400, Some(message)),
            "{label}"
        );
    }
}

/// FS-11: the index file's composite indexes and the ones created at run time count
/// together against the 200 of a database.
#[test]
fn composite_indexes_of_the_file_and_of_the_run_count_together() {
    use fireemu_core_firestore::index::{
        IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope,
    };
    let (state, _clock) = state();
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=capdb",
        native(),
    );
    let configured: Vec<IndexDefinition> = (0..199)
        .map(|i| IndexDefinition {
            collection_group: fireemu_core_types::ids::CollectionId::try_new(format!("c{i}"))
                .unwrap(),
            query_scope: IndexQueryScope::Collection,
            fields: ["a", "b"]
                .into_iter()
                .map(|path| IndexField {
                    path: fireemu_core_firestore::field_path::FieldPath::parse(path).unwrap(),
                    mode: IndexFieldMode::Ascending,
                })
                .collect(),
        })
        .collect();
    let mut set = IndexSet::default();
    for definition in configured {
        set.add_composite(definition);
    }
    assert!(state.local.replace_database_indexes("capdb", set));
    let create = |group: &str| {
        call(
            &state,
            "POST",
            &format!("/v1/projects/p/databases/capdb/collectionGroups/{group}/indexes"),
            json!({"queryScope": "COLLECTION", "fields": [
                {"fieldPath": "x", "order": "ASCENDING"},
                {"fieldPath": "y", "order": "ASCENDING"}
            ]}),
        )
    };
    let (status, answer) = create("one");
    assert_eq!(status, 200, "the 200th index is accepted: {answer}");
    let (status, answer) = create("two");
    assert_eq!(status, 429, "the 201st is refused: {answer}");
    assert_eq!(answer["error"]["status"], "RESOURCE_EXHAUSTED");
    // A duplicate of an existing index is still ALREADY_EXISTS, not a capacity refusal.
    let (status, answer) = create("one");
    assert_eq!(status, 409, "{answer}");
}

const OPEN_RULES: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if true; } } }";

/// A strict REST surface whose `(default)` database has open Security Rules, with the
/// virtual clock the Admin cooldown reads.
fn state_with_open_default_rules() -> (RestState, Arc<Mutex<VirtualClock>>) {
    let (mut state, clock) = state();
    let auth = Arc::new(Mutex::new(fireemu_core_auth::store::AuthStore::new(
        "p",
        fireemu_core_types::determinism::SplitMix64::new(3),
        fireemu_core_auth::mfa::TotpPolicy::default(),
    )));
    let rules = Arc::new(fireemu_core_rules::runtime::RulesetSlot::new(
        fireemu_core_rules::runtime::LoadedRules::from_source(OPEN_RULES).unwrap(),
    ));
    state.rules = Some(Arc::new(
        crate::rules::RulesEnforcer::new(rules, auth, Arc::clone(&clock))
            .with_refusal_without_ruleset(true),
    ));
    (state, clock)
}

fn call_anonymous(state: &RestState, method: &str, path: &str, body: Value) -> (u16, Value) {
    let response = state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: String::new(),
        authorization: None,
        app_check: Vec::new(),
        body,
        origin: None,
        remote_peer: false,
        browser_metadata: false,
        batch_field_order: Vec::new(),
        key_order: crate::rest::json_syntax::KeyOrder::default(),
    });
    (response.status, response.body)
}

/// The capacity is checked where the index is inserted: of many concurrent creates at the edge,
/// exactly as many succeed as there is room for.
#[test]
fn concurrent_index_creates_never_pass_the_capacity() {
    use crate::admin::indexes::{CreateRefusal, IndexRegistry};
    use fireemu_core_firestore::field_path::FieldPath;
    use fireemu_core_firestore::index::{
        IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope,
    };
    let definition = |i: usize| IndexDefinition {
        collection_group: fireemu_core_types::ids::CollectionId::try_new(format!("c{i}")).unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: ["a", "b"]
            .into_iter()
            .map(|path| IndexField {
                path: FieldPath::parse(path).unwrap(),
                mode: IndexFieldMode::Ascending,
            })
            .collect(),
    };
    let configured: Vec<IndexDefinition> = (0..3).map(|i| definition(1000 + i)).collect();
    for room in [0usize, 1, 3] {
        let registry = Arc::new(IndexRegistry::default());
        let capacity = configured.len() + room;
        let results: Vec<_> = (0..8)
            .map(|i| {
                let registry = Arc::clone(&registry);
                let configured = configured.clone();
                let definition = definition(i);
                std::thread::spawn(move || {
                    registry.create_within(
                        "p",
                        "d",
                        definition,
                        LogicalInstant::UNIX_EPOCH,
                        format!("op{i}"),
                        Some((&configured, capacity)),
                    )
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            room,
            "room {room}"
        );
        assert!(results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|refusal| *refusal == CreateRefusal::Full));
        assert_eq!(registry.list("p", "d").len(), room);
    }
}

/// The route that loads one database's rules takes the admission of the project route
/// (`privileged_browser_guard`): a remote peer, a page from a foreign origin and a page without
/// the control token are refused before the path is read, and a process request is admitted.
#[test]
fn the_database_rules_route_is_guarded_like_the_project_route() {
    let (mut state, _clock) = state_with_open_default_rules();
    state.control_token = Some("run-token".to_owned());
    let body = json!({"rules": {"files": [{"name": "firestore.rules", "content": OPEN_RULES}]}});
    let put = |path: &str, mutate: &dyn Fn(&mut RestRequest)| {
        let mut request = RestRequest {
            method: "PUT".to_owned(),
            path: path.to_owned(),
            query: String::new(),
            authorization: None,
            app_check: Vec::new(),
            body: body.clone(),
            origin: None,
            remote_peer: false,
            browser_metadata: false,
            batch_field_order: Vec::new(),
            key_order: crate::rest::json_syntax::KeyOrder::default(),
        };
        mutate(&mut request);
        let response = state.handle(&request);
        (
            response.status,
            response.body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        )
    };
    for path in [
        "/emulator/v1/projects/p:securityRules",
        "/emulator/v1/projects/p/databases/other:securityRules",
    ] {
        let remote = put(path, &|r| r.remote_peer = true);
        assert_eq!(remote.0, 403, "{path}: {remote:?}");
        assert!(remote.1.contains("loopback"), "{path}: {remote:?}");
        let foreign = put(path, &|r| {
            r.browser_metadata = true;
            r.origin = Some("https://evil.example".to_owned());
        });
        assert_eq!(
            (foreign.0, foreign.1.as_str()),
            (403, "FORBIDDEN_ORIGIN"),
            "{path}"
        );
        let tokenless = put(path, &|r| {
            r.browser_metadata = true;
            r.origin = Some("http://localhost:4000".to_owned());
        });
        assert!(
            tokenless.1.starts_with("CONTROL_TOKEN_REQUIRED"),
            "{path}: {tokenless:?}"
        );
        let wrong = put(path, &|r| {
            r.browser_metadata = true;
            r.origin = Some("http://localhost:4000".to_owned());
            r.authorization = Some("Bearer not-the-token".to_owned());
        });
        assert!(
            wrong.1.starts_with("CONTROL_TOKEN_REQUIRED"),
            "{path}: {wrong:?}"
        );
        assert_eq!(
            put(path, &|_| {}).0,
            200,
            "{path}: a process request is admitted"
        );
        let paged = put(path, &|r| {
            r.browser_metadata = true;
            r.origin = Some("http://localhost:4000".to_owned());
            r.authorization = Some("Bearer run-token".to_owned());
        });
        assert_eq!(paged.0, 200, "{path}: {paged:?}");
    }
}

/// FS-2: production governs a database only by its own `cloud.firestore` release
/// (`fs-rules/named-database/releases`), so a database created at run time refuses client
/// requests until rules are set for it, whatever the `(default)` rules say.
#[test]
fn a_database_created_at_run_time_has_no_rules_until_some_are_set_for_it() {
    let (state, clock) = state_with_open_default_rules();
    state.local.admin().set_deleted_id_cooldown(0);
    let fields = json!({"fields": {"n": {"integerValue": "1"}}});
    let docs = "/v1/projects/p/databases/other/documents/items";
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=other",
        native(),
    );

    let (status, answer) = call_anonymous(
        &state,
        "POST",
        &format!("{docs}?documentId=a"),
        fields.clone(),
    );
    assert_eq!(status, 403, "{answer}");
    let (status, answer) = call(
        &state,
        "POST",
        &format!("{docs}?documentId=a"),
        fields.clone(),
    );
    assert_eq!(
        status, 200,
        "the owner credential is not governed by rules: {answer}"
    );
    assert_eq!(
        call_anonymous(
            &state,
            "GET",
            "/v1/projects/p/databases/(default)/documents/items/a",
            Value::Null
        )
        .0,
        404,
        "the (default) database keeps its own open rules"
    );

    // Rules set for the database apply to it alone.
    let set_rules = |path: &str, source: &str| {
        call_anonymous(
            &state,
            "PUT",
            path,
            json!({"rules": {"files": [{"name": "firestore.rules", "content": source}]}}),
        )
    };
    let (status, answer) = set_rules(
        "/emulator/v1/projects/p/databases/other:securityRules",
        OPEN_RULES,
    );
    assert_eq!((status, &answer), (200, &json!({})));
    assert_eq!(
        call_anonymous(&state, "GET", &format!("{docs}/a"), Value::Null).0,
        200
    );

    // A route naming no valid database, or a source that does not compile, changes nothing.
    for path in [
        "/emulator/v1/projects/p/databases/ab:securityRules",
        "/emulator/v1/projects/p/databases/other/extra:securityRules",
    ] {
        assert_eq!(set_rules(path, OPEN_RULES).0, 400, "{path}");
    }
    let (status, _) = set_rules(
        "/emulator/v1/projects/p/databases/other:securityRules",
        "service cloud.firestore {",
    );
    assert_eq!(status, 400);
    assert_eq!(
        call_anonymous(&state, "GET", &format!("{docs}/a"), Value::Null).0,
        200
    );

    // Deleting the database gives up its rules: a database created again under the id has none.
    let (status, _) = call(
        &state,
        "DELETE",
        "/v1/projects/p/databases/other",
        Value::Null,
    );
    assert_eq!(status, 200);
    advance(&clock, 3600);
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=other",
        native(),
    );
    assert_eq!(
        call_anonymous(&state, "GET", &format!("{docs}/a"), Value::Null).0,
        403
    );
}

/// Keeps what an export wrote and hands it back to an import, the way a bucket would.
#[derive(Default)]
struct MemoryStorage {
    exports: Mutex<Vec<crate::admin::managed::ExportJob>>,
}

impl crate::admin::managed::ManagedStorage for MemoryStorage {
    fn bucket_exists(&self, _project: &str, bucket: &str) -> bool {
        bucket == "run-bucket"
    }

    fn export(
        &self,
        job: &crate::admin::managed::ExportJob,
    ) -> Result<crate::admin::managed::ExportOutcome, String> {
        self.exports.lock().unwrap().push(job.clone());
        Ok(crate::admin::managed::ExportOutcome {
            documents: job.documents.len() as u64,
            bytes: 100,
        })
    }

    fn import(
        &self,
        job: &crate::admin::managed::ImportJob,
    ) -> Result<crate::admin::managed::ImportOutcome, crate::admin::managed::ImportRefusal> {
        let exports = self.exports.lock().unwrap();
        let Some(export) = exports.iter().find(|e| e.prefix == job.prefix) else {
            return Err(crate::admin::managed::ImportRefusal::MissingMetadata(
                format!(
                    "/{}/{}/{}.overall_export_metadata",
                    job.bucket,
                    job.prefix,
                    job.prefix.rsplit('/').next().unwrap()
                ),
            ));
        };
        if !job.collection_ids.is_empty() && export.collection_ids.is_empty() {
            return Err(crate::admin::managed::ImportRefusal::KindsUnavailable);
        }
        Ok(crate::admin::managed::ImportOutcome {
            documents: export
                .documents
                .iter()
                .map(|d| crate::admin::managed::ImportedDocument {
                    document: d.clone(),
                    project: export.project.clone(),
                    database: export.database.clone(),
                })
                .collect(),
            bytes: 100,
        })
    }
}

/// Two databases, a document in the first with a reference into it, and managed storage.
fn exporting_state() -> RestState {
    let (state, _clock) = state();
    state
        .local
        .admin()
        .set_managed_storage(Arc::new(MemoryStorage::default()));
    for db in ["srcdb", "dstdb"] {
        call(
            &state,
            "POST",
            &format!("/v1/projects/p/databases?databaseId={db}"),
            native(),
        );
    }
    call(
        &state,
        "POST",
        "/v1/projects/p/databases/srcdb/documents/items?documentId=a",
        json!({"fields": {"r": {"referenceValue": "projects/p/databases/srcdb/documents/other/c"}}}),
    );
    state
}

#[test]
fn export_answers_production_operations() {
    let state = exporting_state();
    let export = "/v1/projects/p/databases/srcdb:exportDocuments";
    let refusals = [
        (json!({}), 400, "Missing required field: output_uri_prefix"),
        (json!({"outputUriPrefix": "http://x/y"}), 400, "Google Cloud Storage resource path must be in format: gs://<bucket-name> or: gs://<bucket-name>/<object-name>"),
        (json!({"outputUriPrefix": "gs://missing/x"}), 404, "Google Cloud Storage bucket does not exist: missing"),
    ];
    for (body, status, message) in refusals {
        let (got, answer) = call(&state, "POST", export, body);
        assert_eq!(
            (got, answer["error"]["message"].as_str()),
            (status, Some(message))
        );
    }
    let (status, operation) = call(
        &state,
        "POST",
        export,
        json!({"outputUriPrefix": "gs://run-bucket/x/all"}),
    );
    assert_eq!(status, 200, "{operation}");
    assert!(operation.get("done").is_none());
    assert_eq!(operation["metadata"]["operationState"], "PROCESSING");
    assert_eq!(
        operation["metadata"]["outputUriPrefix"],
        "gs://run-bucket/x/all"
    );
    let (_, done) = call(
        &state,
        "GET",
        &format!("/v1/{}", operation["name"].as_str().unwrap()),
        Value::Null,
    );
    assert_eq!(done["done"], json!(true));
    assert_eq!(
        done["metadata"]["progressDocuments"],
        json!({"completedWork": "1"})
    );
    assert_eq!(done["response"]["outputUriPrefix"], "gs://run-bucket/x/all");
}

/// FS-13: an export or import names at most 100 collection ids.
#[test]
fn export_and_import_take_at_most_a_hundred_collection_ids() {
    let state = exporting_state();
    let ids = |count: usize| (0..count).map(|i| format!("c{i}")).collect::<Vec<_>>();
    for (path, field) in [
        (
            "/v1/projects/p/databases/srcdb:exportDocuments",
            "outputUriPrefix",
        ),
        (
            "/v1/projects/p/databases/dstdb:importDocuments",
            "inputUriPrefix",
        ),
    ] {
        let (status, answer) = call(
            &state,
            "POST",
            path,
            json!({field: "gs://run-bucket/x/all", "collectionIds": ids(101)}),
        );
        assert_eq!(status, 400, "{path}: {answer}");
        assert!(
            answer["error"]["message"]
                .as_str()
                .unwrap()
                .contains("at most 100 collection IDs"),
            "{answer}"
        );
        let (_, answer) = call(
            &state,
            "POST",
            path,
            json!({field: "gs://run-bucket/x/all", "collectionIds": ids(100)}),
        );
        assert!(
            !answer.to_string().contains("at most 100 collection IDs"),
            "{path}: 100 are accepted: {answer}"
        );
    }
    // The count wins over the bucket check, as a request validation does.
    let (status, answer) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/srcdb:exportDocuments",
        json!({"outputUriPrefix": "gs://missing/x", "collectionIds": ids(101)}),
    );
    assert_eq!(status, 400, "{answer}");
}

#[test]
fn import_answers_production_operations_and_moves_references_to_the_target() {
    let state = exporting_state();
    let (status, _) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/srcdb:exportDocuments",
        json!({"outputUriPrefix": "gs://run-bucket/x/all"}),
    );
    assert_eq!(status, 200);
    let import = "/v1/projects/p/databases/dstdb:importDocuments";
    let (status, answer) = call(
        &state,
        "POST",
        import,
        json!({"inputUriPrefix": "gs://run-bucket/x/all", "collectionIds": ["other"]}),
    );
    assert_eq!(
        (status, answer["error"]["message"].as_str()),
        (
            400,
            Some("The requested kinds/namespaces are not available")
        )
    );
    let (status, answer) = call(
        &state,
        "POST",
        import,
        json!({"inputUriPrefix": "gs://run-bucket/x/none"}),
    );
    assert_eq!(status, 404, "{answer}");
    let (status, operation) = call(
        &state,
        "POST",
        import,
        json!({"inputUriPrefix": "gs://run-bucket/x/all"}),
    );
    assert_eq!(status, 200, "{operation}");
    let (_, done) = call(
        &state,
        "GET",
        &format!("/v1/{}", operation["name"].as_str().unwrap()),
        Value::Null,
    );
    assert_eq!(
        done["metadata"]["progressDocuments"],
        json!({"estimatedWork": "1", "completedWork": "1"})
    );
    assert_eq!(
        done["response"],
        json!({"@type": "type.googleapis.com/google.protobuf.Empty"})
    );
    let (_, imported) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/dstdb/documents/items/a",
        Value::Null,
    );
    assert_eq!(
        imported["fields"]["r"]["referenceValue"],
        "projects/p/databases/dstdb/documents/other/c"
    );
}

#[test]
fn bulk_delete_refuses_an_empty_filter_and_deletes_the_named_collection_groups() {
    let (state, _clock) = state();
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=bulkdb",
        native(),
    );
    let docs = "/v1/projects/p/databases/bulkdb/documents";
    call(
        &state,
        "POST",
        &format!("{docs}/items?documentId=a"),
        json!({"fields": {}}),
    );
    call(
        &state,
        "POST",
        &format!("{docs}/other?documentId=c"),
        json!({"fields": {"i": {"integerValue": "10"}}}),
    );
    let bulk = "/v1/projects/p/databases/bulkdb:bulkDeleteDocuments";
    let (status, answer) = call(&state, "POST", bulk, json!({}));
    assert_eq!(
        (status, answer["error"]["message"].as_str()),
        (
            400,
            Some("Empty entity filter. To delete all entities, Use database deletion instead.")
        )
    );
    let (status, operation) = call(&state, "POST", bulk, json!({"collectionIds": ["other"]}));
    assert_eq!(status, 200, "{operation}");
    assert!(operation["metadata"]["snapshotTime"]
        .as_str()
        .unwrap()
        .ends_with(":00Z"));
    let (_, done) = call(
        &state,
        "GET",
        &format!("/v1/{}", operation["name"].as_str().unwrap()),
        Value::Null,
    );
    // Production (2026-09-24): the stored size of other/c {i: 10} is 66 bytes.
    assert_eq!(
        done["metadata"]["progressBytes"],
        json!({"completedWork": "66"})
    );
    assert_eq!(
        done["metadata"]["progressDocuments"],
        json!({"completedWork": "1"})
    );
    assert_eq!(
        done["response"],
        json!({"@type": "type.googleapis.com/google.firestore.admin.v1.BulkDeleteDocumentsResponse"})
    );
    let (status, _) = call(&state, "GET", &format!("{docs}/other/c"), Value::Null);
    assert_eq!(status, 404);
    let (status, _) = call(&state, "GET", &format!("{docs}/items/a"), Value::Null);
    assert_eq!(status, 200);
}

#[test]
fn managed_infrastructure_is_refused_as_unimplemented() {
    let (state, _clock) = state();
    for (method, path) in [
        ("GET", "/v1/projects/p/databases/(default)/backupSchedules"),
        ("POST", "/v1/projects/p/databases/(default)/backupSchedules"),
        ("GET", "/v1/projects/p/locations/us-central1/backups"),
        ("DELETE", "/v1/projects/p/locations/us-central1/backups/b1"),
        ("POST", "/v1/projects/p/databases:restore"),
        ("POST", "/v1/projects/p/databases:clone"),
    ] {
        let (status, body) = call(&state, method, path, json!({}));
        assert_eq!(status, 501, "{method} {path}: {body}");
        assert!(body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("scope decision C1"));
    }
    let (status, _) = call(
        &state,
        "PATCH",
        "/v1/projects/p/databases/(default)?updateMask=pointInTimeRecoveryEnablement",
        json!({"pointInTimeRecoveryEnablement": "POINT_IN_TIME_RECOVERY_ENABLED"}),
    );
    assert_eq!(status, 501);
}

#[test]
fn a_malformed_index_id_is_refused_and_a_finished_build_reports_its_documents() {
    let (state, clock) = state();
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::from_secs(3600));
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=idxdb",
        native(),
    );
    let docs = "/v1/projects/p/databases/idxdb/documents";
    call(
        &state,
        "POST",
        &format!("{docs}/items?documentId=x"),
        json!({"fields": {}}),
    );
    call(
        &state,
        "POST",
        &format!("{docs}/items?documentId=y"),
        json!({"fields": {}}),
    );
    let group = "/v1/projects/p/databases/idxdb/collectionGroups/items/indexes";
    let (status, body) = call(&state, "GET", &format!("{group}/not-an-index"), Value::Null);
    assert_eq!(
        (status, body["error"]["message"].as_str()),
        (400, Some("Invalid index resource id \"not-an-index\"."))
    );
    let (_, operation) = call(
        &state,
        "POST",
        group,
        json!({"queryScope": "COLLECTION", "fields": [
            {"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "DESCENDING"}]}),
    );
    advance(&clock, 3600);
    let (_, done) = call(
        &state,
        "GET",
        &format!("/v1/{}", operation["name"].as_str().unwrap()),
        Value::Null,
    );
    assert_eq!(
        done["metadata"]["progressDocuments"],
        json!({"estimatedWork": "2", "completedWork": "2"})
    );
    assert_ne!(done["metadata"]["startTime"], done["metadata"]["endTime"]);
}

#[test]
fn an_unpinned_backend_stamps_admin_changes_with_the_wall_clock() {
    // Production stamps a patch after the create; an unpinned daemon writes documents at the
    // wall clock and must stamp Admin changes the same way, not at a clock nothing advances.
    let (state, _clock) = state();
    let state = RestState {
        local: Arc::new(
            LocalBackend::new(
                (*state.gateway).clone(),
                Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(0)))),
                7,
            )
            .with_wall_clock_write_time(),
        ),
        ..state
    };
    let (status, created) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=wall",
        native(),
    );
    assert_eq!(status, 200, "{created}");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let (status, patched) = call(
        &state,
        "PATCH",
        "/v1/projects/p/databases/wall?updateMask=deleteProtectionState",
        json!({"deleteProtectionState": "DELETE_PROTECTION_ENABLED"}),
    );
    assert_eq!(status, 200, "{patched}");
    let created_at = created["response"]["createTime"].as_str().unwrap();
    let updated_at = patched["response"]["updateTime"].as_str().unwrap();
    assert!(!created_at.starts_with("1970"), "{created_at}");
    assert!(updated_at > created_at, "{created_at} then {updated_at}");
}

#[test]
fn deleting_a_database_resets_no_request_in_flight_elsewhere() {
    // A delete detaches one database; a request on another database that verified its
    // credentials before the delete must still be admitted (it is not a session reset).
    let (state, _clock) = state();
    let (status, _) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=gone",
        native(),
    );
    assert_eq!(status, 200);
    let barrier = state.local.barrier();
    let seen = barrier.epoch();
    let (status, deleted) = call(&state, "DELETE", "/v1/projects/p/databases/gone", json!({}));
    assert_eq!(status, 200, "{deleted}");
    assert!(barrier.admit_since(seen).is_ok());
}

#[test]
fn the_default_database_reports_the_configured_create_time() {
    // firestore.databaseCreateTime is when the daemon's databases came into being; the
    // Admin resource of (default) reports it, like production reports when it was created.
    let (state, _clock) = state();
    let created = LogicalInstant::from_nanos(1_780_000_000_000_000_000);
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(
        1_790_000_000_000_000_000,
    ))));
    let state = RestState {
        local: Arc::new(
            LocalBackend::new((*state.gateway).clone(), clock, 7).with_created_at(created),
        ),
        ..state
    };
    let (status, database) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/(default)",
        Value::Null,
    );
    assert_eq!(status, 200, "{database}");
    assert_eq!(database["createTime"], "2026-05-28T20:26:40Z");
    assert_eq!(database["updateTime"], "2026-05-28T20:26:40Z");
}

#[test]
fn operations_list_filter_cancel_and_delete_follow_production() {
    // Production (2026-09-24): a database create is not listed; `done=true` filters; a bare
    // term is refused; an index build cannot be cancelled; a running one cannot be deleted.
    let (state, _clock) = state();
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::from_secs(3600));
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=opsdb",
        native(),
    );
    let operations = "/v1/projects/p/databases/opsdb/operations";
    assert_eq!(
        call(&state, "GET", operations, Value::Null),
        (200, json!({}))
    );
    let index = json!({"queryScope": "COLLECTION", "fields": [
        {"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "DESCENDING"}]});
    let (status, created) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/opsdb/collectionGroups/items/indexes",
        index,
    );
    assert_eq!(status, 200, "{created}");
    let name = created["name"].as_str().unwrap().to_owned();
    let (_, listed) = call(&state, "GET", operations, Value::Null);
    assert_eq!(
        listed["operations"].as_array().unwrap().len(),
        1,
        "{listed}"
    );
    assert_eq!(listed["operations"][0]["name"], name);
    let filtered = |filter: &str| {
        call(
            &state,
            "GET",
            &format!("{operations}?filter={filter}"),
            Value::Null,
        )
    };
    assert_eq!(filtered("done=true"), (200, json!({})));
    assert_eq!(filtered("done=false").1["operations"][0]["name"], name);
    assert_eq!(
        filtered("nope"),
        (
            400,
            json!({"error": {"code": 400, "status": "INVALID_ARGUMENT",
                "message": "Error evaluating filter: Filtering does not support GLOBAL comparator nope."}})
        )
    );
    let cancel = call(&state, "POST", &format!("/v1/{name}:cancel"), json!({}));
    assert_eq!(
        cancel,
        (
            400,
            json!({"error": {"code": 400, "status": "INVALID_ARGUMENT",
                "message": "CancelOperation is not supported for operation type BUILD_INDEX."}})
        )
    );
    let delete = call(&state, "DELETE", &format!("/v1/{name}"), Value::Null);
    assert_eq!(
        delete,
        (
            400,
            json!({"error": {"code": 400, "status": "FAILED_PRECONDITION",
                "message": "Precondition check failed."}})
        )
    );
    assert_eq!(
        call(&state, "GET", &format!("/v1/{name}"), Value::Null).0,
        200
    );
}

#[test]
fn database_patch_and_delete_refusals_use_production_messages() {
    let (state, _clock) = state();
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=patchy",
        native(),
    );
    let db = "/v1/projects/p/databases/patchy";
    let refused = |status: u16, code: &str, message: &str| {
        (
            status,
            json!({"error": {"code": status, "status": code, "message": message}}),
        )
    };
    assert_eq!(
        call(
            &state,
            "PATCH",
            &format!("{db}?updateMask=databaseEdition"),
            json!({"databaseEdition": "ENTERPRISE"})
        ),
        refused(
            400,
            "INVALID_ARGUMENT",
            "Changing the edition of a database is not supported."
        )
    );
    assert_eq!(
        call(&state, "PATCH", &format!("{db}?updateMask=foo"), json!({})),
        refused(
            400,
            "INVALID_ARGUMENT",
            "Invalid updateMask for database proto."
        )
    );
    let missing = refused(404, "NOT_FOUND", "Requested database was not found.");
    assert_eq!(
        call(
            &state,
            "PATCH",
            "/v1/projects/p/databases/never-made?updateMask=deleteProtectionState",
            json!({"deleteProtectionState": "DELETE_PROTECTION_DISABLED"})
        ),
        missing
    );
    assert_eq!(
        call(
            &state,
            "DELETE",
            "/v1/projects/p/databases/never-made",
            Value::Null
        ),
        missing
    );
    assert_eq!(
        call(
            &state,
            "GET",
            "/v1/projects/p/databases/never-made/operations",
            Value::Null
        ),
        refused(
            404,
            "NOT_FOUND",
            "Project 'p' or database 'never-made' does not exist."
        )
    );
    assert_eq!(
        call(
            &state,
            "DELETE",
            &format!("{db}?etag=AAAAAAAAAAAAAAAA"),
            Value::Null
        ),
        refused(
            409,
            "ABORTED",
            "There are concurrent database changes, please try again."
        )
    );
}

#[test]
fn an_empty_native_database_can_become_a_datastore_mode_database() {
    // Production (2026-09-24) accepts the type change on an empty database; realtime updates
    // are then disabled, and the data plane refuses it like any Datastore-mode database.
    let (state, _clock) = state();
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=switch",
        native(),
    );
    let (status, operation) = call(
        &state,
        "PATCH",
        "/v1/projects/p/databases/switch?updateMask=type",
        json!({"type": "DATASTORE_MODE"}),
    );
    assert_eq!(status, 200, "{operation}");
    assert_eq!(operation["done"], true);
    assert_eq!(operation["response"]["type"], "DATASTORE_MODE");
    assert_eq!(
        operation["response"]["realtimeUpdatesMode"],
        "REALTIME_UPDATES_MODE_DISABLED"
    );
    let (status, get) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/switch",
        Value::Null,
    );
    assert_eq!((status, &get["type"]), (200, &json!("DATASTORE_MODE")));
    let (status, _) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/switch/documents/items/a",
        Value::Null,
    );
    assert_ne!(status, 200);

    // A database with a document keeps its type (production, 2026-09-24).
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=keeper",
        native(),
    );
    call(
        &state,
        "POST",
        "/v1/projects/p/databases/keeper/documents/items?documentId=a",
        json!({"fields": {"a": {"integerValue": "1"}}}),
    );
    assert_eq!(
        call(
            &state,
            "PATCH",
            "/v1/projects/p/databases/keeper?updateMask=type",
            json!({"type": "DATASTORE_MODE"}),
        ),
        (
            400,
            json!({"error": {"code": 400, "status": "FAILED_PRECONDITION",
                "message": "A document with key '/items/a' exists in the database. The database must be empty to make this change. Delete this document and try again."}})
        )
    );
}

#[test]
fn a_bounded_backend_refuses_other_projects_as_production_refuses_a_foreign_one() {
    // Scope decision C11: with projects.unknownProjects = "refuse", only the daemon's project
    // exists; production answers a project the credential cannot use like this (2026-09-24).
    let (state, _clock) = state();
    let (status, _) = call(
        &state,
        "GET",
        "/v1/projects/elsewhere/databases",
        Value::Null,
    );
    assert_eq!(status, 200, "unbounded by default");
    let bounded = RestState {
        local: Arc::new(
            LocalBackend::new(
                (*state.gateway).clone(),
                Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(0)))),
                7,
            )
            .with_project_boundary("p"),
        ),
        ..state
    };
    let refusal = json!({"error": {
        "code": 403,
        "message": "Permission denied on resource project elsewhere.",
        "status": "PERMISSION_DENIED",
        "details": [
            {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "domain": "googleapis.com",
             "metadata": {"consumer": "projects/elsewhere", "containerInfo": "elsewhere",
                          "service": "firestore.googleapis.com"},
             "reason": "CONSUMER_INVALID"},
            {"@type": "type.googleapis.com/google.rpc.LocalizedMessage", "locale": "en-US",
             "message": "Permission denied on resource project elsewhere."},
            {"@type": "type.googleapis.com/google.rpc.Help",
             "links": [{"description": "Google developers console",
                        "url": "https://console.developers.google.com"}]}
        ]
    }});
    for path in [
        "/v1/projects/elsewhere/databases",
        "/v1/projects/elsewhere/databases/(default)",
        "/v1/projects/elsewhere/databases/(default)/documents/c/d",
        "/v1/projects/elsewhere/locations",
    ] {
        assert_eq!(
            call(&bounded, "GET", path, Value::Null),
            (403, refusal.clone()),
            "{path}"
        );
    }
    let (status, _) = call(&bounded, "GET", "/v1/projects/p/databases", Value::Null);
    assert_eq!(status, 200);
    // An encoded spelling of the daemon's project is not a way around the boundary.
    let (status, _) = call(
        &bounded,
        "POST",
        "/v1/projects/%70/databases?databaseId=sneaky",
        native(),
    );
    assert_eq!(status, 403);
}

#[test]
fn a_finished_index_build_over_no_documents_still_reports_its_progress() {
    // Production (2026-09-24): the done operation carries progressDocuments {} when the
    // collection group is empty (proto3 JSON leaves out only the zero counts).
    let (state, _clock) = state();
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::ZERO);
    call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=emptyidx",
        native(),
    );
    let index = json!({"queryScope": "COLLECTION", "fields": [
        {"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "DESCENDING"}]});
    let (_, created) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/emptyidx/collectionGroups/items/indexes",
        index,
    );
    let (_, done) = call(
        &state,
        "GET",
        &format!("/v1/{}", created["name"].as_str().unwrap()),
        Value::Null,
    );
    assert_eq!(done["done"], true, "{done}");
    assert_eq!(done["metadata"]["progressDocuments"], json!({}), "{done}");
}

#[test]
fn a_deleted_default_database_lists_nothing_and_can_be_recreated_after_the_cooldown() {
    // Production (fireemu-fs-bisect-0924a, 2026-09-24): after (default) is deleted the list is
    // {} and its index list is still served; it can be created again once the id is free.
    let (state, _clock) = state();
    state.local.admin().set_deleted_id_cooldown(0);
    let (_, before) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/(default)",
        Value::Null,
    );
    assert_eq!(before["freeTier"], true);
    let (status, deleted) = call(
        &state,
        "DELETE",
        "/v1/projects/p/databases/(default)",
        Value::Null,
    );
    assert_eq!(status, 200);
    // The deleted database no longer holds the free tier.
    assert_eq!(deleted["response"]["freeTier"], false, "{deleted}");
    assert_eq!(
        call(&state, "GET", "/v1/projects/p/databases", Value::Null),
        (200, json!({}))
    );
    assert_eq!(
        call(
            &state,
            "GET",
            "/v1/projects/p/databases/(default)/collectionGroups/-/indexes",
            Value::Null
        ),
        (
            404,
            json!({"error": {"code": 404, "status": "NOT_FOUND",
                "message": "Project 'p' or database '(default)' does not exist."}})
        ),
        "production's lasting answer once the deletion settles (fireemu-fs-bisect-0924a, 2026-09-24)"
    );
    let (status, created) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=(default)",
        native(),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        created["response"]["freeTier"], true,
        "a recreated (default) is free tier"
    );
    let (status, _) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/(default)",
        Value::Null,
    );
    assert_eq!(status, 200);
    let (status, missing) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/(default)/documents/c/d",
        Value::Null,
    );
    assert_eq!(status, 404);
    assert_eq!(
        missing["error"]["message"],
        "Document \"projects/p/databases/(default)/documents/c/d\" not found."
    );
}

fn configured_state() -> RestState {
    // (default) with one index declared in the index file, as a deployed index.
    let (state, _clock) = state();
    let mut indexes = IndexSet::default();
    indexes.add_composite(fireemu_core_firestore::index::IndexDefinition {
        collection_group: fireemu_core_types::ids::CollectionId::try_new("items").unwrap(),
        query_scope: fireemu_core_firestore::index::IndexQueryScope::Collection,
        fields: vec![
            fireemu_core_firestore::index::IndexField {
                path: fireemu_core_firestore::field_path::FieldPath::parse("a").unwrap(),
                mode: fireemu_core_firestore::index::IndexFieldMode::Ascending,
            },
            fireemu_core_firestore::index::IndexField {
                path: fireemu_core_firestore::field_path::FieldPath::parse("b").unwrap(),
                mode: fireemu_core_firestore::index::IndexFieldMode::Descending,
            },
        ],
    });
    let gateway = Gateway {
        indexes,
        ..(*state.gateway).clone()
    };
    RestState {
        local: Arc::new(LocalBackend::new(
            gateway.clone(),
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(
                1_790_000_000_000_000_000,
            )))),
            7,
        )),
        gateway: Arc::new(gateway),
        ..state
    }
}

#[test]
fn indexes_declared_in_the_index_file_are_listed_deleted_and_dropped_with_their_database() {
    // Production (2026-09-24) lists deployed indexes READY; after its database is deleted it
    // still lists them, and a recreated database has none.
    let state = configured_state();
    state.local.admin().set_deleted_id_cooldown(0);
    let list = "/v1/projects/p/databases/(default)/collectionGroups/-/indexes";
    let (status, listed) = call(&state, "GET", list, Value::Null);
    assert_eq!(status, 200, "{listed}");
    let index = &listed["indexes"][0];
    assert_eq!(index["state"], "READY", "{listed}");
    assert_eq!(
        index["fields"],
        json!([{"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "DESCENDING"},
               {"fieldPath": "__name__", "order": "DESCENDING"}])
    );
    let name = index["name"].as_str().unwrap().to_owned();
    let id = name.rsplit('/').next().unwrap().to_owned();
    assert_eq!(
        call(&state, "GET", &format!("/v1/{name}"), Value::Null).1,
        *index
    );
    let (status, duplicate) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
        json!({"queryScope": "COLLECTION", "fields": [
            {"fieldPath": "a", "order": "ASCENDING"}, {"fieldPath": "b", "order": "DESCENDING"}]}),
    );
    assert_eq!(
        (status, duplicate["error"]["message"].as_str()),
        (
            409,
            Some(format!("index already exists with index ID = {id}").as_str())
        )
    );
    let query = json!({"structuredQuery": {
        "from": [{"collectionId": "items"}],
        "where": {"fieldFilter": {"field": {"fieldPath": "a"}, "op": "EQUAL", "value": {"integerValue": "1"}}},
        "orderBy": [{"field": {"fieldPath": "b"}, "direction": "DESCENDING"}]
    }});
    let docs = "/v1/projects/p/databases/(default)/documents";
    assert_eq!(
        call(&state, "POST", &format!("{docs}:runQuery"), query.clone()).0,
        200
    );

    // Deleting the database keeps its index list served; recreating it starts with none.
    call(
        &state,
        "DELETE",
        "/v1/projects/p/databases/(default)",
        Value::Null,
    );
    // Production lists them for a while, then answers NOT_FOUND; fireemu answers the settled
    // state (C10).
    let (status, _) = call(&state, "GET", list, Value::Null);
    assert_eq!(status, 404);
    let (status, _) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=(default)",
        native(),
    );
    assert_eq!(status, 200);
    assert_eq!(call(&state, "GET", list, Value::Null), (200, json!({})));
    assert_eq!(
        call(&state, "POST", &format!("{docs}:runQuery"), query).0,
        400
    );
}

#[test]
fn deleting_a_declared_index_withdraws_it_from_queries() {
    let state = configured_state();
    let list = "/v1/projects/p/databases/(default)/collectionGroups/-/indexes";
    let (_, listed) = call(&state, "GET", list, Value::Null);
    let name = listed["indexes"][0]["name"].as_str().unwrap().to_owned();
    assert_eq!(
        call(&state, "DELETE", &format!("/v1/{name}"), Value::Null).0,
        200
    );
    assert_eq!(call(&state, "GET", list, Value::Null), (200, json!({})));
    let query = json!({"structuredQuery": {
        "from": [{"collectionId": "items"}],
        "where": {"fieldFilter": {"field": {"fieldPath": "a"}, "op": "EQUAL", "value": {"integerValue": "1"}}},
        "orderBy": [{"field": {"fieldPath": "b"}, "direction": "DESCENDING"}]
    }});
    let (status, _) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/documents:runQuery",
        query,
    );
    assert_eq!(status, 400);
}

#[test]
fn a_reloaded_index_file_is_what_the_admin_api_lists_and_the_planner_uses() {
    // The index file can be reloaded at any time: its current indexes are the deployed ones,
    // and a query (which may name any database) never records anything in the registry.
    let state = configured_state();
    let list = "/v1/projects/p/databases/(default)/collectionGroups/-/indexes";
    let query = json!({"structuredQuery": {
        "from": [{"collectionId": "items"}],
        "where": {"fieldFilter": {"field": {"fieldPath": "a"}, "op": "EQUAL", "value": {"integerValue": "1"}}},
        "orderBy": [{"field": {"fieldPath": "b"}, "direction": "DESCENDING"}]
    }});
    let docs = "/v1/projects/p/databases/(default)/documents";
    assert_eq!(
        call(&state, "POST", &format!("{docs}:runQuery"), query.clone()).0,
        200
    );
    assert_eq!(
        call(&state, "GET", list, Value::Null).1["indexes"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    state.local.replace_indexes(IndexSet::default());
    assert_eq!(call(&state, "GET", list, Value::Null), (200, json!({})));
    assert_eq!(
        call(&state, "POST", &format!("{docs}:runQuery"), query.clone()).0,
        400
    );
    state
        .local
        .replace_indexes(configured_state().gateway.indexes.clone());
    assert_eq!(
        call(&state, "POST", &format!("{docs}:runQuery"), query).0,
        200
    );
    assert_eq!(
        call(&state, "GET", list, Value::Null).1["indexes"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn refused_queries_leave_the_admin_index_registry_unchanged() {
    // A query may name any project or database; planning only reads the registry, so a
    // request without owner credentials can never grow it (security review, 2026-09-24).
    let (state, _clock) = state();
    let bounded = RestState {
        local: Arc::new(
            LocalBackend::new(
                (*state.gateway).clone(),
                Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(0)))),
                7,
            )
            .with_project_boundary("p"),
        ),
        ..state
    };
    let before = bounded.local.admin().indexes().entry_count();
    let query = json!({"structuredQuery": {
        "from": [{"collectionId": "items"}],
        "orderBy": [{"field": {"fieldPath": "a"}}, {"field": {"fieldPath": "b"}, "direction": "DESCENDING"}]
    }});
    for (project, database) in [
        ("elsewhere", "(default)"),
        ("p", "never-made"),
        ("p", "(default)"),
    ] {
        for n in 0..20 {
            let path = format!("/v1/projects/{project}{n}/databases/{database}/documents:runQuery");
            call(&bounded, "POST", &path, query.clone());
        }
        let path = format!("/v1/projects/{project}/databases/{database}/documents:runQuery");
        call(&bounded, "POST", &path, query.clone());
    }
    assert_eq!(bounded.local.admin().indexes().entry_count(), before);
}

/// Known edge, unobserved in production (issue: managed Admin operations use Commit-route limits
/// in strict): a managed import writes through the Commit route, so under strict it applies the
/// data plane's limits. An export the emulator profile wrote may hold a document strict refuses to
/// write, here a name over the recorded index-entry bound, and strict refuses the chunk of up to
/// 500 documents that holds it. The emulator profile imports the same export.
#[test]
fn strict_import_applies_commit_route_limits_to_exported_documents() {
    let storage = Arc::new(MemoryStorage::default());
    let (emulator, _emulator_clock) = state_with_limits(false);
    let (strict, _strict_clock) = state_with_limits(true);
    for (target, db) in [
        (&emulator, "srcdb"),
        (&strict, "dstdb"),
        (&emulator, "copydb"),
    ] {
        target
            .local
            .admin()
            .set_managed_storage(Arc::clone(&storage) as _);
        call(
            target,
            "POST",
            &format!("/v1/projects/p/databases?databaseId={db}"),
            native(),
        );
    }
    let name = format!(
        "{}/{}/{}/{}",
        "a".repeat(1_500),
        "b".repeat(1_500),
        "c".repeat(1_500),
        "d".repeat(200)
    );
    let (status, body) = call(
        &emulator,
        "PATCH",
        &format!("/v1/projects/p/databases/srcdb/documents/{name}"),
        json!({"fields": {}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = call(
        &strict,
        "PATCH",
        &format!("/v1/projects/p/databases/dstdb/documents/{name}"),
        json!({"fields": {}}),
    );
    assert_eq!(
        (status, body["error"]["message"].as_str()),
        (400, Some("Index entry is too large."))
    );
    let (status, _) = call(
        &emulator,
        "POST",
        "/v1/projects/p/databases/srcdb:exportDocuments",
        json!({"outputUriPrefix": "gs://run-bucket/x/all"}),
    );
    assert_eq!(status, 200);
    let (status, answer) = call(
        &strict,
        "POST",
        "/v1/projects/p/databases/dstdb:importDocuments",
        json!({"inputUriPrefix": "gs://run-bucket/x/all"}),
    );
    assert_eq!(
        (status, answer["error"]["message"].as_str()),
        (400, Some("Index entry is too large."))
    );
    let (status, _) = call(
        &strict,
        "GET",
        &format!("/v1/projects/p/databases/dstdb/documents/{name}"),
        Value::Null,
    );
    assert_eq!(status, 404, "a refused import publishes nothing");
    let (status, operation) = call(
        &emulator,
        "POST",
        "/v1/projects/p/databases/copydb:importDocuments",
        json!({"inputUriPrefix": "gs://run-bucket/x/all"}),
    );
    assert_eq!(status, 200, "{operation}");
    let (status, _) = call(
        &emulator,
        "GET",
        &format!("/v1/projects/p/databases/copydb/documents/{name}"),
        Value::Null,
    );
    assert_eq!(status, 200);
}

#[test]
fn enterprise_native_index_listing_requires_default_page_size() {
    let (state, _) = state();
    let mut database = native();
    database["databaseEdition"] = json!("ENTERPRISE");
    let (status, _) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=entpages",
        database,
    );
    assert_eq!(status, 200);
    let path = "/v1/projects/p/databases/entpages/collectionGroups/items/indexes";
    let (status, body) = call(&state, "GET", &format!("{path}?pageSize=100"), Value::Null);
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body,
        json!({"error": {
            "code": 400, "message": "Invalid page size. Only 0 is supported.",
            "status": "INVALID_ARGUMENT"
        }})
    );
    let with_page_size = call(
        &state,
        "GET",
        &format!("{path}/missing?pageSize=100"),
        Value::Null,
    );
    let without_page_size = call(&state, "GET", &format!("{path}/missing"), Value::Null);
    assert_eq!(with_page_size, without_page_size);
    assert_eq!(
        without_page_size.1["error"]["message"],
        "Invalid index resource id \"missing\"."
    );
    for suffix in ["", "?pageSize=0"] {
        let (status, body) = call(&state, "GET", &format!("{path}{suffix}"), Value::Null);
        assert_eq!(status, 200, "{body}");
    }
    let (status, _) = call(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=stdpages",
        native(),
    );
    assert_eq!(status, 200);
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/stdpages/collectionGroups/items/indexes?pageSize=100",
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
}

fn enterprise_native_state(strict: bool) -> (RestState, Arc<Mutex<VirtualClock>>) {
    let (state, clock) = state_with_context(
        strict,
        if strict {
            IndexValidationPolicy::Production
        } else {
            IndexValidationPolicy::Emulator
        },
        FirestoreEdition::Enterprise,
        FirestoreApiMode::Native,
    );
    state
        .local
        .replace_declared_databases(["entnamed".to_owned()]);
    (state, clock)
}

#[test]
fn configured_enterprise_native_admin_preserves_data_access() {
    for strict in [true, false] {
        let (state, _) = enterprise_native_state(strict);
        for database in ["(default)", "entnamed"] {
            let base = format!("/v1/projects/p/databases/{database}");
            let index = format!("{base}/collectionGroups/items/indexes");
            let pipeline = json!({"structuredPipeline":{"pipeline":{"stages":[
                {"name":"collection","args":[{"referenceValue":"/items"}]}
            ]}}});
            for phase in ["before", "after"] {
                let path = format!("{base}/documents/items/{phase}");
                let (status, body) = call(
                    &state,
                    "PATCH",
                    &path,
                    json!({"fields":{"a":{"integerValue":"1"}}}),
                );
                assert_eq!(status, 200, "{strict} {database} {phase}: {body}");
                let (status, body) = call(&state, "GET", &path, Value::Null);
                assert_eq!(status, 200, "{body}");
                let (status, body) = call(
                    &state,
                    "POST",
                    &format!("{base}/documents:executePipeline"),
                    pipeline.clone(),
                );
                assert_eq!(status, 200, "{strict} {phase}: {body}");
                assert_eq!(
                    body.as_array().unwrap().len(),
                    if phase == "before" { 1 } else { 2 }
                );
                for suffix in ["", "?pageSize=0"] {
                    let (status, body) =
                        call(&state, "GET", &format!("{index}{suffix}"), Value::Null);
                    assert_eq!(status, 200, "{strict} {database}: {body}");
                }
                let record = state.local.admin().get("p", database, true).unwrap();
                let metadata = super::rest::database_json(&record, state.local.admin_now(), None);
                assert_eq!(metadata["databaseEdition"], "ENTERPRISE");
                assert_eq!(metadata["type"], "FIRESTORE_NATIVE");
                assert_eq!(metadata["concurrencyMode"], "OPTIMISTIC");
                assert_eq!(
                    metadata["firestoreDataAccessMode"],
                    "DATA_ACCESS_MODE_ENABLED"
                );
                assert_eq!(
                    metadata["mongodbCompatibleDataAccessMode"],
                    "DATA_ACCESS_MODE_DISABLED"
                );
                let (status, body) =
                    call(&state, "GET", &format!("{index}?pageSize=100"), Value::Null);
                assert_eq!(status, 400, "{body}");
                assert_eq!(
                    body["error"]["message"],
                    "Invalid page size. Only 0 is supported."
                );
            }
        }
    }
}

#[test]
fn configured_enterprise_native_indexes_and_operations_are_scoped() {
    let (state, clock) = enterprise_native_state(true);
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::from_secs(60));
    for database in ["(default)", "entnamed"] {
        let group = format!("/v1/projects/p/databases/{database}/collectionGroups/items/indexes");
        let (status, operation) = call(
            &state,
            "POST",
            &group,
            json!({"queryScope":"COLLECTION","fields":[
                {"fieldPath":"a","order":"ASCENDING"},{"fieldPath":"b","order":"DESCENDING"}
            ]}),
        );
        assert_eq!(status, 200, "{operation}");
        let index = format!("/v1/{}", operation["metadata"]["index"].as_str().unwrap());
        let operation_path = format!("/v1/{}", operation["name"].as_str().unwrap());
        assert_eq!(
            call(&state, "GET", &index, Value::Null).1["state"],
            "CREATING"
        );
        assert_eq!(call(&state, "GET", &operation_path, Value::Null).0, 200);
        let operations = format!("/v1/projects/p/databases/{database}/operations");
        assert_eq!(
            call(&state, "GET", &operations, Value::Null).1["operations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let foreign = operation_path.replacen("/projects/p/", "/projects/other/", 1);
        assert_eq!(call(&state, "GET", &foreign, Value::Null).0, 404);
        advance(&clock, 60);
        assert_eq!(
            call(&state, "GET", &operation_path, Value::Null).1["done"],
            true
        );
        assert_eq!(call(&state, "GET", &index, Value::Null).1["state"], "READY");
        assert_eq!(
            call(&state, "DELETE", &index, Value::Null),
            (200, json!({}))
        );
        assert_eq!(call(&state, "GET", &index, Value::Null).0, 404);
    }
}

#[test]
fn configured_admin_gate_preserves_unrelated_and_mongodb_refusals() {
    for mode in [
        FirestoreApiMode::Native,
        FirestoreApiMode::MongoDbCompatible,
    ] {
        let (state, _) = state_with_context(
            true,
            IndexValidationPolicy::Production,
            FirestoreEdition::Enterprise,
            mode,
        );
        for (method, suffix) in [
            ("GET", ""),
            ("PATCH", ""),
            ("DELETE", ""),
            ("GET", "/changeStreams"),
            ("GET", "/userCreds/u"),
            ("POST", ":exportDocuments"),
            ("POST", ":importDocuments"),
            ("POST", ":bulkDeleteDocuments"),
        ] {
            let (status, body) = call(
                &state,
                method,
                &format!("/v1/projects/p/databases/(default){suffix}"),
                Value::Null,
            );
            assert_eq!(status, 501, "{mode:?} {suffix}: {body}");
        }
        if mode == FirestoreApiMode::MongoDbCompatible {
            for suffix in ["collectionGroups/items/indexes", "operations"] {
                assert_eq!(
                    call(
                        &state,
                        "GET",
                        &format!("/v1/projects/p/databases/(default)/{suffix}"),
                        Value::Null
                    )
                    .0,
                    501
                );
            }
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(48))]
    #[test]
    fn configured_enterprise_native_route_boundary(
        strict in proptest::prelude::any::<bool>(),
        named in proptest::prelude::any::<bool>(),
        mongo in proptest::prelude::any::<bool>(),
        route in 0_usize..16,
    ) {
        let mode = if mongo { FirestoreApiMode::MongoDbCompatible } else { FirestoreApiMode::Native };
        let (state, _) = state_with_context(strict,
            if strict { IndexValidationPolicy::Production } else { IndexValidationPolicy::Emulator },
            FirestoreEdition::Enterprise, mode);
        state.local.replace_declared_databases(["entnamed".to_owned()]);
        let database = if named { "entnamed" } else { "(default)" };
        let (method, suffix, allowed) = [
            ("GET", "/collectionGroups/items/indexes", true),
            ("GET", "/collectionGroups/items/indexes/missing", true),
            ("GET", "/operations", true),
            ("GET", "/operations/missing", true),
            ("POST", "/collectionGroups/items/indexes", true),
            ("DELETE", "/collectionGroups/items/indexes/missing", true),
            ("DELETE", "/operations/missing", true),
            ("POST", "/operations/missing:cancel", true),
            ("DELETE", "/operations", false),
            ("POST", "/operations/missing", false),
            ("POST", "/collectionGroups/items/indexes/missing", false),
            ("GET", "", false),
            ("GET", "/userCreds", false),
            ("POST", ":exportDocuments", false),
            ("PATCH", "/collectionGroups/items/indexes/missing", false),
            ("POST", "/operations", false),
        ][route];
        let (status, _) = call(&state, method, &format!("/v1/projects/p/databases/{database}{suffix}"), Value::Null);
        proptest::prop_assert_eq!(status != 501, allowed && !mongo);
    }
}

fn native_text_body() -> Value {
    json!({"queryScope":"COLLECTION","fields":[{
        "fieldPath":"title","searchConfig":{"textSpec":{"indexSpecs":[{
            "indexType":"TOKENIZED","matchType":"MATCH_GLOBALLY"
        }]}}
    }],"searchIndexOptions":{"textLanguage":"en","textLanguageOverrideFieldPath":"language"}})
}

fn native_text_state() -> (
    RestState,
    Arc<Mutex<VirtualClock>>,
    Arc<Mutex<fireemu_core_firestore::text_index::TextIndexCatalog>>,
) {
    native_text_state_for(true)
}

fn native_text_state_for(
    strict: bool,
) -> (
    RestState,
    Arc<Mutex<VirtualClock>>,
    Arc<Mutex<fireemu_core_firestore::text_index::TextIndexCatalog>>,
) {
    native_text_state_exact(strict, false)
}

fn native_text_state_exact(
    strict: bool,
    production_exact: bool,
) -> (
    RestState,
    Arc<Mutex<VirtualClock>>,
    Arc<Mutex<fireemu_core_firestore::text_index::TextIndexCatalog>>,
) {
    let (state, clock) = enterprise_native_state(strict);
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::from_secs(3600));
    let catalog = Arc::new(Mutex::new(
        fireemu_core_firestore::text_index::TextIndexCatalog::default(),
    ));
    state
        .local
        .set_text_indexes(Arc::clone(&catalog), production_exact)
        .unwrap();
    (state, clock, catalog)
}

#[test]
fn native_text_admin_multiple_fields_preserve_definition_and_search_both_fields() {
    for strict in [true, false] {
        for database in ["(default)", "entnamed"] {
            for explicit_override in [true, false] {
                let (state, clock, _) = native_text_state_for(strict);
                let base = format!("/v1/projects/p/databases/{database}");
                let group = format!("{base}/collectionGroups/items/indexes");
                let mut request = native_text_body();
                let mut second = request["fields"][0].clone();
                second["fieldPath"] = json!("body");
                request["fields"].as_array_mut().unwrap().push(second);
                if !explicit_override {
                    request["searchIndexOptions"]
                        .as_object_mut()
                        .unwrap()
                        .remove("textLanguageOverrideFieldPath");
                }
                for (id, field) in [("titleonly", "title"), ("bodyonly", "body")] {
                    let mut fields = serde_json::Map::new();
                    fields.insert(field.into(), json!({"stringValue":"multifieldmarker"}));
                    fields.insert("language".into(), json!({"stringValue":"en"}));
                    let (status, document) = call(
                        &state,
                        "PATCH",
                        &format!("{base}/documents/items/{id}"),
                        json!({"fields":fields}),
                    );
                    assert_eq!(status, 200, "{document}");
                }
                let (status, initial) = call(&state, "POST", &group, request.clone());
                assert_eq!(status, 200, "{strict} {database}: {initial}");
                let index = format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap());
                let operation = format!("/v1/{}", initial["name"].as_str().unwrap());
                let (status, creating) = call(&state, "GET", &index, Value::Null);
                assert_eq!(status, 200, "{creating}");
                assert_eq!(creating["fields"], request["fields"]);
                assert_eq!(creating["density"], "SPARSE_ANY");
                assert_eq!(
                    creating["searchIndexOptions"],
                    native_text_body()["searchIndexOptions"]
                );
                let (status, listed) = call(&state, "GET", &group, Value::Null);
                assert_eq!(status, 200, "{listed}");
                assert_eq!(listed["indexes"], json!([creating]));
                advance(&clock, 3600);
                let (status, terminal) = call(&state, "GET", &operation, Value::Null);
                assert_eq!(status, 200, "{terminal}");
                assert_eq!(terminal["done"], true);
                assert_eq!(terminal["response"]["state"], "READY");
                assert_eq!(terminal["response"]["fields"], request["fields"]);
                assert_eq!(
                    terminal["response"]["searchIndexOptions"],
                    native_text_body()["searchIndexOptions"]
                );
                let (status, hits) = call(
                    &state,
                    "POST",
                    &format!("{base}/documents:executePipeline"),
                    json!({"structuredPipeline":{"pipeline":{"stages":[
                        {"name":"collection","args":[{"referenceValue":"/items"}]},
                        {"name":"search","options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":"multifieldmarker"}]}}}}
                    ]}}}),
                );
                assert_eq!(status, 200, "{hits}");
                assert_eq!(hits[0]["results"].as_array().unwrap().len(), 2, "{hits}");
            }
        }
    }
}

#[test]
fn native_text_admin_multiple_fields_refuse_unobserved_shapes() {
    for strict in [true, false] {
        for variant in 0..6 {
            let (state, _, _) = native_text_state_for(strict);
            let mut request = native_text_body();
            let mut second = request["fields"][0].clone();
            second["fieldPath"] = json!("body");
            request["fields"].as_array_mut().unwrap().push(second);
            match variant {
                0 => request["fields"] = json!([]),
                1 => request["fields"][1] = json!({"fieldPath":"body","order":"ASCENDING"}),
                2 => {
                    request["fields"][1]["searchConfig"]["textSpec"]["indexSpecs"][0]
                        ["indexType"] = json!("UNRECORDED");
                }
                3 => request["fields"][1]["extra"] = json!(true),
                4 => request["fields"][1]["fieldPath"] = json!(null),
                _ => request["fields"][1]["fieldPath"] = json!("title"),
            }
            let (status, response) = call(
                &state,
                "POST",
                "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
                request,
            );
            assert_ne!(status, 200, "{strict} {variant}: {response}");
            if variant != 5 {
                assert_eq!(status, 501, "{strict} {variant}: {response}");
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_text_admin_cross_group_list_is_database_scoped_and_keeps_item_scope() {
    for strict in [true, false] {
        let (state, clock, _) = native_text_state_for(strict);
        let base = "/v1/projects/p/databases/(default)";
        let mut text_indexes = Vec::new();
        let mut text_operations = Vec::new();
        for group in ["articles", "notes"] {
            let (status, created) = call(
                &state,
                "POST",
                &format!("{base}/collectionGroups/{group}/indexes"),
                native_text_body(),
            );
            assert_eq!(status, 200, "{created}");
            text_indexes.push(created["metadata"]["index"].as_str().unwrap().to_owned());
            text_operations.push(created["name"].as_str().unwrap().to_owned());
        }
        for foreign_base in [
            "/v1/projects/other/databases/(default)",
            "/v1/projects/p/databases/entnamed",
        ] {
            let (status, created) = call(
                &state,
                "POST",
                &format!("{foreign_base}/collectionGroups/articles/indexes"),
                native_text_body(),
            );
            assert_eq!(status, 200, "{created}");
        }
        let mut ordinary_indexes = Vec::new();
        for group in ["articles", "notes"] {
            let (status, created) = call(
                &state,
                "POST",
                &format!("{base}/collectionGroups/{group}/indexes"),
                json!({"queryScope":"COLLECTION","fields":[{"fieldPath":"a","order":"ASCENDING"},{"fieldPath":"b","order":"DESCENDING"}]}),
            );
            assert_eq!(status, 200, "{created}");
            ordinary_indexes.push(created["metadata"]["index"].as_str().unwrap().to_owned());
        }
        advance(&clock, 3600);
        for (position, group) in ["articles", "notes"].into_iter().enumerate() {
            let (status, listed) = call(
                &state,
                "GET",
                &format!("{base}/collectionGroups/{group}/indexes"),
                Value::Null,
            );
            assert_eq!(status, 200, "{listed}");
            let mut names: Vec<_> = listed["indexes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["name"].as_str().unwrap().to_owned())
                .collect();
            names.sort();
            let mut expected = text_indexes.clone();
            expected.push(ordinary_indexes[position].clone());
            expected.sort();
            assert_eq!(names, expected, "{listed}");
            assert!(
                listed["indexes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|entry| entry["state"] == "READY"),
                "{listed}"
            );
        }
        let mut terminal_operations = Vec::new();
        for operation in &text_operations {
            let terminal = call(&state, "GET", &format!("/v1/{operation}"), Value::Null);
            assert_eq!(terminal.0, 200, "{}", terminal.1);
            assert_eq!(terminal.1["done"], true);
            terminal_operations.push(terminal);
        }
        let (status, document) = call(
            &state,
            "PATCH",
            &format!("{base}/documents/notes/later"),
            json!({"fields":{"title":{"stringValue":"later"},"language":{"stringValue":"fr"}}}),
        );
        assert_eq!(status, 200, "{document}");
        let (status, listed) = call(
            &state,
            "GET",
            &format!("{base}/collectionGroups/articles/indexes"),
            Value::Null,
        );
        assert_eq!(
            status, 200,
            "terminal metadata must not revalidate a later source value: {listed}"
        );
        for (operation, terminal) in text_operations.iter().zip(terminal_operations) {
            assert_eq!(
                call(&state, "GET", &format!("/v1/{operation}"), Value::Null),
                terminal
            );
        }
        let wrong_group = format!(
            "/v1/{}",
            text_indexes[0].replace("/collectionGroups/articles/", "/collectionGroups/notes/")
        );
        assert_eq!(call(&state, "GET", &wrong_group, Value::Null).0, 404);
        assert_eq!(
            call(&state, "DELETE", &wrong_group, Value::Null),
            (200, json!({}))
        );
        assert_eq!(
            call(
                &state,
                "GET",
                &format!("/v1/{}", text_indexes[0]),
                Value::Null
            )
            .0,
            200
        );
    }
}

#[test]
fn native_text_admin_cross_group_list_leaves_an_unverified_source_pending() {
    // Review S2: under productionExact a source language without recorded production support
    // leaves only its own build pending; the listing answers and completes the others.
    let (state, clock, catalog) = native_text_state_exact(true, true);
    let base = "/v1/projects/p/databases/(default)";
    for group in ["good", "bad"] {
        let (status, initial) = call(
            &state,
            "POST",
            &format!("{base}/collectionGroups/{group}/indexes"),
            native_text_body(),
        );
        assert_eq!(status, 200, "{initial}");
    }
    assert_eq!(
        call(
            &state,
            "PATCH",
            &format!("{base}/documents/bad/doc"),
            json!({"fields":{"title":{"stringValue":"marker"},"language":{"stringValue":"fr"}}}),
        )
        .0,
        200
    );
    advance(&clock, 3600);
    let list = format!("{base}/collectionGroups/good/indexes");
    let (status, answer) = call(&state, "GET", &list, Value::Null);
    assert_eq!(status, 200, "{answer}");
    let index_states: Vec<_> = answer["indexes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index["state"].as_str().unwrap())
        .collect();
    assert_eq!(
        index_states.iter().filter(|s| **s == "READY").count(),
        1,
        "{answer}"
    );
    assert_eq!(
        index_states.iter().filter(|s| **s == "CREATING").count(),
        1,
        "{answer}"
    );
    let _ = &catalog;
    assert_eq!(
        call(
            &state,
            "PATCH",
            &format!("{base}/documents/bad/doc"),
            json!({"fields":{"title":{"stringValue":"marker"},"language":{"stringValue":"en"}}}),
        )
        .0,
        200
    );
    let (status, answer) = call(&state, "GET", &list, Value::Null);
    assert_eq!(status, 200, "{answer}");
    let indexes = answer["indexes"].as_array().unwrap();
    assert_eq!(indexes.len(), 2);
    assert!(
        indexes.iter().all(|index| index["state"] == "READY"),
        "{answer}"
    );
}

#[test]
fn native_text_admin_cross_group_list_foreign_ready_rejection_preserves_due_builds() {
    let (owner, owner_clock, catalog) = native_text_state();
    let base = "/v1/projects/p/databases/(default)";
    let (_, foreign) = call(
        &owner,
        "POST",
        &format!("{base}/collectionGroups/foreign/indexes"),
        native_text_body(),
    );
    advance(&owner_clock, 3600);
    let foreign_operation = format!("/v1/{}", foreign["name"].as_str().unwrap());
    let foreign_terminal = call(&owner, "GET", &foreign_operation, Value::Null);
    assert_eq!(foreign_terminal.0, 200, "{}", foreign_terminal.1);
    assert_eq!(foreign_terminal.1["response"]["state"], "READY");

    let (other, other_clock) = enterprise_native_state(true);
    other
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::from_secs(3600));
    other
        .local
        .set_text_indexes(Arc::clone(&catalog), false)
        .unwrap();
    let (status, document) = call(
        &other,
        "PATCH",
        &format!("{base}/documents/local/good"),
        json!({"fields":{"title":{"stringValue":"marker"},"language":{"stringValue":"en"}}}),
    );
    assert_eq!(status, 200, "{document}");
    let list = format!("{base}/collectionGroups/local/indexes");
    let (status, own) = call(&other, "POST", &list, native_text_body());
    assert_eq!(status, 200, "{own}");
    let own_operation = format!("/v1/{}", own["name"].as_str().unwrap());
    advance(&other_clock, 3600);
    let before = catalog.lock().unwrap().clone();
    let pending = other.local.admin().operations().list("p", "(default)");
    assert_eq!(pending.len(), 1);
    assert!(pending[0].current.get("done").is_none());
    let catalog_states: Vec<_> = before
        .entries()
        .map(|(_, _, definition)| definition.state)
        .collect();
    assert!(catalog_states.contains(&fireemu_core_firestore::text_index::TextIndexState::Ready));
    assert!(catalog_states.contains(&fireemu_core_firestore::text_index::TextIndexState::Creating));

    let (status, refused) = call(&other, "GET", &list, Value::Null);
    assert_eq!(status, 501, "{refused}");
    assert_eq!(
        *catalog.lock().unwrap(),
        before,
        "a rejected LIST cannot publish the own due build before noticing a foreign READY epoch"
    );
    assert_eq!(
        other.local.admin().operations().list("p", "(default)"),
        pending
    );

    let foreign_index = format!("/v1/{}", foreign["metadata"]["index"].as_str().unwrap());
    assert_eq!(
        call(&owner, "DELETE", &foreign_index, Value::Null),
        (200, json!({}))
    );
    let (status, listed) = call(&other, "GET", &list, Value::Null);
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["indexes"].as_array().unwrap().len(), 1);
    assert_eq!(listed["indexes"][0]["name"], own["metadata"]["index"]);
    assert_eq!(listed["indexes"][0]["state"], "READY");
    let (status, terminal) = call(&other, "GET", &own_operation, Value::Null);
    assert_eq!(status, 200, "{terminal}");
    assert_eq!(terminal["done"], true);
    assert_eq!(terminal["metadata"]["state"], "SUCCESSFUL");
    assert_eq!(terminal["response"]["name"], own["metadata"]["index"]);
    assert_eq!(
        call(&owner, "GET", &foreign_operation, Value::Null),
        foreign_terminal
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_text_admin_cross_group_list_unrenderable_ready_metadata_preserves_due_builds() {
    use fireemu_core_firestore::text_index::{DefaultTextLanguage, LanguageOverridePolicy};
    // Pairwise-generated rows: metadata, scope, foreign READY, own due, changed terminal source.
    let cases = [
        ("Autodetect", "SameDatabase", false, true, true),
        ("Disabled", "SameDatabase", false, true, true),
        ("Implicit", "SameDatabase", false, true, false),
        ("ExplicitEn", "SameDatabase", true, true, true),
        ("Autodetect", "OtherDatabase", false, true, true),
        ("Disabled", "OtherProject", false, true, false),
        ("ExplicitEn", "SameDatabase", false, false, true),
        ("Autodetect", "SameDatabase", false, false, true),
        ("Implicit", "OtherProject", true, false, true),
        ("Implicit", "OtherDatabase", true, false, false),
        ("ExplicitEn", "OtherDatabase", true, true, false),
        ("Disabled", "OtherDatabase", true, false, true),
        ("Autodetect", "OtherProject", true, true, false),
        ("ExplicitEn", "OtherProject", true, true, true),
    ];
    for (row, (metadata, scope, foreign_ready, own_due, changed_source)) in
        cases.into_iter().enumerate()
    {
        eprintln!("Native LIST PICT row {row}: {metadata}/{scope}/foreign={foreign_ready}/due={own_due}/terminal_source_changed={changed_source}");
        let (state, clock, catalog) = native_text_state();
        let base = "/v1/projects/p/databases/(default)";
        let (status, history) = call(
            &state,
            "POST",
            &format!("{base}/collectionGroups/history/indexes"),
            native_text_body(),
        );
        assert_eq!(status, 200, "{history}");
        advance(&clock, 3600);
        let history_operation = format!("/v1/{}", history["name"].as_str().unwrap());
        let history_terminal = call(&state, "GET", &history_operation, Value::Null);
        assert_eq!(history_terminal.0, 200, "{}", history_terminal.1);
        assert_eq!(history_terminal.1["metadata"]["state"], "SUCCESSFUL");
        if changed_source {
            let (status, document) = call(
                &state,
                "PATCH",
                &format!("{base}/documents/history/later"),
                json!({"fields":{"title":{"stringValue":"later"},"language":{"stringValue":"fr"}}}),
            );
            assert_eq!(status, 200, "{document}");
        }
        let foreign_owner = if foreign_ready {
            let (foreign, foreign_clock) = enterprise_native_state(true);
            foreign
                .local
                .admin()
                .indexes()
                .set_build_duration(std::time::Duration::from_secs(3600));
            foreign
                .local
                .set_text_indexes(Arc::clone(&catalog), false)
                .unwrap();
            let (status, initial) = call(
                &foreign,
                "POST",
                &format!("{base}/collectionGroups/foreign/indexes"),
                native_text_body(),
            );
            assert_eq!(status, 200, "{initial}");
            advance(&foreign_clock, 3600);
            let (status, terminal) = call(
                &foreign,
                "GET",
                &format!("/v1/{}", initial["name"].as_str().unwrap()),
                Value::Null,
            );
            assert_eq!(status, 200, "{terminal}");
            assert_eq!(terminal["metadata"]["state"], "SUCCESSFUL");
            Some((
                foreign,
                format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap()),
            ))
        } else {
            None
        };
        let history_id = history["metadata"]["index"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let mut configured = catalog
            .lock()
            .unwrap()
            .get("p", "(default)", history_id)
            .unwrap()
            .clone();
        configured.id = "CICAgConfiguredText".into();
        configured.collection_id =
            fireemu_core_types::ids::CollectionId::try_new("configured").unwrap();
        match metadata {
            "ExplicitEn" => {}
            "Autodetect" => configured.language = DefaultTextLanguage::Autodetect,
            "Disabled" => configured.language_override = LanguageOverridePolicy::Disabled,
            "Implicit" => {
                configured.language_override = LanguageOverridePolicy::ImplicitLanguageField;
            }
            _ => unreachable!("unknown generated metadata policy"),
        }
        let (config_project, config_database) = match scope {
            "SameDatabase" => ("p", "(default)"),
            "OtherDatabase" => ("p", "entnamed"),
            "OtherProject" => ("other", "(default)"),
            _ => unreachable!("unknown generated scope"),
        };
        catalog
            .lock()
            .unwrap()
            .add(config_project, config_database, configured)
            .unwrap();
        let (status, document) = call(
            &state,
            "PATCH",
            &format!("{base}/documents/local/good"),
            json!({"fields":{"title":{"stringValue":"marker"},"language":{"stringValue":"en"}}}),
        );
        assert_eq!(status, 200, "{document}");
        let list = format!("{base}/collectionGroups/local/indexes");
        let (status, own) = call(&state, "POST", &list, native_text_body());
        assert_eq!(status, 200, "{own}");
        let operation = format!("/v1/{}", own["name"].as_str().unwrap());
        if own_due {
            advance(&clock, 3600);
        }
        let before = catalog.lock().unwrap().clone();
        let operations = state.local.admin().operations().list("p", "(default)");
        let (status, observed) = call(&state, "GET", &list, Value::Null);
        // Review S2: in the default profile an unrenderable definition is listed with the
        // options it has; only a foreign epoch refuses the listing.
        let refused = foreign_ready;
        if refused {
            assert_eq!(status, 501, "row {row}: {observed}");
            assert_eq!(
                *catalog.lock().unwrap(),
                before,
                "row {row}: a refused LIST cannot publish the own due build"
            );
            assert_eq!(
                state.local.admin().operations().list("p", "(default)"),
                operations,
                "row {row}"
            );
        } else {
            assert_eq!(status, 200, "row {row}: {observed}");
            let indexes = observed["indexes"].as_array().unwrap();
            assert_eq!(
                indexes.len(),
                2 + usize::from(scope == "SameDatabase"),
                "row {row}: {observed}"
            );
            let own_index = indexes
                .iter()
                .find(|index| index["name"] == own["metadata"]["index"])
                .unwrap();
            assert_eq!(
                own_index["state"],
                if own_due { "READY" } else { "CREATING" }
            );
        }
        assert_eq!(
            call(&state, "GET", &history_operation, Value::Null),
            history_terminal,
            "row {row}"
        );
        let configured_path = format!("/v1/projects/{config_project}/databases/{config_database}/collectionGroups/configured/indexes/CICAgConfiguredText");
        assert_eq!(
            call(&state, "DELETE", &configured_path, Value::Null),
            (200, json!({}))
        );
        if let Some((owner, index)) = &foreign_owner {
            assert_eq!(call(owner, "DELETE", index, Value::Null), (200, json!({})));
        }
        if !own_due {
            advance(&clock, 3600);
        }
        let (status, listed) = call(&state, "GET", &list, Value::Null);
        assert_eq!(status, 200, "row {row}: {listed}");
        let indexes = listed["indexes"].as_array().unwrap();
        assert_eq!(indexes.len(), 2);
        assert!(indexes.iter().all(|index| index["state"] == "READY"));
        assert!(indexes
            .iter()
            .any(|index| index["name"] == own["metadata"]["index"]));
        let (status, terminal) = call(&state, "GET", &operation, Value::Null);
        assert_eq!(status, 200, "{terminal}");
        assert_eq!(terminal["done"], true);
        assert_eq!(terminal["metadata"]["state"], "SUCCESSFUL");
        assert_eq!(terminal["response"]["name"], own["metadata"]["index"]);
        assert_eq!(
            call(&state, "GET", &history_operation, Value::Null),
            history_terminal,
            "row {row}"
        );
    }
}

#[test]
fn native_text_admin_success_shares_catalog_wire_schema_and_terminal_operation() {
    let (state, clock, catalog) = native_text_state();
    for database in ["(default)", "entnamed"] {
        let base = format!("/v1/projects/p/databases/{database}");
        let group = format!("{base}/collectionGroups/items/indexes");
        let (status, body) = call(
            &state,
            "PATCH",
            &format!("{base}/documents/items/good"),
            json!({"fields":{"title":{"stringValue":"repairprobe-marker"},"language":{"stringValue":"en"}}}),
        );
        assert_eq!(status, 200, "{body}");
        let (status, initial) = call(&state, "POST", &group, native_text_body());
        assert_eq!(status, 200, "{initial}");
        assert_eq!(initial["metadata"]["state"], "INITIALIZING");
        assert!(initial.get("done").is_none());
        let index_name = initial["metadata"]["index"].as_str().unwrap();
        let index_path = format!("/v1/{index_name}");
        let operation_path = format!("/v1/{}", initial["name"].as_str().unwrap());
        let id = index_name.rsplit('/').next().unwrap();
        assert_eq!(
            catalog
                .lock()
                .unwrap()
                .get("p", database, id)
                .unwrap()
                .state,
            fireemu_core_firestore::text_index::TextIndexState::Creating
        );
        let (status, creating) = call(&state, "GET", &index_path, Value::Null);
        assert_eq!(status, 200, "{creating}");
        assert_eq!(creating["state"], "CREATING");
        assert_eq!(creating["fields"], native_text_body()["fields"]);
        assert_eq!(creating["density"], "SPARSE_ANY");
        assert_eq!(
            creating["searchIndexOptions"],
            native_text_body()["searchIndexOptions"]
        );
        let (status, listed) = call(&state, "GET", &group, Value::Null);
        assert_eq!(status, 200, "{listed}");
        assert_eq!(listed["indexes"].as_array().unwrap().len(), 1);
        assert_eq!(
            call(
                &state,
                "GET",
                &index_path.replacen("/projects/p/", "/projects/other/", 1),
                Value::Null
            )
            .0,
            404
        );
        advance(&clock, 3600);
        let (status, terminal) = call(&state, "GET", &operation_path, Value::Null);
        assert_eq!(status, 200, "{terminal}");
        assert_eq!(terminal["done"], true);
        assert_eq!(terminal["metadata"]["state"], "SUCCESSFUL");
        assert_eq!(
            terminal["metadata"]["progressDocuments"],
            json!({"estimatedWork":"1","completedWork":"1"})
        );
        assert_eq!(terminal["response"]["state"], "READY");
        assert_eq!(terminal["response"]["fields"], native_text_body()["fields"]);
        assert_eq!(
            catalog
                .lock()
                .unwrap()
                .get("p", database, id)
                .unwrap()
                .state,
            fireemu_core_firestore::text_index::TextIndexState::Ready
        );
        let (status, hits) = call(
            &state,
            "POST",
            &format!("{base}/documents:executePipeline"),
            json!({"structuredPipeline":{"pipeline":{"stages":[
                {"name":"collection","args":[{"referenceValue":"/items"}]},
                {"name":"search","args":[],"options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":"repairprobe-marker"}]}}}}
            ]}}}),
        );
        assert_eq!(status, 200, "{hits}");
        assert_eq!(hits[0]["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            call(&state, "DELETE", &index_path, Value::Null),
            (200, json!({}))
        );
        assert_eq!(call(&state, "GET", &index_path, Value::Null).0, 404);
        assert!(catalog.lock().unwrap().get("p", database, id).is_none());
        assert_eq!(
            call(&state, "GET", &operation_path, Value::Null).1,
            terminal
        );
    }
}

#[test]
fn native_text_admin_failed_operation_stays_terminal_after_source_and_index_deletion() {
    let (state, clock, catalog) = native_text_state();
    let base = "/v1/projects/p/databases/(default)";
    let bad = format!("{base}/documents/items/bad");
    let (status, body) = call(
        &state,
        "PATCH",
        &bad,
        json!({"fields":{"title":{"stringValue":"repairprobe-marker"},"language":{"stringValue":"not a language"}}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, initial) = call(
        &state,
        "POST",
        &format!("{base}/collectionGroups/items/indexes"),
        native_text_body(),
    );
    assert_eq!(status, 200, "{initial}");
    let index_name = initial["metadata"]["index"].as_str().unwrap();
    let id = index_name.rsplit('/').next().unwrap();
    let index_path = format!("/v1/{index_name}");
    let operation_path = format!("/v1/{}", initial["name"].as_str().unwrap());
    advance(&clock, 3600);
    let (status, failed) = call(&state, "GET", &operation_path, Value::Null);
    assert_eq!(status, 200, "{failed}");
    assert_eq!(failed["done"], true);
    assert_eq!(failed["metadata"]["state"], "FAILED");
    assert_eq!(failed["metadata"]["progressDocuments"], json!({}));
    assert_eq!(
        failed["error"],
        json!({"code":3,"message":"Invalid text language: not a language"})
    );
    assert!(failed.get("response").is_none());
    assert_eq!(
        call(&state, "GET", &index_path, Value::Null).1["state"],
        "NEEDS_REPAIR"
    );
    assert_eq!(
        catalog
            .lock()
            .unwrap()
            .get("p", "(default)", id)
            .unwrap()
            .state,
        fireemu_core_firestore::text_index::TextIndexState::NeedsRepair
    );
    let failed_index = call(&state, "GET", &index_path, Value::Null).1;
    let (failed_generation, failed_postings) = {
        let catalog = catalog.lock().unwrap();
        let build = catalog.build("p", "(default)", id).unwrap();
        (build.generation, build.indexed_documents())
    };
    let corrected_fields = json!({
        "title":{"stringValue":"repairprobe-marker"},
        "language":{"stringValue":"en"}
    });
    let (status, corrected) = call(&state, "PATCH", &bad, json!({"fields":corrected_fields}));
    assert_eq!(status, 200, "{corrected}");
    assert_eq!(corrected["name"], bad.strip_prefix("/v1/").unwrap());
    assert_eq!(corrected["fields"], corrected_fields);
    assert_eq!(
        call(&state, "GET", &bad, Value::Null),
        (200, corrected),
        "the same source must contain the successfully corrected language"
    );
    advance(&clock, 3600);
    assert_eq!(
        call(&state, "GET", &index_path, Value::Null),
        (200, failed_index),
        "correcting the same source must not revive the failed index"
    );
    assert_eq!(
        call(&state, "GET", &operation_path, Value::Null),
        (200, failed.clone()),
        "correcting the same source must preserve the terminal operation"
    );
    {
        let catalog = catalog.lock().unwrap();
        let build = catalog.build("p", "(default)", id).unwrap();
        assert_eq!(build.generation, failed_generation);
        assert_eq!(build.indexed_documents(), failed_postings);
    }
    assert_eq!(call(&state, "DELETE", &bad, Value::Null).0, 200);
    advance(&clock, 3600);
    assert_eq!(call(&state, "GET", &operation_path, Value::Null).1, failed);
    assert_eq!(
        call(&state, "GET", &index_path, Value::Null).1["state"],
        "NEEDS_REPAIR"
    );
    assert_eq!(
        call(&state, "DELETE", &index_path, Value::Null),
        (200, json!({}))
    );
    assert_eq!(call(&state, "GET", &index_path, Value::Null).0, 404);
    assert_eq!(call(&state, "GET", &operation_path, Value::Null).1, failed);
}

#[test]
fn native_text_admin_lists_configuration_from_the_same_search_catalog() {
    use fireemu_core_firestore::text_index::{
        DefaultTextLanguage, LanguageOverridePolicy, TextIndexDefinition, TextIndexState,
        TextIndexType, TextIndexedField, TextMatchType,
    };
    let (state, _, catalog) = native_text_state();
    catalog
        .lock()
        .unwrap()
        .add(
            "p",
            "(default)",
            TextIndexDefinition {
                id: "CICAgLocalText".to_owned(),
                collection_id: fireemu_core_types::ids::CollectionId::try_new("items").unwrap(),
                query_scope: fireemu_core_firestore::index::IndexQueryScope::Collection,
                api_scope: "ANY_API".to_owned(),
                fields: vec![TextIndexedField {
                    path: fireemu_core_firestore::field_path::FieldPath::parse("title").unwrap(),
                    index_type: TextIndexType::Tokenized,
                    match_type: TextMatchType::MatchGlobally,
                }],
                language: DefaultTextLanguage::Tag("en".to_owned()),
                language_override: LanguageOverridePolicy::ExplicitField(
                    fireemu_core_firestore::field_path::FieldPath::parse("language").unwrap(),
                ),
                state: TextIndexState::Ready,
            },
        )
        .unwrap();
    let (status, listed) = call(
        &state,
        "GET",
        "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
        Value::Null,
    );
    assert_eq!(status, 200, "{listed}");
    assert_eq!(
        listed["indexes"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    assert_eq!(listed["indexes"][0]["fields"], native_text_body()["fields"]);
    assert_eq!(listed["indexes"][0]["density"], "SPARSE_ANY");
    assert_eq!(
        listed["indexes"][0]["searchIndexOptions"],
        native_text_body()["searchIndexOptions"]
    );
    state.local.reset_project("p");
    assert!(
        catalog
            .lock()
            .unwrap()
            .get("p", "(default)", "CICAgLocalText")
            .is_some(),
        "configured definition survives native cleanup"
    );
}

#[test]
fn native_text_admin_work_outlives_operation_view_retention() {
    let (state, clock, _) = native_text_state();
    let (status, initial) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
        native_text_body(),
    );
    assert_eq!(status, 200, "{initial}");
    let index = format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap());
    for i in 0..130 {
        state.local.admin().operations().record_views(
            "p",
            "(default)",
            &format!("retained-{i}"),
            json!({"done":true}),
            json!({"done":true}),
        );
    }
    advance(&clock, 3600);
    assert_eq!(call(&state, "GET", &index, Value::Null).1["state"], "READY");
    assert_eq!(
        call(
            &state,
            "GET",
            &format!("/v1/{}", initial["name"].as_str().unwrap()),
            Value::Null
        )
        .0,
        404
    );
    state.local.reset_project("p");
    assert_eq!(call(&state, "GET", &index, Value::Null).0, 404);
}

#[test]
fn native_text_admin_completion_reconciles_construction_writes_and_merges_index_kinds() {
    let (state, clock, _) = native_text_state();
    let group = "/v1/projects/p/databases/(default)/collectionGroups/items/indexes";
    let (_, initial) = call(&state, "POST", group, native_text_body());
    let operation = format!("/v1/{}", initial["name"].as_str().unwrap());
    let (status, ordinary) = call(
        &state,
        "POST",
        group,
        json!({"queryScope":"COLLECTION","fields":[{"fieldPath":"a","order":"ASCENDING"},{"fieldPath":"b","order":"DESCENDING"}]}),
    );
    assert_eq!(status, 200, "{ordinary}");
    let (_, listed) = call(&state, "GET", group, Value::Null);
    let mut densities: Vec<_> = listed["indexes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| index["density"].as_str().unwrap())
        .collect();
    densities.sort_unstable();
    assert_eq!(densities, ["SPARSE_ALL", "SPARSE_ANY"]);
    for id in ["during1", "during2"] {
        let (status, body) = call(
            &state,
            "PATCH",
            &format!("/v1/projects/p/databases/(default)/documents/items/{id}"),
            json!({"fields":{"title":{"stringValue":"construction"},"language":{"stringValue":"en"}}}),
        );
        assert_eq!(status, 200, "{body}");
    }
    let pipeline = json!({"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/items"}]},{"name":"search","options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":"construction"}]}}}}]}}});
    assert_eq!(
        call(
            &state,
            "POST",
            "/v1/projects/p/databases/(default)/documents:executePipeline",
            pipeline.clone()
        )
        .0,
        400
    );
    advance(&clock, 3600);
    let (status, hits) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/documents:executePipeline",
        pipeline,
    );
    assert_eq!(status, 200, "{hits}");
    assert_eq!(hits[0]["results"].as_array().unwrap().len(), 2);
    assert_eq!(
        call(&state, "GET", &operation, Value::Null).1["metadata"]["progressDocuments"]
            ["completedWork"],
        "2"
    );
}

#[test]
fn native_text_admin_language_failures_use_the_actual_typed_source_value() {
    for language in [
        json!({"stringValue":"another invalid language!"}),
        json!({"integerValue":"7"}),
        json!({"stringValue":"fr"}),
    ] {
        let (state, clock, catalog) = native_text_state();
        call(
            &state,
            "PATCH",
            "/v1/projects/p/databases/(default)/documents/items/doc",
            json!({"fields":{"title":{"stringValue":"marker"},"language":language}}),
        );
        let (_, initial) = call(
            &state,
            "POST",
            "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
            native_text_body(),
        );
        let operation = format!("/v1/{}", initial["name"].as_str().unwrap());
        advance(&clock, 3600);
        let (status, answer) = call(&state, "GET", &operation, Value::Null);
        assert_eq!(status, 200, "{answer}");
        // Review S2: the default profile builds a valid tag language-neutral and fails a
        // non-string value like a malformed tag.
        match (
            language.get("stringValue").and_then(Value::as_str),
            language.get("integerValue"),
        ) {
            (Some("fr"), _) => {
                assert_eq!(answer["metadata"]["state"], "SUCCESSFUL", "{answer}");
                assert_eq!(
                    catalog.lock().unwrap().entries().next().unwrap().2.state,
                    fireemu_core_firestore::text_index::TextIndexState::Ready
                );
            }
            (Some(text), _) => assert_eq!(
                answer["error"],
                json!({"code":3,"message":format!("Invalid text language: {text}")})
            ),
            (None, _) => assert_eq!(
                answer["error"],
                json!({"code":3,"message":"Invalid text language: 7"})
            ),
        }
    }
}

#[test]
fn native_text_admin_stale_generation_cannot_complete_a_replacement() {
    let (state, clock, catalog) = native_text_state();
    let (_, initial) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
        native_text_body(),
    );
    let name = initial["metadata"]["index"].as_str().unwrap();
    let id = name.rsplit('/').next().unwrap();
    let old_generation;
    {
        let mut catalog = catalog.lock().unwrap();
        let definition = catalog.get("p", "(default)", id).unwrap().clone();
        old_generation = catalog.build("p", "(default)", id).unwrap().generation;
        catalog.remove("p", "(default)", id);
        catalog.add("p", "(default)", definition).unwrap();
        assert_ne!(
            catalog.build("p", "(default)", id).unwrap().generation,
            old_generation
        );
    }
    advance(&clock, 3600);
    let operation = format!("/v1/{}", initial["name"].as_str().unwrap());
    assert_eq!(call(&state, "GET", &operation, Value::Null).1, initial);
    assert_eq!(
        catalog
            .lock()
            .unwrap()
            .get("p", "(default)", id)
            .unwrap()
            .state,
        fireemu_core_firestore::text_index::TextIndexState::Creating
    );
}

#[test]
#[allow(clippy::result_large_err)]
fn native_text_admin_snapshot_serializes_completion_with_delete_and_reset() {
    for reset in [false, true] {
        let (state, clock, catalog) = native_text_state();
        let state = Arc::new(state);
        let (_, initial) = call(
            &state,
            "POST",
            "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
            native_text_body(),
        );
        let path = format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap());
        advance(&clock, 3600);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let started = Arc::new(std::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            let build_state = Arc::clone(&state);
            let build_entered = Arc::clone(&entered);
            let build_release = Arc::clone(&release);
            let build = scope.spawn(move || {
                build_state
                    .local
                    .with_native_text_snapshot("p", "(default)", |db, catalog| {
                        build_entered.wait();
                        build_release.wait();
                        build_state.local.advance_text_builds_at_snapshot(
                            "p",
                            "(default)",
                            db,
                            catalog,
                            super::index_rest::NativeTextSelection::default(),
                        )
                    })
                    .unwrap();
            });
            entered.wait();
            let deleting_state = Arc::clone(&state);
            let started_delete = Arc::clone(&started);
            let delete_path = path.clone();
            let delete = scope.spawn(move || {
                started_delete.wait();
                if reset {
                    deleting_state.local.reset_project("p");
                } else {
                    assert_eq!(
                        call(&deleting_state, "DELETE", &delete_path, Value::Null).0,
                        200
                    );
                }
            });
            started.wait();
            release.wait();
            build.join().unwrap();
            delete.join().unwrap();
        });
        assert!(catalog.lock().unwrap().entries().next().is_none());
        assert_eq!(call(&state, "GET", &path, Value::Null).0, 404);
    }
}

#[test]
fn native_text_admin_unsupported_collection_does_not_block_another_target() {
    let (state, clock, _) = native_text_state();
    let mut good = None;
    let mut bad = None;
    for (group, language) in [("items", "en"), ("unsupported", "fr")] {
        call(
            &state,
            "PATCH",
            &format!("/v1/projects/p/databases/(default)/documents/{group}/doc"),
            json!({"fields":{"title":{"stringValue":"marker"},"language":{"stringValue":language}}}),
        );
        let (status, initial) = call(
            &state,
            "POST",
            &format!("/v1/projects/p/databases/(default)/collectionGroups/{group}/indexes"),
            native_text_body(),
        );
        assert_eq!(status, 200, "{initial}");
        if group == "items" {
            good = Some(initial);
        } else {
            bad = Some(initial);
        }
    }
    advance(&clock, 3600);
    let good = good.unwrap();
    let bad = bad.unwrap();
    let bad_operation = format!("/v1/{}", bad["name"].as_str().unwrap());
    // Review S2: the default profile builds `fr` language-neutral.
    assert_eq!(
        call(&state, "GET", &bad_operation, Value::Null).1["metadata"]["state"],
        "SUCCESSFUL"
    );
    let good_operation = format!("/v1/{}", good["name"].as_str().unwrap());
    assert_eq!(
        call(&state, "GET", &good_operation, Value::Null).1["metadata"]["state"],
        "SUCCESSFUL"
    );
    let index = format!("/v1/{}", good["metadata"]["index"].as_str().unwrap());
    assert_eq!(call(&state, "GET", &index, Value::Null).1["state"], "READY");
    assert_eq!(
        call(
            &state,
            "GET",
            "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
            Value::Null
        )
        .0,
        200
    );
    let (status, hits) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/documents:executePipeline",
        json!({"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/items"}]},{"name":"search","options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":"marker"}]}}}}]}}}),
    );
    assert_eq!(status, 200, "{hits}");
    assert_eq!(hits[0]["results"].as_array().unwrap().len(), 1);
}

#[test]
fn native_text_admin_shared_backend_keeps_one_epoch_and_foreign_backend_cannot_advance() {
    let (state, clock, catalog) = native_text_state();
    let (other, other_clock) = enterprise_native_state(true);
    other
        .local
        .set_text_indexes(Arc::clone(&catalog), false)
        .unwrap();
    call(
        &state,
        "PATCH",
        "/v1/projects/p/databases/(default)/documents/items/source",
        json!({"fields":{"title":{"stringValue":"owner"},"language":{"stringValue":"en"}}}),
    );
    let (_, initial) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
        native_text_body(),
    );
    let index = format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap());
    advance(&other_clock, 3600);
    let (status, body) = call(&other, "GET", &index, Value::Null);
    assert_eq!(status, 501, "{body}");
    assert_eq!(
        catalog.lock().unwrap().entries().next().unwrap().2.state,
        fireemu_core_firestore::text_index::TextIndexState::Creating
    );
    other.local.reset_project("p");
    assert_eq!(
        catalog.lock().unwrap().entries().next().unwrap().2.state,
        fireemu_core_firestore::text_index::TextIndexState::Creating
    );
    let captured = catalog.lock().unwrap().extract(|project| project == "p");
    catalog
        .lock()
        .unwrap()
        .replace(|project| project == "p", &captured);
    let cloned = Arc::clone(&state.local);
    assert!(Arc::ptr_eq(&cloned, &state.local));
    advance(&clock, 3600);
    cloned
        .advance_native_text_builds(
            "p",
            "(default)",
            super::index_rest::NativeTextSelection::default(),
        )
        .unwrap();
    let (_, terminal) = call(
        &state,
        "GET",
        &format!("/v1/{}", initial["name"].as_str().unwrap()),
        Value::Null,
    );
    assert_eq!(
        terminal["metadata"]["progressDocuments"]["completedWork"],
        "1"
    );
    assert_eq!(
        call(
            &state,
            "DELETE",
            &format!("/v1/{}", initial["name"].as_str().unwrap()),
            Value::Null
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &state,
            "GET",
            &format!("/v1/{}", initial["name"].as_str().unwrap()),
            Value::Null
        )
        .0,
        404
    );
    assert_eq!(call(&state, "GET", &index, Value::Null).1["state"], "READY");
    assert_eq!(
        call(
            &state,
            "GET",
            &format!("/v1/{}", initial["name"].as_str().unwrap()),
            Value::Null
        )
        .0,
        404
    );
    cloned.reset_project("p");
    assert!(catalog.lock().unwrap().entries().next().is_none());
}

#[test]
fn native_text_admin_foreign_epoch_does_not_block_unrelated_scopes() {
    let (owner, owner_clock, catalog) = native_text_state();
    let (_, foreign) = call(
        &owner,
        "POST",
        "/v1/projects/p/databases/(default)/collectionGroups/foreign/indexes",
        native_text_body(),
    );
    let (other, _) = enterprise_native_state(true);
    other.local.set_text_indexes(catalog, false).unwrap();
    for base in [
        "/v1/projects/p/databases/(default)",
        "/v1/projects/other/databases/(default)",
        "/v1/projects/p/databases/entnamed",
    ] {
        let group = format!("{base}/collectionGroups/local/indexes");
        let (status, created) = call(&other, "POST", &group, native_text_body());
        assert_eq!(status, 200, "{base}: {created}");
        if base == "/v1/projects/p/databases/(default)" {
            assert_eq!(
                created["name"], foreign["name"],
                "the independent backend ordinals deliberately collide"
            );
        }
        assert_eq!(
            call(&other, "GET", &format!("{base}/operations"), Value::Null).0,
            200
        );
        let index = format!("/v1/{}", created["metadata"]["index"].as_str().unwrap());
        assert_eq!(call(&other, "GET", &index, Value::Null).0, 200);
        assert_eq!(
            call(
                &other,
                "GET",
                &format!("/v1/{}", created["name"].as_str().unwrap()),
                Value::Null
            )
            .0,
            200
        );
        assert_eq!(
            call(&other, "GET", &group, Value::Null).0,
            if base == "/v1/projects/p/databases/(default)" {
                501
            } else {
                200
            }
        );
        assert_eq!(call(&other, "DELETE", &index, Value::Null).0, 200);
    }
    let index = format!("/v1/{}", foreign["metadata"]["index"].as_str().unwrap());
    assert_eq!(call(&other, "GET", &index, Value::Null).0, 501);
    assert_eq!(call(&other, "DELETE", &index, Value::Null).0, 501);
    assert_eq!(
        call(&owner, "GET", &index, Value::Null).1["state"],
        "CREATING"
    );
    advance(&owner_clock, 3600);
    assert_eq!(call(&owner, "GET", &index, Value::Null).1["state"], "READY");
    assert_eq!(call(&other, "GET", &index, Value::Null).0, 501);
    assert_eq!(call(&other, "DELETE", &index, Value::Null).0, 501);
    assert_eq!(
        call(
            &other,
            "GET",
            "/v1/projects/p/databases/(default)/collectionGroups/local/indexes",
            Value::Null,
        )
        .0,
        501,
        "cross-group listing selects the foreign READY definition without changing item scope"
    );
    let (status, body) = call(
        &other,
        "POST",
        "/v1/projects/p/databases/(default)/documents:executePipeline",
        json!({"structuredPipeline":{"pipeline":{"stages":[
            {"name":"collection","args":[{"referenceValue":"/foreign"}]},
            {"name":"search","args":[],"options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":"scopeword"}]}}}}
        ]}}}),
    );
    assert_eq!(
        status, 501,
        "a selected READY Native definition still belongs to its owning backend: {body}"
    );
}

#[test]
fn native_text_admin_foreign_epoch_preserves_configured_ready_search() {
    use fireemu_core_firestore::text_index::*;
    let (owner, _, catalog) = native_text_state();
    let (_, created) = call(
        &owner,
        "POST",
        "/v1/projects/p/databases/(default)/collectionGroups/foreign/indexes",
        native_text_body(),
    );
    let id = created["metadata"]["index"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    let mut definition = catalog
        .lock()
        .unwrap()
        .get("p", "(default)", id)
        .unwrap()
        .clone();
    definition.id = "configured".into();
    definition.collection_id = fireemu_core_types::ids::CollectionId::try_new("local").unwrap();
    definition.state = TextIndexState::Ready;
    for (p, d) in [("p", "(default)"), ("other", "entnamed")] {
        catalog
            .lock()
            .unwrap()
            .add(p, d, definition.clone())
            .unwrap();
    }
    let (other, _) = enterprise_native_state(true);
    other.local.set_text_indexes(catalog, false).unwrap();
    for base in [
        "/v1/projects/p/databases/(default)",
        "/v1/projects/other/databases/entnamed",
    ] {
        assert_eq!(
            call(
                &other,
                "PATCH",
                &format!("{base}/documents/local/good"),
                json!({"fields":{"title":{"stringValue":"scopeword"}}})
            )
            .0,
            200
        );
        let (status, hits) = call(
            &other,
            "POST",
            &format!("{base}/documents:executePipeline"),
            json!({"structuredPipeline":{"pipeline":{"stages":[
                {"name":"collection","args":[{"referenceValue":"/local"}]},
                {"name":"search","args":[],"options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":"scopeword"}]}}}}
            ]}}}),
        );
        assert_eq!(status, 200, "{hits}");
        assert_eq!(hits[0]["results"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn native_text_admin_mode_guards_hold_with_attached_catalog() {
    for (edition, mode, explicit) in [
        (FirestoreEdition::Standard, FirestoreApiMode::Native, false),
        (
            FirestoreEdition::Enterprise,
            FirestoreApiMode::MongoDbCompatible,
            false,
        ),
        (FirestoreEdition::Standard, FirestoreApiMode::Native, true),
    ] {
        let (state, _) = state_with_context(true, IndexValidationPolicy::Production, edition, mode);
        let database = if explicit {
            let mut request = native();
            request["databaseEdition"] = json!("ENTERPRISE");
            assert_eq!(
                call(
                    &state,
                    "POST",
                    "/v1/projects/p/databases?databaseId=disabled",
                    request
                )
                .0,
                200
            );
            "disabled"
        } else {
            "(default)"
        };
        let base = format!("/v1/projects/p/databases/{database}");
        let requests = [
            (
                "GET",
                format!("{base}/collectionGroups/items/indexes"),
                Value::Null,
            ),
            (
                "POST",
                format!("{base}/collectionGroups/items/indexes"),
                native_text_body(),
            ),
            (
                "GET",
                format!("{base}/documents/items/missing"),
                Value::Null,
            ),
        ];
        let before = requests
            .iter()
            .map(|(method, path, body)| call(&state, method, path, body.clone()))
            .collect::<Vec<_>>();
        assert_ne!(
            before[1].0, 200,
            "this mode never admits Native text create"
        );
        state
            .local
            .set_text_indexes(
                Arc::new(Mutex::new(
                    fireemu_core_firestore::text_index::TextIndexCatalog::default(),
                )),
                false,
            )
            .unwrap();
        let after = requests
            .iter()
            .map(|(method, path, body)| call(&state, method, path, body.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            before, after,
            "attaching a catalog cannot change mode or access guards"
        );
    }
}

#[test]
fn native_text_admin_omitted_override_defaults_to_observed_language_field() {
    for strict in [true, false] {
        let (state, _, _) = native_text_state_for(strict);
        let mut request = native_text_body();
        request["searchIndexOptions"]
            .as_object_mut()
            .unwrap()
            .remove("textLanguageOverrideFieldPath");
        let (status, initial) = call(
            &state,
            "POST",
            "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
            request,
        );
        assert_eq!(status, 200, "{initial}");
        let index = format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap());
        let (status, definition) = call(&state, "GET", &index, Value::Null);
        assert_eq!(status, 200, "{definition}");
        assert_eq!(
            definition["searchIndexOptions"],
            json!({"textLanguage":"en","textLanguageOverrideFieldPath":"language"})
        );
        assert_eq!(definition["density"], "SPARSE_ANY");
        let (status, duplicate) = call(
            &state,
            "POST",
            "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
            native_text_body(),
        );
        assert_eq!(
            status, 409,
            "normalization must share the same definition: {duplicate}"
        );
        for value in [Value::Null, json!(true), json!(1), json!(""), json!({})] {
            let mut invalid = native_text_body();
            invalid["searchIndexOptions"]["textLanguageOverrideFieldPath"] = value;
            assert_eq!(
                call(
                    &state,
                    "POST",
                    "/v1/projects/p/databases/(default)/collectionGroups/other/indexes",
                    invalid
                )
                .0,
                501
            );
        }
        let mut unknown = native_text_body();
        unknown["searchIndexOptions"]["unknown"] = json!(true);
        assert_eq!(
            call(
                &state,
                "POST",
                "/v1/projects/p/databases/(default)/collectionGroups/other/indexes",
                unknown
            )
            .0,
            501
        );
    }
}

#[test]
fn native_text_admin_partial_catalog_restore_refuses_disconnected_work_but_keeps_terminal_audit() {
    let (state, clock, catalog) = native_text_state();
    let (_, initial) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
        native_text_body(),
    );
    let captured = catalog.lock().unwrap().extract(|p| p == "p");
    let operation = format!("/v1/{}", initial["name"].as_str().unwrap());
    advance(&clock, 3600);
    let (status, terminal) = call(&state, "GET", &operation, Value::Null);
    assert_eq!(status, 200, "{terminal}");
    assert_eq!(terminal["done"], true);
    // A direct core-only rewind is outside the supported combined CONTROL hook.
    catalog.lock().unwrap().replace(|p| p == "p", &captured);
    let (status, audit) = call(&state, "GET", &operation, Value::Null);
    assert_eq!(
        status, 200,
        "a retained terminal audit needs no source advancement: {audit}"
    );
    assert_eq!(audit, terminal);
    let index = format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap());
    assert_eq!(call(&state, "GET", &index, Value::Null).0, 501);
    assert_eq!(
        *catalog.lock().unwrap(),
        captured,
        "unsupported partial rewind cannot mutate work under an old terminal view"
    );
}

#[test]
fn native_text_admin_operation_observers_resolve_retained_local_targets_only() {
    for mode in ["missing", "ordinary", "terminal", "deleted", "evicted"] {
        let (owner, _, catalog) = native_text_state();
        let (_, foreign) = call(
            &owner,
            "POST",
            "/v1/projects/p/databases/(default)/collectionGroups/foreign/indexes",
            native_text_body(),
        );
        let (other, clock) = enterprise_native_state(true);
        other
            .local
            .set_text_indexes(catalog.clone(), false)
            .unwrap();
        other
            .local
            .admin()
            .indexes()
            .set_build_duration(std::time::Duration::from_secs(3600));
        let store = other.local.admin().operations();
        let id = foreign["name"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let operation = format!("/v1/{}", foreign["name"].as_str().unwrap());
        if mode == "ordinary" {
            store.record_views(
                "p",
                "(default)",
                id,
                json!({"done":true,"ordinary":true}),
                json!({"done":true,"ordinary":true}),
            );
        } else if mode != "missing" {
            let (_, local) = call(
                &other,
                "POST",
                "/v1/projects/p/databases/(default)/collectionGroups/local/indexes",
                native_text_body(),
            );
            assert_eq!(local["name"], foreign["name"]);
            if mode == "evicted" {
                for i in 0..128 {
                    store.record_views(
                        "p",
                        "(default)",
                        &format!("evict-{i}"),
                        Value::Null,
                        json!({"done":true}),
                    );
                }
            } else {
                advance(&clock, 3600);
                let index = format!("/v1/{}", local["metadata"]["index"].as_str().unwrap());
                assert_eq!(call(&other, "GET", &index, Value::Null).1["state"], "READY");
                if mode == "deleted" {
                    assert_eq!(call(&other, "DELETE", &operation, Value::Null).0, 200);
                }
            }
        }
        let before = catalog.lock().unwrap().clone();
        let retained = store.get("p", "(default)", id);
        let (status, body) = call(&other, "GET", &operation, Value::Null);
        if matches!(mode, "ordinary" | "terminal") {
            assert_eq!(status, 200, "{mode}: {body}");
            assert_eq!(body, retained.unwrap().current);
        } else {
            assert_eq!(status, 404, "{mode}: {body}");
        }
        assert_eq!(
            call(
                &other,
                "GET",
                "/v1/projects/p/databases/(default)/operations",
                Value::Null
            )
            .0,
            200,
            "{mode}"
        );
        assert_eq!(
            *catalog.lock().unwrap(),
            before,
            "{mode} operation observation cannot advance unrelated or unretained work"
        );
    }
}

#[test]
fn native_text_admin_operation_list_prepares_all_selected_sources_before_publication() {
    // A source language no longer refuses a list (review S2); a foreign epoch still does.
    {
        let foreign_epoch = true;
        let (state, clock, catalog) = native_text_state();
        call(
            &state,
            "POST",
            "/v1/projects/p/databases/(default)/collectionGroups/good/indexes",
            native_text_body(),
        );
        call(
            &state,
            "PATCH",
            "/v1/projects/p/databases/(default)/documents/bad/doc",
            json!({"fields":{"title":{"stringValue":"bad"},"language":{"stringValue":if foreign_epoch {"en"}else{"fr"}}}}),
        );
        let (_, bad) = call(
            &state,
            "POST",
            "/v1/projects/p/databases/(default)/collectionGroups/bad/indexes",
            native_text_body(),
        );
        let id = bad["metadata"]["index"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let (generation, original) = {
            let catalog = catalog.lock().unwrap();
            let build = catalog.build("p", "(default)", id).unwrap();
            (build.generation, build.native.clone().unwrap())
        };
        if foreign_epoch {
            let mut foreign = original.clone();
            foreign.owner_epoch = Arc::new(());
            catalog
                .lock()
                .unwrap()
                .schedule_native("p", "(default)", id, generation, foreign)
                .unwrap();
        }
        advance(&clock, 3600);
        let before = catalog.lock().unwrap().clone();
        let operations = state.local.admin().operations().list("p", "(default)");
        let (status, body) = call(
            &state,
            "GET",
            "/v1/projects/p/databases/(default)/operations",
            Value::Null,
        );
        assert_eq!(status, 501, "{body}");
        assert_eq!(
            *catalog.lock().unwrap(),
            before,
            "all source and epoch validation precedes any generation publication"
        );
        assert_eq!(
            state.local.admin().operations().list("p", "(default)"),
            operations
        );
        let expected = super::operations::OperationStore::default();
        expected.reserve("p", "(default)");
        expected.reserve("p", "(default)");
        assert_eq!(
            state.local.admin().operations().reserve("p", "(default)"),
            expected.reserve("p", "(default)"),
            "refusal cannot mint an operation ID"
        );
        catalog
            .lock()
            .unwrap()
            .schedule_native("p", "(default)", id, generation, original)
            .unwrap();
        call(
            &state,
            "PATCH",
            "/v1/projects/p/databases/(default)/documents/bad/doc",
            json!({"fields":{"title":{"stringValue":"fixed"},"language":{"stringValue":"en"}}}),
        );
        let (status, body) = call(
            &state,
            "GET",
            "/v1/projects/p/databases/(default)/operations",
            Value::Null,
        );
        assert_eq!(status, 200, "{body}");
        assert!(body["operations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|op| op["metadata"]["state"] == "SUCCESSFUL"));
    }
}

#[test]
fn native_text_admin_stale_retained_operation_cannot_advance_a_new_native_generation() {
    let (state, clock, catalog) = native_text_state();
    let (_, initial) = call(
        &state,
        "POST",
        "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
        native_text_body(),
    );
    let id = initial["metadata"]["index"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    {
        let mut catalog = catalog.lock().unwrap();
        let definition = catalog.get("p", "(default)", id).unwrap().clone();
        let schedule = catalog
            .build("p", "(default)", id)
            .unwrap()
            .native
            .clone()
            .unwrap();
        catalog.remove("p", "(default)", id);
        catalog.add("p", "(default)", definition).unwrap();
        let generation = catalog.build("p", "(default)", id).unwrap().generation;
        catalog
            .schedule_native("p", "(default)", id, generation, schedule)
            .unwrap();
    }
    advance(&clock, 3600);
    let before = catalog.lock().unwrap().clone();
    let (status, body) = call(
        &state,
        "GET",
        &format!("/v1/{}", initial["name"].as_str().unwrap()),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, initial);
    assert_eq!(
        call(
            &state,
            "GET",
            "/v1/projects/p/databases/(default)/operations",
            Value::Null
        )
        .0,
        200
    );
    assert_eq!(*catalog.lock().unwrap(), before);
}

#[test]
fn native_text_admin_lost_observer_selection_returns_current_absence_before_preflight_error() {
    for foreign_epoch in [false, true] {
        let (state, clock, catalog) = native_text_state();
        call(
            &state,
            "PATCH",
            "/v1/projects/p/databases/(default)/documents/items/bad",
            json!({"fields":{"title":{"stringValue":"bad"},"language":{"stringValue":"fr"}}}),
        );
        let (_, initial) = call(
            &state,
            "POST",
            "/v1/projects/p/databases/(default)/collectionGroups/items/indexes",
            native_text_body(),
        );
        let id = initial["name"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let store = state.local.admin().operations();
        let observed = store.get("p", "(default)", id).unwrap();
        let target = observed.native_text.as_ref().unwrap();
        if foreign_epoch {
            let mut catalog = catalog.lock().unwrap();
            let build = catalog.build("p", "(default)", &target.index).unwrap();
            let mut schedule = build.native.clone().unwrap();
            let generation = build.generation;
            schedule.owner_epoch = Arc::new(());
            catalog
                .schedule_native("p", "(default)", &target.index, generation, schedule)
                .unwrap();
        }
        // Deterministically interleave eviction after selection and before admission/preparation.
        for i in 0..128 {
            store.record_views(
                "p",
                "(default)",
                &format!("evicted-{i}"),
                Value::Null,
                json!({"done":true}),
            );
        }
        advance(&clock, 3600);
        let before = catalog.lock().unwrap().clone();
        let targets = [(observed.id.as_str(), target)];
        state.local.advance_native_text_builds("p","(default)",super::index_rest::NativeTextSelection {operation_targets:Some(&targets),..Default::default()}).expect("a lost retained selection returns current absence rather than a source/epoch error");
        assert_eq!(*catalog.lock().unwrap(), before);
        assert_eq!(
            call(
                &state,
                "GET",
                &format!("/v1/{}", initial["name"].as_str().unwrap()),
                Value::Null
            )
            .0,
            404
        );
    }
}

fn assert_operation_publication_waits_for_control(publisher: &str) {
    use fireemu_core_session::tenancy::Scope;
    use std::sync::mpsc;
    use std::time::Duration;
    let (state, _) = state();
    let catalog = Arc::new(Mutex::new(
        fireemu_core_firestore::text_index::TextIndexCatalog::default(),
    ));
    state
        .local
        .set_text_indexes(catalog.clone(), false)
        .unwrap();
    let scope = Scope::Project("p".into());
    let barrier = state.local.barrier();
    let exclusive = barrier.exclusive();
    let captured = state.local.capture_native_text(&scope, &catalog).unwrap();
    let rollback = state
        .local
        .capture_native_text_rollback(&scope, &catalog)
        .unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::scope(|threads| {
        let state_ref = &state;
        let worker=threads.spawn(move || {
            started_tx.send(()).unwrap();
            let answer=match publisher {
                "database"=>(200,super::operations::record(state_ref,"p","(default)",super::operations::OperationKind::UpdateDatabase,&json!({}),Some(json!({}))).initial),
                "composite"=>call(state_ref,"POST","/v1/projects/p/databases/(default)/collectionGroups/items/indexes",json!({"queryScope":"COLLECTION","fields":[{"fieldPath":"a","order":"ASCENDING"},{"fieldPath":"b","order":"DESCENDING"}]})),
                "managed"=>{let response=super::managed::finish(state_ref,"p","(default)",&json!({}),&json!({}),&json!({}));(response.status,response.body)},
                _=>unreachable!(),
            };
            done_tx.send(answer).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let early = done_rx.recv_timeout(Duration::from_secs(2)).ok();
        let completed_during_control = early.is_some();
        state
            .local
            .restore_native_text(&scope, &catalog, &captured)
            .unwrap();
        state
            .local
            .rollback_native_text(&scope, &catalog, &rollback)
            .unwrap();
        drop(exclusive);
        let (status, answer) =
            early.unwrap_or_else(|| done_rx.recv_timeout(Duration::from_secs(10)).unwrap());
        worker.join().unwrap();
        assert!(!completed_during_control,"{publisher} published a retained view inside exclusive CONTROL; rollback can discard that accepted publication");
        assert_eq!(status, 200, "{answer}");
        let id = answer["name"].as_str().unwrap().rsplit('/').next().unwrap();
        assert!(
            state
                .local
                .admin()
                .operations()
                .get("p", "(default)", id)
                .is_some(),
            "publication accepted after CONTROL remains retained"
        );
    });
}

#[test]
fn native_text_admin_database_operation_publication_waits_for_control() {
    assert_operation_publication_waits_for_control("database");
}
#[test]
fn native_text_admin_composite_operation_publication_waits_for_control() {
    assert_operation_publication_waits_for_control("composite");
}
#[test]
fn native_text_admin_managed_operation_publication_waits_for_control() {
    assert_operation_publication_waits_for_control("managed");
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(32))]
    #[test]
    fn native_text_admin_schema_roundtrips_fields_and_refuses_unknown_options(
        field in "[a-z]{1,8}",
        override_field in "[a-z]{1,8}",
        multiple_fields in proptest::bool::ANY,
        unknown in 0usize..4,
    ) {
        let (state,_,_)=native_text_state();
        let mut request=native_text_body();
        request["fields"][0]["fieldPath"]=json!(&field);
        if multiple_fields {
            let mut second=request["fields"][0].clone();
            second["fieldPath"]=json!(format!("{field}z"));
            request["fields"].as_array_mut().unwrap().push(second);
        }
        request["searchIndexOptions"]["textLanguageOverrideFieldPath"]=json!(override_field);
        let (status,initial)=call(&state,"POST","/v1/projects/p/databases/(default)/collectionGroups/items/indexes",request.clone());
        proptest::prop_assert_eq!(status,200,"{}",initial);
        let (_,resource)=call(&state,"GET",&format!("/v1/{}",initial["metadata"]["index"].as_str().unwrap()),Value::Null);
        proptest::prop_assert_eq!(&resource["fields"],&request["fields"]);
        proptest::prop_assert_eq!(&resource["searchIndexOptions"],&request["searchIndexOptions"]);
        let other_group=format!("other{field}");
        let (status,other)=call(&state,"POST",&format!("/v1/projects/p/databases/(default)/collectionGroups/{other_group}/indexes"),request.clone());
        proptest::prop_assert_eq!(status,200,"{}",other);
        let (status,listed)=call(&state,"GET","/v1/projects/p/databases/(default)/collectionGroups/items/indexes",Value::Null);
        proptest::prop_assert_eq!(status,200,"{}",listed);
        let indexes=listed["indexes"].as_array().unwrap();
        proptest::prop_assert_eq!(indexes.len(),2,"{}",listed);
        proptest::prop_assert!(indexes.iter().all(|index| index["fields"]==request["fields"] && index["searchIndexOptions"]==request["searchIndexOptions"]));
        match unknown {
            0=>request["searchIndexOptions"]["textLanguage"]=json!("fr"),
            1=>request["queryScope"]=json!("COLLECTION_GROUP"),
            2=>request["fields"][usize::from(multiple_fields)]["searchConfig"]["textSpec"]["indexSpecs"][0]["matchType"]=json!("UNRECORDED"),
            _=>request["unknown"]=json!(true),
        }
        proptest::prop_assert_eq!(call(&state,"POST","/v1/projects/p/databases/(default)/collectionGroups/items/indexes",request).0,501);
    }
}

/// Review S2 (PICT 2-way over language value, productionExact and observation; seed rows in
/// docs.local): a document's language never poisons the database. In the default profile a
/// valid tag builds language-neutral; under productionExact a tag without recorded production
/// support (only `en` and `ja` have one) or a non-string value is refused only by the requests
/// that name that build. A malformed tag fails the build as production recorded.
#[test]
#[allow(clippy::too_many_lines)]
fn native_text_admin_language_values_never_poison_the_database() {
    const ROWS: [(&str, bool, &str); 44] = [
        ("ja", false, "list-indexes"),
        ("ja", true, "list-indexes"),
        ("non-string", false, "get-operation"),
        ("ja", true, "get-operation"),
        ("fr", false, "composite-list-other-group"),
        ("absent", false, "list-indexes"),
        ("invalid-string", false, "get-operation"),
        ("fr", true, "search"),
        ("non-string", true, "search"),
        ("ja", false, "search"),
        ("non-string", false, "search"),
        ("fr", false, "get-operation"),
        ("en", false, "list-indexes"),
        ("non-string", true, "get-index"),
        ("invalid-string", true, "get-index"),
        ("absent", true, "list-operations"),
        ("fr", false, "get-index"),
        ("non-string", true, "composite-list-other-group"),
        ("fr", true, "delete-operation"),
        ("absent", false, "composite-list-other-group"),
        ("fr", true, "list-indexes"),
        ("non-string", false, "list-operations"),
        ("non-string", false, "list-indexes"),
        ("en", true, "search"),
        ("non-string", false, "delete-operation"),
        ("absent", true, "search"),
        ("ja", true, "composite-list-other-group"),
        ("en", false, "list-operations"),
        ("en", true, "delete-operation"),
        ("en", false, "get-index"),
        ("invalid-string", true, "list-operations"),
        ("ja", true, "delete-operation"),
        ("fr", true, "list-operations"),
        ("invalid-string", false, "composite-list-other-group"),
        ("en", false, "get-operation"),
        ("invalid-string", true, "search"),
        ("absent", false, "delete-operation"),
        ("invalid-string", false, "delete-operation"),
        ("absent", false, "get-operation"),
        ("ja", true, "list-operations"),
        ("invalid-string", false, "list-indexes"),
        ("ja", true, "get-index"),
        ("en", false, "composite-list-other-group"),
        ("absent", false, "get-index"),
    ];
    for (row, (language, production_exact, observation)) in ROWS.into_iter().enumerate() {
        let label = format!("row {row}: {language}/exact={production_exact}/{observation}");
        let (state, clock, _) = native_text_state_exact(true, production_exact);
        let base = "/v1/projects/p/databases/(default)";
        let mut fields = json!({"title":{"stringValue":"marker"}});
        match language {
            "absent" => {}
            "non-string" => fields["language"] = json!({"integerValue":"7"}),
            "invalid-string" => fields["language"] = json!({"stringValue":"bad tag!"}),
            tag => fields["language"] = json!({"stringValue":tag}),
        }
        let (status, _) = call(
            &state,
            "PATCH",
            &format!("{base}/documents/items/doc"),
            json!({"fields":fields}),
        );
        assert_eq!(status, 200, "{label}");
        let (status, composite) = call(
            &state,
            "POST",
            &format!("{base}/collectionGroups/other/indexes"),
            json!({"queryScope":"COLLECTION","fields":[{"fieldPath":"a","order":"ASCENDING"},{"fieldPath":"b","order":"ASCENDING"}]}),
        );
        assert_eq!(status, 200, "{label}: {composite}");
        let (status, initial) = call(
            &state,
            "POST",
            &format!("{base}/collectionGroups/items/indexes"),
            native_text_body(),
        );
        assert_eq!(status, 200, "{label}: {initial}");
        advance(&clock, 3600);
        let operation = format!("/v1/{}", initial["name"].as_str().unwrap());
        let index = format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap());
        let refused = production_exact && matches!(language, "fr" | "non-string");
        let failure = match language {
            "invalid-string" => Some("Invalid text language: bad tag!"),
            "non-string" if !production_exact => Some("Invalid text language: 7"),
            _ => None,
        };
        let (status, answer) = match observation {
            "list-indexes" => call(
                &state,
                "GET",
                &format!("{base}/collectionGroups/items/indexes"),
                Value::Null,
            ),
            "get-index" => call(&state, "GET", &index, Value::Null),
            "get-operation" => call(&state, "GET", &operation, Value::Null),
            "list-operations" => call(&state, "GET", &format!("{base}/operations"), Value::Null),
            "composite-list-other-group" => call(
                &state,
                "GET",
                &format!("{base}/collectionGroups/other/indexes"),
                Value::Null,
            ),
            "search" => call(
                &state,
                "POST",
                &format!("{base}/documents:executePipeline"),
                json!({"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/items"}]},{"name":"search","options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":"marker"}]}}}}]}}}),
            ),
            _ => call(&state, "DELETE", &operation, Value::Null),
        };
        if observation == "search" {
            // Review M1: productionExact never answers a search with a definite result or a
            // definite "no READY index"; the default profile serves a built index and reports a
            // failed one as not READY.
            let error = if answer.is_array() {
                &answer[0]["error"]
            } else {
                &answer["error"]
            };
            if production_exact {
                assert_eq!(status, 501, "{label}: {answer}");
                assert!(
                    error["message"]
                        .as_str()
                        .unwrap()
                        .starts_with("FS_TEXT_UNOBSERVED"),
                    "{label}: {answer}"
                );
            } else if failure.is_some() {
                assert_eq!(status, 400, "{label}: {answer}");
                assert_eq!(error["status"], "FAILED_PRECONDITION", "{label}: {answer}");
            } else {
                assert_eq!(status, 200, "{label}: {answer}");
                assert_eq!(
                    answer[0]["results"].as_array().unwrap().len(),
                    1,
                    "{label}: {answer}"
                );
            }
            continue;
        }
        let direct = matches!(
            observation,
            "get-index" | "get-operation" | "delete-operation"
        );
        if refused && direct {
            assert_eq!(status, 501, "{label}: {answer}");
            assert!(
                answer["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("FS_TEXT_ADMIN_UNVERIFIED:"),
                "{label}: {answer}"
            );
            continue;
        }
        assert_eq!(status, 200, "{label}: {answer}");
        let expected_state = if refused {
            "CREATING"
        } else if failure.is_some() {
            "NEEDS_REPAIR"
        } else {
            "READY"
        };
        match observation {
            "list-indexes" => {
                let text = answer["indexes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|i| i.get("searchIndexOptions").is_some())
                    .unwrap();
                assert_eq!(text["state"], expected_state, "{label}: {answer}");
            }
            "get-index" => assert_eq!(answer["state"], expected_state, "{label}: {answer}"),
            "get-operation" => {
                assert_eq!(answer["done"], true, "{label}: {answer}");
                match failure {
                    Some(message) => assert_eq!(
                        answer["error"],
                        json!({"code":3,"message":message}),
                        "{label}: {answer}"
                    ),
                    None => assert_eq!(
                        answer["metadata"]["state"], "SUCCESSFUL",
                        "{label}: {answer}"
                    ),
                }
            }
            "list-operations" => {
                let text = answer["operations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|op| op["name"] == initial["name"])
                    .unwrap();
                assert_eq!(text.get("done").is_some(), !refused, "{label}: {answer}");
            }
            "composite-list-other-group" => {
                let composites = answer["indexes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|i| i.get("searchIndexOptions").is_none())
                    .count();
                assert_eq!(composites, 1, "{label}: {answer}");
            }
            _ => assert_eq!(answer, json!({}), "{label}"),
        }
    }
}

/// Review S9: deleting a text-index operation after its build deadline needs no prior read;
/// before the deadline it is still running.
#[test]
fn native_text_admin_delete_finished_operation_without_prior_read() {
    let (state, clock, _) = native_text_state();
    let base = "/v1/projects/p/databases/(default)";
    let (_, initial) = call(
        &state,
        "POST",
        &format!("{base}/collectionGroups/items/indexes"),
        native_text_body(),
    );
    let operation = format!("/v1/{}", initial["name"].as_str().unwrap());
    let (status, answer) = call(&state, "DELETE", &operation, Value::Null);
    assert_eq!(status, 400, "{answer}");
    assert_eq!(answer["error"]["status"], "FAILED_PRECONDITION");
    advance(&clock, 3600);
    assert_eq!(
        call(&state, "DELETE", &operation, Value::Null),
        (200, json!({}))
    );
    assert_eq!(call(&state, "GET", &operation, Value::Null).0, 404);
    let index = format!("/v1/{}", initial["metadata"]["index"].as_str().unwrap());
    assert_eq!(call(&state, "GET", &index, Value::Null).1["state"], "READY");
}

/// The index-file reload reaches the very catalog both transports search.
#[test]
fn text_index_catalog_is_the_attached_search_catalog() {
    let (state, _) = enterprise_native_state(true);
    assert!(state.local.text_index_catalog().is_none());
    let catalog = Arc::new(Mutex::new(
        fireemu_core_firestore::text_index::TextIndexCatalog::default(),
    ));
    state
        .local
        .set_text_indexes(Arc::clone(&catalog), false)
        .unwrap();
    assert!(Arc::ptr_eq(
        &state.local.text_index_catalog().unwrap(),
        &catalog
    ));
}

/// Merge review S-a: a definition without the options production always reports (here, from
/// the index file without `searchIndexOptions`) is listed with the options it has in the
/// default profile. productionExact leaves it out of the listing (documented) and refuses a
/// request that names it.
#[test]
fn native_text_admin_unrenderable_definitions_by_profile() {
    use fireemu_core_firestore::text_index::{DefaultTextLanguage, LanguageOverridePolicy};
    for production_exact in [false, true] {
        let (state, clock, catalog) = native_text_state_exact(true, production_exact);
        let base = "/v1/projects/p/databases/(default)";
        let (_, initial) = call(
            &state,
            "POST",
            &format!("{base}/collectionGroups/items/indexes"),
            native_text_body(),
        );
        advance(&clock, 3600);
        let id = initial["metadata"]["index"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let mut file = catalog
            .lock()
            .unwrap()
            .get("p", "(default)", &id)
            .unwrap()
            .clone();
        file.id = "file-text-0".into();
        file.language = DefaultTextLanguage::Autodetect;
        file.language_override = LanguageOverridePolicy::Disabled;
        file.state = fireemu_core_firestore::text_index::TextIndexState::Ready;
        catalog.lock().unwrap().add("p", "(default)", file).unwrap();
        let (status, listed) = call(
            &state,
            "GET",
            &format!("{base}/collectionGroups/items/indexes"),
            Value::Null,
        );
        assert_eq!(status, 200, "{listed}");
        let file_view = listed["indexes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|index| index["name"].as_str().unwrap().ends_with("/file-text-0"));
        let (status, direct) = call(
            &state,
            "GET",
            &format!("{base}/collectionGroups/items/indexes/file-text-0"),
            Value::Null,
        );
        if production_exact {
            assert!(file_view.is_none(), "{listed}");
            assert_eq!(status, 501, "{direct}");
        } else {
            let view = file_view.unwrap();
            assert_eq!(
                view["searchIndexOptions"],
                json!({"textLanguageOverrideFieldPath":""})
            );
            assert_eq!(status, 200, "{direct}");
            assert_eq!(direct, *view);
        }
    }
}
