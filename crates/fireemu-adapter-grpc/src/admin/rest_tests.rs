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
    let gateway = Gateway {
        enforce_limits,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
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
