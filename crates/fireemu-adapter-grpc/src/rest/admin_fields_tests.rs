//! The Admin field-configuration routes (`FS-CONFIG-RT-004`).

use std::sync::{Arc, Mutex};

use fireemu_core_firestore::index::{
    IndexFieldMode, IndexQueryScope, IndexSet, IndexValidationPolicy, PlanningContext,
    SingleFieldExemption,
};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

use super::{RestRequest, RestState};
use crate::gateway::Gateway;
use crate::local::LocalBackend;

const OWNER: Option<&str> = Some("Bearer owner");
const GROUP: &str = "/v1/projects/demo/databases/(default)/collectionGroups/sessions";

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
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_700_000_000),
            ))),
            7,
        )),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
    }
}

fn state() -> RestState {
    state_with(FirestoreEdition::Standard, FirestoreApiMode::Native)
}

fn call(state: &RestState, method: &str, path: &str, body: Value) -> (u16, Value) {
    call_as(state, OWNER, method, path, body)
}

fn call_as(
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
    });
    (response.status, response.body)
}

fn enable_ttl(state: &RestState) -> Value {
    let (status, body) = call(
        state,
        "PATCH",
        &format!("{GROUP}/fields/expiresAt?updateMask=ttlConfig"),
        json!({
            "name": "projects/demo/databases/(default)/collectionGroups/sessions/fields/expiresAt",
            "ttlConfig": {},
        }),
    );
    assert_eq!(status, 200, "{body}");
    body
}

#[test]
fn an_untouched_field_reports_the_inherited_index_configuration_and_no_ttl() {
    let state = state();
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["name"],
        json!("projects/demo/databases/(default)/collectionGroups/sessions/fields/expiresAt")
    );
    assert_eq!(body["indexConfig"]["usesAncestorConfig"], json!(true));
    assert_eq!(
        body["indexConfig"]["ancestorField"],
        json!("projects/demo/databases/(default)/collectionGroups/__default__/fields/*")
    );
    assert_eq!(
        body["indexConfig"]["indexes"].as_array().map(Vec::len),
        Some(3)
    );
    assert!(body.get("ttlConfig").is_none(), "{body}");
}

#[test]
fn patching_the_ttl_config_returns_a_completed_operation_and_the_field_reads_back_active() {
    let state = state();
    let operation = enable_ttl(&state);
    assert_eq!(operation["done"], json!(true));
    assert_eq!(
        operation["metadata"]["@type"],
        json!("type.googleapis.com/google.firestore.admin.v1.FieldOperationMetadata")
    );
    assert_eq!(operation["metadata"]["state"], json!("SUCCESSFUL"));
    assert_eq!(
        operation["metadata"]["field"],
        json!("projects/demo/databases/(default)/collectionGroups/sessions/fields/expiresAt")
    );
    assert_eq!(operation["response"]["ttlConfig"]["state"], json!("ACTIVE"));
    assert!(
        operation["name"]
            .as_str()
            .is_some_and(|name| name.starts_with("projects/demo/databases/(default)/operations/")),
        "{operation}"
    );

    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ttlConfig"]["state"], json!("ACTIVE"));
}

#[test]
fn clearing_the_ttl_config_removes_the_policy() {
    let state = state();
    enable_ttl(&state);
    let (status, body) = call(
        &state,
        "PATCH",
        &format!("{GROUP}/fields/expiresAt?updateMask=ttlConfig"),
        json!({
            "name": "projects/demo/databases/(default)/collectionGroups/sessions/fields/expiresAt"
        }),
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["response"].get("ttlConfig").is_none(), "{body}");
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.get("ttlConfig").is_none(), "{body}");
}

#[test]
fn a_second_ttl_field_in_the_same_collection_group_is_refused() {
    let state = state();
    enable_ttl(&state);
    let (status, body) = call(
        &state,
        "PATCH",
        &format!("{GROUP}/fields/purgeAt?updateMask=ttlConfig"),
        json!({"ttlConfig": {}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("FAILED_PRECONDITION"));
}

#[test]
fn an_invalid_field_path_is_refused_before_anything_is_configured() {
    let state = state();
    let (status, body) = call(
        &state,
        "PATCH",
        &format!("{GROUP}/fields/a..b?updateMask=ttlConfig"),
        json!({"ttlConfig": {}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("INVALID_ARGUMENT"));
}

#[test]
fn the_document_name_cannot_carry_a_ttl_policy() {
    let state = state();
    let (status, body) = call(
        &state,
        "PATCH",
        &format!("{GROUP}/fields/__name__?updateMask=ttlConfig"),
        json!({"ttlConfig": {}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("INVALID_ARGUMENT"));
}

#[test]
fn the_wildcard_field_cannot_carry_a_ttl_policy() {
    let state = state();
    let (status, body) = call(
        &state,
        "PATCH",
        &format!("{GROUP}/fields/*?updateMask=ttlConfig"),
        json!({"ttlConfig": {}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("INVALID_ARGUMENT"));
}

#[test]
fn patching_the_index_config_is_refused_rather_than_silently_ignored() {
    let state = state();
    let (status, body) = call(
        &state,
        "PATCH",
        &format!("{GROUP}/fields/payload?updateMask=indexConfig"),
        json!({"indexConfig": {"indexes": []}}),
    );
    assert_eq!(status, 501, "{body}");
    assert_eq!(body["error"]["status"], json!("UNIMPLEMENTED"));
}

#[test]
fn an_unknown_update_mask_path_is_refused() {
    let state = state();
    let (status, body) = call(
        &state,
        "PATCH",
        &format!("{GROUP}/fields/expiresAt?updateMask=ttlConfig,somethingElse"),
        json!({"ttlConfig": {}}),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("INVALID_ARGUMENT"));
}

#[test]
fn listing_with_the_ttl_filter_reports_only_the_configured_ttl_field() {
    let state = state();
    enable_ttl(&state);
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?filter=ttlConfig:*"),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    let fields = body["fields"].as_array().expect("fields");
    assert_eq!(fields.len(), 1, "{body}");
    assert_eq!(
        fields[0]["name"],
        json!("projects/demo/databases/(default)/collectionGroups/sessions/fields/expiresAt")
    );
    assert_eq!(fields[0]["ttlConfig"]["state"], json!("ACTIVE"));
}

#[test]
fn listing_the_explicit_overrides_reports_the_exempted_field_and_the_ttl_field() {
    let mut indexes = IndexSet::default();
    indexes.add_exemption(&SingleFieldExemption {
        collection_group: fireemu_core_types::ids::CollectionId::try_new("sessions")
            .expect("collection"),
        field: fireemu_core_firestore::field_path::FieldPath::parse("payload").expect("field"),
        query_scope: IndexQueryScope::Collection,
    });
    let state = state();
    state
        .local
        .replace_project_database_indexes("demo", "(default)", indexes);
    enable_ttl(&state);
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?filter=indexConfig.usesAncestorConfig:false"),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    let names: Vec<&str> = body["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .filter_map(|field| field["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "projects/demo/databases/(default)/collectionGroups/sessions/fields/expiresAt",
            "projects/demo/databases/(default)/collectionGroups/sessions/fields/payload",
        ]
    );
    let payload = body["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .find(|field| {
            field["name"]
                .as_str()
                .is_some_and(|n| n.ends_with("payload"))
        })
        .expect("payload field");
    assert!(
        payload["indexConfig"].get("usesAncestorConfig").is_none(),
        "{payload}"
    );
}

#[test]
fn an_exempted_field_reports_the_modes_that_remain() {
    let mut indexes = IndexSet::default();
    let collection =
        fireemu_core_types::ids::CollectionId::try_new("sessions").expect("collection");
    let field = fireemu_core_firestore::field_path::FieldPath::parse("payload").expect("field");
    indexes.set_single_field_indexes(
        &collection,
        &field,
        vec![(IndexQueryScope::Collection, IndexFieldMode::Ascending)],
    );
    let state = state();
    state
        .local
        .replace_project_database_indexes("demo", "(default)", indexes);
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/payload"),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["indexConfig"]["indexes"],
        json!([{"queryScope": "COLLECTION", "fields": [{"fieldPath": "payload", "order": "ASCENDING"}]}])
    );
    assert!(
        body["indexConfig"].get("usesAncestorConfig").is_none(),
        "{body}"
    );
}

#[test]
fn an_unsupported_list_filter_is_refused() {
    let state = state();
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?filter=ttlConfig.state%3DACTIVE"),
        Value::Null,
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("INVALID_ARGUMENT"));
}

#[test]
fn a_page_size_of_one_pages_the_listing() {
    let mut indexes = IndexSet::default();
    let collection =
        fireemu_core_types::ids::CollectionId::try_new("sessions").expect("collection");
    for name in ["a", "b"] {
        indexes.set_single_field_indexes(
            &collection,
            &fireemu_core_firestore::field_path::FieldPath::parse(name).expect("field"),
            vec![(IndexQueryScope::Collection, IndexFieldMode::Ascending)],
        );
    }
    let state = state();
    state
        .local
        .replace_project_database_indexes("demo", "(default)", indexes);
    let (status, first) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?pageSize=1"),
        Value::Null,
    );
    assert_eq!(status, 200, "{first}");
    assert_eq!(first["fields"].as_array().map(Vec::len), Some(1));
    let token = first["nextPageToken"].as_str().expect("a next page");
    let (status, second) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?pageSize=1&pageToken={token}"),
        Value::Null,
    );
    assert_eq!(status, 200, "{second}");
    assert_eq!(second["fields"].as_array().map(Vec::len), Some(1));
    assert!(second.get("nextPageToken").is_none(), "{second}");
    assert_ne!(first["fields"][0]["name"], second["fields"][0]["name"]);
}

#[test]
fn field_configuration_requires_owner_credentials() {
    let state = state();
    let (status, body) = call_as(
        &state,
        Some("Bearer someone-else"),
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"]["status"], json!("PERMISSION_DENIED"));
}

#[test]
fn a_database_that_does_not_exist_has_no_field_configuration() {
    let state = state();
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/demo/databases/absent/collectionGroups/sessions/fields/expiresAt",
        Value::Null,
    );
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"]["status"], json!("NOT_FOUND"));
}

#[test]
fn field_configuration_is_not_served_for_a_non_standard_native_database() {
    let state = state_with(FirestoreEdition::Enterprise, FirestoreApiMode::Native);
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(status, 501, "{body}");
    assert_eq!(body["error"]["status"], json!("UNIMPLEMENTED"));
}

#[test]
fn the_operation_a_patch_returned_can_be_polled_and_listed() {
    let state = state();
    let operation = enable_ttl(&state);
    let name = operation["name"].as_str().expect("operation name");
    let (status, polled) = call(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(status, 200, "{polled}");
    assert_eq!(polled["done"], json!(true));
    assert_eq!(polled["name"], operation["name"]);

    let (status, listed) = call(
        &state,
        "GET",
        "/v1/projects/demo/databases/(default)/operations",
        Value::Null,
    );
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["operations"].as_array().map(Vec::len), Some(1));
}

#[test]
fn an_operation_that_was_never_produced_is_not_found() {
    let state = state();
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/demo/databases/(default)/operations/absent",
        Value::Null,
    );
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"]["status"], json!("NOT_FOUND"));
}

#[test]
fn field_configuration_does_not_shadow_the_document_routes() {
    let state = state();
    enable_ttl(&state);
    let documents = "/v1/projects/demo/databases/(default)/documents";
    let (status, created) = call(
        &state,
        "POST",
        &format!("{documents}/sessions?documentId=s1"),
        json!({"fields": {"v": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200, "{created}");
    let (status, read) = call(
        &state,
        "GET",
        &format!("{documents}/sessions/s1"),
        Value::Null,
    );
    assert_eq!(status, 200, "{read}");
}
