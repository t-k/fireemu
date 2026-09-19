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
        control_token: None,
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
        origin: None,
        browser_metadata: false,
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
fn listing_the_explicit_overrides_reports_only_the_exempted_field() {
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
    // expiresAt carries a TTL policy but no index override of its own, so it still
    // inherits its indexes and does not belong in a usesAncestorConfig:false listing.
    assert_eq!(
        names,
        vec!["projects/demo/databases/(default)/collectionGroups/sessions/fields/payload"]
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
    let indexes = body["indexConfig"]["indexes"].as_array().expect("indexes");
    assert_eq!(indexes.len(), 1, "{body}");
    assert_eq!(indexes[0]["queryScope"], json!("COLLECTION"));
    assert_eq!(
        indexes[0]["fields"],
        json!([{"fieldPath": "payload", "order": "ASCENDING"}])
    );
    assert!(
        indexes[0]["name"].as_str().is_some_and(|name| name
            .starts_with("projects/demo/databases/(default)/collectionGroups/sessions/indexes/")),
        "{body}"
    );
    assert!(
        body["indexConfig"].get("usesAncestorConfig").is_none(),
        "{body}"
    );
}

#[test]
fn listing_with_the_ancestor_filter_excludes_a_ttl_only_field() {
    let state = state();
    enable_ttl(&state);
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?filter=indexConfig.usesAncestorConfig:false"),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["fields"].as_array().map(Vec::len), Some(0), "{body}");
}

#[test]
fn listing_without_a_filter_reports_the_ttl_field_and_the_overrides() {
    let state = state();
    enable_ttl(&state);
    let (status, body) = call(&state, "GET", &format!("{GROUP}/fields"), Value::Null);
    assert_eq!(status, 200, "{body}");
    let names: Vec<&str> = body["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .filter_map(|field| field["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["projects/demo/databases/(default)/collectionGroups/sessions/fields/expiresAt"]
    );
}

#[test]
fn polling_an_operation_returns_the_same_response_the_patch_returned() {
    let state = state();
    let patched = enable_ttl(&state);
    let name = patched["name"].as_str().expect("operation name");
    let (status, polled) = call(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(status, 200, "{polled}");
    assert_eq!(polled, patched);

    // A later patch does not rewrite what the earlier operation answered.
    let (status, cleared) = call(
        &state,
        "PATCH",
        &format!("{GROUP}/fields/expiresAt?updateMask=ttlConfig"),
        json!({}),
    );
    assert_eq!(status, 200, "{cleared}");
    let (_, polled_again) = call(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(polled_again, patched);
}

#[test]
fn admin_operations_require_owner_credentials() {
    let state = state();
    let operation = enable_ttl(&state);
    let name = operation["name"].as_str().expect("operation name");
    for path in [
        format!("/v1/{name}"),
        "/v1/projects/demo/databases/(default)/operations".to_owned(),
    ] {
        let (status, body) = call_as(
            &state,
            Some("Bearer someone-else"),
            "GET",
            &path,
            Value::Null,
        );
        assert_eq!(status, 403, "{path}: {body}");
        assert_eq!(
            body["error"]["status"],
            json!("PERMISSION_DENIED"),
            "{path}"
        );
    }
}

#[test]
fn an_operation_of_another_project_is_not_found_through_this_projects_listing() {
    let state = state();
    let operation = enable_ttl(&state);
    let name = operation["name"].as_str().expect("operation name");
    let id = name.rsplit('/').next().expect("an operation id");
    let (status, body) = call(
        &state,
        "GET",
        &format!("/v1/projects/other/databases/(default)/operations/{id}"),
        Value::Null,
    );
    assert_eq!(status, 404, "{body}");
    let (status, listed) = call(
        &state,
        "GET",
        "/v1/projects/other/databases/(default)/operations",
        Value::Null,
    );
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["operations"].as_array().map(Vec::len), Some(0));
}

#[test]
fn a_patch_body_that_is_not_a_field_resource_is_refused() {
    let state = state();
    enable_ttl(&state);
    for body in [json!([1, 2]), json!("ttlConfig"), json!(7)] {
        let (status, answer) = call(
            &state,
            "PATCH",
            &format!("{GROUP}/fields/expiresAt?updateMask=ttlConfig"),
            body.clone(),
        );
        assert_eq!(status, 400, "{body}: {answer}");
        assert_eq!(
            answer["error"]["status"],
            json!("INVALID_ARGUMENT"),
            "{body}"
        );
    }
    // The policy the malformed bodies did not name is still in force.
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(field["ttlConfig"]["state"], json!("ACTIVE"));
}

#[test]
fn a_ttl_patch_beyond_the_catalog_bound_is_resource_exhausted() {
    let state = state();
    for i in 0..fireemu_core_firestore::ttl::MAX_TTL_FIELDS_PER_DATABASE {
        let (status, body) = call(
            &state,
            "PATCH",
            &format!(
                "/v1/projects/demo/databases/(default)/collectionGroups/g{i}/fields/expiresAt?updateMask=ttlConfig"
            ),
            json!({"ttlConfig": {}}),
        );
        assert_eq!(status, 200, "{i}: {body}");
    }
    let (status, body) = call(
        &state,
        "PATCH",
        "/v1/projects/demo/databases/(default)/collectionGroups/one-too-many/fields/expiresAt?updateMask=ttlConfig",
        json!({"ttlConfig": {}}),
    );
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["error"]["status"], json!("RESOURCE_EXHAUSTED"));
}

#[test]
fn field_configuration_operations_are_not_served_for_a_non_standard_native_database() {
    let state = state_with(FirestoreEdition::Enterprise, FirestoreApiMode::Native);
    let (status, body) = call(
        &state,
        "GET",
        "/v1/projects/demo/databases/(default)/operations",
        Value::Null,
    );
    assert_eq!(status, 501, "{body}");
    assert_eq!(body["error"]["status"], json!("UNIMPLEMENTED"));
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

/// A state whose `sessions` collection group carries two explicitly overridden fields.
fn paged_state() -> RestState {
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
    state
}

#[test]
fn a_page_size_of_one_pages_the_listing() {
    let state = paged_state();
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
fn every_reported_index_carries_a_distinct_stable_resource_name() {
    let state = state();
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    let names: Vec<&str> = body["indexConfig"]["indexes"]
        .as_array()
        .expect("indexes")
        .iter()
        .map(|index| index["name"].as_str().expect("an index name"))
        .collect();
    assert_eq!(names.len(), 3, "{body}");
    for name in &names {
        assert!(
            name.starts_with(
                "projects/demo/databases/(default)/collectionGroups/sessions/indexes/"
            ),
            "{name}"
        );
    }
    let distinct: std::collections::BTreeSet<&&str> = names.iter().collect();
    assert_eq!(distinct.len(), 3, "{body}");

    // The name is derived from what defines the index, so a second read reports the same one.
    let (_, again) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(
        again["indexConfig"]["indexes"],
        body["indexConfig"]["indexes"]
    );

    // A different field is a different index, so the names do not collide.
    let (_, other) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/payload"),
        Value::Null,
    );
    assert_ne!(
        other["indexConfig"]["indexes"][0]["name"],
        body["indexConfig"]["indexes"][0]["name"]
    );
}

#[test]
fn a_page_token_is_opaque_and_carries_no_offset_a_caller_can_read() {
    let state = paged_state();
    let (status, first) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?pageSize=1"),
        Value::Null,
    );
    assert_eq!(status, 200, "{first}");
    let token = first["nextPageToken"].as_str().expect("a next page");
    assert_eq!(token.len(), 20, "{token}");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()), "{token}");
    assert_ne!(token, "1");
}

#[test]
fn a_page_token_issued_for_another_listing_is_refused() {
    let state = paged_state();
    let (_, first) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?pageSize=1"),
        Value::Null,
    );
    let token = first["nextPageToken"].as_str().expect("a next page");

    // The same token against a different collection group names a page of a listing that
    // never issued it.
    let (status, body) = call(
        &state,
        "GET",
        &format!(
            "/v1/projects/demo/databases/(default)/collectionGroups/orders/fields?pageSize=1&pageToken={token}"
        ),
        Value::Null,
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("INVALID_ARGUMENT"));

    // So does the same token against a different filter of the same collection group.
    let (status, body) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?filter=ttlConfig:*&pageSize=1&pageToken={token}"),
        Value::Null,
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("INVALID_ARGUMENT"));
}

#[test]
fn a_malformed_page_token_is_refused() {
    let state = paged_state();
    for token in ["1", "notahexstring0000000", "00112233445566778899aa"] {
        let (status, body) = call(
            &state,
            "GET",
            &format!("{GROUP}/fields?pageSize=1&pageToken={token}"),
            Value::Null,
        );
        assert_eq!(status, 400, "{token}: {body}");
        assert_eq!(
            body["error"]["status"],
            json!("INVALID_ARGUMENT"),
            "{token}"
        );
    }
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

/// The state a refused patch must leave exactly as it found it: the field resource, the
/// listing that selects TTL-configured fields, and the operation record.
fn ttl_observations(state: &RestState) -> (Value, Value, Value) {
    let (_, field) = call(
        state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    let (_, listed) = call(
        state,
        "GET",
        &format!("{GROUP}/fields?filter=ttlConfig:*"),
        Value::Null,
    );
    let (_, operations) = call(
        state,
        "GET",
        "/v1/projects/demo/databases/(default)/operations",
        Value::Null,
    );
    (field, listed, operations)
}

fn patch_ttl(state: &RestState, config: &Value) -> (u16, Value) {
    call(
        state,
        "PATCH",
        &format!("{GROUP}/fields/expiresAt?updateMask=ttlConfig"),
        json!({ "ttlConfig": config }),
    )
}

#[test]
fn a_ttl_config_that_is_not_an_object_is_refused_without_changing_anything() {
    let state = state();
    let before = ttl_observations(&state);
    for config in [
        json!(false),
        json!(true),
        json!(0),
        json!(604_800),
        json!("604800s"),
        json!([]),
        json!([{}]),
    ] {
        let (status, body) = patch_ttl(&state, &config);
        assert_eq!(status, 400, "{config}: {body}");
        assert_eq!(
            body["error"]["status"],
            json!("INVALID_ARGUMENT"),
            "{config}"
        );
        assert_eq!(ttl_observations(&state), before, "{config}");
    }
}

#[test]
fn a_ttl_config_naming_an_unknown_setting_is_refused_without_changing_anything() {
    let state = state();
    let before = ttl_observations(&state);
    let (status, body) = patch_ttl(&state, &json!({ "retention": "604800s" }));
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"]["status"], json!("INVALID_ARGUMENT"));
    assert_eq!(ttl_observations(&state), before);
}

#[test]
fn an_empty_ttl_config_enables_the_policy_without_an_expiration_offset() {
    let state = state();
    let (status, body) = patch_ttl(&state, &json!({}));
    assert_eq!(status, 200, "{body}");
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(field["ttlConfig"], json!({ "state": "ACTIVE" }));
}

#[test]
fn an_echoed_output_only_state_is_ignored_rather_than_installed() {
    let state = state();
    let (status, body) = patch_ttl(&state, &json!({ "state": "NEEDS_REPAIR" }));
    assert_eq!(status, 200, "{body}");
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(field["ttlConfig"]["state"], json!("ACTIVE"));
}

#[test]
fn an_expiration_offset_is_stored_and_read_back_by_every_surface() {
    let state = state();
    let (status, operation) = patch_ttl(&state, &json!({ "expirationOffset": "604800s" }));
    assert_eq!(status, 200, "{operation}");
    let expected = json!({ "state": "ACTIVE", "expirationOffset": "604800s" });
    assert_eq!(operation["response"]["ttlConfig"], expected);
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(field["ttlConfig"], expected);
    let (_, listed) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields?filter=ttlConfig:*"),
        Value::Null,
    );
    assert_eq!(listed["fields"][0]["ttlConfig"], expected);
}

#[test]
fn a_second_patch_replaces_the_expiration_offset_it_found() {
    let state = state();
    patch_ttl(&state, &json!({ "expirationOffset": "604800s" }));
    let (status, body) = patch_ttl(&state, &json!({ "expirationOffset": "60s" }));
    assert_eq!(status, 200, "{body}");
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(field["ttlConfig"]["expirationOffset"], json!("60s"));

    // A bare `{}` names no offset, so the policy carries none again.
    let (status, body) = patch_ttl(&state, &json!({}));
    assert_eq!(status, 200, "{body}");
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(field["ttlConfig"], json!({ "state": "ACTIVE" }));
}

#[test]
fn the_documented_expiration_offset_bounds_are_the_ones_enforced() {
    let state = state();
    for accepted in ["0s", "1s", "2147483647s", "60.000000000s"] {
        let (status, body) = patch_ttl(&state, &json!({ "expirationOffset": accepted }));
        assert_eq!(status, 200, "{accepted}: {body}");
    }
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(field["ttlConfig"]["expirationOffset"], json!("60s"));

    let before = ttl_observations(&state);
    for refused in [
        json!("2147483648s"),
        json!("-1s"),
        json!("1.5s"),
        json!("0.000000001s"),
        json!("604800"),
        json!("P7D"),
        json!(604_800),
        json!(true),
        json!([]),
        json!({}),
    ] {
        let (status, body) = patch_ttl(&state, &json!({ "expirationOffset": refused }));
        assert_eq!(status, 400, "{refused}: {body}");
        assert_eq!(
            body["error"]["status"],
            json!("INVALID_ARGUMENT"),
            "{refused}"
        );
        assert_eq!(ttl_observations(&state), before, "{refused}");
    }
}

#[test]
fn a_null_expiration_offset_is_the_unset_one() {
    let state = state();
    let (status, body) = patch_ttl(&state, &json!({ "expirationOffset": Value::Null }));
    assert_eq!(status, 200, "{body}");
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert_eq!(field["ttlConfig"], json!({ "state": "ACTIVE" }));
}

#[test]
fn a_null_ttl_config_disables_the_policy_the_patch_found() {
    let state = state();
    patch_ttl(&state, &json!({ "expirationOffset": "604800s" }));
    let (status, body) = patch_ttl(&state, &Value::Null);
    assert_eq!(status, 200, "{body}");
    let (_, field) = call(
        &state,
        "GET",
        &format!("{GROUP}/fields/expiresAt"),
        Value::Null,
    );
    assert!(field.get("ttlConfig").is_none(), "{field}");
}
