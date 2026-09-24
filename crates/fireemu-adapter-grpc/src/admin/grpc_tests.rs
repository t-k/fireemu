//! The gRPC Admin services answer as the REST core does: each method is checked against the
//! REST request it corresponds to, and a resource name of another kind is refused.

use std::sync::{Arc, Mutex};

use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::admin::v1 as admin;
use fireemu_proto_firestore::google::firestore::admin::v1::firestore_admin_server::FirestoreAdmin;
use fireemu_proto_firestore::google::longrunning as lro;
use fireemu_proto_firestore::google::longrunning::operations_server::Operations;
use prost::Message;
use serde_json::{json, Value};
use tonic::{Code, Request};

use super::grpc::AdminGrpc;
use crate::gateway::Gateway;
use crate::local::LocalBackend;
use crate::rest::{RestRequest, RestState};

const DB: &str = "projects/p/databases/grpcdb";

fn state() -> Arc<RestState> {
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
    let state = Arc::new(RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), clock, 7)),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    });
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::ZERO);
    state
        .local
        .admin()
        .fields()
        .set_apply_duration(std::time::Duration::ZERO);
    rest(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=grpcdb",
        json!({"locationId": "us-central1", "type": "FIRESTORE_NATIVE"}),
    );
    state
}

fn rest(state: &RestState, method: &str, path: &str, body: Value) -> (u16, Value) {
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

fn owner<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", "Bearer owner".parse().unwrap());
    request
}

fn composite() -> admin::Index {
    use admin::index as i;
    let field = |path: &str, order: i::index_field::Order| i::IndexField {
        field_path: path.to_owned(),
        value_mode: Some(i::index_field::ValueMode::Order(order.into())),
    };
    admin::Index {
        query_scope: i::QueryScope::Collection.into(),
        fields: vec![
            field("a", i::index_field::Order::Ascending),
            field("b", i::index_field::Order::Descending),
        ],
        ..admin::Index::default()
    }
}

#[tokio::test]
async fn indexes_are_listed_and_deleted_over_grpc_as_over_rest() {
    let state = state();
    let service = AdminGrpc::new(Arc::clone(&state));
    let group = format!("{DB}/collectionGroups/items");
    service
        .create_index(owner(admin::CreateIndexRequest {
            parent: group.clone(),
            index: Some(composite()),
        }))
        .await
        .unwrap();
    let listed = service
        .list_indexes(owner(admin::ListIndexesRequest {
            parent: group.clone(),
            ..admin::ListIndexesRequest::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let (_, over_rest) = rest(&state, "GET", &format!("/v1/{group}/indexes"), Value::Null);
    assert_eq!(listed.indexes.len(), 1);
    assert_eq!(listed.indexes[0].name, over_rest["indexes"][0]["name"]);
    assert_eq!(
        listed.indexes[0].fields.len(),
        3,
        "the implied __name__ is listed"
    );
    let name = listed.indexes[0].name.clone();
    service
        .delete_index(owner(admin::DeleteIndexRequest { name: name.clone() }))
        .await
        .unwrap();
    assert_eq!(
        rest(&state, "GET", &format!("/v1/{name}"), Value::Null).0,
        404
    );
}

#[tokio::test]
async fn fields_are_read_listed_and_patched_over_grpc_as_over_rest() {
    let state = state();
    let service = AdminGrpc::new(Arc::clone(&state));
    let name = format!("{DB}/collectionGroups/items/fields/expires");
    let read = service
        .get_field(owner(admin::GetFieldRequest { name: name.clone() }))
        .await
        .unwrap()
        .into_inner();
    let (_, over_rest) = rest(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert_eq!(read.name, over_rest["name"]);
    let config = read.index_config.as_ref().unwrap();
    assert!(config.uses_ancestor_config);
    assert_eq!(
        config.ancestor_field,
        over_rest["indexConfig"]["ancestorField"]
    );
    assert_eq!(config.indexes.len(), 3);

    let operation = service
        .update_field(owner(admin::UpdateFieldRequest {
            field: Some(admin::Field {
                name: name.clone(),
                ttl_config: Some(admin::field::TtlConfig::default()),
                ..admin::Field::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["ttl_config".to_owned()],
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(operation.name.starts_with(&format!("{DB}/operations/")));
    let metadata = operation.metadata.unwrap();
    assert!(metadata.type_url.ends_with("FieldOperationMetadata"));
    let (_, after) = rest(&state, "GET", &format!("/v1/{name}"), Value::Null);
    assert!(after["ttlConfig"].is_object(), "{after}");

    let listed = service
        .list_fields(owner(admin::ListFieldsRequest {
            parent: format!("{DB}/collectionGroups/items"),
            filter: "ttlConfig:*".to_owned(),
            ..admin::ListFieldsRequest::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.fields.len(), 1);
    assert_eq!(listed.fields[0].name, name);
}

#[tokio::test]
async fn a_database_is_patched_and_bulk_deleted_over_grpc_as_over_rest() {
    let state = state();
    let service = AdminGrpc::new(Arc::clone(&state));
    let operation = service
        .update_database(owner(admin::UpdateDatabaseRequest {
            database: Some(admin::Database {
                name: DB.to_owned(),
                delete_protection_state:
                    admin::database::DeleteProtectionState::DeleteProtectionEnabled.into(),
                ..admin::Database::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["delete_protection_state".to_owned()],
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(operation.done);
    let (_, database) = rest(&state, "GET", &format!("/v1/{DB}"), Value::Null);
    assert_eq!(
        database["deleteProtectionState"],
        "DELETE_PROTECTION_ENABLED"
    );

    rest(
        &state,
        "POST",
        &format!("/v1/{DB}/documents/other?documentId=c"),
        json!({"fields": {"i": {"integerValue": "10"}}}),
    );
    let operation = service
        .bulk_delete_documents(owner(admin::BulkDeleteDocumentsRequest {
            name: DB.to_owned(),
            collection_ids: vec!["other".to_owned()],
            namespace_ids: Vec::new(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(operation
        .metadata
        .unwrap()
        .type_url
        .ends_with("BulkDeleteDocumentsMetadata"));
    assert_eq!(
        rest(
            &state,
            "GET",
            &format!("/v1/{DB}/documents/other/c"),
            Value::Null
        )
        .0,
        404
    );
}

#[tokio::test]
async fn operations_are_listed_cancelled_and_deleted_over_grpc_as_over_rest() {
    let state = state();
    state
        .local
        .admin()
        .indexes()
        .set_build_duration(std::time::Duration::from_secs(3600));
    let service = AdminGrpc::new(Arc::clone(&state));
    let created = service
        .create_index(owner(admin::CreateIndexRequest {
            parent: format!("{DB}/collectionGroups/items"),
            index: Some(composite()),
        }))
        .await
        .unwrap()
        .into_inner();
    let listed = service
        .list_operations(owner(lro::ListOperationsRequest {
            name: DB.to_owned(),
            ..lro::ListOperationsRequest::default()
        }))
        .await
        .unwrap()
        .into_inner();
    let (_, over_rest) = rest(&state, "GET", &format!("/v1/{DB}/operations"), Value::Null);
    assert_eq!(listed.operations.len(), 1);
    assert_eq!(
        listed.operations[0].name,
        over_rest["operations"][0]["name"]
    );
    assert_eq!(listed.operations[0].name, created.name);

    let cancel = service
        .cancel_operation(owner(lro::CancelOperationRequest {
            name: created.name.clone(),
        }))
        .await
        .unwrap_err();
    assert_eq!(cancel.code(), Code::InvalidArgument);
    assert_eq!(
        cancel.message(),
        "CancelOperation is not supported for operation type BUILD_INDEX."
    );
    let running = service
        .delete_operation(owner(lro::DeleteOperationRequest {
            name: created.name.clone(),
        }))
        .await
        .unwrap_err();
    assert_eq!(running.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn user_credentials_are_refused_on_standard_as_production_refuses_them() {
    let state = state();
    let service = AdminGrpc::new(Arc::clone(&state));
    let refused = service
        .list_user_creds(owner(admin::ListUserCredsRequest {
            parent: DB.to_owned(),
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert_eq!(
        refused.message(),
        "This operation requires an Enterprise database."
    );
    let refused = service
        .get_user_creds(owner(admin::GetUserCredsRequest {
            name: format!("{DB}/userCreds/someone"),
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn a_resource_name_of_another_kind_is_refused_before_it_is_routed() {
    let state = state();
    let service = AdminGrpc::new(Arc::clone(&state));
    let index_name = format!("{DB}/collectionGroups/items/indexes/CICAgOjXh4EK");
    let refused = service
        .delete_database(owner(admin::DeleteDatabaseRequest {
            name: index_name.clone(),
            etag: String::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument);
    let refused = service
        .get_database(owner(admin::GetDatabaseRequest { name: index_name }))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), Code::InvalidArgument);
    for name in [
        "projects/p/databases/grpcdb%2Fx",
        "projects/p/databases/",
        "projects/p/databases/grpcdb:bulkDeleteDocuments",
    ] {
        let refused = service
            .get_database(owner(admin::GetDatabaseRequest {
                name: name.to_owned(),
            }))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::InvalidArgument, "{name}");
    }
    // The database is untouched.
    assert_eq!(
        rest(&state, "GET", &format!("/v1/{DB}"), Value::Null).0,
        200
    );
}

#[tokio::test]
async fn a_create_with_a_key_or_tags_is_refused_over_grpc_as_over_rest_with_its_details() {
    let state = state();
    let service = AdminGrpc::new(Arc::clone(&state));
    let (status, over_rest) = rest(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=cmekdb",
        json!({"locationId": "us-central1", "type": "FIRESTORE_NATIVE",
               "cmekConfig": {"kmsKeyName": "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k"}}),
    );
    assert_ne!(status, 200, "{over_rest}");
    let refused = service
        .create_database(owner(admin::CreateDatabaseRequest {
            parent: "projects/p".to_owned(),
            database_id: "cmekdb".to_owned(),
            database: Some(admin::Database {
                location_id: "us-central1".to_owned(),
                r#type: admin::database::DatabaseType::FirestoreNative.into(),
                cmek_config: Some(admin::database::CmekConfig {
                    kms_key_name: "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k"
                        .to_owned(),
                    active_key_version: Vec::new(),
                }),
                ..admin::Database::default()
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.message(), over_rest["error"]["message"]);
    // The details REST carries travel in the gRPC status too.
    let details = over_rest["error"]["details"].as_array().map_or(0, Vec::len);
    assert!(details > 0, "{over_rest}");
    let decoded = fireemu_proto_firestore::google::rpc::Status::decode(refused.details()).unwrap();
    assert_eq!(decoded.details.len(), details);
    assert!(decoded.details[0].type_url.ends_with(
        over_rest["error"]["details"][0]["@type"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
    ));
    // Tags are refused as well.
    let (status, tagged) = rest(
        &state,
        "POST",
        "/v1/projects/p/databases?databaseId=tagdb",
        json!({"locationId": "us-central1", "type": "FIRESTORE_NATIVE", "tags": {"env": "dev"}}),
    );
    assert_ne!(status, 200, "{tagged}");
    let refused = service
        .create_database(owner(admin::CreateDatabaseRequest {
            parent: "projects/p".to_owned(),
            database_id: "tagdb".to_owned(),
            database: Some(admin::Database {
                location_id: "us-central1".to_owned(),
                r#type: admin::database::DatabaseType::FirestoreNative.into(),
                tags: [("env".to_owned(), "dev".to_owned())].into_iter().collect(),
                ..admin::Database::default()
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(refused.message(), tagged["error"]["message"]);
}
