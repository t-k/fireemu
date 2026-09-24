//! `projects/{p}/databases/{d}/collectionGroups/{g}/indexes[/{id}]`: create, list, get and
//! delete composite indexes, answered in production's shapes.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope};
use fireemu_core_types::ids::CollectionId;
use serde_json::{json, Value};

use super::indexes::{scope_name, with_implied_name, IndexState, RuntimeIndex};
use super::rest::error;
use crate::encode::encode_instant;
use crate::rest::json::timestamp_to_json;
use crate::rest::{RestResponse, RestState};

const INDEX_TYPE_URL: &str = "type.googleapis.com/google.firestore.admin.v1.Index";
const INDEX_METADATA_TYPE_URL: &str =
    "type.googleapis.com/google.firestore.admin.v1.IndexOperationMetadata";

fn ok(body: Value) -> RestResponse {
    RestResponse { status: 200, body }
}

fn field_json(field: &IndexField) -> Value {
    let path = field.path.canonical();
    match field.mode {
        IndexFieldMode::Ascending => json!({"fieldPath": path, "order": "ASCENDING"}),
        IndexFieldMode::Descending => json!({"fieldPath": path, "order": "DESCENDING"}),
        IndexFieldMode::Contains => json!({"fieldPath": path, "arrayConfig": "CONTAINS"}),
        IndexFieldMode::Vector { dimension } => {
            json!({"fieldPath": path, "vectorConfig": {"dimension": dimension, "flat": {}}})
        }
    }
}

/// The `Index` resource of a runtime index.
pub(crate) fn index_json(
    project: &str,
    database: &str,
    index: &RuntimeIndex,
    state: IndexState,
) -> Value {
    let shown = with_implied_name(&index.definition);
    json!({
        "name": index_name(project, database, index),
        "queryScope": scope_name(shown.query_scope),
        "fields": shown.fields.iter().map(field_json).collect::<Vec<_>>(),
        "state": state.as_str(),
        "density": "SPARSE_ALL",
    })
}

pub(crate) fn index_name(project: &str, database: &str, index: &RuntimeIndex) -> String {
    format!(
        "projects/{project}/databases/{database}/collectionGroups/{}/indexes/{}",
        index.definition.collection_group.as_str(),
        index.id
    )
}

fn instant(at: fireemu_core_types::time::LogicalInstant) -> Value {
    json!(timestamp_to_json(&encode_instant(at)))
}

/// The operation that builds `index`: as first answered while it builds, and done once it
/// is `READY`.
pub(crate) fn operation_json(
    project: &str,
    database: &str,
    operation_name: &str,
    index: &RuntimeIndex,
    state: IndexState,
    (documents, end): (u64, fireemu_core_types::time::LogicalInstant),
) -> Value {
    let name = index_name(project, database, index);
    match state {
        IndexState::Creating => json!({
            "name": operation_name,
            "metadata": {
                "@type": INDEX_METADATA_TYPE_URL,
                "startTime": instant(index.start_time),
                "index": name,
                "state": "INITIALIZING",
            },
        }),
        IndexState::Ready => {
            let mut response = index_json(project, database, index, state);
            response["@type"] = json!(INDEX_TYPE_URL);
            let mut metadata = json!({
                "@type": INDEX_METADATA_TYPE_URL,
                "startTime": instant(index.start_time),
                "endTime": instant(end),
                "index": name,
                "state": "SUCCESSFUL",
            });
            // Present even over no documents, where proto3 JSON leaves out the zero counts.
            metadata["progressDocuments"] = if documents > 0 {
                json!({
                    "estimatedWork": documents.to_string(),
                    "completedWork": documents.to_string(),
                })
            } else {
                json!({})
            };
            json!({
                "name": operation_name,
                "metadata": metadata,
                "done": true,
                "response": response,
            })
        }
    }
}

/// The index list of a deleted database: the indexes it had when it was deleted.
pub(crate) fn deleted_database_list(
    state: &RestState,
    project: &str,
    database: &str,
    group: &str,
) -> RestResponse {
    let indexes: Vec<Value> = state
        .local
        .admin()
        .indexes()
        .tombstone(project, database)
        .iter()
        .filter(|i| group == "-" || i.definition.collection_group.as_str() == group)
        .map(|i| index_json(project, database, i, IndexState::Ready))
        .collect();
    if indexes.is_empty() {
        ok(json!({}))
    } else {
        ok(json!({ "indexes": indexes }))
    }
}

fn violation(field: &str, message: &str) -> RestResponse {
    error(
        tonic::Code::InvalidArgument,
        message,
        Some(json!([{
            "@type": "type.googleapis.com/google.rpc.BadRequest",
            "fieldViolations": [{"field": field, "description": message}]
        }])),
    )
}

/// Reads an `Index` request body into the planner's definition, refusing what production
/// refuses.
fn parse_index(group: &str, body: &Value) -> Result<IndexDefinition, RestResponse> {
    let scope = match body.get("queryScope").and_then(Value::as_str) {
        None | Some("QUERY_SCOPE_UNSPECIFIED") => {
            return Err(error(
                tonic::Code::InvalidArgument,
                "query_scope must be specified.",
                None,
            ))
        }
        Some("COLLECTION") => IndexQueryScope::Collection,
        Some("COLLECTION_GROUP") => IndexQueryScope::CollectionGroup,
        Some(other) => {
            let message = format!(
                "Invalid value at 'index.query_scope' (type.googleapis.com/google.firestore.admin.v1.Index.QueryScope), \"{other}\""
            );
            return Err(violation("index.query_scope", &message));
        }
    };
    let mut fields = Vec::new();
    for (i, field) in body
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let set: Vec<&str> = ["order", "arrayConfig", "vectorConfig"]
            .into_iter()
            .filter(|k| field.get(*k).is_some_and(|v| !v.is_null()))
            .collect();
        if set.len() > 1 {
            let message = format!(
                "Invalid value at 'index.fields[{i}]' (oneof), oneof field 'value_mode' is already set. Cannot set '{}'",
                set[1]
            );
            return Err(violation(&format!("index.fields[{i}]"), &message));
        }
        let path = field
            .get("fieldPath")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mode = match (
            field.get("order").and_then(Value::as_str),
            field.get("arrayConfig").and_then(Value::as_str),
            field.get("vectorConfig"),
        ) {
            (Some("ASCENDING"), None, None) => IndexFieldMode::Ascending,
            (Some("DESCENDING"), None, None) => IndexFieldMode::Descending,
            (None, Some("CONTAINS"), None) => IndexFieldMode::Contains,
            (None, None, Some(config)) => IndexFieldMode::Vector {
                dimension: config
                    .get("dimension")
                    .and_then(|d| d.as_u64().or_else(|| d.as_str()?.parse().ok()))
                    .and_then(|d| u32::try_from(d).ok())
                    .unwrap_or(0),
            },
            _ => {
                return Err(error(
                    tonic::Code::InvalidArgument,
                    "index field value_mode must be specified.",
                    None,
                ))
            }
        };
        let Ok(path) = FieldPath::parse(path) else {
            return Err(error(
                tonic::Code::InvalidArgument,
                &format!("Invalid field path: {path}"),
                None,
            ));
        };
        fields.push(IndexField { path, mode });
    }
    let vector = fields
        .iter()
        .any(|f| matches!(f.mode, IndexFieldMode::Vector { .. }));
    let named: Vec<&IndexField> = fields
        .iter()
        .filter(|f| !f.path.is_document_name())
        .collect();
    if named.len() < 2 && !vector {
        return Err(error(
            tonic::Code::InvalidArgument,
            "this index is not necessary, configure using single field index controls",
            None,
        ));
    }
    let Ok(collection_group) = CollectionId::try_new(group) else {
        return Err(error(
            tonic::Code::InvalidArgument,
            "Invalid collection group id.",
            None,
        ));
    };
    Ok(IndexDefinition {
        collection_group,
        query_scope: scope,
        fields,
    })
}

/// Routes `collectionGroups/{g}/indexes[/{id}]` of a live Standard database.
pub(crate) fn route(
    state: &RestState,
    project: &str,
    database: &str,
    group: &str,
    method: &str,
    rest: &[&str],
    body: &Value,
) -> RestResponse {
    let configured = state.local.configured_composites(project, database);
    let registry = state.local.admin().indexes();
    let now = state.local.admin_now();
    match (method, rest) {
        ("POST", []) => {
            let definition = match parse_index(group, body) {
                Ok(definition) => definition,
                Err(response) => return response,
            };
            // An index the index file declares is an existing index like any other.
            if let Some(existing) = registry
                .view(project, database, &configured)
                .into_iter()
                .find(|i| i.definition == definition)
            {
                return error(
                    tonic::Code::AlreadyExists,
                    &format!("index already exists with index ID = {}", existing.id),
                    None,
                );
            }
            let operation = super::operations::reserve_id(state, project, database);
            match registry.create(project, database, definition, now, operation.clone()) {
                Err(existing) => error(
                    tonic::Code::AlreadyExists,
                    &format!("index already exists with index ID = {existing}"),
                    None,
                ),
                Ok(index) => {
                    let name =
                        format!("projects/{project}/databases/{database}/operations/{operation}");
                    let initial = operation_json(
                        project,
                        database,
                        &name,
                        &index,
                        IndexState::Creating,
                        (0, now),
                    );
                    super::operations::record_index(
                        state,
                        project,
                        database,
                        &operation,
                        &index.id,
                        initial.clone(),
                    );
                    ok(initial)
                }
            }
        }
        ("GET", []) => {
            let indexes: Vec<Value> = registry
                .view(project, database, &configured)
                .iter()
                .filter(|i| group == "-" || i.definition.collection_group.as_str() == group)
                .map(|i| index_json(project, database, i, registry.state(i, now)))
                .collect();
            if indexes.is_empty() {
                ok(json!({}))
            } else {
                ok(json!({ "indexes": indexes }))
            }
        }
        ("GET", [id]) if !super::indexes::is_index_id(id) => error(
            tonic::Code::InvalidArgument,
            &format!("Invalid index resource id \"{id}\"."),
            None,
        ),
        ("GET", [id]) => match registry
            .view(project, database, &configured)
            .into_iter()
            .find(|i| i.id == *id)
        {
            Some(index) if group == "-" || index.definition.collection_group.as_str() == group => {
                ok(index_json(
                    project,
                    database,
                    &index,
                    registry.state(&index, now),
                ))
            }
            _ => error(tonic::Code::NotFound, "index not found.", None),
        },
        // Production answers an empty body whether or not the index still exists.
        ("DELETE", [id]) => {
            registry.remove(project, database, id, &configured);
            ok(json!({}))
        }
        _ => crate::rest::not_found_text(),
    }
}
