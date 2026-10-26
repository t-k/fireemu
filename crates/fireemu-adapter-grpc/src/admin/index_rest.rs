//! `projects/{p}/databases/{d}/collectionGroups/{g}/indexes[/{id}]`: create, list, get and
//! delete composite indexes, answered in production's shapes.

// Native build integration uses the transport's tonic status throughout the admitted callback.
#![allow(clippy::result_large_err)]

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, MAX_COMPOSITE_INDEXES,
};
use fireemu_core_firestore::text_index::{
    DefaultTextLanguage, LanguageOverridePolicy, TextIndexBuildError, TextIndexCatalog,
    TextIndexDefinition, TextIndexState, TextIndexType, TextIndexedField, TextMatchType,
};
use fireemu_core_types::ids::CollectionId;
use serde_json::{json, Value};

use super::indexes::{scope_name, with_implied_name, CreateRefusal, IndexState, RuntimeIndex};
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
    let Ok(collection_group) = CollectionId::try_new(group) else {
        return Err(error(
            tonic::Code::InvalidArgument,
            "Invalid collection group id.",
            None,
        ));
    };
    let definition = IndexDefinition {
        collection_group,
        query_scope: scope,
        fields,
    };
    // The shape rules are the index file's (`firestore.indexes.json`): the field and array
    // caps (UNRECORDED texts) and the recorded "not necessary" refusal of a single field.
    if let Err(shape) = definition
        .check_capacity()
        .and_then(|()| definition.check_necessary())
    {
        return Err(error(
            tonic::Code::InvalidArgument,
            &shape.to_string(),
            None,
        ));
    }
    Ok(definition)
}

/// `POST collectionGroups/{g}/indexes`: starts building an index.
fn create_index(
    state: &RestState,
    (project, database, group): (&str, &str, &str),
    body: &Value,
) -> RestResponse {
    let configured = state.local.configured_composites(project, database);
    let registry = state.local.admin().indexes();
    let now = state.local.admin_now();
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
    // The index file's indexes and the ones created here count together, checked where
    // the index is inserted. The code and text are UNRECORDED: the limit is the
    // documented 200 of a billing-disabled plan.
    match registry.create_within(
        project,
        database,
        definition,
        now,
        operation.clone(),
        Some((&configured, MAX_COMPOSITE_INDEXES)),
    ) {
        Err(CreateRefusal::Full) => error(
            tonic::Code::ResourceExhausted,
            "Maximum number of composite indexes for a database: 200",
            None,
        ),
        Err(CreateRefusal::Exists(existing)) => error(
            tonic::Code::AlreadyExists,
            &format!("index already exists with index ID = {existing}"),
            None,
        ),
        Ok(index) => {
            let name = format!("projects/{project}/databases/{database}/operations/{operation}");
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
    let enterprise =
        state.gateway.ctx.edition == fireemu_core_types::edition::FirestoreEdition::Enterprise;
    if enterprise
        && method == "POST"
        && rest.is_empty()
        && (body.get("searchIndexOptions").is_some()
            || body["fields"].as_array().is_some_and(|fields| {
                fields
                    .iter()
                    .any(|field| field.get("searchConfig").is_some())
            }))
    {
        return create_text_index(state, project, database, group, body)
            .unwrap_or_else(|status| crate::rest::error_response(&status));
    }
    let text = if enterprise {
        match text_route(state, project, database, group, method, rest) {
            Ok(Some(response)) if !rest.is_empty() => return response,
            Ok(response) => response,
            Err(status) => return crate::rest::error_response(&status),
        }
    } else {
        None
    };
    let configured = state.local.configured_composites(project, database);
    let registry = state.local.admin().indexes();
    let now = state.local.admin_now();
    match (method, rest) {
        ("POST", []) => create_index(state, (project, database, group), body),
        ("GET", []) => {
            let mut indexes: Vec<Value> = registry
                .view(project, database, &configured)
                .iter()
                .filter(|i| group == "-" || i.definition.collection_group.as_str() == group)
                .map(|i| index_json(project, database, i, registry.state(i, now)))
                .collect();
            if let Some(response) = &text {
                if let Some(text_indexes) = response.body["indexes"].as_array() {
                    indexes.extend(text_indexes.iter().cloned());
                }
            }
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

fn text_unverified(message: impl std::fmt::Display) -> tonic::Status {
    tonic::Status::unimplemented(format!("FS_TEXT_ADMIN_UNVERIFIED: {message}"))
}

fn text_definition(
    group: &str,
    id: String,
    body: &Value,
) -> Result<TextIndexDefinition, tonic::Status> {
    if body.as_object().is_none_or(|object| {
        object
            .keys()
            .any(|key| !matches!(key.as_str(), "queryScope" | "fields" | "searchIndexOptions"))
    }) || body["queryScope"] != "COLLECTION"
        || body["searchIndexOptions"].as_object().is_none_or(|object| {
            object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "textLanguage" | "textLanguageOverrideFieldPath"
                )
            })
        })
        || body["searchIndexOptions"]["textLanguage"] != "en"
    {
        return Err(text_unverified("text index request options"));
    }
    let fields = body["fields"]
        .as_array()
        .filter(|fields| !fields.is_empty())
        .ok_or_else(|| text_unverified("text index fields"))?;
    let fields = fields
        .iter()
        .map(|field| {
            if field.as_object().is_none_or(|object| object.len() != 2)
                || field["searchConfig"]
                    != json!({"textSpec":{"indexSpecs":[{"indexType":"TOKENIZED","matchType":"MATCH_GLOBALLY"}]}})
            {
                return Err(text_unverified("text index field configuration"));
            }
            let path = field["fieldPath"]
                .as_str()
                .ok_or_else(|| text_unverified("text field path"))?;
            Ok(TextIndexedField {
                path: FieldPath::parse(path).map_err(text_unverified)?,
                index_type: TextIndexType::Tokenized,
                match_type: TextMatchType::MatchGlobally,
            })
        })
        .collect::<Result<Vec<_>, tonic::Status>>()?;
    let override_path = match body["searchIndexOptions"].get("textLanguageOverrideFieldPath") {
        None => "language",
        Some(value) => value
            .as_str()
            .ok_or_else(|| text_unverified("text language override"))?,
    };
    Ok(TextIndexDefinition {
        id,
        collection_id: CollectionId::try_new(group).map_err(text_unverified)?,
        query_scope: IndexQueryScope::Collection,
        api_scope: "ANY_API".into(),
        fields,
        language: DefaultTextLanguage::Tag("en".into()),
        language_override: LanguageOverridePolicy::ExplicitField(
            FieldPath::parse(override_path).map_err(text_unverified)?,
        ),
        state: TextIndexState::Creating,
    })
}

fn text_index_name(project: &str, database: &str, definition: &TextIndexDefinition) -> String {
    format!(
        "projects/{project}/databases/{database}/collectionGroups/{}/indexes/{}",
        definition.collection_id.as_str(),
        definition.id
    )
}

fn text_index_json(
    project: &str,
    database: &str,
    definition: &TextIndexDefinition,
) -> Result<Value, tonic::Status> {
    let DefaultTextLanguage::Tag(_) = &definition.language else {
        return Err(text_unverified("default text language"));
    };
    let LanguageOverridePolicy::ExplicitField(_) = &definition.language_override else {
        return Err(text_unverified("text language override policy"));
    };
    Ok(text_index_view(project, database, definition))
}

/// The Admin view of a text definition. A definition from the index file or the control API
/// may lack the default language or the override path production always reports; the view
/// then leaves that option out (review S2: the default profile lists it instead of failing the
/// whole listing). [`text_index_json`] is the productionExact form, which refuses such views.
fn text_index_view(project: &str, database: &str, definition: &TextIndexDefinition) -> Value {
    let mut options = serde_json::Map::new();
    if let DefaultTextLanguage::Tag(language) = &definition.language {
        options.insert("textLanguage".into(), json!(language));
    }
    match &definition.language_override {
        LanguageOverridePolicy::ExplicitField(path) => {
            options.insert(
                "textLanguageOverrideFieldPath".into(),
                json!(path.canonical()),
            );
        }
        LanguageOverridePolicy::ImplicitLanguageField => {
            options.insert("textLanguageOverrideFieldPath".into(), json!("language"));
        }
        LanguageOverridePolicy::Disabled => {
            options.insert("textLanguageOverrideFieldPath".into(), json!(""));
        }
        LanguageOverridePolicy::BackendDefaultUnresolved => {}
    }
    json!({
        "name": text_index_name(project, database, definition), "queryScope": scope_name(definition.query_scope),
        "fields": definition.fields.iter().map(|field| json!({"fieldPath":field.path.canonical(),"searchConfig":{"textSpec":{"indexSpecs":[{"indexType":"TOKENIZED","matchType":"MATCH_GLOBALLY"}]}}})).collect::<Vec<_>>(),
        "state":definition.state.as_str(),"density":"SPARSE_ANY",
        "searchIndexOptions":options,
    })
}

/// Whether the attached text catalog follows productionExact.
fn production_exact(local: &crate::local::LocalBackend) -> Result<bool, tonic::Status> {
    Ok(local
        .text_search_configuration()?
        .is_some_and(|config| config.production_exact))
}

/// Document language tags production has recorded text search for (the `language-en` and
/// `language-ja` searches of the `fs-ent-text/v1/lexical` program).
const RECORDED_LANGUAGES: [&str; 2] = ["en", "ja"];

/// A non-string language value as the failed build's message names it.
fn language_value_text(value: &fireemu_core_firestore::value::Value) -> String {
    use fireemu_core_firestore::value::Value as V;
    match value {
        V::String(text) => text.clone(),
        V::Null => "null".into(),
        V::Boolean(flag) => flag.to_string(),
        V::Integer(number) => number.to_string(),
        V::Double(number) => number.to_string(),
        other => format!("{:?}", other.kind()),
    }
}

fn create_text_index(
    state: &RestState,
    project: &str,
    database: &str,
    group: &str,
    body: &Value,
) -> Result<RestResponse, tonic::Status> {
    let id = state.local.admin().indexes().reserve_id();
    let mut definition = text_definition(group, id, body)?;
    state.local.with_native_text_snapshot(project, database, |_, catalog| {
        if let Some((_, _, existing)) = catalog.entries().find(|(p,d,existing)| *p == project && *d == database
            && existing.collection_id == definition.collection_id && existing.query_scope == definition.query_scope
            && existing.fields == definition.fields && existing.language == definition.language && existing.language_override == definition.language_override) {
            state.local.check_native_text_epoch(catalog, |p,d,def| p == project && d == database && def.id == existing.id)?;
            return Ok(error(tonic::Code::AlreadyExists, &format!("index already exists with index ID = {}", existing.id), None));
        }
        while catalog.get(project, database, &definition.id).is_some() {
            definition.id = state.local.admin().indexes().reserve_id();
        }
        let now = state.local.admin_now();
        let operation = super::operations::reserve_id(state, project, database);
        let initial = json!({"name":format!("projects/{project}/databases/{database}/operations/{operation}"),"metadata":{
            "@type":INDEX_METADATA_TYPE_URL,"startTime":instant(now),"index":text_index_name(project,database,&definition),"state":"INITIALIZING"
        }});
        catalog.add(project, database, definition.clone()).map_err(text_unverified)?;
        let generation = catalog.build(project, database, &definition.id).ok_or_else(|| tonic::Status::internal("text build is missing"))?.generation;
        catalog.schedule_native(project,database,&definition.id,generation,fireemu_core_firestore::text_index::NativeTextBuildSchedule {operation:operation.clone(),start_time:now,monotonic_start_nanos:state.local.text_build_elapsed_nanos(),owner_epoch:std::sync::Arc::clone(state.local.text_build_epoch())}).map_err(text_unverified)?;
        state.local.admin().operations().record_text(project, database, &operation,
            super::operations::NativeTextBuild {index:definition.id.clone(),generation}, initial.clone());
        Ok(ok(initial))
    })
}

fn source_language<'a>(
    definition: &TextIndexDefinition,
    document: &'a fireemu_core_firestore::store::Document,
) -> Option<&'a fireemu_core_firestore::value::Value> {
    let LanguageOverridePolicy::ExplicitField(path) = &definition.language_override else {
        return None;
    };
    let mut segments = path.segments().iter();
    let mut value = document.fields.get(segments.next()?)?;
    for segment in segments {
        let fireemu_core_firestore::value::Value::Map(fields) = value else {
            return None;
        };
        value = fields.get(segment)?;
    }
    Some(value)
}

/// Optional observer scope; unsupported work in another collection must not block this one.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NativeTextSelection<'a> {
    pub collection: Option<&'a str>,
    pub index: Option<&'a str>,
    pub operation: Option<&'a str>,
    pub operation_targets: Option<&'a [(&'a str, &'a super::operations::NativeTextBuild)]>,
    /// The request names this one build (its index or its operation): only such a request
    /// answers a build fireemu cannot complete faithfully; others leave it pending (review S2).
    pub direct: bool,
}

/// Advances one database's native work while its admitted source snapshot and catalog are held.
/// Separate HTTP observations may straddle this transition; each terminal view remains immutable.
// Keep selected-source preparation and its single publication boundary together.
#[allow(clippy::too_many_lines)]
pub(crate) fn advance_text_builds(
    local: &crate::local::LocalBackend,
    project: &str,
    database: &str,
    db: &fireemu_core_firestore::store::FirestoreState,
    catalog: &mut TextIndexCatalog,
    selection: NativeTextSelection<'_>,
) -> Result<(), tonic::Status> {
    let targets: Vec<_> = catalog
        .entries()
        .filter(|(p, d, definition)| {
            *p == project
                && *d == database
                && definition.state == TextIndexState::Creating
                && selection
                    .collection
                    .is_none_or(|group| definition.collection_id.as_str() == group)
                && selection.index.is_none_or(|id| definition.id == id)
        })
        .filter_map(|(_, _, definition)| {
            catalog
                .build(project, database, &definition.id)
                .and_then(|build| {
                    build
                        .native
                        .clone()
                        .map(|schedule| (definition.clone(), build.generation, schedule))
                })
        })
        .filter(|(definition, generation, schedule)| {
            selection
                .operation
                .is_none_or(|id| schedule.operation == id)
                && selection.operation_targets.is_none_or(|targets| {
                    targets.iter().any(|(operation, target)| {
                        schedule.operation == *operation
                            && definition.id == target.index
                            && *generation == target.generation
                    })
                })
        })
        .collect();
    local.check_native_text_epoch(catalog, |p, d, def| {
        p == project && d == database && targets.iter().any(|(target, _, _)| target.id == def.id)
    })?;
    // Review S5: a search or listing with nothing to complete copies nothing.
    if targets.is_empty() {
        return Ok(());
    }
    let production_exact = production_exact(local)?;
    let mut trial: Option<TextIndexCatalog> = None;
    let mut completions = Vec::new();
    for (definition, generation, schedule) in targets {
        let elapsed = std::time::Duration::from_nanos(
            u64::try_from(
                local
                    .text_build_elapsed_nanos()
                    .saturating_sub(schedule.monotonic_start_nanos),
            )
            .unwrap_or(u64::MAX),
        );
        if !local
            .admin()
            .indexes()
            .build_due(elapsed, schedule.start_time, local.admin_now())
        {
            continue;
        }
        let target = super::operations::NativeTextBuild {
            index: definition.id.clone(),
            generation,
        };
        let documents: Vec<_> = db
            .documents()
            .into_iter()
            .filter(|document| document.path.collection_id() == &definition.collection_id)
            .collect();
        // Review S2: a valid tag builds language-neutral in the default profile; productionExact
        // completes only languages production has recorded, and a malformed tag fails the build
        // below as production recorded.
        let unverified = documents.iter().any(|document| {
            source_language(&definition, document).is_some_and(|language| match language {
                fireemu_core_firestore::value::Value::String(tag) => {
                    production_exact
                        && fireemu_core_firestore::text_index::is_language_tag(tag)
                        && !RECORDED_LANGUAGES.contains(&tag.as_str())
                }
                _ => production_exact,
            })
        });
        if unverified {
            if selection.direct {
                return Err(text_unverified("source language value"));
            }
            continue;
        }
        let trial = trial.get_or_insert_with(|| catalog.clone());
        let mut ready_definition = definition.clone();
        ready_definition.state = TextIndexState::Ready;
        let mut response = text_index_json(project, database, &ready_definition)?;
        response["@type"] = json!(INDEX_TYPE_URL);
        let end = std::cmp::max(
            local.admin_now(),
            fireemu_core_types::time::LogicalInstant::from_nanos(
                schedule.start_time.as_nanos() + 1_000_000,
            ),
        );
        let mut terminal = json!({"name":format!("projects/{project}/databases/{database}/operations/{}",schedule.operation),"metadata":{"@type":INDEX_METADATA_TYPE_URL,"startTime":instant(schedule.start_time),"index":text_index_name(project,database,&definition),"state":"INITIALIZING"}});
        terminal["done"] = json!(true);
        terminal["metadata"]["endTime"] = instant(end);
        match trial.lifecycle(
            project,
            database,
            &target.index,
            "completeBackfill",
            Some(target.generation),
            10_000,
            None,
            documents.clone(),
            fireemu_adapter_support::lexical::tokenize_index,
        ) {
            Ok(()) => {
                terminal["metadata"]["state"] = json!("SUCCESSFUL");
                terminal["metadata"]["progressDocuments"] = if documents.is_empty() {
                    json!({})
                } else {
                    json!({"estimatedWork":documents.len().to_string(),"completedWork":documents.len().to_string()})
                };
                terminal["response"] = response;
            }
            Err(TextIndexBuildError::InvalidSource(
                fireemu_core_firestore::text_index::TextIndexSourceError::Search(
                    fireemu_core_firestore::text_search::SearchError::InvalidLanguageOverride(path),
                ),
            )) => {
                let language = documents
                    .iter()
                    .find(|document| document.path.resource_name() == path)
                    .and_then(|document| source_language(&definition, document));
                let Some(language) = language else {
                    return Err(text_unverified("unresolved source language error"));
                };
                if let fireemu_core_firestore::value::Value::String(value) = language {
                    if fireemu_core_firestore::text_index::is_language_tag(value) {
                        return Err(text_unverified("unrecorded text language error"));
                    }
                }
                // A non-string value reaches here only in the default profile: a development
                // approximation of the recorded malformed-tag failure.
                let message = format!("Invalid text language: {}", language_value_text(language));
                trial
                    .lifecycle(
                        project,
                        database,
                        &target.index,
                        "failBuild",
                        Some(target.generation),
                        1,
                        Some(&message),
                        Vec::new(),
                        fireemu_adapter_support::lexical::tokenize_index,
                    )
                    .map_err(text_unverified)?;
                terminal["metadata"]["state"] = json!("FAILED");
                terminal["metadata"]["progressDocuments"] = json!({});
                terminal["error"] = json!({"code":3,"message":message});
            }
            Err(error) => return Err(text_unverified(error)),
        }
        completions.push((schedule.operation, target, terminal));
    }
    local.admin().operations().finish_text(
        project,
        database,
        &completions,
        selection.operation_targets,
        || {
            if let Some(trial) = trial {
                *catalog = trial;
            }
        },
    )
}

fn text_route(
    state: &RestState,
    project: &str,
    database: &str,
    group: &str,
    method: &str,
    rest: &[&str],
) -> Result<Option<RestResponse>, tonic::Status> {
    if state.local.text_search_configuration()?.is_none() {
        return Ok(None);
    }
    let list = method == "GET" && rest.is_empty();
    if method == "GET" && !list {
        state.local.advance_native_text_builds(
            project,
            database,
            NativeTextSelection {
                collection: (group != "-").then_some(group),
                index: rest.first().copied(),
                operation: None,
                direct: true,
                ..Default::default()
            },
        )?;
    }
    state
        .local
        .with_native_text_snapshot(project, database, |db, catalog| {
            let scoped = |definition: &&TextIndexDefinition| {
                group == "-" || definition.collection_id.as_str() == group
            };
            state
                .local
                .check_native_text_epoch(catalog, |p, d, definition| {
                    p == project
                        && d == database
                        && (list || group == "-" || definition.collection_id.as_str() == group)
                        && rest.first().is_none_or(|id| definition.id == *id)
                })?;
            match (method, rest) {
                ("GET", []) => {
                    state.local.advance_text_builds_at_snapshot(
                        project,
                        database,
                        db,
                        catalog,
                        NativeTextSelection::default(),
                    )?;
                    // Review S2: one text index never fails the listing. productionExact leaves
                    // out the definitions it cannot render as production would.
                    let exact = production_exact(&state.local)?;
                    let indexes = catalog
                        .entries()
                        .filter(|(p, d, _)| *p == project && *d == database)
                        .filter_map(|(_, _, definition)| {
                            if exact {
                                text_index_json(project, database, definition).ok()
                            } else {
                                Some(text_index_view(project, database, definition))
                            }
                        })
                        .collect::<Vec<_>>();
                    Ok(Some(ok(json!({"indexes":indexes}))))
                }
                ("GET", [id]) => catalog.get(project, database, id).filter(scoped).map_or(
                    Ok(None),
                    |definition| {
                        if production_exact(&state.local)? {
                            text_index_json(project, database, definition)
                                .map(|value| Some(ok(value)))
                        } else {
                            Ok(Some(ok(text_index_view(project, database, definition))))
                        }
                    },
                ),
                ("DELETE", [id]) => {
                    if catalog
                        .get(project, database, id)
                        .is_some_and(|definition| {
                            group == "-" || definition.collection_id.as_str() == group
                        })
                    {
                        catalog.remove(project, database, id);
                        return Ok(Some(ok(json!({}))));
                    }
                    Ok(None)
                }
                _ => Ok(None),
            }
        })
}
