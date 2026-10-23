//! Snapshot-derived local lexical search shared by REST and gRPC.
#![allow(clippy::result_large_err)]
use crate::{decode::Parent, local::LocalBackend, pipeline::CompiledExecution, rules::ReadGuard};
use fireemu_core_firestore::{
    field_path::FieldPath,
    index::IndexQueryScope,
    pipeline_exec::{self, Unrecorded},
    text_index::{TextIndexCatalog, TextIndexState},
    text_search::{SearchDocument, SearchIndex, SearchOptions, SearchOrder, SearchQuery},
};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tonic::Status;

/// One startup-bound catalog and policy shared by all transports.
#[derive(Clone)]
pub(crate) struct Configuration {
    pub catalog: Arc<Mutex<TextIndexCatalog>>,
    pub production_exact: bool,
    pub warned: Arc<AtomicBool>,
}
/// A search immediately following collection input. The remaining stages use the existing cursor.
#[derive(Debug, Clone)]
pub struct SearchPlan {
    query: SearchQuery,
    options: SearchOptions,
    score_fields: Vec<String>,
}
fn invalid(message: &str) -> Status {
    Status::invalid_argument(format!("FS_TEXT_QUERY: {message}"))
}
fn unsupported(message: &str) -> Status {
    Status::unimplemented(format!("FS_TEXT_UNSUPPORTED: {message}"))
}
fn is_score(value: &pb::Value) -> bool {
    matches!(&value.value_type, Some(pb::value::ValueType::FunctionValue(f)) if f.name == "score" && f.args.is_empty() && f.options.is_empty())
}
fn count(stage: &pb::pipeline::Stage, key: &str) -> Result<Option<usize>, Status> {
    match stage.options.get(key).map(|v| &v.value_type) {
        None => Ok(None),
        Some(Some(pb::value::ValueType::IntegerValue(n))) if *n >= 0 => usize::try_from(*n)
            .map(Some)
            .map_err(|_| invalid("count exceeds local address space")),
        _ => Err(invalid(
            "offset, limit and retrieval_depth must be nonnegative integers",
        )),
    }
}
/// Decode the SDK's option-based search wire format without registering search-only functions globally.
pub fn decode(stage: &pb::pipeline::Stage) -> Result<SearchPlan, Status> {
    if !stage.args.is_empty() {
        return Err(invalid("search has no positional arguments"));
    }
    for key in stage.options.keys() {
        if !matches!(
            key.as_str(),
            "query"
                | "offset"
                | "limit"
                | "retrieval_depth"
                | "sort"
                | "add_fields"
                | "language_code"
                | "query_enhancement"
        ) {
            return Err(unsupported(&format!("search option {key:?}")));
        }
    }
    let value = stage
        .options
        .get("query")
        .ok_or_else(|| invalid("search requires query"))?;
    let Some(pb::value::ValueType::FunctionValue(function)) = &value.value_type else {
        return Err(unsupported("query must be document_matches(string)"));
    };
    if function.name != "document_matches"
        || function.args.len() != 1
        || !function.options.is_empty()
    {
        return Err(unsupported(
            "query must be document_matches(string) without function options",
        ));
    }
    let Some(pb::value::ValueType::StringValue(text)) = &function.args[0].value_type else {
        return Err(invalid("document_matches requires a string"));
    };
    let query = SearchQuery::parse(text, fireemu_adapter_support::lexical::tokenize)
        .map_err(|e| invalid(&e.to_string()))?;
    let mut options = SearchOptions {
        offset: count(stage, "offset")?.unwrap_or(0),
        limit: count(stage, "limit")?,
        retrieval_depth: count(stage, "retrieval_depth")?,
        ..Default::default()
    };
    if options.retrieval_depth == Some(0) {
        return Err(Status::invalid_argument(
            "search(...): 'retrievalDepth' must be at least 1.",
        ));
    }
    if let Some(value) = stage.options.get("sort") {
        let Some(pb::value::ValueType::ArrayValue(array)) = &value.value_type else {
            return Err(invalid("sort must be an ordering array"));
        };
        let [ordering] = array.values.as_slice() else {
            return Err(unsupported(
                "only one descending score ordering is supported",
            ));
        };
        let Some(pb::value::ValueType::MapValue(map)) = &ordering.value_type else {
            return Err(invalid("sort entry must be an ordering map"));
        };
        if map.fields.len() == 2
            && map.fields.get("expression").is_some_and(is_score)
            && matches!(map.fields.get("direction").and_then(|v|v.value_type.as_ref()),Some(pb::value::ValueType::StringValue(s)) if s == "ascending" || s == "ASCENDING")
        {
            return Err(Status::invalid_argument("search(...) with a document_matches query only supports sorting by score() in descending order."));
        }
        if map.fields.len() != 2
            || !map.fields.get("expression").is_some_and(is_score)
            || !matches!(map.fields.get("direction").and_then(|v|v.value_type.as_ref()),Some(pb::value::ValueType::StringValue(s)) if s == "descending" || s == "DESCENDING")
        {
            return Err(unsupported("only score().descending() is supported"));
        }
        options.order = SearchOrder::ScoreDescending;
    }
    let score_fields = decode_score_fields(stage)?;
    validate_language_option(stage)?;
    if let Some(value) = stage.options.get("query_enhancement") {
        if !matches!(&value.value_type,Some(pb::value::ValueType::StringValue(s)) if s == "disabled")
        {
            return Err(unsupported(
                "query enhancement is not implemented; use disabled",
            ));
        }
    }
    Ok(SearchPlan {
        query,
        options,
        score_fields,
    })
}

fn validate_language_option(stage: &pb::pipeline::Stage) -> Result<(), Status> {
    if let Some(value) = stage.options.get("language_code") {
        let Some(pb::value::ValueType::StringValue(language)) = &value.value_type else {
            return Err(invalid("language_code must be a language tag"));
        };
        if language == "auto" || !fireemu_core_firestore::text_index::is_language_tag(language) {
            return Err(Status::invalid_argument(format!(
                "Unsupported language_code: {language}"
            )));
        }
    }
    Ok(())
}

fn decode_score_fields(stage: &pb::pipeline::Stage) -> Result<Vec<String>, Status> {
    let mut score_fields = Vec::new();
    if let Some(value) = stage.options.get("add_fields") {
        let Some(pb::value::ValueType::MapValue(map)) = &value.value_type else {
            return Err(invalid("add_fields must be an alias map"));
        };
        if map.fields.is_empty() {
            return Err(invalid("add_fields must not be empty"));
        }
        for (alias, value) in &map.fields {
            let field = FieldPath::parse(alias).map_err(|_| invalid("invalid score alias"))?;
            if field.segments().len() != 1 || field.canonical() != *alias || alias.starts_with("__")
            {
                return Err(unsupported(
                    "score aliases must be simple nonreserved top-level fields",
                ));
            }
            if !is_score(value) {
                return Err(unsupported("add_fields supports only score()"));
            }
            score_fields.push(alias.clone());
        }
    }
    Ok(score_fields)
}

/// Execute against one admitted document snapshot. The read guard captures the catalog
/// while the database is locked, so reset cannot mix epochs and catalog mutations cannot
/// mix definitions within the result. No catalog lock is held while taking admission.
pub(crate) fn execute(
    local: &LocalBackend,
    parent: &Parent,
    compiled: CompiledExecution,
    guard: ReadGuard<'_>,
    unrecorded: Unrecorded,
) -> Result<Vec<pb::ExecutePipelineResponse>, Status> {
    execute_at_snapshot(local, parent, compiled, guard, unrecorded, || {})
}

fn execute_at_snapshot(
    local: &LocalBackend,
    parent: &Parent,
    compiled: CompiledExecution,
    guard: ReadGuard<'_>,
    unrecorded: Unrecorded,
    after_snapshot: impl FnOnce(),
) -> Result<Vec<pb::ExecutePipelineResponse>, Status> {
    let plan = compiled
        .search
        .as_ref()
        .ok_or_else(|| Status::internal("missing search plan"))?;
    let (config, collection) = configuration(local, &compiled)?;
    let captured = Mutex::new(None);
    let capture = |db: &fireemu_core_firestore::store::FirestoreState,
                   version: Option<fireemu_core_firestore::store::CommitVersion>,
                   check: crate::rules::ReadCheck<'_>| {
        guard(db, version, check)?;
        let catalog = config
            .catalog
            .lock()
            .map_err(|_| Status::internal("text index catalog is poisoned"))?;
        let definitions = catalog
            .entries()
            .filter(|(p, d, def)| {
                *p == parent.project.as_str()
                    && *d == parent.database.as_str()
                    && def.collection_id.as_str() == collection
                    && def.query_scope == IndexQueryScope::Collection
                    && def.api_scope == "ANY_API"
                    && def.state == TextIndexState::Ready
            })
            .map(|(_, _, definition)| definition.clone())
            .collect::<Vec<_>>();
        if definitions.is_empty() {
            return Err(Status::failed_precondition(
                "FS_TEXT_INDEX: a READY collection text index is required",
            ));
        }
        *captured
            .lock()
            .map_err(|_| Status::internal("text index capture is poisoned"))? = Some(definitions);
        Ok(())
    };
    let barrier = local.barrier();
    let epoch = barrier.epoch();
    let (responses, _) = local.run_query(&compiled.input, &capture)?;
    let definitions = captured
        .into_inner()
        .map_err(|_| Status::internal("text index capture is poisoned"))?
        .ok_or_else(|| Status::internal("text index catalog was not captured"))?;
    after_snapshot();
    let execution_time = responses.iter().find_map(|response| response.read_time);
    let (originals, hits) = search_snapshot(&responses, definitions, plan)?;
    if !config.warned.swap(true, Ordering::Relaxed) {
        eprintln!("[firestore] text search uses fireemu-lexical-v1: approximate BM25, language-neutral tokenization; no stemming, synonyms, typo correction or language autodetection");
    }
    let whole = pipeline_exec::referenced_fields(&compiled.stages).is_none();
    let mut cursor = pipeline_exec::Cursor::new_in(compiled.stages, unrecorded);
    let mut results = Vec::new();
    for hit in hits {
        if cursor.is_exhausted() {
            break;
        }
        let document = originals
            .get(&hit.path)
            .ok_or_else(|| Status::internal("text hit has no source document"))?;
        let mut row = crate::pipeline::document_row(document)?;
        for alias in &plan.score_fields {
            row.fields.insert(
                alias.clone(),
                fireemu_core_firestore::value::Value::Double(hit.score),
            );
        }
        if let Some(fields) = cursor
            .push(row)
            .map_err(|error| crate::pipeline::eval_status(&error))?
        {
            let result = if whole {
                let mut result = document.clone();
                result.fields = fields
                    .iter()
                    .map(|(name, value)| (name.clone(), crate::encode::encode_value(value)))
                    .collect();
                result
            } else {
                crate::pipeline::result_document(&fields)
            };
            results.push(result);
        }
    }
    let responses = pack_search_results(results, execution_time);
    if barrier.epoch() != epoch {
        return Err(Status::unavailable("session reset during text search"));
    }
    Ok(responses)
}

fn pack_search_results(
    documents: Vec<pb::Document>,
    execution_time: Option<prost_types::Timestamp>,
) -> Vec<pb::ExecutePipelineResponse> {
    // Keep small result sets together without growing one gRPC message with every hit.
    // A single document may exceed this target; it is never split across responses.
    const BATCH_BYTES: usize = 1_048_576;
    let mut responses = Vec::new();
    let mut batch = pb::ExecutePipelineResponse {
        execution_time,
        ..Default::default()
    };
    let mut batch_bytes = prost::Message::encoded_len(&batch);
    for document in documents {
        // One tag plus at most ten bytes for the length-delimited document prefix.
        let document_bytes = prost::Message::encoded_len(&document).saturating_add(11);
        if !batch.results.is_empty() && batch_bytes.saturating_add(document_bytes) > BATCH_BYTES {
            responses.push(batch);
            batch = pb::ExecutePipelineResponse {
                execution_time,
                ..Default::default()
            };
            batch_bytes = prost::Message::encoded_len(&batch);
        }
        batch_bytes = batch_bytes.saturating_add(document_bytes);
        batch.results.push(document);
    }
    responses.push(batch);
    responses
}

fn search_snapshot(
    responses: &[pb::RunQueryResponse],
    definitions: Vec<fireemu_core_firestore::text_index::TextIndexDefinition>,
    plan: &SearchPlan,
) -> Result<
    (
        BTreeMap<fireemu_core_firestore::path::DocumentPath, pb::Document>,
        Vec<fireemu_core_firestore::text_search::SearchHit>,
    ),
    Status,
> {
    let mut originals = BTreeMap::new();
    let mut documents = Vec::new();
    for document in responses
        .iter()
        .filter_map(|response| response.document.as_ref())
    {
        let row = crate::pipeline::document_row(document)?;
        documents.push(SearchDocument {
            path: row.path.clone(),
            fields: row.fields,
            created_at: document.create_time.as_ref().map_or(
                fireemu_core_types::time::LogicalInstant::UNIX_EPOCH,
                crate::encode::decode_instant,
            ),
        });
        originals.insert(row.path, document.clone());
    }
    let mut chosen = None;
    let mut last_error = None;
    for definition in definitions {
        if !plan.query.is_covered_by(&definition) {
            continue;
        }
        let index = SearchIndex::build(
            &definition,
            &documents,
            fireemu_adapter_support::lexical::tokenize,
        )
        .map_err(|error| invalid(&error.to_string()))?;
        match index.search(&plan.query, &plan.options) {
            Ok(hits) => {
                chosen = Some(hits);
                break;
            }
            Err(error @ fireemu_core_firestore::text_search::SearchError::UnknownField(_)) => {
                last_error = Some(error);
            }
            Err(error) => return Err(invalid(&error.to_string())),
        }
    }
    let hits = chosen.ok_or_else(|| {
        Status::failed_precondition(format!(
            "FS_TEXT_INDEX: no READY index covers the requested fields: {last_error:?}"
        ))
    })?;
    Ok((originals, hits))
}

fn configuration(
    local: &LocalBackend,
    compiled: &CompiledExecution,
) -> Result<(Configuration, String), Status> {
    let config = local.text_search_configuration()?.ok_or_else(|| {
        Status::failed_precondition("FS_TEXT_INDEX: no local text index catalog is attached")
    })?;
    if config.production_exact {
        return Err(Status::unimplemented("FS_TEXT_UNOBSERVED: lexical search and ranking have no recorded production equivalence; productionExact refuses execution"));
    }
    let collection = match &compiled.input.query_type {
        Some(pb::run_query_request::QueryType::StructuredQuery(query)) => query
            .from
            .first()
            .map(|selector| selector.collection_id.clone())
            .ok_or_else(|| invalid("missing collection"))?,
        _ => return Err(invalid("missing collection input")),
    };
    Ok((config, collection))
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::{gateway::Gateway, pipeline, rules::allow_all_reads};
    use fireemu_core_firestore::{
        index::{IndexSet, IndexValidationPolicy, PlanningContext},
        text_index::{
            DefaultTextLanguage, LanguageOverridePolicy, TextIndexDefinition, TextIndexType,
            TextIndexedField, TextMatchType,
        },
    };
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_types::{
        edition::{FirestoreApiMode, FirestoreEdition},
        ids::CollectionId,
        time::LogicalInstant,
    };
    use serde_json::json;
    const DB: &str = "projects/demo-app/databases/(default)";

    fn fixture() -> (LocalBackend, Arc<Mutex<TextIndexCatalog>>, Parent) {
        let local = LocalBackend::new(
            Gateway {
                enforce_limits: false,
                ctx: PlanningContext {
                    edition: FirestoreEdition::Enterprise,
                    api_mode: FirestoreApiMode::Native,
                    policy: IndexValidationPolicy::Emulator,
                },
                indexes: IndexSet::default(),
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            7,
        );
        let mut catalog = TextIndexCatalog::default();
        catalog
            .add(
                "demo-app",
                "(default)",
                TextIndexDefinition {
                    id: "text".into(),
                    collection_id: CollectionId::try_new("products").unwrap(),
                    query_scope: IndexQueryScope::Collection,
                    api_scope: "ANY_API".into(),
                    fields: vec![TextIndexedField {
                        path: FieldPath::parse("title").unwrap(),
                        index_type: TextIndexType::Tokenized,
                        match_type: TextMatchType::MatchGlobally,
                    }],
                    language: DefaultTextLanguage::Tag("en".into()),
                    language_override: LanguageOverridePolicy::Disabled,
                    state: TextIndexState::Ready,
                },
            )
            .unwrap();
        let catalog = Arc::new(Mutex::new(catalog));
        local.set_text_indexes(catalog.clone(), false).unwrap();
        seed(&local, "before", "after");
        (
            local,
            catalog,
            crate::decode::parse_parent(&format!("{DB}/documents")).unwrap(),
        )
    }
    fn seed(local: &LocalBackend, title: &str, body: &str) {
        seed_named(local, "a", title, body);
    }
    fn seed_named(local: &LocalBackend, name: &str, title: &str, body: &str) {
        local
            .commit(&pb::CommitRequest {
                database: DB.into(),
                writes: vec![pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{DB}/documents/products/{name}"),
                        fields: [("title", title), ("body", body)]
                            .into_iter()
                            .map(|(key, text)| {
                                (
                                    key.into(),
                                    pb::Value {
                                        value_type: Some(pb::value::ValueType::StringValue(
                                            text.into(),
                                        )),
                                    },
                                )
                            })
                            .collect(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
    }
    fn compiled(parent: &Parent) -> CompiledExecution {
        let request = crate::rest::pipeline_json::request_from_json(DB, &json!({"structuredPipeline":{"pipeline":{"stages":[
            {"name":"collection","args":[{"referenceValue":"/products"}]},
            {"name":"search","options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":"before"}]}}}}
        ]}}})).unwrap();
        pipeline::compile_pipeline(&request, parent, Unrecorded::OfficialEmulator).unwrap()
    }
    #[test]
    fn catalog_replacement_and_write_after_capture_cannot_mix_with_the_frozen_source() {
        let (local, catalog, parent) = fixture();
        let result = execute_at_snapshot(
            &local,
            &parent,
            compiled(&parent),
            &allow_all_reads,
            Unrecorded::OfficialEmulator,
            || {
                let mut catalog = catalog.lock().unwrap();
                let mut next = catalog
                    .get("demo-app", "(default)", "text")
                    .unwrap()
                    .clone();
                next.fields[0].path = FieldPath::parse("body").unwrap();
                catalog.remove("demo-app", "(default)", "text");
                catalog.add("demo-app", "(default)", next).unwrap();
                drop(catalog);
                seed(&local, "after", "before");
            },
        )
        .unwrap();
        assert_eq!(
            result[0].results[0].fields["title"].value_type,
            Some(pb::value::ValueType::StringValue("before".into()))
        );
        let next = execute(
            &local,
            &parent,
            compiled(&parent),
            &allow_all_reads,
            Unrecorded::OfficialEmulator,
        )
        .unwrap();
        assert_eq!(
            next[0].results[0].fields["title"].value_type,
            Some(pb::value::ValueType::StringValue("after".into()))
        );
    }
    #[test]
    fn production_option_refusals_match_recorded_rest_and_grpc_contracts() {
        let requests: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/fs-ent-text-refusal-requests.json"
        ))
        .unwrap();
        let production: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/fs-ent-text-production.json"
        ))
        .unwrap();
        let parent = crate::decode::parse_parent(&format!("{DB}/documents")).unwrap();
        let mut checked = 0;
        for program in requests["programs"].as_array().unwrap() {
            for step in program["steps"].as_array().unwrap() {
                let body = &step["body"];
                let request = crate::rest::pipeline_json::request_from_json(DB, body).unwrap();
                let Err(error) = pipeline::compile_pipeline(&request, &parent, Unrecorded::Refuse)
                else {
                    panic!("production refused {}", step["id"]);
                };
                let grpc = step["transport"] == "grpc";
                let shape = if grpc {
                    crate::pipeline_shape::shape_of_request(&request)
                } else {
                    let (_, order) =
                        crate::rest::json_syntax::parse_with_key_order(body.to_string().as_bytes())
                            .unwrap();
                    crate::pipeline_shape::shape_of_json(body, &order)
                };
                let actual =
                    crate::pipeline_shape::RefusalGate::Recorded(shape, DB.into()).answer(error);
                let expected = &production["programs"][program["id"].as_str().unwrap()]["steps"]
                    [step["id"].as_str().unwrap()];
                let message = if grpc {
                    expected["message"].as_str().unwrap()
                } else {
                    expected["body"][0]["error"]["message"].as_str().unwrap()
                };
                assert_eq!(
                    actual.code(),
                    tonic::Code::InvalidArgument,
                    "{}",
                    step["id"]
                );
                assert_eq!(actual.message(), message, "{}", step["id"]);
                checked += 1;
            }
        }
        assert_eq!(checked, 8);
    }

    #[test]
    fn production_search_batches_all_hits_in_one_response() {
        let (local, _, parent) = fixture();
        seed_named(&local, "b", "before", "after");
        let responses = execute(
            &local,
            &parent,
            compiled(&parent),
            &allow_all_reads,
            Unrecorded::OfficialEmulator,
        )
        .unwrap();
        // Both production REST and gRPC recordings return these small hit sets in one batch.
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].results.len(), 2);
        assert!(responses[0].execution_time.is_some());
    }

    #[test]
    fn search_batches_split_large_documents_without_losing_hits() {
        let (local, _, parent) = fixture();
        let body = "x".repeat(600_000);
        seed_named(&local, "a", "before", &body);
        seed_named(&local, "b", "before", &body);
        let responses = execute(
            &local,
            &parent,
            compiled(&parent),
            &allow_all_reads,
            Unrecorded::OfficialEmulator,
        )
        .unwrap();
        assert_eq!(responses.len(), 2);
        assert_eq!(
            responses
                .iter()
                .map(|response| response.results.len())
                .sum::<usize>(),
            2
        );
        assert!(responses
            .iter()
            .all(|response| prost::Message::encoded_len(response) <= 1_048_576));
        let names: Vec<_> = responses
            .iter()
            .flat_map(|response| &response.results)
            .map(|document| document.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                format!("{DB}/documents/products/b"),
                format!("{DB}/documents/products/a")
            ]
        );
    }

    #[test]
    fn reset_after_capture_refuses_the_previous_epoch_instead_of_returning_stale_results() {
        let (local, _, parent) = fixture();
        let error = execute_at_snapshot(
            &local,
            &parent,
            compiled(&parent),
            &allow_all_reads,
            Unrecorded::OfficialEmulator,
            || {
                let barrier = local.barrier();
                let _exclusive = barrier.exclusive();
                local.reset();
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(error.message().contains("reset"));
    }
}
