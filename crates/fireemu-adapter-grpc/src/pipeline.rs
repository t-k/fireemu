//! `ExecutePipeline` decoding for the strict validator (`FS-PIPE-RPC-1`): the request's
//! database, consistency selector and options are checked, the wire stages become
//! [`StageSpec`]s with typed arguments that the core canonicalizes. The finite latest-read
//! collection/where(equal)/select/offset/limit subset executes locally through the core
//! pipeline executor ([`compile_pipeline`]); other semantics are refused. The older lowering
//! to an equivalent `RunQuery` ([`compile_supported`]) stays as the differential baseline.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use crate::rest::json_syntax::KeyOrder;
use fireemu_core_firestore::field_path::{FieldPath, FieldPathError};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::pipeline::{canonicalize, Arg, PipelineAst, PipelineError, StageSpec};
use fireemu_core_firestore::pipeline_exec::{
    self, Arity, Expr, ExprError, Placement, Stage, Unrecorded,
};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use tonic::Status;

use crate::decode::Parent;

/// Option keys a `StructuredPipeline` may carry.
const PIPELINE_OPTIONS: &[&str] = &["index_mode"];

/// Decodes and canonicalizes the request's pipeline. Errors carry the `FS_PIPE_*` code in
/// the `fireemu-code` metadata like the gateway's rejections. The stage registry's refusals
/// (a stage's argument count, argument shape, options, input position) are fireemu's own
/// texts, which no production row holds, so under strict (`Unrecorded::Refuse`) they are
/// `UNIMPLEMENTED`; the emulator profile keeps the texts.
#[allow(clippy::too_many_lines)]
pub fn validate_pipeline(
    req: &pb::ExecutePipelineRequest,
    unrecorded: Unrecorded,
) -> Result<PipelineAst, Status> {
    if req.database.is_empty() {
        return Err(with_code(
            Status::invalid_argument("ExecutePipeline requires a database"),
            "FS_PIPE_DECODE",
        ));
    }
    let segments: Vec<&str> = req.database.split('/').collect();
    let database_ok = match segments.as_slice() {
        ["projects", p, "databases", d] => {
            fireemu_core_types::ids::ProjectId::try_new((*p).to_owned()).is_ok()
                && fireemu_core_types::ids::DatabaseId::try_new((*d).to_owned()).is_ok()
        }
        _ => false,
    };
    if !database_ok {
        return Err(with_code(
            Status::invalid_argument(format!(
                "database {:?} must be projects/{{project}}/databases/{{database}}",
                req.database
            )),
            "FS_PIPE_INVALID",
        ));
    }
    match &req.consistency_selector {
        Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(t)) if t.is_empty() => {
            return Err(with_code(
                Status::invalid_argument("transaction must not be empty"),
                "FS_PIPE_INVALID",
            ));
        }
        Some(
            pb::execute_pipeline_request::ConsistencySelector::Transaction(_)
            | pb::execute_pipeline_request::ConsistencySelector::NewTransaction(_),
        ) => {}
        _ if req.auto_commit_transaction => {
            return Err(with_code(
                Status::invalid_argument(
                    "auto_commit_transaction requires a transaction or new_transaction consistency selector",
                ),
                "FS_PIPE_INVALID",
            ));
        }
        _ => {}
    }
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &req.pipeline_type
    else {
        return Err(with_code(
            Status::invalid_argument("ExecutePipeline requires a structured_pipeline"),
            "FS_PIPE_DECODE",
        ));
    };
    for (key, value) in &structured.options {
        let valid = PIPELINE_OPTIONS.contains(&key.as_str())
            && matches!(value.value_type, Some(pb::value::ValueType::StringValue(_)));
        if !valid {
            return Err(with_code(
                Status::invalid_argument(format!(
                    "pipeline option {key:?} is not one of {} (a string)",
                    PIPELINE_OPTIONS.join(", ")
                )),
                "FS_PIPE_INVALID",
            ));
        }
    }
    let Some(pipeline) = &structured.pipeline else {
        return Err(with_code(
            Status::invalid_argument("structured_pipeline requires a pipeline"),
            "FS_PIPE_DECODE",
        ));
    };
    let mut specs = Vec::with_capacity(pipeline.stages.len());
    for stage in &pipeline.stages {
        let args = stage
            .args
            .iter()
            .map(arg)
            .collect::<Result<Vec<Arg>, Status>>()?;
        let mut options = stage
            .options
            .iter()
            .map(|(k, v)| arg(v).map(|a| (k.clone(), a)))
            .collect::<Result<Vec<(String, Arg)>, Status>>()?;
        options.sort_by(|a, b| a.0.cmp(&b.0));
        specs.push(StageSpec {
            name: stage.name.clone(),
            args,
            options,
        });
    }
    // The collection stage's argument, as the official emulator 1.22.0 checks it before any
    // other stage (probed 2026-10-21, PX1d r7 review M2): a reference of the rooted form
    // `/c(/d/c)*`. Production recorded only that form, so strict answers any refusal here
    // through the shape gate (501).
    if let Some(first) = pipeline.stages.first().filter(|s| s.name == "collection") {
        if let [argument] = first.args.as_slice() {
            let refusal = match argument.value_type.as_ref() {
                Some(pb::value::ValueType::ReferenceValue(name)) => collection_name_error(name),
                other => Some(format!(
                    "Expected collection_name to be REFERENCE_VALUE, but was {}.",
                    value_type_name(other)
                )),
            };
            if let Some(text) = refusal {
                return Err(with_code(Status::invalid_argument(text), "FS_PIPE_INVALID"));
            }
        }
    }
    canonicalize(&specs).map_err(|e| {
        let (status, code) = match &e {
            PipelineError::UnknownStage(_) => (
                Status::unimplemented(e.to_string()),
                "FS_PIPE_UNSUPPORTED_STAGE",
            ),
            PipelineError::WriteStage(_) => {
                (Status::unimplemented(e.to_string()), "FS_PIPE_WRITE_0")
            }
            PipelineError::Empty
            | PipelineError::InputPosition(_)
            | PipelineError::Arity { .. }
            | PipelineError::Argument { .. }
            | PipelineError::Option { .. }
                if unrecorded == Unrecorded::Refuse =>
            {
                (
                    Status::unimplemented(format!("{e}; this text is not observed locally")),
                    "FS_PIPE_UNSUPPORTED_STAGE",
                )
            }
            // A stage fireemu does not run: its own argument texts would refuse what the
            // official emulator may answer (a `sort` ordering written as a map), so the stage is
            // refused as unsupported instead.
            PipelineError::Arity { stage, .. }
            | PipelineError::Argument { stage, .. }
            | PipelineError::Option { stage, .. }
                if !matches!(
                    stage.as_str(),
                    "collection"
                        | "search"
                        | "where"
                        | "select"
                        | "limit"
                        | "offset"
                        | "add_fields"
                        | "distinct"
                        | "aggregate"
                ) =>
            {
                (
                    Status::unimplemented(format!(
                        "pipeline stage {stage:?} is unsupported locally"
                    )),
                    "FS_PIPE_UNSUPPORTED_STAGE",
                )
            }
            PipelineError::Empty
            | PipelineError::InputPosition(_)
            | PipelineError::Arity { .. }
            | PipelineError::Argument { .. }
            | PipelineError::Option { .. } => {
                (Status::invalid_argument(e.to_string()), "FS_PIPE_INVALID")
            }
        };
        with_code(status, code)
    })
}

/// The compiled finite local Enterprise subset. The query is deliberately represented as the
/// ordinary `RunQuery` wire request so execution can reuse its snapshot and paging machinery.
#[derive(Debug, Clone)]
pub struct CompiledPipeline {
    /// The equivalent `RunQuery` request used by the streaming executor.
    pub query: pb::RunQueryRequest,
    /// Optional aliases applied to each streamed document.
    pub projection: Option<Vec<(String, FieldPath)>>,
    /// The original unsigned pipeline limit.
    pub limit: Option<u32>,
}

/// Applies the pipeline's per-document projection to a `RunQuery` response document.
pub fn project_document(
    mut document: pb::Document,
    projection: &Option<Vec<(String, FieldPath)>>,
) -> pb::Document {
    if let Some(aliases) = projection {
        let mut fields = std::collections::HashMap::new();
        for (alias, source) in aliases {
            if source.segments().len() == 1 {
                if let Some(value) = document.fields.get(&source.segments()[0]) {
                    fields.insert(alias.clone(), value.clone());
                }
            }
        }
        document.fields = fields;
    }
    document.name.clear();
    document.create_time = None;
    document.update_time = None;
    document
}

/// The collection input of a locally executable pipeline: its stages, the `RunQuery` parent
/// and the collection ID. Consistency selectors and pipeline options are refused.
fn collection_input<'a>(
    req: &'a pb::ExecutePipelineRequest,
    parent: &Parent,
) -> Result<(&'a pb::Pipeline, String, String), Status> {
    if req.consistency_selector.is_some() || req.auto_commit_transaction {
        return Err(Status::unimplemented(
            "pipeline consistency and auto-commit are unsupported locally",
        ));
    }
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &req.pipeline_type
    else {
        return Err(Status::invalid_argument("structured pipeline required"));
    };
    if !structured.options.is_empty() {
        return Err(Status::unimplemented(
            "pipeline options are unsupported locally",
        ));
    }
    let Some(pipeline) = &structured.pipeline else {
        return Err(Status::invalid_argument("pipeline required"));
    };
    let Some(collection) = pipeline.stages.first().filter(|s| s.name == "collection") else {
        return Err(Status::unimplemented(
            "pipeline input is unsupported locally",
        ));
    };
    let Some(
        pb::value::ValueType::ReferenceValue(reference)
        | pb::value::ValueType::StringValue(reference),
    ) = collection.args.first().and_then(|v| v.value_type.as_ref())
    else {
        return Err(Status::invalid_argument("collection path required"));
    };
    let segments: Vec<&str> = reference.trim_start_matches('/').split('/').collect();
    let collection_id = fireemu_core_types::ids::CollectionId::try_new(*segments.last().unwrap())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let parent_doc = if segments.len() == 1 {
        None
    } else {
        let relative = segments[..segments.len() - 1].join("/");
        Some(
            DocumentPath::parse(&parent.project, &parent.database, &relative)
                .map_err(|e| Status::invalid_argument(e.to_string()))?,
        )
    };
    let query_parent = parent_doc.as_ref().map_or_else(
        || {
            format!(
                "projects/{}/databases/{}/documents",
                parent.project, parent.database
            )
        },
        DocumentPath::resource_name,
    );
    Ok((pipeline, query_parent, collection_id.to_string()))
}

/// A `RunQuery` over one collection, in name order, with an optional filter, projection,
/// offset and limit.
fn collection_query(
    query_parent: String,
    collection_id: String,
    r#where: Option<pb::structured_query::Filter>,
    select: Option<pb::structured_query::Projection>,
    offset: i32,
    limit: Option<i32>,
) -> pb::RunQueryRequest {
    pb::RunQueryRequest {
        parent: query_parent,
        query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                select,
                from: vec![pb::structured_query::CollectionSelector {
                    collection_id,
                    all_descendants: false,
                }],
                r#where,
                order_by: Vec::new(),
                start_at: None,
                end_at: None,
                offset,
                limit,
                find_nearest: None,
            },
        )),
        consistency_selector: None,
        request_options: None,
        explain_options: None,
    }
}

/// Compiles the finite local Enterprise subset into the equivalent `RunQuery`: collection,
/// exact top-level field equality, top-level field-reference select aliases, offset and
/// limit. This lowering no longer serves requests; it is the baseline the executor is
/// compared against.
#[allow(clippy::too_many_lines)]
pub fn compile_supported(
    req: &pb::ExecutePipelineRequest,
    parent: &Parent,
) -> Result<CompiledPipeline, Status> {
    let (pipeline, query_parent, collection_id) = collection_input(req, parent)?;
    let mut projection: Option<Vec<(String, FieldPath)>> = None;
    let mut where_filter = None;
    let mut offset = 0;
    let mut limit = None;
    let mut last_rank = 0u8;
    let mut seen_select = false;
    let mut seen_offset = false;
    let mut seen_limit = false;
    for stage in pipeline.stages.iter().skip(1) {
        let rank = match stage.name.as_str() {
            "where" | "select" => 1,
            "offset" => 2,
            "limit" => 3,
            _ => 4,
        };
        if rank < last_rank {
            return Err(Status::unimplemented(
                "pipeline stages are out of supported order",
            ));
        }
        last_rank = rank;
        match stage.name.as_str() {
            "where" => {
                if where_filter.is_some() || seen_select || seen_limit {
                    return Err(Status::unimplemented("duplicate or misplaced where stage"));
                }
                where_filter = Some(decode_equal_filter(stage)?);
            }
            "limit" => {
                if seen_limit {
                    return Err(Status::unimplemented(
                        "duplicate limit stage is unsupported locally",
                    ));
                }
                seen_limit = true;
                let Some(pb::value::ValueType::IntegerValue(n)) =
                    stage.args.first().and_then(|v| v.value_type.as_ref())
                else {
                    return Err(Status::invalid_argument("limit must be an integer"));
                };
                let value = u32::try_from(*n)
                    .map_err(|_| Status::invalid_argument("limit is out of range"))?;
                limit = Some(value);
            }
            "offset" => {
                if seen_offset {
                    return Err(Status::unimplemented(
                        "duplicate offset stage is unsupported locally",
                    ));
                }
                seen_offset = true;
                let Some(pb::value::ValueType::IntegerValue(n)) =
                    stage.args.first().and_then(|v| v.value_type.as_ref())
                else {
                    return Err(Status::invalid_argument("offset must be an integer"));
                };
                offset = i32::try_from(*n).map_err(|_| {
                    Status::unimplemented("offset exceeds the finite local execution range")
                })?;
            }
            "select" => {
                if seen_select {
                    return Err(Status::unimplemented(
                        "duplicate select stage is unsupported locally",
                    ));
                }
                seen_select = true;
                let Some(pb::value::ValueType::MapValue(map)) =
                    stage.args.first().and_then(|v| v.value_type.as_ref())
                else {
                    return Err(Status::invalid_argument("select requires an alias map"));
                };
                let mut aliases = Vec::new();
                let mut entries: Vec<_> = map.fields.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                for (alias, value) in entries {
                    let Some(pb::value::ValueType::FieldReferenceValue(field)) =
                        value.value_type.as_ref()
                    else {
                        return Err(Status::unimplemented(
                            "select expressions are unsupported locally",
                        ));
                    };
                    aliases.push((
                        alias.clone(),
                        FieldPath::parse(field)
                            .map_err(|e| Status::invalid_argument(e.to_string()))?,
                    ));
                    if aliases.last().unwrap().1.segments().len() != 1 {
                        return Err(Status::unimplemented(
                            "nested select field references are unsupported locally",
                        ));
                    }
                    if aliases.last().unwrap().1.is_document_name() {
                        return Err(Status::unimplemented(
                            "__name__ select field references are unsupported locally",
                        ));
                    }
                }
                if aliases.is_empty() {
                    return Err(Status::invalid_argument(
                        "select requires a non-empty alias map",
                    ));
                }
                projection = Some(aliases);
            }
            other => {
                return Err(Status::unimplemented(format!(
                    "pipeline stage {other:?} is unsupported locally"
                )))
            }
        }
    }
    let limit_i32 = limit.and_then(|value| i32::try_from(value).ok());
    let select = projection
        .as_ref()
        .map(|aliases| pb::structured_query::Projection {
            fields: aliases
                .iter()
                .map(|(_, field)| pb::structured_query::FieldReference {
                    field_path: field.canonical(),
                })
                .collect(),
        });
    Ok(CompiledPipeline {
        query: collection_query(
            query_parent,
            collection_id,
            where_filter,
            select,
            offset,
            limit_i32,
        ),
        projection,
        limit,
    })
}

/// A pipeline compiled for the core executor.
#[derive(Debug, Clone)]
pub struct CompiledExecution {
    /// The input: a name-ordered scan of the collection (projected to the fields the stages
    /// read once a select narrows the rows), read through the `RunQuery` stream so that every
    /// page reads the same snapshot.
    pub input: pb::RunQueryRequest,
    /// The stages the executor runs over the input rows.
    pub stages: Vec<Stage>,
    /// Whether the select kept `__name__` as itself, so that each result carries the document
    /// name next to the selected fields (see [`selected_result`]).
    pub select_keeps_name: bool,
    /// A local lexical search before the existing streaming suffix.
    pub search: Option<crate::text_search::SearchPlan>,
}

/// Compiles the finite local Enterprise subset for the core executor: collection input,
/// then an optional single `where(comparison)`, an optional `select`, an optional `offset`
/// and an optional `limit`, in that order. Operands are field references (nested paths
/// included), literals and the table's functions. Every other stage, function or arrangement
/// is refused. `unrecorded` decides whether shapes with unrecorded production behavior
/// (a constant `where` condition, a literal holding expressions) are refused or answered as
/// the official emulator answers them.
pub fn compile_pipeline(
    req: &pb::ExecutePipelineRequest,
    parent: &Parent,
    unrecorded: Unrecorded,
) -> Result<CompiledExecution, Status> {
    compile_pipeline_in_order(req, parent, unrecorded, None)
}

/// [`compile_pipeline`] with the wire order of the request's maps, where the transport kept it
/// (a REST body): a `select` stage checks its aliases in that order, as the official emulator
/// does, so an alias inside another names the later one.
#[allow(clippy::too_many_lines)]
pub fn compile_pipeline_in_order(
    req: &pb::ExecutePipelineRequest,
    parent: &Parent,
    unrecorded: Unrecorded,
    order: Option<&KeyOrder>,
) -> Result<CompiledExecution, Status> {
    let (pipeline, query_parent, collection_id) = collection_input(req, parent)?;
    if unrecorded == Unrecorded::Refuse {
        let own = format!(
            "projects/{}/databases/{}/documents",
            parent.project.as_str(),
            parent.database.as_str()
        );
        if let Some(error) = pipeline
            .stages
            .iter()
            .skip(1)
            .flat_map(|stage| stage.args.iter().chain(stage.options.values()))
            .find_map(|value| reference_outside(value, &own))
        {
            return Err(error);
        }
    }
    let _wire = WireOrderScope::enter(order);
    let mut stages = Vec::new();
    let mut search = None;
    let mut last_rank = 0u8;
    let (mut seen_where, mut seen_select, mut seen_offset, mut seen_limit) =
        (false, false, false, false);
    let mut pushdown = None;
    // An empty alias map, which the official emulator answers only after every stage's own
    // argument checks.
    let mut deferred: Option<Status> = None;
    // Whether the pipeline was refused only for a stage fireemu does not run, after every part
    // of it passed a check production made (strict answers the deferred empty map only then).
    let mut validated_unrun = false;
    let mut select_keeps_name = false;
    let compiled = (|| -> Result<(), Status> {
        for (position, stage) in pipeline.stages.iter().enumerate().skip(1) {
            let rank = stage_rank(&stage.name);
            if rank < last_rank {
                return Err(Status::unimplemented(
                    "pipeline stages are out of supported order",
                ));
            }
            last_rank = rank;
            match stage.name.as_str() {
                "search" => {
                    if position != 1 || search.is_some() {
                        return Err(Status::unimplemented(
                            "search must occur once immediately after collection",
                        ));
                    }
                    search = Some(crate::text_search::decode(stage)?);
                }
                "where" => {
                    if seen_where || seen_select || seen_limit {
                        return Err(Status::unimplemented("duplicate or misplaced where stage"));
                    }
                    seen_where = true;
                    let (condition, filter) = decode_condition(stage, unrecorded)?;
                    pushdown = filter;
                    stages.push(Stage::Where(condition));
                }
                "select" => {
                    if seen_select {
                        return Err(Status::unimplemented(
                            "duplicate select stage is unsupported locally",
                        ));
                    }
                    seen_select = true;
                    if stage.args.first().is_some_and(is_empty_map) {
                        deferred.get_or_insert_with(|| {
                            Status::invalid_argument(
                                "The 'select(...)' stage requires at least one field.",
                            )
                        });
                        continue;
                    }
                    let aliases = select_wire_order(order, position);
                    match decode_select(stage, unrecorded, aliases) {
                        Ok((select, keeps_name)) => {
                            select_keeps_name = keeps_name;
                            stages.push(Stage::Select(select));
                        }
                        // A reserved alias and a `map(...)` key type are answered after a
                        // later stage's argument type, as an empty map is (the official
                        // emulator 1.22.0: `select {__x__: i}` then `limit("x")` gives the
                        // limit text).
                        Err(error)
                            if error.message().starts_with("Stage 'select': field name")
                                || error.message().starts_with("map key must be of type") =>
                        {
                            deferred.get_or_insert(error);
                        }
                        Err(error) => return Err(error),
                    }
                }
                "offset" => {
                    if seen_offset {
                        return Err(Status::unimplemented(
                            "duplicate offset stage is unsupported locally",
                        ));
                    }
                    seen_offset = true;
                    let offset = count_argument(stage, unrecorded)?;
                    stages.push(Stage::Offset(offset));
                }
                "limit" => {
                    if seen_limit {
                        return Err(Status::unimplemented(
                            "duplicate limit stage is unsupported locally",
                        ));
                    }
                    seen_limit = true;
                    let limit = count_argument(stage, unrecorded)?;
                    stages.push(Stage::Limit(limit));
                }
                other => {
                    // The official emulator checks every stage's arguments before running any.
                    for rest in pipeline.stages.iter().skip(position) {
                        check_unrun_alias_stage(rest, &mut deferred, unrecorded)?;
                    }
                    validated_unrun = true;
                    return Err(Status::unimplemented(format!(
                        "pipeline stage {other:?} is unsupported locally"
                    )));
                }
            }
        }
        Ok(())
    })();
    // An empty map is answered after every other check of every stage (FS-ENT-ORACLE O-4,
    // `o4/stages#select-empty-then-*`, `#add-fields-then-select-empty`): a later stage's
    // refusal comes first. fireemu's own refusal of a stage it does not run is no check
    // production makes, so the empty map wins over it in the emulator profile, as in the
    // official emulator. Production answered a nonexistent function before the empty map
    // (O-4 `#select-empty-then-unknown-function`); where it puts other checks fireemu does
    // not make is unrecorded, so under strict the empty map wins only when every part passed
    // fireemu's checks.
    // Under strict, the request's shape then decides which refusal is answered (`pipeline_shape`).
    // A negative `limit` or `offset` is checked after the empty map (the official emulator
    // 1.22.0; PX1d r5 review S2), a string one before it (O-4).
    match (compiled, deferred) {
        (Err(error), Some(empty))
            if error.code() != tonic::Code::InvalidArgument
                && (validated_unrun || unrecorded == Unrecorded::OfficialEmulator) =>
        {
            Err(empty)
        }
        (Err(error), Some(empty)) if error.message().contains("cannot have a negative value") => {
            Err(empty)
        }
        (Ok(()), Some(empty)) => Err(empty),
        (result, _) => result,
    }?;
    // A select narrows the rows, so the scan copies only the fields the stages read.
    let projection =
        pipeline_exec::referenced_fields(&stages).map(|paths| pb::structured_query::Projection {
            fields: paths
                .iter()
                .map(|path| pb::structured_query::FieldReference {
                    field_path: path.canonical(),
                })
                .collect(),
        });
    if search.is_some() {
        pushdown = None;
    }
    let projection = if search.is_some() { None } else { projection };
    Ok(CompiledExecution {
        input: collection_query(query_parent, collection_id, pushdown, projection, 0, None),
        stages,
        select_keeps_name,
        search,
    })
}

/// The status of an expression error. fireemu's own argument-count texts are not
/// production's (which names the function's signature), so strict refuses them as unobserved.
fn expr_status(error: ExprError, unrecorded: Unrecorded) -> Status {
    match error {
        ExprError::Unsupported(message) => Status::unimplemented(message),
        ExprError::Invalid(message) if unrecorded == Unrecorded::Refuse => {
            Status::unimplemented(format!("{message}; this text is not observed locally"))
        }
        ExprError::Invalid(message) => Status::invalid_argument(message),
    }
}

/// `INVALID_ARGUMENT` with fireemu's own text under the emulator profile; under strict, which
/// answers only texts production recorded, `UNIMPLEMENTED`.
fn own_text(message: String, unrecorded: Unrecorded) -> Status {
    match unrecorded {
        Unrecorded::Refuse => {
            Status::unimplemented(format!("{message}; this text is not observed locally"))
        }
        Unrecorded::OfficialEmulator => Status::invalid_argument(message),
    }
}

/// The status of an evaluation error: `UNIMPLEMENTED` for an input whose production answer is
/// unrecorded, `INVALID_ARGUMENT` for one production or the official emulator refuses.
#[must_use]
pub fn eval_status(error: &pipeline_exec::EvalError) -> Status {
    match error {
        pipeline_exec::EvalError::Unobserved { .. } => Status::unimplemented(error.to_string()),
        pipeline_exec::EvalError::Invalid(message) => Status::invalid_argument(message.clone()),
        pipeline_exec::EvalError::WrongType { function, .. } => {
            crate::production_status::function_wrong_type(&error.to_string(), function)
        }
    }
}

/// Whether a wire value holds no expression at any depth (a literal the core can decode).
fn is_literal(value: &pb::Value) -> bool {
    expression_kind(value).is_none()
}

/// The wire name of the first expression a value holds at any depth, if any.
fn expression_kind(value: &pb::Value) -> Option<&'static str> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => array.values.iter().find_map(expression_kind),
        Some(V::MapValue(map)) => ordered_keys(&map.fields)
            .into_iter()
            .find_map(|key| expression_kind(&map.fields[key])),
        Some(V::FieldReferenceValue(_)) => Some("FIELD_REFERENCE_VALUE"),
        Some(V::VariableReferenceValue(_)) => Some("VARIABLE_REFERENCE_VALUE"),
        Some(V::FunctionValue(_)) => Some("FUNCTION_VALUE"),
        Some(V::PipelineValue(_)) => Some("PIPELINE_VALUE"),
        Some(_) => None,
        None => Some("VALUE_TYPE_NOT_SET"),
    }
}

/// Decodes an operand expression: a field reference (`__name__` is the document reference),
/// a call of a table function or a literal. An array or map literal that holds an
/// expression is refused with `INVALID_ARGUMENT`, as production and the official emulator
/// refuse every such literal; under strict one with a map key that is not plain is
/// `UNIMPLEMENTED` (production answered plain keys only).
fn decode_operand(value: &pb::Value, unrecorded: Unrecorded) -> Result<Expr, Status> {
    let expr = decode_operand_tree(value, unrecorded)?;
    match map_key_error(value) {
        Some(error) => Err(error),
        None => Ok(expr),
    }
}

/// The refusal of a call that reads no field, evaluated once before any row (its answer is the
/// same for every row): `None` when it answers a value.
fn constant_call_error(expr: &Expr) -> Option<Status> {
    fn reads_field(expr: &Expr) -> bool {
        match expr {
            Expr::Field(_) => true,
            Expr::Constant(_) => false,
            Expr::Call { args, .. } => args.iter().any(reads_field),
        }
    }
    if reads_field(expr) {
        return None;
    }
    let row = pipeline_exec::Row {
        path: DocumentPath::parse(
            &fireemu_core_types::ids::ProjectId::try_new("p").ok()?,
            &fireemu_core_types::ids::DatabaseId::try_new("(default)").ok()?,
            "c/d",
        )
        .ok()?,
        fields: std::collections::BTreeMap::new(),
    };
    match expr.eval_in(&row, Unrecorded::Refuse) {
        pipeline_exec::Eval::Error(error) => Some(eval_status(&error)),
        _ => None,
    }
}

/// The `map(...)` key checks of an operand, made after every other check of the whole operand
/// (the official emulator 1.22.0 answers a literal holding a field, a nonexistent function or
/// an argument count anywhere in the operand first; `PX1d` r5 review S2), in document order: a
/// key that is no literal (FS-ENT-ORACLE O-4 `o4/functions#map-key-*-field`), then a literal
/// key of another type than a string, which is refused before any row is read, as the official
/// emulator refuses it on an empty collection (review M3), every type alike (r7 review M1).
fn map_key_error(value: &pb::Value) -> Option<Status> {
    use pb::value::ValueType as V;
    let Some(V::FunctionValue(function)) = &value.value_type else {
        return None;
    };
    if function.name == "map" {
        let keys = || function.args.iter().step_by(2);
        if keys().any(|key| !is_literal(key)) {
            return Some(Status::invalid_argument(
                "map keys must be constants/literals",
            ));
        }
        // Every literal key that is not a string, in the official emulator's type names
        // (a vector is VECTOR, a reference ENTITY_REF; PX1d r7 review M1).
        for key in keys() {
            match &key.value_type {
                Some(V::StringValue(_)) => {}
                kind => {
                    let name = if is_vector_literal(key) {
                        "VECTOR"
                    } else {
                        official_type_name(kind.as_ref())
                    };
                    return Some(Status::invalid_argument(format!(
                        "map key must be of type STRING, given type is {name}"
                    )));
                }
            }
        }
    }
    function.args.iter().find_map(map_key_error)
}

#[allow(clippy::too_many_lines)]
fn decode_operand_tree(value: &pb::Value, unrecorded: Unrecorded) -> Result<Expr, Status> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        None => Err(own_text(
            "expression argument is missing".to_owned(),
            unrecorded,
        )),
        Some(V::FieldReferenceValue(field)) => Ok(Expr::Field(
            FieldPath::parse(field).map_err(|e| own_text(e.to_string(), unrecorded))?,
        )),
        Some(V::FunctionValue(function)) => {
            if pipeline_exec::function(&function.name).is_none() {
                return Err(Status::unimplemented(format!(
                    "function {:?} is unsupported locally",
                    function.name
                )));
            }
            // Production built arrays and maps of one element or more (FS-ENT-ORACLE O-1, O-3,
            // O-4); an empty `array()` or `map()` is unrecorded.
            if matches!(function.name.as_str(), "array" | "map")
                && function.args.is_empty()
                && unrecorded == Unrecorded::Refuse
            {
                return Err(Status::unimplemented(format!(
                    "{}() without arguments is not observed locally",
                    function.name
                )));
            }
            // The official emulator answers a function's argument count before its arguments'
            // own checks.
            let placeholders = vec![
                Expr::Constant(fireemu_core_firestore::value::Value::Null);
                function.args.len()
            ];
            Expr::call(&function.name, placeholders, Placement::Value)
                .map_err(|e| expr_status(e, unrecorded))?;
            // The official emulator ignores function options; production has not answered
            // them, so strict refuses them as unobserved.
            if !function.options.is_empty() && unrecorded == Unrecorded::Refuse {
                return Err(Status::unimplemented(format!(
                    "function {:?} options are not observed locally",
                    function.name
                )));
            }
            // A reference argument of a document function is answered per row, as production
            // recorded it (O-3 and O-4 `functions#*-collection`), not refused as a literal.
            let document_function = matches!(
                function.name.as_str(),
                "document_id" | "collection_id" | "parent"
            );
            let args = function
                .args
                .iter()
                .map(|arg| match &arg.value_type {
                    // Every reference constant passes the official checks first (r8 review
                    // M1): a malformed one is refused before any row, whatever it is passed to.
                    Some(V::ReferenceValue(name))
                        if document_function && unrecorded == Unrecorded::Refuse =>
                    {
                        match reference_literal_error(name) {
                            Some(text) => Err(Status::invalid_argument(text)),
                            None => Ok(Expr::Constant(
                                fireemu_core_firestore::value::Value::Reference(name.clone()),
                            )),
                        }
                    }
                    _ => decode_operand_tree(arg, unrecorded),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let expr = Expr::call(&function.name, args, Placement::Value)
                .map_err(|e| expr_status(e, unrecorded))?;
            // Under strict a call of constants that fails is refused before any row is read,
            // so it never falls through to an empty answer (ruling of 2026-10-21, PX1d r6 (d)).
            if unrecorded == Unrecorded::Refuse {
                if let Some(error) = constant_call_error(&expr) {
                    return Err(error);
                }
            }
            Ok(expr)
        }
        Some(V::VariableReferenceValue(_) | V::PipelineValue(_)) => Err(Status::unimplemented(
            "variable and pipeline operands are unsupported locally",
        )),
        // A literal of literals: the official emulator checks its vectors and `__type__` keys
        // before its other keys; production recorded well-formed vectors and a string
        // `__type__` only, so strict refuses the rest.
        Some(_) if expression_kind(value).is_none() && literal_value_error(value).is_some() => {
            let error = literal_value_error(value).unwrap_or_default();
            match unrecorded {
                Unrecorded::Refuse => Err(Status::unimplemented(unobserved_literal(&error))),
                Unrecorded::OfficialEmulator => Err(Status::invalid_argument(error)),
            }
        }
        Some(_) => match expression_kind(value) {
            // Production read literals of every kind, maps keyed by any name but an empty or a
            // reserved one (FS-ENT-ORACLE O-3, O-4 `o4/literals#*`); strict answers the shapes
            // it recorded (see `literal_shape_recorded`).
            None if unrecorded == Unrecorded::Refuse && !literal_shape_recorded(value) => Err(
                Status::unimplemented("a literal of this shape is not observed locally"),
            ),
            // A literal of more than 20 levels, in the official emulator's words (1.22.0: 20
            // levels are accepted); production has not answered it, so strict gives 501 through
            // the shape gate.
            None => Ok(Expr::Constant(
                decode_official_literal(value)
                    .map(canonical_constant)
                    .map_err(|e| {
                        if e.message().contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH") {
                            Status::invalid_argument("Values can be at most 20 levels deep.")
                        } else {
                            e
                        }
                    })?,
            )),
            // A literal holding an expression with a key that is not plain: the official
            // emulator names a reserved key before the value type; production has not answered
            // such a key, so strict refuses it as unobserved.
            Some(_) if !literal_keys_are_plain(value) && unrecorded == Unrecorded::Refuse => {
                Err(Status::unimplemented(
                    "a literal holding an expression with this key is not observed locally",
                ))
            }
            Some(_) if reserved_key(value).is_some() => Err(Status::invalid_argument(format!(
                "field name '{}' is reserved.",
                reserved_key(value).unwrap_or_default()
            ))),
            // A field or function anywhere in a literal, named by the first in document order
            // (FS-ENT-ORACLE O-1, O-3 and O-4 `o4/literals#*`); a malformed vector or
            // `__type__` met before it is named instead, as the official emulator does.
            Some(kind) => Err(Status::invalid_argument(
                expression_literal_error(value)
                    .unwrap_or_else(|| format!("Value type is not supported: {kind}")),
            )),
        },
    }
}

/// Under strict, a reference constant that names no document of the request's own project and
/// database (another database, the database root or the documents root), more than 100 key
/// path elements, or an id that matches production's
/// documented reserved pattern `__.*__` (`____` included, which the official emulator accepts)
/// is refused as unobserved before any row (ruling of 2026-10-21 for `PX1d` r8: production's
/// documented limits).
fn reference_outside(value: &pb::Value, own: &str) -> Option<Status> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        Some(V::ReferenceValue(name)) => {
            // The documents root names no document, and production recorded none (review r9 M3).
            let inside = name
                .strip_prefix(own)
                .is_some_and(|rest| rest.starts_with('/'));
            // A key path element is a collection id and a document id.
            let path = name
                .strip_prefix(own)
                .and_then(|rest| rest.strip_prefix('/'))
                .unwrap_or_default();
            let elements = path.split('/').count() / 2;
            let reserved = path.split('/').any(is_reserved_name);
            (!inside || elements > MAX_PATH_ELEMENTS || reserved).then(|| {
                Status::unimplemented(
                    "a reference that names no document of the request's database, longer than 100 key path elements or with a reserved-looking id is not observed locally",
                )
            })
        }
        Some(V::ArrayValue(array)) => array.values.iter().find_map(|v| reference_outside(v, own)),
        Some(V::MapValue(map)) => sorted_values(&map.fields)
            .into_iter()
            .find_map(|v| reference_outside(v, own)),
        Some(V::FunctionValue(function)) => function
            .args
            .iter()
            .chain(function.options.values())
            .find_map(|v| reference_outside(v, own)),
        Some(V::PipelineValue(pipeline)) => pipeline
            .stages
            .iter()
            .flat_map(|stage| stage.args.iter().chain(stage.options.values()))
            .find_map(|v| reference_outside(v, own)),
        _ => None,
    }
}

/// The most key path elements (collection and document id pairs) of a document name
/// (production's limit; the official emulator 1.22.0 answers `A key path cannot have more than
/// 100 elements.` past it).
const MAX_PATH_ELEMENTS: usize = 100;

/// A constant as the official emulator 1.22.0 answers it: every timestamp cut to microseconds,
/// as production stores a value (r8 review S4), and a reference to a database root read as its
/// documents root (`projects/p/databases/d` answers `projects/p/databases/d/documents`, and
/// the two are equal; probed 2026-10-21).
fn canonical_constant(
    value: fireemu_core_firestore::value::Value,
) -> fireemu_core_firestore::value::Value {
    use fireemu_core_firestore::value::{Timestamp, Value};
    match value {
        Value::Timestamp(t) => Timestamp::new(t.seconds(), t.nanos() / 1000 * 1000)
            .map_or(Value::Timestamp(t), Value::Timestamp),
        Value::Reference(name) if is_database_root(&name) => {
            Value::Reference(format!("{name}/documents"))
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_constant).collect()),
        Value::Map(fields) => Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (key, canonical_constant(value)))
                .collect(),
        ),
        other => other,
    }
}

/// Whether a name is `projects/{p}/databases/{d}` with both ids present.
fn is_database_root(name: &str) -> bool {
    matches!(
        name.split('/').collect::<Vec<_>>().as_slice(),
        ["projects", project, "databases", database] if !project.is_empty() && !database.is_empty()
    )
}

/// How many map and array levels a literal value nests.
fn literal_depth(value: &pb::Value) -> usize {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => 1 + array.values.iter().map(literal_depth).max().unwrap_or(0),
        Some(V::MapValue(map)) => 1 + map.fields.values().map(literal_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// The official emulator's refusal of an empty key in a literal map.
const EMPTY_LITERAL_KEY: &str = "Property names cannot be empty.";

/// The first reserved map key (`__x__`, `__type__` aside) a literal holds at any depth, in key
/// order.
fn reserved_key(value: &pb::Value) -> Option<String> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => array.values.iter().find_map(reserved_key),
        Some(V::MapValue(map)) => {
            let keys = ordered_keys(&map.fields);
            keys.into_iter().find_map(|key| {
                if is_reserved_name(key) && key != "__type__" {
                    Some(key.clone())
                } else {
                    reserved_key(&map.fields[key])
                }
            })
        }
        _ => None,
    }
}

/// A literal as the official emulator reads it in a pipeline: an empty map key is refused
/// ("Property names cannot be empty."), and a `__type__` key of a map that is no vector is a
/// plain key; everything else decodes as a stored value does.
fn decode_official_literal(
    value: &pb::Value,
) -> Result<fireemu_core_firestore::value::Value, Status> {
    use fireemu_core_firestore::value::Value;
    use pb::value::ValueType as V;
    fn has(value: &pb::Value, test: &dyn Fn(&str, &pb::Value) -> bool) -> bool {
        match value.value_type.as_ref() {
            Some(V::ArrayValue(array)) => array.values.iter().any(|v| has(v, test)),
            Some(V::MapValue(map)) => map
                .fields
                .iter()
                .any(|(key, inner)| test(key, value) || has(inner, test)),
            _ => false,
        }
    }
    // The depth limit holds on both paths below, whatever keys the literal has.
    if literal_depth(value) > fireemu_core_firestore::value::MAX_NESTING_DEPTH as usize {
        return Err(Status::invalid_argument(
            "Values can be at most 20 levels deep.",
        ));
    }
    let typed = |key: &str, map: &pb::Value| key == "__type__" && !is_vector_literal(map);
    // A reserved key is named before an empty one, at any depth (the official emulator 1.22.0,
    // PX1d r5 review order probes).
    if let Some(key) = reserved_key(value) {
        return Err(Status::invalid_argument(format!(
            "field name '{key}' is reserved."
        )));
    }
    if has(value, &|key, _| key.is_empty()) {
        return Err(Status::invalid_argument(EMPTY_LITERAL_KEY));
    }
    if !has(value, &typed) {
        return crate::decode::decode_value(value)
            .map_err(|e| Status::invalid_argument(e.to_string()));
    }
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => Ok(Value::Array(
            array
                .values
                .iter()
                .map(decode_official_literal)
                .collect::<Result<_, _>>()?,
        )),
        Some(V::MapValue(map)) if !is_vector_literal(value) => {
            let mut fields = std::collections::BTreeMap::new();
            let mut entries: Vec<_> = map.fields.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (key, inner) in entries {
                if is_reserved_name(key) && key != "__type__" {
                    return Err(Status::invalid_argument(format!(
                        "field name '{key}' is reserved."
                    )));
                }
                fields.insert(key.clone(), decode_official_literal(inner)?);
            }
            Ok(Value::Map(fields))
        }
        _ => {
            crate::decode::decode_value(value).map_err(|e| Status::invalid_argument(e.to_string()))
        }
    }
}

/// Strict's answer for a literal the official emulator refuses (`error` is its text): it names
/// the limit or the form that fails, since production recorded none of them (review r10 S3).
fn unobserved_literal(error: &str) -> &'static str {
    if error.starts_with("Field name '") {
        "a literal field path over 1500 bytes is not observed locally"
    } else if error.starts_with("String values can be at most")
        || error.starts_with("Bytes values can be at most")
    {
        "a literal string or bytes value over 1,048,487 bytes is not observed locally"
    } else if error.starts_with("Vectors must be at most") {
        "a vector over 2048 dimensions is not observed locally"
    } else if [
        "Document parent",
        "Collection id",
        "Resource id",
        "Path element",
        "The kind / collection group",
        "A key path",
    ]
    .iter()
    .any(|prefix| error.starts_with(prefix))
    {
        "a reference constant that is not a valid document name is not observed locally"
    } else {
        "a malformed vector or __type__ is not observed locally"
    }
}

/// The official emulator's refusal of the first malformed vector or `__type__` key a literal of
/// literals holds (arrays in order, maps in key order: the wire map keeps no order), in its
/// order of checks: a `__type__` that is no string, then for a vector a missing `value`, a
/// `value` that is no array, another key, no element, an element that is no double, a NaN
/// element (firebase-tools 15.28.2, Firestore emulator 1.22.0). The field path inside the
/// literal (its keys joined with `.`, UTF-8 bytes) holds at most 1500 bytes.
fn literal_value_error(value: &pb::Value) -> Option<String> {
    literal_value_error_below(value, None)
}

/// [`literal_value_error`] for a value at the field path of `path_bytes` bytes inside the
/// literal (`None` at its top). An array keeps the path of the map around it; a vector's own
/// keys are not a path (review r9 M1, probed against 1.22.0).
fn literal_value_error_below(value: &pb::Value, path_bytes: Option<usize>) -> Option<String> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        Some(V::ReferenceValue(name)) => reference_literal_error(name),
        Some(V::StringValue(text)) if text.len() > MAX_VALUE_BYTES => {
            Some("String values can be at most 1,048,487 bytes.".to_owned())
        }
        Some(V::BytesValue(bytes)) if bytes.len() > MAX_VALUE_BYTES => {
            Some("Bytes values can be at most 1,048,487 bytes.".to_owned())
        }
        Some(V::ArrayValue(array)) => array
            .values
            .iter()
            .find_map(|inner| literal_value_error_below(inner, path_bytes)),
        Some(V::MapValue(map)) => {
            if let Some(kind) = map
                .fields
                .get("__type__")
                .and_then(|t| match &t.value_type {
                    Some(V::StringValue(_)) => None,
                    other => Some(official_type_name(other.as_ref())),
                })
            {
                return Some(format!("Field __type__ must be a string; founds {kind}."));
            }
            if is_vector_literal(value) {
                return vector_error(map).map(str::to_owned);
            }
            // Depth first, in key order: a key, then what is under it, then the next key
            // (review r10 S2: the official emulator names the first crossing key so).
            let below = |key: &str| path_bytes.map_or(key.len(), |bytes| bytes + 1 + key.len());
            ordered_keys(&map.fields).into_iter().find_map(|key| {
                if below(key) > MAX_ID_BYTES {
                    return Some(format!("Field name '{key}' can be at most 1,500 bytes."));
                }
                literal_value_error_below(&map.fields[key], Some(below(key)))
            })
        }
        _ => None,
    }
}

/// The official emulator's refusal of a collection stage's reference (1.22.0, probed
/// 2026-10-21): the name must start with `/`, then the path's checks as
/// [`document_path_error`] makes them, with an odd number of segments (a collection).
fn collection_name_error(name: &str) -> Option<String> {
    let Some(path) = name.strip_prefix('/') else {
        return Some(format!(
            "Collection name \"{name}\" lacks \"/\" at index 0."
        ));
    };
    document_path_error(name, "Collection name", path, 1, true)
}

/// The official emulator's checks of a path below the documents root, in its order (1.22.0,
/// probed 2026-10-21; indexes count UTF-16 units, as its Java does): segment by segment, an
/// empty segment other than the last, a `.` or `..` id, and a reserved id (`__x__`); then a
/// trailing `/`; then the parity (`collection`: an odd number of segments); then more than 100
/// key path elements (id pairs); then an id of more than 1500 bytes. `offset` is where `path`
/// starts in `name`, and `label` names the whole in the texts.
fn document_path_error(
    name: &str,
    label: &str,
    path: &str,
    offset: usize,
    collection: bool,
) -> Option<String> {
    let units = |text: &str| text.encode_utf16().count();
    let segments: Vec<&str> = path.split('/').collect();
    let mut at_unit = offset;
    for (at, segment) in segments.iter().enumerate() {
        let (id, which) = if at % 2 == 0 {
            ("collection id", "Collection")
        } else {
            ("resource id", "Resource")
        };
        if segment.is_empty() && at + 1 < segments.len() {
            return Some(format!(
                "{label} \"{name}\" lacks a {id} at index {at_unit}."
            ));
        }
        if matches!(*segment, "." | "..") {
            return Some(format!(
                "{label} \"{name}\" contains a {id} \"{segment}\" at index {at_unit}."
            ));
        }
        if is_reserved_id(segment) {
            return Some(format!(
                "{which} id \"{segment}\" is invalid because it is reserved."
            ));
        }
        at_unit += units(segment) + 1;
    }
    if path.is_empty() || name.ends_with('/') {
        return Some(format!("{label} \"{name}\" has invalid trailing \"/\"."));
    }
    if (segments.len() % 2 == 1) != collection {
        return Some(format!(
            "{label} \"{name}\" lacks \"/\" at index {}.",
            units(name)
        ));
    }
    if segments.len() / 2 > MAX_PATH_ELEMENTS {
        return Some("A key path cannot have more than 100 elements.".to_owned());
    }
    let at = segments.iter().position(|id| id.len() > MAX_ID_BYTES)?;
    Some(if at % 2 == 0 {
        "The kind / collection group can be at most 1,500 bytes.".to_owned()
    } else {
        "Path element can be at most 1,500 bytes.".to_owned()
    })
}

/// The official emulator's refusal of a reference constant (1.22.0, probed 2026-10-21; indexes
/// count UTF-16 units, as its Java does). It reads the name left to right: the
/// documents-relative form (`/c`) is not recognized; then `projects`, `/`, a project id, `/`,
/// `databases`, `/`, a database id, and optionally `/documents` and `/` and a path, which
/// [`document_path_error`] checks. A missing keyword or id is named at its index, a name that
/// ends right after a `/` has an invalid trailing `/`, and `documents/` alone is told to omit it.
/// The database root and the documents root are references too.
fn reference_literal_error(name: &str) -> Option<String> {
    let units = |text: &str| text.encode_utf16().count();
    if name.starts_with('/') {
        return Some(format!("Document parent \"{name}\" not recognized."));
    }
    let lacks = |what: &str, at: usize| {
        Some(format!(
            "Document parent name \"{name}\" lacks {what} at index {at}."
        ))
    };
    let trailing = || {
        Some(format!(
            "Document parent name \"{name}\" has invalid trailing \"/\"."
        ))
    };
    let Some(mut rest) = name.strip_prefix("projects") else {
        return lacks("\"projects\"", 0);
    };
    let mut offset = "projects".len();
    for (id, keyword) in [
        ("a project id", "databases"),
        ("a database id", "documents"),
    ] {
        let Some(tail) = rest.strip_prefix('/') else {
            return lacks("\"/\"", offset);
        };
        offset += 1;
        if tail.is_empty() {
            return trailing();
        }
        let (value, tail) = tail.split_at(tail.find('/').unwrap_or(tail.len()));
        if value.is_empty() {
            return lacks(id, offset);
        }
        offset += units(value);
        // The database root names no document but is a reference.
        if tail.is_empty() && keyword == "documents" {
            return None;
        }
        let Some(tail) = tail.strip_prefix('/') else {
            return lacks("\"/\"", offset);
        };
        offset += 1;
        if tail.is_empty() {
            return trailing();
        }
        let Some(tail) = tail.strip_prefix(keyword) else {
            return lacks(&format!("\"{keyword}\""), offset);
        };
        offset += keyword.len();
        rest = tail;
    }
    // Below `documents`: nothing (the documents root), or `/` and a path.
    if rest.is_empty() {
        return None;
    }
    let Some(path) = rest.strip_prefix('/') else {
        return lacks("\"/\"", offset);
    };
    if path.is_empty() {
        return Some(format!(
            "Document parent name \"{name}\" is invalid: Omit trailing \"/\"."
        ));
    }
    document_path_error(name, "Document parent name", path, offset + 1, false)
}

/// The longest document or collection id, and the longest literal map key (production's limits).
const MAX_ID_BYTES: usize = 1500;
/// The largest string or bytes value (production's limit).
const MAX_VALUE_BYTES: usize = 1_048_487;
/// The most dimensions of a vector (production's limit).
const MAX_VECTOR_DIMENSIONS: usize = 2048;

/// The official emulator's refusal of a vector map, in its order of checks.
fn vector_error(map: &pb::MapValue) -> Option<&'static str> {
    use pb::value::ValueType as V;
    let elements = match map.fields.get("value").map(|v| v.value_type.as_ref()) {
        None => return Some("Vector map is missing key 'value'."),
        Some(Some(V::ArrayValue(array))) => &array.values,
        Some(_) => return Some("Vector value type must be an array."),
    };
    if map.fields.len() != 2 {
        return Some("Vector value map has extraneous entries.");
    }
    if elements.is_empty() {
        return Some("Cannot have a zero length vector.");
    }
    if !elements
        .iter()
        .all(|e| matches!(e.value_type, Some(V::DoubleValue(_))))
    {
        return Some("Vector must only contain values of type 'double'");
    }
    if elements
        .iter()
        .any(|e| matches!(e.value_type, Some(V::DoubleValue(d)) if d.is_nan()))
    {
        return Some("Vectors cannot contain NaN values.");
    }
    (elements.len() > MAX_VECTOR_DIMENSIONS).then_some("Vectors must be at most 2048 dimensions.")
}

/// A wire value's type as the official emulator names it in its `__type__` refusal (a string is
/// no refusal).
fn official_type_name(value: Option<&pb::value::ValueType>) -> &'static str {
    use pb::value::ValueType as V;
    match value {
        Some(V::NullValue(_)) => "NULL",
        Some(V::BooleanValue(_)) => "BOOLEAN",
        Some(V::IntegerValue(_)) => "LONG",
        Some(V::DoubleValue(_)) => "DOUBLE",
        Some(V::TimestampValue(_)) => "TIMESTAMP",
        Some(V::BytesValue(_)) => "BYTES",
        Some(V::ReferenceValue(_)) => "ENTITY_REF",
        Some(V::GeoPointValue(_)) => "GEO_POINT",
        Some(V::ArrayValue(_)) => "ARRAY",
        Some(V::MapValue(_)) => "MAP",
        _ => "UNKNOWN",
    }
}

/// The official emulator's refusal of a literal holding an expression: its entries are read in
/// order (arrays in order, maps in key order), a field or function names its kind, and a
/// literal of literals inside it gets the vector and `__type__` checks first.
fn expression_literal_error(value: &pb::Value) -> Option<String> {
    use pb::value::ValueType as V;
    let entry = |inner: &pb::Value| match inner.value_type.as_ref() {
        Some(V::ArrayValue(_) | V::MapValue(_)) if expression_kind(inner).is_some() => {
            expression_literal_error(inner)
        }
        _ => match expression_kind(inner) {
            Some(kind) => Some(format!("Value type is not supported: {kind}")),
            None => literal_value_error(inner),
        },
    };
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => array.values.iter().find_map(entry),
        Some(V::MapValue(map)) => {
            let keys = ordered_keys(&map.fields);
            keys.into_iter().find_map(|key| entry(&map.fields[key]))
        }
        _ => None,
    }
}

/// Whether production recorded a literal of this shape: every vector map is
/// `{__type__: "__vector__", value: [doubles]}` with at least one element, every one finite and
/// none a negative zero (O-3, O-4
/// `literals#vector`, `#map-holding-vector`, `conditions#where-vector`), at most one map key
/// is empty or reserved (production named one, O-4 `literals#key-empty`, `#key-reserved`;
/// which of several it names is unrecorded), and no key is `__name__` (only the official
/// emulator answered it).
fn literal_shape_recorded(value: &pb::Value) -> bool {
    use pb::value::ValueType as V;
    // `in_array`: production read vectors alone and as a map value, never inside an array
    // (O-4 `literals#vector`, `#map-holding-vector`).
    fn walk(value: &pb::Value, refusable: &mut usize, in_array: bool) -> bool {
        match value.value_type.as_ref() {
            Some(V::ArrayValue(array)) => array.values.iter().all(|v| walk(v, refusable, true)),
            Some(V::MapValue(_)) if is_vector_literal(value) && in_array => false,
            Some(V::MapValue(map)) if is_vector_literal(value) => {
                map.fields.len() == 2
                    && matches!(
                        map.fields.get("value").and_then(|v| v.value_type.as_ref()),
                        Some(V::ArrayValue(array)) if !array.values.is_empty()
                            && array.values.iter().all(|e| matches!(e.value_type, Some(V::DoubleValue(d)) if d.is_finite() && !(d == 0.0 && d.is_sign_negative())))
                    )
            }
            // Production read reference literals naming a document (O-3 `literals#*`).
            // A reference that names no document was refused before (`literal_value_error`); the
            // documents root and a non-ASCII name are unrecorded.
            Some(V::ReferenceValue(name)) => name.is_ascii() && name.split('/').count() > 5,
            Some(V::MapValue(map)) => map.fields.iter().all(|(key, inner)| {
                if key.is_empty() || (is_reserved_name(key) && key != "__type__") {
                    *refusable += 1;
                }
                // Production answered a string `__type__` alone in its map only (O-4
                // `literals#key-type`).
                let typed = key != "__type__"
                    || (matches!(inner.value_type, Some(V::StringValue(_)))
                        && map.fields.len() == 1);
                typed && key != "__name__" && walk(inner, refusable, false)
            }),
            _ => true,
        }
    }
    let mut refusable = 0;
    walk(value, &mut refusable, false) && refusable <= 1
}

/// Whether every map key a literal holds, at any depth, is plain.
fn literal_keys_are_plain(value: &pb::Value) -> bool {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => array.values.iter().all(literal_keys_are_plain),
        Some(V::MapValue(map)) => map
            .fields
            .iter()
            .all(|(key, inner)| is_plain_key(key) && literal_keys_are_plain(inner)),
        _ => true,
    }
}

/// Whether a wire map is a vector (`{__type__: "__vector__", value: [...]}`).
fn is_vector_literal(value: &pb::Value) -> bool {
    use pb::value::ValueType as V;
    matches!(&value.value_type, Some(V::MapValue(map))
    if matches!(
        map.fields.get("__type__").and_then(|t| t.value_type.as_ref()),
        Some(V::StringValue(t)) if t == "__vector__"
    ))
}

/// Decodes `where(condition)`: a field or a call of a table function (production keeps the
/// rows where it is `true`), or (under the emulator profile, as the official emulator answers
/// it) a literal. An `equal(field, scalar literal)` also gives the
/// same filter the `RunQuery` lowering sends, for the scan to apply before it copies
/// documents.
fn decode_condition(
    stage: &pb::pipeline::Stage,
    unrecorded: Unrecorded,
) -> Result<(Expr, Option<pb::structured_query::Filter>), Status> {
    use pb::value::ValueType as V;
    let Some(condition) = stage.args.first() else {
        return Err(Status::invalid_argument("where requires a condition"));
    };
    // A field, or a literal: production kept the row for `true` and dropped it for a constant
    // of every other kind (FS-ENT-ORACLE O-3 and O-4, `comparisons#where-constant-*`,
    // `conditions#where-*`), and refused a literal holding a field or function as it does
    // anywhere (O-4 `literals#*`); the operand decoder answers each.
    let Some(V::FunctionValue(function)) = condition.value_type.as_ref() else {
        return Ok((decode_operand(condition, unrecorded)?, None));
    };
    let Some(def) = pipeline_exec::function(&function.name) else {
        return Err(Status::unimplemented(
            "where expression is unsupported locally",
        ));
    };
    if !def.returns_boolean {
        // A function of another value: production drops the row for the kinds it recorded
        // (FS-ENT-ORACLE O-2, `where` on `document_id`, `parent`, `array` and `map`); the
        // cursor decides by the value's kind.
        return Ok((decode_operand(condition, unrecorded)?, None));
    }
    // Every boolean function of the table is a comparison of two arguments; the wording is
    // the finite subset's.
    if def.arity != Arity::Exact(function.args.len()) {
        return Err(own_text(
            format!("{} requires exactly two arguments", def.name),
            unrecorded,
        ));
    }
    // Options are ignored by the official emulator and unobserved in production, as above.
    if !function.options.is_empty() && unrecorded == Unrecorded::Refuse {
        return Err(Status::unimplemented(format!(
            "function {:?} options are not observed locally",
            def.name
        )));
    }
    let args = function
        .args
        .iter()
        .map(|arg| decode_operand(arg, unrecorded))
        .collect::<Result<Vec<_>, _>>()?;
    let scalar_literal = |value: &pb::Value| {
        is_literal(value)
            && !matches!(
                value.value_type,
                Some(pb::value::ValueType::ArrayValue(_) | pb::value::ValueType::MapValue(_))
            )
    };
    let pushdown = match (&args[..], &function.args[..]) {
        ([Expr::Field(path), _], [_, literal])
            if def.name == "equal" && !path.is_document_name() && scalar_literal(literal) =>
        {
            Some(equal_filter(path.canonical(), literal))
        }
        _ => None,
    };
    let condition =
        Expr::call(def.name, args, Placement::Condition).map_err(|e| expr_status(e, unrecorded))?;
    Ok((condition, pushdown))
}

/// Decodes `select({alias: operand, ...})`. An alias is a field path, as production and the
/// official emulator read it (FS-ENT-ORACLE O-1 recorded the same answers from both): a
/// dotted alias nests, a quoted one unquotes, and an invalid path, a reserved name, a
/// repeated path and an alias inside another are refused. `__name__` selected as itself is no
/// alias but the request to keep the document name in the result (strict: alone only): the flag
/// is the second part of the answer.
fn decode_select(
    stage: &pb::pipeline::Stage,
    unrecorded: Unrecorded,
    wire_order: Option<&[String]>,
) -> Result<(Vec<(FieldPath, Expr)>, bool), Status> {
    let Some(pb::value::ValueType::MapValue(map)) =
        stage.args.first().and_then(|v| v.value_type.as_ref())
    else {
        return Err(Status::invalid_argument("select requires an alias map"));
    };
    // Production and the official emulator refuse a wider select (FS-ENT-ORACLE O-2,
    // `fs-ent-pipeline/o2/select-width`).
    if map.fields.len() > MAX_SELECT_FIELDS {
        return Err(Status::invalid_argument(format!(
            "The 'select(...)' stage is limited to {MAX_SELECT_FIELDS} fields but this stage has {}.",
            map.fields.len()
        )));
    }
    if unrecorded == Unrecorded::Refuse && !name_select_recorded(&map.fields) {
        return Err(Status::unimplemented(
            "selecting __name__ as itself, other than alone, is not observed locally",
        ));
    }
    // Every alias is checked before any value, as the official emulator does, in the request's
    // order where the transport kept it, else in key order (a decoded gRPC map keeps none).
    let mut entries: Vec<_> = map.fields.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut in_wire_order = false;
    if let Some(order) = wire_order.filter(|order| {
        order.len() == entries.len() && order.iter().all(|k| map.fields.contains_key(k))
    }) {
        entries.sort_by_key(|(alias, _)| order.iter().position(|k| k == *alias));
        in_wire_order = true;
    }
    // The official emulator 1.22.0 checks every alias's path first, then every value's
    // static checks (a literal holding an expression, a function's existence and argument
    // count, then the `map(...)` keys), then the reserved names (PX1d r6 review S2).
    for (alias, value) in &entries {
        if value.value_type.is_none() {
            return Err(Status::unimplemented(
                "select expressions are unsupported locally",
            ));
        }
        parse_alias(alias)?;
    }
    // An empty literal key is named after every other value's checks (the official emulator
    // 1.22.0 names a literal holding a field, or a reserved key, in a later value first).
    let mut exprs = Vec::with_capacity(entries.len());
    let mut empty_key = None;
    for (_, value) in &entries {
        match decode_operand_tree(value, unrecorded) {
            Ok(expr) => exprs.push(expr),
            Err(error) if error.message() == EMPTY_LITERAL_KEY => {
                empty_key.get_or_insert(error);
            }
            Err(error) => return Err(error),
        }
    }
    if let Some(error) = entries.iter().find_map(|(_, value)| map_key_error(value)) {
        return Err(error);
    }
    if let Some(error) = empty_key {
        return Err(error);
    }
    let mut aliases = Vec::with_capacity(entries.len());
    for ((alias, _), expr) in entries.iter().zip(exprs) {
        // `__name__` set from `__name__` takes part in the overlap checks like any alias, but
        // sets no field.
        let identity = matches!(&expr, Expr::Field(path) if path.is_document_name())
            && parse_alias(alias).is_ok_and(|path| path.segments() == ["__name__"]);
        let path = if identity {
            parse_alias(alias)?
        } else {
            decode_alias(alias)?
        };
        aliases.push((*alias, path, expr, identity));
    }
    if aliases.is_empty() {
        // FS-ENT-ORACLE O-4 `o4/stages#select-empty-map`.
        return Err(Status::invalid_argument(
            "The 'select(...)' stage requires at least one field.",
        ));
    }
    // Without the request's order the aliases are set in path order.
    if !in_wire_order {
        aliases.sort_by(|a, b| a.1.cmp(&b.1));
    }
    // An alias inside another names the alias set later, which is the child in path order
    // (FS-ENT-ORACLE O-1 `px0/aliases#overlap`, `{m, m.r}`) and, in the request's order, the
    // later of the two (the official emulator 1.22.0: `{a.b, a}` names `a`).
    for (at, (alias, path, _, _)) in aliases.iter().enumerate() {
        for (earlier_alias, earlier, _, _) in &aliases[..at] {
            if earlier == path {
                return Err(Status::invalid_argument(format!(
                    "select aliases {earlier_alias:?} and {alias:?} set the same field"
                )));
            }
            if earlier.is_prefix_of(path) || path.is_prefix_of(earlier) {
                return Err(crate::production_status::select_overlapping_paths(alias));
            }
        }
    }
    let keeps_name = aliases.iter().any(|(_, _, _, identity)| *identity);
    Ok((
        aliases
            .into_iter()
            .filter(|(_, _, _, identity)| !identity)
            .map(|(_, path, expr, _)| (path, expr))
            .collect(),
        keeps_name,
    ))
}

/// A select's result for a source document: the selected fields, and the document name when
/// the select kept `__name__` as itself.
#[must_use]
pub fn selected_result(
    fields: &std::collections::BTreeMap<String, fireemu_core_firestore::value::Value>,
    source_name: &str,
    keeps_name: bool,
) -> pb::Document {
    let mut result = result_document(fields);
    if keeps_name {
        source_name.clone_into(&mut result.name);
    }
    result
}

/// Whether a strict select may name the document: it holds no `__name__` selected as itself,
/// or only that, alone and unquoted. Production answered the alone form with the name only
/// (FS-ENT-ORACLE O5 `appendix#proposed-select-name-field`); beside other aliases or quoted it is
/// unobserved. (The emulator profile answers every form as the official emulator does.)
fn name_select_recorded(fields: &std::collections::HashMap<String, pb::Value>) -> bool {
    let names_document =
        |text: &str| parse_alias(text).is_ok_and(|path| path.segments() == ["__name__"]);
    let selects_itself = fields.iter().any(|(alias, value)| {
        names_document(alias)
            && matches!(&value.value_type, Some(pb::value::ValueType::FieldReferenceValue(f))
                if names_document(f))
    });
    !selects_itself
        || matches!(
            fields.iter().collect::<Vec<_>>()[..],
            [(alias, pb::Value { value_type: Some(pb::value::ValueType::FieldReferenceValue(field)) })]
                if alias == "__name__" && field == "__name__"
        )
}

/// The wire order of the aliases of the `select` stage at `position`, where the body kept it.
fn select_wire_order(order: Option<&KeyOrder>, position: usize) -> Option<&[String]> {
    order?.keys(&format!(
        "/structuredPipeline/pipeline/stages/{position}/args/0/mapValue/fields"
    ))
}

/// The official emulator refuses a select alias whose unquoted segments, joined with '.', reach
/// this many bytes (1499 is accepted).
const ALIAS_LIMIT_BYTES: usize = 1500;

/// A syntactically valid alias the path parser refuses for its length, unquoted and joined
/// with '.' as the official emulator names it.
fn unquoted_alias(alias: &str) -> String {
    let mut out = String::with_capacity(alias.len());
    let mut chars = alias.chars();
    while let Some(c) = chars.next() {
        match c {
            '`' => {}
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out
}

/// Reads a select alias as a field path. Production answered every alias shape the official
/// emulator answers, with the same texts (FS-ENT-ORACLE O-1 `fs-ent-pipeline/px0/aliases`, O-3
/// `fs-ent-pipeline/o3/aliases` and O-4 `fs-ent-pipeline/o4/aliases`): a reserved `__x__` or
/// `__name__` is refused as the first segment, quoted or not, with or without a child, and
/// accepted below another field; the path checks are [`parse_alias`]'s.
fn decode_alias(alias: &str) -> Result<FieldPath, Status> {
    let path = parse_alias(alias)?;
    match path.segments() {
        [name, ..] if name == "__name__" => Err(Status::invalid_argument(format!(
            "Stage 'select': field name '{name}' is reserved and can not be overwritten."
        ))),
        [name, ..] if is_reserved_name(name) => Err(Status::invalid_argument(format!(
            "Stage 'select': field name '{name}' is reserved."
        ))),
        // A reserved name below another field is a nested key.
        _ => Ok(path),
    }
}

/// Reads an alias as a field path with production's checks, in its order (FS-ENT-ORACLE O-3,
/// the official emulator alike): the empty path, the path syntax (an invalid name of any
/// length gets the syntax text), then the length of the segments unquoted and joined with
/// '.', refused at 1500 bytes or more with that joined text and a `PROPERTY_PATH_TOO_LONG`
/// detail, counted in UTF-8 bytes whatever the characters (O-4). Reserved names are the
/// caller's.
fn parse_alias(alias: &str) -> Result<FieldPath, Status> {
    // UTF-8 bytes, whatever the characters (FS-ENT-ORACLE O-4 `o4/aliases#multibyte-*`).
    let too_long = |joined: &str| crate::production_status::property_path_too_long(joined);
    let path = match FieldPath::parse_allowing_reserved(alias) {
        Ok(path) => path,
        Err(FieldPathError::Empty) => {
            return Err(Status::invalid_argument(
                crate::query_messages::EMPTY_PROPERTY_PATH,
            ))
        }
        Err(FieldPathError::SegmentTooLong { .. } | FieldPathError::PathTooLong { .. }) => {
            return Err(too_long(&unquoted_alias(alias)))
        }
        Err(_) => {
            return Err(Status::invalid_argument(format!(
                r#"Invalid property path "{alias}". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\]|(?:\\.))+`)"#
            )))
        }
    };
    let joined = path.segments().join(".");
    if joined.len() >= ALIAS_LIMIT_BYTES {
        return Err(too_long(&joined));
    }
    Ok(path)
}

/// The count a `limit` or `offset` stage takes. Any non-negative integer is answered in both
/// profiles (FS-ENT-ORACLE O-4 `o4/stages#limit-*`, `#offset-5000000000`). Production refused a
/// string for both and a negative limit with the official emulator's texts (O-4
/// `#limit-string`, `#offset-string`, `#limit-negative`); the official emulator refuses every
/// other type and a negative offset alike, which production has not answered, so strict
/// refuses those as unobserved.
fn count_argument(stage: &pb::pipeline::Stage, unrecorded: Unrecorded) -> Result<u64, Status> {
    use pb::value::ValueType as V;
    let name = stage.name.as_str();
    let argument = stage.args.first().and_then(|v| v.value_type.as_ref());
    // The values production answered: a limit of 1, 2, 2147483648 and 5000000000 and -1, an
    // offset of 5000000000, a string for both (O-1 `results/metadata#limit`, O-4
    // `o4/stages#limit-*`, `#offset-*`); zero is a boundary it never answered, and an offset
    // within 32 bits is another value range.
    let recorded = match argument {
        Some(V::IntegerValue(n)) if name == "limit" => *n != 0,
        Some(V::IntegerValue(n)) => *n > i64::from(i32::MAX),
        Some(V::StringValue(_)) => true,
        _ => false,
    };
    if unrecorded == Unrecorded::Refuse && !recorded {
        return Err(Status::unimplemented(format!(
            "this {name} argument is not observed locally"
        )));
    }
    match argument {
        Some(V::IntegerValue(n)) if *n >= 0 => Ok(u64::try_from(*n).unwrap_or(u64::MAX)),
        Some(V::IntegerValue(n)) => Err(Status::invalid_argument(format!(
            "The '{name}(...)' cannot have a negative value: {n}"
        ))),
        other => Err(Status::invalid_argument(format!(
            "Expected {name} to be INTEGER_VALUE, but was {}.",
            value_type_name(other)
        ))),
    }
}

/// The proto name of a wire value's type, as the official emulator's messages give it.
fn value_type_name(value: Option<&pb::value::ValueType>) -> &'static str {
    use pb::value::ValueType as V;
    match value {
        Some(V::NullValue(_)) => "NULL_VALUE",
        Some(V::BooleanValue(_)) => "BOOLEAN_VALUE",
        Some(V::IntegerValue(_)) => "INTEGER_VALUE",
        Some(V::DoubleValue(_)) => "DOUBLE_VALUE",
        Some(V::TimestampValue(_)) => "TIMESTAMP_VALUE",
        Some(V::StringValue(_)) => "STRING_VALUE",
        Some(V::BytesValue(_)) => "BYTES_VALUE",
        Some(V::ReferenceValue(_)) => "REFERENCE_VALUE",
        Some(V::GeoPointValue(_)) => "GEO_POINT_VALUE",
        Some(V::ArrayValue(_)) => "ARRAY_VALUE",
        Some(V::MapValue(_)) => "MAP_VALUE",
        Some(V::FieldReferenceValue(_)) => "FIELD_REFERENCE_VALUE",
        Some(V::VariableReferenceValue(_)) => "VARIABLE_REFERENCE_VALUE",
        Some(V::FunctionValue(_)) => "FUNCTION_VALUE",
        Some(V::PipelineValue(_)) => "PIPELINE_VALUE",
        None => "VALUE_TYPE_NOT_SET",
    }
}

/// The subset's order of stages after the input: `where` and `select`, then `offset`, then
/// `limit` (which shares the last rank with the stages fireemu does not run: the checks end
/// at the first such stage, and a second `limit` is refused as repeated).
fn stage_rank(name: &str) -> u8 {
    match name {
        "search" => 0,
        "where" | "select" => 1,
        "offset" => 2,
        _ => 3,
    }
}

/// The official emulator's argument checks on a stage the local executor does not run
/// (`add_fields`, `distinct`, `aggregate`), answered before the stage is refused as
/// unsupported, in the official order: the stage's arity, each alias, then an empty map, which
/// is `deferred` until every stage's other checks are done. Production answers them alike
/// (FS-ENT-ORACLE O-1 `results/metadata#aggregate`, O-4 `o4/stages#*`), so both profiles
/// do. A `select`, `limit` or `offset` after an unrun stage gets its checks here too.
///
/// Production answered a nonexistent function before the empty map (O-4
/// `#select-empty-then-unknown-function`), and where it puts the other checks fireemu does not
/// make for what it does not decode is unrecorded. So under strict a stage's values must pass
/// fireemu's own checks (an accumulator must be `count` of at most one field, as recorded),
/// and any other stage ends the checks: the pipeline is refused as unobserved there.
#[allow(clippy::too_many_lines)]
fn check_unrun_alias_stage(
    stage: &pb::pipeline::Stage,
    deferred: &mut Option<Status>,
    unrecorded: Unrecorded,
) -> Result<(), Status> {
    let strict = unrecorded == Unrecorded::Refuse;
    let unvalidated = || {
        Status::unimplemented(format!(
            "pipeline stage {:?} holds what is not checked locally; the order of its checks is not observed locally",
            stage.name
        ))
    };
    // Every one-argument aggregate gets the arity text before any check of its map
    // (FS-ENT-ORACLE O-1 `results/metadata#aggregate`, O-4 `o4/stages#aggregate-one-*`).
    if stage.name == "aggregate" && stage.args.len() == 1 {
        return Err(Status::invalid_argument(
            "Stage 'aggregate(accumulators: Map[FieldPath, Expr], groups: Map[FieldPath, Expr])' takes [2..2] argument(s), received 1.",
        ));
    }
    let name = stage.name.as_str();
    // A limit or offset after an unrun stage: its argument checks come first, as above.
    if matches!(name, "limit" | "offset") {
        count_argument(stage, unrecorded)?;
        return Ok(());
    }
    if !matches!(name, "aggregate" | "add_fields" | "distinct" | "select") {
        return if strict { Err(unvalidated()) } else { Ok(()) };
    }
    if strict && !unrun_values_validated(stage, unrecorded) {
        return Err(unvalidated());
    }
    // A select after an unrun stage: the official emulator checks its aliases too, with the
    // select texts, and answers an empty map last.
    if name == "select" {
        let aliases: Vec<&String> = stage
            .args
            .iter()
            .filter_map(map_fields)
            .flat_map(ordered_keys)
            .collect();
        for alias in aliases {
            decode_alias(alias)?;
        }
        if let Some(text) = stage
            .args
            .iter()
            .filter_map(map_fields)
            .flat_map(sorted_values)
            .filter(|value| expression_kind(value).is_none())
            .find_map(literal_value_error)
        {
            return Err(Status::invalid_argument(text));
        }
        if stage.args.first().is_some_and(is_empty_map) {
            deferred.get_or_insert_with(|| {
                Status::invalid_argument("The 'select(...)' stage requires at least one field.")
            });
        }
        return Ok(());
    }
    let stage_aliases: Vec<&String> = stage
        .args
        .iter()
        .filter_map(map_fields)
        .flat_map(ordered_keys)
        .collect();
    // The official emulator checks each alias's syntax, then its reserved first segment, then
    // its length (firebase-tools 15.28.2, Firestore emulator 1.22.0; production recorded the
    // syntax and length texts alone, O-4 `o4/stages#add-fields-*-alias*`).
    for alias in &stage_aliases {
        match parse_alias(alias) {
            Err(e) if !is_length_refusal(&e) => return Err(e),
            _ => {}
        }
    }
    let values_of = |alias: &str| {
        stage
            .args
            .iter()
            .filter_map(map_fields)
            .find_map(|fields| fields.get(alias))
    };
    for alias in &stage_aliases {
        // `__name__` assigned itself is no overwrite: the official emulator accepts it.
        let itself = alias.as_str() == "__name__"
            && values_of(alias).is_some_and(|v| {
                matches!(&v.value_type, Some(pb::value::ValueType::FieldReferenceValue(f)) if f == "__name__")
            });
        if let Some(text) = reserved_alias(name, alias).filter(|_| !itself) {
            // Production has not answered a reserved alias of a stage fireemu does not run.
            return Err(if strict {
                Status::unimplemented(format!("{text}; this text is not observed locally"))
            } else {
                Status::invalid_argument(text)
            });
        }
    }
    // The official emulator's checks of the stages that assign top-level fields only, and of an
    // aggregate's names (production has not answered them, so strict refuses them).
    if let Some(text) = unrun_stage_name_error(stage) {
        return Err(if strict {
            Status::unimplemented(format!("{text}; this text is not observed locally"))
        } else {
            Status::invalid_argument(text)
        });
    }
    for alias in &stage_aliases {
        parse_alias(alias)?;
    }
    // A malformed vector or `__type__` among the stage's values: the official emulator refuses
    // it after the aliases and before an empty map (strict refused such a value above).
    if let Some(text) = stage
        .args
        .iter()
        .filter_map(map_fields)
        .flat_map(sorted_values)
        .filter(|value| expression_kind(value).is_none())
        .find_map(literal_value_error)
    {
        return Err(Status::invalid_argument(text));
    }
    let empty = match name {
        "aggregate" => map_fields(&stage.args[0])
            .is_some_and(std::collections::HashMap::is_empty)
            .then(|| "The 'aggregate(...)' stage requires at least one accumulator.".to_owned()),
        _ => stage
            .args
            .iter()
            .any(is_empty_map)
            .then(|| format!("The '{name}(...)' stage requires at least one field.")),
    };
    if let Some(text) = empty {
        deferred.get_or_insert_with(|| Status::invalid_argument(text));
    }
    Ok(())
}

/// Whether every value of an unrun `select`, `add_fields`, `distinct` or two-argument
/// `aggregate` passes fireemu's own checks: each argument is an alias map, each value decodes
/// as an operand, and each accumulator is `count` of no argument or one field (the only
/// accumulator production answered, O-1 `results/metadata#aggregate`, O-4 `o4/stages#*`).
fn unrun_values_validated(stage: &pb::pipeline::Stage, unrecorded: Unrecorded) -> bool {
    use pb::value::ValueType as V;
    let operands = |value: &pb::Value| {
        map_fields(value).is_some_and(|fields| {
            fields
                .values()
                .all(|v| decode_operand(v, unrecorded).is_ok())
        })
    };
    let accumulators = |value: &pb::Value| {
        map_fields(value).is_some_and(|fields| {
            fields.values().all(|v| match v.value_type.as_ref() {
                Some(V::FunctionValue(f)) => {
                    f.name == "count"
                        && f.options.is_empty()
                        && f.args.len() <= 1
                        && f.args.iter().all(|arg| {
                            matches!(&arg.value_type, Some(V::FieldReferenceValue(path))
                                if FieldPath::parse(path).is_ok())
                        })
                }
                _ => false,
            })
        })
    };
    match (stage.name.as_str(), stage.args.as_slice()) {
        ("aggregate", [accumulated, groups]) => accumulators(accumulated) && operands(groups),
        // A one-argument aggregate never gets here: its arity text comes first.
        (_, [aliases]) => operands(aliases),
        _ => false,
    }
}

/// The official emulator's refusal of a `distinct` or `aggregate` alias that names a nested
/// field, and of an `aggregate` whose accumulators and groups share a name.
fn unrun_stage_name_error(stage: &pb::pipeline::Stage) -> Option<String> {
    let name = stage.name.as_str();
    if !matches!(name, "distinct" | "aggregate") {
        return None;
    }
    let mut aliases: Vec<&String> = stage
        .args
        .iter()
        .filter_map(map_fields)
        .flat_map(|fields| fields.keys())
        .collect();
    aliases.sort();
    if let Some(nested) = aliases.iter().find(|alias| {
        FieldPath::parse_allowing_reserved(alias).is_ok_and(|path| path.segments().len() > 1)
    }) {
        return Some(format!(
            "The nested field reference '{nested}' is not supported in its current use case.\n\nCertain stages like `aggregate(...)` or `unnest(...)` only support assigning to top-level fields. This means you cannot use an alias like 'foo.bar' to assign the result to a nested field. If you want to use an alias that has a dot in it, escape the path with backticks, like `foo.bar`.\n\nDepending on the SDK, this can be done like so:`.distinct(field(\"address.city\").as(\"`address.city`\"))`"
        ));
    }
    if let [accumulators, groups] = stage.args.as_slice() {
        if let (Some(a), Some(g)) = (map_fields(accumulators), map_fields(groups)) {
            let mut shared: Vec<&String> = a.keys().filter(|k| g.contains_key(*k)).collect();
            shared.sort();
            if !shared.is_empty() {
                let list = shared
                    .iter()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Some(format!(
                    "The 'aggregate(...)' stage cannot have overlapping field names: [{list}]"
                ));
            }
        }
    }
    None
}

/// Whether an alias refusal is the length one (`PROPERTY_PATH_TOO_LONG`).
fn is_length_refusal(error: &Status) -> bool {
    error.message().starts_with("The field reference '")
}

/// The official emulator's refusal of an alias whose first segment is reserved, in a stage
/// fireemu does not run (`__name__` cannot be overwritten, `__x__` is reserved).
fn reserved_alias(stage: &str, alias: &str) -> Option<String> {
    let unquoted = unquoted_alias(alias);
    let first = match FieldPath::parse_allowing_reserved(alias) {
        Ok(path) => path.segments().first().cloned()?,
        Err(_) => unquoted.split('.').next()?.to_owned(),
    };
    if first == "__name__" {
        Some(format!(
            "Stage '{stage}': field name '__name__' is reserved and can not be overwritten."
        ))
    } else if is_reserved_name(&first) {
        Some(format!(
            "Stage '{stage}': field name '{first}' is reserved."
        ))
    } else {
        None
    }
}

/// A wire map's values in the order of [`ordered_keys`].
fn sorted_values(fields: &std::collections::HashMap<String, pb::Value>) -> Vec<&pb::Value> {
    ordered_keys(fields)
        .into_iter()
        .map(|key| &fields[key])
        .collect()
}

/// Each key list of a body's maps (sorted) with its wire order, `None` where two maps disagree.
type WireKeys = std::collections::HashMap<Vec<String>, Option<Vec<String>>>;

std::thread_local! {
    /// The wire order of the maps of the request being compiled, by their sorted key list,
    /// where the transport kept it (a REST body); `None` for a key list two maps of the body
    /// share in different orders.
    static WIRE_KEYS: std::cell::RefCell<Option<WireKeys>> = const { std::cell::RefCell::new(None) };
}

/// Makes the wire order of a body's maps available to the checks while it lives.
struct WireOrderScope;

impl WireOrderScope {
    fn enter(order: Option<&KeyOrder>) -> Self {
        let table = order.map(|order| {
            let mut table = WireKeys::new();
            for keys in order.objects() {
                let mut sorted = keys.to_vec();
                sorted.sort();
                table
                    .entry(sorted)
                    .and_modify(|known| {
                        if known.as_deref() != Some(keys) {
                            *known = None;
                        }
                    })
                    .or_insert_with(|| Some(keys.to_vec()));
            }
            table
        });
        WIRE_KEYS.with(|cell| *cell.borrow_mut() = table);
        Self
    }
}

impl Drop for WireOrderScope {
    fn drop(&mut self) {
        WIRE_KEYS.with(|cell| *cell.borrow_mut() = None);
    }
}

/// A wire map's keys in the request's order where the transport kept it and no other map of
/// the body holds the same keys in another order, else in key order (a decoded gRPC map keeps
/// none, and a refusal named first must be the same on every run). The official emulator
/// 1.22.0 reads a literal's entries in wire order (`PX1d` r6 review S2).
fn ordered_keys(fields: &std::collections::HashMap<String, pb::Value>) -> Vec<&String> {
    let mut keys: Vec<&String> = fields.keys().collect();
    keys.sort();
    let sorted: Vec<String> = keys.iter().map(|k| (*k).clone()).collect();
    let wire = WIRE_KEYS.with(|cell| {
        cell.borrow()
            .as_ref()
            .and_then(|table| table.get(&sorted).cloned().flatten())
    });
    match wire {
        Some(order) => order
            .iter()
            .filter_map(|k| fields.get_key_value(k).map(|(key, _)| key))
            .collect(),
        None => keys,
    }
}

/// The fields of a wire map value.
fn map_fields(value: &pb::Value) -> Option<&std::collections::HashMap<String, pb::Value>> {
    match value.value_type.as_ref() {
        Some(pb::value::ValueType::MapValue(map)) => Some(&map.fields),
        _ => None,
    }
}

/// Whether a wire value is an empty map.
fn is_empty_map(value: &pb::Value) -> bool {
    matches!(&value.value_type, Some(pb::value::ValueType::MapValue(map)) if map.fields.is_empty())
}

/// A map key a plain path segment names: `[a-zA-Z_][a-zA-Z_0-9]*`, not reserved (`__x__`).
fn is_plain_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !is_reserved_name(key)
}

/// The most fields one `select` stage sets.
const MAX_SELECT_FIELDS: usize = 64;

/// A name like `__x__`, which Firestore reserves (`__.*__`, `____` included).
fn is_reserved_name(segment: &str) -> bool {
    segment.len() >= 4 && segment.starts_with("__") && segment.ends_with("__")
}

/// A collection or document id the official emulator refuses as reserved: `__x__`, but not
/// `____`, which it accepts as a collection id and a document id (1.22.0, probed 2026-10-21;
/// strict refuses `____` in a reference as unobserved, see [`reference_outside`]).
fn is_reserved_id(segment: &str) -> bool {
    segment.len() > 4 && is_reserved_name(segment)
}

/// A projected output row as a pipeline result document: fields only, without a name or
/// times (as the official emulator answers after a select; production is unobserved). A
/// pipeline without a select answers the source documents themselves instead.
#[must_use]
pub fn result_document(
    fields: &std::collections::BTreeMap<String, fireemu_core_firestore::value::Value>,
) -> pb::Document {
    pb::Document {
        fields: fields
            .iter()
            .map(|(k, v)| (k.clone(), crate::encode::encode_value(v)))
            .collect(),
        ..Default::default()
    }
}

/// The size at which a pipeline answer is cut into another response. Production answered up to
/// four documents in one response (FS-ENT-ORACLE O-1, `results/metadata` and `results/order`);
/// where it starts a second one is unobserved, so a response grows to this target and a single
/// document larger than it is never split.
pub(crate) const RESULT_BATCH_BYTES: usize = 1_048_576;

/// What a response's `execution_time` and framing add to the size of its documents.
const RESPONSE_OVERHEAD_BYTES: usize = 16;

/// Packs result documents into responses in arrival order: one response holds every result
/// until the target size is reached, so a small answer is a single response.
#[derive(Debug, Default)]
pub(crate) struct ResultBatcher {
    results: Vec<pb::Document>,
    bytes: usize,
}

impl ResultBatcher {
    /// Adds `document`. When it would push the held results past the target, those results are
    /// returned as a finished batch and `document` starts the next one.
    pub(crate) fn push(&mut self, document: pb::Document) -> Option<Vec<pb::Document>> {
        // One tag plus at most ten bytes for the length-delimited document prefix.
        let document_bytes = prost::Message::encoded_len(&document).saturating_add(11);
        let full = !self.results.is_empty()
            && RESPONSE_OVERHEAD_BYTES
                .saturating_add(self.bytes)
                .saturating_add(document_bytes)
                > RESULT_BATCH_BYTES;
        let finished = full.then(|| self.take());
        self.bytes = self.bytes.saturating_add(document_bytes);
        self.results.push(document);
        finished
    }

    /// Whether no result is held.
    pub(crate) fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// The held results, leaving the batcher empty.
    pub(crate) fn take(&mut self) -> Vec<pb::Document> {
        self.bytes = 0;
        std::mem::take(&mut self.results)
    }
}

/// The responses for a whole answer: every result in order, cut by [`ResultBatcher`]; a pipeline
/// with no result answers one response holding only the execution time.
pub(crate) fn pack_results(
    documents: Vec<pb::Document>,
    execution_time: Option<prost_types::Timestamp>,
) -> Vec<pb::ExecutePipelineResponse> {
    let response = |results| pb::ExecutePipelineResponse {
        results,
        execution_time,
        ..Default::default()
    };
    let mut batcher = ResultBatcher::default();
    let mut responses = Vec::new();
    for document in documents {
        responses.extend(batcher.push(document).map(response));
    }
    if !batcher.is_empty() || responses.is_empty() {
        responses.push(response(batcher.take()));
    }
    responses
}

/// A `RunQuery` result document as an executor row.
pub fn document_row(document: &pb::Document) -> Result<pipeline_exec::Row, Status> {
    let path = DocumentPath::from_resource_name(&document.name).ok_or_else(|| {
        Status::internal(format!(
            "pipeline input {:?} is not a document name",
            document.name
        ))
    })?;
    let fields = document
        .fields
        .iter()
        .map(|(k, v)| {
            crate::decode::decode_value(v)
                .map(|value| (k.clone(), value))
                .map_err(|e| Status::internal(format!("pipeline input field {k:?}: {e}")))
        })
        .collect::<Result<_, _>>()?;
    Ok(pipeline_exec::Row { path, fields })
}

fn decode_equal_filter(
    stage: &pb::pipeline::Stage,
) -> Result<pb::structured_query::Filter, Status> {
    let Some(value) = stage.args.first() else {
        return Err(Status::invalid_argument(
            "where requires an equal expression",
        ));
    };
    let Some(pb::value::ValueType::FunctionValue(function)) = value.value_type.as_ref() else {
        return Err(Status::invalid_argument(
            "where requires an equal expression",
        ));
    };
    if function.name != "equal" {
        return Err(Status::unimplemented(
            "where expression is unsupported locally",
        ));
    }
    if function.args.len() != 2 || !function.options.is_empty() {
        return Err(Status::invalid_argument(
            "equal requires exactly two arguments and no options",
        ));
    }
    let Some(pb::value::ValueType::FieldReferenceValue(field)) =
        function.args[0].value_type.as_ref()
    else {
        return Err(if function.args[0].value_type.is_none() {
            Status::invalid_argument("equal first argument is missing")
        } else {
            Status::unimplemented("equal first argument is unsupported locally")
        });
    };
    let parsed = FieldPath::parse(field).map_err(|e| Status::invalid_argument(e.to_string()))?;
    if parsed.segments().len() != 1 || parsed.is_document_name() {
        return Err(Status::unimplemented(
            "nested and document-name where fields are unsupported locally",
        ));
    }
    let Some(literal) = function.args[1].value_type.as_ref() else {
        return Err(Status::invalid_argument("where literal is missing"));
    };
    if matches!(
        literal,
        pb::value::ValueType::ArrayValue(_)
            | pb::value::ValueType::MapValue(_)
            | pb::value::ValueType::FieldReferenceValue(_)
            | pb::value::ValueType::VariableReferenceValue(_)
            | pb::value::ValueType::FunctionValue(_)
            | pb::value::ValueType::PipelineValue(_)
    ) {
        return Err(Status::unimplemented(
            "where literal is unsupported locally",
        ));
    }
    Ok(equal_filter(field.clone(), &function.args[1]))
}

/// The `RunQuery` filter equivalent to `equal(field, literal)` for a scalar literal: null
/// and NaN become the unary `IS_NULL` / `IS_NAN`, anything else a field equality.
fn equal_filter(field_path: String, value: &pb::Value) -> pb::structured_query::Filter {
    let field_ref = pb::structured_query::FieldReference { field_path };
    let filter_type = match &value.value_type {
        Some(pb::value::ValueType::NullValue(_)) => {
            pb::structured_query::filter::FilterType::UnaryFilter(
                pb::structured_query::UnaryFilter {
                    op: pb::structured_query::unary_filter::Operator::IsNull as i32,
                    operand_type: Some(pb::structured_query::unary_filter::OperandType::Field(
                        field_ref,
                    )),
                },
            )
        }
        Some(pb::value::ValueType::DoubleValue(double)) if double.is_nan() => {
            pb::structured_query::filter::FilterType::UnaryFilter(
                pb::structured_query::UnaryFilter {
                    op: pb::structured_query::unary_filter::Operator::IsNan as i32,
                    operand_type: Some(pb::structured_query::unary_filter::OperandType::Field(
                        field_ref,
                    )),
                },
            )
        }
        _ => pb::structured_query::filter::FilterType::FieldFilter(
            pb::structured_query::FieldFilter {
                field: Some(field_ref),
                op: pb::structured_query::field_filter::Operator::Equal as i32,
                value: Some(value.clone()),
            },
        ),
    };
    pb::structured_query::Filter {
        filter_type: Some(filter_type),
    }
}

/// A wire value as a validation argument. A nested pipeline is typed but its stages are
/// not validated (only `union` takes one).
fn arg(value: &pb::Value) -> Result<Arg, Status> {
    use pb::value::ValueType as V;
    Ok(match &value.value_type {
        None | Some(V::NullValue(_)) => Arg::Null,
        Some(V::BooleanValue(_)) => Arg::Bool,
        Some(V::IntegerValue(n)) => Arg::Integer(*n),
        Some(V::DoubleValue(d)) => Arg::Double(*d),
        Some(V::TimestampValue(_)) => Arg::Timestamp,
        Some(V::StringValue(s)) => Arg::String(s.clone()),
        Some(V::BytesValue(_)) => Arg::Bytes,
        Some(V::ReferenceValue(r)) => Arg::Reference(r.clone()),
        Some(V::GeoPointValue(_)) => Arg::GeoPoint,
        Some(V::ArrayValue(a)) => {
            Arg::Array(a.values.iter().map(arg).collect::<Result<Vec<_>, _>>()?)
        }
        Some(V::MapValue(m)) => {
            let mut entries = m
                .fields
                .iter()
                .map(|(k, v)| arg(v).map(|a| (k.clone(), a)))
                .collect::<Result<Vec<_>, _>>()?;
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Arg::Map(entries)
        }
        Some(V::FieldReferenceValue(f)) => Arg::Field(f.clone()),
        Some(V::VariableReferenceValue(v)) => Arg::Variable(v.clone()),
        Some(V::FunctionValue(f)) => Arg::Function {
            name: f.name.clone(),
            args: f.args.iter().map(arg).collect::<Result<Vec<_>, _>>()?,
        },
        Some(V::PipelineValue(_)) => Arg::Pipeline,
    })
}

fn with_code(mut status: Status, code: &str) -> Status {
    if let Ok(v) = code.parse() {
        status.metadata_mut().insert("fireemu-code", v);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference constants, as the official emulator 1.22.0 answered each (probed 2026-10-21).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn reference_constants_get_the_official_texts() {
        let d = "projects/demo-app/databases/(default)/documents";
        let a1501 = "a".repeat(1501);
        let a1500 = "a".repeat(1500);
        let parent =
            |name: &str, rest: &str| Some(format!("Document parent name \"{name}\" {rest}"));
        let cases: Vec<(String, Option<String>)> = vec![
            (format!("{d}/c/d"), None),
            (d.to_owned(), None),
            (format!("{d}/c/{a1500}"), None),
            (format!("{d}/{a1500}/d"), None),
            (format!("{d}/____/____"), None),
            (
                format!("{d}/c/_____"),
                Some("Resource id \"_____\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/__x__/d"),
                Some("Collection id \"__x__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/c/__x__"),
                Some("Resource id \"__x__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/c/__name__"),
                Some("Resource id \"__name__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/c/d/__x__/e"),
                Some("Collection id \"__x__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/__x__"),
                Some("Collection id \"__x__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/{a1501}/__x__"),
                Some("Resource id \"__x__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/./d"),
                parent(
                    &format!("{d}/./d"),
                    "contains a collection id \".\" at index 48.",
                ),
            ),
            (
                format!("{d}/c/."),
                parent(
                    &format!("{d}/c/."),
                    "contains a resource id \".\" at index 50.",
                ),
            ),
            (
                format!("{d}/c/.."),
                parent(
                    &format!("{d}/c/.."),
                    "contains a resource id \"..\" at index 50.",
                ),
            ),
            (
                format!("{d}/../d"),
                parent(
                    &format!("{d}/../d"),
                    "contains a collection id \"..\" at index 48.",
                ),
            ),
            (
                format!("{d}/c/{a1501}"),
                Some("Path element can be at most 1,500 bytes.".to_owned()),
            ),
            (
                format!("{d}/{a1501}/d"),
                Some("The kind / collection group can be at most 1,500 bytes.".to_owned()),
            ),
            (
                "projects/demo-app/databases/(default)/c/d".to_owned(),
                parent(
                    "projects/demo-app/databases/(default)/c/d",
                    "lacks \"documents\" at index 38.",
                ),
            ),
            (
                "projects//databases/(default)/documents/c/d".to_owned(),
                parent(
                    "projects//databases/(default)/documents/c/d",
                    "lacks a project id at index 9.",
                ),
            ),
            (
                "projects/demo-app/databases//documents/c/d".to_owned(),
                parent(
                    "projects/demo-app/databases//documents/c/d",
                    "lacks a database id at index 28.",
                ),
            ),
            (
                format!("{d}/c/d/"),
                parent(&format!("{d}/c/d/"), "has invalid trailing \"/\"."),
            ),
            (
                format!("{d}/c//d"),
                parent(&format!("{d}/c//d"), "lacks a resource id at index 50."),
            ),
            (
                format!("{d}/"),
                parent(&format!("{d}/"), "is invalid: Omit trailing \"/\"."),
            ),
            (
                format!("{d}/c"),
                parent(
                    &format!("{d}/c"),
                    &format!("lacks \"/\" at index {}.", d.len() + 2),
                ),
            ),
            (
                "/c".to_owned(),
                Some("Document parent \"/c\" not recognized.".to_owned()),
            ),
            (
                "garbage".to_owned(),
                parent("garbage", "lacks \"projects\" at index 0."),
            ),
            (
                "projects".to_owned(),
                parent("projects", "lacks \"/\" at index 8."),
            ),
            (
                "projects/other/databases/(default)/documents/c/d".to_owned(),
                None,
            ),
            // The prefix, read left to right.
            ("projects/demo-app/databases/(default)".to_owned(), None),
            ("projects/o/databases/zz".to_owned(), None),
            (
                "projectsx".to_owned(),
                parent("projectsx", "lacks \"/\" at index 8."),
            ),
            (String::new(), parent("", "lacks \"projects\" at index 0.")),
            (
                "projects/".to_owned(),
                parent("projects/", "has invalid trailing \"/\"."),
            ),
            (
                "projects//".to_owned(),
                parent("projects//", "lacks a project id at index 9."),
            ),
            (
                "projects/p".to_owned(),
                parent("projects/p", "lacks \"/\" at index 10."),
            ),
            (
                "projects/demo-app/".to_owned(),
                parent("projects/demo-app/", "has invalid trailing \"/\"."),
            ),
            (
                "projects/demo-app/x/".to_owned(),
                parent("projects/demo-app/x/", "lacks \"databases\" at index 18."),
            ),
            (
                "projects/demo-app/databases".to_owned(),
                parent("projects/demo-app/databases", "lacks \"/\" at index 27."),
            ),
            (
                "projects/demo-app/databasesx/y".to_owned(),
                parent("projects/demo-app/databasesx/y", "lacks \"/\" at index 27."),
            ),
            (
                "projects/demo-app/databases/".to_owned(),
                parent(
                    "projects/demo-app/databases/",
                    "has invalid trailing \"/\".",
                ),
            ),
            (
                "projects/demo-app/databases//".to_owned(),
                parent(
                    "projects/demo-app/databases//",
                    "lacks a database id at index 28.",
                ),
            ),
            (
                "projects/demo-app/databases/(default)/".to_owned(),
                parent(
                    "projects/demo-app/databases/(default)/",
                    "has invalid trailing \"/\".",
                ),
            ),
            (
                "projects/demo-app/databases/(default)//".to_owned(),
                parent(
                    "projects/demo-app/databases/(default)//",
                    "lacks \"documents\" at index 38.",
                ),
            ),
            (
                format!("{d}x/c"),
                parent(&format!("{d}x/c"), "lacks \"/\" at index 47."),
            ),
            // Below `documents`: segment by segment, then trailing, parity, depth, length.
            (
                format!("{d}//"),
                parent(&format!("{d}//"), "lacks a collection id at index 48."),
            ),
            (
                format!("{d}/c/d//"),
                parent(&format!("{d}/c/d//"), "lacks a collection id at index 52."),
            ),
            (
                format!("{d}/./"),
                parent(
                    &format!("{d}/./"),
                    "contains a collection id \".\" at index 48.",
                ),
            ),
            (
                format!("{d}/__x__/"),
                Some("Collection id \"__x__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/__x__/d/./e"),
                Some("Collection id \"__x__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/c/./__x__/e"),
                parent(
                    &format!("{d}/c/./__x__/e"),
                    "contains a resource id \".\" at index 50.",
                ),
            ),
            (
                format!("{d}/{a1501}//d"),
                parent(
                    &format!("{d}/{a1501}//d"),
                    "lacks a resource id at index 1550.",
                ),
            ),
            (
                format!("{d}/{a1501}/"),
                parent(&format!("{d}/{a1501}/"), "has invalid trailing \"/\"."),
            ),
            (
                format!("{d}/{a1501}"),
                parent(&format!("{d}/{a1501}"), "lacks \"/\" at index 1549."),
            ),
            (format!("{d}/{}", deep(200)), None),
            (
                format!("{d}/{}", deep(202)),
                Some("A key path cannot have more than 100 elements.".to_owned()),
            ),
            (
                format!("{d}/{}/{a1501}", deep(201)),
                Some("A key path cannot have more than 100 elements.".to_owned()),
            ),
            (
                format!("{d}/{}/__x__", deep(201)),
                Some("Resource id \"__x__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("{d}/{}", deep(203)),
                parent(
                    &format!("{d}/{}", deep(203)),
                    &format!("lacks \"/\" at index {}.", d.len() + 1 + deep(203).len()),
                ),
            ),
        ];
        for (name, want) in cases {
            assert_eq!(reference_literal_error(&name), want, "{name:.120}");
        }
    }

    /// A constant as the official emulator answers it: timestamps in microseconds and a
    /// database root as its documents root, inside arrays and maps too (probed 2026-10-21).
    #[test]
    fn constants_answer_microseconds_and_the_documents_root() {
        use fireemu_core_firestore::value::{Timestamp, Value};
        let stamp = |nanos| Value::Timestamp(Timestamp::new(1_577_836_800, nanos).unwrap());
        let root = |name: &str| Value::Reference(name.to_owned());
        for (constant, want) in [
            (stamp(123_456_789), stamp(123_456_000)),
            (stamp(999), stamp(0)),
            (stamp(1000), stamp(1000)),
            (
                root("projects/p/databases/d"),
                root("projects/p/databases/d/documents"),
            ),
            (
                root("projects/p/databases/d/documents"),
                root("projects/p/databases/d/documents"),
            ),
            (
                root("projects/p/databases/d/documents/c/d"),
                root("projects/p/databases/d/documents/c/d"),
            ),
            (
                Value::Array(vec![stamp(1_001), root("projects/p/databases/d")]),
                Value::Array(vec![stamp(1_000), root("projects/p/databases/d/documents")]),
            ),
            (
                Value::Map([("k".to_owned(), stamp(2_999))].into_iter().collect()),
                Value::Map([("k".to_owned(), stamp(2_000))].into_iter().collect()),
            ),
        ] {
            assert_eq!(canonical_constant(constant.clone()), want, "{constant:?}");
        }
        for (name, root) in [
            ("projects/p/databases/d", true),
            ("projects/p/databases/(default)", true),
            ("projects//databases/d", false),
            ("projects/p/databases/", false),
            ("projects/p/databasesx/d", false),
            ("projectsx/p/databases/d", false),
            ("projects/p/databases/d/documents", false),
            ("projects/p/databases", false),
        ] {
            assert_eq!(is_database_root(name), root, "{name}");
        }
    }

    /// `n` path segments alternating `c` and `d`.
    fn deep(n: usize) -> String {
        ["c", "d"]
            .iter()
            .cycle()
            .take(n)
            .copied()
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Under strict, a reference outside the request's documents, or deeper than 100 key path
    /// elements, is refused before any row; one inside is left to the other checks.
    #[test]
    fn strict_refuses_references_outside_or_too_deep() {
        let own = "projects/p/databases/db/documents";
        let reference = |name: String| pb::Value {
            value_type: Some(pb::value::ValueType::ReferenceValue(name)),
        };
        for (name, outside) in [
            (format!("{own}/c/d"), false),
            (own.to_owned(), true),
            (format!("{own}/{}", deep(200)), false),
            (format!("{own}/{}", deep(201)), false),
            (format!("{own}/{}", deep(202)), true),
            ("projects/p/databases/db".to_owned(), true),
            ("projects/p/databases/db2/documents/c/d".to_owned(), true),
            ("projects/p/databases/db/documentsx/c".to_owned(), true),
            ("projects/q/databases/db/documents/c/d".to_owned(), true),
            (format!("{own}/c/____"), true),
            (format!("{own}/____/d"), true),
            (format!("{own}/c/___"), false),
            (format!("{own}/c/__x__"), true),
        ] {
            assert_eq!(
                reference_outside(&reference(name.clone()), own).is_some(),
                outside,
                "{name:.80}"
            );
        }
        // Inside every container a constant can sit in.
        let elsewhere = || reference("projects/q/databases/db/documents/c/d".to_owned());
        let function =
            |args: Vec<pb::Value>, options: std::collections::HashMap<String, pb::Value>| {
                pb::Value {
                    value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
                        name: "equal".to_owned(),
                        args,
                        options,
                    })),
                }
            };
        for holder in [
            pb::Value {
                value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
                    values: vec![reference(format!("{own}/c/d")), elsewhere()],
                })),
            },
            pb::Value {
                value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                    fields: [("k".to_owned(), elsewhere())].into_iter().collect(),
                })),
            },
            function(vec![elsewhere()], std::collections::HashMap::new()),
            function(
                Vec::new(),
                [("o".to_owned(), elsewhere())].into_iter().collect(),
            ),
            pb::Value {
                value_type: Some(pb::value::ValueType::PipelineValue(pb::Pipeline {
                    stages: vec![pb::pipeline::Stage {
                        name: "where".to_owned(),
                        args: vec![elsewhere()],
                        options: std::collections::HashMap::new(),
                    }],
                })),
            },
        ] {
            assert!(reference_outside(&holder, own).is_some(), "{holder:?}");
        }
    }

    /// The field path inside a literal (its keys joined with `.`, UTF-8 bytes) holds at most
    /// 1500 bytes; the official emulator 1.22.0 names the key that crosses (review r9 M1). An
    /// array keeps the path of the map around it, and a vector's own keys do not count.
    #[test]
    fn a_literal_field_path_holds_at_most_1500_bytes() {
        use pb::value::ValueType as V;
        fn map(entries: Vec<(String, pb::Value)>) -> pb::Value {
            pb::Value {
                value_type: Some(V::MapValue(pb::MapValue {
                    fields: entries.into_iter().collect(),
                })),
            }
        }
        let one = || pb::Value {
            value_type: Some(V::IntegerValue(1)),
        };
        let array = |values: Vec<pb::Value>| pb::Value {
            value_type: Some(V::ArrayValue(pb::ArrayValue { values })),
        };
        let vector = || {
            map(vec![
                (
                    "__type__".to_owned(),
                    pb::Value {
                        value_type: Some(V::StringValue("__vector__".to_owned())),
                    },
                ),
                (
                    "value".to_owned(),
                    array(vec![pb::Value {
                        value_type: Some(V::DoubleValue(1.0)),
                    }]),
                ),
            ])
        };
        let a = |n: usize| "a".repeat(n);
        let nested = |outer: &str, inner: String, leaf: pb::Value| {
            map(vec![(outer.to_owned(), map(vec![(inner, leaf)]))])
        };
        let too_long = |key: &str| Some(format!("Field name '{key}' can be at most 1,500 bytes."));
        for (literal, want) in [
            (nested("a", a(1498), one()), None),
            (nested("a", a(1499), one()), too_long(&a(1499))),
            (nested("a", a(1500), one()), too_long(&a(1500))),
            (nested("ab", a(1498), one()), too_long(&a(1498))),
            (
                map(vec![("a".to_owned(), nested("b", a(1497), one()))]),
                too_long(&a(1497)),
            ),
            (nested(&a(1499), "b".to_owned(), one()), too_long("b")),
            (nested("x.y", a(1497), one()), too_long(&a(1497))),
            (array(vec![nested("a", a(1499), one())]), too_long(&a(1499))),
            (
                map(vec![(
                    "a".to_owned(),
                    array(vec![map(vec![(a(1499), one())])]),
                )]),
                too_long(&a(1499)),
            ),
            (array(vec![map(vec![(a(1500), one())])]), None),
            (nested("a", a(1498), vector()), None),
            (map(vec![(a(1500), one()), ("b".to_owned(), one())]), None),
            // Depth first: the key under `a` is named before the long sibling `b...`.
            (
                map(vec![
                    ("a".to_owned(), map(vec![(a(1499), one())])),
                    (format!("b{}", a(1500)), one()),
                ]),
                too_long(&a(1499)),
            ),
        ] {
            assert_eq!(literal_value_error(&literal), want, "{literal:.200?}");
        }
        // Fifteen nested keys of 100 bytes: the fifteenth crosses (1514 bytes).
        let mut deep = one();
        for _ in 0..15 {
            deep = map(vec![(a(100), deep)]);
        }
        assert_eq!(literal_value_error(&deep), too_long(&a(100)));
    }

    /// Strict names the limit or the form a refused literal fails (review r10 S3).
    #[test]
    fn strict_names_the_literal_limit_it_refuses() {
        for (error, want) in [
            (
                "Field name 'x' can be at most 1,500 bytes.",
                "field path over 1500 bytes",
            ),
            (
                "String values can be at most 1,048,487 bytes.",
                "over 1,048,487 bytes",
            ),
            (
                "Bytes values can be at most 1,048,487 bytes.",
                "over 1,048,487 bytes",
            ),
            (
                "Vectors must be at most 2048 dimensions.",
                "over 2048 dimensions",
            ),
            (
                "Document parent name \"x\" lacks \"/\" at index 1.",
                "valid document name",
            ),
            (
                "Collection id \"__x__\" is invalid because it is reserved.",
                "valid document name",
            ),
            (
                "Resource id \"__x__\" is invalid because it is reserved.",
                "valid document name",
            ),
            (
                "Path element can be at most 1,500 bytes.",
                "valid document name",
            ),
            (
                "The kind / collection group can be at most 1,500 bytes.",
                "valid document name",
            ),
            (
                "A key path cannot have more than 100 elements.",
                "valid document name",
            ),
            (
                "Field __type__ must be a string; founds LONG.",
                "malformed vector or __type__",
            ),
        ] {
            assert!(unobserved_literal(error).contains(want), "{error}");
        }
    }

    /// Value limits of production, as the official emulator 1.22.0 answers them.
    #[test]
    fn value_limits_get_the_official_texts() {
        let string = |n: usize| pb::Value {
            value_type: Some(pb::value::ValueType::StringValue("a".repeat(n))),
        };
        let bytes = |n: usize| pb::Value {
            value_type: Some(pb::value::ValueType::BytesValue(vec![b'a'; n])),
        };
        assert_eq!(literal_value_error(&string(1_048_487)), None);
        assert_eq!(
            literal_value_error(&string(1_048_488)).as_deref(),
            Some("String values can be at most 1,048,487 bytes.")
        );
        assert_eq!(literal_value_error(&bytes(1_048_487)), None);
        assert_eq!(
            literal_value_error(&bytes(1_048_488)).as_deref(),
            Some("Bytes values can be at most 1,048,487 bytes.")
        );
        let keyed = |n: usize| pb::Value {
            value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                fields: [("a".repeat(n), string(1))].into_iter().collect(),
            })),
        };
        assert_eq!(literal_value_error(&keyed(1500)), None);
        assert_eq!(
            literal_value_error(&keyed(1501)),
            Some(format!(
                "Field name '{}' can be at most 1,500 bytes.",
                "a".repeat(1501)
            ))
        );
        let vector = |n: usize| pb::Value {
            value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                fields: [
                    ("__type__".to_owned(), string(0).clone()),
                    (
                        "value".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
                                values: vec![
                                    pb::Value {
                                        value_type: Some(pb::value::ValueType::DoubleValue(1.0))
                                    };
                                    n
                                ],
                            })),
                        },
                    ),
                ]
                .into_iter()
                .map(|(k, v)| {
                    if k == "__type__" {
                        (
                            k,
                            pb::Value {
                                value_type: Some(pb::value::ValueType::StringValue(
                                    "__vector__".to_owned(),
                                )),
                            },
                        )
                    } else {
                        (k, v)
                    }
                })
                .collect(),
            })),
        };
        assert_eq!(literal_value_error(&vector(2048)), None);
        assert_eq!(
            literal_value_error(&vector(2049)).as_deref(),
            Some("Vectors must be at most 2048 dimensions.")
        );
        // Inside an array, the same.
        let array = pb::Value {
            value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
                values: vec![string(1_048_488)],
            })),
        };
        assert!(literal_value_error(&array).is_some());
    }

    /// The collection stage's reference, as the official emulator 1.22.0 answered each form
    /// (probed 2026-10-21).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn collection_names_get_the_official_texts() {
        let d = "projects/demo-app/databases/(default)/documents";
        let lacks = |name: &str, at: usize| {
            Some(format!(
                "Collection name \"{name}\" lacks \"/\" at index {at}."
            ))
        };
        let trailing = |name: &str| {
            Some(format!(
                "Collection name \"{name}\" has invalid trailing \"/\"."
            ))
        };
        for (name, want) in [
            ("/c".to_owned(), None),
            ("/c/x/s".to_owned(), None),
            ("c".to_owned(), lacks("c", 0)),
            (String::new(), lacks("", 0)),
            ("c/x/s".to_owned(), lacks("c/x/s", 0)),
            (format!("{d}/c"), lacks(&format!("{d}/c"), 0)),
            ("/c/d".to_owned(), lacks("/c/d", 4)),
            ("/c/é/s/d".to_owned(), lacks("/c/é/s/d", 8)),
            ("/c/d/".to_owned(), trailing("/c/d/")),
            ("/c/".to_owned(), trailing("/c/")),
            ("/".to_owned(), trailing("/")),
            (
                "//c/d".to_owned(),
                Some("Collection name \"//c/d\" lacks a collection id at index 1.".to_owned()),
            ),
            (
                "/c//d".to_owned(),
                Some("Collection name \"/c//d\" lacks a resource id at index 3.".to_owned()),
            ),
            (
                "/ab/x//d".to_owned(),
                Some("Collection name \"/ab/x//d\" lacks a collection id at index 6.".to_owned()),
            ),
            (
                "/ab//d/e/".to_owned(),
                Some("Collection name \"/ab//d/e/\" lacks a resource id at index 4.".to_owned()),
            ),
            (
                "/.".to_owned(),
                Some(
                    "Collection name \"/.\" contains a collection id \".\" at index 1.".to_owned(),
                ),
            ),
            (
                "/c/../s".to_owned(),
                Some(
                    "Collection name \"/c/../s\" contains a resource id \"..\" at index 3."
                        .to_owned(),
                ),
            ),
            (
                "/c/d/.".to_owned(),
                Some(
                    "Collection name \"/c/d/.\" contains a collection id \".\" at index 5."
                        .to_owned(),
                ),
            ),
            (
                "/.//d".to_owned(),
                Some(
                    "Collection name \"/.//d\" contains a collection id \".\" at index 1."
                        .to_owned(),
                ),
            ),
            (
                "/./".to_owned(),
                Some(
                    "Collection name \"/./\" contains a collection id \".\" at index 1.".to_owned(),
                ),
            ),
            (
                "/c//.".to_owned(),
                Some("Collection name \"/c//.\" lacks a resource id at index 3.".to_owned()),
            ),
            (
                "/__c__//d".to_owned(),
                Some("Collection id \"__c__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                "/__c__/".to_owned(),
                Some("Collection id \"__c__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                "/c/__d__".to_owned(),
                Some("Resource id \"__d__\" is invalid because it is reserved.".to_owned()),
            ),
            ("/____".to_owned(), None),
            ("/__x".to_owned(), None),
            (format!("/{}", "a".repeat(1500)), None),
            (format!("/c/{}/s", "a".repeat(1500)), None),
            (
                format!("/{}", "a".repeat(1501)),
                Some("The kind / collection group can be at most 1,500 bytes.".to_owned()),
            ),
            (
                format!("/{}", "é".repeat(751)),
                Some("The kind / collection group can be at most 1,500 bytes.".to_owned()),
            ),
            (
                format!("/c/{}/s", "a".repeat(1501)),
                Some("Path element can be at most 1,500 bytes.".to_owned()),
            ),
            (
                format!("/c/{}/__d__", "a".repeat(1501)),
                Some("Collection id \"__d__\" is invalid because it is reserved.".to_owned()),
            ),
            (
                format!("/{}/", "a".repeat(1501)),
                trailing(&format!("/{}/", "a".repeat(1501))),
            ),
            (
                format!("/c/{}", "a".repeat(1501)),
                lacks(&format!("/c/{}", "a".repeat(1501)), 1504),
            ),
            (format!("/{}", deep(201)), None),
            (
                format!("/{}", deep(203)),
                Some("A key path cannot have more than 100 elements.".to_owned()),
            ),
            (
                format!("/{}/{}", deep(202), "a".repeat(1501)),
                Some("A key path cannot have more than 100 elements.".to_owned()),
            ),
            (
                format!("/{}/{}", deep(200), "a".repeat(1501)),
                Some("The kind / collection group can be at most 1,500 bytes.".to_owned()),
            ),
        ] {
            assert_eq!(collection_name_error(&name), want, "{name}");
        }
    }

    /// A literal map's keys come in the body's order while a REST body is compiled, in key order
    /// otherwise, and in key order where two maps of the body hold the same keys in other orders.
    #[test]
    fn literal_keys_follow_the_wire_order_while_it_is_known() {
        let fields = |keys: &[&str]| -> std::collections::HashMap<String, pb::Value> {
            keys.iter()
                .map(|k| ((*k).to_owned(), pb::Value::default()))
                .collect()
        };
        let map = fields(&["b", "a"]);
        let order = |text: &[u8]| {
            crate::rest::json_syntax::parse_with_key_order(text)
                .unwrap()
                .1
        };
        assert_eq!(ordered_keys(&map), ["a", "b"]);
        {
            let one = order(br#"{"x": {"b": 1, "a": 2}}"#);
            let _scope = WireOrderScope::enter(Some(&one));
            assert_eq!(ordered_keys(&map), ["b", "a"]);
            assert_eq!(ordered_keys(&fields(&["c", "d"])), ["c", "d"]);
        }
        assert_eq!(ordered_keys(&map), ["a", "b"]);
        let both = order(br#"{"x": {"b": 1, "a": 2}, "y": {"a": 1, "b": 2}}"#);
        let _scope = WireOrderScope::enter(Some(&both));
        assert_eq!(ordered_keys(&map), ["a", "b"]);
    }

    /// A wire order that does not name the select's aliases (a body whose map the transcoder
    /// changed) is not used: the aliases are checked in key order and set in path order.
    #[test]
    fn a_select_uses_only_a_wire_order_that_names_its_aliases() {
        let field = |name: &str| pb::Value {
            value_type: Some(pb::value::ValueType::FieldReferenceValue(name.to_owned())),
        };
        let stage = pb::pipeline::Stage {
            name: "select".to_owned(),
            args: vec![pb::Value {
                value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                    fields: [("m".to_owned(), field("i")), ("m.r".to_owned(), field("i"))]
                        .into_iter()
                        .collect(),
                })),
            }],
            ..Default::default()
        };
        let overlap = |order: Option<&[String]>| {
            decode_select(&stage, Unrecorded::OfficialEmulator, order)
                .unwrap_err()
                .details()
                .to_vec()
        };
        let named = |child: &str| {
            crate::production_status::select_overlapping_paths(child)
                .details()
                .to_vec()
        };
        let wire = ["m.r".to_owned(), "m".to_owned()];
        assert_eq!(overlap(Some(&wire)), named("m"));
        assert_eq!(overlap(None), named("m.r"));
        // Another length or other names: not this map's order.
        for order in [
            vec!["x".to_owned(), "m".to_owned()],
            vec!["m".to_owned()],
            vec!["m.r".to_owned(), "m".to_owned(), "x".to_owned()],
        ] {
            assert_eq!(overlap(Some(&order)), named("m.r"), "{order:?}");
        }
    }

    fn request(value: pb::Value) -> pb::ExecutePipelineRequest {
        let function = pb::Value {
            value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
                name: "equal".to_owned(),
                args: vec![
                    pb::Value {
                        value_type: Some(pb::value::ValueType::FieldReferenceValue(
                            "score".to_owned(),
                        )),
                    },
                    value,
                ],
                ..Default::default()
            })),
        };
        pb::ExecutePipelineRequest {
            database: "projects/p/databases/(default)".to_owned(),
            pipeline_type: Some(
                pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                    pb::StructuredPipeline {
                        pipeline: Some(pb::Pipeline {
                            stages: vec![
                                pb::pipeline::Stage {
                                    name: "collection".to_owned(),
                                    args: vec![pb::Value {
                                        value_type: Some(pb::value::ValueType::StringValue(
                                            "/items".to_owned(),
                                        )),
                                    }],
                                    ..Default::default()
                                },
                                pb::pipeline::Stage {
                                    name: "where".to_owned(),
                                    args: vec![function],
                                    ..Default::default()
                                },
                            ],
                        }),
                        ..Default::default()
                    },
                ),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn compile_where_equal_uses_field_and_unary_wire_filters() {
        let parent =
            crate::decode::parse_parent("projects/p/databases/(default)/documents").unwrap();
        let ordinary = compile_supported(
            &request(pb::Value {
                value_type: Some(pb::value::ValueType::StringValue("x".to_owned())),
            }),
            &parent,
        )
        .unwrap();
        assert!(matches!(ordinary.query.query_type,
            Some(pb::run_query_request::QueryType::StructuredQuery(pb::StructuredQuery {
                r#where: Some(pb::structured_query::Filter { filter_type: Some(
                    pb::structured_query::filter::FilterType::FieldFilter(pb::structured_query::FieldFilter { op, field: Some(field), value: Some(value) })
                )}), ..
            })) if op == pb::structured_query::field_filter::Operator::Equal as i32
                && field.field_path == "score"
                && value.value_type == Some(pb::value::ValueType::StringValue("x".to_owned()))));
        for (value, op) in [
            (
                pb::Value {
                    value_type: Some(pb::value::ValueType::NullValue(0)),
                },
                pb::structured_query::unary_filter::Operator::IsNull,
            ),
            (
                pb::Value {
                    value_type: Some(pb::value::ValueType::DoubleValue(f64::NAN)),
                },
                pb::structured_query::unary_filter::Operator::IsNan,
            ),
        ] {
            let compiled = compile_supported(&request(value), &parent).unwrap();
            assert!(matches!(compiled.query.query_type,
                Some(pb::run_query_request::QueryType::StructuredQuery(pb::StructuredQuery {
                    r#where: Some(pb::structured_query::Filter { filter_type: Some(
                        pb::structured_query::filter::FilterType::UnaryFilter(pb::structured_query::UnaryFilter { op: actual, operand_type: Some(pb::structured_query::unary_filter::OperandType::Field(field)) })
                    )}), ..
                })) if actual == op as i32 && field.field_path == "score"));
        }
    }
    mod framing {
        use super::*;
        use proptest::prelude::*;

        fn document(index: usize, padding: usize) -> pb::Document {
            pb::Document {
                name: format!("projects/p/databases/(default)/documents/c/{index}"),
                fields: [(
                    "pad".to_owned(),
                    pb::Value {
                        value_type: Some(pb::value::ValueType::StringValue("x".repeat(padding))),
                    },
                )]
                .into(),
                ..Default::default()
            }
        }

        fn weight(document: &pb::Document) -> usize {
            prost::Message::encoded_len(document) + 11
        }

        proptest! {
            /// The responses carry every result once, in order, and a pipeline with no result
            /// is one response without results.
            #[test]
            fn packing_keeps_every_result_in_order(
                paddings in proptest::collection::vec(0usize..600_000, 0..12),
            ) {
                let documents: Vec<_> = paddings.iter().enumerate().map(|(i, p)| document(i, *p)).collect();
                let responses = pack_results(documents.clone(), None);
                let flat: Vec<_> = responses.iter().flat_map(|r| r.results.clone()).collect();
                prop_assert_eq!(flat, documents.clone());
                prop_assert!(!responses.is_empty());
                if documents.is_empty() {
                    prop_assert_eq!(responses.len(), 1);
                } else {
                    prop_assert!(responses.iter().all(|r| !r.results.is_empty()));
                }
            }

            /// A response stays within the target unless it holds a single oversized document,
            /// and the packing is greedy: the next response's first document would not have fit.
            #[test]
            fn packing_cuts_only_where_the_next_result_does_not_fit(
                paddings in proptest::collection::vec(0usize..600_000, 1..12),
            ) {
                let documents: Vec<_> = paddings.iter().enumerate().map(|(i, p)| document(i, *p)).collect();
                let responses = pack_results(documents, None);
                for response in &responses {
                    let total: usize = response.results.iter().map(weight).sum();
                    prop_assert!(
                        response.results.len() == 1
                            || total + RESPONSE_OVERHEAD_BYTES <= RESULT_BATCH_BYTES
                    );
                }
                for pair in responses.windows(2) {
                    let held: usize = pair[0].results.iter().map(weight).sum();
                    prop_assert!(
                        held + weight(&pair[1].results[0]) + RESPONSE_OVERHEAD_BYTES
                            > RESULT_BATCH_BYTES
                    );
                }
            }

            /// An answer that fits the target is one response, as production sent 2 to 4
            /// documents (FS-ENT-ORACLE O-1).
            #[test]
            fn a_small_answer_is_one_response(count in 0usize..200, padding in 0usize..2_000) {
                let documents: Vec<_> = (0..count).map(|i| document(i, padding)).collect();
                prop_assert_eq!(pack_results(documents, None).len(), 1);
            }
        }

        /// A batch that reaches the target exactly is still one response; one byte more is cut.
        #[test]
        fn a_batch_may_fill_the_target_exactly() {
            let first = document(0, 500_000);
            let want = RESULT_BATCH_BYTES - RESPONSE_OVERHEAD_BYTES - weight(&first);
            let fitting = (want.saturating_sub(400)..want)
                .map(|padding| document(1, padding))
                .find(|candidate| weight(candidate) == want)
                .expect("a padding that fills the target exactly");
            let over = (want.saturating_sub(400)..=want)
                .map(|padding| document(1, padding))
                .find(|candidate| weight(candidate) == want + 1)
                .expect("a padding one byte over the target");
            assert_eq!(pack_results(vec![first.clone(), fitting], None).len(), 1);
            assert_eq!(pack_results(vec![first, over], None).len(), 2);
        }

        #[test]
        fn the_execution_time_is_on_every_response() {
            let time = prost_types::Timestamp {
                seconds: 5,
                nanos: 7,
            };
            let documents = (0..3).map(|i| document(i, 400_000)).collect();
            let responses = pack_results(documents, Some(time));
            assert_eq!(responses.len(), 2);
            assert!(responses.iter().all(|r| r.execution_time == Some(time)));
        }
    }
    mod select_name {
        use super::*;
        use proptest::prelude::*;

        fn field(name: &str) -> pb::Value {
            pb::Value {
                value_type: Some(pb::value::ValueType::FieldReferenceValue(name.to_owned())),
            }
        }

        fn select(entries: &[(&str, &str)]) -> pb::pipeline::Stage {
            pb::pipeline::Stage {
                name: "select".to_owned(),
                args: vec![pb::Value {
                    value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                        fields: entries
                            .iter()
                            .map(|(alias, source)| ((*alias).to_owned(), field(source)))
                            .collect(),
                    })),
                }],
                ..Default::default()
            }
        }

        proptest! {
            /// Under the emulator profile `__name__` selected as itself sets no field and asks
            /// for the name; every other alias is a field, in any combination and order.
            #[test]
            fn the_identity_alias_asks_for_the_name_and_sets_no_field(
                pool in proptest::sample::subsequence(vec!["a", "b", "c.d", "e"], 0..=4),
                identity in any::<bool>(),
                shuffle in any::<u64>(),
            ) {
                let mut entries: Vec<(&str, &str)> = pool.iter().map(|alias| (*alias, "n")).collect();
                if identity {
                    entries.push(("__name__", "__name__"));
                }
                prop_assume!(!entries.is_empty());
                let rotation = usize::try_from(shuffle % u64::try_from(entries.len()).unwrap()).unwrap();
                entries.rotate_left(rotation);
                let (aliases, keeps_name) =
                    decode_select(&select(&entries), Unrecorded::OfficialEmulator, None).unwrap();
                prop_assert_eq!(keeps_name, identity);
                let mut set: Vec<String> = aliases.iter().map(|(path, _)| path.canonical()).collect();
                set.sort();
                let mut want: Vec<String> = pool.iter().map(|alias| (*alias).to_owned()).collect();
                want.sort();
                prop_assert_eq!(set, want);
            }

            /// `__name__` set from any other value is refused, and strict refuses even the
            /// identity as unobserved.
            #[test]
            fn only_the_identity_may_set_the_name(source in "[a-z]{1,4}") {
                let refused = decode_select(
                    &select(&[("__name__", &source)]),
                    Unrecorded::OfficialEmulator,
                    None,
                ).unwrap_err();
                prop_assert_eq!(refused.code(), tonic::Code::InvalidArgument);
                prop_assert!(refused.message().contains("can not be overwritten"));
            }
        }

        #[test]
        fn strict_answers_the_identity_alone_as_production_did_and_refuses_the_rest() {
            let (aliases, keeps_name) = decode_select(
                &select(&[("__name__", "__name__")]),
                Unrecorded::Refuse,
                None,
            )
            .unwrap();
            assert!(aliases.is_empty() && keeps_name);
            for entries in [
                vec![("__name__", "__name__"), ("a", "n")],
                vec![("`__name__`", "__name__")],
            ] {
                let refused =
                    decode_select(&select(&entries), Unrecorded::Refuse, None).unwrap_err();
                assert_eq!(refused.code(), tonic::Code::Unimplemented, "{entries:?}");
            }
        }
    }
}
