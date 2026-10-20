//! `ExecutePipeline` decoding for the strict validator (`FS-PIPE-RPC-1`): the request's
//! database, consistency selector and options are checked, the wire stages become
//! [`StageSpec`]s with typed arguments that the core canonicalizes. The finite latest-read
//! collection/where(equal)/select/offset/limit subset executes locally through the core
//! pipeline executor ([`compile_pipeline`]); other semantics are refused. The older lowering
//! to an equivalent `RunQuery` ([`compile_supported`]) stays as the differential baseline.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

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
/// the `fireemu-code` metadata like the gateway's rejections.
#[allow(clippy::too_many_lines)]
pub fn validate_pipeline(req: &pb::ExecutePipelineRequest) -> Result<PipelineAst, Status> {
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
                for (alias, value) in &map.fields {
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
}

/// Compiles the finite local Enterprise subset for the core executor: collection input,
/// then an optional single `where(comparison)`, an optional `select`, an optional `offset`
/// and an optional `limit`, in that order. Operands are field references (nested paths
/// included), literals and the table's functions. Every other stage, function or arrangement
/// is refused. `unrecorded` decides whether shapes with unrecorded production behavior
/// (a constant `where` condition, a literal holding expressions) are refused or answered as
/// the official emulator answers them.
#[allow(clippy::too_many_lines)]
pub fn compile_pipeline(
    req: &pb::ExecutePipelineRequest,
    parent: &Parent,
    unrecorded: Unrecorded,
) -> Result<CompiledExecution, Status> {
    let (pipeline, query_parent, collection_id) = collection_input(req, parent)?;
    let mut stages = Vec::new();
    let mut last_rank = 0u8;
    let (mut seen_where, mut seen_select, mut seen_offset, mut seen_limit) =
        (false, false, false, false);
    let mut pushdown = None;
    // An empty alias map, which the official emulator answers only after every stage's own
    // argument checks.
    let mut deferred: Option<Status> = None;
    let compiled = (|| -> Result<(), Status> {
        for (position, stage) in pipeline.stages.iter().enumerate().skip(1) {
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
                    if unrecorded != Unrecorded::Refuse
                        && stage.args.first().is_some_and(is_empty_map)
                    {
                        deferred.get_or_insert_with(|| {
                            Status::invalid_argument(
                                "The 'select(...)' stage requires at least one field.",
                            )
                        });
                        continue;
                    }
                    stages.push(Stage::Select(decode_select(stage, unrecorded)?));
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
                    let offset = i32::try_from(*n).map_err(|_| {
                        Status::unimplemented("offset exceeds the finite local execution range")
                    })?;
                    let offset = u64::try_from(offset)
                        .map_err(|_| Status::invalid_argument("offset must not be negative"))?;
                    stages.push(Stage::Offset(offset));
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
                    let limit = u32::try_from(*n)
                        .map_err(|_| Status::invalid_argument("limit is out of range"))?;
                    stages.push(Stage::Limit(u64::from(limit)));
                }
                other => {
                    // The official emulator checks every stage's arguments before running any.
                    for (later, rest) in pipeline.stages.iter().enumerate().skip(position) {
                        check_unrun_alias_stage(rest, later, unrecorded, &mut deferred)?;
                    }
                    return Err(Status::unimplemented(format!(
                        "pipeline stage {other:?} is unsupported locally"
                    )));
                }
            }
        }
        Ok(())
    })();
    match (compiled, deferred) {
        (Err(error), Some(empty)) if error.code() != tonic::Code::InvalidArgument => {
            return Err(empty)
        }
        (Ok(()), Some(empty)) => return Err(empty),
        (result, _) => result?,
    }
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
    Ok(CompiledExecution {
        input: collection_query(query_parent, collection_id, pushdown, projection, 0, None),
        stages,
    })
}

fn expr_status(error: ExprError) -> Status {
    match error {
        ExprError::Unsupported(message) => Status::unimplemented(message),
        ExprError::Invalid(message) => Status::invalid_argument(message),
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
        Some(V::MapValue(map)) => {
            let mut keys: Vec<_> = map.fields.keys().collect();
            keys.sort();
            keys.into_iter()
                .find_map(|key| expression_kind(&map.fields[key]))
        }
        Some(V::FieldReferenceValue(_)) => Some("FIELD_REFERENCE_VALUE"),
        Some(V::VariableReferenceValue(_)) => Some("VARIABLE_REFERENCE_VALUE"),
        Some(V::FunctionValue(_)) => Some("FUNCTION_VALUE"),
        Some(V::PipelineValue(_)) => Some("PIPELINE_VALUE"),
        Some(_) => None,
        None => Some("VALUE_TYPE_NOT_SET"),
    }
}

/// The literal shapes production refused with `Value type is not supported: <kind>` as a select
/// value: a map of fields and literals (FS-ENT-ORACLE O-1 `px1/select#map-literal`, O-3
/// `o3/functions#map-literal-mixed`), a map holding one map of fields (`#map-literal-nested-field`),
/// a map holding one function (`#map-literal-function`) and an array holding one field
/// (`#array-literal-field`). Other compositions stay unobserved under strict.
fn is_recorded_expression_literal(value: &pb::Value) -> bool {
    use pb::value::ValueType as V;
    let field = |v: &pb::Value| matches!(v.value_type, Some(V::FieldReferenceValue(_)));
    let scalar = |v: &pb::Value| {
        is_literal(v) && !matches!(v.value_type, Some(V::ArrayValue(_) | V::MapValue(_)))
    };
    let map_of_fields = |v: &pb::Value| {
        matches!(&v.value_type, Some(V::MapValue(map))
            if !map.fields.is_empty() && map.fields.values().all(field))
    };
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => matches!(array.values.as_slice(), [only] if field(only)),
        Some(V::MapValue(map)) => {
            let values: Vec<&pb::Value> = map.fields.values().collect();
            match values.as_slice() {
                [only] if matches!(only.value_type, Some(V::FunctionValue(_))) => true,
                [only] if map_of_fields(only) => true,
                _ => {
                    values.iter().any(|v| field(v)) && values.iter().all(|v| field(v) || scalar(v))
                }
            }
        }
        _ => false,
    }
}

/// Decodes an operand expression: a field reference (`__name__` is the document reference),
/// a call of a table function or a literal. An array or map literal that holds an
/// expression is refused with `INVALID_ARGUMENT`, as the official emulator refuses every such
/// literal; under strict only the shapes production refused as select values
/// ([`is_recorded_expression_literal`]) are, and the others are `UNIMPLEMENTED`. `select_value` says whether the operand is
/// a select value itself (not an argument).
fn decode_operand(
    value: &pb::Value,
    unrecorded: Unrecorded,
    select_value: bool,
) -> Result<Expr, Status> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        None => Err(Status::invalid_argument("expression argument is missing")),
        Some(V::FieldReferenceValue(field)) => Ok(Expr::Field(
            FieldPath::parse(field).map_err(|e| Status::invalid_argument(e.to_string()))?,
        )),
        Some(V::FunctionValue(function)) => {
            if pipeline_exec::function(&function.name).is_none() {
                return Err(Status::unimplemented(format!(
                    "function {:?} is unsupported locally",
                    function.name
                )));
            }
            if !function.options.is_empty() {
                return Err(Status::invalid_argument(format!(
                    "function {:?} takes no options",
                    function.name
                )));
            }
            let args = function
                .args
                .iter()
                .map(|arg| decode_operand(arg, unrecorded, false))
                .collect::<Result<Vec<_>, _>>()?;
            Expr::call(&function.name, args, Placement::Value).map_err(expr_status)
        }
        Some(V::VariableReferenceValue(_) | V::PipelineValue(_)) => Err(Status::unimplemented(
            "variable and pipeline operands are unsupported locally",
        )),
        Some(_) => match expression_kind(value) {
            None => Ok(Expr::Constant(
                crate::decode::decode_value(value)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?,
            )),
            Some(kind)
                if unrecorded == Unrecorded::OfficialEmulator
                    || (select_value && is_recorded_expression_literal(value)) =>
            {
                Err(Status::invalid_argument(format!(
                    "Value type is not supported: {kind}"
                )))
            }
            Some(_) => Err(Status::unimplemented(
                "array and map literals holding expressions are not observed locally",
            )),
        },
    }
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
    let function = match condition.value_type.as_ref() {
        Some(V::FunctionValue(function)) => function,
        Some(V::FieldReferenceValue(_)) => {
            return Ok((decode_operand(condition, unrecorded, false)?, None))
        }
        // Production kept the row for `true` and dropped it for `false`, null, a double and a
        // string (FS-ENT-ORACLE O-3, `fs-ent-pipeline/o3/comparisons#where-constant-*`).
        _ if is_literal(condition)
            && (unrecorded == Unrecorded::OfficialEmulator
                || matches!(
                    condition.value_type,
                    Some(
                        V::BooleanValue(_)
                            | V::NullValue(_)
                            | V::DoubleValue(_)
                            | V::StringValue(_)
                    )
                )) =>
        {
            return Ok((decode_operand(condition, unrecorded, false)?, None))
        }
        _ => {
            return Err(Status::unimplemented(
                "this where condition is not observed locally",
            ))
        }
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
        return Ok((decode_operand(condition, unrecorded, false)?, None));
    }
    // Every boolean function of the table is a comparison of two arguments; the wording is
    // the finite subset's.
    if def.arity != Arity::Exact(function.args.len()) || !function.options.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{} requires exactly two arguments and no options",
            def.name
        )));
    }
    let args = function
        .args
        .iter()
        .map(|arg| decode_operand(arg, unrecorded, false))
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
    let condition = Expr::call(def.name, args, Placement::Condition).map_err(expr_status)?;
    Ok((condition, pushdown))
}

/// Decodes `select({alias: operand, ...})`. An alias is a field path, as production and the
/// official emulator read it (FS-ENT-ORACLE O-1 recorded the same answers from both): a
/// dotted alias nests, a quoted one unquotes, and an invalid path, a reserved name, a
/// repeated path and an alias inside another are refused.
fn decode_select(
    stage: &pb::pipeline::Stage,
    unrecorded: Unrecorded,
) -> Result<Vec<(FieldPath, Expr)>, Status> {
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
    let mut aliases = Vec::with_capacity(map.fields.len());
    for (alias, value) in &map.fields {
        if value.value_type.is_none() {
            return Err(Status::unimplemented(
                "select expressions are unsupported locally",
            ));
        }
        let path = decode_alias(alias, unrecorded)?;
        if unrecorded == Unrecorded::Refuse
            && is_literal(value)
            && !is_recorded_select_literal(value)
        {
            return Err(Status::unimplemented(
                "a select value literal of this kind is not observed locally",
            ));
        }
        aliases.push((alias, path, decode_operand(value, unrecorded, true)?));
    }
    if aliases.is_empty() {
        // Production has not answered an empty select; the official emulator names the stage.
        return Err(if unrecorded == Unrecorded::Refuse {
            Status::unimplemented("an empty select alias map is not observed locally")
        } else {
            Status::invalid_argument("The 'select(...)' stage requires at least one field.")
        });
    }
    aliases.sort_by(|a, b| a.1.cmp(&b.1));
    for pair in aliases.windows(2) {
        if pair[0].1 == pair[1].1 {
            return Err(Status::invalid_argument(format!(
                "select aliases {:?} and {:?} set the same field",
                pair[0].0, pair[1].0
            )));
        }
        if pair[0].1.is_prefix_of(&pair[1].1) {
            return Err(crate::production_status::select_overlapping_paths(
                pair[1].0,
            ));
        }
    }
    Ok(aliases
        .into_iter()
        .map(|(_, path, expr)| (path, expr))
        .collect())
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
/// emulator answers, with the same texts (FS-ENT-ORACLE O-1 `fs-ent-pipeline/px0/aliases` and
/// O-3 `fs-ent-pipeline/o3/aliases`): a reserved `__x__` or `__name__` is refused at the top
/// level, quoted or not, and accepted below another field; the path checks are
/// [`parse_alias`]'s.
fn decode_alias(alias: &str, unrecorded: Unrecorded) -> Result<FieldPath, Status> {
    let path = parse_alias(alias, unrecorded)?;
    match path.segments() {
        // A reserved first segment with a child is unrecorded (O-3 recorded reserved names
        // alone and below another field only).
        [first, _, ..] if unrecorded == Unrecorded::Refuse && is_reserved_name(first) => {
            Err(Status::unimplemented(format!(
                "select alias {alias:?}: a reserved first segment with a child is not observed locally"
            )))
        }
        [name] if name == "__name__" => Err(Status::invalid_argument(format!(
            "Stage 'select': field name '{name}' is reserved and can not be overwritten."
        ))),
        [name] if is_reserved_name(name) => Err(Status::invalid_argument(format!(
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
/// detail. Production's length rows were all ASCII, so strict refuses a joined path of 1500
/// bytes or more that holds other characters as unobserved (whether production counts bytes
/// or characters is unrecorded). Reserved names are the caller's.
fn parse_alias(alias: &str, unrecorded: Unrecorded) -> Result<FieldPath, Status> {
    let too_long = |joined: &str| {
        if unrecorded == Unrecorded::Refuse && !joined.is_ascii() {
            Status::unimplemented(format!(
                "select alias {alias:?}: the length limit of a non-ASCII path is not observed locally"
            ))
        } else {
            crate::production_status::property_path_too_long(joined)
        }
    };
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

/// The official emulator's argument checks on a stage the local executor does not run
/// (`add_fields`, `distinct`, `aggregate`), answered before the stage is refused as
/// unsupported, in the official order: the stage's arity, each alias, then an empty map, which
/// is `deferred` until every stage's other checks are done. Production answered
/// `aggregate({c: count()})` directly after the collection with the official arity text
/// (FS-ENT-ORACLE O-1, `fs-ent-pipeline/results/metadata#aggregate`), so strict answers that
/// text for that shape (directly after the collection, a non-empty map of plain, valid,
/// unreserved aliases to `count`) and leaves every other shape here to the unsupported-stage
/// refusal. A `select` after an unrun stage gets its alias checks here too.
fn check_unrun_alias_stage(
    stage: &pb::pipeline::Stage,
    position: usize,
    unrecorded: Unrecorded,
    deferred: &mut Option<Status>,
) -> Result<(), Status> {
    let strict = unrecorded == Unrecorded::Refuse;
    if stage.name == "aggregate" && stage.args.len() == 1 {
        let recorded = || {
            position == 1
                && map_fields(&stage.args[0]).is_some_and(|fields| {
                    !fields.is_empty() && fields.iter().all(|(alias, accumulator)| {
                        !alias.contains(['.', '`'])
                            && !is_reserved_name(alias)
                            && parse_alias(alias, unrecorded).is_ok()
                            && matches!(
                                &accumulator.value_type,
                                Some(pb::value::ValueType::FunctionValue(f)) if f.name == "count"
                            )
                    })
                })
        };
        if !strict || recorded() {
            return Err(Status::invalid_argument(
                "Stage 'aggregate(accumulators: Map[FieldPath, Expr], groups: Map[FieldPath, Expr])' takes [2..2] argument(s), received 1.",
            ));
        }
    }
    let name = stage.name.as_str();
    if strict || !matches!(name, "aggregate" | "add_fields" | "distinct" | "select") {
        return Ok(());
    }
    // A select after an unrun stage: the official emulator checks its aliases too, with the
    // select texts, and answers an empty map last.
    if name == "select" {
        for alias in stage
            .args
            .iter()
            .filter_map(map_fields)
            .flat_map(|fields| fields.keys())
        {
            decode_alias(alias, unrecorded)?;
        }
        if stage.args.first().is_some_and(is_empty_map) {
            deferred.get_or_insert_with(|| {
                Status::invalid_argument("The 'select(...)' stage requires at least one field.")
            });
        }
        return Ok(());
    }
    for alias in stage
        .args
        .iter()
        .filter_map(map_fields)
        .flat_map(|fields| fields.keys())
    {
        parse_alias(alias, unrecorded)?;
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

/// The literal select values production answered: integers and finite doubles (O-1, O-2),
/// infinities, NaN, -0.0, strings, booleans, null, timestamps, bytes, geo points, references,
/// `{a: 1}` and empty maps and arrays (FS-ENT-ORACLE O-3, `fs-ent-pipeline/o3/literals`).
/// Arrays of them are compositions of recorded shapes (rulings (5)), and so are maps of them
/// whose keys are plain, non-empty and unreserved (a named coordinator inference, rulings (5),
/// PX1b review M3). A vector literal, and a map with another key (empty, reserved such as
/// `__type__`, or holding dots or backticks), is unrecorded; strict refuses it.
fn is_recorded_select_literal(value: &pb::Value) -> bool {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => array.values.iter().all(is_recorded_select_literal),
        Some(V::MapValue(map)) => map
            .fields
            .iter()
            .all(|(key, value)| is_plain_key(key) && is_recorded_select_literal(value)),
        Some(_) => true,
        None => false,
    }
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

/// A name like `__x__`, which Firestore reserves.
fn is_reserved_name(segment: &str) -> bool {
    segment.len() >= 4 && segment.starts_with("__") && segment.ends_with("__")
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
}
