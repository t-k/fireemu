//! `ExecutePipeline` decoding for the strict validator (`FS-PIPE-RPC-1`): the request's
//! database, consistency selector and options are checked, the wire stages become
//! [`StageSpec`]s with typed arguments that the core canonicalizes. The finite latest-read
//! collection/where(equal)/select/offset/limit subset executes locally through the core
//! pipeline executor ([`compile_pipeline`]); other semantics are refused. The older lowering
//! to an equivalent `RunQuery` ([`compile_supported`]) stays as the differential baseline.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::pipeline::{canonicalize, Arg, PipelineAst, PipelineError, StageSpec};
use fireemu_core_firestore::pipeline_exec::{self, Expr, ExprError, Placement, Stage, Unrecorded};
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
/// then an optional single `where(equal(operand, scalar literal))`, an optional `select`,
/// an optional `offset` and an optional `limit`, in that order. Operands are field
/// references (nested paths included) and the table's value functions (`document_id`,
/// `collection_id`, `parent`). Every other stage, function or arrangement is refused.
/// `unrecorded` decides whether shapes with unrecorded production behavior (dotted or quoted
/// select aliases) are refused or answered as the official emulator answers them.
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
                if seen_where || seen_select || seen_limit {
                    return Err(Status::unimplemented("duplicate or misplaced where stage"));
                }
                seen_where = true;
                stages.push(Stage::Where(decode_condition(stage)?));
            }
            "select" => {
                if seen_select {
                    return Err(Status::unimplemented(
                        "duplicate select stage is unsupported locally",
                    ));
                }
                seen_select = true;
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
                return Err(Status::unimplemented(format!(
                    "pipeline stage {other:?} is unsupported locally"
                )))
            }
        }
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
        input: collection_query(query_parent, collection_id, None, projection, 0, None),
        stages,
    })
}

fn expr_status(error: ExprError) -> Status {
    match error {
        ExprError::Unsupported(message) => Status::unimplemented(message),
        ExprError::Invalid(message) => Status::invalid_argument(message),
    }
}

/// Where an operand stands: directly in a stage (`where` operand, `select` value) or as a
/// function argument.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    Stage,
    Argument,
}

/// Decodes an operand expression: a field reference, a call of a table value function or,
/// as a function argument only, a reference literal. `__name__` is accepted only as a
/// function argument.
fn decode_operand(value: &pb::Value, position: Position) -> Result<Expr, Status> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        None => Err(Status::invalid_argument("expression argument is missing")),
        Some(V::FieldReferenceValue(field)) => {
            let path =
                FieldPath::parse(field).map_err(|e| Status::invalid_argument(e.to_string()))?;
            if path.is_document_name() && position == Position::Stage {
                return Err(Status::unimplemented(
                    "__name__ field references are unsupported locally outside document functions",
                ));
            }
            Ok(Expr::Field(path))
        }
        Some(V::FunctionValue(function)) => {
            match pipeline_exec::function(&function.name) {
                None => {
                    return Err(Status::unimplemented(format!(
                        "function {:?} is unsupported locally",
                        function.name
                    )))
                }
                Some(def) if def.placement != Placement::Value => {
                    return Err(Status::unimplemented(format!(
                        "function {:?} is unsupported in this position locally",
                        function.name
                    )))
                }
                Some(_) => {}
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
                .map(|arg| decode_operand(arg, Position::Argument))
                .collect::<Result<Vec<_>, _>>()?;
            Expr::call(&function.name, args, Placement::Value).map_err(expr_status)
        }
        Some(V::ReferenceValue(reference)) if position == Position::Argument => Ok(Expr::Constant(
            fireemu_core_firestore::value::Value::Reference(reference.clone()),
        )),
        Some(_) => Err(Status::unimplemented(
            "literal expression operands are unsupported locally",
        )),
    }
}

/// Decodes `where(equal(operand, scalar literal))`.
fn decode_condition(stage: &pb::pipeline::Stage) -> Result<Expr, Status> {
    let Some(pb::value::ValueType::FunctionValue(function)) =
        stage.args.first().and_then(|v| v.value_type.as_ref())
    else {
        return Err(Status::invalid_argument(
            "where requires an equal expression",
        ));
    };
    let Some(def) =
        pipeline_exec::function(&function.name).filter(|def| def.placement == Placement::Condition)
    else {
        return Err(Status::unimplemented(
            "where expression is unsupported locally",
        ));
    };
    if function.args.len() != def.arity || !function.options.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{} requires exactly {} arguments and no options",
            def.name, def.arity
        )));
    }
    let left = match function.args[0].value_type.as_ref() {
        None => return Err(Status::invalid_argument("equal first argument is missing")),
        Some(
            pb::value::ValueType::FieldReferenceValue(_) | pb::value::ValueType::FunctionValue(_),
        ) => decode_operand(&function.args[0], Position::Stage)?,
        Some(_) => {
            return Err(Status::unimplemented(
                "equal first argument is unsupported locally",
            ))
        }
    };
    let right = match function.args[1].value_type.as_ref() {
        None => return Err(Status::invalid_argument("where literal is missing")),
        Some(
            pb::value::ValueType::ArrayValue(_)
            | pb::value::ValueType::MapValue(_)
            | pb::value::ValueType::FieldReferenceValue(_)
            | pb::value::ValueType::VariableReferenceValue(_)
            | pb::value::ValueType::FunctionValue(_)
            | pb::value::ValueType::PipelineValue(_),
        ) => {
            return Err(Status::unimplemented(
                "where literal is unsupported locally",
            ))
        }
        Some(_) => Expr::Constant(
            crate::decode::decode_value(&function.args[1])
                .map_err(|e| Status::invalid_argument(e.to_string()))?,
        ),
    };
    Expr::call(def.name, vec![left, right], Placement::Condition).map_err(expr_status)
}

/// Decodes `select({alias: operand, ...})`. An alias is a field path, as the official
/// emulator treats it: an invalid path, `__name__`, a repeated path and an alias inside
/// another are refused as it refuses them. A dotted or quoted alias nests or unquotes the
/// output key there; production is unobserved, so it is refused unless `unrecorded` follows
/// the official emulator.
fn decode_select(
    stage: &pb::pipeline::Stage,
    unrecorded: Unrecorded,
) -> Result<Vec<(FieldPath, Expr)>, Status> {
    let Some(pb::value::ValueType::MapValue(map)) =
        stage.args.first().and_then(|v| v.value_type.as_ref())
    else {
        return Err(Status::invalid_argument("select requires an alias map"));
    };
    let mut aliases = Vec::with_capacity(map.fields.len());
    for (alias, value) in &map.fields {
        if value.value_type.is_none() {
            return Err(Status::unimplemented(
                "select expressions are unsupported locally",
            ));
        }
        let path = FieldPath::parse(alias).map_err(|e| {
            Status::invalid_argument(format!("select alias {alias:?} is not a field path: {e}"))
        })?;
        if path.is_document_name() {
            return Err(Status::invalid_argument(
                "select alias __name__ is reserved",
            ));
        }
        aliases.push((alias, path, decode_operand(value, Position::Stage)?));
    }
    if aliases.is_empty() {
        return Err(Status::invalid_argument(
            "select requires a non-empty alias map",
        ));
    }
    aliases.sort_by(|a, b| a.1.cmp(&b.1));
    for pair in aliases.windows(2) {
        if pair[0].1.is_prefix_of(&pair[1].1) {
            return Err(Status::invalid_argument(format!(
                "select aliases {:?} and {:?} set a field and itself or one of its children",
                pair[0].0, pair[1].0
            )));
        }
    }
    if unrecorded == Unrecorded::Refuse {
        if let Some((alias, _, _)) = aliases
            .iter()
            .find(|(alias, path, _)| path.segments() != [alias.as_str()])
        {
            return Err(Status::unimplemented(format!(
                "select alias {alias:?} names a nested or quoted field path; its output shape is not observed locally"
            )));
        }
    }
    Ok(aliases
        .into_iter()
        .map(|(_, path, expr)| (path, expr))
        .collect())
}

/// The executor's output row as a pipeline result document: fields only, without a name
/// or times, as the finite subset has always answered.
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
    let field_ref = pb::structured_query::FieldReference {
        field_path: field.clone(),
    };
    let filter_type = match literal {
        pb::value::ValueType::NullValue(_) => {
            pb::structured_query::filter::FilterType::UnaryFilter(
                pb::structured_query::UnaryFilter {
                    op: pb::structured_query::unary_filter::Operator::IsNull as i32,
                    operand_type: Some(pb::structured_query::unary_filter::OperandType::Field(
                        field_ref,
                    )),
                },
            )
        }
        pb::value::ValueType::DoubleValue(value) if value.is_nan() => {
            pb::structured_query::filter::FilterType::UnaryFilter(
                pb::structured_query::UnaryFilter {
                    op: pb::structured_query::unary_filter::Operator::IsNan as i32,
                    operand_type: Some(pb::structured_query::unary_filter::OperandType::Field(
                        field_ref,
                    )),
                },
            )
        }
        pb::value::ValueType::ArrayValue(_)
        | pb::value::ValueType::MapValue(_)
        | pb::value::ValueType::FieldReferenceValue(_)
        | pb::value::ValueType::VariableReferenceValue(_)
        | pb::value::ValueType::FunctionValue(_)
        | pb::value::ValueType::PipelineValue(_) => {
            return Err(Status::unimplemented(
                "where literal is unsupported locally",
            ));
        }
        _ => pb::structured_query::filter::FilterType::FieldFilter(
            pb::structured_query::FieldFilter {
                field: Some(field_ref),
                op: pb::structured_query::field_filter::Operator::Equal as i32,
                value: Some(function.args[1].clone()),
            },
        ),
    };
    Ok(pb::structured_query::Filter {
        filter_type: Some(filter_type),
    })
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
