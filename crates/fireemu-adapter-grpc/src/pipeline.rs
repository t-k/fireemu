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
    self, Arity, Expr, ExprError, Placement, ReplaceMode, Stage, Unrecorded,
};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use tonic::Status;

use crate::decode::Parent;

/// Option keys a `StructuredPipeline` may carry.
const PIPELINE_OPTIONS: &[&str] = &["index_mode"];

/// Stages the official emulator 1.22.0 knows (probed 2026-10-27) and the registry does not.
const OFFICIAL_ONLY_STAGES: &[&str] = &["let", "insert", "upsert", "literals"];

/// Bounds nested function expressions after the request and stage registry have been validated.
pub(crate) fn validate_function_depth(request: &pb::ExecutePipelineRequest) -> Result<(), Status> {
    use pb::value::ValueType as V;
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &request.pipeline_type
    else {
        return Ok(());
    };
    let Some(pipeline) = &structured.pipeline else {
        return Ok(());
    };
    let mut stack: Vec<_> = pipeline
        .stages
        .iter()
        .flat_map(|stage| {
            stage
                .args
                .iter()
                .chain(stage.options.values())
                .map(|value| (value, 0_usize))
        })
        .collect();
    while let Some((value, depth)) = stack.pop() {
        match value.value_type.as_ref() {
            Some(V::FunctionValue(function)) => {
                let depth = depth + 1;
                if depth > 32 {
                    return Err(Status::invalid_argument(
                        "Expressions can be at most 32 levels deep.",
                    ));
                }
                stack.extend(
                    function
                        .args
                        .iter()
                        .chain(function.options.values())
                        .map(|value| (value, depth)),
                );
            }
            Some(V::ArrayValue(array)) => {
                stack.extend(array.values.iter().map(|value| (value, depth)));
            }
            Some(V::MapValue(map)) => stack.extend(map.fields.values().map(|value| (value, depth))),
            Some(V::PipelineValue(pipeline)) => {
                for stage in &pipeline.stages {
                    stack.extend(
                        stage
                            .args
                            .iter()
                            .chain(stage.options.values())
                            .map(|value| (value, depth)),
                    );
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Production's scalar-subquery cardinality refusal.
pub(crate) const SCALAR_MULTIPLE_RESULTS: &str = "Subpipeline returned multiple results.";

/// Bounds nested union planning before recursive validation and shape inspection.
pub(crate) fn admit_union(request: &pb::ExecutePipelineRequest) -> Result<(), Status> {
    enum Item<'a> {
        Pipeline(&'a pb::Pipeline),
        Value(&'a pb::Value),
    }
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &request.pipeline_type
    else {
        return Ok(());
    };
    let Some(root) = &structured.pipeline else {
        return Ok(());
    };
    if !root.stages.iter().any(|stage| stage.name == "union") {
        return Ok(());
    }
    let mut stack = vec![(root, 0_usize)];
    let mut count = 0_usize;
    while let Some((pipeline, depth)) = stack.pop() {
        count = count.saturating_add(pipeline.stages.len());
        if depth > 32 || count > 256 {
            return Err(Status::unimplemented(
                "union nesting or plan size exceeds the local execution bound",
            ));
        }
        for stage in &pipeline.stages {
            if stage.name == "union" {
                if let Some(pb::value::ValueType::PipelineValue(child)) = stage
                    .args
                    .first()
                    .and_then(|value| value.value_type.as_ref())
                {
                    stack.push((child, depth + 1));
                }
            }
        }
    }
    let mut nodes = vec![(Item::Pipeline(root), 0_usize)];
    let mut seen = 0_usize;
    while let Some((item, depth)) = nodes.pop() {
        seen += 1;
        if depth > 100 || seen > 32768 {
            return Err(Status::unimplemented(
                "union value nesting or plan size exceeds the local execution bound",
            ));
        }
        match item {
            Item::Pipeline(pipeline) => {
                for stage in &pipeline.stages {
                    for value in stage.args.iter().chain(stage.options.values()) {
                        nodes.push((Item::Value(value), depth + 1));
                    }
                }
            }
            Item::Value(value) => match value.value_type.as_ref() {
                Some(pb::value::ValueType::PipelineValue(pipeline)) => {
                    nodes.push((Item::Pipeline(pipeline), depth + 1));
                }
                Some(pb::value::ValueType::ArrayValue(array)) => {
                    for value in &array.values {
                        nodes.push((Item::Value(value), depth + 1));
                    }
                }
                Some(pb::value::ValueType::MapValue(map)) => {
                    for value in map.fields.values() {
                        nodes.push((Item::Value(value), depth + 1));
                    }
                }
                Some(pb::value::ValueType::FunctionValue(function)) => {
                    for value in function.args.iter().chain(function.options.values()) {
                        nodes.push((Item::Value(value), depth + 1));
                    }
                }
                _ => {}
            },
        }
    }
    Ok(())
}

/// Bounds REST union trees before inspecting their recursive request shape.
pub(crate) fn admit_union_json(body: &serde_json::Value) -> Result<(), Status> {
    let Some(root) = body
        .get("structuredPipeline")
        .or_else(|| body.get("structured_pipeline"))
        .and_then(|value| value.get("pipeline"))
    else {
        return Ok(());
    };
    let Some(stages) = root.get("stages").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };
    if !stages
        .iter()
        .any(|stage| stage.get("name").and_then(serde_json::Value::as_str) == Some("union"))
    {
        return Ok(());
    }
    let mut stack = vec![(root, 0_usize)];
    let mut count = 0_usize;
    while let Some((pipeline, depth)) = stack.pop() {
        let Some(stages) = pipeline.get("stages").and_then(serde_json::Value::as_array) else {
            continue;
        };
        count = count.saturating_add(stages.len());
        if depth > 32 || count > 256 {
            return Err(Status::unimplemented(
                "union nesting or plan size exceeds the local execution bound",
            ));
        }
        for stage in stages {
            if stage.get("name").and_then(serde_json::Value::as_str) == Some("union") {
                if let Some(child) = stage
                    .get("args")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|args| args.first())
                    .and_then(|arg| {
                        arg.get("pipelineValue")
                            .or_else(|| arg.get("pipeline_value"))
                    })
                {
                    stack.push((child, depth + 1));
                }
            }
        }
    }
    let mut nodes = vec![(root, 0_usize)];
    let mut seen = 0_usize;
    while let Some((value, depth)) = nodes.pop() {
        seen += 1;
        if depth > 100 || seen > 32768 {
            return Err(Status::unimplemented(
                "union value nesting or plan size exceeds the local execution bound",
            ));
        }
        match value {
            serde_json::Value::Array(items) => {
                nodes.extend(items.iter().map(|value| (value, depth + 1)));
            }
            serde_json::Value::Object(items) => {
                nodes.extend(items.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(())
}

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
    admit_union(req)?;
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
        // Production's words for a request that names no pipeline (FS-ENT-ORACLE O-8A
        // `precedence-main`: an empty body, `{}`, a null `structuredPipeline`). The official
        // emulator 1.22.0 answers such a request with an `UNKNOWN` fault, so any refusal holds.
        return Err(with_code(
            Status::invalid_argument("Pipeline cannot be empty."),
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
    // An input stage after the first: production's text (FS-ENT-ORACLE O-7
    // `inputs-collection-group#invalid-after-collection`).
    if pipeline
        .stages
        .iter()
        .skip(1)
        .any(|stage| matches!(stage.name.as_str(), "collection_group" | "documents"))
    {
        return Err(with_code(
            Status::invalid_argument(
                "The last stage of a pipeline query must be a transform or output stage.",
            ),
            "FS_PIPE_INVALID",
        ));
    }
    // Production's arity text of the stages with a signature comes before the registry's own.
    if let Some(error) = pipeline.stages.iter().find_map(stage_arity_error) {
        return Err(with_code(error, "FS_PIPE_INVALID"));
    }
    canonicalize(&specs).map_err(|e| {
        let (status, code) = match &e {
            // A stage the official emulator 1.22.0 runs and fireemu does not stays unsupported.
            PipelineError::UnknownStage(name) if OFFICIAL_ONLY_STAGES.contains(&name.as_str()) => (
                Status::unimplemented(e.to_string()),
                "FS_PIPE_UNSUPPORTED_STAGE",
            ),
            // Any other name is no stage of the official emulator, which refuses it in
            // production's words (FS-ENT-ORACLE O-8A `precedence-main#unknown-stage`; strict
            // answers the name production was given and `UNIMPLEMENTED` for any other).
            PipelineError::UnknownStage(name) => (
                Status::invalid_argument(format!(
                    "Unsupported stage: {}",
                    crate::rest::transcode::echo(name)
                )),
                "FS_PIPE_INVALID",
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
/// Where a compiled pipeline reads its rows.
struct Input<'a> {
    pipeline: &'a pb::Pipeline,
    /// The query's parent (the documents root unless a collection of a document is read).
    query_parent: String,
    collection_id: String,
    /// Whether every collection of that id, at any depth, is read (`collection_group`).
    all_descendants: bool,
    /// The documents a `documents` input names, as resource names; nothing is scanned then.
    documents: Option<Vec<String>>,
    database: bool,
}

/// The input of a pipeline: `collection`, `collection_group` or `documents`.
fn pipeline_input<'a>(
    req: &'a pb::ExecutePipelineRequest,
    parent: &Parent,
) -> Result<Input<'a>, Status> {
    let root = format!(
        "projects/{}/databases/{}/documents",
        parent.project, parent.database
    );
    let pipeline = structured_pipeline(req)?;
    match pipeline.stages.first().map(|stage| stage.name.as_str()) {
        Some("database") => Ok(Input {
            pipeline,
            query_parent: root,
            collection_id: String::new(),
            all_descendants: false,
            documents: None,
            database: true,
        }),
        Some("collection_group") => {
            let stage = &pipeline.stages[0];
            // The ancestor is accepted and ignored, whatever document it names (FS-ENT-ORACLE
            // O-7 `inputs-collection-group#nested-parent`): every collection of the id is read.
            let (
                Some(pb::value::ValueType::ReferenceValue(_)),
                Some(pb::value::ValueType::StringValue(id)),
            ) = (
                stage.args.first().and_then(|v| v.value_type.as_ref()),
                stage.args.get(1).and_then(|v| v.value_type.as_ref()),
            )
            else {
                return Err(Status::unimplemented(
                    "this collection_group input is unsupported locally",
                ));
            };
            if let Some(pb::value::ValueType::ReferenceValue(ancestor)) =
                stage.args.first().and_then(|v| v.value_type.as_ref())
            {
                // The ancestor is validated as a document path and otherwise ignored; the empty
                // reference is the root (FS-ENT-ORACLE O-9 `cg-main`).
                if let Some(text) = documents_path_error(ancestor).filter(|_| !ancestor.is_empty())
                {
                    return Err(Status::invalid_argument(text));
                }
            }
            if let Some(text) = collection_group_id_error(id) {
                return Err(Status::invalid_argument(text));
            }
            Ok(Input {
                pipeline,
                query_parent: root,
                collection_id: id.clone(),
                all_descendants: true,
                documents: None,
                database: false,
            })
        }
        Some("documents") => {
            let stage = &pipeline.stages[0];
            let mut names: Vec<String> = Vec::with_capacity(stage.args.len());
            for argument in &stage.args {
                let Some(pb::value::ValueType::ReferenceValue(path)) = argument.value_type.as_ref()
                else {
                    return Err(Status::unimplemented(
                        "this documents input is unsupported locally",
                    ));
                };
                if let Some(text) = documents_path_error(path) {
                    return Err(Status::invalid_argument(text));
                }
                if names.contains(&format!("{root}{path}")) {
                    return Err(Status::invalid_argument(format!(
                        "Duplicate path '{path}' specified in document stage."
                    )));
                }
                names.push(format!("{root}{path}"));
            }
            Ok(Input {
                pipeline,
                query_parent: root,
                collection_id: String::new(),
                all_descendants: false,
                documents: Some(names),
                database: false,
            })
        }
        _ => {
            let (pipeline, query_parent, collection_id) = collection_input(req, parent)?;
            Ok(Input {
                pipeline,
                query_parent,
                collection_id,
                all_descendants: false,
                documents: None,
                database: false,
            })
        }
    }
}

/// Production's refusals of the collection id of `collection_group` (FS-ENT-ORACLE O-7
/// `inputs-collection-group#invalid-*`).
fn collection_group_id_error(id: &str) -> Option<String> {
    if id.is_empty() {
        Some("The kind / collection group cannot be empty.".to_owned())
    } else if id.contains('/') {
        Some(format!(
            "Collection id \"{id}\" is invalid because it contains \"/\"."
        ))
    } else if is_reserved_name(id) {
        Some(format!(
            "Collection id \"{id}\" is invalid because it is reserved."
        ))
    } else {
        None
    }
}

/// Production's refusals of a path of `documents` (FS-ENT-ORACLE O-7 `inputs-documents#invalid-*`):
/// a rooted document path of an even number of segments is none.
fn documents_path_error(path: &str) -> Option<String> {
    if path == "/" {
        return Some(format!(
            "Document path name \"{path}\" is invalid: Omit trailing \"/\"."
        ));
    }
    // A trailing "/" after a name (`anc-trailing-slash`; the official emulator 1.22.0 alike).
    if path.ends_with('/') {
        return Some(format!(
            "Document path name \"{path}\" has invalid trailing \"/\"."
        ));
    }
    // A path without its leading "/" is refused at index 0 (FS-ENT-ORACLE O-9 `cg-main`
    // `anc-no-leading-slash`, `anc-full-name`); one with an odd number of segments, a collection,
    // at its end (`anc-collection-path`).
    if !path.starts_with('/') {
        return Some(format!(
            "Document path name \"{path}\" lacks \"/\" at index 0."
        ));
    }
    let segments = path.trim_start_matches('/').split('/').count();
    if segments % 2 == 1 || path.contains("//") {
        return Some(format!(
            "Document path name \"{path}\" lacks \"/\" at index {}.",
            path.encode_utf16().count()
        ));
    }
    None
}

/// The request's structured pipeline, after the refusals of what is unsupported around it.
fn structured_pipeline(req: &pb::ExecutePipelineRequest) -> Result<&pb::Pipeline, Status> {
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
    Ok(pipeline)
}

fn collection_input<'a>(
    req: &'a pb::ExecutePipelineRequest,
    parent: &Parent,
) -> Result<(&'a pb::Pipeline, String, String), Status> {
    let pipeline = structured_pipeline(req)?;
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

/// One raw union source and its branch-local row transformations.
#[derive(Debug, Clone)]
pub struct UnionSource {
    /// Query authorized independently under the request's selected snapshot.
    pub input: pb::RunQueryRequest,
    /// Where and select stages local to this source.
    pub stages: Vec<Stage>,
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
    /// The documents a `documents` input names (resource names); the rows are those that exist
    /// and `input` is not used.
    pub documents: Option<Vec<String>>,
    /// Read all live documents in the request database at one snapshot.
    pub database: bool,
    /// The stages the executor runs over the input rows.
    pub stages: Vec<Stage>,
    /// A local lexical search before the existing streaming suffix.
    pub search: Option<crate::text_search::SearchPlan>,
    /// Source plans for each union stage, indexed by executor stage position.
    pub unions: Vec<(usize, Vec<UnionSource>)>,
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

/// Strict answers the `documents` paths only in the form production was given (FS-ENT-ORACLE
/// O-7 `inputs-documents`): the document of a collection (`/dc/d1`, two segments). A deeper
/// document path is unobserved. (The ancestor of `collection_group` was recorded in any valid
/// document path form, O-9 `cg-main`.)
fn unrecorded_input_path(stage: &pb::pipeline::Stage) -> Option<Status> {
    if stage.name != "documents" {
        return None;
    }
    let two_segments = |path: &str| {
        path.strip_prefix('/').is_some_and(|rest| {
            let segments: Vec<&str> = rest.split('/').collect();
            segments.len() == 2 && segments.iter().all(|segment| !segment.is_empty())
        })
    };
    stage
        .args
        .iter()
        .filter_map(|value| match &value.value_type {
            Some(pb::value::ValueType::ReferenceValue(path)) => Some(path),
            _ => None,
        })
        .any(|path| !two_segments(path))
        .then(|| {
            Status::unimplemented("a documents reference of this form is not observed locally")
        })
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
    let Input {
        pipeline,
        query_parent,
        collection_id,
        all_descendants,
        documents,
        database,
    } = pipeline_input(req, parent)?;
    if unrecorded == Unrecorded::Refuse {
        if let Some(error) = unrecorded_input_path(&pipeline.stages[0]) {
            return Err(error);
        }
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
    let mut unions = Vec::new();
    let mut search = None;
    // The equality filter of the first `where` is pushed into the scan while only filters have
    // run before it (a filter commutes with another filter, not with a limit or a sort).
    let mut only_filters_so_far = true;
    let mut pushdown = None;
    // An empty alias map, which the official emulator answers only after every stage's own
    // argument checks.
    let mut deferred: Option<Status> = None;
    // Whether the pipeline was refused only for a stage fireemu does not run, after every part
    // of it passed a check production made (strict answers the deferred empty map only then).
    let mut validated_unrun = false;
    // A reserved alias or a `map(...)` key type, which is answered after a later stage's
    // argument type and before an empty map.
    let mut deferred_name: Option<Status> = None;
    // The stage the walk stopped at.
    let mut failed_at = 0;
    let compiled = (|| -> Result<(), Status> {
        for (position, stage) in pipeline.stages.iter().enumerate().skip(1) {
            failed_at = position;
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
                    let (condition, filter) = decode_condition(stage, unrecorded)?;
                    if only_filters_so_far && pushdown.is_none() {
                        pushdown = filter;
                    }
                    stages.push(Stage::Where(condition));
                }
                "select" => {
                    only_filters_so_far = false;
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
                        Ok((aliases, keeps_name)) => {
                            stages.push(Stage::Select {
                                aliases,
                                keeps_name,
                            });
                        }
                        // A reserved alias and a `map(...)` key type are answered after a
                        // later stage's argument type, as an empty map is (the official
                        // emulator 1.22.0: `select {__x__: i}` then `limit("x")` gives the
                        // limit text).
                        Err(error)
                            if error.message().starts_with("Stage 'select': field name")
                                || error.message().starts_with("map key must be of type") =>
                        {
                            deferred_name.get_or_insert(error);
                        }
                        Err(error) => return Err(error),
                    }
                }
                "union" => {
                    only_filters_so_far = false;
                    let Some(pb::value::ValueType::PipelineValue(child)) =
                        stage.args.first().and_then(|v| v.value_type.as_ref())
                    else {
                        return Err(Status::unimplemented("union requires a pipeline argument"));
                    };
                    if child.stages.is_empty() {
                        return Err(Status::invalid_argument(
                            "The 'union(...)' stage must have at least one stage.",
                        ));
                    }
                    let mut nested = req.clone();
                    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                        ref mut structured,
                    )) = nested.pipeline_type
                    else {
                        return Err(Status::internal("missing structured pipeline"));
                    };
                    structured.pipeline = Some(child.clone());
                    validate_pipeline(&nested, unrecorded)?;
                    let nested_order = order.map(|o| o.rebased(
                        &format!("/structuredPipeline/pipeline/stages/{position}/args/0/pipelineValue"),
                        "/structuredPipeline/pipeline",
                    ));
                    let branch = compile_pipeline_in_order(
                        &nested,
                        parent,
                        unrecorded,
                        nested_order.as_ref(),
                    )?;
                    let sources = flatten_union_sources(branch)?;
                    unions.push((stages.len(), sources));
                    stages.push(Stage::Union {
                        branches: Vec::new(),
                    });
                }
                "sample" => {
                    only_filters_so_far = false;
                    stages.push(decode_sample(stage)?);
                }
                "unnest" => {
                    only_filters_so_far = false;
                    stages.push(decode_unnest(stage, unrecorded)?);
                }
                "replace_with" => {
                    only_filters_so_far = false;
                    let expression = decode_operand(&stage.args[0], unrecorded)?;
                    let mode = match stage.args.get(1).and_then(|v| v.value_type.as_ref()) {
                        None => ReplaceMode::Full,
                        Some(pb::value::ValueType::StringValue(m)) if m == "full_replace" => {
                            ReplaceMode::Full
                        }
                        Some(pb::value::ValueType::StringValue(m))
                            if m == "merge_overwrite_existing" =>
                        {
                            ReplaceMode::Overwrite
                        }
                        Some(pb::value::ValueType::StringValue(m))
                            if m == "merge_keep_existing" =>
                        {
                            ReplaceMode::Keep
                        }
                        _ => {
                            return Err(Status::unimplemented(
                                "replace_with mode is not observed locally",
                            ))
                        }
                    };
                    stages.push(Stage::ReplaceWith { expression, mode });
                }
                "find_nearest" => {
                    only_filters_so_far = false;
                    let expression = decode_operand(&stage.args[0], unrecorded)?;
                    let fireemu_core_firestore::value::Value::Vector(query) =
                        crate::decode::decode_value(&stage.args[1])
                            .map_err(|error| Status::invalid_argument(error.to_string()))?
                    else {
                        return Err(Status::unimplemented(
                            "this nearest vector form is not observed locally",
                        ));
                    };
                    let measure = match stage.args[2].value_type.as_ref() {
                        Some(pb::value::ValueType::StringValue(name)) if name == "euclidean" => {
                            fireemu_core_firestore::query::DistanceMeasure::Euclidean
                        }
                        Some(pb::value::ValueType::StringValue(name)) if name == "cosine" => {
                            fireemu_core_firestore::query::DistanceMeasure::Cosine
                        }
                        Some(pb::value::ValueType::StringValue(name)) if name == "dot_product" => {
                            fireemu_core_firestore::query::DistanceMeasure::DotProduct
                        }
                        _ => {
                            return Err(Status::unimplemented(
                                "this nearest measure is unsupported locally",
                            ))
                        }
                    };
                    let Some(pb::value::ValueType::IntegerValue(limit)) = stage
                        .options
                        .get("limit")
                        .and_then(|v| v.value_type.as_ref())
                    else {
                        return Err(Status::unimplemented(
                            "nearest without an observed limit is unsupported locally",
                        ));
                    };
                    let limit = usize::try_from(*limit).map_err(|_| {
                        Status::unimplemented("nearest limit is unsupported locally")
                    })?;
                    let Some(pb::value::ValueType::FieldReferenceValue(field)) = stage
                        .options
                        .get("distance_field")
                        .and_then(|v| v.value_type.as_ref())
                    else {
                        return Err(Status::unimplemented(
                            "nearest without an observed distance field is unsupported locally",
                        ));
                    };
                    let distance_field = Some(
                        FieldPath::parse(field)
                            .map_err(|e| Status::invalid_argument(e.to_string()))?,
                    );
                    stages.push(Stage::FindNearest {
                        expression,
                        query,
                        measure,
                        limit,
                        distance_field,
                    });
                }
                "offset" => {
                    only_filters_so_far = false;
                    let offset = count_argument(stage)?;
                    stages.push(Stage::Offset(offset));
                }
                "limit" => {
                    only_filters_so_far = false;
                    let limit = count_argument(stage)?;
                    stages.push(Stage::Limit(limit));
                }
                "sort" => {
                    only_filters_so_far = false;
                    stages.push(Stage::Sort(decode_sort(stage, unrecorded)?));
                }
                "remove_fields" => {
                    only_filters_so_far = false;
                    stages.push(Stage::RemoveFields(decode_remove_fields(stage)?));
                }
                "add_fields" | "distinct" | "aggregate" => {
                    only_filters_so_far = false;
                    // The stage's alias checks and the deferred empty map, as for a stage that
                    // is not run; then its values.
                    check_unrun_alias_stage(stage, &mut deferred, unrecorded)?;
                    if stage.args.iter().take(1).any(is_empty_map) {
                        continue;
                    }
                    stages.push(match stage.name.as_str() {
                        "add_fields" => match decode_add_fields(stage, unrecorded) {
                            Ok(aliases) => Stage::AddFields(aliases),
                            Err(error)
                                if error.message().starts_with("map key must be of type") =>
                            {
                                deferred_name.get_or_insert(error);
                                continue;
                            }
                            Err(error) => return Err(error),
                        },
                        "distinct" => Stage::Distinct(decode_distinct(stage, unrecorded)?),
                        _ => {
                            let (accumulators, groups) = decode_aggregate(stage, unrecorded)?;
                            Stage::Aggregate {
                                accumulators,
                                groups,
                            }
                        }
                    });
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
    // Under the emulator profile a stage fireemu cannot decode (an unsupported function, say) is
    // refused after the argument checks of the stages behind it, as a stage it does not run is:
    // the official emulator checks every stage's arguments before running any. Strict answers
    // the first refusal (no later check answers past a constant that fails; ruling of
    // 2026-10-21).
    let compiled = match compiled {
        Err(error)
            if error.code() == tonic::Code::Unimplemented
                && !validated_unrun
                && unrecorded == Unrecorded::OfficialEmulator =>
        {
            let mut result = Err(error);
            for rest in pipeline.stages.iter().skip(failed_at).skip(1) {
                if let Err(refusal) = check_unrun_alias_stage(rest, &mut deferred, unrecorded) {
                    result = Err(refusal);
                    break;
                }
            }
            result
        }
        other => other,
    };
    let deferred = deferred_name.or(deferred);
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
        // fireemu's own wording of a `where` condition's argument count (the official emulator
        // answers the deferred refusal first).
        (Err(error), Some(empty))
            if error.message().ends_with("requires exactly two arguments") =>
        {
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
    if search.is_some() || !unions.is_empty() {
        pushdown = None;
    }
    let projection = if search.is_some() || !unions.is_empty() {
        None
    } else {
        projection
    };
    if database && (search.is_some() || !unions.is_empty()) {
        return Err(Status::unimplemented(
            "database input with search or union is unsupported locally",
        ));
    }
    let mut input = collection_query(query_parent, collection_id, pushdown, projection, 0, None);
    if all_descendants {
        if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
            input.query_type.as_mut()
        {
            // Every collection of that id, at any depth; the equality filter stays a stage.
            query.r#where = None;
            for selector in &mut query.from {
                selector.all_descendants = true;
            }
        }
    }
    Ok(CompiledExecution {
        input,
        documents,
        database,
        stages,
        search,
        unions,
    })
}

fn flatten_union_sources(compiled: CompiledExecution) -> Result<Vec<UnionSource>, Status> {
    if compiled.documents.is_some() || compiled.search.is_some() {
        return Err(Status::unimplemented(
            "union child input is not a supported collection",
        ));
    }
    let mut first = compiled.input;
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        first.query_type.as_mut()
    {
        if query.from.iter().any(|selector| selector.all_descendants) {
            return Err(Status::unimplemented(
                "union collection group input is unobserved",
            ));
        }
        query.select = None;
        query.r#where = None;
    }
    let mut result = vec![UnionSource {
        input: first,
        stages: Vec::new(),
    }];
    let mut unions = compiled.unions.into_iter();
    for (index, stage) in compiled.stages.into_iter().enumerate() {
        match stage {
            Stage::Where(_) | Stage::Select { .. } => {
                for source in &mut result {
                    source.stages.push(stage.clone());
                }
            }
            Stage::Union { .. } => {
                let Some((position, branches)) = unions.next() else {
                    return Err(Status::internal("missing union source plan"));
                };
                if position != index {
                    return Err(Status::internal("misordered union source plan"));
                }
                result.extend(branches);
            }
            _ => {
                return Err(Status::unimplemented(
                    "union child contains a non-row-local stage",
                ))
            }
        }
    }
    Ok(result)
}

/// Selects a prepared direct-subcollection array from the same guarded snapshot as its parent.
#[allow(clippy::too_many_lines)]
pub(crate) fn execute_subcollection_array(
    local: &crate::local::LocalBackend,
    compiled: &CompiledExecution,
    guard: crate::rules::ReadGuard<'_>,
    unrecorded: Unrecorded,
    runtime: &pipeline_exec::RuntimeContext,
) -> Result<Vec<pb::ExecutePipelineResponse>, Status> {
    use prost::Message as _;
    let [Stage::Select {
        aliases,
        keeps_name,
    }] = compiled.stages.as_slice()
    else {
        return Err(Status::unimplemented(
            "unsupported subcollection outer stages",
        ));
    };
    if compiled.documents.is_some()
        || compiled.database
        || compiled.search.is_some()
        || !compiled.unions.is_empty()
    {
        return Err(Status::unimplemented(
            "unsupported subcollection outer input",
        ));
    }
    let specs: Vec<_> = aliases
        .iter()
        .filter_map(|(_, expr)| match expr {
            Expr::SubcollectionArray { collection, field } => Some((collection, field)),
            _ => None,
        })
        .collect();
    if aliases.len() > 32
        || specs.len() != 1
        || aliases
            .iter()
            .any(|(_, expr)| !matches!(expr, Expr::Field(_) | Expr::SubcollectionArray { .. }))
    {
        return Err(Status::unimplemented("unsupported subcollection select"));
    }
    let (collection, field) = specs[0];
    let (read_time, sources) =
        local.run_pipeline_subcollections(&compiled.input, collection, guard)?;
    let mut children = std::collections::BTreeMap::new();
    let mut parents = Vec::new();
    for (parent, nested) in sources {
        let name = parent
            .document
            .as_ref()
            .ok_or_else(|| Status::internal("missing parent document"))?
            .name
            .clone();
        if children.insert(name, nested).is_some() {
            return Err(Status::internal("duplicate parent"));
        }
        parents.push(parent);
    }
    let mut output = Vec::new();
    let mut output_bytes = 0usize;
    for parent in in_scan_order(parents) {
        let document = parent
            .document
            .as_ref()
            .ok_or_else(|| Status::internal("missing parent document"))?;
        let nested = children
            .remove(&document.name)
            .ok_or_else(|| Status::internal("missing child input"))?;
        let mut values = Vec::new();
        for child in in_scan_order(nested)
            .iter()
            .filter_map(|r| r.document.as_ref())
        {
            let row = document_row(child)?;
            match Expr::Field(field.clone()).eval_in_with_runtime(
                &row,
                unrecorded,
                (*runtime).clone(),
            ) {
                pipeline_exec::Eval::Value(value) => values.push(value),
                _ => {
                    return Err(Status::unimplemented(
                        "subcollection selected value is unobserved",
                    ))
                }
            }
        }
        let aliases = aliases
            .iter()
            .map(|(name, expr)| {
                (
                    name.clone(),
                    if matches!(expr, Expr::SubcollectionArray { .. }) {
                        Expr::Constant(fireemu_core_firestore::value::Value::Array(values.clone()))
                    } else {
                        expr.clone()
                    },
                )
            })
            .collect();
        let mut cursor = pipeline_exec::Cursor::new_in_with_runtime(
            vec![Stage::Select {
                aliases,
                keeps_name: *keeps_name,
            }],
            unrecorded,
            (*runtime).clone(),
        );
        let mut rows = cursor
            .push(document_row(document)?)
            .map_err(|e| eval_status(&e))?;
        rows.extend(cursor.finish().map_err(|e| eval_status(&e))?);
        for row in rows {
            let result = row_document(&row);
            output_bytes = output_bytes
                .checked_add(result.encoded_len())
                .filter(|n| *n <= 1_048_576)
                .ok_or_else(|| Status::unimplemented("subquery result exceeds local bound"))?;
            output.push(result);
        }
    }
    Ok(pack_results(output, read_time))
}

/// Executes the observed one-binding scalar form from two guarded same-snapshot sources.
#[allow(clippy::too_many_lines)]
pub(crate) fn execute_correlated_scalar(
    local: &crate::local::LocalBackend,
    database: &str,
    compiled: &CompiledExecution,
    binding: &(String, FieldPath),
    guard: crate::rules::ReadGuard<'_>,
    unrecorded: Unrecorded,
    runtime: &pipeline_exec::RuntimeContext,
) -> Result<Vec<pb::ExecutePipelineResponse>, Status> {
    use fireemu_core_firestore::value::Value;
    use prost::Message as _;
    let [Stage::Select {
        aliases,
        keeps_name,
    }] = compiled.stages.as_slice()
    else {
        return Err(Status::unimplemented("unsupported correlated outer stages"));
    };
    if compiled.documents.is_some()
        || compiled.database
        || compiled.search.is_some()
        || !compiled.unions.is_empty()
        || aliases.len() > 32
    {
        return Err(Status::unimplemented("unsupported correlated outer input"));
    }
    let specs: Vec<_> = aliases
        .iter()
        .filter_map(|(_, expr)| match expr {
            Expr::CorrelatedScalar {
                collection,
                predicate,
                filter,
                variable,
                field,
            } => Some((collection, predicate, filter, variable, field)),
            _ => None,
        })
        .collect();
    if specs.len() != 1
        || aliases
            .iter()
            .any(|(_, expr)| !matches!(expr, Expr::Field(_) | Expr::CorrelatedScalar { .. }))
    {
        return Err(Status::unimplemented("unsupported correlated select"));
    }
    let (collection, predicate, filter, variable, field) = specs[0];
    if variable != &binding.0 {
        return Err(Status::unimplemented("correlated variable is unbound"));
    }
    let mut outer = compiled.input.clone();
    let Some(pb::run_query_request::QueryType::StructuredQuery(query)) = outer.query_type.as_mut()
    else {
        return Err(Status::unimplemented("unsupported correlated input"));
    };
    if query.from.len() != 1 || query.from[0].all_descendants {
        return Err(Status::unimplemented("unsupported correlated input"));
    }
    query.select = None;
    query.limit = Some(33);
    let mut inner = collection_query(
        format!("{database}/documents"),
        collection.clone(),
        None,
        None,
        0,
        Some(65),
    );
    let Some(pb::run_query_request::QueryType::StructuredQuery(query)) = inner.query_type.as_mut()
    else {
        return Err(Status::internal("missing correlated query"));
    };
    query.from[0].all_descendants = true;
    let mut sources = local
        .run_pipeline_sources(&[outer, inner], guard)?
        .into_iter();
    let parents = in_scan_order(
        sources
            .next()
            .ok_or_else(|| Status::internal("missing correlated parent"))?,
    );
    let children = in_scan_order(
        sources
            .next()
            .ok_or_else(|| Status::internal("missing correlated source"))?,
    );
    let read_time = parents.iter().find_map(|r| r.read_time);
    let parents: Vec<_> = parents.into_iter().filter_map(|r| r.document).collect();
    let children: Vec<_> = children.into_iter().filter_map(|r| r.document).collect();
    if parents.len() > 32 || children.len() > 64 {
        return Err(Status::unimplemented(
            "correlated input exceeds local bound",
        ));
    }
    let mut input_bytes = 0usize;
    for d in parents.iter().chain(&children) {
        input_bytes = input_bytes
            .checked_add(d.encoded_len())
            .filter(|n| *n <= 1_048_576)
            .ok_or_else(|| Status::unimplemented("correlated input exceeds local bound"))?;
    }
    let mut output = Vec::new();
    let mut output_bytes = 0usize;
    for document in parents {
        let parent_row = document_row(&document)?;
        let pipeline_exec::Eval::Value(Value::String(parent_value)) = Expr::Field(
            binding.1.clone(),
        )
        .eval_in_with_runtime(&parent_row, unrecorded, (*runtime).clone()) else {
            return Err(Status::unimplemented(
                "correlated binding type is unobserved",
            ));
        };
        let mut matched = None;
        for child in &children {
            let child_row = document_row(child)?;
            let pipeline_exec::Eval::Value(Value::String(key)) = Expr::Field(predicate.clone())
                .eval_in_with_runtime(&child_row, unrecorded, (*runtime).clone())
            else {
                return Err(Status::unimplemented(
                    "correlated predicate type is unobserved",
                ));
            };
            if key != parent_value {
                continue;
            }
            if let Some((filter_field, expected)) = filter {
                let pipeline_exec::Eval::Value(Value::String(actual)) = Expr::Field(
                    filter_field.clone(),
                )
                .eval_in_with_runtime(&child_row, unrecorded, (*runtime).clone()) else {
                    return Err(Status::unimplemented(
                        "correlated filter type is unobserved",
                    ));
                };
                if &actual != expected {
                    continue;
                }
            }
            if matched.is_some() {
                return Err(Status::invalid_argument(SCALAR_MULTIPLE_RESULTS));
            }
            matched = Some(
                match Expr::Field(field.clone()).eval_in_with_runtime(
                    &child_row,
                    unrecorded,
                    (*runtime).clone(),
                ) {
                    pipeline_exec::Eval::Value(Value::String(value)) => Value::String(value),
                    _ => {
                        return Err(Status::unimplemented(
                            "correlated scalar value is unobserved",
                        ))
                    }
                },
            );
        }
        let replacement = matched.unwrap_or(Value::Null);
        let aliases = aliases
            .iter()
            .map(|(name, expr)| {
                (
                    name.clone(),
                    if matches!(expr, Expr::CorrelatedScalar { .. }) {
                        Expr::Constant(replacement.clone())
                    } else {
                        expr.clone()
                    },
                )
            })
            .collect();
        let mut cursor = pipeline_exec::Cursor::new_in_with_runtime(
            vec![Stage::Select {
                aliases,
                keeps_name: *keeps_name,
            }],
            unrecorded,
            (*runtime).clone(),
        );
        let mut rows = cursor.push(parent_row).map_err(|e| eval_status(&e))?;
        rows.extend(cursor.finish().map_err(|e| eval_status(&e))?);
        for row in rows {
            let result = row_document(&row);
            output_bytes = output_bytes
                .checked_add(result.encoded_len())
                .filter(|n| *n <= 1_048_576)
                .ok_or_else(|| Status::unimplemented("correlated output exceeds local bound"))?;
            output.push(result);
        }
    }
    Ok(pack_results(output, read_time))
}

/// Extracts the sole observed lexical binding and removes it from the compiler-only clone.
pub(crate) fn prepare_correlated_binding(
    request: &mut pb::ExecutePipelineRequest,
) -> Result<Option<(String, FieldPath)>, Status> {
    use pb::value::ValueType as V;
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        request.pipeline_type.as_mut()
    else {
        return Ok(None);
    };
    let Some(pipeline) = structured.pipeline.as_mut() else {
        return Ok(None);
    };
    if !pipeline.stages.iter().any(|stage| stage.name == "let") {
        return Ok(None);
    }
    let [outer, binding, select] = pipeline.stages.as_slice() else {
        return Err(Status::unimplemented("unsupported correlated stages"));
    };
    if outer.name != "collection"
        || binding.name != "let"
        || select.name != "select"
        || !binding.options.is_empty()
    {
        return Err(Status::unimplemented("unsupported correlated stages"));
    }
    let [pb::Value {
        value_type: Some(V::MapValue(map)),
    }] = binding.args.as_slice()
    else {
        return Err(Status::unimplemented("unsupported correlated binding"));
    };
    if map.fields.len() != 1 {
        return Err(Status::unimplemented("unsupported correlated binding"));
    }
    let Some((
        name,
        pb::Value {
            value_type: Some(V::FieldReferenceValue(field)),
        },
    )) = map.fields.iter().next()
    else {
        return Err(Status::unimplemented("unsupported correlated binding"));
    };
    if decode_alias(name)?.segments().len() != 1 {
        return Err(Status::unimplemented("unsupported correlated binding"));
    }
    let field = FieldPath::parse(field)
        .map_err(|_| Status::unimplemented("unsupported correlated binding field"))?;
    let name = name.clone();
    pipeline.stages.remove(1);
    Ok(Some((name, field)))
}

/// Whether the selected expression requires a correlated scalar source.
pub(crate) fn has_correlated_scalar(compiled: &CompiledExecution) -> bool {
    compiled.stages.iter().any(|stage| matches!(stage, Stage::Select { aliases, .. } if aliases.iter().any(|(_, expr)| matches!(expr, Expr::CorrelatedScalar { .. }))))
}

/// Whether a direct selected operand requires prepared subcollection input.
pub(crate) fn has_subcollection_array(compiled: &CompiledExecution) -> bool {
    compiled.stages.iter().any(|stage| matches!(stage, Stage::Select { aliases, .. } if aliases.iter().any(|(_, expr)| matches!(expr, Expr::SubcollectionArray { .. }))))
}

/// Executes the admitted union plan from one guarded, immutable snapshot.
pub(crate) fn execute_union(
    local: &crate::local::LocalBackend,
    mut compiled: CompiledExecution,
    guard: crate::rules::ReadGuard<'_>,
    unrecorded: Unrecorded,
    runtime: pipeline_exec::RuntimeContext,
) -> Result<Vec<pb::ExecutePipelineResponse>, Status> {
    if compiled.documents.is_some() || compiled.search.is_some() {
        return Err(Status::unimplemented(
            "union parent input is not a supported collection",
        ));
    }
    let mut requests = vec![compiled.input.clone()];
    for (_, branches) in &compiled.unions {
        requests.extend(branches.iter().map(|branch| branch.input.clone()));
    }
    let mut results = local.run_pipeline_sources(&requests, guard)?.into_iter();
    let primary = in_scan_order(
        results
            .next()
            .ok_or_else(|| Status::internal("missing union input"))?,
    );
    let execution_time = primary.iter().find_map(|row| row.read_time);
    for (position, branches) in compiled.unions {
        let mut prepared = Vec::with_capacity(branches.len());
        for branch in branches {
            let rows = in_scan_order(
                results
                    .next()
                    .ok_or_else(|| Status::internal("missing union branch"))?,
            )
            .iter()
            .filter_map(|row| row.document.as_ref())
            .map(document_row)
            .collect::<Result<Vec<_>, _>>()?;
            prepared.push(pipeline_exec::PreparedUnionBranch {
                stages: branch.stages,
                rows,
            });
        }
        let Some(Stage::Union { branches }) = compiled.stages.get_mut(position) else {
            return Err(Status::internal("invalid union stage position"));
        };
        *branches = prepared;
    }
    let mut cursor =
        pipeline_exec::Cursor::new_in_with_runtime(compiled.stages, unrecorded, runtime);
    let mut output = Vec::new();
    for row in primary.iter().filter_map(|row| row.document.as_ref()) {
        if cursor.is_exhausted() {
            break;
        }
        output.extend(
            cursor
                .push(document_row(row)?)
                .map_err(|error| eval_status(&error))?,
        );
    }
    output.extend(cursor.finish().map_err(|error| eval_status(&error))?);
    Ok(pack_results(
        output.iter().map(row_document).collect(),
        execution_time,
    ))
}

/// The status of an expression error. fireemu's own argument-count texts are not
/// production's (which names the function's signature), so strict refuses them as unobserved.
fn expr_status(error: ExprError, unrecorded: Unrecorded) -> Status {
    match error {
        ExprError::Unsupported(message) => Status::unimplemented(message),
        ExprError::Invalid(message) if unrecorded == Unrecorded::Refuse => {
            Status::unimplemented(format!("{message}; this text is not observed locally"))
        }
        // `Arity` is production's wording (the signature); strict's shape gate answers it only
        // for a recorded request.
        ExprError::Invalid(message) | ExprError::Arity(message) => {
            Status::invalid_argument(message)
        }
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
        pipeline_exec::EvalError::TimestampOutOfRange { .. } => {
            crate::production_status::timestamp_out_of_range(&error.to_string())
        }
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

/// An operand as the official emulator 1.22.0 prints it in a refusal (probed 2026-10-27):
/// integers as `1L`, doubles as `1.5D`, strings in quotes (unescaped), `true`, `false`, `null`,
/// arrays as `[1L, 2L]`, maps as `{k=1L, b=true}` in the order the request wrote them, field
/// references by path and calls as
/// `name(arg, ...)`. `None` for the kinds not printed here (timestamps, bytes, references,
/// vectors, variables, pipelines) and for a double Java prints in exponent form.
fn expression_text(value: &pb::Value) -> Option<String> {
    use pb::value::ValueType as V;
    Some(match value.value_type.as_ref()? {
        V::NullValue(_) => "null".to_owned(),
        V::BooleanValue(b) => b.to_string(),
        V::IntegerValue(n) => format!("{n}L"),
        V::DoubleValue(d) => {
            let magnitude = d.abs();
            if !d.is_finite() || (magnitude != 0.0 && !(1e-3..1e7).contains(&magnitude)) {
                return None;
            }
            // The official emulator stores a negative zero as zero.
            let d = if *d == 0.0 { 0.0 } else { *d };
            format!("{d:?}D")
        }
        V::StringValue(text) => format!("\"{text}\""),
        V::FieldReferenceValue(path) => path.clone(),
        V::ArrayValue(array) => format!(
            "[{}]",
            array
                .values
                .iter()
                .map(expression_text)
                .collect::<Option<Vec<_>>>()?
                .join(", ")
        ),
        V::MapValue(map) => {
            // The jar prints the entries in the order the request wrote them (probed
            // 2026-10-27: `{k=1L, b=true}`); a map whose order was lost has no text.
            let keys = wire_keys(&map.fields)?;
            let entries = keys
                .into_iter()
                .map(|key| Some(format!("{key}={}", expression_text(&map.fields[key])?)))
                .collect::<Option<Vec<_>>>()?;
            format!("{{{}}}", entries.join(", "))
        }
        V::FunctionValue(function) => format!(
            "{}({})",
            function.name,
            function
                .args
                .iter()
                .map(expression_text)
                .collect::<Option<Vec<_>>>()?
                .join(", ")
        ),
        _ => return None,
    })
}

/// The refusal of a call that reads no field, evaluated once before any row (its answer is the
/// same for every row): `None` when it answers a value.
fn constant_call_error(expr: &Expr) -> Option<Status> {
    fn reads_field(expr: &Expr) -> bool {
        match expr {
            Expr::Field(_)
            | Expr::Variable(_)
            | Expr::SubcollectionArray { .. }
            | Expr::CorrelatedScalar { .. } => true,
            Expr::Constant(_) => false,
            Expr::Call { function, args } => {
                matches!(
                    function.name,
                    "current_document"
                        | "array_filter"
                        | "array_transform"
                        | "rand"
                        | "autogen_document_id"
                ) || args.iter().any(reads_field)
            }
        }
    }
    // A call of a string or math function fails per row, like the logic functions below: its
    // failures were recorded with a row (O-8B), and the empty collection answers no row.
    fn calls_scalar(expr: &Expr) -> bool {
        match expr {
            Expr::Call { function, args } => {
                pipeline_exec::scalar::NAMES.contains(&function.name)
                    || args.iter().any(calls_scalar)
            }
            _ => false,
        }
    }
    if reads_field(expr) || calls_scalar(expr) {
        return None;
    }
    let row = pipeline_exec::Row::document(
        DocumentPath::parse(
            &fireemu_core_types::ids::ProjectId::try_new("p").ok()?,
            &fireemu_core_types::ids::DatabaseId::try_new("(default)").ok()?,
            "c/d",
        )
        .ok()?,
        std::collections::BTreeMap::new(),
    );
    match expr.eval_in(&row, Unrecorded::Refuse) {
        // Production fails these calls per row and answered the empty collection with no result
        // (FS-ENT-ORACLE O-1 `px1/static-refusals`), and with a row it refused them in the words
        // of O-9 `ops-main`: they are executed, and the shape gate answers the failure.
        pipeline_exec::Eval::Error(pipeline_exec::EvalError::WrongType {
            function: "and" | "or" | "nor" | "xor" | "array_contains" | "eq_any",
            ..
        }) => None,
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

fn decode_operand_tree(value: &pb::Value, unrecorded: Unrecorded) -> Result<Expr, Status> {
    decode_operand_tree_in(value, unrecorded, false, &[], true)
}

#[allow(clippy::too_many_lines)]
fn decode_correlated_scalar(nested: &pb::Pipeline) -> Result<Expr, Status> {
    use pb::value::ValueType as V;
    let (input, filter, extra_filter, select) = match nested.stages.as_slice() {
        [input, filter, select] => (input, filter, None, select),
        [input, filter, extra_filter, select] => (input, filter, Some(extra_filter), select),
        _ => return Err(Status::unimplemented("unsupported scalar pipeline")),
    };
    if input.name != "collection_group"
        || filter.name != "where"
        || select.name != "select"
        || !input.options.is_empty()
        || !filter.options.is_empty()
        || !select.options.is_empty()
    {
        return Err(Status::unimplemented("unsupported scalar pipeline"));
    }
    let [pb::Value {
        value_type: Some(V::ReferenceValue(ancestor)),
    }, pb::Value {
        value_type: Some(V::StringValue(collection)),
    }] = input.args.as_slice()
    else {
        return Err(Status::unimplemented("unsupported scalar collection group"));
    };
    if !ancestor.is_empty() {
        return Err(Status::unimplemented("scalar group ancestor is unobserved"));
    }
    fireemu_core_types::ids::CollectionId::try_new(collection.as_str())
        .map_err(|_| Status::unimplemented("unsupported scalar collection id"))?;
    let [pb::Value {
        value_type: Some(V::FunctionValue(equal)),
    }] = filter.args.as_slice()
    else {
        return Err(Status::unimplemented("unsupported scalar predicate"));
    };
    if equal.name != "equal" || !equal.options.is_empty() {
        return Err(Status::unimplemented("unsupported scalar predicate"));
    }
    let [pb::Value {
        value_type: Some(V::FieldReferenceValue(predicate)),
    }, pb::Value {
        value_type: Some(V::VariableReferenceValue(variable)),
    }] = equal.args.as_slice()
    else {
        return Err(Status::unimplemented("unsupported scalar predicate"));
    };
    let predicate = FieldPath::parse(predicate)
        .map_err(|_| Status::unimplemented("unsupported scalar predicate field"))?;
    let variable_path = decode_alias(variable)?;
    if variable_path.segments().len() != 1 {
        return Err(Status::unimplemented("unsupported scalar variable"));
    }
    let extra_filter = if let Some(stage) = extra_filter {
        if stage.name != "where" || !stage.options.is_empty() {
            return Err(Status::unimplemented("unsupported scalar filter"));
        }
        let [pb::Value {
            value_type: Some(V::FunctionValue(equal)),
        }] = stage.args.as_slice()
        else {
            return Err(Status::unimplemented("unsupported scalar filter"));
        };
        if equal.name != "equal" || !equal.options.is_empty() {
            return Err(Status::unimplemented("unsupported scalar filter"));
        }
        let [pb::Value {
            value_type: Some(V::FieldReferenceValue(field)),
        }, pb::Value {
            value_type: Some(V::StringValue(expected)),
        }] = equal.args.as_slice()
        else {
            return Err(Status::unimplemented("unsupported scalar filter"));
        };
        Some((
            FieldPath::parse(field)
                .map_err(|_| Status::unimplemented("unsupported scalar filter field"))?,
            expected.clone(),
        ))
    } else {
        None
    };
    let [pb::Value {
        value_type: Some(V::MapValue(map)),
    }] = select.args.as_slice()
    else {
        return Err(Status::unimplemented("unsupported scalar select"));
    };
    if map.fields.len() != 1 {
        return Err(Status::unimplemented("unsupported scalar select"));
    }
    let Some((
        alias,
        pb::Value {
            value_type: Some(V::FieldReferenceValue(field)),
        },
    )) = map.fields.iter().next()
    else {
        return Err(Status::unimplemented("unsupported scalar select"));
    };
    if decode_alias(alias)?.segments().len() != 1 {
        return Err(Status::unimplemented("unsupported scalar alias"));
    }
    let field = FieldPath::parse(field)
        .map_err(|_| Status::unimplemented("unsupported scalar select field"))?;
    Ok(Expr::CorrelatedScalar {
        collection: collection.clone(),
        predicate,
        filter: extra_filter,
        variable: variable.clone(),
        field,
    })
}

fn decode_subcollection_array(nested: &pb::Pipeline) -> Result<Expr, Status> {
    use pb::value::ValueType as V;
    let [input, select] = nested.stages.as_slice() else {
        return Err(Status::unimplemented("unsupported nested pipeline"));
    };
    if input.name != "subcollection"
        || select.name != "select"
        || !input.options.is_empty()
        || !select.options.is_empty()
    {
        return Err(Status::unimplemented("unsupported nested pipeline"));
    }
    let [pb::Value {
        value_type: Some(V::StringValue(collection)),
    }] = input.args.as_slice()
    else {
        return Err(Status::unimplemented("unsupported subcollection input"));
    };
    fireemu_core_types::ids::CollectionId::try_new(collection.as_str())
        .map_err(|_| Status::unimplemented("unsupported subcollection id"))?;
    let [pb::Value {
        value_type: Some(V::MapValue(map)),
    }] = select.args.as_slice()
    else {
        return Err(Status::unimplemented("unsupported nested select"));
    };
    if map.fields.len() != 1 {
        return Err(Status::unimplemented("unsupported nested select"));
    }
    let Some((
        alias,
        pb::Value {
            value_type: Some(V::FieldReferenceValue(field)),
        },
    )) = map.fields.iter().next()
    else {
        return Err(Status::unimplemented("unsupported nested select"));
    };
    let alias = decode_alias(alias)?;
    if alias.segments().len() != 1 {
        return Err(Status::unimplemented(
            "nested select alias paths are unobserved",
        ));
    }
    let field =
        FieldPath::parse(field).map_err(|_| Status::unimplemented("unsupported nested field"))?;
    Ok(Expr::SubcollectionArray {
        collection: collection.clone(),
        field,
    })
}

#[allow(clippy::too_many_lines)]
fn decode_operand_tree_in(
    value: &pb::Value,
    unrecorded: Unrecorded,
    defer_constant: bool,
    bindings: &[String],
    direct: bool,
) -> Result<Expr, Status> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        None => Err(own_text(
            "expression argument is missing".to_owned(),
            unrecorded,
        )),
        Some(V::ReferenceValue(name))
            if !direct && unrecorded == Unrecorded::Refuse && name.split('/').count() == 5 =>
        {
            Err(Status::unimplemented(
                "a root reference inside an expression is not observed locally",
            ))
        }
        Some(V::FieldReferenceValue(field)) => Ok(Expr::Field(
            FieldPath::parse(field).map_err(|e| own_text(e.to_string(), unrecorded))?,
        )),
        Some(V::FunctionValue(function)) => {
            if function.name == "scalar" && function.options.is_empty() {
                if let [pb::Value {
                    value_type: Some(V::PipelineValue(nested)),
                }] = function.args.as_slice()
                {
                    return decode_correlated_scalar(nested);
                }
            }
            if function.name == "array" && function.options.is_empty() {
                if let [pb::Value {
                    value_type: Some(V::PipelineValue(nested)),
                }] = function.args.as_slice()
                {
                    return decode_subcollection_array(nested);
                }
            }
            if unrecorded == Unrecorded::Refuse
                && function.name == "array_reverse"
                && function.args.is_empty()
                && function.options.is_empty()
            {
                return Err(recorded_internal("array_reverse requires an argument"));
            }
            if pipeline_exec::function(&function.name).is_none() {
                return Err(Status::unimplemented(format!(
                    "function {:?} is unsupported locally",
                    function.name
                )));
            }
            // Production also records empty array() and map() (O-5 `function-names`).
            // The official emulator answers a function's argument count before its arguments'
            // own checks.
            let placeholders = vec![
                Expr::Constant(fireemu_core_firestore::value::Value::Null);
                function.args.len()
            ];
            Expr::call(&function.name, placeholders, Placement::Value)
                .map_err(|e| expr_status(e, unrecorded))?;
            // `exists` and `is_absent` take a field reference, nothing else: production and the
            // official emulator 1.22.0 refuse any other operand before any row, printing it
            // (FS-ENT-ORACLE O-9 `types-main`: `is_absent(is_type(zz, "null"))`).
            if matches!(function.name.as_str(), "exists" | "is_absent") {
                if let Some(argument) = function.args.first().filter(|argument| {
                    !matches!(argument.value_type, Some(V::FieldReferenceValue(_)))
                }) {
                    return Err(match expression_text(argument) {
                        Some(text) => Status::invalid_argument(format!(
                            "The argument {text} for function '{}' is required to be a constant field reference.",
                            function.name
                        )),
                        None if unrecorded == Unrecorded::Refuse => Status::unimplemented(
                            "this operand of exists or is_absent is not observed locally",
                        ),
                        None => Status::invalid_argument(format!(
                            "The argument of function '{}' is required to be a constant field reference.",
                            function.name
                        )),
                    });
                }
            }
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
            let mut body_bindings = bindings.to_vec();
            let binder = matches!(function.name.as_str(), "array_filter" | "array_transform");
            if binder {
                for (index, arg) in function.args[1..function.args.len() - 1].iter().enumerate() {
                    let Some(V::StringValue(alias)) = &arg.value_type else {
                        if function.name == "array_transform"
                            && index == 0
                            && matches!(arg.value_type, Some(V::FieldReferenceValue(_)))
                        {
                            return Err(Status::invalid_argument("The 'element_alias' argument of the 'array_transform' function must be a literal value, found: a property reference"));
                        }
                        return Err(Status::unimplemented(
                            "array callback aliases must be literal strings",
                        ));
                    };
                    body_bindings.push(alias.clone());
                }
            }
            let args = function
                .args
                .iter()
                .enumerate()
                .map(|(index, arg)| match &arg.value_type {
                    // Every reference constant passes the official checks first (r8 review
                    // M1): a malformed one is refused before any row, whatever it is passed to.
                    Some(V::ReferenceValue(name))
                        if document_function && unrecorded == Unrecorded::Refuse =>
                    {
                        if name.split('/').count() == 5 {
                            return Err(Status::unimplemented(
                                "a root reference inside an expression is not observed locally",
                            ));
                        }
                        match reference_literal_error(name) {
                            Some(text) => Err(Status::invalid_argument(text)),
                            None => Ok(Expr::Constant(
                                fireemu_core_firestore::value::Value::Reference(name.clone()),
                            )),
                        }
                    }
                    _ => decode_operand_tree_in(
                        arg,
                        unrecorded,
                        defer_constant
                            || matches!(
                                function.name.as_str(),
                                "if_absent"
                                    | "if_null"
                                    | "if_error"
                                    | "conditional"
                                    | "switch_on"
                                    | "coalesce"
                            )
                            || binder,
                        if binder && index == function.args.len() - 1 {
                            &body_bindings
                        } else {
                            bindings
                        },
                        false,
                    ),
                })
                .collect::<Result<Vec<_>, _>>()?;
            // `is_type` takes its type name as a literal, checked before any row is read
            // (FS-ENT-ORACLE O-1 `px1/static-refusals#select-is-type-bogus`, also on an empty
            // collection).
            if function.name == "is_type" {
                let named = function.args.get(1).is_some_and(|name| {
                    matches!(&name.value_type, Some(V::StringValue(n))
                        if pipeline_exec::TYPE_NAMES.contains(&n.as_str()))
                });
                if !named {
                    return Err(Status::invalid_argument(format!(
                        "The argument 'type' for function 'is_type' must be a literal of type string from the following list: [{}]",
                        pipeline_exec::TYPE_NAMES.join(", ")
                    )));
                }
            }
            let expr = Expr::call(&function.name, args, Placement::Value)
                .map_err(|e| expr_status(e, unrecorded))?;
            // Under strict a call of constants that fails is refused before any row is read,
            // so it never falls through to an empty answer (ruling of 2026-10-21, PX1d r6 (d)).
            if unrecorded == Unrecorded::Refuse && !defer_constant {
                if let Some(error) = constant_call_error(&expr) {
                    return Err(error);
                }
            }
            Ok(expr)
        }
        Some(V::VariableReferenceValue(name)) if bindings.contains(name) => {
            Ok(Expr::Variable(name.clone()))
        }
        Some(V::VariableReferenceValue(_) | V::PipelineValue(_)) => Err(Status::unimplemented(
            "variable and pipeline operands are unsupported locally",
        )),
        // The official emulator checks vectors and `__type__` keys before other literal keys.
        Some(_) if expression_kind(value).is_none() && literal_value_error(value).is_some() => {
            let error = literal_value_error(value).unwrap_or_default();
            match unrecorded {
                Unrecorded::Refuse if recorded_literal_error_class(&error) => {
                    Err(Status::invalid_argument(error))
                }
                Unrecorded::Refuse => Err(Status::unimplemented(unobserved_literal(&error))),
                Unrecorded::OfficialEmulator => Err(Status::invalid_argument(error)),
            }
        }
        Some(_) => match expression_kind(value) {
            // Production read literals of every kind, maps keyed by any name but an empty or a
            // reserved one (FS-ENT-ORACLE O-3, O-4 `o4/literals#*`); strict answers the shapes
            // it recorded (see `literal_shape_recorded`).
            None if unrecorded == Unrecorded::Refuse && !literal_shape_recorded(value, direct) => {
                Err(Status::unimplemented(
                    "a literal of this shape is not observed locally",
                ))
            }
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
            // Preserve the strict guard for malformed or unrecorded literal subtrees while
            // allowing recorded reserved-key and expression-type refusals to be checked.
            Some(_)
                if !literal_keys_are_plain(value)
                    && unrecorded == Unrecorded::Refuse
                    && !literal_expression_shape_safe(value) =>
            {
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
/// database (another database or the database root), more than 100 key
/// path elements, or an id that matches production's
/// documented reserved pattern `__.*__` (`____` included, which the official emulator accepts)
/// is refused as unobserved before any row (ruling of 2026-10-21 for `PX1d` r8: production's
/// documented limits).
fn reference_outside(value: &pb::Value, own: &str) -> Option<Status> {
    use pb::value::ValueType as V;
    match value.value_type.as_ref() {
        Some(V::ReferenceValue(name)) => {
            // A syntactically invalid non-resource name has a computed refusal; the caller's
            // request-shape gate decides whether production recorded it.
            if !name.starts_with("projects/") {
                if let Some(error) = reference_literal_error(name) {
                    return Some(Status::invalid_argument(error));
                }
            }
            // O-5 appendix also records the request database's documents root.
            let inside = name == own
                || name
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
        Some(V::FunctionValue(function)) => {
            if function.name == "scalar" && function.options.is_empty() {
                if let [pb::Value {
                    value_type: Some(V::PipelineValue(nested)),
                }] = function.args.as_slice()
                {
                    if decode_correlated_scalar(nested).is_ok() {
                        return None;
                    }
                }
            }
            function
                .args
                .iter()
                .chain(function.options.values())
                .find_map(|v| reference_outside(v, own))
        }
        Some(V::PipelineValue(pipeline)) => pipeline
            .stages
            .iter()
            .enumerate()
            .flat_map(|(index, stage)| {
                let source = usize::from(index == 0 && stage.name == "collection");
                stage.args.iter().skip(source).chain(stage.options.values())
            })
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

// These structural classes have recorded refusals. The request gate remains authoritative for
// the exact request shape and computed message.
fn recorded_literal_error_class(error: &str) -> bool {
    error.starts_with("Field __type__ must be a string; founds ")
        || error.starts_with("Document parent name ")
        || matches!(
            error,
            "Vector map is missing key 'value'."
                | "Vector value type must be an array."
                | "Vector value map has extraneous entries."
                | "Vector must only contain values of type 'double'"
        )
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

/// Whether production recorded a literal of this shape. Vectors contain finite doubles other
/// than negative zero (O-3 and O-4); O-5 additionally records direct single-component infinity
/// vectors and the documents-root reference. Reserved keys are handled by the ordered refusal
/// checks after this shape check.
fn literal_shape_recorded(value: &pb::Value, direct: bool) -> bool {
    use pb::value::ValueType as V;
    // O-5 appendix also records a well-formed vector within an array.
    fn walk(value: &pb::Value) -> bool {
        match value.value_type.as_ref() {
            Some(V::ArrayValue(array)) => array.values.iter().all(walk),
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
                // A non-vector tag remains an ordinary map (O-5 appendix n41 and r11).
                let typed =
                    key != "__type__" || matches!(inner.value_type, Some(V::StringValue(_)));
                typed && walk(inner)
            }),
            _ => true,
        }
    }
    // O-5 appendix records these as direct projection literals. Nested nonfinite vectors and
    // nested root references retain their existing unobserved guard.
    let recorded_direct = match value.value_type.as_ref() {
        Some(V::MapValue(map)) if is_vector_literal(value) && map.fields.len() == 2 => {
            matches!(map.fields.get("value").and_then(|v| v.value_type.as_ref()),
                Some(V::ArrayValue(array)) if matches!(array.values.as_slice(), [pb::Value { value_type: Some(V::DoubleValue(d)) }] if d.is_infinite()))
        }
        Some(V::ReferenceValue(name)) => name.is_ascii() && name.split('/').count() == 5,
        _ => false,
    };
    (direct && recorded_direct) || walk(value)
}

/// Keeps unrecorded malformed literal subtrees guarded when a container holds an expression.
fn literal_expression_shape_safe(value: &pb::Value) -> bool {
    use pb::value::ValueType as V;
    if literal_depth(value) > fireemu_core_firestore::value::MAX_NESTING_DEPTH as usize {
        return false;
    }
    if expression_kind(value).is_none() {
        return literal_value_error(value).is_none() && literal_shape_recorded(value, false);
    }
    match value.value_type.as_ref() {
        Some(V::ArrayValue(array)) => array.values.iter().all(literal_expression_shape_safe),
        Some(V::MapValue(map)) => {
            if is_vector_literal(value) {
                return false;
            }
            if let Some(typed) = map.fields.get("__type__") {
                if map.fields.len() != 1 || expression_kind(typed).is_none() {
                    return false;
                }
            }
            map.fields.values().all(literal_expression_shape_safe)
        }
        Some(V::FieldReferenceValue(_) | V::FunctionValue(_)) => true,
        _ => false,
    }
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
    if !def.returns_boolean
        || !matches!(def.arity, Arity::Exact(2))
        || (!def.signature.is_empty()
            && !matches!(
                def.name,
                "equal"
                    | "not_equal"
                    | "less_than"
                    | "less_than_or_equal"
                    | "greater_than"
                    | "greater_than_or_equal"
            ))
    {
        // A function of another value: production drops the row for the kinds it recorded
        // (FS-ENT-ORACLE O-2, `where` on `document_id`, `parent`, `array` and `map`); the
        // cursor decides by the value's kind.
        return Ok((decode_operand(condition, unrecorded)?, None));
    }
    // Check the outer call before decoding operands, using the same registry as value calls.
    let placeholders =
        vec![Expr::Constant(fireemu_core_firestore::value::Value::Null); function.args.len()];
    Expr::call(def.name, placeholders, Placement::Condition)
        .map_err(|error| expr_status(error, unrecorded))?;
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
                if unrecorded == Unrecorded::Refuse && quoted_alias_pair(earlier_alias, alias) {
                    return Err(recorded_internal("duplicate quoted select alias"));
                }
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

/// Writes a fixed explanation without including request contents in the diagnostic.
fn recorded_internal(reason: &'static str) -> Status {
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr(),
        "[firestore] pipeline: {reason}; production returns an internal error"
    );
    Status::internal("An internal error occurred.")
}

/// A plain alias and the same complete alias in quotes.
fn quoted_alias_pair(a: &str, b: &str) -> bool {
    fn quotes(quoted: &str, plain: &str) -> bool {
        !plain.contains('`')
            && quoted.strip_prefix('`').and_then(|s| s.strip_suffix('`')) == Some(plain)
    }
    quotes(a, b) || quotes(b, a)
}

/// Whether strict has a production answer for this `select` over `__name__`: the name selected
/// as itself is recorded alone (FS-ENT-ORACLE O5 `appendix#proposed-select-name-field`), with
/// either side quoted (O-8A `names-main`: a quoted alias, a quoted value) and, unquoted, beside
/// other aliases of plain field references (O-8A: a field under another alias, the name under a
/// second alias). Both sides quoted, or a quoted side beside other aliases, was never sent.
/// (The emulator profile answers every form as the official emulator does.)
fn name_select_recorded(fields: &std::collections::HashMap<String, pb::Value>) -> bool {
    fn reference(value: &pb::Value) -> Option<&str> {
        match &value.value_type {
            Some(pb::value::ValueType::FieldReferenceValue(field)) => Some(field.as_str()),
            _ => None,
        }
    }
    let names_document =
        |text: &str| parse_alias(text).is_ok_and(|path| path.segments() == ["__name__"]);
    let plain = |text: &str| {
        let mut chars = text.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let itself: Vec<_> = fields
        .iter()
        .filter(|(alias, value)| {
            names_document(alias) && reference(value).is_some_and(names_document)
        })
        .collect();
    let [(alias, value)] = itself[..] else {
        // None selects the name as itself; several spell the same alias twice.
        return itself.is_empty();
    };
    let field = reference(value).unwrap_or_default();
    if fields.len() == 1 {
        return plain(alias) || plain(field);
    }
    plain(alias)
        && plain(field)
        && fields
            .iter()
            .filter(|(other, _)| *other != alias)
            .all(|(other, value)| plain(other) && reference(value).is_some_and(plain))
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
/// `#limit-string`, `#offset-string`, `#limit-negative`). O-5 records additional wrong-type
/// refusals and a negative offset. The outer request shape gate determines strict admission.
fn count_argument(stage: &pb::pipeline::Stage) -> Result<u64, Status> {
    use pb::value::ValueType as V;
    let name = stage.name.as_str();
    let argument = stage.args.first().and_then(|v| v.value_type.as_ref());
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

/// Decodes `sort(ordering, ...)`: each ordering is a map of `direction` (`ascending` or
/// `descending`) and `expression`, whose checks production answered in this order
/// (FS-ENT-ORACLE O-6 `sort-wire-errors`): the argument is a map, the expression is present,
/// the direction is present, a string and one of the two names, and nothing else is in the map.
/// Any value is an expression: a string literal orders every row alike.
fn decode_sort(
    stage: &pb::pipeline::Stage,
    unrecorded: Unrecorded,
) -> Result<Vec<pipeline_exec::SortKey>, Status> {
    use pb::value::ValueType as V;
    let mut keys = Vec::with_capacity(stage.args.len());
    for (index, argument) in stage.args.iter().enumerate() {
        let Some(V::MapValue(map)) = argument.value_type.as_ref() else {
            return Err(Status::invalid_argument(format!(
                "Expected ordering[{index}] to be MAP_VALUE, but was {}.",
                value_type_name(argument.value_type.as_ref())
            )));
        };
        let Some(expression) = map.fields.get("expression") else {
            return Err(Status::invalid_argument(
                "Order is missing 'expression' field.",
            ));
        };
        let Some(direction) = map.fields.get("direction") else {
            return Err(Status::invalid_argument(
                "Order is missing 'direction' field.",
            ));
        };
        let descending = match direction.value_type.as_ref() {
            Some(V::StringValue(name)) if name == "ascending" => false,
            Some(V::StringValue(name)) if name == "descending" => true,
            Some(V::StringValue(name)) => {
                return Err(Status::invalid_argument(format!(
                    "Unsupported direction '{name}'. Valid options are: [ascending, descending]."
                )))
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "Expected Order.direction to be STRING_VALUE, but was {}.",
                    value_type_name(other)
                )))
            }
        };
        let mut unexpected: Vec<&str> = map
            .fields
            .keys()
            .map(String::as_str)
            .filter(|key| !matches!(*key, "expression" | "direction"))
            .collect();
        if !unexpected.is_empty() {
            unexpected.sort_unstable();
            return Err(Status::invalid_argument(format!(
                "Order has unexpected fields: [{}].",
                unexpected.join(", ")
            )));
        }
        keys.push(pipeline_exec::SortKey {
            expr: decode_operand_tree(expression, unrecorded)?,
            descending,
        });
    }
    Ok(keys)
}

/// The type texts production answered for the arguments of a stage with a signature, after its
/// arity (FS-ENT-ORACLE O-7 `aggregate-args`, `distinct-main`, `fields-main`, `inputs-*`).
fn stage_type_error(stage: &pb::pipeline::Stage) -> Option<Status> {
    use pb::value::ValueType as V;
    let expected = |what: &str, wanted: &str, got: Option<&V>| {
        Some(Status::invalid_argument(format!(
            "Expected {what} to be {wanted}, but was {}.",
            value_type_name(got)
        )))
    };
    match stage.name.as_str() {
        "sample" => {
            let mode = match stage.args[1].value_type.as_ref() {
                Some(V::StringValue(mode)) if mode == "documents" || mode == "percent" => mode,
                Some(V::StringValue(mode)) => {
                    return Some(Status::invalid_argument(format!(
                        "Unsupported Sample Mode: {mode}"
                    )))
                }
                other => return expected("SampleMode", "STRING_VALUE", other),
            };
            match (mode.as_str(), stage.args[0].value_type.as_ref()) {
                ("documents", Some(V::IntegerValue(n))) if *n < 0 => Some(
                    Status::invalid_argument("The 'size' parameter must be non-negative."),
                ),
                ("documents", Some(V::IntegerValue(_))) => None,
                ("documents", other) => expected("size", "INTEGER_VALUE", other),
                ("percent", Some(V::IntegerValue(n))) if !(0..=1).contains(n) => Some(
                    Status::invalid_argument("The 'size' parameter must be between 0.0 and 1.0."),
                ),
                ("percent", Some(V::DoubleValue(n)))
                    if n.is_finite() && !(0.0..=1.0).contains(n) =>
                {
                    Some(Status::invalid_argument(
                        "The 'size' parameter must be between 0.0 and 1.0.",
                    ))
                }
                ("percent", Some(V::IntegerValue(_) | V::DoubleValue(_))) => None,
                (_, other) => expected("size", "DOUBLE_VALUE", other),
            }
        }
        "union" => match stage.args[0].value_type.as_ref() {
            Some(V::PipelineValue(_)) => None,
            other => expected("other", "PIPELINE_VALUE", other),
        },
        "distinct" => match stage.args[0].value_type.as_ref() {
            Some(V::MapValue(_)) => None,
            other => expected("fields", "MAP_VALUE", other),
        },
        "aggregate" => [("accumulators", &stage.args[0]), ("groups", &stage.args[1])]
            .into_iter()
            .find_map(|(what, arg)| match arg.value_type.as_ref() {
                Some(V::MapValue(_)) => None,
                other => expected(what, "MAP_VALUE", other),
            }),
        "remove_fields" => {
            stage
                .args
                .iter()
                .enumerate()
                .find_map(|(i, arg)| match arg.value_type.as_ref() {
                    Some(V::FieldReferenceValue(_)) => None,
                    other => expected(&format!("fields[{i}]"), "FIELD_REFERENCE_VALUE", other),
                })
        }
        "documents" => {
            stage
                .args
                .iter()
                .enumerate()
                .find_map(|(i, arg)| match arg.value_type.as_ref() {
                    Some(V::ReferenceValue(_)) => None,
                    other => expected(&format!("paths[{i}]"), "REFERENCE_VALUE", other),
                })
        }
        "collection_group" => match stage.args[0].value_type.as_ref() {
            Some(V::ReferenceValue(_)) => match stage.args[1].value_type.as_ref() {
                Some(V::StringValue(_)) => None,
                other => expected("collection_id", "STRING_VALUE", other),
            },
            other => expected("ancestor", "REFERENCE_VALUE", other),
        },
        _ => None,
    }
}

/// A top-level output name of `distinct` or `aggregate`: an alias of one segment.
fn top_level_name(alias: &str) -> Result<String, Status> {
    let path = parse_alias(alias)?;
    match path.segments() {
        [name] => Ok(name.clone()),
        _ => Err(Status::unimplemented(
            "a nested alias of this stage is not observed locally",
        )),
    }
}

/// The aliases of an alias map with their decoded values, in alias order.
fn decode_alias_map(
    value: &pb::Value,
    unrecorded: Unrecorded,
) -> Result<Vec<(String, Expr)>, Status> {
    let Some(fields) = map_fields(value) else {
        return Err(Status::unimplemented("an alias map is expected"));
    };
    ordered_keys(fields)
        .into_iter()
        .map(|alias| {
            Ok((
                top_level_name(alias)?,
                decode_operand_tree(&fields[alias], unrecorded)?,
            ))
        })
        .collect()
}

/// Decodes `distinct({alias: expression, ...})`.
fn decode_distinct(
    stage: &pb::pipeline::Stage,
    unrecorded: Unrecorded,
) -> Result<Vec<(String, Expr)>, Status> {
    decode_alias_map(&stage.args[0], unrecorded)
}

/// Decodes `add_fields({alias: expression, ...})`: an alias is a field path, as in `select`.
fn decode_add_fields(
    stage: &pb::pipeline::Stage,
    unrecorded: Unrecorded,
) -> Result<Vec<(FieldPath, Expr)>, Status> {
    let Some(fields) = stage.args.first().and_then(map_fields) else {
        return Err(Status::unimplemented("an alias map is expected"));
    };
    let mut aliases = Vec::with_capacity(fields.len());
    for alias in ordered_keys(fields) {
        let expr = decode_operand_tree(&fields[alias], unrecorded)?;
        let path = parse_alias(alias)?;
        // `__name__` assigned itself is no overwrite: the official emulator accepts it.
        if path.is_document_name()
            && matches!(&expr, Expr::Field(source) if source.is_document_name())
        {
            continue;
        }
        aliases.push((path, expr));
    }
    // An alias inside another is refused naming the alias set later in the request, in both
    // orders and also when the parent's value is missing (FS-ENT-ORACLE O-9 `fields-main`).
    for (at, (path, _)) in aliases.iter().enumerate() {
        if aliases[..at]
            .iter()
            .any(|(earlier, _)| earlier.is_prefix_of(path) || path.is_prefix_of(earlier))
        {
            return Err(crate::production_status::add_fields_overlapping_paths(
                &path.canonical(),
            ));
        }
    }
    if let Some(error) = ordered_keys(fields)
        .into_iter()
        .find_map(|alias| map_key_error(&fields[alias]))
    {
        return Err(error);
    }
    Ok(aliases)
}

/// Decodes `remove_fields(field, ...)`; the types are checked by [`stage_type_error`].
fn decode_remove_fields(stage: &pb::pipeline::Stage) -> Result<Vec<FieldPath>, Status> {
    stage
        .args
        .iter()
        .map(|arg| match &arg.value_type {
            Some(pb::value::ValueType::FieldReferenceValue(field)) => {
                FieldPath::parse(field).map_err(|e| Status::invalid_argument(e.to_string()))
            }
            _ => Err(Status::unimplemented("a field reference is expected")),
        })
        .collect()
}

/// The accumulators `aggregate` takes, with the signatures production names in its refusals.
fn accumulator_kind(name: &str) -> Option<(pipeline_exec::AccumulatorKind, &'static str)> {
    use pipeline_exec::AccumulatorKind as K;
    Some(match name {
        "count" => (K::Count, "count(expression: any?): int64"),
        "count_distinct" => (K::CountDistinct, "count_distinct(expression: any?): int64"),
        "sum" => (K::Sum, "sum(expression: any?): number?"),
        "average" => (K::Average, "average(expression: any?): number?"),
        "minimum" => (K::Minimum, "minimum(expression: any?): any?"),
        "maximum" => (K::Maximum, "maximum(expression: any?): any?"),
        "array_agg" => (K::ArrayAgg, "array_agg(expression: any): array[any]"),
        "array_agg_distinct" => (
            K::ArrayAggDistinct,
            "array_agg_distinct(expression: any): array[any]",
        ),
        "first" => (K::First, "first(expression: any): any"),
        "last" => (K::Last, "last(expression: any): any"),
        "count_if" => (K::CountIf, "count_if(expression: boolean): int64"),
        _ => return None,
    })
}

/// Decodes one accumulator of `aggregate`, with production's refusals (FS-ENT-ORACLE O-7
/// `aggregate-args`): a field is "only allowed in a scalar expression", a scalar function is
/// "not an" accumulator (named as its own suggestion), `count` takes none or one argument, the
/// others exactly one.
fn decode_accumulator(
    value: &pb::Value,
    unrecorded: Unrecorded,
) -> Result<pipeline_exec::Accumulator, Status> {
    use pb::value::ValueType as V;
    use pipeline_exec::{Accumulator, AccumulatorKind};
    let function = match value.value_type.as_ref() {
        Some(V::FunctionValue(function)) => function,
        Some(V::FieldReferenceValue(_)) => {
            return Err(Status::invalid_argument(
                "Field references are only allowed in a scalar expression.",
            ))
        }
        _ => {
            return Err(Status::unimplemented(
                "an accumulator that is no function is not observed locally",
            ))
        }
    };
    let Some((kind, signature)) = accumulator_kind(&function.name) else {
        return Err(if pipeline_exec::function(&function.name).is_some() {
            Status::invalid_argument(format!(
                "The function '{0}' does not exist, did you mean '{0}'?",
                function.name
            ))
        } else {
            Status::unimplemented(format!(
                "function {:?} is unsupported locally",
                function.name
            ))
        });
    };
    if !function.options.is_empty() && unrecorded == Unrecorded::Refuse {
        return Err(Status::unimplemented(format!(
            "function {:?} options are not observed locally",
            function.name
        )));
    }
    let given = function.args.len();
    if function.name == "count" {
        if given > 1 {
            return Err(Status::invalid_argument(format!(
                "The function 'count' does not accept {given} argument(s). Valid options are:\n- count(): int64 with [0..0] argument(s).\n- {signature} with [1..1] argument(s)."
            )));
        }
    } else if given != 1 {
        return Err(Status::invalid_argument(format!(
            "The function '{signature}' takes [1..1] argument(s), but {given} {} provided.",
            if given == 1 { "was" } else { "were" }
        )));
    }
    let argument = function
        .args
        .first()
        .map(|arg| decode_operand_tree(arg, unrecorded))
        .transpose()?;
    Ok(Accumulator {
        kind: match (kind, &argument) {
            (AccumulatorKind::Count, None) => AccumulatorKind::CountAll,
            (kind, _) => kind,
        },
        argument,
    })
}

type AggregateParts = (
    Vec<(String, pipeline_exec::Accumulator)>,
    Vec<(String, Expr)>,
);

/// Decodes `aggregate({accumulators}, {groups})`.
fn decode_aggregate(
    stage: &pb::pipeline::Stage,
    unrecorded: Unrecorded,
) -> Result<AggregateParts, Status> {
    let Some(accumulators) = map_fields(&stage.args[0]) else {
        return Err(Status::unimplemented("an alias map is expected"));
    };
    let accumulators = ordered_keys(accumulators)
        .into_iter()
        .map(|alias| {
            Ok((
                top_level_name(alias)?,
                decode_accumulator(&accumulators[alias], unrecorded)?,
            ))
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let groups = decode_alias_map(&stage.args[1], unrecorded)?;
    Ok((accumulators, groups))
}

fn decode_unnest(stage: &pb::pipeline::Stage, unrecorded: Unrecorded) -> Result<Stage, Status> {
    use pb::value::ValueType as V;
    let [value, alias] = stage.args.as_slice() else {
        return Err(Status::unimplemented("unnest arity is unobserved"));
    };
    let Some(V::FieldReferenceValue(alias_name)) = alias.value_type.as_ref() else {
        return Err(Status::unimplemented("unnest alias type is unobserved"));
    };
    let alias = parse_alias(alias_name)?;
    if let Some(message) = reserved_alias("unnest", alias_name) {
        return Err(Status::invalid_argument(message));
    }
    if alias.segments().len() != 1 {
        let message = format!("The nested field reference '{alias_name}' is not supported in its current use case.\n\nCertain stages like `aggregate(...)` or `unnest(...)` only support assigning to top-level fields. This means you cannot use an alias like 'foo.bar' to assign the result to a nested field. If you want to use an alias that has a dot in it, escape the path with backticks, like `foo.bar`.\n\nDepending on the SDK, this can be done like so:`.distinct(field(\"address.city\").as(\"`address.city`\"))`");
        return Err(crate::production_status::top_level_property_path_only(
            alias_name, &message,
        ));
    }
    let index_field = match stage.options.get("index_field") {
        None => None,
        Some(option) => {
            let Some(V::FieldReferenceValue(name)) = option.value_type.as_ref() else {
                return Err(Status::unimplemented(
                    "unnest index field type is unobserved",
                ));
            };
            let path = parse_alias(name)?;
            if path.segments().len() != 1 || reserved_alias("unnest", name).is_some() {
                return Err(Status::unimplemented(
                    "unnest index field path is unobserved",
                ));
            }
            if path == alias {
                return Err(Status::invalid_argument(format!(
                    "Index field `{name}` cannot be the same name as the alias `{alias_name}`."
                )));
            }
            Some(path)
        }
    };
    let expression = decode_operand_tree(value, unrecorded)?;
    Ok(Stage::Unnest {
        expression,
        alias,
        index_field,
    })
}

fn decode_sample(stage: &pb::pipeline::Stage) -> Result<Stage, Status> {
    use pb::value::ValueType as V;
    if !stage.options.is_empty() {
        return Err(Status::unimplemented("sample options are unobserved"));
    }
    let mode = match stage.args[1].value_type.as_ref() {
        Some(V::StringValue(value)) => value.as_str(),
        _ => return Err(Status::unimplemented("sample mode is unobserved")),
    };
    let sample = match (mode, stage.args[0].value_type.as_ref()) {
        ("documents", Some(V::IntegerValue(n))) if *n >= 0 => {
            pipeline_exec::SampleMode::Documents(u64::try_from(*n).unwrap())
        }
        ("percent", Some(V::IntegerValue(n))) if (0..=1).contains(n) => {
            pipeline_exec::SampleMode::Percent(if *n == 0 { 0.0 } else { 1.0 })
        }
        ("percent", Some(V::DoubleValue(n))) if n.is_finite() && (0.0..=1.0).contains(n) => {
            pipeline_exec::SampleMode::Percent(*n)
        }
        _ => return Err(Status::unimplemented("sample arguments are unobserved")),
    };
    Ok(Stage::Sample(sample))
}

/// The arity text production answered for a stage with a signature, before any other check of
/// the stage (FS-ENT-ORACLE O-6 `sort-wire-errors#no-args`, O-7 `aggregate-args`,
/// `distinct-main`, `fields-main`, `inputs-*`).
fn stage_arity_error(stage: &pb::pipeline::Stage) -> Option<Status> {
    let (signature, min, max) = match stage.name.as_str() {
        "sample" => ("sample(size: int64 | double, mode: SampleMode)", 2, Some(2)),
        "union" => ("union(other: Pipeline)", 1, Some(1)),
        "unnest" => (
            "unnest(field: Expr, alias: FieldReference, index_field: FieldReference?)",
            2,
            Some(2),
        ),
        "sort" => ("sort(ordering: Order*)", 1, None),
        "distinct" => ("distinct(fields: Map[FieldPath, Expr])", 1, Some(1)),
        "aggregate" => (
            "aggregate(accumulators: Map[FieldPath, Expr], groups: Map[FieldPath, Expr])",
            2,
            Some(2),
        ),
        "remove_fields" => ("remove_fields(fields: FieldReference*)", 1, None),
        "collection_group" => (
            "collection_group(ancestor: Path, collection_id: String)",
            2,
            Some(2),
        ),
        "documents" => ("documents(paths: Path*)", 1, None),
        _ => return None,
    };
    let got = stage.args.len();
    if got >= min && max.is_none_or(|max| got <= max) {
        return stage_type_error(stage);
    }
    let range = max.map_or_else(
        || format!("[{min}..+\u{221e})"),
        |max| format!("[{min}..{max}]"),
    );
    Some(Status::invalid_argument(format!(
        "Stage '{signature}' takes {range} argument(s), received {got}."
    )))
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
        count_argument(stage)?;
        return Ok(());
    }
    if !matches!(name, "aggregate" | "add_fields" | "distinct" | "select") {
        return if strict { Err(unvalidated()) } else { Ok(()) };
    }
    // `aggregate`, `add_fields` and `distinct` run: their values are decoded by the stage, not
    // validated here.
    let runs = matches!(name, "aggregate" | "add_fields" | "distinct");
    if strict && !runs && !unrun_values_validated(stage, unrecorded) {
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
            // Production answered a reserved alias of `aggregate`, `distinct` and `add_fields`
            // (FS-ENT-ORACLE O-7); under strict the shape gate answers it only for a recorded
            // request.
            return Err(Status::invalid_argument(text));
        }
    }
    // The checks of the stages that assign top-level fields only, and of an aggregate's names
    // (FS-ENT-ORACLE O-7; under strict the shape gate answers them only for a recorded request).
    if let Some(text) = unrun_stage_name_error(stage) {
        return Err(
            if let Some(field) = text
                .strip_prefix("The nested field reference '")
                .and_then(|rest| rest.split('\'').next())
            {
                crate::production_status::top_level_property_path_only(field, &text)
            } else {
                Status::invalid_argument(text)
            },
        );
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
    wire_keys(fields).unwrap_or_else(|| {
        let mut keys: Vec<&String> = fields.keys().collect();
        keys.sort();
        keys
    })
}

/// A wire map's keys in the order the request wrote them, or `None` when the transport lost it
/// (a decoded gRPC map with two or more entries) or the body holds two maps with the same keys
/// in different orders.
fn wire_keys(fields: &std::collections::HashMap<String, pb::Value>) -> Option<Vec<&String>> {
    let mut keys: Vec<&String> = fields.keys().collect();
    keys.sort();
    if keys.len() < 2 {
        return Some(keys);
    }
    let sorted: Vec<String> = keys.iter().map(|k| (*k).clone()).collect();
    let order = WIRE_KEYS.with(|cell| {
        cell.borrow()
            .as_ref()
            .and_then(|table| table.get(&sorted).cloned().flatten())
    })?;
    Some(
        order
            .iter()
            .filter_map(|k| fields.get_key_value(k).map(|(key, _)| key))
            .collect(),
    )
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

/// The rows of a `documents` input: the named documents that exist, in name order, as the
/// responses of a query over one snapshot (production answered them in name order, not the order
/// of the paths; FS-ENT-ORACLE O-7 `inputs-documents#argument-order`).
pub fn documents_input(
    local: &crate::local::LocalBackend,
    database: &str,
    names: &[String],
    guard: crate::rules::ReadGuard<'_>,
) -> Result<Vec<pb::RunQueryResponse>, Status> {
    documents_input_selected(local, database, names, guard, None)
}

/// Reads document inputs through the existing selected-snapshot transaction machinery.
pub fn documents_input_selected(
    local: &crate::local::LocalBackend,
    database: &str,
    names: &[String],
    guard: crate::rules::ReadGuard<'_>,
    selector: Option<pb::batch_get_documents_request::ConsistencySelector>,
) -> Result<Vec<pb::RunQueryResponse>, Status> {
    let outcome = local.batch_get_documents(
        &pb::BatchGetDocumentsRequest {
            database: database.to_owned(),
            documents: names.to_vec(),
            consistency_selector: selector,
            ..Default::default()
        },
        guard,
    )?;
    let read_time = Some(crate::encode::encode_instant(outcome.read_time));
    let mut responses: Vec<_> = outcome
        .items
        .iter()
        .filter_map(|item| match item {
            crate::local::BatchGetItem::Found(document) => Some(pb::RunQueryResponse {
                document: Some(crate::encode::encode_document(document)),
                read_time,
                ..Default::default()
            }),
            crate::local::BatchGetItem::Missing(_) => None,
        })
        .collect();
    if responses.is_empty() {
        responses.push(pb::RunQueryResponse {
            read_time,
            ..Default::default()
        });
    }
    Ok(responses)
}

/// Reads every live document of the requested database from one latest snapshot.
pub fn database_input(
    local: &crate::local::LocalBackend,
    parent: &Parent,
    guard: crate::rules::ReadGuard<'_>,
) -> Result<Vec<pb::RunQueryResponse>, Status> {
    local.with_snapshot(parent, |db, version, read_time, _| {
        let read_time = Some(crate::encode::encode_instant(read_time));
        let documents: Vec<_> = db
            .documents()
            .into_iter()
            .map(|document| (document.path.clone(), Some(document)))
            .collect();
        guard(
            db,
            Some(version),
            crate::rules::ReadCheck::Documents(&documents),
        )?;
        Ok(documents
            .into_iter()
            .filter_map(|(_, document)| document)
            .map(|document| pb::RunQueryResponse {
                document: Some(crate::encode::encode_document(&document)),
                read_time,
                ..Default::default()
            })
            .collect())
    })?
}

/// The CRC-32 (IEEE, as zlib computes it) of `bytes`.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The documents of a pipeline's input in the order production scans them (FS-ENT-ORACLE O-9
/// `order-main`, O-9b `order-fresh`): a collection is read in ascending CRC-32 of the UTF-8
/// bytes of the document ID (the last path segment), nothing else, so an unsorted answer, a
/// `limit` or `offset` over it, the ties of a `sort` and the first member of a group all follow
/// it; a collection group is read by parent path (the root first), and inside one parent by the
/// same CRC-32. The parent-path order is an assumption generalized from the four parents
/// production showed (root, `cg/a`, `cg/a/items/x`, `cg/b`, `oth/p` in O-9 `cg-main`; the root, `pp/a` and
/// `pp/b` in O-9b): it is plain string order of the parent document's path. CRC-32 ties, which production has not shown, fall back to the name.
#[must_use]
pub fn in_scan_order(mut responses: Vec<pb::RunQueryResponse>) -> Vec<pb::RunQueryResponse> {
    let key = |response: &pb::RunQueryResponse| {
        let name = response
            .document
            .as_ref()
            .map(|document| document.name.as_str())?;
        let (collection, id) = name.rsplit_once('/')?;
        // The parent document of the collection (the root for a top-level collection); every
        // document of one collection has the same one, so it orders a collection group only.
        let collection = collection
            .split_once("/documents")
            .map_or("", |(_, path)| path.trim_start_matches('/'));
        let parent = collection
            .rsplit_once('/')
            .map_or(String::new(), |(document, _)| document.to_owned());
        Some((parent, crc32(id.as_bytes()), name.to_owned()))
    };
    responses.sort_by_cached_key(key);
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
    let time = |time: &Option<prost_types::Timestamp>| {
        time.as_ref().and_then(|t| {
            fireemu_core_firestore::value::Timestamp::new(t.seconds, u32::try_from(t.nanos).ok()?)
                .ok()
        })
    };
    let times = time(&document.create_time)
        .zip(time(&document.update_time))
        .map(|(created, updated)| pipeline_exec::RowTimes { created, updated });
    Ok(pipeline_exec::Row {
        path: Some(path),
        times,
        fields,
    })
}

/// A result row as a response document: its name and times where the stages left them, and its
/// fields. A pipeline without a select answers the source documents, name and times included;
/// after a select only the fields (and the name when the select kept `__name__`).
#[must_use]
pub fn row_document(row: &pipeline_exec::Row) -> pb::Document {
    let time = |time: fireemu_core_firestore::value::Timestamp| prost_types::Timestamp {
        seconds: time.seconds(),
        nanos: i32::try_from(time.nanos()).unwrap_or(0),
    };
    pb::Document {
        name: row
            .path
            .as_ref()
            .map(DocumentPath::resource_name)
            .unwrap_or_default(),
        fields: row
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), crate::encode::encode_value(v)))
            .collect(),
        create_time: row.times.map(|t| time(t.created)),
        update_time: row.times.map(|t| time(t.updated)),
    }
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generated_map_refusal_precedence_cases() {
        use serde_json::json;
        const ROWS: &str = r"Operation	Key	Later	Profile
odd_map	valid	none	strict
odd_map	unknown	none	strict
add_fields_map	double	empty_select	strict
add_fields_map	double	invalid_limit	emulator
add_fields_map	valid	empty_select	strict
add_fields_map	unknown	empty_select	strict
odd_map	unknown	invalid_limit	emulator
odd_map	double	none	emulator
odd_map	valid	empty_select	emulator
add_fields_map	valid	invalid_limit	strict
add_fields_map	unknown	none	strict";
        let database = "projects/p/databases/db";
        let parent = crate::decode::parse_parent(&format!("{database}/documents")).unwrap();
        for line in ROWS.lines().skip(1) {
            let cells: Vec<_> = line.split('\t').collect();
            let [operation, key, later, profile] = cells.as_slice() else {
                panic!("{line}")
            };
            let mode = if *profile == "strict" {
                Unrecorded::Refuse
            } else {
                Unrecorded::OfficialEmulator
            };
            let key_value = match *key {
                "valid" => json!({"stringValue":"k"}),
                "double" => json!({"doubleValue":1.5}),
                "unknown" => json!({"functionValue":{"name":"unknown_function","args":[]}}),
                _ => unreachable!(),
            };
            let args = if *operation == "odd_map" {
                vec![key_value]
            } else {
                vec![key_value, json!({"fieldReferenceValue":"i"})]
            };
            let map = json!({"functionValue":{"name":"map","args":args}});
            let mut stages = vec![json!({"name":"collection","args":[{"referenceValue":"/c"}]})];
            if *operation == "odd_map" {
                stages.push(json!({"name":"select","args":[{"mapValue":{"fields":{"v":map}}}]}));
            } else {
                stages
                    .push(json!({"name":"add_fields","args":[{"mapValue":{"fields":{"a":map}}}]}));
            }
            match *later {
                "empty_select" => stages.push(json!({"name":"select","args":[{"mapValue":{}}]})),
                "invalid_limit" => {
                    stages.push(json!({"name":"limit","args":[{"stringValue":"bad"}]}));
                }
                _ => {}
            }
            let body = json!({"structuredPipeline":{"pipeline":{"stages":stages}}});
            let request = crate::rest::pipeline_json::request_from_json(database, &body).unwrap();
            let result = compile_pipeline_in_order(&request, &parent, mode, None);
            let error = result.unwrap_err();
            if *operation == "odd_map" {
                assert_eq!(
                    error.message(),
                    "'map' function must have an even number of arguments",
                    "{line}"
                );
            } else if *key == "unknown" {
                assert_eq!(error.code(), tonic::Code::Unimplemented, "{line}");
            } else if *later == "invalid_limit" {
                assert!(error.message().contains("limit"), "{line}: {error:?}");
            } else if *key == "double" {
                assert_eq!(
                    error.message(),
                    "map key must be of type STRING, given type is DOUBLE",
                    "{line}"
                );
            } else {
                assert!(error.message().contains("select"), "{line}: {error:?}");
            }
            if mode == Unrecorded::Refuse {
                let gate = crate::pipeline_shape::RefusalGate::Recorded(None, database.to_owned());
                assert_eq!(
                    gate.answer(error).code(),
                    tonic::Code::Unimplemented,
                    "{line}"
                );
            }
        }
    }

    #[test]
    fn recorded_map_add_fields_refusal_precedes_empty_select() {
        let requests = include_str!("../../../conformance/fs-ent-pipeline-requests.json");
        let (requests, order) =
            crate::rest::json_syntax::parse_with_key_order(requests.as_bytes()).unwrap();
        let programs = requests["programs"].as_array().unwrap();
        let (p, program) = programs
            .iter()
            .enumerate()
            .find(|(_, p)| p["id"] == "fs-ent-pipeline/o5/appendix")
            .unwrap();
        let (n, step) = program["steps"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .find(|(_, s)| s["id"] == "proposed-n76-map-add-then-empty")
            .unwrap();
        let database = "projects/demo-fs-query-index/databases/entpipe1";
        let parent = crate::decode::parse_parent(&format!("{database}/documents")).unwrap();
        let request =
            crate::rest::pipeline_json::request_from_json(database, &step["body"]).unwrap();
        let body_order = order.rebased(&format!("/programs/{p}/steps/{n}/body"), "");
        let error =
            compile_pipeline_in_order(&request, &parent, Unrecorded::Refuse, Some(&body_order))
                .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            error.message(),
            "map key must be of type STRING, given type is DOUBLE"
        );
    }

    #[test]
    fn recorded_map_constructor_refusals() {
        use crate::pipeline_shape::{shape_of_json, shape_of_request, RefusalGate};
        use fireemu_core_firestore::value::Value;
        let odd = Expr::call(
            "map",
            vec![Expr::Constant(Value::String("k".to_owned()))],
            Placement::Value,
        )
        .unwrap_err();
        assert_eq!(
            odd,
            ExprError::Arity("'map' function must have an even number of arguments".to_owned())
        );
        let requests = include_str!("../../../conformance/fs-ent-pipeline-requests.json");
        let (requests, order) =
            crate::rest::json_syntax::parse_with_key_order(requests.as_bytes()).unwrap();
        let production: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/fs-ent-pipeline-production.json"
        ))
        .unwrap();
        let database = "projects/demo-fs-query-index/databases/entpipe1";
        let parent = crate::decode::parse_parent(&format!("{database}/documents")).unwrap();
        let programs = requests["programs"].as_array().unwrap();
        for (program, id) in [
            ("value-shapes", "map-one-argument"),
            ("appendix", "proposed-n76-map-add-then-empty"),
        ] {
            let full = format!("fs-ent-pipeline/o5/{program}");
            let (p, entry) = programs
                .iter()
                .enumerate()
                .find(|(_, p)| p["id"] == full)
                .unwrap();
            let (n, step) = entry["steps"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .find(|(_, s)| s["id"] == id)
                .unwrap();
            let body = &step["body"];
            let body_order = order.rebased(&format!("/programs/{p}/steps/{n}/body"), "");
            let request = crate::rest::pipeline_json::request_from_json(database, body).unwrap();
            let expected = production["programs"][&full]["steps"][id]["body"][0]["error"]
                ["message"]
                .as_str()
                .unwrap();
            let computed =
                compile_pipeline_in_order(&request, &parent, Unrecorded::Refuse, Some(&body_order))
                    .unwrap_err();
            assert_eq!(
                computed.code(),
                tonic::Code::InvalidArgument,
                "{id}: {computed:?}"
            );
            assert_eq!(computed.message(), expected, "{id}");
            let rest = RefusalGate::Recorded(shape_of_json(body, &body_order), database.to_owned())
                .answer(computed.clone());
            assert_eq!(rest.code(), tonic::Code::InvalidArgument, "REST {id}");
            assert_eq!(rest.message(), expected, "REST {id}");
            let grpc_shape = shape_of_request(&request);
            assert!(grpc_shape.is_some(), "gRPC shape {id}");
            let grpc = RefusalGate::Recorded(grpc_shape, database.to_owned()).answer(computed);
            assert_eq!(grpc.code(), tonic::Code::InvalidArgument, "gRPC {id}");
            assert_eq!(grpc.message(), expected, "gRPC {id}");
        }
    }

    #[test]
    fn recorded_registered_function_arities_match_both_transports() {
        use crate::pipeline_shape::{shape_of_json, shape_of_request, RefusalGate};
        let requests = include_str!("../../../conformance/fs-ent-pipeline-requests.json");
        let (requests, order) =
            crate::rest::json_syntax::parse_with_key_order(requests.as_bytes()).unwrap();
        let production: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/fs-ent-pipeline-production.json"
        ))
        .unwrap();
        let database = "projects/demo-fs-query-index/databases/entpipe1";
        let parent = crate::decode::parse_parent(&format!("{database}/documents")).unwrap();
        let programs = requests["programs"].as_array().unwrap();
        let full = "fs-ent-pipeline/o5/function-names";
        let (p, program) = programs
            .iter()
            .enumerate()
            .find(|(_, program)| program["id"] == full)
            .unwrap();
        let names = [
            "get_field",
            "offset",
            "sum",
            "minimum",
            "maximum",
            "negate",
            "cmp",
            "reverse",
            "length",
            "storage_size",
            "coalesce",
            "namespace",
            "has_ancestor",
            "reference_slice",
            "autogen_document_id",
            "replace_document_id",
            "string_concat",
        ];
        let mut failures = Vec::new();
        for name in names {
            let id = format!("fn-{name}");
            let (n, step) = program["steps"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .find(|(_, step)| step["id"] == id)
                .unwrap();
            let body = &step["body"];
            let order = order.rebased(&format!("/programs/{p}/steps/{n}/body"), "");
            let request = crate::rest::pipeline_json::request_from_json(database, body).unwrap();
            let expected = production["programs"][full]["steps"][&id]["body"][0]["error"]
                ["message"]
                .as_str()
                .unwrap();
            let actual =
                compile_pipeline_in_order(&request, &parent, Unrecorded::Refuse, Some(&order))
                    .unwrap_err();
            for (transport, shape) in [
                ("rest", shape_of_json(body, &order)),
                ("grpc", shape_of_request(&request)),
            ] {
                let answered =
                    RefusalGate::Recorded(shape, database.to_owned()).answer(actual.clone());
                if answered.code() != tonic::Code::InvalidArgument || answered.message() != expected
                {
                    failures.push(format!("{id} {transport}: {answered:?}"));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn recorded_literal_refusal_gate_matrix() {
        use crate::pipeline_shape::{shape_of_json, shape_of_request, RefusalGate};
        use tonic::Code;
        let database = "projects/demo-fs-query-index/databases/entpipe1";
        let docs = format!("{database}/documents");
        let requests = include_str!("../../../conformance/fs-ent-pipeline-requests.json")
            .replace("{docs}", &docs);
        let (requests, order) =
            crate::rest::json_syntax::parse_with_key_order(requests.as_bytes()).unwrap();
        let production: serde_json::Value = serde_json::from_str(include_str!(
            "../../../conformance/fs-ent-pipeline-production.json"
        ))
        .unwrap();
        let parent = crate::decode::parse_parent(&docs).unwrap();
        let targets = [
            ("stage-order", "where-vector-of-integer", true),
            ("value-shapes", "vector-of-integer", true),
            ("value-shapes", "vector-of-double-and-integer", true),
            ("value-shapes", "vector-without-value", false),
            ("value-shapes", "vector-with-extra-key", true),
            ("value-shapes", "vector-value-not-array", true),
            ("appendix", "proposed-type-tag-integer", false),
            ("appendix", "proposed-type-tag-boolean", false),
            ("appendix", "proposed-type-tag-null", false),
            ("appendix", "proposed-type-tag-double", false),
            ("appendix", "proposed-type-tag-map", false),
            ("appendix", "proposed-type-tag-array", false),
            ("appendix", "proposed-type-tag-nested", false),
            ("appendix", "proposed-type-tag-where", false),
            ("appendix", "proposed-type-tag-function-argument", false),
            ("appendix", "proposed-reference-collection", false),
            ("appendix", "proposed-reference-empty-segment", false),
            ("appendix", "proposed-reference-garbage", false),
        ];
        let programs = requests["programs"].as_array().unwrap();
        for (program, id, unordered) in targets {
            let full = format!("fs-ent-pipeline/o5/{program}");
            let (p, entry) = programs
                .iter()
                .enumerate()
                .find(|(_, p)| p["id"] == full)
                .unwrap();
            let (n, step) = entry["steps"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .find(|(_, s)| s["id"] == id)
                .unwrap();
            let body = &step["body"];
            let body_order = order.rebased(&format!("/programs/{p}/steps/{n}/body"), "");
            let request = crate::rest::pipeline_json::request_from_json(database, body).unwrap();
            let expected = production["programs"][&full]["steps"][id]["body"][0]["error"]
                ["message"]
                .as_str()
                .unwrap();
            let computed =
                compile_pipeline_in_order(&request, &parent, Unrecorded::Refuse, Some(&body_order))
                    .unwrap_err();
            assert_eq!(
                computed.code(),
                Code::InvalidArgument,
                "{full}#{id}: {computed:?}"
            );
            if id == "proposed-reference-collection" || id == "proposed-reference-empty-segment" {
                let suffix = if id == "proposed-reference-collection" {
                    "/c"
                } else {
                    "/c/"
                };
                let index = format!("{docs}{suffix}").encode_utf16().count();
                assert!(
                    computed.message().contains(&format!(" at index {index}.")),
                    "{full}#{id}: {computed:?}"
                );
                assert_eq!(
                    crate::pipeline_shape::normalized_text(computed.message()),
                    crate::pipeline_shape::normalized_text(expected),
                    "{full}#{id}"
                );
            } else {
                assert_eq!(computed.message(), expected, "{full}#{id}");
            }
            let computed_message = computed.message().to_owned();
            let rest = RefusalGate::Recorded(shape_of_json(body, &body_order), database.to_owned())
                .answer(computed.clone());
            assert_eq!(
                rest.code(),
                Code::InvalidArgument,
                "REST {full}#{id}: {rest:?}"
            );
            assert_eq!(rest.message(), computed_message, "REST {full}#{id}");
            let grpc_shape = shape_of_request(&request);
            if unordered {
                assert!(grpc_shape.is_none(), "gRPC shape {full}#{id}");
            }
            let grpc = RefusalGate::Recorded(grpc_shape, database.to_owned()).answer(computed);
            println!(
                "literal-matrix {full}#{id} rest={:?} grpc={:?} unordered={unordered}",
                rest.code(),
                grpc.code()
            );
            if unordered {
                assert_eq!(grpc.code(), Code::Unimplemented, "gRPC {full}#{id}");
            } else {
                assert_eq!(grpc.code(), Code::InvalidArgument, "gRPC {full}#{id}");
                assert_eq!(grpc.message(), computed_message, "gRPC {full}#{id}");
            }
        }
    }
    use super::*;

    #[test]
    fn literal_refusal_preserves_precedence_gate_and_utf16_index() {
        use pb::value::ValueType as V;
        let val = |kind| pb::Value {
            value_type: Some(kind),
        };
        let invalid = tagged_literal(
            val(V::StringValue("__vector__".to_owned())),
            vec![val(V::IntegerValue(1))],
            false,
        );
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            for name in ["equal", "unknown_function"] {
                let call = val(V::FunctionValue(pb::Function {
                    name: name.to_owned(),
                    args: vec![invalid.clone()],
                    ..Default::default()
                }));
                let error = decode_operand_tree(&call, mode).unwrap_err();
                if name == "equal" {
                    assert!(error.message().contains("argument(s)"), "{error:?}");
                } else {
                    assert_eq!(error.code(), tonic::Code::Unimplemented);
                }
            }
        }
        let gate = crate::pipeline_shape::RefusalGate::Recorded(
            None,
            "projects/p/databases/db".to_owned(),
        );
        assert_eq!(
            gate.answer(Status::invalid_argument(
                "Vector must only contain values of type 'double'"
            ))
            .code(),
            tonic::Code::Unimplemented
        );
        let foreign = val(V::ReferenceValue(
            "projects/q/databases/db/documents/c/d".to_owned(),
        ));
        assert_eq!(
            reference_outside(&foreign, "projects/p/databases/db/documents")
                .unwrap()
                .code(),
            tonic::Code::Unimplemented
        );
        let name = "projects/😀/databases/☃/documents/c";
        let error = reference_literal_error(name).unwrap();
        assert!(
            error.contains(&format!("at index {}.", name.encode_utf16().count())),
            "{error}"
        );
        let unicode_path = "projects/p/databases/db/documents/😀";
        let error = reference_literal_error(unicode_path).unwrap();
        assert!(
            error.contains(&format!(
                "at index {}.",
                unicode_path.encode_utf16().count()
            )),
            "{error}"
        );
        let prefix = "projects/😀/databases/☃/";
        let missing_keyword = format!("{prefix}documentX");
        let error = reference_literal_error(&missing_keyword).unwrap();
        assert!(
            error.contains(&format!("at index {}.", prefix.encode_utf16().count())),
            "{error}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generated_literal_refusal_boundary_cases() {
        use pb::value::ValueType as V;
        const ROWS: &str = r"Family	Transport	Profile	Position	Conflict
vector	rest	strict	direct	none
vector	grpc	strict	where	none
type_tag	rest	strict	nested	none
type_tag	grpc	strict	function	none
reference	rest	strict	direct	none
reference	grpc	strict	direct	foreign
vector	rest	emulator	function	arity
type_tag	grpc	strict	function	unknown
vector	grpc	emulator	nested	foreign
reference	grpc	strict	nested	arity
type_tag	rest	emulator	direct	unknown
reference	rest	emulator	where	foreign
type_tag	grpc	strict	direct	arity
reference	rest	strict	where	unknown
vector	rest	strict	nested	unknown
type_tag	grpc	strict	where	foreign
type_tag	rest	emulator	where	arity
reference	rest	emulator	function	none
vector	grpc	emulator	function	foreign";
        let value = |kind| pb::Value {
            value_type: Some(kind),
        };
        for line in ROWS.lines().skip(1) {
            let cells: Vec<_> = line.split('\t').collect();
            let [family, transport, profile, position, conflict] = cells.as_slice() else {
                panic!("{line}")
            };
            let policy = if *profile == "strict" {
                Unrecorded::Refuse
            } else {
                Unrecorded::OfficialEmulator
            };
            let literal = match *family {
                "vector" => tagged_literal(
                    value(V::StringValue("__vector__".to_owned())),
                    vec![value(V::IntegerValue(1))],
                    false,
                ),
                "type_tag" => tagged_literal(
                    value(V::IntegerValue(7)),
                    vec![value(V::DoubleValue(1.0))],
                    false,
                ),
                "reference" => value(V::ReferenceValue("garbage".to_owned())),
                _ => unreachable!(),
            };
            let mut operand = match *position {
                "nested" => value(V::ArrayValue(pb::ArrayValue {
                    values: vec![literal],
                })),
                "function" => value(V::FunctionValue(pb::Function {
                    name: "equal".to_owned(),
                    args: vec![value(V::FieldReferenceValue("i".to_owned())), literal],
                    ..Default::default()
                })),
                _ => literal,
            };
            if *conflict == "arity" || *conflict == "unknown" {
                let name = if *conflict == "arity" {
                    "equal"
                } else {
                    "unknown_function"
                };
                operand = value(V::FunctionValue(pb::Function {
                    name: name.to_owned(),
                    args: vec![operand],
                    ..Default::default()
                }));
            }
            if *conflict == "foreign" {
                let foreign = value(V::ReferenceValue(
                    "projects/q/databases/db/documents/c/d".to_owned(),
                ));
                assert_eq!(
                    reference_outside(&foreign, "projects/p/databases/db/documents")
                        .unwrap()
                        .code(),
                    tonic::Code::Unimplemented,
                    "{line}"
                );
            }
            let error = if *position == "where" {
                decode_condition(
                    &pb::pipeline::Stage {
                        name: "where".to_owned(),
                        args: vec![operand],
                        ..Default::default()
                    },
                    policy,
                )
                .unwrap_err()
            } else {
                decode_operand_tree(&operand, policy).unwrap_err()
            };
            if *conflict == "unknown" {
                assert_eq!(error.code(), tonic::Code::Unimplemented, "{line}");
            }
            if *conflict == "arity" {
                assert!(error.message().contains("argument(s)"), "{line}: {error:?}");
            }
            let gate = if *profile == "strict" {
                crate::pipeline_shape::RefusalGate::Recorded(
                    None,
                    "projects/p/databases/db".to_owned(),
                )
            } else {
                crate::pipeline_shape::RefusalGate::Open
            };
            let gated = gate.answer(error.clone());
            if *profile == "strict" {
                assert_eq!(
                    gated.code(),
                    tonic::Code::Unimplemented,
                    "{transport}: {line}"
                );
            } else {
                assert_eq!(gated.code(), error.code(), "{transport}: {line}");
            }
        }
    }

    fn tagged_literal(tag: pb::Value, values: Vec<pb::Value>, in_array: bool) -> pb::Value {
        use pb::value::ValueType as V;
        let map = pb::Value {
            value_type: Some(V::MapValue(pb::MapValue {
                fields: [
                    ("__type__".to_owned(), tag),
                    (
                        "value".to_owned(),
                        pb::Value {
                            value_type: Some(V::ArrayValue(pb::ArrayValue { values })),
                        },
                    ),
                ]
                .into_iter()
                .collect(),
            })),
        };
        if in_array {
            pb::Value {
                value_type: Some(V::ArrayValue(pb::ArrayValue { values: vec![map] })),
            }
        } else {
            map
        }
    }

    #[test]
    fn recorded_tagged_literals_preserve_wire_shapes() {
        use pb::value::ValueType as V;
        let cases = [
            ("unknown", "double", "strict", "map", "valid"),
            ("unknown", "integer", "strict", "map", "valid"),
            ("vector", "double", "strict", "array", "valid"),
            ("vector", "integer", "strict", "array", "invalid"),
            ("unknown", "double", "emulator", "map", "valid"),
            ("unknown", "integer", "emulator", "array", "invalid"),
            ("vector", "double", "emulator", "map", "invalid"),
        ];
        for (kind, number, profile, context, validity) in cases {
            let tag = if kind == "unknown" && validity == "invalid" {
                V::IntegerValue(7)
            } else {
                V::StringValue(if kind == "vector" { "__vector__" } else { "x" }.to_owned())
            };
            let number = if number == "integer" {
                V::IntegerValue(1)
            } else {
                V::DoubleValue(1.0)
            };
            let values =
                if kind == "vector" && validity == "invalid" && matches!(number, V::DoubleValue(_))
                {
                    vec![]
                } else {
                    vec![pb::Value {
                        value_type: Some(number),
                    }]
                };
            let wire = tagged_literal(
                pb::Value {
                    value_type: Some(tag),
                },
                values,
                context == "array",
            );
            let profile = if profile == "strict" {
                Unrecorded::Refuse
            } else {
                Unrecorded::OfficialEmulator
            };
            let result = decode_operand_tree(&wire, profile);
            if validity == "valid" {
                let Expr::Constant(value) = result.unwrap() else {
                    panic!("expected constant")
                };
                assert_eq!(crate::encode::encode_value(&value), wire);
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn recorded_infinite_vectors_and_documents_root_preserve_types() {
        use fireemu_core_firestore::value::Value;
        use pb::value::ValueType as V;
        for number in [f64::INFINITY, f64::NEG_INFINITY] {
            let wire = tagged_literal(
                pb::Value {
                    value_type: Some(V::StringValue("__vector__".to_owned())),
                },
                vec![pb::Value {
                    value_type: Some(V::DoubleValue(number)),
                }],
                false,
            );
            let Expr::Constant(Value::Vector(vector)) =
                decode_operand_tree(&wire, Unrecorded::Refuse).unwrap()
            else {
                panic!("expected vector")
            };
            assert_eq!(vector, vec![number]);
            assert_eq!(crate::encode::encode_value(&Value::Vector(vector)), wire);
        }
        let own = "projects/p/databases/db/documents";
        let root = pb::Value {
            value_type: Some(V::ReferenceValue(own.to_owned())),
        };
        assert!(reference_outside(&root, own).is_none());
        let Expr::Constant(Value::Reference(reference)) =
            decode_operand_tree(&root, Unrecorded::Refuse).unwrap()
        else {
            panic!("expected reference")
        };
        assert_eq!(reference, own);
        let foreign = pb::Value {
            value_type: Some(V::ReferenceValue(
                "projects/p/databases/other/documents".to_owned(),
            )),
        };
        assert!(reference_outside(&foreign, own).is_some());
    }

    #[test]
    fn generated_infinity_reference_projection_cases() {
        use fireemu_core_firestore::value::Value;
        use pb::value::ValueType as V;
        let own = "projects/p/databases/db/documents";
        for profile in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            for (number, allowed) in [
                (f64::INFINITY, true),
                (f64::NEG_INFINITY, true),
                (1.0, true),
                (f64::NAN, false),
            ] {
                let wire = tagged_literal(
                    pb::Value {
                        value_type: Some(V::StringValue("__vector__".to_owned())),
                    },
                    vec![pb::Value {
                        value_type: Some(V::DoubleValue(number)),
                    }],
                    false,
                );
                let result = decode_operand_tree(&wire, profile);
                if allowed {
                    let Expr::Constant(Value::Vector(vector)) = result.unwrap() else {
                        panic!("expected vector")
                    };
                    assert_eq!(vector, vec![number]);
                } else {
                    assert!(result.is_err());
                }
            }
            let too_long = tagged_literal(
                pb::Value {
                    value_type: Some(V::StringValue("__vector__".to_owned())),
                },
                vec![
                    pb::Value {
                        value_type: Some(V::DoubleValue(1.0))
                    };
                    2049
                ],
                false,
            );
            assert!(decode_operand_tree(&too_long, profile).is_err());
            for (name, own_database) in
                [(own, true), ("projects/p/databases/other/documents", false)]
            {
                let wire = pb::Value {
                    value_type: Some(V::ReferenceValue(name.to_owned())),
                };
                if profile == Unrecorded::Refuse && !own_database {
                    assert!(reference_outside(&wire, own).is_some());
                } else {
                    assert!(decode_operand_tree(&wire, profile).is_ok());
                }
            }
        }
    }

    #[test]
    fn infinity_vector_admission_depends_on_expression_position() {
        use pb::value::ValueType as V;
        let val = |kind| pb::Value {
            value_type: Some(kind),
        };
        for profile in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            for (kind, number) in [
                ("positive", f64::INFINITY),
                ("negative", f64::NEG_INFINITY),
                ("finite", 1.0),
                ("unknown", 1.0),
            ] {
                let tag = if kind == "unknown" { "x" } else { "__vector__" };
                let literal = tagged_literal(
                    val(V::StringValue(tag.to_owned())),
                    vec![val(V::DoubleValue(number))],
                    false,
                );
                for position in ["direct", "constructor", "equal", "literal_nested"] {
                    let operand = match position {
                        "direct" => literal.clone(),
                        "literal_nested" => val(V::ArrayValue(pb::ArrayValue {
                            values: vec![literal.clone()],
                        })),
                        name => {
                            let (name, args) = if name == "constructor" {
                                ("array", vec![literal.clone()])
                            } else {
                                (
                                    "equal",
                                    vec![
                                        val(V::FieldReferenceValue("i".to_owned())),
                                        literal.clone(),
                                    ],
                                )
                            };
                            val(V::FunctionValue(pb::Function {
                                name: name.to_owned(),
                                args,
                                ..Default::default()
                            }))
                        }
                    };
                    let result = decode_operand_tree(&operand, profile);
                    let refused = profile == Unrecorded::Refuse
                        && number.is_infinite()
                        && position != "direct";
                    if refused {
                        assert_eq!(
                            result.unwrap_err().code(),
                            tonic::Code::Unimplemented,
                            "{kind} {position} {profile:?}"
                        );
                    } else {
                        assert!(result.is_ok(), "{kind} {position} {profile:?}: {result:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn vector_in_array_keeps_unobserved_components_refused() {
        use pb::value::ValueType as V;
        for number in [f64::INFINITY, -0.0] {
            let wire = tagged_literal(
                pb::Value {
                    value_type: Some(V::StringValue("__vector__".to_owned())),
                },
                vec![pb::Value {
                    value_type: Some(V::DoubleValue(number)),
                }],
                true,
            );
            assert!(decode_operand_tree(&wire, Unrecorded::Refuse).is_err());
        }
    }

    #[test]
    fn generated_comparison_arity_and_precedence_cases() {
        use pb::value::ValueType as V;
        let cases = [
            ("equal", "where", 0, "valid", "strict"),
            ("equal", "where", 1, "unknown", "strict"),
            ("equal", "select", 1, "valid", "strict"),
            ("less_than", "select", 0, "valid", "strict"),
            ("equal", "where", 2, "valid", "emulator"),
            ("equal", "select", 3, "unknown", "emulator"),
            ("less_than", "where", 0, "unknown", "emulator"),
            ("less_than", "select", 2, "unknown", "strict"),
            ("less_than", "where", 3, "valid", "strict"),
            ("less_than", "select", 1, "unknown", "emulator"),
        ];
        for (name, position, count, operand, profile) in cases {
            let valid = || pb::Value {
                value_type: Some(V::IntegerValue(1)),
            };
            let mut args = vec![valid(); count];
            if let Some(first) = args.first_mut() {
                *first = if operand == "unknown" {
                    pb::Value {
                        value_type: Some(V::FunctionValue(pb::Function {
                            name: "not_a_registered_function".to_owned(),
                            ..Default::default()
                        })),
                    }
                } else {
                    pb::Value {
                        value_type: Some(V::FieldReferenceValue("i".to_owned())),
                    }
                };
            }
            let wire = pb::Value {
                value_type: Some(V::FunctionValue(pb::Function {
                    name: name.to_owned(),
                    args,
                    ..Default::default()
                })),
            };
            let mode = if profile == "strict" {
                Unrecorded::Refuse
            } else {
                Unrecorded::OfficialEmulator
            };
            let result = if position == "where" {
                decode_condition(
                    &pb::pipeline::Stage {
                        name: "where".to_owned(),
                        args: vec![wire],
                        ..Default::default()
                    },
                    mode,
                )
                .map(|_| ())
            } else {
                decode_operand_tree(&wire, mode).map(|_| ())
            };
            if count != 2 {
                let error = result.unwrap_err();
                assert_eq!(
                    error.code(),
                    tonic::Code::InvalidArgument,
                    "{name} {position} {count} {profile}"
                );
                assert_eq!(error.message(), format!("The function '{name}(x: any, y: any): boolean' takes [2..2] argument(s), but {count} {} provided.", if count == 1 { "was" } else { "were" }));
            } else if operand == "unknown" {
                assert_eq!(result.unwrap_err().code(), tonic::Code::Unimplemented);
            } else {
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn array_transform_element_alias_validation_and_priority() {
        use pb::value::ValueType as V;
        let cases = [
            ("exact", "field", "field", Unrecorded::Refuse),
            ("exact", "field", "empty", Unrecorded::Refuse),
            ("short", "field", "field", Unrecorded::Refuse),
            ("exact", "string", "empty", Unrecorded::Refuse),
            ("exact", "integer", "field", Unrecorded::Refuse),
            ("exact", "variable", "field", Unrecorded::Refuse),
            ("exact", "field", "field", Unrecorded::OfficialEmulator),
            ("short", "variable", "empty", Unrecorded::OfficialEmulator),
            ("short", "integer", "empty", Unrecorded::OfficialEmulator),
            ("short", "string", "field", Unrecorded::OfficialEmulator),
        ];
        let field = || pb::Value {
            value_type: Some(V::FieldReferenceValue("i".to_owned())),
        };
        for (arity, alias, input, profile) in cases {
            let input = if input == "empty" {
                pb::Value {
                    value_type: Some(V::ArrayValue(pb::ArrayValue { values: vec![] })),
                }
            } else {
                field()
            };
            let alias = pb::Value {
                value_type: Some(match alias {
                    "field" => V::FieldReferenceValue("i".to_owned()),
                    "string" => V::StringValue("item".to_owned()),
                    "integer" => V::IntegerValue(1),
                    _ => V::VariableReferenceValue("item".to_owned()),
                }),
            };
            let mut args = vec![input, alias];
            if arity == "exact" {
                args.extend([
                    pb::Value {
                        value_type: Some(V::StringValue("index".to_owned())),
                    },
                    field(),
                ]);
            }
            let operand = pb::Value {
                value_type: Some(V::FunctionValue(pb::Function {
                    name: "array_transform".to_owned(),
                    args,
                    ..Default::default()
                })),
            };
            let result = decode_operand_tree(&operand, profile);
            if arity == "short" {
                assert!(!result.unwrap_err().message().contains("element_alias"));
            } else if matches!(operand.value_type.as_ref(), Some(V::FunctionValue(f)) if matches!(f.args[1].value_type, Some(V::FieldReferenceValue(_))))
            {
                let error = result.unwrap_err();
                assert_eq!(error.code(), tonic::Code::InvalidArgument);
                assert_eq!(error.message(), "The 'element_alias' argument of the 'array_transform' function must be a literal value, found: a property reference");
                let gate = crate::pipeline_shape::RefusalGate::Recorded(None, String::new());
                assert_eq!(gate.answer(error).code(), tonic::Code::Unimplemented);
            } else if matches!(operand.value_type.as_ref(), Some(V::FunctionValue(f)) if matches!(f.args[1].value_type, Some(V::StringValue(_))))
            {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.unwrap_err().code(), tonic::Code::Unimplemented);
            }
        }
    }

    #[test]
    fn array_transform_unobserved_index_alias_remains_refused() {
        use pb::value::ValueType as V;
        let value = |kind| pb::Value {
            value_type: Some(kind),
        };
        let call = value(V::FunctionValue(pb::Function {
            name: "array_transform".to_owned(),
            args: vec![
                value(V::ArrayValue(pb::ArrayValue { values: vec![] })),
                value(V::StringValue("item".to_owned())),
                value(V::FieldReferenceValue("i".to_owned())),
                value(V::FieldReferenceValue("i".to_owned())),
            ],
            ..Default::default()
        }));
        for profile in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            assert_eq!(
                decode_operand_tree(&call, profile).unwrap_err().code(),
                tonic::Code::Unimplemented
            );
        }
    }

    #[test]
    fn where_is_type_keeps_static_type_validation() {
        use pb::value::ValueType as V;
        let field = || pb::Value {
            value_type: Some(V::FieldReferenceValue("i".to_owned())),
        };
        let bogus = || pb::Value {
            value_type: Some(V::StringValue("bogus".to_owned())),
        };
        let variable = || pb::Value {
            value_type: Some(V::VariableReferenceValue("v".to_owned())),
        };
        let unknown = || pb::Value {
            value_type: Some(V::FunctionValue(pb::Function {
                name: "not_a_registered_function".to_owned(),
                ..Default::default()
            })),
        };
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            for (args, code, text) in [
                (
                    vec![field(), bogus()],
                    tonic::Code::InvalidArgument,
                    "argument 'type'",
                ),
                (
                    vec![field(), variable()],
                    tonic::Code::Unimplemented,
                    "variable and pipeline",
                ),
                (
                    vec![unknown(), bogus()],
                    tonic::Code::Unimplemented,
                    "not_a_registered_function",
                ),
            ] {
                let condition = pb::Value {
                    value_type: Some(V::FunctionValue(pb::Function {
                        name: "is_type".to_owned(),
                        args,
                        ..Default::default()
                    })),
                };
                let stage = pb::pipeline::Stage {
                    name: "where".to_owned(),
                    args: vec![condition],
                    ..Default::default()
                };
                let error = decode_condition(&stage, mode).unwrap_err();
                assert_eq!(error.code(), code);
                assert!(error.message().contains(text), "{error}");
            }
        }
    }

    #[test]
    fn valid_where_equal_retains_field_filter_pushdown() {
        use pb::value::ValueType as V;
        let condition = pb::Value {
            value_type: Some(V::FunctionValue(pb::Function {
                name: "equal".to_owned(),
                args: vec![
                    pb::Value {
                        value_type: Some(V::FieldReferenceValue("i".to_owned())),
                    },
                    pb::Value {
                        value_type: Some(V::IntegerValue(1)),
                    },
                ],
                ..Default::default()
            })),
        };
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            let stage = pb::pipeline::Stage {
                name: "where".to_owned(),
                args: vec![condition.clone()],
                ..Default::default()
            };
            assert!(decode_condition(&stage, mode).unwrap().1.is_some());
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn captured_array_and_like_expressions_preserve_typed_results() {
        use fireemu_core_firestore::pipeline_exec::{Eval, Row, RuntimeContext};
        use fireemu_core_firestore::value::Value;
        use pb::value::ValueType as V;
        let val = |kind| pb::Value {
            value_type: Some(kind),
        };
        let field = |name: &str| val(V::FieldReferenceValue(name.to_owned()));
        let variable = |name: &str| val(V::VariableReferenceValue(name.to_owned()));
        let string = |text: &str| val(V::StringValue(text.to_owned()));
        let integer = |number| val(V::IntegerValue(number));
        let call = |name: &str, args| {
            val(V::FunctionValue(pb::Function {
                name: name.to_owned(),
                args,
                ..Default::default()
            }))
        };
        let row = Row::derived(
            [
                (
                    "itemsPop".to_owned(),
                    Value::Array(vec![Value::Integer(0), Value::Integer(2)]),
                ),
                ("itemsEmpty".to_owned(), Value::Array(vec![])),
                (
                    "textPositive".to_owned(),
                    Value::String("apricot".to_owned()),
                ),
                ("textNegative".to_owned(), Value::String("berry".to_owned())),
            ]
            .into_iter()
            .collect(),
        );
        let cases = [
            (
                call(
                    "array_filter",
                    vec![
                        field("itemsPop"),
                        string("item"),
                        call("greater_than", vec![variable("item"), integer(1)]),
                    ],
                ),
                Value::Array(vec![Value::Integer(2)]),
            ),
            (
                call(
                    "array_filter",
                    vec![
                        field("itemsEmpty"),
                        string("item"),
                        call("greater_than", vec![variable("item"), integer(1)]),
                    ],
                ),
                Value::Array(vec![]),
            ),
            (
                call(
                    "array_transform",
                    vec![
                        field("itemsPop"),
                        string("item"),
                        call("multiply", vec![variable("item"), integer(2)]),
                    ],
                ),
                Value::Array(vec![Value::Integer(0), Value::Integer(4)]),
            ),
            (
                call(
                    "array_transform",
                    vec![
                        field("itemsEmpty"),
                        string("item"),
                        call("multiply", vec![variable("item"), integer(2)]),
                    ],
                ),
                Value::Array(vec![]),
            ),
            (
                call("like", vec![field("textPositive"), string("%ap%")]),
                Value::Boolean(true),
            ),
            (
                call("like", vec![field("textNegative"), string("%ap%")]),
                Value::Boolean(false),
            ),
        ];
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            for (wire, expected) in &cases {
                let expression = decode_operand_tree(wire, mode).unwrap();
                let runtime = RuntimeContext {
                    regex_resolver: Some(crate::pipeline_regex::resolve),
                    ..RuntimeContext::default()
                };
                assert_eq!(
                    expression.eval_in_with_runtime(&row, mode, runtime),
                    Eval::Value(expected.clone())
                );
            }
            assert!(decode_operand_tree(&call("rand", vec![]), mode).is_ok());
        }
    }

    #[test]
    fn captured_numeric_scalar_expressions_preserve_integer_results() {
        use fireemu_core_firestore::pipeline_exec::{Eval, Row, RuntimeContext};
        use fireemu_core_firestore::value::Value;
        use pb::value::ValueType as V;
        let value = |kind| pb::Value {
            value_type: Some(kind),
        };
        let integer = |number| value(V::IntegerValue(number));
        let array = || {
            value(V::ArrayValue(pb::ArrayValue {
                values: vec![integer(7), integer(2), integer(5)],
            }))
        };
        let call = |name: &str, args| {
            value(V::FunctionValue(pb::Function {
                name: name.to_owned(),
                args,
                ..Default::default()
            }))
        };
        let cases = [
            (call("minimum", vec![array()]), 2),
            (call("minimum", vec![integer(7), integer(2)]), 2),
            (call("maximum", vec![array()]), 7),
            (call("maximum", vec![integer(7), integer(2)]), 7),
            (call("sum", vec![array()]), 14),
            (call("negate", vec![integer(7)]), -7),
        ];
        let row = Row::derived(std::collections::BTreeMap::default());
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            for (wire, expected) in &cases {
                let expression = decode_operand_tree(wire, mode).unwrap();
                assert_eq!(
                    expression.eval_in_with_runtime(&row, mode, RuntimeContext::default()),
                    Eval::Value(Value::Integer(*expected))
                );
            }
        }
    }

    #[test]
    fn numeric_scalar_unobserved_arity_keeps_profile_boundary() {
        use pb::value::ValueType as V;
        for name in ["minimum", "maximum", "sum", "negate"] {
            let wire = pb::Value {
                value_type: Some(V::FunctionValue(pb::Function {
                    name: name.to_owned(),
                    args: vec![],
                    ..Default::default()
                })),
            };
            for (mode, code) in [
                (Unrecorded::Refuse, tonic::Code::Unimplemented),
                (Unrecorded::OfficialEmulator, tonic::Code::InvalidArgument),
            ] {
                assert_eq!(
                    decode_operand_tree(&wire, mode).unwrap_err().code(),
                    code,
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn captured_generic_expressions_preserve_typed_results() {
        use fireemu_core_firestore::pipeline_exec::{Eval, Row, RuntimeContext};
        use fireemu_core_firestore::value::Value;
        use serde_json::json;
        let cases: serde_json::Value = serde_json::from_str(r#"[{"id":"cmp-int","expression":{"functionValue":{"name":"cmp","args":[{"integerValue":"2"},{"integerValue":"7"}]}},"expected":{"integerValue":"-1"}},{"id":"storage-size-string","expression":{"functionValue":{"name":"storage_size","args":[{"stringValue":"abc"}]}},"expected":{"integerValue":"4"}},{"id":"coalesce-null-string","expression":{"functionValue":{"name":"coalesce","args":[{"nullValue":"NULL_VALUE"},{"stringValue":"fallback"}]}},"expected":{"stringValue":"fallback"}},{"id":"namespace-reference","expression":{"functionValue":{"name":"namespace","args":[{"referenceValue":"projects/fireemu-oracle-query/databases/entpipe2-20261031/documents/positive/d1"}]}},"expected":{"stringValue":""}},{"id":"has-ancestor-reference","expression":{"functionValue":{"name":"has_ancestor","args":[{"referenceValue":"projects/fireemu-oracle-query/databases/entpipe2-20261031/documents/positive/d1/children/c1"},{"referenceValue":"projects/fireemu-oracle-query/databases/entpipe2-20261031/documents/positive/d1"}]}},"expected":{"booleanValue":true}},{"id":"reference-slice","expression":{"functionValue":{"name":"reference_slice","args":[{"referenceValue":"projects/fireemu-oracle-query/databases/entpipe2-20261031/documents/positive/d1/children/c1"},{"integerValue":"0"},{"integerValue":"1"}]}},"expected":{"referenceValue":"projects/fireemu-oracle-query/databases/entpipe2-20261031/documents/positive/d1"}},{"id":"autogen-document-id","expression":{"functionValue":{"name":"autogen_document_id","args":[]}},"expected":null},{"id":"replace-document-id","expression":{"functionValue":{"name":"replace_document_id","args":[{"referenceValue":"projects/fireemu-oracle-query/databases/entpipe2-20261031/documents/positive/d1"},{"stringValue":"d2"}]}},"expected":{"referenceValue":"projects/fireemu-oracle-query/databases/entpipe2-20261031/documents/positive/d2"}},{"id":"get-field-map","expression":{"functionValue":{"name":"get_field","args":[{"mapValue":{"fields":{"answer":{"integerValue":"7"}}}},{"stringValue":"answer"}]}},"expected":{"integerValue":"7"}},{"id":"offset-array","expression":{"functionValue":{"name":"offset","args":[{"arrayValue":{"values":[{"integerValue":"10"},{"integerValue":"20"}]}},{"integerValue":"1"}]}},"expected":{"integerValue":"20"}},{"id":"reverse-string","expression":{"functionValue":{"name":"reverse","args":[{"stringValue":"abc"}]}},"expected":{"stringValue":"cba"}},{"id":"reverse-bytes","expression":{"functionValue":{"name":"reverse","args":[{"bytesValue":"YWJj"}]}},"expected":{"bytesValue":"Y2Jh"}},{"id":"reverse-array","expression":{"functionValue":{"name":"reverse","args":[{"arrayValue":{"values":[{"integerValue":"1"},{"integerValue":"2"}]}}]}},"expected":{"arrayValue":{"values":[{"integerValue":"2"},{"integerValue":"1"}]}}},{"id":"length-string","expression":{"functionValue":{"name":"length","args":[{"stringValue":"abc"}]}},"expected":{"integerValue":"3"}},{"id":"length-bytes","expression":{"functionValue":{"name":"length","args":[{"bytesValue":"YWJj"}]}},"expected":{"integerValue":"3"}},{"id":"length-array","expression":{"functionValue":{"name":"length","args":[{"arrayValue":{"values":[{"integerValue":"1"},{"integerValue":"2"}]}}]}},"expected":{"integerValue":"2"}},{"id":"length-map","expression":{"functionValue":{"name":"length","args":[{"mapValue":{"fields":{"answer":{"integerValue":"7"}}}}]}},"expected":{"integerValue":"1"}},{"id":"length-vector","expression":{"functionValue":{"name":"length","args":[{"mapValue":{"fields":{"__type__":{"stringValue":"__vector__"},"value":{"arrayValue":{"values":[{"doubleValue":1},{"doubleValue":2}]}}}}}]}},"expected":{"integerValue":"2"}},{"id":"string-concat","expression":{"functionValue":{"name":"string_concat","args":[{"stringValue":"ab"},{"stringValue":"cd"}]}},"expected":{"stringValue":"abcd"}}]"#).unwrap();
        let database = "projects/fireemu-oracle-query/databases/entpipe2-20261031";
        let wire = |input: &serde_json::Value| {
            let body = json!({"structuredPipeline":{"pipeline":{"stages":[{"name":"select","args":[input]}]}}});
            let request = crate::rest::pipeline_json::request_from_json(database, &body).unwrap();
            structured_pipeline(&request).unwrap().stages[0].args[0].clone()
        };
        let row = Row::derived(std::collections::BTreeMap::default());
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            let mut ids = Vec::new();
            let runtime = RuntimeContext {
                expr_rng: Some(std::sync::Arc::new(std::sync::Mutex::new(
                    fireemu_core_types::determinism::SplitMix64::new(42),
                ))),
                ..RuntimeContext::default()
            };
            for case in cases.as_array().unwrap() {
                let id = case["id"].as_str().unwrap();
                let expression = decode_operand_tree(&wire(&case["expression"]), mode)
                    .unwrap_or_else(|error| panic!("{id}: {error:?}"));
                let actual = expression.eval_in_with_runtime(&row, mode, runtime.clone());
                if id == "autogen-document-id" {
                    for result in [
                        actual,
                        expression.eval_in_with_runtime(&row, mode, runtime.clone()),
                    ] {
                        let Eval::Value(Value::String(value)) = result else {
                            panic!("{id}: {result:?}")
                        };
                        assert_eq!(value.len(), 20);
                        assert!(value.bytes().all(|b| b.is_ascii_alphanumeric()));
                        ids.push(value);
                    }
                } else {
                    let expected = crate::decode::decode_value(&wire(&case["expected"])).unwrap();
                    assert_eq!(actual, Eval::Value(expected), "{id}");
                }
            }
            assert_ne!(ids[0], ids[1]);
        }
    }

    #[test]
    fn autogen_document_id_uses_request_runtime() {
        use fireemu_core_firestore::pipeline_exec::{Eval, Row, RuntimeContext};
        use fireemu_core_firestore::value::Value;
        use pb::value::ValueType as V;
        let wire = pb::Value {
            value_type: Some(V::FunctionValue(pb::Function {
                name: "autogen_document_id".to_owned(),
                args: vec![],
                ..Default::default()
            })),
        };
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            let expression = decode_operand_tree(&wire, mode).unwrap();
            let runtime = RuntimeContext {
                expr_rng: Some(std::sync::Arc::new(std::sync::Mutex::new(
                    fireemu_core_types::determinism::SplitMix64::new(42),
                ))),
                ..RuntimeContext::default()
            };
            let row = Row::derived(std::collections::BTreeMap::default());
            let mut ids = Vec::new();
            for _ in 0..2 {
                let Eval::Value(Value::String(id)) =
                    expression.eval_in_with_runtime(&row, mode, runtime.clone())
                else {
                    panic!("expected ID")
                };
                assert_eq!(id.len(), 20);
                assert!(id.bytes().all(|b| b.is_ascii_alphanumeric()));
                ids.push(id);
            }
            assert_ne!(ids[0], ids[1]);
        }
    }

    #[test]
    fn coalesce_skips_failing_constant_but_validates_static_errors() {
        use fireemu_core_firestore::pipeline_exec::{Eval, Row, RuntimeContext};
        use fireemu_core_firestore::value::Value;
        use pb::value::ValueType as V;
        let value = |kind| pb::Value {
            value_type: Some(kind),
        };
        let int = |number| value(V::IntegerValue(number));
        let call = |name: &str, args| {
            value(V::FunctionValue(pb::Function {
                name: name.to_owned(),
                args,
                ..Default::default()
            }))
        };
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            let expression = decode_operand_tree(
                &call(
                    "coalesce",
                    vec![int(7), call("divide", vec![int(1), int(0)])],
                ),
                mode,
            )
            .unwrap();
            assert_eq!(
                expression.eval_in_with_runtime(
                    &Row::derived(std::collections::BTreeMap::default()),
                    mode,
                    RuntimeContext::default()
                ),
                Eval::Value(Value::Integer(7))
            );
            let array = value(V::ArrayValue(pb::ArrayValue {
                values: vec![int(1)],
            }));
            let skipped = decode_operand_tree(
                &call(
                    "coalesce",
                    vec![int(7), call("offset", vec![array, int(5)])],
                ),
                mode,
            )
            .unwrap();
            assert_eq!(
                skipped.eval_in_with_runtime(
                    &Row::derived(std::collections::BTreeMap::default()),
                    mode,
                    RuntimeContext::default()
                ),
                Eval::Value(Value::Integer(7))
            );
            assert!(decode_operand_tree(
                &call("coalesce", vec![int(7), call("unknown_function", vec![])]),
                mode
            )
            .is_err());
            assert!(decode_operand_tree(
                &call("coalesce", vec![int(7), call("divide", vec![int(1)])]),
                mode
            )
            .is_err());
        }
    }

    proptest::proptest! {
        #[test]
        fn vector_in_array_preserves_dimension_order(numbers in proptest::collection::vec(-1000i32..1000, 1..8)) {
            use pb::value::ValueType as V;
            let values = numbers.iter().map(|n| pb::Value { value_type: Some(V::DoubleValue(f64::from(*n))) }).collect();
            let wire = tagged_literal(pb::Value { value_type: Some(V::StringValue("__vector__".to_owned())) }, values, true);
            let Expr::Constant(value) = decode_operand_tree(&wire, Unrecorded::Refuse).unwrap() else { panic!("expected constant") };
            proptest::prop_assert_eq!(crate::encode::encode_value(&value), wire);
        }
    }

    proptest::proptest! {
        #[test]
        fn unknown_tag_preserves_ordered_integer_values(tag in "[a-z]{1,8}", numbers in proptest::collection::vec(-1000i64..1000, 0..8)) {
            use pb::value::ValueType as V;
            let values = numbers.iter().map(|n| pb::Value { value_type: Some(V::IntegerValue(*n)) }).collect();
            let wire = tagged_literal(pb::Value { value_type: Some(V::StringValue(tag)) }, values, false);
            let Expr::Constant(value) = decode_operand_tree(&wire, Unrecorded::Refuse).unwrap() else { panic!("expected constant") };
            proptest::prop_assert_eq!(crate::encode::encode_value(&value), wire);
        }
    }

    proptest::proptest! {
        #[test]
        fn function_depth_tracks_each_branch(depth in 0_usize..45, width in 1_usize..5) {
            let mut value = pb::Value { value_type: Some(pb::value::ValueType::IntegerValue(1)) };
            for _ in 0..depth {
                value = pb::Value { value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
                    name: "array".into(), args: vec![value], ..Default::default()
                })) };
            }
            let mut fields = std::collections::HashMap::new();
            for index in 0..width { fields.insert(format!("a{index}"), value.clone()); }
            let request = pb::ExecutePipelineRequest {
                pipeline_type: Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline { stages: vec![pb::pipeline::Stage {
                        args: vec![pb::Value { value_type: Some(pb::value::ValueType::MapValue(pb::MapValue { fields })) }],
                        ..Default::default()
                    }] }), ..Default::default()
                })), ..Default::default()
            };
            let result = validate_function_depth(&request);
            proptest::prop_assert_eq!(result.is_err(), depth > 32);
        }
    }

    #[test]
    fn function_depth_reaches_arrays_and_nested_pipelines() {
        use pb::value::ValueType as V;
        let mut value = pb::Value {
            value_type: Some(V::IntegerValue(1)),
        };
        for _ in 0..33 {
            value = pb::Value {
                value_type: Some(V::FunctionValue(pb::Function {
                    name: "array".into(),
                    args: vec![value],
                    ..Default::default()
                })),
            };
        }
        let array = pb::Value {
            value_type: Some(V::ArrayValue(pb::ArrayValue {
                values: vec![value],
            })),
        };
        let nested = pb::Value {
            value_type: Some(V::PipelineValue(pb::Pipeline {
                stages: vec![pb::pipeline::Stage {
                    args: vec![array],
                    ..Default::default()
                }],
            })),
        };
        let request = pb::ExecutePipelineRequest {
            pipeline_type: Some(
                pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                    pb::StructuredPipeline {
                        pipeline: Some(pb::Pipeline {
                            stages: vec![pb::pipeline::Stage {
                                args: vec![nested],
                                ..Default::default()
                            }],
                        }),
                        ..Default::default()
                    },
                ),
            ),
            ..Default::default()
        };
        assert_eq!(
            validate_function_depth(&request).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn lazy_control_keeps_standalone_constant_errors_and_nested_arity_checks() {
        use pb::value::ValueType as V;
        let value = |kind| pb::Value {
            value_type: Some(kind),
        };
        let call = |name: &str, args: Vec<pb::Value>| {
            value(V::FunctionValue(pb::Function {
                name: name.to_owned(),
                args,
                ..Default::default()
            }))
        };
        let bad = call(
            "array_length",
            vec![value(V::StringValue("bad".to_owned()))],
        );
        assert!(decode_operand_tree(&bad, Unrecorded::Refuse).is_err());
        let invalid_arity = call("array_length", vec![]);
        let expression = call(
            "conditional",
            vec![
                value(V::BooleanValue(true)),
                value(V::StringValue("ok".to_owned())),
                invalid_arity,
            ],
        );
        assert!(decode_operand_tree(&expression, Unrecorded::Refuse).is_err());
    }

    #[test]
    fn count_argument_retains_the_full_positive_i64_range() {
        use pb::value::ValueType as V;
        for name in ["limit", "offset"] {
            let stage = pb::pipeline::Stage {
                name: name.to_owned(),
                args: vec![pb::Value {
                    value_type: Some(V::IntegerValue(i64::MAX)),
                }],
                ..Default::default()
            };
            assert_eq!(
                count_argument(&stage).unwrap(),
                u64::try_from(i64::MAX).unwrap()
            );
        }
    }

    #[test]
    fn count_argument_pict_cases() {
        use pb::value::ValueType as V;
        use tonic::Code;
        // Pairwise rows and required seeds from the zero-count coverage model.
        let cases = [
            (true, "limit", "zero"),
            (true, "offset", "zero"),
            (false, "limit", "zero"),
            (false, "offset", "zero"),
            (true, "limit", "positive"),
            (false, "limit", "string"),
            (true, "limit", "negative"),
            (true, "offset", "string"),
            (false, "limit", "boolean"),
            (false, "offset", "positive"),
            (true, "offset", "boolean"),
            (false, "offset", "negative"),
            (true, "offset", "negative"),
            (true, "limit", "boolean"),
        ];
        for (strict, name, kind) in cases {
            let arg = match kind {
                "zero" => V::IntegerValue(0),
                "positive" => V::IntegerValue(1),
                "negative" => V::IntegerValue(-1),
                "string" => V::StringValue("x".to_owned()),
                "boolean" => V::BooleanValue(true),
                _ => unreachable!(),
            };
            let stage = pb::pipeline::Stage {
                name: name.to_owned(),
                args: vec![pb::Value {
                    value_type: Some(arg),
                }],
                ..Default::default()
            };
            let got = count_argument(&stage);
            match kind {
                "zero" => assert_eq!(got.unwrap(), 0, "{strict} {name} {kind}"),
                "positive" => assert_eq!(got.unwrap(), 1, "{strict} {name} {kind}"),
                _ => assert_eq!(
                    got.unwrap_err().code(),
                    Code::InvalidArgument,
                    "{strict} {name} {kind}"
                ),
            }
        }
    }

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
            (own.to_owned(), false),
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

    const GENERATED_LITERAL_KEY_CASES: &[(&str, &str, &str, &str)] = &[
        ("reserved", "literal", "direct", "strict"),
        ("reserved", "literal", "nested", "strict"),
        ("name", "literal", "direct", "strict"),
        ("name", "literal", "nested", "strict"),
        ("reserved", "field", "direct", "strict"),
        ("empty", "field", "direct", "strict"),
        ("type", "field", "direct", "strict"),
        ("dotted", "function", "direct", "strict"),
        ("name", "field", "nested", "strict"),
        ("reserved", "field", "array", "strict"),
        ("plain", "literal", "direct", "strict"),
        ("plain", "field", "direct", "strict"),
        ("name", "field", "direct", "ordinary"),
        ("type", "literal", "direct", "ordinary"),
        ("dotted", "literal", "array", "ordinary"),
        ("dotted", "function", "nested", "ordinary"),
        ("empty", "function", "array", "ordinary"),
        ("empty", "literal", "nested", "strict"),
        ("reserved", "function", "array", "ordinary"),
        ("plain", "function", "nested", "ordinary"),
        ("plain", "field", "array", "ordinary"),
        ("name", "function", "array", "ordinary"),
        ("type", "function", "array", "ordinary"),
        ("dotted", "field", "direct", "ordinary"),
        ("type", "field", "nested", "strict"),
    ];

    #[test]
    fn generated_literal_key_combinations() {
        use pb::value::ValueType as V;
        let wrap_map = |key: &str, inner: pb::Value| pb::Value {
            value_type: Some(V::MapValue(pb::MapValue {
                fields: [(key.to_owned(), inner)].into_iter().collect(),
            })),
        };
        for &(key, payload, nest, profile) in GENERATED_LITERAL_KEY_CASES {
            let name = match key {
                "reserved" => "__x__",
                "name" => "__name__",
                "empty" => "",
                "dotted" => "a.b",
                "type" => "__type__",
                "plain" => "k",
                _ => unreachable!(),
            };
            let inner = match payload {
                "literal" if key == "type" => pb::Value {
                    value_type: Some(V::StringValue("tag".to_owned())),
                },
                "literal" => pb::Value {
                    value_type: Some(V::IntegerValue(1)),
                },
                "field" => pb::Value {
                    value_type: Some(V::FieldReferenceValue("i".to_owned())),
                },
                "function" => pb::Value {
                    value_type: Some(V::FunctionValue(pb::Function {
                        name: "document_id".to_owned(),
                        ..Default::default()
                    })),
                },
                _ => unreachable!(),
            };
            let mut value = wrap_map(name, inner);
            if nest == "nested" {
                value = wrap_map("outer", value);
            }
            if nest == "array" {
                value = pb::Value {
                    value_type: Some(V::ArrayValue(pb::ArrayValue {
                        values: vec![value],
                    })),
                };
            }
            let mode = if profile == "strict" {
                Unrecorded::Refuse
            } else {
                Unrecorded::OfficialEmulator
            };
            let result = decode_operand_tree(&value, mode);
            let expected = if matches!(key, "reserved" | "name") {
                Some(format!("field name '{name}' is reserved."))
            } else if payload == "field" {
                Some("Value type is not supported: FIELD_REFERENCE_VALUE".to_owned())
            } else if payload == "function" {
                Some("Value type is not supported: FUNCTION_VALUE".to_owned())
            } else if key == "empty" {
                Some(EMPTY_LITERAL_KEY.to_owned())
            } else {
                None
            };
            match expected {
                Some(text) => assert_eq!(
                    result.unwrap_err().message(),
                    text,
                    "{key} {payload} {nest} {profile}"
                ),
                None => assert!(
                    result.is_ok(),
                    "{key} {payload} {nest} {profile}: {result:?}"
                ),
            }
        }
        let name = pb::Value {
            value_type: Some(V::FieldReferenceValue("__name__".to_owned())),
        };
        for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            assert!(decode_operand_tree(&name, mode).is_ok());
        }
    }

    #[test]
    fn malformed_vector_and_literal_depth_stay_unobserved_with_expressions() {
        use pb::value::ValueType as V;
        let value = |kind| pb::Value {
            value_type: Some(kind),
        };
        let vector = value(V::MapValue(pb::MapValue {
            fields: [
                (
                    "__type__".to_owned(),
                    value(V::StringValue("__vector__".to_owned())),
                ),
                (
                    "value".to_owned(),
                    value(V::ArrayValue(pb::ArrayValue { values: vec![] })),
                ),
            ]
            .into_iter()
            .collect(),
        }));
        let map = |fields| value(V::MapValue(pb::MapValue { fields }));
        let field = value(V::FieldReferenceValue("i".to_owned()));
        let bad = map([("a".to_owned(), vector), ("__x__".to_owned(), field)]
            .into_iter()
            .collect());
        assert_eq!(
            decode_operand_tree(&bad, Unrecorded::Refuse)
                .unwrap_err()
                .code(),
            tonic::Code::Unimplemented
        );
        let mut deep = value(V::FieldReferenceValue("i".to_owned()));
        for _ in 0..21 {
            deep = map([("x".to_owned(), deep)].into_iter().collect());
        }
        let bad = map([("__x__".to_owned(), deep)].into_iter().collect());
        assert_eq!(
            decode_operand_tree(&bad, Unrecorded::Refuse)
                .unwrap_err()
                .code(),
            tonic::Code::Unimplemented
        );
    }

    proptest::proptest! {
        #[test]
        fn generated_reserved_key_stems_preserve_literal_diagnostics(stem in "[a-z]{1,12}") {
            use pb::value::ValueType as V;
            let map = |key: String| pb::Value { value_type: Some(V::MapValue(pb::MapValue {
                fields: [(key, pb::Value { value_type: Some(V::IntegerValue(1)) })].into_iter().collect(),
            })) };
            let reserved = format!("__{stem}__");
            let expected = format!("field name '{reserved}' is reserved.");
            for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
                let error = decode_operand_tree(&map(reserved.clone()), mode).unwrap_err();
                proptest::prop_assert_eq!(error.message(), expected.as_str());
                proptest::prop_assert!(decode_operand_tree(&map(stem.clone()), mode).is_ok());
            }
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
    mod scan_order {
        use super::*;
        use proptest::prelude::*;

        fn response(name: &str) -> pb::RunQueryResponse {
            pb::RunQueryResponse {
                document: Some(pb::Document {
                    name: format!("projects/p/databases/(default)/documents/{name}"),
                    ..Default::default()
                }),
                ..Default::default()
            }
        }

        fn names(responses: &[pb::RunQueryResponse]) -> Vec<String> {
            responses
                .iter()
                .filter_map(|r| r.document.as_ref())
                .map(|d| d.name.rsplit("/documents/").next().unwrap().to_owned())
                .collect()
        }

        #[test]
        fn crc32_is_the_zlib_checksum() {
            // The check value of the CRC-32/ISO-HDLC catalogue entry, and zlib's own answers.
            assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
            assert_eq!(crc32(b""), 0);
            assert_eq!(crc32(b"a"), 3_904_355_907);
            assert_eq!(crc32(b"d01"), 1_040_682_023);
        }

        #[test]
        fn a_collection_is_read_in_ascending_crc_of_the_id() {
            // O-9b: ids chosen so that the order differs from the name order.
            let read = in_scan_order(["c/a", "c/b", "c/d15", "c/d01"].map(response).to_vec());
            assert_eq!(names(&read), ["c/d15", "c/d01", "c/b", "c/a"]);
        }

        #[test]
        fn a_collection_group_is_read_by_parent_document_then_crc_of_the_id() {
            // O-9 `cg-main`: the root first, then cg/a, cg/a/items/x, cg/b, oth/p.
            let read = in_scan_order(
                [
                    "oth/p/items/q",
                    "cg/b/items/y",
                    "items/z",
                    "cg/a/items/x/items/w",
                    "cg/a/items/x",
                ]
                .map(response)
                .to_vec(),
            );
            assert_eq!(
                names(&read),
                [
                    "items/z",
                    "cg/a/items/x",
                    "cg/a/items/x/items/w",
                    "cg/b/items/y",
                    "oth/p/items/q"
                ]
            );
        }

        #[test]
        fn a_response_without_a_document_stays_first() {
            let mut responses = vec![response("c/a"), pb::RunQueryResponse::default()];
            responses.push(response("c/b"));
            let read = in_scan_order(responses);
            assert!(read[0].document.is_none());
        }

        proptest! {
            /// The result is a permutation in ascending CRC-32 of the ids, whatever the input
            /// order, and putting it in order twice changes nothing.
            #[test]
            fn the_scan_order_is_a_sorted_permutation(
                ids in proptest::collection::btree_set("[a-zA-Z0-9_.-]{1,8}", 0..24),
                shuffle in any::<u64>(),
            ) {
                let mut input: Vec<_> = ids.iter().map(|id| response(&format!("c/{id}"))).collect();
                let len = input.len().max(1);
                input.rotate_left(usize::try_from(shuffle).unwrap_or(0) % len);
                let read = in_scan_order(input);
                let keys: Vec<u32> = names(&read)
                    .iter()
                    .map(|name| crc32(name.rsplit('/').next().unwrap().as_bytes()))
                    .collect();
                prop_assert!(keys.windows(2).all(|pair| pair[0] <= pair[1]));
                prop_assert_eq!(read.len(), ids.len());
                prop_assert_eq!(names(&in_scan_order(read.clone())), names(&read));
            }
        }
    }
    mod operand_text {
        use super::*;

        fn function(name: &str, args: Vec<pb::Value>) -> pb::Value {
            pb::Value {
                value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
                    name: name.to_owned(),
                    args,
                    ..Default::default()
                })),
            }
        }

        fn field(path: &str) -> pb::Value {
            pb::Value {
                value_type: Some(pb::value::ValueType::FieldReferenceValue(path.to_owned())),
            }
        }

        fn scalar(value: pb::value::ValueType) -> pb::Value {
            pb::Value {
                value_type: Some(value),
            }
        }

        /// The texts the official emulator 1.22.0 and production print (probed 2026-10-27).
        #[test]
        fn an_operand_is_printed_as_the_official_emulator_prints_it() {
            use pb::value::ValueType as V;
            for (value, text) in [
                (scalar(V::IntegerValue(1)), "1L"),
                (scalar(V::IntegerValue(-5)), "-5L"),
                (scalar(V::DoubleValue(1.5)), "1.5D"),
                (scalar(V::DoubleValue(1.0)), "1.0D"),
                (scalar(V::DoubleValue(-0.0)), "0.0D"),
                (scalar(V::StringValue("s".into())), "\"s\""),
                (scalar(V::StringValue("a\"b".into())), "\"a\"b\""),
                (scalar(V::BooleanValue(true)), "true"),
                (scalar(V::NullValue(0)), "null"),
                (field("a.b"), "a.b"),
                (
                    function("equal", vec![field("v"), scalar(V::IntegerValue(1))]),
                    "equal(v, 1L)",
                ),
                (
                    function(
                        "is_type",
                        vec![field("zz"), scalar(V::StringValue("null".into()))],
                    ),
                    "is_type(zz, \"null\")",
                ),
                (function("array", vec![]), "array()"),
                (
                    scalar(V::ArrayValue(pb::ArrayValue {
                        values: vec![scalar(V::IntegerValue(1))],
                    })),
                    "[1L]",
                ),
                (
                    scalar(V::MapValue(pb::MapValue {
                        fields: [("k".to_owned(), scalar(V::IntegerValue(1)))].into(),
                    })),
                    "{k=1L}",
                ),
            ] {
                assert_eq!(expression_text(&value).as_deref(), Some(text));
            }
            // Doubles Java prints in exponent form, and kinds not printed here, have no text.
            assert_eq!(expression_text(&scalar(V::DoubleValue(1e7))), None);
            assert_eq!(expression_text(&scalar(V::DoubleValue(1e-4))), None);
            assert_eq!(expression_text(&scalar(V::DoubleValue(f64::NAN))), None);
            assert_eq!(
                expression_text(&scalar(V::ReferenceValue("/a/b".into()))),
                None
            );
        }

        /// The jar prints a map's entries in the order the request wrote them (`{k=1L, b=true}`);
        /// where that order is lost (a decoded gRPC map) there is no text.
        #[test]
        fn a_map_operand_keeps_the_request_order_or_has_no_text() {
            use pb::value::ValueType as V;
            let map = |entries: &[(&str, V)]| {
                scalar(V::MapValue(pb::MapValue {
                    fields: entries
                        .iter()
                        .map(|(key, value)| ((*key).to_owned(), scalar(value.clone())))
                        .collect(),
                }))
            };
            let two = map(&[("k", V::IntegerValue(1)), ("b", V::BooleanValue(true))]);
            let one = map(&[("k", V::IntegerValue(1))]);
            // No wire order: one entry is still printed, two are not.
            assert_eq!(expression_text(&one).as_deref(), Some("{k=1L}"));
            assert_eq!(expression_text(&two), None);
            // The body's order is known (REST): the entries come as written.
            let (_, order) =
                crate::rest::json_syntax::parse_with_key_order(br#"{"k": 1, "b": true}"#).unwrap();
            let scope = WireOrderScope::enter(Some(&order));
            assert_eq!(expression_text(&two).as_deref(), Some("{k=1L, b=true}"));
            let (_, reversed) =
                crate::rest::json_syntax::parse_with_key_order(br#"{"b": true, "k": 1}"#).unwrap();
            drop(scope);
            let _scope = WireOrderScope::enter(Some(&reversed));
            assert_eq!(expression_text(&two).as_deref(), Some("{b=true, k=1L}"));
        }

        #[test]
        fn exists_and_is_absent_take_a_field_reference_and_nothing_else() {
            let call = |name: &str, argument: pb::Value, unrecorded| {
                decode_operand_tree(&function(name, vec![argument]), unrecorded)
            };
            for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
                for name in ["exists", "is_absent"] {
                    assert!(call(name, field("a"), unrecorded).is_ok(), "{name}");
                    let refused = call(
                        name,
                        function(
                            "is_type",
                            vec![
                                field("zz"),
                                scalar(pb::value::ValueType::StringValue("null".into())),
                            ],
                        ),
                        unrecorded,
                    )
                    .unwrap_err();
                    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
                    assert_eq!(
                        refused.message(),
                        format!(
                            "The argument is_type(zz, \"null\") for function '{name}' is required to be a constant field reference."
                        )
                    );
                }
            }
            // An operand with no printed form is unobserved under strict.
            let reference = scalar(pb::value::ValueType::ReferenceValue("/a/b".into()));
            let refused = call("exists", reference.clone(), Unrecorded::Refuse).unwrap_err();
            assert_eq!(refused.code(), tonic::Code::Unimplemented);
            let refused = call("exists", reference, Unrecorded::OfficialEmulator).unwrap_err();
            assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        }

        #[test]
        fn document_paths_are_refused_in_the_words_of_the_recordings() {
            // O-9 `cg-main`, also the official emulator 1.22.0.
            assert_eq!(documents_path_error("/cg/a"), None);
            assert_eq!(documents_path_error("/cg/a/items/x"), None);
            for (path, text) in [
                ("/", "Document path name \"/\" is invalid: Omit trailing \"/\"."),
                ("/cg", "Document path name \"/cg\" lacks \"/\" at index 3."),
                (
                    "/cg/a/items",
                    "Document path name \"/cg/a/items\" lacks \"/\" at index 11.",
                ),
                (
                    "/cg/a/",
                    "Document path name \"/cg/a/\" has invalid trailing \"/\".",
                ),
                ("cg/a", "Document path name \"cg/a\" lacks \"/\" at index 0."),
                (
                    "projects/p/databases/d/documents/cg/a",
                    "Document path name \"projects/p/databases/d/documents/cg/a\" lacks \"/\" at index 0.",
                ),
            ] {
                assert_eq!(documents_path_error(path).as_deref(), Some(text), "{path}");
            }
        }
    }
    mod unknown_stage {
        use super::*;
        use proptest::prelude::*;

        fn with_stage(name: &str) -> pb::ExecutePipelineRequest {
            let stage = |name: &str, args: Vec<pb::Value>| pb::pipeline::Stage {
                name: name.to_owned(),
                args,
                ..Default::default()
            };
            pb::ExecutePipelineRequest {
                database: "projects/p/databases/(default)".to_owned(),
                pipeline_type: Some(
                    pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                        pb::StructuredPipeline {
                            pipeline: Some(pb::Pipeline {
                                stages: vec![
                                    stage(
                                        "collection",
                                        vec![pb::Value {
                                            value_type: Some(pb::value::ValueType::ReferenceValue(
                                                "/items".to_owned(),
                                            )),
                                        }],
                                    ),
                                    stage(name, Vec::new()),
                                ],
                            }),
                            options: std::collections::HashMap::new(),
                        },
                    ),
                ),
                ..Default::default()
            }
        }

        proptest! {
            /// A name that is no stage is refused in production's words by both profiles (the
            /// strict gate then answers only the recorded name); a stage the official emulator
            /// runs and the registry lacks stays `UNIMPLEMENTED`.
            #[test]
            fn a_name_that_is_no_stage_is_refused_in_production_words(name in "[A-Z][A-Z0-9_]{0,12}") {
                for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
                    let refused = validate_pipeline(&with_stage(&name), unrecorded).unwrap_err();
                    prop_assert_eq!(refused.code(), tonic::Code::InvalidArgument);
                    prop_assert_eq!(refused.message(), format!("Unsupported stage: {name}"));
                }
            }
        }

        #[test]
        fn a_stage_only_the_official_emulator_runs_stays_unsupported() {
            for name in OFFICIAL_ONLY_STAGES {
                for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
                    let refused = validate_pipeline(&with_stage(name), unrecorded).unwrap_err();
                    assert_eq!(refused.code(), tonic::Code::Unimplemented, "{name}");
                }
            }
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

        /// Production answered the identity alone, with either side quoted and beside plain
        /// aliases (FS-ENT-ORACLE O5, O-8A `names-main`); strict refuses the unrecorded
        /// combinations as unobserved.
        #[test]
        fn strict_answers_the_recorded_identity_selects_and_refuses_the_rest() {
            for entries in [
                vec![("__name__", "__name__")],
                vec![("`__name__`", "__name__")],
                vec![("__name__", "`__name__`")],
                vec![("__name__", "__name__"), ("a", "n")],
                vec![("__name__", "__name__"), ("nm", "__name__")],
            ] {
                let (_, keeps_name) =
                    decode_select(&select(&entries), Unrecorded::Refuse, None).unwrap();
                assert!(keeps_name, "{entries:?}");
            }
            for entries in [
                vec![("`__name__`", "`__name__`")],
                vec![("`__name__`", "__name__"), ("a", "n")],
                vec![("__name__", "`__name__`"), ("a", "n")],
                vec![("__name__", "__name__"), ("`a`", "n")],
                vec![("__name__", "__name__"), ("a", "`n`")],
                vec![("__name__", "__name__"), ("a", "n.m")],
                vec![("__name__", "__name__"), ("a.b", "n")],
                vec![("__name__", "__name__"), ("__name__.x", "n")],
            ] {
                let refused =
                    decode_select(&select(&entries), Unrecorded::Refuse, None).unwrap_err();
                assert_eq!(refused.code(), tonic::Code::Unimplemented, "{entries:?}");
            }
        }
    }
    #[test]
    fn observed_aggregate_functions_decode() {
        for name in [
            "array_agg",
            "array_agg_distinct",
            "first",
            "last",
            "count_if",
        ] {
            let input = pb::Value {
                value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
                    name: name.to_owned(),
                    args: vec![pb::Value {
                        value_type: Some(pb::value::ValueType::FieldReferenceValue("v".to_owned())),
                    }],
                    ..Default::default()
                })),
            };
            assert!(
                decode_accumulator(&input, Unrecorded::Refuse).is_ok(),
                "{name}"
            );
        }
    }
    #[test]
    fn subcollection_nested_select_alias_validation() {
        use pb::value::ValueType as V;
        for alias in ["", "__reserved__", "__name__", "a.b"] {
            let nested = pb::Pipeline {
                stages: vec![
                    pb::pipeline::Stage {
                        name: "subcollection".to_owned(),
                        args: vec![pb::Value {
                            value_type: Some(V::StringValue("kids".to_owned())),
                        }],
                        ..Default::default()
                    },
                    pb::pipeline::Stage {
                        name: "select".to_owned(),
                        args: vec![pb::Value {
                            value_type: Some(V::MapValue(pb::MapValue {
                                fields: [(
                                    alias.to_owned(),
                                    pb::Value {
                                        value_type: Some(V::FieldReferenceValue(
                                            "value".to_owned(),
                                        )),
                                    },
                                )]
                                .into_iter()
                                .collect(),
                            })),
                        }],
                        ..Default::default()
                    },
                ],
            };
            assert!(decode_subcollection_array(&nested).is_err(), "{alias:?}");
        }
        let nested = pb::Pipeline {
            stages: vec![
                pb::pipeline::Stage {
                    name: "subcollection".to_owned(),
                    args: vec![pb::Value {
                        value_type: Some(V::StringValue("kids".to_owned())),
                    }],
                    ..Default::default()
                },
                pb::pipeline::Stage {
                    name: "select".to_owned(),
                    args: vec![pb::Value {
                        value_type: Some(V::MapValue(pb::MapValue {
                            fields: [(
                                "renamed".to_owned(),
                                pb::Value {
                                    value_type: Some(V::FieldReferenceValue("value".to_owned())),
                                },
                            )]
                            .into_iter()
                            .collect(),
                        })),
                    }],
                    ..Default::default()
                },
            ],
        };
        assert!(matches!(
            decode_subcollection_array(&nested),
            Ok(Expr::SubcollectionArray { .. })
        ));
    }
}
