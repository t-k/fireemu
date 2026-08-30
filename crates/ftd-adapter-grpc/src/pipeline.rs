//! `ExecutePipeline` decoding for the strict validator (`FS-PIPE-RPC-1`): the wire stages
//! become [`StageSpec`]s that the core canonicalizes; nothing is executed.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use ftd_core_firestore::pipeline::{canonicalize, PipelineAst, PipelineError, StageSpec};
use ftd_proto_firestore::google::firestore::v1 as pb;
use tonic::Status;

/// Decodes and canonicalizes the request's pipeline. Errors carry the `FS_PIPE_*` code in
/// the `ftd-code` metadata like the gateway's rejections.
pub fn validate_pipeline(req: &pb::ExecutePipelineRequest) -> Result<PipelineAst, Status> {
    if req.database.is_empty() {
        return Err(with_code(
            Status::invalid_argument("ExecutePipeline requires a database"),
            "FS_PIPE_DECODE",
        ));
    }
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &req.pipeline_type
    else {
        return Err(with_code(
            Status::invalid_argument("ExecutePipeline requires a structured_pipeline"),
            "FS_PIPE_DECODE",
        ));
    };
    let Some(pipeline) = &structured.pipeline else {
        return Err(with_code(
            Status::invalid_argument("structured_pipeline requires a pipeline"),
            "FS_PIPE_DECODE",
        ));
    };
    let mut specs = Vec::with_capacity(pipeline.stages.len());
    for stage in &pipeline.stages {
        for arg in &stage.args {
            if matches!(arg.value_type, Some(pb::value::ValueType::PipelineValue(_))) {
                return Err(with_code(
                    Status::unimplemented(format!(
                        "stage {:?}: nested pipeline arguments are not modelled",
                        stage.name
                    )),
                    "FS_PIPE_UNSUPPORTED",
                ));
            }
        }
        let mut options: Vec<String> = stage.options.keys().cloned().collect();
        options.sort();
        specs.push(StageSpec {
            name: stage.name.clone(),
            args: stage.args.len(),
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
            | PipelineError::Arity { .. } => {
                (Status::invalid_argument(e.to_string()), "FS_PIPE_INVALID")
            }
        };
        with_code(status, code)
    })
}

fn with_code(mut status: Status, code: &str) -> Status {
    if let Ok(v) = code.parse() {
        status.metadata_mut().insert("ftd-code", v);
    }
    status
}
