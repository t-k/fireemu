//! `ExecutePipeline` strict validation (`FS-PIPE-RPC-1`, spec 8.9.2): the wire stages are
//! canonicalized into a [`PipelineAst`] whose stages are identified against the documented
//! stage registry; unknown stages, misplaced input stages and write stages
//! (`FS-PIPE-WRITE-0`) are refused explicitly, never skipped. Execution is not part of
//! 1.0 (`strict-validation-only`).

use std::fmt;

/// A stage as decoded from the wire: its name, argument count and option keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageSpec {
    /// Stage name (`collection`, `where`, ...).
    pub name: String,
    /// Number of arguments.
    pub args: usize,
    /// Option keys, sorted.
    pub options: Vec<String>,
}

/// What a stage does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageRole {
    /// Produces documents (first stage only).
    Input,
    /// Transforms the stream.
    Transform,
    /// Writes results back (Preview; decoded, refused).
    Write,
}

/// A stage of the documented registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalStage {
    /// Stage name.
    pub name: String,
    /// Role.
    pub role: StageRole,
    /// Arguments.
    pub args: usize,
    /// Option keys.
    pub options: Vec<String>,
}

/// The canonical pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineAst {
    /// Stages in order; the first is the input.
    pub stages: Vec<CanonicalStage>,
}

impl PipelineAst {
    /// `collection(1) | where(1) | limit(1)`.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        self.stages
            .iter()
            .map(|s| format!("{}({})", s.name, s.args))
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

/// Why a pipeline is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    /// No stages.
    Empty,
    /// The first stage is not an input stage, or an input stage appears later.
    InputPosition(String),
    /// A stage the registry does not know.
    UnknownStage(String),
    /// Too few / many arguments.
    Arity {
        /// Stage.
        stage: String,
        /// Minimum.
        min: usize,
        /// Maximum (`None` = unbounded).
        max: Option<usize>,
        /// Given.
        got: usize,
    },
    /// A write stage (`update`, `delete`): `FS-PIPE-WRITE-0`.
    WriteStage(String),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a pipeline needs at least an input stage"),
            Self::InputPosition(s) => write!(
                f,
                "stage {s:?}: an input stage (collection, collection_group, database, documents) must come first and only first"
            ),
            Self::UnknownStage(s) => write!(f, "unknown pipeline stage {s:?}"),
            Self::Arity {
                stage,
                min,
                max,
                got,
            } => match max {
                Some(max) if max == min => {
                    write!(f, "stage {stage:?} takes {min} argument(s), got {got}")
                }
                Some(max) => write!(
                    f,
                    "stage {stage:?} takes {min}..={max} argument(s), got {got}"
                ),
                None => write!(f, "stage {stage:?} takes at least {min} argument(s), got {got}"),
            },
            Self::WriteStage(s) => write!(
                f,
                "stage {s:?} writes results back; write stages are declared unsupported (FS-PIPE-WRITE-0)"
            ),
        }
    }
}

impl std::error::Error for PipelineError {}

/// The documented stage registry: `(name, role, min args, max args)`.
const REGISTRY: &[(&str, StageRole, usize, Option<usize>)] = &[
    ("collection", StageRole::Input, 1, Some(1)),
    ("collection_group", StageRole::Input, 1, Some(1)),
    ("database", StageRole::Input, 0, Some(0)),
    ("documents", StageRole::Input, 1, None),
    ("select", StageRole::Transform, 1, None),
    ("add_fields", StageRole::Transform, 1, None),
    ("remove_fields", StageRole::Transform, 1, None),
    ("where", StageRole::Transform, 1, Some(1)),
    ("sort", StageRole::Transform, 1, None),
    ("limit", StageRole::Transform, 1, Some(1)),
    ("offset", StageRole::Transform, 1, Some(1)),
    ("distinct", StageRole::Transform, 1, None),
    ("aggregate", StageRole::Transform, 1, Some(2)),
    ("find_nearest", StageRole::Transform, 3, Some(3)),
    ("sample", StageRole::Transform, 1, Some(1)),
    ("union", StageRole::Transform, 1, Some(1)),
    ("unnest", StageRole::Transform, 1, Some(2)),
    ("replace_with", StageRole::Transform, 1, Some(2)),
    ("update", StageRole::Write, 0, None),
    ("delete", StageRole::Write, 0, None),
];

/// Identifies every stage and checks their placement and arity.
pub fn canonicalize(stages: &[StageSpec]) -> Result<PipelineAst, PipelineError> {
    if stages.is_empty() {
        return Err(PipelineError::Empty);
    }
    let mut out = Vec::with_capacity(stages.len());
    for (i, s) in stages.iter().enumerate() {
        let Some((name, role, min, max)) = REGISTRY.iter().find(|(n, ..)| *n == s.name) else {
            return Err(PipelineError::UnknownStage(s.name.clone()));
        };
        if (*role == StageRole::Input) != (i == 0) {
            return Err(PipelineError::InputPosition(s.name.clone()));
        }
        if s.args < *min || max.is_some_and(|m| s.args > m) {
            return Err(PipelineError::Arity {
                stage: s.name.clone(),
                min: *min,
                max: *max,
                got: s.args,
            });
        }
        if *role == StageRole::Write {
            return Err(PipelineError::WriteStage(s.name.clone()));
        }
        out.push(CanonicalStage {
            name: (*name).to_owned(),
            role: *role,
            args: s.args,
            options: s.options.clone(),
        });
    }
    Ok(PipelineAst { stages: out })
}
