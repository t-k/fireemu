//! `ExecutePipeline` strict validation (`FS-PIPE-RPC-1`, spec 8.9.2): the wire stages are
//! canonicalized into a [`PipelineAst`] whose stages are identified against the documented
//! stage registry; unknown stages, misplaced input stages, badly typed arguments, unknown
//! options and write stages (`FS-PIPE-WRITE-0`) are refused explicitly, never skipped.
//! Execution is not part of 1.0 (`strict-validation-only`).

use std::fmt;

/// A stage argument as decoded from the wire (the shape that matters for validation).
#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    /// `null`.
    Null,
    /// A boolean.
    Bool,
    /// An integer.
    Integer(i64),
    /// A double.
    Double(f64),
    /// A timestamp.
    Timestamp,
    /// A string.
    String(String),
    /// Bytes.
    Bytes,
    /// A reference (document or collection path).
    Reference(String),
    /// A geo point.
    GeoPoint,
    /// An array.
    Array(Vec<Arg>),
    /// A map.
    Map(Vec<(String, Arg)>),
    /// A field reference.
    Field(String),
    /// A variable reference.
    Variable(String),
    /// A function call.
    Function {
        /// Function name.
        name: String,
        /// Arguments.
        args: Vec<Arg>,
    },
    /// A nested pipeline.
    Pipeline,
}

impl Arg {
    /// Whether the argument is an expression (anything but a nested pipeline).
    #[must_use]
    pub fn is_expression(&self) -> bool {
        !matches!(self, Self::Pipeline)
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool => "a boolean",
            Self::Integer(_) => "an integer",
            Self::Double(_) => "a double",
            Self::Timestamp => "a timestamp",
            Self::String(_) => "a string",
            Self::Bytes => "bytes",
            Self::Reference(_) => "a reference",
            Self::GeoPoint => "a geo point",
            Self::Array(_) => "an array",
            Self::Map(_) => "a map",
            Self::Field(_) => "a field reference",
            Self::Variable(_) => "a variable reference",
            Self::Function { .. } => "a function",
            Self::Pipeline => "a pipeline",
        }
    }
}

/// A stage as decoded from the wire: its name, arguments and options.
#[derive(Debug, Clone, PartialEq)]
pub struct StageSpec {
    /// Stage name (`collection`, `where`, ...).
    pub name: String,
    /// Arguments.
    pub args: Vec<Arg>,
    /// Options by key.
    pub options: Vec<(String, Arg)>,
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
    /// Option keys, sorted.
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
    /// An argument of the wrong shape.
    Argument {
        /// Stage.
        stage: String,
        /// Argument index.
        index: usize,
        /// What was expected.
        expected: &'static str,
        /// What was given.
        got: &'static str,
    },
    /// An option the stage does not take, or one of the wrong shape.
    Option {
        /// Stage.
        stage: String,
        /// Option key.
        key: String,
        /// What was expected (`"no such option"` for an unknown key).
        expected: &'static str,
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
            Self::Argument {
                stage,
                index,
                expected,
                got,
            } => write!(
                f,
                "stage {stage:?}: argument {index} must be {expected}, got {got}"
            ),
            Self::Option {
                stage,
                key,
                expected,
            } => write!(f, "stage {stage:?}: option {key:?}: {expected}"),
            Self::WriteStage(s) => write!(
                f,
                "stage {s:?} writes results back; write stages are declared unsupported (FS-PIPE-WRITE-0)"
            ),
        }
    }
}

impl std::error::Error for PipelineError {}

/// One registry entry: `(name, role, min args, max args, option keys)`.
type RegistryEntry = (
    &'static str,
    StageRole,
    usize,
    Option<usize>,
    &'static [&'static str],
);

/// The documented stage registry.
const REGISTRY: &[RegistryEntry] = &[
    ("collection", StageRole::Input, 1, Some(1), &[]),
    ("collection_group", StageRole::Input, 1, Some(1), &[]),
    ("database", StageRole::Input, 0, Some(0), &[]),
    ("documents", StageRole::Input, 1, None, &[]),
    ("select", StageRole::Transform, 1, Some(1), &[]),
    ("add_fields", StageRole::Transform, 1, Some(1), &[]),
    ("remove_fields", StageRole::Transform, 1, None, &[]),
    ("where", StageRole::Transform, 1, Some(1), &[]),
    ("sort", StageRole::Transform, 1, None, &[]),
    ("limit", StageRole::Transform, 1, Some(1), &[]),
    ("offset", StageRole::Transform, 1, Some(1), &[]),
    ("distinct", StageRole::Transform, 1, None, &[]),
    ("aggregate", StageRole::Transform, 1, Some(2), &[]),
    (
        "find_nearest",
        StageRole::Transform,
        3,
        Some(3),
        &["limit", "distance_field"],
    ),
    ("sample", StageRole::Transform, 1, Some(1), &["mode"]),
    ("union", StageRole::Transform, 1, Some(1), &[]),
    ("unnest", StageRole::Transform, 1, Some(2), &["index_field"]),
    ("replace_with", StageRole::Transform, 1, Some(2), &[]),
    ("update", StageRole::Write, 0, None, &[]),
    ("delete", StageRole::Write, 0, None, &[]),
];

fn segments_ok(path: &str, document: bool) -> bool {
    let path = path.trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').collect();
    !path.is_empty()
        && segments.iter().all(|s| !s.is_empty())
        && (segments.len() % 2 == 0) == document
}

fn argument(stage: &str, index: usize, expected: &'static str, got: &Arg) -> PipelineError {
    PipelineError::Argument {
        stage: stage.to_owned(),
        index,
        expected,
        got: got.kind(),
    }
}

fn alias_map(
    stage: &str,
    index: usize,
    arg: &Arg,
    values: &'static str,
) -> Result<(), PipelineError> {
    let Arg::Map(entries) = arg else {
        return Err(argument(
            stage,
            index,
            "a map of aliases to expressions",
            arg,
        ));
    };
    if entries.is_empty() {
        return Err(argument(stage, index, "a non-empty map of aliases", arg));
    }
    for (alias, value) in entries {
        if alias.is_empty() || !value.is_expression() {
            return Err(argument(stage, index, values, value));
        }
        if values == "a map of aliases to aggregate functions"
            && !matches!(value, Arg::Function { .. })
        {
            return Err(argument(stage, index, values, value));
        }
    }
    Ok(())
}

/// Checks the argument shapes of one stage (its arity is already checked).
#[allow(clippy::too_many_lines)]
fn check_arguments(name: &str, args: &[Arg]) -> Result<(), PipelineError> {
    match name {
        "collection" => match &args[0] {
            Arg::String(p) | Arg::Reference(p) if segments_ok(p, false) => Ok(()),
            other => Err(argument(name, 0, "a collection path", other)),
        },
        "collection_group" => match &args[0] {
            Arg::String(id) if !id.is_empty() && !id.contains('/') => Ok(()),
            other => Err(argument(name, 0, "a collection ID", other)),
        },
        "documents" => args.iter().enumerate().try_for_each(|(i, a)| match a {
            Arg::String(p) | Arg::Reference(p) if segments_ok(p, true) => Ok(()),
            other => Err(argument(name, i, "a document path", other)),
        }),
        "select" | "add_fields" => alias_map(name, 0, &args[0], "a map of aliases to expressions"),
        "remove_fields" => args.iter().enumerate().try_for_each(|(i, a)| match a {
            Arg::Field(_) => Ok(()),
            other => Err(argument(name, i, "a field reference", other)),
        }),
        "where" => match &args[0] {
            Arg::Function { .. } | Arg::Field(_) => Ok(()),
            other => Err(argument(name, 0, "a boolean expression", other)),
        },
        "sort" => args.iter().enumerate().try_for_each(|(i, a)| match a {
            Arg::Function { name: f, args }
                if (f == "ascending" || f == "descending")
                    && args.len() == 1
                    && args[0].is_expression() =>
            {
                Ok(())
            }
            other => Err(argument(
                name,
                i,
                "ascending(expr) or descending(expr)",
                other,
            )),
        }),
        "limit" | "offset" => match &args[0] {
            Arg::Integer(n) if *n >= 0 => Ok(()),
            other => Err(argument(name, 0, "a non-negative integer", other)),
        },
        "distinct" => args.iter().enumerate().try_for_each(|(i, a)| match a {
            Arg::Field(_) | Arg::Function { .. } => Ok(()),
            Arg::Map(_) => alias_map(name, i, a, "a map of aliases to expressions"),
            other => Err(argument(name, i, "a field, expression or alias map", other)),
        }),
        "aggregate" => {
            alias_map(name, 0, &args[0], "a map of aliases to aggregate functions")?;
            match args.get(1) {
                None => Ok(()),
                Some(groups) => alias_map(name, 1, groups, "a map of aliases to expressions"),
            }
        }
        "find_nearest" => {
            match &args[0] {
                Arg::Field(_) | Arg::Function { .. } => {}
                other => return Err(argument(name, 0, "a vector field", other)),
            }
            match &args[1] {
                Arg::Map(_) | Arg::Array(_) => {}
                other => return Err(argument(name, 1, "a vector value", other)),
            }
            match &args[2] {
                Arg::String(m) if matches!(m.as_str(), "euclidean" | "cosine" | "dot_product") => {
                    Ok(())
                }
                other => Err(argument(
                    name,
                    2,
                    "a distance measure (euclidean, cosine, dot_product)",
                    other,
                )),
            }
        }
        "sample" => match &args[0] {
            Arg::Integer(n) if *n >= 0 => Ok(()),
            Arg::Double(p) if (0.0..=100.0).contains(p) => Ok(()),
            other => Err(argument(name, 0, "a document count or a percentage", other)),
        },
        "union" => match &args[0] {
            Arg::Pipeline => Ok(()),
            other => Err(argument(name, 0, "a pipeline", other)),
        },
        "unnest" => {
            if !args[0].is_expression() {
                return Err(argument(name, 0, "an array expression", &args[0]));
            }
            match args.get(1) {
                None | Some(Arg::Field(_) | Arg::String(_)) => Ok(()),
                Some(other) => Err(argument(name, 1, "an alias", other)),
            }
        }
        "replace_with" => {
            if !args[0].is_expression() {
                return Err(argument(name, 0, "a map expression", &args[0]));
            }
            match args.get(1) {
                None => Ok(()),
                Some(Arg::String(m))
                    if matches!(
                        m.as_str(),
                        "full_replace" | "merge_prefer_nest" | "merge_prefer_parent"
                    ) =>
                {
                    Ok(())
                }
                Some(other) => Err(argument(
                    name,
                    1,
                    "a replace mode (full_replace, merge_prefer_nest, merge_prefer_parent)",
                    other,
                )),
            }
        }
        _ => Ok(()),
    }
}

fn check_options(
    name: &str,
    allowed: &[&str],
    options: &[(String, Arg)],
) -> Result<(), PipelineError> {
    for (key, value) in options {
        let option = |expected: &'static str| PipelineError::Option {
            stage: name.to_owned(),
            key: key.clone(),
            expected,
        };
        if !allowed.contains(&key.as_str()) {
            return Err(option("no such option"));
        }
        let ok = match (name, key.as_str(), value) {
            ("find_nearest", "limit", Arg::Integer(n)) => *n >= 1,
            ("find_nearest", "distance_field" | "index_field", Arg::Field(_) | Arg::String(_))
            | ("unnest", "index_field", Arg::Field(_) | Arg::String(_)) => true,
            ("sample", "mode", Arg::String(m)) => m == "documents" || m == "percent",
            _ => false,
        };
        if !ok {
            return Err(option(match (name, key.as_str()) {
                ("find_nearest", "limit") => "must be a positive integer",
                ("find_nearest", "distance_field") | ("unnest", "index_field") => {
                    "must be a field name"
                }
                ("sample", "mode") => "must be documents or percent",
                _ => "no such option",
            }));
        }
    }
    Ok(())
}

/// Identifies every stage and checks their placement, arity, argument shapes and options.
pub fn canonicalize(stages: &[StageSpec]) -> Result<PipelineAst, PipelineError> {
    if stages.is_empty() {
        return Err(PipelineError::Empty);
    }
    let mut out = Vec::with_capacity(stages.len());
    for (i, s) in stages.iter().enumerate() {
        let Some((name, role, min, max, allowed)) = REGISTRY.iter().find(|(n, ..)| *n == s.name)
        else {
            return Err(PipelineError::UnknownStage(s.name.clone()));
        };
        if (*role == StageRole::Input) != (i == 0) {
            return Err(PipelineError::InputPosition(s.name.clone()));
        }
        if s.args.len() < *min || max.is_some_and(|m| s.args.len() > m) {
            return Err(PipelineError::Arity {
                stage: s.name.clone(),
                min: *min,
                max: *max,
                got: s.args.len(),
            });
        }
        if *role == StageRole::Write {
            return Err(PipelineError::WriteStage(s.name.clone()));
        }
        check_arguments(name, &s.args)?;
        check_options(name, allowed, &s.options)?;
        let mut options: Vec<String> = s.options.iter().map(|(k, _)| k.clone()).collect();
        options.sort();
        out.push(CanonicalStage {
            name: (*name).to_owned(),
            role: *role,
            args: s.args.len(),
            options,
        });
    }
    Ok(PipelineAst { stages: out })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(name: &str, args: Vec<Arg>) -> StageSpec {
        StageSpec {
            name: name.to_owned(),
            args,
            options: Vec::new(),
        }
    }

    #[test]
    fn typed_arguments_are_checked_per_stage() {
        let users = || stage("collection", vec![Arg::Reference("/users".into())]);
        let eq = Arg::Function {
            name: "eq".into(),
            args: vec![Arg::Field("age".into()), Arg::Integer(3)],
        };
        assert!(canonicalize(&[
            users(),
            stage("where", vec![eq.clone()]),
            stage("limit", vec![Arg::Integer(5)])
        ])
        .is_ok());
        let bad_limit =
            canonicalize(&[users(), stage("limit", vec![Arg::String("text".into())])]).unwrap_err();
        assert!(
            matches!(bad_limit, PipelineError::Argument { index: 0, .. }),
            "{bad_limit}"
        );
        assert!(canonicalize(&[stage("collection", vec![Arg::Null])]).is_err());
        assert!(
            canonicalize(&[stage("collection", vec![Arg::String("/users/u1".into())])]).is_err()
        );
        assert!(canonicalize(&[users(), stage("where", vec![Arg::String("x".into())])]).is_err());
        assert!(canonicalize(&[users(), stage("sort", vec![Arg::Field("age".into())])]).is_err());
        assert!(canonicalize(&[
            users(),
            stage(
                "sort",
                vec![Arg::Function {
                    name: "ascending".into(),
                    args: vec![Arg::Field("age".into())]
                }]
            )
        ])
        .is_ok());
        let mut sample = stage("sample", vec![Arg::Integer(3)]);
        sample
            .options
            .push(("mode".into(), Arg::String("documents".into())));
        assert!(canonicalize(&[users(), sample.clone()]).is_ok());
        sample.options[0].1 = Arg::String("rows".into());
        assert!(matches!(
            canonicalize(&[users(), sample.clone()]).unwrap_err(),
            PipelineError::Option { .. }
        ));
        sample.options[0].0 = "speed".into();
        assert!(matches!(
            canonicalize(&[users(), sample]).unwrap_err(),
            PipelineError::Option { .. }
        ));
    }
}
