//! Pipeline execution core (`FS-PIPE-RPC-1`, slice PX0 of FS-PIPE-EXEC-CORE).
//!
//! Three layers, all pure:
//!
//! 1. An expression evaluator over three values ([`Eval`]: a value, absent, or an error).
//!    Functions come from a static table ([`function`]); a name outside the table is never
//!    evaluated, so callers refuse it instead of ignoring it.
//! 2. Stage operators ([`Stage`]) applied row by row through a [`Cursor`].
//! 3. Rows ([`Row`]) are documents read at one fixed read version; reading them is the
//!    caller's job, so the executor never sees two versions of the database.
//!
//! Only shapes whose behavior is already pinned by the finite local subset evaluate to
//! values. Anything whose production behavior is unrecorded (a function applied to an
//! absent or mistyped input, the parent of a top-level document, a non-boolean condition)
//! evaluates to [`EvalError::Unobserved`], and the caller refuses the pipeline.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use crate::field_path::FieldPath;
use crate::path::DocumentPath;
use crate::store::get_field;
use crate::value::Value;

/// A document read at the pipeline's read version.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// Document path (what `__name__` evaluates to).
    pub path: DocumentPath,
    /// Current fields of the row.
    pub fields: BTreeMap<String, Value>,
}

/// Why an expression has no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// The inputs fall outside the shapes whose production behavior is recorded; the
    /// executor refuses rather than guesses (ADR-005).
    Unobserved {
        /// Function or stage that met the input.
        function: &'static str,
        /// What was outside the recorded shapes.
        reason: &'static str,
    },
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unobserved { function, reason } => write!(
                f,
                "{function}: {reason}; this behavior is not observed locally"
            ),
        }
    }
}

impl std::error::Error for EvalError {}

/// The three-valued result of an expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Eval {
    /// A value.
    Value(Value),
    /// No value (a missing field, or a function of one).
    Absent,
    /// An evaluation error.
    Error(EvalError),
}

/// Where a function may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Only as the whole condition of a `where` stage.
    Condition,
    /// Anywhere a value is expected (select aliases, function arguments, conditions).
    Value,
}

/// One entry of the static function table.
pub struct Function {
    /// Wire name (`equal`, `document_id`, ...).
    pub name: &'static str,
    /// Exact number of arguments.
    pub arity: usize,
    /// Where the function may appear.
    pub placement: Placement,
    eval: fn(&[Eval]) -> Eval,
}

impl fmt::Debug for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Function")
            .field("name", &self.name)
            .field("arity", &self.arity)
            .field("placement", &self.placement)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

/// The functions the executor evaluates. Every other name is refused by [`Expr::call`].
const FUNCTIONS: &[Function] = &[
    Function {
        name: "equal",
        arity: 2,
        placement: Placement::Condition,
        eval: eval_equal,
    },
    Function {
        name: "document_id",
        arity: 1,
        placement: Placement::Value,
        eval: eval_document_id,
    },
    Function {
        name: "collection_id",
        arity: 1,
        placement: Placement::Value,
        eval: eval_collection_id,
    },
    Function {
        name: "parent",
        arity: 1,
        placement: Placement::Value,
        eval: eval_parent,
    },
];

/// Looks a function up in the static table.
#[must_use]
pub fn function(name: &str) -> Option<&'static Function> {
    FUNCTIONS.iter().find(|f| f.name == name)
}

/// Why an expression cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExprError {
    /// The function is not in the table, or not allowed in this position.
    Unsupported(String),
    /// The call is malformed (wrong number of arguments).
    Invalid(String),
}

impl fmt::Display for ExprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(m) | Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ExprError {}

/// An executable expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// A field reference (`__name__` evaluates to the row's document reference).
    Field(FieldPath),
    /// A constant.
    Constant(Value),
    /// A call of a table function.
    Call {
        /// The function.
        function: &'static Function,
        /// Arguments.
        args: Vec<Expr>,
    },
}

impl Expr {
    /// Builds a call of `name` in a position that accepts `placement`, checking the table
    /// and the arity.
    pub fn call(name: &str, args: Vec<Self>, placement: Placement) -> Result<Self, ExprError> {
        let Some(function) = function(name) else {
            return Err(ExprError::Unsupported(format!(
                "function {name:?} is unsupported locally"
            )));
        };
        if function.placement == Placement::Condition && placement != Placement::Condition {
            return Err(ExprError::Unsupported(format!(
                "function {name:?} is unsupported in this position locally"
            )));
        }
        if args.len() != function.arity {
            return Err(ExprError::Invalid(format!(
                "function {name:?} takes {} argument(s), got {}",
                function.arity,
                args.len()
            )));
        }
        Ok(Self::Call { function, args })
    }

    /// Evaluates the expression against one row.
    #[must_use]
    pub fn eval(&self, row: &Row) -> Eval {
        match self {
            Self::Field(path) if path.is_document_name() => {
                Eval::Value(Value::Reference(row.path.resource_name()))
            }
            Self::Field(path) => get_field(&row.fields, path)
                .cloned()
                .map_or(Eval::Absent, Eval::Value),
            Self::Constant(value) => Eval::Value(value.clone()),
            Self::Call { function, args } => {
                let args: Vec<Eval> = args.iter().map(|arg| arg.eval(row)).collect();
                (function.eval)(&args)
            }
        }
    }
}

/// The first error among the arguments, which every function propagates unchanged.
fn first_error(args: &[Eval]) -> Option<Eval> {
    args.iter()
        .find(|arg| matches!(arg, Eval::Error(_)))
        .cloned()
}

/// `equal(a, b)`: an error wins, then an absent operand makes the result absent (a `where`
/// drops the row, as the finite subset always did for a missing field).
fn eval_equal(args: &[Eval]) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    match args {
        [Eval::Value(a), Eval::Value(b)] => Eval::Value(Value::Boolean(values_equal(a, b))),
        _ => Eval::Absent,
    }
}

/// The document a reference argument names. Anything else (absent, another type, a name
/// that is not a document) is unrecorded.
fn document_argument(function: &'static str, args: &[Eval]) -> Result<DocumentPath, Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    let unobserved = |reason| Err(Eval::Error(EvalError::Unobserved { function, reason }));
    match args {
        [Eval::Value(Value::Reference(name))] => DocumentPath::from_resource_name(name)
            .map_or_else(|| unobserved("the reference does not name a document"), Ok),
        [Eval::Absent] => unobserved("the argument is absent"),
        _ => unobserved("the argument is not a document reference"),
    }
}

fn eval_document_id(args: &[Eval]) -> Eval {
    match document_argument("document_id", args) {
        Ok(path) => Eval::Value(Value::String(path.document_id().as_str().to_owned())),
        Err(e) => e,
    }
}

fn eval_collection_id(args: &[Eval]) -> Eval {
    match document_argument("collection_id", args) {
        Ok(path) => Eval::Value(Value::String(path.collection_id().as_str().to_owned())),
        Err(e) => e,
    }
}

fn eval_parent(args: &[Eval]) -> Eval {
    match document_argument("parent", args) {
        Ok(path) => path.parent_document().map_or(
            Eval::Error(EvalError::Unobserved {
                function: "parent",
                reason: "a top-level document has no parent document",
            }),
            |parent| Eval::Value(Value::Reference(parent.resource_name())),
        ),
        Err(e) => e,
    }
}

/// Equality of two values as the finite subset defines it: numbers compare across integer
/// and double, `NaN` equals only `NaN`, `null` equals only `null`, values of different
/// kinds are unequal.
#[must_use]
pub fn values_equal(a: &Value, b: &Value) -> bool {
    let nan = |v: &Value| matches!(v, Value::Double(d) if d.is_nan());
    match (nan(a), nan(b)) {
        (true, true) => true,
        (false, false) => a.canonical_cmp(b) == Ordering::Equal,
        _ => false,
    }
}

/// One stage operator.
#[derive(Debug, Clone, PartialEq)]
pub enum Stage {
    /// Keeps rows whose condition is `true`.
    Where(Expr),
    /// Replaces the fields by the aliases' values; an absent value leaves its alias out.
    Select(Vec<(String, Expr)>),
    /// Drops the first rows.
    Offset(u64),
    /// Keeps at most this many rows.
    Limit(u64),
}

/// Runs stages over rows one at a time.
#[derive(Debug, Clone)]
pub struct Cursor {
    stages: Vec<Stage>,
    /// Rows still to skip (offset) or to keep (limit), per stage; unused for other stages.
    counters: Vec<u64>,
}

impl Cursor {
    /// A cursor at the first row.
    #[must_use]
    pub fn new(stages: Vec<Stage>) -> Self {
        let counters = stages
            .iter()
            .map(|stage| match stage {
                Stage::Offset(n) | Stage::Limit(n) => *n,
                Stage::Where(_) | Stage::Select(_) => 0,
            })
            .collect();
        Self { stages, counters }
    }

    /// Whether no later row can produce output (a limit is used up).
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.stages
            .iter()
            .zip(&self.counters)
            .any(|(stage, remaining)| matches!(stage, Stage::Limit(_)) && *remaining == 0)
    }

    /// Pushes one row through the stages: `Some(fields)` when it comes out, `None` when a
    /// stage drops it.
    pub fn push(&mut self, mut row: Row) -> Result<Option<BTreeMap<String, Value>>, EvalError> {
        for (stage, remaining) in self.stages.iter().zip(self.counters.iter_mut()) {
            match stage {
                Stage::Where(condition) => match condition.eval(&row) {
                    Eval::Value(Value::Boolean(true)) => {}
                    Eval::Value(Value::Boolean(false)) | Eval::Absent => return Ok(None),
                    Eval::Value(_) => {
                        return Err(EvalError::Unobserved {
                            function: "where",
                            reason: "the condition is not a boolean",
                        })
                    }
                    Eval::Error(error) => return Err(error),
                },
                Stage::Select(aliases) => {
                    let mut fields = BTreeMap::new();
                    for (alias, expr) in aliases {
                        match expr.eval(&row) {
                            Eval::Value(value) => {
                                fields.insert(alias.clone(), value);
                            }
                            Eval::Absent => {}
                            Eval::Error(error) => return Err(error),
                        }
                    }
                    row.fields = fields;
                }
                Stage::Offset(_) => {
                    if *remaining > 0 {
                        *remaining -= 1;
                        return Ok(None);
                    }
                }
                Stage::Limit(_) => {
                    if *remaining == 0 {
                        return Ok(None);
                    }
                    *remaining -= 1;
                }
            }
        }
        Ok(Some(row.fields))
    }
}

/// Runs stages over all rows, stopping once a limit is used up.
pub fn execute(
    stages: Vec<Stage>,
    rows: impl IntoIterator<Item = Row>,
) -> Result<Vec<BTreeMap<String, Value>>, EvalError> {
    let mut cursor = Cursor::new(stages);
    let mut out = Vec::new();
    for row in rows {
        if cursor.is_exhausted() {
            break;
        }
        if let Some(fields) = cursor.push(row)? {
            out.push(fields);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
