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
//! Under the strict profile only shapes whose behavior is already pinned evaluate to values:
//! [`check_recorded_shapes`] refuses, before any row is read, the shapes classic queries
//! cannot express, and anything whose production behavior is unrecorded (a function applied
//! to an absent or mistyped input, the parent of a top-level document, a comparison across
//! kinds) evaluates to [`EvalError::Unobserved`], and the caller refuses the pipeline. The
//! emulator profile answers as the official emulator does instead.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use crate::field_path::FieldPath;
use crate::path::DocumentPath;
use crate::store::get_field;
use crate::value::{Value, ValueKind};

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

/// What an input with unrecorded production behavior evaluates to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unrecorded {
    /// An [`EvalError::Unobserved`] error, which the caller refuses (the strict profile).
    Refuse,
    /// What the official emulator (firebase-tools 15.28.2, Firestore emulator 1.22.0,
    /// Enterprise) answers, where it answers; where it refuses, the error stays (the
    /// emulator profile, which may refuse nothing the official emulator completes).
    OfficialEmulator,
}

/// Where an expression stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// The whole condition of a `where` stage: only a function that returns a boolean.
    Condition,
    /// Anywhere a value is expected (select aliases, function arguments).
    Value,
}

/// How many arguments a function takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arity {
    /// Exactly this many.
    Exact(usize),
    /// Any number.
    Any,
    /// Key and value pairs (an even number).
    Pairs,
}

/// What a function sees besides its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// What inputs with unrecorded production behavior give.
    pub unrecorded: Unrecorded,
    /// Whether the call is the whole condition of a `where` stage (its arguments are not).
    pub condition: bool,
}

/// One entry of the static function table.
pub struct Function {
    /// Wire name (`equal`, `document_id`, ...).
    pub name: &'static str,
    /// Number of arguments.
    pub arity: Arity,
    /// Whether the function returns a boolean, so that it may be a whole `where` condition.
    pub returns_boolean: bool,
    eval: fn(&[Eval], Context) -> Eval,
}

impl fmt::Debug for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Function")
            .field("name", &self.name)
            .field("arity", &self.arity)
            .field("returns_boolean", &self.returns_boolean)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

/// A comparison of the table.
const fn comparison(name: &'static str, eval: fn(&[Eval], Context) -> Eval) -> Function {
    Function {
        name,
        arity: Arity::Exact(2),
        returns_boolean: true,
        eval,
    }
}

/// A function of one document reference.
const fn document_function(name: &'static str, eval: fn(&[Eval], Context) -> Eval) -> Function {
    Function {
        name,
        arity: Arity::Exact(1),
        returns_boolean: false,
        eval,
    }
}

/// The functions the executor evaluates. Every other name is refused by [`Expr::call`].
const FUNCTIONS: &[Function] = &[
    comparison("equal", |args, cx| {
        eval_comparison(Comparison::Equal, args, cx)
    }),
    comparison("not_equal", |args, cx| {
        eval_comparison(Comparison::NotEqual, args, cx)
    }),
    comparison("less_than", |args, cx| {
        eval_comparison(Comparison::Less, args, cx)
    }),
    comparison("less_than_or_equal", |args, cx| {
        eval_comparison(Comparison::LessOrEqual, args, cx)
    }),
    comparison("greater_than", |args, cx| {
        eval_comparison(Comparison::Greater, args, cx)
    }),
    comparison("greater_than_or_equal", |args, cx| {
        eval_comparison(Comparison::GreaterOrEqual, args, cx)
    }),
    Function {
        name: "array",
        arity: Arity::Any,
        returns_boolean: false,
        eval: eval_array,
    },
    Function {
        name: "map",
        arity: Arity::Pairs,
        returns_boolean: false,
        eval: eval_map,
    },
    document_function("document_id", eval_document_id),
    document_function("collection_id", eval_collection_id),
    document_function("parent", eval_parent),
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
        if placement == Placement::Condition && !function.returns_boolean {
            return Err(ExprError::Unsupported(format!(
                "function {name:?} is unsupported in this position locally"
            )));
        }
        let fits = match function.arity {
            Arity::Exact(n) => args.len() == n,
            Arity::Any => true,
            Arity::Pairs => args.len() % 2 == 0,
        };
        if !fits {
            let expected = match function.arity {
                Arity::Exact(n) => format!("{n} argument(s)"),
                Arity::Any => "any number of arguments".to_owned(),
                Arity::Pairs => "key and value pairs".to_owned(),
            };
            return Err(ExprError::Invalid(format!(
                "function {name:?} takes {expected}, got {} argument(s)",
                args.len()
            )));
        }
        Ok(Self::Call { function, args })
    }

    /// Adds every field path the expression reads.
    fn collect_fields(&self, out: &mut Vec<FieldPath>) {
        match self {
            Self::Field(path) => out.push(path.clone()),
            Self::Constant(_) => {}
            Self::Call { args, .. } => args.iter().for_each(|arg| arg.collect_fields(out)),
        }
    }

    /// Evaluates the expression against one row, refusing unrecorded inputs.
    #[must_use]
    pub fn eval(&self, row: &Row) -> Eval {
        self.eval_in(row, Unrecorded::Refuse)
    }

    /// Evaluates the expression against one row; `unrecorded` decides what inputs with
    /// unrecorded production behavior give.
    #[must_use]
    pub fn eval_in(&self, row: &Row, unrecorded: Unrecorded) -> Eval {
        self.eval_at(
            row,
            Context {
                unrecorded,
                condition: false,
            },
        )
    }

    /// Evaluates the expression as the whole condition of a `where` stage.
    #[must_use]
    pub fn eval_condition_in(&self, row: &Row, unrecorded: Unrecorded) -> Eval {
        self.eval_at(
            row,
            Context {
                unrecorded,
                condition: true,
            },
        )
    }

    fn eval_at(&self, row: &Row, cx: Context) -> Eval {
        match self {
            Self::Field(path) if path.is_document_name() => {
                Eval::Value(Value::Reference(row.path.resource_name()))
            }
            Self::Field(path) => get_field(&row.fields, path)
                .cloned()
                .map_or(Eval::Absent, Eval::Value),
            Self::Constant(value) => Eval::Value(value.clone()),
            Self::Call { function, args } => {
                let args: Vec<Eval> = args
                    .iter()
                    .map(|arg| arg.eval_in(row, cx.unrecorded))
                    .collect();
                (function.eval)(&args, cx)
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

/// The six comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

impl Comparison {
    const fn name(self) -> &'static str {
        match self {
            Self::Equal => "equal",
            Self::NotEqual => "not_equal",
            Self::Less => "less_than",
            Self::LessOrEqual => "less_than_or_equal",
            Self::Greater => "greater_than",
            Self::GreaterOrEqual => "greater_than_or_equal",
        }
    }

    /// The answer for two operands whose order is `order` (`None`: incomparable).
    fn holds(self, order: Option<Ordering>) -> bool {
        match self {
            Self::Equal => order == Some(Ordering::Equal),
            Self::NotEqual => order != Some(Ordering::Equal),
            Self::Less => order == Some(Ordering::Less),
            Self::LessOrEqual => matches!(order, Some(Ordering::Less | Ordering::Equal)),
            Self::Greater => order == Some(Ordering::Greater),
            Self::GreaterOrEqual => matches!(order, Some(Ordering::Greater | Ordering::Equal)),
        }
    }
}

/// The order the official emulator compares two operands in: two absent operands are equal,
/// one absent operand or operands of different kinds (NaN being a kind of its own) are
/// incomparable, and values of one kind follow the canonical order (arrays and maps compare
/// element by element in the total order).
fn official_order(a: &Eval, b: &Eval) -> Option<Ordering> {
    match (a, b) {
        (Eval::Absent, Eval::Absent) => Some(Ordering::Equal),
        (Eval::Value(a), Eval::Value(b)) if a.kind() == b.kind() => Some(a.canonical_cmp(b)),
        _ => None,
    }
}

/// A comparison. The emulator profile answers what the official emulator answers. Strict
/// answers only what classic queries decide the same way ([`check_recorded_shapes`] keeps
/// the shapes to `field op literal`): as the whole `where` condition, an equality answers
/// whatever the operands are (classic `==`, `IS_NULL` and `IS_NAN`), and one absent operand
/// drops the row as a classic filter on a missing field does (except `not_equal`, which the
/// official emulator keeps and classic `!=` drops); otherwise strict answers only two present
/// operands of one kind, neither null nor NaN. Everything else is unobserved.
fn eval_comparison(op: Comparison, args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let [a, b] = args else {
        unreachable!("the table checks the arity");
    };
    let answer = Eval::Value(Value::Boolean(op.holds(official_order(a, b))));
    if cx.unrecorded == Unrecorded::OfficialEmulator {
        return answer;
    }
    let unobserved = |reason| {
        Eval::Error(EvalError::Unobserved {
            function: op.name(),
            reason,
        })
    };
    let special = |v: &Value| matches!(v.kind(), ValueKind::Null | ValueKind::Nan);
    match (a, b) {
        (Eval::Value(_), Eval::Value(_)) if cx.condition && op == Comparison::Equal => answer,
        (Eval::Value(a), Eval::Value(b)) if a.kind() == b.kind() && !special(a) => answer,
        (Eval::Value(_), Eval::Value(_)) => {
            unobserved("the operands differ in kind, or one is null or NaN")
        }
        (Eval::Absent, Eval::Value(_)) | (Eval::Value(_), Eval::Absent)
            if cx.condition && op != Comparison::NotEqual =>
        {
            Eval::Absent
        }
        _ => unobserved("an operand is absent"),
    }
}

/// `array(...)`: the elements in order. The official emulator writes null for an absent
/// element; strict refuses one.
fn eval_array(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let mut values = Vec::with_capacity(args.len());
    for arg in args {
        match (arg, cx.unrecorded) {
            (Eval::Value(value), _) => values.push(value.clone()),
            (_, Unrecorded::OfficialEmulator) => values.push(Value::Null),
            (_, Unrecorded::Refuse) => {
                return Eval::Error(EvalError::Unobserved {
                    function: "array",
                    reason: "an element is absent",
                })
            }
        }
    }
    Eval::Value(Value::Array(values))
}

/// `map(key, value, ...)`: the official emulator leaves out a key whose value is absent;
/// strict refuses one, and a repeated key. A key that is not a string is unrecorded.
fn eval_map(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let unobserved = |reason| {
        Eval::Error(EvalError::Unobserved {
            function: "map",
            reason,
        })
    };
    let mut fields = BTreeMap::new();
    for pair in args.chunks(2) {
        let [Eval::Value(Value::String(key)), value] = pair else {
            return unobserved("a key is not a string");
        };
        match (value, cx.unrecorded) {
            (Eval::Value(value), _) => {
                if fields.insert(key.clone(), value.clone()).is_some()
                    && cx.unrecorded == Unrecorded::Refuse
                {
                    return unobserved("a key repeats");
                }
            }
            (_, Unrecorded::OfficialEmulator) => {}
            (_, Unrecorded::Refuse) => return unobserved("a value is absent"),
        }
    }
    Eval::Value(Value::Map(fields))
}

/// The document a reference argument names. Anything else (absent, another type, a name
/// that is not a document) is unrecorded; the official emulator answers null for an absent
/// or null argument and refuses the rest.
fn document_argument(
    function: &'static str,
    args: &[Eval],
    unrecorded: Unrecorded,
) -> Result<DocumentPath, Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    let unobserved = |reason| Err(Eval::Error(EvalError::Unobserved { function, reason }));
    match (args, unrecorded) {
        ([Eval::Value(Value::Reference(name))], _) => DocumentPath::from_resource_name(name)
            .map_or_else(|| unobserved("the reference does not name a document"), Ok),
        ([Eval::Absent | Eval::Value(Value::Null)], Unrecorded::OfficialEmulator) => {
            Err(Eval::Value(Value::Null))
        }
        ([Eval::Absent], Unrecorded::Refuse) => unobserved("the argument is absent"),
        _ => unobserved("the argument is not a document reference"),
    }
}

fn eval_document_id(args: &[Eval], cx: Context) -> Eval {
    match document_argument("document_id", args, cx.unrecorded) {
        Ok(path) => Eval::Value(Value::String(path.document_id().as_str().to_owned())),
        Err(e) => e,
    }
}

fn eval_collection_id(args: &[Eval], cx: Context) -> Eval {
    match document_argument("collection_id", args, cx.unrecorded) {
        Ok(path) => Eval::Value(Value::String(path.collection_id().as_str().to_owned())),
        Err(e) => e,
    }
}

/// The parent document; for a top-level document the official emulator answers the
/// database's documents root as a reference.
fn eval_parent(args: &[Eval], cx: Context) -> Eval {
    let unrecorded = cx.unrecorded;
    match document_argument("parent", args, unrecorded) {
        Ok(path) => match (path.parent_document(), unrecorded) {
            (Some(parent), _) => Eval::Value(Value::Reference(parent.resource_name())),
            (None, Unrecorded::OfficialEmulator) => Eval::Value(Value::Reference(format!(
                "projects/{}/databases/{}/documents",
                path.project().as_str(),
                path.database().as_str()
            ))),
            (None, Unrecorded::Refuse) => Eval::Error(EvalError::Unobserved {
                function: "parent",
                reason: "a top-level document has no parent document",
            }),
        },
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

/// Whether `function` takes a document reference (`document_id`, `collection_id`, `parent`).
fn is_document_function(function: &Function) -> bool {
    matches!(function.name, "document_id" | "collection_id" | "parent")
}

/// A field reference, or a document function of an operand or a literal (the finite
/// subset's operands).
fn is_operand(expr: &Expr) -> bool {
    match expr {
        Expr::Field(_) => true,
        Expr::Call { function, args } => {
            is_document_function(function)
                && args
                    .iter()
                    .all(|arg| matches!(arg, Expr::Constant(_)) || is_operand(arg))
        }
        Expr::Constant(_) => false,
    }
}

/// The two arguments of a comparison as an operand and a scalar literal (neither an array,
/// a map nor a vector), in either order.
fn operand_and_literal(args: &[Expr]) -> Option<(&Expr, &Value)> {
    fn scalar(expr: &Expr) -> Option<&Value> {
        match expr {
            Expr::Constant(value)
                if !matches!(value, Value::Array(_) | Value::Map(_) | Value::Vector(_)) =>
            {
                Some(value)
            }
            _ => None,
        }
    }
    match args {
        [operand, literal] | [literal, operand] if is_operand(operand) => {
            scalar(literal).map(|value| (operand, value))
        }
        _ => None,
    }
}

/// Whether strict answers this `where` condition without production observation: a field
/// compared with a scalar literal (null or NaN only in an equality), or the finite subset's
/// equality of a document function and a literal.
fn is_recorded_condition(expr: &Expr) -> bool {
    let Expr::Call { function, args } = expr else {
        return false;
    };
    if !function.returns_boolean {
        return false;
    }
    let Some((operand, literal)) = operand_and_literal(args) else {
        return false;
    };
    let equal = function.name == "equal";
    let field = matches!(operand, Expr::Field(_));
    (field || equal) && (equal || !matches!(literal.kind(), ValueKind::Null | ValueKind::Nan))
}

/// Whether strict answers this `select` value without production observation: an operand,
/// or a field compared with a scalar literal that is neither null nor NaN.
fn is_recorded_value(expr: &Expr) -> bool {
    if is_operand(expr) {
        return true;
    }
    let Expr::Call { function, args } = expr else {
        return false;
    };
    function.returns_boolean
        && matches!(
            operand_and_literal(args),
            Some((Expr::Field(_), literal))
                if !matches!(literal.kind(), ValueKind::Null | ValueKind::Nan)
        )
}

/// Checks the shapes strict answers before any row is read (the PX1 plan's strict column):
/// only shapes a classic query expresses and decides the same way. Comparisons of two fields
/// or two literals, comparisons below another function, array, map and vector literals and
/// constructions, and null or NaN outside a `where` equality are unobserved until production
/// answers them; the emulator profile skips this check.
pub fn check_recorded_shapes(stages: &[Stage]) -> Result<(), EvalError> {
    for stage in stages {
        match stage {
            Stage::Where(condition) if !is_recorded_condition(condition) => {
                return Err(EvalError::Unobserved {
                    function: "where",
                    reason: "only a field compared with a scalar literal is answered without production observation",
                });
            }
            Stage::Select(aliases) if !aliases.iter().all(|(_, expr)| is_recorded_value(expr)) => {
                return Err(EvalError::Unobserved {
                    function: "select",
                    reason: "only fields, document functions and a field compared with a scalar literal are answered without production observation",
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// One stage operator.
#[derive(Debug, Clone, PartialEq)]
pub enum Stage {
    /// Keeps rows whose condition is `true`.
    Where(Expr),
    /// Replaces the fields by the aliases' values. An alias is a field path, so a dotted
    /// alias nests its value; an absent value leaves its alias out. The aliases must not
    /// repeat or contain one another (the caller checks).
    Select(Vec<(FieldPath, Expr)>),
    /// Drops the first rows.
    Offset(u64),
    /// Keeps at most this many rows.
    Limit(u64),
}

/// Runs stages over rows one at a time.
#[derive(Debug, Clone)]
pub struct Cursor {
    stages: Vec<Stage>,
    unrecorded: Unrecorded,
    /// Rows still to skip (offset) or to keep (limit), per stage; unused for other stages.
    counters: Vec<u64>,
}

impl Cursor {
    /// A cursor at the first row that refuses unrecorded inputs.
    #[must_use]
    pub fn new(stages: Vec<Stage>) -> Self {
        Self::new_in(stages, Unrecorded::Refuse)
    }

    /// A cursor at the first row; `unrecorded` decides what unrecorded inputs give.
    #[must_use]
    pub fn new_in(stages: Vec<Stage>, unrecorded: Unrecorded) -> Self {
        let counters = stages
            .iter()
            .map(|stage| match stage {
                Stage::Offset(n) | Stage::Limit(n) => *n,
                Stage::Where(_) | Stage::Select(_) => 0,
            })
            .collect();
        Self {
            stages,
            unrecorded,
            counters,
        }
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
                Stage::Where(condition) => match condition.eval_condition_in(&row, self.unrecorded)
                {
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
                        match expr.eval_in(&row, self.unrecorded) {
                            Eval::Value(value) => set_path(&mut fields, alias, value),
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

/// Sets `value` at `path`, creating the maps on its way (a non-map on the way is replaced).
fn set_path(fields: &mut BTreeMap<String, Value>, path: &FieldPath, value: Value) {
    let Some((last, parents)) = path.segments().split_last() else {
        return;
    };
    let mut map = fields;
    for segment in parents {
        let entry = map
            .entry(segment.clone())
            .or_insert_with(|| Value::Map(BTreeMap::new()));
        if !matches!(entry, Value::Map(_)) {
            *entry = Value::Map(BTreeMap::new());
        }
        let Value::Map(inner) = entry else {
            unreachable!("replaced by a map above")
        };
        map = inner;
    }
    map.insert(last.clone(), value);
}

/// The field paths a scan must read for these stages, or `None` when every field can reach
/// the output (no `select`). The paths are sorted and minimal (no path under another); a
/// pipeline that reads no field still names `__name__`, so the scan reads names only.
#[must_use]
pub fn referenced_fields(stages: &[Stage]) -> Option<Vec<FieldPath>> {
    if !stages.iter().any(|stage| matches!(stage, Stage::Select(_))) {
        return None;
    }
    let mut paths = Vec::new();
    for stage in stages {
        match stage {
            Stage::Where(condition) => condition.collect_fields(&mut paths),
            Stage::Select(aliases) => aliases
                .iter()
                .for_each(|(_, expr)| expr.collect_fields(&mut paths)),
            Stage::Offset(_) | Stage::Limit(_) => {}
        }
    }
    paths.sort();
    paths.dedup();
    let minimal: Vec<FieldPath> = paths
        .iter()
        .filter(|path| {
            !paths
                .iter()
                .any(|other| other != *path && other.is_prefix_of(path))
        })
        .cloned()
        .collect();
    if minimal.is_empty() {
        return Some(vec![FieldPath::document_name()]);
    }
    Some(minimal)
}

/// Runs stages over all rows, stopping once a limit is used up and refusing unrecorded
/// inputs.
pub fn execute(
    stages: Vec<Stage>,
    rows: impl IntoIterator<Item = Row>,
) -> Result<Vec<BTreeMap<String, Value>>, EvalError> {
    execute_in(stages, rows, Unrecorded::Refuse)
}

/// [`execute`] with a choice of what unrecorded inputs give.
pub fn execute_in(
    stages: Vec<Stage>,
    rows: impl IntoIterator<Item = Row>,
    unrecorded: Unrecorded,
) -> Result<Vec<BTreeMap<String, Value>>, EvalError> {
    if unrecorded == Unrecorded::Refuse {
        check_recorded_shapes(&stages)?;
    }
    let mut cursor = Cursor::new_in(stages, unrecorded);
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

#[cfg(test)]
mod compare_tests;

#[cfg(test)]
mod official_compare;
