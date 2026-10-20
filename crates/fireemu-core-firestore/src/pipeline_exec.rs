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
//! Production answers recorded by FS-ENT-ORACLE O-1 (2026-10-19, an Enterprise database)
//! are answered under both profiles; they agree with the official emulator (firebase-tools
//! 15.28.2) everywhere O-1 looked. Under the strict profile anything whose production
//! behavior is still unrecorded (a comparison cell O-1 and O-2 did not record and no classic
//! query decides, a document function of an unrecorded input, a repeated map key) evaluates to
//! [`EvalError::Unobserved`], and the caller refuses the pipeline; the emulator profile answers
//! what the official emulator answers instead. An input both refuse evaluates to
//! [`EvalError::Invalid`].

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
    /// The input is invalid, as production or the official emulator refuses it with
    /// `INVALID_ARGUMENT` (the message is the official emulator's).
    Invalid(String),
    /// A function met an argument of a type it does not take: `INVALID_ARGUMENT`, which
    /// production details with a `FUNCTION_WRONG_TYPE` `ErrorInfo` naming the function.
    WrongType {
        /// The function.
        function: &'static str,
        /// The type it takes.
        expected: &'static str,
        /// The type name of the argument it got.
        got: &'static str,
    },
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unobserved { function, reason } => write!(
                f,
                "{function}: {reason}; this behavior is not observed locally"
            ),
            Self::Invalid(message) => f.write_str(message),
            Self::WrongType {
                function,
                expected,
                got,
            } => write!(
                f,
                "The function {function}(...) requires `{expected}` but got `{got}`."
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
            // The official emulator's text for an odd number of `map(...)` arguments.
            if function.arity == Arity::Pairs {
                return Err(ExprError::Invalid(format!(
                    "'{name}' function must have an even number of arguments"
                )));
            }
            let expected = match function.arity {
                Arity::Exact(n) => format!("{n} argument(s)"),
                Arity::Any => "any number of arguments".to_owned(),
                Arity::Pairs => unreachable!("answered above"),
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
        self.eval_at(row, unrecorded, false)
    }

    /// Evaluates the expression as the whole condition of a `where` stage.
    #[must_use]
    pub fn eval_condition_in(&self, row: &Row, unrecorded: Unrecorded) -> Eval {
        self.eval_at(row, unrecorded, true)
    }

    fn eval_at(&self, row: &Row, unrecorded: Unrecorded, condition: bool) -> Eval {
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
                    .map(|arg| arg.eval_in(row, unrecorded))
                    .collect();
                let cx = Context {
                    unrecorded,
                    condition,
                };
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

/// A comparison, in the official emulator's order under both profiles: production answered
/// every pair of operand kinds, a missing field included, under all six comparisons as the
/// official emulator does (FS-ENT-ORACLE O-2 for every kind but vectors, O-3 for vectors and a
/// missing field against every other kind, 2026-10-20).
fn eval_comparison(op: Comparison, args: &[Eval], _cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let [a, b] = args else {
        unreachable!("the table checks the arity");
    };
    Eval::Value(Value::Boolean(op.holds(official_order(a, b))))
}

/// `array(...)`: the elements in order, null for an absent element (production and the
/// official emulator answer `[1, null]` for `array(i, x)`).
fn eval_array(args: &[Eval], _cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    Eval::Value(Value::Array(
        args.iter()
            .map(|arg| match arg {
                Eval::Value(value) => value.clone(),
                _ => Value::Null,
            })
            .collect(),
    ))
}

/// The type name the official emulator's messages give a value.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NULL",
        Value::Boolean(_) => "BOOLEAN",
        Value::Integer(_) => "LONG",
        Value::Double(_) => "DOUBLE",
        Value::Timestamp(_) => "TIMESTAMP",
        Value::String(_) => "STRING",
        Value::Bytes(_) => "BYTES",
        Value::Reference(_) => "REFERENCE",
        Value::GeoPoint(_) => "GEO_POINT",
        Value::Array(_) => "ARRAY",
        Value::Vector(_) => "VECTOR",
        Value::Map(_) => "MAP",
    }
}

/// The key types production named when it refused a `map(...)` key (FS-ENT-ORACLE O-3
/// `functions#map-integer-key`, O-4 `functions#map-key-boolean`).
const RECORDED_MAP_KEY_TYPES: [&str; 2] = ["LONG", "BOOLEAN"];

/// The argument types production named, per document function, when it refused one: the
/// text names the function, so each pair is its own row (FS-ENT-ORACLE O-3
/// `functions#document-id-string`, `#collection-id-string`, `#parent-string`, O-4
/// `functions#document-id-integer`, `#collection-id-map`, `#parent-boolean`).
const RECORDED_DOCUMENT_ARGUMENT_TYPES: [(&str, &str); 6] = [
    ("document_id", "STRING"),
    ("document_id", "LONG"),
    ("collection_id", "STRING"),
    ("collection_id", "MAP"),
    ("parent", "STRING"),
    ("parent", "BOOLEAN"),
];

/// `map(key, value, ...)`, as production answered it (FS-ENT-ORACLE O-1, O-3 and O-4
/// `functions#map-*`) and the official emulator alike: a key whose value is absent is left out
/// (`map("k", i, "k2", x)` is `{k: 1}`), only two present values repeat a key (a missing value
/// drops its entry before the duplicate check), and a key that is not a string is refused
/// naming its type (production named LONG and BOOLEAN keys; strict refuses another type as
/// unobserved).
fn eval_map(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let mut fields = BTreeMap::new();
    for pair in args.chunks(2) {
        let [key, value] = pair else {
            unreachable!("the table checks the pairs");
        };
        let key = match key {
            Eval::Value(Value::String(key)) => key,
            Eval::Value(other)
                if cx.unrecorded == Unrecorded::Refuse
                    && !RECORDED_MAP_KEY_TYPES.contains(&type_name(other)) =>
            {
                return Eval::Error(EvalError::Unobserved {
                    function: "map",
                    reason: "a key of this type",
                })
            }
            Eval::Value(other) => {
                return Eval::Error(EvalError::Invalid(format!(
                    "map key must be of type STRING, given type is {}",
                    type_name(other)
                )))
            }
            // The adapter refuses a key that is no literal before evaluation.
            _ => {
                return Eval::Error(EvalError::Unobserved {
                    function: "map",
                    reason: "a key is absent",
                })
            }
        };
        if let Eval::Value(value) = value {
            if fields.insert(key.clone(), value.clone()).is_some() {
                return Eval::Error(EvalError::Invalid(format!(
                    "map(...) constructor given duplicate key: {key}"
                )));
            }
        }
    }
    Eval::Value(Value::Map(fields))
}

/// The document a reference argument names, or the answer for any other argument, as
/// production answered them (FS-ENT-ORACLE O-1, O-3 and O-4) and the official emulator answers
/// them alike:
/// - absent or null: null;
/// - the documents root (the parent of a top-level document): `INVALID_ARGUMENT` for
///   `document_id` and `collection_id`, null for `parent`;
/// - a collection at any depth: `INVALID_ARGUMENT` naming the reference and its length in
///   UTF-16 units as the index where the separator is missing (strict answers ASCII names
///   only, the ones production recorded);
/// - another type: `INVALID_ARGUMENT` with a `FUNCTION_WRONG_TYPE` detail (strict answers the
///   recorded types only).
///
/// A malformed reference is unrecorded in both profiles.
fn document_argument(
    function: &'static str,
    args: &[Eval],
    unrecorded: Unrecorded,
) -> Result<DocumentPath, Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    let unobserved = |reason| Err(Eval::Error(EvalError::Unobserved { function, reason }));
    let invalid = |message: String| Err(Eval::Error(EvalError::Invalid(message)));
    match args {
        [Eval::Value(Value::Reference(name))] => match DocumentPath::from_resource_name(name) {
            Some(path) => Ok(path),
            None if is_documents_root(name) && function == "parent" => {
                Err(Eval::Value(Value::Null))
            }
            None if is_documents_root(name) => {
                invalid(format!("{function}(...) requires a non-empty path."))
            }
            // Production answered every document function of a collection at any depth (O-3,
            // O-4 `functions#*-collection`, `*-subcollection`), as the official emulator does.
            // The index is the name's length in UTF-16 units, as the official emulator (Java)
            // counts it; production recorded ASCII names only, where units and bytes agree, so
            // strict refuses another name as unobserved.
            None if is_collection(name)
                && (name.is_ascii() || unrecorded == Unrecorded::OfficialEmulator) =>
            {
                invalid(format!(
                    "Document parent name \"{name}\" lacks \"/\" at index {}.",
                    name.encode_utf16().count()
                ))
            }
            None => unobserved("the reference does not name a document"),
        },
        [Eval::Absent | Eval::Value(Value::Null)] => Err(Eval::Value(Value::Null)),
        // Production refused every argument type it was given but a reference, naming the
        // type (O-3 a string, O-4 an integer, a map and a boolean, each with one function);
        // strict refuses the other pairs as unobserved.
        [Eval::Value(other)]
            if unrecorded == Unrecorded::Refuse
                && !RECORDED_DOCUMENT_ARGUMENT_TYPES.contains(&(function, type_name(other))) =>
        {
            unobserved("an argument of this type")
        }
        [Eval::Value(other)] => Err(Eval::Error(EvalError::WrongType {
            function,
            expected: "Reference",
            got: type_name(other),
        })),
        _ => unreachable!("the table checks the arity"),
    }
}

/// Whether `name` is a collection of a database, at any depth
/// (`projects/{p}/databases/{d}/documents/{collection}[/{document}/{collection}...]`).
fn is_collection(name: &str) -> bool {
    match name.split('/').collect::<Vec<_>>().as_slice() {
        ["projects", project, "databases", database, "documents", rest @ ..] => {
            !project.is_empty()
                && !database.is_empty()
                && rest.len() % 2 == 1
                && rest.iter().all(|segment| !segment.is_empty())
        }
        _ => false,
    }
}

/// Whether `name` is a database's documents root (`projects/{p}/databases/{d}/documents`), the
/// parent production answers for a top-level document.
fn is_documents_root(name: &str) -> bool {
    matches!(
        name.split('/').collect::<Vec<_>>().as_slice(),
        ["projects", project, "databases", database, "documents"]
            if !project.is_empty() && !database.is_empty()
    )
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

/// The parent document; for a top-level document production and the official emulator
/// answer the database's documents root as a reference.
fn eval_parent(args: &[Eval], cx: Context) -> Eval {
    match document_argument("parent", args, cx.unrecorded) {
        Ok(path) => Eval::Value(Value::Reference(path.parent_document().map_or_else(
            || {
                format!(
                    "projects/{}/databases/{}/documents",
                    path.project().as_str(),
                    path.database().as_str()
                )
            },
            |parent| parent.resource_name(),
        ))),
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
    /// Keeps rows whose condition is `true`; any other value, and an absent one, drops the row
    /// (production drops a row whose condition is an integer, null, a string, a reference, an
    /// array, a map or missing; strict refuses the other kinds, which are unrecorded).
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
                Stage::Where(condition) => {
                    match condition.eval_condition_in(&row, self.unrecorded) {
                        Eval::Value(Value::Boolean(true)) => {}
                        // Production dropped the row for a condition of every other kind
                        // (FS-ENT-ORACLE O-1 and O-2; O-3 for doubles, NaN, timestamps, bytes,
                        // geo points and vectors) and for a missing one.
                        Eval::Value(_) | Eval::Absent => return Ok(None),
                        // Production answered no refusal inside a where condition, so strict
                        // refuses one as unobserved (coordinator ruling of 2026-10-21: a
                        // recorded text answers only in the stage it was recorded in).
                        Eval::Error(error)
                            if self.unrecorded == Unrecorded::Refuse
                                && !matches!(error, EvalError::Unobserved { .. }) =>
                        {
                            return Err(EvalError::Unobserved {
                                function: "where",
                                reason: "a refusal inside a where condition",
                            })
                        }
                        Eval::Error(error) => return Err(error),
                    }
                }
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
