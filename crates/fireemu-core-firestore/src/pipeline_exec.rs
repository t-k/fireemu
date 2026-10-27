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
use std::fmt::{self, Write as _};

use crate::field_path::FieldPath;
use crate::path::DocumentPath;
use crate::store::get_field;
use crate::value::{Timestamp, Value};

/// The create and update times of the document a row came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowTimes {
    /// When the document was created.
    pub created: Timestamp,
    /// When the document was last updated.
    pub updated: Timestamp,
}

/// A row of a pipeline: a document read at the pipeline's read version, or what a stage made
/// of one. A `select`, `distinct` or `aggregate` leaves nothing of the document but fields;
/// `add_fields` and `remove_fields` keep the document's name and times (removing `__name__`
/// drops the name and keeps the times, as production answered, FS-ENT-ORACLE O-7
/// `fields-main#remove-name`).
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    /// Document path (what `__name__` evaluates to); `None` once a stage dropped the name.
    pub path: Option<DocumentPath>,
    /// The document's times; `None` once a stage dropped them.
    pub times: Option<RowTimes>,
    /// Current fields of the row.
    pub fields: BTreeMap<String, Value>,
}

impl Row {
    /// A document read as it is stored, without times.
    #[must_use]
    pub fn document(path: DocumentPath, fields: BTreeMap<String, Value>) -> Self {
        Self {
            path: Some(path),
            times: None,
            fields,
        }
    }

    /// A row that is no document (the result of an aggregation).
    #[must_use]
    pub fn derived(fields: BTreeMap<String, Value>) -> Self {
        Self {
            path: None,
            times: None,
            fields,
        }
    }
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
    /// At least this many.
    AtLeast(usize),
    /// From the first number to the second, both included (a function with overloads).
    Between(usize, usize),
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
    /// The signature production names in its argument-count refusal (empty where fireemu
    /// answers its own wording).
    pub signature: &'static str,
    /// For a function with several overloads, production's argument-count refusal lists them:
    /// each is its signature with the fewest and the most arguments it takes. Empty for a
    /// function with one signature.
    pub overloads: &'static [(&'static str, usize, usize)],
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
        signature: "",
        overloads: &[],
        eval,
    }
}

/// A function of one document reference.
const fn document_function(name: &'static str, eval: fn(&[Eval], Context) -> Eval) -> Function {
    Function {
        name,
        arity: Arity::Exact(1),
        returns_boolean: false,
        signature: "",
        overloads: &[],
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
        signature: "",
        overloads: &[],
        eval: eval_array,
    },
    Function {
        name: "map",
        arity: Arity::Pairs,
        returns_boolean: false,
        signature: "",
        overloads: &[],
        eval: eval_map,
    },
    document_function("document_id", eval_document_id),
    document_function("collection_id", eval_collection_id),
    document_function("parent", eval_parent),
    logic::AND,
    logic::OR,
    logic::NOT,
    logic::XOR,
    logic::NOR,
    logic::EXISTS,
    logic::IS_ABSENT,
    logic::IS_ERROR,
    logic::TYPE,
    logic::IS_TYPE,
    logic::ARRAY_CONTAINS,
    logic::ARRAY_CONTAINS_ALL,
    logic::ARRAY_CONTAINS_ANY,
    logic::EQUAL_ANY,
    logic::NOT_EQUAL_ANY,
    scalar::CONCAT,
    scalar::TO_LOWER,
    scalar::TO_UPPER,
    scalar::STARTS_WITH,
    scalar::ENDS_WITH,
    scalar::STRING_CONTAINS,
    scalar::CHAR_LENGTH,
    scalar::SUBSTRING,
    scalar::TRIM,
    scalar::LTRIM,
    scalar::RTRIM,
    scalar::SPLIT,
    scalar::ADD,
    scalar::SUBTRACT,
    scalar::MULTIPLY,
    scalar::DIVIDE,
    scalar::MOD,
    scalar::ABS,
    scalar::ROUND,
    scalar::FLOOR,
    scalar::CEIL,
    scalar::POW,
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
    /// The call is malformed (wrong number of arguments), in fireemu's own words.
    Invalid(String),
    /// The call has the wrong number of arguments, in production's words (the signature).
    Arity(String),
}

impl fmt::Display for ExprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(m) | Self::Invalid(m) | Self::Arity(m) => f.write_str(m),
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
            Arity::AtLeast(n) => args.len() >= n,
            Arity::Between(low, high) => (low..=high).contains(&args.len()),
        };
        if !fits && !function.overloads.is_empty() {
            // Production lists the signatures that would have taken the call.
            let got = args.len();
            let mut options = String::new();
            for (signature, low, high) in function.overloads {
                let _ = write!(options, "\n- {signature} with [{low}..{high}] argument(s).");
            }
            return Err(ExprError::Arity(format!(
                "The function '{name}' does not accept {got} argument(s). Valid options are:{options}"
            )));
        }
        if !fits && !function.signature.is_empty() {
            let range = match function.arity {
                Arity::Exact(n) => format!("[{n}..{n}]"),
                Arity::AtLeast(n) => format!("[{n}..+\u{221e})"),
                Arity::Any | Arity::Pairs | Arity::Between(..) => {
                    unreachable!("these have no single signature")
                }
            };
            let got = args.len();
            return Err(ExprError::Arity(format!(
                "The function '{}' takes {range} argument(s), but {got} {} provided.",
                function.signature,
                if got == 1 { "was" } else { "were" }
            )));
        }
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
                Arity::Between(low, high) => format!("{low} to {high} argument(s)"),
                Arity::Pairs | Arity::AtLeast(_) => unreachable!("answered above"),
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
                row.path.as_ref().map_or(Eval::Absent, |path| {
                    Eval::Value(Value::Reference(path.resource_name()))
                })
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

/// One ordering of a `sort` stage.
#[derive(Debug, Clone, PartialEq)]
pub struct SortKey {
    /// The expression whose value orders the rows.
    pub expr: Expr,
    /// Whether the order is descending.
    pub descending: bool,
}

/// What an accumulator of an `aggregate` stage computes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccumulatorKind {
    /// `count()`: the rows.
    CountAll,
    /// `count(x)`: the rows where `x` is neither null nor missing.
    Count,
    /// `count_distinct(x)`: the distinct values of `x`, null and missing left out.
    CountDistinct,
    /// `sum(x)`: the sum of the numbers among the values of `x`.
    Sum,
    /// `average(x)`: their mean, always a double.
    Average,
    /// `minimum(x)`: the least value of `x` in the cross-type order.
    Minimum,
    /// `maximum(x)`: the greatest.
    Maximum,
}

/// An accumulator of an `aggregate` stage.
#[derive(Debug, Clone, PartialEq)]
pub struct Accumulator {
    /// What it computes.
    pub kind: AccumulatorKind,
    /// The expression it reads (`None` for `count()`).
    pub argument: Option<Expr>,
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
    /// repeat or contain one another (the caller checks). The row keeps its name only when the
    /// select named `__name__` as itself; it loses its times.
    Select {
        /// The aliases and their values.
        aliases: Vec<(FieldPath, Expr)>,
        /// Whether `__name__` was selected as itself.
        keeps_name: bool,
    },
    /// Sets the aliases on the row, each value read from the row as it was before the stage
    /// (a later alias does not see an earlier one). An absent value sets nothing.
    AddFields(Vec<(FieldPath, Expr)>),
    /// Removes the fields from the row; a missing field is ignored. Removing `__name__` drops
    /// the row's name.
    RemoveFields(Vec<FieldPath>),
    /// Drops the first rows.
    Offset(u64),
    /// Keeps at most this many rows.
    Limit(u64),
    /// Orders the rows (blocking): ascending or descending by each key in turn, ties kept in
    /// their input order.
    Sort(Vec<SortKey>),
    /// One row per distinct combination of the aliases' values (blocking); null and a missing
    /// value are one value.
    Distinct(Vec<(String, Expr)>),
    /// Groups the rows by the group aliases and computes the accumulators over each group
    /// (blocking). Without groups the whole input is one group, which exists even when the
    /// input is empty.
    Aggregate {
        /// The accumulators, by output name.
        accumulators: Vec<(String, Accumulator)>,
        /// The group keys, by output name.
        groups: Vec<(String, Expr)>,
    },
}

impl Stage {
    /// A `select` that does not keep the document name.
    #[must_use]
    pub fn select(aliases: Vec<(FieldPath, Expr)>) -> Self {
        Self::Select {
            aliases,
            keeps_name: false,
        }
    }

    /// Whether the stage needs every row before it can emit one.
    fn is_blocking(&self) -> bool {
        matches!(
            self,
            Self::Sort(_) | Self::Distinct(_) | Self::Aggregate { .. }
        )
    }
}

/// What a stage keeps between rows.
#[derive(Debug, Clone)]
enum StageState {
    /// Nothing.
    Idle,
    /// Rows still to skip (offset) or to keep (limit).
    Remaining(u64),
    /// The rows a blocking stage has received.
    Buffer(Vec<Row>),
}

/// Runs stages over rows one at a time. Rows that a blocking stage (`sort`, `distinct`,
/// `aggregate`) holds come out of [`Cursor::finish`].
#[derive(Debug, Clone)]
pub struct Cursor {
    stages: Vec<Stage>,
    unrecorded: Unrecorded,
    state: Vec<StageState>,
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
        let state = stages
            .iter()
            .map(|stage| match stage {
                Stage::Offset(n) | Stage::Limit(n) => StageState::Remaining(*n),
                Stage::Sort(_) | Stage::Distinct(_) | Stage::Aggregate { .. } => {
                    StageState::Buffer(Vec::new())
                }
                Stage::Where(_)
                | Stage::Select { .. }
                | Stage::AddFields(_)
                | Stage::RemoveFields(_) => StageState::Idle,
            })
            .collect();
        Self {
            stages,
            unrecorded,
            state,
        }
    }

    /// Whether no later row can produce output: a limit before the first blocking stage is used
    /// up, so the input need not be read further.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.stages
            .iter()
            .zip(&self.state)
            .take_while(|(stage, _)| !stage.is_blocking())
            .any(|(stage, state)| {
                matches!(stage, Stage::Limit(_)) && matches!(state, StageState::Remaining(0))
            })
    }

    /// Pushes one row through the stages: the rows that come out (none when a stage drops the
    /// row or a blocking stage holds it).
    pub fn push(&mut self, row: Row) -> Result<Vec<Row>, EvalError> {
        let mut out = Vec::new();
        self.run(0, row, &mut out)?;
        Ok(out)
    }

    /// Ends the input: the rows the blocking stages held, run through the stages after them.
    pub fn finish(&mut self) -> Result<Vec<Row>, EvalError> {
        let mut out = Vec::new();
        for index in 0..self.stages.len() {
            if !self.stages[index].is_blocking() {
                continue;
            }
            let StageState::Buffer(rows) =
                std::mem::replace(&mut self.state[index], StageState::Buffer(Vec::new()))
            else {
                continue;
            };
            let produced = match &self.stages[index] {
                Stage::Sort(keys) => sort_rows(rows, keys, self.unrecorded)?,
                Stage::Distinct(aliases) => distinct_rows(&rows, aliases, self.unrecorded)?,
                Stage::Aggregate {
                    accumulators,
                    groups,
                } => aggregate_rows(&rows, accumulators, groups, self.unrecorded)?,
                _ => continue,
            };
            for row in produced {
                self.run(index + 1, row, &mut out)?;
            }
        }
        Ok(out)
    }

    /// Runs `row` through the stages from `from`; a row that gets through is appended to `out`.
    #[allow(clippy::too_many_lines)]
    fn run(&mut self, from: usize, mut row: Row, out: &mut Vec<Row>) -> Result<(), EvalError> {
        for index in from..self.stages.len() {
            let stage = &self.stages[index];
            let held = &mut self.state[index];
            match stage {
                Stage::Where(condition) => {
                    match condition.eval_condition_in(&row, self.unrecorded) {
                        Eval::Value(Value::Boolean(true)) => {}
                        // Production dropped the row for a condition of every other kind
                        // (FS-ENT-ORACLE O-1 and O-2; O-3 for doubles, NaN, timestamps, bytes,
                        // geo points and vectors) and for a missing one.
                        Eval::Value(_) | Eval::Absent => return Ok(()),
                        // Production refused an `and`, `or` or `not` with an operand of the
                        // wrong type inside a where condition (FS-ENT-ORACLE O-6
                        // `where-functions-non-boolean`) and answered no other refusal there, so
                        // strict refuses the others as unobserved (coordinator ruling of
                        // 2026-10-21: a recorded text answers only in the stage it was recorded
                        // in).
                        Eval::Error(error)
                            if self.unrecorded == Unrecorded::Refuse
                                && !matches!(
                                    error,
                                    EvalError::Unobserved { .. }
                                        | EvalError::WrongType {
                                            function: "and" | "or" | "not",
                                            ..
                                        }
                                ) =>
                        {
                            return Err(EvalError::Unobserved {
                                function: "where",
                                reason: "a refusal inside a where condition",
                            })
                        }
                        Eval::Error(error) => return Err(error),
                    }
                }
                Stage::Select {
                    aliases,
                    keeps_name,
                } => {
                    let mut fields = BTreeMap::new();
                    let mut refused = None;
                    for (alias, expr) in aliases {
                        match expr.eval_in(&row, self.unrecorded) {
                            Eval::Value(value) => set_path(&mut fields, alias, value),
                            Eval::Absent if alias.segments().len() > 1 => {
                                // The official emulator keeps the parents of a nested alias
                                // whose value is missing as empty maps; production has not
                                // answered one (PX1d round 5 sweep, g20261021-02669).
                                if self.unrecorded == Unrecorded::Refuse {
                                    return Err(EvalError::Unobserved {
                                        function: "select",
                                        reason: "a nested alias of a missing value",
                                    });
                                }
                                set_parents(&mut fields, alias);
                            }
                            Eval::Absent => {}
                            Eval::Error(error) => {
                                refused = first_refusal(
                                    refused.as_ref(),
                                    error,
                                    self.unrecorded,
                                    "select",
                                )?;
                            }
                        }
                    }
                    if let Some(error) = refused {
                        return Err(error);
                    }
                    row.fields = fields;
                    if !*keeps_name {
                        row.path = None;
                    }
                    row.times = None;
                }
                Stage::AddFields(aliases) => {
                    // Every value is read from the row as it was before the stage.
                    let mut values = Vec::with_capacity(aliases.len());
                    let mut refused = None;
                    for (alias, expr) in aliases {
                        match expr.eval_in(&row, self.unrecorded) {
                            Eval::Value(value) => values.push((alias, Some(value))),
                            // A missing value (FS-ENT-ORACLE O-9 `fields-main`): a nested
                            // alias creates the parents as empty maps (a scalar parent is
                            // replaced) and sets nothing; a top-level alias removes the field.
                            Eval::Absent => values.push((alias, None)),
                            Eval::Error(error) => {
                                refused = first_refusal(
                                    refused.as_ref(),
                                    error,
                                    self.unrecorded,
                                    "add_fields",
                                )?;
                            }
                        }
                    }
                    if let Some(error) = refused {
                        return Err(error);
                    }
                    for (alias, value) in values {
                        match value {
                            Some(value) => set_path(&mut row.fields, alias, value),
                            None if alias.segments().len() > 1 => {
                                set_parents(&mut row.fields, alias);
                            }
                            None => remove_path(&mut row.fields, alias),
                        }
                    }
                }
                Stage::RemoveFields(paths) => {
                    for path in paths {
                        if path.is_document_name() {
                            row.path = None;
                        } else {
                            remove_path(&mut row.fields, path);
                        }
                    }
                }
                Stage::Offset(_) => {
                    let StageState::Remaining(remaining) = held else {
                        unreachable!("an offset keeps a count");
                    };
                    if *remaining > 0 {
                        *remaining -= 1;
                        return Ok(());
                    }
                }
                Stage::Limit(_) => {
                    let StageState::Remaining(remaining) = held else {
                        unreachable!("a limit keeps a count");
                    };
                    if *remaining == 0 {
                        return Ok(());
                    }
                    *remaining -= 1;
                }
                Stage::Sort(_) | Stage::Distinct(_) | Stage::Aggregate { .. } => {
                    let StageState::Buffer(rows) = held else {
                        unreachable!("a blocking stage keeps rows");
                    };
                    rows.push(row);
                    return Ok(());
                }
            }
        }
        out.push(row);
        Ok(())
    }
}

/// Keeps the first refusal of a stage that evaluates several values. Strict answers a refusal
/// only when exactly one value was refused: which of two production names depends on the
/// request's field order, which the decoded map no longer holds (`PX1d` round 4, `H9`).
fn first_refusal(
    refused: Option<&EvalError>,
    error: EvalError,
    unrecorded: Unrecorded,
    stage: &'static str,
) -> Result<Option<EvalError>, EvalError> {
    match (&error, unrecorded) {
        (EvalError::Unobserved { .. }, _) | (_, Unrecorded::OfficialEmulator) => Err(error),
        (_, Unrecorded::Refuse) if refused.is_some() => Err(EvalError::Unobserved {
            function: stage,
            reason: "a second refused field in one stage",
        }),
        (_, Unrecorded::Refuse) => Ok(Some(error)),
    }
}

/// What a blocking stage's expression gave a row, as the stage reads it: a missing value is
/// null (a sort, a group and `distinct` treat them as one value), and a refusal inside the
/// expression is unobserved under strict.
fn blocking_value(
    eval: Eval,
    unrecorded: Unrecorded,
    stage: &'static str,
) -> Result<Option<Value>, EvalError> {
    match eval {
        Eval::Value(value) => Ok(Some(value)),
        Eval::Absent => Ok(None),
        Eval::Error(error @ EvalError::Unobserved { .. }) => Err(error),
        Eval::Error(_) if unrecorded == Unrecorded::Refuse => Err(EvalError::Unobserved {
            function: stage,
            reason: "a refusal inside this stage's expression",
        }),
        Eval::Error(error) => Err(error),
    }
}

/// Orders rows by the keys, ties staying in input order. A missing key value sorts as null.
fn sort_rows(
    rows: Vec<Row>,
    keys: &[SortKey],
    unrecorded: Unrecorded,
) -> Result<Vec<Row>, EvalError> {
    let mut keyed = Vec::with_capacity(rows.len());
    for row in rows {
        let values = keys
            .iter()
            .map(|key| {
                blocking_value(key.expr.eval_in(&row, unrecorded), unrecorded, "sort")
                    .map(|value| value.unwrap_or(Value::Null))
            })
            .collect::<Result<Vec<_>, _>>()?;
        keyed.push((values, row));
    }
    keyed.sort_by(|(a, _), (b, _)| {
        for ((x, y), key) in a.iter().zip(b).zip(keys) {
            let order = x.canonical_cmp(y);
            let order = if key.descending {
                order.reverse()
            } else {
                order
            };
            if order != Ordering::Equal {
                return order;
            }
        }
        Ordering::Equal
    });
    Ok(keyed.into_iter().map(|(_, row)| row).collect())
}

/// A tuple of values grouped by equality: `1` and `1.0`, `-0.0` and `0.0`, and NaNs are equal,
/// arrays and maps element by element.
#[derive(Debug, Clone)]
struct GroupKey(Vec<Value>);

impl PartialEq for GroupKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for GroupKey {}
impl PartialOrd for GroupKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for GroupKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .iter()
            .zip(&other.0)
            .map(|(a, b)| a.canonical_cmp(b))
            .find(|order| *order != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    }
}

/// The key values of one row for the aliases, a missing value being null.
fn key_values(
    row: &Row,
    aliases: &[(String, Expr)],
    unrecorded: Unrecorded,
    stage: &'static str,
) -> Result<Vec<Value>, EvalError> {
    aliases
        .iter()
        .map(|(_, expr)| {
            blocking_value(expr.eval_in(row, unrecorded), unrecorded, stage)
                .map(|value| value.unwrap_or(Value::Null))
        })
        .collect()
}

/// `distinct`: one row per distinct combination of the aliases' values, in the order first met.
fn distinct_rows(
    rows: &[Row],
    aliases: &[(String, Expr)],
    unrecorded: Unrecorded,
) -> Result<Vec<Row>, EvalError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for row in rows {
        let key = GroupKey(key_values(row, aliases, unrecorded, "distinct")?);
        if seen.contains(&key) {
            continue;
        }
        let fields = aliases
            .iter()
            .map(|(name, _)| name.clone())
            .zip(key.0.iter().cloned())
            .collect();
        seen.insert(key);
        out.push(Row::derived(fields));
    }
    Ok(out)
}

/// The state of one accumulator over one group.
#[derive(Debug, Clone)]
enum Running {
    Count(i64),
    Distinct(std::collections::BTreeSet<GroupKey>),
    Sum(NumberSum, i64),
    Extreme(Option<Value>),
}

/// A running sum of numbers: integers stay integers until a double joins them.
#[derive(Debug, Clone, Copy)]
enum NumberSum {
    Nothing,
    Integer(i64),
    Double(f64),
}

impl NumberSum {
    // Production adds in doubles once one is met; the loss of an integer's low bits is its.
    #[allow(clippy::cast_precision_loss)]
    fn add(self, value: &Value) -> Result<Self, EvalError> {
        let overflow = || EvalError::Invalid("Long overflow".to_owned());
        Ok(match (self, value) {
            (Self::Nothing, Value::Integer(i)) => Self::Integer(*i),
            (Self::Nothing, Value::Double(d)) => Self::Double(*d),
            (Self::Integer(sum), Value::Integer(i)) => {
                Self::Integer(sum.checked_add(*i).ok_or_else(overflow)?)
            }
            (Self::Integer(sum), Value::Double(d)) => Self::Double(sum as f64 + d),
            (Self::Double(sum), Value::Integer(i)) => Self::Double(sum + *i as f64),
            (Self::Double(sum), Value::Double(d)) => Self::Double(sum + d),
            (other, _) => other,
        })
    }
}

impl Accumulator {
    fn start(&self) -> Running {
        match self.kind {
            AccumulatorKind::CountAll | AccumulatorKind::Count => Running::Count(0),
            AccumulatorKind::CountDistinct => Running::Distinct(std::collections::BTreeSet::new()),
            AccumulatorKind::Sum | AccumulatorKind::Average => Running::Sum(NumberSum::Nothing, 0),
            AccumulatorKind::Minimum | AccumulatorKind::Maximum => Running::Extreme(None),
        }
    }

    fn add(
        &self,
        running: &mut Running,
        row: &Row,
        unrecorded: Unrecorded,
    ) -> Result<(), EvalError> {
        let value = match &self.argument {
            Some(argument) => {
                blocking_value(argument.eval_in(row, unrecorded), unrecorded, "aggregate")?
            }
            None => None,
        };
        match (running, self.kind) {
            (Running::Count(n), AccumulatorKind::CountAll) => *n += 1,
            (Running::Count(n), _) => {
                if value.is_some_and(|v| v != Value::Null) {
                    *n += 1;
                }
            }
            (Running::Distinct(set), _) => {
                if let Some(value) = value.filter(|v| *v != Value::Null) {
                    set.insert(GroupKey(vec![value]));
                }
            }
            (Running::Sum(sum, numbers), _) => {
                if let Some(value @ (Value::Integer(_) | Value::Double(_))) = value {
                    *sum = sum.add(&value)?;
                    *numbers += 1;
                }
            }
            (Running::Extreme(best), kind) => {
                if let Some(value) = value.filter(|v| *v != Value::Null) {
                    let replace = best.as_ref().is_none_or(|current| {
                        let order = value.canonical_cmp(current);
                        if kind == AccumulatorKind::Minimum {
                            order == Ordering::Less
                        } else {
                            order == Ordering::Greater
                        }
                    });
                    if replace {
                        *best = Some(value);
                    }
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::cast_precision_loss)]
    fn finish(&self, running: Running) -> Value {
        match running {
            Running::Count(n) => Value::Integer(n),
            Running::Distinct(set) => Value::Integer(i64::try_from(set.len()).unwrap_or(i64::MAX)),
            Running::Sum(sum, numbers) => match (self.kind, sum) {
                (_, NumberSum::Nothing) => Value::Null,
                (AccumulatorKind::Sum, NumberSum::Integer(i)) => Value::Integer(i),
                (AccumulatorKind::Sum, NumberSum::Double(d)) => Value::Double(d),
                (_, NumberSum::Integer(i)) => Value::Double(i as f64 / numbers as f64),
                (_, NumberSum::Double(d)) => Value::Double(d / numbers as f64),
            },
            Running::Extreme(best) => best.unwrap_or(Value::Null),
        }
    }
}

/// `aggregate`: the groups in the order first met; without group aliases one group, which
/// exists for an empty input too.
fn aggregate_rows(
    rows: &[Row],
    accumulators: &[(String, Accumulator)],
    groups: &[(String, Expr)],
    unrecorded: Unrecorded,
) -> Result<Vec<Row>, EvalError> {
    type Group = (Vec<Value>, Vec<Running>);
    let start = || {
        accumulators
            .iter()
            .map(|(_, a)| a.start())
            .collect::<Vec<_>>()
    };
    let mut order: Vec<Group> = Vec::new();
    let mut index: std::collections::BTreeMap<GroupKey, usize> = std::collections::BTreeMap::new();
    if groups.is_empty() {
        order.push((Vec::new(), start()));
    }
    for row in rows {
        let key = key_values(row, groups, unrecorded, "aggregate")?;
        let at = if groups.is_empty() {
            0
        } else {
            *index.entry(GroupKey(key.clone())).or_insert_with(|| {
                order.push((key, start()));
                order.len() - 1
            })
        };
        let running = &mut order[at].1;
        for ((_, accumulator), state) in accumulators.iter().zip(running.iter_mut()) {
            accumulator.add(state, row, unrecorded)?;
        }
    }
    Ok(order
        .into_iter()
        .map(|(key, running)| {
            let mut fields = BTreeMap::new();
            for ((name, _), value) in groups.iter().zip(key) {
                fields.insert(name.clone(), value);
            }
            for ((name, accumulator), state) in accumulators.iter().zip(running) {
                fields.insert(name.clone(), accumulator.finish(state));
            }
            Row::derived(fields)
        })
        .collect())
}

/// Removes the value at `path` (nothing happens when a segment is missing or not a map).
fn remove_path(fields: &mut BTreeMap<String, Value>, path: &FieldPath) {
    let Some((last, parents)) = path.segments().split_last() else {
        return;
    };
    let mut map = fields;
    for segment in parents {
        match map.get_mut(segment) {
            Some(Value::Map(inner)) => map = inner,
            _ => return,
        }
    }
    map.remove(last);
}

/// Sets `value` at `path`, creating the maps on its way (a non-map on the way is replaced).
fn set_path(fields: &mut BTreeMap<String, Value>, path: &FieldPath, value: Value) {
    let Some((last, parents)) = path.segments().split_last() else {
        return;
    };
    parent_map(fields, parents).insert(last.clone(), value);
}

/// Creates the maps on the way to `path` without setting it, as the official emulator does for a
/// nested alias whose value is missing.
fn set_parents(fields: &mut BTreeMap<String, Value>, path: &FieldPath) {
    if let Some((_, parents)) = path.segments().split_last() {
        parent_map(fields, parents);
    }
}

/// The map at `parents`, created on the way (a non-map on the way is replaced).
fn parent_map<'a>(
    fields: &'a mut BTreeMap<String, Value>,
    parents: &[String],
) -> &'a mut BTreeMap<String, Value> {
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
    map
}

/// The field paths a scan must read for these stages, or `None` when every field can reach
/// the output (no stage that narrows the rows to computed fields: `select`, `distinct` or
/// `aggregate`). The paths are sorted and minimal (no path under another); a pipeline that
/// reads no field still names `__name__`, so the scan reads names only.
#[must_use]
pub fn referenced_fields(stages: &[Stage]) -> Option<Vec<FieldPath>> {
    let narrowing = stages.iter().position(|stage| {
        matches!(
            stage,
            Stage::Select { .. } | Stage::Distinct(_) | Stage::Aggregate { .. }
        )
    })?;
    let mut paths = Vec::new();
    for stage in &stages[..=narrowing] {
        match stage {
            Stage::Where(condition) => condition.collect_fields(&mut paths),
            Stage::Select { aliases, .. } | Stage::AddFields(aliases) => aliases
                .iter()
                .for_each(|(_, expr)| expr.collect_fields(&mut paths)),
            Stage::Sort(keys) => keys
                .iter()
                .for_each(|key| key.expr.collect_fields(&mut paths)),
            Stage::Distinct(aliases) => aliases
                .iter()
                .for_each(|(_, expr)| expr.collect_fields(&mut paths)),
            Stage::Aggregate {
                accumulators,
                groups,
            } => {
                for (_, accumulator) in accumulators {
                    if let Some(argument) = &accumulator.argument {
                        argument.collect_fields(&mut paths);
                    }
                }
                for (_, expr) in groups {
                    expr.collect_fields(&mut paths);
                }
            }
            Stage::RemoveFields(_) | Stage::Offset(_) | Stage::Limit(_) => {}
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
    Ok(execute_rows_in(stages, rows, unrecorded)?
        .into_iter()
        .map(|row| row.fields)
        .collect())
}

/// [`execute_in`] keeping what is left of each row besides its fields.
pub fn execute_rows_in(
    stages: Vec<Stage>,
    rows: impl IntoIterator<Item = Row>,
    unrecorded: Unrecorded,
) -> Result<Vec<Row>, EvalError> {
    let mut cursor = Cursor::new_in(stages, unrecorded);
    let mut out = Vec::new();
    for row in rows {
        if cursor.is_exhausted() {
            break;
        }
        out.extend(cursor.push(row)?);
    }
    out.extend(cursor.finish()?);
    Ok(out)
}

mod logic;
pub mod scalar;

pub use logic::TYPE_NAMES;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod scalar_tests;

#[cfg(test)]
mod compare_tests;

#[cfg(test)]
mod stage_tests;

#[cfg(test)]
mod official_compare;
