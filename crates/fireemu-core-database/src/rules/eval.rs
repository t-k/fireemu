//! Running a checked rule expression. Any error at run time (a member of a non-object, a
//! comparison of different types, a division by zero) makes the rule false, as the
//! official emulator denies such a request.

use std::collections::BTreeMap;

use super::parse::{BinaryOp, Expr, ExprKind};
use crate::json::Json;
use crate::key::validate_key;
use crate::node::{Content, Leaf, Node, Priority};
use crate::path::{Path, PRIORITY_KEY};
use crate::query::{Bound, Limit, OrderBy, QueryParams};

/// A location in one version of the tree.
#[derive(Debug, Clone)]
pub struct Snapshot<'a> {
    /// The root of that version.
    pub root: Option<&'a Node>,
    /// The location.
    pub path: Path,
}

/// What a snapshot's location holds. A `.priority` key names the priority of the node above
/// it, as a leaf (review r10 M29); anything below a priority, or below a leaf, is absent.
enum Located<'a> {
    Node(&'a Node),
    Priority(Leaf),
    Absent,
}

impl<'a> Snapshot<'a> {
    fn locate(&self) -> Located<'a> {
        let Some(mut node) = self.root else {
            return Located::Absent;
        };
        let keys = self.path.keys();
        for (i, key) in keys.iter().enumerate() {
            if key == PRIORITY_KEY {
                if i + 1 < keys.len() {
                    return Located::Absent;
                }
                return node
                    .priority
                    .as_ref()
                    .map_or(Located::Absent, |p| Located::Priority(p.as_leaf()));
            }
            match node.child(key) {
                Some(child) => node = child,
                None => return Located::Absent,
            }
        }
        Located::Node(node)
    }

    /// The snapshot `path` below this one: its keys, empty ones dropped.
    fn child(&self, path: &str) -> Self {
        let mut at = self.path.clone();
        for key in path.split('/').filter(|k| !k.is_empty()) {
            at = at.child(key);
        }
        Self {
            root: self.root,
            path: at,
        }
    }

    /// Whether the official emulator takes this location as a path: every key valid (a
    /// final `.priority` aside) within the depth and length limits. Its `getPriority()` is
    /// an internal error elsewhere (review r10 M30).
    fn is_valid_location(&self) -> bool {
        let limits = crate::limits::Limits::default();
        let keys = self.path.keys();
        keys.len() <= limits.max_depth
            && self.path.byte_len() <= limits.max_path_bytes
            && keys.iter().enumerate().all(|(i, key)| {
                (key == PRIORITY_KEY && i + 1 == keys.len()) || validate_key(key).is_ok()
            })
    }
}

/// The kind of read a rule judges. A read without a query is ordered by key for a REST `GET`,
/// by priority for an event stream and every realtime read (a listen or a `get`), and not
/// ordered at all where a write checks the read (a transaction, a conditional REST write) and
/// in `.write` and `.validate` (reviews r9 M24 and r10 M32, recorded on the official emulator).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadKind {
    /// A REST `GET`.
    Get,
    /// An event stream, or a realtime listen or `get`.
    Stream,
    /// A write, or the read a conditional write checks.
    Check,
}

/// What a rule can see.
pub struct Scope<'a> {
    /// `auth`: the token's claims as the server shows them, or null.
    pub auth: &'a Json,
    /// `now`, in milliseconds.
    pub now: i64,
    /// `root`
    pub root: Snapshot<'a>,
    /// `data`
    pub data: Snapshot<'a>,
    /// `newData`, for `.write` and `.validate`.
    pub new_data: Option<Snapshot<'a>>,
    /// `query`, for `.read`.
    pub query: Option<&'a QueryParams>,
    /// What kind of read the rule judges; it decides the ordering of a read without a query.
    pub read_kind: ReadKind,
    /// The `$wildcard` keys of the location.
    pub wildcards: &'a BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
enum Value<'a> {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    /// An object or array inside `auth`: a new value each time it is read.
    Json(Json),
    /// `auth` itself, one object.
    Auth(Json),
    /// `auth` without a user, and any absent member of `auth`: the official emulator's empty
    /// object, which equals `null` and whose members are itself.
    AuthEmpty,
    /// What `val()` gives for a location with children: the official emulator's sentinel,
    /// which equals nothing and has no members.
    Sentinel,
    /// An ordering by the child at these keys.
    Ordering(Vec<String>),
    /// An integer query bound: the official emulator holds it as a `Long`, which equals the
    /// number it stands for but is no number to `<`, `+`, `-` or a member.
    Long(i64),
    Snapshot(Snapshot<'a>),
    Query,
    Regex(super::pattern::Pattern),
    Array(Vec<Value<'a>>),
}

/// Evaluates a whole rule: true only when it evaluates to `true`.
pub fn allows(expr: &Expr, scope: &Scope<'_>) -> bool {
    matches!(eval(expr, scope), Some(Value::Bool(true)))
}

fn from_json<'a>(json: &Json) -> Value<'a> {
    match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => Value::Num(n.as_f64()),
        Json::String(s) => Value::Str(s.clone()),
        other => Value::Json(other.clone()),
    }
}

fn leaf_value<'a>(leaf: &Leaf) -> Value<'a> {
    match leaf {
        Leaf::Bool(b) => Value::Bool(*b),
        Leaf::Number(n) => Value::Num(n.as_f64()),
        Leaf::String(s) => Value::Str(s.clone()),
    }
}

/// A number as the official emulator prints it: a number that a 64-bit integer holds after
/// Java's saturating cast as that integer (so 2^63 prints as 9223372036854775807), anything
/// else as Java's `Double.toString` (plain from 10^-3 up to 10^7, otherwise
/// `d.dddE<exponent>`).
fn number_text(n: f64) -> String {
    if n.is_nan() {
        return "NaN".to_owned();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    // Rust's `as` saturates as Java's `(long)` does.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::float_cmp
    )]
    let whole = (n as i64) as f64 == n;
    if whole {
        #[allow(clippy::cast_possible_truncation)]
        return format!("{}", n as i64);
    }
    if (1e-3..1e7).contains(&n.abs()) {
        return format!("{n}");
    }
    // Rust's `{:e}` has the same shortest digits: `1.5e-7`, `1e21`.
    let text = format!("{n:e}");
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let mantissa = if mantissa.contains('.') {
        mantissa.to_owned()
    } else {
        format!("{mantissa}.0")
    };
    format!("{mantissa}E{exponent}")
}

fn eval<'a>(expr: &Expr, scope: &Scope<'a>) -> Option<Value<'a>> {
    match &expr.kind {
        ExprKind::Bool(b) => Some(Value::Bool(*b)),
        ExprKind::Number(n) => Some(Value::Num(*n)),
        ExprKind::Str(s) => Some(Value::Str(s.clone())),
        ExprKind::Null => Some(Value::Null),
        ExprKind::Ordering(keys) => Some(Value::Ordering(keys.clone())),
        ExprKind::Regex(pattern) => Some(Value::Regex(pattern.clone())),
        ExprKind::Array(items) => items
            .iter()
            .map(|item| eval(item, scope))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        ExprKind::Name(name) => variable(name, scope),
        ExprKind::Member(object, name) => member(eval(object, scope)?, name, scope),
        ExprKind::Index(object, index) => {
            let object = eval(object, scope)?;
            let key = match eval(index, scope)? {
                Value::Str(s) => s,
                Value::Num(n) => number_text(n),
                _ => return None,
            };
            member(object, &key, scope)
        }
        ExprKind::Call(callee, arguments) => {
            let ExprKind::Member(object, name) = &callee.kind else {
                return None;
            };
            let object = eval(object, scope)?;
            let arguments = arguments
                .iter()
                .map(|a| eval(a, scope))
                .collect::<Option<Vec<_>>>()?;
            call(object, name, &arguments)
        }
        ExprKind::Not(operand) => match eval(operand, scope)? {
            Value::Bool(b) => Some(Value::Bool(!b)),
            _ => None,
        },
        ExprKind::Neg(operand) => match eval(operand, scope)? {
            Value::Num(n) => Some(Value::Num(-n)),
            _ => None,
        },
        ExprKind::Binary(op, left, right) => binary(*op, left, right, scope),
        ExprKind::Chain(op, operands) => chain(*op, operands, scope),
        ExprKind::Ternary(condition, then, otherwise) => match eval(condition, scope)? {
            Value::Bool(true) => eval(then, scope),
            Value::Bool(false) => eval(otherwise, scope),
            _ => None,
        },
    }
}

fn variable<'a>(name: &str, scope: &Scope<'a>) -> Option<Value<'a>> {
    match name {
        "auth" => Some(match scope.auth {
            Json::Object(_) | Json::Array(_) => Value::Auth(scope.auth.clone()),
            Json::Null => Value::AuthEmpty,
            other => from_json(other),
        }),
        #[allow(clippy::cast_precision_loss)]
        "now" => Some(Value::Num(scope.now as f64)),
        "root" => Some(Value::Snapshot(scope.root.clone())),
        "data" => Some(Value::Snapshot(scope.data.clone())),
        "newData" => scope.new_data.clone().map(Value::Snapshot),
        "query" => Some(Value::Query),
        _ => scope.wildcards.get(name).map(|key| Value::Str(key.clone())),
    }
}

/// A member of `object`. Inside `auth` any member of an object or array, `length` included,
/// is its value, or the empty object when absent; the empty object's members are itself
/// (review r8 M23, the r10 ternary matrix). Anything else has only `length` of a string and
/// the members of `query`.
fn member<'a>(object: Value<'a>, name: &str, scope: &Scope<'a>) -> Option<Value<'a>> {
    let object = match object {
        Value::Auth(json) => Value::Json(json),
        other => other,
    };
    match object {
        Value::AuthEmpty => Some(Value::AuthEmpty),
        Value::Json(Json::Object(map)) => Some(map.get(name).map_or(Value::AuthEmpty, from_json)),
        // An array is an object keyed by its indexes, read as `Integer.parseInt` reads them
        // (review r10 M33).
        Value::Json(Json::Array(items)) => Some(
            java_int(name)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| items.get(index))
                .map_or(Value::AuthEmpty, from_json),
        ),
        Value::Str(s) if name == "length" =>
        {
            #[allow(clippy::cast_precision_loss)]
            Some(Value::Num(s.encode_utf16().count() as f64))
        }
        Value::Query => Some(query_member(scope.query, scope.read_kind, name)),
        _ => None,
    }
}

/// `text` as Java's `Integer.parseInt` reads it: an optional sign, then one or more decimal
/// digits of any script (`Character.digit`), in the range of an `int`.
fn java_int(text: &str) -> Option<i32> {
    let (negative, digits) = match text.chars().next()? {
        '-' => (true, &text[1..]),
        '+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for c in digits.chars() {
        value = value
            .checked_mul(10)?
            .checked_add(i64::from(super::java_chars::decimal_digit(c)?))?;
    }
    i32::try_from(if negative { -value } else { value }).ok()
}

/// Code units whose case Java 21 leaves as they are and Rust's newer Unicode tables map (or
/// the other way round); a case change of a string holding one is an error, so the rule is
/// false (the r11 case-map comparison).
const CASE_DIFFERS: [char; 16] = [
    '\u{019B}', '\u{0264}', '\u{1C89}', '\u{1C8A}', '\u{A7CB}', '\u{A7CC}', '\u{A7CD}', '\u{A7CE}',
    '\u{A7CF}', '\u{A7D2}', '\u{A7D3}', '\u{A7D4}', '\u{A7D5}', '\u{A7DA}', '\u{A7DB}', '\u{A7DC}',
];

/// `s.toLowerCase()` or `s.toUpperCase()` as Java 21 gives it.
pub(crate) fn java_case(s: &str, lower: bool) -> Option<String> {
    if s.chars().any(|c| CASE_DIFFERS.contains(&c)) {
        return None;
    }
    Some(if lower {
        s.to_lowercase()
    } else {
        s.to_uppercase()
    })
}

/// `s.replace(from, to)` as Java gives it: an empty `from` puts `to` before every UTF-16 unit
/// and at the end (a string with a character beyond the Basic Multilingual Plane would be
/// split there, which this text cannot hold, so that is an error).
fn java_replace(s: &str, from: &str, to: &str) -> Option<String> {
    if !from.is_empty() {
        return Some(s.replace(from, to));
    }
    if s.chars().any(|c| u32::from(c) > 0xFFFF) {
        return None;
    }
    let mut out = String::with_capacity(s.len() + to.len() * (s.len() + 1));
    for c in s.chars() {
        out.push_str(to);
        out.push(c);
    }
    out.push_str(to);
    Some(out)
}

fn bound_value<'a>(bound: Option<&Bound>) -> Value<'a> {
    match bound.map(|b| &b.value) {
        None => Value::Null,
        Some(Json::Number(crate::number::Number::Int(n))) => Value::Long(*n),
        Some(value) => from_json(value),
    }
}

/// A member of `query`. A read without a query is ordered as its [`ReadKind`] says. `startAt` is the start
/// bound, inclusive or not; `endAt` is an inclusive end bound only; `equalTo` is the start
/// value when an inclusive end bound has the same value.
fn query_member<'a>(query: Option<&QueryParams>, kind: ReadKind, name: &str) -> Value<'a> {
    let Some(q) = query else {
        return match name {
            "orderByKey" => Value::Bool(kind == ReadKind::Get),
            "orderByPriority" => Value::Bool(kind == ReadKind::Stream),
            "orderByValue" => Value::Bool(false),
            _ => Value::Null,
        };
    };
    let end = q.end.as_ref().filter(|e| e.inclusive);
    let equal = match (&q.start, end) {
        (Some(s), Some(e)) if s.value == e.value => Some(s),
        _ => None,
    };
    match name {
        "orderByKey" => Value::Bool(q.order_by == OrderBy::Key),
        "orderByValue" => Value::Bool(q.order_by == OrderBy::Value),
        "orderByPriority" => Value::Bool(q.order_by == OrderBy::Priority),
        "orderByChild" => match &q.order_by {
            OrderBy::Child(path) => Value::Ordering(path.keys().to_vec()),
            _ => Value::Null,
        },
        "equalTo" => bound_value(equal),
        "startAt" => bound_value(q.start.as_ref()),
        "endAt" => bound_value(end),
        "limitToFirst" => match q.limit {
            Some(Limit::First(n)) => Value::Num(f64::from(n)),
            _ => Value::Null,
        },
        "limitToLast" => match q.limit {
            Some(Limit::Last(n)) => Value::Num(f64::from(n)),
            _ => Value::Null,
        },
        _ => Value::Null,
    }
}

fn string_argument(arguments: &[Value<'_>], i: usize) -> Option<String> {
    match arguments.get(i)? {
        Value::Str(s) => Some(s.clone()),
        _ => None,
    }
}

fn call<'a>(object: Value<'a>, name: &str, arguments: &[Value<'a>]) -> Option<Value<'a>> {
    match object {
        Value::Snapshot(snapshot) => snapshot_call(&snapshot, name, arguments),
        Value::Str(s) => match name {
            "contains" => Some(Value::Bool(s.contains(&string_argument(arguments, 0)?))),
            "beginsWith" => Some(Value::Bool(s.starts_with(&string_argument(arguments, 0)?))),
            "endsWith" => Some(Value::Bool(s.ends_with(&string_argument(arguments, 0)?))),
            "replace" => java_replace(
                &s,
                &string_argument(arguments, 0)?,
                &string_argument(arguments, 1)?,
            )
            .map(Value::Str),
            "toLowerCase" => java_case(&s, true).map(Value::Str),
            "toUpperCase" => java_case(&s, false).map(Value::Str),
            "matches" => match arguments.first()? {
                Value::Regex(pattern) => pattern.matches(&s).map(Value::Bool),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

fn snapshot_call<'a>(
    snapshot: &Snapshot<'a>,
    name: &str,
    arguments: &[Value<'a>],
) -> Option<Value<'a>> {
    let located = snapshot.locate();
    match name {
        "val" => Some(match &located {
            Located::Absent => Value::Null,
            Located::Priority(leaf)
            | Located::Node(Node {
                content: Content::Leaf(leaf),
                ..
            }) => leaf_value(leaf),
            Located::Node(_) => Value::Sentinel,
        }),
        "child" => Some(Value::Snapshot(
            snapshot.child(&string_argument(arguments, 0)?),
        )),
        "parent" => snapshot.path.parent().map(|path| {
            Value::Snapshot(Snapshot {
                root: snapshot.root,
                path,
            })
        }),
        "exists" => Some(Value::Bool(!matches!(located, Located::Absent))),
        "hasChild" => Some(Value::Bool(!matches!(
            snapshot.child(&string_argument(arguments, 0)?).locate(),
            Located::Absent
        ))),
        "hasChildren" => {
            let has_children = matches!(
                located,
                Located::Node(Node {
                    content: Content::Children(_),
                    ..
                })
            );
            let keys = match arguments.first() {
                None => return Some(Value::Bool(has_children)),
                Some(Value::Array(keys)) => keys,
                Some(_) => return None,
            };
            // Each name is a path below the node, read in order up to the first absent one; a
            // name that is no string before that is an error, on any node (review r10 M31,
            // S25, and the r11 hasChildren table). An empty list is true anywhere.
            for key in keys {
                let Value::Str(key) = key else { return None };
                if matches!(snapshot.child(key).locate(), Located::Absent) {
                    return Some(Value::Bool(false));
                }
            }
            Some(Value::Bool(true))
        }
        "getPriority" => {
            if !snapshot.is_valid_location() {
                return None;
            }
            Some(match &located {
                // A priority written through a `.priority` path keeps an integer's type: the
                // official emulator holds it as a `Long`, equal to its number but no number to
                // `<`, `+` or `-` (review r11 M40). One inside an object body is a double.
                Located::Node(Node {
                    priority: Some(Priority::Number(crate::number::Number::Int(n))),
                    ..
                }) => Value::Long(*n),
                Located::Node(Node {
                    priority: Some(Priority::Number(n)),
                    ..
                }) => Value::Num(n.as_f64()),
                Located::Node(Node {
                    priority: Some(Priority::String(s)),
                    ..
                }) => Value::Str(s.clone()),
                _ => Value::Null,
            })
        }
        "isNumber" | "isString" | "isBoolean" => {
            let leaf = match &located {
                Located::Priority(leaf)
                | Located::Node(Node {
                    content: Content::Leaf(leaf),
                    ..
                }) => Some(leaf),
                _ => None,
            };
            Some(Value::Bool(matches!(
                (name, leaf),
                ("isNumber", Some(Leaf::Number(_)))
                    | ("isString", Some(Leaf::String(_)))
                    | ("isBoolean", Some(Leaf::Bool(_)))
            )))
        }
        _ => None,
    }
}

/// `left op right` for an operator the parser does not chain (`&&`, `||` and `+` are
/// always [`chain`]s).
fn binary<'a>(op: BinaryOp, left: &Expr, right: &Expr, scope: &Scope<'a>) -> Option<Value<'a>> {
    let l = eval(left, scope)?;
    let r = eval(right, scope)?;
    combine(op, &l, &r)
}

/// A chain of `&&`, `||` or `+`, read left to right as the nested operators it stands for:
/// `&&` and `||` stop at the first operand that decides.
fn chain<'a>(op: BinaryOp, operands: &[Expr], scope: &Scope<'a>) -> Option<Value<'a>> {
    let (first, rest) = operands.split_first()?;
    if matches!(op, BinaryOp::And | BinaryOp::Or) {
        let Value::Bool(mut value) = eval(first, scope)? else {
            return None;
        };
        for operand in rest {
            if (op == BinaryOp::And && !value) || (op == BinaryOp::Or && value) {
                break;
            }
            let Value::Bool(next) = eval(operand, scope)? else {
                return None;
            };
            value = next;
        }
        return Some(Value::Bool(value));
    }
    let mut value = eval(first, scope)?;
    for operand in rest {
        value = combine(op, &value, &eval(operand, scope)?)?;
    }
    Some(value)
}

/// `l op r` for an operator that is not `&&` or `||`.
fn combine<'a>(op: BinaryOp, l: &Value<'a>, r: &Value<'a>) -> Option<Value<'a>> {
    match op {
        BinaryOp::Eq => equal(l, r).map(Value::Bool),
        BinaryOp::Ne => equal(l, r).map(|equal| Value::Bool(!equal)),
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            let ordering = match (l, r) {
                // Any comparison with NaN is false there.
                (Value::Num(a), Value::Num(b)) => match a.partial_cmp(b) {
                    Some(ordering) => ordering,
                    None => return Some(Value::Bool(false)),
                },
                (Value::Str(a), Value::Str(b)) => a.encode_utf16().cmp(b.encode_utf16()),
                // Any other pair is an error there, so the rule is false negated or not
                // (review r8 M22).
                _ => return None,
            };
            Some(Value::Bool(match op {
                BinaryOp::Lt => ordering.is_lt(),
                BinaryOp::Le => ordering.is_le(),
                BinaryOp::Gt => ordering.is_gt(),
                _ => ordering.is_ge(),
            }))
        }
        BinaryOp::Add => match (l, r) {
            (Value::Num(a), Value::Num(b)) => Some(Value::Num(a + b)),
            (Value::Str(a), _) => Some(Value::Str(format!("{a}{}", text(r)?))),
            (_, Value::Str(b)) => Some(Value::Str(format!("{}{b}", text(l)?))),
            _ => None,
        },
        BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => {
            let (Value::Num(a), Value::Num(b)) = (l, r) else {
                return None;
            };
            // NaN and the infinities are numbers there, as in JavaScript (the r9 operator
            // matrix).
            Some(Value::Num(match op {
                BinaryOp::Sub => a - b,
                BinaryOp::Mul => a * b,
                // A division by zero is NaN there, never an infinity (recorded 2026-10-21).
                #[allow(clippy::float_cmp)]
                BinaryOp::Div if *b == 0.0 => f64::NAN,
                BinaryOp::Div => a / b,
                _ => a % b,
            }))
        }
        BinaryOp::And | BinaryOp::Or => None,
    }
}

/// The text of a value added to a string: only numbers and strings have one.
fn text(value: &Value<'_>) -> Option<String> {
    match value {
        Value::Num(n) => Some(number_text(*n)),
        Value::Str(s) => Some(s.clone()),
        _ => None,
    }
}

/// Equality of two values of the same primitive type, or of two orderings; values of
/// different types are not equal, and a new object (`val()`, a member of `auth`) equals
/// nothing. The official emulator compares two snapshots by location, and `auth` and
/// `query` each by identity; that is not reproduced, so such a comparison is an error and
/// the rule is false whether or not it is negated (review r9 M25, option (b)).
#[allow(clippy::float_cmp)]
fn equal(l: &Value<'_>, r: &Value<'_>) -> Option<bool> {
    Some(match (l, r) {
        (Value::Snapshot(_), Value::Snapshot(_))
        | (Value::Auth(_), Value::Auth(_))
        | (Value::Query, Value::Query) => return None,
        (Value::Null | Value::AuthEmpty, Value::Null | Value::AuthEmpty) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Num(a), Value::Num(b)) => a == b,
        (Value::Long(a), Value::Long(b)) => a == b,
        // A `Long` and a `Double` compare as doubles there.
        #[allow(clippy::cast_precision_loss)]
        (Value::Long(a), Value::Num(b)) | (Value::Num(b), Value::Long(a)) => *a as f64 == *b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Ordering(a), Value::Ordering(b)) => a == b,
        _ => false,
    })
}
