//! Running a checked rule expression. Any error at run time (a member of a non-object, a
//! comparison of different types, a division by zero) makes the rule false, as the
//! official emulator denies such a request.

use std::collections::BTreeMap;

use super::parse::{BinaryOp, Expr, ExprKind};
use crate::json::Json;
use crate::node::{Content, Leaf, Node, Priority};
use crate::path::Path;
use crate::query::{Bound, Limit, OrderBy, QueryParams};

/// A location in one version of the tree.
#[derive(Debug, Clone)]
pub struct Snapshot<'a> {
    /// The root of that version.
    pub root: Option<&'a Node>,
    /// The location.
    pub path: Path,
}

impl<'a> Snapshot<'a> {
    fn node(&self) -> Option<&'a Node> {
        self.root?.descendant(&self.path)
    }
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
        // An array is an object keyed by its indexes.
        Value::Json(Json::Array(items)) => Some(
            name.parse::<usize>()
                .ok()
                .filter(|index| index.to_string() == name)
                .and_then(|index| items.get(index))
                .map_or(Value::AuthEmpty, from_json),
        ),
        Value::Str(s) if name == "length" =>
        {
            #[allow(clippy::cast_precision_loss)]
            Some(Value::Num(s.encode_utf16().count() as f64))
        }
        Value::Query => Some(query_member(scope.query, scope.new_data.is_some(), name)),
        _ => None,
    }
}

fn bound_value<'a>(bound: Option<&Bound>) -> Value<'a> {
    match bound.map(|b| &b.value) {
        None => Value::Null,
        Some(Json::Number(crate::number::Number::Int(n))) => Value::Long(*n),
        Some(value) => from_json(value),
    }
}

/// A member of `query`. A read without a query is ordered by key; a write has no ordering at
/// all (review r9 M24: `orderByKey` is false in `.write` and `.validate` there). `startAt` is the start
/// bound, inclusive or not; `endAt` is an inclusive end bound only; `equalTo` is the start
/// value when an inclusive end bound has the same value.
fn query_member<'a>(query: Option<&QueryParams>, writing: bool, name: &str) -> Value<'a> {
    let Some(q) = query else {
        return match name {
            "orderByKey" => Value::Bool(!writing),
            "orderByValue" | "orderByPriority" => Value::Bool(false),
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
            "replace" => {
                let from = string_argument(arguments, 0)?;
                let to = string_argument(arguments, 1)?;
                if from.is_empty() {
                    return Some(Value::Str(s));
                }
                Some(Value::Str(s.replace(&from, &to)))
            }
            "toLowerCase" => Some(Value::Str(s.to_lowercase())),
            "toUpperCase" => Some(Value::Str(s.to_uppercase())),
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
    let node = snapshot.node();
    match name {
        "val" => Some(match node {
            None => Value::Null,
            Some(Node {
                content: Content::Leaf(leaf),
                ..
            }) => leaf_value(leaf),
            Some(_) => Value::Sentinel,
        }),
        "child" => {
            let child = string_argument(arguments, 0)?;
            let mut path = snapshot.path.clone();
            for key in child.split('/').filter(|k| !k.is_empty()) {
                path = path.child(key);
            }
            Some(Value::Snapshot(Snapshot {
                root: snapshot.root,
                path,
            }))
        }
        "parent" => snapshot.path.parent().map(|path| {
            Value::Snapshot(Snapshot {
                root: snapshot.root,
                path,
            })
        }),
        "exists" => Some(Value::Bool(node.is_some())),
        "hasChild" => {
            let child = string_argument(arguments, 0)?;
            let mut path = snapshot.path.clone();
            for key in child.split('/').filter(|k| !k.is_empty()) {
                path = path.child(key);
            }
            Some(Value::Bool(
                snapshot.root.and_then(|r| r.descendant(&path)).is_some(),
            ))
        }
        "hasChildren" => {
            // An empty list of names is true wherever the node is, as there (the r9 method
            // matrix).
            if matches!(arguments.first(), Some(Value::Array(keys)) if keys.is_empty()) {
                return Some(Value::Bool(true));
            }
            let Some(Node {
                content: Content::Children(children),
                ..
            }) = node
            else {
                return Some(Value::Bool(false));
            };
            match arguments.first() {
                None => Some(Value::Bool(true)),
                Some(Value::Array(keys)) => {
                    let mut all = true;
                    for key in keys {
                        let Value::Str(key) = key else { return None };
                        all &= children.contains_key(key.as_str());
                    }
                    Some(Value::Bool(all))
                }
                Some(_) => None,
            }
        }
        "getPriority" => Some(match node.and_then(|n| n.priority.as_ref()) {
            None => Value::Null,
            Some(Priority::Number(n)) => Value::Num(n.as_f64()),
            Some(Priority::String(s)) => Value::Str(s.clone()),
        }),
        "isNumber" | "isString" | "isBoolean" => Some(Value::Bool(matches!(
            (name, node.map(|n| &n.content)),
            ("isNumber", Some(Content::Leaf(Leaf::Number(_))))
                | ("isString", Some(Content::Leaf(Leaf::String(_))))
                | ("isBoolean", Some(Content::Leaf(Leaf::Bool(_))))
        ))),
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
