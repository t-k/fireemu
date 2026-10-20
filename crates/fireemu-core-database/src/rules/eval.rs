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
    /// An object or array from `auth` or `val()`.
    Json(Json),
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
        "auth" => Some(from_json(scope.auth)),
        #[allow(clippy::cast_precision_loss)]
        "now" => Some(Value::Num(scope.now as f64)),
        "root" => Some(Value::Snapshot(scope.root.clone())),
        "data" => Some(Value::Snapshot(scope.data.clone())),
        "newData" => scope.new_data.clone().map(Value::Snapshot),
        "query" => Some(Value::Query),
        _ => scope.wildcards.get(name).map(|key| Value::Str(key.clone())),
    }
}

fn member<'a>(object: Value<'a>, name: &str, scope: &Scope<'a>) -> Option<Value<'a>> {
    match object {
        Value::Json(Json::Object(map)) => Some(map.get(name).map_or(Value::Null, from_json)),
        // An array is an object keyed by its indexes: any other member is null.
        Value::Json(Json::Array(items)) => Some(
            name.parse::<usize>()
                .ok()
                .filter(|index| index.to_string() == name)
                .and_then(|index| items.get(index))
                .map_or(Value::Null, from_json),
        ),
        Value::Str(s) if name == "length" =>
        {
            #[allow(clippy::cast_precision_loss)]
            Some(Value::Num(s.encode_utf16().count() as f64))
        }
        Value::Query => Some(query_member(scope.query, name)),
        _ => None,
    }
}

fn bound_value<'a>(bound: Option<&Bound>) -> Value<'a> {
    bound.map_or(Value::Null, |b| from_json(&b.value))
}

/// A member of `query`. A read without a query is ordered by key. `startAt` is the start
/// bound, inclusive or not; `endAt` is an inclusive end bound only; `equalTo` is the start
/// value when an inclusive end bound has the same value.
fn query_member<'a>(query: Option<&QueryParams>, name: &str) -> Value<'a> {
    let Some(q) = query else {
        return match name {
            "orderByKey" => Value::Bool(true),
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
            OrderBy::Child(path) => Value::Str(path.keys().join("/")),
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
            Some(n) => Value::Json(n.to_json(crate::node::Format::Plain)),
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
        BinaryOp::Eq => Some(Value::Bool(equal(l, r))),
        BinaryOp::Ne => Some(Value::Bool(!equal(l, r))),
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            let ordering = match (l, r) {
                (Value::Num(a), Value::Num(b)) => a.partial_cmp(b)?,
                (Value::Str(a), Value::Str(b)) => a.encode_utf16().cmp(b.encode_utf16()),
                _ => return Some(Value::Bool(false)),
            };
            Some(Value::Bool(match op {
                BinaryOp::Lt => ordering.is_lt(),
                BinaryOp::Le => ordering.is_le(),
                BinaryOp::Gt => ordering.is_gt(),
                _ => ordering.is_ge(),
            }))
        }
        BinaryOp::Add => match (l, r) {
            (Value::Num(a), Value::Num(b)) => finite(a + b),
            (Value::Str(a), _) => Some(Value::Str(format!("{a}{}", text(r)?))),
            (_, Value::Str(b)) => Some(Value::Str(format!("{}{b}", text(l)?))),
            _ => None,
        },
        BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => {
            let (Value::Num(a), Value::Num(b)) = (l, r) else {
                return None;
            };
            finite(match op {
                BinaryOp::Sub => a - b,
                BinaryOp::Mul => a * b,
                BinaryOp::Div => a / b,
                _ => a % b,
            })
        }
        BinaryOp::And | BinaryOp::Or => None,
    }
}

fn finite<'a>(n: f64) -> Option<Value<'a>> {
    n.is_finite().then_some(Value::Num(n))
}

/// The text of a value added to a string: only numbers and strings have one.
fn text(value: &Value<'_>) -> Option<String> {
    match value {
        Value::Num(n) => Some(number_text(*n)),
        Value::Str(s) => Some(s.clone()),
        _ => None,
    }
}

/// Equality of two values of the same primitive type; values of different types are not
/// equal, and an object or snapshot equals nothing.
#[allow(clippy::float_cmp)]
fn equal(l: &Value<'_>, r: &Value<'_>) -> bool {
    match (l, r) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Num(a), Value::Num(b)) => a == b,
        (Value::Str(a), Value::Str(b)) => a == b,
        _ => false,
    }
}
