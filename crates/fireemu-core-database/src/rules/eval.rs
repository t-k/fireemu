//! Running a checked rule expression. Any error at run time (a member of a non-object, a
//! comparison of different types, a division by zero) makes the rule false, as the
//! official emulator denies such a request.

use std::collections::BTreeMap;

use super::coverage::Observer;
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
    /// Whether regular expressions are read in the official emulator's dialect (emulator profile).
    pub dialect: Dialect,
}

/// How the emulator profile reads what the official emulator reads differently from this engine's default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dialect {
    /// Regular expressions: `\W`, `\D` and escaped letters as the official emulator reads them.
    pub regex: bool,
    /// The strings of `auth` are written in the claims encoding of [`crate::lone`], and a lone surrogate in one
    /// reads as the Java string it is.
    pub claims: bool,
}

/// Which version of the tree a snapshot value reads: `root` and `data` read the tree before
/// the write, `newData` the tree after it. The official emulator compares two snapshots by
/// this version and their location (review r9 M25, option (a)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    Data,
    New,
}

#[derive(Debug, Clone)]
enum Value<'a> {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    /// A string that holds a lone surrogate, as the UTF-16 units Java holds it (a `String` cannot). A string
    /// whose units are valid UTF-16 is always a [`Value::Str`], so the two never hold the same string.
    Units(Vec<u16>),
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
    /// A snapshot, with the version of the tree it reads.
    Snapshot(Snapshot<'a>, Version),
    /// `query`, one object.
    Query,
    Regex(super::pattern::Pattern),
    Array(Vec<Value<'a>>),
}

/// Evaluates a whole rule: true only when it evaluates to `true`.
pub fn allows(expr: &Expr, scope: &Scope<'_>, observer: &mut Observer<'_>) -> bool {
    matches!(eval(expr, scope, observer), Some(Value::Bool(true)))
}

/// A JSON value as a Rules value. `claims` reads the strings of `auth` as the emulator profile writes
/// them (see [`crate::lone`]): a string that holds a lone surrogate is [`Value::Units`].
fn from_json<'a>(json: &Json, claims: bool) -> Value<'a> {
    match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => Value::Num(n.as_f64()),
        Json::String(s) if claims && crate::lone::is_encoded(s) => {
            from_units(crate::lone::decode(s))
        }
        Json::String(s) => Value::Str(s.clone()),
        other => Value::Json(other.clone()),
    }
}

/// The key of a member of `auth`: as the emulator profile's claims are written, or `None` for a name that
/// holds a lone surrogate and the claims cannot hold one (the strict profile).
fn claim_key(name: Option<&str>, units: Option<&[u16]>, claims: bool) -> Option<String> {
    match (name, units) {
        (Some(name), _) if claims => Some(crate::lone::escape(name)),
        (Some(name), _) => Some(name.to_owned()),
        (None, Some(units)) if claims => Some(crate::lone::encode(units)),
        _ => None,
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

fn eval<'a>(expr: &Expr, scope: &Scope<'a>, observer: &mut Observer<'_>) -> Option<Value<'a>> {
    let value = eval_inner(expr, scope, observer);
    if let Some(value) = &value {
        let variable = match &expr.kind {
            ExprKind::Name(name) => Some(name.as_str()),
            _ => None,
        };
        record_value(observer, expr.diagnostic, value, variable);
    }
    value
}

fn record_value(observer: &mut Observer<'_>, id: usize, value: &Value<'_>, variable: Option<&str>) {
    let diagnostic = match value {
        Value::Null | Value::AuthEmpty => Json::Null,
        Value::Bool(value) => Json::Bool(*value),
        Value::Num(value) => crate::number::Number::from_f64(*value)
            .map_or_else(|| Json::string(number_text(*value)), Json::Number),
        Value::Long(value) => Json::int(*value),
        Value::Str(value) => Json::String(value.clone()),
        Value::Units(units) => Json::String(String::from_utf16_lossy(units)),
        Value::Ordering(keys) => Json::String(keys.join("/")),
        _ => observer.opaque(variable),
    };
    observer.record(id, diagnostic);
}

fn eval_inner<'a>(
    expr: &Expr,
    scope: &Scope<'a>,
    observer: &mut Observer<'_>,
) -> Option<Value<'a>> {
    match &expr.kind {
        ExprKind::Bool(b) => Some(Value::Bool(*b)),
        ExprKind::Number(n) => Some(Value::Num(*n)),
        ExprKind::Str(s) => Some(Value::Str(s.clone())),
        ExprKind::Units(units) => Some(Value::Units(units.clone())),
        ExprKind::Null => Some(Value::Null),
        ExprKind::Ordering(keys) => Some(Value::Ordering(keys.clone())),
        ExprKind::Regex(pattern) => Some(Value::Regex(pattern.clone())),
        ExprKind::Array(items) => items
            .iter()
            .map(|item| eval(item, scope, observer))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        ExprKind::Name(name) => variable(name, scope),
        ExprKind::Member(object, name) => {
            let object = eval(object, scope, observer)?;
            observer.member_name(expr.diagnostic, name);
            let key = claim_key(Some(name), None, scope.dialect.claims);
            member(object, key.as_deref(), scope)
        }
        ExprKind::Index(object, index) => {
            let object = eval(object, scope, observer)?;
            // A key holding a lone surrogate names no member of anything (no stored or claimed
            // name can hold one), so it reads as an absent member, not an error.
            let key = match eval(index, scope, observer)? {
                Value::Str(s) => claim_key(Some(&s), None, scope.dialect.claims),
                Value::Num(n) => claim_key(Some(&number_text(n)), None, scope.dialect.claims),
                Value::Units(units) => claim_key(None, Some(&units), scope.dialect.claims),
                _ => return None,
            };
            member(object, key.as_deref(), scope)
        }
        ExprKind::Call(callee, arguments) => {
            let ExprKind::Member(object, name) = &callee.kind else {
                return None;
            };
            let object = eval(object, scope, observer)?;
            observer.member_name(callee.diagnostic, name);
            let callable = matches!(
                object,
                Value::Snapshot(..) | Value::Str(_) | Value::Units(_)
            );
            if callable {
                let method = observer.opaque(None);
                observer.record(callee.diagnostic, method);
            }
            // Authorization retains its original receiver/argument/call order. The local
            // diagnostic format resolves a missing callee before observing its arguments.
            if !callable {
                observer.suppressed += 1;
            }
            let arguments = arguments
                .iter()
                .map(|a| eval(a, scope, observer))
                .collect::<Option<Vec<_>>>();
            if !callable {
                observer.suppressed -= 1;
            }
            call(object, name, &arguments?, scope.dialect.regex)
        }
        ExprKind::Not(operand) => match eval(operand, scope, observer)? {
            Value::Bool(b) => Some(Value::Bool(!b)),
            _ => None,
        },
        ExprKind::Neg(operand) => match eval(operand, scope, observer)? {
            Value::Num(n) => Some(Value::Num(-n)),
            _ => None,
        },
        ExprKind::Binary(op, left, right) => binary(*op, left, right, scope, observer),
        ExprKind::Chain(op, operands) => chain(*op, operands, scope, observer, expr.diagnostic),
        ExprKind::Ternary(condition, then, otherwise) => match eval(condition, scope, observer)? {
            Value::Bool(true) => eval(then, scope, observer),
            Value::Bool(false) => eval(otherwise, scope, observer),
            _ => None,
        },
    }
}

fn variable<'a>(name: &str, scope: &Scope<'a>) -> Option<Value<'a>> {
    match name {
        "auth" => Some(match scope.auth {
            Json::Object(_) | Json::Array(_) => Value::Auth(scope.auth.clone()),
            Json::Null => Value::AuthEmpty,
            other => from_json(other, scope.dialect.claims),
        }),
        #[allow(clippy::cast_precision_loss)]
        "now" => Some(Value::Num(scope.now as f64)),
        "root" => Some(Value::Snapshot(scope.root.clone(), Version::Data)),
        "data" => Some(Value::Snapshot(scope.data.clone(), Version::Data)),
        "newData" => scope
            .new_data
            .clone()
            .map(|snapshot| Value::Snapshot(snapshot, Version::New)),
        "query" => Some(Value::Query),
        _ => scope.wildcards.get(name).map(|key| Value::Str(key.clone())),
    }
}

/// A member of `object`; `None` for a name that holds a lone surrogate, which no member bears.
/// Inside `auth` any member of an object or array, `length` included,
/// is its value, or the empty object when absent; the empty object's members are itself
/// (review r8 M23, the r10 ternary matrix). Anything else has only `length` of a string and
/// the members of `query`.
fn member<'a>(object: Value<'a>, name: Option<&str>, scope: &Scope<'a>) -> Option<Value<'a>> {
    let object = match object {
        Value::Auth(json) => Value::Json(json),
        other => other,
    };
    match object {
        Value::AuthEmpty => Some(Value::AuthEmpty),
        Value::Json(Json::Object(map)) => Some(
            name.and_then(|name| map.get(name))
                .map_or(Value::AuthEmpty, |json| {
                    from_json(json, scope.dialect.claims)
                }),
        ),
        // An array is an object keyed by its indexes, read as `Integer.parseInt` reads them
        // (review r10 M33).
        Value::Json(Json::Array(items)) => Some(
            name.and_then(java_int)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| items.get(index))
                .map_or(Value::AuthEmpty, |json| {
                    from_json(json, scope.dialect.claims)
                }),
        ),
        Value::Str(s) if name == Some("length") =>
        {
            #[allow(clippy::cast_precision_loss)]
            Some(Value::Num(s.encode_utf16().count() as f64))
        }
        Value::Units(units) if name == Some("length") =>
        {
            #[allow(clippy::cast_precision_loss)]
            Some(Value::Num(units.len() as f64))
        }
        Value::Query => Some(query_member(
            scope.query,
            scope.read_kind,
            name.unwrap_or_default(),
        )),
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

/// Code points whose case Java 21 maps otherwise than Rust's newer Unicode tables, over every
/// plane (the r11 JVM case-map comparison and review r11 M41). A case change of a string
/// holding one is an error, so the rule is false.
const CASE_DIFFERS: [(char, char); 10] = [
    ('\u{019B}', '\u{019B}'),
    ('\u{0264}', '\u{0264}'),
    ('\u{1C89}', '\u{1C8A}'),
    ('\u{A7CB}', '\u{A7CF}'),
    ('\u{A7D2}', '\u{A7D5}'),
    ('\u{A7DA}', '\u{A7DC}'),
    ('\u{10D50}', '\u{10D65}'),
    ('\u{10D70}', '\u{10D85}'),
    ('\u{16EA0}', '\u{16EB8}'),
    ('\u{16EBB}', '\u{16ED3}'),
];

/// `s.toLowerCase()` or `s.toUpperCase()` as Java 21 gives it. Java 21 makes `Σ` the final
/// `ς` by its word-break iterator, and Rust by skipping case-ignorable characters; the two
/// agree when each neighbour of the `Σ` is a [`plain_sigma_neighbour`], and a lowercase with
/// any other `Σ` is an error (review r11 M41).
pub(crate) fn java_case(s: &str, lower: bool) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let ambiguous_sigma = |i: usize| {
        chars[i] == '\u{03A3}'
            && !(plain_sigma_neighbour(i.checked_sub(1).map(|p| chars[p]))
                && plain_sigma_neighbour(chars.get(i + 1).copied()))
    };
    if chars
        .iter()
        .any(|&c| CASE_DIFFERS.iter().any(|&(lo, hi)| (lo..=hi).contains(&c)))
        || (lower && (0..chars.len()).any(ambiguous_sigma))
    {
        return None;
    }
    Some(if lower {
        s.to_lowercase()
    } else {
        s.to_uppercase()
    })
}

/// A neighbour of `Σ` both Java 21 and Rust read alike: the string's edge, an ASCII space, or
/// a Latin, Greek or Cyrillic letter that changes case (so cased, and a word character).
fn plain_sigma_neighbour(c: Option<char>) -> bool {
    let Some(c) = c else {
        return true;
    };
    let letter_block = matches!(
        c,
        'A'..='Z' | 'a'..='z' | '\u{00C0}'..='\u{024F}' | '\u{0370}'..='\u{04FF}'
    );
    c == ' '
        || (letter_block
            && c.is_alphabetic()
            && (c.to_lowercase().ne(std::iter::once(c)) || c.to_uppercase().ne(std::iter::once(c))))
}

/// The longest string a Rules operation (`replace`, `+`) may build, in UTF-16 units (bytes for
/// a [`Value::Str`], which is never fewer). The operation is checked before it allocates, and
/// past the bound it is an error, so the rule is false negated or not. A chain of ten
/// `replace('', '0123456789')` would otherwise grow 11 times per step to about 5e10 units
/// from a rule an anonymous read evaluates. The official emulator's heap decides its own limit:
/// at 512 MB it answers seven such steps (3.9e7 units) and fails the eighth (4.3e8) with a 500,
/// negated or not. 2^26 lies between, and is above the largest stored string (10 MiB) grown
/// threefold by a case change.
pub(crate) const MAX_STRING_UNITS: usize = 1 << 26;

/// `s.replace(from, to)` as Java gives it: an empty `from` puts `to` before every UTF-16 unit
/// and at the end. The caller sends a string with a character beyond the Basic Multilingual
/// Plane through [`units_call`], since the replacement splits its pair. `None` past
/// [`MAX_STRING_UNITS`], before any allocation.
fn java_replace(s: &str, from: &str, to: &str) -> Option<String> {
    if !from.is_empty() {
        let found = s.matches(from).count();
        let grown = found.checked_mul(to.len())?.checked_add(s.len())?;
        if grown.saturating_sub(found.checked_mul(from.len())?) > MAX_STRING_UNITS {
            return None;
        }
        return Some(s.replace(from, to));
    }
    debug_assert!(s.chars().all(|c| u32::from(c) <= 0xFFFF));
    let pieces = s.chars().count().checked_add(1)?;
    if pieces.checked_mul(to.len())?.checked_add(s.len())? > MAX_STRING_UNITS {
        return None;
    }
    let mut out = String::with_capacity(s.len() + to.len() * pieces);
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
        Some(value) => from_json(value, false),
    }
}

/// `query.orderBy` on a read that does not order by a child: an ordering no path names (`$` is
/// no key), so it equals only itself. In a write, a validation or a shallow read it is null, as
/// the official emulator answers (`query.orderBy != null` is false in those).
fn order_by_marker<'a>(kind: ReadKind) -> Value<'a> {
    if kind == ReadKind::Check {
        Value::Null
    } else {
        Value::Ordering(vec!["$".to_owned()])
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
            "orderBy" => order_by_marker(kind),
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
        // The same ordering as `orderByChild` when the query orders by a child. Otherwise a
        // value that is not null and equals nothing but itself (the official emulator answers
        // `query.orderBy == null` false and `query.orderBy == query.orderBy` true on a read
        // ordered by key, by value or by priority).
        "orderBy" => match &q.order_by {
            OrderBy::Child(path) => Value::Ordering(path.keys().to_vec()),
            _ => order_by_marker(kind),
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

/// A path or key argument as text. A lone surrogate is written `$` and its four hex digits: no
/// stored key holds a `$`, so a path with one names nothing, as in the official emulator.
fn path_argument(arguments: &[Value<'_>], i: usize) -> Option<String> {
    path_text(arguments.get(i)?)
}

fn path_text(value: &Value<'_>) -> Option<String> {
    match value {
        Value::Str(s) => Some(s.clone()),
        Value::Units(units) => Some(
            char::decode_utf16(units.iter().copied())
                .map(|decoded| match decoded {
                    Ok(c) => c.to_string(),
                    Err(lone) => format!("${:04X}", lone.unpaired_surrogate()),
                })
                .collect(),
        ),
        _ => None,
    }
}

fn string_argument(arguments: &[Value<'_>], i: usize) -> Option<String> {
    match arguments.get(i)? {
        Value::Str(s) => Some(s.clone()),
        _ => None,
    }
}

fn call<'a>(
    object: Value<'a>,
    name: &str,
    arguments: &[Value<'a>],
    jar_regex: bool,
) -> Option<Value<'a>> {
    match object {
        Value::Snapshot(snapshot, version) => snapshot_call(&snapshot, version, name, arguments),
        Value::Str(s) if arguments.iter().any(|a| matches!(a, Value::Units(_))) => units_call(
            &s.encode_utf16().collect::<Vec<_>>(),
            name,
            arguments,
            jar_regex,
        ),
        Value::Units(units) => units_call(&units, name, arguments, jar_regex),
        Value::Str(s) => match name {
            "contains" => Some(Value::Bool(s.contains(&string_argument(arguments, 0)?))),
            "beginsWith" => Some(Value::Bool(s.starts_with(&string_argument(arguments, 0)?))),
            "endsWith" => Some(Value::Bool(s.ends_with(&string_argument(arguments, 0)?))),
            "replace" => {
                let (from, to) = (
                    string_argument(arguments, 0)?,
                    string_argument(arguments, 1)?,
                );
                if from.is_empty() && s.chars().any(|c| c.len_utf16() == 2) {
                    // Java puts the replacement between the halves of a pair.
                    return units_call(
                        &s.encode_utf16().collect::<Vec<_>>(),
                        name,
                        arguments,
                        jar_regex,
                    );
                }
                java_replace(&s, &from, &to).map(Value::Str)
            }
            "toLowerCase" => java_case(&s, true).map(Value::Str),
            "toUpperCase" => java_case(&s, false).map(Value::Str),
            "matches" => match arguments.first()? {
                Value::Regex(pattern) => pattern.matches(&s, jar_regex).map(Value::Bool),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// The UTF-16 units of a string value.
fn units_of(value: &Value<'_>) -> Option<Vec<u16>> {
    match value {
        Value::Str(s) => Some(s.encode_utf16().collect()),
        Value::Units(units) => Some(units.clone()),
        _ => None,
    }
}

/// A string value from UTF-16 units: a [`Value::Str`] when they are valid UTF-16, so a pair written as two
/// escapes is the same string as the character.
fn from_units<'a>(units: Vec<u16>) -> Value<'a> {
    String::from_utf16(&units).map_or_else(|_| Value::Units(units), Value::Str)
}

/// Where `needle` starts in `haystack`, as Java's `String.indexOf` reads UTF-16 units.
fn find_units(haystack: &[u16], needle: &[u16]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The string methods on a string that holds a lone surrogate, or whose argument does, read by UTF-16
/// unit as Java reads them. A method not listed here is an error, so the rule is false negated or not.
fn units_call<'a>(
    units: &[u16],
    name: &str,
    arguments: &[Value<'a>],
    jar_regex: bool,
) -> Option<Value<'a>> {
    let argument = |i: usize| arguments.get(i).and_then(units_of);
    match name {
        "contains" => Some(Value::Bool(find_units(units, &argument(0)?).is_some())),
        "beginsWith" => Some(Value::Bool(units.starts_with(&argument(0)?))),
        "endsWith" => Some(Value::Bool(units.ends_with(&argument(0)?))),
        "replace" => {
            let (from, to) = (argument(0)?, argument(1)?);
            if from.is_empty() {
                let pieces = units.len().checked_add(1)?;
                if pieces.checked_mul(to.len())?.checked_add(units.len())? > MAX_STRING_UNITS {
                    return None;
                }
                // Java puts the replacement before every unit and after the last, even between the halves of a pair.
                let mut out = to.clone();
                for unit in units {
                    out.push(*unit);
                    out.extend_from_slice(&to);
                }
                return Some(from_units(out));
            }
            let mut out = Vec::with_capacity(units.len());
            let mut rest = units;
            while let Some(at) = find_units(rest, &from) {
                if out.len() + at + to.len() > MAX_STRING_UNITS {
                    return None;
                }
                out.extend_from_slice(&rest[..at]);
                out.extend_from_slice(&to);
                rest = &rest[at + from.len()..];
            }
            if out.len() + rest.len() > MAX_STRING_UNITS {
                return None;
            }
            out.extend_from_slice(rest);
            Some(from_units(out))
        }
        "toLowerCase" | "toUpperCase" => {
            let lower = name == "toLowerCase";
            let mut out = Vec::with_capacity(units.len());
            let mut run = String::new();
            for decoded in char::decode_utf16(units.iter().copied()) {
                match decoded {
                    Ok(c) => run.push(c),
                    Err(lone) => {
                        out.extend(java_case(&std::mem::take(&mut run), lower)?.encode_utf16());
                        out.push(lone.unpaired_surrogate());
                    }
                }
            }
            out.extend(java_case(&run, lower)?.encode_utf16());
            Some(from_units(out))
        }
        "matches" => match arguments.first()? {
            Value::Regex(pattern) => pattern.matches_units(units, jar_regex).map(Value::Bool),
            _ => None,
        },
        _ => None,
    }
}

fn snapshot_call<'a>(
    snapshot: &Snapshot<'a>,
    version: Version,
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
            snapshot.child(&path_argument(arguments, 0)?),
            version,
        )),
        "parent" => snapshot.path.parent().map(|path| {
            Value::Snapshot(
                Snapshot {
                    root: snapshot.root,
                    path,
                },
                version,
            )
        }),
        "exists" => Some(Value::Bool(!matches!(located, Located::Absent))),
        "hasChild" => Some(Value::Bool(!matches!(
            snapshot.child(&path_argument(arguments, 0)?).locate(),
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
                let key = path_text(key)?;
                if matches!(snapshot.child(&key).locate(), Located::Absent) {
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
fn binary<'a>(
    op: BinaryOp,
    left: &Expr,
    right: &Expr,
    scope: &Scope<'a>,
    observer: &mut Observer<'_>,
) -> Option<Value<'a>> {
    let l = eval(left, scope, observer)?;
    let r = eval(right, scope, observer)?;
    combine(op, &l, &r)
}

/// A chain of `&&`, `||` or `+`, read left to right as the nested operators it stands for:
/// `&&` and `||` stop at the first operand that decides.
fn chain<'a>(
    op: BinaryOp,
    operands: &[Expr],
    scope: &Scope<'a>,
    observer: &mut Observer<'_>,
    diagnostic: usize,
) -> Option<Value<'a>> {
    let (first, rest) = operands.split_first()?;
    if matches!(op, BinaryOp::And | BinaryOp::Or) {
        let Value::Bool(mut value) = eval(first, scope, observer)? else {
            return None;
        };
        let prefixes = observer.prefixes(diagnostic, operands.len());
        for (index, operand) in rest.iter().enumerate() {
            if !((op == BinaryOp::And && !value) || (op == BinaryOp::Or && value)) {
                let Value::Bool(next) = eval(operand, scope, observer)? else {
                    return None;
                };
                value = next;
            }
            if prefixes[index] != diagnostic {
                observer.record(prefixes[index], Json::Bool(value));
            }
        }
        return Some(Value::Bool(value));
    }
    let mut value = eval(first, scope, observer)?;
    let prefixes = observer.prefixes(diagnostic, operands.len());
    for (index, operand) in rest.iter().enumerate() {
        value = combine(op, &value, &eval(operand, scope, observer)?)?;
        if prefixes[index] != diagnostic {
            record_value(observer, prefixes[index], &value, None);
        }
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
                // Any comparison with NaN is false there.
                (Value::Num(a), Value::Num(b)) => match a.partial_cmp(b) {
                    Some(ordering) => ordering,
                    None => return Some(Value::Bool(false)),
                },
                (Value::Str(a), Value::Str(b)) => a.encode_utf16().cmp(b.encode_utf16()),
                (Value::Str(_) | Value::Units(_), Value::Str(_) | Value::Units(_)) => {
                    units_of(l)?.cmp(&units_of(r)?)
                }
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
            (Value::Units(_), _) | (_, Value::Units(_)) => {
                let mut units = units_text(l)?;
                let right = units_text(r)?;
                if units.len() + right.len() > MAX_STRING_UNITS {
                    return None;
                }
                units.extend(right);
                Some(from_units(units))
            }
            (Value::Str(a), _) => {
                let right = text(r)?;
                (a.len() + right.len() <= MAX_STRING_UNITS)
                    .then(|| Value::Str(format!("{a}{right}")))
            }
            (_, Value::Str(b)) => {
                let left = text(l)?;
                (left.len() + b.len() <= MAX_STRING_UNITS).then(|| Value::Str(format!("{left}{b}")))
            }
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

/// [`text`] as UTF-16 units, for a sum that holds a string with a lone surrogate.
fn units_text(value: &Value<'_>) -> Option<Vec<u16>> {
    match value {
        Value::Num(n) => Some(number_text(*n).encode_utf16().collect()),
        other => units_of(other),
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

/// Primitive values and orderings compare by value, and values of different types are
/// unequal. New objects from `val()` or an `auth` member equal nothing. Objects compare by
/// identity, as the official emulator compares them (review r9 M25, option (a)): `auth` and
/// `query` are one object each in a scope, and two snapshots are equal when they read the
/// same version of the tree at the same location.
#[allow(clippy::float_cmp)]
fn equal(l: &Value<'_>, r: &Value<'_>) -> bool {
    match (l, r) {
        (Value::Snapshot(a, a_version), Value::Snapshot(b, b_version)) => {
            a_version == b_version && a.path == b.path
        }
        // Every root auth value in one evaluation comes from the same scope.
        (Value::Auth(_), Value::Auth(_))
        | (Value::Query, Value::Query)
        | (Value::Null | Value::AuthEmpty, Value::Null | Value::AuthEmpty) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Num(a), Value::Num(b)) => a == b,
        (Value::Long(a), Value::Long(b)) => a == b,
        // A `Long` and a `Double` compare as doubles there.
        #[allow(clippy::cast_precision_loss)]
        (Value::Long(a), Value::Num(b)) | (Value::Num(b), Value::Long(a)) => *a as f64 == *b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Units(a), Value::Units(b)) => a == b,
        (Value::Ordering(a), Value::Ordering(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;

    const MAX: usize = MAX_STRING_UNITS;

    fn units(len: usize) -> Vec<u16> {
        vec![0x61; len]
    }

    fn length(value: &Value<'_>) -> Option<usize> {
        match value {
            Value::Str(s) => Some(s.len()),
            Value::Units(u) => Some(u.len()),
            _ => None,
        }
    }

    /// The bound is on the string built: exactly the bound is built, one more is an error, and a
    /// replacement that shrinks the string is never held up by what it started from.
    #[test]
    fn replacing_in_a_str_stops_one_past_the_bound() {
        let at = "a".repeat(MAX / 2);
        assert_eq!(java_replace(&at, "a", "bb").map(|s| s.len()), Some(MAX));
        let past = "a".repeat(MAX / 2 + 1);
        assert_eq!(java_replace(&past, "a", "bb"), None);
        // No match: the string is returned whole, up to the bound.
        let whole = "a".repeat(MAX);
        assert_eq!(java_replace(&whole, "z", "yy").map(|s| s.len()), Some(MAX));
        let over = "a".repeat(MAX + 1);
        assert_eq!(java_replace(&over, "z", "y"), None);
        // A shrinking replacement of a string made of its target.
        let shrinking = "aa".repeat(MAX / 2);
        assert_eq!(
            java_replace(&shrinking, "aa", "b").map(|s| s.len()),
            Some(MAX / 2)
        );
        // An empty target: `to` before each character and after the last.
        assert_eq!(
            java_replace("", "", &"x".repeat(MAX)).map(|s| s.len()),
            Some(MAX)
        );
        assert_eq!(java_replace("", "", &"x".repeat(MAX + 1)), None);
        // `to` before each of four characters and after the last: 5 x 13421772 + 4 is the bound.
        let each = MAX / 5;
        assert_eq!(
            java_replace("abcd", "", &"x".repeat(each)).map(|s| s.len()),
            Some(MAX)
        );
        assert_eq!(java_replace("abcd", "", &"x".repeat(each + 1)), None);
    }

    #[test]
    fn replacing_in_units_stops_one_past_the_bound() {
        let call = |haystack: &[u16], from: &[u16], to: &[u16]| {
            units_call(
                haystack,
                "replace",
                &[Value::Units(from.to_vec()), Value::Units(to.to_vec())],
                false,
            )
        };
        let lone = [0xD83D_u16];
        let at = call(&units(MAX / 2), &[0x61], &[0x62, 0x62]).unwrap();
        assert_eq!(length(&at), Some(MAX));
        assert!(call(&units(MAX / 2 + 1), &[0x61], &[0x62, 0x62]).is_none());
        // No match.
        assert_eq!(
            length(&call(&units(MAX), &lone, &[0x62]).unwrap()),
            Some(MAX)
        );
        assert!(call(&units(MAX + 1), &lone, &[0x62]).is_none());
        // A match late in a string that fits: the text before it counts.
        let mut late = units(MAX - 1);
        late.push(0xD83D);
        assert_eq!(length(&call(&late, &lone, &[0x62]).unwrap()), Some(MAX));
        assert!(call(&late, &lone, &[0x62, 0x62]).is_none());
        // An empty target.
        assert_eq!(length(&call(&[], &[], &units(MAX)).unwrap()), Some(MAX));
        assert!(call(&[], &[], &units(MAX + 1)).is_none());
        assert_eq!(
            length(&call(&units(4), &[], &units(MAX / 5)).unwrap()),
            Some(MAX)
        );
        assert!(call(&units(4), &[], &units(MAX / 5 + 1)).is_none());
    }

    #[test]
    fn adding_strings_stops_one_past_the_bound() {
        let add = |l: Value<'static>, r: Value<'static>| combine(BinaryOp::Add, &l, &r);
        let half = |extra: usize| -> Value<'static> { Value::Str("a".repeat(MAX / 2 + extra)) };
        assert_eq!(add(half(0), half(0)).as_ref().and_then(length), Some(MAX));
        assert!(add(half(0), half(1)).is_none());
        assert!(add(half(1), half(0)).is_none());
        let half_units = |extra: usize| -> Value<'static> { Value::Units(units(MAX / 2 + extra)) };
        assert_eq!(
            add(half_units(0), half_units(0)).as_ref().and_then(length),
            Some(MAX)
        );
        assert!(add(half_units(0), half_units(1)).is_none());
        assert!(add(half_units(1), half_units(0)).is_none());
        assert!(add(Value::Units(units(MAX)), Value::Num(1.0)).is_none());
        // A number joins a string on either side: its text counts.
        let full = |len: usize| -> Value<'static> { Value::Str("a".repeat(len)) };
        assert_eq!(
            add(Value::Num(1.0), full(MAX - 1))
                .as_ref()
                .and_then(length),
            Some(MAX)
        );
        assert!(add(Value::Num(1.0), full(MAX)).is_none());
        assert_eq!(
            add(full(MAX - 1), Value::Num(1.0))
                .as_ref()
                .and_then(length),
            Some(MAX)
        );
        assert!(add(full(MAX), Value::Num(1.0)).is_none());
    }
}
