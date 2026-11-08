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

    /// The snapshot `path` below this one: its keys, empty ones dropped. The location is built once, so its cost is
    /// the bytes of the keys of this location (copied) and of `path` (charged before anything is copied), not their
    /// product; `None` past the evaluation's budget.
    fn child(&self, path: &str, work: &std::cell::Cell<u64>) -> Option<Self> {
        charge(work, self.path_cost().saturating_add(path.len()))?;
        let mut keys: Vec<String> = Vec::with_capacity(self.path.depth() + 1);
        keys.extend(self.path.keys().iter().cloned());
        keys.extend(path.split('/').filter(|k| !k.is_empty()).map(str::to_owned));
        Some(Self {
            root: self.root,
            path: Path::from_keys(keys),
        })
    }

    /// What copying this location costs: its keys' bytes, and one unit for each key.
    fn path_cost(&self) -> usize {
        self.path.byte_len().saturating_add(self.path.depth())
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
    /// How the emulator profile reads what the official emulator reads differently.
    pub dialect: Dialect,
    /// The work this evaluation has done so far, in units of text processed (see [`MAX_EVALUATION_WORK`]).
    pub work: std::cell::Cell<u64>,
}

/// How the emulator profile reads what the official emulator reads differently from this engine's default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dialect {
    /// Regular expressions: `\W`, `\D` and escaped letters as the official emulator reads them.
    pub regex: bool,
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
    /// `http`, one object: its one member is `encodeURL`.
    Http,
    /// A method read without a call (`auth.uid.contains`, `data.child`): its receiver and its name. It is no
    /// null and equals nothing, and a call through it (`(c ? data.child : data.parent)('a')`) calls it.
    Method(Box<Value<'a>>, &'static str),
    Regex(super::pattern::Pattern),
    Array(Vec<Value<'a>>),
}

/// Evaluates a whole rule: true only when it evaluates to `true`.
pub fn allows(expr: &Expr, scope: &Scope<'_>, observer: &mut Observer<'_>) -> bool {
    let allowed = matches!(eval(expr, scope, observer), Some(Value::Bool(true)));
    HIGH_WATER.with(|high| high.set(high.get().max(scope.work.get())));
    allowed
}

/// The most work one evaluation of one rule may do, in units: every string a rule reads from the data or the claims,
/// joins, compares, searches, converts or replaces is charged by its length (a search by the lengths of both
/// strings, itself linear), every copy of the claims or of a nested value by its size, and the building of a location
/// by its keys. Past it the rule is an error, so it denies, negated or not. The bound is 2^30, chosen on purpose: a
/// stored string is at most 10 MiB, and reading it with `val()` and searching it with `contains` is two passes of 10
/// MiB (20 MiB), so a rule can do that about fifty times (thirteen such checks, the case a review named, use a quarter
/// of the bound and are allowed). The Rules corpora (22k rows) and the rules of the tests use a few dozen units. The
/// bound stops what the size bound alone does not: a long string compared, searched or joined again and again, each
/// time below the size bound, and a path or an `auth` copied again and again.
///
/// The matcher of a regular expression is bounded on its own: at most 200,000 steps and 32 levels of nesting for each
/// `matches` call (`fireemu_core_rules::regex`), an error past either. The subject is charged by its length here as
/// for any string method; the pattern, a literal of the rules document, is not (its size is the document's).
///
/// The bound is per evaluation: one request can run many (a write validates each child it writes), and nothing here is
/// a wall-clock limit. Thirteen searches of a 10 MiB string fit; about fifty-two of them do not.
pub(crate) const MAX_EVALUATION_WORK: u64 = 1 << 30;

thread_local! {
    static HIGH_WATER: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The most work any one rule evaluation has done on this thread since the last
/// [`reset_evaluation_work_high_water`]. For the tests that show ordinary rules stay far below the bound.
#[doc(hidden)]
pub fn evaluation_work_high_water() -> u64 {
    HIGH_WATER.with(std::cell::Cell::get)
}

/// Resets [`evaluation_work_high_water`].
#[doc(hidden)]
pub fn reset_evaluation_work_high_water() {
    HIGH_WATER.with(|high| high.set(0));
}

/// The evaluation's context for the string operations: the regex dialect and the work counter.
#[derive(Clone, Copy)]
struct Ctx<'c> {
    regex: bool,
    work: &'c std::cell::Cell<u64>,
    /// The query and read kind, for `query.isOrderByChild()`.
    query: Option<&'c QueryParams>,
    read_kind: ReadKind,
}

/// Charges `amount` units of work; `None` (an error) past [`MAX_EVALUATION_WORK`].
fn charge(work: &std::cell::Cell<u64>, amount: usize) -> Option<()> {
    let total = work.get().checked_add(u64::try_from(amount).ok()?)?;
    if total > MAX_EVALUATION_WORK {
        return None;
    }
    work.set(total);
    Some(())
}

/// The length of a string value (bytes for a `Str`, units for `Units`), 0 for any other.
fn text_len(value: &Value<'_>) -> usize {
    match value {
        Value::Str(s) => s.len(),
        Value::Units(u) => u.len(),
        _ => 0,
    }
}

/// A JSON value as a Rules value; a string or a nested value is copied, and that copy is work by its size.
fn from_json<'a>(json: &Json, work: &std::cell::Cell<u64>) -> Option<Value<'a>> {
    charge(work, json_cost(json))?;
    Some(from_json_uncharged(json))
}

fn from_json_uncharged<'a>(json: &Json) -> Value<'a> {
    match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => Value::Num(n.as_f64()),
        Json::String(s) => Value::Str(s.clone()),
        other => Value::Json(other.clone()),
    }
}

/// What copying `json` costs, in units: one for each value and the bytes of each string and name. Counted without
/// recursion, so a deep document costs no stack.
fn json_cost(json: &Json) -> usize {
    let mut cost = 0_usize;
    let mut pending = vec![json];
    while let Some(value) = pending.pop() {
        cost = cost.saturating_add(1);
        match value {
            Json::String(s) => cost = cost.saturating_add(s.len()),
            Json::Array(items) => pending.extend(items),
            Json::Object(members) => {
                for (name, member) in members {
                    cost = cost.saturating_add(name.len());
                    pending.push(member);
                }
            }
            _ => {}
        }
    }
    cost
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
            member(object, Some(name), scope)
        }
        ExprKind::Index(object, index) => {
            let object = eval(object, scope, observer)?;
            // A key holding a lone surrogate names no member of anything (no stored or claimed
            // name can hold one), so it reads as an absent member, not an error.
            let key = match eval(index, scope, observer)? {
                Value::Str(s) => Some(s),
                Value::Num(n) => Some(number_text(n)),
                Value::Units(_) => None,
                _ => return None,
            };
            member(object, key.as_deref(), scope)
        }
        ExprKind::Call(callee, arguments) => {
            let ctx = Ctx {
                regex: scope.dialect.regex,
                work: &scope.work,
                query: scope.query,
                read_kind: scope.read_kind,
            };
            let ExprKind::Member(object, name) = &callee.kind else {
                // Any other callee is called when it evaluates to a method (a ternary of methods,
                // a parenthesised member), with the arguments that method takes.
                let Value::Method(receiver, name) = eval(callee, scope, observer)? else {
                    return None;
                };
                let arguments = arguments
                    .iter()
                    .map(|a| eval(a, scope, observer))
                    .collect::<Option<Vec<_>>>()?;
                if !takes_arguments(name, arguments.len()) {
                    return None;
                }
                return call(*receiver, name, &arguments, ctx);
            };
            let object = eval(object, scope, observer)?;
            observer.member_name(callee.diagnostic, name);
            let callable = matches!(
                object,
                Value::Snapshot(..) | Value::Str(_) | Value::Units(_) | Value::Query | Value::Http
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
            call(object, name, &arguments?, ctx)
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
            Json::Object(_) | Json::Array(_) => {
                // The claims are copied for each use of `auth`: that is work, by their size.
                charge(&scope.work, json_cost(scope.auth))?;
                Value::Auth(scope.auth.clone())
            }
            Json::Null => Value::AuthEmpty,
            other => from_json(other, &scope.work)?,
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
        "http" => Some(Value::Http),
        "OrderByKey" => Some(Value::Ordering(vec![ORDER_BY_KEY.to_owned()])),
        "OrderByValue" => Some(Value::Ordering(vec![ORDER_BY_VALUE.to_owned()])),
        "OrderByPriority" => Some(Value::Ordering(vec![PRIORITY_KEY.to_owned()])),
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
        Value::Json(Json::Object(map)) => Some(match name.and_then(|name| map.get(name)) {
            Some(json) => from_json(json, &scope.work)?,
            None => Value::AuthEmpty,
        }),
        // An array is an object keyed by its indexes, read as `Integer.parseInt` reads them
        // (review r10 M33).
        Value::Json(Json::Array(items)) => Some(
            match name
                .and_then(java_int)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| items.get(index))
            {
                Some(json) => from_json(json, &scope.work)?,
                None => Value::AuthEmpty,
            },
        ),
        Value::Str(s) if name == Some("length") => {
            charge(&scope.work, s.len())?;
            #[allow(clippy::cast_precision_loss)]
            Some(Value::Num(s.encode_utf16().count() as f64))
        }
        Value::Units(units) if name == Some("length") =>
        {
            #[allow(clippy::cast_precision_loss)]
            Some(Value::Num(units.len() as f64))
        }
        Value::Str(_) | Value::Units(_) => method(object, name, &super::check::STRING_METHODS),
        Value::Snapshot(..) => method(object, name, &super::check::SNAPSHOT_METHODS),
        Value::Query if name == Some("isOrderByChild") => method(object, name, &["isOrderByChild"]),
        Value::Http => method(object, name, &["encodeURL"]),
        Value::Query => query_member(
            scope.query,
            scope.read_kind,
            name.unwrap_or_default(),
            &scope.work,
        ),
        _ => None,
    }
}

/// The method `name` of `object` read without a call, when `object` has one of that name.
fn method<'a>(object: Value<'a>, name: Option<&str>, names: &[&'static str]) -> Option<Value<'a>> {
    let name = names.iter().copied().find(|known| Some(*known) == name)?;
    Some(Value::Method(Box::new(object), name))
}

/// Whether a method called through a value (`(c ? data.child : data.parent)(x)`) takes `n`
/// arguments: the load checked the first method of the callee's type only, and the official
/// emulator fails a call with another count (an internal error there, a denial here).
fn takes_arguments(name: &str, n: usize) -> bool {
    match name {
        "replace" => n == 2,
        "hasChildren" => n <= 1,
        "val" | "parent" | "exists" | "getPriority" | "isNumber" | "isString" | "isBoolean"
        | "toLowerCase" | "toUpperCase" => n == 0,
        _ => n == 1,
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
    java_case_within(s, lower, MAX_STRING_UNITS, char::len_utf8)
}

/// [`java_case`] for a result of at most `room` (counted with `width` per character); the result is measured
/// before it is allocated, since a character can grow (`ﬃ` is `FFI`), and `None` past `room`.
fn java_case_within(s: &str, lower: bool, room: usize, width: fn(char) -> usize) -> Option<String> {
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
    let mut size = 0_usize;
    for &c in &chars {
        let mapped: usize = if lower {
            c.to_lowercase().map(width).sum()
        } else {
            c.to_uppercase().map(width).sum()
        };
        size = size.checked_add(mapped)?;
        if size > room {
            return None;
        }
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
        Some(value) => from_json_uncharged(value),
    }
}

/// The ordering `OrderByKey` names: no path names it (`$` starts no key).
const ORDER_BY_KEY: &str = "$key";
/// The ordering `OrderByValue` names.
const ORDER_BY_VALUE: &str = "$value";

/// The ordering of a query that orders by key, by value or by priority, as `query.orderBy`
/// gives it and `OrderByKey`, `OrderByValue` and `OrderByPriority` name it. An ordering by
/// priority is the ordering by the child `.priority` (`query.orderBy == '.priority'` and
/// `query.isOrderByChild('.priority')` hold there, recorded on the official emulator).
fn ordering_of<'a>(order_by: &OrderBy) -> Value<'a> {
    Value::Ordering(vec![match order_by {
        OrderBy::Key => ORDER_BY_KEY,
        OrderBy::Value => ORDER_BY_VALUE,
        _ => PRIORITY_KEY,
    }
    .to_owned()])
}

/// `query.orderBy` on a read without a query: ordered by key for a REST `GET` and by priority
/// for a stream or a realtime read. In a write, a validation or a shallow read it is null, as
/// production and the official emulator answer (`query.orderBy != null` is false in those).
fn order_by_marker<'a>(kind: ReadKind) -> Value<'a> {
    match kind {
        ReadKind::Check => Value::Null,
        ReadKind::Get => ordering_of(&OrderBy::Key),
        ReadKind::Stream => ordering_of(&OrderBy::Priority),
    }
}

/// A member of `query`. A read without a query is ordered as its [`ReadKind`] says. `startAt` is the start
/// bound, inclusive or not; `endAt` is an inclusive end bound only; `equalTo` is the start
/// value when an inclusive end bound has the same value.
fn query_member<'a>(
    query: Option<&QueryParams>,
    kind: ReadKind,
    name: &str,
    work: &std::cell::Cell<u64>,
) -> Option<Value<'a>> {
    let Some(q) = query else {
        return Some(match name {
            "orderByKey" => Value::Bool(kind == ReadKind::Get),
            "orderByPriority" => Value::Bool(kind == ReadKind::Stream),
            "orderByValue" => Value::Bool(false),
            "orderBy" => order_by_marker(kind),
            _ => Value::Null,
        });
    };
    let end = q.end.as_ref().filter(|e| e.inclusive);
    let equal = match (&q.start, end) {
        (Some(s), Some(e)) if s.value == e.value => Some(s),
        _ => None,
    };
    // A member that copies the query's child path or a bound value is work by the size copied, charged first.
    let ordering = |path: &Path| -> Option<Value<'a>> {
        charge(work, path.byte_len().saturating_add(path.depth()))?;
        Some(Value::Ordering(path.keys().to_vec()))
    };
    let bound = |bound: Option<&Bound>| -> Option<Value<'a>> {
        if let Some(bound) = bound {
            charge(work, json_cost(&bound.value))?;
        }
        Some(bound_value(bound))
    };
    Some(match name {
        "orderByKey" => Value::Bool(q.order_by == OrderBy::Key),
        "orderByValue" => Value::Bool(q.order_by == OrderBy::Value),
        "orderByPriority" => Value::Bool(q.order_by == OrderBy::Priority),
        "orderByChild" => match &q.order_by {
            OrderBy::Child(path) => ordering(path)?,
            _ => Value::Null,
        },
        // The same ordering as `orderByChild` when the query orders by a child. Otherwise a
        // value that is not null and equals nothing but itself (the official emulator answers
        // `query.orderBy == null` false and `query.orderBy == query.orderBy` true on a read
        // ordered by key, by value or by priority).
        "orderBy" => match &q.order_by {
            OrderBy::Child(path) => ordering(path)?,
            other => ordering_of(other),
        },
        "equalTo" => bound(equal)?,
        "startAt" => bound(q.start.as_ref())?,
        "endAt" => bound(end)?,
        // The exclusive end bound (`endBefore`), recorded RTDB-RULES-SYNTAX-20261108-01.
        "endBefore" => bound(q.end.as_ref().filter(|e| !e.inclusive))?,
        "limitToFirst" => match q.limit {
            Some(Limit::First(n)) => Value::Num(f64::from(n)),
            _ => Value::Null,
        },
        "limitToLast" => match q.limit {
            Some(Limit::Last(n)) => Value::Num(f64::from(n)),
            _ => Value::Null,
        },
        _ => Value::Null,
    })
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
    ctx: Ctx<'_>,
) -> Option<Value<'a>> {
    // A string method reads its receiver and its arguments: that is its work.
    if matches!(object, Value::Str(_) | Value::Units(_)) {
        charge(
            ctx.work,
            text_len(&object) + arguments.iter().map(text_len).sum::<usize>(),
        )?;
    }
    match object {
        Value::Snapshot(snapshot, version) => {
            snapshot_call(&snapshot, version, name, arguments, ctx)
        }
        // `query` and `http` have one method each. Another name reaches here when a union type let it past the
        // load (`(c ? 's' : http).replace(...)`): that call is an error, as there.
        Value::Query if name == "isOrderByChild" => {
            let keys = ordering_path(&path_argument(arguments, 0)?)?;
            charge(
                ctx.work,
                keys.iter().map(String::len).sum::<usize>() + keys.len(),
            )?;
            let ordering = query_member(ctx.query, ctx.read_kind, "orderBy", ctx.work)?;
            Some(Value::Bool(equal(&ordering, &Value::Ordering(keys))))
        }
        Value::Http if name == "encodeURL" => {
            let units = units_of(arguments.first()?)?;
            charge(ctx.work, units.len())?;
            let encoded = java_url_encode(&units);
            if encoded.len() > MAX_STRING_UNITS {
                return None;
            }
            charge(ctx.work, encoded.len())?;
            Some(Value::Str(encoded))
        }
        Value::Str(s) if arguments.iter().any(|a| matches!(a, Value::Units(_))) => {
            units_call(&s.encode_utf16().collect::<Vec<_>>(), name, arguments, ctx)
        }
        Value::Units(units) => units_call(&units, name, arguments, ctx),
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
                    return units_call(&s.encode_utf16().collect::<Vec<_>>(), name, arguments, ctx);
                }
                let replaced = java_replace(&s, &from, &to)?;
                charge(ctx.work, replaced.len())?;
                Some(Value::Str(replaced))
            }
            "toLowerCase" | "toUpperCase" => {
                let converted = java_case(&s, name == "toLowerCase")?;
                // The converted copy is work by its length (it can be longer than the receiver).
                charge(ctx.work, converted.len())?;
                Some(Value::Str(converted))
            }
            "matches" => match arguments.first()? {
                Value::Regex(pattern) => pattern.matches(&s, ctx.regex).map(Value::Bool),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// The keys of a path `isOrderByChild()` names, read as a string literal compared with an
/// ordering is read: segments between slashes, empty ones dropped, each a valid key. A path
/// without a segment, an invalid key or a lone surrogate is an error there, so the rule is false
/// negated or not (recorded on the official emulator).
fn ordering_path(text: &str) -> Option<Vec<String>> {
    let joined: Vec<&str> = text.split('/').filter(|s| !s.is_empty()).collect();
    if joined.is_empty()
        || joined[0] == ".info"
        || joined.len() > crate::limits::Limits::default().max_depth
    {
        return None;
    }
    let path = Path::parse(&joined.join("/"), &crate::limits::Limits::default()).ok()?;
    Some(path.keys().to_vec())
}

/// `http.encodeURL(s)` as the official emulator computes it: Java's
/// `URLEncoder.encode(s, "UTF-8")` with each `+` it made for a space replaced by `%20`. ASCII
/// letters, digits, `.`, `-`, `*` and `_` stay; every other character is each byte of its UTF-8
/// form as `%XX` (upper case); a lone surrogate is encoded as `?` is, as Java's encoder
/// replaces it.
fn java_url_encode(units: &[u16]) -> String {
    let mut out = String::new();
    for decoded in char::decode_utf16(units.iter().copied()) {
        let c = decoded.unwrap_or('?');
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | '_') {
            out.push(c);
        } else if c == ' ' {
            out.push_str("%20");
        } else {
            let mut bytes = [0; 4];
            for byte in c.encode_utf8(&mut bytes).bytes() {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 15)]));
            }
        }
    }
    out
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

/// The failure function of Knuth, Morris and Pratt for `needle`, so that a search costs the length of the
/// text plus that of the needle however the two look (the windowed comparison it replaces was quadratic).
fn failure_table(needle: &[u16]) -> Vec<usize> {
    let mut table = vec![0; needle.len()];
    let mut matched = 0;
    for at in 1..needle.len() {
        while matched > 0 && needle[at] != needle[matched] {
            matched = table[matched - 1];
        }
        if needle[at] == needle[matched] {
            matched += 1;
        }
        table[at] = matched;
    }
    table
}

/// Where `needle` first starts in `haystack`, as Java's `String.indexOf` reads UTF-16 units; `table` is
/// [`failure_table`] of `needle`, which is not empty.
fn search_units(haystack: &[u16], needle: &[u16], table: &[usize]) -> Option<usize> {
    let mut matched = 0;
    for (at, unit) in haystack.iter().enumerate() {
        while matched > 0 && *unit != needle[matched] {
            matched = table[matched - 1];
        }
        if *unit == needle[matched] {
            matched += 1;
        }
        if matched == needle.len() {
            return Some(at + 1 - matched);
        }
    }
    None
}

/// Where `needle` starts in `haystack`.
fn find_units(haystack: &[u16], needle: &[u16]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    search_units(haystack, needle, &failure_table(needle))
}

/// The string methods on a string that holds a lone surrogate, or whose argument does, read by UTF-16
/// unit as Java reads them. A method not listed here is an error, so the rule is false negated or not.
fn units_call<'a>(
    units: &[u16],
    name: &str,
    arguments: &[Value<'a>],
    ctx: Ctx<'_>,
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
                charge(ctx.work, out.len())?;
                return Some(from_units(out));
            }
            let table = failure_table(&from);
            let mut out = Vec::with_capacity(units.len());
            let mut rest = units;
            while let Some(at) = search_units(rest, &from, &table) {
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
            charge(ctx.work, out.len())?;
            Some(from_units(out))
        }
        "toLowerCase" | "toUpperCase" => {
            let lower = name == "toLowerCase";
            let mut out: Vec<u16> = Vec::with_capacity(units.len());
            let mut run = String::new();
            for decoded in char::decode_utf16(units.iter().copied()) {
                match decoded {
                    Ok(c) => run.push(c),
                    Err(lone) => {
                        let room = MAX_STRING_UNITS.checked_sub(out.len() + 1)?;
                        out.extend(
                            java_case_within(
                                &std::mem::take(&mut run),
                                lower,
                                room,
                                char::len_utf16,
                            )?
                            .encode_utf16(),
                        );
                        out.push(lone.unpaired_surrogate());
                    }
                }
            }
            let room = MAX_STRING_UNITS.checked_sub(out.len())?;
            out.extend(java_case_within(&run, lower, room, char::len_utf16)?.encode_utf16());
            // The converted copy is work by its length.
            charge(ctx.work, out.len())?;
            Some(from_units(out))
        }
        "matches" => match arguments.first()? {
            Value::Regex(pattern) => pattern.matches_units(units, ctx.regex).map(Value::Bool),
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
    ctx: Ctx<'_>,
) -> Option<Value<'a>> {
    let located = snapshot.locate();
    match name {
        "val" => {
            let value = match &located {
                Located::Absent => Value::Null,
                Located::Priority(leaf)
                | Located::Node(Node {
                    content: Content::Leaf(leaf),
                    ..
                }) => leaf_value(leaf),
                Located::Node(_) => Value::Sentinel,
            };
            // The value is copied out of the tree: that is work, by its length.
            charge(ctx.work, text_len(&value))?;
            Some(value)
        }
        "child" => Some(Value::Snapshot(
            snapshot.child(&path_argument(arguments, 0)?, ctx.work)?,
            version,
        )),
        "parent" => {
            // The parent is a copy of the location without its last key: charged by the bytes copied.
            charge(ctx.work, snapshot.path_cost())?;
            snapshot.path.parent().map(|path| {
                Value::Snapshot(
                    Snapshot {
                        root: snapshot.root,
                        path,
                    },
                    version,
                )
            })
        }
        "exists" => Some(Value::Bool(!matches!(located, Located::Absent))),
        "hasChild" => Some(Value::Bool(!matches!(
            snapshot
                .child(&path_argument(arguments, 0)?, ctx.work)?
                .locate(),
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
                if matches!(snapshot.child(&key, ctx.work)?.locate(), Located::Absent) {
                    return Some(Value::Bool(false));
                }
            }
            Some(Value::Bool(true))
        }
        "getPriority" => {
            if !snapshot.is_valid_location() {
                return None;
            }
            let priority = match &located {
                Located::Node(node) => node.priority.as_deref(),
                _ => None,
            };
            Some(match priority {
                // A priority written through a `.priority` path keeps an integer's type: the
                // official emulator holds it as a `Long`, equal to its number but no number to
                // `<`, `+` or `-` (review r11 M40). One inside an object body is a double.
                Some(Priority::Number(crate::number::Number::Int(n))) => Value::Long(*n),
                Some(Priority::Number(n)) => Value::Num(n.as_f64()),
                Some(Priority::String(s)) => {
                    charge(ctx.work, s.len())?;
                    Value::Str(s.clone())
                }
                None => Value::Null,
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
    combine(op, &l, &r, &scope.work)
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
        value = combine(op, &value, &eval(operand, scope, observer)?, &scope.work)?;
        if prefixes[index] != diagnostic {
            record_value(observer, prefixes[index], &value, None);
        }
    }
    Some(value)
}

/// `l op r` for an operator that is not `&&` or `||`.
fn combine<'a>(
    op: BinaryOp,
    l: &Value<'a>,
    r: &Value<'a>,
    work: &std::cell::Cell<u64>,
) -> Option<Value<'a>> {
    // Comparing or joining strings reads both of them.
    charge(work, text_len(l) + text_len(r))?;
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
        | (Value::Http, Value::Http)
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
                Ctx {
                    regex: false,
                    work: &std::cell::Cell::new(0),
                    query: None,
                    read_kind: ReadKind::Get,
                },
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
        let add = |l: Value<'static>, r: Value<'static>| {
            combine(BinaryOp::Add, &l, &r, &std::cell::Cell::new(0))
        };
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
    /// The evaluation work is charged up to the bound and refused past it: exactly the bound is allowed.
    #[test]
    fn evaluation_work_is_charged_up_to_the_bound_and_not_past_it() {
        let bound = usize::try_from(MAX_EVALUATION_WORK).unwrap();
        let work = std::cell::Cell::new(0);
        assert!(charge(&work, bound - 3).is_some());
        assert!(charge(&work, 3).is_some());
        assert_eq!(work.get(), MAX_EVALUATION_WORK);
        assert!(charge(&work, 0).is_some());
        assert!(charge(&work, 1).is_none());
        assert_eq!(
            work.get(),
            MAX_EVALUATION_WORK,
            "a refused charge adds nothing"
        );
    }

    /// A string is charged by its length, whichever form it is held in.
    #[test]
    fn a_string_is_charged_by_its_length() {
        assert_eq!(text_len(&Value::Str("ab\u{1F600}".to_owned())), 6);
        assert_eq!(text_len(&Value::Units(vec![0x61, 0xD83D, 0x62])), 3);
        assert_eq!(text_len(&Value::Null), 0);
    }

    /// A result measured exactly at the room is allowed and one unit more is not.
    #[test]
    fn case_conversion_is_measured_against_the_room_exactly() {
        assert_eq!(
            java_case_within("abc", true, 3, char::len_utf16).as_deref(),
            Some("abc")
        );
        assert_eq!(java_case_within("abc", true, 2, char::len_utf16), None);
        // `\u{DF}` grows to two characters in upper case.
        assert_eq!(
            java_case_within("\u{DF}", false, 2, char::len_utf16).as_deref(),
            Some("SS")
        );
        assert_eq!(java_case_within("\u{DF}", false, 1, char::len_utf16), None);
    }

    proptest::proptest! {
        /// The failure table is the length of the longest proper prefix that is also a suffix, and the search
        /// finds what a window comparison finds.
        #[test]
        fn the_search_is_the_window_search(
            haystack in proptest::collection::vec(0_u16..3, 0..14),
            needle in proptest::collection::vec(0_u16..3, 1..6),
        ) {
            let table = failure_table(&needle);
            for (at, entry) in table.iter().enumerate() {
                let prefix = &needle[..=at];
                let best = (0..prefix.len())
                    .rev()
                    .find(|&k| prefix[..k] == prefix[prefix.len() - k..])
                    .unwrap_or(0);
                proptest::prop_assert_eq!(*entry, best);
            }
            let naive = haystack.windows(needle.len()).position(|w| w == needle.as_slice());
            proptest::prop_assert_eq!(find_units(&haystack, &needle), naive);
        }

        /// `encodeURL` keeps exactly ASCII letters, digits and `.-*_`, and every other character is
        /// the `%XX` bytes of its UTF-8 form (a lone surrogate those of `?`), so decoding gives the
        /// input back with each lone surrogate as `?`.
        #[test]
        fn encode_url_is_utf8_percent_encoding_with_the_java_unreserved_set(
            units in proptest::collection::vec(proptest::prop_oneof![0_u16..0x80, 0xD7F0_u16..0xE010, 0_u16..=u16::MAX], 0..12),
        ) {
            let encoded = java_url_encode(&units);
            let mut bytes = Vec::new();
            let mut rest = encoded.as_str();
            while let Some(c) = rest.chars().next() {
                if c == '%' {
                    let hex = &rest[1..3];
                    proptest::prop_assert_eq!(hex, hex.to_ascii_uppercase());
                    bytes.extend(fireemu_core_types::codec::percent_decode_bytes(
                        &rest[..3],
                        fireemu_core_types::codec::PlusMode::Literal,
                    ));
                    rest = &rest[3..];
                } else {
                    proptest::prop_assert!(c.is_ascii_alphanumeric() || ".-*_".contains(c), "{c:?} kept");
                    bytes.push(u8::try_from(c).unwrap());
                    rest = &rest[1..];
                }
            }
            let expected: String = char::decode_utf16(units.iter().copied()).map(|d| d.unwrap_or('?')).collect();
            proptest::prop_assert_eq!(String::from_utf8(bytes).unwrap(), expected.clone());
            for c in expected.chars() {
                if c.is_ascii_alphanumeric() || ".-*_".contains(c) {
                    proptest::prop_assert!(encoded.contains(c));
                }
            }
        }

        /// A path for `isOrderByChild` is its non-empty segments: extra slashes never change it, and
        /// no segment at all is an error.
        #[test]
        fn ordering_paths_ignore_empty_segments(keys in proptest::collection::vec("[a-z]{1,3}", 0..4), slashes in proptest::collection::vec(1_usize..3, 0..6)) {
            let mut text = String::new();
            for (i, key) in keys.iter().enumerate() {
                text.push_str(&"/".repeat(*slashes.get(i).unwrap_or(&1)));
                text.push_str(key);
            }
            text.push_str(&"/".repeat(*slashes.last().unwrap_or(&0)));
            match ordering_path(&text) {
                Some(path) => proptest::prop_assert_eq!(path, keys.clone()),
                None => proptest::prop_assert!(keys.is_empty()),
            }
        }
    }

    fn query_call(argument: &str, work: &std::cell::Cell<u64>) -> Option<Value<'static>> {
        call(
            Value::Query,
            "isOrderByChild",
            &[Value::Str(argument.to_owned())],
            Ctx {
                regex: false,
                work,
                query: None,
                read_kind: ReadKind::Get,
            },
        )
    }

    fn encode_call(argument: String, work: &std::cell::Cell<u64>) -> Option<usize> {
        match call(
            Value::Http,
            "encodeURL",
            &[Value::Str(argument)],
            Ctx {
                regex: false,
                work,
                query: None,
                read_kind: ReadKind::Get,
            },
        ) {
            Some(Value::Str(s)) => Some(s.len()),
            _ => None,
        }
    }

    #[test]
    fn query_and_http_answer_only_their_own_method() {
        let work = std::cell::Cell::new(0);
        let ctx = || Ctx {
            regex: false,
            work: &work,
            query: None,
            read_kind: ReadKind::Get,
        };
        let text = [Value::Str("a".to_owned())];
        assert!(call(
            Value::Http,
            "replace",
            &[Value::Str("a".to_owned()), Value::Str("b".to_owned())],
            ctx()
        )
        .is_none());
        assert!(call(Value::Http, "contains", &text, ctx()).is_none());
        assert!(call(Value::Query, "contains", &text, ctx()).is_none());
        assert!(call(Value::Query, "encodeURL", &text, ctx()).is_none());
        assert!(call(Value::Http, "encodeURL", &text, ctx()).is_some());
    }

    #[test]
    fn is_order_by_child_is_charged_by_the_keys_it_reads() {
        let work = std::cell::Cell::new(0);
        assert!(matches!(
            query_call("ab//c/", &work),
            Some(Value::Bool(false))
        ));
        // `ab` and `c`: three bytes and two keys.
        assert_eq!(work.get(), 5);
        let work = std::cell::Cell::new(0);
        assert!(query_call("$key", &work).is_none());
        assert!(query_call("", &work).is_none());
    }

    #[test]
    fn encode_url_builds_at_most_the_longest_string() {
        // `+` encodes to three characters: 3n + 1 = 2^26 exactly.
        let n = (MAX_STRING_UNITS - 1) / 3;
        assert_eq!(3 * n + 1, MAX_STRING_UNITS);
        let work = std::cell::Cell::new(0);
        assert_eq!(
            encode_call(format!("{}a", "+".repeat(n)), &work),
            Some(MAX_STRING_UNITS)
        );
        assert_eq!(work.get(), u64::try_from(n + 1 + MAX_STRING_UNITS).unwrap());
        let work = std::cell::Cell::new(0);
        assert_eq!(encode_call(format!("{}ab", "+".repeat(n)), &work), None);
    }

    #[test]
    fn methods_called_through_a_value_take_their_own_argument_counts() {
        for (name, n) in [
            ("replace", 2),
            ("hasChildren", 0),
            ("hasChildren", 1),
            ("parent", 0),
            ("val", 0),
            ("child", 1),
            ("contains", 1),
            ("isOrderByChild", 1),
            ("encodeURL", 1),
            ("toUpperCase", 0),
        ] {
            assert!(takes_arguments(name, n), "{name} {n}");
            assert!(
                !takes_arguments(name, n + if name == "hasChildren" { 2 - n } else { 1 }),
                "{name} {n}+"
            );
        }
        assert!(!takes_arguments("child", 0));
        assert!(!takes_arguments("replace", 1));
        assert_eq!(
            java_url_encode(&"a b+".encode_utf16().collect::<Vec<_>>()),
            "a%20b%2B"
        );
        assert_eq!(java_url_encode(&[0xD83D]), "%3F");
    }
}
