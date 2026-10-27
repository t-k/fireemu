//! The string and math functions of a pipeline (`FS-PIPELINE`): `concat`, `to_lower`,
//! `to_upper`, `starts_with`, `ends_with`, `string_contains`, `char_length`, `substring`,
//! `trim`, `ltrim`, `rtrim`, `split`, `add`, `subtract`, `multiply`, `divide`, `mod`, `abs`,
//! `round`, `floor`, `ceil` and `pow`.
//!
//! Everything here was observed in production by FS-ENT-ORACLE O-8B (2026-10-26, an Enterprise
//! database, two identical recordings; `fs-ent-pipeline/o8b/strings-main` and `math-main`).
//! The rules those rows show:
//!
//! - A null or a missing argument gives null.
//! - An argument of the wrong type fails the whole request with
//!   ``The function f(...) requires `T` but got `U`.`` (the type names are production's).
//! - Integer arithmetic is checked: an overflow fails the request, except that `divide` wraps
//!   and `mod` answers 0 for `int64::MIN` by `-1`.
//!
//! What production did not answer is [`EvalError::Unobserved`] under strict (the arguments of
//! a shape no row covers, a null beside a wrong type, a function used as a whole `where`
//! condition); the emulator profile evaluates it by the same rules. The four `regex_*`
//! functions are not here: they need a regular expression engine.

use super::{first_error, type_name, Arity, Context, Eval, EvalError, Function, Unrecorded};
use crate::value::Value;

/// The function names this module defines, for callers that must tell them from the rest.
pub const NAMES: [&str; 22] = [
    "concat",
    "to_lower",
    "to_upper",
    "starts_with",
    "ends_with",
    "string_contains",
    "char_length",
    "substring",
    "trim",
    "ltrim",
    "rtrim",
    "split",
    "add",
    "subtract",
    "multiply",
    "divide",
    "mod",
    "abs",
    "round",
    "floor",
    "ceil",
    "pow",
];

const fn function(
    name: &'static str,
    arity: Arity,
    returns_boolean: bool,
    signature: &'static str,
    overloads: &'static [(&'static str, usize, usize)],
    eval: fn(&[Eval], Context) -> Eval,
) -> Function {
    Function {
        name,
        arity,
        returns_boolean,
        signature,
        overloads,
        eval,
    }
}

pub(super) const CONCAT: Function = function(
    "concat",
    Arity::AtLeast(2),
    false,
    "concat[T: string | bytes | array[any]](input: T*): T",
    &[],
    eval_concat,
);
pub(super) const TO_LOWER: Function = function(
    "to_lower",
    Arity::Exact(1),
    false,
    "to_lower[T: string | bytes](input: T): T",
    &[],
    eval_to_lower,
);
pub(super) const TO_UPPER: Function = function(
    "to_upper",
    Arity::Exact(1),
    false,
    "to_upper[T: string | bytes](input: T): T",
    &[],
    eval_to_upper,
);
pub(super) const STARTS_WITH: Function = function(
    "starts_with",
    Arity::Exact(2),
    true,
    "starts_with(value: string, prefix: string): boolean",
    &[],
    eval_starts_with,
);
pub(super) const ENDS_WITH: Function = function(
    "ends_with",
    Arity::Exact(2),
    true,
    "ends_with(value: string, postfix: string): boolean",
    &[],
    eval_ends_with,
);
pub(super) const STRING_CONTAINS: Function = function(
    "string_contains",
    Arity::Exact(2),
    true,
    "string_contains(value: string, substring: string): boolean",
    &[],
    eval_string_contains,
);
pub(super) const CHAR_LENGTH: Function = function(
    "char_length",
    Arity::Exact(1),
    false,
    "char_length(str: string): int64",
    &[],
    eval_char_length,
);
pub(super) const SUBSTRING: Function = function(
    "substring",
    Arity::Between(2, 3),
    false,
    "",
    &[
        (
            "substring[T: string | bytes](input: T, position: int64): T",
            2,
            2,
        ),
        (
            "substring[T: string | bytes](input: T, position: int64, length: int64): T",
            3,
            3,
        ),
    ],
    eval_substring,
);
pub(super) const TRIM: Function = function(
    "trim",
    Arity::Between(1, 2),
    false,
    "",
    &[
        ("trim[T: string | bytes](input: T): T", 1, 1),
        (
            "trim[T: string | bytes](input: T, values_to_trim: T): T",
            2,
            2,
        ),
    ],
    eval_trim,
);
// The argument-count refusals of `ltrim` and `rtrim` were not recorded: their signatures stay
// unknown, so the count is refused in fireemu's own words (unobserved under strict).
pub(super) const LTRIM: Function =
    function("ltrim", Arity::Between(1, 2), false, "", &[], eval_ltrim);
pub(super) const RTRIM: Function =
    function("rtrim", Arity::Between(1, 2), false, "", &[], eval_rtrim);
pub(super) const SPLIT: Function = function(
    "split",
    Arity::Between(1, 2),
    false,
    "",
    &[
        ("split(input: string): array[string]", 1, 1),
        (
            "split[T: string | bytes](input: T, delimiter: T): array[T]",
            2,
            2,
        ),
    ],
    eval_split,
);
pub(super) const ADD: Function = function(
    "add",
    Arity::Exact(2),
    false,
    "add[T <: number](x: T, y: T): T",
    &[],
    eval_add,
);
pub(super) const SUBTRACT: Function = function(
    "subtract",
    Arity::Exact(2),
    false,
    "subtract[T <: number](x: T, y: T): T",
    &[],
    eval_subtract,
);
pub(super) const MULTIPLY: Function = function(
    "multiply",
    Arity::Exact(2),
    false,
    "multiply[T <: number](x: T, y: T): T",
    &[],
    eval_multiply,
);
pub(super) const DIVIDE: Function = function(
    "divide",
    Arity::Exact(2),
    false,
    "divide[T <: number](x: T, y: T): T",
    &[],
    eval_divide,
);
pub(super) const MOD: Function = function(
    "mod",
    Arity::Exact(2),
    false,
    "mod[T <: number](x: T, y: T): T",
    &[],
    eval_mod,
);
pub(super) const ABS: Function = function(
    "abs",
    Arity::Exact(1),
    false,
    "abs[T <: number](number: T): T",
    &[],
    eval_abs,
);
pub(super) const ROUND: Function = function(
    "round",
    Arity::Between(1, 2),
    false,
    "",
    &[
        ("round[T <: number](number: T): T", 1, 1),
        ("round[T <: number](number: T, places: int64): T", 2, 2),
    ],
    eval_round,
);
pub(super) const FLOOR: Function = function(
    "floor",
    Arity::Exact(1),
    false,
    "floor[T <: number](number: T): T",
    &[],
    eval_floor,
);
pub(super) const CEIL: Function = function(
    "ceil",
    Arity::Exact(1),
    false,
    "ceil[T <: number](number: T): T",
    &[],
    eval_ceil,
);
pub(super) const POW: Function = function(
    "pow",
    Arity::Exact(2),
    false,
    "pow(base: number, exponent: number): float64",
    &[],
    eval_pow,
);

fn unobserved(function: &'static str, reason: &'static str) -> Eval {
    Eval::Error(EvalError::Unobserved { function, reason })
}

fn invalid(message: impl Into<String>) -> Eval {
    Eval::Error(EvalError::Invalid(message.into()))
}

fn null() -> Eval {
    Eval::Value(Value::Null)
}

fn strict(cx: Context) -> bool {
    cx.unrecorded == Unrecorded::Refuse
}

/// What an argument of a function must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Param {
    /// A string; the text production names in a refusal.
    Str(&'static str),
    /// A string or bytes.
    StrOrBytes,
    /// A string or bytes, named in a refusal by the text of a plain string (`split`).
    StrOrBytesAsString,
    /// An `int64`.
    Int,
    /// A number (an integer or a double).
    Number,
}

impl Param {
    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::Str(_) => matches!(value, Value::String(_)),
            Self::StrOrBytes | Self::StrOrBytesAsString => {
                matches!(value, Value::String(_) | Value::Bytes(_))
            }
            Self::Int => matches!(value, Value::Integer(_)),
            Self::Number => matches!(value, Value::Integer(_) | Value::Double(_)),
        }
    }

    fn expected(self) -> &'static str {
        match self {
            Self::Str(text) => text,
            Self::StrOrBytes => "String | Bytes",
            Self::StrOrBytesAsString => "String",
            Self::Int => "Int64",
            Self::Number => "Number",
        }
    }
}

/// The arguments checked against `params`: `Ok` with every value, or the answer that ends the
/// call (an error of an argument, a wrong type, or null for a null or missing argument).
///
/// A wrong type is reported before a null makes the answer null; production did not show which
/// of the two comes first when both occur, so strict calls that unobserved.
fn check<'a>(
    function: &'static str,
    args: &'a [Eval],
    params: &[Param],
    cx: Context,
) -> Result<Vec<&'a Value>, Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    let mut values = Vec::with_capacity(args.len());
    let mut wrong = None;
    let mut missing = false;
    for (arg, param) in args.iter().zip(params) {
        match arg {
            Eval::Value(Value::Null) | Eval::Absent => missing = true,
            Eval::Value(value) if param.accepts(value) => values.push(value),
            Eval::Value(value) => {
                wrong.get_or_insert((*param, value));
            }
            Eval::Error(_) => unreachable!("errors are returned above"),
        }
    }
    if let Some((param, value)) = wrong {
        if missing && strict(cx) {
            return Err(unobserved(
                function,
                "a null beside an argument of the wrong type",
            ));
        }
        return Err(Eval::Error(EvalError::WrongType {
            function,
            expected: param.expected(),
            got: type_name(value),
        }));
    }
    if missing {
        return Err(null());
    }
    Ok(values)
}

/// The text of a double in a refusal, as Java prints it (`1.5`, `2.0`); `None` for the doubles
/// whose Java form this module does not reproduce (an exponent, NaN, infinity).
fn java_double(d: f64) -> Option<String> {
    let magnitude = d.abs();
    if !d.is_finite() || (magnitude != 0.0 && !(1e-3..1e7).contains(&magnitude)) {
        return None;
    }
    Some(format!("{d:?}"))
}

/// An `int64` argument that production would have coerced from a double: it refuses a double
/// with `Cannot coerce Float64 (x) to Int64`.
fn int_argument(function: &'static str, arg: &Eval, cx: Context) -> Option<Eval> {
    let Eval::Value(Value::Double(d)) = arg else {
        return None;
    };
    Some(match java_double(*d) {
        Some(text) => invalid(format!("Cannot coerce Float64 ({text}) to Int64")),
        None if strict(cx) => unobserved(function, "a double with no recorded text"),
        None => invalid(format!("Cannot coerce Float64 ({d:?}) to Int64")),
    })
}

/// `concat(a, b, ...)`: strings, bytes or arrays of one kind joined. The first argument sets the
/// kind; production refused a string followed by bytes or an integer.
fn eval_concat(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let first = args.iter().find_map(|arg| match arg {
        Eval::Value(Value::Null) | Eval::Absent | Eval::Error(_) => None,
        Eval::Value(value) => Some(value),
    });
    // A null or a missing argument gives null, unless another argument is of the wrong type
    // for the kind the first value sets.
    let expected = match first {
        Some(Value::String(_)) => "STRING",
        Some(Value::Bytes(_)) => "BYTES",
        Some(Value::Array(_)) => "ARRAY",
        Some(other) => {
            return if strict(cx) {
                unobserved("concat", "an argument that is no string, bytes or array")
            } else {
                Eval::Error(EvalError::WrongType {
                    function: "concat",
                    expected: "STRING",
                    got: type_name(other),
                })
            }
        }
        None => return null(),
    };
    let mut missing = false;
    for arg in args {
        match arg {
            Eval::Value(Value::Null) | Eval::Absent => missing = true,
            Eval::Value(value) if type_name(value) == expected => {}
            Eval::Value(value) => {
                if strict(cx) && (expected != "STRING" || args.iter().any(is_missing)) {
                    return unobserved("concat", "an argument of another type than the first");
                }
                return Eval::Error(EvalError::WrongType {
                    function: "concat",
                    expected,
                    got: type_name(value),
                });
            }
            Eval::Error(_) => unreachable!("errors are returned above"),
        }
    }
    if missing {
        return null();
    }
    match first {
        Some(Value::String(_)) => Eval::Value(Value::String(
            args.iter()
                .filter_map(|arg| match arg {
                    Eval::Value(Value::String(text)) => Some(text.as_str()),
                    _ => None,
                })
                .collect(),
        )),
        Some(Value::Bytes(_)) => Eval::Value(Value::Bytes(
            args.iter()
                .filter_map(|arg| match arg {
                    Eval::Value(Value::Bytes(bytes)) => Some(bytes.iter().copied()),
                    _ => None,
                })
                .flatten()
                .collect(),
        )),
        _ => Eval::Value(Value::Array(
            args.iter()
                .filter_map(|arg| match arg {
                    Eval::Value(Value::Array(values)) => Some(values.iter().cloned()),
                    _ => None,
                })
                .flatten()
                .collect(),
        )),
    }
}

fn is_missing(arg: &Eval) -> bool {
    matches!(arg, Eval::Value(Value::Null) | Eval::Absent)
}

/// Whether strict has a recording for a letter case mapping of this text: the mapping is
/// context free except for the Greek sigma, whose lower case depends on the word it ends.
fn case_recorded(text: &str) -> bool {
    !text.contains(['\u{3a3}', '\u{3c2}'])
}

fn eval_to_lower(args: &[Eval], cx: Context) -> Eval {
    map_case(
        "to_lower",
        args,
        cx,
        str::to_lowercase,
        u8::to_ascii_lowercase,
    )
}

fn eval_to_upper(args: &[Eval], cx: Context) -> Eval {
    map_case(
        "to_upper",
        args,
        cx,
        str::to_uppercase,
        u8::to_ascii_uppercase,
    )
}

fn map_case(
    function: &'static str,
    args: &[Eval],
    cx: Context,
    text: fn(&str) -> String,
    byte: fn(&u8) -> u8,
) -> Eval {
    let values = match check(function, args, &[Param::StrOrBytes], cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match values[0] {
        Value::String(s) if strict(cx) && !case_recorded(s) => unobserved(
            function,
            "a Greek sigma, whose case mapping depends on its position",
        ),
        Value::String(s) => Eval::Value(Value::String(text(s))),
        // Production answered the bytes `[1]` unchanged; a letter among the bytes is a case the
        // rows do not show.
        Value::Bytes(b) if strict(cx) && b.iter().any(u8::is_ascii_alphabetic) => {
            unobserved(function, "bytes holding ASCII letters")
        }
        Value::Bytes(b) => Eval::Value(Value::Bytes(b.iter().map(byte).collect())),
        _ => unreachable!("checked above"),
    }
}

fn eval_starts_with(args: &[Eval], cx: Context) -> Eval {
    two_strings("starts_with", args, cx, |value, prefix| {
        value.starts_with(prefix)
    })
}

fn eval_ends_with(args: &[Eval], cx: Context) -> Eval {
    two_strings("ends_with", args, cx, |value, suffix| {
        value.ends_with(suffix)
    })
}

fn eval_string_contains(args: &[Eval], cx: Context) -> Eval {
    two_strings("string_contains", args, cx, |value, part| {
        value.contains(part)
    })
}

/// A boolean function of two strings. Production showed them only as `select` values, so strict
/// does not answer one as the whole condition of a `where`.
fn two_strings(
    function: &'static str,
    args: &[Eval],
    cx: Context,
    test: fn(&str, &str) -> bool,
) -> Eval {
    if cx.condition && strict(cx) {
        return unobserved(function, "a whole `where` condition");
    }
    let values = match check(
        function,
        args,
        &[Param::Str("String"), Param::Str("String")],
        cx,
    ) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values[1]) {
        (Value::String(a), Value::String(b)) => Eval::Value(Value::Boolean(test(a, b))),
        _ => unreachable!("checked above"),
    }
}

fn eval_char_length(args: &[Eval], cx: Context) -> Eval {
    let values = match check("char_length", args, &[Param::Str("String")], cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match values[0] {
        Value::String(s) => Eval::Value(Value::Integer(
            i64::try_from(s.chars().count()).unwrap_or(i64::MAX),
        )),
        _ => unreachable!("checked above"),
    }
}

fn eval_substring(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    // A null length was not asked.
    if strict(cx) && args.get(2).is_some_and(is_missing) {
        return unobserved("substring", "a null length");
    }
    if let Some(answer) = args
        .get(1)
        .and_then(|arg| int_argument("substring", arg, cx))
    {
        if !args.first().is_some_and(is_missing) {
            return answer;
        }
    }
    if let Some(answer) = args
        .get(2)
        .and_then(|arg| int_argument("substring", arg, cx))
    {
        return answer;
    }
    let params = [Param::StrOrBytes, Param::Int, Param::Int];
    let values = match check("substring", args, &params, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    let (Value::Integer(position), length) = (
        values[1],
        match values.get(2) {
            Some(Value::Integer(length)) => Some(*length),
            _ => None,
        },
    ) else {
        unreachable!("checked above")
    };
    if length.is_some_and(|length| length < 0) {
        return invalid("substring(...) length must be non-negative");
    }
    let take = |len: usize| -> Result<(usize, usize), Eval> {
        let len = i64::try_from(len).unwrap_or(i64::MAX);
        let start = if *position < 0 {
            len + *position
        } else {
            *position
        };
        if start < 0 && strict(cx) {
            return Err(unobserved(
                "substring",
                "a negative position before the start",
            ));
        }
        let start = start.max(0).min(len);
        let end = length.map_or(len, |length| start.saturating_add(length).min(len));
        Ok((
            usize::try_from(start).unwrap_or(0),
            usize::try_from(end).unwrap_or(0),
        ))
    };
    match values[0] {
        Value::String(s) => {
            let chars: Vec<char> = s.chars().collect();
            match take(chars.len()) {
                Ok((start, end)) => Eval::Value(Value::String(chars[start..end].iter().collect())),
                Err(answer) => answer,
            }
        }
        Value::Bytes(b) => match take(b.len()) {
            Ok((start, end)) => Eval::Value(Value::Bytes(b[start..end].to_vec())),
            Err(answer) => answer,
        },
        _ => unreachable!("checked above"),
    }
}

/// The characters `trim` removes by default: the ASCII space, tab and line feed and the
/// no-break space were shown; any other white space is not.
fn recorded_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{a0}')
}

/// Which ends `trim`, `ltrim` and `rtrim` strip.
#[derive(Debug, Clone, Copy)]
struct Ends {
    start: bool,
    end: bool,
}

fn eval_trim(args: &[Eval], cx: Context) -> Eval {
    trim_call(
        "trim",
        args,
        cx,
        Ends {
            start: true,
            end: true,
        },
    )
}

fn eval_ltrim(args: &[Eval], cx: Context) -> Eval {
    trim_call(
        "ltrim",
        args,
        cx,
        Ends {
            start: true,
            end: false,
        },
    )
}

fn eval_rtrim(args: &[Eval], cx: Context) -> Eval {
    trim_call(
        "rtrim",
        args,
        cx,
        Ends {
            start: false,
            end: true,
        },
    )
}

fn trim_call(function: &'static str, args: &[Eval], cx: Context, ends: Ends) -> Eval {
    let params = [Param::StrOrBytes, Param::StrOrBytes];
    let values = match check(function, args, &params, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values.get(1)) {
        (Value::String(s), None) => trim_string(function, s, None, cx, ends),
        (Value::String(s), Some(Value::String(set))) => {
            trim_string(function, s, Some(set), cx, ends)
        }
        (Value::Bytes(b), None) => {
            let space = |byte: &u8| byte.is_ascii_whitespace();
            if strict(cx)
                && ((ends.start && b.first().is_some_and(space))
                    || (ends.end && b.last().is_some_and(space)))
            {
                return unobserved(function, "bytes with white space at an end");
            }
            Eval::Value(Value::Bytes(trim_slice(b, space, ends).to_vec()))
        }
        (Value::Bytes(b), Some(Value::Bytes(set))) => {
            if strict(cx) {
                return unobserved(function, "bytes to trim");
            }
            Eval::Value(Value::Bytes(
                trim_slice(b, |byte| set.contains(byte), ends).to_vec(),
            ))
        }
        _ => {
            if strict(cx) {
                unobserved(function, "an input and a set of another type")
            } else {
                Eval::Error(EvalError::WrongType {
                    function,
                    expected: "String | Bytes",
                    got: type_name(values[1]),
                })
            }
        }
    }
}

/// The part of `items` left once `strip` has removed the characters at the chosen ends.
fn trim_range<T>(items: &[T], strip: impl Fn(&T) -> bool, ends: Ends) -> (usize, usize) {
    let mut start = 0;
    let mut end = items.len();
    if ends.start {
        while start < end && strip(&items[start]) {
            start += 1;
        }
    }
    if ends.end {
        while end > start && strip(&items[end - 1]) {
            end -= 1;
        }
    }
    (start, end)
}

fn trim_slice<T>(items: &[T], strip: impl Fn(&T) -> bool, ends: Ends) -> &[T] {
    let (start, end) = trim_range(items, strip, ends);
    &items[start..end]
}

fn trim_string(
    function: &'static str,
    text: &str,
    set: Option<&str>,
    cx: Context,
    ends: Ends,
) -> Eval {
    let chars: Vec<char> = text.chars().collect();
    let strip = |c: &char| match set {
        Some(set) => set.contains(*c),
        None => recorded_space(*c) || c.is_whitespace(),
    };
    let (start, end) = trim_range(&chars, strip, ends);
    if strict(cx) {
        // The white space beyond the recorded characters, and an empty set, were not shown.
        let unrecorded_removed = set.is_none()
            && chars[..start]
                .iter()
                .chain(&chars[end..])
                .any(|c| !recorded_space(*c));
        if unrecorded_removed || set.is_some_and(str::is_empty) {
            return unobserved(function, "white space or a set the rows do not show");
        }
    }
    Eval::Value(Value::String(chars[start..end].iter().collect()))
}

fn eval_split(args: &[Eval], cx: Context) -> Eval {
    // Production named `String` for an integer input (O-8B `split-int`).
    let params = [Param::StrOrBytesAsString, Param::StrOrBytesAsString];
    let values = match check("split", args, &params, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values.get(1).copied()) {
        (Value::String(s), None) => {
            // One argument splits at commas; the one row shows a text with none.
            if strict(cx) && s.contains(',') {
                return unobserved("split", "one argument and a text with a comma");
            }
            Eval::Value(Value::Array(
                s.split(',')
                    .map(|part| Value::String(part.to_owned()))
                    .collect(),
            ))
        }
        (Value::String(s), Some(Value::String(delimiter))) => {
            if delimiter.is_empty() {
                if strict(cx) && s.is_empty() {
                    return unobserved("split", "an empty text and an empty delimiter");
                }
                return Eval::Value(Value::Array(
                    s.chars().map(|c| Value::String(c.to_string())).collect(),
                ));
            }
            Eval::Value(Value::Array(
                s.split(delimiter.as_str())
                    .map(|part| Value::String(part.to_owned()))
                    .collect(),
            ))
        }
        (Value::Bytes(b), Some(Value::Bytes(delimiter))) => {
            if delimiter.is_empty() {
                return if strict(cx) {
                    unobserved("split", "an empty delimiter of bytes")
                } else {
                    Eval::Value(Value::Array(
                        b.iter().map(|byte| Value::Bytes(vec![*byte])).collect(),
                    ))
                };
            }
            let mut parts = Vec::new();
            let mut start = 0;
            let mut at = 0;
            while at + delimiter.len() <= b.len() {
                if b[at..at + delimiter.len()] == delimiter[..] {
                    parts.push(Value::Bytes(b[start..at].to_vec()));
                    at += delimiter.len();
                    start = at;
                } else {
                    at += 1;
                }
            }
            parts.push(Value::Bytes(b[start..].to_vec()));
            Eval::Value(Value::Array(parts))
        }
        (Value::Bytes(_), None) => {
            if strict(cx) {
                unobserved("split", "bytes and no delimiter")
            } else {
                Eval::Error(EvalError::WrongType {
                    function: "split",
                    expected: "String",
                    got: "BYTES",
                })
            }
        }
        (_, Some(other)) => {
            if strict(cx) {
                unobserved("split", "an input and a delimiter of another type")
            } else {
                Eval::Error(EvalError::WrongType {
                    function: "split",
                    expected: "String",
                    got: type_name(other),
                })
            }
        }
        _ => unreachable!("checked above"),
    }
}

/// A number argument.
#[derive(Debug, Clone, Copy)]
enum Num {
    Int(i64),
    Double(f64),
}

impl Num {
    fn of(value: &Value) -> Self {
        match value {
            Value::Integer(i) => Self::Int(*i),
            Value::Double(d) => Self::Double(*d),
            _ => unreachable!("checked as a number"),
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn double(self) -> f64 {
        match self {
            Self::Int(i) => i as f64,
            Self::Double(d) => d,
        }
    }
}

fn numbers(
    function: &'static str,
    args: &[Eval],
    count: usize,
    cx: Context,
) -> Result<Vec<Num>, Eval> {
    let params = vec![Param::Number; count];
    check(function, args, &params, cx).map(|values| values.into_iter().map(Num::of).collect())
}

fn double(d: f64) -> Eval {
    Eval::Value(Value::Double(d))
}

fn integer(i: i64) -> Eval {
    Eval::Value(Value::Integer(i))
}

fn eval_add(args: &[Eval], cx: Context) -> Eval {
    arithmetic(
        "add",
        args,
        cx,
        i64::checked_add,
        |a, b| a + b,
        "add(...) int64 overflow",
    )
}

fn eval_subtract(args: &[Eval], cx: Context) -> Eval {
    arithmetic(
        "subtract",
        args,
        cx,
        i64::checked_sub,
        |a, b| a - b,
        "subtract(...) int64 overflow",
    )
}

fn eval_multiply(args: &[Eval], cx: Context) -> Eval {
    arithmetic(
        "multiply",
        args,
        cx,
        i64::checked_mul,
        |a, b| a * b,
        "multiply(...) overflow error",
    )
}

/// Integers give an integer (an overflow fails the request), a double on either side gives a
/// double.
fn arithmetic(
    function: &'static str,
    args: &[Eval],
    cx: Context,
    exact: fn(i64, i64) -> Option<i64>,
    float: fn(f64, f64) -> f64,
    overflow: &str,
) -> Eval {
    let values = match numbers(function, args, 2, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values[1]) {
        (Num::Int(a), Num::Int(b)) => exact(a, b).map_or_else(|| invalid(overflow), integer),
        (a, b) => double(float(a.double(), b.double())),
    }
}

fn eval_divide(args: &[Eval], cx: Context) -> Eval {
    let values = match numbers("divide", args, 2, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values[1]) {
        (Num::Int(_), Num::Int(0)) => invalid("divide(...) requires a non-zero right operand"),
        // The quotient of the smallest integer by -1 wraps (O-8B `divide-min-by-minus-one`).
        (Num::Int(a), Num::Int(b)) => integer(a.wrapping_div(b)),
        (Num::Double(a), Num::Double(b)) => double(a / b),
        // A double by an integer was shown (`divide-nan`); an integer by a double was not.
        (Num::Double(a), Num::Int(_)) => double(a / values[1].double()),
        (a, b) if strict(cx) => {
            let _ = (a, b);
            unobserved("divide", "an integer by a double")
        }
        (a, b) => double(a.double() / b.double()),
    }
}

fn eval_mod(args: &[Eval], cx: Context) -> Eval {
    let values = match numbers("mod", args, 2, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values[1]) {
        (Num::Int(_), Num::Int(0)) => invalid("mod(...) requires a non-zero divisor"),
        // The remainder of the smallest integer by -1 is 0 (O-8B `mod-min-by-minus-one`).
        (Num::Int(a), Num::Int(b)) => integer(a.wrapping_rem(b)),
        (Num::Double(a), Num::Double(b)) => double(a % b),
        (a, b) if strict(cx) => {
            let _ = (a, b);
            unobserved("mod", "an integer and a double")
        }
        (a, b) => double(a.double() % b.double()),
    }
}

fn eval_abs(args: &[Eval], cx: Context) -> Eval {
    let values = match numbers("abs", args, 1, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match values[0] {
        Num::Int(i) => i.checked_abs().map_or_else(
            || invalid("abs(...) cannot be used on minimum Int64 value (-2^63)"),
            integer,
        ),
        Num::Double(d) => double(d.abs()),
    }
}

fn eval_floor(args: &[Eval], cx: Context) -> Eval {
    rounding("floor", args, cx, f64::floor)
}

fn eval_ceil(args: &[Eval], cx: Context) -> Eval {
    rounding("ceil", args, cx, f64::ceil)
}

/// An integer stays as it is; a double goes to a whole double. Infinity was not shown.
fn rounding(function: &'static str, args: &[Eval], cx: Context, op: fn(f64) -> f64) -> Eval {
    let values = match numbers(function, args, 1, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match values[0] {
        Num::Int(i) => integer(i),
        Num::Double(d) if strict(cx) && d.is_infinite() => {
            unobserved(function, "an infinite number")
        }
        Num::Double(d) => double(op(d)),
    }
}

fn eval_round(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    if let Some(answer) = args.get(1).and_then(|arg| int_argument("round", arg, cx)) {
        if !args.first().is_some_and(is_missing) {
            return answer;
        }
    }
    let params = [Param::Number, Param::Int];
    let values = match check("round", args, &params, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    let number = Num::of(values[0]);
    let places = match values.get(1) {
        Some(Value::Integer(places)) => Some(*places),
        _ => None,
    };
    match (number, places) {
        (Num::Int(i), None) => integer(i),
        (Num::Int(i), Some(places)) if places >= 0 => {
            if strict(cx) {
                unobserved("round", "an integer and places of zero or more")
            } else {
                integer(i)
            }
        }
        (Num::Int(i), Some(places)) => round_integer(i, places, cx),
        (Num::Double(d), _) if strict(cx) && !d.is_finite() => {
            unobserved("round", "a number that is not finite")
        }
        (Num::Double(d), None) => double(d.round()),
        (Num::Double(d), Some(places)) => round_places(d, places, cx),
    }
}

/// A double rounded to `places` decimals, half away from zero. Places of 309 or more leave the
/// number alone (O-8B `round-huge-places`); the places the rows do not show are unobserved.
fn round_places(d: f64, places: i64, cx: Context) -> Eval {
    if places >= 309 {
        return double(d);
    }
    if strict(cx) && !(-15..=15).contains(&places) {
        return unobserved("round", "places the rows do not show");
    }
    if places < -308 {
        return double(0.0);
    }
    let Ok(exponent) = i32::try_from(places.abs()) else {
        return double(d);
    };
    // (`powi` is not exact for large exponents; the decimal text of the power is.)
    let scale: f64 = format!("1e{exponent}").parse().unwrap_or(f64::INFINITY);
    // A scaled number past the double range has no digits left to round away.
    if places >= 0 && !(d * scale).is_finite() {
        return double(d);
    }
    double(if places >= 0 {
        (d * scale).round() / scale
    } else {
        (d / scale).round() * scale
    })
}

/// An integer rounded to a power of ten, half away from zero.
fn round_integer(i: i64, places: i64, cx: Context) -> Eval {
    let overflow = || {
        if strict(cx) {
            unobserved("round", "an integer that rounds past the largest")
        } else {
            invalid("round(...) int64 overflow")
        }
    };
    let Some(digits) = places
        .checked_neg()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|digits| *digits <= 18)
    else {
        return if strict(cx) {
            unobserved("round", "places the rows do not show")
        } else {
            integer(0)
        };
    };
    let unit = 10i64.pow(digits);
    let rest = i % unit;
    let base = i - rest;
    let up = rest.unsigned_abs() * 2 >= unit.unsigned_abs();
    if !up {
        return integer(base);
    }
    let step = unit * i.signum();
    base.checked_add(step).map_or_else(overflow, integer)
}

fn eval_pow(args: &[Eval], cx: Context) -> Eval {
    let values = match numbers("pow", args, 2, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    let (base, exponent) = (values[0].double(), values[1].double());
    if strict(cx) && (!base.is_finite() || !exponent.is_finite()) {
        return unobserved("pow", "a number that is not finite");
    }
    if base < 0.0 && exponent.is_finite() && exponent.fract() != 0.0 {
        return invalid(
            "pow(...) the base cannot be negative when the exponent is not an integer.",
        );
    }
    double(base.powf(exponent))
}
