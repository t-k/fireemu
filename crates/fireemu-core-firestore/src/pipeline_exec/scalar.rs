//! The string and math functions of a pipeline (`FS-PIPELINE`): `concat`, `to_lower`,
//! `to_upper`, `starts_with`, `ends_with`, `string_contains`, `char_length`, `substring`,
//! `trim`, `ltrim`, `rtrim`, `split`, `add`, `subtract`, `multiply`, `divide`, `mod`, `abs`,
//! `round`, `floor`, `ceil`, `pow` and `sqrt`.
//!
//! The existing functions were observed in production by FS-ENT-ORACLE O-8B (2026-10-26, an Enterprise
//! database, two identical recordings; `fs-ent-pipeline/o8b/strings-main` and `math-main`).
//! SQRT has only a recorded wrong-type refusal and empty-input witnesses (O-1); numeric
//! behavior is not established by those rows. The rules the O-8B rows show:
//!
//! - A null or a missing argument gives null.
//! - An argument of the wrong type fails the whole request with
//!   ``The function f(...) requires `T` but got `U`.`` (the type names are production's).
//! - Integer arithmetic is checked: an overflow fails the request, except that `divide` wraps
//!   and `mod` answers 0 for `int64::MIN` by `-1`.
//!
//! What production did not answer is [`EvalError::Unobserved`] under strict (the arguments of
//! a shape no row covers, a null beside a wrong type, a function used as a whole `where`
//! condition); the emulator profile evaluates it by the same rules. Regex inputs use a bounded
//! Rust regex engine; general RE2 equivalence beyond the recorded cases is not established.

use super::{
    first_error, type_name, Arity, Context, Eval, EvalError, Function, RegexError, RegexOperation,
    RegexResult, Unrecorded, ZoneError, ZoneOperation, ZoneResult,
};
use crate::value::{Timestamp, Value};

/// The function names this module defines, for callers that must tell them from the rest.
pub const NAMES: [&str; 55] = [
    "current_timestamp",
    "timestamp_trunc",
    "timestamp_extract",
    "timestamp_add",
    "timestamp_subtract",
    "timestamp_diff",
    "unix_micros_to_timestamp",
    "unix_millis_to_timestamp",
    "unix_seconds_to_timestamp",
    "timestamp_to_unix_micros",
    "timestamp_to_unix_millis",
    "timestamp_to_unix_seconds",
    "like",
    "regex_contains",
    "regex_match",
    "regex_find",
    "regex_find_all",
    "concat",
    "to_lower",
    "to_upper",
    "starts_with",
    "ends_with",
    "string_contains",
    "char_length",
    "byte_length",
    "string_index_of",
    "string_repeat",
    "string_replace_all",
    "string_replace_one",
    "string_reverse",
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
    "sqrt",
    "vector_length",
    "dot_product",
    "euclidean_distance",
    "cosine_distance",
    "exp",
    "ln",
    "log",
    "log10",
    "trunc",
];

pub(super) const LIKE: Function = function(
    "like",
    Arity::Exact(2),
    true,
    "like[T: string | regex](search_space: string, pattern: T): boolean",
    &[],
    eval_like,
);

pub(super) const CURRENT_TIMESTAMP: Function = function(
    "current_timestamp",
    Arity::Exact(0),
    false,
    "current_timestamp(): timestamp",
    &[],
    |_, cx| {
        cx.runtime.request_timestamp.map_or_else(
            || unobserved("current_timestamp", "request clock is unavailable"),
            |value| Eval::Value(Value::Timestamp(value)),
        )
    },
);

pub(super) const TIMESTAMP_TRUNC: Function = function("timestamp_trunc", Arity::Between(2, 3), false, "", &[
    ("timestamp_trunc[T: timestamp | bson_timestamp](timestamp: T, granularity: (microsecond|millisecond|second|minute|hour|day|week|week(monday)|week(tuesday)|week(wednesday)|week(thursday)|week(friday)|week(saturday)|week(sunday)|isoweek|month|quarter|year|isoyear)): timestamp", 2, 2),
    ("timestamp_trunc[T: timestamp | bson_timestamp](timestamp: T, granularity: (microsecond|millisecond|second|minute|hour|day|week|week(monday)|week(tuesday)|week(wednesday)|week(thursday)|week(friday)|week(saturday)|week(sunday)|isoweek|month|quarter|year|isoyear), time_zone: string): timestamp", 3, 3),
], eval_timestamp_trunc);
pub(super) const TIMESTAMP_EXTRACT: Function = function("timestamp_extract", Arity::Between(2, 3), false, "", &[
    ("timestamp_extract[T: timestamp | bson_timestamp](timestamp: T, part: (microsecond|millisecond|second|minute|hour|dayofweek|day|dayofyear|week|week(monday)|week(tuesday)|week(wednesday)|week(thursday)|week(friday)|week(saturday)|week(sunday)|isoweek|month|quarter|year|isoyear)): int64", 2, 2),
    ("timestamp_extract[T: timestamp | bson_timestamp](timestamp: T, part: (microsecond|millisecond|second|minute|hour|dayofweek|day|dayofyear|week|week(monday)|week(tuesday)|week(wednesday)|week(thursday)|week(friday)|week(saturday)|week(sunday)|isoweek|month|quarter|year|isoyear), time_zone: string): int64", 3, 3),
], eval_timestamp_extract);

pub(super) const TIMESTAMP_ADD: Function = function("timestamp_add", Arity::Exact(3), false, "timestamp_add[T: timestamp | bson_timestamp](timestamp: T, unit: (microsecond|millisecond|second|minute|hour|day), amount: int64): timestamp", &[], |args, cx| timestamp_shift("timestamp_add", args, cx.clone(), false));
pub(super) const TIMESTAMP_SUBTRACT: Function = function("timestamp_subtract", Arity::Exact(3), false, "timestamp_subtract[T: timestamp | bson_timestamp](timestamp: T, unit: (microsecond|millisecond|second|minute|hour|day), amount: int64): timestamp", &[], |args, cx| timestamp_shift("timestamp_subtract", args, cx.clone(), true));
pub(super) const TIMESTAMP_DIFF: Function = function("timestamp_diff", Arity::Exact(3), false, "timestamp_diff[T1: timestamp | bson_timestamp, T2: timestamp | bson_timestamp](end: T1, start: T2, unit: (microsecond|millisecond|second|minute|hour|day)): int64", &[], timestamp_diff);

pub(super) const UNIX_MICROS_TO_TIMESTAMP: Function = function(
    "unix_micros_to_timestamp",
    Arity::Exact(1),
    false,
    "unix_micros_to_timestamp(input: int64): timestamp",
    &[],
    |args, cx| unix_to_timestamp("unix_micros_to_timestamp", args, cx.clone(), 1_000_000),
);
pub(super) const UNIX_MILLIS_TO_TIMESTAMP: Function = function(
    "unix_millis_to_timestamp",
    Arity::Exact(1),
    false,
    "unix_millis_to_timestamp(input: int64): timestamp",
    &[],
    |args, cx| unix_to_timestamp("unix_millis_to_timestamp", args, cx.clone(), 1_000),
);
pub(super) const UNIX_SECONDS_TO_TIMESTAMP: Function = function(
    "unix_seconds_to_timestamp",
    Arity::Exact(1),
    false,
    "unix_seconds_to_timestamp(input: int64): timestamp",
    &[],
    |args, cx| unix_to_timestamp("unix_seconds_to_timestamp", args, cx.clone(), 1),
);
pub(super) const TIMESTAMP_TO_UNIX_MICROS: Function = function(
    "timestamp_to_unix_micros",
    Arity::Exact(1),
    false,
    "timestamp_to_unix_micros[T: timestamp | bson_timestamp](input: T): int64",
    &[],
    |args, cx| timestamp_to_unix("timestamp_to_unix_micros", args, cx.clone(), 1_000_000),
);
pub(super) const TIMESTAMP_TO_UNIX_MILLIS: Function = function(
    "timestamp_to_unix_millis",
    Arity::Exact(1),
    false,
    "timestamp_to_unix_millis[T: timestamp | bson_timestamp](input: T): int64",
    &[],
    |args, cx| timestamp_to_unix("timestamp_to_unix_millis", args, cx.clone(), 1_000),
);
pub(super) const TIMESTAMP_TO_UNIX_SECONDS: Function = function(
    "timestamp_to_unix_seconds",
    Arity::Exact(1),
    false,
    "timestamp_to_unix_seconds[T: timestamp | bson_timestamp](input: T): int64",
    &[],
    |args, cx| timestamp_to_unix("timestamp_to_unix_seconds", args, cx.clone(), 1),
);

const REGEX_CONTAINS_SIGNATURE: &str =
    "regex_contains[T: string | regex](search_space: string, regexp: T): boolean";
const REGEX_MATCH_SIGNATURE: &str =
    "regex_match[T: string | regex](search_space: string, regexp: T): boolean";
const REGEX_FIND_SIGNATURE: &str =
    "regex_find[T: string | regex](search_space: string, regexp: T): string?";
const REGEX_FIND_ALL_SIGNATURE: &str =
    "regex_find_all[T: string | regex](search_space: string, regexp: T): array[string?]";

pub(super) const REGEX_CONTAINS: Function = function(
    "regex_contains",
    Arity::Exact(2),
    true,
    REGEX_CONTAINS_SIGNATURE,
    &[],
    eval_regex_contains,
);
pub(super) const REGEX_MATCH: Function = function(
    "regex_match",
    Arity::Exact(2),
    true,
    REGEX_MATCH_SIGNATURE,
    &[],
    eval_regex_match,
);
pub(super) const REGEX_FIND: Function = function(
    "regex_find",
    Arity::Exact(2),
    false,
    REGEX_FIND_SIGNATURE,
    &[],
    eval_regex_find,
);
pub(super) const REGEX_FIND_ALL: Function = function(
    "regex_find_all",
    Arity::Exact(2),
    false,
    REGEX_FIND_ALL_SIGNATURE,
    &[],
    eval_regex_find_all,
);

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
pub(super) const BYTE_LENGTH: Function = function(
    "byte_length",
    Arity::Exact(1),
    false,
    "byte_length[T: string | bytes](input: T): int64",
    &[],
    eval_byte_length,
);
pub(super) const STRING_INDEX_OF: Function = function(
    "string_index_of",
    Arity::Exact(2),
    false,
    "string_index_of[T: string | bytes](value: T, search: T): int64",
    &[],
    eval_string_index_of,
);
pub(super) const STRING_REPEAT: Function = function(
    "string_repeat",
    Arity::Exact(2),
    false,
    "string_repeat[T: string | bytes](input: T, repetitions: int64): T",
    &[],
    eval_string_repeat,
);
pub(super) const STRING_REPLACE_ALL: Function = function(
    "string_replace_all",
    Arity::Exact(3),
    false,
    "string_replace_all[T: string | bytes](input: T, find: T, replacement: T): T",
    &[],
    |args, cx| eval_string_replace("string_replace_all", args, cx.clone(), true),
);
pub(super) const STRING_REPLACE_ONE: Function = function(
    "string_replace_one",
    Arity::Exact(3),
    false,
    "string_replace_one[T: string | bytes](input: T, find: T, replacement: T): T",
    &[],
    |args, cx| eval_string_replace("string_replace_one", args, cx.clone(), false),
);
pub(super) const STRING_REVERSE: Function = function(
    "string_reverse",
    Arity::Exact(1),
    false,
    "string_reverse[T: string | bytes](input: T): T",
    &[],
    eval_string_reverse,
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
// Production records the two overloads when either function is called with no arguments.
pub(super) const LTRIM: Function = function(
    "ltrim",
    Arity::Between(1, 2),
    false,
    "",
    &[
        ("ltrim[T: string | bytes](value: T): T", 1, 1),
        ("ltrim[T: string | bytes](value: T, to_trim: T): T", 2, 2),
    ],
    eval_ltrim,
);
pub(super) const RTRIM: Function = function(
    "rtrim",
    Arity::Between(1, 2),
    false,
    "",
    &[
        ("rtrim[T: string | bytes](value: T): T", 1, 1),
        ("rtrim[T: string | bytes](value: T, to_trim: T): T", 2, 2),
    ],
    eval_rtrim,
);
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

pub(super) const SQRT: Function = function(
    "sqrt",
    Arity::Exact(1),
    false,
    "sqrt(number: number): float64",
    &[],
    eval_sqrt,
);

pub(super) const VECTOR_LENGTH: Function = function(
    "vector_length",
    Arity::Exact(1),
    false,
    "vector_length(vector: vector): int64",
    &[],
    eval_vector_length,
);
pub(super) const DOT_PRODUCT: Function = function(
    "dot_product",
    Arity::Exact(2),
    false,
    "dot_product(x: vector, y: vector): float64",
    &[],
    |args, _cx| {
        eval_vector_distance(
            "dot_product",
            args,
            crate::query::DistanceMeasure::DotProduct,
        )
    },
);
pub(super) const EUCLIDEAN_DISTANCE: Function = function(
    "euclidean_distance",
    Arity::Exact(2),
    false,
    "euclidean_distance(x: vector, y: vector): float64",
    &[],
    |args, _cx| {
        eval_vector_distance(
            "euclidean_distance",
            args,
            crate::query::DistanceMeasure::Euclidean,
        )
    },
);
pub(super) const COSINE_DISTANCE: Function = function(
    "cosine_distance",
    Arity::Exact(2),
    false,
    "cosine_distance(x: vector, y: vector): float64",
    &[],
    |args, _cx| {
        eval_vector_distance(
            "cosine_distance",
            args,
            crate::query::DistanceMeasure::Cosine,
        )
    },
);

fn eval_vector_length(args: &[Eval], _cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let [Eval::Value(Value::Vector(vector))] = args else {
        return unobserved("vector_length", "an unrecorded argument shape");
    };
    i64::try_from(vector.len()).map_or_else(
        |_| unobserved("vector_length", "vector length exceeds int64"),
        |length| Eval::Value(Value::Integer(length)),
    )
}

fn eval_vector_distance(
    name: &'static str,
    args: &[Eval],
    measure: crate::query::DistanceMeasure,
) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let [Eval::Value(Value::Vector(left)), Eval::Value(Value::Vector(right))] = args else {
        return unobserved(name, "an unrecorded argument shape");
    };
    if left.is_empty()
        || left.len() != right.len()
        || left.iter().chain(right).any(|v| !v.is_finite())
    {
        return unobserved(name, "an empty, mismatched or non-finite vector");
    }
    let result = if measure == crate::query::DistanceMeasure::Cosine {
        super::pipeline_vector_distance(left, right, measure)
    } else {
        crate::store::vector_distance(left, right, measure)
    };
    result.map_or_else(
        || unobserved(name, "a distance outside the finite supported domain"),
        |value| Eval::Value(Value::Double(value)),
    )
}

pub(super) const EXP: Function = function(
    "exp",
    Arity::Exact(1),
    false,
    "exp(exponent: number): number",
    &[],
    eval_exp,
);
pub(super) const LN: Function = function(
    "ln",
    Arity::Exact(1),
    false,
    "ln(number: number): number",
    &[],
    eval_ln,
);
pub(super) const LOG: Function = function(
    "log",
    Arity::Between(1, 2),
    false,
    "",
    &[
        ("log(number: number): number", 1, 1),
        ("log(number: number, base: number): number", 2, 2),
    ],
    eval_log,
);
pub(super) const LOG10: Function = function(
    "log10",
    Arity::Exact(1),
    false,
    "log10(number: number): number",
    &[],
    eval_log10,
);
pub(super) const TRUNC: Function = function(
    "trunc",
    Arity::Between(1, 2),
    false,
    "",
    &[
        ("trunc[T <: number](number: T): T", 1, 1),
        ("trunc[T <: number](number: T, places: int64): T", 2, 2),
    ],
    eval_trunc,
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
    /// A timestamp.
    Timestamp,
    /// A timestamp named with the recorded BSON alternative.
    TimestampOrBson,
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
            Self::Timestamp | Self::TimestampOrBson => matches!(value, Value::Timestamp(_)),
        }
    }

    fn expected(self) -> &'static str {
        match self {
            Self::Str(text) => text,
            Self::StrOrBytes => "String | Bytes",
            Self::StrOrBytesAsString => "String",
            Self::Int => "Int64",
            Self::Number => "Number",
            Self::Timestamp => "Timestamp",
            Self::TimestampOrBson => "Timestamp or BsonTimestamp",
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
        if missing && strict(cx.clone()) {
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
pub(super) fn int_argument(function: &'static str, arg: &Eval, cx: Context) -> Option<Eval> {
    let Eval::Value(Value::Double(d)) = arg else {
        return None;
    };
    Some(match java_double(*d) {
        Some(text) => invalid(format!("Cannot coerce Float64 ({text}) to Int64")),
        None if strict(cx.clone()) => unobserved(function, "a double with no recorded text"),
        None => invalid(format!("Cannot coerce Float64 ({d:?}) to Int64")),
    })
}

/// Recognize a conservative common RE2/Rust grammar without interpreting escaped literals as syntax.
/// Constructs outside this subset are unobserved, not reported as production syntax failures.
fn common_regex_grammar(pattern: &str) -> bool {
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some(
                    '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^'
                    | '$',
                ) => {}
                Some(_) => return false,
                None => return true,
            },
            '[' if in_class => return false,
            '[' => in_class = true,
            ']' if in_class => in_class = false,
            '&' | '-' | '~' if in_class && chars.peek() == Some(&ch) => return false,
            '{' | '}' if !in_class => return false,
            '(' if !in_class && chars.peek() == Some(&'?') => {
                chars.next();
                if chars.peek() == Some(&':') {
                    chars.next();
                    continue;
                }
                let mut has_flag = false;
                loop {
                    match chars.next() {
                        Some('i' | 'm' | 's' | 'U') => has_flag = true,
                        Some('-') => {}
                        Some(':' | ')') if has_flag => break,
                        Some(_) => return false,
                        None => return true,
                    }
                }
            }
            _ => {}
        }
    }
    true
}

const TRUNC_PARTS: &str = "[microsecond, millisecond, second, minute, hour, day, week, week(monday), week(tuesday), week(wednesday), week(thursday), week(friday), week(saturday), week(sunday), isoweek, month, quarter, year, isoyear]";
const EXTRACT_PARTS: &str = "[microsecond, millisecond, second, minute, hour, dayofweek, day, dayofyear, week, week(monday), week(tuesday), week(wednesday), week(thursday), week(friday), week(saturday), week(sunday), isoweek, month, quarter, year, isoyear]";

fn calendar_unit(name: &'static str, arg: &Eval, extract: bool) -> Result<String, Eval> {
    let allowed = if extract { EXTRACT_PARTS } else { TRUNC_PARTS };
    if let Eval::Value(Value::String(unit)) = arg {
        if allowed[1..allowed.len() - 1]
            .split(", ")
            .any(|item| item == unit)
        {
            return Ok(unit.clone());
        }
    }
    let label = if extract { "part" } else { "granularity" };
    Err(invalid(format!("The argument '{label}' for function '{name}' must be a literal of type string from the following list: {allowed}")))
}

fn calendar_values(
    name: &'static str,
    args: &[Eval],
    cx: Context,
    extract: bool,
) -> Result<(Timestamp, String, Option<String>), Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    let unit = calendar_unit(name, &args[1], extract)?;
    let params = if args.len() == 3 {
        vec![Param::Timestamp, Param::Str("String"), Param::Str("String")]
    } else {
        vec![Param::Timestamp, Param::Str("String")]
    };
    let values = check(name, args, &params, cx.clone())?;
    let Value::Timestamp(timestamp) = values[0] else {
        unreachable!()
    };
    let zone = if args.len() == 3 {
        let Value::String(zone) = values[2] else {
            unreachable!()
        };
        Some(zone.clone())
    } else {
        None
    };
    Ok((*timestamp, unit, zone))
}

fn resolve_zone(
    name: &'static str,
    timestamp: Timestamp,
    zone: &str,
    unit: &str,
    operation: ZoneOperation,
    cx: Context,
) -> Eval {
    let Some(resolver) = cx.runtime.zone_resolver else {
        return unobserved(name, "named time zone resolver is unavailable");
    };
    match resolver(timestamp, zone, unit, operation) {
        Ok(ZoneResult::Timestamp(value)) => Eval::Value(Value::Timestamp(value)),
        Ok(ZoneResult::Integer(value)) => Eval::Value(Value::Integer(value)),
        Err(ZoneError::InvalidZone) => invalid(format!("{name}(...) given an invalid timezone")),
        Err(ZoneError::Unsupported) => unobserved(name, "custom GMT offsets are unobserved"),
        Err(ZoneError::Ambiguous) => {
            unobserved(name, "time zone boundary is ambiguous or nonexistent")
        }
        Err(ZoneError::OutOfRange) => {
            Eval::Error(EvalError::TimestampOutOfRange { function: name })
        }
    }
}

pub(super) fn local_calendar_value(
    timestamp: Timestamp,
    unit: &str,
    operation: ZoneOperation,
) -> Result<ZoneResult, ZoneError> {
    let args = [
        Eval::Value(Value::Timestamp(timestamp)),
        Eval::Value(Value::String(unit.to_owned())),
    ];
    let cx = Context {
        unrecorded: Unrecorded::Refuse,
        condition: false,
        runtime: super::RuntimeContext::default(),
    };
    let result = match operation {
        ZoneOperation::Trunc => eval_timestamp_trunc(&args, cx.clone()),
        ZoneOperation::Extract => eval_timestamp_extract(&args, cx.clone()),
    };
    match result {
        Eval::Value(Value::Timestamp(value)) => Ok(ZoneResult::Timestamp(value)),
        Eval::Value(Value::Integer(value)) => Ok(ZoneResult::Integer(value)),
        _ => Err(ZoneError::OutOfRange),
    }
}

fn week_start(days: i64, start: i64) -> i64 {
    let weekday = (days + 4).rem_euclid(7);
    days - (weekday - start).rem_euclid(7)
}

fn iso_year_start(year: i64) -> i64 {
    week_start(fireemu_core_types::time::days_from_civil(year, 1, 4), 1)
}

fn week_day(unit: &str) -> Option<i64> {
    match unit {
        "week" | "week(sunday)" => Some(0),
        "week(monday)" | "isoweek" => Some(1),
        "week(tuesday)" => Some(2),
        "week(wednesday)" => Some(3),
        "week(thursday)" => Some(4),
        "week(friday)" => Some(5),
        "week(saturday)" => Some(6),
        _ => None,
    }
}

fn eval_timestamp_trunc(args: &[Eval], cx: Context) -> Eval {
    let (timestamp, unit, zone) = match calendar_values("timestamp_trunc", args, cx.clone(), false)
    {
        Ok(value) => value,
        Err(error) => return error,
    };
    if let Some(zone) = zone {
        return resolve_zone(
            "timestamp_trunc",
            timestamp,
            &zone,
            &unit,
            ZoneOperation::Trunc,
            cx,
        );
    }
    let seconds = timestamp.seconds();
    let days = seconds.div_euclid(86_400);
    let (year, month, _) = fireemu_core_types::time::civil_from_days(days);
    let (seconds, nanos) = match unit.as_str() {
        "microsecond" => (seconds, timestamp.nanos() / 1_000 * 1_000),
        "millisecond" => (seconds, timestamp.nanos() / 1_000_000 * 1_000_000),
        "second" => (seconds, 0),
        "minute" => (seconds.div_euclid(60) * 60, 0),
        "hour" => (seconds.div_euclid(3_600) * 3_600, 0),
        "day" => (days * 86_400, 0),
        "month" => (
            fireemu_core_types::time::days_from_civil(year, month, 1) * 86_400,
            0,
        ),
        "quarter" => (
            fireemu_core_types::time::days_from_civil(year, (month - 1) / 3 * 3 + 1, 1) * 86_400,
            0,
        ),
        "year" => (
            fireemu_core_types::time::days_from_civil(year, 1, 1) * 86_400,
            0,
        ),
        "isoyear" => {
            let (iso_year, _, _) =
                fireemu_core_types::time::civil_from_days(days + (3 - (days + 3).rem_euclid(7)));
            (iso_year_start(iso_year) * 86_400, 0)
        }
        other => (week_start(days, week_day(other).unwrap_or(0)) * 86_400, 0),
    };
    match Timestamp::new(seconds, nanos) {
        Ok(value) => Eval::Value(Value::Timestamp(value)),
        Err(_) => Eval::Error(EvalError::TimestampOutOfRange {
            function: "timestamp_trunc",
        }),
    }
}

fn eval_timestamp_extract(args: &[Eval], cx: Context) -> Eval {
    let (timestamp, unit, zone) = match calendar_values("timestamp_extract", args, cx.clone(), true)
    {
        Ok(value) => value,
        Err(error) => return error,
    };
    if let Some(zone) = zone {
        return resolve_zone(
            "timestamp_extract",
            timestamp,
            &zone,
            &unit,
            ZoneOperation::Extract,
            cx,
        );
    }
    let seconds = timestamp.seconds();
    let days = seconds.div_euclid(86_400);
    let within_day = seconds.rem_euclid(86_400);
    let (year, month, day) = fireemu_core_types::time::civil_from_days(days);
    let first = fireemu_core_types::time::days_from_civil(year, 1, 1);
    let day_of_year = days - first;
    let value = match unit.as_str() {
        "microsecond" => i64::from(timestamp.nanos() / 1_000),
        "millisecond" => i64::from(timestamp.nanos() / 1_000_000),
        "second" => within_day % 60,
        "minute" => within_day / 60 % 60,
        "hour" => within_day / 3_600,
        "dayofweek" => (days + 4).rem_euclid(7) + 1,
        "day" => day,
        "dayofyear" => day_of_year + 1,
        "month" => month,
        "quarter" => (month - 1) / 3 + 1,
        "year" => year,
        "isoyear" | "isoweek" => {
            let (iso_year, _, _) =
                fireemu_core_types::time::civil_from_days(days + (3 - (days + 3).rem_euclid(7)));
            if unit == "isoyear" {
                iso_year
            } else {
                (days - iso_year_start(iso_year)) / 7 + 1
            }
        }
        other => {
            let start = week_day(other).unwrap_or(0);
            let first_start = (start - (first + 4).rem_euclid(7)).rem_euclid(7);
            if day_of_year < first_start {
                0
            } else {
                1 + (day_of_year - first_start) / 7
            }
        }
    };
    Eval::Value(Value::Integer(value))
}

const TIMESTAMP_UNITS: &str = "[microsecond, millisecond, second, minute, hour, day]";

fn timestamp_unit(name: &'static str, unit: &Eval) -> Result<i64, Eval> {
    let scale = match unit {
        Eval::Value(Value::String(unit)) => match unit.as_str() {
            "microsecond" => Some(1_i64),
            "millisecond" => Some(1_000),
            "second" => Some(1_000_000),
            "minute" => Some(60_000_000),
            "hour" => Some(3_600_000_000),
            "day" => Some(86_400_000_000),
            _ => None,
        },
        _ => None,
    };
    scale.ok_or_else(|| invalid(format!("The argument 'unit' for function '{name}' must be a literal of type string from the following list: {TIMESTAMP_UNITS}")))
}

fn timestamp_shift(name: &'static str, args: &[Eval], cx: Context, subtract: bool) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let scale = match timestamp_unit(name, &args[1]) {
        Ok(scale) => scale,
        Err(error) => return error,
    };
    if let Some(error) = int_argument(name, &args[2], cx.clone()) {
        return error;
    }
    let error_name = if subtract { "timestamp_sub" } else { name };
    let values = match check(
        error_name,
        args,
        &[Param::TimestampOrBson, Param::Str("String"), Param::Int],
        cx,
    ) {
        Ok(values) => values,
        Err(value) => return value,
    };
    let [Value::Timestamp(timestamp), Value::String(_), Value::Integer(amount)] = values.as_slice()
    else {
        unreachable!()
    };
    let Some(micros) = amount.checked_mul(scale).and_then(|value| {
        if subtract {
            value.checked_neg()
        } else {
            Some(value)
        }
    }) else {
        return invalid(format!("{name}(...) result is out of range"));
    };
    let nanos = i128::from(timestamp.seconds()) * 1_000_000_000
        + i128::from(timestamp.nanos())
        + i128::from(micros) * 1_000;
    let seconds = nanos.div_euclid(1_000_000_000);
    let fraction = u32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap_or(0);
    let timestamp = i64::try_from(seconds)
        .ok()
        .and_then(|seconds| Timestamp::new(seconds, fraction).ok());
    match timestamp {
        Some(timestamp) => Eval::Value(Value::Timestamp(timestamp)),
        None => Eval::Error(EvalError::TimestampOutOfRange {
            function: if subtract {
                "timestamp_sub"
            } else {
                "timestamp_add"
            },
        }),
    }
}

fn timestamp_diff(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let scale = match timestamp_unit("timestamp_diff", &args[2]) {
        Ok(scale) => scale,
        Err(error) => return error,
    };
    let values = match check(
        "timestamp_diff",
        args,
        &[Param::Timestamp, Param::Timestamp, Param::Str("String")],
        cx,
    ) {
        Ok(values) => values,
        Err(value) => return value,
    };
    let [Value::Timestamp(end), Value::Timestamp(start), Value::String(_)] = values.as_slice()
    else {
        unreachable!()
    };
    let end_nanos = i128::from(end.seconds()) * 1_000_000_000 + i128::from(end.nanos());
    let start_nanos = i128::from(start.seconds()) * 1_000_000_000 + i128::from(start.nanos());
    match i64::try_from((end_nanos - start_nanos) / (i128::from(scale) * 1_000)) {
        Ok(value) => Eval::Value(Value::Integer(value)),
        Err(_) => invalid("timestamp_diff(...) result is out of range"),
    }
}

/// Convert signed Unix units without losing subsecond precision at negative epochs.
fn unix_to_timestamp(name: &'static str, args: &[Eval], cx: Context, scale: i64) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    if let Some(error) = int_argument(name, &args[0], cx.clone()) {
        return error;
    }
    let values = match check(name, args, &[Param::Int], cx.clone()) {
        Ok(values) => values,
        Err(value) => return value,
    };
    let [Value::Integer(value)] = values.as_slice() else {
        unreachable!()
    };
    let seconds = value.div_euclid(scale);
    let nanos = u32::try_from(value.rem_euclid(scale) * (1_000_000_000 / scale)).unwrap_or(0);
    match Timestamp::new(seconds, nanos) {
        Ok(timestamp) => Eval::Value(Value::Timestamp(timestamp)),
        Err(_) => invalid(format!("{name}(...) argument out of range")),
    }
}

/// Convert a bounded timestamp to Unix units, truncating fractional units toward the past.
fn timestamp_to_unix(name: &'static str, args: &[Eval], cx: Context, scale: i64) -> Eval {
    let values = match check(name, args, &[Param::Timestamp], cx.clone()) {
        Ok(values) => values,
        Err(value) => return value,
    };
    let [Value::Timestamp(value)] = values.as_slice() else {
        unreachable!()
    };
    let fraction = i64::from(value.nanos()) / (1_000_000_000 / scale);
    match value
        .seconds()
        .checked_mul(scale)
        .and_then(|seconds| seconds.checked_add(fraction))
    {
        Some(value) => Eval::Value(Value::Integer(value)),
        None => invalid(format!("{name}(...) result is out of range")),
    }
}

/// Compile a bounded pattern and preserve the distinction between syntax and resource limits.
fn regex_eval(name: &'static str, args: &[Eval], cx: Context, operation: RegexOperation) -> Eval {
    let values = match check(
        name,
        args,
        &[Param::Str("String"), Param::Str("String or Regex")],
        cx.clone(),
    ) {
        Ok(values) => values,
        Err(error) => return error,
    };
    let [Value::String(subject), Value::String(pattern)] = values.as_slice() else {
        unreachable!()
    };
    if strict(cx.clone()) && !common_regex_grammar(pattern) {
        return unobserved(name, "a regex construct outside the common RE2 grammar");
    }
    let Some(resolver) = cx.runtime.regex_resolver else {
        return unobserved(name, "no regex resolver is available");
    };
    match (operation, resolver(subject, pattern, operation)) {
        (_, Err(RegexError::InvalidSyntax)) => invalid("Unsupported regex syntax."),
        (_, Err(RegexError::ResourceLimit)) => {
            unobserved(name, "regex compilation exceeded local resources")
        }
        (RegexOperation::Contains | RegexOperation::Match, Ok(RegexResult::Boolean(value))) => {
            Eval::Value(Value::Boolean(value))
        }
        (RegexOperation::Find, Ok(RegexResult::Match(value))) => {
            value.map_or_else(null, |value| Eval::Value(Value::String(value)))
        }
        (RegexOperation::FindAll, Ok(RegexResult::Matches(values))) => Eval::Value(Value::Array(
            values
                .into_iter()
                .map(|value| value.map_or(Value::Null, Value::String))
                .collect(),
        )),
        _ => unobserved(name, "the regex resolver returned an incompatible result"),
    }
}

fn eval_like(args: &[Eval], cx: Context) -> Eval {
    let values = match check(
        "like",
        args,
        &[Param::Str("String"), Param::Str("String")],
        cx.clone(),
    ) {
        Ok(values) => values,
        Err(error) => return error,
    };
    let [Value::String(subject), Value::String(pattern)] = values.as_slice() else {
        unreachable!()
    };
    let mut regex = String::from("(?s)");
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        let literal = match ch {
            '%' => {
                regex.push_str(".*");
                continue;
            }
            '_' => {
                regex.push('.');
                continue;
            }
            '\\' => match chars.next() {
                Some(escaped) => escaped,
                None => return unobserved("like", "a trailing escape is unobserved"),
            },
            other => other,
        };
        if "\\.^$|?*+()[]{}".contains(literal) {
            regex.push('\\');
        }
        regex.push(literal);
    }
    let Some(resolver) = cx.runtime.regex_resolver else {
        return unobserved("like", "no regex resolver is available");
    };
    match resolver(subject, &regex, RegexOperation::Match) {
        Ok(RegexResult::Boolean(value)) => Eval::Value(Value::Boolean(value)),
        Err(RegexError::InvalidSyntax) => invalid("Unsupported regex syntax."),
        Err(RegexError::ResourceLimit) => {
            unobserved("like", "regex compilation exceeded local resources")
        }
        _ => unobserved("like", "the regex resolver returned an incompatible result"),
    }
}

fn eval_regex_contains(args: &[Eval], cx: Context) -> Eval {
    regex_eval("regex_contains", args, cx.clone(), RegexOperation::Contains)
}

fn eval_regex_match(args: &[Eval], cx: Context) -> Eval {
    regex_eval("regex_match", args, cx.clone(), RegexOperation::Match)
}

fn eval_regex_find(args: &[Eval], cx: Context) -> Eval {
    regex_eval("regex_find", args, cx.clone(), RegexOperation::Find)
}

fn eval_regex_find_all(args: &[Eval], cx: Context) -> Eval {
    regex_eval("regex_find_all", args, cx.clone(), RegexOperation::FindAll)
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
            return if strict(cx.clone()) {
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
                if strict(cx.clone()) && (expected != "STRING" || args.iter().any(is_missing)) {
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
    let values = match check(function, args, &[Param::StrOrBytes], cx.clone()) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match values[0] {
        Value::String(s) if strict(cx.clone()) && !case_recorded(s) => unobserved(
            function,
            "a Greek sigma, whose case mapping depends on its position",
        ),
        Value::String(s) => Eval::Value(Value::String(text(s))),
        // Production answered the bytes `[1]` unchanged; a letter among the bytes is a case the
        // rows do not show.
        Value::Bytes(b) if strict(cx.clone()) && b.iter().any(u8::is_ascii_alphabetic) => {
            unobserved(function, "bytes holding ASCII letters")
        }
        Value::Bytes(b) => Eval::Value(Value::Bytes(b.iter().map(byte).collect())),
        _ => unreachable!("checked above"),
    }
}

fn eval_starts_with(args: &[Eval], cx: Context) -> Eval {
    two_strings("starts_with", args, cx.clone(), |value, prefix| {
        value.starts_with(prefix)
    })
}

fn eval_ends_with(args: &[Eval], cx: Context) -> Eval {
    two_strings("ends_with", args, cx.clone(), |value, suffix| {
        value.ends_with(suffix)
    })
}

fn eval_string_contains(args: &[Eval], cx: Context) -> Eval {
    two_strings("string_contains", args, cx.clone(), |value, part| {
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
    if cx.condition && strict(cx.clone()) {
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
    let values = match check("char_length", args, &[Param::Str("String")], cx.clone()) {
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

// The recorded cases use string arguments; other types and null are not promoted.
fn recorded_string_args<'a>(
    function: &'static str,
    args: &'a [Eval],
    cx: Context,
    params: &[Param],
) -> Result<Vec<&'a Value>, Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    if strict(cx.clone())
        && args.iter().zip(params).any(|(arg, param)| {
            !matches!(
                (arg, param),
                (Eval::Value(Value::String(_)), Param::Str(_))
                    | (Eval::Value(Value::Integer(_)), Param::Int)
            )
        })
    {
        return Err(unobserved(function, "an unrecorded argument type or null"));
    }
    check(function, args, params, cx.clone())
}

fn eval_byte_length(args: &[Eval], cx: Context) -> Eval {
    let values =
        match recorded_string_args("byte_length", args, cx.clone(), &[Param::Str("String")]) {
            Ok(v) => v,
            Err(e) => return e,
        };
    let Value::String(value) = values[0] else {
        unreachable!("checked above")
    };
    Eval::Value(Value::Integer(
        i64::try_from(value.len()).unwrap_or(i64::MAX),
    ))
}

fn eval_string_index_of(args: &[Eval], cx: Context) -> Eval {
    let values = match recorded_string_args(
        "string_index_of",
        args,
        cx.clone(),
        &[Param::Str("String"), Param::Str("String")],
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (Value::String(value), Value::String(search)) = (values[0], values[1]) else {
        unreachable!("checked above")
    };
    if strict(cx.clone()) && !value.is_ascii() && !search.is_empty() {
        return unobserved("string_index_of", "a non-ASCII search offset");
    }
    let index = value.find(search).map_or(-1, |byte| {
        i64::try_from(value[..byte].chars().count()).unwrap_or(i64::MAX)
    });
    Eval::Value(Value::Integer(index))
}

fn eval_string_repeat(args: &[Eval], cx: Context) -> Eval {
    let values = match recorded_string_args(
        "string_repeat",
        args,
        cx,
        &[Param::Str("String"), Param::Int],
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (Value::String(value), Value::Integer(count)) = (values[0], values[1]) else {
        unreachable!("checked above")
    };
    if *count < 0 {
        return invalid("string_repeat(...) repetition must be non-negative");
    }
    if value.is_empty() || *count == 0 {
        return Eval::Value(Value::String(String::new()));
    }
    let Ok(count) = usize::try_from(*count) else {
        return unobserved("string_repeat", "an excessive output size");
    };
    // This local bound protects allocation; it is not a production limit claim.
    if value
        .len()
        .checked_mul(count)
        .is_none_or(|size| size > 1_048_576)
    {
        return unobserved("string_repeat", "an excessive output size");
    }
    Eval::Value(Value::String(value.repeat(count)))
}

fn eval_string_replace(function: &'static str, args: &[Eval], cx: Context, all: bool) -> Eval {
    let values = match recorded_string_args(
        function,
        args,
        cx,
        &[
            Param::Str("String"),
            Param::Str("String"),
            Param::Str("String"),
        ],
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (Value::String(value), Value::String(find), Value::String(replacement)) =
        (values[0], values[1], values[2])
    else {
        unreachable!("checked above")
    };
    if find.is_empty() {
        return Eval::Value(Value::String(value.clone()));
    }
    let matches = if all {
        value.matches(find).count()
    } else {
        usize::from(value.contains(find))
    };
    let Some(size) = value
        .len()
        .checked_sub(matches.saturating_mul(find.len()))
        .and_then(|n| {
            replacement
                .len()
                .checked_mul(matches)
                .and_then(|extra| n.checked_add(extra))
        })
    else {
        return unobserved(function, "an excessive output size");
    };
    if size > 1_048_576 {
        return unobserved(function, "an excessive output size");
    }
    Eval::Value(Value::String(if all {
        value.replace(find, replacement)
    } else {
        value.replacen(find, replacement, 1)
    }))
}

fn eval_string_reverse(args: &[Eval], cx: Context) -> Eval {
    let values =
        match recorded_string_args("string_reverse", args, cx.clone(), &[Param::Str("String")]) {
            Ok(v) => v,
            Err(e) => return e,
        };
    let Value::String(value) = values[0] else {
        unreachable!("checked above")
    };
    Eval::Value(Value::String(value.chars().rev().collect()))
}

fn eval_substring(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    // A null length was not asked.
    if strict(cx.clone()) && args.get(2).is_some_and(is_missing) {
        return unobserved("substring", "a null length");
    }
    if let Some(answer) = args
        .get(1)
        .and_then(|arg| int_argument("substring", arg, cx.clone()))
    {
        if !args.first().is_some_and(is_missing) {
            return answer;
        }
    }
    if let Some(answer) = args
        .get(2)
        .and_then(|arg| int_argument("substring", arg, cx.clone()))
    {
        return answer;
    }
    let params = [Param::StrOrBytes, Param::Int, Param::Int];
    let values = match check("substring", args, &params, cx.clone()) {
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
        if start < 0 && strict(cx.clone()) {
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
    let values = match check(function, args, &params, cx.clone()) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values.get(1)) {
        (Value::String(s), None) => trim_string(function, s, None, cx.clone(), ends),
        (Value::String(s), Some(Value::String(set))) => {
            trim_string(function, s, Some(set), cx.clone(), ends)
        }
        (Value::Bytes(b), None) => {
            let space = |byte: &u8| byte.is_ascii_whitespace();
            if strict(cx.clone())
                && ((ends.start && b.first().is_some_and(space))
                    || (ends.end && b.last().is_some_and(space)))
            {
                return unobserved(function, "bytes with white space at an end");
            }
            Eval::Value(Value::Bytes(trim_slice(b, space, ends).to_vec()))
        }
        (Value::Bytes(b), Some(Value::Bytes(set))) => {
            if strict(cx.clone()) {
                return unobserved(function, "bytes to trim");
            }
            Eval::Value(Value::Bytes(
                trim_slice(b, |byte| set.contains(byte), ends).to_vec(),
            ))
        }
        _ => {
            if strict(cx.clone()) {
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
    if strict(cx.clone()) {
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
    let values = match check("split", args, &params, cx.clone()) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values.get(1).copied()) {
        (Value::String(s), None) => {
            // One argument splits at commas; the one row shows a text with none.
            if strict(cx.clone()) && s.contains(',') {
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
                if strict(cx.clone()) && s.is_empty() {
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
                return if strict(cx.clone()) {
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
            if strict(cx.clone()) {
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
            if strict(cx.clone()) {
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
    check(function, args, &params, cx.clone())
        .map(|values| values.into_iter().map(Num::of).collect())
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
    let values = match numbers(function, args, 2, cx.clone()) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values[1]) {
        (Num::Int(a), Num::Int(b)) => exact(a, b).map_or_else(|| invalid(overflow), integer),
        (a, b) => double(float(a.double(), b.double())),
    }
}

fn eval_divide(args: &[Eval], cx: Context) -> Eval {
    let values = match numbers("divide", args, 2, cx.clone()) {
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
        (a, b) if strict(cx.clone()) => {
            let _ = (a, b);
            unobserved("divide", "an integer by a double")
        }
        (a, b) => double(a.double() / b.double()),
    }
}

fn eval_mod(args: &[Eval], cx: Context) -> Eval {
    let values = match numbers("mod", args, 2, cx.clone()) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match (values[0], values[1]) {
        (Num::Int(_), Num::Int(0)) => invalid("mod(...) requires a non-zero divisor"),
        // The remainder of the smallest integer by -1 is 0 (O-8B `mod-min-by-minus-one`).
        (Num::Int(a), Num::Int(b)) => integer(a.wrapping_rem(b)),
        (Num::Double(a), Num::Double(b)) => double(a % b),
        (a, b) if strict(cx.clone()) => {
            let _ = (a, b);
            unobserved("mod", "an integer and a double")
        }
        (a, b) => double(a.double() % b.double()),
    }
}

fn eval_abs(args: &[Eval], cx: Context) -> Eval {
    let values = match numbers("abs", args, 1, cx.clone()) {
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
    rounding("floor", args, cx.clone(), f64::floor)
}

fn eval_ceil(args: &[Eval], cx: Context) -> Eval {
    rounding("ceil", args, cx.clone(), f64::ceil)
}

/// An integer stays as it is; a double goes to a whole double. Infinity was not shown.
fn rounding(function: &'static str, args: &[Eval], cx: Context, op: fn(f64) -> f64) -> Eval {
    let values = match numbers(function, args, 1, cx.clone()) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match values[0] {
        Num::Int(i) => integer(i),
        Num::Double(d) if strict(cx.clone()) && d.is_infinite() => {
            unobserved(function, "an infinite number")
        }
        Num::Double(d) => double(op(d)),
    }
}

fn eval_round(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    if let Some(answer) = args
        .get(1)
        .and_then(|arg| int_argument("round", arg, cx.clone()))
    {
        if !args.first().is_some_and(is_missing) {
            return answer;
        }
    }
    let params = [Param::Number, Param::Int];
    let values = match check("round", args, &params, cx.clone()) {
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
            if strict(cx.clone()) {
                unobserved("round", "an integer and places of zero or more")
            } else {
                integer(i)
            }
        }
        (Num::Int(i), Some(places)) => round_integer(i, places, cx.clone()),
        (Num::Double(d), _) if strict(cx.clone()) && !d.is_finite() => {
            unobserved("round", "a number that is not finite")
        }
        (Num::Double(d), None) => double(d.round()),
        (Num::Double(d), Some(places)) => round_places(d, places, cx.clone()),
    }
}

/// A double rounded to `places` decimals, half away from zero. Places of 309 or more leave the
/// number alone (O-8B `round-huge-places`); the places the rows do not show are unobserved.
fn round_places(d: f64, places: i64, cx: Context) -> Eval {
    if places >= 309 {
        return double(d);
    }
    if strict(cx.clone()) && !(-15..=15).contains(&places) {
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
        if strict(cx.clone()) {
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
        return if strict(cx.clone()) {
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
    let values = match numbers("pow", args, 2, cx.clone()) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    let (base, exponent) = (values[0].double(), values[1].double());
    if strict(cx.clone()) && (!base.is_finite() || !exponent.is_finite()) {
        return unobserved("pow", "a number that is not finite");
    }
    if base < 0.0 && exponent.is_finite() && exponent.fract() != 0.0 {
        return invalid(
            "pow(...) the base cannot be negative when the exponent is not an integer.",
        );
    }
    double(base.powf(exponent))
}

fn eval_sqrt(args: &[Eval], cx: Context) -> Eval {
    let values = match numeric_inputs("sqrt", args, cx.clone()) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    let value = values[0].double();
    if value < 0.0 {
        invalid("sqrt(...) cannot be used on negative numbers")
    } else {
        double(value.sqrt())
    }
}

fn numeric_inputs(name: &'static str, args: &[Eval], cx: Context) -> Result<Vec<Num>, Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    if !strict(cx.clone())
        && args.len() == 1
        && matches!(name, "exp" | "ln" | "log" | "log10")
        && matches!(&args[0], Eval::Value(Value::String(_)))
    {
        return Err(Eval::Error(EvalError::WrongType {
            function: if name == "log" { "ln" } else { name },
            expected: "Float",
            got: "STRING",
        }));
    }
    if !strict(cx.clone()) && name == "sqrt" {
        if let Some(Eval::Value(value)) = args.first() {
            if !matches!(value, Value::Null | Value::Integer(_) | Value::Double(_)) {
                return Err(Eval::Error(EvalError::WrongType {
                    function: "sqrt",
                    expected: "Float",
                    got: type_name(value),
                }));
            }
        }
    }
    if strict(cx.clone()) {
        if args.len() == 1 {
            match &args[0] {
                Eval::Value(Value::Null) => return Err(null()),
                Eval::Value(Value::String(_)) => {
                    return Err(Eval::Error(EvalError::WrongType {
                        function: if name == "log" { "ln" } else { name },
                        expected: if name == "trunc" { "Number" } else { "Float" },
                        got: "STRING",
                    }))
                }
                _ => {}
            }
        }
        if !args.iter().all(|a| match a {
            Eval::Value(Value::Integer(_)) => true,
            Eval::Value(Value::Double(d)) => d.is_finite() && !(d.is_sign_negative() && *d == 0.0),
            _ => false,
        }) {
            return Err(unobserved(
                name,
                "argument shape or special value is unobserved",
            ));
        }
    }
    numbers(name, args, args.len(), cx.clone())
}

fn eval_exp(args: &[Eval], cx: Context) -> Eval {
    match numeric_inputs("exp", args, cx.clone()) {
        Ok(v) => {
            let input = v[0].double();
            let result = input.exp();
            if input.is_finite() && (result.is_infinite() || result == 0.0) {
                invalid("exp(...) overflow or underflow")
            } else if input.is_finite() && result.is_subnormal() {
                unobserved("exp", "subnormal underflow behavior is unobserved")
            } else {
                double(result)
            }
        }
        Err(e) => e,
    }
}
fn logarithm(name: &'static str, args: &[Eval], cx: Context) -> Eval {
    let values = match numeric_inputs(name, args, cx.clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let x = values[0].double();
    let base = values.get(1).map(|v| v.double());
    if base.is_some_and(|b| {
        (x.is_nan() || x == f64::NEG_INFINITY) && (b <= 0.0 || b.to_bits() == 1.0_f64.to_bits())
    }) || (x <= 0.0 && base.is_some_and(|b| b.is_nan() || b == f64::INFINITY))
    {
        return unobserved(name, "mixed special and invalid arguments");
    }
    if x.is_nan()
        || x == f64::NEG_INFINITY
        || base.is_some_and(f64::is_nan)
        || base == Some(f64::INFINITY)
    {
        return double(f64::NAN);
    }
    if x <= 0.0 || base.is_some_and(|b| b <= 0.0 || b.to_bits() == 1.0_f64.to_bits()) {
        if name == "log" && base.is_some() {
            return invalid(
                "log(...) base must be larger than 0 and argument must be larger than 0",
            );
        }
        let label = if name == "log" { "ln" } else { name };
        return match java_double(x) {
            Some(value) => invalid(format!(
                "{label}(...) requires a positive number but got {value}"
            )),
            None => unobserved(name, "domain error text is unobserved"),
        };
    }
    double(match base {
        Some(b) => x.log(b),
        None if name == "log10" => x.log10(),
        None => x.ln(),
    })
}
fn eval_ln(args: &[Eval], cx: Context) -> Eval {
    logarithm("ln", args, cx.clone())
}
fn eval_log(args: &[Eval], cx: Context) -> Eval {
    logarithm("log", args, cx.clone())
}
fn eval_log10(args: &[Eval], cx: Context) -> Eval {
    logarithm("log10", args, cx.clone())
}
fn eval_trunc(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    if strict(cx.clone()) && args.len() == 1 {
        match &args[0] {
            Eval::Value(Value::Null) => return null(),
            Eval::Value(Value::String(_)) => {
                return Eval::Error(EvalError::WrongType {
                    function: "trunc",
                    expected: "Number",
                    got: "STRING",
                })
            }
            _ => {}
        }
    }
    if strict(cx.clone())
        && (args.iter().any(is_missing)
            || args
                .iter()
                .any(|a| matches!(a, Eval::Value(Value::Double(d)) if !d.is_finite())))
    {
        return unobserved("trunc", "argument shape or special value is unobserved");
    }
    if strict(cx.clone())
        && !args.iter().enumerate().all(|(i, arg)| match (i, arg) {
            (0 | 1, Eval::Value(Value::Integer(_))) => true,
            (0, Eval::Value(Value::Double(d))) => {
                d.is_finite() && !(d.is_sign_negative() && *d == 0.0)
            }
            _ => false,
        })
    {
        return unobserved("trunc", "argument shape is unobserved");
    }
    let values = match check("trunc", args, &[Param::Number, Param::Int], cx.clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let places = values
        .get(1)
        .and_then(|v| {
            if let Value::Integer(i) = v {
                Some(*i)
            } else {
                None
            }
        })
        .unwrap_or(0);
    if places != 0 {
        return unobserved("trunc", "nonzero decimal precision is unobserved");
    }
    match Num::of(values[0]) {
        Num::Int(i) => integer(i),
        Num::Double(d) => double(d.trunc()),
    }
}
