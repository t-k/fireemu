//! The logical, existence, type and membership functions (`FS-PIPELINE`): `and`, `or`, `not`,
//! `xor`, `nor`, `exists`, `is_absent`, `is_error`, `type`, `is_type`, `array_contains`,
//! `array_contains_all`, `array_contains_any`, `equal_any` and `not_equal_any`.
//!
//! Production answered these in FS-ENT-ORACLE O-1 (`px1/select`, `px1/where`) and O-6
//! (`where-functions-*`). The logic is three-valued: a null and a missing value are both
//! unknown, `false` decides an `and` and `true` an `or`. An operand that is neither a boolean
//! nor unknown fails the call, even when other documents are fine. What production did not
//! answer is `UNOBSERVED` under strict (`EvalError::Unobserved`).

use super::{
    first_error, type_name, values_equal, Arity, Context, Eval, EvalError, Function, Unrecorded,
};
use crate::value::Value;

const fn function(
    name: &'static str,
    arity: Arity,
    signature: &'static str,
    eval: fn(&[Eval], Context) -> Eval,
) -> Function {
    Function {
        name,
        arity,
        returns_boolean: true,
        signature,
        eval,
    }
}

pub(super) const AND: Function = function(
    "and",
    Arity::AtLeast(2),
    "and(x: boolean?*): boolean?",
    eval_and,
);
pub(super) const OR: Function = function(
    "or",
    Arity::AtLeast(2),
    "or(x: boolean?*): boolean?",
    eval_or,
);
pub(super) const NOT: Function =
    function("not", Arity::Exact(1), "not(x: boolean): boolean", eval_not);
pub(super) const XOR: Function = function(
    "xor",
    Arity::AtLeast(2),
    "xor(x: boolean*): boolean",
    eval_xor,
);
pub(super) const NOR: Function = function(
    "nor",
    Arity::AtLeast(2),
    "nor(x: boolean*): boolean",
    eval_nor,
);
pub(super) const EXISTS: Function = function(
    "exists",
    Arity::Exact(1),
    "exists(value: any?): boolean",
    eval_exists,
);
pub(super) const IS_ABSENT: Function = function(
    "is_absent",
    Arity::Exact(1),
    "is_absent(value: any?): boolean",
    eval_is_absent,
);
pub(super) const IS_ERROR: Function = function(
    "is_error",
    Arity::Exact(1),
    "is_error(try: any): boolean",
    eval_is_error,
);
pub(super) const TYPE: Function = Function {
    name: "type",
    arity: Arity::Exact(1),
    returns_boolean: false,
    signature: "type(input: any): string",
    eval: eval_type,
};
pub(super) const IS_TYPE: Function = function(
    "is_type",
    Arity::Exact(2),
    "is_type(value: any, type: (null|array|boolean|bytes|timestamp|geo_point|number|int32|int64|float64|decimal128|map|reference|string|vector|max_key|min_key|object_id|regex|bson_timestamp)): boolean",
    eval_is_type,
);
pub(super) const ARRAY_CONTAINS: Function = function(
    "array_contains",
    Arity::Exact(2),
    "array_contains(array: array[any], value: any): boolean",
    eval_array_contains,
);
pub(super) const ARRAY_CONTAINS_ALL: Function = function(
    "array_contains_all",
    Arity::Exact(2),
    "array_contains_all(array: array[any], search_values: array[any]): boolean",
    eval_array_contains_all,
);
pub(super) const ARRAY_CONTAINS_ANY: Function = function(
    "array_contains_any",
    Arity::Exact(2),
    "array_contains_any(array: array[any], search_values: array[any]): boolean",
    eval_array_contains_any,
);
pub(super) const EQUAL_ANY: Function = function(
    "equal_any",
    Arity::Exact(2),
    "equal_any(value: any, search_space: array[any]): boolean",
    eval_equal_any,
);
pub(super) const NOT_EQUAL_ANY: Function = function(
    "not_equal_any",
    Arity::Exact(2),
    "not_equal_any(value: any, search_space: array[any]): boolean",
    eval_not_equal_any,
);

/// The type names `is_type` takes, in the order production lists them.
pub const TYPE_NAMES: [&str; 20] = [
    "null",
    "array",
    "boolean",
    "bytes",
    "timestamp",
    "geo_point",
    "number",
    "int32",
    "int64",
    "float64",
    "decimal128",
    "map",
    "reference",
    "string",
    "vector",
    "max_key",
    "min_key",
    "object_id",
    "regex",
    "bson_timestamp",
];

fn unobserved(function: &'static str, reason: &'static str) -> Eval {
    Eval::Error(EvalError::Unobserved { function, reason })
}

fn wrong_type(function: &'static str, expected: &'static str, got: &Value) -> Eval {
    Eval::Error(EvalError::WrongType {
        function,
        expected,
        got: type_name(got),
    })
}

fn boolean(value: bool) -> Eval {
    Eval::Value(Value::Boolean(value))
}

fn null() -> Eval {
    Eval::Value(Value::Null)
}

/// The operands as three-valued booleans (`None` is unknown: null or missing), or the error the
/// first operand of another type gives. Under strict a wrong-typed operand beside one that
/// decides the call (`false` for an `and`, `true` for an `or`) is unobserved: whether
/// production fails or short-circuits was not recorded.
fn tri_state(
    function: &'static str,
    args: &[Eval],
    deciding: Option<bool>,
    cx: Context,
) -> Result<Vec<Option<bool>>, Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    let mut states = Vec::with_capacity(args.len());
    let mut wrong = None;
    for arg in args {
        match arg {
            Eval::Value(Value::Boolean(b)) => states.push(Some(*b)),
            Eval::Value(Value::Null) | Eval::Absent => states.push(None),
            Eval::Value(other) => {
                wrong.get_or_insert(other);
                states.push(None);
            }
            Eval::Error(_) => unreachable!("errors are returned above"),
        }
    }
    if let Some(value) = wrong {
        if cx.unrecorded == Unrecorded::Refuse
            && deciding.is_some_and(|decider| states.contains(&Some(decider)))
        {
            return Err(unobserved(
                function,
                "an operand of another type beside one that decides the call",
            ));
        }
        return Err(wrong_type(function, "Boolean", value));
    }
    Ok(states)
}

fn tri(state: Option<bool>) -> Eval {
    state.map_or_else(null, boolean)
}

fn or_of(states: &[Option<bool>]) -> Option<bool> {
    if states.contains(&Some(true)) {
        Some(true)
    } else if states.contains(&None) {
        None
    } else {
        Some(false)
    }
}

fn eval_and(args: &[Eval], cx: Context) -> Eval {
    match tri_state("and", args, Some(false), cx) {
        Ok(states) => tri(if states.contains(&Some(false)) {
            Some(false)
        } else if states.contains(&None) {
            None
        } else {
            Some(true)
        }),
        Err(error) => error,
    }
}

/// `or`: production answered two operands, and only `and` with three (O-6
/// `where-functions-truth#and3`); more operands of `or` are unobserved under strict, as for `xor`
/// and `nor`.
fn eval_or(args: &[Eval], cx: Context) -> Eval {
    if cx.unrecorded == Unrecorded::Refuse && args.len() > 2 {
        return unobserved("or", "more than two operands");
    }
    // Production failed an `or` with an operand of another type beside a `true` one (O-6
    // `where-functions-non-boolean#or`): no short circuit past a type error.
    match tri_state("or", args, None, cx) {
        Ok(states) => tri(or_of(&states)),
        Err(error) => error,
    }
}

fn eval_not(args: &[Eval], cx: Context) -> Eval {
    match tri_state("not", args, None, cx) {
        Ok(states) => tri(states[0].map(|b| !b)),
        Err(error) => error,
    }
}

/// `xor`: unknown when any operand is, else whether an odd number is true. Production answered
/// two operands; more are unobserved under strict.
fn eval_xor(args: &[Eval], cx: Context) -> Eval {
    if cx.unrecorded == Unrecorded::Refuse && args.len() > 2 {
        return unobserved("xor", "more than two operands");
    }
    match tri_state("xor", args, None, cx) {
        Ok(states) if states.contains(&None) => null(),
        Ok(states) => boolean(states.iter().filter(|s| **s == Some(true)).count() % 2 == 1),
        Err(error) => error,
    }
}

/// `nor`: the negation of `or`.
fn eval_nor(args: &[Eval], cx: Context) -> Eval {
    if cx.unrecorded == Unrecorded::Refuse && args.len() > 2 {
        return unobserved("nor", "more than two operands");
    }
    match tri_state("nor", args, Some(true), cx) {
        Ok(states) => tri(or_of(&states).map(|b| !b)),
        Err(error) => error,
    }
}

fn eval_exists(args: &[Eval], _cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    boolean(!matches!(args[0], Eval::Absent))
}

fn eval_is_absent(args: &[Eval], _cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    boolean(matches!(args[0], Eval::Absent))
}

/// `is_error(x)`: whether evaluating `x` failed. A refusal fireemu cannot classify stays one.
fn eval_is_error(args: &[Eval], _cx: Context) -> Eval {
    match &args[0] {
        Eval::Error(error @ EvalError::Unobserved { .. }) => Eval::Error(error.clone()),
        Eval::Error(_) => boolean(true),
        Eval::Value(_) | Eval::Absent => boolean(false),
    }
}

/// The name `type` gives a value: those of production's type list. Production evaluated `type`
/// over every kind (FS-ENT-ORACLE O-1 `px1/select#type-*`, O-6 `where-functions-kinds`).
fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Boolean(_) => "boolean",
        Value::Integer(_) => "int64",
        Value::Double(_) => "float64",
        Value::Timestamp(_) => "timestamp",
        Value::String(_) => "string",
        Value::Reference(_) => "reference",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Bytes(_) => "bytes",
        Value::GeoPoint(_) => "geo_point",
        Value::Vector(_) => "vector",
    }
}

fn eval_type(args: &[Eval], _cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    match &args[0] {
        Eval::Absent => null(),
        Eval::Value(value) => Eval::Value(Value::String(kind_name(value).to_owned())),
        Eval::Error(_) => unreachable!("errors are returned above"),
    }
}

/// `is_type(x, "name")`: whether `x` is of the type; unknown for a missing `x`. A name outside
/// the list is the adapter's refusal before any row. Production answered `null`, `array`,
/// `string`, `int64`, `float64` and `number`; strict refuses the other names.
fn eval_is_type(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let Eval::Value(Value::String(name)) = &args[1] else {
        return unobserved("is_type", "a type name that is no constant string");
    };
    if !TYPE_NAMES.contains(&name.as_str()) {
        return Eval::Error(EvalError::Invalid(format!(
            "The argument 'type' for function 'is_type' must be a literal of type string from the following list: [{}]",
            TYPE_NAMES.join(", ")
        )));
    }
    let recorded = matches!(
        name.as_str(),
        "null" | "array" | "string" | "int64" | "float64" | "number"
    );
    if cx.unrecorded == Unrecorded::Refuse && !recorded {
        return unobserved("is_type", "this type name");
    }
    // A missing value has no type: production answered null for `null` (O-1
    // `px1/select#is-type-x-null`) and dropped the row for the other names when the call is
    // the whole condition of a `where` (O-6 `where-functions-kinds`, which shows no
    // difference between null and false there). Strict answers nothing else.
    let Eval::Value(value) = &args[0] else {
        if cx.unrecorded == Unrecorded::Refuse && !cx.condition && name != "null" {
            return unobserved("is_type", "a missing value for this type name");
        }
        return null();
    };
    boolean(match name.as_str() {
        "null" => matches!(value, Value::Null),
        "array" => matches!(value, Value::Array(_)),
        "boolean" => matches!(value, Value::Boolean(_)),
        "bytes" => matches!(value, Value::Bytes(_)),
        "timestamp" => matches!(value, Value::Timestamp(_)),
        "geo_point" => matches!(value, Value::GeoPoint(_)),
        "number" => matches!(value, Value::Integer(_) | Value::Double(_)),
        "int64" => matches!(value, Value::Integer(_)),
        "float64" => matches!(value, Value::Double(_)),
        "map" => matches!(value, Value::Map(_)),
        "reference" => matches!(value, Value::Reference(_)),
        "string" => matches!(value, Value::String(_)),
        "vector" => matches!(value, Value::Vector(_)),
        // No stored value is of these types.
        _ => false,
    })
}

/// The array an array argument holds, or the answer for any other argument: a missing one is
/// unknown, another type fails the call naming the type it got.
fn array_argument<'a>(
    function: &'static str,
    arg: &'a Eval,
    cx: Context,
) -> Result<&'a [Value], Eval> {
    match arg {
        Eval::Value(Value::Array(values)) => Ok(values),
        Eval::Value(Value::Null) if cx.unrecorded == Unrecorded::Refuse => {
            Err(unobserved(function, "a null array argument"))
        }
        Eval::Absent | Eval::Value(Value::Null) => Err(null()),
        Eval::Value(other) => Err(wrong_type(function, "Array", other)),
        Eval::Error(_) => unreachable!("errors are returned by the caller"),
    }
}

fn contains(values: &[Value], wanted: &Eval) -> bool {
    match wanted {
        Eval::Value(wanted) => values.iter().any(|value| values_equal(value, wanted)),
        // A missing value equals nothing.
        _ => false,
    }
}

fn eval_array_contains(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    match array_argument("array_contains", &args[0], cx) {
        Ok(values) => boolean(contains(values, &args[1])),
        Err(answer) => answer,
    }
}

fn eval_array_contains_all(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let values = match array_argument("array_contains_all", &args[0], cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match array_argument("array_contains_all", &args[1], cx) {
        Ok(wanted) => boolean(
            wanted
                .iter()
                .all(|w| contains(values, &Eval::Value(w.clone()))),
        ),
        Err(answer) => answer,
    }
}

fn eval_array_contains_any(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let values = match array_argument("array_contains_any", &args[0], cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match array_argument("array_contains_any", &args[1], cx) {
        Ok(wanted) => boolean(
            wanted
                .iter()
                .any(|w| contains(values, &Eval::Value(w.clone()))),
        ),
        Err(answer) => answer,
    }
}

/// `equal_any(x, list)`: whether `x` equals an element; a missing `x` equals nothing. Production
/// named the failed call `eq_any` when the list was not an array.
fn eval_equal_any(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    match array_argument("eq_any", &args[1], cx) {
        Ok(list) => boolean(contains(list, &args[0])),
        Err(answer) => answer,
    }
}

/// `not_equal_any(x, list)`: the opposite, true for a missing `x`. Production did not answer a
/// list that is no array, so strict refuses it.
fn eval_not_equal_any(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    if cx.unrecorded == Unrecorded::Refuse && !matches!(args[1], Eval::Value(Value::Array(_))) {
        return unobserved("not_equal_any", "a list that is no array");
    }
    match array_argument("not_eq_any", &args[1], cx) {
        Ok(list) => boolean(!contains(list, &args[0])),
        Err(answer) => answer,
    }
}
