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

/// The result of a Kleene `and` or `or` read left to right: the operands are examined in order
/// and the first one that decides the call (`decider`) ends it, so an operand of another type
/// after it is never looked at, while one before it (or with no decider at all) fails the call
/// (FS-ENT-ORACLE O-9 `ops-main`: `and(false, 1)` is false, `and(1, false)`, `and(true, 1)` and
/// `and(null, 1)` fail; likewise `or(true, 1)` against `or(1, true)`, `or(false, 1)` and
/// `or(null, 1)`). A null or missing operand is unknown. `None` is the unknown result.
fn left_to_right(
    function: &'static str,
    args: &[Eval],
    decider: bool,
    cx: Context,
) -> Result<Option<bool>, Eval> {
    if let Some(error) = first_error(args) {
        // An operand whose own evaluation fails is reported before the walk, wherever it
        // stands, so `or(true, not(1))` fails with the error of `not` although `true` decides
        // first. Production was not asked about an error-valued operand beside a deciding one
        // (O-9 `ops-main` only has constants of the wrong type, which a deciding operand
        // before them hides): the emulator profile answers the error, strict says it is
        // unobserved whatever a recording of the same shape might hold.
        if cx.unrecorded == Unrecorded::Refuse
            && args
                .iter()
                .any(|arg| matches!(arg, Eval::Value(Value::Boolean(b)) if *b == decider))
        {
            return Err(unobserved(
                function,
                "an operand that fails beside one that decides the call",
            ));
        }
        return Err(error);
    }
    let mut unknown = false;
    for arg in args {
        match arg {
            Eval::Value(Value::Boolean(b)) if *b == decider => return Ok(Some(decider)),
            Eval::Value(Value::Boolean(_)) => {}
            Eval::Value(Value::Null) | Eval::Absent => unknown = true,
            Eval::Value(other) => return Err(wrong_type(function, "Boolean", other)),
            Eval::Error(_) => unreachable!("errors are returned above"),
        }
    }
    Ok(if unknown { None } else { Some(!decider) })
}

/// The operands of `xor`, all of them boolean: `None` when one is null or missing, since the
/// parity of an unknown is unknown (production answered null at any position, O-9 `ops-main`).
fn all_booleans(function: &'static str, args: &[Eval]) -> Result<Vec<Option<bool>>, Eval> {
    if let Some(error) = first_error(args) {
        return Err(error);
    }
    args.iter()
        .map(|arg| match arg {
            Eval::Value(Value::Boolean(b)) => Ok(Some(*b)),
            Eval::Value(Value::Null) | Eval::Absent => Ok(None),
            Eval::Value(other) => Err(wrong_type(function, "Boolean", other)),
            Eval::Error(_) => unreachable!("errors are returned above"),
        })
        .collect()
}

fn tri(state: Option<bool>) -> Eval {
    state.map_or_else(null, boolean)
}

fn eval_and(args: &[Eval], cx: Context) -> Eval {
    match left_to_right("and", args, false, cx) {
        Ok(state) => tri(state),
        Err(error) => error,
    }
}

fn eval_or(args: &[Eval], cx: Context) -> Eval {
    match left_to_right("or", args, true, cx) {
        Ok(state) => tri(state),
        Err(error) => error,
    }
}

fn eval_not(args: &[Eval], _cx: Context) -> Eval {
    match all_booleans("not", args) {
        Ok(states) => tri(states[0].map(|b| !b)),
        Err(error) => error,
    }
}

/// `xor`: unknown when any operand is, else whether an odd number is true (two to five operands
/// were recorded, O-6 and O-9).
fn eval_xor(args: &[Eval], _cx: Context) -> Eval {
    match all_booleans("xor", args) {
        Ok(states) if states.contains(&None) => null(),
        Ok(states) => boolean(states.iter().filter(|s| **s == Some(true)).count() % 2 == 1),
        Err(error) => error,
    }
}

/// `nor`: the negation of `or`, read left to right like it.
fn eval_nor(args: &[Eval], cx: Context) -> Eval {
    match left_to_right("nor", args, true, cx) {
        Ok(state) => tri(state.map(|b| !b)),
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
/// the list is the adapter's refusal before any row. Production answered every name of the list
/// (FS-ENT-ORACLE O-9b `types-matrix`): a missing value gives null whatever the name (the name
/// `null` included), a stored value gives true for its own type and false for every other, and
/// the names no stored value has (`int32`, `decimal128`, `max_key`, ...) give false.
fn eval_is_type(args: &[Eval], _cx: Context) -> Eval {
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
    let Eval::Value(value) = &args[0] else {
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
/// unknown, another type fails the call naming the type it got. A null one is unknown too,
/// which production answered for `array_contains` (first argument), `array_contains_any`
/// (second) and `not_equal_any` (second) only (O-9 `ops-main`); strict refuses the others.
fn array_argument<'a>(
    function: &'static str,
    arg: &'a Eval,
    null_recorded: bool,
    cx: Context,
) -> Result<&'a [Value], Eval> {
    match arg {
        Eval::Value(Value::Array(values)) => Ok(values),
        Eval::Value(Value::Null) if cx.unrecorded == Unrecorded::Refuse && !null_recorded => {
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
    match array_argument("array_contains", &args[0], true, cx) {
        Ok(values) => boolean(contains(values, &args[1])),
        Err(answer) => answer,
    }
}

fn eval_array_contains_all(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    let values = match array_argument("array_contains_all", &args[0], false, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match array_argument("array_contains_all", &args[1], false, cx) {
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
    let values = match array_argument("array_contains_any", &args[0], false, cx) {
        Ok(values) => values,
        Err(answer) => return answer,
    };
    match array_argument("array_contains_any", &args[1], true, cx) {
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
    match array_argument("eq_any", &args[1], false, cx) {
        Ok(list) => boolean(contains(list, &args[0])),
        Err(answer) => answer,
    }
}

/// `not_equal_any(x, list)`: the opposite, true for a missing `x`. Production named the failed
/// call `eq_any` when the list was not an array, as for `equal_any` (O-9 `ops-main`).
fn eval_not_equal_any(args: &[Eval], cx: Context) -> Eval {
    if let Some(error) = first_error(args) {
        return error;
    }
    match array_argument("eq_any", &args[1], true, cx) {
        Ok(list) => boolean(!contains(list, &args[0])),
        Err(answer) => answer,
    }
}
