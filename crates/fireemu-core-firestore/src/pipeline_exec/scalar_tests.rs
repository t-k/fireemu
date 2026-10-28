//! The string and math functions against the FS-ENT-ORACLE O-8B rows and reference models.
#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::float_cmp,
    clippy::too_many_lines
)]

use super::scalar::NAMES;
use super::*;
use proptest::prelude::*;

fn text(s: &str) -> Eval {
    Eval::Value(Value::String(s.to_owned()))
}

fn int(i: i64) -> Eval {
    Eval::Value(Value::Integer(i))
}

fn dbl(d: f64) -> Eval {
    Eval::Value(Value::Double(d))
}

fn bytes(b: &[u8]) -> Eval {
    Eval::Value(Value::Bytes(b.to_vec()))
}

fn null() -> Eval {
    Eval::Value(Value::Null)
}

fn array(items: Vec<Value>) -> Eval {
    Eval::Value(Value::Array(items))
}

fn call_in(name: &str, args: &[Eval], unrecorded: Unrecorded, condition: bool) -> Eval {
    (function(name).unwrap().eval)(
        args,
        Context {
            unrecorded,
            condition,
        },
    )
}

fn strict(name: &str, args: &[Eval]) -> Eval {
    call_in(name, args, Unrecorded::Refuse, false)
}

fn emulator(name: &str, args: &[Eval]) -> Eval {
    call_in(name, args, Unrecorded::OfficialEmulator, false)
}

/// The answer in both profiles, which must agree.
fn both(name: &str, args: &[Eval]) -> Eval {
    let (a, b) = (strict(name, args), emulator(name, args));
    // (Compared as text: a NaN is not equal to itself.)
    assert_eq!(format!("{a:?}"), format!("{b:?}"), "{name} {args:?}");
    a
}

fn is_unobserved(eval: &Eval) -> bool {
    matches!(eval, Eval::Error(EvalError::Unobserved { .. }))
}

fn wrong(function: &'static str, expected: &'static str, got: &'static str) -> Eval {
    Eval::Error(EvalError::WrongType {
        function,
        expected,
        got,
    })
}

fn invalid(message: &str) -> Eval {
    Eval::Error(EvalError::Invalid(message.to_owned()))
}

#[test]
fn the_table_holds_exactly_the_named_functions() {
    for name in NAMES {
        assert!(function(name).is_some(), "{name}");
    }
    assert_eq!(NAMES.len(), 26);
    assert!(function("sqrt").is_none());
}

#[test]
fn a_null_or_missing_argument_gives_null_in_every_position() {
    let cases: Vec<(&str, Vec<Eval>)> = vec![
        ("concat", vec![null(), text("a")]),
        ("concat", vec![text("a"), Eval::Absent]),
        ("to_lower", vec![null()]),
        ("to_upper", vec![Eval::Absent]),
        ("starts_with", vec![null(), text("a")]),
        ("starts_with", vec![text("a"), Eval::Absent]),
        ("ends_with", vec![Eval::Absent, text("a")]),
        ("string_contains", vec![text("a"), null()]),
        ("char_length", vec![null()]),
        ("substring", vec![null(), int(1)]),
        ("substring", vec![text("abc"), null()]),
        ("trim", vec![null()]),
        ("ltrim", vec![Eval::Absent]),
        ("rtrim", vec![null()]),
        ("split", vec![null(), text(",")]),
        ("split", vec![text("a,b"), Eval::Absent]),
        ("add", vec![null(), int(1)]),
        ("subtract", vec![Eval::Absent, int(1)]),
        ("multiply", vec![int(1), null()]),
        ("divide", vec![null(), int(1)]),
        ("mod", vec![Eval::Absent, int(1)]),
        ("abs", vec![null()]),
        ("round", vec![Eval::Absent]),
        ("floor", vec![null()]),
        ("ceil", vec![Eval::Absent]),
        ("pow", vec![null(), int(2)]),
    ];
    for (name, args) in cases {
        assert_eq!(both(name, &args), null(), "{name} {args:?}");
    }
}

#[test]
fn a_wrong_type_fails_with_production_names_and_a_null_beside_it_is_unobserved_under_strict() {
    let cases: Vec<(&str, Vec<Eval>, &'static str, &'static str, &'static str)> = vec![
        (
            "concat",
            vec![text("a"), bytes(&[1])],
            "concat",
            "STRING",
            "BYTES",
        ),
        (
            "concat",
            vec![text("a"), int(1)],
            "concat",
            "STRING",
            "LONG",
        ),
        (
            "to_lower",
            vec![int(1)],
            "to_lower",
            "String | Bytes",
            "LONG",
        ),
        (
            "to_upper",
            vec![int(1)],
            "to_upper",
            "String | Bytes",
            "LONG",
        ),
        (
            "starts_with",
            vec![int(1), text("a")],
            "starts_with",
            "String",
            "LONG",
        ),
        (
            "starts_with",
            vec![text("a"), int(1)],
            "starts_with",
            "String",
            "LONG",
        ),
        (
            "starts_with",
            vec![bytes(&[1]), bytes(&[1])],
            "starts_with",
            "String",
            "BYTES",
        ),
        (
            "ends_with",
            vec![bytes(&[1]), bytes(&[1])],
            "ends_with",
            "String",
            "BYTES",
        ),
        (
            "string_contains",
            vec![int(1), text("a")],
            "string_contains",
            "String",
            "LONG",
        ),
        (
            "char_length",
            vec![bytes(&[1])],
            "char_length",
            "String",
            "BYTES",
        ),
        ("char_length", vec![int(1)], "char_length", "String", "LONG"),
        (
            "substring",
            vec![int(12345), int(1)],
            "substring",
            "String | Bytes",
            "LONG",
        ),
        ("trim", vec![int(1)], "trim", "String | Bytes", "LONG"),
        ("ltrim", vec![int(1)], "ltrim", "String | Bytes", "LONG"),
        ("rtrim", vec![int(1)], "rtrim", "String | Bytes", "LONG"),
        ("split", vec![int(1), text(",")], "split", "String", "LONG"),
        ("add", vec![text("a"), int(1)], "add", "Number", "STRING"),
        (
            "add",
            vec![Eval::Value(Value::Boolean(true)), int(1)],
            "add",
            "Number",
            "BOOLEAN",
        ),
        (
            "subtract",
            vec![text("a"), int(1)],
            "subtract",
            "Number",
            "STRING",
        ),
        (
            "multiply",
            vec![text("a"), int(1)],
            "multiply",
            "Number",
            "STRING",
        ),
        (
            "divide",
            vec![text("a"), int(1)],
            "divide",
            "Number",
            "STRING",
        ),
        ("mod", vec![text("a"), int(1)], "mod", "Number", "STRING"),
        ("abs", vec![text("a")], "abs", "Number", "STRING"),
        ("round", vec![text("a")], "round", "Number", "STRING"),
        ("floor", vec![text("a")], "floor", "Number", "STRING"),
        ("ceil", vec![text("a")], "ceil", "Number", "STRING"),
        ("pow", vec![text("a"), int(2)], "pow", "Number", "STRING"),
    ];
    for (name, args, function, expected, got) in cases {
        assert_eq!(
            both(name, &args),
            wrong(function, expected, got),
            "{name} {args:?}"
        );
        // A null in another position: the order of the two answers was not shown.
        let mut with_null = args.clone();
        // (`concat` takes its kind from the first value that is not null, so a null in front
        // of the wrong one changes the kind.)
        if args.len() > 1 && name != "concat" {
            // Replace the argument that is not the wrong one by a null.
            let wrong_at = args
                .iter()
                .position(|arg| matches!(arg, Eval::Value(v) if type_name(v) == got))
                .unwrap();
            let other = usize::from(wrong_at == 0);
            with_null[other] = null();
            assert!(
                is_unobserved(&strict(name, &with_null)),
                "{name} {with_null:?}"
            );
            assert_eq!(
                emulator(name, &with_null),
                wrong(function, expected, got),
                "{name} {with_null:?}"
            );
        }
    }
}

#[test]
fn strings_follow_the_recorded_rows() {
    assert_eq!(both("concat", &[text("ab"), text("cd")]), text("abcd"));
    assert_eq!(
        both("concat", &[text("a"), text("b"), text("c")]),
        text("abc")
    );
    assert_eq!(both("concat", &[text(""), text("")]), text(""));
    assert_eq!(
        both("concat", &[text("héllo ☃😀"), text("x")]),
        text("héllo ☃😀x")
    );
    assert_eq!(both("concat", &[bytes(&[1]), bytes(&[2])]), bytes(&[1, 2]));
    assert_eq!(
        both(
            "concat",
            &[
                array(vec![Value::Integer(1)]),
                array(vec![Value::Integer(2)])
            ]
        ),
        array(vec![Value::Integer(1), Value::Integer(2)])
    );
    assert_eq!(both("to_lower", &[text("ABC")]), text("abc"));
    assert_eq!(both("to_lower", &[text("ÀÉ☃")]), text("àé☃"));
    assert_eq!(both("to_lower", &[text("İ")]), text("i\u{307}"));
    assert_eq!(both("to_upper", &[text("ß")]), text("SS"));
    assert_eq!(both("to_upper", &[text("àé☃")]), text("ÀÉ☃"));
    assert_eq!(both("to_lower", &[bytes(&[1])]), bytes(&[1]));
    assert_eq!(both("to_upper", &[bytes(&[1])]), bytes(&[1]));
    assert_eq!(both("char_length", &[text("😀")]), int(1));
    assert_eq!(both("char_length", &[text("e\u{301}")]), int(2));
    assert_eq!(both("char_length", &[text("")]), int(0));
    for (value, prefix, starts, ends) in [
        ("Hello", "He", true, false),
        ("Hello", "lo", false, true),
        ("Hello", "", true, true),
        ("", "a", false, false),
        ("He", "Hello", false, false),
        ("Hello", "he", false, false),
    ] {
        let args = [text(value), text(prefix)];
        let bool_of = |b| Eval::Value(Value::Boolean(b));
        assert_eq!(
            both("starts_with", &args),
            bool_of(starts),
            "{value} {prefix}"
        );
        assert_eq!(both("ends_with", &args), bool_of(ends), "{value} {prefix}");
    }
    assert_eq!(
        both("string_contains", &[text("Hello World"), text("o W")]),
        Eval::Value(Value::Boolean(true))
    );
    assert_eq!(
        both("string_contains", &[text("Hello"), text("")]),
        Eval::Value(Value::Boolean(true))
    );
}

#[test]
fn a_boolean_string_function_is_not_answered_as_a_strict_where_condition() {
    for name in ["starts_with", "ends_with", "string_contains"] {
        let args = [text("Hello"), text("He")];
        assert!(is_unobserved(&call_in(
            name,
            &args,
            Unrecorded::Refuse,
            true
        )));
        assert_eq!(
            call_in(name, &args, Unrecorded::OfficialEmulator, true),
            call_in(name, &args, Unrecorded::OfficialEmulator, false)
        );
    }
}

#[test]
fn substring_follows_the_recorded_rows() {
    let s = "Hello World";
    assert_eq!(both("substring", &[text(s), int(6)]), text("World"));
    assert_eq!(both("substring", &[text(s), int(0), int(5)]), text("Hello"));
    assert_eq!(both("substring", &[text(s), int(-5)]), text("World"));
    assert_eq!(both("substring", &[text(s), int(100)]), text(""));
    assert_eq!(both("substring", &[text(s), int(0), int(0)]), text(""));
    assert_eq!(
        both("substring", &[text("héllo ☃😀"), int(1), int(2)]),
        text("él")
    );
    assert_eq!(
        both("substring", &[text(s), int(0), int(i64::MAX)]),
        text(s)
    );
    assert_eq!(
        both("substring", &[bytes(&[1, 2, 3]), int(1)]),
        bytes(&[2, 3])
    );
    assert_eq!(
        both("substring", &[text(s), int(0), int(-1)]),
        invalid("substring(...) length must be non-negative")
    );
    assert_eq!(
        both("substring", &[text(s), dbl(1.5)]),
        invalid("Cannot coerce Float64 (1.5) to Int64")
    );
    // A null length, and a position before the start, were not shown.
    assert!(is_unobserved(&strict(
        "substring",
        &[text(s), int(0), null()]
    )));
    assert_eq!(emulator("substring", &[text(s), int(0), null()]), null());
    assert!(is_unobserved(&strict("substring", &[text("abc"), int(-5)])));
    assert_eq!(emulator("substring", &[text("abc"), int(-5)]), text("abc"));
    // A double with no Java text is unobserved under strict.
    assert!(is_unobserved(&strict("substring", &[text(s), dbl(1e7)])));
}

#[test]
fn trim_follows_the_recorded_rows() {
    assert_eq!(both("trim", &[text("  pad  ")]), text("pad"));
    assert_eq!(both("ltrim", &[text("  pad  ")]), text("pad  "));
    assert_eq!(both("rtrim", &[text("  pad  ")]), text("  pad"));
    assert_eq!(both("trim", &[text("xxaxx"), text("x")]), text("a"));
    assert_eq!(both("ltrim", &[text("xxaxx"), text("x")]), text("axx"));
    assert_eq!(both("rtrim", &[text("xxaxx"), text("x")]), text("xxa"));
    assert_eq!(both("trim", &[text("abcab"), text("ab")]), text("c"));
    assert_eq!(both("trim", &[text("")]), text(""));
    assert_eq!(both("trim", &[text("   ")]), text(""));
    assert_eq!(both("trim", &[text("\t a \n")]), text("a"));
    assert_eq!(both("trim", &[text("\u{a0}a\u{a0}")]), text("a"));
    assert_eq!(both("trim", &[bytes(&[1])]), bytes(&[1]));
    // Other white space, an empty set and bytes to trim were not shown.
    assert!(is_unobserved(&strict("trim", &[text("\ra\r")])));
    assert_eq!(emulator("trim", &[text("\ra\r")]), text("a"));
    assert!(is_unobserved(&strict("trim", &[text("abc"), text("")])));
    assert!(is_unobserved(&strict("trim", &[bytes(&[b' ', 1])])));
    assert_eq!(emulator("trim", &[bytes(&[b' ', 1])]), bytes(&[1]));
    assert!(is_unobserved(&strict(
        "trim",
        &[bytes(&[1, 2]), bytes(&[2])]
    )));
    assert_eq!(
        emulator("trim", &[bytes(&[1, 2]), bytes(&[2])]),
        bytes(&[1])
    );
}

#[test]
fn split_follows_the_recorded_rows() {
    let parts = |items: &[&str]| {
        array(
            items
                .iter()
                .map(|s| Value::String((*s).to_owned()))
                .collect(),
        )
    };
    assert_eq!(
        both("split", &[text("a,b,,c"), text(",")]),
        parts(&["a", "b", "", "c"])
    );
    assert_eq!(
        both("split", &[text("a,b,,c"), text("")]),
        parts(&["a", ",", "b", ",", ",", "c"])
    );
    assert_eq!(
        both("split", &[text("a,b,,c"), text(";")]),
        parts(&["a,b,,c"])
    );
    assert_eq!(both("split", &[text(""), text(",")]), parts(&[""]));
    assert_eq!(
        both("split", &[text(",,"), text(",")]),
        parts(&["", "", ""])
    );
    assert_eq!(
        both("split", &[text("Hello World")]),
        parts(&["Hello World"])
    );
    assert_eq!(
        both("split", &[text("a--b--c"), text("--")]),
        parts(&["a", "b", "c"])
    );
    assert_eq!(
        both("split", &[text("héllo ☃😀"), text("☃")]),
        parts(&["héllo ", "😀"])
    );
    let byte_parts =
        |items: &[&[u8]]| array(items.iter().map(|b| Value::Bytes(b.to_vec())).collect());
    assert_eq!(
        both("split", &[bytes(&[1, 2, 3, 1, 2, 3]), bytes(&[1])]),
        byte_parts(&[&[], &[2, 3], &[2, 3]])
    );
    // One argument with a comma, an empty text with an empty delimiter and bytes with an empty
    // delimiter were not shown.
    assert!(is_unobserved(&strict("split", &[text("a,b")])));
    assert_eq!(emulator("split", &[text("a,b")]), parts(&["a", "b"]));
    assert!(is_unobserved(&strict("split", &[text(""), text("")])));
    assert!(is_unobserved(&strict("split", &[bytes(&[1]), bytes(&[])])));
    assert!(is_unobserved(&strict("split", &[text("a"), bytes(&[1])])));
}

#[test]
fn integer_arithmetic_is_checked_and_a_double_makes_a_double() {
    assert_eq!(both("add", &[int(2), int(3)]), int(5));
    assert_eq!(both("add", &[dbl(1.5), dbl(2.25)]), dbl(3.75));
    assert_eq!(both("add", &[int(2), dbl(0.5)]), dbl(2.5));
    assert_eq!(both("add", &[int(0), int(0)]), int(0));
    for args in [[int(i64::MAX), int(1)], [int(i64::MIN), int(-1)]] {
        assert_eq!(both("add", &args), invalid("add(...) int64 overflow"));
    }
    for args in [[int(i64::MIN), int(1)], [int(i64::MAX), int(-1)]] {
        assert_eq!(
            both("subtract", &args),
            invalid("subtract(...) int64 overflow")
        );
    }
    for args in [[int(i64::MAX), int(2)], [int(i64::MIN), int(-1)]] {
        assert_eq!(
            both("multiply", &args),
            invalid("multiply(...) overflow error")
        );
    }
    assert_eq!(both("subtract", &[int(5), int(3)]), int(2));
    assert_eq!(both("subtract", &[int(2), dbl(0.5)]), dbl(1.5));
    assert_eq!(both("multiply", &[int(6), int(7)]), int(42));
    assert_eq!(both("multiply", &[int(2), dbl(0.5)]), dbl(1.0));
    let nan = |eval: Eval| matches!(eval, Eval::Value(Value::Double(d)) if d.is_nan());
    assert!(nan(both("add", &[dbl(f64::NAN), int(1)])));
    assert!(nan(both(
        "add",
        &[dbl(f64::INFINITY), dbl(f64::NEG_INFINITY)]
    )));
    assert!(nan(both(
        "subtract",
        &[dbl(f64::INFINITY), dbl(f64::INFINITY)]
    )));
    assert!(nan(both("multiply", &[int(0), dbl(f64::INFINITY)])));
    let negative_zero = |eval: Eval| matches!(eval, Eval::Value(Value::Double(d)) if d == 0.0 && d.is_sign_negative());
    assert!(negative_zero(both("add", &[dbl(-0.0), dbl(-0.0)])));
    assert!(negative_zero(both("multiply", &[dbl(-0.0), int(1)])));
}

#[test]
fn division_and_remainder_follow_the_recorded_rows() {
    assert_eq!(both("divide", &[int(6), int(3)]), int(2));
    assert_eq!(both("divide", &[int(7), int(2)]), int(3));
    assert_eq!(both("divide", &[int(-7), int(2)]), int(-3));
    assert_eq!(both("divide", &[dbl(7.0), dbl(2.0)]), dbl(3.5));
    assert_eq!(
        both("divide", &[int(1), int(0)]),
        invalid("divide(...) requires a non-zero right operand")
    );
    assert_eq!(both("divide", &[dbl(1.0), dbl(0.0)]), dbl(f64::INFINITY));
    assert!(
        matches!(both("divide", &[dbl(0.0), dbl(0.0)]), Eval::Value(Value::Double(d)) if d.is_nan())
    );
    assert!(
        matches!(both("divide", &[dbl(f64::NAN), int(1)]), Eval::Value(Value::Double(d)) if d.is_nan())
    );
    assert_eq!(both("divide", &[int(i64::MIN), int(-1)]), int(i64::MIN));
    assert_eq!(both("mod", &[int(7), int(3)]), int(1));
    assert_eq!(both("mod", &[int(-7), int(3)]), int(-1));
    assert_eq!(both("mod", &[int(7), int(-3)]), int(1));
    assert_eq!(both("mod", &[dbl(7.5), dbl(2.0)]), dbl(1.5));
    assert_eq!(
        both("mod", &[int(1), int(0)]),
        invalid("mod(...) requires a non-zero divisor")
    );
    assert!(
        matches!(both("mod", &[dbl(1.0), dbl(0.0)]), Eval::Value(Value::Double(d)) if d.is_nan())
    );
    assert_eq!(both("mod", &[int(i64::MIN), int(-1)]), int(0));
    // An integer by a double, and a remainder across the two kinds, were not shown.
    assert!(is_unobserved(&strict("divide", &[int(7), dbl(2.0)])));
    assert_eq!(emulator("divide", &[int(7), dbl(2.0)]), dbl(3.5));
    assert!(is_unobserved(&strict("mod", &[dbl(7.5), int(2)])));
    assert_eq!(emulator("mod", &[dbl(7.5), int(2)]), dbl(1.5));
}

#[test]
fn abs_round_floor_ceil_and_pow_follow_the_recorded_rows() {
    assert_eq!(both("abs", &[int(5)]), int(5));
    assert_eq!(both("abs", &[int(-5)]), int(5));
    assert_eq!(both("abs", &[dbl(-2.5)]), dbl(2.5));
    assert!(
        matches!(both("abs", &[dbl(-0.0)]), Eval::Value(Value::Double(d)) if d == 0.0 && d.is_sign_positive())
    );
    assert_eq!(both("abs", &[dbl(f64::NEG_INFINITY)]), dbl(f64::INFINITY));
    assert_eq!(
        both("abs", &[int(i64::MIN)]),
        invalid("abs(...) cannot be used on minimum Int64 value (-2^63)")
    );
    assert_eq!(both("round", &[dbl(2.5)]), dbl(3.0));
    assert_eq!(both("round", &[dbl(-2.5)]), dbl(-3.0));
    assert_eq!(both("round", &[dbl(0.5)]), dbl(1.0));
    assert_eq!(both("round", &[int(5)]), int(5));
    assert_eq!(both("round", &[dbl(1.2345), int(2)]), dbl(1.23));
    assert_eq!(both("round", &[dbl(1234.5), int(-2)]), dbl(1200.0));
    assert_eq!(both("round", &[int(1250), int(-2)]), int(1300));
    assert_eq!(both("round", &[dbl(1.5), int(400)]), dbl(1.5));
    assert_eq!(
        both("round", &[dbl(1.5), dbl(1.5)]),
        invalid("Cannot coerce Float64 (1.5) to Int64")
    );
    assert_eq!(both("floor", &[dbl(2.5)]), dbl(2.0));
    assert_eq!(both("floor", &[dbl(-2.5)]), dbl(-3.0));
    assert_eq!(both("floor", &[int(5)]), int(5));
    assert!(matches!(both("floor", &[dbl(f64::NAN)]), Eval::Value(Value::Double(d)) if d.is_nan()));
    assert_eq!(both("ceil", &[dbl(2.5)]), dbl(3.0));
    assert_eq!(both("ceil", &[dbl(-2.5)]), dbl(-2.0));
    assert_eq!(both("ceil", &[int(5)]), int(5));
    assert!(matches!(both("ceil", &[dbl(f64::NAN)]), Eval::Value(Value::Double(d)) if d.is_nan()));
    assert_eq!(both("pow", &[int(2), int(10)]), dbl(1024.0));
    assert_eq!(both("pow", &[int(0), int(0)]), dbl(1.0));
    assert_eq!(both("pow", &[int(2), int(-2)]), dbl(0.25));
    assert_eq!(both("pow", &[int(4), dbl(0.5)]), dbl(2.0));
    assert_eq!(both("pow", &[int(10), int(400)]), dbl(f64::INFINITY));
    assert_eq!(both("pow", &[int(2), int(3)]), dbl(8.0));
    assert_eq!(
        both("pow", &[int(-8), dbl(1.0 / 3.0)]),
        invalid("pow(...) the base cannot be negative when the exponent is not an integer.")
    );
    // What the rows do not show: infinity in floor, ceil and pow, a number that is not finite
    // to round, places and integers of other forms.
    assert!(is_unobserved(&strict("floor", &[dbl(f64::INFINITY)])));
    assert_eq!(emulator("floor", &[dbl(f64::INFINITY)]), dbl(f64::INFINITY));
    assert!(is_unobserved(&strict("ceil", &[dbl(f64::INFINITY)])));
    assert!(is_unobserved(&strict("round", &[dbl(f64::NAN)])));
    assert!(is_unobserved(&strict("round", &[dbl(1.5), int(30)])));
    assert!(is_unobserved(&strict("round", &[int(5), int(2)])));
    assert_eq!(emulator("round", &[int(5), int(2)]), int(5));
    assert!(is_unobserved(&strict("pow", &[dbl(f64::NAN), int(2)])));
    assert!(is_unobserved(&strict("pow", &[int(2), dbl(f64::INFINITY)])));
}

#[test]
fn argument_counts_are_refused_in_the_words_production_used() {
    let refusal = |name: &str, count: usize| {
        let args = vec![Expr::Constant(Value::Integer(1)); count];
        Expr::call(name, args, Placement::Value).unwrap_err()
    };
    let arity = |text: &str| ExprError::Arity(text.to_owned());
    assert_eq!(
        refusal("concat", 1),
        arity("The function 'concat[T: string | bytes | array[any]](input: T*): T' takes [2..+\u{221e}) argument(s), but 1 was provided.")
    );
    assert_eq!(
        refusal("to_lower", 0),
        arity("The function 'to_lower[T: string | bytes](input: T): T' takes [1..1] argument(s), but 0 were provided.")
    );
    assert_eq!(
        refusal("string_contains", 3),
        arity("The function 'string_contains(value: string, substring: string): boolean' takes [2..2] argument(s), but 3 were provided.")
    );
    assert_eq!(
        refusal("pow", 1),
        arity("The function 'pow(base: number, exponent: number): float64' takes [2..2] argument(s), but 1 was provided.")
    );
    assert_eq!(
        refusal("substring", 1),
        arity("The function 'substring' does not accept 1 argument(s). Valid options are:\n- substring[T: string | bytes](input: T, position: int64): T with [2..2] argument(s).\n- substring[T: string | bytes](input: T, position: int64, length: int64): T with [3..3] argument(s).")
    );
    assert_eq!(
        refusal("trim", 3),
        arity("The function 'trim' does not accept 3 argument(s). Valid options are:\n- trim[T: string | bytes](input: T): T with [1..1] argument(s).\n- trim[T: string | bytes](input: T, values_to_trim: T): T with [2..2] argument(s).")
    );
    assert_eq!(
        refusal("split", 0),
        arity("The function 'split' does not accept 0 argument(s). Valid options are:\n- split(input: string): array[string] with [1..1] argument(s).\n- split[T: string | bytes](input: T, delimiter: T): array[T] with [2..2] argument(s).")
    );
    assert_eq!(
        refusal("round", 3),
        arity("The function 'round' does not accept 3 argument(s). Valid options are:\n- round[T <: number](number: T): T with [1..1] argument(s).\n- round[T <: number](number: T, places: int64): T with [2..2] argument(s).")
    );
    // `ltrim` and `rtrim` have no recorded signature: fireemu's own words.
    for name in ["ltrim", "rtrim"] {
        assert!(matches!(refusal(name, 0), ExprError::Invalid(_)), "{name}");
        assert!(matches!(refusal(name, 3), ExprError::Invalid(_)), "{name}");
        assert!(Expr::call(
            name,
            vec![Expr::Constant(Value::Integer(1))],
            Placement::Value
        )
        .is_ok());
    }
    // In range the calls build, and only the boolean functions can be a whole condition.
    for name in ["starts_with", "ends_with", "string_contains"] {
        let args = vec![Expr::Constant(Value::Integer(1)); 2];
        assert!(
            Expr::call(name, args, Placement::Condition).is_ok(),
            "{name}"
        );
    }
    assert!(Expr::call(
        "add",
        vec![Expr::Constant(Value::Integer(1)); 2],
        Placement::Condition
    )
    .is_err());
}

#[test]
fn the_profiles_differ_only_where_the_rows_stop() {
    // A double with no Java text: unobserved under strict, a refusal all the same in the
    // emulator profile.
    assert!(is_unobserved(&strict("round", &[dbl(1.5), dbl(1e7)])));
    assert!(matches!(
        emulator("round", &[dbl(1.5), dbl(1e7)]),
        Eval::Error(EvalError::Invalid(_))
    ));
    // `concat`: a later argument of another type than a string first argument, or than any
    // other first argument, and a null beside it.
    assert_eq!(
        both("concat", &[text("a"), int(1)]),
        wrong("concat", "STRING", "LONG")
    );
    assert!(is_unobserved(&strict(
        "concat",
        &[text("a"), int(1), null()]
    )));
    assert_eq!(
        emulator("concat", &[text("a"), int(1), null()]),
        wrong("concat", "STRING", "LONG")
    );
    assert!(is_unobserved(&strict("concat", &[bytes(&[1]), text("a")])));
    assert_eq!(
        emulator("concat", &[bytes(&[1]), text("a")]),
        wrong("concat", "BYTES", "STRING")
    );
    assert!(is_unobserved(&strict("concat", &[int(1), text("a")])));
    assert_eq!(
        emulator("concat", &[int(1), text("a")]),
        wrong("concat", "STRING", "LONG")
    );
    // The Greek sigma, whose lower case depends on its place in the word.
    for name in ["to_lower", "to_upper"] {
        for input in ["ΑΣ", "ας"] {
            assert!(
                is_unobserved(&strict(name, &[text(input)])),
                "{name} {input}"
            );
            assert!(matches!(
                emulator(name, &[text(input)]),
                Eval::Value(Value::String(_))
            ));
        }
    }
    assert_eq!(emulator("to_lower", &[text("ΑΣ")]), text("ας"));
    // Bytes that hold letters.
    assert!(is_unobserved(&strict("to_lower", &[bytes(b"Ab")])));
    assert_eq!(emulator("to_lower", &[bytes(b"Ab")]), bytes(b"ab"));
    assert!(is_unobserved(&strict("to_upper", &[bytes(b"Ab")])));
    assert_eq!(emulator("to_upper", &[bytes(b"Ab")]), bytes(b"AB"));
    // Bytes with no delimiter.
    assert!(is_unobserved(&strict("split", &[bytes(&[1])])));
    assert_eq!(
        emulator("split", &[bytes(&[1])]),
        wrong("split", "String", "BYTES")
    );
    // A double by an integer is shown for `divide` under both profiles.
    assert_eq!(both("divide", &[dbl(7.0), int(2)]), dbl(3.5));
    // Rounding places at the edges of the double range, in the emulator profile.
    assert_eq!(emulator("round", &[dbl(10.0), int(308)]), dbl(10.0));
    assert_eq!(emulator("round", &[dbl(1e308), int(-308)]), dbl(1e308));
    assert_eq!(emulator("round", &[dbl(1e308), int(-309)]), dbl(0.0));
    assert!(is_unobserved(&strict("round", &[dbl(1e308), int(-308)])));
    assert_eq!(emulator("round", &[int(1250), int(-19)]), int(0));
    assert!(is_unobserved(&strict("round", &[int(1250), int(-19)])));
    // A zero base with a fractional exponent is no negative base.
    assert_eq!(both("pow", &[int(0), dbl(0.5)]), dbl(0.0));
    assert_eq!(both("pow", &[dbl(-0.0), dbl(0.5)]), dbl(0.0));
    assert!(matches!(
        both("pow", &[int(-4), dbl(0.5)]),
        Eval::Error(EvalError::Invalid(_))
    ));
}

#[test]
fn integer_round_minimum_places_preserves_profile_policy() {
    assert!(is_unobserved(&strict("round", &[int(1250), int(i64::MIN)])));
    assert_eq!(emulator("round", &[int(1250), int(i64::MIN)]), int(0));
}

#[test]
fn integer_round_profile_value_places_matrix() {
    // PICT pairwise rows, including the required minimum and boundary seeds.
    let cases = [
        (true, 1250, i64::MIN),
        (false, 1250, i64::MIN),
        (true, -1250, -18),
        (false, -1250, -18),
        (true, -1250, i64::MIN),
        (true, 0, -2),
        (false, -1250, -19),
        (true, 1250, -19),
        (false, 0, -18),
        (false, 1250, -2),
        (false, 1250, -18),
        (true, 0, -19),
        (false, 0, i64::MIN),
        (false, -1250, -2),
    ];
    for (is_strict, value, places) in cases {
        let args = [int(value), int(places)];
        let got = if is_strict {
            strict("round", &args)
        } else {
            emulator("round", &args)
        };
        if is_strict && places < -18 {
            assert!(is_unobserved(&got), "{value}, {places}");
        } else {
            let expected = if places == -2 { value / 1250 * 1300 } else { 0 };
            assert_eq!(got, int(expected), "{value}, {places}");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn integer_round_extreme_negative_places_preserve_policy(value in any::<i64>(), places in i64::MIN..-18i64) {
        prop_assert!(is_unobserved(&strict("round", &[int(value), int(places)])));
        prop_assert_eq!(emulator("round", &[int(value), int(places)]), int(0));
    }

    #[test]
    fn concat_of_strings_is_their_join(parts in proptest::collection::vec(".{0,6}", 2..6)) {
        let args: Vec<Eval> = parts.iter().map(|p| text(p)).collect();
        prop_assert_eq!(both("concat", &args), text(&parts.concat()));
        // A null anywhere gives null.
        for at in 0..args.len() {
            let mut with_null = args.clone();
            with_null[at] = null();
            prop_assert_eq!(both("concat", &with_null), null());
        }
    }

    #[test]
    fn char_length_counts_code_points(s in ".{0,12}") {
        prop_assert_eq!(
            both("char_length", &[text(&s)]),
            int(i64::try_from(s.chars().count()).unwrap())
        );
    }

    #[test]
    fn case_mapping_agrees_with_the_standard_library(s in "[a-zA-Z0-9 ÀÉéß☃😀]{0,12}") {
        prop_assert_eq!(both("to_lower", &[text(&s)]), text(&s.to_lowercase()));
        prop_assert_eq!(both("to_upper", &[text(&s)]), text(&s.to_uppercase()));
    }

    #[test]
    fn substring_agrees_with_a_model_of_code_points(
        s in "[a-zé☃😀 ]{0,10}",
        position in 0i64..14,
        length in proptest::option::of(0i64..14),
    ) {
        let chars: Vec<char> = s.chars().collect();
        let start = usize::try_from(position).unwrap().min(chars.len());
        let end = length.map_or(chars.len(), |l| (start + usize::try_from(l).unwrap()).min(chars.len()));
        let want: String = chars[start..end].iter().collect();
        let mut args = vec![text(&s), int(position)];
        if let Some(length) = length {
            args.push(int(length));
        }
        prop_assert_eq!(both("substring", &args), text(&want));
        // A negative position counts from the end while it stays inside the text.
        if !chars.is_empty() {
            let back = i64::try_from(chars.len()).unwrap().min(position + 1);
            let want: String = chars[chars.len() - usize::try_from(back).unwrap()..].iter().collect();
            prop_assert_eq!(both("substring", &[text(&s), int(-back)]), text(&want));
        }
    }

    #[test]
    fn trim_agrees_with_the_standard_library_on_the_recorded_characters(
        s in "[ \t\na-c]{0,10}",
    ) {
        let set = |c: char| matches!(c, ' ' | '\t' | '\n');
        prop_assert_eq!(both("trim", &[text(&s)]), text(s.trim_matches(set)));
        prop_assert_eq!(both("ltrim", &[text(&s)]), text(s.trim_start_matches(set)));
        prop_assert_eq!(both("rtrim", &[text(&s)]), text(s.trim_end_matches(set)));
    }

    #[test]
    fn split_agrees_with_the_standard_library_and_joins_back(
        s in "[a-c,;]{0,10}",
        delimiter in "[,;]{1,2}",
    ) {
        let want: Vec<Value> = s.split(delimiter.as_str()).map(|p| Value::String(p.to_owned())).collect();
        prop_assert_eq!(both("split", &[text(&s), text(&delimiter)]), array(want.clone()));
        let joined: Vec<String> = want
            .iter()
            .map(|v| match v { Value::String(p) => p.clone(), _ => unreachable!() })
            .collect();
        prop_assert_eq!(joined.join(&delimiter), s);
    }

    #[test]
    fn integer_arithmetic_agrees_with_a_wide_reference(a in any::<i64>(), b in any::<i64>()) {
        let wide = |x: i128| i64::try_from(x).ok();
        let check = |name: &str, reference: Option<i64>, message: &str| {
            let got = both(name, &[int(a), int(b)]);
            let want = reference.map_or_else(|| invalid(message), int);
            prop_assert_eq!(got, want);
            Ok(())
        };
        check("add", wide(i128::from(a) + i128::from(b)), "add(...) int64 overflow")?;
        check("subtract", wide(i128::from(a) - i128::from(b)), "subtract(...) int64 overflow")?;
        check("multiply", wide(i128::from(a) * i128::from(b)), "multiply(...) overflow error")?;
        if b != 0 {
            // The two wrapping cases are the one place division leaves the overflow rule.
            let quotient = if a == i64::MIN && b == -1 { i64::MIN } else { a / b };
            let remainder = if a == i64::MIN && b == -1 { 0 } else { a % b };
            prop_assert_eq!(both("divide", &[int(a), int(b)]), int(quotient));
            prop_assert_eq!(both("mod", &[int(a), int(b)]), int(remainder));
        }
    }

    #[test]
    fn integer_rounding_to_tens_is_half_away_from_zero(n in -1_000_000i64..1_000_000, digits in 1i64..5) {
        let unit = 10i64.pow(u32::try_from(digits).unwrap());
        let want = {
            let r = n.rem_euclid(unit);
            let down = n - r;
            // rem_euclid is non-negative: -1250 rounds to -1300, 1250 to 1300.
            if n >= 0 {
                if r * 2 >= unit { down + unit } else { down }
            } else if r * 2 > unit { down + unit } else { down }
        };
        prop_assert_eq!(both("round", &[int(n), int(-digits)]), int(want));
    }

    #[test]
    fn a_double_rounded_to_places_is_within_half_a_unit(
        d in -1.0e6f64..1.0e6,
        places in 0i64..6,
    ) {
        let got = match both("round", &[dbl(d), int(places)]) {
            Eval::Value(Value::Double(x)) => x,
            other => panic!("{other:?}"),
        };
        let unit = 10f64.powi(i32::try_from(places).unwrap());
        prop_assert!((got - d).abs() <= 0.5 / unit + 1e-9);
        // Rounding twice changes nothing.
        let again = match both("round", &[dbl(got), int(places)]) {
            Eval::Value(Value::Double(x)) => x,
            other => panic!("{other:?}"),
        };
        prop_assert_eq!(again, got);
    }
}

#[test]
fn recorded_array_access_results() {
    let a = array(vec![
        Value::Integer(1),
        Value::Integer(2),
        Value::Integer(3),
    ]);
    for (name, args, expected) in [
        ("array_length", vec![a.clone()], int(3)),
        ("array_length", vec![array(vec![])], int(0)),
        ("array_first", vec![a.clone()], int(1)),
        ("array_last", vec![a.clone()], int(3)),
        ("array_first", vec![array(vec![])], Eval::Absent),
        ("array_last", vec![array(vec![])], Eval::Absent),
        ("array_get", vec![a.clone(), int(0)], int(1)),
        ("array_get", vec![a.clone(), int(2)], int(3)),
        ("array_get", vec![a.clone(), int(-1)], int(3)),
        ("array_get", vec![a.clone(), int(10)], Eval::Absent),
        ("array_get", vec![a.clone(), null()], null()),
        ("array_get", vec![null(), int(0)], null()),
        ("array_get", vec![Eval::Absent, int(0)], null()),
        (
            "array_length",
            vec![text("abc")],
            wrong("array_length", "Array", "STRING"),
        ),
        ("array_first", vec![int(5)], wrong("first", "Array", "LONG")),
        ("array_last", vec![int(5)], wrong("last", "Array", "LONG")),
        (
            "array_get",
            vec![int(5), int(0)],
            wrong("array_get", "Array", "LONG"),
        ),
        (
            "array_get",
            vec![a, dbl(1.5)],
            invalid("Cannot coerce Float64 (1.5) to Int64"),
        ),
    ] {
        assert_eq!(strict(name, &args), expected, "{name} {args:?}");
    }
    let nested = Eval::Error(EvalError::Invalid("nested failure".to_owned()));
    assert_eq!(strict("array_get", &[nested.clone(), int(0)]), nested);
    assert!(is_unobserved(&strict("array_get", &[null(), dbl(1.5)])));
    assert!(is_unobserved(&strict(
        "array_get",
        &[array(vec![]), text("0")]
    )));
    for name in ["array_length", "array_first", "array_last"] {
        for arg in [null(), Eval::Absent] {
            assert_eq!(strict(name, &[arg]), null());
        }
    }
    for name in ["array_first", "array_last"] {
        assert_eq!(
            Expr::call(name, vec![], Placement::Value).unwrap_err().to_string(),
            format!("The function '{name}(array: array[any]): any' takes [1..1] argument(s), but 0 were provided.")
        );
    }
    assert_eq!(Expr::call("array_length", vec![], Placement::Value).unwrap_err().to_string(), "The function 'array_length(x: array[any]): int64' takes [1..1] argument(s), but 0 were provided.");
    assert_eq!(Expr::call("array_get", vec![Expr::Constant(Value::Null)], Placement::Value).unwrap_err().to_string(), "The function 'array_get(array: array[any], index: int64): any?' takes [2..2] argument(s), but 1 was provided.");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn array_access_matches_reference_for_nonempty_integer_arrays(items in proptest::collection::vec(any::<i64>(), 1..20), offset in 0usize..40) {
        let values = items.iter().copied().map(Value::Integer).collect::<Vec<_>>();
        let argument = array(values);
        prop_assert_eq!(strict("array_length", std::slice::from_ref(&argument)), int(i64::try_from(items.len()).unwrap()));
        prop_assert_eq!(strict("array_first", std::slice::from_ref(&argument)), int(items[0]));
        prop_assert_eq!(strict("array_last", std::slice::from_ref(&argument)), int(*items.last().unwrap()));
        prop_assert_eq!(strict("array_get", &[argument.clone(), int(-1)]), int(*items.last().unwrap()));
        let index = offset % items.len();
        let negative_index = i64::try_from(index).unwrap() - i64::try_from(items.len()).unwrap();
        prop_assert_eq!(strict("array_get", &[argument, int(negative_index)]), int(items[index]));
    }
}

#[test]
fn array_access_pict_generated_cases() {
    let cases = [
        ("length", "populated", "strict"),
        ("first", "empty", "strict"),
        ("last", "populated", "strict"),
        ("get", "populated", "strict"),
        ("get", "null", "strict"),
        ("first", "populated", "emulator"),
        ("last", "null", "emulator"),
        ("first", "wrong", "strict"),
        ("last", "wrong", "emulator"),
        ("last", "absent", "strict"),
        ("length", "empty", "emulator"),
        ("last", "empty", "strict"),
        ("get", "empty", "emulator"),
        ("length", "absent", "emulator"),
        ("first", "null", "strict"),
        ("first", "absent", "strict"),
        ("get", "absent", "emulator"),
        ("get", "wrong", "emulator"),
        ("length", "null", "strict"),
        ("length", "wrong", "emulator"),
    ];
    for (operation, input, profile) in cases {
        let name = format!("array_{operation}");
        let arg = match input {
            "populated" => array(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3),
            ]),
            "empty" => array(vec![]),
            "null" => null(),
            "absent" => Eval::Absent,
            "wrong" if operation == "length" => text("abc"),
            "wrong" => int(5),
            _ => unreachable!(),
        };
        let mut args = vec![arg];
        if operation == "get" {
            args.push(int(0));
        }
        let expected = match (operation, input) {
            (_, "null" | "absent") => null(),
            ("length", "wrong") => wrong("array_length", "Array", "STRING"),
            ("first", "wrong") => wrong("first", "Array", "LONG"),
            ("last", "wrong") => wrong("last", "Array", "LONG"),
            ("get", "wrong") => wrong("array_get", "Array", "LONG"),
            ("length", "empty") => int(0),
            (_, "empty") => Eval::Absent,
            ("length" | "last", "populated") => int(3),
            (_, "populated") => int(1),
            _ => unreachable!(),
        };
        let actual = if profile == "strict" {
            strict(&name, &args)
        } else {
            emulator(&name, &args)
        };
        assert_eq!(actual, expected, "{operation} {input} {profile}");
    }
}

#[test]
fn map_get_recorded_and_pict_cases() {
    let inner = Value::Map([("c".to_owned(), Value::Integer(2))].into_iter().collect());
    let map = Eval::Value(Value::Map(
        [
            ("a".to_owned(), Value::Integer(1)),
            ("b".to_owned(), inner.clone()),
        ]
        .into_iter()
        .collect(),
    ));
    let cases = [
        ("present", "strict", "select"),
        ("missing", "strict", "select"),
        ("dotted", "strict", "select"),
        ("null", "strict", "select"),
        ("wrongmap", "strict", "select"),
        ("wrongkey", "strict", "select"),
        ("present", "emulator", "nested"),
        ("nested", "strict", "nested"),
        ("empty", "emulator", "select"),
        ("absent", "strict", "nested"),
        ("wrongmap", "emulator", "nested"),
        ("dotted", "emulator", "nested"),
        ("wrongkey", "emulator", "nested"),
        ("absent", "emulator", "select"),
        ("missing", "emulator", "nested"),
        ("empty", "strict", "nested"),
        ("null", "emulator", "nested"),
        ("nested", "emulator", "select"),
    ];
    for (input, profile, placement) in cases {
        let (m, key, expected) = match input {
            "present" => (map.clone(), text("a"), int(1)),
            "missing" => (map.clone(), text("zz"), Eval::Absent),
            "dotted" => (map.clone(), text("b.c"), Eval::Absent),
            "nested" => (map.clone(), text("b"), Eval::Value(inner.clone())),
            "empty" => (
                Eval::Value(Value::Map(BTreeMap::new())),
                text("a"),
                Eval::Absent,
            ),
            "null" => (null(), text("a"), null()),
            "absent" => (Eval::Absent, text("a"), null()),
            "wrongmap" => (array(vec![]), text("a"), wrong("map_get", "Map", "ARRAY")),
            "wrongkey" => (map.clone(), int(1), wrong("map_get", "String", "LONG")),
            _ => unreachable!(),
        };
        let as_expr = |value: Eval| match value {
            Eval::Value(value) => Expr::Constant(value),
            Eval::Absent => Expr::Field(FieldPath::parse("missing").unwrap()),
            Eval::Error(_) => unreachable!(),
        };
        let call = Expr::call("map_get", vec![as_expr(m), as_expr(key)], Placement::Value).unwrap();
        let (expr, expected) = if placement == "nested" {
            let wrapped = match expected {
                Eval::Value(value) => array(vec![value]),
                Eval::Absent => array(vec![Value::Null]),
                Eval::Error(error) => Eval::Error(error),
            };
            (
                Expr::call("array", vec![call], Placement::Value).unwrap(),
                wrapped,
            )
        } else {
            (call, expected)
        };
        let mode = if profile == "strict" {
            Unrecorded::Refuse
        } else {
            Unrecorded::OfficialEmulator
        };
        assert_eq!(
            expr.eval_in(&Row::derived(BTreeMap::new()), mode),
            expected,
            "{input} {profile} {placement}"
        );
    }
    assert_eq!(strict("map_get", &[map.clone(), null()]), null());
    assert_eq!(strict("map_get", &[map.clone(), Eval::Absent]), null());
    assert!(is_unobserved(&strict("map_get", &[null(), int(1)])));
    assert!(is_unobserved(&strict("map_get", &[array(vec![]), int(1)])));
    let err = invalid("nested error");
    assert_eq!(strict("map_get", &[err.clone(), text("a")]), err);
    for (args, n, verb) in [
        (vec![], 0, "were"),
        (vec![Expr::Constant(Value::Null)], 1, "was"),
    ] {
        assert_eq!(Expr::call("map_get", args, Placement::Value).unwrap_err().to_string(), format!("The function 'map_get(map: map[string, any], key: string): any?' takes [2..2] argument(s), but {n} {verb} provided."));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn map_get_matches_literal_key_reference(entries in proptest::collection::btree_map(".{0,8}", any::<i64>(), 0..20), key in ".{0,8}") {
        let expected = entries.get(&key).map_or(Eval::Absent, |v| int(*v));
        let values = entries.into_iter().map(|(k, v)| (k, Value::Integer(v))).collect();
        prop_assert_eq!(strict("map_get", &[Eval::Value(Value::Map(values)), text(&key)]), expected);
    }
}

#[test]
fn regex_recorded_production_cases() {
    let subject = text("Hello World");
    let yes = Eval::Value(Value::Boolean(true));
    let no = Eval::Value(Value::Boolean(false));
    let strings = |items: &[&str]| {
        array(
            items
                .iter()
                .map(|s| Value::String((*s).to_owned()))
                .collect(),
        )
    };
    for (name, args, expected) in [
        (
            "regex_contains",
            vec![subject.clone(), text("o W")],
            yes.clone(),
        ),
        (
            "regex_contains",
            vec![subject.clone(), text("xyz")],
            no.clone(),
        ),
        (
            "regex_contains",
            vec![subject.clone(), text("^Hello")],
            yes.clone(),
        ),
        (
            "regex_contains",
            vec![subject.clone(), text("^World")],
            no.clone(),
        ),
        (
            "regex_contains",
            vec![subject.clone(), text("hello")],
            no.clone(),
        ),
        (
            "regex_contains",
            vec![subject.clone(), text("(?i)hello")],
            yes.clone(),
        ),
        (
            "regex_contains",
            vec![subject.clone(), text("")],
            yes.clone(),
        ),
        (
            "regex_contains",
            vec![text("héllo ☃😀"), text("☃")],
            yes.clone(),
        ),
        (
            "regex_match",
            vec![subject.clone(), text("H.*d")],
            yes.clone(),
        ),
        (
            "regex_match",
            vec![subject.clone(), text("o W")],
            no.clone(),
        ),
        (
            "regex_match",
            vec![subject.clone(), text("^Hello World$")],
            yes.clone(),
        ),
        ("regex_match", vec![text(""), text("")], yes.clone()),
        ("regex_find", vec![subject.clone(), text("o")], text("o")),
        ("regex_find", vec![subject.clone(), text("xyz")], null()),
        (
            "regex_find",
            vec![subject.clone(), text("(W)orld")],
            text("W"),
        ),
        ("regex_find", vec![subject.clone(), text("x*")], text("")),
        (
            "regex_find_all",
            vec![subject.clone(), text("o")],
            strings(&["o", "o"]),
        ),
        (
            "regex_find_all",
            vec![subject.clone(), text("xyz")],
            strings(&[]),
        ),
        (
            "regex_find_all",
            vec![text("aaa"), text("aa")],
            strings(&["aa"]),
        ),
        (
            "regex_find_all",
            vec![text("abc"), text("x*")],
            strings(&["", "", "", ""]),
        ),
    ] {
        assert_eq!(both(name, &args), expected, "{name} {args:?}");
    }
    assert_eq!(
        both("regex_match", &[subject.clone(), text("[")]),
        invalid("Unsupported regex syntax.")
    );
    for name in [
        "regex_contains",
        "regex_match",
        "regex_find",
        "regex_find_all",
    ] {
        assert_eq!(
            both(name, &[subject.clone(), text("(")]),
            invalid("Unsupported regex syntax.")
        );
        assert_eq!(both(name, &[null(), text("a")]), null());
        assert_eq!(both(name, &[Eval::Absent, text("a")]), null());
        assert_eq!(
            both(name, &[int(1), text("a")]),
            wrong(name, "String", "LONG")
        );
        assert_eq!(both(name, &[subject.clone(), null()]), null());
        assert_eq!(
            both(name, &[subject.clone(), int(1)]),
            wrong(name, "String or Regex", "LONG")
        );
        for (n, verb) in [(0, "were"), (1, "was")] {
            let result = match name {
                "regex_contains" | "regex_match" => "boolean",
                "regex_find" => "string?",
                _ => "array[string?]",
            };
            let args = vec![Expr::Constant(Value::Null); n];
            let signature =
                format!("{name}[T: string | regex](search_space: string, regexp: T): {result}");
            assert_eq!(
                Expr::call(name, args, Placement::Value)
                    .unwrap_err()
                    .to_string(),
                format!(
                    "The function '{signature}' takes [2..2] argument(s), but {n} {verb} provided."
                )
            );
        }
    }
}

#[test]
fn regex_pict_generated_cases() {
    let cases = [
        ("contains", "text", "match", "strict"),
        ("match", "text", "match", "strict"),
        ("find", "text", "match", "strict"),
        ("find_all", "text", "match", "strict"),
        ("contains", "null", "match", "strict"),
        ("contains", "text", "invalid", "strict"),
        ("match", "null", "empty", "emulator"),
        ("find_all", "absent", "match", "emulator"),
        ("match", "empty", "no_match", "emulator"),
        ("match", "empty", "invalid", "emulator"),
        ("find", "empty", "null", "emulator"),
        ("find", "empty", "invalid", "strict"),
        ("contains", "text", "wrong", "emulator"),
        ("contains", "absent", "empty", "strict"),
        ("find_all", "text", "empty", "strict"),
        ("find_all", "empty", "wrong", "strict"),
        ("contains", "empty", "match", "emulator"),
        ("find_all", "wrong", "no_match", "strict"),
        ("find", "wrong", "empty", "emulator"),
        ("find_all", "empty", "empty", "emulator"),
        ("find", "null", "no_match", "strict"),
        ("find", "text", "wrong", "emulator"),
        ("find_all", "null", "null", "strict"),
        ("contains", "text", "no_match", "strict"),
        ("contains", "wrong", "match", "strict"),
        ("find_all", "text", "invalid", "emulator"),
        ("match", "absent", "null", "emulator"),
        ("contains", "text", "null", "strict"),
        ("match", "wrong", "match", "emulator"),
        ("find", "absent", "no_match", "emulator"),
        ("match", "empty", "wrong", "strict"),
    ];
    for (function, subject, pattern, profile) in cases {
        let name = match function {
            "contains" => "regex_contains",
            "match" => "regex_match",
            "find" => "regex_find",
            _ => "regex_find_all",
        };
        let input = match subject {
            "text" => text("abc"),
            "empty" => text(""),
            "null" => null(),
            "absent" => Eval::Absent,
            "wrong" => int(1),
            _ => unreachable!(),
        };
        let pattern_arg = match pattern {
            "match" => text("b"),
            "no_match" => text("z"),
            "empty" => text(""),
            "invalid" => text("("),
            "null" => null(),
            "wrong" => int(1),
            _ => unreachable!(),
        };
        let expected = if subject == "wrong" {
            wrong(name, "String", "LONG")
        } else if pattern == "wrong" {
            wrong(name, "String or Regex", "LONG")
        } else if subject == "null" || subject == "absent" || pattern == "null" {
            null()
        } else if pattern == "invalid" {
            invalid("Unsupported regex syntax.")
        } else {
            let matches = pattern == "empty" || (pattern == "match" && subject == "text");
            let full = pattern == "empty" && subject == "empty";
            match function {
                "contains" => Eval::Value(Value::Boolean(matches)),
                "match" => Eval::Value(Value::Boolean(full)),
                "find" if !matches => null(),
                "find" => text(if pattern == "empty" { "" } else { "b" }),
                "find_all" if !matches => array(vec![]),
                "find_all" if pattern == "empty" => {
                    array(vec![
                        Value::String(String::new());
                        if subject == "empty" { 1 } else { 4 }
                    ])
                }
                "find_all" => array(vec![Value::String("b".to_owned())]),
                _ => unreachable!(),
            }
        };
        let got = if profile == "strict" {
            strict(name, &[input, pattern_arg])
        } else {
            emulator(name, &[input, pattern_arg])
        };
        assert_eq!(got, expected, "{function} {subject} {pattern} {profile}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn regex_contains_and_match_agree_with_literal_reference(prefix in "[a-z]{0,8}", suffix in "[a-z]{0,8}") {
        let subject = format!("{prefix}Q{suffix}");
        prop_assert_eq!(strict("regex_contains", &[text(&subject), text("Q")]), Eval::Value(Value::Boolean(true)));
        prop_assert_eq!(strict("regex_match", &[text(&subject), text("Q")]), Eval::Value(Value::Boolean(prefix.is_empty() && suffix.is_empty())));
        prop_assert_eq!(strict("regex_find_all", &[text(&subject), text("Q")]), array(vec![Value::String("Q".to_owned())]));
    }
}

#[test]
fn regex_strict_guards_known_re2_differences() {
    for (subject, pattern) in [
        ("١", r"\d"),
        ("١", r"\D"),
        ("é", r"\w"),
        ("é", r"\W"),
        (" ", r"\s"),
        (" ", r"\S"),
        ("é", r"\bé\b"),
        ("é", r"\B"),
        ("\u{000b}", r"\s"),
        ("ab", "(?x)a b"),
        ("a", "[a&&b]"),
        ("α", r"\p{Greek}"),
        ("a", r"[\d]"),
        ("a", r"\Qabc\E"),
        ("a", r"\C"),
        ("a", "(?u)a"),
        ("a", "(?R)^a$"),
        ("a", "[a--b]"),
        ("a", "[a~~b]"),
        ("a", "[a[b]]"),
        ("a", "a{2}"),
    ] {
        assert!(
            is_unobserved(&strict("regex_contains", &[text(subject), text(pattern)])),
            "{subject:?} {pattern:?}"
        );
    }
    for name in [
        "regex_contains",
        "regex_match",
        "regex_find",
        "regex_find_all",
    ] {
        assert!(is_unobserved(&strict(name, &[text("١"), text(r"\d")])));
    }
    assert_eq!(
        emulator("regex_contains", &[text("١"), text(r"\d")]),
        Eval::Value(Value::Boolean(true))
    );
    assert_eq!(
        strict("regex_contains", &[text("☃"), text("☃")]),
        Eval::Value(Value::Boolean(true))
    );
    assert_eq!(
        strict("regex_contains", &[text(r"\d"), text(r"\\d")]),
        Eval::Value(Value::Boolean(true))
    );
    for (subject, pattern) in [
        ("[", r"\["),
        ("{", r"\{"),
        ("?", r"\?"),
        ("a", "[a-z]"),
        ("z", "[^a]"),
        ("foo", "(?im:foo)"),
        ("a&&b", "a&&b"),
        (r"\s", r"\\s"),
    ] {
        assert_eq!(
            strict("regex_contains", &[text(subject), text(pattern)]),
            Eval::Value(Value::Boolean(true)),
            "{pattern}"
        );
    }
    assert_eq!(
        strict("regex_contains", &[text("Hello"), text("(?i)hello")]),
        Eval::Value(Value::Boolean(true))
    );
}

#[test]
fn map_family_recorded_cases() {
    let m = Eval::Value(Value::Map(
        [
            ("a".to_owned(), Value::Integer(1)),
            (
                "b".to_owned(),
                Value::Map([("c".to_owned(), Value::Integer(2))].into_iter().collect()),
            ),
        ]
        .into_iter()
        .collect(),
    ));
    let empty = Eval::Value(Value::Map(BTreeMap::new()));
    let mk = |pairs: &[(&str, Value)]| {
        Eval::Value(Value::Map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        ))
    };
    let inner = Value::Map([("c".to_owned(), Value::Integer(2))].into_iter().collect());
    let inner_d = Value::Map([("d".to_owned(), Value::Integer(2))].into_iter().collect());
    for (name, args, expected) in [
        (
            "map_set",
            vec![m.clone(), text("z"), int(9)],
            mk(&[
                ("a", Value::Integer(1)),
                ("b", inner.clone()),
                ("z", Value::Integer(9)),
            ]),
        ),
        (
            "map_set",
            vec![m.clone(), text("a"), int(9)],
            mk(&[("a", Value::Integer(9)), ("b", inner.clone())]),
        ),
        (
            "map_set",
            vec![m.clone(), text("y"), int(8), text("z"), int(9)],
            mk(&[
                ("a", Value::Integer(1)),
                ("b", inner.clone()),
                ("y", Value::Integer(8)),
                ("z", Value::Integer(9)),
            ]),
        ),
        (
            "map_set",
            vec![m.clone(), text("z"), null()],
            mk(&[
                ("a", Value::Integer(1)),
                ("b", inner.clone()),
                ("z", Value::Null),
            ]),
        ),
        (
            "map_set",
            vec![m.clone(), text("a"), Eval::Absent],
            mk(&[("b", inner.clone())]),
        ),
        (
            "map_set",
            vec![m.clone(), int(1), int(9)],
            invalid("map_set keys must be of type STRING, given type is LONG"),
        ),
        (
            "map_remove",
            vec![m.clone(), text("a")],
            mk(&[("b", inner.clone())]),
        ),
        ("map_remove", vec![m.clone(), text("zz")], m.clone()),
        (
            "map_remove",
            vec![m.clone(), text("a"), text("b")],
            empty.clone(),
        ),
        (
            "map_remove",
            vec![m.clone(), int(1)],
            wrong("map_remove", "String", "LONG"),
        ),
        (
            "map_merge",
            vec![m.clone(), mk(&[("z", Value::Integer(9))])],
            mk(&[
                ("a", Value::Integer(1)),
                ("b", inner.clone()),
                ("z", Value::Integer(9)),
            ]),
        ),
        (
            "map_merge",
            vec![
                mk(&[("a", Value::Integer(1))]),
                mk(&[("a", Value::Integer(2))]),
            ],
            mk(&[("a", Value::Integer(2))]),
        ),
        (
            "map_merge",
            vec![
                mk(&[("a", Value::Integer(1))]),
                mk(&[("b", Value::Integer(2))]),
                mk(&[("c", Value::Integer(3))]),
            ],
            mk(&[
                ("a", Value::Integer(1)),
                ("b", Value::Integer(2)),
                ("c", Value::Integer(3)),
            ]),
        ),
        ("map_merge", vec![m.clone(), empty.clone()], m.clone()),
        (
            "map_merge",
            vec![mk(&[("b", inner.clone())]), mk(&[("b", inner_d.clone())])],
            mk(&[("b", inner_d)]),
        ),
        ("map_merge", vec![m.clone(), null()], null()),
        ("map_merge", vec![m.clone(), Eval::Absent], null()),
        (
            "map_merge",
            vec![m.clone(), array(vec![])],
            wrong("map_merge", "Map", "ARRAY"),
        ),
        (
            "map_keys",
            vec![m.clone()],
            array(vec![
                Value::String("a".to_owned()),
                Value::String("b".to_owned()),
            ]),
        ),
        (
            "map_values",
            vec![m.clone()],
            array(vec![Value::Integer(1), inner.clone()]),
        ),
        (
            "map_entries",
            vec![m.clone()],
            array(vec![
                Value::Map(
                    [
                        ("k".to_owned(), Value::String("a".to_owned())),
                        ("v".to_owned(), Value::Integer(1)),
                    ]
                    .into_iter()
                    .collect(),
                ),
                Value::Map(
                    [
                        ("k".to_owned(), Value::String("b".to_owned())),
                        ("v".to_owned(), inner),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ]),
        ),
    ] {
        assert_eq!(both(name, &args), expected, "{name} {args:?}");
    }
    assert!(is_unobserved(&strict("map_set", &[null(), int(1), int(9)])));
    assert!(is_unobserved(&strict("map_remove", &[null(), int(1)])));
    assert!(is_unobserved(&strict(
        "map_merge",
        &[null(), array(vec![])]
    )));
    for name in ["map_set", "map_remove"] {
        for arg in [null(), Eval::Absent] {
            let args = if name == "map_set" {
                vec![arg, text("z"), int(9)]
            } else {
                vec![arg, text("a")]
            };
            assert_eq!(
                both(name, &args),
                if name == "map_set" {
                    Eval::Absent
                } else {
                    null()
                }
            );
        }
    }
    for name in ["map_keys", "map_values", "map_entries"] {
        assert_eq!(both(name, std::slice::from_ref(&empty)), array(vec![]));
        assert_eq!(both(name, &[null()]), null());
        assert_eq!(both(name, &[Eval::Absent]), null());
        assert_eq!(both(name, &[array(vec![])]), wrong(name, "Map", "ARRAY"));
    }
    for (name, args, expected) in [
        ("map_set", 2, "The function 'map_set(map: map[string, any], entries: any*): map[string, any]' takes [3..+∞) argument(s), but 2 were provided."),
        ("map_remove", 1, "The function 'map_remove(map: map[string, any], key: string*): map[string, any]' takes [2..+∞) argument(s), but 1 was provided."),
        ("map_merge", 1, "The function 'map_merge(maps: map[string, any]*): map[string, any]' takes [2..+∞) argument(s), but 1 was provided."),
        ("map_keys", 0, "The function 'map_keys(map: map[string, any]): array[string]' takes [1..1] argument(s), but 0 were provided."),
        ("map_values", 0, "The function 'map_values(map: map[string, any]): array[any]' takes [1..1] argument(s), but 0 were provided."),
        ("map_entries", 0, "The function 'map_entries(map: map[string, any]): array[map[string, any]]' takes [1..1] argument(s), but 0 were provided."),
    ] { assert_eq!(Expr::call(name,vec![Expr::Constant(Value::Null);args],Placement::Value).unwrap_err().to_string(),expected); }
    for (name, signature, min) in [
        (
            "map_set",
            "map_set(map: map[string, any], entries: any*): map[string, any]",
            3,
        ),
        (
            "map_remove",
            "map_remove(map: map[string, any], key: string*): map[string, any]",
            2,
        ),
        (
            "map_merge",
            "map_merge(maps: map[string, any]*): map[string, any]",
            2,
        ),
    ] {
        assert_eq!(
            Expr::call(name, vec![], Placement::Value)
                .unwrap_err()
                .to_string(),
            format!(
                "The function '{signature}' takes [{min}..+∞) argument(s), but 0 were provided."
            )
        );
    }
    assert_eq!(
        Expr::call(
            "map_set",
            vec![Expr::Constant(Value::Null); 4],
            Placement::Value
        )
        .unwrap_err()
        .to_string(),
        "'map_set' function must have an odd number of arguments"
    );
}

#[test]
fn map_family_pict_generated_cases() {
    let cases = [
        ("set", "populated", "strict"),
        ("set", "null", "strict"),
        ("remove", "populated", "strict"),
        ("merge", "populated", "strict"),
        ("keys", "populated", "strict"),
        ("values", "populated", "strict"),
        ("entries", "populated", "strict"),
        ("merge", "wrong", "emulator"),
        ("keys", "empty", "emulator"),
        ("remove", "null", "emulator"),
        ("remove", "empty", "strict"),
        ("merge", "null", "strict"),
        ("values", "empty", "emulator"),
        ("entries", "wrong", "emulator"),
        ("keys", "wrong", "strict"),
        ("set", "absent", "emulator"),
        ("values", "null", "strict"),
        ("keys", "null", "emulator"),
        ("keys", "absent", "strict"),
        ("entries", "null", "emulator"),
        ("set", "wrong", "emulator"),
        ("merge", "empty", "strict"),
        ("values", "absent", "emulator"),
        ("merge", "absent", "emulator"),
        ("entries", "empty", "emulator"),
        ("values", "wrong", "emulator"),
        ("remove", "wrong", "emulator"),
        ("entries", "absent", "emulator"),
        ("set", "empty", "emulator"),
        ("remove", "absent", "strict"),
        ("entries", "populated", "emulator"),
    ];
    for (function, input, profile) in cases {
        let name = match function {
            "set" => "map_set",
            "remove" => "map_remove",
            "merge" => "map_merge",
            "keys" => "map_keys",
            "values" => "map_values",
            _ => "map_entries",
        };
        let m = match input {
            "populated" => Eval::Value(Value::Map(
                [("a".to_owned(), Value::Integer(1))].into_iter().collect(),
            )),
            "empty" => Eval::Value(Value::Map(BTreeMap::new())),
            "null" => null(),
            "absent" => Eval::Absent,
            "wrong" => array(vec![]),
            _ => unreachable!(),
        };
        let args = match function {
            "set" => vec![m.clone(), text("b"), int(2)],
            "remove" => vec![m.clone(), text("a")],
            "merge" => vec![m.clone(), Eval::Value(Value::Map(BTreeMap::new()))],
            _ => vec![m.clone()],
        };
        let expected = if input == "wrong" {
            wrong(name, "Map", "ARRAY")
        } else if input == "null" || input == "absent" {
            if function == "set" {
                Eval::Absent
            } else {
                null()
            }
        } else {
            match function {
                "set" => {
                    let Eval::Value(Value::Map(mut m)) = m else {
                        unreachable!()
                    };
                    m.insert("b".to_owned(), Value::Integer(2));
                    Eval::Value(Value::Map(m))
                }
                "remove" => Eval::Value(Value::Map(BTreeMap::new())),
                "merge" => m,
                "keys" => array(if input == "populated" {
                    vec![Value::String("a".to_owned())]
                } else {
                    vec![]
                }),
                "values" => array(if input == "populated" {
                    vec![Value::Integer(1)]
                } else {
                    vec![]
                }),
                _ => array(if input == "populated" {
                    vec![Value::Map(
                        [
                            ("k".to_owned(), Value::String("a".to_owned())),
                            ("v".to_owned(), Value::Integer(1)),
                        ]
                        .into_iter()
                        .collect(),
                    )]
                } else {
                    vec![]
                }),
            }
        };
        let got = if profile == "strict" {
            strict(name, &args)
        } else {
            emulator(name, &args)
        };
        assert_eq!(got, expected, "{function} {input} {profile}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn map_family_pairs_and_absent_deletion(entries in proptest::collection::btree_map("[a-z]{1,6}", any::<i64>(), 0..15), key in "[a-z]{1,6}") {
        let original: BTreeMap<String,Value> = entries.iter().map(|(k,v)| (k.clone(),Value::Integer(*v))).collect();
        let m = Eval::Value(Value::Map(original.clone()));
        let mut removed = original.clone(); removed.remove(&key);
        prop_assert_eq!(strict("map_set", &[m.clone(),text(&key),Eval::Absent]), Eval::Value(Value::Map(removed)));
        let keys = strict("map_keys", std::slice::from_ref(&m));
        let values = strict("map_values", std::slice::from_ref(&m));
        let expected_keys = array(original.keys().cloned().map(Value::String).collect());
        let expected_values = array(original.values().cloned().collect());
        let expected_entries = array(original.iter().map(|(key,value)| Value::Map([("k".to_owned(),Value::String(key.clone())), ("v".to_owned(),value.clone())].into_iter().collect())).collect());
        prop_assert_eq!(strict("map_entries", std::slice::from_ref(&m)), expected_entries);
        prop_assert_eq!(keys, expected_keys);
        prop_assert_eq!(values, expected_values);
    }
}

#[test]
fn map_family_mixed_precedence_is_unobserved() {
    let m = Eval::Value(Value::Map(BTreeMap::new()));
    for args in [
        vec![m.clone(), int(1), null()],
        vec![m.clone(), null(), int(1)],
        vec![array(vec![]), int(1)],
        vec![array(vec![]), null()],
        vec![m.clone(), int(1), text("x"), null()],
    ] {
        assert!(is_unobserved(&strict("map_remove", &args)), "{args:?}");
    }
    for args in [
        vec![array(vec![]), int(1), int(2)],
        vec![m.clone(), int(1), int(2), null(), int(3)],
        vec![m.clone(), null(), int(3), int(1), int(2)],
        vec![array(vec![]), null(), int(2)],
    ] {
        assert!(is_unobserved(&strict("map_set", &args)), "{args:?}");
    }
    assert_eq!(
        emulator("map_remove", &[m.clone(), int(1), null()]),
        wrong("map_remove", "String", "LONG")
    );
    assert_eq!(
        emulator("map_set", &[array(vec![]), int(1), int(2)]),
        wrong("map_set", "Map", "ARRAY")
    );
    assert_eq!(
        emulator("map_merge", &[int(1), text("x")]),
        wrong("map_merge", "Map", "LONG")
    );
    assert!(is_unobserved(&strict("map_merge", &[int(1), text("x")])));
    assert!(is_unobserved(&strict("map_merge", &[text("x"), int(1)])));
    assert!(is_unobserved(&strict(
        "map_merge",
        &[array(vec![]), array(vec![])]
    )));
}
