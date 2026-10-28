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
            runtime: RuntimeContext::default(),
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
    assert_eq!(NAMES.len(), 44);
    for name in ["exp", "ln", "log", "log10", "trunc"] {
        assert!(function(name).is_some());
    }
    assert!(function("sqrt").is_some());
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

#[test]
fn array_sequence_recorded_cases() {
    let a = array(vec![
        Value::Integer(1),
        Value::Integer(2),
        Value::Integer(3),
    ]);
    let strings = array(vec![
        Value::String("a".to_owned()),
        Value::String("b".to_owned()),
        Value::String("c".to_owned()),
    ]);
    for (name, args, expected) in [
        (
            "array_reverse",
            vec![a.clone()],
            array(vec![
                Value::Integer(3),
                Value::Integer(2),
                Value::Integer(1),
            ]),
        ),
        ("array_reverse", vec![array(vec![])], array(vec![])),
        ("array_reverse", vec![null()], null()),
        ("array_reverse", vec![Eval::Absent], null()),
        (
            "array_reverse",
            vec![int(5)],
            wrong("array_reverse", "Array", "LONG"),
        ),
        (
            "array_concat",
            vec![a.clone(), strings],
            array(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3),
                Value::String("a".to_owned()),
                Value::String("b".to_owned()),
                Value::String("c".to_owned()),
            ]),
        ),
        (
            "array_concat",
            vec![a.clone(), a.clone(), a.clone()],
            array(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3),
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3),
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3),
            ]),
        ),
        ("array_concat", vec![a.clone(), array(vec![])], a.clone()),
        ("array_concat", vec![a.clone(), null()], null()),
        ("array_concat", vec![a.clone(), Eval::Absent], null()),
        (
            "array_concat",
            vec![a.clone(), text("x")],
            wrong("array_concat", "Array", "STRING"),
        ),
    ] {
        assert_eq!(both(name, &args), expected, "{name} {args:?}");
    }
    for (n, verb) in [(0, "were"), (1, "was")] {
        assert_eq!(Expr::call("array_concat",vec![Expr::Constant(Value::Null);n],Placement::Value).unwrap_err().to_string(),format!("The function 'array_concat(arrays: array[any]*): array[any]' takes [2..+∞) argument(s), but {n} {verb} provided."));
    }
    assert!(matches!(
        Expr::call("array_reverse", vec![], Placement::Value),
        Err(ExprError::Unsupported(_))
    ));
    assert!(is_unobserved(&strict("array_concat", &[null(), text("x")])));
    assert!(is_unobserved(&strict("array_concat", &[text("x"), null()])));
}

#[test]
fn array_sequence_pict_cases() {
    let cases = [
        ("reverse", "populated", "strict"),
        ("reverse", "empty", "strict"),
        ("concat", "populated", "strict"),
        ("concat", "null", "strict"),
        ("reverse", "absent", "strict"),
        ("concat", "wrong", "emulator"),
        ("reverse", "populated", "emulator"),
        ("reverse", "null", "emulator"),
        ("concat", "absent", "emulator"),
        ("concat", "empty", "emulator"),
        ("reverse", "wrong", "strict"),
    ];
    for (operation, input, profile) in cases {
        let name = if operation == "reverse" {
            "array_reverse"
        } else {
            "array_concat"
        };
        let arg = match input {
            "populated" => array(vec![Value::Integer(1), Value::Integer(2)]),
            "empty" => array(vec![]),
            "null" => null(),
            "absent" => Eval::Absent,
            "wrong" => int(5),
            _ => unreachable!(),
        };
        let args = if operation == "reverse" {
            vec![arg]
        } else {
            vec![arg, array(vec![])]
        };
        let expected = match input {
            "populated" if operation == "reverse" => {
                array(vec![Value::Integer(2), Value::Integer(1)])
            }
            "populated" => array(vec![Value::Integer(1), Value::Integer(2)]),
            "empty" => array(vec![]),
            "null" | "absent" => null(),
            "wrong" => wrong(name, "Array", "LONG"),
            _ => unreachable!(),
        };
        let got = if profile == "strict" {
            strict(name, &args)
        } else {
            emulator(name, &args)
        };
        assert_eq!(got, expected, "{operation} {input} {profile}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn array_sequence_properties(a in proptest::collection::vec(any::<i64>(),0..30), b in proptest::collection::vec(any::<i64>(),0..30)) {
        let av: Vec<Value> = a.into_iter().map(Value::Integer).collect();
        let bv: Vec<Value> = b.into_iter().map(Value::Integer).collect();
        let reverse = strict("array_reverse", &[array(av.clone())]);
        prop_assert_eq!(strict("array_reverse", &[reverse]),array(av.clone()));
        let mut expected = av.clone(); expected.extend(bv.clone());
        prop_assert_eq!(strict("array_concat", &[array(av),array(bv)]),array(expected));
    }
}

#[test]
fn array_concat_multiple_wrong_types_preserves_profile_behavior() {
    for args in [vec![int(1), text("x")], vec![text("x"), int(1)]] {
        assert!(is_unobserved(&strict("array_concat", &args)));
        let expected_type = if matches!(args[0], Eval::Value(Value::Integer(_))) {
            "LONG"
        } else {
            "STRING"
        };
        assert_eq!(
            emulator("array_concat", &args),
            wrong("array_concat", "Array", expected_type)
        );
    }
}

#[test]
fn timestamp_unix_conversion_pict_cases() {
    let cases = [
        ("to_timestamp", "microseconds", "negative", "strict"),
        ("to_timestamp", "seconds", "zero", "strict"),
        ("to_timestamp", "milliseconds", "boundary", "strict"),
        ("to_unix", "microseconds", "negative", "strict"),
        ("to_unix", "seconds", "boundary", "strict"),
        ("to_unix", "milliseconds", "wrong", "emulator"),
        ("to_timestamp", "milliseconds", "null", "emulator"),
        ("to_timestamp", "seconds", "negative", "emulator"),
        ("to_unix", "microseconds", "zero", "emulator"),
        ("to_unix", "microseconds", "null", "strict"),
        ("to_unix", "seconds", "null", "emulator"),
        ("to_unix", "milliseconds", "positive", "strict"),
        ("to_timestamp", "microseconds", "boundary", "emulator"),
        ("to_timestamp", "milliseconds", "absent", "strict"),
        ("to_unix", "milliseconds", "zero", "strict"),
        ("to_unix", "milliseconds", "negative", "emulator"),
        ("to_timestamp", "microseconds", "positive", "emulator"),
        ("to_timestamp", "seconds", "positive", "emulator"),
        ("to_timestamp", "microseconds", "wrong", "strict"),
        ("to_unix", "seconds", "wrong", "strict"),
        ("to_unix", "seconds", "absent", "emulator"),
        ("to_timestamp", "microseconds", "absent", "strict"),
    ];
    for (direction, unit, input, profile) in cases {
        let (name, scale) = match (direction, unit) {
            ("to_timestamp", "seconds") => ("unix_seconds_to_timestamp", 1_i64),
            ("to_timestamp", "milliseconds") => ("unix_millis_to_timestamp", 1_000),
            ("to_timestamp", "microseconds") => ("unix_micros_to_timestamp", 1_000_000),
            ("to_unix", "seconds") => ("timestamp_to_unix_seconds", 1),
            ("to_unix", "milliseconds") => ("timestamp_to_unix_millis", 1_000),
            _ => ("timestamp_to_unix_micros", 1_000_000),
        };
        let value = match (direction, input) {
            (_, "null") => null(),
            (_, "absent") => Eval::Absent,
            ("to_timestamp", "wrong") => text("1"),
            ("to_unix", "wrong") => int(5),
            ("to_timestamp", "boundary") => int(i64::MAX),
            ("to_timestamp", "positive") => int(1),
            ("to_timestamp", "zero") => int(0),
            ("to_timestamp", "negative") => int(-1),
            ("to_unix", "positive") => Eval::Value(Value::Timestamp(
                Timestamp::new(1_582_979_696, 789_012_000).unwrap(),
            )),
            ("to_unix", "zero") => Eval::Value(Value::Timestamp(Timestamp::new(0, 0).unwrap())),
            ("to_unix", "negative") => {
                Eval::Value(Value::Timestamp(Timestamp::new(-1, 999_999_000).unwrap()))
            }
            ("to_unix", "boundary") => Eval::Value(Value::Timestamp(
                Timestamp::new(Timestamp::MAX_SECONDS, 999_999_000).unwrap(),
            )),
            _ => unreachable!(),
        };
        let expected = match (direction, input) {
            (_, "null" | "absent") => null(),
            ("to_timestamp", "wrong") => wrong(name, "Int64", "STRING"),
            ("to_unix", "wrong") => wrong(name, "Timestamp", "LONG"),
            ("to_timestamp", "boundary") => invalid(&format!("{name}(...) argument out of range")),
            ("to_timestamp", "positive") => Eval::Value(Value::Timestamp(
                Timestamp::new(
                    1 / scale,
                    u32::try_from((1 % scale) * (1_000_000_000 / scale)).unwrap(),
                )
                .unwrap(),
            )),
            ("to_timestamp", "zero") => {
                Eval::Value(Value::Timestamp(Timestamp::new(0, 0).unwrap()))
            }
            ("to_timestamp", "negative") => Eval::Value(Value::Timestamp(
                Timestamp::new(
                    -1,
                    u32::try_from(1_000_000_000 - (1_000_000_000 / scale)).unwrap(),
                )
                .unwrap(),
            )),
            ("to_unix", "positive") => {
                int(1_582_979_696 * scale + 789_012_000 / (1_000_000_000 / scale))
            }
            ("to_unix", "zero") => int(0),
            ("to_unix", "negative") => int(-1),
            ("to_unix", "boundary") => {
                int(Timestamp::MAX_SECONDS * scale + 999_999_000 / (1_000_000_000 / scale))
            }
            _ => unreachable!(),
        };
        let got = if profile == "strict" {
            strict(name, &[value])
        } else {
            emulator(name, &[value])
        };
        assert_eq!(got, expected, "{direction} {unit} {input} {profile}");
    }
}

#[test]
fn timestamp_unix_conversion_recorded_arities_and_float() {
    for unit in ["seconds", "millis", "micros"] {
        let from = format!("unix_{unit}_to_timestamp");
        let to = format!("timestamp_to_unix_{unit}");
        assert_eq!(
            strict(&from, &[int(i64::MIN)]),
            invalid(&format!("{from}(...) argument out of range"))
        );
        assert_eq!(
            strict(&from, &[dbl(1.5)]),
            invalid("Cannot coerce Float64 (1.5) to Int64")
        );
        for (name, signature) in [
            (&from, format!("{from}(input: int64): timestamp")),
            (
                &to,
                format!("{to}[T: timestamp | bson_timestamp](input: T): int64"),
            ),
        ] {
            assert_eq!(
                Expr::call(name, vec![], Placement::Value)
                    .unwrap_err()
                    .to_string(),
                format!(
                    "The function '{signature}' takes [1..1] argument(s), but 0 were provided."
                )
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn timestamp_unix_round_trip_for_microsecond_aligned_values(seconds in -62_135_596_800i64..=253_402_300_799, micros in 0u32..1_000_000) {
        let timestamp = Eval::Value(Value::Timestamp(Timestamp::new(seconds,micros*1_000).unwrap()));
        let encoded = strict("timestamp_to_unix_micros", std::slice::from_ref(&timestamp));
        prop_assert_eq!(strict("unix_micros_to_timestamp", &[encoded]), timestamp);
    }
}

#[test]
fn timestamp_duration_arithmetic_pict_cases() {
    let cases = [
        ("add", "day", "positive", "strict"),
        ("add", "microsecond", "positive", "strict"),
        ("subtract", "day", "negative", "strict"),
        ("diff", "second", "positive", "strict"),
        ("diff", "day", "negative", "strict"),
        ("add", "hour", "absent", "emulator"),
        ("subtract", "second", "absent", "emulator"),
        ("diff", "microsecond", "negative", "emulator"),
        ("add", "minute", "negative", "emulator"),
        ("subtract", "millisecond", "positive", "emulator"),
        ("subtract", "microsecond", "zero", "emulator"),
        ("add", "second", "negative", "strict"),
        ("diff", "millisecond", "null", "strict"),
        ("add", "day", "null", "emulator"),
        ("subtract", "hour", "null", "strict"),
        ("add", "millisecond", "absent", "strict"),
        ("diff", "minute", "null", "strict"),
        ("diff", "day", "zero", "strict"),
        ("diff", "hour", "zero", "emulator"),
        ("add", "millisecond", "zero", "strict"),
        ("diff", "microsecond", "absent", "emulator"),
        ("subtract", "minute", "absent", "emulator"),
        ("diff", "millisecond", "negative", "strict"),
        ("add", "day", "absent", "emulator"),
        ("diff", "second", "null", "strict"),
        ("add", "minute", "zero", "emulator"),
        ("add", "second", "zero", "emulator"),
        ("add", "minute", "positive", "strict"),
        ("subtract", "hour", "negative", "emulator"),
        ("add", "microsecond", "null", "emulator"),
        ("add", "hour", "positive", "strict"),
    ];
    let base = Eval::Value(Value::Timestamp(
        Timestamp::new(100_000, 123_456_000).unwrap(),
    ));
    let origin = Eval::Value(Value::Timestamp(
        Timestamp::new(100_000, 123_456_000).unwrap(),
    ));
    for (operation, unit, input, profile) in cases {
        let name = match operation {
            "add" => "timestamp_add",
            "subtract" => "timestamp_subtract",
            _ => "timestamp_diff",
        };
        let factor: i64 = match unit {
            "microsecond" => 1_000,
            "millisecond" => 1_000_000,
            "second" => 1_000_000_000,
            "minute" => 60_000_000_000,
            "hour" => 3_600_000_000_000,
            _ => 86_400_000_000_000,
        };
        let amount = match input {
            "negative" => -1_i64,
            "zero" => 0,
            _ => 1,
        };
        let first = match input {
            "null" => null(),
            "absent" => Eval::Absent,
            _ => base.clone(),
        };
        let args = if operation == "diff" {
            let end = match input {
                "null" => null(),
                "absent" => Eval::Absent,
                _ => Eval::Value(Value::Timestamp(
                    Timestamp::new(100_000 + amount, 123_456_000).unwrap(),
                )),
            };
            vec![end, origin.clone(), text(unit)]
        } else {
            vec![first, text(unit), int(amount)]
        };
        let expected = if input == "null" || input == "absent" {
            null()
        } else if operation == "diff" {
            int((amount * 1_000_000_000) / factor)
        } else {
            let sign = if operation == "subtract" { -1 } else { 1 };
            let nanos = 100_000_i64 * 1_000_000_000 + 123_456_000 + sign * amount * factor;
            Eval::Value(Value::Timestamp(
                Timestamp::new(
                    nanos.div_euclid(1_000_000_000),
                    u32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap(),
                )
                .unwrap(),
            ))
        };
        let got = if profile == "strict" {
            strict(name, &args)
        } else {
            emulator(name, &args)
        };
        assert_eq!(got, expected, "{operation} {unit} {input} {profile}");
    }
}

#[test]
fn timestamp_duration_recorded_boundaries() {
    let base = Eval::Value(Value::Timestamp(
        Timestamp::new(1_582_979_696, 789_012_000).unwrap(),
    ));
    let epoch = Eval::Value(Value::Timestamp(Timestamp::new(0, 0).unwrap()));
    assert_eq!(
        strict(
            "timestamp_diff",
            &[base.clone(), epoch.clone(), text("day")]
        ),
        int(18_321)
    );
    assert_eq!(
        strict(
            "timestamp_diff",
            &[epoch.clone(), base.clone(), text("day")]
        ),
        int(-18_321)
    );
    let negative = Eval::Value(Value::Timestamp(Timestamp::new(-1, 999_999_000).unwrap()));
    assert_eq!(
        strict("timestamp_diff", &[epoch, negative, text("second")]),
        int(0)
    );
    for unit in ["month", "week", "DAY"] {
        let message = "The argument 'unit' for function 'timestamp_add' must be a literal of type string from the following list: [microsecond, millisecond, second, minute, hour, day]";
        assert_eq!(
            strict("timestamp_add", &[base.clone(), text(unit), int(1)]),
            invalid(message)
        );
    }
    assert_eq!(
        strict(
            "timestamp_add",
            &[base.clone(), text("second"), int(i64::MAX)]
        ),
        invalid("timestamp_add(...) result is out of range")
    );
    assert_eq!(
        strict("timestamp_add", &[base.clone(), text("day"), dbl(1.5)]),
        invalid("Cannot coerce Float64 (1.5) to Int64")
    );
    assert_eq!(
        strict("timestamp_subtract", &[int(5), text("day"), int(1)]),
        wrong("timestamp_sub", "Timestamp or BsonTimestamp", "LONG")
    );
    let max = Eval::Value(Value::Timestamp(
        Timestamp::new(Timestamp::MAX_SECONDS, 999_999_000).unwrap(),
    ));
    let result = strict("timestamp_add", &[max, text("day"), int(1)]);
    assert!(
        matches!(result, Eval::Error(error) if error.to_string() == "timestamp_add(...) received a timestamp value that is out of range.")
    );
}

#[test]
fn timestamp_calendar_recorded_utc_cases() {
    let base = Eval::Value(Value::Timestamp(
        Timestamp::new(1_582_979_696, 789_012_000).unwrap(),
    ));
    for (unit, seconds, nanos) in [
        ("microsecond", 1_582_979_696_i64, 789_012_000_u32),
        ("millisecond", 1_582_979_696_i64, 789_000_000_u32),
        ("second", 1_582_979_696_i64, 0_u32),
        ("minute", 1_582_979_640_i64, 0_u32),
        ("hour", 1_582_977_600_i64, 0_u32),
        ("day", 1_582_934_400_i64, 0_u32),
        ("week", 1_582_416_000_i64, 0_u32),
        ("week(monday)", 1_582_502_400_i64, 0_u32),
        ("isoweek", 1_582_502_400_i64, 0_u32),
        ("month", 1_580_515_200_i64, 0_u32),
        ("quarter", 1_577_836_800_i64, 0_u32),
        ("year", 1_577_836_800_i64, 0_u32),
        ("isoyear", 1_577_664_000_i64, 0_u32),
    ] {
        assert_eq!(
            both("timestamp_trunc", &[base.clone(), text(unit)]),
            Eval::Value(Value::Timestamp(Timestamp::new(seconds, nanos).unwrap())),
            "{unit}"
        );
    }
    for (unit, value) in [
        ("year", 2020_i64),
        ("month", 2_i64),
        ("day", 29_i64),
        ("dayofweek", 7_i64),
        ("dayofyear", 60_i64),
        ("hour", 12_i64),
        ("minute", 34_i64),
        ("second", 56_i64),
        ("microsecond", 789_012_i64),
        ("week", 8_i64),
        ("isoweek", 9_i64),
        ("quarter", 1_i64),
    ] {
        assert_eq!(
            both("timestamp_extract", &[base.clone(), text(unit)]),
            int(value),
            "{unit}"
        );
    }
}

#[test]
fn timestamp_calendar_pict_cases() {
    let cases = [
        ("trunc", "day", "positive", "strict"),
        ("extract", "hour", "positive", "strict"),
        ("trunc", "second", "negative", "strict"),
        ("extract", "microsecond", "null", "strict"),
        ("trunc", "second", "null", "emulator"),
        ("extract", "millisecond", "positive", "emulator"),
        ("extract", "day", "negative", "emulator"),
        ("extract", "day", "null", "strict"),
        ("trunc", "hour", "absent", "emulator"),
        ("trunc", "hour", "negative", "emulator"),
        ("trunc", "millisecond", "null", "strict"),
        ("trunc", "minute", "null", "emulator"),
        ("trunc", "microsecond", "absent", "emulator"),
        ("extract", "millisecond", "absent", "strict"),
        ("extract", "microsecond", "negative", "emulator"),
        ("extract", "second", "positive", "emulator"),
        ("extract", "hour", "null", "emulator"),
        ("extract", "minute", "positive", "strict"),
        ("extract", "microsecond", "positive", "strict"),
        ("extract", "minute", "negative", "emulator"),
        ("trunc", "second", "absent", "strict"),
        ("trunc", "day", "absent", "emulator"),
        ("extract", "millisecond", "negative", "strict"),
        ("extract", "minute", "absent", "strict"),
    ];
    for (operation, unit, input, profile) in cases {
        let name = if operation == "trunc" {
            "timestamp_trunc"
        } else {
            "timestamp_extract"
        };
        let timestamp = match input {
            "positive" => Eval::Value(Value::Timestamp(
                Timestamp::new(1_582_979_696, 789_012_000).unwrap(),
            )),
            "negative" => Eval::Value(Value::Timestamp(Timestamp::new(-1, 999_999_000).unwrap())),
            "null" => null(),
            _ => Eval::Absent,
        };
        let expected = if input == "null" || input == "absent" {
            null()
        } else if operation == "extract" {
            let v = if input == "positive" {
                match unit {
                    "microsecond" => 789_012,
                    "millisecond" => 789,
                    "second" => 56,
                    "minute" => 34,
                    "hour" => 12,
                    _ => 29,
                }
            } else {
                match unit {
                    "microsecond" => 999_999,
                    "millisecond" => 999,
                    "second" | "minute" => 59,
                    "hour" => 23,
                    _ => 31,
                }
            };
            int(v)
        } else {
            let (seconds, nanos) = if input == "positive" {
                match unit {
                    "microsecond" => (1_582_979_696, 789_012_000),
                    "millisecond" => (1_582_979_696, 789_000_000),
                    "second" => (1_582_979_696, 0),
                    "minute" => (1_582_979_640, 0),
                    "hour" => (1_582_977_600, 0),
                    _ => (1_582_934_400, 0),
                }
            } else {
                match unit {
                    "microsecond" => (-1, 999_999_000),
                    "millisecond" => (-1, 999_000_000),
                    "second" => (-1, 0),
                    "minute" => (-60, 0),
                    "hour" => (-3_600, 0),
                    _ => (-86_400, 0),
                }
            };
            Eval::Value(Value::Timestamp(Timestamp::new(seconds, nanos).unwrap()))
        };
        let args = [timestamp, text(unit)];
        let got = if profile == "strict" {
            strict(name, &args)
        } else {
            emulator(name, &args)
        };
        assert_eq!(got, expected, "{operation} {unit} {input} {profile}");
    }
}

#[test]
fn timestamp_request_clock_is_stable_through_nested_and_blocking_stages() {
    let clock = Timestamp::new(1234, 567_890_000).unwrap();
    let later = Timestamp::new(4321, 0).unwrap();
    let now = || Expr::call("current_timestamp", vec![], Placement::Value).unwrap();
    let stages = || {
        vec![
            Stage::Sort(vec![SortKey {
                expr: now(),
                descending: false,
            }]),
            Stage::Select {
                aliases: vec![
                    (FieldPath::parse("t").unwrap(), now()),
                    (
                        FieldPath::parse("nested").unwrap(),
                        Expr::call("array", vec![now()], Placement::Value).unwrap(),
                    ),
                ],
                keeps_name: false,
            },
        ]
    };
    let mut cursor = Cursor::new_in_with_runtime(
        stages(),
        Unrecorded::Refuse,
        RuntimeContext {
            request_timestamp: Some(clock),
            zone_resolver: None,
            regex_resolver: None,
            sample_seed: None,
        },
    );
    assert!(cursor
        .push(Row::derived(BTreeMap::new()))
        .unwrap()
        .is_empty());
    assert!(cursor
        .push(Row::derived(BTreeMap::new()))
        .unwrap()
        .is_empty());
    let rows = cursor.finish().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.fields["t"], Value::Timestamp(clock));
        assert_eq!(
            row.fields["nested"],
            Value::Array(vec![Value::Timestamp(clock)])
        );
    }
    let mut second = Cursor::new_in_with_runtime(
        stages(),
        Unrecorded::Refuse,
        RuntimeContext {
            request_timestamp: Some(later),
            zone_resolver: None,
            regex_resolver: None,
            sample_seed: None,
        },
    );
    second.push(Row::derived(BTreeMap::new())).unwrap();
    assert_eq!(
        second.finish().unwrap()[0].fields["t"],
        Value::Timestamp(later)
    );
    for stages in [
        vec![Stage::Distinct(vec![("t".to_owned(), now())])],
        vec![Stage::Aggregate {
            accumulators: vec![(
                "t".to_owned(),
                Accumulator {
                    kind: AccumulatorKind::Maximum,
                    argument: Some(now()),
                },
            )],
            groups: vec![],
        }],
    ] {
        let mut blocking = Cursor::new_in_with_runtime(
            stages,
            Unrecorded::Refuse,
            RuntimeContext {
                request_timestamp: Some(clock),
                zone_resolver: None,
                regex_resolver: None,
                sample_seed: None,
            },
        );
        blocking.push(Row::derived(BTreeMap::new())).unwrap();
        blocking.push(Row::derived(BTreeMap::new())).unwrap();
        assert_eq!(
            blocking.finish().unwrap()[0].fields["t"],
            Value::Timestamp(clock)
        );
    }
    assert!(is_unobserved(
        &now().eval_in(&Row::derived(BTreeMap::new()), Unrecorded::Refuse)
    ));
}

#[test]
fn timestamp_named_zone_uses_injected_resolver_and_refuses_when_missing() {
    fn resolve(
        timestamp: Timestamp,
        zone: &str,
        unit: &str,
        operation: ZoneOperation,
    ) -> Result<ZoneResult, ZoneError> {
        assert_eq!(zone, "Asia/Tokyo");
        assert_eq!(
            timestamp,
            Timestamp::new(1_582_979_696, 789_012_000).unwrap()
        );
        match (operation, unit) {
            (ZoneOperation::Trunc, "day") => Ok(ZoneResult::Timestamp(
                Timestamp::new(1_582_902_000, 0).unwrap(),
            )),
            (ZoneOperation::Extract, "hour") => Ok(ZoneResult::Integer(21)),
            _ => Err(ZoneError::InvalidZone),
        }
    }
    let t = Expr::Constant(Value::Timestamp(
        Timestamp::new(1_582_979_696, 789_012_000).unwrap(),
    ));
    let call = |name: &str, unit: &str| {
        Expr::call(
            name,
            vec![
                t.clone(),
                Expr::Constant(Value::String(unit.to_owned())),
                Expr::Constant(Value::String("Asia/Tokyo".to_owned())),
            ],
            Placement::Value,
        )
        .unwrap()
    };
    let row = Row::derived(BTreeMap::new());
    assert!(is_unobserved(
        &call("timestamp_trunc", "day").eval_in(&row, Unrecorded::Refuse)
    ));
    let runtime = RuntimeContext {
        request_timestamp: None,
        zone_resolver: Some(resolve),
        regex_resolver: None,
        sample_seed: None,
    };
    let stages = vec![Stage::Select {
        aliases: vec![
            (
                FieldPath::parse("t").unwrap(),
                call("timestamp_trunc", "day"),
            ),
            (
                FieldPath::parse("h").unwrap(),
                call("timestamp_extract", "hour"),
            ),
        ],
        keeps_name: false,
    }];
    let mut cursor = Cursor::new_in_with_runtime(stages, Unrecorded::Refuse, runtime);
    let out = cursor.push(row).unwrap();
    assert_eq!(
        out[0].fields["t"],
        Value::Timestamp(Timestamp::new(1_582_902_000, 0).unwrap())
    );
    assert_eq!(out[0].fields["h"], Value::Integer(21));
}

#[test]
fn timestamp_shift_wrong_timestamp_uses_recorded_type_name() {
    for name in ["timestamp_add", "timestamp_subtract"] {
        let args = [int(1), text("day"), int(1)];
        let error_name = if name == "timestamp_subtract" {
            "timestamp_sub"
        } else {
            name
        };
        assert_eq!(
            strict(name, &args),
            wrong(error_name, "Timestamp or BsonTimestamp", "LONG")
        );
    }
}

#[test]
fn regex_without_adapter_resolver_is_unobserved() {
    let expression = Expr::call(
        "regex_contains",
        vec![
            Expr::Constant(Value::String("abc".to_owned())),
            Expr::Constant(Value::String("b".to_owned())),
        ],
        Placement::Value,
    )
    .unwrap();
    for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert!(is_unobserved(
            &expression.eval_in(&Row::derived(BTreeMap::new()), mode)
        ));
    }
}

#[allow(clippy::unnecessary_wraps)]
fn fake_regex(
    subject: &str,
    pattern: &str,
    operation: RegexOperation,
) -> Result<RegexResult, RegexError> {
    assert_eq!((subject, pattern), ("abc", "b"));
    Ok(match operation {
        RegexOperation::Contains => RegexResult::Boolean(true),
        RegexOperation::Match => RegexResult::Boolean(false),
        RegexOperation::Find => RegexResult::Match(Some("b".to_owned())),
        RegexOperation::FindAll => RegexResult::Matches(vec![Some("b".to_owned())]),
    })
}

#[test]
fn regex_port_pict_generated_cases() {
    let table = include_str!("regex_port.generated.tsv");
    let mut count = 0;
    for line in table.lines().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        let [operation, profile, availability] = fields.as_slice() else {
            panic!("bad generated row: {line}");
        };
        let (name, expected) = match *operation {
            "contains" => ("regex_contains", Eval::Value(Value::Boolean(true))),
            "match" => ("regex_match", Eval::Value(Value::Boolean(false))),
            "find" => ("regex_find", text("b")),
            "find_all" => ("regex_find_all", array(vec![Value::String("b".to_owned())])),
            _ => panic!("bad operation: {operation}"),
        };
        let mode = match *profile {
            "strict" => Unrecorded::Refuse,
            "emulator" => Unrecorded::OfficialEmulator,
            _ => panic!("bad profile: {profile}"),
        };
        let resolver = match *availability {
            "present" => Some(fake_regex as RegexResolver),
            "absent" => None,
            _ => panic!("bad resolver: {availability}"),
        };
        let expression = Expr::call(
            name,
            vec![
                Expr::Constant(Value::String("abc".to_owned())),
                Expr::Constant(Value::String("b".to_owned())),
            ],
            Placement::Value,
        )
        .unwrap();
        let got = expression.eval_in_with_runtime(
            &Row::derived(BTreeMap::new()),
            mode,
            RuntimeContext {
                regex_resolver: resolver,
                ..RuntimeContext::default()
            },
        );
        if resolver.is_some() {
            assert_eq!(got, expected, "{line}");
        } else {
            assert!(is_unobserved(&got), "{line}: {got:?}");
        }
        count += 1;
    }
    assert_eq!(count, 8);
}

#[test]
fn regex_invalid_inputs_and_unobserved_grammar_never_call_the_resolver() {
    fn unexpected(_: &str, _: &str, _: RegexOperation) -> Result<RegexResult, RegexError> {
        panic!("invalid input reached the resolver");
    }
    let cx = Context {
        unrecorded: Unrecorded::Refuse,
        condition: false,
        runtime: RuntimeContext {
            regex_resolver: Some(unexpected),
            ..RuntimeContext::default()
        },
    };
    let evaluate = |args: &[Eval]| (function("regex_contains").unwrap().eval)(args, cx);
    assert_eq!(evaluate(&[null(), text("b")]), null());
    assert_eq!(
        evaluate(&[int(1), text("b")]),
        wrong("regex_contains", "String", "LONG")
    );
    assert!(is_unobserved(&evaluate(&[text("1"), text(r"\d")])));
}

#[test]
fn regex_resolver_reaches_nested_and_blocking_stages() {
    let regex = || {
        Expr::call(
            "regex_contains",
            vec![
                Expr::Constant(Value::String("abc".to_owned())),
                Expr::Constant(Value::String("b".to_owned())),
            ],
            Placement::Value,
        )
        .unwrap()
    };
    let nested = || Expr::call("array", vec![regex()], Placement::Value).unwrap();
    let runtime = RuntimeContext {
        regex_resolver: Some(fake_regex),
        ..RuntimeContext::default()
    };
    let stages = vec![
        Stage::Sort(vec![SortKey {
            expr: regex(),
            descending: false,
        }]),
        Stage::Select {
            aliases: vec![(FieldPath::parse("result").unwrap(), nested())],
            keeps_name: false,
        },
    ];
    let mut cursor = Cursor::new_in_with_runtime(stages, Unrecorded::Refuse, runtime);
    assert!(cursor
        .push(Row::derived(BTreeMap::new()))
        .unwrap()
        .is_empty());
    let rows = cursor.finish().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].fields["result"],
        Value::Array(vec![Value::Boolean(true)])
    );
    for stage in [
        Stage::Distinct(vec![("result".to_owned(), regex())]),
        Stage::Aggregate {
            groups: vec![("result".to_owned(), regex())],
            accumulators: vec![(
                "count".to_owned(),
                Accumulator {
                    kind: AccumulatorKind::Count,
                    argument: Some(regex()),
                },
            )],
        },
    ] {
        let mut buffered = Cursor::new_in_with_runtime(vec![stage], Unrecorded::Refuse, runtime);
        assert!(buffered
            .push(Row::derived(BTreeMap::new()))
            .unwrap()
            .is_empty());
        let rows = buffered.finish().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].fields["result"], Value::Boolean(true));
        if rows[0].fields.contains_key("count") {
            assert_eq!(rows[0].fields["count"], Value::Integer(1));
        }
    }
    let condition = Expr::call(
        "equal",
        vec![regex(), Expr::Constant(Value::Boolean(true))],
        Placement::Condition,
    )
    .unwrap();
    let mut filtered =
        Cursor::new_in_with_runtime(vec![Stage::Where(condition)], Unrecorded::Refuse, runtime);
    assert_eq!(
        filtered.push(Row::derived(BTreeMap::new())).unwrap().len(),
        1
    );
}

#[test]
fn regex_port_maps_syntax_resource_and_incompatible_results() {
    fn invalid_syntax(_: &str, _: &str, _: RegexOperation) -> Result<RegexResult, RegexError> {
        Err(RegexError::InvalidSyntax)
    }
    fn exhausted(_: &str, _: &str, _: RegexOperation) -> Result<RegexResult, RegexError> {
        Err(RegexError::ResourceLimit)
    }
    #[allow(clippy::unnecessary_wraps)]
    fn wrong_result(_: &str, _: &str, _: RegexOperation) -> Result<RegexResult, RegexError> {
        Ok(RegexResult::Match(None))
    }
    let call = |resolver: RegexResolver, mode| {
        let cx = Context {
            unrecorded: mode,
            condition: false,
            runtime: RuntimeContext {
                regex_resolver: Some(resolver),
                ..RuntimeContext::default()
            },
        };
        (function("regex_contains").unwrap().eval)(&[text("abc"), text("b")], cx)
    };
    for mode in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert_eq!(
            call(invalid_syntax, mode),
            invalid("Unsupported regex syntax.")
        );
        assert!(is_unobserved(&call(exhausted, mode)));
        assert!(is_unobserved(&call(wrong_result, mode)));
    }
}

#[test]
fn recorded_array_subsequence_results() {
    let a = array(vec![
        Value::Integer(1),
        Value::Integer(2),
        Value::Integer(3),
    ]);
    let repeated = array(vec![
        Value::Integer(1),
        Value::Integer(2),
        Value::Integer(1),
    ]);
    let null_search = array(vec![Value::Integer(1), Value::Null]);
    let empty = array(vec![]);
    let cases = [
        ("array_slice", vec![a.clone(), int(1)], array(vec![Value::Integer(2), Value::Integer(3)])),
        ("array_slice", vec![a.clone(), int(1), int(1)], array(vec![Value::Integer(2)])),
        ("array_slice", vec![a.clone(), int(-1)], array(vec![Value::Integer(3)])),
        ("array_slice", vec![a.clone(), int(10)], empty.clone()),
        ("array_slice", vec![null(), int(1)], null()),
        ("array_slice", vec![Eval::Absent, int(1)], null()),
        ("array_slice", vec![int(5), int(1)], wrong("array_slice", "Array", "LONG")),
        ("array_index_of", vec![repeated.clone(), int(1), text("first")], int(0)),
        ("array_index_of", vec![repeated, int(1), text("last")], int(2)),
        ("array_index_of", vec![a.clone(), int(9), text("first")], int(-1)),
        ("array_index_of", vec![null_search, null(), text("first")], int(1)),
        ("array_index_of", vec![a.clone(), int(1), text("middle")], invalid("The argument 'direction' for function 'array_index_of' must be a literal of type string from the following list: [first, last]")),
        ("array_index_of", vec![null(), int(1), text("first")], null()),
        ("array_index_of", vec![Eval::Absent, int(1), text("first")], null()),
        ("array_index_of", vec![int(5), int(1), text("first")], wrong("array_index_of", "Array", "LONG")),
    ];
    for (name, args, expected) in cases {
        assert_eq!(both(name, &args), expected, "{name} {args:?}");
    }
    for (name, result) in [
        (
            "array_first_n",
            array(vec![Value::Integer(1), Value::Integer(2)]),
        ),
        (
            "array_last_n",
            array(vec![Value::Integer(2), Value::Integer(3)]),
        ),
    ] {
        for (args, expected) in [
            (vec![a.clone(), int(2)], result),
            (vec![a.clone(), int(0)], empty.clone()),
            (
                vec![a.clone(), int(-1)],
                invalid(&format!(
                    "The function `{name}(...)` requires non-negative count."
                )),
            ),
            (vec![a.clone(), int(10)], a.clone()),
            (vec![null(), int(2)], null()),
            (vec![Eval::Absent, int(2)], null()),
            (
                vec![a.clone(), dbl(1.5)],
                invalid("Cannot coerce Float64 (1.5) to Int64"),
            ),
        ] {
            assert_eq!(both(name, &args), expected, "{name} {args:?}");
        }
        assert_eq!(Expr::call(name, vec![Expr::Constant(Value::Null)], Placement::Value).unwrap_err().to_string(), format!("The function '{name}(array: array[any], n: int64): array[any]' takes [2..2] argument(s), but 1 was provided."));
    }
    assert_eq!(Expr::call("array_index_of", vec![Expr::Constant(Value::Null); 2], Placement::Value).unwrap_err().to_string(), "The function 'array_index_of(array: array[any], search: any, direction: (first|last)): int64' takes [3..3] argument(s), but 2 were provided.");
}

#[test]
fn array_subsequence_pict_rows() {
    let cases = [
        ("slice", "populated", "positive", "strict"),
        ("slice", "populated", "negative", "strict"),
        ("first", "populated", "zero", "emulator"),
        ("last", "populated", "large", "strict"),
        ("index", "populated", "positive", "strict"),
        ("index", "null", "negative", "emulator"),
        ("first", "absent", "large", "strict"),
        ("last", "empty", "zero", "emulator"),
        ("first", "empty", "negative", "strict"),
        ("index", "empty", "large", "emulator"),
        ("first", "null", "zero", "strict"),
        ("first", "absent", "positive", "emulator"),
        ("slice", "empty", "positive", "emulator"),
        ("slice", "absent", "zero", "strict"),
        ("last", "absent", "negative", "strict"),
        ("index", "absent", "zero", "strict"),
        ("last", "null", "positive", "emulator"),
        ("slice", "null", "large", "strict"),
    ];
    for (function, array_case, operand, profile) in cases {
        let items = vec![Value::Integer(1), Value::Integer(2), Value::Integer(1)];
        let input = match array_case {
            "populated" => array(items.clone()),
            "empty" => array(vec![]),
            "null" => null(),
            _ => Eval::Absent,
        };
        let n = match operand {
            "positive" => 2_i64,
            "zero" => 0,
            "negative" => -1,
            _ => 10,
        };
        let mode = if profile == "strict" {
            Unrecorded::Refuse
        } else {
            Unrecorded::OfficialEmulator
        };
        let name = match function {
            "slice" => "array_slice",
            "first" => "array_first_n",
            "last" => "array_last_n",
            _ => "array_index_of",
        };
        let args = if function == "index" {
            vec![input, int(n), text("first")]
        } else {
            vec![input, int(n)]
        };
        let expected = if matches!(array_case, "null" | "absent") {
            null()
        } else if function == "index" {
            let values: &[Value] = if array_case == "empty" { &[] } else { &items };
            int(values
                .iter()
                .position(|value| *value == Value::Integer(n))
                .map_or(-1, |index| i64::try_from(index).unwrap()))
        } else if n < 0 && function != "slice" {
            invalid(&format!(
                "The function `{name}(...)` requires non-negative count."
            ))
        } else {
            let values: &[Value] = if array_case == "empty" { &[] } else { &items };
            let count = usize::try_from(n.max(0)).unwrap().min(values.len());
            let selected = match function {
                "slice" => {
                    let start = if n < 0 {
                        values
                            .len()
                            .saturating_sub(usize::try_from(n.unsigned_abs()).unwrap())
                    } else {
                        count
                    };
                    &values[start..]
                }
                "first" => &values[..count],
                _ => &values[values.len() - count..],
            };
            array(selected.to_vec())
        };
        assert_eq!(
            call_in(name, &args, mode, false),
            expected,
            "{function}/{array_case}/{operand}/{profile}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn array_subsequence_matches_reference(items in proptest::collection::vec(-20_i64..20, 0..25), count in 0_usize..40, offset in -40_i64..40) {
        let values: Vec<Value> = items.iter().copied().map(Value::Integer).collect();
        let input = array(values.clone());
        let n = count.min(values.len());
        prop_assert_eq!(strict("array_first_n", &[input.clone(), int(i64::try_from(count).unwrap())]), array(values[..n].to_vec()));
        prop_assert_eq!(strict("array_last_n", &[input.clone(), int(i64::try_from(count).unwrap())]), array(values[values.len()-n..].to_vec()));
        let start = if offset < 0 { values.len().saturating_sub(usize::try_from(offset.unsigned_abs()).unwrap()) } else { usize::try_from(offset).unwrap().min(values.len()) };
        prop_assert_eq!(strict("array_slice", &[input.clone(), int(offset), int(i64::try_from(count).unwrap())]), array(values[start..start.saturating_add(count).min(values.len())].to_vec()));
        let needle = 3_i64;
        let expected = items.iter().position(|v| *v == needle).map_or(-1, |i| i64::try_from(i).unwrap());
        prop_assert_eq!(strict("array_index_of", &[input, int(needle), text("first")]), int(expected));
    }
}

#[test]
fn array_index_of_mixed_invalid_direction_remains_unobserved() {
    for input in [null(), int(5)] {
        assert!(is_unobserved(&strict(
            "array_index_of",
            &[input, int(1), text("middle")]
        )));
    }
    assert_eq!(
        strict("array_index_of", &[null(), int(1), text("first")]),
        null()
    );
}

#[test]
fn array_slice_bad_arity_returns_error_without_panicking() {
    for count in [0, 1, 4] {
        assert!(Expr::call(
            "array_slice",
            vec![Expr::Constant(Value::Null); count],
            Placement::Value
        )
        .is_err());
    }
}

#[test]
fn array_index_of_dynamic_direction_is_unobserved_only_in_strict() {
    let mut fields = BTreeMap::new();
    fields.insert("direction".to_owned(), Value::String("first".to_owned()));
    let row = Row::derived(fields);
    let value = Expr::Constant(Value::Array(vec![Value::Integer(7)]));
    let needle = Expr::Constant(Value::Integer(7));
    let field = Expr::Field(FieldPath::parse("direction").unwrap());
    let computed = Expr::call(
        "to_lower",
        vec![Expr::Constant(Value::String("FIRST".to_owned()))],
        Placement::Value,
    )
    .unwrap();
    for direction in [field, computed] {
        let expr = Expr::call(
            "array_index_of",
            vec![value.clone(), needle.clone(), direction],
            Placement::Value,
        )
        .unwrap();
        assert!(is_unobserved(&expr.eval_in(&row, Unrecorded::Refuse)));
        assert_eq!(expr.eval_in(&row, Unrecorded::OfficialEmulator), int(0));
    }
    let literal = Expr::call(
        "array_index_of",
        vec![
            value,
            needle,
            Expr::Constant(Value::String("first".to_owned())),
        ],
        Placement::Value,
    )
    .unwrap();
    assert_eq!(literal.eval_in(&row, Unrecorded::Refuse), int(0));
}

#[test]
fn recorded_join_results_and_arity() {
    let strings = array(vec![
        Value::String("a".into()),
        Value::String("b".into()),
        Value::String("c".into()),
    ]);
    let with_null = array(vec![Value::String("a".into()), Value::Null]);
    let cases = [
        (vec![strings.clone(), text(",")], text("a,b,c")),
        (vec![array(vec![]), text(",")], text("")),
        (
            vec![with_null.clone(), text(","), text("NULL")],
            text("a,NULL"),
        ),
        (vec![with_null, text(",")], text("a")),
        (
            vec![array(vec![Value::Integer(1), Value::Integer(2)]), text(",")],
            invalid("Cannot join non-string types."),
        ),
        (vec![strings, null()], null()),
        (vec![null(), text(",")], null()),
        (vec![Eval::Absent, text(",")], null()),
    ];
    for (args, expected) in cases {
        assert_eq!(both("join", &args), expected, "{args:?}");
    }
    let error = Expr::call("join", vec![Expr::Constant(Value::Null)], Placement::Value)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "The function 'join' does not accept 1 argument(s). Valid options are:\n- join[T: string | bytes](array: array[T], delimiter: T): string with [2..2] argument(s).\n- join[T: string | bytes](array: array[T], delimiter: T, null_text: T): string with [3..3] argument(s).");
}

#[test]
fn join_pict_rows() {
    let rows = [
        ("strings", "omitted", "comma", "strict"),
        ("empty", "omitted", "comma", "emulator"),
        ("null_element", "omitted", "comma", "strict"),
        ("null_element", "present", "comma", "strict"),
        ("null_input", "present", "empty", "emulator"),
        ("absent", "omitted", "empty", "strict"),
        ("empty", "present", "empty", "strict"),
        ("absent", "present", "comma", "emulator"),
        ("null_element", "present", "empty", "emulator"),
        ("null_input", "omitted", "comma", "strict"),
        ("strings", "present", "empty", "emulator"),
    ];
    for (shape, replacement, delimiter, profile) in rows {
        let items = match shape {
            "strings" => vec![Value::String("a".into()), Value::String("b".into())],
            "null_element" => vec![Value::String("a".into()), Value::Null],
            _ => vec![],
        };
        let input = match shape {
            "null_input" => null(),
            "absent" => Eval::Absent,
            _ => array(items.clone()),
        };
        let separator = if delimiter == "comma" { "," } else { "" };
        let mut args = vec![input, text(separator)];
        if replacement == "present" {
            args.push(text("X"));
        }
        let expected = if matches!(shape, "null_input" | "absent") {
            null()
        } else {
            let parts: Vec<&str> = items
                .iter()
                .filter_map(|item| match item {
                    Value::String(value) => Some(value.as_str()),
                    Value::Null if replacement == "present" => Some("X"),
                    _ => None,
                })
                .collect();
            text(&parts.join(separator))
        };
        let mode = if profile == "strict" {
            Unrecorded::Refuse
        } else {
            Unrecorded::OfficialEmulator
        };
        assert_eq!(
            call_in("join", &args, mode, false),
            expected,
            "{shape}/{replacement}/{delimiter}/{profile}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn join_matches_string_reference(items in proptest::collection::vec(proptest::option::of("[a-z]{0,8}"), 0..24), delimiter in "[,;|]{0,3}", replacement in proptest::option::of("[A-Z]{0,4}")) {
        let values: Vec<Value> = items.iter().map(|item| item.as_ref().map_or(Value::Null, |s| Value::String(s.clone()))).collect();
        let mut args = vec![array(values), text(&delimiter)];
        if let Some(value) = &replacement { args.push(text(value)); }
        let parts: Vec<&str> = items.iter().filter_map(|item| item.as_deref().or(replacement.as_deref())).collect();
        prop_assert_eq!(both("join", &args), text(&parts.join(&delimiter)));
    }
}

#[test]
fn join_bytes_and_ambiguous_invalid_arguments_are_unobserved() {
    for values in [
        vec![Value::Bytes(vec![97]), Value::Integer(1)],
        vec![Value::Integer(1), Value::Bytes(vec![97])],
    ] {
        assert!(is_unobserved(&strict("join", &[array(values), text(",")])));
    }
    assert!(is_unobserved(&strict(
        "join",
        &[array(vec![Value::Integer(1)]), null()]
    )));
    assert!(is_unobserved(&strict("join", &[null(), int(4)])));
}

#[test]
fn recorded_array_extrema_results_and_arity() {
    let input = array(vec![
        Value::Integer(1),
        Value::Integer(2),
        Value::Integer(3),
    ]);
    for (name, expected_two, expected_all) in [
        (
            "maximum_n",
            vec![Value::Integer(3), Value::Integer(2)],
            vec![Value::Integer(3), Value::Integer(2), Value::Integer(1)],
        ),
        (
            "minimum_n",
            vec![Value::Integer(1), Value::Integer(2)],
            vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)],
        ),
    ] {
        for (args, expected) in [
            (vec![input.clone(), int(2)], array(expected_two)),
            (vec![input.clone(), int(10)], array(expected_all)),
            (vec![input.clone(), int(0)], array(vec![])),
            (vec![null(), int(2)], null()),
            (vec![Eval::Absent, int(2)], null()),
            (vec![int(5), int(2)], wrong(name, "Array", "LONG")),
        ] {
            assert_eq!(both(name, &args), expected, "{name} {args:?}");
        }
        assert_eq!(Expr::call(name, vec![], Placement::Value).unwrap_err().to_string(), format!("The function '{name}(input: array[any?], n: int64): array[any]' takes [2..2] argument(s), but 0 were provided."));
    }
}

#[test]
fn array_extrema_pict_rows() {
    let cases = [
        ("maximum", "integers", "two", "strict"),
        ("minimum", "integers", "two", "strict"),
        ("maximum", "null_elements", "large", "emulator"),
        ("minimum", "strings", "large", "strict"),
        ("maximum", "empty", "zero", "emulator"),
        ("minimum", "null", "two", "strict"),
        ("maximum", "absent", "large", "strict"),
        ("minimum", "integers", "negative", "emulator"),
        ("maximum", "integers", "large", "strict"),
        ("maximum", "strings", "zero", "emulator"),
        ("minimum", "empty", "large", "strict"),
        ("minimum", "empty", "two", "emulator"),
        ("maximum", "empty", "negative", "strict"),
        ("minimum", "absent", "negative", "emulator"),
        ("maximum", "null", "zero", "emulator"),
        ("minimum", "null_elements", "two", "strict"),
        ("maximum", "absent", "two", "strict"),
        ("minimum", "null", "large", "emulator"),
        ("minimum", "null_elements", "negative", "emulator"),
        ("minimum", "absent", "zero", "strict"),
        ("maximum", "strings", "two", "emulator"),
        ("minimum", "integers", "zero", "emulator"),
        ("maximum", "strings", "negative", "strict"),
        ("minimum", "null", "negative", "emulator"),
        ("maximum", "null_elements", "zero", "emulator"),
    ];
    for (function, shape, count, profile) in cases {
        let (input, mut ordered) = match shape {
            "integers" => (
                array(vec![
                    Value::Integer(3),
                    Value::Integer(1),
                    Value::Integer(2),
                ]),
                vec![Value::Integer(1), Value::Integer(2), Value::Integer(3)],
            ),
            "strings" => (
                array(vec![Value::String("c".into()), Value::String("a".into())]),
                vec![Value::String("a".into()), Value::String("c".into())],
            ),
            "null_elements" => (
                array(vec![Value::Integer(2), Value::Null, Value::Integer(1)]),
                vec![Value::Integer(1), Value::Integer(2)],
            ),
            "empty" => (array(vec![]), vec![]),
            "null" => (null(), vec![]),
            _ => (Eval::Absent, vec![]),
        };
        let n = match count {
            "zero" => 0_i64,
            "two" => 2,
            "negative" => -1,
            _ => 10,
        };
        let name = if function == "maximum" {
            "maximum_n"
        } else {
            "minimum_n"
        };
        let mode = if profile == "strict" {
            Unrecorded::Refuse
        } else {
            Unrecorded::OfficialEmulator
        };
        let got = call_in(name, &[input, int(n)], mode, false);
        if matches!(shape, "null" | "absent") {
            assert_eq!(got, null());
        } else if n < 0 {
            assert!(is_unobserved(&got));
        } else {
            if function == "maximum" {
                ordered.reverse();
            }
            ordered.truncate(usize::try_from(n).unwrap());
            assert_eq!(got, array(ordered), "{function}/{shape}/{count}/{profile}");
        }
    }
}

#[test]
fn extrema_mixed_types_ties_and_negative_count_remain_unobserved() {
    for name in ["maximum_n", "minimum_n"] {
        let mixed = array(vec![Value::Integer(1), Value::String("a".into())]);
        assert!(is_unobserved(&strict(name, &[mixed, int(1)])));
        assert!(is_unobserved(&strict(
            name,
            &[array(vec![Value::Integer(1)]), int(-1)]
        )));
        let duplicate = array(vec![Value::Integer(2), Value::Integer(2)]);
        assert_eq!(
            strict(name, &[duplicate, int(2)]),
            array(vec![Value::Integer(2), Value::Integer(2)])
        );
        assert!(is_unobserved(&strict(
            name,
            &[array(vec![Value::Integer(1), Value::Double(1.0)]), int(1)]
        )));
        assert!(is_unobserved(&strict(
            name,
            &[
                array(vec![Value::Double(f64::NAN), Value::Double(f64::NAN)]),
                int(1)
            ]
        )));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn array_extrema_matches_integer_reference(items in proptest::collection::vec(-100_i64..100, 0..30), n in 0_usize..40) {
        let input = array(items.iter().copied().map(Value::Integer).collect());
        let mut sorted = items.clone(); sorted.sort_unstable();
        let first: Vec<Value> = sorted.iter().take(n).copied().map(Value::Integer).collect();
        let last: Vec<Value> = sorted.iter().rev().take(n).copied().map(Value::Integer).collect();
        prop_assert_eq!(strict("minimum_n", &[input.clone(), int(i64::try_from(n).unwrap())]), array(first));
        prop_assert_eq!(strict("maximum_n", &[input, int(i64::try_from(n).unwrap())]), array(last));
    }
}

#[test]
fn extrema_distinguishable_signed_zero_ties_are_unobserved() {
    for name in ["maximum_n", "minimum_n"] {
        for (left, right) in [
            (Value::Double(-0.0), Value::Double(0.0)),
            (Value::Double(0.0), Value::Double(-0.0)),
            (
                Value::Array(vec![Value::Double(-0.0)]),
                Value::Array(vec![Value::Double(0.0)]),
            ),
            (
                Value::Array(vec![Value::Double(0.0)]),
                Value::Array(vec![Value::Double(-0.0)]),
            ),
        ] {
            assert!(
                is_unobserved(&strict(name, &[array(vec![left, right]), int(1)])),
                "{name}"
            );
        }
    }
}

#[test]
fn map_set_odd_count_is_recorded_arity_and_minimum_still_precedes_it() {
    let args = vec![Expr::Constant(Value::Null); 4];
    assert!(
        matches!(Expr::call("map_set", args, Placement::Value), Err(ExprError::Arity(message)) if message == "'map_set' function must have an odd number of arguments")
    );
    let args = vec![Expr::Constant(Value::Null); 2];
    assert!(
        matches!(Expr::call("map_set", args, Placement::Value), Err(ExprError::Arity(message)) if message.contains("takes [3..+∞)"))
    );
    let args = vec![Expr::Constant(Value::Null); 3];
    assert!(Expr::call("map_set", args, Placement::Value).is_ok());
}

#[test]
fn sqrt_observed_wrong_type_and_unobserved_strict_numeric() {
    assert!(function("sqrt").is_some(), "sqrt must be registered");
    assert_eq!(both("sqrt", &[text("s")]), wrong("sqrt", "Float", "STRING"));
    for value in [
        int(25),
        dbl(0.0),
        dbl(-1.0),
        dbl(f64::NAN),
        dbl(f64::INFINITY),
        null(),
        Eval::Absent,
    ] {
        assert!(
            is_unobserved(&strict("sqrt", &[value])),
            "strict sqrt must not claim unobserved values"
        );
    }
}

#[test]
fn sqrt_ordinary_numeric_examples_and_domain() {
    assert_eq!(emulator("sqrt", &[int(25)]), dbl(5.0));
    assert_eq!(emulator("sqrt", &[dbl(0.0)]), dbl(0.0));
    assert!(
        matches!(emulator("sqrt", &[dbl(f64::NAN)]), Eval::Value(Value::Double(x)) if x.is_nan())
    );
    assert!(
        matches!(emulator("sqrt", &[dbl(f64::INFINITY)]), Eval::Value(Value::Double(x)) if x == f64::INFINITY)
    );
    assert!(matches!(
        emulator("sqrt", &[dbl(-1.0)]),
        Eval::Error(EvalError::Invalid(_))
    ));
    assert!(matches!(
        emulator("sqrt", &[dbl(f64::NEG_INFINITY)]),
        Eval::Error(EvalError::Invalid(_))
    ));
    assert!(matches!(
        emulator("sqrt", &[dbl(-0.0)]),
        Eval::Value(Value::Double(value)) if value == 0.0 && value.is_sign_negative()
    ));
    assert!(is_unobserved(&strict("sqrt", &[dbl(f64::NEG_INFINITY)])));
    assert!(is_unobserved(&strict("sqrt", &[dbl(-0.0)])));
}

#[test]
fn sqrt_seeded_pairwise_cases_cover_registered_execution() {
    let cases = r"Input	Profile	Position	Rows	Arity
string	strict	is_error	populated	valid
string	strict	where	populated	valid
string	strict	select	empty	valid
string	strict	where	empty	valid
positive	ordinary	select	populated	valid
zero	ordinary	select	populated	valid
negative	ordinary	select	populated	valid
nan	ordinary	select	populated	valid
infinity	ordinary	select	populated	valid
zero	ordinary	is_error	empty	invalid
negative	strict	where	empty	invalid
missing	strict	is_error	populated	invalid
infinity	ordinary	where	empty	invalid
nan	strict	where	empty	invalid
other	ordinary	select	populated	invalid
null	ordinary	select	populated	valid
positive	strict	is_error	empty	invalid
positive	strict	where	populated	valid
other	strict	is_error	empty	valid
infinity	strict	is_error	populated	invalid
missing	ordinary	select	empty	valid
null	strict	is_error	empty	invalid
negative	ordinary	is_error	empty	invalid
missing	ordinary	where	populated	invalid
zero	strict	where	empty	invalid
nan	ordinary	is_error	empty	invalid
null	strict	where	empty	valid
string	ordinary	is_error	populated	invalid
other	strict	where	empty	valid
";
    for line in cases.lines().skip(1) {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 5, "{line}");
        let [kind, profile, position, rows, arity] = columns.as_slice() else {
            unreachable!()
        };
        if *arity == "invalid" {
            assert!(
                Expr::call("sqrt", vec![], Placement::Value).is_err(),
                "{line}"
            );
            continue;
        }
        let value = match *kind {
            "string" => Some(Value::String("s".to_owned())),
            "positive" => Some(Value::Double(25.0)),
            "zero" => Some(Value::Double(0.0)),
            "negative" => Some(Value::Double(-1.0)),
            "nan" => Some(Value::Double(f64::NAN)),
            "infinity" => Some(Value::Double(f64::INFINITY)),
            "null" => Some(Value::Null),
            "missing" => None,
            "other" => Some(Value::Boolean(true)),
            _ => panic!("unknown input: {line}"),
        };
        let row = Row::derived(value.map_or_else(BTreeMap::new, |v| {
            [("v".to_owned(), v)].into_iter().collect()
        }));
        let arg = Expr::Field(FieldPath::parse("v").unwrap());
        let sqrt = Expr::call("sqrt", vec![arg], Placement::Value).unwrap();
        let expr = if *position == "is_error" {
            Expr::call("is_error", vec![sqrt], Placement::Value).unwrap()
        } else {
            sqrt
        };
        let stage = if *position == "where" {
            Stage::Where(expr)
        } else {
            Stage::Select {
                aliases: vec![(FieldPath::parse("out").unwrap(), expr)],
                keeps_name: false,
            }
        };
        let input = if *rows == "empty" { vec![] } else { vec![row] };
        let strict_profile = *profile == "strict";
        let unrecorded = if strict_profile {
            Unrecorded::Refuse
        } else {
            Unrecorded::OfficialEmulator
        };
        let result = execute_rows_in(vec![stage], input, unrecorded);
        if *rows == "empty" {
            assert_eq!(result.unwrap().len(), 0, "{line}");
            continue;
        }
        if strict_profile && *kind != "string" {
            assert!(
                matches!(result, Err(EvalError::Unobserved { .. })),
                "{line}: {result:?}"
            );
        } else if (*kind == "string"
            || *kind == "other"
            || (!strict_profile && *kind == "negative"))
            && *position != "is_error"
        {
            assert!(result.is_err(), "{line}: {result:?}");
        } else {
            assert!(result.is_ok(), "{line}: {result:?}");
        }
    }
}

proptest! {
    #[test]
    fn ordinary_sqrt_squares_nonnegative_finite_inputs(value in 0_u32..1_000_000) {
        let result = emulator("sqrt", &[dbl(f64::from(value))]);
        let Eval::Value(Value::Double(root)) = result else { panic!("expected numeric result") };
        prop_assert!((root * root - f64::from(value)).abs() <= 1e-8);
        prop_assert!(is_unobserved(&strict("sqrt", &[dbl(f64::from(value))])));
    }
}

#[test]
fn sqrt_declares_one_argument_without_claiming_unobserved_error_text() {
    assert_eq!(Expr::call("sqrt", vec![], Placement::Value).unwrap_err().to_string(), "The function 'sqrt(number: number): float64' takes [1..1] argument(s), but 0 were provided.");
    assert!(Expr::call(
        "sqrt",
        vec![
            Expr::Constant(Value::Double(1.0)),
            Expr::Constant(Value::Double(2.0))
        ],
        Placement::Value
    )
    .is_err());
    assert!(Expr::call(
        "sqrt",
        vec![Expr::Constant(Value::Double(1.0))],
        Placement::Value
    )
    .is_ok());
}

#[test]
fn sqrt_propagates_an_existing_error_before_inspecting_the_input() {
    let previous = Eval::Error(EvalError::WrongType {
        function: "inner",
        expected: "String",
        got: "LONG",
    });
    assert_eq!(strict("sqrt", std::slice::from_ref(&previous)), previous);
    assert_eq!(emulator("sqrt", std::slice::from_ref(&previous)), previous);
}

#[test]
fn sqrt_where_propagates_the_observed_wrong_type_class() {
    let sqrt = || {
        Expr::call(
            "sqrt",
            vec![Expr::Field(FieldPath::parse("v").unwrap())],
            Placement::Value,
        )
        .unwrap()
    };
    let gt = |arg| {
        Expr::call(
            "greater_than",
            vec![sqrt(), Expr::Constant(Value::Integer(arg))],
            Placement::Condition,
        )
        .unwrap()
    };
    let row = || {
        Row::derived(
            [("v".to_owned(), Value::String("s".to_owned()))]
                .into_iter()
                .collect(),
        )
    };
    let recorded = execute_rows_in(vec![Stage::Where(gt(0))], vec![row()], Unrecorded::Refuse);
    assert!(matches!(
        recorded,
        Err(EvalError::WrongType {
            function: "sqrt",
            expected: "Float",
            got: "STRING"
        })
    ));
    let same_error = execute_rows_in(vec![Stage::Where(gt(1))], vec![row()], Unrecorded::Refuse);
    assert!(matches!(
        same_error,
        Err(EvalError::WrongType {
            function: "sqrt",
            expected: "Float",
            got: "STRING"
        })
    ));
}

#[test]
fn numeric_family_documented_cases_and_strict_boundary() {
    for (name, args, expected) in [
        ("exp", vec![int(0)], 1.0),
        ("ln", vec![int(1)], 0.0),
        ("log", vec![int(100), int(10)], 2.0),
        ("log10", vec![int(100)], 2.0),
        ("trunc", vec![dbl(-15.5)], -15.0),
        ("trunc", vec![dbl(15.5)], 15.0),
    ] {
        assert_eq!(emulator(name, &args), dbl(expected), "{name}");
        assert!(is_unobserved(&strict(name, &args)), "{name}");
    }
    assert_eq!(emulator("trunc", &[int(15), int(0)]), int(15));
    assert!(matches!(emulator("ln", &[int(0)]), Eval::Error(_)));
    assert!(matches!(
        emulator("log", &[int(10), int(1)]),
        Eval::Error(_)
    ));
}

#[test]
fn numeric_family_seeded_pairwise_and_edges() {
    let rows = r"Function	Profile	Input	Arity
exp	ordinary	positive	one
log	ordinary	positive	two
trunc	ordinary	positive	two
ln	strict	null	one
exp	strict	null	one
log	strict	wrong	one
log10	ordinary	null	one
exp	strict	domain	one
log10	strict	positive	one
ln	ordinary	positive	one
log	strict	null	two
exp	ordinary	wrong	one
log10	ordinary	wrong	one
trunc	ordinary	domain	one
ln	ordinary	wrong	one
trunc	strict	wrong	two
log	strict	domain	two
ln	ordinary	domain	one
log10	strict	domain	one
trunc	ordinary	null	two
";
    for line in rows.lines().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        let name = fields[0];
        let input = match fields[2] {
            "positive" => int(2),
            "null" => Eval::Value(Value::Null),
            "wrong" => Eval::Value(Value::String("x".into())),
            "domain" => int(0),
            _ => unreachable!(),
        };
        let mut args = vec![input];
        if fields[3] == "two" {
            args.push(int(2));
        }
        let value = if fields[1] == "strict" {
            strict(name, &args)
        } else {
            emulator(name, &args)
        };
        if fields[1] == "strict" {
            assert!(is_unobserved(&value), "{line}");
        }
    }
    assert_eq!(emulator("trunc", &[int(-15), int(0)]), int(-15));
    assert!(is_unobserved(&emulator(
        "trunc",
        &[int(i64::MIN), int(i64::MIN)]
    )));
    for name in ["ln", "log10"] {
        assert!(
            matches!(emulator(name, &[dbl(f64::NEG_INFINITY)]), Eval::Value(Value::Double(x)) if x.is_nan())
        );
    }
    assert!(matches!(
        emulator("log", &[int(10), int(1)]),
        Eval::Error(_)
    ));
}

proptest! {
    #[test]
    fn numeric_family_trunc_integer_is_toward_zero(value in -1_000_000_i64..1_000_000) {
        prop_assert_eq!(emulator("trunc", &[int(value), int(0)]), int(value));
        prop_assert!(is_unobserved(&strict("trunc", &[int(value), int(0)])));
    }
}

#[test]
fn numeric_family_decimal_and_special_boundaries_are_conservative() {
    for value in [0.29, -0.29, 1.15] {
        assert!(is_unobserved(&emulator("trunc", &[dbl(value), int(2)])));
    }
    for value in [1e-320, -1e-320] {
        assert!(is_unobserved(&emulator("trunc", &[dbl(value), int(309)])));
    }
    for value in [-0.0, -0.001] {
        let Eval::Value(Value::Double(result)) = emulator("trunc", &[dbl(value), int(0)]) else {
            panic!("expected double");
        };
        assert_eq!(result.to_bits(), (-0.0_f64).to_bits());
    }
    assert!(is_unobserved(&emulator("log", &[int(0), dbl(f64::NAN)])));
}
