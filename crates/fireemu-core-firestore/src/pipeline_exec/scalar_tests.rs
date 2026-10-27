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
    assert_eq!(NAMES.len(), 22);
    for name in [
        "regex_contains",
        "regex_match",
        "regex_find",
        "regex_find_all",
        "sqrt",
    ] {
        assert!(function(name).is_none(), "{name}");
    }
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
