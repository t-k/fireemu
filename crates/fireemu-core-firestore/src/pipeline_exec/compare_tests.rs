// PX1a: comparisons, array and map literals, and the profile rules for inputs whose
// production answer is unrecorded.
#![allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]

use super::official_compare::{MATRIX, OPERANDS};
use super::*;
use crate::value::Timestamp;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use proptest::prelude::*;

const OPS: [&str; 6] = [
    "equal",
    "not_equal",
    "less_than",
    "less_than_or_equal",
    "greater_than",
    "greater_than_or_equal",
];

fn row(fields: Vec<(String, Value)>) -> Row {
    Row {
        path: DocumentPath::parse(
            &ProjectId::try_new("p").unwrap(),
            &DatabaseId::try_new("(default)").unwrap(),
            "c/d",
        )
        .unwrap(),
        fields: fields.into_iter().collect(),
    }
}

fn field(p: &str) -> Expr {
    Expr::Field(FieldPath::parse(p).unwrap())
}

fn call(name: &str, args: Vec<Expr>) -> Expr {
    Expr::call(name, args, Placement::Value).unwrap()
}

fn boolean(b: bool) -> Eval {
    Eval::Value(Value::Boolean(b))
}

fn unobserved(e: &Eval) -> bool {
    matches!(e, Eval::Error(EvalError::Unobserved { .. }))
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

/// The operand classes of the official matrix, as the Admin SDK wrote them (a JS `1.0` is an
/// integer; `-0` is the double negative zero). `x` is absent.
fn operand(name: &str) -> Option<Value> {
    Some(match name {
        "x" => return None,
        "n" => Value::Null,
        "nan" => Value::Double(f64::NAN),
        "i" | "one" => Value::Integer(1),
        "i2" => Value::Integer(2),
        "d5" => Value::Double(1.5),
        "nz" => Value::Double(-0.0),
        "s" => s("a"),
        "s2" => s("b"),
        "b" => Value::Boolean(true),
        "bf" => Value::Boolean(false),
        "arr" => Value::Array(vec![Value::Integer(1), s("a")]),
        "arr2" => Value::Array(vec![Value::Integer(1), s("b")]),
        "arrn" => Value::Array(vec![Value::Null]),
        "m" => Value::Map([("a".to_owned(), Value::Integer(1))].into()),
        "m2" => Value::Map([("a".to_owned(), Value::Integer(2))].into()),
        "ts" => Value::Timestamp(Timestamp::new(0, 0).unwrap()),
        "ts2" => Value::Timestamp(Timestamp::new(1, 0).unwrap()),
        other => panic!("{other}"),
    })
}

fn matrix_row() -> Row {
    row(OPERANDS
        .iter()
        .filter_map(|name| operand(name).map(|v| ((*name).to_owned(), v)))
        .collect())
}

#[test]
fn the_table_lists_the_comparisons_and_literals() {
    for name in OPS {
        let f = function(name).unwrap();
        assert_eq!(f.arity, Arity::Exact(2), "{name}");
        assert!(f.returns_boolean, "{name}");
        assert_eq!(f.placement, Placement::Value, "{name}");
    }
    assert_eq!(function("array").unwrap().arity, Arity::Any);
    assert_eq!(function("map").unwrap().arity, Arity::Pairs);
    for name in ["array", "map", "document_id", "collection_id", "parent"] {
        assert!(!function(name).unwrap().returns_boolean, "{name}");
    }
    // A boolean function may be a whole where condition; a value function may not.
    assert!(Expr::call(
        "less_than",
        vec![field("a"), field("b")],
        Placement::Condition
    )
    .is_ok());
    assert!(matches!(
        Expr::call("document_id", vec![field("__name__")], Placement::Condition),
        Err(ExprError::Unsupported(_))
    ));
    assert!(matches!(
        Expr::call("map", vec![Expr::Constant(s("k"))], Placement::Value),
        Err(ExprError::Invalid(_))
    ));
    assert!(Expr::call("array", vec![], Placement::Value).is_ok());
    assert!(Expr::call("map", vec![], Placement::Value).is_ok());
}

/// The emulator profile answers every cell of the official emulator's matrix.
#[test]
fn the_emulator_profile_answers_the_official_matrix() {
    let r = matrix_row();
    for (op, rows) in MATRIX {
        for (li, left) in OPERANDS.iter().enumerate() {
            for (ri, right) in OPERANDS.iter().enumerate() {
                let expected = rows[li].as_bytes()[ri] == b'T';
                let expr = call(op, vec![field(left), field(right)]);
                assert_eq!(
                    expr.eval_in(&r, Unrecorded::OfficialEmulator),
                    boolean(expected),
                    "{op}({left}, {right})"
                );
                // At the top of a where condition the emulator profile answers the same.
                assert_eq!(
                    expr.eval_condition_in(&r, Unrecorded::OfficialEmulator),
                    boolean(expected),
                    "{op}({left}, {right}) as a condition"
                );
            }
        }
    }
}

/// Strict answers only what classic queries already decide, and then what the official
/// emulator answers; everything else is unobserved.
#[test]
fn strict_answers_a_subset_of_the_official_matrix() {
    let r = matrix_row();
    for (op, rows) in MATRIX {
        for (li, left) in OPERANDS.iter().enumerate() {
            for (ri, right) in OPERANDS.iter().enumerate() {
                let expected = rows[li].as_bytes()[ri] == b'T';
                let got = call(op, vec![field(left), field(right)]).eval_in(&r, Unrecorded::Refuse);
                let absent = *left == "x" || *right == "x";
                let special = |name: &str| name == "n" || name == "nan";
                let refused = absent || (op != "equal" && (special(left) || special(right)));
                if refused {
                    assert!(unobserved(&got), "{op}({left}, {right}) = {got:?}");
                } else {
                    assert_eq!(got, boolean(expected), "{op}({left}, {right})");
                }
            }
        }
    }
}

/// At the top of a where condition, strict drops a row whose comparison has one absent operand
/// (classic queries never match a missing field, and the official answer, false, drops it
/// too), except for `not_equal`, where the official emulator keeps the row and classic
/// `!=` drops it.
#[test]
fn strict_drops_one_absent_operand_at_the_top_of_where() {
    let r = row(vec![("i".to_owned(), Value::Integer(1))]);
    for op in OPS {
        let one_absent = call(op, vec![field("x"), field("i")]);
        let got = one_absent.eval_condition_in(&r, Unrecorded::Refuse);
        if op == "not_equal" {
            assert!(unobserved(&got), "{op}");
        } else {
            assert_eq!(got, Eval::Absent, "{op}");
        }
        // Both absent is no classic shape.
        assert!(unobserved(
            &call(op, vec![field("x"), field("y")]).eval_condition_in(&r, Unrecorded::Refuse)
        ));
        // Below the top, absence is unobserved.
        assert!(
            unobserved(&one_absent.eval_in(&r, Unrecorded::Refuse)),
            "{op}"
        );
    }
}

#[test]
fn comparison_errors_propagate_first() {
    let r = row(vec![("i".to_owned(), Value::Integer(1))]);
    let error = call("document_id", vec![field("i")]);
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        for op in OPS {
            for args in [
                vec![error.clone(), field("i")],
                vec![field("i"), error.clone()],
                vec![field("x"), error.clone()],
            ] {
                let got = call(op, args).eval_in(&r, unrecorded);
                assert!(
                    matches!(
                        got,
                        Eval::Error(EvalError::Unobserved {
                            function: "document_id",
                            ..
                        })
                    ),
                    "{op} {unrecorded:?}: {got:?}"
                );
            }
        }
    }
}

/// `array(...)` and `map(...)` as the official emulator answers them: a missing element is
/// null in an array and leaves its key out of a map (`official-px1-probe.json`:
/// `array(i,x)` = `[1, null]`, `map(k:i,k2:x)` = `{k: 1}`). Strict refuses a missing element.
#[test]
fn array_and_map_literals() {
    let r = row(vec![
        ("i".to_owned(), Value::Integer(1)),
        ("s".to_owned(), s("a")),
    ]);
    let k = |v: &str| Expr::Constant(s(v));
    let array = call("array", vec![field("i"), field("x")]);
    assert_eq!(
        array.eval_in(&r, Unrecorded::OfficialEmulator),
        Eval::Value(Value::Array(vec![Value::Integer(1), Value::Null]))
    );
    assert!(unobserved(&array.eval_in(&r, Unrecorded::Refuse)));
    let full = call(
        "array",
        vec![field("i"), field("s"), Expr::Constant(Value::Null)],
    );
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert_eq!(
            full.eval_in(&r, unrecorded),
            Eval::Value(Value::Array(vec![Value::Integer(1), s("a"), Value::Null]))
        );
        assert_eq!(
            call("array", vec![]).eval_in(&r, unrecorded),
            Eval::Value(Value::Array(vec![]))
        );
    }
    let map = call("map", vec![k("k"), field("i"), k("k2"), field("x")]);
    assert_eq!(
        map.eval_in(&r, Unrecorded::OfficialEmulator),
        Eval::Value(Value::Map([("k".to_owned(), Value::Integer(1))].into()))
    );
    assert!(unobserved(&map.eval_in(&r, Unrecorded::Refuse)));
    let whole = call("map", vec![k("k"), field("i"), k("j"), field("s")]);
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert_eq!(
            whole.eval_in(&r, unrecorded),
            Eval::Value(Value::Map(
                [
                    ("k".to_owned(), Value::Integer(1)),
                    ("j".to_owned(), s("a"))
                ]
                .into()
            ))
        );
    }
    // A key that is not a string is unrecorded; a repeated key too under strict.
    let bad_key = call("map", vec![Expr::Constant(Value::Integer(1)), field("i")]);
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert!(unobserved(&bad_key.eval_in(&r, unrecorded)));
    }
    let repeated = call("map", vec![k("k"), field("i"), k("k"), field("s")]);
    assert!(unobserved(&repeated.eval_in(&r, Unrecorded::Refuse)));
    // Errors propagate.
    let error = call("document_id", vec![field("i")]);
    assert!(unobserved(
        &call("array", vec![error.clone()]).eval_in(&r, Unrecorded::OfficialEmulator)
    ));
    assert!(unobserved(
        &call("map", vec![k("k"), error]).eval_in(&r, Unrecorded::OfficialEmulator)
    ));
    // A literal compares with a field (the official matrix's arrays compare deeply).
    let eq = call(
        "equal",
        vec![
            call("array", vec![field("i"), field("s")]),
            Expr::Constant(Value::Array(vec![Value::Integer(1), s("a")])),
        ],
    );
    assert_eq!(eq.eval_in(&r, Unrecorded::Refuse), boolean(true));
}

/// The cursor keeps a row only when the condition is true; a comparison may also be a select
/// value now.
#[test]
fn comparisons_in_where_and_select() {
    let input = vec![
        row(vec![("i".to_owned(), Value::Integer(1))]),
        row(vec![("i".to_owned(), Value::Integer(5))]),
    ];
    let stages = |unrecorded| {
        execute_in(
            vec![
                Stage::Where(
                    Expr::call(
                        "less_than",
                        vec![field("i"), Expr::Constant(Value::Integer(3))],
                        Placement::Condition,
                    )
                    .unwrap(),
                ),
                Stage::Select(vec![(
                    FieldPath::parse("big").unwrap(),
                    call(
                        "greater_than",
                        vec![field("i"), Expr::Constant(Value::Integer(0))],
                    ),
                )]),
            ],
            input.clone(),
            unrecorded,
        )
        .unwrap()
    };
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert_eq!(
            stages(unrecorded),
            vec![[("big".to_owned(), Value::Boolean(true))].into()]
        );
    }
}

fn value() -> impl Strategy<Value = Option<Value>> {
    let scalar = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Boolean),
        (-2_i64..3).prop_map(Value::Integer),
        prop_oneof![Just(f64::NAN), Just(-0.0), Just(0.0), Just(1.0), Just(1.5)]
            .prop_map(Value::Double),
        "[ab]{0,2}".prop_map(Value::String),
        (0_i64..2).prop_map(|seconds| Value::Timestamp(Timestamp::new(seconds, 0).unwrap())),
    ];
    let value = scalar.prop_recursive(2, 8, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..3).prop_map(Value::Array),
            prop::collection::btree_map("[ab]", inner, 0..2).prop_map(Value::Map),
        ]
    });
    prop::option::weighted(0.85, value)
}

fn eval_op(op: &str, a: Option<&Value>, b: Option<&Value>, unrecorded: Unrecorded) -> Eval {
    let mut fields = Vec::new();
    if let Some(a) = a {
        fields.push(("a".to_owned(), a.clone()));
    }
    if let Some(b) = b {
        fields.push(("b".to_owned(), b.clone()));
    }
    call(op, vec![field("a"), field("b")]).eval_in(&row(fields), unrecorded)
}

fn official(op: &str, a: Option<&Value>, b: Option<&Value>) -> bool {
    match eval_op(op, a, b, Unrecorded::OfficialEmulator) {
        Eval::Value(Value::Boolean(v)) => v,
        other => panic!("{op}: {other:?}"),
    }
}

/// The classic answer of `field op literal` (a missing field never matches, null and NaN only
/// through `IS_NULL` / `IS_NAN` equality, ranges only within one type), where classic queries have
/// one.
fn classic(op: &str, field: Option<&Value>, literal: &Value) -> Option<bool> {
    let nan = |v: &Value| matches!(v, Value::Double(d) if d.is_nan());
    let field = field?;
    if op == "equal" {
        return Some(values_equal(field, literal));
    }
    if matches!(field, Value::Null) || matches!(literal, Value::Null) || nan(field) || nan(literal)
    {
        return None;
    }
    if op == "not_equal" {
        return Some(!values_equal(field, literal));
    }
    if field.kind() != literal.kind() {
        return Some(false);
    }
    let order = field.canonical_cmp(literal);
    Some(match op {
        "less_than" => order == Ordering::Less,
        "less_than_or_equal" => order != Ordering::Greater,
        "greater_than" => order == Ordering::Greater,
        _ => order != Ordering::Less,
    })
}

proptest! {
    /// The official order: not_equal is the negation of equal, the inclusive comparisons are
    /// the strict ones or equality, greater is the mirror of less, and less is antisymmetric.
    #[test]
    fn the_official_comparisons_are_one_order(a in value(), b in value()) {
        let (a, b) = (a.as_ref(), b.as_ref());
        let eq = official("equal", a, b);
        prop_assert_eq!(official("equal", b, a), eq);
        prop_assert_eq!(official("not_equal", a, b), !eq);
        let lt = official("less_than", a, b);
        prop_assert_eq!(official("less_than_or_equal", a, b), lt || eq);
        prop_assert_eq!(official("greater_than", b, a), lt);
        prop_assert_eq!(official("greater_than_or_equal", b, a), lt || eq);
        prop_assert!(!(lt && official("less_than", b, a)));
        prop_assert!(!(lt && eq));
        prop_assert!(official("equal", a, a));
    }

    /// Whenever strict answers, it answers what the official emulator answers.
    #[test]
    fn strict_answers_agree_with_the_official_emulator(a in value(), b in value()) {
        for op in OPS {
            match eval_op(op, a.as_ref(), b.as_ref(), Unrecorded::Refuse) {
                Eval::Value(Value::Boolean(v)) => prop_assert_eq!(v, official(op, a.as_ref(), b.as_ref()), "{}", op),
                Eval::Error(EvalError::Unobserved { .. }) => {}
                other => prop_assert!(false, "{op}: {other:?}"),
            }
        }
    }

    /// At the top of a where, strict keeps exactly the rows classic queries keep for
    /// `field op literal`, wherever classic queries have an answer and strict answers.
    #[test]
    fn strict_where_matches_classic_queries(stored in value(), literal in value().prop_filter("a literal is present", Option::is_some)) {
        let literal = literal.unwrap();
        for op in OPS {
            let mut fields = Vec::new();
            if let Some(v) = &stored {
                fields.push(("f".to_owned(), v.clone()));
            }
            let got = Expr::call(op, vec![field("f"), Expr::Constant(literal.clone())], Placement::Condition)
                .unwrap()
                .eval_condition_in(&row(fields), Unrecorded::Refuse);
            let kept = match got {
                Eval::Value(Value::Boolean(v)) => Some(v),
                Eval::Absent => Some(false),
                Eval::Error(EvalError::Unobserved { .. }) => None,
                other => { prop_assert!(false, "{op}: {other:?}"); None }
            };
            if let (Some(kept), Some(expected)) = (kept, classic(op, stored.as_ref(), &literal)) {
                prop_assert_eq!(kept, expected, "{}", op);
            }
            // Strict answers every equality classic queries answer.
            if op == "equal" && stored.is_some() {
                prop_assert!(kept.is_some());
            }
        }
    }
}

/// A comparison's refusal names the comparison.
#[test]
fn comparison_refusals_name_the_function() {
    let r = row(vec![("n".to_owned(), Value::Null)]);
    for op in OPS {
        let got = call(op, vec![field("x"), field("n")]).eval_in(&r, Unrecorded::Refuse);
        assert!(
            matches!(got, Eval::Error(EvalError::Unobserved { function, .. }) if function == op),
            "{op}: {got:?}"
        );
    }
}
