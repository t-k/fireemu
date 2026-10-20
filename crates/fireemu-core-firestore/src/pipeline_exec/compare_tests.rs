// PX1a: comparisons, array and map literals, and the profile rules for inputs whose
// production answer is unrecorded. FS-ENT-ORACLE O-1 (2026-10-19) recorded production
// answering every comparison probe as the official emulator does, so both profiles answer the
// official matrix.
#![allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]

use super::official_compare::matrix;
use super::*;
use crate::value::{Timestamp, ValueKind};
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

/// The operand classes of the official matrix, with the types the generator writes over REST.
/// `x` is absent.
fn operand(name: &str) -> Option<Value> {
    let reference = |path: &str| {
        Value::Reference(format!(
            "projects/demo-app/databases/(default)/documents/{path}"
        ))
    };
    Some(match name {
        "x" => return None,
        "n" => Value::Null,
        "nan" => Value::Double(f64::NAN),
        "i" => Value::Integer(1),
        "i2" => Value::Integer(2),
        "d5" => Value::Double(1.5),
        "one" => Value::Double(1.0),
        "iz" => Value::Integer(0),
        "dz" => Value::Double(0.0),
        "nz" => Value::Double(-0.0),
        "i53" => Value::Integer(1 << 53),
        "d53" => Value::Double(9_007_199_254_740_992.0),
        "i53p" => Value::Integer((1 << 53) + 1),
        "imax" => Value::Integer(i64::MAX),
        "d63" => Value::Double(9_223_372_036_854_775_808.0),
        "inf" => Value::Double(f64::INFINITY),
        "ninf" => Value::Double(f64::NEG_INFINITY),
        "s" => s("a"),
        "s2" => s("b"),
        "by" => Value::Bytes(vec![0, 1]),
        "ref" => reference("c/a"),
        "geo" => Value::GeoPoint(crate::value::GeoPoint::new(0.0, 1.0).unwrap()),
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
    row(matrix()
        .operands
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

fn condition(op: &str, args: Vec<Expr>) -> Expr {
    Expr::call(op, args, Placement::Condition).unwrap()
}

/// The emulator profile answers every cell of the official emulator's matrix, as a value and
/// as a where condition (the row is kept exactly when the cell is true).
#[test]
fn the_emulator_profile_answers_the_official_matrix() {
    let r = matrix_row();
    let m = matrix();
    let unrecorded = Unrecorded::OfficialEmulator;
    for (op, rows) in &m.rows {
        for (li, left) in m.operands.iter().enumerate() {
            for (ri, right) in m.operands.iter().enumerate() {
                let expected = rows[li].as_bytes()[ri] == b'T';
                let args = vec![field(left), field(right)];
                assert_eq!(
                    call(op, args.clone()).eval_in(&r, unrecorded),
                    boolean(expected),
                    "{op}({left}, {right})"
                );
                let kept = execute_in(
                    vec![Stage::Where(condition(op, args))],
                    [r.clone()],
                    unrecorded,
                )
                .unwrap();
                assert_eq!(
                    kept.len(),
                    usize::from(expected),
                    "where {op}({left}, {right})"
                );
            }
        }
    }
}

/// Strict answers every cell of the official matrix as the official emulator does: production
/// answered every pair of operand kinds under all six comparisons as the official emulator
/// does (FS-ENT-ORACLE O-2, 810 cells; O-3 for vectors and a missing field against every
/// kind), as a value and as a where condition.
#[test]
fn strict_answers_the_official_matrix() {
    let r = matrix_row();
    let m = matrix();
    for (op, rows) in &m.rows {
        for (li, left) in m.operands.iter().enumerate() {
            for (ri, right) in m.operands.iter().enumerate() {
                let expected = rows[li].as_bytes()[ri] == b'T';
                let args = vec![field(left), field(right)];
                assert_eq!(
                    call(op, args.clone()).eval_in(&r, Unrecorded::Refuse),
                    boolean(expected),
                    "{op}({left}, {right})"
                );
                let kept = execute_in(
                    vec![Stage::Where(condition(op, args))],
                    [r.clone()],
                    Unrecorded::Refuse,
                )
                .unwrap();
                assert_eq!(
                    kept.len(),
                    usize::from(expected),
                    "where {op}({left}, {right})"
                );
            }
        }
    }
}

/// The cells FS-ENT-ORACLE O-3 recorded (2026-10-20), as production answered them, under both
/// profiles: vectors with each other (`[1, 2]` before `[1, 3]`) and against every other kind
/// and a missing field (unequal and unordered), a missing field against a string or geo point
/// (unequal and unordered, `not_equal` true), and a comparison of a comparison.
#[test]
fn both_profiles_answer_what_o3_recorded() {
    let r = row(vec![
        ("d".to_owned(), Value::Double(1.5)),
        (
            "g".to_owned(),
            Value::GeoPoint(crate::value::GeoPoint::new(0.0, 0.0).unwrap()),
        ),
        ("s".to_owned(), s("a")),
        ("v".to_owned(), Value::Vector(vec![1.0, 2.0])),
        ("v2".to_owned(), Value::Vector(vec![1.0, 3.0])),
    ]);
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        for (expr, expected) in [
            (call("equal", vec![field("v"), field("v")]), true),
            (call("not_equal", vec![field("v"), field("v")]), false),
            (call("less_than", vec![field("v"), field("v2")]), true),
            (call("greater_than", vec![field("v"), field("v2")]), false),
            (
                call("less_than_or_equal", vec![field("v"), field("v")]),
                true,
            ),
            (call("less_than", vec![field("v"), field("d")]), false),
            (
                call("greater_than_or_equal", vec![field("d"), field("v")]),
                false,
            ),
            (call("not_equal", vec![field("v"), field("d")]), true),
            (call("equal", vec![field("v"), field("x")]), false),
            (call("not_equal", vec![field("x"), field("v")]), true),
            (call("less_than", vec![field("x"), field("s")]), false),
            (call("equal", vec![field("s"), field("x")]), false),
            (call("not_equal", vec![field("g"), field("y")]), true),
            (
                call(
                    "equal",
                    vec![
                        call("less_than", vec![field("v"), field("v2")]),
                        Expr::Constant(Value::Boolean(true)),
                    ],
                ),
                true,
            ),
        ] {
            assert_eq!(
                expr.eval_in(&r, unrecorded),
                boolean(expected),
                "{expr:?} {unrecorded:?}"
            );
        }
        // A where condition of any kind but `true` drops the row.
        for value in [field("d"), field("v"), field("g"), field("s"), field("x")] {
            let stages = vec![Stage::Where(value.clone())];
            assert!(
                execute_in(stages, [r.clone()], unrecorded)
                    .unwrap()
                    .is_empty(),
                "{value:?}"
            );
        }
    }
}

/// The comparison answers FS-ENT-ORACLE O-1 recorded from production for its probe document
/// (`fs-ent-pipeline/px1/select` and `/where`), under both profiles.
#[test]
#[allow(clippy::too_many_lines)]
fn both_profiles_answer_what_production_answered() {
    let r = row(vec![
        ("i".to_owned(), Value::Integer(1)),
        ("d5".to_owned(), Value::Double(1.5)),
        ("s".to_owned(), s("a")),
        ("n".to_owned(), Value::Null),
        ("nan".to_owned(), Value::Double(f64::NAN)),
        ("b".to_owned(), Value::Boolean(true)),
        (
            "arr".to_owned(),
            Value::Array(vec![Value::Integer(1), s("a"), Value::Null]),
        ),
        (
            "m".to_owned(),
            Value::Map([("a".to_owned(), Value::Integer(1))].into()),
        ),
        ("big".to_owned(), Value::Integer(9_007_199_254_740_993)),
        ("bigd".to_owned(), Value::Double(9_007_199_254_740_992.0)),
        ("max".to_owned(), Value::Integer(i64::MAX)),
        ("nz".to_owned(), Value::Double(-0.0)),
        ("z".to_owned(), Value::Integer(0)),
    ]);
    let c = Expr::Constant;
    let one = || c(Value::Integer(1));
    let cases = [
        ("equal", field("i"), field("d5"), false),
        ("equal", field("i"), field("s"), false),
        ("equal", field("n"), c(Value::Null), true),
        ("equal", field("nan"), field("nan"), true),
        ("equal", field("x"), one(), false),
        ("equal", field("x"), field("x"), true),
        ("equal", field("x"), c(Value::Null), false),
        (
            "equal",
            field("arr"),
            c(Value::Array(vec![Value::Integer(1), s("a"), Value::Null])),
            true,
        ),
        ("equal", field("nz"), field("z"), true),
        ("equal", field("big"), field("bigd"), false),
        ("not_equal", field("x"), one(), true),
        ("not_equal", field("n"), one(), true),
        ("not_equal", field("i"), field("s"), true),
        ("not_equal", field("nan"), field("nan"), false),
        ("less_than", field("i"), field("d5"), true),
        ("less_than", field("i"), field("s"), false),
        ("less_than", field("s"), field("i"), false),
        ("less_than", field("n"), one(), false),
        ("less_than", field("nan"), one(), false),
        ("less_than", field("x"), one(), false),
        ("less_than", c(Value::Null), c(Value::Boolean(false)), false),
        ("less_than", c(Value::Boolean(true)), one(), false),
        ("less_than", field("bigd"), field("big"), true),
        (
            "less_than",
            field("max"),
            c(Value::Double(9_223_372_036_854_775_808.0)),
            true,
        ),
        ("less_than_or_equal", field("n"), c(Value::Null), true),
        (
            "greater_than",
            field("arr"),
            c(Value::Array(vec![Value::Integer(0)])),
            true,
        ),
        (
            "greater_than",
            field("s"),
            c(Value::Bytes(b"a".to_vec())),
            false,
        ),
    ];
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        for (op, a, b, expected) in &cases {
            assert_eq!(
                call(op, vec![a.clone(), b.clone()]).eval_in(&r, unrecorded),
                boolean(*expected),
                "{op}({a:?}, {b:?}) {unrecorded:?}"
            );
        }
        // where: not_equal of a missing field keeps the row, the less_than across kinds drops it.
        let kept = |cond: Expr| {
            execute_in(vec![Stage::Where(cond)], [r.clone()], unrecorded)
                .unwrap()
                .len()
        };
        assert_eq!(kept(condition("not_equal", vec![field("x"), one()])), 1);
        assert_eq!(
            kept(condition("less_than", vec![field("i"), field("s")])),
            0
        );
        assert_eq!(kept(condition("equal", vec![field("x"), one()])), 0);
        assert_eq!(kept(field("b")), 1);
        for dropped in ["i", "n", "x"] {
            assert_eq!(kept(field(dropped)), 0, "{dropped}");
        }
        // `__name__` compares with a reference.
        let name = Value::Reference(r.path.resource_name());
        assert_eq!(
            call("equal", vec![field("__name__"), c(name)]).eval_in(&r, unrecorded),
            boolean(true)
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
                    matches!(got, Eval::Error(_)),
                    "{op} {unrecorded:?}: {got:?}"
                );
                assert_eq!(got, error.eval_in(&r, unrecorded), "{op} {unrecorded:?}");
            }
        }
    }
}

/// `array(...)` and `map(...)` as production and the official emulator answer them (FS-ENT-ORACLE
/// O-1: `array(i, x)` = `[1, null]`, `map("k", i, "k2", x)` = `{k: 1}`). Production refused an
/// integer key and a key repeated with both values present as the official emulator does
/// (O-3); another key type and a repeated key with an absent value are unrecorded, so strict
/// refuses them as unobserved and the emulator profile refuses them as the official emulator
/// does.
#[test]
fn array_and_map_literals() {
    let r = row(vec![
        ("i".to_owned(), Value::Integer(1)),
        ("s".to_owned(), s("a")),
    ]);
    let k = |v: &str| Expr::Constant(s(v));
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert_eq!(
            call("array", vec![field("i"), field("x")]).eval_in(&r, unrecorded),
            Eval::Value(Value::Array(vec![Value::Integer(1), Value::Null]))
        );
        assert_eq!(
            call(
                "array",
                vec![field("i"), field("s"), Expr::Constant(Value::Null)]
            )
            .eval_in(&r, unrecorded),
            Eval::Value(Value::Array(vec![Value::Integer(1), s("a"), Value::Null]))
        );
        assert_eq!(
            call("array", vec![]).eval_in(&r, unrecorded),
            Eval::Value(Value::Array(vec![]))
        );
        assert_eq!(
            call("map", vec![k("k"), field("i"), k("k2"), field("x")]).eval_in(&r, unrecorded),
            Eval::Value(Value::Map([("k".to_owned(), Value::Integer(1))].into()))
        );
        assert_eq!(
            call("map", vec![k("k"), field("i"), k("j"), field("s")]).eval_in(&r, unrecorded),
            Eval::Value(Value::Map(
                [
                    ("k".to_owned(), Value::Integer(1)),
                    ("j".to_owned(), s("a"))
                ]
                .into()
            ))
        );
        // A missing key is unrecorded in both.
        assert!(unobserved(
            &call("map", vec![field("x"), field("i")]).eval_in(&r, unrecorded)
        ));
    }
    let integer_key = call("map", vec![Expr::Constant(Value::Integer(1)), field("i")]);
    let boolean_key = call(
        "map",
        vec![Expr::Constant(Value::Boolean(true)), field("i")],
    );
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert_eq!(
            integer_key.eval_in(&r, unrecorded),
            Eval::Error(EvalError::Invalid(
                "map key must be of type STRING, given type is LONG".into()
            ))
        );
    }
    assert!(unobserved(&boolean_key.eval_in(&r, Unrecorded::Refuse)));
    assert_eq!(
        boolean_key.eval_in(&r, Unrecorded::OfficialEmulator),
        Eval::Error(EvalError::Invalid(
            "map key must be of type STRING, given type is BOOLEAN".into()
        ))
    );
    // A repeated key is refused even when a value is missing; production answered it with
    // both values present.
    let duplicate = Eval::Error(EvalError::Invalid(
        "map(...) constructor given duplicate key: k".into(),
    ));
    let both = call("map", vec![k("k"), field("i"), k("k"), field("s")]);
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert_eq!(both.eval_in(&r, unrecorded), duplicate);
    }
    // A repeat with a missing value: the official emulator counts only present values, so it
    // keeps the present one; production has not answered it.
    for (repeated, kept) in [
        (
            call("map", vec![k("k"), field("x"), k("k"), field("s")]),
            Some(s("a")),
        ),
        (
            call("map", vec![k("k"), field("i"), k("k"), field("x")]),
            Some(Value::Integer(1)),
        ),
        (
            call("map", vec![k("k"), field("x"), k("k"), field("y")]),
            None,
        ),
    ] {
        assert!(unobserved(&repeated.eval_in(&r, Unrecorded::Refuse)));
        assert_eq!(
            repeated.eval_in(&r, Unrecorded::OfficialEmulator),
            Eval::Value(Value::Map(
                kept.into_iter().map(|v| ("k".to_owned(), v)).collect()
            ))
        );
    }
    // Two present values repeat even with a missing one between them.
    let around = call(
        "map",
        vec![k("k"), field("i"), k("k"), field("x"), k("k"), field("s")],
    );
    assert!(unobserved(&around.eval_in(&r, Unrecorded::Refuse)));
    assert_eq!(around.eval_in(&r, Unrecorded::OfficialEmulator), duplicate);
    // Errors propagate.
    let error = call("document_id", vec![field("i")]);
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        assert!(matches!(
            call("array", vec![error.clone()]).eval_in(&r, unrecorded),
            Eval::Error(_)
        ));
        assert!(matches!(
            call("map", vec![k("k"), error.clone()]).eval_in(&r, unrecorded),
            Eval::Error(_)
        ));
    }
    // A literal compares with a field (arrays compare deeply).
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

/// Scalars of every kind, with the integer and double boundaries near 2^53 and 2^63, both
/// zeros, both infinities, references of different depths and collections, bytes and geo
/// points.
fn scalar() -> impl Strategy<Value = Value> {
    const TWO_53: i64 = 1 << 53;
    let reference =
        |path: &str| Value::Reference(format!("projects/p/databases/(default)/documents/{path}"));
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Boolean),
        prop_oneof![
            -2_i64..3,
            Just(TWO_53 - 1),
            Just(TWO_53),
            Just(TWO_53 + 1),
            Just(-TWO_53),
            Just(i64::MAX),
            Just(i64::MIN),
        ]
        .prop_map(Value::Integer),
        prop_oneof![
            Just(f64::NAN),
            Just(-0.0),
            Just(0.0),
            Just(1.0),
            Just(1.5),
            Just(f64::INFINITY),
            Just(f64::NEG_INFINITY),
            Just(9_007_199_254_740_992.0),
            Just(9_007_199_254_740_994.0),
            Just(9_223_372_036_854_775_808.0),
            Just(-9_223_372_036_854_775_808.0),
        ]
        .prop_map(Value::Double),
        "[ab]{0,2}".prop_map(Value::String),
        prop::collection::vec(prop_oneof![Just(0_u8), Just(1), Just(255)], 0..3)
            .prop_map(Value::Bytes),
        prop_oneof![
            Just(reference("c/a")),
            Just(reference("c/b")),
            Just(reference("c/a/d/x")),
            Just(reference("d/a")),
        ],
        prop_oneof![
            Just((0.0, 0.0)),
            Just((0.0, 1.0)),
            Just((1.0, 0.0)),
            Just((-1.0, 0.0))
        ]
        .prop_map(|(lat, lng)| Value::GeoPoint(crate::value::GeoPoint::new(lat, lng).unwrap())),
        ((0_i64..2), prop_oneof![Just(0_u32), Just(1_000)])
            .prop_map(|(seconds, nanos)| Value::Timestamp(Timestamp::new(seconds, nanos).unwrap())),
    ]
}

/// A storable value, or absent: a scalar of every kind, or arrays and maps nested to depth 2
/// holding them (an array never directly holds an array, as Firestore requires).
fn value() -> impl Strategy<Value = Option<Value>> {
    let array =
        |inner: BoxedStrategy<Value>| prop::collection::vec(inner, 0..3).prop_map(Value::Array);
    let map = |inner: BoxedStrategy<Value>| {
        prop::collection::btree_map("[ab]", inner, 0..2).prop_map(Value::Map)
    };
    let inner_map = map(scalar().boxed());
    let inner_array = array(scalar().boxed());
    let value = prop_oneof![
        4 => scalar(),
        1 => array(prop_oneof![3 => scalar(), 1 => inner_map].boxed()),
        1 => map(prop_oneof![3 => scalar(), 1 => inner_array.clone(), 1 => map(scalar().boxed())].boxed()),
    ];
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

fn document(index: usize) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("p").unwrap(),
        &DatabaseId::try_new("(default)").unwrap(),
        &format!("c/d{index}"),
    )
    .unwrap()
}

/// The documents of `stored` (field `f`, missing when `None`; field `k` numbers them).
fn documents(stored: &[Option<Value>]) -> Vec<Row> {
    stored
        .iter()
        .enumerate()
        .map(|(index, value)| Row {
            path: document(index),
            fields: value
                .iter()
                .map(|v| ("f".to_owned(), v.clone()))
                .chain([("k".to_owned(), Value::Integer(index as i64))])
                .collect(),
        })
        .collect()
}

/// Which of the documents a classic query `f op literal` returns, through the store's
/// `RunQuery` path (null and NaN equalities as the SDKs send them, `IS_NULL` / `IS_NAN` and
/// their negations), or `None` when the store refuses the query.
fn classic_keeps(op: &str, stored: &[Option<Value>], literal: &Value) -> Option<Vec<i64>> {
    use crate::query::{FieldOp, FilterExpr, Query, QueryScope, UnaryOp};
    use crate::store::{FirestoreState, Write, WriteOp};
    use fireemu_core_types::ids::CollectionId;
    use fireemu_core_types::time::LogicalInstant;
    let mut state = FirestoreState::new();
    for (index, row) in documents(stored).into_iter().enumerate() {
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: row.path,
                        fields: row.fields,
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: vec![],
                }],
                None,
                LogicalInstant::from_unix_seconds(1_000 + index as i64),
            )
            .unwrap();
    }
    let f = FieldPath::parse("f").unwrap();
    let nan = matches!(literal, Value::Double(d) if d.is_nan());
    let unary = |op| FilterExpr::Unary {
        field: f.clone(),
        op,
    };
    let filter = match (op, literal) {
        ("equal", Value::Null) => unary(UnaryOp::IsNull),
        ("equal", _) if nan => unary(UnaryOp::IsNan),
        ("not_equal", Value::Null) => unary(UnaryOp::IsNotNull),
        ("not_equal", _) if nan => unary(UnaryOp::IsNotNan),
        _ => FilterExpr::Field {
            field: f.clone(),
            op: match op {
                "equal" => FieldOp::Equal,
                "not_equal" => FieldOp::NotEqual,
                "less_than" => FieldOp::LessThan,
                "less_than_or_equal" => FieldOp::LessThanOrEqual,
                "greater_than" => FieldOp::GreaterThan,
                _ => FieldOp::GreaterThanOrEqual,
            },
            value: literal.clone(),
        },
    };
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("c").unwrap(),
    ))
    .with_filter(filter)
    .canonicalize()
    .ok()?;
    let kept = state.run_query(&query, None).ok()?;
    // A range query orders by its field first; the documents kept are what is compared.
    let mut kept: Vec<i64> = kept
        .iter()
        .map(|document| match document.fields["k"] {
            Value::Integer(k) => k,
            ref other => panic!("{other:?}"),
        })
        .collect();
    kept.sort_unstable();
    Some(kept)
}

/// The mirror of a comparison (`literal op field` is `field mirror(op) literal`).
fn mirror(op: &str) -> &str {
    match op {
        "less_than" => "greater_than",
        "less_than_or_equal" => "greater_than_or_equal",
        "greater_than" => "less_than",
        "greater_than_or_equal" => "less_than_or_equal",
        other => other,
    }
}

proptest! {
    /// Strict and the emulator profile give one answer for every comparison of any two
    /// operands, present or not: production answered every pair of kinds as the official
    /// emulator does (FS-ENT-ORACLE O-2 and O-3).
    #[test]
    fn strict_and_the_emulator_profile_agree_on_every_comparison(a in value(), b in value()) {
        for op in OPS {
            prop_assert_eq!(
                eval_op(op, a.as_ref(), b.as_ref(), Unrecorded::Refuse),
                eval_op(op, a.as_ref(), b.as_ref(), Unrecorded::OfficialEmulator),
                "{}({:?}, {:?})", op, a, b
            );
        }
    }

    /// The official order: not_equal is the negation of equal, the inclusive comparisons are
    /// the strict ones or equality, greater is the mirror of less, less is antisymmetric, and
    /// less and equal are transitive.
    #[test]
    fn the_official_comparisons_are_one_order(a in value(), b in value(), c in value()) {
        let (a, b, c) = (a.as_ref(), b.as_ref(), c.as_ref());
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
        if lt && official("less_than", b, c) {
            prop_assert!(official("less_than", a, c));
        }
        if eq && official("equal", b, c) {
            prop_assert!(official("equal", a, c));
        }
        if lt && official("equal", b, c) {
            prop_assert!(official("less_than", a, c));
        }
    }

    /// Where a classic query decides `field op literal` the same way (two present values of one
    /// kind that are neither null nor NaN; any equality of a present field; a missing field
    /// under every comparison but not_equal), the where condition keeps exactly the documents
    /// the store's classic query keeps, for `literal op field` too. Elsewhere the two differ by
    /// design (production keeps a missing field under not_equal and compares across kinds),
    /// so those documents are left out of the comparison.
    #[test]
    fn where_matches_classic_queries_where_both_decide(
        stored in prop::collection::vec(value(), 0..5),
        literal in scalar(),
    ) {
        let rows = documents(&stored);
        let special = |v: &Value| matches!(v.kind(), ValueKind::Null | ValueKind::Nan);
        for op in OPS {
            let decided: Vec<i64> = stored
                .iter()
                .enumerate()
                .filter(|(_, value)| match value {
                    None => op != "not_equal",
                    Some(v) => op == "equal"
                        || (v.kind() == literal.kind() && !special(v) && !special(&literal)),
                })
                .map(|(k, _)| k as i64)
                .collect();
            for (args, classic_op) in [
                (vec![field("f"), Expr::Constant(literal.clone())], op),
                (vec![Expr::Constant(literal.clone()), field("f")], mirror(op)),
            ] {
                for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
                    let got = execute_in(vec![Stage::Where(condition(op, args.clone()))], rows.clone(), unrecorded);
                    // Both profiles answer every comparison (FS-ENT-ORACLE O-2 and O-3).
                    prop_assert!(got.is_ok(), "{} {:?}: {:?}", op, unrecorded, got);
                    let Ok(out) = got else { continue };
                    let kept: Vec<i64> = out
                        .iter()
                        .map(|fields| match fields["k"] { Value::Integer(k) => k, _ => -1 })
                        .filter(|k| decided.contains(k))
                        .collect();
                    let classic = classic_keeps(classic_op, &stored, &literal)
                        .map(|keys| keys.into_iter().filter(|k| decided.contains(k)).collect::<Vec<_>>());
                    if let Some(classic) = classic {
                        prop_assert_eq!(kept, classic, "{}", op);
                    }
                }
            }
        }
    }
}
