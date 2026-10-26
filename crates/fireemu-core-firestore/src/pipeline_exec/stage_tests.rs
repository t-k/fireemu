//! Tests of the stages that reshape or reorder rows (`sort`, `distinct`, `aggregate`,
//! `add_fields`, `remove_fields`), the blocking cursor, and the logical functions.
#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::needless_pass_by_value,
    clippy::option_option
)]

use super::*;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use proptest::prelude::*;

fn path(relative: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("p").unwrap(),
        &DatabaseId::try_new("(default)").unwrap(),
        relative,
    )
    .unwrap()
}

fn doc(name: &str, fields: &[(&str, Value)]) -> Row {
    Row::document(
        path(&format!("c/{name}")),
        fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    )
}

fn field(p: &str) -> Expr {
    Expr::Field(FieldPath::parse(p).unwrap())
}

fn alias(p: &str) -> FieldPath {
    FieldPath::parse(p).unwrap()
}

fn int(i: i64) -> Value {
    Value::Integer(i)
}

fn ascending(expr: Expr) -> SortKey {
    SortKey {
        expr,
        descending: false,
    }
}

fn descending(expr: Expr) -> SortKey {
    SortKey {
        expr,
        descending: true,
    }
}

fn names(rows: &[Row]) -> Vec<String> {
    rows.iter()
        .map(|row| {
            row.path
                .as_ref()
                .map_or_else(String::new, |p| p.document_id().as_str().to_owned())
        })
        .collect()
}

fn run(stages: Vec<Stage>, rows: Vec<Row>) -> Vec<Row> {
    execute_rows_in(stages, rows, Unrecorded::OfficialEmulator).unwrap()
}

fn fields_of(rows: &[Row]) -> Vec<BTreeMap<String, Value>> {
    rows.iter().map(|row| row.fields.clone()).collect()
}

#[test]
fn sort_orders_every_kind_ascending_and_descending_with_missing_as_null() {
    let rows = vec![
        doc("d1", &[("v", Value::String("a".into()))]),
        doc("d2", &[("v", int(2))]),
        doc("d3", &[]),
        doc("d4", &[("v", Value::Null)]),
        doc("d5", &[("v", Value::Boolean(false))]),
        doc("d6", &[("v", Value::Double(0.5))]),
        doc("d7", &[("v", Value::Double(f64::NAN))]),
    ];
    let up = run(vec![Stage::Sort(vec![ascending(field("v"))])], rows.clone());
    // Missing and null are one value and keep their input order; then false, NaN, numbers,
    // strings.
    assert_eq!(names(&up), ["d3", "d4", "d5", "d7", "d6", "d2", "d1"]);
    let down = run(vec![Stage::Sort(vec![descending(field("v"))])], rows);
    assert_eq!(names(&down), ["d1", "d2", "d6", "d7", "d5", "d3", "d4"]);
}

#[test]
fn sort_keys_apply_in_turn_and_ties_keep_input_order() {
    let rows = vec![
        doc("m1", &[("a", int(1)), ("b", int(2))]),
        doc("m2", &[("a", int(1)), ("b", int(1))]),
        doc("m3", &[("a", int(0)), ("b", int(9))]),
        doc("m4", &[("a", int(1)), ("b", int(2))]),
    ];
    let both = run(
        vec![Stage::Sort(vec![
            ascending(field("a")),
            descending(field("b")),
        ])],
        rows.clone(),
    );
    assert_eq!(names(&both), ["m3", "m1", "m4", "m2"]);
    let constant = run(
        vec![Stage::Sort(vec![ascending(Expr::Constant(int(1)))])],
        rows,
    );
    assert_eq!(names(&constant), ["m1", "m2", "m3", "m4"]);
}

#[test]
fn a_blocking_stage_holds_rows_until_finish_and_limits_before_it_stop_the_input() {
    let rows: Vec<Row> = (0..6)
        .map(|i| doc(&format!("r{i}"), &[("n", int(5 - i))]))
        .collect();
    // limit(3) then sort: only the first three rows are sorted.
    let mut cursor = Cursor::new(vec![
        Stage::Limit(3),
        Stage::Sort(vec![ascending(field("n"))]),
    ]);
    let mut seen = 0;
    for row in rows.clone() {
        if cursor.is_exhausted() {
            break;
        }
        assert!(cursor.push(row).unwrap().is_empty());
        seen += 1;
    }
    assert_eq!(seen, 3);
    assert_eq!(names(&cursor.finish().unwrap()), ["r2", "r1", "r0"]);
    // sort then limit(2): the input is read to the end, the limit cuts the sorted rows.
    let mut cursor = Cursor::new(vec![
        Stage::Sort(vec![ascending(field("n"))]),
        Stage::Limit(2),
    ]);
    assert!(!cursor.is_exhausted());
    for row in rows {
        assert!(cursor.push(row).unwrap().is_empty());
    }
    assert!(!cursor.is_exhausted());
    assert_eq!(names(&cursor.finish().unwrap()), ["r5", "r4"]);
}

#[test]
fn stages_may_repeat_and_come_in_any_order() {
    let rows: Vec<Row> = (1..=5)
        .map(|i| doc(&format!("s{i}"), &[("n", int(i))]))
        .collect();
    let gt = |n| {
        Stage::Where(
            Expr::call(
                "greater_than",
                vec![field("n"), Expr::Constant(int(n))],
                Placement::Condition,
            )
            .unwrap(),
        )
    };
    let lt = |n| {
        Stage::Where(
            Expr::call(
                "less_than",
                vec![field("n"), Expr::Constant(int(n))],
                Placement::Condition,
            )
            .unwrap(),
        )
    };
    let out = run(vec![gt(1), lt(5), Stage::Offset(1)], rows.clone());
    assert_eq!(names(&out), ["s3", "s4"]);
    // limit(4) then offset(1) then limit(2).
    let out = run(
        vec![Stage::Limit(4), Stage::Offset(1), Stage::Limit(2)],
        rows.clone(),
    );
    assert_eq!(names(&out), ["s2", "s3"]);
    // A where after a select reads the alias; a select after a select reads the first's.
    let out = run(
        vec![
            Stage::select(vec![(alias("a"), field("n"))]),
            Stage::Where(
                Expr::call(
                    "greater_than",
                    vec![field("a"), Expr::Constant(int(3))],
                    Placement::Condition,
                )
                .unwrap(),
            ),
            Stage::select(vec![(alias("b"), field("a"))]),
        ],
        rows,
    );
    assert_eq!(
        fields_of(&out),
        [
            BTreeMap::from([("b".to_owned(), int(4))]),
            BTreeMap::from([("b".to_owned(), int(5))])
        ]
    );
}

#[test]
fn a_select_drops_the_name_and_times_unless_it_kept_the_name() {
    let times = RowTimes {
        created: Timestamp::new(1, 0).unwrap(),
        updated: Timestamp::new(2, 0).unwrap(),
    };
    let mut row = doc("x", &[("n", int(1))]);
    row.times = Some(times);
    let plain = run(
        vec![Stage::select(vec![(alias("n"), field("n"))])],
        vec![row.clone()],
    );
    assert_eq!((plain[0].path.clone(), plain[0].times), (None, None));
    let named = run(
        vec![Stage::Select {
            aliases: vec![(alias("n"), field("n"))],
            keeps_name: true,
        }],
        vec![row.clone()],
    );
    assert_eq!(named[0].path, row.path);
    assert_eq!(named[0].times, None);
    // `__name__` read after a select is missing.
    let after = run(
        vec![
            Stage::select(vec![(alias("n"), field("n"))]),
            Stage::select(vec![(alias("k"), field("__name__"))]),
        ],
        vec![row],
    );
    assert!(after[0].fields.is_empty());
}

#[test]
fn add_fields_reads_the_row_before_the_stage_and_keeps_name_and_times() {
    let times = RowTimes {
        created: Timestamp::new(1, 0).unwrap(),
        updated: Timestamp::new(2, 0).unwrap(),
    };
    let mut row = doc(
        "f",
        &[
            ("a", int(1)),
            ("m", Value::Map(BTreeMap::from([("p".to_owned(), int(1))]))),
        ],
    );
    row.times = Some(times);
    let out = run(
        vec![Stage::AddFields(vec![
            (alias("k1"), field("a")),
            // A later alias does not see an earlier one: `k1` is missing here.
            (alias("k2"), field("k1")),
            // A missing source adds nothing.
            (alias("k3"), field("zz")),
            (alias("m.r"), Expr::Constant(int(9))),
            (alias("n.s"), Expr::Constant(int(7))),
        ])],
        vec![row.clone()],
    );
    let fields = &out[0].fields;
    assert_eq!(fields["k1"], int(1));
    assert!(!fields.contains_key("k2") && !fields.contains_key("k3"));
    assert_eq!(
        fields["m"],
        Value::Map(BTreeMap::from([
            ("p".to_owned(), int(1)),
            ("r".to_owned(), int(9))
        ]))
    );
    assert_eq!(
        fields["n"],
        Value::Map(BTreeMap::from([("s".to_owned(), int(7))]))
    );
    assert_eq!(
        (out[0].path.clone(), out[0].times),
        (row.path.clone(), Some(times))
    );
    // A nested alias replaces a scalar parent.
    let scalar = doc("g", &[("m", int(5))]);
    let out = run(
        vec![Stage::AddFields(vec![(
            alias("m.r"),
            Expr::Constant(int(9)),
        )])],
        vec![scalar],
    );
    assert_eq!(
        out[0].fields["m"],
        Value::Map(BTreeMap::from([("r".to_owned(), int(9))]))
    );
}

#[test]
fn remove_fields_removes_nested_paths_ignores_missing_and_the_name_drops_the_name_only() {
    let times = RowTimes {
        created: Timestamp::new(1, 0).unwrap(),
        updated: Timestamp::new(2, 0).unwrap(),
    };
    let mut row = doc(
        "f",
        &[
            ("a", int(1)),
            ("b", int(2)),
            (
                "m",
                Value::Map(BTreeMap::from([
                    ("p".to_owned(), int(1)),
                    ("q".to_owned(), int(2)),
                ])),
            ),
        ],
    );
    row.times = Some(times);
    let out = run(
        vec![Stage::RemoveFields(vec![
            alias("a"),
            alias("a"),
            alias("m.p"),
            alias("zz"),
            alias("z.y"),
        ])],
        vec![row.clone()],
    );
    assert_eq!(
        out[0].fields,
        BTreeMap::from([
            ("b".to_owned(), int(2)),
            (
                "m".to_owned(),
                Value::Map(BTreeMap::from([("q".to_owned(), int(2))]))
            ),
        ])
    );
    assert_eq!(out[0].path, row.path);
    let nameless = run(
        vec![Stage::RemoveFields(vec![FieldPath::document_name()])],
        vec![row.clone()],
    );
    assert_eq!(nameless[0].path, None);
    assert_eq!(nameless[0].times, Some(times));
    assert_eq!(nameless[0].fields, row.fields);
}

fn count_all() -> Accumulator {
    Accumulator {
        kind: AccumulatorKind::CountAll,
        argument: None,
    }
}

fn accumulate(kind: AccumulatorKind, argument: &str) -> Accumulator {
    Accumulator {
        kind,
        argument: Some(field(argument)),
    }
}

#[test]
fn aggregate_over_nothing_gives_one_row_ungrouped_and_none_grouped() {
    let accumulators = vec![
        ("n".to_owned(), count_all()),
        ("c".to_owned(), accumulate(AccumulatorKind::Count, "x")),
        ("s".to_owned(), accumulate(AccumulatorKind::Sum, "x")),
        ("a".to_owned(), accumulate(AccumulatorKind::Average, "x")),
        ("mn".to_owned(), accumulate(AccumulatorKind::Minimum, "x")),
        ("mx".to_owned(), accumulate(AccumulatorKind::Maximum, "x")),
        (
            "d".to_owned(),
            accumulate(AccumulatorKind::CountDistinct, "x"),
        ),
    ];
    let out = run(
        vec![Stage::Aggregate {
            accumulators: accumulators.clone(),
            groups: vec![],
        }],
        vec![],
    );
    assert_eq!(
        out[0].fields,
        BTreeMap::from([
            ("n".to_owned(), int(0)),
            ("c".to_owned(), int(0)),
            ("s".to_owned(), Value::Null),
            ("a".to_owned(), Value::Null),
            ("mn".to_owned(), Value::Null),
            ("mx".to_owned(), Value::Null),
            ("d".to_owned(), int(0)),
        ])
    );
    assert_eq!((out[0].path.clone(), out[0].times), (None, None));
    let grouped = run(
        vec![Stage::Aggregate {
            accumulators,
            groups: vec![("g".to_owned(), field("x"))],
        }],
        vec![],
    );
    assert!(grouped.is_empty());
}

#[test]
fn aggregate_numbers_follow_the_recorded_rules() {
    let rows = |values: &[Value]| -> Vec<Row> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| doc(&format!("n{i}"), &[("v", v.clone())]))
            .collect()
    };
    let all = |values: &[Value]| {
        run(
            vec![Stage::Aggregate {
                accumulators: vec![
                    ("s".to_owned(), accumulate(AccumulatorKind::Sum, "v")),
                    ("a".to_owned(), accumulate(AccumulatorKind::Average, "v")),
                    ("mn".to_owned(), accumulate(AccumulatorKind::Minimum, "v")),
                    ("mx".to_owned(), accumulate(AccumulatorKind::Maximum, "v")),
                    (
                        "d".to_owned(),
                        accumulate(AccumulatorKind::CountDistinct, "v"),
                    ),
                    ("c".to_owned(), accumulate(AccumulatorKind::Count, "v")),
                ],
                groups: vec![],
            }],
            rows(values),
        )
        .remove(0)
        .fields
    };
    // Integers stay integers, a double makes the sum a double, the mean is a double.
    let ints = all(&[int(1), int(2), int(3)]);
    assert_eq!((&ints["s"], &ints["a"]), (&int(3 + 3), &Value::Double(2.0)));
    let mixed = all(&[int(1), Value::Double(2.5), int(3)]);
    assert_eq!(mixed["s"], Value::Double(6.5));
    // Non-numbers are ignored by sum and average, nulls by all.
    let strings = all(&[Value::String("a".into()), Value::String("b".into())]);
    assert_eq!((&strings["s"], &strings["a"]), (&Value::Null, &Value::Null));
    assert_eq!(
        (&strings["mn"], &strings["mx"]),
        (&Value::String("a".into()), &Value::String("b".into()))
    );
    let some = all(&[int(1), Value::Boolean(true), Value::Null]);
    assert_eq!(
        (&some["s"], &some["c"], &some["d"]),
        (&int(1), &int(2), &int(2))
    );
    // 1 and 1.0, 0 and -0 are one distinct value.
    let equal_numbers = all(&[int(1), Value::Double(1.0), Value::Double(-0.0), int(0)]);
    assert_eq!(equal_numbers["d"], int(2));
    // NaN poisons the sum, and is the least number.
    let nan = all(&[Value::Double(f64::NAN), int(2)]);
    assert!(matches!(&nan["s"], Value::Double(d) if d.is_nan()));
    assert!(matches!(&nan["mn"], Value::Double(d) if d.is_nan()));
    assert_eq!(nan["mx"], int(2));
    // An integer sum that overflows fails the request; the largest sum that fits does not.
    let fits = all(&[int(i64::MAX - 1), int(1)]);
    assert_eq!(fits["s"], int(i64::MAX));
    let error = execute_in(
        vec![Stage::Aggregate {
            accumulators: vec![("s".to_owned(), accumulate(AccumulatorKind::Sum, "v"))],
            groups: vec![],
        }],
        rows(&[int(i64::MAX), int(1)]),
        Unrecorded::OfficialEmulator,
    )
    .unwrap_err();
    assert_eq!(error, EvalError::Invalid("Long overflow".to_owned()));
}

#[test]
fn aggregate_groups_merge_null_and_missing_and_equal_numbers() {
    let rows = vec![
        doc("a", &[("g", int(1)), ("n", int(1))]),
        doc("b", &[("g", Value::Double(1.0)), ("n", int(2))]),
        doc("c", &[("n", int(3))]),
        doc("d", &[("g", Value::Null), ("n", int(4))]),
        doc("e", &[("g", Value::Double(-0.0)), ("n", int(5))]),
        doc("f", &[("g", int(0)), ("n", int(6))]),
    ];
    let out = run(
        vec![Stage::Aggregate {
            accumulators: vec![
                ("c".to_owned(), count_all()),
                ("s".to_owned(), accumulate(AccumulatorKind::Sum, "n")),
            ],
            groups: vec![("g".to_owned(), field("g"))],
        }],
        rows,
    );
    let rows: Vec<_> = out
        .iter()
        .map(|row| {
            (
                row.fields["g"].clone(),
                row.fields["c"].clone(),
                row.fields["s"].clone(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (int(1), int(2), int(3)),
            (Value::Null, int(2), int(7)),
            (Value::Double(0.0), int(2), int(11)),
        ]
    );
}

#[test]
fn distinct_gives_one_row_per_combination_null_and_missing_alike() {
    let rows = vec![
        doc("a", &[("g", int(1)), ("h", int(1))]),
        doc("b", &[("g", int(1)), ("h", int(1))]),
        doc("c", &[("h", int(1))]),
        doc("d", &[("g", Value::Null), ("h", int(1))]),
        doc("e", &[("g", int(1))]),
    ];
    let out = run(
        vec![Stage::Distinct(vec![
            ("g".to_owned(), field("g")),
            ("h".to_owned(), field("h")),
        ])],
        rows,
    );
    assert_eq!(out.len(), 3);
    assert_eq!(
        out[1].fields,
        BTreeMap::from([("g".to_owned(), Value::Null), ("h".to_owned(), int(1))])
    );
    assert_eq!(
        out[2].fields,
        BTreeMap::from([("g".to_owned(), int(1)), ("h".to_owned(), Value::Null)])
    );
}

#[test]
fn a_refusal_in_a_stage_keeps_its_wording_under_the_emulator_profile() {
    let rows = vec![doc("a", &[("v", int(1))])];
    let not = Expr::call("not", vec![field("v")], Placement::Value).unwrap();
    for stage in [
        Stage::AddFields(vec![(alias("k"), not.clone())]),
        Stage::Sort(vec![ascending(not.clone())]),
        Stage::Distinct(vec![("k".to_owned(), not.clone())]),
    ] {
        let error =
            execute_in(vec![stage], rows.clone(), Unrecorded::OfficialEmulator).unwrap_err();
        assert!(
            matches!(
                error,
                EvalError::WrongType {
                    function: "not",
                    ..
                }
            ),
            "{error:?}"
        );
    }
}

// ---- logical functions ----

fn tri_value(state: Option<Option<bool>>) -> Eval {
    match state {
        None => Eval::Absent,
        Some(None) => Eval::Value(Value::Null),
        Some(Some(b)) => Eval::Value(Value::Boolean(b)),
    }
}

fn eval_function(name: &str, args: Vec<Eval>) -> Eval {
    let function = function(name).unwrap();
    (function.eval)(
        &args,
        Context {
            unrecorded: Unrecorded::OfficialEmulator,
            condition: false,
        },
    )
}

fn kleene(states: &[Option<bool>]) -> (Option<bool>, Option<bool>) {
    // (and, or) by definition: false decides and, true decides or, unknown otherwise.
    let and = if states.contains(&Some(false)) {
        Some(false)
    } else if states.contains(&None) {
        None
    } else {
        Some(true)
    };
    let or = if states.contains(&Some(true)) {
        Some(true)
    } else if states.contains(&None) {
        None
    } else {
        Some(false)
    };
    (and, or)
}

fn as_state(eval: &Eval) -> Option<bool> {
    match eval {
        Eval::Value(Value::Boolean(b)) => Some(*b),
        Eval::Value(Value::Null) => None,
        other => panic!("not a three-valued boolean: {other:?}"),
    }
}

proptest! {
    /// `and`, `or`, `nor` and `not` follow Kleene's tables over true, false, null and missing,
    /// whatever the number of operands.
    #[test]
    fn logical_functions_follow_kleene_logic(
        operands in proptest::collection::vec(proptest::option::of(proptest::option::of(any::<bool>())), 2..6),
    ) {
        let args: Vec<Eval> = operands.iter().copied().map(tri_value).collect();
        // Missing and null are both unknown.
        let states: Vec<Option<bool>> = operands.iter().map(|o| o.flatten()).collect();
        let (and, or) = kleene(&states);
        prop_assert_eq!(as_state(&eval_function("and", args.clone())), and);
        prop_assert_eq!(as_state(&eval_function("or", args.clone())), or);
        prop_assert_eq!(as_state(&eval_function("nor", args)), or.map(|b| !b));
    }

    /// `not` negates a boolean and keeps an unknown unknown; `xor` is the parity of two
    /// booleans and unknown with an unknown operand.
    #[test]
    fn not_and_xor_follow_their_tables(
        a in proptest::option::of(proptest::option::of(any::<bool>())),
        b in proptest::option::of(proptest::option::of(any::<bool>())),
    ) {
        prop_assert_eq!(
            as_state(&eval_function("not", vec![tri_value(a)])),
            a.flatten().map(|x| !x)
        );
        let expected = match (a.flatten(), b.flatten()) {
            (Some(x), Some(y)) => Some(x != y),
            _ => None,
        };
        prop_assert_eq!(as_state(&eval_function("xor", vec![tri_value(a), tri_value(b)])), expected);
    }

    /// `equal_any` is membership under value equality (1 equals 1.0, NaN equals NaN, null equals
    /// null); `not_equal_any` is its negation, and a missing value is in no list.
    #[test]
    fn equal_any_is_membership_and_not_equal_any_its_negation(
        needle in proptest::option::of(-3i64..3),
        list in proptest::collection::vec(-3i64..3, 0..5),
    ) {
        let list_value = Eval::Value(Value::Array(
            list.iter()
                .map(|i| if i % 2 == 0 { Value::Integer(*i) } else { Value::Double(*i as f64) })
                .collect(),
        ));
        let needle_eval = needle.map_or(Eval::Absent, |i| Eval::Value(Value::Integer(i)));
        let member = needle.is_some_and(|n| list.contains(&n));
        prop_assert_eq!(
            eval_function("equal_any", vec![needle_eval.clone(), list_value.clone()]),
            Eval::Value(Value::Boolean(member))
        );
        prop_assert_eq!(
            eval_function("not_equal_any", vec![needle_eval, list_value]),
            Eval::Value(Value::Boolean(!member))
        );
    }
}

#[test]
fn a_value_that_is_not_a_boolean_fails_the_logical_call() {
    for name in ["and", "or", "not"] {
        let args = if name == "not" {
            vec![Eval::Value(int(1))]
        } else {
            vec![Eval::Value(int(1)), Eval::Value(Value::Boolean(true))]
        };
        assert_eq!(
            eval_function(name, args),
            Eval::Error(EvalError::WrongType {
                function: if name == "and" {
                    "and"
                } else if name == "or" {
                    "or"
                } else {
                    "not"
                },
                expected: "Boolean",
                got: "LONG"
            })
        );
    }
    // Under strict a wrong operand beside one that decides the call is unobserved.
    let strict = Context {
        unrecorded: Unrecorded::Refuse,
        condition: false,
    };
    let result = (function("and").unwrap().eval)(
        &[Eval::Value(Value::Boolean(false)), Eval::Value(int(1))],
        strict,
    );
    assert!(matches!(result, Eval::Error(EvalError::Unobserved { .. })));
}

#[test]
fn existence_type_and_array_functions_answer_as_recorded() {
    let value = |v: Value| Eval::Value(v);
    assert_eq!(
        eval_function("exists", vec![Eval::Absent]),
        value(Value::Boolean(false))
    );
    assert_eq!(
        eval_function("exists", vec![value(Value::Null)]),
        value(Value::Boolean(true))
    );
    assert_eq!(
        eval_function("is_absent", vec![Eval::Absent]),
        value(Value::Boolean(true))
    );
    assert_eq!(
        eval_function("type", vec![value(Value::Double(f64::NAN))]),
        value(Value::String("float64".into()))
    );
    assert_eq!(
        eval_function("type", vec![Eval::Absent]),
        value(Value::Null)
    );
    let is_type =
        |v: Eval, name: &str| eval_function("is_type", vec![v, value(Value::String(name.into()))]);
    assert_eq!(
        is_type(value(int(1)), "number"),
        value(Value::Boolean(true))
    );
    assert_eq!(
        is_type(value(Value::Double(1.5)), "int64"),
        value(Value::Boolean(false))
    );
    assert_eq!(is_type(Eval::Absent, "null"), value(Value::Null));
    let array = value(Value::Array(vec![
        int(1),
        Value::String("a".into()),
        Value::Null,
    ]));
    assert_eq!(
        eval_function("array_contains", vec![array.clone(), value(Value::Null)]),
        value(Value::Boolean(true))
    );
    assert_eq!(
        eval_function("array_contains", vec![array.clone(), Eval::Absent]),
        value(Value::Boolean(false))
    );
    assert_eq!(
        eval_function("array_contains", vec![Eval::Absent, value(int(1))]),
        value(Value::Null)
    );
    assert_eq!(
        eval_function("array_contains", vec![value(int(1)), value(int(1))]),
        Eval::Error(EvalError::WrongType {
            function: "array_contains",
            expected: "Array",
            got: "LONG"
        })
    );
    let empty = value(Value::Array(vec![]));
    assert_eq!(
        eval_function("array_contains_all", vec![array.clone(), empty.clone()]),
        value(Value::Boolean(true))
    );
    assert_eq!(
        eval_function("array_contains_any", vec![array, empty]),
        value(Value::Boolean(false))
    );
    // `is_error` catches an error value, and a call that fails inside it does not propagate.
    let failing = Eval::Error(EvalError::Invalid("x".into()));
    assert_eq!(
        eval_function("is_error", vec![failing]),
        value(Value::Boolean(true))
    );
    assert_eq!(
        eval_function("is_error", vec![Eval::Absent]),
        value(Value::Boolean(false))
    );
    // The wording of an argument-count refusal is the signature's.
    let error = Expr::call("and", vec![field("a")], Placement::Value).unwrap_err();
    assert_eq!(
        error,
        ExprError::Arity("The function 'and(x: boolean?*): boolean?' takes [2..+\u{221e}) argument(s), but 1 was provided.".to_owned())
    );
    let error = Expr::call("not", vec![field("a"), field("b")], Placement::Value).unwrap_err();
    assert_eq!(
        error,
        ExprError::Arity("The function 'not(x: boolean): boolean' takes [1..1] argument(s), but 2 were provided.".to_owned())
    );
}

proptest! {
    /// Sorting agrees with a reference model: a stable sort of the keys, `null` and missing alike
    /// first, descending being the reverse comparison.
    #[test]
    fn sort_matches_a_stable_reference_sort(
        keys in proptest::collection::vec(proptest::option::of(proptest::option::of(-4i64..4)), 0..24),
        descending_order in any::<bool>(),
    ) {
        let rows: Vec<Row> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| match key {
                None => doc(&format!("r{i:02}"), &[]),
                Some(None) => doc(&format!("r{i:02}"), &[("k", Value::Null)]),
                Some(Some(k)) => doc(&format!("r{i:02}"), &[("k", Value::Integer(*k))]),
            })
            .collect();
        let sort_key = SortKey { expr: field("k"), descending: descending_order };
        let got = names(&run(vec![Stage::Sort(vec![sort_key])], rows));
        let rank = |key: &Option<Option<i64>>| key.flatten().map_or(i64::MIN, |k| k);
        let mut model: Vec<(usize, i64)> = keys.iter().enumerate().map(|(i, k)| (i, rank(k))).collect();
        model.sort_by(|a, b| if descending_order { b.1.cmp(&a.1) } else { a.1.cmp(&b.1) });
        let want: Vec<String> = model.iter().map(|(i, _)| format!("r{i:02}")).collect();
        prop_assert_eq!(got, want);
    }

    /// Aggregation agrees with a direct computation over small integers: counts, sums, extremes
    /// and distinct counts per group.
    #[test]
    fn aggregate_matches_a_direct_computation(
        rows in proptest::collection::vec((0i64..3, proptest::option::of(-5i64..5)), 0..24),
    ) {
        let input: Vec<Row> = rows
            .iter()
            .enumerate()
            .map(|(i, (g, v))| {
                let mut fields = vec![("g", Value::Integer(*g))];
                if let Some(v) = v {
                    fields.push(("v", Value::Integer(*v)));
                }
                doc(&format!("r{i:02}"), &fields)
            })
            .collect();
        let out = run(
            vec![Stage::Aggregate {
                accumulators: vec![
                    ("n".to_owned(), count_all()),
                    ("c".to_owned(), accumulate(AccumulatorKind::Count, "v")),
                    ("s".to_owned(), accumulate(AccumulatorKind::Sum, "v")),
                    ("mn".to_owned(), accumulate(AccumulatorKind::Minimum, "v")),
                    ("mx".to_owned(), accumulate(AccumulatorKind::Maximum, "v")),
                    ("d".to_owned(), accumulate(AccumulatorKind::CountDistinct, "v")),
                ],
                groups: vec![("g".to_owned(), field("g"))],
            }],
            input,
        );
        let mut seen = std::collections::BTreeSet::new();
        for row in &rows {
            seen.insert(row.0);
        }
        prop_assert_eq!(out.len(), seen.len());
        for result in &out {
            let Value::Integer(g) = result.fields["g"] else { panic!("group key") };
            let values: Vec<i64> = rows.iter().filter(|r| r.0 == g).filter_map(|r| r.1).collect();
            prop_assert_eq!(&result.fields["n"], &Value::Integer(rows.iter().filter(|r| r.0 == g).count() as i64));
            prop_assert_eq!(&result.fields["c"], &Value::Integer(values.len() as i64));
            let sum = if values.is_empty() { Value::Null } else { Value::Integer(values.iter().sum()) };
            prop_assert_eq!(&result.fields["s"], &sum);
            let min = values.iter().min().map_or(Value::Null, |v| Value::Integer(*v));
            let max = values.iter().max().map_or(Value::Null, |v| Value::Integer(*v));
            prop_assert_eq!(&result.fields["mn"], &min);
            prop_assert_eq!(&result.fields["mx"], &max);
            let distinct: std::collections::BTreeSet<_> = values.iter().collect();
            prop_assert_eq!(&result.fields["d"], &Value::Integer(distinct.len() as i64));
        }
    }
}
