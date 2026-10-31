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
fn ordered_select_first_refusal_is_default_off_and_type_bounded() {
    let call = |name| Expr::call("collection_id", vec![field(name)], Placement::Value).unwrap();
    let stage = Stage::select(vec![
        (alias("v"), call("first")),
        (alias("w"), call("second")),
    ]);
    let row = doc(
        "x",
        &[
            ("first", Value::String("a".into())),
            ("second", Value::String("b".into())),
        ],
    );
    let mut default = Cursor::new(vec![stage.clone()]);
    assert!(matches!(
        default.push(row.clone()),
        Err(EvalError::Unobserved { .. })
    ));
    let mut admitted = Cursor::new(vec![stage.clone()]).with_recorded_select_first_wrong_type();
    assert!(matches!(
        admitted.push(row),
        Err(EvalError::WrongType {
            function: "collection_id",
            expected: "Reference",
            got: "STRING"
        })
    ));
    let changed = doc(
        "x",
        &[("first", int(7)), ("second", Value::String("b".into()))],
    );
    let mut admitted = Cursor::new(vec![stage]).with_recorded_select_first_wrong_type();
    assert!(matches!(
        admitted.push(changed),
        Err(EvalError::Unobserved { .. })
    ));
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
            (Value::Double(-0.0), int(2), int(11)),
        ]
    );
    // The key shows the first member met, as stored.
    assert!(matches!(&rows[2].0, Value::Double(d) if d.is_sign_negative()));
}

/// A group of one member shows that member as stored (O-7 `aggregate-group-keys#by-g-h-n`:
/// a lone `-0.0` is shown as `-0`), in `aggregate` and in `distinct`.
#[test]
fn a_lone_negative_zero_key_is_shown_as_stored() {
    let rows = vec![doc("a", &[("g", Value::Double(-0.0)), ("n", int(1))])];
    let grouped = run(
        vec![Stage::Aggregate {
            accumulators: vec![("c".to_owned(), count_all())],
            groups: vec![("g".to_owned(), field("g"))],
        }],
        rows.clone(),
    );
    let distinct = run(
        vec![Stage::Distinct(vec![("g".to_owned(), field("g"))])],
        rows,
    );
    for out in [grouped, distinct] {
        assert!(matches!(&out[0].fields["g"], Value::Double(d) if d.is_sign_negative()));
    }
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
            runtime: &RuntimeContext::default(),
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
    let one = || Eval::Value(int(1));
    let t = || Eval::Value(Value::Boolean(true));
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        let call = |name: &str, args: &[Eval]| {
            (function(name).unwrap().eval)(
                args,
                Context {
                    unrecorded,
                    condition: false,
                    runtime: &RuntimeContext::default(),
                },
            )
        };
        for (name, args) in [
            ("and", vec![one(), t()]),
            ("or", vec![one(), t()]),
            ("not", vec![one()]),
        ] {
            let function = function(name).unwrap().name;
            assert_eq!(
                call(name, &args),
                Eval::Error(EvalError::WrongType {
                    function,
                    expected: "Boolean",
                    got: "LONG"
                }),
                "{name}"
            );
        }
    }
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

// ---- tests that pin the details the mutation run showed unpinned ----

fn strict(function_name: &str, args: &[Eval]) -> Eval {
    (function(function_name).unwrap().eval)(
        args,
        Context {
            unrecorded: Unrecorded::Refuse,
            condition: false,
            runtime: &RuntimeContext::default(),
        },
    )
}

fn emulator(function_name: &str, args: &[Eval]) -> Eval {
    eval_function(function_name, args.to_vec())
}

fn is_unobserved(eval: &Eval) -> bool {
    matches!(eval, Eval::Error(EvalError::Unobserved { .. }))
}

#[test]
fn group_keys_compare_by_value_not_by_representation() {
    let key = |v: Value| GroupKey(vec![v]);
    assert!(key(int(1)) == key(Value::Double(1.0)));
    assert!(key(Value::Double(-0.0)) == key(int(0)));
    assert!(key(Value::Double(f64::NAN)) == key(Value::Double(f64::NAN)));
    assert!(key(int(1)) != key(int(2)));
    assert_eq!(key(int(1)).partial_cmp(&key(int(2))), Some(Ordering::Less));
    assert_eq!(
        key(Value::Null).partial_cmp(&key(Value::Null)),
        Some(Ordering::Equal)
    );
}

#[test]
fn a_group_shows_the_first_member_met_as_stored_negative_zero_included() {
    let rows = vec![
        doc("a", &[("g", Value::Double(1.5))]),
        doc("b", &[("g", Value::Double(-0.0))]),
        doc("c", &[("g", Value::Double(0.0))]),
        doc("d", &[("g", Value::Double(-2.5))]),
    ];
    let out = run(
        vec![Stage::Distinct(vec![("g".to_owned(), field("g"))])],
        rows,
    );
    let shown: Vec<f64> = out
        .iter()
        .map(|row| match row.fields["g"] {
            Value::Double(d) => d,
            ref other => panic!("{other:?}"),
        })
        .collect();
    // The key shows one of the group's own members (production chose by its scan order, which
    // is not reproduced: O-7 `aggregate-group-keys#by-g`); a lone -0.0 stays -0.0
    // (`#by-g-h-n`).
    assert_eq!(shown, [1.5, -0.0, -2.5]);
    assert!(shown[1].is_sign_negative());
}

#[test]
fn doubles_sum_and_average_as_doubles() {
    let rows: Vec<Row> = [1.5, 2.5, 3.0]
        .iter()
        .enumerate()
        .map(|(i, d)| doc(&format!("d{i}"), &[("v", Value::Double(*d))]))
        .collect();
    let out = run(
        vec![Stage::Aggregate {
            accumulators: vec![
                ("s".to_owned(), accumulate(AccumulatorKind::Sum, "v")),
                ("a".to_owned(), accumulate(AccumulatorKind::Average, "v")),
            ],
            groups: vec![],
        }],
        rows,
    );
    assert_eq!(out[0].fields["s"], Value::Double(7.0));
    assert_eq!(out[0].fields["a"], Value::Double(7.0 / 3.0));
    // An integer after a double adds to it, as a double.
    let rows = vec![
        doc("a", &[("v", Value::Double(0.5))]),
        doc("b", &[("v", int(2))]),
        doc("c", &[("v", Value::Double(0.25))]),
    ];
    let out = run(
        vec![Stage::Aggregate {
            accumulators: vec![("s".to_owned(), accumulate(AccumulatorKind::Sum, "v"))],
            groups: vec![],
        }],
        rows,
    );
    assert_eq!(out[0].fields["s"], Value::Double(2.75));
}

#[test]
fn strict_refuses_what_it_cannot_attribute_inside_a_blocking_stage() {
    let rows = vec![doc("a", &[("v", int(1))])];
    let failing = Expr::call("not", vec![field("v")], Placement::Value).unwrap();
    for stage in [
        Stage::Sort(vec![ascending(failing.clone())]),
        Stage::Distinct(vec![("k".to_owned(), failing.clone())]),
        Stage::Aggregate {
            accumulators: vec![("c".to_owned(), count_all())],
            groups: vec![("k".to_owned(), failing.clone())],
        },
    ] {
        let error = execute_in(vec![stage.clone()], rows.clone(), Unrecorded::Refuse).unwrap_err();
        assert!(matches!(error, EvalError::Unobserved { .. }), "{error:?}");
        let error =
            execute_in(vec![stage], rows.clone(), Unrecorded::OfficialEmulator).unwrap_err();
        assert!(matches!(error, EvalError::WrongType { .. }), "{error:?}");
    }
}

#[test]
fn or_xor_and_nor_of_more_than_two_operands_follow_the_recorded_tables() {
    // FS-ENT-ORACLE O-9 `ops-main`: three-valued tables over three and four operands, xor as odd
    // parity (three to five operands), nor true only when every operand is false, and a null or
    // missing operand makes xor and nor of any position null.
    let t = || Eval::Value(Value::Boolean(true));
    let f = || Eval::Value(Value::Boolean(false));
    let n = || Eval::Value(Value::Null);
    for call in [strict, emulator] {
        assert_eq!(call("or", &[f(), f(), t()]), t());
        assert_eq!(call("or", &[f(), f(), f()]), f());
        assert_eq!(call("or", &[f(), n(), f()]), n());
        assert_eq!(call("or", &[f(), Eval::Absent, f()]), n());
        assert_eq!(call("or", &[n(), f(), t()]), t());
        assert_eq!(call("and", &[t(), t(), f()]), f());
        assert_eq!(call("and", &[t(), n(), t()]), n());
        assert_eq!(call("xor", &[t(), t(), t()]), t());
        assert_eq!(call("xor", &[t(), t(), f(), t()]), t());
        assert_eq!(call("xor", &[t(), f(), f(), f(), f()]), t());
        assert_eq!(call("xor", &[t(), t()]), f());
        assert_eq!(call("xor", &[t(), n()]), n());
        assert_eq!(call("xor", &[n(), t(), t()]), n());
        assert_eq!(call("xor", &[t(), t(), Eval::Absent]), n());
        assert_eq!(call("nor", &[f(), f(), f()]), t());
        assert_eq!(call("nor", &[f(), t(), f()]), f());
        assert_eq!(call("nor", &[f(), f(), n()]), n());
        assert_eq!(call("nor", &[Eval::Absent, f()]), n());
    }
}
#[test]
fn operands_are_read_left_to_right_and_the_first_deciding_one_ends_the_call() {
    // FS-ENT-ORACLE O-9 `ops-main`: `and(false, 1)`, `or(true, 1)` and `nor(true, 1)` answer; the
    // same operands the other way round, or beside no deciding operand, fail the call. A null is
    // not deciding.
    let t = || Eval::Value(Value::Boolean(true));
    let f = || Eval::Value(Value::Boolean(false));
    let n = || Eval::Value(Value::Null);
    let one = || Eval::Value(int(1));
    let wrong = |name: &'static str| {
        Eval::Error(EvalError::WrongType {
            function: name,
            expected: "Boolean",
            got: "LONG",
        })
    };
    for call in [strict, emulator] {
        assert_eq!(call("and", &[f(), one()]), f());
        assert_eq!(call("or", &[t(), one()]), t());
        assert_eq!(call("nor", &[t(), one()]), f());
        for (name, args) in [
            ("and", vec![one(), f()]),
            ("and", vec![t(), one()]),
            ("and", vec![n(), one()]),
            ("or", vec![one(), t()]),
            ("or", vec![f(), one()]),
            ("or", vec![n(), one()]),
            ("nor", vec![f(), one()]),
            ("xor", vec![t(), one()]),
        ] {
            let function: &'static str = match name {
                "and" => "and",
                "or" => "or",
                "nor" => "nor",
                _ => "xor",
            };
            assert_eq!(call(name, &args), wrong(function), "{name} {args:?}");
        }
        // Later operands after a deciding one are never looked at, however many.
        assert_eq!(call("and", &[t(), f(), one(), one()]), f());
        assert_eq!(call("or", &[f(), t(), one()]), t());
    }
}
fn sample_values() -> Vec<(Value, &'static str)> {
    vec![
        (Value::Null, "null"),
        (Value::Boolean(true), "boolean"),
        (int(1), "int64"),
        (Value::Double(1.5), "float64"),
        (Value::Double(f64::NAN), "float64"),
        (Value::Timestamp(Timestamp::new(1, 0).unwrap()), "timestamp"),
        (Value::String("a".into()), "string"),
        (Value::Bytes(vec![1]), "bytes"),
        (
            Value::Reference("projects/p/databases/d/documents/c/d".into()),
            "reference",
        ),
        (
            Value::GeoPoint(crate::value::GeoPoint::new(1.0, 2.0).unwrap()),
            "geo_point",
        ),
        (Value::Array(vec![int(1)]), "array"),
        (Value::Map(BTreeMap::new()), "map"),
        (Value::Vector(vec![1.0]), "vector"),
    ]
}

#[test]
fn type_and_is_type_agree_for_every_kind_and_every_name() {
    for (value, name) in sample_values() {
        assert_eq!(
            emulator("type", &[Eval::Value(value.clone())]),
            Eval::Value(Value::String(name.to_owned()))
        );
        // `type` names every kind under strict too.
        assert_eq!(
            strict("type", &[Eval::Value(value.clone())]),
            Eval::Value(Value::String(name.to_owned()))
        );
        for candidate in TYPE_NAMES {
            let expected =
                candidate == name || (candidate == "number" && matches!(name, "int64" | "float64"));
            let answer = emulator(
                "is_type",
                &[
                    Eval::Value(value.clone()),
                    Eval::Value(Value::String(candidate.to_owned())),
                ],
            );
            assert_eq!(
                answer,
                Eval::Value(Value::Boolean(expected)),
                "{value:?} is {name}, asked {candidate}"
            );
        }
    }
}

/// `is_type` answers every name of the list for a stored value: true for its own type and false
/// for every other name, never an error, under both profiles (O-9b `types-matrix`); the names no
/// stored value has (`int32`, `decimal128`, ...) are false.
#[test]
fn is_type_answers_every_name_for_a_stored_value_under_both_profiles() {
    let kinds: [(Value, &[&str]); 6] = [
        (Value::Null, &["null"]),
        (Value::Boolean(true), &["boolean"]),
        (int(1), &["int64", "number"]),
        (Value::Double(1.5), &["float64", "number"]),
        (Value::String("s".into()), &["string"]),
        (Value::Array(vec![]), &["array"]),
    ];
    for (value, own) in kinds {
        for name in TYPE_NAMES {
            for call in [strict, emulator] {
                assert_eq!(
                    call(
                        "is_type",
                        &[
                            Eval::Value(value.clone()),
                            Eval::Value(Value::String(name.to_owned()))
                        ]
                    ),
                    Eval::Value(Value::Boolean(own.contains(&name))),
                    "{value:?} {name}"
                );
            }
        }
    }
    // A name that is no constant string is unobserved.
    assert!(is_unobserved(&strict(
        "is_type",
        &[Eval::Value(int(1)), Eval::Absent]
    )));
    assert!(matches!(
        emulator(
            "is_type",
            &[
                Eval::Value(int(1)),
                Eval::Value(Value::String("bogus".into()))
            ]
        ),
        Eval::Error(EvalError::Invalid(_))
    ));
}
#[test]
fn a_null_array_is_unknown_where_production_answered_it_and_unobserved_under_strict_elsewhere() {
    let null = || Eval::Value(Value::Null);
    let one = || Eval::Value(int(1));
    let list = || Eval::Value(Value::Array(vec![int(1)]));
    // Recorded (O-9 `ops-main`): `array_contains(null | missing, 1)`, `array_contains_any(list,
    // null)` and `not_equal_any(1, null)` are null.
    for call in [strict, emulator] {
        assert_eq!(call("array_contains", &[null(), one()]), null());
        assert_eq!(call("array_contains", &[Eval::Absent, one()]), null());
        assert_eq!(call("array_contains_any", &[list(), null()]), null());
        assert_eq!(call("not_equal_any", &[one(), null()]), null());
    }
    // Not recorded: the other null-array forms, null under the emulator profile only.
    for (name, args) in [
        ("array_contains_all", vec![null(), list()]),
        ("array_contains_all", vec![list(), null()]),
        ("array_contains_any", vec![null(), list()]),
        ("equal_any", vec![one(), null()]),
    ] {
        assert!(is_unobserved(&strict(name, &args)), "{name}");
        assert_eq!(emulator(name, &args), null(), "{name}");
    }
    // A search list that is no array fails the call, naming its type.
    assert!(matches!(
        emulator(
            "array_contains_any",
            &[Eval::Value(Value::Array(vec![])), one()]
        ),
        Eval::Error(EvalError::WrongType {
            function: "array_contains_any",
            ..
        })
    ));
}
#[test]
fn equal_any_and_not_equal_any_of_a_list_that_is_no_array_fail_naming_eq_any() {
    // O-9 `ops-main`: production named `eq_any` for both functions and the type it got.
    let one = || Eval::Value(int(1));
    let list = || Eval::Value(Value::Array(vec![int(1)]));
    for call in [strict, emulator] {
        for name in ["equal_any", "not_equal_any"] {
            assert_eq!(
                call(name, &[one(), one()]),
                Eval::Error(EvalError::WrongType {
                    function: "eq_any",
                    expected: "Array",
                    got: "LONG"
                }),
                "{name}"
            );
            assert_eq!(
                call(name, &[one(), Eval::Value(Value::String("a".into()))]),
                Eval::Error(EvalError::WrongType {
                    function: "eq_any",
                    expected: "Array",
                    got: "STRING"
                }),
                "{name}"
            );
        }
        assert_eq!(
            call("not_equal_any", &[one(), list()]),
            Eval::Value(Value::Boolean(false))
        );
    }
}
#[test]
fn the_registry_checks_the_replace_with_mode() {
    use crate::pipeline::{canonicalize, Arg, StageSpec};
    let users = || StageSpec {
        name: "collection".into(),
        args: vec![Arg::Reference("/users".into())],
        options: vec![],
    };
    let replace = |mode: Option<&str>| {
        let mut args = vec![Arg::Field("m".into())];
        args.extend(mode.map(|m| Arg::String(m.into())));
        StageSpec {
            name: "replace_with".into(),
            args,
            options: vec![],
        }
    };
    assert!(canonicalize(&[users(), replace(None)]).is_ok());
    assert!(canonicalize(&[users(), replace(Some("full_replace"))]).is_ok());
    assert!(canonicalize(&[users(), replace(Some("merge_overwrite_existing"))]).is_ok());
    assert!(canonicalize(&[users(), replace(Some("merge_keep_existing"))]).is_ok());
    assert!(canonicalize(&[users(), replace(Some("merge_prefer_nest"))]).is_ok());
    assert!(canonicalize(&[users(), replace(Some("merge_prefer_parent"))]).is_ok());
    assert!(canonicalize(&[users(), replace(Some("sideways"))]).is_err());
}

/// `add_fields` of a missing value (FS-ENT-ORACLE O-9 `fields-main`, production): a nested alias
/// creates its parents as empty maps and sets nothing (a scalar parent is replaced, a map parent
/// keeps its members), a top-level alias removes the field, a present value is set at any depth.
/// Both profiles answer alike (the official emulator keeps a top-level field).
#[test]
fn add_fields_of_a_missing_value_follows_production() {
    let stage = |name: &str| vec![Stage::AddFields(vec![(alias(name), field("zz"))])];
    let row = || {
        vec![doc(
            "a",
            &[
                ("m", int(5)),
                ("v", int(1)),
                ("q", Value::Map(BTreeMap::from([("k".to_owned(), int(1))]))),
            ],
        )]
    };
    let empty = || Value::Map(BTreeMap::new());
    for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        let add = |name: &str| execute_rows_in(stage(name), row(), unrecorded).unwrap();
        assert_eq!(add("nm.r")[0].fields["nm"], empty(), "{unrecorded:?}");
        assert!(!add("nm.r")[0].fields.contains_key("nm.r"));
        assert_eq!(add("m.r")[0].fields["m"], empty());
        assert_eq!(
            add("nm.p.q")[0].fields["nm"],
            Value::Map(BTreeMap::from([("p".to_owned(), empty())]))
        );
        // A map parent keeps its members.
        assert_eq!(add("q.r")[0].fields["q"], row()[0].fields["q"]);
        // A top-level alias removes the field, whatever it held; a missing one stays missing.
        for name in ["m", "q", "nm"] {
            assert!(!add(name)[0].fields.contains_key(name), "{name}");
        }
        assert_eq!(add("m")[0].fields["v"], int(1));
        // A present value is set at any depth; siblings beside a missing one survive.
        let out = execute_rows_in(
            vec![Stage::AddFields(vec![
                (alias("s.a"), field("zz")),
                (alias("s.b"), field("v")),
            ])],
            row(),
            unrecorded,
        )
        .unwrap();
        assert_eq!(
            out[0].fields["s"],
            Value::Map(BTreeMap::from([("b".to_owned(), int(1))]))
        );
        let out = execute_rows_in(
            vec![Stage::AddFields(vec![(
                alias("m.r"),
                Expr::Constant(Value::Null),
            )])],
            row(),
            unrecorded,
        )
        .unwrap();
        assert_eq!(
            out[0].fields["m"],
            Value::Map(BTreeMap::from([("r".to_owned(), Value::Null)]))
        );
    }
}

/// `is_type` of a missing value is null for every type name, `null` included, in any position
/// (FS-ENT-ORACLE O-9b `types-matrix`).
#[test]
fn is_type_of_a_missing_value_is_null_for_every_type_name() {
    let call = |name: &str, unrecorded, condition| {
        (function("is_type").unwrap().eval)(
            &[Eval::Absent, Eval::Value(Value::String(name.into()))],
            Context {
                unrecorded,
                condition,
                runtime: &RuntimeContext::default(),
            },
        )
    };
    for name in TYPE_NAMES {
        for unrecorded in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
            for condition in [false, true] {
                assert_eq!(
                    call(name, unrecorded, condition),
                    Eval::Value(Value::Null),
                    "{name} {unrecorded:?} {condition}"
                );
            }
        }
    }
}
/// Registry entries without recorded signatures still retain the legacy boolean/arity relation.
#[test]
fn functions_without_a_signature_are_boolean_if_and_only_if_they_take_two_arguments() {
    for function in FUNCTIONS.iter().filter(|f| {
        f.signature.is_empty()
            && !matches!(
                f.name,
                "namespace"
                    | "has_ancestor"
                    | "reference_slice"
                    | "replace_document_id"
                    | "autogen_document_id"
                    | "coalesce"
                    | "cmp"
                    | "storage_size"
                    | "get_field"
                    | "offset"
                    | "reverse"
                    | "length"
                    | "string_concat"
            )
    }) {
        assert_eq!(
            function.returns_boolean,
            matches!(function.arity, Arity::Exact(2)),
            "{}",
            function.name
        );
    }
}

/// An operand whose evaluation fails is reported wherever it stands (the emulator profile), and
/// strict calls it unobserved when another operand decides the call: `or(true, not(1))` was not
/// asked of production, so no recording of that shape may make strict answer it.
#[test]
fn a_failing_operand_beside_a_deciding_one_is_unobserved_under_strict() {
    let t = || Eval::Value(Value::Boolean(true));
    let f = || Eval::Value(Value::Boolean(false));
    let failing = || {
        Eval::Error(EvalError::WrongType {
            function: "not",
            expected: "Boolean",
            got: "LONG",
        })
    };
    for (name, deciding) in [("or", t()), ("nor", t()), ("and", f())] {
        for position in 0..2 {
            let mut args = vec![failing()];
            args.insert(position, deciding.clone());
            assert!(is_unobserved(&strict(name, &args)), "{name} {args:?}");
            assert_eq!(emulator(name, &args), failing(), "{name} {args:?}");
        }
    }
    // No deciding operand: the failure is the answer under both profiles.
    for (name, plain) in [("or", f()), ("nor", f()), ("and", t())] {
        let args = [plain, failing()];
        assert_eq!(strict(name, &args), failing(), "{name}");
        assert_eq!(emulator(name, &args), failing(), "{name}");
    }
}

#[test]
fn unnest_expands_arrays_preserves_rows_and_stops_at_downstream_limit() {
    let source = doc(
        "x",
        &[
            ("tags", Value::Array(vec![int(1), int(2), int(3)])),
            ("keep", int(8)),
        ],
    );
    let stages = vec![
        Stage::Unnest {
            expression: field("tags"),
            alias: alias("v"),
            index_field: Some(alias("idx")),
        },
        Stage::Limit(2),
    ];
    let mut cursor = Cursor::new_in(stages, Unrecorded::Refuse);
    let rows = cursor.push(source.clone()).unwrap();
    assert_eq!(rows.len(), 2);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row.path, source.path);
        assert_eq!(row.times, source.times);
        assert_eq!(row.fields["keep"], int(8));
        assert_eq!(row.fields["v"], int(i64::try_from(index).unwrap() + 1));
        assert_eq!(row.fields["idx"], int(i64::try_from(index).unwrap()));
    }
    assert!(cursor.is_exhausted());
}

#[test]
fn unnest_absent_source_removes_existing_alias() {
    for profile in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        let source = doc("x", &[("v", int(9)), ("keep", int(8))]);
        let stages = vec![Stage::Unnest {
            expression: field("missing"),
            alias: alias("v"),
            index_field: None,
        }];
        let rows = Cursor::new_in(stages, profile).push(source).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].fields.contains_key("v"));
        assert_eq!(rows[0].fields["keep"], int(8));
    }
}

#[test]
fn unnest_pict_generated_cases() {
    let cases = [
        ("array", "new", "present", "none", "strict"),
        ("empty", "new", "none", "none", "strict"),
        ("null", "new", "none", "none", "strict"),
        ("scalar", "overwrite", "none", "where", "strict"),
        ("absent", "new", "none", "offset", "emulator"),
        ("array", "overwrite", "present", "limit", "strict"),
        ("array", "new", "none", "sort", "emulator"),
        ("null", "overwrite", "present", "sort", "emulator"),
        ("empty", "overwrite", "present", "offset", "strict"),
        ("empty", "new", "none", "limit", "emulator"),
        ("null", "new", "present", "where", "emulator"),
        ("absent", "overwrite", "present", "where", "strict"),
        ("empty", "overwrite", "none", "where", "emulator"),
        ("null", "overwrite", "none", "limit", "emulator"),
        ("array", "overwrite", "present", "offset", "emulator"),
        ("scalar", "overwrite", "present", "none", "emulator"),
        ("scalar", "new", "none", "limit", "emulator"),
        ("scalar", "overwrite", "present", "offset", "emulator"),
        ("scalar", "new", "none", "sort", "strict"),
        ("array", "overwrite", "none", "where", "emulator"),
        ("null", "overwrite", "present", "offset", "strict"),
        ("absent", "new", "none", "none", "strict"),
        ("empty", "new", "present", "sort", "strict"),
        ("absent", "new", "none", "sort", "strict"),
        ("absent", "new", "present", "limit", "emulator"),
    ];
    for (input, alias_mode, index, downstream, profile) in cases {
        let mut source = doc("x", &[("keep", int(8)), ("target", int(9))]);
        match input {
            "array" => {
                source
                    .fields
                    .insert("v".into(), Value::Array(vec![int(1), int(2)]));
            }
            "empty" => {
                source.fields.insert("v".into(), Value::Array(vec![]));
            }
            "null" => {
                source.fields.insert("v".into(), Value::Null);
            }
            "scalar" => {
                source.fields.insert("v".into(), int(7));
            }
            _ => {}
        }
        let dest = if alias_mode == "overwrite" {
            "target"
        } else {
            "out"
        };
        let mut stages = vec![Stage::Unnest {
            expression: field("v"),
            alias: alias(dest),
            index_field: if index == "present" {
                Some(alias("idx"))
            } else {
                None
            },
        }];
        match downstream {
            "where" => stages.push(Stage::Where(Expr::Constant(Value::Boolean(true)))),
            "limit" => stages.push(Stage::Limit(1)),
            "offset" => stages.push(Stage::Offset(1)),
            "sort" => stages.push(Stage::Sort(vec![ascending(field(dest))])),
            _ => {}
        }
        let mode = if profile == "strict" {
            Unrecorded::Refuse
        } else {
            Unrecorded::OfficialEmulator
        };
        let result = execute_rows_in(stages, vec![source.clone()], mode);
        if index == "present" && matches!(input, "null" | "scalar" | "absent") {
            assert!(matches!(result, Err(EvalError::Unobserved { .. })));
            continue;
        }
        let result = result.unwrap();
        let initial: usize = match input {
            "array" => 2,
            "empty" => 0,
            _ => 1,
        };
        let count = match downstream {
            "limit" => initial.min(1),
            "offset" => initial.saturating_sub(1),
            _ => initial,
        };
        assert_eq!(
            result.len(),
            count,
            "{input}/{alias_mode}/{index}/{downstream}/{profile}"
        );
        for row in result {
            assert_eq!(row.path, source.path);
            assert_eq!(row.fields["keep"], int(8));
        }
    }
}

#[test]
fn unnest_cartesian_product_and_limit_before_stage() {
    let row = doc("x", &[("v", Value::Array(vec![int(1), int(2)]))]);
    let stage = |name| Stage::Unnest {
        expression: field("v"),
        alias: alias(name),
        index_field: None,
    };
    let rows = run(vec![Stage::Limit(1), stage("a"), stage("b")], vec![row]);
    assert_eq!(
        rows.iter()
            .map(|row| (row.fields["a"].clone(), row.fields["b"].clone()))
            .collect::<Vec<_>>(),
        [
            (int(1), int(1)),
            (int(1), int(2)),
            (int(2), int(1)),
            (int(2), int(2))
        ]
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn unnest_preserves_array_order_and_indices(items in proptest::collection::vec(-100_i64..100, 0..32)) {
        let row = doc("x", &[("v", Value::Array(items.iter().copied().map(int).collect())), ("keep", int(8))]);
        let rows = run(vec![Stage::Unnest { expression: field("v"), alias: alias("out"), index_field: Some(alias("idx")) }], vec![row.clone()]);
        prop_assert_eq!(rows.len(), items.len());
        for (i, (actual, expected)) in rows.iter().zip(items).enumerate() {
            prop_assert_eq!(&actual.path, &row.path);
            prop_assert_eq!(&actual.fields["keep"], &int(8));
            prop_assert_eq!(&actual.fields["out"], &int(expected));
            prop_assert_eq!(&actual.fields["idx"], &int(i64::try_from(i).unwrap()));
        }
    }
}

#[test]
fn unnest_overwrite_is_seen_by_where_and_limit_zero_emits_nothing() {
    let row = doc("x", &[("v", Value::Array(vec![int(1), int(2), int(3)]))]);
    let unnest = || Stage::Unnest {
        expression: field("v"),
        alias: alias("v"),
        index_field: None,
    };
    let condition = Expr::call(
        "equal",
        vec![field("v"), Expr::Constant(int(2))],
        Placement::Condition,
    )
    .unwrap();
    let rows = run(vec![unnest(), Stage::Where(condition)], vec![row.clone()]);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].fields["v"], int(2));
    assert!(run(vec![unnest(), Stage::Limit(0)], vec![row]).is_empty());
}

#[test]
fn unnest_preserves_nonempty_metadata_and_runtime_context() {
    let mut row = doc("x", &[("keep", int(8))]);
    row.times = Some(RowTimes {
        created: Timestamp::new(1, 0).unwrap(),
        updated: Timestamp::new(2, 0).unwrap(),
    });
    let timestamp = Timestamp::new(10, 123_000).unwrap();
    let expression = Expr::call("current_timestamp", vec![], Placement::Value).unwrap();
    let mut cursor = Cursor::new_in_with_runtime(
        vec![Stage::Unnest {
            expression,
            alias: alias("out"),
            index_field: None,
        }],
        Unrecorded::Refuse,
        RuntimeContext {
            request_timestamp: Some(timestamp),
            ..RuntimeContext::default()
        },
    );
    let rows = cursor.push(row.clone()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].times, row.times);
    assert_eq!(rows[0].path, row.path);
    assert_eq!(rows[0].fields["out"], Value::Timestamp(timestamp));
}

#[test]
fn unnest_deep_chain_does_not_depend_on_thread_stack() {
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let stages = (0..2_000)
                .map(|_| Stage::Unnest {
                    expression: Expr::Constant(Value::Array(vec![int(7)])),
                    alias: alias("v"),
                    index_field: None,
                })
                .collect();
            let rows = run(stages, vec![doc("x", &[])]);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].fields["v"], int(7));
        })
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn union_appends_prepared_branch_with_suffix_limit_and_metadata() {
    let left = doc("left", &[("n", int(1))]);
    let right = doc("right", &[("n", int(2))]);
    let mut cursor = Cursor::new(vec![
        Stage::Union {
            branches: vec![PreparedUnionBranch {
                stages: Vec::new(),
                rows: vec![right.clone()],
            }],
        },
        Stage::Limit(2),
    ]);
    let mut rows = cursor.push(left.clone()).unwrap();
    rows.extend(cursor.finish().unwrap());
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].path, left.path);
    assert_eq!(rows[1].path, right.path);
    assert!(cursor.finish().unwrap().is_empty());
}

#[test]
fn union_prefix_limit_does_not_limit_child_and_suffix_limit_counts_both() {
    let left = doc("left", &[("n", int(1))]);
    let right = doc("right", &[("n", int(2))]);
    let mut cursor = Cursor::new(vec![
        Stage::Limit(1),
        Stage::Union {
            branches: vec![PreparedUnionBranch {
                stages: Vec::new(),
                rows: vec![right],
            }],
        },
        Stage::Limit(2),
    ]);
    let mut rows = cursor.push(left).unwrap();
    assert!(cursor.is_exhausted());
    rows.extend(cursor.finish().unwrap());
    assert_eq!(
        rows.iter().map(|r| &r.fields["n"]).collect::<Vec<_>>(),
        vec![&int(1), &int(2)]
    );
}

#[test]
fn union_keeps_duplicates_and_child_select_drops_only_child_metadata() {
    let left = doc("left", &[("n", int(1))]);
    let mut cursor = Cursor::new(vec![Stage::Union {
        branches: vec![PreparedUnionBranch {
            stages: vec![Stage::select(vec![(alias("n"), field("n"))])],
            rows: vec![left.clone(), left.clone()],
        }],
    }]);
    let mut rows = cursor.push(left.clone()).unwrap();
    rows.extend(cursor.finish().unwrap());
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].path, left.path);
    assert!(rows[1].path.is_none() && rows[2].path.is_none());
    assert_eq!(rows[1].fields["n"], int(1));
}

#[test]
fn union_refuses_non_row_local_prepared_children() {
    let mut cursor = Cursor::new(vec![Stage::Union {
        branches: vec![PreparedUnionBranch {
            stages: vec![Stage::Limit(1)],
            rows: vec![doc("right", &[("n", int(2))])],
        }],
    }]);
    assert!(matches!(
        cursor.finish(),
        Err(EvalError::Unobserved {
            function: "union",
            ..
        })
    ));
}

#[test]
fn union_blocking_prefix_and_suffix_keep_order_and_child_is_lazy_after_limit() {
    let source = |n| doc(&format!("n{n}"), &[("n", int(n))]);
    let branch = || PreparedUnionBranch {
        stages: Vec::new(),
        rows: vec![source(2)],
    };
    let mut cursor = Cursor::new(vec![
        Stage::Sort(vec![ascending(field("n"))]),
        Stage::Union {
            branches: vec![branch()],
        },
        Stage::Sort(vec![ascending(field("n"))]),
    ]);
    cursor.push(source(3)).unwrap();
    cursor.push(source(1)).unwrap();
    let rows = cursor.finish().unwrap();
    assert_eq!(
        rows.iter().map(|r| &r.fields["n"]).collect::<Vec<_>>(),
        vec![&int(1), &int(2), &int(3)]
    );
    let failing = Expr::call("not", vec![field("n")], Placement::Value).unwrap();
    let mut cursor = Cursor::new(vec![
        Stage::Union {
            branches: vec![PreparedUnionBranch {
                stages: vec![Stage::Where(failing)],
                rows: vec![source(2)],
            }],
        },
        Stage::Limit(0),
    ]);
    assert!(cursor.finish().unwrap().is_empty());
}

proptest! {
    #[test]
    fn union_preserves_order_duplicates_and_empty_identity(left in proptest::collection::vec(-10_i64..10, 0..20), right in proptest::collection::vec(-10_i64..10, 0..20)) {
        let rows = |values: &[i64]| values.iter().enumerate().map(|(i, n)| doc(&format!("x{i}"), &[("n", int(*n))])).collect::<Vec<_>>();
        let mut cursor = Cursor::new(vec![Stage::Union { branches: vec![PreparedUnionBranch { stages: Vec::new(), rows: rows(&right) }] }]);
        let mut output = Vec::new();
        for row in rows(&left) { output.extend(cursor.push(row).unwrap()); }
        output.extend(cursor.finish().unwrap());
        let actual = output.iter().map(|row| row.fields["n"].clone()).collect::<Vec<_>>();
        let expected = left.iter().chain(&right).map(|n| int(*n)).collect::<Vec<_>>();
        prop_assert_eq!(actual, expected);
    }
}

#[test]
fn union_stops_lazy_children_across_later_union_when_limit_is_full() {
    let row = doc("left", &[("n", int(1))]);
    let failing = Expr::call("not", vec![field("n")], Placement::Value).unwrap();
    let mut cursor = Cursor::new(vec![
        Stage::Union {
            branches: vec![PreparedUnionBranch {
                stages: vec![Stage::Where(failing)],
                rows: vec![row.clone()],
            }],
        },
        Stage::Union {
            branches: Vec::new(),
        },
        Stage::Limit(1),
    ]);
    assert_eq!(cursor.push(row).unwrap().len(), 1);
    assert!(cursor.finish().unwrap().is_empty());
}

#[test]
fn union_generated_core_combinations() {
    let cases = [
        ("different", "plain", "none"),
        ("same", "plain", "none"),
        ("empty", "plain", "none"),
        ("different", "where", "none"),
        ("different", "select", "none"),
        ("different", "nested", "none"),
        ("different", "plain", "prefix_limit"),
        ("different", "plain", "suffix_limit"),
        ("different", "plain", "blocking"),
        ("same", "where", "blocking"),
        ("empty", "where", "prefix_limit"),
        ("same", "select", "suffix_limit"),
        ("empty", "where", "suffix_limit"),
        ("empty", "select", "prefix_limit"),
        ("empty", "select", "blocking"),
        ("empty", "nested", "suffix_limit"),
        ("same", "nested", "prefix_limit"),
        ("different", "nested", "blocking"),
    ];
    for (branch, child, boundary) in cases {
        let row = |n| doc(&format!("p{n}"), &[("n", int(n))]);
        let left = vec![1, 4];
        let right = match branch {
            "different" => vec![2, 3],
            "same" => left.clone(),
            "empty" => Vec::new(),
            _ => unreachable!(),
        };
        let child_stages = match child {
            "where" => vec![Stage::Where(
                Expr::call(
                    "equal",
                    vec![field("n"), Expr::Constant(int(2))],
                    Placement::Condition,
                )
                .unwrap(),
            )],
            "select" => vec![Stage::select(vec![(alias("n"), field("n"))])],
            "plain" | "nested" => Vec::new(),
            _ => unreachable!(),
        };
        let mut branches = vec![PreparedUnionBranch {
            stages: child_stages,
            rows: right.iter().copied().map(row).collect(),
        }];
        if child == "nested" {
            branches.push(PreparedUnionBranch {
                stages: Vec::new(),
                rows: vec![row(5)],
            });
        }
        let mut stages = Vec::new();
        if boundary == "prefix_limit" {
            stages.push(Stage::Limit(1));
        }
        stages.push(Stage::Union { branches });
        if boundary == "suffix_limit" {
            stages.push(Stage::Limit(2));
        }
        if boundary == "blocking" {
            stages.push(Stage::Sort(vec![ascending(field("n"))]));
        }
        let mut cursor = Cursor::new(stages);
        let mut actual = Vec::new();
        for n in &left {
            if cursor.is_exhausted() {
                break;
            }
            actual.extend(cursor.push(row(*n)).unwrap());
        }
        actual.extend(cursor.finish().unwrap());
        let mut expected = if boundary == "prefix_limit" {
            vec![1]
        } else {
            left
        };
        expected.extend(right.into_iter().filter(|n| child != "where" || *n == 2));
        if child == "nested" {
            expected.push(5);
        }
        if boundary == "suffix_limit" {
            expected.truncate(2);
        }
        if boundary == "blocking" {
            expected.sort_unstable();
        }
        assert_eq!(
            actual
                .iter()
                .map(|row| row.fields["n"].clone())
                .collect::<Vec<_>>(),
            expected.into_iter().map(int).collect::<Vec<_>>(),
            "{branch} {child} {boundary}"
        );
    }
}

#[test]
fn sample_documents_and_percent_preserve_cardinality_order_and_finish_once() {
    let rows = vec![
        doc("a", &[("v", int(1))]),
        doc("b", &[("v", int(2))]),
        doc("c", &[("v", int(3))]),
    ];
    let runtime = RuntimeContext {
        sample_seed: Some(17),
        ..RuntimeContext::default()
    };
    let mut cursor = Cursor::new_in_with_runtime(
        vec![Stage::Sample(SampleMode::Documents(2))],
        Unrecorded::Refuse,
        runtime.clone(),
    );
    for row in &rows {
        assert!(cursor.push(row.clone()).unwrap().is_empty());
    }
    let sampled = cursor.finish().unwrap();
    assert_eq!(sampled.len(), 2);
    assert!(sampled.iter().all(|row| rows.contains(row)));
    assert!(cursor.finish().unwrap().is_empty());
    let mut all = Cursor::new_in_with_runtime(
        vec![Stage::Sample(SampleMode::Percent(1.0))],
        Unrecorded::Refuse,
        runtime.clone(),
    );
    let mut observed = Vec::new();
    for row in &rows {
        observed.extend(all.push(row.clone()).unwrap());
    }
    observed.extend(all.finish().unwrap());
    assert_eq!(observed, rows);
    let mut none = Cursor::new_in_with_runtime(
        vec![Stage::Sample(SampleMode::Percent(0.0))],
        Unrecorded::Refuse,
        runtime.clone(),
    );
    for row in rows {
        assert!(none.push(row).unwrap().is_empty());
    }
    assert!(none.finish().unwrap().is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn sample_pict_rows_execute_with_seeded_contracts() {
    let mut tested = 0;
    for line in include_str!("sample.generated.tsv").lines().skip(1) {
        let fields: Vec<_> = line.split('\t').collect();
        let [mode, size, input, placement, profile, seed] = fields.as_slice() else {
            panic!("invalid row {line}")
        };
        let values: Vec<i64> = match *input {
            "empty" => vec![],
            "single" => vec![1],
            "duplicates" => vec![1, 1, 2, 2],
            _ => vec![1, 2, 3, 4],
        };
        let rows: Vec<Row> = values
            .iter()
            .enumerate()
            .map(|(i, n)| doc(&format!("d{i}"), &[("v", int(*n))]))
            .collect();
        let count = match *size {
            "zero" => 0,
            "middle" => 2,
            "full" => 4,
            _ => 10,
        };
        let sample = if *mode == "documents" {
            SampleMode::Documents(count)
        } else {
            SampleMode::Percent(match *size {
                "zero" => 0.0,
                "middle" => 0.5,
                _ => 1.0,
            })
        };
        let mut stages = Vec::new();
        if *placement == "prefix_limit" {
            stages.push(Stage::Limit(1));
        }
        stages.push(Stage::Sample(sample));
        if *placement == "suffix_limit" {
            stages.push(Stage::Limit(1));
        }
        if *placement == "blocking" {
            stages.push(Stage::Sort(vec![ascending(field("v"))]));
        }
        let runtime = RuntimeContext {
            sample_seed: Some(if *seed == "first" { 17 } else { 23 }),
            ..RuntimeContext::default()
        };
        let policy = if *profile == "strict" {
            Unrecorded::Refuse
        } else {
            Unrecorded::OfficialEmulator
        };
        let execute = || {
            let mut cursor = Cursor::new_in_with_runtime(stages.clone(), policy, runtime.clone());
            let mut out = Vec::new();
            for row in &rows {
                if cursor.is_exhausted() {
                    break;
                }
                out.extend(cursor.push(row.clone()).unwrap());
            }
            out.extend(cursor.finish().unwrap());
            assert!(cursor.finish().unwrap().is_empty(), "{line}");
            out
        };
        let actual = execute();
        assert_eq!(actual, execute(), "{line}");
        let eligible = if *placement == "prefix_limit" {
            &rows[..rows.len().min(1)]
        } else {
            &rows[..]
        };
        assert!(actual.iter().all(|row| eligible.contains(row)), "{line}");
        let got_names = names(&actual);
        let mut unique = got_names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), actual.len(), "{line}");
        if *mode == "documents" {
            let mut expected = usize::try_from(count).unwrap().min(eligible.len());
            if *placement == "suffix_limit" {
                expected = expected.min(1);
            }
            assert_eq!(actual.len(), expected, "{line}");
        }
        if *mode == "percent" && *placement != "blocking" {
            let positions: Vec<_> = actual
                .iter()
                .map(|row| {
                    eligible
                        .iter()
                        .position(|candidate| candidate == row)
                        .unwrap()
                })
                .collect();
            assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{line}");
        }
        if *mode == "percent" && *size == "zero" {
            assert!(actual.is_empty(), "{line}");
        }
        tested += 1;
    }
    assert_eq!(tested, 22);
}

proptest! {
    #[test]
    fn sample_documents_preserve_occurrences_and_metadata(size in 0_u64..16, input in proptest::collection::vec(-3_i64..4, 0..12), seed in any::<u64>()) {
        let rows: Vec<Row> = input.iter().enumerate().map(|(i, n)| doc(&format!("d{i}"), &[("v", int(*n))])).collect();
        let runtime = RuntimeContext { sample_seed: Some(seed), ..RuntimeContext::default() };
        let execute = || { let mut cursor = Cursor::new_in_with_runtime(vec![Stage::Sample(SampleMode::Documents(size))], Unrecorded::Refuse, runtime.clone()); for row in &rows { cursor.push(row.clone()).unwrap(); } let out = cursor.finish().unwrap(); assert!(cursor.finish().unwrap().is_empty()); out };
        let out = execute();
        prop_assert_eq!(out.len(), usize::try_from(size).unwrap().min(rows.len()));
        prop_assert!(out.iter().all(|row| rows.contains(row)));
        let mut ids = names(&out); ids.sort(); ids.dedup(); prop_assert_eq!(ids.len(), out.len());
        prop_assert_eq!(out, execute());
    }
}

#[test]
fn sampling_seed_variation_limit_and_finish_contracts() {
    let rows: Vec<Row> = (0..12)
        .map(|i| doc(&format!("d{i}"), &[("v", int(i))]))
        .collect();
    let sample = |seed, stages: Vec<Stage>| {
        let mut cursor = Cursor::new_in_with_runtime(
            stages,
            Unrecorded::Refuse,
            RuntimeContext {
                sample_seed: Some(seed),
                ..RuntimeContext::default()
            },
        );
        let mut out = Vec::new();
        for row in &rows {
            if cursor.is_exhausted() {
                break;
            }
            out.extend(cursor.push(row.clone()).unwrap());
        }
        out.extend(cursor.finish().unwrap());
        assert!(cursor.finish().unwrap().is_empty());
        assert!(cursor.push(rows[0].clone()).unwrap().is_empty());
        out
    };
    let samples: Vec<_> = (0..16)
        .map(|seed| names(&sample(seed, vec![Stage::Sample(SampleMode::Documents(3))])))
        .collect();
    assert!(samples.windows(2).any(|pair| pair[0] != pair[1]));
    let post_limit = sample(
        4,
        vec![Stage::Sample(SampleMode::Documents(4)), Stage::Limit(1)],
    );
    assert_eq!(post_limit.len(), 1);
    let pre_limit = sample(
        4,
        vec![Stage::Limit(1), Stage::Sample(SampleMode::Documents(4))],
    );
    assert_eq!(pre_limit, vec![rows[0].clone()]);
    let percent_counts: Vec<_> = (0..16)
        .map(|seed| sample(seed, vec![Stage::Sample(SampleMode::Percent(0.5))]).len())
        .collect();
    assert!(percent_counts
        .iter()
        .any(|count| *count > 0 && *count < rows.len()));
    assert!(percent_counts.windows(2).any(|pair| pair[0] != pair[1]));
    let percent = sample(4, vec![Stage::Sample(SampleMode::Percent(0.5))]);
    let positions: Vec<_> = percent
        .iter()
        .map(|row| rows.iter().position(|r| r == row).unwrap())
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn observed_replace_modes_preserve_expected_fields() {
    let nested = Value::Map(BTreeMap::from([
        ("shared".into(), Value::String("new".into())),
        ("added".into(), Value::String("a".into())),
    ]));
    let mut row = doc(
        "a",
        &[
            ("shared", Value::String("old".into())),
            ("keep", int(1)),
            ("m", nested),
        ],
    );
    row.times = Some(RowTimes {
        created: Timestamp::new(1, 0).unwrap(),
        updated: Timestamp::new(2, 0).unwrap(),
    });
    for policy in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        for (mode, expected, keeps) in [
            (ReplaceMode::Full, "new", false),
            (ReplaceMode::Overwrite, "new", true),
            (ReplaceMode::Keep, "old", true),
        ] {
            let out = execute_rows_in(
                vec![Stage::ReplaceWith {
                    expression: field("m"),
                    mode,
                }],
                vec![row.clone()],
                policy,
            )
            .unwrap();
            assert_eq!(out[0].fields["shared"], Value::String(expected.into()));
            assert_eq!(out[0].fields["added"], Value::String("a".into()));
            assert_eq!(out[0].fields.contains_key("keep"), keeps);
            assert_eq!(out[0].path, if keeps { row.path.clone() } else { None });
            assert_eq!(out[0].times, if keeps { row.times } else { None });
            let after = execute_rows_in(
                vec![Stage::AddFields(vec![(
                    alias("after_name"),
                    field("__name__"),
                )])],
                out,
                policy,
            )
            .unwrap();
            assert_eq!(after[0].fields.contains_key("after_name"), keeps);
        }
        let result = execute_rows_in(
            vec![Stage::ReplaceWith {
                expression: Expr::Constant(int(7)),
                mode: ReplaceMode::Full,
            }],
            vec![row.clone()],
            policy,
        );
        assert!(matches!(result, Err(EvalError::Unobserved { .. })));
    }
}

proptest! {
    #[test]
    fn replace_keep_preserves_existing_collision_and_adds_new(old in any::<i64>(), new in any::<i64>()) {
        let map = Value::Map(BTreeMap::from([("collision".into(), int(new)), ("added".into(), int(new))]));
        let row = doc("a", &[("collision", int(old)), ("m", map)]);
        let out = execute_rows_in(vec![Stage::ReplaceWith { expression: field("m"), mode: ReplaceMode::Keep }], vec![row], Unrecorded::Refuse).unwrap();
        prop_assert_eq!(&out[0].fields["collision"], &int(old));
        prop_assert_eq!(&out[0].fields["added"], &int(new));
    }
}

#[test]
fn observed_nearest_cosine_distances_match_exact_typed_results() {
    let rows = vec![
        doc("a", &[("vec", Value::Vector(vec![2.0, 1.0]))]),
        doc("b", &[("vec", Value::Vector(vec![3.0, 2.0]))]),
        doc("c", &[("vec", Value::Vector(vec![2.0, 4.0]))]),
    ];
    for policy in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        let out = execute_rows_in(
            vec![Stage::FindNearest {
                expression: field("vec"),
                query: vec![1.0, 2.0],
                measure: DistanceMeasure::Cosine,
                limit: 3,
                distance_field: Some(alias("dist")),
            }],
            rows.clone(),
            policy,
        )
        .unwrap();
        assert_eq!(names(&out), ["c", "b", "a"]);
        let distances: Vec<f64> = out
            .iter()
            .map(|row| match row.fields["dist"] {
                Value::Double(x) => x,
                _ => panic!("distance type"),
            })
            .collect();
        assert_eq!(
            distances,
            [0.0, 0.131_756_857_875_540_7, 0.199_999_999_999_999_96]
        );
    }
}

#[test]
fn nearest_observed_dimension_mismatch_is_empty_and_dot_ranks_descending() {
    let rows = vec![
        doc("a", &[("vec", Value::Vector(vec![2.0, 1.0]))]),
        doc("b", &[("vec", Value::Vector(vec![3.0, 2.0]))]),
        doc("c", &[("vec", Value::Vector(vec![2.0, 4.0]))]),
    ];
    for policy in [Unrecorded::Refuse, Unrecorded::OfficialEmulator] {
        let stage = |query, measure| Stage::FindNearest {
            expression: field("vec"),
            query,
            measure,
            limit: 3,
            distance_field: Some(alias("dist")),
        };
        let mismatch = execute_rows_in(
            vec![stage(vec![1.0, 2.0, 3.0], DistanceMeasure::Euclidean)],
            rows.clone(),
            policy,
        );
        assert!(mismatch.is_ok());
        assert!(mismatch.unwrap().is_empty());
        let out = execute_rows_in(
            vec![stage(vec![1.0, 2.0], DistanceMeasure::DotProduct)],
            rows.clone(),
            policy,
        )
        .unwrap();
        assert_eq!(names(&out), ["c", "b", "a"]);
        assert_eq!(
            out.iter()
                .map(|r| r.fields["dist"].clone())
                .collect::<Vec<_>>(),
            [Value::Double(10.0), Value::Double(7.0), Value::Double(4.0)]
        );
        assert_eq!(out[0].path, rows[2].path);
    }
}

#[test]
fn nearest_zero_and_overflow_distances_are_unobserved() {
    assert_eq!(
        pipeline_vector_distance(&[0.0, 0.0], &[1.0, 2.0], DistanceMeasure::Cosine),
        None
    );
    assert_eq!(
        pipeline_vector_distance(&[1e200, 1e200], &[1e200, 1e200], DistanceMeasure::Cosine),
        None
    );
    assert_eq!(
        pipeline_vector_distance(
            &[1e-200, 1e-200],
            &[1e-200, 1e-200],
            DistanceMeasure::Cosine
        ),
        None
    );
}

#[test]
#[ignore = "recorded scalar replacement remains unserved pending a general semantic rule"]
fn recorded_scalar_replace_witness_remains_open() {
    let row = doc("a", &[("keep", int(1))]);
    let out = execute_rows_in(
        vec![Stage::ReplaceWith {
            expression: Expr::Constant(int(7)),
            mode: ReplaceMode::Full,
        }],
        vec![row],
        Unrecorded::Refuse,
    )
    .unwrap();
    assert!(out[0].fields.is_empty());
}

#[test]
fn five_aggregate_functions_preserve_values_and_input_order() {
    let rows = vec![
        doc("a", &[("v", int(1)), ("b", Value::Boolean(true))]),
        doc("b", &[("v", int(1)), ("b", Value::Boolean(false))]),
        doc("c", &[("v", int(3)), ("b", Value::Boolean(true))]),
    ];
    let out = run(
        vec![Stage::Aggregate {
            accumulators: vec![
                ("a".into(), accumulate(AccumulatorKind::ArrayAgg, "v")),
                (
                    "d".into(),
                    accumulate(AccumulatorKind::ArrayAggDistinct, "v"),
                ),
                ("f".into(), accumulate(AccumulatorKind::First, "v")),
                ("l".into(), accumulate(AccumulatorKind::Last, "v")),
                ("c".into(), accumulate(AccumulatorKind::CountIf, "b")),
            ],
            groups: vec![],
        }],
        rows,
    );
    assert_eq!(
        out[0].fields["a"],
        Value::Array(vec![int(1), int(1), int(3)])
    );
    assert_eq!(out[0].fields["d"], Value::Array(vec![int(1), int(3)]));
    assert_eq!(out[0].fields["f"], int(1));
    assert_eq!(out[0].fields["l"], int(3));
    assert_eq!(out[0].fields["c"], int(2));
}

#[test]
fn aggregate_new_functions_keep_absence_and_limits_explicit() {
    let stages = |kind| {
        vec![Stage::Aggregate {
            accumulators: vec![("v".into(), accumulate(kind, "v"))],
            groups: vec![],
        }]
    };
    let absent = vec![doc("a", &[])];
    for kind in [AccumulatorKind::ArrayAgg, AccumulatorKind::ArrayAggDistinct] {
        assert_eq!(
            run(stages(kind), absent.clone())[0].fields["v"],
            Value::Array(vec![Value::Null])
        );
    }
    for kind in [
        AccumulatorKind::First,
        AccumulatorKind::Last,
        AccumulatorKind::CountIf,
    ] {
        assert!(execute_rows_in(stages(kind), absent.clone(), Unrecorded::Refuse).is_err());
    }
    for kind in [AccumulatorKind::First, AccumulatorKind::Last] {
        assert!(execute_rows_in(stages(kind), vec![], Unrecorded::Refuse).is_err());
    }
    assert!(execute_rows_in(
        stages(AccumulatorKind::ArrayAgg),
        vec![doc("a", &[("v", Value::String("x".repeat(1_048_576)))])],
        Unrecorded::Refuse
    )
    .is_err());
}

proptest! {
    #[test]
    fn aggregate_arrays_match_ordered_reference(values in proptest::collection::vec(-3_i64..4, 0..30)) {
        let rows=values.iter().enumerate().map(|(i,n)| doc(&format!("{i}"), &[("v",int(*n))])).collect();
        let result=run(vec![Stage::Aggregate { accumulators: vec![("a".into(),accumulate(AccumulatorKind::ArrayAgg,"v")), ("d".into(),accumulate(AccumulatorKind::ArrayAggDistinct,"v"))],groups:vec![] }],rows);
        let mut distinct=Vec::new(); for v in &values { if !distinct.contains(v) { distinct.push(*v); } }
        prop_assert_eq!(&result[0].fields["a"], &Value::Array(values.into_iter().map(int).collect()));
        prop_assert_eq!(&result[0].fields["d"], &Value::Array(distinct.into_iter().map(int).collect()));
    }
}

#[test]
fn aggregate_five_seeded_pict_rows() {
    for (name, input, grouping) in [
        ("array", "normal", "ungrouped"),
        ("distinct", "normal", "ungrouped"),
        ("first", "normal", "ungrouped"),
        ("last", "normal", "ungrouped"),
        ("count_if", "normal", "ungrouped"),
        ("array", "missing", "grouped"),
        ("distinct", "mixed", "grouped"),
        ("first", "empty", "ungrouped"),
        ("last", "empty", "ungrouped"),
        ("count_if", "missing", "grouped"),
        ("array", "empty", "grouped"),
        ("array", "mixed", "ungrouped"),
        ("count_if", "empty", "grouped"),
        ("last", "missing", "ungrouped"),
        ("last", "mixed", "grouped"),
        ("distinct", "missing", "grouped"),
        ("first", "missing", "grouped"),
        ("distinct", "empty", "ungrouped"),
        ("count_if", "mixed", "ungrouped"),
        ("last", "normal", "grouped"),
        ("first", "mixed", "grouped"),
    ] {
        let kind = match name {
            "array" => AccumulatorKind::ArrayAgg,
            "distinct" => AccumulatorKind::ArrayAggDistinct,
            "first" => AccumulatorKind::First,
            "last" => AccumulatorKind::Last,
            "count_if" => AccumulatorKind::CountIf,
            _ => unreachable!(),
        };
        let field_value = if name == "count_if" {
            Value::Boolean(true)
        } else {
            int(1)
        };
        let rows = match input {
            "empty" => vec![],
            "missing" => vec![doc("a", &[("g", int(1))])],
            "mixed" => vec![
                doc("a", &[("g", int(1)), ("v", field_value)]),
                doc("b", &[("g", int(1)), ("v", int(2))]),
            ],
            "normal" => vec![doc("a", &[("g", int(1)), ("v", field_value)])],
            _ => unreachable!(),
        };
        let groups = if grouping == "grouped" {
            vec![("g".to_owned(), field("g"))]
        } else {
            vec![]
        };
        let result = execute_rows_in(
            vec![Stage::Aggregate {
                accumulators: vec![("out".to_owned(), accumulate(kind, "v"))],
                groups,
            }],
            rows,
            Unrecorded::Refuse,
        );
        let should_fail = (input == "missing" && matches!(name, "first" | "last" | "count_if"))
            || (input == "mixed" && name == "count_if")
            || (input == "empty" && grouping == "ungrouped" && matches!(name, "first" | "last"));
        assert_eq!(
            result.is_err(),
            should_fail,
            "{name}/{input}/{grouping}: {result:?}"
        );
    }
}

#[test]
fn nested_sum_uses_actual_row_type() {
    let nested = Expr::call("sum", vec![field("n")], Placement::Value).unwrap();
    let stage = Stage::Aggregate {
        accumulators: vec![(
            "s".to_owned(),
            Accumulator {
                kind: AccumulatorKind::Sum,
                argument: Some(nested),
            },
        )],
        groups: vec![],
    };
    let run = |rows: Vec<Row>| {
        let mut cursor = Cursor::new(vec![stage.clone()]).with_recorded_nested_sum_wrong_type();
        for row in rows {
            cursor.push(row)?;
        }
        cursor.finish()
    };
    let row = doc("one", &[("n", int(7))]);
    assert!(matches!(
        execute_rows_in(vec![stage.clone()], vec![row.clone()], Unrecorded::Refuse),
        Err(EvalError::Unobserved { .. })
    ));
    let error = run(vec![row]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "The function array_sum(...) requires `Array` but got `LONG`."
    );
    assert!(run(vec![]).is_ok());
    assert!(run(vec![doc("one", &[("n", Value::Array(vec![int(7)]))])]).is_ok());
    assert!(matches!(
        run(vec![doc("one", &[("n", Value::String("x".to_owned()))])]),
        Err(EvalError::Unobserved { .. })
    ));
}

proptest! {
    #[test]
    fn nested_sum_long_requires_admission(value in any::<i64>(), admitted in any::<bool>(), ordinary in any::<bool>()) {
        let nested = Expr::call("sum", vec![field("n")], Placement::Value).unwrap();
        let stage = Stage::Aggregate {
            accumulators: vec![("s".to_owned(), Accumulator { kind: AccumulatorKind::Sum, argument: Some(nested) })],
            groups: vec![],
        };
        let mode = if ordinary { Unrecorded::OfficialEmulator } else { Unrecorded::Refuse };
        let mut cursor = Cursor::new_in(vec![stage], mode);
        if admitted {
            cursor = cursor.with_recorded_nested_sum_wrong_type();
        }
        cursor.push(doc("one", &[("n", int(value))])).unwrap();
        let result = cursor.finish();
        if admitted {
            prop_assert!(matches!(result, Err(EvalError::WrongType { function: "array_sum", expected: "Array", got: "LONG" })), "expected recorded type refusal");
        } else {
            prop_assert!(matches!(result, Err(EvalError::Unobserved { function: "sum", .. })), "expected unobserved fallback");
        }
    }
}

#[test]
fn admitted_nested_sum_evaluates_child_once() {
    let rand = Expr::call("rand", vec![], Placement::Value).unwrap();
    let nested = Expr::call("sum", vec![rand], Placement::Value).unwrap();
    let stage = Stage::Aggregate {
        accumulators: vec![(
            "s".to_owned(),
            Accumulator {
                kind: AccumulatorKind::Sum,
                argument: Some(nested),
            },
        )],
        groups: vec![],
    };
    let rng = std::sync::Arc::new(std::sync::Mutex::new(SplitMix64::new(42)));
    let runtime = RuntimeContext {
        expr_rng: Some(rng.clone()),
        ..RuntimeContext::default()
    };
    let mut cursor = Cursor::new_in_with_runtime(vec![stage], Unrecorded::Refuse, runtime)
        .with_recorded_nested_sum_wrong_type();
    cursor.push(doc("one", &[])).unwrap();
    assert!(matches!(cursor.finish(), Err(EvalError::Unobserved { .. })));
    let mut expected = SplitMix64::new(42);
    expected.next_u64();
    assert_eq!(rng.lock().unwrap().next_u64(), expected.next_u64());
}
