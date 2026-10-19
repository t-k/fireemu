// Test fixtures index small row counts; the casts cannot wrap.
#![allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]

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

fn row(relative: &str, fields: &[(&str, Value)]) -> Row {
    Row {
        path: path(relative),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    }
}

fn field(p: &str) -> Expr {
    Expr::Field(FieldPath::parse(p).unwrap())
}

fn call(name: &str, args: Vec<Expr>) -> Expr {
    Expr::call(name, args, Placement::Value).unwrap()
}

fn condition(name: &str, args: Vec<Expr>) -> Expr {
    Expr::call(name, args, Placement::Condition).unwrap()
}

fn alias(path: &str) -> FieldPath {
    FieldPath::parse(path).unwrap()
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

fn unobserved(e: &Eval) -> bool {
    matches!(e, Eval::Error(EvalError::Unobserved { .. }))
}

#[test]
fn table_lists_exactly_the_px0_functions() {
    let names: Vec<_> = FUNCTIONS.iter().map(|f| f.name).collect();
    assert_eq!(names, ["equal", "document_id", "collection_id", "parent"]);
    assert_eq!(function("equal").unwrap().arity, 2);
    assert_eq!(function("equal").unwrap().placement, Placement::Condition);
    for name in ["document_id", "collection_id", "parent"] {
        assert_eq!(function(name).unwrap().arity, 1, "{name}");
        assert_eq!(
            function(name).unwrap().placement,
            Placement::Value,
            "{name}"
        );
    }
    for name in ["eq", "less_than", "abs", "and", "", "Equal"] {
        assert!(function(name).is_none(), "{name}");
    }
}

#[test]
fn call_refuses_unknown_misplaced_and_misarity_functions() {
    assert!(matches!(
        Expr::call("abs", vec![field("a")], Placement::Value),
        Err(ExprError::Unsupported(m)) if m.contains("abs")
    ));
    assert!(matches!(
        Expr::call("abs", vec![field("a")], Placement::Condition),
        Err(ExprError::Unsupported(_))
    ));
    // A condition-only function is refused where a value is expected.
    assert!(matches!(
        Expr::call("equal", vec![field("a"), Expr::Constant(Value::Integer(1))], Placement::Value),
        Err(ExprError::Unsupported(m)) if m.contains("equal")
    ));
    // A value function is accepted as a condition position too (its result is then checked
    // at run time), but not with the wrong arity.
    assert!(Expr::call("document_id", vec![field("__name__")], Placement::Condition).is_ok());
    for (name, args) in [
        ("equal", vec![]),
        ("equal", vec![field("a")]),
        ("equal", vec![field("a"), field("b"), field("c")]),
        ("document_id", vec![]),
        ("parent", vec![field("a"), field("b")]),
    ] {
        let placement = function(name).unwrap().placement;
        assert!(
            matches!(Expr::call(name, args.clone(), placement), Err(ExprError::Invalid(m)) if m.contains(name)),
            "{name}/{}",
            args.len()
        );
    }
}

#[test]
fn field_references_resolve_nested_paths_and_document_name() {
    let r = row(
        "c/x",
        &[
            (
                "a",
                Value::Map([("b".to_owned(), Value::Integer(3))].into()),
            ),
            ("top", s("t")),
            ("scalar", Value::Integer(1)),
        ],
    );
    assert_eq!(field("top").eval(&r), Eval::Value(s("t")));
    assert_eq!(field("a.b").eval(&r), Eval::Value(Value::Integer(3)));
    assert_eq!(field("a.missing").eval(&r), Eval::Absent);
    assert_eq!(field("missing").eval(&r), Eval::Absent);
    // A path through a non-map is absent, not an error.
    assert_eq!(field("scalar.b").eval(&r), Eval::Absent);
    assert_eq!(
        field("__name__").eval(&r),
        Eval::Value(Value::Reference(
            "projects/p/databases/(default)/documents/c/x".to_owned()
        ))
    );
    assert_eq!(
        Expr::Constant(Value::Null).eval(&r),
        Eval::Value(Value::Null)
    );
}

#[test]
fn document_functions_split_the_reference() {
    let r = row("c/x/sub/y", &[]);
    assert_eq!(
        call("document_id", vec![field("__name__")]).eval(&r),
        Eval::Value(s("y"))
    );
    assert_eq!(
        call("collection_id", vec![field("__name__")]).eval(&r),
        Eval::Value(s("sub"))
    );
    assert_eq!(
        call("parent", vec![field("__name__")]).eval(&r),
        Eval::Value(Value::Reference(
            "projects/p/databases/(default)/documents/c/x".to_owned()
        ))
    );
    let nested = call("document_id", vec![call("parent", vec![field("__name__")])]);
    assert_eq!(nested.eval(&r), Eval::Value(s("x")));
    let top = row(
        "c/x",
        &[(
            "ref",
            Value::Reference("projects/q/databases/d/documents/o/z".into()),
        )],
    );
    assert_eq!(
        call("document_id", vec![field("__name__")]).eval(&top),
        Eval::Value(s("x"))
    );
    assert_eq!(
        call("collection_id", vec![field("__name__")]).eval(&top),
        Eval::Value(s("c"))
    );
    // A stored reference into another database still splits.
    assert_eq!(
        call("document_id", vec![field("ref")]).eval(&top),
        Eval::Value(s("z"))
    );
    assert_eq!(
        call("collection_id", vec![field("ref")]).eval(&top),
        Eval::Value(s("o"))
    );
}

#[test]
fn document_functions_refuse_unobserved_inputs() {
    let r = row(
        "c/x",
        &[
            ("str", s("c/x")),
            ("null", Value::Null),
            (
                "collection",
                Value::Reference("projects/p/databases/(default)/documents/c".into()),
            ),
        ],
    );
    for name in ["document_id", "collection_id", "parent"] {
        for arg in ["missing", "str", "null", "collection"] {
            let e = call(name, vec![field(arg)]).eval(&r);
            assert!(unobserved(&e), "{name}({arg}) = {e:?}");
        }
    }
    // The parent of a top-level document is unrecorded.
    assert!(unobserved(
        &call("parent", vec![field("__name__")]).eval(&r)
    ));
    // An error argument propagates unchanged.
    let inner = call("parent", vec![field("__name__")]).eval(&r);
    assert_eq!(
        call("document_id", vec![call("parent", vec![field("__name__")])]).eval(&r),
        inner
    );
}

#[test]
fn equal_is_three_valued() {
    let r = row(
        "c/x",
        &[("n", Value::Integer(7)), ("nan", Value::Double(f64::NAN))],
    );
    let eq = |a: Expr, b: Expr| condition("equal", vec![a, b]).eval(&r);
    let k = |v: Value| Expr::Constant(v);
    assert_eq!(
        eq(field("n"), k(Value::Integer(7))),
        Eval::Value(Value::Boolean(true))
    );
    assert_eq!(
        eq(field("n"), k(Value::Double(7.0))),
        Eval::Value(Value::Boolean(true))
    );
    assert_eq!(
        eq(field("n"), k(Value::Integer(8))),
        Eval::Value(Value::Boolean(false))
    );
    assert_eq!(
        eq(field("n"), k(s("7"))),
        Eval::Value(Value::Boolean(false))
    );
    assert_eq!(
        eq(field("nan"), k(Value::Double(f64::NAN))),
        Eval::Value(Value::Boolean(true))
    );
    assert_eq!(
        eq(field("n"), k(Value::Double(f64::NAN))),
        Eval::Value(Value::Boolean(false))
    );
    assert_eq!(eq(field("missing"), k(Value::Integer(7))), Eval::Absent);
    assert_eq!(eq(k(Value::Integer(7)), field("missing")), Eval::Absent);
    // An error wins over absent and values, on either side.
    let error = call("parent", vec![field("__name__")]);
    assert!(unobserved(&eq(error.clone(), k(Value::Integer(7)))));
    assert!(unobserved(&eq(field("missing"), error.clone())));
    assert!(unobserved(&eq(error, field("missing"))));
}

#[test]
fn values_equal_edges() {
    assert!(values_equal(&Value::Null, &Value::Null));
    assert!(!values_equal(&Value::Null, &Value::Boolean(false)));
    assert!(values_equal(&Value::Double(0.0), &Value::Double(-0.0)));
    assert!(values_equal(&Value::Integer(0), &Value::Double(-0.0)));
    assert!(values_equal(
        &Value::Double(f64::NAN),
        &Value::Double(f64::NAN)
    ));
    assert!(!values_equal(&Value::Double(f64::NAN), &Value::Integer(0)));
    assert!(!values_equal(&Value::Integer(0), &Value::Double(f64::NAN)));
    assert!(values_equal(
        &Value::Double(f64::INFINITY),
        &Value::Double(f64::INFINITY)
    ));
    assert!(!values_equal(&s("a"), &Value::Bytes(b"a".to_vec())));
}

fn rows(n: usize) -> Vec<Row> {
    (0..n)
        .map(|i| row(&format!("c/{i:03}"), &[("i", Value::Integer(i as i64))]))
        .collect()
}

fn ids(out: &[BTreeMap<String, Value>]) -> Vec<i64> {
    out.iter()
        .map(|f| match f.get("i") {
            Some(Value::Integer(i)) => *i,
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn where_keeps_true_drops_false_and_absent_and_refuses_errors() {
    let input = vec![
        row("c/a", &[("k", s("keep"))]),
        row("c/b", &[("k", s("drop"))]),
        row("c/c", &[]),
    ];
    let keep = condition("equal", vec![field("k"), Expr::Constant(s("keep"))]);
    let out = execute(vec![Stage::Where(keep)], input.clone()).unwrap();
    assert_eq!(out, vec![input[0].fields.clone()]);
    let error = condition(
        "equal",
        vec![
            call("parent", vec![field("__name__")]),
            Expr::Constant(s("x")),
        ],
    );
    assert!(matches!(
        execute(vec![Stage::Where(error)], input.clone()),
        Err(EvalError::Unobserved {
            function: "parent",
            ..
        })
    ));
    // A non-boolean condition is unrecorded.
    let value = call("document_id", vec![field("__name__")]);
    assert!(matches!(
        execute(vec![Stage::Where(value)], input),
        Err(EvalError::Unobserved {
            function: "where",
            ..
        })
    ));
}

#[test]
fn select_projects_aliases_and_omits_absent_values() {
    let input = vec![row(
        "c/x/s/y",
        &[
            (
                "a",
                Value::Map([("b".to_owned(), Value::Integer(3))].into()),
            ),
            ("other", s("dropped")),
        ],
    )];
    let out = execute(
        vec![Stage::Select(vec![
            (alias("nested"), field("a.b")),
            (alias("gone"), field("a.zzz")),
            (alias("id"), call("document_id", vec![field("__name__")])),
            (
                alias("coll"),
                call("collection_id", vec![field("__name__")]),
            ),
            (alias("up"), call("parent", vec![field("__name__")])),
        ])],
        input.clone(),
    )
    .unwrap();
    let expected: BTreeMap<String, Value> = [
        ("nested".to_owned(), Value::Integer(3)),
        ("id".to_owned(), s("y")),
        ("coll".to_owned(), s("s")),
        (
            "up".to_owned(),
            Value::Reference("projects/p/databases/(default)/documents/c/x".to_owned()),
        ),
    ]
    .into();
    assert_eq!(out, vec![expected]);
    assert!(execute(
        vec![Stage::Select(vec![(
            alias("up"),
            call("parent", vec![field("__name__")])
        )])],
        vec![row("c/x", &[])]
    )
    .is_err());
}

#[test]
fn offset_and_limit_count_rows_once() {
    let out = execute(vec![Stage::Offset(2), Stage::Limit(3)], rows(10)).unwrap();
    assert_eq!(ids(&out), [2, 3, 4]);
    let out = execute(vec![Stage::Limit(3), Stage::Offset(2)], rows(10)).unwrap();
    assert_eq!(ids(&out), [2]);
    assert!(execute(vec![Stage::Limit(0)], rows(3)).unwrap().is_empty());
    assert_eq!(
        ids(&execute(vec![Stage::Offset(0)], rows(3)).unwrap()),
        [0, 1, 2]
    );
    assert!(execute(vec![Stage::Offset(5)], rows(3)).unwrap().is_empty());
}

#[test]
fn cursor_reports_exhaustion_only_when_a_limit_is_used_up() {
    let mut cursor = Cursor::new(vec![Stage::Offset(1), Stage::Limit(1)]);
    assert!(!cursor.is_exhausted());
    let mut input = rows(3).into_iter();
    assert_eq!(cursor.push(input.next().unwrap()).unwrap(), None);
    assert!(!cursor.is_exhausted());
    assert!(cursor.push(input.next().unwrap()).unwrap().is_some());
    assert!(cursor.is_exhausted());
    assert_eq!(cursor.push(input.next().unwrap()).unwrap(), None);
    assert!(Cursor::new(vec![Stage::Limit(0)]).is_exhausted());
    assert!(!Cursor::new(vec![Stage::Offset(0)]).is_exhausted());
    assert!(!Cursor::new(vec![]).is_exhausted());
    // Without stages a row comes out unchanged.
    let r = row("c/x", &[("k", s("v"))]);
    assert_eq!(Cursor::new(vec![]).push(r.clone()).unwrap(), Some(r.fields));
}

#[test]
fn execute_stops_reading_after_the_limit() {
    // The third row would fail the where stage; the limit stops before it is read.
    let mut input = rows(2);
    input.push(row("c/zzz", &[]));
    let error = condition(
        "equal",
        vec![
            call("document_id", vec![field("i")]),
            Expr::Constant(s("x")),
        ],
    );
    let guarded = vec![
        Stage::Limit(2),
        Stage::Where(condition("equal", vec![field("i"), field("i")])),
    ];
    assert_eq!(ids(&execute(guarded, input.clone()).unwrap()), [0, 1]);
    assert!(execute(vec![Stage::Where(error)], input).is_err());
}

fn scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Boolean),
        (-3_i64..3).prop_map(Value::Integer),
        prop_oneof![
            Just(f64::NAN),
            Just(f64::INFINITY),
            Just(-0.0),
            Just(0.0),
            Just(1.0),
            Just(1.5),
            Just(-2.0)
        ]
        .prop_map(Value::Double),
        "[ab]{0,2}".prop_map(Value::String),
        prop::collection::vec(0_u8..3, 0..2).prop_map(Value::Bytes),
    ]
}

proptest! {
    #[test]
    fn values_equal_is_symmetric_reflexive_and_matches_canonical_order(a in scalar(), b in scalar()) {
        prop_assert_eq!(values_equal(&a, &b), values_equal(&b, &a));
        prop_assert!(values_equal(&a, &a));
        let nan = |v: &Value| matches!(v, Value::Double(d) if d.is_nan());
        if !nan(&a) && !nan(&b) {
            prop_assert_eq!(values_equal(&a, &b), a.canonical_cmp(&b) == Ordering::Equal);
        } else {
            prop_assert_eq!(values_equal(&a, &b), nan(&a) && nan(&b));
        }
    }

    #[test]
    fn equal_condition_matches_values_equal_or_absent(stored in prop::option::of(scalar()), literal in scalar()) {
        let fields: Vec<(&str, Value)> = stored.iter().map(|v| ("f", v.clone())).collect();
        let r = row("c/x", &fields);
        let got = Expr::call("equal", vec![field("f"), Expr::Constant(literal.clone())], Placement::Condition)
            .unwrap()
            .eval(&r);
        match stored {
            None => prop_assert_eq!(got, Eval::Absent),
            Some(v) => prop_assert_eq!(got, Eval::Value(Value::Boolean(values_equal(&v, &literal)))),
        }
    }

    #[test]
    fn offset_and_limit_match_slicing(n in 0_usize..12, offset in 0_u64..14, limit in 0_u64..14, second in 0_u64..14) {
        let all: Vec<i64> = (0..n as i64).collect();
        let start = (offset as usize).min(n);
        let end = start.saturating_add(limit as usize).min(n);
        let out = execute(vec![Stage::Offset(offset), Stage::Limit(limit)], rows(n)).unwrap();
        prop_assert_eq!(ids(&out), all[start..end].to_vec());
        // Two limits are the smaller one; two offsets add up.
        let twice = execute(vec![Stage::Limit(limit), Stage::Limit(second)], rows(n)).unwrap();
        let once = execute(vec![Stage::Limit(limit.min(second))], rows(n)).unwrap();
        prop_assert_eq!(twice, once);
        let twice = execute(vec![Stage::Offset(offset), Stage::Offset(second)], rows(n)).unwrap();
        let once = execute(vec![Stage::Offset(offset + second)], rows(n)).unwrap();
        prop_assert_eq!(twice, once);
    }

    #[test]
    fn where_then_select_equals_filtering_then_projecting(values in prop::collection::vec(prop::option::of(scalar()), 0..8), literal in scalar()) {
        let input: Vec<Row> = values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let mut fields = vec![("i", Value::Integer(i as i64))];
                if let Some(v) = v {
                    fields.push(("f", v.clone()));
                }
                row(&format!("c/{i:03}"), &fields)
            })
            .collect();
        let cond = Expr::call("equal", vec![field("f"), Expr::Constant(literal.clone())], Placement::Condition).unwrap();
        let out = execute(
            vec![Stage::Where(cond), Stage::Select(vec![(alias("copy"), field("f")), (alias("id"), call("document_id", vec![field("__name__")]))])],
            input.clone(),
        )
        .unwrap();
        let expected: Vec<BTreeMap<String, Value>> = input
            .iter()
            .filter(|r| r.fields.get("f").is_some_and(|v| values_equal(v, &literal)))
            .map(|r| {
                [
                    ("copy".to_owned(), r.fields["f"].clone()),
                    ("id".to_owned(), Value::String(r.path.document_id().as_str().to_owned())),
                ]
                .into()
            })
            .collect();
        prop_assert_eq!(out.len(), expected.len());
        for (got, want) in out.iter().zip(&expected) {
            prop_assert_eq!(got.keys().collect::<Vec<_>>(), want.keys().collect::<Vec<_>>());
            for (k, v) in want {
                prop_assert!(values_equal(&got[k], v));
            }
        }
    }
}

#[test]
fn referenced_fields_cover_every_stage_once_a_select_narrows_the_row() {
    let paths = |ps: &[&str]| {
        ps.iter()
            .map(|p| FieldPath::parse(p).unwrap())
            .collect::<Vec<_>>()
    };
    // Without a select every field reaches the output.
    assert_eq!(
        referenced_fields(&[
            Stage::Where(condition(
                "equal",
                vec![field("a"), Expr::Constant(Value::Integer(1))]
            )),
            Stage::Limit(1)
        ]),
        None
    );
    assert_eq!(referenced_fields(&[]), None);
    // A select keeps what the select and every earlier condition read, minimal and sorted.
    let stages = [
        Stage::Where(condition(
            "equal",
            vec![field("w.x"), Expr::Constant(Value::Integer(1))],
        )),
        Stage::Select(vec![
            (alias("one"), field("a.b")),
            (alias("two"), field("a")),
            (alias("three"), field("w.x")),
            (alias("id"), call("document_id", vec![field("__name__")])),
            (alias("ref"), call("collection_id", vec![field("r")])),
        ]),
        Stage::Offset(1),
    ];
    assert_eq!(
        referenced_fields(&stages),
        Some(paths(&["__name__", "a", "r", "w.x"]))
    );
    // Only document functions: the scan needs no field, so it reads names only.
    let names_only = [Stage::Select(vec![(
        alias("id"),
        call("document_id", vec![field("__name__")]),
    )])];
    assert_eq!(referenced_fields(&names_only), Some(paths(&["__name__"])));
    let constant = [Stage::Select(vec![(
        alias("c"),
        call("document_id", vec![Expr::Constant(Value::Null)]),
    )])];
    assert_eq!(referenced_fields(&constant), Some(paths(&["__name__"])));
}

#[test]
fn errors_and_functions_describe_themselves() {
    let error = EvalError::Unobserved {
        function: "parent",
        reason: "a top-level document has no parent document",
    };
    assert_eq!(
        error.to_string(),
        "parent: a top-level document has no parent document; this behavior is not observed locally"
    );
    assert_eq!(
        ExprError::Unsupported("function \"abs\" is unsupported locally".into()).to_string(),
        "function \"abs\" is unsupported locally"
    );
    assert_eq!(
        ExprError::Invalid("function \"equal\" takes 2 argument(s), got 1".into()).to_string(),
        "function \"equal\" takes 2 argument(s), got 1"
    );
    let debug = format!("{:?}", function("document_id").unwrap());
    assert!(
        debug.contains("\"document_id\"") && debug.contains("arity: 1") && debug.contains("Value"),
        "{debug}"
    );
    // Calls compare by function and arguments.
    assert_eq!(
        call("document_id", vec![field("__name__")]),
        call("document_id", vec![field("__name__")])
    );
    assert_ne!(
        call("document_id", vec![field("__name__")]),
        call("collection_id", vec![field("__name__")])
    );
    assert_ne!(
        call("document_id", vec![field("__name__")]),
        call("document_id", vec![field("a")])
    );
}

#[test]
fn document_functions_name_why_an_input_is_unobserved() {
    let r = row("c/x", &[("str", s("c/x"))]);
    let reason = |name: &str, arg: Expr| match call(name, vec![arg]).eval(&r) {
        Eval::Error(EvalError::Unobserved { function, reason }) => {
            assert_eq!(function, name);
            reason
        }
        other => panic!("{name}: {other:?}"),
    };
    for name in ["document_id", "collection_id", "parent"] {
        assert_eq!(reason(name, field("missing")), "the argument is absent");
        assert_eq!(
            reason(name, field("str")),
            "the argument is not a document reference"
        );
        assert_eq!(
            reason(
                name,
                Expr::Constant(Value::Reference(
                    "projects/p/databases/(default)/documents/c".into()
                ))
            ),
            "the reference does not name a document"
        );
    }
    assert_eq!(
        reason("parent", field("__name__")),
        "a top-level document has no parent document"
    );
    // A reference constant names its document.
    assert_eq!(
        call(
            "document_id",
            vec![Expr::Constant(Value::Reference(
                "projects/p/databases/(default)/documents/o/z".into()
            ))]
        )
        .eval(&r),
        Eval::Value(s("z"))
    );
}

/// The official emulator (firebase-tools 15.28.2, Enterprise) answers null for a document
/// function of a missing or null value and the database root for the parent of a top-level
/// document, and refuses other types; the emulator profile follows it, strict refuses all.
#[test]
fn the_official_emulator_answers_replace_unobserved_errors_only_where_it_answers() {
    let r = row(
        "c/x",
        &[
            ("str", s("c/x")),
            ("null", Value::Null),
            ("num", Value::Integer(1)),
        ],
    );
    let official = |e: &Expr| e.eval_in(&r, Unrecorded::OfficialEmulator);
    for name in ["document_id", "collection_id", "parent"] {
        for arg in ["missing", "null"] {
            let e = call(name, vec![field(arg)]);
            assert_eq!(official(&e), Eval::Value(Value::Null), "{name}({arg})");
            assert!(unobserved(&e.eval(&r)), "{name}({arg})");
            assert!(
                unobserved(&e.eval_in(&r, Unrecorded::Refuse)),
                "{name}({arg})"
            );
        }
        for arg in ["str", "num"] {
            assert!(
                unobserved(&official(&call(name, vec![field(arg)]))),
                "{name}({arg})"
            );
        }
    }
    let root = Value::Reference("projects/p/databases/(default)/documents".to_owned());
    let top_parent = call("parent", vec![field("__name__")]);
    assert_eq!(official(&top_parent), Eval::Value(root));
    assert!(unobserved(&top_parent.eval(&r)));
    // The root names no document: the official emulator refuses its ID too.
    assert!(unobserved(&official(&call(
        "document_id",
        vec![top_parent.clone()]
    ))));
    assert!(unobserved(&official(&call(
        "collection_id",
        vec![top_parent]
    ))));
    // A subcollection document's parent is the same in both.
    let sub = row("c/x/s/y", &[]);
    let up = call("parent", vec![field("__name__")]);
    assert_eq!(
        up.eval_in(&sub, Unrecorded::OfficialEmulator),
        up.eval(&sub)
    );
    // Through a cursor: a null result compares unequal and is kept by select.
    let stages = vec![
        Stage::Where(condition(
            "equal",
            vec![
                call("document_id", vec![field("missing")]),
                Expr::Constant(Value::Null),
            ],
        )),
        Stage::Select(vec![(
            alias("id"),
            call("document_id", vec![field("missing")]),
        )]),
    ];
    let out = execute_in(
        stages.clone(),
        vec![r.clone()],
        Unrecorded::OfficialEmulator,
    )
    .unwrap();
    assert_eq!(out, vec![[("id".to_owned(), Value::Null)].into()]);
    assert!(execute(stages, vec![r]).is_err());
}

/// A select alias is a field path: a dotted alias nests its value, as the official emulator
/// answers `select('profile.score')` with `{profile: {score}}`. An absent value creates no
/// map on its way.
#[test]
fn select_aliases_are_field_paths() {
    let map = |entries: &[(&str, Value)]| {
        Value::Map(
            entries
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    };
    let input = vec![row(
        "c/x",
        &[
            (
                "profile",
                map(&[("score", Value::Integer(7)), ("rank", Value::Integer(2))]),
            ),
            ("top", s("t")),
        ],
    )];
    let out = execute(
        vec![Stage::Select(vec![
            (alias("x.y"), field("top")),
            (alias("m.s"), field("profile.score")),
            (alias("m.r"), field("profile.rank")),
            (alias("`q.r`"), field("top")),
            (alias("gone.deep"), field("missing")),
        ])],
        input,
    )
    .unwrap();
    let expected: BTreeMap<String, Value> = [
        ("x".to_owned(), map(&[("y", s("t"))])),
        (
            "m".to_owned(),
            map(&[("s", Value::Integer(7)), ("r", Value::Integer(2))]),
        ),
        ("q.r".to_owned(), s("t")),
    ]
    .into();
    assert_eq!(out, vec![expected]);
}
