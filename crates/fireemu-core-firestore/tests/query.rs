//! Query AST canonicalization and Standard query limits (spec 8.5, 8.10.4).

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::query::{
    Direction, FieldOp, FilterExpr, OrderClause, Query, QueryLimitViolation, QueryScope,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::CollectionId;

fn fp(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}

fn field(path: &str, op: FieldOp, v: Value) -> FilterExpr {
    FilterExpr::Field {
        field: fp(path),
        op,
        value: v,
    }
}

fn base() -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tasks").unwrap(),
    ))
}

#[test]
fn canonicalize_flattens_and_sorts_deterministically() {
    let q = base().with_filter(FilterExpr::And(vec![
        field("b", FieldOp::Equal, Value::Integer(2)),
        FilterExpr::And(vec![field("a", FieldOp::Equal, Value::Integer(1))]),
    ]));
    let c = q.canonicalize().unwrap();
    let again = c.canonicalize().unwrap();
    assert_eq!(c, again, "canonicalization is idempotent");
    match c.filter.as_ref().unwrap() {
        FilterExpr::And(children) => {
            assert_eq!(children.len(), 2);
            assert!(matches!(&children[0], FilterExpr::Field { field, .. } if field == &fp("a")));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn single_child_and_or_collapse() {
    let q = base().with_filter(FilterExpr::Or(vec![FilterExpr::And(vec![field(
        "a",
        FieldOp::Equal,
        Value::Null,
    )])]));
    let c = q.canonicalize().unwrap();
    assert!(matches!(c.filter, Some(FilterExpr::Field { .. })));
}

#[test]
fn dnf_disjunction_count_and_limit() {
    // (a in [1..6]) AND (b in [1..5]) AND (c == 1) = 30 disjunctions: allowed.
    let a = field(
        "a",
        FieldOp::In,
        Value::Array((1..=6).map(Value::Integer).collect()),
    );
    let b = field(
        "b",
        FieldOp::In,
        Value::Array((1..=5).map(Value::Integer).collect()),
    );
    let c = field("c", FieldOp::Equal, Value::Integer(1));
    let q = base().with_filter(FilterExpr::And(vec![a.clone(), b.clone(), c.clone()]));
    let canon = q.canonicalize().unwrap();
    assert_eq!(canon.dnf_disjunction_count(), 30);
    assert!(canon.check_standard_limits().is_ok());
    // 31 disjunctions: rejected.
    let a7 = field(
        "a",
        FieldOp::In,
        Value::Array((1..=7).map(Value::Integer).collect()),
    );
    let q = base().with_filter(FilterExpr::And(vec![a7, b, c]));
    let canon = q.canonicalize().unwrap();
    assert_eq!(canon.dnf_disjunction_count(), 35);
    let err = canon.check_standard_limits().unwrap_err();
    assert!(err
        .iter()
        .any(|v| v.limit_id == "FS-QUERY-LIMIT-DNF-DISJUNCTIONS" && v.current == 35));
}

#[test]
fn array_contains_rules_per_disjunction() {
    let ac1 = field(
        "tags",
        FieldOp::ArrayContains,
        Value::String("a".to_owned()),
    );
    let ac2 = field(
        "labels",
        FieldOp::ArrayContains,
        Value::String("b".to_owned()),
    );
    let any = field(
        "tags",
        FieldOp::ArrayContainsAny,
        Value::Array(vec![Value::String("c".to_owned())]),
    );
    let err = base()
        .with_filter(FilterExpr::And(vec![ac1.clone(), ac2.clone()]))
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .unwrap_err();
    assert!(err
        .iter()
        .any(|v| v.limit_id == "FS-QUERY-LIMIT-ARRAY-CONTAINS-PER-DISJUNCTION"));
    // Two array-contains in different disjunctions are fine.
    assert!(base()
        .with_filter(FilterExpr::Or(vec![ac1.clone(), ac2]))
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .is_ok());
    let err = base()
        .with_filter(FilterExpr::And(vec![ac1, any]))
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .unwrap_err();
    assert!(err
        .iter()
        .any(|v| v.limit_id == "FS-QUERY-LIMIT-ARRAY-CONTAINS-COMBINATION"));
}

#[test]
fn not_in_limits() {
    let ten = field(
        "a",
        FieldOp::NotIn,
        Value::Array((0..10).map(Value::Integer).collect()),
    );
    assert!(base()
        .with_filter(ten)
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .is_ok());
    let eleven = field(
        "a",
        FieldOp::NotIn,
        Value::Array((0..11).map(Value::Integer).collect()),
    );
    let err = base()
        .with_filter(eleven)
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .unwrap_err();
    assert!(err
        .iter()
        .any(|v| v.limit_id == "FS-QUERY-LIMIT-NOT-IN-VALUES" && v.current == 11));
    let combo = FilterExpr::And(vec![
        field("a", FieldOp::NotIn, Value::Array(vec![Value::Integer(1)])),
        field("b", FieldOp::NotEqual, Value::Integer(2)),
    ]);
    // The combination is structurally invalid in every edition (one negating filter per
    // query), so canonicalization refuses it before the catalog limit is consulted; the
    // catalog limit still describes the same query on its own.
    assert_eq!(
        base()
            .with_filter(combo.clone())
            .canonicalize()
            .unwrap_err(),
        fireemu_core_firestore::query::QueryError::MultipleNegations
    );
    let err = base()
        .with_filter(combo)
        .check_standard_limits()
        .unwrap_err();
    assert!(err
        .iter()
        .any(|v| v.limit_id == "FS-QUERY-LIMIT-NOT-IN-NEQ-COMBINATION"));
}

#[test]
fn inequality_field_count_limit() {
    let ten: Vec<FilterExpr> = (0..10)
        .map(|i| field(&format!("f{i}"), FieldOp::GreaterThan, Value::Integer(0)))
        .collect();
    assert!(base()
        .with_filter(FilterExpr::And(ten.clone()))
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .is_ok());
    let mut eleven = ten;
    eleven.push(field("f10", FieldOp::LessThan, Value::Integer(9)));
    let err = base()
        .with_filter(FilterExpr::And(eleven))
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .unwrap_err();
    assert!(err
        .iter()
        .any(|v| v.limit_id == "FS-QUERY-LIMIT-INEQUALITY-FIELDS" && v.current == 11));
    // The same field twice counts once.
    let same = FilterExpr::And(vec![
        field("f", FieldOp::GreaterThan, Value::Integer(0)),
        field("f", FieldOp::LessThan, Value::Integer(9)),
    ]);
    let c = base().with_filter(same).canonicalize().unwrap();
    assert_eq!(c.inequality_fields().len(), 1);
}

#[test]
fn component_count_includes_orders_and_parent_path() {
    // 98 equality filters + 1 order + parent document path (subcollection) = 100: allowed.
    let filters: Vec<FilterExpr> = (0..98)
        .map(|i| field(&format!("f{i}"), FieldOp::Equal, Value::Integer(i)))
        .collect();
    let parent = fireemu_core_firestore::path::DocumentPath::parse(
        &fireemu_core_types::ids::ProjectId::try_new("demo-app").unwrap(),
        &fireemu_core_types::ids::DatabaseId::default_database(),
        "users/u1",
    )
    .unwrap();
    let scope = QueryScope::collection(Some(parent), CollectionId::try_new("tasks").unwrap());
    let q = Query::new(scope.clone())
        .with_filter(FilterExpr::And(filters.clone()))
        .with_order(OrderClause {
            field: fp("z"),
            direction: Direction::Ascending,
        });
    let c = q.canonicalize().unwrap();
    assert_eq!(c.component_count().total, 100);
    assert!(c.check_standard_limits().is_ok());
    let mut more = filters;
    more.push(field("f98", FieldOp::Equal, Value::Integer(98)));
    let q = Query::new(scope)
        .with_filter(FilterExpr::And(more))
        .with_order(OrderClause {
            field: fp("z"),
            direction: Direction::Ascending,
        });
    let err = q
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .unwrap_err();
    let v: &QueryLimitViolation = err
        .iter()
        .find(|v| v.limit_id == "FS-QUERY-LIMIT-COMPONENTS")
        .unwrap();
    assert_eq!(v.current, 101);
}

#[test]
fn implicit_key_inequality_orders_last_but_explicit_key_order_is_not_rewritten() {
    let q = base().with_filter(FilterExpr::And(vec![
        field(
            "__name__",
            FieldOp::GreaterThan,
            Value::Reference("projects/demo-app/databases/(default)/documents/tasks/a".into()),
        ),
        field("amount", FieldOp::GreaterThan, Value::Integer(0)),
    ]));
    for direction in [Direction::Ascending, Direction::Descending] {
        let ordered = if direction == Direction::Descending {
            q.clone().with_order(OrderClause {
                field: fp("amount"),
                direction,
            })
        } else {
            q.clone()
        };
        assert_eq!(
            ordered.canonicalize().unwrap().effective_order_by(),
            vec![
                OrderClause {
                    field: fp("amount"),
                    direction
                },
                OrderClause {
                    field: fp("__name__"),
                    direction
                }
            ]
        );
    }
    assert!(q
        .with_order(OrderClause {
            field: fp("__name__"),
            direction: Direction::Ascending
        })
        .canonicalize()
        .is_err());
}

#[test]
fn effective_order_appends_inequality_fields_and_document_name() {
    let q = base()
        .with_filter(field("age", FieldOp::GreaterThan, Value::Integer(18)))
        .with_order(OrderClause {
            field: fp("name"),
            direction: Direction::Descending,
        });
    let c = q.canonicalize().unwrap();
    let eff = c.effective_order_by();
    let fields: Vec<String> = eff.iter().map(|o| o.field.canonical()).collect();
    // Explicit order first (name DESC), then the inequality field, then __name__ following the
    // last explicit direction.
    assert_eq!(fields, vec!["name", "age", "__name__"]);
    assert_eq!(eff[2].direction, Direction::Descending);
}

#[test]
fn in_and_array_contains_any_require_array_values() {
    let bad = base().with_filter(field("a", FieldOp::In, Value::Integer(1)));
    assert!(bad.canonicalize().is_err());
    let empty = base().with_filter(field("a", FieldOp::In, Value::Array(vec![])));
    assert!(empty.canonicalize().is_err());
}

#[test]
fn not_in_combination_rules() {
    use fireemu_core_firestore::query::QueryError;
    let arr = |n: i64| Value::Array((0..n).map(Value::Integer).collect());
    let two = FilterExpr::And(vec![
        field("a", FieldOp::NotIn, arr(2)),
        field("b", FieldOp::NotIn, arr(2)),
    ]);
    assert_eq!(
        base().with_filter(two).canonicalize().unwrap_err(),
        QueryError::MultipleNotIn
    );
    let with_in = FilterExpr::And(vec![
        field("a", FieldOp::NotIn, arr(2)),
        field("b", FieldOp::In, arr(2)),
    ]);
    assert_eq!(
        base().with_filter(with_in).canonicalize().unwrap_err(),
        QueryError::NotInWithDisjunction
    );
    let with_or = FilterExpr::Or(vec![
        field("a", FieldOp::NotIn, arr(2)),
        field("b", FieldOp::Equal, Value::Integer(1)),
    ]);
    assert_eq!(
        base().with_filter(with_or).canonicalize().unwrap_err(),
        QueryError::NotInWithDisjunction
    );
    let alone = field("a", FieldOp::NotIn, arr(2));
    assert!(base().with_filter(alone).canonicalize().is_ok());
}

#[test]
fn component_count_sums_every_filter_across_disjunctions() {
    let branch = |prefix: &str| {
        FilterExpr::And(
            (0..51)
                .map(|i| field(&format!("{prefix}{i}"), FieldOp::Equal, Value::Integer(i)))
                .collect(),
        )
    };
    let q = base().with_filter(FilterExpr::Or(vec![branch("a"), branch("b")]));
    let c = q.canonicalize().unwrap();
    assert_eq!(c.dnf_disjunction_count(), 2);
    assert_eq!(c.component_count().filters, 102);
    let err = c.check_standard_limits().unwrap_err();
    assert!(err
        .iter()
        .any(|v| v.limit_id == "FS-QUERY-LIMIT-COMPONENTS" && v.current == 102));
}

#[test]
fn oversized_dnf_is_rejected_without_materializing() {
    // 30^10 disjunctions: counted symbolically, never expanded.
    let filters: Vec<FilterExpr> = (0..10)
        .map(|i| {
            field(
                &format!("f{i}"),
                FieldOp::In,
                Value::Array((0..30).map(Value::Integer).collect()),
            )
        })
        .collect();
    let c = base()
        .with_filter(FilterExpr::And(filters))
        .canonicalize()
        .unwrap();
    assert_eq!(c.dnf_disjunction_count(), 30u64.pow(10));
    assert!(c.component_count().filters > 100);
    let err = c.check_standard_limits().unwrap_err();
    assert_eq!(err.len(), 1);
    assert_eq!(err[0].limit_id, "FS-QUERY-LIMIT-DNF-DISJUNCTIONS");
}
