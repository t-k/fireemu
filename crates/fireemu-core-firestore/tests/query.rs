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
    // Production answers the negation rule first (FS-QUERY-INDEX filter-validation).
    assert_eq!(
        base().with_filter(two).canonicalize().unwrap_err(),
        QueryError::MultipleNegations
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

// Cursor validation against the effective order-by (`O4-REPAIR-002`, `O4-REPAIR-003`).
//
// Reference, `google.firestore.v1.StructuredQuery`: a `Cursor` holds "the values that
// represent a position, in the order they appear in the order by clause of a query", and
// the `start_at` example starts a `SELECT * FROM k` query at `START BEFORE (2, /k/123)`,
// which is "right before `a = 1 AND b > 2 AND __name__ > /k/123`". The value standing in
// the `__name__` position is therefore a document reference, and it names a document of
// the collection the query selects.

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Cursor, QueryError};
use fireemu_core_types::ids::{DatabaseId, ProjectId};

fn document(relative: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        relative,
    )
    .unwrap()
}

fn reference(relative: &str) -> Value {
    Value::Reference(document(relative).resource_name())
}

fn cursor_scope() -> QueryScope {
    QueryScope::collection(
        Some(document("root/r1")),
        CollectionId::try_new("cur").unwrap(),
    )
}

fn name_order() -> OrderClause {
    OrderClause {
        field: FieldPath::document_name(),
        direction: Direction::Ascending,
    }
}

fn order(path: &str) -> OrderClause {
    OrderClause {
        field: fp(path),
        direction: Direction::Ascending,
    }
}

fn starting_at(query: Query, values: Vec<Value>) -> Query {
    Query {
        start_at: Some(Cursor {
            values,
            before: true,
        }),
        ..query
    }
}

fn cursor_error(query: &Query) -> QueryError {
    query
        .canonicalize()
        .expect("the cursor rules are checked after canonicalization")
        .check_production_cursor_constraints()
        .expect_err("the query must be refused")
}

fn cursor_accepted(query: &Query) {
    query
        .canonicalize()
        .expect("canonicalization accepts the query")
        .check_production_cursor_constraints()
        .expect("the cursor is well formed");
}

#[test]
fn a_cursor_value_in_the_document_name_slot_must_be_a_document_reference() {
    let query = starting_at(
        Query::new(cursor_scope()).with_order(name_order()),
        vec![Value::String("c3".to_owned())],
    );
    assert_eq!(
        cursor_error(&query),
        QueryError::CursorNameValue { position: 0 }
    );
}

#[test]
fn a_cursor_without_an_explicit_order_has_too_many_values() {
    // Production positions a cursor against the explicit order only; the implicit
    // `__name__` order takes no value (FS-QUERY-INDEX cursors, recorded 2026-09-24).
    let query = starting_at(Query::new(cursor_scope()), vec![Value::Integer(3)]);
    assert_eq!(
        query.canonicalize().unwrap_err(),
        QueryError::CursorArityMismatch {
            cursor: 1,
            order_by: 0
        }
    );
}

#[test]
fn a_cursor_value_in_the_document_name_slot_must_be_a_full_resource_name() {
    let query = starting_at(
        Query::new(cursor_scope()).with_order(name_order()),
        vec![Value::Reference("cur/c3".to_owned())],
    );
    // Not a resource name at all, so not production's collection-reference refusal
    // (cursors/names#name-collection-reference); it positions nothing.
    assert_eq!(
        cursor_error(&query),
        QueryError::CursorNameValue { position: 0 }
    );
}

#[test]
fn a_cursor_reference_in_a_sibling_collection_is_accepted() {
    // Production positions by any document of the database, inside the query's scope or
    // not (FS-QUERY-INDEX cursors/names, recorded 2026-09-24).
    cursor_accepted(&starting_at(
        Query::new(cursor_scope()).with_order(name_order()),
        vec![reference("root/r1/other/absent")],
    ));
}

#[test]
fn a_cursor_reference_under_another_parent_document_is_accepted() {
    // Production positions by any document of the database, inside the query's scope or
    // not (FS-QUERY-INDEX cursors/names, recorded 2026-09-24).
    cursor_accepted(&starting_at(
        Query::new(cursor_scope()).with_order(name_order()),
        vec![reference("root/r2/cur/c3")],
    ));
}

#[test]
fn a_cursor_reference_in_a_deeper_collection_of_the_same_name_is_accepted() {
    // Production positions by any document of the database, inside the query's scope or
    // not (FS-QUERY-INDEX cursors/names, recorded 2026-09-24).
    cursor_accepted(&starting_at(
        Query::new(cursor_scope()).with_order(name_order()),
        vec![reference("root/r1/cur/c3/cur/c9")],
    ));
}

#[test]
fn a_collection_group_cursor_may_name_any_document() {
    let scope = QueryScope::collection_group_under(
        Some(document("root/r1")),
        CollectionId::try_new("cur").unwrap(),
    );
    cursor_accepted(&starting_at(
        Query::new(scope.clone()).with_order(name_order()),
        vec![reference("root/r1/sub/s1/cur/c3")],
    ));
    cursor_accepted(&starting_at(
        Query::new(scope).with_order(name_order()),
        vec![reference("root/r1/other/x1")],
    ));
}

#[test]
fn a_cursor_reference_in_another_database_is_left_to_the_request_check() {
    // The request decoder refuses a cursor key outside the request's database (it knows the
    // database; a root-level scope does not), so the query itself accepts it.
    cursor_accepted(&starting_at(
        Query::new(cursor_scope()).with_order(name_order()),
        vec![Value::Reference(
            "projects/demo-app/databases/other/documents/root/r1/cur/c3".to_owned(),
        )],
    ));
}

#[test]
fn a_cursor_reference_in_another_project_is_left_to_the_request_check() {
    // The request decoder refuses a cursor key outside the request's database (it knows the
    // database; a root-level scope does not), so the query itself accepts it.
    cursor_accepted(&starting_at(
        Query::new(cursor_scope()).with_order(name_order()),
        vec![Value::Reference(
            "projects/other-app/databases/(default)/documents/root/r1/cur/c3".to_owned(),
        )],
    ));
}

#[test]
fn the_document_name_slot_is_checked_after_an_explicit_field_order() {
    // `ORDER BY n ASC, __name__ ASC`: the second cursor value stands in the `__name__` slot.
    let query = starting_at(
        Query::new(cursor_scope())
            .with_order(order("n"))
            .with_order(name_order()),
        vec![Value::Integer(3), Value::String("c3".to_owned())],
    );
    assert_eq!(
        cursor_error(&query),
        QueryError::CursorNameValue { position: 1 }
    );
}

#[test]
fn an_end_cursor_is_validated_like_a_start_cursor() {
    let query = Query {
        end_at: Some(Cursor {
            values: vec![Value::Integer(7)],
            before: false,
        }),
        ..Query::new(cursor_scope()).with_order(name_order())
    };
    assert_eq!(
        cursor_error(&query),
        QueryError::CursorNameValue { position: 0 }
    );
}

#[test]
fn more_cursor_values_than_order_fields_stay_refused() {
    // `ORDER BY n ASC` is one explicit field, so three values exceed the order.
    let query = starting_at(
        Query::new(cursor_scope()).with_order(order("n")),
        vec![
            Value::Integer(3),
            reference("root/r1/cur/c3"),
            Value::Integer(9),
        ],
    );
    assert_eq!(
        query.canonicalize().unwrap_err(),
        QueryError::CursorArityMismatch {
            cursor: 3,
            order_by: 1
        }
    );
}

#[test]
fn well_formed_document_and_value_cursors_stay_accepted() {
    // A document cursor naming a member of the queried collection.
    cursor_accepted(&starting_at(
        Query::new(cursor_scope()).with_order(name_order()),
        vec![reference("root/r1/cur/c3")],
    ));
    // A value cursor: position 0 is `n`, which carries no type rule. Firestore orders
    // across types, so a string in a numeric field's slot is a position, not an error.
    cursor_accepted(&starting_at(
        Query::new(cursor_scope()).with_order(order("n")),
        vec![Value::String("c3".to_owned())],
    ));
    // An explicit field and `__name__` ordering, both slots filled correctly.
    cursor_accepted(&starting_at(
        Query::new(cursor_scope())
            .with_order(order("n"))
            .with_order(name_order()),
        vec![Value::Integer(3), reference("root/r1/cur/c3")],
    ));
    // The `limitToLast(3)` shape: a descending order with a document cursor.
    let descending = Query {
        limit: Some(3),
        end_at: Some(Cursor {
            values: vec![reference("root/r1/cur/c3")],
            before: true,
        }),
        ..Query::new(cursor_scope()).with_order(OrderClause {
            field: FieldPath::document_name(),
            direction: Direction::Descending,
        })
    };
    cursor_accepted(&descending);
    // A root collection, whose scope carries no parent document.
    cursor_accepted(&starting_at(
        Query::new(QueryScope::collection(
            None,
            CollectionId::try_new("tasks").unwrap(),
        ))
        .with_order(name_order()),
        vec![reference("tasks/t1")],
    ));
    // No cursor at all.
    cursor_accepted(&Query::new(cursor_scope()).with_order(name_order()));
}

#[test]
fn a_root_collection_cursor_reference_may_name_another_collection() {
    cursor_accepted(&starting_at(
        Query::new(QueryScope::collection(
            None,
            CollectionId::try_new("tasks").unwrap(),
        ))
        .with_order(name_order()),
        vec![reference("other/o1")],
    ));
}

/// The refusals production makes and the official emulator does not are strict-profile
/// refusals only: the emulator profile may add no rejection
/// (`spec/compatibility/contract.json`). Each text is production's (FS-QUERY-INDEX rows named
/// per case).
#[test]
fn production_only_refusals_apply_to_the_strict_canonicalization_only() {
    use fireemu_core_firestore::query::{Cursor, UnaryOp};
    let reference =
        || Value::Reference("projects/p/databases/(default)/documents/tasks/a".to_owned());
    let kindless = || Query::new(QueryScope::kindless_all_descendants(None));
    let asc = |path: &str| OrderClause {
        field: fp(path),
        direction: Direction::Ascending,
    };
    let cases: Vec<(&str, Query, &str)> = vec![
        (
            // collection-group/scopes#kindless-with-filter
            "kindless filter",
            kindless().with_filter(field("n", FieldOp::Equal, Value::Integer(1))),
            "kind is required for filter: n",
        ),
        (
            // collection-group/scopes#kindless-name-descending
            "kindless order",
            kindless().with_order(OrderClause {
                field: FieldPath::document_name(),
                direction: Direction::Descending,
            }),
            "kind is required for all orders except __key__ ascending",
        ),
        (
            // order-by/basic#duplicate-field
            "duplicate order field",
            base()
                .with_order(asc("a"))
                .with_order(asc("b"))
                .with_order(asc("a")),
            "order by clause cannot contain duplicate fields a",
        ),
        (
            // filter-validation/operators-and-values#or-empty
            "empty or",
            base().with_filter(FilterExpr::Or(Vec::new())),
            "Composite filter must have at least one sub-filter.",
        ),
        (
            // filter-validation/paths-and-names#name-array-contains
            "name array-contains",
            base().with_filter(field("__name__", FieldOp::ArrayContains, reference())),
            "the name __key__ is reserved",
        ),
        (
            // unary-filters/all#is-null-name
            "name unary",
            base().with_filter(FilterExpr::Unary {
                field: FieldPath::document_name(),
                op: UnaryOp::IsNull,
            }),
            "__key__ filter value must be a Key",
        ),
        (
            // cursors/values: a cursor longer than the explicit order
            "cursor past the explicit order",
            {
                let mut q = base().with_filter(field("n", FieldOp::GreaterThan, Value::Integer(0)));
                q.start_at = Some(Cursor {
                    values: vec![Value::Integer(1)],
                    before: true,
                });
                q
            },
            "Cursor has too many values.",
        ),
    ];
    for (name, query, text) in cases {
        let error = query.canonicalize().expect_err(name);
        assert_eq!(error.to_string(), text, "{name}");
        assert!(
            query.canonicalize_emulator().is_ok(),
            "{name} under the emulator profile"
        );
    }
    // What both refuse: a cursor longer than the whole implied order, an empty in list.
    let mut long = base();
    long.start_at = Some(Cursor {
        values: vec![Value::Integer(1), Value::Integer(2)],
        before: true,
    });
    assert!(long.canonicalize().is_err());
    assert!(long.canonicalize_emulator().is_err());
    let empty_in = base().with_filter(field("n", FieldOp::In, Value::Array(Vec::new())));
    assert_eq!(
        empty_in.canonicalize().unwrap_err().to_string(),
        empty_in.canonicalize_emulator().unwrap_err().to_string()
    );
}

/// Duplicate order fields are found in one pass over a long order-by.
#[test]
fn a_long_order_by_is_checked_without_quadratic_work() {
    let mut query = base();
    for i in 0..200_000 {
        query = query.with_order(OrderClause {
            field: fp(&format!("f{i}")),
            direction: Direction::Ascending,
        });
    }
    let started = std::time::Instant::now();
    assert!(query.canonicalize().is_ok());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
}

/// A cursor reference that names a collection is refused in production's words
/// (cursors/names#name-collection-reference); another malformed reference is no document
/// reference either, but that text is not production's, so it is not reused.
#[test]
fn cursor_references_to_collections_and_malformed_names_are_told_apart() {
    use fireemu_core_firestore::query::Cursor;
    let at = |name: &str| {
        let mut q = base().with_order(OrderClause {
            field: FieldPath::document_name(),
            direction: Direction::Ascending,
        });
        q.start_at = Some(Cursor {
            values: vec![Value::Reference(name.to_owned())],
            before: true,
        });
        q.canonicalize()
            .unwrap()
            .check_production_cursor_constraints()
            .unwrap_err()
            .to_string()
    };
    let collection = "projects/p/databases/(default)/documents/qn";
    assert_eq!(
        at(collection),
        format!("Document parent name \"{collection}\" lacks \"/\" at index 43.")
    );
    for malformed in [
        "projects/p/databases/(default)/documents/qn//d",
        "projects/p/databases/(default)/documents/qn/d/",
        "projects/p/databases/(default)/documents",
    ] {
        assert_eq!(
            at(malformed),
            "Cursor __key__ value is not a document reference.",
            "{malformed}"
        );
    }
}

/// Production reports a value count before the other limits, in its words
/// (query-limits/not-in-and-inequalities#not-in-11, #inequality-fields-11); the later checks
/// still run, so the official emulator's own refusal of two array-contains filters is kept
/// (core review note).
#[test]
fn value_counts_come_first_and_do_not_hide_later_limits() {
    let values = |count: i64| Value::Array((0..count).map(Value::Integer).collect());
    let query = base().with_filter(FilterExpr::And(vec![
        field("n", FieldOp::NotIn, values(11)),
        field("t1", FieldOp::ArrayContains, Value::Integer(1)),
        field("t2", FieldOp::ArrayContains, Value::Integer(2)),
    ]));
    let violations = query
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .unwrap_err();
    assert_eq!(
        violations[0].message,
        "'NOT_IN' supports up to 10 comparison values."
    );
    assert!(
        violations.len() > 1,
        "the array-contains limit is still checked: {violations:?}"
    );
    let inequalities = base().with_filter(FilterExpr::And(
        (0..11)
            .map(|i| field(&format!("f{i}"), FieldOp::GreaterThan, Value::Integer(0)))
            .collect(),
    ));
    let violations = inequalities
        .canonicalize()
        .unwrap()
        .check_standard_limits()
        .unwrap_err();
    assert!(violations[0]
        .message
        .starts_with("The query contains 11 distinct inequality fields: ["));
    assert!(violations[0]
        .message
        .ends_with("]. A query may not have more than 10 distinct inequality fields."));
}
