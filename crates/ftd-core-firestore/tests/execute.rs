//! Query execution semantics: filters, missing fields, type restrictions, ordering, cursors,
//! limits, projections, collection groups, aggregations.

use std::collections::BTreeMap;

use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::query::{
    Cursor, Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope, UnaryOp,
};
use ftd_core_firestore::store::{Aggregation, FirestoreState, Write, WriteOp};
use ftd_core_firestore::value::Value;
use ftd_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use ftd_core_types::time::LogicalInstant;

fn path(p: &str) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        p,
    )
    .unwrap()
}
fn fp(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}
fn field(p: &str, op: FieldOp, v: Value) -> FilterExpr {
    FilterExpr::Field {
        field: fp(p),
        op,
        value: v,
    }
}
fn seeded() -> FirestoreState {
    let mut s = FirestoreState::new();
    let docs: Vec<(&str, Vec<(&str, Value)>)> = vec![
        (
            "tasks/t1",
            vec![
                ("priority", Value::Integer(1)),
                ("done", Value::Boolean(false)),
                (
                    "tags",
                    Value::Array(vec![Value::String("a".into()), Value::String("b".into())]),
                ),
                ("owner", Value::String("u1".into())),
            ],
        ),
        (
            "tasks/t2",
            vec![
                ("priority", Value::Integer(3)),
                ("done", Value::Boolean(true)),
                ("tags", Value::Array(vec![Value::String("b".into())])),
                ("owner", Value::String("u2".into())),
            ],
        ),
        (
            "tasks/t3",
            vec![
                ("priority", Value::Double(2.5)),
                ("done", Value::Boolean(false)),
                ("owner", Value::String("u1".into())),
                ("score", Value::Null),
            ],
        ),
        (
            "tasks/t4",
            vec![
                ("priority", Value::String("high".into())),
                ("done", Value::Boolean(false)),
            ],
        ),
        ("tasks/t5", vec![("done", Value::Boolean(true))]),
        (
            "users/u1/tasks/t9",
            vec![
                ("priority", Value::Integer(9)),
                ("done", Value::Boolean(false)),
            ],
        ),
    ];
    for (i, (p, f)) in docs.into_iter().enumerate() {
        let fields: BTreeMap<String, Value> =
            f.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
        s.commit(
            &[Write {
                op: WriteOp::Set {
                    path: path(p),
                    fields,
                    update_mask: None,
                },
                precondition: None,
                transforms: vec![],
            }],
            None,
            LogicalInstant::from_unix_seconds(1_000 + i64::try_from(i).unwrap()),
        )
        .unwrap();
    }
    s
}
fn tasks() -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tasks").unwrap(),
    ))
}
fn ids(s: &FirestoreState, q: &Query) -> Vec<String> {
    s.run_query(&q.canonicalize().unwrap(), None)
        .unwrap()
        .iter()
        .map(|d| d.path.document_id().as_str().to_owned())
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)]
fn equality_and_inequality_filters_respect_types_and_missing_fields() {
    let s = seeded();
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field("done", FieldOp::Equal, Value::Boolean(true)))
        ),
        vec!["t2", "t5"]
    );
    // Range filters only match numbers when the value is a number; strings and missing fields are excluded.
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field("priority", FieldOp::GreaterThan, Value::Integer(1)))
        ),
        vec!["t3", "t2"]
    );
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field(
                "priority",
                FieldOp::GreaterThanOrEqual,
                Value::Integer(1)
            ))
        ),
        vec!["t1", "t3", "t2"]
    );
    // != excludes documents without the field.
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field("priority", FieldOp::NotEqual, Value::Integer(3)))
        ),
        vec!["t1", "t3", "t4"]
    );
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field(
                "owner",
                FieldOp::In,
                Value::Array(vec![Value::String("u2".into()), Value::String("zz".into())])
            ))
        ),
        vec!["t2"]
    );
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field(
                "owner",
                FieldOp::NotIn,
                Value::Array(vec![Value::String("u1".into())])
            ))
        ),
        vec!["t2"]
    );
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field(
                "tags",
                FieldOp::ArrayContains,
                Value::String("b".into())
            ))
        ),
        vec!["t1", "t2"]
    );
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field(
                "tags",
                FieldOp::ArrayContainsAny,
                Value::Array(vec![Value::String("a".into()), Value::String("zz".into())])
            ))
        ),
        vec!["t1"]
    );
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(FilterExpr::Unary {
                field: fp("score"),
                op: UnaryOp::IsNull
            })
        ),
        vec!["t3"]
    );
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(FilterExpr::Unary {
                field: fp("score"),
                op: UnaryOp::IsNotNull
            })
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(FilterExpr::Or(vec![
                field("owner", FieldOp::Equal, Value::String("u2".into())),
                field("priority", FieldOp::Equal, Value::String("high".into()))
            ]))
        ),
        vec!["t2", "t4"]
    );
}

#[test]
fn ordering_cursors_limit_offset_and_projection() {
    let s = seeded();
    let by_priority_desc = tasks().with_order(OrderClause {
        field: fp("priority"),
        direction: Direction::Descending,
    });
    // Documents without `priority` are excluded; type order puts numbers before strings.
    assert_eq!(
        ids(&s, &by_priority_desc.clone()),
        vec!["t4", "t2", "t3", "t1"]
    );
    let mut limited = by_priority_desc.clone();
    limited.limit = Some(2);
    limited.offset = 1;
    assert_eq!(ids(&s, &limited), vec!["t2", "t3"]);
    let mut after = by_priority_desc.clone();
    after.start_at = Some(Cursor {
        values: vec![Value::Integer(3)],
        before: false,
    });
    assert_eq!(ids(&s, &after), vec!["t3", "t1"]);
    let mut at = by_priority_desc.clone();
    at.start_at = Some(Cursor {
        values: vec![Value::Integer(3)],
        before: true,
    });
    at.end_at = Some(Cursor {
        values: vec![Value::Double(2.5)],
        before: true,
    });
    assert_eq!(ids(&s, &at), vec!["t2"]);
    // Default ordering is by __name__.
    assert_eq!(ids(&s, &tasks()), vec!["t1", "t2", "t3", "t4", "t5"]);
    let mut projected = tasks();
    projected.projection = Some(vec![fp("done")]);
    let docs = s
        .run_query(&projected.canonicalize().unwrap(), None)
        .unwrap();
    assert!(docs.iter().all(|d| d.fields.keys().all(|k| k == "done")));
    let mut names_only = tasks();
    names_only.projection = Some(vec![FieldPath::document_name()]);
    assert!(s
        .run_query(&names_only.canonicalize().unwrap(), None)
        .unwrap()
        .iter()
        .all(|d| d.fields.is_empty()));
}

#[test]
fn collection_group_and_subcollection_scopes() {
    let s = seeded();
    let group = Query::new(QueryScope::collection_group(
        CollectionId::try_new("tasks").unwrap(),
    ))
    .with_filter(field("priority", FieldOp::GreaterThan, Value::Integer(2)));
    let mut found: Vec<String> = s
        .run_query(&group.canonicalize().unwrap(), None)
        .unwrap()
        .iter()
        .map(|d| d.path.relative())
        .collect();
    found.sort();
    assert_eq!(found, vec!["tasks/t2", "tasks/t3", "users/u1/tasks/t9"]);
    let sub = Query::new(QueryScope::collection(
        Some(path("users/u1")),
        CollectionId::try_new("tasks").unwrap(),
    ));
    assert_eq!(ids(&s, &sub), vec!["t9"]);
}

#[test]
fn aggregations_count_sum_avg() {
    let s = seeded();
    let q = tasks().canonicalize().unwrap();
    let r = s
        .run_aggregation(
            &q,
            &[
                Aggregation::Count { up_to: None },
                Aggregation::Sum(fp("priority")),
                Aggregation::Avg(fp("priority")),
            ],
            None,
        )
        .unwrap();
    assert_eq!(r[0], Value::Integer(5));
    // Only numeric values participate: 1 + 3 + 2.5 = 6.5 over 3 numeric documents.
    assert_eq!(r[1], Value::Double(6.5));
    assert_eq!(r[2], Value::Double(6.5 / 3.0));
    let capped = s
        .run_aggregation(&q, &[Aggregation::Count { up_to: Some(2) }], None)
        .unwrap();
    assert_eq!(capped[0], Value::Integer(2));
    let empty = tasks()
        .with_filter(field(
            "owner",
            FieldOp::Equal,
            Value::String("nobody".into()),
        ))
        .canonicalize()
        .unwrap();
    let r = s
        .run_aggregation(
            &empty,
            &[
                Aggregation::Count { up_to: None },
                Aggregation::Sum(fp("priority")),
                Aggregation::Avg(fp("priority")),
            ],
            None,
        )
        .unwrap();
    assert_eq!(r, vec![Value::Integer(0), Value::Integer(0), Value::Null]);
}

#[test]
fn snapshot_reads_by_version() {
    let mut s = seeded();
    let before = s.current_version();
    s.commit(
        &[Write {
            op: WriteOp::Delete {
                path: path("tasks/t1"),
            },
            precondition: None,
            transforms: vec![],
        }],
        None,
        LogicalInstant::from_unix_seconds(2_000),
    )
    .unwrap();
    assert_eq!(
        ids(
            &s,
            &tasks().with_filter(field("owner", FieldOp::Equal, Value::String("u1".into())))
        ),
        vec!["t3"]
    );
    let old: Vec<String> = s
        .run_query(
            &tasks()
                .with_filter(field("owner", FieldOp::Equal, Value::String("u1".into())))
                .canonicalize()
                .unwrap(),
            Some(before),
        )
        .unwrap()
        .iter()
        .map(|d| d.path.document_id().as_str().to_owned())
        .collect();
    assert_eq!(
        old,
        vec!["t1", "t3"],
        "reads at an older version see the deleted document"
    );
}

#[test]
fn not_in_with_a_null_candidate_matches_nothing() {
    let s = seeded();
    let q = tasks().with_filter(field(
        "priority",
        FieldOp::NotIn,
        Value::Array(vec![Value::Integer(1)]),
    ));
    // Missing fields and nulls never match not-in; every other typed value does. The result
    // is ordered by the implied inequality field (numbers before strings).
    assert_eq!(ids(&s, &q), vec!["t3", "t2", "t4"]);
    let with_null = tasks().with_filter(field(
        "priority",
        FieldOp::NotIn,
        Value::Array(vec![Value::Integer(1), Value::Null]),
    ));
    assert!(ids(&s, &with_null).is_empty());
}
