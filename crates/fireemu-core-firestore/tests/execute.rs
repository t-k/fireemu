//! Query execution semantics: filters, missing fields, type restrictions, ordering, cursors,
//! limits, projections, collection groups, aggregations.

use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{
    Cursor, Direction, DistanceMeasure, FieldOp, FilterExpr, FindNearest, OrderClause, Query,
    QueryScope, UnaryOp,
};
use fireemu_core_firestore::store::{Aggregation, FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

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

fn vector_state() -> FirestoreState {
    let mut state = FirestoreState::new();
    for (index, (id, vector)) in [
        ("near", vec![1.0, 0.0]),
        ("mid", vec![0.0, 1.0]),
        ("far", vec![-1.0, 0.0]),
    ]
    .into_iter()
    .enumerate()
    {
        let fields = [("embedding".to_owned(), Value::Vector(vector))]
            .into_iter()
            .collect();
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: path(&format!("items/{id}")),
                        fields,
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: vec![],
                }],
                None,
                LogicalInstant::from_unix_seconds(2_000 + i64::try_from(index).unwrap()),
            )
            .unwrap();
    }
    state
}

fn nearest(measure: DistanceMeasure, limit: u32) -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("items").unwrap(),
    ))
    .with_find_nearest(FindNearest {
        vector_field: fp("embedding"),
        query_vector: vec![1.0, 0.0],
        distance_measure: measure,
        limit,
        distance_result_field: Some(fp("distance")),
        distance_threshold: None,
    })
}

#[test]
fn nearest_vector_query_orders_euclidean_cosine_and_dot_product() {
    let state = vector_state();
    let ids_for = |query: Query| {
        state
            .run_query(&query.canonicalize().unwrap(), None)
            .unwrap()
            .into_iter()
            .map(|document| document.path.document_id().as_str().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids_for(nearest(DistanceMeasure::Euclidean, 3)),
        ["near", "mid", "far"]
    );
    assert_eq!(
        ids_for(nearest(DistanceMeasure::Cosine, 3)),
        ["near", "mid", "far"]
    );
    assert_eq!(
        ids_for(nearest(DistanceMeasure::DotProduct, 3)),
        ["near", "mid", "far"]
    );
}

#[test]
fn nearest_vector_query_excludes_wrong_dimensions_and_non_vectors_and_adds_distance() {
    let mut state = vector_state();
    for (id, value) in [
        ("wrong", Value::Vector(vec![1.0])),
        ("scalar", Value::Double(0.0)),
    ] {
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: path(&format!("items/{id}")),
                        fields: [("embedding".to_owned(), value)].into_iter().collect(),
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: vec![],
                }],
                None,
                LogicalInstant::from_unix_seconds(2_100),
            )
            .unwrap();
    }
    let query = nearest(DistanceMeasure::Euclidean, 1)
        .canonicalize()
        .unwrap();
    let before = state.current_version();
    let documents = state.run_query(&query, None).unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0].path.document_id().as_str(), "near");
    assert_eq!(documents[0].fields["distance"], Value::Double(0.0));
    assert_eq!(state.current_version(), before);
}

#[test]
fn nearest_projection_controls_synthesized_distance_field() {
    let state = vector_state();
    let mut without_distance = nearest(DistanceMeasure::Euclidean, 1);
    without_distance.projection = Some(vec![fp("embedding")]);
    let document = state
        .run_query(&without_distance.canonicalize().unwrap(), None)
        .unwrap()
        .pop()
        .unwrap();
    assert!(document.fields.contains_key("embedding"));
    assert!(!document.fields.contains_key("distance"));

    let mut with_distance = nearest(DistanceMeasure::Euclidean, 1);
    with_distance.projection = Some(vec![fp("distance")]);
    let document = state
        .run_query(&with_distance.canonicalize().unwrap(), None)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(document.fields.get("distance"), Some(&Value::Double(0.0)));
    assert!(!document.fields.contains_key("embedding"));
}

#[test]
fn nearest_distance_math_excludes_non_finite_results() {
    let mut state = FirestoreState::new();
    for (id, vector) in [
        ("finite", vec![f64::MAX, f64::MAX]),
        ("infinite", vec![f64::INFINITY, 0.0]),
    ] {
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: path(&format!("items/{id}")),
                        fields: [("embedding".to_owned(), Value::Vector(vector))]
                            .into_iter()
                            .collect(),
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: vec![],
                }],
                None,
                LogicalInstant::from_unix_seconds(2_200),
            )
            .unwrap();
    }
    let mut euclidean = nearest(DistanceMeasure::Euclidean, 10);
    euclidean.find_nearest.as_mut().unwrap().query_vector = vec![f64::MAX, f64::MAX];
    let documents = state
        .run_query(&euclidean.canonicalize().unwrap(), None)
        .unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0].path.document_id().as_str(), "finite");
    let Value::Double(euclidean_distance) = documents[0].fields["distance"] else {
        panic!("distance is not a double");
    };
    assert!(euclidean_distance.is_finite());

    let mut cosine = nearest(DistanceMeasure::Cosine, 10);
    cosine.find_nearest.as_mut().unwrap().query_vector = vec![f64::MAX, f64::MAX];
    let documents = state
        .run_query(&cosine.canonicalize().unwrap(), None)
        .unwrap();
    assert_eq!(documents.len(), 1);
    let Value::Double(cosine_distance) = documents[0].fields["distance"] else {
        panic!("distance is not a double");
    };
    assert!(cosine_distance.is_finite());
    assert!((0.0..=2.0).contains(&cosine_distance));
}

#[test]
fn nearest_projection_respects_nested_distance_field_masks_and_replaces_collisions() {
    let mut state = vector_state();
    state
        .commit(
            &[Write {
                op: WriteOp::Set {
                    path: path("items/near"),
                    fields: [
                        ("embedding".to_owned(), Value::Vector(vec![1.0, 0.0])),
                        (
                            "meta".to_owned(),
                            Value::Map(
                                [(
                                    "distance".to_owned(),
                                    Value::Map(
                                        [("raw".to_owned(), Value::String("stored".to_owned()))]
                                            .into_iter()
                                            .collect(),
                                    ),
                                )]
                                .into_iter()
                                .collect(),
                            ),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                    update_mask: None,
                },
                precondition: None,
                transforms: vec![],
            }],
            None,
            LogicalInstant::from_unix_seconds(3_000),
        )
        .unwrap();

    let mut ancestor = nearest(DistanceMeasure::Euclidean, 1);
    ancestor
        .find_nearest
        .as_mut()
        .unwrap()
        .distance_result_field = Some(fp("meta.distance"));
    ancestor.projection = Some(vec![fp("meta")]);
    let document = state
        .run_query(&ancestor.canonicalize().unwrap(), None)
        .unwrap()
        .pop()
        .unwrap();
    let Value::Map(meta) = &document.fields["meta"] else {
        panic!("ancestor projection should retain the map");
    };
    assert_eq!(meta["distance"], Value::Double(0.0));

    let mut exact = ancestor.clone();
    exact.projection = Some(vec![fp("meta.distance")]);
    let document = state
        .run_query(&exact.canonicalize().unwrap(), None)
        .unwrap()
        .pop()
        .unwrap();
    let Value::Map(meta) = &document.fields["meta"] else {
        panic!("nested projection should retain the parent map");
    };
    assert_eq!(meta["distance"], Value::Double(0.0));

    let mut descendant = ancestor;
    descendant.projection = Some(vec![fp("meta.distance.raw")]);
    let document = state
        .run_query(&descendant.canonicalize().unwrap(), None)
        .unwrap()
        .pop()
        .unwrap();
    let Value::Map(meta) = &document.fields["meta"] else {
        panic!("descendant projection should retain the parent map");
    };
    let Value::Map(distance) = &meta["distance"] else {
        panic!("descendant projection must not synthesize the scalar distance");
    };
    assert_eq!(distance["raw"], Value::String("stored".to_owned()));
}

#[test]
fn nearest_vector_query_limit_and_threshold_are_applied() {
    let state = vector_state();
    let mut query = nearest(DistanceMeasure::Euclidean, 3);
    query.find_nearest.as_mut().unwrap().distance_threshold = Some(1.1);
    query.find_nearest.as_mut().unwrap().limit = 1;
    let documents = state
        .run_query(&query.canonicalize().unwrap(), None)
        .unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0].path.document_id().as_str(), "near");
    assert!(nearest(DistanceMeasure::Euclidean, 0)
        .canonicalize()
        .is_err());
    assert!(nearest(DistanceMeasure::Euclidean, 1001)
        .canonicalize()
        .is_err());
}

#[test]
fn nearest_cosine_threshold_includes_small_distance_and_excludes_large_distance() {
    let mut query = nearest(DistanceMeasure::Cosine, 3);
    query.find_nearest.as_mut().unwrap().distance_threshold = Some(0.5);
    let documents = vector_state()
        .run_query(&query.canonicalize().unwrap(), None)
        .unwrap();
    let ids = documents
        .into_iter()
        .map(|document| document.path.document_id().as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["near"]);
}

#[test]
fn nearest_dot_product_threshold_includes_large_score_and_excludes_small_score() {
    let mut query = nearest(DistanceMeasure::DotProduct, 3);
    query.find_nearest.as_mut().unwrap().distance_threshold = Some(0.5);
    let documents = vector_state()
        .run_query(&query.canonicalize().unwrap(), None)
        .unwrap();
    let ids = documents
        .into_iter()
        .map(|document| document.path.document_id().as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["near"]);
}

#[test]
fn nearest_vector_query_retains_only_the_requested_top_k_candidates() {
    let mut state = FirestoreState::new();
    for index in 0..2_000 {
        let value = f64::from(i32::try_from(index).unwrap());
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: path(&format!("items/item-{index:04}")),
                        fields: [
                            ("embedding".to_owned(), Value::Vector(vec![value, 0.0])),
                            ("rank".to_owned(), Value::Integer(index)),
                        ]
                        .into_iter()
                        .collect(),
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: vec![],
                }],
                None,
                LogicalInstant::from_unix_seconds(4_000 + index),
            )
            .unwrap();
    }

    let query = nearest(DistanceMeasure::Euclidean, 1)
        .canonicalize()
        .unwrap();
    let (documents, query_stats) = state.run_query_with_stats(&query, None).unwrap();

    assert_eq!(documents.len(), 1);
    assert_eq!(query_stats.nearest_peak_candidates, 1);

    let mut huge_name_limit = nearest(DistanceMeasure::Euclidean, 1);
    huge_name_limit.limit = Some(i32::MAX as u32);
    let (documents, query_stats) = state
        .run_query_with_stats(&huge_name_limit.canonicalize().unwrap(), None)
        .unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(query_stats.peak_candidates, 0);
    assert_eq!(query_stats.nearest_peak_candidates, 1);

    let mut offset_query = nearest(DistanceMeasure::Euclidean, 1);
    offset_query.offset = 100;
    let (documents, query_stats) = state
        .run_query_with_stats(&offset_query.canonicalize().unwrap(), None)
        .unwrap();
    assert_eq!(documents[0].path.document_id().as_str(), "item-0100");
    assert_eq!(query_stats.peak_candidates, 0);
    assert_eq!(query_stats.nearest_peak_candidates, 1);

    let mut unbounded_explicit_order = nearest(DistanceMeasure::Euclidean, 1);
    unbounded_explicit_order.offset = 1;
    unbounded_explicit_order.order_by = vec![OrderClause {
        field: fp("rank"),
        direction: Direction::Ascending,
    }];
    assert!(matches!(
        state.run_query(&unbounded_explicit_order.canonicalize().unwrap(), None),
        Err(fireemu_core_firestore::store::FirestoreError::InvalidArgument(message))
            if message.contains("unbounded offset")
    ));

    let mut huge_explicit_order = nearest(DistanceMeasure::Euclidean, 1);
    huge_explicit_order.limit = Some(i32::MAX as u32);
    huge_explicit_order.order_by = vec![OrderClause {
        field: fp("rank"),
        direction: Direction::Ascending,
    }];
    assert!(matches!(
        state.run_query(&huge_explicit_order.canonicalize().unwrap(), None),
        Err(fireemu_core_firestore::store::FirestoreError::InvalidArgument(message))
            if message.contains("offset + limit")
    ));

    let mut bounded_explicit_order = nearest(DistanceMeasure::Euclidean, 1);
    bounded_explicit_order.limit = Some(100);
    bounded_explicit_order.order_by = vec![OrderClause {
        field: fp("rank"),
        direction: Direction::Ascending,
    }];
    let (documents, query_stats) = state
        .run_query_with_stats(&bounded_explicit_order.canonicalize().unwrap(), None)
        .unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(query_stats.nearest_peak_candidates, 1);
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
    // The document missing `priority` is excluded from the common aggregation input, while
    // the non-numeric value remains countable.
    assert_eq!(r[0], Value::Integer(4));
    // Only numeric values contribute: 1 + 3 + 2.5 = 6.5 over 3 numeric documents.
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

fn put_vector(state: &mut FirestoreState, id: &str, vector: Vec<f64>, second: i64) {
    state
        .commit(
            &[Write {
                op: WriteOp::Set {
                    path: path(&format!("items/{id}")),
                    fields: [
                        ("embedding".to_owned(), Value::Vector(vector)),
                        ("n".to_owned(), Value::Integer(second)),
                    ]
                    .into_iter()
                    .collect(),
                    update_mask: None,
                },
                precondition: None,
                transforms: vec![],
            }],
            None,
            LogicalInstant::from_unix_seconds(3_000 + second),
        )
        .unwrap();
}

/// A cosine search that meets a zero vector is refused (FS-QUERY-INDEX
/// vector/measures#cosine, whose seed holds a zero vector); the other measures rank it.
#[test]
fn a_cosine_search_over_a_zero_vector_is_refused() {
    let mut state = vector_state();
    put_vector(&mut state, "zero", vec![0.0, 0.0], 1);
    let error = state
        .run_query(
            &nearest(DistanceMeasure::Cosine, 3).canonicalize().unwrap(),
            None,
        )
        .unwrap_err();
    assert_eq!(
        error,
        fireemu_core_firestore::store::FirestoreError::FailedPrecondition(
            "Cannot compute cosine distance against a vector with a magnitude of zero.".to_owned()
        )
    );
    assert!(state
        .run_query(
            &nearest(DistanceMeasure::Euclidean, 4)
                .canonicalize()
                .unwrap(),
            None
        )
        .is_ok());
}

/// Candidates at the same distance come back in document-name order (FS-QUERY-INDEX
/// vector/measures#euclidean, whose seed holds equidistant vectors), whatever order they were
/// written in.
#[test]
fn nearest_ties_are_broken_by_document_name() {
    let mut state = FirestoreState::new();
    for (second, id) in ["d", "b", "c", "a"].into_iter().enumerate() {
        put_vector(
            &mut state,
            id,
            vec![0.0, 1.0],
            i64::try_from(second).unwrap(),
        );
    }
    let ids: Vec<String> = state
        .run_query(
            &nearest(DistanceMeasure::Euclidean, 4)
                .canonicalize()
                .unwrap(),
            None,
        )
        .unwrap()
        .into_iter()
        .map(|document| document.path.document_id().as_str().to_owned())
        .collect();
    assert_eq!(ids, ["a", "b", "c", "d"]);
}

/// An aggregation over a nearest-neighbour query aggregates its results (FS-QUERY-INDEX
/// vector/with-query-clauses#count-over-nearest and #sum-over-nearest).
#[test]
fn aggregations_run_over_the_nearest_results() {
    let mut state = FirestoreState::new();
    for (second, (id, vector)) in [
        ("a", vec![1.0, 0.0]),
        ("b", vec![0.9, 0.1]),
        ("c", vec![-1.0, 0.0]),
    ]
    .into_iter()
    .enumerate()
    {
        put_vector(&mut state, id, vector, i64::try_from(second).unwrap() + 1);
    }
    let query = nearest(DistanceMeasure::Euclidean, 2)
        .canonicalize()
        .unwrap();
    assert_eq!(
        state
            .run_aggregation(
                &query,
                &[
                    Aggregation::Count { up_to: None },
                    Aggregation::Sum(fp("n"))
                ],
                None
            )
            .unwrap(),
        vec![Value::Integer(2), Value::Integer(3)]
    );
}

/// The zero-vector refusal is production's, so a query without production's refusals (the
/// emulator profile) leaves the zero candidate out as a distance that is not finite, as
/// fireemu did before.
#[test]
fn without_production_refusals_a_zero_vector_is_left_out() {
    let mut state = vector_state();
    put_vector(&mut state, "zero", vec![0.0, 0.0], 1);
    let mut query = nearest(DistanceMeasure::Cosine, 4)
        .canonicalize_emulator()
        .unwrap();
    assert!(!query.production_refusals);
    let ids: Vec<String> = state
        .run_query(&query, None)
        .unwrap()
        .into_iter()
        .map(|document| document.path.document_id().as_str().to_owned())
        .collect();
    assert_eq!(ids, ["near", "mid", "far"]);
    query.find_nearest.as_mut().unwrap().query_vector = vec![0.0, 0.0];
    assert!(state.run_query(&query, None).unwrap().is_empty());
}
