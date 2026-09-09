//! Production-rule index validator (spec 8.6, 8.7, 8.8.1): never accept a query whose supporting
//! index is missing; Enterprise turns missing composite indexes into full-scan plans.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDecision, IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
    IndexValidationPolicy, PlanningContext, SingleFieldExemption,
};
use fireemu_core_firestore::query::{
    Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope,
};
use fireemu_core_firestore::store::Aggregation;
use fireemu_core_firestore::value::Value;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;

fn fp(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}

#[test]
fn index_usage_counts_maps_arrays_and_distinct_array_elements() {
    use fireemu_core_firestore::path::DocumentPath;
    use fireemu_core_types::ids::{DatabaseId, ProjectId};
    use std::collections::BTreeMap;
    let path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        "tasks/a",
    )
    .unwrap();
    let fields = BTreeMap::from([
        (
            "tags".into(),
            Value::Array(vec![
                Value::Integer(1),
                Value::Integer(1),
                Value::Integer(2),
            ]),
        ),
        (
            "map".into(),
            Value::Map(BTreeMap::from([("x".into(), Value::Integer(3))])),
        ),
    ]);
    let mut indexes = IndexSet::default();
    let usage = indexes.document_index_usage(&path, &fields).unwrap();
    assert_eq!(usage.entries, 10); // Array: 2 ordered + 4 membership; map and subfield: 4.
    assert!(usage.total_bytes > 0);
    indexes.add_exemption(&SingleFieldExemption {
        collection_group: CollectionId::try_new("tasks").unwrap(),
        field: fp("map"),
        query_scope: IndexQueryScope::Collection,
    });
    assert_eq!(
        indexes
            .document_index_usage(&path, &fields)
            .unwrap()
            .entries,
        6
    );
    indexes.add_composite(composite(&[
        ("tags", IndexFieldMode::Contains),
        ("map.x", IndexFieldMode::Ascending),
    ]));
    assert_eq!(
        indexes
            .document_index_usage(&path, &fields)
            .unwrap()
            .entries,
        8
    );
}

#[test]
fn index_entry_size_and_total_size_budgets_are_independent() {
    use fireemu_core_firestore::path::DocumentPath;
    use fireemu_core_types::ids::{DatabaseId, ProjectId};
    use std::collections::BTreeMap;
    let path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        "tasks/a",
    )
    .unwrap();
    let fields = (0..6)
        .map(|n| (format!("v{n}"), Value::String("x".repeat(1600))))
        .collect::<BTreeMap<_, _>>();
    let mut indexes = IndexSet::default();
    indexes.add_composite(composite(&[
        ("v0", IndexFieldMode::Ascending),
        ("v1", IndexFieldMode::Ascending),
        ("v2", IndexFieldMode::Ascending),
        ("v3", IndexFieldMode::Ascending),
        ("v4", IndexFieldMode::Ascending),
    ]));
    assert!(indexes.document_index_usage(&path, &fields).is_ok());
    indexes.add_composite(composite(&[
        ("v0", IndexFieldMode::Ascending),
        ("v1", IndexFieldMode::Ascending),
        ("v2", IndexFieldMode::Ascending),
        ("v3", IndexFieldMode::Ascending),
        ("v4", IndexFieldMode::Ascending),
        ("v5", IndexFieldMode::Ascending),
    ]));
    assert!(indexes
        .document_index_usage(&path, &fields)
        .unwrap_err()
        .to_string()
        .contains("FS-LIMIT-INDEX-ENTRY-BYTES"));
    let long_path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        &format!("tasks/{}", "x".repeat(1490)),
    )
    .unwrap();
    let array = |count| {
        BTreeMap::from([(
            "v".into(),
            Value::Array((0..count).map(Value::Integer).collect()),
        )])
    };
    assert!(IndexSet::default()
        .document_index_usage(&long_path, &array(2000))
        .is_ok());
    assert!(IndexSet::default()
        .document_index_usage(&long_path, &array(3000))
        .unwrap_err()
        .to_string()
        .contains("FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT"));
}

#[test]
fn wildcard_exemption_allows_explicit_map_child_collection_group_index() {
    let mut indexes = IndexSet::default();
    let collection = CollectionId::try_new("tasks").unwrap();
    indexes.set_default_single_field_indexes(&collection, vec![]);
    indexes.set_single_field_indexes(
        &collection,
        &fp("map.x"),
        vec![(IndexQueryScope::CollectionGroup, IndexFieldMode::Ascending)],
    );
    assert!(indexes
        .single_field_modes(&collection, &fp("map"))
        .is_empty());
    assert!(indexes
        .single_field_modes(&collection, &fp("map.y"))
        .is_empty());
    assert_eq!(
        indexes.single_field_modes(&collection, &fp("map.x")),
        vec![(IndexQueryScope::CollectionGroup, IndexFieldMode::Ascending)]
    );
}
fn field(path: &str, op: FieldOp, v: Value) -> FilterExpr {
    FilterExpr::Field {
        field: fp(path),
        op,
        value: v,
    }
}
fn tasks() -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tasks").unwrap(),
    ))
}
fn standard() -> PlanningContext {
    PlanningContext {
        edition: FirestoreEdition::Standard,
        api_mode: FirestoreApiMode::Native,
        policy: IndexValidationPolicy::Production,
    }
}
fn enterprise() -> PlanningContext {
    PlanningContext {
        edition: FirestoreEdition::Enterprise,
        api_mode: FirestoreApiMode::Native,
        policy: IndexValidationPolicy::Production,
    }
}
fn composite(fields: &[(&str, IndexFieldMode)]) -> IndexDefinition {
    IndexDefinition {
        collection_group: CollectionId::try_new("tasks").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: fields
            .iter()
            .map(|(f, m)| IndexField {
                path: fp(f),
                mode: *m,
            })
            .collect(),
    }
}
fn decide(q: &Query, indexes: &IndexSet, ctx: PlanningContext) -> IndexDecision {
    fireemu_core_firestore::index::decide(&q.canonicalize().unwrap(), indexes, &ctx)
}

#[test]
fn single_field_queries_use_automatic_indexes() {
    let idx = IndexSet::default();
    let q = tasks().with_filter(field("done", FieldOp::Equal, Value::Boolean(true)));
    assert!(matches!(
        decide(&q, &idx, standard()),
        IndexDecision::UseIndex { .. }
    ));
    let q = tasks()
        .with_filter(field("priority", FieldOp::GreaterThan, Value::Integer(1)))
        .with_order(OrderClause {
            field: fp("priority"),
            direction: Direction::Descending,
        });
    assert!(matches!(
        decide(&q, &idx, standard()),
        IndexDecision::UseIndex { .. }
    ));
    let q = tasks().with_filter(field(
        "tags",
        FieldOp::ArrayContains,
        Value::String("x".to_owned()),
    ));
    assert!(matches!(
        decide(&q, &idx, standard()),
        IndexDecision::UseIndex { .. }
    ));
    assert!(matches!(
        decide(&tasks(), &idx, standard()),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn equality_plus_inequality_needs_a_composite_index() {
    // Production merges the automatic single-field indexes of two equality filters, so the
    // query that needs a composite index is an equality combined with an inequality on
    // another field (conformance: firestore/missing-composite-index).
    let q = tasks().with_filter(FilterExpr::And(vec![
        field("done", FieldOp::Equal, Value::Boolean(false)),
        field("owner", FieldOp::GreaterThan, Value::String("u".to_owned())),
    ]));
    match decide(&q, &IndexSet::default(), standard()) {
        IndexDecision::MissingRequired { requirement } => {
            let fields: Vec<String> = requirement
                .fields
                .iter()
                .map(|f| f.path.canonical())
                .collect();
            assert_eq!(fields, vec!["done", "owner", "__name__"]);
            assert!(requirement
                .indexes_json_fragment()
                .contains("\"collectionGroup\": \"tasks\""));
        }
        other => panic!("{other:?}"),
    }
    let mut idx = IndexSet::default();
    idx.add_composite(composite(&[
        ("done", IndexFieldMode::Ascending),
        ("owner", IndexFieldMode::Ascending),
    ]));
    // The equality field first, the inequality field after it: the index serves the query.
    assert!(matches!(
        decide(&q, &idx, standard()),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn order_direction_and_position_matter() {
    let q = tasks()
        .with_filter(field(
            "owner",
            FieldOp::Equal,
            Value::String("u".to_owned()),
        ))
        .with_order(OrderClause {
            field: fp("createdAt"),
            direction: Direction::Descending,
        })
        .with_order(OrderClause {
            field: fp("priority"),
            direction: Direction::Ascending,
        });
    // Mixed directions that are neither equal nor fully reversed do not serve the query.
    let mut wrong_dir = IndexSet::default();
    wrong_dir.add_composite(composite(&[
        ("owner", IndexFieldMode::Ascending),
        ("createdAt", IndexFieldMode::Ascending),
        ("priority", IndexFieldMode::Ascending),
    ]));
    assert!(matches!(
        decide(&q, &wrong_dir, standard()),
        IndexDecision::MissingRequired { .. }
    ));
    let mut right = IndexSet::default();
    right.add_composite(composite(&[
        ("owner", IndexFieldMode::Ascending),
        ("createdAt", IndexFieldMode::Descending),
        ("priority", IndexFieldMode::Ascending),
    ]));
    assert!(matches!(
        decide(&q, &right, standard()),
        IndexDecision::UseIndex { .. }
    ));
    // Equality-prefix direction is flexible, but ordered fields must not be served by a fully
    // reversed index.
    let mut reversed = IndexSet::default();
    reversed.add_composite(composite(&[
        ("owner", IndexFieldMode::Descending),
        ("createdAt", IndexFieldMode::Ascending),
        ("priority", IndexFieldMode::Descending),
    ]));
    assert!(matches!(
        decide(&q, &reversed, standard()),
        IndexDecision::MissingRequired { .. }
    ));
    // Order fields before the equality field do not serve the query.
    let mut swapped = IndexSet::default();
    swapped.add_composite(composite(&[
        ("createdAt", IndexFieldMode::Descending),
        ("priority", IndexFieldMode::Ascending),
        ("owner", IndexFieldMode::Ascending),
    ]));
    assert!(matches!(
        decide(&q, &swapped, standard()),
        IndexDecision::MissingRequired { .. }
    ));
}

#[test]
fn automatic_single_field_indexes_require_the_requested_direction() {
    let collection = CollectionId::try_new("tasks").unwrap();
    let mut indexes = IndexSet::default();
    indexes.set_single_field_indexes(
        &collection,
        &fp("priority"),
        vec![(IndexQueryScope::Collection, IndexFieldMode::Ascending)],
    );

    let ascending = tasks().with_order(OrderClause {
        field: fp("priority"),
        direction: Direction::Ascending,
    });
    assert!(matches!(
        decide(&ascending, &indexes, standard()),
        IndexDecision::UseIndex { .. }
    ));

    let descending = tasks().with_order(OrderClause {
        field: fp("priority"),
        direction: Direction::Descending,
    });
    match decide(&descending, &indexes, standard()) {
        IndexDecision::MissingRequired { requirement } => {
            assert_eq!(requirement.fields[0].path, fp("priority"));
            assert_eq!(requirement.fields[0].mode, IndexFieldMode::Descending);
        }
        other => panic!("{other:?}"),
    }

    let inequality_ascending = tasks()
        .with_filter(field("priority", FieldOp::GreaterThan, Value::Integer(1)))
        .with_order(OrderClause {
            field: fp("priority"),
            direction: Direction::Ascending,
        });
    assert!(matches!(
        decide(&inequality_ascending, &indexes, standard()),
        IndexDecision::UseIndex { .. }
    ));

    let inequality_descending = tasks()
        .with_filter(field("priority", FieldOp::GreaterThan, Value::Integer(1)))
        .with_order(OrderClause {
            field: fp("priority"),
            direction: Direction::Descending,
        });
    assert!(matches!(
        decide(&inequality_descending, &indexes, standard()),
        IndexDecision::MissingRequired { .. }
    ));
}

fn name_order(direction: Direction) -> OrderClause {
    OrderClause {
        field: FieldPath::document_name(),
        direction,
    }
}

fn index_modes(index: &IndexDefinition) -> Vec<(String, IndexFieldMode)> {
    index
        .fields
        .iter()
        .map(|f| (f.path.canonical(), f.mode))
        .collect()
}

#[test]
fn automatic_index_name_direction_follows_the_ordered_field() {
    let idx = IndexSet::default();
    let priority = |direction| OrderClause {
        field: fp("priority"),
        direction,
    };

    // The implicit `__name__` of an automatic index shares the field's direction.
    match decide(
        &tasks().with_order(priority(Direction::Ascending)),
        &idx,
        standard(),
    ) {
        IndexDecision::UseIndex { index } => assert_eq!(
            index_modes(&index),
            vec![
                ("priority".to_owned(), IndexFieldMode::Ascending),
                ("__name__".to_owned(), IndexFieldMode::Ascending),
            ]
        ),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        decide(
            &tasks()
                .with_order(priority(Direction::Descending))
                .with_order(name_order(Direction::Descending)),
            &idx,
            standard(),
        ),
        IndexDecision::UseIndex { .. }
    ));

    // A `__name__` direction opposite to the ordered field needs a composite index.
    let reversed_name = tasks()
        .with_order(priority(Direction::Ascending))
        .with_order(name_order(Direction::Descending));
    match decide(&reversed_name, &idx, standard()) {
        IndexDecision::MissingRequired { requirement } => assert_eq!(
            index_modes(&requirement),
            vec![
                ("priority".to_owned(), IndexFieldMode::Ascending),
                ("__name__".to_owned(), IndexFieldMode::Descending),
            ]
        ),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        decide(
            &tasks()
                .with_order(priority(Direction::Descending))
                .with_order(name_order(Direction::Ascending)),
            &idx,
            standard(),
        ),
        IndexDecision::MissingRequired { .. }
    ));
    // Production behaves the same way; this is not a fireemu-only rejection.
    assert!(matches!(
        decide(&reversed_name, &idx, standard()),
        IndexDecision::MissingRequired { .. }
    ));

    // The matching explicit composite index serves the reversed direction, and the decision
    // names that index rather than a synthesized one.
    let mut explicit = IndexSet::default();
    let composite_index = composite(&[
        ("priority", IndexFieldMode::Ascending),
        ("__name__", IndexFieldMode::Descending),
    ]);
    explicit.add_composite(composite_index.clone());
    match decide(&reversed_name, &explicit, standard()) {
        IndexDecision::UseIndex { index } => assert_eq!(index, composite_index),
        other => panic!("{other:?}"),
    }
}

#[test]
fn automatic_index_name_direction_for_equality_and_array_queries() {
    let collection = CollectionId::try_new("tasks").unwrap();
    let equality = tasks().with_filter(field(
        "owner",
        FieldOp::Equal,
        Value::String("u".to_owned()),
    ));

    // Equality plus `__name__ DESC` is served by the descending automatic index.
    match decide(
        &equality
            .clone()
            .with_order(name_order(Direction::Descending)),
        &IndexSet::default(),
        standard(),
    ) {
        IndexDecision::UseIndex { index } => assert_eq!(
            index_modes(&index),
            vec![
                ("owner".to_owned(), IndexFieldMode::Descending),
                ("__name__".to_owned(), IndexFieldMode::Descending),
            ]
        ),
        other => panic!("{other:?}"),
    }
    // An equality prefix serves either direction, so the only enabled mode is used (see
    // `equality_only_automatic_indexes_accept_either_enabled_order_direction`), but the
    // decision names that index.
    let mut ascending_only = IndexSet::default();
    ascending_only.set_single_field_indexes(
        &collection,
        &fp("owner"),
        vec![(IndexQueryScope::Collection, IndexFieldMode::Ascending)],
    );
    match decide(
        &equality
            .clone()
            .with_order(name_order(Direction::Descending)),
        &ascending_only,
        standard(),
    ) {
        IndexDecision::UseIndex { index } => assert_eq!(
            index_modes(&index),
            vec![
                ("owner".to_owned(), IndexFieldMode::Ascending),
                ("__name__".to_owned(), IndexFieldMode::Descending),
            ]
        ),
        other => panic!("{other:?}"),
    }
    let mut disabled = IndexSet::default();
    disabled.set_single_field_indexes(&collection, &fp("owner"), vec![]);
    assert!(matches!(
        decide(&equality, &disabled, standard()),
        IndexDecision::MissingRequired { .. }
    ));

    // The automatic array-contains index serves a bare name order in either direction, but
    // not an ordering on a further field.
    let contains = tasks().with_filter(field(
        "tags",
        FieldOp::ArrayContains,
        Value::String("t".to_owned()),
    ));
    assert!(matches!(
        decide(&contains, &IndexSet::default(), standard()),
        IndexDecision::UseIndex { .. }
    ));
    assert!(matches!(
        decide(
            &contains
                .clone()
                .with_order(name_order(Direction::Descending)),
            &IndexSet::default(),
            standard(),
        ),
        IndexDecision::UseIndex { .. }
    ));
    match decide(
        &contains.with_order(OrderClause {
            field: fp("priority"),
            direction: Direction::Descending,
        }),
        &IndexSet::default(),
        standard(),
    ) {
        IndexDecision::MissingRequired { requirement } => assert_eq!(
            index_modes(&requirement),
            vec![
                ("tags".to_owned(), IndexFieldMode::Contains),
                ("priority".to_owned(), IndexFieldMode::Descending),
                ("__name__".to_owned(), IndexFieldMode::Descending),
            ]
        ),
        other => panic!("{other:?}"),
    }

    // A bare name order: see `bare_descending_name_order_needs_an_explicit_index`.
}

/// Production serves `orderBy(__name__, desc)` only through an explicit `(__name__ DESC)`
/// index in the query's scope; the wildcard single-field override does not change that, and
/// a `__name__` inequality with the same order is the same query.
#[test]
fn bare_descending_name_order_needs_an_explicit_index() {
    let collection = CollectionId::try_new("tasks").unwrap();
    let desc = tasks().with_order(name_order(Direction::Descending));
    let group_desc = Query::new(QueryScope::collection_group(collection.clone()))
        .with_order(name_order(Direction::Descending));
    let name_desc = composite(&[("__name__", IndexFieldMode::Descending)]);

    // A bare ascending name order is the primary key; a bare descending one needs an explicit
    // `(__name__ DESC)` index (production, 2026-09-08: FAILED_PRECONDITION without it).
    assert!(matches!(
        decide(
            &tasks().with_order(name_order(Direction::Ascending)),
            &IndexSet::default(),
            standard(),
        ),
        IndexDecision::UseIndex { .. }
    ));
    match decide(&desc, &IndexSet::default(), standard()) {
        IndexDecision::MissingRequired { requirement } => assert_eq!(
            index_modes(&requirement),
            vec![("__name__".to_owned(), IndexFieldMode::Descending)]
        ),
        other => panic!("{other:?}"),
    }

    let mut explicit = IndexSet::default();
    explicit.add_composite(name_desc.clone());
    match decide(&desc, &explicit, standard()) {
        IndexDecision::UseIndex { index } => assert_eq!(index, name_desc),
        other => panic!("{other:?}"),
    }
    match decide(&desc, &explicit, standard()) {
        IndexDecision::UseIndex { index } => assert_eq!(index, name_desc),
        other => panic!("{other:?}"),
    }
    // A collection-scoped index does not serve the collection group.
    assert!(matches!(
        decide(&group_desc, &explicit, standard()),
        IndexDecision::MissingRequired { .. }
    ));
    let mut group_index = IndexSet::default();
    group_index.add_composite(IndexDefinition {
        query_scope: IndexQueryScope::CollectionGroup,
        ..name_desc.clone()
    });
    assert!(matches!(
        decide(&group_desc, &group_index, standard()),
        IndexDecision::UseIndex { .. }
    ));
}

/// Exempting every field neither helps nor hurts the primary key; a `__name__` range with a
/// descending name order is rejected like the bare order, while an equality prefix still
/// serves it through the automatic descending index.
#[test]
fn descending_name_order_ignores_field_overrides_but_rides_equality_prefixes() {
    let collection = CollectionId::try_new("tasks").unwrap();
    let desc = tasks().with_order(name_order(Direction::Descending));
    let mut all_exempt = IndexSet::default();
    all_exempt.set_default_single_field_indexes(&collection, vec![]);
    assert!(matches!(
        decide(&desc, &all_exempt, standard()),
        IndexDecision::MissingRequired { .. }
    ));
    assert!(matches!(
        decide(
            &tasks().with_order(name_order(Direction::Ascending)),
            &all_exempt,
            standard()
        ),
        IndexDecision::UseIndex { .. }
    ));

    // `__name__ > ref` ordered descending by name is rejected too.
    let range_desc = tasks()
        .with_filter(FilterExpr::Field {
            field: FieldPath::document_name(),
            op: FieldOp::GreaterThan,
            value: Value::Reference("projects/p/databases/(default)/documents/tasks/a".to_owned()),
        })
        .with_order(name_order(Direction::Descending));
    assert!(matches!(
        decide(&range_desc, &IndexSet::default(), standard()),
        IndexDecision::MissingRequired { .. }
    ));

    // An equality prefix still serves the descending name through its automatic index.
    let equality_desc = tasks()
        .with_filter(field("done", FieldOp::Equal, Value::Boolean(true)))
        .with_order(name_order(Direction::Descending));
    assert!(matches!(
        decide(&equality_desc, &IndexSet::default(), standard()),
        IndexDecision::UseIndex { .. }
    ));

    // The Emulator policy assumes the index like every other composite.
    assert!(matches!(
        decide(&desc, &IndexSet::default(), emulator()),
        IndexDecision::AssumedIndex { .. }
    ));
}

#[test]
fn production_merges_single_field_indexes_for_scalar_equality_queries() {
    let collection = CollectionId::try_new("tasks").unwrap();
    let q = tasks().with_filter(FilterExpr::And(vec![
        field("state", FieldOp::Equal, Value::String("open".to_owned())),
        field("owner", FieldOp::Equal, Value::String("u1".to_owned())),
    ]));

    // Production merges the automatic single-field indexes (verified against a real project
    // on 2026-09-08), so no composite index is demanded.
    match decide(&q, &IndexSet::default(), standard()) {
        IndexDecision::MergeIndexes { indexes } => {
            let merged: Vec<_> = indexes.iter().map(index_modes).collect();
            assert_eq!(
                merged,
                vec![
                    vec![
                        ("owner".to_owned(), IndexFieldMode::Ascending),
                        ("__name__".to_owned(), IndexFieldMode::Ascending),
                    ],
                    vec![
                        ("state".to_owned(), IndexFieldMode::Ascending),
                        ("__name__".to_owned(), IndexFieldMode::Ascending),
                    ],
                ]
            );
        }
        other => panic!("{other:?}"),
    }

    // A composite index that serves the query is still preferred over a merge.
    let mut explicit = IndexSet::default();
    let composite_index = composite(&[
        ("owner", IndexFieldMode::Ascending),
        ("state", IndexFieldMode::Ascending),
    ]);
    explicit.add_composite(composite_index.clone());
    match decide(&q, &explicit, standard()) {
        IndexDecision::UseIndex { index } => assert_eq!(index, composite_index),
        other => panic!("{other:?}"),
    }

    // Every merged field must have its automatic index enabled.
    let mut exempt = IndexSet::default();
    exempt.add_exemption(&SingleFieldExemption {
        collection_group: collection.clone(),
        field: fp("owner"),
        query_scope: IndexQueryScope::Collection,
    });
    assert!(matches!(
        decide(&q, &exempt, standard()),
        IndexDecision::MissingRequired { .. }
    ));

    // A descending name order merges the descending automatic indexes only when enabled.
    let descending_names = q.clone().with_order(name_order(Direction::Descending));
    assert!(matches!(
        decide(&descending_names, &IndexSet::default(), standard()),
        IndexDecision::MergeIndexes { .. }
    ));
    let mut ascending_only = IndexSet::default();
    ascending_only.set_single_field_indexes(
        &collection,
        &fp("owner"),
        vec![(IndexQueryScope::Collection, IndexFieldMode::Ascending)],
    );
    assert!(matches!(
        decide(&descending_names, &ascending_only, standard()),
        IndexDecision::MissingRequired { .. }
    ));
}

#[test]
fn firebase_policy_index_merge_stops_at_ordering_arrays_and_inequalities() {
    let q = tasks().with_filter(FilterExpr::And(vec![
        field("state", FieldOp::Equal, Value::String("open".to_owned())),
        field("owner", FieldOp::Equal, Value::String("u1".to_owned())),
    ]));
    // Ordering by a further field, an array filter, or an inequality is outside the merge.
    assert!(matches!(
        decide(
            &q.clone().with_order(OrderClause {
                field: fp("createdAt"),
                direction: Direction::Ascending,
            }),
            &IndexSet::default(),
            standard(),
        ),
        IndexDecision::MissingRequired { .. }
    ));
    assert!(matches!(
        decide(
            &tasks().with_filter(FilterExpr::And(vec![
                field("state", FieldOp::Equal, Value::String("open".to_owned())),
                field(
                    "tags",
                    FieldOp::ArrayContains,
                    Value::String("t".to_owned())
                ),
            ])),
            &IndexSet::default(),
            standard(),
        ),
        IndexDecision::MissingRequired { .. }
    ));
    assert!(matches!(
        decide(
            &tasks().with_filter(FilterExpr::And(vec![
                field("state", FieldOp::Equal, Value::String("open".to_owned())),
                field("priority", FieldOp::GreaterThan, Value::Integer(1)),
            ])),
            &IndexSet::default(),
            standard(),
        ),
        IndexDecision::MissingRequired { .. }
    ));

    // `in` expands to several equality disjunctions; each merges on its own.
    assert!(matches!(
        decide(
            &tasks().with_filter(FilterExpr::And(vec![
                field(
                    "state",
                    FieldOp::In,
                    Value::Array(vec![
                        Value::String("open".to_owned()),
                        Value::String("done".to_owned()),
                    ]),
                ),
                field("owner", FieldOp::Equal, Value::String("u1".to_owned())),
            ])),
            &IndexSet::default(),
            standard(),
        ),
        IndexDecision::MergeIndexes { .. }
    ));
}

#[test]
fn aggregation_fields_participate_in_index_validation_without_changing_the_query() {
    let collection = CollectionId::try_new("tasks").unwrap();
    let mut disabled = IndexSet::default();
    disabled.set_single_field_indexes(&collection, &fp("amount"), vec![]);
    let bare = tasks();

    assert!(matches!(
        fireemu_core_firestore::index::validate_aggregation_query(
            &bare.canonicalize().unwrap(),
            &[Aggregation::Sum(fp("amount"))],
            &disabled,
            &standard(),
        ),
        IndexDecision::MissingRequired { .. }
    ));
    assert!(matches!(
        fireemu_core_firestore::index::validate_aggregation_query(
            &bare.canonicalize().unwrap(),
            &[Aggregation::Avg(fp("amount"))],
            &disabled,
            &standard(),
        ),
        IndexDecision::MissingRequired { .. }
    ));

    assert!(matches!(
        fireemu_core_firestore::index::validate_aggregation_query(
            &bare.canonicalize().unwrap(),
            &[Aggregation::Count { up_to: None }],
            &disabled,
            &standard(),
        ),
        IndexDecision::UseIndex { .. }
    ));

    let filtered = tasks().with_filter(field(
        "status",
        FieldOp::Equal,
        Value::String("open".to_owned()),
    ));
    let mut composite_indexes = IndexSet::default();
    composite_indexes.add_composite(composite(&[
        ("status", IndexFieldMode::Ascending),
        ("amount", IndexFieldMode::Ascending),
    ]));
    assert!(matches!(
        fireemu_core_firestore::index::validate_aggregation_query(
            &filtered.canonicalize().unwrap(),
            &[Aggregation::Sum(fp("amount"))],
            &disabled,
            &standard(),
        ),
        IndexDecision::MissingRequired { .. }
    ));
    assert!(matches!(
        fireemu_core_firestore::index::validate_aggregation_query(
            &filtered.canonicalize().unwrap(),
            &[Aggregation::Sum(fp("amount"))],
            &composite_indexes,
            &standard(),
        ),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn equality_only_automatic_indexes_accept_either_enabled_order_direction() {
    let collection = CollectionId::try_new("tasks").unwrap();
    let mut indexes = IndexSet::default();
    indexes.set_single_field_indexes(
        &collection,
        &fp("priority"),
        vec![(IndexQueryScope::Collection, IndexFieldMode::Descending)],
    );

    let equality = tasks().with_filter(field("priority", FieldOp::Equal, Value::Integer(1)));
    assert!(matches!(
        decide(&equality, &indexes, standard()),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn collection_group_scope_is_not_ignored() {
    let q = Query::new(QueryScope::collection_group(
        CollectionId::try_new("tasks").unwrap(),
    ))
    .with_filter(FilterExpr::And(vec![
        field("done", FieldOp::Equal, Value::Boolean(false)),
        field("owner", FieldOp::Equal, Value::String("u".to_owned())),
    ]));
    let mut collection_only = IndexSet::default();
    collection_only.add_composite(composite(&[
        ("done", IndexFieldMode::Ascending),
        ("owner", IndexFieldMode::Ascending),
    ]));
    assert!(matches!(
        decide(&q, &collection_only, standard()),
        IndexDecision::MissingRequired { .. }
    ));
    let mut group = IndexSet::default();
    let mut d = composite(&[
        ("done", IndexFieldMode::Ascending),
        ("owner", IndexFieldMode::Ascending),
    ]);
    d.query_scope = IndexQueryScope::CollectionGroup;
    group.add_composite(d);
    assert!(matches!(
        decide(&q, &group, standard()),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn array_mode_is_not_ignored() {
    let q = tasks().with_filter(FilterExpr::And(vec![
        field(
            "tags",
            FieldOp::ArrayContains,
            Value::String("x".to_owned()),
        ),
        field("owner", FieldOp::Equal, Value::String("u".to_owned())),
    ]));
    let mut asc = IndexSet::default();
    asc.add_composite(composite(&[
        ("owner", IndexFieldMode::Ascending),
        ("tags", IndexFieldMode::Ascending),
    ]));
    assert!(matches!(
        decide(&q, &asc, standard()),
        IndexDecision::MissingRequired { .. }
    ));
    let mut contains = IndexSet::default();
    contains.add_composite(composite(&[
        ("owner", IndexFieldMode::Ascending),
        ("tags", IndexFieldMode::Contains),
    ]));
    assert!(matches!(
        decide(&q, &contains, standard()),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn exempted_single_field_index_makes_simple_query_unservable() {
    let mut idx = IndexSet::default();
    idx.add_exemption(&SingleFieldExemption {
        collection_group: CollectionId::try_new("tasks").unwrap(),
        field: fp("blob"),
        query_scope: IndexQueryScope::Collection,
    });
    let q = tasks().with_filter(field("blob", FieldOp::Equal, Value::Integer(1)));
    assert!(matches!(
        decide(&q, &idx, standard()),
        IndexDecision::MissingRequired { .. }
    ));
}

#[test]
fn or_queries_require_every_disjunction_to_be_servable() {
    // The inequality on `priority` orders the whole query, so every disjunction needs an index
    // that yields results in `priority` order (conservative: never assume merge-sorting).
    let q = tasks().with_filter(FilterExpr::Or(vec![
        field("done", FieldOp::Equal, Value::Boolean(true)),
        FilterExpr::And(vec![
            field("owner", FieldOp::Equal, Value::String("u".to_owned())),
            field("priority", FieldOp::GreaterThan, Value::Integer(1)),
        ]),
    ]));
    assert!(matches!(
        decide(&q, &IndexSet::default(), standard()),
        IndexDecision::MissingRequired { .. }
    ));
    let mut idx = IndexSet::default();
    idx.add_composite(composite(&[
        ("owner", IndexFieldMode::Ascending),
        ("priority", IndexFieldMode::Ascending),
    ]));
    match decide(&q, &idx, standard()) {
        IndexDecision::MissingRequired { requirement } => {
            let fields: Vec<String> = requirement
                .fields
                .iter()
                .map(|f| f.path.canonical())
                .collect();
            assert_eq!(fields, vec!["done", "priority", "__name__"]);
        }
        other => panic!("{other:?}"),
    }
    idx.add_composite(composite(&[
        ("done", IndexFieldMode::Ascending),
        ("priority", IndexFieldMode::Ascending),
    ]));
    assert!(matches!(
        decide(&q, &idx, standard()),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn enterprise_missing_index_is_a_full_scan_not_an_error() {
    let q = tasks().with_filter(FilterExpr::And(vec![
        field("done", FieldOp::Equal, Value::Boolean(false)),
        field("owner", FieldOp::GreaterThan, Value::String("u".to_owned())),
    ]));
    match decide(&q, &IndexSet::default(), enterprise()) {
        IndexDecision::FullScanAllowed { plan } => {
            assert!(plan.diagnostics.contains(&"FS_ENT_FULL_COLLECTION_SCAN"));
        }
        other => panic!("{other:?}"),
    }
    // With a matching index Enterprise uses it like Standard does.
    let mut idx = IndexSet::default();
    idx.add_composite(composite(&[
        ("done", IndexFieldMode::Ascending),
        ("owner", IndexFieldMode::Ascending),
    ]));
    assert!(matches!(
        decide(&q, &idx, enterprise()),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn an_accepted_query_carries_the_index_that_serves_it() {
    // Every UseIndex decision must be backed by a concrete index or the automatic single-field
    // index; the decision carries that evidence.
    let q = tasks().with_filter(field("done", FieldOp::Equal, Value::Boolean(true)));
    match decide(&q, &IndexSet::default(), standard()) {
        IndexDecision::UseIndex { index } => assert_eq!(index.fields.len(), 2), // done ASC, __name__ ASC
        other => panic!("{other:?}"),
    }
}

#[test]
fn contains_only_override_cannot_serve_scalar_equality() {
    let mut indexes = IndexSet::default();
    indexes.set_single_field_indexes(
        &CollectionId::try_new("tasks").unwrap(),
        &fp("tags"),
        vec![(IndexQueryScope::Collection, IndexFieldMode::Contains)],
    );
    let scalar = tasks().with_filter(field("tags", FieldOp::Equal, Value::Integer(1)));
    assert!(matches!(
        decide(&scalar, &indexes, standard()),
        IndexDecision::MissingRequired { .. }
    ));
    let membership = tasks().with_filter(field("tags", FieldOp::ArrayContains, Value::Integer(1)));
    assert!(matches!(
        decide(&membership, &indexes, standard()),
        IndexDecision::UseIndex { .. }
    ));
}

#[test]
fn literal_star_field_exemption_does_not_disable_other_fields() {
    let mut indexes = IndexSet::default();
    let collection = CollectionId::try_new("tasks").unwrap();
    indexes.set_single_field_indexes(&collection, &fp("`*`"), vec![]);
    assert!(indexes
        .single_field_modes(&collection, &fp("`*`"))
        .is_empty());
    assert_eq!(
        indexes.single_field_modes(&collection, &fp("other")).len(),
        3
    );
}

fn emulator() -> PlanningContext {
    PlanningContext {
        policy: IndexValidationPolicy::Emulator,
        ..standard()
    }
}

#[test]
fn the_emulator_policy_serves_queries_without_their_composite_index() {
    let q = tasks().with_filter(FilterExpr::And(vec![
        field("done", FieldOp::Equal, Value::Boolean(false)),
        field("owner", FieldOp::GreaterThan, Value::String("u".to_owned())),
    ]));
    let required = match decide(&q, &IndexSet::default(), standard()) {
        IndexDecision::MissingRequired { requirement } => requirement,
        other => panic!("{other}"),
    };
    match decide(&q, &IndexSet::default(), emulator()) {
        IndexDecision::AssumedIndex { requirement } => assert_eq!(requirement, required),
        other => panic!("{other}"),
    }
    // A configured index is still preferred and reported as such.
    let mut idx = IndexSet::default();
    idx.add_composite(required);
    assert!(matches!(
        decide(&q, &idx, emulator()),
        IndexDecision::UseIndex { .. }
    ));
    // Single-field queries need no assumption.
    assert!(matches!(
        decide(&tasks(), &IndexSet::default(), emulator()),
        IndexDecision::UseIndex { .. }
    ));
}

fn restaurants() -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("restaurants").unwrap(),
    ))
}

fn restaurant_composite(fields: &[(&str, IndexFieldMode)]) -> IndexDefinition {
    IndexDefinition {
        collection_group: CollectionId::try_new("restaurants").unwrap(),
        ..composite(fields)
    }
}

/// The index-merging example from the Firestore index overview: `category`/`city`/
/// `editors_pick` equality clauses sorted by `star_rating` are served by merging one composite
/// index per equality field, each ending in `star_rating ASC`.
#[test]
fn production_merges_composite_indexes_sharing_the_order_suffix() {
    let star_rating = OrderClause {
        field: fp("star_rating"),
        direction: Direction::Ascending,
    };
    let two = restaurants()
        .with_filter(FilterExpr::And(vec![
            field(
                "category",
                FieldOp::Equal,
                Value::String("burgers".to_owned()),
            ),
            field("city", FieldOp::Equal, Value::String("SF".to_owned())),
        ]))
        .with_order(star_rating.clone());
    let three = restaurants()
        .with_filter(FilterExpr::And(vec![
            field(
                "category",
                FieldOp::Equal,
                Value::String("burgers".to_owned()),
            ),
            field("city", FieldOp::Equal, Value::String("SF".to_owned())),
            field("editors_pick", FieldOp::Equal, Value::Boolean(true)),
        ]))
        .with_order(star_rating.clone());
    let category = restaurant_composite(&[
        ("category", IndexFieldMode::Ascending),
        ("star_rating", IndexFieldMode::Ascending),
    ]);
    let city = restaurant_composite(&[
        ("city", IndexFieldMode::Ascending),
        ("star_rating", IndexFieldMode::Ascending),
    ]);
    let editors_pick = restaurant_composite(&[
        ("editors_pick", IndexFieldMode::Ascending),
        ("star_rating", IndexFieldMode::Ascending),
    ]);

    let mut indexes = IndexSet::default();
    indexes.add_composite(category.clone());
    indexes.add_composite(city.clone());
    indexes.add_composite(editors_pick.clone());
    match decide(&two, &indexes, standard()) {
        IndexDecision::MergeIndexes { indexes } => {
            assert_eq!(indexes, vec![category.clone(), city.clone()]);
        }
        other => panic!("{other:?}"),
    }
    match decide(&three, &indexes, standard()) {
        IndexDecision::MergeIndexes { indexes } => {
            assert_eq!(
                indexes,
                vec![category.clone(), city.clone(), editors_pick.clone()]
            );
        }
        other => panic!("{other:?}"),
    }
    // One index short: nothing covers `city`.
    let mut only_category = IndexSet::default();
    only_category.add_composite(category.clone());
    assert!(matches!(
        decide(&two, &only_category, standard()),
        IndexDecision::MissingRequired { .. }
    ));

    // Members must agree on the order suffix: `city DESC, star_rating DESC` sorts the wrong way.
    let mut mismatched = IndexSet::default();
    mismatched.add_composite(category.clone());
    mismatched.add_composite(restaurant_composite(&[
        ("city", IndexFieldMode::Ascending),
        ("star_rating", IndexFieldMode::Descending),
    ]));
    assert!(matches!(
        decide(&two, &mismatched, standard()),
        IndexDecision::MissingRequired { .. }
    ));

    // An automatic index on `city` does not end in `star_rating`, so it cannot fill the gap.
    assert!(matches!(
        decide(&two, &only_category, standard()),
        IndexDecision::MissingRequired { .. }
    ));
}

/// A composite covering several equality fields merges with the automatic index of the rest
/// when nothing but `__name__` is ordered.
#[test]
fn production_merges_a_composite_index_with_automatic_indexes() {
    let mut pair = IndexSet::default();
    let category_city = restaurant_composite(&[
        ("category", IndexFieldMode::Ascending),
        ("city", IndexFieldMode::Ascending),
    ]);
    pair.add_composite(category_city.clone());
    let unordered_three = restaurants().with_filter(FilterExpr::And(vec![
        field(
            "category",
            FieldOp::Equal,
            Value::String("burgers".to_owned()),
        ),
        field("city", FieldOp::Equal, Value::String("SF".to_owned())),
        field("editors_pick", FieldOp::Equal, Value::Boolean(true)),
    ]));
    match decide(&unordered_three, &pair, standard()) {
        IndexDecision::MergeIndexes { indexes } => {
            assert_eq!(indexes.len(), 2);
            assert_eq!(indexes[0], category_city);
            assert_eq!(
                index_modes(&indexes[1]),
                vec![
                    ("editors_pick".to_owned(), IndexFieldMode::Ascending),
                    ("__name__".to_owned(), IndexFieldMode::Ascending),
                ]
            );
        }
        other => panic!("{other:?}"),
    }
}

/// `__name__` is the primary key: equality and `in` filters on it never need a single-field
/// index, so a wildcard exemption of every field leaves them servable. Other fields keep
/// their exemption checks.
#[test]
fn document_name_equality_is_served_without_field_indexes() {
    let collection = CollectionId::try_new("tasks").unwrap();
    let mut all_exempt = IndexSet::default();
    all_exempt.set_default_single_field_indexes(&collection, vec![]);
    let reference = |id: &str| {
        Value::Reference(format!(
            "projects/p/databases/(default)/documents/tasks/{id}"
        ))
    };

    let by_name = tasks().with_filter(FilterExpr::Field {
        field: FieldPath::document_name(),
        op: FieldOp::Equal,
        value: reference("a"),
    });
    assert!(matches!(
        decide(&by_name, &all_exempt, standard()),
        IndexDecision::UseIndex { .. }
    ));
    let by_names = tasks().with_filter(FilterExpr::Field {
        field: FieldPath::document_name(),
        op: FieldOp::In,
        value: Value::Array(vec![reference("a"), reference("b")]),
    });
    assert!(matches!(
        decide(&by_names, &all_exempt, standard()),
        IndexDecision::UseIndex { .. }
    ));

    // A name filter does not lift the exemption of the other field in the conjunction.
    let name_and_field = tasks().with_filter(FilterExpr::And(vec![
        FilterExpr::Field {
            field: FieldPath::document_name(),
            op: FieldOp::Equal,
            value: reference("a"),
        },
        field("done", FieldOp::Equal, Value::Boolean(true)),
    ]));
    assert!(matches!(
        decide(&name_and_field, &all_exempt, standard()),
        IndexDecision::MissingRequired { .. }
    ));
    // With the field indexed, the name filter rides on the automatic index of `done`.
    assert!(matches!(
        decide(&name_and_field, &IndexSet::default(), standard()),
        IndexDecision::UseIndex { .. }
    ));
    // And a composite index serving the other equality fields serves the query too.
    let mut explicit = IndexSet::default();
    explicit.add_composite(composite(&[
        ("done", IndexFieldMode::Ascending),
        ("owner", IndexFieldMode::Ascending),
    ]));
    let name_and_two = tasks().with_filter(FilterExpr::And(vec![
        FilterExpr::Field {
            field: FieldPath::document_name(),
            op: FieldOp::Equal,
            value: reference("a"),
        },
        field("done", FieldOp::Equal, Value::Boolean(true)),
        field("owner", FieldOp::Equal, Value::String("u1".to_owned())),
    ]));
    assert!(matches!(
        decide(&name_and_two, &explicit, standard()),
        IndexDecision::UseIndex { .. }
    ));
}
