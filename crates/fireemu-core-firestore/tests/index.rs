//! Conservative index validator (spec 8.6, 8.7, 8.8.1): never accept a query whose supporting
//! index is missing; Enterprise turns missing composite indexes into full-scan plans.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDecision, IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
    IndexValidationPolicy, PlanningContext, SingleFieldExemption,
};
use fireemu_core_firestore::query::{
    Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope,
};
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
        policy: IndexValidationPolicy::Conservative,
    }
}
fn enterprise() -> PlanningContext {
    PlanningContext {
        edition: FirestoreEdition::Enterprise,
        api_mode: FirestoreApiMode::Native,
        policy: IndexValidationPolicy::Conservative,
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
fn equality_on_two_fields_needs_a_composite_index() {
    let q = tasks().with_filter(FilterExpr::And(vec![
        field("done", FieldOp::Equal, Value::Boolean(false)),
        field("owner", FieldOp::Equal, Value::String("u".to_owned())),
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
        ("owner", IndexFieldMode::Ascending),
        ("done", IndexFieldMode::Ascending),
    ]));
    // Equality fields may appear in any order in the index.
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
        field("owner", FieldOp::Equal, Value::String("u".to_owned())),
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
fn conservative_accept_implies_reference_support() {
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
        field("owner", FieldOp::Equal, Value::String("u".to_owned())),
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
