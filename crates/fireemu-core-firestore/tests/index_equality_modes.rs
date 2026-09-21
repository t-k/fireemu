//! A vector index is not an ordered index for ordinary equality clauses.
//! These are local planner regressions, not production observation receipts.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    decide, validate_aggregation_query, IndexDecision, IndexDefinition, IndexField, IndexFieldMode,
    IndexQueryScope, IndexSet, IndexValidationPolicy, PlanningContext,
};
use fireemu_core_firestore::query::{
    DistanceMeasure, FieldOp, FilterExpr, FindNearest, Query, QueryScope,
};
use fireemu_core_firestore::store::Aggregation;
use fireemu_core_firestore::value::Value;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;

fn collection() -> CollectionId {
    CollectionId::try_new("mode-regression").unwrap()
}

fn fp(name: &str) -> FieldPath {
    FieldPath::parse(name).unwrap()
}

fn context() -> PlanningContext {
    PlanningContext {
        edition: FirestoreEdition::Standard,
        api_mode: FirestoreApiMode::Native,
        policy: IndexValidationPolicy::Production,
    }
}

fn query(scope: IndexQueryScope, fields: &[&str]) -> Query {
    let scope = match scope {
        IndexQueryScope::Collection => QueryScope::collection(None, collection()),
        IndexQueryScope::CollectionGroup => QueryScope::collection_group(collection()),
    };
    let query = Query::new(scope);
    if fields.is_empty() {
        return query.canonicalize().unwrap();
    }
    query
        .with_filter(FilterExpr::And(
            fields
                .iter()
                .map(|name| FilterExpr::Field {
                    field: fp(name),
                    op: FieldOp::Equal,
                    // A field with a vector index may also contain a non-vector value.
                    value: Value::String("ordinary-scalar".to_owned()),
                })
                .collect(),
        ))
        .canonicalize()
        .unwrap()
}

fn index(scope: IndexQueryScope, fields: &[(&str, IndexFieldMode)]) -> IndexDefinition {
    IndexDefinition {
        collection_group: collection(),
        query_scope: scope,
        fields: fields
            .iter()
            .map(|(name, mode)| IndexField {
                path: fp(name),
                mode: *mode,
            })
            .collect(),
    }
}

fn no_automatic_indexes() -> IndexSet {
    let mut indexes = IndexSet::default();
    indexes.set_default_single_field_indexes(&collection(), vec![]);
    indexes
}

const SCOPES: [IndexQueryScope; 2] = [
    IndexQueryScope::Collection,
    IndexQueryScope::CollectionGroup,
];
const VECTOR: IndexFieldMode = IndexFieldMode::Vector { dimension: 2 };

#[test]
fn vector_only_index_does_not_serve_scalar_equality() {
    for scope in SCOPES {
        let mut indexes = no_automatic_indexes();
        indexes.add_composite(index(scope, &[("embedding", VECTOR)]));
        assert!(matches!(
            decide(&query(scope, &["embedding"]), &indexes, &context()),
            IndexDecision::MissingRequired { .. }
        ));
    }
}

#[test]
fn prefiltered_vector_index_does_not_serve_equality_on_its_vector_field() {
    for scope in SCOPES {
        let mut indexes = no_automatic_indexes();
        indexes.add_composite(index(
            scope,
            &[
                ("category", IndexFieldMode::Ascending),
                ("embedding", VECTOR),
            ],
        ));
        assert!(matches!(
            decide(
                &query(scope, &["category", "embedding"]),
                &indexes,
                &context()
            ),
            IndexDecision::MissingRequired { .. }
        ));
    }
}

#[test]
fn an_index_merge_cannot_cover_an_equality_field_with_vector_mode() {
    for scope in SCOPES {
        let mut indexes = no_automatic_indexes();
        indexes.add_composite(index(
            scope,
            &[
                ("category", IndexFieldMode::Ascending),
                ("embedding", VECTOR),
            ],
        ));
        indexes.set_single_field_indexes(
            &collection(),
            &fp("tag"),
            vec![(scope, IndexFieldMode::Ascending)],
        );
        assert!(matches!(
            decide(
                &query(scope, &["category", "embedding", "tag"]),
                &indexes,
                &context(),
            ),
            IndexDecision::MissingRequired { .. }
        ));
    }
}

#[test]
fn either_ordered_mode_still_serves_an_equality_prefix() {
    for scope in SCOPES {
        for a in [IndexFieldMode::Ascending, IndexFieldMode::Descending] {
            for b in [IndexFieldMode::Ascending, IndexFieldMode::Descending] {
                let mut indexes = no_automatic_indexes();
                let ordered = index(
                    scope,
                    &[
                        ("embedding", a),
                        ("category", b),
                        ("__name__", IndexFieldMode::Ascending),
                    ],
                );
                indexes.add_composite(ordered.clone());
                let decision = decide(
                    &query(scope, &["category", "embedding"]),
                    &indexes,
                    &context(),
                );
                assert!(matches!(decision, IndexDecision::UseIndex { index } if index == ordered));
            }
        }
    }
}

#[test]
fn contains_mode_remains_ineligible_for_scalar_equality() {
    for scope in SCOPES {
        let mut indexes = no_automatic_indexes();
        indexes.add_composite(index(scope, &[("embedding", IndexFieldMode::Contains)]));
        assert!(matches!(
            decide(&query(scope, &["embedding"]), &indexes, &context()),
            IndexDecision::MissingRequired { .. }
        ));
    }
}

#[test]
fn a_vector_candidate_does_not_hide_a_later_valid_scalar_index() {
    for scope in SCOPES {
        let mut indexes = no_automatic_indexes();
        indexes.add_composite(index(
            scope,
            &[
                ("category", IndexFieldMode::Ascending),
                ("embedding", VECTOR),
            ],
        ));
        let scalar = index(
            scope,
            &[
                ("category", IndexFieldMode::Ascending),
                ("embedding", IndexFieldMode::Ascending),
            ],
        );
        indexes.add_composite(scalar.clone());
        let decision = decide(
            &query(scope, &["category", "embedding"]),
            &indexes,
            &context(),
        );
        assert!(matches!(decision, IndexDecision::UseIndex { index } if index == scalar));
    }
}

#[test]
fn scalar_index_merging_still_works_beside_an_unrelated_vector_index() {
    for scope in SCOPES {
        let mut indexes = no_automatic_indexes();
        indexes.add_composite(index(scope, &[("embedding", VECTOR)]));
        for field in ["category", "embedding"] {
            indexes.set_single_field_indexes(
                &collection(),
                &fp(field),
                vec![(scope, IndexFieldMode::Ascending)],
            );
        }
        let decision = decide(
            &query(scope, &["category", "embedding"]),
            &indexes,
            &context(),
        );
        let IndexDecision::MergeIndexes { indexes } = decision else {
            panic!("expected scalar index merging, got {decision:?}");
        };
        assert_eq!(indexes.len(), 2);
        assert!(indexes.iter().flat_map(|i| &i.fields).all(|f| {
            matches!(
                f.mode,
                IndexFieldMode::Ascending | IndexFieldMode::Descending
            )
        }));
    }
}

#[test]
fn vector_nearest_planning_is_unchanged_with_and_without_a_scalar_prefilter() {
    for scope in SCOPES {
        for prefiltered in [false, true] {
            let mut indexes = no_automatic_indexes();
            let fields = if prefiltered {
                vec![
                    ("category", IndexFieldMode::Ascending),
                    ("embedding", VECTOR),
                ]
            } else {
                vec![("embedding", VECTOR)]
            };
            let vector = index(scope, &fields);
            indexes.add_composite(vector.clone());
            let equalities: &[&str] = if prefiltered { &["category"] } else { &[] };
            let nearest = query(scope, equalities)
                .with_find_nearest(FindNearest {
                    vector_field: fp("embedding"),
                    query_vector: vec![1.0, 2.0],
                    distance_measure: DistanceMeasure::Euclidean,
                    limit: 5,
                    distance_result_field: None,
                    distance_threshold: None,
                })
                .canonicalize()
                .unwrap();
            assert!(matches!(
                decide(&nearest, &indexes, &context()),
                IndexDecision::UseIndex { index } if index == vector
            ));
        }
    }
}

#[test]
fn count_with_a_scalar_equality_filter_also_needs_an_ordered_index() {
    for scope in SCOPES {
        let mut indexes = no_automatic_indexes();
        indexes.add_composite(index(scope, &[("embedding", VECTOR)]));
        let aggregation = [Aggregation::Count { up_to: None }];
        assert!(matches!(
            validate_aggregation_query(
                &query(scope, &["embedding"]),
                &aggregation,
                &indexes,
                &context(),
            ),
            IndexDecision::MissingRequired { .. }
        ));
    }
}
