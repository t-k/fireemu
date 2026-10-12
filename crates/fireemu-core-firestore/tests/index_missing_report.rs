//! `IndexValidationPolicy::ProductionReport` (`firestore.missingIndexes: "report"` under the
//! strict profile): production's planning decides whether a query has an index, including the
//! merges production performs, and only a query production would refuse for a missing
//! composite index is served as if the index existed.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    decide, plan_scans, IndexDecision, IndexDefinition, IndexField, IndexFieldMode,
    IndexQueryScope, IndexSet, IndexValidationPolicy, PlanningContext, SingleFieldExemption,
};
use fireemu_core_firestore::query::{
    Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;
use proptest::prelude::*;

fn fp(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}

fn tasks() -> CollectionId {
    CollectionId::try_new("tasks").unwrap()
}

fn ctx(edition: FirestoreEdition, policy: IndexValidationPolicy) -> PlanningContext {
    PlanningContext {
        edition,
        api_mode: FirestoreApiMode::Native,
        policy,
    }
}

fn field(path: &str, op: FieldOp, value: Value) -> FilterExpr {
    FilterExpr::Field {
        field: fp(path),
        op,
        value,
    }
}

/// Production's decision with its one refusal turned into an assumption: what report mode
/// must answer for every query.
fn reported(production: IndexDecision) -> IndexDecision {
    match production {
        IndexDecision::MissingRequired { requirement } => {
            IndexDecision::AssumedIndex { requirement }
        }
        other => other,
    }
}

#[test]
fn report_mode_serves_a_query_production_refuses_and_names_the_same_index() {
    let query = Query::new(QueryScope::collection(None, tasks()))
        .with_filter(FilterExpr::And(vec![
            field("done", FieldOp::Equal, Value::Boolean(false)),
            field("owner", FieldOp::GreaterThan, Value::String("u".to_owned())),
        ]))
        .canonicalize()
        .unwrap();
    let indexes = IndexSet::default();
    let standard = |policy| ctx(FirestoreEdition::Standard, policy);
    let IndexDecision::MissingRequired { requirement } = decide(
        &query,
        &indexes,
        &standard(IndexValidationPolicy::Production),
    ) else {
        panic!("production refuses the query");
    };
    assert_eq!(
        decide(
            &query,
            &indexes,
            &standard(IndexValidationPolicy::ProductionReport)
        ),
        IndexDecision::AssumedIndex { requirement }
    );
}

#[test]
fn report_mode_keeps_production_merges_where_the_emulator_policy_assumes() {
    // Two scalar equality filters: production merges the automatic indexes, so nothing is
    // missing and nothing may be reported. The emulator policy does not model merges.
    let query = Query::new(QueryScope::collection(None, tasks()))
        .with_filter(FilterExpr::And(vec![
            field("state", FieldOp::Equal, Value::String("open".to_owned())),
            field("owner", FieldOp::Equal, Value::String("u1".to_owned())),
        ]))
        .canonicalize()
        .unwrap();
    let indexes = IndexSet::default();
    let standard = |policy| ctx(FirestoreEdition::Standard, policy);
    assert!(matches!(
        decide(
            &query,
            &indexes,
            &standard(IndexValidationPolicy::ProductionReport)
        ),
        IndexDecision::MergeIndexes { .. }
    ));
    assert!(matches!(
        decide(&query, &indexes, &standard(IndexValidationPolicy::Emulator)),
        IndexDecision::AssumedIndex { .. }
    ));
}

#[test]
fn report_mode_on_enterprise_plans_the_full_scan_production_plans() {
    let query = Query::new(QueryScope::collection(None, tasks()))
        .with_filter(FilterExpr::And(vec![
            field("done", FieldOp::Equal, Value::Boolean(false)),
            field("owner", FieldOp::GreaterThan, Value::String("u".to_owned())),
        ]))
        .canonicalize()
        .unwrap();
    let indexes = IndexSet::default();
    let enterprise = |policy| ctx(FirestoreEdition::Enterprise, policy);
    assert!(matches!(
        decide(
            &query,
            &indexes,
            &enterprise(IndexValidationPolicy::ProductionReport)
        ),
        IndexDecision::FullScanAllowed { .. }
    ));
}

#[test]
fn only_the_emulator_policy_drops_the_production_rules() {
    assert!(IndexValidationPolicy::Production.production_rules());
    assert!(IndexValidationPolicy::ProductionReport.production_rules());
    assert!(!IndexValidationPolicy::Emulator.production_rules());
    assert!(!IndexValidationPolicy::Production.assumes_missing_indexes());
    assert!(IndexValidationPolicy::ProductionReport.assumes_missing_indexes());
    assert!(IndexValidationPolicy::Emulator.assumes_missing_indexes());
}

const FIELDS: &[&str] = &["a", "b", "c", "tags"];

fn arb_field() -> impl Strategy<Value = &'static str> {
    prop::sample::select(FIELDS)
}

fn arb_filter() -> impl Strategy<Value = FilterExpr> {
    (arb_field(), 0..6usize, 0..3i64).prop_map(|(path, op, n)| match op {
        0 => field(path, FieldOp::Equal, Value::Integer(n)),
        1 => field(path, FieldOp::GreaterThan, Value::Integer(n)),
        2 => field(path, FieldOp::LessThanOrEqual, Value::Integer(n)),
        3 => field(path, FieldOp::ArrayContains, Value::Integer(n)),
        4 => field(
            path,
            FieldOp::In,
            Value::Array(vec![Value::Integer(n), Value::Integer(n + 1)]),
        ),
        _ => field(path, FieldOp::NotEqual, Value::Integer(n)),
    })
}

fn arb_order() -> impl Strategy<Value = OrderClause> {
    (
        prop::sample::select(&["a", "b", "c", "__name__"][..]),
        any::<bool>(),
    )
        .prop_map(|(path, descending)| OrderClause {
            field: fp(path),
            direction: if descending {
                Direction::Descending
            } else {
                Direction::Ascending
            },
        })
}

fn arb_mode() -> impl Strategy<Value = IndexFieldMode> {
    prop_oneof![
        Just(IndexFieldMode::Ascending),
        Just(IndexFieldMode::Descending),
        Just(IndexFieldMode::Contains),
    ]
}

fn arb_indexes() -> impl Strategy<Value = IndexSet> {
    let composite = (
        any::<bool>(),
        prop::collection::vec((arb_field(), arb_mode()), 2..4),
    )
        .prop_map(|(group, fields)| IndexDefinition {
            collection_group: tasks(),
            query_scope: if group {
                IndexQueryScope::CollectionGroup
            } else {
                IndexQueryScope::Collection
            },
            fields: fields
                .into_iter()
                .map(|(path, mode)| IndexField {
                    path: fp(path),
                    mode,
                })
                .collect(),
        });
    (
        prop::collection::vec(composite, 0..4),
        prop::collection::vec((arb_field(), any::<bool>()), 0..2),
    )
        .prop_map(|(composites, exemptions)| {
            let mut set = IndexSet::default();
            for index in composites {
                set.add_composite(index);
            }
            for (path, group) in exemptions {
                set.add_exemption(&SingleFieldExemption {
                    collection_group: tasks(),
                    field: fp(path),
                    query_scope: if group {
                        IndexQueryScope::CollectionGroup
                    } else {
                        IndexQueryScope::Collection
                    },
                });
            }
            set
        })
}

/// Scalar equality conjunctions, the shape production merges, are drawn as often as the rest.
fn arb_query() -> impl Strategy<Value = Query> {
    let equality =
        (arb_field(), 0..3i64).prop_map(|(path, n)| field(path, FieldOp::Equal, Value::Integer(n)));
    let filters = prop_oneof![
        prop::collection::vec(arb_filter(), 0..4),
        prop::collection::vec(equality, 2..4),
    ];
    let orders = prop_oneof![
        prop::collection::vec(arb_order(), 0..3),
        prop::collection::vec(
            (any::<bool>()).prop_map(|descending| OrderClause {
                field: fp("__name__"),
                direction: if descending {
                    Direction::Descending
                } else {
                    Direction::Ascending
                },
            }),
            0..2,
        ),
    ];
    (any::<bool>(), filters, any::<bool>(), orders).prop_map(|(group, filters, or, orders)| {
        let scope = if group {
            QueryScope::collection_group(tasks())
        } else {
            QueryScope::collection(None, tasks())
        };
        let mut query = Query::new(scope);
        if !filters.is_empty() {
            query = query.with_filter(if or {
                FilterExpr::Or(filters)
            } else {
                FilterExpr::And(filters)
            });
        }
        for order in orders {
            query = query.with_order(order);
        }
        query
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Report mode is production's decision with the missing-index refusal replaced by an
    /// assumption of the same index, on both editions: it never reports a query production
    /// serves (by one index or by a merge) and never serves one through a different plan.
    #[test]
    fn report_mode_is_production_with_the_refusal_turned_into_an_assumption(
        query in arb_query(),
        indexes in arb_indexes(),
        enterprise in any::<bool>(),
    ) {
        let Ok(query) = query.canonicalize() else {
            return Ok(());
        };
        let edition = if enterprise {
            FirestoreEdition::Enterprise
        } else {
            FirestoreEdition::Standard
        };
        let production = ctx(edition, IndexValidationPolicy::Production);
        let report = ctx(edition, IndexValidationPolicy::ProductionReport);
        let refused = decide(&query, &indexes, &production);
        let served = decide(&query, &indexes, &report);
        prop_assert_eq!(&served, &reported(refused.clone()));
        if !matches!(refused, IndexDecision::MissingRequired { .. }) {
            prop_assert_eq!(
                plan_scans(&query, &[], &indexes, &report),
                plan_scans(&query, &[], &indexes, &production)
            );
        }
    }
}
