//! `firestore.missingIndexes: "report"` under the strict profile: the gateway serves a query
//! production refuses for a missing composite index, keeps every other strict check, and
//! reports the index once per database in production's words.

use fireemu_adapter_grpc::gateway::{
    database_name, missing_index_reports, Gateway, MISSING_INDEX_REPORTED,
};
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDecision, IndexSet, IndexValidationPolicy, PlanningContext,
};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{
    Cursor, Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};

fn gateway(policy: IndexValidationPolicy) -> Gateway {
    Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy,
        },
        indexes: IndexSet::default(),
    }
}

fn field(path: &str, op: FieldOp, value: Value) -> FilterExpr {
    FilterExpr::Field {
        field: FieldPath::parse(path).unwrap(),
        op,
        value,
    }
}

/// Equality plus an inequality on another field: production needs a composite index.
fn needs_composite() -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tasks").unwrap(),
    ))
    .with_filter(FilterExpr::And(vec![
        field("done", FieldOp::Equal, Value::Boolean(false)),
        field("priority", FieldOp::GreaterThan, Value::Integer(1)),
    ]))
}

/// Two scalar equalities: production serves it by merging the automatic indexes.
fn merged() -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tasks").unwrap(),
    ))
    .with_filter(FilterExpr::And(vec![
        field("state", FieldOp::Equal, Value::String("open".to_owned())),
        field("owner", FieldOp::Equal, Value::String("u1".to_owned())),
    ]))
}

fn database(id: &str) -> String {
    format!("projects/demo-app/databases/{id}")
}

#[test]
fn report_mode_serves_the_query_production_refuses_and_marks_it() {
    let refusal = gateway(IndexValidationPolicy::Production)
        .validate_query(&needs_composite())
        .unwrap_err();
    assert_eq!(refusal.to_status().code(), tonic::Code::FailedPrecondition);

    let accepted = gateway(IndexValidationPolicy::ProductionReport)
        .validate_query(&needs_composite())
        .expect("report mode runs the query");
    assert!(matches!(
        accepted.decision,
        IndexDecision::AssumedIndex { .. }
    ));
    assert_eq!(accepted.warnings, vec![MISSING_INDEX_REPORTED.to_owned()]);
    assert!(
        accepted.query.production_refusals,
        "the strict profile's canonical query keeps production's refusals"
    );
    assert!(
        accepted.scans.is_some(),
        "Explain describes the assumed index"
    );
}

#[test]
fn report_mode_reports_nothing_production_serves_by_a_merge() {
    let gateway = gateway(IndexValidationPolicy::ProductionReport);
    let accepted = gateway.validate_query(&merged()).unwrap();
    assert!(matches!(
        accepted.decision,
        IndexDecision::MergeIndexes { .. }
    ));
    assert!(accepted.warnings.is_empty());
    let database = database("merged-only");
    gateway.report_missing_index(&database, &accepted);
    assert!(missing_index_reports()
        .iter()
        .all(|report| report.database != database));
}

#[test]
fn only_the_emulator_policy_turns_off_production_refusals() {
    assert!(gateway(IndexValidationPolicy::Production).production_refusals());
    assert!(gateway(IndexValidationPolicy::ProductionReport).production_refusals());
    assert!(!gateway(IndexValidationPolicy::Emulator).production_refusals());
}

#[test]
fn report_mode_keeps_the_strict_cursor_refusal() {
    let document = |relative: &str| {
        DocumentPath::parse(
            &ProjectId::try_new("demo-app").unwrap(),
            &DatabaseId::default_database(),
            relative,
        )
        .unwrap()
    };
    let mistyped = Query {
        start_at: Some(Cursor {
            values: vec![Value::String("c3".to_owned())],
            before: true,
        }),
        ..Query::new(QueryScope::collection(
            Some(document("root/r1")),
            CollectionId::try_new("cur").unwrap(),
        ))
        .with_order(OrderClause {
            field: FieldPath::document_name(),
            direction: Direction::Ascending,
        })
    };
    let rejection = gateway(IndexValidationPolicy::ProductionReport)
        .validate_query(&mistyped)
        .unwrap_err();
    assert_eq!(rejection.to_status().code(), tonic::Code::InvalidArgument);
    gateway(IndexValidationPolicy::Emulator)
        .validate_query(&mistyped)
        .expect("the emulator profile may not add a rejection");
}

#[test]
fn a_reported_index_carries_production_refusal_text_and_the_fragment_once_per_database() {
    let gateway = gateway(IndexValidationPolicy::ProductionReport);
    let accepted = gateway.validate_query(&needs_composite()).unwrap();
    let first = database("reported-a");
    let second = database("reported-b");
    for _ in 0..3 {
        gateway.report_missing_index(&first, &accepted);
    }
    gateway.report_missing_index(&second, &accepted);

    let production = gateway_refusal_message(&first);
    let reports: Vec<_> = missing_index_reports()
        .into_iter()
        .filter(|report| report.database == first || report.database == second)
        .collect();
    assert_eq!(reports.len(), 2, "{reports:?}");
    let IndexDecision::AssumedIndex { requirement } = &accepted.decision else {
        unreachable!()
    };
    let in_first = reports.iter().find(|r| r.database == first).unwrap();
    assert_eq!(in_first.message, production);
    assert_eq!(in_first.fragment, requirement.indexes_json_fragment());
    assert!(
        in_first.message.contains("create_composite="),
        "{}",
        in_first.message
    );
}

#[test]
fn neither_refuse_mode_nor_the_emulator_profile_reports_through_the_strict_registry() {
    let database = database("not-reported");
    let emulator = gateway(IndexValidationPolicy::Emulator);
    let accepted = emulator.validate_query(&needs_composite()).unwrap();
    assert_eq!(
        accepted.warnings,
        vec!["FS_EMULATOR_INDEX_ASSUMED".to_owned()]
    );
    emulator.report_missing_index(&database, &accepted);
    gateway(IndexValidationPolicy::Production).report_missing_index(&database, &accepted);
    assert!(missing_index_reports()
        .iter()
        .all(|report| report.database != database));
}

fn gateway_refusal_message(database: &str) -> String {
    let parent = fireemu_adapter_grpc::decode::Parent {
        project: ProjectId::try_new("demo-app").unwrap(),
        database: DatabaseId::try_new(database.rsplit('/').next().unwrap()).unwrap(),
        document: None,
    };
    assert_eq!(database_name(&parent), database);
    gateway(IndexValidationPolicy::Production)
        .validate_query(&needs_composite())
        .unwrap_err()
        .to_status_in(database)
        .message()
        .to_owned()
}

/// Every query surface (unary, REST, Listen, aggregations) plans through the local backend,
/// which reports with the database it serves.
#[test]
fn the_local_backend_reports_the_query_it_serves_in_report_mode() {
    use fireemu_adapter_grpc::local::LocalBackend;
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_types::time::LogicalInstant;
    use fireemu_proto_firestore::google::firestore::v1 as pb;
    use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;
    use std::sync::{Arc, Mutex};

    let field_filter =
        |path: &str, op: sq::field_filter::Operator, value: pb::value::ValueType| sq::Filter {
            filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
                field: Some(sq::FieldReference {
                    field_path: path.to_owned(),
                }),
                op: op as i32,
                value: Some(pb::Value {
                    value_type: Some(value),
                }),
            })),
        };
    let structured = pb::StructuredQuery {
        from: vec![sq::CollectionSelector {
            collection_id: "tasks".to_owned(),
            all_descendants: false,
        }],
        r#where: Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::And as i32,
                    filters: vec![
                        field_filter(
                            "done",
                            sq::field_filter::Operator::Equal,
                            pb::value::ValueType::BooleanValue(false),
                        ),
                        field_filter(
                            "priority",
                            sq::field_filter::Operator::GreaterThan,
                            pb::value::ValueType::IntegerValue(1),
                        ),
                    ],
                },
            )),
        }),
        ..Default::default()
    };
    let parent = fireemu_adapter_grpc::decode::Parent {
        project: ProjectId::try_new("demo-local").unwrap(),
        database: DatabaseId::default_database(),
        document: None,
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let refuse = LocalBackend::new(gateway(IndexValidationPolicy::Production), clock.clone(), 7);
    assert_eq!(
        refuse
            .accepted_query(&parent, &structured)
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    let report = LocalBackend::new(gateway(IndexValidationPolicy::ProductionReport), clock, 7);
    report.accepted_query(&parent, &structured).unwrap();
    let database = database_name(&parent);
    let reports: Vec<_> = missing_index_reports()
        .into_iter()
        .filter(|r| r.database == database)
        .collect();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(
        reports[0].message,
        refuse
            .accepted_query(&parent, &structured)
            .unwrap_err()
            .message()
    );
}
