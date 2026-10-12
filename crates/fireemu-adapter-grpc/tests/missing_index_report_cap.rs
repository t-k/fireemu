//! The list of reported missing indexes is bounded, and an index past the bound is neither
//! listed nor logged again on every query. Its own test binary: it fills the process-wide list.

use fireemu_adapter_grpc::gateway::{missing_index_reports, Gateway};
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;

#[test]
fn the_report_list_stops_at_its_bound() {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::ProductionReport,
        },
        indexes: IndexSet::default(),
    };
    let field = |path: &str, op, value| FilterExpr::Field {
        field: FieldPath::parse(path).unwrap(),
        op,
        value,
    };
    let accepted = gateway
        .validate_query(
            &Query::new(QueryScope::collection(
                None,
                CollectionId::try_new("tasks").unwrap(),
            ))
            .with_filter(FilterExpr::And(vec![
                field("done", FieldOp::Equal, Value::Boolean(false)),
                field("priority", FieldOp::GreaterThan, Value::Integer(1)),
            ])),
        )
        .unwrap();
    let database = |n: usize| format!("projects/demo-cap/databases/db-{n}");
    for n in 0..1000 {
        let line = gateway
            .report_missing_index(&database(n), &accepted)
            .unwrap();
        assert!(
            line.starts_with(&format!("[firestore] {}: ", database(n))),
            "{line}"
        );
    }
    assert_eq!(
        gateway.report_missing_index(&database(999), &accepted),
        None
    );
    // The first index past the bound says so once; later ones are quiet.
    let over = gateway
        .report_missing_index(&database(1000), &accepted)
        .unwrap();
    assert!(
        over.contains("more than 1000 distinct missing composite indexes"),
        "{over}"
    );
    assert_eq!(
        gateway.report_missing_index(&database(1000), &accepted),
        None
    );
    assert_eq!(
        gateway.report_missing_index(&database(1001), &accepted),
        None
    );
    let reports = missing_index_reports();
    assert_eq!(reports.len(), 1000);
    assert_eq!(reports[999].database, database(999));
    assert!(reports
        .iter()
        .all(|r| r.database != database(1000) && r.database != database(1001)));
}
