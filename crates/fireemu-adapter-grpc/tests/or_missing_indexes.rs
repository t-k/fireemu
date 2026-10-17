//! Every missing OR branch is diagnosed without changing the SDK's first refusal.

use fireemu_adapter_grpc::gateway::{missing_index_reports, Gateway};
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    decide, IndexDecision, IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
    IndexValidationPolicy, PlanningContext,
};
use fireemu_core_firestore::query::{
    Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;

fn query() -> Query {
    let filter = |name, value: &str| FilterExpr::Field {
        field: FieldPath::parse(name).unwrap(),
        op: FieldOp::Equal,
        value: Value::String(value.into()),
    };
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("useGetDocsTest").unwrap(),
    ))
    .with_filter(FilterExpr::Or(vec![
        filter("content", "foo"),
        filter("status", "published"),
        filter("content", "bar"),
    ]))
    .with_order(OrderClause {
        field: FieldPath::parse("createdAt").unwrap(),
        direction: Direction::Descending,
    })
}

fn index(name: &str) -> IndexDefinition {
    IndexDefinition {
        collection_group: CollectionId::try_new("useGetDocsTest").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: [
            (name, IndexFieldMode::Ascending),
            ("createdAt", IndexFieldMode::Descending),
            ("__name__", IndexFieldMode::Descending),
        ]
        .into_iter()
        .map(|(path, mode)| IndexField {
            path: FieldPath::parse(path).unwrap(),
            mode,
        })
        .collect(),
    }
}

#[test]
fn or_diagnostics_include_each_missing_index_once() {
    if let Ok(case) = std::env::var("FIREEMU_OR_DIAGNOSTIC_CASE") {
        let (profile, mask) = case.split_once(':').unwrap();
        let mask: u8 = mask.parse().unwrap();
        let policy = match profile {
            "strict" => IndexValidationPolicy::Production,
            "report" => IndexValidationPolicy::ProductionReport,
            _ => IndexValidationPolicy::Emulator,
        };
        let mut gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy,
            },
            indexes: IndexSet::default(),
        };
        for (bit, name) in [(1, "content"), (2, "status")] {
            if mask & bit != 0 {
                gateway.indexes.add_composite(index(name));
            }
        }
        let q = query();
        for _ in 0..2 {
            let result = gateway.validate_query(&q);
            if profile == "strict" && mask != 3 {
                let rejection = result.unwrap_err();
                let IndexDecision::MissingRequired { requirement } =
                    decide(&q.canonicalize().unwrap(), &gateway.indexes, &gateway.ctx)
                else {
                    panic!("missing index expected")
                };
                let expected = fireemu_adapter_grpc::index_messages::missing_index_message(
                    "projects/test/databases/(default)",
                    &requirement,
                    false,
                );
                let status = rejection.to_status_in("projects/test/databases/(default)");
                assert_eq!(status.code(), tonic::Code::FailedPrecondition);
                assert_eq!(status.message(), expected);
            } else {
                let accepted = result.unwrap();
                gateway.report_missing_index("projects/test/databases/(default)", &accepted);
            }
        }
        if profile == "report" {
            let reports = missing_index_reports();
            assert_eq!(reports.len(), 2 - mask.count_ones() as usize);
            for (bit, name) in [(1, "content"), (2, "status")] {
                assert_eq!(
                    reports
                        .iter()
                        .any(|r| r.fragment == index(name).indexes_json_fragment()),
                    mask & bit == 0
                );
            }
        }
        return;
    }
    for profile in ["strict", "emulator", "report"] {
        for mask in 0..4 {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "or_diagnostics_include_each_missing_index_once",
                    "--nocapture",
                ])
                .env("FIREEMU_OR_DIAGNOSTIC_CASE", format!("{profile}:{mask}"))
                .output()
                .unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                output.status.success(),
                "{profile}:{mask}\n{stderr}\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
            for (bit, name) in [(1, "content"), (2, "status")] {
                assert_eq!(
                    stderr
                        .matches(&format!("\"fieldPath\": \"{name}\""))
                        .count(),
                    usize::from(mask & bit == 0),
                    "{profile}:{mask}: {stderr}"
                );
            }
            if profile == "strict" {
                assert!(!stderr.contains("served without"), "{stderr}");
            }
        }
    }
}

#[test]
fn report_overflow_counts_queries_not_or_branches() {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::ProductionReport,
        },
        indexes: IndexSet::default(),
    };
    let accepted = gateway.validate_query(&query()).unwrap();
    for n in 0..500 {
        gateway.report_missing_index(&format!("projects/or-cap/databases/db-{n}"), &accepted);
    }
    assert_eq!(missing_index_reports().len(), 1000);
    let database = "projects/or-cap/databases/overflow";
    assert!(gateway.report_missing_index(database, &accepted).is_some());
    assert!(gateway.report_missing_index(database, &accepted).is_none());
    assert_eq!(
        fireemu_adapter_grpc::gateway::missing_index_dropped(Some("or-cap")),
        2
    );
    // Clear the second project's counter between formatting its OR branches. Formatting is
    // outside the batch lock, so clearing cannot erase only part of a query's accounting.
    let mut formatted = 0;
    gateway.report_missing_index_as(
        "projects/or-cap-clear/databases/(default)",
        &accepted,
        |_, _| {
            formatted += 1;
            if formatted == 2 {
                std::thread::spawn(|| {
                    fireemu_adapter_grpc::gateway::clear_missing_index_reports(Some(
                        "or-cap-clear",
                    ));
                })
                .join()
                .unwrap();
            }
            "missing index".to_owned()
        },
    );
    assert_eq!(formatted, 2);
    assert_eq!(
        fireemu_adapter_grpc::gateway::missing_index_dropped(Some("or-cap-clear")),
        1
    );
}
