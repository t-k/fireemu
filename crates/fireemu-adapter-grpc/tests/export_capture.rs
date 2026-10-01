//! What an export reads from the backend: every owned database's live documents, as the
//! allocations the stores hold, matching the visible snapshot an export used to copy.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::tenancy::Scope;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;

fn backend() -> LocalBackend {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    LocalBackend::new(
        gateway,
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    )
    .with_declared_databases(["analytics".to_owned()])
}

fn write(backend: &LocalBackend, project: &str, database: &str, document: &str, delete: bool) {
    let name = format!("projects/{project}/databases/{database}/documents/{document}");
    let operation = if delete {
        pb::write::Operation::Delete(name)
    } else {
        pb::write::Operation::Update(pb::Document {
            name,
            fields: [(
                "v".to_owned(),
                pb::Value {
                    value_type: Some(pb::value::ValueType::StringValue(document.to_owned())),
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        })
    };
    backend
        .commit_with(
            &pb::CommitRequest {
                database: format!("projects/{project}/databases/{database}"),
                writes: vec![pb::Write {
                    operation: Some(operation),
                    ..Default::default()
                }],
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
}

#[test]
fn live_document_handles_match_the_visible_snapshot_of_every_owned_database() {
    let backend = backend();
    for (project, database, document) in [
        ("demo-b", "(default)", "items/2"),
        ("demo-a", "(default)", "items/1"),
        ("demo-a", "analytics", "events/e"),
        ("demo-a", "(default)", "items/gone"),
    ] {
        write(&backend, project, database, document, false);
    }
    write(&backend, "demo-a", "(default)", "items/gone", true);

    let scope = Scope::AllExcept(std::collections::BTreeSet::new());
    let handles = backend.live_document_handles(&scope);
    let snapshot = backend.snapshot_scope(&scope);
    assert_eq!(
        handles.keys().collect::<Vec<_>>(),
        snapshot.databases.keys().collect::<Vec<_>>()
    );
    for (key, state) in snapshot.databases {
        assert_eq!(
            handles[&key]
                .iter()
                .map(|document| document.as_ref().clone())
                .collect::<Vec<_>>(),
            state.into_documents(),
            "{key:?}"
        );
    }
    assert_eq!(
        handles[&("demo-a".to_owned(), "(default)".to_owned())].len(),
        1
    );
}
