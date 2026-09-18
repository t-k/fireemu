//! Time-to-live field configuration and the expiry sweep it drives (`FS-CONFIG-RT-004`).
//!
//! The sweep runs on the virtual clock. An expired document stays readable until the sweep
//! reaches it, which is what production's documented deletion delay means for a client.

// `tonic::Status` is the error type of the backend's own closures.
#![allow(clippy::result_large_err)]

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::ttl::TtlState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use fireemu_proto_firestore::google::firestore::v1 as pb;

const PROJECT: &str = "demo-app";
const DATABASE: &str = "(default)";
const DB: &str = "projects/demo-app/databases/(default)";

fn backend(start: LogicalInstant) -> (Arc<LocalBackend>, Arc<Mutex<VirtualClock>>) {
    let clock = Arc::new(Mutex::new(VirtualClock::new(start)));
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let backend = LocalBackend::new(gateway, Arc::clone(&clock), 7)
        .with_ttl_sweep_interval(LogicalDuration::from_seconds(86_400));
    (Arc::new(backend), clock)
}

fn group(name: &str) -> CollectionId {
    CollectionId::try_new(name).expect("collection id")
}

fn field(name: &str) -> FieldPath {
    FieldPath::parse(name).expect("field path")
}

fn timestamp(seconds: i64) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::TimestampValue(
            prost_types::Timestamp { seconds, nanos: 0 },
        )),
    }
}

fn write_document(backend: &LocalBackend, relative: &str, expires_at: Option<pb::Value>) {
    let fields = expires_at
        .map(|value| [("expiresAt".to_owned(), value)].into_iter().collect())
        .unwrap_or_default();
    backend
        .commit(&pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{DB}/documents/{relative}"),
                    fields,
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .expect("commit");
}

fn exists(backend: &LocalBackend, relative: &str) -> bool {
    backend
        .get_document(
            &pb::GetDocumentRequest {
                name: format!("{DB}/documents/{relative}"),
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .is_ok()
}

#[test]
fn an_expired_document_stays_readable_until_the_sweep_interval_elapses() {
    let (backend, clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(LogicalInstant::from_unix_seconds(1_000));

    // One second after expiry the document is gone in no emulator and in no production
    // project: the deletion is asynchronous and bounded by the sweep interval.
    clock
        .lock()
        .expect("clock")
        .advance_to(LogicalInstant::from_unix_seconds(1_101))
        .expect("advance");
    assert_eq!(
        backend.sweep_expired_documents(LogicalInstant::from_unix_seconds(1_101)),
        0
    );
    assert!(exists(&backend, "sessions/s1"));

    // One interval after the baseline the sweep runs and the expired document is deleted.
    let due = LogicalInstant::from_unix_seconds(1_000 + 86_400);
    clock
        .lock()
        .expect("clock")
        .advance_to(due)
        .expect("advance");
    assert_eq!(backend.sweep_expired_documents(due), 1);
    assert!(!exists(&backend, "sessions/s1"));
}

#[test]
fn an_unexpired_document_survives_a_sweep() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/future", Some(timestamp(9_000_000)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(LogicalInstant::from_unix_seconds(1_000));
    let due = LogicalInstant::from_unix_seconds(1_000 + 86_400);
    assert_eq!(backend.sweep_expired_documents(due), 0);
    assert!(exists(&backend, "sessions/future"));
}

#[test]
fn a_non_timestamp_ttl_value_is_ignored_rather_than_deleted() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(
        &backend,
        "sessions/text",
        Some(pb::Value {
            value_type: Some(pb::value::ValueType::StringValue("1970-01-01".to_owned())),
        }),
    );
    write_document(&backend, "sessions/absent", None);
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend.sweep_expired_documents_now(LogicalInstant::from_unix_seconds(9_000_000)),
        0
    );
    assert!(exists(&backend, "sessions/text"));
    assert!(exists(&backend, "sessions/absent"));
}

#[test]
fn an_immediate_sweep_deletes_without_waiting_for_the_interval() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend.sweep_expired_documents_now(LogicalInstant::from_unix_seconds(1_101)),
        1
    );
    assert!(!exists(&backend, "sessions/s1"));
}

#[test]
fn a_sweep_deletes_only_the_configured_collection_group() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    write_document(&backend, "orders/o1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend.sweep_expired_documents_now(LogicalInstant::from_unix_seconds(1_101)),
        1
    );
    assert!(!exists(&backend, "sessions/s1"));
    assert!(exists(&backend, "orders/o1"));
}

#[test]
fn a_subcollection_of_the_same_name_is_swept_as_one_collection_group() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "users/u1/sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend.sweep_expired_documents_now(LogicalInstant::from_unix_seconds(1_101)),
        1
    );
    assert!(!exists(&backend, "users/u1/sessions/s1"));
}

#[test]
fn removing_the_policy_stops_the_sweep() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    assert_eq!(
        backend
            .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
            .expect("enable ttl"),
        TtlState::Active
    );
    assert!(backend.disable_ttl(PROJECT, DATABASE, &group("sessions"), &field("expiresAt")));
    backend.start_ttl_sweeps(LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend.sweep_expired_documents_now(LogicalInstant::from_unix_seconds(9_000_000)),
        0
    );
    assert!(exists(&backend, "sessions/s1"));
}

#[test]
fn a_swept_deletion_is_published_to_listeners() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(LogicalInstant::from_unix_seconds(1_000));
    let mut commits = backend.subscribe();
    assert_eq!(
        backend.sweep_expired_documents_now(LogicalInstant::from_unix_seconds(1_101)),
        1
    );
    let notification = commits.try_recv().expect("a commit notification");
    assert_eq!(notification.project, PROJECT);
    assert_eq!(notification.database, DATABASE);
}

#[test]
fn the_catalog_is_recorded_per_project_and_database() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    assert_eq!(
        backend
            .ttl_catalog(PROJECT, DATABASE)
            .state(&group("sessions"), &field("expiresAt")),
        Some(TtlState::Active)
    );
    assert!(backend.ttl_catalog("other-project", DATABASE).is_empty());
    assert!(backend.ttl_catalog(PROJECT, "other").is_empty());
}

#[test]
fn a_recorded_operation_can_be_polled_by_the_name_the_patch_returned() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    let name = backend.record_field_operation(
        PROJECT,
        DATABASE,
        "projects/demo-app/databases/(default)/collectionGroups/sessions/fields/expiresAt",
        LogicalInstant::from_unix_seconds(1_000),
    );
    assert!(name.starts_with("projects/demo-app/databases/(default)/operations/"));
    let operation = backend.field_operation(&name).expect("operation");
    assert_eq!(operation.name, name);
    assert_eq!(backend.field_operation("projects/x/operations/y"), None);
}

#[test]
fn the_operation_record_is_bounded() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    let mut first = String::new();
    for i in 0..(fireemu_adapter_grpc::local::FIELD_OPERATIONS_RETAINED + 10) {
        let name = backend.record_field_operation(
            PROJECT,
            DATABASE,
            &format!("field-{i}"),
            LogicalInstant::from_unix_seconds(1_000),
        );
        if i == 0 {
            first = name;
        }
    }
    assert_eq!(
        backend.field_operations().len(),
        fireemu_adapter_grpc::local::FIELD_OPERATIONS_RETAINED
    );
    assert_eq!(backend.field_operation(&first), None);
}
