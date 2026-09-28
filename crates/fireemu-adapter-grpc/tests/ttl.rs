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
use fireemu_core_session::tenancy::Scope;
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

/// The scope of the default session: every project it was not told to exclude.
fn everything() -> Scope {
    Scope::AllExcept(std::collections::BTreeSet::new())
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
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    // One second after expiry the document is gone in no emulator and in no production
    // project: the deletion is asynchronous and bounded by the sweep interval.
    clock
        .lock()
        .expect("clock")
        .advance_to(LogicalInstant::from_unix_seconds(1_101))
        .expect("advance");
    assert_eq!(
        backend.sweep_expired_documents(&everything(), LogicalInstant::from_unix_seconds(1_101)),
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
    assert_eq!(backend.sweep_expired_documents(&everything(), due), 1);
    assert!(!exists(&backend, "sessions/s1"));
}

/// Deletes one document the way an ordinary client does.
fn delete_document(backend: &LocalBackend, relative: &str) {
    backend
        .delete_document(&pb::DeleteDocumentRequest {
            name: format!("{DB}/documents/{relative}"),
            ..Default::default()
        })
        .expect("delete");
}

/// The creation time of one document, which distinguishes a recreated document from the one
/// a sweep scanned.
fn create_time(backend: &LocalBackend, relative: &str) -> Option<prost_types::Timestamp> {
    backend
        .get_document(
            &pb::GetDocumentRequest {
                name: format!("{DB}/documents/{relative}"),
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .ok()
        .and_then(|document| document.create_time)
}

/// Runs one forced sweep with `between` applied after the candidate scan and before the
/// first deletion, and returns how many documents the sweep deleted.
///
/// This is the window a client writes into in production: the expiry scan has already chosen
/// the document and the deletion has not happened yet. Without the seam the interleaving is a
/// race no test could pin down.
fn sweep_with_write_between(
    backend: &Arc<LocalBackend>,
    now: LogicalInstant,
    between: impl FnOnce(),
) -> usize {
    let (scanned_tx, scanned_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let resume_rx = Mutex::new(resume_rx);
    let sweeper = Arc::clone(backend);
    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            sweeper.sweep_expired_documents_now_with_hook(&everything(), now, &|| {
                scanned_tx.send(()).expect("the sweep reached the seam");
                resume_rx
                    .lock()
                    .expect("resume")
                    .recv()
                    .expect("the test released the seam");
            })
        });
        scanned_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the sweep scanned its candidates");
        between();
        resume_tx.send(()).expect("release the sweep");
        handle.join().expect("the sweep finished")
    })
}

#[test]
fn a_document_whose_ttl_is_extended_after_the_scan_survives_the_sweep() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    let deleted = sweep_with_write_between(
        &backend,
        LogicalInstant::from_unix_seconds(1_101),
        // The client pushes the expiry into the future while the sweep holds the candidate.
        || write_document(&backend, "sessions/s1", Some(timestamp(9_000_000))),
    );

    assert_eq!(deleted, 0);
    assert!(exists(&backend, "sessions/s1"));
}

#[test]
fn a_document_whose_ttl_field_is_cleared_after_the_scan_survives_the_sweep() {
    for (name, value) in [
        ("sessions/removed", None),
        (
            "sessions/nulled",
            Some(pb::Value {
                value_type: Some(pb::value::ValueType::NullValue(0)),
            }),
        ),
    ] {
        let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
        write_document(&backend, name, Some(timestamp(1_100)));
        backend
            .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
            .expect("enable ttl");
        backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

        let deleted =
            sweep_with_write_between(&backend, LogicalInstant::from_unix_seconds(1_101), || {
                write_document(&backend, name, value);
            });

        assert_eq!(deleted, 0, "{name}");
        assert!(exists(&backend, name), "{name}");
    }
}

#[test]
fn a_document_recreated_after_the_scan_is_not_deleted_by_the_sweep() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));
    let scanned = create_time(&backend, "sessions/s1").expect("the scanned document exists");

    let deleted = sweep_with_write_between(
        &backend,
        LogicalInstant::from_unix_seconds(1_101),
        // The path is reused by a document of its own, which the expiry of the document the
        // sweep scanned says nothing about.
        || {
            delete_document(&backend, "sessions/s1");
            write_document(&backend, "sessions/s1", Some(timestamp(9_000_000)));
        },
    );

    assert_eq!(deleted, 0);
    let recreated = create_time(&backend, "sessions/s1").expect("the recreated document exists");
    assert_ne!(recreated, scanned);
}

#[test]
fn an_expired_document_left_alone_during_the_sweep_is_still_deleted() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    write_document(&backend, "sessions/s2", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    // The control of the three cases above: one candidate is extended, the other is left
    // alone, and only the untouched one is deleted.
    let deleted =
        sweep_with_write_between(&backend, LogicalInstant::from_unix_seconds(1_101), || {
            write_document(&backend, "sessions/s1", Some(timestamp(9_000_000)));
        });

    assert_eq!(deleted, 1);
    assert!(exists(&backend, "sessions/s1"));
    assert!(!exists(&backend, "sessions/s2"));
}

#[test]
fn a_policy_disabled_after_the_scan_deletes_nothing_it_had_already_chosen() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    let deleted = sweep_with_write_between(
        &backend,
        LogicalInstant::from_unix_seconds(1_101),
        // The configuration the sweep is applying is withdrawn while it holds the candidate.
        || {
            assert!(backend.disable_ttl(
                PROJECT,
                DATABASE,
                &group("sessions"),
                &field("expiresAt")
            ));
        },
    );

    assert_eq!(deleted, 0);
    assert!(exists(&backend, "sessions/s1"));
}

#[test]
fn a_commit_fault_stops_one_sweep_deletion_and_the_next_candidate_still_goes() {
    use fireemu_core_session::fault::{
        FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
    };

    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    write_document(&backend, "sessions/s2", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    // The sweep draws one commit fault occurrence per candidate, so a rule that fires on the
    // first occurrence stops the first deletion alone.
    let registry = Arc::new(FaultRegistry::new());
    registry
        .default_state()
        .lock()
        .expect("fault state")
        .install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "firestore.commit".into(),
                    nth: Some(1),
                    function: None,
                    event_type: None,
                },
                action: FaultAction::ReturnError {
                    code: "UNAVAILABLE".into(),
                },
            }],
        });
    backend.set_faults(registry);

    assert_eq!(
        backend
            .sweep_expired_documents_now(&everything(), LogicalInstant::from_unix_seconds(1_101)),
        1
    );
    // The candidate the fault took is left for the next sweep rather than reported deleted.
    assert!(exists(&backend, "sessions/s1"));
    assert!(!exists(&backend, "sessions/s2"));

    backend.set_faults(Arc::new(FaultRegistry::new()));
    assert_eq!(
        backend
            .sweep_expired_documents_now(&everything(), LogicalInstant::from_unix_seconds(1_101)),
        1
    );
    assert!(!exists(&backend, "sessions/s1"));
}

#[test]
fn a_policy_moved_to_another_field_after_the_scan_is_evaluated_on_the_new_field() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    let deleted = sweep_with_write_between(
        &backend,
        LogicalInstant::from_unix_seconds(1_101),
        // A collection group carries one policy, so moving it takes a disable and a second
        // enable. The document carries no purgeAt, so the policy now in force expires
        // nothing, even though the field it used to name is still an expired timestamp.
        || {
            assert!(backend.disable_ttl(
                PROJECT,
                DATABASE,
                &group("sessions"),
                &field("expiresAt")
            ));
            backend
                .enable_ttl(PROJECT, DATABASE, group("sessions"), field("purgeAt"))
                .expect("move the policy");
        },
    );

    assert_eq!(deleted, 0);
    assert!(exists(&backend, "sessions/s1"));
}

#[test]
fn an_expiration_offset_extended_after_the_scan_keeps_the_document() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    let deleted = sweep_with_write_between(
        &backend,
        LogicalInstant::from_unix_seconds(1_101),
        // The document is untouched; the policy now pushes its expiration time a week out.
        || {
            backend
                .enable_ttl_with_offset(
                    PROJECT,
                    DATABASE,
                    group("sessions"),
                    field("expiresAt"),
                    Some(LogicalDuration::from_seconds(604_800)),
                )
                .expect("extend the offset");
        },
    );

    assert_eq!(deleted, 0);
    assert!(exists(&backend, "sessions/s1"));
}

#[test]
fn the_expiration_offset_moves_the_instant_the_sweep_deletes_a_document() {
    let week = 604_800;
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/s1", Some(timestamp(1_100)));
    backend
        .enable_ttl_with_offset(
            PROJECT,
            DATABASE,
            group("sessions"),
            field("expiresAt"),
            Some(LogicalDuration::from_seconds(week)),
        )
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    // The expiration time is the stored timestamp plus the offset, so the document that a
    // zero offset would have deleted at 1101 survives until one week later.
    assert_eq!(
        backend
            .sweep_expired_documents_now(&everything(), LogicalInstant::from_unix_seconds(1_101)),
        0
    );
    assert!(exists(&backend, "sessions/s1"));
    assert_eq!(
        backend.sweep_expired_documents_now(
            &everything(),
            LogicalInstant::from_unix_seconds(1_100 + week)
        ),
        0
    );
    assert!(exists(&backend, "sessions/s1"));
    assert_eq!(
        backend.sweep_expired_documents_now(
            &everything(),
            LogicalInstant::from_unix_seconds(1_100 + week + 1)
        ),
        1
    );
    assert!(!exists(&backend, "sessions/s1"));
}

#[test]
fn an_unexpired_document_survives_a_sweep() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    write_document(&backend, "sessions/future", Some(timestamp(9_000_000)));
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));
    let due = LogicalInstant::from_unix_seconds(1_000 + 86_400);
    assert_eq!(backend.sweep_expired_documents(&everything(), due), 0);
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
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend.sweep_expired_documents_now(
            &everything(),
            LogicalInstant::from_unix_seconds(9_000_000)
        ),
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
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend
            .sweep_expired_documents_now(&everything(), LogicalInstant::from_unix_seconds(1_101)),
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
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend
            .sweep_expired_documents_now(&everything(), LogicalInstant::from_unix_seconds(1_101)),
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
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend
            .sweep_expired_documents_now(&everything(), LogicalInstant::from_unix_seconds(1_101)),
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
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));
    assert_eq!(
        backend.sweep_expired_documents_now(
            &everything(),
            LogicalInstant::from_unix_seconds(9_000_000)
        ),
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
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));
    let mut commits = backend.subscribe();
    assert_eq!(
        backend
            .sweep_expired_documents_now(&everything(), LogicalInstant::from_unix_seconds(1_101)),
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
        serde_json::json!({"name": "a field"}),
    );
    assert!(name.starts_with("projects/demo-app/databases/(default)/operations/"));
    let operation = backend.field_operation(PROJECT, &name).expect("operation");
    assert_eq!(operation.name, name);
    assert_eq!(operation.response, serde_json::json!({"name": "a field"}));
    assert_eq!(
        backend.field_operation(PROJECT, "projects/x/operations/y"),
        None
    );
    // The record is per project, so another project never sees it.
    assert_eq!(backend.field_operation("other-project", &name), None);
}

#[test]
fn the_operation_record_is_bounded() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    let mut first = String::new();
    for i in 0..(fireemu_adapter_grpc::local::FIELD_OPERATIONS_RETAINED_PER_PROJECT + 10) {
        let name = backend.record_field_operation(
            PROJECT,
            DATABASE,
            &format!("field-{i}"),
            LogicalInstant::from_unix_seconds(1_000),
            serde_json::Value::Null,
        );
        if i == 0 {
            first = name;
        }
    }
    assert_eq!(
        backend.field_operations(PROJECT).len(),
        fireemu_adapter_grpc::local::FIELD_OPERATIONS_RETAINED_PER_PROJECT
    );
    assert_eq!(backend.field_operation(PROJECT, &first), None);
}

#[test]
fn operation_names_stay_unique_past_the_retention_bound() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    // The clock never moves and the field never changes, so only the ordinal separates one
    // record from the next. It must keep separating them after the bound starts evicting.
    let mut names = std::collections::BTreeSet::new();
    let total = fireemu_adapter_grpc::local::FIELD_OPERATIONS_RETAINED_PER_PROJECT + 2;
    for _ in 0..total {
        names.insert(backend.record_field_operation(
            PROJECT,
            DATABASE,
            "projects/demo-app/databases/(default)/collectionGroups/sessions/fields/expiresAt",
            LogicalInstant::from_unix_seconds(1_000),
            serde_json::Value::Null,
        ));
    }
    assert_eq!(names.len(), total);
}

#[test]
fn the_operation_record_of_one_project_survives_another_projects_patches() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    let mine = backend.record_field_operation(
        PROJECT,
        DATABASE,
        "a field",
        LogicalInstant::from_unix_seconds(1_000),
        serde_json::Value::Null,
    );
    for i in 0..(fireemu_adapter_grpc::local::FIELD_OPERATIONS_RETAINED_PER_PROJECT + 10) {
        backend.record_field_operation(
            "noisy-project",
            DATABASE,
            &format!("field-{i}"),
            LogicalInstant::from_unix_seconds(1_000),
            serde_json::Value::Null,
        );
    }
    assert!(backend.field_operation(PROJECT, &mine).is_some());
    assert_eq!(backend.field_operations(PROJECT).len(), 1);
}

#[test]
fn a_sweep_touches_only_the_projects_its_scope_owns() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    for project in [PROJECT, "other-app"] {
        let db = format!("projects/{project}/databases/(default)");
        backend
            .commit(&pb::CommitRequest {
                database: db.clone(),
                writes: vec![pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{db}/documents/sessions/s1"),
                        fields: [("expiresAt".to_owned(), timestamp(1_100))]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .expect("commit");
        backend
            .enable_ttl(project, DATABASE, group("sessions"), field("expiresAt"))
            .expect("enable ttl");
    }

    let mine = Scope::Project(PROJECT.to_owned());
    assert_eq!(
        backend.sweep_expired_documents_now(&mine, LogicalInstant::from_unix_seconds(1_101)),
        1
    );
    assert!(!exists(&backend, "sessions/s1"));
    // The other project keeps the grace period between expiry and deletion that its own
    // session's clock defines.
    assert!(backend
        .get_document(
            &pb::GetDocumentRequest {
                name: "projects/other-app/databases/(default)/documents/sessions/s1".to_owned(),
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .is_ok());
}

#[test]
fn a_sweep_deletes_at_most_the_configured_batch_and_the_next_one_continues() {
    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    let total = fireemu_adapter_grpc::local::MAX_SWEEP_DELETES_PER_RUN + 5;
    for i in 0..total {
        write_document(&backend, &format!("sessions/s{i}"), Some(timestamp(1_100)));
    }
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    let due = LogicalInstant::from_unix_seconds(1_000 + 86_400);
    assert_eq!(
        backend.sweep_expired_documents(&everything(), due),
        fireemu_adapter_grpc::local::MAX_SWEEP_DELETES_PER_RUN
    );
    // The truncated sweep did not record itself as having run, so the very next one
    // continues instead of waiting another interval.
    assert_eq!(backend.sweep_expired_documents(&everything(), due), 5);
    assert_eq!(backend.sweep_expired_documents(&everything(), due), 0);
}

#[test]
fn a_sweep_already_running_against_a_database_is_not_started_a_second_time() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (backend, _clock) = backend(LogicalInstant::from_unix_seconds(1_000));
    for i in 0..8 {
        write_document(&backend, &format!("sessions/s{i}"), Some(timestamp(1_100)));
    }
    backend
        .enable_ttl(PROJECT, DATABASE, group("sessions"), field("expiresAt"))
        .expect("enable ttl");
    backend.start_ttl_sweeps(&everything(), LogicalInstant::from_unix_seconds(1_000));

    // Two callers arrive together. Exactly one of them scans; the other is turned away by
    // the claim, so no document is visited twice and the counts cannot double.
    let deleted = Arc::new(AtomicUsize::new(0));
    let due = LogicalInstant::from_unix_seconds(1_000 + 86_400);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let backend = Arc::clone(&backend);
            let deleted = Arc::clone(&deleted);
            scope.spawn(move || {
                deleted.fetch_add(
                    backend.sweep_expired_documents(&everything(), due),
                    Ordering::SeqCst,
                );
            });
        }
    });
    assert_eq!(deleted.load(Ordering::SeqCst), 8);
    for i in 0..8 {
        assert!(!exists(&backend, &format!("sessions/s{i}")));
    }
}
