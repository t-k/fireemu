//! End-to-end local execution through a real tonic client: documents, queries, transactions,
//! aggregations and batch writes on the virtual clock.

// `tonic::Status` is the error type of the backend's own closures.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::{
    AtomicChangeSink, CommitPublication, HistoryBudgetLimits, LocalBackend, QueryExecutionStats,
};
use fireemu_adapter_grpc::rules::ReadCheck;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet, IndexValidationPolicy,
    PlanningContext,
};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::tenancy::Tenancy;
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

const DB: &str = "projects/demo-app/databases/(default)";
const DOCS: &str = "projects/demo-app/databases/(default)/documents";

fn history_budget_write(project: &str, database: &str, document: &str) -> pb::CommitRequest {
    history_budget_update(project, database, document, 1)
}

fn history_budget_update(
    project: &str,
    database: &str,
    document: &str,
    value: i64,
) -> pb::CommitRequest {
    pb::CommitRequest {
        database: format!("projects/{project}/databases/{database}"),
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: format!("projects/{project}/databases/{database}/documents/items/{document}"),
                fields: [("v".to_owned(), i(value))].into_iter().collect(),
                ..Default::default()
            })),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn observing_transaction_expiry_releases_aggregate_history_capacity() {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let backend = LocalBackend::new(gateway, Arc::clone(&clock), 7).with_history_budget_limits(
        HistoryBudgetLimits {
            session_bytes: u64::MAX,
            session_versions: u64::MAX,
            global_bytes: u64::MAX,
            global_versions: 2,
        },
    );
    backend
        .commit_with(
            &history_budget_update("demo-a", "(default)", "a", 1),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(1))
        .unwrap();
    backend
        .commit_with(
            &history_budget_update("demo-a", "(default)", "a", 2),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    let transaction = backend
        .begin_transaction(&pb::BeginTransactionRequest {
            database: "projects/demo-a/databases/(default)".to_owned(),
            ..Default::default()
        })
        .unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(3_601))
        .unwrap();

    let expired = backend
        .get_document(
            &pb::GetDocumentRequest {
                name: "projects/demo-a/databases/(default)/documents/items/a".to_owned(),
                consistency_selector: Some(
                    pb::get_document_request::ConsistencySelector::Transaction(transaction),
                ),
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .unwrap_err();
    assert_eq!(expired.code(), tonic::Code::Aborted);

    backend
        .commit_with(
            &history_budget_write("demo-b", "(default)", "b"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .expect("the expired transaction's unreachable version was released");
    assert_eq!(backend.history_usage().versions, 2);
}

fn history_budget_backend(session_versions: u64, global_versions: u64) -> LocalBackend {
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
    .with_history_budget_limits(HistoryBudgetLimits {
        session_bytes: u64::MAX,
        session_versions,
        global_bytes: u64::MAX,
        global_versions,
    })
    // The budget is shared across databases, so these tests write to a named one. It is
    // declared, the way a configuration declares it: a database nothing created is refused.
    .with_declared_databases(["analytics".to_owned()])
}

#[test]
fn unregistered_projects_and_named_databases_share_the_default_session_history_budget() {
    let backend = history_budget_backend(1, 10);
    let tenancy = Arc::new(RwLock::new(Tenancy::new("demo-a")));
    tenancy
        .write()
        .unwrap()
        .register("demo-b", &[], &[])
        .unwrap();
    backend.set_tenancy(tenancy);

    backend
        .commit_with(
            &history_budget_write("demo-a", "(default)", "a"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    let refused = backend
        .commit_with(
            &history_budget_write("demo-c", "analytics", "c"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::ResourceExhausted);

    backend
        .commit_with(
            &history_budget_write("demo-b", "analytics", "b"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    assert_eq!(backend.history_usage().versions, 2);
}

#[test]
fn reset_refunds_aggregate_history_capacity() {
    let backend = history_budget_backend(1, 1);
    backend
        .commit_with(
            &history_budget_write("demo-a", "(default)", "a"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    assert_eq!(backend.history_usage().versions, 1);
    let refused = backend
        .commit_with(
            &history_budget_write("demo-c", "analytics", "c"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::ResourceExhausted);

    backend.reset();
    assert_eq!(backend.history_usage().versions, 0);
    backend
        .commit_with(
            &history_budget_write("demo-c", "analytics", "c"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
}

#[test]
fn an_over_budget_restore_is_all_or_nothing() {
    use fireemu_core_session::tenancy::Scope;

    let source = history_budget_backend(10, 10);
    for document in ["a", "b"] {
        source
            .commit_with(
                &history_budget_write("demo-a", "(default)", document),
                &fireemu_adapter_grpc::rules::allow_all,
            )
            .unwrap();
    }
    let scope = Scope::AllExcept(std::collections::BTreeSet::new());
    let snapshot = source.snapshot_scope(&scope);
    let target = history_budget_backend(1, 1);
    target
        .commit_with(
            &history_budget_write("demo-a", "(default)", "original"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    let before = target.snapshot_scope(&scope);

    let error = target.restore_scope(&scope, &snapshot).unwrap_err();

    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    let names = |snapshot: &fireemu_adapter_grpc::local::FirestoreSnapshot| {
        snapshot
            .databases
            .values()
            .flat_map(|state| {
                state
                    .documents()
                    .into_iter()
                    .map(|document| document.path.resource_name())
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(names(&target.snapshot_scope(&scope)), names(&before));
    assert_eq!(target.history_usage().versions, 1);
}

struct RejectEveryCommit;

struct AcceptEveryCommit;
struct AcceptedPublication;

struct CountReservations(Arc<AtomicUsize>);

impl CommitPublication for AcceptedPublication {
    fn publish(self: Box<Self>) {}
}

impl AtomicChangeSink for CountReservations {
    fn reserve(
        &self,
        _event: &CommitEvent,
    ) -> Result<Box<dyn CommitPublication>, fireemu_core_types::admission::EventAdmissionError>
    {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(AcceptedPublication))
    }
}

#[test]
fn history_refusal_precedes_functions_event_reservation() {
    let backend = history_budget_backend(1, 1);
    backend
        .commit_with(
            &history_budget_write("demo-a", "(default)", "a"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    let reservations = Arc::new(AtomicUsize::new(0));
    backend.set_atomic_change_sink(Arc::new(CountReservations(reservations.clone())));

    let refused = backend
        .commit_with(
            &history_budget_write("demo-a", "analytics", "b"),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap_err();

    assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
    assert_eq!(reservations.load(Ordering::SeqCst), 0);
    assert_eq!(backend.history_usage().versions, 1);
}

impl AtomicChangeSink for AcceptEveryCommit {
    fn reserve(
        &self,
        _event: &CommitEvent,
    ) -> Result<Box<dyn CommitPublication>, fireemu_core_types::admission::EventAdmissionError>
    {
        Ok(Box::new(AcceptedPublication))
    }
}

impl AtomicChangeSink for RejectEveryCommit {
    fn reserve(
        &self,
        _event: &CommitEvent,
    ) -> Result<Box<dyn CommitPublication>, fireemu_core_types::admission::EventAdmissionError>
    {
        Err(
            fireemu_core_types::admission::EventAdmissionError::Capacity(
                "logical outbox capacity is exhausted".to_owned(),
            ),
        )
    }
}

fn deny_read(
    _: &fireemu_core_firestore::store::FirestoreState,
    _: Option<fireemu_core_firestore::store::CommitVersion>,
    _: ReadCheck<'_>,
) -> Result<(), tonic::Status> {
    Err(tonic::Status::permission_denied("denied by test"))
}

async fn start_with_write_time(
    wall_clock: bool,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    Arc<Mutex<VirtualClock>>,
    tokio::task::JoinHandle<()>,
) {
    start_with_write_time_and_policy(wall_clock, IndexValidationPolicy::Production).await
}

async fn start_with_write_time_and_policy(
    wall_clock: bool,
    policy: IndexValidationPolicy,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    Arc<Mutex<VirtualClock>>,
    tokio::task::JoinHandle<()>,
) {
    let (client, clock, _backend, handle) = start_with_backend_and_policy(wall_clock, policy).await;
    (client, clock, handle)
}

async fn start_with_backend_and_policy(
    wall_clock: bool,
    policy: IndexValidationPolicy,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    Arc<Mutex<VirtualClock>>,
    Arc<LocalBackend>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(if wall_clock {
        LocalBackend::new(gateway.clone(), clock.clone(), 7).with_wall_clock_write_time()
    } else {
        LocalBackend::new(gateway.clone(), clock.clone(), 7)
    });
    let svc = FirestoreServer::new(GatewayService::local(gateway, backend.clone()));
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (FirestoreClient::new(channel), clock, backend, handle)
}

/// A server whose backend waits `wait` for a transaction to release its locks before
/// refusing a contended commit.
async fn start_with_contention_wait(
    wait: std::time::Duration,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    start_with_contention_wait_and_lease(wait, std::time::Duration::from_secs(60)).await
}

/// As [`start_with_contention_wait`], with the lock lease a blocking transaction is allowed.
async fn start_with_contention_wait_and_lease(
    wait: std::time::Duration,
    lease: std::time::Duration,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(
        LocalBackend::new(gateway.clone(), clock, 7)
            .with_contention_wait(wait)
            .with_lock_lease(lease),
    );
    let svc = FirestoreServer::new(GatewayService::local(gateway, backend));
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (FirestoreClient::new(channel), handle)
}

/// A contended commit outside a transaction waits for the transaction to finish and then
/// goes through (production's normal path); one that waits past the bound is refused with
/// production's wording.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contended_commit_waits_for_the_lock_release() {
    let (mut client, handle) = start_with_contention_wait(std::time::Duration::from_secs(10)).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("wait/doc", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/wait/doc"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                txn.clone(),
            )),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut releaser = client.clone();
    let release = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        releaser
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write("wait/doc", &[("v", i(2))])],
                transaction: txn,
                ..Default::default()
            })
            .await
            .unwrap();
    });
    let started = std::time::Instant::now();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("wait/doc", &[("v", i(3))])],
            ..Default::default()
        })
        .await
        .expect("the writer proceeds once the transaction released its locks");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the writer was woken by the release, not by the deadline"
    );
    release.await.unwrap();
    let doc = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/wait/doc"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(doc.fields.get("v"), Some(&i(3)));
    handle.abort();
}

/// A transaction that keeps a writer blocked for the lock lease is rolled back, the way
/// production expires an idle transaction, and the writer then goes through; the holder's own
/// commit is refused afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transaction_blocking_writers_past_the_lock_lease_is_rolled_back() {
    let (mut client, handle) = start_with_contention_wait_and_lease(
        std::time::Duration::from_millis(100),
        std::time::Duration::from_millis(400),
    )
    .await;
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let _ = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/lease/doc"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                txn.clone(),
            )),
            ..Default::default()
        })
        .await;
    // The SDKs retry a commit outside a transaction on ABORTED; so does this writer.
    let started = std::time::Instant::now();
    let mut attempts = 0;
    loop {
        attempts += 1;
        let outcome = client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write("lease/doc", &[("v", i(1))])],
                ..Default::default()
            })
            .await;
        match outcome {
            Ok(_) => break,
            Err(status) if status.code() == tonic::Code::Aborted && attempts < 50 => {}
            Err(status) => panic!("unexpected refusal: {status}"),
        }
    }
    assert!(attempts >= 2, "the first attempts were refused");
    assert!(started.elapsed() >= std::time::Duration::from_millis(400));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    let expired = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("lease/doc", &[("v", i(2))])],
            transaction: txn,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(expired.code(), tonic::Code::Aborted);
    let doc = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/lease/doc"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(doc.fields.get("v"), Some(&i(1)));
    handle.abort();
}

/// A transaction whose held-back commit was abandoned by its client keeps its locks, and its
/// waiting mark makes every later transactional commit into those locks the deadlock victim.
/// The lock lease ends that: after it, the next such commit rolls the holder back and goes
/// through, even though the victim itself could not wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abandoned_waiting_holder_does_not_abort_other_transactions_forever() {
    let (mut client, handle) = start_with_contention_wait_and_lease(
        std::time::Duration::ZERO,
        std::time::Duration::from_millis(300),
    )
    .await;
    let begin = |client: &mut FirestoreClient<tonic::transport::Channel>| {
        let mut client = client.clone();
        async move {
            client
                .begin_transaction(pb::BeginTransactionRequest {
                    database: DB.to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .transaction
        }
    };
    let read = |client: &mut FirestoreClient<tonic::transport::Channel>, txn: Vec<u8>| {
        let mut client = client.clone();
        async move {
            let _ = client
                .get_document(pb::GetDocumentRequest {
                    name: format!("{DOCS}/abandoned/doc"),
                    consistency_selector: Some(
                        pb::get_document_request::ConsistencySelector::Transaction(txn),
                    ),
                    ..Default::default()
                })
                .await;
        }
    };
    // The abandoned holder: it read the document and its commit was held back by another
    // reader's lock; the client never returns.
    let holder = begin(&mut client).await;
    let other = begin(&mut client).await;
    read(&mut client, holder.clone()).await;
    read(&mut client, other.clone()).await;
    let held = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("abandoned/doc", &[("v", i(1))])],
            transaction: holder,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(held.code(), tonic::Code::Aborted);
    client
        .rollback(pb::RollbackRequest {
            database: DB.to_owned(),
            transaction: other,
            ..Default::default()
        })
        .await
        .unwrap();
    // Fresh transactions that read the document and commit are victims until the lease ends.
    let started = std::time::Instant::now();
    let mut attempts = 0;
    loop {
        attempts += 1;
        let txn = begin(&mut client).await;
        read(&mut client, txn.clone()).await;
        let outcome = client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write("abandoned/doc", &[("v", i(2))])],
                transaction: txn,
                ..Default::default()
            })
            .await;
        match outcome {
            Ok(_) => break,
            Err(status) if status.code() == tonic::Code::Aborted && attempts < 100 => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(status) => panic!("unexpected refusal: {status}"),
        }
    }
    assert!(
        attempts >= 2,
        "the first attempts were the deadlock victims"
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(300));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    handle.abort();
}

/// The lease is enforced on every write path, not only Commit: a single-document update
/// against an abandoned holder goes through once the lease has run out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_document_update_also_expires_the_lock_lease() {
    let (mut client, handle) = start_with_contention_wait_and_lease(
        std::time::Duration::ZERO,
        std::time::Duration::from_millis(300),
    )
    .await;
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let _ = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/updates/doc"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                txn,
            )),
            ..Default::default()
        })
        .await;
    let started = std::time::Instant::now();
    let mut attempts = 0;
    loop {
        attempts += 1;
        let outcome = client
            .update_document(pb::UpdateDocumentRequest {
                document: Some(pb::Document {
                    name: format!("{DOCS}/updates/doc"),
                    fields: HashMap::from([("v".to_owned(), i(1))]),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await;
        match outcome {
            Ok(_) => break,
            Err(status) if status.code() == tonic::Code::Aborted && attempts < 100 => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(status) => panic!("unexpected refusal: {status}"),
        }
    }
    assert!(attempts >= 2);
    assert!(started.elapsed() >= std::time::Duration::from_millis(300));
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    handle.abort();
}

/// A holder that keeps driving its transaction is not idle: the lease does not roll it back
/// while it reads, and starts counting once it stops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_holder_keeps_its_locks_past_the_lease() {
    let (mut client, handle) = start_with_contention_wait_and_lease(
        std::time::Duration::ZERO,
        std::time::Duration::from_millis(300),
    )
    .await;
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let read = |client: &mut FirestoreClient<tonic::transport::Channel>, txn: Vec<u8>| {
        let mut client = client.clone();
        async move {
            let _ = client
                .get_document(pb::GetDocumentRequest {
                    name: format!("{DOCS}/busy/doc"),
                    consistency_selector: Some(
                        pb::get_document_request::ConsistencySelector::Transaction(txn),
                    ),
                    ..Default::default()
                })
                .await;
        }
    };
    read(&mut client, txn.clone()).await;
    let write = pb::CommitRequest {
        database: DB.to_owned(),
        writes: vec![update_write("busy/doc", &[("v", i(1))])],
        ..Default::default()
    };
    // For twice the lease the holder reads every 50 ms; every write attempt is refused.
    let busy_until = std::time::Instant::now() + std::time::Duration::from_millis(700);
    while std::time::Instant::now() < busy_until {
        read(&mut client, txn.clone()).await;
        let refused = client.commit(write.clone()).await.unwrap_err();
        assert_eq!(
            refused.code(),
            tonic::Code::Aborted,
            "a busy holder keeps its locks"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Idle now: the lease runs out and the writer gets through.
    let idle_since = std::time::Instant::now();
    loop {
        match client.commit(write.clone()).await {
            Ok(_) => break,
            Err(status) if status.code() == tonic::Code::Aborted => {
                assert!(idle_since.elapsed() < std::time::Duration::from_secs(10));
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(status) => panic!("unexpected refusal: {status}"),
        }
    }
    // The lease clock started at the last refused attempt, up to one busy-loop pause before
    // `idle_since`.
    assert!(idle_since.elapsed() >= std::time::Duration::from_millis(200));
    handle.abort();
}

/// A transaction token is authenticated: a token with an adjacent id, or one with its
/// authenticator changed, names no transaction, so a client cannot roll back or commit a
/// transaction it was never handed.
#[tokio::test]
async fn a_transaction_token_cannot_be_forged_from_a_neighbouring_id() {
    let (mut client, _clock, handle) = start().await;
    let mine = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let other = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    assert_ne!(mine, other);
    // The id sits in the leading bytes; the neighbouring id is what the other client holds.
    let mut forged = mine.clone();
    let handle_len = forged.len() - 16;
    forged[handle_len - 1] = forged[handle_len - 1].wrapping_add(1);
    let refused = client
        .rollback(pb::RollbackRequest {
            database: DB.to_owned(),
            transaction: forged,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    let mut tampered = mine.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let refused = client
        .rollback(pb::RollbackRequest {
            database: DB.to_owned(),
            transaction: tampered,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    // Both genuine tokens still work.
    for txn in [mine, other] {
        client
            .rollback(pb::RollbackRequest {
                database: DB.to_owned(),
                transaction: txn,
                ..Default::default()
            })
            .await
            .unwrap();
    }
    handle.abort();
}

/// A contended commit that waits past the bound is refused with production's wording.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contended_commit_is_refused_after_the_wait_bound() {
    let (mut client, handle) =
        start_with_contention_wait(std::time::Duration::from_millis(100)).await;
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let _ = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/wait/held"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                txn,
            )),
            ..Default::default()
        })
        .await;
    let started = std::time::Instant::now();
    let refused = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("wait/held", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(started.elapsed() >= std::time::Duration::from_millis(100));
    assert_eq!(refused.code(), tonic::Code::Aborted);
    assert_eq!(
        refused.message(),
        "Too much contention on these documents. Please try again."
    );
    handle.abort();
}

async fn start() -> (
    FirestoreClient<tonic::transport::Channel>,
    Arc<Mutex<VirtualClock>>,
    tokio::task::JoinHandle<()>,
) {
    start_with_write_time(false).await
}

#[tokio::test]
async fn event_admission_refusal_prevents_firestore_publication() {
    let (mut client, _clock, backend, server) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    backend.set_atomic_change_sink(Arc::new(RejectEveryCommit));
    let name = format!("{DOCS}/admission/refused");
    let error = client
        .create_document(pb::CreateDocumentRequest {
            parent: DOCS.to_owned(),
            collection_id: "admission".to_owned(),
            document_id: "refused".to_owned(),
            document: Some(pb::Document {
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);
    let missing = client
        .get_document(pb::GetDocumentRequest {
            name,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    let generated_error = client
        .create_document(pb::CreateDocumentRequest {
            parent: DOCS.to_owned(),
            collection_id: "generated".to_owned(),
            document_id: String::new(),
            document: Some(pb::Document::default()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(generated_error.code(), tonic::Code::ResourceExhausted);

    backend.set_atomic_change_sink(Arc::new(AcceptEveryCommit));
    let accepted = client
        .create_document(pb::CreateDocumentRequest {
            parent: DOCS.to_owned(),
            collection_id: "generated".to_owned(),
            document_id: String::new(),
            document: Some(pb::Document::default()),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let reference = LocalBackend::new(
        Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        },
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    );
    let (_, expected_write) = reference
        .plan_create(&pb::CreateDocumentRequest {
            parent: DOCS.to_owned(),
            collection_id: "generated".to_owned(),
            document_id: String::new(),
            document: Some(pb::Document::default()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        accepted.name,
        format!("{DOCS}/{}", expected_write.op.path().relative())
    );
    server.abort();
    let _ = server.await;
}

#[test]
fn routed_projects_can_use_isolated_index_catalogs() {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
    let backend = LocalBackend::new(gateway, clock, 7);
    let mut indexes = IndexSet::default();
    indexes.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("tasks").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: vec![
            IndexField {
                path: FieldPath::parse("owner").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
            IndexField {
                path: FieldPath::parse("done").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
        ],
    });
    backend.replace_project_database_indexes(
        "demo-a",
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        indexes,
    );
    let field = |name: &str, op: sq::field_filter::Operator| sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: name.to_owned(),
            }),
            op: op as i32,
            value: Some(i(1)),
        })),
    };
    // Equality plus inequality: the shape production refuses without a composite index.
    let query = pb::StructuredQuery {
        from: vec![sq::CollectionSelector {
            collection_id: "tasks".to_owned(),
            all_descendants: false,
        }],
        r#where: Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::And as i32,
                    filters: vec![
                        field("owner", sq::field_filter::Operator::Equal),
                        field("done", sq::field_filter::Operator::GreaterThan),
                    ],
                },
            )),
        }),
        ..Default::default()
    };
    let parent = |project: &str| {
        fireemu_adapter_grpc::decode::parse_parent(&format!(
            "projects/{project}/databases/(default)/documents"
        ))
        .unwrap()
    };
    assert!(backend.accepted_query(&parent("demo-a"), &query).is_ok());
    let error = backend
        .accepted_query(&parent("demo-b"), &query)
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
}

#[test]
fn project_index_exemptions_apply_to_writes_and_import_catalog_snapshots_only_in_that_project() {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let backend = LocalBackend::new(
        gateway,
        Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
        7,
    );
    let collection = CollectionId::try_new("items").unwrap();
    let field = FieldPath::parse("v").unwrap();
    let mut indexes = IndexSet::default();
    indexes.set_single_field_indexes(&collection, &field, vec![]);
    backend.replace_project_database_indexes("demo-a", "(default)", indexes);
    assert!(backend
        .indexes_for_project_database("demo-a", "(default)")
        .single_field_modes(&collection, &field)
        .is_empty());
    assert_eq!(
        backend
            .indexes_for_project_database("demo-b", "(default)")
            .single_field_modes(&collection, &field)
            .len(),
        3
    );
    let oversized = |project: &str| {
        let mut request = history_budget_write(project, "(default)", "a");
        let Some(pb::write::Operation::Update(document)) = &mut request.writes[0].operation else {
            unreachable!()
        };
        document.fields.insert(
            "v".into(),
            pb::Value {
                value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
                    values: (0..20_000).map(i).collect(),
                })),
            },
        );
        request
    };
    assert!(backend.commit(&oversized("demo-a")).is_ok());
    assert_eq!(
        backend.commit(&oversized("demo-b")).unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    backend.replace_project_database_indexes("demo-a", "(default)", IndexSet::default());
    assert_eq!(
        backend.commit(&oversized("demo-a")).unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}

async fn start_with_edition(
    edition: FirestoreEdition,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    Arc<Mutex<VirtualClock>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), 7));
    let svc = FirestoreServer::new(GatewayService::local(gateway, backend));
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (FirestoreClient::new(channel), clock, handle)
}

fn s(v: &str) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::StringValue(v.to_owned())),
    }
}
fn i(v: i64) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::IntegerValue(v)),
    }
}
fn doc(name: &str, fields: &[(&str, pb::Value)]) -> pb::Document {
    pb::Document {
        name: format!("{DOCS}/{name}"),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
        create_time: None,
        update_time: None,
    }
}
fn update_write(name: &str, fields: &[(&str, pb::Value)]) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(doc(name, fields))),
        ..Default::default()
    }
}
fn delete_write(name: &str) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Delete(format!("{DOCS}/{name}"))),
        ..Default::default()
    }
}
fn server_timestamp_write(name: &str) -> pb::Write {
    let mut write = update_write(name, &[]);
    write.update_transforms = ["createdAt", "updatedAt"]
        .into_iter()
        .map(|field_path| pb::document_transform::FieldTransform {
            field_path: field_path.to_owned(),
            transform_type: Some(
                pb::document_transform::field_transform::TransformType::SetToServerValue(
                    pb::document_transform::field_transform::ServerValue::RequestTime as i32,
                ),
            ),
        })
        .collect();
    write
}
fn timestamp_field_nanos(document: &pb::Document, field: &str) -> i128 {
    let Some(pb::value::ValueType::TimestampValue(timestamp)) = document
        .fields
        .get(field)
        .and_then(|value| value.value_type.as_ref())
    else {
        panic!("missing timestamp field {field}");
    };
    i128::from(timestamp.seconds) * 1_000_000_000 + i128::from(timestamp.nanos)
}
fn wall_clock_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap()
}
fn query(collection: &str, filter: Option<sq::Filter>) -> pb::RunQueryRequest {
    pb::RunQueryRequest {
        parent: DOCS.to_owned(),
        query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: collection.to_owned(),
                    all_descendants: false,
                }],
                r#where: filter,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}
fn field_eq(path: &str, value: pb::Value) -> sq::Filter {
    field_op(path, sq::field_filter::Operator::Equal, value)
}
fn field_gt(path: &str, value: pb::Value) -> sq::Filter {
    field_op(path, sq::field_filter::Operator::GreaterThan, value)
}
fn field_op(path: &str, op: sq::field_filter::Operator, value: pb::Value) -> sq::Filter {
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: path.to_owned(),
            }),
            op: op as i32,
            value: Some(value),
        })),
    }
}
async fn collect_docs(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    req: pb::RunQueryRequest,
) -> Vec<pb::Document> {
    let mut stream = client.run_query(req).await.unwrap().into_inner();
    let mut out = Vec::new();
    while let Some(r) = stream.next().await {
        if let Some(d) = r.unwrap().document {
            out.push(d);
        }
    }
    out
}

fn vector(values: &[f64]) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
            fields: [
                ("__type__".to_owned(), s("__vector__")),
                (
                    "value".to_owned(),
                    pb::Value {
                        value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
                            values: values
                                .iter()
                                .map(|value| pb::Value {
                                    value_type: Some(pb::value::ValueType::DoubleValue(*value)),
                                })
                                .collect(),
                        })),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        })),
    }
}

#[tokio::test]
async fn grpc_find_nearest_without_a_source_is_rejected_before_kindless_scan() {
    let (mut client, _, handle) = start().await;
    let error = client
        .run_query(pb::RunQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                pb::StructuredQuery {
                    find_nearest: Some(sq::FindNearest {
                        vector_field: Some(sq::FieldReference {
                            field_path: "embedding".to_owned(),
                        }),
                        query_vector: Some(vector(&[0.0, 1.0])),
                        distance_measure: sq::find_nearest::DistanceMeasure::Cosine as i32,
                        limit: Some(1),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unimplemented);
    assert!(error.message().contains("collection source"));
    handle.abort();
}

#[tokio::test]
async fn grpc_run_query_supports_standard_find_nearest() {
    let (mut client, _, handle) =
        start_with_write_time_and_policy(false, IndexValidationPolicy::Emulator).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("items/near", &[("embedding", vector(&[1.0, 0.0]))]),
                update_write("items/far", &[("embedding", vector(&[-1.0, 0.0]))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let documents = collect_docs(
        &mut client,
        pb::RunQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                pb::StructuredQuery {
                    from: vec![sq::CollectionSelector {
                        collection_id: "items".to_owned(),
                        ..Default::default()
                    }],
                    find_nearest: Some(sq::FindNearest {
                        vector_field: Some(sq::FieldReference {
                            field_path: "embedding".to_owned(),
                        }),
                        query_vector: Some(vector(&[1.0, 0.0])),
                        distance_measure: sq::find_nearest::DistanceMeasure::Euclidean as i32,
                        limit: Some(1),
                        distance_result_field: "distance".to_owned(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(documents.len(), 1);
    assert!(documents[0].name.ends_with("/items/near"));
    assert!(matches!(
        documents[0].fields["distance"].value_type,
        Some(pb::value::ValueType::DoubleValue(value)) if value == 0.0
    ));
    handle.abort();
}

#[tokio::test]
async fn grpc_find_nearest_query_clauses_are_served_by_the_emulator_profile() {
    // Production refuses a query limit, offset or cursor beside findNearest: a strict-profile
    // refusal only. The emulator profile applies those stages before the nearest-neighbour
    // ranking, as fireemu did before, and adds no rejection.
    let (mut emulator, _, emulator_handle) =
        start_with_write_time_and_policy(false, IndexValidationPolicy::Emulator).await;
    emulator
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("items/near", &[("embedding", vector(&[1.0, 0.0]))]),
                update_write("items/mid", &[("embedding", vector(&[1.0, 1.0]))]),
                update_write("items/far", &[("embedding", vector(&[-1.0, 0.0]))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let served = collect_docs(
        &mut emulator,
        pb::RunQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                pb::StructuredQuery {
                    from: vec![sq::CollectionSelector {
                        collection_id: "items".to_owned(),
                        ..Default::default()
                    }],
                    find_nearest: Some(sq::FindNearest {
                        vector_field: Some(sq::FieldReference {
                            field_path: "embedding".to_owned(),
                        }),
                        query_vector: Some(vector(&[1.0, 0.0])),
                        distance_measure: sq::find_nearest::DistanceMeasure::Euclidean as i32,
                        limit: Some(2),
                        ..Default::default()
                    }),
                    limit: Some(2),
                    offset: 1,
                    ..Default::default()
                },
            )),
            ..Default::default()
        },
    )
    .await;
    // Offset 1 and limit 2 by name (mid, near), then ranked; the whole stream is read.
    let names: Vec<&str> = served
        .iter()
        .map(|document| document.name.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(names, ["near", "mid"]);
    emulator_handle.abort();
}

#[tokio::test]
async fn grpc_find_nearest_refuses_query_limits_offsets_and_cursors() {
    // Production refuses each (FS-QUERY-INDEX vector/with-query-clauses, 2026-09-24).
    let (mut client, _, handle) =
        start_with_write_time_and_policy(false, IndexValidationPolicy::Production).await;
    let nearest = || sq::FindNearest {
        vector_field: Some(sq::FieldReference {
            field_path: "embedding".to_owned(),
        }),
        query_vector: Some(vector(&[1.0, 0.0])),
        distance_measure: sq::find_nearest::DistanceMeasure::Euclidean as i32,
        limit: Some(2),
        ..Default::default()
    };
    let cursor = || pb::Cursor {
        values: vec![vector(&[1.0, 0.0])],
        before: true,
    };
    for (query, expected) in [
        (
            pb::StructuredQuery {
                limit: Some(2),
                ..Default::default()
            },
            "A query limit cannot be used with FindNearest",
        ),
        (
            pb::StructuredQuery {
                offset: 1,
                ..Default::default()
            },
            "A query offset cannot be used with FindNearest",
        ),
        (
            pb::StructuredQuery {
                start_at: Some(cursor()),
                ..Default::default()
            },
            "A cursor cannot be used with FindNearest",
        ),
    ] {
        let status = client
            .run_query(pb::RunQueryRequest {
                parent: DOCS.to_owned(),
                query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                    pb::StructuredQuery {
                        from: vec![sq::CollectionSelector {
                            collection_id: "items".to_owned(),
                            ..Default::default()
                        }],
                        find_nearest: Some(nearest()),
                        ..query
                    },
                )),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(status.message(), expected);
    }
    handle.abort();
}

#[tokio::test]
async fn grpc_find_nearest_pages_from_one_snapshot() {
    let (mut client, _, handle) =
        start_with_write_time_and_policy(false, IndexValidationPolicy::Emulator).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..40)
                .map(|index| {
                    update_write(
                        &format!("items/{index:02}"),
                        &[("embedding", vector(&[1.0, 0.0]))],
                    )
                })
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let documents = collect_docs(
        &mut client,
        pb::RunQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                pb::StructuredQuery {
                    from: vec![sq::CollectionSelector {
                        collection_id: "items".to_owned(),
                        ..Default::default()
                    }],
                    find_nearest: Some(sq::FindNearest {
                        vector_field: Some(sq::FieldReference {
                            field_path: "embedding".to_owned(),
                        }),
                        query_vector: Some(vector(&[1.0, 0.0])),
                        distance_measure: sq::find_nearest::DistanceMeasure::Euclidean as i32,
                        limit: Some(40),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(documents.len(), 40);
    handle.abort();
}

#[tokio::test]
async fn kindless_all_descendants_query_is_scoped_to_its_parent() {
    let (mut client, _, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: [
                "roots/target",
                "roots/target/children/a",
                "roots/target/children/a/grandchildren/b",
                "roots/sibling/children/c",
            ]
            .into_iter()
            .map(|name| update_write(name, &[("value", i(1))]))
            .collect(),
            ..Default::default()
        })
        .await
        .unwrap();

    let descendants = collect_docs(
        &mut client,
        pb::RunQueryRequest {
            parent: format!("{DOCS}/roots/target"),
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                pb::StructuredQuery {
                    select: Some(sq::Projection {
                        fields: vec![sq::FieldReference {
                            field_path: "__name__".to_owned(),
                        }],
                    }),
                    from: vec![sq::CollectionSelector {
                        collection_id: String::new(),
                        all_descendants: true,
                    }],
                    ..Default::default()
                },
            )),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        descendants
            .iter()
            .map(|document| document.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            format!("{DOCS}/roots/target/children/a"),
            format!("{DOCS}/roots/target/children/a/grandchildren/b"),
        ]
    );
    assert!(descendants
        .iter()
        .all(|document| document.fields.is_empty()));

    // An empty collection id without `allDescendants` selects the parent's direct children
    // in any collection (production, FS-QUERY-INDEX
    // collection-group/scopes#kindless-without-descendants).
    let children = |parent: String| pb::RunQueryRequest {
        parent,
        query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: String::new(),
                    all_descendants: false,
                }],
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let names = |documents: Vec<pb::Document>| {
        documents
            .into_iter()
            .map(|document| document.name)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(collect_docs(&mut client, children(DOCS.to_owned())).await),
        vec![format!("{DOCS}/roots/target")]
    );
    assert_eq!(
        names(collect_docs(&mut client, children(format!("{DOCS}/roots/target"))).await),
        vec![format!("{DOCS}/roots/target/children/a")]
    );
    handle.abort();
}

#[tokio::test]
async fn unpinned_server_timestamps_follow_each_write_wall_time() {
    let (mut client, _, handle) = start_with_write_time(true).await;
    let before_first = wall_clock_nanos();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![server_timestamp_write("timestamps/first")],
            ..Default::default()
        })
        .await
        .unwrap();
    let after_first = wall_clock_nanos();
    let first = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/timestamps/first"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let first_nanos = timestamp_field_nanos(&first, "createdAt");
    assert_eq!(first_nanos, timestamp_field_nanos(&first, "updatedAt"));
    assert!(
        first_nanos >= before_first - 1_000_000,
        "{first_nanos} < {before_first}"
    );
    assert!(first_nanos <= after_first, "{first_nanos} > {after_first}");

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let before_second = wall_clock_nanos();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![server_timestamp_write("timestamps/second")],
            ..Default::default()
        })
        .await
        .unwrap();
    let after_second = wall_clock_nanos();
    let second = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/timestamps/second"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let second_nanos = timestamp_field_nanos(&second, "createdAt");
    assert!(second_nanos >= before_second - 1_000_000);
    assert!(second_nanos <= after_second);
    assert!(second_nanos / 1_000_000 > first_nanos / 1_000_000);
    handle.abort();
}

#[tokio::test]
async fn transaction_query_immediately_finds_a_recent_server_timestamp_document() {
    let (mut client, _, handle) =
        start_with_write_time_and_policy(true, IndexValidationPolicy::Emulator).await;
    let mut write = server_timestamp_write("recent-jobs/one");
    let Some(pb::write::Operation::Update(document)) = write.operation.as_mut() else {
        unreachable!("the server timestamp helper always creates an update")
    };
    document.fields.insert("owner".to_owned(), s("user-one"));
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![write],
            ..Default::default()
        })
        .await
        .unwrap();

    let threshold_nanos = wall_clock_nanos() - LogicalDuration::from_seconds(30 * 60).as_nanos();
    let threshold = pb::Value {
        value_type: Some(pb::value::ValueType::TimestampValue(
            prost_types::Timestamp {
                seconds: i64::try_from(threshold_nanos.div_euclid(1_000_000_000)).unwrap(),
                nanos: i32::try_from(threshold_nanos.rem_euclid(1_000_000_000)).unwrap(),
            },
        )),
    };
    let comparison = |path: &str, op: sq::field_filter::Operator, value: pb::Value| sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: path.to_owned(),
            }),
            op: op as i32,
            value: Some(value),
        })),
    };
    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut request = query(
        "recent-jobs",
        Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::And as i32,
                    filters: vec![
                        comparison("owner", sq::field_filter::Operator::Equal, s("user-one")),
                        comparison(
                            "createdAt",
                            sq::field_filter::Operator::GreaterThanOrEqual,
                            threshold,
                        ),
                    ],
                },
            )),
        }),
    );
    let Some(pb::run_query_request::QueryType::StructuredQuery(structured)) =
        request.query_type.as_mut()
    else {
        unreachable!("the query helper always creates a structured query")
    };
    structured.limit = Some(1);
    request.consistency_selector = Some(pb::run_query_request::ConsistencySelector::Transaction(
        transaction.clone(),
    ));

    let documents = collect_docs(&mut client, request).await;
    assert_eq!(documents.len(), 1);
    assert!(matches!(
        documents[0]
            .fields
            .get("createdAt")
            .and_then(|value| value.value_type.as_ref()),
        Some(pb::value::ValueType::TimestampValue(_))
    ));
    client
        .rollback(pb::RollbackRequest {
            database: DB.to_owned(),
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

#[tokio::test]
async fn commit_get_query_and_delete_round_trip() {
    let (mut client, clock, handle) = start().await;
    let commit = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("users/alice", &[("name", s("Alice")), ("age", i(30))]),
                update_write("users/bob", &[("name", s("Bob")), ("age", i(25))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(commit.write_results.len(), 2);
    assert_eq!(commit.commit_time.unwrap().seconds, 1_788_004_860);

    let got = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/users/alice"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.fields.get("age"), Some(&i(30)));
    assert_eq!(got.create_time.unwrap().seconds, 1_788_004_860);
    let missing = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/users/zoe"),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    assert_eq!(
        missing.message(),
        format!("Document \"{DOCS}/users/zoe\" not found.")
    );

    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(60))
        .unwrap();
    let docs = collect_docs(&mut client, query("users", Some(field_eq("age", i(25))))).await;
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].name, format!("{DOCS}/users/bob"));
    let all = collect_docs(&mut client, query("users", None)).await;
    assert_eq!(all.len(), 2);

    client
        .delete_document(pb::DeleteDocumentRequest {
            name: format!("{DOCS}/users/alice"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        collect_docs(&mut client, query("users", None)).await.len(),
        1
    );
    let ids = client
        .list_collection_ids(pb::ListCollectionIdsRequest {
            parent: DOCS.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ids.collection_ids, vec!["users"]);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn grpc_field_filter_enum_values_are_executable_and_unknown_values_refused() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write(
                    "enum/one",
                    &[
                        ("n", i(1)),
                        (
                            "tags",
                            pb::Value {
                                value_type: Some(pb::value::ValueType::ArrayValue(
                                    pb::ArrayValue {
                                        values: vec![s("a")],
                                    },
                                )),
                            },
                        ),
                    ],
                ),
                update_write(
                    "enum/two",
                    &[
                        ("n", i(2)),
                        (
                            "tags",
                            pb::Value {
                                value_type: Some(pb::value::ValueType::ArrayValue(
                                    pb::ArrayValue {
                                        values: vec![s("b")],
                                    },
                                )),
                            },
                        ),
                    ],
                ),
                update_write(
                    "enum/three",
                    &[
                        ("n", i(3)),
                        (
                            "tags",
                            pb::Value {
                                value_type: Some(pb::value::ValueType::ArrayValue(
                                    pb::ArrayValue {
                                        values: vec![s("a"), s("b")],
                                    },
                                )),
                            },
                        ),
                    ],
                ),
            ],
            ..Default::default()
        })
        .await
        .unwrap();

    let array = |values: Vec<pb::Value>| pb::Value {
        value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue { values })),
    };
    let cases = [
        ("n", sq::field_filter::Operator::LessThan, i(2), vec!["one"]),
        (
            "n",
            sq::field_filter::Operator::LessThanOrEqual,
            i(2),
            vec!["one", "two"],
        ),
        (
            "n",
            sq::field_filter::Operator::GreaterThan,
            i(2),
            vec!["three"],
        ),
        (
            "n",
            sq::field_filter::Operator::GreaterThanOrEqual,
            i(2),
            vec!["three", "two"],
        ),
        ("n", sq::field_filter::Operator::Equal, i(2), vec!["two"]),
        (
            "n",
            sq::field_filter::Operator::NotEqual,
            i(2),
            vec!["one", "three"],
        ),
        (
            "n",
            sq::field_filter::Operator::In,
            array(vec![i(1), i(3)]),
            vec!["one", "three"],
        ),
        (
            "n",
            sq::field_filter::Operator::NotIn,
            array(vec![i(2)]),
            vec!["one", "three"],
        ),
        (
            "tags",
            sq::field_filter::Operator::ArrayContains,
            s("a"),
            vec!["one", "three"],
        ),
        (
            "tags",
            sq::field_filter::Operator::ArrayContainsAny,
            array(vec![s("b")]),
            vec!["three", "two"],
        ),
    ];
    for (field, operator, value, expected) in cases {
        let mut rows = collect_docs(
            &mut client,
            query("enum", Some(field_op(field, operator, value))),
        )
        .await;
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        let names = rows
            .into_iter()
            .map(|document| document.name.rsplit('/').next().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, expected, "operator {operator:?}");
    }

    let mut invalid = query(
        "enum",
        Some(field_op("n", sq::field_filter::Operator::Equal, i(1))),
    );
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) = &mut invalid.query_type
    {
        if let Some(sq::filter::FilterType::FieldFilter(filter)) = query
            .r#where
            .as_mut()
            .and_then(|filter| filter.filter_type.as_mut())
        {
            filter.op = 99;
        }
    }
    assert_eq!(
        client.run_query(invalid).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn list_collection_ids_supports_read_time_and_rejects_negative_page_size() {
    use fireemu_core_session::fault::{
        FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
    };

    let (mut client, clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    let first = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("first/doc", &[("value", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let read_time = first.commit_time.unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(1))
        .unwrap();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("second/doc", &[("value", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();

    let historical = client
        .list_collection_ids(pb::ListCollectionIdsRequest {
            parent: DOCS.to_owned(),
            consistency_selector: Some(
                pb::list_collection_ids_request::ConsistencySelector::ReadTime(read_time),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(historical.collection_ids, vec!["first"]);

    let token = client
        .list_collection_ids(pb::ListCollectionIdsRequest {
            parent: DOCS.to_owned(),
            page_size: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .next_page_token;
    assert!(!token.is_empty());
    let cross_parent = client
        .list_collection_ids(pb::ListCollectionIdsRequest {
            parent: "projects/other/databases/(default)/documents".to_owned(),
            page_size: 1,
            page_token: token.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(cross_parent.code(), tonic::Code::InvalidArgument);
    backend.reset_project("demo-app");
    let after_reset = client
        .list_collection_ids(pb::ListCollectionIdsRequest {
            parent: DOCS.to_owned(),
            page_size: 1,
            page_token: token,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(after_reset.code(), tonic::Code::InvalidArgument);

    let invalid = client
        .list_collection_ids(pb::ListCollectionIdsRequest {
            parent: DOCS.to_owned(),
            page_size: -1,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
    let registry = Arc::new(FaultRegistry::new());
    registry.default_state().lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "firestore.read".into(),
                nth: None,
                function: None,
                event_type: None,
            },
            action: FaultAction::ReturnError {
                code: "UNAVAILABLE".into(),
            },
        }],
    });
    backend.set_faults(Arc::clone(&registry));
    let invalid_again = client
        .list_collection_ids(pb::ListCollectionIdsRequest {
            parent: DOCS.to_owned(),
            page_token: "eg==".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(invalid_again.code(), tonic::Code::InvalidArgument);
    let state = registry.default_state();
    let state = state.lock().unwrap();
    assert!(state.counters().is_empty());
    assert!(state.fired().is_empty());
    handle.abort();
}

#[tokio::test]
async fn create_update_with_mask_transforms_and_preconditions() {
    let (mut client, _clock, handle) = start().await;
    let created = client
        .create_document(pb::CreateDocumentRequest {
            parent: DOCS.to_owned(),
            collection_id: "posts".to_owned(),
            document_id: String::new(),
            document: Some(pb::Document {
                fields: HashMap::from([("title".to_owned(), s("hi")), ("likes".to_owned(), i(0))]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(created.name.starts_with(&format!("{DOCS}/posts/")));
    let id = created.name.rsplit('/').next().unwrap().to_owned();
    assert_eq!(id.len(), 20);

    // Update with a mask plus an increment transform.
    let write = pb::Write {
        operation: Some(pb::write::Operation::Update(doc(
            &format!("posts/{id}"),
            &[("title", s("hello"))],
        ))),
        update_mask: Some(pb::DocumentMask {
            field_paths: vec!["title".to_owned()],
        }),
        update_transforms: vec![pb::document_transform::FieldTransform {
            field_path: "likes".to_owned(),
            transform_type: Some(
                pb::document_transform::field_transform::TransformType::Increment(i(5)),
            ),
        }],
        current_document: Some(pb::Precondition {
            condition_type: Some(pb::precondition::ConditionType::Exists(true)),
        }),
    };
    let resp = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![write],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.write_results[0].transform_results, vec![i(5)]);
    let got = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/posts/{id}"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.fields.get("title"), Some(&s("hello")));
    assert_eq!(got.fields.get("likes"), Some(&i(5)));

    // Creating the same document again is ALREADY_EXISTS; updating a missing one is NOT_FOUND.
    let dup = client
        .create_document(pb::CreateDocumentRequest {
            parent: DOCS.to_owned(),
            collection_id: "posts".to_owned(),
            document_id: id.clone(),
            document: Some(pb::Document::default()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(dup.code(), tonic::Code::AlreadyExists);
    let missing = client
        .update_document(pb::UpdateDocumentRequest {
            document: Some(doc("posts/nope", &[("x", i(1))])),
            update_mask: Some(pb::DocumentMask {
                field_paths: vec!["x".to_owned()],
            }),
            current_document: Some(pb::Precondition {
                condition_type: Some(pb::precondition::ConditionType::Exists(true)),
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_read_transaction_locks_its_documents_and_batch_get_reports_missing() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(100))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut stream = client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![format!("{DOCS}/acct/a"), format!("{DOCS}/acct/none")],
            consistency_selector: Some(
                pb::batch_get_documents_request::ConsistencySelector::Transaction(txn.clone()),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut found = 0;
    let mut missing = 0;
    while let Some(r) = stream.next().await {
        match r.unwrap().result {
            Some(pb::batch_get_documents_response::Result::Found(_)) => found += 1,
            Some(pb::batch_get_documents_response::Result::Missing(_)) => missing += 1,
            None => {}
        }
    }
    assert_eq!((found, missing), (1, 1));
    // Production (PESSIMISTIC): the read locked both paths, so the out-of-band write is refused
    // with production's wording (the test backend waits zero seconds for a release).
    let contended = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(90))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(contended.code(), tonic::Code::Aborted);
    assert_eq!(
        contended.message(),
        "Too much contention on these documents. Please try again."
    );
    // A second transaction reading the same document shares the lock; the first to commit
    // is aborted for its client to retry.
    let other = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/acct/a"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                other.clone(),
            )),
            ..Default::default()
        })
        .await
        .unwrap();
    // The first committer is held back (this backend waits zero seconds, so the answer is the
    // contention refusal) and stays active; the other transaction then runs into a waiting
    // holder and is the deadlock victim, aborted for its client to retry.
    let held = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(80))])],
            transaction: txn.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(held.code(), tonic::Code::Aborted);
    let victim = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(70))])],
            transaction: other.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(victim.code(), tonic::Code::Aborted);
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(80))])],
            transaction: txn.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    // Released: the out-of-band write goes through now.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(90))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let txn = other;
    let retry = || pb::BeginTransactionRequest {
        database: DB.to_owned(),
        options: Some(pb::TransactionOptions {
            mode: Some(pb::transaction_options::Mode::ReadWrite(
                pb::transaction_options::ReadWrite {
                    retry_transaction: txn.clone(),
                    ..Default::default()
                },
            )),
        }),
        ..Default::default()
    };
    assert!(client.begin_transaction(retry()).await.is_ok());
    let replay = client.begin_transaction(retry()).await.unwrap_err();
    assert_eq!(replay.code(), tonic::Code::InvalidArgument);
    let got = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/acct/a"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.fields.get("balance"), Some(&i(90)));

    let txn2 = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    client
        .rollback(pb::RollbackRequest {
            database: DB.to_owned(),
            transaction: txn2,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn concurrent_transaction_retries_preserve_every_increment_and_item() {
    const CLIENTS: usize = 20;
    // Every round commits the held-back transaction and aborts the others as deadlock
    // victims, so a client may lose many rounds in a row before its turn.
    const ATTEMPTS: usize = CLIENTS * 4;
    // A held-back commit waits for the holders to finish, as the daemon does; the deadlock
    // rule aborts the others, so every round makes progress.
    let (mut client, handle) = start_with_contention_wait(std::time::Duration::from_secs(30)).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("counters/shared", &[("value", i(0))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let first_reads = Arc::new(tokio::sync::Barrier::new(CLIENTS));
    let tasks: Vec<_> = (0..CLIENTS)
        .map(|client_id| {
            let mut client = client.clone();
            let first_reads = first_reads.clone();
            tokio::spawn(async move {
                let mut retry_transaction = Vec::new();
                for attempt in 0..ATTEMPTS {
                    let transaction = client
                        .begin_transaction(pb::BeginTransactionRequest {
                            database: DB.to_owned(),
                            options: Some(pb::TransactionOptions {
                                mode: Some(pb::transaction_options::Mode::ReadWrite(
                                    pb::transaction_options::ReadWrite {
                                        retry_transaction,
                                        ..Default::default()
                                    },
                                )),
                            }),
                            ..Default::default()
                        })
                        .await
                        .unwrap()
                        .into_inner()
                        .transaction;
                    let counter = client
                        .get_document(pb::GetDocumentRequest {
                            name: format!("{DOCS}/counters/shared"),
                            consistency_selector: Some(
                                pb::get_document_request::ConsistencySelector::Transaction(
                                    transaction.clone(),
                                ),
                            ),
                            ..Default::default()
                        })
                        .await
                        .unwrap()
                        .into_inner();
                    let Some(pb::value::ValueType::IntegerValue(value)) = counter
                        .fields
                        .get("value")
                        .and_then(|value| value.value_type.as_ref())
                    else {
                        panic!("counter is not an integer");
                    };
                    if attempt == 0 {
                        first_reads.wait().await;
                    }
                    let result = client
                        .commit(pb::CommitRequest {
                            database: DB.to_owned(),
                            writes: vec![
                                update_write(&format!("items/client-{client_id}"), &[("ok", i(1))]),
                                update_write("counters/shared", &[("value", i(value + 1))]),
                            ],
                            transaction: transaction.clone(),
                            ..Default::default()
                        })
                        .await;
                    match result {
                        Ok(_) => return,
                        Err(status) if status.code() == tonic::Code::Aborted => {
                            retry_transaction = transaction;
                            tokio::task::yield_now().await;
                        }
                        Err(status) => panic!("unexpected transaction failure: {status}"),
                    }
                }
                panic!("transaction did not make progress after {ATTEMPTS} attempts");
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }

    let counter = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/counters/shared"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let expected_clients = i64::try_from(CLIENTS).expect("client count fits in i64");
    assert_eq!(counter.fields.get("value"), Some(&i(expected_clients)));
    assert_eq!(
        collect_docs(&mut client, query("items", None)).await.len(),
        CLIENTS
    );
    handle.abort();
}

#[tokio::test]
async fn aggregation_batch_write_and_gateway_rejections_in_local_mode() {
    let (mut client, _clock, handle) = start().await;
    let resp = client
        .batch_write(pb::BatchWriteRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("n/1", &[("v", i(1))]),
                update_write("n/2", &[("v", i(2))]),
                update_write("n/3", &[("other", i(3))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.status[0].code, 0);
    assert_eq!(resp.status[1].code, 0);
    assert_eq!(resp.status[2].code, 0);
    let agg = pb::RunAggregationQueryRequest {
        parent: DOCS.to_owned(),
        query_type: Some(
            pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                pb::StructuredAggregationQuery {
                    query_type: Some(
                        pb::structured_aggregation_query::QueryType::StructuredQuery(
                            pb::StructuredQuery {
                                from: vec![sq::CollectionSelector {
                                    collection_id: "n".to_owned(),
                                    all_descendants: false,
                                }],
                                ..Default::default()
                            },
                        ),
                    ),
                    aggregations: vec![
                        pb::structured_aggregation_query::Aggregation {
                            alias: "count".to_owned(),
                            operator: Some(
                                pb::structured_aggregation_query::aggregation::Operator::Count(
                                    pb::structured_aggregation_query::aggregation::Count {
                                        up_to: None,
                                    },
                                ),
                            ),
                        },
                        pb::structured_aggregation_query::Aggregation {
                            alias: "sum".to_owned(),
                            operator: Some(
                                pb::structured_aggregation_query::aggregation::Operator::Sum(
                                    pb::structured_aggregation_query::aggregation::Sum {
                                        field: Some(sq::FieldReference {
                                            field_path: "v".to_owned(),
                                        }),
                                    },
                                ),
                            ),
                        },
                    ],
                },
            ),
        ),
        ..Default::default()
    };
    let mut stream = client
        .run_aggregation_query(agg)
        .await
        .unwrap()
        .into_inner();
    let result = stream.next().await.unwrap().unwrap().result.unwrap();
    assert_eq!(result.aggregate_fields.get("count"), Some(&i(2)));
    assert_eq!(result.aggregate_fields.get("sum"), Some(&i(3)));

    // The strict gateway still applies in local mode: an equality plus an inequality on
    // another field needs a composite index, as in production.
    let needs_index = query(
        "n",
        Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::And as i32,
                    filters: vec![field_eq("v", i(1)), field_gt("w", i(2))],
                },
            )),
        }),
    );
    let err = client.run_query(needs_index).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    handle.abort();
}

/// The local adapter validates every write before publishing any of them. A late precondition
/// failure therefore leaves both the existing document and the missing target unchanged. This
/// records local behavior; production parity is unobserved here.
#[tokio::test]
async fn commit_late_precondition_failure_is_atomic() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("atomic/existing", &[("value", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();

    let mut missing_precondition = update_write("atomic/missing", &[("value", i(2))]);
    missing_precondition.current_document = Some(pb::Precondition {
        condition_type: Some(pb::precondition::ConditionType::Exists(true)),
    });
    let first_write = update_write("atomic/existing", &[("value", i(9))]);
    let error = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![first_write.clone(), missing_precondition],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);

    let existing = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/atomic/existing"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(existing.fields.get("value"), Some(&i(1)));
    assert_eq!(
        client
            .get_document(pb::GetDocumentRequest {
                name: format!("{DOCS}/atomic/missing"),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    handle.abort();
}

/// The local adapter keeps a failed transactional commit available for rollback. Rollback
/// releases its read locks so the same document can then be written by another request. This
/// records local behavior; production parity is unobserved here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn failed_transaction_commit_can_be_rolled_back_and_releases_ownership() {
    let (mut client, handle) = start_with_contention_wait(std::time::Duration::ZERO).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("txn-failure/doc", &[("value", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![format!("{DOCS}/txn-failure/doc")],
            consistency_selector: Some(
                pb::batch_get_documents_request::ConsistencySelector::Transaction(
                    transaction.clone(),
                ),
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut missing_precondition = update_write("txn-failure/missing", &[("value", i(2))]);
    missing_precondition.current_document = Some(pb::Precondition {
        condition_type: Some(pb::precondition::ConditionType::Exists(true)),
    });
    let failed = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            transaction: transaction.clone(),
            writes: vec![
                update_write("txn-failure/doc", &[("value", i(9))]),
                missing_precondition,
            ],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(failed.code(), tonic::Code::NotFound);

    // The failed transaction published neither staged write before rollback.
    let unchanged = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/txn-failure/doc"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(unchanged.fields.get("value"), Some(&i(1)));
    assert_eq!(
        client
            .get_document(pb::GetDocumentRequest {
                name: format!("{DOCS}/txn-failure/missing"),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );

    let blocked = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("txn-failure/doc", &[("value", i(3))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(blocked.code(), tonic::Code::Aborted);

    client
        .rollback(pb::RollbackRequest {
            database: DB.to_owned(),
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("txn-failure/doc", &[("value", i(3))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let document = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/txn-failure/doc"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(document.fields.get("value"), Some(&i(3)));
    handle.abort();
}

/// The local adapter's `BatchWrite` reports a precondition failure for one write while
/// publishing an independent later write, preserving its per-write status and result alignment.
/// Production parity is unobserved here.
#[tokio::test]
async fn batch_write_precondition_failure_is_per_write_and_later_writes_commit() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("batch-failure/existing", &[("value", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let mut wrong_precondition = update_write("batch-failure/existing", &[("value", i(9))]);
    wrong_precondition.current_document = Some(pb::Precondition {
        condition_type: Some(pb::precondition::ConditionType::Exists(false)),
    });
    let response = client
        .batch_write(pb::BatchWriteRequest {
            database: DB.to_owned(),
            writes: vec![
                wrong_precondition,
                update_write("batch-failure/later", &[("value", i(2))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.status.len(), 2);
    assert_eq!(response.write_results.len(), 2);
    assert_eq!(
        response.status[0].code,
        i32::from(tonic::Code::AlreadyExists)
    );
    assert_eq!(response.status[1].code, 0);
    assert!(response.write_results[0].update_time.is_none());
    assert!(response.write_results[1].update_time.is_some());

    let existing = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/batch-failure/existing"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(existing.fields.get("value"), Some(&i(1)));
    let later = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/batch-failure/later"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(later.fields.get("value"), Some(&i(2)));
    handle.abort();
}

#[tokio::test]
async fn batch_write_rejects_unspecified_operation_before_valid_rows() {
    let (mut client, _clock, handle) = start().await;
    let error = client
        .batch_write(pb::BatchWriteRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("rows/prefix", &[("value", i(1))]),
                pb::Write::default(),
                update_write("rows/suffix", &[("value", i(3))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);

    for name in ["rows/prefix", "rows/suffix"] {
        let error = client
            .get_document(pb::GetDocumentRequest {
                name: format!("{DOCS}/{name}"),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);
    }

    handle.abort();
}

#[tokio::test]
async fn aggregation_index_validation_rejects_unindexed_fields_before_transaction_observation() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    let collection = CollectionId::try_new("orders").unwrap();
    let mut indexes = IndexSet::default();
    indexes.set_single_field_indexes(&collection, &FieldPath::parse("amount").unwrap(), vec![]);
    backend.replace_indexes(indexes);

    let request = |consistency_selector| pb::RunAggregationQueryRequest {
        parent: DOCS.to_owned(),
        query_type: Some(
            pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                agg_count_and_sum("orders", "amount"),
            ),
        ),
        consistency_selector,
        ..Default::default()
    };
    let error = client
        .run_aggregation_query(request(None))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(
        error.message().starts_with(
            "The query requires a COLLECTION_ASC index for collection orders and field amount."
        ),
        "{error}"
    );

    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let error = client
        .run_aggregation_query(request(Some(
            pb::run_aggregation_query_request::ConsistencySelector::Transaction(
                transaction.clone(),
            ),
        )))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);

    // Validation happened before the rejected aggregation could record a read, so the same
    // transaction remains usable.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write(
                "after-rejected-aggregation/doc",
                &[("v", i(1))],
            )],
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

fn agg_count(collection: &str, alias: &str) -> pb::StructuredAggregationQuery {
    pb::StructuredAggregationQuery {
        query_type: Some(
            pb::structured_aggregation_query::QueryType::StructuredQuery(pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: collection.to_owned(),
                    all_descendants: false,
                }],
                ..Default::default()
            }),
        ),
        aggregations: vec![pb::structured_aggregation_query::Aggregation {
            alias: alias.to_owned(),
            operator: Some(
                pb::structured_aggregation_query::aggregation::Operator::Count(
                    pb::structured_aggregation_query::aggregation::Count { up_to: None },
                ),
            ),
        }],
    }
}

fn agg_count_and_sum(collection: &str, field: &str) -> pb::StructuredAggregationQuery {
    let mut query = agg_count(collection, "count");
    query
        .aggregations
        .push(pb::structured_aggregation_query::Aggregation {
            alias: "sum".to_owned(),
            operator: Some(
                pb::structured_aggregation_query::aggregation::Operator::Sum(
                    pb::structured_aggregation_query::aggregation::Sum {
                        field: Some(sq::FieldReference {
                            field_path: field.to_owned(),
                        }),
                    },
                ),
            ),
        });
    query
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn malformed_wire_shapes_are_rejected_before_any_mutation() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    // The second database is the one a foreign document name and a foreign transaction token
    // point at, so it is declared: a database nothing created is refused before either check.
    backend.replace_declared_databases(["other".to_owned()]);
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("w/1", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();

    // A present but empty precondition must not become an unconditional delete.
    let err = client
        .delete_document(pb::DeleteDocumentRequest {
            name: format!("{DOCS}/w/1"),
            current_document: Some(pb::Precondition {
                condition_type: None,
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/w/1"),
            ..Default::default()
        })
        .await
        .is_ok());

    // Document names must belong to the request database.
    let foreign = "projects/demo-app/databases/other/documents/w/2";
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: foreign.to_owned(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let err = client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![foreign.to_owned()],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // A transaction token is bound to the database that issued it.
    let other_txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: "projects/demo-app/databases/other".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![],
            transaction: other_txn,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // BatchWrite rejects duplicate targets as a whole.
    let err = client
        .batch_write(pb::BatchWriteRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("w/3", &[("v", i(1))]),
                update_write("w/3", &[("v", i(2))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let err = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/w/3"),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    // Empty document transforms and unspecified server values are malformed.
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Transform(pb::DocumentTransform {
                    document: format!("{DOCS}/w/4"),
                    field_transforms: vec![],
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // Aggregation aliases must be unique.
    let mut dup = agg_count("w", "n");
    dup.aggregations.push(dup.aggregations[0].clone());
    let err = client
        .run_aggregation_query(pb::RunAggregationQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(dup),
            ),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn new_transaction_queries_and_aggregations_read_the_snapshot() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("snap/1", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let mut req = query("snap", None);
    req.consistency_selector = Some(pb::run_query_request::ConsistencySelector::NewTransaction(
        pb::TransactionOptions {
            mode: Some(pb::transaction_options::Mode::ReadWrite(
                pb::transaction_options::ReadWrite {
                    retry_transaction: vec![],
                    ..Default::default()
                },
            )),
        },
    ));
    let mut stream = client.run_query(req).await.unwrap().into_inner();
    let first = stream.next().await.unwrap().unwrap();
    assert!(
        first.document.is_none(),
        "the first response only carries the transaction"
    );
    assert!(!first.transaction.is_empty());
    let txn = first.transaction.clone();
    let second = stream.next().await.unwrap().unwrap();
    assert!(second.document.is_some());
    assert!(second.transaction.is_empty());
    assert!(stream.next().await.is_none());

    // The queried range is locked: a phantom row cannot be written out of band while the
    // transaction is active (production blocks the writer and aborts it).
    let phantom = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("snap/2", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(phantom.code(), tonic::Code::Aborted);
    let mut stream = client
        .run_aggregation_query(pb::RunAggregationQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    agg_count("snap", "n"),
                ),
            ),
            consistency_selector: Some(
                pb::run_aggregation_query_request::ConsistencySelector::Transaction(txn.clone()),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let result = stream.next().await.unwrap().unwrap().result.unwrap();
    assert_eq!(result.aggregate_fields.get("n"), Some(&i(1)));
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("snap/3", &[("v", i(3))])],
            transaction: txn,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/snap/3"),
            ..Default::default()
        })
        .await
        .is_ok());
    // Released: the phantom row can be written now.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("snap/2", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();

    // An empty BatchGet with new_transaction still returns the token.
    let mut stream = client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![],
            consistency_selector: Some(
                pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                    pb::TransactionOptions::default(),
                ),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let only = stream.next().await.unwrap().unwrap();
    assert!(!only.transaction.is_empty());
    assert!(only.result.is_none());
    handle.abort();
}

#[tokio::test]
async fn run_query_streams_bounded_batches_and_releases_its_snapshot_pin() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..65)
                .map(|index| update_write(&format!("paged/{index:03}"), &[("v", i(index))]))
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();

    let responses = client
        .run_query(query("paged", None))
        .await
        .unwrap()
        .into_inner()
        .collect::<Vec<_>>()
        .await;

    assert_eq!(
        responses
            .iter()
            .filter(|response| response
                .as_ref()
                .is_ok_and(|response| response.document.is_some()))
            .count(),
        65
    );
    let names = responses
        .iter()
        .filter_map(|response| response.as_ref().ok()?.document.as_ref())
        .map(|document| document.name.rsplit('/').next().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        (0..65)
            .map(|index| format!("{index:03}"))
            .collect::<Vec<_>>()
    );
    let parent = fireemu_adapter_grpc::decode::parse_parent(DOCS).unwrap();
    assert_eq!(
        backend.read_unadmitted(&parent, |state| state
            .transaction_bookkeeping_stats()
            .active),
        Some(0)
    );
    handle.abort();
}

#[tokio::test]
async fn run_query_pages_seek_value_and_descending_name_orders() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    // A bare descending name order needs an explicit index, as in production.
    let mut indexes = IndexSet::default();
    indexes.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("ordered").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: vec![IndexField {
            path: FieldPath::document_name(),
            mode: IndexFieldMode::Descending,
        }],
    });
    backend.replace_indexes(indexes);
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..65)
                .map(|index| update_write(&format!("ordered/{index:03}"), &[("v", i(index))]))
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();

    for order in ["v", "__name__"] {
        let mut request = query("ordered", None);
        let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
            request.query_type.as_mut()
        else {
            unreachable!();
        };
        query.order_by = vec![sq::Order {
            field: Some(sq::FieldReference {
                field_path: order.to_owned(),
            }),
            direction: sq::Direction::Descending as i32,
        }];
        query.offset = 3;
        query.limit = Some(65);

        let documents = collect_docs(&mut client, request).await;
        let expected = (0..65)
            .rev()
            .skip(3)
            .map(|index| format!("{DOCS}/ordered/{index:03}"))
            .collect::<Vec<_>>();
        assert_eq!(
            documents
                .iter()
                .map(|document| document.name.clone())
                .collect::<Vec<_>>(),
            expected,
            "order {order}"
        );
    }
    handle.abort();
}

#[tokio::test]
async fn value_ordered_transaction_query_commits_after_all_pages() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..65)
                .map(|index| {
                    update_write(
                        &format!("transaction-ordered/{index:03}"),
                        &[("v", i(index))],
                    )
                })
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut request = query("transaction-ordered", None);
    let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        request.query_type.as_mut()
    else {
        unreachable!();
    };
    query.order_by = vec![sq::Order {
        field: Some(sq::FieldReference {
            field_path: "v".to_owned(),
        }),
        direction: sq::Direction::Descending as i32,
    }];
    query.limit = Some(65);
    request.consistency_selector = Some(pb::run_query_request::ConsistencySelector::Transaction(
        transaction.clone(),
    ));

    let documents = collect_docs(&mut client, request).await;
    assert_eq!(documents.len(), 65);
    assert_eq!(documents[0].name, format!("{DOCS}/transaction-ordered/064"));
    assert_eq!(
        documents[64].name,
        format!("{DOCS}/transaction-ordered/000")
    );

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("transaction-ordered/commit", &[("v", i(100))])],
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

#[tokio::test]
async fn run_query_logical_completion_covers_every_page_and_limit() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    for count in [0, 1, 31, 32, 33, 63, 64, 65, 200] {
        let collection = format!("completion-{count}");
        if count > 0 {
            client
                .commit(pb::CommitRequest {
                    database: DB.to_owned(),
                    writes: (0..count)
                        .map(|index| {
                            update_write(&format!("{collection}/{index:03}"), &[("v", i(index))])
                        })
                        .collect(),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        for limit in [
            None,
            Some(1),
            Some(31),
            Some(32),
            Some(33),
            Some(64),
            Some(200),
            Some(201),
        ] {
            let mut request = query(&collection, None);
            let Some(pb::run_query_request::QueryType::StructuredQuery(ref mut query)) =
                request.query_type
            else {
                unreachable!()
            };
            query.limit = limit;
            let mut stream = client.run_query(request).await.unwrap().into_inner();
            let mut names = Vec::new();
            // Production marks no response `done`: the stream's end is the completion.
            while let Some(response) = stream.next().await {
                let response = response.unwrap();
                assert!(response.transaction.is_empty());
                assert_eq!(response.continuation_selector, None);
                if let Some(document) = response.document {
                    names.push(document.name);
                }
            }
            let expected = limit.map_or(count, |limit| count.min(i64::from(limit)));
            assert_eq!(
                names,
                (0..expected)
                    .map(|index| format!("{DOCS}/{collection}/{index:03}"))
                    .collect::<Vec<_>>(),
                "logical completion: count={count}, limit={limit:?}"
            );
            let parent = fireemu_adapter_grpc::decode::parse_parent(DOCS).unwrap();
            assert_eq!(
                backend.read_unadmitted(&parent, |state| state
                    .transaction_bookkeeping_stats()
                    .active),
                Some(0)
            );
        }
    }
    handle.abort();
}

#[tokio::test]
async fn paged_query_preserves_offset_and_read_time_metadata() {
    let (mut client, _clock, _backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..65)
                .map(|index| update_write(&format!("offset-page/{index:03}"), &[("v", i(index))]))
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    for offset in [0, 1, 31, 32, 66] {
        let mut request = query("offset-page", None);
        let Some(pb::run_query_request::QueryType::StructuredQuery(ref mut query)) =
            request.query_type
        else {
            unreachable!()
        };
        query.offset = offset;
        let responses = client
            .run_query(request)
            .await
            .unwrap()
            .into_inner()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(responses
            .iter()
            .all(|r| r.read_time.is_some() && r.transaction.is_empty()));
        assert_eq!(
            responses.iter().map(|r| r.skipped_results).sum::<i32>(),
            offset.min(65)
        );
        let names = responses
            .iter()
            .filter_map(|r| r.document.as_ref().map(|d| d.name.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            (offset..65)
                .map(|index| format!("{DOCS}/offset-page/{index:03}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(responses.last().unwrap().continuation_selector, None);
    }
    handle.abort();
}

async fn seed_large_query_documents(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    collection: &str,
    count: usize,
    payload: &str,
) {
    for start in (0..count).step_by(8) {
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: (start..(start + 8).min(count))
                    .map(|index| {
                        update_write(
                            &format!("{collection}/{index:03}"),
                            &[("payload", s(payload))],
                        )
                    })
                    .collect(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn large_read_only_query_pages_preserve_snapshot_completion_and_cleanup() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    let payload = "x".repeat(192 * 1024);
    let parent = fireemu_adapter_grpc::decode::parse_parent(DOCS).unwrap();
    for count in [64, 65] {
        let collection = format!("large-snapshot-{count}");
        seed_large_query_documents(&mut client, &collection, count, &payload).await;
        let mut stream = client
            .run_query(query(&collection, None))
            .await
            .unwrap()
            .into_inner();
        let first = stream.next().await.unwrap().unwrap();
        assert!(first.document.is_some());
        let read_time = first.read_time;
        assert!(read_time.is_some());
        let bookkeeping = backend
            .read_unadmitted(
                &parent,
                fireemu_core_firestore::store::FirestoreState::transaction_bookkeeping_stats,
            )
            .unwrap();
        assert_eq!(bookkeeping.active, 1);
        assert!(
            bookkeeping.conflict_ledger_bytes < 4096,
            "only the bounded query descriptor is retained"
        );
        // Write while the stream still owns its snapshot; later responses must retain it.
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write(
                    &format!("{collection}/{:03}", count - 1),
                    &[("payload", s("changed"))],
                )],
                ..Default::default()
            })
            .await
            .unwrap();
        let mut response = Some(first);
        let mut names = Vec::new();
        // Production marks no response `done`; the stream's end completes it.
        while let Some(item) = response {
            assert_eq!(item.read_time, read_time);
            assert!(item.transaction.is_empty());
            assert_eq!(item.continuation_selector, None);
            if let Some(document) = item.document {
                assert_eq!(document.fields.get("payload"), Some(&s(&payload)));
                names.push(document.name);
            }
            response = stream.next().await.transpose().unwrap();
        }
        assert_eq!(
            names,
            (0..count)
                .map(|index| format!("{DOCS}/{collection}/{index:03}"))
                .collect::<Vec<_>>()
        );
        let bookkeeping = backend
            .read_unadmitted(
                &parent,
                fireemu_core_firestore::store::FirestoreState::transaction_bookkeeping_stats,
            )
            .unwrap();
        assert_eq!(bookkeeping.active, 0);
        assert_eq!(bookkeeping.conflict_ledger_bytes, 0);

        let mut cancelled = client
            .run_query(query(&collection, None))
            .await
            .unwrap()
            .into_inner();
        assert!(cancelled.next().await.unwrap().unwrap().document.is_some());
        drop(cancelled);
        for _ in 0..1000 {
            if backend.read_unadmitted(&parent, |state| {
                state.transaction_bookkeeping_stats().active
            }) == Some(0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            backend.read_unadmitted(&parent, |state| state
                .transaction_bookkeeping_stats()
                .active),
            Some(0)
        );
    }
    handle.abort();
}

#[tokio::test]
async fn later_query_page_failure_never_announces_success_and_releases_pin() {
    use fireemu_core_session::fault::{
        FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
    };
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    seed_large_query_documents(&mut client, "failed-page", 65, &"x".repeat(192 * 1024)).await;
    let registry = Arc::new(FaultRegistry::new());
    registry.default_state().lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "firestore.read".into(),
                nth: Some(2),
                function: None,
                event_type: None,
            },
            action: FaultAction::ReturnError {
                code: "UNAVAILABLE".into(),
            },
        }],
    });
    backend.set_faults(registry);
    let mut stream = client
        .run_query(query("failed-page", None))
        .await
        .unwrap()
        .into_inner();
    let mut failed = false;
    let mut documents = 0;
    while let Some(response) = stream.next().await {
        match response {
            Ok(response) => {
                assert!(!failed);
                assert!(response.continuation_selector.is_none());
                documents += usize::from(response.document.is_some());
            }
            Err(error) => {
                assert_eq!(error.code(), tonic::Code::Unavailable);
                failed = true;
            }
        }
    }
    assert!(failed);
    assert!(documents < 65);
    let parent = fireemu_adapter_grpc::decode::parse_parent(DOCS).unwrap();
    assert_eq!(
        backend.read_unadmitted(&parent, |state| state
            .transaction_bookkeeping_stats()
            .active),
        Some(0)
    );
    handle.abort();
}

#[tokio::test]
async fn dropping_a_slow_query_stream_releases_the_internal_snapshot_pin() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..65)
                .map(|index| update_write(&format!("cancel/{index:03}"), &[("v", i(index))]))
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut stream = client
        .run_query(query("cancel", None))
        .await
        .unwrap()
        .into_inner();
    assert!(stream.next().await.unwrap().unwrap().document.is_some());
    drop(stream);

    let parent = fireemu_adapter_grpc::decode::parse_parent(DOCS).unwrap();
    for _ in 0..100 {
        if backend.read_unadmitted(&parent, |state| {
            state.transaction_bookkeeping_stats().active
        }) == Some(0)
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        backend.read_unadmitted(&parent, |state| state
            .transaction_bookkeeping_stats()
            .active),
        Some(0)
    );
    handle.abort();
}

#[tokio::test]
async fn aggregation_transaction_locks_the_aggregated_range() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("aggregation-conflict/present", &[("v", i(1))]),
                update_write("aggregation-conflict/missing", &[("other", i(2))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();

    let mut stream = client
        .run_aggregation_query(pb::RunAggregationQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    agg_count_and_sum("aggregation-conflict", "v"),
                ),
            ),
            consistency_selector: Some(
                pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                    pb::TransactionOptions {
                        mode: Some(pb::transaction_options::Mode::ReadWrite(
                            pb::transaction_options::ReadWrite::default(),
                        )),
                    },
                ),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let response = stream.next().await.unwrap().unwrap();
    let result = response.result.unwrap();
    assert_eq!(result.aggregate_fields.get("count"), Some(&i(1)));
    assert_eq!(result.aggregate_fields.get("sum"), Some(&i(1)));
    assert!(!response.transaction.is_empty());
    assert!(stream.next().await.is_none());

    // Giving the missing field a value would change the aggregate, and the range is locked
    // while the transaction is active: the out-of-band write is refused, the transaction
    // commits into the range.
    let refused = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("aggregation-conflict/missing", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Aborted);
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("aggregation-conflict/inside", &[("v", i(3))])],
            transaction: response.transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("aggregation-conflict/missing", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();

    handle.abort();
}

#[tokio::test]
async fn refused_new_transaction_is_abandoned_for_every_shared_selector_surface() {
    let (_client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    let parent = fireemu_adapter_grpc::decode::parse_parent(DOCS).unwrap();
    let assert_no_transaction = || {
        let stats = backend
            .database_handle(&parent)
            .unwrap()
            .with(|db| Ok(db.transaction_bookkeeping_stats()))
            .unwrap();
        assert_eq!(stats.active, 0);
        assert_eq!(stats.finished, 0);
    };

    let batch_error = backend
        .batch_get_documents(
            &pb::BatchGetDocumentsRequest {
                database: DB.to_owned(),
                documents: vec![format!("{DOCS}/denied/batch")],
                consistency_selector: Some(
                    pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                        pb::TransactionOptions::default(),
                    ),
                ),
                ..Default::default()
            },
            &deny_read,
        )
        .unwrap_err();
    assert_eq!(batch_error.code(), tonic::Code::PermissionDenied);
    assert_no_transaction();

    let mut query_request = query("denied", None);
    query_request.consistency_selector =
        Some(pb::run_query_request::ConsistencySelector::NewTransaction(
            pb::TransactionOptions::default(),
        ));
    let query_error = backend.run_query(&query_request, &deny_read).unwrap_err();
    assert_eq!(query_error.code(), tonic::Code::PermissionDenied);
    assert_no_transaction();

    let aggregation_error = backend
        .run_aggregation_query(
            &pb::RunAggregationQueryRequest {
                parent: DOCS.to_owned(),
                query_type: Some(
                    pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                        agg_count("denied", "n"),
                    ),
                ),
                consistency_selector: Some(
                    pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                        pb::TransactionOptions::default(),
                    ),
                ),
                ..Default::default()
            },
            &deny_read,
        )
        .unwrap_err();
    assert_eq!(aggregation_error.code(), tonic::Code::PermissionDenied);
    assert_no_transaction();

    handle.abort();
}

#[tokio::test]
async fn list_documents_pages_by_name_with_opaque_tokens() {
    let (mut client, _clock, handle) = start().await;
    let mut writes: Vec<pb::Write> = (0..5i64)
        .map(|n| update_write(&format!("pg/d{n}"), &[("v", i(n))]))
        .collect();
    writes.extend(
        (0..5i64).map(|n| update_write(&format!("missing/m{n}/children/leaf"), &[("v", i(n))])),
    );
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let mut token = String::new();
    let mut seen = Vec::new();
    loop {
        let page = client
            .list_documents(pb::ListDocumentsRequest {
                parent: DOCS.to_owned(),
                collection_id: "pg".to_owned(),
                page_size: 2,
                page_token: token.clone(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        seen.extend(page.documents.iter().map(|d| d.name.clone()));
        if page.next_page_token.is_empty() {
            break;
        }
        token = page.next_page_token;
    }
    assert_eq!(seen.len(), 5);
    assert!(
        seen.windows(2).all(|w| w[0] < w[1]),
        "listed by name: {seen:?}"
    );
    let mut token = String::new();
    let mut missing = Vec::new();
    loop {
        let page = client
            .list_documents(pb::ListDocumentsRequest {
                parent: DOCS.to_owned(),
                collection_id: "missing".to_owned(),
                page_size: 2,
                page_token: token,
                show_missing: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert!(page
            .documents
            .iter()
            .all(|document| document.fields.is_empty()));
        missing.extend(page.documents.iter().map(|document| document.name.clone()));
        if page.next_page_token.is_empty() {
            break;
        }
        token = page.next_page_token;
    }
    assert_eq!(missing.len(), 5);
    assert!(missing.windows(2).all(|window| window[0] < window[1]));
    for (collection_id, show_missing) in [("pg", false), ("missing", true)] {
        let page = client
            .list_documents(pb::ListDocumentsRequest {
                parent: DOCS.to_owned(),
                collection_id: collection_id.to_owned(),
                page_size: i32::MAX,
                show_missing,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.documents.len(), 5);
        assert!(page.next_page_token.is_empty());
    }
    let err = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "pg".to_owned(),
            page_token: "not-a-token".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn grpc_batch_get_and_list_apply_masks_without_confusing_missing_and_null() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write(
                "types/doc",
                &[
                    ("present", i(1)),
                    (
                        "nullable",
                        pb::Value {
                            value_type: Some(pb::value::ValueType::NullValue(0)),
                        },
                    ),
                ],
            )],
            ..Default::default()
        })
        .await
        .unwrap();

    let mask = pb::DocumentMask {
        field_paths: vec!["nullable".to_owned(), "missing".to_owned()],
    };
    let got = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/types/doc"),
            mask: Some(mask.clone()),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        got.fields
            .get("nullable")
            .and_then(|value| value.value_type.as_ref()),
        Some(&pb::value::ValueType::NullValue(0))
    );
    assert!(!got.fields.contains_key("missing"));
    assert!(!got.fields.contains_key("present"));

    let mut stream = client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![format!("{DOCS}/types/doc"), format!("{DOCS}/types/missing")],
            mask: Some(mask.clone()),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut results = Vec::new();
    while let Some(response) = stream.next().await {
        if let Some(result) = response.unwrap().result {
            results.push(result);
        }
    }
    assert_eq!(results.len(), 2);
    let found = results
        .iter()
        .find_map(|result| match result {
            pb::batch_get_documents_response::Result::Found(document) => Some(document),
            pb::batch_get_documents_response::Result::Missing(_) => None,
        })
        .expect("one found response");
    assert_eq!(found.name, format!("{DOCS}/types/doc"));
    assert_eq!(
        found
            .fields
            .get("nullable")
            .and_then(|value| value.value_type.as_ref()),
        Some(&pb::value::ValueType::NullValue(0))
    );
    assert!(!found.fields.contains_key("missing"));
    assert!(!found.fields.contains_key("present"));
    let missing_name = results
        .iter()
        .find_map(|result| match result {
            pb::batch_get_documents_response::Result::Missing(name) => Some(name),
            pb::batch_get_documents_response::Result::Found(_) => None,
        })
        .expect("one missing response");
    let expected_missing = format!("{DOCS}/types/missing");
    assert_eq!(missing_name, &expected_missing);

    let page = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "types".to_owned(),
            mask: Some(mask),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page.documents.len(), 1);
    assert_eq!(page.documents[0].name, format!("{DOCS}/types/doc"));
    assert_eq!(
        page.documents[0]
            .fields
            .get("nullable")
            .and_then(|value| value.value_type.as_ref()),
        Some(&pb::value::ValueType::NullValue(0))
    );
    assert!(page.documents[0].fields.contains_key("nullable"));
    assert!(!page.documents[0].fields.contains_key("missing"));
    assert!(!page.documents[0].fields.contains_key("present"));
    handle.abort();
}

#[tokio::test]
async fn list_pages_include_missing_parents_in_name_order() {
    let (mut client, _clock, handle) = start().await;
    let mut writes = (0..5i64)
        .map(|value| update_write(&format!("mixed/d{value}"), &[("v", i(value))]))
        .collect::<Vec<_>>();
    writes
        .extend((0..3i64).map(|value| update_write(&format!("mixed/m{value}/children/leaf"), &[])));
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();

    let mut token = String::new();
    let mut seen = Vec::new();
    loop {
        let page = client
            .list_documents(pb::ListDocumentsRequest {
                parent: DOCS.to_owned(),
                collection_id: "mixed".to_owned(),
                page_size: 2,
                page_token: token,
                show_missing: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        seen.extend(page.documents.iter().map(|document| document.name.clone()));
        if page.next_page_token.is_empty() {
            break;
        }
        token = page.next_page_token;
    }

    let expected = ["d0", "d1", "d2", "d3", "d4", "m0", "m1", "m2"]
        .map(|document| format!("{DOCS}/mixed/{document}"));
    assert_eq!(seen, expected);
    handle.abort();
}

#[tokio::test]
async fn list_documents_rejects_show_missing_with_order_by() {
    let (mut client, _clock, handle) = start().await;

    for (order_by, page_token) in [("v desc", ""), ("   ", ""), ("v desc", "%%%INVALID%%%")] {
        let error = client
            .list_documents(pb::ListDocumentsRequest {
                parent: DOCS.to_owned(),
                collection_id: "mixed".to_owned(),
                order_by: order_by.to_owned(),
                page_token: page_token.to_owned(),
                show_missing: true,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            error.message(),
            "cannot specify an order when show_missing is true"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn commit_notifications_are_compact_and_the_ring_is_bounded() {
    use fireemu_adapter_grpc::local::{CommitChangeKind, COMMIT_NOTIFICATION_CAPACITY};

    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    let mut notifications = backend.subscribe();
    for write in [
        update_write("events/a", &[("v", i(1))]),
        update_write("events/a", &[("v", i(2))]),
        delete_write("events/a"),
    ] {
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![write],
                ..Default::default()
            })
            .await
            .unwrap();
    }

    for expected in [
        CommitChangeKind::Created,
        CommitChangeKind::Updated,
        CommitChangeKind::Deleted,
    ] {
        let notification = notifications.recv().await.unwrap();
        assert!(!notification.reset);
        assert_eq!(notification.changes.len(), 1);
        assert_eq!(notification.changes[0].kind, expected);
        assert_eq!(notification.changes[0].path.relative(), "events/a");
    }

    for value in 0..=COMMIT_NOTIFICATION_CAPACITY {
        let value = i64::try_from(value).unwrap();
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write("events/a", &[("v", i(value))])],
                ..Default::default()
            })
            .await
            .unwrap();
    }
    assert!(matches!(
        notifications.recv().await,
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_))
    ));
    handle.abort();
}

#[tokio::test]
async fn a_batched_transaction_query_commits_after_its_continuation_page() {
    let (mut client, _clock, handle) = start().await;
    let writes = (0..33)
        .map(|index| update_write(&format!("continued/{index:03}"), &[("v", i(index))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();

    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            request_options: None,
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut request = query("continued", None);
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        request.query_type.as_mut()
    {
        query.limit = Some(33);
    }
    request.consistency_selector = Some(pb::run_query_request::ConsistencySelector::Transaction(
        transaction.clone(),
    ));
    let documents = collect_docs(&mut client, request).await;

    assert_eq!(documents.len(), 33);
    assert_eq!(
        documents.first().unwrap().name,
        format!("{DOCS}/continued/000")
    );
    assert_eq!(
        documents.last().unwrap().name,
        format!("{DOCS}/continued/032")
    );

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("continued/commit", &[("v", i(1))])],
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

#[tokio::test]
async fn repeated_transaction_queries_keep_observations_separate() {
    let (mut client, _clock, handle) = start().await;
    let writes = (0..33)
        .map(|index| update_write(&format!("repeated/{index:03}"), &[("v", i(index))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();

    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            request_options: None,
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut request = query("repeated", None);
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        request.query_type.as_mut()
    {
        query.limit = Some(33);
    }
    request.consistency_selector = Some(pb::run_query_request::ConsistencySelector::Transaction(
        transaction.clone(),
    ));

    let first = collect_docs(&mut client, request.clone()).await;
    let second = collect_docs(&mut client, request).await;
    assert_eq!(first.len(), 33);
    assert_eq!(second.len(), 33);

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("repeated/commit", &[("v", i(1))])],
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

#[tokio::test]
async fn direct_authorized_query_continuation_reuses_public_transaction_execution() {
    let (_client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    backend
        .commit(&pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..33)
                .map(|index| update_write(&format!("direct/{index:03}"), &[("v", i(index))]))
                .collect(),
            ..Default::default()
        })
        .unwrap();
    let transaction = backend
        .begin_transaction(&pb::BeginTransactionRequest {
            database: DB.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
            ..Default::default()
        })
        .unwrap();
    let mut original = query("direct", None);
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        original.query_type.as_mut()
    {
        query.limit = Some(33);
    }
    original.consistency_selector = Some(pb::run_query_request::ConsistencySelector::Transaction(
        transaction.clone(),
    ));
    let mut first_request = original.clone();
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        first_request.query_type.as_mut()
    {
        query.limit = Some(32);
    }
    let (first, _) = backend
        .run_query_authorized_as(
            &first_request,
            &original,
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .unwrap();
    let last_document = first
        .iter()
        .rev()
        .find_map(|response| response.document.as_ref())
        .expect("the first bounded page returns a document");
    let after = fireemu_adapter_grpc::encode::decode_document_name(&last_document.name).unwrap();
    let mut continuation_request = original.clone();
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        continuation_request.query_type.as_mut()
    {
        query.limit = Some(1);
    }
    let (second, _) = backend
        .run_query_authorized_as_after(
            &continuation_request,
            &original,
            &fireemu_adapter_grpc::rules::allow_all_reads,
            Some(&after),
        )
        .unwrap();
    assert_eq!(
        second
            .iter()
            .filter(|response| response.document.is_some())
            .count(),
        1
    );
    backend
        .commit(&pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("direct/commit", &[("v", i(1))])],
            transaction,
            ..Default::default()
        })
        .unwrap();
    handle.abort();
}

#[tokio::test]
async fn interleaved_identical_transaction_queries_keep_observations_separate() {
    let (mut client, _clock, handle) = start().await;
    let writes = (0..33)
        .map(|index| update_write(&format!("interleaved/{index:03}"), &[("v", i(index))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();

    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut request = query("interleaved", None);
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        request.query_type.as_mut()
    {
        query.limit = Some(33);
    }
    request.consistency_selector = Some(pb::run_query_request::ConsistencySelector::Transaction(
        transaction.clone(),
    ));

    let mut second_client = client.clone();
    let (first, second) = tokio::join!(
        collect_docs(&mut client, request.clone()),
        collect_docs(&mut second_client, request),
    );
    assert_eq!(first.len(), 33);
    assert_eq!(second.len(), 33);

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("interleaved/commit", &[("v", i(1))])],
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

#[tokio::test]
async fn cancelled_transaction_query_can_be_retried_before_commit() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..64)
                .map(|index| update_write(&format!("cancelled/{index:03}"), &[("v", i(index))]))
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();

    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut request = query("cancelled", None);
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        request.query_type.as_mut()
    {
        query.limit = Some(64);
    }
    request.consistency_selector = Some(pb::run_query_request::ConsistencySelector::Transaction(
        transaction.clone(),
    ));

    let mut partial = client
        .run_query(request.clone())
        .await
        .unwrap()
        .into_inner();
    assert!(partial.next().await.unwrap().unwrap().document.is_some());
    drop(partial);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let retried = collect_docs(&mut client, request).await;
    assert_eq!(retried.len(), 64);
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("cancelled/commit", &[("v", i(1))])],
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

#[tokio::test]
async fn large_transaction_queries_keep_one_observation_across_all_pages() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;

    for (collection, count) in [
        ("large-8191", 8_191),
        ("large-8192", 8_192),
        ("large-8193", 8_193),
    ] {
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: (0..count)
                    .map(|index| {
                        update_write(
                            &format!("{collection}/{index:05}"),
                            &[(
                                "v",
                                i(i64::try_from(index).expect("test document index fits in i64")),
                            )],
                        )
                    })
                    .collect(),
                ..Default::default()
            })
            .await
            .unwrap();

        let transaction = client
            .begin_transaction(pb::BeginTransactionRequest {
                database: DB.to_owned(),
                options: Some(pb::TransactionOptions {
                    mode: Some(pb::transaction_options::Mode::ReadWrite(
                        pb::transaction_options::ReadWrite::default(),
                    )),
                }),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .transaction;
        let mut request = query(collection, None);
        request.consistency_selector = Some(
            pb::run_query_request::ConsistencySelector::Transaction(transaction.clone()),
        );
        let documents = collect_docs(&mut client, request).await;
        assert_eq!(documents.len(), count);

        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write(
                    &format!("{collection}/committed"),
                    &[("v", i(1))],
                )],
                transaction,
                ..Default::default()
            })
            .await
            .unwrap();

        let parent = fireemu_adapter_grpc::decode::parse_parent(DOCS).unwrap();
        let bookkeeping = backend
            .read_unadmitted(
                &parent,
                fireemu_core_firestore::store::FirestoreState::transaction_bookkeeping_stats,
            )
            .unwrap();
        assert_eq!(bookkeeping.active, 0);
        assert_eq!(bookkeeping.deadlines, 0);
        assert_eq!(bookkeeping.conflict_ledger_bytes, 0);
    }

    handle.abort();
}

#[tokio::test]
async fn list_document_tokens_bind_result_shape_and_session() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..3)
                .map(|index| update_write(&format!("pg/d{index}"), &[]))
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let first_token = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "pg".to_owned(),
            page_size: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .next_page_token;

    for (show_missing, order_by) in [(true, ""), (false, "__name__ desc")] {
        let error = client
            .list_documents(pb::ListDocumentsRequest {
                parent: DOCS.to_owned(),
                collection_id: "pg".to_owned(),
                page_size: 1,
                page_token: first_token.clone(),
                show_missing,
                order_by: order_by.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
    let decoded =
        String::from_utf8(fireemu_adapter_grpc::rest::json::base64_decode(&first_token).unwrap())
            .unwrap();
    let (_, identity) = decoded.split_once('\n').unwrap();
    let forged = fireemu_adapter_grpc::rest::json::base64_encode(
        format!("{DOCS}/other/a\n{identity}").as_bytes(),
    );
    let error = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "pg".to_owned(),
            page_size: 1,
            page_token: forged,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    backend.reset_scope(&Scope::Project("demo-app".to_owned()));
    let error = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "pg".to_owned(),
            page_size: 1,
            page_token: first_token,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    handle.abort();
}

#[tokio::test]
async fn verify_writes_check_preconditions_without_changing_anything() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("vf/a", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let verify = |exists: bool| pb::Write {
        operation: Some(pb::write::Operation::Verify(format!("{DOCS}/vf/a"))),
        current_document: Some(pb::Precondition {
            condition_type: Some(pb::precondition::ConditionType::Exists(exists)),
        }),
        ..Default::default()
    };
    // A transaction that read vf/a and writes vf/b sends a verify for vf/a.
    let response = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![verify(true), update_write("vf/b", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.write_results.len(), 2);
    // A verify reports the update time of the document it verified (the official emulator
    // reports one too; conformance/src/firestore-probe, writes/preconditions-and-masks).
    assert!(response.write_results[0].update_time.is_some());
    assert_ne!(
        response.write_results[0].update_time, response.write_results[1].update_time,
        "the verified document keeps its own update time, not the commit's"
    );
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![verify(false)],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists);
    let doc = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/vf/a"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(doc.fields.get("v"), Some(&i(1)), "verify changed nothing");
    handle.abort();
}

#[tokio::test]
async fn read_time_selectors_serve_historical_snapshots() {
    let (mut client, clock, handle) = start().await;
    // The database exists for a second before the document does, so a read_time just before
    // the first write is a read of an existing database in which the document is missing.
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(1))
        .unwrap();
    let t0 = clock.lock().unwrap().now();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("hist/a", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let t1 = clock.lock().unwrap().now();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(60))
        .unwrap();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("hist/a", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let at = |t: LogicalInstant| {
        Some(pb::get_document_request::ConsistencySelector::ReadTime(
            fireemu_adapter_grpc::encode::encode_instant(t),
        ))
    };
    let old = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/hist/a"),
            consistency_selector: at(t1),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(old.fields.get("v"), Some(&i(1)));
    let before = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/hist/a"),
            consistency_selector: at(LogicalInstant::from_nanos(t0.as_nanos() - 1_000)),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(before.code(), tonic::Code::NotFound);
    let mut q = query("hist", None);
    q.consistency_selector = Some(pb::run_query_request::ConsistencySelector::ReadTime(
        fireemu_adapter_grpc::encode::encode_instant(t1),
    ));
    let docs = collect_docs(&mut client, q).await;
    assert_eq!(docs[0].fields.get("v"), Some(&i(1)));
    handle.abort();
}

#[tokio::test]
async fn every_read_time_surface_refuses_a_capacity_compacted_snapshot() {
    let (mut client, clock, handle) = start().await;
    let old = fireemu_adapter_grpc::encode::encode_instant(clock.lock().unwrap().now());
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("capacity/a", &[("v", i(0))])],
            ..Default::default()
        })
        .await
        .unwrap();
    for value in 1..=fireemu_core_firestore::store::DEFAULT_MAX_RETAINED_VERSIONS_PER_PATH {
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write(
                    "capacity/a",
                    &[("v", i(i64::try_from(value).unwrap()))],
                )],
                ..Default::default()
            })
            .await
            .unwrap();
    }

    let get = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/capacity/a"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::ReadTime(
                old,
            )),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(get.code(), tonic::Code::FailedPrecondition);

    let batch = client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![format!("{DOCS}/capacity/a")],
            consistency_selector: Some(
                pb::batch_get_documents_request::ConsistencySelector::ReadTime(old),
            ),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(batch.code(), tonic::Code::FailedPrecondition);

    let mut run_query = query("capacity", None);
    run_query.consistency_selector =
        Some(pb::run_query_request::ConsistencySelector::ReadTime(old));
    let query_error = client.run_query(run_query).await.unwrap_err();
    assert_eq!(query_error.code(), tonic::Code::FailedPrecondition);

    let aggregation_error = client
        .run_aggregation_query(pb::RunAggregationQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    agg_count("capacity", "count"),
                ),
            ),
            consistency_selector: Some(
                pb::run_aggregation_query_request::ConsistencySelector::ReadTime(old),
            ),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(aggregation_error.code(), tonic::Code::FailedPrecondition);

    let list_error = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "capacity".to_owned(),
            consistency_selector: Some(pb::list_documents_request::ConsistencySelector::ReadTime(
                old,
            )),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(list_error.code(), tonic::Code::FailedPrecondition);
    handle.abort();
}

#[tokio::test]
async fn clock_maintenance_compacts_an_idle_database_without_another_commit() {
    let (mut client, clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("idle/a", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(1_800))
        .unwrap();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("idle/a", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let parent = fireemu_adapter_grpc::decode::parse_parent(&format!("{DB}/documents")).unwrap();
    let database = backend.database_handle(&parent).unwrap();
    assert_eq!(
        database
            .with(|state| Ok(state.compaction_floor().value()))
            .unwrap(),
        0
    );

    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(7_200))
        .unwrap();
    backend.compact_all(clock.lock().unwrap().now());

    assert!(
        database
            .with(|state| Ok(state.compaction_floor().value()))
            .unwrap()
            > 0,
        "clock maintenance releases history even when no later write arrives"
    );
    handle.abort();
}

#[tokio::test]
async fn wall_clock_restores_keep_the_time_window_without_the_pinned_clock_cap() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(true, IndexValidationPolicy::Production).await;
    backend
        .restore_databases(std::collections::BTreeMap::from([(
            (
                "demo-app".to_owned(),
                fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned(),
            ),
            fireemu_core_firestore::store::FirestoreState::new(),
        )]))
        .unwrap();
    for value in 0..=fireemu_core_firestore::store::DEFAULT_MAX_RETAINED_VERSIONS_PER_PATH {
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write(
                    "wall/a",
                    &[("v", i(i64::try_from(value).unwrap()))],
                )],
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let parent = fireemu_adapter_grpc::decode::parse_parent(&format!("{DB}/documents")).unwrap();
    let retained = backend
        .database_handle(&parent)
        .unwrap()
        .with(|state| Ok(state.retained_versions()))
        .unwrap();
    assert_eq!(
        retained,
        fireemu_core_firestore::store::DEFAULT_MAX_RETAINED_VERSIONS_PER_PATH + 1,
        "wall-clock parity keeps every version still inside the documented time window"
    );
    handle.abort();
}

#[tokio::test]
async fn list_documents_inside_a_transaction_records_the_scan() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("scan/a", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let listed = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "scan".to_owned(),
            consistency_selector: Some(
                pb::list_documents_request::ConsistencySelector::Transaction(txn.clone()),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.documents.len(), 1);
    // The listed range is locked like a queried one: a new row cannot be written out of band
    // while the transaction is active, and the transaction commits into the range.
    let refused = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("scan/b", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Aborted);
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("scan/a", &[("v", i(3))])],
            transaction: txn,
            ..Default::default()
        })
        .await
        .unwrap();
    let current = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/scan/a"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(current.fields.get("v"), Some(&i(3)));
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn read_time_selectors_are_validated_and_read_only_transactions_can_start_at_one() {
    let (mut client, clock, handle) = start().await;
    let first = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("rt/a", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .commit_time
        .unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(10))
        .unwrap();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("rt/a", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let get_at = |ts: prost_types::Timestamp| pb::GetDocumentRequest {
        name: format!("{DOCS}/rt/a"),
        consistency_selector: Some(pb::get_document_request::ConsistencySelector::ReadTime(ts)),
        ..Default::default()
    };
    // Sub-microsecond precision, the future and the distant past are rejected.
    for (ts, what) in [
        (
            prost_types::Timestamp {
                seconds: first.seconds,
                nanos: first.nanos + 1,
            },
            "nanosecond precision",
        ),
        (
            prost_types::Timestamp {
                seconds: first.seconds + 3600,
                nanos: 0,
            },
            "future",
        ),
        (
            prost_types::Timestamp {
                seconds: first.seconds - 7200,
                nanos: 0,
            },
            "before the database was created",
        ),
        (
            prost_types::Timestamp {
                seconds: first.seconds,
                nanos: 1_000_000_000,
            },
            "nanos out of range",
        ),
    ] {
        let err = client.get_document(get_at(ts)).await.unwrap_err();
        // A read_time before the database existed is INVALID_ARGUMENT like a malformed one
        // (production: "cannot be before database creation time").
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{what}");
    }
    // An empty transaction token is not "no transaction".
    let err = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/rt/a"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                Vec::new(),
            )),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // A read-only transaction at the first commit time reads that snapshot.
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadOnly(
                    pb::transaction_options::ReadOnly {
                        consistency_selector: Some(
                            pb::transaction_options::read_only::ConsistencySelector::ReadTime(
                                first,
                            ),
                        ),
                    },
                )),
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let doc = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/rt/a"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                txn.clone(),
            )),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(doc.fields.get("v"), Some(&i(1)));
    // The same through `new_transaction` on a query.
    let mut q = query("rt", None);
    q.consistency_selector = Some(pb::run_query_request::ConsistencySelector::NewTransaction(
        pb::TransactionOptions {
            mode: Some(pb::transaction_options::Mode::ReadOnly(
                pb::transaction_options::ReadOnly {
                    consistency_selector: Some(
                        pb::transaction_options::read_only::ConsistencySelector::ReadTime(first),
                    ),
                },
            )),
        },
    ));
    let docs = collect_docs(&mut client, q).await;
    assert_eq!(docs[0].fields.get("v"), Some(&i(1)));
    // Inside the database's life but older than the retention window is FAILED_PRECONDITION
    // with production's wording.
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(7200))
        .unwrap();
    let too_old = client.get_document(get_at(first)).await.unwrap_err();
    assert_eq!(too_old.code(), tonic::Code::FailedPrecondition);
    assert_eq!(too_old.message(), "The requested 'read_time' is too old.");
    handle.abort();
}

#[tokio::test]
async fn list_page_tokens_are_bound_to_their_listing() {
    let (mut client, _clock, handle) = start().await;
    let writes = (0..3)
        .map(|n| update_write(&format!("pg/{n}"), &[("v", i(n))]))
        .collect();
    let committed = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let page = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "pg".to_owned(),
            page_size: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!page.next_page_token.is_empty());
    let continued = |token: String, collection: &str, selector| pb::ListDocumentsRequest {
        parent: DOCS.to_owned(),
        collection_id: collection.to_owned(),
        page_size: 1,
        page_token: token,
        consistency_selector: selector,
        ..Default::default()
    };
    assert!(client
        .list_documents(continued(page.next_page_token.clone(), "pg", None))
        .await
        .is_ok());
    let err = client
        .list_documents(continued(page.next_page_token.clone(), "other", None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "Invalid page token.");
    // The snapshot is not part of the listing: production continues a token at a read time
    // (FS-DATA-WRITE-LIST read-time#paged-at-write-1-next-without-read-time).
    let continued_at = client
        .list_documents(continued(
            page.next_page_token,
            "pg",
            Some(pb::list_documents_request::ConsistencySelector::ReadTime(
                committed.commit_time.unwrap(),
            )),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(continued_at.documents[0].name.ends_with("/pg/1"));
    handle.abort();
}

#[tokio::test]
async fn database_snapshots_restore_documents_and_start_a_new_epoch() {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = LocalBackend::new(gateway, clock, 7);
    let write = |name: &str, v: i64| pb::CommitRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        writes: vec![update_write(name, &[("v", i(v))])],
        ..Default::default()
    };
    backend.commit(&write("snap/a", 1)).unwrap();
    let taken = backend.snapshot_databases();
    assert_eq!(taken.len(), 1);
    backend.commit(&write("snap/a", 2)).unwrap();
    backend.commit(&write("snap/b", 1)).unwrap();
    let epoch = backend.epoch();
    backend.restore_databases(taken).unwrap();
    assert_eq!(backend.epoch(), epoch + 1, "a restore is a new epoch");
    let get = |name: &str| pb::GetDocumentRequest {
        name: format!("projects/demo-app/databases/(default)/documents/{name}"),
        ..Default::default()
    };
    let a = backend
        .get_document(
            &get("snap/a"),
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .unwrap();
    assert_eq!(
        a.fields["v"].value_type,
        Some(pb::value::ValueType::IntegerValue(1))
    );
    assert_eq!(
        backend
            .get_document(
                &get("snap/b"),
                &fireemu_adapter_grpc::rules::allow_all_reads
            )
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    // The restored state keeps committing.
    backend.commit(&write("snap/c", 1)).unwrap();
    assert!(backend
        .get_document(
            &get("snap/c"),
            &fireemu_adapter_grpc::rules::allow_all_reads
        )
        .is_ok());
}

#[tokio::test]
async fn fault_plans_fail_the_nth_commit_and_time_out_reads() {
    use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = LocalBackend::new(gateway, clock.clone(), 7);
    let registry = Arc::new(fireemu_core_session::fault::FaultRegistry::new());
    let faults = registry.default_state();
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![
            FaultRule {
                matches: FaultMatch {
                    operation: "firestore.commit".into(),
                    nth: Some(2),
                    function: None,
                    event_type: None,
                },
                action: FaultAction::ReturnError {
                    code: "ABORTED".into(),
                },
            },
            FaultRule {
                matches: FaultMatch {
                    operation: "firestore.read".into(),
                    nth: Some(1),
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Timeout,
            },
            FaultRule {
                matches: FaultMatch {
                    operation: "firestore.commit".into(),
                    nth: Some(3),
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Delay { seconds: 90 },
            },
        ],
    });
    backend.set_faults(registry.clone());
    let write = |name: &str, v: i64| pb::CommitRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        writes: vec![update_write(name, &[("v", i(v))])],
        ..Default::default()
    };
    assert!(backend.commit(&write("f/a", 1)).is_ok());
    let err = backend.commit(&write("f/b", 1)).unwrap_err();
    assert_eq!(err.code(), tonic::Code::Aborted);
    assert!(err.message().contains("fault plan"));
    // The third commit is delayed: the clock moved 90 s before it ran.
    let before = clock.lock().unwrap().now_for_test();
    assert!(backend.commit(&write("f/c", 1)).is_ok());
    let after = clock.lock().unwrap().now_for_test();
    assert_eq!(after.as_nanos() - before.as_nanos(), 90 * 1_000_000_000);
    let get = |name: &str| pb::GetDocumentRequest {
        name: format!("projects/demo-app/databases/(default)/documents/{name}"),
        ..Default::default()
    };
    assert_eq!(
        backend
            .get_document(&get("f/a"), &fireemu_adapter_grpc::rules::allow_all_reads)
            .unwrap_err()
            .code(),
        tonic::Code::DeadlineExceeded
    );
    assert!(backend
        .get_document(&get("f/a"), &fireemu_adapter_grpc::rules::allow_all_reads)
        .is_ok());
    let fired = faults.lock().unwrap().fired().len();
    assert_eq!(fired, 3);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn execute_pipeline_validates_unsupported_shapes_and_executes_supported_subset() {
    // Typed arguments: a collection path, a boolean function, an integer.
    let stage = |name: &str, args: usize| pb::pipeline::Stage {
        name: name.to_owned(),
        args: (0..args)
            .map(|_| match name {
                "collection" => pb::Value {
                    value_type: Some(pb::value::ValueType::ReferenceValue("/users".to_owned())),
                },
                "where" => pb::Value {
                    value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
                        name: "equal".to_owned(),
                        args: vec![
                            pb::Value {
                                value_type: Some(pb::value::ValueType::FieldReferenceValue(
                                    "age".to_owned(),
                                )),
                            },
                            i(3),
                        ],
                        options: std::collections::HashMap::default(),
                    })),
                },
                "limit" => i(5),
                _ => s("x"),
            })
            .collect(),
        options: std::collections::HashMap::default(),
    };
    let request = |stages: Vec<pb::pipeline::Stage>| pb::ExecutePipelineRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline { stages }),
                    options: std::collections::HashMap::default(),
                },
            ),
        ),
        ..Default::default()
    };
    // Standard edition: pipelines are an Enterprise feature.
    let (mut client, _, handle) = start().await;
    let err = client
        .execute_pipeline(request(vec![stage("collection", 1)]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        err.metadata().get("fireemu-code").unwrap(),
        "FS_PIPE_EDITION"
    );
    handle.abort();
    // Enterprise: supported reads execute; other shapes retain explicit refusals.
    let (mut client, _, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    let mut valid = client
        .execute_pipeline(request(vec![
            stage("collection", 1),
            stage("where", 1),
            stage("limit", 1),
        ]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(valid.message().await.unwrap().unwrap().results.len(), 0);
    let unknown = client
        .execute_pipeline(request(vec![stage("collection", 1), stage("explode", 1)]))
        .await
        .unwrap_err();
    assert_eq!(unknown.code(), tonic::Code::Unimplemented);
    assert_eq!(
        unknown.metadata().get("fireemu-code").unwrap(),
        "FS_PIPE_UNSUPPORTED_STAGE"
    );
    let write = client
        .execute_pipeline(request(vec![stage("collection", 1), stage("update", 1)]))
        .await
        .unwrap_err();
    assert_eq!(
        write.metadata().get("fireemu-code").unwrap(),
        "FS_PIPE_WRITE_0"
    );
    let misplaced = client
        .execute_pipeline(request(vec![stage("where", 1)]))
        .await
        .unwrap_err();
    assert_eq!(misplaced.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        misplaced.metadata().get("fireemu-code").unwrap(),
        "FS_PIPE_INVALID"
    );
    let empty = client
        .execute_pipeline(pb::ExecutePipelineRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        empty.metadata().get("fireemu-code").unwrap(),
        "FS_PIPE_DECODE"
    );
    // Strict: argument shapes, option keys, the database name and the consistency
    // selector are checked, not only stage names and arities.
    let typed = |name: &str, value: pb::Value| pb::pipeline::Stage {
        name: name.to_owned(),
        args: vec![value],
        options: std::collections::HashMap::default(),
    };
    for (what, bad) in [
        (
            "limit(text)",
            request(vec![stage("collection", 1), typed("limit", s("text"))]),
        ),
        (
            "collection(null)",
            request(vec![typed("collection", pb::Value { value_type: None })]),
        ),
        (
            "collection(document path)",
            request(vec![typed("collection", s("/users/u1"))]),
        ),
        (
            "where(string)",
            request(vec![stage("collection", 1), typed("where", s("x"))]),
        ),
        (
            "unknown option",
            request(vec![
                stage("collection", 1),
                pb::pipeline::Stage {
                    name: "sample".to_owned(),
                    args: vec![i(3)],
                    options: [("speed".to_owned(), s("fast"))].into_iter().collect(),
                },
            ]),
        ),
        (
            "garbage database",
            pb::ExecutePipelineRequest {
                database: "garbage".to_owned(),
                ..request(vec![stage("collection", 1)])
            },
        ),
        (
            "pipeline option",
            pb::ExecutePipelineRequest {
                pipeline_type: Some(
                    pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                        pb::StructuredPipeline {
                            pipeline: Some(pb::Pipeline {
                                stages: vec![stage("collection", 1)],
                            }),
                            options: [("turbo".to_owned(), s("on"))].into_iter().collect(),
                        },
                    ),
                ),
                ..request(vec![])
            },
        ),
        (
            "auto-commit without a new transaction",
            pb::ExecutePipelineRequest {
                auto_commit_transaction: true,
                ..request(vec![stage("collection", 1)])
            },
        ),
    ] {
        let err = client.execute_pipeline(bad).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{what}: {err}");
        assert_eq!(
            err.metadata().get("fireemu-code").unwrap(),
            "FS_PIPE_INVALID",
            "{what}"
        );
    }
    handle.abort();
}

async fn drain_pipeline(
    mut stream: tonic::Streaming<pb::ExecutePipelineResponse>,
    messages: usize,
) -> Vec<pb::Document> {
    let mut documents = Vec::new();
    let mut received = 0;
    while let Some(response) = stream.next().await {
        let response = response.unwrap();
        assert!(
            response.results.len() <= 1,
            "one document per wire response"
        );
        for doc in &response.results {
            assert!(doc.name.is_empty());
            assert!(doc.create_time.is_none());
            assert!(doc.update_time.is_none());
        }
        documents.extend(response.results);
        received += 1;
    }
    assert_eq!(received, messages);
    documents
}

fn pipeline_stage(name: &str, value: pb::Value) -> pb::pipeline::Stage {
    pb::pipeline::Stage {
        name: name.to_owned(),
        args: vec![value],
        ..Default::default()
    }
}

fn pipeline_request(stages: Vec<pb::pipeline::Stage>) -> pb::ExecutePipelineRequest {
    pb::ExecutePipelineRequest {
        database: DB.to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline { stages }),
                    ..Default::default()
                },
            ),
        ),
        ..Default::default()
    }
}

fn pipeline_field(field: &str) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::FieldReferenceValue(field.to_owned())),
    }
}

fn pipeline_function(name: &str, args: Vec<pb::Value>) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
            name: name.to_owned(),
            args,
            ..Default::default()
        })),
    }
}

fn pipeline_equal(field: &str, value: pb::Value) -> pb::pipeline::Stage {
    pipeline_stage(
        "where",
        pipeline_function("equal", vec![pipeline_field(field), value]),
    )
}

fn pipeline_select(field: &str) -> pb::pipeline::Stage {
    pipeline_stage(
        "select",
        pb::Value {
            value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                fields: [("label".to_owned(), pipeline_field(field))]
                    .into_iter()
                    .collect(),
            })),
        },
    )
}

fn pipeline_offset(value: i64) -> pb::pipeline::Stage {
    pipeline_stage("offset", i(value))
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn execute_pipeline_where_equal_executes_scalar_matrix_and_rejects_missing_fields() {
    use pb::value::ValueType as V;
    let value = |v| pb::Value {
        value_type: Some(v),
    };
    let cases = [
        (
            "bool",
            V::BooleanValue(true),
            V::BooleanValue(true),
            V::BooleanValue(false),
        ),
        (
            "integer",
            V::IntegerValue(7),
            V::IntegerValue(7),
            V::IntegerValue(8),
        ),
        (
            "integer-double",
            V::IntegerValue(7),
            V::DoubleValue(7.0),
            V::DoubleValue(8.0),
        ),
        (
            "double-integer",
            V::DoubleValue(7.0),
            V::IntegerValue(7),
            V::DoubleValue(8.0),
        ),
        (
            "timestamp",
            V::TimestampValue(prost_types::Timestamp {
                seconds: 123,
                nanos: 456_000,
            }),
            V::TimestampValue(prost_types::Timestamp {
                seconds: 123,
                nanos: 456_000,
            }),
            V::TimestampValue(prost_types::Timestamp {
                seconds: 123,
                nanos: 457_000,
            }),
        ),
        (
            "string",
            V::StringValue("keep".into()),
            V::StringValue("keep".into()),
            V::StringValue("drop".into()),
        ),
        (
            "bytes",
            V::BytesValue(vec![0, 255]),
            V::BytesValue(vec![0, 255]),
            V::BytesValue(vec![0, 254]),
        ),
        (
            "reference",
            V::ReferenceValue(format!("{DOCS}/refs/one")),
            V::ReferenceValue(format!("{DOCS}/refs/one")),
            V::ReferenceValue(format!("{DOCS}/refs/two")),
        ),
        (
            "geo",
            V::GeoPointValue(fireemu_proto_firestore::google::r#type::LatLng {
                latitude: 1.0,
                longitude: 2.0,
            }),
            V::GeoPointValue(fireemu_proto_firestore::google::r#type::LatLng {
                latitude: 1.0,
                longitude: 2.0,
            }),
            V::GeoPointValue(fireemu_proto_firestore::google::r#type::LatLng {
                latitude: 1.0,
                longitude: 3.0,
            }),
        ),
        (
            "infinity",
            V::DoubleValue(f64::INFINITY),
            V::DoubleValue(f64::INFINITY),
            V::DoubleValue(f64::NEG_INFINITY),
        ),
        (
            "null",
            V::NullValue(0),
            V::NullValue(0),
            V::BooleanValue(false),
        ),
        (
            "nan",
            V::DoubleValue(f64::NAN),
            V::DoubleValue(f64::NAN),
            V::DoubleValue(0.0),
        ),
    ];
    let (mut client, _, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    for (label, stored, literal, nonmatch) in cases {
        let collection = format!("scalar-{label}");
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![
                    update_write(
                        &format!("{collection}/a"),
                        &[("score", value(nonmatch)), ("name", s("drop"))],
                    ),
                    update_write(
                        &format!("{collection}/b"),
                        &[("score", value(stored)), ("name", s("keep"))],
                    ),
                    update_write(&format!("{collection}/c"), &[("name", s("missing"))]),
                ],
                ..Default::default()
            })
            .await
            .unwrap();
        // No limit or projection: every result must be the matching document, including null/NaN.
        let docs = drain_pipeline(
            client
                .execute_pipeline(pipeline_request(vec![
                    pipeline_stage("collection", s(&collection)),
                    pipeline_equal("score", value(literal)),
                ]))
                .await
                .unwrap()
                .into_inner(),
            1,
        )
        .await;
        assert_eq!(docs.len(), 1, "{label}");
        assert_eq!(docs[0].fields.get("name"), Some(&s("keep")), "{label}");
        assert_eq!(docs[0].fields.len(), 2, "{label}");
    }
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn execute_pipeline_where_equal_refusals_preserve_status_context_and_documents() {
    use pb::value::ValueType as V;
    let collection = || pipeline_stage("collection", s("where-refusals"));
    let predicate = || pipeline_equal("score", i(7));
    let unsupported = tonic::Code::Unimplemented;
    let invalid = tonic::Code::InvalidArgument;
    let expression = |name: &str, args| pipeline_stage("where", pipeline_function(name, args));
    let mut options = pipeline_function("equal", vec![pipeline_field("score"), i(7)]);
    let Some(V::FunctionValue(function)) = options.value_type.as_mut() else {
        unreachable!()
    };
    function.options.insert("unexpected".into(), i(1));
    let cases = [
        (
            "duplicate where",
            vec![predicate(), predicate()],
            unsupported,
        ),
        (
            "where after select",
            vec![pipeline_select("score"), predicate()],
            unsupported,
        ),
        (
            "where after limit",
            vec![pipeline_stage("limit", i(1)), predicate()],
            unsupported,
        ),
        (
            "other function",
            vec![expression("less_than", vec![pipeline_field("score"), i(7)])],
            unsupported,
        ),
        (
            "eq alias",
            vec![expression("eq", vec![pipeline_field("score"), i(7)])],
            unsupported,
        ),
        (
            "reversed operands",
            vec![expression("equal", vec![i(7), pipeline_field("score")])],
            unsupported,
        ),
        (
            "expression left",
            vec![expression(
                "equal",
                vec![
                    pipeline_function("abs", vec![pipeline_field("score")]),
                    i(7),
                ],
            )],
            unsupported,
        ),
        (
            "nested field",
            vec![pipeline_equal("profile.score", i(7))],
            unsupported,
        ),
        (
            "document name",
            vec![pipeline_equal("__name__", s("x"))],
            unsupported,
        ),
        (
            "array literal",
            vec![pipeline_equal(
                "score",
                pb::Value {
                    value_type: Some(V::ArrayValue(pb::ArrayValue { values: vec![i(7)] })),
                },
            )],
            unsupported,
        ),
        (
            "map literal",
            vec![pipeline_equal(
                "score",
                pb::Value {
                    value_type: Some(V::MapValue(pb::MapValue {
                        fields: [("n".into(), i(7))].into_iter().collect(),
                    })),
                },
            )],
            unsupported,
        ),
        (
            "expression right",
            vec![pipeline_equal(
                "score",
                pipeline_function("abs", vec![i(7)]),
            )],
            unsupported,
        ),
        (
            "field right",
            vec![pipeline_equal("score", pipeline_field("other"))],
            unsupported,
        ),
        ("zero arity", vec![expression("equal", vec![])], invalid),
        (
            "one argument",
            vec![expression("equal", vec![pipeline_field("score")])],
            invalid,
        ),
        (
            "three arguments",
            vec![expression(
                "equal",
                vec![pipeline_field("score"), i(7), i(8)],
            )],
            invalid,
        ),
        (
            "function options",
            vec![pipeline_stage("where", options)],
            invalid,
        ),
        ("empty field", vec![pipeline_equal("", i(7))], invalid),
        ("invalid field", vec![pipeline_equal("a..b", i(7))], invalid),
        (
            "missing literal",
            vec![pipeline_equal("score", pb::Value::default())],
            invalid,
        ),
        (
            "missing left operand",
            vec![expression("equal", vec![pb::Value::default(), i(7)])],
            invalid,
        ),
    ];
    let (mut client, _, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write(
                "where-refusals/a",
                &[("score", i(7)), ("name", s("original"))],
            )],
            ..Default::default()
        })
        .await
        .unwrap();
    let get = pb::GetDocumentRequest {
        name: format!("{DOCS}/where-refusals/a"),
        ..Default::default()
    };
    let before = client.get_document(get.clone()).await.unwrap().into_inner();
    for (label, tail, code) in cases {
        let stages = std::iter::once(collection())
            .chain(tail)
            .collect::<Vec<_>>();
        let canonical = stages
            .iter()
            .map(|stage| format!("{}({})", stage.name, stage.args.len()))
            .collect::<Vec<_>>()
            .join(" | ");
        let err = client
            .execute_pipeline(pipeline_request(stages))
            .await
            .unwrap_err();
        assert_eq!(err.code(), code, "{label}: {err}");
        assert_eq!(
            err.metadata()
                .get("fireemu-code")
                .unwrap()
                .to_str()
                .unwrap(),
            if code == unsupported {
                "FS_PIPE_UNSUPPORTED_STAGE"
            } else {
                "FS_PIPE_INVALID"
            },
            "{label}"
        );
        assert_eq!(
            err.metadata()
                .get("fireemu-pipeline")
                .unwrap()
                .to_str()
                .unwrap(),
            canonical,
            "{label}"
        );
        assert_eq!(
            client.get_document(get.clone()).await.unwrap().into_inner(),
            before,
            "{label}"
        );
    }
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn execute_pipeline_where_equal_pushes_filter_before_limit() {
    let (mut client, _clock, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: [
                update_write("where-equal/a", &[("kind", s("drop")), ("name", s("drop"))]),
                update_write("where-equal/b", &[("kind", s("keep")), ("name", s("keep"))]),
                update_write("where-equal/c", &[("kind", s("keep")), ("name", s("keep"))]),
                update_write("where-equal/d", &[("name", s("missing"))]),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let function = pb::Value {
        value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
            name: "equal".to_owned(),
            args: vec![
                pb::Value {
                    value_type: Some(pb::value::ValueType::FieldReferenceValue("kind".to_owned())),
                },
                s("keep"),
            ],
            options: std::collections::HashMap::default(),
        })),
    };
    let request = pb::ExecutePipelineRequest {
        database: DB.to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline {
                        stages: vec![
                            pb::pipeline::Stage {
                                name: "collection".to_owned(),
                                args: vec![s("/where-equal")],
                                ..Default::default()
                            },
                            pb::pipeline::Stage {
                                name: "where".to_owned(),
                                args: vec![function],
                                ..Default::default()
                            },
                            pipeline_select("name"),
                            pb::pipeline::Stage {
                                name: "limit".to_owned(),
                                args: vec![i(1)],
                                ..Default::default()
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ),
        ),
        ..Default::default()
    };
    let documents = drain_pipeline(
        client.execute_pipeline(request).await.unwrap().into_inner(),
        1,
    )
    .await;
    assert_eq!(documents.len(), 1);
    assert_eq!(
        documents[0].fields,
        [("label".to_owned(), s("keep"))].into_iter().collect()
    );
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn execute_pipeline_streams_all_pages_and_preserves_finite_limits() {
    let (mut client, _clock, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    let collection = "pipeline-scale";
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..65)
                .map(|index| {
                    update_write(
                        &format!("{collection}/{index:03}"),
                        &[("value", i(index)), ("extra", s("retained"))],
                    )
                })
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let request = |limit: i64| pb::ExecutePipelineRequest {
        database: DB.to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline {
                        stages: vec![
                            pb::pipeline::Stage {
                                name: "collection".to_owned(),
                                args: vec![pb::Value {
                                    value_type: Some(pb::value::ValueType::StringValue(format!(
                                        "/{collection}"
                                    ))),
                                }],
                                ..Default::default()
                            },
                            pb::pipeline::Stage {
                                name: "select".to_owned(),
                                args: vec![pb::Value {
                                    value_type: Some(pb::value::ValueType::MapValue(
                                        pb::MapValue {
                                            fields: [(
                                                "out".to_owned(),
                                                pb::Value {
                                                    value_type: Some(
                                                        pb::value::ValueType::FieldReferenceValue(
                                                            "value".to_owned(),
                                                        ),
                                                    ),
                                                },
                                            )]
                                            .into_iter()
                                            .collect(),
                                        },
                                    )),
                                }],
                                ..Default::default()
                            },
                            pb::pipeline::Stage {
                                name: "limit".to_owned(),
                                args: vec![i(limit)],
                                ..Default::default()
                            },
                        ],
                    }),
                    ..Default::default()
                },
            ),
        ),
        ..Default::default()
    };
    let docs = drain_pipeline(
        client
            .execute_pipeline(request(65))
            .await
            .unwrap()
            .into_inner(),
        65,
    )
    .await;
    assert_eq!(docs.len(), 65);
    assert_eq!(
        docs.iter()
            .map(|doc| doc.fields["out"].clone())
            .collect::<Vec<_>>(),
        (0..65).map(i).collect::<Vec<_>>()
    );
    assert!(docs.iter().all(|doc| doc.fields.len() == 1));
    let docs = drain_pipeline(
        client
            .execute_pipeline(request(33))
            .await
            .unwrap()
            .into_inner(),
        33,
    )
    .await;
    assert_eq!(
        docs.iter()
            .map(|doc| doc.fields["out"].clone())
            .collect::<Vec<_>>(),
        (0..33).map(i).collect::<Vec<_>>()
    );
    let docs = drain_pipeline(
        client
            .execute_pipeline(request(i64::from(i32::MAX) + 1))
            .await
            .unwrap()
            .into_inner(),
        65,
    )
    .await;
    assert_eq!(docs.len(), 65);
    let docs = drain_pipeline(
        client
            .execute_pipeline(request(0))
            .await
            .unwrap()
            .into_inner(),
        1,
    )
    .await;
    assert!(docs.is_empty());
    let mut empty = request(65);
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &mut empty.pipeline_type
    else {
        unreachable!()
    };
    structured.pipeline.as_mut().unwrap().stages[0].args[0] = s("/empty-scale");
    let mut stream = client.execute_pipeline(empty).await.unwrap().into_inner();
    assert_eq!(
        stream.message().await.unwrap(),
        Some(pb::ExecutePipelineResponse::default())
    );
    assert!(stream.message().await.unwrap().is_none());
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn execute_pipeline_offset_skips_filtered_rows_once_across_pages_and_preserves_state() {
    let (mut client, _clock, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    let collection = "pipeline-offset";
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..67)
                .map(|index| {
                    let mut fields = vec![
                        ("group", s(if index % 2 == 0 { "match" } else { "other" })),
                        ("value", i(index)),
                    ];
                    if index != 4 {
                        fields.push(("label", s(&format!("row-{index:03}"))));
                    }
                    update_write(&format!("{collection}/{index:03}"), &fields)
                })
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut source_before = Vec::new();
    for index in 0..67 {
        source_before.push(
            client
                .get_document(pb::GetDocumentRequest {
                    name: format!("{DOCS}/{collection}/{index:03}"),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner(),
        );
    }

    let collection_stage = || pipeline_stage("collection", s(collection));
    let limit = |value| pipeline_stage("limit", i(value));
    let execute = |stages| pipeline_request(stages);

    let baseline = drain_pipeline(
        client
            .execute_pipeline(execute(vec![collection_stage(), pipeline_select("value")]))
            .await
            .unwrap()
            .into_inner(),
        67,
    )
    .await;
    for (offset, limit_value) in [
        (0, None),
        (1, Some(33)),
        (31, Some(33)),
        (32, Some(33)),
        (33, Some(33)),
        (64, None),
        (65, None),
        (66, None),
        (67, None),
        (68, None),
        (i64::from(i32::MAX), None),
    ] {
        let mut stages = vec![
            collection_stage(),
            pipeline_select("value"),
            pipeline_offset(offset),
        ];
        if let Some(limit_value) = limit_value {
            stages.push(limit(limit_value));
        }
        let expected = baseline
            .iter()
            .skip(usize::try_from(offset).unwrap())
            .take(limit_value.map_or(usize::MAX, |value| usize::try_from(value).unwrap()))
            .cloned()
            .collect::<Vec<_>>();
        let messages = expected.len().max(1);
        let actual = drain_pipeline(
            client
                .execute_pipeline(execute(stages))
                .await
                .unwrap()
                .into_inner(),
            messages,
        )
        .await;
        assert_eq!(actual, expected, "offset={offset}, limit={limit_value:?}");
    }

    let filtered_baseline = drain_pipeline(
        client
            .execute_pipeline(execute(vec![
                collection_stage(),
                pipeline_equal("group", s("match")),
                pipeline_select("label"),
            ]))
            .await
            .unwrap()
            .into_inner(),
        34,
    )
    .await;
    let filtered = drain_pipeline(
        client
            .execute_pipeline(execute(vec![
                collection_stage(),
                pipeline_equal("group", s("match")),
                pipeline_select("label"),
                pipeline_offset(1),
                limit(33),
            ]))
            .await
            .unwrap()
            .into_inner(),
        33,
    )
    .await;
    assert_eq!(filtered, filtered_baseline[1..]);
    assert!(filtered.iter().any(|document| document.fields.is_empty()));

    for (label, stages) in [
        (
            "duplicate offset",
            vec![collection_stage(), pipeline_offset(1), pipeline_offset(2)],
        ),
        (
            "offset after limit",
            vec![collection_stage(), limit(1), pipeline_offset(1)],
        ),
        (
            "where after offset",
            vec![
                collection_stage(),
                pipeline_offset(1),
                pipeline_equal("group", s("match")),
            ],
        ),
        (
            "select after offset",
            vec![
                collection_stage(),
                pipeline_offset(1),
                pipeline_select("value"),
            ],
        ),
    ] {
        let error = client.execute_pipeline(execute(stages)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{label}: {error}");
        assert_eq!(
            error.metadata().get("fireemu-code").unwrap(),
            "FS_PIPE_UNSUPPORTED_STAGE",
            "{label}: {error}"
        );
        assert!(error.metadata().get("fireemu-pipeline").is_some());
    }
    let too_large = client
        .execute_pipeline(execute(vec![
            collection_stage(),
            pipeline_offset(i64::from(i32::MAX) + 1),
        ]))
        .await
        .unwrap_err();
    assert_eq!(too_large.code(), tonic::Code::Unimplemented);
    assert_eq!(
        too_large.metadata().get("fireemu-code").unwrap(),
        "FS_PIPE_UNSUPPORTED_STAGE"
    );
    assert!(too_large.metadata().get("fireemu-pipeline").is_some());

    for (label, value) in [
        ("negative", i(-1)),
        (
            "double",
            pb::Value {
                value_type: Some(pb::value::ValueType::DoubleValue(1.0)),
            },
        ),
        ("unset", pb::Value::default()),
    ] {
        let error = client
            .execute_pipeline(execute(vec![
                collection_stage(),
                pipeline_stage("offset", value),
            ]))
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            tonic::Code::InvalidArgument,
            "{label}: {error}"
        );
        assert_eq!(
            error.metadata().get("fireemu-code").unwrap(),
            "FS_PIPE_INVALID",
            "{label}: {error}"
        );
        assert!(error.metadata().get("fireemu-pipeline").is_none());
    }
    for (label, offset) in [
        (
            "missing argument",
            pb::pipeline::Stage {
                name: "offset".to_owned(),
                ..Default::default()
            },
        ),
        (
            "extra argument",
            pb::pipeline::Stage {
                name: "offset".to_owned(),
                args: vec![i(1), i(2)],
                ..Default::default()
            },
        ),
        (
            "stage option",
            pb::pipeline::Stage {
                name: "offset".to_owned(),
                args: vec![i(1)],
                options: [("mode".to_owned(), s("ignored"))].into_iter().collect(),
            },
        ),
    ] {
        let error = client
            .execute_pipeline(execute(vec![collection_stage(), offset]))
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            tonic::Code::InvalidArgument,
            "{label}: {error}"
        );
        assert_eq!(
            error.metadata().get("fireemu-code").unwrap(),
            "FS_PIPE_INVALID",
            "{label}: {error}"
        );
        assert!(error.metadata().get("fireemu-pipeline").is_none());
    }

    let after = drain_pipeline(
        client
            .execute_pipeline(execute(vec![collection_stage(), pipeline_select("value")]))
            .await
            .unwrap()
            .into_inner(),
        67,
    )
    .await;
    assert_eq!(after, baseline);
    let mut source_after = Vec::new();
    for index in 0..67 {
        source_after.push(
            client
                .get_document(pb::GetDocumentRequest {
                    name: format!("{DOCS}/{collection}/{index:03}"),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner(),
        );
    }
    assert_eq!(source_after, source_before);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn execute_pipeline_reads_collection_projects_field_aliases_and_applies_limit() {
    use pb::execute_pipeline_request::ConsistencySelector;

    let (mut client, _, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write(
                    "items/one",
                    &[
                        ("name", s("one")),
                        ("ignored", i(1)),
                        ("literal.dot", s("literal")),
                    ],
                ),
                update_write("items/two", &[("name", s("two")), ("ignored", i(2))]),
                update_write("rooms/r1/messages/m1", &[("name", s("nested"))]),
                update_write("rooms/r2/messages/m1", &[("name", s("sibling"))]),
                update_write("messages/m1", &[("name", s("root"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let stage = |name: &str, value: pb::Value| pb::pipeline::Stage {
        name: name.to_owned(),
        args: vec![value],
        options: HashMap::new(),
    };
    let select = |field: &str| {
        stage(
            "select",
            pb::Value {
                value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
                    fields: [(
                        "label".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::FieldReferenceValue(
                                field.to_owned(),
                            )),
                        },
                    )]
                    .into_iter()
                    .collect(),
                })),
            },
        )
    };
    let request = |stages: Vec<pb::pipeline::Stage>| pb::ExecutePipelineRequest {
        database: DB.to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline { stages }),
                    options: HashMap::new(),
                },
            ),
        ),
        ..Default::default()
    };
    let collection = |name: &str| stage("collection", s(name));
    let limit = |n| stage("limit", i(n));
    let projected = drain_pipeline(
        client
            .execute_pipeline(request(vec![collection("items"), select("name"), limit(1)]))
            .await
            .unwrap()
            .into_inner(),
        1,
    )
    .await;
    assert_eq!(projected.len(), 1);
    assert_eq!(
        projected[0].fields,
        [("label".to_owned(), s("one"))].into_iter().collect()
    );
    // Drain both responses, preserving multiplicity; collection input does not promise ordering.
    let all = drain_pipeline(
        client
            .execute_pipeline(request(vec![collection("items"), select("name")]))
            .await
            .unwrap()
            .into_inner(),
        2,
    )
    .await;
    assert_eq!(all.len(), 2);
    assert_eq!(
        all.iter()
            .filter(|doc| doc.fields.get("label") == Some(&s("one")))
            .count(),
        1
    );
    assert_eq!(
        all.iter()
            .filter(|doc| doc.fields.get("label") == Some(&s("two")))
            .count(),
        1
    );
    for (path, count, expected) in [
        ("items", 0, None),
        ("empty", 10, None),
        ("rooms/r1/messages", 10, Some("nested")),
        ("rooms/r2/messages", 10, Some("sibling")),
        ("messages", 10, Some("root")),
    ] {
        let docs = drain_pipeline(
            client
                .execute_pipeline(request(vec![collection(path), limit(count)]))
                .await
                .unwrap()
                .into_inner(),
            1,
        )
        .await;
        match expected {
            None => assert!(docs.is_empty()),
            Some(name) => {
                assert_eq!(docs.len(), 1);
                assert_eq!(
                    docs[0].fields,
                    [("name".to_owned(), s(name))].into_iter().collect()
                );
            }
        }
    }
    // A quoted literal dot is one field, unlike the unsupported nested extraction below.
    let literal = drain_pipeline(
        client
            .execute_pipeline(request(vec![
                collection("items"),
                select("`literal.dot`"),
                limit(1),
            ]))
            .await
            .unwrap()
            .into_inner(),
        1,
    )
    .await;
    assert_eq!(literal[0].fields.get("label"), Some(&s("literal")));
    for (label, stages) in [
        (
            "duplicate limit",
            vec![collection("items"), limit(1), limit(2)],
        ),
        (
            "duplicate select",
            vec![collection("items"), select("name"), select("label")],
        ),
        (
            "limit before select",
            vec![collection("items"), limit(1), select("name")],
        ),
        (
            "nested reference",
            vec![collection("items"), select("profile.name")],
        ),
        (
            "document metadata",
            vec![collection("items"), select("__name__")],
        ),
    ] {
        let err = client.execute_pipeline(request(stages)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented, "{label}: {err}");
    }
    for selector in [
        ConsistencySelector::Transaction(vec![1]),
        ConsistencySelector::NewTransaction(pb::TransactionOptions::default()),
        ConsistencySelector::ReadTime(prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
    ] {
        let mut req = request(vec![collection("items")]);
        req.consistency_selector = Some(selector);
        assert_eq!(
            client.execute_pipeline(req).await.unwrap_err().code(),
            tonic::Code::Unimplemented
        );
    }
    let mut req = request(vec![collection("items")]);
    req.consistency_selector = Some(ConsistencySelector::NewTransaction(
        pb::TransactionOptions::default(),
    ));
    req.auto_commit_transaction = true;
    assert_eq!(
        client.execute_pipeline(req).await.unwrap_err().code(),
        tonic::Code::Unimplemented
    );
    let mut req = request(vec![collection("items")]);
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        req.pipeline_type.as_mut()
    else {
        panic!("structured request")
    };
    structured
        .options
        .insert("index_mode".to_owned(), s("recommended"));
    assert_eq!(
        client.execute_pipeline(req).await.unwrap_err().code(),
        tonic::Code::Unimplemented
    );
    // Refusals do not consume or alter the source data.
    let after = drain_pipeline(
        client
            .execute_pipeline(request(vec![collection("items"), select("name")]))
            .await
            .unwrap()
            .into_inner(),
        2,
    )
    .await;
    assert_eq!(after, all);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn scoped_resets_and_partition_tokens_respect_project_ownership() {
    use fireemu_core_session::tenancy::Scope;
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = LocalBackend::new(gateway, clock, 7);
    let write = |project: &str, name: &str| pb::CommitRequest {
        database: format!("projects/{project}/databases/(default)"),
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: format!("projects/{project}/databases/(default)/documents/{name}"),
                fields: [("v".to_owned(), i(1))].into_iter().collect(),
                create_time: None,
                update_time: None,
            })),
            ..Default::default()
        }],
        ..Default::default()
    };
    // Names the partition sampler picks, so the group splits and pages carry tokens.
    let names: Vec<String> = {
        let project = fireemu_core_types::ids::ProjectId::try_new("demo-a").unwrap();
        let database = fireemu_core_types::ids::DatabaseId::try_new("(default)").unwrap();
        (0..)
            .map(|n| format!("owners/o{n}/items/i{n}"))
            .filter(|relative| {
                fireemu_adapter_grpc::partition::is_sample(
                    &fireemu_core_firestore::path::DocumentPath::parse(
                        &project, &database, relative,
                    )
                    .unwrap(),
                )
            })
            .take(4)
            .collect()
    };
    for project in ["demo-a", "demo-b"] {
        for name in &names {
            backend
                .commit_with(
                    &write(project, name),
                    &fireemu_adapter_grpc::rules::allow_all,
                )
                .unwrap();
        }
    }
    let count = |project: &str| {
        let parent = fireemu_adapter_grpc::decode::parse_parent(&format!(
            "projects/{project}/databases/(default)/documents"
        ))
        .unwrap();
        backend
            .read_unadmitted(&parent, |db| db.current_version().value())
            .unwrap_or(0)
    };
    assert_eq!(count("demo-a"), 4);
    // A partition page token is bound to the reset epoch and database generation.
    let partition = |project: &str, token: &str| pb::PartitionQueryRequest {
        parent: format!("projects/{project}/databases/(default)/documents"),
        partition_count: 3,
        page_size: 1,
        page_token: token.to_owned(),
        query_type: Some(pb::partition_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: "items".to_owned(),
                    all_descendants: true,
                }],
                order_by: vec![sq::Order {
                    field: Some(sq::FieldReference {
                        field_path: "__name__".to_owned(),
                    }),
                    direction: sq::Direction::Ascending as i32,
                }],
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let first = backend.partition_query(&partition("demo-b", "")).unwrap();
    assert!(!first.next_page_token.is_empty());
    assert!(backend
        .partition_query(&partition("demo-b", &first.next_page_token))
        .is_ok());
    // The default session's reset leaves the registered project demo-b alone.
    backend.reset_scope(&Scope::AllExcept(
        ["demo-b".to_owned()].into_iter().collect(),
    ));
    assert_eq!(count("demo-a"), 0);
    assert_eq!(count("demo-b"), 4);
    // Its epoch moved: demo-b's token is refused too (the history it named is gone).
    let err = backend
        .partition_query(&partition("demo-b", &first.next_page_token))
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let again = backend.partition_query(&partition("demo-b", "")).unwrap();
    backend.reset_scope(&Scope::Project("demo-b".to_owned()));
    assert_eq!(count("demo-b"), 0);
    // A project reset bumps only that database's generation: the token is refused.
    for name in &names {
        backend
            .commit_with(
                &write("demo-b", name),
                &fireemu_adapter_grpc::rules::allow_all,
            )
            .unwrap();
    }
    assert!(backend
        .partition_query(&partition("demo-b", &again.next_page_token))
        .is_err());
    // Snapshots are scoped the same way.
    let snapshot = backend.snapshot_scope(&Scope::Project("demo-b".to_owned()));
    assert_eq!(snapshot.databases.len(), 1);
    assert!(snapshot.ids.is_none());
    backend.reset_scope(&Scope::Project("demo-b".to_owned()));
    backend
        .restore_scope(&Scope::Project("demo-b".to_owned()), &snapshot)
        .unwrap();
    assert_eq!(count("demo-b"), 4);
    assert!(backend
        .snapshot_scope(&Scope::AllExcept(std::collections::BTreeSet::new()))
        .ids
        .is_some());
}

// ---------------------------------------------------------------------------------------
// Database lock isolation (FS-LOCK-01 .. FS-LOCK-06)
//
// The backend keeps one lock per database and holds the catalog lock only long enough to
// find an entry, so unrelated databases run concurrently while one database stays
// serialized. These tests pin an operation inside its critical section (through the change
// sink or through its write guard) and observe what other operations can do meanwhile.
// ---------------------------------------------------------------------------------------

use fireemu_adapter_grpc::local::{Actor, CommitEvent};
use fireemu_adapter_grpc::rules::allow_all;
use fireemu_core_firestore::store::{FirestoreState, Write};
use fireemu_core_session::tenancy::Scope;

/// How long a test waits for something that must happen.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a test waits to convince itself that something does not happen.
const BRIEF: std::time::Duration = std::time::Duration::from_millis(250);

/// A rendezvous the change sink or a write guard blocks on, so a test can pin operations
/// inside their database critical sections.
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    signal: std::sync::Condvar,
}

#[derive(Default)]
struct GateState {
    arrived: usize,
    open: bool,
}

impl Gate {
    /// Records an arrival and blocks until [`Gate::open`].
    fn hold(&self) {
        let mut state = self.state.lock().unwrap();
        state.arrived += 1;
        self.signal.notify_all();
        while !state.open {
            let (next, timeout) = self.signal.wait_timeout(state, PATIENCE).unwrap();
            assert!(!timeout.timed_out(), "the gate was never opened");
            state = next;
        }
    }

    /// Records an arrival and blocks until `n` operations wait here: it only completes if
    /// they really do hold their databases at the same time.
    fn rendezvous(&self, n: usize) {
        let mut state = self.state.lock().unwrap();
        state.arrived += 1;
        self.signal.notify_all();
        while state.arrived < n {
            let (next, timeout) = self.signal.wait_timeout(state, PATIENCE).unwrap();
            assert!(
                !timeout.timed_out(),
                "{n} operations never held their databases at the same time"
            );
            state = next;
        }
    }

    /// Waits until `n` operations are held at the gate.
    fn wait_for(&self, n: usize) {
        let mut state = self.state.lock().unwrap();
        while state.arrived < n {
            let (next, timeout) = self.signal.wait_timeout(state, PATIENCE).unwrap();
            assert!(!timeout.timed_out(), "no operation reached the gate");
            state = next;
        }
    }

    fn open(&self) {
        let mut state = self.state.lock().unwrap();
        state.open = true;
        self.signal.notify_all();
    }
}

fn lock_test_backend() -> Arc<LocalBackend> {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    Arc::new(LocalBackend::new(gateway, clock, 11))
}

fn lock_test_commit(project: &str, document: &str) -> pb::CommitRequest {
    pb::CommitRequest {
        database: format!("projects/{project}/databases/(default)"),
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: format!("projects/{project}/databases/(default)/documents/{document}"),
                fields: [("v".to_owned(), i(1))].into_iter().collect(),
                create_time: None,
                update_time: None,
            })),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn lock_test_parent(project: &str) -> fireemu_adapter_grpc::decode::Parent {
    fireemu_adapter_grpc::decode::parse_parent(&format!(
        "projects/{project}/databases/(default)/documents"
    ))
    .unwrap()
}

/// The database's current version, or `None` when the catalog has no such database.
fn lock_test_version(backend: &LocalBackend, project: &str) -> Option<u64> {
    backend.read_unadmitted(&lock_test_parent(project), |db| {
        db.current_version().value()
    })
}

/// Installs a change sink that holds the first commit of `project` at the gate and records
/// every event it sees.
fn hold_first_commit(
    backend: &LocalBackend,
    project: &'static str,
    gate: &Arc<Gate>,
    seen: &Arc<Mutex<Vec<(String, u64)>>>,
) {
    let gate = gate.clone();
    let seen = seen.clone();
    let held = std::sync::atomic::AtomicBool::new(false);
    backend.set_change_sink(Arc::new(move |event: &CommitEvent| {
        seen.lock()
            .unwrap()
            .push((event.project.clone(), event.version));
        if event.project == project && !held.swap(true, std::sync::atomic::Ordering::SeqCst) {
            gate.hold();
        }
    }));
}

/// FS-LOCK-01: a commit pinned inside one project's database does not keep another
/// project's commit out.
#[test]
fn a_held_operation_in_one_project_does_not_block_another() {
    let backend = lock_test_backend();
    let gate = Arc::new(Gate::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    hold_first_commit(&backend, "demo-held", &gate, &seen);

    let holder = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            backend
                .commit_with(&lock_test_commit("demo-held", "items/a"), &allow_all)
                .unwrap();
        })
    };
    gate.wait_for(1);

    let (done, finished) = std::sync::mpsc::channel();
    let other = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            let outcome =
                backend.commit_with(&lock_test_commit("demo-free", "items/b"), &allow_all);
            done.send(outcome.is_ok()).unwrap();
        })
    };
    assert_eq!(
        finished.recv_timeout(PATIENCE),
        Ok(true),
        "a commit in another project queued behind the held database"
    );

    gate.open();
    holder.join().unwrap();
    other.join().unwrap();
    assert_eq!(lock_test_version(&backend, "demo-held"), Some(1));
    assert_eq!(lock_test_version(&backend, "demo-free"), Some(1));
}

/// FS-LOCK-02: two commits to one database stay serialized and are published in commit
/// order.
#[test]
fn commits_to_one_database_stay_serialized() {
    let backend = lock_test_backend();
    let gate = Arc::new(Gate::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    hold_first_commit(&backend, "demo-serial", &gate, &seen);

    let first = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            backend
                .commit_with(&lock_test_commit("demo-serial", "items/a"), &allow_all)
                .unwrap();
        })
    };
    gate.wait_for(1);

    let (done, finished) = std::sync::mpsc::channel();
    let second = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            backend
                .commit_with(&lock_test_commit("demo-serial", "items/b"), &allow_all)
                .unwrap();
            done.send(()).unwrap();
        })
    };
    assert!(
        finished.recv_timeout(BRIEF).is_err(),
        "a second commit entered the database while the first one held it"
    );

    gate.open();
    assert!(finished.recv_timeout(PATIENCE).is_ok());
    first.join().unwrap();
    second.join().unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![("demo-serial".to_owned(), 1), ("demo-serial".to_owned(), 2)],
        "the two commits of one database were not published in commit order"
    );
    assert_eq!(lock_test_version(&backend, "demo-serial"), Some(2));
}

/// FS-LOCK-05: two commits that hold different databases at the same time each publish
/// their own principal, whatever order they were staged and released in.
#[test]
fn concurrent_commits_in_different_databases_keep_their_own_actor() {
    let backend = lock_test_backend();
    let gate = Arc::new(Gate::default());
    let seen: Arc<Mutex<Vec<(String, Actor)>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let seen = seen.clone();
        backend.set_change_sink(Arc::new(move |event: &CommitEvent| {
            seen.lock()
                .unwrap()
                .push((event.project.clone(), event.actor.clone()));
        }));
    }

    let commit_as = |project: &'static str, uid: &'static str| {
        let backend = backend.clone();
        let gate = gate.clone();
        std::thread::spawn(move || {
            let staging = backend.clone();
            let actor = Actor {
                auth_type: "app_user".to_owned(),
                auth_id: Some(uid.to_owned()),
            };
            // Both guards stage their principal and only then meet here, so each commit
            // runs with the other's principal already staged.
            let guard = move |_: &FirestoreState,
                              _: &[Write],
                              _: LogicalInstant|
                  -> Result<(), tonic::Status> {
                staging.set_actor(actor.clone());
                gate.rendezvous(2);
                Ok(())
            };
            backend
                .commit_with(&lock_test_commit(project, "items/a"), &guard)
                .unwrap();
        })
    };
    let alice = commit_as("demo-p1", "alice");
    let bob = commit_as("demo-p2", "bob");
    alice.join().unwrap();
    bob.join().unwrap();

    let mut published = seen.lock().unwrap().clone();
    published.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        published,
        vec![
            (
                "demo-p1".to_owned(),
                Actor {
                    auth_type: "app_user".to_owned(),
                    auth_id: Some("alice".to_owned()),
                }
            ),
            (
                "demo-p2".to_owned(),
                Actor {
                    auth_type: "app_user".to_owned(),
                    auth_id: Some("bob".to_owned()),
                }
            ),
        ]
    );
}

/// FS-LOCK-04: a database dropped by a reset or replaced by a restore cannot be reached
/// through a handle retained across it.
#[test]
fn a_reset_or_restore_detaches_retained_database_handles() {
    let backend = lock_test_backend();
    backend
        .commit_with(&lock_test_commit("demo-detach", "items/a"), &allow_all)
        .unwrap();
    let parent = lock_test_parent("demo-detach");
    let handle = backend.database_handle(&parent).unwrap();
    assert_eq!(
        handle.with(|db| Ok(db.current_version().value())).unwrap(),
        1
    );

    backend.reset_scope(&Scope::Project("demo-detach".to_owned()));
    assert!(handle.is_detached());
    assert_eq!(
        handle
            .with(|db| Ok(db.current_version().value()))
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert!(
        lock_test_version(&backend, "demo-detach").is_none(),
        "the reset left the wiped database in the catalog"
    );

    // The catalog serves a fresh, empty database under the same name.
    let fresh = backend.database_handle(&parent).unwrap();
    assert_eq!(
        fresh.with(|db| Ok(db.current_version().value())).unwrap(),
        0
    );

    // A restore retires the database it replaced the same way.
    backend
        .commit_with(&lock_test_commit("demo-detach", "items/b"), &allow_all)
        .unwrap();
    let snapshot = backend.snapshot_scope(&Scope::Project("demo-detach".to_owned()));
    backend
        .restore_scope(&Scope::Project("demo-detach".to_owned()), &snapshot)
        .unwrap();
    assert!(fresh.is_detached());
    assert_eq!(
        fresh.with(|_| Ok(())).unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert_eq!(lock_test_version(&backend, "demo-detach"), Some(1));
}

/// FS-LOCK-03: a reset taken under the exclusive barrier waits for the operation it races
/// and then starts a new epoch (ADR-011).
#[test]
fn a_reset_waits_for_the_operation_it_races() {
    let backend = lock_test_backend();
    let gate = Arc::new(Gate::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    hold_first_commit(&backend, "demo-race", &gate, &seen);
    let epoch_before = backend.epoch();

    let holder = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            backend
                .commit_with(&lock_test_commit("demo-race", "items/a"), &allow_all)
                .unwrap();
        })
    };
    gate.wait_for(1);

    let (done, finished) = std::sync::mpsc::channel();
    let resetter = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            let barrier = backend.barrier();
            let _exclusive = barrier.exclusive();
            backend.reset();
            done.send(()).unwrap();
        })
    };
    assert!(
        finished.recv_timeout(BRIEF).is_err(),
        "the reset did not wait for the commit that was in flight"
    );

    gate.open();
    assert!(finished.recv_timeout(PATIENCE).is_ok());
    holder.join().unwrap();
    resetter.join().unwrap();
    assert_eq!(backend.epoch(), epoch_before + 1);
    assert_eq!(lock_test_version(&backend, "demo-race"), None);
    // The commit that was in flight was published whole, before the reset's wipe.
    assert_eq!(
        seen.lock().unwrap().first(),
        Some(&("demo-race".to_owned(), 1))
    );
}

/// FS-LOCK-06: capture and restore under the exclusive barrier keep every database of the
/// scope consistent, and no operation runs while they do.
#[test]
fn capture_and_restore_stay_atomic_under_the_barrier() {
    let backend = lock_test_backend();
    for project in ["demo-s1", "demo-s2"] {
        backend
            .commit_with(&lock_test_commit(project, "items/a"), &allow_all)
            .unwrap();
    }
    let everything = Scope::AllExcept(std::collections::BTreeSet::new());

    let barrier = backend.barrier();
    let exclusive = barrier.exclusive();
    let (done, finished) = std::sync::mpsc::channel();
    let writer = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            let outcome = backend.commit_with(&lock_test_commit("demo-s1", "items/b"), &allow_all);
            done.send(outcome.is_ok()).unwrap();
        })
    };
    assert!(
        finished.recv_timeout(BRIEF).is_err(),
        "an operation was admitted while a capture held the barrier exclusively"
    );

    let snapshot = backend.snapshot_scope(&everything);
    assert_eq!(snapshot.databases.len(), 2);
    backend.reset();
    backend.restore_scope(&everything, &snapshot).unwrap();
    drop(exclusive);

    assert_eq!(finished.recv_timeout(PATIENCE), Ok(true));
    writer.join().unwrap();
    // Both databases came back whole, and the waiting commit landed on top of the restore
    // rather than on a half-restored state.
    assert_eq!(lock_test_version(&backend, "demo-s1"), Some(2));
    assert_eq!(lock_test_version(&backend, "demo-s2"), Some(1));
}

#[test]
fn resources_report_the_session_charge_active_transactions_and_refusals() {
    use fireemu_core_session::tenancy::Scope;
    use fireemu_core_types::resources::RootBudget;

    let backend = history_budget_backend(2, 10);
    backend
        .commit_with(
            &history_budget_update("demo-a", "(default)", "a", 1),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    backend
        .commit_with(
            &history_budget_update("demo-a", "(default)", "b", 1),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap();
    // The third version exceeds the session's two-version budget: refused and counted.
    let refused = backend
        .commit_with(
            &history_budget_update("demo-a", "(default)", "c", 1),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
    let _transaction = backend
        .begin_transaction(&pb::BeginTransactionRequest {
            database: "projects/demo-a/databases/(default)".to_owned(),
            ..Default::default()
        })
        .unwrap();

    let default = backend
        .resources(
            &Scope::AllExcept(std::collections::BTreeSet::new()),
            RootBudget::DEFAULT,
        )
        .unwrap();
    assert_eq!(default.service, "firestore");
    let gauge = |report: &fireemu_core_types::resources::ServiceResources, id: &str| {
        report
            .gauges
            .iter()
            .find(|g| g.id == id)
            .unwrap_or_else(|| panic!("{id} in {:?}", report.gauges))
            .clone()
    };
    assert_eq!(gauge(&default, "history.session_versions").current, 2);
    assert_eq!(gauge(&default, "history.session_versions").limit, Some(2));
    assert!(gauge(&default, "history.session_versions").saturated());
    assert_eq!(gauge(&default, "history.global_versions").current, 2);
    assert_eq!(gauge(&default, "history.global_versions").limit, Some(10));
    assert_eq!(gauge(&default, "transactions.active").current, 1);
    assert!(gauge(&default, "history.live_document_bytes").current > 0);
    assert!(
        default
            .refusals
            .iter()
            .any(|r| r.reason == "history.session_versions" && r.count == 1),
        "{:?}",
        default.refusals
    );
    let database = default
        .roots
        .roots
        .iter()
        .find(|r| r.kind == "database")
        .unwrap();
    assert_eq!(database.id, "demo-a/(default)");
    assert_eq!(database.count, 2);
    assert!(!database.outstanding);
    let transactions = default
        .roots
        .roots
        .iter()
        .find(|r| r.kind == "transactions")
        .unwrap();
    assert_eq!(transactions.id, "demo-a/(default)");
    assert_eq!(transactions.count, 1);
    assert!(transactions.outstanding);
    assert_eq!(
        default.roots.roots[0].kind, "transactions",
        "outstanding roots come first"
    );

    // A project session sees its own databases and never the backend-wide totals.
    let project = backend
        .resources(&Scope::Project("demo-a".to_owned()), RootBudget::DEFAULT)
        .unwrap();
    assert!(project
        .gauges
        .iter()
        .all(|g| !g.id.starts_with("history.global_")));
    assert!(project
        .roots
        .roots
        .iter()
        .any(|r| r.id == "demo-a/(default)"));
    let other = backend
        .resources(&Scope::Project("demo-z".to_owned()), RootBudget::DEFAULT)
        .unwrap();
    assert_eq!(other.roots.total, 0);
    assert_eq!(gauge(&other, "transactions.active").current, 0);
}

#[test]
fn resources_report_history_the_next_compaction_would_reclaim() {
    use fireemu_core_session::tenancy::Scope;
    use fireemu_core_types::resources::RootBudget;

    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let backend = LocalBackend::new(gateway, Arc::clone(&clock), 7);
    let scope = Scope::AllExcept(std::collections::BTreeSet::new());
    let reclaimable = |backend: &LocalBackend| {
        backend
            .resources(&scope, RootBudget::DEFAULT)
            .unwrap()
            .gauges
            .into_iter()
            .find(|g| g.id == "history.reclaimable_bytes")
            .expect("reclaimable gauge")
    };
    for value in 1..=3 {
        backend
            .commit_with(
                &history_budget_update("demo-a", "(default)", "a", value),
                &fireemu_adapter_grpc::rules::allow_all,
            )
            .unwrap();
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(1))
            .unwrap();
    }
    // Every version is still inside the read-time retention window: nothing to reclaim.
    let fresh = reclaimable(&backend);
    assert_eq!(fresh.current, 0, "{fresh:?}");
    assert_eq!(fresh.reclaimable, 0);

    // Past the window, the two superseded versions are what a compaction would release.
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(3_601))
        .unwrap();
    let aged = reclaimable(&backend);
    assert!(aged.current > 0, "{aged:?}");
    assert_eq!(aged.reclaimable, aged.current);
    let retained = backend
        .resources(&scope, RootBudget::DEFAULT)
        .unwrap()
        .gauges
        .into_iter()
        .find(|g| g.id == "history.session_versions")
        .unwrap();
    assert_eq!(retained.current, 3);
}

/// One streamed general-order execution records its selection stage once (paths visited,
/// filter evaluations, retained selection) and accumulates the page stage across every
/// page, so the whole stream's work is visible rather than only the last page's row count.
#[tokio::test]
async fn streamed_query_execution_records_selection_and_page_stats_separately() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Production).await;
    let mut indexes = IndexSet::default();
    indexes.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("stats").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: vec![
            IndexField {
                path: FieldPath::parse("keep").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
            IndexField {
                path: FieldPath::parse("v").unwrap(),
                mode: IndexFieldMode::Descending,
            },
        ],
    });
    backend.replace_indexes(indexes);
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (0..70)
                .map(|index| {
                    update_write(
                        &format!("stats/{index:03}"),
                        &[("v", i(index)), ("keep", i(index % 2))],
                    )
                })
                .chain(
                    (0..1000).map(|index| {
                        update_write(&format!("noise/{index:04}"), &[("v", i(index))])
                    }),
                )
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();

    for transactional in [false, true] {
        let mut request = kept_stats_by_v_desc();
        if transactional {
            let transaction = client
                .begin_transaction(pb::BeginTransactionRequest {
                    database: DB.to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .transaction;
            request.consistency_selector = Some(
                pb::run_query_request::ConsistencySelector::Transaction(transaction),
            );
        }
        let documents = collect_docs(&mut client, request).await;
        assert_eq!(documents.len(), 35, "transactional {transactional}");

        let (_, stats) = backend
            .latest_query_execution_stats()
            .expect("the streamed execution recorded its stats");
        assert_selection_then_pages(&stats, &format!("transactional {transactional}"));
    }
    for offset in [2, 34, 35, 40] {
        let mut request = kept_stats_by_v_desc();
        let Some(pb::run_query_request::QueryType::StructuredQuery(q)) =
            request.query_type.as_mut()
        else {
            unreachable!()
        };
        q.offset = offset;
        let mut stream = client.run_query(request).await.unwrap().into_inner();
        let mut skipped = 0;
        let mut returned = 0;
        while let Some(response) = stream.message().await.unwrap() {
            skipped += response.skipped_results;
            returned += u64::from(response.document.is_some());
        }
        assert_eq!(skipped, offset.min(35));
        assert_eq!(
            returned,
            35u64.saturating_sub(u64::try_from(offset).unwrap())
        );
        let (_, stats) = backend.latest_query_execution_stats().unwrap();
        assert_eq!(stats.pages.matched, returned);
        assert_eq!(stats.pages.cloned_documents, returned);
    }
    handle.abort();
}

/// `stats` where `keep == 1`, ordered by `v` descending.
fn kept_stats_by_v_desc() -> pb::RunQueryRequest {
    let mut request = query("stats", None);
    let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        request.query_type.as_mut()
    else {
        unreachable!();
    };
    query.r#where = Some(sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: "keep".to_owned(),
            }),
            op: sq::field_filter::Operator::Equal as i32,
            value: Some(i(1)),
        })),
    });
    query.order_by = vec![sq::Order {
        field: Some(sq::FieldReference {
            field_path: "v".to_owned(),
        }),
        direction: sq::Direction::Descending as i32,
    }];
    request
}

/// The selection stage walked the 70 in-scope paths once, never the 1,000 noise paths, and
/// evaluated the filter on each; two pages (32 + 3) then materialized the 35 selected
/// documents without rescanning.
fn assert_selection_then_pages(stats: &QueryExecutionStats, context: &str) {
    let selection = stats.selection.expect("a general order builds a selection");
    assert_eq!(selection.index_paths_visited, 70, "{context}");
    assert_eq!(selection.filter_evaluations, 70, "{context}");
    assert_eq!(selection.matched, 35, "{context}");
    assert_eq!(stats.selection_paths, 35, "{context}");
    assert!(stats.selection_bytes > 0, "{context}");
    assert_eq!(stats.page_count, 2, "{context}");
    assert_eq!(stats.pages.index_paths_visited, 0, "{context}");
    assert_eq!(stats.pages.filter_evaluations, 0, "{context}");
    assert_eq!(stats.pages.cloned_documents, 35, "{context}");
    assert_eq!(stats.pages.matched, 35, "{context}");
    assert!(stats.pages.cloned_field_bytes > 0, "{context}");
}

#[tokio::test]
async fn batch_write_refuses_decode_failures_but_continues_after_failed_preconditions() {
    let (mut client, _clock, handle) = start().await;
    for decode_failure in [false, true] {
        for failure_index in [0, 1] {
            let collection = format!("batch-continuation-{decode_failure}-{failure_index}");
            let mut writes = (0..3)
                .map(|index| update_write(&format!("{collection}/{index}"), &[("v", i(index))]))
                .collect::<Vec<_>>();
            writes[failure_index] = if decode_failure {
                pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: "bad name".to_owned(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }
            } else {
                pb::Write {
                    operation: Some(pb::write::Operation::Delete(format!(
                        "{DOCS}/{collection}/{failure_index}"
                    ))),
                    current_document: Some(pb::Precondition {
                        condition_type: Some(pb::precondition::ConditionType::Exists(true)),
                    }),
                    ..Default::default()
                }
            };
            let result = client
                .batch_write(pb::BatchWriteRequest {
                    database: DB.to_owned(),
                    writes,
                    ..Default::default()
                })
                .await;
            let response = if decode_failure {
                assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
                None
            } else {
                let response = result.unwrap().into_inner();
                assert_eq!(response.status.len(), 3);
                assert_eq!(response.write_results.len(), 3);
                Some(response)
            };
            for index in 0..3 {
                let document = client
                    .get_document(pb::GetDocumentRequest {
                        name: format!("{DOCS}/{collection}/{index}"),
                        ..Default::default()
                    })
                    .await;
                if decode_failure || index == failure_index {
                    if let Some(response) = &response {
                        assert_ne!(response.status[index].code, 0);
                        assert_eq!(response.write_results[index], pb::WriteResult::default());
                    }
                    assert_eq!(document.unwrap_err().code(), tonic::Code::NotFound);
                } else {
                    let response = response.as_ref().unwrap();
                    assert_eq!(response.status[index].code, 0);
                    let document = document.unwrap().into_inner();
                    assert_eq!(
                        document.fields,
                        [("v".to_owned(), i(i64::try_from(index).unwrap()))].into()
                    );
                    assert_eq!(
                        document.update_time,
                        response.write_results[index].update_time
                    );
                    assert!(document.update_time.is_some());
                }
            }
        }
    }
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn batch_write_reports_lock_contention_per_item_and_preserves_suffix() {
    let (mut client, _clock, handle) = start().await;
    for contended_index in [0, 1] {
        let collection = format!("batch-contention-{contended_index}");
        let locked = format!("{collection}/locked");
        let prefix = format!("{collection}/prefix");
        let suffix = format!("{collection}/suffix");
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write(&locked, &[("v", i(1))])],
                ..Default::default()
            })
            .await
            .unwrap();
        let transaction = client
            .begin_transaction(pb::BeginTransactionRequest {
                database: DB.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .transaction;
        let mut reads = client
            .batch_get_documents(pb::BatchGetDocumentsRequest {
                database: DB.to_owned(),
                documents: vec![format!("{DOCS}/{locked}")],
                consistency_selector: Some(
                    pb::batch_get_documents_request::ConsistencySelector::Transaction(
                        transaction.clone(),
                    ),
                ),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        let read = reads.next().await.unwrap().unwrap();
        assert!(matches!(
            read.result,
            Some(pb::batch_get_documents_response::Result::Found(_))
        ));

        let (writes, ordered_paths, ordered_values) = if contended_index == 0 {
            (
                vec![
                    update_write(&locked, &[("v", i(3))]),
                    update_write(&prefix, &[("v", i(2))]),
                    update_write(&suffix, &[("v", i(4))]),
                ],
                [&locked, &prefix, &suffix],
                [3, 2, 4],
            )
        } else {
            (
                vec![
                    update_write(&prefix, &[("v", i(2))]),
                    update_write(&locked, &[("v", i(3))]),
                    update_write(&suffix, &[("v", i(4))]),
                ],
                [&prefix, &locked, &suffix],
                [2, 3, 4],
            )
        };
        let response = client
            .batch_write(pb::BatchWriteRequest {
                database: DB.to_owned(),
                writes,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.status.len(), 3);
        assert_eq!(response.write_results.len(), 3);
        // BatchWrite contention is a per-item local result; it is not retried or promoted to a
        // whole-request error. The exact wording is the core's local contention contract.
        assert_eq!(
            response.status[contended_index].code,
            i32::from(tonic::Code::Aborted)
        );
        assert_eq!(
            response.status[contended_index].message,
            "Too much contention on these documents. Please try again."
        );
        assert_eq!(
            response.write_results[contended_index],
            pb::WriteResult::default()
        );
        for index in 0..3 {
            if index == contended_index {
                continue;
            }
            assert_eq!(response.status[index].code, 0);
            assert!(response.write_results[index].update_time.is_some());
        }

        let get = |path: &str| pb::GetDocumentRequest {
            name: format!("{DOCS}/{path}"),
            ..Default::default()
        };
        let locked_after_batch = client
            .get_document(get(&locked))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(locked_after_batch.fields, [("v".to_owned(), i(1))].into());
        for (index, (path, value)) in ordered_paths.iter().zip(ordered_values).enumerate() {
            if index == contended_index {
                continue;
            }
            let document = client.get_document(get(path)).await.unwrap().into_inner();
            assert_eq!(document.fields, [("v".to_owned(), i(value))].into());
            assert_eq!(
                document.update_time,
                response.write_results[index].update_time
            );
        }

        // The refused BatchWrite item leaves its holder active. Its own commit can finish and
        // release the lock, after which an out-of-band write to the same path succeeds.
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write(&locked, &[("v", i(5))])],
                transaction,
                ..Default::default()
            })
            .await
            .unwrap();
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write(&locked, &[("v", i(6))])],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            client
                .get_document(get(&locked))
                .await
                .unwrap()
                .into_inner()
                .fields,
            [("v".to_owned(), i(6))].into()
        );
    }
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn transaction_commit_late_precondition_failure_preserves_documents_and_versions() {
    let (mut client, clock, handle) = start().await;
    for verify in [false, true] {
        let collection = format!("late-precondition-{verify}");
        let original_path = format!("{collection}/original");
        let created_path = format!("{collection}/created");
        let guard_path = format!("{DOCS}/{collection}/guard");
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![
                    update_write(&original_path, &[("v", i(7)), ("label", s("preserved"))]),
                    update_write(&format!("{collection}/guard"), &[("v", i(9))]),
                ],
                ..Default::default()
            })
            .await
            .unwrap();
        let get = |path: &str| pb::GetDocumentRequest {
            name: format!("{DOCS}/{path}"),
            ..Default::default()
        };
        let original = client
            .get_document(get(&original_path))
            .await
            .unwrap()
            .into_inner();
        let guard = client
            .get_document(get(&format!("{collection}/guard")))
            .await
            .unwrap()
            .into_inner();
        let transaction = client
            .begin_transaction(pb::BeginTransactionRequest {
                database: DB.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .transaction;
        let mut read = get(&original_path);
        read.consistency_selector = Some(
            pb::get_document_request::ConsistencySelector::Transaction(transaction.clone()),
        );
        assert_eq!(
            client.get_document(read).await.unwrap().into_inner(),
            original
        );
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(1))
            .unwrap();
        let writes = |exists| {
            vec![
                pb::Write {
                    operation: Some(pb::write::Operation::Delete(format!(
                        "{DOCS}/{original_path}"
                    ))),
                    ..Default::default()
                },
                update_write(&created_path, &[("v", i(11))]),
                pb::Write {
                    operation: Some(if verify {
                        pb::write::Operation::Verify(guard_path.clone())
                    } else {
                        pb::write::Operation::Delete(guard_path.clone())
                    }),
                    current_document: Some(pb::Precondition {
                        condition_type: Some(pb::precondition::ConditionType::Exists(exists)),
                    }),
                    ..Default::default()
                },
            ]
        };
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: writes(false),
                transaction: transaction.clone(),
                ..Default::default()
            })
            .await
            .expect_err("a late failing precondition rejects the entire transaction");
        assert_eq!(
            client
                .get_document(get(&original_path))
                .await
                .unwrap()
                .into_inner(),
            original
        );
        assert_eq!(
            client
                .get_document(get(&format!("{collection}/guard")))
                .await
                .unwrap()
                .into_inner(),
            guard
        );
        assert_eq!(
            client
                .get_document(get(&created_path))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        client
            .rollback(pb::RollbackRequest {
                database: DB.to_owned(),
                transaction,
                ..Default::default()
            })
            .await
            .unwrap();

        // The same write sequence succeeds with the guard's actual existence condition.
        let transaction = client
            .begin_transaction(pb::BeginTransactionRequest {
                database: DB.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .transaction;
        let response = client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: writes(true),
                transaction,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.write_results.len(), 3);
        assert_eq!(
            client
                .get_document(get(&original_path))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        let created = client
            .get_document(get(&created_path))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.fields, [("v".to_owned(), i(11))].into());
        assert_eq!(created.update_time, response.write_results[1].update_time);
        assert_ne!(created.update_time, original.update_time);
        let after_guard = client
            .get_document(get(&format!("{collection}/guard")))
            .await;
        if verify {
            assert_eq!(after_guard.unwrap().into_inner(), guard);
        } else {
            assert_eq!(after_guard.unwrap_err().code(), tonic::Code::NotFound);
        }
    }
    handle.abort();
}

/// The message production answers on the data plane for a database that was never created,
/// recorded from the oracle project in `conformance/firestore-production-matrix.json`
/// (`emulator/routes#named-database-document`). The trailing space is production's.
fn missing_database_message(project: &str, database: &str) -> String {
    format!(
        "The database {database} does not exist for project {project} Please visit \
         https://console.cloud.google.com/datastore/setup?project={project} to add a Cloud \
         Datastore or Cloud Firestore database. "
    )
}

/// Asserts one surface answered with production's refusal for a database nothing created.
fn assert_missing_database(error: &tonic::Status, surface: &str) {
    assert_eq!(error.code(), tonic::Code::NotFound, "{surface}");
    assert_eq!(
        error.message(),
        missing_database_message("demo-app", "never-created"),
        "{surface}"
    );
}

const NEVER_CREATED: &str = "projects/demo-app/databases/never-created";

#[tokio::test]
async fn grpc_refuses_document_calls_on_a_database_that_was_never_created() {
    let (mut client, _clock, handle) = start().await;
    let docs = format!("{NEVER_CREATED}/documents");
    let document = format!("{docs}/c/d");

    assert_missing_database(
        &client
            .get_document(pb::GetDocumentRequest {
                name: document.clone(),
                ..Default::default()
            })
            .await
            .unwrap_err(),
        "GetDocument",
    );
    assert_missing_database(
        &client
            .list_documents(pb::ListDocumentsRequest {
                parent: docs.clone(),
                collection_id: "c".to_owned(),
                ..Default::default()
            })
            .await
            .unwrap_err(),
        "ListDocuments",
    );
    assert_missing_database(
        &client
            .batch_get_documents(pb::BatchGetDocumentsRequest {
                database: NEVER_CREATED.to_owned(),
                documents: vec![document.clone()],
                ..Default::default()
            })
            .await
            .unwrap_err(),
        "BatchGetDocuments",
    );
    assert_missing_database(
        &client
            .list_collection_ids(pb::ListCollectionIdsRequest {
                parent: docs,
                ..Default::default()
            })
            .await
            .unwrap_err(),
        "ListCollectionIds",
    );
    let write = pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: document,
            ..Default::default()
        })),
        ..Default::default()
    };
    assert_missing_database(
        &client
            .commit(pb::CommitRequest {
                database: NEVER_CREATED.to_owned(),
                writes: vec![write.clone()],
                ..Default::default()
            })
            .await
            .unwrap_err(),
        "Commit",
    );
    assert_missing_database(
        &client
            .batch_write(pb::BatchWriteRequest {
                database: NEVER_CREATED.to_owned(),
                writes: vec![write],
                ..Default::default()
            })
            .await
            .unwrap_err(),
        "BatchWrite",
    );

    handle.abort();
}

#[tokio::test]
async fn grpc_refuses_query_and_transaction_calls_on_a_database_that_was_never_created() {
    let (mut client, _clock, handle) = start().await;
    let docs = format!("{NEVER_CREATED}/documents");
    let collection = vec![sq::CollectionSelector {
        collection_id: "c".to_owned(),
        all_descendants: false,
    }];

    assert_missing_database(
        &client
            .begin_transaction(pb::BeginTransactionRequest {
                database: NEVER_CREATED.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap_err(),
        "BeginTransaction",
    );
    assert_missing_database(
        &client
            .partition_query(pb::PartitionQueryRequest {
                parent: docs.clone(),
                partition_count: 2,
                query_type: Some(pb::partition_query_request::QueryType::StructuredQuery(
                    pb::StructuredQuery {
                        from: vec![sq::CollectionSelector {
                            collection_id: "c".to_owned(),
                            all_descendants: true,
                        }],
                        ..Default::default()
                    },
                )),
                ..Default::default()
            })
            .await
            .unwrap_err(),
        "PartitionQuery",
    );

    // A refusal a stream carries instead of returning is still the same refusal.
    let refused = match client
        .run_query(pb::RunQueryRequest {
            parent: docs,
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                pb::StructuredQuery {
                    from: collection,
                    ..Default::default()
                },
            )),
            ..Default::default()
        })
        .await
    {
        Err(error) => error,
        Ok(response) => response
            .into_inner()
            .next()
            .await
            .expect("the stream reports the refusal")
            .unwrap_err(),
    };
    assert_missing_database(&refused, "RunQuery");

    handle.abort();
}

/// A server under one compatibility profile: `strict` enforces the Standard limits with
/// production's index policy, `emulator` observes them with the official emulator's. The
/// write-path refusals below are the same under both.
async fn start_with_profile(
    strict: bool,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: strict,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: if strict {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
    let svc = FirestoreServer::new(GatewayService::local(gateway, backend));
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (FirestoreClient::new(channel), handle)
}

/// Production's refusal of a `BatchWrite` that names one document twice
/// (`conformance/firestore-production-matrix.json`, `writes/batch-write` step
/// `non-atomic-batch`, 2026-09-07 live corpus).
const BATCH_WRITE_REPEATED_DOCUMENT: &str =
    "the same document cannot be written more than once in a single request";

/// FS-WRITE-002. A `BatchWrite` that writes one document twice is refused as a whole request,
/// not per item: `INVALID_ARGUMENT` with production's exact wording, no status array, and none
/// of its writes land, the distinct sibling included (production readbacks in the matrix row
/// prove nothing landed). The refusal does not depend on the profile. A batch of distinct
/// documents keeps its per-item results.
#[tokio::test]
async fn batch_write_refuses_a_repeated_document_as_a_whole_with_production_wording() {
    for strict in [true, false] {
        let (mut client, handle) = start_with_profile(strict).await;
        let existing = "batch-repeat/existing";
        let before = client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![update_write(existing, &[("v", i(0))])],
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        let before_time = before.write_results[0].update_time;
        assert!(before_time.is_some());

        // The repeated document is neither the first nor the last write, and the second
        // occurrence is a different operation (delete after update), as in the production
        // observation.
        let err = client
            .batch_write(pb::BatchWriteRequest {
                database: DB.to_owned(),
                writes: vec![
                    update_write("batch-repeat/sibling", &[("v", i(1))]),
                    update_write(existing, &[("v", i(1))]),
                    delete_write(existing),
                    update_write("batch-repeat/suffix", &[("v", i(2))]),
                ],
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "strict={strict}");
        assert_eq!(
            err.message(),
            BATCH_WRITE_REPEATED_DOCUMENT,
            "strict={strict}"
        );

        // Nothing landed: siblings absent, the repeated document unchanged (same version).
        for absent in ["batch-repeat/sibling", "batch-repeat/suffix"] {
            let missing = client
                .get_document(pb::GetDocumentRequest {
                    name: format!("{DOCS}/{absent}"),
                    ..Default::default()
                })
                .await
                .unwrap_err();
            assert_eq!(
                missing.code(),
                tonic::Code::NotFound,
                "strict={strict} {absent}"
            );
        }
        let unchanged = client
            .get_document(pb::GetDocumentRequest {
                name: format!("{DOCS}/{existing}"),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(unchanged.fields, [("v".to_owned(), i(0))].into());
        assert_eq!(unchanged.update_time, before_time, "strict={strict}");

        // Distinct documents: every write is its own commit with its own result.
        let response = client
            .batch_write(pb::BatchWriteRequest {
                database: DB.to_owned(),
                writes: vec![
                    update_write("batch-repeat/a", &[("v", i(1))]),
                    update_write("batch-repeat/b", &[("v", i(2))]),
                ],
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.status.len(), 2);
        assert!(response.status.iter().all(|status| status.code == 0));
        assert!(response
            .write_results
            .iter()
            .all(|result| result.update_time.is_some()));
        handle.abort();
    }
}

/// One gRPC server and one REST surface over the same backend, so a shape sent on either
/// transport lands in (or is refused from) the same store.
async fn start_with_rest_surface() -> (
    FirestoreClient<tonic::transport::Channel>,
    fireemu_adapter_grpc::rest::RestState,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
    let rest = fireemu_adapter_grpc::rest::RestState {
        local: Arc::clone(&backend),
        gateway: Arc::new(gateway.clone()),
        rules: None,
        app_check: None,
        control_token: None,
    };
    let svc = FirestoreServer::new(GatewayService::local(gateway, backend));
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (FirestoreClient::new(channel), rest, handle)
}

/// How a `BatchWrite` answered: refused as a whole request, or answered per item.
#[derive(Debug, PartialEq, Eq)]
enum BatchWriteAnswer {
    /// `(code, message)` of the whole-request refusal; no position got a status.
    WholeRequest(i32, String),
    /// `(code, message)` per position, `0` and empty for a write that landed.
    PerItem(Vec<(i32, String)>),
}

/// The transport-independent outcome of one `BatchWrite`: the answer and which of the named
/// documents exist afterwards, with their `v` field.
#[derive(Debug, PartialEq, Eq)]
struct BatchWriteOutcome {
    answer: BatchWriteAnswer,
    present: Vec<Option<i64>>,
}

/// `google.rpc.Code` of a REST error body's `status` name (the ones a `BatchWrite` can answer).
fn rpc_code_of_status_name(name: &str) -> i32 {
    match name {
        "INVALID_ARGUMENT" => 3,
        "NOT_FOUND" => 5,
        "ALREADY_EXISTS" => 6,
        "FAILED_PRECONDITION" => 9,
        "ABORTED" => 10,
        other => panic!("unexpected REST status {other}"),
    }
}

/// Reads `v` of every document under `paths` (relative to `DOCS`), `None` when absent.
async fn read_v_of(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    paths: &[String],
) -> Vec<Option<i64>> {
    let mut present = Vec::with_capacity(paths.len());
    for path in paths {
        let read = client
            .get_document(pb::GetDocumentRequest {
                name: format!("{DOCS}/{path}"),
                ..Default::default()
            })
            .await;
        present.push(match read {
            Ok(document) => match document.into_inner().fields.get("v") {
                Some(pb::Value {
                    value_type: Some(pb::value::ValueType::IntegerValue(v)),
                }) => Some(*v),
                other => panic!("{path} has no integer v: {other:?}"),
            },
            Err(status) if status.code() == tonic::Code::NotFound => None,
            Err(status) => panic!("{path}: {status}"),
        });
    }
    present
}

/// FS-WRITE-006. The three `BatchWrite` item shapes whose classification (per position or
/// whole request) is not yet production-observed for a malformed middle item
/// (`spec/compatibility/broad-runs/fs-write-limits-03.json`, cases `batch-malformed-middle`
/// and `batch-undecodable-value`, pending) answer identically on REST and gRPC today, with
/// identical post-state. Each shape is a three-write batch whose middle write is the shape and
/// whose neighbours are ordinary updates:
///
/// - `operation-less`: a write with no operation. Whole request refused, nothing lands.
/// - `invalid-name`: a decodable `update` whose name is not a resource. Whole request refused.
/// - `duplicate-document`: the middle write names the first write's document again. Whole
///   request, production's wording, nothing lands (production-observed on REST,
///   `writes/batch-write#non-atomic-batch`).
///
/// The sandbox exploration found whole-request validation refusal; the conformance fixture
/// will supply the final production status and wording for these shapes.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn batch_write_item_shapes_answer_identically_on_rest_and_grpc() {
    struct Shape {
        name: &'static str,
        /// The middle write, given the collection and the first write's document path.
        middle_grpc: fn(&str, &str) -> pb::Write,
        middle_rest: fn(&str, &str) -> serde_json::Value,
        expected: fn(&str) -> BatchWriteOutcome,
    }
    let shapes = [
        Shape {
            name: "operation-less",
            middle_grpc: |_, _| pb::Write::default(),
            middle_rest: |_, _| serde_json::json!({}),
            expected: |_| BatchWriteOutcome {
                answer: BatchWriteAnswer::WholeRequest(3, "empty write operation".to_owned()),
                present: vec![None, None, None],
            },
        },
        Shape {
            name: "empty-field-name",
            middle_grpc: |_, first| update_write(first, &[("", i(1))]),
            middle_rest: |_, first| serde_json::json!({"update": {"name": format!("{DOCS}/{first}"), "fields": {"": {"integerValue": "1"}}}}),
            expected: |_| BatchWriteOutcome {
                answer: BatchWriteAnswer::WholeRequest(
                    3,
                    "The property.name is the empty string.".to_owned(),
                ),
                present: vec![None, None, None],
            },
        },
        Shape {
            name: "reserved-field-name",
            middle_grpc: |_, first| update_write(first, &[("__bad__", i(1))]),
            middle_rest: |_, first| serde_json::json!({"update": {"name": format!("{DOCS}/{first}"), "fields": {"__bad__": {"integerValue": "1"}}}}),
            expected: |_| BatchWriteOutcome {
                answer: BatchWriteAnswer::WholeRequest(
                    3,
                    "field name __bad__ is reserved".to_owned(),
                ),
                present: vec![None, None, None],
            },
        },
        Shape {
            name: "invalid-name",
            middle_grpc: |_, _| pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: "bad name".to_owned(),
                    fields: [("v".to_owned(), i(1))].into_iter().collect(),
                    ..Default::default()
                })),
                ..Default::default()
            },
            middle_rest: |_, _| serde_json::json!({"update": {"name": "bad name", "fields": {"v": {"integerValue": "1"}}}}),
            expected: |_| BatchWriteOutcome {
                answer: BatchWriteAnswer::WholeRequest(3, "invalid parent: bad name".to_owned()),
                present: vec![None, None, None],
            },
        },
        Shape {
            name: "duplicate-document",
            middle_grpc: |_, first| update_write(first, &[("v", i(1))]),
            middle_rest: |_, first| serde_json::json!({"update": {"name": format!("{DOCS}/{first}"), "fields": {"v": {"integerValue": "1"}}}}),
            expected: |_| BatchWriteOutcome {
                answer: BatchWriteAnswer::WholeRequest(3, BATCH_WRITE_REPEATED_DOCUMENT.to_owned()),
                present: vec![None, None, None],
            },
        },
    ];

    let (mut client, rest, handle) = start_with_rest_surface().await;
    for shape in &shapes {
        let mut outcomes = Vec::new();
        for transport in ["grpc", "rest"] {
            let collection = format!("batch-parity-{transport}-{}", shape.name);
            let paths: Vec<String> = (0..3).map(|n| format!("{collection}/{n}")).collect();
            let answer = if transport == "grpc" {
                let writes = vec![
                    update_write(&paths[0], &[("v", i(0))]),
                    (shape.middle_grpc)(&collection, &paths[0]),
                    update_write(&paths[2], &[("v", i(2))]),
                ];
                match client
                    .batch_write(pb::BatchWriteRequest {
                        database: DB.to_owned(),
                        writes,
                        ..Default::default()
                    })
                    .await
                {
                    Ok(response) => BatchWriteAnswer::PerItem(
                        response
                            .into_inner()
                            .status
                            .into_iter()
                            .map(|status| (status.code, status.message))
                            .collect(),
                    ),
                    Err(status) => BatchWriteAnswer::WholeRequest(
                        i32::from(status.code()),
                        status.message().to_owned(),
                    ),
                }
            } else {
                let writes = vec![
                    serde_json::json!({"update": {"name": format!("{DOCS}/{}", paths[0]), "fields": {"v": {"integerValue": "0"}}}}),
                    (shape.middle_rest)(&collection, &paths[0]),
                    serde_json::json!({"update": {"name": format!("{DOCS}/{}", paths[2]), "fields": {"v": {"integerValue": "2"}}}}),
                ];
                let response = rest.handle(&fireemu_adapter_grpc::rest::RestRequest {
                    method: "POST".to_owned(),
                    path: format!("/v1/{DOCS}:batchWrite"),
                    query: String::new(),
                    authorization: Some("Bearer owner".to_owned()),
                    app_check: Vec::new(),
                    body: serde_json::json!({"writes": writes}),
                    origin: None,
                    browser_metadata: false,
                });
                if response.status == 200 {
                    let body = &response.body;
                    assert!(body.get("error").is_none(), "{} {body}", shape.name);
                    BatchWriteAnswer::PerItem(
                        body["status"]
                            .as_array()
                            .unwrap_or_else(|| panic!("{} {body}", shape.name))
                            .iter()
                            .map(|status| {
                                (
                                    i32::try_from(status["code"].as_i64().unwrap_or(0)).unwrap(),
                                    status["message"].as_str().unwrap_or_default().to_owned(),
                                )
                            })
                            .collect(),
                    )
                } else {
                    let body = &response.body;
                    assert!(body.get("status").is_none(), "{} {body}", shape.name);
                    assert!(body.get("writeResults").is_none(), "{} {body}", shape.name);
                    BatchWriteAnswer::WholeRequest(
                        rpc_code_of_status_name(body["error"]["status"].as_str().unwrap()),
                        body["error"]["message"].as_str().unwrap().to_owned(),
                    )
                }
            };
            let present = read_v_of(&mut client, &paths).await;
            outcomes.push((transport, BatchWriteOutcome { answer, present }));
        }
        let (grpc, rest_outcome) = (&outcomes[0].1, &outcomes[1].1);
        assert_eq!(
            grpc, rest_outcome,
            "{}: REST and gRPC classify the shape differently",
            shape.name
        );
        assert_eq!(
            *grpc,
            (shape.expected)(shape.name),
            "{}: the documented classification changed",
            shape.name
        );
    }
    handle.abort();
}

/// A count capped at zero answers without reading (FS-QUERY-INDEX
/// aggregation/options#count-up-to-zero), but only once the database exists and the rules let
/// the caller read the query; an Explain still runs and reports its metrics.
#[test]
fn a_count_capped_at_zero_is_authorized_before_it_answers() {
    let backend = history_budget_backend(u64::MAX, u64::MAX);
    let request =
        |database: &str, explain: Option<pb::ExplainOptions>| pb::RunAggregationQueryRequest {
            parent: format!("projects/demo-app/databases/{database}/documents"),
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    pb::StructuredAggregationQuery {
                        query_type: Some(
                            pb::structured_aggregation_query::QueryType::StructuredQuery(
                                pb::StructuredQuery {
                                    from: vec![sq::CollectionSelector {
                                        collection_id: "c".to_owned(),
                                        all_descendants: false,
                                    }],
                                    ..Default::default()
                                },
                            ),
                        ),
                        aggregations: vec![pb::structured_aggregation_query::Aggregation {
                            alias: "c".to_owned(),
                            operator: Some(
                                pb::structured_aggregation_query::aggregation::Operator::Count(
                                    pb::structured_aggregation_query::aggregation::Count {
                                        up_to: Some(0),
                                    },
                                ),
                            ),
                        }],
                    },
                ),
            ),
            explain_options: explain,
            ..Default::default()
        };
    let owner = backend
        .run_aggregation_query(
            &request("(default)", None),
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .unwrap();
    assert_eq!(
        owner.read_time,
        Some(prost_types::Timestamp {
            seconds: -1,
            nanos: 999_999_000
        })
    );
    let denied = backend
        .run_aggregation_query(&request("(default)", None), &deny_read)
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    let missing = backend
        .run_aggregation_query(
            &request("never-created", None),
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    let explained = backend
        .run_aggregation_query(
            &request("(default)", Some(pb::ExplainOptions { analyze: true })),
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .unwrap();
    assert!(explained.explain_metrics.is_some());
}

/// `ExecutePipeline` on a Standard database: the strict profile answers with production's
/// status, the emulator profile keeps the refusal fireemu always made, in fireemu's words
/// (confirmation review 2026-09-24, Should Fix 2).
#[tokio::test]
async fn grpc_execute_pipeline_on_standard_keeps_each_profiles_words() {
    let request = || pb::ExecutePipelineRequest {
        database: DB.to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline {
                        stages: vec![pb::pipeline::Stage {
                            name: "collection".to_owned(),
                            args: vec![pb::Value {
                                value_type: Some(pb::value::ValueType::ReferenceValue(
                                    "/items".to_owned(),
                                )),
                            }],
                            options: std::collections::HashMap::new(),
                        }],
                    }),
                    options: std::collections::HashMap::new(),
                },
            ),
        ),
        ..Default::default()
    };
    for (policy, message) in [
        (
            IndexValidationPolicy::Emulator,
            "pipelines require firestore.edition = enterprise (Enterprise Native)",
        ),
        (
            IndexValidationPolicy::Production,
            fireemu_adapter_grpc::production_status::PIPELINE_REQUIRES_ENTERPRISE,
        ),
    ] {
        let (mut client, _, handle) = start_with_write_time_and_policy(false, policy).await;
        let status = match client.execute_pipeline(request()).await {
            Ok(response) => {
                let mut stream = response.into_inner();
                stream.message().await.unwrap_err()
            }
            Err(status) => status,
        };
        assert_eq!(status.code(), tonic::Code::FailedPrecondition, "{policy:?}");
        assert_eq!(status.message(), message, "{policy:?}");
        handle.abort();
    }
}

/// `ListDocuments` without a collection id lists every document directly below the parent, in
/// name order and paged, and refuses `show_missing` (FS-DATA-WRITE-LIST grpc/list-documents
/// #every-collection-of-document, #every-collection-of-missing-document).
#[tokio::test]
async fn grpc_list_documents_without_a_collection_id_lists_every_child_collection() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: [
                "p/d",
                "p/d/sub/s1",
                "p/d/sub/s2",
                "p/d/other/o1",
                "p/d/sub/s1/deep/x",
                "q/y",
            ]
            .iter()
            .map(|path| update_write(path, &[("v", i(1))]))
            .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let list = |page_size, page_token: String| pb::ListDocumentsRequest {
        parent: format!("{DOCS}/p/d"),
        page_size,
        page_token,
        ..Default::default()
    };
    let names = |response: &pb::ListDocumentsResponse| -> Vec<String> {
        response
            .documents
            .iter()
            .map(|d| {
                d.name
                    .trim_start_matches(&format!("{DOCS}/p/d/"))
                    .to_owned()
            })
            .collect()
    };
    let all = client
        .list_documents(list(0, String::new()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(names(&all), ["other/o1", "sub/s1", "sub/s2"]);
    let first = client
        .list_documents(list(2, String::new()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(names(&first), ["other/o1", "sub/s1"]);
    let next = client
        .list_documents(list(2, first.next_page_token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(names(&next), ["sub/s2"]);
    assert!(next.next_page_token.is_empty());
    let root = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        root.documents
            .iter()
            .map(|d| d.name.trim_start_matches(&format!("{DOCS}/")).to_owned())
            .collect::<Vec<_>>(),
        ["p/d", "q/y"]
    );
    let refused = client
        .list_documents(pb::ListDocumentsRequest {
            parent: format!("{DOCS}/p/d"),
            show_missing: true,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        refused.message(),
        "collection id must be set when show_missing is true"
    );
    handle.abort();
}

#[tokio::test]
async fn grpc_find_nearest_applies_ordinary_offset_and_limit_before_ranking() {
    let (mut client, _, handle) =
        start_with_write_time_and_policy(false, IndexValidationPolicy::Emulator).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("items/a", &[("embedding", vector(&[1.0, 0.0]))]),
                update_write("items/b", &[("embedding", vector(&[-1.0, 0.0]))]),
                update_write("items/c", &[("embedding", vector(&[0.0, 1.0]))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let responses = collect_responses(
        &mut client,
        pb::RunQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                pb::StructuredQuery {
                    from: vec![sq::CollectionSelector {
                        collection_id: "items".to_owned(),
                        ..Default::default()
                    }],
                    offset: 1,
                    limit: Some(2),
                    find_nearest: Some(sq::FindNearest {
                        vector_field: Some(sq::FieldReference {
                            field_path: "embedding".to_owned(),
                        }),
                        query_vector: Some(vector(&[1.0, 0.0])),
                        distance_measure: sq::find_nearest::DistanceMeasure::Euclidean as i32,
                        limit: Some(2),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        responses
            .iter()
            .map(|response| response.skipped_results)
            .sum::<i32>(),
        1,
        "the original offset is reported in skipped_results"
    );
    let ids = responses
        .iter()
        .filter_map(|response| response.document.as_ref())
        .map(|document| document.name.rsplit('/').next().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["c", "b"]);
    handle.abort();
}

#[tokio::test]
async fn grpc_find_nearest_skipped_results_use_pre_offset_matches() {
    let (mut client, _, handle) =
        start_with_write_time_and_policy(false, IndexValidationPolicy::Emulator).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("items/a", &[("embedding", vector(&[1.0, 0.0]))]),
                update_write("items/b", &[("embedding", vector(&[-1.0, 0.0]))]),
                update_write("items/c", &[("embedding", vector(&[0.0, 1.0]))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    for (offset, expected_skipped, expected_ids) in [(2, 2, vec!["c"]), (5, 3, vec![])] {
        let responses = collect_responses(
            &mut client,
            pb::RunQueryRequest {
                parent: DOCS.to_owned(),
                query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
                    pb::StructuredQuery {
                        from: vec![sq::CollectionSelector {
                            collection_id: "items".to_owned(),
                            ..Default::default()
                        }],
                        offset,
                        limit: Some(2),
                        find_nearest: Some(sq::FindNearest {
                            vector_field: Some(sq::FieldReference {
                                field_path: "embedding".to_owned(),
                            }),
                            query_vector: Some(vector(&[1.0, 0.0])),
                            distance_measure: sq::find_nearest::DistanceMeasure::Euclidean as i32,
                            limit: Some(2),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(
            responses
                .iter()
                .map(|response| response.skipped_results)
                .sum::<i32>(),
            expected_skipped,
            "offset {offset}"
        );
        let ids = responses
            .iter()
            .filter_map(|response| response.document.as_ref())
            .map(|document| document.name.rsplit('/').next().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(ids, expected_ids, "offset {offset}");
    }
    handle.abort();
}

async fn collect_responses(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    req: pb::RunQueryRequest,
) -> Vec<pb::RunQueryResponse> {
    let mut stream = client.run_query(req).await.unwrap().into_inner();
    let mut out = Vec::new();
    while let Some(response) = stream.next().await {
        out.push(response.unwrap());
    }
    out
}

/// A cosine search that meets a zero vector over gRPC: the strict profile refuses it as
/// production does, the emulator profile leaves that candidate out as fireemu did before
/// (confirmation review 2026-09-24, round 2).
#[tokio::test]
async fn grpc_cosine_search_over_a_zero_vector_differs_between_the_profiles() {
    let request = || pb::RunQueryRequest {
        parent: DOCS.to_owned(),
        query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: "items".to_owned(),
                    ..Default::default()
                }],
                find_nearest: Some(sq::FindNearest {
                    vector_field: Some(sq::FieldReference {
                        field_path: "embedding".to_owned(),
                    }),
                    query_vector: Some(vector(&[1.0, 0.0])),
                    distance_measure: sq::find_nearest::DistanceMeasure::Cosine as i32,
                    limit: Some(3),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    for policy in [
        IndexValidationPolicy::Emulator,
        IndexValidationPolicy::Production,
    ] {
        let (mut client, _, backend, handle) = start_with_backend_and_policy(false, policy).await;
        let mut indexes = IndexSet::default();
        indexes.add_composite(IndexDefinition {
            collection_group: CollectionId::try_new("items").unwrap(),
            query_scope: IndexQueryScope::Collection,
            fields: vec![IndexField {
                path: FieldPath::parse("embedding").unwrap(),
                mode: IndexFieldMode::Vector { dimension: 2 },
            }],
        });
        backend.replace_project_database_indexes(
            "demo-app",
            fireemu_core_types::ids::DatabaseId::DEFAULT,
            indexes,
        );
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![
                    update_write("items/near", &[("embedding", vector(&[1.0, 0.0]))]),
                    update_write("items/zero", &[("embedding", vector(&[0.0, 0.0]))]),
                    update_write("items/far", &[("embedding", vector(&[-1.0, 0.0]))]),
                ],
                ..Default::default()
            })
            .await
            .unwrap();
        let mut names = Vec::new();
        let mut refused = None;
        let mut stream = match client.run_query(request()).await {
            Ok(response) => Some(response.into_inner()),
            Err(status) => {
                refused = Some(status);
                None
            }
        };
        while let Some(message) = match stream.as_mut() {
            Some(stream) => stream.next().await,
            None => None,
        } {
            match message {
                Ok(response) => names.extend(
                    response
                        .document
                        .map(|d| d.name.rsplit('/').next().unwrap().to_owned()),
                ),
                Err(status) => refused = Some(status),
            }
        }
        if policy == IndexValidationPolicy::Production {
            let refused = refused.expect("the strict profile refuses the search");
            assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
            assert_eq!(
                refused.message(),
                "Cannot compute cosine distance against a vector with a magnitude of zero."
            );
        } else {
            assert!(refused.is_none(), "{refused:?}");
            assert_eq!(names, ["near", "far"]);
        }
        handle.abort();
    }
}

/// Under the emulator profile, `show_missing` without a collection id is not refused: the
/// listing is answered without missing documents (production refuses it; strict above).
#[tokio::test]
async fn grpc_list_without_a_collection_id_ignores_show_missing_under_the_emulator_profile() {
    let (mut client, _, handle) =
        start_with_write_time_and_policy(false, IndexValidationPolicy::Emulator).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: ["p/d/sub/s1", "p/d/gone/g1/deeper/x"]
                .iter()
                .map(|path| update_write(path, &[("v", i(1))]))
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let listed = client
        .list_documents(pb::ListDocumentsRequest {
            parent: format!("{DOCS}/p/d"),
            show_missing: true,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let names: Vec<&str> = listed
        .documents
        .iter()
        .map(|d| d.name.rsplit_once("/p/d/").unwrap().1)
        .collect();
    assert_eq!(names, ["sub/s1"]);
    handle.abort();
}

async fn list_in(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    collection: &str,
    order_by: &str,
    page_token: String,
    transaction: Option<Vec<u8>>,
) -> pb::ListDocumentsResponse {
    client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: collection.to_owned(),
            page_size: 2,
            order_by: order_by.to_owned(),
            page_token,
            consistency_selector: transaction
                .map(pb::list_documents_request::ConsistencySelector::Transaction),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
}

fn listed_ids(response: &pb::ListDocumentsResponse) -> Vec<String> {
    response
        .documents
        .iter()
        .map(|d| d.name.rsplit('/').next().unwrap().to_owned())
        .collect()
}

/// A read-write transaction that pages an ordered listing continues a token issued outside
/// it, holds the whole listing as its read set (an out-of-band write to a document it did not
/// return is refused while it is open) and commits (FS-DATA-WRITE-LIST review, round 3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_write_transaction_holds_an_ordered_listing_it_pages() {
    let (mut client, handle) =
        start_with_contention_wait(std::time::Duration::from_millis(100)).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: (1..=5)
                .map(|n| update_write(&format!("o/d{n}"), &[("n", i(n))]))
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let outside = list_in(&mut client, "o", "n desc", String::new(), None).await;
    assert_eq!(listed_ids(&outside), ["d5", "d4"]);
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let page = list_in(
        &mut client,
        "o",
        "n desc",
        outside.next_page_token,
        Some(txn.clone()),
    )
    .await;
    assert_eq!(listed_ids(&page), ["d3", "d2"]);
    // The listing is the transaction's read set: a write to a document of an earlier page
    // (`o/d5`), to one not returned yet (`o/d1`) and an insert before the token (`o/d0`) are
    // each refused while it is open.
    for write in [
        update_write("o/d5", &[("n", i(8))]),
        update_write("o/d1", &[("n", i(9))]),
        update_write("o/d0", &[("n", i(7))]),
    ] {
        let refused = client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![write],
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::Aborted);
    }
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            transaction: txn,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

/// Inside a transaction a name-ordered page, and an ordered page whose token carries no order
/// values (a value past the token bound), continue after the named document.
#[tokio::test]
async fn transaction_pages_without_order_values_continue_after_the_named_document() {
    let (mut client, _clock, handle) = start().await;
    let big = "x".repeat(2_000);
    let mut writes: Vec<pb::Write> = (1..=4)
        .map(|n| update_write(&format!("p/d{n}"), &[("n", i(n))]))
        .collect();
    writes.extend((1..=4).map(|n| {
        update_write(
            &format!("q/d{n}"),
            &[(
                "s",
                pb::Value {
                    value_type: Some(pb::value::ValueType::StringValue(format!("{big}{n}"))),
                },
            )],
        )
    }));
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let first = list_in(&mut client, "p", "", String::new(), Some(txn.clone())).await;
    assert_eq!(listed_ids(&first), ["d1", "d2"]);
    let next = list_in(
        &mut client,
        "p",
        "",
        first.next_page_token,
        Some(txn.clone()),
    )
    .await;
    assert_eq!(listed_ids(&next), ["d3", "d4"]);
    let first = list_in(&mut client, "q", "s", String::new(), Some(txn.clone())).await;
    assert_eq!(listed_ids(&first), ["d1", "d2"]);
    let next = list_in(
        &mut client,
        "q",
        "s",
        first.next_page_token,
        Some(txn.clone()),
    )
    .await;
    assert_eq!(listed_ids(&next), ["d3", "d4"]);
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            transaction: txn,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}
