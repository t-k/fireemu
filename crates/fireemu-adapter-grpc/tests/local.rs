//! End-to-end local execution through a real tonic client: documents, queries, transactions,
//! aggregations and batch writes on the virtual clock.

// `tonic::Status` is the error type of the backend's own closures.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::{
    AtomicChangeSink, CommitPublication, HistoryBudgetLimits, LocalBackend,
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
            policy: IndexValidationPolicy::Conservative,
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
            policy: IndexValidationPolicy::Conservative,
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
    start_with_write_time_and_policy(wall_clock, IndexValidationPolicy::Conservative).await
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
            policy: IndexValidationPolicy::Conservative,
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
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;
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
                policy: IndexValidationPolicy::Conservative,
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
            policy: IndexValidationPolicy::Conservative,
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
                path: FieldPath::parse("done").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
            IndexField {
                path: FieldPath::parse("owner").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
        ],
    });
    backend.replace_project_database_indexes(
        "demo-a",
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        indexes,
    );
    let field = |name: &str| sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: name.to_owned(),
            }),
            op: sq::field_filter::Operator::Equal as i32,
            value: Some(i(1)),
        })),
    };
    let query = pb::StructuredQuery {
        from: vec![sq::CollectionSelector {
            collection_id: "tasks".to_owned(),
            all_descendants: false,
        }],
        r#where: Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::And as i32,
                    filters: vec![field("owner"), field("done")],
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
            policy: IndexValidationPolicy::Conservative,
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
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: path.to_owned(),
            }),
            op: sq::field_filter::Operator::Equal as i32,
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

    // An empty collection id without `allDescendants` is the same scan of everything under
    // the parent: production and the official emulator both serve it.
    let everything = collect_docs(
        &mut client,
        pb::RunQueryRequest {
            parent: DOCS.to_owned(),
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
        },
    )
    .await;
    assert_eq!(everything.len(), 4, "{everything:?}");
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
                pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: "bad name".to_owned(),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.status[0].code, 0);
    assert_eq!(resp.status[1].code, 0);
    assert_eq!(resp.status[2].code, 0);
    assert_eq!(resp.status[3].code, i32::from(tonic::Code::InvalidArgument));

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

    // The strict gateway still applies in local mode: a two-field equality query needs an index.
    let needs_index = query(
        "n",
        Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::And as i32,
                    filters: vec![field_eq("v", i(1)), field_eq("w", i(2))],
                },
            )),
        }),
    );
    let err = client.run_query(needs_index).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
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
    let (mut client, _clock, handle) = start().await;
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
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;
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
async fn dropping_a_slow_query_stream_releases_the_internal_snapshot_pin() {
    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;
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
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;
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
async fn ordered_list_pages_continue_across_present_and_missing_rows() {
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
                order_by: "v desc".to_owned(),
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

    let expected = ["d4", "d3", "d2", "d1", "d0", "m0", "m1", "m2"]
        .map(|document| format!("{DOCS}/mixed/{document}"));
    assert_eq!(seen, expected);
    handle.abort();
}

#[tokio::test]
async fn commit_notifications_are_compact_and_the_ring_is_bounded() {
    use fireemu_adapter_grpc::local::{CommitChangeKind, COMMIT_NOTIFICATION_CAPACITY};

    let (mut client, _clock, backend, handle) =
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;
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
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;
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
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;

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
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;
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
        start_with_backend_and_policy(false, IndexValidationPolicy::Conservative).await;
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
        start_with_backend_and_policy(true, IndexValidationPolicy::Conservative).await;
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
    let err = client
        .list_documents(continued(
            page.next_page_token,
            "pg",
            Some(pb::list_documents_request::ConsistencySelector::ReadTime(
                committed.commit_time.unwrap(),
            )),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    handle.abort();
}

#[tokio::test]
async fn database_snapshots_restore_documents_and_start_a_new_epoch() {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
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
            policy: IndexValidationPolicy::Conservative,
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
async fn execute_pipeline_is_validated_strictly_and_never_executed() {
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
                        name: "eq".to_owned(),
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
    // Enterprise: decoded, canonicalized, refused explicitly or answered validation-only.
    let (mut client, _, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    let valid = client
        .execute_pipeline(request(vec![
            stage("collection", 1),
            stage("where", 1),
            stage("limit", 1),
        ]))
        .await
        .unwrap_err();
    assert_eq!(valid.code(), tonic::Code::Unimplemented);
    assert_eq!(
        valid.metadata().get("fireemu-pipeline").unwrap(),
        "collection(1) | where(1) | limit(1)"
    );
    assert_eq!(
        valid.metadata().get("fireemu-code").unwrap(),
        "FS_PIPE_VALIDATION_ONLY"
    );
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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn scoped_resets_and_partition_tokens_respect_project_ownership() {
    use fireemu_core_session::tenancy::Scope;
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
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
    for project in ["demo-a", "demo-b"] {
        for n in 0..4 {
            backend
                .commit_with(
                    &write(project, &format!("owners/o{n}/items/i{n}")),
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
    for n in 0..4 {
        backend
            .commit_with(
                &write("demo-b", &format!("owners/o{n}/items/i{n}")),
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
            policy: IndexValidationPolicy::Conservative,
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
            policy: IndexValidationPolicy::Conservative,
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
