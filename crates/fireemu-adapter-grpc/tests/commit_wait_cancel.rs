//! Request cancellation removes only that request's deadlock edges, preserving read locks.

// The backend intentionally returns tonic status values from attempt closures.
#![allow(clippy::result_large_err)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rules::{allow_all, allow_all_reads};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;

const DB: &str = "projects/demo-app/databases/(default)";
const DOC: &str = "projects/demo-app/databases/(default)/documents/items/locked";

fn backend() -> LocalBackend {
    LocalBackend::new(
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
    )
    .with_contention_wait(Duration::from_secs(10))
}

fn reader(backend: &LocalBackend) -> Vec<u8> {
    let transaction = backend
        .begin_transaction(&pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .unwrap();
    let error = backend
        .get_document(
            &pb::GetDocumentRequest {
                name: DOC.to_owned(),
                consistency_selector: Some(
                    pb::get_document_request::ConsistencySelector::Transaction(transaction.clone()),
                ),
                ..Default::default()
            },
            &allow_all_reads,
        )
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    transaction
}

fn request(transaction: Vec<u8>) -> pb::CommitRequest {
    pb::CommitRequest {
        database: DB.to_owned(),
        transaction,
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: DOC.to_owned(),
                ..Default::default()
            })),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn probe(backend: &LocalBackend, older: Vec<u8>, younger: Vec<u8>, releases: u64) {
    let error = backend
        .commit_once(&request(older.clone()), &allow_all)
        .unwrap_err();
    assert!(LocalBackend::is_contention(&error), "{error}");
    assert_eq!(
        backend.release_count(),
        releases,
        "cancellation must not abort either transaction"
    );
    backend
        .rollback(&pb::RollbackRequest {
            database: DB.to_owned(),
            transaction: younger,
            ..Default::default()
        })
        .unwrap();
    backend.commit_once(&request(older), &allow_all).unwrap();
}

#[tokio::test]
async fn dropping_an_async_transaction_wait_removes_its_deadlock_edge() {
    let backend = backend();
    let older = reader(&backend);
    let younger = reader(&backend);
    let request = request(younger.clone());
    let (parent, writes) = LocalBackend::plan_commit(&request).unwrap();
    let own = backend.txn_of(&parent, &younger).unwrap();
    let releases = backend.release_count();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut sender = Some(sender);
    let mut wait =
        Box::pin(
            backend.retry_on_contention_async(&parent, own.as_ref(), &writes, || {
                let result = backend.commit_once(&request, &allow_all);
                assert!(result.as_ref().is_err_and(LocalBackend::is_contention));
                if let Some(sender) = sender.take() {
                    sender.send(()).unwrap();
                }
                result
            }),
        );
    tokio::select! {
        result = &mut wait => panic!("wait unexpectedly finished: {result:?}"),
        () = async { receiver.await.unwrap(); } => {},
    }
    drop(wait);
    probe(&backend, older, younger, releases);
}

async fn start() -> (
    std::net::SocketAddr,
    Arc<LocalBackend>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    use fireemu_adapter_grpc::{
        rest::RestState, serve::serve_multiplexed, service::GatewayService,
    };
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let backend = Arc::new(backend());
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway.clone()),
        rules: None,
        app_check: None,
        control_token: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_multiplexed(
        listener,
        FirestoreServer::new(GatewayService::local(gateway, backend.clone())),
        rest,
    ));
    (addr, backend, task)
}

async fn wait_for_pending(backend: &LocalBackend, transaction: &[u8], expected: usize) {
    let parent = LocalBackend::plan_commit(&request(transaction.to_vec()))
        .unwrap()
        .0;
    let id = backend.txn_of(&parent, transaction).unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pending = backend
                .with_snapshot(&parent, |db, _, _, _| db.transaction_commit_wait_count(&id))
                .unwrap();
            if pending == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the server must reach the expected pending Commit state");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_deadline_cancels_only_the_requests_commit_wait() {
    use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
    let (addr, backend, server) = start().await;
    let older = reader(&backend);
    let younger = reader(&backend);
    let releases = backend.release_count();
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = FirestoreClient::new(channel);
    let mut request = tonic::Request::new(request(younger.clone()));
    request.set_timeout(Duration::from_secs(1));
    let committing = tokio::spawn(async move { client.commit(request).await });
    wait_for_pending(&backend, &younger, 1).await;
    let error = committing.await.unwrap().unwrap_err();
    assert!(matches!(
        error.code(),
        tonic::Code::Cancelled | tonic::Code::DeadlineExceeded
    ));
    wait_for_pending(&backend, &younger, 0).await;
    probe(&backend, older, younger, releases);
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disconnected_rest_commit_does_not_leave_a_deadlock_edge() {
    use tokio::io::AsyncWriteExt;
    let (addr, backend, server) = start().await;
    let older = reader(&backend);
    let younger = reader(&backend);
    let releases = backend.release_count();
    let body = serde_json::json!({
        "transaction": fireemu_adapter_grpc::rest::json::base64_encode(&younger),
        "writes": [{"update": {"name": DOC}}]
    })
    .to_string();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(format!("POST /v1/{DB}/documents:commit HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    wait_for_pending(&backend, &younger, 1).await;
    drop(stream);
    wait_for_pending(&backend, &younger, 0).await;
    probe(&backend, older, younger, releases);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn another_writers_lease_expiry_wakes_an_already_waiting_commit() {
    let backend = backend().with_lock_lease(Duration::from_millis(80));
    let holder = reader(&backend);
    let request = request(Vec::new());
    let (parent, writes) = LocalBackend::plan_commit(&request).unwrap();
    let holder_id = backend.txn_of(&parent, &holder).unwrap().unwrap();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let mut sender = Some(sender);
    let mut waiting = Box::pin(
        backend.retry_on_contention_async(&parent, None, &writes, || {
            let result = backend.commit_once(&request, &allow_all);
            if let Some(sender) = sender.take() {
                assert!(result.as_ref().is_err_and(LocalBackend::is_contention));
                sender.send(()).unwrap();
            }
            result
        }),
    );
    tokio::select! {
        result = &mut waiting => panic!("wait unexpectedly finished: {result:?}"),
        () = async { receiver.await.unwrap(); } => {},
    }
    tokio::time::sleep(Duration::from_millis(120)).await;
    // A different writer expires the idle holder and succeeds without releasing a transaction itself.
    backend.commit(&request).unwrap();
    tokio::time::timeout(Duration::from_millis(500), &mut waiting)
        .await
        .expect("lease expiry must wake earlier waiters")
        .unwrap();
    assert!(!backend
        .with_snapshot(&parent, |db, _, _, _| db.transaction_is_active(&holder_id))
        .unwrap());
}

#[tokio::test]
async fn lease_expiry_notifies_rest_release_waiters() {
    let backend = backend().with_lock_lease(Duration::from_millis(80));
    let _holder = reader(&backend);
    let seen = backend.release_count();
    tokio::time::sleep(Duration::from_millis(120)).await;
    backend.commit(&request(Vec::new())).unwrap();
    assert!(
        backend
            .await_any_release(seen, std::time::Instant::now() + Duration::from_millis(200))
            .await,
        "lease expiry must publish to REST waiters"
    );
}
