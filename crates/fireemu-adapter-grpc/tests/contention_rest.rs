//! A REST commit held behind another transaction's read lock: refused after the strict wait on the virtual clock, and kept waiting under the emulator profile.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::{LocalBackend, STRICT_CONTENTION_WAIT};
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_grpc::serve::serve_multiplexed;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DATABASE: &str = "projects/demo-app/databases/(default)";
const DOCUMENT: &str = "projects/demo-app/databases/(default)/documents/contended/doc";

async fn http(addr: std::net::SocketAddr, method: &str, path: &str, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

struct Server {
    addr: std::net::SocketAddr,
    backend: Arc<LocalBackend>,
    clock: Arc<Mutex<VirtualClock>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn start(strict: bool) -> Server {
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
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_unix_seconds(1_788_004_860))));
    let local = LocalBackend::new(gateway.clone(), Arc::clone(&clock), 7).with_contention_wait(STRICT_CONTENTION_WAIT);
    let backend = Arc::new(if strict { local.with_virtual_contention_wait() } else { local });
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway.clone()),
        rules: None,
        app_check: None,
        control_token: None,
    });
    let task = tokio::spawn(serve_multiplexed(
        listener,
        FirestoreServer::new(GatewayService::local(gateway, backend.clone())),
        rest,
    ));
    Server { addr, backend, clock, task }
}

/// A transaction that holds the read lock on the contended document.
fn hold(backend: &LocalBackend) -> Vec<u8> {
    let transaction = backend
        .begin_transaction(&pb::BeginTransactionRequest {
            database: DATABASE.to_owned(),
            ..Default::default()
        })
        .unwrap();
    backend
        .get_document(
            &pb::GetDocumentRequest {
                name: DOCUMENT.to_owned(),
                consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(transaction.clone())),
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .unwrap_err();
    transaction
}

fn commit_body() -> String {
    format!(r#"{{"writes":[{{"update":{{"name":"{DOCUMENT}","fields":{{"v":{{"integerValue":"1"}}}}}}}}]}}"#)
}

fn move_clock(clock: &Arc<Mutex<VirtualClock>>, seconds: i64) {
    clock.lock().unwrap().advance(LogicalDuration::from_seconds(seconds)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_rest_commit_is_refused_when_the_virtual_clock_moves_the_strict_wait() {
    let server = start(true).await;
    let _holder = hold(&server.backend);
    let addr = server.addr;
    let writer = tokio::spawn(async move { http(addr, "POST", "/v1/projects/demo-app/databases/(default)/documents:commit", &commit_body()).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    move_clock(&server.clock, 19);
    assert!(tokio::time::timeout(Duration::from_millis(400), async { writer.is_finished() }).await.unwrap() == false, "held");
    move_clock(&server.clock, 2);
    let response = tokio::time::timeout(Duration::from_secs(5), writer).await.expect("the writer answers").unwrap();
    assert!(response.starts_with("HTTP/1.1 409"), "{response}");
    assert!(response.contains("ABORTED") && response.contains("Too much contention"), "{response}");
    server.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_rest_commit_under_the_emulator_profile_waits_for_the_release_whatever_the_virtual_clock_does() {
    let server = start(false).await;
    let holder = hold(&server.backend);
    let addr = server.addr;
    let writer = tokio::spawn(async move { http(addr, "POST", "/v1/projects/demo-app/databases/(default)/documents:commit", &commit_body()).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    move_clock(&server.clock, 100);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!writer.is_finished(), "still held");
    server
        .backend
        .rollback(&pb::RollbackRequest {
            database: DATABASE.to_owned(),
            transaction: holder,
            ..Default::default()
        })
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), writer).await.expect("the writer answers").unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    server.task.abort();
}
