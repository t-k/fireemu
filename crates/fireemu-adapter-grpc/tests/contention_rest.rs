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
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let local = LocalBackend::new(gateway.clone(), Arc::clone(&clock), 7)
        .with_contention_wait(STRICT_CONTENTION_WAIT);
    let backend = Arc::new(if strict {
        local.with_virtual_contention_wait()
    } else {
        local
    });
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
    Server {
        addr,
        backend,
        clock,
        task,
    }
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
                consistency_selector: Some(
                    pb::get_document_request::ConsistencySelector::Transaction(transaction.clone()),
                ),
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .unwrap_err();
    transaction
}

fn commit_body() -> String {
    format!(
        r#"{{"writes":[{{"update":{{"name":"{DOCUMENT}","fields":{{"v":{{"integerValue":"1"}}}}}}}}]}}"#
    )
}

fn move_clock(clock: &Arc<Mutex<VirtualClock>>, seconds: i64) {
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(seconds))
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_rest_commit_is_refused_when_the_virtual_clock_moves_the_strict_wait() {
    let server = start(true).await;
    let _holder = hold(&server.backend);
    let addr = server.addr;
    let writer = tokio::spawn(async move {
        http(
            addr,
            "POST",
            "/v1/projects/demo-app/databases/(default)/documents:commit",
            &commit_body(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    move_clock(&server.clock, 19);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!writer.is_finished(), "held");
    move_clock(&server.clock, 2);
    let response = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("the writer answers")
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 409"), "{response}");
    assert!(
        response.contains("ABORTED") && response.contains("Too much contention"),
        "{response}"
    );
    server.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_rest_commit_under_the_emulator_profile_waits_for_the_release_whatever_the_virtual_clock_does(
) {
    let server = start(false).await;
    let holder = hold(&server.backend);
    let addr = server.addr;
    let writer = tokio::spawn(async move {
        http(
            addr,
            "POST",
            "/v1/projects/demo-app/databases/(default)/documents:commit",
            &commit_body(),
        )
        .await
    });
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
    let response = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("the writer answers")
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    server.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn grpc_replays_all_four_recorded_transaction_age_cases() {
    const DEADLOCK: &str = "Aborted due to cross-transaction contention. This occurs when multiple transactions attempt to access the same data, requiring Firestore to abort at least one in order to enforce serializability.";
    for case in ["conflict", "control", "retry", "retry-older"] {
        let server = start(true).await;
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", server.addr))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = pb::firestore_client::FirestoreClient::new(channel);
        let write = |role: &str, state: &str| pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: format!("{DATABASE}/documents/age/{role}"),
                fields: [(
                    "state".to_owned(),
                    pb::Value {
                        value_type: Some(pb::value::ValueType::StringValue(state.to_owned())),
                    },
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            })),
            ..Default::default()
        };
        client
            .commit(pb::CommitRequest {
                database: DATABASE.to_owned(),
                writes: ["a", "b", "c"].map(|role| write(role, "baseline")).to_vec(),
                ..Default::default()
            })
            .await
            .unwrap();
        let read_new =
            |mut client: pb::firestore_client::FirestoreClient<tonic::transport::Channel>,
             role: &str,
             retry: Vec<u8>| {
                let name = format!("{DATABASE}/documents/age/{role}");
                async move {
                    let mut stream = client
                    .batch_get_documents(pb::BatchGetDocumentsRequest {
                        database: DATABASE.to_owned(),
                        documents: vec![name],
                        consistency_selector: Some(
                            pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                                pb::TransactionOptions {
                                    mode: Some(pb::transaction_options::Mode::ReadWrite(
                                        pb::transaction_options::ReadWrite {
                                            retry_transaction: retry,
                                            ..Default::default()
                                        },
                                    )),
                                },
                            ),
                        ),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
                    .into_inner();
                    let mut transaction = Vec::new();
                    let mut state = None;
                    while let Some(response) = stream.message().await.unwrap() {
                        if !response.transaction.is_empty() {
                            transaction = response.transaction;
                        }
                        if let Some(pb::batch_get_documents_response::Result::Found(document)) =
                            response.result
                        {
                            state = document.fields["state"].value_type.clone();
                        }
                    }
                    assert!(!transaction.is_empty());
                    (transaction, state.unwrap())
                }
            };
        let baseline = pb::value::ValueType::StringValue("baseline".into());
        let mut writer = Vec::new();
        if case == "retry-older" {
            let (transaction, state) = read_new(client.clone(), "b", vec![]).await;
            assert_eq!(state, baseline);
            writer = transaction;
            move_clock(&server.clock, 1);
        }
        let (transaction, state) = read_new(client.clone(), "a", vec![]).await;
        assert_eq!(state, baseline);
        if case != "retry-older" && case != "control" {
            move_clock(&server.clock, 1);
            let (token, state) = read_new(client.clone(), "b", vec![]).await;
            assert_eq!(state, baseline);
            writer = token;
        }
        let mut writer_client = client.clone();
        let writer_request = pb::CommitRequest {
            database: DATABASE.to_owned(),
            transaction: writer.clone(),
            writes: vec![write(if case == "control" { "c" } else { "a" }, "writer")],
            ..Default::default()
        };
        let mut pending = tokio::spawn(async move { writer_client.commit(writer_request).await });
        if case == "control" {
            tokio::time::timeout(Duration::from_secs(5), &mut pending)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(150), &mut pending)
                    .await
                    .is_err(),
                "{case}: W must wait before T commits"
            );
        }
        let first = client
            .commit(pb::CommitRequest {
                database: DATABASE.to_owned(),
                transaction: transaction.clone(),
                writes: vec![write("b", "transaction-baseline")],
                ..Default::default()
            })
            .await;
        let mut attempts = 1;
        if case == "retry-older" {
            let error = first.unwrap_err();
            assert_eq!(error.code(), tonic::Code::Aborted);
            assert_eq!(error.message(), DEADLOCK);
            tokio::time::timeout(Duration::from_secs(5), &mut pending)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            // The first attempt never published b; the older writer published only a.
            let document = client
                .get_document(pb::GetDocumentRequest {
                    name: format!("{DATABASE}/documents/age/b"),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                document.fields["state"].value_type.as_ref(),
                Some(&baseline)
            );
            client
                .rollback(pb::RollbackRequest {
                    database: DATABASE.to_owned(),
                    transaction: transaction.clone(),
                    ..Default::default()
                })
                .await
                .unwrap();
            let (retry, state) = read_new(client.clone(), "a", transaction).await;
            assert_eq!(state, pb::value::ValueType::StringValue("writer".into()));
            attempts += 1;
            client
                .commit(pb::CommitRequest {
                    database: DATABASE.to_owned(),
                    transaction: retry,
                    writes: vec![write("b", "transaction-writer")],
                    ..Default::default()
                })
                .await
                .unwrap();
        } else {
            first.unwrap();
            if case != "control" {
                let error = tokio::time::timeout(Duration::from_secs(5), &mut pending)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err();
                assert_eq!(error.code(), tonic::Code::Aborted);
                assert_eq!(error.message(), DEADLOCK);
                client
                    .rollback(pb::RollbackRequest {
                        database: DATABASE.to_owned(),
                        transaction: writer,
                        ..Default::default()
                    })
                    .await
                    .unwrap();
            }
        }
        assert_eq!(attempts, if case == "retry-older" { 2 } else { 1 });
        for (role, expected) in [
            (
                "a",
                if case == "retry-older" {
                    "writer"
                } else {
                    "baseline"
                },
            ),
            (
                "b",
                if case == "retry-older" {
                    "transaction-writer"
                } else {
                    "transaction-baseline"
                },
            ),
            (
                "c",
                if case == "control" {
                    "writer"
                } else {
                    "baseline"
                },
            ),
        ] {
            let document = client
                .get_document(pb::GetDocumentRequest {
                    name: format!("{DATABASE}/documents/age/{role}"),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                document.fields["state"].value_type,
                Some(pb::value::ValueType::StringValue(expected.into())),
                "{case}/{role}"
            );
        }
        server.task.abort();
        assert!(server.task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn contention_lease_bookkeeping_preserves_other_refusals_in_both_wait_loops() {
    use fireemu_core_firestore::store::CROSS_TRANSACTION_CONTENTION;
    let server = start(true).await;
    for asynchronous in [false, true] {
        for (code, message, released) in [
            (tonic::Code::Aborted, CROSS_TRANSACTION_CONTENTION, true),
            (
                tonic::Code::Aborted,
                "Transaction was aborted due to a concurrent modification.",
                false,
            ),
            (
                tonic::Code::PermissionDenied,
                CROSS_TRANSACTION_CONTENTION,
                false,
            ),
            (tonic::Code::PermissionDenied, "write guard refused", false),
        ] {
            let backend = LocalBackend::new(
                Gateway {
                    enforce_limits: true,
                    ctx: PlanningContext {
                        edition: FirestoreEdition::Standard,
                        api_mode: FirestoreApiMode::Native,
                        policy: IndexValidationPolicy::Production,
                    },
                    indexes: IndexSet::default(),
                },
                Arc::clone(&server.clock),
                7,
            )
            .with_lock_lease(Duration::ZERO);
            let token = hold(&backend);
            let (parent, writes) = LocalBackend::plan_commit(&pb::CommitRequest {
                database: DATABASE.to_owned(),
                writes: vec![pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: DOCUMENT.to_owned(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .unwrap();
            let transaction = backend.txn_of(&parent, &token).unwrap().unwrap();
            let attempt = || Err::<(), _>(tonic::Status::new(code, message));
            let error = if asynchronous {
                backend
                    .retry_on_contention_async(&parent, None, &writes, attempt)
                    .await
                    .unwrap_err()
            } else {
                backend
                    .retry_on_contention(&parent, None, &writes, attempt)
                    .unwrap_err()
            };
            assert_eq!(error.code(), code);
            assert_eq!(error.message(), message);
            assert_eq!(
                backend
                    .database_handle(&parent)
                    .unwrap()
                    .with(|db| Ok(db.transaction_is_active(&transaction)))
                    .unwrap(),
                !released,
                "async={asynchronous}, code={code:?}, message={message}"
            );
        }
    }
    server.task.abort();
    assert!(server.task.await.unwrap_err().is_cancelled());
}
