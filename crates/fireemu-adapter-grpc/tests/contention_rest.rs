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
async fn grpc_replays_all_four_recorded_transaction_age_cases_with_a_pinned_clock() {
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
        }
        let (transaction, state) = read_new(client.clone(), "a", vec![]).await;
        assert_eq!(state, baseline);
        if case != "retry-older" && case != "control" {
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

#[tokio::test]
#[allow(clippy::too_many_lines, clippy::result_large_err)]
async fn deadlock_winner_commits_in_one_attempt_with_zero_wait_or_an_expired_deadline() {
    for asynchronous in [false, true] {
        for expired in [false, true] {
            let clock = Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            )));
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
                Arc::clone(&clock),
                7,
            )
            .with_contention_wait(if expired {
                STRICT_CONTENTION_WAIT
            } else {
                Duration::ZERO
            })
            .with_virtual_contention_wait();
            let older = hold(&backend);
            let younger = hold(&backend);
            let mut request = pb::CommitRequest {
                database: DATABASE.into(),
                transaction: younger.clone(),
                writes: vec![pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: DOCUMENT.into(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            };
            let error = backend
                .commit_once(&request, &|_, _, _| Ok(()))
                .unwrap_err();
            assert!(LocalBackend::is_contention(&error));
            request.transaction = older;
            let (parent, writes) = LocalBackend::plan_commit(&request).unwrap();
            let own = backend.txn_of(&parent, &request.transaction).unwrap();
            let mut calls = 0;
            let attempt = || {
                calls += 1;
                if expired {
                    move_clock(&clock, 21);
                }
                backend.commit_once(&request, &|_, _, _| Ok(()))
            };
            let result = if asynchronous {
                backend
                    .retry_on_contention_async(&parent, own.as_ref(), &writes, attempt)
                    .await
            } else {
                backend.retry_on_contention(&parent, own.as_ref(), &writes, attempt)
            };
            result.unwrap();
            assert_eq!(calls, 1, "async={asynchronous}, expired={expired}");
            request.transaction = younger;
            let error = backend
                .commit_once(&request, &|_, _, _| Ok(()))
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::Aborted);
            assert_eq!(
                error.message(),
                fireemu_core_firestore::store::CROSS_TRANSACTION_CONTENTION
            );
        }
    }
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn a_commit_that_stopped_waiting_is_not_a_deadlock_holder() {
    for asynchronous in [false, true] {
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        )));
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
            clock,
            7,
        )
        .with_contention_wait(Duration::ZERO);
        let older = hold(&backend);
        let younger = hold(&backend);
        let mut request = pb::CommitRequest {
            database: DATABASE.into(),
            transaction: younger,
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: DOCUMENT.into(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        };
        let (parent, writes) = LocalBackend::plan_commit(&request).unwrap();
        let own = backend.txn_of(&parent, &request.transaction).unwrap();
        let error = if asynchronous {
            backend
                .retry_on_contention_async(&parent, own.as_ref(), &writes, || {
                    backend.commit_once(&request, &|_, _, _| Ok(()))
                })
                .await
                .unwrap_err()
        } else {
            backend.commit(&request).unwrap_err()
        };
        assert!(LocalBackend::is_contention(&error));
        request.transaction = older;
        assert!(LocalBackend::is_contention(
            &backend
                .commit_once(&request, &|_, _, _| Ok(()))
                .unwrap_err()
        ));
        assert!(backend
            .database_handle(&parent)
            .unwrap()
            .with(|db| Ok(db.transaction_is_active(own.as_ref().unwrap())))
            .unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn rest_replays_all_four_recorded_transaction_age_cases_with_a_pinned_clock() {
    use serde_json::{json, Value};
    const DEADLOCK: &str = fireemu_core_firestore::store::CROSS_TRANSACTION_CONTENTION;
    for case in ["conflict", "control", "retry", "retry-older"] {
        let server = start(true).await;
        let addr = server.addr;
        let commit_path = format!("/v1/{DATABASE}/documents:commit");
        let write = |role: &str, state: &str| json!({"update": {"name": format!("{DATABASE}/documents/age/{role}"), "fields": {"state": {"stringValue": state}}}});
        let parse = |response: &str| -> Value {
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
        };
        let response = http(
            addr,
            "POST",
            &commit_path,
            &json!({"writes": (["a", "b", "c"].map(|role| write(role, "baseline")))}).to_string(),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let read_new = |role: &str, retry: String| {
            let body = json!({"documents": [format!("{DATABASE}/documents/age/{role}")], "newTransaction": {"readWrite": if retry.is_empty() { json!({}) } else { json!({"retryTransaction": retry}) }}}).to_string();
            async move {
                let response = http(
                    addr,
                    "POST",
                    &format!("/v1/{DATABASE}/documents:batchGet"),
                    &body,
                )
                .await;
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                let rows: Value =
                    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
                let rows = rows.as_array().unwrap();
                let token = rows
                    .iter()
                    .find_map(|row| row["transaction"].as_str())
                    .unwrap()
                    .to_owned();
                let state = rows
                    .iter()
                    .find_map(|row| row["found"]["fields"]["state"]["stringValue"].as_str())
                    .unwrap()
                    .to_owned();
                (token, state)
            }
        };
        let mut writer = String::new();
        if case == "retry-older" {
            let (token, state) = read_new("b", String::new()).await;
            assert_eq!(state, "baseline");
            writer = token;
        }
        let (transaction, state) = read_new("a", String::new()).await;
        assert_eq!(state, "baseline");
        if case != "retry-older" && case != "control" {
            let (token, state) = read_new("b", String::new()).await;
            assert_eq!(state, "baseline");
            writer = token;
        }
        let body = json!({"transaction": writer, "writes": [write(if case == "control" { "c" } else { "a" }, "writer")]}).to_string();
        let path = commit_path.clone();
        let mut pending = tokio::spawn(async move { http(addr, "POST", &path, &body).await });
        if case == "control" {
            let response = tokio::time::timeout(Duration::from_secs(5), &mut pending)
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(150), &mut pending)
                    .await
                    .is_err(),
                "{case}: W waits before T commits"
            );
        }
        let response = http(
            addr,
            "POST",
            &commit_path,
            &json!({"transaction": transaction, "writes": [write("b", "transaction-baseline")]})
                .to_string(),
        )
        .await;
        let mut attempts = 1;
        if case == "retry-older" {
            assert!(response.starts_with("HTTP/1.1 409"), "{response}");
            assert_eq!(parse(&response)["error"]["status"], "ABORTED");
            assert_eq!(parse(&response)["error"]["message"], DEADLOCK);
            let response = tokio::time::timeout(Duration::from_secs(5), &mut pending)
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            for (role, state) in [("a", "writer"), ("b", "baseline"), ("c", "baseline")] {
                let response = http(
                    addr,
                    "GET",
                    &format!("/v1/{DATABASE}/documents/age/{role}"),
                    "",
                )
                .await;
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                assert_eq!(parse(&response)["fields"]["state"]["stringValue"], state);
            }
            let response = http(
                addr,
                "POST",
                &format!("/v1/{DATABASE}/documents:rollback"),
                &json!({"transaction": transaction}).to_string(),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            let (token, state) = read_new("a", transaction).await;
            assert_eq!(state, "writer");
            attempts += 1;
            let response = http(
                addr,
                "POST",
                &commit_path,
                &json!({"transaction": token, "writes": [write("b", "transaction-writer")]})
                    .to_string(),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        } else {
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            if case != "control" {
                let response = tokio::time::timeout(Duration::from_secs(5), &mut pending)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(response.starts_with("HTTP/1.1 409"), "{response}");
                assert_eq!(parse(&response)["error"]["status"], "ABORTED");
                assert_eq!(parse(&response)["error"]["message"], DEADLOCK);
                let response = http(
                    addr,
                    "POST",
                    &format!("/v1/{DATABASE}/documents:rollback"),
                    &json!({"transaction": writer}).to_string(),
                )
                .await;
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
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
            let response = http(
                addr,
                "GET",
                &format!("/v1/{DATABASE}/documents/age/{role}"),
                "",
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert_eq!(
                parse(&response)["fields"]["state"]["stringValue"],
                expected,
                "{case}/{role}"
            );
        }
        server.task.abort();
        assert!(server.task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::result_large_err)]
async fn a_rest_commit_that_timed_out_is_not_a_deadlock_holder() {
    use fireemu_adapter_grpc::rest::json::base64_encode;
    let server = start(true).await;
    let older = hold(&server.backend);
    let younger = hold(&server.backend);
    let addr = server.addr;
    let body = serde_json::json!({"transaction": base64_encode(&younger), "writes": [{"update": {"name": DOCUMENT}}]}).to_string();
    let mut pending = tokio::spawn(async move {
        http(
            addr,
            "POST",
            "/v1/projects/demo-app/databases/%28default%29/documents:commit",
            &body,
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut pending)
            .await
            .is_err()
    );
    move_clock(&server.clock, 21);
    let response = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 409"), "{response}");
    assert!(
        response.contains(fireemu_core_firestore::store::TOO_MUCH_CONTENTION),
        "{response}"
    );
    let request = pb::CommitRequest {
        database: DATABASE.into(),
        transaction: older,
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: DOCUMENT.into(),
                ..Default::default()
            })),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(LocalBackend::is_contention(
        &server
            .backend
            .commit_once(&request, &|_, _, _| Ok(()))
            .unwrap_err()
    ));
    let (parent, _) = LocalBackend::plan_commit(&request).unwrap();
    let own = server.backend.txn_of(&parent, &younger).unwrap().unwrap();
    assert!(server
        .backend
        .database_handle(&parent)
        .unwrap()
        .with(|db| Ok(db.transaction_is_active(&own)))
        .unwrap());
    server.task.abort();
    assert!(server.task.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::result_large_err)]
async fn an_unrelated_rest_refusal_does_not_clear_a_pending_commits_wait() {
    let server = start(true).await;
    let older = hold(&server.backend);
    let younger = hold(&server.backend);
    let addr = server.addr;
    let body = serde_json::json!({"transaction": fireemu_adapter_grpc::rest::json::base64_encode(&younger), "writes": [{"update": {"name": DOCUMENT}}]}).to_string();
    let pending_body = body.clone();
    let mut pending = tokio::spawn(async move {
        http(
            addr,
            "POST",
            &format!("/v1/{DATABASE}/documents:commit"),
            &pending_body,
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut pending)
            .await
            .is_err()
    );
    let response = http(
        addr,
        "GET",
        &format!("/v1/{DATABASE}/documents:commit"),
        &body,
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    let request = pb::CommitRequest {
        database: DATABASE.into(),
        transaction: older,
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: DOCUMENT.into(),
                ..Default::default()
            })),
            ..Default::default()
        }],
        ..Default::default()
    };
    server
        .backend
        .commit_once(&request, &|_, _, _| Ok(()))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 409"), "{response}");
    assert!(
        response.contains(fireemu_core_firestore::store::CROSS_TRANSACTION_CONTENTION),
        "{response}"
    );
    server.task.abort();
    assert!(server.task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn a_guard_refusal_does_not_clear_another_commit_wait() {
    for asynchronous in [false, true] {
        let server = start(true).await;
        let older = hold(&server.backend);
        let younger = hold(&server.backend);
        let mut request = pb::CommitRequest {
            database: DATABASE.into(),
            transaction: younger.clone(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: DOCUMENT.into(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(LocalBackend::is_contention(
            &server
                .backend
                .commit_once(&request, &|_, _, _| Ok(()))
                .unwrap_err()
        ));
        let (parent, writes) = LocalBackend::plan_commit(&request).unwrap();
        let own = server
            .backend
            .txn_of(&parent, &request.transaction)
            .unwrap();
        let denied =
            |_: &fireemu_core_firestore::store::FirestoreState,
             _: &[fireemu_core_firestore::store::Write],
             _: LogicalInstant| Err(tonic::Status::permission_denied("guard refused"));
        let error = if asynchronous {
            server
                .backend
                .retry_on_contention_async(&parent, own.as_ref(), &writes, || {
                    server.backend.commit_once(&request, &denied)
                })
                .await
                .unwrap_err()
        } else {
            server.backend.commit_with(&request, &denied).unwrap_err()
        };
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        request.transaction = older;
        server
            .backend
            .commit_once(&request, &|_, _, _| Ok(()))
            .unwrap();
        request.transaction = younger;
        assert_eq!(
            server
                .backend
                .commit_once(&request, &|_, _, _| Ok(()))
                .unwrap_err()
                .message(),
            fireemu_core_firestore::store::CROSS_TRANSACTION_CONTENTION
        );
        server.task.abort();
        assert!(server.task.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn a_guard_refusal_after_a_wait_clears_that_commits_wait() {
    let server = start(true).await;
    for asynchronous in [false, true] {
        let older = hold(&server.backend);
        let younger = hold(&server.backend);
        let mut request = pb::CommitRequest {
            database: DATABASE.into(),
            transaction: younger.clone(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: DOCUMENT.into(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        };
        let (parent, writes) = LocalBackend::plan_commit(&request).unwrap();
        let own = server.backend.txn_of(&parent, &younger).unwrap();
        let mut calls = 0;
        let attempt = || {
            calls += 1;
            if calls > 1 {
                return Err(tonic::Status::permission_denied(
                    "guard changed while waiting",
                ));
            }
            let refusal = server.backend.commit_once(&request, &|_, _, _| Ok(()));
            let unrelated = server
                .backend
                .begin_transaction(&pb::BeginTransactionRequest {
                    database: DATABASE.into(),
                    ..Default::default()
                })
                .unwrap();
            server
                .backend
                .rollback(&pb::RollbackRequest {
                    database: DATABASE.into(),
                    transaction: unrelated,
                    ..Default::default()
                })
                .unwrap();
            refusal
        };
        let error = if asynchronous {
            server
                .backend
                .retry_on_contention_async(&parent, own.as_ref(), &writes, attempt)
                .await
                .unwrap_err()
        } else {
            server
                .backend
                .retry_on_contention(&parent, own.as_ref(), &writes, attempt)
                .unwrap_err()
        };
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert_eq!(calls, 2);
        request.transaction = older.clone();
        assert!(LocalBackend::is_contention(
            &server
                .backend
                .commit_once(&request, &|_, _, _| Ok(()))
                .unwrap_err()
        ));
        for transaction in [older, younger] {
            server
                .backend
                .rollback(&pb::RollbackRequest {
                    database: DATABASE.into(),
                    transaction,
                    ..Default::default()
                })
                .unwrap();
        }
    }
    server.task.abort();
    assert!(server.task.await.unwrap_err().is_cancelled());
}
