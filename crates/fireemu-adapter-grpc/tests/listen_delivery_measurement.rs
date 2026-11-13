//! Ignored local TCP/gRPC measurements; the client and server share one process.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use pb::firestore_client::FirestoreClient;
use pb::firestore_server::FirestoreServer;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

const DB: &str = "projects/demo-measure/databases/(default)";
const DOCS: &str = "projects/demo-measure/databases/(default)/documents";
const PAYLOAD_BYTES: usize = 1024;

struct ServerTask(tokio::task::JoinHandle<()>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        // A failed assertion must not leave the server running until the test process exits.
        self.0.abort();
    }
}

fn phase(name: &str) {
    eprintln!(
        "listen_network_phase {}",
        serde_json::json!({"phase": name})
    );
}

async fn start() -> (
    FirestoreClient<tonic::transport::Channel>,
    oneshot::Sender<()>,
    ServerTask,
) {
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
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let service = FirestoreServer::new(GatewayService::local(gateway, backend));
    let task = ServerTask(tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    }));
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (FirestoreClient::new(channel), shutdown, task)
}

fn document_name(index: usize) -> String {
    format!("{DOCS}/measured/d{index:06}")
}

fn write(name: String, revision: i64) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name,
            fields: [
                (
                    "revision".to_owned(),
                    pb::Value {
                        value_type: Some(pb::value::ValueType::IntegerValue(revision)),
                    },
                ),
                (
                    "payload".to_owned(),
                    pb::Value {
                        value_type: Some(pb::value::ValueType::StringValue(
                            "x".repeat(PAYLOAD_BYTES),
                        )),
                    },
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn query() -> pb::ListenRequest {
    pb::ListenRequest {
        database: DB.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
            target_id: 1,
            target_type: Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                parent: DOCS.to_owned(),
                query_type: Some(pb::target::query_target::QueryType::StructuredQuery(
                    pb::StructuredQuery {
                        from: vec![pb::structured_query::CollectionSelector {
                            collection_id: "measured".to_owned(),
                            all_descendants: false,
                        }],
                        ..Default::default()
                    },
                )),
            })),
            ..Default::default()
        })),
        ..Default::default()
    }
}

async fn receive(
    stream: &mut tonic::Streaming<pb::ListenResponse>,
) -> pb::listen_response::ResponseType {
    tokio::time::timeout(Duration::from_secs(30), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .response_type
        .unwrap()
}

fn check_document(document: &pb::Document, revision: i64) {
    assert_eq!(
        document.fields["revision"].value_type,
        Some(pb::value::ValueType::IntegerValue(revision))
    );
    assert_eq!(
        document.fields["payload"].value_type,
        Some(pb::value::ValueType::StringValue("x".repeat(PAYLOAD_BYTES)))
    );
}

/// The schedule knobs also support small generated coverage combinations.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "release TCP Listen measurement with external RSS sampling"]
#[allow(clippy::too_many_lines)]
async fn measure_listen_network_delivery() {
    use pb::listen_response::ResponseType as Response;
    use pb::target_change::TargetChangeType as Kind;

    let count = std::env::var("FIREEMU_LISTEN_MEASURE_DOCUMENTS")
        .ok()
        .map_or(100_000, |value| value.parse::<usize>().unwrap());
    assert!(count >= 257);
    let pause =
        std::env::var("FIREEMU_LISTEN_MEASURE_RECEIVER").unwrap_or_else(|_| "normal".to_owned());
    assert!(matches!(pause.as_str(), "normal" | "pause"));
    let mutation =
        std::env::var("FIREEMU_LISTEN_MEASURE_MUTATION").unwrap_or_else(|_| "none".to_owned());
    assert!(matches!(mutation.as_str(), "none" | "write"));
    let termination =
        std::env::var("FIREEMU_LISTEN_MEASURE_TERMINATION").unwrap_or_else(|_| "drain".to_owned());
    assert!(matches!(termination.as_str(), "drain" | "cancel"));
    phase("connection_setup");
    let connection_start = Instant::now();
    let (mut client, shutdown, mut server) = start().await;
    let connection_micros = connection_start.elapsed().as_micros();
    phase("fixture_setup");
    let setup_start = Instant::now();
    for begin in (0..count).step_by(500) {
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: (begin..(begin + 500).min(count))
                    .map(|index| write(document_name(index), 0))
                    .collect(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let setup_micros = setup_start.elapsed().as_micros();
    let (requests, inbound) = mpsc::channel(1);
    let mut stream = client
        .listen(ReceiverStream::new(inbound))
        .await
        .unwrap()
        .into_inner();
    phase("initial_delivery");
    let start = Instant::now();
    requests.send(query()).await.unwrap();
    let Response::TargetChange(add) = receive(&mut stream).await else {
        panic!("expected ADD")
    };
    assert_eq!(add.target_change_type, Kind::Add as i32);
    assert_eq!(add.target_ids, [1]);
    let first_add_micros = start.elapsed().as_micros();
    let mut commit_micros = None;
    let mut get_micros = None;
    let mut expected_delta = BTreeMap::new();
    if mutation == "write" {
        phase("concurrent_write");
        let mut writes = (0..100)
            .map(|index| {
                let name = document_name(index);
                expected_delta.insert(name.clone(), "change");
                write(name, 1)
            })
            .collect::<Vec<_>>();
        let deleted = document_name(count - 1);
        expected_delta.insert(deleted.clone(), "delete");
        writes.push(pb::Write {
            operation: Some(pb::write::Operation::Delete(deleted)),
            ..Default::default()
        });
        let created = format!("{DOCS}/measured/new");
        expected_delta.insert(created.clone(), "change");
        writes.push(write(created, 1));
        let commit_start = Instant::now();
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes,
                ..Default::default()
            })
            .await
            .unwrap();
        commit_micros = Some(commit_start.elapsed().as_micros());
        let get_start = Instant::now();
        let observed = client
            .get_document(pb::GetDocumentRequest {
                name: document_name(0),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        check_document(&observed, 1);
        get_micros = Some(get_start.elapsed().as_micros());
    }
    if pause == "pause" {
        phase("paused_receiver");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let mut first_document_micros = None;
    let mut initial_complete_micros = None;
    let mut received = 0usize;
    if termination == "drain" {
        phase("drain");
        let mut boundary = None;
        loop {
            match receive(&mut stream).await {
                Response::DocumentChange(change) => {
                    first_document_micros.get_or_insert_with(|| start.elapsed().as_micros());
                    assert!(boundary.is_none());
                    assert_eq!(change.target_ids, [1]);
                    assert_eq!(change.removed_target_ids, [] as [i32; 0]);
                    let document = change.document.unwrap();
                    assert_eq!(document.name, document_name(received));
                    check_document(&document, 0);
                    received += 1;
                }
                Response::TargetChange(change)
                    if change.target_change_type == Kind::Current as i32 =>
                {
                    assert_eq!(received, count);
                    assert_eq!(change.target_ids, [1]);
                    assert_ne!(change.resume_token, [] as [u8; 0]);
                    assert!(change.read_time.is_some());
                    assert!(boundary
                        .replace((change.resume_token, change.read_time))
                        .is_none());
                }
                Response::TargetChange(change)
                    if change.target_change_type == Kind::NoChange as i32 =>
                {
                    assert_eq!(change.target_ids, [] as [i32; 0]);
                    assert_eq!(boundary, Some((change.resume_token, change.read_time)));
                    break;
                }
                other => panic!("unexpected initial frame: {other:?}"),
            }
        }
        assert_eq!(received, count);
        initial_complete_micros = Some(start.elapsed().as_micros());
        if mutation == "write" {
            loop {
                match receive(&mut stream).await {
                    Response::DocumentChange(change) => {
                        assert_eq!(change.target_ids, [1]);
                        let document = change.document.unwrap();
                        check_document(&document, 1);
                        assert_eq!(expected_delta.remove(&document.name), Some("change"));
                    }
                    Response::DocumentDelete(delete) => {
                        assert_eq!(delete.removed_target_ids, [1]);
                        assert_eq!(expected_delta.remove(&delete.document), Some("delete"));
                    }
                    Response::TargetChange(change)
                        if change.target_change_type == Kind::NoChange as i32 =>
                    {
                        assert_eq!(change.target_ids, [] as [i32; 0]);
                        assert!(expected_delta.is_empty());
                        break;
                    }
                    other => panic!("unexpected delta frame: {other:?}"),
                }
            }
        }
    }
    phase("cancellation_cleanup");
    let cleanup_start = Instant::now();
    drop(stream);
    drop(requests);
    drop(client);
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), &mut server.0)
        .await
        .unwrap()
        .unwrap();
    let cleanup_micros = cleanup_start.elapsed().as_micros();
    eprintln!(
        "listen_network_measure {}",
        serde_json::json!({
            "documents": count, "received_initial_documents": received, "payload_bytes_per_document": PAYLOAD_BYTES,
            "runtime_workers": 2, "receiver": pause, "mutation": mutation, "termination": termination,
            "connection_micros": connection_micros, "setup_micros": setup_micros,
            "first_add_micros": first_add_micros, "first_document_micros": first_document_micros,
            "initial_complete_micros": initial_complete_micros, "commit_micros": commit_micros, "get_micros": get_micros,
            "cleanup_micros": cleanup_micros, "transport": "loopback TCP/gRPC", "rss_scope": "combined client and server process"
        })
    );
}
