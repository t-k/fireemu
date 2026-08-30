//! A `dropConnection` fault closes the connection (HTTP/1) or resets the stream (gRPC over
//! HTTP/2) instead of answering, so transport-loss retry paths can be exercised.

use std::sync::{Arc, Mutex};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::rest::RestState;
use ftd_adapter_grpc::serve::serve_multiplexed;
use ftd_adapter_grpc::service::GatewayService;
use ftd_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use ftd_core_session::clock::VirtualClock;
use ftd_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule};
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::time::LogicalInstant;
use ftd_proto_firestore::google::firestore::v1 as pb;
use ftd_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DOC: &str = "projects/demo-app/databases/(default)/documents/things/t1";

async fn rest_get(addr: std::net::SocketAddr, path: &str) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out).await;
    out
}

#[tokio::test]
async fn drop_connection_faults_close_rest_and_reset_grpc_streams() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
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
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
    let registry = Arc::new(FaultRegistry::new());
    let rule = |nth: u64| FaultRule {
        matches: FaultMatch {
            operation: "firestore.read".into(),
            nth: Some(nth),
            function: None,
            event_type: None,
        },
        action: FaultAction::DropConnection,
    };
    registry.default_state().lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![rule(1), rule(3)],
    });
    backend.set_faults(registry.clone());
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway.clone()),
        rules: None,
    });
    let server = tokio::spawn(serve_multiplexed(
        listener,
        FirestoreServer::new(GatewayService::local(gateway, backend)),
        rest,
    ));
    // REST, first read: the connection closes without any response bytes.
    let dropped = rest_get(addr, &format!("/v1/{DOC}")).await;
    assert!(dropped.is_empty(), "{}", String::from_utf8_lossy(&dropped));
    // Second read: served (the document does not exist).
    let answered = rest_get(addr, &format!("/v1/{DOC}")).await;
    assert!(
        answered.starts_with(b"HTTP/1.1 404"),
        "{}",
        String::from_utf8_lossy(&answered)
    );
    // gRPC, third read: the stream is reset, which the client reports as a transport
    // error rather than a Firestore status; the channel serves the next call.
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = FirestoreClient::new(channel);
    let get = || pb::GetDocumentRequest {
        name: DOC.to_owned(),
        ..Default::default()
    };
    let err = client.get_document(get()).await.unwrap_err();
    assert_ne!(err.code(), tonic::Code::NotFound, "{err}");
    let err = client.get_document(get()).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound, "{err}");
    let fired = registry.default_state().lock().unwrap().fired().len();
    assert_eq!(fired, 2);
    server.abort();
}
