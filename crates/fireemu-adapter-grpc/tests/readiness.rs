//! The shared Firestore listener serves an exact HTTP readiness route without capturing gRPC.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_grpc::serve::serve_multiplexed;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn http(addr: std::net::SocketAddr, request: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn start() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
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
    let backend = Arc::new(LocalBackend::new(
        gateway.clone(),
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    ));
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway.clone()),
        rules: None,
        app_check: None,
        control_token: None,
    });
    let server = tokio::spawn(serve_multiplexed(
        listener,
        FirestoreServer::new(GatewayService::local(gateway, backend)),
        rest,
    ));

    (addr, server)
}

#[tokio::test]
async fn firestore_root_is_ready_without_capturing_rest_or_grpc() {
    let (addr, server) = start().await;
    let ready = http(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");
    assert!(ready.contains("cache-control: no-store"), "{ready}");

    let unknown = http(
        addr,
        "GET /unknown HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");

    let foreign = http(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(foreign.starts_with("HTTP/1.1 403"), "{foreign}");

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = FirestoreClient::new(channel);
    let error = client
        .get_document(pb::GetDocumentRequest {
            name: "projects/demo-app/databases/(default)/documents/things/missing".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    server.abort();
}

/// DNS rebinding: an HTTP/1 request whose `Host` names a public domain is refused on every
/// REST and `WebChannel` route, while gRPC (HTTP/2, which no browser speaks in cleartext) is
/// not checked even when its `:authority` names another host.
#[tokio::test]
async fn a_rebound_host_is_refused_over_http1_and_grpc_is_not_checked() {
    let (addr, server) = start().await;
    for path in [
        "/",
        "/v1/projects/demo-app/databases/(default)/documents/things/missing",
        "/google.firestore.v1.Firestore/Listen/channel?VER=8&database=projects%2Fdemo-app%2Fdatabases%2F(default)&RID=1&CVER=22&X-HTTP-Session-Id=gsessionid&zx=1&t=1",
    ] {
        let refused = http(
            addr,
            &format!("GET {path} HTTP/1.1\r\nHost: evil.example:8080\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(refused.starts_with("HTTP/1.1 403"), "{path}: {refused}");
        assert!(refused.contains("network.allowedHosts"), "{refused}");
    }
    let admitted = http(
        addr,
        "GET /v1/projects/demo-app/databases/(default)/documents/things/missing HTTP/1.1\r\nHost: 10.0.2.2:8080\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(admitted.starts_with("HTTP/1.1 404"), "{admitted}");

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .origin("http://firestore.evil.example:8080".parse().unwrap())
        .connect()
        .await
        .unwrap();
    let error = FirestoreClient::new(channel)
        .get_document(pb::GetDocumentRequest {
            name: "projects/demo-app/databases/(default)/documents/things/missing".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    server.abort();
}
