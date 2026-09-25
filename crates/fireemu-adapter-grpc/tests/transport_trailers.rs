//! How a gRPC error reaches the client through the daemon's multiplexed server.

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
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;

const DOCS: &str = "projects/demo-app/databases/(default)/documents";

fn gateway(strict: bool) -> Gateway {
    Gateway {
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
    }
}

async fn client(
    strict: bool,
) -> (
    tonic::transport::Channel,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = Arc::new(LocalBackend::new(
        gateway(strict),
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    ));
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway(strict)),
        rules: None,
        app_check: None,
        control_token: None,
    });
    let server = tokio::spawn(serve_multiplexed(
        listener,
        FirestoreServer::new(GatewayService::local(gateway(strict), backend)),
        rest,
    ));
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (channel, server)
}

/// FS-DATA-WRITE decision 1 (2026-09-25): production's front end sends a gRPC error as
/// headers and then trailers, so a client never finds `content-type` among the error's
/// trailers (`writes/limits/grpc-unary-request-bytes/*`, recorded twice). tonic answers an
/// error trailers-only; strict splits it, the emulator profile keeps tonic's answer.
#[tokio::test]
async fn strict_errors_arrive_as_headers_then_trailers() {
    for strict in [true, false] {
        let (channel, server) = client(strict).await;
        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready().await.expect("gRPC channel ready");
        let response: Result<tonic::Response<tonic::codec::Streaming<pb::Document>>, _> = grpc
            .server_streaming(
                tonic::Request::new(pb::GetDocumentRequest {
                    name: format!("{DOCS}/missing/doc"),
                    ..Default::default()
                }),
                tonic::codegen::http::uri::PathAndQuery::from_static(
                    "/google.firestore.v1.Firestore/GetDocument",
                ),
                tonic::codec::ProstCodec::default(),
            )
            .await;
        if strict {
            let response = response.expect("strict sends initial headers before the error");
            assert!(response.metadata().contains_key("content-type"));
            let error = response.into_inner().message().await.unwrap_err();
            assert_eq!(error.code(), tonic::Code::NotFound);
            assert!(!error.metadata().contains_key("content-type"));
        } else {
            let error = response.expect_err("emulator keeps tonic's trailers-only answer");
            assert_eq!(error.code(), tonic::Code::NotFound);
            assert!(error.metadata().contains_key("content-type"));
        }
        server.abort();
    }
}
