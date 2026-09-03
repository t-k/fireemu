//! Transport-level guards for maliciously deep Firestore values.

use std::sync::{Arc, Mutex};

use bytes::{Buf, BufMut};
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
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};

const DB: &str = "projects/demo-app/databases/(default)";
const DOC: &str = "projects/demo-app/databases/(default)/documents/items/deep";

#[derive(Debug, Clone, Default)]
struct RawCodec;

#[derive(Debug, Clone, Default)]
struct RawEncoder;

#[derive(Debug, Clone, Default)]
struct UnitDecoder;

impl Codec for RawCodec {
    type Encode = Vec<u8>;
    type Decode = ();
    type Encoder = RawEncoder;
    type Decoder = UnitDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        RawEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        UnitDecoder
    }
}

impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = tonic::Status;

    fn encode(&mut self, item: Self::Item, buffer: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        buffer.put_slice(&item);
        Ok(())
    }
}

impl Decoder for UnitDecoder {
    type Item = ();
    type Error = tonic::Status;

    fn decode(&mut self, buffer: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        buffer.advance(buffer.remaining());
        Ok(Some(()))
    }
}

fn push_varint(output: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        output.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    output.push(u8::try_from(value).unwrap());
}

fn delimited(field: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(1 + 10 + payload.len());
    output.push((field << 3) | 2);
    push_varint(&mut output, payload.len());
    output.extend_from_slice(payload);
    output
}

fn map_entry(key: &str, value: &[u8]) -> Vec<u8> {
    let mut entry = delimited(1, key.as_bytes());
    entry.extend(delimited(2, value));
    entry
}

fn commit_with_nested_map(levels: usize) -> Vec<u8> {
    // Value.integer_value = 1.
    let mut value = vec![0x10, 0x01];
    for _ in 0..levels {
        // Value.map_value -> MapValue.fields["next"] -> Value.
        value = delimited(6, &delimited(1, &map_entry("next", &value)));
    }
    let mut document = delimited(1, DOC.as_bytes());
    document.extend(delimited(2, &map_entry("deep", &value)));
    let write = delimited(1, &document);
    let mut commit = delimited(1, DB.as_bytes());
    commit.extend(delimited(2, &write));
    commit
}

fn get_document_with_nested_unknown_groups(levels: usize) -> Vec<u8> {
    let mut request = delimited(1, DOC.as_bytes());
    for _ in 0..levels {
        // Unknown field 99 with the deprecated group wire types. Prost applies its
        // recursion guard while skipping these fields.
        push_varint(&mut request, (99 << 3) | 3);
    }
    for _ in 0..levels {
        push_varint(&mut request, (99 << 3) | 4);
    }
    request
}

fn json_commit_with_nested_map(levels: usize) -> String {
    let mut value = r#"{"integerValue":"1"}"#.to_owned();
    for _ in 0..levels {
        value = format!(r#"{{"mapValue":{{"fields":{{"next":{value}}}}}}}"#);
    }
    format!(r#"{{"writes":[{{"update":{{"name":"{DOC}","fields":{{"deep":{value}}}}}}}]}}"#)
}

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

async fn verify_grpc_value_boundary(
    raw: &mut tonic::client::Grpc<tonic::transport::Channel>,
    channel: tonic::transport::Channel,
) {
    raw.ready().await.unwrap();
    raw.unary(
        tonic::Request::new(commit_with_nested_map(20)),
        hyper::http::uri::PathAndQuery::from_static("/google.firestore.v1.Firestore/Commit"),
        RawCodec,
    )
    .await
    .expect("the documented depth boundary must be accepted");

    let mut client = FirestoreClient::new(channel.clone());
    let stored = client
        .get_document(pb::GetDocumentRequest {
            name: DOC.to_owned(),
            ..Default::default()
        })
        .await
        .expect("the raw fixture must encode a valid nested Firestore value")
        .into_inner();
    let stored_depth = stored.fields["deep"]
        .clone()
        .value_type
        .expect("the stored value has a value type");
    let mut cursor = stored_depth;
    for _ in 0..20 {
        let pb::value::ValueType::MapValue(map) = cursor else {
            panic!("the raw fixture did not encode a nested map")
        };
        cursor = map.fields["next"]
            .clone()
            .value_type
            .expect("each nested value has a value type");
    }
    assert!(matches!(cursor, pb::value::ValueType::IntegerValue(1)));

    raw.ready().await.unwrap();
    let boundary_error = raw
        .unary(
            tonic::Request::new(commit_with_nested_map(21)),
            hyper::http::uri::PathAndQuery::from_static("/google.firestore.v1.Firestore/Commit"),
            RawCodec,
        )
        .await
        .unwrap_err();
    assert_eq!(
        boundary_error.code(),
        tonic::Code::InvalidArgument,
        "{boundary_error}"
    );
    assert!(
        boundary_error
            .message()
            .contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"),
        "{boundary_error}"
    );
}

async fn verify_grpc_recursion_guard(
    raw: &mut tonic::client::Grpc<tonic::transport::Channel>,
    channel: tonic::transport::Channel,
) {
    raw.ready().await.unwrap();
    let error = raw
        .unary(
            tonic::Request::new(commit_with_nested_map(10_000)),
            hyper::http::uri::PathAndQuery::from_static("/google.firestore.v1.Firestore/Commit"),
            RawCodec,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
    assert!(
        error.message().contains("recursion limit reached"),
        "{error}"
    );
    assert!(!error.message().contains("FS-LIMIT"), "{error}");

    raw.ready().await.unwrap();
    let unrelated_recursion = raw
        .unary(
            tonic::Request::new(get_document_with_nested_unknown_groups(200)),
            hyper::http::uri::PathAndQuery::from_static(
                "/google.firestore.v1.Firestore/GetDocument",
            ),
            RawCodec,
        )
        .await
        .unwrap_err();
    assert_eq!(
        unrelated_recursion.code(),
        tonic::Code::InvalidArgument,
        "{unrelated_recursion}"
    );
    assert!(
        unrelated_recursion
            .message()
            .contains("recursion limit reached"),
        "{unrelated_recursion}"
    );
    assert!(
        !unrelated_recursion.message().contains("FS-LIMIT"),
        "{unrelated_recursion}"
    );

    let mut client = FirestoreClient::new(channel);
    let alive = client
        .get_document(pb::GetDocumentRequest {
            name: "projects/demo-app/databases/(default)/documents/items/missing".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(alive.code(), tonic::Code::NotFound);
}

async fn verify_rest_depth_cases(addr: std::net::SocketAddr) {
    let nested_rest = http(
        addr,
        "POST",
        "/v1/projects/demo-app/databases/(default)/documents:commit",
        &json_commit_with_nested_map(21),
    )
    .await;
    assert!(nested_rest.starts_with("HTTP/1.1 400"), "{nested_rest}");
    assert!(
        nested_rest.contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"),
        "{nested_rest}"
    );
    assert!(nested_rest.contains("INVALID_ARGUMENT"), "{nested_rest}");

    let serde_boundary = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    let malformed = http(
        addr,
        "POST",
        "/v1/projects/demo-app/databases/(default)/documents:commit",
        &serde_boundary,
    )
    .await;
    assert!(malformed.starts_with("HTTP/1.1 400"), "{malformed}");
    assert!(malformed.contains("INVALID_ARGUMENT"), "{malformed}");

    let ready = http(addr, "GET", "/", "").await;
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");
}

async fn run_transport_case() {
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
    });
    let server = tokio::spawn(serve_multiplexed(
        listener,
        FirestoreServer::new(GatewayService::local(gateway, backend))
            .max_decoding_message_size(10 * 1024 * 1024),
        rest,
    ));
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut raw = tonic::client::Grpc::new(channel.clone());
    verify_grpc_value_boundary(&mut raw, channel.clone()).await;
    verify_grpc_recursion_guard(&mut raw, channel).await;
    verify_rest_depth_cases(addr).await;
    server.abort();
    let _ = server.await;
}

#[test]
fn deeply_nested_grpc_commit_is_invalid_argument_and_the_daemon_survives() {
    std::thread::Builder::new()
        .name("depth-transport".to_owned())
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_transport_case());
        })
        .unwrap()
        .join()
        .unwrap();
}
