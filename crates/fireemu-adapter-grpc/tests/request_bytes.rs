//! `FS-LIMIT-API-REQUEST-BYTES`: the 10 MiB inclusive maximum on one API request, at the
//! transport decode boundary of each Firestore protocol.
//!
//! The limit is measured on the message payload before protocol decode, so it is refused
//! without the request ever being parsed and without the over-long body being held whole in
//! memory: the REST and `WebChannel` bodies come through a bounded stream
//! (`fireemu_adapter_support::body::collect_limited`) and a gRPC message is refused by tonic
//! before prost sees it. Both profiles refuse it, because it is a transport bound rather
//! than a document rule and it is already in force.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_grpc::serve::{
    serve_multiplexed, API_REQUEST_BYTES, MAX_GRPC_MESSAGE_BYTES, MAX_REST_BODY_BYTES,
};
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_adapter_grpc::webchannel::MAX_FORM_BYTES;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_limits::catalogs::FIRESTORE_STANDARD_2026_08_25;
use fireemu_core_limits::model::LimitMaximum;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DB: &str = "projects/demo-app/databases/(default)";
const NAMES: &str = "projects/demo-app/databases/(default)/documents";
const COMMIT: &str = "/v1/projects/demo-app/databases/(default)/documents:commit";
const CHANNEL: &str = "/google.firestore.v1.Firestore/Write/channel";

/// Documents per boundary request. Each one stays well inside `FS-LIMIT-DOCUMENT-BYTES`
/// (1 MiB), so a 10 MiB request is refused for its own size and nothing else.
const DOCUMENTS: usize = 12;

#[test]
fn every_transport_bound_is_the_catalog_maximum() {
    let limit = FIRESTORE_STANDARD_2026_08_25
        .find("FS-LIMIT-API-REQUEST-BYTES")
        .expect("the catalog defines the API request limit");
    assert_eq!(limit.maximum, LimitMaximum::Fixed(10_485_760));
    assert_eq!(API_REQUEST_BYTES, 10_485_760);
    assert_eq!(MAX_REST_BODY_BYTES, API_REQUEST_BYTES);
    assert_eq!(MAX_FORM_BYTES, API_REQUEST_BYTES);
    assert_eq!(MAX_GRPC_MESSAGE_BYTES, API_REQUEST_BYTES);
}

// ---------------------------------------------------------------------------
// Fixtures: a valid Commit of an exact byte length
// ---------------------------------------------------------------------------

/// A REST `commit` body of exactly `bytes` compact UTF-8 bytes, writing [`DOCUMENTS`]
/// documents named `{scope}-{index}`, with the padding spread across their string fields.
fn rest_commit_of(bytes: usize, scope: &str) -> String {
    let body = |pads: &[usize]| {
        let writes: Vec<String> = pads
            .iter()
            .enumerate()
            .map(|(index, pad)| {
                format!(
                    r#"{{"update":{{"name":"{NAMES}/req/{scope}-{index}","fields":{{"v":{{"stringValue":"{}"}}}}}}}}"#,
                    "x".repeat(*pad)
                )
            })
            .collect();
        format!(r#"{{"writes":[{}]}}"#, writes.join(","))
    };
    let base = body(&[0; DOCUMENTS]).len();
    let padding = bytes
        .checked_sub(base)
        .expect("the boundary is larger than the envelope");
    let mut pads = vec![padding / DOCUMENTS; DOCUMENTS];
    pads[DOCUMENTS - 1] += padding % DOCUMENTS;
    let out = body(&pads);
    assert_eq!(out.len(), bytes, "the fixture must be exact");
    out
}

/// One `Write` that stores `pad` bytes in document `req/{scope}-{index}`.
fn grpc_write(scope: &str, index: usize, pad: usize) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: format!("{NAMES}/req/{scope}-{index}"),
            fields: [(
                "v".to_owned(),
                pb::Value {
                    value_type: Some(pb::value::ValueType::StringValue("x".repeat(pad))),
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// Bytes one `Write` contributes to a `CommitRequest`: the field-2 tag, its length
/// delimiter, and the message itself.
fn grpc_write_contribution(write: &pb::Write) -> usize {
    let len = write.encoded_len();
    1 + prost::length_delimiter_len(len) + len
}

/// Payload of each of the [`DOCUMENTS`] `- 1` fixed documents. Their contribution never
/// changes, so only the last document has to be searched, and each one stays inside
/// `FS-LIMIT-DOCUMENT-BYTES`.
const FIXED_PAYLOAD: usize = 950_000;

/// A `CommitRequest` whose protobuf encoding is exactly `bytes` long.
///
/// Padding a string also lengthens the length delimiter of every message enclosing it, so a
/// single correction overshoots and some totals are unreachable by one payload alone. The
/// fixed documents are measured once, the last document's payload is searched for the exact
/// crossing, and the first document absorbs a byte at a time when a delimiter step jumps
/// over the target.
fn grpc_commit_of(bytes: usize, scope: &str) -> pb::CommitRequest {
    let last = DOCUMENTS - 1;
    for bump in 0..16usize {
        let fixed: Vec<pb::Write> = (0..last)
            .map(|index| grpc_write(scope, index, FIXED_PAYLOAD + usize::from(index == 0) * bump))
            .collect();
        let head = pb::CommitRequest {
            database: DB.to_owned(),
            writes: fixed.clone(),
            ..Default::default()
        }
        .encoded_len();
        let tail_budget = bytes
            .checked_sub(head)
            .expect("the fixed documents are smaller than the boundary");
        let envelope = grpc_write_contribution(&grpc_write(scope, last, 0));
        // contribution(pad) is envelope + pad + a delimiter step or two, so the crossing is
        // at or just below this estimate.
        let estimate = tail_budget.saturating_sub(envelope);
        for pad in estimate.saturating_sub(64)..=estimate {
            let write = grpc_write(scope, last, pad);
            if head + grpc_write_contribution(&write) == bytes {
                let mut writes = fixed;
                writes.push(write);
                let request = pb::CommitRequest {
                    database: DB.to_owned(),
                    writes,
                    ..Default::default()
                };
                assert_eq!(request.encoded_len(), bytes, "the fixture must be exact");
                return request;
            }
        }
    }
    panic!("no fixture encodes {scope} to exactly {bytes} bytes");
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn gateway() -> Gateway {
    Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    }
}

async fn http(addr: std::net::SocketAddr, method: &str, path: &str, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    // Only the head is asserted on; a 10 MiB echo is never useful in a failure message.
    let text = String::from_utf8_lossy(&response).into_owned();
    text.chars().take(512).collect()
}

/// A readback that answers only whether the document exists.
async fn exists(addr: std::net::SocketAddr, name: &str) -> bool {
    let head = http(
        addr,
        "GET",
        &format!("/v1/projects/demo-app/databases/(default)/documents/req/{name}"),
        "",
    )
    .await;
    assert!(
        head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.1 404"),
        "{head}"
    );
    head.starts_with("HTTP/1.1 200")
}

async fn boundary_cases() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = Arc::new(LocalBackend::new(
        gateway(),
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    ));
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway()),
        rules: None,
        app_check: None,
        control_token: None,
    });
    let server = tokio::spawn(serve_multiplexed(
        listener,
        FirestoreServer::new(GatewayService::local(gateway(), backend))
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        rest,
    ));

    // REST: the inclusive maximum is accepted.
    let accepted = http(
        addr,
        "POST",
        COMMIT,
        &rest_commit_of(API_REQUEST_BYTES, "rest-at"),
    )
    .await;
    assert!(accepted.starts_with("HTTP/1.1 200"), "{accepted}");
    assert!(exists(addr, "rest-at-0").await);
    assert!(exists(addr, &format!("rest-at-{}", DOCUMENTS - 1)).await);

    // REST: one more byte is refused at the transport, before any write is applied.
    let refused = http(
        addr,
        "POST",
        COMMIT,
        &rest_commit_of(API_REQUEST_BYTES + 1, "rest-over"),
    )
    .await;
    assert!(refused.starts_with("HTTP/1.1 413"), "{refused}");
    assert!(refused.contains("request body too large"), "{refused}");
    assert!(refused.contains("INVALID_ARGUMENT"), "{refused}");
    for index in 0..DOCUMENTS {
        assert!(
            !exists(addr, &format!("rest-over-{index}")).await,
            "the refused request must publish nothing"
        );
    }

    // gRPC: the same boundary pair on a protobuf message.
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = FirestoreClient::new(channel)
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(API_REQUEST_BYTES + 1);

    let at = grpc_commit_of(API_REQUEST_BYTES, "grpc-at");
    assert_eq!(at.encoded_len(), API_REQUEST_BYTES);
    client
        .commit(at)
        .await
        .expect("the inclusive maximum is accepted");
    assert!(exists(addr, "grpc-at-0").await);

    let over = grpc_commit_of(API_REQUEST_BYTES + 1, "grpc-over");
    assert_eq!(over.encoded_len(), API_REQUEST_BYTES + 1);
    let error = client.commit(over).await.unwrap_err();
    // tonic refuses the message before prost decodes it, and names both byte counts.
    assert_eq!(error.code(), tonic::Code::OutOfRange, "{}", error.message());
    assert_eq!(
        error.message(),
        format!(
            "Error, decoded message length too large: found {} bytes, the limit is: {} bytes",
            API_REQUEST_BYTES + 1,
            API_REQUEST_BYTES
        )
    );
    for index in 0..DOCUMENTS {
        assert!(
            !exists(addr, &format!("grpc-over-{index}")).await,
            "the refused message must publish nothing"
        );
    }

    // WebChannel: the same bound on a form body. The exact maximum is read and handed to the
    // channel, which then answers on its own merits; one more byte never reaches it.
    let at_maximum = http(addr, "POST", CHANNEL, &"x".repeat(API_REQUEST_BYTES)).await;
    assert!(
        !at_maximum.starts_with("HTTP/1.1 413"),
        "the inclusive maximum must reach the channel: {at_maximum}"
    );
    let over = http(addr, "POST", CHANNEL, &"x".repeat(API_REQUEST_BYTES + 1)).await;
    assert!(over.starts_with("HTTP/1.1 413"), "{over}");
    assert!(over.contains("request body too large"), "{over}");

    // The daemon survives both refusals.
    let ready = http(addr, "GET", "/", "").await;
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");

    server.abort();
    let _ = server.await;
}

#[test]
fn the_api_request_boundary_is_refused_at_the_transport_and_the_daemon_survives() {
    std::thread::Builder::new()
        .name("request-bytes".to_owned())
        .stack_size(4 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(boundary_cases());
        })
        .unwrap()
        .join()
        .unwrap();
}
