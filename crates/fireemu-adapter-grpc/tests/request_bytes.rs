//! `FS-LIMIT-API-REQUEST-BYTES`: transport payload boundaries at each Firestore protocol's
//! decode boundary. The normal REST and `WebChannel` profiles retain the 10 MiB inclusive
//! raw-body bound; the strict REST `:commit` route has a production-observed 11 MiB raw guard.
//! Production also accepts REST Commit requests whose decoded protobuf exceeds 10 MiB.
//!
//! The limit is measured on the message payload before protocol decode, so it is refused
//! without an oversized raw request being parsed or held whole in memory: REST and
//! `WebChannel` bodies come through a bounded stream
//! (`fireemu_adapter_support::body::collect_limited`) and a gRPC message is refused by tonic
//! before prost sees it. Both profiles refuse it, because it is a transport bound rather
//! than a document rule and it is already in force.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_grpc::serve::{
    serve_multiplexed, serve_multiplexed_with, API_REQUEST_BYTES, MAX_GRPC_MESSAGE_BYTES,
    MAX_REST_BODY_BYTES, MAX_STRICT_COMMIT_RAW_BYTES,
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

/// Writes whose enclosing message, measured by `envelope`, encodes to exactly `bytes`.
///
/// Padding a string also lengthens the length delimiter of every message enclosing it, so a
/// single correction overshoots and some totals are unreachable by one payload alone. The
/// fixed documents are measured once, the last document's payload is searched for the exact
/// crossing, and the first document absorbs a byte at a time when a delimiter step jumps over
/// the target.
fn grpc_writes_of(
    bytes: usize,
    scope: &str,
    envelope: impl Fn(&[pb::Write]) -> usize,
) -> Vec<pb::Write> {
    let last = DOCUMENTS - 1;
    for bump in 0..16usize {
        let fixed: Vec<pb::Write> = (0..last)
            .map(|index| grpc_write(scope, index, FIXED_PAYLOAD + usize::from(index == 0) * bump))
            .collect();
        let head = envelope(&fixed);
        let Some(tail_budget) = bytes.checked_sub(head) else {
            continue;
        };
        let estimate =
            tail_budget.saturating_sub(grpc_write_contribution(&grpc_write(scope, last, 0)));
        for pad in estimate.saturating_sub(64)..=estimate {
            let write = grpc_write(scope, last, pad);
            if head + grpc_write_contribution(&write) == bytes {
                let mut writes = fixed;
                writes.push(write);
                assert_eq!(envelope(&writes), bytes, "the fixture must be exact");
                return writes;
            }
        }
    }
    panic!("no fixture encodes {scope} to exactly {bytes} bytes");
}

/// A `CommitRequest` whose protobuf encoding is exactly `bytes` long.
fn grpc_commit_of(bytes: usize, scope: &str) -> pb::CommitRequest {
    let build = |writes: Vec<pb::Write>| pb::CommitRequest {
        database: DB.to_owned(),
        writes,
        ..Default::default()
    };
    let writes = grpc_writes_of(bytes, scope, |w| build(w.to_vec()).encoded_len());
    build(writes)
}

/// A streaming `WriteRequest` whose protobuf encoding is exactly `bytes` long.
fn grpc_write_request_of(bytes: usize, scope: &str, stream_token: &[u8]) -> pb::WriteRequest {
    let build = |writes: Vec<pb::Write>| pb::WriteRequest {
        stream_token: stream_token.to_vec(),
        writes,
        ..Default::default()
    };
    let writes = grpc_writes_of(bytes, scope, |w| build(w.to_vec()).encoded_len());
    build(writes)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn gateway(enforce_limits: bool) -> Gateway {
    Gateway {
        enforce_limits,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: if enforce_limits {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    }
}

/// The refusal each profile answers for a request over the boundary.
///
/// The boundary is the same under both. Only the shape differs: the strict profile answers
/// the documented production shape on every transport, the emulator profile keeps the 413 and
/// tonic's own `OUT_OF_RANGE` that the local runtime has always answered. Neither is a
/// production observation.
struct ExpectedRefusal {
    http_status: &'static str,
    http_message: String,
    grpc_code: tonic::Code,
    grpc_message: String,
}

fn expected_refusal(enforce_limits: bool) -> ExpectedRefusal {
    let production_shape =
        format!("Request payload size exceeds the limit: {API_REQUEST_BYTES} bytes.");
    if enforce_limits {
        ExpectedRefusal {
            http_status: "HTTP/1.1 400",
            http_message: production_shape.clone(),
            grpc_code: tonic::Code::InvalidArgument,
            grpc_message: production_shape,
        }
    } else {
        ExpectedRefusal {
            http_status: "HTTP/1.1 413",
            http_message: "request body too large".to_owned(),
            grpc_code: tonic::Code::OutOfRange,
            grpc_message: format!(
                "Error, decoded message length too large: found {} bytes, the limit is: {} bytes",
                API_REQUEST_BYTES + 1,
                API_REQUEST_BYTES
            ),
        }
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

/// REST `:commit`: the inclusive maximum writes twelve documents, one more byte is refused
/// before any write is applied.
async fn rest_boundary(addr: std::net::SocketAddr, expected: &ExpectedRefusal) {
    if expected.http_status == "HTTP/1.1 400" {
        assert_eq!(MAX_STRICT_COMMIT_RAW_BYTES, 11 * 1024 * 1024);
        let compact = r#"{"writes":[]}"#;
        let accepted_body = format!(
            "{}{}",
            compact,
            " ".repeat(MAX_STRICT_COMMIT_RAW_BYTES - compact.len())
        );
        let accepted = http(addr, "POST", COMMIT, &accepted_body).await;
        assert!(accepted.starts_with("HTTP/1.1 200"), "{accepted}");
        let decoded_over = http(
            addr,
            "POST",
            COMMIT,
            &rest_commit_of(MAX_STRICT_COMMIT_RAW_BYTES, "decoded-over"),
        )
        .await;
        assert!(decoded_over.starts_with("HTTP/1.1 200"), "{decoded_over}");
        assert!(exists(addr, "decoded-over-0").await);
        assert!(exists(addr, &format!("decoded-over-{}", DOCUMENTS - 1)).await);
        let refused_body = format!(
            "{}{}",
            compact,
            " ".repeat(MAX_STRICT_COMMIT_RAW_BYTES + 1 - compact.len())
        );
        let refused = http(addr, "POST", COMMIT, &refused_body).await;
        assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
        assert!(refused.contains("Request payload size exceeds the limit: 11534336 bytes."));
        let sentinel = format!(
            "{}{}",
            compact,
            " ".repeat(16 * 1024 * 1024 + 1 - compact.len())
        );
        let refused_sentinel = http(addr, "POST", COMMIT, &sentinel).await;
        assert!(
            refused_sentinel.starts_with("HTTP/1.1 400"),
            "{refused_sentinel}"
        );
        return;
    }
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

    let refused = http(
        addr,
        "POST",
        COMMIT,
        &rest_commit_of(API_REQUEST_BYTES + 1, "rest-over"),
    )
    .await;
    assert!(refused.starts_with(expected.http_status), "{refused}");
    assert!(refused.contains(&expected.http_message), "{refused}");
    assert!(refused.contains("INVALID_ARGUMENT"), "{refused}");
    assert_nothing_published(addr, "rest-over").await;
}

/// gRPC unary `Commit`: tonic refuses the over-boundary message before prost decodes it.
async fn grpc_unary_boundary(
    addr: std::net::SocketAddr,
    client: &mut FirestoreClient<tonic::transport::Channel>,
    expected: &ExpectedRefusal,
) {
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
    assert_eq!(error.code(), expected.grpc_code, "{}", error.message());
    assert_eq!(error.message(), expected.grpc_message);
    assert_nothing_published(addr, "grpc-over").await;
}

/// The `Write` stream: tonic applies the same per-message bound to a streamed request, and
/// the status arrives in the trailers rather than the headers.
async fn write_stream_boundary(
    addr: std::net::SocketAddr,
    client: &mut FirestoreClient<tonic::transport::Channel>,
    expected: &ExpectedRefusal,
) {
    write_stream_case(client, API_REQUEST_BYTES, "stream-at")
        .await
        .expect("the inclusive maximum is accepted on the stream");
    assert!(exists(addr, "stream-at-0").await);

    let refused = write_stream_case(client, API_REQUEST_BYTES + 1, "stream-over")
        .await
        .expect_err("one more byte is refused on the stream");
    assert_eq!(refused.code(), expected.grpc_code, "{}", refused.message());
    assert_eq!(refused.message(), expected.grpc_message);
    assert_nothing_published(addr, "stream-over").await;
}

/// `WebChannel`: the exact maximum is read and handed to the channel, which then answers on its
/// own merits; one more byte never reaches it.
async fn webchannel_boundary(addr: std::net::SocketAddr, expected: &ExpectedRefusal) {
    let at_maximum = http(addr, "POST", CHANNEL, &"x".repeat(API_REQUEST_BYTES)).await;
    assert!(
        !at_maximum.starts_with("HTTP/1.1 413") && !at_maximum.starts_with("HTTP/1.1 400"),
        "the inclusive maximum must reach the channel: {at_maximum}"
    );
    let over = http(addr, "POST", CHANNEL, &"x".repeat(API_REQUEST_BYTES + 1)).await;
    assert!(over.starts_with(expected.http_status), "{over}");
    assert!(over.contains(&expected.http_message), "{over}");
}

/// Every document of a refused request is absent.
async fn assert_nothing_published(addr: std::net::SocketAddr, scope: &str) {
    for index in 0..DOCUMENTS {
        assert!(
            !exists(addr, &format!("{scope}-{index}")).await,
            "{scope}: the refused request must publish nothing"
        );
    }
}

async fn boundary_cases(enforce_limits: bool) {
    let expected = expected_refusal(enforce_limits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = Arc::new(LocalBackend::new(
        gateway(enforce_limits),
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    ));
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway(enforce_limits)),
        rules: None,
        app_check: None,
        control_token: None,
    });
    let server = tokio::spawn(serve_multiplexed(
        listener,
        FirestoreServer::new(GatewayService::local(gateway(enforce_limits), backend))
            .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        rest,
    ));

    rest_boundary(addr, &expected).await;

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    // The client must be allowed to encode one byte past the boundary so that the server is
    // the side that refuses it.
    let mut client = FirestoreClient::new(channel)
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_encoding_message_size(API_REQUEST_BYTES + 1);

    grpc_unary_boundary(addr, &mut client, &expected).await;
    write_stream_boundary(addr, &mut client, &expected).await;
    webchannel_boundary(addr, &expected).await;

    // The daemon survives every refusal.
    let ready = http(addr, "GET", "/", "").await;
    assert!(ready.starts_with("HTTP/1.1 200"), "{ready}");

    server.abort();
    let _ = server.await;
}

/// Opens a `Write` stream, hands it one request of exactly `bytes`, and reports what came
/// back. Each case gets its own stream: an error is terminal for the one it happened on.
async fn write_stream_case(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    bytes: usize,
    scope: &str,
) -> Result<(), tonic::Status> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut responses = client
        .write(tonic::Request::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
        .await?
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DB.to_owned(),
        ..Default::default()
    })
    .await
    .expect("the handshake is accepted");
    let handshake = tokio_stream::StreamExt::next(&mut responses)
        .await
        .expect("the handshake is answered")?;
    let request = grpc_write_request_of(bytes, scope, &handshake.stream_token);
    assert_eq!(request.encoded_len(), bytes, "the fixture must be exact");
    if tx.send(request).await.is_err() {
        // The server closed the stream before the request was queued; read the status.
        return match tokio_stream::StreamExt::next(&mut responses).await {
            Some(Err(status)) => Err(status),
            other => panic!("the stream closed without a status: {}", other.is_some()),
        };
    }
    match tokio_stream::StreamExt::next(&mut responses).await {
        Some(Ok(_)) => Ok(()),
        Some(Err(status)) => Err(status),
        None => Err(tonic::Status::unknown(
            "the stream ended without a response",
        )),
    }
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
                .block_on(boundary_cases(true));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn the_emulator_profile_keeps_its_own_over_boundary_refusal_shape() {
    std::thread::Builder::new()
        .name("request-bytes-emulator".to_owned())
        .stack_size(4 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(boundary_cases(false));
        })
        .unwrap()
        .join()
        .unwrap();
}

// ---------------------------------------------------------------------------
// The body-read deadline on the REST path, over a real socket
// ---------------------------------------------------------------------------

/// A client that announces a body and then stalls holds a permit. Without a deadline it holds
/// one until it disconnects, and enough of them stall every write surface. This drives a real
/// connection that promises 100 bytes and sends one.
async fn rest_deadline_case() {
    const DEADLINE: std::time::Duration = std::time::Duration::from_millis(300);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let backend = Arc::new(LocalBackend::new(
        gateway(true),
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    ));
    let rest = Arc::new(RestState {
        local: backend.clone(),
        gateway: Arc::new(gateway(true)),
        rules: None,
        app_check: None,
        control_token: None,
    });
    let server = tokio::spawn(serve_multiplexed_with(
        listener,
        FirestoreServer::new(GatewayService::local(gateway(true), backend)),
        rest,
        DEADLINE,
    ));

    // Promise 100 bytes, send one, then hold the connection open.
    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    stalled
        .write_all(
            format!(
                "POST {COMMIT} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    stalled.flush().await.unwrap();

    // While it stalls, an ordinary request is served rather than refused for load.
    let ready = http(addr, "GET", "/", "").await;
    assert!(
        ready.starts_with("HTTP/1.1 200"),
        "a stalled sender must not refuse anyone else: {ready}"
    );
    let control = format!(
        r#"{{"writes":[{{"update":{{"name":"{NAMES}/req/deadline-control","fields":{{"n":{{"integerValue":"1"}}}}}}}}]}}"#
    );
    let commit = http(addr, "POST", COMMIT, &control).await;
    assert!(
        !commit.starts_with("HTTP/1.1 503"),
        "a stalled sender must not exhaust the pool: {commit}"
    );

    // The stalled request itself ends at the deadline.
    let started = tokio::time::Instant::now();
    let mut answer = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        stalled.read_to_end(&mut answer),
    )
    .await
    .expect("the deadline must end the read")
    .unwrap();
    let answer = String::from_utf8_lossy(&answer).into_owned();
    assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
    assert!(answer.contains("DEADLINE_EXCEEDED"), "{answer}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the answer must come from the deadline, not from the client giving up"
    );

    server.abort();
    let _ = server.await;
}

#[test]
fn a_stalled_rest_body_ends_at_the_deadline_without_refusing_anyone_else() {
    std::thread::Builder::new()
        .name("rest-body-deadline".to_owned())
        .stack_size(4 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(rest_deadline_case());
        })
        .unwrap()
        .join()
        .unwrap();
}
