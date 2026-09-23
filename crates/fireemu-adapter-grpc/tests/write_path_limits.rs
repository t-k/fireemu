//! `FS-LIMIT-FIELD-VALUE-BYTES` and `FS-LIMIT-FIELD-PATH-BYTES` on every write surface:
//! REST `commit`, REST `batchWrite`, the gRPC unary `Commit` and the gRPC `Write` stream.
//!
//! A `Commit` is atomic, so an over-limit write refuses the whole request and publishes
//! nothing. A `BatchWrite` is not, so the refusal is one entry in the per-write `status`
//! vector and its siblings still publish, which is what production does.
//!
//! The aggregate-value rule is strict-only: the `emulator` profile may not gain a refusal.
//! The field-path rule already applied under both profiles and still does.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use serde_json::{json, Value};

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";
const NAMES: &str = "projects/demo-app/databases/(default)/documents";

/// The inclusive maximum of `FS-LIMIT-FIELD-VALUE-BYTES`.
const FIELD_VALUE_MAXIMUM: usize = 1_048_487;
/// The string payload of a one-entry map whose aggregate storage size is `total`:
/// `string_size("s") + string_size(payload)`.
const fn map_payload(total: usize) -> usize {
    total - 3
}

const OVER_VALUE: &str = "The value of property \"v\" is longer than 1048487 bytes.";

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

fn backend(enforce_limits: bool) -> Arc<LocalBackend> {
    Arc::new(LocalBackend::new(
        gateway(enforce_limits),
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    ))
}

fn state(enforce_limits: bool) -> RestState {
    RestState {
        local: backend(enforce_limits),
        gateway: Arc::new(gateway(enforce_limits)),
        rules: None,
        app_check: None,
        control_token: None,
    }
}

fn call(s: &RestState, method: &str, path: &str, body: Value) -> (u16, Value) {
    let r = s.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        app_check: Vec::new(),
        body,
        origin: None,
        browser_metadata: false,
    });
    (r.status, r.body)
}

/// A JSON `mapValue` whose aggregate storage size is exactly `total` bytes.
fn aggregate_map_json(total: usize) -> Value {
    json!({"mapValue": {"fields": {"s": {"stringValue": "x".repeat(map_payload(total))}}}})
}

/// The core value behind [`aggregate_map_json`], for the protobuf surfaces.
fn aggregate_map_pb(total: usize) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::MapValue(pb::MapValue {
            fields: [(
                "s".to_owned(),
                pb::Value {
                    value_type: Some(pb::value::ValueType::StringValue(
                        "x".repeat(map_payload(total)),
                    )),
                },
            )]
            .into_iter()
            .collect(),
        })),
    }
}

/// A field whose canonical path is `bytes` long: 14 segments of 100 bytes plus one of
/// `bytes - 1414`, joined by 14 separators.
fn nested_path_json(bytes: usize) -> (String, Value) {
    let mut lengths = vec![100usize; 14];
    lengths.push(bytes - 1414);
    let names: Vec<String> = lengths
        .iter()
        .enumerate()
        .map(|(index, len)| {
            let mut name = String::from(char::from(b'a' + u8::try_from(index).unwrap()));
            name.push_str(&"z".repeat(len - 1));
            name
        })
        .collect();
    let mut value = json!({"integerValue": "1"});
    for name in names.iter().skip(1).rev() {
        value = json!({"mapValue": {"fields": {name.clone(): value}}});
    }
    (names[0].clone(), value)
}

// ---------------------------------------------------------------------------
// REST commit
// ---------------------------------------------------------------------------

#[test]
fn a_rest_commit_accepts_the_aggregate_value_boundary_and_refuses_one_more_byte() {
    let s = state(true);
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/exact"),
        json!({"fields": {"v": aggregate_map_json(FIELD_VALUE_MAXIMUM)}}),
    );
    assert_eq!(status, 200, "{}", body["error"]);

    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/over"),
        json!({"fields": {"v": aggregate_map_json(FIELD_VALUE_MAXIMUM + 1)}}),
    );
    assert_eq!(status, 400, "{}", body["error"]);
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    // Not the document-bytes message: this document is 1,048,550 logical bytes.
    assert_eq!(body["error"]["message"], OVER_VALUE);

    let (status, missing) = call(&s, "GET", &format!("{DOCS}/limits/over"), Value::Null);
    assert_eq!(status, 404, "{missing}");
}

#[test]
fn a_rest_commit_over_the_aggregate_value_boundary_publishes_none_of_its_writes() {
    let s = state(true);
    let (status, _) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/atomic/control"),
        json!({"fields": {"n": {"integerValue": "1"}}}),
    );
    assert_eq!(status, 200);

    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [
            {"update": {"name": format!("{NAMES}/atomic/control"),
                        "fields": {"n": {"integerValue": "2"}}}},
            {"update": {"name": format!("{NAMES}/atomic/over"),
                        "fields": {"v": aggregate_map_json(FIELD_VALUE_MAXIMUM + 1)}}},
            {"update": {"name": format!("{NAMES}/atomic/after"),
                        "fields": {"n": {"integerValue": "3"}}}}
        ]}),
    );
    assert_eq!(status, 400, "{}", body["error"]);
    assert_eq!(body["error"]["message"], OVER_VALUE);

    let (_, control) = call(&s, "GET", &format!("{DOCS}/atomic/control"), Value::Null);
    assert_eq!(
        control["fields"]["n"]["integerValue"], "1",
        "the sibling write must not publish"
    );
    for name in ["over", "after"] {
        let (status, _) = call(&s, "GET", &format!("{DOCS}/atomic/{name}"), Value::Null);
        assert_eq!(status, 404, "{name}");
    }
}

#[test]
fn a_rest_batch_write_reports_the_refusal_per_item_and_still_publishes_its_siblings() {
    let s = state(true);
    let (status, body) = call(
        &s,
        "POST",
        &format!("{DOCS}:batchWrite"),
        json!({"writes": [
            {"update": {"name": format!("{NAMES}/batch/ok-first"),
                        "fields": {"n": {"integerValue": "1"}}}},
            {"update": {"name": format!("{NAMES}/batch/over"),
                        "fields": {"v": aggregate_map_json(FIELD_VALUE_MAXIMUM + 1)}}},
            {"update": {"name": format!("{NAMES}/batch/ok-last"),
                        "fields": {"n": {"integerValue": "2"}}}}
        ]}),
    );
    assert_eq!(status, 200, "{}", body["error"]);
    assert_eq!(
        body["status"],
        json!([{}, {"code": 3, "message": OVER_VALUE}, {}]),
        "per-write status"
    );
    assert_eq!(body["writeResults"].as_array().unwrap().len(), 3);

    for name in ["ok-first", "ok-last"] {
        let (status, _) = call(&s, "GET", &format!("{DOCS}/batch/{name}"), Value::Null);
        assert_eq!(status, 200, "{name} must publish");
    }
    let (status, _) = call(&s, "GET", &format!("{DOCS}/batch/over"), Value::Null);
    assert_eq!(status, 404, "the refused entry must publish nothing");
}

#[test]
fn the_emulator_profile_gains_no_aggregate_value_refusal_over_rest() {
    let s = state(false);
    let (status, body) = call(
        &s,
        "PATCH",
        &format!("{DOCS}/limits/over"),
        json!({"fields": {"v": aggregate_map_json(FIELD_VALUE_MAXIMUM + 1)}}),
    );
    assert_eq!(status, 200, "{}", body["error"]);
    let (status, stored) = call(&s, "GET", &format!("{DOCS}/limits/over"), Value::Null);
    assert_eq!(status, 200, "{stored}");
}

// ---------------------------------------------------------------------------
// REST field path
// ---------------------------------------------------------------------------

#[test]
fn a_rest_commit_accepts_the_field_path_boundary_and_refuses_one_more_byte_in_both_profiles() {
    for enforce_limits in [true, false] {
        let s = state(enforce_limits);
        let (name, value) = nested_path_json(1_500);
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/paths/exact"),
            json!({"fields": {name: value}}),
        );
        assert_eq!(status, 200, "{enforce_limits}: {}", body["error"]);

        let (name, value) = nested_path_json(1_501);
        let (status, body) = call(
            &s,
            "PATCH",
            &format!("{DOCS}/paths/over"),
            json!({"fields": {name: value}}),
        );
        assert_eq!(status, 400, "{enforce_limits}: {}", body["error"]);
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
        let message = body["error"]["message"].as_str().expect("error message");
        assert!(
            message.starts_with("Property ") && message.len() == 400,
            "{enforce_limits}: {message}"
        );

        let (status, _) = call(&s, "GET", &format!("{DOCS}/paths/over"), Value::Null);
        assert_eq!(status, 404, "{enforce_limits}");
    }
}

// ---------------------------------------------------------------------------
// gRPC unary Commit and the Write stream
// ---------------------------------------------------------------------------

async fn start(
    enforce_limits: bool,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = GatewayService::local(gateway(enforce_limits), backend(enforce_limits));
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(
                FirestoreServer::new(service)
                    .max_decoding_message_size(10 * 1024 * 1024)
                    .max_encoding_message_size(10 * 1024 * 1024),
            )
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (
        FirestoreClient::new(channel)
            .max_decoding_message_size(10 * 1024 * 1024)
            .max_encoding_message_size(10 * 1024 * 1024),
        server,
    )
}

fn document(name: &str, total: usize) -> pb::Document {
    pb::Document {
        name: format!("{NAMES}/{name}"),
        fields: [("v".to_owned(), aggregate_map_pb(total))]
            .into_iter()
            .collect(),
        ..Default::default()
    }
}

fn write(name: &str, total: usize) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(document(name, total))),
        ..Default::default()
    }
}

async fn grpc_cases() {
    let (mut client, server) = start(true).await;

    client
        .commit(pb::CommitRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            writes: vec![write("grpc/exact", FIELD_VALUE_MAXIMUM)],
            ..Default::default()
        })
        .await
        .expect("the inclusive maximum is accepted");

    let refused = client
        .commit(pb::CommitRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            writes: vec![write("grpc/over", FIELD_VALUE_MAXIMUM + 1)],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    assert_eq!(refused.message(), OVER_VALUE);

    let missing = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{NAMES}/grpc/over"),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    // The Write stream applies the same rule and keeps the stream usable afterwards.
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let mut responses = client
        .write(tonic::Request::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
        .await
        .unwrap()
        .into_inner();
    tx.send(pb::WriteRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    let handshake = tokio_stream::StreamExt::next(&mut responses)
        .await
        .unwrap()
        .unwrap();
    tx.send(pb::WriteRequest {
        stream_token: handshake.stream_token.clone(),
        writes: vec![write("stream/over", FIELD_VALUE_MAXIMUM + 1)],
        ..Default::default()
    })
    .await
    .unwrap();
    let refused = tokio_stream::StreamExt::next(&mut responses)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::InvalidArgument);
    assert_eq!(refused.message(), OVER_VALUE);
    drop(tx);

    let missing = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{NAMES}/stream/over"),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    server.abort();
    let _ = server.await;
}

async fn grpc_emulator_profile_case() {
    let (mut client, server) = start(false).await;
    client
        .commit(pb::CommitRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            writes: vec![write("grpc/over", FIELD_VALUE_MAXIMUM + 1)],
            ..Default::default()
        })
        .await
        .expect("the emulator profile may not gain a refusal");
    server.abort();
    let _ = server.await;
}

#[test]
fn the_grpc_write_surfaces_apply_the_aggregate_value_boundary() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(grpc_cases());
}

#[test]
fn the_grpc_commit_gains_no_aggregate_value_refusal_under_the_emulator_profile() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(grpc_emulator_profile_case());
}
