//! Recorded document reference argument errors over REST and gRPC.

use fireemu_adapter_grpc::{
    gateway::Gateway,
    local::LocalBackend,
    rest::{RestRequest, RestState},
    service::GatewayService,
};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::{
    edition::{FirestoreApiMode, FirestoreEdition},
    time::LogicalInstant,
};
use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
use serde_json::Value;
use std::sync::{Arc, Mutex};

fn state(strict: bool) -> RestState {
    let gateway = Gateway {
        enforce_limits: strict,
        ctx: PlanningContext {
            edition: FirestoreEdition::Enterprise,
            api_mode: FirestoreApiMode::Native,
            policy: if strict {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), clock, 7)),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn recorded_document_reference_wrong_type_rest_and_grpc() {
    let (fixture, order) = fireemu_adapter_grpc::rest::json_syntax::parse_with_key_order(
        include_bytes!("document_reference_validation.json"),
    )
    .unwrap();
    let rows = fixture.as_array().unwrap();
    assert_eq!(rows.len(), 11);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut failures = Vec::new();
    for strict in [true, false] {
        for (index, row) in rows.iter().enumerate() {
            let s = state(strict);
            let body: Value = serde_json::from_str(
                &row["body"]
                    .to_string()
                    .replace("{docs}", "projects/demo-app/databases/(default)/documents"),
            )
            .unwrap();
            let collection = body["structuredPipeline"]["pipeline"]["stages"][0]["args"][0]
                ["referenceValue"]
                .as_str()
                .unwrap();
            let seeded = s.handle(&RestRequest {
                method: "PATCH".into(),
                path: format!(
                    "/v1/projects/demo-app/databases/(default)/documents{collection}/seed"
                ),
                query: String::new(),
                authorization: Some("Bearer owner".into()),
                origin: None,
                remote_peer: false,
                browser_metadata: false,
                app_check: Vec::new(),
                body: serde_json::json!({"fields":{"v":{"integerValue":"1"}}}),
                batch_field_order: Vec::new(),
                key_order: fireemu_adapter_grpc::rest::json_syntax::KeyOrder::default(),
            });
            assert_eq!(seeded.status, 200, "seed: {}", seeded.body);
            let response = s.handle(&RestRequest {
                method: "POST".into(),
                path: "/v1/projects/demo-app/databases/(default)/documents:executePipeline".into(),
                query: String::new(),
                authorization: Some("Bearer owner".into()),
                origin: None,
                remote_peer: false,
                browser_metadata: false,
                app_check: Vec::new(),
                body: body.clone(),
                batch_field_order: Vec::new(),
                key_order: order.rebased(&format!("/{index}/body"), ""),
            });
            if response.status != 400 || response.body != row["production"]["body"] {
                failures.push(format!(
                    "REST {} strict={strict}: {} {}",
                    row["id"], response.status, response.body
                ));
            }
            let request = fireemu_adapter_grpc::rest::pipeline_json::request_from_json(
                "projects/demo-app/databases/(default)",
                &body,
            )
            .unwrap();
            let service = GatewayService::local((*s.gateway).clone(), Arc::clone(&s.local));
            let result = runtime.block_on(async {
                use tokio_stream::StreamExt as _;
                let mut stream =
                    Firestore::execute_pipeline(&service, tonic::Request::new(request))
                        .await?
                        .into_inner();
                while let Some(response) = stream.next().await {
                    response?;
                }
                Ok::<(), tonic::Status>(())
            });
            let Err(error) = result else {
                failures.push(format!(
                    "gRPC {} strict={strict}: unexpectedly succeeded",
                    row["id"]
                ));
                continue;
            };
            if strict && row["id"] == "fs-ent-pipeline/o5/value-shapes#document-id-vector" {
                if error.code() != tonic::Code::Unimplemented {
                    failures.push(format!(
                        "gRPC {} strict vector must retain unordered-map refusal",
                        row["id"]
                    ));
                }
                continue;
            }
            let expected = &row["production"]["body"][0]["error"];
            if error.code() != tonic::Code::InvalidArgument
                || error.message() != expected["message"].as_str().unwrap()
                || fireemu_adapter_grpc::production_status::details_to_json(error.details())
                    != Some(expected["details"].as_array().unwrap().clone())
            {
                failures.push(format!(
                    "gRPC {} strict={strict}: {:?} {} {:?}",
                    row["id"],
                    error.code(),
                    error.message(),
                    fireemu_adapter_grpc::production_status::details_to_json(error.details())
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
