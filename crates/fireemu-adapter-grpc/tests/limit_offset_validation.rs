//! Recorded limit and offset validation over REST and gRPC.

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
fn recorded_limit_offset_errors_rest_and_grpc() {
    let (fixture, order) = fireemu_adapter_grpc::rest::json_syntax::parse_with_key_order(
        include_bytes!("limit_offset_validation.json"),
    )
    .unwrap();
    let rows = fixture.as_array().unwrap();
    assert_eq!(rows.len(), 6);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut failures = Vec::new();
    for strict in [true, false] {
        for (index, row) in rows.iter().enumerate() {
            let s = state(strict);
            let body: Value = serde_json::from_str(&row["body"].to_string()).unwrap();
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
            let expected = &row["production"]["body"][0]["error"];
            if error.code() != tonic::Code::InvalidArgument
                || error.message() != expected["message"].as_str().unwrap()
                || fireemu_adapter_grpc::production_status::details_to_json(error.details())
                    != expected.get("details").and_then(Value::as_array).cloned()
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

#[test]
#[allow(clippy::too_many_lines)]
fn count_pict_routes_cover_profiles_contexts_and_input_states() {
    let mut checked = 0;
    for line in include_str!("limit_offset.generated.tsv").lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        let [stage, profile, argument, context, input] = cols.as_slice() else {
            panic!("bad PICT row {line}")
        };
        let strict = *profile == "strict";
        let s = state(strict);
        if *input == "seeded" {
            let seed = s.handle(&RestRequest {
                method: "PATCH".into(),
                path: "/v1/projects/demo-app/databases/(default)/documents/so5/d".into(),
                query: String::new(),
                authorization: Some("Bearer owner".into()),
                origin: None,
                remote_peer: false,
                browser_metadata: false,
                app_check: Vec::new(),
                body: serde_json::json!({"fields":{"n":{"integerValue":"1"}}}),
                batch_field_order: Vec::new(),
                key_order: fireemu_adapter_grpc::rest::json_syntax::KeyOrder::default(),
            });
            assert_eq!(seed.status, 200, "{line}");
        }
        let value = match *argument {
            "zero" => serde_json::json!({"integerValue":"0"}),
            "large" => serde_json::json!({"integerValue":"5000000000"}),
            "negative" => serde_json::json!({"integerValue":"-1"}),
            "string" => serde_json::json!({"stringValue":"x"}),
            "boolean" => serde_json::json!({"booleanValue":true}),
            "double" => serde_json::json!({"doubleValue":1.5}),
            "null" => serde_json::json!({"nullValue":null}),
            "map" => serde_json::json!({"mapValue":{"fields":{}}}),
            _ => panic!("bad argument {line}"),
        };
        let mut stages = vec![
            serde_json::json!({"name":"collection","args":[{"referenceValue":"/so5"}]}),
            serde_json::json!({"name":stage,"args":[value]}),
        ];
        if *context == "mixed" {
            stages.push(serde_json::json!({"name":"unobserved_stage","args":[]}));
        }
        let body = serde_json::json!({"structuredPipeline":{"pipeline":{"stages":stages}}});
        let response = s.handle(&RestRequest {
            method: "POST".into(),
            path: "/v1/projects/demo-app/databases/(default)/documents:executePipeline".into(),
            query: String::new(),
            authorization: Some("Bearer owner".into()),
            origin: None,
            remote_peer: false,
            browser_metadata: false,
            app_check: Vec::new(),
            body,
            batch_field_order: Vec::new(),
            key_order: fireemu_adapter_grpc::rest::json_syntax::KeyOrder::default(),
        });
        let valid = matches!(*argument, "zero" | "large");
        let wanted = if *context == "mixed" {
            if strict {
                501
            } else {
                400
            }
        } else if valid {
            200
        } else if strict && *stage == "offset" && matches!(*argument, "double" | "null" | "map") {
            501
        } else {
            400
        };
        assert_eq!(response.status, wanted, "{line}: {}", response.body);
        if wanted == 200 {
            let count: usize = response
                .body
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|r| r.get("results").and_then(Value::as_array))
                .map(Vec::len)
                .sum();
            let expected = usize::from(
                !(*input == "empty"
                    || (*stage == "limit" && *argument == "zero")
                    || (*stage == "offset" && *argument == "large")),
            );
            assert_eq!(count, expected, "{line}");
            for row in response
                .body
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|part| part["results"].as_array().into_iter().flatten())
            {
                assert!(row["name"].as_str().unwrap().ends_with("/so5/d"), "{line}");
                assert_eq!(row["fields"]["n"]["integerValue"], "1", "{line}");
                assert!(
                    row["createTime"].is_string() && row["updateTime"].is_string(),
                    "{line}"
                );
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 24);
}

#[test]
fn unrecorded_count_arity_keeps_profile_refusal() {
    for strict in [true, false] {
        for name in ["limit", "offset"] {
            for args in [
                vec![],
                vec![
                    serde_json::json!({"integerValue":"1"}),
                    serde_json::json!({"integerValue":"2"}),
                ],
            ] {
                let body = serde_json::json!({"structuredPipeline":{"pipeline":{"stages":[{"name":"collection","args":[{"referenceValue":"/so5"}]},{"name":name,"args":args}]}}});
                let response = state(strict).handle(&RestRequest {
                    method: "POST".into(),
                    path: "/v1/projects/demo-app/databases/(default)/documents:executePipeline"
                        .into(),
                    query: String::new(),
                    authorization: Some("Bearer owner".into()),
                    origin: None,
                    remote_peer: false,
                    browser_metadata: false,
                    app_check: Vec::new(),
                    body,
                    batch_field_order: Vec::new(),
                    key_order: fireemu_adapter_grpc::rest::json_syntax::KeyOrder::default(),
                });
                assert_eq!(
                    response.status,
                    if strict { 501 } else { 400 },
                    "{name} strict={strict}: {}",
                    response.body
                );
            }
        }
    }
}
