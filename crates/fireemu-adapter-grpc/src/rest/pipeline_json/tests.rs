use super::*;
use pb::value::ValueType as V;
use proptest::prelude::*;

/// The JSON form of a pipeline value, as the Web SDK writes it (the inverse of
/// [`expression_from_json`]).
fn expression_to_json(value: &pb::Value) -> Value {
    match &value.value_type {
        Some(V::FieldReferenceValue(path)) => json!({"fieldReferenceValue": path}),
        Some(V::VariableReferenceValue(name)) => json!({"variableReferenceValue": name}),
        Some(V::FunctionValue(function)) => json!({"functionValue": {
            "name": function.name,
            "args": function.args.iter().map(expression_to_json).collect::<Vec<_>>(),
            "options": function.options.iter().map(|(k, v)| (k.clone(), expression_to_json(v))).collect::<Map<_, _>>(),
        }}),
        Some(V::PipelineValue(pipeline)) => json!({"pipelineValue": pipeline_to_json(pipeline)}),
        Some(V::ArrayValue(array)) => json!({"arrayValue": {
            "values": array.values.iter().map(expression_to_json).collect::<Vec<_>>(),
        }}),
        Some(V::MapValue(map)) => json!({"mapValue": {
            "fields": map.fields.iter().map(|(k, v)| (k.clone(), expression_to_json(v))).collect::<Map<_, _>>(),
        }}),
        _ => value_to_json(value),
    }
}

fn pipeline_to_json(pipeline: &pb::Pipeline) -> Value {
    json!({"stages": pipeline.stages.iter().map(|stage| json!({
        "name": stage.name,
        "args": stage.args.iter().map(expression_to_json).collect::<Vec<_>>(),
        "options": stage.options.iter().map(|(k, v)| (k.clone(), expression_to_json(v))).collect::<Map<_, _>>(),
    })).collect::<Vec<_>>()})
}

fn value(v: V) -> pb::Value {
    pb::Value {
        value_type: Some(v),
    }
}

fn scalar() -> impl Strategy<Value = pb::Value> {
    prop_oneof![
        Just(V::NullValue(0)),
        any::<bool>().prop_map(V::BooleanValue),
        any::<i64>().prop_map(V::IntegerValue),
        prop_oneof![Just(0.5), Just(-2.0), Just(f64::INFINITY), Just(1e300)]
            .prop_map(V::DoubleValue),
        "[a-z]{0,3}".prop_map(V::StringValue),
        prop::collection::vec(any::<u8>(), 0..4).prop_map(V::BytesValue),
        "[a-z]{1,2}".prop_map(|id| V::ReferenceValue(format!(
            "projects/p/databases/(default)/documents/c/{id}"
        ))),
        (0_i64..2_000_000_000, 0_i32..1_000_000_000).prop_map(
            |(seconds, nanos)| V::TimestampValue(prost_types::Timestamp { seconds, nanos })
        ),
        "[a-z]{1,3}(\\.[a-z]{1,2})?".prop_map(V::FieldReferenceValue),
        "[a-z]{1,3}".prop_map(V::VariableReferenceValue),
    ]
    .prop_map(value)
}

fn expression() -> impl Strategy<Value = pb::Value> {
    scalar().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            (
                "[a-z_]{1,8}",
                prop::collection::vec(inner.clone(), 0..3),
                prop::collection::hash_map("[a-z]{1,3}", inner.clone(), 0..2)
            )
                .prop_map(|(name, args, options)| value(V::FunctionValue(
                    pb::Function {
                        name,
                        args,
                        options
                    }
                ))),
            prop::collection::vec(inner.clone(), 0..3)
                .prop_map(|values| value(V::ArrayValue(pb::ArrayValue { values }))),
            prop::collection::hash_map("[a-z]{1,3}", inner.clone(), 0..3)
                .prop_map(|fields| value(V::MapValue(pb::MapValue { fields }))),
            prop::collection::vec(("[a-z_]{1,8}", prop::collection::vec(inner, 0..2)), 0..2)
                .prop_map(|stages| value(V::PipelineValue(pb::Pipeline {
                    stages: stages
                        .into_iter()
                        .map(|(name, args)| pb::pipeline::Stage {
                            name,
                            args,
                            options: std::collections::HashMap::default()
                        })
                        .collect(),
                }))),
        ]
    })
}

proptest! {
    #[test]
    fn expressions_round_trip_through_json(expr in expression()) {
        let encoded = expression_to_json(&expr);
        let decoded = expression_from_json(&encoded, 0).unwrap();
        prop_assert_eq!(decoded, expr);
    }

    #[test]
    fn requests_round_trip_through_json(stages in prop::collection::vec(("[a-z_]{1,8}", prop::collection::vec(expression(), 0..3)), 0..4), read_time in prop::option::of(0_i64..2_000_000_000), auto_commit in any::<bool>()) {
        let pipeline = pb::Pipeline {
            stages: stages.into_iter().map(|(name, args)| pb::pipeline::Stage { name, args, options: std::collections::HashMap::default() }).collect(),
        };
        let mut body = json!({
            "database": "projects/p/databases/(default)",
            "structuredPipeline": {"pipeline": pipeline_to_json(&pipeline), "options": {}},
            "autoCommitTransaction": auto_commit,
        });
        if let Some(seconds) = read_time {
            body["readTime"] = timestamp_to_json(&prost_types::Timestamp { seconds, nanos: 0 });
        }
        let request = request_from_json("projects/p/databases/(default)", &body).unwrap();
        prop_assert_eq!(request, pb::ExecutePipelineRequest {
            database: "projects/p/databases/(default)".to_owned(),
            pipeline_type: Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(pb::StructuredPipeline {
                pipeline: Some(pipeline),
                options: std::collections::HashMap::default(),
            })),
            consistency_selector: read_time.map(|seconds| pb::execute_pipeline_request::ConsistencySelector::ReadTime(prost_types::Timestamp { seconds, nanos: 0 })),
            auto_commit_transaction: auto_commit,
            request_options: None,
        });
    }
}

#[test]
fn the_web_sdk_request_decodes() {
    // As firebase 12.18.0 (firestore/lite) sends it.
    let body: Value = serde_json::from_str(r#"{"database":"projects/demo-app/databases/(default)","structuredPipeline":{"pipeline":{"stages":[{"name":"collection","options":{},"args":[{"referenceValue":"/nest"}]},{"name":"where","options":{},"args":[{"functionValue":{"name":"equal","args":[{"fieldReferenceValue":"profile.score"},{"integerValue":"7"}]}}]},{"name":"select","options":{},"args":[{"mapValue":{"fields":{"label":{"fieldReferenceValue":"name"}}}}]}]},"options":{}}}"#).unwrap();
    let request = request_from_json("projects/demo-app/databases/(default)", &body).unwrap();
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        request.pipeline_type
    else {
        panic!("{request:?}")
    };
    let stages = structured.pipeline.unwrap().stages;
    assert_eq!(
        stages.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["collection", "where", "select"]
    );
    assert_eq!(
        stages[0].args,
        vec![value(V::ReferenceValue("/nest".into()))]
    );
    assert_eq!(
        stages[1].args,
        vec![value(V::FunctionValue(pb::Function {
            name: "equal".into(),
            args: vec![
                value(V::FieldReferenceValue("profile.score".into())),
                value(V::IntegerValue(7))
            ],
            options: std::collections::HashMap::default(),
        }))]
    );
    assert_eq!(request.consistency_selector, None);
    assert!(!request.auto_commit_transaction);
}

#[test]
fn malformed_requests_are_refused() {
    let db = "projects/p/databases/(default)";
    for body in [
        json!({"bogus": 1}),
        json!({"database": "projects/q/databases/(default)"}),
        json!({"database": 7}),
        json!({"structuredPipeline": 1}),
        json!({"structuredPipeline": {"pipeline": 1}}),
        json!({"structuredPipeline": {"pipeline": {"stages": 1}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [1]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": 1}]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "x", "args": 1}]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "x", "options": []}]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "x", "args": [{"fieldReferenceValue": 1}]}]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "x", "args": [{"variableReferenceValue": 1}]}]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "x", "args": [{"functionValue": 1}]}]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "x", "args": [{"arrayValue": 1}]}]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "x", "args": [{"mapValue": 1}]}]}}}),
        json!({"structuredPipeline": {"pipeline": {"stages": [{"name": "x", "args": [{"integerValue": "x"}]}]}}}),
        json!({"transaction": "AAAA", "readTime": "2026-01-01T00:00:00Z"}),
        json!({"transaction": 1}),
        json!({"autoCommitTransaction": "yes"}),
    ] {
        assert!(request_from_json(db, &body).is_err(), "{body}");
    }
    // A nested container past the depth limit is refused, not decoded.
    let mut deep = json!({"integerValue": "1"});
    for _ in 0..=MAX_NESTING_DEPTH {
        deep = json!({"arrayValue": {"values": [deep]}});
    }
    assert!(expression_from_json(&deep, 0).is_err());
    let mut shallow = json!({"integerValue": "1"});
    for _ in 0..MAX_NESTING_DEPTH - 1 {
        shallow = json!({"arrayValue": {"values": [shallow]}});
    }
    assert!(expression_from_json(&shallow, 0).is_ok());
    // The selectors decode to their oneof arms; null keys are absent.
    let tx = request_from_json(db, &json!({"transaction": "AQI=", "readTime": null})).unwrap();
    assert_eq!(
        tx.consistency_selector,
        Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(vec![1, 2]))
    );
    let new = request_from_json(db, &json!({"newTransaction": {"readOnly": {}}})).unwrap();
    assert!(matches!(
        new.consistency_selector,
        Some(pb::execute_pipeline_request::ConsistencySelector::NewTransaction(_))
    ));
    let named =
        request_from_json(db, &json!({"database": db, "structuredPipeline": null})).unwrap();
    assert_eq!(named.pipeline_type, None);
    assert_eq!(named.database, db);
}

#[test]
fn responses_render_results_transaction_and_execution_time() {
    assert_eq!(
        response_to_json(&pb::ExecutePipelineResponse::default()),
        json!({})
    );
    let response = pb::ExecutePipelineResponse {
        transaction: vec![1, 2],
        results: vec![
            pb::Document {
                fields: [("a".to_owned(), value(V::IntegerValue(1)))]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
            pb::Document {
                name: "projects/p/databases/(default)/documents/c/d".into(),
                create_time: Some(prost_types::Timestamp {
                    seconds: 1,
                    nanos: 0,
                }),
                update_time: Some(prost_types::Timestamp {
                    seconds: 2,
                    nanos: 0,
                }),
                ..Default::default()
            },
        ],
        execution_time: Some(prost_types::Timestamp {
            seconds: 3,
            nanos: 0,
        }),
        ..Default::default()
    };
    assert_eq!(
        response_to_json(&response),
        json!({
            "transaction": "AQI=",
            "results": [
                {"fields": {"a": {"integerValue": "1"}}},
                {"name": "projects/p/databases/(default)/documents/c/d", "createTime": "1970-01-01T00:00:01Z", "updateTime": "1970-01-01T00:00:02Z"},
            ],
            "executionTime": "1970-01-01T00:00:03Z",
        })
    );
}
