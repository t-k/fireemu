//! Differential tests: the core pipeline executor against the `RunQuery` lowering
//! (`compile_supported`) it replaced, on the same documents and the same pipeline.

use super::*;
use proptest::prelude::*;
use std::collections::BTreeMap;
use tokio_stream::StreamExt;

const PARENT: &str = "projects/demo-app/databases/(default)/documents";

fn value(v: pb::value::ValueType) -> pb::Value {
    pb::Value {
        value_type: Some(v),
    }
}

fn scalar() -> impl Strategy<Value = pb::Value> {
    use pb::value::ValueType as V;
    prop_oneof![
        Just(V::NullValue(0)),
        any::<bool>().prop_map(V::BooleanValue),
        (-2_i64..3).prop_map(V::IntegerValue),
        prop_oneof![
            Just(f64::NAN),
            Just(f64::INFINITY),
            Just(f64::NEG_INFINITY),
            Just(-0.0),
            Just(0.0),
            Just(1.0),
            Just(2.5)
        ]
        .prop_map(V::DoubleValue),
        "[ab]{0,2}".prop_map(V::StringValue),
        prop::collection::vec(0_u8..2, 0..2).prop_map(V::BytesValue),
        "[ab]".prop_map(|id| V::ReferenceValue(format!("{PARENT}/refs/{id}"))),
        (0_i64..2, prop_oneof![Just(0), Just(1_000)]).prop_map(|(seconds, nanos)| {
            V::TimestampValue(prost_types::Timestamp { seconds, nanos })
        }),
    ]
    .prop_map(value)
}

/// One generated case: documents with an optional `f` and `g`, and the optional stages of
/// the finite subset.
#[derive(Debug, Clone)]
struct Case {
    docs: Vec<(Option<pb::Value>, Option<pb::Value>)>,
    literal: Option<pb::Value>,
    select: Option<Vec<(String, String)>>,
    offset: Option<i64>,
    limit: Option<i64>,
}

fn case() -> impl Strategy<Value = Case> {
    let field = prop_oneof![Just("f".to_owned()), Just("g".to_owned())];
    (
        prop::collection::vec(
            (prop::option::of(scalar()), prop::option::of(scalar())),
            0..8,
        ),
        prop::option::of(scalar()),
        prop::option::of(prop::collection::vec(("[xy]", field), 1..3)),
        prop::option::of(0_i64..10),
        prop::option::of(0_i64..10),
    )
        .prop_map(|(docs, literal, select, offset, limit)| Case {
            docs,
            literal,
            select,
            offset,
            limit,
        })
}

fn stage(name: &str, arg: pb::Value) -> pb::pipeline::Stage {
    pb::pipeline::Stage {
        name: name.to_owned(),
        args: vec![arg],
        ..Default::default()
    }
}

fn field_ref(path: &str) -> pb::Value {
    value(pb::value::ValueType::FieldReferenceValue(path.to_owned()))
}

/// The pipeline of a case; `prefix` reads `f` and `g` through a map (`m.f`), which the
/// lowering cannot express but must match its top-level answer.
fn pipeline(case: &Case, prefix: &str) -> pb::ExecutePipelineRequest {
    let mut stages = vec![stage(
        "collection",
        value(pb::value::ValueType::StringValue("/items".to_owned())),
    )];
    if let Some(literal) = &case.literal {
        stages.push(stage(
            "where",
            value(pb::value::ValueType::FunctionValue(pb::Function {
                name: "equal".to_owned(),
                args: vec![field_ref(&format!("{prefix}f")), literal.clone()],
                ..Default::default()
            })),
        ));
    }
    if let Some(aliases) = &case.select {
        stages.push(stage(
            "select",
            value(pb::value::ValueType::MapValue(pb::MapValue {
                fields: aliases
                    .iter()
                    .map(|(alias, source)| (alias.clone(), field_ref(&format!("{prefix}{source}"))))
                    .collect(),
            })),
        ));
    }
    if let Some(offset) = case.offset {
        stages.push(stage(
            "offset",
            value(pb::value::ValueType::IntegerValue(offset)),
        ));
    }
    if let Some(limit) = case.limit {
        stages.push(stage(
            "limit",
            value(pb::value::ValueType::IntegerValue(limit)),
        ));
    }
    pb::ExecutePipelineRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline { stages }),
                    ..Default::default()
                },
            ),
        ),
        ..Default::default()
    }
}

fn seed(backend: &LocalBackend, case: &Case) {
    let writes = case
        .docs
        .iter()
        .enumerate()
        .map(|(index, (f, g))| {
            let mut fields = std::collections::HashMap::new();
            let mut nested = std::collections::HashMap::new();
            for (name, v) in [("f", f), ("g", g)] {
                if let Some(v) = v {
                    fields.insert(name.to_owned(), v.clone());
                    nested.insert(name.to_owned(), v.clone());
                }
            }
            fields.insert(
                "m".to_owned(),
                value(pb::value::ValueType::MapValue(pb::MapValue {
                    fields: nested,
                })),
            );
            pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{PARENT}/items/{index:03}"),
                    fields,
                    ..Default::default()
                })),
                ..Default::default()
            }
        })
        .collect::<Vec<_>>();
    if !writes.is_empty() {
        backend
            .commit(&pb::CommitRequest {
                database: "projects/demo-app/databases/(default)".to_owned(),
                writes,
                ..Default::default()
            })
            .unwrap();
    }
}

/// Result fields in a comparable form: the decoded value's debug text keeps `NaN`, `-0.0`
/// and the integer/double distinction, and orders map keys (wire maps are unordered).
type Fields = BTreeMap<String, String>;

fn comparable(document: &pb::Document) -> Fields {
    document
        .fields
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                format!("{:?}", crate::decode::decode_value(v).unwrap()),
            )
        })
        .collect()
}

async fn executor(service: &GatewayService, request: pb::ExecutePipelineRequest) -> Vec<Fields> {
    let mut stream = Firestore::execute_pipeline(service, Request::new(request))
        .await
        .unwrap()
        .into_inner();
    let mut out = Vec::new();
    while let Some(response) = stream.next().await {
        out.extend(response.unwrap().results.iter().map(comparable));
    }
    out
}

async fn lowering(service: &GatewayService, request: &pb::ExecutePipelineRequest) -> Vec<Fields> {
    let parent = crate::decode::parse_parent(PARENT).unwrap();
    let compiled = crate::pipeline::compile_supported(request, &parent).unwrap();
    let mut query = compiled.query;
    if compiled.limit.is_some_and(|limit| limit > i32::MAX as u32) {
        if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
            query.query_type.as_mut()
        {
            query.limit = None;
        }
    }
    let mut stream = Firestore::run_query(service, Request::new(query))
        .await
        .unwrap()
        .into_inner();
    let mut out = Vec::new();
    while let Some(response) = stream.next().await {
        if let Some(document) = response.unwrap().document {
            out.push(comparable(&crate::pipeline::project_document(
                document,
                &compiled.projection,
            )));
        }
    }
    if let Some(limit) = compiled.limit {
        out.truncate(limit as usize);
    }
    out
}

fn service_for(case: &Case) -> GatewayService {
    let backend = test_backend();
    seed(&backend, case);
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    GatewayService::local(gateway, backend)
}

/// Every document also carries its `f` and `g` inside the map `m`, so a pipeline reading
/// `m.f` must answer exactly what the lowering answers for `f`.
#[tokio::test]
async fn executor_matches_the_lowering_on_a_fixed_case() {
    let case = Case {
        docs: vec![
            (Some(value(pb::value::ValueType::IntegerValue(1))), None),
            (
                Some(value(pb::value::ValueType::DoubleValue(1.0))),
                Some(value(pb::value::ValueType::NullValue(0))),
            ),
            (None, Some(value(pb::value::ValueType::IntegerValue(1)))),
            (
                Some(value(pb::value::ValueType::DoubleValue(f64::NAN))),
                None,
            ),
        ],
        literal: Some(value(pb::value::ValueType::IntegerValue(1))),
        select: Some(vec![
            ("x".to_owned(), "f".to_owned()),
            ("y".to_owned(), "g".to_owned()),
        ]),
        offset: Some(1),
        limit: Some(5),
    };
    let service = service_for(&case);
    let expected = lowering(&service, &pipeline(&case, "")).await;
    assert_eq!(expected.len(), 1);
    assert_eq!(executor(&service, pipeline(&case, "")).await, expected);
    assert_eq!(executor(&service, pipeline(&case, "m.")).await, expected);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn executor_matches_the_lowering(case in case()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let service = service_for(&case);
        let (expected, top, nested) = runtime.block_on(async {
            let expected = lowering(&service, &pipeline(&case, "")).await;
            let top = executor(&service, pipeline(&case, "")).await;
            let nested = executor(&service, pipeline(&case, "m.")).await;
            (expected, top, nested)
        });
        prop_assert_eq!(&top, &expected);
        // Read through the map `m`, the same values give the same answer.
        prop_assert_eq!(&nested, &expected);
    }
}
