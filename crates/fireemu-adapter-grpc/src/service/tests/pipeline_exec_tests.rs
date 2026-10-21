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
        prop_oneof![Just((1.0, 2.0)), Just((1.0, 3.0))].prop_map(|(latitude, longitude)| {
            V::GeoPointValue(fireemu_proto_firestore::google::r#type::LatLng {
                latitude,
                longitude,
            })
        }),
        // Integers next to the doubles that round to them.
        prop_oneof![
            Just(V::IntegerValue(1 << 53)),
            Just(V::IntegerValue((1 << 53) + 1)),
            Just(V::IntegerValue(i64::MAX)),
            Just(V::DoubleValue(9_007_199_254_740_992.0)),
            Just(V::DoubleValue(9.223_372_036_854_776e18)),
        ],
    ]
    .prop_map(value)
}

/// A stored value: a scalar, or an array or map of scalars (literals stay scalar).
fn stored() -> impl Strategy<Value = pb::Value> {
    prop_oneof![
        4 => scalar(),
        1 => prop::collection::vec(scalar(), 0..3)
            .prop_map(|values| value(pb::value::ValueType::ArrayValue(pb::ArrayValue { values }))),
        1 => scalar().prop_map(|v| value(pb::value::ValueType::MapValue(pb::MapValue {
            fields: [("x".to_owned(), v)].into_iter().collect(),
        }))),
    ]
}

/// One generated case: documents with an optional `f` and `g`, and the optional stages of
/// the finite subset.
#[derive(Debug, Clone)]
struct Case {
    docs: Vec<(Option<pb::Value>, Option<pb::Value>)>,
    /// Per document, how `m` is stored: 0 (or no entry) a map of `f` and `g`, 1 missing,
    /// 2 a scalar, so that `m.f` meets a missing map or a non-map.
    m_shapes: Vec<u8>,
    literal: Option<pb::Value>,
    select: Option<Vec<(String, String)>>,
    offset: Option<i64>,
    limit: Option<i64>,
}

fn case() -> impl Strategy<Value = Case> {
    let field = prop_oneof![Just("f".to_owned()), Just("g".to_owned())];
    (
        prop::collection::vec(
            (prop::option::of(stored()), prop::option::of(stored())),
            0..8,
        ),
        prop::collection::vec(
            prop_oneof![4 => Just(0_u8), 1 => Just(1_u8), 1 => Just(2_u8)],
            8,
        ),
        prop::option::of(scalar()),
        prop::option::of(prop::collection::vec(("[xy]", field), 1..3)),
        prop::option::of(0_i64..10),
        prop::option::of(0_i64..10),
    )
        .prop_map(|(docs, m_shapes, literal, select, offset, limit)| Case {
            docs,
            m_shapes,
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
            match case.m_shapes.get(index).copied().unwrap_or(0) {
                0 => {
                    fields.insert(
                        "m".to_owned(),
                        value(pb::value::ValueType::MapValue(pb::MapValue {
                            fields: nested,
                        })),
                    );
                }
                1 => {}
                _ => {
                    fields.insert("m".to_owned(), value(pb::value::ValueType::IntegerValue(5)));
                }
            }
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

/// The executor's whole result documents and whether every response carried an execution time.
async fn executor_documents(
    service: &GatewayService,
    request: pb::ExecutePipelineRequest,
) -> (Vec<pb::Document>, bool) {
    let mut stream = Firestore::execute_pipeline(service, Request::new(request))
        .await
        .unwrap()
        .into_inner();
    let (mut out, mut timed) = (Vec::new(), true);
    while let Some(response) = stream.next().await {
        let response = response.unwrap();
        timed &= response.execution_time.is_some();
        out.extend(response.results);
    }
    (out, timed)
}

async fn stored_document(service: &GatewayService, name: &str) -> pb::Document {
    Firestore::get_document(
        service,
        Request::new(pb::GetDocumentRequest {
            name: name.to_owned(),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner()
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
    // The executor against the lowering is the same in both profiles; the emulator profile
    // answers every offset and limit the cases draw (strict answers only the recorded ones).
    gateway.ctx.policy = fireemu_core_firestore::index::IndexValidationPolicy::Emulator;
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
        m_shapes: vec![],
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
        // Where `m` is missing or not a map, `m.f` and `m.g` are absent: the lowering answers
        // that through documents without `f` and `g` there.
        let mut flat = case.clone();
        for (index, (f, g)) in flat.docs.iter_mut().enumerate() {
            if case.m_shapes.get(index).copied().unwrap_or(0) != 0 {
                *f = None;
                *g = None;
            }
        }
        let flat_service = service_for(&flat);
        let regular_m = case.m_shapes.iter().take(case.docs.len()).all(|shape| *shape == 0);
        let (expected, top, nested, nested_expected, (documents, timed), stored) = runtime.block_on(async {
            let expected = lowering(&service, &pipeline(&case, "")).await;
            let top = executor(&service, pipeline(&case, "")).await;
            let nested = executor(&service, pipeline(&case, "m.")).await;
            let nested_expected = lowering(&flat_service, &pipeline(&flat, "")).await;
            let documents = executor_documents(&service, pipeline(&case, "")).await;
            let mut stored = Vec::new();
            for document in &documents.0 {
                if !document.name.is_empty() {
                    stored.push(stored_document(&service, &document.name).await);
                }
            }
            (expected, top, nested, nested_expected, documents, stored)
        });
        // Every response carries the execution time. Without a select every result is the
        // stored source document (name and times included); after one, results are fields only.
        prop_assert!(timed);
        if case.select.is_none() {
            prop_assert_eq!(stored.len(), documents.len());
            for (result, stored) in documents.iter().zip(&stored) {
                prop_assert!(result.create_time.is_some() && result.update_time.is_some());
                prop_assert_eq!(&result.name, &stored.name);
                prop_assert_eq!(result.create_time, stored.create_time);
                prop_assert_eq!(result.update_time, stored.update_time);
                prop_assert_eq!(comparable(result), comparable(stored));
            }
        } else {
            prop_assert!(stored.is_empty());
            prop_assert!(documents.iter().all(|d| d.create_time.is_none() && d.update_time.is_none()));
        }
        prop_assert_eq!(&top, &expected);
        // Read through the map `m`, the same values give the same answer. Without a select
        // the rows carry `m` itself, so only a regular `m` compares whole rows.
        if regular_m {
            prop_assert_eq!(&nested, &expected);
        } else if case.select.is_some() {
            prop_assert_eq!(&nested, &nested_expected);
        }
    }
}

/// Enterprise runs a pipeline without an index (ruling (c)): an equality on a field whose
/// single-field index is exempted is still answered, under both profiles.
#[tokio::test]
async fn equality_on_an_exempted_field_is_answered() {
    for policy in [
        fireemu_core_firestore::index::IndexValidationPolicy::Production,
        fireemu_core_firestore::index::IndexValidationPolicy::Emulator,
    ] {
        let mut indexes = fireemu_core_firestore::index::IndexSet::default();
        indexes.set_single_field_indexes(
            &CollectionId::try_new("items").unwrap(),
            &FieldPath::parse("f").unwrap(),
            vec![],
        );
        let mut gateway = test_gateway();
        gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
        gateway.ctx.policy = policy;
        gateway.indexes = indexes;
        let backend = Arc::new(LocalBackend::new(
            gateway.clone(),
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
            7,
        ));
        let case = Case {
            docs: vec![
                (
                    Some(value(pb::value::ValueType::StringValue("hit".into()))),
                    None,
                ),
                (
                    Some(value(pb::value::ValueType::StringValue("miss".into()))),
                    None,
                ),
            ],
            m_shapes: vec![],
            literal: Some(value(pb::value::ValueType::StringValue("hit".into()))),
            select: None,
            offset: None,
            limit: None,
        };
        seed(&backend, &case);
        let service = GatewayService::local(gateway, backend);
        assert_eq!(
            executor(&service, pipeline(&case, "")).await.len(),
            1,
            "{policy:?}"
        );
        assert_eq!(
            executor(&service, pipeline(&case, "m.")).await.len(),
            1,
            "{policy:?}"
        );
    }
}

fn input_filter(
    compiled: &crate::pipeline::CompiledExecution,
) -> Option<pb::structured_query::Filter> {
    match &compiled.input.query_type {
        Some(pb::run_query_request::QueryType::StructuredQuery(query)) => query.r#where.clone(),
        None => None,
    }
}

/// A field equality is pushed into the scan as the same filter the lowering sends (the
/// executor keeps it as a residual check); an equality on a document function is not.
#[test]
fn field_equality_is_pushed_into_the_scan() {
    use pb::structured_query::filter::FilterType;
    let parent = crate::decode::parse_parent(PARENT).unwrap();
    let unrecorded = fireemu_core_firestore::pipeline_exec::Unrecorded::Refuse;
    for literal in [
        value(pb::value::ValueType::StringValue("x".into())),
        value(pb::value::ValueType::NullValue(0)),
        value(pb::value::ValueType::DoubleValue(f64::NAN)),
    ] {
        let case = Case {
            docs: vec![],
            m_shapes: vec![],
            literal: Some(literal),
            select: None,
            offset: None,
            limit: None,
        };
        let request = pipeline(&case, "");
        let baseline = crate::pipeline::compile_supported(&request, &parent).unwrap();
        let Some(pb::run_query_request::QueryType::StructuredQuery(lowered)) =
            baseline.query.query_type
        else {
            unreachable!()
        };
        let compiled = crate::pipeline::compile_pipeline(&request, &parent, unrecorded).unwrap();
        assert_eq!(
            format!("{:?}", input_filter(&compiled)),
            format!("{:?}", lowered.r#where)
        );
        // A nested path names its canonical field path.
        let nested =
            crate::pipeline::compile_pipeline(&pipeline(&case, "m."), &parent, unrecorded).unwrap();
        let path = match input_filter(&nested).and_then(|f| f.filter_type) {
            Some(FilterType::FieldFilter(f)) => f.field.unwrap().field_path,
            Some(FilterType::UnaryFilter(u)) => match u.operand_type {
                Some(pb::structured_query::unary_filter::OperandType::Field(f)) => f.field_path,
                None => unreachable!(),
            },
            other => panic!("{other:?}"),
        };
        assert_eq!(path, "m.f");
        assert!(matches!(
            compiled.stages[0],
            fireemu_core_firestore::pipeline_exec::Stage::Where(_)
        ));
    }
    let mut request = pipeline(
        &Case {
            docs: vec![],
            m_shapes: vec![],
            literal: None,
            select: None,
            offset: None,
            limit: None,
        },
        "",
    );
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        request.pipeline_type.as_mut()
    else {
        unreachable!()
    };
    structured.pipeline.as_mut().unwrap().stages.push(stage(
        "where",
        value(pb::value::ValueType::FunctionValue(pb::Function {
            name: "equal".to_owned(),
            args: vec![
                value(pb::value::ValueType::FunctionValue(pb::Function {
                    name: "document_id".to_owned(),
                    args: vec![field_ref("__name__")],
                    ..Default::default()
                })),
                value(pb::value::ValueType::StringValue("x".into())),
            ],
            ..Default::default()
        })),
    ));
    let compiled = crate::pipeline::compile_pipeline(&request, &parent, unrecorded).unwrap();
    assert!(input_filter(&compiled).is_none());
}

/// With the filter in the scan, only matching documents are copied out of the store: the
/// executor clones exactly what the lowering clones.
#[tokio::test]
async fn a_where_copies_only_matching_documents() {
    let wide = value(pb::value::ValueType::StringValue("w".repeat(2048)));
    let case = Case {
        docs: (0..40)
            .map(|index| {
                (
                    Some(value(pb::value::ValueType::IntegerValue(i64::from(
                        index == 7,
                    )))),
                    Some(wide.clone()),
                )
            })
            .collect(),
        m_shapes: vec![],
        literal: Some(value(pb::value::ValueType::IntegerValue(1))),
        select: None,
        offset: None,
        limit: None,
    };
    let backend = test_backend();
    seed(&backend, &case);
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    let service = GatewayService::local(gateway, backend.clone());
    assert_eq!(lowering(&service, &pipeline(&case, "")).await.len(), 1);
    let (_, lowered) = backend.latest_query_execution_stats().unwrap();
    assert_eq!(executor(&service, pipeline(&case, "")).await.len(), 1);
    let (_, executed) = backend.latest_query_execution_stats().unwrap();
    assert_eq!(
        executed.pages.cloned_field_bytes,
        lowered.pages.cloned_field_bytes
    );
    assert!(executed.pages.cloned_field_bytes < 2 * 4096);
}

/// A refusal found at run time can follow results already streamed, and rows after a used-up
/// limit are never evaluated.
#[tokio::test]
async fn a_run_time_refusal_may_follow_results_and_a_limit_stops_before_it() {
    let backend = test_backend();
    backend
        .commit(&pb::CommitRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            writes: [
                (
                    "a",
                    pb::value::ValueType::ReferenceValue(format!("{PARENT}/o/z/s/y")),
                ),
                // The parent of a top-level document is the documents root, whose ID production
                // refuses at run time (FS-ENT-ORACLE O-1).
                (
                    "b",
                    pb::value::ValueType::ReferenceValue(format!("{PARENT}/o/z")),
                ),
            ]
            .into_iter()
            .map(|(id, r)| pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{PARENT}/items/{id}"),
                    fields: [("r".to_owned(), value(r))].into_iter().collect(),
                    ..Default::default()
                })),
                ..Default::default()
            })
            .collect(),
            ..Default::default()
        })
        .unwrap();
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    // The emulator profile answers the run-time refusal (strict answers it only in a shape
    // production refused).
    gateway.ctx.policy = fireemu_core_firestore::index::IndexValidationPolicy::Emulator;
    let service = GatewayService::local(gateway, backend);
    let request = |limit: Option<i64>| {
        let mut stages = vec![
            stage(
                "collection",
                value(pb::value::ValueType::StringValue("/items".to_owned())),
            ),
            stage(
                "select",
                value(pb::value::ValueType::MapValue(pb::MapValue {
                    fields: [(
                        "id".to_owned(),
                        value(pb::value::ValueType::FunctionValue(pb::Function {
                            name: "document_id".to_owned(),
                            args: vec![value(pb::value::ValueType::FunctionValue(pb::Function {
                                name: "parent".to_owned(),
                                args: vec![field_ref("r")],
                                ..Default::default()
                            }))],
                            ..Default::default()
                        })),
                    )]
                    .into_iter()
                    .collect(),
                })),
            ),
        ];
        if let Some(limit) = limit {
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
    };
    let mut stream = Firestore::execute_pipeline(&service, Request::new(request(None)))
        .await
        .unwrap()
        .into_inner();
    let first = stream.next().await.unwrap().unwrap();
    assert_eq!(first.results.len(), 1);
    let refusal = stream.next().await.unwrap().unwrap_err();
    assert_eq!(refusal.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        refusal.message(),
        "document_id(...) requires a non-empty path."
    );
    assert!(stream.next().await.is_none());
    assert_eq!(executor(&service, request(Some(1))).await.len(), 1);
}
