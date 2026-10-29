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
        value(pb::value::ValueType::ReferenceValue("/items".to_owned())),
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
    // The lowering reads in name order and cuts there; the executor reads in production's scan
    // order (CRC-32 of the document ID), so the baseline reads everything, puts it in that order
    // and applies the offset and the limit itself.
    let mut offset = 0;
    if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
        query.query_type.as_mut()
    {
        offset = usize::try_from(query.offset).unwrap();
        query.offset = 0;
        query.limit = None;
    }
    let mut stream = Firestore::run_query(service, Request::new(query))
        .await
        .unwrap()
        .into_inner();
    let mut responses = Vec::new();
    while let Some(response) = stream.next().await {
        responses.push(response.unwrap());
    }
    let mut out: Vec<Fields> = crate::pipeline::in_scan_order(responses)
        .into_iter()
        .filter_map(|response| response.document)
        .map(|document| {
            comparable(&crate::pipeline::project_document(
                document,
                &compiled.projection,
            ))
        })
        .skip(offset)
        .collect();
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
    fn zero_counts_keep_or_remove_generated_documents(case in case(), strict in any::<bool>()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let backend = test_backend();
        seed(&backend, &case);
        let mut gateway = test_gateway();
        gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
        gateway.ctx.policy = if strict {
            fireemu_core_firestore::index::IndexValidationPolicy::Production
        } else {
            fireemu_core_firestore::index::IndexValidationPolicy::Emulator
        };
        let service = GatewayService::local(gateway, backend);
        let mut base = case;
        base.literal = None;
        base.select = None;
        base.offset = None;
        base.limit = None;
        let all = runtime.block_on(executor(&service, pipeline(&base, "")));
        base.offset = Some(0);
        let offset = runtime.block_on(executor(&service, pipeline(&base, "")));
        base.limit = Some(0);
        let limit = runtime.block_on(executor(&service, pipeline(&base, "")));
        prop_assert_eq!(offset, all);
        prop_assert!(limit.is_empty());
    }

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
                // (The scan reads "b" before "a": ascending CRC-32 of the document ID.)
                (
                    "b",
                    pb::value::ValueType::ReferenceValue(format!("{PARENT}/o/z/s/y")),
                ),
                // The parent of a top-level document is the documents root, whose ID production
                // refuses at run time (FS-ENT-ORACLE O-1).
                (
                    "a",
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
                value(pb::value::ValueType::ReferenceValue("/items".to_owned())),
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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sqrt_wrong_type_is_captured_or_reported_and_empty_rows_are_lazy() {
    use pb::value::ValueType as V;
    let case = Case {
        docs: vec![(Some(value(V::StringValue("s".to_owned()))), None)],
        m_shapes: vec![],
        literal: None,
        select: None,
        offset: None,
        limit: None,
    };
    let call = |name: &str, args: Vec<pb::Value>| {
        value(V::FunctionValue(pb::Function {
            name: name.to_owned(),
            args,
            ..Default::default()
        }))
    };
    for policy in [
        fireemu_core_firestore::index::IndexValidationPolicy::Production,
        fireemu_core_firestore::index::IndexValidationPolicy::Emulator,
    ] {
        let backend = test_backend();
        seed(&backend, &case);
        let mut gateway = test_gateway();
        gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
        gateway.ctx.policy = policy;
        let service = GatewayService::local(gateway, backend);
        let sqrt = || call("sqrt", vec![field_ref("f")]);
        let request = |empty: bool, stage_name: &str, expression: pb::Value| {
            let mut req = pipeline(&case, "");
            let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
                req.pipeline_type.as_mut()
            else {
                unreachable!()
            };
            let stages = &mut structured.pipeline.as_mut().unwrap().stages;
            if empty {
                stages[0].args[0] = value(V::ReferenceValue("/empty".to_owned()));
            }
            stages.push(stage(stage_name, expression));
            req
        };
        let select = |v| {
            value(V::MapValue(pb::MapValue {
                fields: [("v".to_owned(), v)].into_iter().collect(),
            }))
        };
        let actual = executor(
            &service,
            request(false, "select", select(call("is_error", vec![sqrt()]))),
        )
        .await;
        assert_eq!(actual.len(), 1);
        assert_eq!(
            actual[0].get("v").map(String::as_str),
            Some("Boolean(true)")
        );
        let two_args = call(
            "sqrt",
            vec![value(V::IntegerValue(1)), value(V::IntegerValue(2))],
        );
        let Err(error) = Firestore::execute_pipeline(
            &service,
            Request::new(request(false, "select", select(two_args))),
        )
        .await
        else {
            panic!("unrecorded two-argument call must refuse");
        };
        if matches!(
            policy,
            fireemu_core_firestore::index::IndexValidationPolicy::Production
        ) {
            assert_eq!(error.code(), tonic::Code::Unimplemented);
        } else {
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        let condition = call("greater_than", vec![sqrt(), value(V::IntegerValue(0))]);
        let mut unrecorded_stream = Firestore::execute_pipeline(
            &service,
            Request::new(request(false, "where", condition.clone())),
        )
        .await
        .unwrap()
        .into_inner();
        let unrecorded = unrecorded_stream.next().await.unwrap().unwrap_err();
        if matches!(
            policy,
            fireemu_core_firestore::index::IndexValidationPolicy::Production
        ) {
            assert_eq!(unrecorded.code(), tonic::Code::Unimplemented);
        } else {
            assert_eq!(unrecorded.code(), tonic::Code::InvalidArgument);
        }
        let mut where_request = request(false, "where", condition);
        let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
            where_request.pipeline_type.as_mut()
        else {
            unreachable!()
        };
        let id = call("document_id", vec![field_ref("__name__")]);
        structured.pipeline.as_mut().unwrap().stages.push(stage(
            "select",
            value(V::MapValue(pb::MapValue {
                fields: [("id".to_owned(), id)].into_iter().collect(),
            })),
        ));
        let mut stream = Firestore::execute_pipeline(&service, Request::new(where_request))
            .await
            .unwrap()
            .into_inner();
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error:?}");
        assert_eq!(
            error.message(),
            "The function sqrt(...) requires `Float` but got `STRING`."
        );
        let empty_sqrt = || call("sqrt", vec![value(V::StringValue("a".to_owned()))]);
        assert!(
            executor(&service, request(true, "select", select(empty_sqrt())))
                .await
                .is_empty()
        );
        assert!(executor(&service, request(true, "where", empty_sqrt()))
            .await
            .is_empty());
    }
}

#[tokio::test]
async fn observed_replace_with_full_serves_map_fields() {
    let case = Case {
        docs: vec![(Some(value(pb::value::ValueType::IntegerValue(7))), None)],
        m_shapes: vec![0],
        literal: None,
        select: None,
        offset: None,
        limit: None,
    };
    let backend = test_backend();
    seed(&backend, &case);
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    let service = GatewayService::local(gateway, backend);
    let mut request = pipeline(&case, "");
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        request.pipeline_type.as_mut()
    else {
        unreachable!()
    };
    structured
        .pipeline
        .as_mut()
        .unwrap()
        .stages
        .push(pb::pipeline::Stage {
            name: "replace_with".to_owned(),
            args: vec![
                field_ref("m"),
                value(pb::value::ValueType::StringValue("full_replace".to_owned())),
            ],
            ..Default::default()
        });
    let rows = executor(&service, request).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("f").map(String::as_str), Some("Integer(7)"));
    assert!(!rows[0].contains_key("m"));
}

#[tokio::test]
async fn database_input_returns_all_collections_in_its_database() {
    let case = Case {
        docs: vec![(Some(value(pb::value::ValueType::IntegerValue(1))), None); 3],
        m_shapes: vec![],
        literal: None,
        select: None,
        offset: None,
        limit: None,
    };
    let backend = test_backend();
    seed(&backend, &case);
    backend
        .commit(&pb::CommitRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            writes: ["other/a", "ne/d1"]
                .into_iter()
                .map(|name| pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{PARENT}/{name}"),
                        fields: [("x".to_owned(), value(pb::value::ValueType::IntegerValue(2)))]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
        .unwrap();
    backend
        .commit(&pb::CommitRequest {
            database: "projects/other-app/databases/(default)".to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: "projects/other-app/databases/(default)/documents/foreign/a".to_owned(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();
    backend
        .ensure_database(
            &crate::decode::parse_parent("projects/demo-app/databases/other/documents").unwrap(),
        )
        .unwrap();
    backend
        .commit(&pb::CommitRequest {
            database: "projects/demo-app/databases/other".to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: "projects/demo-app/databases/other/documents/foreign/b".to_owned(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    let service = GatewayService::local(gateway, backend);
    let mut request = pipeline(&case, "");
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        request.pipeline_type.as_mut()
    else {
        unreachable!()
    };
    structured.pipeline.as_mut().unwrap().stages = vec![pb::pipeline::Stage {
        name: "database".to_owned(),
        ..Default::default()
    }];
    let (rows, timed) = executor_documents(&service, request).await;
    assert!(timed);
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().any(|row| row.name.ends_with("/items/000")));
    assert!(rows.iter().any(|row| row.name.ends_with("/other/a")));
    assert!(rows
        .iter()
        .all(|row| row.create_time.is_some() && row.update_time.is_some()));
}

#[tokio::test]
async fn observed_nearest_euclidean_returns_ranked_distances() {
    use pb::value::ValueType as V;
    let vector = |items: &[f64]| {
        value(V::MapValue(pb::MapValue {
            fields: [
                (
                    "__type__".to_owned(),
                    value(V::StringValue("__vector__".to_owned())),
                ),
                (
                    "value".to_owned(),
                    value(V::ArrayValue(pb::ArrayValue {
                        values: items.iter().map(|n| value(V::DoubleValue(*n))).collect(),
                    })),
                ),
            ]
            .into_iter()
            .collect(),
        }))
    };
    let backend = test_backend();
    backend
        .commit(&pb::CommitRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            writes: [
                ("a", vec![2.0, 1.0]),
                ("b", vec![3.0, 2.0]),
                ("c", vec![2.0, 4.0]),
            ]
            .into_iter()
            .map(|(name, coordinates)| pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{PARENT}/items/{name}"),
                    fields: [("vec".to_owned(), vector(&coordinates))]
                        .into_iter()
                        .collect(),
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
    let service = GatewayService::local(gateway, backend);
    let case = Case {
        docs: vec![],
        m_shapes: vec![],
        literal: None,
        select: None,
        offset: None,
        limit: None,
    };
    let mut request = pipeline(&case, "");
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        request.pipeline_type.as_mut()
    else {
        unreachable!()
    };
    structured
        .pipeline
        .as_mut()
        .unwrap()
        .stages
        .push(pb::pipeline::Stage {
            name: "find_nearest".to_owned(),
            args: vec![
                field_ref("vec"),
                vector(&[1.0, 2.0]),
                value(V::StringValue("euclidean".to_owned())),
            ],
            options: [
                ("limit".to_owned(), value(V::IntegerValue(3))),
                ("distance_field".to_owned(), field_ref("dist")),
            ]
            .into_iter()
            .collect(),
        });
    let (rows, _) = executor_documents(&service, request).await;
    assert_eq!(rows.len(), 3);
    let values: Vec<_> = rows
        .iter()
        .map(|r| match r.fields["dist"].value_type.as_ref().unwrap() {
            V::DoubleValue(v) => *v,
            _ => panic!("distance type"),
        })
        .collect();
    assert_eq!(values, [2.0_f64.sqrt(), 2.0, 5.0_f64.sqrt()]);
}

#[tokio::test]
async fn observed_replace_map_modes_serve_in_both_profiles() {
    let case = Case {
        docs: vec![(Some(value(pb::value::ValueType::IntegerValue(7))), None)],
        m_shapes: vec![0],
        literal: None,
        select: None,
        offset: None,
        limit: None,
    };
    for policy in [
        fireemu_core_firestore::index::IndexValidationPolicy::Production,
        fireemu_core_firestore::index::IndexValidationPolicy::Emulator,
    ] {
        let backend = test_backend();
        seed(&backend, &case);
        let mut gateway = test_gateway();
        gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
        gateway.ctx.policy = policy;
        let service = GatewayService::local(gateway, backend);
        for (mode, expression) in [
            ("full_replace", field_ref("m")),
            ("merge_overwrite_existing", field_ref("m")),
            ("merge_keep_existing", field_ref("m")),
        ] {
            let mut request = pipeline(&case, "");
            let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
                request.pipeline_type.as_mut()
            else {
                unreachable!()
            };
            structured
                .pipeline
                .as_mut()
                .unwrap()
                .stages
                .push(pb::pipeline::Stage {
                    name: "replace_with".to_owned(),
                    args: vec![
                        expression,
                        value(pb::value::ValueType::StringValue(mode.to_owned())),
                    ],
                    ..Default::default()
                });
            let rows = executor(&service, request).await;
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].get("f").map(String::as_str), Some("Integer(7)"));
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn stage_context_seeded_pict_rows_execute() {
    use pb::value::ValueType as V;
    let Ok(matrix) = std::env::var("STAGE_CONTEXT_PICT") else {
        return;
    };
    let text = std::fs::read_to_string(matrix).unwrap();
    let vector = |items: &[f64]| {
        value(V::MapValue(pb::MapValue {
            fields: [
                (
                    "__type__".to_owned(),
                    value(V::StringValue("__vector__".to_owned())),
                ),
                (
                    "value".to_owned(),
                    value(V::ArrayValue(pb::ArrayValue {
                        values: items.iter().map(|n| value(V::DoubleValue(*n))).collect(),
                    })),
                ),
            ]
            .into_iter()
            .collect(),
        }))
    };
    for line in text.lines().skip(1) {
        let cols: Vec<_> = line.split('\t').collect();
        assert_eq!(cols.len(), 5);
        let (kind, profile, input, mode, metadata) = (cols[0], cols[1], cols[2], cols[3], cols[4]);
        let backend = test_backend();
        if input != "empty" {
            let map = value(V::MapValue(pb::MapValue {
                fields: [
                    ("shared".to_owned(), value(V::StringValue("new".into()))),
                    ("added".to_owned(), value(V::StringValue("a".into()))),
                ]
                .into_iter()
                .collect(),
            }));
            let vec = if kind == "nearest" && input == "wrongtype" {
                value(V::IntegerValue(7))
            } else {
                vector(&[2.0, 1.0])
            };
            backend
                .commit(&pb::CommitRequest {
                    database: "projects/demo-app/databases/(default)".into(),
                    writes: vec![pb::Write {
                        operation: Some(pb::write::Operation::Update(pb::Document {
                            name: format!("{PARENT}/items/a"),
                            fields: [
                                ("m".into(), map),
                                ("vec".into(), vec),
                                ("shared".into(), value(V::StringValue("old".into()))),
                            ]
                            .into_iter()
                            .collect(),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .unwrap();
        }
        let mut gateway = test_gateway();
        gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
        gateway.ctx.policy = if profile == "strict" {
            fireemu_core_firestore::index::IndexValidationPolicy::Production
        } else {
            fireemu_core_firestore::index::IndexValidationPolicy::Emulator
        };
        let service = GatewayService::local(gateway, backend);
        let case = Case {
            docs: vec![],
            m_shapes: vec![],
            literal: None,
            select: None,
            offset: None,
            limit: None,
        };
        let mut request = pipeline(&case, "");
        let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
            request.pipeline_type.as_mut()
        else {
            unreachable!()
        };
        let stages = &mut structured.pipeline.as_mut().unwrap().stages;
        if kind == "database" {
            stages[0] = pb::pipeline::Stage {
                name: "database".into(),
                ..Default::default()
            };
        }
        if metadata == "absent" {
            stages.push(stage(
                "select",
                value(V::MapValue(pb::MapValue {
                    fields: ["m", "vec", "shared"]
                        .into_iter()
                        .map(|f| (f.to_owned(), field_ref(f)))
                        .collect(),
                })),
            ));
        }
        if kind == "replace" {
            let wire_mode = match mode {
                "full" => "full_replace",
                "merge_overwrite" => "merge_overwrite_existing",
                "merge_keep" => "merge_keep_existing",
                _ => unreachable!(),
            };
            stages.push(pb::pipeline::Stage {
                name: "replace_with".into(),
                args: vec![
                    if input == "wrongtype" {
                        value(V::IntegerValue(7))
                    } else {
                        field_ref("m")
                    },
                    value(V::StringValue(wire_mode.into())),
                ],
                ..Default::default()
            });
        }
        if kind == "nearest" {
            stages.push(pb::pipeline::Stage {
                name: "find_nearest".into(),
                args: vec![
                    field_ref("vec"),
                    vector(if input == "dimension" {
                        &[1.0, 2.0, 3.0]
                    } else {
                        &[1.0, 2.0]
                    }),
                    value(V::StringValue(
                        if mode == "dot" { "dot_product" } else { mode }.into(),
                    )),
                ],
                options: [
                    ("limit".into(), value(V::IntegerValue(3))),
                    ("distance_field".into(), field_ref("dist")),
                ]
                .into_iter()
                .collect(),
            });
        }
        let error_expected = input != "empty"
            && ((kind == "replace" && input == "wrongtype")
                || (kind == "nearest" && input == "wrongtype" && profile == "strict"));
        let response = Firestore::execute_pipeline(&service, Request::new(request)).await;
        let mut rows = Vec::new();
        let mut error = response.is_err();
        if let Ok(response) = response {
            let mut stream = response.into_inner();
            while let Some(item) = stream.next().await {
                if let Ok(value) = item {
                    rows.extend(value.results);
                } else {
                    error = true;
                    break;
                }
            }
        }
        assert_eq!(error, error_expected, "{line}");
        if !error {
            let expected = usize::from(
                input != "empty"
                    && !(kind == "nearest" && matches!(input, "wrongtype" | "dimension")),
            );
            assert_eq!(rows.len(), expected, "{line}");
            if let Some(row) = rows.first() {
                let keeps_metadata =
                    metadata == "present" && !(kind == "replace" && mode == "full");
                assert_eq!(row.create_time.is_some(), keeps_metadata, "{line}");
                if kind == "replace" && input == "wrongtype" {
                    assert!(row.fields.is_empty(), "{line}");
                }
            }
        }
    }
}

#[test]
fn database_input_enforces_snapshot_guard_for_empty_and_nonempty() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let parent = crate::decode::parse_parent(PARENT).unwrap();
    for populated in [false, true] {
        let backend = test_backend();
        if populated {
            let case = Case {
                docs: vec![(Some(value(pb::value::ValueType::IntegerValue(1))), None)],
                m_shapes: vec![],
                literal: None,
                select: None,
                offset: None,
                limit: None,
            };
            seed(&backend, &case);
        }
        let calls = AtomicUsize::new(0);
        let guard = |_: &fireemu_core_firestore::store::FirestoreState,
                     version: Option<fireemu_core_firestore::store::CommitVersion>,
                     check: crate::rules::ReadCheck<'_>| {
            assert!(version.is_some());
            let crate::rules::ReadCheck::Documents(documents) = check else {
                panic!("expected document read check")
            };
            assert_eq!(documents.len(), usize::from(populated));
            calls.fetch_add(1, Ordering::SeqCst);
            Err(Status::permission_denied("test guard"))
        };
        let result = crate::pipeline::database_input(&backend, &parent, &guard);
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn database_input_rejects_stale_epoch_even_when_empty() {
    let backend = test_backend();
    let old_epoch = backend.barrier().epoch();
    drop(backend.barrier().exclusive());
    for (epoch, stale) in [(old_epoch, true), (backend.barrier().epoch(), false)] {
        let caller = Caller {
            principal: Principal::Owner,
            epoch,
        };
        let result = blocking_read(backend.clone(), None, caller, |local, guard| {
            let parent = parse_parent(PARENT).unwrap();
            crate::pipeline::database_input(local, &parent, guard)
        })
        .await;
        if stale {
            assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
        } else {
            assert!(result.unwrap().is_empty());
        }
    }
}
