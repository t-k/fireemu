//! End-to-end: a real tonic client talks to the strict gateway over loopback.

use std::collections::HashMap;

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet, IndexValidationPolicy,
    PlanningContext,
};
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;
use tokio_stream::wrappers::TcpListenerStream;

async fn start(
    edition: FirestoreEdition,
    indexes: IndexSet,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
        },
        indexes,
    };
    let svc = FirestoreServer::new(GatewayService::new(gateway, None));
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (format!("http://{addr}"), handle)
}

async fn connect(url: &str) -> FirestoreClient<tonic::transport::Channel> {
    let channel = tonic::transport::Endpoint::from_shared(url.to_owned())
        .unwrap()
        .connect()
        .await
        .unwrap();
    FirestoreClient::new(channel)
}

fn string(s: &str) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::StringValue(s.to_owned())),
    }
}

fn field_filter(path: &str, op: sq::field_filter::Operator, value: pb::Value) -> sq::Filter {
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: path.to_owned(),
            }),
            op: op as i32,
            value: Some(value),
        })),
    }
}

fn and(filters: Vec<sq::Filter>) -> sq::Filter {
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::CompositeFilter(
            sq::CompositeFilter {
                op: sq::composite_filter::Operator::And as i32,
                filters,
            },
        )),
    }
}

fn run_query(filter: sq::Filter) -> pb::RunQueryRequest {
    pb::RunQueryRequest {
        parent: "projects/demo-app/databases/(default)/documents".to_owned(),
        query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: "tasks".to_owned(),
                    all_descendants: false,
                }],
                r#where: Some(filter),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

#[tokio::test]
async fn standard_query_without_composite_index_is_failed_precondition_with_fragment() {
    let (url, handle) = start(FirestoreEdition::Standard, IndexSet::default()).await;
    let mut client = connect(&url).await;
    let req = run_query(and(vec![
        field_filter("owner", sq::field_filter::Operator::Equal, string("u")),
        field_filter(
            "done",
            sq::field_filter::Operator::Equal,
            pb::Value {
                value_type: Some(pb::value::ValueType::BooleanValue(false)),
            },
        ),
    ]));
    let status = client.run_query(req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status.message().contains("\"collectionGroup\": \"tasks\""),
        "{}",
        status.message()
    );
    assert_eq!(
        status
            .metadata()
            .get("fireemu-reason")
            .map(|v| v.to_str().unwrap()),
        Some("FS_GW_MISSING_INDEX")
    );
    handle.abort();
}

#[tokio::test]
async fn standard_query_limit_violation_is_invalid_argument() {
    let (url, handle) = start(FirestoreEdition::Standard, IndexSet::default()).await;
    let mut client = connect(&url).await;
    let values = pb::Value {
        value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue {
            values: (0..11)
                .map(|i| pb::Value {
                    value_type: Some(pb::value::ValueType::IntegerValue(i)),
                })
                .collect(),
        })),
    };
    let status = client
        .run_query(run_query(field_filter(
            "a",
            sq::field_filter::Operator::NotIn,
            values,
        )))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("FS-QUERY-LIMIT-NOT-IN-VALUES"),
        "{}",
        status.message()
    );
    handle.abort();
}

#[tokio::test]
async fn validated_query_without_upstream_is_unimplemented_never_a_fake_success() {
    let mut indexes = IndexSet::default();
    indexes.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("tasks").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: vec![
            IndexField {
                path: FieldPath::parse("done").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
            IndexField {
                path: FieldPath::parse("owner").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
        ],
    });
    let (url, handle) = start(FirestoreEdition::Standard, indexes).await;
    let mut client = connect(&url).await;
    let req = run_query(and(vec![
        field_filter("owner", sq::field_filter::Operator::Equal, string("u")),
        field_filter(
            "done",
            sq::field_filter::Operator::Equal,
            pb::Value {
                value_type: Some(pb::value::ValueType::BooleanValue(false)),
            },
        ),
    ]));
    let status = client.run_query(req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
    handle.abort();
}

#[tokio::test]
async fn enterprise_query_without_index_passes_validation() {
    let (url, handle) = start(FirestoreEdition::Enterprise, IndexSet::default()).await;
    let mut client = connect(&url).await;
    let req = run_query(and(vec![
        field_filter("owner", sq::field_filter::Operator::Equal, string("u")),
        field_filter(
            "done",
            sq::field_filter::Operator::Equal,
            pb::Value {
                value_type: Some(pb::value::ValueType::BooleanValue(false)),
            },
        ),
    ]));
    // Passes the index check (full scan allowed) and then hits the missing upstream.
    let status = client.run_query(req).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
    handle.abort();
}

#[tokio::test]
async fn malformed_parent_and_unknown_operator_are_invalid_argument() {
    let (url, handle) = start(FirestoreEdition::Standard, IndexSet::default()).await;
    let mut client = connect(&url).await;
    let mut req = run_query(field_filter(
        "a",
        sq::field_filter::Operator::Equal,
        string("x"),
    ));
    req.parent = "projects/demo-app/wrong".to_owned();
    assert_eq!(
        client.run_query(req).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    let mut bad = run_query(field_filter(
        "a",
        sq::field_filter::Operator::Equal,
        string("x"),
    ));
    if let Some(pb::run_query_request::QueryType::StructuredQuery(q)) = &mut bad.query_type {
        if let Some(sq::filter::FilterType::FieldFilter(f)) =
            q.r#where.as_mut().and_then(|w| w.filter_type.as_mut())
        {
            f.op = 99;
        }
    }
    assert_eq!(
        client.run_query(bad).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    let _unused: HashMap<String, String> = HashMap::new();
    handle.abort();
}

#[tokio::test]
async fn pipeline_and_listen_are_explicitly_unimplemented() {
    let (url, handle) = start(FirestoreEdition::Enterprise, IndexSet::default()).await;
    let mut client = connect(&url).await;
    // Strict validation only: an undecodable request is refused as such, a valid pipeline
    // is answered with UNIMPLEMENTED (never forwarded or executed).
    let status = client
        .execute_pipeline(pb::ExecutePipelineRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        status.metadata().get("fireemu-code").unwrap(),
        "FS_PIPE_DECODE"
    );
    let status = client
        .execute_pipeline(pb::ExecutePipelineRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            pipeline_type: Some(
                pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                    pb::StructuredPipeline {
                        pipeline: Some(pb::Pipeline {
                            stages: vec![pb::pipeline::Stage {
                                name: "collection".to_owned(),
                                args: vec![pb::Value {
                                    value_type: Some(pb::value::ValueType::StringValue(
                                        "users".to_owned(),
                                    )),
                                }],
                                options: HashMap::new(),
                            }],
                        }),
                        options: HashMap::new(),
                    },
                ),
            ),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
    assert_eq!(
        status.metadata().get("fireemu-pipeline").unwrap(),
        "collection(1)"
    );
    let status = client
        .get_document(pb::GetDocumentRequest {
            name: "projects/demo-app/databases/(default)/documents/a/b".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::Unimplemented,
        "passthrough without upstream fails closed"
    );
    handle.abort();
}

/// `firestore.enforceLimits`, which the compatibility profile defaults: `strict` refuses a
/// query over a Standard limit, `firebase` reports it and runs the query, because refusing it
/// is a rejection the official emulator does not make.
#[test]
fn the_limit_switch_turns_a_refusal_into_an_observation() {
    use fireemu_core_firestore::query::{FieldOp, FilterExpr, Query, QueryScope};
    use fireemu_core_firestore::value::Value;

    let ctx = PlanningContext {
        edition: FirestoreEdition::Standard,
        api_mode: FirestoreApiMode::Native,
        policy: IndexValidationPolicy::Emulator,
    };
    // Eleven `not-in` values: one Standard query limit that only production enforces (the
    // official emulator serves the query), no index question, so the two profiles differ in
    // exactly one thing.
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tasks").unwrap(),
    ))
    .with_filter(FilterExpr::Field {
        field: FieldPath::parse("tag").unwrap(),
        op: FieldOp::NotIn,
        value: Value::Array((0..11).map(Value::Integer).collect()),
    });

    let strict = Gateway {
        enforce_limits: true,
        ctx,
        indexes: IndexSet::default(),
    };
    let rejection = strict.validate_query(&query).unwrap_err();
    assert_eq!(rejection.to_status().code(), tonic::Code::InvalidArgument);
    assert!(rejection.to_string().contains("NOT-IN"), "{rejection}");

    let firebase = Gateway {
        enforce_limits: false,
        ctx,
        indexes: IndexSet::default(),
    };
    let accepted = firebase
        .validate_query(&query)
        .expect("the firebase profile may add no rejection the official emulator does not make");
    assert!(
        accepted
            .warnings
            .iter()
            .any(|w| w.starts_with("FS_LIMIT_OBSERVED:")),
        "the violation is still reported, as a warning: {:?}",
        accepted.warnings
    );

    // Two `array-contains` in one disjunction is a limit the official emulator refuses too
    // (conformance/src/firestore-probe, errors/rest-shapes#two-array-contains), so the
    // switch leaves it refused, with the FAILED_PRECONDITION the official emulator answers.
    let contains = |path: &str, v: &str| FilterExpr::Field {
        field: FieldPath::parse(path).unwrap(),
        op: FieldOp::ArrayContains,
        value: Value::String(v.to_owned()),
    };
    let two_contains = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tasks").unwrap(),
    ))
    .with_filter(FilterExpr::And(vec![
        contains("tags", "a"),
        contains("labels", "b"),
    ]));
    let rejection = firebase.validate_query(&two_contains).unwrap_err();
    assert_eq!(
        rejection.to_status().code(),
        tonic::Code::FailedPrecondition
    );
    assert!(
        rejection.to_string().contains("ARRAY-CONTAINS"),
        "{rejection}"
    );
}
