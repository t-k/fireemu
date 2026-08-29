//! End-to-end: a real tonic client talks to the strict gateway over loopback.

use std::collections::HashMap;

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::service::GatewayService;
use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet, IndexValidationPolicy,
    PlanningContext,
};
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::ids::CollectionId;
use ftd_proto_firestore::google::firestore::v1 as pb;
use ftd_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use ftd_proto_firestore::google::firestore::v1::structured_query as sq;
use tokio_stream::wrappers::TcpListenerStream;

async fn start(
    edition: FirestoreEdition,
    indexes: IndexSet,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
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
            .get("ftd-reason")
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
    let status = client
        .execute_pipeline(pb::ExecutePipelineRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
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
