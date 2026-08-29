//! End-to-end local execution through a real tonic client: documents, queries, transactions,
//! aggregations and batch writes on the virtual clock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::service::GatewayService;
use ftd_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::time::{LogicalDuration, LogicalInstant};
use ftd_proto_firestore::google::firestore::v1 as pb;
use ftd_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use ftd_proto_firestore::google::firestore::v1::structured_query as sq;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

const DB: &str = "projects/demo-app/databases/(default)";
const DOCS: &str = "projects/demo-app/databases/(default)/documents";

async fn start() -> (
    FirestoreClient<tonic::transport::Channel>,
    Arc<Mutex<VirtualClock>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), 7));
    let svc = FirestoreServer::new(GatewayService::local(gateway, backend));
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (FirestoreClient::new(channel), clock, handle)
}

fn s(v: &str) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::StringValue(v.to_owned())),
    }
}
fn i(v: i64) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::IntegerValue(v)),
    }
}
fn doc(name: &str, fields: &[(&str, pb::Value)]) -> pb::Document {
    pb::Document {
        name: format!("{DOCS}/{name}"),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
        create_time: None,
        update_time: None,
    }
}
fn update_write(name: &str, fields: &[(&str, pb::Value)]) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(doc(name, fields))),
        ..Default::default()
    }
}
fn query(collection: &str, filter: Option<sq::Filter>) -> pb::RunQueryRequest {
    pb::RunQueryRequest {
        parent: DOCS.to_owned(),
        query_type: Some(pb::run_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: collection.to_owned(),
                    all_descendants: false,
                }],
                r#where: filter,
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}
fn field_eq(path: &str, value: pb::Value) -> sq::Filter {
    sq::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: path.to_owned(),
            }),
            op: sq::field_filter::Operator::Equal as i32,
            value: Some(value),
        })),
    }
}
async fn collect_docs(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    req: pb::RunQueryRequest,
) -> Vec<pb::Document> {
    let mut stream = client.run_query(req).await.unwrap().into_inner();
    let mut out = Vec::new();
    while let Some(r) = stream.next().await {
        if let Some(d) = r.unwrap().document {
            out.push(d);
        }
    }
    out
}

#[tokio::test]
async fn commit_get_query_and_delete_round_trip() {
    let (mut client, clock, handle) = start().await;
    let commit = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("users/alice", &[("name", s("Alice")), ("age", i(30))]),
                update_write("users/bob", &[("name", s("Bob")), ("age", i(25))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(commit.write_results.len(), 2);
    assert_eq!(commit.commit_time.unwrap().seconds, 1_788_004_860);

    let got = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/users/alice"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.fields.get("age"), Some(&i(30)));
    assert_eq!(got.create_time.unwrap().seconds, 1_788_004_860);
    let missing = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/users/zoe"),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(60))
        .unwrap();
    let docs = collect_docs(&mut client, query("users", Some(field_eq("age", i(25))))).await;
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].name, format!("{DOCS}/users/bob"));
    let all = collect_docs(&mut client, query("users", None)).await;
    assert_eq!(all.len(), 2);

    client
        .delete_document(pb::DeleteDocumentRequest {
            name: format!("{DOCS}/users/alice"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        collect_docs(&mut client, query("users", None)).await.len(),
        1
    );
    let ids = client
        .list_collection_ids(pb::ListCollectionIdsRequest {
            parent: DOCS.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ids.collection_ids, vec!["users"]);
    handle.abort();
}

#[tokio::test]
async fn create_update_with_mask_transforms_and_preconditions() {
    let (mut client, _clock, handle) = start().await;
    let created = client
        .create_document(pb::CreateDocumentRequest {
            parent: DOCS.to_owned(),
            collection_id: "posts".to_owned(),
            document_id: String::new(),
            document: Some(pb::Document {
                fields: HashMap::from([("title".to_owned(), s("hi")), ("likes".to_owned(), i(0))]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(created.name.starts_with(&format!("{DOCS}/posts/")));
    let id = created.name.rsplit('/').next().unwrap().to_owned();
    assert_eq!(id.len(), 20);

    // Update with a mask plus an increment transform.
    let write = pb::Write {
        operation: Some(pb::write::Operation::Update(doc(
            &format!("posts/{id}"),
            &[("title", s("hello"))],
        ))),
        update_mask: Some(pb::DocumentMask {
            field_paths: vec!["title".to_owned()],
        }),
        update_transforms: vec![pb::document_transform::FieldTransform {
            field_path: "likes".to_owned(),
            transform_type: Some(
                pb::document_transform::field_transform::TransformType::Increment(i(5)),
            ),
        }],
        current_document: Some(pb::Precondition {
            condition_type: Some(pb::precondition::ConditionType::Exists(true)),
        }),
    };
    let resp = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![write],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.write_results[0].transform_results, vec![i(5)]);
    let got = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/posts/{id}"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.fields.get("title"), Some(&s("hello")));
    assert_eq!(got.fields.get("likes"), Some(&i(5)));

    // Creating the same document again is ALREADY_EXISTS; updating a missing one is NOT_FOUND.
    let dup = client
        .create_document(pb::CreateDocumentRequest {
            parent: DOCS.to_owned(),
            collection_id: "posts".to_owned(),
            document_id: id.clone(),
            document: Some(pb::Document::default()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(dup.code(), tonic::Code::AlreadyExists);
    let missing = client
        .update_document(pb::UpdateDocumentRequest {
            document: Some(doc("posts/nope", &[("x", i(1))])),
            update_mask: Some(pb::DocumentMask {
                field_paths: vec!["x".to_owned()],
            }),
            current_document: Some(pb::Precondition {
                condition_type: Some(pb::precondition::ConditionType::Exists(true)),
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);
    handle.abort();
}

#[tokio::test]
async fn transactions_abort_on_conflict_and_batch_get_reports_missing() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(100))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let mut stream = client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![format!("{DOCS}/acct/a"), format!("{DOCS}/acct/none")],
            consistency_selector: Some(
                pb::batch_get_documents_request::ConsistencySelector::Transaction(txn.clone()),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut found = 0;
    let mut missing = 0;
    while let Some(r) = stream.next().await {
        match r.unwrap().result {
            Some(pb::batch_get_documents_response::Result::Found(_)) => found += 1,
            Some(pb::batch_get_documents_response::Result::Missing(_)) => missing += 1,
            None => {}
        }
    }
    assert_eq!((found, missing), (1, 1));
    // Someone else writes the document.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(90))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let aborted = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("acct/a", &[("balance", i(80))])],
            transaction: txn,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(aborted.code(), tonic::Code::Aborted);
    let got = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/acct/a"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.fields.get("balance"), Some(&i(90)));

    let txn2 = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    client
        .rollback(pb::RollbackRequest {
            database: DB.to_owned(),
            transaction: txn2,
            ..Default::default()
        })
        .await
        .unwrap();
    handle.abort();
}

#[tokio::test]
async fn aggregation_batch_write_and_gateway_rejections_in_local_mode() {
    let (mut client, _clock, handle) = start().await;
    let resp = client
        .batch_write(pb::BatchWriteRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("n/1", &[("v", i(1))]),
                update_write("n/2", &[("v", i(2))]),
                pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: "bad name".to_owned(),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.status[0].code, 0);
    assert_eq!(resp.status[1].code, 0);
    assert_eq!(resp.status[2].code, i32::from(tonic::Code::InvalidArgument));

    let agg = pb::RunAggregationQueryRequest {
        parent: DOCS.to_owned(),
        query_type: Some(
            pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                pb::StructuredAggregationQuery {
                    query_type: Some(
                        pb::structured_aggregation_query::QueryType::StructuredQuery(
                            pb::StructuredQuery {
                                from: vec![sq::CollectionSelector {
                                    collection_id: "n".to_owned(),
                                    all_descendants: false,
                                }],
                                ..Default::default()
                            },
                        ),
                    ),
                    aggregations: vec![
                        pb::structured_aggregation_query::Aggregation {
                            alias: "count".to_owned(),
                            operator: Some(
                                pb::structured_aggregation_query::aggregation::Operator::Count(
                                    pb::structured_aggregation_query::aggregation::Count {
                                        up_to: None,
                                    },
                                ),
                            ),
                        },
                        pb::structured_aggregation_query::Aggregation {
                            alias: "sum".to_owned(),
                            operator: Some(
                                pb::structured_aggregation_query::aggregation::Operator::Sum(
                                    pb::structured_aggregation_query::aggregation::Sum {
                                        field: Some(sq::FieldReference {
                                            field_path: "v".to_owned(),
                                        }),
                                    },
                                ),
                            ),
                        },
                    ],
                },
            ),
        ),
        ..Default::default()
    };
    let mut stream = client
        .run_aggregation_query(agg)
        .await
        .unwrap()
        .into_inner();
    let result = stream.next().await.unwrap().unwrap().result.unwrap();
    assert_eq!(result.aggregate_fields.get("count"), Some(&i(2)));
    assert_eq!(result.aggregate_fields.get("sum"), Some(&i(3)));

    // The strict gateway still applies in local mode: a two-field equality query needs an index.
    let needs_index = query(
        "n",
        Some(sq::Filter {
            filter_type: Some(sq::filter::FilterType::CompositeFilter(
                sq::CompositeFilter {
                    op: sq::composite_filter::Operator::And as i32,
                    filters: vec![field_eq("v", i(1)), field_eq("w", i(2))],
                },
            )),
        }),
    );
    let err = client.run_query(needs_index).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    handle.abort();
}

fn agg_count(collection: &str, alias: &str) -> pb::StructuredAggregationQuery {
    pb::StructuredAggregationQuery {
        query_type: Some(
            pb::structured_aggregation_query::QueryType::StructuredQuery(pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: collection.to_owned(),
                    all_descendants: false,
                }],
                ..Default::default()
            }),
        ),
        aggregations: vec![pb::structured_aggregation_query::Aggregation {
            alias: alias.to_owned(),
            operator: Some(
                pb::structured_aggregation_query::aggregation::Operator::Count(
                    pb::structured_aggregation_query::aggregation::Count { up_to: None },
                ),
            ),
        }],
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn malformed_wire_shapes_are_rejected_before_any_mutation() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("w/1", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();

    // A present but empty precondition must not become an unconditional delete.
    let err = client
        .delete_document(pb::DeleteDocumentRequest {
            name: format!("{DOCS}/w/1"),
            current_document: Some(pb::Precondition {
                condition_type: None,
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/w/1"),
            ..Default::default()
        })
        .await
        .is_ok());

    // Document names must belong to the request database.
    let foreign = "projects/demo-app/databases/other/documents/w/2";
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: foreign.to_owned(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let err = client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![foreign.to_owned()],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // A transaction token is bound to the database that issued it.
    let other_txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: "projects/demo-app/databases/other".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![],
            transaction: other_txn,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // BatchWrite rejects duplicate targets as a whole.
    let err = client
        .batch_write(pb::BatchWriteRequest {
            database: DB.to_owned(),
            writes: vec![
                update_write("w/3", &[("v", i(1))]),
                update_write("w/3", &[("v", i(2))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let err = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/w/3"),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    // Empty document transforms and unspecified server values are malformed.
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Transform(pb::DocumentTransform {
                    document: format!("{DOCS}/w/4"),
                    field_transforms: vec![],
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // Aggregation aliases must be unique.
    let mut dup = agg_count("w", "n");
    dup.aggregations.push(dup.aggregations[0].clone());
    let err = client
        .run_aggregation_query(pb::RunAggregationQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(dup),
            ),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    handle.abort();
}

#[tokio::test]
async fn new_transaction_queries_and_aggregations_read_the_snapshot() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("snap/1", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let mut req = query("snap", None);
    req.consistency_selector = Some(pb::run_query_request::ConsistencySelector::NewTransaction(
        pb::TransactionOptions {
            mode: Some(pb::transaction_options::Mode::ReadWrite(
                pb::transaction_options::ReadWrite {
                    retry_transaction: vec![],
                    ..Default::default()
                },
            )),
        },
    ));
    let mut stream = client.run_query(req).await.unwrap().into_inner();
    let first = stream.next().await.unwrap().unwrap();
    assert!(
        first.document.is_none(),
        "the first response only carries the transaction"
    );
    assert!(!first.transaction.is_empty());
    let txn = first.transaction.clone();
    let second = stream.next().await.unwrap().unwrap();
    assert!(second.document.is_some());
    assert!(second.transaction.is_empty());
    assert!(stream.next().await.is_none());

    // A concurrent insert is invisible to the transaction's aggregation and aborts its commit.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("snap/2", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let mut stream = client
        .run_aggregation_query(pb::RunAggregationQueryRequest {
            parent: DOCS.to_owned(),
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    agg_count("snap", "n"),
                ),
            ),
            consistency_selector: Some(
                pb::run_aggregation_query_request::ConsistencySelector::Transaction(txn.clone()),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let result = stream.next().await.unwrap().unwrap().result.unwrap();
    assert_eq!(result.aggregate_fields.get("n"), Some(&i(1)));
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("snap/3", &[("v", i(3))])],
            transaction: txn,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Aborted);

    // An empty BatchGet with new_transaction still returns the token.
    let mut stream = client
        .batch_get_documents(pb::BatchGetDocumentsRequest {
            database: DB.to_owned(),
            documents: vec![],
            consistency_selector: Some(
                pb::batch_get_documents_request::ConsistencySelector::NewTransaction(
                    pb::TransactionOptions::default(),
                ),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let only = stream.next().await.unwrap().unwrap();
    assert!(!only.transaction.is_empty());
    assert!(only.result.is_none());
    handle.abort();
}
