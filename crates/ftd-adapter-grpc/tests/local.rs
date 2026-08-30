//! End-to-end local execution through a real tonic client: documents, queries, transactions,
//! aggregations and batch writes on the virtual clock.

// `tonic::Status` is the error type of the backend's own closures.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::service::GatewayService;
use ftd_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::Clock;
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

async fn start_with_edition(
    edition: FirestoreEdition,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    Arc<Mutex<VirtualClock>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        ctx: PlanningContext {
            edition,
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

#[tokio::test]
async fn list_documents_pages_by_name_with_opaque_tokens() {
    let (mut client, _clock, handle) = start().await;
    let writes: Vec<pb::Write> = (0..5i64)
        .map(|n| update_write(&format!("pg/d{n}"), &[("v", i(n))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let mut token = String::new();
    let mut seen = Vec::new();
    loop {
        let page = client
            .list_documents(pb::ListDocumentsRequest {
                parent: DOCS.to_owned(),
                collection_id: "pg".to_owned(),
                page_size: 2,
                page_token: token.clone(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        seen.extend(page.documents.iter().map(|d| d.name.clone()));
        if page.next_page_token.is_empty() {
            break;
        }
        token = page.next_page_token;
    }
    assert_eq!(seen.len(), 5);
    assert!(
        seen.windows(2).all(|w| w[0] < w[1]),
        "listed by name: {seen:?}"
    );
    let err = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "pg".to_owned(),
            page_token: "not-a-token".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    handle.abort();
}

#[tokio::test]
async fn verify_writes_check_preconditions_without_changing_anything() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("vf/a", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let verify = |exists: bool| pb::Write {
        operation: Some(pb::write::Operation::Verify(format!("{DOCS}/vf/a"))),
        current_document: Some(pb::Precondition {
            condition_type: Some(pb::precondition::ConditionType::Exists(exists)),
        }),
        ..Default::default()
    };
    // A transaction that read vf/a and writes vf/b sends a verify for vf/a.
    let response = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![verify(true), update_write("vf/b", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.write_results.len(), 2);
    assert!(response.write_results[0].update_time.is_none());
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![verify(false)],
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists);
    let doc = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/vf/a"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(doc.fields.get("v"), Some(&i(1)), "verify changed nothing");
    handle.abort();
}

#[tokio::test]
async fn read_time_selectors_serve_historical_snapshots() {
    let (mut client, clock, handle) = start().await;
    let t0 = clock.lock().unwrap().now();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("hist/a", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let t1 = clock.lock().unwrap().now();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(60))
        .unwrap();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("hist/a", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let at = |t: LogicalInstant| {
        Some(pb::get_document_request::ConsistencySelector::ReadTime(
            ftd_adapter_grpc::encode::encode_instant(t),
        ))
    };
    let old = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/hist/a"),
            consistency_selector: at(t1),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(old.fields.get("v"), Some(&i(1)));
    let before = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/hist/a"),
            consistency_selector: at(LogicalInstant::from_nanos(t0.as_nanos() - 1_000)),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(before.code(), tonic::Code::NotFound);
    let mut q = query("hist", None);
    q.consistency_selector = Some(pb::run_query_request::ConsistencySelector::ReadTime(
        ftd_adapter_grpc::encode::encode_instant(t1),
    ));
    let docs = collect_docs(&mut client, q).await;
    assert_eq!(docs[0].fields.get("v"), Some(&i(1)));
    handle.abort();
}

#[tokio::test]
async fn list_documents_inside_a_transaction_records_the_scan() {
    let (mut client, _clock, handle) = start().await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("scan/a", &[("v", i(1))])],
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
    let listed = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "scan".to_owned(),
            consistency_selector: Some(
                pb::list_documents_request::ConsistencySelector::Transaction(txn.clone()),
            ),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.documents.len(), 1);
    // A document added to the scanned collection after the read aborts the transaction.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("scan/b", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let err = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("scan/a", &[("v", i(3))])],
            transaction: txn,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Aborted);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn read_time_selectors_are_validated_and_read_only_transactions_can_start_at_one() {
    let (mut client, clock, handle) = start().await;
    let first = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("rt/a", &[("v", i(1))])],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .commit_time
        .unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(10))
        .unwrap();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![update_write("rt/a", &[("v", i(2))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let get_at = |ts: prost_types::Timestamp| pb::GetDocumentRequest {
        name: format!("{DOCS}/rt/a"),
        consistency_selector: Some(pb::get_document_request::ConsistencySelector::ReadTime(ts)),
        ..Default::default()
    };
    // Sub-microsecond precision, the future and the distant past are rejected.
    for (ts, what) in [
        (
            prost_types::Timestamp {
                seconds: first.seconds,
                nanos: first.nanos + 1,
            },
            "nanosecond precision",
        ),
        (
            prost_types::Timestamp {
                seconds: first.seconds + 3600,
                nanos: 0,
            },
            "future",
        ),
        (
            prost_types::Timestamp {
                seconds: first.seconds - 7200,
                nanos: 0,
            },
            "older than the retention window",
        ),
        (
            prost_types::Timestamp {
                seconds: first.seconds,
                nanos: 1_000_000_000,
            },
            "nanos out of range",
        ),
    ] {
        let err = client.get_document(get_at(ts)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{what}");
    }
    // An empty transaction token is not "no transaction".
    let err = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/rt/a"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                Vec::new(),
            )),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // A read-only transaction at the first commit time reads that snapshot.
    let txn = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadOnly(
                    pb::transaction_options::ReadOnly {
                        consistency_selector: Some(
                            pb::transaction_options::read_only::ConsistencySelector::ReadTime(
                                first,
                            ),
                        ),
                    },
                )),
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    let doc = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/rt/a"),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                txn.clone(),
            )),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(doc.fields.get("v"), Some(&i(1)));
    // The same through `new_transaction` on a query.
    let mut q = query("rt", None);
    q.consistency_selector = Some(pb::run_query_request::ConsistencySelector::NewTransaction(
        pb::TransactionOptions {
            mode: Some(pb::transaction_options::Mode::ReadOnly(
                pb::transaction_options::ReadOnly {
                    consistency_selector: Some(
                        pb::transaction_options::read_only::ConsistencySelector::ReadTime(first),
                    ),
                },
            )),
        },
    ));
    let docs = collect_docs(&mut client, q).await;
    assert_eq!(docs[0].fields.get("v"), Some(&i(1)));
    handle.abort();
}

#[tokio::test]
async fn list_page_tokens_are_bound_to_their_listing() {
    let (mut client, _clock, handle) = start().await;
    let writes = (0..3)
        .map(|n| update_write(&format!("pg/{n}"), &[("v", i(n))]))
        .collect();
    let committed = client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let page = client
        .list_documents(pb::ListDocumentsRequest {
            parent: DOCS.to_owned(),
            collection_id: "pg".to_owned(),
            page_size: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!page.next_page_token.is_empty());
    let continued = |token: String, collection: &str, selector| pb::ListDocumentsRequest {
        parent: DOCS.to_owned(),
        collection_id: collection.to_owned(),
        page_size: 1,
        page_token: token,
        consistency_selector: selector,
        ..Default::default()
    };
    assert!(client
        .list_documents(continued(page.next_page_token.clone(), "pg", None))
        .await
        .is_ok());
    let err = client
        .list_documents(continued(page.next_page_token.clone(), "other", None))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let err = client
        .list_documents(continued(
            page.next_page_token,
            "pg",
            Some(pb::list_documents_request::ConsistencySelector::ReadTime(
                committed.commit_time.unwrap(),
            )),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    handle.abort();
}

#[tokio::test]
async fn database_snapshots_restore_documents_and_start_a_new_epoch() {
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
    let backend = LocalBackend::new(gateway, clock, 7);
    let write = |name: &str, v: i64| pb::CommitRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        writes: vec![update_write(name, &[("v", i(v))])],
        ..Default::default()
    };
    backend.commit(&write("snap/a", 1)).unwrap();
    let taken = backend.snapshot_databases();
    assert_eq!(taken.len(), 1);
    backend.commit(&write("snap/a", 2)).unwrap();
    backend.commit(&write("snap/b", 1)).unwrap();
    let epoch = backend.epoch();
    backend.restore_databases(taken);
    assert_eq!(backend.epoch(), epoch + 1, "a restore is a new epoch");
    let get = |name: &str| pb::GetDocumentRequest {
        name: format!("projects/demo-app/databases/(default)/documents/{name}"),
        ..Default::default()
    };
    let a = backend
        .get_document(&get("snap/a"), &ftd_adapter_grpc::rules::allow_all_reads)
        .unwrap();
    assert_eq!(
        a.fields["v"].value_type,
        Some(pb::value::ValueType::IntegerValue(1))
    );
    assert_eq!(
        backend
            .get_document(&get("snap/b"), &ftd_adapter_grpc::rules::allow_all_reads)
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    // The restored state keeps committing.
    backend.commit(&write("snap/c", 1)).unwrap();
    assert!(backend
        .get_document(&get("snap/c"), &ftd_adapter_grpc::rules::allow_all_reads)
        .is_ok());
}

#[tokio::test]
async fn fault_plans_fail_the_nth_commit_and_time_out_reads() {
    use ftd_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
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
    let backend = LocalBackend::new(gateway, clock.clone(), 7);
    let registry = Arc::new(ftd_core_session::fault::FaultRegistry::new());
    let faults = registry.default_state();
    faults.lock().unwrap().install(FaultPlan {
        seed: 1,
        rules: vec![
            FaultRule {
                matches: FaultMatch {
                    operation: "firestore.commit".into(),
                    nth: Some(2),
                    function: None,
                    event_type: None,
                },
                action: FaultAction::ReturnError {
                    code: "ABORTED".into(),
                },
            },
            FaultRule {
                matches: FaultMatch {
                    operation: "firestore.read".into(),
                    nth: Some(1),
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Timeout,
            },
            FaultRule {
                matches: FaultMatch {
                    operation: "firestore.commit".into(),
                    nth: Some(3),
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Delay { seconds: 90 },
            },
        ],
    });
    backend.set_faults(registry.clone());
    let write = |name: &str, v: i64| pb::CommitRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        writes: vec![update_write(name, &[("v", i(v))])],
        ..Default::default()
    };
    assert!(backend.commit(&write("f/a", 1)).is_ok());
    let err = backend.commit(&write("f/b", 1)).unwrap_err();
    assert_eq!(err.code(), tonic::Code::Aborted);
    assert!(err.message().contains("fault plan"));
    // The third commit is delayed: the clock moved 90 s before it ran.
    let before = clock.lock().unwrap().now_for_test();
    assert!(backend.commit(&write("f/c", 1)).is_ok());
    let after = clock.lock().unwrap().now_for_test();
    assert_eq!(after.as_nanos() - before.as_nanos(), 90 * 1_000_000_000);
    let get = |name: &str| pb::GetDocumentRequest {
        name: format!("projects/demo-app/databases/(default)/documents/{name}"),
        ..Default::default()
    };
    assert_eq!(
        backend
            .get_document(&get("f/a"), &ftd_adapter_grpc::rules::allow_all_reads)
            .unwrap_err()
            .code(),
        tonic::Code::DeadlineExceeded
    );
    assert!(backend
        .get_document(&get("f/a"), &ftd_adapter_grpc::rules::allow_all_reads)
        .is_ok());
    let fired = faults.lock().unwrap().fired().len();
    assert_eq!(fired, 3);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn execute_pipeline_is_validated_strictly_and_never_executed() {
    // Typed arguments: a collection path, a boolean function, an integer.
    let stage = |name: &str, args: usize| pb::pipeline::Stage {
        name: name.to_owned(),
        args: (0..args)
            .map(|_| match name {
                "collection" => pb::Value {
                    value_type: Some(pb::value::ValueType::ReferenceValue("/users".to_owned())),
                },
                "where" => pb::Value {
                    value_type: Some(pb::value::ValueType::FunctionValue(pb::Function {
                        name: "eq".to_owned(),
                        args: vec![
                            pb::Value {
                                value_type: Some(pb::value::ValueType::FieldReferenceValue(
                                    "age".to_owned(),
                                )),
                            },
                            i(3),
                        ],
                        options: std::collections::HashMap::default(),
                    })),
                },
                "limit" => i(5),
                _ => s("x"),
            })
            .collect(),
        options: std::collections::HashMap::default(),
    };
    let request = |stages: Vec<pb::pipeline::Stage>| pb::ExecutePipelineRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline { stages }),
                    options: std::collections::HashMap::default(),
                },
            ),
        ),
        ..Default::default()
    };
    // Standard edition: pipelines are an Enterprise feature.
    let (mut client, _, handle) = start().await;
    let err = client
        .execute_pipeline(request(vec![stage("collection", 1)]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(err.metadata().get("ftd-code").unwrap(), "FS_PIPE_EDITION");
    handle.abort();
    // Enterprise: decoded, canonicalized, refused explicitly or answered validation-only.
    let (mut client, _, handle) = start_with_edition(FirestoreEdition::Enterprise).await;
    let valid = client
        .execute_pipeline(request(vec![
            stage("collection", 1),
            stage("where", 1),
            stage("limit", 1),
        ]))
        .await
        .unwrap_err();
    assert_eq!(valid.code(), tonic::Code::Unimplemented);
    assert_eq!(
        valid.metadata().get("ftd-pipeline").unwrap(),
        "collection(1) | where(1) | limit(1)"
    );
    assert_eq!(
        valid.metadata().get("ftd-code").unwrap(),
        "FS_PIPE_VALIDATION_ONLY"
    );
    let unknown = client
        .execute_pipeline(request(vec![stage("collection", 1), stage("explode", 1)]))
        .await
        .unwrap_err();
    assert_eq!(unknown.code(), tonic::Code::Unimplemented);
    assert_eq!(
        unknown.metadata().get("ftd-code").unwrap(),
        "FS_PIPE_UNSUPPORTED_STAGE"
    );
    let write = client
        .execute_pipeline(request(vec![stage("collection", 1), stage("update", 1)]))
        .await
        .unwrap_err();
    assert_eq!(write.metadata().get("ftd-code").unwrap(), "FS_PIPE_WRITE_0");
    let misplaced = client
        .execute_pipeline(request(vec![stage("where", 1)]))
        .await
        .unwrap_err();
    assert_eq!(misplaced.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        misplaced.metadata().get("ftd-code").unwrap(),
        "FS_PIPE_INVALID"
    );
    let empty = client
        .execute_pipeline(pb::ExecutePipelineRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(empty.metadata().get("ftd-code").unwrap(), "FS_PIPE_DECODE");
    // Strict: argument shapes, option keys, the database name and the consistency
    // selector are checked, not only stage names and arities.
    let typed = |name: &str, value: pb::Value| pb::pipeline::Stage {
        name: name.to_owned(),
        args: vec![value],
        options: std::collections::HashMap::default(),
    };
    for (what, bad) in [
        (
            "limit(text)",
            request(vec![stage("collection", 1), typed("limit", s("text"))]),
        ),
        (
            "collection(null)",
            request(vec![typed("collection", pb::Value { value_type: None })]),
        ),
        (
            "collection(document path)",
            request(vec![typed("collection", s("/users/u1"))]),
        ),
        (
            "where(string)",
            request(vec![stage("collection", 1), typed("where", s("x"))]),
        ),
        (
            "unknown option",
            request(vec![
                stage("collection", 1),
                pb::pipeline::Stage {
                    name: "sample".to_owned(),
                    args: vec![i(3)],
                    options: [("speed".to_owned(), s("fast"))].into_iter().collect(),
                },
            ]),
        ),
        (
            "garbage database",
            pb::ExecutePipelineRequest {
                database: "garbage".to_owned(),
                ..request(vec![stage("collection", 1)])
            },
        ),
        (
            "pipeline option",
            pb::ExecutePipelineRequest {
                pipeline_type: Some(
                    pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                        pb::StructuredPipeline {
                            pipeline: Some(pb::Pipeline {
                                stages: vec![stage("collection", 1)],
                            }),
                            options: [("turbo".to_owned(), s("on"))].into_iter().collect(),
                        },
                    ),
                ),
                ..request(vec![])
            },
        ),
        (
            "auto-commit without a new transaction",
            pb::ExecutePipelineRequest {
                auto_commit_transaction: true,
                ..request(vec![stage("collection", 1)])
            },
        ),
    ] {
        let err = client.execute_pipeline(bad).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{what}: {err}");
        assert_eq!(
            err.metadata().get("ftd-code").unwrap(),
            "FS_PIPE_INVALID",
            "{what}"
        );
    }
    handle.abort();
}

#[tokio::test]
async fn scoped_resets_and_partition_tokens_respect_project_ownership() {
    use ftd_core_session::tenancy::Scope;
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
    let backend = LocalBackend::new(gateway, clock, 7);
    let write = |project: &str, name: &str| pb::CommitRequest {
        database: format!("projects/{project}/databases/(default)"),
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: format!("projects/{project}/databases/(default)/documents/{name}"),
                fields: [("v".to_owned(), i(1))].into_iter().collect(),
                create_time: None,
                update_time: None,
            })),
            ..Default::default()
        }],
        ..Default::default()
    };
    for project in ["demo-a", "demo-b"] {
        for n in 0..4 {
            backend
                .commit_with(
                    &write(project, &format!("owners/o{n}/items/i{n}")),
                    &ftd_adapter_grpc::rules::allow_all,
                )
                .unwrap();
        }
    }
    let count = |project: &str| {
        let parent = ftd_adapter_grpc::decode::parse_parent(&format!(
            "projects/{project}/databases/(default)/documents"
        ))
        .unwrap();
        backend
            .read_unadmitted(&parent, |db| db.current_version().value())
            .unwrap_or(0)
    };
    assert_eq!(count("demo-a"), 4);
    // A partition page token is bound to the reset epoch and database generation.
    let partition = |project: &str, token: &str| pb::PartitionQueryRequest {
        parent: format!("projects/{project}/databases/(default)/documents"),
        partition_count: 3,
        page_size: 1,
        page_token: token.to_owned(),
        query_type: Some(pb::partition_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: "items".to_owned(),
                    all_descendants: true,
                }],
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let first = backend.partition_query(&partition("demo-b", "")).unwrap();
    assert!(!first.next_page_token.is_empty());
    assert!(backend
        .partition_query(&partition("demo-b", &first.next_page_token))
        .is_ok());
    // The default session's reset leaves the registered project demo-b alone.
    backend.reset_scope(&Scope::AllExcept(
        ["demo-b".to_owned()].into_iter().collect(),
    ));
    assert_eq!(count("demo-a"), 0);
    assert_eq!(count("demo-b"), 4);
    // Its epoch moved: demo-b's token is refused too (the history it named is gone).
    let err = backend
        .partition_query(&partition("demo-b", &first.next_page_token))
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    let again = backend.partition_query(&partition("demo-b", "")).unwrap();
    backend.reset_scope(&Scope::Project("demo-b".to_owned()));
    assert_eq!(count("demo-b"), 0);
    // A project reset bumps only that database's generation: the token is refused.
    for n in 0..4 {
        backend
            .commit_with(
                &write("demo-b", &format!("owners/o{n}/items/i{n}")),
                &ftd_adapter_grpc::rules::allow_all,
            )
            .unwrap();
    }
    assert!(backend
        .partition_query(&partition("demo-b", &again.next_page_token))
        .is_err());
    // Snapshots are scoped the same way.
    let snapshot = backend.snapshot_scope(&Scope::Project("demo-b".to_owned()));
    assert_eq!(snapshot.databases.len(), 1);
    assert!(snapshot.ids.is_none());
    backend.reset_scope(&Scope::Project("demo-b".to_owned()));
    backend.restore_scope(&Scope::Project("demo-b".to_owned()), &snapshot);
    assert_eq!(count("demo-b"), 4);
    assert!(backend
        .snapshot_scope(&Scope::AllExcept(std::collections::BTreeSet::new()))
        .ids
        .is_some());
}

// ---------------------------------------------------------------------------------------
// Database lock isolation (FS-LOCK-01 .. FS-LOCK-06)
//
// The backend keeps one lock per database and holds the catalog lock only long enough to
// find an entry, so unrelated databases run concurrently while one database stays
// serialized. These tests pin an operation inside its critical section (through the change
// sink or through its write guard) and observe what other operations can do meanwhile.
// ---------------------------------------------------------------------------------------

use ftd_adapter_grpc::local::{Actor, CommitEvent};
use ftd_adapter_grpc::rules::allow_all;
use ftd_core_firestore::store::{FirestoreState, Write};
use ftd_core_session::tenancy::Scope;

/// How long a test waits for something that must happen.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a test waits to convince itself that something does not happen.
const BRIEF: std::time::Duration = std::time::Duration::from_millis(250);

/// A rendezvous the change sink or a write guard blocks on, so a test can pin operations
/// inside their database critical sections.
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    signal: std::sync::Condvar,
}

#[derive(Default)]
struct GateState {
    arrived: usize,
    open: bool,
}

impl Gate {
    /// Records an arrival and blocks until [`Gate::open`].
    fn hold(&self) {
        let mut state = self.state.lock().unwrap();
        state.arrived += 1;
        self.signal.notify_all();
        while !state.open {
            let (next, timeout) = self.signal.wait_timeout(state, PATIENCE).unwrap();
            assert!(!timeout.timed_out(), "the gate was never opened");
            state = next;
        }
    }

    /// Records an arrival and blocks until `n` operations wait here: it only completes if
    /// they really do hold their databases at the same time.
    fn rendezvous(&self, n: usize) {
        let mut state = self.state.lock().unwrap();
        state.arrived += 1;
        self.signal.notify_all();
        while state.arrived < n {
            let (next, timeout) = self.signal.wait_timeout(state, PATIENCE).unwrap();
            assert!(
                !timeout.timed_out(),
                "{n} operations never held their databases at the same time"
            );
            state = next;
        }
    }

    /// Waits until `n` operations are held at the gate.
    fn wait_for(&self, n: usize) {
        let mut state = self.state.lock().unwrap();
        while state.arrived < n {
            let (next, timeout) = self.signal.wait_timeout(state, PATIENCE).unwrap();
            assert!(!timeout.timed_out(), "no operation reached the gate");
            state = next;
        }
    }

    fn open(&self) {
        let mut state = self.state.lock().unwrap();
        state.open = true;
        self.signal.notify_all();
    }
}

fn lock_test_backend() -> Arc<LocalBackend> {
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
    Arc::new(LocalBackend::new(gateway, clock, 11))
}

fn lock_test_commit(project: &str, document: &str) -> pb::CommitRequest {
    pb::CommitRequest {
        database: format!("projects/{project}/databases/(default)"),
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: format!("projects/{project}/databases/(default)/documents/{document}"),
                fields: [("v".to_owned(), i(1))].into_iter().collect(),
                create_time: None,
                update_time: None,
            })),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn lock_test_parent(project: &str) -> ftd_adapter_grpc::decode::Parent {
    ftd_adapter_grpc::decode::parse_parent(&format!(
        "projects/{project}/databases/(default)/documents"
    ))
    .unwrap()
}

/// The database's current version, or `None` when the catalog has no such database.
fn lock_test_version(backend: &LocalBackend, project: &str) -> Option<u64> {
    backend.read_unadmitted(&lock_test_parent(project), |db| {
        db.current_version().value()
    })
}

/// Installs a change sink that holds the first commit of `project` at the gate and records
/// every event it sees.
fn hold_first_commit(
    backend: &LocalBackend,
    project: &'static str,
    gate: &Arc<Gate>,
    seen: &Arc<Mutex<Vec<(String, u64)>>>,
) {
    let gate = gate.clone();
    let seen = seen.clone();
    let held = std::sync::atomic::AtomicBool::new(false);
    backend.set_change_sink(Arc::new(move |event: &CommitEvent| {
        seen.lock()
            .unwrap()
            .push((event.project.clone(), event.version));
        if event.project == project && !held.swap(true, std::sync::atomic::Ordering::SeqCst) {
            gate.hold();
        }
    }));
}

/// FS-LOCK-01: a commit pinned inside one project's database does not keep another
/// project's commit out.
#[test]
fn a_held_operation_in_one_project_does_not_block_another() {
    let backend = lock_test_backend();
    let gate = Arc::new(Gate::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    hold_first_commit(&backend, "demo-held", &gate, &seen);

    let holder = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            backend
                .commit_with(&lock_test_commit("demo-held", "items/a"), &allow_all)
                .unwrap();
        })
    };
    gate.wait_for(1);

    let (done, finished) = std::sync::mpsc::channel();
    let other = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            let outcome =
                backend.commit_with(&lock_test_commit("demo-free", "items/b"), &allow_all);
            done.send(outcome.is_ok()).unwrap();
        })
    };
    assert_eq!(
        finished.recv_timeout(PATIENCE),
        Ok(true),
        "a commit in another project queued behind the held database"
    );

    gate.open();
    holder.join().unwrap();
    other.join().unwrap();
    assert_eq!(lock_test_version(&backend, "demo-held"), Some(1));
    assert_eq!(lock_test_version(&backend, "demo-free"), Some(1));
}

/// FS-LOCK-02: two commits to one database stay serialized and are published in commit
/// order.
#[test]
fn commits_to_one_database_stay_serialized() {
    let backend = lock_test_backend();
    let gate = Arc::new(Gate::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    hold_first_commit(&backend, "demo-serial", &gate, &seen);

    let first = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            backend
                .commit_with(&lock_test_commit("demo-serial", "items/a"), &allow_all)
                .unwrap();
        })
    };
    gate.wait_for(1);

    let (done, finished) = std::sync::mpsc::channel();
    let second = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            backend
                .commit_with(&lock_test_commit("demo-serial", "items/b"), &allow_all)
                .unwrap();
            done.send(()).unwrap();
        })
    };
    assert!(
        finished.recv_timeout(BRIEF).is_err(),
        "a second commit entered the database while the first one held it"
    );

    gate.open();
    assert!(finished.recv_timeout(PATIENCE).is_ok());
    first.join().unwrap();
    second.join().unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![("demo-serial".to_owned(), 1), ("demo-serial".to_owned(), 2)],
        "the two commits of one database were not published in commit order"
    );
    assert_eq!(lock_test_version(&backend, "demo-serial"), Some(2));
}

/// FS-LOCK-05: two commits that hold different databases at the same time each publish
/// their own principal, whatever order they were staged and released in.
#[test]
fn concurrent_commits_in_different_databases_keep_their_own_actor() {
    let backend = lock_test_backend();
    let gate = Arc::new(Gate::default());
    let seen: Arc<Mutex<Vec<(String, Actor)>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let seen = seen.clone();
        backend.set_change_sink(Arc::new(move |event: &CommitEvent| {
            seen.lock()
                .unwrap()
                .push((event.project.clone(), event.actor.clone()));
        }));
    }

    let commit_as = |project: &'static str, uid: &'static str| {
        let backend = backend.clone();
        let gate = gate.clone();
        std::thread::spawn(move || {
            let staging = backend.clone();
            let actor = Actor {
                auth_type: "app_user".to_owned(),
                auth_id: Some(uid.to_owned()),
            };
            // Both guards stage their principal and only then meet here, so each commit
            // runs with the other's principal already staged.
            let guard = move |_: &FirestoreState,
                              _: &[Write],
                              _: LogicalInstant|
                  -> Result<(), tonic::Status> {
                staging.set_actor(actor.clone());
                gate.rendezvous(2);
                Ok(())
            };
            backend
                .commit_with(&lock_test_commit(project, "items/a"), &guard)
                .unwrap();
        })
    };
    let alice = commit_as("demo-p1", "alice");
    let bob = commit_as("demo-p2", "bob");
    alice.join().unwrap();
    bob.join().unwrap();

    let mut published = seen.lock().unwrap().clone();
    published.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        published,
        vec![
            (
                "demo-p1".to_owned(),
                Actor {
                    auth_type: "app_user".to_owned(),
                    auth_id: Some("alice".to_owned()),
                }
            ),
            (
                "demo-p2".to_owned(),
                Actor {
                    auth_type: "app_user".to_owned(),
                    auth_id: Some("bob".to_owned()),
                }
            ),
        ]
    );
}

/// FS-LOCK-04: a database dropped by a reset or replaced by a restore cannot be reached
/// through a handle retained across it.
#[test]
fn a_reset_or_restore_detaches_retained_database_handles() {
    let backend = lock_test_backend();
    backend
        .commit_with(&lock_test_commit("demo-detach", "items/a"), &allow_all)
        .unwrap();
    let parent = lock_test_parent("demo-detach");
    let handle = backend.database_handle(&parent).unwrap();
    assert_eq!(
        handle.with(|db| Ok(db.current_version().value())).unwrap(),
        1
    );

    backend.reset_scope(&Scope::Project("demo-detach".to_owned()));
    assert!(handle.is_detached());
    assert_eq!(
        handle
            .with(|db| Ok(db.current_version().value()))
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert!(
        lock_test_version(&backend, "demo-detach").is_none(),
        "the reset left the wiped database in the catalog"
    );

    // The catalog serves a fresh, empty database under the same name.
    let fresh = backend.database_handle(&parent).unwrap();
    assert_eq!(
        fresh.with(|db| Ok(db.current_version().value())).unwrap(),
        0
    );

    // A restore retires the database it replaced the same way.
    backend
        .commit_with(&lock_test_commit("demo-detach", "items/b"), &allow_all)
        .unwrap();
    let snapshot = backend.snapshot_scope(&Scope::Project("demo-detach".to_owned()));
    backend.restore_scope(&Scope::Project("demo-detach".to_owned()), &snapshot);
    assert!(fresh.is_detached());
    assert_eq!(
        fresh.with(|_| Ok(())).unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert_eq!(lock_test_version(&backend, "demo-detach"), Some(1));
}

/// FS-LOCK-03: a reset taken under the exclusive barrier waits for the operation it races
/// and then starts a new epoch (ADR-011).
#[test]
fn a_reset_waits_for_the_operation_it_races() {
    let backend = lock_test_backend();
    let gate = Arc::new(Gate::default());
    let seen = Arc::new(Mutex::new(Vec::new()));
    hold_first_commit(&backend, "demo-race", &gate, &seen);
    let epoch_before = backend.epoch();

    let holder = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            backend
                .commit_with(&lock_test_commit("demo-race", "items/a"), &allow_all)
                .unwrap();
        })
    };
    gate.wait_for(1);

    let (done, finished) = std::sync::mpsc::channel();
    let resetter = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            let barrier = backend.barrier();
            let _exclusive = barrier.exclusive();
            backend.reset();
            done.send(()).unwrap();
        })
    };
    assert!(
        finished.recv_timeout(BRIEF).is_err(),
        "the reset did not wait for the commit that was in flight"
    );

    gate.open();
    assert!(finished.recv_timeout(PATIENCE).is_ok());
    holder.join().unwrap();
    resetter.join().unwrap();
    assert_eq!(backend.epoch(), epoch_before + 1);
    assert_eq!(lock_test_version(&backend, "demo-race"), None);
    // The commit that was in flight was published whole, before the reset's wipe.
    assert_eq!(
        seen.lock().unwrap().first(),
        Some(&("demo-race".to_owned(), 1))
    );
}

/// FS-LOCK-06: capture and restore under the exclusive barrier keep every database of the
/// scope consistent, and no operation runs while they do.
#[test]
fn capture_and_restore_stay_atomic_under_the_barrier() {
    let backend = lock_test_backend();
    for project in ["demo-s1", "demo-s2"] {
        backend
            .commit_with(&lock_test_commit(project, "items/a"), &allow_all)
            .unwrap();
    }
    let everything = Scope::AllExcept(std::collections::BTreeSet::new());

    let barrier = backend.barrier();
    let exclusive = barrier.exclusive();
    let (done, finished) = std::sync::mpsc::channel();
    let writer = {
        let backend = backend.clone();
        std::thread::spawn(move || {
            let outcome = backend.commit_with(&lock_test_commit("demo-s1", "items/b"), &allow_all);
            done.send(outcome.is_ok()).unwrap();
        })
    };
    assert!(
        finished.recv_timeout(BRIEF).is_err(),
        "an operation was admitted while a capture held the barrier exclusively"
    );

    let snapshot = backend.snapshot_scope(&everything);
    assert_eq!(snapshot.databases.len(), 2);
    backend.reset();
    backend.restore_scope(&everything, &snapshot);
    drop(exclusive);

    assert_eq!(finished.recv_timeout(PATIENCE), Ok(true));
    writer.join().unwrap();
    // Both databases came back whole, and the waiting commit landed on top of the restore
    // rather than on a half-restored state.
    assert_eq!(lock_test_version(&backend, "demo-s1"), Some(2));
    assert_eq!(lock_test_version(&backend, "demo-s2"), Some(1));
}
