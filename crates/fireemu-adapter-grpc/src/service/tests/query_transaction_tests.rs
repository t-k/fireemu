use super::*;
use fireemu_core_session::tenancy::Scope;
use fireemu_core_types::resources::RootBudget;
use std::collections::BTreeSet;
use tokio_stream::StreamExt;

fn seeded_query(backend: &LocalBackend, count: i64, field_order: bool) -> pb::RunQueryRequest {
    let mut request = query_request();
    backend
        .commit(&pb::CommitRequest {
            database: database_name_from_query_parent(&request.parent),
            writes: (0..count)
                .map(|index| pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{}/items/{index:03}", request.parent),
                        fields: [(
                            "rank".to_owned(),
                            pb::Value {
                                value_type: Some(pb::value::ValueType::IntegerValue(count - index)),
                            },
                        )]
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
    let Some(pb::run_query_request::QueryType::StructuredQuery(query)) = &mut request.query_type
    else {
        unreachable!()
    };
    query.order_by = vec![pb::structured_query::Order {
        field: Some(pb::structured_query::FieldReference {
            field_path: if field_order { "rank" } else { "__name__" }.to_owned(),
        }),
        direction: pb::structured_query::Direction::Ascending as i32,
    }];
    request
}

fn selection_bytes(backend: &LocalBackend) -> u64 {
    backend
        .resources(&Scope::AllExcept(BTreeSet::default()), RootBudget::DEFAULT)
        .unwrap()
        .gauges
        .into_iter()
        .find(|gauge| gauge.id == "queries.ordered_selection_bytes")
        .unwrap()
        .current
}

// The worker pauses after materializing page two and before sending its rows. Dropping
// the stream then exercises cancellation with both a live snapshot and a live selection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_query_multipage_cancellation_preserves_transaction_ownership() {
    for count in [33, 65] {
        for field_order in [false, true] {
            for selector in [
                None,
                Some(new_query_transaction(true)),
                Some(new_query_transaction(false)),
            ] {
                let internal = selector.is_none();
                let backend = test_backend();
                let mut service = GatewayService::local(test_gateway(), backend.clone());
                let mut request = seeded_query(&backend, count, field_order);
                request.consistency_selector = selector;
                let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel();
                let ready_tx = Mutex::new(Some(ready_tx));
                let (release_tx, release_rx) = mpsc::channel();
                let release_rx = Mutex::new(release_rx);
                service.continuation_query_page_ready = Some(Arc::new(move || {
                    if let Some(ready) = ready_tx.lock().unwrap().take() {
                        ready.send(()).unwrap();
                        release_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap();
                    }
                }));
                let mut stream = Firestore::run_query(&service, Request::new(request))
                    .await
                    .unwrap()
                    .into_inner();
                let mut transaction = Vec::new();
                let mut documents = 0;
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        tokio::select! {
                            result = &mut ready_rx => { result.unwrap(); break; }
                            response = stream.next() => {
                                let response = response.unwrap().unwrap();
                                documents += usize::from(response.document.is_some());
                                if !response.transaction.is_empty() {
                                    transaction = response.transaction;
                                }
                            }
                        }
                    }
                })
                .await
                .unwrap();
                assert!(documents > 0 && documents < 32);
                assert_eq!(transaction.is_empty(), internal);
                assert_eq!(
                    backend.latest_query_execution_stats().unwrap().1.page_count,
                    2
                );
                assert_eq!(transaction_stats(&backend).active, 1);
                assert_eq!(selection_bytes(&backend) > 0, field_order);
                drop(stream);
                release_tx.send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(5), async {
                    // Selection accounting and backend references have independent destructors.
                    // Wait for both: no selection remains and no guard can roll back later.
                    while Arc::strong_count(&backend) != 2 || selection_bytes(&backend) != 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("cancelled query must release its backend and selection ownership");
                assert_eq!(selection_bytes(&backend), 0);
                assert_eq!(transaction_stats(&backend).active, usize::from(!internal));
                if !internal {
                    backend
                        .rollback(&pb::RollbackRequest {
                            database: database_name_from_query_parent(&query_request().parent),
                            transaction,
                            ..Default::default()
                        })
                        .unwrap();
                }
                assert_eq!(transaction_stats(&backend).active, 0);
                assert_eq!(transaction_stats(&backend).conflict_ledger_bytes, 0);
            }
        }
    }
}

#[tokio::test]
async fn run_query_multipage_read_write_commits_after_complete_delivery() {
    for count in [33, 65] {
        for field_order in [false, true] {
            let backend = test_backend();
            let service = GatewayService::local(test_gateway(), backend.clone());
            let mut request = seeded_query(&backend, count, field_order);
            request.consistency_selector = Some(new_query_transaction(false));
            let mut stream = Firestore::run_query(&service, Request::new(request))
                .await
                .unwrap()
                .into_inner();
            let mut transaction = Vec::new();
            let mut names = Vec::new();
            let mut completions = 0;
            while let Some(response) = stream.next().await {
                let response = response.unwrap();
                assert_eq!(completions, 0, "Done must be the last response");
                if !response.transaction.is_empty() {
                    assert!(transaction.is_empty());
                    transaction = response.transaction;
                }
                if let Some(document) = response.document {
                    names.push(document.name);
                }
                completions += usize::from(
                    response.continuation_selector
                        == Some(pb::run_query_response::ContinuationSelector::Done(true)),
                );
            }
            assert_eq!(completions, 1);
            let mut expected: Vec<_> = (0..count)
                .map(|index| format!("{}/items/{index:03}", query_request().parent))
                .collect();
            if field_order {
                expected.reverse();
            }
            assert_eq!(names, expected);
            assert!(!transaction.is_empty());
            assert_eq!(transaction_stats(&backend).active, 1);
            let result = Firestore::commit(
                &service,
                Request::new(pb::CommitRequest {
                    database: database_name_from_query_parent(&query_request().parent),
                    transaction,
                    writes: vec![pb::Write {
                        operation: Some(pb::write::Operation::Update(pb::Document {
                            name: format!("{}/results/committed", query_request().parent),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            )
            .await
            .unwrap()
            .into_inner();
            assert_eq!(result.write_results.len(), 1);
            assert!(result.commit_time.is_some());
            assert_eq!(transaction_stats(&backend).active, 0);
            assert_eq!(transaction_stats(&backend).conflict_ledger_bytes, 0);
            assert_eq!(selection_bytes(&backend), 0);
        }
    }
}
