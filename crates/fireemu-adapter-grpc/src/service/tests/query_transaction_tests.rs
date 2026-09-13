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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_pipeline_snapshot_remains_stable_across_page_boundary() {
    let backend = test_backend();
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    let mut service = GatewayService::local(gateway, backend.clone());
    let query = seeded_query(&backend, 65, false);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let ready_tx = Mutex::new(Some(ready_tx));
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    service.first_query_page_ready = Some(Arc::new(move || {
        ready_tx.lock().unwrap().take().unwrap().send(()).unwrap();
        release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
    }));
    let request = pb::ExecutePipelineRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline {
                        stages: vec![pb::pipeline::Stage {
                            name: "collection".to_owned(),
                            args: vec![pb::Value {
                                value_type: Some(pb::value::ValueType::StringValue(
                                    "/items".to_owned(),
                                )),
                            }],
                            ..Default::default()
                        }],
                    }),
                    ..Default::default()
                },
            ),
        ),
        ..Default::default()
    };
    let task = tokio::spawn(async move {
        Firestore::execute_pipeline(&service, Request::new(request))
            .await
            .unwrap()
            .into_inner()
    });
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    backend
        .commit(&pb::CommitRequest {
            database: database_name_from_query_parent(&query.parent),
            writes: vec![
                pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{}/items/000", query.parent),
                        fields: [(
                            "rank".to_owned(),
                            pb::Value {
                                value_type: Some(pb::value::ValueType::IntegerValue(-1)),
                            },
                        )]
                        .into_iter()
                        .collect(),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
                pb::Write {
                    operation: Some(pb::write::Operation::Delete(format!(
                        "{}/items/001",
                        query.parent
                    ))),
                    ..Default::default()
                },
                pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{}/items/999", query.parent),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            ],
            ..Default::default()
        })
        .unwrap();
    release_tx.send(()).unwrap();
    let mut stream = task.await.unwrap();
    let mut names = Vec::new();
    while let Some(response) = stream.next().await {
        let response = response.unwrap();
        names.extend(response.results.into_iter().map(|document| document.fields));
    }
    assert_eq!(names.len(), 65);
    assert!(names.iter().any(|fields| fields.get("rank")
        == Some(&pb::Value {
            value_type: Some(pb::value::ValueType::IntegerValue(64)),
        })));
    assert!(!names.iter().any(std::collections::HashMap::is_empty));
}

fn pipeline_request() -> pb::ExecutePipelineRequest {
    pb::ExecutePipelineRequest {
        database: "projects/demo-app/databases/(default)".to_owned(),
        pipeline_type: Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                pb::StructuredPipeline {
                    pipeline: Some(pb::Pipeline {
                        stages: vec![pb::pipeline::Stage {
                            name: "collection".to_owned(),
                            args: vec![pb::Value {
                                value_type: Some(pb::value::ValueType::StringValue(
                                    "/items".to_owned(),
                                )),
                            }],
                            ..Default::default()
                        }],
                    }),
                    ..Default::default()
                },
            ),
        ),
        ..Default::default()
    }
}

#[tokio::test]
async fn execute_pipeline_records_deterministic_small_and_large_page_stats() {
    for count in [17, 257] {
        let backend = test_backend();
        let mut gateway = test_gateway();
        gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
        let service = GatewayService::local(gateway, backend.clone());
        seeded_query(&backend, count, false);
        let mut stream = Firestore::execute_pipeline(&service, Request::new(pipeline_request()))
            .await
            .unwrap()
            .into_inner();
        let mut returned = 0;
        while let Some(response) = stream.next().await {
            returned += response.unwrap().results.len();
        }
        let (_, stats) = backend.latest_query_execution_stats().unwrap();
        println!(
            "pipeline_stats count={count} returned={returned} pages={} cloned={} field_bytes={} selection_paths={} selection_bytes={}",
            stats.page_count,
            stats.pages.cloned_documents,
            stats.pages.cloned_field_bytes,
            stats.selection_paths,
            stats.selection_bytes,
        );
        assert_eq!(returned, usize::try_from(count).unwrap());
        assert_eq!(stats.pages.cloned_documents, u64::try_from(count).unwrap());
        assert_eq!(stats.page_count, if count == 17 { 1 } else { 9 });
        assert_eq!(stats.selection_paths, 0);
        assert_eq!(stats.selection_bytes, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_pipeline_drop_before_first_delivery_releases_snapshot() {
    let backend = test_backend();
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    let mut service = GatewayService::local(gateway, backend.clone());
    let request = seeded_query(&backend, 33, false);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let ready_tx = Mutex::new(Some(ready_tx));
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    service.first_query_page_ready = Some(Arc::new(move || {
        ready_tx.lock().unwrap().take().unwrap().send(()).unwrap();
        release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
    }));
    let task = tokio::spawn(async move {
        Firestore::execute_pipeline(&service, Request::new(pipeline_request())).await
    });
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transaction_stats_for(&backend, &request.parent).active, 1);
    task.abort();
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while transaction_stats_for(&backend, &request.parent).active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_pipeline_drop_after_first_delivery_releases_selection() {
    let backend = test_backend();
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    let mut service = GatewayService::local(gateway, backend.clone());
    seeded_query(&backend, 65, true);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let ready_tx = Mutex::new(Some(ready_tx));
    service.first_query_page_ready = Some(Arc::new(move || {
        ready_tx.lock().unwrap().take().unwrap().send(()).unwrap();
    }));
    let task = tokio::spawn(async move {
        Firestore::execute_pipeline(&service, Request::new(pipeline_request())).await
    });
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let mut stream = task.await.unwrap().unwrap().into_inner();
    let _ = stream.next().await.unwrap().unwrap();
    drop(stream);
    tokio::time::timeout(Duration::from_secs(5), async {
        while transaction_stats_for(&backend, "projects/demo-app/databases/(default)/documents")
            .active
            != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn failed_commit_keeps_transaction_usable_and_locked_until_rollback() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let database = database_name_from_query_parent(&query_request().parent);
    let document_name = format!("{}/locked/doc", query_request().parent);
    backend
        .commit(&pb::CommitRequest {
            database: database.clone(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: document_name.clone(),
                    fields: [(
                        "value".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::IntegerValue(1)),
                        },
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();

    let transaction = backend
        .begin_transaction(&pb::BeginTransactionRequest {
            database: database.clone(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
            ..Default::default()
        })
        .unwrap();
    Firestore::get_document(
        &service,
        Request::new(pb::GetDocumentRequest {
            name: document_name.clone(),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                transaction.clone(),
            )),
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    let invalid = "x".repeat(1_048_488);
    let failed = Firestore::commit(
        &service,
        Request::new(pb::CommitRequest {
            database: database.clone(),
            transaction: transaction.clone(),
            writes: vec![
                pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{}/atomic/valid", query_request().parent),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
                pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{}/atomic/invalid", query_request().parent),
                        fields: [(
                            "value".to_owned(),
                            pb::Value {
                                value_type: Some(pb::value::ValueType::StringValue(invalid)),
                            },
                        )]
                        .into_iter()
                        .collect(),
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }),
    )
    .await
    .expect_err("oversized second write must reject the whole Commit");
    assert_eq!(failed.code(), tonic::Code::InvalidArgument);
    let missing_valid = Firestore::get_document(
        &service,
        Request::new(pb::GetDocumentRequest {
            name: format!("{}/atomic/valid", query_request().parent),
            ..Default::default()
        }),
    )
    .await
    .expect_err("the failed multiwrite must not publish its valid target");
    assert_eq!(missing_valid.code(), tonic::Code::NotFound);

    let valid_control = Firestore::commit(
        &service,
        Request::new(pb::CommitRequest {
            database: database.clone(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{}/atomic/valid", query_request().parent),
                    fields: [(
                        "value".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::IntegerValue(3)),
                        },
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        }),
    )
    .await
    .expect("the same valid document path must commit successfully");
    assert_eq!(valid_control.into_inner().write_results.len(), 1);

    let valid_document = Firestore::get_document(
        &service,
        Request::new(pb::GetDocumentRequest {
            name: format!("{}/atomic/valid", query_request().parent),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        valid_document.into_inner().fields["value"].value_type,
        Some(pb::value::ValueType::IntegerValue(3))
    );
    let missing_invalid = Firestore::get_document(
        &service,
        Request::new(pb::GetDocumentRequest {
            name: format!("{}/atomic/invalid", query_request().parent),
            ..Default::default()
        }),
    )
    .await
    .expect_err("the failed multiwrite must not publish its invalid target");
    assert_eq!(missing_invalid.code(), tonic::Code::NotFound);

    // The failed request leaves the transaction usable and its read lock held.
    Firestore::get_document(
        &service,
        Request::new(pb::GetDocumentRequest {
            name: document_name.clone(),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                transaction.clone(),
            )),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let contended = Firestore::commit(
        &service,
        Request::new(pb::CommitRequest {
            database: database.clone(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: document_name.clone(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        }),
    )
    .await
    .expect_err("the active transaction must retain its document lock");
    assert_eq!(contended.code(), tonic::Code::Aborted);
    let locked_before_rollback = Firestore::get_document(
        &service,
        Request::new(pb::GetDocumentRequest {
            name: document_name.clone(),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        locked_before_rollback.into_inner().fields["value"].value_type,
        Some(pb::value::ValueType::IntegerValue(1))
    );

    Firestore::rollback(
        &service,
        Request::new(pb::RollbackRequest {
            database,
            transaction,
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    Firestore::commit(
        &service,
        Request::new(pb::CommitRequest {
            database: database_name_from_query_parent(&query_request().parent),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: document_name.clone(),
                    fields: [(
                        "value".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::IntegerValue(2)),
                        },
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let after_rollback = Firestore::get_document(
        &service,
        Request::new(pb::GetDocumentRequest {
            name: document_name,
            ..Default::default()
        }),
    )
    .await
    .expect("the independent post-rollback write must be visible");
    assert_eq!(
        after_rollback.into_inner().fields["value"].value_type,
        Some(pb::value::ValueType::IntegerValue(2))
    );
}
