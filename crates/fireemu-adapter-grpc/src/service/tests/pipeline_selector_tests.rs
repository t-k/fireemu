//! `ExecutePipeline` selector contracts for documents, collection and collection-group
//! inputs, including stream ownership.

use super::*;

const DATABASE: &str = "projects/demo-app/databases/(default)";
const DOCUMENT: &str = "projects/demo-app/databases/(default)/documents/items/000";
// Resource-independent google.rpc.Status/ErrorInfo from two native recordings.
const AUTO_ALONE_DETAILS: &[u8] = &[
    0x08, 0x03, 0x12, 0x3a, 0x27, 0x61, 0x75, 0x74, 0x6f, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
    0x5f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x27, 0x20, 0x6d, 0x75,
    0x73, 0x74, 0x20, 0x62, 0x65, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20,
    0x61, 0x20, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x1a, 0x68,
    0x0a, 0x28, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69,
    0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x72, 0x70, 0x63,
    0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x3c, 0x0a, 0x20, 0x41, 0x55,
    0x54, 0x4f, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x49, 0x54, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x49, 0x52,
    0x45, 0x53, 0x5f, 0x54, 0x52, 0x41, 0x4e, 0x53, 0x41, 0x43, 0x54, 0x49, 0x4f, 0x4e, 0x12, 0x18,
    0x66, 0x69, 0x72, 0x65, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
    0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
];

fn fixture(profile: &str) -> (GatewayService, Arc<LocalBackend>) {
    let backend = test_backend();
    backend
        .commit(&pb::CommitRequest {
            database: DATABASE.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: DOCUMENT.to_owned(),
                    fields: [("v".to_owned(), value(pb::value::ValueType::IntegerValue(1)))]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();
    let mut gateway = test_gateway();
    gateway.ctx.edition = fireemu_core_types::edition::FirestoreEdition::Enterprise;
    gateway.enforce_limits = profile == "strict";
    (GatewayService::local(gateway, backend.clone()), backend)
}

fn new_options(mode: &str) -> pb::TransactionOptions {
    pb::TransactionOptions {
        mode: match mode {
            "default" => None,
            "ro" => Some(pb::transaction_options::Mode::ReadOnly(
                pb::transaction_options::ReadOnly::default(),
            )),
            "rw" | "existing" => Some(pb::transaction_options::Mode::ReadWrite(
                pb::transaction_options::ReadWrite::default(),
            )),
            _ => unreachable!(),
        },
    }
}

fn request(
    backend: &LocalBackend,
    mode: &str,
    auto: bool,
    input: &str,
) -> (pb::ExecutePipelineRequest, Vec<u8>) {
    let case = Case {
        docs: vec![],
        m_shapes: vec![],
        literal: None,
        select: None,
        offset: None,
        limit: None,
    };
    let mut req = pipeline(&case, "");
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        req.pipeline_type.as_mut()
    else {
        unreachable!()
    };
    structured.pipeline.as_mut().unwrap().stages[0] = stage(
        "documents",
        value(pb::value::ValueType::ReferenceValue(
            if input == "found" {
                "/items/000"
            } else {
                "/items/missing"
            }
            .to_owned(),
        )),
    );
    let token = if mode == "existing" {
        backend
            .begin_transaction(&pb::BeginTransactionRequest {
                database: DATABASE.to_owned(),
                options: Some(new_options("rw")),
                ..Default::default()
            })
            .unwrap()
    } else {
        Vec::new()
    };
    req.consistency_selector = if mode == "none" {
        None
    } else if mode == "existing" {
        Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(token.clone()))
    } else {
        Some(pb::execute_pipeline_request::ConsistencySelector::NewTransaction(new_options(mode)))
    };
    req.auto_commit_transaction = auto;
    (req, token)
}

async fn responses(
    service: &GatewayService,
    req: pb::ExecutePipelineRequest,
) -> Result<Vec<pb::ExecutePipelineResponse>, Status> {
    let mut stream = Firestore::execute_pipeline(service, Request::new(req))
        .await?
        .into_inner();
    let mut rows = Vec::new();
    while let Some(response) = stream.next().await {
        rows.push(response?);
    }
    Ok(rows)
}

fn read_token(
    backend: &LocalBackend,
    token: &[u8],
) -> Result<crate::local::BatchGetOutcome, Status> {
    backend.batch_get_documents(
        &pb::BatchGetDocumentsRequest {
            database: DATABASE.to_owned(),
            documents: vec![DOCUMENT.to_owned()],
            consistency_selector: Some(
                pb::batch_get_documents_request::ConsistencySelector::Transaction(token.to_vec()),
            ),
            ..Default::default()
        },
        &crate::rules::allow_all_reads,
    )
}

fn rollback(backend: &LocalBackend, token: Vec<u8>) -> Result<(), Status> {
    backend.rollback(&pb::RollbackRequest {
        database: DATABASE.to_owned(),
        transaction: token,
        ..Default::default()
    })
}

#[tokio::test]
async fn selector_native_cases_match_both_rounds_and_profiles() {
    for profile in ["strict", "ordinary"] {
        for round in 1..=2 {
            for (mode, auto) in [
                ("default", false),
                ("ro", false),
                ("rw", false),
                ("existing", false),
                ("rw", true),
                ("existing", true),
                ("none", true),
            ] {
                let (service, backend) = fixture(profile);
                let (req, existing) = request(&backend, mode, auto, "found");
                let result = responses(&service, req).await;
                if mode == "none" {
                    let err = result.unwrap_err();
                    assert_eq!(
                        err.code(),
                        tonic::Code::InvalidArgument,
                        "{profile}/{round}/auto-alone"
                    );
                    assert_eq!(
                        err.message(),
                        "'auto_commit_transaction' must be used with a transaction."
                    );
                    assert_eq!(err.details(), AUTO_ALONE_DETAILS);
                    assert_eq!(transaction_stats(&backend).active, 0);
                    continue;
                }
                let rows =
                    result.unwrap_or_else(|err| panic!("{profile}/{round}/{mode}/{auto}: {err}"));
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].results.len(), 1);
                assert_eq!(
                    rows[0].results[0].fields["v"],
                    value(pb::value::ValueType::IntegerValue(1))
                );
                assert!(rows[0].execution_time.is_some());
                assert_eq!(!rows[0].transaction.is_empty(), mode != "existing" && !auto);
                if mode == "existing" {
                    if auto {
                        assert_eq!(
                            read_token(&backend, &existing).unwrap_err().code(),
                            tonic::Code::Aborted
                        );
                        assert_eq!(
                            rollback(&backend, existing).unwrap_err().code(),
                            tonic::Code::Aborted
                        );
                        assert_eq!(transaction_stats(&backend).active, 0);
                    } else {
                        assert!(read_token(&backend, &existing).is_ok());
                        rollback(&backend, existing).unwrap();
                    }
                } else if !auto {
                    assert!(read_token(&backend, &rows[0].transaction).is_ok());
                    rollback(&backend, rows[0].transaction.clone()).unwrap();
                } else {
                    // Local lifecycle obligation, not a native same-token closure observation.
                    assert_eq!(transaction_stats(&backend).active, 0);
                }
            }
        }
    }
}

#[tokio::test]
async fn selector_seeded_generated_inputs_keep_empty_announcements_and_auto_closure() {
    // PICT pairwise rows, including every mandatory native/empty seed.
    for (mode, auto, input, profile) in [
        ("default", false, "found", "strict"),
        ("ro", false, "found", "strict"),
        ("rw", false, "found", "strict"),
        ("existing", false, "found", "strict"),
        ("rw", true, "found", "strict"),
        ("existing", true, "found", "strict"),
        ("default", false, "missing", "ordinary"),
        ("rw", true, "missing", "ordinary"),
        ("existing", true, "missing", "ordinary"),
        ("ro", false, "missing", "strict"),
        ("ro", false, "found", "ordinary"),
    ] {
        let (service, backend) = fixture(profile);
        let (req, existing) = request(&backend, mode, auto, input);
        let rows = responses(&service, req).await.unwrap();
        assert_eq!(rows.len(), 1, "{mode}/{auto}/{input}/{profile}");
        assert_eq!(rows[0].results.len(), usize::from(input == "found"));
        assert!(rows[0].execution_time.is_some());
        assert_eq!(!rows[0].transaction.is_empty(), mode != "existing" && !auto);
        if !auto {
            rollback(
                &backend,
                if mode == "existing" {
                    existing
                } else {
                    rows[0].transaction.clone()
                },
            )
            .unwrap();
        }
        assert_eq!(transaction_stats(&backend).active, 0);
    }
}

#[tokio::test]
async fn selector_new_default_and_explicit_modes_reuse_query_transaction_semantics() {
    for profile in ["strict", "ordinary"] {
        for mode in ["default", "ro", "rw"] {
            let (service, backend) = fixture(profile);
            let (req, _) = request(&backend, mode, false, "found");
            let rows = responses(&service, req).await.unwrap();
            let token = rows[0].transaction.clone();
            assert!(!token.is_empty());
            let result = backend.commit(&pb::CommitRequest {
                database: DATABASE.to_owned(),
                transaction: token.clone(),
                writes: vec![pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: DOCUMENT.to_owned(),
                        fields: [("v".to_owned(), value(pb::value::ValueType::IntegerValue(2)))]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            });
            if mode == "rw" {
                result.unwrap();
                assert_eq!(
                    read_token(&backend, &token).unwrap_err().code(),
                    tonic::Code::Aborted
                );
            } else {
                assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
            }
        }
    }
}

#[tokio::test]
async fn selector_unpolled_new_stream_releases_owned_transaction_but_existing_survives() {
    for profile in ["strict", "ordinary"] {
        for mode in ["default", "ro", "rw", "existing"] {
            let (service, backend) = fixture(profile);
            let (req, existing) = request(&backend, mode, false, "found");
            let stream = Firestore::execute_pipeline(&service, Request::new(req))
                .await
                .unwrap();
            assert_eq!(transaction_stats(&backend).active, 1);
            drop(stream);
            if mode == "existing" {
                assert!(read_token(&backend, &existing).is_ok());
                rollback(&backend, existing).unwrap();
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while transaction_stats(&backend).active != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("unpolled owned token must be released");
        }
    }
}

#[tokio::test]
async fn selector_polled_announcement_transfers_ownership_before_stream_drop() {
    for mode in ["default", "ro", "rw"] {
        let (service, backend) = fixture("strict");
        let (req, _) = request(&backend, mode, false, "found");
        let mut stream = Firestore::execute_pipeline(&service, Request::new(req))
            .await
            .unwrap()
            .into_inner();
        let first = stream.next().await.unwrap().unwrap();
        assert!(!first.transaction.is_empty());
        drop(stream);
        assert_eq!(transaction_stats(&backend).active, 1);
        assert!(read_token(&backend, &first.transaction).is_ok());
        rollback(&backend, first.transaction).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selector_cancelled_blocking_result_releases_only_new_transactions() {
    for mode in ["ro", "rw", "existing"] {
        let (mut service, backend) = fixture("strict");
        let (req, existing) = request(&backend, mode, false, "found");
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let ready_tx = Mutex::new(Some(ready_tx));
        let (release_tx, release_rx) = std::sync::mpsc::channel();
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
            Firestore::execute_pipeline(&service, Request::new(req))
                .await
                .map(|_| ())
        });
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(transaction_stats(&backend).active, 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release_tx.send(()).unwrap();
        if mode == "existing" {
            assert!(read_token(&backend, &existing).is_ok());
            rollback(&backend, existing).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while transaction_stats(&backend).active != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("discarded worker result must release owned token");
    }
}

#[tokio::test]
async fn selector_validation_precedes_minting() {
    for auto in [false, true] {
        let (service, backend) = fixture("strict");
        let (mut req, _) = request(&backend, "rw", auto, "found");
        let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
            req.pipeline_type.as_mut()
        else {
            unreachable!()
        };
        structured.pipeline.as_mut().unwrap().stages.push(stage(
            "not_a_pipeline_stage",
            value(pb::value::ValueType::IntegerValue(1)),
        ));
        assert!(responses(&service, req).await.is_err());
        assert_eq!(transaction_stats(&backend).active, 0);
        assert_eq!(transaction_stats(&backend).finished, 0);
    }
}

#[tokio::test]
async fn selector_evaluation_error_does_not_commit_or_abandon_existing_token() {
    for mode in ["rw", "existing"] {
        let (mut service, backend) = fixture("strict");
        let selected = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_selected = selected.clone();
        service.first_query_page_ready = Some(Arc::new(move || {
            worker_selected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        let (mut req, existing) = request(&backend, mode, true, "found");
        let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
            req.pipeline_type.as_mut()
        else {
            unreachable!()
        };
        structured.pipeline.as_mut().unwrap().stages.push(stage(
            "select",
            value(pb::value::ValueType::MapValue(pb::MapValue {
                fields: [(
                    "bad".to_owned(),
                    value(pb::value::ValueType::FunctionValue(pb::Function {
                        name: "array_length".to_owned(),
                        args: vec![field_ref("v")],
                        ..Default::default()
                    })),
                )]
                .into_iter()
                .collect(),
            })),
        ));
        assert!(responses(&service, req).await.is_err());
        assert_eq!(
            selected.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an unsupported selector refusal is not an evaluation failure"
        );
        if mode == "existing" {
            assert!(read_token(&backend, &existing).is_ok());
            rollback(&backend, existing).unwrap();
        }
        assert_eq!(transaction_stats(&backend).active, 0);
        assert_eq!(transaction_stats(&backend).finished, 1);
    }
}

#[tokio::test]
async fn selector_commit_failure_is_returned_and_releases_only_own_new_token() {
    use fireemu_core_session::fault::{
        FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
    };
    for action in [
        FaultAction::ReturnError {
            code: "UNAVAILABLE".to_owned(),
        },
        FaultAction::Timeout,
    ] {
        for mode in ["rw", "existing"] {
            let (service, backend) = fixture("strict");
            let (req, existing) = request(&backend, mode, true, "found");
            let faults = Arc::new(FaultRegistry::new());
            faults.default_state().lock().unwrap().install(FaultPlan {
                seed: 1,
                rules: vec![FaultRule {
                    matches: FaultMatch {
                        operation: "firestore.commit".to_owned(),
                        nth: None,
                        function: None,
                        event_type: None,
                    },
                    action: action.clone(),
                }],
            });
            backend.set_faults(faults);
            let err = responses(&service, req).await.unwrap_err();
            let expected = if matches!(action, FaultAction::Timeout) {
                tonic::Code::DeadlineExceeded
            } else {
                tonic::Code::Unavailable
            };
            assert_eq!(err.code(), expected);
            if mode == "existing" {
                assert!(read_token(&backend, &existing).is_ok());
                rollback(&backend, existing).unwrap();
            }
            assert_eq!(transaction_stats(&backend).active, 0);
        }
    }
}

#[tokio::test]
async fn selector_invalid_auto_existing_token_is_not_treated_as_latest() {
    for profile in ["strict", "ordinary"] {
        let (service, backend) = fixture(profile);
        let (mut req, _) = request(&backend, "none", true, "found");
        req.consistency_selector =
            Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(vec![1]));
        assert_eq!(
            responses(&service, req).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(transaction_stats(&backend).active, 0);
    }
}

#[tokio::test]
async fn selector_new_token_is_only_on_the_first_result_batch() {
    let (service, backend) = fixture("strict");
    let large = "a".repeat(600_000);
    backend
        .commit(&pb::CommitRequest {
            database: DATABASE.to_owned(),
            writes: (0..3)
                .map(|id| pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{PARENT}/large/{id}"),
                        fields: [(
                            "v".to_owned(),
                            value(pb::value::ValueType::StringValue(large.clone())),
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
    let (mut req, _) = request(&backend, "ro", false, "found");
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        req.pipeline_type.as_mut()
    else {
        unreachable!()
    };
    structured.pipeline.as_mut().unwrap().stages[0] = pb::pipeline::Stage {
        name: "documents".to_owned(),
        args: (0..3)
            .map(|id| value(pb::value::ValueType::ReferenceValue(format!("/large/{id}"))))
            .collect(),
        ..Default::default()
    };
    let rows = responses(&service, req).await.unwrap();
    assert!(rows.len() > 1);
    assert_eq!(rows.iter().map(|r| r.results.len()).sum::<usize>(), 3);
    assert!(!rows[0].transaction.is_empty());
    assert!(rows[1..].iter().all(|r| r.transaction.is_empty()));
    assert!(rows.iter().all(|r| r.execution_time.is_some()));
    rollback(&backend, rows[0].transaction.clone()).unwrap();
}

#[tokio::test]
async fn selector_queued_announcement_keeps_guard_until_polled() {
    for poll in [false, true] {
        let (_, backend) = fixture("strict");
        let token = backend
            .begin_transaction(&pb::BeginTransactionRequest {
                database: DATABASE.to_owned(),
                options: Some(new_options("ro")),
                ..Default::default()
            })
            .unwrap();
        let mut stream = PipelineResponseStream::new(
            Box::pin(tokio_stream::empty()),
            fireemu_core_firestore::pipeline_exec::Cursor::new(Vec::new()),
        )
        .with_transaction(
            token.clone(),
            Some(QueryTransactionGuard {
                local: backend.clone(),
                database: DATABASE.to_owned(),
                transaction: token.clone(),
            }),
            None,
        );
        stream.flush();
        assert_eq!(stream.ready.len(), 1);
        assert_eq!(transaction_stats(&backend).active, 1);
        if poll {
            assert_eq!(stream.next().await.unwrap().unwrap().transaction, token);
        }
        drop(stream);
        if poll {
            assert!(read_token(&backend, &token).is_ok());
            rollback(&backend, token).unwrap();
        } else {
            assert_eq!(transaction_stats(&backend).active, 0);
            assert_eq!(
                read_token(&backend, &token).unwrap_err().code(),
                tonic::Code::Aborted
            );
        }
    }
}

// ---- Collection and collection-group inputs (production recording of 2026-11-01) ----------

fn source_stage(source: &str) -> pb::pipeline::Stage {
    match source {
        "collection" => stage(
            "collection",
            value(pb::value::ValueType::ReferenceValue("/items".to_owned())),
        ),
        "group" => pb::pipeline::Stage {
            name: "collection_group".to_owned(),
            args: vec![
                value(pb::value::ValueType::ReferenceValue(String::new())),
                value(pb::value::ValueType::StringValue("items".to_owned())),
            ],
            ..Default::default()
        },
        _ => unreachable!(),
    }
}

fn query_request(
    backend: &LocalBackend,
    source: &str,
    mode: &str,
    auto: bool,
) -> (pb::ExecutePipelineRequest, Vec<u8>) {
    let (mut req, token) = request(backend, mode, auto, "found");
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        req.pipeline_type.as_mut()
    else {
        unreachable!()
    };
    structured.pipeline.as_mut().unwrap().stages[0] = source_stage(source);
    (req, token)
}

fn set_v(backend: &LocalBackend, v: i64) {
    backend
        .commit(&pb::CommitRequest {
            database: DATABASE.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: DOCUMENT.to_owned(),
                    fields: [("v".to_owned(), value(pb::value::ValueType::IntegerValue(v)))]
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

fn only_v(rows: &[pb::ExecutePipelineResponse]) -> i64 {
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].results.len(), 1);
    match rows[0].results[0].fields["v"].value_type {
        Some(pb::value::ValueType::IntegerValue(v)) => v,
        _ => panic!("v is not an integer"),
    }
}

fn begin_ro_at(backend: &LocalBackend, at: prost_types::Timestamp) -> Vec<u8> {
    backend
        .begin_transaction(&pb::BeginTransactionRequest {
            database: DATABASE.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadOnly(
                    pb::transaction_options::ReadOnly {
                        consistency_selector: Some(
                            pb::transaction_options::read_only::ConsistencySelector::ReadTime(at),
                        ),
                    },
                )),
            }),
            ..Default::default()
        })
        .unwrap()
}

/// The three native recordings (`native-collection-read-time`, `native-group-existing-ro`,
/// `native-collection-new-rw-auto`): the answer at the selected time or transaction, the
/// execution time of that snapshot, and no transaction field in any of them.
#[tokio::test]
async fn selector_query_native_cases_match_the_recording() {
    for profile in ["strict", "ordinary"] {
        let (service, backend) = fixture(profile);
        let read_time = stored_document(&service, DOCUMENT)
            .await
            .update_time
            .unwrap();
        let anchored = begin_ro_at(&backend, read_time);
        set_v(&backend, 2);
        // collection + readTime: the old value, executed at that time.
        let (mut req, _) = query_request(&backend, "collection", "none", false);
        req.consistency_selector = Some(
            pb::execute_pipeline_request::ConsistencySelector::ReadTime(read_time),
        );
        let rows = responses(&service, req).await.unwrap();
        assert_eq!(only_v(&rows), 1, "{profile}");
        assert_eq!(rows[0].execution_time, Some(read_time), "{profile}");
        assert!(rows[0].transaction.is_empty());
        // The same pipeline without a selector reads the latest value at a later time.
        let (req, _) = query_request(&backend, "collection", "none", false);
        let latest = responses(&service, req).await.unwrap();
        assert_eq!(only_v(&latest), 2);
        let at = latest[0].execution_time.unwrap();
        assert!((at.seconds, at.nanos) > (read_time.seconds, read_time.nanos));
        // collection_group + a read-only transaction begun at the old time.
        let (mut req, _) = query_request(&backend, "group", "none", false);
        req.consistency_selector =
            Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(anchored.clone()));
        let rows = responses(&service, req).await.unwrap();
        assert_eq!(only_v(&rows), 1, "{profile}");
        assert_eq!(rows[0].execution_time, Some(read_time), "{profile}");
        assert!(rows[0].transaction.is_empty());
        // The caller still owns the token.
        assert!(read_token(&backend, &anchored).is_ok());
        rollback(&backend, anchored).unwrap();
        // collection + new read-write transaction with auto-commit: the latest value, no token,
        // and exactly one transaction is closed by the commit.
        let before = transaction_stats(&backend).finished;
        let (req, _) = query_request(&backend, "collection", "rw", true);
        let rows = responses(&service, req).await.unwrap();
        assert_eq!(only_v(&rows), 2);
        assert!(rows[0].transaction.is_empty());
        assert!(rows[0].execution_time.is_some());
        let stats = transaction_stats(&backend);
        assert_eq!((stats.active, stats.finished), (0, before + 1), "{profile}");
    }
}

#[tokio::test]
async fn selector_query_modes_report_the_token_and_close_auto_commits() {
    for profile in ["strict", "ordinary"] {
        for source in ["collection", "group"] {
            for (mode, auto) in [
                ("default", false),
                ("ro", false),
                ("rw", false),
                ("existing", false),
                ("rw", true),
                ("existing", true),
            ] {
                let (service, backend) = fixture(profile);
                let (req, existing) = query_request(&backend, source, mode, auto);
                let rows = responses(&service, req)
                    .await
                    .unwrap_or_else(|err| panic!("{profile}/{source}/{mode}/{auto}: {err}"));
                assert_eq!(only_v(&rows), 1);
                assert!(rows[0].execution_time.is_some());
                assert_eq!(
                    !rows[0].transaction.is_empty(),
                    mode != "existing" && !auto,
                    "{profile}/{source}/{mode}/{auto}"
                );
                match (mode, auto) {
                    ("existing", true) => {
                        assert_eq!(
                            read_token(&backend, &existing).unwrap_err().code(),
                            tonic::Code::Aborted
                        );
                        assert_eq!(
                            rollback(&backend, existing).unwrap_err().code(),
                            tonic::Code::Aborted
                        );
                    }
                    ("existing", false) => {
                        assert!(read_token(&backend, &existing).is_ok());
                        rollback(&backend, existing).unwrap();
                    }
                    (_, false) => {
                        assert!(read_token(&backend, &rows[0].transaction).is_ok());
                        rollback(&backend, rows[0].transaction.clone()).unwrap();
                    }
                    (_, true) => {}
                }
                assert_eq!(transaction_stats(&backend).active, 0);
            }
        }
    }
}

#[tokio::test]
async fn selector_query_new_modes_reuse_query_transaction_semantics() {
    for source in ["collection", "group"] {
        for mode in ["default", "ro", "rw"] {
            let (service, backend) = fixture("strict");
            let (req, _) = query_request(&backend, source, mode, false);
            let rows = responses(&service, req).await.unwrap();
            let token = rows[0].transaction.clone();
            assert!(!token.is_empty());
            let result = backend.commit(&pb::CommitRequest {
                database: DATABASE.to_owned(),
                transaction: token.clone(),
                writes: vec![pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: DOCUMENT.to_owned(),
                        fields: [("v".to_owned(), value(pb::value::ValueType::IntegerValue(2)))]
                            .into_iter()
                            .collect(),
                        ..Default::default()
                    })),
                    ..Default::default()
                }],
                ..Default::default()
            });
            if mode == "rw" {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
                rollback(&backend, token).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn selector_query_empty_result_still_announces_the_token_once() {
    for source in ["collection", "group"] {
        for mode in ["default", "ro", "rw"] {
            let (service, backend) = fixture("strict");
            let (mut req, _) = query_request(&backend, source, mode, false);
            let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
                req.pipeline_type.as_mut()
            else {
                unreachable!()
            };
            structured.pipeline.as_mut().unwrap().stages[0] = if source == "collection" {
                stage(
                    "collection",
                    value(pb::value::ValueType::ReferenceValue("/nothing".to_owned())),
                )
            } else {
                pb::pipeline::Stage {
                    name: "collection_group".to_owned(),
                    args: vec![
                        value(pb::value::ValueType::ReferenceValue(String::new())),
                        value(pb::value::ValueType::StringValue("nothing".to_owned())),
                    ],
                    ..Default::default()
                }
            };
            let rows = responses(&service, req).await.unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].results, []);
            assert!(rows[0].execution_time.is_some());
            assert!(!rows[0].transaction.is_empty(), "{source}/{mode}");
            rollback(&backend, rows[0].transaction.clone()).unwrap();
        }
    }
}

#[tokio::test]
async fn selector_query_unpolled_new_stream_releases_owned_transaction_but_existing_survives() {
    for source in ["collection", "group"] {
        for mode in ["default", "ro", "rw", "existing"] {
            let (service, backend) = fixture("strict");
            let (req, existing) = query_request(&backend, source, mode, false);
            let stream = Firestore::execute_pipeline(&service, Request::new(req))
                .await
                .unwrap();
            assert_eq!(transaction_stats(&backend).active, 1, "{source}/{mode}");
            drop(stream);
            if mode == "existing" {
                assert!(read_token(&backend, &existing).is_ok());
                rollback(&backend, existing).unwrap();
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while transaction_stats(&backend).active != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("unpolled owned token must be released");
        }
    }
}

#[tokio::test]
async fn selector_query_polled_announcement_transfers_ownership() {
    for source in ["collection", "group"] {
        for mode in ["default", "ro", "rw"] {
            let (service, backend) = fixture("strict");
            let (req, _) = query_request(&backend, source, mode, false);
            let mut stream = Firestore::execute_pipeline(&service, Request::new(req))
                .await
                .unwrap()
                .into_inner();
            let first = stream.next().await.unwrap().unwrap();
            assert_ne!(first.transaction, []);
            drop(stream);
            assert_eq!(transaction_stats(&backend).active, 1);
            assert!(read_token(&backend, &first.transaction).is_ok());
            rollback(&backend, first.transaction).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selector_query_cancelled_first_page_releases_only_new_transactions() {
    for source in ["collection", "group"] {
        for mode in ["ro", "rw", "existing"] {
            let (mut service, backend) = fixture("strict");
            let (req, existing) = query_request(&backend, source, mode, false);
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let ready_tx = Mutex::new(Some(ready_tx));
            let (release_tx, release_rx) = std::sync::mpsc::channel();
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
                Firestore::execute_pipeline(&service, Request::new(req))
                    .await
                    .map(|_| ())
            });
            tokio::time::timeout(Duration::from_secs(5), ready_rx)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(transaction_stats(&backend).active, 1);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            release_tx.send(()).unwrap();
            if mode == "existing" {
                assert!(read_token(&backend, &existing).is_ok());
                rollback(&backend, existing).unwrap();
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while transaction_stats(&backend).active != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("discarded worker result must release owned token");
        }
    }
}

/// The announcement is already delivered to the pipeline when a later page is read, so the
/// pipeline itself must own the new token while it collects the rest of the input.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selector_query_cancelled_while_collecting_releases_only_new_transactions() {
    for mode in ["ro", "rw", "existing"] {
        let (mut service, backend) = fixture("strict");
        backend
            .commit(&pb::CommitRequest {
                database: DATABASE.to_owned(),
                writes: (1..=40)
                    .map(|id| pb::Write {
                        operation: Some(pb::write::Operation::Update(pb::Document {
                            name: format!("{PARENT}/items/{id:03}"),
                            fields: [(
                                "v".to_owned(),
                                value(pb::value::ValueType::IntegerValue(1)),
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
        let (req, existing) = query_request(&backend, "collection", mode, false);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let ready_tx = Mutex::new(Some(ready_tx));
        let (release_tx, release_rx) = std::sync::mpsc::channel();
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
        let task = tokio::spawn(async move {
            Firestore::execute_pipeline(&service, Request::new(req))
                .await
                .map(|_| ())
        });
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(transaction_stats(&backend).active, 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release_tx.send(()).unwrap();
        if mode == "existing" {
            assert!(read_token(&backend, &existing).is_ok());
            rollback(&backend, existing).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while transaction_stats(&backend).active != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a token the pipeline owns must be released when it is dropped");
    }
}

#[tokio::test]
async fn selector_query_validation_precedes_minting_and_other_inputs_stay_refused() {
    for auto in [false, true] {
        for source in ["collection", "group"] {
            let (service, backend) = fixture("strict");
            let (mut req, _) = query_request(&backend, source, "rw", auto);
            let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
                req.pipeline_type.as_mut()
            else {
                unreachable!()
            };
            structured.pipeline.as_mut().unwrap().stages.push(stage(
                "not_a_pipeline_stage",
                value(pb::value::ValueType::IntegerValue(1)),
            ));
            assert!(responses(&service, req).await.is_err());
            assert_eq!(transaction_stats(&backend).active, 0);
            assert_eq!(transaction_stats(&backend).finished, 0);
        }
        // Inputs production did not answer with a selector keep the refusal, before any mint.
        let union = stage(
            "union",
            value(pb::value::ValueType::PipelineValue(pb::Pipeline {
                stages: vec![stage(
                    "collection",
                    value(pb::value::ValueType::ReferenceValue("/items".to_owned())),
                )],
            })),
        );
        let database = pb::pipeline::Stage {
            name: "database".to_owned(),
            ..Default::default()
        };
        for refused in [vec![database], vec![source_stage("collection"), union]] {
            let (service, backend) = fixture("strict");
            let (mut req, _) = query_request(&backend, "collection", "rw", auto);
            let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
                req.pipeline_type.as_mut()
            else {
                unreachable!()
            };
            structured.pipeline.as_mut().unwrap().stages = refused;
            let err = responses(&service, req).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unimplemented);
            assert_eq!(
                err.message(),
                "pipeline consistency is unsupported for this input"
            );
            assert_eq!(transaction_stats(&backend).active, 0);
            assert_eq!(transaction_stats(&backend).finished, 0);
        }
    }
}

#[tokio::test]
async fn selector_query_read_time_with_auto_commit_stays_refused() {
    let (service, backend) = fixture("strict");
    let read_time = stored_document(&service, DOCUMENT)
        .await
        .update_time
        .unwrap();
    let (mut req, _) = query_request(&backend, "collection", "none", true);
    req.consistency_selector = Some(pb::execute_pipeline_request::ConsistencySelector::ReadTime(
        read_time,
    ));
    assert!(responses(&service, req).await.is_err());
    assert_eq!(transaction_stats(&backend).finished, 0);
}

#[tokio::test]
async fn selector_query_evaluation_error_does_not_commit_or_abandon_existing_token() {
    for source in ["collection", "group"] {
        for mode in ["rw", "existing"] {
            let (mut service, backend) = fixture("strict");
            let selected = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let worker_selected = selected.clone();
            service.first_query_page_ready = Some(Arc::new(move || {
                worker_selected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }));
            let (mut req, existing) = query_request(&backend, source, mode, true);
            let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
                req.pipeline_type.as_mut()
            else {
                unreachable!()
            };
            structured.pipeline.as_mut().unwrap().stages.push(stage(
                "select",
                value(pb::value::ValueType::MapValue(pb::MapValue {
                    fields: [(
                        "bad".to_owned(),
                        value(pb::value::ValueType::FunctionValue(pb::Function {
                            name: "array_length".to_owned(),
                            args: vec![field_ref("v")],
                            ..Default::default()
                        })),
                    )]
                    .into_iter()
                    .collect(),
                })),
            ));
            assert!(responses(&service, req).await.is_err());
            assert_eq!(selected.load(std::sync::atomic::Ordering::SeqCst), 1);
            if mode == "existing" {
                assert!(read_token(&backend, &existing).is_ok());
                rollback(&backend, existing).unwrap();
            }
            assert_eq!(transaction_stats(&backend).active, 0);
            assert_eq!(transaction_stats(&backend).finished, 1);
        }
    }
}

#[tokio::test]
async fn selector_query_commit_failure_is_returned_and_releases_only_own_new_token() {
    use fireemu_core_session::fault::{
        FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
    };
    for action in [
        FaultAction::ReturnError {
            code: "UNAVAILABLE".to_owned(),
        },
        FaultAction::Timeout,
    ] {
        for mode in ["rw", "existing"] {
            let (service, backend) = fixture("strict");
            let (req, existing) = query_request(&backend, "collection", mode, true);
            let faults = Arc::new(FaultRegistry::new());
            faults.default_state().lock().unwrap().install(FaultPlan {
                seed: 1,
                rules: vec![FaultRule {
                    matches: FaultMatch {
                        operation: "firestore.commit".to_owned(),
                        nth: None,
                        function: None,
                        event_type: None,
                    },
                    action: action.clone(),
                }],
            });
            backend.set_faults(faults);
            let err = responses(&service, req).await.unwrap_err();
            let expected = if matches!(action, FaultAction::Timeout) {
                tonic::Code::DeadlineExceeded
            } else {
                tonic::Code::Unavailable
            };
            assert_eq!(err.code(), expected);
            if mode == "existing" {
                assert!(read_token(&backend, &existing).is_ok());
                rollback(&backend, existing).unwrap();
            }
            assert_eq!(transaction_stats(&backend).active, 0);
        }
    }
}

#[tokio::test]
async fn selector_query_invalid_existing_token_is_not_treated_as_latest() {
    for profile in ["strict", "ordinary"] {
        for source in ["collection", "group"] {
            for (token, auto) in [
                (vec![1], false),
                (vec![1], true),
                (Vec::new(), false),
                (Vec::new(), true),
            ] {
                let (service, backend) = fixture(profile);
                let (mut req, _) = query_request(&backend, source, "none", auto);
                req.consistency_selector =
                    Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(token));
                assert_eq!(
                    responses(&service, req).await.unwrap_err().code(),
                    tonic::Code::InvalidArgument
                );
                assert_eq!(transaction_stats(&backend).active, 0);
            }
        }
    }
}

#[tokio::test]
async fn selector_query_new_token_is_only_on_the_first_result_batch() {
    let (service, backend) = fixture("strict");
    let large = "a".repeat(600_000);
    backend
        .commit(&pb::CommitRequest {
            database: DATABASE.to_owned(),
            writes: (0..3)
                .map(|id| pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{PARENT}/large/{id}"),
                        fields: [(
                            "v".to_owned(),
                            value(pb::value::ValueType::StringValue(large.clone())),
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
    let (mut req, _) = query_request(&backend, "collection", "ro", false);
    let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        req.pipeline_type.as_mut()
    else {
        unreachable!()
    };
    structured.pipeline.as_mut().unwrap().stages[0] = stage(
        "collection",
        value(pb::value::ValueType::ReferenceValue("/large".to_owned())),
    );
    let rows = responses(&service, req).await.unwrap();
    assert!(rows.len() > 1);
    assert_eq!(rows.iter().map(|r| r.results.len()).sum::<usize>(), 3);
    assert_ne!(rows[0].transaction, []);
    assert!(rows[1..].iter().all(|r| r.transaction.is_empty()));
    rollback(&backend, rows[0].transaction.clone()).unwrap();
}

mod selector_query_model {
    use super::*;

    /// A reference model of what one selected pipeline leaves behind.
    #[derive(Debug)]
    struct Expected {
        token_in_answer: bool,
        value: i64,
        committed: bool,
        caller_token_open: bool,
    }

    fn model(mode: &str, auto: bool, read_time: bool) -> Expected {
        Expected {
            token_in_answer: matches!(mode, "default" | "ro" | "rw") && !auto,
            // The caller's transaction is anchored at the old value; a read time is the old
            // value; everything else reads the latest value.
            value: if mode == "existing" && !auto || read_time {
                1
            } else {
                2
            },
            committed: auto,
            caller_token_open: mode == "existing" && !auto,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn selected_query_pipelines_follow_the_reference_model(
            group in any::<bool>(),
            strict in any::<bool>(),
            mode in prop::sample::select(vec!["none", "default", "ro", "rw", "existing", "read_time"]),
            auto in any::<bool>(),
        ) {
            // Auto-commit needs a transaction selector.
            prop_assume!(!auto || !matches!(mode, "none" | "read_time"));
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async {
                let profile = if strict { "strict" } else { "ordinary" };
                let (service, backend) = fixture(profile);
                let read_time = stored_document(&service, DOCUMENT).await.update_time.unwrap();
                let anchored = begin_ro_at(&backend, read_time);
                set_v(&backend, 2);
                let source = if group { "group" } else { "collection" };
                let (mut req, _) = query_request(&backend, source, "none", auto);
                req.consistency_selector = match mode {
                    "none" => None,
                    "default" | "ro" | "rw" => Some(
                        pb::execute_pipeline_request::ConsistencySelector::NewTransaction(
                            new_options(mode),
                        ),
                    ),
                    "existing" => Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(
                        anchored.clone(),
                    )),
                    "read_time" => Some(pb::execute_pipeline_request::ConsistencySelector::ReadTime(read_time)),
                    _ => unreachable!(),
                };
                // An auto-committed existing transaction is the anchored read-only one in the
                // model above, which cannot commit writes; use a read-write one for that.
                let mut existing_rw = None;
                if mode == "existing" && auto {
                    let token = backend.begin_transaction(&pb::BeginTransactionRequest {
                        database: DATABASE.to_owned(),
                        options: Some(new_options("rw")),
                        ..Default::default()
                    }).unwrap();
                    req.consistency_selector = Some(
                        pb::execute_pipeline_request::ConsistencySelector::Transaction(token.clone()),
                    );
                    existing_rw = Some(token);
                }
                let rows = responses(&service, req).await.unwrap();
                let expected = model(mode, auto, mode == "read_time");
                prop_assert_eq!(!rows[0].transaction.is_empty(), expected.token_in_answer);
                prop_assert_eq!(only_v(&rows), expected.value);
                if let Some(token) = existing_rw {
                    prop_assert_eq!(read_token(&backend, &token).is_err(), expected.committed);
                } else if expected.token_in_answer {
                    rollback(&backend, rows[0].transaction.clone()).unwrap();
                }
                if expected.caller_token_open {
                    prop_assert!(read_token(&backend, &anchored).is_ok());
                }
                rollback(&backend, anchored).ok();
                prop_assert_eq!(transaction_stats(&backend).active, 0);
                Ok(())
            })?;
        }
    }
}

/// Auto-commit of a default or read-only new transaction commits it after the answer, like
/// the read-write one (committing a transaction that wrote nothing is harmless).
#[tokio::test]
async fn selector_auto_commit_of_a_new_read_only_transaction_commits_it() {
    for source in ["collection", "group", "documents"] {
        for mode in ["default", "ro"] {
            let (service, backend) = fixture("strict");
            let (req, _) = if source == "documents" {
                request(&backend, mode, true, "found")
            } else {
                query_request(&backend, source, mode, true)
            };
            let rows = responses(&service, req)
                .await
                .unwrap_or_else(|err| panic!("{source}/{mode}: {err}"));
            assert_eq!(only_v(&rows), 1);
            assert!(rows[0].transaction.is_empty());
            let stats = transaction_stats(&backend);
            assert_eq!((stats.active, stats.finished), (0, 1), "{source}/{mode}");
        }
    }
}
