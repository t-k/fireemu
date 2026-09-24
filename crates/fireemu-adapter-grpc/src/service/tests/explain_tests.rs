use super::*;
use tokio_stream::StreamExt;

fn analyze(mut request: pb::RunQueryRequest, enabled: bool) -> pb::RunQueryRequest {
    request.explain_options = Some(pb::ExplainOptions { analyze: enabled });
    request
}

fn aggregation(request: pb::RunQueryRequest) -> pb::RunAggregationQueryRequest {
    let query = request.query_type.map(|query| match query {
        pb::run_query_request::QueryType::StructuredQuery(query) => {
            pb::structured_aggregation_query::QueryType::StructuredQuery(query)
        }
    });
    pb::RunAggregationQueryRequest {
        parent: request.parent,
        query_type: Some(
            pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                pb::StructuredAggregationQuery {
                    query_type: query,
                    aggregations: vec![pb::structured_aggregation_query::Aggregation {
                        alias: "count".to_owned(),
                        operator: Some(
                            pb::structured_aggregation_query::aggregation::Operator::Count(
                                pb::structured_aggregation_query::aggregation::Count::default(),
                            ),
                        ),
                    }],
                },
            ),
        ),
        explain_options: request.explain_options,
        ..Default::default()
    }
}

#[tokio::test]
async fn explain_analyze_counts_emitted_documents_once_after_offset() {
    for field_order in [false, true] {
        let backend = test_backend();
        let service = GatewayService::local(test_gateway(), backend.clone());
        let mut request = analyze(
            super::query_transaction_tests::seeded_query(&backend, 80, field_order),
            true,
        );
        let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
            &mut request.query_type
        else {
            unreachable!()
        };
        query.offset = 7;
        query.limit = Some(65);
        let responses: Vec<_> = Firestore::run_query(&service, Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.document.is_some())
                .count(),
            65
        );
        let metrics: Vec<_> = responses
            .iter()
            .filter_map(|response| response.explain_metrics.as_ref())
            .collect();
        assert_eq!(metrics.len(), 1);
        assert_eq!(
            metrics[0]
                .execution_stats
                .as_ref()
                .unwrap()
                .results_returned,
            65
        );
        assert!(responses.last().unwrap().explain_metrics.is_some());
        assert!(responses
            .iter()
            .all(|response| response.read_time.is_some()));
        assert_eq!(transaction_stats(&backend).active, 0);
    }
}

#[tokio::test]
async fn explain_analyze_survives_more_than_64_in_flight_queries() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let request = analyze(
        super::query_transaction_tests::seeded_query(&backend, 65, false),
        true,
    );
    // Every stream stalls on its first page while later executions evict the diagnostic cache.
    let mut streams = Vec::new();
    for _ in 0..70 {
        streams.push(
            Firestore::run_query(&service, Request::new(request.clone()))
                .await
                .unwrap()
                .into_inner(),
        );
    }
    for stream in streams {
        let responses: Vec<_> = stream.map(Result::unwrap).collect().await;
        let metrics: Vec<_> = responses
            .iter()
            .filter_map(|response| response.explain_metrics.as_ref())
            .collect();
        assert_eq!(metrics.len(), 1);
        assert_eq!(
            metrics[0]
                .execution_stats
                .as_ref()
                .unwrap()
                .results_returned,
            65
        );
    }
    assert_eq!(transaction_stats(&backend).active, 0);
}

#[tokio::test]
async fn explain_aggregation_counts_one_emitted_result() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let request = aggregation(analyze(
        super::query_transaction_tests::seeded_query(&backend, 7, false),
        true,
    ));
    let responses: Vec<_> = Firestore::run_aggregation_query(&service, Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .map(Result::unwrap)
        .collect()
        .await;
    assert_eq!(responses.len(), 1);
    assert!(responses[0].result.is_some());
    assert!(responses[0].read_time.is_some());
    assert_eq!(
        responses[0]
            .explain_metrics
            .as_ref()
            .unwrap()
            .execution_stats
            .as_ref()
            .unwrap()
            .results_returned,
        1
    );
}

#[tokio::test]
async fn explain_plan_only_query_preserves_transaction_ownership_without_scanning() {
    for selector in [
        None,
        Some(new_query_transaction(true)),
        Some(new_query_transaction(false)),
    ] {
        for consume in [false, true] {
            let backend = test_backend();
            let service = GatewayService::local(test_gateway(), backend.clone());
            let mut request = analyze(query_request(), false);
            request.consistency_selector = selector.clone();
            let mut stream = Firestore::run_query(&service, Request::new(request))
                .await
                .unwrap()
                .into_inner();
            let mut token = Vec::new();
            if consume {
                if selector.is_some() {
                    let announcement = stream.next().await.unwrap().unwrap();
                    token = announcement.transaction.clone();
                    assert!(!token.is_empty());
                    assert_eq!(
                        announcement,
                        pb::RunQueryResponse {
                            transaction: token.clone(),
                            ..Default::default()
                        }
                    );
                }
                let response = stream.next().await.unwrap().unwrap();
                assert!(response.transaction.is_empty());
                assert!(response.document.is_none());
                assert!(response.read_time.is_none());
                assert!(response.explain_metrics.unwrap().execution_stats.is_none());
                assert!(stream.next().await.is_none());
            }
            drop(stream);
            assert!(backend.latest_query_execution_stats().is_none());
            if !token.is_empty() {
                // The announced token remains usable by its owner after the Explain stream ends.
                let mut reuse = analyze(query_request(), false);
                reuse.consistency_selector = Some(
                    pb::run_query_request::ConsistencySelector::Transaction(token.clone()),
                );
                let result: Vec<_> = Firestore::run_query(&service, Request::new(reuse))
                    .await
                    .unwrap()
                    .into_inner()
                    .map(Result::unwrap)
                    .collect()
                    .await;
                assert!(result[0].transaction.is_empty());
                backend
                    .rollback(&pb::RollbackRequest {
                        database: database_name_from_query_parent(&query_request().parent),
                        transaction: token,
                        ..Default::default()
                    })
                    .unwrap();
            }
            assert_eq!(transaction_stats(&backend).active, 0);
        }
    }
}

#[tokio::test]
async fn explain_plan_only_aggregation_releases_unannounced_transaction() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let mut request = aggregation(analyze(query_request(), false));
    request.consistency_selector = Some(
        pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
            pb::TransactionOptions::default(),
        ),
    );
    let stream = Firestore::run_aggregation_query(&service, Request::new(request))
        .await
        .unwrap()
        .into_inner();
    drop(stream);
    assert_eq!(transaction_stats(&backend).active, 0);
}

#[tokio::test]
async fn explain_grpc_rejects_invalid_query_parent_and_snapshot() {
    for enabled in [false, true] {
        let backend = test_backend();
        let service = GatewayService::local(test_gateway(), backend.clone());
        let mut invalid = Vec::new();
        let mut request = analyze(query_request(), enabled);
        request.query_type = None;
        invalid.push(request);
        let mut request = analyze(query_request(), enabled);
        request.parent = "not-a-parent".to_owned();
        invalid.push(request);
        let mut request = analyze(query_request(), enabled);
        if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
            &mut request.query_type
        {
            query.offset = -1;
        }
        invalid.push(request);
        let mut request = analyze(query_request(), enabled);
        request.consistency_selector = Some(
            pb::run_query_request::ConsistencySelector::Transaction(b"invalid".to_vec()),
        );
        invalid.push(request);
        let mut request = analyze(query_request(), enabled);
        request.consistency_selector = Some(pb::run_query_request::ConsistencySelector::ReadTime(
            prost_types::Timestamp {
                seconds: 0,
                nanos: -1,
            },
        ));
        invalid.push(request);
        for request in invalid {
            let mut aggregate = aggregation(request.clone());
            aggregate.consistency_selector =
                request
                    .consistency_selector
                    .clone()
                    .map(|selector| match selector {
                        pb::run_query_request::ConsistencySelector::Transaction(token) => {
                            pb::run_aggregation_query_request::ConsistencySelector::Transaction(
                                token,
                            )
                        }
                        pb::run_query_request::ConsistencySelector::ReadTime(time) => {
                            pb::run_aggregation_query_request::ConsistencySelector::ReadTime(time)
                        }
                        pb::run_query_request::ConsistencySelector::NewTransaction(options) => {
                            pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                                options,
                            )
                        }
                    });
            // An aggregation over an absent query aggregates the empty one, as production does
            // (request-shape/rest#aggregation-without-structured-query), so that case is valid.
            let aggregation_query_absent = request.query_type.is_none();
            let Err(error) = Firestore::run_query(&service, Request::new(request)).await else {
                panic!("invalid query accepted")
            };
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            if aggregation_query_absent {
                continue;
            }
            let Err(error) =
                Firestore::run_aggregation_query(&service, Request::new(aggregate)).await
            else {
                panic!("invalid aggregation accepted")
            };
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        assert_eq!(transaction_stats(&backend).active, 0);
    }
}

#[tokio::test]
async fn explain_grpc_authorizes_before_scanning_and_cleans_rejected_new_transactions() {
    use fireemu_core_auth::{mfa::TotpPolicy, store::AuthStore};
    use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
    use fireemu_core_types::determinism::SplitMix64;
    for condition in ["false", "request.auth != null"] {
        let backend = test_backend();
        let source = format!("service cloud.firestore {{ match /databases/{{database}}/documents {{ match /{{document=**}} {{ allow read: if {condition}; }} }} }}");
        let rules = Arc::new(RulesEnforcer::new(
            Arc::new(RulesetSlot::new(LoadedRules::from_source(&source).unwrap())),
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(3),
                TotpPolicy::default(),
            ))),
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
        ));
        let service = GatewayService::local(test_gateway(), backend.clone()).with_rules(rules);
        for enabled in [false, true] {
            for token in [None, Some("Bearer malformed")] {
                let mut query = analyze(query_request(), enabled);
                query.consistency_selector = Some(new_query_transaction(true));
                let mut aggregate = aggregation(query.clone());
                aggregate.consistency_selector = Some(
                    pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                        pb::TransactionOptions::default(),
                    ),
                );
                let mut query = Request::new(query);
                let mut aggregate = Request::new(aggregate);
                if let Some(token) = token {
                    query
                        .metadata_mut()
                        .insert("authorization", token.parse().unwrap());
                    aggregate
                        .metadata_mut()
                        .insert("authorization", token.parse().unwrap());
                }
                let expected = if token.is_some() {
                    tonic::Code::Unauthenticated
                } else {
                    tonic::Code::PermissionDenied
                };
                let Err(error) = Firestore::run_query(&service, query).await else {
                    panic!("unauthorized query accepted")
                };
                assert_eq!(error.code(), expected);
                let Err(error) = Firestore::run_aggregation_query(&service, aggregate).await else {
                    panic!("unauthorized aggregation accepted")
                };
                assert_eq!(error.code(), expected);
                assert!(backend.latest_query_execution_stats().is_none());
                assert_eq!(transaction_stats(&backend).active, 0);
            }
        }
    }
}

#[tokio::test]
async fn explain_plan_only_aggregation_preserves_announced_and_existing_transactions() {
    for read_only in [false, true] {
        let backend = test_backend();
        let service = GatewayService::local(test_gateway(), backend.clone());
        let mut request = aggregation(analyze(query_request(), false));
        // No selector must not allocate a transaction.
        let response = Firestore::run_aggregation_query(&service, Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner()
            .next()
            .await
            .unwrap()
            .unwrap();
        assert!(response.transaction.is_empty());
        assert!(response.result.is_none());
        assert!(response.read_time.is_none());
        assert_eq!(transaction_stats(&backend).active, 0);
        let pb::run_query_request::ConsistencySelector::NewTransaction(options) =
            new_query_transaction(read_only)
        else {
            unreachable!()
        };
        request.consistency_selector =
            Some(pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(options));
        let mut stream = Firestore::run_aggregation_query(&service, Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        let response = stream.next().await.unwrap().unwrap();
        assert!(response.result.is_none());
        assert!(response.read_time.is_none());
        assert!(response.explain_metrics.unwrap().execution_stats.is_none());
        assert!(!response.transaction.is_empty());
        drop(stream);
        assert_eq!(transaction_stats(&backend).active, 1);
        request.consistency_selector = Some(
            pb::run_aggregation_query_request::ConsistencySelector::Transaction(
                response.transaction.clone(),
            ),
        );
        let response2 = Firestore::run_aggregation_query(&service, Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .next()
            .await
            .unwrap()
            .unwrap();
        assert!(response2.transaction.is_empty());
        backend
            .rollback(&pb::RollbackRequest {
                database: database_name_from_query_parent(&query_request().parent),
                transaction: response.transaction,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(transaction_stats(&backend).active, 0);
    }
}

#[tokio::test]
async fn explain_analyze_empty_output_still_returns_final_metrics() {
    for (count, offset, limit) in [(0, 0, None), (4, 10, None), (4, 0, Some(0))] {
        let backend = test_backend();
        let service = GatewayService::local(test_gateway(), backend.clone());
        let mut request = analyze(
            super::query_transaction_tests::seeded_query(&backend, count, false),
            true,
        );
        if let Some(pb::run_query_request::QueryType::StructuredQuery(query)) =
            &mut request.query_type
        {
            query.offset = offset;
            query.limit = limit;
        }
        let aggregate = aggregation(request.clone());
        let responses: Vec<_> = Firestore::run_query(&service, Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .map(Result::unwrap)
            .collect()
            .await;
        assert!(responses.iter().all(|response| response.document.is_none()));
        assert!(responses
            .iter()
            .all(|response| response.read_time.is_some()));
        let metrics: Vec<_> = responses
            .iter()
            .filter_map(|response| response.explain_metrics.as_ref())
            .collect();
        assert_eq!(metrics.len(), 1);
        assert_eq!(
            metrics[0]
                .execution_stats
                .as_ref()
                .unwrap()
                .results_returned,
            0
        );
        let response = Firestore::run_aggregation_query(&service, Request::new(aggregate))
            .await
            .unwrap()
            .into_inner()
            .next()
            .await
            .unwrap()
            .unwrap();
        assert!(response.result.is_some());
        assert!(response.read_time.is_some());
        assert_eq!(
            response
                .explain_metrics
                .unwrap()
                .execution_stats
                .unwrap()
                .results_returned,
            1
        );
        assert_eq!(transaction_stats(&backend).active, 0);
    }
}

#[tokio::test]
async fn explain_name_scan_billing_includes_offset_across_stream_pages() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let mut request = analyze(
        super::query_transaction_tests::seeded_query(&backend, 80, false),
        true,
    );
    let Some(pb::run_query_request::QueryType::StructuredQuery(query)) = &mut request.query_type
    else {
        unreachable!()
    };
    query.offset = 7;
    query.limit = Some(65);
    let responses: Vec<_> = Firestore::run_query(&service, Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .map(Result::unwrap)
        .collect()
        .await;
    let metrics = responses.last().unwrap().explain_metrics.as_ref().unwrap();
    assert_eq!(metrics.plan_summary.as_ref().unwrap().indexes_used.len(), 1);
    let stats = metrics.execution_stats.as_ref().unwrap();
    assert_eq!(stats.results_returned, 65);
    assert_eq!(stats.read_operations, 72);
    assert!(stats.execution_duration.is_some());
    assert!(stats.debug_stats.is_some());
}

#[tokio::test]
async fn explain_count_read_operations_use_thousand_entry_batches() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let request = aggregation(analyze(
        super::query_transaction_tests::seeded_query(&backend, 1001, false),
        true,
    ));
    let responses: Vec<_> = Firestore::run_aggregation_query(&service, Request::new(request))
        .await
        .unwrap()
        .into_inner()
        .map(Result::unwrap)
        .collect()
        .await;
    assert_eq!(
        responses[0]
            .explain_metrics
            .as_ref()
            .unwrap()
            .execution_stats
            .as_ref()
            .unwrap()
            .read_operations,
        2
    );
}

#[tokio::test]
async fn explain_count_up_to_caps_billable_index_entries() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let request = aggregation(analyze(
        super::query_transaction_tests::seeded_query(&backend, 1001, false),
        true,
    ));
    for (cap, offset, limit, scanned) in [
        (7, 0, None, 7),
        (7, 3, None, 10),
        (7, 3, Some(2), 5),
        (2000, 0, None, 1001),
    ] {
        let mut request = request.clone();
        let Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
            aggregate,
        )) = &mut request.query_type
        else {
            unreachable!()
        };
        let Some(pb::structured_aggregation_query::aggregation::Operator::Count(count)) =
            &mut aggregate.aggregations[0].operator
        else {
            unreachable!()
        };
        count.up_to = Some(cap);
        let Some(pb::structured_aggregation_query::QueryType::StructuredQuery(query)) =
            &mut aggregate.query_type
        else {
            unreachable!()
        };
        query.offset = offset;
        query.limit = limit;
        let response = Firestore::run_aggregation_query(&service, Request::new(request))
            .await
            .unwrap()
            .into_inner()
            .next()
            .await
            .unwrap()
            .unwrap();
        let stats = response.explain_metrics.unwrap().execution_stats.unwrap();
        assert_eq!(stats.read_operations, (scanned + 999) / 1000);
        let debug = stats.debug_stats.unwrap();
        assert_eq!(
            debug.fields["index_entries_scanned"].kind,
            Some(prost_types::value::Kind::StringValue(scanned.to_string()))
        );
        let Some(prost_types::value::Kind::StructValue(billing)) =
            &debug.fields["billing_details"].kind
        else {
            unreachable!()
        };
        assert_eq!(
            billing.fields["index_entries_billable"].kind,
            Some(prost_types::value::Kind::StringValue(scanned.to_string()))
        );
    }
}

#[tokio::test]
/// Every aggregation reports the index its plan reads and bills its entries, as production's
/// count and sum rows do (FS-QUERY-INDEX explain/aggregations): a sum or average reads the
/// automatic index of its field.
async fn explain_aggregations_report_their_index_and_billing() {
    use pb::structured_aggregation_query::aggregation::{Avg, Operator, Sum};
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let request = aggregation(analyze(
        super::query_transaction_tests::seeded_query(&backend, 3, false),
        true,
    ));
    let sum = Operator::Sum(Sum {
        field: Some(pb::structured_query::FieldReference {
            field_path: "rank".to_owned(),
        }),
    });
    let avg = Operator::Avg(Avg {
        field: Some(pb::structured_query::FieldReference {
            field_path: "rank".to_owned(),
        }),
    });
    let count = Operator::Count(pb::structured_aggregation_query::aggregation::Count::default());
    for (operators, index) in [
        (vec![sum.clone()], "(rank ASC, __name__ ASC)"),
        (vec![avg], "(rank ASC, __name__ ASC)"),
        (vec![count.clone(), sum], "(rank ASC, __name__ ASC)"),
        (vec![count.clone(), count], "(__name__ ASC)"),
    ] {
        for analyze in [false, true] {
            let mut request = request.clone();
            request.explain_options = Some(pb::ExplainOptions { analyze });
            let Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                aggregate,
            )) = &mut request.query_type
            else {
                unreachable!()
            };
            let Some(pb::structured_aggregation_query::QueryType::StructuredQuery(query)) =
                &mut aggregate.query_type
            else {
                unreachable!()
            };
            query.order_by.clear();
            aggregate.aggregations = operators
                .iter()
                .enumerate()
                .map(
                    |(index, operator)| pb::structured_aggregation_query::Aggregation {
                        alias: format!("value{index}"),
                        operator: Some(operator.clone()),
                    },
                )
                .collect();
            let response = Firestore::run_aggregation_query(&service, Request::new(request))
                .await
                .unwrap()
                .into_inner()
                .next()
                .await
                .unwrap()
                .unwrap();
            let metrics = response.explain_metrics.unwrap();
            let used = metrics.plan_summary.unwrap().indexes_used;
            assert_eq!(used.len(), 1, "{operators:?}");
            assert_eq!(
                used[0].fields["properties"].kind,
                Some(prost_types::value::Kind::StringValue(index.to_owned())),
                "{operators:?}"
            );
            if analyze {
                let stats = metrics.execution_stats.unwrap();
                assert_eq!(stats.results_returned, 1);
                assert!(stats.execution_duration.is_some());
                assert_eq!(stats.read_operations, 1);
                let debug = stats.debug_stats.unwrap();
                assert_eq!(
                    debug.fields["index_entries_scanned"].kind,
                    Some(prost_types::value::Kind::StringValue("3".to_owned())),
                    "{operators:?}"
                );
                assert_eq!(
                    debug.fields["documents_scanned"].kind,
                    Some(prost_types::value::Kind::StringValue("0".to_owned()))
                );
            } else {
                assert!(metrics.execution_stats.is_none());
            }
        }
    }
}

/// gRPC Explain counts index entries at the snapshot the query read (its read time), not the
/// latest state (closure review F7 / safety review S1).
#[tokio::test]
async fn explain_analyze_counts_entries_at_the_query_read_time() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let request = super::query_transaction_tests::seeded_query(&backend, 5, false);
    let read_time = Firestore::run_query(&service, Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .find_map(|response| response.read_time)
        .unwrap();
    backend
        .commit(&pb::CommitRequest {
            database: database_name_from_query_parent(&request.parent),
            writes: (5..8)
                .map(|index| pb::Write {
                    operation: Some(pb::write::Operation::Update(pb::Document {
                        name: format!("{}/items/{index:03}", request.parent),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
        .unwrap();
    let entries = |mut request: pb::RunQueryRequest| {
        let service = &service;
        async move {
            request.explain_options = Some(pb::ExplainOptions { analyze: true });
            let responses: Vec<_> = Firestore::run_query(service, Request::new(request))
                .await
                .unwrap()
                .into_inner()
                .map(Result::unwrap)
                .collect()
                .await;
            let metrics = responses
                .iter()
                .find_map(|response| response.explain_metrics.clone())
                .unwrap();
            metrics.execution_stats.unwrap().debug_stats.unwrap().fields["index_entries_scanned"]
                .kind
                .clone()
        }
    };
    let mut at_read_time = request.clone();
    at_read_time.consistency_selector = Some(pb::run_query_request::ConsistencySelector::ReadTime(
        read_time,
    ));
    assert_eq!(
        entries(at_read_time).await,
        Some(prost_types::value::Kind::StringValue("5".to_owned()))
    );
    assert_eq!(
        entries(request).await,
        Some(prost_types::value::Kind::StringValue("8".to_owned()))
    );
}

/// gRPC aggregates an absent query as the empty one and refuses a missing one in production's
/// words, as REST does (closure review F5).
#[tokio::test]
async fn grpc_aggregation_and_query_without_a_query_answer_as_rest_does() {
    let backend = test_backend();
    let service = GatewayService::local(test_gateway(), backend.clone());
    let request = super::query_transaction_tests::seeded_query(&backend, 3, false);
    let mut counted = aggregation(request.clone());
    if let Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
        aggregation,
    )) = &mut counted.query_type
    {
        aggregation.query_type = None;
    }
    let response = Firestore::run_aggregation_query(&service, Request::new(counted))
        .await
        .unwrap()
        .into_inner()
        .next()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        response.result.unwrap().aggregate_fields["count"].value_type,
        Some(pb::value::ValueType::IntegerValue(3))
    );
    let mut bare = request.clone();
    bare.query_type = None;
    let refused = Firestore::run_query(&service, Request::new(bare))
        .await
        .err()
        .expect("a query is required");
    assert_eq!(
        refused.message(),
        crate::query_messages::RUN_QUERY_WITHOUT_QUERY
    );
    let mut no_aggregation = aggregation(request);
    no_aggregation.query_type = None;
    let refused = Firestore::run_aggregation_query(&service, Request::new(no_aggregation))
        .await
        .err()
        .expect("an aggregation query is required");
    assert_eq!(
        refused.message(),
        crate::query_messages::AGGREGATION_WITHOUT_QUERY
    );
}
