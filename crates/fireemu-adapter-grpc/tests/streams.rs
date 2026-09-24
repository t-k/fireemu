//! `Write` and `Listen` streams through a real tonic client: handshake, sequential commits,
//! initial snapshots, live diffs after commits, target removal and rules denials.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::{FirestoreSnapshot, LocalBackend};
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_adapter_grpc::service::GatewayService;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet, IndexValidationPolicy,
    PlanningContext,
};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreState, Write as CoreWrite, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::tenancy::Scope;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use fireemu_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::StreamExt;
use tonic::Request;

const DB: &str = "projects/demo-app/databases/(default)";
const DOCS: &str = "projects/demo-app/databases/(default)/documents";

const RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /open/{id} { allow read, write: if true; }
    match /closed/{id} { allow read, write: if false; }
  }
}
";

thread_local! {
    static BACKEND: std::cell::RefCell<Option<Arc<LocalBackend>>> =
        const { std::cell::RefCell::new(None) };
}

async fn start(
    with_rules: bool,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    start_with_rules_source(with_rules.then_some(RULES)).await
}

async fn start_with_rules_source(
    rules_source: Option<&str>,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), 7));
    BACKEND.with(|b| *b.borrow_mut() = Some(backend.clone()));
    let mut service = GatewayService::local(gateway, backend);
    if let Some(rules_source) = rules_source {
        let auth = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        let rules = Arc::new(RulesetSlot::new(
            LoadedRules::from_source(rules_source).unwrap(),
        ));
        service = service.with_rules(Arc::new(RulesEnforcer::new(rules, auth, clock)));
    }
    let svc = FirestoreServer::new(service);
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
    (FirestoreClient::new(channel), handle)
}

fn s(v: &str) -> pb::Value {
    pb::Value {
        value_type: Some(pb::value::ValueType::StringValue(v.to_owned())),
    }
}
fn set_write(name: &str, fields: &[(&str, pb::Value)]) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: format!("{DOCS}/{name}"),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
            ..Default::default()
        })),
        ..Default::default()
    }
}
fn delete_write(name: &str) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Delete(format!("{DOCS}/{name}"))),
        ..Default::default()
    }
}

fn exists_precondition_write(name: &str, exists: bool) -> pb::Write {
    let mut write = set_write(name, &[("v", s("next"))]);
    write.current_document = Some(pb::Precondition {
        condition_type: Some(pb::precondition::ConditionType::Exists(exists)),
    });
    write
}

fn server_timestamp_write(name: &str) -> pb::Write {
    let mut write = set_write(name, &[]);
    write.update_transforms = vec![pb::document_transform::FieldTransform {
        field_path: "updatedAt".to_owned(),
        transform_type: Some(
            pb::document_transform::field_transform::TransformType::SetToServerValue(
                pb::document_transform::field_transform::ServerValue::RequestTime as i32,
            ),
        ),
    }];
    write
}

fn increment_write(name: &str, field: &str, amount: i64) -> pb::Write {
    let mut write = set_write(
        name,
        &[(
            field,
            pb::Value {
                value_type: Some(pb::value::ValueType::IntegerValue(5)),
            },
        )],
    );
    write.update_transforms = vec![pb::document_transform::FieldTransform {
        field_path: field.to_owned(),
        transform_type: Some(
            pb::document_transform::field_transform::TransformType::Increment(pb::Value {
                value_type: Some(pb::value::ValueType::IntegerValue(amount)),
            }),
        ),
    }];
    write
}
fn add_query_target(id: i32, collection: &str) -> pb::ListenRequest {
    pb::ListenRequest {
        database: DB.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
            target_id: id,
            target_type: Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                parent: DOCS.to_owned(),
                query_type: Some(pb::target::query_target::QueryType::StructuredQuery(
                    pb::StructuredQuery {
                        from: vec![sq::CollectionSelector {
                            collection_id: collection.to_owned(),
                            all_descendants: false,
                        }],
                        ..Default::default()
                    },
                )),
            })),
            ..Default::default()
        })),
        ..Default::default()
    }
}
fn add_filtered_query_target(id: i32, collection: &str) -> pb::ListenRequest {
    let mut request = add_query_target(id, collection);
    let Some(pb::listen_request::TargetChange::AddTarget(target)) = &mut request.target_change
    else {
        unreachable!();
    };
    let Some(pb::target::TargetType::Query(target)) = &mut target.target_type else {
        unreachable!();
    };
    let Some(pb::target::query_target::QueryType::StructuredQuery(query)) = &mut target.query_type
    else {
        unreachable!();
    };
    query.r#where = Some(pb::structured_query::Filter {
        filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: Some(sq::FieldReference {
                field_path: "state".to_owned(),
            }),
            op: sq::field_filter::Operator::Equal as i32,
            value: Some(s("included")),
        })),
    });
    request
}
fn add_limited_query_target(id: i32, collection: &str) -> pb::ListenRequest {
    let mut request = add_query_target(id, collection);
    let Some(pb::listen_request::TargetChange::AddTarget(target)) = &mut request.target_change
    else {
        unreachable!();
    };
    let Some(pb::target::TargetType::Query(target)) = &mut target.target_type else {
        unreachable!();
    };
    let Some(pb::target::query_target::QueryType::StructuredQuery(query)) = &mut target.query_type
    else {
        unreachable!();
    };
    query.order_by = vec![sq::Order {
        field: Some(sq::FieldReference {
            field_path: "v".to_owned(),
        }),
        direction: sq::Direction::Ascending as i32,
    }];
    query.limit = Some(1);
    request
}
fn add_documents_target(id: i32, names: &[&str]) -> pb::ListenRequest {
    pb::ListenRequest {
        database: DB.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
            target_id: id,
            target_type: Some(pb::target::TargetType::Documents(
                pb::target::DocumentsTarget {
                    documents: names.iter().map(|n| format!("{DOCS}/{n}")).collect(),
                },
            )),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// Short human-readable trace of listen responses.
fn describe(r: &pb::ListenResponse) -> String {
    use pb::listen_response::ResponseType as R;
    match &r.response_type {
        Some(R::TargetChange(t)) => {
            let kind = match t.target_change_type {
                0 => "NO_CHANGE",
                1 => "ADD",
                2 => "REMOVE",
                3 => "CURRENT",
                _ => "RESET",
            };
            let cause = t
                .cause
                .as_ref()
                .map_or(String::new(), |c| format!(" cause={}", c.code));
            format!("{kind}{:?}{cause}", t.target_ids)
        }
        Some(R::DocumentChange(d)) => format!(
            "CHANGE {}",
            d.document
                .as_ref()
                .map(|d| d.name.rsplit('/').next().unwrap_or("").to_owned())
                .unwrap_or_default()
        ),
        Some(R::DocumentDelete(d)) => {
            format!("DELETE {}", d.document.rsplit('/').next().unwrap_or(""))
        }
        Some(R::DocumentRemove(d)) => {
            format!("REMOVE {}", d.document.rsplit('/').next().unwrap_or(""))
        }
        Some(R::Filter(f)) => format!("FILTER {}", f.count),
        None => "?".to_owned(),
    }
}

async fn next_until<S>(stream: &mut S, stop: &str) -> Vec<String>
where
    S: tokio_stream::Stream<Item = Result<pb::ListenResponse, tonic::Status>> + Unpin,
{
    let mut out = Vec::new();
    loop {
        let item = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("listen response within 5 s")
            .expect("stream open")
            .unwrap();
        let text = describe(&item);
        out.push(text.clone());
        if text == stop {
            return out;
        }
    }
}

#[tokio::test]
async fn write_stream_handshake_then_sequential_commits() {
    let (mut client, handle) = start(false).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .write(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DB.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    let handshake = responses.next().await.unwrap().unwrap();
    assert!(!handshake.stream_token.is_empty());
    assert!(handshake.write_results.is_empty());
    tx.send(pb::WriteRequest {
        writes: vec![set_write("open/a", &[("v", s("1"))])],
        stream_token: handshake.stream_token.clone(),
        ..Default::default()
    })
    .await
    .unwrap();
    let committed = responses.next().await.unwrap().unwrap();
    assert_eq!(committed.write_results.len(), 1);
    assert!(committed.commit_time.is_some());
    // A stale token is rejected and ends the stream.
    tx.send(pb::WriteRequest {
        writes: vec![set_write("open/b", &[("v", s("2"))])],
        stream_token: vec![9, 9, 9],
        ..Default::default()
    })
    .await
    .unwrap();
    let err = responses.next().await.unwrap().unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/open/b"),
            ..Default::default()
        })
        .await
        .is_err());
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn write_stream_refuses_active_transaction_contention_without_mutation() {
    let (mut client, handle) = start(false).await;
    let locked_name = format!("{DOCS}/open/locked");

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("open/locked", &[("v", s("before"))])],
            ..Default::default()
        })
        .await
        .unwrap();

    // An uncontended stream write is the nearby positive control.
    let (control_tx, control_rx) = mpsc::channel(8);
    let mut control = client
        .write(ReceiverStream::new(control_rx))
        .await
        .unwrap()
        .into_inner();
    control_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let control_handshake = control.next().await.unwrap().unwrap();
    control_tx
        .send(pb::WriteRequest {
            stream_token: control_handshake.stream_token,
            writes: vec![set_write("open/control", &[("v", s("accepted"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        control.next().await.unwrap().unwrap().write_results.len(),
        1
    );
    drop(control_tx);
    drop(control);

    let transaction = client
        .begin_transaction(pb::BeginTransactionRequest {
            database: DB.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite::default(),
                )),
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .transaction;
    client
        .get_document(pb::GetDocumentRequest {
            name: locked_name.clone(),
            consistency_selector: Some(pb::get_document_request::ConsistencySelector::Transaction(
                transaction.clone(),
            )),
            ..Default::default()
        })
        .await
        .unwrap();

    let (contended_tx, contended_rx) = mpsc::channel(8);
    let mut contended = client
        .write(ReceiverStream::new(contended_rx))
        .await
        .unwrap()
        .into_inner();
    contended_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let handshake = contended.next().await.unwrap().unwrap();
    contended_tx
        .send(pb::WriteRequest {
            stream_token: handshake.stream_token,
            writes: vec![
                set_write("open/locked", &[("v", s("must-not-commit"))]),
                set_write("open/contended-tail", &[("v", s("must-not-commit"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let error = contended.next().await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::Aborted);
    drop(contended_tx);
    drop(contended);

    let locked = client
        .get_document(pb::GetDocumentRequest {
            name: locked_name.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(locked.fields["v"], s("before"));
    assert_eq!(
        client
            .get_document(pb::GetDocumentRequest {
                name: format!("{DOCS}/open/contended-tail"),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );

    client
        .rollback(pb::RollbackRequest {
            database: DB.to_owned(),
            transaction,
            ..Default::default()
        })
        .await
        .unwrap();

    let (released_tx, released_rx) = mpsc::channel(8);
    let mut released = client
        .write(ReceiverStream::new(released_rx))
        .await
        .unwrap()
        .into_inner();
    released_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let released_handshake = released.next().await.unwrap().unwrap();
    released_tx
        .send(pb::WriteRequest {
            stream_token: released_handshake.stream_token,
            writes: vec![set_write("open/locked", &[("v", s("after-rollback"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        released.next().await.unwrap().unwrap().write_results.len(),
        1
    );
    drop(released_tx);
    drop(released);
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn write_stream_tokens_are_bound_to_stream_and_stream_id() {
    let (mut client, handle) = start(false).await;
    let (first_tx, first_rx) = mpsc::channel(8);
    let mut first = client
        .write(ReceiverStream::new(first_rx))
        .await
        .unwrap()
        .into_inner();
    first_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let first_handshake = first.next().await.unwrap().unwrap();

    first_tx
        .send(pb::WriteRequest {
            stream_id: "fireemu-wrong".to_owned(),
            stream_token: first_handshake.stream_token.clone(),
            writes: vec![set_write("stream/wrong-id", &[("v", s("x"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        first.next().await.unwrap().unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    drop(first_tx);
    drop(first);

    let (second_tx, second_rx) = mpsc::channel(8);
    let mut second = client
        .write(ReceiverStream::new(second_rx))
        .await
        .unwrap()
        .into_inner();
    second_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let second_handshake = second.next().await.unwrap().unwrap();
    second_tx
        .send(pb::WriteRequest {
            stream_token: first_handshake.stream_token,
            writes: vec![set_write("stream/cross-stream", &[("v", s("x"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        second.next().await.unwrap().unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    assert_ne!(second_handshake.stream_token, Vec::<u8>::new());
    drop(second_tx);
    drop(second);

    let (third_tx, third_rx) = mpsc::channel(8);
    let mut third = client
        .write(ReceiverStream::new(third_rx))
        .await
        .unwrap()
        .into_inner();
    third_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let third_handshake = third.next().await.unwrap().unwrap();
    let acknowledged_token = third_handshake.stream_token.clone();
    third_tx
        .send(pb::WriteRequest {
            stream_token: acknowledged_token.clone(),
            writes: vec![set_write("stream/continuity", &[("v", s("x"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let next = third.next().await.unwrap().unwrap();
    third_tx
        .send(pb::WriteRequest {
            stream_token: next.stream_token.clone(),
            writes: vec![set_write("stream/continuity-2", &[("v", s("y"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let _next = third.next().await.unwrap().unwrap();
    third_tx
        .send(pb::WriteRequest {
            stream_token: acknowledged_token,
            writes: vec![set_write("stream/replay", &[("v", s("x"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        third.next().await.unwrap().unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    drop(third_tx);
    drop(third);

    let (fourth_tx, fourth_rx) = mpsc::channel(8);
    let mut fourth = client
        .write(ReceiverStream::new(fourth_rx))
        .await
        .unwrap()
        .into_inner();
    fourth_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let fourth_handshake = fourth.next().await.unwrap().unwrap();
    let mut future_token = fourth_handshake.stream_token;
    future_token[15] = 9;
    fourth_tx
        .send(pb::WriteRequest {
            stream_token: future_token,
            writes: vec![set_write("stream/future", &[("v", s("x"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        fourth.next().await.unwrap().unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    drop(fourth_tx);
    drop(fourth);
    handle.abort();
    handle.await.unwrap_err();
}

#[tokio::test]
async fn listen_delivers_snapshot_then_live_diffs() {
    let (mut client, handle) = start(false).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("open/a", &[("v", s("1"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(1, "open")).await.unwrap();
    let initial = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(
        initial,
        vec![
            "ADD[1]",
            "CHANGE a",
            "CURRENT[1]",
            "NO_CHANGE[1]",
            "NO_CHANGE[]"
        ]
    );

    // A commit on the database is pushed as a diff.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                set_write("open/b", &[("v", s("2"))]),
                set_write("open/a", &[("v", s("1b"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let diff = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(
        diff,
        vec!["CHANGE a", "CHANGE b", "NO_CHANGE[1]", "NO_CHANGE[]"]
    );

    // Deleting a document is reported as DELETE; a no-op write reports nothing new.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![delete_write("open/b")],
            ..Default::default()
        })
        .await
        .unwrap();
    let diff = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(diff, vec!["DELETE b", "NO_CHANGE[1]", "NO_CHANGE[]"]);

    // Document targets for a missing document become CURRENT without a change.
    tx.send(add_documents_target(2, &["open/missing"]))
        .await
        .unwrap();
    let initial = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(
        initial,
        vec![
            "ADD[2]",
            "CURRENT[2]",
            "NO_CHANGE[1]",
            "NO_CHANGE[2]",
            "NO_CHANGE[]"
        ],
        "every active target reaches the same snapshot before the global boundary"
    );

    tx.send(pb::ListenRequest {
        database: DB.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::RemoveTarget(1)),
        ..Default::default()
    })
    .await
    .unwrap();
    let removed = next_until(&mut responses, "REMOVE[1]").await;
    assert_eq!(removed, vec!["REMOVE[1]"]);
    handle.abort();
}

#[tokio::test]
async fn incremental_listen_preserves_enter_update_remove_and_delete() {
    let (mut client, handle) = start(false).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("delta/a", &[("state", s("excluded"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_filtered_query_target(1, "delta"))
        .await
        .unwrap();
    assert_eq!(
        next_until(&mut responses, "NO_CHANGE[]").await,
        vec!["ADD[1]", "CURRENT[1]", "NO_CHANGE[1]", "NO_CHANGE[]"]
    );

    for (write, expected) in [
        (
            set_write("delta/a", &[("state", s("included")), ("revision", s("1"))]),
            "CHANGE a",
        ),
        (
            set_write("delta/a", &[("state", s("included")), ("revision", s("2"))]),
            "CHANGE a",
        ),
        (
            set_write("delta/a", &[("state", s("excluded"))]),
            "REMOVE a",
        ),
        (
            set_write("delta/a", &[("state", s("included"))]),
            "CHANGE a",
        ),
        (delete_write("delta/a"), "DELETE a"),
    ] {
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![write],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            next_until(&mut responses, "NO_CHANGE[]").await,
            vec![expected, "NO_CHANGE[1]", "NO_CHANGE[]"]
        );
    }
    handle.abort();
}

#[tokio::test]
async fn limited_listen_recomputes_the_boundary_after_an_update() {
    let (mut client, handle) = start(false).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                set_write("limited/a", &[("v", s("1"))]),
                set_write("limited/b", &[("v", s("2"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_limited_query_target(1, "limited"))
        .await
        .unwrap();
    assert_eq!(
        next_until(&mut responses, "NO_CHANGE[]").await,
        vec![
            "ADD[1]",
            "CHANGE a",
            "CURRENT[1]",
            "NO_CHANGE[1]",
            "NO_CHANGE[]"
        ]
    );

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("limited/a", &[("v", s("3"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        next_until(&mut responses, "NO_CHANGE[]").await,
        vec!["CHANGE b", "REMOVE a", "NO_CHANGE[1]", "NO_CHANGE[]"]
    );
    handle.abort();
    handle.await.unwrap_err();
}

#[tokio::test]
async fn listen_and_write_streams_enforce_rules() {
    let (mut client, handle) = start(true).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(7, "closed")).await.unwrap();
    let denied = next_until(&mut responses, "REMOVE[7] cause=7").await;
    assert_eq!(denied, vec!["ADD[7]", "REMOVE[7] cause=7"]);
    tx.send(add_documents_target(8, &["open/x"])).await.unwrap();
    let ok = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(
        ok,
        vec!["ADD[8]", "CURRENT[8]", "NO_CHANGE[8]", "NO_CHANGE[]"]
    );

    let (wtx, wrx) = mpsc::channel(8);
    let mut writes = client
        .write(ReceiverStream::new(wrx))
        .await
        .unwrap()
        .into_inner();
    wtx.send(pb::WriteRequest {
        database: DB.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    let handshake = writes.next().await.unwrap().unwrap();
    wtx.send(pb::WriteRequest {
        writes: vec![set_write("closed/x", &[("v", s("1"))])],
        stream_token: handshake.stream_token,
        ..Default::default()
    })
    .await
    .unwrap();
    let err = writes.next().await.unwrap().unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    handle.abort();
}

#[tokio::test]
async fn listen_reauthorizes_when_a_rules_dependency_changes() {
    const DEPENDENT_RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /gate/{id} { allow read, write: if true; }
    match /protected/{id} {
      allow read: if get(/databases/$(database)/documents/gate/access).data.enabled == 'yes';
      allow write: if true;
    }
  }
}
";
    let (mut client, handle) = start_with_rules_source(Some(DEPENDENT_RULES)).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                set_write("gate/access", &[("enabled", s("yes"))]),
                set_write("protected/a", &[("v", s("1"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(1, "protected")).await.unwrap();
    assert_eq!(
        next_until(&mut responses, "NO_CHANGE[]").await,
        vec![
            "ADD[1]",
            "CHANGE a",
            "CURRENT[1]",
            "NO_CHANGE[1]",
            "NO_CHANGE[]"
        ]
    );

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("gate/access", &[("enabled", s("no"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        next_until(&mut responses, "REMOVE[1] cause=7").await,
        vec!["REMOVE[1] cause=7"]
    );
    handle.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_denied_target_stays_removed_until_explicitly_readded_after_rules_recovery() {
    const DEPENDENT_RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /gate/{id} { allow read, write: if true; }
    match /protected/{id} {
      allow read: if get(/databases/$(database)/documents/gate/access).data.enabled == 'yes';
      allow write: if true;
    }
  }
}
";
    let (mut client, handle) = start_with_rules_source(Some(DEPENDENT_RULES)).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                set_write("gate/access", &[("enabled", s("yes"))]),
                set_write("protected/a", &[("v", s("1"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(1, "protected")).await.unwrap();
    let (initial, token) = trace_and_token(&mut responses, "NO_CHANGE[]").await;
    assert!(!token.is_empty());
    assert_eq!(
        initial,
        vec![
            "ADD[1]",
            "CHANGE a",
            "CURRENT[1]",
            "NO_CHANGE[1]",
            "NO_CHANGE[]"
        ]
    );

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("gate/access", &[("enabled", s("no"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        next_until(&mut responses, "REMOVE[1] cause=7").await,
        vec!["REMOVE[1] cause=7"]
    );
    // Local safety regression: a previously valid resume token cannot bypass current rules.
    let (reconnect_tx, reconnect_rx) = mpsc::channel(8);
    let mut reconnect = client
        .listen(ReceiverStream::new(reconnect_rx))
        .await
        .unwrap()
        .into_inner();
    let mut resumed = add_query_target(3, "protected");
    if let Some(pb::listen_request::TargetChange::AddTarget(target)) = &mut resumed.target_change {
        target.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
    }
    reconnect_tx.send(resumed).await.unwrap();
    assert_eq!(
        next_until(&mut reconnect, "REMOVE[3] cause=7").await,
        vec!["ADD[3]", "REMOVE[3] cause=7"]
    );
    drop(reconnect_tx);
    drop(reconnect);

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                set_write("gate/access", &[("enabled", s("yes"))]),
                set_write("protected/a", &[("v", s("2"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    // A successful target snapshot is a positive barrier, avoiding a silence timeout.
    tx.send(add_documents_target(2, &["gate/access"]))
        .await
        .unwrap();
    let barrier = next_until(&mut responses, "CURRENT[2]").await;
    assert!(barrier.iter().any(|event| event == "CHANGE access"));
    assert!(barrier.iter().all(|event| matches!(
        event.as_str(),
        "NO_CHANGE[]" | "ADD[2]" | "CHANGE access" | "CURRENT[2]"
    )));
    assert_eq!(
        next_until(&mut responses, "NO_CHANGE[]").await,
        vec!["NO_CHANGE[2]", "NO_CHANGE[]"]
    );

    tx.send(add_query_target(1, "protected")).await.unwrap();
    let mut revision = None;
    loop {
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match response.response_type.unwrap() {
            pb::listen_response::ResponseType::DocumentChange(change) => {
                assert_eq!(change.target_ids, vec![1]);
                let document = change.document.unwrap();
                assert_eq!(document.name, format!("{DOCS}/protected/a"));
                assert!(revision.replace(document.fields["v"].clone()).is_none());
            }
            pb::listen_response::ResponseType::TargetChange(change) => {
                assert_ne!(
                    change.target_change_type,
                    pb::target_change::TargetChangeType::Remove as i32
                );
                if change.target_change_type == pb::target_change::TargetChangeType::Current as i32
                {
                    assert_eq!(change.target_ids, vec![1]);
                    break;
                }
            }
            other => panic!("unexpected readd response: {other:?}"),
        }
    }
    assert_eq!(revision, Some(s("2")));
    drop(tx);
    drop(responses);

    let (trailing_tx, trailing_rx) = mpsc::channel(8);
    let mut trailing = client
        .write(ReceiverStream::new(trailing_rx))
        .await
        .unwrap()
        .into_inner();
    trailing_tx
        .send(pb::WriteRequest {
            database: format!("{DB}/documents"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        trailing.next().await.unwrap().unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    drop(trailing_tx);
    drop(trailing);
    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn write_stream_rules_refuse_malformed_and_wrong_audience_auth() {
    for authorization in [
        "Bearer malformed",
        "Bearer eyJhbGciOiJub25lIn0.eyJhdWQiOiJvdGhlciJ9.",
    ] {
        let (mut client, handle) = start(true).await;
        let (tx, rx) = mpsc::channel(8);
        let mut request = Request::new(ReceiverStream::new(rx));
        request.metadata_mut().insert(
            "authorization",
            authorization.parse().expect("ASCII authorization"),
        );
        let mut responses = client.write(request).await.unwrap().into_inner();
        tx.send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
        responses.next().await.unwrap().unwrap();
        tx.send(pb::WriteRequest {
            writes: vec![set_write("stream/auth-refused", &[("v", s("x"))])],
            ..Default::default()
        })
        .await
        .unwrap();
        let error = responses.next().await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert!(client
            .get_document(pb::GetDocumentRequest {
                name: format!("{DOCS}/stream/auth-refused"),
                ..Default::default()
            })
            .await
            .is_err());
        drop(tx);
        drop(responses);
        handle.abort();
        handle.await.unwrap_err();
    }
}

#[tokio::test]
async fn write_stream_accepts_pipelined_acknowledgements_and_once_targets_are_removed() {
    let (mut client, handle) = start(false).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .write(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DB.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    let handshake = responses.next().await.unwrap().unwrap();
    assert!(!handshake.stream_id.is_empty());
    // Two distinguishable batches queued against the same acknowledged token (what the JS
    // SDK does); response swapping is observable from result cardinality.
    tx.send(pb::WriteRequest {
        writes: vec![set_write("open/p1", &[("v", s("one"))])],
        stream_token: handshake.stream_token.clone(),
        ..Default::default()
    })
    .await
    .unwrap();
    tx.send(pb::WriteRequest {
        writes: vec![
            set_write("open/p2", &[("v", s("two"))]),
            set_write("open/p3", &[("v", s("three"))]),
        ],
        stream_token: handshake.stream_token.clone(),
        ..Default::default()
    })
    .await
    .unwrap();
    let first = responses.next().await.unwrap().unwrap();
    let second = responses.next().await.unwrap().unwrap();
    assert!(
        first.stream_id.is_empty(),
        "the stream id is only announced once"
    );
    assert_ne!(first.stream_token, second.stream_token);
    assert_eq!(first.write_results.len(), 1);
    assert_eq!(second.write_results.len(), 2);

    // A `once` target ends with REMOVE after its consistent snapshot; a resume token
    // triggers RESET before the replay.
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    let mut once = add_query_target(3, "open");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut once.target_change {
        t.once = true;
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(vec![1, 2, 3]));
    }
    ltx.send(once).await.unwrap();
    let trace = next_until(&mut listen, "REMOVE[3]").await;
    assert_eq!(
        trace,
        vec![
            "ADD[3]",
            "RESET[3]",
            "CHANGE p1",
            "CHANGE p2",
            "CHANGE p3",
            "CURRENT[3]",
            "NO_CHANGE[3]",
            "NO_CHANGE[]",
            "REMOVE[3]"
        ]
    );
    handle.abort();
}

/// FS-WRITE-STREAM-LOCAL: the public stream contract preserves request order, applies
/// preconditions and transforms atomically, and exposes commit versions in every result.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn write_stream_preserves_order_preconditions_transforms_and_post_state() {
    let (mut client, handle) = start(false).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .write(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DB.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    let handshake = responses.next().await.unwrap().unwrap();

    tx.send(pb::WriteRequest {
        stream_token: handshake.stream_token,
        writes: vec![
            set_write("stream/a", &[("v", s("first"))]),
            set_write("stream/a", &[("v", s("second"))]),
            increment_write("stream/b", "v", 2),
            server_timestamp_write("stream/c"),
        ],
        ..Default::default()
    })
    .await
    .unwrap();
    let committed = responses.next().await.unwrap().unwrap();
    assert_eq!(committed.write_results.len(), 4);
    assert!(committed.write_results[0].update_time.is_some());
    assert!(committed.write_results[1].update_time.is_some());
    assert_eq!(
        committed.write_results[0].transform_results,
        Vec::<pb::Value>::new()
    );
    assert_eq!(
        committed.write_results[2].transform_results,
        vec![pb::Value {
            value_type: Some(pb::value::ValueType::IntegerValue(7))
        }]
    );
    assert!(committed.commit_time.is_some());

    let a = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/stream/a"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let b = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/stream/b"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let c = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/stream/c"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(a.fields["v"], s("second"));
    assert_eq!(
        b.fields["v"],
        pb::Value {
            value_type: Some(pb::value::ValueType::IntegerValue(7))
        }
    );
    let stored_c = match c.fields["updatedAt"].value_type.as_ref() {
        Some(pb::value::ValueType::TimestampValue(timestamp)) => timestamp,
        other => panic!("expected stored timestamp, got {other:?}"),
    };
    assert_eq!(
        committed.write_results[3].transform_results,
        vec![pb::Value {
            value_type: Some(pb::value::ValueType::TimestampValue(*stored_c))
        }]
    );
    assert_eq!(Some(*stored_c), committed.write_results[3].update_time);
    assert_eq!(a.fields["v"], s("second"));
    assert_eq!(committed.write_results[0].update_time, a.update_time);
    assert_eq!(committed.write_results[1].update_time, a.update_time);
    assert_eq!(committed.write_results[2].update_time, b.update_time);
    assert_eq!(committed.write_results[3].update_time, c.update_time);
    assert_eq!(
        committed.write_results[0].update_time,
        committed.commit_time
    );
    assert_eq!(
        committed.write_results[1].update_time,
        committed.commit_time
    );
    assert_eq!(
        committed.write_results[2].update_time,
        committed.commit_time
    );
    assert_eq!(
        committed.write_results[3].update_time,
        committed.commit_time
    );
    assert_eq!(
        committed.commit_time,
        committed.write_results[0].update_time
    );

    // A refused precondition does not publish an earlier write in the same request and
    // terminates this stream; a fresh stream can still commit successfully.
    tx.send(pb::WriteRequest {
        writes: vec![
            set_write("stream/refused-prefix", &[("v", s("must-not-publish"))]),
            exists_precondition_write("stream/a", false),
        ],
        stream_token: committed.stream_token,
        ..Default::default()
    })
    .await
    .unwrap();
    let refused = responses.next().await.unwrap().unwrap_err();
    // Local precedence for this conflicting exists=false update is ALREADY_EXISTS;
    // production precedence is intentionally unclaimed without a saved observation.
    assert_eq!(refused.code(), tonic::Code::AlreadyExists);
    let unchanged = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/stream/a"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(unchanged.fields, a.fields);
    assert_eq!(unchanged.update_time, a.update_time);
    assert!(client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/stream/refused-prefix"),
            ..Default::default()
        })
        .await
        .is_err());
    assert!(tx
        .send(pb::WriteRequest {
            writes: vec![set_write("stream/after-refusal", &[("v", s("no"))])],
            ..Default::default()
        })
        .await
        .is_err());
    drop(responses);

    let (reopen_tx, reopen_rx) = mpsc::channel(8);
    let mut reopened = client
        .write(ReceiverStream::new(reopen_rx))
        .await
        .unwrap()
        .into_inner();
    reopen_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let fresh = reopened.next().await.unwrap().unwrap();
    reopen_tx
        .send(pb::WriteRequest {
            stream_token: fresh.stream_token,
            writes: vec![set_write("stream/reopened", &[("v", s("ok"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let reopened_result = reopened.next().await.unwrap().unwrap();
    assert_eq!(reopened_result.write_results.len(), 1);
    assert!(reopened_result.write_results[0].update_time.is_some());
    let reopened_doc = client
        .get_document(pb::GetDocumentRequest {
            name: format!("{DOCS}/stream/reopened"),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reopened_doc.fields["v"], s("ok"));
    drop(reopen_tx);
    drop(reopened);
    handle.abort();
    handle.await.unwrap_err();
}

/// FS-WRITE-STREAM-LOCAL: a graceful client half-close completes the stream after the
/// handshake and has no mutation side effect.
#[tokio::test]
async fn write_stream_graceful_half_close_has_no_side_effect() {
    let (mut client, handle) = start(false).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .write(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DB.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    let handshake = responses.next().await.unwrap().unwrap();
    drop(tx);
    assert!(responses.next().await.is_none());
    assert!(!handshake.stream_token.is_empty());
    handle.abort();
    handle.await.unwrap_err();
}

/// FS-WRITE-STREAM-LOCAL: handshake fields establish the routed database, and every later
/// write must stay inside that project/database namespace.
#[tokio::test]
async fn write_stream_enforces_handshake_and_database_ownership() {
    let (mut client, handle) = start(false).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .write(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DB.to_owned(),
        writes: vec![set_write("stream/invalid-handshake", &[("v", s("x"))])],
        ..Default::default()
    })
    .await
    .unwrap();
    let error = responses.next().await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    drop(tx);
    drop(responses);

    let (escape_tx, escape_rx) = mpsc::channel(8);
    let mut escape = client
        .write(ReceiverStream::new(escape_rx))
        .await
        .unwrap()
        .into_inner();
    escape_tx
        .send(pb::WriteRequest {
            database: format!("{DB}/documents/escape"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        escape.next().await.unwrap().unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
    drop(escape_tx);
    drop(escape);

    let (resume_tx, resume_rx) = mpsc::channel(8);
    let mut resume = client
        .write(ReceiverStream::new(resume_rx))
        .await
        .unwrap()
        .into_inner();
    resume_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            stream_id: "old-stream".to_owned(),
            stream_token: vec![1],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        resume.next().await.unwrap().unwrap_err().code(),
        tonic::Code::FailedPrecondition
    );
    drop(resume_tx);
    drop(resume);

    let (owner_tx, owner_rx) = mpsc::channel(8);
    let mut owner_responses = client
        .write(ReceiverStream::new(owner_rx))
        .await
        .unwrap()
        .into_inner();
    owner_tx
        .send(pb::WriteRequest {
            database: DB.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let handshake = owner_responses.next().await.unwrap().unwrap();
    let mut foreign = set_write("stream/foreign", &[("v", s("x"))]);
    if let Some(pb::write::Operation::Update(document)) = &mut foreign.operation {
        document.name = "projects/demo-app/databases/other/documents/stream/foreign".to_owned();
    }
    owner_tx
        .send(pb::WriteRequest {
            stream_token: handshake.stream_token,
            writes: vec![foreign],
            ..Default::default()
        })
        .await
        .unwrap();
    let error = owner_responses.next().await.unwrap().unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(client
        .get_document(pb::GetDocumentRequest {
            name: "projects/demo-app/databases/other/documents/stream/foreign".to_owned(),
            ..Default::default()
        })
        .await
        .is_err());
    drop(owner_tx);
    drop(owner_responses);
    handle.abort();
    handle.await.unwrap_err();
}

#[tokio::test]
async fn a_removed_target_id_can_be_reused_without_delivering_the_old_query() {
    let (mut client, handle) = start(false).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                set_write("first/a", &[("v", s("first"))]),
                set_write("second/b", &[("v", s("second"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    tx.send(add_query_target(1, "first")).await.unwrap();
    assert_eq!(
        next_until(&mut responses, "NO_CHANGE[]").await,
        vec![
            "ADD[1]",
            "CHANGE a",
            "CURRENT[1]",
            "NO_CHANGE[1]",
            "NO_CHANGE[]"
        ]
    );
    tx.send(pb::ListenRequest {
        database: DB.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::RemoveTarget(1)),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        next_until(&mut responses, "REMOVE[1]").await,
        vec!["REMOVE[1]"]
    );

    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("first/late", &[("v", s("stale"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    tx.send(add_query_target(1, "second")).await.unwrap();
    assert_eq!(
        next_until(&mut responses, "NO_CHANGE[]").await,
        vec![
            "ADD[1]",
            "CHANGE b",
            "CURRENT[1]",
            "NO_CHANGE[1]",
            "NO_CHANGE[]"
        ]
    );
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                set_write("first/new", &[("v", s("must-not-deliver"))]),
                set_write("second/c", &[("v", s("replacement"))]),
            ],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        next_until(&mut responses, "NO_CHANGE[]").await,
        vec!["CHANGE c", "NO_CHANGE[1]", "NO_CHANGE[]"]
    );
    handle.abort();
}

#[tokio::test]
async fn streams_end_when_the_session_is_reset() {
    let (mut client, handle) = start(false).await;
    // The write stream is opened before the reset...
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .write(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(pb::WriteRequest {
        database: DB.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    let handshake = responses.next().await.unwrap().unwrap();
    // ...and a listener too.
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    ltx.send(add_query_target(1, "open")).await.unwrap();
    let _ = next_until(&mut listen, "NO_CHANGE[]").await;

    // Reset through the shared backend (what the control API does).
    BACKEND.with(|b| {
        if let Some(backend) = b.borrow().as_ref() {
            backend.reset();
        }
    });

    tx.send(pb::WriteRequest {
        writes: vec![set_write("open/after", &[("v", s("1"))])],
        stream_token: handshake.stream_token,
        ..Default::default()
    })
    .await
    .unwrap();
    let err = responses.next().await.unwrap().unwrap_err();
    assert_eq!(err.code(), tonic::Code::Aborted, "{err}");
    let trace = next_until(&mut listen, "REMOVE[1] cause=10").await;
    assert!(
        trace.ends_with(&["REMOVE[1] cause=10".to_owned()]),
        "{trace:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn slow_listeners_get_coalesced_refreshes_and_targets_are_capped() {
    let (mut client, handle) = start(false).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("open/a", &[("v", s("0"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(1, "open")).await.unwrap();
    let _ = next_until(&mut responses, "NO_CHANGE[]").await;
    // 300 commits of a 20 KiB document while the client reads nothing: the HTTP/2 flow
    // control window and the response channel fill, the loop blocks on the send, and the
    // commits that land meanwhile are coalesced into few refreshes.
    let payload = "x".repeat(20 * 1024);
    for i in 0..300 {
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![set_write(
                    "open/a",
                    &[("v", s(&format!("{}-{payload}", i + 1)))],
                )],
                ..Default::default()
            })
            .await
            .unwrap();
    }
    // Drain until the stream is idle for a while.
    let mut labels: Vec<String> = Vec::new();
    while let Ok(Some(item)) =
        tokio::time::timeout(std::time::Duration::from_millis(700), responses.next()).await
    {
        labels.push(describe(&item.unwrap()));
    }
    let changes = labels.iter().filter(|l| l.starts_with("CHANGE a")).count();
    assert!(changes < 300, "{changes} refreshes for 300 commits");
    assert!(changes >= 1, "{labels:?}");
    assert_eq!(labels.last().map(String::as_str), Some("NO_CHANGE[]"));
    // The 1001st target is refused explicitly.
    for id in 2..=1000 {
        tx.send(add_documents_target(id, &["open/missing"]))
            .await
            .unwrap();
        let _ = next_until(&mut responses, "NO_CHANGE[]").await;
    }
    tx.send(add_documents_target(1001, &["open/missing"]))
        .await
        .unwrap();
    let err = loop {
        match responses.next().await {
            Some(Ok(_)) => {}
            Some(Err(e)) => break e,
            None => panic!("stream ended without an error"),
        }
    };
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    handle.abort();
}

/// The trace up to `stop` and the resume token of its last boundary.
async fn trace_and_token<S>(stream: &mut S, stop: &str) -> (Vec<String>, Vec<u8>)
where
    S: tokio_stream::Stream<Item = Result<pb::ListenResponse, tonic::Status>> + Unpin,
{
    let mut token = Vec::new();
    let mut trace = Vec::new();
    loop {
        let item = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("listen response within 5 s")
            .expect("stream open")
            .unwrap();
        if let Some(pb::listen_response::ResponseType::TargetChange(t)) = &item.response_type {
            if !t.resume_token.is_empty() {
                token.clone_from(&t.resume_token);
            }
        }
        let text = describe(&item);
        trace.push(text.clone());
        if text == stop {
            return (trace, token);
        }
    }
}

#[tokio::test]
async fn resumed_targets_replay_only_what_changed_since_the_token() {
    let (mut client, handle) = start(false).await;
    let commit = |writes| pb::CommitRequest {
        database: DB.to_owned(),
        writes,
        ..Default::default()
    };
    client
        .commit(commit(vec![
            set_write("r/a", &[("v", s("1"))]),
            set_write("r/b", &[("v", s("1"))]),
        ]))
        .await
        .unwrap();
    // First listener: initial snapshot, keep its token.
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    ltx.send(add_query_target(1, "r")).await.unwrap();
    let (_, token) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(
        token.len(),
        32,
        "version, epoch, database and target binding"
    );
    drop(ltx);
    // Meanwhile: b changes, c is added, a is deleted.
    client
        .commit(commit(vec![
            set_write("r/b", &[("v", s("2"))]),
            set_write("r/c", &[("v", s("1"))]),
            delete_write("r/a"),
        ]))
        .await
        .unwrap();
    // Resume with the token: no RESET, only the changes since, then the existence filter.
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    let mut resumed = add_query_target(2, "r");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut resumed.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token.clone()));
    }
    ltx.send(resumed).await.unwrap();
    let (trace, latest) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(
        trace,
        vec![
            "ADD[2]",
            "CHANGE b",
            "CHANGE c",
            "DELETE a",
            "FILTER 2",
            "CURRENT[2]",
            "NO_CHANGE[2]",
            "NO_CHANGE[]"
        ]
    );
    // Nothing changed: a resume replays nothing but the filter and the boundary.
    let mut again = add_query_target(3, "r");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut again.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(latest));
    }
    ltx.send(again).await.unwrap();
    let trace = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(
        trace,
        vec![
            "ADD[3]",
            "FILTER 2",
            "CURRENT[3]",
            "NO_CHANGE[2]",
            "NO_CHANGE[3]",
            "NO_CHANGE[]"
        ]
    );
    // A token from the future (or garbage) resets.
    let mut future = add_query_target(4, "r");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut future.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(
            u64::MAX.to_be_bytes().to_vec(),
        ));
    }
    ltx.send(future).await.unwrap();
    let trace = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(trace[..4], ["ADD[4]", "RESET[4]", "CHANGE b", "CHANGE c"]);
    handle.abort();
}

/// The first `count` names `name(i)` the partition sampler picks, so a small test group splits
/// the way a large production group does.
fn sampled_names(count: usize, name: impl Fn(usize) -> String) -> Vec<String> {
    let project = fireemu_core_types::ids::ProjectId::try_new("demo-app").unwrap();
    let database = fireemu_core_types::ids::DatabaseId::try_new("(default)").unwrap();
    (0..)
        .map(name)
        .filter(|relative| {
            fireemu_adapter_grpc::partition::is_sample(
                &fireemu_core_firestore::path::DocumentPath::parse(&project, &database, relative)
                    .unwrap(),
            )
        })
        .take(count)
        .collect()
}

fn partition_request(
    collection: &str,
    count: i64,
    page_size: i32,
    page_token: &str,
) -> pb::PartitionQueryRequest {
    pb::PartitionQueryRequest {
        parent: DOCS.to_owned(),
        partition_count: count,
        page_size,
        page_token: page_token.to_owned(),
        query_type: Some(pb::partition_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: collection.to_owned(),
                    all_descendants: true,
                }],
                order_by: vec![sq::Order {
                    field: Some(sq::FieldReference {
                        field_path: "__name__".to_owned(),
                    }),
                    direction: sq::Direction::Ascending as i32,
                }],
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

fn cursor_name(cursor: &pb::Cursor) -> String {
    match &cursor.values[0].value_type {
        Some(pb::value::ValueType::ReferenceValue(r)) => {
            r.strip_prefix(&format!("{DOCS}/")).unwrap_or(r).to_owned()
        }
        other => panic!("{other:?}"),
    }
}

/// Production splits a collection group at sampled keys: `partition_count` cursors (all the
/// samples when there are fewer), nested across counts, in key order, without `before`
/// (FS-QUERY-INDEX partition-query/large-group).
#[tokio::test]
async fn partition_query_splits_a_collection_group_at_sampled_keys() {
    let (mut client, handle) = start(false).await;
    let samples = sampled_names(5, |i| format!("owners/o{i}/items/i{i}"));
    let others: Vec<String> = (0..5)
        .map(|i| format!("owners/x{i}/items/j{i}"))
        .filter(|name| !sampled_names(64, |i| format!("owners/x{i}/items/j{i}")).contains(name))
        .collect();
    let writes: Vec<pb::Write> = samples
        .iter()
        .chain(&others)
        .map(|name| set_write(name, &[("v", s("x"))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let names = |response: &pb::PartitionQueryResponse| {
        response
            .partitions
            .iter()
            .map(cursor_name)
            .collect::<Vec<_>>()
    };
    let four = client
        .partition_query(partition_request("items", 4, 0, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(four.partitions.len(), 4);
    assert!(four.partitions.iter().all(|c| !c.before));
    assert!(names(&four).iter().all(|name| samples.contains(name)));
    let mut sorted = names(&four);
    sorted.sort_by(|a, b| a.split('/').cmp(b.split('/')));
    assert_eq!(names(&four), sorted, "key order");
    assert!(four.next_page_token.is_empty());
    let two = client
        .partition_query(partition_request("items", 2, 0, ""))
        .await
        .unwrap()
        .into_inner();
    assert!(
        names(&two).iter().all(|name| names(&four).contains(name)),
        "nested"
    );
    // More partitions than samples: every sample.
    let all = client
        .partition_query(partition_request("items", 100, 0, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(all.partitions.len(), samples.len());
    // Paged.
    let first = client
        .partition_query(partition_request("items", 4, 3, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.partitions.len(), 3);
    assert!(!first.next_page_token.is_empty());
    let second = client
        .partition_query(partition_request("items", 4, 3, &first.next_page_token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!([names(&first), names(&second)].concat(), names(&four));
    assert!(second.next_page_token.is_empty());
    // Without an explicit order production does not split at all.
    let mut unordered = partition_request("items", 4, 0, "");
    if let Some(pb::partition_query_request::QueryType::StructuredQuery(sq)) =
        &mut unordered.query_type
    {
        sq.order_by.clear();
    }
    assert!(client
        .partition_query(unordered)
        .await
        .unwrap()
        .into_inner()
        .partitions
        .is_empty());
    // A plain collection query is refused.
    let mut plain = partition_request("items", 2, 0, "");
    if let Some(pb::partition_query_request::QueryType::StructuredQuery(sq)) = &mut plain.query_type
    {
        sq.from[0].all_descendants = false;
    }
    let refused = client.partition_query(plain).await.unwrap_err();
    assert_eq!(
        (refused.code(), refused.message()),
        (
            tonic::Code::InvalidArgument,
            "Query must select all descendant collections."
        )
    );
    handle.abort();
}

#[tokio::test]
async fn resume_tokens_are_refused_after_a_reset_and_for_other_targets() {
    let (mut client, handle) = start(false).await;
    let commit = |writes| pb::CommitRequest {
        database: DB.to_owned(),
        writes,
        ..Default::default()
    };
    client
        .commit(commit(vec![set_write("rt/a", &[("v", s("1"))])]))
        .await
        .unwrap();
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    ltx.send(add_query_target(1, "rt")).await.unwrap();
    // The per-target boundary carries a token bound to the target (the global one is
    // accepted by every target, as the SDKs apply it to all of them).
    let (_, token) = trace_and_token(&mut listen, "NO_CHANGE[1]").await;
    let _ = next_until(&mut listen, "NO_CHANGE[]").await;
    // The token of the `rt` target does not resume an `other` target: full replay.
    let mut other = add_query_target(2, "other");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut other.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token.clone()));
    }
    ltx.send(other).await.unwrap();
    let trace = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(trace[..2], ["ADD[2]", "RESET[2]"]);
    drop(ltx);
    // After a reset the same versions come around again: the old token must not line up
    // with the new history.
    BACKEND.with(|b| b.borrow().as_ref().unwrap().reset());
    client
        .commit(commit(vec![set_write("rt/b", &[("v", s("1"))])]))
        .await
        .unwrap();
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    let mut resumed = add_query_target(3, "rt");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut resumed.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
    }
    ltx.send(resumed).await.unwrap();
    let trace = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(trace[..3], ["ADD[3]", "RESET[3]", "CHANGE b"]);
    handle.abort();
}

#[tokio::test]
async fn current_boundary_tokens_are_bound_to_their_target() {
    let (mut client, handle) = start(false).await;
    let (tx, rx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(1, "first")).await.unwrap();
    let (_, current_token) = trace_and_token(&mut listen, "CURRENT[1]").await;
    assert!(!current_token.is_empty());
    let _ = next_until(&mut listen, "NO_CHANGE[]").await;

    let mut other = add_query_target(2, "second");
    if let Some(pb::listen_request::TargetChange::AddTarget(target)) = &mut other.target_change {
        target.resume_type = Some(pb::target::ResumeType::ResumeToken(current_token));
    }
    tx.send(other).await.unwrap();
    let trace = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(trace[..2], ["ADD[2]", "RESET[2]"]);
    handle.abort();
}

#[tokio::test]
async fn project_restore_replays_a_same_version_document_with_new_fields() {
    let (mut client, handle) = start(false).await;
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write("restored/a", &[("v", s("before"))])],
            ..Default::default()
        })
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(1, "restored")).await.unwrap();
    let _ = next_until(&mut listen, "NO_CHANGE[]").await;

    let project = ProjectId::try_new("demo-app").unwrap();
    let database = DatabaseId::default_database();
    let path = DocumentPath::parse(&project, &database, "restored/a").unwrap();
    let mut restored = FirestoreState::new();
    restored
        .commit(
            &[CoreWrite {
                op: WriteOp::Set {
                    path,
                    fields: BTreeMap::from([("v".to_owned(), Value::String("after".to_owned()))]),
                    update_mask: None,
                },
                precondition: None,
                transforms: Vec::new(),
            }],
            None,
            LogicalInstant::from_unix_seconds(1_788_004_861),
        )
        .unwrap();
    let snapshot = FirestoreSnapshot {
        databases: BTreeMap::from([(
            (
                "demo-app".to_owned(),
                fireemu_core_types::ids::DatabaseId::DEFAULT.to_owned(),
            ),
            restored,
        )]),
        ids: None,
    };
    BACKEND.with(|backend| {
        backend
            .borrow()
            .as_ref()
            .unwrap()
            .restore_scope(&Scope::Project("demo-app".to_owned()), &snapshot)
            .unwrap();
    });

    let mut trace = Vec::new();
    let mut restored_value = None;
    loop {
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), listen.next())
            .await
            .expect("listen response within 5 s")
            .expect("stream open")
            .unwrap();
        if let Some(pb::listen_response::ResponseType::DocumentChange(change)) =
            &response.response_type
        {
            restored_value = change.document.as_ref().and_then(|document| {
                document.fields.get("v").and_then(|value| {
                    if let Some(pb::value::ValueType::StringValue(value)) = &value.value_type {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
            });
        }
        let description = describe(&response);
        trace.push(description.clone());
        if description == "NO_CHANGE[]" {
            break;
        }
    }
    assert_eq!(
        trace,
        vec![
            "RESET[1]",
            "CHANGE a",
            "CURRENT[1]",
            "NO_CHANGE[1]",
            "NO_CHANGE[]"
        ]
    );
    assert_eq!(restored_value.as_deref(), Some("after"));
    handle.abort();
}

#[tokio::test]
async fn partition_pages_stay_consistent_while_documents_change() {
    let (mut client, handle) = start(false).await;
    let original = sampled_names(3, |i| format!("owners/o{i}/parts/p{i}"));
    let writes: Vec<pb::Write> = original
        .iter()
        .map(|name| set_write(name, &[("v", s("x"))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let names = |response: &pb::PartitionQueryResponse| {
        response
            .partitions
            .iter()
            .map(cursor_name)
            .collect::<Vec<_>>()
    };
    let whole = client
        .partition_query(partition_request("parts", 3, 0, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(whole.partitions.len(), 3);
    let first = client
        .partition_query(partition_request("parts", 3, 2, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(names(&first), names(&whole)[..2]);
    // Documents inserted before the next page, sampled ones too, do not shift the cuts of
    // this partitioning.
    let added = sampled_names(3, |i| format!("owners/n{i}/parts/a{i}"));
    let writes: Vec<pb::Write> = added
        .iter()
        .map(|name| set_write(name, &[("v", s("y"))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let second = client
        .partition_query(partition_request("parts", 3, 2, &first.next_page_token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(names(&second), names(&whole)[2..]);
    // A fresh partitioning sees the new documents; a token for another count, and a
    // negative page size, are refused in production's words.
    let fresh = client
        .partition_query(partition_request("parts", 100, 0, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(fresh.partitions.len(), 6);
    let foreign = client
        .partition_query(partition_request("parts", 4, 2, &first.next_page_token))
        .await
        .unwrap_err();
    assert_eq!(
        (foreign.code(), foreign.message()),
        (tonic::Code::InvalidArgument, "Invalid page token.")
    );
    let negative = client
        .partition_query(partition_request("parts", 3, -1, ""))
        .await
        .unwrap_err();
    assert_eq!(
        (negative.code(), negative.message()),
        (
            tonic::Code::InvalidArgument,
            "Page size must be nonnegative."
        )
    );
    handle.abort();
}

/// A server whose virtual clock the test can move: history retention is expressed in logical
/// time, so compaction only happens when the clock passes the window.
async fn start_with_clock() -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
    Arc<Mutex<VirtualClock>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
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
    (FirestoreClient::new(channel), handle, clock)
}

/// Opens a listener on `collection`, reads its initial snapshot and returns its resume token.
async fn snapshot_token(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    id: i32,
    collection: &str,
) -> Vec<u8> {
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    ltx.send(add_query_target(id, collection)).await.unwrap();
    let (_, token) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
    token
}

/// Resumes `collection` from `token` on a fresh stream and returns the trace.
async fn resume_trace(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    id: i32,
    collection: &str,
    token: Vec<u8>,
) -> Vec<String> {
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    let mut request = add_query_target(id, collection);
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
    }
    ltx.send(request).await.unwrap();
    next_until(&mut listen, "NO_CHANGE[]").await
}

/// FS-MVCC-04: a token whose version is still retained resumes with the diff since it, and a
/// token whose version the store compacted away is refused explicitly (`RESET`, then a full
/// replay) instead of being diffed against unrelated history.
#[tokio::test]
async fn retained_and_compacted_resume_tokens_have_distinct_outcomes() {
    let (mut client, handle, clock) = start_with_clock().await;
    let commit = |writes| pb::CommitRequest {
        database: DB.to_owned(),
        writes,
        ..Default::default()
    };
    client
        .commit(commit(vec![set_write("w/a", &[("v", s("1"))])]))
        .await
        .unwrap();
    let old_token = snapshot_token(&mut client, 1, "w").await;
    client
        .commit(commit(vec![set_write("w/b", &[("v", s("1"))])]))
        .await
        .unwrap();
    let recent_token = snapshot_token(&mut client, 2, "w").await;
    assert_ne!(old_token, recent_token);

    // The clock passes the read_time retention window; the next commit compacts everything
    // the window no longer covers, which leaves the first token below the floor.
    clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(
            2 * fireemu_adapter_grpc::local::READ_TIME_RETENTION_SECONDS,
        ))
        .unwrap();
    client
        .commit(commit(vec![set_write("w/c", &[("v", s("1"))])]))
        .await
        .unwrap();

    let resumed = resume_trace(&mut client, 3, "w", recent_token).await;
    assert_eq!(
        resumed,
        vec![
            "ADD[3]",
            "CHANGE c",
            "FILTER 3",
            "CURRENT[3]",
            "NO_CHANGE[3]",
            "NO_CHANGE[]"
        ],
        "a retained token replays only what changed since it"
    );

    let expired = resume_trace(&mut client, 4, "w", old_token).await;
    assert_eq!(
        expired,
        vec![
            "ADD[4]",
            "RESET[4]",
            "CHANGE a",
            "CHANGE b",
            "CHANGE c",
            "CURRENT[4]",
            "NO_CHANGE[4]",
            "NO_CHANGE[]"
        ],
        "a compacted token is refused and the client resyncs from scratch"
    );
    handle.abort();
}

/// The clock-independent retention root also invalidates an unreachable token explicitly.
/// A pinned clock can therefore run an arbitrarily fast update loop without retaining every
/// version or diffing a listener against the wrong historical snapshot.
#[tokio::test]
async fn a_pinned_clock_version_cap_resets_a_compacted_resume_token() {
    let (mut client, handle) = start(false).await;
    let commit = |value: String| pb::CommitRequest {
        database: DB.to_owned(),
        writes: vec![set_write("cap/a", &[("v", s(&value))])],
        ..Default::default()
    };
    client.commit(commit("0".to_owned())).await.unwrap();
    let old_token = snapshot_token(&mut client, 1, "cap").await;

    for value in 1..=fireemu_core_firestore::store::DEFAULT_MAX_RETAINED_VERSIONS_PER_PATH {
        client.commit(commit(value.to_string())).await.unwrap();
    }

    let expired = resume_trace(&mut client, 2, "cap", old_token).await;
    assert_eq!(
        expired,
        vec![
            "ADD[2]",
            "RESET[2]",
            "CHANGE a",
            "CURRENT[2]",
            "NO_CHANGE[2]",
            "NO_CHANGE[]"
        ]
    );
    handle.abort();
}

/// The retention window the wire declares is the one the store compacts against.
#[test]
fn the_declared_read_time_window_is_the_stores_retention_window() {
    assert_eq!(
        fireemu_adapter_grpc::local::READ_TIME_RETENTION_SECONDS,
        fireemu_core_firestore::store::READ_TIME_RETENTION_SECONDS
    );
}

/// The one declared composite index of the missing-index reproduction: `tasks` ordered by
/// `createdAt` descending under an `ownerId` equality.
fn declared_task_index() -> IndexSet {
    let mut indexes = IndexSet::default();
    indexes.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("tasks").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: vec![
            IndexField {
                path: FieldPath::parse("ownerId").unwrap(),
                mode: IndexFieldMode::Ascending,
            },
            IndexField {
                path: FieldPath::parse("createdAt").unwrap(),
                mode: IndexFieldMode::Descending,
            },
        ],
    });
    indexes
}

async fn start_with_indexes(
    indexes: IndexSet,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes,
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
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
    (FirestoreClient::new(channel), handle)
}

/// `where ownerId == "u1" order by <field> desc` on `tasks`: covered by the declared index
/// for `createdAt`, and a missing composite index for any other field.
fn add_owner_ordered_target(id: i32, order_field: &str) -> pb::ListenRequest {
    pb::ListenRequest {
        database: DB.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
            target_id: id,
            target_type: Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                parent: DOCS.to_owned(),
                query_type: Some(pb::target::query_target::QueryType::StructuredQuery(
                    pb::StructuredQuery {
                        from: vec![sq::CollectionSelector {
                            collection_id: "tasks".to_owned(),
                            all_descendants: false,
                        }],
                        r#where: Some(sq::Filter {
                            filter_type: Some(sq::filter::FilterType::FieldFilter(
                                sq::FieldFilter {
                                    field: Some(sq::FieldReference {
                                        field_path: "ownerId".to_owned(),
                                    }),
                                    op: sq::field_filter::Operator::Equal as i32,
                                    value: Some(s("u1")),
                                },
                            )),
                        }),
                        order_by: vec![sq::Order {
                            field: Some(sq::FieldReference {
                                field_path: order_field.to_owned(),
                            }),
                            direction: sq::Direction::Descending as i32,
                        }],
                        ..Default::default()
                    },
                )),
            })),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// FS-LSN-1: a query the strict gateway refuses concerns the target that carried it, never
/// the stream. The rejected target is removed with its own cause (code 9 and the actionable
/// index diagnostic) while every other target on the same stream keeps listening.
#[tokio::test]
async fn a_missing_index_removes_only_its_own_target_and_the_stream_keeps_listening() {
    let (mut client, handle) = start_with_indexes(declared_task_index()).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    // The covered query is an ordinary active target.
    tx.send(add_owner_ordered_target(21, "createdAt"))
        .await
        .unwrap();
    let covered = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(
        covered,
        vec!["ADD[21]", "CURRENT[21]", "NO_CHANGE[21]", "NO_CHANGE[]"]
    );

    // The undeclared one is refused, and the refusal names the target.
    tx.send(add_owner_ordered_target(22, "updatedAt"))
        .await
        .unwrap();
    let rejected = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
        .await
        .expect("a response within 5 s")
        .expect("the stream is still open")
        .expect("a target removal, not a stream error");
    assert_eq!(describe(&rejected), "REMOVE[22] cause=9");
    let cause = match &rejected.response_type {
        Some(pb::listen_response::ResponseType::TargetChange(t)) => t.cause.clone().unwrap(),
        other => panic!("expected a target change: {other:?}"),
    };
    assert_eq!(cause.code, tonic::Code::FailedPrecondition as i32);
    assert!(
        // Production's wording: the console link encodes the index to create.
        cause.message.starts_with(
            "The query requires an index. You can create it here: https://console.firebase.google.com/v1/r/project/demo-app/firestore/indexes?create_composite="
        ),
        "the actionable diagnostic survives the target removal: {}",
        cause.message
    );

    // The surviving target still receives live diffs on the same stream.
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![set_write(
                "tasks/t1",
                &[("ownerId", s("u1")), ("createdAt", s("2026-08-30"))],
            )],
            ..Default::default()
        })
        .await
        .unwrap();
    let diff = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(
        diff,
        vec!["CHANGE t1", "NO_CHANGE[21]", "NO_CHANGE[]"],
        "target 21 stayed active after target 22 was refused"
    );
    handle.abort();
}

#[tokio::test]
async fn the_streaming_surfaces_refuse_a_database_that_was_never_created() {
    // Production answers NOT_FOUND for a database `databases.create` was never called for,
    // before the target or the write is considered. The message is the one recorded from the
    // oracle project in `conformance/firestore-production-matrix.json`.
    let expected = "The database never-created does not exist for project demo-app Please \
                    visit https://console.cloud.google.com/datastore/setup?project=demo-app \
                    to add a Cloud Datastore or Cloud Firestore database. ";
    let (mut client, handle) = start(false).await;
    let database = "projects/demo-app/databases/never-created";

    let (tx, rx) = mpsc::channel(8);
    let mut listened = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let mut target = add_query_target(1, "open");
    target.database = database.to_owned();
    let Some(pb::listen_request::TargetChange::AddTarget(added)) = &mut target.target_change else {
        panic!("the fixture adds a query target");
    };
    let Some(pb::target::TargetType::Query(query)) = &mut added.target_type else {
        panic!("the fixture adds a query target");
    };
    query.parent = format!("{database}/documents");
    tx.send(target).await.unwrap();
    // The target is acknowledged before it is served, so the refusal is the next message.
    let refused = loop {
        match listened
            .next()
            .await
            .expect("the stream reports the refusal")
        {
            Ok(response) => assert!(
                matches!(
                    response.response_type,
                    Some(pb::listen_response::ResponseType::TargetChange(_))
                ),
                "no document is served from a database that does not exist: {response:?}"
            ),
            Err(error) => break error,
        }
    };
    assert_eq!(refused.code(), tonic::Code::NotFound);
    assert_eq!(refused.message(), expected);

    let (write_tx, write_rx) = mpsc::channel(8);
    let mut written = client
        .write(ReceiverStream::new(write_rx))
        .await
        .unwrap()
        .into_inner();
    write_tx
        .send(pb::WriteRequest {
            database: database.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let refused = written.next().await.unwrap().unwrap_err();
    assert_eq!(refused.code(), tonic::Code::NotFound);
    assert_eq!(refused.message(), expected);

    handle.abort();
}

/// A partition page token carries the snapshot version it was issued for; an edited version
/// is a token issued for another request (safety review note).
#[tokio::test]
async fn an_edited_partition_token_version_is_refused() {
    let (mut client, handle) = start(false).await;
    let samples = sampled_names(4, |i| format!("owners/e{i}/edits/x{i}"));
    let writes: Vec<pb::Write> = samples
        .iter()
        .map(|name| set_write(name, &[("v", s("x"))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let first = client
        .partition_query(partition_request("edits", 4, 1, ""))
        .await
        .unwrap()
        .into_inner();
    let mut parts: Vec<String> = first
        .next_page_token
        .split(':')
        .map(str::to_owned)
        .collect();
    assert_eq!(parts.len(), 3);
    parts[0] = parts[0]
        .parse::<u64>()
        .unwrap()
        .saturating_sub(1)
        .to_string();
    let refused = client
        .partition_query(partition_request("edits", 4, 1, &parts.join(":")))
        .await
        .unwrap_err();
    assert_eq!(
        (refused.code(), refused.message()),
        (tonic::Code::InvalidArgument, "Invalid page token.")
    );
    assert!(client
        .partition_query(partition_request("edits", 4, 1, &first.next_page_token))
        .await
        .is_ok());
    handle.abort();
}
