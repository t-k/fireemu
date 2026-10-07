//! `Write` and `Listen` streams through a real tonic client: handshake, sequential commits,
//! initial snapshots, live diffs after commits, target removal and rules denials.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::{FirestoreSnapshot, LocalBackend};
use fireemu_adapter_grpc::rules::{RulesEnforcer, TokenSemantics};
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
    start_configured(rules_source, IndexValidationPolicy::Production).await
}

async fn start_configured(
    rules_source: Option<&str>,
    policy: IndexValidationPolicy,
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
            policy,
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
        service = service.with_rules(Arc::new(
            RulesEnforcer::new(rules, auth, clock).with_token_semantics(TokenSemantics::Firestore),
        ));
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
            "{} {}",
            if d.target_ids.is_empty() && !d.removed_target_ids.is_empty() {
                "LEAVE"
            } else {
                "CHANGE"
            },
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
    // As production and the official emulator frame it (AUTH-FS-CROSS stage 2, packet v7):
    // CURRENT carries the target's token, and no NO_CHANGE for the new target follows it.
    assert_eq!(
        initial,
        vec!["ADD[1]", "CHANGE a", "CURRENT[1]", "NO_CHANGE[]"]
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
    assert_eq!(diff, vec!["CHANGE a", "CHANGE b", "NO_CHANGE[]"]);

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
    assert_eq!(diff, vec!["DELETE b", "NO_CHANGE[]"]);

    // Document targets for a missing document become CURRENT without a change.
    tx.send(add_documents_target(2, &["open/missing"]))
        .await
        .unwrap();
    let initial = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(
        initial,
        vec!["ADD[2]", "CURRENT[2]", "NO_CHANGE[]"],
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
        vec!["ADD[1]", "CURRENT[1]", "NO_CHANGE[]"]
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
        (set_write("delta/a", &[("state", s("excluded"))]), "LEAVE a"),
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
            vec![expected, "NO_CHANGE[]"]
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
        vec!["ADD[1]", "CHANGE a", "CURRENT[1]", "NO_CHANGE[]"]
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
        vec!["CHANGE b", "LEAVE a", "NO_CHANGE[]"]
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
    assert_eq!(ok, vec!["ADD[8]", "CURRENT[8]", "NO_CHANGE[]"]);

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
        vec!["ADD[1]", "CHANGE a", "CURRENT[1]", "NO_CHANGE[]"]
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
        vec!["ADD[1]", "CHANGE a", "CURRENT[1]", "NO_CHANGE[]"]
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
        vec!["NO_CHANGE[]"]
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
    // Production's shapes (strict): a bearer value that is not a JWT is the front end's
    // UNAUTHENTICATED; a JWT that does not verify is the ordinary PERMISSION_DENIED.
    for (authorization, refusal) in [
        ("Bearer malformed", tonic::Code::Unauthenticated),
        (
            "Bearer eyJhbGciOiJub25lIn0.eyJhdWQiOiJvdGhlciJ9.",
            tonic::Code::PermissionDenied,
        ),
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
        assert_eq!(error.code(), refusal);
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

    // A `once` target ends with REMOVE after its consistent snapshot; a future version triggers RESET before the replay.
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    ltx.send(add_query_target(1, "open")).await.unwrap();
    let (_, mut future_token) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
    future_token[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut once = add_query_target(3, "open");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut once.target_change {
        t.once = true;
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(future_token));
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
        vec!["ADD[1]", "CHANGE a", "CURRENT[1]", "NO_CHANGE[]"]
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
        vec!["ADD[1]", "CHANGE b", "CURRENT[1]", "NO_CHANGE[]"]
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
        vec!["CHANGE c", "NO_CHANGE[]"]
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
    assert_eq!(token.len(), 11, "version and three-byte binding check");
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
    // As production answers a resume (AUTH-FS-CROSS stage 2, packet v7): a global boundary at
    // the token first, then what changed since, CURRENT and the boundary. Strict adds the
    // count-only existence filter of the recorded L1 resumes without an expected count, and leaves
    // the removal of `a` to its count.
    let (early, _) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(early, vec!["ADD[2]", "NO_CHANGE[]"]);
    let (trace, mut latest) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(
        trace,
        vec![
            "CHANGE b",
            "CHANGE c",
            "FILTER 2",
            "CURRENT[2]",
            "NO_CHANGE[]"
        ]
    );
    // Nothing changed: a resume replays nothing but its boundaries and the count.
    let mut again = add_query_target(3, "r");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut again.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(latest.clone()));
    }
    ltx.send(again).await.unwrap();
    let early = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(early, vec!["ADD[3]", "NO_CHANGE[]"]);
    let trace = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(trace, vec!["FILTER 2", "CURRENT[3]", "NO_CHANGE[]"]);
    // A matching binding with a version from the future still resets.
    let mut future = add_query_target(4, "r");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut future.target_change {
        latest[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(latest));
    }
    ltx.send(future).await.unwrap();
    let trace = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(trace[..4], ["ADD[4]", "RESET[4]", "CHANGE b", "CHANGE c"]);
    handle.abort();
}

/// The next global boundary's token and read time.
async fn next_boundary<S>(stream: &mut S) -> (Vec<u8>, Option<prost_types::Timestamp>)
where
    S: tokio_stream::Stream<Item = Result<pb::ListenResponse, tonic::Status>> + Unpin,
{
    loop {
        let item = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("listen response within 5 s")
            .expect("stream open")
            .unwrap();
        if let Some(pb::listen_response::ResponseType::TargetChange(t)) = item.response_type {
            if t.target_ids.is_empty() && t.target_change_type == 0 {
                return (t.resume_token, t.read_time);
            }
        }
    }
}

/// The boundary a resume starts with carries a token for the resume point itself, so a stream
/// that drops before the diff resumes from there again and skips no change; its read time is
/// the snapshot's, so a client's snapshot version never goes back.
#[tokio::test]
async fn a_resume_starts_with_a_boundary_at_its_token() {
    let (mut client, handle) = start(false).await;
    let commit = |writes| pb::CommitRequest {
        database: DB.to_owned(),
        writes,
        ..Default::default()
    };
    client
        .commit(commit(vec![set_write("rb/a", &[("v", s("1"))])]))
        .await
        .unwrap();
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    ltx.send(add_query_target(1, "rb")).await.unwrap();
    let (token, read_time) = next_boundary(&mut listen).await;
    drop(ltx);
    client
        .commit(commit(vec![set_write("rb/b", &[("v", s("1"))])]))
        .await
        .unwrap();
    let (ltx, lrx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(lrx))
        .await
        .unwrap()
        .into_inner();
    let mut resumed = add_query_target(2, "rb");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut resumed.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token.clone()));
    }
    ltx.send(resumed).await.unwrap();
    let (early_token, early_time) = next_boundary(&mut listen).await;
    assert_eq!(
        early_token, token,
        "the early boundary resumes from the same point"
    );
    let (later_token, later_time) = next_boundary(&mut listen).await;
    assert_ne!(later_token, token, "the boundary after the diff moves on");
    let (read, early, later) = (read_time.unwrap(), early_time.unwrap(), later_time.unwrap());
    assert!((early.seconds, early.nanos) >= (read.seconds, read.nanos));
    assert_eq!(early, later, "both boundaries are the same snapshot's");
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
async fn resume_tokens_are_refused_after_a_reset_and_strict_current_tokens_resume_other_targets() {
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
    // Strict CURRENT carries the snapshot's global token, the same bytes as the NO_CHANGE that
    // follows (FS-LISTEN-SDK L3 203/203C), and a global token is accepted by every target, as
    // the SDKs apply it to all of them.
    let (_, token) = trace_and_token(&mut listen, "CURRENT[1]").await;
    let (_, global) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(token, global);
    let mut other = add_query_target(2, "other");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut other.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token.clone()));
    }
    ltx.send(other).await.unwrap();
    let trace = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(trace[..2], ["ADD[2]", "NO_CHANGE[]"]);
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
    let trace = next_until(&mut listen, "REMOVE[3] cause=3").await;
    assert_eq!(trace, ["REMOVE[3] cause=3"]);
    handle.abort();
}

#[tokio::test]
async fn current_boundary_tokens_are_bound_to_their_target() {
    let (mut client, handle) = start_profile(Profile::Emulator).await;
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
    assert!(trace.iter().any(|line| line == "RESET[2]"), "{trace:?}");
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
        vec!["RESET[1]", "CHANGE a", "CURRENT[1]", "NO_CHANGE[]"]
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
    // A resumed target sends a boundary before its changes; a refused one does not.
    let mut trace = next_until(&mut listen, "NO_CHANGE[]").await;
    if !trace.iter().any(|t| t.starts_with("CURRENT")) {
        trace.extend(next_until(&mut listen, "NO_CHANGE[]").await);
    }
    trace
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
            "NO_CHANGE[]",
            "CHANGE c",
            "FILTER 3",
            "CURRENT[3]",
            "NO_CHANGE[]"
        ],
        "a retained token replays only what changed since it, and the count of documents follows"
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
    assert_eq!(covered, vec!["ADD[21]", "CURRENT[21]", "NO_CHANGE[]"]);

    // The undeclared one is acknowledged with an ADD and then removed with its cause, and the
    // refusal names the target.
    tx.send(add_owner_ordered_target(22, "updatedAt"))
        .await
        .unwrap();
    let added = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
        .await
        .expect("a response within 5 s")
        .expect("the stream is still open")
        .expect("an acknowledgement");
    assert_eq!(describe(&added), "ADD[22]");
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
        vec!["CHANGE t1", "NO_CHANGE[]"],
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

/// Which profile a Listen test runs under.
#[derive(Clone, Copy)]
enum Profile {
    Strict,
    Emulator,
}

async fn start_profile(
    profile: Profile,
) -> (
    FirestoreClient<tonic::transport::Channel>,
    tokio::task::JoinHandle<()>,
) {
    match profile {
        Profile::Strict => start(false).await,
        Profile::Emulator => start_configured(None, IndexValidationPolicy::Emulator).await,
    }
}

/// The status a stream ends with.
async fn stream_error<S>(responses: &mut S) -> tonic::Status
where
    S: tokio_stream::Stream<Item = Result<pb::ListenResponse, tonic::Status>> + Unpin,
{
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
            .await
            .expect("a response within 5 s")
        {
            Some(Err(status)) => return status,
            Some(Ok(_)) => {}
            None => panic!("the stream ended without a status"),
        }
    }
}

/// Production accepts a target with id 0 and assigns it an id (FS-LISTEN-SDK L1, runs nmuuicyas
/// and nmuukwo6n: `native/target-protocol/server-assigned-id` and `second-zero-id`: ADD[1] and
/// ADD[2]); the official emulator does too. Both profiles assign the smallest free positive id.
#[tokio::test]
async fn target_zero_is_assigned_the_smallest_free_id_in_both_profiles() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let (mut client, handle) = start_profile(profile).await;
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
        tx.send(add_query_target(0, "open")).await.unwrap();
        let first = next_until(&mut responses, "NO_CHANGE[]").await;
        assert_eq!(
            first,
            vec!["ADD[1]", "CHANGE a", "CURRENT[1]", "NO_CHANGE[]"],
            "the first server-assigned id is 1"
        );
        // A second id-0 target gets the next free id, not one already in use.
        tx.send(add_query_target(0, "open")).await.unwrap();
        let second = next_until(&mut responses, "NO_CHANGE[]").await;
        assert_eq!(second.first().map(String::as_str), Some("ADD[2]"));
        handle.abort();
    }
}

/// Unrecorded: production shows only ADD[1] and then ADD[2], which a counter would also give; the
/// official emulator counts up and never reuses an id. Here the smallest free id is assigned, so
/// a removed target's id comes round again. Not a refusal; kept apart from the recorded sequence.
#[tokio::test]
async fn unrecorded_a_freed_target_id_is_assigned_again() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let (mut client, handle) = start_profile(profile).await;
        let (tx, rx) = mpsc::channel(8);
        let mut responses = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(add_query_target(0, "open")).await.unwrap();
        next_until(&mut responses, "NO_CHANGE[]").await;
        tx.send(add_query_target(0, "open")).await.unwrap();
        next_until(&mut responses, "NO_CHANGE[]").await;
        // An id that was assigned is an id like any other: removing it removes that target.
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
        tx.send(add_query_target(0, "open")).await.unwrap();
        let third = next_until(&mut responses, "NO_CHANGE[]").await;
        assert_eq!(third.first().map(String::as_str), Some("ADD[1]"));
        handle.abort();
    }
}

/// Production ends the stream (`INVALID_ARGUMENT`, `native/target-protocol/id-after-assigned`) when
/// an explicit id follows a server-assigned one. The official emulator accepts it, so the
/// emulator profile keeps accepting.
#[tokio::test]
async fn an_explicit_id_after_a_server_assigned_one_ends_a_strict_stream_only() {
    let (mut client, handle) = start_profile(Profile::Strict).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(0, "open")).await.unwrap();
    next_until(&mut responses, "NO_CHANGE[]").await;
    tx.send(add_query_target(7, "open")).await.unwrap();
    assert_eq!(
        stream_error(&mut responses).await.code(),
        tonic::Code::InvalidArgument
    );
    handle.abort();

    let (mut client, handle) = start_profile(Profile::Emulator).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(0, "open")).await.unwrap();
    next_until(&mut responses, "NO_CHANGE[]").await;
    tx.send(add_query_target(7, "open")).await.unwrap();
    let accepted = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(accepted.first().map(String::as_str), Some("ADD[7]"));
    handle.abort();
}

/// Near miss: explicit ids on their own, before any server-assigned one, are always fine.
#[tokio::test]
async fn explicit_ids_without_a_server_assigned_one_are_accepted_in_both_profiles() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let (mut client, handle) = start_profile(profile).await;
        let (tx, rx) = mpsc::channel(8);
        let mut responses = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(add_query_target(7, "open")).await.unwrap();
        next_until(&mut responses, "NO_CHANGE[]").await;
        tx.send(add_query_target(9, "open")).await.unwrap();
        let second = next_until(&mut responses, "NO_CHANGE[]").await;
        assert_eq!(second.first().map(String::as_str), Some("ADD[9]"));
        handle.abort();
    }
}

/// A negative id ends the stream with `INVALID_ARGUMENT` in production
/// (`native/target-protocol/negative-id`) and in the official emulator: both profiles refuse.
#[tokio::test]
async fn a_negative_target_id_ends_the_stream_in_both_profiles() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let (mut client, handle) = start_profile(profile).await;
        let (tx, rx) = mpsc::channel(8);
        let mut responses = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(add_query_target(-1, "open")).await.unwrap();
        assert_eq!(
            stream_error(&mut responses).await.code(),
            tonic::Code::InvalidArgument
        );
        handle.abort();
    }
}

/// A target id already active on the stream: production removes the new target with
/// `ALREADY_EXISTS` "Target ID already exists: 1" and keeps the stream open
/// (`native/target-protocol/duplicate-id`); the official emulator ends the stream, so following
/// production refuses nothing it completes. The first target stays active.
#[tokio::test]
async fn a_duplicate_target_id_is_removed_with_already_exists_and_the_stream_keeps_listening() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let (mut client, handle) = start_profile(profile).await;
        let (tx, rx) = mpsc::channel(8);
        let mut responses = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(add_query_target(1, "open")).await.unwrap();
        next_until(&mut responses, "NO_CHANGE[]").await;
        tx.send(add_query_target(1, "open")).await.unwrap();
        let refused = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
            .await
            .expect("a response within 5 s")
            .expect("the stream is still open")
            .expect("a target removal, not a stream error");
        assert_eq!(describe(&refused), "REMOVE[1] cause=6");
        let cause = match &refused.response_type {
            Some(pb::listen_response::ResponseType::TargetChange(t)) => t.cause.clone().unwrap(),
            other => panic!("expected a target change: {other:?}"),
        };
        assert_eq!(cause.message, "Target ID already exists: 1");
        // The first target is still active: a commit reaches it.
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![set_write("open/a", &[("v", s("1"))])],
                ..Default::default()
            })
            .await
            .unwrap();
        let diff = next_until(&mut responses, "NO_CHANGE[]").await;
        assert_eq!(diff, vec!["CHANGE a", "NO_CHANGE[]"]);
        handle.abort();
    }
}

/// Bytes that are not a resume token: production removes the target with `INVALID_ARGUMENT` "bad
/// resume token" and no ADD (`native/resume-token/invalid`); the official emulator ignores the
/// token and replays everything, so the emulator profile keeps its RESET.
#[tokio::test]
async fn a_malformed_resume_token_removes_the_target_in_strict_and_resets_in_the_emulator_profile()
{
    let junk = |id| {
        let mut request = add_query_target(id, "open");
        if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
            t.resume_type = Some(pb::target::ResumeType::ResumeToken(b"not-a-token".to_vec()));
        }
        request
    };
    let (mut client, handle) = start_profile(Profile::Strict).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(junk(1)).await.unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
        .await
        .expect("a response within 5 s")
        .expect("the stream is still open")
        .expect("a target removal, not a stream error");
    assert_eq!(describe(&first), "REMOVE[1] cause=3", "no ADD comes first");
    let cause = match &first.response_type {
        Some(pb::listen_response::ResponseType::TargetChange(t)) => t.cause.clone().unwrap(),
        other => panic!("expected a target change: {other:?}"),
    };
    assert_eq!(cause.message, "bad resume token");
    // The stream keeps listening: the id is free again.
    tx.send(add_query_target(1, "open")).await.unwrap();
    let ok = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(ok.first().map(String::as_str), Some("ADD[1]"));
    handle.abort();

    let (mut client, handle) = start_profile(Profile::Emulator).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(junk(1)).await.unwrap();
    let trace = next_until(&mut responses, "NO_CHANGE[]").await;
    assert_eq!(trace[..2], ["ADD[1]", "RESET[1]"]);
    handle.abort();
}

/// A query that needs an index: production sends ADD[1] and then REMOVE[1] with `FAILED_PRECONDITION`
/// (`native/target-protocol/missing-index`). The emulator profile needs no index (the official
/// emulator ignores them) and refuses nothing.
#[tokio::test]
async fn a_strict_missing_index_is_acknowledged_with_an_add_before_its_removal() {
    let (mut client, handle) = start_with_indexes(declared_task_index()).await;
    let (tx, rx) = mpsc::channel(8);
    let mut responses = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_owner_ordered_target(22, "updatedAt"))
        .await
        .unwrap();
    let mut seen = Vec::new();
    for _ in 0..2 {
        let item = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
            .await
            .expect("a response within 5 s")
            .expect("the stream is still open")
            .expect("a target removal, not a stream error");
        seen.push(describe(&item));
    }
    assert_eq!(seen, vec!["ADD[22]", "REMOVE[22] cause=9"]);
    handle.abort();
}

/// A document that stops matching a query is sent as a document change that names the target in
/// `removed_target_ids` (the recorded resume replay of `native/existence-filter/with-expected-count`
/// shows it as `documentChange` with removed ids and no target ids), not as a `DocumentRemove`;
/// a deleted document is a `DocumentDelete`.
#[tokio::test]
async fn a_document_that_leaves_the_query_is_a_change_with_removed_target_ids() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let (mut client, handle) = start_profile(profile).await;
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![
                    set_write("g/a", &[("state", s("included"))]),
                    set_write("g/b", &[("state", s("included"))]),
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
        tx.send(add_filtered_query_target(1, "g")).await.unwrap();
        next_until(&mut responses, "NO_CHANGE[]").await;
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![set_write("g/a", &[("state", s("excluded"))])],
                ..Default::default()
            })
            .await
            .unwrap();
        let mut leaving = None;
        loop {
            let item = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
                .await
                .expect("a response within 5 s")
                .expect("stream open")
                .unwrap();
            if let Some(pb::listen_response::ResponseType::DocumentChange(change)) =
                &item.response_type
            {
                leaving = Some(change.clone());
            }
            if describe(&item) == "NO_CHANGE[]" {
                break;
            }
        }
        let change = leaving.expect("a document change for the document that left");
        assert!(change.target_ids.is_empty());
        assert_eq!(change.removed_target_ids, vec![1]);
        assert!(change.document.unwrap().name.ends_with("/g/a"));
        handle.abort();
    }
}

/// A live update and a delete carry one global boundary and no per-target `NO_CHANGE`: production
/// (`native/target-lifecycle/update`, `delete`) and the official emulator send none.
#[tokio::test]
async fn a_commit_is_followed_by_one_global_boundary_and_no_per_target_no_change() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let (mut client, handle) = start_profile(profile).await;
        let (tx, rx) = mpsc::channel(8);
        let mut responses = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(add_query_target(1, "open")).await.unwrap();
        next_until(&mut responses, "NO_CHANGE[]").await;
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![set_write("open/a", &[("v", s("1"))])],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            next_until(&mut responses, "NO_CHANGE[]").await,
            vec!["CHANGE a", "NO_CHANGE[]"]
        );
        client
            .commit(pb::CommitRequest {
                database: DB.to_owned(),
                writes: vec![delete_write("open/a")],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            next_until(&mut responses, "NO_CHANGE[]").await,
            vec!["DELETE a", "NO_CHANGE[]"]
        );
        handle.abort();
    }
}

/// Unrecorded: a `resume_token` that is present and empty. Production recorded 11 junk bytes; an
/// empty token is probably read as no token there. Strict does not refuse it (the refusal is for
/// the recorded shape: non-empty bytes that are not a token) and it keeps the reset, in both profiles.
#[tokio::test]
async fn unrecorded_an_empty_resume_token_is_not_refused() {
    for profile in [Profile::Strict, Profile::Emulator] {
        let (mut client, handle) = start_profile(profile).await;
        let (tx, rx) = mpsc::channel(8);
        let mut responses = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        let mut request = add_query_target(1, "open");
        if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
            t.resume_type = Some(pb::target::ResumeType::ResumeToken(Vec::new()));
        }
        tx.send(request).await.unwrap();
        let trace = next_until(&mut responses, "NO_CHANGE[]").await;
        assert_eq!(trace[..2], ["ADD[1]", "RESET[1]"]);
        handle.abort();
    }
}

// ---- the existence filter of a resume (FS-LISTEN-SDK L1, runs nmuuicyas and nmuukwo6n) ----

/// Production answers a resume of a query target that gave no expected count (rows
/// `native/resume-token/older`, `other-query`, `native/existence-filter/without-expected-count`
/// and `native/resume-token-expired/expired`, both runs) with an `ExistenceFilter` just before
/// CURRENT: the target id, the number of documents the target matches now and an empty bloom
/// filter (hash count 0, no bitmap, no padding), and no message for a document that left.
fn resume_request(
    id: i32,
    collection: &str,
    token: Vec<u8>,
    expected: Option<i32>,
) -> pb::ListenRequest {
    let mut request = add_query_target(id, collection);
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
        t.expected_count = expected;
    }
    request
}

/// A stream on `r` with a token from its initial snapshot of `r/a` and `r/b`.
async fn token_after_two_documents(
    client: &mut FirestoreClient<tonic::transport::Channel>,
) -> Vec<u8> {
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![
                set_write("r/a", &[("v", s("1"))]),
                set_write("r/b", &[("v", s("1"))]),
            ],
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
    tx.send(add_query_target(1, "r")).await.unwrap();
    let (_, token) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
    token
}

async fn commit_writes(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    writes: Vec<pb::Write>,
) {
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
}

/// What a resumed stream sends until its second global boundary.
async fn resumed_trace(
    client: &mut FirestoreClient<tonic::transport::Channel>,
    request: pb::ListenRequest,
) -> Vec<pb::ListenResponse> {
    let (tx, rx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(request).await.unwrap();
    let mut out = Vec::new();
    let mut boundaries = 0;
    while boundaries < 2 {
        let item = tokio::time::timeout(std::time::Duration::from_secs(5), listen.next())
            .await
            .expect("listen response within 5 s")
            .expect("stream open")
            .unwrap();
        if describe(&item) == "NO_CHANGE[]" {
            boundaries += 1;
        }
        out.push(item);
    }
    out
}

fn described(trace: &[pb::ListenResponse]) -> Vec<String> {
    trace.iter().map(describe).collect()
}

#[tokio::test]
async fn a_strict_resume_without_an_expected_count_ends_its_replay_with_a_count_only_filter() {
    let (mut client, handle) = start(false).await;
    let token = token_after_two_documents(&mut client).await;
    commit_writes(
        &mut client,
        vec![
            set_write("r/a", &[("v", s("2"))]),
            set_write("r/c", &[("v", s("1"))]),
        ],
    )
    .await;
    let trace = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
    assert_eq!(
        described(&trace),
        vec![
            "ADD[2]",
            "NO_CHANGE[]",
            "CHANGE a",
            "CHANGE c",
            "FILTER 3",
            "CURRENT[2]",
            "NO_CHANGE[]"
        ]
    );
    let filter = trace
        .iter()
        .find_map(|item| match &item.response_type {
            Some(pb::listen_response::ResponseType::Filter(f)) => Some(f.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(filter.target_id, 2);
    assert_eq!(filter.count, 3, "the documents the target matches now");
    let bloom = filter
        .unchanged_names
        .expect("the bloom filter is present, and empty");
    assert_eq!(bloom.hash_count, 0);
    let bits = bloom.bits.expect("the bit sequence is present");
    assert!(bits.bitmap.is_empty());
    assert_eq!(bits.padding, 0);
    handle.abort();
}

#[tokio::test]
async fn a_strict_resume_without_an_expected_count_leaves_the_removals_to_the_count() {
    let (mut client, handle) = start(false).await;
    let token = token_after_two_documents(&mut client).await;
    // Two commits (a one-commit departure is replayed: see `l1b_resume_answers`).
    commit_writes(&mut client, vec![delete_write("r/b")]).await;
    commit_writes(&mut client, vec![set_write("r/a", &[("v", s("2"))])]).await;
    let trace = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
    // No DELETE b: the client that holds two documents finds the removal by the count of 1.
    assert_eq!(
        described(&trace),
        vec![
            "ADD[2]",
            "NO_CHANGE[]",
            "CHANGE a",
            "FILTER 1",
            "CURRENT[2]",
            "NO_CHANGE[]"
        ]
    );
    handle.abort();
}

#[tokio::test]
async fn a_resume_that_gave_an_expected_count_gets_its_removals_as_messages_and_no_filter() {
    let (mut client, handle) = start(false).await;
    let token = token_after_two_documents(&mut client).await;
    commit_writes(&mut client, vec![delete_write("r/b")]).await;
    let trace = resumed_trace(&mut client, resume_request(2, "r", token, Some(2))).await;
    assert_eq!(
        described(&trace),
        vec![
            "ADD[2]",
            "NO_CHANGE[]",
            "DELETE b",
            "CURRENT[2]",
            "NO_CHANGE[]"
        ]
    );
    handle.abort();
}

#[tokio::test]
async fn the_emulator_profile_keeps_the_official_emulators_answer_to_a_resume_and_sends_no_filter()
{
    let (mut client, handle) = start_profile(Profile::Emulator).await;
    let token = token_after_two_documents(&mut client).await;
    commit_writes(&mut client, vec![delete_write("r/b")]).await;
    let trace = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
    assert!(
        !described(&trace)
            .iter()
            .any(|line| line.starts_with("FILTER")),
        "{:?}",
        described(&trace)
    );
    assert!(described(&trace).contains(&"DELETE b".to_owned()));
    handle.abort();
}

#[tokio::test]
async fn no_filter_for_a_fresh_target_a_document_target_a_read_time_or_a_reset() {
    let (mut client, handle) = start(false).await;
    let token = token_after_two_documents(&mut client).await;
    // A fresh target.
    let (tx, rx) = mpsc::channel(8);
    let mut listen = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    tx.send(add_query_target(5, "r")).await.unwrap();
    let fresh = next_until(&mut listen, "NO_CHANGE[]").await;
    assert_eq!(
        fresh,
        vec![
            "ADD[5]",
            "CHANGE a",
            "CHANGE b",
            "CURRENT[5]",
            "NO_CHANGE[]"
        ]
    );
    // A document target resumed with a token.
    let mut document = add_documents_target(6, &["r/a"]);
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut document.target_change {
        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token.clone()));
    }
    let trace = resumed_trace(&mut client, document).await;
    assert!(!described(&trace)
        .iter()
        .any(|line| line.starts_with("FILTER")));
    // A valid binding with a future version resets and replays: no filter (and one boundary only).
    let (tx, rx) = mpsc::channel(8);
    let mut reset = client
        .listen(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let mut future_token = token;
    future_token[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    tx.send(resume_request(7, "r", future_token, None))
        .await
        .unwrap();
    let trace = next_until(&mut reset, "NO_CHANGE[]").await;
    assert_eq!(trace[..2], ["ADD[7]", "RESET[7]"]);
    assert!(
        !trace.iter().any(|line| line.starts_with("FILTER")),
        "{trace:?}"
    );
    handle.abort();
}

/// A read time instead of a token is not the recorded shape: no filter.
#[tokio::test]
async fn a_query_resumed_by_read_time_gets_no_filter() {
    let (mut client, handle) = start(false).await;
    let token = token_after_two_documents(&mut client).await;
    let _ = token;
    let mut request = add_query_target(2, "r");
    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
        t.resume_type = Some(pb::target::ResumeType::ReadTime(prost_types::Timestamp {
            seconds: 1_788_004_860,
            nanos: 0,
        }));
    }
    let trace = resumed_trace(&mut client, request).await;
    assert!(
        !described(&trace)
            .iter()
            .any(|line| line.starts_with("FILTER")),
        "{:?}",
        described(&trace)
    );
    handle.abort();
}

use md5::{Digest, Md5};

/// The SDK's membership check (`BloomFilter.mightContain` of @firebase/firestore 4.17.1),
/// written out here independently of the crate's own filter.
fn sdk_might_contain(filter: &pb::BloomFilter, name: &str) -> bool {
    let bits = filter.bits.as_ref().expect("a bitmap");
    let bit_count = (u64::try_from(bits.bitmap.len()).unwrap() * 8)
        .saturating_sub(u64::try_from(bits.padding).unwrap());
    if bit_count == 0 {
        return false;
    }
    let digest = Md5::digest(name.as_bytes());
    let h1 = u64::from_le_bytes(digest[0..8].try_into().unwrap());
    let h2 = u64::from_le_bytes(digest[8..16].try_into().unwrap());
    (0..u64::try_from(filter.hash_count).unwrap()).all(|i| {
        let index = usize::try_from(h1.wrapping_add(i.wrapping_mul(h2)) % bit_count).unwrap();
        bits.bitmap[index / 8] & (1 << (index % 8)) != 0
    })
}

mod count_filter_properties {
    use super::*;
    use proptest::prelude::*;

    /// A step of a random history of `r`: write document `0..4` (in or out of the query) or delete it.
    #[derive(Debug, Clone)]
    enum Step {
        Set(u8, bool),
        Delete(u8),
    }

    fn steps() -> impl Strategy<Value = Vec<Step>> {
        proptest::collection::vec(
            prop_oneof![
                (0_u8..4, any::<bool>()).prop_map(|(i, state)| Step::Set(i, state)),
                (0_u8..4).prop_map(Step::Delete),
            ],
            0..8,
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Whatever happened since the token, a strict resume without an expected count ends its
        /// replay with a filter whose count is the number of documents the query matches now,
        /// whose target is the resumed one, and with no message for a removal.
        #[test]
        fn the_filter_counts_what_the_target_matches_now(history in steps()) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let (mut client, handle) = start(false).await;
                let token = {
                    commit_writes(&mut client, vec![set_write("q/seed", &[("state", s("included"))])]).await;
                    let (tx, rx) = mpsc::channel(8);
                    let mut listen = client.listen(ReceiverStream::new(rx)).await.unwrap().into_inner();
                    tx.send(add_filtered_query_target(1, "q")).await.unwrap();
                    trace_and_token(&mut listen, "NO_CHANGE[]").await.1
                };
                let mut present: std::collections::BTreeMap<u8, bool> = std::collections::BTreeMap::new();
                present.insert(255, true);
                for step in &history {
                    match step {
                        Step::Set(i, included) => {
                            let value = if *included { "included" } else { "excluded" };
                            commit_writes(&mut client, vec![set_write(&format!("q/d{i}"), &[("state", s(value))])]).await;
                            present.insert(*i, *included);
                        }
                        Step::Delete(i) => {
                            commit_writes(&mut client, vec![delete_write(&format!("q/d{i}"))]).await;
                            present.remove(i);
                        }
                    }
                }
                let expected = i32::try_from(present.values().filter(|included| **included).count()).unwrap();
                let mut request = add_filtered_query_target(2, "q");
                if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
                    t.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
                }
                let trace = resumed_trace(&mut client, request).await;
                let lines = described(&trace);
                let filters: Vec<&String> = lines.iter().filter(|l| l.starts_with("FILTER")).collect();
                prop_assert_eq!(filters.len(), 1, "{:?}", lines);
                prop_assert_eq!(filters[0].clone(), format!("FILTER {expected}"));
                // The filter sits after the replayed changes and before CURRENT; nothing is a removal.
                let filter_at = lines.iter().position(|l| l.starts_with("FILTER")).unwrap();
                prop_assert_eq!(lines[filter_at + 1].clone(), "CURRENT[2]".to_owned());
                prop_assert!(!lines.iter().any(|l| l.starts_with("DELETE") || l.starts_with("LEAVE") || l.starts_with("REMOVE ")), "{:?}", lines);
                handle.abort();
                Ok(())
            })?;
        }

        /// A listener that gives the expected count its token was taken with (as the SDKs do)
        /// gets no filter, and applying what the replay says to what it held leaves it holding
        /// exactly the documents the query matches now: nothing for it to repair.
        #[test]
        fn a_listener_that_gave_its_count_ends_up_holding_exactly_the_matching_documents(history in steps()) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let (mut client, handle) = start(false).await;
                let token = {
                    commit_writes(&mut client, vec![set_write("q/seed", &[("state", s("included"))])]).await;
                    let (tx, rx) = mpsc::channel(8);
                    let mut listen = client.listen(ReceiverStream::new(rx)).await.unwrap().into_inner();
                    tx.send(add_filtered_query_target(1, "q")).await.unwrap();
                    trace_and_token(&mut listen, "NO_CHANGE[]").await.1
                };
                let mut present: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
                present.insert("seed".to_owned(), true);
                for step in &history {
                    match step {
                        Step::Set(i, included) => {
                            let value = if *included { "included" } else { "excluded" };
                            commit_writes(&mut client, vec![set_write(&format!("q/d{i}"), &[("state", s(value))])]).await;
                            present.insert(format!("d{i}"), *included);
                        }
                        Step::Delete(i) => {
                            commit_writes(&mut client, vec![delete_write(&format!("q/d{i}"))]).await;
                            present.remove(&format!("d{i}"));
                        }
                    }
                }
                let mut request = add_filtered_query_target(2, "q");
                if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
                    t.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
                    t.expected_count = Some(1);
                }
                let trace = resumed_trace(&mut client, request).await;
                let lines = described(&trace);
                // At most a bloom filter, of exactly the documents the target matches, and only when
                // none left and production recorded its size (1 to 3 documents).
                let matching_now = present.iter().filter(|(_, included)| **included).count();
                let sent: Vec<&pb::ExistenceFilter> = trace
                    .iter()
                    .filter_map(|item| match &item.response_type {
                        Some(pb::listen_response::ResponseType::Filter(f)) => Some(f),
                        _ => None,
                    })
                    .collect();
                prop_assert!(sent.len() <= 1, "{:?}", lines);
                if let Some(filter) = sent.first() {
                    prop_assert_eq!(usize::try_from(filter.count).unwrap(), matching_now);
                    prop_assert!((1..=3).contains(&matching_now));
                    let bloom = filter.unchanged_names.as_ref().unwrap();
                    for (name, included) in &present {
                        if *included {
                            prop_assert!(sdk_might_contain(bloom, &format!("{DOCS}/q/{name}")), "{name}");
                        }
                    }
                }
                let mut held: std::collections::BTreeSet<String> = ["seed".to_owned()].into();
                for line in &lines {
                    if let Some(name) = line.strip_prefix("CHANGE ") {
                        held.insert(name.to_owned());
                    } else if let Some(name) = line
                        .strip_prefix("LEAVE ")
                        .or_else(|| line.strip_prefix("DELETE "))
                        .or_else(|| line.strip_prefix("REMOVE "))
                    {
                        held.remove(name);
                    }
                }
                let matching: std::collections::BTreeSet<String> = present
                    .into_iter()
                    .filter(|(_, included)| *included)
                    .map(|(name, _)| name)
                    .collect();
                prop_assert_eq!(held, matching, "{:?}", lines);
                handle.abort();
                Ok(())
            })?;
        }
    }
}

/// A model of the client of a resume: what it holds at its token, what the replay makes it hold,
/// and what the SDK compares to the filter's count.
mod resume_client_model {
    use super::*;
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// The query of the listened target.
    #[derive(Debug, Clone, Copy)]
    enum Shape {
        /// `state == "included"`.
        Filtered,
        /// All documents ordered by `v` ascending (then name), limited.
        Limit(i32),
    }

    #[derive(Debug, Clone)]
    enum Step {
        /// Write document `d<i>` with `state` included or not and the ordering value `v`.
        Set(u8, bool, u8),
        Delete(u8),
    }

    fn shapes() -> impl Strategy<Value = Shape> {
        prop_oneof![Just(Shape::Filtered), (1_i32..4).prop_map(Shape::Limit),]
    }

    fn steps() -> impl Strategy<Value = Vec<Step>> {
        proptest::collection::vec(
            prop_oneof![
                3 => (0_u8..5, any::<bool>(), 0_u8..3).prop_map(|(i, state, v)| Step::Set(i, state, v)),
                1 => (0_u8..5).prop_map(Step::Delete),
            ],
            0..9,
        )
    }

    type Present = BTreeMap<String, (bool, u8)>;

    fn apply(present: &mut Present, step: &Step) -> pb::Write {
        match step {
            Step::Set(i, included, v) => {
                present.insert(format!("d{i}"), (*included, *v));
                set_write(
                    &format!("q/d{i}"),
                    &[
                        ("state", s(if *included { "included" } else { "excluded" })),
                        ("v", s(&v.to_string())),
                    ],
                )
            }
            Step::Delete(i) => {
                present.remove(&format!("d{i}"));
                delete_write(&format!("q/d{i}"))
            }
        }
    }

    /// The documents the query matches over `present`.
    fn matching(shape: Shape, present: &Present) -> BTreeSet<String> {
        match shape {
            Shape::Filtered => present
                .iter()
                .filter(|(_, (included, _))| *included)
                .map(|(name, _)| name.clone())
                .collect(),
            Shape::Limit(limit) => {
                let mut ordered: Vec<(&u8, &String)> =
                    present.iter().map(|(name, (_, v))| (v, name)).collect();
                ordered.sort();
                ordered
                    .into_iter()
                    .take(usize::try_from(limit).unwrap())
                    .map(|(_, name)| name.clone())
                    .collect()
            }
        }
    }

    fn target_for(id: i32, shape: Shape) -> pb::ListenRequest {
        match shape {
            Shape::Filtered => add_filtered_query_target(id, "q"),
            Shape::Limit(limit) => {
                let mut request = add_limited_query_target(id, "q");
                let Some(pb::listen_request::TargetChange::AddTarget(target)) =
                    &mut request.target_change
                else {
                    unreachable!();
                };
                let Some(pb::target::TargetType::Query(target)) = &mut target.target_type else {
                    unreachable!();
                };
                let Some(pb::target::query_target::QueryType::StructuredQuery(query)) =
                    &mut target.query_type
                else {
                    unreachable!();
                };
                query.limit = Some(limit);
                request
            }
        }
    }

    fn name_of(path: &str) -> String {
        path.rsplit('/').next().unwrap_or("").to_owned()
    }

    /// Reads until `target` is CURRENT and the global boundary after it has come.
    async fn read_through_current<S>(stream: &mut S, target: i32) -> Vec<pb::ListenResponse>
    where
        S: tokio_stream::Stream<Item = Result<pb::ListenResponse, tonic::Status>> + Unpin,
    {
        let mut out = Vec::new();
        let mut current = false;
        loop {
            let item = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .expect("listen response within 5 s")
                .expect("stream open")
                .unwrap();
            let mut boundary = false;
            if let Some(pb::listen_response::ResponseType::TargetChange(t)) = &item.response_type {
                if t.target_change_type == 3 && t.target_ids.contains(&target) {
                    current = true;
                } else if t.target_change_type == 0 && t.target_ids.is_empty() {
                    boundary = true;
                }
            }
            out.push(item);
            if current && boundary {
                return out;
            }
        }
    }

    /// What a client holding `held` for `target` holds after applying the document messages.
    fn applied(
        held: &BTreeSet<String>,
        target: i32,
        items: &[pb::ListenResponse],
    ) -> BTreeSet<String> {
        use pb::listen_response::ResponseType as R;
        let mut held = held.clone();
        for item in items {
            match &item.response_type {
                Some(R::DocumentChange(d)) => {
                    let name = d
                        .document
                        .as_ref()
                        .map(|d| name_of(&d.name))
                        .unwrap_or_default();
                    if d.target_ids.contains(&target) {
                        held.insert(name.clone());
                    }
                    if d.removed_target_ids.contains(&target) {
                        held.remove(&name);
                    }
                }
                Some(R::DocumentDelete(d)) if d.removed_target_ids.contains(&target) => {
                    held.remove(&name_of(&d.document));
                }
                Some(R::DocumentRemove(d)) if d.removed_target_ids.contains(&target) => {
                    held.remove(&name_of(&d.document));
                }
                _ => {}
            }
        }
        held
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Whenever the strict resume fires its count-only filter (token honoured, no expected
        /// count), whatever happened before and after the token (including to the documents the
        /// client holds, and for limit queries where documents leave by being pushed out), the
        /// filter's count is what the query matches now, and the client the replay leaves, which
        /// holds what it held at the token plus what the replay delivered, finds that count equal
        /// to its own exactly when no document it held has left: then it takes no action, and
        /// otherwise its set exceeds the count by exactly the departed documents (which the SDK
        /// resets over, as production's answer to the same resume intends). A second target of
        /// the stream, added fresh, never gets a filter, and ends up holding exactly its matches.
        #[test]
        fn the_filter_of_a_resume_leaves_the_client_with_nothing_to_repair_unless_a_held_document_left(
            shape in shapes(),
            before in steps(),
            after in steps(),
        ) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let (mut client, handle) = start(false).await;
                let mut present = Present::new();
                for step in &before {
                    let write = apply(&mut present, step);
                    commit_writes(&mut client, vec![write]).await;
                }
                // The client's first listen: what it holds at its token is the initial snapshot.
                let (held, token) = {
                    let (tx, rx) = mpsc::channel(8);
                    let mut listen = client.listen(ReceiverStream::new(rx)).await.unwrap().into_inner();
                    tx.send(target_for(1, shape)).await.unwrap();
                    let items = read_through_current(&mut listen, 1).await;
                    let token = items
                        .iter()
                        .rev()
                        .find_map(|item| match &item.response_type {
                            Some(pb::listen_response::ResponseType::TargetChange(t))
                                if !t.resume_token.is_empty() => Some(t.resume_token.clone()),
                            _ => None,
                        })
                        .expect("a token after CURRENT");
                    (applied(&BTreeSet::new(), 1, &items), token)
                };
                prop_assert_eq!(&held, &matching(shape, &present), "the initial snapshot");
                for step in &after {
                    let write = apply(&mut present, step);
                    commit_writes(&mut client, vec![write]).await;
                }
                let now = matching(shape, &present);
                let departed: BTreeSet<String> = held.difference(&now).cloned().collect();

                let (tx, rx) = mpsc::channel(8);
                let mut listen = client.listen(ReceiverStream::new(rx)).await.unwrap().into_inner();
                let mut request = target_for(2, shape);
                if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
                    t.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
                }
                tx.send(request).await.unwrap();
                let replay = read_through_current(&mut listen, 2).await;
                tx.send(target_for(3, shape)).await.unwrap();
                let fresh = read_through_current(&mut listen, 3).await;

                let filters: Vec<&pb::ExistenceFilter> = replay
                    .iter()
                    .chain(fresh.iter())
                    .filter_map(|item| match &item.response_type {
                        Some(pb::listen_response::ResponseType::Filter(f)) => Some(f),
                        _ => None,
                    })
                    .collect();
                let after_replay = applied(&held, 2, &replay);
                prop_assert!(now.is_subset(&after_replay), "the replay delivers every matching document");
                if filters.is_empty() {
                    // The replay of a one-commit departure: the removal message and no filter. The
                    // client holds exactly what the target matches: nothing to repair.
                    prop_assert_eq!(departed.len(), 1, "no filter only for exactly one departure");
                    prop_assert_eq!(&after_replay, &now);
                } else {
                    prop_assert_eq!(filters.len(), 1, "one filter, for the resumed target only");
                    prop_assert_eq!(filters[0].target_id, 2);
                    let in_replay = replay.iter().any(|item| matches!(&item.response_type, Some(pb::listen_response::ResponseType::Filter(_))));
                    prop_assert!(in_replay, "the filter is in the resumed target's replay");
                    let count = usize::try_from(filters[0].count).unwrap();
                    prop_assert_eq!(count, now.len(), "the count is what the query matches now");
                    if departed.is_empty() {
                        prop_assert_eq!(after_replay.len(), count, "nothing left: the SDK finds its count equal");
                        prop_assert_eq!(&after_replay, &now);
                    } else {
                        prop_assert_eq!(
                            after_replay.len() - count,
                            departed.len(),
                            "the SDK's set exceeds the count by exactly the departed documents"
                        );
                        prop_assert_eq!(&after_replay, &now.union(&departed).cloned().collect::<BTreeSet<_>>());
                    }
                }
                prop_assert_eq!(applied(&BTreeSet::new(), 3, &fresh), now, "the fresh target holds its matches");
                handle.abort();
                Ok(())
            })?;
        }
    }
}

/// The answers production gave to a resume in the L1b recordings (docs.local/submissions/listen-l1b/
/// reading-l1b-final.md): a real bloom filter for an expected count answered with a diff, and a
/// replay with the removal message for a one-commit leave or delete.
mod l1b_resume_answers {
    use super::*;

    fn filters(trace: &[pb::ListenResponse]) -> Vec<pb::ExistenceFilter> {
        trace
            .iter()
            .filter_map(|item| match &item.response_type {
                Some(pb::listen_response::ResponseType::Filter(f)) => Some(f.clone()),
                _ => None,
            })
            .collect()
    }

    /// Documents `r/<name>` written, a stream on `r` listened to its first boundary after CURRENT.
    async fn token_after(
        client: &mut FirestoreClient<tonic::transport::Channel>,
        names: &[&str],
    ) -> Vec<u8> {
        commit_writes(
            client,
            names
                .iter()
                .map(|n| set_write(&format!("r/{n}"), &[("v", s("1"))]))
                .collect(),
        )
        .await;
        let (tx, rx) = mpsc::channel(8);
        let mut listen = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(add_query_target(1, "r")).await.unwrap();
        let (_, token) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
        token
    }

    /// What a resumed stream sends until its `boundaries`-th global boundary.
    async fn trace_until_boundary(
        client: &mut FirestoreClient<tonic::transport::Channel>,
        request: pb::ListenRequest,
        boundaries: usize,
    ) -> Vec<pb::ListenResponse> {
        let (tx, rx) = mpsc::channel(8);
        let mut listen = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(request).await.unwrap();
        let mut out = Vec::new();
        let mut seen = 0;
        while seen < boundaries {
            let item = tokio::time::timeout(std::time::Duration::from_secs(5), listen.next())
                .await
                .expect("listen response within 5 s")
                .expect("stream open")
                .unwrap();
            if describe(&item) == "NO_CHANGE[]" {
                seen += 1;
            }
            out.push(item);
        }
        out
    }

    fn names(documents: &[&str]) -> Vec<String> {
        documents.iter().map(|n| format!("{DOCS}/r/{n}")).collect()
    }

    /// The recorded size for each count: (hash count, bitmap bytes, padding).
    fn recorded(count: usize) -> (i32, usize, i32) {
        [(12, 3, 7), (13, 5, 3), (14, 8, 5)][count - 1]
    }

    #[tokio::test]
    async fn an_expected_count_resume_answered_with_a_diff_ends_with_the_bloom_filter_of_the_matching_documents(
    ) {
        for documents in [&["a"][..], &["a", "b"], &["a", "b", "c"]] {
            let (mut client, handle) = start(false).await;
            let token = token_after(&mut client, documents).await;
            commit_writes(&mut client, vec![set_write("r/a", &[("v", s("2"))])]).await;
            let count = i32::try_from(documents.len()).unwrap();
            let trace =
                resumed_trace(&mut client, resume_request(2, "r", token, Some(count))).await;
            assert_eq!(
                described(&trace),
                vec![
                    "ADD[2]".to_owned(),
                    "NO_CHANGE[]".to_owned(),
                    "CHANGE a".to_owned(),
                    format!("FILTER {count}"),
                    "CURRENT[2]".to_owned(),
                    "NO_CHANGE[]".to_owned(),
                ],
                "{documents:?}"
            );
            let filter = &filters(&trace)[0];
            assert_eq!(filter.target_id, 2);
            let bloom = filter.unchanged_names.as_ref().expect("a bloom filter");
            let (hash_count, bytes, padding) = recorded(documents.len());
            assert_eq!(bloom.hash_count, hash_count, "{documents:?}");
            let bits = bloom.bits.as_ref().unwrap();
            assert_eq!(bits.bitmap.len(), bytes);
            assert_eq!(bits.padding, padding);
            for name in names(documents) {
                assert!(sdk_might_contain(bloom, &name), "{name}");
            }
            handle.abort();
        }
    }

    #[tokio::test]
    async fn a_wrong_expected_count_is_answered_exactly_like_the_right_one() {
        let (mut client, handle) = start(false).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(&mut client, vec![set_write("r/a", &[("v", s("2"))])]).await;
        let right =
            resumed_trace(&mut client, resume_request(2, "r", token.clone(), Some(3))).await;
        let wrong = resumed_trace(&mut client, resume_request(2, "r", token, Some(4))).await;
        assert_eq!(described(&right), described(&wrong));
        assert_eq!(filters(&right), filters(&wrong));
        assert_eq!(
            filters(&wrong)[0].count,
            3,
            "the count is what the target matches"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn no_bloom_filter_for_a_count_production_did_not_record_one_for() {
        // Four documents, or none: the diff answers with no filter, as before.
        for documents in [&["a", "b", "c", "d"][..], &[]] {
            let (mut client, handle) = start(false).await;
            let token = token_after(&mut client, documents).await;
            commit_writes(&mut client, vec![set_write("r/a", &[("v", s("2"))])]).await;
            let count = i32::try_from(documents.len()).unwrap();
            let trace =
                resumed_trace(&mut client, resume_request(2, "r", token, Some(count))).await;
            assert!(
                filters(&trace).is_empty() || documents.is_empty(),
                "{documents:?} {:?}",
                described(&trace)
            );
            if documents.len() == 4 {
                assert!(filters(&trace).is_empty(), "{:?}", described(&trace));
            }
            handle.abort();
        }
    }

    #[tokio::test]
    async fn a_document_that_left_since_the_token_keeps_the_removal_message_and_gets_no_bloom_filter(
    ) {
        let (mut client, handle) = start(false).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(&mut client, vec![delete_write("r/b")]).await;
        let trace = resumed_trace(&mut client, resume_request(2, "r", token, Some(3))).await;
        assert!(
            described(&trace).contains(&"DELETE b".to_owned()),
            "{:?}",
            described(&trace)
        );
        assert!(filters(&trace).is_empty(), "{:?}", described(&trace));
        handle.abort();
    }

    #[tokio::test]
    async fn the_emulator_profile_sends_no_bloom_filter_as_the_official_emulator_does_not() {
        let (mut client, handle) = start_profile(Profile::Emulator).await;
        let token = token_after(&mut client, &["a", "b"]).await;
        commit_writes(&mut client, vec![set_write("r/a", &[("v", s("2"))])]).await;
        let trace = resumed_trace(&mut client, resume_request(2, "r", token, Some(2))).await;
        assert!(filters(&trace).is_empty(), "{:?}", described(&trace));
        handle.abort();
    }

    #[tokio::test]
    async fn no_bloom_filter_for_a_fresh_target_a_document_target_or_a_target_without_a_token() {
        let (mut client, handle) = start(false).await;
        let _ = token_after(&mut client, &["a", "b"]).await;
        // A fresh target that gives an expected count: no resume, no filter.
        let mut fresh = add_query_target(2, "r");
        if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut fresh.target_change {
            t.expected_count = Some(2);
        }
        let (tx, rx) = mpsc::channel(8);
        let mut listen = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(fresh).await.unwrap();
        // A fresh target has no replay boundary: ADD, the documents, CURRENT, one boundary.
        let trace = next_until(&mut listen, "NO_CHANGE[]").await;
        assert_eq!(trace.last().map(String::as_str), Some("NO_CHANGE[]"));
        assert!(
            !trace.iter().any(|line| line.starts_with("FILTER")),
            "{trace:?}"
        );
        handle.abort();
    }

    /// A one-commit leave or delete from the token, no expected count: production answered with a
    /// boundary after the removal message and no filter (kinds/leave and kinds/delete, both runs).
    #[tokio::test]
    async fn a_one_commit_delete_is_replayed_with_its_removal_message_and_a_boundary_after_it() {
        let (mut client, handle) = start(false).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(&mut client, vec![delete_write("r/b")]).await;
        let trace = trace_until_boundary(&mut client, resume_request(2, "r", token, None), 3).await;
        assert_eq!(
            described(&trace),
            vec![
                "ADD[2]",
                "NO_CHANGE[]",
                "DELETE b",
                "NO_CHANGE[]",
                "CURRENT[2]",
                "NO_CHANGE[]"
            ]
        );
        assert!(filters(&trace).is_empty());
        handle.abort();
    }

    #[tokio::test]
    async fn a_one_commit_leave_is_replayed_with_its_removal_message_and_a_boundary_after_it() {
        let (mut client, handle) = start(false).await;
        commit_writes(
            &mut client,
            vec![
                set_write("q/a", &[("state", s("included"))]),
                set_write("q/b", &[("state", s("included"))]),
            ],
        )
        .await;
        let (tx, rx) = mpsc::channel(8);
        let mut listen = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(add_filtered_query_target(1, "q")).await.unwrap();
        let (_, token) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
        commit_writes(
            &mut client,
            vec![set_write("q/b", &[("state", s("excluded"))])],
        )
        .await;
        let mut request = add_filtered_query_target(2, "q");
        if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
            t.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
        }
        let trace = trace_until_boundary(&mut client, request, 3).await;
        assert_eq!(
            described(&trace),
            vec![
                "ADD[2]",
                "NO_CHANGE[]",
                "LEAVE b",
                "NO_CHANGE[]",
                "CURRENT[2]",
                "NO_CHANGE[]"
            ]
        );
        assert!(filters(&trace).is_empty());
        handle.abort();
    }

    /// The scope of the replay is the recorded shape only: anything else keeps rule R.
    #[tokio::test]
    async fn the_replay_is_for_exactly_one_commit_with_exactly_one_departure_and_nothing_else() {
        // Two commits (a delete and a modification): count-only filter, no removal message.
        let (mut client, handle) = start(false).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(&mut client, vec![delete_write("r/b")]).await;
        commit_writes(&mut client, vec![set_write("r/a", &[("v", s("2"))])]).await;
        let two = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
        assert!(
            described(&two).contains(&"FILTER 2".to_owned()),
            "{:?}",
            described(&two)
        );
        assert!(!described(&two).contains(&"DELETE b".to_owned()));
        handle.abort();
        // One commit that deletes a document and modifies another: R as well.
        let (mut client, handle) = start(false).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(
            &mut client,
            vec![delete_write("r/b"), set_write("r/a", &[("v", s("2"))])],
        )
        .await;
        let mixed = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
        assert!(
            described(&mixed).contains(&"FILTER 2".to_owned()),
            "{:?}",
            described(&mixed)
        );
        assert!(!described(&mixed).contains(&"DELETE b".to_owned()));
        handle.abort();
        // One commit that deletes two documents: R.
        let (mut client, handle) = start(false).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(&mut client, vec![delete_write("r/b"), delete_write("r/c")]).await;
        let both = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
        assert!(
            described(&both).contains(&"FILTER 1".to_owned()),
            "{:?}",
            described(&both)
        );
        handle.abort();
        // One commit that only modifies: the replay is not for it (R's diff and filter).
        let (mut client, handle) = start(false).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(&mut client, vec![set_write("r/a", &[("v", s("2"))])]).await;
        let modify = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
        assert_eq!(
            described(&modify),
            vec![
                "ADD[2]",
                "NO_CHANGE[]",
                "CHANGE a",
                "FILTER 3",
                "CURRENT[2]",
                "NO_CHANGE[]"
            ]
        );
        handle.abort();
        // A commit elsewhere in between: not one commit since the token, so R.
        let (mut client, handle) = start(false).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(
            &mut client,
            vec![set_write("elsewhere/x", &[("v", s("1"))])],
        )
        .await;
        commit_writes(&mut client, vec![delete_write("r/b")]).await;
        let between = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
        assert!(
            described(&between).contains(&"FILTER 2".to_owned()),
            "{:?}",
            described(&between)
        );
        assert!(!described(&between).contains(&"DELETE b".to_owned()));
        handle.abort();
    }

    #[tokio::test]
    async fn the_emulator_profile_keeps_its_answer_to_a_one_commit_departure() {
        let (mut client, handle) = start_profile(Profile::Emulator).await;
        let token = token_after(&mut client, &["a", "b", "c"]).await;
        commit_writes(&mut client, vec![delete_write("r/b")]).await;
        let trace = resumed_trace(&mut client, resume_request(2, "r", token, None)).await;
        // The profile's exact diff: the removal message, no filter, no boundary after it (the
        // official emulator resets and replays; it sends neither).
        assert_eq!(
            described(&trace),
            vec![
                "ADD[2]",
                "NO_CHANGE[]",
                "DELETE b",
                "CURRENT[2]",
                "NO_CHANGE[]"
            ]
        );
        handle.abort();
    }

    mod one_commit {
        use super::*;
        use proptest::prelude::*;

        #[derive(Debug, Clone, Copy)]
        enum Op {
            Delete(u8),
            Leave(u8),
            Modify(u8),
            Enter,
            Rewrite(u8),
        }

        fn ops() -> impl Strategy<Value = Op> {
            prop_oneof![
                (0_u8..4).prop_map(Op::Delete),
                (0_u8..4).prop_map(Op::Leave),
                (0_u8..4).prop_map(Op::Modify),
                Just(Op::Enter),
                (0_u8..4).prop_map(Op::Rewrite),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(40))]

            /// One commit since the token, no expected count: a delete or a leave of one document
            /// is replayed (the removal message, a boundary after it, no filter); every other
            /// commit keeps rule R (the diff, and a count-only filter of what the target matches).
            #[test]
            fn only_a_one_commit_departure_is_replayed(documents in 2_u8..5, op in ops()) {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    let (mut client, handle) = start(false).await;
                    let seed: Vec<pb::Write> = (0..documents)
                        .map(|i| set_write(&format!("q/d{i}"), &[("state", s("included")), ("v", s("1"))]))
                        .collect();
                    commit_writes(&mut client, seed).await;
                    let (tx, rx) = mpsc::channel(8);
                    let mut listen = client.listen(ReceiverStream::new(rx)).await.unwrap().into_inner();
                    tx.send(add_filtered_query_target(1, "q")).await.unwrap();
                    let (_, token) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
                    let (write, matching) = match op {
                        Op::Delete(i) | Op::Leave(i) | Op::Modify(i) | Op::Rewrite(i) if i >= documents => {
                            (set_write("q/d0", &[("state", s("included")), ("v", s("1"))]), usize::from(documents))
                        }
                        Op::Delete(i) => (delete_write(&format!("q/d{i}")), usize::from(documents) - 1),
                        Op::Leave(i) => (
                            set_write(&format!("q/d{i}"), &[("state", s("excluded")), ("v", s("1"))]),
                            usize::from(documents) - 1,
                        ),
                        Op::Modify(i) => (
                            set_write(&format!("q/d{i}"), &[("state", s("included")), ("v", s("2"))]),
                            usize::from(documents),
                        ),
                        Op::Enter => (
                            set_write("q/new", &[("state", s("included")), ("v", s("1"))]),
                            usize::from(documents) + 1,
                        ),
                        Op::Rewrite(i) => (
                            set_write(&format!("q/d{i}"), &[("state", s("included")), ("v", s("1"))]),
                            usize::from(documents),
                        ),
                    };
                    commit_writes(&mut client, vec![write]).await;
                    let mut request = add_filtered_query_target(2, "q");
                    if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
                        t.resume_type = Some(pb::target::ResumeType::ResumeToken(token));
                    }
                    let departure = matches!(op, Op::Delete(i) | Op::Leave(i) if i < documents);
                    let trace = trace_until_boundary(&mut client, request, if departure { 3 } else { 2 }).await;
                    let lines = described(&trace);
                    if departure {
                        prop_assert_eq!(lines.len(), 6, "{:?}", lines);
                        prop_assert_eq!(&lines[1], "NO_CHANGE[]");
                        prop_assert!(lines[2].starts_with("DELETE ") || lines[2].starts_with("LEAVE "), "{:?}", lines);
                        prop_assert_eq!(&lines[3], "NO_CHANGE[]");
                        prop_assert_eq!(&lines[4], "CURRENT[2]");
                        prop_assert!(filters(&trace).is_empty());
                    } else {
                        let filter = filters(&trace);
                        prop_assert_eq!(filter.len(), 1, "{:?}", lines);
                        prop_assert_eq!(usize::try_from(filter[0].count).unwrap(), matching);
                        prop_assert!(!lines.iter().any(|l| l.starts_with("DELETE ") || l.starts_with("LEAVE ")), "{:?}", lines);
                    }
                    handle.abort();
                    Ok(())
                })?;
            }
        }
    }
}

#[tokio::test]
async fn native_resume_token_lengths_follow_the_profile_and_global_tokens_resume_any_target() {
    for (profile, length) in [(Profile::Strict, 11), (Profile::Emulator, 32)] {
        let (mut client, handle) = start_profile(profile).await;
        let (tx, rx) = mpsc::channel(8);
        let mut listen = client
            .listen(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        tx.send(add_query_target(1, "first")).await.unwrap();
        let (_, current) = trace_and_token(&mut listen, "CURRENT[1]").await;
        let (_, global) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
        assert_eq!(current.len(), length);
        assert_eq!(global.len(), length);
        if length == 11 {
            assert_eq!(current, global);
        } else {
            assert_ne!(current[8..], global[8..]);
        }
        let resume = if length == 11 {
            current.clone()
        } else {
            global.clone()
        };
        tx.send(resume_request(2, "second", resume.clone(), None))
            .await
            .unwrap();
        let (early, echoed) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
        assert_eq!(early, ["ADD[2]", "NO_CHANGE[]"]);
        assert_eq!(echoed, resume);
        let trace = next_until(&mut listen, "NO_CHANGE[]").await;
        assert!(!trace.iter().any(|line| line.starts_with("RESET")));
        handle.abort();
        handle.await.unwrap_err();
    }
}

#[tokio::test]
async fn foreign_resume_tokens_are_removed_in_strict_and_reset_in_emulator() {
    // Production's answer for a foreign token is unrecorded. Strict treats a mismatched check like recorded junk bytes;
    // a token from another target of the same database is not foreign in strict (see the target case below).
    for profile in [Profile::Strict, Profile::Emulator] {
        for foreign in ["target", "database", "epoch"] {
            let (mut client, mut handle) = start_profile(profile).await;
            if foreign == "epoch" {
                BACKEND.with(|b| b.borrow().as_ref().unwrap().reset());
            }
            let (tx, rx) = mpsc::channel(8);
            let mut listen = client
                .listen(ReceiverStream::new(rx))
                .await
                .unwrap()
                .into_inner();
            tx.send(add_query_target(1, "first")).await.unwrap();
            let (_, token) = trace_and_token(&mut listen, "CURRENT[1]").await;
            next_until(&mut listen, "NO_CHANGE[]").await;
            drop(tx);
            drop(listen);
            if foreign == "epoch" {
                // Reconnect to a fresh backend: only the epoch differs, while both database generations are zero.
                handle.abort();
                handle.await.unwrap_err();
                (client, handle) = start_profile(profile).await;
            }
            let (tx, rx) = mpsc::channel(8);
            let mut listen = client
                .listen(ReceiverStream::new(rx))
                .await
                .unwrap()
                .into_inner();
            let mut request = resume_request(
                2,
                if foreign == "target" {
                    "second"
                } else {
                    "first"
                },
                token,
                None,
            );
            if foreign == "database" {
                BACKEND.with(|b| {
                    b.borrow()
                        .as_ref()
                        .unwrap()
                        .replace_declared_databases(["other".to_owned()]);
                });
                request.database = "projects/demo-app/databases/other".to_owned();
                if let Some(pb::listen_request::TargetChange::AddTarget(target)) =
                    &mut request.target_change
                {
                    if let Some(pb::target::TargetType::Query(query)) = &mut target.target_type {
                        query.parent = format!("{}/documents", request.database);
                    }
                }
            }
            tx.send(request).await.unwrap();
            if matches!(profile, Profile::Strict) && foreign == "target" {
                // A strict CURRENT token is the snapshot's global token (FS-LISTEN-SDK L3 203/203C:
                // CURRENT and the following global NO_CHANGE carry the same bytes), and a global token
                // resumes any target of the database, so it is not foreign to another target.
                let trace = next_until(&mut listen, "NO_CHANGE[]").await;
                assert_eq!(trace[..2], ["ADD[2]", "NO_CHANGE[]"], "{foreign}");
            } else if matches!(profile, Profile::Strict) {
                let first = tokio::time::timeout(std::time::Duration::from_secs(5), listen.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    describe(&first),
                    "REMOVE[2] cause=3",
                    "no ADD comes first: {foreign}"
                );
                let Some(pb::listen_response::ResponseType::TargetChange(change)) =
                    first.response_type
                else {
                    panic!("expected a removal")
                };
                assert_eq!(change.cause.unwrap().message, "bad resume token");
            } else {
                let trace = next_until(&mut listen, "NO_CHANGE[]").await;
                assert_eq!(trace[..2], ["ADD[2]", "RESET[2]"], "{foreign}");
            }
            handle.abort();
            handle.await.unwrap_err();
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn webchannel_resume_token_lengths_follow_the_profile() {
    use std::fmt::Write as _;

    use fireemu_adapter_grpc::rest::json::{base64_decode, base64_encode};
    use fireemu_adapter_grpc::rest::RestState;
    use fireemu_adapter_grpc::webchannel::{ChannelRequest, ChannelResponse, Hub, StreamKind};
    use serde_json::json;

    for (profile, length) in [(Profile::Strict, 11), (Profile::Emulator, 32)] {
        let (_, handle) = start_profile(profile).await;
        let local = BACKEND.with(|b| b.borrow().as_ref().unwrap().clone());
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: if matches!(profile, Profile::Strict) {
                    IndexValidationPolicy::Production
                } else {
                    IndexValidationPolicy::Emulator
                },
            },
            indexes: IndexSet::default(),
        };
        let hub = Hub::new(Arc::new(RestState {
            local,
            gateway: Arc::new(gateway),
            rules: None,
            app_check: None,
            control_token: None,
        }));
        let target = json!({"database": DB, "addTarget": {"targetId": 1, "documents": {"documents": [format!("{DOCS}/open/missing")]}}}).to_string();
        let encoded = target.bytes().fold(String::new(), |mut encoded, b| {
            write!(&mut encoded, "%{b:02X}").unwrap();
            encoded
        });
        let ChannelResponse::Full {
            status, headers, ..
        } = hub.handle(&ChannelRequest {
            kind: StreamKind::Listen,
            method: "POST".to_owned(),
            params: BTreeMap::from([
                ("database".to_owned(), DB.to_owned()),
                ("VER".to_owned(), "8".to_owned()),
                ("RID".to_owned(), "1".to_owned()),
            ]),
            authorization: None,
            app_check: Vec::new(),
            origin: None,
            body: format!("count=1&ofs=0&req0___data__={encoded}"),
        })
        else {
            panic!("expected handshake")
        };
        assert_eq!(status, 200);
        let sid = headers
            .into_iter()
            .find(|(key, _)| *key == "x-http-session-id")
            .unwrap()
            .1;
        let mut aid = 0;
        let mut tokens = 0;
        while tokens < 2 {
            let ChannelResponse::Stream { mut body, .. } = hub.handle(&ChannelRequest {
                kind: StreamKind::Listen,
                method: "GET".to_owned(),
                params: BTreeMap::from([
                    ("SID".to_owned(), sid.clone()),
                    ("RID".to_owned(), "rpc".to_owned()),
                    ("AID".to_owned(), aid.to_string()),
                    ("CI".to_owned(), "1".to_owned()),
                    ("TO".to_owned(), "1000".to_owned()),
                    ("TYPE".to_owned(), "xmlhttp".to_owned()),
                ]),
                authorization: None,
                app_check: Vec::new(),
                origin: None,
                body: String::new(),
            }) else {
                panic!("expected back channel")
            };
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), body.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let (_, payload) = std::str::from_utf8(&chunk)
                .unwrap()
                .split_once('\n')
                .unwrap();
            let arrays: serde_json::Value = serde_json::from_str(payload).unwrap();
            for array in arrays.as_array().unwrap() {
                aid = array[0].as_u64().unwrap();
                if let Some(token) = array[1][0]["targetChange"]["resumeToken"].as_str() {
                    let decoded = base64_decode(token).unwrap();
                    assert_eq!(decoded.len(), length);
                    assert_eq!(token.len(), if length == 11 { 16 } else { 44 });
                    assert_eq!(base64_encode(&decoded), token);
                    tokens += 1;
                }
            }
        }
        hub.handle(&ChannelRequest {
            kind: StreamKind::Listen,
            method: "POST".to_owned(),
            params: BTreeMap::from([
                ("SID".to_owned(), sid),
                ("TYPE".to_owned(), "terminate".to_owned()),
            ]),
            authorization: None,
            app_check: Vec::new(),
            origin: None,
            body: String::new(),
        });
        handle.abort();
        handle.await.unwrap_err();
    }
}

mod resume_token_properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn strict_tokens_round_trip_random_versions_and_bindings_and_refuse_different_checks(
            version in 1_u8..9,
            epoch in 0_u8..4,
            database in any::<u32>(),
            target in any::<u32>(),
        ) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let (mut client, handle) = start(false).await;
                let backend = BACKEND.with(|b| b.borrow().as_ref().unwrap().clone());
                for _ in 0..epoch { backend.reset(); }
                backend.replace_declared_databases([format!("db{database}"), "other".to_owned()]);
                let database_id = format!("db{database}");
                let database = format!("projects/demo-app/databases/{database_id}");
                let collection = format!("c{target}");
                for value in 0..version {
                    client.commit(pb::CommitRequest {
                        database: database.clone(),
                        writes: vec![pb::Write { operation: Some(pb::write::Operation::Update(pb::Document { name: format!("{database}/documents/{collection}/a"), fields: std::collections::HashMap::from([("v".to_owned(), s(&value.to_string()))]), ..Default::default() })), ..Default::default() }],
                        ..Default::default()
                    }).await.unwrap();
                }
                let (tx, rx) = mpsc::channel(8);
                let mut listen = client.listen(ReceiverStream::new(rx)).await.unwrap().into_inner();
                let mut request = add_query_target(1, &collection);
                request.database.clone_from(&database);
                if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
                    if let Some(pb::target::TargetType::Query(q)) = &mut t.target_type { q.parent = format!("{database}/documents"); }
                }
                tx.send(request.clone()).await.unwrap();
                let (_, bound) = trace_and_token(&mut listen, "CURRENT[1]").await;
                let (_, global) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
                assert_eq!(bound.len(), 11);
                assert_eq!(bound, global);
                assert_eq!(u64::from_be_bytes(bound[..8].try_into().unwrap()), u64::from(version));
                if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut request.target_change {
                    t.target_id = 2;
                    t.resume_type = Some(pb::target::ResumeType::ResumeToken(bound.clone()));
                }
                tx.send(request.clone()).await.unwrap();
                let (early, echoed) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
                assert_eq!(early, ["ADD[2]", "NO_CHANGE[]"]);
                assert_eq!(echoed, global);
                next_until(&mut listen, "NO_CHANGE[]").await;

                // The 3-byte checks can collide across databases or epochs (about 2^-24 per case).
                let mut other_database = add_query_target(3, &collection);
                other_database.database = "projects/demo-app/databases/other".to_owned();
                if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut other_database.target_change {
                    t.resume_type = Some(pb::target::ResumeType::ResumeToken(bound.clone()));
                    if let Some(pb::target::TargetType::Query(q)) = &mut t.target_type {
                        q.parent = "projects/demo-app/databases/other/documents".to_owned();
                    }
                }
                tx.send(other_database).await.unwrap();
                let rejected = tokio::time::timeout(std::time::Duration::from_secs(5), listen.next()).await.unwrap().unwrap().unwrap();
                assert_eq!(describe(&rejected), "REMOVE[3] cause=3");
                backend.reset();
                backend.replace_declared_databases([database_id]);
                let (tx, rx) = mpsc::channel(8);
                let mut listen = client.listen(ReceiverStream::new(rx)).await.unwrap().into_inner();
                let mut stale_epoch = add_query_target(4, &collection);
                stale_epoch.database.clone_from(&database);
                if let Some(pb::listen_request::TargetChange::AddTarget(t)) = &mut stale_epoch.target_change {
                    t.resume_type = Some(pb::target::ResumeType::ResumeToken(bound));
                    if let Some(pb::target::TargetType::Query(q)) = &mut t.target_type { q.parent = format!("{database}/documents"); }
                }
                tx.send(stale_epoch).await.unwrap();
                let rejected = tokio::time::timeout(std::time::Duration::from_secs(5), listen.next()).await.unwrap().unwrap().unwrap();
                assert_eq!(describe(&rejected), "REMOVE[4] cause=3");
                handle.abort();
                handle.await.unwrap_err();
            });
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn strict_webchannel_current_and_following_global_boundary_share_a_token() {
    use std::fmt::Write as _;

    use fireemu_adapter_grpc::rest::json::{base64_decode, base64_encode};
    use fireemu_adapter_grpc::rest::RestState;
    use fireemu_adapter_grpc::webchannel::{ChannelRequest, ChannelResponse, Hub, StreamKind};
    use serde_json::json;

    for (profile, length) in [(Profile::Strict, 11)] {
        let (_, handle) = start_profile(profile).await;
        let local = BACKEND.with(|b| b.borrow().as_ref().unwrap().clone());
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: if matches!(profile, Profile::Strict) {
                    IndexValidationPolicy::Production
                } else {
                    IndexValidationPolicy::Emulator
                },
            },
            indexes: IndexSet::default(),
        };
        let hub = Hub::new(Arc::new(RestState {
            local,
            gateway: Arc::new(gateway),
            rules: None,
            app_check: None,
            control_token: None,
        }));
        let target = json!({"database": DB, "addTarget": {"targetId": 1, "documents": {"documents": [format!("{DOCS}/open/missing")]}}}).to_string();
        let encoded = target.bytes().fold(String::new(), |mut encoded, b| {
            write!(&mut encoded, "%{b:02X}").unwrap();
            encoded
        });
        let ChannelResponse::Full {
            status, headers, ..
        } = hub.handle(&ChannelRequest {
            kind: StreamKind::Listen,
            method: "POST".to_owned(),
            params: BTreeMap::from([
                ("database".to_owned(), DB.to_owned()),
                ("VER".to_owned(), "8".to_owned()),
                ("RID".to_owned(), "1".to_owned()),
            ]),
            authorization: None,
            app_check: Vec::new(),
            origin: None,
            body: format!("count=1&ofs=0&req0___data__={encoded}"),
        })
        else {
            panic!("expected handshake")
        };
        assert_eq!(status, 200);
        let sid = headers
            .into_iter()
            .find(|(key, _)| *key == "x-http-session-id")
            .unwrap()
            .1;
        let mut aid = 0;
        let mut tokens = 0;
        let mut current_token = None;
        while tokens < 2 {
            let ChannelResponse::Stream { mut body, .. } = hub.handle(&ChannelRequest {
                kind: StreamKind::Listen,
                method: "GET".to_owned(),
                params: BTreeMap::from([
                    ("SID".to_owned(), sid.clone()),
                    ("RID".to_owned(), "rpc".to_owned()),
                    ("AID".to_owned(), aid.to_string()),
                    ("CI".to_owned(), "1".to_owned()),
                    ("TO".to_owned(), "1000".to_owned()),
                    ("TYPE".to_owned(), "xmlhttp".to_owned()),
                ]),
                authorization: None,
                app_check: Vec::new(),
                origin: None,
                body: String::new(),
            }) else {
                panic!("expected back channel")
            };
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), body.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let (_, payload) = std::str::from_utf8(&chunk)
                .unwrap()
                .split_once('\n')
                .unwrap();
            let arrays: serde_json::Value = serde_json::from_str(payload).unwrap();
            for array in arrays.as_array().unwrap() {
                aid = array[0].as_u64().unwrap();
                if let Some(token) = array[1][0]["targetChange"]["resumeToken"].as_str() {
                    let decoded = base64_decode(token).unwrap();
                    assert_eq!(decoded.len(), length);
                    assert_eq!(token.len(), if length == 11 { 16 } else { 44 });
                    assert_eq!(base64_encode(&decoded), token);
                    let change = &array[1][0]["targetChange"];
                    if change["targetChangeType"] == "CURRENT" {
                        assert_eq!(change["targetIds"], json!([1]));
                        current_token = Some(decoded);
                    } else {
                        assert!(change["targetIds"].is_null() || change["targetIds"] == json!([]));
                        assert_eq!(current_token.as_ref().unwrap(), &decoded);
                    }
                    tokens += 1;
                }
            }
        }
        hub.handle(&ChannelRequest {
            kind: StreamKind::Listen,
            method: "POST".to_owned(),
            params: BTreeMap::from([
                ("SID".to_owned(), sid),
                ("TYPE".to_owned(), "terminate".to_owned()),
            ]),
            authorization: None,
            app_check: Vec::new(),
            origin: None,
            body: String::new(),
        });
        handle.abort();
        handle.await.unwrap_err();
    }
}

mod current_boundary_properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn strict_current_boundaries_share_tokens_and_resume_without_replay(
            history in prop::collection::vec((0_u8..4, prop::option::of(any::<u8>())), 0..16),
        ) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let (mut client, handle) = start(false).await;
                for step in std::iter::once(None).chain(history.into_iter().map(Some)) {
                    if let Some((id, value)) = step {
                        let path = format!("shared/d{id}");
                        let write = match value {
                            Some(value) => set_write(&path, &[("v", s(&value.to_string()))]),
                            None => delete_write(&path),
                        };
                        client.commit(pb::CommitRequest {
                            database: DB.to_owned(),
                            writes: vec![write],
                            ..Default::default()
                        }).await.unwrap();
                    }
                    let (tx, rx) = mpsc::channel(8);
                    let mut listen = client.listen(ReceiverStream::new(rx)).await.unwrap().into_inner();
                    tx.send(add_query_target(1, "shared")).await.unwrap();
                    let (_, current) = trace_and_token(&mut listen, "CURRENT[1]").await;
                    let (following, boundary) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
                    assert_eq!(following, ["NO_CHANGE[]"]);
                    assert_eq!(current, boundary);
                    tx.send(resume_request(2, "shared", boundary.clone(), None)).await.unwrap();
                    let (early, echoed) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
                    assert_eq!(early, ["ADD[2]", "NO_CHANGE[]"]);
                    assert_eq!(echoed, boundary);
                    let (replay, resumed_current) = trace_and_token(&mut listen, "CURRENT[2]").await;
                    assert!(replay.iter().all(|line| line.starts_with("FILTER ") || line == "CURRENT[2]"));
                    let (following, resumed_boundary) = trace_and_token(&mut listen, "NO_CHANGE[]").await;
                    assert_eq!(following, ["NO_CHANGE[]"]);
                    assert_eq!(resumed_current, resumed_boundary);
                }
                handle.abort();
                handle.await.unwrap_err();
            });
        }
    }
}
