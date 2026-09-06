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
            policy: IndexValidationPolicy::Conservative,
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
        stream_token: handshake.stream_token,
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
    // Two batches queued against the same acknowledged token (what the JS SDK does).
    for name in ["open/p1", "open/p2"] {
        tx.send(pb::WriteRequest {
            writes: vec![set_write(name, &[("v", s("1"))])],
            stream_token: handshake.stream_token.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    let first = responses.next().await.unwrap().unwrap();
    let second = responses.next().await.unwrap().unwrap();
    assert!(
        first.stream_id.is_empty(),
        "the stream id is only announced once"
    );
    assert_ne!(first.stream_token, second.stream_token);
    assert_eq!(second.write_results.len(), 1);

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
            "CURRENT[3]",
            "NO_CHANGE[3]",
            "NO_CHANGE[]",
            "REMOVE[3]"
        ]
    );
    handle.abort();
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

#[tokio::test]
async fn partition_query_splits_a_collection_group_by_name() {
    let (mut client, handle) = start(false).await;
    let writes: Vec<pb::Write> = (0..10)
        .map(|i| set_write(&format!("owners/o{i}/items/i{i}"), &[("v", s("x"))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let request = |count: i64, page_size: i32, page_token: &str| pb::PartitionQueryRequest {
        parent: DOCS.to_owned(),
        partition_count: count,
        page_size,
        page_token: page_token.to_owned(),
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
    let name_of = |c: &pb::Cursor| match &c.values[0].value_type {
        Some(pb::value::ValueType::ReferenceValue(r)) => r.rsplit('/').next().unwrap().to_owned(),
        other => panic!("{other:?}"),
    };
    let r = client
        .partition_query(request(4, 0, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.partitions.len(), 4);
    assert!(r.partitions.iter().all(|c| c.before));
    assert_eq!(
        r.partitions.iter().map(name_of).collect::<Vec<_>>(),
        ["i2", "i4", "i6", "i8"]
    );
    assert!(r.next_page_token.is_empty());
    // Paged.
    let first = client
        .partition_query(request(4, 3, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.partitions.len(), 3);
    assert!(
        first.next_page_token.ends_with(":3"),
        "{}",
        first.next_page_token
    );
    let second = client
        .partition_query(request(4, 3, &first.next_page_token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        second.partitions.iter().map(name_of).collect::<Vec<_>>(),
        ["i8"]
    );
    assert!(second.next_page_token.is_empty());
    // More partitions than documents: at most n - 1 cut points.
    let r = client
        .partition_query(request(100, 0, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(r.partitions.len(), 9);
    // A plain collection query is refused.
    let mut plain = request(2, 0, "");
    if let Some(pb::partition_query_request::QueryType::StructuredQuery(sq)) = &mut plain.query_type
    {
        sq.from[0].all_descendants = false;
    }
    assert_eq!(
        client.partition_query(plain).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
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
    let writes: Vec<pb::Write> = (0..8)
        .map(|i| set_write(&format!("owners/o{i}/parts/p{i}"), &[("v", s("x"))]))
        .collect();
    client
        .commit(pb::CommitRequest {
            database: DB.to_owned(),
            writes,
            ..Default::default()
        })
        .await
        .unwrap();
    let request = |count: i64, page_size: i32, page_token: &str| pb::PartitionQueryRequest {
        parent: DOCS.to_owned(),
        partition_count: count,
        page_size,
        page_token: page_token.to_owned(),
        query_type: Some(pb::partition_query_request::QueryType::StructuredQuery(
            pb::StructuredQuery {
                from: vec![sq::CollectionSelector {
                    collection_id: "parts".to_owned(),
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
    };
    let name_of = |c: &pb::Cursor| match &c.values[0].value_type {
        Some(pb::value::ValueType::ReferenceValue(r)) => r.rsplit('/').next().unwrap().to_owned(),
        other => panic!("{other:?}"),
    };
    let first = client
        .partition_query(request(3, 2, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        first.partitions.iter().map(name_of).collect::<Vec<_>>(),
        ["p2", "p4"]
    );
    // Documents inserted before the next page do not shift the cuts of this partitioning.
    let writes: Vec<pb::Write> = (0..8)
        .map(|i| set_write(&format!("owners/n{i}/parts/a{i}"), &[("v", s("y"))]))
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
        .partition_query(request(3, 2, &first.next_page_token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        second.partitions.iter().map(name_of).collect::<Vec<_>>(),
        ["p6"]
    );
    // A fresh partitioning sees the new documents; a token for another count is refused.
    let fresh = client
        .partition_query(request(3, 0, ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        fresh.partitions.iter().map(name_of).collect::<Vec<_>>(),
        ["a4", "p0", "p4"]
    );
    assert_eq!(
        client
            .partition_query(request(4, 2, &first.next_page_token))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        client
            .partition_query(request(3, -1, ""))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
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
            policy: IndexValidationPolicy::Conservative,
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
        cause.message.contains("The query requires an index.")
            && cause.message.contains("firestore.indexes.json")
            && cause.message.contains("updatedAt"),
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
