//! `Write` and `Listen` streams through a real tonic client: handshake, sequential commits,
//! initial snapshots, live diffs after commits, target removal and rules denials.

use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::rules::RulesEnforcer;
use ftd_adapter_grpc::service::GatewayService;
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::AuthStore;
use ftd_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::SplitMix64;
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::time::LogicalInstant;
use ftd_proto_firestore::google::firestore::v1 as pb;
use ftd_proto_firestore::google::firestore::v1::firestore_client::FirestoreClient;
use ftd_proto_firestore::google::firestore::v1::firestore_server::FirestoreServer;
use ftd_proto_firestore::google::firestore::v1::structured_query as sq;
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
    BACKEND.with(|b| *b.borrow_mut() = Some(backend.clone()));
    let mut service = GatewayService::local(gateway, backend);
    if with_rules {
        let auth = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        let rules = Arc::new(RwLock::new(LoadedRules::from_source(RULES).unwrap()));
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
