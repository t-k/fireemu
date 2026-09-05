//! End-to-end tests over the real gRPC surface: a tonic client drives create / publish / pull /
//! ack / filter / redelivery against a served adapter on a loopback port.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use fireemu_adapter_pubsub::{serve_pubsub, BridgeMessage, PubSubHandle, TopicDelivery};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
use pb::subscriber_client::SubscriberClient;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_stream::StreamExt as _;

struct Harness {
    endpoint: String,
    clock: Arc<Mutex<VirtualClock>>,
    handle: PubSubHandle,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl Harness {
    async fn channel(&self) -> tonic::transport::Channel {
        tonic::transport::Channel::from_shared(self.endpoint.clone())
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    async fn publisher(&self) -> PublisherClient<tonic::transport::Channel> {
        PublisherClient::new(self.channel().await)
    }

    async fn subscriber(&self) -> SubscriberClient<tonic::transport::Channel> {
        SubscriberClient::new(self.channel().await)
    }

    async fn shutdown(mut self) {
        self.handle.shutdown_push_dispatcher().await;
        if let Some(server) = self.server.take() {
            server.abort();
            let _ = server.await;
        }
    }

    async fn abort_server(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
            let _ = server.await;
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.handle.cancel_push_dispatcher();
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

async fn start() -> Harness {
    start_with_bridge(None).await
}

async fn start_with_bridge(bridge: Option<Arc<dyn TopicDelivery>>) -> Harness {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_700_000_000),
    )));
    let state = Arc::new(Mutex::new(PubSubState::new(42)));
    let handle = PubSubHandle::new(state, clock.clone(), bridge);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = handle.clone();
    let server = tokio::spawn(async move {
        let _ = serve_pubsub(listener, server_handle).await;
    });
    // Give the server a moment to accept.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Harness {
        endpoint: format!("http://{addr}"),
        clock,
        handle,
        server: Some(server),
    }
}

#[derive(Default)]
struct RecordingTopicDelivery(Mutex<Vec<String>>);

impl TopicDelivery for RecordingTopicDelivery {
    fn deliver(&self, topic: &str, _messages: &[BridgeMessage]) {
        self.0.lock().unwrap().push(topic.to_owned());
    }
}

#[tokio::test]
async fn functions_bridge_receives_the_full_source_topic_resource() {
    let delivery = Arc::new(RecordingTopicDelivery::default());
    let harness = start_with_bridge(Some(delivery.clone())).await;
    let mut publisher = harness.publisher().await;
    publisher
        .create_topic(pb::Topic {
            name: "projects/other-project/topics/jobs".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    publisher
        .publish(pb::PublishRequest {
            topic: "projects/other-project/topics/jobs".to_owned(),
            messages: vec![msg(b"scope sentinel")],
        })
        .await
        .unwrap();

    assert_eq!(
        *delivery.0.lock().unwrap(),
        vec!["projects/other-project/topics/jobs"]
    );
    harness.shutdown().await;
}

fn msg(data: &[u8]) -> pb::PubsubMessage {
    pb::PubsubMessage {
        data: data.to_vec(),
        ..Default::default()
    }
}

type PushSink = (
    String,
    Arc<Mutex<Vec<Vec<u8>>>>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
);

type BarrierPushSink = (
    String,
    Arc<Mutex<Vec<Vec<u8>>>>,
    tokio::sync::oneshot::Receiver<()>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
);

fn push_sink(status: u16) -> PushSink {
    push_sink_sequence(vec![status])
}

fn push_sink_sequence(statuses: Vec<u16>) -> PushSink {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let received = bodies.clone();
    let statuses = Arc::new(Mutex::new(VecDeque::from(statuses)));
    let response_statuses = statuses.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let should_stop = stop.clone();
    let worker = thread::spawn(move || {
        while !should_stop.load(Ordering::Acquire) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(std::time::Duration::from_millis(2));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let body_start = loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break None;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break Some(index + 4);
                }
            };
            let Some(body_start) = body_start else {
                continue;
            };
            let content_length = request
                .windows(b"content-length:".len())
                .position(|window| window.eq_ignore_ascii_case(b"content-length:"))
                .and_then(|index| {
                    let line = request[index..].split(|byte| *byte == b'\n').next()?;
                    std::str::from_utf8(line)
                        .ok()?
                        .split(':')
                        .nth(1)?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .unwrap_or_default();
            while request.len() < body_start.saturating_add(content_length) {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            if request.len() >= body_start.saturating_add(content_length) {
                received
                    .lock()
                    .unwrap()
                    .push(request[body_start..body_start + content_length].to_vec());
            }
            let status = response_statuses.lock().unwrap().pop_front().unwrap_or(204);
            let response =
                format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{address}/push"), bodies, stop, worker)
}

fn barrier_push_sink() -> BarrierPushSink {
    barrier_push_sink_with_status(204)
}

fn barrier_push_sink_with_status(status: u16) -> BarrierPushSink {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let received = bodies.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let should_stop = stop.clone();
    let release = Arc::new(AtomicBool::new(false));
    let can_release = release.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let worker = thread::spawn(move || {
        let mut first = true;
        let mut started_tx = Some(started_tx);
        while !should_stop.load(Ordering::Acquire) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(std::time::Duration::from_millis(2));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let body_start = loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break None;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break Some(index + 4);
                }
            };
            let Some(body_start) = body_start else {
                continue;
            };
            let content_length = request
                .windows(b"content-length:".len())
                .position(|window| window.eq_ignore_ascii_case(b"content-length:"))
                .and_then(|index| {
                    let line = request[index..].split(|byte| *byte == b'\n').next()?;
                    std::str::from_utf8(line)
                        .ok()?
                        .split(':')
                        .nth(1)?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .unwrap_or_default();
            while request.len() < body_start.saturating_add(content_length) {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            if request.len() < body_start.saturating_add(content_length) {
                continue;
            }
            received
                .lock()
                .unwrap()
                .push(request[body_start..body_start + content_length].to_vec());
            if first {
                first = false;
                if let Some(sender) = started_tx.take() {
                    let _ = sender.send(());
                }
                while !can_release.load(Ordering::Acquire) && !should_stop.load(Ordering::Acquire) {
                    thread::sleep(std::time::Duration::from_millis(2));
                }
            }
            let response =
                format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (
        format!("http://{address}/push"),
        bodies,
        started_rx,
        release,
        stop,
        worker,
    )
}

type GatedPushSink = (
    String,
    Arc<AtomicUsize>,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
);

async fn gated_push_sink(expected: usize) -> GatedPushSink {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let observed = received.clone();
    let (release, released) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..expected {
            let (mut stream, _) = listener.accept().await.unwrap();
            let observed = observed.clone();
            let mut released = released.clone();
            connections.spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                let body_end = loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0, "push request ended before its body");
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|index| index + 4)
                    else {
                        continue;
                    };
                    let content_length = request
                        .windows(b"content-length:".len())
                        .position(|window| window.eq_ignore_ascii_case(b"content-length:"))
                        .and_then(|index| {
                            let line = request[index..].split(|byte| *byte == b'\n').next()?;
                            std::str::from_utf8(line)
                                .ok()?
                                .split(':')
                                .nth(1)?
                                .trim()
                                .parse::<usize>()
                                .ok()
                        })
                        .unwrap_or_default();
                    if request.len() >= header_end.saturating_add(content_length) {
                        break header_end + content_length;
                    }
                };
                assert!(request.len() >= body_end);
                observed.fetch_add(1, Ordering::AcqRel);
                while !*released.borrow() {
                    released.changed().await.unwrap();
                }
                stream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = connections.join_next().await {
            result.unwrap();
        }
    });
    (format!("http://{address}/push"), received, release, worker)
}

#[tokio::test]
async fn publish_pull_ack_round_trip() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    pubc.create_topic(pb::Topic {
        name: "projects/demo-app/topics/orders".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/orders-sub".to_owned(),
        topic: "projects/demo-app/topics/orders".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    let ids = pubc
        .publish(pb::PublishRequest {
            topic: "projects/demo-app/topics/orders".to_owned(),
            messages: vec![msg(b"hello"), msg(b"world")],
        })
        .await
        .unwrap()
        .into_inner()
        .message_ids;
    assert_eq!(ids.len(), 2);

    let pulled = subc
        .pull(pb::PullRequest {
            subscription: "projects/demo-app/subscriptions/orders-sub".to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(pulled.len(), 2);
    let ack_ids: Vec<String> = pulled.iter().map(|m| m.ack_id.clone()).collect();

    subc.acknowledge(pb::AcknowledgeRequest {
        subscription: "projects/demo-app/subscriptions/orders-sub".to_owned(),
        ack_ids,
    })
    .await
    .unwrap();

    // Nothing outstanding after ack.
    let again = subc
        .pull(pb::PullRequest {
            subscription: "projects/demo-app/subscriptions/orders-sub".to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(again.is_empty());
}

#[tokio::test]
async fn creating_subscription_for_missing_topic_is_not_found() {
    let h = start().await;
    let mut subc = h.subscriber().await;
    let err = subc
        .create_subscription(pb::Subscription {
            name: "projects/demo-app/subscriptions/x-sub".to_owned(),
            topic: "projects/demo-app/topics/missing".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn filter_drops_non_matching_messages() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    pubc.create_topic(pb::Topic {
        name: "projects/demo-app/topics/events".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/orders-only".to_owned(),
        topic: "projects/demo-app/topics/events".to_owned(),
        filter: "attributes.type = \"order\"".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    let mut order = msg(b"o");
    order
        .attributes
        .insert("type".to_owned(), "order".to_owned());
    let mut refund = msg(b"r");
    refund
        .attributes
        .insert("type".to_owned(), "refund".to_owned());
    pubc.publish(pb::PublishRequest {
        topic: "projects/demo-app/topics/events".to_owned(),
        messages: vec![order, refund],
    })
    .await
    .unwrap();

    let pulled = subc
        .pull(pb::PullRequest {
            subscription: "projects/demo-app/subscriptions/orders-only".to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].message.as_ref().unwrap().data, b"o");
}

#[tokio::test]
async fn redelivery_after_ack_deadline_on_virtual_clock() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    pubc.create_topic(pb::Topic {
        name: "projects/demo-app/topics/jobs".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/jobs-sub".to_owned(),
        topic: "projects/demo-app/topics/jobs".to_owned(),
        ack_deadline_seconds: 10,
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: "projects/demo-app/topics/jobs".to_owned(),
        messages: vec![msg(b"job")],
    })
    .await
    .unwrap();

    let sub = "projects/demo-app/subscriptions/jobs-sub".to_owned();
    let first = subc
        .pull(pb::PullRequest {
            subscription: sub.clone(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].delivery_attempt, 1);

    // The message is not redelivered without ack until the deadline passes.
    let none = subc
        .pull(pb::PullRequest {
            subscription: sub.clone(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(none.is_empty());

    // Advance the virtual clock past the ack deadline: the message comes back.
    h.clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(11))
        .unwrap();
    let second = subc
        .pull(pb::PullRequest {
            subscription: sub,
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].delivery_attempt, 2);
}

#[tokio::test]
async fn streaming_pull_delivers_and_acks() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    pubc.create_topic(pb::Topic {
        name: "projects/demo-app/topics/stream".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/stream-sub".to_owned(),
        topic: "projects/demo-app/topics/stream".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: "projects/demo-app/topics/stream".to_owned(),
        messages: vec![msg(b"streamed")],
    })
    .await
    .unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel::<pb::StreamingPullRequest>(4);
    tx.send(pb::StreamingPullRequest {
        subscription: "projects/demo-app/subscriptions/stream-sub".to_owned(),
        stream_ack_deadline_seconds: 10,
        ..Default::default()
    })
    .await
    .unwrap();
    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut responses = subc.streaming_pull(outbound).await.unwrap().into_inner();

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
        .await
        .expect("a streaming response arrives")
        .expect("stream open")
        .expect("ok response");
    assert_eq!(msg.received_messages.len(), 1);
    assert_eq!(
        msg.received_messages[0].message.as_ref().unwrap().data,
        b"streamed"
    );
    // Ack it on the same stream.
    let ack = msg.received_messages[0].ack_id.clone();
    tx.send(pb::StreamingPullRequest {
        ack_ids: vec![ack],
        ..Default::default()
    })
    .await
    .unwrap();
    drop(tx);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn snapshot_lifecycle_replays_backlog_and_post_creation_messages() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    let topic = "projects/demo-app/topics/snapshots";
    let source = "projects/demo-app/subscriptions/snapshot-source";
    let replay = "projects/demo-app/subscriptions/snapshot-replay";
    let snapshot = "projects/demo-app/snapshots/checkpoint";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: source.to_owned(),
        topic: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"acked"), msg(b"backlog")],
    })
    .await
    .unwrap();

    let source_messages = subc
        .pull(pb::PullRequest {
            subscription: source.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(source_messages.len(), 2);
    subc.acknowledge(pb::AcknowledgeRequest {
        subscription: source.to_owned(),
        ack_ids: vec![source_messages[0].ack_id.clone()],
    })
    .await
    .unwrap();

    let created = subc
        .create_snapshot(pb::CreateSnapshotRequest {
            name: snapshot.to_owned(),
            subscription: source.to_owned(),
            labels: HashMap::from([(String::from("env"), String::from("test"))]),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.name, snapshot);
    assert_eq!(created.topic, topic);
    assert!(created.expire_time.is_some());

    let listed = subc
        .list_snapshots(pb::ListSnapshotsRequest {
            project: "projects/demo-app".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .snapshots;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, snapshot);

    let topic_snapshots = pubc
        .list_topic_snapshots(pb::ListTopicSnapshotsRequest {
            topic: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .snapshots;
    assert_eq!(topic_snapshots, vec![snapshot]);

    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"future")],
    })
    .await
    .unwrap();
    subc.delete_subscription(pb::DeleteSubscriptionRequest {
        subscription: source.to_owned(),
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: replay.to_owned(),
        topic: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    subc.seek(pb::SeekRequest {
        subscription: replay.to_owned(),
        target: Some(pb::seek_request::Target::Snapshot(snapshot.to_owned())),
    })
    .await
    .unwrap();
    let replayed = subc
        .pull(pb::PullRequest {
            subscription: replay.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    let bodies: Vec<Vec<u8>> = replayed
        .iter()
        .map(|message| message.message.as_ref().unwrap().data.clone())
        .collect();
    assert_eq!(bodies, vec![b"backlog".to_vec(), b"future".to_vec()]);

    let updated = subc
        .update_snapshot(pb::UpdateSnapshotRequest {
            snapshot: Some(pb::Snapshot {
                name: snapshot.to_owned(),
                labels: HashMap::from([(String::from("env"), String::from("prod"))]),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec![String::from("labels")],
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.labels.get("env"), Some(&String::from("prod")));

    subc.delete_snapshot(pb::DeleteSnapshotRequest {
        snapshot: snapshot.to_owned(),
    })
    .await
    .unwrap();
    let err = subc
        .get_snapshot(pb::GetSnapshotRequest {
            snapshot: snapshot.to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn list_topic_snapshots_rejects_a_deleted_topic() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let topic = "projects/demo-app/topics/deleted-snapshot-topic";
    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.delete_topic(pb::DeleteTopicRequest {
        topic: topic.to_owned(),
    })
    .await
    .unwrap();

    let status = pubc
        .list_topic_snapshots(pb::ListTopicSnapshotsRequest {
            topic: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    h.shutdown().await;
}

#[tokio::test]
async fn push_subscription_delivers_json_and_acknowledges_the_message() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink(204);
    let topic = "projects/demo-app/topics/push";
    let subscription = "projects/demo-app/subscriptions/push";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"push-me")],
    })
    .await
    .unwrap();

    for _ in 0..100 {
        if !bodies.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let pushed = bodies.lock().unwrap().clone();
    assert_eq!(pushed.len(), 1);
    let body = String::from_utf8(pushed[0].clone()).unwrap();
    assert!(body.contains("\"data\":\"cHVzaC1tZQ==\""));
    assert!(body.contains(subscription));

    let pulled = subc
        .pull(pb::PullRequest {
            subscription: subscription.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(pulled.is_empty());
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn push_subscription_retries_after_failures_without_a_new_publish() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![500, 500, 500, 204]);
    let topic = "projects/demo-app/topics/push-retry";
    let subscription = "projects/demo-app/subscriptions/push-retry";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"retry-me")],
    })
    .await
    .unwrap();

    for _ in 0..200 {
        if bodies.lock().unwrap().len() >= 4 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(bodies.lock().unwrap().len(), 4);
    let pulled = subc
        .pull(pb::PullRequest {
            subscription: subscription.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(pulled.is_empty());
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn saturated_workers_release_cross_topic_work_without_another_publish() {
    const SATURATED_WORKERS: usize = 256;

    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (blocked_endpoint, blocked_count, release, blocked_worker) =
        gated_push_sink(SATURATED_WORKERS).await;
    let (other_endpoint, other_bodies, stop_other, other_worker) = push_sink(204);
    let first_topic = "projects/demo-app/topics/saturated-first";
    let second_topic = "projects/demo-app/topics/saturated-second";

    for topic in [first_topic, second_topic] {
        pubc.create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    for index in 0..SATURATED_WORKERS {
        subc.create_subscription(pb::Subscription {
            name: format!("projects/demo-app/subscriptions/saturated-{index:04}"),
            topic: first_topic.to_owned(),
            push_config: Some(pb::PushConfig {
                push_endpoint: blocked_endpoint.clone(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/saturated-other".to_owned(),
        topic: second_topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: other_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();

    pubc.publish(pb::PublishRequest {
        topic: first_topic.to_owned(),
        messages: vec![msg(b"occupy")],
    })
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while blocked_count.load(Ordering::Acquire) != SATURATED_WORKERS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all worker slots must be occupied");

    pubc.publish(pb::PublishRequest {
        topic: second_topic.to_owned(),
        messages: vec![msg(b"other-topic")],
    })
    .await
    .unwrap();
    assert!(other_bodies.lock().unwrap().is_empty());
    release.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while other_bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cross-topic work must remain queued at saturation");

    h.shutdown().await;
    blocked_worker.await.unwrap();
    stop_other.store(true, Ordering::Release);
    other_worker.join().unwrap();
}

#[tokio::test]
async fn shutdown_cancels_and_joins_in_flight_push_io() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, started, release, stop, worker) = barrier_push_sink();
    let topic = "projects/demo-app/topics/push-shutdown";
    let subscription = "projects/demo-app/subscriptions/push-shutdown";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"in-flight")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), h.shutdown())
        .await
        .expect("dispatcher shutdown must cancel and join in-flight I/O");
    assert_eq!(bodies.lock().unwrap().len(), 1);

    release.store(true, Ordering::Release);
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn aborting_the_public_server_cancels_in_flight_push_retries() {
    let mut h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, started, release, stop, worker) = barrier_push_sink_with_status(500);
    let topic = "projects/demo-app/topics/push-server-abort";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/push-server-abort".to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"must-not-retry")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    h.abort_server().await;
    release.store(true, Ordering::Release);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(bodies.lock().unwrap().len(), 1);

    h.handle.shutdown_push_dispatcher().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn ready_notification_is_not_consumed_by_an_unrelated_blocked_worker() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (blocked_endpoint, _blocked_bodies, started, release, stop_blocked, blocked_worker) =
        barrier_push_sink();
    let (ready_endpoint, ready_bodies, stop_ready, ready_worker) = push_sink(204);
    let blocked_topic = "projects/demo-app/topics/blocked-notify";
    let ready_topic = "projects/demo-app/topics/ready-notify";

    for topic in [blocked_topic, ready_topic] {
        pubc.create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    for (name, topic, endpoint) in [
        (
            "projects/demo-app/subscriptions/blocked-notify",
            blocked_topic,
            blocked_endpoint,
        ),
        (
            "projects/demo-app/subscriptions/ready-notify",
            ready_topic,
            ready_endpoint,
        ),
    ] {
        subc.create_subscription(pb::Subscription {
            name: name.to_owned(),
            topic: topic.to_owned(),
            push_config: Some(pb::PushConfig {
                push_endpoint: endpoint,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    pubc.publish(pb::PublishRequest {
        topic: blocked_topic.to_owned(),
        messages: vec![msg(b"blocked")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    pubc.publish(pb::PublishRequest {
        topic: ready_topic.to_owned(),
        messages: vec![msg(b"ready")],
    })
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while ready_bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dispatcher readiness must have a dedicated notification");

    h.shutdown().await;
    release.store(true, Ordering::Release);
    stop_blocked.store(true, Ordering::Release);
    stop_ready.store(true, Ordering::Release);
    blocked_worker.join().unwrap();
    ready_worker.join().unwrap();
}

#[tokio::test]
async fn push_endpoint_update_only_changes_deliveries_not_started_before_the_update() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (old_endpoint, old_bodies, started, release, stop_old, worker_old) = barrier_push_sink();
    let (new_endpoint, new_bodies, stop_new, worker_new) = push_sink(204);
    let topic = "projects/demo-app/topics/push-update";
    let subscription = "projects/demo-app/subscriptions/push-update";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: old_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"first"), msg(b"second")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    subc.modify_push_config(pb::ModifyPushConfigRequest {
        subscription: subscription.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: new_endpoint,
            ..Default::default()
        }),
    })
    .await
    .unwrap();
    release.store(true, Ordering::Release);

    for _ in 0..200 {
        if !new_bodies.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(old_bodies.lock().unwrap().len(), 1);
    assert_eq!(new_bodies.lock().unwrap().len(), 1);
    stop_old.store(true, Ordering::Release);
    stop_new.store(true, Ordering::Release);
    worker_old.join().unwrap();
    worker_new.join().unwrap();
}

#[tokio::test]
async fn deleting_and_recreating_a_subscription_invalidates_the_old_push_generation() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (old_endpoint, old_bodies, started, release, stop_old, worker_old) = barrier_push_sink();
    let (new_endpoint, new_bodies, stop_new, worker_new) = push_sink(204);
    let topic = "projects/demo-app/topics/push-recreate";
    let subscription = "projects/demo-app/subscriptions/push-recreate";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: old_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"old-generation")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    subc.delete_subscription(pb::DeleteSubscriptionRequest {
        subscription: subscription.to_owned(),
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: new_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"new-generation")],
    })
    .await
    .unwrap();
    release.store(true, Ordering::Release);

    for _ in 0..200 {
        if !new_bodies.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(old_bodies.lock().unwrap().len(), 1);
    assert_eq!(new_bodies.lock().unwrap().len(), 1);
    let pulled = subc
        .pull(pb::PullRequest {
            subscription: subscription.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(pulled.is_empty());
    stop_old.store(true, Ordering::Release);
    stop_new.store(true, Ordering::Release);
    worker_old.join().unwrap();
    worker_new.join().unwrap();
}
