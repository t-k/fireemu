//! End-to-end tests over the real gRPC surface: a tonic client drives create / publish / pull /
//! ack / filter / redelivery against a served adapter on a loopback port.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use fireemu_adapter_pubsub::{serve_pubsub, PubSubHandle};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
use pb::subscriber_client::SubscriberClient;
use tokio_stream::StreamExt as _;

struct Harness {
    endpoint: String,
    clock: Arc<Mutex<VirtualClock>>,
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
}

async fn start() -> Harness {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_700_000_000),
    )));
    let state = Arc::new(Mutex::new(PubSubState::new(42)));
    let handle = PubSubHandle::new(state, clock.clone(), None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_pubsub(listener, handle).await;
    });
    // Give the server a moment to accept.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Harness {
        endpoint: format!("http://{addr}"),
        clock,
    }
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

fn push_sink(status: u16) -> PushSink {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let received = bodies.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let should_stop = stop.clone();
    let worker = thread::spawn(move || {
        while !should_stop.load(Ordering::Acquire) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(std::time::Duration::from_millis(2));
                continue;
            };
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
            let response =
                format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{address}/push"), bodies, stop, worker)
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
    for name in [source, replay] {
        subc.create_subscription(pb::Subscription {
            name: name.to_owned(),
            topic: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
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
    let initial_replay = subc
        .pull(pb::PullRequest {
            subscription: replay.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(initial_replay.len(), 3);
    subc.acknowledge(pb::AcknowledgeRequest {
        subscription: replay.to_owned(),
        ack_ids: initial_replay
            .iter()
            .map(|message| message.ack_id.clone())
            .collect(),
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
