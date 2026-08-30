//! End-to-end tests over the real gRPC surface: a tonic client drives create / publish / pull /
//! ack / filter / redelivery against a served adapter on a loopback port.

use std::sync::{Arc, Mutex};

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
