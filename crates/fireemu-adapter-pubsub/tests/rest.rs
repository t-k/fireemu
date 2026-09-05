//! Cross-transport Pub/Sub checks for the shared REST and gRPC state.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use fireemu_adapter_pubsub::{serve_pubsub, PubSubHandle};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
use pb::subscriber_client::SubscriberClient;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start() -> std::net::SocketAddr {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_700_000_000),
    )));
    let state = Arc::new(Mutex::new(PubSubState::new(99)));
    let handle = PubSubHandle::new(state, clock, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_pubsub(listener, handle).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    address
}

async fn rest_request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Value,
) -> (u16, Value) {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let body = serde_json::to_vec(&body).unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| {
            panic!(
                "raw HTTP response: {:?}",
                String::from_utf8_lossy(&response)
            )
        });
    let (headers, body) = response.split_at(separator);
    let body = &body[4..];
    let status = std::str::from_utf8(headers)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, serde_json::from_slice(body).unwrap())
}

async fn grpc_channel(address: std::net::SocketAddr) -> tonic::transport::Channel {
    tonic::transport::Channel::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

#[tokio::test]
async fn rest_publish_is_visible_to_grpc_and_grpc_publish_is_visible_to_rest() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/topics/events",
        json!({"labels": {"owner": "rest"}}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/events-sub",
        json!({"topic": "projects/demo-app/topics/events"}),
    )
    .await;
    assert_eq!(status, 200);

    let (status, rest_published) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/topics/events:publish",
        json!({"messages": [{"data": BASE64.encode(b"from-rest")}]}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(rest_published["messageIds"].as_array().unwrap().len(), 1);

    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let pulled = subscriber
        .pull(pb::PullRequest {
            subscription: "projects/demo-app/subscriptions/events-sub".to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].message.as_ref().unwrap().data, b"from-rest");

    let mut publisher = PublisherClient::new(grpc_channel(address).await);
    publisher
        .publish(pb::PublishRequest {
            topic: "projects/demo-app/topics/events".to_owned(),
            messages: vec![pb::PubsubMessage {
                data: b"from-grpc".to_vec(),
                ..Default::default()
            }],
        })
        .await
        .unwrap();
    let (status, pulled) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/events-sub:pull",
        json!({"maxMessages": 10}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        pulled["receivedMessages"][0]["message"]["data"],
        BASE64.encode(b"from-grpc")
    );
}

#[tokio::test]
async fn grpc_snapshot_can_be_sought_through_rest_into_a_new_subscription() {
    let address = start().await;
    let mut publisher = PublisherClient::new(grpc_channel(address).await);
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    publisher
        .create_topic(pb::Topic {
            name: "projects/demo-app/topics/events".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    subscriber
        .create_subscription(pb::Subscription {
            name: "projects/demo-app/subscriptions/source".to_owned(),
            topic: "projects/demo-app/topics/events".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    publisher
        .publish(pb::PublishRequest {
            topic: "projects/demo-app/topics/events".to_owned(),
            messages: vec![pb::PubsubMessage {
                data: b"captured".to_vec(),
                ..Default::default()
            }],
        })
        .await
        .unwrap();
    let snapshot = subscriber
        .create_snapshot(pb::CreateSnapshotRequest {
            name: "projects/demo-app/snapshots/checkpoint".to_owned(),
            subscription: "projects/demo-app/subscriptions/source".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .name;
    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/replay",
        json!({"topic": "projects/demo-app/topics/events"}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/replay:seek",
        json!({"snapshot": snapshot}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, pulled) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/replay:pull",
        json!({"maxMessages": 10}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(pulled["receivedMessages"].as_array().unwrap().len(), 1);
    assert_eq!(
        pulled["receivedMessages"][0]["message"]["data"],
        BASE64.encode(b"captured")
    );
}
