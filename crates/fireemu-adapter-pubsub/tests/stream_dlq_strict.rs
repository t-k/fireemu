//! Recorded STREAM-DLQ response shapes, with explicit emulator controls and owned teardown.
use fireemu_adapter_pubsub::{serve_pubsub, PubSubHandle, PubSubProfile};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
use pb::subscriber_client::SubscriberClient;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    address: std::net::SocketAddr,
    handle: PubSubHandle,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.handle.cancel_push_dispatcher();
        self.task.abort();
    }
}
impl Server {
    async fn new(profile: PubSubProfile) -> Self {
        let handle = PubSubHandle::new(
            Arc::new(Mutex::new(PubSubState::new(42))),
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(
                1_700_000_000_123_000_000,
            )))),
            None,
        )
        .with_profile(profile);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cloned = handle.clone();
        let task = tokio::spawn(async move {
            serve_pubsub(listener, cloned).await.unwrap();
        });
        Self {
            address,
            handle,
            task,
        }
    }
    async fn channel(&self) -> tonic::transport::Channel {
        tonic::transport::Channel::from_shared(format!("http://{}", self.address))
            .unwrap()
            .connect()
            .await
            .unwrap()
    }
    async fn rest(&self, method: &str, path: &str, body: Value) -> (u16, Vec<u8>) {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let body = serde_json::to_vec(&body).unwrap();
        let header=format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",self.address,body.len());
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let status = std::str::from_utf8(&bytes[..split])
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, bytes[split + 4..].to_vec())
    }
}
const TOPIC: &str = "projects/demo-oracle-masks0/topics/fe000000000001-dc-r-cursor-0";
const SUB: &str = "projects/demo-oracle-masks0/subscriptions/fe000000000001-sa-g-stream-sub";
async fn resources(server: &Server) {
    let mut publisher = PublisherClient::new(server.channel().await);
    publisher
        .create_topic(pb::Topic {
            name: TOPIC.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut subscriber = SubscriberClient::new(server.channel().await);
    subscriber
        .create_subscription(pb::Subscription {
            name: SUB.into(),
            topic: TOPIC.into(),
            ack_deadline_seconds: 10,
            ..Default::default()
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn strict_recorded_topic_empty_reply_and_publication_layout_preserves_emulator() {
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        let server = Server::new(profile).await;
        let (code, bytes) = server.rest("PUT", &format!("/v1/{TOPIC}"), json!({})).await;
        assert_eq!(code, 200);
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        if profile == PubSubProfile::Strict {
            assert_eq!(body, json!({"name":TOPIC}));
            assert_eq!(bytes.len(), 80);
            assert!(bytes.ends_with(b"\n"));
        } else {
            assert_eq!(body, json!({"name":TOPIC,"labels":{}}));
            assert!(!bytes.ends_with(b"\n"));
        }
        let (code, bytes) = server
            .rest(
                "POST",
                &format!("/v1/{TOPIC}:publish"),
                json!({"messages":[{"data":"eA=="}]}),
            )
            .await;
        assert_eq!(code, 200);
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let id = body["messageIds"][0].as_str().unwrap();
        assert!(id.bytes().all(|c| c.is_ascii_digit()));
        assert_eq!(
            id.len(),
            if profile == PubSubProfile::Strict {
                17
            } else {
                1
            }
        );
        if profile == PubSubProfile::Strict {
            assert_eq!(bytes.len(), 50);
        }
        let (code, bytes) = server
            .rest("DELETE", &format!("/v1/{TOPIC}"), json!({}))
            .await;
        assert_eq!(code, 200);
        assert_eq!(
            bytes,
            if profile == PubSubProfile::Strict {
                b"{}\n".to_vec()
            } else {
                b"{}".to_vec()
            }
        );
    }
}

#[tokio::test]
async fn strict_empty_pull_and_issued_ack_wire_roundtrip_preserve_internal_identity() {
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        let server = Server::new(profile).await;
        resources(&server).await;
        let (_, bytes) = server
            .rest(
                "POST",
                &format!("/v1/{SUB}:pull"),
                json!({"maxMessages":1,"returnImmediately":true}),
            )
            .await;
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            if profile == PubSubProfile::Strict {
                json!({})
            } else {
                json!({"receivedMessages":[]})
            }
        );
        let (_, published) = server
            .rest(
                "POST",
                &format!("/v1/{TOPIC}:publish"),
                json!({"messages":[{"data":"eA=="}]}),
            )
            .await;
        let published: Value = serde_json::from_slice(&published).unwrap();
        let (_, bytes) = server
            .rest(
                "POST",
                &format!("/v1/{SUB}:pull"),
                json!({"maxMessages":1,"returnImmediately":true}),
            )
            .await;
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let received = &body["receivedMessages"][0];
        let ack = received["ackId"].as_str().unwrap();
        assert_eq!(received["message"]["messageId"], published["messageIds"][0]);
        if profile == PubSubProfile::Strict {
            assert_eq!(ack.len(), 196);
            assert!(ack
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
            assert!(received.get("deliveryAttempt").is_none());
            assert!(received["message"].get("attributes").is_none());
            assert!(received["message"].get("orderingKey").is_none());
            assert_eq!(
                received["message"]["publishTime"],
                "2023-11-14T22:13:20.123Z"
            );
        } else {
            assert!(ack.starts_with("ack-"));
            assert_eq!(received["deliveryAttempt"], 1);
        }
        let (code, _) = server
            .rest(
                "POST",
                &format!("/v1/{SUB}:acknowledge"),
                json!({"ackIds":[ack]}),
            )
            .await;
        assert_eq!(code, 200);
        let (_, bytes) = server
            .rest(
                "POST",
                &format!("/v1/{SUB}:pull"),
                json!({"maxMessages":1,"returnImmediately":true}),
            )
            .await;
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body
            .get("receivedMessages")
            .is_none_or(|v| v.as_array().unwrap().is_empty()));
    }
}

#[tokio::test]
async fn strict_recorded_invalid_ack_only_half_close_is_silent_for_thirty_seconds() {
    let server = Server::new(PubSubProfile::Strict).await;
    resources(&server).await;
    let mut subscriber = SubscriberClient::new(server.channel().await);
    let requests = tokio_stream::iter([
        pb::StreamingPullRequest {
            subscription: SUB.into(),
            stream_ack_deadline_seconds: 10,
            max_outstanding_messages: 1,
            max_outstanding_bytes: 1024,
            ..Default::default()
        },
        pb::StreamingPullRequest {
            ack_ids: vec!["invalid-ack-for-stream-observation".into()],
            ..Default::default()
        },
    ]);
    let mut response = subscriber
        .streaming_pull(requests)
        .await
        .unwrap()
        .into_inner();
    assert!(tokio::time::timeout(Duration::from_secs(30),response.message()).await.is_err(),"the recorded invalid ACK and write-side half-close must not produce a reply or terminal status during30s");
    drop(response);
}

#[tokio::test]
async fn emulator_invalid_ack_half_close_keeps_its_existing_terminal_behavior() {
    let server = Server::new(PubSubProfile::Emulator).await;
    resources(&server).await;
    let mut subscriber = SubscriberClient::new(server.channel().await);
    let requests = tokio_stream::iter([
        pb::StreamingPullRequest {
            subscription: SUB.into(),
            stream_ack_deadline_seconds: 10,
            ..Default::default()
        },
        pb::StreamingPullRequest {
            ack_ids: vec!["invalid-ack-for-stream-observation".into()],
            ..Default::default()
        },
    ]);
    let mut response = subscriber
        .streaming_pull(requests)
        .await
        .unwrap()
        .into_inner();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), response.message())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn strict_recorded_probe_does_not_generalize_to_an_additional_ack_frame() {
    let server = Server::new(PubSubProfile::Strict).await;
    resources(&server).await;
    let mut subscriber = SubscriberClient::new(server.channel().await);
    let requests = tokio_stream::iter([
        pb::StreamingPullRequest {
            subscription: SUB.into(),
            stream_ack_deadline_seconds: 10,
            max_outstanding_messages: 1,
            max_outstanding_bytes: 1024,
            ..Default::default()
        },
        pb::StreamingPullRequest {
            ack_ids: vec!["invalid-ack-for-stream-observation".into()],
            ..Default::default()
        },
        pb::StreamingPullRequest {
            ack_ids: vec!["another-unobserved-ack".into()],
            ..Default::default()
        },
    ]);
    let mut response = subscriber
        .streaming_pull(requests)
        .await
        .unwrap()
        .into_inner();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), response.message())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn strict_recorded_push_config_creation_and_stream_gate_preserve_emulator() {
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        let server = Server::new(profile).await;
        PublisherClient::new(server.channel().await)
            .create_topic(pb::Topic {
                name: TOPIC.into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut client = SubscriberClient::new(server.channel().await);
        let result = client
            .create_subscription(pb::Subscription {
                name: SUB.into(),
                topic: TOPIC.into(),
                ack_deadline_seconds: 10,
                push_config: Some(pb::PushConfig {
                    push_endpoint: "https://example.invalid/pubsub-never-published".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await;
        if profile == PubSubProfile::Emulator {
            assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
            continue;
        }
        let sub = result.unwrap().into_inner();
        let config = sub.push_config.unwrap();
        assert_eq!(
            config.push_endpoint,
            "https://example.invalid/pubsub-never-published"
        );
        assert_eq!(
            config.attributes.get("x-goog-version").map(String::as_str),
            Some("v1")
        );
        let result = client
            .streaming_pull(tokio_stream::iter([pb::StreamingPullRequest {
                subscription: SUB.into(),
                stream_ack_deadline_seconds: 10,
                ..Default::default()
            }]))
            .await;
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            status.message(),
            "This method is not supported for this subscription type."
        );
    }
}
#[tokio::test]
async fn strict_recorded_negative_stream_deadline_has_recorded_status() {
    let server = Server::new(PubSubProfile::Strict).await;
    resources(&server).await;
    PublisherClient::new(server.channel().await)
        .publish(pb::PublishRequest {
            topic: TOPIC.into(),
            messages: vec![pb::PubsubMessage {
                data: b"x".to_vec(),
                ..Default::default()
            }],
        })
        .await
        .unwrap();
    let mut client = SubscriberClient::new(server.channel().await);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(pb::StreamingPullRequest {
        subscription: SUB.into(),
        stream_ack_deadline_seconds: 10,
        max_outstanding_messages: 1,
        max_outstanding_bytes: 1024,
        ..Default::default()
    })
    .await
    .unwrap();
    let mut stream = client
        .streaming_pull(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let response = tokio::time::timeout(Duration::from_secs(2), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ack = response.received_messages[0].ack_id.clone();
    assert_eq!(ack.len(), 196);
    tx.send(pb::StreamingPullRequest {
        modify_deadline_ack_ids: vec![ack],
        modify_deadline_seconds: vec![-1],
        ..Default::default()
    })
    .await
    .unwrap();
    drop(tx);
    let status = tokio::time::timeout(Duration::from_secs(2), stream.message())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_eq!(status.message(),"Invalid ack deadline given (ack_deadline=-1). The ack deadline must be between 0 and 600 seconds.");
}

#[tokio::test]
async fn strict_recorded_push_admission_rejects_unobserved_endpoint_and_auth_shapes() {
    let server = Server::new(PubSubProfile::Strict).await;
    PublisherClient::new(server.channel().await)
        .create_topic(pb::Topic {
            name: TOPIC.into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut client = SubscriberClient::new(server.channel().await);
    for endpoint in [
        "https://example.invalid/different-path",
        "https://other.invalid/pubsub-never-published",
    ] {
        let status = client
            .create_subscription(pb::Subscription {
                name: SUB.into(),
                topic: TOPIC.into(),
                push_config: Some(pb::PushConfig {
                    push_endpoint: endpoint.into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }
    let status = client
        .create_subscription(pb::Subscription {
            name: SUB.into(),
            topic: TOPIC.into(),
            push_config: Some(pb::PushConfig {
                push_endpoint: "https://example.invalid/pubsub-never-published".into(),
                attributes: std::collections::HashMap::from([(
                    "unobserved".into(),
                    "value".into(),
                )]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
}
