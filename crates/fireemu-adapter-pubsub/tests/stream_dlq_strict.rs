//! Recorded STREAM-DLQ response shapes, with explicit emulator controls and owned teardown.
use fireemu_adapter_pubsub::{
    serve_pubsub, BridgeMessage, PubSubHandle, PubSubProfile, TopicDelivery, TopicDeliveryError,
    TopicDeliveryReservation,
};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
use pb::subscriber_client::SubscriberClient;
use prost::Message as _;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    address: std::net::SocketAddr,
    handle: PubSubHandle,
    clock: Arc<Mutex<VirtualClock>>,
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
        Self::with_bridge(profile, None).await
    }
    async fn with_bridge(profile: PubSubProfile, bridge: Option<Arc<dyn TopicDelivery>>) -> Self {
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(
            1_700_000_000_123_000_000,
        ))));
        let handle = PubSubHandle::new(
            Arc::new(Mutex::new(PubSubState::new(42))),
            Arc::clone(&clock),
            bridge,
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
            clock,
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

struct CommittedBridge {
    committed: Arc<Mutex<Vec<BridgeMessage>>>,
}
struct BridgeReservation {
    committed: Arc<Mutex<Vec<BridgeMessage>>>,
    messages: Vec<BridgeMessage>,
}
impl TopicDeliveryReservation for BridgeReservation {
    fn commit(self: Box<Self>) {
        self.committed.lock().unwrap().extend(self.messages);
    }
}
impl TopicDelivery for CommittedBridge {
    fn reserve(
        &self,
        topic: &str,
        messages: &[BridgeMessage],
    ) -> Result<Box<dyn TopicDeliveryReservation>, TopicDeliveryError> {
        assert_eq!(topic, TOPIC);
        assert!(self.committed.lock().unwrap().is_empty());
        Ok(Box::new(BridgeReservation {
            committed: Arc::clone(&self.committed),
            messages: messages.to_vec(),
        }))
    }
}

#[tokio::test]
async fn strict_functions_bridge_matches_published_identity_without_changing_broker_ids() {
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        let committed = Arc::new(Mutex::new(Vec::new()));
        let bridge = Arc::new(CommittedBridge {
            committed: Arc::clone(&committed),
        });
        let server = Server::with_bridge(profile, Some(bridge)).await;
        resources(&server).await;
        let messages = (0..3)
            .map(|index| pb::PubsubMessage {
                data: vec![index],
                attributes: [("tag".into(), index.to_string())].into(),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let published = PublisherClient::new(server.channel().await)
            .publish(pb::PublishRequest {
                topic: TOPIC.into(),
                messages,
            })
            .await
            .unwrap()
            .into_inner();
        let committed = committed.lock().unwrap();
        assert_eq!(committed.len(), 3);
        let internal = server
            .handle
            .pull(
                &fireemu_core_pubsub::SubscriptionName::parse(SUB).unwrap(),
                3,
            )
            .unwrap();
        assert_eq!(internal.len(), 3);
        for (index, (event, stored)) in committed.iter().zip(internal.iter()).enumerate() {
            assert_eq!(event.message.message_id, published.message_ids[index]);
            assert_eq!(stored.message.message_id, (index + 1).to_string());
            assert_eq!(event.message.message, stored.message.message);
            assert_eq!(event.message.publish_time, stored.message.publish_time);
            assert_eq!(
                event.message.message.data,
                vec![u8::try_from(index).unwrap()]
            );
            if profile == PubSubProfile::Emulator {
                assert!(Arc::ptr_eq(&event.message, &stored.message));
            } else {
                assert!(!Arc::ptr_eq(&event.message, &stored.message));
                assert_eq!(event.message.message_id.len(), 17);
            }
        }
    }
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
        let listed = client
            .list_subscriptions(pb::ListSubscriptionsRequest {
                project: "projects/demo-oracle-masks0".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            listed.subscriptions[0]
                .push_config
                .as_ref()
                .unwrap()
                .attributes,
            config.attributes
        );
        let (_, bytes) = server.rest("GET", &format!("/v1/{SUB}"), json!({})).await;
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["pushConfig"]["attributes"],
            json!({"x-goog-version":"v1"})
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
    assert_eq!(
        response.subscription_properties,
        Some(pb::streaming_pull_response::SubscriptionProperties::default())
    );
    let ack = response.received_messages[0].ack_id.clone();
    assert_eq!(ack.len(), 190);
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

struct OwnedPushReceiver(tokio::task::JoinHandle<Value>);
impl Drop for OwnedPushReceiver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl OwnedPushReceiver {
    async fn new() -> (Self, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let callback = Self(tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 1024];
            let (start, length) = loop {
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
                assert!(bytes.len() < 1_000_000);
                if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = std::str::from_utf8(&bytes[..i]).unwrap();
                    let len = header
                        .lines()
                        .find_map(|l| {
                            l.split_once(':')
                                .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                                .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (i + 4, len);
                }
            };
            while bytes.len() < start + length {
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
            }
            let body = serde_json::from_slice(&bytes[start..start + length]).unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            body
        }));
        (callback, address)
    }
}
async fn create_loopback_push_subscription(server: &Server, address: std::net::SocketAddr) {
    SubscriberClient::new(server.channel().await)
        .create_subscription(pb::Subscription {
            name: format!("{SUB}-push"),
            topic: TOPIC.into(),
            push_config: Some(pb::PushConfig {
                push_endpoint: format!("http://{address}/push"),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
}
#[tokio::test]
async fn strict_native_publication_pull_and_loopback_push_share_one_wire_identity() {
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        let server = Server::new(profile).await;
        resources(&server).await;
        let (mut callback, address) = OwnedPushReceiver::new().await;
        create_loopback_push_subscription(&server, address).await;
        let published = PublisherClient::new(server.channel().await)
            .publish(pb::PublishRequest {
                topic: TOPIC.into(),
                messages: vec![pb::PubsubMessage {
                    data: b"x".to_vec(),
                    ..Default::default()
                }],
            })
            .await
            .unwrap()
            .into_inner();
        let id = &published.message_ids[0];
        assert_eq!(
            id.len(),
            if profile == PubSubProfile::Strict {
                17
            } else {
                1
            }
        );
        let pushed = tokio::time::timeout(Duration::from_secs(2), &mut callback.0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pushed["message"]["messageId"], id.as_str());
        let received = SubscriberClient::new(server.channel().await)
            .pull(pb::PullRequest {
                subscription: SUB.into(),
                max_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        let message = received.received_messages[0].message.as_ref().unwrap();
        assert_eq!(message.message_id, *id);
        assert_eq!(message.data, b"x");
        let mut client = SubscriberClient::new(server.channel().await);
        client
            .modify_ack_deadline(pb::ModifyAckDeadlineRequest {
                subscription: SUB.into(),
                ack_ids: vec![received.received_messages[0].ack_id.clone()],
                ack_deadline_seconds: 0,
            })
            .await
            .unwrap();
        let redelivery = client
            .pull(pb::PullRequest {
                subscription: SUB.into(),
                max_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(redelivery.received_messages.len(), 1);
        assert_eq!(
            redelivery.received_messages[0]
                .message
                .as_ref()
                .unwrap()
                .message_id,
            *id
        );
        client
            .acknowledge(pb::AcknowledgeRequest {
                subscription: SUB.into(),
                ack_ids: vec![redelivery.received_messages[0].ack_id.clone()],
            })
            .await
            .unwrap();
        server
            .clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(11))
            .unwrap();
        assert!(client
            .pull(pb::PullRequest {
                subscription: SUB.into(),
                max_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .received_messages
            .is_empty());
    }
}

#[tokio::test]
async fn streaming_properties_follow_profile_and_subscription_configuration() {
    // Exhaust the two profile and two ordering states; only unordered strict is a production claim.
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        for ordered in [false, true] {
            let server = Server::new(profile).await;
            resources(&server).await;
            let name = format!("{SUB}-properties");
            let mut client = SubscriberClient::new(server.channel().await);
            client
                .create_subscription(pb::Subscription {
                    name: name.clone(),
                    topic: TOPIC.into(),
                    enable_message_ordering: ordered,
                    ..Default::default()
                })
                .await
                .unwrap();
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
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tx.send(pb::StreamingPullRequest {
                subscription: name,
                stream_ack_deadline_seconds: 10,
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
            let expected = (profile == PubSubProfile::Strict).then_some(
                pb::streaming_pull_response::SubscriptionProperties {
                    exactly_once_delivery_enabled: false,
                    message_ordering_enabled: ordered,
                },
            );
            assert_eq!(response.subscription_properties, expected);
            drop(stream);
            drop(tx);
        }
    }
}

#[tokio::test]
#[allow(deprecated, clippy::too_many_lines)]
async fn strict_stream_ack_has_recorded_layout_and_cross_route_decode() {
    let server = Server::new(PubSubProfile::Strict).await;
    *server.clock.lock().unwrap() =
        VirtualClock::new(LogicalInstant::from_nanos(1_700_000_000_350_000_000));
    resources(&server).await;
    PublisherClient::new(server.channel().await)
        .publish(pb::PublishRequest {
            topic: TOPIC.into(),
            messages: vec![pb::PubsubMessage {
                data: vec![b'x'; 28],
                ..Default::default()
            }],
        })
        .await
        .unwrap();
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
    let mut client = SubscriberClient::new(server.channel().await);
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
    let received = &response.received_messages[0];
    assert_eq!(received.ack_id.len(), 190);
    assert_eq!(received.message.as_ref().unwrap().message_id.len(), 17);
    assert_eq!(response.encoded_len(), 263);
    assert_eq!(
        response.subscription_properties,
        Some(pb::streaming_pull_response::SubscriptionProperties::default())
    );
    let path = format!("/v1/{SUB}:modifyAckDeadline");
    assert_eq!(
        server
            .rest(
                "POST",
                &path,
                json!({"ackIds":[received.ack_id],"ackDeadlineSeconds":60})
            )
            .await
            .0,
        200
    );
    drop(tx);
    drop(stream);
    server
        .clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(11))
        .unwrap();
    assert!(client
        .pull(pb::PullRequest {
            subscription: SUB.into(),
            return_immediately: true,
            max_messages: 1
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages
        .is_empty());
    assert_eq!(
        server
            .rest(
                "POST",
                &format!("/v1/{SUB}:acknowledge"),
                json!({"ackIds":[received.ack_id]})
            )
            .await
            .0,
        200
    );
    server
        .clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(60))
        .unwrap();
    assert!(client
        .pull(pb::PullRequest {
            subscription: SUB.into(),
            return_immediately: true,
            max_messages: 1
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages
        .is_empty());
}

async fn pagination_resources(server: &Server) {
    let mut publisher = PublisherClient::new(server.channel().await);
    let mut subscriber = SubscriberClient::new(server.channel().await);
    for i in 0..3 {
        let topic = format!("projects/demo-paging/topics/topic{i}");
        let sub = format!("projects/demo-paging/subscriptions/sub{i}");
        publisher
            .create_topic(pb::Topic {
                name: topic.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        subscriber
            .create_subscription(pb::Subscription {
                name: sub.clone(),
                topic: "projects/demo-paging/topics/topic0".into(),
                ack_deadline_seconds: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        subscriber
            .create_snapshot(pb::CreateSnapshotRequest {
                name: format!("projects/demo-paging/snapshots/snap{i}"),
                subscription: sub,
                ..Default::default()
            })
            .await
            .unwrap();
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn strict_pagination_all_rest_and_native_lists_and_emulator_controls() {
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        let server = Server::new(profile).await;
        pagination_resources(&server).await;
        let mut publisher = PublisherClient::new(server.channel().await);
        let mut subscriber = SubscriberClient::new(server.channel().await);
        let expected_count = if profile == PubSubProfile::Strict {
            1
        } else {
            3
        };
        let topics = publisher
            .list_topics(pb::ListTopicsRequest {
                project: "projects/demo-paging".into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(topics.topics.len(), expected_count);
        assert_eq!(
            topics.next_page_token.len(),
            if profile == PubSubProfile::Strict {
                26
            } else {
                0
            }
        );
        let subs = subscriber
            .list_subscriptions(pb::ListSubscriptionsRequest {
                project: "projects/demo-paging".into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(subs.subscriptions.len(), expected_count);
        let topic_subs = publisher
            .list_topic_subscriptions(pb::ListTopicSubscriptionsRequest {
                topic: "projects/demo-paging/topics/topic0".into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(topic_subs.subscriptions.len(), expected_count);
        assert_eq!(topic_subs.next_page_token, subs.next_page_token);
        let snaps = subscriber
            .list_snapshots(pb::ListSnapshotsRequest {
                project: "projects/demo-paging".into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(snaps.snapshots.len(), expected_count);
        let topic_snaps = publisher
            .list_topic_snapshots(pb::ListTopicSnapshotsRequest {
                topic: "projects/demo-paging/topics/topic0".into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(topic_snaps.snapshots.len(), expected_count);
        for (route, member) in [
            ("topics", "topics"),
            ("subscriptions", "subscriptions"),
            ("snapshots", "snapshots"),
            ("topics/topic0/subscriptions", "subscriptions"),
            ("topics/topic0/snapshots", "snapshots"),
        ] {
            let (status, bytes) = server
                .rest(
                    "GET",
                    &format!("/v1/projects/demo-paging/{route}?pageSize=1"),
                    json!({}),
                )
                .await;
            if profile == PubSubProfile::Emulator && route.contains('/') {
                assert_eq!(status, 404);
                continue;
            }
            assert_eq!(status, 200, "{route}");
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                body[member].as_array().unwrap().len(),
                expected_count,
                "{route}"
            );
            if profile == PubSubProfile::Strict {
                let token = body["nextPageToken"].as_str().unwrap();
                assert_eq!(token.len(), 26);
                let (_, next_bytes) = server
                    .rest(
                        "GET",
                        &format!("/v1/projects/demo-paging/{route}?pageSize=1&pageToken={token}"),
                        json!({}),
                    )
                    .await;
                let next: Value = serde_json::from_slice(&next_bytes).unwrap();
                assert_eq!(next[member].as_array().unwrap().len(), 1, "{route}");
                assert_ne!(next[member][0], body[member][0], "{route}");
                assert_ne!(next["nextPageToken"], body["nextPageToken"], "{route}");
            }
        }
        for size in [-1, 1001] {
            let result = publisher
                .list_topics(pb::ListTopicsRequest {
                    project: "projects/demo-paging".into(),
                    page_size: size,
                    ..Default::default()
                })
                .await;
            let (status, bytes) = server
                .rest(
                    "GET",
                    &format!("/v1/projects/demo-paging/topics?pageSize={size}"),
                    json!({}),
                )
                .await;
            if profile == PubSubProfile::Strict {
                let message=format!("The value for page_size is out of bounds. You passed {size} in the request, but the value must be between 0 and 1000.");
                assert_eq!(result.unwrap_err().message(), message);
                assert_eq!(status, 400);
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap()["error"]["message"],
                    message
                );
            } else {
                assert_eq!(result.unwrap().into_inner().topics.len(), 3);
                assert_eq!(status, 200);
            }
        }
        let result = publisher
            .list_topics(pb::ListTopicsRequest {
                project: "projects/demo-paging".into(),
                page_size: 1,
                page_token: "garbage".into(),
            })
            .await;
        if profile == PubSubProfile::Strict {
            assert_eq!(
                result.unwrap_err().message(),
                "Invalid page token given (token=garbage)."
            );
        } else {
            assert_eq!(result.unwrap().into_inner().topics.len(), 3);
        }
        let all = publisher
            .list_topics(pb::ListTopicsRequest {
                project: "projects/demo-paging".into(),
                page_size: 0,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(all.topics.len(), 3);
        assert!(all.next_page_token.is_empty());
    }
}

#[tokio::test]
async fn strict_deleted_issued_cursor_continues_across_transport_and_empty_snapshots_omit_members()
{
    let server = Server::new(PubSubProfile::Strict).await;
    pagination_resources(&server).await;
    let mut publisher = PublisherClient::new(server.channel().await);
    let first = publisher
        .list_topics(pb::ListTopicsRequest {
            project: "projects/demo-paging".into(),
            page_size: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.topics.len(), 1);
    publisher
        .delete_topic(pb::DeleteTopicRequest {
            topic: first.topics[0].name.clone(),
        })
        .await
        .unwrap();
    let (status, bytes) = server
        .rest(
            "GET",
            &format!(
                "/v1/projects/demo-paging/topics?pageSize=1&pageToken={}",
                first.next_page_token
            ),
            json!({}),
        )
        .await;
    assert_eq!(status, 200);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["topics"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["topics"][0]["name"],
        "projects/demo-paging/topics/topic1"
    );
    assert_eq!(body["nextPageToken"].as_str().unwrap().len(), 26);
    let second = publisher
        .list_topics(pb::ListTopicsRequest {
            project: "projects/demo-paging".into(),
            page_size: 1,
            page_token: body["nextPageToken"].as_str().unwrap().into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second.topics.len(), 1);
    assert_eq!(second.topics[0].name, "projects/demo-paging/topics/topic2");
    assert!(second.next_page_token.is_empty());
    let (status, bytes) = server
        .rest(
            "GET",
            "/v1/projects/empty-project/snapshots?pageSize=1",
            json!({}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), json!({}));
}

#[tokio::test]
async fn strict_list_resource_defaults_use_the_recorded_empty_label_omission() {
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        let server = Server::new(profile).await;
        pagination_resources(&server).await;
        for (kind, member) in [("topics", "topics"), ("snapshots", "snapshots")] {
            let (status, bytes) = server
                .rest(
                    "GET",
                    &format!("/v1/projects/demo-paging/{kind}?pageSize=1"),
                    json!({}),
                )
                .await;
            assert_eq!(status, 200);
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            let first = &body[member][0];
            if profile == PubSubProfile::Strict {
                assert!(first.get("labels").is_none(), "{kind}");
            } else {
                assert_eq!(first["labels"], json!({}));
            }
        }
        server
            .rest(
                "PUT",
                "/v1/projects/demo-paging/topics/labelled",
                json!({"labels":{"label":"value"}}),
            )
            .await;
        let (_, bytes) = server
            .rest("GET", "/v1/projects/demo-paging/topics", json!({}))
            .await;
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["topics"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == "projects/demo-paging/topics/labelled")
                .unwrap()["labels"],
            json!({"label":"value"})
        );
    }
}

async fn forwarding_resources(server: &Server) -> (String, String, String) {
    let project = "demo-oracle-masks0";
    let source_topic = format!("projects/{project}/topics/source-topic");
    let sink_topic = format!("projects/{project}/topics/sink-topic");
    let source = format!("projects/{project}/subscriptions/source-sub");
    let sink = format!("projects/{project}/subscriptions/sink-sub");
    for topic in [&source_topic, &sink_topic] {
        assert_eq!(
            server
                .rest("PUT", &format!("/v1/{topic}"), json!({}))
                .await
                .0,
            200
        );
    }
    for (name, body) in [
        (
            &source,
            json!({"topic":source_topic,"ackDeadlineSeconds":10,"deadLetterPolicy":{"deadLetterTopic":sink_topic,"maxDeliveryAttempts":5}}),
        ),
        (&sink, json!({"topic":sink_topic,"ackDeadlineSeconds":10})),
    ] {
        assert_eq!(
            server.rest("PUT", &format!("/v1/{name}"), body).await.0,
            200
        );
    }
    (source_topic, source, sink)
}

async fn nack_five_deliveries_over_rest(server: &Server, source: &str) {
    for _ in 0..5 {
        let (status, bytes) = server
            .rest(
                "POST",
                &format!("/v1/{source}:pull"),
                json!({"maxMessages":1,"returnImmediately":true}),
            )
            .await;
        assert_eq!(status, 200);
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let ack = body["receivedMessages"][0]["ackId"].as_str().unwrap();
        assert_eq!(
            server
                .rest(
                    "POST",
                    &format!("/v1/{source}:modifyAckDeadline"),
                    json!({"ackIds":[ack],"ackDeadlineSeconds":0})
                )
                .await
                .0,
            200
        );
    }
}

#[tokio::test]
async fn forwarded_identity_attributes_follow_the_recorded_strict_shape_only() {
    // The paired sink receipts are run1/run2 n114; values remain causal, not fixture literals.
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        let server = Server::new(profile).await;
        let project = "demo-oracle-masks0";
        let (source_topic, source, sink) = forwarding_resources(&server).await;
        let original_attributes = json!({"recorderRun":"000000000001","user":"keep"});
        let (status, published) = server
            .rest(
                "POST",
                &format!("/v1/{source_topic}:publish"),
                json!({"messages":[{"data":"b3JpZ2luYWw=","attributes":original_attributes}]}),
            )
            .await;
        assert_eq!(status, 200);
        let published: Value = serde_json::from_slice(&published).unwrap();
        nack_five_deliveries_over_rest(&server, &source).await;
        // This triggers the existing local transfer decision; no production timing claim.
        assert_eq!(
            server
                .rest(
                    "POST",
                    &format!("/v1/{source}:pull"),
                    json!({"maxMessages":1,"returnImmediately":true})
                )
                .await
                .0,
            200
        );
        let mut client = SubscriberClient::new(server.channel().await);
        let delivered = client
            .pull(pb::PullRequest {
                subscription: sink.clone(),
                max_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(delivered.received_messages.len(), 1);
        let received = &delivered.received_messages[0];
        let message = received.message.as_ref().unwrap();
        assert_eq!(message.data, b"original");
        assert_ne!(
            message.message_id,
            published["messageIds"][0].as_str().unwrap()
        );
        assert_eq!(message.attributes["recorderRun"], "000000000001");
        assert_eq!(message.attributes["user"], "keep");
        if profile == PubSubProfile::Strict {
            assert_eq!(message.message_id.len(), 17);
            assert!(message.message_id.bytes().all(|b| b.is_ascii_digit()));
            assert_eq!(
                message.attributes["CloudPubSubDeadLetterSourceSubscription"],
                "source-sub"
            );
            assert_eq!(
                message.attributes["CloudPubSubDeadLetterSourceSubscriptionProject"],
                project
            );
            assert_eq!(
                message.attributes["CloudPubSubDeadLetterSourceTopicPublishTime"],
                "2023-11-14T22:13:20.123+00:00"
            );
            assert_eq!(
                message.attributes["CloudPubSubDeadLetterSourceDeliveryCount"],
                "5"
            );
            assert_eq!(message.attributes.len(), 6);
        } else {
            assert_eq!(message.attributes.len(), 2);
        }
        client
            .acknowledge(pb::AcknowledgeRequest {
                subscription: sink.clone(),
                ack_ids: vec![received.ack_id.clone()],
            })
            .await
            .unwrap();
        assert!(client
            .pull(pb::PullRequest {
                subscription: sink,
                max_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .received_messages
            .is_empty());
    }
}

#[test]
fn paired_recorded_sink_bodies_replay_through_the_forward_metadata_generator() {
    use base64::Engine as _;
    use fireemu_core_pubsub::{PubsubMessage, StoredMessage, SubscriptionName};
    let fixture: Value = serde_json::from_str(include_str!("../../../conformance/src/pubsub-production/fixtures/stream-dlq-normalization-recorded.json")).unwrap();
    for capture in fixture["captures"].as_array().unwrap() {
        let row = |n| {
            capture
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["n"] == n)
                .unwrap()
        };
        let source_row = row(100);
        let source_message = &source_row["response"]["body"]["receivedMessages"][0]["message"];
        let expected = &row(114)["response"]["body"]["receivedMessages"][0]["message"];
        let source = StoredMessage {
            message_id: source_message["messageId"].as_str().unwrap().into(),
            publish_time: LogicalInstant::parse_rfc3339(
                source_message["publishTime"].as_str().unwrap(),
            )
            .unwrap(),
            message: PubsubMessage {
                data: base64::engine::general_purpose::STANDARD
                    .decode(source_message["data"].as_str().unwrap())
                    .unwrap(),
                attributes: source_message["attributes"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
                    .collect(),
                ordering_key: source_message["orderingKey"].as_str().unwrap_or("").into(),
            },
        };
        let path = source_row["request"]["path"].as_str().unwrap();
        let subscription = SubscriptionName::parse(
            path.strip_prefix("/v1/")
                .unwrap()
                .strip_suffix(":pull")
                .unwrap(),
        )
        .unwrap();
        let count = expected["attributes"]["CloudPubSubDeadLetterSourceDeliveryCount"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let generated =
            fireemu_core_pubsub::dead_letter::forwarded_message(&source, &subscription, count)
                .unwrap();
        assert_eq!(
            serde_json::to_value(&generated.attributes).unwrap(),
            expected["attributes"]
        );
        assert_eq!(
            generated.data,
            base64::engine::general_purpose::STANDARD
                .decode(expected["data"].as_str().unwrap())
                .unwrap()
        );
        let recorded_ack = row(80)["response"]["body"]["receivedMessages"][0]["ackId"]
            .as_str()
            .unwrap();
        assert_eq!(recorded_ack.len(), 195);
        assert!(recorded_ack
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }
}

#[tokio::test]
async fn valid_publish_boundaries_forward_without_loosening_public_admission() {
    use fireemu_core_pubsub::message::{MAX_ATTRIBUTES, MAX_DATA_BYTES};
    use fireemu_core_pubsub::{PubsubMessage, SubscriptionName, TopicName};
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        for attribute_boundary in [true, false] {
            let server = Server::new(profile).await;
            let (topic, source, sink) = forwarding_resources(&server).await;
            let message = PubsubMessage {
                data: if attribute_boundary {
                    b"valid".to_vec()
                } else {
                    vec![b'x'; MAX_DATA_BYTES]
                },
                attributes: if attribute_boundary {
                    (0..MAX_ATTRIBUTES)
                        .map(|i| (format!("user{i}"), "value".to_owned()))
                        .collect()
                } else {
                    std::collections::BTreeMap::default()
                },
                ..Default::default()
            };
            assert!(message.validate().is_ok());
            let published = server
                .handle
                .publish(&TopicName::parse(&topic).unwrap(), vec![message.clone()])
                .unwrap();
            let source_name = SubscriptionName::parse(&source).unwrap();
            for _ in 0..5 {
                let pulled = server.handle.pull(&source_name, 1).unwrap();
                assert_eq!(pulled.len(), 1);
                assert_eq!(
                    server
                        .rest(
                            "POST",
                            &format!("/v1/{source}:modifyAckDeadline"),
                            json!({"ackIds":[pulled[0].ack_id],"ackDeadlineSeconds":0})
                        )
                        .await
                        .0,
                    200
                );
            }
            assert!(server.handle.pull(&source_name, 1).unwrap().is_empty());
            let delivered = server
                .handle
                .pull(&SubscriptionName::parse(&sink).unwrap(), 1)
                .unwrap();
            assert_eq!(delivered.len(), 1);
            let forwarded = &delivered[0].message;
            assert_eq!(forwarded.message.data, message.data);
            assert_ne!(forwarded.message_id, published[0].message_id);
            for (key, value) in &message.attributes {
                assert_eq!(forwarded.message.attributes[key], *value);
            }
            if profile == PubSubProfile::Strict {
                assert_eq!(
                    forwarded.message.attributes.len(),
                    message.attributes.len() + 4
                );
                assert!(forwarded.message.validate().is_err());
                assert!(server
                    .handle
                    .publish(
                        &TopicName::parse(&topic).unwrap(),
                        vec![forwarded.message.clone()]
                    )
                    .is_err());
            } else {
                assert_eq!(forwarded.message.attributes, message.attributes);
            }
            // ACK invokes the normal pending-transfer retry path; it must not duplicate the transfer.
            assert_eq!(
                server
                    .rest(
                        "POST",
                        &format!("/v1/{sink}:acknowledge"),
                        json!({"ackIds":[delivered[0].ack_id]})
                    )
                    .await
                    .0,
                200
            );
            assert!(server.handle.pull(&source_name, 1).unwrap().is_empty());
            assert!(server
                .handle
                .pull(&SubscriptionName::parse(&sink).unwrap(), 1)
                .unwrap()
                .is_empty());
        }
    }
}

fn compact_alias(ack: &str, profile: PubSubProfile) -> String {
    use base64::Engine as _;
    let seed = if profile == PubSubProfile::Strict {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(ack)
            .unwrap();
        u64::from_be_bytes(bytes[..8].try_into().unwrap())
    } else {
        u64::from_str_radix(ack.strip_prefix("ack-").unwrap(), 16).unwrap()
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(fireemu_core_pubsub::wire_ack::encode_compact_unary(seed))
}

async fn control_ack(server: &Server, native: bool, operation: &str, ack: &str, seconds: i32) {
    if native {
        let mut client = SubscriberClient::new(server.channel().await);
        if operation == "acknowledge" {
            client
                .acknowledge(pb::AcknowledgeRequest {
                    subscription: SUB.into(),
                    ack_ids: vec![ack.into()],
                })
                .await
                .unwrap();
        } else {
            client
                .modify_ack_deadline(pb::ModifyAckDeadlineRequest {
                    subscription: SUB.into(),
                    ack_ids: vec![ack.into()],
                    ack_deadline_seconds: seconds,
                })
                .await
                .unwrap();
        }
    } else {
        let body = if operation == "acknowledge" {
            json!({"ackIds":[ack]})
        } else {
            json!({"ackIds":[ack],"ackDeadlineSeconds":seconds})
        };
        assert_eq!(
            server
                .rest("POST", &format!("/v1/{SUB}:{operation}"), body)
                .await
                .0,
            200
        );
    }
}

#[tokio::test]
async fn compact_ack_controls_follow_causal_rest_native_effects_and_emulator_control() {
    use base64::Engine as _;
    use fireemu_core_pubsub::{PubsubMessage, SubscriptionName, TopicName};
    for profile in [PubSubProfile::Strict, PubSubProfile::Emulator] {
        for native in [false, true] {
            let server = Server::new(profile).await;
            resources(&server).await;
            server
                .handle
                .publish(
                    &TopicName::parse(TOPIC).unwrap(),
                    vec![PubsubMessage {
                        data: b"causal".to_vec(),
                        ..Default::default()
                    }],
                )
                .unwrap();
            let sub = SubscriptionName::parse(SUB).unwrap();
            let first = server.handle.pull(&sub, 1).unwrap();
            let seed =
                u64::from_str_radix(first[0].ack_id.strip_prefix("ack-").unwrap(), 16).unwrap();
            let compact = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(fireemu_core_pubsub::wire_ack::encode_compact_unary(seed));
            let mut altered = compact.clone().into_bytes();
            altered[12] = if altered[12] == b'A' { b'B' } else { b'A' };
            for invalid in [
                String::from_utf8(altered).unwrap(),
                compact[..compact.len() - 1].to_owned(),
            ] {
                control_ack(&server, native, "acknowledge", &invalid, 0).await;
            }
            let compact = if profile == PubSubProfile::Strict {
                control_ack(&server, native, "modifyAckDeadline", &compact, 0).await;
                let still_owned = server.handle.pull(&sub, 1).unwrap();
                assert_eq!(still_owned.len(), 1);
                assert_eq!(
                    still_owned[0].message.message_id,
                    first[0].message.message_id
                );
                compact_alias(&still_owned[0].ack_id, PubSubProfile::Emulator)
            } else {
                compact
            };
            control_ack(&server, native, "modifyAckDeadline", &compact, 60).await;
            server
                .clock
                .lock()
                .unwrap()
                .advance(LogicalDuration::from_seconds(11))
                .unwrap();
            let replayed = server.handle.pull(&sub, 1).unwrap();
            if profile == PubSubProfile::Strict {
                assert!(replayed.is_empty());
                control_ack(&server, !native, "acknowledge", &compact, 0).await;
                server
                    .clock
                    .lock()
                    .unwrap()
                    .advance(LogicalDuration::from_seconds(60))
                    .unwrap();
                assert!(server.handle.pull(&sub, 1).unwrap().is_empty());
            } else {
                assert_eq!(replayed.len(), 1);
                assert_eq!(replayed[0].message.message.data, b"causal");
                control_ack(&server, !native, "acknowledge", &replayed[0].ack_id, 0).await;
            }
        }
    }
}

#[tokio::test]
async fn compact_stream_deadline_control_redelivers_the_bound_message() {
    let server = Server::new(PubSubProfile::Strict).await;
    resources(&server).await;
    PublisherClient::new(server.channel().await)
        .publish(pb::PublishRequest {
            topic: TOPIC.into(),
            messages: vec![pb::PubsubMessage {
                data: b"stream-causal".to_vec(),
                ..Default::default()
            }],
        })
        .await
        .unwrap();
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
    let mut client = SubscriberClient::new(server.channel().await);
    let mut stream = client
        .streaming_pull(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();
    let first = tokio::time::timeout(Duration::from_secs(2), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let original = &first.received_messages[0];
    assert_eq!(original.ack_id.len(), 190);
    let alias = compact_alias(&original.ack_id, PubSubProfile::Strict);
    assert_eq!(alias.len(), 195);
    tx.send(pb::StreamingPullRequest {
        modify_deadline_ack_ids: vec![alias],
        modify_deadline_seconds: vec![0],
        ..Default::default()
    })
    .await
    .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = &second.received_messages[0];
    assert_eq!(repeated.message, original.message);
    assert_ne!(repeated.ack_id, original.ack_id);
    let fresh = compact_alias(&repeated.ack_id, PubSubProfile::Strict);
    control_ack(&server, true, "acknowledge", &fresh, 0).await;
    drop(tx);
    drop(stream);
    server
        .clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(11))
        .unwrap();
    assert!(server
        .handle
        .pull(
            &fireemu_core_pubsub::SubscriptionName::parse(SUB).unwrap(),
            1
        )
        .unwrap()
        .is_empty());
}

fn exhaust_by_deadline(server: &Server, subscription: &str) {
    let name = fireemu_core_pubsub::SubscriptionName::parse(subscription).unwrap();
    for _ in 0..5 {
        assert_eq!(server.handle.pull(&name, 1).unwrap().len(), 1);
        server
            .clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(11))
            .unwrap();
    }
    assert!(server.handle.pull(&name, 1).unwrap().is_empty());
}

#[tokio::test]
async fn attributed_boundary_message_can_forward_again_from_its_retained_source() {
    use fireemu_core_pubsub::{PubsubMessage, SubscriptionName, TopicName};
    let server = Server::new(PubSubProfile::Strict).await;
    let (topic, source, sink) = forwarding_resources(&server).await;
    let final_topic = "projects/demo-oracle-masks0/topics/final-topic";
    let final_sub = "projects/demo-oracle-masks0/subscriptions/final-sub";
    assert_eq!(
        server
            .rest("PUT", &format!("/v1/{final_topic}"), json!({}))
            .await
            .0,
        200
    );
    assert_eq!(
        server
            .rest(
                "PUT",
                &format!("/v1/{final_sub}"),
                json!({"topic":final_topic,"ackDeadlineSeconds":10})
            )
            .await
            .0,
        200
    );
    assert_eq!(
        server
            .rest("DELETE", &format!("/v1/{sink}"), json!({}))
            .await
            .0,
        200
    );
    assert_eq!(server.rest("PUT",&format!("/v1/{sink}"),json!({"topic":"projects/demo-oracle-masks0/topics/sink-topic","ackDeadlineSeconds":10,"deadLetterPolicy":{"deadLetterTopic":final_topic,"maxDeliveryAttempts":5}})).await.0,200);
    let original = PubsubMessage {
        data: b"twice".to_vec(),
        attributes: (0..100)
            .map(|i| (format!("user{i}"), "keep".into()))
            .collect(),
        ..Default::default()
    };
    assert!(original.validate().is_ok());
    server
        .handle
        .publish(&TopicName::parse(&topic).unwrap(), vec![original.clone()])
        .unwrap();
    exhaust_by_deadline(&server, &source);
    exhaust_by_deadline(&server, &sink);
    let final_name = SubscriptionName::parse(final_sub).unwrap();
    let delivered = server.handle.pull(&final_name, 1).unwrap();
    assert_eq!(delivered.len(), 1);
    let message = &delivered[0].message.message;
    assert_eq!(message.data, original.data);
    assert_eq!(message.attributes.len(), 104);
    for (key, value) in &original.attributes {
        assert_eq!(message.attributes[key], *value);
    }
    assert_eq!(
        message.attributes["CloudPubSubDeadLetterSourceSubscription"],
        "sink-sub"
    );
    assert!(server
        .handle
        .pull(&SubscriptionName::parse(&source).unwrap(), 1)
        .unwrap()
        .is_empty());
    assert!(server
        .handle
        .pull(&SubscriptionName::parse(&sink).unwrap(), 1)
        .unwrap()
        .is_empty());
}
