//! A subscription carries the same recorded production defaults and the same stored options on both
//! transports: `pushConfig {}`, a 604800 s retention, an expiration policy of 2,678,400 s and state
//! ACTIVE unless the request set them, and no `enableMessageOrdering` unless it is true. The REST body
//! of a subscription is the proto3 JSON of the gRPC response. Explicit labels and expiration policies
//! are accepted and stored (production accepts them; the recorded bodies are in
//! docs.local/issues/open/pubsub-grpc-subscription-lacks-the-recorded-production-defaults.md).

use std::sync::{Arc, Mutex};

use fireemu_adapter_pubsub::{serve_pubsub, PubSubHandle};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::subscriber_client::SubscriberClient;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Harness {
    address: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    handle: PubSubHandle,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.handle.cancel_push_dispatcher();
        self.server.abort();
    }
}

impl Harness {
    async fn new() -> Self {
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_700_000_000),
        )));
        let state = Arc::new(Mutex::new(PubSubState::new(99)));
        let handle = PubSubHandle::new(state, clock, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            let _ = serve_pubsub(listener, server_handle).await;
        });
        Self {
            address,
            server,
            handle,
        }
    }

    async fn shutdown(mut self) {
        self.handle.shutdown_push_dispatcher().await;
        self.server.abort();
        let _ = (&mut self.server).await;
    }

    async fn grpc(&self) -> SubscriberClient<tonic::transport::Channel> {
        SubscriberClient::new(
            tonic::transport::Channel::from_shared(format!("http://{}", self.address))
                .unwrap()
                .connect()
                .await
                .unwrap(),
        )
    }

    async fn rest(&self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let body = serde_json::to_vec(&body).unwrap();
        let headers = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", self.address, body.len());
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let split = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        let status = std::str::from_utf8(&response[..split])
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (
            status,
            serde_json::from_slice(&response[split + 4..]).unwrap(),
        )
    }

    async fn topic(&self, project: &str) {
        let (status, body) = self
            .rest(
                "PUT",
                &format!("/v1/projects/{project}/topics/events"),
                json!({}),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }
}

const TOPIC: &str = "projects/demo/topics/events";
const PUSH_ENDPOINT: &str = "http://127.0.0.1:8080/push";

fn seconds(value: i64) -> prost_types::Duration {
    prost_types::Duration {
        seconds: value,
        nanos: 0,
    }
}

/// The proto3 JSON rendering of the supported parts of a subscription, as the REST transcoding of the
/// same message: zero values are omitted, `pushConfig` and `expirationPolicy` are present when set.
fn proto3_json(sub: &pb::Subscription) -> Value {
    fn duration(value: &prost_types::Duration) -> String {
        if value.nanos == 0 {
            return format!("{}s", value.seconds);
        }
        let (divisor, width) = if value.nanos % 1_000_000 == 0 {
            (1_000_000, 3)
        } else if value.nanos % 1_000 == 0 {
            (1_000, 6)
        } else {
            (1, 9)
        };
        format!("{}.{:0width$}s", value.seconds, value.nanos / divisor)
    }
    let mut map = Map::new();
    map.insert("name".into(), json!(sub.name));
    map.insert("topic".into(), json!(sub.topic));
    if let Some(push) = &sub.push_config {
        let mut value = Map::new();
        if !push.push_endpoint.is_empty() {
            value.insert("pushEndpoint".into(), json!(push.push_endpoint));
        }
        map.insert("pushConfig".into(), Value::Object(value));
    }
    if sub.ack_deadline_seconds != 0 {
        map.insert("ackDeadlineSeconds".into(), json!(sub.ack_deadline_seconds));
    }
    if sub.retain_acked_messages {
        map.insert("retainAckedMessages".into(), json!(true));
    }
    if let Some(value) = &sub.message_retention_duration {
        map.insert("messageRetentionDuration".into(), json!(duration(value)));
    }
    if !sub.labels.is_empty() {
        let labels: std::collections::BTreeMap<_, _> = sub.labels.iter().collect();
        map.insert("labels".into(), json!(labels));
    }
    if sub.enable_message_ordering {
        map.insert("enableMessageOrdering".into(), json!(true));
    }
    if let Some(policy) = &sub.expiration_policy {
        let mut value = Map::new();
        if let Some(ttl) = &policy.ttl {
            value.insert("ttl".into(), json!(duration(ttl)));
        }
        map.insert("expirationPolicy".into(), Value::Object(value));
    }
    if !sub.filter.is_empty() {
        map.insert("filter".into(), json!(sub.filter));
    }
    if sub.state == pb::subscription::State::Active as i32 {
        map.insert("state".into(), json!("ACTIVE"));
    }
    Value::Object(map)
}

fn base(name: &str) -> pb::Subscription {
    pb::Subscription {
        name: format!("projects/demo/subscriptions/{name}"),
        topic: TOPIC.to_owned(),
        ..Default::default()
    }
}

/// Five kinds of subscription: pull, push, ordered, retain-acked and explicit retention.
fn kinds() -> Vec<pb::Subscription> {
    vec![
        base("pull"),
        pb::Subscription {
            push_config: Some(pb::PushConfig {
                push_endpoint: PUSH_ENDPOINT.to_owned(),
                ..Default::default()
            }),
            ..base("push")
        },
        pb::Subscription {
            enable_message_ordering: true,
            ..base("ordered")
        },
        pb::Subscription {
            retain_acked_messages: true,
            ..base("retain")
        },
        pb::Subscription {
            message_retention_duration: Some(seconds(900)),
            ack_deadline_seconds: 30,
            ..base("explicit")
        },
    ]
}

#[tokio::test]
async fn a_grpc_pull_subscription_carries_the_recorded_production_defaults() {
    let h = Harness::new().await;
    h.topic("demo").await;
    let mut grpc = h.grpc().await;
    let created = grpc
        .create_subscription(base("pull"))
        .await
        .unwrap()
        .into_inner();
    let from_get = grpc
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: created.name.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let listed = grpc
        .list_subscriptions(pb::ListSubscriptionsRequest {
            project: "projects/demo".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .subscriptions;
    assert_eq!(listed, vec![created.clone()]);
    for sub in [&created, &from_get] {
        assert_eq!(sub.push_config, Some(pb::PushConfig::default()));
        assert_eq!(sub.message_retention_duration, Some(seconds(604_800)));
        assert_eq!(
            sub.expiration_policy,
            Some(pb::ExpirationPolicy {
                ttl: Some(seconds(2_678_400))
            })
        );
        assert_eq!(sub.state, pb::subscription::State::Active as i32);
        assert_eq!(sub.ack_deadline_seconds, 10);
        assert!(!sub.enable_message_ordering);
        assert!(!sub.retain_acked_messages);
        assert!(sub.labels.is_empty());
    }
    h.shutdown().await;
}

#[tokio::test]
async fn the_rest_body_of_a_subscription_is_the_proto3_json_of_the_grpc_response() {
    let h = Harness::new().await;
    h.topic("demo").await;
    let mut grpc = h.grpc().await;
    for sub in kinds() {
        let created = grpc.create_subscription(sub).await.unwrap().into_inner();
        let (status, rest) = h
            .rest("GET", &format!("/v1/{}", created.name), json!({}))
            .await;
        assert_eq!(status, 200, "{rest}");
        assert_eq!(rest, proto3_json(&created), "{}", created.name);
    }
    // The same subscriptions created over REST read the same on both transports.
    for sub in kinds() {
        let id = sub.name.rsplit('/').next().unwrap().to_owned();
        let name = format!("projects/demo/subscriptions/rest-{id}");
        let mut body = Map::new();
        body.insert("topic".into(), json!(TOPIC));
        if let Some(push) = &sub.push_config {
            body.insert(
                "pushConfig".into(),
                json!({"pushEndpoint": push.push_endpoint}),
            );
        }
        if sub.enable_message_ordering {
            body.insert("enableMessageOrdering".into(), json!(true));
        }
        if sub.retain_acked_messages {
            body.insert("retainAckedMessages".into(), json!(true));
        }
        if let Some(retention) = &sub.message_retention_duration {
            body.insert(
                "messageRetentionDuration".into(),
                json!(format!("{}s", retention.seconds)),
            );
        }
        if sub.ack_deadline_seconds != 0 {
            body.insert("ackDeadlineSeconds".into(), json!(sub.ack_deadline_seconds));
        }
        let (status, rest) = h
            .rest("PUT", &format!("/v1/{name}"), Value::Object(body))
            .await;
        assert_eq!(status, 200, "{rest}");
        let from_grpc = grpc
            .get_subscription(pb::GetSubscriptionRequest { subscription: name })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(rest, proto3_json(&from_grpc), "rest-{id}");
    }
    h.shutdown().await;
}

#[tokio::test]
async fn explicit_labels_and_expiration_policies_are_accepted_stored_and_read_on_both_transports() {
    let h = Harness::new().await;
    h.topic("demo").await;
    let mut grpc = h.grpc().await;
    let custom = pb::Subscription {
        labels: [
            ("owner".to_owned(), "grpc".to_owned()),
            ("env".to_owned(), "test".to_owned()),
        ]
        .into(),
        expiration_policy: Some(pb::ExpirationPolicy {
            ttl: Some(seconds(172_800)),
        }),
        ..base("custom")
    };
    let created = grpc.create_subscription(custom).await.unwrap().into_inner();
    assert_eq!(
        created.labels.get("owner").map(String::as_str),
        Some("grpc")
    );
    assert_eq!(created.labels.len(), 2);
    assert_eq!(
        created.expiration_policy,
        Some(pb::ExpirationPolicy {
            ttl: Some(seconds(172_800))
        })
    );
    let (status, rest) = h
        .rest("GET", &format!("/v1/{}", created.name), json!({}))
        .await;
    assert_eq!(status, 200, "{rest}");
    assert_eq!(rest["labels"], json!({"env": "test", "owner": "grpc"}));
    assert_eq!(rest["expirationPolicy"], json!({"ttl": "172800s"}));
    assert_eq!(rest, proto3_json(&created));
    // An expiration policy without a ttl means the subscription never expires, and is read back as such.
    let never = pb::Subscription {
        expiration_policy: Some(pb::ExpirationPolicy { ttl: None }),
        ..base("never")
    };
    let created = grpc.create_subscription(never).await.unwrap().into_inner();
    assert_eq!(
        created.expiration_policy,
        Some(pb::ExpirationPolicy { ttl: None })
    );
    let (status, rest) = h
        .rest("GET", &format!("/v1/{}", created.name), json!({}))
        .await;
    assert_eq!(status, 200, "{rest}");
    assert_eq!(rest["expirationPolicy"], json!({}));
    // Over REST: the same options, in the same stored form.
    let (status, rest) = h
        .rest(
            "PUT",
            "/v1/projects/demo/subscriptions/rest-custom",
            json!({"topic": TOPIC, "labels": {"a": "1"}, "expirationPolicy": {"ttl": "86400s"}}),
        )
        .await;
    assert_eq!(status, 200, "{rest}");
    assert_eq!(rest["labels"], json!({"a": "1"}));
    assert_eq!(rest["expirationPolicy"], json!({"ttl": "86400s"}));
    let from_grpc = grpc
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: "projects/demo/subscriptions/rest-custom".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(from_grpc.labels.get("a").map(String::as_str), Some("1"));
    assert_eq!(
        from_grpc.expiration_policy,
        Some(pb::ExpirationPolicy {
            ttl: Some(seconds(86_400))
        })
    );
    let (status, rest) = h
        .rest(
            "PUT",
            "/v1/projects/demo/subscriptions/rest-never",
            json!({"topic": TOPIC, "expirationPolicy": {}}),
        )
        .await;
    assert_eq!(status, 200, "{rest}");
    assert_eq!(rest["expirationPolicy"], json!({}));
    h.shutdown().await;
}

#[tokio::test]
async fn an_expiration_ttl_under_one_day_is_refused_on_both_transports_and_creates_nothing() {
    let h = Harness::new().await;
    h.topic("demo").await;
    let mut grpc = h.grpc().await;
    let short = pb::Subscription {
        expiration_policy: Some(pb::ExpirationPolicy {
            ttl: Some(seconds(86_399)),
        }),
        ..base("short")
    };
    let error = grpc.create_subscription(short).await.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
    let (status, body) = h
        .rest(
            "PUT",
            "/v1/projects/demo/subscriptions/short-rest",
            json!({"topic": TOPIC, "expirationPolicy": {"ttl": "86399s"}}),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    for name in ["short", "short-rest"] {
        let (status, _) = h
            .rest(
                "GET",
                &format!("/v1/projects/demo/subscriptions/{name}"),
                json!({}),
            )
            .await;
        assert_eq!(status, 404, "{name} must not exist after the refusal");
    }
    // The boundary itself is accepted.
    let exact = pb::Subscription {
        expiration_policy: Some(pb::ExpirationPolicy {
            ttl: Some(seconds(86_400)),
        }),
        ..base("exact")
    };
    grpc.create_subscription(exact).await.unwrap();
    h.shutdown().await;
}

#[tokio::test]
async fn a_rest_get_body_can_be_sent_back_as_a_create_body_and_output_only_state_is_ignored() {
    let h = Harness::new().await;
    h.topic("demo").await;
    let (status, created) = h
        .rest(
            "PUT",
            "/v1/projects/demo/subscriptions/original",
            json!({"topic": TOPIC}),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    let mut again = created.clone();
    again["name"] = json!("projects/demo/subscriptions/copy");
    let (status, copy) = h
        .rest("PUT", "/v1/projects/demo/subscriptions/copy", again)
        .await;
    assert_eq!(status, 200, "{copy}");
    let mut expected = created.clone();
    expected["name"] = json!("projects/demo/subscriptions/copy");
    assert_eq!(copy, expected);
    // `state` is output only: any state the client names is ignored, a value that is not a state is not.
    for state in ["ACTIVE", "RESOURCE_ERROR", "STATE_UNSPECIFIED"] {
        let name = format!("projects/demo/subscriptions/state-{}", state.to_lowercase());
        let (status, body) = h
            .rest(
                "PUT",
                &format!("/v1/{name}"),
                json!({"topic": TOPIC, "state": state}),
            )
            .await;
        assert_eq!(status, 200, "{state}: {body}");
        assert_eq!(body["state"], "ACTIVE", "{state}");
    }
    let (status, body) = h
        .rest(
            "PUT",
            "/v1/projects/demo/subscriptions/state-bad",
            json!({"topic": TOPIC, "state": 5}),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    // gRPC ignores a named state too.
    let mut grpc = h.grpc().await;
    let named = pb::Subscription {
        state: pb::subscription::State::ResourceError as i32,
        ..base("grpc-state")
    };
    let created = grpc.create_subscription(named).await.unwrap().into_inner();
    assert_eq!(created.state, pb::subscription::State::Active as i32);
    h.shutdown().await;
}
