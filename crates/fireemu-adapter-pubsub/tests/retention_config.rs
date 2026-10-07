//! Explicit retention configuration is shared across transports; delivery expiry is out of scope.

use std::sync::{Arc, Mutex};

use fireemu_adapter_pubsub::{serve_pubsub, PubSubHandle};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::subscriber_client::SubscriberClient;
use serde_json::{json, Value};
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
        Self::with_policy(fireemu_adapter_pubsub::PagingPolicy::Emulator).await
    }

    async fn with_policy(policy: fireemu_adapter_pubsub::PagingPolicy) -> Self {
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_700_000_000),
        )));
        let state = Arc::new(Mutex::new(PubSubState::new(99)));
        let handle = PubSubHandle::new(state, clock, None).with_paging_policy(policy);
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

    async fn assert_config(
        &self,
        project: &str,
        id: &str,
        retain: bool,
        duration: Option<prost_types::Duration>,
        ack: i32,
    ) {
        let name = format!("projects/{project}/subscriptions/{id}");
        let mut grpc = self.grpc().await;
        let from_get = grpc
            .get_subscription(pb::GetSubscriptionRequest {
                subscription: name.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(from_get.retain_acked_messages, retain);
        // Known divergence from production, not a parity claim: gRPC leaves an unset retention unset,
        // while production's gRPC response carries the same defaults as its REST transcoding (see
        // docs.local/issues/open/pubsub-grpc-subscription-lacks-the-recorded-production-defaults.md).
        assert_eq!(from_get.message_retention_duration, duration);
        assert_eq!(from_get.ack_deadline_seconds, ack);
        let list = grpc
            .list_subscriptions(pb::ListSubscriptionsRequest {
                project: format!("projects/{project}"),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            list.subscriptions.iter().find(|sub| sub.name == name),
            Some(&from_get)
        );
        let (status, from_rest) = self.rest("GET", &format!("/v1/{name}"), json!({})).await;
        assert_eq!(status, 200);
        assert_eq!(
            from_rest
                .get("retainAckedMessages")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            retain
        );
        let expected_duration = duration.map(|d| {
            if d.nanos == 0 {
                format!("{}s", d.seconds)
            } else {
                format!("{}.{:09}s", d.seconds, d.nanos)
            }
        });
        // An unset retention is reported by REST as the recorded production default of seven days (the
        // shape of a created subscription in the recorded bootstrap responses, see `subscription_json`).
        // gRPC still leaves the field unset: a known divergence from production, whose gRPC response
        // carries the same defaults as its REST transcoding. Tracked in
        // docs.local/issues/open/pubsub-grpc-subscription-lacks-the-recorded-production-defaults.md;
        // this assertion is not a claim that the two transports should differ.
        assert_eq!(
            from_rest
                .get("messageRetentionDuration")
                .and_then(Value::as_str),
            Some(expected_duration.as_deref().unwrap_or("604800s"))
        );
        assert_eq!(from_rest["ackDeadlineSeconds"], ack);
        let (status, list) = self
            .rest(
                "GET",
                &format!("/v1/projects/{project}/subscriptions"),
                json!({}),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(
            list["subscriptions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|sub| sub["name"] == name),
            Some(&from_rest)
        );
    }
}

fn duration(seconds: i64, nanos: i32) -> prost_types::Duration {
    prost_types::Duration { seconds, nanos }
}

#[tokio::test]
async fn explicit_retention_config_cross_transport_isolated_and_recreated() {
    let h = Harness::new().await;
    for project in ["demo-a", "demo-b"] {
        h.topic(project).await;
    }
    let name = "projects/demo-a/subscriptions/retention";
    let (status, created) = h.rest("PUT", &format!("/v1/{name}"), json!({"topic": "projects/demo-a/topics/events", "retainAckedMessages": true, "messageRetentionDuration": "600s"})).await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["retainAckedMessages"], true);
    assert_eq!(created["messageRetentionDuration"], "600s");
    h.assert_config("demo-a", "retention", true, Some(duration(600, 0)), 10)
        .await;
    let mut grpc = h.grpc().await;
    let created = grpc
        .create_subscription(pb::Subscription {
            name: "projects/demo-b/subscriptions/retention".into(),
            topic: "projects/demo-b/topics/events".into(),
            message_retention_duration: Some(duration(601, 1)),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.message_retention_duration, Some(duration(601, 1)));
    assert!(!created.retain_acked_messages);
    h.assert_config("demo-b", "retention", false, Some(duration(601, 1)), 10)
        .await;
    let acked_name = "projects/demo-a/subscriptions/acked";
    grpc.create_subscription(pb::Subscription {
        name: acked_name.into(),
        topic: "projects/demo-a/topics/events".into(),
        retain_acked_messages: true,
        ..Default::default()
    })
    .await
    .unwrap();
    h.assert_config("demo-a", "acked", true, None, 10).await;
    grpc.update_subscription(pb::UpdateSubscriptionRequest {
        subscription: Some(pb::Subscription {
            name: name.into(),
            ack_deadline_seconds: 30,
            ..Default::default()
        }),
        update_mask: Some(prost_types::FieldMask {
            paths: vec!["ack_deadline_seconds".into()],
        }),
    })
    .await
    .unwrap();
    h.assert_config("demo-a", "retention", true, Some(duration(600, 0)), 30)
        .await;
    let (status, body) = h.rest("PATCH", &format!("/v1/{name}"), json!({"subscription": {"name": name, "pushConfig": {"pushEndpoint": "http://127.0.0.1:1/push"}}, "updateMask": "pushConfig"})).await;
    assert_eq!(status, 200, "{body}");
    h.assert_config("demo-a", "retention", true, Some(duration(600, 0)), 30)
        .await;
    grpc.delete_subscription(pb::DeleteSubscriptionRequest {
        subscription: name.into(),
    })
    .await
    .unwrap();
    assert_eq!(
        grpc.get_subscription(pb::GetSubscriptionRequest {
            subscription: name.into()
        })
        .await
        .unwrap_err()
        .code(),
        tonic::Code::NotFound
    );
    grpc.create_subscription(pb::Subscription {
        name: name.into(),
        topic: "projects/demo-a/topics/events".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    h.assert_config("demo-a", "retention", false, None, 10)
        .await;
    h.assert_config("demo-b", "retention", false, Some(duration(601, 1)), 10)
        .await;
    h.shutdown().await;
}

#[tokio::test]
async fn retention_config_invalid_input_is_atomic_and_aliases_are_checked() {
    let h = Harness::new().await;
    h.topic("demo-a").await;
    let name = "projects/demo-a/subscriptions/invalid";
    for invalid in [
        json!("599.999999999s"),
        json!("2678400.000000001s"),
        json!("600.0000000001s"),
        json!("600"),
        json!("-600s"),
        json!(600),
        json!({}),
    ] {
        let (status, body) = h.rest("PUT", &format!("/v1/{name}"), json!({"topic": "projects/demo-a/topics/events", "messageRetentionDuration": invalid})).await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(
            h.rest("GET", &format!("/v1/{name}"), json!({})).await.0,
            404
        );
    }
    // A malformed duration (a negative second count, nanos outside 0..1e9) is refused as such; a
    // well-formed one outside ten minutes through thirty-one days is refused with the range.
    let malformed = "non-negative canonical";
    let out_of_range = "between 10m and 744h";
    for (invalid, expected) in [
        (duration(600, -1), malformed),
        (duration(600, 1_000_000_000), malformed),
        (duration(-600, 0), malformed),
        (duration(-1, 0), malformed),
        (duration(0, 0), out_of_range),
        (duration(0, 1), out_of_range),
        (duration(599, 999_999_999), out_of_range),
        (duration(2_678_400, 1), out_of_range),
    ] {
        let mut grpc = h.grpc().await;
        let error = grpc
            .create_subscription(pb::Subscription {
                name: name.into(),
                topic: "projects/demo-a/topics/events".into(),
                message_retention_duration: Some(invalid),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            error.message().contains(expected),
            "{invalid:?}: {}",
            error.message()
        );
        assert_eq!(
            grpc.get_subscription(pb::GetSubscriptionRequest {
                subscription: name.into()
            })
            .await
            .unwrap_err()
            .code(),
            tonic::Code::NotFound
        );
    }
    for duplicate in [
        json!({"retainAckedMessages": true, "retain_acked_messages": true}),
        json!({"messageRetentionDuration": "600s", "message_retention_duration": "600s"}),
        json!({"retainAckedMessages": "true"}),
    ] {
        let mut body = duplicate;
        body["topic"] = json!("projects/demo-a/topics/events");
        assert_eq!(h.rest("PUT", &format!("/v1/{name}"), body).await.0, 400);
        assert_eq!(
            h.rest("GET", &format!("/v1/{name}"), json!({})).await.0,
            404
        );
    }
    let (status, body) = h.rest("PUT", &format!("/v1/{name}"), json!({"topic": "projects/demo-a/topics/events", "retain_acked_messages": true, "message_retention_duration": "2678400s"})).await;
    assert_eq!(status, 200, "{body}");
    h.assert_config("demo-a", "invalid", true, Some(duration(2_678_400, 0)), 10)
        .await;
    for field in ["retainAckedMessages", "messageRetentionDuration"] {
        let (status, body) = h
            .rest(
                "PATCH",
                &format!("/v1/{name}"),
                json!({"subscription": {"name": name}, "updateMask": field}),
            )
            .await;
        assert_eq!(status, 200, "{body}");
    }
    h.assert_config("demo-a", "invalid", false, None, 10).await;
    h.shutdown().await;
}

#[tokio::test]
async fn retention_config_duration_codec_preserves_canonical_fraction_precision() {
    let h = Harness::new().await;
    h.topic("demo-codec").await;
    let mut grpc = h.grpc().await;
    for (index, (wire, seconds, nanos)) in [
        ("600s", 600, 0),
        ("600.001s", 600, 1_000_000),
        ("600.000001s", 600, 1_000),
        ("600.000000001s", 600, 1),
        ("2678399.999999999s", 2_678_399, 999_999_999),
        ("2678400s", 2_678_400, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("projects/demo-codec/subscriptions/codec-{index}");
        let expected = duration(seconds, nanos);
        let created = grpc
            .create_subscription(pb::Subscription {
                name: name.clone(),
                topic: "projects/demo-codec/topics/events".into(),
                retain_acked_messages: index % 2 == 0,
                message_retention_duration: Some(expected),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(created.message_retention_duration, Some(expected));
        let (status, rest) = h.rest("GET", &format!("/v1/{name}"), json!({})).await;
        assert_eq!(status, 200);
        assert_eq!(rest["messageRetentionDuration"], wire);
        let name = format!("projects/demo-codec/subscriptions/from-rest-{index}");
        let (status, created) = h.rest("PUT", &format!("/v1/{name}"), json!({"topic": "projects/demo-codec/topics/events", "retainAckedMessages": index % 2 == 0, "messageRetentionDuration": wire})).await;
        assert_eq!(status, 200, "{created}");
        assert_eq!(created["messageRetentionDuration"], wire);
        let from_grpc = grpc
            .get_subscription(pb::GetSubscriptionRequest { subscription: name })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(from_grpc.message_retention_duration, Some(expected));
        assert_eq!(from_grpc.retain_acked_messages, index % 2 == 0);
    }
    h.shutdown().await;
}

#[tokio::test]
async fn recorded_configuration_roundtrips_and_atomic_updates() {
    let h = Harness::with_policy(fireemu_adapter_pubsub::PagingPolicy::Strict).await;
    h.topic("demo-config").await;
    let name = "projects/demo-config/subscriptions/configured";
    let (status, created) = h.rest("PUT", &format!("/v1/{name}"), json!({"topic":"projects/demo-config/topics/events","labels":{"env":"test"},"expirationPolicy":{}})).await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["labels"], json!({"env":"test"}));
    assert_eq!(created["expirationPolicy"], json!({}));
    let mut grpc = h.grpc().await;
    let updated = grpc
        .update_subscription(pb::UpdateSubscriptionRequest {
            subscription: Some(pb::Subscription {
                name: name.into(),
                ack_deadline_seconds: 30,
                labels: [("a".into(), "b".into())].into(),
                retain_acked_messages: true,
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec![
                    "ack_deadline_seconds".into(),
                    "labels".into(),
                    "retain_acked_messages".into(),
                ],
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.ack_deadline_seconds, 30);
    assert_eq!(updated.labels.get("a").map(String::as_str), Some("b"));
    assert!(updated.retain_acked_messages);
    assert_eq!(
        updated.expiration_policy,
        Some(pb::ExpirationPolicy { ttl: None })
    );
    let before = grpc
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: name.into(),
        })
        .await
        .unwrap()
        .into_inner();
    let error = grpc
        .update_subscription(pb::UpdateSubscriptionRequest {
            subscription: Some(pb::Subscription {
                name: name.into(),
                ack_deadline_seconds: 40,
                expiration_policy: Some(pb::ExpirationPolicy {
                    ttl: Some(duration(3600, 0)),
                }),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["ack_deadline_seconds".into(), "expiration_policy".into()],
            }),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.message(), "The value for expiration duration is too small. You passed 1h in the request, but the minimum value is 24h.");
    assert_eq!(
        grpc.get_subscription(pb::GetSubscriptionRequest {
            subscription: name.into()
        })
        .await
        .unwrap()
        .into_inner(),
        before
    );
    let error = grpc
        .update_subscription(pb::UpdateSubscriptionRequest {
            subscription: Some(pb::Subscription {
                name: name.into(),
                enable_message_ordering: true,
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["enable_message_ordering".into()],
            }),
        })
        .await
        .unwrap_err();
    assert_eq!(error.message(), "Invalid update_mask provided in the UpdateSubscriptionRequest: the 'enable_message_ordering' field in the Subscription is not mutable.");
    h.shutdown().await;
}

#[tokio::test]
async fn recorded_https_push_configuration_keeps_delivery_guard() {
    let h = Harness::with_policy(fireemu_adapter_pubsub::PagingPolicy::Strict).await;
    h.topic("demo-push-config").await;
    let name = "projects/demo-push-config/subscriptions/configured";
    let (status, created) = h.rest("PUT", &format!("/v1/{name}"), json!({"topic":"projects/demo-push-config/topics/events","pushConfig":{"pushEndpoint":"https://example.com/probe","attributes":{"x-goog-version":"v1"}}})).await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        created["pushConfig"],
        json!({"pushEndpoint":"https://example.com/probe","attributes":{"x-goog-version":"v1"}})
    );
    let (_, get) = h.rest("GET", &format!("/v1/{name}"), json!({})).await;
    assert_eq!(
        get["pushConfig"],
        json!({"pushEndpoint":"https://example.com/probe"})
    );
    let mut grpc = h.grpc().await;
    let error = grpc
        .pull(pb::PullRequest {
            subscription: name.into(),
            max_messages: 1,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "This method is not supported for this subscription type."
    );
    grpc.modify_push_config(pb::ModifyPushConfigRequest {
        subscription: name.into(),
        push_config: Some(pb::PushConfig::default()),
    })
    .await
    .unwrap();
    let (_, get) = h.rest("GET", &format!("/v1/{name}"), json!({})).await;
    assert_eq!(get["pushConfig"], json!({}));
    h.shutdown().await;
}

#[tokio::test]
async fn recorded_topic_retention_is_persisted_and_bounded() {
    let h = Harness::with_policy(fireemu_adapter_pubsub::PagingPolicy::Strict).await;
    let name = "projects/demo-topic-config/topics/retained";
    let (status, created) = h
        .rest(
            "PUT",
            &format!("/v1/{name}"),
            json!({"messageRetentionDuration":"600.500s"}),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["messageRetentionDuration"], "600.500s");
    let (_, get) = h.rest("GET", &format!("/v1/{name}"), json!({})).await;
    assert_eq!(get, created);
    let (status, error) = h
        .rest(
            "PUT",
            "/v1/projects/demo-topic-config/topics/too-short",
            json!({"messageRetentionDuration":"599s"}),
        )
        .await;
    assert_eq!(status, 400, "{error}");
    assert_eq!(error["error"]["message"],"The value for message retention duration is out of bounds. You passed 9m59s in the request, but the value must be between 10m and 744h.");
    h.shutdown().await;
}

#[tokio::test]
async fn recorded_resource_names_and_label_refusals() {
    let h = Harness::with_policy(fireemu_adapter_pubsub::PagingPolicy::Strict).await;
    for id in ["ab", "goog-probe", "1-leading-digit", "bad$character"] {
        let name = format!("projects/demo-names/topics/{id}");
        let (status, error) = h.rest("PUT", &format!("/v1/{name}"), json!({})).await;
        assert_eq!(status, 400, "{error}");
        assert_eq!(error["error"]["message"],format!("Invalid resource name given (name={name}). Refer to https://cloud.google.com/pubsub/docs/pubsub-basics#resource_names for more information."));
    }
    h.shutdown().await;
}

#[tokio::test]
async fn recorded_label_refusals() {
    let h = Harness::with_policy(fireemu_adapter_pubsub::PagingPolicy::Strict).await;
    let (status, error) = h
        .rest(
            "PUT",
            "/v1/projects/demo-names/topics/upper-label",
            json!({"labels":{"Upper":"x"}}),
        )
        .await;
    assert_eq!(status, 400, "{error}");
    assert_eq!(
        error["error"]["message"],
        r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels"; key "Upper" does not conform to regular expression "[\p{Ll}\p{Lo}][\p{Ll}\p{Lo}\p{N}_-]{0,62}"; first character "U" is not a non-uppercased letter (Unicode character class Ll or Lo))."#
    );
    h.shutdown().await;
}

#[tokio::test]
async fn official_emulator_ack_deadline_admission_preserves_completed_inputs() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let h = Harness::with_policy(policy).await;
        h.topic("demo-profile").await;
        let (status,body)=h.rest("PUT","/v1/projects/demo-profile/subscriptions/short-ack",json!({"topic":"projects/demo-profile/topics/events","ackDeadlineSeconds":9,"labels":{"Upper":"x"},"expirationPolicy":{"ttl":"3600s"}})).await;
        if policy == fireemu_adapter_pubsub::PagingPolicy::Emulator {
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["ackDeadlineSeconds"], 9);
        } else {
            assert_eq!(status, 400, "{body}");
        }
        h.shutdown().await;
    }
}

#[tokio::test]
async fn recorded_rest_schema_errors_preserve_structured_details() {
    let h = Harness::with_policy(fireemu_adapter_pubsub::PagingPolicy::Strict).await;
    let (status, error) = h
        .rest(
            "PUT",
            "/v1/projects/demo-schema/topics/unknown",
            json!({"noSuchField":true}),
        )
        .await;
    assert_eq!(status, 400);
    let description =
        "Invalid JSON payload received. Unknown name \"noSuchField\": Cannot find field.";
    assert_eq!(error["error"]["message"], description);
    assert_eq!(
        error["error"]["details"],
        json!([{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"description":description}]}])
    );
    h.topic("demo-schema").await;
    let name = "projects/demo-schema/subscriptions/configured";
    h.rest(
        "PUT",
        &format!("/v1/{name}"),
        json!({"topic":"projects/demo-schema/topics/events"}),
    )
    .await;
    let (status, error) = h
        .rest(
            "PATCH",
            &format!("/v1/{name}"),
            json!({"subscription":{"name":name},"updateMask":""}),
        )
        .await;
    assert_eq!(status, 400);
    assert_eq!(error["error"]["message"],"The update_mask in the UpdateSubscriptionRequest must be set, and must contain a non-empty paths list.");
    h.shutdown().await;
}
