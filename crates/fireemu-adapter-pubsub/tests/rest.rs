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

async fn assert_subscription_values(
    address: std::net::SocketAddr,
    path: &str,
    ack_deadline_seconds: u64,
    push_endpoint: &str,
) {
    let (status, subscription) = rest_request(address, "GET", path, json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(subscription["ackDeadlineSeconds"], ack_deadline_seconds);
    assert_eq!(subscription["pushConfig"]["pushEndpoint"], push_endpoint);
}

#[tokio::test]
async fn rest_publish_is_visible_to_grpc_and_grpc_publish_is_visible_to_rest() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/events",
        json!({"labels": {"owner": "rest"}}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = rest_request(
        address,
        "PUT",
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
async fn rest_topic_options_are_rejected_before_create_or_update_mutation() {
    let address = start().await;
    let rejected = "/v1/projects/demo-app/topics/rest-rejected-options";
    let (status, error) = rest_request(
        address,
        "PUT",
        rejected,
        json!({"schemaSettings": {"schema": "projects/demo-app/schemas/orders"}}),
    )
    .await;
    assert_eq!(status, 501);
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("schema_settings"));
    let (status, _) = rest_request(address, "GET", rejected, json!({})).await;
    assert_eq!(status, 404);

    let topic = "/v1/projects/demo-app/topics/rest-supported-options";
    let (status, _) = rest_request(address, "PUT", topic, json!({"labels": {"env": "test"}})).await;
    assert_eq!(status, 200);
    let (status, error) = rest_request(
        address,
        "PATCH",
        topic,
        json!({
            "topic": {"name": "projects/demo-app/topics/rest-supported-options", "kmsKeyName": "projects/p/locations/l/keyRings/r/cryptoKeys/k"},
            "updateMask": "kmsKeyName"
        }),
    )
    .await;
    assert_eq!(status, 501);
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("kms_key_name"));
    let (status, current) = rest_request(address, "GET", topic, json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(current["labels"]["env"], "test");

    let (status, error) = rest_request(
        address,
        "PATCH",
        topic,
        json!({
            "topic": {"name": "projects/demo-app/topics/rest-supported-options", "schemaSettings": {}},
            "updateMask": "schemaSettings.schema"
        }),
    )
    .await;
    assert_eq!(status, 501);
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("schema_settings"));
}

#[tokio::test]
async fn rest_rejects_each_non_default_topic_option() {
    let address = start().await;
    let cases = [
        ("schema", json!({"schemaSettings": {}}), "schema_settings"),
        (
            "retention",
            json!({"messageRetentionDuration": "600s"}),
            "message_retention_duration",
        ),
        (
            "kms",
            json!({"kmsKeyName": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}),
            "kms_key_name",
        ),
        (
            "storage",
            json!({"messageStoragePolicy": {}}),
            "message_storage_policy",
        ),
        (
            "ingestion",
            json!({"ingestionDataSourceSettings": {}}),
            "ingestion_data_source_settings",
        ),
        (
            "transforms",
            json!({"messageTransforms": [{}]}),
            "message_transforms",
        ),
        ("tags", json!({"tags": {"env": "test"}}), "tags"),
    ];
    for (id, options, field) in cases {
        let path = format!("/v1/projects/demo-app/topics/rest-rejected-{id}");
        let (status, error) = rest_request(address, "PUT", &path, options).await;
        assert_eq!(status, 501, "{id}: {error}");
        assert!(error["error"]["message"].as_str().unwrap().contains(field));
        let (status, _) = rest_request(address, "GET", &path, json!({})).await;
        assert_eq!(status, 404, "{id} was created");
    }

    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/rest-output-only",
        json!({"state": "ACTIVE", "satisfiesPzs": true}),
    )
    .await;
    assert_eq!(status, 200);
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
        "PUT",
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

#[tokio::test]
async fn a_rejected_rest_subscription_update_keeps_the_previous_configuration() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/events",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, created) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/events-sub",
        json!({"topic": "projects/demo-app/topics/events"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(created["ackDeadlineSeconds"], 10);

    let (status, _) = rest_request(
        address,
        "PATCH",
        "/v1/projects/demo-app/subscriptions/events-sub",
        json!({
            "subscription": {
                "name": "projects/demo-app/subscriptions/events-sub",
                "ackDeadlineSeconds": 20,
                "pushConfig": {"pushEndpoint": "https://example.com/not-loopback"}
            },
            "updateMask": "ackDeadlineSeconds,pushConfig"
        }),
    )
    .await;
    assert_eq!(status, 400);

    let (status, after) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/subscriptions/events-sub",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(after["ackDeadlineSeconds"], 10);
    assert!(after.get("pushConfig").is_none());
}

#[tokio::test]
async fn a_malformed_rest_push_config_cannot_clear_an_existing_endpoint() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/events",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let endpoint = "http://127.0.0.1:8080/push";
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/events-sub",
        json!({
            "topic": "projects/demo-app/topics/events",
            "pushConfig": {"pushEndpoint": endpoint}
        }),
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = rest_request(
        address,
        "PATCH",
        "/v1/projects/demo-app/subscriptions/events-sub",
        json!({
            "subscription": {
                "name": "projects/demo-app/subscriptions/events-sub",
                "pushConfig": "not-an-object"
            },
            "updateMask": "pushConfig"
        }),
    )
    .await;
    assert_eq!(status, 400);

    let (status, after) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/subscriptions/events-sub",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(after["pushConfig"]["pushEndpoint"], endpoint);
}

#[tokio::test]
async fn rest_put_routes_preserve_every_supported_subscription_field() {
    let address = start().await;
    let topic = "/v1/projects/demo-app/topics/rest-wire";
    let dead_topic = "/v1/projects/demo-app/topics/rest-dead";
    for path in [topic, dead_topic] {
        let (status, _) = rest_request(address, "PUT", path, json!({})).await;
        assert_eq!(status, 200);
    }
    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/topics/wrong-verb",
        json!({}),
    )
    .await;
    assert_eq!(status, 405);

    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/wrong-verb",
        json!({"topic": "projects/demo-app/topics/rest-wire"}),
    )
    .await;
    assert_eq!(status, 405);

    let subscription_path = "/v1/projects/demo-app/subscriptions/rest-wire";
    let filter = "attributes.kind = \"kept\"";
    let (status, created) = rest_request(
        address,
        "PUT",
        subscription_path,
        json!({
            "topic": "projects/demo-app/topics/rest-wire",
            "ackDeadlineSeconds": 20,
            "enableMessageOrdering": true,
            "filter": filter,
            "deadLetterPolicy": {
                "deadLetterTopic": "projects/demo-app/topics/rest-dead",
                "maxDeliveryAttempts": 5
            },
            "retryPolicy": {
                "minimumBackoff": "1.500s",
                "maximumBackoff": "3s"
            }
        }),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["filter"], filter);
    assert_eq!(created["deadLetterPolicy"]["maxDeliveryAttempts"], 5);
    assert_eq!(created["retryPolicy"]["minimumBackoff"], "1.500s");

    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let from_grpc = subscriber
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: "projects/demo-app/subscriptions/rest-wire".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(from_grpc.ack_deadline_seconds, 20);
    assert!(from_grpc.enable_message_ordering);
    assert_eq!(from_grpc.filter, filter);
    assert_eq!(
        from_grpc.dead_letter_policy.unwrap().dead_letter_topic,
        "projects/demo-app/topics/rest-dead"
    );
    let retry = from_grpc.retry_policy.unwrap();
    assert_eq!(retry.minimum_backoff.unwrap().seconds, 1);
    assert_eq!(retry.maximum_backoff.unwrap().seconds, 3);

    let snapshot_path = "/v1/projects/demo-app/snapshots/rest-wire";
    let (status, snapshot) = rest_request(
        address,
        "PUT",
        snapshot_path,
        json!({
            "subscription": "projects/demo-app/subscriptions/rest-wire",
            "labels": {"source": "rest"}
        }),
    )
    .await;
    assert_eq!(status, 200, "{snapshot}");
    assert_eq!(snapshot["labels"]["source"], "rest");
    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/snapshots/wrong-verb",
        json!({"subscription": "projects/demo-app/subscriptions/rest-wire"}),
    )
    .await;
    assert_eq!(status, 405);
}

#[tokio::test]
async fn rest_update_mask_is_atomic_scoped_and_rejects_unsupported_fields() {
    let address = start().await;
    rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/update-wire",
        json!({}),
    )
    .await;
    let subscription_path = "/v1/projects/demo-app/subscriptions/update-wire";
    let original_endpoint = "http://127.0.0.1:8080/original";
    let (status, _) = rest_request(
        address,
        "PUT",
        subscription_path,
        json!({
            "topic": "projects/demo-app/topics/update-wire",
            "pushConfig": {"pushEndpoint": original_endpoint}
        }),
    )
    .await;
    assert_eq!(status, 200);

    let (status, updated) = rest_request(
        address,
        "PATCH",
        subscription_path,
        json!({
            "subscription": {
                "name": "projects/demo-app/subscriptions/update-wire",
                "ackDeadlineSeconds": 20,
                "pushConfig": {"pushEndpoint": "http://127.0.0.1:8081/ignored"}
            },
            "updateMask": "ackDeadlineSeconds"
        }),
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["ackDeadlineSeconds"], 20);
    assert_eq!(updated["pushConfig"]["pushEndpoint"], original_endpoint);

    for (body, expected_status) in [
        (
            json!({
                "subscription": {"ackDeadlineSeconds": 30},
                "updateMask": "unknownField"
            }),
            400,
        ),
        (
            json!({
                "subscription": {"ackDeadlineSeconds": "30"},
                "updateMask": "ackDeadlineSeconds"
            }),
            400,
        ),
        (
            json!({
                "subscription": {"retryPolicy": {"minimumBackoff": "1s"}},
                "updateMask": "retryPolicy"
            }),
            501,
        ),
        (
            json!({
                "subscription": {"ackDeadlineSeconds": 30},
                "updateMask": ["ackDeadlineSeconds"]
            }),
            400,
        ),
    ] {
        let (status, _) = rest_request(address, "PATCH", subscription_path, body).await;
        assert_eq!(status, expected_status);
    }

    assert_subscription_values(address, subscription_path, 20, original_endpoint).await;

    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let error = subscriber
        .update_subscription(pb::UpdateSubscriptionRequest {
            subscription: Some(pb::Subscription {
                name: "projects/demo-app/subscriptions/update-wire".to_owned(),
                ack_deadline_seconds: 30,
                push_config: Some(pb::PushConfig {
                    push_endpoint: "https://example.com/rejected".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["ack_deadline_seconds".to_owned(), "push_config".to_owned()],
            }),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_subscription_values(address, subscription_path, 20, original_endpoint).await;
}

#[tokio::test]
async fn rest_and_grpc_allow_a_subscription_to_reference_a_cross_project_topic() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/source-project/topics/shared-topic",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, created) = rest_request(
        address,
        "PUT",
        "/v1/projects/consumer-project/subscriptions/cross-project",
        json!({"topic": "projects/source-project/topics/shared-topic"}),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        created["topic"],
        "projects/source-project/topics/shared-topic"
    );

    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let from_grpc = subscriber
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: "projects/consumer-project/subscriptions/cross-project".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        from_grpc.topic,
        "projects/source-project/topics/shared-topic"
    );
}

#[tokio::test]
async fn rest_policy_defaults_and_retry_bounds_match_the_wire_contract() {
    let address = start().await;
    for topic in ["source", "dead"] {
        let (status, _) = rest_request(
            address,
            "PUT",
            &format!("/v1/projects/demo-app/topics/{topic}"),
            json!({}),
        )
        .await;
        assert_eq!(status, 200);
    }
    let path = "/v1/projects/demo-app/subscriptions/default-policy";
    let (status, created) = rest_request(
        address,
        "PUT",
        path,
        json!({
            "topic": "projects/demo-app/topics/source",
            "deadLetterPolicy": {"deadLetterTopic": "projects/demo-app/topics/dead"},
            "retryPolicy": {"minimumBackoff": "2s"}
        }),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["deadLetterPolicy"]["maxDeliveryAttempts"], 5);
    assert_eq!(created["retryPolicy"]["minimumBackoff"], "2s");
    assert_eq!(created["retryPolicy"]["maximumBackoff"], "600s");
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let from_grpc = subscriber
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: "projects/demo-app/subscriptions/default-policy".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        from_grpc.dead_letter_policy.unwrap().max_delivery_attempts,
        5
    );
    let retry = from_grpc.retry_policy.unwrap();
    assert_eq!(retry.minimum_backoff.unwrap().seconds, 2);
    assert_eq!(retry.maximum_backoff.unwrap().seconds, 600);

    let (status, zero_default) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/zero-dead-policy",
        json!({
            "topic": "projects/demo-app/topics/source",
            "deadLetterPolicy": {
                "deadLetterTopic": "projects/demo-app/topics/dead",
                "maxDeliveryAttempts": 0
            }
        }),
    )
    .await;
    assert_eq!(status, 200, "{zero_default}");
    assert_eq!(zero_default["deadLetterPolicy"]["maxDeliveryAttempts"], 5);

    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/missing-dead-topic",
        json!({
            "topic": "projects/demo-app/topics/source",
            "deadLetterPolicy": {"deadLetterTopic": "projects/demo-app/topics/missing"}
        }),
    )
    .await;
    assert_eq!(status, 404);

    for (name, duration) in [
        ("too-large", "601s"),
        ("overflow", "999999999999999999999s"),
    ] {
        let (status, _) = rest_request(
            address,
            "PUT",
            &format!("/v1/projects/demo-app/subscriptions/{name}"),
            json!({
                "topic": "projects/demo-app/topics/source",
                "retryPolicy": {"minimumBackoff": duration}
            }),
        )
        .await;
        assert_eq!(status, 400);
    }
}

#[tokio::test]
async fn rest_and_grpc_masks_reset_ack_deadline_and_push_config_to_defaults() {
    let address = start().await;
    rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/reset-policy",
        json!({}),
    )
    .await;
    let path = "/v1/projects/demo-app/subscriptions/reset-policy";
    let endpoint = "http://127.0.0.1:8080/original";
    rest_request(
        address,
        "PUT",
        path,
        json!({
            "topic": "projects/demo-app/topics/reset-policy",
            "ackDeadlineSeconds": 20,
            "pushConfig": {"pushEndpoint": endpoint}
        }),
    )
    .await;

    let (status, reset) = rest_request(
        address,
        "PATCH",
        path,
        json!({
            "subscription": {"name": "projects/demo-app/subscriptions/reset-policy"},
            "updateMask": "ackDeadlineSeconds,pushConfig"
        }),
    )
    .await;
    assert_eq!(status, 200, "{reset}");
    assert_eq!(reset["ackDeadlineSeconds"], 10);
    assert!(reset.get("pushConfig").is_none());

    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let reset = subscriber
        .update_subscription(pb::UpdateSubscriptionRequest {
            subscription: Some(pb::Subscription {
                name: "projects/demo-app/subscriptions/reset-policy".to_owned(),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["ack_deadline_seconds".to_owned(), "push_config".to_owned()],
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reset.ack_deadline_seconds, 10);
    assert_eq!(reset.push_config, None);
}

#[tokio::test]
async fn grpc_create_uses_the_same_policy_defaults_and_retry_bounds_as_rest() {
    let address = start().await;
    let mut publisher = PublisherClient::new(grpc_channel(address).await);
    for topic in ["grpc-source", "grpc-dead"] {
        publisher
            .create_topic(pb::Topic {
                name: format!("projects/demo-app/topics/{topic}"),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let created = subscriber
        .create_subscription(pb::Subscription {
            name: "projects/demo-app/subscriptions/grpc-default-policy".to_owned(),
            topic: "projects/demo-app/topics/grpc-source".to_owned(),
            dead_letter_policy: Some(pb::DeadLetterPolicy {
                dead_letter_topic: "projects/demo-app/topics/grpc-dead".to_owned(),
                max_delivery_attempts: 0,
            }),
            retry_policy: Some(pb::RetryPolicy {
                minimum_backoff: Some(prost_types::Duration {
                    seconds: 2,
                    nanos: 0,
                }),
                maximum_backoff: None,
            }),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.dead_letter_policy.unwrap().max_delivery_attempts, 5);
    assert_eq!(
        created
            .retry_policy
            .unwrap()
            .maximum_backoff
            .unwrap()
            .seconds,
        600
    );

    let error = subscriber
        .create_subscription(pb::Subscription {
            name: "projects/demo-app/subscriptions/grpc-excessive-policy".to_owned(),
            topic: "projects/demo-app/topics/grpc-source".to_owned(),
            retry_policy: Some(pb::RetryPolicy {
                minimum_backoff: Some(prost_types::Duration {
                    seconds: 601,
                    nanos: 0,
                }),
                maximum_backoff: Some(prost_types::Duration {
                    seconds: 601,
                    nanos: 0,
                }),
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);

    let error = subscriber
        .create_subscription(pb::Subscription {
            name: "projects/demo-app/subscriptions/grpc-malformed-duration".to_owned(),
            topic: "projects/demo-app/topics/grpc-source".to_owned(),
            retry_policy: Some(pb::RetryPolicy {
                minimum_backoff: Some(prost_types::Duration {
                    seconds: 1,
                    nanos: -1,
                }),
                maximum_backoff: None,
            }),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
}
