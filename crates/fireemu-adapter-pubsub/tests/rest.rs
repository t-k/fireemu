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

/// One unsupported subscription option: its JSON name, its protobuf name, the JSON value a REST
/// client sends and the protobuf field a gRPC client sets.
type UnsupportedOption = (&'static str, &'static str, Value, fn(&mut pb::Subscription));

/// Every subscription option declared by `google.pubsub.v1.Subscription` that the emulator
/// cannot represent, with the JSON value a REST client sends and the protobuf field a gRPC
/// client sets. Both transports must refuse each of them by name.
#[allow(clippy::too_many_lines)] // One row per declared unsupported field.
fn unsupported_subscription_options() -> Vec<UnsupportedOption> {
    vec![
        (
            "bigqueryConfig",
            "bigquery_config",
            json!({"table": "demo.dataset.table"}),
            (|sub: &mut pb::Subscription| {
                sub.bigquery_config = Some(pb::BigQueryConfig {
                    table: "demo.dataset.table".to_owned(),
                    ..Default::default()
                });
            }) as fn(&mut pb::Subscription),
        ),
        (
            "cloudStorageConfig",
            "cloud_storage_config",
            json!({"bucket": "demo-bucket"}),
            |sub| {
                sub.cloud_storage_config = Some(pb::CloudStorageConfig {
                    bucket: "demo-bucket".to_owned(),
                    ..Default::default()
                });
            },
        ),
        (
            "bigtableConfig",
            "bigtable_config",
            json!({"table": "projects/demo-app/instances/demo/tables/events"}),
            |sub| {
                sub.bigtable_config = Some(pb::BigtableConfig {
                    table: "projects/demo-app/instances/demo/tables/events".to_owned(),
                    ..Default::default()
                });
            },
        ),
        (
            "retainAckedMessages",
            "retain_acked_messages",
            json!(true),
            |sub| sub.retain_acked_messages = true,
        ),
        (
            "messageRetentionDuration",
            "message_retention_duration",
            json!("600s"),
            |sub| {
                sub.message_retention_duration = Some(prost_types::Duration {
                    seconds: 600,
                    nanos: 0,
                });
            },
        ),
        ("labels", "labels", json!({"owner": "test"}), |sub| {
            sub.labels.insert("owner".to_owned(), "test".to_owned());
        }),
        (
            "expirationPolicy",
            "expiration_policy",
            json!({"ttl": "86400s"}),
            |sub| {
                sub.expiration_policy = Some(pb::ExpirationPolicy {
                    ttl: Some(prost_types::Duration {
                        seconds: 86_400,
                        nanos: 0,
                    }),
                });
            },
        ),
        ("detached", "detached", json!(true), |sub| {
            sub.detached = true;
        }),
        (
            "enableExactlyOnceDelivery",
            "enable_exactly_once_delivery",
            json!(true),
            |sub| sub.enable_exactly_once_delivery = true,
        ),
        (
            "topicMessageRetentionDuration",
            "topic_message_retention_duration",
            json!("600s"),
            |sub| {
                sub.topic_message_retention_duration = Some(prost_types::Duration {
                    seconds: 600,
                    nanos: 0,
                });
            },
        ),
        ("state", "state", json!("ACTIVE"), |sub| sub.state = 1),
        (
            "analyticsHubSubscriptionInfo",
            "analytics_hub_subscription_info",
            json!({"listing": "projects/demo-app/locations/us/dataExchanges/e/listings/l"}),
            |sub| {
                sub.analytics_hub_subscription_info =
                    Some(pb::subscription::AnalyticsHubSubscriptionInfo::default());
            },
        ),
        (
            "messageTransforms",
            "message_transforms",
            json!([{"disabled": false}]),
            |sub| sub.message_transforms = vec![pb::MessageTransform::default()],
        ),
        ("tags", "tags", json!({"env": "test"}), |sub| {
            sub.tags.insert("env".to_owned(), "test".to_owned());
        }),
    ]
}

#[tokio::test]
async fn both_transports_refuse_every_declared_but_unsupported_subscription_option_on_create() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/option-matrix",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);

    for (index, (json_field, proto_field, value, set)) in
        unsupported_subscription_options().into_iter().enumerate()
    {
        let rest_id = format!("matrix-rest-{index}");
        let rest_path = format!("/v1/projects/demo-app/subscriptions/{rest_id}");
        let (status, error) = rest_request(
            address,
            "PUT",
            &rest_path,
            json!({
                "topic": "projects/demo-app/topics/option-matrix",
                json_field: value,
            }),
        )
        .await;
        assert_eq!(status, 501, "{json_field}: {error}");
        assert_eq!(error["error"]["status"], "UNIMPLEMENTED", "{json_field}");
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .contains(proto_field),
            "{json_field}: {error}"
        );
        let (status, _) = rest_request(address, "GET", &rest_path, json!({})).await;
        assert_eq!(status, 404, "{json_field} must not create a subscription");

        let grpc_name = format!("projects/demo-app/subscriptions/matrix-grpc-{index}");
        let mut subscription = pb::Subscription {
            name: grpc_name.clone(),
            topic: "projects/demo-app/topics/option-matrix".to_owned(),
            ..Default::default()
        };
        set(&mut subscription);
        let error = subscriber
            .create_subscription(subscription)
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{proto_field}");
        assert!(
            error.message().contains(proto_field),
            "{proto_field}: {error}"
        );
        let error = subscriber
            .get_subscription(pb::GetSubscriptionRequest {
                subscription: grpc_name,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound, "{proto_field}");
    }

    let (status, listed) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/subscriptions",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        listed["subscriptions"].as_array().unwrap().len(),
        0,
        "a refused option must not leave a listed subscription: {listed}"
    );
}

#[tokio::test]
async fn both_transports_refuse_every_declared_but_unsupported_update_mask_path() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/update-matrix",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let subscription_path = "/v1/projects/demo-app/subscriptions/update-matrix";
    let endpoint = "http://127.0.0.1:8080/original";
    let (status, _) = rest_request(
        address,
        "PUT",
        subscription_path,
        json!({
            "topic": "projects/demo-app/topics/update-matrix",
            "ackDeadlineSeconds": 20,
            "pushConfig": {"pushEndpoint": endpoint}
        }),
    )
    .await;
    assert_eq!(status, 200);
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);

    for (json_field, proto_field, value, set) in unsupported_subscription_options() {
        let (status, error) = rest_request(
            address,
            "PATCH",
            subscription_path,
            json!({
                "subscription": {json_field: value, "ackDeadlineSeconds": 45},
                "updateMask": json_field,
            }),
        )
        .await;
        assert_eq!(status, 501, "{json_field}: {error}");
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .contains(proto_field),
            "{json_field}: {error}"
        );

        let mut subscription = pb::Subscription {
            name: "projects/demo-app/subscriptions/update-matrix".to_owned(),
            ack_deadline_seconds: 45,
            ..Default::default()
        };
        set(&mut subscription);
        let error = subscriber
            .update_subscription(pb::UpdateSubscriptionRequest {
                subscription: Some(subscription),
                update_mask: Some(prost_types::FieldMask {
                    paths: vec![proto_field.to_owned(), "ack_deadline_seconds".to_owned()],
                }),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{proto_field}");
        assert!(
            error.message().contains(proto_field),
            "{proto_field}: {error}"
        );

        assert_subscription_values(address, subscription_path, 20, endpoint).await;
    }
}

#[tokio::test]
async fn both_transports_reject_an_undeclared_subscription_field_as_an_invalid_argument() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/undeclared",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);

    // A field the wire schema never declared is a client mistake, not an emulator limitation.
    let (status, error) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/undeclared",
        json!({
            "topic": "projects/demo-app/topics/undeclared",
            "notAField": true
        }),
    )
    .await;
    assert_eq!(status, 400, "{error}");
    assert_eq!(error["error"]["status"], "INVALID_ARGUMENT");

    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/undeclared",
        json!({"topic": "projects/demo-app/topics/undeclared"}),
    )
    .await;
    assert_eq!(status, 200);

    let (status, error) = rest_request(
        address,
        "PATCH",
        "/v1/projects/demo-app/subscriptions/undeclared",
        json!({
            "subscription": {"ackDeadlineSeconds": 30},
            "updateMask": "notAField"
        }),
    )
    .await;
    assert_eq!(status, 400, "{error}");

    // The protobuf schema drops unknown fields on the wire, so only the field mask can name one.
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let error = subscriber
        .update_subscription(pb::UpdateSubscriptionRequest {
            subscription: Some(pb::Subscription {
                name: "projects/demo-app/subscriptions/undeclared".to_owned(),
                ack_deadline_seconds: 30,
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["not_a_field".to_owned()],
            }),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert!(error.message().contains("not_a_field"), "{error}");
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One create per transport plus the four cross-transport reads.
async fn every_supported_subscription_option_round_trips_through_create_get_list_and_update() {
    let address = start().await;
    for topic in ["roundtrip", "roundtrip-dead"] {
        let (status, _) = rest_request(
            address,
            "PUT",
            &format!("/v1/projects/demo-app/topics/{topic}"),
            json!({}),
        )
        .await;
        assert_eq!(status, 200);
    }
    let filter = "attributes.kind = \"kept\"";
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);

    // One subscription created per transport, carrying every supported option.
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/roundtrip-rest",
        json!({
            "topic": "projects/demo-app/topics/roundtrip",
            "ackDeadlineSeconds": 20,
            "enableMessageOrdering": true,
            "filter": filter,
            "deadLetterPolicy": {
                "deadLetterTopic": "projects/demo-app/topics/roundtrip-dead",
                "maxDeliveryAttempts": 7
            },
            "retryPolicy": {"minimumBackoff": "1.500s", "maximumBackoff": "3s"},
            "pushConfig": {"pushEndpoint": "http://127.0.0.1:8080/rest"}
        }),
    )
    .await;
    assert_eq!(status, 200);
    subscriber
        .create_subscription(pb::Subscription {
            name: "projects/demo-app/subscriptions/roundtrip-grpc".to_owned(),
            topic: "projects/demo-app/topics/roundtrip".to_owned(),
            ack_deadline_seconds: 20,
            enable_message_ordering: true,
            filter: filter.to_owned(),
            dead_letter_policy: Some(pb::DeadLetterPolicy {
                dead_letter_topic: "projects/demo-app/topics/roundtrip-dead".to_owned(),
                max_delivery_attempts: 7,
            }),
            retry_policy: Some(pb::RetryPolicy {
                minimum_backoff: Some(prost_types::Duration {
                    seconds: 1,
                    nanos: 500_000_000,
                }),
                maximum_backoff: Some(prost_types::Duration {
                    seconds: 3,
                    nanos: 0,
                }),
            }),
            push_config: Some(pb::PushConfig {
                push_endpoint: "http://127.0.0.1:8080/grpc".to_owned(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();

    for (id, endpoint, ack_deadline) in [
        ("roundtrip-rest", "http://127.0.0.1:8080/rest", 20),
        ("roundtrip-grpc", "http://127.0.0.1:8080/grpc", 20),
    ] {
        assert_subscription_matrix(address, id, endpoint, ack_deadline, filter).await;
    }

    // An update through one transport is visible identically through every read on both.
    let (status, _) = rest_request(
        address,
        "PATCH",
        "/v1/projects/demo-app/subscriptions/roundtrip-rest",
        json!({
            "subscription": {"ackDeadlineSeconds": 45},
            "updateMask": "ackDeadlineSeconds"
        }),
    )
    .await;
    assert_eq!(status, 200);
    subscriber
        .update_subscription(pb::UpdateSubscriptionRequest {
            subscription: Some(pb::Subscription {
                name: "projects/demo-app/subscriptions/roundtrip-grpc".to_owned(),
                push_config: Some(pb::PushConfig {
                    push_endpoint: "http://127.0.0.1:8080/grpc-updated".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["push_config".to_owned()],
            }),
        })
        .await
        .unwrap();

    assert_subscription_matrix(
        address,
        "roundtrip-rest",
        "http://127.0.0.1:8080/rest",
        45,
        filter,
    )
    .await;
    assert_subscription_matrix(
        address,
        "roundtrip-grpc",
        "http://127.0.0.1:8080/grpc-updated",
        20,
        filter,
    )
    .await;
}

/// Asserts that REST get, REST list, gRPC get and gRPC list report the same supported options for
/// one subscription, and that no unsupported option acquires an invented value.
#[allow(clippy::too_many_lines)] // One assertion per declared field on four read paths.
async fn assert_subscription_matrix(
    address: std::net::SocketAddr,
    id: &str,
    push_endpoint: &str,
    ack_deadline_seconds: u64,
    filter: &str,
) {
    let full_name = format!("projects/demo-app/subscriptions/{id}");
    let (status, from_get) = rest_request(
        address,
        "GET",
        &format!("/v1/projects/demo-app/subscriptions/{id}"),
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "{from_get}");
    let (status, listed) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/subscriptions",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let from_list = listed["subscriptions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == full_name)
        .unwrap_or_else(|| panic!("{id} missing from the REST listing: {listed}"))
        .clone();
    assert_eq!(from_get, from_list, "{id}: REST get and list must agree");
    assert_eq!(from_get["ackDeadlineSeconds"], ack_deadline_seconds, "{id}");
    assert_eq!(
        from_get["pushConfig"]["pushEndpoint"], push_endpoint,
        "{id}"
    );
    assert_eq!(from_get["filter"], filter, "{id}");
    assert_eq!(from_get["enableMessageOrdering"], true, "{id}");
    assert_eq!(
        from_get["deadLetterPolicy"]["maxDeliveryAttempts"], 7,
        "{id}"
    );
    assert_eq!(from_get["retryPolicy"]["minimumBackoff"], "1.500s", "{id}");
    for unsupported in [
        "bigqueryConfig",
        "cloudStorageConfig",
        "bigtableConfig",
        "retainAckedMessages",
        "messageRetentionDuration",
        "labels",
        "expirationPolicy",
        "detached",
        "enableExactlyOnceDelivery",
        "state",
    ] {
        assert!(
            from_get.get(unsupported).is_none(),
            "{id}: REST reported the unsupported field {unsupported}: {from_get}"
        );
    }

    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let grpc_get = subscriber
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: full_name.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let grpc_list = subscriber
        .list_subscriptions(pb::ListSubscriptionsRequest {
            project: "projects/demo-app".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .subscriptions
        .into_iter()
        .find(|entry| entry.name == full_name)
        .unwrap_or_else(|| panic!("{id} missing from the gRPC listing"));
    assert_eq!(grpc_get, grpc_list, "{id}: gRPC get and list must agree");
    assert_eq!(
        u64::try_from(grpc_get.ack_deadline_seconds).unwrap(),
        ack_deadline_seconds,
        "{id}"
    );
    assert_eq!(
        grpc_get.push_config.as_ref().unwrap().push_endpoint,
        push_endpoint,
        "{id}"
    );
    assert_eq!(grpc_get.filter, filter, "{id}");
    assert!(grpc_get.enable_message_ordering, "{id}");
    assert_eq!(
        grpc_get
            .dead_letter_policy
            .as_ref()
            .unwrap()
            .max_delivery_attempts,
        7,
        "{id}"
    );
    assert!(!grpc_get.retain_acked_messages, "{id}");
    assert!(grpc_get.message_retention_duration.is_none(), "{id}");
    assert!(grpc_get.labels.is_empty(), "{id}");
    assert!(grpc_get.expiration_policy.is_none(), "{id}");
    assert!(!grpc_get.detached, "{id}");
    assert!(!grpc_get.enable_exactly_once_delivery, "{id}");
    assert!(grpc_get.bigquery_config.is_none(), "{id}");
    assert!(grpc_get.cloud_storage_config.is_none(), "{id}");
    assert!(grpc_get.bigtable_config.is_none(), "{id}");
    assert!(grpc_get.message_transforms.is_empty(), "{id}");
    assert!(grpc_get.tags.is_empty(), "{id}");
    assert_eq!(grpc_get.state, 0, "{id}");
    let push = grpc_get.push_config.as_ref().unwrap();
    assert!(push.attributes.is_empty(), "{id}");
    assert!(push.authentication_method.is_none(), "{id}");
    assert!(push.wrapper.is_none(), "{id}");
}

/// Every topic option declared by `google.pubsub.v1.Topic` that the emulator cannot represent.
type UnsupportedTopicOption = (&'static str, &'static str, Value, fn(&mut pb::Topic));

fn unsupported_topic_options() -> Vec<UnsupportedTopicOption> {
    vec![
        (
            "schemaSettings",
            "schema_settings",
            json!({"schema": "projects/demo-app/schemas/s"}),
            (|topic: &mut pb::Topic| {
                topic.schema_settings = Some(pb::SchemaSettings::default());
            }) as fn(&mut pb::Topic),
        ),
        (
            "messageRetentionDuration",
            "message_retention_duration",
            json!("600s"),
            |topic| {
                topic.message_retention_duration = Some(prost_types::Duration {
                    seconds: 600,
                    nanos: 0,
                });
            },
        ),
        (
            "kmsKeyName",
            "kms_key_name",
            json!("projects/p/locations/l/keyRings/r/cryptoKeys/k"),
            |topic| {
                "projects/p/locations/l/keyRings/r/cryptoKeys/k"
                    .clone_into(&mut topic.kms_key_name);
            },
        ),
        (
            "messageStoragePolicy",
            "message_storage_policy",
            json!({"allowedPersistenceRegions": ["us-central1"]}),
            |topic| {
                topic.message_storage_policy = Some(pb::MessageStoragePolicy::default());
            },
        ),
        (
            "ingestionDataSourceSettings",
            "ingestion_data_source_settings",
            json!({}),
            |topic| {
                topic.ingestion_data_source_settings =
                    Some(pb::IngestionDataSourceSettings::default());
            },
        ),
        (
            "messageTransforms",
            "message_transforms",
            json!([{"disabled": false}]),
            |topic| topic.message_transforms = vec![pb::MessageTransform::default()],
        ),
        ("tags", "tags", json!({"env": "test"}), |topic| {
            topic.tags.insert("env".to_owned(), "test".to_owned());
        }),
    ]
}

#[tokio::test]
async fn both_transports_refuse_every_declared_but_unsupported_topic_option_on_create() {
    let address = start().await;
    let mut publisher = PublisherClient::new(grpc_channel(address).await);

    for (index, (json_field, proto_field, value, set)) in
        unsupported_topic_options().into_iter().enumerate()
    {
        let rest_path = format!("/v1/projects/demo-app/topics/topic-matrix-rest-{index}");
        let (status, error) =
            rest_request(address, "PUT", &rest_path, json!({json_field: value})).await;
        assert_eq!(status, 501, "{json_field}: {error}");
        assert_eq!(error["error"]["status"], "UNIMPLEMENTED", "{json_field}");
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .contains(proto_field),
            "{json_field}: {error}"
        );
        let (status, _) = rest_request(address, "GET", &rest_path, json!({})).await;
        assert_eq!(status, 404, "{json_field} must not create a topic");

        let grpc_name = format!("projects/demo-app/topics/topic-matrix-grpc-{index}");
        let mut topic = pb::Topic {
            name: grpc_name.clone(),
            ..Default::default()
        };
        set(&mut topic);
        let error = publisher.create_topic(topic).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{proto_field}");
        assert!(
            error.message().contains(proto_field),
            "{proto_field}: {error}"
        );
        let error = publisher
            .get_topic(pb::GetTopicRequest { topic: grpc_name })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound, "{proto_field}");
    }
}

#[tokio::test]
async fn rest_rejects_an_undeclared_topic_field_as_an_invalid_argument() {
    let address = start().await;
    // An unknown JSON name is a client mistake, not an emulator limitation.
    let (status, error) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/topic-undeclared",
        json!({"notAField": true}),
    )
    .await;
    assert_eq!(status, 400, "{error}");
    assert_eq!(error["error"]["status"], "INVALID_ARGUMENT");
    let (status, _) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/topics/topic-undeclared",
        json!({}),
    )
    .await;
    assert_eq!(status, 404);

    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/topic-undeclared",
        json!({"labels": {"owner": "test"}, "state": "ACTIVE", "satisfiesPzs": false}),
    )
    .await;
    assert_eq!(status, 200, "declared and output-only fields stay accepted");

    // The same split applies to an update mask: an unknown path is invalid, a declared but
    // unsupported path is an emulator limitation.
    for (mask, expected) in [("notAField", 400), ("kmsKeyName", 501), ("labels", 501)] {
        let (status, error) = rest_request(
            address,
            "PATCH",
            "/v1/projects/demo-app/topics/topic-undeclared",
            json!({"topic": {}, "updateMask": mask}),
        )
        .await;
        assert_eq!(status, expected, "{mask}: {error}");
    }
}

#[tokio::test]
async fn a_supported_topic_round_trips_through_get_and_list_on_both_transports() {
    let address = start().await;
    let (status, created) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/topic-roundtrip",
        json!({"labels": {"owner": "test"}}),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["labels"]["owner"], "test");

    let (status, from_get) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/topics/topic-roundtrip",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, listed) =
        rest_request(address, "GET", "/v1/projects/demo-app/topics", json!({})).await;
    assert_eq!(status, 200);
    let from_list = listed["topics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "projects/demo-app/topics/topic-roundtrip")
        .unwrap_or_else(|| panic!("topic missing from the REST listing: {listed}"))
        .clone();
    assert_eq!(from_get, from_list);
    for unsupported in [
        "schemaSettings",
        "messageRetentionDuration",
        "kmsKeyName",
        "messageStoragePolicy",
        "ingestionDataSourceSettings",
        "messageTransforms",
        "tags",
    ] {
        assert!(
            from_get.get(unsupported).is_none(),
            "REST reported the unsupported topic field {unsupported}: {from_get}"
        );
    }

    let mut publisher = PublisherClient::new(grpc_channel(address).await);
    let grpc_get = publisher
        .get_topic(pb::GetTopicRequest {
            topic: "projects/demo-app/topics/topic-roundtrip".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    let grpc_list = publisher
        .list_topics(pb::ListTopicsRequest {
            project: "projects/demo-app".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .topics
        .into_iter()
        .find(|entry| entry.name == "projects/demo-app/topics/topic-roundtrip")
        .expect("topic missing from the gRPC listing");
    assert_eq!(grpc_get, grpc_list);
    assert_eq!(
        grpc_get.labels.get("owner").map(String::as_str),
        Some("test")
    );
    assert!(grpc_get.schema_settings.is_none());
    assert!(grpc_get.message_retention_duration.is_none());
    assert!(grpc_get.kms_key_name.is_empty());
    assert!(grpc_get.message_storage_policy.is_none());
    assert!(grpc_get.ingestion_data_source_settings.is_none());
    assert!(grpc_get.message_transforms.is_empty());
    assert!(grpc_get.tags.is_empty());
}

#[tokio::test]
async fn a_rest_body_spelled_in_snake_case_applies_every_supported_option() {
    let address = start().await;
    for topic in ["snake", "snake-dead"] {
        let (status, _) = rest_request(
            address,
            "PUT",
            &format!("/v1/projects/demo-app/topics/{topic}"),
            json!({}),
        )
        .await;
        assert_eq!(status, 200);
    }
    // proto3 JSON accepts the original field names, so these must be applied, never dropped.
    let (status, created) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/snake",
        json!({
            "topic": "projects/demo-app/topics/snake",
            "ack_deadline_seconds": 30,
            "enable_message_ordering": true,
            "filter": "attributes.kind = \"kept\"",
            "dead_letter_policy": {
                "dead_letter_topic": "projects/demo-app/topics/snake-dead",
                "max_delivery_attempts": 7
            },
            "retry_policy": {"minimum_backoff": "1.500s", "maximum_backoff": "3s"},
            "push_config": {"push_endpoint": "http://127.0.0.1:8080/snake"}
        }),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["ackDeadlineSeconds"], 30, "{created}");
    assert_eq!(created["enableMessageOrdering"], true, "{created}");
    assert_eq!(created["filter"], "attributes.kind = \"kept\"", "{created}");
    assert_eq!(
        created["deadLetterPolicy"]["deadLetterTopic"], "projects/demo-app/topics/snake-dead",
        "{created}"
    );
    assert_eq!(created["deadLetterPolicy"]["maxDeliveryAttempts"], 7);
    assert_eq!(created["retryPolicy"]["minimumBackoff"], "1.500s");
    assert_eq!(
        created["pushConfig"]["pushEndpoint"],
        "http://127.0.0.1:8080/snake"
    );

    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let from_grpc = subscriber
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: "projects/demo-app/subscriptions/snake".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(from_grpc.ack_deadline_seconds, 30);
    assert!(from_grpc.enable_message_ordering);
    assert_eq!(
        from_grpc.dead_letter_policy.unwrap().max_delivery_attempts,
        7
    );
    assert_eq!(
        from_grpc.push_config.unwrap().push_endpoint,
        "http://127.0.0.1:8080/snake"
    );

    // A snake_case mask with a snake_case body updates the endpoint; it must never clear it.
    let (status, updated) = rest_request(
        address,
        "PATCH",
        "/v1/projects/demo-app/subscriptions/snake",
        json!({
            "subscription": {"push_config": {"push_endpoint": "http://127.0.0.1:8081/snake"}},
            "update_mask": "push_config"
        }),
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        updated["pushConfig"]["pushEndpoint"], "http://127.0.0.1:8081/snake",
        "a snake_case update must apply its value, not clear the endpoint"
    );
    assert_subscription_values(
        address,
        "/v1/projects/demo-app/subscriptions/snake",
        30,
        "http://127.0.0.1:8081/snake",
    )
    .await;

    // A snake_case ack deadline update is applied too.
    let (status, updated) = rest_request(
        address,
        "PATCH",
        "/v1/projects/demo-app/subscriptions/snake",
        json!({
            "subscription": {"ack_deadline_seconds": 45},
            "updateMask": "ack_deadline_seconds"
        }),
    )
    .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["ackDeadlineSeconds"], 45);
}

#[tokio::test]
async fn a_rest_body_that_spells_one_field_twice_is_rejected() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/duplicate",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, error) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/duplicate",
        json!({
            "topic": "projects/demo-app/topics/duplicate",
            "ackDeadlineSeconds": 30,
            "ack_deadline_seconds": 45
        }),
    )
    .await;
    assert_eq!(status, 400, "{error}");
    let (status, _) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/subscriptions/duplicate",
        json!({}),
    )
    .await;
    assert_eq!(
        status, 404,
        "an ambiguous body must not create a subscription"
    );
}

#[tokio::test]
async fn a_nested_update_mask_path_is_refused_under_its_protobuf_name_on_both_transports() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/nested-mask",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/nested-mask",
        json!({"topic": "projects/demo-app/topics/nested-mask"}),
    )
    .await;
    assert_eq!(status, 200);

    let (status, error) = rest_request(
        address,
        "PATCH",
        "/v1/projects/demo-app/subscriptions/nested-mask",
        json!({"subscription": {}, "updateMask": "pushConfig.oidcToken"}),
    )
    .await;
    assert_eq!(status, 501, "{error}");
    let message = error["error"]["message"].as_str().unwrap().to_owned();
    assert!(message.contains("push_config.oidc_token"), "{message}");

    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let grpc_error = subscriber
        .update_subscription(pb::UpdateSubscriptionRequest {
            subscription: Some(pb::Subscription {
                name: "projects/demo-app/subscriptions/nested-mask".to_owned(),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["push_config.oidc_token".to_owned()],
            }),
        })
        .await
        .unwrap_err();
    assert_eq!(grpc_error.code(), tonic::Code::Unimplemented);
    assert_eq!(grpc_error.message(), message);
}

#[tokio::test]
async fn rest_seek_accepts_a_time_target_and_replays_the_backlog() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/seek-time",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/seek-time",
        json!({"topic": "projects/demo-app/topics/seek-time"}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/topics/seek-time:publish",
        json!({"messages": [{"data": "cmVwbGF5"}]}),
    )
    .await;
    assert_eq!(status, 200);

    let (status, pulled) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/seek-time:pull",
        json!({"maxMessages": 10}),
    )
    .await;
    assert_eq!(status, 200);
    let ack_id = pulled["receivedMessages"][0]["ackId"].as_str().unwrap();
    let (status, _) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/seek-time:acknowledge",
        json!({"ackIds": [ack_id]}),
    )
    .await;
    assert_eq!(status, 200);

    // The harness clock starts at 2023-11-14T22:13:20Z; seek before the publish to replay it.
    let (status, error) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/seek-time:seek",
        json!({"time": "2023-11-14T22:00:00Z"}),
    )
    .await;
    assert_eq!(status, 200, "{error}");
    let (status, replayed) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/seek-time:pull",
        json!({"maxMessages": 10}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        replayed["receivedMessages"].as_array().unwrap().len(),
        1,
        "a seek by time must replay the acknowledged message: {replayed}"
    );

    for (body, expected) in [
        (json!({}), 400),
        (json!({"time": "not-a-time"}), 400),
        (
            json!({"time": "2023-11-14T22:00:00Z", "snapshot": "projects/demo-app/snapshots/x"}),
            400,
        ),
    ] {
        let (status, _) = rest_request(
            address,
            "POST",
            "/v1/projects/demo-app/subscriptions/seek-time:seek",
            body,
        )
        .await;
        assert_eq!(status, expected);
    }
}

#[tokio::test]
async fn rest_snapshot_creation_separates_unknown_names_from_unsupported_fields() {
    let address = start().await;
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/topics/snapshot-keys",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/snapshot-keys",
        json!({"topic": "projects/demo-app/topics/snapshot-keys"}),
    )
    .await;
    assert_eq!(status, 200);

    for (body, expected) in [
        (
            json!({
                "subscription": "projects/demo-app/subscriptions/snapshot-keys",
                "notAField": true
            }),
            400,
        ),
        (
            json!({
                "subscription": "projects/demo-app/subscriptions/snapshot-keys",
                "expireTime": "2023-11-15T00:00:00Z"
            }),
            501,
        ),
    ] {
        let (status, error) = rest_request(
            address,
            "PUT",
            "/v1/projects/demo-app/snapshots/snapshot-keys",
            body,
        )
        .await;
        assert_eq!(status, expected, "{error}");
        let (status, _) = rest_request(
            address,
            "GET",
            "/v1/projects/demo-app/snapshots/snapshot-keys",
            json!({}),
        )
        .await;
        assert_eq!(status, 404, "a refused snapshot must not be created");
    }

    // The snake_case spelling of a supported field is applied.
    let (status, snapshot) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/snapshots/snapshot-keys",
        json!({
            "subscription": "projects/demo-app/subscriptions/snapshot-keys",
            "labels": {"owner": "test"}
        }),
    )
    .await;
    assert_eq!(status, 200, "{snapshot}");
    assert_eq!(snapshot["labels"]["owner"], "test");
}
