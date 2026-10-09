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
    start_policy(fireemu_adapter_pubsub::PagingPolicy::Strict).await
}

async fn start_policy(policy: fireemu_adapter_pubsub::PagingPolicy) -> std::net::SocketAddr {
    start_with_numbers(policy, std::collections::BTreeMap::new()).await
}

async fn start_with_numbers(
    policy: fireemu_adapter_pubsub::PagingPolicy,
    numbers: std::collections::BTreeMap<String, String>,
) -> std::net::SocketAddr {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_700_000_000),
    )));
    let state = Arc::new(Mutex::new(PubSubState::new(99)));
    state.lock().unwrap().set_project_numbers(numbers).unwrap();
    let handle = PubSubHandle::new(state, clock, None).with_paging_policy(policy);
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
    let (status, body) = rest_request_raw(address, method, path, body).await;
    (status, serde_json::from_slice(&body).unwrap())
}

async fn rest_request_raw(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Value,
) -> (u16, Vec<u8>) {
    rest_request_bytes(address, method, path, &serde_json::to_vec(&body).unwrap()).await
}

async fn rest_request_bytes(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
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
    (status, body.to_vec())
}

async fn grpc_channel(address: std::net::SocketAddr) -> tonic::transport::Channel {
    tonic::transport::Channel::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn strict_rest_layout_uses_proto_order_while_emulator_keeps_compact_json() {
    use fireemu_adapter_pubsub::PagingPolicy;
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        let address = start_policy(policy).await;
        let (_, empty) =
            rest_request_raw(address, "GET", "/v1/projects/demo-app/topics", json!({})).await;
        assert_eq!(
            empty,
            if policy == PagingPolicy::Strict {
                b"{}\n".as_slice()
            } else {
                b"{}".as_slice()
            }
        );
        rest_request(
            address,
            "PUT",
            "/v1/projects/demo-app/topics/layout",
            json!({}),
        )
        .await;
        let (_, subscription) = rest_request_raw(
            address,
            "PUT",
            "/v1/projects/demo-app/subscriptions/layout",
            json!({"topic":"projects/demo-app/topics/layout"}),
        )
        .await;
        let expected = concat!(
            "{\n",
            "  \"name\": \"projects/demo-app/subscriptions/layout\",\n",
            "  \"topic\": \"projects/demo-app/topics/layout\",\n",
            "  \"pushConfig\": {},\n",
            "  \"ackDeadlineSeconds\": 10,\n",
            "  \"messageRetentionDuration\": \"604800s\",\n",
            "  \"expirationPolicy\": {\n",
            "    \"ttl\": \"2678400s\"\n",
            "  },\n",
            "  \"state\": \"ACTIVE\"\n",
            "}\n",
        );
        if policy == PagingPolicy::Strict {
            assert_eq!(subscription, expected.as_bytes());
        } else {
            let parsed: Value = serde_json::from_slice(&subscription).unwrap();
            assert_eq!(subscription, serde_json::to_vec(&parsed).unwrap());
        }
        let (_, collection) = rest_request_raw(
            address,
            "GET",
            "/v1/projects/demo-app/subscriptions",
            json!({}),
        )
        .await;
        if policy == PagingPolicy::Strict {
            let nested = expected.trim_end().replace('\n', "\n    ");
            assert_eq!(
                collection,
                format!("{{\n  \"subscriptions\": [\n    {nested}\n  ]\n}}\n").as_bytes()
            );
        } else {
            let parsed: Value = serde_json::from_slice(&collection).unwrap();
            assert_eq!(collection, serde_json::to_vec(&parsed).unwrap());
        }
        rest_request(
            address,
            "PUT",
            "/v1/projects/demo-app/subscriptions/layout-second",
            json!({"topic":"projects/demo-app/topics/layout"}),
        )
        .await;
        let (_, page) = rest_request_raw(
            address,
            "GET",
            "/v1/projects/demo-app/subscriptions?pageSize=1",
            json!({}),
        )
        .await;
        if policy == PagingPolicy::Strict {
            let text = std::str::from_utf8(&page).unwrap();
            assert!(
                text.find("\"subscriptions\"").unwrap() < text.find("\"nextPageToken\"").unwrap()
            );
        } else {
            let parsed: Value = serde_json::from_slice(&page).unwrap();
            assert_eq!(page, serde_json::to_vec(&parsed).unwrap());
        }
        let (status, error) = rest_request_raw(
            address,
            "GET",
            "/v1/projects/demo-app/topics/missing-layout",
            json!({}),
        )
        .await;
        assert_eq!(status, 404);
        if policy == PagingPolicy::Strict {
            assert_eq!(
                error,
                concat!(
                    "{\n",
                    "  \"error\": {\n",
                    "    \"code\": 404,\n",
                    "    \"message\": \"Resource not found (resource=missing-layout).\",\n",
                    "    \"status\": \"NOT_FOUND\"\n",
                    "  }\n",
                    "}\n"
                )
                .as_bytes()
            );
        } else {
            let parsed: Value = serde_json::from_slice(&error).unwrap();
            assert_eq!(error, serde_json::to_vec(&parsed).unwrap());
        }
    }
}

#[tokio::test]
async fn recorded_rest_bootstrap_empty_lists_omit_default_fields() {
    let address = start().await;
    for collection in ["topics", "subscriptions"] {
        let (status, body) = rest_request(
            address,
            "GET",
            &format!("/v1/projects/demo-app/{collection}"),
            json!({}),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({}), "{collection}");
    }
}

#[tokio::test]
async fn paging_query_invalid_pairs_preserve_valid_siblings_by_profile() {
    use fireemu_adapter_pubsub::PagingPolicy;
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        let address = start_policy(policy).await;
        for leaf in ["query-alpha", "query-beta", "query-gamma"] {
            let (status, _) = rest_request(
                address,
                "PUT",
                &format!("/v1/projects/demo-app/topics/{leaf}"),
                json!({}),
            )
            .await;
            assert_eq!(status, 200);
        }
        for invalid in [
            "pageSize=abc",
            "pageSize=99999999999",
            "pageSize=%zz",
            "pageSize=%FF",
            "pageToken=%zz",
            "pageToken=%FF",
            "%zz=1",
            "%FF=1",
        ] {
            let (status, body) = rest_request(
                address,
                "GET",
                &format!("/v1/projects/demo-app/topics?pageSize=1&{invalid}"),
                json!({}),
            )
            .await;
            if policy == PagingPolicy::Emulator {
                assert_eq!(status, 200, "{invalid}: {body}");
                assert_eq!(body["topics"].as_array().unwrap().len(), 1, "{invalid}");
                assert!(body["nextPageToken"].is_string());
            } else {
                assert_eq!(status, 400, "{invalid}: {body}");
                assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
            }
        }
    }
}

#[tokio::test]
async fn missing_topic_lists_preserve_profile_refusals_on_both_transports() {
    use fireemu_adapter_pubsub::PagingPolicy;
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        let address = start_policy(policy).await;
        let mut publisher = PublisherClient::new(grpc_channel(address).await);
        let topic = "projects/demo-app/topics/missing-matrix";
        for collection in ["subscriptions", "snapshots"] {
            let (status, body) = rest_request(
                address,
                "GET",
                &format!("/v1/{topic}/{collection}"),
                json!({}),
            )
            .await;
            if policy == PagingPolicy::Strict {
                assert_eq!(status, 404);
                assert_eq!(
                    body["error"]["message"],
                    "Resource not found (resource=missing-matrix)."
                );
            } else {
                assert_eq!(status, 200);
                assert_eq!(body, json!({}));
            }
        }
        let subscriptions = publisher
            .list_topic_subscriptions(pb::ListTopicSubscriptionsRequest {
                topic: topic.into(),
                ..Default::default()
            })
            .await;
        let snapshots = publisher
            .list_topic_snapshots(pb::ListTopicSnapshotsRequest {
                topic: topic.into(),
                ..Default::default()
            })
            .await;
        if policy == PagingPolicy::Strict {
            for error in [subscriptions.unwrap_err(), snapshots.unwrap_err()] {
                assert_eq!(error.code(), tonic::Code::NotFound);
                assert_eq!(
                    error.message(),
                    "Resource not found (resource=missing-matrix)."
                );
            }
        } else {
            let subscriptions = subscriptions.unwrap().into_inner();
            let snapshots = snapshots.unwrap().into_inner();
            assert!(
                subscriptions.subscriptions.is_empty() && subscriptions.next_page_token.is_empty()
            );
            assert!(snapshots.snapshots.is_empty() && snapshots.next_page_token.is_empty());
        }
    }
}

#[tokio::test]
async fn native_push_create_version_and_unary_pull_are_profile_scoped() {
    use fireemu_adapter_pubsub::PagingPolicy;
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        let address = start_policy(policy).await;
        let topic = "projects/demo-app/topics/native-push-version";
        assert_eq!(
            rest_request(address, "PUT", &format!("/v1/{topic}"), json!({}))
                .await
                .0,
            200
        );
        let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
        let name = "projects/demo-app/subscriptions/native-push-version";
        let created = subscriber
            .create_subscription(pb::Subscription {
                name: name.into(),
                topic: topic.into(),
                push_config: Some(pb::PushConfig {
                    push_endpoint: "https://example.com/push".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        let attributes = created.push_config.unwrap().attributes;
        if policy == PagingPolicy::Strict {
            assert_eq!(
                attributes.get("x-goog-version").map(String::as_str),
                Some("v1")
            );
        } else {
            assert!(attributes.is_empty());
        }
        let fetched = subscriber
            .get_subscription(pb::GetSubscriptionRequest {
                subscription: name.into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(fetched.push_config.unwrap().attributes.is_empty());
        let native = subscriber
            .pull(pb::PullRequest {
                subscription: name.into(),
                max_messages: 1,
                ..Default::default()
            })
            .await;
        let (status, body) = rest_request(
            address,
            "POST",
            &format!("/v1/{name}:pull"),
            json!({"maxMessages":1}),
        )
        .await;
        if policy == PagingPolicy::Strict {
            let error = native.unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert_eq!(
                error.message(),
                "This method is not supported for this subscription type."
            );
            assert_eq!(status, 400);
            assert_eq!(body["error"]["message"], error.message());
        } else {
            assert!(native.unwrap().into_inner().received_messages.is_empty());
            assert_eq!(status, 200);
            assert_eq!(body, json!({}));
        }
    }
}

/// The exact defaults are the recorded production REST response of a created pull subscription: see
/// `subscription_json` in `src/rest.rs` for the captures (run shape-001-6a666e3ffa9444cc80de18944b38ae36
/// on fireemu-oracle-idp, and the fireemu-oracle-sbx recorded-shape-responses). Capture-only evidence.
#[tokio::test]
async fn recorded_rest_bootstrap_pull_subscription_has_exact_defaults() {
    let address = start().await;
    let topic = "projects/demo-app/topics/bootstrap-defaults";
    let subscription = "projects/demo-app/subscriptions/bootstrap-defaults-sub";
    let (status, _) = rest_request(address, "PUT", &format!("/v1/{topic}"), json!({})).await;
    assert_eq!(status, 200);
    let expected = json!({
        "name": subscription, "topic": topic, "pushConfig": {}, "ackDeadlineSeconds": 60,
        "messageRetentionDuration": "604800s", "expirationPolicy": {"ttl": "2678400s"}, "state": "ACTIVE",
    });
    let (status, created) = rest_request(
        address,
        "PUT",
        &format!("/v1/{subscription}"),
        json!({"topic": topic, "ackDeadlineSeconds": 60}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(created, expected);
    let (status, fetched) =
        rest_request(address, "GET", &format!("/v1/{subscription}"), json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(fetched, expected);
    for resource in [subscription, topic] {
        let (status, deleted) =
            rest_request(address, "DELETE", &format!("/v1/{resource}"), json!({})).await;
        assert_eq!(status, 200);
        assert_eq!(deleted, json!({}));
        let (status, absent) =
            rest_request(address, "GET", &format!("/v1/{resource}"), json!({})).await;
        assert_eq!(status, 404);
        let leaf = resource.rsplit('/').next().unwrap();
        assert_eq!(
            absent,
            json!({"error": {
                "code": 404, "message": format!("Resource not found (resource={leaf})."), "status": "NOT_FOUND",
            }})
        );
    }
    for collection in ["topics", "subscriptions"] {
        let (status, body) = rest_request(
            address,
            "GET",
            &format!("/v1/projects/demo-app/{collection}"),
            json!({}),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({}));
    }
}

#[tokio::test]
async fn recorded_rest_bootstrap_missing_get_uses_leaf_resource_error() {
    let address = start().await;
    for collection in ["topics", "subscriptions"] {
        let leaf = "bootstrap-never-created";
        let (status, error) = rest_request(
            address,
            "GET",
            &format!("/v1/projects/demo-app/{collection}/{leaf}"),
            json!({}),
        )
        .await;
        assert_eq!(status, 404);
        assert_eq!(
            error,
            json!({"error": {
                "code": 404, "message": format!("Resource not found (resource={leaf})."), "status": "NOT_FOUND",
            }})
        );
    }
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
    for (id, options, field) in cases
        .into_iter()
        .filter(|(_, _, field)| *field != "message_retention_duration")
    {
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
                "pushConfig": {"pushEndpoint": "not a url"}
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
    assert_eq!(
        after, created,
        "a rejected update must preserve every field"
    );
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
                "subscription": {"retryPolicy": {"minimumBackoff": "601s"}},
                "updateMask": "retryPolicy"
            }),
            400,
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
                    push_endpoint: "not a url".to_owned(),
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
    assert_eq!(
        reset["pushConfig"],
        json!({"attributes":{"x-goog-version":"v1"}})
    );

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
    assert_eq!(
        reset.push_config,
        Some(pb::PushConfig {
            attributes: [("x-goog-version".into(), "v1".into())].into(),
            ..Default::default()
        })
    );
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

/// One subscription option unsupported on update (and, except retention, on create): its JSON name, its protobuf name, the JSON value a REST
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

    for (index, (json_field, proto_field, value, set)) in unsupported_subscription_options()
        .into_iter()
        .filter(|(_, field, _, _)| {
            ![
                "retain_acked_messages",
                "message_retention_duration",
                "labels",
                "expiration_policy",
                "state",
            ]
            .contains(field)
        })
        .enumerate()
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
        listed,
        json!({}),
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

    for (json_field, proto_field, value, set) in unsupported_subscription_options()
        .into_iter()
        .filter(|(_, field, _, _)| {
            ![
                "retain_acked_messages",
                "message_retention_duration",
                "labels",
                "expiration_policy",
            ]
            .contains(field)
        })
    {
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
    // The proto defines mode-independent policy defaults and output-only ACTIVE state.
    // These fixed REST metadata values do not enable unsupported mutation inputs.
    assert_eq!(from_get["messageRetentionDuration"], "604800s", "{id}");
    assert_eq!(
        from_get["expirationPolicy"],
        json!({"ttl": "2678400s"}),
        "{id}"
    );
    assert_eq!(from_get["state"], "ACTIVE", "{id}");
    for unsupported in [
        "bigqueryConfig",
        "cloudStorageConfig",
        "bigtableConfig",
        "retainAckedMessages",
        "labels",
        "detached",
        "enableExactlyOnceDelivery",
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
    assert_eq!(
        grpc_get
            .message_retention_duration
            .as_ref()
            .unwrap()
            .seconds,
        604_800,
        "{id}"
    );
    assert!(grpc_get.labels.is_empty(), "{id}");
    assert_eq!(
        grpc_get
            .expiration_policy
            .as_ref()
            .unwrap()
            .ttl
            .as_ref()
            .unwrap()
            .seconds,
        2_678_400,
        "{id}"
    );
    assert!(!grpc_get.detached, "{id}");
    assert!(!grpc_get.enable_exactly_once_delivery, "{id}");
    assert!(grpc_get.bigquery_config.is_none(), "{id}");
    assert!(grpc_get.cloud_storage_config.is_none(), "{id}");
    assert!(grpc_get.bigtable_config.is_none(), "{id}");
    assert!(grpc_get.message_transforms.is_empty(), "{id}");
    assert!(grpc_get.tags.is_empty(), "{id}");
    assert_eq!(
        grpc_get.state,
        pb::subscription::State::Active as i32,
        "{id}"
    );
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

    for (index, (json_field, proto_field, value, set)) in unsupported_topic_options()
        .into_iter()
        .filter(|(_, field, _, _)| *field != "message_retention_duration")
        .enumerate()
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
    assert_eq!(status, 400, "{error}");
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
    assert_eq!(grpc_error.code(), tonic::Code::InvalidArgument);
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

#[tokio::test]
async fn rest_collection_fields_follow_cardinality_on_the_pubsub_listener() {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_700_000_000),
    )));
    let handle = PubSubHandle::new(Arc::new(Mutex::new(PubSubState::new(99))), clock, None);
    let port = std::env::var("PORT").unwrap_or_else(|_| "0".to_owned());
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_pubsub(listener, handle));

    // Exhaust a small cardinality model and sample larger collections reproducibly.
    let generated_counts = (0..12).scan(0x5eed_u64, |seed, _| {
        *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        Some(((*seed >> 32) % 8) as usize)
    });
    for (case, count) in (0..=3).chain(generated_counts).enumerate() {
        let project = format!("list-cardinality-{case}");
        let topics_path = format!("/v1/projects/{project}/topics");
        let subscriptions_path = format!("/v1/projects/{project}/subscriptions");
        for path in [&topics_path, &subscriptions_path] {
            let (status, body) = rest_request_raw(address, "GET", path, json!({})).await;
            assert_eq!(status, 200);
            assert_eq!(body, b"{}", "fresh collection: {path}");
        }
        for id in 0..count {
            let topic_name = format!("projects/{project}/topics/topic-{id}");
            let (status, _) =
                rest_request(address, "PUT", &format!("/v1/{topic_name}"), json!({})).await;
            assert_eq!(status, 200);
            let (status, _) = rest_request(
                address,
                "PUT",
                &format!("{subscriptions_path}/sub-{id}"),
                json!({"topic": topic_name}),
            )
            .await;
            assert_eq!(status, 200);
        }
        for (path, field, prefix) in [
            (&topics_path, "topics", "topic"),
            (&subscriptions_path, "subscriptions", "sub"),
        ] {
            let (status, response) = rest_request(address, "GET", path, json!({})).await;
            assert_eq!(status, 200);
            let object = response.as_object().unwrap();
            assert!(!object.contains_key("nextPageToken"));
            if count == 0 {
                assert!(object.is_empty());
            } else {
                assert_eq!(object.len(), 1);
                let resources = response[field].as_array().unwrap();
                assert_eq!(resources.len(), count);
                for id in 0..count {
                    let name = format!("projects/{project}/{field}/{prefix}-{id}");
                    assert!(resources.iter().any(|resource| resource["name"] == name));
                }
            }
        }
        for id in 0..count {
            for path in [
                format!("{subscriptions_path}/sub-{id}"),
                format!("{topics_path}/topic-{id}"),
            ] {
                let (status, _) = rest_request(address, "DELETE", &path, json!({})).await;
                assert_eq!(status, 200);
            }
        }
        for path in [&topics_path, &subscriptions_path] {
            let (status, body) = rest_request_raw(address, "GET", path, json!({})).await;
            assert_eq!(status, 200);
            assert_eq!(body, b"{}", "deleted collection: {path}");
        }
    }
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn recorded_rest_paging_omits_empty_snapshots_and_validates_size_and_token() {
    let address = start().await;
    let (status, body) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/snapshots?pageSize=1",
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, json!({}));
    for collection in ["topics", "subscriptions"] {
        let (status, body) = rest_request(
            address,
            "GET",
            &format!("/v1/projects/demo-app/{collection}?pageSize=-1"),
            json!({}),
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(body["error"]["message"], "The value for page_size is out of bounds. You passed -1 in the request, but the value must be between 0 and 1000.");
        let (status, body) = rest_request(
            address,
            "GET",
            &format!("/v1/projects/demo-app/{collection}?pageToken=garbage"),
            json!({}),
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(
            body["error"]["message"],
            "Invalid page token given (token=garbage)."
        );
    }
}

#[tokio::test]
async fn recorded_rest_topic_subscriptions_share_cursor_with_grpc_project_list() {
    let address = start().await;
    let topic = "projects/demo-app/topics/paging";
    assert_eq!(
        rest_request(address, "PUT", &format!("/v1/{topic}"), json!({}))
            .await
            .0,
        200
    );
    for suffix in ["a", "b", "c"] {
        assert_eq!(
            rest_request(
                address,
                "PUT",
                &format!("/v1/projects/demo-app/subscriptions/paging-{suffix}"),
                json!({"topic":topic})
            )
            .await
            .0,
            200
        );
    }
    let (status, first) = rest_request(
        address,
        "GET",
        &format!("/v1/{topic}/subscriptions?pageSize=2"),
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(first["subscriptions"].as_array().unwrap().len(), 2);
    let token = first["nextPageToken"].as_str().unwrap();
    assert!((22..=26).contains(&token.len()));
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let second = subscriber
        .list_subscriptions(pb::ListSubscriptionsRequest {
            project: "projects/demo-app".into(),
            page_size: 2,
            page_token: token.into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second.subscriptions.len(), 1);
    assert_eq!(
        second.subscriptions[0].name,
        "projects/demo-app/subscriptions/paging-c"
    );
    assert!(second.next_page_token.is_empty());
    let (status, all) = rest_request(
        address,
        "GET",
        &format!("/v1/{topic}/subscriptions?pageSize=0"),
        json!({}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(all["subscriptions"].as_array().unwrap().len(), 3);
    assert!(all.get("nextPageToken").is_none());
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One partition check per list route and both wire profiles.
async fn both_profiles_page_all_five_lists_and_preserve_deleted_topic_marker() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let mut publisher = PublisherClient::new(grpc_channel(address).await);
        let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
        let topic = "projects/demo-app/topics/paging-topic";
        publisher
            .create_topic(pb::Topic {
                name: topic.into(),
                ..Default::default()
            })
            .await
            .unwrap();
        for suffix in ["a", "b", "c"] {
            publisher
                .create_topic(pb::Topic {
                    name: format!("{topic}-{suffix}"),
                    ..Default::default()
                })
                .await
                .unwrap();
            let name = format!("projects/demo-app/subscriptions/paging-{suffix}");
            subscriber
                .create_subscription(pb::Subscription {
                    name: name.clone(),
                    topic: topic.into(),
                    ..Default::default()
                })
                .await
                .unwrap();
            subscriber
                .create_snapshot(pb::CreateSnapshotRequest {
                    name: format!("projects/demo-app/snapshots/paging-{suffix}"),
                    subscription: name,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let routes = [
            ("projects/demo-app/topics".to_owned(), "topics", 4usize),
            (
                "projects/demo-app/subscriptions".to_owned(),
                "subscriptions",
                3,
            ),
            ("projects/demo-app/snapshots".to_owned(), "snapshots", 3),
            (format!("{topic}/subscriptions"), "subscriptions", 3),
            (format!("{topic}/snapshots"), "snapshots", 3),
        ];
        for (route, field, count) in routes {
            let (status, all) = rest_request(
                address,
                "GET",
                &format!("/v1/{route}?pageSize=0"),
                json!({}),
            )
            .await;
            assert_eq!(status, 200);
            let expected = all[field].as_array().unwrap().clone();
            assert_eq!(expected.len(), count);
            let mut actual = Vec::new();
            let mut token = String::new();
            for _ in 0..count {
                let (status, page) = rest_request(
                    address,
                    "GET",
                    &format!("/v1/{route}?pageSize=1&pageToken={token}"),
                    json!({}),
                )
                .await;
                assert_eq!(status, 200);
                actual.extend(page[field].as_array().unwrap().clone());
                token = page
                    .get("nextPageToken")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if token.is_empty() {
                    break;
                }
            }
            assert_eq!(actual, expected, "{policy:?} {route}");
        }
        let topics = publisher
            .list_topics(pb::ListTopicsRequest {
                project: "projects/demo-app".into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(topics.topics.len(), 1);
        assert!(!topics.next_page_token.is_empty());
        let subscriptions = subscriber
            .list_subscriptions(pb::ListSubscriptionsRequest {
                project: "projects/demo-app".into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(subscriptions.subscriptions.len(), 1);
        let topic_subs = publisher
            .list_topic_subscriptions(pb::ListTopicSubscriptionsRequest {
                topic: topic.into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(topic_subs.subscriptions.len(), 1);
        assert_eq!(subscriptions.next_page_token, topic_subs.next_page_token);
        let snapshots = subscriber
            .list_snapshots(pb::ListSnapshotsRequest {
                project: "projects/demo-app".into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(snapshots.snapshots.len(), 1);
        let topic_snaps = publisher
            .list_topic_snapshots(pb::ListTopicSnapshotsRequest {
                topic: topic.into(),
                page_size: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(topic_snaps.snapshots.len(), 1);
        assert_eq!(snapshots.next_page_token, topic_snaps.next_page_token);
        let negative = publisher
            .list_topics(pb::ListTopicsRequest {
                project: "projects/demo-app".into(),
                page_size: -1,
                ..Default::default()
            })
            .await;
        if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            let error = negative.unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert_eq!(error.message(),"The value for page_size is out of bounds. You passed -1 in the request, but the value must be between 0 and 1000.");
            let error = publisher
                .list_topics(pb::ListTopicsRequest {
                    project: "projects/demo-app".into(),
                    page_token: "garbage".into(),
                    ..Default::default()
                })
                .await
                .unwrap_err();
            assert_eq!(error.message(), "Invalid page token given (token=garbage).");
        } else {
            assert_eq!(negative.unwrap().into_inner().topics.len(), 4);
            assert!(publisher
                .list_topics(pb::ListTopicsRequest {
                    project: "projects/demo-app".into(),
                    page_token: "garbage".into(),
                    ..Default::default()
                })
                .await
                .is_ok());
        }
        publisher
            .delete_topic(pb::DeleteTopicRequest {
                topic: topic.into(),
            })
            .await
            .unwrap();
        let subscription = subscriber
            .get_subscription(pb::GetSubscriptionRequest {
                subscription: "projects/demo-app/subscriptions/paging-a".into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(subscription.topic, "_deleted-topic_");
        publisher
            .create_topic(pb::Topic {
                name: topic.into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let (status, subscription) = rest_request(
            address,
            "GET",
            "/v1/projects/demo-app/subscriptions/paging-a",
            json!({}),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(subscription["topic"], "_deleted-topic_");
        let detached = publisher
            .list_topic_subscriptions(pb::ListTopicSubscriptionsRequest {
                topic: topic.into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert!(detached.subscriptions.is_empty());
    }
}

/// Production runs148026092d56/a8ed1cce53f0: plain topic and subscription responses.
#[tokio::test]
async fn recorded_both_transports_omit_empty_labels_and_return_subscription_defaults() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let topic = "projects/demo-app/topics/recorded-defaults";
        let subscription = "projects/demo-app/subscriptions/recorded-defaults";
        let (code, created) =
            rest_request(address, "PUT", &format!("/v1/{topic}"), json!({})).await;
        assert_eq!(code, 200);
        assert_eq!(created, json!({"name":topic}));
        let (code, created) = rest_request(
            address,
            "PUT",
            &format!("/v1/{subscription}"),
            json!({"topic":topic,"ackDeadlineSeconds":10}),
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(created["pushConfig"], json!({}));
        let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
        let got = subscriber
            .get_subscription(pb::GetSubscriptionRequest {
                subscription: subscription.to_owned(),
            })
            .await
            .unwrap()
            .into_inner();
        if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            assert_eq!(got.push_config, Some(pb::PushConfig::default()));
            assert_eq!(got.message_retention_duration.unwrap().seconds, 604_800);
            assert_eq!(
                got.expiration_policy.unwrap().ttl.unwrap().seconds,
                2_678_400
            );
            assert_eq!(got.state, pb::subscription::State::Active as i32);
        } else {
            assert!(got.push_config.is_none());
            assert!(got.message_retention_duration.is_none());
            assert!(got.expiration_policy.is_none());
        }
    }
}

#[tokio::test]
async fn recorded_grpc_missing_and_duplicate_resources_use_production_diagnostics() {
    let address = start().await;
    let mut publisher = PublisherClient::new(grpc_channel(address).await);
    let name = "projects/demo-app/topics/recorded-diagnostics";
    let error = publisher
        .get_topic(pb::GetTopicRequest {
            topic: name.to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        error.message(),
        "Resource not found (resource=recorded-diagnostics)."
    );
    publisher
        .create_topic(pb::Topic {
            name: name.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let error = publisher
        .create_topic(pb::Topic {
            name: name.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(
        error.message(),
        "Resource already exists in the project (resource=recorded-diagnostics)."
    );
    let (status, body) = rest_request(address, "PUT", &format!("/v1/{name}"), json!({})).await;
    assert_eq!(status, 409);
    assert_eq!(body["error"]["message"], error.message());
}

#[tokio::test]
async fn recorded_strict_unary_refusals_preserve_emulator_inputs() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let topic = "projects/demo-app/topics/recorded-admission";
        let sub = "projects/demo-app/subscriptions/recorded-admission";
        rest_request(address, "PUT", &format!("/v1/{topic}"), json!({})).await;
        rest_request(
            address,
            "PUT",
            &format!("/v1/{sub}"),
            json!({"topic":topic}),
        )
        .await;
        for (resource, verb, body) in [
            (sub, "pull", json!({"maxMessages":0})),
            (sub, "acknowledge", json!({"ackIds":[]})),
            (
                sub,
                "modifyAckDeadline",
                json!({"ackIds":["ack-0123456789abcdef"],"ackDeadlineSeconds":601}),
            ),
            (topic, "publish", json!({"messages":[]})),
        ] {
            let (code, _) =
                rest_request(address, "POST", &format!("/v1/{resource}:{verb}"), body).await;
            assert_eq!(
                code,
                if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
                    400
                } else {
                    200
                },
                "{verb}"
            );
        }
        let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
        let pulled = subscriber
            .pull(pb::PullRequest {
                subscription: sub.to_owned(),
                max_messages: 0,
                ..Default::default()
            })
            .await;
        let ack = subscriber
            .acknowledge(pb::AcknowledgeRequest {
                subscription: sub.to_owned(),
                ack_ids: vec![],
            })
            .await;
        let deadline = subscriber
            .modify_ack_deadline(pb::ModifyAckDeadlineRequest {
                subscription: sub.to_owned(),
                ack_ids: vec!["ack-0123456789abcdef".to_owned()],
                ack_deadline_seconds: 601,
            })
            .await;
        let mut publisher = PublisherClient::new(grpc_channel(address).await);
        let publish = publisher
            .publish(pb::PublishRequest {
                topic: topic.to_owned(),
                messages: vec![],
            })
            .await;
        assert_eq!(
            pulled.is_err(),
            policy == fireemu_adapter_pubsub::PagingPolicy::Strict
        );
        assert_eq!(
            ack.is_err(),
            policy == fireemu_adapter_pubsub::PagingPolicy::Strict
        );
        assert_eq!(
            deadline.is_err(),
            policy == fireemu_adapter_pubsub::PagingPolicy::Strict
        );
        assert_eq!(
            publish.is_err(),
            policy == fireemu_adapter_pubsub::PagingPolicy::Strict
        );
    }
}

#[tokio::test]
async fn strict_mixed_invalid_ack_is_atomic_and_stale_issued_ack_is_accepted() {
    let address = start().await;
    let mut publisher = PublisherClient::new(grpc_channel(address).await);
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let topic = "projects/demo-app/topics/atomic-ack";
    let sub = "projects/demo-app/subscriptions/atomic-ack";
    publisher
        .create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    subscriber
        .create_subscription(pb::Subscription {
            name: sub.to_owned(),
            topic: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    publisher
        .publish(pb::PublishRequest {
            topic: topic.to_owned(),
            messages: vec![pb::PubsubMessage {
                data: vec![1],
                ..Default::default()
            }],
        })
        .await
        .unwrap();
    let received = subscriber
        .pull(pb::PullRequest {
            subscription: sub.to_owned(),
            max_messages: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    let issued = received[0].ack_id.clone();
    let error = subscriber
        .acknowledge(pb::AcknowledgeRequest {
            subscription: sub.to_owned(),
            ack_ids: vec![issued.clone(), "not-an-ack-id".to_owned()],
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    subscriber
        .modify_ack_deadline(pb::ModifyAckDeadlineRequest {
            subscription: sub.to_owned(),
            ack_ids: vec![issued.clone()],
            ack_deadline_seconds: 0,
        })
        .await
        .unwrap();
    let redelivered = subscriber
        .pull(pb::PullRequest {
            subscription: sub.to_owned(),
            max_messages: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(redelivered.len(), 1);
    assert_eq!(redelivered[0].message, received[0].message);
    subscriber
        .acknowledge(pb::AcknowledgeRequest {
            subscription: sub.to_owned(),
            ack_ids: vec![issued],
        })
        .await
        .unwrap();
    subscriber
        .acknowledge(pb::AcknowledgeRequest {
            subscription: sub.to_owned(),
            ack_ids: vec![redelivered[0].ack_id.clone()],
        })
        .await
        .unwrap();
    let (code, empty) = rest_request(
        address,
        "POST",
        &format!("/v1/{sub}:pull"),
        json!({"maxMessages":1}),
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(empty, json!({}));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn recorded_opaque_ack_ids_roundtrip_across_both_wires_and_profiles() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let topic = "projects/demo-app/topics/wire-ack";
        let subscription = "projects/demo-app/subscriptions/wire-ack";
        assert_eq!(
            rest_request(address, "PUT", &format!("/v1/{topic}"), json!({}))
                .await
                .0,
            200
        );
        assert_eq!(
            rest_request(
                address,
                "PUT",
                &format!("/v1/{subscription}"),
                json!({"topic":topic})
            )
            .await
            .0,
            200
        );
        assert_eq!(
            rest_request(
                address,
                "POST",
                &format!("/v1/{topic}:publish"),
                json!({"messages":[{"data":"AQ=="}]})
            )
            .await
            .0,
            200
        );
        let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
        let first = subscriber
            .pull(pb::PullRequest {
                subscription: subscription.to_owned(),
                max_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .received_messages;
        let issued = &first[0].ack_id;
        let expected_length = if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            196
        } else {
            20
        };
        assert_eq!(issued.len(), expected_length);
        assert!(issued
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
        assert_eq!(
            rest_request(
                address,
                "POST",
                &format!("/v1/{subscription}:modifyAckDeadline"),
                json!({"ackIds":[issued],"ackDeadlineSeconds":0})
            )
            .await
            .0,
            200
        );
        let (code, second) = rest_request(
            address,
            "POST",
            &format!("/v1/{subscription}:pull"),
            json!({"maxMessages":1}),
        )
        .await;
        assert_eq!(code, 200);
        let renewed = second["receivedMessages"][0]["ackId"].as_str().unwrap();
        let rest_length = if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            195
        } else {
            20
        };
        assert_eq!(renewed.len(), rest_length);
        assert_ne!(renewed, issued);
        assert_eq!(
            second["receivedMessages"][0]["message"]["messageId"],
            first[0].message.as_ref().unwrap().message_id
        );
        subscriber
            .acknowledge(pb::AcknowledgeRequest {
                subscription: subscription.to_owned(),
                ack_ids: vec![issued.clone()],
            })
            .await
            .unwrap();
        assert_eq!(
            rest_request(
                address,
                "POST",
                &format!("/v1/{subscription}:modifyAckDeadline"),
                json!({"ackIds":[renewed],"ackDeadlineSeconds":0})
            )
            .await
            .0,
            200
        );
        let (code, third) = rest_request(
            address,
            "POST",
            &format!("/v1/{subscription}:pull"),
            json!({"maxMessages":1}),
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(
            third["receivedMessages"][0]["message"]["messageId"],
            first[0].message.as_ref().unwrap().message_id
        );
        let current = third["receivedMessages"][0]["ackId"].as_str().unwrap();
        assert_ne!(current, renewed);
        assert_eq!(current.len(), rest_length);
        assert_eq!(
            rest_request(
                address,
                "POST",
                &format!("/v1/{subscription}:acknowledge"),
                json!({"ackIds":[current]})
            )
            .await
            .0,
            200
        );
        let (_, empty) = rest_request(
            address,
            "POST",
            &format!("/v1/{subscription}:pull"),
            json!({"maxMessages":1}),
        )
        .await;
        assert!(empty.get("receivedMessages").is_none());
    }
}

#[tokio::test]
async fn emulator_push_attributes_roundtrip_through_create_get_and_list_on_both_wires() {
    let address = start_policy(fireemu_adapter_pubsub::PagingPolicy::Emulator).await;
    let mut publisher = PublisherClient::new(grpc_channel(address).await);
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let topic = "projects/demo-app/topics/push-roundtrip";
    publisher
        .create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    for (index, native) in [true, false].into_iter().enumerate() {
        let name = format!("projects/demo-app/subscriptions/push-roundtrip-{index}");
        if native {
            subscriber
                .create_subscription(pb::Subscription {
                    name: name.clone(),
                    topic: topic.to_owned(),
                    push_config: Some(pb::PushConfig {
                        push_endpoint: "https://example.com/push".to_owned(),
                        attributes: [("x-goog-version".to_owned(), "v1".to_owned())].into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .await
                .unwrap();
        } else {
            assert_eq!(rest_request(address,"PUT",&format!("/v1/{name}"),json!({"topic":topic,"pushConfig":{"pushEndpoint":"https://example.com/push","attributes":{"x-goog-version":"v1"}}})).await.0,200);
        }
        let native = subscriber
            .get_subscription(pb::GetSubscriptionRequest {
                subscription: name.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            native.push_config.unwrap().attributes["x-goog-version"],
            "v1"
        );
        let (_, rest) = rest_request(address, "GET", &format!("/v1/{name}"), json!({})).await;
        assert_eq!(rest["pushConfig"]["attributes"]["x-goog-version"], "v1");
    }
    let (_, list) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/subscriptions",
        json!({}),
    )
    .await;
    assert_eq!(list["subscriptions"].as_array().unwrap().len(), 2);
    for item in list["subscriptions"].as_array().unwrap() {
        assert_eq!(item["pushConfig"]["attributes"]["x-goog-version"], "v1");
    }
}

#[tokio::test]
async fn recorded_unknown_get_routes_return_html_only_in_strict() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        for (path, expected) in [
            (
                "/v1/projects/demo-app/topic/x",
                include_bytes!("fixtures/missing-topic-route.html").as_slice(),
            ),
            (
                "/v1/topics/x",
                include_bytes!("fixtures/missing-project-route.html").as_slice(),
            ),
        ] {
            let (status, body) = rest_request_raw(address, "GET", path, json!({})).await;
            assert_eq!(status, 404);
            if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
                assert_eq!(body, expected);
            } else {
                assert_eq!(
                    serde_json::from_slice::<Value>(&body).unwrap()["error"]["status"],
                    "NOT_FOUND"
                );
            }
        }
        let (status, body) = rest_request(
            address,
            "GET",
            "/v1/projects/demo-app/topics/absent",
            json!({}),
        )
        .await;
        assert_eq!(status, 404);
        assert_eq!(
            body["error"]["message"],
            "Resource not found (resource=absent)."
        );
        let (status, body) = rest_request(address, "POST", "/v1/topics/x", json!({})).await;
        assert_eq!(status, 404);
        assert_eq!(body["error"]["status"], "NOT_FOUND");
    }
}

#[tokio::test]
async fn recorded_push_pull_and_filter_refusals_have_exact_rest_shapes() {
    let address = start().await;
    let topic = "projects/demo-app/topics/diagnostic-shapes";
    let sub = "projects/demo-app/subscriptions/diagnostic-shapes";
    assert_eq!(
        rest_request(address, "PUT", &format!("/v1/{topic}"), json!({}))
            .await
            .0,
        200
    );
    assert_eq!(
        rest_request(
            address,
            "PUT",
            &format!("/v1/{sub}"),
            json!({"topic":topic,"pushConfig":{"pushEndpoint":"https://example.com/push"}})
        )
        .await
        .0,
        200
    );
    let (status, body) = rest_request(
        address,
        "POST",
        &format!("/v1/{sub}:pull"),
        json!({"maxMessages":1}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body,
        json!({"error":{"code":400,"message":"This method is not supported for this subscription type.","status":"FAILED_PRECONDITION"}})
    );
    let (status, body) = rest_request(
        address,
        "PUT",
        "/v1/projects/demo-app/subscriptions/invalid-filter",
        json!({"topic":topic,"filter":"attributes.color == \"red\""}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body["error"]["details"],
        json!([{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"FILTER_EXPRESSION_FAILED_TO_PARSE","domain":"pubsub.googleapis.com","metadata":{"column":"19","line":"1","token":"=","message":"syntax error"}}])
    );
}

#[tokio::test]
async fn native_error_headers_preserve_recorded_anchors_and_missing_list_leaf() {
    use prost::Message as _;
    use tonic::codegen::Service as _;
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let mut channel = grpc_channel(address).await;
        let encoded = pb::GetTopicRequest {
            topic: "projects/demo-app/topics/goog-probe".to_owned(),
        }
        .encode_to_vec();
        let mut frame = vec![0];
        frame.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
        frame.extend(encoded);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "http://{address}/google.pubsub.v1.Publisher/GetTopic"
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(tonic::body::Body::new(axum::body::Body::from(frame)))
            .unwrap();
        std::future::poll_fn(|context| channel.poll_ready(context))
            .await
            .unwrap();
        let response = channel.call(request).await.unwrap();
        let message = response.headers()["grpc-message"].to_str().unwrap();
        if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            assert!(
                message.contains("pubsub-basics#resource_names"),
                "{message}"
            );
        } else {
            assert!(
                message.contains("pubsub-basics%23resource_names"),
                "{message}"
            );
        }
        if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            let mut publisher = PublisherClient::new(grpc_channel(address).await);
            let error = publisher
                .list_topic_subscriptions(pb::ListTopicSubscriptionsRequest {
                    topic: "projects/demo-app/topics/absent-list".to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::NotFound);
            assert_eq!(
                error.message(),
                "Resource not found (resource=absent-list)."
            );
        }
    }
}

#[tokio::test]
async fn recorded_snapshot_and_seek_refusals_preserve_profile_diagnostics() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let topic = "projects/demo-app/topics/snapshot-errors";
        let sub = "projects/demo-app/subscriptions/snapshot-errors";
        assert_eq!(
            rest_request(address, "PUT", &format!("/v1/{topic}"), json!({}))
                .await
                .0,
            200
        );
        assert_eq!(
            rest_request(
                address,
                "PUT",
                &format!("/v1/{sub}"),
                json!({"topic":topic})
            )
            .await
            .0,
            200
        );
        let snapshot = "projects/demo-app/snapshots/goog-probe";
        let (_, body) = rest_request(
            address,
            "PUT",
            &format!("/v1/{snapshot}"),
            json!({"subscription":sub}),
        )
        .await;
        let expected_name = if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            format!("Invalid resource name given (name={snapshot}). Refer to https://cloud.google.com/pubsub/docs/pubsub-basics#resource_names for more information.")
        } else {
            "snapshot id must not start with the reserved prefix 'goog'".to_owned()
        };
        assert_eq!(body["error"]["message"], expected_name);
        let mut native = SubscriberClient::new(grpc_channel(address).await);
        let error = native
            .create_snapshot(pb::CreateSnapshotRequest {
                name: snapshot.into(),
                subscription: sub.into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.message(), expected_name);
        let expected_seek = if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            "No target was specified in the SeekRequest. Must specify either a time or a snapshot."
        } else {
            "seek requires a time or a snapshot"
        };
        let (_, body) = rest_request(address, "POST", &format!("/v1/{sub}:seek"), json!({})).await;
        assert_eq!(body["error"]["message"], expected_seek);
        let error = native
            .seek(pb::SeekRequest {
                subscription: sub.into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.message(), expected_seek);
        let (_, body) = rest_request(
            address,
            "POST",
            &format!("/v1/{sub}:seek"),
            json!({"snapshot":"projects/demo-app/snapshots/absent","time":"2000-01-01T00:00:00Z"}),
        )
        .await;
        if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            let descriptions =
                ["Invalid value (oneof), oneof field 'target' is already set. Cannot set 'time'", "Invalid JSON payload received. Unknown name \"subscription\": Root element must be a message."];
            assert_eq!(body["error"]["message"], descriptions.join("\n"));
            assert_eq!(
                body["error"]["details"],
                json!([{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":descriptions.map(|description|json!({"description":description}))}])
            );
        } else {
            assert_eq!(
                body["error"]["message"],
                "seek takes either a time or a snapshot"
            );
        }
        assert_eq!(
            rest_request(
                address,
                "POST",
                &format!("/v1/{sub}:pull"),
                json!({"maxMessages":1})
            )
            .await
            .1,
            json!({})
        );
    }
}

#[allow(clippy::too_many_lines)]
async fn streaming_update_case(
    policy: fireemu_adapter_pubsub::PagingPolicy,
    deadline: Option<i32>,
    expected_error: Option<&str>,
) {
    use std::time::Duration;
    use tokio_stream::wrappers::ReceiverStream;
    let address = start_policy(policy).await;
    let mut publisher = PublisherClient::new(grpc_channel(address).await);
    let mut subscriber = SubscriberClient::new(grpc_channel(address).await);
    let topic = "projects/demo-app/topics/stream-update";
    let sub = "projects/demo-app/subscriptions/stream-update";
    publisher
        .create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    subscriber
        .create_subscription(pb::Subscription {
            name: sub.to_owned(),
            topic: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    let initial = publisher
        .publish(pb::PublishRequest {
            topic: topic.to_owned(),
            messages: vec![pb::PubsubMessage {
                data: b"owned".to_vec(),
                ..Default::default()
            }],
        })
        .await
        .unwrap()
        .into_inner();
    let (requests, inbound) = tokio::sync::mpsc::channel(8);
    requests
        .send(pb::StreamingPullRequest {
            subscription: sub.to_owned(),
            stream_ack_deadline_seconds: 10,
            max_outstanding_messages: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    let mut outbound = subscriber
        .streaming_pull(ReceiverStream::new(inbound))
        .await
        .unwrap()
        .into_inner();
    let received = tokio::time::timeout(Duration::from_secs(2), outbound.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.received_messages.len(), 1);
    assert_eq!(
        received.received_messages[0]
            .message
            .as_ref()
            .unwrap()
            .message_id,
        initial.message_ids[0]
    );
    let mut ack = received.received_messages[0].ack_id.clone();
    requests
        .send(pb::StreamingPullRequest {
            modify_deadline_ack_ids: vec![ack.clone()],
            modify_deadline_seconds: deadline.into_iter().collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    if let Some(details) = expected_error {
        let error = tokio::time::timeout(Duration::from_millis(500), outbound.message())
            .await
            .expect("invalid update must terminate without client cancellation")
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(error.message(), details);
        assert!(
            tokio::time::timeout(Duration::from_millis(500), outbound.message())
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        subscriber
            .modify_ack_deadline(pb::ModifyAckDeadlineRequest {
                subscription: sub.to_owned(),
                ack_ids: vec![ack],
                ack_deadline_seconds: 0,
            })
            .await
            .unwrap();
        let retained = subscriber
            .pull(pb::PullRequest {
                subscription: sub.to_owned(),
                max_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(retained.received_messages.len(), 1);
        assert_eq!(
            retained.received_messages[0]
                .message
                .as_ref()
                .unwrap()
                .message_id,
            initial.message_ids[0]
        );
    } else {
        if deadline == Some(0) {
            let redelivery = tokio::time::timeout(Duration::from_secs(2), outbound.message())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                redelivery.received_messages[0]
                    .message
                    .as_ref()
                    .unwrap()
                    .message_id,
                initial.message_ids[0]
            );
            ack.clone_from(&redelivery.received_messages[0].ack_id);
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), outbound.message())
                    .await
                    .is_err()
            );
        }
        requests
            .send(pb::StreamingPullRequest {
                ack_ids: vec![ack],
                ..Default::default()
            })
            .await
            .unwrap();
        let next = publisher
            .publish(pb::PublishRequest {
                topic: topic.to_owned(),
                messages: vec![pb::PubsubMessage {
                    data: b"next".to_vec(),
                    ..Default::default()
                }],
            })
            .await
            .unwrap()
            .into_inner();
        let delivered = tokio::time::timeout(Duration::from_secs(2), outbound.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            delivered.received_messages[0]
                .message
                .as_ref()
                .unwrap()
                .message_id,
            next.message_ids[0]
        );
    }
}

#[tokio::test]
async fn recorded_streaming_update_refusals_preserve_emulator_inputs() {
    use fireemu_adapter_pubsub::PagingPolicy;
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        streaming_update_case(policy, None, (policy == PagingPolicy::Strict).then_some(
            "Invalid arguments provided: the number of ack ids to modify must be equal to the number of ack deadlines."
        )).await;
    }
}

#[tokio::test]
async fn recorded_streaming_deadline_601_refusal_preserves_emulator_input() {
    use fireemu_adapter_pubsub::PagingPolicy;
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        streaming_update_case(policy, Some(601), (policy == PagingPolicy::Strict).then_some(
            "Invalid ack deadline given (ack_deadline=601). The ack deadline must be between 0 and 600 seconds."
        )).await;
    }
}

#[tokio::test]
async fn valid_streaming_deadline_bounds_keep_owned_ack_delivery() {
    use fireemu_adapter_pubsub::PagingPolicy;
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        for deadline in [0, 600] {
            streaming_update_case(policy, Some(deadline), None).await;
        }
    }
}
#[tokio::test]
async fn strict_create_topic_uses_route_name_and_keeps_body_name_absent() {
    let address = start().await;
    let route = "projects/demo-app/topics/route-topic";
    let body_name = "projects/demo-app/topics/body-topic";
    let (status, created) = rest_request(
        address,
        "PUT",
        &format!("/v1/{route}"),
        json!({"name": body_name}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(created, json!({"name": route}));
    let (status, found) = rest_request(address, "GET", &format!("/v1/{route}"), json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(found, created);
    assert_eq!(
        rest_request(address, "GET", &format!("/v1/{body_name}"), json!({}))
            .await
            .0,
        404
    );
    assert_eq!(
        rest_request(address, "DELETE", &format!("/v1/{route}"), json!({})).await,
        (200, json!({}))
    );
    assert_eq!(
        rest_request(address, "GET", &format!("/v1/{route}"), json!({}))
            .await
            .0,
        404
    );
}

#[tokio::test]
async fn strict_create_subscription_uses_route_identity_and_existing_storage() {
    let address = start().await;
    let topic = "projects/demo-app/topics/route-sub-topic";
    let route = "projects/demo-app/subscriptions/route-sub";
    let body_name = "projects/demo-app/subscriptions/body-sub";
    assert_eq!(
        rest_request(address, "PUT", &format!("/v1/{topic}"), json!({}))
            .await
            .0,
        200
    );
    let (status, created) = rest_request(
        address,
        "PUT",
        &format!("/v1/{route}"),
        json!({"name":body_name,"topic":topic}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        created,
        json!({"name":route,"topic":topic,"pushConfig":{},"ackDeadlineSeconds":10,
        "messageRetentionDuration":"604800s","expirationPolicy":{"ttl":"2678400s"},"state":"ACTIVE"})
    );
    assert_eq!(
        rest_request(address, "GET", &format!("/v1/{body_name}"), json!({}))
            .await
            .0,
        404
    );
    assert_eq!(
        rest_request(address, "DELETE", &format!("/v1/{topic}"), json!({}))
            .await
            .0,
        200
    );
    let (status, retained) = rest_request(address, "GET", &format!("/v1/{route}"), json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(retained["name"], route);
    assert_eq!(retained["topic"], "_deleted-topic_");
    assert_eq!(
        rest_request(address, "DELETE", &format!("/v1/{route}"), json!({})).await,
        (200, json!({}))
    );
    assert_eq!(
        rest_request(address, "GET", &format!("/v1/{route}"), json!({}))
            .await
            .0,
        404
    );
}
#[tokio::test]
async fn create_route_precedence_keeps_type_and_field_validation() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let topic = "projects/demo-app/topics/name-guards";
        let subscription = "projects/demo-app/subscriptions/name-guards";
        assert_eq!(
            rest_request(address, "PUT", &format!("/v1/{topic}"), json!({}))
                .await
                .0,
            200
        );
        assert_eq!(
            rest_request(
                address,
                "PUT",
                &format!("/v1/{subscription}"),
                json!({"topic":topic})
            )
            .await
            .0,
            200
        );
        for name in [Value::Null, json!(7), json!([]), json!({})] {
            for (route, body) in [
                (topic, json!({"name":name})),
                (subscription, json!({"name":name,"topic":topic})),
            ] {
                assert_eq!(
                    rest_request(address, "PUT", &format!("/v1/{route}"), body)
                        .await
                        .0,
                    400
                );
            }
        }
        for (route, body) in [
            (topic, json!({"unknownField":true})),
            (subscription, json!({"topic":topic,"unknownField":true})),
            (
                topic,
                json!({"messageRetentionDuration":"600s","message_retention_duration":"600s"}),
            ),
            (
                subscription,
                json!({"topic":topic,"ackDeadlineSeconds":10,"ack_deadline_seconds":10}),
            ),
        ] {
            assert_eq!(
                rest_request(address, "PUT", &format!("/v1/{route}"), body)
                    .await
                    .0,
                400
            );
        }
    }
}

#[tokio::test]
async fn route_name_precedence_does_not_widen_patch_or_emulator_create() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let topic = "projects/demo-app/topics/scoped-name";
        let subscription = "projects/demo-app/subscriptions/scoped-name";
        assert_eq!(
            rest_request(address, "PUT", &format!("/v1/{topic}"), json!({}))
                .await
                .0,
            200
        );
        assert_eq!(
            rest_request(
                address,
                "PUT",
                &format!("/v1/{subscription}"),
                json!({"topic":topic})
            )
            .await
            .0,
            200
        );
        for (route, body) in [
            (
                topic,
                json!({"topic":{"name":"projects/demo-app/topics/other"},"updateMask":"labels"}),
            ),
            (
                subscription,
                json!({"subscription":{"name":"projects/demo-app/subscriptions/other","ackDeadlineSeconds":20},"updateMask":"ackDeadlineSeconds"}),
            ),
        ] {
            assert_eq!(
                rest_request(address, "PATCH", &format!("/v1/{route}"), body)
                    .await
                    .0,
                400
            );
        }
        if policy == fireemu_adapter_pubsub::PagingPolicy::Emulator {
            for (route, body) in [
                (topic, json!({"name":"projects/demo-app/topics/other"})),
                (
                    subscription,
                    json!({"name":"projects/demo-app/subscriptions/other","topic":topic}),
                ),
            ] {
                assert_eq!(
                    rest_request(address, "PUT", &format!("/v1/{route}"), body)
                        .await
                        .0,
                    400
                );
            }
        }
    }
}

/// A cursor issued before its boundary resource is deleted still selects current names after it.
#[tokio::test]
async fn issued_deleted_topic_cursor_continues_over_current_names() {
    let address = start().await;
    for id in ["cursor-a", "cursor-c", "cursor-e"] {
        assert_eq!(
            rest_request(
                address,
                "PUT",
                &format!("/v1/projects/demo-app/topics/{id}"),
                json!({})
            )
            .await
            .0,
            200
        );
    }
    let (code, first) = rest_request(
        address,
        "GET",
        "/v1/projects/demo-app/topics?pageSize=1",
        json!({}),
    )
    .await;
    assert_eq!(code, 200);
    let token = first["nextPageToken"].as_str().unwrap();
    let boundary = first["topics"][0]["name"].as_str().unwrap();
    assert_eq!(
        rest_request(address, "DELETE", &format!("/v1/{boundary}"), json!({}))
            .await
            .0,
        200
    );
    assert_eq!(
        rest_request(address, "GET", &format!("/v1/{boundary}"), json!({}))
            .await
            .0,
        404
    );
    assert_eq!(
        rest_request(
            address,
            "PUT",
            "/v1/projects/demo-app/topics/cursor-b",
            json!({})
        )
        .await
        .0,
        200
    );
    let (code, continued) = rest_request(
        address,
        "GET",
        &format!("/v1/projects/demo-app/topics?pageSize=0&pageToken={token}"),
        json!({}),
    )
    .await;
    assert_eq!(code, 200, "{continued}");
    assert_eq!(
        continued["topics"],
        json!([
            {"name":"projects/demo-app/topics/cursor-b"},
            {"name":"projects/demo-app/topics/cursor-c"},
            {"name":"projects/demo-app/topics/cursor-e"}
        ])
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn strict_seek_conflicts_preserve_request_order_and_present_fields() {
    let address = start().await;
    let path = "/v1/projects/demo-app/subscriptions/seek-errors:seek";
    let topic = "/v1/projects/demo-app/topics/seek-errors";
    let sub = "projects/demo-app/subscriptions/seek-errors";
    assert_eq!(rest_request(address, "PUT", topic, json!({})).await.0, 200);
    assert_eq!(
        rest_request(
            address,
            "PUT",
            &format!("/v1/{sub}"),
            json!({"topic":"projects/demo-app/topics/seek-errors"})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        rest_request(
            address,
            "POST",
            &format!("{topic}:publish"),
            json!({"messages":[{"data":"cmVwbGF5"}]})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        rest_request(
            address,
            "PUT",
            "/v1/projects/demo-app/snapshots/saved",
            json!({"subscription":sub})
        )
        .await
        .0,
        200
    );
    let (_, pulled) = rest_request(
        address,
        "POST",
        &format!("/v1/{sub}:pull"),
        json!({"maxMessages":1}),
    )
    .await;
    let ack = pulled["receivedMessages"][0]["ackId"].as_str().unwrap();
    assert_eq!(
        rest_request(
            address,
            "POST",
            &format!("/v1/{sub}:acknowledge"),
            json!({"ackIds":[ack]})
        )
        .await
        .0,
        200
    );
    let before = rest_request(address, "GET", &format!("/v1/{sub}"), json!({})).await;
    for (request, conflict, extra_violation) in [
        (
            r#"{"time":"2000-01-01T00:00:00Z","snapshot":"projects/demo-app/snapshots/saved"}"#,
            "snapshot",
            false,
        ),
        (
            r#"{"snapshot":"projects/demo-app/snapshots/saved","time":"2000-01-01T00:00:00Z"}"#,
            "time",
            true,
        ),
        (
            r#"{"time":"2000-01-01T00:00:00Z","snapshot":"projects/demo-app/snapshots/saved","subscription":"projects/demo-app/subscriptions/seek-errors"}"#,
            "snapshot",
            true,
        ),
        (
            r#"{"time":"snapshot,\"time\":","snapshot":"projects/demo-app/snapshots/saved"}"#,
            "snapshot",
            false,
        ),
    ] {
        let (status, bytes) = rest_request_bytes(address, "POST", path, request.as_bytes()).await;
        assert_eq!(status, 400);
        if conflict == "snapshot" && !extra_violation {
            assert_eq!(bytes.len(), 447);
        }
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let mut descriptions = vec![format!(
            "Invalid value (oneof), oneof field 'target' is already set. Cannot set '{conflict}'"
        )];
        if extra_violation {
            descriptions.push("Invalid JSON payload received. Unknown name \"subscription\": Root element must be a message.".into());
        }
        assert_eq!(body["error"]["code"], 400);
        assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
        assert_eq!(
            bytes.len(),
            if extra_violation {
                682 + usize::from(conflict == "snapshot") * 8
            } else {
                447
            }
        );
        assert_eq!(body["error"]["message"], descriptions.join("\n"));
        assert_eq!(
            body,
            json!({"error": {
                "code":400, "status":"INVALID_ARGUMENT", "message":descriptions.join("\n"),
                "details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":descriptions.iter().map(|description|json!({"description":description})).collect::<Vec<_>>()}]
            }})
        );
    }
    assert_eq!(
        rest_request(address, "GET", &format!("/v1/{sub}"), json!({})).await,
        before
    );
    let (_, unchanged) = rest_request(
        address,
        "POST",
        &format!("/v1/{sub}:pull"),
        json!({"maxMessages":1}),
    )
    .await;
    assert!(unchanged.get("receivedMessages").is_none(), "{unchanged}");
    for target in [
        json!({"snapshot":"projects/demo-app/snapshots/saved"}),
        json!({"time":"2000-01-01T00:00:00Z"}),
    ] {
        assert_eq!(
            rest_request(address, "POST", path, target).await,
            (200, json!({}))
        );
        let (_, replayed) = rest_request(
            address,
            "POST",
            &format!("/v1/{sub}:pull"),
            json!({"maxMessages":1}),
        )
        .await;
        assert_eq!(
            replayed["receivedMessages"][0]["message"]["data"],
            "cmVwbGF5"
        );
        let ack = replayed["receivedMessages"][0]["ackId"].as_str().unwrap();
        assert_eq!(
            rest_request(
                address,
                "POST",
                &format!("/v1/{sub}:acknowledge"),
                json!({"ackIds":[ack]})
            )
            .await
            .0,
            200
        );
    }
}

#[tokio::test]
async fn wrong_topic_seek_preserves_shared_core_message_on_both_transports() {
    let address = start().await;
    for topic in ["first", "second"] {
        assert_eq!(
            rest_request(
                address,
                "PUT",
                &format!("/v1/projects/demo-app/topics/{topic}"),
                json!({})
            )
            .await
            .0,
            200
        );
        assert_eq!(
            rest_request(
                address,
                "PUT",
                &format!("/v1/projects/demo-app/subscriptions/{topic}"),
                json!({"topic":format!("projects/demo-app/topics/{topic}")})
            )
            .await
            .0,
            200
        );
    }
    let snapshot = "projects/demo-app/snapshots/saved";
    assert_eq!(
        rest_request(
            address,
            "PUT",
            &format!("/v1/{snapshot}"),
            json!({"subscription":"projects/demo-app/subscriptions/first"})
        )
        .await
        .0,
        200
    );
    let expected="The subscription's topic (projects/demo-app/topics/second) is different from that of the snapshot (projects/demo-app/topics/first); they must match in order for Seek work. Note that if a topic is deleted and then re-created with the same name, it is considered a distinct topic for these purposes.";
    let (status, body) = rest_request(
        address,
        "POST",
        "/v1/projects/demo-app/subscriptions/second:seek",
        json!({"snapshot":snapshot}),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["status"], "FAILED_PRECONDITION");
    assert_eq!(body["error"]["message"], expected);
    let mut native = SubscriberClient::new(grpc_channel(address).await);
    let error = native
        .seek(pb::SeekRequest {
            subscription: "projects/demo-app/subscriptions/second".into(),
            target: Some(pb::seek_request::Target::Snapshot(snapshot.into())),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(error.message(), expected);
    native
        .seek(pb::SeekRequest {
            subscription: "projects/demo-app/subscriptions/first".into(),
            target: Some(pb::seek_request::Target::Snapshot(snapshot.into())),
        })
        .await
        .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn strict_pending_rest_pull_disconnect_does_not_lease_or_ack_outstanding_message() {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_700_000_000),
    )));
    let handle = PubSubHandle::new(
        Arc::new(Mutex::new(PubSubState::new(99))),
        clock.clone(),
        None,
    )
    .with_paging_policy(fireemu_adapter_pubsub::PagingPolicy::Strict);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        serve_pubsub(listener, handle).await.unwrap();
    });
    let topic = "/v1/projects/demo-app/topics/pending-cancel";
    let sub = "/v1/projects/demo-app/subscriptions/pending-cancel";
    assert_eq!(rest_request(address, "PUT", topic, json!({})).await.0, 200);
    assert_eq!(
        rest_request(
            address,
            "PUT",
            sub,
            json!({"topic":"projects/demo-app/topics/pending-cancel", "ackDeadlineSeconds":10})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        rest_request(
            address,
            "POST",
            &format!("{topic}:publish"),
            json!({"messages":[{"data":"b3V0c3RhbmRpbmc="},{"data":"Y29udHJvbA=="}]})
        )
        .await
        .0,
        200
    );
    let (_, initial) = rest_request(
        address,
        "POST",
        &format!("{sub}:pull"),
        json!({"maxMessages":2,"returnImmediately":true}),
    )
    .await;
    let messages = initial["receivedMessages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    let outstanding = messages
        .iter()
        .find(|m| m["message"]["data"] == "b3V0c3RhbmRpbmc=")
        .unwrap();
    let control = messages
        .iter()
        .find(|m| m["message"]["data"] == "Y29udHJvbA==")
        .unwrap();
    assert_eq!(
        rest_request(
            address,
            "POST",
            &format!("{sub}:acknowledge"),
            json!({"ackIds":[control["ackId"]]})
        )
        .await
        .0,
        200
    );
    let mut pending = tokio::net::TcpStream::connect(address).await.unwrap();
    let body = br#"{"maxMessages":2,"returnImmediately":false}"#;
    let headers = format!("POST {sub}:pull HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len());
    pending.write_all(headers.as_bytes()).await.unwrap();
    pending.write_all(body).await.unwrap();
    let mut byte = [0];
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), pending.read(&mut byte))
            .await
            .is_err(),
        "strict REST Pull must still be pending at disconnect"
    );
    drop(pending);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    clock
        .lock()
        .unwrap()
        .advance(fireemu_core_types::time::LogicalDuration::from_seconds(11))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let (_, fresh) = rest_request(
        address,
        "POST",
        &format!("{sub}:pull"),
        json!({"maxMessages":2,"returnImmediately":true}),
    )
    .await;
    let fresh = fresh["receivedMessages"].as_array().unwrap();
    assert_eq!(
        fresh.len(),
        1,
        "disconnected server future must not steal redelivery"
    );
    assert_eq!(fresh[0]["message"], outstanding["message"]);
    assert_ne!(fresh[0]["ackId"], outstanding["ackId"]);
    assert_eq!(
        rest_request(
            address,
            "POST",
            &format!("{sub}:acknowledge"),
            json!({"ackIds":[fresh[0]["ackId"]]})
        )
        .await
        .0,
        200
    );
    let path = format!("{sub}:pull");
    let mut wake = tokio::spawn(async move {
        rest_request(
            address,
            "POST",
            &path,
            json!({"maxMessages":2,"returnImmediately":false}),
        )
        .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut wake)
            .await
            .is_err()
    );
    assert_eq!(
        rest_request(
            address,
            "POST",
            &format!("{topic}:publish"),
            json!({"messages":[{"data":"d2FrZQ=="}]})
        )
        .await
        .0,
        200
    );
    let (status, response) = tokio::time::timeout(std::time::Duration::from_secs(1), wake)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(response["receivedMessages"].as_array().unwrap().len(), 1);
    assert_eq!(
        response["receivedMessages"][0]["message"]["data"],
        "d2FrZQ=="
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn unary_rest_pull_immediate_invalid_and_emulator_controls_are_prompt() {
    for policy in [
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        fireemu_adapter_pubsub::PagingPolicy::Emulator,
    ] {
        let address = start_policy(policy).await;
        let sub = "/v1/projects/demo-app/subscriptions/pull-controls";
        assert_eq!(
            rest_request(
                address,
                "PUT",
                "/v1/projects/demo-app/topics/pull-controls",
                json!({})
            )
            .await
            .0,
            200
        );
        assert_eq!(
            rest_request(
                address,
                "PUT",
                sub,
                json!({"topic":"projects/demo-app/topics/pull-controls"})
            )
            .await
            .0,
            200
        );
        let immediate = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            rest_request(
                address,
                "POST",
                &format!("{sub}:pull"),
                json!({"maxMessages":1,"returnImmediately":true}),
            ),
        )
        .await
        .unwrap();
        assert_eq!(immediate, (200, json!({})));
        let missing = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            rest_request(
                address,
                "POST",
                "/v1/projects/demo-app/subscriptions/absent:pull",
                json!({"maxMessages":1}),
            ),
        )
        .await
        .unwrap();
        assert_eq!(missing.0, 404);
        if policy == fireemu_adapter_pubsub::PagingPolicy::Strict {
            let invalid = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                rest_request(
                    address,
                    "POST",
                    &format!("{sub}:pull"),
                    json!({"maxMessages":0}),
                ),
            )
            .await
            .unwrap();
            assert_eq!(invalid.0, 400);
        } else {
            let ordinary = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                rest_request(
                    address,
                    "POST",
                    &format!("{sub}:pull"),
                    json!({"maxMessages":1,"returnImmediately":false}),
                ),
            )
            .await
            .unwrap();
            assert_eq!(ordinary, (200, json!({})));
        }
    }
}

#[tokio::test]
async fn resource_iam_roundtrip_normalizes_version_and_restores_empty_bindings() {
    let address = start().await;
    let topic = "projects/demo-iam/topics/source";
    let subscription = "projects/demo-iam/subscriptions/source";
    for (resource, body) in [(topic, json!({})), (subscription, json!({"topic":topic}))] {
        assert_eq!(
            rest_request(address, "PUT", &format!("/v1/{resource}"), body)
                .await
                .0,
            200
        );
    }
    for (resource, role) in [
        (topic, "roles/pubsub.publisher"),
        (subscription, "roles/pubsub.subscriber"),
    ] {
        let get = format!("/v1/{resource}:getIamPolicy?options.requestedPolicyVersion=3");
        let set = format!("/v1/{resource}:setIamPolicy");
        let (status, baseline) = rest_request(address, "GET", &get, json!({})).await;
        assert_eq!(status, 200);
        assert_eq!(baseline.as_object().unwrap().len(), 1);
        assert_eq!(baseline["etag"].as_str().unwrap().len(), 4);
        let binding = json!({"role":role,"members":["serviceAccount:service-123456789@gcp-sa-pubsub.iam.gserviceaccount.com"]});
        let (status, granted) = rest_request(
            address,
            "POST",
            &set,
            json!({"policy":{"version":3,"etag":baseline["etag"],"bindings":[binding.clone()]}}),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(granted["version"], 1);
        assert_eq!(granted["etag"].as_str().unwrap().len(), 12);
        assert_eq!(granted["bindings"], json!([binding]));
        assert_eq!(
            rest_request(address, "GET", &get, json!({})).await.1,
            granted
        );
        let (stale, _) = rest_request(
            address,
            "POST",
            &set,
            json!({"policy":{"etag":baseline["etag"],"bindings":[]}}),
        )
        .await;
        assert_ne!(stale, 200);
        assert_eq!(
            rest_request(address, "GET", &get, json!({})).await.1,
            granted
        );
        let (status, restored) = rest_request(
            address,
            "POST",
            &set,
            json!({"policy":{"version":1,"etag":granted["etag"],"bindings":[]}}),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(restored["version"], 1);
        assert!(restored.get("bindings").is_none());
        assert_eq!(
            rest_request(address, "GET", &get, json!({})).await.1,
            restored
        );
    }
}

#[tokio::test]
async fn strict_ungranted_dead_letter_keeps_positive_attempts_and_source_redelivery() {
    let address = start().await;
    let topic = "projects/demo-iam/topics/source";
    let dead = "projects/demo-iam/topics/dead";
    let source = "projects/demo-iam/subscriptions/source";
    let sink = "projects/demo-iam/subscriptions/sink";
    for resource in [topic, dead] {
        assert_eq!(
            rest_request(address, "PUT", &format!("/v1/{resource}"), json!({}))
                .await
                .0,
            200
        );
    }
    assert_eq!(rest_request(address,"PUT",&format!("/v1/{source}"),json!({"topic":topic,"deadLetterPolicy":{"deadLetterTopic":dead,"maxDeliveryAttempts":5}})).await.0,200);
    assert_eq!(
        rest_request(
            address,
            "PUT",
            &format!("/v1/{sink}"),
            json!({"topic":dead})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        rest_request(
            address,
            "POST",
            &format!("/v1/{topic}:publish"),
            json!({"messages":[{"data":"eA=="}]})
        )
        .await
        .0,
        200
    );
    for attempt in 1..=6 {
        let (_, body) = rest_request(
            address,
            "POST",
            &format!("/v1/{source}:pull"),
            json!({"maxMessages":1,"returnImmediately":true}),
        )
        .await;
        assert_eq!(body["receivedMessages"][0]["deliveryAttempt"], attempt);
        assert_eq!(
            rest_request(
                address,
                "POST",
                &format!("/v1/{source}:modifyAckDeadline"),
                json!({"ackIds":[body["receivedMessages"][0]["ackId"]],"ackDeadlineSeconds":0})
            )
            .await
            .0,
            200
        );
    }
    let (_, body) = rest_request(
        address,
        "POST",
        &format!("/v1/{sink}:pull"),
        json!({"maxMessages":1,"returnImmediately":true}),
    )
    .await;
    assert!(body.get("receivedMessages").is_none());
}

#[tokio::test]
#[allow(clippy::too_many_lines, deprecated)]
async fn actual_rest_iam_requires_both_grants_before_native_dead_letter_transfer() {
    let address = start_with_numbers(
        fireemu_adapter_pubsub::PagingPolicy::Strict,
        std::collections::BTreeMap::from([("demo-iam".to_owned(), "123456789".to_owned())]),
    )
    .await;
    let topic = "projects/demo-iam/topics/source";
    let dead = "projects/demo-iam/topics/dead";
    let source = "projects/demo-iam/subscriptions/source";
    let sink = "projects/demo-iam/subscriptions/sink";
    for resource in [topic, dead] {
        assert_eq!(
            rest_request(address, "PUT", &format!("/v1/{resource}"), json!({}))
                .await
                .0,
            200
        );
    }
    assert_eq!(rest_request(address,"PUT",&format!("/v1/{source}"),json!({"topic":topic,"deadLetterPolicy":{"deadLetterTopic":dead,"maxDeliveryAttempts":5}})).await.0,200);
    assert_eq!(
        rest_request(
            address,
            "PUT",
            &format!("/v1/{sink}"),
            json!({"topic":dead})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        rest_request(
            address,
            "POST",
            &format!("/v1/{topic}:publish"),
            json!({"messages":[{"data":"eA=="}]})
        )
        .await
        .0,
        200
    );
    let mut client = SubscriberClient::new(grpc_channel(address).await);
    for attempt in 1..=6 {
        let response = client
            .pull(pb::PullRequest {
                subscription: source.to_owned(),
                max_messages: 1,
                return_immediately: true,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.received_messages.len(), 1);
        assert_eq!(response.received_messages[0].delivery_attempt, attempt);
        client
            .modify_ack_deadline(pb::ModifyAckDeadlineRequest {
                subscription: source.to_owned(),
                ack_ids: vec![response.received_messages[0].ack_id.clone()],
                ack_deadline_seconds: 0,
            })
            .await
            .unwrap();
    }
    let mut baselines = Vec::new();
    for (resource, role) in [
        (source, "roles/pubsub.subscriber"),
        (dead, "roles/pubsub.publisher"),
    ] {
        let get = format!("/v1/{resource}:getIamPolicy?options.requestedPolicyVersion=3");
        let (_, before) = rest_request(address, "GET", &get, json!({})).await;
        let (_,after)=rest_request(address,"POST",&format!("/v1/{resource}:setIamPolicy"),json!({"policy":{"etag":before["etag"],"version":3,"bindings":[{"role":role,"members":["serviceAccount:service-123456789@gcp-sa-pubsub.iam.gserviceaccount.com"]}]}})).await;
        assert_eq!(after["version"], 1);
        assert_eq!(rest_request(address, "GET", &get, json!({})).await.1, after);
        baselines.push((resource, after));
        if resource == source {
            let response = client
                .pull(pb::PullRequest {
                    subscription: source.to_owned(),
                    max_messages: 1,
                    return_immediately: true,
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.received_messages[0].delivery_attempt, 7);
            client
                .modify_ack_deadline(pb::ModifyAckDeadlineRequest {
                    subscription: source.to_owned(),
                    ack_ids: vec![response.received_messages[0].ack_id.clone()],
                    ack_deadline_seconds: 0,
                })
                .await
                .unwrap();
        }
    }
    assert!(client
        .pull(pb::PullRequest {
            subscription: source.to_owned(),
            max_messages: 1,
            return_immediately: true
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages
        .is_empty());
    let (_, received) = rest_request(
        address,
        "POST",
        &format!("/v1/{sink}:pull"),
        json!({"maxMessages":1,"returnImmediately":true}),
    )
    .await;
    assert_eq!(received["receivedMessages"].as_array().unwrap().len(), 1);
    assert!(received["receivedMessages"][0]
        .get("deliveryAttempt")
        .is_none());
    let attributes = &received["receivedMessages"][0]["message"]["attributes"];
    assert_eq!(
        attributes["CloudPubSubDeadLetterSourceSubscription"],
        "source"
    );
    assert_eq!(
        attributes["CloudPubSubDeadLetterSourceSubscriptionProject"],
        "demo-iam"
    );
    assert_eq!(attributes["CloudPubSubDeadLetterSourceDeliveryCount"], "7");
    assert_eq!(
        attributes["CloudPubSubDeadLetterSourceTopicPublishTime"],
        "2023-11-14T22:13:20Z"
    );
    for (resource, after) in baselines {
        let (status, restored) = rest_request(
            address,
            "POST",
            &format!("/v1/{resource}:setIamPolicy"),
            json!({"policy":{"etag":after["etag"],"version":1,"bindings":[]}}),
        )
        .await;
        assert_eq!(status, 200);
        assert!(restored.get("bindings").is_none());
    }
}
