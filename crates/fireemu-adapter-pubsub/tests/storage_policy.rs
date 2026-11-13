//! Topic `messageStoragePolicy` admission and round trip across both transports and both profiles.
//!
//! Evidence behind the expectations:
//! - Production (recorded 2026-10-04 and 2026-10-05, REST and gRPC): a topic created with
//!   `{"allowedPersistenceRegions": ["us-central1"]}` is answered with that policy and nothing else
//!   added; an unknown region is refused with `INVALID_ARGUMENT`.
//! - The official Pub/Sub emulator shipped with firebase-tools 15.28.2 (pubsub-emulator 0.8.35)
//!   stores the policy it is given without looking at it (an unknown region, a repeated region, an
//!   empty list, an empty message and a lone `enforceInTransit` were all accepted and returned by
//!   Get and List), and its `UpdateTopic` refuses every field mask.
//! - The strict profile has no cited region inventory to validate against, so it keeps refusing.

use std::sync::{Arc, Mutex};

use fireemu_adapter_pubsub::{serve_pubsub, PagingPolicy, PubSubHandle};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
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
    async fn new(policy: PagingPolicy) -> Self {
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

    async fn grpc(&self) -> PublisherClient<tonic::transport::Channel> {
        PublisherClient::new(
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

    async fn rest_get(&self, id: &str) -> (u16, Value) {
        self.rest(
            "GET",
            &format!("/v1/projects/demo-app/topics/{id}"),
            json!({}),
        )
        .await
    }

    async fn rest_create(&self, id: &str, body: Value) -> (u16, Value) {
        self.rest("PUT", &format!("/v1/projects/demo-app/topics/{id}"), body)
            .await
    }

    async fn rest_patch(&self, id: &str, topic: Value, mask: &str) -> (u16, Value) {
        self.rest(
            "PATCH",
            &format!("/v1/projects/demo-app/topics/{id}"),
            json!({"topic": topic, "updateMask": mask}),
        )
        .await
    }

    /// The topic as the REST listing renders it.
    async fn rest_listed(&self, id: &str) -> Value {
        let (status, listed) = self
            .rest("GET", "/v1/projects/demo-app/topics", json!({}))
            .await;
        assert_eq!(status, 200, "{listed}");
        let name = topic_name(id);
        listed["topics"]
            .as_array()
            .and_then(|topics| topics.iter().find(|topic| topic["name"] == name))
            .unwrap_or_else(|| panic!("{id} missing from the listing: {listed}"))
            .clone()
    }

    async fn grpc_get(&self, id: &str) -> pb::Topic {
        self.grpc()
            .await
            .get_topic(pb::GetTopicRequest {
                topic: topic_name(id),
            })
            .await
            .unwrap()
            .into_inner()
    }

    async fn grpc_listed(&self, id: &str) -> pb::Topic {
        let name = topic_name(id);
        self.grpc()
            .await
            .list_topics(pb::ListTopicsRequest {
                project: "projects/demo-app".to_owned(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .topics
            .into_iter()
            .find(|topic| topic.name == name)
            .unwrap_or_else(|| panic!("{id} missing from the gRPC listing"))
    }

    async fn grpc_create(&self, id: &str, policy: Option<pb::MessageStoragePolicy>) -> pb::Topic {
        self.grpc()
            .await
            .create_topic(pb::Topic {
                name: topic_name(id),
                message_storage_policy: policy,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
    }

    async fn grpc_update(
        &self,
        id: &str,
        topic: pb::Topic,
        paths: &[&str],
    ) -> Result<pb::Topic, Box<tonic::Status>> {
        let mut topic = topic;
        topic.name = topic_name(id);
        self.grpc()
            .await
            .update_topic(pb::UpdateTopicRequest {
                topic: Some(topic),
                update_mask: Some(prost_types::FieldMask {
                    paths: paths.iter().map(|path| (*path).to_owned()).collect(),
                }),
            })
            .await
            .map(tonic::Response::into_inner)
            .map_err(Box::new)
    }
}

fn topic_name(id: &str) -> String {
    format!("projects/demo-app/topics/{id}")
}

fn policy(regions: &[&str], enforce: bool) -> pb::MessageStoragePolicy {
    pb::MessageStoragePolicy {
        allowed_persistence_regions: regions.iter().map(|region| (*region).to_owned()).collect(),
        enforce_in_transit: enforce,
    }
}

// --- Emulator profile: the recorded production input --------------------------------------

#[tokio::test]
async fn the_recorded_production_input_round_trips_through_rest_get_and_list() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let body = json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}});
    let (status, created) = h.rest_create("recorded", body).await;
    // Production answered exactly this body for the recorded input.
    let expected = json!({
        "name": topic_name("recorded"),
        "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]},
    });
    assert_eq!(status, 200, "{created}");
    assert_eq!(created, expected);
    let (status, got) = h.rest_get("recorded").await;
    assert_eq!((status, &got), (200, &expected));
    assert_eq!(h.rest_listed("recorded").await, expected);
}

#[tokio::test]
async fn the_recorded_production_input_round_trips_through_grpc() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let created = h
        .grpc_create("recorded", Some(policy(&["us-central1"], false)))
        .await;
    assert_eq!(
        created.message_storage_policy,
        Some(policy(&["us-central1"], false))
    );
    assert_eq!(h.grpc_get("recorded").await, created);
    assert_eq!(h.grpc_listed("recorded").await, created);
    // The other transport reads the same stored policy.
    let (status, rest) = h.rest_get("recorded").await;
    assert_eq!(status, 200);
    assert_eq!(
        rest["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["us-central1"]})
    );
}

#[tokio::test]
async fn a_policy_created_over_rest_is_read_over_grpc_and_the_reverse() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let (status, _) = h
        .rest_create(
            "from-rest",
            json!({"messageStoragePolicy": {
                "allowedPersistenceRegions": ["europe-west1", "asia-east1"],
                "enforceInTransit": true,
            }}),
        )
        .await;
    assert_eq!(status, 200);
    let expected = policy(&["europe-west1", "asia-east1"], true);
    assert_eq!(
        h.grpc_get("from-rest").await.message_storage_policy,
        Some(expected.clone())
    );
    assert_eq!(
        h.grpc_listed("from-rest").await.message_storage_policy,
        Some(expected)
    );

    h.grpc_create("from-grpc", Some(policy(&["us-east1"], true)))
        .await;
    let (_, rest) = h.rest_get("from-grpc").await;
    assert_eq!(
        rest["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["us-east1"], "enforceInTransit": true})
    );
}

#[tokio::test]
async fn snake_case_spellings_are_accepted_for_the_policy() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let (status, created) = h
        .rest_create(
            "snake",
            json!({"message_storage_policy": {
                "allowed_persistence_regions": ["us-central1"],
                "enforce_in_transit": true,
            }}),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        created["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["us-central1"], "enforceInTransit": true})
    );
}

// --- Emulator profile: shapes the official emulator stores without looking ------------------

/// Each row is accepted by the official emulator and returned unchanged by its Get and List.
fn official_accepted_policies() -> Vec<(&'static str, Value, Value, pb::MessageStoragePolicy)> {
    vec![
        (
            "unknown-region",
            json!({"allowedPersistenceRegions": ["no-such-region1"]}),
            json!({"allowedPersistenceRegions": ["no-such-region1"]}),
            policy(&["no-such-region1"], false),
        ),
        (
            "repeated-region",
            json!({"allowedPersistenceRegions": ["us-central1", "us-central1"], "enforceInTransit": true}),
            json!({"allowedPersistenceRegions": ["us-central1", "us-central1"], "enforceInTransit": true}),
            policy(&["us-central1", "us-central1"], true),
        ),
        (
            "empty-list",
            json!({"allowedPersistenceRegions": []}),
            json!({}),
            policy(&[], false),
        ),
        ("empty-message", json!({}), json!({}), policy(&[], false)),
        (
            "enforce-only",
            json!({"enforceInTransit": true}),
            json!({"enforceInTransit": true}),
            policy(&[], true),
        ),
        (
            "enforce-false",
            json!({"enforceInTransit": false, "allowedPersistenceRegions": ["us-east1"]}),
            json!({"allowedPersistenceRegions": ["us-east1"]}),
            policy(&["us-east1"], false),
        ),
        (
            "empty-and-odd-strings",
            json!({"allowedPersistenceRegions": ["", "US-CENTRAL1", " us-central1 "]}),
            json!({"allowedPersistenceRegions": ["", "US-CENTRAL1", " us-central1 "]}),
            policy(&["", "US-CENTRAL1", " us-central1 "], false),
        ),
    ]
}

#[tokio::test]
async fn every_shape_the_official_emulator_stores_is_stored_and_returned_in_the_emulator_profile() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    for (id, request, rendered, wire) in official_accepted_policies() {
        let (status, created) = h
            .rest_create(
                &format!("rest-{id}"),
                json!({"messageStoragePolicy": request}),
            )
            .await;
        assert_eq!(status, 200, "{id}: {created}");
        // A present policy stays present, even an empty one.
        assert_eq!(created["messageStoragePolicy"], rendered, "{id}");
        let (_, got) = h.rest_get(&format!("rest-{id}")).await;
        assert_eq!(got["messageStoragePolicy"], rendered, "{id}");
        assert_eq!(
            h.rest_listed(&format!("rest-{id}")).await["messageStoragePolicy"],
            rendered,
            "{id}"
        );

        let created = h
            .grpc_create(&format!("grpc-{id}"), Some(wire.clone()))
            .await;
        assert_eq!(created.message_storage_policy, Some(wire.clone()), "{id}");
        assert_eq!(h.grpc_get(&format!("grpc-{id}")).await, created, "{id}");
        assert_eq!(h.grpc_listed(&format!("grpc-{id}")).await, created, "{id}");
        // The same stored value reads the same over the other transport.
        let (_, rest_of_grpc) = h.rest_get(&format!("grpc-{id}")).await;
        assert_eq!(rest_of_grpc["messageStoragePolicy"], rendered, "{id}");
    }
}

#[tokio::test]
async fn a_null_policy_and_an_omitted_policy_are_the_same_absence() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    for (id, body) in [
        ("null-policy", json!({"messageStoragePolicy": null})),
        ("omitted-policy", json!({})),
    ] {
        let (status, created) = h.rest_create(id, body).await;
        assert_eq!(status, 200, "{id}: {created}");
        assert!(created.get("messageStoragePolicy").is_none(), "{id}");
        assert!(
            h.grpc_get(id).await.message_storage_policy.is_none(),
            "{id}"
        );
    }
}

#[tokio::test]
async fn a_policy_belongs_to_its_topic_and_does_not_survive_deletion() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.grpc_create("with-policy", Some(policy(&["us-central1"], true)))
        .await;
    h.grpc_create("without-policy", None).await;
    assert!(h
        .grpc_get("without-policy")
        .await
        .message_storage_policy
        .is_none());

    let (status, _) = h
        .rest(
            "DELETE",
            &format!("/v1/{}", topic_name("with-policy")),
            json!({}),
        )
        .await;
    assert_eq!(status, 200);
    h.grpc_create("with-policy", None).await;
    assert!(h
        .grpc_get("with-policy")
        .await
        .message_storage_policy
        .is_none());
}

#[tokio::test]
async fn a_policy_does_not_disturb_labels_or_retention() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let (status, created) = h
        .rest_create(
            "combined",
            json!({
                "labels": {"owner": "test"},
                "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]},
            }),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["labels"], json!({"owner": "test"}));
    let topic = h.grpc_get("combined").await;
    assert_eq!(topic.labels.get("owner").map(String::as_str), Some("test"));
    assert_eq!(
        topic.message_storage_policy,
        Some(policy(&["us-central1"], false))
    );
}

// --- Emulator profile: malformed REST bodies -----------------------------------------------

#[tokio::test]
async fn malformed_policy_bodies_are_invalid_arguments_and_create_nothing() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let cases = [
        (
            "string-policy",
            json!({"messageStoragePolicy": "us-central1"}),
        ),
        ("array-policy", json!({"messageStoragePolicy": []})),
        (
            "string-regions",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": "us-central1"}}),
        ),
        (
            "object-regions",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": {}}}),
        ),
        (
            "number-region",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": [1]}}),
        ),
        (
            "null-region",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": [null]}}),
        ),
        (
            "string-enforce",
            json!({"messageStoragePolicy": {"enforceInTransit": "true"}}),
        ),
        (
            "number-enforce",
            json!({"messageStoragePolicy": {"enforceInTransit": 1}}),
        ),
        (
            "unknown-subfield",
            json!({"messageStoragePolicy": {"noSuchField": true}}),
        ),
        (
            "near-miss-subfield",
            json!({"messageStoragePolicy": {"allowedPersistenceRegion": ["us-central1"]}}),
        ),
        (
            "duplicate-policy-spelling",
            json!({
                "messageStoragePolicy": {},
                "message_storage_policy": {},
            }),
        ),
        (
            "duplicate-regions-spelling",
            json!({"messageStoragePolicy": {
                "allowedPersistenceRegions": ["a"],
                "allowed_persistence_regions": ["a"],
            }}),
        ),
    ];
    for (id, body) in cases {
        let (status, error) = h.rest_create(id, body).await;
        assert_eq!(status, 400, "{id}: {error}");
        assert_eq!(error["error"]["status"], "INVALID_ARGUMENT", "{id}");
        let (status, _) = h.rest_get(id).await;
        assert_eq!(status, 404, "{id} was created");
    }
}

#[tokio::test]
async fn the_other_unsupported_topic_fields_are_still_refused_in_the_emulator_profile() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let (status, error) = h.rest_create("schema", json!({"schemaSettings": {}})).await;
    assert_eq!(status, 501, "{error}");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("schema_settings"));
    assert_eq!(h.rest_get("schema").await.0, 404);
}

// --- Emulator profile: UpdateTopic ---------------------------------------------------------

#[tokio::test]
async fn rest_patch_replaces_the_whole_policy_when_the_mask_names_it() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "patch",
        json!({
            "labels": {"owner": "test"},
            "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"], "enforceInTransit": true},
        }),
    )
    .await;
    let (status, updated) = h
        .rest_patch(
            "patch",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["europe-west1"]}}),
            "messageStoragePolicy",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    // The whole message is replaced: enforceInTransit goes back to its default. Labels are kept.
    assert_eq!(
        updated["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["europe-west1"]})
    );
    assert_eq!(updated["labels"], json!({"owner": "test"}));
    let (_, got) = h.rest_get("patch").await;
    assert_eq!(got, updated);
    assert_eq!(h.rest_listed("patch").await, updated);
    assert_eq!(
        h.grpc_get("patch").await.message_storage_policy,
        Some(policy(&["europe-west1"], false))
    );
}

#[tokio::test]
async fn rest_patch_with_the_mask_and_no_policy_in_the_topic_removes_the_policy() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "clear",
        json!({
            "labels": {"owner": "test"},
            "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]},
        }),
    )
    .await;
    let (status, updated) = h
        .rest_patch("clear", json!({}), "messageStoragePolicy")
        .await;
    assert_eq!(status, 200, "{updated}");
    assert!(updated.get("messageStoragePolicy").is_none(), "{updated}");
    assert_eq!(updated["labels"], json!({"owner": "test"}));
    assert!(h.grpc_get("clear").await.message_storage_policy.is_none());
}

#[tokio::test]
async fn rest_patch_leaves_the_policy_alone_unless_the_mask_names_it() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "keep",
        json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
    )
    .await;
    let (status, updated) = h
        .rest_patch(
            "keep",
            json!({
                "labels": {"owner": "test"},
                "messageStoragePolicy": {"allowedPersistenceRegions": ["asia-east1"]},
            }),
            "labels",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        updated["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["us-central1"]}),
        "a policy in the body without the mask must not be applied"
    );
    assert_eq!(updated["labels"], json!({"owner": "test"}));
}

#[tokio::test]
async fn rest_patch_updates_labels_and_policy_together() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create("both", json!({"labels": {"a": "b"}})).await;
    let (status, updated) = h
        .rest_patch(
            "both",
            json!({
                "labels": {"owner": "test"},
                "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"], "enforceInTransit": true},
            }),
            "labels,messageStoragePolicy",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["labels"], json!({"owner": "test"}));
    assert_eq!(
        updated["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["us-central1"], "enforceInTransit": true})
    );
}

#[tokio::test]
async fn rest_patch_nested_paths_update_one_field_of_the_policy() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "nested",
        json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"], "enforceInTransit": true}}),
    )
    .await;
    let (status, updated) = h
        .rest_patch(
            "nested",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["asia-east1", "us-east1"], "enforceInTransit": false}}),
            "messageStoragePolicy.allowedPersistenceRegions",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        updated["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["asia-east1", "us-east1"], "enforceInTransit": true}),
        "only the named field changes"
    );
    let (status, updated) = h
        .rest_patch(
            "nested",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["ignored"]}}),
            "messageStoragePolicy.enforceInTransit",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        updated["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["asia-east1", "us-east1"]}),
        "enforceInTransit takes the body's value, which is absent"
    );
}

#[tokio::test]
async fn rest_patch_nested_path_creates_the_policy_of_a_topic_that_had_none() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create("fresh", json!({})).await;
    let (status, updated) = h
        .rest_patch(
            "fresh",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
            "messageStoragePolicy.allowedPersistenceRegions",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        updated["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["us-central1"]})
    );
}

#[tokio::test]
async fn the_whole_policy_path_subsumes_its_nested_paths() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "subsume",
        json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"], "enforceInTransit": true}}),
    )
    .await;
    let (status, updated) = h
        .rest_patch(
            "subsume",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["asia-east1"]}}),
            "messageStoragePolicy.enforceInTransit,messageStoragePolicy",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        updated["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["asia-east1"]})
    );
}

#[tokio::test]
async fn rest_patch_refusals_leave_the_policy_untouched() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "refuse",
        json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
    )
    .await;
    for (mask, topic, expected) in [
        // A mask path the emulator cannot apply refuses the whole update.
        ("messageStoragePolicy,schemaSettings", json!({}), 501),
        (
            "messageStoragePolicy,messageRetentionDuration",
            json!({}),
            501,
        ),
        ("messageStoragePolicy,state", json!({}), 501),
        // A near miss of the nested names is an unknown path.
        (
            "messageStoragePolicy.allowedPersistenceRegion",
            json!({}),
            400,
        ),
        ("messageStoragePolicy.noSuch", json!({}), 400),
        ("messageStoragePolicyX", json!({}), 400),
        // A malformed body is refused before anything is applied.
        (
            "messageStoragePolicy",
            json!({"messageStoragePolicy": {"enforceInTransit": "yes"}}),
            400,
        ),
    ] {
        let (status, error) = h.rest_patch("refuse", topic, mask).await;
        assert_eq!(status, expected, "{mask}: {error}");
        let (_, got) = h.rest_get("refuse").await;
        assert_eq!(
            got["messageStoragePolicy"],
            json!({"allowedPersistenceRegions": ["us-central1"]}),
            "{mask}"
        );
    }
}

#[tokio::test]
async fn a_failed_label_check_in_strict_style_keeps_the_policy_unchanged_in_one_update() {
    // The emulator profile admits any label; this documents that a combined update is applied as a
    // whole when it succeeds, and that a missing topic changes nothing.
    let h = Harness::new(PagingPolicy::Emulator).await;
    let (status, error) = h
        .rest_patch(
            "missing",
            json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
            "messageStoragePolicy",
        )
        .await;
    assert_eq!(status, 404, "{error}");
    assert_eq!(h.rest_get("missing").await.0, 404);
}

#[tokio::test]
async fn grpc_update_topic_applies_the_policy_mask() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.grpc_create("grpc-patch", Some(policy(&["us-central1"], true)))
        .await;

    // Whole policy replaced.
    let updated = h
        .grpc_update(
            "grpc-patch",
            pb::Topic {
                message_storage_policy: Some(policy(&["europe-west1"], false)),
                ..Default::default()
            },
            &["message_storage_policy"],
        )
        .await
        .unwrap();
    assert_eq!(
        updated.message_storage_policy,
        Some(policy(&["europe-west1"], false))
    );
    assert_eq!(h.grpc_get("grpc-patch").await, updated);
    let (_, rest) = h.rest_get("grpc-patch").await;
    assert_eq!(
        rest["messageStoragePolicy"],
        json!({"allowedPersistenceRegions": ["europe-west1"]})
    );

    // One nested field.
    let updated = h
        .grpc_update(
            "grpc-patch",
            pb::Topic {
                message_storage_policy: Some(policy(&[], true)),
                ..Default::default()
            },
            &["message_storage_policy.enforce_in_transit"],
        )
        .await
        .unwrap();
    assert_eq!(
        updated.message_storage_policy,
        Some(policy(&["europe-west1"], true))
    );

    // Labels and policy together.
    let updated = h
        .grpc_update(
            "grpc-patch",
            pb::Topic {
                labels: [("owner".to_owned(), "test".to_owned())].into(),
                message_storage_policy: Some(policy(&["asia-east1"], false)),
                ..Default::default()
            },
            &["labels", "message_storage_policy"],
        )
        .await
        .unwrap();
    assert_eq!(
        updated.labels.get("owner").map(String::as_str),
        Some("test")
    );
    assert_eq!(
        updated.message_storage_policy,
        Some(policy(&["asia-east1"], false))
    );

    // The mask without a policy in the topic removes it.
    let updated = h
        .grpc_update(
            "grpc-patch",
            pb::Topic::default(),
            &["message_storage_policy"],
        )
        .await
        .unwrap();
    assert!(updated.message_storage_policy.is_none());
    assert_eq!(
        updated.labels.get("owner").map(String::as_str),
        Some("test")
    );
}

#[tokio::test]
async fn grpc_update_topic_refusals_keep_their_codes_and_change_nothing() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.grpc_create("grpc-refuse", Some(policy(&["us-central1"], false)))
        .await;
    for (paths, code) in [
        (
            vec!["message_storage_policy", "schema_settings"],
            tonic::Code::Unimplemented,
        ),
        (
            vec!["message_storage_policy", "message_retention_duration"],
            tonic::Code::Unimplemented,
        ),
        (
            vec!["message_storage_policy.nope"],
            tonic::Code::InvalidArgument,
        ),
        (vec![], tonic::Code::Unimplemented),
    ] {
        let topic = pb::Topic {
            message_storage_policy: Some(policy(&["asia-east1"], true)),
            ..Default::default()
        };
        let error = h
            .grpc_update("grpc-refuse", topic, &paths)
            .await
            .unwrap_err();
        assert_eq!(error.code(), code, "{paths:?}: {error}");
        assert_eq!(
            h.grpc_get("grpc-refuse").await.message_storage_policy,
            Some(policy(&["us-central1"], false)),
            "{paths:?}"
        );
    }
    let error = h
        .grpc_update(
            "grpc-missing",
            pb::Topic {
                message_storage_policy: Some(policy(&[], false)),
                ..Default::default()
            },
            &["message_storage_policy"],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
}

// --- Strict profile ------------------------------------------------------------------------

fn assert_strict_explanation(message: &str) {
    assert!(message.contains("message_storage_policy"), "{message}");
    // Why: no cited region inventory to validate against, so strict cannot give production's answer.
    assert!(message.contains("strict"), "{message}");
    assert!(message.contains("region"), "{message}");
    // How to proceed: the profile that stores it, or leaving it out.
    assert!(message.contains(r#"profile = "emulator""#), "{message}");
}

#[tokio::test]
async fn strict_refuses_every_policy_shape_on_create_over_rest_and_grpc() {
    let h = Harness::new(PagingPolicy::Strict).await;
    let mut shapes = vec![(
        "recorded".to_owned(),
        json!({"allowedPersistenceRegions": ["us-central1"]}),
        policy(&["us-central1"], false),
    )];
    for (id, request, _rendered, wire) in official_accepted_policies() {
        shapes.push((id.to_owned(), request, wire));
    }
    for (id, request, wire) in shapes {
        let (status, error) = h
            .rest_create(
                &format!("rest-{id}"),
                json!({"messageStoragePolicy": request}),
            )
            .await;
        assert_eq!(status, 501, "{id}: {error}");
        assert_eq!(error["error"]["status"], "UNIMPLEMENTED", "{id}");
        assert_strict_explanation(error["error"]["message"].as_str().unwrap());
        assert_eq!(h.rest_get(&format!("rest-{id}")).await.0, 404, "{id}");

        let error = h
            .grpc()
            .await
            .create_topic(pb::Topic {
                name: topic_name(&format!("grpc-{id}")),
                message_storage_policy: Some(wire),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{id}");
        assert_strict_explanation(error.message());
        let missing = h
            .grpc()
            .await
            .get_topic(pb::GetTopicRequest {
                topic: topic_name(&format!("grpc-{id}")),
            })
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound, "{id}");
    }
}

#[tokio::test]
async fn strict_still_creates_topics_without_a_policy_and_reports_none() {
    let h = Harness::new(PagingPolicy::Strict).await;
    for (id, body) in [
        ("omitted", json!({})),
        ("null-policy", json!({"messageStoragePolicy": null})),
    ] {
        let (status, created) = h.rest_create(id, body).await;
        assert_eq!(status, 200, "{id}: {created}");
        assert!(created.get("messageStoragePolicy").is_none(), "{id}");
    }
    assert!(h.grpc_get("omitted").await.message_storage_policy.is_none());
}

/// Each REST mask is paired with the gRPC paths that mean the same thing.
const STRICT_MASKS: [(&str, &[&str]); 7] = [
    ("messageStoragePolicy", &["message_storage_policy"]),
    ("message_storage_policy", &["message_storage_policy"]),
    (
        "messageStoragePolicy.allowedPersistenceRegions",
        &["message_storage_policy.allowed_persistence_regions"],
    ),
    (
        "message_storage_policy.enforce_in_transit",
        &["message_storage_policy.enforce_in_transit"],
    ),
    (
        "labels,messageStoragePolicy",
        &["labels", "message_storage_policy"],
    ),
    (
        "messageStoragePolicy,labels",
        &["message_storage_policy", "labels"],
    ),
    (
        "labels,messageStoragePolicy.enforceInTransit",
        &["labels", "message_storage_policy.enforce_in_transit"],
    ),
];

#[tokio::test]
async fn strict_refuses_a_policy_in_an_update_mask_and_changes_nothing() {
    let h = Harness::new(PagingPolicy::Strict).await;
    let (status, created) = h
        .rest_create("strict-patch", json!({"labels": {"keep": "me"}}))
        .await;
    assert_eq!(status, 200, "{created}");
    let before_rest = h.rest_get("strict-patch").await;
    let before_grpc = h.grpc_get("strict-patch").await;
    assert_eq!(before_rest.1["labels"], json!({"keep": "me"}));
    assert!(before_grpc.message_storage_policy.is_none());

    for (mask, paths) in STRICT_MASKS {
        let (status, error) = h
            .rest_patch(
                "strict-patch",
                json!({"labels": {"k": "v"}, "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
                mask,
            )
            .await;
        assert_eq!(status, 501, "{mask}: {error}");
        assert_eq!(error["error"]["status"], "UNIMPLEMENTED", "{mask}");
        assert_strict_explanation(error["error"]["message"].as_str().unwrap());

        let error = h
            .grpc_update(
                "strict-patch",
                pb::Topic {
                    labels: [("k".to_owned(), "v".to_owned())].into(),
                    message_storage_policy: Some(policy(&["us-central1"], true)),
                    ..Default::default()
                },
                paths,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{paths:?}");
        assert_strict_explanation(error.message());

        // Neither the labels nor the policy moved, as either transport reads them.
        assert_eq!(h.rest_get("strict-patch").await, before_rest, "{mask}");
        assert_eq!(h.grpc_get("strict-patch").await, before_grpc, "{paths:?}");
    }

    // A labels-only update is unaffected and keeps working.
    let (status, updated) = h
        .rest_patch(
            "strict-patch",
            json!({"labels": {"owner": "test"}}),
            "labels",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["labels"], json!({"owner": "test"}));
    assert!(h
        .grpc_get("strict-patch")
        .await
        .message_storage_policy
        .is_none());
}

#[tokio::test]
async fn the_profile_is_the_only_difference_for_the_recorded_input() {
    let strict = Harness::new(PagingPolicy::Strict).await;
    let emulator = Harness::new(PagingPolicy::Emulator).await;
    let body = json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}});
    assert_eq!(strict.rest_create("same", body.clone()).await.0, 501);
    assert_eq!(emulator.rest_create("same", body).await.0, 200);
}

#[tokio::test]
async fn an_unknown_policy_member_is_named_with_its_parent() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let (status, error) = h
        .rest_create(
            "member",
            json!({"messageStoragePolicy": {"noSuchField": 1}}),
        )
        .await;
    assert_eq!(status, 400, "{error}");
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message.contains(r#"Unknown name "noSuchField" at 'message_storage_policy'"#),
        "{message}"
    );
    assert_eq!(
        error["error"]["details"][0]["fieldViolations"][0]["field"],
        "message_storage_policy"
    );
}

// --- Spellings, duplicate masks and refused mixed updates ----------------------------------

#[tokio::test]
async fn hybrid_json_spellings_are_unknown_names_and_never_silently_dropped() {
    // Proto3 JSON accepts the lowerCamelCase name or the original snake_case name of a field, not a
    // mixture of the two inside one name. The official emulator has no REST surface to compare with.
    for profile in [PagingPolicy::Emulator, PagingPolicy::Strict] {
        let h = Harness::new(profile).await;
        let cases = [
            (
                "hybrid-top",
                json!({"message_storagePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
            ),
            (
                "hybrid-top-b",
                json!({"messageStorage_policy": {"allowedPersistenceRegions": ["us-central1"]}}),
            ),
            (
                "hybrid-regions",
                json!({"messageStoragePolicy": {"allowed_persistenceRegions": ["us-central1"]}}),
            ),
            (
                "hybrid-regions-b",
                json!({"messageStoragePolicy": {"allowedPersistence_regions": ["us-central1"]}}),
            ),
            (
                "hybrid-enforce",
                json!({"message_storage_policy": {"enforce_inTransit": true}}),
            ),
            (
                "hybrid-retention",
                json!({"message_retentionDuration": "600s"}),
            ),
            ("hybrid-state", json!({"satisfies_Pzs": true})),
            (
                "capitalised",
                json!({"MessageStoragePolicy": {"enforceInTransit": true}}),
            ),
        ];
        for (id, body) in cases {
            let (status, error) = h.rest_create(id, body).await;
            assert_eq!(status, 400, "{profile:?} {id}: {error}");
            assert_eq!(error["error"]["status"], "INVALID_ARGUMENT", "{id}");
            assert_eq!(h.rest_get(id).await.0, 404, "{profile:?} {id} was created");
        }
        // The two accepted spellings still work in a profile that stores the field.
        if profile == PagingPolicy::Emulator {
            for (id, body) in [
                (
                    "camel",
                    json!({"messageStoragePolicy": {"allowedPersistenceRegions": ["a"], "enforceInTransit": true}}),
                ),
                (
                    "snake",
                    json!({"message_storage_policy": {"allowed_persistence_regions": ["a"], "enforce_in_transit": true}}),
                ),
            ] {
                let (status, created) = h.rest_create(id, body).await;
                assert_eq!(status, 200, "{id}: {created}");
                assert_eq!(
                    created["messageStoragePolicy"],
                    json!({"allowedPersistenceRegions": ["a"], "enforceInTransit": true}),
                    "{id}"
                );
            }
        }
    }
}

#[tokio::test]
async fn hybrid_update_mask_spellings_are_unknown_paths_and_change_nothing() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "hybrid-mask",
        json!({"labels": {"keep": "me"}, "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
    )
    .await;
    let before = h.rest_get("hybrid-mask").await;
    for mask in [
        "messageStoragePolicy.allowed_persistenceRegions",
        "message_storagePolicy",
        "message_storagePolicy.enforce_in_transit",
        "labels,message_storagePolicy",
        "messageStoragePolicy.enforce_inTransit",
    ] {
        let (status, error) = h
            .rest_patch(
                "hybrid-mask",
                json!({"labels": {"k": "v"}, "messageStoragePolicy": {"allowedPersistenceRegions": ["asia-east1"]}}),
                mask,
            )
            .await;
        assert_eq!(status, 400, "{mask}: {error}");
        assert_eq!(error["error"]["status"], "INVALID_ARGUMENT", "{mask}");
        assert_eq!(h.rest_get("hybrid-mask").await, before, "{mask}");
    }
}

#[tokio::test]
async fn duplicate_and_overlapping_masks_apply_once_in_every_spelling() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let start = json!({
        "labels": {"keep": "me"},
        "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"], "enforceInTransit": true},
    });
    // (REST mask, the body's policy, expected policy, expected labels)
    let cases = [
        (
            "messageStoragePolicy,messageStoragePolicy",
            json!({"allowedPersistenceRegions": ["asia-east1"]}),
            json!({"allowedPersistenceRegions": ["asia-east1"]}),
            json!({"keep": "me"}),
        ),
        (
            "messageStoragePolicy,message_storage_policy",
            json!({"allowedPersistenceRegions": ["asia-east1"]}),
            json!({"allowedPersistenceRegions": ["asia-east1"]}),
            json!({"keep": "me"}),
        ),
        // The whole path wins over a member path, whatever the order or the spelling.
        (
            "messageStoragePolicy.enforceInTransit,message_storage_policy",
            json!({"allowedPersistenceRegions": ["asia-east1"]}),
            json!({"allowedPersistenceRegions": ["asia-east1"]}),
            json!({"keep": "me"}),
        ),
        (
            "message_storage_policy,messageStoragePolicy.allowedPersistenceRegions",
            json!({"enforceInTransit": false}),
            json!({}),
            json!({"keep": "me"}),
        ),
        // The same member twice, in both spellings.
        (
            "message_storage_policy.allowed_persistence_regions,messageStoragePolicy.allowedPersistenceRegions",
            json!({"allowedPersistenceRegions": ["europe-west1"]}),
            json!({"allowedPersistenceRegions": ["europe-west1"], "enforceInTransit": true}),
            json!({"keep": "me"}),
        ),
        // Both members, in mixed spellings: the topic's own body supplies both values.
        (
            "messageStoragePolicy.allowedPersistenceRegions,message_storage_policy.enforce_in_transit",
            json!({"allowedPersistenceRegions": ["europe-west1"]}),
            json!({"allowedPersistenceRegions": ["europe-west1"]}),
            json!({"keep": "me"}),
        ),
        // The same labels twice, beside a duplicate member path.
        (
            "labels,labels,messageStoragePolicy.enforceInTransit,messageStoragePolicy.enforceInTransit",
            json!({"enforceInTransit": false}),
            json!({"allowedPersistenceRegions": ["us-central1"]}),
            json!({"owner": "test"}),
        ),
    ];
    for (index, (mask, body_policy, expected_policy, expected_labels)) in
        cases.into_iter().enumerate()
    {
        let id = format!("overlap-{index}");
        h.rest_create(&id, start.clone()).await;
        let (status, updated) = h
            .rest_patch(
                &id,
                json!({"labels": {"owner": "test"}, "messageStoragePolicy": body_policy}),
                mask,
            )
            .await;
        assert_eq!(status, 200, "{mask}: {updated}");
        assert_eq!(updated["messageStoragePolicy"], expected_policy, "{mask}");
        let labels = if mask.contains("labels") {
            expected_labels
        } else {
            json!({"keep": "me"})
        };
        assert_eq!(updated["labels"], labels, "{mask}");
        // The read after the update agrees with the answer to it.
        assert_eq!(h.rest_get(&id).await.1, updated, "{mask}");
    }
}

#[tokio::test]
async fn duplicate_and_overlapping_grpc_paths_apply_once() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let cases: [(&[&str], pb::MessageStoragePolicy, pb::MessageStoragePolicy); 5] = [
        (
            &["message_storage_policy", "message_storage_policy"],
            policy(&["asia-east1"], false),
            policy(&["asia-east1"], false),
        ),
        (
            &[
                "message_storage_policy.enforce_in_transit",
                "message_storage_policy",
            ],
            policy(&["asia-east1"], false),
            policy(&["asia-east1"], false),
        ),
        (
            &[
                "message_storage_policy.allowed_persistence_regions",
                "message_storage_policy.allowed_persistence_regions",
            ],
            policy(&["europe-west1"], false),
            policy(&["europe-west1"], true),
        ),
        (
            &[
                "message_storage_policy.enforce_in_transit",
                "message_storage_policy.allowed_persistence_regions",
            ],
            policy(&["europe-west1"], false),
            policy(&["europe-west1"], false),
        ),
        (
            &[
                "labels",
                "message_storage_policy.enforce_in_transit",
                "labels",
            ],
            policy(&["ignored"], false),
            policy(&["us-central1"], false),
        ),
    ];
    for (index, (paths, requested, expected)) in cases.into_iter().enumerate() {
        let id = format!("grpc-overlap-{index}");
        h.grpc_create(&id, Some(policy(&["us-central1"], true)))
            .await;
        let updated = h
            .grpc_update(
                &id,
                pb::Topic {
                    labels: [("owner".to_owned(), "test".to_owned())].into(),
                    message_storage_policy: Some(requested),
                    ..Default::default()
                },
                paths,
            )
            .await
            .unwrap();
        assert_eq!(updated.message_storage_policy, Some(expected), "{paths:?}");
        assert_eq!(
            updated.labels.contains_key("owner"),
            paths.contains(&"labels"),
            "{paths:?}"
        );
        assert_eq!(h.grpc_get(&id).await, updated, "{paths:?}");
    }
}

#[tokio::test]
async fn a_refused_mixed_update_changes_neither_labels_nor_policy() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "mixed",
        json!({"labels": {"keep": "me"}, "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
    )
    .await;
    let before_rest = h.rest_get("mixed").await;
    let before_grpc = h.grpc_get("mixed").await;
    let body = json!({"labels": {"k": "v"}, "messageStoragePolicy": {"allowedPersistenceRegions": ["asia-east1"]}});
    for (mask, expected) in [
        ("labels,messageStoragePolicy,schemaSettings", 501),
        ("labels,messageStoragePolicy,messageRetentionDuration", 501),
        ("labels,messageStoragePolicy,state", 501),
        ("labels,messageStoragePolicy,notAField", 400),
        ("labels,messageStoragePolicy.noSuch", 400),
        ("messageStoragePolicy,labels.owner", 501),
    ] {
        let (status, error) = h.rest_patch("mixed", body.clone(), mask).await;
        assert_eq!(status, expected, "{mask}: {error}");
        assert_eq!(h.rest_get("mixed").await, before_rest, "{mask}");
        assert_eq!(h.grpc_get("mixed").await, before_grpc, "{mask}");
    }
    // A malformed policy in an otherwise valid mixed mask is refused before anything applies.
    let (status, error) = h
        .rest_patch(
            "mixed",
            json!({"labels": {"k": "v"}, "messageStoragePolicy": {"enforceInTransit": "yes"}}),
            "labels,messageStoragePolicy",
        )
        .await;
    assert_eq!(status, 400, "{error}");
    assert_eq!(h.rest_get("mixed").await, before_rest);

    for (paths, code) in [
        (
            vec!["labels", "message_storage_policy", "schema_settings"],
            tonic::Code::Unimplemented,
        ),
        (
            vec!["labels", "message_storage_policy", "state"],
            tonic::Code::Unimplemented,
        ),
        (
            vec!["labels", "message_storage_policy.nope"],
            tonic::Code::InvalidArgument,
        ),
        (
            vec!["labels", "message_storage_policy", "not_a_field"],
            tonic::Code::InvalidArgument,
        ),
    ] {
        let error = h
            .grpc_update(
                "mixed",
                pb::Topic {
                    labels: [("k".to_owned(), "v".to_owned())].into(),
                    message_storage_policy: Some(policy(&["asia-east1"], true)),
                    ..Default::default()
                },
                &paths,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), code, "{paths:?}: {error}");
        assert_eq!(h.rest_get("mixed").await, before_rest, "{paths:?}");
        assert_eq!(h.grpc_get("mixed").await, before_grpc, "{paths:?}");
    }
}
