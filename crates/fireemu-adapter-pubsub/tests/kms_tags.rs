//! Topic `kmsKeyName` and `tags` admission and round trip across both transports and both profiles.
//!
//! Evidence behind the expectations:
//! - The official Pub/Sub emulator shipped with firebase-tools 15.28.2 (pubsub-emulator 0.8.35,
//!   probed over gRPC on 2026-11-10) stores both fields without looking at them: a malformed key
//!   name, spaces and Unicode, a 5000 character key name, an empty tag key, an empty tag value and
//!   100 tags were all accepted and returned unchanged by Get and List. An empty key name is the
//!   same as none. Its `UpdateTopic` refuses every field mask, and a duplicate `CreateTopic`
//!   changes nothing.
//! - Production behaviour is not recorded for either field, so the strict profile keeps refusing.
//! - The vendored proto documents `kms_key_name` as updatable and `tags` as input only and
//!   immutable; the emulator profile follows that for `UpdateTopic`.

use std::sync::{Arc, Mutex};

use fireemu_adapter_pubsub::{serve_pubsub, PagingPolicy, PubSubHandle};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k";
const OTHER_KEY: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/other";

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

    async fn rest_delete(&self, id: &str) -> u16 {
        self.rest(
            "DELETE",
            &format!("/v1/projects/demo-app/topics/{id}"),
            json!({}),
        )
        .await
        .0
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

    async fn grpc_create_topic(
        &self,
        id: &str,
        mut topic: pb::Topic,
    ) -> Result<pb::Topic, tonic::Status> {
        topic.name = topic_name(id);
        self.grpc()
            .await
            .create_topic(topic)
            .await
            .map(tonic::Response::into_inner)
    }

    async fn grpc_create(&self, id: &str, kms: &str, tags: &[(&str, &str)]) -> pb::Topic {
        self.grpc_create_topic(
            id,
            pb::Topic {
                kms_key_name: kms.to_owned(),
                tags: tag_map(tags),
                ..Default::default()
            },
        )
        .await
        .unwrap()
    }

    async fn grpc_update(
        &self,
        id: &str,
        topic: pb::Topic,
        paths: &[&str],
    ) -> Result<pb::Topic, tonic::Status> {
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
    }
}

fn topic_name(id: &str) -> String {
    format!("projects/demo-app/topics/{id}")
}

fn tag_map(tags: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
    tags.iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

// --- Emulator profile: the shapes the official emulator stores -------------------------------

/// Each row is accepted by the official emulator and returned unchanged by its Get and List.
fn official_kms_names() -> Vec<(&'static str, String)> {
    vec![
        ("well-formed", KEY.to_owned()),
        ("garbage", "not a key name".to_owned()),
        ("spaces-and-unicode", " \u{3042} ".to_owned()),
        ("long", "x".repeat(5000)),
    ]
}

fn official_tag_sets() -> Vec<(&'static str, Vec<(String, String)>)> {
    let pair = |key: &str, value: &str| (key.to_owned(), value.to_owned());
    vec![
        ("one", vec![pair("a/b", "c")]),
        (
            "mixed",
            vec![
                pair("p/k1", "v1"),
                pair("p/k2", "v2"),
                pair("plain", "x"),
                pair("", "emptykey"),
                pair("e", ""),
            ],
        ),
        (
            "many",
            (0..100)
                .map(|i| (format!("k{i}"), format!("v{i}")))
                .collect(),
        ),
        (
            "unicode-and-long",
            vec![("\u{3042}/\u{3044}".to_owned(), "x".repeat(300))],
        ),
        // Two keys that normalize to the same field name are still two different map keys.
        ("case-variants", vec![pair("aB", "1"), pair("a_b", "2")]),
    ]
}

fn tags_json(tags: &[(String, String)]) -> Value {
    Value::Object(
        tags.iter()
            .map(|(key, value)| (key.clone(), json!(value)))
            .collect(),
    )
}

fn tags_wire(tags: &[(String, String)]) -> std::collections::HashMap<String, String> {
    tags.iter().cloned().collect()
}

#[tokio::test]
async fn every_kms_key_name_the_official_emulator_stores_round_trips_over_rest() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    for (id, key) in official_kms_names() {
        let (status, created) = h.rest_create(id, json!({"kmsKeyName": key})).await;
        let expected = json!({"name": topic_name(id), "kmsKeyName": key});
        assert_eq!((status, &created), (200, &expected), "{id}");
        assert_eq!(h.rest_get(id).await, (200, expected.clone()), "{id}");
        assert_eq!(h.rest_listed(id).await, expected, "{id}");
        // Over gRPC the same stored value comes back.
        assert_eq!(h.grpc_get(id).await.kms_key_name, key, "{id}");
        assert_eq!(h.grpc_listed(id).await.kms_key_name, key, "{id}");
    }
}

#[tokio::test]
async fn every_kms_key_name_the_official_emulator_stores_round_trips_over_grpc() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    for (id, key) in official_kms_names() {
        let created = h.grpc_create(id, &key, &[]).await;
        assert_eq!(created.kms_key_name, key, "{id}");
        assert_eq!(h.grpc_get(id).await, created, "{id}");
        assert_eq!(h.grpc_listed(id).await, created, "{id}");
        let (status, rest) = h.rest_get(id).await;
        assert_eq!(status, 200, "{id}");
        assert_eq!(rest["kmsKeyName"], key, "{id}");
    }
}

#[tokio::test]
async fn every_tag_set_the_official_emulator_stores_round_trips_over_rest_and_grpc() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    for (id, tags) in official_tag_sets() {
        let rest_id = format!("rest-{id}");
        let (status, created) = h
            .rest_create(&rest_id, json!({"tags": tags_json(&tags)}))
            .await;
        let expected = json!({"name": topic_name(&rest_id), "tags": tags_json(&tags)});
        assert_eq!((status, &created), (200, &expected), "{id}");
        assert_eq!(h.rest_get(&rest_id).await, (200, expected.clone()), "{id}");
        assert_eq!(h.rest_listed(&rest_id).await, expected, "{id}");
        assert_eq!(h.grpc_get(&rest_id).await.tags, tags_wire(&tags), "{id}");
        assert_eq!(h.grpc_listed(&rest_id).await.tags, tags_wire(&tags), "{id}");

        let grpc_id = format!("grpc-{id}");
        let created = h
            .grpc_create_topic(
                &grpc_id,
                pb::Topic {
                    tags: tags_wire(&tags),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(created.tags, tags_wire(&tags), "{id}");
        assert_eq!(h.grpc_get(&grpc_id).await, created, "{id}");
        assert_eq!(h.grpc_listed(&grpc_id).await, created, "{id}");
        let (status, rest) = h.rest_get(&grpc_id).await;
        assert_eq!(status, 200, "{id}");
        assert_eq!(rest["tags"], tags_json(&tags), "{id}");
    }
}

#[tokio::test]
async fn raw_json_duplicate_members_and_tag_order() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    // This pins current behavior: the last duplicate member wins. Neither the gRPC-only
    // official emulator nor production was recorded for duplicate JSON members.
    for (id, body) in [
        (
            "duplicate-tags",
            &br#"{"tags":{"k":"first","k":"last"}}"#[..],
        ),
        (
            "duplicate-kms",
            &br#"{"kmsKeyName":"first","kmsKeyName":"last"}"#[..],
        ),
        (
            "both-spellings",
            &br#"{"kmsKeyName":"first","kms_key_name":"last"}"#[..],
        ),
        ("tags-ab", &br#"{"tags":{"a":"1","b":"2"}}"#[..]),
        ("tags-ba", &br#"{"tags":{"b":"2","a":"1"}}"#[..]),
    ] {
        let mut stream = tokio::net::TcpStream::connect(h.address).await.unwrap();
        let headers = format!("PUT /v1/projects/demo-app/topics/{id} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", h.address, body.len());
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let split = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        let status: u16 = std::str::from_utf8(&response[..split])
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let created: Value = serde_json::from_slice(&response[split + 4..]).unwrap();
        if id == "both-spellings" {
            // This also pins current behavior; neither the gRPC-only official emulator nor
            // production was recorded for duplicate JSON members with both spellings.
            assert_eq!(status, 400, "{created}");
            assert_eq!(created["error"]["status"], "INVALID_ARGUMENT");
            assert_eq!(h.rest_get(id).await.0, 404);
            continue;
        }
        let expected = match id {
            "duplicate-tags" => json!({"name": topic_name(id), "tags": {"k": "last"}}),
            "duplicate-kms" => json!({"name": topic_name(id), "kmsKeyName": "last"}),
            _ => json!({"name": topic_name(id), "tags": {"a": "1", "b": "2"}}),
        };
        assert_eq!((status, &created), (200, &expected), "{id}");
        assert_eq!(h.rest_get(id).await, (200, expected), "{id}");
        let topic = h.grpc_get(id).await;
        match id {
            "duplicate-tags" => assert_eq!(topic.tags, tag_map(&[("k", "last")])),
            "duplicate-kms" => assert_eq!(topic.kms_key_name, "last"),
            _ => assert_eq!(topic.tags, tag_map(&[("a", "1"), ("b", "2")])),
        }
    }
}

#[tokio::test]
async fn snake_case_spelling_of_the_key_name_is_accepted() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let (status, created) = h.rest_create("snake", json!({"kms_key_name": KEY})).await;
    assert_eq!(status, 200, "{created}");
    assert_eq!(created["kmsKeyName"], KEY);
}

#[tokio::test]
async fn empty_null_and_absent_fields_are_the_same_absence() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    for (id, body) in [
        ("omitted", json!({})),
        ("empty-kms", json!({"kmsKeyName": ""})),
        ("null-kms", json!({"kmsKeyName": null})),
        ("empty-tags", json!({"tags": {}})),
        ("null-tags", json!({"tags": null})),
        (
            "all-empty",
            json!({"kmsKeyName": "", "tags": {}, "labels": {}}),
        ),
    ] {
        let (status, created) = h.rest_create(id, body).await;
        assert_eq!(status, 200, "{id}: {created}");
        assert_eq!(created, json!({"name": topic_name(id)}), "{id}");
        let topic = h.grpc_get(id).await;
        assert_eq!(topic.kms_key_name, "", "{id}");
        assert!(topic.tags.is_empty(), "{id}");
    }
    let created = h.grpc_create("grpc-empty", "", &[]).await;
    assert_eq!(created.kms_key_name, "");
    assert!(created.tags.is_empty());
}

#[tokio::test]
async fn the_fields_belong_to_their_topic_and_do_not_survive_deletion() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create("owner", json!({"kmsKeyName": KEY, "tags": {"a/b": "c"}}))
        .await;
    h.rest_create("neighbour", json!({})).await;
    assert_eq!(
        h.rest_get("neighbour").await.1,
        json!({"name": topic_name("neighbour")})
    );
    // A duplicate create is refused and changes nothing, as in the official emulator.
    let (status, error) = h
        .rest_create(
            "owner",
            json!({"kmsKeyName": OTHER_KEY, "tags": {"x": "y"}}),
        )
        .await;
    assert_eq!(status, 409, "{error}");
    let error = h
        .grpc_create_topic(
            "owner",
            pb::Topic {
                kms_key_name: OTHER_KEY.to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::AlreadyExists);
    let after = h.grpc_get("owner").await;
    assert_eq!(after.kms_key_name, KEY);
    assert_eq!(after.tags, tag_map(&[("a/b", "c")]));
    // Delete and re-create without the fields: nothing is inherited.
    assert_eq!(h.rest_delete("owner").await, 200);
    let (status, recreated) = h.rest_create("owner", json!({})).await;
    assert_eq!(status, 200, "{recreated}");
    assert_eq!(recreated, json!({"name": topic_name("owner")}));
    let topic = h.grpc_get("owner").await;
    assert_eq!(topic.kms_key_name, "");
    assert!(topic.tags.is_empty());
}

#[tokio::test]
async fn the_fields_do_not_disturb_labels_retention_or_the_storage_policy() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let body = json!({
        "kmsKeyName": KEY,
        "tags": {"a/b": "c"},
        "labels": {"l": "v"},
        "messageRetentionDuration": "3600s",
        "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]},
    });
    let (status, created) = h.rest_create("combined", body.clone()).await;
    assert_eq!(status, 200, "{created}");
    let mut expected = body;
    expected["name"] = json!(topic_name("combined"));
    assert_eq!(created, expected);
    assert_eq!(h.rest_get("combined").await.1, expected);
    assert_eq!(h.rest_listed("combined").await, expected);
    let wire = h.grpc_get("combined").await;
    assert_eq!(wire.kms_key_name, KEY);
    assert_eq!(wire.tags, tag_map(&[("a/b", "c")]));
    assert_eq!(wire.labels, tag_map(&[("l", "v")]));
    assert_eq!(
        wire.message_retention_duration.map(|d| d.seconds),
        Some(3600)
    );
    assert_eq!(
        wire.message_storage_policy
            .map(|policy| policy.allowed_persistence_regions),
        Some(vec!["us-central1".to_owned()])
    );
}

#[tokio::test]
async fn malformed_bodies_are_invalid_arguments_and_create_nothing() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    let cases = [
        ("number-kms", json!({"kmsKeyName": 1})),
        ("object-kms", json!({"kmsKeyName": {}})),
        ("array-kms", json!({"kmsKeyName": []})),
        ("string-tags", json!({"tags": "a/b=c"})),
        ("array-tags", json!({"tags": ["a/b"]})),
        ("number-tag-value", json!({"tags": {"a/b": 1}})),
        ("null-tag-value", json!({"tags": {"a/b": null}})),
        ("object-tag-value", json!({"tags": {"a/b": {}}})),
        (
            "duplicate-kms-spelling",
            json!({"kmsKeyName": KEY, "kms_key_name": KEY}),
        ),
        // Proto3 JSON accepts the lowerCamelCase or the snake_case name, not a mixture.
        ("hybrid-kms", json!({"kms_keyName": KEY})),
        ("hybrid-kms-b", json!({"kmsKey_name": KEY})),
        ("capitalised-kms", json!({"KmsKeyName": KEY})),
        ("capitalised-tags", json!({"Tags": {"a/b": "c"}})),
    ];
    for (id, body) in cases {
        let (status, error) = h.rest_create(id, body).await;
        assert_eq!(status, 400, "{id}: {error}");
        assert_eq!(error["error"]["status"], "INVALID_ARGUMENT", "{id}");
        assert_eq!(h.rest_get(id).await.0, 404, "{id} was created");
    }
}

#[tokio::test]
async fn the_remaining_unsupported_topic_fields_are_still_refused_in_the_emulator_profile() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    for (id, body, field) in [
        ("schema", json!({"schemaSettings": {}}), "schema_settings"),
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
        (
            "mixed",
            json!({"kmsKeyName": KEY, "tags": {"a/b": "c"}, "schemaSettings": {}}),
            "schema_settings",
        ),
    ] {
        let (status, error) = h.rest_create(id, body).await;
        assert_eq!(status, 501, "{id}: {error}");
        assert!(error["error"]["message"].as_str().unwrap().contains(field));
        assert_eq!(h.rest_get(id).await.0, 404, "{id} was created");
    }
}

// --- Emulator profile: UpdateTopic -----------------------------------------------------------

#[tokio::test]
async fn rest_patch_replaces_the_key_name_when_the_mask_names_it() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "patch",
        json!({"kmsKeyName": KEY, "tags": {"a/b": "c"}, "labels": {"keep": "me"}}),
    )
    .await;
    for mask in ["kmsKeyName", "kms_key_name"] {
        let (status, updated) = h
            .rest_patch("patch", json!({"kmsKeyName": OTHER_KEY}), mask)
            .await;
        assert_eq!(status, 200, "{mask}: {updated}");
        assert_eq!(updated["kmsKeyName"], OTHER_KEY, "{mask}");
        // Labels and tags are untouched because the mask does not name them.
        assert_eq!(updated["labels"], json!({"keep": "me"}), "{mask}");
        assert_eq!(updated["tags"], json!({"a/b": "c"}), "{mask}");
        assert_eq!(h.grpc_get("patch").await.kms_key_name, OTHER_KEY, "{mask}");
        // Put the first key back for the next spelling.
        let (status, _) = h
            .rest_patch("patch", json!({"kmsKeyName": KEY}), "kmsKeyName")
            .await;
        assert_eq!(status, 200);
    }
}

#[tokio::test]
async fn rest_patch_with_the_mask_and_no_key_in_the_topic_clears_the_key() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create("clear", json!({"kmsKeyName": KEY, "tags": {"a/b": "c"}}))
        .await;
    let (status, updated) = h.rest_patch("clear", json!({}), "kmsKeyName").await;
    assert_eq!(status, 200, "{updated}");
    assert!(updated.get("kmsKeyName").is_none(), "{updated}");
    assert_eq!(updated["tags"], json!({"a/b": "c"}));
    assert_eq!(h.grpc_get("clear").await.kms_key_name, "");
    // An empty string and null clear it the same way.
    h.rest_patch("clear", json!({"kmsKeyName": KEY}), "kmsKeyName")
        .await;
    let (_, cleared) = h
        .rest_patch("clear", json!({"kmsKeyName": ""}), "kmsKeyName")
        .await;
    assert!(cleared.get("kmsKeyName").is_none(), "{cleared}");
    h.rest_patch("clear", json!({"kmsKeyName": KEY}), "kmsKeyName")
        .await;
    let (_, cleared) = h
        .rest_patch("clear", json!({"kmsKeyName": null}), "kmsKeyName")
        .await;
    assert!(cleared.get("kmsKeyName").is_none(), "{cleared}");
}

#[tokio::test]
async fn rest_patch_leaves_the_key_and_tags_alone_unless_the_mask_names_the_key() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create("keep", json!({"kmsKeyName": KEY, "tags": {"a/b": "c"}}))
        .await;
    // The topic carries other values, but the mask selects only the labels.
    let (status, updated) = h
        .rest_patch(
            "keep",
            json!({"labels": {"k": "v"}, "kmsKeyName": OTHER_KEY, "tags": {"x": "y"}}),
            "labels",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["labels"], json!({"k": "v"}));
    assert_eq!(updated["kmsKeyName"], KEY);
    assert_eq!(updated["tags"], json!({"a/b": "c"}));
}

#[tokio::test]
async fn rest_patch_updates_the_key_and_the_other_supported_fields_together() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "together",
        json!({"kmsKeyName": KEY, "tags": {"a/b": "c"}, "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
    )
    .await;
    for mask in [
        "labels,kmsKeyName,messageStoragePolicy",
        "kmsKeyName,labels,messageStoragePolicy",
        "kms_key_name,labels,message_storage_policy",
        // A repeated path applies once.
        "kmsKeyName,kmsKeyName,labels,messageStoragePolicy",
    ] {
        let (status, updated) = h
            .rest_patch(
                "together",
                json!({
                    "labels": {"k": "v"},
                    "kmsKeyName": OTHER_KEY,
                    "messageStoragePolicy": {"allowedPersistenceRegions": ["asia-east1"]},
                }),
                mask,
            )
            .await;
        assert_eq!(status, 200, "{mask}: {updated}");
        assert_eq!(
            updated,
            json!({
                "name": topic_name("together"),
                "labels": {"k": "v"},
                "kmsKeyName": OTHER_KEY,
                "tags": {"a/b": "c"},
                "messageStoragePolicy": {"allowedPersistenceRegions": ["asia-east1"]},
            }),
            "{mask}"
        );
        h.rest_patch(
            "together",
            json!({"kmsKeyName": KEY, "messageStoragePolicy": {"allowedPersistenceRegions": ["us-central1"]}}),
            "kmsKeyName,messageStoragePolicy",
        )
        .await;
    }
}

#[tokio::test]
async fn a_mask_that_names_tags_is_refused_and_changes_nothing() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "immutable",
        json!({"kmsKeyName": KEY, "tags": {"a/b": "c"}, "labels": {"keep": "me"}}),
    )
    .await;
    let before = h.rest_get("immutable").await;
    for mask in [
        "tags",
        "tags.a/b",
        "labels,tags",
        "tags,kmsKeyName",
        "kmsKeyName,tags",
    ] {
        let (status, error) = h
            .rest_patch(
                "immutable",
                json!({"labels": {"k": "v"}, "kmsKeyName": OTHER_KEY, "tags": {"x": "y"}}),
                mask,
            )
            .await;
        assert_eq!(status, 400, "{mask}: {error}");
        assert_eq!(error["error"]["status"], "INVALID_ARGUMENT", "{mask}");
        let message = error["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("tags") && message.contains("immutable"),
            "{mask}: {message}"
        );
        assert_eq!(h.rest_get("immutable").await, before, "{mask}");
    }
}

#[tokio::test]
async fn hybrid_mask_spellings_are_unknown_paths_and_change_nothing() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create("hybrid-mask", json!({"kmsKeyName": KEY}))
        .await;
    let before = h.rest_get("hybrid-mask").await;
    for mask in [
        "kms_keyName",
        "kmsKey_name",
        "labels,kms_keyName",
        "kmsKeyNameX",
    ] {
        let (status, error) = h
            .rest_patch("hybrid-mask", json!({"kmsKeyName": OTHER_KEY}), mask)
            .await;
        assert_eq!(status, 400, "{mask}: {error}");
        assert_eq!(error["error"]["status"], "INVALID_ARGUMENT", "{mask}");
        assert_eq!(h.rest_get("hybrid-mask").await, before, "{mask}");
    }
}

#[tokio::test]
async fn a_malformed_patch_body_is_refused_before_anything_is_applied() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.rest_create(
        "refuse",
        json!({"kmsKeyName": KEY, "labels": {"keep": "me"}}),
    )
    .await;
    let before = h.rest_get("refuse").await;
    for (mask, topic, expected) in [
        (
            "labels,kmsKeyName",
            json!({"labels": {"k": "v"}, "kmsKeyName": 1}),
            400,
        ),
        ("kmsKeyName", json!({"kmsKeyName": {}}), 400),
        // A mask path the emulator cannot apply refuses the whole update.
        (
            "kmsKeyName,schemaSettings",
            json!({"kmsKeyName": OTHER_KEY}),
            501,
        ),
        ("kmsKeyName,state", json!({"kmsKeyName": OTHER_KEY}), 501),
        (
            "kmsKeyName,noSuchField",
            json!({"kmsKeyName": OTHER_KEY}),
            400,
        ),
    ] {
        let (status, error) = h.rest_patch("refuse", topic, mask).await;
        assert_eq!(status, expected, "{mask}: {error}");
        assert_eq!(h.rest_get("refuse").await, before, "{mask}");
    }
    let (status, error) = h
        .rest_patch("missing", json!({"kmsKeyName": KEY}), "kmsKeyName")
        .await;
    assert_eq!(status, 404, "{error}");
    assert_eq!(h.rest_get("missing").await.0, 404);
}

#[tokio::test]
async fn grpc_update_topic_applies_the_key_mask_and_refuses_tags() {
    let h = Harness::new(PagingPolicy::Emulator).await;
    h.grpc_create("grpc-patch", KEY, &[("a/b", "c")]).await;
    let updated = h
        .grpc_update(
            "grpc-patch",
            pb::Topic {
                kms_key_name: OTHER_KEY.to_owned(),
                tags: tag_map(&[("x", "y")]),
                labels: tag_map(&[("ignored", "yes")]),
                ..Default::default()
            },
            &["kms_key_name"],
        )
        .await
        .unwrap();
    assert_eq!(updated.kms_key_name, OTHER_KEY);
    assert_eq!(updated.tags, tag_map(&[("a/b", "c")]));
    assert!(updated.labels.is_empty());
    assert_eq!(h.grpc_get("grpc-patch").await, updated);
    // Together with the labels, and a repeated path applies once.
    let updated = h
        .grpc_update(
            "grpc-patch",
            pb::Topic {
                labels: tag_map(&[("k", "v")]),
                ..Default::default()
            },
            &["labels", "kms_key_name", "kms_key_name"],
        )
        .await
        .unwrap();
    assert_eq!(updated.kms_key_name, "");
    assert_eq!(updated.labels, tag_map(&[("k", "v")]));
    assert_eq!(updated.tags, tag_map(&[("a/b", "c")]));

    let before = h.grpc_get("grpc-patch").await;
    for paths in [
        &["tags"][..],
        &["tags.a/b"],
        &["labels", "tags"],
        &["kms_key_name", "tags"],
    ] {
        let error = h
            .grpc_update(
                "grpc-patch",
                pb::Topic {
                    kms_key_name: KEY.to_owned(),
                    tags: tag_map(&[("x", "y")]),
                    ..Default::default()
                },
                paths,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument, "{paths:?}");
        assert!(error.message().contains("immutable"), "{paths:?}: {error}");
        assert_eq!(h.grpc_get("grpc-patch").await, before, "{paths:?}");
    }
    // Hybrid and camelCase spellings are unknown paths over gRPC, which only knows protobuf names.
    for path in ["kmsKeyName", "kms_keyName"] {
        let error = h
            .grpc_update("grpc-patch", pb::Topic::default(), &[path])
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument, "{path}");
        assert_eq!(h.grpc_get("grpc-patch").await, before, "{path}");
    }
    let error = h
        .grpc_update("missing", pb::Topic::default(), &["kms_key_name"])
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
}

// --- Strict profile --------------------------------------------------------------------------

fn assert_strict_explanation(message: &str, field: &str) {
    assert!(message.contains(&format!("topic.{field}")), "{message}");
    // Why: production's answer is not recorded and strict has nothing to check against.
    assert!(message.contains("strict profile"), "{message}");
    assert!(message.contains("not recorded"), "{message}");
    // How to proceed: the profile that stores it, or leaving it out.
    assert!(message.contains(r#"profile = "emulator""#), "{message}");
}

#[tokio::test]
async fn strict_refuses_every_key_name_and_tag_set_on_create_over_rest_and_grpc() {
    let h = Harness::new(PagingPolicy::Strict).await;
    for (id, key) in official_kms_names() {
        let (status, error) = h
            .rest_create(&format!("rest-kms-{id}"), json!({"kmsKeyName": key}))
            .await;
        assert_eq!(status, 501, "{id}: {error}");
        assert_eq!(error["error"]["status"], "UNIMPLEMENTED", "{id}");
        assert_strict_explanation(error["error"]["message"].as_str().unwrap(), "kms_key_name");
        assert_eq!(h.rest_get(&format!("rest-kms-{id}")).await.0, 404, "{id}");
        let error = h
            .grpc_create_topic(
                &format!("grpc-kms-{id}"),
                pb::Topic {
                    kms_key_name: key,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{id}");
        assert_strict_explanation(error.message(), "kms_key_name");
    }
    for (id, tags) in official_tag_sets() {
        let (status, error) = h
            .rest_create(
                &format!("rest-tags-{id}"),
                json!({"tags": tags_json(&tags)}),
            )
            .await;
        assert_eq!(status, 501, "{id}: {error}");
        assert_eq!(error["error"]["status"], "UNIMPLEMENTED", "{id}");
        assert_strict_explanation(error["error"]["message"].as_str().unwrap(), "tags");
        assert_eq!(h.rest_get(&format!("rest-tags-{id}")).await.0, 404, "{id}");
        let error = h
            .grpc_create_topic(
                &format!("grpc-tags-{id}"),
                pb::Topic {
                    tags: tags_wire(&tags),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{id}");
        assert_strict_explanation(error.message(), "tags");
    }
}

#[tokio::test]
async fn strict_still_creates_topics_without_the_fields_and_reports_none() {
    let h = Harness::new(PagingPolicy::Strict).await;
    for (id, body) in [
        ("omitted", json!({})),
        ("empty-kms", json!({"kmsKeyName": ""})),
        ("null-kms", json!({"kmsKeyName": null})),
        ("empty-tags", json!({"tags": {}})),
        ("null-tags", json!({"tags": null})),
    ] {
        let (status, created) = h.rest_create(id, body).await;
        assert_eq!(status, 200, "{id}: {created}");
        assert_eq!(created, json!({"name": topic_name(id)}), "{id}");
    }
    let topic = h.grpc_get("omitted").await;
    assert_eq!(topic.kms_key_name, "");
    assert!(topic.tags.is_empty());
}

#[tokio::test]
async fn strict_refuses_the_fields_in_an_update_mask_and_changes_nothing() {
    let h = Harness::new(PagingPolicy::Strict).await;
    h.rest_create("strict-patch", json!({"labels": {"keep": "me"}}))
        .await;
    let before_rest = h.rest_get("strict-patch").await;
    let before_grpc = h.grpc_get("strict-patch").await;
    // (REST mask, gRPC paths, the field the refusal names)
    let masks: [(&str, &[&str], &str); 6] = [
        ("kmsKeyName", &["kms_key_name"], "kms_key_name"),
        ("kms_key_name", &["kms_key_name"], "kms_key_name"),
        (
            "labels,kmsKeyName",
            &["labels", "kms_key_name"],
            "kms_key_name",
        ),
        ("tags", &["tags"], "tags"),
        ("tags.a/b", &["tags.a/b"], "tags"),
        ("labels,tags", &["labels", "tags"], "tags"),
    ];
    for (mask, paths, field) in masks {
        let (status, error) = h
            .rest_patch(
                "strict-patch",
                json!({"labels": {"k": "v"}, "kmsKeyName": KEY, "tags": {"a/b": "c"}}),
                mask,
            )
            .await;
        assert_eq!(status, 501, "{mask}: {error}");
        assert_eq!(error["error"]["status"], "UNIMPLEMENTED", "{mask}");
        assert_strict_explanation(error["error"]["message"].as_str().unwrap(), field);
        let error = h
            .grpc_update(
                "strict-patch",
                pb::Topic {
                    labels: tag_map(&[("k", "v")]),
                    kms_key_name: KEY.to_owned(),
                    tags: tag_map(&[("a/b", "c")]),
                    ..Default::default()
                },
                paths,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{paths:?}");
        assert_strict_explanation(error.message(), field);
        assert_eq!(h.rest_get("strict-patch").await, before_rest, "{mask}");
        assert_eq!(h.grpc_get("strict-patch").await, before_grpc, "{paths:?}");
    }
    // A labels-only update is unaffected, even when the body carries the fields the mask skips.
    let (status, updated) = h
        .rest_patch(
            "strict-patch",
            json!({"labels": {"owner": "test"}, "kmsKeyName": KEY}),
            "labels",
        )
        .await;
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["labels"], json!({"owner": "test"}));
    assert!(updated.get("kmsKeyName").is_none(), "{updated}");
}

#[tokio::test]
async fn the_profile_is_the_only_difference_for_each_field() {
    let strict = Harness::new(PagingPolicy::Strict).await;
    let emulator = Harness::new(PagingPolicy::Emulator).await;
    for body in [
        json!({"kmsKeyName": KEY}),
        json!({"tags": {"a/b": "c"}}),
        json!({"kmsKeyName": KEY, "tags": {"a/b": "c"}}),
    ] {
        assert_eq!(strict.rest_create("same", body.clone()).await.0, 501);
        assert_eq!(emulator.rest_create("same", body).await.0, 200);
        assert_eq!(emulator.rest_delete("same").await, 200);
    }
}
