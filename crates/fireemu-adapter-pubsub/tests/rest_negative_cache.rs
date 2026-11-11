//! The REST negative cache of production's frontend, behind `with_rest_negative_cache`.
//!
//! PROVISIONAL (`negcache-v1`): the rule these tests pin is the best fit of the recorded
//! production runs, not a verified rule. Tests named `provisional_*` change with the
//! observation recording; the others (off by default, gRPC and topics unaffected, the
//! virtual clock decides) are the contract of the switch.

use std::sync::{Arc, Mutex};

use fireemu_adapter_pubsub::{serve_pubsub, PagingPolicy, PubSubHandle};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::subscriber_client::SubscriberClient;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Clock = Arc<Mutex<VirtualClock>>;

async fn start(cache: bool) -> (std::net::SocketAddr, Clock) {
    let clock: Clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_700_000_000),
    )));
    let state = Arc::new(Mutex::new(PubSubState::new(99)));
    let handle = PubSubHandle::new(state, clock.clone(), None)
        .with_paging_policy(PagingPolicy::Strict)
        .with_rest_negative_cache(cache);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_pubsub(listener, handle).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (address, clock)
}

fn advance(clock: &Clock, millis: i64) {
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_millis(millis))
        .unwrap();
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

const SUB: &str = "/v1/projects/demo-app/subscriptions/sub1";
const SNAP: &str = "/v1/projects/demo-app/snapshots/snap1";
const TOPIC: &str = "/v1/projects/demo-app/topics/topic1";

async fn topic(address: std::net::SocketAddr) {
    let (status, body) = rest_request(address, "PUT", TOPIC, json!({})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(status, 200);
}

async fn create_subscription(address: std::net::SocketAddr, body: Value) -> u16 {
    rest_request(address, "PUT", SUB, body).await.0
}

fn plain() -> Value {
    json!({"topic": "projects/demo-app/topics/topic1"})
}

fn missing(leaf: &str) -> Value {
    json!({"error": {"code": 404, "message": format!("Resource not found (resource={leaf})."), "status": "NOT_FOUND"}})
}

#[tokio::test]
async fn off_by_default_a_resource_is_visible_right_after_it_is_created() {
    let (address, _clock) = start(false).await;
    topic(address).await;
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 404);
    assert_eq!(create_subscription(address, plain()).await, 200);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 200);
}

#[tokio::test]
async fn provisional_a_404_is_repeated_after_the_create_until_the_window_ends() {
    let (address, clock) = start(true).await;
    topic(address).await;
    let first = rest_request(address, "GET", SUB, json!({})).await;
    assert_eq!(first, (404, missing("sub1")));
    advance(&clock, 1_000);
    assert_eq!(create_subscription(address, plain()).await, 200);
    advance(&clock, 2_000);
    assert_eq!(
        rest_request(address, "GET", SUB, json!({})).await,
        (404, missing("sub1"))
    );
    // 9.5 s after the first 404 is still inside; the hit did not extend the entry.
    advance(&clock, 6_499);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 404);
    advance(&clock, 101);
    let (status, body) = rest_request(address, "GET", SUB, json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(body["name"], "projects/demo-app/subscriptions/sub1");
}

#[tokio::test]
async fn provisional_a_snapshot_behaves_like_a_subscription() {
    let (address, clock) = start(true).await;
    topic(address).await;
    assert_eq!(create_subscription(address, plain()).await, 200);
    assert_eq!(
        rest_request(address, "GET", SNAP, json!({})).await,
        (404, missing("snap1"))
    );
    let body = json!({"subscription": "projects/demo-app/subscriptions/sub1"});
    assert_eq!(rest_request(address, "PUT", SNAP, body).await.0, 200);
    advance(&clock, 3_000);
    assert_eq!(
        rest_request(address, "GET", SNAP, json!({})).await,
        (404, missing("snap1"))
    );
    advance(&clock, 7_000);
    assert_eq!(rest_request(address, "GET", SNAP, json!({})).await.0, 200);
}

#[tokio::test]
async fn topics_are_never_cached() {
    let (address, clock) = start(true).await;
    assert_eq!(rest_request(address, "GET", TOPIC, json!({})).await.0, 404);
    advance(&clock, 1_000);
    topic(address).await;
    advance(&clock, 1_000);
    assert_eq!(rest_request(address, "GET", TOPIC, json!({})).await.0, 200);
}

#[tokio::test]
async fn grpc_is_never_cached() {
    let (address, _clock) = start(true).await;
    topic(address).await;
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 404);
    assert_eq!(create_subscription(address, plain()).await, 200);
    let mut client = SubscriberClient::new(grpc_channel(address).await);
    let found = client
        .get_subscription(pb::GetSubscriptionRequest {
            subscription: "projects/demo-app/subscriptions/sub1".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(found.name, "projects/demo-app/subscriptions/sub1");
}

#[tokio::test]
async fn provisional_only_a_get_is_answered_from_the_cache() {
    let (address, _clock) = start(true).await;
    topic(address).await;
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 404);
    assert_eq!(create_subscription(address, plain()).await, 200);
    // A delete still reaches the backend and removes the subscription.
    assert_eq!(rest_request(address, "DELETE", SUB, json!({})).await.0, 200);
    assert_eq!(create_subscription(address, plain()).await, 200);
}

#[tokio::test]
async fn provisional_a_failed_create_arms_the_url_resource() {
    let (address, clock) = start(true).await;
    // The topic does not exist yet: the create answers 404.
    assert_eq!(create_subscription(address, plain()).await, 404);
    advance(&clock, 500);
    topic(address).await;
    assert_eq!(create_subscription(address, plain()).await, 200);
    advance(&clock, 2_000);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 404);
    advance(&clock, 8_000);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 200);
}

#[tokio::test]
async fn provisional_a_recent_200_keeps_a_later_404_from_arming() {
    let (address, clock) = start(true).await;
    topic(address).await;
    assert_eq!(create_subscription(address, plain()).await, 200);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 200);
    advance(&clock, 1_000);
    assert_eq!(rest_request(address, "DELETE", SUB, json!({})).await.0, 200);
    advance(&clock, 1_000);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 404);
    advance(&clock, 1_000);
    assert_eq!(create_subscription(address, plain()).await, 200);
    advance(&clock, 1_000);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 200);
}

#[tokio::test]
async fn provisional_a_create_naming_a_resource_in_its_body_clears_that_resource() {
    let (address, clock) = start(true).await;
    topic(address).await;
    let named = "/v1/projects/demo-app/subscriptions/named";
    assert_eq!(rest_request(address, "GET", named, json!({})).await.0, 404);
    advance(&clock, 1_000);
    let body = json!({"topic": "projects/demo-app/topics/topic1", "name": "projects/demo-app/subscriptions/named"});
    assert_eq!(rest_request(address, "PUT", named, body).await.0, 200);
    advance(&clock, 1_000);
    assert_eq!(rest_request(address, "GET", named, json!({})).await.0, 200);
}

#[tokio::test]
async fn the_query_string_is_not_part_of_the_key() {
    let (address, clock) = start(true).await;
    topic(address).await;
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 404);
    assert_eq!(create_subscription(address, plain()).await, 200);
    advance(&clock, 1_000);
    let with_query = format!("{SUB}?alt=json");
    assert_eq!(
        rest_request(address, "GET", &with_query, json!({})).await.0,
        404
    );
}

#[tokio::test]
async fn a_verb_url_is_not_read_as_the_plain_resource() {
    let (address, clock) = start(true).await;
    topic(address).await;
    // A pull of a subscription that does not exist is a 404 but is not a GET of the resource.
    let pull = format!("{SUB}:pull");
    assert_eq!(
        rest_request(address, "POST", &pull, json!({"maxMessages": 1}))
            .await
            .0,
        404
    );
    assert_eq!(create_subscription(address, plain()).await, 200);
    advance(&clock, 1_000);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 200);
}

#[tokio::test]
async fn a_create_that_failed_without_a_404_does_not_arm() {
    let (address, clock) = start(true).await;
    topic(address).await;
    assert_eq!(create_subscription(address, plain()).await, 200);
    // The duplicate create answers 409 and the invalid one 400; neither is a missing resource.
    assert_eq!(create_subscription(address, plain()).await, 409);
    assert_eq!(
        create_subscription(address, json!({"topic": "not a topic name"})).await,
        400
    );
    advance(&clock, 1_000);
    assert_eq!(rest_request(address, "GET", SUB, json!({})).await.0, 200);
}

#[tokio::test]
async fn the_handle_reports_whether_the_cache_is_on() {
    let state = Arc::new(Mutex::new(PubSubState::new(99)));
    let clock: Clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(0),
    )));
    let handle = PubSubHandle::new(state, clock, None);
    assert!(!handle.rest_negative_cache_enabled());
    let handle = handle.with_rest_negative_cache(true);
    assert!(handle.rest_negative_cache_enabled());
    assert!(!handle
        .with_rest_negative_cache(false)
        .rest_negative_cache_enabled());
}
