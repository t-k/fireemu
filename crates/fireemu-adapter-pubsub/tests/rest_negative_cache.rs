//! The REST negative cache of production's frontend, behind `with_rest_negative_cache`.
//!
//! The rule these tests pin is the one two production recordings settle (`rule.md` of the packet
//! `PUBSUB-NEGCACHE`): the entry belongs to a connection; a 404 of GET or PATCH of a plain
//! subscription URL arms it; GET, PATCH and DELETE of that URL are answered from it for the window;
//! nothing else arms and a create clears nothing. The choices the recordings leave open are the
//! tests named `unrecorded_*`.

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

/// One keep-alive HTTP/1.1 connection: the negative cache belongs to the connection, so the
/// requests of one cell must share it.
struct Conn {
    address: std::net::SocketAddr,
    stream: tokio::net::TcpStream,
}

impl Conn {
    async fn open(address: std::net::SocketAddr) -> Self {
        Self {
            address,
            stream: tokio::net::TcpStream::connect(address).await.unwrap(),
        }
    }

    async fn request(&mut self, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (status, bytes) = self
            .raw(method, path, &serde_json::to_vec(&body).unwrap())
            .await;
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn status(&mut self, method: &str, path: &str, body: Value) -> u16 {
        self.request(method, path, body).await.0
    }

    async fn raw(&mut self, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            self.address,
            body.len()
        );
        self.stream.write_all(request.as_bytes()).await.unwrap();
        self.stream.write_all(body).await.unwrap();
        let mut response = Vec::new();
        let mut chunk = [0_u8; 4096];
        let (headers_end, length) = loop {
            let read = self.stream.read(&mut chunk).await.unwrap();
            assert!(
                read > 0,
                "the connection closed: {:?}",
                String::from_utf8_lossy(&response)
            );
            response.extend_from_slice(&chunk[..read]);
            if let Some(end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&response[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap_or_else(|| panic!("no content-length: {head}"))
                    .trim()
                    .parse::<usize>()
                    .unwrap();
                break (end + 4, length);
            }
        };
        while response.len() < headers_end + length {
            let read = self.stream.read(&mut chunk).await.unwrap();
            assert!(read > 0);
            response.extend_from_slice(&chunk[..read]);
        }
        let status = std::str::from_utf8(&response[..headers_end])
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (status, response[headers_end..headers_end + length].to_vec())
    }
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
const WINDOW_MS: i64 = 10_350;

async fn topic(conn: &mut Conn) {
    let (status, body) = conn.request("PUT", TOPIC, json!({})).await;
    assert_eq!(status, 200, "{body}");
}

fn plain() -> Value {
    json!({"topic": "projects/demo-app/topics/topic1"})
}

fn missing(leaf: &str) -> Value {
    json!({"error": {"code": 404, "message": format!("Resource not found (resource={leaf})."), "status": "NOT_FOUND"}})
}

fn patch() -> Value {
    json!({"subscription": {"ackDeadlineSeconds": 20}, "updateMask": "ackDeadlineSeconds"})
}

#[tokio::test]
async fn off_by_default_a_resource_is_visible_right_after_it_is_created() {
    let (address, _clock) = start(false).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(conn.status("GET", SUB, json!({})).await, 404);
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 200);
}

#[tokio::test]
async fn a_404_is_repeated_after_the_create_on_the_same_connection_until_the_window_ends() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(
        conn.request("GET", SUB, json!({})).await,
        (404, missing("sub1"))
    );
    advance(&clock, 1_000);
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 2_000);
    assert_eq!(
        conn.request("GET", SUB, json!({})).await,
        (404, missing("sub1"))
    );
    // Just inside the window, measured from the first 404; the hit did not extend the entry.
    advance(&clock, WINDOW_MS - 3_000 - 1);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 404);
    advance(&clock, 1);
    let (status, body) = conn.request("GET", SUB, json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(body["name"], "projects/demo-app/subscriptions/sub1");
}

#[tokio::test]
async fn another_connection_is_never_answered_from_the_entry() {
    let (address, clock) = start(true).await;
    let mut first = Conn::open(address).await;
    topic(&mut first).await;
    assert_eq!(first.status("GET", SUB, json!({})).await, 404);
    assert_eq!(first.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 1_000);
    let mut second = Conn::open(address).await;
    assert_eq!(second.status("GET", SUB, json!({})).await, 200);
    // The first connection still sees its entry, and a fresh connection per request never does.
    assert_eq!(first.status("GET", SUB, json!({})).await, 404);
    for _ in 0..3 {
        let mut fresh = Conn::open(address).await;
        assert_eq!(fresh.status("GET", SUB, json!({})).await, 200);
    }
}

#[tokio::test]
async fn each_connection_arms_its_own_entry() {
    let (address, clock) = start(true).await;
    let mut first = Conn::open(address).await;
    let mut second = Conn::open(address).await;
    topic(&mut first).await;
    assert_eq!(first.status("GET", SUB, json!({})).await, 404);
    advance(&clock, 2_000);
    assert_eq!(second.status("GET", SUB, json!({})).await, 404);
    assert_eq!(first.status("PUT", SUB, plain()).await, 200);
    advance(&clock, WINDOW_MS - 2_000);
    // The first entry has ended; the second, armed 2 s later, has not.
    assert_eq!(first.status("GET", SUB, json!({})).await, 200);
    assert_eq!(second.status("GET", SUB, json!({})).await, 404);
}

#[tokio::test]
async fn a_patch_404_arms_and_patch_and_delete_are_answered_from_the_entry_without_running() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(
        conn.request("PATCH", SUB, patch()).await,
        (404, missing("sub1"))
    );
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 1_000);
    // The patch and the delete are answered 404 and neither ran: the subscription is unchanged and
    // still there (a connection that did not arm sees it).
    assert_eq!(
        conn.request("PATCH", SUB, patch()).await,
        (404, missing("sub1"))
    );
    assert_eq!(
        conn.request("DELETE", SUB, json!({})).await,
        (404, missing("sub1"))
    );
    let mut other = Conn::open(address).await;
    let (status, body) = other.request("GET", SUB, json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(body["ackDeadlineSeconds"], 10);
}

#[tokio::test]
async fn a_delete_404_does_not_arm() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(conn.status("DELETE", SUB, json!({})).await, 404);
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 200);
}

#[tokio::test]
async fn a_snapshot_is_never_cached() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    assert_eq!(
        conn.request("GET", SNAP, json!({})).await,
        (404, missing("snap1"))
    );
    let body = json!({"subscription": "projects/demo-app/subscriptions/sub1"});
    assert_eq!(conn.status("PUT", SNAP, body).await, 200);
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", SNAP, json!({})).await, 200);
}

#[tokio::test]
async fn topics_are_never_cached() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    assert_eq!(conn.status("GET", TOPIC, json!({})).await, 404);
    advance(&clock, 1_000);
    topic(&mut conn).await;
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", TOPIC, json!({})).await, 200);
}

#[tokio::test]
async fn grpc_is_never_cached() {
    let (address, _clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(conn.status("GET", SUB, json!({})).await, 404);
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
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
async fn a_verb_reaches_the_backend_while_the_entry_is_armed() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(conn.status("GET", SUB, json!({})).await, 404);
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 1_000);
    let pull = format!("{SUB}:pull");
    let iam = format!("{SUB}:getIamPolicy");
    assert_eq!(
        conn.status(
            "POST",
            &pull,
            json!({"maxMessages": 1, "returnImmediately": true})
        )
        .await,
        200
    );
    assert_eq!(conn.status("GET", &iam, json!({})).await, 200);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 404);
}

#[tokio::test]
async fn a_404_of_a_verb_does_not_arm() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    // A pull of a subscription that does not exist is a 404 but is not a GET of the resource.
    let pull = format!("{SUB}:pull");
    assert_eq!(
        conn.status("POST", &pull, json!({"maxMessages": 1})).await,
        404
    );
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 200);
}

#[tokio::test]
async fn a_failed_create_does_not_arm() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    // The topic does not exist yet: the create answers 404, and it does not arm.
    assert_eq!(conn.status("PUT", SUB, plain()).await, 404);
    advance(&clock, 500);
    topic(&mut conn).await;
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 2_000);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 200);
    // A duplicate create (409) and an invalid one (400) do not arm either.
    assert_eq!(conn.status("PUT", SUB, plain()).await, 409);
    assert_eq!(
        conn.status("PUT", SUB, json!({"topic": "not a topic name"}))
            .await,
        400
    );
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 200);
}

#[tokio::test]
async fn a_request_with_a_query_string_is_neither_served_nor_arming() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    let with_query = format!("{SUB}?alt=json");
    assert_eq!(conn.status("GET", &with_query, json!({})).await, 404);
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 200);
    // An armed plain entry is not served to a query-string request.
    let mut second = Conn::open(address).await;
    assert_eq!(second.status("DELETE", SUB, json!({})).await, 200);
    assert_eq!(second.status("GET", SUB, json!({})).await, 404);
    assert_eq!(second.status("PUT", SUB, plain()).await, 200);
    assert_eq!(second.status("GET", &with_query, json!({})).await, 200);
    assert_eq!(second.status("GET", SUB, json!({})).await, 404);
}

#[tokio::test]
async fn a_create_whose_body_names_the_url_resource_does_not_clear_the_entry() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(conn.status("GET", SUB, json!({})).await, 404);
    advance(&clock, 1_000);
    let body = json!({"topic": "projects/demo-app/topics/topic1", "name": "projects/demo-app/subscriptions/sub1"});
    assert_eq!(conn.status("PUT", SUB, body).await, 200);
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 404);
}

#[tokio::test]
async fn unrecorded_a_recent_200_keeps_a_later_404_from_arming() {
    let (address, clock) = start(true).await;
    let mut conn = Conn::open(address).await;
    topic(&mut conn).await;
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 200);
    advance(&clock, 1_000);
    assert_eq!(conn.status("DELETE", SUB, json!({})).await, 200);
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 404);
    advance(&clock, 1_000);
    assert_eq!(conn.status("PUT", SUB, plain()).await, 200);
    advance(&clock, 1_000);
    assert_eq!(conn.status("GET", SUB, json!({})).await, 200);
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
