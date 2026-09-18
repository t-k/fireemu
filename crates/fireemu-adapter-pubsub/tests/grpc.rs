//! End-to-end tests over the real gRPC surface: a tonic client drives create / publish / pull /
//! ack / filter / redelivery against a served adapter on a loopback port.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use fireemu_adapter_pubsub::{
    serve_pubsub, BridgeMessage, PubSubHandle, TopicDelivery, TopicDeliveryError,
    TopicDeliveryReservation,
};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
use pb::subscriber_client::SubscriberClient;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_stream::StreamExt as _;

struct Harness {
    endpoint: String,
    clock: Arc<Mutex<VirtualClock>>,
    state: Arc<Mutex<PubSubState>>,
    handle: PubSubHandle,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl Harness {
    async fn channel(&self) -> tonic::transport::Channel {
        tonic::transport::Channel::from_shared(self.endpoint.clone())
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    async fn publisher(&self) -> PublisherClient<tonic::transport::Channel> {
        PublisherClient::new(self.channel().await)
    }

    async fn subscriber(&self) -> SubscriberClient<tonic::transport::Channel> {
        SubscriberClient::new(self.channel().await)
    }

    async fn shutdown(mut self) {
        self.handle.shutdown_push_dispatcher().await;
        if let Some(server) = self.server.take() {
            server.abort();
            let _ = server.await;
        }
    }

    async fn abort_server(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
            let _ = server.await;
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.handle.cancel_push_dispatcher();
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

async fn start() -> Harness {
    start_with_bridge(None).await
}

async fn start_with_bridge(bridge: Option<Arc<dyn TopicDelivery>>) -> Harness {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_700_000_000),
    )));
    let state = Arc::new(Mutex::new(PubSubState::new(42)));
    let handle = PubSubHandle::new(state.clone(), clock.clone(), bridge);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = handle.clone();
    let server = tokio::spawn(async move {
        let _ = serve_pubsub(listener, server_handle).await;
    });
    // Give the server a moment to accept.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Harness {
        endpoint: format!("http://{addr}"),
        clock,
        state,
        handle,
        server: Some(server),
    }
}

#[derive(Default)]
struct RecordingTopicDelivery(Arc<Mutex<Vec<String>>>);

impl TopicDelivery for RecordingTopicDelivery {
    fn reserve(
        &self,
        topic: &str,
        _messages: &[BridgeMessage],
    ) -> Result<Box<dyn TopicDeliveryReservation>, TopicDeliveryError> {
        Ok(Box::new(RecordingReservation {
            topics: self.0.clone(),
            topic: topic.to_owned(),
        }))
    }
}

struct RecordingReservation {
    topics: Arc<Mutex<Vec<String>>>,
    topic: String,
}

struct RejectingTopicDelivery;

impl TopicDelivery for RejectingTopicDelivery {
    fn reserve(
        &self,
        _topic: &str,
        _messages: &[BridgeMessage],
    ) -> Result<Box<dyn TopicDeliveryReservation>, TopicDeliveryError> {
        Err(TopicDeliveryError::Capacity)
    }
}

struct ToggleTopicDelivery {
    destination: String,
    accept_destination: Arc<AtomicBool>,
    committed: Arc<Mutex<Vec<String>>>,
    recovery_notify: Arc<tokio::sync::Notify>,
}

impl TopicDelivery for ToggleTopicDelivery {
    fn reserve(
        &self,
        topic: &str,
        _messages: &[BridgeMessage],
    ) -> Result<Box<dyn TopicDeliveryReservation>, TopicDeliveryError> {
        if topic == self.destination && !self.accept_destination.load(Ordering::Acquire) {
            return Err(TopicDeliveryError::Capacity);
        }
        Ok(Box::new(RecordingReservation {
            topics: self.committed.clone(),
            topic: topic.to_owned(),
        }))
    }

    fn recovery_notify(&self) -> Option<Arc<tokio::sync::Notify>> {
        Some(self.recovery_notify.clone())
    }
}

impl TopicDeliveryReservation for RecordingReservation {
    fn commit(self: Box<Self>) {
        self.topics.lock().unwrap().push(self.topic.clone());
    }
}

#[tokio::test]
async fn functions_bridge_receives_the_full_source_topic_resource() {
    let delivery = Arc::new(RecordingTopicDelivery::default());
    let harness = start_with_bridge(Some(delivery.clone())).await;
    let mut publisher = harness.publisher().await;
    publisher
        .create_topic(pb::Topic {
            name: "projects/other-project/topics/jobs".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    publisher
        .publish(pb::PublishRequest {
            topic: "projects/other-project/topics/jobs".to_owned(),
            messages: vec![msg(b"scope sentinel")],
        })
        .await
        .unwrap();

    assert_eq!(
        *delivery.0.lock().unwrap(),
        vec!["projects/other-project/topics/jobs"]
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn topic_options_are_rejected_before_create_or_update_mutation() {
    let harness = start().await;
    let mut publisher = harness.publisher().await;
    let rejected = "projects/demo-app/topics/rejected-options";
    let error = publisher
        .create_topic(pb::Topic {
            name: rejected.to_owned(),
            schema_settings: Some(pb::SchemaSettings::default()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unimplemented);
    assert!(error.message().contains("schema_settings"));
    let missing = publisher
        .get_topic(pb::GetTopicRequest {
            topic: rejected.to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), tonic::Code::NotFound);

    let topic = "projects/demo-app/topics/supported-options";
    publisher
        .create_topic(pb::Topic {
            name: topic.to_owned(),
            labels: [(String::from("env"), String::from("test"))]
                .into_iter()
                .collect(),
            ..Default::default()
        })
        .await
        .unwrap();
    let error = publisher
        .update_topic(pb::UpdateTopicRequest {
            topic: Some(pb::Topic {
                name: topic.to_owned(),
                kms_key_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k".to_owned(),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["kms_key_name".to_owned()],
            }),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::Unimplemented);
    assert!(error.message().contains("kms_key_name"));
    let current = publisher
        .get_topic(pb::GetTopicRequest {
            topic: topic.to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(current.labels.get("env"), Some(&String::from("test")));
    harness.shutdown().await;
}

#[tokio::test]
async fn bridge_capacity_refusal_does_not_publish_to_the_broker() {
    let harness = start_with_bridge(Some(Arc::new(RejectingTopicDelivery))).await;
    let mut publisher = harness.publisher().await;
    let mut subscriber = harness.subscriber().await;
    let topic = "projects/demo-app/topics/atomic-refusal";
    let subscription = "projects/demo-app/subscriptions/atomic-refusal";
    publisher
        .create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    subscriber
        .create_subscription(pb::Subscription {
            name: subscription.to_owned(),
            topic: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();

    let error = publisher
        .publish(pb::PublishRequest {
            topic: topic.to_owned(),
            messages: vec![msg(b"must not be visible")],
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::ResourceExhausted);

    let pulled = subscriber
        .pull(pb::PullRequest {
            subscription: subscription.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(pulled.is_empty());
    harness.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the admission failure and retry lifecycle in one scenario.
async fn dead_letter_transfer_retries_after_destination_admission_recovers() {
    let destination = "projects/demo-app/topics/retry-dead".to_owned();
    let accept_destination = Arc::new(AtomicBool::new(false));
    let committed = Arc::new(Mutex::new(Vec::new()));
    let recovery_notify = Arc::new(tokio::sync::Notify::new());
    let delivery = Arc::new(ToggleTopicDelivery {
        destination: destination.clone(),
        accept_destination: accept_destination.clone(),
        committed: committed.clone(),
        recovery_notify: recovery_notify.clone(),
    });
    let harness = start_with_bridge(Some(delivery)).await;
    let mut publisher = harness.publisher().await;
    let mut subscriber = harness.subscriber().await;
    let source_topic = "projects/demo-app/topics/retry-source";
    let source_subscription = "projects/demo-app/subscriptions/retry-source";
    let destination_subscription = "projects/demo-app/subscriptions/retry-dead";

    for topic in [source_topic, destination.as_str()] {
        publisher
            .create_topic(pb::Topic {
                name: topic.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    subscriber
        .create_subscription(pb::Subscription {
            name: source_subscription.to_owned(),
            topic: source_topic.to_owned(),
            dead_letter_policy: Some(pb::DeadLetterPolicy {
                dead_letter_topic: destination.clone(),
                max_delivery_attempts: 5,
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    subscriber
        .create_subscription(pb::Subscription {
            name: destination_subscription.to_owned(),
            topic: destination.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    publisher
        .publish(pb::PublishRequest {
            topic: source_topic.to_owned(),
            messages: vec![msg(b"retry me")],
        })
        .await
        .unwrap();

    for _ in 0..5 {
        let received = subscriber
            .pull(pb::PullRequest {
                subscription: source_subscription.to_owned(),
                max_messages: 1,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .received_messages;
        assert_eq!(received.len(), 1);
        subscriber
            .modify_ack_deadline(pb::ModifyAckDeadlineRequest {
                subscription: source_subscription.to_owned(),
                ack_ids: vec![received[0].ack_id.clone()],
                ack_deadline_seconds: 0,
            })
            .await
            .unwrap();
    }

    let exhausted = subscriber
        .pull(pb::PullRequest {
            subscription: source_subscription.to_owned(),
            max_messages: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(exhausted.is_empty());
    assert!(subscriber
        .pull(pb::PullRequest {
            subscription: destination_subscription.to_owned(),
            max_messages: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages
        .is_empty());
    assert_eq!(
        committed.lock().unwrap().clone(),
        vec![source_topic.to_owned()]
    );

    accept_destination.store(true, Ordering::Release);
    recovery_notify.notify_waiters();

    let forwarded = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let received = subscriber
                .pull(pb::PullRequest {
                    subscription: destination_subscription.to_owned(),
                    max_messages: 1,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .received_messages;
            if !received.is_empty() {
                break received;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("capacity recovery must retry without another Pub/Sub mutation");
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].message.as_ref().unwrap().data, b"retry me");
    assert_eq!(
        committed.lock().unwrap().clone(),
        vec![source_topic.to_owned(), destination.clone()]
    );
    assert!(subscriber
        .pull(pb::PullRequest {
            subscription: source_subscription.to_owned(),
            max_messages: 1,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages
        .is_empty());
    harness.shutdown().await;
}

fn msg(data: &[u8]) -> pb::PubsubMessage {
    pb::PubsubMessage {
        data: data.to_vec(),
        ..Default::default()
    }
}

type PushSink = (
    String,
    Arc<Mutex<Vec<Vec<u8>>>>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
);

type BarrierPushSink = (
    String,
    Arc<Mutex<Vec<Vec<u8>>>>,
    tokio::sync::oneshot::Receiver<()>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
);

/// The interval a test opts into when it exercises the push redelivery protection. It is not the
/// default: without a retry policy the default is immediate redelivery, as production does. It is
/// deliberately longer than the push backoff of the first few failures, so a test that asserts
/// "exactly this interval" is asserting the larger of the two waits.
fn configured_push_redelivery_interval() -> LogicalDuration {
    LogicalDuration::from_seconds(5)
}

/// Opts the subscription registry into a minimum push redelivery interval, exactly as the daemon
/// does from `pubsub.pushMinimumRedeliveryIntervalMillis`.
fn configure_push_redelivery_interval(h: &Harness, interval: LogicalDuration) {
    h.state
        .lock()
        .unwrap()
        .set_push_minimum_redelivery_interval(interval);
}

/// The subscription-level push backoff owed after `consecutive_failures` failed push attempts in
/// a row, spelled out here rather than read from the implementation so a test pins the curve.
/// Production documents the 100 ms and 60 s bounds but not the curve between them.
fn push_backoff_after(consecutive_failures: u32) -> LogicalDuration {
    let doublings = consecutive_failures.saturating_sub(1).min(20);
    LogicalDuration::from_millis((100_i64 << doublings).min(60_000))
}

/// The longest push backoff, which releases a held subscription whatever its failure streak.
fn maximum_push_backoff() -> LogicalDuration {
    LogicalDuration::from_millis(60_000)
}

/// Advances the clock past the whole push backoff, which is what releases the next push attempt
/// on a subscription whose endpoint keeps failing.
fn release_push_backoff(h: &Harness) {
    advance(h, maximum_push_backoff());
}

/// Waits until the subscription's push backoff is recorded for `expected`, which is the point at
/// which the failed attempt is fully accounted for and nothing is in flight any more.
async fn await_push_backoff(h: &Harness, subscription: &str, expected: LogicalInstant) {
    let name = fireemu_core_pubsub::SubscriptionName::parse(subscription).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while h.handle.push_backoff_resume_at(&name) != Some(expected) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("the push backoff of {subscription} must hold delivery until {expected}")
    });
}

/// Waits for `count` recorded push requests, releasing the subscription's push backoff between
/// attempts. A failing endpoint throttles its subscription, so a test that wants the next attempt
/// has to let the virtual clock reach it.
async fn await_push_count_releasing_backoff(
    h: &Harness,
    bodies: &Arc<Mutex<Vec<Vec<u8>>>>,
    count: usize,
) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while bodies.lock().unwrap().len() < count {
            release_push_backoff(h);
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("push request {count} must be sent"));
}

/// Advances the shared virtual clock and wakes the push dispatcher, exactly as the control API
/// does.
fn advance(h: &Harness, duration: LogicalDuration) {
    h.clock.lock().unwrap().advance(duration).unwrap();
    h.handle.on_clock_changed();
}

/// Waits until the subscription's next redelivery is scheduled for `expected`, which is also the
/// point at which the failed attempt has been nacked and nothing is in flight any more.
async fn await_scheduled_redelivery(h: &Harness, subscription: &str, expected: LogicalInstant) {
    let name = fireemu_core_pubsub::SubscriptionName::parse(subscription).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let scheduled = h.state.lock().unwrap().next_delivery_at(&name).unwrap();
            if scheduled == Some(expected) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("the redelivery of {subscription} must be scheduled for {expected}")
    });
}

/// Waits until the sink has recorded `count` requests.
async fn await_push_count(bodies: &Arc<Mutex<Vec<Vec<u8>>>>, count: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while bodies.lock().unwrap().len() < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("push request {count} must be sent"));
}

/// Asserts the sink stays at `count` requests: a redelivery that is still waiting for the virtual
/// clock must not be sent by wall-clock time passing.
async fn assert_push_count_stays(bodies: &Arc<Mutex<Vec<Vec<u8>>>>, count: usize) {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        bodies.lock().unwrap().len(),
        count,
        "no push request may be sent before the virtual clock reaches the redelivery instant"
    );
}

fn push_sink(status: u16) -> PushSink {
    push_sink_sequence(vec![status])
}

fn push_sink_sequence(statuses: Vec<u16>) -> PushSink {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let received = bodies.clone();
    let statuses = Arc::new(Mutex::new(VecDeque::from(statuses)));
    let response_statuses = statuses.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let should_stop = stop.clone();
    let worker = thread::spawn(move || {
        while !should_stop.load(Ordering::Acquire) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(std::time::Duration::from_millis(2));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let body_start = loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break None;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break Some(index + 4);
                }
            };
            let Some(body_start) = body_start else {
                continue;
            };
            let content_length = request
                .windows(b"content-length:".len())
                .position(|window| window.eq_ignore_ascii_case(b"content-length:"))
                .and_then(|index| {
                    let line = request[index..].split(|byte| *byte == b'\n').next()?;
                    std::str::from_utf8(line)
                        .ok()?
                        .split(':')
                        .nth(1)?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .unwrap_or_default();
            while request.len() < body_start.saturating_add(content_length) {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            if request.len() >= body_start.saturating_add(content_length) {
                received
                    .lock()
                    .unwrap()
                    .push(request[body_start..body_start + content_length].to_vec());
            }
            let status = response_statuses.lock().unwrap().pop_front().unwrap_or(204);
            let response =
                format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{address}/push"), bodies, stop, worker)
}

fn barrier_push_sink() -> BarrierPushSink {
    barrier_push_sink_with_status(204)
}

fn barrier_push_sink_with_status(status: u16) -> BarrierPushSink {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let received = bodies.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let should_stop = stop.clone();
    let release = Arc::new(AtomicBool::new(false));
    let can_release = release.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let worker = thread::spawn(move || {
        let mut first = true;
        let mut started_tx = Some(started_tx);
        while !should_stop.load(Ordering::Acquire) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(std::time::Duration::from_millis(2));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let body_start = loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break None;
                }
                request.extend_from_slice(&buffer[..read]);
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break Some(index + 4);
                }
            };
            let Some(body_start) = body_start else {
                continue;
            };
            let content_length = request
                .windows(b"content-length:".len())
                .position(|window| window.eq_ignore_ascii_case(b"content-length:"))
                .and_then(|index| {
                    let line = request[index..].split(|byte| *byte == b'\n').next()?;
                    std::str::from_utf8(line)
                        .ok()?
                        .split(':')
                        .nth(1)?
                        .trim()
                        .parse::<usize>()
                        .ok()
                })
                .unwrap_or_default();
            while request.len() < body_start.saturating_add(content_length) {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            if request.len() < body_start.saturating_add(content_length) {
                continue;
            }
            received
                .lock()
                .unwrap()
                .push(request[body_start..body_start + content_length].to_vec());
            if first {
                first = false;
                if let Some(sender) = started_tx.take() {
                    let _ = sender.send(());
                }
                while !can_release.load(Ordering::Acquire) && !should_stop.load(Ordering::Acquire) {
                    thread::sleep(std::time::Duration::from_millis(2));
                }
            }
            let response =
                format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (
        format!("http://{address}/push"),
        bodies,
        started_rx,
        release,
        stop,
        worker,
    )
}

type GatedPushSink = (
    String,
    Arc<AtomicUsize>,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
);

async fn gated_push_sink(expected: usize) -> GatedPushSink {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let observed = received.clone();
    let (release, released) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..expected {
            let (mut stream, _) = listener.accept().await.unwrap();
            let observed = observed.clone();
            let mut released = released.clone();
            connections.spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                let body_end = loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0, "push request ended before its body");
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|index| index + 4)
                    else {
                        continue;
                    };
                    let content_length = request
                        .windows(b"content-length:".len())
                        .position(|window| window.eq_ignore_ascii_case(b"content-length:"))
                        .and_then(|index| {
                            let line = request[index..].split(|byte| *byte == b'\n').next()?;
                            std::str::from_utf8(line)
                                .ok()?
                                .split(':')
                                .nth(1)?
                                .trim()
                                .parse::<usize>()
                                .ok()
                        })
                        .unwrap_or_default();
                    if request.len() >= header_end.saturating_add(content_length) {
                        break header_end + content_length;
                    }
                };
                assert!(request.len() >= body_end);
                observed.fetch_add(1, Ordering::AcqRel);
                while !*released.borrow() {
                    released.changed().await.unwrap();
                }
                stream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = connections.join_next().await {
            result.unwrap();
        }
    });
    (format!("http://{address}/push"), received, release, worker)
}

#[tokio::test]
async fn publish_pull_ack_round_trip() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    pubc.create_topic(pb::Topic {
        name: "projects/demo-app/topics/orders".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/orders-sub".to_owned(),
        topic: "projects/demo-app/topics/orders".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    let ids = pubc
        .publish(pb::PublishRequest {
            topic: "projects/demo-app/topics/orders".to_owned(),
            messages: vec![msg(b"hello"), msg(b"world")],
        })
        .await
        .unwrap()
        .into_inner()
        .message_ids;
    assert_eq!(ids.len(), 2);

    let pulled = subc
        .pull(pb::PullRequest {
            subscription: "projects/demo-app/subscriptions/orders-sub".to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(pulled.len(), 2);
    let ack_ids: Vec<String> = pulled.iter().map(|m| m.ack_id.clone()).collect();

    subc.acknowledge(pb::AcknowledgeRequest {
        subscription: "projects/demo-app/subscriptions/orders-sub".to_owned(),
        ack_ids,
    })
    .await
    .unwrap();

    // Nothing outstanding after ack.
    let again = subc
        .pull(pb::PullRequest {
            subscription: "projects/demo-app/subscriptions/orders-sub".to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(again.is_empty());
}

#[tokio::test]
async fn creating_subscription_for_missing_topic_is_not_found() {
    let h = start().await;
    let mut subc = h.subscriber().await;
    let err = subc
        .create_subscription(pb::Subscription {
            name: "projects/demo-app/subscriptions/x-sub".to_owned(),
            topic: "projects/demo-app/topics/missing".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // The table covers every unsupported wire-level option.
async fn grpc_rejects_unsupported_subscription_options_before_creation() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let topic = "projects/demo-app/topics/unsupported-options";
    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    let options = vec![
        (
            "bigquery_config",
            pb::Subscription {
                bigquery_config: Some(pb::BigQueryConfig {
                    table: "demo.dataset.table".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "cloud_storage_config",
            pb::Subscription {
                cloud_storage_config: Some(pb::CloudStorageConfig::default()),
                ..Default::default()
            },
        ),
        (
            "bigtable_config",
            pb::Subscription {
                bigtable_config: Some(pb::BigtableConfig::default()),
                ..Default::default()
            },
        ),
        (
            "retain_acked_messages",
            pb::Subscription {
                retain_acked_messages: true,
                ..Default::default()
            },
        ),
        (
            "message_retention_duration",
            pb::Subscription {
                message_retention_duration: Some(prost_types::Duration {
                    seconds: 600,
                    nanos: 0,
                }),
                ..Default::default()
            },
        ),
        (
            "expiration_policy",
            pb::Subscription {
                expiration_policy: Some(pb::ExpirationPolicy {
                    ttl: Some(prost_types::Duration {
                        seconds: 86_400,
                        nanos: 0,
                    }),
                }),
                ..Default::default()
            },
        ),
        (
            "detached",
            pb::Subscription {
                detached: true,
                ..Default::default()
            },
        ),
        (
            "enable_exactly_once_delivery",
            pb::Subscription {
                enable_exactly_once_delivery: true,
                ..Default::default()
            },
        ),
        (
            "message_transforms",
            pb::Subscription {
                message_transforms: vec![pb::MessageTransform::default()],
                ..Default::default()
            },
        ),
        (
            "labels",
            pb::Subscription {
                labels: HashMap::from([(String::from("owner"), String::from("test"))]),
                ..Default::default()
            },
        ),
        (
            "tags",
            pb::Subscription {
                tags: HashMap::from([(String::from("env"), String::from("test"))]),
                ..Default::default()
            },
        ),
        (
            "topic_message_retention_duration",
            pb::Subscription {
                topic_message_retention_duration: Some(prost_types::Duration {
                    seconds: 600,
                    nanos: 0,
                }),
                ..Default::default()
            },
        ),
        (
            "push_config.authentication_method",
            pb::Subscription {
                push_config: Some(pb::PushConfig {
                    push_endpoint: "http://127.0.0.1:1/push".to_owned(),
                    authentication_method: Some(pb::push_config::AuthenticationMethod::OidcToken(
                        pb::push_config::OidcToken {
                            service_account_email: "push@example.com".to_owned(),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "push_config.attributes",
            pb::Subscription {
                push_config: Some(pb::PushConfig {
                    push_endpoint: "http://127.0.0.1:1/push".to_owned(),
                    attributes: HashMap::from([(
                        String::from("x-goog-version"),
                        String::from("v1"),
                    )]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
        (
            "push_config.wrapper",
            pb::Subscription {
                push_config: Some(pb::PushConfig {
                    push_endpoint: "http://127.0.0.1:1/push".to_owned(),
                    wrapper: Some(pb::push_config::Wrapper::NoWrapper(
                        pb::push_config::NoWrapper {
                            write_metadata: true,
                        },
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ),
    ];

    for (index, (field, mut subscription)) in options.into_iter().enumerate() {
        let name = format!("projects/demo-app/subscriptions/unsupported-{index}");
        subscription.name = name.clone();
        subscription.topic = topic.to_owned();
        let error = subc.create_subscription(subscription).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{field}");
        assert!(error.message().contains(field), "{field}: {error}");
        let get_error = subc
            .get_subscription(pb::GetSubscriptionRequest { subscription: name })
            .await
            .unwrap_err();
        assert_eq!(get_error.code(), tonic::Code::NotFound, "{field}");
    }

    h.shutdown().await;
}

#[tokio::test]
async fn modify_push_config_rejects_unsupported_options_without_mutating_the_endpoint() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let topic = "projects/demo-app/topics/modify-unsupported-options";
    let subscription = "projects/demo-app/subscriptions/modify-unsupported-options";
    let endpoint = "http://127.0.0.1:1/push";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint.to_owned(),
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();

    let options = vec![
        (
            "push_config.authentication_method",
            pb::PushConfig {
                push_endpoint: endpoint.to_owned(),
                authentication_method: Some(pb::push_config::AuthenticationMethod::OidcToken(
                    pb::push_config::OidcToken {
                        service_account_email: "push@example.com".to_owned(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        ),
        (
            "push_config.attributes",
            pb::PushConfig {
                push_endpoint: endpoint.to_owned(),
                attributes: HashMap::from([("x-goog-version".to_owned(), "v1".to_owned())]),
                ..Default::default()
            },
        ),
        (
            "push_config.wrapper",
            pb::PushConfig {
                push_endpoint: endpoint.to_owned(),
                wrapper: Some(pb::push_config::Wrapper::NoWrapper(
                    pb::push_config::NoWrapper {
                        write_metadata: true,
                    },
                )),
                ..Default::default()
            },
        ),
    ];
    for (field, push_config) in options {
        let error = subc
            .modify_push_config(pb::ModifyPushConfigRequest {
                subscription: subscription.to_owned(),
                push_config: Some(push_config),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented, "{field}");
        assert!(error.message().contains(field), "{field}: {error}");
        let current = subc
            .get_subscription(pb::GetSubscriptionRequest {
                subscription: subscription.to_owned(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            current.push_config.unwrap().push_endpoint,
            endpoint,
            "{field} must not partially update the endpoint"
        );
    }

    h.shutdown().await;
}

#[tokio::test]
async fn filter_drops_non_matching_messages() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    pubc.create_topic(pb::Topic {
        name: "projects/demo-app/topics/events".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/orders-only".to_owned(),
        topic: "projects/demo-app/topics/events".to_owned(),
        filter: "attributes.type = \"order\"".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    let mut order = msg(b"o");
    order
        .attributes
        .insert("type".to_owned(), "order".to_owned());
    let mut refund = msg(b"r");
    refund
        .attributes
        .insert("type".to_owned(), "refund".to_owned());
    pubc.publish(pb::PublishRequest {
        topic: "projects/demo-app/topics/events".to_owned(),
        messages: vec![order, refund],
    })
    .await
    .unwrap();

    let pulled = subc
        .pull(pb::PullRequest {
            subscription: "projects/demo-app/subscriptions/orders-only".to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].message.as_ref().unwrap().data, b"o");
}

#[tokio::test]
async fn redelivery_after_ack_deadline_on_virtual_clock() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    pubc.create_topic(pb::Topic {
        name: "projects/demo-app/topics/jobs".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/jobs-sub".to_owned(),
        topic: "projects/demo-app/topics/jobs".to_owned(),
        ack_deadline_seconds: 10,
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: "projects/demo-app/topics/jobs".to_owned(),
        messages: vec![msg(b"job")],
    })
    .await
    .unwrap();

    let sub = "projects/demo-app/subscriptions/jobs-sub".to_owned();
    let first = subc
        .pull(pb::PullRequest {
            subscription: sub.clone(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].delivery_attempt, 1);

    // The message is not redelivered without ack until the deadline passes.
    let none = subc
        .pull(pb::PullRequest {
            subscription: sub.clone(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(none.is_empty());

    // Advance the virtual clock past the ack deadline: the message comes back.
    h.clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(11))
        .unwrap();
    let second = subc
        .pull(pb::PullRequest {
            subscription: sub,
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].delivery_attempt, 2);
}

#[tokio::test]
async fn streaming_pull_delivers_and_acks() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    pubc.create_topic(pb::Topic {
        name: "projects/demo-app/topics/stream".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/stream-sub".to_owned(),
        topic: "projects/demo-app/topics/stream".to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: "projects/demo-app/topics/stream".to_owned(),
        messages: vec![msg(b"streamed")],
    })
    .await
    .unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel::<pb::StreamingPullRequest>(4);
    tx.send(pb::StreamingPullRequest {
        subscription: "projects/demo-app/subscriptions/stream-sub".to_owned(),
        stream_ack_deadline_seconds: 10,
        ..Default::default()
    })
    .await
    .unwrap();
    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut responses = subc.streaming_pull(outbound).await.unwrap().into_inner();

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
        .await
        .expect("a streaming response arrives")
        .expect("stream open")
        .expect("ok response");
    assert_eq!(msg.received_messages.len(), 1);
    assert_eq!(
        msg.received_messages[0].message.as_ref().unwrap().data,
        b"streamed"
    );
    // Ack it on the same stream.
    let ack = msg.received_messages[0].ack_id.clone();
    tx.send(pb::StreamingPullRequest {
        ack_ids: vec![ack],
        ..Default::default()
    })
    .await
    .unwrap();
    drop(tx);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn snapshot_lifecycle_replays_backlog_and_post_creation_messages() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    let topic = "projects/demo-app/topics/snapshots";
    let source = "projects/demo-app/subscriptions/snapshot-source";
    let replay = "projects/demo-app/subscriptions/snapshot-replay";
    let snapshot = "projects/demo-app/snapshots/checkpoint";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: source.to_owned(),
        topic: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"acked"), msg(b"backlog")],
    })
    .await
    .unwrap();

    let source_messages = subc
        .pull(pb::PullRequest {
            subscription: source.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert_eq!(source_messages.len(), 2);
    subc.acknowledge(pb::AcknowledgeRequest {
        subscription: source.to_owned(),
        ack_ids: vec![source_messages[0].ack_id.clone()],
    })
    .await
    .unwrap();

    let created = subc
        .create_snapshot(pb::CreateSnapshotRequest {
            name: snapshot.to_owned(),
            subscription: source.to_owned(),
            labels: HashMap::from([(String::from("env"), String::from("test"))]),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(created.name, snapshot);
    assert_eq!(created.topic, topic);
    assert!(created.expire_time.is_some());

    let listed = subc
        .list_snapshots(pb::ListSnapshotsRequest {
            project: "projects/demo-app".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .snapshots;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, snapshot);

    let topic_snapshots = pubc
        .list_topic_snapshots(pb::ListTopicSnapshotsRequest {
            topic: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .snapshots;
    assert_eq!(topic_snapshots, vec![snapshot]);

    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"future")],
    })
    .await
    .unwrap();
    subc.delete_subscription(pb::DeleteSubscriptionRequest {
        subscription: source.to_owned(),
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: replay.to_owned(),
        topic: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();

    subc.seek(pb::SeekRequest {
        subscription: replay.to_owned(),
        target: Some(pb::seek_request::Target::Snapshot(snapshot.to_owned())),
    })
    .await
    .unwrap();
    let replayed = subc
        .pull(pb::PullRequest {
            subscription: replay.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    let bodies: Vec<Vec<u8>> = replayed
        .iter()
        .map(|message| message.message.as_ref().unwrap().data.clone())
        .collect();
    assert_eq!(bodies, vec![b"backlog".to_vec(), b"future".to_vec()]);

    let updated = subc
        .update_snapshot(pb::UpdateSnapshotRequest {
            snapshot: Some(pb::Snapshot {
                name: snapshot.to_owned(),
                labels: HashMap::from([(String::from("env"), String::from("prod"))]),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec![String::from("labels")],
            }),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.labels.get("env"), Some(&String::from("prod")));

    subc.delete_snapshot(pb::DeleteSnapshotRequest {
        snapshot: snapshot.to_owned(),
    })
    .await
    .unwrap();
    let err = subc
        .get_snapshot(pb::GetSnapshotRequest {
            snapshot: snapshot.to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn list_topic_snapshots_rejects_a_deleted_topic() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let topic = "projects/demo-app/topics/deleted-snapshot-topic";
    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.delete_topic(pb::DeleteTopicRequest {
        topic: topic.to_owned(),
    })
    .await
    .unwrap();

    let status = pubc
        .list_topic_snapshots(pb::ListTopicSnapshotsRequest {
            topic: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    h.shutdown().await;
}

#[tokio::test]
async fn push_subscription_delivers_json_and_acknowledges_the_message() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink(204);
    let topic = "projects/demo-app/topics/push";
    let subscription = "projects/demo-app/subscriptions/push";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"push-me")],
    })
    .await
    .unwrap();

    for _ in 0..100 {
        if !bodies.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let pushed = bodies.lock().unwrap().clone();
    assert_eq!(pushed.len(), 1);
    let body = String::from_utf8(pushed[0].clone()).unwrap();
    assert!(body.contains("\"data\":\"cHVzaC1tZQ==\""));
    assert!(body.contains(subscription));

    let pulled = subc
        .pull(pb::PullRequest {
            subscription: subscription.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(pulled.is_empty());
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn push_subscription_retries_after_failures_without_a_new_publish() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![500, 500, 500, 204]);
    let topic = "projects/demo-app/topics/push-retry";
    let subscription = "projects/demo-app/subscriptions/push-retry";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"retry-me")],
    })
    .await
    .unwrap();

    // The retry policy is immediate, but push delivery carries its own subscription-level backoff:
    // each failed attempt holds the subscription until the virtual clock reaches its wait.
    await_push_count_releasing_backoff(&h, &bodies, 4).await;
    assert_eq!(bodies.lock().unwrap().len(), 4);
    let pulled = subc
        .pull(pb::PullRequest {
            subscription: subscription.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(pulled.is_empty());
    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

/// Without a retry policy, and only when `pubsub.pushMinimumRedeliveryIntervalMillis` opts the
/// protection in, the emulator keeps a minimum interval between two push attempts of the same
/// message: the endpoint is re-requested only once the virtual clock reaches it, never before it.
/// The default stays immediate, which is what production does.
#[tokio::test]
async fn push_without_a_retry_policy_waits_exactly_the_minimum_redelivery_interval() {
    let h = start().await;
    configure_push_redelivery_interval(&h, configured_push_redelivery_interval());
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![500, 500, 500, 500]);
    let topic = "projects/demo-app/topics/push-minimum-interval";
    let subscription = "projects/demo-app/subscriptions/push-minimum-interval";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"throttle-me")],
    })
    .await
    .unwrap();

    let interval = configured_push_redelivery_interval();
    let just_short = LogicalDuration::from_nanos(interval.as_nanos() - 1);
    for attempt in 1..=4 {
        await_push_count(&bodies, attempt).await;
        if attempt < 4 {
            let eligible_at = h
                .clock
                .lock()
                .unwrap()
                .now_for_test()
                .checked_add(interval)
                .unwrap();
            await_scheduled_redelivery(&h, subscription, eligible_at).await;
            // One nanosecond short of the interval must not release the redelivery.
            advance(&h, just_short);
            assert_push_count_stays(&bodies, attempt).await;
            advance(&h, LogicalDuration::from_nanos(1));
        }
    }
    assert_push_count_stays(&bodies, 4).await;
    assert_eq!(bodies.lock().unwrap().len(), 4);

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn ordered_push_delivers_successor_after_dead_letter_forwarding() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    // Five failed pushes exhaust the dead-letter budget of the predecessor; the sixth request is
    // the successor's.
    let mut statuses = vec![500; 5];
    statuses.push(204);
    let (endpoint, bodies, stop, worker) = push_sink_sequence(statuses);
    let source_topic = "projects/demo-app/topics/ordered-dlq-source";
    let dead_letter_topic = "projects/demo-app/topics/ordered-dlq-destination";
    let subscription = "projects/demo-app/subscriptions/ordered-dlq";

    for topic in [source_topic, dead_letter_topic] {
        pubc.create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: source_topic.to_owned(),
        enable_message_ordering: true,
        dead_letter_policy: Some(pb::DeadLetterPolicy {
            dead_letter_topic: dead_letter_topic.to_owned(),
            max_delivery_attempts: 5,
        }),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();

    let mut first = msg(b"ordered-first");
    first.ordering_key = "same-key".to_owned();
    let mut successor = msg(b"ordered-successor");
    successor.ordering_key = "same-key".to_owned();
    pubc.publish(pb::PublishRequest {
        topic: source_topic.to_owned(),
        messages: vec![first, successor],
    })
    .await
    .unwrap();

    // The five failing attempts have no retry policy, but each one owes the subscription's push
    // backoff; the dead-letter budget still counts one attempt per request.
    await_push_count_releasing_backoff(&h, &bodies, 6).await;
    let pushed = bodies.lock().unwrap().clone();
    assert_eq!(pushed.len(), 6);
    let last = String::from_utf8(pushed.last().unwrap().clone()).unwrap();
    assert!(last.contains("b3JkZXJlZC1zdWNjZXNzb3I"));

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn push_retry_waits_for_virtual_backoff_and_resumes_after_clock_advance() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![500, 500, 500, 204]);
    let topic = "projects/demo-app/topics/push-logical-backoff";
    let subscription = "projects/demo-app/subscriptions/push-logical-backoff";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        retry_policy: Some(pb::RetryPolicy {
            minimum_backoff: Some(prost_types::Duration {
                seconds: 5,
                nanos: 0,
            }),
            maximum_backoff: Some(prost_types::Duration {
                seconds: 5,
                nanos: 0,
            }),
        }),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"logical-backoff")],
    })
    .await
    .unwrap();

    // One request per attempt: every retry waits for the logical backoff, so the count only grows
    // when the virtual clock advances.
    for attempt in 1..=4 {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while bodies.lock().unwrap().len() < attempt {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the eligible attempt must be delivered");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            bodies.lock().unwrap().len(),
            attempt,
            "attempt {attempt} must wait for the logical backoff"
        );
        if attempt < 4 {
            h.clock
                .lock()
                .unwrap()
                .advance(LogicalDuration::from_seconds(5))
                .unwrap();
            h.handle.on_clock_changed();
        }
    }

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn a_new_publication_wakes_a_subscription_deferred_for_push_backoff() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![500, 500, 500, 204, 204]);
    let topic = "projects/demo-app/topics/push-backoff-wake";
    let subscription = "projects/demo-app/subscriptions/push-backoff-wake";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        retry_policy: Some(pb::RetryPolicy {
            minimum_backoff: Some(prost_types::Duration {
                seconds: 30,
                nanos: 0,
            }),
            maximum_backoff: Some(prost_types::Duration {
                seconds: 30,
                nanos: 0,
            }),
        }),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"first")],
    })
    .await
    .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first message must fail its attempt and enter backoff");

    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"second")],
    })
    .await
    .unwrap();
    // The failed attempt holds the subscription for its push backoff, so the new message waits
    // that out. It must not wait the 30 s retry policy, which belongs to the first message alone.
    advance(&h, push_backoff_after(1));
    let second_delivered = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while bodies.lock().unwrap().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await;

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
    second_delivered.expect("a new message must wake deferred push work");
}

#[tokio::test]
async fn deferred_push_backoff_leaves_worker_capacity_for_other_subscriptions() {
    const DELAYED_SUBSCRIPTIONS: usize = 256;
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (blocked_endpoint, blocked_bodies, stop_blocked, blocked_worker) =
        push_sink_sequence(vec![500; DELAYED_SUBSCRIPTIONS]);
    let (other_endpoint, other_bodies, stop_other, other_worker) = push_sink(204);
    let blocked_topic = "projects/demo-app/topics/push-backoff-saturated";
    let other_topic = "projects/demo-app/topics/push-backoff-other";

    for topic in [blocked_topic, other_topic] {
        pubc.create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    for index in 0..DELAYED_SUBSCRIPTIONS {
        subc.create_subscription(pb::Subscription {
            name: format!("projects/demo-app/subscriptions/push-backoff-{index:04}"),
            topic: blocked_topic.to_owned(),
            retry_policy: Some(pb::RetryPolicy {
                minimum_backoff: Some(prost_types::Duration {
                    seconds: 30,
                    nanos: 0,
                }),
                maximum_backoff: Some(prost_types::Duration {
                    seconds: 30,
                    nanos: 0,
                }),
            }),
            push_config: Some(pb::PushConfig {
                push_endpoint: blocked_endpoint.clone(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/push-backoff-other".to_owned(),
        topic: other_topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: other_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();

    pubc.publish(pb::PublishRequest {
        topic: blocked_topic.to_owned(),
        messages: vec![msg(b"defer")],
    })
    .await
    .unwrap();
    let attempts = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while blocked_bodies.lock().unwrap().len() < DELAYED_SUBSCRIPTIONS {
            tokio::task::yield_now().await;
        }
    })
    .await;

    pubc.publish(pb::PublishRequest {
        topic: other_topic.to_owned(),
        messages: vec![msg(b"other")],
    })
    .await
    .unwrap();
    let other_delivered = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while other_bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;

    h.shutdown().await;
    stop_blocked.store(true, Ordering::Release);
    stop_other.store(true, Ordering::Release);
    blocked_worker.join().unwrap();
    other_worker.join().unwrap();
    attempts.expect("all delayed workers must reach their logical backoff");
    other_delivered.expect("delayed workers must not consume all push capacity");
}

#[tokio::test]
async fn deleting_an_unrelated_subscription_does_not_stop_a_deferred_retry() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![500, 500, 500, 204]);
    let first_topic = "projects/demo-app/topics/push-delete-first";
    let second_topic = "projects/demo-app/topics/push-delete-second";
    let first_subscription = "projects/demo-app/subscriptions/push-delete-first";
    let second_subscription = "projects/demo-app/subscriptions/push-delete-second";

    for topic in [first_topic, second_topic] {
        pubc.create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    subc.create_subscription(pb::Subscription {
        name: first_subscription.to_owned(),
        topic: first_topic.to_owned(),
        retry_policy: Some(pb::RetryPolicy {
            minimum_backoff: Some(prost_types::Duration {
                seconds: 5,
                nanos: 0,
            }),
            maximum_backoff: Some(prost_types::Duration {
                seconds: 5,
                nanos: 0,
            }),
        }),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: second_subscription.to_owned(),
        topic: second_topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: "http://127.0.0.1:1/unused".to_owned(),
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: first_topic.to_owned(),
        messages: vec![msg(b"retry")],
    })
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first subscription must enter backoff");

    subc.delete_subscription(pb::DeleteSubscriptionRequest {
        subscription: second_subscription.to_owned(),
    })
    .await
    .unwrap();
    h.clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(5))
        .unwrap();
    h.handle.on_clock_changed();
    let retried = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while bodies.lock().unwrap().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await;

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
    retried.expect("deleting another subscription must not cancel this retry");
}

#[tokio::test]
async fn saturated_workers_release_cross_topic_work_without_another_publish() {
    const SATURATED_WORKERS: usize = 256;

    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (blocked_endpoint, blocked_count, release, blocked_worker) =
        gated_push_sink(SATURATED_WORKERS).await;
    let (other_endpoint, other_bodies, stop_other, other_worker) = push_sink(204);
    let first_topic = "projects/demo-app/topics/saturated-first";
    let second_topic = "projects/demo-app/topics/saturated-second";

    for topic in [first_topic, second_topic] {
        pubc.create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    for index in 0..SATURATED_WORKERS {
        subc.create_subscription(pb::Subscription {
            name: format!("projects/demo-app/subscriptions/saturated-{index:04}"),
            topic: first_topic.to_owned(),
            push_config: Some(pb::PushConfig {
                push_endpoint: blocked_endpoint.clone(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/saturated-other".to_owned(),
        topic: second_topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: other_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();

    pubc.publish(pb::PublishRequest {
        topic: first_topic.to_owned(),
        messages: vec![msg(b"occupy")],
    })
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while blocked_count.load(Ordering::Acquire) != SATURATED_WORKERS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all worker slots must be occupied");

    pubc.publish(pb::PublishRequest {
        topic: second_topic.to_owned(),
        messages: vec![msg(b"other-topic")],
    })
    .await
    .unwrap();
    assert!(other_bodies.lock().unwrap().is_empty());
    release.send(true).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while other_bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cross-topic work must remain queued at saturation");

    h.shutdown().await;
    blocked_worker.await.unwrap();
    stop_other.store(true, Ordering::Release);
    other_worker.join().unwrap();
}

#[tokio::test]
async fn shutdown_cancels_and_joins_in_flight_push_io() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, started, release, stop, worker) = barrier_push_sink();
    let topic = "projects/demo-app/topics/push-shutdown";
    let subscription = "projects/demo-app/subscriptions/push-shutdown";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"in-flight")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(1), h.shutdown())
        .await
        .expect("dispatcher shutdown must cancel and join in-flight I/O");
    assert_eq!(bodies.lock().unwrap().len(), 1);

    release.store(true, Ordering::Release);
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn aborting_the_public_server_cancels_in_flight_push_retries() {
    let mut h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, started, release, stop, worker) = barrier_push_sink_with_status(500);
    let topic = "projects/demo-app/topics/push-server-abort";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/push-server-abort".to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"must-not-retry")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    h.abort_server().await;
    release.store(true, Ordering::Release);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(bodies.lock().unwrap().len(), 1);

    h.handle.shutdown_push_dispatcher().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn ready_notification_is_not_consumed_by_an_unrelated_blocked_worker() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (blocked_endpoint, _blocked_bodies, started, release, stop_blocked, blocked_worker) =
        barrier_push_sink();
    let (ready_endpoint, ready_bodies, stop_ready, ready_worker) = push_sink(204);
    let blocked_topic = "projects/demo-app/topics/blocked-notify";
    let ready_topic = "projects/demo-app/topics/ready-notify";

    for topic in [blocked_topic, ready_topic] {
        pubc.create_topic(pb::Topic {
            name: topic.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    for (name, topic, endpoint) in [
        (
            "projects/demo-app/subscriptions/blocked-notify",
            blocked_topic,
            blocked_endpoint,
        ),
        (
            "projects/demo-app/subscriptions/ready-notify",
            ready_topic,
            ready_endpoint,
        ),
    ] {
        subc.create_subscription(pb::Subscription {
            name: name.to_owned(),
            topic: topic.to_owned(),
            push_config: Some(pb::PushConfig {
                push_endpoint: endpoint,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    pubc.publish(pb::PublishRequest {
        topic: blocked_topic.to_owned(),
        messages: vec![msg(b"blocked")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    pubc.publish(pb::PublishRequest {
        topic: ready_topic.to_owned(),
        messages: vec![msg(b"ready")],
    })
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while ready_bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dispatcher readiness must have a dedicated notification");

    h.shutdown().await;
    release.store(true, Ordering::Release);
    stop_blocked.store(true, Ordering::Release);
    stop_ready.store(true, Ordering::Release);
    blocked_worker.join().unwrap();
    ready_worker.join().unwrap();
}

#[tokio::test]
async fn push_endpoint_update_only_changes_deliveries_not_started_before_the_update() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (old_endpoint, old_bodies, started, release, stop_old, worker_old) = barrier_push_sink();
    let (new_endpoint, new_bodies, stop_new, worker_new) = push_sink(204);
    let topic = "projects/demo-app/topics/push-update";
    let subscription = "projects/demo-app/subscriptions/push-update";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: old_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"first"), msg(b"second")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    subc.modify_push_config(pb::ModifyPushConfigRequest {
        subscription: subscription.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: new_endpoint,
            ..Default::default()
        }),
    })
    .await
    .unwrap();
    release.store(true, Ordering::Release);

    for _ in 0..200 {
        if !new_bodies.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(old_bodies.lock().unwrap().len(), 1);
    assert_eq!(new_bodies.lock().unwrap().len(), 1);
    stop_old.store(true, Ordering::Release);
    stop_new.store(true, Ordering::Release);
    worker_old.join().unwrap();
    worker_new.join().unwrap();
}

#[tokio::test]
async fn deleting_and_recreating_a_subscription_invalidates_the_old_push_generation() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (old_endpoint, old_bodies, started, release, stop_old, worker_old) = barrier_push_sink();
    let (new_endpoint, new_bodies, stop_new, worker_new) = push_sink(204);
    let topic = "projects/demo-app/topics/push-recreate";
    let subscription = "projects/demo-app/subscriptions/push-recreate";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: old_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"old-generation")],
    })
    .await
    .unwrap();
    started.await.unwrap();

    subc.delete_subscription(pb::DeleteSubscriptionRequest {
        subscription: subscription.to_owned(),
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: new_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"new-generation")],
    })
    .await
    .unwrap();
    release.store(true, Ordering::Release);

    for _ in 0..200 {
        if !new_bodies.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(old_bodies.lock().unwrap().len(), 1);
    assert_eq!(new_bodies.lock().unwrap().len(), 1);
    let pulled = subc
        .pull(pb::PullRequest {
            subscription: subscription.to_owned(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(pulled.is_empty());
    stop_old.store(true, Ordering::Release);
    stop_new.store(true, Ordering::Release);
    worker_old.join().unwrap();
    worker_new.join().unwrap();
}

/// Creates a source topic, a destination topic and a source subscription whose dead-letter policy
/// forwards after `max_delivery_attempts` deliveries. Returns the source subscription name.
async fn setup_dead_letter_source(
    h: &Harness,
    slug: &str,
    push_endpoint: Option<String>,
) -> (String, String, String) {
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let source_topic = format!("projects/demo-app/topics/{slug}-source");
    let destination_topic = format!("projects/demo-app/topics/{slug}-destination");
    for topic in [&source_topic, &destination_topic] {
        pubc.create_topic(pb::Topic {
            name: topic.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    let subscription = format!("projects/demo-app/subscriptions/{slug}-source");
    subc.create_subscription(pb::Subscription {
        name: subscription.clone(),
        topic: source_topic.clone(),
        ack_deadline_seconds: 10,
        dead_letter_policy: Some(pb::DeadLetterPolicy {
            dead_letter_topic: destination_topic.clone(),
            max_delivery_attempts: 5,
        }),
        push_config: push_endpoint.map(|push_endpoint| pb::PushConfig {
            push_endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    (source_topic, destination_topic, subscription)
}

#[tokio::test]
async fn unary_pull_exhaustion_forwards_to_an_idle_destination_push_subscriber() {
    let h = start().await;
    let (source_topic, destination_topic, subscription) =
        setup_dead_letter_source(&h, "dlq-unary", None).await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;

    // The destination subscriber is a push subscription that has been idle since it was created:
    // only the forwarded message may wake it.
    let (endpoint, bodies, stop, worker) = push_sink(204);
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/dlq-unary-destination".to_owned(),
        topic: destination_topic,
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();

    pubc.publish(pb::PublishRequest {
        topic: source_topic,
        messages: vec![msg(b"poison")],
    })
    .await
    .unwrap();

    for attempt in 1..=5 {
        let received = subc
            .pull(pb::PullRequest {
                subscription: subscription.clone(),
                max_messages: 10,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .received_messages;
        assert_eq!(received.len(), 1, "attempt {attempt}");
        h.clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(11))
            .unwrap();
    }
    // The pull that exhausts the budget forwards instead of delivering.
    let forwarded = subc
        .pull(pb::PullRequest {
            subscription: subscription.clone(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(forwarded.is_empty());

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the forwarded message must wake the idle destination push subscriber");
    let pushed = bodies.lock().unwrap().clone();
    assert_eq!(pushed.len(), 1, "the transfer must not be repeated");
    assert!(String::from_utf8(pushed[0].clone())
        .unwrap()
        .contains("cG9pc29u"));

    // The source keeps no redeliverable copy of a committed transfer.
    let after = subc
        .pull(pb::PullRequest {
            subscription,
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(after.is_empty());

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn streaming_pull_exhaustion_forwards_to_the_destination_exactly_once() {
    let h = start().await;
    let (source_topic, destination_topic, subscription) =
        setup_dead_letter_source(&h, "dlq-stream", None).await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/dlq-stream-destination".to_owned(),
        topic: destination_topic,
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: source_topic,
        messages: vec![msg(b"poison")],
    })
    .await
    .unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel::<pb::StreamingPullRequest>(8);
    tx.send(pb::StreamingPullRequest {
        subscription: subscription.clone(),
        stream_ack_deadline_seconds: 10,
        ..Default::default()
    })
    .await
    .unwrap();
    let mut responses = subc
        .streaming_pull(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    // Nack every delivery on the same stream until the budget is exhausted.
    let mut deliveries = 0;
    while deliveries < 5 {
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), responses.next())
            .await
            .expect("a streaming response arrives")
            .expect("stream open")
            .expect("ok response");
        for received in response.received_messages {
            deliveries += 1;
            tx.send(pb::StreamingPullRequest {
                modify_deadline_ack_ids: vec![received.ack_id],
                modify_deadline_seconds: vec![0],
                ..Default::default()
            })
            .await
            .unwrap();
        }
    }

    let mut destination = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while destination.is_empty() {
            destination = subc
                .pull(pb::PullRequest {
                    subscription: "projects/demo-app/subscriptions/dlq-stream-destination"
                        .to_owned(),
                    max_messages: 10,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .received_messages;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("streaming-pull exhaustion must forward to the dead-letter topic");
    assert_eq!(destination.len(), 1);
    assert_eq!(destination[0].message.as_ref().unwrap().data, b"poison");
    drop(tx);

    h.shutdown().await;
}

#[tokio::test]
async fn push_exhaustion_forwards_to_the_destination_exactly_once() {
    let h = start().await;
    // Every source delivery fails, so the delivery budget is exhausted by push alone.
    let (source_endpoint, _source_bodies, source_stop, source_worker) =
        push_sink_sequence(vec![500; 200]);
    let (source_topic, destination_topic, _subscription) =
        setup_dead_letter_source(&h, "dlq-push", Some(source_endpoint)).await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/dlq-push-destination".to_owned(),
        topic: destination_topic,
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: source_topic,
        messages: vec![msg(b"poison")],
    })
    .await
    .unwrap();

    let mut destination = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while destination.is_empty() {
            destination = subc
                .pull(pb::PullRequest {
                    subscription: "projects/demo-app/subscriptions/dlq-push-destination".to_owned(),
                    max_messages: 10,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .received_messages;
            // Each failed push holds the subscription for its push backoff.
            release_push_backoff(&h);
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("push exhaustion must forward to the dead-letter topic");
    assert_eq!(destination.len(), 1);
    assert_eq!(destination[0].message.as_ref().unwrap().data, b"poison");

    h.shutdown().await;
    source_stop.store(true, Ordering::Release);
    source_worker.join().unwrap();
}

#[tokio::test]
async fn a_deleted_destination_topic_retains_the_forward_until_it_is_created_again() {
    // The bridge records every committed publication, so the transfer is observable even though a
    // destination subscription cannot outlive the deleted topic.
    let recorder = Arc::new(RecordingTopicDelivery::default());
    let h = start_with_bridge(Some(recorder.clone())).await;
    let (source_topic, destination_topic, subscription) =
        setup_dead_letter_source(&h, "dlq-missing", None).await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    pubc.publish(pb::PublishRequest {
        topic: source_topic,
        messages: vec![msg(b"poison")],
    })
    .await
    .unwrap();
    pubc.delete_topic(pb::DeleteTopicRequest {
        topic: destination_topic.clone(),
    })
    .await
    .unwrap();

    for _ in 0..5 {
        subc.pull(pb::PullRequest {
            subscription: subscription.clone(),
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap();
        h.clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(11))
            .unwrap();
    }
    // The destination is gone: the exhausted message is retained, neither delivered nor dropped.
    for _ in 0..2 {
        let received = subc
            .pull(pb::PullRequest {
                subscription: subscription.clone(),
                max_messages: 10,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .received_messages;
        assert!(
            received.is_empty(),
            "a pending forward must not be delivered to the source subscriber again"
        );
    }
    assert_eq!(
        recorder
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|topic| **topic == destination_topic)
            .count(),
        0,
        "a missing destination must not receive a partial publication"
    );

    pubc.create_topic(pb::Topic {
        name: destination_topic.clone(),
        ..Default::default()
    })
    .await
    .unwrap();

    assert_eq!(
        recorder
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|topic| **topic == destination_topic)
            .count(),
        1,
        "a recreated destination must accept the retained transfer exactly once"
    );
    let after = subc
        .pull(pb::PullRequest {
            subscription,
            max_messages: 10,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .received_messages;
    assert!(
        after.is_empty(),
        "the source must be completed once the destination accepted the transfer"
    );

    h.shutdown().await;
}

#[tokio::test]
async fn seeking_to_a_snapshot_replays_the_backlog_to_an_idle_push_subscriber() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let topic = "projects/demo-app/topics/seek-push";
    let subscription = "projects/demo-app/subscriptions/seek-push";
    let (endpoint, bodies, stop, worker) = push_sink(204);
    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_snapshot(pb::CreateSnapshotRequest {
        name: "projects/demo-app/snapshots/seek-push".to_owned(),
        subscription: subscription.to_owned(),
        labels: HashMap::new(),
        tags: HashMap::new(),
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"replayed")],
    })
    .await
    .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while bodies.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first delivery reaches the push endpoint");

    // The subscription is now idle: the seek alone must schedule the replayed backlog.
    subc.seek(pb::SeekRequest {
        subscription: subscription.to_owned(),
        target: Some(pb::seek_request::Target::Snapshot(
            "projects/demo-app/snapshots/seek-push".to_owned(),
        )),
    })
    .await
    .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while bodies.lock().unwrap().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a seek must wake an idle push subscriber without another publish");

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[tokio::test]
async fn a_failed_push_delivery_counts_one_delivery_attempt_against_the_dead_letter_budget() {
    let h = start().await;
    // More failures than the budget allows: only the budget may decide when forwarding happens.
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![500; 50]);
    let (source_topic, destination_topic, _subscription) =
        setup_dead_letter_source(&h, "dlq-attempts", Some(endpoint)).await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    subc.create_subscription(pb::Subscription {
        name: "projects/demo-app/subscriptions/dlq-attempts-destination".to_owned(),
        topic: destination_topic,
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: source_topic,
        messages: vec![msg(b"poison")],
    })
    .await
    .unwrap();

    let mut destination = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while destination.is_empty() {
            destination = subc
                .pull(pb::PullRequest {
                    subscription: "projects/demo-app/subscriptions/dlq-attempts-destination"
                        .to_owned(),
                    max_messages: 10,
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_inner()
                .received_messages;
            // Each failed push holds the subscription for its push backoff.
            release_push_backoff(&h);
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("the message must reach the dead-letter topic");
    assert_eq!(destination.len(), 1);

    // Each failed push request is one delivery attempt, so the budget of five allows five.
    let pushed = bodies.lock().unwrap().clone();
    assert_eq!(
        pushed.len(),
        5,
        "a push subscription must dead-letter after exactly max_delivery_attempts failed pushes"
    );
    // Every attempt reports its own delivery_attempt to the endpoint, as production does when a
    // dead-letter policy is set.
    for (index, body) in pushed.iter().enumerate() {
        let body = String::from_utf8(body.clone()).unwrap();
        let expected = format!("\"deliveryAttempt\":{}", index + 1);
        assert!(body.contains(&expected), "attempt {}: {body}", index + 1);
    }

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

/// Push delivery carries a subscription-level backoff of its own, separate from the per-message
/// retry policy and not disableable: an endpoint that keeps failing is re-requested less and less
/// often. The documented bounds are 100 ms to 60 s; the progression between them doubles here.
#[tokio::test]
async fn continuous_push_failure_backs_the_subscription_off_exponentially() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![503; 8]);
    let topic = "projects/demo-app/topics/push-backoff-growth";
    let subscription = "projects/demo-app/subscriptions/push-backoff-growth";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"always-503")],
    })
    .await
    .unwrap();

    // The retry policy is immediate, so nothing but the push backoff holds the message back.
    for attempt in 1..=4_u32 {
        await_push_count(&bodies, attempt as usize).await;
        let wait = push_backoff_after(attempt);
        assert_eq!(
            wait,
            LogicalDuration::from_millis(100_i64 << (attempt - 1)),
            "the wait must double with every consecutive failure"
        );
        let resume_at = h
            .clock
            .lock()
            .unwrap()
            .now_for_test()
            .checked_add(wait)
            .unwrap();
        await_push_backoff(&h, subscription, resume_at).await;

        // One nanosecond short of the backoff must not release the endpoint.
        advance(&h, LogicalDuration::from_nanos(wait.as_nanos() - 1));
        assert_push_count_stays(&bodies, attempt as usize).await;
        advance(&h, LogicalDuration::from_nanos(1));
    }
    await_push_count(&bodies, 5).await;

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

/// The backoff throttles the subscription, not one message: a message published while the
/// endpoint is failing waits with it rather than being pushed straight away.
#[tokio::test]
async fn a_message_published_during_push_backoff_is_held_with_the_subscription() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![503, 204, 204]);
    let topic = "projects/demo-app/topics/push-backoff-hold";
    let subscription = "projects/demo-app/subscriptions/push-backoff-hold";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"first")],
    })
    .await
    .unwrap();
    await_push_count(&bodies, 1).await;
    let wait = push_backoff_after(1);
    let resume_at = h
        .clock
        .lock()
        .unwrap()
        .now_for_test()
        .checked_add(wait)
        .unwrap();
    await_push_backoff(&h, subscription, resume_at).await;

    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"second")],
    })
    .await
    .unwrap();
    assert_push_count_stays(&bodies, 1).await;

    advance(&h, wait);
    await_push_count(&bodies, 3).await;
    let pushed = bodies.lock().unwrap().clone();
    assert_eq!(pushed.len(), 3);

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

/// The backoff is owned by one subscription: a healthy subscription keeps delivering at full
/// speed while another one's endpoint is failing, without the virtual clock moving at all.
#[tokio::test]
async fn push_backoff_on_one_subscription_leaves_another_untouched() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (failing_endpoint, failing_bodies, stop_failing, failing_worker) =
        push_sink_sequence(vec![503; 4]);
    let (healthy_endpoint, healthy_bodies, stop_healthy, healthy_worker) = push_sink(204);
    let topic = "projects/demo-app/topics/push-backoff-isolation";
    let failing = "projects/demo-app/subscriptions/push-backoff-failing";
    let healthy = "projects/demo-app/subscriptions/push-backoff-healthy";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    for (name, endpoint) in [(failing, failing_endpoint), (healthy, healthy_endpoint)] {
        subc.create_subscription(pb::Subscription {
            name: name.to_owned(),
            topic: topic.to_owned(),
            push_config: Some(pb::PushConfig {
                push_endpoint: endpoint,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"fan-out")],
    })
    .await
    .unwrap();

    await_push_count(&failing_bodies, 1).await;
    let resume_at = h
        .clock
        .lock()
        .unwrap()
        .now_for_test()
        .checked_add(push_backoff_after(1))
        .unwrap();
    await_push_backoff(&h, failing, resume_at).await;

    // The healthy subscription never entered a backoff, so its delivery needs no clock advance.
    await_push_count(&healthy_bodies, 1).await;
    let healthy_name = fireemu_core_pubsub::SubscriptionName::parse(healthy).unwrap();
    assert_eq!(h.handle.push_backoff_resume_at(&healthy_name), None);
    assert_push_count_stays(&failing_bodies, 1).await;

    h.shutdown().await;
    stop_failing.store(true, Ordering::Release);
    stop_healthy.store(true, Ordering::Release);
    failing_worker.join().unwrap();
    healthy_worker.join().unwrap();
}

/// A retry policy and the push backoff are separate waits and the later one decides: a 30 s retry
/// policy outlasts the first 100 ms of push backoff, so the message is not re-pushed at 100 ms.
#[tokio::test]
async fn a_longer_retry_policy_outlasts_the_push_backoff() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![503, 503, 204]);
    let topic = "projects/demo-app/topics/push-backoff-retry-wins";
    let subscription = "projects/demo-app/subscriptions/push-backoff-retry-wins";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        retry_policy: Some(pb::RetryPolicy {
            minimum_backoff: Some(prost_types::Duration {
                seconds: 30,
                nanos: 0,
            }),
            maximum_backoff: Some(prost_types::Duration {
                seconds: 30,
                nanos: 0,
            }),
        }),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"slow-retry")],
    })
    .await
    .unwrap();

    await_push_count(&bodies, 1).await;
    let backoff = push_backoff_after(1);
    let resume_at = h
        .clock
        .lock()
        .unwrap()
        .now_for_test()
        .checked_add(backoff)
        .unwrap();
    await_push_backoff(&h, subscription, resume_at).await;

    // The push backoff elapses first, and the retry policy still holds the message.
    advance(&h, backoff);
    assert_push_count_stays(&bodies, 1).await;

    advance(&h, LogicalDuration::from_seconds(30));
    await_push_count(&bodies, 2).await;

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

/// The other direction: a retry policy shorter than the push backoff does not shorten it. After
/// three consecutive failures the subscription owes 400 ms, so a 150 ms retry policy expiring
/// does not release the endpoint.
#[tokio::test]
async fn a_shorter_retry_policy_does_not_shorten_the_push_backoff() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![503; 6]);
    let topic = "projects/demo-app/topics/push-backoff-wins";
    let subscription = "projects/demo-app/subscriptions/push-backoff-wins";
    let retry = LogicalDuration::from_millis(150);

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        retry_policy: Some(pb::RetryPolicy {
            minimum_backoff: Some(prost_types::Duration {
                seconds: 0,
                nanos: 150_000_000,
            }),
            maximum_backoff: Some(prost_types::Duration {
                seconds: 0,
                nanos: 150_000_000,
            }),
        }),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"fast-retry")],
    })
    .await
    .unwrap();

    // Walk to the third failure, where the push backoff (400 ms) outlasts the retry policy.
    for attempt in 1..=3_u32 {
        await_push_count(&bodies, attempt as usize).await;
        let backoff = push_backoff_after(attempt);
        let resume_at = h
            .clock
            .lock()
            .unwrap()
            .now_for_test()
            .checked_add(backoff)
            .unwrap();
        await_push_backoff(&h, subscription, resume_at).await;
        if attempt < 3 {
            // Both waits start at the same instant, so the later one releases the attempt.
            advance(&h, backoff.max(retry));
        }
    }
    assert_eq!(push_backoff_after(3), LogicalDuration::from_millis(400));

    // The retry policy expires long before the backoff does, and releases nothing.
    advance(&h, retry);
    assert_push_count_stays(&bodies, 3).await;

    advance(&h, LogicalDuration::from_millis(250));
    await_push_count(&bodies, 4).await;

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

/// A delivery the endpoint accepts clears the streak, so the next failure starts again at the
/// minimum wait rather than continuing to double.
#[tokio::test]
async fn a_successful_push_resets_the_backoff_streak() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, stop, worker) = push_sink_sequence(vec![503, 503, 204, 503, 204]);
    let topic = "projects/demo-app/topics/push-backoff-reset";
    let subscription = "projects/demo-app/subscriptions/push-backoff-reset";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"recovering")],
    })
    .await
    .unwrap();

    // Two failures take the wait to 200 ms, then the third attempt succeeds and clears it.
    for attempt in 1..=2_u32 {
        await_push_count(&bodies, attempt as usize).await;
        let backoff = push_backoff_after(attempt);
        let resume_at = h
            .clock
            .lock()
            .unwrap()
            .now_for_test()
            .checked_add(backoff)
            .unwrap();
        await_push_backoff(&h, subscription, resume_at).await;
        advance(&h, backoff);
    }
    await_push_count(&bodies, 3).await;
    let name = fireemu_core_pubsub::SubscriptionName::parse(subscription).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while h.handle.push_backoff_resume_at(&name).is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("an accepted delivery must clear the push backoff");

    // The next message fails once, and owes the minimum wait again rather than 400 ms.
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"fails-once")],
    })
    .await
    .unwrap();
    await_push_count(&bodies, 4).await;
    let resume_at = h
        .clock
        .lock()
        .unwrap()
        .now_for_test()
        .checked_add(push_backoff_after(1))
        .unwrap();
    await_push_backoff(&h, subscription, resume_at).await;

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

/// The interleaving that reopens the immediate loop: a message is published while a failing push
/// attempt is still awaiting its endpoint. The publication is admitted before the failure is
/// known, so nothing may turn it into a request before the backoff the failure records elapses.
#[tokio::test]
async fn a_publish_during_an_in_flight_failing_push_sends_nothing_before_the_backoff_elapses() {
    let h = start().await;
    let mut pubc = h.publisher().await;
    let mut subc = h.subscriber().await;
    let (endpoint, bodies, started, release, stop, worker) = barrier_push_sink_with_status(503);
    let topic = "projects/demo-app/topics/push-backoff-inflight";
    let subscription = "projects/demo-app/subscriptions/push-backoff-inflight";

    pubc.create_topic(pb::Topic {
        name: topic.to_owned(),
        ..Default::default()
    })
    .await
    .unwrap();
    subc.create_subscription(pb::Subscription {
        name: subscription.to_owned(),
        topic: topic.to_owned(),
        push_config: Some(pb::PushConfig {
            push_endpoint: endpoint,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await
    .unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"first")],
    })
    .await
    .unwrap();

    // The endpoint has the first request and is holding it: the attempt has not failed yet.
    started.await.unwrap();
    pubc.publish(pb::PublishRequest {
        topic: topic.to_owned(),
        messages: vec![msg(b"published-mid-flight")],
    })
    .await
    .unwrap();

    let resume_at = h
        .clock
        .lock()
        .unwrap()
        .now_for_test()
        .checked_add(push_backoff_after(1))
        .unwrap();
    release.store(true, Ordering::Release);
    await_push_backoff(&h, subscription, resume_at).await;

    // The publication admitted mid-flight must not have become a request of its own.
    assert_push_count_stays(&bodies, 1).await;
    advance(&h, push_backoff_after(1));
    await_push_count(&bodies, 2).await;

    h.shutdown().await;
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}
