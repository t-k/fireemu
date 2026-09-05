//! gRPC surface for the Cloud Pub/Sub emulator.
//!
//! This adapter serves the `google.pubsub.v1` `Publisher` and `Subscriber` services over the
//! [`fireemu_core_pubsub`] state machine, mirroring the Firestore and Storage core/adapter
//! split. It is the wire protocol a real `@google-cloud/pubsub` or `firebase-admin` client
//! reaches through `PUBSUB_EMULATOR_HOST`.
//!
//! # Security posture
//!
//! The daemon binds the listener to loopback (`127.0.0.1`) only, exactly like the official
//! emulator and the other fireemu services, and no credential is required on loopback. Message
//! sizes are bounded at the gRPC codec (10 MiB decode / encode), and the core state machine
//! bounds topics, subscriptions and retained messages so a client cannot exhaust memory.
//!
//! # Determinism
//!
//! Every time-dependent operation reads the shared [`VirtualClock`]; ack deadlines and
//! redelivery therefore advance only when the control API advances the clock, and message /
//! ack ids come from the daemon seed, so a run reproduces and `await-idle` stays deterministic.

mod convert;
mod publisher;
mod push;
mod subscriber;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::time::LogicalInstant;
use tokio::sync::Notify;

use fireemu_proto_pubsub::google::pubsub::v1::publisher_server::PublisherServer;
use fireemu_proto_pubsub::google::pubsub::v1::subscriber_server::SubscriberServer;

pub use publisher::PublisherService;
pub use subscriber::SubscriberService;

/// Maximum gRPC message size accepted or produced (10 MiB), matching Pub/Sub's message bound.
pub const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_PUSH_WORKERS: usize = 256;
const MAX_PUSH_ATTEMPTS: usize = 3;

/// A message handed to the functions bridge for topic-trigger delivery.
#[derive(Debug, Clone)]
pub struct BridgeMessage {
    /// The broker record shared with every subscription.
    pub message: Arc<fireemu_core_pubsub::StoredMessage>,
}

/// Bridge to the Functions runtime: a message published on a topic is also delivered to any
/// Cloud Function subscribed to that topic (EVTINFRA-02). The daemon implements this by calling
/// the existing `FunctionsRuntime::publish`, so the topic-trigger path is unchanged and the new
/// broker state is additive.
pub trait TopicDelivery: Send + Sync {
    /// Deliver `messages` published on the short `topic` name to subscribed functions.
    fn deliver(&self, topic: &str, messages: &[BridgeMessage]);
}

/// The shared state a Pub/Sub adapter serves: the core registry, the virtual clock and the
/// optional Functions bridge.
#[derive(Clone)]
pub struct PubSubHandle {
    state: Arc<Mutex<PubSubState>>,
    clock: Arc<Mutex<VirtualClock>>,
    bridge: Option<Arc<dyn TopicDelivery>>,
    push_workers: Arc<Mutex<BTreeSet<String>>>,
    push_notify: Arc<Notify>,
}

impl PubSubHandle {
    /// Builds a handle over shared state, the clock and an optional Functions bridge.
    #[must_use]
    pub fn new(
        state: Arc<Mutex<PubSubState>>,
        clock: Arc<Mutex<VirtualClock>>,
        bridge: Option<Arc<dyn TopicDelivery>>,
    ) -> Self {
        Self {
            state,
            clock,
            bridge,
            push_workers: Arc::new(Mutex::new(BTreeSet::new())),
            push_notify: Arc::new(Notify::new()),
        }
    }

    /// The current virtual-clock instant.
    fn now(&self) -> LogicalInstant {
        self.clock.lock().expect("clock lock").now()
    }

    /// Locks the core state.
    fn state(&self) -> std::sync::MutexGuard<'_, PubSubState> {
        self.state.lock().expect("pubsub state lock")
    }

    /// Delivers published messages to subscribed functions through the bridge, if one is wired.
    fn bridge_deliver(&self, topic: &str, messages: &[BridgeMessage]) {
        if let Some(bridge) = &self.bridge {
            if !messages.is_empty() {
                bridge.deliver(topic, messages);
            }
        }
    }

    /// Starts at most one bounded push worker per subscription. Pull and push share the same
    /// core delivery state, so a successful push acknowledges the same record a pull would see.
    fn schedule_push(&self, topic: &fireemu_core_pubsub::TopicName) {
        self.push_notify.notify_waiters();
        let subscriptions = self.state().push_subscriptions(topic);
        for (subscription, endpoint) in subscriptions {
            let key = subscription.to_full();
            let claimed = {
                let mut workers = self.push_workers.lock().expect("push worker lock");
                if workers.len() >= MAX_PUSH_WORKERS {
                    false
                } else {
                    workers.insert(key.clone())
                }
            };
            if !claimed {
                continue;
            }
            let handle = self.clone();
            tokio::spawn(async move {
                handle.run_push_worker(subscription, endpoint).await;
                handle
                    .push_workers
                    .lock()
                    .expect("push worker lock")
                    .remove(&key);
                handle.push_notify.notify_waiters();
            });
        }
    }

    async fn run_push_worker(
        &self,
        subscription: fireemu_core_pubsub::SubscriptionName,
        endpoint: String,
    ) {
        loop {
            let now = self.now();
            let received = {
                self.state()
                    .pull(&subscription, 100, now)
                    .unwrap_or_default()
            };
            if received.is_empty() {
                // A publication can race the final empty pull. A short bounded grace period
                // lets the same worker observe it without leaving a permanent task behind.
                tokio::select! {
                    () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {},
                    () = self.push_notify.notified() => {},
                }
                let still_configured = self
                    .state()
                    .subscription_config(&subscription)
                    .is_ok_and(fireemu_core_pubsub::SubscriptionConfig::is_push);
                if !still_configured {
                    return;
                }
                let retry = self
                    .state()
                    .pull(&subscription, 1, self.now())
                    .unwrap_or_default();
                if retry.is_empty() {
                    return;
                }
                if !self
                    .deliver_push_messages(&subscription, &endpoint, retry)
                    .await
                {
                    return;
                }
                continue;
            }
            if !self
                .deliver_push_messages(&subscription, &endpoint, received)
                .await
            {
                return;
            }
        }
    }

    async fn deliver_push_messages(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
        endpoint: &str,
        received: Vec<fireemu_core_pubsub::ReceivedMessage>,
    ) -> bool {
        for (index, message) in received.iter().enumerate() {
            let mut delivered = false;
            for attempt in 0..MAX_PUSH_ATTEMPTS {
                if push::deliver(endpoint, subscription, message).await.is_ok() {
                    delivered = true;
                    break;
                }
                if attempt + 1 < MAX_PUSH_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
            if delivered {
                let _ = self
                    .state()
                    .acknowledge(subscription, std::slice::from_ref(&message.ack_id));
                continue;
            }
            let now = self.now();
            let mut state = self.state();
            for remaining in &received[index..] {
                let _ = state.modify_ack_deadline(
                    subscription,
                    std::slice::from_ref(&remaining.ack_id),
                    0,
                    now,
                );
            }
            return false;
        }
        true
    }
}

/// Serves the Pub/Sub gRPC surface on an already-bound loopback listener until it is closed.
///
/// The daemon binds the `TcpListener` to `127.0.0.1`; this function never binds a socket itself.
pub async fn serve_pubsub(
    listener: tokio::net::TcpListener,
    handle: PubSubHandle,
) -> Result<(), tonic::transport::Error> {
    let publisher = PublisherServer::new(PublisherService::new(handle.clone()))
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);
    let subscriber = SubscriberServer::new(SubscriberService::new(handle))
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);
    tonic::transport::Server::builder()
        .add_service(publisher)
        .add_service(subscriber)
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
        .await
}
