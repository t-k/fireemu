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
mod rest;
mod subscriber;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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
const PUSH_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

struct PushDispatcherCancellationGuard(PubSubHandle);

impl Drop for PushDispatcherCancellationGuard {
    fn drop(&mut self) {
        self.0.cancel_push_dispatcher();
    }
}

#[derive(Debug, Clone)]
struct PushWork {
    subscription: fireemu_core_pubsub::SubscriptionName,
    generation: u64,
}

#[derive(Debug, Default)]
struct PushDispatchState {
    ready: VecDeque<PushWork>,
    queued: BTreeSet<String>,
    active: BTreeMap<String, u64>,
    generations: BTreeMap<String, u64>,
    next_generation: u64,
    spawned: u64,
    shutting_down: bool,
}

#[derive(Debug, Default)]
struct PushDispatcherLifecycle {
    task: Option<tokio::task::JoinHandle<()>>,
    stopped: bool,
}

impl PushDispatchState {
    fn generation_for(&mut self, key: &str) -> u64 {
        if let Some(generation) = self.generations.get(key) {
            return *generation;
        }
        self.next_generation = self.next_generation.wrapping_add(1);
        let generation = self.next_generation;
        self.generations.insert(key.to_owned(), generation);
        generation
    }

    fn enqueue(&mut self, subscription: fireemu_core_pubsub::SubscriptionName) {
        if self.shutting_down {
            return;
        }
        let key = subscription.to_full();
        if self.queued.insert(key.clone()) {
            let generation = self.generation_for(&key);
            self.ready.push_back(PushWork {
                subscription,
                generation,
            });
        }
    }

    fn claim(&mut self) -> Option<PushWork> {
        let candidates = self.ready.len();
        for _ in 0..candidates {
            let work = self.ready.pop_front()?;
            let key = work.subscription.to_full();
            if self.generations.get(&key).copied() != Some(work.generation) {
                self.queued.remove(&key);
                continue;
            }
            if self.active.get(&key).copied() == Some(work.generation) {
                self.ready.push_back(work);
                continue;
            }
            self.queued.remove(&key);
            self.active.insert(key, work.generation);
            self.spawned = self.spawned.saturating_add(1);
            return Some(work);
        }
        None
    }

    fn complete(&mut self, work: &PushWork, continue_delivery: bool) {
        let key = work.subscription.to_full();
        if self.active.get(&key).copied() == Some(work.generation) {
            self.active.remove(&key);
        }
        if continue_delivery
            && self.generations.get(&key).copied() == Some(work.generation)
            && self.queued.insert(key)
        {
            self.ready.push_back(work.clone());
        }
    }

    fn invalidate(&mut self, key: &str) {
        self.generations.remove(key);
        self.queued.remove(key);
        self.active.remove(key);
        self.ready.retain(|work| work.subscription.to_full() != key);
    }

    fn invalidate_all(&mut self) {
        self.generations.clear();
        self.queued.clear();
        self.ready.clear();
        self.active.clear();
    }

    fn invalidate_projects_where(&mut self, matches: impl Fn(&str) -> bool) {
        let keys = self
            .generations
            .keys()
            .filter_map(|key| {
                fireemu_core_pubsub::SubscriptionName::parse(key)
                    .ok()
                    .filter(|name| matches(name.project()))
                    .map(|_| key.clone())
            })
            .collect::<Vec<_>>();
        for key in keys {
            self.invalidate(&key);
        }
    }
}

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
    push_dispatch: Arc<Mutex<PushDispatchState>>,
    push_dispatcher: Arc<Mutex<PushDispatcherLifecycle>>,
    push_ready_notify: Arc<Notify>,
    push_cancel_notify: Arc<Notify>,
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
            push_dispatch: Arc::new(Mutex::new(PushDispatchState::default())),
            push_dispatcher: Arc::new(Mutex::new(PushDispatcherLifecycle::default())),
            push_ready_notify: Arc::new(Notify::new()),
            push_cancel_notify: Arc::new(Notify::new()),
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

    fn is_current_push_generation(&self, subscription: &str, generation: u64) -> bool {
        let dispatch = self.push_dispatch.lock().expect("push dispatch lock");
        !dispatch.shutting_down
            && dispatch.generations.get(subscription).copied() == Some(generation)
    }

    /// Invalidates a worker for a deleted subscription incarnation. An update keeps the
    /// incarnation so a delivery that already crossed its start point may still acknowledge the
    /// message; the next message reads the updated endpoint immediately before it starts.
    pub(crate) fn invalidate_push_worker(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
    ) {
        let key = subscription.to_full();
        self.push_dispatch
            .lock()
            .expect("push dispatch lock")
            .invalidate(&key);
        self.push_cancel_notify.notify_waiters();
        self.push_ready_notify.notify_one();
    }

    /// Invalidates all known workers before a project or session reset.
    pub fn invalidate_all_push_workers(&self) {
        self.push_dispatch
            .lock()
            .expect("push dispatch lock")
            .invalidate_all();
        self.push_cancel_notify.notify_waiters();
        self.push_ready_notify.notify_one();
    }

    /// Invalidates queued and active push work owned by matching subscription projects.
    pub fn invalidate_push_workers_where(
        &self,
        matches: impl Fn(&str) -> bool,
    ) -> Result<(), String> {
        self.push_dispatch
            .lock()
            .map_err(|_| "the Pub/Sub push dispatcher is poisoned".to_owned())?
            .invalidate_projects_where(matches);
        self.push_cancel_notify.notify_waiters();
        self.push_ready_notify.notify_one();
        Ok(())
    }

    /// Starts at most one bounded push worker per subscription. Pull and push share the same
    /// core delivery state, so a successful push acknowledges the same record a pull would see.
    fn schedule_push(&self, topic: &fireemu_core_pubsub::TopicName) {
        let subscriptions = self.state().push_subscriptions(topic);
        let mut dispatch = self.push_dispatch.lock().expect("push dispatch lock");
        for (subscription, _) in subscriptions {
            dispatch.enqueue(subscription);
        }
        drop(dispatch);
        self.push_ready_notify.notify_one();
    }

    fn start_push_dispatcher(&self) {
        let mut lifecycle = self.push_dispatcher.lock().expect("push dispatcher lock");
        if lifecycle.stopped || lifecycle.task.is_some() {
            return;
        }
        let handle = self.clone();
        lifecycle.task = Some(tokio::spawn(
            async move { handle.run_push_dispatcher().await },
        ));
    }

    async fn run_push_dispatcher(&self) {
        let mut workers = tokio::task::JoinSet::new();
        let mut work_by_task = HashMap::new();
        loop {
            let notified = self.push_ready_notify.notified();
            let shutting_down = self
                .push_dispatch
                .lock()
                .expect("push dispatch lock")
                .shutting_down;
            if shutting_down {
                workers.abort_all();
                while workers.join_next().await.is_some() {}
                let mut dispatch = self.push_dispatch.lock().expect("push dispatch lock");
                dispatch.active.clear();
                dispatch.ready.clear();
                dispatch.queued.clear();
                return;
            }
            while workers.len() < MAX_PUSH_WORKERS {
                let work = self
                    .push_dispatch
                    .lock()
                    .expect("push dispatch lock")
                    .claim();
                let Some(work) = work else { break };
                let handle = self.clone();
                let fallback = work.clone();
                let task = workers.spawn(async move {
                    let task_id = tokio::task::id();
                    let continue_delivery = handle.run_push_quantum(&work).await;
                    (task_id, work, continue_delivery)
                });
                work_by_task.insert(task.id(), fallback);
            }
            if workers.is_empty() {
                notified.await;
                continue;
            }
            tokio::select! {
                () = notified => {},
                completed = workers.join_next() => {
                    match completed {
                        Some(Ok((task_id, work, continue_delivery))) => {
                            work_by_task.remove(&task_id);
                            self.push_dispatch
                                .lock()
                                .expect("push dispatch lock")
                                .complete(&work, continue_delivery);
                        }
                        Some(Err(error)) => {
                            if let Some(work) = work_by_task.remove(&error.id()) {
                                self.push_dispatch
                                    .lock()
                                    .expect("push dispatch lock")
                                    .complete(&work, false);
                            }
                        }
                        None => {}
                    }
                }
            }
        }
    }

    async fn run_push_quantum(&self, work: &PushWork) -> bool {
        let key = work.subscription.to_full();
        if !self.is_current_push_generation(&key, work.generation) {
            return false;
        }
        let received = self
            .state()
            .pull(&work.subscription, 100, self.now())
            .unwrap_or_default();
        if received.is_empty() {
            return false;
        }
        self.deliver_push_messages(&work.subscription, &key, work.generation, received)
            .await
    }

    async fn wait_until_push_invalidated(&self, key: &str, generation: u64) {
        loop {
            let notified = self.push_cancel_notify.notified();
            if !self.is_current_push_generation(key, generation) {
                return;
            }
            notified.await;
        }
    }

    fn push_endpoint_if_current(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
        key: &str,
        generation: u64,
    ) -> Option<String> {
        let dispatch = self.push_dispatch.lock().expect("push dispatch lock");
        if dispatch.shutting_down || dispatch.generations.get(key).copied() != Some(generation) {
            return None;
        }
        self.state()
            .subscription_config(subscription)
            .ok()
            .filter(|config| config.is_push())
            .map(|config| config.push_config.push_endpoint.clone())
    }

    fn acknowledge_push_if_current(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
        key: &str,
        generation: u64,
        ack_id: &str,
    ) -> bool {
        let dispatch = self.push_dispatch.lock().expect("push dispatch lock");
        if dispatch.shutting_down || dispatch.generations.get(key).copied() != Some(generation) {
            return false;
        }
        self.state()
            .acknowledge(subscription, &[ack_id.to_owned()])
            .is_ok()
    }

    fn nack_push_if_current(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
        key: &str,
        generation: u64,
        messages: &[fireemu_core_pubsub::ReceivedMessage],
    ) -> bool {
        let dispatch = self.push_dispatch.lock().expect("push dispatch lock");
        if dispatch.shutting_down || dispatch.generations.get(key).copied() != Some(generation) {
            return false;
        }
        let now = self.now();
        let mut state = self.state();
        for message in messages {
            let _ = state.modify_ack_deadline(
                subscription,
                std::slice::from_ref(&message.ack_id),
                0,
                now,
            );
        }
        true
    }

    async fn deliver_push_messages(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
        key: &str,
        generation: u64,
        received: Vec<fireemu_core_pubsub::ReceivedMessage>,
    ) -> bool {
        for (index, message) in received.iter().enumerate() {
            if !self.is_current_push_generation(key, generation) {
                return false;
            }
            let mut delivered = false;
            for attempt in 0..MAX_PUSH_ATTEMPTS {
                if !self.is_current_push_generation(key, generation) {
                    return false;
                }
                let Some(endpoint) = self.push_endpoint_if_current(subscription, key, generation)
                else {
                    return false;
                };
                tokio::select! {
                    result = push::deliver(&endpoint, subscription, message) => {
                        if result.is_ok() {
                            delivered = true;
                            break;
                        }
                    }
                    () = self.wait_until_push_invalidated(key, generation) => return false,
                }
                if attempt + 1 < MAX_PUSH_ATTEMPTS {
                    tokio::select! {
                        () = tokio::time::sleep(PUSH_RETRY_DELAY) => {},
                        () = self.wait_until_push_invalidated(key, generation) => return false,
                    }
                }
            }
            if delivered {
                if !self.acknowledge_push_if_current(subscription, key, generation, &message.ack_id)
                {
                    return false;
                }
                continue;
            }
            if !self.nack_push_if_current(subscription, key, generation, &received[index..]) {
                return false;
            }
            tokio::select! {
                () = tokio::time::sleep(PUSH_RETRY_DELAY) => {},
                () = self.wait_until_push_invalidated(key, generation) => return false,
            }
            return true;
        }
        true
    }

    /// Cancels all dispatcher-owned push I/O and waits for every worker to finish.
    pub async fn shutdown_push_dispatcher(&self) {
        self.cancel_push_dispatcher();
        let task = {
            let mut lifecycle = self.push_dispatcher.lock().expect("push dispatcher lock");
            lifecycle.task.take()
        };
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    /// Signals dispatcher shutdown without waiting. Daemon and test owners should normally call
    /// [`Self::shutdown_push_dispatcher`] so the owned tasks are also joined.
    pub fn cancel_push_dispatcher(&self) {
        self.push_dispatcher
            .lock()
            .expect("push dispatcher lock")
            .stopped = true;
        {
            let mut dispatch = self.push_dispatch.lock().expect("push dispatch lock");
            dispatch.shutting_down = true;
            dispatch.invalidate_all();
        }
        self.push_cancel_notify.notify_waiters();
        self.push_ready_notify.notify_one();
    }
}

/// Serves the Pub/Sub gRPC surface on an already-bound loopback listener until it is closed.
///
/// The daemon binds the `TcpListener` to `127.0.0.1`; this function never binds a socket itself.
pub async fn serve_pubsub(
    listener: tokio::net::TcpListener,
    handle: PubSubHandle,
) -> Result<(), tonic::transport::Error> {
    handle.start_push_dispatcher();
    let _dispatcher_cancellation = PushDispatcherCancellationGuard(handle.clone());
    let publisher = PublisherServer::new(PublisherService::new(handle.clone()))
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);
    let subscriber = SubscriberServer::new(SubscriberService::new(handle.clone()))
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_MESSAGE_BYTES);
    let mut route_builder = tonic::service::Routes::builder();
    route_builder.add_service(publisher).add_service(subscriber);
    let routes = route_builder.routes();
    let rest_handle = handle.clone();
    let mut prepared_router = routes.into_axum_router().with_state(());
    prepared_router = prepared_router.fallback(move |request| {
        let handle = rest_handle.clone();
        async move { rest::handle(request, handle).await }
    });
    let result = tonic::transport::Server::builder()
        .accept_http1(true)
        .serve_with_incoming(
            prepared_router,
            tokio_stream::wrappers::TcpListenerStream::new(listener),
        )
        .await;
    handle.shutdown_push_dispatcher().await;
    result
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use fireemu_core_pubsub::{
        Filter, PubsubMessage, PushConfig, SubscriptionConfig, SubscriptionName, TopicName,
    };
    use fireemu_core_types::time::LogicalInstant;

    fn subscription(index: usize, topic: &TopicName) -> SubscriptionName {
        let name = SubscriptionName::new("demo-project", format!("push-{index:04}"))
            .expect("valid subscription name");
        let _ = topic;
        name
    }

    #[test]
    fn ready_queue_is_fifo_across_topics_after_worker_saturation() {
        let first_topic = TopicName::new("demo-project", "first").unwrap();
        let second_topic = TopicName::new("demo-project", "second").unwrap();
        let mut dispatch = PushDispatchState::default();
        for index in 0..MAX_PUSH_WORKERS {
            dispatch.enqueue(subscription(index, &first_topic));
        }
        let other_topic = subscription(MAX_PUSH_WORKERS, &second_topic);
        dispatch.enqueue(other_topic.clone());

        let claimed = (0..MAX_PUSH_WORKERS)
            .map(|_| dispatch.claim().expect("worker capacity remains"))
            .collect::<Vec<_>>();
        dispatch.complete(&claimed[0], true);

        assert_eq!(
            dispatch
                .claim()
                .expect("queued cross-topic work")
                .subscription,
            other_topic
        );
    }

    #[test]
    fn ready_queue_deduplicates_active_and_queued_admission() {
        let topic = TopicName::new("demo-project", "topic").unwrap();
        let subscription = subscription(0, &topic);
        let mut dispatch = PushDispatchState::default();
        dispatch.enqueue(subscription.clone());
        dispatch.enqueue(subscription.clone());
        let active = dispatch.claim().unwrap();
        dispatch.enqueue(subscription.clone());
        dispatch.enqueue(subscription);

        assert_eq!(dispatch.ready.len(), 1);
        dispatch.complete(&active, true);
        assert_eq!(dispatch.ready.len(), 1);
    }

    #[tokio::test]
    async fn an_empty_push_subscription_runs_one_worker_and_then_stays_idle() {
        let topic = TopicName::new("demo-project", "empty").unwrap();
        let subscription = SubscriptionName::new("demo-project", "empty-push").unwrap();
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        {
            let mut state = state.lock().unwrap();
            state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
            state
                .create_subscription(SubscriptionConfig {
                    name: subscription,
                    topic: topic.clone(),
                    ack_deadline_seconds: 10,
                    enable_message_ordering: false,
                    filter: Filter::always(),
                    dead_letter_policy: None,
                    retry_policy: None,
                    push_config: PushConfig {
                        push_endpoint: "http://127.0.0.1:1/push".to_owned(),
                    },
                })
                .unwrap();
        }
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let handle = PubSubHandle::new(state, clock, None);
        handle.start_push_dispatcher();
        handle.schedule_push(&topic);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let converged = {
                    let dispatch = handle.push_dispatch.lock().unwrap();
                    dispatch.spawned == 1 && dispatch.active.is_empty()
                };
                if converged {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("empty worker must converge");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        {
            let dispatch = handle.push_dispatch.lock().unwrap();
            assert_eq!(dispatch.spawned, 1);
            assert!(dispatch.active.is_empty());
            assert!(dispatch.ready.is_empty());
        }

        handle
            .state()
            .publish(
                &topic,
                vec![PubsubMessage {
                    data: b"wake".to_vec(),
                    ..PubsubMessage::default()
                }],
                LogicalInstant::UNIX_EPOCH,
            )
            .unwrap();
        handle.schedule_push(&topic);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if handle.push_dispatch.lock().unwrap().spawned >= 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a new publication restarts delivery");

        handle.shutdown_push_dispatcher().await;
    }

    #[test]
    fn a_stale_generation_cannot_ack_a_reused_ack_id_after_reset() {
        let topic = TopicName::new("demo-project", "reset-topic").unwrap();
        let subscription = SubscriptionName::new("demo-project", "reset-subscription").unwrap();
        let config = || SubscriptionConfig {
            name: subscription.clone(),
            topic: topic.clone(),
            ack_deadline_seconds: 10,
            enable_message_ordering: false,
            filter: Filter::always(),
            dead_letter_policy: None,
            retry_policy: None,
            push_config: PushConfig {
                push_endpoint: "http://127.0.0.1:1/push".to_owned(),
            },
        };
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let handle = PubSubHandle::new(state.clone(), clock, None);
        let publish_and_pull = |state: &mut PubSubState| {
            state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
            state.create_subscription(config()).unwrap();
            state
                .publish(
                    &topic,
                    vec![PubsubMessage {
                        data: b"message".to_vec(),
                        ..PubsubMessage::default()
                    }],
                    LogicalInstant::UNIX_EPOCH,
                )
                .unwrap();
            state
                .pull(&subscription, 1, LogicalInstant::UNIX_EPOCH)
                .unwrap()
                .pop()
                .unwrap()
        };

        let old_message = publish_and_pull(&mut state.lock().unwrap());
        let old_work = {
            let mut dispatch = handle.push_dispatch.lock().unwrap();
            dispatch.enqueue(subscription.clone());
            dispatch.claim().unwrap()
        };
        handle.invalidate_all_push_workers();
        *state.lock().unwrap() = PubSubState::new(42);
        let new_message = publish_and_pull(&mut state.lock().unwrap());
        assert_eq!(old_message.ack_id, new_message.ack_id);

        let new_work = {
            let mut dispatch = handle.push_dispatch.lock().unwrap();
            dispatch.enqueue(subscription.clone());
            dispatch.claim().unwrap()
        };
        assert_ne!(old_work.generation, new_work.generation);
        assert!(!handle.acknowledge_push_if_current(
            &subscription,
            &subscription.to_full(),
            old_work.generation,
            &old_message.ack_id,
        ));
        assert_eq!(
            state
                .lock()
                .unwrap()
                .acknowledge(&subscription, &[new_message.ack_id]),
            Ok(1)
        );
    }

    #[test]
    fn project_scoped_invalidation_replaces_only_owned_push_generations() {
        let first = SubscriptionName::new("project-a", "push-sub").unwrap();
        let second = SubscriptionName::new("project-b", "push-sub").unwrap();
        let mut dispatch = PushDispatchState::default();
        dispatch.enqueue(first.clone());
        dispatch.enqueue(second.clone());
        let old_first = dispatch.claim().unwrap();
        let old_second = dispatch.claim().unwrap();

        dispatch.invalidate_projects_where(|project| project == "project-a");
        dispatch.enqueue(first.clone());
        let new_first = dispatch.claim().unwrap();

        assert_ne!(old_first.generation, new_first.generation);
        assert_eq!(
            dispatch.generations.get(&second.to_full()),
            Some(&old_second.generation)
        );
        dispatch.complete(&old_first, false);
        assert_eq!(
            dispatch.active.get(&first.to_full()),
            Some(&new_first.generation)
        );
    }

    #[tokio::test]
    async fn shutdown_state_refuses_to_resurrect_the_dispatcher() {
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let handle = PubSubHandle::new(state, clock, None);

        handle.cancel_push_dispatcher();
        handle.start_push_dispatcher();

        {
            let lifecycle = handle.push_dispatcher.lock().unwrap();
            assert!(lifecycle.stopped);
            assert!(lifecycle.task.is_none());
        }
        handle.shutdown_push_dispatcher().await;
    }
}
