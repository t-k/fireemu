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

use fireemu_core_pubsub::{
    DeadLetterForward, PubSubError, PubSubState, PubsubMessage, ReceivedMessage, StoredMessage,
    SubscriptionName, TopicName,
};
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

#[derive(Debug, Clone, Copy)]
enum PushQuantumResult {
    Continue,
    Stop,
    Defer(LogicalInstant),
}

/// How one batch of push deliveries ended, which is what decides the subscription's backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PushAttemptOutcome {
    /// Every message in the batch was delivered and acknowledged.
    Delivered,
    /// A push request failed, so it and every message behind it were nacked.
    Failed,
    /// The subscription's push generation changed; this worker owns nothing any more.
    Invalidated,
}

/// The subscription-level push backoff: how many push attempts have failed in a row and the
/// instant push delivery may resume. It is separate from the per-message retry policy, which
/// schedules one message, and it throttles the whole subscription.
#[derive(Debug, Clone, Copy)]
struct PushBackoff {
    consecutive_failures: u32,
    resume_at: LogicalInstant,
}

/// When push delivery may resume after a failed attempt. The subscription-level push backoff and
/// whatever the retry policy scheduled for the next message are separate waits, so the later one
/// decides. A subscription with nothing left to deliver owes only its backoff.
fn push_resume_after_failure(
    backoff_resume_at: LogicalInstant,
    next_delivery_at: Option<LogicalInstant>,
) -> LogicalInstant {
    next_delivery_at.map_or(backoff_resume_at, |next| next.max(backoff_resume_at))
}

#[derive(Debug, Default)]
struct PushDispatchState {
    ready: VecDeque<PushWork>,
    deferred: BTreeMap<String, (PushWork, LogicalInstant)>,
    queued: BTreeSet<String>,
    active: BTreeMap<String, u64>,
    generations: BTreeMap<String, u64>,
    /// Push backoff per subscription. Absent means the subscription's last push attempt
    /// succeeded, or it has not attempted one yet.
    backoff: BTreeMap<String, PushBackoff>,
    next_generation: u64,
    spawned: u64,
    shutting_down: bool,
}

#[derive(Debug, Default)]
struct PushDispatcherLifecycle {
    task: Option<tokio::task::JoinHandle<()>>,
    stopped: bool,
}

#[derive(Debug, Default)]
struct DeadLetterDispatcherLifecycle {
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

    /// Makes a subscription's push work runnable, unless its push backoff is still in force. A
    /// new publication never shortens the backoff: while an endpoint is failing, every message on
    /// that subscription waits, exactly as the whole subscription is throttled in production.
    fn enqueue(
        &mut self,
        subscription: fireemu_core_pubsub::SubscriptionName,
        now: LogicalInstant,
    ) {
        if self.shutting_down {
            return;
        }
        let key = subscription.to_full();
        if let Some(resume_at) = self.backoff_resume_at(&key).filter(|resume| *resume > now) {
            if !self.queued.contains(&key) {
                let generation = self.generation_for(&key);
                self.deferred.insert(
                    key,
                    (
                        PushWork {
                            subscription,
                            generation,
                        },
                        resume_at,
                    ),
                );
            }
            return;
        }
        self.deferred.remove(&key);
        if self.queued.insert(key.clone()) {
            let generation = self.generation_for(&key);
            self.ready.push_back(PushWork {
                subscription,
                generation,
            });
        }
    }

    /// The instant a subscription's push delivery may resume, when a backoff is in force.
    fn backoff_resume_at(&self, key: &str) -> Option<LogicalInstant> {
        self.backoff.get(key).map(|backoff| backoff.resume_at)
    }

    /// Whether `generation` is still the incarnation this dispatcher serves for `key`. A worker
    /// that no longer owns its subscription must not touch any of its state.
    fn owns(&self, key: &str, generation: u64) -> bool {
        !self.shutting_down && self.generations.get(key).copied() == Some(generation)
    }

    /// Records one failed push attempt and returns the instant delivery may resume, or `None`
    /// when `generation` no longer owns the subscription. Consecutive failures lengthen the wait;
    /// the progression is [`push::push_backoff_after`].
    ///
    /// The ownership check and the update share this one borrow, which is the dispatch lock: a
    /// caller that checked first and updated afterwards would leave the window where the
    /// subscription is deleted and recreated in between.
    fn record_push_failure(
        &mut self,
        key: &str,
        generation: u64,
        now: LogicalInstant,
    ) -> Option<LogicalInstant> {
        if !self.owns(key, generation) {
            return None;
        }
        let consecutive_failures = self
            .backoff
            .get(key)
            .map_or(0, |backoff| backoff.consecutive_failures)
            .saturating_add(1);
        let resume_at = now
            .checked_add(push::push_backoff_after(consecutive_failures))
            .unwrap_or(LogicalInstant::MAX);
        self.backoff.insert(
            key.to_owned(),
            PushBackoff {
                consecutive_failures,
                resume_at,
            },
        );
        Some(resume_at)
    }

    /// Clears a subscription's push backoff after a successful delivery.
    /// Clears a subscription's push backoff after a delivery its endpoint accepted. Returns
    /// whether `generation` still owned the subscription; a stale worker changes nothing. The
    /// check and the removal share this borrow for the reason given on [`Self::record_push_failure`].
    fn clear_push_backoff(&mut self, key: &str, generation: u64) -> bool {
        if !self.owns(key, generation) {
            return false;
        }
        self.backoff.remove(key);
        true
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

    fn defer(&mut self, work: PushWork, eligible_at: LogicalInstant, now: LogicalInstant) {
        let key = work.subscription.to_full();
        if self.active.get(&key).copied() == Some(work.generation) {
            self.active.remove(&key);
        }
        if self.shutting_down || self.generations.get(&key).copied() != Some(work.generation) {
            return;
        }
        // A backoff counts only while it is still running. It is cleared by a successful delivery
        // or by invalidation, so an elapsed one can still be recorded here, and it must hold
        // nothing. `enqueue` and the delivery gate read it the same way.
        if let Some(resume_at) = self.backoff_resume_at(&key).filter(|resume| *resume > now) {
            // A live push backoff throttles the subscription itself. Work enqueued while the
            // failing attempt was in flight was admitted before the failure was known, so it
            // waits with the subscription instead of running at once.
            self.queued.remove(&key);
            self.ready
                .retain(|queued| queued.subscription.to_full() != key);
            self.deferred
                .insert(key, (work, eligible_at.max(resume_at)));
            return;
        }
        // No live backoff: a publication that arrived during the attempt is deliverable now, and
        // its queued work must not be turned back into a deferral.
        if self.queued.contains(&key) {
            return;
        }
        self.deferred.insert(key, (work, eligible_at));
    }

    fn promote_due(&mut self, now: LogicalInstant) {
        let due = self
            .deferred
            .iter()
            .filter(|(_, (_, eligible_at))| *eligible_at <= now)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in due {
            let Some((work, _)) = self.deferred.remove(&key) else {
                continue;
            };
            if self.generations.get(&key).copied() == Some(work.generation)
                && self.queued.insert(key)
            {
                self.ready.push_back(work);
            }
        }
    }

    fn invalidate(&mut self, key: &str) {
        self.generations.remove(key);
        self.deferred.remove(key);
        self.queued.remove(key);
        self.active.remove(key);
        self.backoff.remove(key);
        self.ready.retain(|work| work.subscription.to_full() != key);
    }

    fn invalidate_all(&mut self) {
        self.generations.clear();
        self.deferred.clear();
        self.queued.clear();
        self.ready.clear();
        self.active.clear();
        self.backoff.clear();
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

/// Why a topic-trigger admission failed before broker publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopicDeliveryError {
    /// The complete trigger fan-out would exceed the Functions retention bound.
    Capacity,
    /// The Functions runtime is shutting down or otherwise unavailable.
    Unavailable,
    /// A generated trigger event was invalid.
    InvalidEvent,
}

/// A reserved topic-trigger fan-out that becomes visible only after the broker publication is
/// committed.
pub trait TopicDeliveryReservation: Send {
    /// Commits every delivery admitted by the reservation.
    fn commit(self: Box<Self>);
}

/// Bridge to the Functions runtime: a message published on a topic is also delivered to any
/// Cloud Function subscribed to that topic (EVTINFRA-02). Admission is fallible and occurs before
/// the broker makes the publication visible.
pub trait TopicDelivery: Send + Sync {
    /// Reserves the complete topic-trigger fan-out for `messages` published on the canonical
    /// `projects/{project}/topics/{topic}` resource.
    fn reserve(
        &self,
        topic: &str,
        messages: &[BridgeMessage],
    ) -> Result<Box<dyn TopicDeliveryReservation>, TopicDeliveryError>;

    /// Returns a notification raised when a failed capacity admission may succeed again.
    /// Implementations should notify it after releasing a reservation; adapters without a
    /// recoverable capacity signal leave the retry driver disabled.
    fn recovery_notify(&self) -> Option<Arc<Notify>> {
        None
    }
}

/// The shared state a Pub/Sub adapter serves: the core registry, the virtual clock and the
/// optional Functions bridge.
#[derive(Clone)]
pub struct PubSubHandle {
    state: Arc<Mutex<PubSubState>>,
    clock: Arc<Mutex<VirtualClock>>,
    bridge: Option<Arc<dyn TopicDelivery>>,
    publication_gate: Arc<Mutex<()>>,
    dead_letter_gate: Arc<Mutex<()>>,
    push_dispatch: Arc<Mutex<PushDispatchState>>,
    push_dispatcher: Arc<Mutex<PushDispatcherLifecycle>>,
    dead_letter_dispatcher: Arc<Mutex<DeadLetterDispatcherLifecycle>>,
    push_ready_notify: Arc<Notify>,
    push_cancel_notify: Arc<Notify>,
    push_clock_notify: Arc<Notify>,
    dead_letter_cancel_notify: Arc<Notify>,
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
            publication_gate: Arc::new(Mutex::new(())),
            dead_letter_gate: Arc::new(Mutex::new(())),
            push_dispatch: Arc::new(Mutex::new(PushDispatchState::default())),
            push_dispatcher: Arc::new(Mutex::new(PushDispatcherLifecycle::default())),
            dead_letter_dispatcher: Arc::new(Mutex::new(DeadLetterDispatcherLifecycle::default())),
            push_ready_notify: Arc::new(Notify::new()),
            push_cancel_notify: Arc::new(Notify::new()),
            push_clock_notify: Arc::new(Notify::new()),
            dead_letter_cancel_notify: Arc::new(Notify::new()),
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

    /// Locks the publication coordinator. Reset and snapshot restore paths use this same lock so
    /// a Functions reservation cannot be invalidated between admission and commit.
    ///
    /// # Errors
    ///
    /// Returns the refusal when the gate is poisoned. A panic here would be the second one:
    /// the gate is held across the control-plane transitions that publish and reset Pub/Sub
    /// state, so panicking on a poisoned gate turns one earlier failure into a permanent one
    /// for every caller that needs it.
    pub fn lock_publication(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        self.publication_gate
            .lock()
            .map_err(|_| "the Pub/Sub publication gate is poisoned".to_owned())
    }

    /// Shares the publication coordinator with session reset and snapshot hooks.
    #[must_use]
    pub fn publication_gate(&self) -> Arc<Mutex<()>> {
        self.publication_gate.clone()
    }

    /// Wakes push workers after the shared virtual clock advances. The core state must be expired
    /// before this is called so a deadline-based redelivery is visible to the next pull.
    pub fn on_clock_changed(&self) {
        self.push_clock_notify.notify_waiters();
        self.push_ready_notify.notify_one();
    }

    fn start_dead_letter_dispatcher(&self) {
        let Some(recovery_notify) = self
            .bridge
            .as_ref()
            .and_then(|bridge| bridge.recovery_notify())
        else {
            return;
        };
        let mut lifecycle = self
            .dead_letter_dispatcher
            .lock()
            .expect("dead-letter dispatcher lock");
        if lifecycle.stopped || lifecycle.task.is_some() {
            return;
        }
        let handle = self.clone();
        lifecycle.task = Some(tokio::spawn(async move {
            handle.run_dead_letter_dispatcher(recovery_notify).await;
        }));
    }

    /// Serializes dead-letter snapshots with destination publication and source completion. The
    /// gate is acquired before the state and publication locks so a pull cannot race a retry with
    /// a stale `ForwardPending` snapshot.
    fn lock_dead_letter(&self) -> std::sync::MutexGuard<'_, ()> {
        self.dead_letter_gate
            .lock()
            .expect("Pub/Sub dead-letter lock")
    }

    fn topic_delivery_error(error: TopicDeliveryError) -> PubSubError {
        match error {
            TopicDeliveryError::Capacity => {
                PubSubError::resource_exhausted("Functions topic-trigger admission was exhausted")
            }
            TopicDeliveryError::Unavailable => {
                PubSubError::failed_precondition("Functions topic-trigger runtime is unavailable")
            }
            TopicDeliveryError::InvalidEvent => {
                PubSubError::invalid_argument("Functions topic-trigger event is invalid")
            }
        }
    }

    /// Prepares and commits one publication through the broker and every configured topic
    /// delivery bridge. A bridge reservation is dropped automatically when broker admission
    /// fails, so neither side can observe a partial publication.
    fn publish_locked(
        &self,
        topic: &TopicName,
        messages: Vec<PubsubMessage>,
    ) -> Result<Vec<Arc<StoredMessage>>, PubSubError> {
        let now = self.now();
        let mut state = self.state();
        let prepared = state.prepare_publish(topic, messages, now)?;
        let bridge_reservation = self
            .bridge
            .as_ref()
            .map(|bridge| {
                let bridge_messages = prepared
                    .published_messages()
                    .iter()
                    .cloned()
                    .map(|message| BridgeMessage { message })
                    .collect::<Vec<_>>();
                bridge
                    .reserve(&topic.to_full(), &bridge_messages)
                    .map_err(Self::topic_delivery_error)
            })
            .transpose()?;
        let published = state.commit_prepared(prepared, now)?;
        drop(state);
        if let Some(reservation) = bridge_reservation {
            reservation.commit();
        }
        self.schedule_push(topic);
        Ok(published)
    }

    /// Publishes a batch through broker admission and every configured topic delivery bridge.
    /// The broker is unchanged when a bridge refuses the complete fan-out.
    pub fn publish(
        &self,
        topic: &TopicName,
        messages: Vec<PubsubMessage>,
    ) -> Result<Vec<Arc<StoredMessage>>, PubSubError> {
        let _publication = self.lock_publication();
        self.publish_locked(topic, messages)
    }

    /// Pulls from the broker and routes exhausted messages through the same publication
    /// coordinator used by ordinary publishes. A destination admission failure leaves the source
    /// message pending for a later retry, while the source pull response remains successful.
    pub fn pull(
        &self,
        subscription: &SubscriptionName,
        max: usize,
    ) -> Result<Vec<ReceivedMessage>, PubSubError> {
        let _dead_letter = self.lock_dead_letter();
        let now = self.now();
        let outcome = {
            let mut state = self.state();
            state.pull_with_dead_letters(subscription, max, now)?
        };
        self.commit_dead_letters_locked(&outcome.dead_lettered);
        Ok(outcome.received)
    }

    fn commit_dead_letter(&self, forward: &DeadLetterForward) {
        let _publication = self.lock_publication();
        let published = self.publish_locked(
            &forward.dead_letter_topic,
            vec![forward.message.message.clone()],
        );
        if published.is_ok() {
            let mut state = self.state();
            let _ = state
                .complete_dead_letter(&forward.source_subscription, &forward.message.message_id);
        }
    }

    fn commit_dead_letters_locked(&self, forwards: &[DeadLetterForward]) {
        for forward in forwards {
            self.commit_dead_letter(forward);
        }
    }

    fn dead_letter_dispatcher_stopped(&self) -> bool {
        self.dead_letter_dispatcher
            .lock()
            .expect("dead-letter dispatcher lock")
            .stopped
    }

    fn has_pending_dead_letters(&self) -> bool {
        !self.state().pending_dead_letters().is_empty()
    }

    async fn run_dead_letter_dispatcher(&self, recovery_notify: Arc<Notify>) {
        loop {
            let notified = recovery_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let cancelled = self.dead_letter_cancel_notify.notified();
            tokio::pin!(cancelled);
            cancelled.as_mut().enable();
            if self.dead_letter_dispatcher_stopped() {
                return;
            }
            if self.has_pending_dead_letters() {
                self.retry_pending_dead_letters();
            }
            tokio::select! {
                () = &mut notified => {},
                () = &mut cancelled => return,
            }
        }
    }

    /// Retries dead-letter transfers that were retained after a destination admission failure.
    /// Callers invoke this after an acknowledgement or another operation that may reclaim
    /// destination retention capacity.
    pub(crate) fn retry_pending_dead_letters(&self) {
        let _dead_letter = self.lock_dead_letter();
        let pending = self.state().pending_dead_letters();
        self.commit_dead_letters_locked(&pending);
    }

    /// Seeks a subscription to a point in time.
    ///
    /// The seek is serialized with dead-letter forwarding: a transfer that has already published
    /// to the destination completes its source before the seek rewrites the delivery states, so a
    /// replay cannot duplicate a committed transfer. A seek also republishes the resulting backlog
    /// to an idle push subscriber, which would otherwise wait for an unrelated operation.
    pub fn seek_to_time(
        &self,
        subscription: &SubscriptionName,
        time: LogicalInstant,
    ) -> Result<(), PubSubError> {
        let now = self.now();
        self.seek_locked(subscription, |state| {
            state.seek_to_time(subscription, time, now)
        })
    }

    /// Seeks a subscription to a snapshot. See [`PubSubHandle::seek_to_time`] for the ordering
    /// guarantees this shares with dead-letter forwarding and push delivery.
    pub fn seek_to_snapshot(
        &self,
        subscription: &SubscriptionName,
        snapshot: &str,
    ) -> Result<(), PubSubError> {
        let now = self.now();
        self.seek_locked(subscription, |state| {
            state.seek_to_snapshot(subscription, snapshot, now)
        })
    }

    fn seek_locked(
        &self,
        subscription: &SubscriptionName,
        seek: impl FnOnce(&mut PubSubState) -> Result<(), PubSubError>,
    ) -> Result<(), PubSubError> {
        let topic = {
            let _dead_letter = self.lock_dead_letter();
            let mut state = self.state();
            seek(&mut state)?;
            state.subscription_config(subscription)?.topic.clone()
        };
        self.schedule_push(&topic);
        Ok(())
    }

    pub(crate) fn acknowledge(
        &self,
        subscription: &SubscriptionName,
        ack_ids: &[String],
    ) -> Result<usize, PubSubError> {
        let result = {
            let mut state = self.state();
            state.acknowledge(subscription, ack_ids)
        };
        if result.is_ok() {
            self.retry_pending_dead_letters();
        }
        result
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
        let now = self.now();
        let mut dispatch = self.push_dispatch.lock().expect("push dispatch lock");
        for (subscription, _) in subscriptions {
            dispatch.enqueue(subscription, now);
        }
        drop(dispatch);
        self.push_ready_notify.notify_one();
    }

    fn next_push_delivery_at(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
    ) -> Option<LogicalInstant> {
        self.state().next_delivery_at(subscription).ok().flatten()
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
            let clock_notified = self.push_clock_notify.notified();
            tokio::pin!(clock_notified);
            let shutting_down = self
                .push_dispatch
                .lock()
                .expect("push dispatch lock")
                .shutting_down;
            self.push_dispatch
                .lock()
                .expect("push dispatch lock")
                .promote_due(self.now());
            if shutting_down {
                workers.abort_all();
                while workers.join_next().await.is_some() {}
                let mut dispatch = self.push_dispatch.lock().expect("push dispatch lock");
                dispatch.active.clear();
                dispatch.deferred.clear();
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
                    let result = handle.run_push_quantum(&work).await;
                    (task_id, work, result)
                });
                work_by_task.insert(task.id(), fallback);
            }
            if workers.is_empty() {
                tokio::select! {
                    () = notified => {},
                    () = &mut clock_notified => {},
                }
                continue;
            }
            tokio::select! {
                () = notified => {},
                () = &mut clock_notified => {},
                completed = workers.join_next() => {
                    match completed {
                        Some(Ok((task_id, work, result))) => {
                            work_by_task.remove(&task_id);
                            // Read the clock before the dispatch lock, as every other caller does.
                            let now = self.now();
                            let mut dispatch =
                                self.push_dispatch.lock().expect("push dispatch lock");
                            match result {
                                PushQuantumResult::Continue => dispatch.complete(&work, true),
                                PushQuantumResult::Stop => dispatch.complete(&work, false),
                                PushQuantumResult::Defer(eligible_at) => {
                                    dispatch.defer(work, eligible_at, now);
                                }
                            }
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

    async fn run_push_quantum(&self, work: &PushWork) -> PushQuantumResult {
        let key = work.subscription.to_full();
        if !self.is_current_push_generation(&key, work.generation) {
            return PushQuantumResult::Stop;
        }
        // The gate every delivering path passes: while the subscription owes a push backoff, no
        // request reaches its endpoint, however the work came to be claimed.
        let now = self.now();
        if let Some(resume_at) = self
            .push_backoff_for_key(&key)
            .filter(|resume| *resume > now)
        {
            return PushQuantumResult::Defer(push_resume_after_failure(
                resume_at,
                self.next_push_delivery_at(&work.subscription),
            ));
        }
        let received = self.pull(&work.subscription, 100).unwrap_or_default();
        if received.is_empty() {
            // Nothing is deliverable yet. The retry policy schedules the next message; whether it
            // or an elapsing backoff decides, the subscription is looked at again then.
            return match self.next_push_delivery_at(&work.subscription) {
                Some(next) if next > now => PushQuantumResult::Defer(next),
                Some(_) => PushQuantumResult::Continue,
                None => PushQuantumResult::Stop,
            };
        }
        match self
            .deliver_push_messages(&work.subscription, &key, work.generation, received)
            .await
        {
            // The backoff belongs to the incarnation that delivered, not to the name. The
            // subscription may have been deleted and recreated while the endpoint was being
            // awaited, and then this worker owns nothing and stops without touching it.
            PushAttemptOutcome::Delivered => {
                if self.clear_push_backoff(&key, work.generation) {
                    PushQuantumResult::Continue
                } else {
                    PushQuantumResult::Stop
                }
            }
            // The endpoint failed, so the subscription owes its push backoff before the next
            // attempt. The retry policy may ask for longer, and then it decides.
            PushAttemptOutcome::Failed => match self.record_push_failure(&key, work.generation) {
                Some(resume_at) => PushQuantumResult::Defer(push_resume_after_failure(
                    resume_at,
                    self.next_push_delivery_at(&work.subscription),
                )),
                None => PushQuantumResult::Stop,
            },
            PushAttemptOutcome::Invalidated => PushQuantumResult::Stop,
        }
    }

    /// The instant this subscription's push delivery may resume, when a backoff is in force.
    fn push_backoff_for_key(&self, key: &str) -> Option<LogicalInstant> {
        self.push_dispatch
            .lock()
            .expect("push dispatch lock")
            .backoff_resume_at(key)
    }

    /// The instant push delivery may resume on a subscription its push backoff is holding, or
    /// `None` when its endpoint is not failing. Push delivery throttles the whole subscription
    /// after a failed attempt, independently of any per-message retry policy, so this is the
    /// observable state of that throttle.
    #[must_use]
    pub fn push_backoff_resume_at(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
    ) -> Option<LogicalInstant> {
        self.push_backoff_for_key(&subscription.to_full())
    }

    /// Records a failed push attempt on the virtual clock and returns when delivery may resume,
    /// or `None` when the delivering incarnation is no longer the current one.
    fn record_push_failure(&self, key: &str, generation: u64) -> Option<LogicalInstant> {
        let now = self.now();
        self.push_dispatch
            .lock()
            .expect("push dispatch lock")
            .record_push_failure(key, generation, now)
    }

    /// Releases a subscription's push backoff after a delivery the endpoint accepted. Returns
    /// whether the delivering incarnation still owned the subscription.
    fn clear_push_backoff(&self, key: &str, generation: u64) -> bool {
        self.push_dispatch
            .lock()
            .expect("push dispatch lock")
            .clear_push_backoff(key, generation)
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

    /// Returns the current push endpoint and whether the subscription has a dead-letter policy,
    /// which decides whether the payload reports the delivery attempt.
    fn push_endpoint_if_current(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
        key: &str,
        generation: u64,
    ) -> Option<(String, bool)> {
        let dispatch = self.push_dispatch.lock().expect("push dispatch lock");
        if dispatch.shutting_down || dispatch.generations.get(key).copied() != Some(generation) {
            return None;
        }
        self.state()
            .subscription_config(subscription)
            .ok()
            .filter(|config| config.is_push())
            .map(|config| {
                (
                    config.push_config.push_endpoint.clone(),
                    config.dead_letter_policy.is_some(),
                )
            })
    }

    fn acknowledge_push_if_current(
        &self,
        subscription: &fireemu_core_pubsub::SubscriptionName,
        key: &str,
        generation: u64,
        ack_id: &str,
    ) -> bool {
        {
            let dispatch = self.push_dispatch.lock().expect("push dispatch lock");
            if dispatch.shutting_down || dispatch.generations.get(key).copied() != Some(generation)
            {
                return false;
            }
        }
        self.acknowledge(subscription, &[ack_id.to_owned()]).is_ok()
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
    ) -> PushAttemptOutcome {
        for (index, message) in received.iter().enumerate() {
            if !self.is_current_push_generation(key, generation) {
                return PushAttemptOutcome::Invalidated;
            }
            // One request per delivery attempt: a failed push is nacked rather than retried inside
            // the worker, so the attempt the endpoint sees, the attempt the retry policy schedules
            // and the attempt the dead-letter budget counts are the same attempt.
            let Some((endpoint, report_delivery_attempt)) =
                self.push_endpoint_if_current(subscription, key, generation)
            else {
                return PushAttemptOutcome::Invalidated;
            };
            let delivered = tokio::select! {
                result = push::deliver(&endpoint, subscription, message, report_delivery_attempt) => {
                    result.is_ok()
                }
                () = self.wait_until_push_invalidated(key, generation) => {
                    return PushAttemptOutcome::Invalidated;
                }
            };
            if delivered {
                if !self.acknowledge_push_if_current(subscription, key, generation, &message.ack_id)
                {
                    return PushAttemptOutcome::Invalidated;
                }
                continue;
            }
            if !self.nack_push_if_current(subscription, key, generation, &received[index..]) {
                return PushAttemptOutcome::Invalidated;
            }
            // A batch that fails part-way through is a failed attempt: the endpoint is refusing
            // work, which is what the subscription-level backoff answers.
            return PushAttemptOutcome::Failed;
        }
        PushAttemptOutcome::Delivered
    }

    /// Cancels all dispatcher-owned push I/O and waits for every worker to finish.
    pub async fn shutdown_push_dispatcher(&self) {
        self.cancel_push_dispatcher();
        let push_task = {
            let mut lifecycle = self.push_dispatcher.lock().expect("push dispatcher lock");
            lifecycle.task.take()
        };
        let dead_letter_task = {
            let mut lifecycle = self
                .dead_letter_dispatcher
                .lock()
                .expect("dead-letter dispatcher lock");
            lifecycle.task.take()
        };
        if let Some(task) = push_task {
            let _ = task.await;
        }
        if let Some(task) = dead_letter_task {
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
        self.dead_letter_dispatcher
            .lock()
            .expect("dead-letter dispatcher lock")
            .stopped = true;
        self.push_cancel_notify.notify_waiters();
        self.push_ready_notify.notify_one();
        self.dead_letter_cancel_notify.notify_waiters();
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
    handle.start_dead_letter_dispatcher();
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
        subscription::{
            DeadLetterPolicy, RetryPolicy, DEFAULT_ACK_DEADLINE_SECONDS, MIN_DEAD_LETTER_ATTEMPTS,
        },
        Filter, PubsubMessage, PushConfig, SubscriptionConfig, SubscriptionName, TopicName,
    };
    use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    /// The virtual instant the dispatch-queue tests enqueue at. These tests exercise the queue,
    /// not the push backoff, so any instant serves as long as it is the same one throughout.
    const TEST_NOW: LogicalInstant = LogicalInstant::UNIX_EPOCH;

    struct BlockingDeadLetterDelivery {
        destination: String,
        block_first_commit: Arc<AtomicBool>,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
        destination_commits: Arc<AtomicUsize>,
    }

    struct BlockingDeadLetterReservation {
        block_commit: bool,
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
        destination_commits: Arc<AtomicUsize>,
    }

    impl TopicDelivery for BlockingDeadLetterDelivery {
        fn reserve(
            &self,
            topic: &str,
            _messages: &[BridgeMessage],
        ) -> Result<Box<dyn TopicDeliveryReservation>, TopicDeliveryError> {
            let block_commit = topic == self.destination
                && self
                    .block_first_commit
                    .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
            Ok(Box::new(BlockingDeadLetterReservation {
                block_commit,
                entered: self.entered.clone(),
                release: self.release.clone(),
                destination_commits: self.destination_commits.clone(),
            }))
        }
    }

    impl TopicDeliveryReservation for BlockingDeadLetterReservation {
        fn commit(self: Box<Self>) {
            if self.block_commit {
                self.entered.wait();
                self.release.wait();
            }
            self.destination_commits.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn subscription(index: usize, topic: &TopicName) -> SubscriptionName {
        let name = SubscriptionName::new("demo-project", format!("push-{index:04}"))
            .expect("valid subscription name");
        let _ = topic;
        name
    }

    /// Records a failed attempt the way the dispatcher does, for the incarnation the dispatcher
    /// currently serves, registering one when the subscription has none yet.
    fn record_failure_for_current(
        dispatch: &mut PushDispatchState,
        name: &SubscriptionName,
        now: LogicalInstant,
    ) -> LogicalInstant {
        let key = name.to_full();
        let generation = dispatch.generation_for(&key);
        dispatch
            .record_push_failure(&key, generation, now)
            .expect("the current incarnation records its own failure")
    }

    /// The push backoff doubles from the documented minimum and stops at the documented maximum.
    /// The curve between the two bounds is this emulator's choice; the bounds are production's.
    #[test]
    fn the_push_backoff_doubles_from_the_minimum_and_clamps_at_the_maximum() {
        assert_eq!(push::push_backoff_after(0), LogicalDuration::ZERO);
        for (failures, millis) in [
            (1_u32, 100_i64),
            (2, 200),
            (3, 400),
            (4, 800),
            (5, 1_600),
            (6, 3_200),
            (7, 6_400),
            (8, 12_800),
            (9, 25_600),
            (10, 51_200),
        ] {
            assert_eq!(
                push::push_backoff_after(failures),
                LogicalDuration::from_millis(millis),
                "{failures} consecutive failures"
            );
        }
        // The eleventh doubling would pass the ceiling, so every later failure owes the ceiling.
        for failures in [11_u32, 12, 64, u32::MAX] {
            assert_eq!(
                push::push_backoff_after(failures),
                LogicalDuration::from_millis(push::PUSH_BACKOFF_MAXIMUM_MILLIS),
                "{failures} consecutive failures"
            );
        }
        assert_eq!(
            push::push_backoff_after(1),
            LogicalDuration::from_millis(push::PUSH_BACKOFF_MINIMUM_MILLIS)
        );
    }

    /// The wait a failed attempt owes composes the two mechanisms at the failure point itself,
    /// rather than leaving the longer of the two to be discovered by a later empty pull.
    #[test]
    fn the_wait_after_a_failure_is_the_later_of_the_backoff_and_the_retry_policy() {
        let backoff = TEST_NOW
            .checked_add(LogicalDuration::from_millis(100))
            .unwrap();
        let retry_is_longer = TEST_NOW
            .checked_add(LogicalDuration::from_seconds(30))
            .unwrap();
        let retry_is_shorter = TEST_NOW
            .checked_add(LogicalDuration::from_millis(10))
            .unwrap();

        assert_eq!(
            push_resume_after_failure(backoff, Some(retry_is_longer)),
            retry_is_longer,
            "a retry policy longer than the backoff decides"
        );
        assert_eq!(
            push_resume_after_failure(backoff, Some(retry_is_shorter)),
            backoff,
            "a retry policy shorter than the backoff never shortens it"
        );
        assert_eq!(
            push_resume_after_failure(backoff, Some(backoff)),
            backoff,
            "equal waits leave one instant"
        );
        assert_eq!(
            push_resume_after_failure(backoff, None),
            backoff,
            "a subscription with nothing left to deliver owes only its backoff"
        );
    }

    /// Consecutive failures lengthen one subscription's wait, and a delivery the endpoint accepts
    /// puts it back to the minimum.
    #[test]
    fn recording_push_failures_lengthens_the_wait_until_a_success_clears_it() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let name = subscription(0, &topic);
        let key = name.to_full();
        let mut dispatch = PushDispatchState::default();
        assert_eq!(dispatch.backoff_resume_at(&key), None);

        for failures in 1..=3_u32 {
            let resume_at = record_failure_for_current(&mut dispatch, &name, TEST_NOW);
            assert_eq!(
                resume_at,
                TEST_NOW
                    .checked_add(push::push_backoff_after(failures))
                    .unwrap()
            );
            assert_eq!(dispatch.backoff_resume_at(&key), Some(resume_at));
        }

        let generation = dispatch.generation_for(&key);
        assert!(dispatch.clear_push_backoff(&key, generation));
        assert_eq!(dispatch.backoff_resume_at(&key), None);
        assert_eq!(
            record_failure_for_current(&mut dispatch, &name, TEST_NOW),
            TEST_NOW.checked_add(push::push_backoff_after(1)).unwrap(),
            "a success must reset the streak, not merely pause it"
        );
    }

    /// A worker delivers for one incarnation of a subscription. If that incarnation is deleted
    /// and a new one takes its name, the old worker's outcome must not reach the new one's
    /// backoff: a stale success would release a throttle the new incarnation just earned.
    #[test]
    fn a_stale_success_does_not_clear_the_backoff_of_a_recreated_subscription() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let name = subscription(0, &topic);
        let key = name.to_full();
        let mut dispatch = PushDispatchState::default();

        dispatch.enqueue(name.clone(), TEST_NOW);
        let first = dispatch.claim().expect("the first incarnation is claimed");

        // The subscription is deleted and recreated while that worker is still delivering.
        dispatch.invalidate(&key);
        dispatch.enqueue(name.clone(), TEST_NOW);
        let second = dispatch.claim().expect("the new incarnation is claimed");
        assert_ne!(first.generation, second.generation);
        let resume_at = dispatch.record_push_failure(&key, second.generation, TEST_NOW);
        assert!(resume_at.is_some(), "the new incarnation earned a backoff");

        // The stale worker's delivery completes only now.
        assert!(
            !dispatch.clear_push_backoff(&key, first.generation),
            "a stale worker owns nothing"
        );
        assert_eq!(
            dispatch.backoff_resume_at(&key),
            resume_at,
            "the new incarnation keeps the backoff it earned"
        );
    }

    /// The other direction: a stale failure must not throttle a healthy new incarnation.
    #[test]
    fn a_stale_failure_does_not_back_off_a_recreated_subscription() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let name = subscription(0, &topic);
        let key = name.to_full();
        let mut dispatch = PushDispatchState::default();

        dispatch.enqueue(name.clone(), TEST_NOW);
        let first = dispatch.claim().expect("the first incarnation is claimed");
        dispatch.invalidate(&key);
        dispatch.enqueue(name.clone(), TEST_NOW);
        let second = dispatch.claim().expect("the new incarnation is claimed");
        assert_ne!(first.generation, second.generation);

        assert_eq!(
            dispatch.record_push_failure(&key, first.generation, TEST_NOW),
            None,
            "a stale worker owns nothing"
        );
        assert_eq!(
            dispatch.backoff_resume_at(&key),
            None,
            "the healthy new incarnation must not inherit a throttle"
        );
    }

    /// The controls: the worker that owns the current incarnation does update the backoff.
    #[test]
    fn the_current_incarnation_clears_and_extends_its_own_backoff() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let name = subscription(0, &topic);
        let key = name.to_full();
        let mut dispatch = PushDispatchState::default();
        dispatch.enqueue(name, TEST_NOW);
        let work = dispatch.claim().expect("the incarnation is claimed");

        let first = dispatch
            .record_push_failure(&key, work.generation, TEST_NOW)
            .expect("the owner records its failure");
        let second = dispatch
            .record_push_failure(&key, work.generation, TEST_NOW)
            .expect("the owner records its second failure");
        assert!(second > first, "consecutive failures extend the wait");

        assert!(
            dispatch.clear_push_backoff(&key, work.generation),
            "the owner clears its own backoff"
        );
        assert_eq!(dispatch.backoff_resume_at(&key), None);
    }

    /// A failing subscription's backoff never reaches another subscription's queue.
    #[test]
    fn a_push_backoff_holds_only_its_own_subscription() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let failing = subscription(0, &topic);
        let healthy = subscription(1, &topic);
        let mut dispatch = PushDispatchState::default();
        let resume_at = record_failure_for_current(&mut dispatch, &failing, TEST_NOW);

        dispatch.enqueue(failing.clone(), TEST_NOW);
        dispatch.enqueue(healthy.clone(), TEST_NOW);

        // The healthy subscription is the only claimable work.
        let claimed = dispatch.claim().expect("the healthy subscription is ready");
        assert_eq!(claimed.subscription.to_full(), healthy.to_full());
        assert!(dispatch.claim().is_none());
        assert_eq!(
            dispatch.deferred.get(&failing.to_full()).map(|(_, at)| *at),
            Some(resume_at)
        );

        // It becomes claimable again only once the clock reaches the backoff.
        dispatch.promote_due(resume_at);
        let claimed = dispatch.claim().expect("the backoff has elapsed");
        assert_eq!(claimed.subscription.to_full(), failing.to_full());
    }

    /// A new publication must not shorten a backoff: it is the subscription that is throttled.
    #[test]
    fn a_new_publication_does_not_shorten_an_active_push_backoff() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let name = subscription(0, &topic);
        let key = name.to_full();
        let mut dispatch = PushDispatchState::default();
        let resume_at = record_failure_for_current(&mut dispatch, &name, TEST_NOW);

        for _ in 0..3 {
            dispatch.enqueue(name.clone(), TEST_NOW);
        }
        assert!(dispatch.claim().is_none(), "the subscription stays held");
        assert_eq!(
            dispatch.deferred.get(&key).map(|(_, at)| *at),
            Some(resume_at),
            "republishing must not move the backoff"
        );
    }

    /// A publication that arrives while a failing attempt is still in flight must not cancel the
    /// backoff that attempt is about to record. The enqueue happens before the failure is known,
    /// so the deferral has to win over the work it queued.
    #[test]
    fn a_publication_during_a_failing_attempt_does_not_reopen_the_immediate_loop() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let name = subscription(0, &topic);
        let key = name.to_full();
        let mut dispatch = PushDispatchState::default();

        dispatch.enqueue(name.clone(), TEST_NOW);
        let work = dispatch.claim().expect("the worker claims the work");
        // The endpoint is still being awaited, so no failure is recorded yet.
        dispatch.enqueue(name.clone(), TEST_NOW);
        let resume_at = dispatch
            .record_push_failure(&key, work.generation, TEST_NOW)
            .expect("the delivering incarnation records its failure");
        dispatch.defer(work, resume_at, TEST_NOW);

        assert!(
            dispatch.claim().is_none(),
            "the subscription owes a backoff until {resume_at}, so nothing may be claimable yet"
        );
        dispatch.promote_due(resume_at);
        assert!(
            dispatch.claim().is_some(),
            "the work returns once the backoff elapses"
        );
    }

    /// A backoff that has already elapsed must not hold anything. It is cleared only by a
    /// successful delivery or by invalidation, so an expired one can still be recorded when an
    /// unrelated retry-policy deferral arrives: that deferral must not withdraw work a
    /// publication made deliverable now and fold it into the retry instant.
    #[test]
    fn an_elapsed_backoff_does_not_fold_a_mid_attempt_publication_into_a_retry_deferral() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let name = subscription(0, &topic);
        let key = name.to_full();
        let mut dispatch = PushDispatchState::default();

        let resume_at = record_failure_for_current(&mut dispatch, &name, TEST_NOW);
        let now = resume_at
            .checked_add(LogicalDuration::from_millis(1))
            .unwrap();
        assert!(
            dispatch.backoff_resume_at(&key).is_some(),
            "the streak is still recorded after it elapses"
        );

        dispatch.enqueue(name.clone(), now);
        let work = dispatch.claim().expect("the worker claims the work");
        // A publication lands while the worker holds the key.
        dispatch.enqueue(name.clone(), now);
        // The worker found nothing deliverable and defers to what the retry policy scheduled.
        let retry_at = now.checked_add(LogicalDuration::from_seconds(30)).unwrap();
        dispatch.defer(work, retry_at, now);

        assert!(
            dispatch.claim().is_some(),
            "the elapsed backoff holds nothing, so the publication is deliverable now"
        );
    }

    /// Invalidating a subscription drops its backoff with the rest of its dispatch state, so a
    /// recreated subscription starts clean.
    #[test]
    fn invalidating_a_subscription_clears_its_push_backoff() {
        let topic = TopicName::new("demo-project", "backoff").unwrap();
        let name = subscription(0, &topic);
        let key = name.to_full();
        let mut dispatch = PushDispatchState::default();
        record_failure_for_current(&mut dispatch, &name, TEST_NOW);
        dispatch.enqueue(name.clone(), TEST_NOW);

        dispatch.invalidate(&key);
        assert_eq!(dispatch.backoff_resume_at(&key), None);

        dispatch.enqueue(name.clone(), TEST_NOW);
        assert!(dispatch.claim().is_some(), "a clean subscription is ready");

        record_failure_for_current(&mut dispatch, &name, TEST_NOW);
        dispatch.invalidate_all();
        assert_eq!(dispatch.backoff_resume_at(&key), None);
    }

    #[test]
    fn ready_queue_is_fifo_across_topics_after_worker_saturation() {
        let first_topic = TopicName::new("demo-project", "first").unwrap();
        let second_topic = TopicName::new("demo-project", "second").unwrap();
        let mut dispatch = PushDispatchState::default();
        for index in 0..MAX_PUSH_WORKERS {
            dispatch.enqueue(subscription(index, &first_topic), TEST_NOW);
        }
        let other_topic = subscription(MAX_PUSH_WORKERS, &second_topic);
        dispatch.enqueue(other_topic.clone(), TEST_NOW);

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
        dispatch.enqueue(subscription.clone(), TEST_NOW);
        dispatch.enqueue(subscription.clone(), TEST_NOW);
        let active = dispatch.claim().unwrap();
        dispatch.enqueue(subscription.clone(), TEST_NOW);
        dispatch.enqueue(subscription, TEST_NOW);

        assert_eq!(dispatch.ready.len(), 1);
        dispatch.complete(&active, true);
        assert_eq!(dispatch.ready.len(), 1);
    }

    #[test]
    fn deferred_push_work_is_released_by_time_or_new_publication() {
        let topic = TopicName::new("demo-project", "topic").unwrap();
        let first = subscription(0, &topic);
        let second = subscription(1, &topic);
        let now = LogicalInstant::from_unix_seconds(100);
        let mut dispatch = PushDispatchState::default();
        dispatch.enqueue(first.clone(), TEST_NOW);
        let first_work = dispatch.claim().unwrap();
        dispatch.defer(
            first_work,
            now.checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(10))
                .unwrap(),
            now,
        );
        assert!(dispatch.active.is_empty());
        assert!(dispatch.ready.is_empty());
        assert!(dispatch.deferred.contains_key(&first.to_full()));

        dispatch.enqueue(first.clone(), TEST_NOW);
        assert!(dispatch.deferred.is_empty());
        assert_eq!(dispatch.ready.len(), 1);
        let second_work = {
            dispatch.enqueue(second.clone(), TEST_NOW);
            dispatch.claim().unwrap()
        };
        dispatch.invalidate(&second.to_full());
        assert!(!dispatch.deferred.contains_key(&second.to_full()));
        dispatch.complete(&second_work, false);
    }

    #[test]
    fn unrelated_invalidation_does_not_remove_deferred_push_work() {
        let first_topic = TopicName::new("demo-project", "first").unwrap();
        let second_topic = TopicName::new("demo-project", "second").unwrap();
        let first = subscription(0, &first_topic);
        let second = subscription(1, &second_topic);
        let now = LogicalInstant::from_unix_seconds(100);
        let mut dispatch = PushDispatchState::default();
        dispatch.enqueue(first.clone(), TEST_NOW);
        dispatch.enqueue(second.clone(), TEST_NOW);
        let first_work = dispatch.claim().unwrap();
        let second_work = dispatch.claim().unwrap();
        dispatch.defer(
            first_work,
            now.checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(10))
                .unwrap(),
            now,
        );
        dispatch.invalidate(&second.to_full());

        assert!(dispatch.deferred.contains_key(&first.to_full()));
        dispatch.promote_due(
            now.checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(10))
                .unwrap(),
        );
        assert_eq!(dispatch.claim().unwrap().subscription, first);
        dispatch.complete(&second_work, false);
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

    #[tokio::test]
    async fn ordered_backoff_enters_one_deferred_quantum_until_the_predecessor_is_ready() {
        let topic = TopicName::new("demo-project", "ordered-backoff").unwrap();
        let subscription =
            SubscriptionName::new("demo-project", "ordered-backoff-subscription").unwrap();
        let now = LogicalInstant::UNIX_EPOCH;
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        {
            let mut state = state.lock().unwrap();
            state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
            state
                .create_subscription(SubscriptionConfig {
                    name: subscription.clone(),
                    topic: topic.clone(),
                    ack_deadline_seconds: 10,
                    enable_message_ordering: true,
                    filter: Filter::always(),
                    dead_letter_policy: None,
                    retry_policy: Some(RetryPolicy {
                        minimum_backoff: LogicalDuration::from_seconds(10),
                        maximum_backoff: LogicalDuration::from_seconds(10),
                    }),
                    push_config: PushConfig {
                        push_endpoint: "http://127.0.0.1:1/push".to_owned(),
                    },
                })
                .unwrap();
            state
                .publish(
                    &topic,
                    vec![
                        PubsubMessage {
                            data: b"first".to_vec(),
                            ordering_key: "key".to_owned(),
                            ..PubsubMessage::default()
                        },
                        PubsubMessage {
                            data: b"second".to_vec(),
                            ordering_key: "key".to_owned(),
                            ..PubsubMessage::default()
                        },
                    ],
                    now,
                )
                .unwrap();
            let first = state.pull(&subscription, 1, now).unwrap();
            state
                .modify_ack_deadline(&subscription, &[first[0].ack_id.clone()], 0, now)
                .unwrap();
        }
        let clock = Arc::new(Mutex::new(VirtualClock::new(now)));
        let handle = PubSubHandle::new(state, clock, None);
        handle.start_push_dispatcher();
        handle.schedule_push(&topic);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let deferred = {
                    let dispatch = handle.push_dispatch.lock().unwrap();
                    dispatch.deferred.contains_key(&subscription.to_full())
                };
                if deferred {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ordered predecessor backoff must be deferred");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        {
            let dispatch = handle.push_dispatch.lock().unwrap();
            assert_eq!(dispatch.spawned, 1);
            assert!(dispatch.active.is_empty());
            assert!(dispatch.ready.is_empty());
        }

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
            dispatch.enqueue(subscription.clone(), TEST_NOW);
            dispatch.claim().unwrap()
        };
        handle.invalidate_all_push_workers();
        *state.lock().unwrap() = PubSubState::new(42);
        let new_message = publish_and_pull(&mut state.lock().unwrap());
        assert_eq!(old_message.ack_id, new_message.ack_id);

        let new_work = {
            let mut dispatch = handle.push_dispatch.lock().unwrap();
            dispatch.enqueue(subscription.clone(), TEST_NOW);
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
        dispatch.enqueue(first.clone(), TEST_NOW);
        dispatch.enqueue(second.clone(), TEST_NOW);
        let old_first = dispatch.claim().unwrap();
        let old_second = dispatch.claim().unwrap();

        dispatch.invalidate_projects_where(|project| project == "project-a");
        dispatch.enqueue(first.clone(), TEST_NOW);
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

    /// Builds a registry whose source subscription holds one exhausted message waiting for
    /// dead-letter destination admission. Returns the state, the destination topic, the source
    /// subscription and the instant the exhaustion happened at.
    fn pending_dead_letter_fixture() -> (
        Arc<Mutex<PubSubState>>,
        TopicName,
        SubscriptionName,
        LogicalInstant,
    ) {
        let source_topic = TopicName::new("demo-project", "source").unwrap();
        let destination_topic = TopicName::new("demo-project", "dead-letter").unwrap();
        let source_subscription =
            SubscriptionName::new("demo-project", "source-subscription").unwrap();
        let now = LogicalInstant::UNIX_EPOCH;
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        {
            let mut state = state.lock().unwrap();
            state
                .create_topic(source_topic.clone(), BTreeMap::new())
                .unwrap();
            state
                .create_topic(destination_topic.clone(), BTreeMap::new())
                .unwrap();
            state
                .create_subscription(SubscriptionConfig {
                    name: source_subscription.clone(),
                    topic: source_topic.clone(),
                    ack_deadline_seconds: DEFAULT_ACK_DEADLINE_SECONDS,
                    enable_message_ordering: false,
                    filter: Filter::always(),
                    dead_letter_policy: Some(DeadLetterPolicy {
                        dead_letter_topic: destination_topic.clone(),
                        max_delivery_attempts: MIN_DEAD_LETTER_ATTEMPTS,
                    }),
                    retry_policy: None,
                    push_config: PushConfig::default(),
                })
                .unwrap();
            state
                .publish(
                    &source_topic,
                    vec![PubsubMessage {
                        data: b"pending dead letter".to_vec(),
                        ..PubsubMessage::default()
                    }],
                    now,
                )
                .unwrap();

            let mut current = now;
            for _ in 0..MIN_DEAD_LETTER_ATTEMPTS {
                let outcome = state
                    .pull_with_dead_letters(&source_subscription, 1, current)
                    .unwrap();
                assert_eq!(outcome.received.len(), 1);
                current = current
                    .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(11))
                    .unwrap();
                state.expire_all(current);
            }
            let outcome = state
                .pull_with_dead_letters(&source_subscription, 1, current)
                .unwrap();
            assert!(outcome.received.is_empty());
            assert_eq!(outcome.dead_lettered.len(), 1);
        }
        (state, destination_topic, source_subscription, now)
    }

    #[test]
    fn concurrent_dead_letter_retries_forward_a_pending_message_once() {
        let (state, destination_topic, _source_subscription, now) = pending_dead_letter_fixture();

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let destination_commits = Arc::new(AtomicUsize::new(0));
        let handle = PubSubHandle::new(
            state.clone(),
            Arc::new(Mutex::new(VirtualClock::new(now))),
            Some(Arc::new(BlockingDeadLetterDelivery {
                destination: destination_topic.to_full(),
                block_first_commit: Arc::new(AtomicBool::new(true)),
                entered: entered.clone(),
                release: release.clone(),
                destination_commits: destination_commits.clone(),
            })),
        );

        let first_handle = handle.clone();
        let first = std::thread::spawn(move || first_handle.retry_pending_dead_letters());
        entered.wait();

        let second_handle = handle.clone();
        let (second_waiting_sender, second_waiting_receiver) = std::sync::mpsc::sync_channel(0);
        let second = std::thread::spawn(move || {
            loop {
                match second_handle.dead_letter_gate.try_lock() {
                    Ok(gate) => drop(gate),
                    Err(std::sync::TryLockError::WouldBlock) => break,
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        panic!("dead-letter gate was poisoned")
                    }
                }
                std::thread::yield_now();
            }
            second_waiting_sender.send(()).unwrap();
            second_handle.retry_pending_dead_letters();
        });
        second_waiting_receiver.recv().unwrap();
        release.wait();

        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(destination_commits.load(Ordering::SeqCst), 1);
        assert!(state.lock().unwrap().pending_dead_letters().is_empty());
    }

    #[test]
    fn a_seek_cannot_interleave_with_an_in_flight_dead_letter_transfer() {
        let (state, destination_topic, source_subscription, now) = pending_dead_letter_fixture();

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let destination_commits = Arc::new(AtomicUsize::new(0));
        let handle = PubSubHandle::new(
            state.clone(),
            Arc::new(Mutex::new(VirtualClock::new(now))),
            Some(Arc::new(BlockingDeadLetterDelivery {
                destination: destination_topic.to_full(),
                block_first_commit: Arc::new(AtomicBool::new(true)),
                entered: entered.clone(),
                release: release.clone(),
                destination_commits: destination_commits.clone(),
            })),
        );

        // The transfer has published to the destination and has not completed its source yet.
        let transfer_handle = handle.clone();
        let transfer = std::thread::spawn(move || transfer_handle.retry_pending_dead_letters());
        entered.wait();

        let seek_handle = handle.clone();
        let seek_subscription = source_subscription.clone();
        let (finished_sender, finished_receiver) = std::sync::mpsc::channel();
        let seek = std::thread::spawn(move || {
            loop {
                match seek_handle.dead_letter_gate.try_lock() {
                    Ok(gate) => drop(gate),
                    Err(std::sync::TryLockError::WouldBlock) => break,
                    Err(std::sync::TryLockError::Poisoned(_)) => {
                        panic!("dead-letter gate was poisoned")
                    }
                }
                std::thread::yield_now();
            }
            seek_handle
                .seek_to_time(&seek_subscription, LogicalInstant::UNIX_EPOCH)
                .unwrap();
            finished_sender.send(()).unwrap();
        });

        // A seek that rewrote the delivery states here would strand the published transfer with
        // no source completion, so it waits for the transfer instead.
        assert!(
            matches!(
                finished_receiver.recv_timeout(std::time::Duration::from_millis(200)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "a seek must not run inside an in-flight dead-letter transfer"
        );

        release.wait();
        transfer.join().unwrap();
        seek.join().unwrap();
        finished_receiver.recv().unwrap();

        assert_eq!(destination_commits.load(Ordering::SeqCst), 1);
        let mut state = state.lock().unwrap();
        assert!(state.pending_dead_letters().is_empty());
        // The seek replayed the backlog, so the source holds one deliverable copy and the
        // destination still holds exactly the one message the completed transfer published.
        assert_eq!(state.pull(&source_subscription, 10, now).unwrap().len(), 1);
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

#[cfg(test)]
mod publication_gate_tests {
    use std::sync::{Arc, Mutex};

    use fireemu_core_pubsub::PubSubState;
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_types::time::LogicalInstant;

    use super::PubSubHandle;

    fn handle() -> PubSubHandle {
        PubSubHandle::new(
            Arc::new(Mutex::new(PubSubState::new(5))),
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            None,
        )
    }

    /// PUBGATE-1: the publication gate is held across the control-plane transitions that
    /// publish and reset Pub/Sub state, so panicking on a poisoned gate would turn one earlier
    /// failure into a permanent one for every later caller. The refusal is returned instead.
    #[test]
    fn a_poisoned_publication_gate_is_reported_rather_than_panicked_on() {
        let handle = handle();
        assert!(
            handle.lock_publication().is_ok(),
            "a fresh gate must be lockable"
        );

        let gate = handle.publication_gate();
        let poisoner = std::thread::spawn(move || {
            let _held = gate.lock().expect("the gate is not yet poisoned");
            panic!("the holder fails while the gate is held");
        });
        assert!(
            poisoner.join().is_err(),
            "the poisoning thread must have panicked"
        );

        let refusal = handle
            .lock_publication()
            .expect_err("a poisoned gate must be reported");
        assert!(refusal.contains("publication gate"), "{refusal}");
        assert!(refusal.contains("poisoned"), "{refusal}");
    }
}
