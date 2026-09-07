//! The Pub/Sub registry: topics, subscriptions, publish routing, dead-letter forwarding and
//! deterministic identifier generation.
//!
//! [`PubSubState`] is a pure, std-only state machine. It owns no clock and no sockets: every
//! operation that depends on time takes an explicit [`LogicalInstant`], and identifiers are
//! derived from the daemon seed so a run reproduces byte for byte. The protocol adapter drives
//! it, forwarding the virtual clock and holding the lock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::resources::{Gauge, RetentionRoot, RootBudget, ServiceResources, Unit};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::error::{PubSubError, Result};
use crate::message::{PubsubMessage, StoredMessage};
use crate::name::{
    validate_project, validate_resource_id, SubscriptionName, TopicName, DELETED_TOPIC,
};
use crate::subscription::{PushConfig, ReceivedMessage, SubscriptionConfig, SubscriptionState};

/// Upper bound on the number of topics one project session keeps.
pub const MAX_TOPICS: usize = 10_000;
/// Upper bound on the number of subscriptions one project session keeps.
pub const MAX_SUBSCRIPTIONS: usize = 10_000;
/// Maximum messages accepted in one publish request.
pub const MAX_MESSAGES_PER_PUBLISH: usize = 1_000;
/// Maximum snapshots retained by one daemon.
pub const MAX_SNAPSHOTS: usize = 10_000;
/// Snapshot lifetime used by the local emulator's deterministic clock.
pub const SNAPSHOT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
/// Minimum remaining snapshot lifetime accepted by production Pub/Sub.
pub const MIN_SNAPSHOT_TTL_SECONDS: i64 = 60 * 60;
/// Upper bound for the conservative in-memory accounting of all live snapshots.
pub const MAX_SNAPSHOT_RETAINED_BYTES: usize = 64 * 1024 * 1024;

/// A Pub/Sub snapshot and the acknowledgement state it captures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Fully-qualified snapshot resource name.
    pub name: String,
    /// Project that owns the snapshot resource, independent of the source topic project.
    pub owner_project: String,
    /// The topic retained by this snapshot.
    pub topic: TopicName,
    /// Internal identity of the topic resource instance captured by the snapshot.
    pub topic_incarnation: u64,
    /// When the snapshot was created.
    pub created_at: LogicalInstant,
    /// When the snapshot expires.
    pub expire_at: LogicalInstant,
    /// User-provided labels.
    pub labels: BTreeMap<String, String>,
    /// Message IDs that were unacknowledged at creation.
    pub unacknowledged_message_ids: Arc<BTreeSet<String>>,
    /// All message IDs retained by the source subscription at creation. Keeping this boundary
    /// lets seek distinguish an acknowledged message from a later message published at the same
    /// logical instant.
    pub retained_message_ids: Arc<BTreeSet<String>>,
    /// Shared message records retained by the source at creation. These records let seek restore
    /// a snapshot into a subscription created after the source backlog existed.
    pub captured_messages: Arc<Vec<Arc<StoredMessage>>>,
}

/// One exhausted source message waiting for dead-letter destination admission.
#[derive(Debug, Clone)]
pub struct DeadLetterForward {
    /// The source subscription that owns the pending message.
    pub source_subscription: SubscriptionName,
    /// The configured destination topic.
    pub dead_letter_topic: TopicName,
    /// The source message retained until the transfer completes.
    pub message: Arc<StoredMessage>,
}

/// The result of a pull before dead-letter forwarding is committed.
#[derive(Debug, Clone, Default)]
pub struct PullResult {
    /// Messages delivered to the caller.
    pub received: Vec<ReceivedMessage>,
    /// Messages that became eligible for dead-letter forwarding during the pull.
    pub dead_lettered: Vec<DeadLetterForward>,
}

/// A fully admitted publication that has not become visible to subscriptions yet.
#[derive(Debug)]
pub struct PreparedPublication {
    topic_key: String,
    topic_incarnation: u64,
    initial_message_counter: u64,
    next_message_counter: u64,
    published: Vec<Arc<StoredMessage>>,
    subscription_keys: Vec<String>,
    snapshot_names: Vec<String>,
    snapshot_total_bytes: usize,
}

impl PreparedPublication {
    /// The shared records that will be visible after commit.
    #[must_use]
    pub fn published_messages(&self) -> &[Arc<StoredMessage>] {
        &self.published
    }
}

/// A topic and the record of which subscriptions attach to it.
#[derive(Debug, Clone)]
struct TopicEntry {
    name: TopicName,
    labels: BTreeMap<String, String>,
    incarnation: u64,
}

/// The whole Pub/Sub state for one daemon (all projects share one registry; names are
/// project-qualified so projects never collide).
#[derive(Debug)]
pub struct PubSubState {
    seed: u64,
    topics: BTreeMap<String, TopicEntry>,
    subscriptions: BTreeMap<String, SubscriptionState>,
    topic_subs: BTreeMap<String, BTreeSet<String>>,
    function_subscriptions: BTreeSet<String>,
    snapshots: BTreeMap<String, Snapshot>,
    topic_snapshots: BTreeMap<(String, u64), BTreeSet<String>>,
    snapshot_message_refs: BTreeMap<String, usize>,
    topic_counter: u64,
    message_counter: u64,
    ack_rng: SplitMix64,
    snapshot_counter: u64,
    snapshot_retained_bytes: usize,
}

impl PubSubState {
    /// Creates an empty registry seeded for deterministic identifier generation.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            topics: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            topic_subs: BTreeMap::new(),
            function_subscriptions: BTreeSet::new(),
            snapshots: BTreeMap::new(),
            topic_snapshots: BTreeMap::new(),
            snapshot_message_refs: BTreeMap::new(),
            topic_counter: 0,
            message_counter: 0,
            // Mix a fixed tag so ack ids never coincide with any other seeded stream.
            ack_rng: SplitMix64::new(seed ^ 0x5053_5542_4143_4b5f),
            snapshot_counter: 0,
            snapshot_retained_bytes: 0,
        }
    }

    /// The retention report of the topics, subscriptions and snapshots of the projects `owns`
    /// selects: counts against the per-project limits, unacknowledged messages and their
    /// payload bytes as outstanding roots (one per subscription), and snapshots as retained
    /// roots. The snapshot byte total is daemon-wide and reported only when `report_global`
    /// is set (the default session), so a session never reads another session's totals.
    /// Message payloads are never included.
    #[must_use]
    pub fn resources(
        &self,
        owns: &dyn Fn(&str) -> bool,
        report_global: bool,
        budget: RootBudget,
    ) -> ServiceResources {
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        let mut roots = Vec::new();
        let mut topics = 0u64;
        for topic in self.topics.values() {
            if owns(topic.name.project()) {
                topics += 1;
            }
        }
        let mut subscriptions = 0u64;
        let mut unacked = 0u64;
        let mut unacked_bytes = 0u64;
        let mut retained_acked_bytes = 0u64;
        for (name, subscription) in &self.subscriptions {
            if !owns(subscription.config().name.project()) {
                continue;
            }
            subscriptions += 1;
            let (pending, bytes, acked_bytes) = subscription.retention_accounting();
            retained_acked_bytes = retained_acked_bytes.saturating_add(acked_bytes);
            if pending == 0 {
                continue;
            }
            let pending = count(pending);
            unacked = unacked.saturating_add(pending);
            unacked_bytes = unacked_bytes.saturating_add(bytes);
            roots.push(RetentionRoot {
                kind: "unacked".to_owned(),
                id: name.clone(),
                count: pending,
                bytes,
                outstanding: true,
            });
        }
        let mut snapshots = 0u64;
        for (name, snapshot) in &self.snapshots {
            if !owns(&snapshot.owner_project) {
                continue;
            }
            snapshots += 1;
            let bytes = snapshot
                .captured_messages
                .iter()
                .fold(0u64, |sum, message| {
                    sum.saturating_add(count(message.message.data.len()))
                });
            roots.push(RetentionRoot {
                kind: "snapshot".to_owned(),
                id: name.clone(),
                count: count(snapshot.captured_messages.len()),
                bytes,
                outstanding: false,
            });
        }
        let mut gauges = vec![
            Gauge::logical("topics", Unit::Count, topics, Some(count(MAX_TOPICS))),
            Gauge::logical(
                "subscriptions",
                Unit::Count,
                subscriptions,
                Some(count(MAX_SUBSCRIPTIONS)),
            ),
            Gauge::logical("unacked.messages", Unit::Count, unacked, None),
            Gauge::logical("unacked.bytes", Unit::Bytes, unacked_bytes, None),
            Gauge::logical(
                "retained.bytes",
                Unit::Bytes,
                unacked_bytes.saturating_add(retained_acked_bytes),
                None,
            )
            .with_reclaimable(retained_acked_bytes),
            Gauge::logical(
                "snapshots.retained",
                Unit::Count,
                snapshots,
                Some(count(MAX_SNAPSHOTS)),
            ),
        ];
        if report_global {
            gauges.push(Gauge::logical(
                "snapshots.retained_bytes",
                Unit::Bytes,
                count(self.snapshot_retained_bytes),
                Some(count(MAX_SNAPSHOT_RETAINED_BYTES)),
            ));
        }
        ServiceResources {
            service: "pubsub".to_owned(),
            gauges,
            refusals: Vec::new(),
            roots: budget.bound(roots),
        }
    }

    /// Drops every topic and subscription (session reset). The seed and counters are reset so
    /// that a fresh run after a reset reproduces the same identifiers.
    pub fn clear(&mut self) {
        self.topics.clear();
        self.subscriptions.clear();
        self.topic_subs.clear();
        self.function_subscriptions.clear();
        self.snapshots.clear();
        self.topic_snapshots.clear();
        self.snapshot_message_refs.clear();
        self.snapshot_retained_bytes = 0;
        self.message_counter = 0;
        self.ack_rng = SplitMix64::new(self.seed ^ 0x5053_5542_4143_4b5f);
        self.snapshot_counter = 0;
        self.topic_counter = 0;
    }

    /// Drops one project's topics and subscriptions without disturbing other sessions.
    pub fn clear_project(&mut self, project: &str) {
        let subscriptions = self
            .subscriptions
            .values()
            .filter(|state| state.config().name.project() == project)
            .map(|state| state.config().name.clone())
            .collect::<Vec<_>>();
        for subscription in subscriptions {
            let _ = self.delete_subscription(&subscription);
        }
        let topics = self
            .topics
            .values()
            .filter(|entry| entry.name.project() == project)
            .map(|entry| entry.name.clone())
            .collect::<Vec<_>>();
        for topic in topics {
            let _ = self.delete_topic(&topic);
        }
        let snapshots = self
            .snapshots
            .values()
            .filter(|snapshot| snapshot.owner_project == project)
            .map(|snapshot| snapshot.name.clone())
            .collect::<Vec<_>>();
        for snapshot in snapshots {
            self.remove_snapshot(&snapshot);
        }
    }

    /// Drops every resource owned by a project accepted by `matches`.
    pub fn clear_projects_where(&mut self, matches: impl Fn(&str) -> bool) {
        let mut projects = BTreeSet::new();
        projects.extend(
            self.topics
                .values()
                .map(|entry| entry.name.project().to_owned()),
        );
        projects.extend(
            self.subscriptions
                .values()
                .map(|state| state.config().name.project().to_owned()),
        );
        projects.extend(
            self.snapshots
                .values()
                .map(|snapshot| snapshot.owner_project.clone()),
        );
        for project in projects.into_iter().filter(|project| matches(project)) {
            self.clear_project(&project);
        }
    }

    // --- Topics -----------------------------------------------------------------------------

    /// Creates a topic. Returns `ALREADY_EXISTS` if one is present under that name.
    pub fn create_topic(
        &mut self,
        name: TopicName,
        labels: BTreeMap<String, String>,
    ) -> Result<()> {
        let key = name.to_full();
        if self.topics.contains_key(&key) {
            return Err(PubSubError::already_exists(format!(
                "topic {key} already exists"
            )));
        }
        if self.topics.len() >= MAX_TOPICS {
            return Err(PubSubError::resource_exhausted(format!(
                "the maximum of {MAX_TOPICS} topics has been reached"
            )));
        }
        self.topic_counter = self
            .topic_counter
            .checked_add(1)
            .ok_or_else(|| PubSubError::resource_exhausted("topic incarnation space exhausted"))?;
        self.topic_subs.entry(key.clone()).or_default();
        self.topics.insert(
            key,
            TopicEntry {
                name,
                labels,
                incarnation: self.topic_counter,
            },
        );
        Ok(())
    }

    /// Whether a topic exists.
    #[must_use]
    pub fn topic_exists(&self, name: &TopicName) -> bool {
        self.topics.contains_key(&name.to_full())
    }

    /// The labels of a topic, or `NOT_FOUND`.
    pub fn topic_labels(&self, name: &TopicName) -> Result<&BTreeMap<String, String>> {
        self.topics
            .get(&name.to_full())
            .map(|t| &t.labels)
            .ok_or_else(|| PubSubError::not_found(format!("topic {} not found", name.to_full())))
    }

    /// Lists the topics of a project, sorted by name.
    #[must_use]
    pub fn list_topics(&self, project: &str) -> Vec<TopicName> {
        self.topics
            .values()
            .filter(|t| t.name.project() == project)
            .map(|t| t.name.clone())
            .collect()
    }

    /// Deletes a topic. Its subscriptions survive, reporting `_deleted-topic_` as their topic.
    pub fn delete_topic(&mut self, name: &TopicName) -> Result<()> {
        let key = name.to_full();
        if self.topics.remove(&key).is_none() {
            return Err(PubSubError::not_found(format!("topic {key} not found")));
        }
        for subscription in self.topic_subs.remove(&key).unwrap_or_default() {
            if let Some(state) = self.subscriptions.get_mut(&subscription) {
                state.mark_topic_deleted();
            }
        }
        Ok(())
    }

    /// Lists the subscription names attached to a topic (`ListTopicSubscriptions`).
    #[must_use]
    pub fn topic_subscriptions(&self, name: &TopicName) -> Vec<String> {
        self.topic_subs
            .get(&name.to_full())
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    // --- Subscriptions ----------------------------------------------------------------------

    /// Creates a subscription. The topic must already exist. `ALREADY_EXISTS` if one is present.
    pub fn create_subscription(&mut self, config: SubscriptionConfig) -> Result<()> {
        config.validate()?;
        let key = config.name.to_full();
        let topic_key = config.topic.to_full();
        if self.subscriptions.contains_key(&key) {
            return Err(PubSubError::already_exists(format!(
                "subscription {key} already exists"
            )));
        }
        if !config.topic.is_deleted_sentinel() && !self.topics.contains_key(&topic_key) {
            return Err(PubSubError::not_found(format!(
                "topic {topic_key} not found"
            )));
        }
        if let Some(dl) = &config.dead_letter_policy {
            let dead_letter_topic = dl.dead_letter_topic.to_full();
            if !self.topics.contains_key(&dead_letter_topic) {
                return Err(PubSubError::not_found(format!(
                    "dead-letter topic {dead_letter_topic} not found"
                )));
            }
        }
        if self.subscriptions.len() >= MAX_SUBSCRIPTIONS {
            return Err(PubSubError::resource_exhausted(format!(
                "the maximum of {MAX_SUBSCRIPTIONS} subscriptions has been reached"
            )));
        }
        self.topic_subs
            .entry(topic_key)
            .or_default()
            .insert(key.clone());
        self.subscriptions
            .insert(key, SubscriptionState::new(config));
        Ok(())
    }

    /// Marks a visible subscription as owned by the Functions bridge. Messages are delivered
    /// directly by that bridge, so this subscription must not retain a duplicate backlog.
    pub fn mark_function_subscription(&mut self, name: &SubscriptionName) -> Result<()> {
        let key = name.to_full();
        if !self.subscriptions.contains_key(&key) {
            return Err(PubSubError::not_found(format!(
                "subscription {key} not found"
            )));
        }
        self.function_subscriptions.insert(key);
        Ok(())
    }

    /// Borrows a subscription's configuration, or `NOT_FOUND`.
    pub fn subscription_config(&self, name: &SubscriptionName) -> Result<&SubscriptionConfig> {
        self.subscriptions
            .get(&name.to_full())
            .map(SubscriptionState::config)
            .ok_or_else(|| {
                PubSubError::not_found(format!("subscription {} not found", name.to_full()))
            })
    }

    /// Returns the earliest logical delivery time for an available message in a subscription.
    pub fn next_delivery_at(&self, name: &SubscriptionName) -> Result<Option<LogicalInstant>> {
        self.subscriptions
            .get(&name.to_full())
            .map(SubscriptionState::next_available_at)
            .ok_or_else(|| {
                PubSubError::not_found(format!("subscription {} not found", name.to_full()))
            })
    }

    /// Lists the subscriptions of a project, sorted by name.
    #[must_use]
    pub fn list_subscriptions(&self, project: &str) -> Vec<SubscriptionConfig> {
        self.subscriptions
            .values()
            .map(SubscriptionState::config)
            .filter(|c| c.name.project() == project)
            .cloned()
            .collect()
    }

    /// Returns push-enabled subscriptions attached to a topic.
    #[must_use]
    pub fn push_subscriptions(&self, topic: &TopicName) -> Vec<(SubscriptionName, String)> {
        self.topic_subs
            .get(&topic.to_full())
            .into_iter()
            .flatten()
            .filter_map(|key| self.subscriptions.get(key))
            .filter(|subscription| subscription.config().is_push())
            .map(|subscription| {
                (
                    subscription.config().name.clone(),
                    subscription.config().push_config.push_endpoint.clone(),
                )
            })
            .collect()
    }

    /// Deletes a subscription.
    pub fn delete_subscription(&mut self, name: &SubscriptionName) -> Result<()> {
        let key = name.to_full();
        let Some(state) = self.subscriptions.remove(&key) else {
            return Err(PubSubError::not_found(format!(
                "subscription {key} not found"
            )));
        };
        self.function_subscriptions.remove(&key);
        if let Some(set) = self.topic_subs.get_mut(&state.config().topic.to_full()) {
            set.remove(&key);
        }
        Ok(())
    }

    /// Updates the ack deadline of a subscription.
    pub fn update_ack_deadline(&mut self, name: &SubscriptionName, seconds: u32) -> Result<()> {
        let s = self.sub_mut(name)?;
        if !(crate::subscription::MIN_ACK_DEADLINE_SECONDS
            ..=crate::subscription::MAX_ACK_DEADLINE_SECONDS)
            .contains(&seconds)
        {
            return Err(PubSubError::invalid_argument(
                "ackDeadlineSeconds must be 10..=600",
            ));
        }
        s.set_ack_deadline(seconds);
        Ok(())
    }

    /// Replaces a subscription's push endpoint configuration.
    pub fn update_push_config(
        &mut self,
        name: &SubscriptionName,
        push_config: PushConfig,
    ) -> Result<()> {
        let subscription = self.sub_mut(name)?;
        subscription.set_push_config(push_config);
        Ok(())
    }

    /// Atomically applies the mutable subscription fields supported by the emulator.
    pub fn update_subscription(
        &mut self,
        name: &SubscriptionName,
        ack_deadline_seconds: Option<u32>,
        push_config: Option<PushConfig>,
    ) -> Result<()> {
        let mut candidate = self.subscription_config(name)?.clone();
        if let Some(seconds) = ack_deadline_seconds {
            candidate.ack_deadline_seconds = seconds;
        }
        if let Some(push_config) = &push_config {
            candidate.push_config = push_config.clone();
        }
        candidate.validate()?;

        let subscription = self.sub_mut(name)?;
        if let Some(seconds) = ack_deadline_seconds {
            subscription.set_ack_deadline(seconds);
        }
        if let Some(push_config) = push_config {
            subscription.set_push_config(push_config);
        }
        Ok(())
    }

    fn parse_snapshot_name(name: &str) -> Result<(&str, &str)> {
        let rest = name.strip_prefix("projects/").ok_or_else(|| {
            PubSubError::invalid_argument("snapshot name must be projects/{p}/snapshots/{s}")
        })?;
        let (project, snapshot) = rest.split_once("/snapshots/").ok_or_else(|| {
            PubSubError::invalid_argument("snapshot name must be projects/{p}/snapshots/{s}")
        })?;
        validate_project(project)?;
        validate_resource_id(snapshot, "snapshot")?;
        Ok((project, snapshot))
    }

    fn remove_expired_snapshots(&mut self, now: LogicalInstant) {
        let expired = self
            .snapshots
            .values()
            .filter(|snapshot| snapshot.expire_at <= now)
            .map(|snapshot| snapshot.name.clone())
            .collect::<Vec<_>>();
        for name in expired {
            self.remove_snapshot(&name);
        }
    }

    fn remove_snapshot(&mut self, name: &str) -> Option<Snapshot> {
        let snapshot = self.snapshots.remove(name)?;
        let topic_key = (snapshot.topic.to_full(), snapshot.topic_incarnation);
        if let Some(names) = self.topic_snapshots.get_mut(&topic_key) {
            names.remove(name);
            if names.is_empty() {
                self.topic_snapshots.remove(&topic_key);
            }
        }
        self.snapshot_retained_bytes = self
            .snapshot_retained_bytes
            .saturating_sub(Self::snapshot_owned_bytes(&snapshot));
        for message in snapshot.captured_messages.iter() {
            let remove_shared = if let Some(refs) = self
                .snapshot_message_refs
                .get_mut(message.message_id.as_str())
            {
                *refs = refs.saturating_sub(1);
                *refs == 0
            } else {
                false
            };
            if remove_shared {
                self.snapshot_message_refs
                    .remove(message.message_id.as_str());
                self.snapshot_retained_bytes = self
                    .snapshot_retained_bytes
                    .saturating_sub(Self::snapshot_shared_message_bytes(message));
            }
        }
        Some(snapshot)
    }

    fn owned_string_bytes(value: &String) -> usize {
        std::mem::size_of::<String>()
            .saturating_add(value.capacity())
            .saturating_add(64)
    }

    fn snapshot_reference_bytes(message_id: &String, unacknowledged: bool) -> usize {
        // Two Arc slots conservatively cover Vec capacity growth below 2x, and each set entry
        // is charged independently because both sets own their own String allocation.
        std::mem::size_of::<Arc<StoredMessage>>()
            .saturating_mul(2)
            .saturating_add(Self::owned_string_bytes(message_id))
            .saturating_add(if unacknowledged {
                Self::owned_string_bytes(message_id)
            } else {
                0
            })
    }

    fn snapshot_shared_message_bytes(message: &StoredMessage) -> usize {
        let attributes = message
            .message
            .attributes
            .iter()
            .map(|(key, value)| {
                Self::owned_string_bytes(key).saturating_add(Self::owned_string_bytes(value))
            })
            .sum::<usize>();
        std::mem::size_of::<StoredMessage>()
            .saturating_add(std::mem::size_of::<usize>().saturating_mul(2))
            .saturating_add(message.message.data.capacity())
            .saturating_add(message.message.ordering_key.capacity())
            .saturating_add(attributes)
            // The global reference-count index owns one additional message-id String.
            .saturating_add(Self::owned_string_bytes(&message.message_id))
    }

    fn snapshot_owned_bytes(snapshot: &Snapshot) -> usize {
        let references = snapshot
            .captured_messages
            .iter()
            .map(|message| {
                Self::snapshot_reference_bytes(
                    &message.message_id,
                    snapshot
                        .unacknowledged_message_ids
                        .contains(&message.message_id),
                )
            })
            .sum::<usize>();
        let labels = snapshot
            .labels
            .iter()
            .map(|(key, value)| {
                Self::owned_string_bytes(key).saturating_add(Self::owned_string_bytes(value))
            })
            .sum::<usize>();
        std::mem::size_of::<Snapshot>()
            .saturating_add(256)
            .saturating_add(Self::owned_string_bytes(&snapshot.name))
            .saturating_add(Self::owned_string_bytes(&snapshot.owner_project))
            .saturating_add(snapshot.topic.to_full().len())
            .saturating_add(references)
            .saturating_add(labels)
    }

    fn snapshot_lifetime(
        oldest_unacknowledged: Option<LogicalInstant>,
        now: LogicalInstant,
    ) -> Result<LogicalDuration> {
        let maximum_lifetime = LogicalDuration::from_seconds(SNAPSHOT_TTL_SECONDS);
        let age = oldest_unacknowledged
            .and_then(|published_at| now.checked_duration_since(published_at))
            .filter(|age| age.as_nanos() > 0)
            .unwrap_or(LogicalDuration::ZERO);
        let lifetime = LogicalDuration::from_nanos(
            maximum_lifetime
                .as_nanos()
                .checked_sub(age.as_nanos())
                .unwrap_or(i128::MIN),
        );
        if lifetime < LogicalDuration::from_seconds(MIN_SNAPSHOT_TTL_SECONDS) {
            return Err(PubSubError::failed_precondition(format!(
                "snapshot lifetime must be at least {MIN_SNAPSHOT_TTL_SECONDS} seconds"
            )));
        }
        Ok(lifetime)
    }

    fn available_snapshot_name(
        &self,
        requested_name: &str,
        subscription: &SubscriptionName,
    ) -> Result<(String, Option<u64>)> {
        if !requested_name.is_empty() {
            return Ok((requested_name.to_owned(), None));
        }
        let mut counter = self.snapshot_counter;
        loop {
            counter = counter.checked_add(1).ok_or_else(|| {
                PubSubError::resource_exhausted("snapshot identifier space exhausted")
            })?;
            let candidate = format!(
                "projects/{}/snapshots/snapshot-{counter}",
                subscription.project()
            );
            if !self.snapshots.contains_key(&candidate) {
                return Ok((candidate, Some(counter)));
            }
        }
    }

    fn additional_snapshot_bytes(&self, snapshot: &Snapshot) -> Result<usize> {
        snapshot.captured_messages.iter().try_fold(
            Self::snapshot_owned_bytes(snapshot),
            |total, message| {
                if self
                    .snapshot_message_refs
                    .contains_key(message.message_id.as_str())
                {
                    Ok(total)
                } else {
                    total
                        .checked_add(Self::snapshot_shared_message_bytes(message))
                        .ok_or_else(|| {
                            PubSubError::resource_exhausted("snapshot byte count overflow")
                        })
                }
            },
        )
    }

    /// Creates a snapshot of the unacknowledged messages in a subscription. An empty name is
    /// assigned a deterministic resource name; REST callers normally provide the name.
    pub fn create_snapshot(
        &mut self,
        requested_name: &str,
        subscription: &SubscriptionName,
        labels: BTreeMap<String, String>,
        now: LogicalInstant,
    ) -> Result<Snapshot> {
        self.remove_expired_snapshots(now);
        let topic = self.subscription_config(subscription)?.topic.clone();
        if topic.is_deleted_sentinel() || !self.topic_exists(&topic) {
            return Err(PubSubError::not_found(format!(
                "topic {} not found",
                topic.to_full()
            )));
        }
        let topic_incarnation = self
            .topics
            .get(&topic.to_full())
            .expect("topic existence was checked above")
            .incarnation;
        let (name, next_snapshot_counter) =
            self.available_snapshot_name(requested_name, subscription)?;
        let (project, _) = Self::parse_snapshot_name(&name)?;
        if project != subscription.project() {
            return Err(PubSubError::invalid_argument(
                "snapshot and subscription must belong to the same project",
            ));
        }
        if self.snapshots.contains_key(&name) {
            return Err(PubSubError::already_exists(format!(
                "snapshot {name} already exists"
            )));
        }
        if self.snapshots.len() >= MAX_SNAPSHOTS {
            return Err(PubSubError::resource_exhausted(format!(
                "the maximum of {MAX_SNAPSHOTS} snapshots has been reached"
            )));
        }
        let source_subscription =
            self.subscriptions
                .get(&subscription.to_full())
                .ok_or_else(|| {
                    PubSubError::not_found(format!(
                        "subscription {} not found",
                        subscription.to_full()
                    ))
                })?;
        let oldest_unacknowledged = source_subscription.oldest_unacknowledged_publish_time();
        let unacknowledged_message_ids = source_subscription.unacknowledged_message_ids();
        let retained_message_ids = source_subscription.retained_message_ids();
        let captured_messages = source_subscription.retained_messages();
        let lifetime = Self::snapshot_lifetime(oldest_unacknowledged, now)?;
        let expire_at = now.checked_add(lifetime).unwrap_or(LogicalInstant::MAX);
        let snapshot = Snapshot {
            name: name.clone(),
            owner_project: project.to_owned(),
            topic,
            topic_incarnation,
            created_at: now,
            expire_at,
            labels,
            unacknowledged_message_ids: Arc::new(unacknowledged_message_ids),
            retained_message_ids: Arc::new(retained_message_ids),
            captured_messages: Arc::new(captured_messages),
        };
        let snapshot_bytes = self.additional_snapshot_bytes(&snapshot)?;
        if self
            .snapshot_retained_bytes
            .checked_add(snapshot_bytes)
            .is_none_or(|total| total > MAX_SNAPSHOT_RETAINED_BYTES)
        {
            return Err(PubSubError::resource_exhausted(format!(
                "snapshots retain at most {MAX_SNAPSHOT_RETAINED_BYTES} bytes"
            )));
        }
        self.snapshot_retained_bytes += snapshot_bytes;
        for message in snapshot.captured_messages.iter() {
            *self
                .snapshot_message_refs
                .entry(message.message_id.clone())
                .or_default() += 1;
        }
        if let Some(counter) = next_snapshot_counter {
            self.snapshot_counter = counter;
        }
        self.topic_snapshots
            .entry((snapshot.topic.to_full(), snapshot.topic_incarnation))
            .or_default()
            .insert(name.clone());
        self.snapshots.insert(name, snapshot.clone());
        Ok(snapshot)
    }

    /// Gets a non-expired snapshot.
    pub fn get_snapshot(&mut self, name: &str, now: LogicalInstant) -> Result<Snapshot> {
        Self::parse_snapshot_name(name)?;
        self.remove_expired_snapshots(now);
        self.snapshots
            .get(name)
            .cloned()
            .ok_or_else(|| PubSubError::not_found(format!("snapshot {name} not found")))
    }

    /// Lists non-expired snapshots in a project in deterministic resource-name order.
    pub fn list_snapshots(&mut self, project: &str, now: LogicalInstant) -> Vec<Snapshot> {
        self.remove_expired_snapshots(now);
        self.snapshots
            .values()
            .filter(|snapshot| snapshot.owner_project == project)
            .cloned()
            .collect()
    }

    /// Lists snapshot names retaining the exact topic, independent of snapshot ownership.
    pub fn list_topic_snapshots(
        &mut self,
        topic: &TopicName,
        now: LogicalInstant,
    ) -> Result<Vec<String>> {
        self.remove_expired_snapshots(now);
        let topic_key = topic.to_full();
        let incarnation = self
            .topics
            .get(&topic_key)
            .ok_or_else(|| PubSubError::not_found(format!("topic {topic_key} not found")))?
            .incarnation;
        Ok(self
            .topic_snapshots
            .get(&(topic_key, incarnation))
            .into_iter()
            .flatten()
            .cloned()
            .collect())
    }

    /// Updates snapshot labels. The snapshot name and topic are immutable.
    pub fn update_snapshot(
        &mut self,
        name: &str,
        labels: BTreeMap<String, String>,
        now: LogicalInstant,
    ) -> Result<Snapshot> {
        Self::parse_snapshot_name(name)?;
        self.remove_expired_snapshots(now);
        let mut updated = self
            .snapshots
            .get(name)
            .cloned()
            .ok_or_else(|| PubSubError::not_found(format!("snapshot {name} not found")))?;
        let previous_bytes = Self::snapshot_owned_bytes(&updated);
        updated.labels = labels;
        let updated_bytes = Self::snapshot_owned_bytes(&updated);
        let total = self
            .snapshot_retained_bytes
            .saturating_sub(previous_bytes)
            .checked_add(updated_bytes)
            .ok_or_else(|| PubSubError::resource_exhausted("snapshot byte accounting overflow"))?;
        if total > MAX_SNAPSHOT_RETAINED_BYTES {
            return Err(PubSubError::resource_exhausted(format!(
                "snapshots retain at most {MAX_SNAPSHOT_RETAINED_BYTES} bytes"
            )));
        }
        self.snapshot_retained_bytes = total;
        self.snapshots.insert(name.to_owned(), updated.clone());
        Ok(updated)
    }

    /// Deletes a snapshot.
    pub fn delete_snapshot(&mut self, name: &str, now: LogicalInstant) -> Result<()> {
        Self::parse_snapshot_name(name)?;
        self.remove_expired_snapshots(now);
        self.remove_snapshot(name)
            .map(|_| ())
            .ok_or_else(|| PubSubError::not_found(format!("snapshot {name} not found")))
    }

    /// Seeks a subscription to the acknowledgement state captured by a snapshot.
    pub fn seek_to_snapshot(
        &mut self,
        subscription: &SubscriptionName,
        snapshot_name: &str,
        now: LogicalInstant,
    ) -> Result<()> {
        Self::parse_snapshot_name(snapshot_name)?;
        let snapshot = self.get_snapshot(snapshot_name, now)?;
        let config = self.subscription_config(subscription)?;
        let current_topic_incarnation = self
            .topics
            .get(&config.topic.to_full())
            .map(|entry| entry.incarnation);
        if config.topic != snapshot.topic
            || current_topic_incarnation != Some(snapshot.topic_incarnation)
        {
            return Err(PubSubError::failed_precondition(
                "snapshot topic does not match subscription topic",
            ));
        }
        self.sub_mut(subscription)?.seek_to_snapshot(
            &snapshot.captured_messages,
            &snapshot.retained_message_ids,
            &snapshot.unacknowledged_message_ids,
            snapshot.created_at,
            now,
        )?;
        Ok(())
    }

    // --- Publish / deliver ------------------------------------------------------------------

    fn publish_admission(
        &self,
        topic_key: &str,
        topic_incarnation: u64,
        published: &[Arc<StoredMessage>],
    ) -> Result<(Vec<String>, Vec<String>, usize)> {
        let subscription_keys: Vec<String> = self
            .topic_subs
            .get(topic_key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        for key in &subscription_keys {
            if self.function_subscriptions.contains(key) {
                continue;
            }
            if let Some(sub) = self.subscriptions.get(key) {
                sub.ensure_enqueue_capacity(
                    published
                        .iter()
                        .filter(|stored| sub.admits(&stored.message.attributes))
                        .map(AsRef::as_ref),
                )?;
            }
        }
        let (snapshot_names, snapshot_total_bytes) =
            self.snapshot_publish_admission(topic_key, topic_incarnation, published)?;
        Ok((subscription_keys, snapshot_names, snapshot_total_bytes))
    }

    /// Prepares a publication after validating broker capacity and assigning stable message ids.
    /// The returned records are not visible to subscriptions until [`Self::commit_prepared`] is
    /// called. Expired snapshots may be reclaimed as part of this admission.
    pub fn prepare_publish(
        &mut self,
        topic: &TopicName,
        messages: Vec<PubsubMessage>,
        now: LogicalInstant,
    ) -> Result<PreparedPublication> {
        let topic_key = topic.to_full();
        let topic_incarnation = self
            .topics
            .get(&topic_key)
            .ok_or_else(|| PubSubError::not_found(format!("topic {topic_key} not found")))?
            .incarnation;
        if messages.len() > MAX_MESSAGES_PER_PUBLISH {
            return Err(PubSubError::invalid_argument(format!(
                "a publish request carries at most {MAX_MESSAGES_PER_PUBLISH} messages"
            )));
        }
        for message in &messages {
            message.validate()?;
        }
        self.remove_expired_snapshots(now);

        let initial_message_counter = self.message_counter;
        let mut next_message_counter = initial_message_counter;
        let mut published = Vec::with_capacity(messages.len());
        for message in messages {
            next_message_counter = next_message_counter.checked_add(1).ok_or_else(|| {
                PubSubError::resource_exhausted("Pub/Sub message identifier space exhausted")
            })?;
            let message_id = next_message_counter.to_string();
            published.push(Arc::new(StoredMessage {
                message_id,
                publish_time: now,
                message,
            }));
        }

        let (subscription_keys, snapshot_names, snapshot_total_bytes) =
            self.publish_admission(&topic_key, topic_incarnation, &published)?;
        Ok(PreparedPublication {
            topic_key,
            topic_incarnation,
            initial_message_counter,
            next_message_counter,
            published,
            subscription_keys,
            snapshot_names,
            snapshot_total_bytes,
        })
    }

    /// Commits a previously admitted publication atomically after rechecking its state boundary.
    pub fn commit_prepared(
        &mut self,
        prepared: PreparedPublication,
        now: LogicalInstant,
    ) -> Result<Vec<Arc<StoredMessage>>> {
        let topic_incarnation = self
            .topics
            .get(&prepared.topic_key)
            .map(|topic| topic.incarnation)
            .ok_or_else(|| {
                PubSubError::not_found(format!("topic {} not found", prepared.topic_key))
            })?;
        if topic_incarnation != prepared.topic_incarnation
            || self.message_counter != prepared.initial_message_counter
        {
            return Err(PubSubError::failed_precondition(
                "the prepared Pub/Sub publication is no longer current",
            ));
        }
        let (subscription_keys, snapshot_names, snapshot_total_bytes) = self.publish_admission(
            &prepared.topic_key,
            prepared.topic_incarnation,
            &prepared.published,
        )?;
        if subscription_keys != prepared.subscription_keys
            || snapshot_names != prepared.snapshot_names
            || snapshot_total_bytes != prepared.snapshot_total_bytes
        {
            return Err(PubSubError::failed_precondition(
                "the Pub/Sub publication admission changed before commit",
            ));
        }

        let publish_time = prepared
            .published
            .first()
            .map_or(now, |message| message.publish_time);
        for key in &prepared.subscription_keys {
            if self.function_subscriptions.contains(key) {
                continue;
            }
            if let Some(sub) = self.subscriptions.get_mut(key) {
                for stored in &prepared.published {
                    if sub.admits(&stored.message.attributes) {
                        sub.enqueue(Arc::clone(stored), publish_time)
                            .expect("publish admission preflight guaranteed capacity");
                    }
                }
            }
        }
        self.retain_snapshot_publication(&prepared.snapshot_names, &prepared.published);
        self.snapshot_retained_bytes = prepared.snapshot_total_bytes;
        self.message_counter = prepared.next_message_counter;
        Ok(prepared.published)
    }

    fn snapshot_publish_admission(
        &self,
        topic_key: &str,
        topic_incarnation: u64,
        published: &[Arc<StoredMessage>],
    ) -> Result<(Vec<String>, usize)> {
        let snapshot_names = self
            .topic_snapshots
            .get(&(topic_key.to_owned(), topic_incarnation))
            .map(|names| names.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let per_snapshot_bytes = published.iter().try_fold(0_usize, |total, stored| {
            total
                .checked_add(Self::snapshot_reference_bytes(&stored.message_id, true))
                .ok_or_else(|| PubSubError::resource_exhausted("snapshot byte count overflow"))
        })?;
        let reference_bytes = per_snapshot_bytes
            .checked_mul(snapshot_names.len())
            .ok_or_else(|| PubSubError::resource_exhausted("snapshot byte count overflow"))?;
        let shared_bytes = if snapshot_names.is_empty() {
            0
        } else {
            published.iter().try_fold(0_usize, |total, stored| {
                if self
                    .snapshot_message_refs
                    .contains_key(stored.message_id.as_str())
                {
                    Ok(total)
                } else {
                    total
                        .checked_add(Self::snapshot_shared_message_bytes(stored))
                        .ok_or_else(|| {
                            PubSubError::resource_exhausted("snapshot byte count overflow")
                        })
                }
            })?
        };
        let total = self
            .snapshot_retained_bytes
            .checked_add(reference_bytes)
            .and_then(|total| total.checked_add(shared_bytes))
            .filter(|total| *total <= MAX_SNAPSHOT_RETAINED_BYTES)
            .ok_or_else(|| {
                PubSubError::resource_exhausted(format!(
                    "snapshots retain at most {MAX_SNAPSHOT_RETAINED_BYTES} bytes"
                ))
            })?;
        Ok((snapshot_names, total))
    }

    fn retain_snapshot_publication(
        &mut self,
        snapshot_names: &[String],
        published: &[Arc<StoredMessage>],
    ) {
        for snapshot_name in snapshot_names {
            let snapshot = self
                .snapshots
                .get_mut(snapshot_name)
                .expect("active snapshot was collected from the same map");
            for stored in published {
                Arc::make_mut(&mut snapshot.unacknowledged_message_ids)
                    .insert(stored.message_id.clone());
                Arc::make_mut(&mut snapshot.retained_message_ids).insert(stored.message_id.clone());
                Arc::make_mut(&mut snapshot.captured_messages).push(Arc::clone(stored));
            }
        }
        for stored in published {
            if !snapshot_names.is_empty() {
                let refs = self
                    .snapshot_message_refs
                    .entry(stored.message_id.clone())
                    .or_default();
                *refs = refs.saturating_add(snapshot_names.len());
            }
        }
    }

    /// Publishes messages to a topic, fanning them out to every subscription whose filter
    /// admits them. Returns one message id per input message, in order. The topic must exist.
    pub fn publish(
        &mut self,
        topic: &TopicName,
        messages: Vec<PubsubMessage>,
        now: LogicalInstant,
    ) -> Result<Vec<String>> {
        self.publish_shared(topic, messages, now).map(|published| {
            published
                .iter()
                .map(|message| message.message_id.clone())
                .collect()
        })
    }

    /// Publishes messages and returns the shared stored records used by every subscription.
    pub fn publish_shared(
        &mut self,
        topic: &TopicName,
        messages: Vec<PubsubMessage>,
        now: LogicalInstant,
    ) -> Result<Vec<Arc<StoredMessage>>> {
        let prepared = self.prepare_publish(topic, messages, now)?;
        self.commit_prepared(prepared, now)
    }

    /// Delivers up to `max` messages from a subscription. Dead-lettered messages are forwarded
    /// to the subscription's dead-letter topic (when it exists) before returning. The source is
    /// completed only after each destination publication succeeds.
    pub fn pull(
        &mut self,
        name: &SubscriptionName,
        max: usize,
        now: LogicalInstant,
    ) -> Result<Vec<ReceivedMessage>> {
        let outcome = self.pull_with_dead_letters(name, max, now)?;
        for forward in outcome.dead_lettered {
            if self
                .publish(
                    &forward.dead_letter_topic,
                    vec![forward.message.message.clone()],
                    now,
                )
                .is_ok()
            {
                let _ = self.complete_dead_letter(
                    &forward.source_subscription,
                    &forward.message.message_id,
                );
            }
        }
        Ok(outcome.received)
    }

    /// Delivers up to `max` messages and returns newly exhausted messages without attempting the
    /// destination publication. Adapters use this seam to route the transfer through the shared
    /// publication coordinator.
    pub fn pull_with_dead_letters(
        &mut self,
        name: &SubscriptionName,
        max: usize,
        now: LogicalInstant,
    ) -> Result<PullResult> {
        let key = name.to_full();
        if !self.subscriptions.contains_key(&key) {
            return Err(PubSubError::not_found(format!(
                "subscription {key} not found"
            )));
        }
        // Redeliver anything whose deadline lapsed before this pull.
        if let Some(sub) = self.subscriptions.get_mut(&key) {
            sub.expire_deadlines(now);
        }
        let seed_bump = &mut self.ack_rng;
        let outcome = {
            let sub = self
                .subscriptions
                .get_mut(&key)
                .expect("subscription present");
            sub.pull(max, now, || format!("ack-{:016x}", seed_bump.next_u64()))
        };
        let dead_letter_topic = self
            .subscriptions
            .get(&key)
            .and_then(|s| s.config().dead_letter_policy.as_ref())
            .map(|policy| policy.dead_letter_topic.clone());
        let received = outcome.received;
        let dead_lettered = match dead_letter_topic {
            Some(topic) => outcome
                .dead_lettered
                .into_iter()
                .map(|message| DeadLetterForward {
                    source_subscription: name.clone(),
                    dead_letter_topic: topic.clone(),
                    message,
                })
                .collect(),
            None => Vec::new(),
        };
        Ok(PullResult {
            received,
            dead_lettered,
        })
    }

    /// Returns every source message waiting for dead-letter destination admission.
    #[must_use]
    pub fn pending_dead_letters(&self) -> Vec<DeadLetterForward> {
        self.subscriptions
            .values()
            .flat_map(|subscription| {
                let source_subscription = subscription.config().name.clone();
                let dead_letter_topic = subscription
                    .config()
                    .dead_letter_policy
                    .as_ref()
                    .map(|policy| policy.dead_letter_topic.clone());
                subscription
                    .pending_forwards()
                    .into_iter()
                    .filter_map(move |message| {
                        dead_letter_topic
                            .clone()
                            .map(|dead_letter_topic| DeadLetterForward {
                                source_subscription: source_subscription.clone(),
                                dead_letter_topic,
                                message,
                            })
                    })
            })
            .collect()
    }

    /// Marks a dead-letter source message complete after its destination publication succeeds.
    pub fn complete_dead_letter(
        &mut self,
        source_subscription: &SubscriptionName,
        message_id: &str,
    ) -> Result<bool> {
        Ok(self
            .sub_mut(source_subscription)?
            .complete_forward(message_id))
    }

    /// Acknowledges messages on a subscription. Unknown ack ids are ignored.
    pub fn acknowledge(&mut self, name: &SubscriptionName, ack_ids: &[String]) -> Result<usize> {
        Ok(self.sub_mut(name)?.acknowledge(ack_ids))
    }

    /// Modifies the ack deadline of the named messages. Zero seconds nacks (immediate
    /// redelivery). Unknown ack ids are ignored.
    pub fn modify_ack_deadline(
        &mut self,
        name: &SubscriptionName,
        ack_ids: &[String],
        seconds: u32,
        now: LogicalInstant,
    ) -> Result<()> {
        let sub = self.sub_mut(name)?;
        for id in ack_ids {
            sub.modify_ack_deadline(id, seconds, now);
        }
        Ok(())
    }

    /// Seeks a subscription to a point in time.
    pub fn seek_to_time(
        &mut self,
        name: &SubscriptionName,
        time: LogicalInstant,
        now: LogicalInstant,
    ) -> Result<()> {
        self.sub_mut(name)?.seek_to_time(time, now)
    }

    /// Expires lapsed ack deadlines across every subscription. Call on each clock advance so a
    /// later pull redelivers messages whose deadline passed while the clock moved.
    pub fn expire_all(&mut self, now: LogicalInstant) {
        self.remove_expired_snapshots(now);
        for sub in self.subscriptions.values_mut() {
            sub.expire_deadlines(now);
        }
    }

    fn sub_mut(&mut self, name: &SubscriptionName) -> Result<&mut SubscriptionState> {
        let key = name.to_full();
        self.subscriptions
            .get_mut(&key)
            .ok_or_else(|| PubSubError::not_found(format!("subscription {key} not found")))
    }

    /// The topic a subscription reports (the sentinel `_deleted-topic_` once its topic is gone).
    #[must_use]
    pub fn reported_topic(&self, name: &SubscriptionName) -> Option<String> {
        self.subscriptions.get(&name.to_full()).map(|s| {
            let topic = s.config().topic.to_full();
            if self.topics.contains_key(&topic) {
                topic
            } else {
                DELETED_TOPIC.to_owned()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;
    use crate::subscription::{PushConfig, DEFAULT_ACK_DEADLINE_SECONDS};

    fn topic(p: &str, t: &str) -> TopicName {
        TopicName::new(p, t).unwrap()
    }

    fn sub_cfg(p: &str, s: &str, t: &str, filter: Filter) -> SubscriptionConfig {
        SubscriptionConfig {
            name: SubscriptionName::new(p, s).unwrap(),
            topic: TopicName::new(p, t).unwrap(),
            ack_deadline_seconds: DEFAULT_ACK_DEADLINE_SECONDS,
            enable_message_ordering: false,
            filter,
            dead_letter_policy: None,
            retry_policy: None,
            push_config: PushConfig::default(),
        }
    }

    fn data(d: &[u8]) -> PubsubMessage {
        PubsubMessage {
            data: d.to_vec(),
            ..PubsubMessage::default()
        }
    }

    #[test]
    fn publish_then_pull_delivers() {
        let mut s = PubSubState::new(42);
        let now = LogicalInstant::from_unix_seconds(1000);
        s.create_topic(topic("demo-app", "orders"), BTreeMap::new())
            .unwrap();
        s.create_subscription(sub_cfg(
            "demo-app",
            "orders-sub",
            "orders",
            Filter::always(),
        ))
        .unwrap();
        let ids = s
            .publish(&topic("demo-app", "orders"), vec![data(b"hello")], now)
            .unwrap();
        assert_eq!(ids.len(), 1);
        let subscription = SubscriptionName::new("demo-app", "orders-sub").unwrap();
        let msgs = s.pull(&subscription, 10, now).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].message.message.data, b"hello");
        assert_eq!(s.acknowledge(&subscription, &["unknown".to_owned()]), Ok(0));
        assert_eq!(
            s.acknowledge(&subscription, &[msgs[0].ack_id.clone()]),
            Ok(1)
        );

        s.publish(&topic("demo-app", "orders"), vec![data(b"again")], now)
            .unwrap();
        let delivered = s.pull(&subscription, 1, now).unwrap();
        s.modify_ack_deadline(&subscription, &[delivered[0].ack_id.clone()], 0, now)
            .unwrap();
        assert_eq!(s.pull(&subscription, 1, now).unwrap().len(), 1);
    }

    #[test]
    fn subscriptions_share_one_published_message_allocation() {
        let mut state = PubSubState::new(42);
        let now = LogicalInstant::from_unix_seconds(1000);
        let topic = topic("demo-app", "shared");
        state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        let first = SubscriptionName::new("demo-app", "first-sub").unwrap();
        let second = SubscriptionName::new("demo-app", "second-sub").unwrap();
        state
            .create_subscription(sub_cfg("demo-app", "first-sub", "shared", Filter::always()))
            .unwrap();
        state
            .create_subscription(sub_cfg(
                "demo-app",
                "second-sub",
                "shared",
                Filter::always(),
            ))
            .unwrap();

        let published = state
            .publish_shared(&topic, vec![data(b"one allocation")], now)
            .unwrap();
        let first_message = state.pull(&first, 1, now).unwrap();
        let second_message = state.pull(&second, 1, now).unwrap();
        assert!(Arc::ptr_eq(&published[0], &first_message[0].message));
        assert!(Arc::ptr_eq(
            &first_message[0].message,
            &second_message[0].message
        ));
    }

    #[test]
    fn prepared_publication_is_invisible_until_commit() {
        let mut state = PubSubState::new(42);
        let now = LogicalInstant::from_unix_seconds(1000);
        let topic = topic("demo-app", "prepared");
        let subscription = SubscriptionName::new("demo-app", "prepared-sub").unwrap();
        state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        state
            .create_subscription(sub_cfg(
                "demo-app",
                "prepared-sub",
                "prepared",
                Filter::always(),
            ))
            .unwrap();

        let prepared = state
            .prepare_publish(&topic, vec![data(b"held back")], now)
            .unwrap();
        assert_eq!(prepared.published_messages().len(), 1);
        assert!(state.pull(&subscription, 10, now).unwrap().is_empty());

        let published = state.commit_prepared(prepared, now).unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(
            state.pull(&subscription, 10, now).unwrap()[0]
                .message
                .message
                .data,
            b"held back"
        );
    }

    #[test]
    fn function_owned_subscription_is_visible_without_retaining_duplicate_messages() {
        let mut state = PubSubState::new(42);
        let now = LogicalInstant::from_unix_seconds(1000);
        let topic = topic("demo-app", "orders");
        let subscription = SubscriptionName::new("demo-app", "emulator-sub-orders").unwrap();
        state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        state
            .create_subscription(sub_cfg(
                "demo-app",
                "emulator-sub-orders",
                "orders",
                Filter::always(),
            ))
            .unwrap();
        state.mark_function_subscription(&subscription).unwrap();

        state.publish(&topic, vec![data(b"hello")], now).unwrap();

        assert!(state.subscription_config(&subscription).is_ok());
        assert!(state.pull(&subscription, 10, now).unwrap().is_empty());
        state.delete_subscription(&subscription).unwrap();
        assert!(state.subscription_config(&subscription).is_err());
    }

    #[test]
    fn clearing_one_project_preserves_other_project_resources() {
        let mut state = PubSubState::new(42);
        for project in ["demo-a", "demo-b"] {
            state
                .create_topic(topic(project, "orders"), BTreeMap::new())
                .unwrap();
            state
                .create_subscription(sub_cfg(project, "orders-sub", "orders", Filter::always()))
                .unwrap();
        }
        let cross_project = SubscriptionName::new("demo-b", "cross-sub").unwrap();
        let mut cross_project_config = sub_cfg("demo-b", "cross-sub", "orders", Filter::always());
        cross_project_config.topic = topic("demo-a", "orders");
        state.create_subscription(cross_project_config).unwrap();

        state.clear_project("demo-a");

        assert!(!state.topic_exists(&topic("demo-a", "orders")));
        assert!(state.topic_exists(&topic("demo-b", "orders")));
        assert!(state
            .subscription_config(&SubscriptionName::new("demo-a", "orders-sub").unwrap())
            .is_err());
        assert!(state
            .subscription_config(&SubscriptionName::new("demo-b", "orders-sub").unwrap())
            .is_ok());
        assert_eq!(state.reported_topic(&cross_project).unwrap(), DELETED_TOPIC);

        let recreated = topic("demo-a", "orders");
        state
            .create_topic(recreated.clone(), BTreeMap::new())
            .unwrap();
        assert_eq!(state.reported_topic(&cross_project).unwrap(), DELETED_TOPIC);
        state
            .publish(
                &recreated,
                vec![data(b"new topic incarnation")],
                LogicalInstant::from_unix_seconds(1),
            )
            .unwrap();
        assert!(state
            .pull(&cross_project, 10, LogicalInstant::from_unix_seconds(1))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn duplicate_topic_is_already_exists() {
        let mut s = PubSubState::new(1);
        s.create_topic(topic("p1", "top-a"), BTreeMap::new())
            .unwrap();
        assert_eq!(
            s.create_topic(topic("p1", "top-a"), BTreeMap::new())
                .unwrap_err()
                .code(),
            crate::error::Code::AlreadyExists
        );
    }

    #[test]
    fn subscription_needs_topic() {
        let mut s = PubSubState::new(1);
        assert_eq!(
            s.create_subscription(sub_cfg("p1", "sub-a", "missing", Filter::always()))
                .unwrap_err()
                .code(),
            crate::error::Code::NotFound
        );
    }

    #[test]
    fn rejected_subscription_update_does_not_publish_any_candidate_field() {
        let mut state = PubSubState::new(1);
        state
            .create_topic(topic("p1", "top-a"), BTreeMap::new())
            .unwrap();
        let subscription = SubscriptionName::new("p1", "sub-a").unwrap();
        state
            .create_subscription(sub_cfg("p1", "sub-a", "top-a", Filter::always()))
            .unwrap();

        let error = state
            .update_subscription(
                &subscription,
                Some(1),
                Some(PushConfig {
                    push_endpoint: "http://127.0.0.1:8080/candidate".to_owned(),
                }),
            )
            .unwrap_err();

        assert_eq!(error.code(), crate::error::Code::InvalidArgument);
        let config = state.subscription_config(&subscription).unwrap();
        assert_eq!(config.ack_deadline_seconds, DEFAULT_ACK_DEADLINE_SECONDS);
        assert_eq!(config.push_config, PushConfig::default());
    }

    #[test]
    fn filter_drops_non_matching_messages() {
        let mut s = PubSubState::new(7);
        let now = LogicalInstant::from_unix_seconds(1);
        s.create_topic(topic("p", "events"), BTreeMap::new())
            .unwrap();
        s.create_subscription(sub_cfg(
            "p",
            "orders-only",
            "events",
            Filter::parse("attributes.type = \"order\"").unwrap(),
        ))
        .unwrap();
        let mut order = data(b"o");
        order
            .attributes
            .insert("type".to_owned(), "order".to_owned());
        let mut refund = data(b"r");
        refund
            .attributes
            .insert("type".to_owned(), "refund".to_owned());
        s.publish(&topic("p", "events"), vec![order, refund], now)
            .unwrap();
        let got = s
            .pull(&SubscriptionName::new("p", "orders-only").unwrap(), 10, now)
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].message.message.data, b"o");
    }

    #[test]
    fn deleting_topic_leaves_subscription_with_sentinel() {
        let mut s = PubSubState::new(1);
        let topic = topic("p", "top-a");
        let subscription = SubscriptionName::new("p", "sub-a").unwrap();
        s.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        s.create_subscription(sub_cfg("p", "sub-a", "top-a", Filter::always()))
            .unwrap();
        s.delete_topic(&topic).unwrap();
        assert_eq!(s.reported_topic(&subscription).unwrap(), DELETED_TOPIC);

        s.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        assert_eq!(s.reported_topic(&subscription).unwrap(), DELETED_TOPIC);
        s.publish(
            &topic,
            vec![data(b"belongs only to the recreated topic")],
            LogicalInstant::from_unix_seconds(1),
        )
        .unwrap();
        assert!(s
            .pull(&subscription, 10, LogicalInstant::from_unix_seconds(1))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn dead_letters_reach_the_dead_letter_topic() {
        use crate::subscription::{DeadLetterPolicy, MIN_DEAD_LETTER_ATTEMPTS};
        let mut s = PubSubState::new(3);
        let mut now = LogicalInstant::from_unix_seconds(0);
        s.create_topic(topic("p", "main"), BTreeMap::new()).unwrap();
        s.create_topic(topic("p", "dead"), BTreeMap::new()).unwrap();
        let mut cfg = sub_cfg("p", "main-sub", "main", Filter::always());
        cfg.dead_letter_policy = Some(DeadLetterPolicy {
            dead_letter_topic: topic("p", "dead"),
            max_delivery_attempts: MIN_DEAD_LETTER_ATTEMPTS,
        });
        s.create_subscription(cfg).unwrap();
        s.create_subscription(sub_cfg("p", "dead-sub", "dead", Filter::always()))
            .unwrap();
        s.publish(&topic("p", "main"), vec![data(b"poison")], now)
            .unwrap();
        let main_sub = SubscriptionName::new("p", "main-sub").unwrap();
        // Exhaust the delivery budget.
        for _ in 0..MIN_DEAD_LETTER_ATTEMPTS {
            assert_eq!(s.pull(&main_sub, 10, now).unwrap().len(), 1);
            now = now
                .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(11))
                .unwrap();
            s.expire_all(now);
        }
        // The next pull forwards to the dead-letter topic.
        assert!(s.pull(&main_sub, 10, now).unwrap().is_empty());
        let dead = s
            .pull(&SubscriptionName::new("p", "dead-sub").unwrap(), 10, now)
            .unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].message.message.data, b"poison");
    }

    #[test]
    fn dead_letter_forward_remains_pending_until_a_recreated_destination_accepts_it() {
        use crate::subscription::{DeadLetterPolicy, MIN_DEAD_LETTER_ATTEMPTS};
        let mut state = PubSubState::new(4);
        let mut now = LogicalInstant::from_unix_seconds(0);
        let main_topic = topic("p", "main");
        let dead_topic = topic("p", "dead");
        let source = SubscriptionName::new("p", "main-sub").unwrap();
        let dead_sub = SubscriptionName::new("p", "dead-sub").unwrap();
        state
            .create_topic(main_topic.clone(), BTreeMap::new())
            .unwrap();
        state
            .create_topic(dead_topic.clone(), BTreeMap::new())
            .unwrap();
        let mut source_config = sub_cfg("p", "main-sub", "main", Filter::always());
        source_config.dead_letter_policy = Some(DeadLetterPolicy {
            dead_letter_topic: dead_topic.clone(),
            max_delivery_attempts: MIN_DEAD_LETTER_ATTEMPTS,
        });
        state.create_subscription(source_config).unwrap();
        state
            .create_subscription(sub_cfg("p", "dead-sub", "dead", Filter::always()))
            .unwrap();
        state
            .publish(&main_topic, vec![data(b"recoverable poison")], now)
            .unwrap();

        for _ in 0..MIN_DEAD_LETTER_ATTEMPTS {
            assert_eq!(state.pull(&source, 10, now).unwrap().len(), 1);
            now = now
                .checked_add(fireemu_core_types::time::LogicalDuration::from_seconds(11))
                .unwrap();
            state.expire_all(now);
        }
        state.delete_topic(&dead_topic).unwrap();
        assert!(state.pull(&source, 10, now).unwrap().is_empty());
        assert_eq!(state.pending_dead_letters().len(), 1);
        assert!(state.pull(&source, 10, now).unwrap().is_empty());

        state.delete_subscription(&dead_sub).unwrap();
        state
            .create_topic(dead_topic.clone(), BTreeMap::new())
            .unwrap();
        state
            .create_subscription(sub_cfg("p", "dead-sub", "dead", Filter::always()))
            .unwrap();

        let pending = state.pending_dead_letters();
        assert_eq!(pending.len(), 1);
        let forward = &pending[0];
        state
            .publish(
                &forward.dead_letter_topic,
                vec![forward.message.message.clone()],
                now,
            )
            .unwrap();
        assert!(state
            .complete_dead_letter(&forward.source_subscription, &forward.message.message_id)
            .unwrap());
        assert!(state.pending_dead_letters().is_empty());
        let dead = state.pull(&dead_sub, 10, now).unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].message.message.data, b"recoverable poison");
    }

    #[test]
    fn ack_ids_are_deterministic_under_seed() {
        let run = || {
            let mut s = PubSubState::new(99);
            let now = LogicalInstant::from_unix_seconds(0);
            s.create_topic(topic("p", "top-a"), BTreeMap::new())
                .unwrap();
            s.create_subscription(sub_cfg("p", "sub-a", "top-a", Filter::always()))
                .unwrap();
            s.publish(&topic("p", "top-a"), vec![data(b"a"), data(b"b")], now)
                .unwrap();
            s.pull(&SubscriptionName::new("p", "sub-a").unwrap(), 10, now)
                .unwrap()
                .into_iter()
                .map(|r| r.ack_id)
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn snapshots_replay_the_unacknowledged_backlog_and_messages_published_after_creation() {
        let mut state = PubSubState::new(11);
        let topic = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let replay = SubscriptionName::new("p", "replay-sub").unwrap();
        let before = LogicalInstant::from_unix_seconds(1000);
        let snapshot_time = LogicalInstant::from_unix_seconds(1001);
        let after = LogicalInstant::from_unix_seconds(1002);
        state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        state
            .publish(&topic, vec![data(b"acked"), data(b"backlog")], before)
            .unwrap();

        let source_messages = state.pull(&source, 10, before).unwrap();
        assert_eq!(source_messages.len(), 2);
        state
            .acknowledge(&source, &[source_messages[0].ack_id.clone()])
            .unwrap();
        let snapshot_name = "projects/p/snapshots/checkpoint";
        state
            .create_snapshot(snapshot_name, &source, BTreeMap::new(), snapshot_time)
            .unwrap();
        state.publish(&topic, vec![data(b"future")], after).unwrap();
        state.delete_subscription(&source).unwrap();
        state
            .create_subscription(sub_cfg("p", "replay-sub", "events", Filter::always()))
            .unwrap();
        state
            .seek_to_snapshot(&replay, snapshot_name, after)
            .unwrap();

        let replayed = state.pull(&replay, 10, after).unwrap();
        let bodies = replayed
            .iter()
            .map(|message| message.message.message.data.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(bodies, vec![b"backlog".as_slice(), b"future".as_slice()]);
        assert_eq!(state.list_snapshots("p", after).len(), 1);
    }

    #[test]
    fn seeking_a_snapshot_applies_the_target_filter_to_captured_messages() {
        let mut state = PubSubState::new(12);
        let topic = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let replay = SubscriptionName::new("p", "replay-sub").unwrap();
        let created_at = LogicalInstant::from_unix_seconds(100);
        state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        state
            .publish(
                &topic,
                vec![
                    PubsubMessage {
                        attributes: BTreeMap::from([("kind".to_owned(), "keep".to_owned())]),
                        data: b"keep".to_vec(),
                        ..PubsubMessage::default()
                    },
                    PubsubMessage {
                        attributes: BTreeMap::from([("kind".to_owned(), "drop".to_owned())]),
                        data: b"drop".to_vec(),
                        ..PubsubMessage::default()
                    },
                ],
                created_at,
            )
            .unwrap();
        state
            .create_snapshot(
                "projects/p/snapshots/filtered",
                &source,
                BTreeMap::new(),
                created_at,
            )
            .unwrap();
        state
            .publish(
                &topic,
                vec![
                    PubsubMessage {
                        attributes: BTreeMap::from([("kind".to_owned(), "keep".to_owned())]),
                        data: b"future-keep".to_vec(),
                        ..PubsubMessage::default()
                    },
                    PubsubMessage {
                        attributes: BTreeMap::from([("kind".to_owned(), "drop".to_owned())]),
                        data: b"future-drop".to_vec(),
                        ..PubsubMessage::default()
                    },
                ],
                created_at,
            )
            .unwrap();
        state.delete_subscription(&source).unwrap();
        state
            .create_subscription(sub_cfg(
                "p",
                "replay-sub",
                "events",
                Filter::parse("attributes.kind = \"keep\"").unwrap(),
            ))
            .unwrap();

        state
            .seek_to_snapshot(&replay, "projects/p/snapshots/filtered", created_at)
            .unwrap();
        let messages = state.pull(&replay, 10, created_at).unwrap();
        let bodies = messages
            .iter()
            .map(|message| message.message.message.data.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(bodies, [b"keep".as_slice(), b"future-keep".as_slice()]);
    }

    #[test]
    fn snapshot_retention_is_released_at_deletion_and_ttl_boundary() {
        let mut state = PubSubState::new(13);
        let topic_name = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let created_at = LogicalInstant::from_unix_seconds(100);
        state
            .create_topic(topic_name.clone(), BTreeMap::new())
            .unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        state
            .publish(&topic_name, vec![data(b"retained")], created_at)
            .unwrap();

        let deleted = "projects/p/snapshots/deleted";
        state
            .create_snapshot(deleted, &source, BTreeMap::new(), created_at)
            .unwrap();
        assert!(state.snapshot_retained_bytes > 0);
        state.delete_snapshot(deleted, created_at).unwrap();
        assert_eq!(state.snapshot_retained_bytes, 0);

        let expiring = "projects/p/snapshots/expiring";
        state
            .create_snapshot(expiring, &source, BTreeMap::new(), created_at)
            .unwrap();
        let expires_at = created_at
            .checked_add(LogicalDuration::from_seconds(SNAPSHOT_TTL_SECONDS))
            .unwrap();
        state.expire_all(expires_at);
        assert!(state.get_snapshot(expiring, expires_at).is_err());
        assert_eq!(state.snapshot_retained_bytes, 0);
    }

    #[test]
    fn a_snapshot_cannot_cross_a_deleted_and_recreated_topic_incarnation() {
        let mut state = PubSubState::new(18);
        let topic_name = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let target = SubscriptionName::new("p", "target-sub").unwrap();
        let now = LogicalInstant::from_unix_seconds(100);
        state
            .create_topic(topic_name.clone(), BTreeMap::new())
            .unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        state.publish(&topic_name, vec![data(b"old")], now).unwrap();
        let snapshot_name = "projects/p/snapshots/old-incarnation";
        state
            .create_snapshot(snapshot_name, &source, BTreeMap::new(), now)
            .unwrap();

        state.delete_topic(&topic_name).unwrap();
        state
            .create_topic(topic_name.clone(), BTreeMap::new())
            .unwrap();
        state.publish(&topic_name, vec![data(b"new")], now).unwrap();
        state
            .create_subscription(sub_cfg("p", "target-sub", "events", Filter::always()))
            .unwrap();

        assert!(state
            .list_topic_snapshots(&topic_name, now)
            .unwrap()
            .is_empty());
        assert_eq!(
            state
                .seek_to_snapshot(&target, snapshot_name, now)
                .unwrap_err()
                .code(),
            crate::error::Code::FailedPrecondition
        );
    }

    #[test]
    fn cross_project_snapshot_is_owned_by_its_resource_project() {
        let mut state = PubSubState::new(17);
        let topic_name = topic("source-project", "events");
        let source = SubscriptionName::new("consumer-project", "source-sub").unwrap();
        let now = LogicalInstant::from_unix_seconds(100);
        state
            .create_topic(topic_name.clone(), BTreeMap::new())
            .unwrap();
        let mut config = sub_cfg("consumer-project", "source-sub", "events", Filter::always());
        config.topic = topic_name.clone();
        state.create_subscription(config).unwrap();
        state
            .publish(&topic_name, vec![data(b"retained")], now)
            .unwrap();
        let snapshot_name = "projects/consumer-project/snapshots/cross-project";
        state
            .create_snapshot(snapshot_name, &source, BTreeMap::new(), now)
            .unwrap();

        assert_eq!(state.list_snapshots("consumer-project", now).len(), 1);
        assert!(state.list_snapshots("source-project", now).is_empty());
        assert_eq!(
            state.list_topic_snapshots(&topic_name, now).unwrap(),
            [snapshot_name.to_owned()]
        );
        let cross_target = SubscriptionName::new("other-project", "target-sub").unwrap();
        let mut target_config = sub_cfg("other-project", "target-sub", "events", Filter::always());
        target_config.topic = topic_name.clone();
        state.create_subscription(target_config).unwrap();
        state
            .seek_to_snapshot(&cross_target, snapshot_name, now)
            .unwrap();
        assert_eq!(state.pull(&cross_target, 10, now).unwrap().len(), 1);
        state.clear_project("source-project");
        assert!(state.get_snapshot(snapshot_name, now).is_ok());
        state.clear_project("consumer-project");
        assert!(state.get_snapshot(snapshot_name, now).is_err());
        assert_eq!(state.snapshot_retained_bytes, 0);
    }

    #[test]
    fn snapshot_lifetime_uses_the_oldest_unacknowledged_message_age() {
        const HOUR: i64 = 60 * 60;
        let seven_days = LogicalDuration::from_seconds(SNAPSHOT_TTL_SECONDS);
        let now = LogicalInstant::from_unix_seconds(SNAPSHOT_TTL_SECONDS + 100);

        let empty_lifetime = |name: &str| {
            let mut state = PubSubState::new(14);
            let topic_name = topic("p", "events");
            let source = SubscriptionName::new("p", "source-sub").unwrap();
            state.create_topic(topic_name, BTreeMap::new()).unwrap();
            state
                .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
                .unwrap();
            state
                .create_snapshot(name, &source, BTreeMap::new(), now)
                .unwrap()
                .expire_at
        };
        assert_eq!(
            empty_lifetime("projects/p/snapshots/empty"),
            now.checked_add(seven_days).unwrap()
        );

        for (suffix, remaining_nanos, accepted) in [
            ("before", i128::from(HOUR) * 1_000_000_000 + 1, true),
            ("exact", i128::from(HOUR) * 1_000_000_000, true),
            ("after", i128::from(HOUR) * 1_000_000_000 - 1, false),
        ] {
            let mut state = PubSubState::new(15);
            let topic_name = topic("p", "events");
            let source = SubscriptionName::new("p", "source-sub").unwrap();
            state
                .create_topic(topic_name.clone(), BTreeMap::new())
                .unwrap();
            state
                .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
                .unwrap();
            let age_nanos = seven_days.as_nanos() - remaining_nanos;
            let published_at = LogicalInstant::from_nanos(now.as_nanos() - age_nanos);
            state
                .publish(&topic_name, vec![data(b"oldest")], published_at)
                .unwrap();
            let result = state.create_snapshot(
                &format!("projects/p/snapshots/{suffix}"),
                &source,
                BTreeMap::new(),
                now,
            );
            assert_eq!(result.is_ok(), accepted, "{suffix}");
            if let Ok(snapshot) = result {
                assert_eq!(
                    snapshot.expire_at,
                    LogicalInstant::from_nanos(now.as_nanos() + remaining_nanos)
                );
            }
        }

        let mut rejected_state = PubSubState::new(15);
        let topic_name = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        rejected_state
            .create_topic(topic_name.clone(), BTreeMap::new())
            .unwrap();
        rejected_state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        let too_old = LogicalInstant::from_nanos(
            now.as_nanos() - seven_days.as_nanos() + i128::from(HOUR) * 1_000_000_000 - 1,
        );
        rejected_state
            .publish(&topic_name, vec![data(b"too old")], too_old)
            .unwrap();
        assert!(rejected_state
            .create_snapshot("", &source, BTreeMap::new(), now)
            .is_err());
        assert!(rejected_state.snapshots.is_empty());
        assert_eq!(rejected_state.snapshot_retained_bytes, 0);
        let ack_id = rejected_state.pull(&source, 1, now).unwrap()[0]
            .ack_id
            .clone();
        rejected_state.acknowledge(&source, &[ack_id]).unwrap();
        let generated = rejected_state
            .create_snapshot("", &source, BTreeMap::new(), now)
            .unwrap();
        assert_eq!(generated.name, "projects/p/snapshots/snapshot-1");
    }

    #[test]
    fn acknowledged_old_messages_do_not_shorten_snapshot_lifetime() {
        let mut state = PubSubState::new(14);
        let topic_name = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let now = LogicalInstant::from_unix_seconds(SNAPSHOT_TTL_SECONDS + 100);
        state
            .create_topic(topic_name.clone(), BTreeMap::new())
            .unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        state
            .publish(
                &topic_name,
                vec![data(b"old but acknowledged")],
                LogicalInstant::from_unix_seconds(1),
            )
            .unwrap();
        let ack_id = state.pull(&source, 1, now).unwrap()[0].ack_id.clone();
        state.acknowledge(&source, &[ack_id]).unwrap();

        let snapshot = state
            .create_snapshot(
                "projects/p/snapshots/acked-only",
                &source,
                BTreeMap::new(),
                now,
            )
            .unwrap();

        assert_eq!(
            snapshot.expire_at,
            now.checked_add(LogicalDuration::from_seconds(SNAPSHOT_TTL_SECONDS))
                .unwrap()
        );
    }

    #[test]
    fn snapshot_capacity_rejection_does_not_publish_to_any_subscription() {
        let mut state = PubSubState::new(16);
        let topic_name = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let now = LogicalInstant::from_unix_seconds(100);
        state
            .create_topic(topic_name.clone(), BTreeMap::new())
            .unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        state
            .publish(&topic_name, vec![data(&vec![b'a'; 8 * 1024 * 1024])], now)
            .unwrap();
        for index in 0..7 {
            state
                .create_snapshot(
                    &format!("projects/p/snapshots/snapshot-{index}"),
                    &source,
                    BTreeMap::new(),
                    now,
                )
                .unwrap();
        }
        let retained_before_failures = state.snapshot_retained_bytes;
        assert!(
            retained_before_failures < 9 * 1024 * 1024,
            "the 8 MiB payload must be charged once, not once per snapshot"
        );
        state
            .update_snapshot(
                "projects/p/snapshots/snapshot-0",
                BTreeMap::from([("environment".to_owned(), "test".to_owned())]),
                now,
            )
            .unwrap();
        assert!(state.snapshot_retained_bytes > retained_before_failures);
        state
            .update_snapshot("projects/p/snapshots/snapshot-0", BTreeMap::new(), now)
            .unwrap();
        assert!(state
            .get_snapshot("projects/p/snapshots/snapshot-0", now)
            .unwrap()
            .labels
            .is_empty());
        assert_eq!(state.snapshot_retained_bytes, retained_before_failures);
        for index in 7..1_000 {
            state
                .create_snapshot(
                    &format!("projects/p/snapshots/snapshot-{index}"),
                    &source,
                    BTreeMap::new(),
                    now,
                )
                .unwrap();
        }
        let retained_before_failures = state.snapshot_retained_bytes;
        let observers = [
            SubscriptionName::new("p", "observer-a").unwrap(),
            SubscriptionName::new("p", "observer-b").unwrap(),
        ];
        for observer in &observers {
            state
                .create_subscription(sub_cfg(
                    "p",
                    observer.subscription(),
                    "events",
                    Filter::always(),
                ))
                .unwrap();
        }

        let error = state
            .publish(&topic_name, vec![data(b"b"); 1_000], now)
            .unwrap_err();
        assert_eq!(error.code(), crate::error::Code::ResourceExhausted);
        assert_eq!(state.snapshot_retained_bytes, retained_before_failures);
        for observer in &observers {
            assert!(state.pull(observer, 10, now).unwrap().is_empty());
        }
        for index in 0..1_000 {
            state
                .delete_snapshot(&format!("projects/p/snapshots/snapshot-{index}"), now)
                .unwrap();
        }
        let published = state
            .publish_shared(&topic_name, vec![data(b"accepted")], now)
            .unwrap();
        assert_eq!(published[0].message_id, "2");
        for observer in &observers {
            let received = state.pull(observer, 10, now).unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(received[0].message.message.data, b"accepted");
        }
    }

    #[test]
    fn snapshot_count_limit_rejects_without_changing_existing_snapshots() {
        let mut state = PubSubState::new(18);
        let topic_name = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let now = LogicalInstant::from_unix_seconds(100);
        state.create_topic(topic_name, BTreeMap::new()).unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        for index in 0..MAX_SNAPSHOTS {
            state
                .create_snapshot(
                    &format!("projects/p/snapshots/snapshot-{index}"),
                    &source,
                    BTreeMap::new(),
                    now,
                )
                .unwrap();
        }
        let retained = state.snapshot_retained_bytes;
        let error = state
            .create_snapshot(
                "projects/p/snapshots/one-too-many",
                &source,
                BTreeMap::new(),
                now,
            )
            .unwrap_err();
        assert_eq!(error.code(), crate::error::Code::ResourceExhausted);
        assert_eq!(state.snapshots.len(), MAX_SNAPSHOTS);
        assert_eq!(state.snapshot_retained_bytes, retained);
    }

    #[test]
    fn generated_snapshot_names_skip_explicit_collisions() {
        let mut state = PubSubState::new(19);
        let topic_name = topic("p", "events");
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let now = LogicalInstant::from_unix_seconds(100);
        state.create_topic(topic_name, BTreeMap::new()).unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "events", Filter::always()))
            .unwrap();
        state
            .create_snapshot(
                "projects/p/snapshots/snapshot-1",
                &source,
                BTreeMap::new(),
                now,
            )
            .unwrap();

        let first = state
            .create_snapshot("", &source, BTreeMap::new(), now)
            .unwrap();
        let second = state
            .create_snapshot("", &source, BTreeMap::new(), now)
            .unwrap();
        assert_eq!(first.name, "projects/p/snapshots/snapshot-2");
        assert_eq!(second.name, "projects/p/snapshots/snapshot-3");
    }

    #[test]
    fn failed_seek_and_pre_seek_ack_ids_cannot_mutate_the_resulting_generation() {
        let mut state = PubSubState::new(19);
        let now = LogicalInstant::from_unix_seconds(100);
        let first_topic = topic("p", "first");
        let second_topic = topic("p", "second");
        for topic in [&first_topic, &second_topic] {
            state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        }
        let source = SubscriptionName::new("p", "source-sub").unwrap();
        let target = SubscriptionName::new("p", "target-sub").unwrap();
        let wrong_target = SubscriptionName::new("p", "wrong-target").unwrap();
        state
            .create_subscription(sub_cfg("p", "source-sub", "first", Filter::always()))
            .unwrap();
        state
            .create_subscription(sub_cfg("p", "target-sub", "first", Filter::always()))
            .unwrap();
        state
            .create_subscription(sub_cfg("p", "wrong-target", "second", Filter::always()))
            .unwrap();
        state
            .publish(&first_topic, vec![data(b"restored")], now)
            .unwrap();
        state
            .publish(&second_topic, vec![data(b"unchanged")], now)
            .unwrap();
        let old_target_ack = state.pull(&target, 1, now).unwrap()[0].ack_id.clone();
        let wrong_target_ack = state.pull(&wrong_target, 1, now).unwrap()[0].ack_id.clone();
        let snapshot = "projects/p/snapshots/generation";
        state
            .create_snapshot(snapshot, &source, BTreeMap::new(), now)
            .unwrap();

        let error = state
            .seek_to_snapshot(&wrong_target, snapshot, now)
            .unwrap_err();
        assert_eq!(error.code(), crate::error::Code::FailedPrecondition);
        assert_eq!(
            state
                .acknowledge(&wrong_target, &[wrong_target_ack])
                .unwrap(),
            1
        );

        state.seek_to_snapshot(&target, snapshot, now).unwrap();
        assert_eq!(
            state
                .acknowledge(&target, std::slice::from_ref(&old_target_ack))
                .unwrap(),
            0
        );
        state
            .modify_ack_deadline(&target, &[old_target_ack], 0, now)
            .unwrap();
        let restored = state.pull(&target, 1, now).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].message.message.data, b"restored");
    }

    #[test]
    fn resources_report_owned_subscriptions_and_unacknowledged_messages() {
        use fireemu_core_types::resources::RootBudget;
        let mut s = PubSubState::new(42);
        let now = LogicalInstant::from_unix_seconds(1000);
        for project in ["demo-app", "demo-other"] {
            s.create_topic(topic(project, "orders"), BTreeMap::new())
                .unwrap();
            s.create_subscription(sub_cfg(project, "orders-sub", "orders", Filter::always()))
                .unwrap();
            s.publish(
                &topic(project, "orders"),
                vec![data(b"hello"), data(b"world!")],
                now,
            )
            .unwrap();
        }
        s.create_subscription(sub_cfg("demo-app", "idle-sub", "orders", Filter::always()))
            .unwrap();

        let mine = |project: &str| project == "demo-app";
        let report = s.resources(&mine, false, RootBudget::DEFAULT);
        assert_eq!(report.service, "pubsub");
        let gauge = |id: &str| report.gauges.iter().find(|g| g.id == id).unwrap().clone();
        assert_eq!(gauge("topics").current, 1);
        assert_eq!(gauge("subscriptions").current, 2);
        assert_eq!(gauge("subscriptions").limit, Some(MAX_SUBSCRIPTIONS as u64));
        assert_eq!(gauge("unacked.messages").current, 2);
        assert_eq!(gauge("unacked.bytes").current, 11);
        assert!(
            report
                .gauges
                .iter()
                .all(|g| g.id != "snapshots.retained_bytes"),
            "the daemon-wide snapshot total is reported to the default session only"
        );
        assert_eq!(report.roots.total, 1);
        let root = &report.roots.roots[0];
        assert_eq!(root.kind, "unacked");
        assert_eq!(root.id, "projects/demo-app/subscriptions/orders-sub");
        assert_eq!(root.count, 2);
        assert!(root.outstanding);

        let subscription = SubscriptionName::new("demo-app", "orders-sub").unwrap();
        let pulled = s.pull(&subscription, 10, now).unwrap();
        let acks: Vec<String> = pulled.iter().map(|m| m.ack_id.clone()).collect();
        assert_eq!(s.acknowledge(&subscription, &acks), Ok(2));
        let quiet = s.resources(&mine, true, RootBudget::DEFAULT);
        assert_eq!(quiet.roots.total, 0);
        let retained = quiet
            .gauges
            .iter()
            .find(|g| g.id == "retained.bytes")
            .unwrap();
        assert_eq!(
            retained.current, 11,
            "acknowledged payloads stay retained until reclaimed"
        );
        assert_eq!(retained.reclaimable, 11);
        assert!(quiet
            .gauges
            .iter()
            .any(|g| g.id == "snapshots.retained_bytes"
                && g.limit == Some(MAX_SNAPSHOT_RETAINED_BYTES as u64)));
    }
}
