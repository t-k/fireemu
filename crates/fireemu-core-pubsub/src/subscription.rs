//! Subscription configuration and the per-subscription delivery state machine.
//!
//! A subscription owns an ordered log of the messages published to its topic while it existed.
//! Each entry is `Available`, `Outstanding` (delivered, awaiting ack) or `Acked`. Delivery,
//! acknowledgement, nack, ack-deadline extension, redelivery of expired messages and seek all
//! run against an explicit [`LogicalInstant`]; the state machine never reads a clock itself, so
//! redelivery timing is driven by the virtual clock the rest of fireemu uses.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::error::{PubSubError, Result};
use crate::filter::Filter;
use crate::message::StoredMessage;
use crate::name::{SubscriptionName, TopicName};

/// Default ack deadline, in seconds.
pub const DEFAULT_ACK_DEADLINE_SECONDS: u32 = 10;
/// Inclusive minimum ack deadline, in seconds.
pub const MIN_ACK_DEADLINE_SECONDS: u32 = 10;
/// Inclusive maximum ack deadline, in seconds.
pub const MAX_ACK_DEADLINE_SECONDS: u32 = 600;
/// Inclusive minimum `max_delivery_attempts` for a dead-letter policy.
pub const MIN_DEAD_LETTER_ATTEMPTS: u32 = 5;
/// Inclusive maximum `max_delivery_attempts` for a dead-letter policy.
pub const MAX_DEAD_LETTER_ATTEMPTS: u32 = 100;
/// Default retry minimum backoff when a policy omits the field.
pub const DEFAULT_RETRY_MINIMUM_BACKOFF_SECONDS: i64 = 10;
/// Default and maximum retry maximum backoff.
pub const MAX_RETRY_BACKOFF_SECONDS: i64 = 600;
/// Upper bound on the number of retained entries a single subscription keeps in memory.
pub const MAX_RETAINED_PER_SUB: usize = 100_000;
/// Upper bound on message bytes retained by one subscription.
pub const MAX_RETAINED_BYTES_PER_SUB: usize = 1024 * 1024 * 1024;

/// A dead-letter policy: after `max_delivery_attempts` failed deliveries a message is forwarded
/// to `dead_letter_topic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetterPolicy {
    /// The topic that receives exhausted messages.
    pub dead_letter_topic: TopicName,
    /// The delivery-attempt count at which forwarding happens.
    pub max_delivery_attempts: u32,
}

/// A retry policy: the backoff applied before a nacked or expired message is redelivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Minimum backoff before redelivery.
    pub minimum_backoff: LogicalDuration,
    /// Maximum backoff before redelivery.
    pub maximum_backoff: LogicalDuration,
}

/// A push delivery configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PushConfig {
    /// The endpoint messages are delivered to by HTTP POST; empty means this is a pull subscription.
    pub push_endpoint: String,
}

/// Validated subscription configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionConfig {
    /// The subscription's own name.
    pub name: SubscriptionName,
    /// The topic it is attached to.
    pub topic: TopicName,
    /// Ack deadline, in seconds.
    pub ack_deadline_seconds: u32,
    /// Whether ordering keys are honoured.
    pub enable_message_ordering: bool,
    /// The attribute filter; [`Filter::always`] when unset.
    pub filter: Filter,
    /// The dead-letter policy, if any.
    pub dead_letter_policy: Option<DeadLetterPolicy>,
    /// The retry policy, if any.
    pub retry_policy: Option<RetryPolicy>,
    /// The push configuration; empty endpoint means pull.
    pub push_config: PushConfig,
}

impl SubscriptionConfig {
    /// Validates the numeric fields of the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.ack_deadline_seconds < MIN_ACK_DEADLINE_SECONDS
            || self.ack_deadline_seconds > MAX_ACK_DEADLINE_SECONDS
        {
            return Err(PubSubError::invalid_argument(format!(
                "ackDeadlineSeconds must be {MIN_ACK_DEADLINE_SECONDS}..={MAX_ACK_DEADLINE_SECONDS}"
            )));
        }
        if let Some(dl) = &self.dead_letter_policy {
            if dl.max_delivery_attempts < MIN_DEAD_LETTER_ATTEMPTS
                || dl.max_delivery_attempts > MAX_DEAD_LETTER_ATTEMPTS
            {
                return Err(PubSubError::invalid_argument(format!(
                    "maxDeliveryAttempts must be {MIN_DEAD_LETTER_ATTEMPTS}..={MAX_DEAD_LETTER_ATTEMPTS}"
                )));
            }
        }
        if let Some(rp) = &self.retry_policy {
            let maximum = LogicalDuration::from_seconds(MAX_RETRY_BACKOFF_SECONDS);
            if rp.minimum_backoff.as_nanos() < 0
                || rp.maximum_backoff.as_nanos() < 0
                || rp.minimum_backoff > maximum
                || rp.maximum_backoff > maximum
            {
                return Err(PubSubError::invalid_argument(
                    "retry policy backoff must be between 0 and 600 seconds",
                ));
            }
            if rp.minimum_backoff > rp.maximum_backoff {
                return Err(PubSubError::invalid_argument(
                    "retry policy minimumBackoff must not exceed maximumBackoff",
                ));
            }
        }
        Ok(())
    }

    /// Whether this is a push subscription.
    #[must_use]
    pub fn is_push(&self) -> bool {
        !self.push_config.push_endpoint.is_empty()
    }

    fn ack_deadline(&self) -> LogicalDuration {
        LogicalDuration::from_seconds(i64::from(self.ack_deadline_seconds))
    }

    fn redelivery_backoff(&self, delivery_attempt: u32) -> LogicalDuration {
        let Some(policy) = self.retry_policy else {
            return LogicalDuration::ZERO;
        };
        if policy.minimum_backoff == LogicalDuration::ZERO
            || policy.maximum_backoff == LogicalDuration::ZERO
        {
            return LogicalDuration::ZERO;
        }

        let mut backoff = policy.minimum_backoff;
        let steps = delivery_attempt.saturating_sub(1).min(127);
        for _ in 0..steps {
            if backoff >= policy.maximum_backoff {
                break;
            }
            let doubled = backoff.as_nanos().saturating_mul(2);
            backoff = LogicalDuration::from_nanos(doubled.min(policy.maximum_backoff.as_nanos()));
        }
        backoff
    }
}

/// The delivery state of one retained message.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Delivery {
    /// Not currently delivered; becomes deliverable once the clock reaches `available_at`.
    Available { available_at: LogicalInstant },
    /// Delivered and awaiting acknowledgement.
    Outstanding {
        ack_id: String,
        deadline: LogicalInstant,
    },
    /// Acknowledged (kept for seek).
    Acked,
    /// Exhausted and waiting for dead-letter destination admission.
    ForwardPending,
}

#[derive(Debug, Clone)]
struct Entry {
    stored: Arc<StoredMessage>,
    state: Delivery,
    /// How many times this message has been handed to a subscriber.
    delivery_attempt: u32,
}

/// A message returned by a pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// The ack id the subscriber uses to acknowledge or nack.
    pub ack_id: String,
    /// The message.
    pub message: Arc<StoredMessage>,
    /// 1-based delivery attempt.
    pub delivery_attempt: u32,
}

/// The result of a pull: messages handed to the subscriber plus any messages that exhausted
/// their dead-letter budget and must be forwarded to the dead-letter topic by the registry.
#[derive(Debug, Clone, Default)]
pub struct PullOutcome {
    /// Messages delivered to the caller.
    pub received: Vec<ReceivedMessage>,
    /// Messages to forward to the subscription's dead-letter topic (registry does the publish).
    pub dead_lettered: Vec<Arc<StoredMessage>>,
}

/// The live state of one subscription: its configuration plus its message log.
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    config: SubscriptionConfig,
    entries: Vec<Entry>,
    first_unacked: usize,
    outstanding: BTreeMap<String, usize>,
    retained_bytes: usize,
}

impl SubscriptionState {
    /// Creates an empty subscription from validated configuration.
    #[must_use]
    pub fn new(config: SubscriptionConfig) -> Self {
        Self {
            config,
            entries: Vec::new(),
            first_unacked: 0,
            outstanding: BTreeMap::new(),
            retained_bytes: 0,
        }
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &SubscriptionConfig {
        &self.config
    }

    /// Replaces the mutable configuration fields on an update (ack deadline, filter is fixed).
    pub fn set_ack_deadline(&mut self, seconds: u32) {
        self.config.ack_deadline_seconds = seconds;
    }

    /// Sets the push configuration (used by `ModifyPushConfig`).
    pub fn set_push_config(&mut self, push: PushConfig) {
        self.config.push_config = push;
    }

    /// Permanently detaches this subscription from a deleted topic incarnation.
    pub fn mark_topic_deleted(&mut self) {
        self.config.topic = TopicName::parse(crate::name::DELETED_TOPIC)
            .expect("the deleted-topic sentinel is always valid");
    }

    fn message_bytes(stored: &StoredMessage) -> usize {
        stored
            .message
            .data
            .len()
            .saturating_add(stored.message.ordering_key.len())
            .saturating_add(
                stored
                    .message
                    .attributes
                    .iter()
                    .map(|(key, value)| key.len().saturating_add(value.len()))
                    .sum::<usize>(),
            )
    }

    fn rebuild_indexes(&mut self) {
        self.first_unacked = self
            .entries
            .iter()
            .position(|entry| entry.state != Delivery::Acked)
            .unwrap_or(self.entries.len());
        self.outstanding.clear();
        for (index, entry) in self.entries.iter().enumerate() {
            if let Delivery::Outstanding { ack_id, .. } = &entry.state {
                self.outstanding.insert(ack_id.clone(), index);
            }
        }
        self.retained_bytes = self
            .entries
            .iter()
            .map(|entry| Self::message_bytes(&entry.stored))
            .sum();
    }

    fn advance_first_unacked(&mut self) {
        while self
            .entries
            .get(self.first_unacked)
            .is_some_and(|entry| entry.state == Delivery::Acked)
        {
            self.first_unacked += 1;
        }
    }

    fn reclaim_acked_entries(&mut self) {
        self.entries.retain(|entry| entry.state != Delivery::Acked);
        self.rebuild_indexes();
    }

    /// Checks whether a whole publish batch can be appended without partial mutation.
    pub fn ensure_enqueue_capacity<'a>(
        &self,
        mut messages: impl Iterator<Item = &'a StoredMessage>,
    ) -> Result<()> {
        let (additional_count, additional_bytes) =
            messages.try_fold((0_usize, 0_usize), |(count, bytes), message| {
                Ok::<_, PubSubError>((
                    count.checked_add(1).ok_or_else(|| {
                        PubSubError::resource_exhausted("subscription entry count overflow")
                    })?,
                    bytes
                        .checked_add(Self::message_bytes(message))
                        .ok_or_else(|| {
                            PubSubError::resource_exhausted("subscription byte count overflow")
                        })?,
                ))
            })?;
        let fits = |count: usize, bytes: usize| {
            count
                .checked_add(additional_count)
                .is_some_and(|total| total <= MAX_RETAINED_PER_SUB)
                && bytes
                    .checked_add(additional_bytes)
                    .is_some_and(|total| total <= MAX_RETAINED_BYTES_PER_SUB)
        };
        if fits(self.entries.len(), self.retained_bytes) {
            return Ok(());
        }
        let (acked_count, acked_bytes) = self
            .entries
            .iter()
            .filter(|entry| entry.state == Delivery::Acked)
            .fold((0_usize, 0_usize), |(count, bytes), entry| {
                (
                    count.saturating_add(1),
                    bytes.saturating_add(Self::message_bytes(&entry.stored)),
                )
            });
        if fits(
            self.entries.len().saturating_sub(acked_count),
            self.retained_bytes.saturating_sub(acked_bytes),
        ) {
            return Ok(());
        }
        Err(PubSubError::resource_exhausted(format!(
            "subscription {} cannot retain the complete publish batch",
            self.config.name.to_full()
        )))
    }

    /// Appends a message that already passed the subscription filter. Returns
    /// `RESOURCE_EXHAUSTED` when the retention bound is reached and no acked entry can be
    /// reclaimed.
    pub fn enqueue(
        &mut self,
        stored: impl Into<Arc<StoredMessage>>,
        now: LogicalInstant,
    ) -> Result<()> {
        let stored = stored.into();
        let message_bytes = Self::message_bytes(&stored);
        let exceeds_entry_limit = self.entries.len() >= MAX_RETAINED_PER_SUB;
        let exceeds_byte_limit = self
            .retained_bytes
            .checked_add(message_bytes)
            .is_none_or(|total| total > MAX_RETAINED_BYTES_PER_SUB);
        if (exceeds_entry_limit || exceeds_byte_limit)
            && self
                .entries
                .iter()
                .any(|entry| entry.state == Delivery::Acked)
        {
            // Reclaim the oldest acked entries first; a backlog of live messages cannot be
            // dropped, so a subscription that is never drained is bounded and refuses further
            // publishes rather than growing without limit.
            self.reclaim_acked_entries();
        }
        if self.entries.len() >= MAX_RETAINED_PER_SUB {
            return Err(PubSubError::resource_exhausted(format!(
                "subscription {} retains the maximum of {MAX_RETAINED_PER_SUB} messages",
                self.config.name.to_full()
            )));
        }
        if self
            .retained_bytes
            .checked_add(message_bytes)
            .is_none_or(|total| total > MAX_RETAINED_BYTES_PER_SUB)
        {
            return Err(PubSubError::resource_exhausted(format!(
                "subscription {} retains the maximum of {MAX_RETAINED_BYTES_PER_SUB} message bytes",
                self.config.name.to_full()
            )));
        }
        self.entries.push(Entry {
            stored,
            state: Delivery::Available { available_at: now },
            delivery_attempt: 0,
        });
        self.retained_bytes += message_bytes;
        Ok(())
    }

    /// Whether the message filter admits a set of attributes.
    #[must_use]
    pub fn admits(&self, attributes: &std::collections::BTreeMap<String, String>) -> bool {
        self.config.filter.matches(attributes)
    }

    /// Whether any message is deliverable now or outstanding (used by await-idle: a subscription
    /// with undelivered or unacked messages is not idle).
    #[must_use]
    pub fn has_pending(&self, now: LogicalInstant) -> bool {
        self.entries[self.first_unacked..]
            .iter()
            .any(|e| match &e.state {
                Delivery::Outstanding { .. } => true,
                Delivery::Available { available_at } => *available_at <= now,
                Delivery::Acked | Delivery::ForwardPending => false,
            })
    }

    /// Returns the earliest logical instant at which an available message can be delivered.
    /// Outstanding, acknowledged and dead-letter-forwarding entries do not make a push worker
    /// eligible to run another pull quantum.
    #[must_use]
    pub fn next_available_at(&self) -> Option<LogicalInstant> {
        self.entries[self.first_unacked..]
            .iter()
            .filter_map(|entry| match &entry.state {
                Delivery::Available { available_at } => Some(*available_at),
                Delivery::Outstanding { .. } | Delivery::Acked | Delivery::ForwardPending => None,
            })
            .min()
    }

    /// The number of outstanding (delivered, unacked) messages.
    #[must_use]
    pub fn outstanding_count(&self) -> usize {
        self.outstanding.len()
    }

    /// Moves every outstanding message whose ack deadline has passed back to available, so the
    /// next pull redelivers it. Call this on every clock advance.
    pub fn expire_deadlines(&mut self, now: LogicalInstant) {
        let expired: Vec<String> = self
            .outstanding
            .iter()
            .filter(|(_, index)| match &self.entries[**index].state {
                Delivery::Outstanding { deadline, .. } => *deadline <= now,
                Delivery::Available { .. } | Delivery::Acked | Delivery::ForwardPending => false,
            })
            .map(|(ack_id, _)| ack_id.clone())
            .collect();
        for ack_id in expired {
            if let Some(index) = self.outstanding.remove(&ack_id) {
                let backoff = self
                    .config
                    .redelivery_backoff(self.entries[index].delivery_attempt);
                let available_at = now.checked_add(backoff).unwrap_or(now);
                self.entries[index].state = Delivery::Available { available_at };
            }
        }
    }

    /// Delivers up to `max` deliverable messages, assigning ack ids from `next_ack_id`. Messages
    /// that have already been delivered `max_delivery_attempts` times (dead-letter policy) are
    /// not delivered again: they are acked here and returned for forwarding.
    pub fn pull(
        &mut self,
        max: usize,
        now: LogicalInstant,
        mut next_ack_id: impl FnMut() -> String,
    ) -> PullOutcome {
        let mut out = PullOutcome::default();
        if max == 0 {
            return out;
        }
        let deadline = now
            .checked_add(self.config.ack_deadline())
            .unwrap_or(LogicalInstant::MAX);
        let max_attempts = self
            .config
            .dead_letter_policy
            .as_ref()
            .map(|d| d.max_delivery_attempts);
        let ordered = self.config.enable_message_ordering;
        let mut blocked_keys = BTreeSet::new();

        for i in self.first_unacked..self.entries.len() {
            if out.received.len() >= max {
                break;
            }
            if self.entries[i].state == Delivery::Acked {
                continue;
            }
            let ordering_key = self.entries[i].stored.message.ordering_key.clone();
            if ordered && !ordering_key.is_empty() && !blocked_keys.insert(ordering_key.clone()) {
                continue;
            }
            if !matches!(&self.entries[i].state, Delivery::Available { available_at } if *available_at <= now)
            {
                continue;
            }
            // Dead-letter: a message that already used its whole attempt budget is forwarded
            // rather than delivered again.
            if let Some(limit) = max_attempts {
                if self.entries[i].delivery_attempt >= limit {
                    self.entries[i].state = Delivery::ForwardPending;
                    out.dead_lettered.push(Arc::clone(&self.entries[i].stored));
                    continue;
                }
            }
            let ack_id = next_ack_id();
            let entry = &mut self.entries[i];
            entry.delivery_attempt += 1;
            entry.state = Delivery::Outstanding {
                ack_id: ack_id.clone(),
                deadline,
            };
            self.outstanding.insert(ack_id.clone(), i);
            out.received.push(ReceivedMessage {
                ack_id,
                message: Arc::clone(&entry.stored),
                delivery_attempt: entry.delivery_attempt,
            });
        }
        self.advance_first_unacked();
        out
    }

    /// Acknowledges the messages named by `ack_ids`. Unknown or already-expired ack ids are
    /// ignored, exactly as the service ignores them. Returns the number actually acked.
    pub fn acknowledge(&mut self, ack_ids: &[String]) -> usize {
        let mut acked = 0;
        for ack_id in ack_ids {
            if let Some(index) = self.outstanding.remove(ack_id) {
                self.entries[index].state = Delivery::Acked;
                acked += 1;
            }
        }
        self.advance_first_unacked();
        acked
    }

    /// Completes a dead-letter transfer for a retained message. The source is acknowledged only
    /// after the destination publication has been admitted.
    pub fn complete_forward(&mut self, message_id: &str) -> bool {
        let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry.stored.message_id == message_id && entry.state == Delivery::ForwardPending
        }) else {
            return false;
        };
        entry.state = Delivery::Acked;
        self.advance_first_unacked();
        true
    }

    /// Returns exhausted messages whose dead-letter destination has not accepted them yet.
    #[must_use]
    pub fn pending_forwards(&self) -> Vec<Arc<StoredMessage>> {
        self.entries
            .iter()
            .filter(|entry| entry.state == Delivery::ForwardPending)
            .map(|entry| Arc::clone(&entry.stored))
            .collect()
    }

    /// Modifies the ack deadline of one outstanding message. A deadline of zero seconds nacks
    /// the message: it becomes available for immediate redelivery (after the retry backoff).
    /// Unknown ack ids are ignored.
    pub fn modify_ack_deadline(&mut self, ack_id: &str, seconds: u32, now: LogicalInstant) {
        let Some(index) = self.outstanding.get(ack_id).copied() else {
            return;
        };
        if seconds == 0 {
            let backoff = self
                .config
                .redelivery_backoff(self.entries[index].delivery_attempt);
            self.outstanding.remove(ack_id);
            self.entries[index].state = Delivery::Available {
                available_at: now.checked_add(backoff).unwrap_or(now),
            };
        } else if let Delivery::Outstanding { deadline, .. } = &mut self.entries[index].state {
            let duration = LogicalDuration::from_seconds(i64::from(seconds));
            *deadline = now.checked_add(duration).unwrap_or(LogicalInstant::MAX);
        }
    }

    /// Seeks the subscription to a point in time: every message published before `time` is
    /// marked acked (skipped) and every message published at or after it becomes available for
    /// redelivery. Rejected for ordered subscriptions, which the official emulator does not
    /// support seeking by time.
    pub fn seek_to_time(&mut self, time: LogicalInstant, now: LogicalInstant) -> Result<()> {
        if self.config.enable_message_ordering {
            return Err(PubSubError::unimplemented(
                "seek to a timestamp is not supported for ordered subscriptions (official emulator limitation)",
            ));
        }
        for e in &mut self.entries {
            if e.stored.publish_time < time {
                e.state = Delivery::Acked;
            } else {
                e.state = Delivery::Available { available_at: now };
                e.delivery_attempt = 0;
            }
        }
        self.rebuild_indexes();
        Ok(())
    }

    /// Retained payload accounting for the resource diagnostics: `(unacknowledged messages,
    /// their payload bytes, acknowledged-but-retained payload bytes)`. Acknowledged entries
    /// stay retained only while a snapshot or the retention window still needs them, so their
    /// bytes are what a reclaim could release.
    #[must_use]
    pub fn retention_accounting(&self) -> (usize, u64, u64) {
        let mut unacked = 0usize;
        let mut unacked_bytes = 0u64;
        let mut acked_bytes = 0u64;
        for entry in &self.entries {
            let bytes = u64::try_from(entry.stored.message.data.len()).unwrap_or(u64::MAX);
            if entry.state == Delivery::Acked {
                acked_bytes = acked_bytes.saturating_add(bytes);
            } else {
                unacked += 1;
                unacked_bytes = unacked_bytes.saturating_add(bytes);
            }
        }
        (unacked, unacked_bytes, acked_bytes)
    }

    /// Returns the stable message IDs that were not acknowledged at the current point in time.
    #[must_use]
    pub fn unacknowledged_message_ids(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .filter(|entry| entry.state != Delivery::Acked)
            .map(|entry| entry.stored.message_id.clone())
            .collect()
    }

    /// Returns the stable message IDs retained by this subscription at the snapshot boundary.
    #[must_use]
    pub fn retained_message_ids(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .map(|entry| entry.stored.message_id.clone())
            .collect()
    }

    /// Returns the shared message records retained at the snapshot boundary, in subscription
    /// order. The returned arcs let snapshots keep the payload alive without copying it.
    #[must_use]
    pub fn retained_messages(&self) -> Vec<Arc<StoredMessage>> {
        self.entries
            .iter()
            .map(|entry| Arc::clone(&entry.stored))
            .collect()
    }

    /// Oldest publish time among entries that were not acknowledged at the snapshot boundary.
    #[must_use]
    pub fn oldest_unacknowledged_publish_time(&self) -> Option<LogicalInstant> {
        self.entries
            .iter()
            .filter(|entry| entry.state != Delivery::Acked)
            .map(|entry| entry.stored.publish_time)
            .min()
    }

    /// Restores the acknowledgement state captured by a snapshot. Messages that were in the
    /// source backlog remain available, and messages published after the snapshot was created
    /// are also available. Older messages that were acknowledged at snapshot creation stay
    /// acknowledged.
    pub fn seek_to_snapshot(
        &mut self,
        captured_messages: &[Arc<StoredMessage>],
        retained_message_ids: &BTreeSet<String>,
        unacknowledged_message_ids: &BTreeSet<String>,
        created_at: LogicalInstant,
        now: LogicalInstant,
    ) -> Result<()> {
        let existing_ids = self
            .entries
            .iter()
            .map(|entry| entry.stored.message_id.as_str())
            .collect::<BTreeSet<_>>();
        let missing_messages = captured_messages
            .iter()
            .filter(|message| {
                retained_message_ids.contains(&message.message_id)
                    && !existing_ids.contains(message.message_id.as_str())
                    && self.admits(&message.message.attributes)
            })
            .cloned()
            .collect::<Vec<_>>();

        let acked_count = self
            .entries
            .iter()
            .filter(|entry| entry.state == Delivery::Acked)
            .count();
        let acked_bytes = self
            .entries
            .iter()
            .filter(|entry| entry.state == Delivery::Acked)
            .map(|entry| Self::message_bytes(&entry.stored))
            .sum::<usize>();
        let missing_bytes = missing_messages
            .iter()
            .map(|message| Self::message_bytes(message))
            .sum::<usize>();
        let entries_without_acked = self.entries.len().saturating_sub(acked_count);
        let bytes_without_acked = self.retained_bytes.saturating_sub(acked_bytes);
        let entries_after = self.entries.len().saturating_add(missing_messages.len());
        let bytes_after = self.retained_bytes.saturating_add(missing_bytes);
        let can_reclaim_acked =
            entries_after > MAX_RETAINED_PER_SUB || bytes_after > MAX_RETAINED_BYTES_PER_SUB;
        if can_reclaim_acked {
            if entries_without_acked.saturating_add(missing_messages.len()) > MAX_RETAINED_PER_SUB
                || bytes_without_acked.saturating_add(missing_bytes) > MAX_RETAINED_BYTES_PER_SUB
            {
                return Err(PubSubError::resource_exhausted(format!(
                    "subscription {} cannot restore the snapshot within its retention bounds",
                    self.config.name.to_full()
                )));
            }
            self.entries.retain(|entry| entry.state != Delivery::Acked);
            self.rebuild_indexes();
        } else if entries_after > MAX_RETAINED_PER_SUB || bytes_after > MAX_RETAINED_BYTES_PER_SUB {
            return Err(PubSubError::resource_exhausted(format!(
                "subscription {} cannot restore the snapshot within its retention bounds",
                self.config.name.to_full()
            )));
        }

        let insertion_index = self
            .entries
            .iter()
            .position(|entry| {
                !retained_message_ids.contains(&entry.stored.message_id)
                    && entry.stored.publish_time >= created_at
            })
            .unwrap_or(self.entries.len());
        self.entries.splice(
            insertion_index..insertion_index,
            missing_messages.into_iter().map(|stored| Entry {
                stored,
                state: Delivery::Available { available_at: now },
                delivery_attempt: 0,
            }),
        );
        for entry in &mut self.entries {
            if unacknowledged_message_ids.contains(&entry.stored.message_id)
                || (!retained_message_ids.contains(&entry.stored.message_id)
                    && entry.stored.publish_time >= created_at)
            {
                entry.state = Delivery::Available { available_at: now };
                entry.delivery_attempt = 0;
            } else {
                entry.state = Delivery::Acked;
            }
        }
        self.rebuild_indexes();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::PubsubMessage;
    use std::cell::Cell;

    fn cfg() -> SubscriptionConfig {
        SubscriptionConfig {
            name: SubscriptionName::new("demo-app", "sub-one").unwrap(),
            topic: TopicName::new("demo-app", "topic-one").unwrap(),
            ack_deadline_seconds: DEFAULT_ACK_DEADLINE_SECONDS,
            enable_message_ordering: false,
            filter: Filter::always(),
            dead_letter_policy: None,
            retry_policy: None,
            push_config: PushConfig::default(),
        }
    }

    fn stored(id: &str, data: &[u8], t: i64) -> StoredMessage {
        StoredMessage {
            message_id: id.to_owned(),
            publish_time: LogicalInstant::from_unix_seconds(t),
            message: PubsubMessage {
                data: data.to_vec(),
                ..PubsubMessage::default()
            },
        }
    }

    fn counter() -> impl FnMut() -> String {
        let n = Cell::new(0u64);
        move || {
            n.set(n.get() + 1);
            format!("ack-{}", n.get())
        }
    }

    #[test]
    fn pull_delivers_then_ack_removes() {
        let mut s = SubscriptionState::new(cfg());
        let now = LogicalInstant::from_unix_seconds(100);
        s.enqueue(stored("1", b"a", 100), now).unwrap();
        let mut ids = counter();
        let out = s.pull(10, now, &mut ids);
        assert_eq!(out.received.len(), 1);
        assert_eq!(out.received[0].delivery_attempt, 1);
        let ack = out.received[0].ack_id.clone();
        // A second pull sees nothing outstanding.
        assert!(s.pull(10, now, &mut ids).received.is_empty());
        assert_eq!(s.acknowledge(&[ack]), 1);
        assert!(!s.has_pending(now));
    }

    #[test]
    fn acknowledgement_indexes_skip_acked_prefixes_and_redelivery_shares_payloads() {
        let mut s = SubscriptionState::new(cfg());
        let now = LogicalInstant::from_unix_seconds(100);
        for id in ["1", "2", "3"] {
            s.enqueue(stored(id, id.as_bytes(), 100), now).unwrap();
        }
        let mut ids = counter();
        let pulled = s.pull(3, now, &mut ids);
        assert_eq!(s.outstanding_count(), 3);
        assert_eq!(s.acknowledge(&[pulled.received[0].ack_id.clone()]), 1);
        assert_eq!(s.first_unacked, 1);
        assert_eq!(
            s.acknowledge(&[
                pulled.received[1].ack_id.clone(),
                pulled.received[2].ack_id.clone(),
            ]),
            2
        );
        assert_eq!(s.first_unacked, 3);
        assert_eq!(s.outstanding_count(), 0);

        s.seek_to_time(now, now).unwrap();
        let replay = s.pull(1, now, &mut ids);
        let first_allocation = Arc::clone(&replay.received[0].message);
        s.modify_ack_deadline(&replay.received[0].ack_id, 0, now);
        let redelivery = s.pull(1, now, &mut ids);
        assert!(Arc::ptr_eq(
            &first_allocation,
            &redelivery.received[0].message
        ));
    }

    #[test]
    fn retained_message_bytes_are_bounded_without_allocating_the_limit() {
        let mut s = SubscriptionState::new(cfg());
        let mut measured = stored("measured", b"abc", 100);
        measured.message.ordering_key = "key".to_owned();
        measured
            .message
            .attributes
            .insert("name".to_owned(), "value".to_owned());
        assert_eq!(SubscriptionState::message_bytes(&measured), 3 + 3 + 4 + 5);
        s.retained_bytes = MAX_RETAINED_BYTES_PER_SUB - 1;
        let now = LogicalInstant::from_unix_seconds(100);
        assert!(s.enqueue(stored("1", b"a", 100), now).is_ok());
        let error = s.enqueue(stored("2", b"b", 100), now).unwrap_err();
        assert_eq!(error.code(), crate::error::Code::ResourceExhausted);
    }

    #[test]
    fn batch_admission_rejects_before_reclaim_or_enqueue_mutation() {
        let mut subscription = SubscriptionState::new(cfg());
        subscription.retained_bytes = MAX_RETAINED_BYTES_PER_SUB - 1;
        let incoming = [stored("1", b"a", 100), stored("2", b"b", 100)];

        let error = subscription
            .ensure_enqueue_capacity(incoming.iter())
            .unwrap_err();

        assert_eq!(error.code(), crate::error::Code::ResourceExhausted);
        assert!(subscription.entries.is_empty());
        assert_eq!(subscription.retained_bytes, MAX_RETAINED_BYTES_PER_SUB - 1);
    }

    #[test]
    fn entry_cap_reclaims_acked_tombstones_before_refusing_a_publish() {
        let mut s = SubscriptionState::new(cfg());
        let shared = Arc::new(stored("old", b"a", 100));
        s.entries = (0..MAX_RETAINED_PER_SUB)
            .map(|_| Entry {
                stored: Arc::clone(&shared),
                state: Delivery::Acked,
                delivery_attempt: 1,
            })
            .collect();
        s.rebuild_indexes();

        let now = LogicalInstant::from_unix_seconds(100);
        s.enqueue(stored("new", b"b", 100), now).unwrap();
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].stored.message_id, "new");
    }

    #[test]
    fn byte_pressure_reclaims_acked_tombstones_before_refusing_a_publish() {
        let mut s = SubscriptionState::new(cfg());
        s.entries.push(Entry {
            stored: Arc::new(stored("acked", b"a", 100)),
            state: Delivery::Acked,
            delivery_attempt: 1,
        });
        s.rebuild_indexes();
        s.retained_bytes = MAX_RETAINED_BYTES_PER_SUB;

        let now = LogicalInstant::from_unix_seconds(100);
        s.enqueue(stored("new", b"b", 100), now).unwrap();

        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].stored.message_id, "new");
        assert_eq!(s.retained_bytes, 1);
    }

    #[test]
    fn expired_deadline_redelivers() {
        let mut s = SubscriptionState::new(cfg());
        let t0 = LogicalInstant::from_unix_seconds(100);
        s.enqueue(stored("1", b"a", 100), t0).unwrap();
        let mut ids = counter();
        let first = s.pull(10, t0, &mut ids);
        assert_eq!(first.received[0].delivery_attempt, 1);
        // Before the deadline, nothing redelivers.
        let t_before = LogicalInstant::from_unix_seconds(105);
        s.expire_deadlines(t_before);
        assert!(s.pull(10, t_before, &mut ids).received.is_empty());
        // After the 10s deadline, it comes back with an incremented attempt.
        let t_after = LogicalInstant::from_unix_seconds(111);
        s.expire_deadlines(t_after);
        let second = s.pull(10, t_after, &mut ids);
        assert_eq!(second.received.len(), 1);
        assert_eq!(second.received[0].delivery_attempt, 2);
    }

    #[test]
    fn nack_redelivers_immediately() {
        let mut s = SubscriptionState::new(cfg());
        let now = LogicalInstant::from_unix_seconds(100);
        s.enqueue(stored("1", b"a", 100), now).unwrap();
        let mut ids = counter();
        let out = s.pull(10, now, &mut ids);
        let ack = out.received[0].ack_id.clone();
        s.modify_ack_deadline(&ack, 0, now);
        let again = s.pull(10, now, &mut ids);
        assert_eq!(again.received.len(), 1);
        assert_eq!(again.received[0].delivery_attempt, 2);
    }

    #[test]
    fn retry_backoff_increases_after_each_nack_and_clamps_to_maximum() {
        let mut c = cfg();
        c.retry_policy = Some(RetryPolicy {
            minimum_backoff: LogicalDuration::from_seconds(2),
            maximum_backoff: LogicalDuration::from_seconds(5),
        });
        let mut s = SubscriptionState::new(c);
        let t0 = LogicalInstant::from_unix_seconds(100);
        s.enqueue(stored("1", b"a", 100), t0).unwrap();
        let mut ids = counter();

        let first = s.pull(1, t0, &mut ids);
        s.modify_ack_deadline(&first.received[0].ack_id, 0, t0);
        assert_eq!(
            s.next_available_at(),
            Some(t0.checked_add(LogicalDuration::from_seconds(2)).unwrap())
        );
        assert!(s.pull(1, t0, &mut ids).received.is_empty());
        let t_first_retry = t0.checked_add(LogicalDuration::from_seconds(2)).unwrap();
        let second = s.pull(1, t_first_retry, &mut ids);
        assert_eq!(second.received[0].delivery_attempt, 2);
        assert_eq!(s.next_available_at(), None);

        s.modify_ack_deadline(&second.received[0].ack_id, 0, t_first_retry);
        let before_second_retry = t_first_retry
            .checked_add(LogicalDuration::from_seconds(3))
            .unwrap();
        assert!(s.pull(1, before_second_retry, &mut ids).received.is_empty());
        let t_second_retry = t_first_retry
            .checked_add(LogicalDuration::from_seconds(4))
            .unwrap();
        let third = s.pull(1, t_second_retry, &mut ids);
        assert_eq!(third.received[0].delivery_attempt, 3);

        s.modify_ack_deadline(&third.received[0].ack_id, 0, t_second_retry);
        let before_clamp = t_second_retry
            .checked_add(LogicalDuration::from_seconds(4))
            .unwrap();
        assert!(s.pull(1, before_clamp, &mut ids).received.is_empty());
        let at_clamp = t_second_retry
            .checked_add(LogicalDuration::from_seconds(5))
            .unwrap();
        assert_eq!(s.pull(1, at_clamp, &mut ids).received.len(), 1);
    }

    #[test]
    fn retry_backoff_is_attempt_dependent_for_expired_deadlines() {
        let mut c = cfg();
        c.retry_policy = Some(RetryPolicy {
            minimum_backoff: LogicalDuration::from_seconds(2),
            maximum_backoff: LogicalDuration::from_seconds(5),
        });
        let mut s = SubscriptionState::new(c);
        let t0 = LogicalInstant::from_unix_seconds(100);
        s.enqueue(stored("1", b"a", 100), t0).unwrap();
        let mut ids = counter();

        let _first = s.pull(1, t0, &mut ids);
        let t_deadline = t0.checked_add(LogicalDuration::from_seconds(10)).unwrap();
        s.expire_deadlines(t_deadline);
        assert!(s.pull(1, t_deadline, &mut ids).received.is_empty());
        let t_first_retry = t_deadline
            .checked_add(LogicalDuration::from_seconds(2))
            .unwrap();
        let second = s.pull(1, t_first_retry, &mut ids);
        assert_eq!(second.received[0].delivery_attempt, 2);

        let t_second_deadline = t_first_retry
            .checked_add(LogicalDuration::from_seconds(10))
            .unwrap();
        s.expire_deadlines(t_second_deadline);
        let before_second_retry = t_second_deadline
            .checked_add(LogicalDuration::from_seconds(3))
            .unwrap();
        assert!(s.pull(1, before_second_retry, &mut ids).received.is_empty());
        let t_second_retry = t_second_deadline
            .checked_add(LogicalDuration::from_seconds(4))
            .unwrap();
        let third = s.pull(1, t_second_retry, &mut ids);
        assert_eq!(third.received[0].delivery_attempt, 3);

        s.modify_ack_deadline(&third.received[0].ack_id, 0, t_second_retry);
        let before_clamp = t_second_retry
            .checked_add(LogicalDuration::from_seconds(4))
            .unwrap();
        assert!(s.pull(1, before_clamp, &mut ids).received.is_empty());
        let at_clamp = t_second_retry
            .checked_add(LogicalDuration::from_seconds(5))
            .unwrap();
        assert_eq!(s.pull(1, at_clamp, &mut ids).received.len(), 1);
    }

    #[test]
    fn dead_letter_after_max_attempts() {
        let mut c = cfg();
        c.dead_letter_policy = Some(DeadLetterPolicy {
            dead_letter_topic: TopicName::new("demo-app", "dead-letters").unwrap(),
            max_delivery_attempts: MIN_DEAD_LETTER_ATTEMPTS,
        });
        let mut s = SubscriptionState::new(c);
        let mut now = LogicalInstant::from_unix_seconds(100);
        s.enqueue(stored("1", b"a", 100), now).unwrap();
        let mut ids = counter();
        // Deliver-and-expire five times.
        for _ in 0..MIN_DEAD_LETTER_ATTEMPTS {
            let out = s.pull(10, now, &mut ids);
            assert_eq!(out.received.len(), 1);
            now = now.checked_add(LogicalDuration::from_seconds(11)).unwrap();
            s.expire_deadlines(now);
        }
        // The sixth pull dead-letters instead of delivering.
        let out = s.pull(10, now, &mut ids);
        assert!(out.received.is_empty());
        assert_eq!(out.dead_lettered.len(), 1);
    }

    #[test]
    fn ordering_holds_key_until_ack() {
        let mut c = cfg();
        c.enable_message_ordering = true;
        let mut s = SubscriptionState::new(c);
        let now = LogicalInstant::from_unix_seconds(100);
        let mut m1 = stored("1", b"a", 100);
        m1.message.ordering_key = "k".to_owned();
        let mut m2 = stored("2", b"b", 100);
        m2.message.ordering_key = "k".to_owned();
        s.enqueue(m1, now).unwrap();
        s.enqueue(m2, now).unwrap();
        let mut ids = counter();
        // Only the first message of the key is delivered.
        let out = s.pull(10, now, &mut ids);
        assert_eq!(out.received.len(), 1);
        assert_eq!(out.received[0].message.message_id, "1");
        let ack = out.received[0].ack_id.clone();
        // The second is still blocked until the first is acked.
        assert!(s.pull(10, now, &mut ids).received.is_empty());
        s.acknowledge(&[ack]);
        let out2 = s.pull(10, now, &mut ids);
        assert_eq!(out2.received[0].message.message_id, "2");
    }

    #[test]
    fn seek_to_time_replays_and_skips() {
        let mut s = SubscriptionState::new(cfg());
        let now = LogicalInstant::from_unix_seconds(300);
        s.enqueue(stored("1", b"a", 100), now).unwrap();
        s.enqueue(stored("2", b"b", 200), now).unwrap();
        let mut ids = counter();
        // Ack everything.
        let out = s.pull(10, now, &mut ids);
        let acks: Vec<String> = out.received.iter().map(|r| r.ack_id.clone()).collect();
        s.acknowledge(&acks);
        assert!(!s.has_pending(now));
        // Seek to t=150: message "1" (t=100) stays skipped, "2" (t=200) replays.
        s.seek_to_time(LogicalInstant::from_unix_seconds(150), now)
            .unwrap();
        let replayed = s.pull(10, now, &mut ids);
        assert_eq!(replayed.received.len(), 1);
        assert_eq!(replayed.received[0].message.message_id, "2");
    }
}
