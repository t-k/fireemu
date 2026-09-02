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
            if rp.minimum_backoff.as_nanos() < 0 || rp.maximum_backoff.as_nanos() < 0 {
                return Err(PubSubError::invalid_argument(
                    "retry policy backoff must not be negative",
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

    fn redelivery_backoff(&self) -> LogicalDuration {
        self.retry_policy
            .map_or(LogicalDuration::ZERO, |rp| rp.minimum_backoff)
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
        if self.entries.len() >= MAX_RETAINED_PER_SUB {
            // Reclaim the oldest acked entries first; a backlog of live messages cannot be
            // dropped, so a subscription that is never drained is bounded and refuses further
            // publishes rather than growing without limit.
            self.entries.retain(|e| e.state != Delivery::Acked);
            self.rebuild_indexes();
            if self.entries.len() >= MAX_RETAINED_PER_SUB {
                return Err(PubSubError::resource_exhausted(format!(
                    "subscription {} retains the maximum of {MAX_RETAINED_PER_SUB} messages",
                    self.config.name.to_full()
                )));
            }
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
                Delivery::Acked => false,
            })
    }

    /// The number of outstanding (delivered, unacked) messages.
    #[must_use]
    pub fn outstanding_count(&self) -> usize {
        self.outstanding.len()
    }

    /// Moves every outstanding message whose ack deadline has passed back to available, so the
    /// next pull redelivers it. Call this on every clock advance.
    pub fn expire_deadlines(&mut self, now: LogicalInstant) {
        let backoff = self.config.redelivery_backoff();
        let available_at = now.checked_add(backoff).unwrap_or(now);
        let expired: Vec<String> = self
            .outstanding
            .iter()
            .filter(|(_, index)| match &self.entries[**index].state {
                Delivery::Outstanding { deadline, .. } => *deadline <= now,
                Delivery::Available { .. } | Delivery::Acked => false,
            })
            .map(|(ack_id, _)| ack_id.clone())
            .collect();
        for ack_id in expired {
            if let Some(index) = self.outstanding.remove(&ack_id) {
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
                    self.entries[i].state = Delivery::Acked;
                    out.dead_lettered.push(Arc::clone(&self.entries[i].stored));
                    blocked_keys.remove(&ordering_key);
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

    /// Modifies the ack deadline of one outstanding message. A deadline of zero seconds nacks
    /// the message: it becomes available for immediate redelivery (after the retry backoff).
    /// Unknown ack ids are ignored.
    pub fn modify_ack_deadline(&mut self, ack_id: &str, seconds: u32, now: LogicalInstant) {
        let backoff = self.config.redelivery_backoff();
        let Some(index) = self.outstanding.get(ack_id).copied() else {
            return;
        };
        if seconds == 0 {
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
