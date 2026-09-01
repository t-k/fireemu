//! The Pub/Sub registry: topics, subscriptions, publish routing, dead-letter forwarding and
//! deterministic identifier generation.
//!
//! [`PubSubState`] is a pure, std-only state machine. It owns no clock and no sockets: every
//! operation that depends on time takes an explicit [`LogicalInstant`], and identifiers are
//! derived from the daemon seed so a run reproduces byte for byte. The protocol adapter drives
//! it, forwarding the virtual clock and holding the lock.

use std::collections::{BTreeMap, BTreeSet};

use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::time::LogicalInstant;

use crate::error::{PubSubError, Result};
use crate::message::{PubsubMessage, StoredMessage};
use crate::name::{SubscriptionName, TopicName, DELETED_TOPIC};
use crate::subscription::{ReceivedMessage, SubscriptionConfig, SubscriptionState};

/// Upper bound on the number of topics one project session keeps.
pub const MAX_TOPICS: usize = 10_000;
/// Upper bound on the number of subscriptions one project session keeps.
pub const MAX_SUBSCRIPTIONS: usize = 10_000;
/// Maximum messages accepted in one publish request.
pub const MAX_MESSAGES_PER_PUBLISH: usize = 1_000;

/// A topic and the record of which subscriptions attach to it.
#[derive(Debug, Clone)]
struct TopicEntry {
    name: TopicName,
    labels: BTreeMap<String, String>,
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
    message_counter: u64,
    ack_rng: SplitMix64,
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
            message_counter: 0,
            // Mix a fixed tag so ack ids never coincide with any other seeded stream.
            ack_rng: SplitMix64::new(seed ^ 0x5053_5542_4143_4b5f),
        }
    }

    /// Drops every topic and subscription (session reset). The seed and counters are reset so
    /// that a fresh run after a reset reproduces the same identifiers.
    pub fn clear(&mut self) {
        self.topics.clear();
        self.subscriptions.clear();
        self.topic_subs.clear();
        self.function_subscriptions.clear();
        self.message_counter = 0;
        self.ack_rng = SplitMix64::new(self.seed ^ 0x5053_5542_4143_4b5f);
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
        self.topic_subs.entry(key.clone()).or_default();
        self.topics.insert(key, TopicEntry { name, labels });
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
        self.topic_subs.remove(&key);
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
            // A dead-letter topic that does not exist is accepted by the service (messages are
            // simply dropped when forwarded), so we do not reject it here.
            let _ = dl;
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

    // --- Publish / deliver ------------------------------------------------------------------

    /// Publishes messages to a topic, fanning them out to every subscription whose filter
    /// admits them. Returns one message id per input message, in order. The topic must exist.
    pub fn publish(
        &mut self,
        topic: &TopicName,
        messages: Vec<PubsubMessage>,
        now: LogicalInstant,
    ) -> Result<Vec<String>> {
        let topic_key = topic.to_full();
        if !self.topics.contains_key(&topic_key) {
            return Err(PubSubError::not_found(format!(
                "topic {topic_key} not found"
            )));
        }
        if messages.len() > MAX_MESSAGES_PER_PUBLISH {
            return Err(PubSubError::invalid_argument(format!(
                "a publish request carries at most {MAX_MESSAGES_PER_PUBLISH} messages"
            )));
        }
        for m in &messages {
            m.validate()?;
        }
        let sub_keys: Vec<String> = self
            .topic_subs
            .get(&topic_key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();

        let mut ids = Vec::with_capacity(messages.len());
        for message in messages {
            self.message_counter += 1;
            let message_id = self.message_counter.to_string();
            let stored = StoredMessage {
                message_id: message_id.clone(),
                publish_time: now,
                message,
            };
            for key in &sub_keys {
                if self.function_subscriptions.contains(key) {
                    continue;
                }
                if let Some(sub) = self.subscriptions.get_mut(key) {
                    if sub.admits(&stored.message.attributes) {
                        sub.enqueue(stored.clone(), now)?;
                    }
                }
            }
            ids.push(message_id);
        }
        Ok(ids)
    }

    /// Delivers up to `max` messages from a subscription. Dead-lettered messages are forwarded
    /// to the subscription's dead-letter topic (when it exists) before returning.
    pub fn pull(
        &mut self,
        name: &SubscriptionName,
        max: usize,
        now: LogicalInstant,
    ) -> Result<Vec<ReceivedMessage>> {
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
        // Forward dead-lettered messages, if a dead-letter topic is configured and exists.
        if !outcome.dead_lettered.is_empty() {
            if let Some(dl_topic) = self
                .subscriptions
                .get(&key)
                .and_then(|s| s.config().dead_letter_policy.as_ref())
                .map(|d| d.dead_letter_topic.clone())
            {
                self.forward_dead_letters(&dl_topic, outcome.dead_lettered, now);
            }
        }
        Ok(outcome.received)
    }

    /// Forwards exhausted messages to a dead-letter topic. Best effort: a missing dead-letter
    /// topic drops them, exactly as the service does.
    fn forward_dead_letters(
        &mut self,
        dl_topic: &TopicName,
        messages: Vec<StoredMessage>,
        now: LogicalInstant,
    ) {
        if !self.topics.contains_key(&dl_topic.to_full()) {
            return;
        }
        let bodies: Vec<PubsubMessage> = messages.into_iter().map(|m| m.message).collect();
        // Ignore the result: a dead-letter republish that hits a bound is dropped rather than
        // failing the original pull.
        let _ = self.publish(dl_topic, bodies, now);
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
        let msgs = s
            .pull(
                &SubscriptionName::new("demo-app", "orders-sub").unwrap(),
                10,
                now,
            )
            .unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].message.message.data, b"hello");
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
        s.create_topic(topic("p", "top-a"), BTreeMap::new())
            .unwrap();
        s.create_subscription(sub_cfg("p", "sub-a", "top-a", Filter::always()))
            .unwrap();
        s.delete_topic(&topic("p", "top-a")).unwrap();
        let reported = s
            .reported_topic(&SubscriptionName::new("p", "sub-a").unwrap())
            .unwrap();
        assert_eq!(reported, DELETED_TOPIC);
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
}
