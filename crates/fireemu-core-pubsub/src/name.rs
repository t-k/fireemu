//! Resource-name validation and parsing (`projects/{p}/topics/{t}`,
//! `projects/{p}/subscriptions/{s}`).
//!
//! The rules mirror the documented Cloud Pub/Sub constraints: a topic or subscription ID is
//! 3..=255 characters, starts with a letter, is drawn from `[A-Za-z0-9._~%+-]`, and must not
//! start with `goog`. Control characters and NUL are excluded by that alphabet, so a resource
//! name can never smuggle a terminal control sequence or a path separator into a trace, a log
//! line or a wire name. Project IDs are validated only for length and the absence of slashes
//! and control characters, because the emulator accepts any project a client presents.

use crate::error::{PubSubError, Result};

/// Inclusive minimum length of a topic or subscription ID.
pub const MIN_ID_LEN: usize = 3;
/// Inclusive maximum length of a topic or subscription ID.
pub const MAX_ID_LEN: usize = 255;
/// Inclusive maximum length of a project ID.
pub const MAX_PROJECT_LEN: usize = 255;

/// Validates a project ID: non-empty, `<= MAX_PROJECT_LEN`, no `/`, no control characters.
pub fn validate_project(project: &str) -> Result<()> {
    if project.is_empty() {
        return Err(PubSubError::invalid_argument("project id is empty"));
    }
    if project.len() > MAX_PROJECT_LEN {
        return Err(PubSubError::invalid_argument(format!(
            "project id exceeds {MAX_PROJECT_LEN} bytes"
        )));
    }
    if project.contains('/') {
        return Err(PubSubError::invalid_argument(
            "project id must not contain '/'",
        ));
    }
    if let Some(offset) = project.char_indices().find(|(_, c)| c.is_control()) {
        return Err(PubSubError::invalid_argument(format!(
            "project id has a control character at byte {}",
            offset.0
        )));
    }
    Ok(())
}

/// Validates a topic or subscription short ID against the documented Pub/Sub rules.
pub fn validate_resource_id(id: &str, kind: &str) -> Result<()> {
    if id.len() < MIN_ID_LEN || id.len() > MAX_ID_LEN {
        return Err(PubSubError::invalid_argument(format!(
            "{kind} id must be {MIN_ID_LEN}..={MAX_ID_LEN} characters"
        )));
    }
    let first = id.as_bytes()[0];
    if !first.is_ascii_alphabetic() {
        return Err(PubSubError::invalid_argument(format!(
            "{kind} id must start with a letter"
        )));
    }
    if let Some(offset) = id.bytes().position(|b| !is_id_byte(b)) {
        return Err(PubSubError::invalid_argument(format!(
            "{kind} id has an invalid character at byte {offset}; allowed: letters, digits and . _ ~ % + -"
        )));
    }
    if id.starts_with("goog") {
        return Err(PubSubError::invalid_argument(format!(
            "{kind} id must not start with the reserved prefix 'goog'"
        )));
    }
    Ok(())
}

/// The Pub/Sub resource-name alphabet after the mandatory leading letter.
const fn is_id_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(b, b'.' | b'_' | b'~' | b'%' | b'+' | b'-')
}

/// A fully-qualified topic name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TopicName {
    project: String,
    topic: String,
}

/// A fully-qualified subscription name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionName {
    project: String,
    subscription: String,
}

impl TopicName {
    /// Builds a validated topic name from its parts.
    pub fn new(project: impl Into<String>, topic: impl Into<String>) -> Result<Self> {
        let project = project.into();
        let topic = topic.into();
        validate_project(&project)?;
        validate_resource_id(&topic, "topic")?;
        Ok(Self { project, topic })
    }

    /// Parses `projects/{project}/topics/{topic}`. The special sentinel `_deleted-topic_` is a
    /// valid topic reference on a dead-lettered subscription and is accepted verbatim.
    pub fn parse(full: &str) -> Result<Self> {
        if full == DELETED_TOPIC {
            return Ok(Self {
                project: String::new(),
                topic: DELETED_TOPIC.to_owned(),
            });
        }
        let (project, topic) = split_two(full, "topics")
            .ok_or_else(|| PubSubError::invalid_argument("topic name must be projects/{p}/topics/{t}"))?;
        Self::new(project, topic)
    }

    /// The project component.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The short topic ID.
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }

    /// Whether this is the deleted-topic sentinel.
    #[must_use]
    pub fn is_deleted_sentinel(&self) -> bool {
        self.topic == DELETED_TOPIC
    }

    /// The canonical `projects/{p}/topics/{t}` string.
    #[must_use]
    pub fn to_full(&self) -> String {
        if self.is_deleted_sentinel() {
            return DELETED_TOPIC.to_owned();
        }
        format!("projects/{}/topics/{}", self.project, self.topic)
    }
}

impl SubscriptionName {
    /// Builds a validated subscription name from its parts.
    pub fn new(project: impl Into<String>, subscription: impl Into<String>) -> Result<Self> {
        let project = project.into();
        let subscription = subscription.into();
        validate_project(&project)?;
        validate_resource_id(&subscription, "subscription")?;
        Ok(Self {
            project,
            subscription,
        })
    }

    /// Parses `projects/{project}/subscriptions/{subscription}`.
    pub fn parse(full: &str) -> Result<Self> {
        let (project, subscription) = split_two(full, "subscriptions").ok_or_else(|| {
            PubSubError::invalid_argument("subscription name must be projects/{p}/subscriptions/{s}")
        })?;
        Self::new(project, subscription)
    }

    /// The project component.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The short subscription ID.
    #[must_use]
    pub fn subscription(&self) -> &str {
        &self.subscription
    }

    /// The canonical `projects/{p}/subscriptions/{s}` string.
    #[must_use]
    pub fn to_full(&self) -> String {
        format!("projects/{}/subscriptions/{}", self.project, self.subscription)
    }
}

/// The reserved topic name a subscription reports once its topic has been deleted.
pub const DELETED_TOPIC: &str = "_deleted-topic_";

/// Splits `projects/{a}/{collection}/{b}` into `(a, b)`, requiring exactly that shape.
fn split_two<'a>(full: &'a str, collection: &str) -> Option<(&'a str, &'a str)> {
    let rest = full.strip_prefix("projects/")?;
    let (project, tail) = rest.split_once('/')?;
    let id = tail.strip_prefix(collection)?.strip_prefix('/')?;
    if project.is_empty() || id.is_empty() || id.contains('/') {
        return None;
    }
    Some((project, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_plain_topic() {
        let n = TopicName::parse("projects/demo-app/topics/orders").unwrap();
        assert_eq!(n.project(), "demo-app");
        assert_eq!(n.topic(), "orders");
        assert_eq!(n.to_full(), "projects/demo-app/topics/orders");
    }

    #[test]
    fn rejects_short_ids() {
        assert_eq!(
            validate_resource_id("ab", "topic").unwrap_err().code(),
            crate::error::Code::InvalidArgument
        );
    }

    #[test]
    fn rejects_leading_digit() {
        assert!(validate_resource_id("1orders", "topic").is_err());
    }

    #[test]
    fn rejects_goog_prefix() {
        assert!(validate_resource_id("google-thing", "topic").is_err());
    }

    #[test]
    fn rejects_slash_and_control_in_project() {
        assert!(validate_project("a/b").is_err());
        assert!(validate_project("a\u{0}b").is_err());
    }

    #[test]
    fn rejects_control_characters_in_id() {
        assert!(validate_resource_id("ord\u{7}ers", "topic").is_err());
    }

    #[test]
    fn deleted_topic_sentinel_round_trips() {
        let n = TopicName::parse(DELETED_TOPIC).unwrap();
        assert!(n.is_deleted_sentinel());
        assert_eq!(n.to_full(), DELETED_TOPIC);
    }
}
