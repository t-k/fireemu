//! Conversions between the `google.pubsub.v1` protobuf types and the core state machine, plus
//! the mapping from a [`PubSubError`] to a `tonic::Status`.

use std::collections::BTreeMap;

use fireemu_core_pubsub::subscription::{
    DeadLetterPolicy, PushConfig, RetryPolicy, DEFAULT_ACK_DEADLINE_SECONDS,
};
use fireemu_core_pubsub::{
    Code, Filter, PubSubError, PubsubMessage, ReceivedMessage, StoredMessage, SubscriptionConfig,
    SubscriptionName, TopicName,
};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use fireemu_proto_pubsub::google::pubsub::v1 as pb;

/// Maps a core error to a gRPC status.
#[must_use]
pub fn status(err: &PubSubError) -> tonic::Status {
    let code = match err.code() {
        Code::InvalidArgument => tonic::Code::InvalidArgument,
        Code::NotFound => tonic::Code::NotFound,
        Code::AlreadyExists => tonic::Code::AlreadyExists,
        Code::FailedPrecondition => tonic::Code::FailedPrecondition,
        Code::ResourceExhausted => tonic::Code::ResourceExhausted,
        Code::Unimplemented => tonic::Code::Unimplemented,
    };
    tonic::Status::new(code, err.message().to_owned())
}

const NANOS_PER_SEC: i128 = 1_000_000_000;

/// Converts a logical instant to a protobuf timestamp.
#[must_use]
pub fn to_timestamp(instant: LogicalInstant) -> prost_types::Timestamp {
    let nanos = instant.as_nanos();
    let seconds = nanos.div_euclid(NANOS_PER_SEC);
    let sub = nanos.rem_euclid(NANOS_PER_SEC);
    prost_types::Timestamp {
        seconds: i64::try_from(seconds).unwrap_or(i64::MAX),
        nanos: i32::try_from(sub).unwrap_or(0),
    }
}

/// Converts a protobuf timestamp to a logical instant.
#[must_use]
pub fn from_timestamp(ts: &prost_types::Timestamp) -> LogicalInstant {
    LogicalInstant::from_nanos(i128::from(ts.seconds) * NANOS_PER_SEC + i128::from(ts.nanos))
}

/// Converts a wire message to the core message model.
#[must_use]
pub fn message_from_proto(m: pb::PubsubMessage) -> PubsubMessage {
    PubsubMessage {
        data: m.data,
        attributes: m.attributes.into_iter().collect(),
        ordering_key: m.ordering_key,
    }
}

/// Renders a stored message as a wire message.
#[must_use]
pub fn message_to_proto(stored: &StoredMessage) -> pb::PubsubMessage {
    pb::PubsubMessage {
        data: stored.message.data.clone(),
        attributes: stored
            .message
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        message_id: stored.message_id.clone(),
        publish_time: Some(to_timestamp(stored.publish_time)),
        ordering_key: stored.message.ordering_key.clone(),
    }
}

/// Renders a delivered message as a wire `ReceivedMessage`.
#[must_use]
pub fn received_to_proto(r: &ReceivedMessage) -> pb::ReceivedMessage {
    pb::ReceivedMessage {
        ack_id: r.ack_id.clone(),
        message: Some(message_to_proto(&r.message)),
        delivery_attempt: i32::try_from(r.delivery_attempt).unwrap_or(i32::MAX),
    }
}

fn duration_from_proto(d: &prost_types::Duration) -> LogicalDuration {
    LogicalDuration::from_nanos(i128::from(d.seconds) * NANOS_PER_SEC + i128::from(d.nanos))
}

fn duration_to_proto(d: LogicalDuration) -> prost_types::Duration {
    let nanos = d.as_nanos();
    prost_types::Duration {
        seconds: i64::try_from(nanos.div_euclid(NANOS_PER_SEC)).unwrap_or(0),
        nanos: i32::try_from(nanos.rem_euclid(NANOS_PER_SEC)).unwrap_or(0),
    }
}

/// Builds a validated [`SubscriptionConfig`] from a wire `Subscription`.
pub fn subscription_from_proto(sub: &pb::Subscription) -> Result<SubscriptionConfig, PubSubError> {
    let name = SubscriptionName::parse(&sub.name)?;
    let topic = TopicName::parse(&sub.topic)?;
    let ack_deadline_seconds = if sub.ack_deadline_seconds == 0 {
        DEFAULT_ACK_DEADLINE_SECONDS
    } else {
        u32::try_from(sub.ack_deadline_seconds)
            .map_err(|_| PubSubError::invalid_argument("ackDeadlineSeconds must be positive"))?
    };
    let filter = Filter::parse(&sub.filter)?;
    let dead_letter_policy = match &sub.dead_letter_policy {
        Some(dl) if !dl.dead_letter_topic.is_empty() => Some(DeadLetterPolicy {
            dead_letter_topic: TopicName::parse(&dl.dead_letter_topic)?,
            max_delivery_attempts: u32::try_from(dl.max_delivery_attempts).map_err(|_| {
                PubSubError::invalid_argument("maxDeliveryAttempts must be positive")
            })?,
        }),
        _ => None,
    };
    let retry_policy = sub.retry_policy.as_ref().map(|rp| RetryPolicy {
        minimum_backoff: rp
            .minimum_backoff
            .as_ref()
            .map_or(LogicalDuration::ZERO, duration_from_proto),
        maximum_backoff: rp
            .maximum_backoff
            .as_ref()
            .map_or(LogicalDuration::ZERO, duration_from_proto),
    });
    let push_config = PushConfig {
        push_endpoint: sub
            .push_config
            .as_ref()
            .map(|p| p.push_endpoint.clone())
            .unwrap_or_default(),
    };
    Ok(SubscriptionConfig {
        name,
        topic,
        ack_deadline_seconds,
        enable_message_ordering: sub.enable_message_ordering,
        filter,
        dead_letter_policy,
        retry_policy,
        push_config,
    })
}

/// Renders a subscription config as a wire `Subscription`, reporting `reported_topic` (which is
/// `_deleted-topic_` when the topic has been deleted).
#[must_use]
pub fn subscription_to_proto(
    config: &SubscriptionConfig,
    reported_topic: &str,
) -> pb::Subscription {
    pb::Subscription {
        name: config.name.to_full(),
        topic: reported_topic.to_owned(),
        ack_deadline_seconds: i32::try_from(config.ack_deadline_seconds).unwrap_or(10),
        enable_message_ordering: config.enable_message_ordering,
        filter: String::new(),
        dead_letter_policy: config
            .dead_letter_policy
            .as_ref()
            .map(|dl| pb::DeadLetterPolicy {
                dead_letter_topic: dl.dead_letter_topic.to_full(),
                max_delivery_attempts: i32::try_from(dl.max_delivery_attempts).unwrap_or(5),
            }),
        retry_policy: config.retry_policy.map(|rp| pb::RetryPolicy {
            minimum_backoff: Some(duration_to_proto(rp.minimum_backoff)),
            maximum_backoff: Some(duration_to_proto(rp.maximum_backoff)),
        }),
        push_config: if config.is_push() {
            Some(pb::PushConfig {
                push_endpoint: config.push_config.push_endpoint.clone(),
                ..pb::PushConfig::default()
            })
        } else {
            None
        },
        ..pb::Subscription::default()
    }
}

/// Renders a topic name and labels as a wire `Topic`.
#[must_use]
pub fn topic_to_proto(name: &TopicName, labels: &BTreeMap<String, String>) -> pb::Topic {
    pb::Topic {
        name: name.to_full(),
        labels: labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        ..pb::Topic::default()
    }
}
