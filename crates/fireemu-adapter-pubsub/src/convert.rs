//! Conversions between the `google.pubsub.v1` protobuf types and the core state machine, plus
//! the mapping from a [`PubSubError`] to a `tonic::Status`.

use std::collections::BTreeMap;

use fireemu_core_pubsub::subscription::{
    DeadLetterPolicy, PushConfig, RetryPolicy, DEFAULT_ACK_DEADLINE_SECONDS,
    DEFAULT_RETRY_MINIMUM_BACKOFF_SECONDS, MAX_RETRY_BACKOFF_SECONDS, MIN_DEAD_LETTER_ATTEMPTS,
};
use fireemu_core_pubsub::{
    Code, Filter, PubSubError, PubsubMessage, ReceivedMessage, Snapshot, StoredMessage,
    SubscriptionConfig, SubscriptionName, TopicName,
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

fn retry_duration_from_proto(
    duration: &prost_types::Duration,
) -> Result<LogicalDuration, PubSubError> {
    if duration.seconds < 0 || !(0..1_000_000_000).contains(&duration.nanos) {
        return Err(PubSubError::invalid_argument(
            "retry policy duration must use non-negative canonical seconds and nanos",
        ));
    }
    Ok(LogicalDuration::from_nanos(
        i128::from(duration.seconds) * NANOS_PER_SEC + i128::from(duration.nanos),
    ))
}

fn duration_to_proto(d: LogicalDuration) -> prost_types::Duration {
    let nanos = d.as_nanos();
    prost_types::Duration {
        seconds: i64::try_from(nanos.div_euclid(NANOS_PER_SEC)).unwrap_or(0),
        nanos: i32::try_from(nanos.rem_euclid(NANOS_PER_SEC)).unwrap_or(0),
    }
}

/// Rejects push fields that have no representation in the core state machine.
pub fn validate_push_config_options(push: Option<&pb::PushConfig>) -> Result<(), PubSubError> {
    let unsupported = push.and_then(|push| {
        if !push.attributes.is_empty() {
            Some("push_config.attributes")
        } else if push.authentication_method.is_some() {
            Some("push_config.authentication_method")
        } else if push.wrapper.is_some() {
            Some("push_config.wrapper")
        } else {
            None
        }
    });
    unsupported.map_or(Ok(()), |field| {
        Err(PubSubError::unimplemented(format!(
            "subscription.{field} is not supported by the Pub/Sub emulator"
        )))
    })
}

/// Rejects subscription fields that have no representation in the core state machine.
pub fn validate_subscription_options(sub: &pb::Subscription) -> Result<(), PubSubError> {
    let unsupported = if sub.bigquery_config.is_some() {
        Some("bigquery_config")
    } else if sub.cloud_storage_config.is_some() {
        Some("cloud_storage_config")
    } else if sub.bigtable_config.is_some() {
        Some("bigtable_config")
    } else if sub.retain_acked_messages {
        Some("retain_acked_messages")
    } else if sub.message_retention_duration.is_some() {
        Some("message_retention_duration")
    } else if !sub.labels.is_empty() {
        Some("labels")
    } else if sub.expiration_policy.is_some() {
        Some("expiration_policy")
    } else if sub.detached {
        Some("detached")
    } else if sub.enable_exactly_once_delivery {
        Some("enable_exactly_once_delivery")
    } else if sub.topic_message_retention_duration.is_some() {
        Some("topic_message_retention_duration")
    } else if sub.state != 0 {
        Some("state")
    } else if sub.analytics_hub_subscription_info.is_some() {
        Some("analytics_hub_subscription_info")
    } else if !sub.message_transforms.is_empty() {
        Some("message_transforms")
    } else if !sub.tags.is_empty() {
        Some("tags")
    } else {
        None
    };
    if let Some(field) = unsupported {
        return Err(PubSubError::unimplemented(format!(
            "subscription.{field} is not supported by the Pub/Sub emulator"
        )));
    }
    validate_push_config_options(sub.push_config.as_ref())
}

/// Builds a validated [`SubscriptionConfig`] from a wire `Subscription`.
pub fn subscription_from_proto(sub: &pb::Subscription) -> Result<SubscriptionConfig, PubSubError> {
    validate_subscription_options(sub)?;
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
            max_delivery_attempts: if dl.max_delivery_attempts == 0 {
                MIN_DEAD_LETTER_ATTEMPTS
            } else {
                u32::try_from(dl.max_delivery_attempts).map_err(|_| {
                    PubSubError::invalid_argument("maxDeliveryAttempts must be positive")
                })?
            },
        }),
        _ => None,
    };
    let retry_policy = sub
        .retry_policy
        .as_ref()
        .map(|rp| {
            Ok::<_, PubSubError>(RetryPolicy {
                minimum_backoff: rp
                    .minimum_backoff
                    .as_ref()
                    .map(retry_duration_from_proto)
                    .transpose()?
                    .unwrap_or_else(|| {
                        LogicalDuration::from_seconds(DEFAULT_RETRY_MINIMUM_BACKOFF_SECONDS)
                    }),
                maximum_backoff: rp
                    .maximum_backoff
                    .as_ref()
                    .map(retry_duration_from_proto)
                    .transpose()?
                    .unwrap_or_else(|| LogicalDuration::from_seconds(MAX_RETRY_BACKOFF_SECONDS)),
            })
        })
        .transpose()?;
    let push_endpoint = sub
        .push_config
        .as_ref()
        .map(|p| p.push_endpoint.clone())
        .unwrap_or_default();
    crate::push::validate_endpoint(&push_endpoint).map_err(PubSubError::invalid_argument)?;
    let push_config = PushConfig { push_endpoint };
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
        filter: config.filter.as_str().to_owned(),
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

/// Renders a core snapshot resource as the Pub/Sub wire representation.
#[must_use]
pub fn snapshot_to_proto(snapshot: &Snapshot) -> pb::Snapshot {
    pb::Snapshot {
        name: snapshot.name.clone(),
        topic: snapshot.topic.to_full(),
        expire_time: Some(to_timestamp(snapshot.expire_at)),
        labels: snapshot
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}
