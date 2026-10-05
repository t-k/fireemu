//! Conversions between the `google.pubsub.v1` protobuf types and the core state machine, plus
//! the mapping from a [`PubSubError`] to a `tonic::Status`.

use std::collections::BTreeMap;

use fireemu_core_pubsub::subscription::{
    DeadLetterPolicy, ExpirationPolicy, PushConfig, RetryPolicy, DEFAULT_ACK_DEADLINE_SECONDS,
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
    tonic::Status::new(code, wire_error_message(err))
}

/// Renders the production leaf-resource diagnostics without changing the core error class.
pub(crate) fn wire_error_message(err: &PubSubError) -> String {
    let prefix = match err.code() {
        Code::NotFound => "Resource not found",
        Code::AlreadyExists => "Resource already exists in the project",
        _ => return err.message().to_owned(),
    };
    let suffix = match err.code() {
        Code::NotFound => " not found",
        _ => " already exists",
    };
    let resource = ["topic ", "subscription ", "snapshot ", "dead-letter topic "]
        .iter()
        .find_map(|kind| err.message().strip_prefix(kind))
        .and_then(|message| message.strip_suffix(suffix));
    resource.and_then(|name| name.rsplit_once('/')).map_or_else(
        || err.message().to_owned(),
        |(_, leaf)| format!("{prefix} (resource={leaf})."),
    )
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
pub fn received_to_proto(
    r: &ReceivedMessage,
    report_attempt: bool,
    policy: crate::PagingPolicy,
) -> pb::ReceivedMessage {
    pb::ReceivedMessage {
        ack_id: crate::ack_token::wire(&r.ack_id, policy),
        message: Some(message_to_proto(&r.message)),
        delivery_attempt: if report_attempt {
            i32::try_from(r.delivery_attempt).unwrap_or(i32::MAX)
        } else {
            0
        },
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

pub(crate) fn duration_to_proto(d: LogicalDuration) -> prost_types::Duration {
    let nanos = d.as_nanos();
    prost_types::Duration {
        seconds: i64::try_from(nanos.div_euclid(NANOS_PER_SEC)).unwrap_or(0),
        nanos: i32::try_from(nanos.rem_euclid(NANOS_PER_SEC)).unwrap_or(0),
    }
}

/// Rejects push fields that have no representation in the core state machine.
pub fn validate_push_config_options(push: Option<&pb::PushConfig>) -> Result<(), PubSubError> {
    let unsupported = push.and_then(|push| {
        if push.authentication_method.as_ref().is_some_and(|method| !matches!(method, pb::push_config::AuthenticationMethod::OidcToken(token) if token.service_account_email.is_empty() && token.audience.is_empty())) {
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

/// Subscription fields declared by `google.pubsub.v1.Subscription` whose value the emulator
/// applies. Every other declared field is refused explicitly instead of being dropped.
pub const SUPPORTED_SUBSCRIPTION_FIELDS: [&str; 13] = [
    "name",
    "topic",
    "ack_deadline_seconds",
    "enable_message_ordering",
    "retain_acked_messages",
    "message_retention_duration",
    "filter",
    "dead_letter_policy",
    "retry_policy",
    "push_config",
    "labels",
    "expiration_policy",
    "state",
];

/// Subscription fields declared by `google.pubsub.v1.Subscription` that the emulator cannot
/// represent. Naming one of these is an explicit unsupported-feature refusal; naming anything
/// outside both tables is an unknown field, which is an invalid argument.
pub const UNSUPPORTED_SUBSCRIPTION_FIELDS: [&str; 9] = [
    "bigquery_config",
    "cloud_storage_config",
    "bigtable_config",
    "detached",
    "enable_exactly_once_delivery",
    "topic_message_retention_duration",
    "analytics_hub_subscription_info",
    "message_transforms",
    "tags",
];

/// Reports whether `field` is a subscription field declared by the wire schema.
#[must_use]
pub fn is_declared_subscription_field(field: &str) -> bool {
    SUPPORTED_SUBSCRIPTION_FIELDS.contains(&field)
        || UNSUPPORTED_SUBSCRIPTION_FIELDS.contains(&field)
}

/// Rejects an `UpdateSubscription` field mask that names a field the emulator cannot apply.
///
/// Configuration fields are selected as complete field values. Immutable fields and unknown
/// paths are invalid arguments; managed fields outside the broker subset remain unsupported.
pub fn validate_subscription_update_paths<S: AsRef<str>>(paths: &[S]) -> Result<(), PubSubError> {
    for path in paths {
        let path = path.as_ref();
        if [
            "ack_deadline_seconds",
            "push_config",
            "labels",
            "expiration_policy",
            "retain_acked_messages",
            "message_retention_duration",
            "retry_policy",
            "dead_letter_policy",
        ]
        .contains(&path)
        {
            continue;
        }
        if ["name", "topic", "enable_message_ordering", "filter"].contains(&path) {
            return Err(PubSubError::invalid_argument(format!("Invalid update_mask provided in the UpdateSubscriptionRequest: the '{path}' field in the Subscription is not mutable.")));
        }
        if is_declared_subscription_field(path) {
            return Err(PubSubError::unimplemented(format!(
                "updating {path} is not supported by the Pub/Sub emulator"
            )));
        }
        return Err(PubSubError::invalid_argument(format!("Invalid update_mask provided in the UpdateSubscriptionRequest: '{path}' is not a known Subscription field. Note that field paths must be of the form 'push_config' rather than 'pushConfig'.")));
    }
    Ok(())
}

/// Rejects subscription fields that have no representation in the core state machine.
pub fn validate_subscription_options(sub: &pb::Subscription) -> Result<(), PubSubError> {
    let unsupported = if sub.bigquery_config.is_some() {
        Some("bigquery_config")
    } else if sub.cloud_storage_config.is_some() {
        Some("cloud_storage_config")
    } else if sub.bigtable_config.is_some() {
        Some("bigtable_config")
    } else if sub.detached {
        Some("detached")
    } else if sub.enable_exactly_once_delivery {
        Some("enable_exactly_once_delivery")
    } else if sub.topic_message_retention_duration.is_some() {
        Some("topic_message_retention_duration")
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

/// Topic fields declared by `google.pubsub.v1.Topic` whose value the emulator applies, plus the
/// output-only fields it accepts and ignores on input.
pub const SUPPORTED_TOPIC_FIELDS: [&str; 5] = [
    "name",
    "labels",
    "state",
    "satisfies_pzs",
    "message_retention_duration",
];

/// Topic fields declared by `google.pubsub.v1.Topic` that the emulator cannot represent. Naming
/// one of these is an explicit unsupported-feature refusal; a name outside both tables is an
/// unknown field, which is an invalid argument.
pub const UNSUPPORTED_TOPIC_FIELDS: [&str; 6] = [
    "schema_settings",
    "kms_key_name",
    "message_storage_policy",
    "ingestion_data_source_settings",
    "message_transforms",
    "tags",
];

/// Reports whether `field` is a topic field declared by the wire schema.
#[must_use]
pub fn is_declared_topic_field(field: &str) -> bool {
    SUPPORTED_TOPIC_FIELDS.contains(&field) || UNSUPPORTED_TOPIC_FIELDS.contains(&field)
}

/// Rejects topic fields that are accepted by the wire schema but not represented by the core
/// broker state. Output-only and reserved fields are intentionally ignored by this validator.
pub fn validate_topic_options(topic: &pb::Topic) -> Result<(), PubSubError> {
    let unsupported = if topic.schema_settings.is_some() {
        Some("schema_settings")
    } else if !topic.kms_key_name.is_empty() {
        Some("kms_key_name")
    } else if topic.message_storage_policy.is_some() {
        Some("message_storage_policy")
    } else if topic.ingestion_data_source_settings.is_some() {
        Some("ingestion_data_source_settings")
    } else if !topic.message_transforms.is_empty() {
        Some("message_transforms")
    } else if !topic.tags.is_empty() {
        Some("tags")
    } else {
        None
    };
    unsupported.map_or(Ok(()), |field| {
        Err(PubSubError::unimplemented(format!(
            "topic.{field} is not supported by the Pub/Sub emulator"
        )))
    })
}

/// Rejects unsupported fields named by an `UpdateTopic` field mask before the endpoint's generic
/// unsupported response. This keeps a future update implementation from silently dropping them.
pub fn validate_topic_update_options(request: &pb::UpdateTopicRequest) -> Result<(), PubSubError> {
    if let Some(mask) = request.update_mask.as_ref() {
        for path in &mask.paths {
            let head = path.split_once('.').map_or(path.as_str(), |(head, _)| head);
            if UNSUPPORTED_TOPIC_FIELDS.contains(&head) {
                return Err(PubSubError::unimplemented(format!(
                    "topic.{head} is not supported by the Pub/Sub emulator"
                )));
            }
            if !is_declared_topic_field(head) {
                return Err(PubSubError::invalid_argument(format!(
                    "unknown update_mask path {path}"
                )));
            }
        }
    } else if let Some(topic) = request.topic.as_ref() {
        validate_topic_options(topic)?;
    }
    Ok(())
}

/// Builds a validated [`SubscriptionConfig`] from a wire `Subscription`.
pub(crate) fn duration_from_proto(
    duration: &prost_types::Duration,
) -> Result<LogicalDuration, PubSubError> {
    if duration.seconds < 0 || !(0..1_000_000_000).contains(&duration.nanos) {
        return Err(PubSubError::invalid_argument(
            "duration must use non-negative canonical seconds and nanos",
        ));
    }
    Ok(LogicalDuration::from_nanos(
        i128::from(duration.seconds) * NANOS_PER_SEC + i128::from(duration.nanos),
    ))
}

pub(crate) fn push_config_from_proto(
    push: Option<&pb::PushConfig>,
    policy: crate::PagingPolicy,
) -> Result<PushConfig, PubSubError> {
    validate_push_config_options(push)?;
    let Some(push) = push else {
        return Ok(PushConfig::default());
    };
    let endpoint = &push.push_endpoint;
    if !endpoint.is_empty() {
        let uri = endpoint.parse::<axum::http::Uri>().ok();
        let valid = uri.as_ref().is_some_and(|uri| {
            uri.host().is_some() && matches!(uri.scheme_str(), Some("http" | "https"))
        });
        let strict = policy == crate::PagingPolicy::Strict;
        if !valid
            || (strict
                && uri
                    .as_ref()
                    .is_none_or(|uri| uri.scheme_str() != Some("https"))
                && crate::push::validate_endpoint(endpoint).is_err())
        {
            return Err(PubSubError::invalid_argument(format!("Invalid push endpoint given (endpoint={endpoint}). Refer to https://cloud.google.com/pubsub/subscriber#create for more information.")));
        }
    }
    if policy == crate::PagingPolicy::Strict {
        if let Some(version) = push.attributes.get("x-goog-version") {
            if version != "v1" && !endpoint.is_empty() {
                return Err(PubSubError::invalid_argument(format!(
                    "Invalid push endpoint version given in push config (version={version})."
                )));
            }
        }
    }
    Ok(PushConfig {
        push_endpoint: endpoint.clone(),
        attributes: if endpoint.is_empty() {
            BTreeMap::new()
        } else {
            push.attributes
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        },
    })
}

pub(crate) fn validate_strict_ack_deadline(value: i32) -> Result<(), PubSubError> {
    if value != 0 && !(10..=600).contains(&value) {
        return Err(PubSubError::invalid_argument(format!("Invalid ack deadline given (ack_deadline={value}). The ack deadline must be between 10 and 600 seconds.")));
    }
    Ok(())
}

pub(crate) fn subscription_from_proto_with_policy(
    sub: &pb::Subscription,
    policy: crate::PagingPolicy,
) -> Result<SubscriptionConfig, PubSubError> {
    let mut config = subscription_from_proto(sub)?;
    config.push_config = push_config_from_proto(sub.push_config.as_ref(), policy)?;
    if policy == crate::PagingPolicy::Strict {
        validate_strict_ack_deadline(sub.ack_deadline_seconds)?;
        if config.message_retention_duration.is_none() {
            config.message_retention_duration = Some(
                config
                    .expiration_policy
                    .and_then(|policy| policy.ttl)
                    .map_or(LogicalDuration::from_seconds(604_800), |ttl| {
                        ttl.min(LogicalDuration::from_seconds(604_800))
                    }),
            );
        }
        config.validate_production_configuration()?;
    }
    Ok(config)
}

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
    let push_config =
        push_config_from_proto(sub.push_config.as_ref(), crate::PagingPolicy::Emulator)?;
    let message_retention_duration = sub
        .message_retention_duration
        .as_ref()
        .map(duration_from_proto)
        .transpose()?;
    Ok(SubscriptionConfig {
        labels: sub
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        expiration_policy: sub
            .expiration_policy
            .as_ref()
            .map(|policy| {
                Ok::<_, PubSubError>(ExpirationPolicy {
                    ttl: policy.ttl.as_ref().map(duration_from_proto).transpose()?,
                })
            })
            .transpose()?,
        retain_acked_messages: sub.retain_acked_messages,
        message_retention_duration,
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
    policy: crate::PagingPolicy,
) -> pb::Subscription {
    pb::Subscription {
        name: config.name.to_full(),
        topic: reported_topic.to_owned(),
        ack_deadline_seconds: i32::try_from(config.ack_deadline_seconds).unwrap_or(10),
        enable_message_ordering: config.enable_message_ordering,
        retain_acked_messages: config.retain_acked_messages,
        message_retention_duration: config
            .message_retention_duration
            .map(duration_to_proto)
            .or_else(|| {
                (policy == crate::PagingPolicy::Strict).then_some(prost_types::Duration {
                    seconds: 604_800,
                    nanos: 0,
                })
            }),
        labels: config
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        expiration_policy: config
            .expiration_policy
            .map(|policy| pb::ExpirationPolicy {
                ttl: policy.ttl.map(duration_to_proto),
            })
            .or_else(|| {
                (policy == crate::PagingPolicy::Strict).then_some(pb::ExpirationPolicy {
                    ttl: Some(prost_types::Duration {
                        seconds: 2_678_400,
                        nanos: 0,
                    }),
                })
            }),
        state: if policy == crate::PagingPolicy::Strict {
            pb::subscription::State::Active as i32
        } else {
            0
        },
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
        push_config: if config.is_push() || policy == crate::PagingPolicy::Strict {
            Some(pb::PushConfig {
                push_endpoint: config.push_config.push_endpoint.clone(),
                attributes: config
                    .push_config
                    .attributes
                    .iter()
                    .filter(|(key, _)| {
                        policy == crate::PagingPolicy::Emulator || key.as_str() != "x-goog-version"
                    })
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn strict_push_admission_distinguishes_remote_http_https_and_loopback(host in "[a-z]{1,12}", path in "[a-z]{1,12}") {
            for (endpoint, strict_ok) in [(format!("http://{host}.example/{path}"), false), (format!("https://{host}.example/{path}"), true), (format!("http://127.0.0.1:1/{path}"), true)] {
                let push = pb::PushConfig { push_endpoint: endpoint, ..Default::default() };
                prop_assert_eq!(push_config_from_proto(Some(&push), crate::PagingPolicy::Strict).is_ok(), strict_ok);
                prop_assert!(push_config_from_proto(Some(&push), crate::PagingPolicy::Emulator).is_ok());
            }
        }
        #[test]
        fn strict_native_default_retention_matches_ttl_reference(ttl in 86_400i64..=2_678_400, explicit in any::<bool>()) {
            let input = pb::Subscription {
                name: "projects/demo-app/subscriptions/ttl-property".to_owned(), topic: "projects/demo-app/topics/ttl-property".to_owned(),
                expiration_policy: Some(pb::ExpirationPolicy { ttl: Some(prost_types::Duration { seconds: ttl, nanos: 0 }) }),
                message_retention_duration: explicit.then_some(prost_types::Duration { seconds: 600, nanos: 0 }), ..Default::default()
            };
            let strict = subscription_from_proto_with_policy(&input, crate::PagingPolicy::Strict).unwrap();
            prop_assert_eq!(strict.resolved_retention(), LogicalDuration::from_seconds(if explicit { 600 } else { ttl.min(604_800) }));
            let emulator = subscription_from_proto_with_policy(&input, crate::PagingPolicy::Emulator).unwrap();
            prop_assert_eq!(emulator.message_retention_duration.is_some(), explicit);
        }
        #[test]
        fn subscription_update_path_error_classes_are_distinct(path in prop::sample::select(vec!["name", "topic", "enable_message_ordering", "filter", "no_such_field", "pushConfig", "enable_exactly_once_delivery", "labels", "push_config"])) {
            let result = validate_subscription_update_paths(&[path]);
            if ["labels", "push_config"].contains(&path) { prop_assert!(result.is_ok()); }
            else {
                let error = result.unwrap_err();
                if ["name", "topic", "enable_message_ordering", "filter"].contains(&path) {
                    prop_assert_eq!(error.code(), Code::InvalidArgument);
                    prop_assert_eq!(error.message(), format!("Invalid update_mask provided in the UpdateSubscriptionRequest: the '{path}' field in the Subscription is not mutable."));
                } else if path == "enable_exactly_once_delivery" { prop_assert_eq!(error.code(), Code::Unimplemented); }
                else {
                    prop_assert_eq!(error.code(), Code::InvalidArgument);
                    prop_assert!(error.message().contains("not a known Subscription field"));
                }
            }
        }
    }

    proptest! {
        #[test]
        fn resource_errors_preserve_leaf_and_unrelated_diagnostics(leaf in "[a-z][a-z0-9-]{2,30}", kind in prop_oneof![Just("topic"), Just("subscription"), Just("snapshot"),Just("dead-letter topic")]) {
            let error = fireemu_core_pubsub::PubSubError::not_found(format!("{kind} projects/demo-app/resources/{leaf} not found"));
            prop_assert_eq!(super::wire_error_message(&error),format!("Resource not found (resource={leaf})."));
            let error = fireemu_core_pubsub::PubSubError::already_exists(format!("{kind} projects/demo-app/resources/{leaf} already exists"));
            prop_assert_eq!(super::wire_error_message(&error),format!("Resource already exists in the project (resource={leaf})."));
            let error = fireemu_core_pubsub::PubSubError::invalid_argument(leaf.clone());
            prop_assert_eq!(super::wire_error_message(&error),leaf);
        }
    }
    proptest! {
        #[test]
        fn strict_creation_ack_deadline_matches_recorded_bounds(value in -100i32..700) {
            prop_assert_eq!(validate_strict_ack_deadline(value).is_ok(),value==0 || (10..=600).contains(&value));
        }
    }
    use fireemu_core_pubsub::Code;

    use super::pb;

    proptest! {
        #[test]
        fn push_configuration_admission_does_not_admit_network_delivery(host in "[a-z]{1,20}", path in "[a-z/]{1,30}",version in "v[0-9]{1,3}") {
            let endpoint=format!("https://{host}.example/{path}");
            let push=pb::PushConfig {push_endpoint:endpoint.clone(),attributes:[("x-goog-version".to_owned(),version.clone())].into(),..Default::default()};
            prop_assert_eq!(push_config_from_proto(Some(&push),crate::PagingPolicy::Strict).is_ok(),version=="v1");
            prop_assert!(push_config_from_proto(Some(&push),crate::PagingPolicy::Emulator).is_ok());
            prop_assert!(crate::push::validate_endpoint(&endpoint).is_err());
        }
        #[test]
        fn subscription_update_paths_admit_only_selected_mutable_fields(path in prop_oneof![Just("labels"),Just("retain_acked_messages"),Just("message_retention_duration"),Just("expiration_policy"),Just("retry_policy"),Just("ack_deadline_seconds"),Just("push_config"),Just("dead_letter_policy"),Just("topic"),Just("filter"),Just("enable_message_ordering"),Just(""),Just("no_such_field")]) {
            let expected=["labels","retain_acked_messages","message_retention_duration","expiration_policy","retry_policy","ack_deadline_seconds","push_config","dead_letter_policy"].contains(&path);
            prop_assert_eq!(validate_subscription_update_paths(&[path]).is_ok(),expected);
        }
    }

    #[test]
    fn topic_option_validation_rejects_each_unrepresentable_value() {
        let cases = [
            (
                "schema_settings",
                pb::Topic {
                    schema_settings: Some(pb::SchemaSettings::default()),
                    ..Default::default()
                },
            ),
            (
                "message_retention_duration",
                pb::Topic {
                    message_retention_duration: Some(prost_types::Duration {
                        seconds: 600,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            (
                "kms_key_name",
                pb::Topic {
                    kms_key_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k".to_owned(),
                    ..Default::default()
                },
            ),
            (
                "message_storage_policy",
                pb::Topic {
                    message_storage_policy: Some(pb::MessageStoragePolicy::default()),
                    ..Default::default()
                },
            ),
            (
                "ingestion_data_source_settings",
                pb::Topic {
                    ingestion_data_source_settings: Some(pb::IngestionDataSourceSettings::default()),
                    ..Default::default()
                },
            ),
            (
                "message_transforms",
                pb::Topic {
                    message_transforms: vec![pb::MessageTransform::default()],
                    ..Default::default()
                },
            ),
            (
                "tags",
                pb::Topic {
                    tags: HashMap::from([(String::from("env"), String::from("test"))]),
                    ..Default::default()
                },
            ),
        ];
        for (field, topic) in cases
            .into_iter()
            .filter(|(field, _)| *field != "message_retention_duration")
        {
            let error = validate_topic_options(&topic).unwrap_err();
            assert_eq!(error.code(), Code::Unimplemented);
            assert!(error.message().contains(field), "{field}: {error}");
        }
    }

    #[test]
    fn topic_option_validation_accepts_supported_and_output_only_defaults() {
        assert!(validate_topic_options(&pb::Topic::default()).is_ok());
        assert!(validate_topic_options(&pb::Topic {
            name: "projects/p/topics/t".to_owned(),
            labels: HashMap::from([(String::from("env"), String::from("test"))]),
            satisfies_pzs: true,
            state: pb::topic::State::Active as i32,
            ..Default::default()
        })
        .is_ok());
    }

    #[test]
    fn topic_update_validation_rejects_unsupported_mask_even_without_a_value() {
        let error = validate_topic_update_options(&pb::UpdateTopicRequest {
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["schema_settings".to_owned()],
            }),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(error.code(), Code::Unimplemented);
        assert!(error.message().contains("schema_settings"));
    }

    #[test]
    fn topic_update_validation_only_checks_values_selected_by_the_mask() {
        assert!(validate_topic_update_options(&pb::UpdateTopicRequest {
            topic: Some(pb::Topic {
                schema_settings: Some(pb::SchemaSettings::default()),
                ..Default::default()
            }),
            update_mask: Some(prost_types::FieldMask {
                paths: vec!["labels".to_owned()],
            }),
        })
        .is_ok());
    }
}
