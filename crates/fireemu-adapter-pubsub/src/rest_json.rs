//! Profile-scoped JSON layout. Message fields follow protobuf tags; map keys remain lexical.

use serde_json::ser::{Formatter, PrettyFormatter};
use serde_json::Value;

use crate::PubSubProfile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Schema {
    Topic,
    Subscription,
    Snapshot,
    Topics,
    Subscriptions,
    Snapshots,
    Publish,
    Pull,
    ReceivedMessage,
    Message,
    PushConfig,
    ExpirationPolicy,
    DeadLetterPolicy,
    RetryPolicy,
    ErrorEnvelope,
    Error,
    ErrorDetail,
    FieldViolation,
    Map,
}

impl Schema {
    fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Topic => &["name", "labels", "messageRetentionDuration"],
            Self::Subscription => &[
                "name",
                "topic",
                "pushConfig",
                "ackDeadlineSeconds",
                "retainAckedMessages",
                "messageRetentionDuration",
                "labels",
                "enableMessageOrdering",
                "expirationPolicy",
                "filter",
                "deadLetterPolicy",
                "retryPolicy",
                "state",
            ],
            Self::Snapshot => &["name", "topic", "expireTime", "labels"],
            Self::Topics => &["topics", "nextPageToken"],
            Self::Subscriptions => &["subscriptions", "nextPageToken"],
            Self::Snapshots => &["snapshots", "nextPageToken"],
            Self::Publish => &["messageIds"],
            Self::Pull => &["receivedMessages"],
            Self::ReceivedMessage => &["ackId", "message", "deliveryAttempt"],
            Self::Message => &[
                "data",
                "attributes",
                "messageId",
                "publishTime",
                "orderingKey",
            ],
            Self::PushConfig => &["pushEndpoint", "attributes"],
            Self::ExpirationPolicy => &["ttl"],
            Self::DeadLetterPolicy => &["deadLetterTopic", "maxDeliveryAttempts"],
            Self::RetryPolicy => &["minimumBackoff", "maximumBackoff"],
            Self::ErrorEnvelope => &["error"],
            Self::Error => &["code", "message", "status", "details"],
            Self::ErrorDetail => &["@type", "reason", "domain", "metadata", "fieldViolations"],
            Self::FieldViolation => &["field", "description"],
            Self::Map => &[],
        }
    }

    fn child(self, field: &str) -> Self {
        match (self, field) {
            (Self::Topics, "topics") => Self::Topic,
            (Self::Subscriptions, "subscriptions") => Self::Subscription,
            (Self::Snapshots, "snapshots") => Self::Snapshot,
            (Self::Subscription, "pushConfig") => Self::PushConfig,
            (Self::Subscription, "expirationPolicy") => Self::ExpirationPolicy,
            (Self::Subscription, "deadLetterPolicy") => Self::DeadLetterPolicy,
            (Self::Subscription, "retryPolicy") => Self::RetryPolicy,
            (Self::Pull, "receivedMessages") => Self::ReceivedMessage,
            (Self::ReceivedMessage, "message") => Self::Message,
            (Self::ErrorEnvelope, "error") => Self::Error,
            (Self::Error, "details") => Self::ErrorDetail,
            (Self::ErrorDetail, "fieldViolations") => Self::FieldViolation,
            _ => Self::Map,
        }
    }
}

pub(crate) fn encode(value: &Value, policy: PubSubProfile, schema: Schema) -> Vec<u8> {
    if policy == PubSubProfile::Emulator {
        return serde_json::to_vec(value).expect("JSON values serialize");
    }
    let mut bytes = Vec::new();
    let mut formatter = PrettyFormatter::with_indent(b"  ");
    write(value, schema, &mut bytes, &mut formatter).expect("writing JSON to a vector succeeds");
    bytes.push(b'\n');
    bytes
}

fn write(
    value: &Value,
    schema: Schema,
    output: &mut Vec<u8>,
    formatter: &mut PrettyFormatter<'_>,
) -> std::io::Result<()> {
    match value {
        Value::Object(object) => {
            formatter.begin_object(output)?;
            // Preserve unexpected fields in a lexical tail. This local fallback never drops data
            // and does not claim a production order for unobserved fields or map keys.
            let fields = schema.fields();
            let keys = fields
                .iter()
                .copied()
                .filter(|key| object.contains_key(*key))
                .chain(
                    object
                        .keys()
                        .map(String::as_str)
                        .filter(|key| !fields.contains(key)),
                );
            for (index, key) in keys.enumerate() {
                formatter.begin_object_key(output, index == 0)?;
                serde_json::to_writer(&mut *output, key).map_err(std::io::Error::other)?;
                formatter.end_object_key(output)?;
                formatter.begin_object_value(output)?;
                write(&object[key], schema.child(key), output, formatter)?;
                formatter.end_object_value(output)?;
            }
            formatter.end_object(output)
        }
        Value::Array(values) => {
            formatter.begin_array(output)?;
            for (index, value) in values.iter().enumerate() {
                formatter.begin_array_value(output, index == 0)?;
                write(value, schema, output, formatter)?;
                formatter.end_array_value(output)?;
            }
            formatter.end_array(output)
        }
        _ => serde_json::to_writer(output, value).map_err(std::io::Error::other),
    }
}
