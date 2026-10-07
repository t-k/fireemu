//! Profile-scoped JSON layout. Message fields follow protobuf tags; map keys remain lexical.

use serde_json::ser::{Formatter, PrettyFormatter};
use serde_json::Value;

use crate::PagingPolicy;

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

pub(crate) fn encode(value: &Value, policy: PagingPolicy, schema: Schema) -> Vec<u8> {
    if policy == PagingPolicy::Emulator {
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[tokio::test]
    async fn early_body_errors_and_authentication_keep_profile_layout() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Method, Request};
        use fireemu_core_pubsub::PubSubState;
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::time::LogicalInstant;
        use std::sync::{Arc, Mutex};
        for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
            let handle = crate::PubSubHandle::new(
                Arc::new(Mutex::new(PubSubState::new(99))),
                Arc::new(Mutex::new(VirtualClock::new(
                    LogicalInstant::from_unix_seconds(0),
                ))),
                None,
            )
            .with_paging_policy(policy);
            for body in [
                b"{".to_vec(),
                vec![b' '; crate::MAX_MESSAGE_BYTES + 1024 * 1024 + 1],
            ] {
                let request = Request::builder()
                    .method(Method::PUT)
                    .uri("/v1/projects/demo-app/topics/t")
                    .body(Body::from(body))
                    .unwrap();
                let response = crate::rest::handle(request, handle.clone()).await;
                assert_eq!(response.status(), 400);
                let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    bytes.as_ref(),
                    encode(&value, policy, Schema::ErrorEnvelope)
                );
            }
            let response = crate::rest::unauthenticated(
                &Method::GET,
                "/v1/projects/demo-app/topics/t",
                policy,
            );
            assert_eq!(response.status(), 401);
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                bytes.as_ref(),
                encode(&value, policy, Schema::ErrorEnvelope)
            );
            if policy == PagingPolicy::Strict {
                assert_eq!(
                    keys_at_indent(&bytes, 4),
                    ["code", "message", "status", "details"]
                );
            }
        }
    }

    #[test]
    fn all_88_recorded_rest_body_lengths_match_reconstructed_layout() {
        // Values are character-class/escaped-length aliases. These independent expected bytes
        // reconstruct recorded member order; the original raw response buffers were not retained.
        let rows = include_str!("../tests/fixtures/production-rest-layout.jsonl");
        let mut seen = std::collections::BTreeSet::new();
        let mut per_run = std::collections::BTreeMap::new();
        for line in rows.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let run = row["run"].as_str().unwrap();
            assert!(seen.insert((run.to_owned(), row["n"].as_u64().unwrap())));
            *per_run.entry(run.to_owned()).or_insert(0) += 1;
            let schema = match row["schema"].as_str().unwrap() {
                "Topic" => Schema::Topic,
                "Subscription" => Schema::Subscription,
                "Topics" => Schema::Topics,
                "Subscriptions" => Schema::Subscriptions,
                "ErrorEnvelope" => Schema::ErrorEnvelope,
                other => panic!("unallocated recorded schema: {other}"),
            };
            let expected = row["expected"].as_str().unwrap();
            let body: Value = serde_json::from_str(expected).unwrap();
            let actual = encode(&body, PagingPolicy::Strict, schema);
            assert_eq!(actual, expected.as_bytes(), "run={run}, n={}", row["n"]);
            assert_eq!(
                u64::try_from(actual.len()).unwrap(),
                row["bodyBytes"].as_u64().unwrap()
            );
            assert_eq!(
                encode(&body, PagingPolicy::Emulator, schema),
                serde_json::to_vec(&body).unwrap()
            );
        }
        assert_eq!(seen.len(), 88);
        assert_eq!(per_run.values().copied().collect::<Vec<_>>(), [44, 44]);
    }

    fn keys_at_indent(bytes: &[u8], spaces: usize) -> Vec<String> {
        let prefix = " ".repeat(spaces) + "\"";
        String::from_utf8(bytes.to_vec())
            .unwrap()
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .map(|line| serde_json::from_str(line.trim().split_once(':').unwrap().0).unwrap())
            .collect()
    }

    #[test]
    fn nested_proto_order_keeps_map_keys_lexical_and_never_drops_unknown_fields() {
        let body = json!({"receivedMessages":[{"deliveryAttempt":2,"message":{
            "orderingKey":"k","publishTime":"2026-10-05T00:00:00Z","messageId":"opaque-id",
            "attributes":{"name":"map-name","labels":"map-label"},"data":"eA=="
        },"ackId":"opaque-ack"}]});
        let bytes = encode(&body, PagingPolicy::Strict, Schema::Pull);
        assert_eq!(
            keys_at_indent(&bytes, 6),
            ["ackId", "message", "deliveryAttempt"]
        );
        assert_eq!(
            keys_at_indent(&bytes, 8),
            [
                "data",
                "attributes",
                "messageId",
                "publishTime",
                "orderingKey"
            ]
        );
        assert_eq!(keys_at_indent(&bytes, 10), ["labels", "name"]);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), body);

        let subscription = json!({"retryPolicy":{"maximumBackoff":"600s","minimumBackoff":"10s"},
            "deadLetterPolicy":{"maxDeliveryAttempts":5,"deadLetterTopic":"projects/demo-app/topics/dlq"},
            "pushConfig":{"attributes":{"name":"x","labels":"y"},"pushEndpoint":"http://localhost/"},
            "topic":"projects/demo-app/topics/t","name":"projects/demo-app/subscriptions/s"});
        let bytes = encode(&subscription, PagingPolicy::Strict, Schema::Subscription);
        assert_eq!(
            keys_at_indent(&bytes, 2),
            [
                "name",
                "topic",
                "pushConfig",
                "deadLetterPolicy",
                "retryPolicy"
            ]
        );
        assert_eq!(
            keys_at_indent(&bytes, 4),
            [
                "pushEndpoint",
                "attributes",
                "deadLetterTopic",
                "maxDeliveryAttempts",
                "minimumBackoff",
                "maximumBackoff"
            ]
        );
        assert_eq!(keys_at_indent(&bytes, 6), ["labels", "name"]);

        for (schema, body, expected) in [
            (
                Schema::Snapshots,
                json!({"nextPageToken":"opaque","snapshots":[{"labels":{"name":"x","labels":"y"},"expireTime":"2026-10-05T00:00:00Z","topic":"t","name":"s"}]}),
                vec!["name", "topic", "expireTime", "labels"],
            ),
            (
                Schema::Topics,
                json!({"nextPageToken":"opaque","topics":[{"messageRetentionDuration":"600s","labels":{"name":"x","labels":"y"},"name":"t"}]}),
                vec!["name", "labels", "messageRetentionDuration"],
            ),
        ] {
            let bytes = encode(&body, PagingPolicy::Strict, schema);
            assert_eq!(keys_at_indent(&bytes, 6), expected);
            assert_eq!(keys_at_indent(&bytes, 8), ["labels", "name"]);
            assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), body);
        }
        let unknown = json!({"name":"t","futureZ":true,"futureA":{"topic":"data","name":"data"}});
        let bytes = encode(&unknown, PagingPolicy::Strict, Schema::Topic);
        assert_eq!(keys_at_indent(&bytes, 2), ["name", "futureA", "futureZ"]);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), unknown);
    }

    #[test]
    fn error_details_follow_their_declared_order_with_map_metadata() {
        let body = json!({"error":{"details":[{"metadata":{"reason":"data","domain":"data"},"domain":"pubsub.googleapis.com","reason":"CREDENTIALS_MISSING","@type":"type.googleapis.com/google.rpc.ErrorInfo"},
            {"fieldViolations":[{"description":"bad","field":"labels"}],"@type":"type.googleapis.com/google.rpc.BadRequest"}],"status":"UNAUTHENTICATED","message":"unsupported locally","code":401}});
        let bytes = encode(&body, PagingPolicy::Strict, Schema::ErrorEnvelope);
        assert_eq!(
            keys_at_indent(&bytes, 4),
            ["code", "message", "status", "details"]
        );
        assert_eq!(
            keys_at_indent(&bytes, 8),
            [
                "@type",
                "reason",
                "domain",
                "metadata",
                "@type",
                "fieldViolations"
            ]
        );
        assert_eq!(keys_at_indent(&bytes, 10), ["domain", "reason"]);
        assert_eq!(keys_at_indent(&bytes, 12), ["field", "description"]);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), body);
    }

    fn arbitrary_json() -> impl Strategy<Value = Value> {
        prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i32>().prop_map(|n| json!(n)),
            any::<String>().prop_map(Value::String)
        ]
        .prop_recursive(3, 48, 5, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                prop::collection::btree_map("[a-z]{1,8}", inner, 0..4)
                    .prop_map(|map| Value::Object(map.into_iter().collect()))
            ]
        })
    }

    proptest! {
        #[test]
        fn strict_maps_match_independent_serde_pretty_reference_and_emulator_stays_compact(value in arbitrary_json()) {
            let strict = encode(&value, PagingPolicy::Strict, Schema::Map);
            let mut expected = serde_json::to_vec_pretty(&value).unwrap(); expected.push(b'\n');
            prop_assert_eq!(&strict, &expected);
            prop_assert_eq!(serde_json::from_slice::<Value>(&strict).unwrap(), value.clone());
            prop_assert_eq!(encode(&value, PagingPolicy::Emulator, Schema::Map), serde_json::to_vec(&value).unwrap());
            prop_assert_eq!(strict.last(), Some(&b'\n'));
            prop_assert_ne!(strict.get(strict.len() - 2), Some(&b'\n'));
        }

        #[test]
        fn optional_subscription_fields_preserve_values_and_recorded_field_order(
            name in any::<String>(), topic in any::<String>(), push in any::<bool>(), retention in any::<bool>(), expiration in any::<bool>(),
            retain_acked in any::<bool>(), ordering in any::<bool>(), filter in any::<bool>(),
            labels in prop::collection::btree_map("[a-z]{1,8}", any::<String>(), 0..4),
        ) {
            let mut body = json!({"name":name,"topic":topic,"ackDeadlineSeconds":10,"state":"ACTIVE"});
            let mut expected = vec!["name","topic"];
            if push { body["pushConfig"] = json!({"attributes":{"name":"x","labels":"y"},"pushEndpoint":"http://localhost/"}); expected.push("pushConfig"); }
            expected.push("ackDeadlineSeconds");
            if retain_acked { body["retainAckedMessages"] = json!(true); expected.push("retainAckedMessages"); }
            if retention { body["messageRetentionDuration"] = json!("604800s"); expected.push("messageRetentionDuration"); }
            if !labels.is_empty() { body["labels"] = json!(labels); expected.push("labels"); }
            if ordering { body["enableMessageOrdering"] = json!(true); expected.push("enableMessageOrdering"); }
            if expiration { body["expirationPolicy"] = json!({"ttl":"2678400s"}); expected.push("expirationPolicy"); }
            if filter { body["filter"] = json!("attributes.foo = \"bar\""); expected.push("filter"); }
            expected.push("state");
            let strict = encode(&body, PagingPolicy::Strict, Schema::Subscription);
            prop_assert_eq!(keys_at_indent(&strict, 2), expected);
            prop_assert_eq!(serde_json::from_slice::<Value>(&strict).unwrap(), body.clone());
            prop_assert_eq!(encode(&body, PagingPolicy::Emulator, Schema::Subscription), serde_json::to_vec(&body).unwrap());
        }
    }
}
