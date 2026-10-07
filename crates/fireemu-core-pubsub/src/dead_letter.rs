//! Recorded dead-letter envelope metadata; broker transfer eligibility stays separate.

use crate::{PubSubError, PubsubMessage, Result, StoredMessage, SubscriptionName};

/// Copies the source payload and adds the recorded forwarding attribution fields.
///
/// The caller supplies the source delivery count captured with the pending transfer. The source publication time uses the observed millisecond precision and numeric UTC offset. Publication assigns a new destination identity separately.
///
/// # Errors
///
/// Returns an error if the source publication time cannot be represented as RFC3339.
pub fn forwarded_message(
    source: &StoredMessage,
    subscription: &SubscriptionName,
    delivery_count: u32,
) -> Result<PubsubMessage> {
    let timestamp = source.publish_time.to_rfc3339().map_err(|_| {
        PubSubError::invalid_argument("source publication time cannot be represented as RFC3339")
    })?;
    let utc = timestamp
        .strip_suffix('Z')
        .expect("canonical UTC timestamp");
    let (seconds, fraction) = utc
        .split_once('.')
        .map_or((utc, "000"), |(seconds, fraction)| {
            (seconds, &fraction[..3])
        });
    let mut message = source.message.clone();
    for (key, value) in [
        (
            "CloudPubSubDeadLetterSourceSubscription",
            subscription.subscription().to_owned(),
        ),
        (
            "CloudPubSubDeadLetterSourceSubscriptionProject",
            subscription.project().to_owned(),
        ),
        (
            "CloudPubSubDeadLetterSourceTopicPublishTime",
            format!("{seconds}.{fraction}+00:00"),
        ),
        (
            "CloudPubSubDeadLetterSourceDeliveryCount",
            delivery_count.to_string(),
        ),
    ] {
        message.attributes.insert(key.to_owned(), value);
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_core_types::time::LogicalInstant;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    proptest! {
        #[test]
        fn envelope_preserves_payload_and_binds_source_metadata(
            data in proptest::collection::vec(any::<u8>(), 0..256),
            project in "[a-z]{6,20}",
            subscription in "[a-z]{6,30}",
            ordering in "[a-z]{0,20}",
            seconds in 1_600_000_000i64..1_900_000_000,
            millis in 0u32..1000,
            count in 5u32..101,
            user in "[a-z]{0,40}",
        ) {
            let name=SubscriptionName::new(project.clone(),subscription.clone()).unwrap();
            let source=StoredMessage {
                message_id:"source-identity".into(),
                publish_time:LogicalInstant::from_nanos(i128::from(seconds)*1_000_000_000+i128::from(millis)*1_000_000),
                message:PubsubMessage {data:data.clone(),attributes:BTreeMap::from([("user".into(),user.clone())]),ordering_key:ordering.clone()},
            };
            let original=source.clone();
            let wrapped=forwarded_message(&source,&name,count).unwrap();
            prop_assert_eq!(&source,&original);
            prop_assert_eq!(&wrapped.data,&data);
            prop_assert_eq!(&wrapped.ordering_key,&ordering);
            prop_assert_eq!(wrapped.attributes.get("user"),Some(&user));
            prop_assert_eq!(wrapped.attributes.len(),5);
            prop_assert_eq!(&wrapped.attributes["CloudPubSubDeadLetterSourceSubscriptionProject"],&project);
            prop_assert_eq!(&wrapped.attributes["CloudPubSubDeadLetterSourceSubscription"],&subscription);
            prop_assert_eq!(&wrapped.attributes["CloudPubSubDeadLetterSourceDeliveryCount"],&count.to_string());
            let time=&wrapped.attributes["CloudPubSubDeadLetterSourceTopicPublishTime"];
            prop_assert_eq!(time.len(),29);
            prop_assert!(time.ends_with("+00:00"));
            prop_assert_eq!(LogicalInstant::parse_rfc3339(time).unwrap(),original.publish_time);
        }
    }

    #[test]
    fn attribution_is_owned_by_the_source_and_unrepresentable_time_fails() {
        let name = SubscriptionName::new("demo-project", "source-sub").unwrap();
        let mut source = StoredMessage {
            message_id: "source".into(),
            publish_time: LogicalInstant::UNIX_EPOCH,
            message: PubsubMessage::default(),
        };
        source.message.attributes.insert(
            "CloudPubSubDeadLetterSourceSubscriptionProject".into(),
            "foreign-project".into(),
        );
        let message = forwarded_message(&source, &name, 7).unwrap();
        assert_eq!(
            message.attributes["CloudPubSubDeadLetterSourceSubscriptionProject"],
            "demo-project"
        );
        assert_eq!(
            message.attributes["CloudPubSubDeadLetterSourceDeliveryCount"],
            "7"
        );
        assert_eq!(
            message.attributes["CloudPubSubDeadLetterSourceTopicPublishTime"],
            "1970-01-01T00:00:00.000+00:00"
        );
        source.publish_time = LogicalInstant::MAX;
        assert!(forwarded_message(&source, &name, 7).is_err());
    }
}
