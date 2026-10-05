//! Strict unary request admission from the two frozen production recordings.
use fireemu_core_pubsub::{PubSubError, Result};

pub(crate) fn max_messages(value: i64) -> Result<usize> {
    usize::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            PubSubError::invalid_argument(
                "You have passed an invalid argument to the service (argument=max_messages).",
            )
        })
}

pub(crate) fn ack_deadline(value: i64) -> Result<u32> {
    if !(0..=600).contains(&value) {
        return Err(PubSubError::invalid_argument(format!("Invalid ack deadline given (ack_deadline={value}). The ack deadline must be between 0 and 600 seconds.")));
    }
    Ok(u32::try_from(value).expect("checked ack deadline"))
}

pub(crate) fn ack_ids(ids: &[String]) -> Result<Vec<String>> {
    if ids.is_empty() {
        return Err(PubSubError::invalid_argument(
            "You have not specified an ack ID in the request.",
        ));
    }
    ids.iter()
        .map(|id| {
            crate::ack_token::decode(id).ok_or_else(|| {
                PubSubError::invalid_argument(format!(
                    "You have passed an invalid ack ID to the service (ack_id={id})."
                ))
            })
        })
        .collect()
}

pub(crate) fn message_count(value: usize) -> Result<()> {
    if value == 0 {
        return Err(PubSubError::invalid_argument("The value for message_count is too small. You passed 0 in the request, but the minimum value is 1."));
    }
    if value > 1000 {
        return Err(PubSubError::invalid_argument(format!("The value for message_count is too large. You passed {value} in the request, but the maximum value is 1000.")));
    }
    Ok(())
}

pub(crate) fn publish_request_size(value: usize) -> Result<()> {
    if value > 10_485_760 {
        return Err(PubSubError::invalid_argument(
            "Request payload size exceeds the limit: 10485760 bytes.",
        ));
    }
    if value > 10_000_000 {
        return Err(PubSubError::invalid_argument(format!("The value for request_size is too large. You passed {value} in the request, but the maximum value is 10000000.")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn strict_counts_and_deadlines_follow_reference_bounds(value in -2_000i64..2_000) {
            prop_assert_eq!(max_messages(value).is_ok(),value>0);
            if value>0 {prop_assert_eq!(max_messages(value).unwrap(), usize::try_from(value).unwrap());}
            prop_assert_eq!(ack_deadline(value).is_ok(),(0..=600).contains(&value));
            if (0..=600).contains(&value) {prop_assert_eq!(ack_deadline(value).unwrap(),u32::try_from(value).unwrap());}
            let count = usize::try_from(value.max(0)).unwrap();
            prop_assert_eq!(message_count(count).is_ok(),(1..=1000).contains(&count));
        }

        #[test]
        fn ack_id_near_misses_do_not_admit_foreign_shapes(value in any::<u64>(), wrong in "[a-z]{1,18}") {
            let id = crate::ack_token::wire(&format!("ack-{value:016x}"),crate::PagingPolicy::Strict);
            prop_assert!(ack_ids(&[id]).is_ok());
            prop_assert!(ack_ids(&[]).is_err());
            prop_assert!(ack_ids(&[wrong]).is_err());
        }
    }

    proptest! {
        #[test]
        fn encoded_publish_size_follows_decimal_service_bound(value in 9_990_000usize..10_490_000) {
            prop_assert_eq!(publish_request_size(value).is_ok(),value<=10_000_000);
        }
    }

    #[test]
    fn recorded_large_publish_refusals_have_exact_messages() {
        assert_eq!(publish_request_size(10_000_068).unwrap_err().message(),"The value for request_size is too large. You passed 10000068 in the request, but the maximum value is 10000000.");
        assert_eq!(
            publish_request_size(10_485_761).unwrap_err().message(),
            "Request payload size exceeds the limit: 10485760 bytes."
        );
    }

    #[test]
    fn recorded_request_refusals_have_exact_messages() {
        assert_eq!(
            max_messages(0).unwrap_err().message(),
            "You have passed an invalid argument to the service (argument=max_messages)."
        );
        assert_eq!(ack_deadline(601).unwrap_err().message(), "Invalid ack deadline given (ack_deadline=601). The ack deadline must be between 0 and 600 seconds.");
        assert_eq!(
            ack_ids(&[]).unwrap_err().message(),
            "You have not specified an ack ID in the request."
        );
        assert_eq!(
            ack_ids(&["not-an-ack-id".to_owned()])
                .unwrap_err()
                .message(),
            "You have passed an invalid ack ID to the service (ack_id=not-an-ack-id)."
        );
        assert_eq!(message_count(0).unwrap_err().message(), "The value for message_count is too small. You passed 0 in the request, but the minimum value is 1.");
        assert_eq!(message_count(1001).unwrap_err().message(), "The value for message_count is too large. You passed 1001 in the request, but the maximum value is 1000.");
    }
}
