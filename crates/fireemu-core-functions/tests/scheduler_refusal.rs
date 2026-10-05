//! Cloud Scheduler's refusal of a job whose `retryCount` is 5 or more.
//!
//! Source: the production deploy `e0ec2f416f5ea7e8` (SCHEDULED-FUNCTIONS delivery recording, 2026-10-05) created the
//! job of a function declared with `retryCount: 6`; Cloud Scheduler answered HTTP 400 `INVALID_ARGUMENT` with the
//! message pinned here. Only the count 6 was observed; the boundary at 5 is the message's own statement.

use fireemu_core_functions::manifest::{
    ScheduleRetryConfig, SCHEDULER_MAX_RETRY_COUNT, SCHEDULER_RETRY_COUNT_REFUSAL,
};
use proptest::prelude::*;

const RECORDED: &str =
    "invalid retry count. The retry_count must be a positive integer less than 5: invalid argument";

fn with_count(retry_count: u32) -> ScheduleRetryConfig {
    ScheduleRetryConfig {
        retry_count,
        ..ScheduleRetryConfig::default()
    }
}

#[test]
fn the_message_is_the_recorded_text_byte_for_byte() {
    assert_eq!(SCHEDULER_RETRY_COUNT_REFUSAL, RECORDED);
    assert_eq!(SCHEDULER_MAX_RETRY_COUNT, 4);
}

#[test]
fn counts_up_to_four_are_accepted_and_five_or_more_are_refused() {
    for count in 0..=4 {
        assert_eq!(with_count(count).scheduler_refusal(), None, "{count}");
    }
    for count in [5, 6, 7, 100, u32::MAX] {
        assert_eq!(
            with_count(count).scheduler_refusal(),
            Some(RECORDED),
            "{count}"
        );
    }
}

#[test]
fn the_recorded_declaration_is_refused_and_the_default_is_not() {
    let recorded = ScheduleRetryConfig {
        retry_count: 6,
        max_retry_seconds: 0,
        max_backoff_seconds: 50,
        max_doublings: 2,
        min_backoff_seconds: 4,
    };
    assert_eq!(recorded.scheduler_refusal(), Some(RECORDED));
    assert_eq!(ScheduleRetryConfig::default().scheduler_refusal(), None);
}

proptest! {
    /// Only the count decides; every other field is irrelevant to this refusal.
    #[test]
    fn refusal_iff_the_count_exceeds_four(
        retry_count in any::<u32>(),
        max_retry_seconds in any::<u64>(),
        max_backoff_seconds in any::<u64>(),
        max_doublings in any::<u32>(),
        min_backoff_seconds in any::<u64>(),
    ) {
        let config = ScheduleRetryConfig {
            retry_count,
            max_retry_seconds,
            max_backoff_seconds,
            max_doublings,
            min_backoff_seconds,
        };
        prop_assert_eq!(
            config.scheduler_refusal().is_some(),
            retry_count > SCHEDULER_MAX_RETRY_COUNT
        );
        if let Some(why) = config.scheduler_refusal() {
            prop_assert_eq!(why, RECORDED);
        }
    }
}
