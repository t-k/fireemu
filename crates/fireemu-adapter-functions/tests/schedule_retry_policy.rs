//! The retry policy of a scheduled function (`schedule_retry_policy`), against what production's Cloud Scheduler did in
//! the second delivery recording (run `156715222b86ea44`, 2026-10-05).
//!
//! Recorded attempt offsets from the first attempt, in seconds (each carries about half a second of dispatch latency
//! per attempt that fireemu's logical clock does not have):
//! - `retryCount: 4`, `minBackoff 4s`, `maxBackoff 50s`, `maxDoublings 2`: 0, 4.6, 13.2, 29.7, 48.2 (five attempts; the
//!   gaps are 4, 8, 16 and an unexplained 18).
//! - `retryCount: 5`, defaults (`minBackoff 5s`, `maxDoublings 5`): 0, 5.6, 16.3, 36.8, 77.3, 157.8 (six attempts).
//! - `retryCount: 0`: one attempt.
//! - `maxRetryDuration 30s`, `minBackoff 4s`, `maxBackoff 10s`, no `retryCount`: 0, 4.6, 13.2, 23.7 (four attempts; the
//!   next would have been at about 33.7, past the window).

use fireemu_adapter_functions::runtime::schedule_retry_policy;
use fireemu_core_events::retry::RetryPolicy;
use fireemu_core_functions::manifest::ScheduleRetryConfig;
use fireemu_core_types::time::LogicalDuration;
use proptest::prelude::*;

fn config(
    retry_count: u32,
    max_retry_seconds: u64,
    min_backoff_seconds: u64,
    max_backoff_seconds: u64,
    max_doublings: u32,
) -> ScheduleRetryConfig {
    ScheduleRetryConfig {
        retry_count,
        max_retry_seconds,
        max_backoff_seconds,
        max_doublings,
        min_backoff_seconds,
    }
}

/// The offsets, in whole seconds from the first attempt, at which a handler that always fails is attempted.
fn attempt_offsets(policy: &RetryPolicy) -> Vec<i64> {
    let mut offsets = vec![0];
    let mut elapsed = LogicalDuration::from_seconds(0);
    let mut attempt = 1;
    while policy.allows_retry_after_elapsed(attempt, elapsed) && attempt < 64 {
        elapsed = elapsed
            .checked_add(policy.backoff_for_attempt(attempt))
            .unwrap();
        attempt += 1;
        offsets.push(i64::try_from(elapsed.as_nanos() / 1_000_000_000).unwrap());
    }
    offsets
}

#[test]
fn a_retry_count_alone_makes_that_many_retries_with_the_recorded_first_gaps() {
    let policy = schedule_retry_policy(&config(4, 0, 4, 50, 2));
    assert_eq!(policy.max_attempts(), 5);
    let offsets = attempt_offsets(&policy);
    assert_eq!(offsets.len(), 5, "{offsets:?}");
    // The first three gaps are the recorded 4, 8 and 16 seconds; the fourth gap production showed (about 18) is not
    // claimed here.
    assert_eq!(&offsets[..4], &[0, 4, 12, 28]);
}

#[test]
fn the_default_backoff_doubles_five_times_and_makes_six_attempts_for_a_count_of_five() {
    let policy = schedule_retry_policy(&config(5, 0, 5, 3_600, 5));
    assert_eq!(attempt_offsets(&policy), vec![0, 5, 15, 35, 75, 155]);
}

#[test]
fn a_count_of_zero_is_one_attempt() {
    let policy = schedule_retry_policy(&config(0, 0, 5, 3_600, 5));
    assert_eq!(policy.max_attempts(), 1);
    assert_eq!(attempt_offsets(&policy), vec![0]);
}

#[test]
fn a_retry_window_with_no_count_retries_until_the_window_ends() {
    let policy = schedule_retry_policy(&config(0, 30, 4, 10, 5));
    // 4, 8, then 10 (the cap): 0, 4, 12, 22; the next would be at 32, past the 30 s window.
    assert_eq!(attempt_offsets(&policy), vec![0, 4, 12, 22]);
    assert_eq!(policy.max_attempts(), u32::MAX);
}

#[test]
fn a_count_and_a_window_together_stop_at_whichever_comes_first() {
    // Not recorded (production refused that combination's job); both limits apply.
    let by_count = schedule_retry_policy(&config(2, 600, 4, 50, 5));
    assert_eq!(attempt_offsets(&by_count), vec![0, 4, 12]);
    let by_window = schedule_retry_policy(&config(10, 10, 4, 50, 5));
    assert_eq!(attempt_offsets(&by_window), vec![0, 4]);
}

#[test]
fn a_maximum_backoff_below_the_minimum_is_raised_to_it() {
    let policy = schedule_retry_policy(&config(2, 0, 8, 3, 5));
    assert_eq!(policy.base_backoff(), LogicalDuration::from_seconds(8));
    assert_eq!(policy.max_backoff(), LogicalDuration::from_seconds(8));
}

proptest! {
    /// A positive count means exactly count + 1 attempts with no window, and never more with one.
    #[test]
    fn a_positive_count_bounds_the_attempts(
        count in 1u32..30,
        window in 0u64..10_000,
        min in 1u64..30,
        max in 1u64..400,
        doublings in 0u32..8,
    ) {
        let policy = schedule_retry_policy(&config(count, window, min, max, doublings));
        prop_assert_eq!(policy.max_attempts(), count + 1);
        let attempts = attempt_offsets(&policy).len();
        prop_assert!(attempts <= count as usize + 1);
        if window == 0 {
            prop_assert_eq!(attempts, count as usize + 1);
        }
    }

    /// Without a count, a window is the only bound: the last attempt is inside it and the next would not be.
    #[test]
    fn a_window_alone_ends_the_chain_inside_the_window(
        window in 1u64..300,
        min in 1u64..20,
        max in 20u64..100,
        doublings in 0u32..6,
    ) {
        let policy = schedule_retry_policy(&config(0, window, min, max, doublings));
        let offsets = attempt_offsets(&policy);
        let window = i64::try_from(window).unwrap();
        prop_assert!(*offsets.last().unwrap() <= window);
        prop_assert!(offsets.len() >= 2 || i64::try_from(min).unwrap() > window);
    }

    /// No window and no count is one attempt, whatever the backoff.
    #[test]
    fn neither_count_nor_window_is_one_attempt(min in 0u64..50, max in 0u64..500, doublings in 0u32..10) {
        let policy = schedule_retry_policy(&config(0, 0, min, max, doublings));
        prop_assert_eq!(attempt_offsets(&policy), vec![0]);
    }
}
