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
//!   next would have been at about 33.7, past the window). That job targeted HTTP (second generation). A first-generation
//!   schedule's job targets Pub/Sub, so Cloud Scheduler's retry covers the publish and not the handler: no handler retry
//!   was recorded for it, and a window alone is one attempt there.

use fireemu_adapter_functions::runtime::schedule_retry_policy;
use fireemu_core_events::retry::RetryPolicy;
use fireemu_core_functions::manifest::{FunctionGeneration, ScheduleRetryConfig};
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
    let policy = schedule_retry_policy(&config(4, 0, 4, 50, 2), FunctionGeneration::Second);
    assert_eq!(policy.max_attempts(), 5);
    let offsets = attempt_offsets(&policy);
    assert_eq!(offsets.len(), 5, "{offsets:?}");
    // 4, 8, 16, then 18: the recorded gaps (the fourth, 18, is the first step after the two doublings: 2 s more)
    assert_eq!(offsets, vec![0, 4, 12, 28, 46]);
}

/// Run `ecef353d18975246`, the REST jobs `double1` (min 4 s, one doubling), `double3` (min 2 s, three) and `double0` (min
/// 3 s, asked for no doublings): attempt offsets, latency taken off.
#[test]
fn the_recorded_double_chains() {
    let double1 = schedule_retry_policy(&config(5, 0, 4, 100, 1), FunctionGeneration::Second);
    assert_eq!(attempt_offsets(&double1), vec![0, 4, 12, 22, 34, 48]);
    let double3 = schedule_retry_policy(&config(5, 0, 2, 100, 3), FunctionGeneration::Second);
    assert_eq!(attempt_offsets(&double3), vec![0, 2, 6, 14, 30, 48]);
    // A doubling count of 0 is stored by Cloud Scheduler as the default 5 (the create answer of `double0` read
    // `maxDoublings 5`): the chain doubles every time.
    let double0 = schedule_retry_policy(&config(5, 0, 3, 100, 0), FunctionGeneration::Second);
    assert_eq!(attempt_offsets(&double0), vec![0, 3, 9, 21, 45, 93]);
    let five = schedule_retry_policy(&config(5, 0, 3, 100, 5), FunctionGeneration::Second);
    assert_eq!(attempt_offsets(&five), attempt_offsets(&double0));
}

#[test]
fn the_default_backoff_doubles_five_times_and_makes_six_attempts_for_a_count_of_five() {
    let policy = schedule_retry_policy(&config(5, 0, 5, 3_600, 5), FunctionGeneration::Second);
    assert_eq!(attempt_offsets(&policy), vec![0, 5, 15, 35, 75, 155]);
}

#[test]
fn a_count_of_zero_is_one_attempt() {
    let policy = schedule_retry_policy(&config(0, 0, 5, 3_600, 5), FunctionGeneration::Second);
    assert_eq!(policy.max_attempts(), 1);
    assert_eq!(attempt_offsets(&policy), vec![0]);
}

#[test]
fn a_retry_window_with_no_count_retries_until_the_window_ends() {
    let policy = schedule_retry_policy(&config(0, 30, 4, 10, 5), FunctionGeneration::Second);
    // 4, 8, then 10 (the cap): 0, 4, 12, 22; the next would be at 32, past the 30 s window.
    assert_eq!(attempt_offsets(&policy), vec![0, 4, 12, 22]);
    // no count: the window alone decides, and the count is one attempt
    assert_eq!(policy.max_attempts(), 1);
}

/// Run `f123d4fa2d61c5f5`, the REST job `count`: `retryCount 3`, `maxRetryDuration 20s`, `minBackoff 4s`, `maxBackoff 10s`.
/// Production attempted it four times in both passes, at 0, 4.65, 13.26, 23.88 s and 0, 4.5, 13.02, 23.68 s, so the window
/// of 20 s did not stop the fourth attempt: the retries went on until the count and the window were both used up (Cloud
/// Scheduler's documentation says the same: with both set "the job will be retried until both limits are reached"). The
/// same run's control, the window alone (30 s, same backoff), made four attempts too.
#[test]
fn a_count_and_a_window_retry_until_both_are_used_up_as_recorded() {
    let count = schedule_retry_policy(&config(3, 20, 4, 10, 5), FunctionGeneration::Second);
    // 4, 8, then 10 (the cap): the fourth attempt, at 22, is past the window and uses the count up
    assert_eq!(attempt_offsets(&count), vec![0, 4, 12, 22]);
    let control = schedule_retry_policy(&config(0, 30, 4, 10, 5), FunctionGeneration::Second);
    assert_eq!(attempt_offsets(&control), vec![0, 4, 12, 22]);
}

/// Not recorded, and read from the same documentation: a count that is used up inside the window does not end the
/// chain while the next attempt still fits the window, and a window that is used up does not end it while the count has
/// retries left. A count of 1 with a window of 30 s: the second attempt uses the count up, the later ones fit the window.
#[test]
fn each_limit_alone_keeps_the_chain_going_until_the_other_is_used_up() {
    let count_runs_out_inside_the_window =
        schedule_retry_policy(&config(1, 30, 4, 10, 5), FunctionGeneration::Second);
    assert_eq!(
        attempt_offsets(&count_runs_out_inside_the_window),
        vec![0, 4, 12, 22]
    );
    // the window is used up after the first retry, the count still has one: the third attempt is made, a fourth is not
    let window_runs_out_first =
        schedule_retry_policy(&config(2, 5, 4, 50, 5), FunctionGeneration::Second);
    assert_eq!(attempt_offsets(&window_runs_out_first), vec![0, 4, 12]);
}

/// Run `f123d4fa2d61c5f5`, the REST job `zerobackoff`: `minBackoff 0s`, `maxBackoff 0s`, window 10 s. Cloud Scheduler stored
/// `minBackoffDuration 5s` and `maxBackoffDuration 3600s` and the chain was two attempts, 5.62 s apart, in both passes: a
/// zero minimum and maximum together are the defaults (only that pair was recorded).
#[test]
fn a_zero_minimum_and_maximum_backoff_together_are_the_defaults() {
    let policy = schedule_retry_policy(&config(0, 10, 0, 0, 5), FunctionGeneration::Second);
    assert_eq!(policy.base_backoff(), LogicalDuration::from_seconds(5));
    assert_eq!(policy.max_backoff(), LogicalDuration::from_seconds(3_600));
    assert_eq!(attempt_offsets(&policy), vec![0, 5]);
    // one of the two alone is not the recorded pair: it is kept as declared
    let only_min = schedule_retry_policy(&config(2, 0, 0, 100, 5), FunctionGeneration::Second);
    assert_eq!(only_min.base_backoff(), LogicalDuration::from_seconds(0));
    assert_eq!(only_min.max_backoff(), LogicalDuration::from_seconds(100));
    let only_max = schedule_retry_policy(&config(2, 0, 3, 0, 5), FunctionGeneration::Second);
    assert_eq!(only_max.base_backoff(), LogicalDuration::from_seconds(3));
    assert_eq!(only_max.max_backoff(), LogicalDuration::from_seconds(3));
}

#[test]
fn a_maximum_backoff_below_the_minimum_is_raised_to_it() {
    let policy = schedule_retry_policy(&config(2, 0, 8, 3, 5), FunctionGeneration::Second);
    assert_eq!(policy.base_backoff(), LogicalDuration::from_seconds(8));
    assert_eq!(policy.max_backoff(), LogicalDuration::from_seconds(8));
}

proptest! {
    /// A positive count means exactly count + 1 attempts with no window, and at least that many with one (the window
    /// keeps the chain going after the count is used up while the next attempt fits it).
    #[test]
    fn a_positive_count_bounds_the_attempts(
        count in 1u32..30,
        window in 0u64..10_000,
        min in 1u64..30,
        max in 1u64..400,
        doublings in 0u32..8,
    ) {
        let policy = schedule_retry_policy(&config(count, window, min, max, doublings), FunctionGeneration::Second);
        prop_assert_eq!(policy.max_attempts(), count + 1);
        let attempts = attempt_offsets(&policy).len();
        prop_assert!(attempts > count as usize);
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
        let policy = schedule_retry_policy(&config(0, window, min, max, doublings), FunctionGeneration::Second);
        let offsets = attempt_offsets(&policy);
        let window = i64::try_from(window).unwrap();
        prop_assert!(*offsets.last().unwrap() <= window);
        prop_assert!(offsets.len() >= 2 || i64::try_from(min).unwrap() > window);
    }

    /// No window and no count is one attempt, whatever the backoff.
    #[test]
    fn neither_count_nor_window_is_one_attempt(min in 0u64..50, max in 0u64..500, doublings in 0u32..10) {
        let policy = schedule_retry_policy(&config(0, 0, min, max, doublings), FunctionGeneration::Second);
        prop_assert_eq!(attempt_offsets(&policy), vec![0]);
    }
}

/// The chain a handler that always fails makes, written out from the rule rather than from the policy: after attempt `k`
/// (1-based) there is a next one when the count has retries left (`k <= count`) or the window is set and the next attempt
/// fits it (`elapsed + gap <= window`); the gap after attempt `k` doubles `min` for `doublings` steps (a count of 0 is
/// 5), then grows by 2 s per step, never above `max`.
fn reference_offsets(count: u32, window: u64, min: u64, max: u64, doublings: u32) -> Vec<i64> {
    let (min, max) = if min == 0 && max == 0 {
        (5, 3_600)
    } else {
        (min, max.max(min))
    };
    // a doubling count of 0 is stored as 5; after the doublings the gap grows by 2 s a step
    let doublings = if doublings == 0 { 5 } else { doublings };
    let gap = |k: u32| -> u64 {
        let steps = k - 1;
        let doubled = steps.min(doublings);
        let linear = u64::from(steps - doubled);
        min.saturating_mul(1u64 << doubled.min(40))
            .saturating_add(2 * linear)
            .min(max)
    };
    let mut offsets = vec![0u64];
    let mut elapsed = 0u64;
    let mut k = 1u32;
    while k < 64 {
        let next = elapsed + gap(k);
        let by_count = k <= count;
        let by_window = window > 0 && next <= window;
        if !(by_count || by_window) {
            break;
        }
        elapsed = next;
        k += 1;
        offsets.push(elapsed);
    }
    offsets
        .into_iter()
        .map(|o| i64::try_from(o).unwrap())
        .collect()
}

proptest! {
    /// The policy makes exactly the chain the rule describes, for any count, window, backoff and doubling count.
    #[test]
    fn the_second_generation_chain_follows_the_rule(
        count in 0u32..12,
        window in 0u64..400,
        min in 0u64..30,
        max in 0u64..300,
        doublings in 0u32..8,
    ) {
        let policy = schedule_retry_policy(&config(count, window, min, max, doublings), FunctionGeneration::Second);
        prop_assert_eq!(
            attempt_offsets(&policy),
            reference_offsets(count, window, min, max, doublings)
        );
    }
}

#[test]
fn a_first_generation_window_alone_is_one_attempt() {
    // The job of a first-generation schedule targets Pub/Sub: its retry governs the publish, not the handler.
    let policy = schedule_retry_policy(&config(0, 30, 4, 10, 5), FunctionGeneration::First);
    assert_eq!(policy.max_attempts(), 1);
    assert_eq!(attempt_offsets(&policy), vec![0]);
}

#[test]
fn a_first_generation_count_is_one_attempt_too() {
    // Recorded (run `156715222b86ea44`): schedFailV1's handler threw at every occurrence and ran once per occurrence,
    // and every Scheduler attempt of its job finished without an error: the job's retry covers the publish, never the
    // handler, whatever the declared count.
    for count in [1, 4, 5] {
        let policy = schedule_retry_policy(&config(count, 0, 4, 50, 2), FunctionGeneration::First);
        assert_eq!(policy.max_attempts(), 1, "count {count}");
        assert_eq!(attempt_offsets(&policy), vec![0], "count {count}");
    }
    // the second generation keeps its count
    let second = schedule_retry_policy(&config(4, 0, 4, 50, 2), FunctionGeneration::Second);
    assert_eq!(second.max_attempts(), 5);
}

proptest! {
    /// Whatever the count, window and backoff, a first-generation schedule is one attempt.
    #[test]
    fn a_first_generation_schedule_is_one_attempt(
        count in 0u32..30,
        window in 0u64..10_000,
        min in 0u64..50,
        max in 0u64..500,
        doublings in 0u32..10,
    ) {
        let policy = schedule_retry_policy(&config(count, window, min, max, doublings), FunctionGeneration::First);
        prop_assert_eq!(attempt_offsets(&policy), vec![0]);
    }
}
