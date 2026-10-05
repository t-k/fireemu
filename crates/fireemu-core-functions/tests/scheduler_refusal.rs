//! Cloud Scheduler's refusal of a job whose `retryCount` is 5 or more.
//!
//! Source: the production deploy `e0ec2f416f5ea7e8` (SCHEDULED-FUNCTIONS delivery recording, 2026-10-05) created the
//! job of a function declared with `retryCount: 6`; Cloud Scheduler answered HTTP 400 `INVALID_ARGUMENT` with the
//! message pinned here. Only the count 6 was observed; the boundary at 5 is the message's own statement.

use fireemu_core_functions::cron::Schedule;
use fireemu_core_functions::manifest::{
    ConsumeAppCheckToken, FunctionGeneration, FunctionManifest, FunctionSpec, PlatformOptions,
    ScheduleRetryConfig, Trigger, DEFAULT_REGION, DEFAULT_TIMEOUT_SECONDS,
    SCHEDULER_MAX_RETRY_COUNT, SCHEDULER_RETRY_COUNT_REFUSAL,
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

fn function(name: &str, generation: FunctionGeneration, trigger: Trigger) -> FunctionSpec {
    FunctionSpec {
        name: name.to_owned(),
        region: DEFAULT_REGION.to_owned(),
        entry_point: name.to_owned(),
        trigger,
        timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        retry: false,
        generation,
        concurrency: None,
        platform_options: PlatformOptions::default(),
    }
}

fn http(callable: bool) -> Trigger {
    Trigger::Http {
        callable,
        enforce_app_check: false,
        consume_app_check_token: ConsumeAppCheckToken::Undetermined,
    }
}

fn scheduled(name: &str, generation: FunctionGeneration, retry_count: u32) -> FunctionSpec {
    function(
        name,
        generation,
        Trigger::Schedule {
            schedule: Schedule::parse("every 5 minutes").unwrap(),
            time_zone: None,
            retry: with_count(retry_count),
        },
    )
}

#[test]
fn a_manifest_lists_each_refused_schedule_by_name_in_order_for_both_generations() {
    let manifest = FunctionManifest {
        functions: vec![
            scheduled("accepted", FunctionGeneration::Second, 4),
            scheduled("refusedSecond", FunctionGeneration::Second, 6),
            function("other", FunctionGeneration::First, http(false)),
            scheduled("zero", FunctionGeneration::First, 0),
            scheduled("refusedFirst", FunctionGeneration::First, 5),
        ],
        ignored: vec![],
    };
    assert_eq!(
        manifest.scheduler_refusals(),
        vec![("refusedSecond", RECORDED), ("refusedFirst", RECORDED)]
    );
}

#[test]
fn a_manifest_of_accepted_schedules_and_other_triggers_has_no_refusal() {
    let manifest = FunctionManifest {
        functions: vec![
            scheduled("a", FunctionGeneration::Second, 4),
            scheduled("b", FunctionGeneration::First, 0),
            function("c", FunctionGeneration::Second, http(true)),
        ],
        ignored: vec![],
    };
    assert!(manifest.scheduler_refusals().is_empty());
    assert!(FunctionManifest {
        functions: vec![],
        ignored: vec![]
    }
    .scheduler_refusals()
    .is_empty());
}
