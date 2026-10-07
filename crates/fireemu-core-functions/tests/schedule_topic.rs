//! The Pub/Sub topic of a first-generation schedule.
//!
//! Source: the production deploys `156715222b86ea44` and `f123d4fa2d61c5f5` (SCHEDULED-FUNCTIONS delivery recordings,
//! 2026-10-05, us-central1). The Firebase CLI gives a first-generation `pubsub.schedule` function a Cloud Scheduler job
//! `firebase-schedule-<name>-<region>` whose target is a Pub/Sub topic of the same id; a second-generation `onSchedule`
//! function has a job that calls its HTTP URL and no topic. Every message pulled from such a topic carried the attribute
//! `scheduled: "true"` and no data.

use fireemu_core_functions::cron::Schedule;
use fireemu_core_functions::manifest::{
    ConsumeAppCheckToken, FunctionGeneration, FunctionSpec, PlatformOptions, ScheduleRetryConfig,
    Trigger, DEFAULT_TIMEOUT_SECONDS,
};
use proptest::prelude::*;

fn spec(
    name: &str,
    region: &str,
    generation: FunctionGeneration,
    trigger: Trigger,
) -> FunctionSpec {
    FunctionSpec {
        name: name.to_owned(),
        region: region.to_owned(),
        entry_point: name.to_owned(),
        trigger,
        timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        retry: false,
        generation,
        concurrency: None,
        platform_options: PlatformOptions::default(),
    }
}

fn schedule() -> Trigger {
    Trigger::Schedule {
        schedule: Schedule::parse("every 5 minutes").unwrap(),
        time_zone: None,
        retry: ScheduleRetryConfig::default(),
    }
}

#[test]
fn a_first_generation_schedule_has_the_topic_of_its_job() {
    let function = spec(
        "schedRetryV1",
        "us-central1",
        FunctionGeneration::First,
        schedule(),
    );
    assert_eq!(
        function.schedule_topic().as_deref(),
        Some("firebase-schedule-schedRetryV1-us-central1")
    );
}

#[test]
fn a_second_generation_schedule_has_no_topic() {
    let function = spec(
        "schedRetryV2",
        "us-central1",
        FunctionGeneration::Second,
        schedule(),
    );
    assert_eq!(function.schedule_topic(), None);
}

#[test]
fn a_function_that_is_not_scheduled_has_no_schedule_topic() {
    let http = Trigger::Http {
        callable: false,
        enforce_app_check: false,
        consume_app_check_token: ConsumeAppCheckToken::Undetermined,
    };
    for generation in [FunctionGeneration::First, FunctionGeneration::Second] {
        assert_eq!(
            spec("web", "us-central1", generation, http.clone()).schedule_topic(),
            None
        );
    }
}

proptest! {
    /// The topic id is exactly the job id the CLI names, `firebase-schedule-<name>-<region>`, for any name and region.
    #[test]
    fn the_topic_id_is_the_job_id(name in "[a-zA-Z][a-zA-Z0-9]{0,20}", region in "[a-z]{2,10}-[a-z]{2,10}[0-9]") {
        let function = spec(&name, &region, FunctionGeneration::First, schedule());
        prop_assert_eq!(
            function.schedule_topic(),
            Some(format!("firebase-schedule-{name}-{region}"))
        );
    }
}
