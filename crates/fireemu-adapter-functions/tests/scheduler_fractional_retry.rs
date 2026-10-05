//! Cloud Scheduler's refusal of a job whose `maxRetryDuration` has a fractional second.
//!
//! Source: the second SCHEDULED-FUNCTIONS delivery recording (run `156715222b86ea44`, 2026-10-05). The REST job
//! create with `maxRetryDuration: "20.5s"` (and `minBackoffDuration: "2.5s"`, `maxBackoffDuration: "20s"`,
//! `retryCount: 3`, `maxDoublings: 1`) answered HTTP 400 `INVALID_ARGUMENT` with the message pinned here; the create
//! with `maxRetryDuration: "30s"` answered 200. firebase-tools writes a schedule's `maxRetrySeconds` as
//! `` `${seconds}s` ``, so a fractional `maxRetrySeconds` reaches production in the same shape.

use fireemu_adapter_functions::manifest_json::{
    scheduler_fractional_retry_refusals, SCHEDULER_MAX_RETRY_NANOS_REFUSAL,
};
use proptest::prelude::*;
use serde_json::{json, Value};

const RECORDED: &str = "retryConfig.max_retry_duration.nanos cannot be set: invalid argument";

fn scheduled(name: &str, retry_config: &Value) -> Value {
    json!({"name": name, "trigger": {"type": "schedule", "schedule": "every 5 minutes", "retryConfig": retry_config}})
}

#[test]
fn the_message_is_the_recorded_text_byte_for_byte() {
    assert_eq!(SCHEDULER_MAX_RETRY_NANOS_REFUSAL, RECORDED);
    assert_eq!(RECORDED.len(), 68);
}

#[test]
fn the_recorded_declaration_is_listed_and_the_accepted_one_is_not() {
    let recorded = json!({"functions": [scheduled(
        "count",
        &json!({"retryCount": 3, "maxRetrySeconds": 20.5, "minBackoffSeconds": 2.5, "maxBackoffSeconds": 20, "maxDoublings": 1}),
    )]});
    assert_eq!(
        scheduler_fractional_retry_refusals(&recorded),
        vec![("count".to_owned(), RECORDED)]
    );
    let accepted = json!({"functions": [scheduled(
        "duration",
        &json!({"maxRetrySeconds": 30, "minBackoffSeconds": 4, "maxBackoffSeconds": 10}),
    )]});
    assert!(scheduler_fractional_retry_refusals(&accepted).is_empty());
}

#[test]
fn only_a_scheduled_functions_max_retry_seconds_counts_and_names_keep_manifest_order() {
    let manifest = json!({"functions": [
        scheduled("b", &json!({"maxRetrySeconds": 0.5})),
        {"name": "h", "trigger": {"type": "http", "retryConfig": {"maxRetrySeconds": 0.5}}},
        scheduled("whole", &json!({"maxRetrySeconds": 30.0})),
        scheduled("backoffs", &json!({"minBackoffSeconds": 2.5, "maxBackoffSeconds": 20.5})),
        scheduled("a", &json!({"maxRetrySeconds": 1.25})),
        scheduled("string", &json!({"maxRetrySeconds": "20.5"})),
        scheduled("none", &json!({})),
        {"name": "no-retry-config", "trigger": {"type": "schedule", "schedule": "every 1 minutes"}},
    ]});
    assert_eq!(
        scheduler_fractional_retry_refusals(&manifest),
        vec![("b".to_owned(), RECORDED), ("a".to_owned(), RECORDED)]
    );
    assert!(scheduler_fractional_retry_refusals(&json!({})).is_empty());
    assert!(scheduler_fractional_retry_refusals(&json!({"functions": "x"})).is_empty());
}

proptest! {
    /// A finite value is listed iff it has a fractional part, whatever the other retry fields hold.
    #[test]
    fn listed_iff_the_value_has_a_fractional_part(
        seconds in -1.0e6f64..1.0e6,
        other in 0u32..50,
    ) {
        let manifest = json!({"functions": [scheduled(
            "job",
            &json!({"maxRetrySeconds": seconds, "retryCount": other, "maxDoublings": other}),
        )]});
        let listed = !scheduler_fractional_retry_refusals(&manifest).is_empty();
        prop_assert_eq!(listed, seconds.fract() != 0.0);
    }

    /// An integer is never listed, however it is written.
    #[test]
    fn whole_seconds_are_never_listed(seconds in 0u32..1_000_000, as_float in any::<bool>()) {
        let value = if as_float { json!(f64::from(seconds)) } else { json!(seconds) };
        let manifest = json!({"functions": [scheduled("job", &json!({"maxRetrySeconds": value}))]});
        prop_assert!(scheduler_fractional_retry_refusals(&manifest).is_empty());
    }
}
