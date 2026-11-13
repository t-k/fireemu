use super::event_frame_member;
use proptest::prelude::*;
use serde_json::{json, Value};

/// What the frame carried before the member was borrowed: a deep copy of the event with
/// `traceparent` assigned, then serialized.
fn copied(event: &Value, traceparent: Option<&Value>) -> String {
    let mut event = event.clone();
    if let Some(traceparent) = traceparent {
        event["traceparent"] = traceparent.clone();
    }
    serde_json::value::to_raw_value(&event)
        .unwrap()
        .get()
        .to_owned()
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        "[a-z\u{e9}\u{1F600}\"\\\\ ]{0,6}".prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            // Keys on both sides of `traceparent`, and that very key.
            prop::collection::btree_map(
                prop_oneof![
                    Just("traceparent".to_owned()),
                    Just("data".to_owned()),
                    Just("zeta".to_owned()),
                    Just("trace".to_owned()),
                    Just("traceparent0".to_owned()),
                    "[a-z]{0,4}".prop_map(String::from),
                ],
                inner,
                0..5
            )
            .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn the_borrowed_member_has_the_bytes_of_the_copied_event(
        event in json_value(),
        traceparent in prop::option::of(
            "[0-9a-f]{32}-[0-9a-f]{16}".prop_map(|ids| Value::String(format!("00-{ids}-01")))
        ),
    ) {
        // The old code panicked on a scalar or array event with a `traceparent`; events
        // are objects (or null), so only those are compared.
        prop_assume!(traceparent.is_none() || event.is_object() || event.is_null());
        let borrowed = event_frame_member(&event, traceparent.as_ref());
        prop_assert_eq!(borrowed.get(), copied(&event, traceparent.as_ref()));
    }
}

#[test]
fn the_strict_profile_backs_off_one_step_earlier_than_the_official_emulator() {
    use fireemu_core_functions::manifest::TaskRetryConfig;
    let retry = TaskRetryConfig {
        max_attempts: 6,
        max_retry_millis: None,
        max_backoff_millis: 6000,
        max_doublings: 2,
        min_backoff_millis: 1000,
    };
    // Attempt 2 is the first retry. Production waited 1, 2, 4, 6 and 6 seconds; the official emulator 2, 4, 6, 6 and 6.
    let strict: Vec<u64> = (2..=6)
        .map(|a| retry.backoff_millis(super::backoff_step(true, a)))
        .collect();
    let official: Vec<u64> = (2..=6)
        .map(|a| retry.backoff_millis(super::backoff_step(false, a)))
        .collect();
    assert_eq!(strict, [1000, 2000, 4000, 6000, 6000]);
    assert_eq!(official, [2000, 4000, 6000, 6000, 6000]);
    let default = TaskRetryConfig {
        min_backoff_millis: 100,
        max_backoff_millis: 3_600_000,
        max_doublings: 16,
        ..retry
    };
    assert_eq!(default.backoff_millis(super::backoff_step(true, 2)), 100);
    assert_eq!(
        default.backoff_millis(super::backoff_step(true, 1)),
        100,
        "never below the first step"
    );
}
