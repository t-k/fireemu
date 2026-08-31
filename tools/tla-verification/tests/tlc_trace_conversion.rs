//! Conversion from TLC's structured JSON trace to the canonical event schema.

use tla_verification::event_trace::{convert_eventdelivery_tlc_trace, EventOperation};

fn raw_fixture(scenario: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/EventDelivery/{scenario}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path).expect("raw TLC fixture")
}

fn raw_success() -> &'static str {
    r#"{
      "counterexample": {
        "action": [],
        "state": [
          [1, {"state":{"e1":"Pending"},"attempts":{"e1":0},"eventEpoch":{"e1":0},"epoch":0,"previousState":{"e1":"Pending"},"previousAttempts":{"e1":0},"previousEventEpoch":{"e1":0},"previousEpoch":0,"lastAction":"Init","lastTarget":[]}],
          [2, {"state":{"e1":"Leased"},"attempts":{"e1":0},"eventEpoch":{"e1":0},"epoch":0,"previousState":{"e1":"Pending"},"previousAttempts":{"e1":0},"previousEventEpoch":{"e1":0},"previousEpoch":0,"lastAction":"Lease","lastTarget":["e1"]}],
          [3, {"state":{"e1":"Running"},"attempts":{"e1":1},"eventEpoch":{"e1":0},"epoch":0,"previousState":{"e1":"Leased"},"previousAttempts":{"e1":0},"previousEventEpoch":{"e1":0},"previousEpoch":0,"lastAction":"Start","lastTarget":["e1"]}],
          [4, {"state":{"e1":"Succeeded"},"attempts":{"e1":1},"eventEpoch":{"e1":0},"epoch":0,"previousState":{"e1":"Running"},"previousAttempts":{"e1":1},"previousEventEpoch":{"e1":0},"previousEpoch":0,"lastAction":"Succeed","lastTarget":["e1"]}]
        ]
      },
      "vars": ["state","attempts","eventEpoch","epoch","previousState","previousAttempts","previousEventEpoch","previousEpoch","lastAction","lastTarget"]
    }"#
}

#[test]
fn structured_tlc_states_convert_to_canonical_operations_and_projections() {
    let trace = convert_eventdelivery_tlc_trace(raw_success(), "success", 2).expect("convert");

    assert_eq!(trace.steps.len(), 3);
    assert_eq!(trace.steps[0].operation, EventOperation::Lease);
    assert_eq!(trace.steps[2].operation, EventOperation::Succeed);
    assert!(trace.steps[2].expected.terminal);
}

#[test]
fn all_four_real_tlc_dumps_convert_to_the_expected_action_sequences() {
    let cases: [(&str, &[EventOperation]); 4] = [
        (
            "success",
            &[
                EventOperation::Lease,
                EventOperation::Start,
                EventOperation::Succeed,
            ],
        ),
        (
            "retry-exhaustion",
            &[
                EventOperation::Lease,
                EventOperation::Start,
                EventOperation::Fail,
                EventOperation::RetryDue,
                EventOperation::Lease,
                EventOperation::Start,
                EventOperation::Fail,
            ],
        ),
        (
            "stale-discard",
            &[EventOperation::Reset, EventOperation::DiscardStale],
        ),
        ("cancel", &[EventOperation::Lease, EventOperation::Cancel]),
    ];
    for (scenario, expected) in cases {
        let trace = convert_eventdelivery_tlc_trace(&raw_fixture(scenario), scenario, 2)
            .expect("real TLC dump converts");
        let actual = trace
            .steps
            .iter()
            .map(|step| step.operation)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{scenario}");
    }
}

#[test]
fn conversion_rejects_missing_actions_unsupported_actions_and_inconsistent_states() {
    let missing = raw_success().replace("\"lastAction\":\"Lease\",", "");
    assert!(convert_eventdelivery_tlc_trace(&missing, "missing", 2).is_err());

    let unsupported =
        raw_success().replace("\"lastAction\":\"Lease\"", "\"lastAction\":\"Interrupt\"");
    assert!(convert_eventdelivery_tlc_trace(&unsupported, "unsupported", 2).is_err());

    let inconsistent = raw_success().replace(
        "\"state\":{\"e1\":\"Leased\"},\"attempts\":{\"e1\":0}",
        "\"state\":{\"e1\":\"Running\"},\"attempts\":{\"e1\":0}",
    );
    assert!(
        convert_eventdelivery_tlc_trace(&inconsistent, "inconsistent", 2)
            .unwrap_err()
            .contains("does not match operation")
    );

    assert!(convert_eventdelivery_tlc_trace(raw_success(), "cancel", 2)
        .unwrap_err()
        .contains("did not reach"));

    let malformed_init = raw_success().replacen(
        "\"state\":{\"e1\":\"Pending\"}",
        "\"state\":{\"e1\":\"Leased\"}",
        1,
    );
    assert!(
        convert_eventdelivery_tlc_trace(&malformed_init, "success", 2)
            .unwrap_err()
            .contains("Init state")
    );
}
