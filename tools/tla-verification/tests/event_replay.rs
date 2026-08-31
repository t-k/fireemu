//! Canonical `EventDelivery` traces must agree with the Rust event core after every action.

use tla_verification::event_replay::replay_event_trace;
use tla_verification::event_trace::{parse_event_trace, EventLifecycle};

fn fixture(name: &str) -> tla_verification::event_trace::EventTrace {
    let path = format!(
        "{}/../../verification/tla/traces/EventDelivery/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = std::fs::read_to_string(path).expect("trace fixture");
    parse_event_trace(&json).expect("valid canonical trace")
}

#[test]
fn success_retry_exhaustion_stale_discard_and_cancel_match_the_rust_core() {
    for scenario in ["success", "retry-exhaustion", "stale-discard", "cancel"] {
        let trace = fixture(scenario);
        let report = replay_event_trace(&trace).expect("model and implementation agree");
        assert_eq!(report.scenario, scenario);
        assert_eq!(report.steps_checked, trace.steps.len());
    }
}

#[test]
fn replay_reports_the_exact_step_whose_expected_projection_drifted() {
    let mut trace = fixture("success");
    trace.steps[1].expected.state = EventLifecycle::Pending;
    trace.steps[1].expected.terminal = false;

    let error = replay_event_trace(&trace).unwrap_err();
    assert!(error.contains("success"), "{error}");
    assert!(error.contains("step 1 Start"), "{error}");
    assert!(error.contains("projection mismatch"), "{error}");
}

#[test]
fn replay_does_not_take_the_rust_policy_projection_from_each_expected_step() {
    let mut trace = fixture("success");
    trace.steps[0].expected.max_attempts = 3;

    let error = replay_event_trace(&trace).unwrap_err();
    assert!(error.contains("success step 0 Lease"), "{error}");
    assert!(error.contains("max_attempts: 2"), "{error}");
}

#[test]
fn transition_errors_report_scenario_step_action_expected_and_actual() {
    let mut trace = fixture("success");
    trace.steps[0].operation = tla_verification::event_trace::EventOperation::Start;

    let error = replay_event_trace(&trace).unwrap_err();
    for required in [
        "success",
        "step 0 Start",
        "transition failed",
        "expected EventProjection",
        "found EventProjection",
    ] {
        assert!(error.contains(required), "missing {required:?}: {error}");
    }
}
