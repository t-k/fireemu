//! Strict canonical `EventDelivery` trace schema.

use tla_verification::event_trace::{parse_event_trace, EventOperation};

fn valid_trace() -> &'static str {
    r#"{
      "schemaVersion": 1,
      "scenario": "success",
      "initial": {"state":"Pending","attempts":0,"maxAttempts":2,"capturedEpoch":0,"currentEpoch":0,"terminal":false,"cancelled":false,"stale":false},
      "steps": [{
        "operation": "Lease",
        "target": "e1",
        "expected": {"state":"Leased","attempts":0,"maxAttempts":2,"capturedEpoch":0,"currentEpoch":0,"terminal":false,"cancelled":false,"stale":false}
      }]
    }"#
}

#[test]
fn strict_event_trace_accepts_only_the_supported_projection() {
    let trace = parse_event_trace(valid_trace()).expect("valid trace");
    assert_eq!(trace.steps[0].operation, EventOperation::Lease);

    let unknown = valid_trace().replace(
        "\"scenario\": \"success\",",
        "\"scenario\": \"success\", \"surprise\": true,",
    );
    assert!(parse_event_trace(&unknown).is_err());

    let interrupt = valid_trace().replace("\"Lease\"", "\"Interrupt\"");
    assert!(parse_event_trace(&interrupt).is_err());

    let missing_target = valid_trace().replace("        \"target\": \"e1\",\n", "");
    assert!(parse_event_trace(&missing_target)
        .unwrap_err()
        .contains("requires target"));
}
