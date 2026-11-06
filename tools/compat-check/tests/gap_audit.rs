//! Regression checks for the source-audited compatibility descriptions. These check the
//! contract and its behavioral evidence links, not execution of the linked runtime tests.

use serde_json::Value;

fn surface(id: &str) -> Value {
    let contract: Value =
        serde_json::from_str(include_str!("../../../spec/compatibility/contract.json")).unwrap();
    contract["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|surface| surface["id"] == id)
        .unwrap()
        .clone()
}

fn gaps(surface: &Value) -> String {
    surface["gaps"].to_string()
}

fn has_test(surface: &Value, name: &str) -> bool {
    surface["claims"].as_array().unwrap().iter().any(|claim| {
        claim["evidence"]["tests"]
            .as_array()
            .is_some_and(|tests| tests.iter().any(|test| test == name))
    })
}

#[test]
fn node_reload_has_behavioral_evidence_and_keeps_the_python_boundary() {
    let functions = surface("functions");
    assert!(
        has_test(
            &functions,
            "http_callable_stream_and_task_requests_finish_across_two_reloads"
        ),
        "implemented Node reload must cite the in-flight invocation regression"
    );
    assert!(!gaps(&functions).contains("hot reload of a codebase's source"));
    assert!(gaps(&functions).contains("Python source changes are not reloaded"));
}

#[test]
fn python_execution_is_supported_without_claiming_dart_support() {
    let functions = surface("functions");
    assert!(has_test(
        &functions,
        "a_python_codebase_serves_http_callables_and_event_triggers_in_both_profiles"
    ));
    assert!(!gaps(&functions).contains("Python and Dart codebases"));
    assert!(gaps(&functions).contains("Dart codebases"));
    assert!(gaps(&functions).contains("real time"));
    assert!(functions["claims"].as_array().unwrap().iter().all(|claim| {
        !claim
            .to_string()
            .contains("declared runtime is not nodejs*")
    }));
}

#[test]
fn hub_export_cites_success_and_preserves_the_control_token_requirement() {
    let hub = surface("hub");
    assert!(has_test(
        &hub,
        "the_export_route_requires_the_control_capability_and_refuses_browser_origins"
    ));
    assert!(!gaps(&hub).contains("answers 501"));
    assert!(hub["claims"].to_string().contains("control token"));
}

#[test]
fn protobuf_gap_distinguishes_ingress_from_python_firestore_adaptation() {
    let functions = surface("functions");
    assert!(gaps(&functions).contains("general protobuf CloudEvents ingress"));
    assert!(gaps(&functions).contains("Python Firestore"));
    assert!(functions["claims"].as_array().unwrap().iter().any(|claim| {
        claim["evidence"]["integration"]
            .as_array()
            .is_some_and(|paths| {
                paths
                    .iter()
                    .any(|path| path == "tools/runner-python/tests/test_firestore_events.py")
            })
    }));
}

#[test]
fn auth_local_token_matrix_does_not_imply_production_observation() {
    let auth = surface("auth");
    assert!(has_test(
        &auth,
        "blocking_identity_exports_have_a_synchronous_runner_endpoint"
    ));
    assert!(!gaps(&auth).contains("per-token-kind matrix against real Node SDK handlers"));
    assert!(gaps(&auth).contains("production expectation remains unobserved"));
}
