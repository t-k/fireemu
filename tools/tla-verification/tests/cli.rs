//! Command-line contract tests for the manual TLA+ verification tool.

use std::process::Command;

fn binary() -> String {
    std::env::var("CARGO_BIN_EXE_tla-verification").expect("binary path from Cargo")
}

#[test]
fn help_lists_the_manual_mutation_and_verification_commands() {
    let output = Command::new(binary()).arg("--help").output().expect("help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help");
    assert!(stdout.contains("mutate"));
    assert!(stdout.contains("verify-evidence"));
    assert!(stdout.contains("verify-triage"));
    assert!(stdout.contains("trace-generate-eventdelivery"));
    assert!(stdout.contains("trace-convert"));
    assert!(stdout.contains("check-eventdelivery"));
}

#[test]
fn eventdelivery_check_replays_a_canonical_fixture() {
    let trace = format!(
        "{}/../../verification/tla/traces/EventDelivery/success.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(binary())
        .args(["check-eventdelivery", "--trace", &trace])
        .output()
        .expect("event trace check");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("success: ok (3 steps)"), "{stdout}");
}

#[test]
fn eventdelivery_check_defaults_to_all_four_repository_fixtures() {
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(binary())
        .args(["check-eventdelivery", "--root", &root])
        .output()
        .expect("all event trace checks");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    for scenario in ["success", "retry-exhaustion", "stale-discard", "cancel"] {
        assert!(stdout.contains(&format!("{scenario}: ok")), "{stdout}");
    }
}

#[test]
fn eventdelivery_check_exits_nonzero_and_names_the_divergent_step() {
    let source = format!(
        "{}/../../verification/tla/traces/EventDelivery/success.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let json = std::fs::read_to_string(source)
        .expect("success fixture")
        .replacen("\"state\": \"Running\"", "\"state\": \"Pending\"", 1);
    let trace = std::env::temp_dir().join(format!(
        "fireemu-event-trace-drift-{}.json",
        std::process::id()
    ));
    std::fs::write(&trace, json).expect("drifted fixture");
    let output = Command::new(binary())
        .args(["check-eventdelivery", "--trace"])
        .arg(&trace)
        .output()
        .expect("divergent event trace check");
    let _ = std::fs::remove_file(trace);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert!(stderr.contains("success step 1 Start"), "{stderr}");
    assert!(stderr.contains("projection mismatch"), "{stderr}");
}

#[test]
fn unknown_commands_fail_with_usage() {
    let output = Command::new(binary())
        .arg("unknown")
        .output()
        .expect("unknown command");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert!(stderr.contains("unknown command"));
    assert!(stderr.contains("Usage:"));
}
