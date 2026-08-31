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
