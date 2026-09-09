//! `fireemu --version` against the built binary.
//!
//! Tooling that records which build it measured (the paired benchmark harness in
//! `tools/bench/`, packaging scripts) asks the binary for its version the way every other
//! CLI answers: `--version` on stdout, exit 0, nothing else.

use std::process::{Command, Stdio};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("fireemu runs")
}

#[test]
fn version_flag_prints_the_crate_version_and_exits_zero() {
    for flag in ["--version", "-V", "version"] {
        let output = run(&[flag]);
        assert!(output.status.success(), "{flag}: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.trim(),
            format!("fireemu {}", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
        assert!(output.stderr.is_empty(), "{flag}: stderr must stay empty");
    }
}

#[test]
fn version_flag_rejects_extra_arguments_as_usage_errors() {
    let output = run(&["--version", "extra"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
