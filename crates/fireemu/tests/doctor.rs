//! `fireemu doctor` against the built binary: what a release actually ships.
//!
//! `doctor` is the one command a user runs after installing, so it is checked the way they run
//! it -- by executing the binary -- rather than by calling the functions behind it. The
//! release layout (`bin/fireemu` beside `bin/runner-node/`) is reproduced here so the
//! packaging contract the npm platform packages depend on is covered by a test, not only by
//! the packaging scripts.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The runner sources shipped in a platform package.
const RUNNER_FILES: [&str; 2] = ["index.mjs", "callable-app-check.mjs"];

fn workspace_runner_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/runner-node")
}

fn doctor() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fireemu"));
    cmd.arg("doctor")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A scratch directory beside the test binary (the same filesystem, so the executable can be
/// hard-linked into it instead of copied).
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_BIN_EXE_fireemu"))
        .parent()
        .expect("the test binary has a directory")
        .join(format!("doctor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    dir
}

/// The daemon installed the way a platform package installs it: the executable with a
/// `runner-node/` directory beside it and nothing else.
fn install_release_layout(name: &str) -> (PathBuf, PathBuf) {
    let dir = scratch(name);
    let exe = dir.join(if cfg!(windows) {
        "fireemu.exe"
    } else {
        "fireemu"
    });
    let built = PathBuf::from(env!("CARGO_BIN_EXE_fireemu"));
    if std::fs::hard_link(&built, &exe).is_err() {
        std::fs::copy(&built, &exe).expect("install the binary");
    }
    let runner = dir.join("runner-node");
    std::fs::create_dir_all(&runner).expect("create runner-node");
    for file in RUNNER_FILES {
        std::fs::copy(workspace_runner_dir().join(file), runner.join(file))
            .unwrap_or_else(|e| panic!("copy {file}: {e}"));
    }
    (dir, exe)
}

/// Every component a release carries is named, and the report succeeds when they are all
/// there. Java is called out explicitly because the Firebase Emulator Suite needs a JVM and
/// the first question about a replacement is whether this one does too.
#[test]
fn doctor_names_the_binary_the_ui_bundle_the_runner_and_the_runtimes() {
    let output = doctor().output().expect("doctor runs");
    let text = stdout(&output);
    for label in [
        "fireemu",
        "target",
        "vendored googleapis commit",
        "limit catalogs",
        "ui bundle",
        "functions runner",
        "firebase-functions support",
        "node",
        "java",
    ] {
        assert!(text.contains(label), "{label} is missing from:\n{text}");
    }
    assert!(
        text.contains(env!("CARGO_PKG_VERSION")),
        "the binary reports its own version:\n{text}"
    );
    assert!(
        text.contains("not required"),
        "doctor states that no JVM is needed:\n{text}"
    );
    assert!(
        text.contains("majors "),
        "the runner's firebase-functions range is reported:\n{text}"
    );
    assert!(
        output.status.success(),
        "a complete build has nothing to report as broken:\n{text}"
    );
}

/// A binary installed the way a platform package installs it finds the runner beside itself,
/// and says so. This is the contract `npm/platforms` relies on: the package ships
/// `bin/fireemu` and `bin/runner-node/`, and nothing reaches back to the build machine.
#[test]
fn an_installed_binary_finds_the_runner_beside_itself() {
    let (dir, exe) = install_release_layout("beside");
    let output = Command::new(&exe)
        .arg("doctor")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the installed binary runs");
    let text = stdout(&output);
    assert!(
        text.contains("bundled beside the binary"),
        "the sibling runner-node directory is used:\n{text}"
    );
    assert!(
        text.contains(&dir.join("runner-node").display().to_string()),
        "the reported path is the installed one, not the workspace one:\n{text}"
    );
    assert!(
        text.contains("majors "),
        "the shipped runner declares the range it instruments:\n{text}"
    );
    assert!(
        output.status.success(),
        "the installed layout is complete:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An installation whose runner is missing is a problem, not a footnote: `doctor` exits
/// non-zero so a script can gate on it, names every place it looked, and says what breaks.
#[test]
fn a_missing_runner_fails_the_report_with_actionable_remediation() {
    let output = doctor()
        .env(
            "FIREEMU_RUNNER_NODE",
            workspace_runner_dir().join("does-not-exist.mjs"),
        )
        .output()
        .expect("doctor runs");
    let text = stdout(&output);
    assert!(
        text.contains("!! functions runner"),
        "the missing runner is marked as broken:\n{text}"
    );
    assert!(
        text.contains("FIREEMU_RUNNER_NODE"),
        "the override that named it is explained:\n{text}"
    );
    assert!(
        text.contains("every other service works"),
        "the report says what still works:\n{text}"
    );
    assert!(
        !output.status.success(),
        "a broken installation exits non-zero:\n{text}"
    );
}

/// The report is safe to paste into an issue: it carries versions, catalog identifiers and
/// paths, and never the environment it was run in.
#[test]
fn the_report_carries_no_secrets_from_the_environment() {
    let output = doctor()
        .env("FIREEMU_CONTROL_TOKEN", "doctor-must-not-print-this")
        .env(
            "GOOGLE_APPLICATION_CREDENTIALS",
            "/secret/service-account.json",
        )
        .output()
        .expect("doctor runs");
    let text = stdout(&output);
    assert!(!text.contains("doctor-must-not-print-this"), "{text}");
    assert!(!text.contains("service-account.json"), "{text}");
}
