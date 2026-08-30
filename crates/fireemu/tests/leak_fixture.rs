//! Leak-detection gates for tests that start processes (TEST-LEAK-02, TEST-LEAK-04,
//! TEST-LEAK-06).
//!
//! Two things can survive a test that spawns processes, and only one of them is visible to
//! nextest:
//!
//! - a child that still holds the test's captured stdout or stderr. Nextest waits
//!   `leak-timeout` for those handles to close and, with `result = "fail"`, fails the run.
//!   `nested_run_fails_when_a_child_keeps_captured_stdout` proves that the configured policy
//!   actually fails, by running an intentional-leak fixture through a nested nextest.
//! - a child that closed or redirected them. Nextest never sees it;
//!   `the_census_sees_a_child_that_redirected_its_output` proves that the process census does.
//!
//! Both fixtures are `#[ignore]`d so that a normal workspace run never leaks on purpose; the
//! nested driver selects them explicitly. Every nested run gets its own process group, and the
//! group is terminated and reaped before the outer test returns, on the assertion-failure path
//! as well.

mod census;

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// How long a fixture child stays alive. Longer than any nested run, so that the leak is
/// deterministic rather than a race with the runner.
const FIXTURE_CHILD_SECONDS: u32 = 120;

/// Environment variable naming the file a fixture writes its child PID to.
const PIDFILE_VAR: &str = "FIREEMU_LEAK_FIXTURE_PIDFILE";

// --- the intentional-leak fixtures ------------------------------------------------------

/// TEST-LEAK-02: a child that keeps the test's captured stdout open. Nextest must report this
/// as leaky and, under the `pr` / `ci` / `leak-fixture` policy, fail the run.
#[test]
#[ignore = "intentional leak; run through the nested nextest driver"]
// Never waiting for the child is the whole point of the fixture; the nested driver reaps it.
#[allow(clippy::zombie_processes)]
fn fixture_child_keeps_captured_stdout() {
    let child = Command::new("sh")
        .arg("-c")
        .arg(format!("exec sleep {FIXTURE_CHILD_SECONDS}"))
        .stdin(Stdio::null())
        // Inheriting means holding the pipe nextest captured this test's output with.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the fixture child must start");
    record_child(child.id());
    // Deliberately never waited for: that is the condition under test.
}

/// TEST-LEAK-04: a child that survives with its output redirected. Nextest's inherited-handle
/// signal cannot see it; the process census must.
#[test]
#[ignore = "intentional leak; run through the nested nextest driver"]
#[allow(clippy::zombie_processes)]
fn fixture_child_redirects_output() {
    let child = Command::new("sh")
        .arg("-c")
        .arg(format!("exec sleep {FIXTURE_CHILD_SECONDS}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the fixture child must start");
    record_child(child.id());
}

fn record_child(pid: u32) {
    if let Ok(path) = std::env::var(PIDFILE_VAR) {
        std::fs::write(path, pid.to_string()).expect("the fixture must record its child PID");
    }
}

// --- the nested driver ------------------------------------------------------------------

/// A nested nextest run in its own process group. Dropping it terminates and reaps the whole
/// group, whatever happened to the assertions.
struct NestedRun {
    pgid: i32,
    pidfile: PathBuf,
    output: Output,
    cleaned: bool,
}

impl NestedRun {
    /// Runs one `#[ignore]`d fixture test through its own `cargo nextest` process.
    fn start(test_name: &str) -> Option<Self> {
        if !nextest_available() {
            return None;
        }
        let pidfile = std::env::temp_dir().join(format!(
            "fireemu-leak-{test_name}-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&pidfile);
        let mut command = Command::new(env!("CARGO"));
        command
            .current_dir(workspace_root())
            .args([
                "nextest",
                "run",
                "--profile",
                "leak-fixture",
                "-p",
                "fireemu",
                "--test",
                "leak_fixture",
                "--run-ignored",
                "all",
                "-E",
                &format!("test(={test_name})"),
            ])
            .env(PIDFILE_VAR, &pidfile)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own group: the fixture children inherit it, so cleanup is one signal.
            .process_group(0);
        for inherited in [
            "NEXTEST",
            "NEXTEST_PROFILE",
            "NEXTEST_RUN_ID",
            "NEXTEST_EXECUTION_MODE",
            "NEXTEST_TEST_GROUP",
        ] {
            command.env_remove(inherited);
        }
        let child = command.spawn().expect("the nested nextest run must start");
        let pgid = i32::try_from(child.id()).expect("pid fits in i32");
        let output = child
            .wait_with_output()
            .expect("the nested nextest run must finish");
        Some(Self {
            pgid,
            pidfile,
            output,
            cleaned: false,
        })
    }

    fn combined_output(&self) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&self.output.stdout),
            String::from_utf8_lossy(&self.output.stderr)
        )
    }

    /// The PID the fixture recorded, if it got that far.
    fn fixture_child(&self) -> Option<i32> {
        std::fs::read_to_string(&self.pidfile)
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// Terminates and reaps the nested run. Idempotent; also runs from `Drop`.
    ///
    /// Two groups matter: the one this driver created for `cargo nextest` itself, and the one
    /// nextest put the fixture's test process (and therefore its children) into. Never the
    /// group of the test doing the cleaning.
    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        census::kill_process_group(self.pgid);
        if let Some(pid) = self.fixture_child() {
            let own = census::own_process_group();
            if let Some(entry) = census::find(pid) {
                if Some(entry.pgid) != own {
                    census::kill_process_group(entry.pgid);
                }
            }
            census::kill_pid(pid);
        }
        let _ = std::fs::remove_file(&self.pidfile);
    }
}

impl Drop for NestedRun {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate lives two levels below the workspace root")
}

fn nextest_available() -> bool {
    Command::new(env!("CARGO"))
        .args(["nextest", "--version"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// --- the gates ---------------------------------------------------------------------------

#[test]
fn nested_run_fails_when_a_child_keeps_captured_stdout() {
    let Some(mut run) = NestedRun::start("fixture_child_keeps_captured_stdout") else {
        eprintln!("cargo nextest is not available; skipping the nested leak gate");
        return;
    };
    let text = run.combined_output();
    let child = run.fixture_child();
    // The census is taken before the cleanup guard runs, so the failure message can name the
    // process that held the pipe.
    let leaked = child.and_then(census::find);
    run.cleanup();

    assert!(
        !run.output.status.success(),
        "the nested run must fail on the leaked output handle, got {:?}\n{text}",
        run.output.status
    );
    assert!(
        text.contains("leaky"),
        "the nested run must report the leak\n{text}"
    );
    let child = child.expect("the fixture must have recorded its child PID");
    let leaked = leaked.expect("the leaked child must outlive the nested run");
    assert_eq!(leaked.pid, child);
    assert!(
        !census::alive(child),
        "the leaked child survived cleanup\n{}",
        census::table(&census::find(child).into_iter().collect::<Vec<_>>())
    );
    census::assert_no_owned_descendants(
        "nested_run_fails_when_a_child_keeps_captured_stdout",
        Duration::from_secs(5),
    );
}

#[test]
fn the_census_sees_a_child_that_redirected_its_output() {
    let Some(mut run) = NestedRun::start("fixture_child_redirects_output") else {
        eprintln!("cargo nextest is not available; skipping the nested census gate");
        return;
    };
    let text = run.combined_output();
    let child = run
        .fixture_child()
        .expect("the fixture must have recorded its child PID");
    // Nextest sees nothing: the child closed the captured handles before the test ended.
    let survivor = census::find(child);
    let nextest_reported_a_leak = text.contains("leaky");
    run.cleanup();

    assert!(
        run.output.status.success(),
        "the redirected-output fixture must pass the nested run: {:?}\n{text}",
        run.output.status
    );
    assert!(
        !nextest_reported_a_leak,
        "nextest is not expected to see a child that redirected its output\n{text}"
    );
    let survivor = survivor.unwrap_or_else(|| {
        panic!("the census must see the surviving child {child}, redirected output and all")
    });
    assert_eq!(survivor.pid, child);
    assert!(
        survivor.command.contains("sleep"),
        "the census must record the command line\n{}",
        census::table(std::slice::from_ref(&survivor))
    );
    assert!(
        !census::alive(child),
        "the surviving child was not reaped by the cleanup guard"
    );
    census::assert_no_owned_descendants(
        "the_census_sees_a_child_that_redirected_its_output",
        Duration::from_secs(5),
    );
}
