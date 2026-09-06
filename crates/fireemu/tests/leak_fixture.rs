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

/// A nested nextest run. Dropping it terminates the verified fixture child, whatever happened
/// to the assertions.
struct NestedRun {
    pidfile: PathBuf,
    stdout_file: PathBuf,
    stderr_file: PathBuf,
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
        let stdout_file = pidfile.with_extension("stdout");
        let stderr_file = pidfile.with_extension("stderr");
        for path in [&pidfile, &stdout_file, &stderr_file] {
            let _ = std::fs::remove_file(path);
        }
        let stdout = std::fs::File::create(&stdout_file)
            .expect("the nested nextest stdout file must be created");
        let stderr = std::fs::File::create(&stderr_file)
            .expect("the nested nextest stderr file must be created");
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
            // Files reach EOF independently of an intentional child holding nextest's
            // captured test handles. Piped output would make `wait_with_output` wait for the
            // very leak this driver must clean up.
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        for inherited in [
            "NEXTEST",
            "NEXTEST_PROFILE",
            "NEXTEST_RUN_ID",
            "NEXTEST_EXECUTION_MODE",
            "NEXTEST_TEST_GROUP",
        ] {
            command.env_remove(inherited);
        }
        let mut child = command.spawn().expect("the nested nextest run must start");
        let status = child.wait().expect("the nested nextest run must finish");
        let output = Output {
            status,
            stdout: std::fs::read(&stdout_file).expect("the nested stdout must be readable"),
            stderr: std::fs::read(&stderr_file).expect("the nested stderr must be readable"),
        };
        Some(Self {
            pidfile,
            stdout_file,
            stderr_file,
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

    /// Terminates the verified fixture child. Idempotent; also runs from `Drop`.
    ///
    /// Nested cargo has already been waited and its numeric process group can be reused. Only
    /// signal a currently live fixture child whose PID, process group and command still match
    /// the identity established by the fixture.
    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        self.cleaned = true;
        let cleanup_grace = Duration::from_millis(250);
        if let Some(process) = self.fixture_child().and_then(census::find) {
            if process.command == format!("sleep {FIXTURE_CHILD_SECONDS}") {
                census::terminate_exact_process(&process, cleanup_grace);
            }
        }
        for path in [&self.pidfile, &self.stdout_file, &self.stderr_file] {
            let _ = std::fs::remove_file(path);
        }
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
}
