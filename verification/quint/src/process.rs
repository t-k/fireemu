//! Bounded Quint process construction and outcome classification.

use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;

fn bound_diagnostic(bytes: &[u8]) -> String {
    if bytes.len() <= MAX_DIAGNOSTIC_BYTES {
        return String::from_utf8_lossy(bytes).into_owned();
    }

    let mut bounded = String::from_utf8_lossy(&bytes[..MAX_DIAGNOSTIC_BYTES]).into_owned();
    bounded.push_str("\n...[truncated]");
    bounded
}

/// The baseline `EventDelivery` TLC verification request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyRequest;

impl VerifyRequest {
    /// Returns the stable Quint 0.32.0 command arguments.
    #[must_use]
    pub fn arguments(self) -> Vec<&'static str> {
        vec![
            "verify",
            "specs/EventDelivery.qnt",
            "--main",
            "EventDeliveryProof",
            "--backend",
            "tlc",
            "--tlc-config",
            "specs/tlc-config.json",
            "--invariants",
            "TypeOK",
            "AttemptsBounded",
            "DeadLetterOnlyAfterExhaustion",
            "LegalStateTransitions",
            "AttemptsChangeOnlyOnStart",
            "StaleDiscardRequiresOlderEpoch",
            "--temporal",
            "NoTerminalRegression,EventEventuallyTerminates",
            "--verbosity",
            "0",
        ]
    }
}

/// Coarse checker outcome used before property-specific mutation validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckerOutcome {
    /// The requested check completed successfully.
    Passed,
    /// TLC reported a property counterexample.
    Counterexample,
    /// The guarded wrapper reached its deadline.
    Timeout,
    /// Quint or a backend failed without a valid counterexample.
    ToolError,
}

/// Captured output from one waited checker process.
#[derive(Debug)]
pub struct Execution {
    /// Waited process status.
    pub status: ExitStatus,
    /// Bounded standard output.
    pub stdout: String,
    /// Bounded standard error.
    pub stderr: String,
    /// Wall-clock time spent waiting for the process.
    pub elapsed: Duration,
}

/// Classifies one completed checker process without treating tool failures as evidence.
#[must_use]
pub fn classify_execution(execution: &Execution) -> CheckerOutcome {
    if execution.status.code() == Some(124) {
        return CheckerOutcome::Timeout;
    }
    if execution.status.success() {
        return CheckerOutcome::Passed;
    }

    let diagnostic = format!("{}\n{}", execution.stdout, execution.stderr).to_ascii_lowercase();
    let tool_error = [
        "parsing failed",
        "typechecking failed",
        "compilation failed",
        "translation failed",
        "does not exist",
        "failed to launch",
    ]
    .iter()
    .any(|marker| diagnostic.contains(marker));
    if tool_error {
        return CheckerOutcome::ToolError;
    }

    if diagnostic.contains("invariant violated")
        || diagnostic.contains("temporal properties were violated")
        || diagnostic.contains("temporal property violated")
    {
        CheckerOutcome::Counterexample
    } else {
        CheckerOutcome::ToolError
    }
}

/// Executes the named guarded Quint command and waits for completion.
pub fn execute_quint(workdir: &Path, arguments: &[&str]) -> Result<Execution, String> {
    let started = Instant::now();
    let output = Command::new("quint")
        .args(arguments)
        .current_dir(workdir)
        .output()
        .map_err(|error| format!("failed to launch guarded quint command: {error}"))?;
    Ok(Execution {
        status: output.status,
        stdout: bound_diagnostic(&output.stdout),
        stderr: bound_diagnostic(&output.stderr),
        elapsed: started.elapsed(),
    })
}

/// Verifies the baseline `EventDelivery` model with Quint's TLC backend.
pub fn verify_event_delivery_model(repository_root: &Path) -> Result<Execution, String> {
    let workdir = repository_root.join("verification/quint");
    if !workdir.is_dir() {
        return Err(format!(
            "Quint verification directory does not exist: {}",
            workdir.display()
        ));
    }
    let checker_output = workdir.join("_apalache-out");
    if checker_output.exists() {
        return Err(format!(
            "refusing to replace pre-existing checker output: {}",
            checker_output.display()
        ));
    }
    let execution_result = execute_quint(&workdir, &VerifyRequest.arguments());
    let cleanup_result = cleanup_checker_output(&checker_output);
    let execution = execution_result?;
    cleanup_result?;
    match classify_execution(&execution) {
        CheckerOutcome::Passed => Ok(execution),
        CheckerOutcome::Counterexample => Err(format!(
            "EventDelivery baseline produced a counterexample after {:?}:\n{}\n{}",
            execution.elapsed, execution.stdout, execution.stderr
        )),
        CheckerOutcome::Timeout => Err(format!(
            "EventDelivery baseline timed out after {:?}:\n{}\n{}",
            execution.elapsed, execution.stdout, execution.stderr
        )),
        CheckerOutcome::ToolError => Err(format!(
            "EventDelivery baseline checker failed after {:?}:\n{}\n{}",
            execution.elapsed, execution.stdout, execution.stderr
        )),
    }
}

fn cleanup_checker_output(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect owned checker output {}: {error}",
                path.display()
            ));
        }
    };
    let result = if metadata.file_type().is_symlink() || metadata.is_file() {
        fs::remove_file(path)
    } else {
        fs::remove_dir_all(path)
    };
    result.map_err(|error| {
        format!(
            "cannot remove owned checker output {}: {error}",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::{classify_execution, CheckerOutcome, Execution, VerifyRequest};

    fn execution(code: i32, stdout: &str, stderr: &str) -> Execution {
        let status = Command::new("/bin/sh")
            .args(["-c", &format!("exit {code}")])
            .status()
            .expect("fixture shell must launch");
        Execution {
            status,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            elapsed: std::time::Duration::ZERO,
        }
    }

    #[test]
    fn baseline_request_checks_every_registered_property_with_tlc() {
        assert_eq!(
            VerifyRequest.arguments(),
            [
                "verify",
                "specs/EventDelivery.qnt",
                "--main",
                "EventDeliveryProof",
                "--backend",
                "tlc",
                "--tlc-config",
                "specs/tlc-config.json",
                "--invariants",
                "TypeOK",
                "AttemptsBounded",
                "DeadLetterOnlyAfterExhaustion",
                "LegalStateTransitions",
                "AttemptsChangeOnlyOnStart",
                "StaleDiscardRequiresOlderEpoch",
                "--temporal",
                "NoTerminalRegression,EventEventuallyTerminates",
                "--verbosity",
                "0",
            ]
        );
    }

    #[test]
    fn classifier_never_turns_timeouts_or_tool_errors_into_counterexamples() {
        assert_eq!(
            classify_execution(&execution(0, "", "")),
            CheckerOutcome::Passed
        );
        assert_eq!(
            classify_execution(&execution(124, "Error: Invariant violated", "")),
            CheckerOutcome::Timeout
        );
        assert_eq!(
            classify_execution(&execution(1, "", "error: parsing failed")),
            CheckerOutcome::ToolError
        );
        assert_eq!(
            classify_execution(&execution(1, "Error: Invariant violated", "")),
            CheckerOutcome::Counterexample
        );
        assert_eq!(
            classify_execution(&execution(1, "", "Temporal properties were violated")),
            CheckerOutcome::Counterexample
        );
    }

    #[test]
    fn checker_diagnostics_are_bounded_and_marked() {
        let input = vec![b'x'; super::MAX_DIAGNOSTIC_BYTES + 100];
        let bounded = super::bound_diagnostic(&input);
        assert!(bounded.starts_with("xxxx"));
        assert!(bounded.ends_with("\n...[truncated]"));
        assert!(bounded.len() <= super::MAX_DIAGNOSTIC_BYTES + 32);
    }
}
