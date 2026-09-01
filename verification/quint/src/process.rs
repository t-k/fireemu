//! Bounded Quint process construction and outcome classification.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;

/// Strict source-mutation manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Stable model name.
    pub model: String,
    /// Required semantic source mutations.
    pub mutations: Vec<Mutation>,
}

impl MutationManifest {
    /// Parses and validates a manifest without accepting ambiguous mutation intent.
    pub fn parse(json: &str) -> Result<Self, String> {
        let manifest: Self = serde_json::from_str(json)
            .map_err(|error| format!("invalid mutation manifest: {error}"))?;
        if manifest.schema_version != 1 || manifest.model != "EventDelivery" {
            return Err("unsupported mutation manifest identity".to_owned());
        }
        if manifest.mutations.is_empty() {
            return Err("mutation manifest must not be empty".to_owned());
        }
        let mut ids = BTreeSet::new();
        let mut operators = BTreeSet::new();
        for mutation in &manifest.mutations {
            if mutation.id.is_empty()
                || mutation.property.is_empty()
                || mutation.operator.is_empty()
                || mutation.from.is_empty()
                || mutation.to.is_empty()
            {
                return Err("mutation fields must not be empty".to_owned());
            }
            if mutation.from == mutation.to {
                return Err(format!(
                    "mutation {} does not change its source",
                    mutation.id
                ));
            }
            if !ids.insert(&mutation.id) {
                return Err(format!("duplicate mutation id {}", mutation.id));
            }
            if !operators.insert(&mutation.operator) {
                return Err(format!("duplicate mutation intent {}", mutation.operator));
            }
        }
        let actual = manifest
            .mutations
            .iter()
            .map(|mutation| (mutation.id.as_str(), mutation.property.as_str()))
            .collect::<BTreeSet<_>>();
        let expected = [
            ("M-TLA-EVENT-TERMINAL-001", "NoTerminalRegression"),
            ("M-TLA-EVENT-LIVENESS-001", "EventEventuallyTerminates"),
            ("M-TLA-EVENT-LEGAL-001", "LegalStateTransitions"),
            ("M-TLA-EVENT-ATTEMPTS-001", "AttemptsChangeOnlyOnStart"),
            ("M-TLA-EVENT-STALE-001", "StaleDiscardRequiresOlderEpoch"),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(
                "mutation IDs and property mappings do not match the required set".to_owned(),
            );
        }
        Ok(manifest)
    }
}

/// One exact Quint source replacement.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    /// Stable legacy mutation identifier.
    pub id: String,
    /// Property expected to kill this mutation.
    pub property: String,
    /// Stable fault intent.
    pub operator: String,
    /// Source text that must occur exactly once.
    pub from: String,
    /// Replacement source text.
    pub to: String,
}

impl Mutation {
    fn is_temporal_property(&self) -> bool {
        matches!(
            self.property.as_str(),
            "NoTerminalRegression" | "EventEventuallyTerminates"
        )
    }

    fn requires_temporal_counterexample(&self) -> bool {
        self.property == "EventEventuallyTerminates"
    }
}

/// Applies an exact source mutation only when its source has one occurrence.
pub fn apply_source_replacement(source: &str, mutation: &Mutation) -> Result<String, String> {
    let occurrences = source.match_indices(&mutation.from).count();
    if occurrences != 1 {
        return Err(format!(
            "mutation {} source occurs {occurrences} times, expected exactly once",
            mutation.id
        ));
    }
    Ok(source.replacen(&mutation.from, &mutation.to, 1))
}

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

/// Property-specific outcome for one waited mutation checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MutationOutcome {
    /// A state invariant killed the mutation.
    KilledSafety,
    /// A temporal property killed the mutation.
    KilledTemporal,
    /// The mutated property still held.
    Survived,
    /// The guarded checker reached its deadline.
    Timeout,
    /// Quint, translation, or TLC failed without valid counterexample evidence.
    ToolError,
}

/// Serializable result for one required mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationResult {
    /// Stable mutation identifier.
    pub id: String,
    /// Property that killed the mutation.
    pub property: String,
    /// Strictly classified checker result.
    pub outcome: MutationOutcome,
    /// Bounded checker diagnostic.
    pub diagnostic: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationReport {
    schema_version: u32,
    model: &'static str,
    mutations: Vec<MutationResult>,
}

impl MutationOutcome {
    /// Whether this outcome is valid mutation evidence.
    #[must_use]
    pub const fn is_killed(self) -> bool {
        matches!(self, Self::KilledSafety | Self::KilledTemporal)
    }
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
        "translation error",
        "failed to translate",
        "unexpected error",
        "does not exist",
        "failed to launch",
    ]
    .iter()
    .any(|marker| diagnostic.contains(marker));
    if tool_error {
        return CheckerOutcome::ToolError;
    }

    if has_safety_counterexample(&diagnostic) || has_temporal_counterexample(&diagnostic) {
        CheckerOutcome::Counterexample
    } else {
        CheckerOutcome::ToolError
    }
}

/// Classifies a mutation run while requiring the expected counterexample kind.
#[must_use]
pub fn classify_mutation_execution(
    execution: &Execution,
    expects_temporal: bool,
) -> MutationOutcome {
    match classify_execution(execution) {
        CheckerOutcome::Passed => MutationOutcome::Survived,
        CheckerOutcome::Timeout => MutationOutcome::Timeout,
        CheckerOutcome::ToolError => MutationOutcome::ToolError,
        CheckerOutcome::Counterexample => {
            let diagnostic =
                format!("{}\n{}", execution.stdout, execution.stderr).to_ascii_lowercase();
            let temporal = has_temporal_counterexample(&diagnostic);
            let safety = has_safety_counterexample(&diagnostic);
            match (expects_temporal, temporal, safety) {
                (true, true, _) => MutationOutcome::KilledTemporal,
                (false, _, true) => MutationOutcome::KilledSafety,
                _ => MutationOutcome::ToolError,
            }
        }
    }
}

fn has_safety_counterexample(diagnostic: &str) -> bool {
    diagnostic.contains("invariant violated")
        || (diagnostic.contains("invariant ") && diagnostic.contains(" violated"))
}

fn has_temporal_counterexample(diagnostic: &str) -> bool {
    diagnostic.contains("temporal properties were violated")
        || diagnostic.contains("temporal property violated")
        || (diagnostic.contains("temporal property") && diagnostic.contains(" violated"))
}

/// Runs all required `EventDelivery` source mutations with the guarded Quint/TLC checker.
pub fn mutate_event_delivery(
    repository_root: &Path,
    evidence_path: Option<&Path>,
) -> Result<Vec<MutationResult>, String> {
    let workdir = repository_root.join("verification/quint");
    let source_path = workdir.join("specs/EventDelivery.qnt");
    let config_path = workdir.join("specs/tlc-config.json");
    let manifest_path = workdir.join("mutations/EventDelivery.json");
    let source = fs::read_to_string(&source_path)
        .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
    let config = fs::read(&config_path)
        .map_err(|error| format!("cannot read {}: {error}", config_path.display()))?;
    let manifest_json = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?;
    let manifest = MutationManifest::parse(&manifest_json)?;
    let mut results = Vec::with_capacity(manifest.mutations.len());

    for (index, mutation) in manifest.mutations.iter().enumerate() {
        let mutated = apply_source_replacement(&source, mutation)?;
        let temporary = OwnedMutationDirectory::create(index)?;
        let specs = temporary.path.join("specs");
        fs::create_dir(&specs)
            .map_err(|error| format!("cannot create {}: {error}", specs.display()))?;
        fs::write(specs.join("EventDelivery.qnt"), mutated)
            .map_err(|error| format!("cannot write mutated Quint model: {error}"))?;
        fs::write(specs.join("tlc-config.json"), &config)
            .map_err(|error| format!("cannot write copied TLC config: {error}"))?;

        let arguments = mutation_arguments(mutation);
        let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let execution_result = execute_quint(&temporary.path, &argument_refs);
        let execution = execution_result?;
        let outcome =
            classify_mutation_execution(&execution, mutation.requires_temporal_counterexample());
        let diagnostic =
            bound_diagnostic(format!("{}\n{}", execution.stdout, execution.stderr).as_bytes());
        temporary.close()?;
        let result = MutationResult {
            id: mutation.id.clone(),
            property: mutation.property.clone(),
            outcome,
            diagnostic,
        };
        if !outcome.is_killed() {
            return Err(format!(
                "mutation {} was not killed by {} ({outcome:?}):\n{}",
                mutation.id, mutation.property, result.diagnostic
            ));
        }
        results.push(result);
    }

    if let Some(path) = evidence_path {
        let report = MutationReport {
            schema_version: 1,
            model: "EventDelivery",
            mutations: results.clone(),
        };
        let mut json = serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot serialize mutation report: {error}"))?;
        json.push('\n');
        fs::write(path, json)
            .map_err(|error| format!("cannot write mutation report {}: {error}", path.display()))?;
    }
    Ok(results)
}

fn mutation_arguments(mutation: &Mutation) -> Vec<String> {
    let mut arguments = vec![
        "verify".to_owned(),
        "specs/EventDelivery.qnt".to_owned(),
        "--main".to_owned(),
        "EventDeliveryProof".to_owned(),
        "--backend".to_owned(),
        "tlc".to_owned(),
        "--tlc-config".to_owned(),
        "specs/tlc-config.json".to_owned(),
    ];
    if mutation.is_temporal_property() {
        arguments.push("--temporal".to_owned());
    } else {
        arguments.push("--invariants".to_owned());
    }
    arguments.push(mutation.property.clone());
    // Quint 0.32.0 forwards TLC's raw property-kind diagnostic only at level 3.
    // Output is still bounded by `execute_quint` before classification or reporting.
    arguments.extend(["--verbosity".to_owned(), "3".to_owned()]);
    arguments
}

struct OwnedMutationDirectory {
    path: PathBuf,
    closed: bool,
}

impl OwnedMutationDirectory {
    fn create(index: usize) -> Result<Self, String> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("system time is before UNIX epoch: {error}"))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fireemu-quint-mutant-{}-{index}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).map_err(|error| {
            format!("cannot create owned directory {}: {error}", path.display())
        })?;
        Ok(Self {
            path,
            closed: false,
        })
    }

    fn close(mut self) -> Result<(), String> {
        fs::remove_dir_all(&self.path).map_err(|error| {
            format!(
                "cannot remove owned mutation directory {}: {error}",
                self.path.display()
            )
        })?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for OwnedMutationDirectory {
    fn drop(&mut self) {
        if !self.closed {
            let _ = fs::remove_dir_all(&self.path);
        }
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

    use super::{
        classify_execution, classify_mutation_execution, CheckerOutcome, Execution,
        MutationOutcome, VerifyRequest,
    };

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
    fn mutation_classifier_requires_expected_counterexample_evidence() {
        let safety = execution(1, "Error: Invariant LegalStateTransitions violated", "");
        assert_eq!(
            classify_mutation_execution(&safety, false),
            MutationOutcome::KilledSafety
        );
        assert_eq!(
            classify_mutation_execution(&safety, true),
            MutationOutcome::ToolError
        );

        let temporal = execution(1, "Temporal property was violated", "");
        assert_eq!(
            classify_mutation_execution(&temporal, true),
            MutationOutcome::KilledTemporal
        );
        assert_eq!(
            classify_mutation_execution(&execution(0, "", ""), false),
            MutationOutcome::Survived
        );
        assert_eq!(
            classify_mutation_execution(&execution(124, "Error: Invariant X violated", ""), false),
            MutationOutcome::Timeout
        );
        assert_eq!(
            classify_mutation_execution(
                &execution(1, "Error: Invariant X violated", "translation failed"),
                false
            ),
            MutationOutcome::ToolError
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
