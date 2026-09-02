//! Bounded Quint process construction and outcome classification.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::model::{model, ModelDescriptor, PropertyDescriptor, PropertyKind};

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
    pub fn parse(json: &str, descriptor: &ModelDescriptor) -> Result<Self, String> {
        let manifest: Self = serde_json::from_str(json)
            .map_err(|error| format!("invalid mutation manifest: {error}"))?;
        if manifest.schema_version != 1 || manifest.model != descriptor.name {
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
            descriptor.property(&mutation.property)?;
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

/// A bounded TLC verification request for one registered Quint model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyRequest {
    descriptor: &'static ModelDescriptor,
}

impl VerifyRequest {
    /// Creates a request for a registered model descriptor.
    #[must_use]
    pub const fn new(descriptor: &'static ModelDescriptor) -> Self {
        Self { descriptor }
    }

    /// Returns the stable Quint 0.32.0 command arguments.
    #[must_use]
    pub fn arguments(self) -> Vec<String> {
        let mut arguments = vec![
            "verify".to_owned(),
            self.descriptor.spec.to_owned(),
            "--main".to_owned(),
            self.descriptor.main.to_owned(),
            "--backend".to_owned(),
            "tlc".to_owned(),
            "--tlc-config".to_owned(),
            self.descriptor.config.to_owned(),
        ];
        let invariants = self
            .descriptor
            .properties
            .iter()
            .filter(|property| property.kind == PropertyKind::Invariant)
            .map(|property| property.name)
            .collect::<Vec<_>>();
        if !invariants.is_empty() {
            arguments.push("--invariants".to_owned());
            arguments.extend(invariants.into_iter().map(str::to_owned));
        }
        let temporal = self
            .descriptor
            .properties
            .iter()
            .filter(|property| property.kind == PropertyKind::Temporal)
            .map(|property| property.name)
            .collect::<Vec<_>>();
        if !temporal.is_empty() {
            arguments.push("--temporal".to_owned());
            arguments.push(temporal.join(","));
        }
        arguments.extend(["--verbosity".to_owned(), "0".to_owned()]);
        arguments
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
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
    expected_property: &str,
    expects_temporal: bool,
) -> MutationOutcome {
    match classify_execution(execution) {
        CheckerOutcome::Passed => MutationOutcome::Survived,
        CheckerOutcome::Timeout => MutationOutcome::Timeout,
        CheckerOutcome::ToolError => MutationOutcome::ToolError,
        CheckerOutcome::Counterexample => {
            let diagnostic =
                format!("{}\n{}", execution.stdout, execution.stderr).to_ascii_lowercase();
            let quint_counterexample = execution.stderr.lines().any(|line| {
                line.trim()
                    .eq_ignore_ascii_case("error: found a counterexample")
            });
            if execution.status.code() != Some(1) || !quint_counterexample {
                return MutationOutcome::ToolError;
            }
            let temporal = expected_property == "EventEventuallyTerminates"
                && has_temporal_counterexample(&diagnostic);
            let safety = has_expected_safety_counterexample(&diagnostic, expected_property);
            match (expects_temporal, temporal, safety) {
                (true, true, _) => MutationOutcome::KilledTemporal,
                (false, _, true) => MutationOutcome::KilledSafety,
                _ => MutationOutcome::ToolError,
            }
        }
    }
}

/// Classifies a mutation against the exact diagnostic registered for its property.
#[must_use]
pub fn classify_model_mutation_execution(
    execution: &Execution,
    property: &PropertyDescriptor,
) -> MutationOutcome {
    match classify_execution(execution) {
        CheckerOutcome::Passed => MutationOutcome::Survived,
        CheckerOutcome::Timeout => MutationOutcome::Timeout,
        CheckerOutcome::ToolError => MutationOutcome::ToolError,
        CheckerOutcome::Counterexample => {
            let diagnostic =
                format!("{}\n{}", execution.stdout, execution.stderr).to_ascii_lowercase();
            let quint_counterexample = execution.stderr.lines().any(|line| {
                line.trim()
                    .eq_ignore_ascii_case("error: found a counterexample")
            });
            if execution.status.code() != Some(1) || !quint_counterexample {
                return MutationOutcome::ToolError;
            }
            if property.diagnostic_name == "temporal properties" {
                return if has_temporal_counterexample(&diagnostic) {
                    MutationOutcome::KilledTemporal
                } else {
                    MutationOutcome::ToolError
                };
            }
            if has_named_safety_counterexample(&diagnostic, property.diagnostic_name) {
                MutationOutcome::KilledSafety
            } else {
                MutationOutcome::ToolError
            }
        }
    }
}

fn has_safety_counterexample(diagnostic: &str) -> bool {
    diagnostic.lines().any(|line| {
        let line = line.trim();
        line.starts_with("error: invariant ")
            && (line.ends_with(" is violated.")
                || line.ends_with(" is violated by the initial state:"))
    })
}

fn has_expected_safety_counterexample(diagnostic: &str, expected_property: &str) -> bool {
    let invariant = match expected_property {
        "NoTerminalRegression" => "eventdeliveryproof_eventdelivery_noterminalregression",
        "LegalStateTransitions"
        | "AttemptsChangeOnlyOnStart"
        | "StaleDiscardRequiresOlderEpoch" => "q_inv",
        _ => return false,
    };
    has_named_safety_counterexample(diagnostic, invariant)
}

fn has_named_safety_counterexample(diagnostic: &str, invariant: &str) -> bool {
    let violated = format!(
        "error: invariant {} is violated.",
        invariant.to_ascii_lowercase()
    );
    let violated_initially = format!(
        "error: invariant {} is violated by the initial state:",
        invariant.to_ascii_lowercase()
    );
    diagnostic.lines().any(|line| {
        let line = line.trim();
        line == violated || line == violated_initially
    })
}

fn has_temporal_counterexample(diagnostic: &str) -> bool {
    diagnostic
        .lines()
        .any(|line| line.trim() == "error: temporal properties were violated.")
}

/// Runs every declared source mutation for one registered Quint model.
pub fn mutate_model(
    repository_root: &Path,
    descriptor: &'static ModelDescriptor,
    evidence_path: Option<&Path>,
) -> Result<Vec<MutationResult>, String> {
    let workdir = repository_root.join("verification/quint");
    let source_path = workdir.join(descriptor.spec);
    let config_path = workdir.join(descriptor.config);
    let manifest_path = workdir.join(descriptor.mutation_manifest);
    let source = fs::read_to_string(&source_path)
        .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
    let config = fs::read(&config_path)
        .map_err(|error| format!("cannot read {}: {error}", config_path.display()))?;
    let manifest_json = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?;
    let manifest = MutationManifest::parse(&manifest_json, descriptor)?;
    let mut results = Vec::with_capacity(manifest.mutations.len());

    for (index, mutation) in manifest.mutations.iter().enumerate() {
        let mutated = apply_source_replacement(&source, mutation)?;
        let temporary = OwnedMutationDirectory::create(index)?;
        let temporary_source = temporary.path.join(descriptor.spec);
        let source_parent = temporary_source
            .parent()
            .ok_or_else(|| format!("model source has no parent: {}", descriptor.spec))?;
        fs::create_dir_all(source_parent)
            .map_err(|error| format!("cannot create {}: {error}", source_parent.display()))?;
        fs::write(&temporary_source, mutated)
            .map_err(|error| format!("cannot write mutated Quint model: {error}"))?;
        let temporary_config = temporary.path.join(descriptor.config);
        let config_parent = temporary_config
            .parent()
            .ok_or_else(|| format!("model config has no parent: {}", descriptor.config))?;
        fs::create_dir_all(config_parent)
            .map_err(|error| format!("cannot create {}: {error}", config_parent.display()))?;
        fs::write(&temporary_config, &config)
            .map_err(|error| format!("cannot write copied TLC config: {error}"))?;

        let property = descriptor.property(&mutation.property)?;
        let arguments = mutation_arguments(descriptor, mutation, property.kind);
        let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let execution_result = execute_quint(&temporary.path, &argument_refs);
        let execution = execution_result?;
        let outcome = classify_model_mutation_execution(&execution, property);
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
        crate::evidence::write_evidence(repository_root, path, descriptor, &results)?;
    }
    Ok(results)
}

/// Compatibility wrapper for the original `EventDelivery` pilot API.
pub fn mutate_event_delivery(
    repository_root: &Path,
    evidence_path: Option<&Path>,
) -> Result<Vec<MutationResult>, String> {
    mutate_model(
        repository_root,
        model("EventDelivery").expect("EventDelivery must remain registered"),
        evidence_path,
    )
}

fn mutation_arguments(
    descriptor: &ModelDescriptor,
    mutation: &Mutation,
    property_kind: PropertyKind,
) -> Vec<String> {
    let mut arguments = vec![
        "verify".to_owned(),
        descriptor.spec.to_owned(),
        "--main".to_owned(),
        descriptor.main.to_owned(),
        "--backend".to_owned(),
        "tlc".to_owned(),
        "--tlc-config".to_owned(),
        descriptor.config.to_owned(),
    ];
    if property_kind == PropertyKind::Temporal {
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

/// Verifies one registered model with Quint's TLC backend.
pub fn verify_model(
    repository_root: &Path,
    descriptor: &'static ModelDescriptor,
) -> Result<Execution, String> {
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
    let arguments = VerifyRequest::new(descriptor).arguments();
    let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let execution_result = execute_quint(&workdir, &argument_refs);
    let cleanup_result = cleanup_checker_output(&checker_output);
    let execution = execution_result?;
    cleanup_result?;
    match classify_execution(&execution) {
        CheckerOutcome::Passed => Ok(execution),
        CheckerOutcome::Counterexample => Err(format!(
            "{} baseline produced a counterexample after {:?}:\n{}\n{}",
            descriptor.name, execution.elapsed, execution.stdout, execution.stderr
        )),
        CheckerOutcome::Timeout => Err(format!(
            "{} baseline timed out after {:?}:\n{}\n{}",
            descriptor.name, execution.elapsed, execution.stdout, execution.stderr
        )),
        CheckerOutcome::ToolError => Err(format!(
            "{} baseline checker failed after {:?}:\n{}\n{}",
            descriptor.name, execution.elapsed, execution.stdout, execution.stderr
        )),
    }
}

/// Compatibility wrapper for the original `EventDelivery` pilot API.
pub fn verify_event_delivery_model(repository_root: &Path) -> Result<Execution, String> {
    verify_model(
        repository_root,
        model("EventDelivery").expect("EventDelivery must remain registered"),
    )
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
        classify_execution, classify_model_mutation_execution, classify_mutation_execution,
        CheckerOutcome, Execution, MutationOutcome, VerifyRequest,
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
        let descriptor = crate::model::model("EventDelivery").expect("registered model");
        assert_eq!(
            VerifyRequest::new(descriptor).arguments(),
            [
                "verify",
                "specs/EventDelivery.qnt",
                "--main",
                "EventDeliveryProof",
                "--backend",
                "tlc",
                "--tlc-config",
                "configs/EventDelivery.json",
                "--invariants",
                "TypeOK",
                "AttemptsBounded",
                "DeadLetterOnlyAfterExhaustion",
                "LegalStateTransitions",
                "AttemptsChangeOnlyOnStart",
                "StaleDiscardRequiresOlderEpoch",
                "RetryDeadlineMatchesPolicy",
                "RetryRequiresDeadline",
                "--temporal",
                "NoTerminalRegression,TimeNeverDecreases,EventEventuallyTerminates",
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
            classify_execution(&execution(124, "Error: Invariant q_inv is violated.", "")),
            CheckerOutcome::Timeout
        );
        assert_eq!(
            classify_execution(&execution(1, "", "error: parsing failed")),
            CheckerOutcome::ToolError
        );
        assert_eq!(
            classify_execution(&execution(1, "Error: Invariant q_inv is violated.", "")),
            CheckerOutcome::Counterexample
        );
        assert_eq!(
            classify_execution(&execution(
                1,
                "Error: Temporal properties were violated.",
                ""
            )),
            CheckerOutcome::Counterexample
        );
    }

    #[test]
    fn mutation_classifier_requires_expected_counterexample_evidence() {
        let safety = execution(
            1,
            "Error: Invariant q_inv is violated.",
            "error: found a counterexample",
        );
        assert_eq!(
            classify_mutation_execution(&safety, "LegalStateTransitions", false),
            MutationOutcome::KilledSafety
        );
        assert_eq!(
            classify_mutation_execution(&safety, "LegalStateTransitions", true),
            MutationOutcome::ToolError
        );
        let unrelated = execution(
            1,
            "Error: Invariant EventDeliveryProof_EventDelivery_AttemptsChangeOnlyOnStart is violated.",
            "error: found a counterexample",
        );
        assert_eq!(
            classify_mutation_execution(&unrelated, "LegalStateTransitions", false),
            MutationOutcome::ToolError
        );

        let temporal = execution(
            1,
            "Error: Temporal properties were violated.",
            "error: found a counterexample",
        );
        assert_eq!(
            classify_mutation_execution(&temporal, "EventEventuallyTerminates", true),
            MutationOutcome::KilledTemporal
        );
        assert_eq!(
            classify_mutation_execution(&execution(0, "", ""), "LegalStateTransitions", false),
            MutationOutcome::Survived
        );
        assert_eq!(
            classify_mutation_execution(
                &execution(
                    124,
                    "Error: Invariant X is violated.",
                    "error: found a counterexample",
                ),
                "LegalStateTransitions",
                false,
            ),
            MutationOutcome::Timeout
        );
        assert_eq!(
            classify_mutation_execution(
                &execution(
                    1,
                    "Error: Invariant X is violated.",
                    "translation failed\nerror: found a counterexample",
                ),
                "LegalStateTransitions",
                false
            ),
            MutationOutcome::ToolError
        );
    }

    #[test]
    fn descriptor_classifier_rejects_a_counterexample_for_another_property() {
        let descriptor = crate::model::model("EventDelivery").expect("registered model");
        let legal = descriptor
            .property("LegalStateTransitions")
            .expect("registered property");
        let expected = execution(
            1,
            "Error: Invariant q_inv is violated.",
            "error: found a counterexample",
        );
        assert_eq!(
            classify_model_mutation_execution(&expected, legal),
            MutationOutcome::KilledSafety
        );

        let initial_state_counterexample = execution(
            1,
            "Error: Invariant q_inv is violated by the initial state:",
            "error: found a counterexample",
        );
        assert_eq!(
            classify_model_mutation_execution(&initial_state_counterexample, legal),
            MutationOutcome::KilledSafety,
            "an exact initial-state counterexample is valid kill evidence"
        );

        let terminal = descriptor
            .property("NoTerminalRegression")
            .expect("registered property");
        assert_eq!(
            classify_model_mutation_execution(&expected, terminal),
            MutationOutcome::ToolError
        );
        let exact_terminal = execution(
            1,
            "Error: Invariant EventDeliveryProof_EventDelivery_NoTerminalRegression is violated.",
            "error: found a counterexample",
        );
        assert_eq!(
            classify_model_mutation_execution(&exact_terminal, terminal),
            MutationOutcome::KilledSafety
        );

        let time = descriptor
            .property("TimeNeverDecreases")
            .expect("registered property");
        let exact_time = execution(
            1,
            "Error: Invariant EventDeliveryProof_EventDelivery_TimeNeverDecreases is violated.",
            "error: found a counterexample",
        );
        assert_eq!(
            classify_model_mutation_execution(&exact_time, time),
            MutationOutcome::KilledSafety
        );

        let eventual = descriptor
            .property("EventEventuallyTerminates")
            .expect("registered property");
        let temporal = execution(
            1,
            "Error: Temporal properties were violated.",
            "error: found a counterexample",
        );
        assert_eq!(
            classify_model_mutation_execution(&temporal, eventual),
            MutationOutcome::KilledTemporal
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
