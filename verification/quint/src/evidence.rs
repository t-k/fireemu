//! Deterministic evidence binding for the `EventDelivery` Quint pilot.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event_delivery::{GENERATED_TRACE_SEEDS, MODELED_ACTIONS};
use crate::process::{MutationOutcome, MutationResult};

const QUINT_VERSION: &str = "0.32.0";
const QUINT_CONNECT_VERSION: &str = "0.1.2";
const TLC_VERSION: &str = "2.19 of 08 August 2024";
const BACKEND: &str = "tlc";
const DIGEST_PATHS: [&str; 30] = [
    ".github/workflows/ci.yml",
    "Cargo.toml",
    "Cargo.lock",
    "crates/fireemu-core-events/Cargo.toml",
    "crates/fireemu-core-events/src/event.rs",
    "crates/fireemu-core-events/src/retry.rs",
    "crates/fireemu-core-events/src/state.rs",
    "crates/fireemu-core-types/Cargo.toml",
    "crates/fireemu-core-types/src/ids.rs",
    "crates/fireemu-core-types/src/time.rs",
    "verification/quint/Cargo.toml",
    "verification/quint/README.md",
    "verification/quint/bin/quint",
    "verification/quint/bin/process-group",
    "verification/quint/run-pilot.sh",
    "verification/quint/specs/EventDelivery.qnt",
    "verification/quint/specs/tlc-config.json",
    "verification/quint/mutations/EventDelivery.json",
    "verification/quint/package.json",
    "verification/quint/pnpm-lock.yaml",
    "verification/quint/src/event_delivery.rs",
    "verification/quint/src/evidence.rs",
    "verification/quint/src/lib.rs",
    "verification/quint/src/main.rs",
    "verification/quint/src/model.rs",
    "verification/quint/src/process.rs",
    "verification/quint/tests/cli_contract.rs",
    "verification/quint/tests/event_delivery_connect.rs",
    "verification/quint/tests/event_delivery_evidence.rs",
    "verification/quint/tests/model_registry.rs",
];
const INVARIANTS: [&str; 6] = [
    "TypeOK",
    "AttemptsBounded",
    "DeadLetterOnlyAfterExhaustion",
    "LegalStateTransitions",
    "AttemptsChangeOnlyOnStart",
    "StaleDiscardRequiresOlderEpoch",
];
const TEMPORAL_PROPERTIES: [&str; 2] = ["NoTerminalRegression", "EventEventuallyTerminates"];
const SCENARIOS: [&str; 4] = ["success", "retryExhaustion", "staleDiscard", "cancel"];
const PROJECTION_FIELDS: [&str; 8] = [
    "state",
    "attempts",
    "maxAttempts",
    "capturedEpoch",
    "currentEpoch",
    "terminal",
    "cancelled",
    "stale",
];

/// Strict, versioned pilot evidence document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    /// Evidence schema version.
    pub schema_version: u32,
    /// Bound model name.
    pub model: String,
    /// Exact checker and bridge tool metadata.
    pub tools: ToolEvidence,
    /// SHA-256 digests keyed by repository-relative input path.
    pub digests: BTreeMap<String, String>,
    /// Safety property names checked by the baseline.
    pub invariants: Vec<String>,
    /// Temporal property names checked by the baseline.
    pub temporal_properties: Vec<String>,
    /// Required mutation results.
    pub mutations: Vec<MutationEvidence>,
    /// Deterministic Quint scenario names.
    pub scenarios: Vec<String>,
    /// Modeled action coverage set.
    pub actions: Vec<String>,
    /// Projection fields with negative conformance checks.
    pub projection_fields: Vec<String>,
    /// Bounded generated-trace campaign configuration.
    pub simulation: SimulationEvidence,
}

/// Tool versions bound into evidence.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolEvidence {
    /// Pinned Quint CLI version.
    pub quint: String,
    /// Pinned Quint Connect crate version.
    pub quint_connect: String,
    /// TLC version bundled by the pinned Quint translator path.
    pub tlc: String,
    /// Selected verification backend.
    pub backend: String,
}

/// Stable mutation result without nondeterministic paths or timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationEvidence {
    /// Stable legacy mutation identifier.
    pub id: String,
    /// Property that killed the mutation.
    pub property: String,
    /// Strict mutation classification.
    pub outcome: MutationOutcome,
    /// Stable bounded diagnostic classification.
    pub diagnostic: String,
}

/// Fixed generated-trace campaign bounds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulationEvidence {
    /// Checked-in reproducible seed strings.
    pub seeds: Vec<String>,
    /// Number of generated traces for each seed.
    pub traces_per_seed: usize,
    /// Maximum actions in each trace.
    pub max_steps: usize,
}

/// Builds deterministic evidence after all mutation results have been killed.
pub fn build_evidence(
    repository_root: &Path,
    mutation_results: &[MutationResult],
) -> Result<Evidence, String> {
    let mutations = normalize_mutations(mutation_results)?;
    Ok(Evidence {
        schema_version: 1,
        model: "EventDelivery".to_owned(),
        tools: expected_tools(),
        digests: compute_digests(repository_root)?,
        invariants: strings(INVARIANTS),
        temporal_properties: strings(TEMPORAL_PROPERTIES),
        mutations,
        scenarios: strings(SCENARIOS),
        actions: strings(MODELED_ACTIONS),
        projection_fields: strings(PROJECTION_FIELDS),
        simulation: SimulationEvidence {
            seeds: strings(GENERATED_TRACE_SEEDS),
            traces_per_seed: 100,
            max_steps: 20,
        },
    })
}

/// Writes stable, newline-terminated evidence JSON.
pub fn write_evidence(
    repository_root: &Path,
    path: &Path,
    mutation_results: &[MutationResult],
) -> Result<(), String> {
    let evidence = build_evidence(repository_root, mutation_results)?;
    let mut json = serde_json::to_string_pretty(&evidence)
        .map_err(|error| format!("cannot serialize evidence: {error}"))?;
    json.push('\n');
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "cannot create evidence directory {}: {error}",
                parent.display()
            )
        })?;
    }
    fs::write(path, json)
        .map_err(|error| format!("cannot write evidence {}: {error}", path.display()))
}

/// Parses strict evidence and optionally validates its repository input digests.
pub fn validate_evidence_json(
    json: &str,
    repository_root: Option<&Path>,
) -> Result<Evidence, String> {
    let evidence: Evidence =
        serde_json::from_str(json).map_err(|error| format!("invalid evidence JSON: {error}"))?;
    validate_semantics(&evidence)?;
    if let Some(root) = repository_root {
        let expected = compute_digests(root)?;
        for (path, digest) in expected {
            match evidence.digests.get(&path) {
                Some(actual) if actual == &digest => {}
                _ => return Err(format!("digest mismatch for {path}")),
            }
        }
    }
    Ok(evidence)
}

/// Validates a checked-in evidence file against current repository inputs.
pub fn validate_evidence_file(repository_root: &Path, path: &Path) -> Result<Evidence, String> {
    let json = fs::read_to_string(path)
        .map_err(|error| format!("cannot read evidence {}: {error}", path.display()))?;
    validate_evidence_json(&json, Some(repository_root))
}

fn validate_semantics(evidence: &Evidence) -> Result<(), String> {
    if evidence.schema_version != 1 || evidence.model != "EventDelivery" {
        return Err("unsupported evidence identity".to_owned());
    }
    if evidence.tools != expected_tools() {
        return Err("tool metadata mismatch".to_owned());
    }
    if evidence.digests.len() != DIGEST_PATHS.len()
        || evidence.invariants != strings(INVARIANTS)
        || evidence.temporal_properties != strings(TEMPORAL_PROPERTIES)
        || evidence.scenarios != strings(SCENARIOS)
        || evidence.actions != strings(MODELED_ACTIONS)
        || evidence.projection_fields != strings(PROJECTION_FIELDS)
        || evidence.simulation
            != (SimulationEvidence {
                seeds: strings(GENERATED_TRACE_SEEDS),
                traces_per_seed: 100,
                max_steps: 20,
            })
    {
        return Err("evidence coverage metadata mismatch".to_owned());
    }
    validate_mutation_evidence(&evidence.mutations)
}

fn validate_mutation_evidence(mutations: &[MutationEvidence]) -> Result<(), String> {
    let expected = [
        (
            "M-TLA-EVENT-TERMINAL-001",
            "NoTerminalRegression",
            MutationOutcome::KilledSafety,
        ),
        (
            "M-TLA-EVENT-LIVENESS-001",
            "EventEventuallyTerminates",
            MutationOutcome::KilledTemporal,
        ),
        (
            "M-TLA-EVENT-LEGAL-001",
            "LegalStateTransitions",
            MutationOutcome::KilledSafety,
        ),
        (
            "M-TLA-EVENT-ATTEMPTS-001",
            "AttemptsChangeOnlyOnStart",
            MutationOutcome::KilledSafety,
        ),
        (
            "M-TLA-EVENT-STALE-001",
            "StaleDiscardRequiresOlderEpoch",
            MutationOutcome::KilledSafety,
        ),
    ];
    if mutations.len() != expected.len() {
        return Err("mutation evidence count mismatch".to_owned());
    }
    for (mutation, (id, property, outcome)) in mutations.iter().zip(expected) {
        if mutation.id != id
            || mutation.property != property
            || mutation.outcome != outcome
            || mutation.diagnostic != stable_diagnostic(outcome)
        {
            return Err(format!("invalid mutation evidence for {id}"));
        }
    }
    Ok(())
}

fn normalize_mutations(results: &[MutationResult]) -> Result<Vec<MutationEvidence>, String> {
    if results.iter().any(|result| !result.outcome.is_killed()) {
        return Err("cannot generate evidence from a non-killed mutation".to_owned());
    }
    let normalized = results
        .iter()
        .map(|result| MutationEvidence {
            id: result.id.clone(),
            property: result.property.clone(),
            outcome: result.outcome,
            diagnostic: stable_diagnostic(result.outcome).to_owned(),
        })
        .collect::<Vec<_>>();
    validate_mutation_evidence(&normalized)?;
    Ok(normalized)
}

fn stable_diagnostic(outcome: MutationOutcome) -> &'static str {
    match outcome {
        MutationOutcome::KilledSafety => "TLC invariant violation",
        MutationOutcome::KilledTemporal => "TLC temporal property violation",
        MutationOutcome::Survived => "survived",
        MutationOutcome::Timeout => "timeout",
        MutationOutcome::ToolError => "tool error",
    }
}

fn expected_tools() -> ToolEvidence {
    ToolEvidence {
        quint: QUINT_VERSION.to_owned(),
        quint_connect: QUINT_CONNECT_VERSION.to_owned(),
        tlc: TLC_VERSION.to_owned(),
        backend: BACKEND.to_owned(),
    }
}

fn compute_digests(repository_root: &Path) -> Result<BTreeMap<String, String>, String> {
    DIGEST_PATHS
        .into_iter()
        .map(|relative| {
            let path = repository_root.join(relative);
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read bound input {}: {error}", path.display()))?;
            Ok((relative.to_owned(), format!("{:x}", Sha256::digest(bytes))))
        })
        .collect()
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
    values.into_iter().map(str::to_owned).collect()
}
