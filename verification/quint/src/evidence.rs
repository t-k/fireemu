//! Deterministic, model-neutral evidence for the Quint verification authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event_delivery::GENERATED_TRACE_SEEDS;
use crate::model::{ModelDescriptor, PropertyKind};
use crate::process::{
    validate_apalache_distribution, MutationManifest, MutationOutcome, MutationResult,
    APALACHE_ARCHIVE_SHA256, APALACHE_ARCHIVE_URL, APALACHE_JAR_SHA256, APALACHE_LAUNCHER_SHA256,
    APALACHE_VERSION,
};

const QUINT_VERSION: &str = "0.32.0";
const QUINT_CONNECT_VERSION: &str = "0.1.2";
const TLC_VERSION: &str = "2.19 of 08 August 2024";
const BACKEND: &str = "tlc";
const TRACES_PER_SEED: usize = 100;
const MAX_STEPS: usize = 20;
const COMMON_DIGEST_PATHS: &[&str] = &[
    ".github/workflows/quint.yml",
    "rust-toolchain.toml",
    "verification/quint/apalache.lock.json",
    "verification/quint/bin/install-apalache",
    "verification/quint/bin/process-group",
    "verification/quint/bin/publish-evidence",
    "verification/quint/bin/quint",
    "verification/quint/bin/authority-lock",
    "verification/quint/package.json",
    "verification/quint/pnpm-lock.yaml",
    "verification/quint/run-verification.sh",
    "verification/quint/evidence/cargo-authority.json",
    "verification/quint/src/cargo_authority.rs",
    "verification/quint/src/evidence.rs",
    "verification/quint/src/lib.rs",
    "verification/quint/src/main.rs",
    "verification/quint/src/model.rs",
    "verification/quint/src/process.rs",
];

/// Strict, versioned evidence document shared by every model.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    /// Evidence schema version.
    pub schema_version: u32,
    /// Bound model name.
    pub model: String,
    /// Quint source path.
    pub spec: String,
    /// Quint module passed to the checker.
    pub main: String,
    /// Bounded checker configuration path.
    pub config: String,
    /// Exact source mutation manifest path.
    pub mutation_manifest: String,
    /// Exact checker and bridge tool metadata.
    pub tools: ToolEvidence,
    /// Canonical finite checker bounds.
    pub bounds: BTreeMap<String, String>,
    /// Sorted repository-relative inputs bound by SHA-256.
    pub bound_inputs: Vec<String>,
    /// SHA-256 digests keyed by repository-relative input path.
    pub digests: BTreeMap<String, String>,
    /// Safety property names checked by the baseline.
    pub invariants: Vec<String>,
    /// Temporal property names checked by the baseline.
    pub temporal_properties: Vec<String>,
    /// Exact ordered mutation results.
    pub mutations: Vec<MutationEvidence>,
    /// Deterministic Quint scenario names.
    pub scenarios: Vec<String>,
    /// Modeled action coverage set.
    pub actions: Vec<String>,
    /// Production-derived fields with independent negative conformance checks.
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
    /// Pinned Apalache distribution version used by Quint's translator.
    pub apalache: String,
    /// Official release URL installed before verification.
    pub apalache_archive_url: String,
    /// SHA-256 of the reviewed release archive.
    pub apalache_archive_sha256: String,
    /// SHA-256 of the launcher that starts the translation server.
    pub apalache_launcher_sha256: String,
    /// SHA-256 of the exact Apalache JAR used for translation and TLC.
    pub apalache_jar_sha256: String,
    /// TLC version bundled by the pinned Quint translator path.
    pub tlc: String,
    /// Selected verification backend.
    pub backend: String,
}

/// Stable mutation result without nondeterministic paths or timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationEvidence {
    /// Stable tool-neutral mutation identifier.
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

/// Builds deterministic evidence after every declared mutation has been killed.
pub fn build_evidence(
    repository_root: &Path,
    descriptor: &'static ModelDescriptor,
    mutation_results: &[MutationResult],
) -> Result<Evidence, String> {
    validate_apalache_distribution()?;
    let manifest = read_manifest(repository_root, descriptor)?;
    let mutations = normalize_mutations(&manifest, mutation_results)?;
    let bound_inputs = expected_bound_inputs(descriptor);
    let evidence = Evidence {
        schema_version: 3,
        model: descriptor.name.to_owned(),
        spec: descriptor.spec.to_owned(),
        main: descriptor.main.to_owned(),
        config: descriptor.config.to_owned(),
        mutation_manifest: descriptor.mutation_manifest.to_owned(),
        tools: expected_tools(),
        bounds: expected_bounds(descriptor)?,
        digests: compute_digests(repository_root, &bound_inputs)?,
        bound_inputs,
        invariants: expected_properties(descriptor, PropertyKind::Invariant),
        temporal_properties: expected_properties(descriptor, PropertyKind::Temporal),
        mutations,
        scenarios: strings(descriptor.scenarios),
        actions: strings(descriptor.actions),
        projection_fields: strings(descriptor.projection_fields),
        simulation: expected_simulation(),
    };
    validate_semantics(&evidence, descriptor, Some(repository_root))?;
    Ok(evidence)
}

/// Writes stable, newline-terminated evidence JSON.
pub fn write_evidence(
    repository_root: &Path,
    path: &Path,
    descriptor: &'static ModelDescriptor,
    mutation_results: &[MutationResult],
) -> Result<(), String> {
    let evidence = build_evidence(repository_root, descriptor, mutation_results)?;
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

/// Parses strict evidence and optionally validates its repository-bound contract.
pub fn validate_evidence_json(
    json: &str,
    descriptor: &'static ModelDescriptor,
    repository_root: Option<&Path>,
) -> Result<Evidence, String> {
    let evidence: Evidence =
        serde_json::from_str(json).map_err(|error| format!("invalid evidence JSON: {error}"))?;
    validate_semantics(&evidence, descriptor, repository_root)?;
    Ok(evidence)
}

/// Validates a checked-in evidence file against current repository inputs.
pub fn validate_evidence_file(
    repository_root: &Path,
    path: &Path,
    descriptor: &'static ModelDescriptor,
) -> Result<Evidence, String> {
    let json = fs::read_to_string(path)
        .map_err(|error| format!("cannot read evidence {}: {error}", path.display()))?;
    validate_evidence_json(&json, descriptor, Some(repository_root))
}

fn validate_semantics(
    evidence: &Evidence,
    descriptor: &'static ModelDescriptor,
    repository_root: Option<&Path>,
) -> Result<(), String> {
    if evidence.schema_version != 3
        || evidence.model != descriptor.name
        || evidence.spec != descriptor.spec
        || evidence.main != descriptor.main
        || evidence.config != descriptor.config
        || evidence.mutation_manifest != descriptor.mutation_manifest
    {
        return Err("unsupported evidence identity".to_owned());
    }
    if evidence.tools != expected_tools() {
        return Err("tool metadata mismatch".to_owned());
    }

    let bound_inputs = expected_bound_inputs(descriptor);
    if evidence.bound_inputs != bound_inputs {
        return Err(format!(
            "evidence bound inputs mismatch: expected {bound_inputs:?}, found {:?}",
            evidence.bound_inputs
        ));
    }
    let coverage_matches = [
        (evidence.bounds == expected_bounds(descriptor)?, "bounds"),
        (
            evidence.digests.keys().eq(bound_inputs.iter()),
            "digest paths",
        ),
        (
            evidence.invariants == expected_properties(descriptor, PropertyKind::Invariant),
            "invariants",
        ),
        (
            evidence.temporal_properties == expected_properties(descriptor, PropertyKind::Temporal),
            "temporal properties",
        ),
        (
            evidence.scenarios == strings(descriptor.scenarios),
            "scenarios",
        ),
        (evidence.actions == strings(descriptor.actions), "actions"),
        (
            evidence.projection_fields == strings(descriptor.projection_fields),
            "projection fields",
        ),
        (evidence.simulation == expected_simulation(), "simulation"),
    ];
    if let Some((_, field)) = coverage_matches.iter().find(|(matches, _)| !matches) {
        return Err(format!("evidence {field} mismatch"));
    }

    validate_killed_mutations(&evidence.mutations)?;
    if let Some(root) = repository_root {
        let manifest = read_manifest(root, descriptor)?;
        validate_manifest_results(&manifest, &evidence.mutations)?;
        let expected_digests = compute_digests(root, &bound_inputs)?;
        for (path, digest) in expected_digests {
            match evidence.digests.get(&path) {
                Some(actual) if actual == &digest => {}
                _ => {
                    return Err(format!(
                        "digest mismatch for {path}; run verification/quint/run-verification.sh --refresh"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn read_manifest(
    repository_root: &Path,
    descriptor: &'static ModelDescriptor,
) -> Result<MutationManifest, String> {
    let path = repository_root
        .join("verification/quint")
        .join(descriptor.mutation_manifest);
    let json = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read mutation manifest {}: {error}", path.display()))?;
    MutationManifest::parse(&json, descriptor)
        .map_err(|error| format!("invalid mutation manifest {}: {error}", path.display()))
}

fn validate_manifest_results(
    manifest: &MutationManifest,
    results: &[MutationEvidence],
) -> Result<(), String> {
    if manifest.mutations.len() != results.len() {
        return Err("mutation evidence count mismatch".to_owned());
    }
    for (mutation, result) in manifest.mutations.iter().zip(results) {
        if mutation.id != result.id || mutation.property != result.property {
            return Err(format!("mutation evidence mismatch for {}", mutation.id));
        }
    }
    Ok(())
}

fn validate_killed_mutations(mutations: &[MutationEvidence]) -> Result<(), String> {
    if mutations.is_empty() {
        return Err("mutation evidence must not be empty".to_owned());
    }
    let mut ids = BTreeSet::new();
    for mutation in mutations {
        if !ids.insert(&mutation.id) {
            return Err(format!("duplicate mutation evidence {}", mutation.id));
        }
        if !mutation.outcome.is_killed() {
            return Err(format!("mutation {} is not killed", mutation.id));
        }
        if mutation.diagnostic != stable_diagnostic(mutation.outcome) {
            return Err(format!("invalid mutation diagnostic for {}", mutation.id));
        }
    }
    Ok(())
}

fn normalize_mutations(
    manifest: &MutationManifest,
    results: &[MutationResult],
) -> Result<Vec<MutationEvidence>, String> {
    let normalized = results
        .iter()
        .map(|result| MutationEvidence {
            id: result.id.clone(),
            property: result.property.clone(),
            outcome: result.outcome,
            diagnostic: stable_diagnostic(result.outcome).to_owned(),
        })
        .collect::<Vec<_>>();
    validate_killed_mutations(&normalized)?;
    validate_manifest_results(manifest, &normalized)?;
    Ok(normalized)
}

fn expected_bound_inputs(descriptor: &ModelDescriptor) -> Vec<String> {
    let mut inputs = COMMON_DIGEST_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    for relative in [
        descriptor.spec,
        descriptor.config,
        descriptor.mutation_manifest,
    ] {
        inputs.insert(format!("verification/quint/{relative}"));
    }
    inputs.extend(
        [descriptor.driver, descriptor.connect_test]
            .into_iter()
            .chain(descriptor.production_sources.iter().copied())
            .chain(descriptor.additional_evidence_inputs.iter().copied())
            .map(str::to_owned),
    );
    inputs.into_iter().collect()
}

fn expected_bounds(descriptor: &ModelDescriptor) -> Result<BTreeMap<String, String>, String> {
    let bounds = descriptor
        .bounds
        .iter()
        .map(|bound| (bound.name.to_owned(), bound.value.to_owned()))
        .collect::<BTreeMap<_, _>>();
    if bounds.len() != descriptor.bounds.len() || bounds.is_empty() {
        return Err(format!(
            "invalid bounds for Quint model {}",
            descriptor.name
        ));
    }
    Ok(bounds)
}

fn expected_properties(descriptor: &ModelDescriptor, kind: PropertyKind) -> Vec<String> {
    descriptor
        .properties
        .iter()
        .filter(|property| property.kind == kind)
        .map(|property| property.name.to_owned())
        .collect()
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
        apalache: APALACHE_VERSION.to_owned(),
        apalache_archive_url: APALACHE_ARCHIVE_URL.to_owned(),
        apalache_archive_sha256: APALACHE_ARCHIVE_SHA256.to_owned(),
        apalache_launcher_sha256: APALACHE_LAUNCHER_SHA256.to_owned(),
        apalache_jar_sha256: APALACHE_JAR_SHA256.to_owned(),
        tlc: TLC_VERSION.to_owned(),
        backend: BACKEND.to_owned(),
    }
}

fn expected_simulation() -> SimulationEvidence {
    SimulationEvidence {
        seeds: strings(&GENERATED_TRACE_SEEDS),
        traces_per_seed: TRACES_PER_SEED,
        max_steps: MAX_STEPS,
    }
}

fn compute_digests(
    repository_root: &Path,
    relative_paths: &[String],
) -> Result<BTreeMap<String, String>, String> {
    relative_paths
        .iter()
        .map(|relative| {
            let path = repository_root.join(relative);
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read bound input {}: {error}", path.display()))?;
            Ok((relative.clone(), format!("{:x}", Sha256::digest(bytes))))
        })
        .collect()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
