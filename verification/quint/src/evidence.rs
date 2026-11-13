//! Deterministic, model-neutral evidence for the Quint verification authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod source_closure;

use crate::cargo_authority::CargoAuthority;
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
const CARGO_AUTHORITY_INPUT: &str = "verification/quint/evidence/cargo-authority.json";
const COMMON_DIGEST_PATHS: &[&str] = &[
    ".github/workflows/quint.yml",
    "rust-toolchain.toml",
    "verification/quint/apalache.lock.json",
    "verification/quint/bin/install-apalache",
    "verification/quint/bin/process-group",
    "verification/quint/bin/quint",
    "verification/quint/java/io/fireemu/verification/LoopbackServerProviderAgent.java",
    "verification/quint/package.json",
    "verification/quint/pnpm-lock.yaml",
    "verification/quint/run-verification.sh",
    CARGO_AUTHORITY_INPUT,
    "verification/quint/src/cargo_authority.rs",
    "verification/quint/src/evidence.rs",
    "verification/quint/src/evidence/source_closure.rs",
    "verification/quint/src/lib.rs",
    "verification/quint/src/main.rs",
    "verification/quint/src/model.rs",
    "verification/quint/src/process.rs",
    "verification/quint/src/publication.rs",
    "verification/quint/src/server.rs",
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
    pub digests: BTreeMap<String, InputDigest>,
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

/// Digest algorithm and value for one bound input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputDigest {
    /// Canonicalization applied before SHA-256.
    pub kind: String,
    /// Lowercase hexadecimal SHA-256.
    pub value: String,
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
    build_evidence_with_cargo_authority(repository_root, descriptor, mutation_results, None)
}

fn build_evidence_with_cargo_authority(
    repository_root: &Path,
    descriptor: &'static ModelDescriptor,
    mutation_results: &[MutationResult],
    cargo_authority: Option<&Path>,
) -> Result<Evidence, String> {
    validate_apalache_distribution()?;
    let manifest = read_manifest(repository_root, descriptor)?;
    let mutations = normalize_mutations(&manifest, mutation_results)?;
    let bound_inputs = expected_bound_inputs(repository_root, descriptor, cargo_authority)?;
    let evidence = Evidence {
        schema_version: 3,
        model: descriptor.name.to_owned(),
        spec: descriptor.spec.to_owned(),
        main: descriptor.main.to_owned(),
        config: descriptor.config.to_owned(),
        mutation_manifest: descriptor.mutation_manifest.to_owned(),
        tools: expected_tools(),
        bounds: expected_bounds(descriptor)?,
        digests: compute_digests(repository_root, &bound_inputs, cargo_authority)?,
        bound_inputs,
        invariants: expected_properties(descriptor, PropertyKind::Invariant),
        temporal_properties: expected_properties(descriptor, PropertyKind::Temporal),
        mutations,
        scenarios: strings(descriptor.scenarios),
        actions: strings(descriptor.actions),
        projection_fields: strings(descriptor.projection_fields),
        simulation: expected_simulation(),
    };
    validate_semantics(
        &evidence,
        descriptor,
        Some(repository_root),
        cargo_authority,
    )?;
    Ok(evidence)
}

/// Writes stable, newline-terminated evidence JSON.
pub fn write_evidence(
    repository_root: &Path,
    path: &Path,
    descriptor: &'static ModelDescriptor,
    mutation_results: &[MutationResult],
    cargo_authority: Option<&Path>,
) -> Result<(), String> {
    let evidence = build_evidence_with_cargo_authority(
        repository_root,
        descriptor,
        mutation_results,
        cargo_authority,
    )?;
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

/// Parses strict evidence and validates its repository-bound contract.
///
/// A repository root is required because semantic source inventories cannot be
/// reconstructed from an evidence document alone.
pub fn validate_evidence_json(
    json: &str,
    descriptor: &'static ModelDescriptor,
    repository_root: Option<&Path>,
) -> Result<Evidence, String> {
    let evidence = parse_evidence(json, descriptor)?;
    validate_semantics(&evidence, descriptor, repository_root, None)?;
    Ok(evidence)
}

/// Validates a checked-in evidence file against current repository inputs.
pub fn validate_evidence_file(
    repository_root: &Path,
    path: &Path,
    descriptor: &'static ModelDescriptor,
) -> Result<Evidence, String> {
    validate_evidence_file_with_cargo_authority(repository_root, path, descriptor, None)
}

/// Validates an evidence file using an explicit staged Cargo authority input.
pub fn validate_evidence_file_with_cargo_authority(
    repository_root: &Path,
    path: &Path,
    descriptor: &'static ModelDescriptor,
    cargo_authority: Option<&Path>,
) -> Result<Evidence, String> {
    let json = fs::read_to_string(path)
        .map_err(|error| format!("cannot read evidence {}: {error}", path.display()))?;
    let evidence = parse_evidence(&json, descriptor)?;
    validate_semantics(
        &evidence,
        descriptor,
        Some(repository_root),
        cargo_authority,
    )?;
    Ok(evidence)
}

fn parse_evidence(json: &str, descriptor: &ModelDescriptor) -> Result<Evidence, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|error| format!("invalid evidence JSON: {error}"))?;
    if value
        .get("digests")
        .and_then(|value| value.as_object())
        .is_some_and(|digests| digests.values().any(|digest| digest.get("kind").is_none()))
    {
        return Err(format!(
            "evidence digest kind missing; regenerate {}",
            descriptor.name
        ));
    }
    if value
        .get("digests")
        .and_then(|v| v.as_object())
        .is_some_and(|digests| {
            digests
                .values()
                .any(|digest| digest.get("kind").and_then(|v| v.as_str()) == Some("yaml-workflow"))
        })
    {
        return Err(format!(
            "obsolete workflow digest kind; regenerate {}",
            descriptor.name
        ));
    }
    serde_json::from_value(value).map_err(|error| format!("invalid evidence JSON: {error}"))
}

fn validate_semantics(
    evidence: &Evidence,
    descriptor: &'static ModelDescriptor,
    repository_root: Option<&Path>,
    cargo_authority: Option<&Path>,
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

    let root = repository_root.ok_or_else(|| {
        "repository root is required to validate semantic source closure".to_owned()
    })?;
    let bound_inputs = expected_bound_inputs(root, descriptor, cargo_authority)?;
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
        let expected_digests = compute_digests(root, &bound_inputs, cargo_authority)?;
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

fn expected_bound_inputs(
    repository_root: &Path,
    descriptor: &ModelDescriptor,
    cargo_authority: Option<&Path>,
) -> Result<Vec<String>, String> {
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
    let authority_path = cargo_authority.map_or_else(
        || repository_root.join(CARGO_AUTHORITY_INPUT),
        Path::to_path_buf,
    );
    let authority: CargoAuthority = serde_json::from_slice(
        &fs::read(&authority_path)
            .map_err(|error| format!("cannot read source closure Cargo authority: {error}"))?,
    )
    .map_err(|error| format!("invalid source closure Cargo authority: {error}"))?;
    inputs.extend(source_closure::production_inputs(
        repository_root,
        descriptor.production_sources,
        &authority,
    )?);
    Ok(inputs.into_iter().collect())
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
    cargo_authority: Option<&Path>,
) -> Result<BTreeMap<String, InputDigest>, String> {
    relative_paths
        .iter()
        .map(|relative| {
            let path = if relative == CARGO_AUTHORITY_INPUT {
                cargo_authority.map_or_else(|| repository_root.join(relative), Path::to_path_buf)
            } else {
                repository_root.join(relative)
            };
            if relative != CARGO_AUTHORITY_INPUT || cargo_authority.is_none() {
                source_closure::checked_path(repository_root, relative, false)?;
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                format!("cannot inspect bound input {}: {error}", path.display())
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "bound input is not a regular file: {}",
                    path.display()
                ));
            }
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read bound input {}: {error}", path.display()))?;
            Ok((relative.clone(), input_digest(relative, &bytes)?))
        })
        .collect()
}

/// Whether `path` has the given extension, compared without regard to ASCII case.
fn has_extension(path: &str, extension: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .is_some_and(|found| found.eq_ignore_ascii_case(extension))
}

/// Computes the digest used to bind an input to evidence.
pub fn input_digest(path: &str, bytes: &[u8]) -> Result<InputDigest, String> {
    let (kind, normalized) = if has_extension(path, "json") {
        fn strip(value: &mut serde_json::Value) {
            let Some(map) = value.as_object_mut() else {
                return;
            };
            for key in [
                "description",
                "title",
                "examples",
                "$comment",
                "markdownDescription",
            ] {
                map.remove(key);
            }
            for key in [
                "properties",
                "patternProperties",
                "$defs",
                "definitions",
                "dependentSchemas",
            ] {
                if let Some(entries) = map.get_mut(key).and_then(|v| v.as_object_mut()) {
                    for schema in entries.values_mut() {
                        strip(schema);
                    }
                }
            }
            for key in [
                "additionalProperties",
                "unevaluatedProperties",
                "propertyNames",
                "items",
                "contains",
                "unevaluatedItems",
                "not",
                "if",
                "then",
                "else",
                "contentSchema",
                "additionalItems",
            ] {
                if let Some(schema) = map.get_mut(key) {
                    strip(schema);
                }
            }
            for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
                if let Some(schemas) = map.get_mut(key).and_then(|v| v.as_array_mut()) {
                    for schema in schemas {
                        strip(schema);
                    }
                }
            }
        }
        // Sort explicitly even if serde_json is built with preserve_order enabled.
        fn sorted(value: serde_json::Value) -> serde_json::Value {
            match value {
                serde_json::Value::Object(map) => {
                    let entries: BTreeMap<_, _> =
                        map.into_iter().map(|(k, v)| (k, sorted(v))).collect();
                    serde_json::Value::Object(entries.into_iter().collect())
                }
                serde_json::Value::Array(values) => {
                    serde_json::Value::Array(values.into_iter().map(sorted).collect())
                }
                other => other,
            }
        }
        let mut value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid JSON bound input {path}: {error}"))?;
        if path.ends_with(".schema.json") {
            strip(&mut value);
        }
        (
            "json-semantic",
            serde_json::to_vec(&sorted(value)).map_err(|error| error.to_string())?,
        )
    } else if has_extension(path, "rs") {
        ("rust-semantic", normalize_rust(bytes)?)
    } else {
        ("sha256", bytes.to_vec())
    };
    Ok(InputDigest {
        kind: kind.to_owned(),
        value: format!("{:x}", Sha256::digest(normalized)),
    })
}

#[allow(clippy::too_many_lines)]
fn normalize_rust(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut space = false;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            space = true;
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"//") {
            let doc = (bytes[i..].starts_with(b"///") && !bytes[i..].starts_with(b"////"))
                || bytes[i..].starts_with(b"//!");
            let start = i;
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            if doc {
                if space && !out.is_empty() {
                    out.push(b' ');
                }
                if i < bytes.len() {
                    i += 1;
                }
                out.extend_from_slice(&bytes[start..i]);
                space = false;
            } else {
                space = true;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            let doc = (bytes[i..].starts_with(b"/**") && !bytes[i..].starts_with(b"/***"))
                || bytes[i..].starts_with(b"/*!");
            let start = i;
            i += 2;
            let mut depth = 1usize;
            while i < bytes.len() && depth > 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if depth != 0 {
                return Err("unterminated Rust block comment".to_owned());
            }
            if doc {
                if space && !out.is_empty() {
                    out.push(b' ');
                }
                out.extend_from_slice(&bytes[start..i]);
                space = false;
            } else {
                space = true;
            }
            continue;
        }
        if space && !out.is_empty() {
            out.push(b' ');
        }
        space = false;
        let start = i;
        // Recognize raw strings, including byte and C raw strings.
        let prefix = if bytes[i..].starts_with(b"br") || bytes[i..].starts_with(b"cr") {
            2
        } else {
            usize::from(bytes[i] == b'r')
        };
        if prefix > 0 {
            let mut quote = i + prefix;
            while quote < bytes.len() && bytes[quote] == b'#' {
                quote += 1;
            }
            if quote < bytes.len() && bytes[quote] == b'"' {
                let hashes = quote - i - prefix;
                i = quote + 1;
                loop {
                    if i >= bytes.len() {
                        return Err("unterminated Rust raw string".to_owned());
                    }
                    if bytes[i] == b'"'
                        && i + 1 + hashes <= bytes.len()
                        && bytes[i + 1..i + 1 + hashes].iter().all(|b| *b == b'#')
                    {
                        i += 1 + hashes;
                        break;
                    }
                    i += 1;
                }
                out.extend_from_slice(&bytes[start..i]);
                continue;
            }
        }
        // A quote is a character literal only when a closing quote follows one character or escape.
        let quote = if (matches!(bytes[i], b'b' | b'c') && bytes.get(i + 1) == Some(&b'"'))
            || (bytes[i] == b'b' && bytes.get(i + 1) == Some(&b'\''))
        {
            i + 1
        } else {
            i
        };
        let is_char = bytes[quote] == b'\'' && {
            let mut end = quote + 1;
            if bytes.get(end) == Some(&b'\\') {
                end += 1;
                if bytes.get(end) == Some(&b'u') && bytes.get(end + 1) == Some(&b'{') {
                    end += 2;
                    while end < bytes.len() && bytes[end] != b'}' {
                        end += 1;
                    }
                    end += 1;
                } else if bytes.get(end) == Some(&b'x') {
                    end += 3;
                } else {
                    end += 1;
                }
            } else if end < bytes.len() {
                end += 1;
                while end < bytes.len() && bytes[end] & 0xc0 == 0x80 {
                    end += 1;
                }
            }
            bytes.get(end) == Some(&b'\'')
        };
        if bytes[quote] == b'"' || is_char {
            let delimiter = bytes[quote];
            i = quote + 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == delimiter {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            if bytes.get(i.wrapping_sub(1)) != Some(&delimiter) {
                return Err("unterminated Rust literal".to_owned());
            }
        } else {
            i += 1;
        }
        out.extend_from_slice(&bytes[start..i]);
    }
    Ok(out)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn semantic_digests_ignore_only_the_requested_changes() {
        let json = |text: &str| input_digest("config.schema.json", text.as_bytes()).unwrap();
        let baseline = json(r#"{"type":"object","description":"old","properties":{}}"#);
        assert_eq!(
            baseline,
            json(r#"{"properties":{},"description":"new","type":"object"}"#)
        );
        assert_ne!(
            baseline,
            json(r#"{"type":"object","properties":{"title":{"type":"string"}}}"#)
        );
        for key in ["properties", "patternProperties", "$defs", "definitions"] {
            let empty = format!(r#"{{"{key}":{{}}}}"#);
            let named = format!(r#"{{"{key}":{{"description":{{"type":"string"}}}}}}"#);
            assert_ne!(json(&empty), json(&named));
        }
        assert_ne!(
            input_digest("data.json", br#"{"description":"old"}"#).unwrap(),
            input_digest("data.json", br#"{"description":"new"}"#).unwrap()
        );

        let rust = |text: &str| input_digest("source.rs", text.as_bytes()).unwrap();
        let source =
            r##"let a = r#"// raw"#; let b = b"// byte"; let c = '\''; let d = "// string";"##;
        assert_eq!(
            rust(source),
            rust(&format!("// heading\n{source} // trailing\n"))
        );
        assert_eq!(
            rust("let x = 1; /* outer /* nested */ end */ let y = 2;"),
            rust("let x = 1; let y = 2;")
        );
        assert_ne!(rust(source), rust(&source.replace("// string", "changed")));
        assert_ne!(rust(source), rust(&source.replace("// raw", "changed")));
        assert_ne!(rust(source), rust(&source.replace("// byte", "changed")));
        assert_ne!(rust(source), rust(&source.replace(r"'\''", "'x'")));
        assert_eq!(
            rust("fn f<'a>(x: &'a str) {}"),
            rust("fn f<'a>(x: &'a str) {} // comment")
        );

        for doc in ["/// doc", "//! doc", "/** doc */", "/*! doc */"] {
            assert_ne!(rust("fn f() {}"), rust(&format!("{doc}\nfn f() {{}}")));
        }
        assert_ne!(
            rust("//! module docs\nfn f() {}"),
            rust("//! module docs\n//! ```\n//! assert!(false);\n//! ```\nfn f() {}")
        );
        assert_eq!(
            input_digest(".github/workflows/test.yml", b"x")
                .unwrap()
                .kind,
            "sha256"
        );
    }

    #[test]
    fn legacy_digests_require_regeneration() {
        let descriptor = crate::model::model("EventDelivery").unwrap();
        let legacy = r#"{"digests":{"old.rs":"abc"}}"#;
        let error = parse_evidence(legacy, descriptor).unwrap_err();
        assert!(error.contains("regenerate EventDelivery"), "{error}");
        let obsolete = r#"{"digests":{"workflow.yml":{"kind":"yaml-workflow","value":"abc"}}}"#;
        assert!(parse_evidence(obsolete, descriptor)
            .unwrap_err()
            .contains("regenerate EventDelivery"));
        let missing_kind = r#"{"digests":{"old.rs":{"value":"abc"}}}"#;
        assert!(parse_evidence(missing_kind, descriptor)
            .unwrap_err()
            .contains("regenerate EventDelivery"));
    }

    #[test]
    fn production_roots_bind_previously_omitted_transitive_helpers() {
        for (name, required) in [
            ("SessionEpoch", "crates/fireemu-core-types/src/ids.rs"),
            ("AuthTotp", "crates/fireemu-core-auth/src/sha1.rs"),
            ("AuthTotp", "crates/fireemu-core-types/src/time.rs"),
        ] {
            let descriptor = crate::model::model(name).expect("registered model");
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            assert!(
                expected_bound_inputs(&root, descriptor, None)
                    .expect("closure")
                    .iter()
                    .any(|path| path == required),
                "{name} omits transitive semantic source {required}"
            );
        }
    }

    #[test]
    fn all_model_production_roots_resolve_with_the_current_canonical_graph() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let temporary = tempfile::tempdir().expect("staged authority directory");
        let authority_path = temporary.path().join("cargo-authority.json");
        crate::cargo_authority::write_authority(&root, &authority_path).expect("current graph");
        for descriptor in crate::model::all_models() {
            let inputs = expected_bound_inputs(&root, descriptor, Some(&authority_path))
                .unwrap_or_else(|error| panic!("{} closure failed: {error}", descriptor.name));
            assert!(
                descriptor
                    .production_sources
                    .iter()
                    .all(|source| inputs.iter().any(|path| path == source)),
                "{} omitted an explicit production source",
                descriptor.name
            );
            assert!(
                inputs.iter().any(|path| path.ends_with("/Cargo.toml")),
                "{} omitted owning package manifests",
                descriptor.name
            );
            if descriptor.name == "EventDelivery" {
                assert!(
                    !inputs
                        .iter()
                        .any(|path| path.starts_with("crates/fireemu-core-auth/")),
                    "EventDelivery should not bind unrelated Auth sources"
                );
            }
        }
    }

    #[test]
    fn cargo_authority_digest_can_be_read_from_a_staged_override() {
        let temporary = OwnedTestDirectory::create();
        let live = temporary
            .path
            .join("verification/quint/evidence/cargo-authority.json");
        let staged = temporary.path.join("staged/cargo-authority.json");
        fs::create_dir_all(live.parent().expect("live parent")).expect("create live parent");
        fs::create_dir_all(staged.parent().expect("staged parent")).expect("create staged parent");
        fs::write(&live, b"{\"live\":true}").expect("write live authority");
        fs::write(&staged, b"{\"staged\":true}").expect("write staged authority");

        let digests = compute_digests(
            &temporary.path,
            &["verification/quint/evidence/cargo-authority.json".to_owned()],
            Some(&staged),
        )
        .expect("staged authority must be digestible");

        assert_eq!(
            digests["verification/quint/evidence/cargo-authority.json"],
            input_digest(CARGO_AUTHORITY_INPUT, b"{\"staged\":true}").unwrap()
        );
    }

    struct OwnedTestDirectory {
        path: PathBuf,
    }

    impl OwnedTestDirectory {
        fn create() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock must be after the epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fireemu-quint-evidence-override-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary test directory");
            Self { path }
        }
    }

    impl Drop for OwnedTestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
