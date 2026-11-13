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
            digests.values().any(|digest| {
                matches!(
                    digest.get("kind").and_then(|v| v.as_str()),
                    Some("yaml-workflow" | "rust-semantic")
                )
            })
        })
    {
        return Err(format!(
            "obsolete digest kind; regenerate {}",
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

/// Derives the complete inventory of inputs required for a model.
pub fn expected_bound_inputs(
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
    let explicit_inputs = inputs.clone();
    inputs.extend(source_closure::production_inputs(
        repository_root,
        descriptor.production_sources,
        &authority,
    )?);
    // Directory exclusions use package roots, not arbitrary directories named "tests" in src.
    inputs.retain(|input| {
        !authority
            .packages
            .iter()
            .filter_map(|package| package.manifest.as_deref())
            .filter_map(|manifest| Path::new(manifest).parent())
            .any(|directory| {
                ["tests", "benches", "examples"]
                    .iter()
                    .any(|name| Path::new(input).starts_with(directory.join(name)))
            })
    });

    // Tokenize only to prove file-level exclusions. Digests still cover every byte of bound files.
    // Unknown syntax and alternate references retain files; literals and comments cannot supply cfg.
    let mut sources = BTreeMap::new();
    let mut unparsed = BTreeSet::new();
    for input in &inputs {
        if input.strip_suffix(".rs").is_some() || has_extension(input, "rs") {
            source_closure::checked_path(repository_root, input, false)?;
            let bytes = fs::read(repository_root.join(input))
                .map_err(|error| format!("cannot read source inventory {input}: {error}"))?;
            let Ok(source) = String::from_utf8(bytes) else {
                unparsed.insert(input.as_str());
                continue;
            };
            sources.insert(input.as_str(), source);
        }
    }
    let mut syntax = BTreeMap::new();
    for (&path, source) in &sources {
        if let Some(tokens) = tokenize_source(source) {
            syntax.insert(path, tokens);
        } else {
            unparsed.insert(path);
        }
    }
    let mut candidates = test_module_candidates(&syntax, &authority, &inputs, &explicit_inputs);
    if !retain_referenced_candidates(&syntax, &unparsed, &mut candidates) {
        return Ok(inputs.iter().cloned().collect());
    }
    let excluded: BTreeSet<_> = candidates.into_keys().collect();
    Ok(inputs
        .into_iter()
        .filter(|input| !excluded.contains(input))
        .collect())
}

fn tokenize_source(source: &str) -> Option<Vec<(usize, &str)>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            let mut depth = 1;
            i += 2;
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
                return None;
            }
            continue;
        }
        let raw_prefix = if bytes[i..].starts_with(b"br") || bytes[i..].starts_with(b"cr") {
            2
        } else {
            usize::from(bytes[i] == b'r')
        };
        let mut raw_quote = i + raw_prefix;
        if raw_prefix != 0 {
            while raw_quote < bytes.len() && bytes[raw_quote] == b'#' {
                raw_quote += 1;
            }
        }
        if raw_prefix != 0 && bytes.get(raw_quote) == Some(&b'"') {
            let terminator = format!("\"{}", "#".repeat(raw_quote - i - raw_prefix));
            let end = source[raw_quote + 1..].find(&terminator)?;
            i = raw_quote + 1 + end + terminator.len();
        } else if bytes[i] == b'"'
            || (bytes[i] == b'\''
                && (bytes.get(i + 1) == Some(&b'\\')
                    || source[i + 1..]
                        .chars()
                        .next()
                        .is_some_and(|ch| bytes.get(i + 1 + ch.len_utf8()) == Some(&b'\''))))
        {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i >= bytes.len() {
                return None;
            }
            i += 1;
        } else if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] >= 128 {
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] >= 128)
            {
                i += 1;
            }
        } else {
            i += 1;
        }
        tokens.push((start, &source[start..i]));
    }
    Some(tokens)
}

type TestModuleCandidates<'a> = BTreeMap<String, (String, BTreeSet<(&'a str, usize)>)>;

fn test_module_candidates<'a>(
    syntax: &BTreeMap<&'a str, Vec<(usize, &'a str)>>,
    authority: &CargoAuthority,
    inputs: &BTreeSet<String>,
    explicit_inputs: &BTreeSet<String>,
) -> TestModuleCandidates<'a> {
    let mut candidates: TestModuleCandidates<'_> = BTreeMap::new();
    // Discover descendants until every cfg(test)-only file has propagated to its children.
    loop {
        let previous_count = candidates.len();
        for (&parent, tokens) in syntax {
            collect_test_module_candidates(
                parent,
                tokens,
                authority,
                inputs,
                explicit_inputs,
                &mut candidates,
            );
        }
        if candidates.len() == previous_count {
            return candidates;
        }
    }
}

fn collect_test_module_candidates<'a>(
    parent: &'a str,
    tokens: &[(usize, &'a str)],
    authority: &CargoAuthority,
    inputs: &BTreeSet<String>,
    explicit_inputs: &BTreeSet<String>,
    candidates: &mut TestModuleCandidates<'a>,
) {
    let path = Path::new(parent);
    if !authority
        .packages
        .iter()
        .filter_map(|package| package.manifest.as_deref())
        .filter_map(|manifest| Path::new(manifest).parent())
        .any(|directory| path.starts_with(directory.join("src")))
    {
        return;
    }
    let inherited = candidates.contains_key(parent);
    let directory = if matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("lib.rs" | "main.rs" | "mod.rs")
    ) {
        path.parent().expect("source parent").to_path_buf()
    } else {
        path.with_extension("")
    };
    let mut scopes = vec![(0usize, directory, false)];
    let mut depth = 0usize;
    for (index, &(_, token)) in tokens.iter().enumerate() {
        if matches!(token, "{" | "(" | "[") {
            depth += 1;
            continue;
        }
        if matches!(token, "}" | ")" | "]") {
            depth = depth.saturating_sub(1);
            while scopes.len() > 1 && scopes.last().unwrap().0 > depth {
                scopes.pop();
            }
            continue;
        }
        let (scope_depth, directory, scope_test_only) = scopes.last().unwrap();
        if depth != *scope_depth || token != "mod" {
            continue;
        }
        let Some(&(name_offset, name)) = tokens.get(index + 1) else {
            continue;
        };
        let delimiter = tokens.get(index + 2).map(|(_, token)| *token);
        if !matches!(delimiter, Some(";" | "{")) {
            continue;
        }
        let (start, test_only, redirected) = module_attributes(tokens, index, *scope_test_only);
        if redirected || (start > 0 && !matches!(tokens[start - 1].1, ";" | "{" | "}")) {
            continue;
        }
        if delimiter == Some("{") {
            scopes.push((depth + 1, directory.join(name), test_only));
            continue;
        }
        if !test_only && !inherited {
            continue;
        }
        let alternatives = [
            directory.join(format!("{name}.rs")),
            directory.join(name).join("mod.rs"),
        ];
        let present: Vec<_> = alternatives
            .iter()
            .filter_map(|path| path.to_str())
            .filter(|path| inputs.contains(*path))
            .collect();
        if present.len() != 1 || explicit_inputs.contains(present[0]) {
            continue;
        }
        let declarations = &mut candidates
            .entry(present[0].to_owned())
            .or_insert_with(|| (name.to_owned(), BTreeSet::new()))
            .1;
        // Inherited declarations are valid only while their parent remains excluded.
        // If a reference retains the parent, the retention pass must also retain its children.
        if test_only {
            declarations.insert((parent, name_offset));
        }
    }
}

fn module_attributes(
    tokens: &[(usize, &str)],
    index: usize,
    scope_test_only: bool,
) -> (usize, bool, bool) {
    let mut start = index;
    if start > 0 && tokens[start - 1].1 == "pub" {
        start -= 1;
    } else if start >= 4
        && tokens[start - 4].1 == "pub"
        && tokens[start - 3].1 == "("
        && matches!(tokens[start - 2].1, "crate" | "super" | "self")
        && tokens[start - 1].1 == ")"
    {
        start -= 4;
    }
    let mut test_only = scope_test_only;
    let mut redirected = false;
    while start > 0 && tokens[start - 1].1 == "]" {
        let end = start;
        let mut brackets = 1usize;
        start -= 1;
        while start > 0 && brackets > 0 {
            start -= 1;
            match tokens[start].1 {
                "]" => brackets += 1,
                "[" => brackets -= 1,
                _ => {}
            }
        }
        if brackets != 0 || start == 0 || tokens[start - 1].1 != "#" {
            redirected = true;
            break;
        }
        start -= 1;
        test_only |= tokens[start..end]
            .iter()
            .map(|(_, token)| *token)
            .eq(["#", "[", "cfg", "(", "test", ")", "]"]);
        redirected |= tokens[start..end].iter().any(|(_, token)| *token == "path");
    }
    (start, test_only, redirected)
}

fn retain_referenced_candidates(
    syntax: &BTreeMap<&str, Vec<(usize, &str)>>,
    unparsed: &BTreeSet<&str>,
    candidates: &mut TestModuleCandidates<'_>,
) -> bool {
    // Iterate because a retained candidate can itself refer to another candidate.
    loop {
        let mut retained = BTreeSet::new();
        if unparsed.iter().any(|path| !candidates.contains_key(*path)) {
            return false;
        }
        for (&parent, tokens) in syntax {
            if candidates.contains_key(parent) {
                continue;
            }
            let parent_path = Path::new(parent);
            let module_directory = if matches!(
                parent_path.file_name().and_then(|name| name.to_str()),
                Some("lib.rs" | "main.rs" | "mod.rs")
            ) {
                parent_path.parent().expect("source parent").to_path_buf()
            } else {
                parent_path.with_extension("")
            };
            for (index, &(offset, token)) in tokens.iter().enumerate() {
                // Only literal includes and the repository's fixed manifest-relative concat form
                // have an inspectable destination. Any computed destination keeps all candidates.
                if matches!(token, "include" | "include_str" | "include_bytes")
                    && tokens.get(index + 1).map(|(_, token)| *token) == Some("!")
                {
                    let tail: Vec<_> = tokens[index + 2..]
                        .iter()
                        .take(13)
                        .map(|(_, token)| *token)
                        .collect();
                    let literal = match tail.as_slice() {
                        ["(", literal, ")", ..] => Some(*literal),
                        ["(", "concat", "!", "(", "env", "!", "(", "\"CARGO_MANIFEST_DIR\"", ")", ",", literal, ")", ")"] => {
                            Some(*literal)
                        }
                        _ => None,
                    };
                    if !literal.is_some_and(|literal| {
                        literal.starts_with('"')
                            && literal.ends_with('"')
                            && !literal.contains('\\')
                    }) {
                        retained.extend(candidates.keys().cloned());
                    }
                }
                if token == "path"
                    && index > 0
                    && matches!(tokens[index - 1].1, "[" | ",")
                    && tokens.get(index + 1).map(|(_, token)| *token) == Some("=")
                    && tokens.get(index + 2).map(|(_, token)| *token) != Some(">")
                    && !tokens.get(index + 2).is_some_and(|(_, literal)| {
                        literal.starts_with('"')
                            && literal.ends_with('"')
                            && !literal.contains('\\')
                    })
                {
                    retained.extend(candidates.keys().cloned());
                }
                for (candidate, (name, declarations)) in candidates.iter() {
                    if (token == name
                        && Path::new(candidate).starts_with(&module_directory)
                        && !declarations.contains(&(parent, offset))
                        && !(index > 0
                            && tokens[index - 1].1 == "mod"
                            && tokens.get(index + 1).map(|(_, token)| *token) == Some("{")))
                        || (token.contains('"')
                            && (token.contains(&format!("{name}.rs"))
                                || token.contains(&format!("{name}/"))))
                    {
                        retained.insert(candidate.clone());
                    }
                }
            }
        }
        if retained.is_empty() {
            break;
        }
        for path in retained {
            candidates.remove(&path);
        }
    }
    true
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

/// Computes the current digest of one bound input with the same path checks as validation.
pub fn current_input_digest(repository_root: &Path, relative: &str) -> Result<InputDigest, String> {
    let mut digests = compute_digests(repository_root, &[relative.to_owned()], None)?;
    digests
        .remove(relative)
        .ok_or_else(|| format!("missing digest for {relative}"))
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
            for key in ["description", "title", "$comment", "markdownDescription"] {
                if map.get(key).is_some_and(serde_json::Value::is_string) {
                    map.remove(key);
                }
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
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        if serde::de::DeserializeSeed::deserialize(NoDuplicateKeys, &mut deserializer).is_err() {
            return Ok(InputDigest {
                kind: "sha256".to_owned(),
                value: format!("{:x}", Sha256::digest(bytes)),
            });
        }
        if path.ends_with(".schema.json") {
            strip(&mut value);
        }
        (
            "json-semantic",
            serde_json::to_vec(&sorted(value)).map_err(|error| error.to_string())?,
        )
    } else {
        ("sha256", bytes.to_vec())
    };
    Ok(InputDigest {
        kind: kind.to_owned(),
        value: format!("{:x}", Sha256::digest(normalized)),
    })
}

struct NoDuplicateKeys;

impl<'de> serde::de::DeserializeSeed<'de> for NoDuplicateKeys {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
                Ok(())
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
                Ok(())
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
                Ok(())
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
                Ok(())
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
                Ok(())
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
                Ok(())
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
                while seq.next_element_seed(NoDuplicateKeys)?.is_some() {}
                Ok(())
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(serde::de::Error::custom("duplicate object key"));
                    }
                    map.next_value_seed(NoDuplicateKeys)?;
                }
                Ok(())
            }
        }
        deserializer.deserialize_any(Visitor)
    }
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

        assert_ne!(json(r#"{"title":"valid"}"#), json(r#"{"title":false}"#));
        for key in ["description", "title", "$comment", "markdownDescription"] {
            assert_ne!(json("{}"), json(&format!(r#"{{"{key}":false}}"#)));
            assert_eq!(json("{}"), json(&format!(r#"{{"{key}":"text"}}"#)));
        }
        assert_ne!(json(r#"{"examples":[]}"#), json("{}"));
        assert_ne!(json(r#"{"examples":[]}"#), json(r#"{"examples":false}"#));
        let single = br#"{"schemaVersion":1}"#;
        let duplicate = br#"{"schemaVersion":1,"schemaVersion":1}"#;
        assert_ne!(
            input_digest("mutation.json", single).unwrap(),
            input_digest("mutation.json", duplicate).unwrap()
        );
        assert_eq!(
            input_digest("mutation.json", duplicate).unwrap().kind,
            "sha256"
        );
        assert_eq!(
            input_digest("mutation.json", br#"{"nested":{"x":1,"x":1}}"#)
                .unwrap()
                .kind,
            "sha256"
        );
        assert_eq!(
            input_digest("source.rs", b"// comment").unwrap().kind,
            "sha256"
        );
        let rust = |text: &str| input_digest("source.rs", text.as_bytes()).unwrap();
        let suffix = r#"const S: &str = stringify!(r""r"\"//before");"#;
        assert_ne!(rust(suffix), rust(&suffix.replace("before", "after")));
        assert_ne!(rust("fn main() {}"), rust("fn main() {} // \u{202e}"));
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
        let obsolete_rust = r#"{"digests":{"source.rs":{"kind":"rust-semantic","value":"abc"}}}"#;
        assert!(parse_evidence(obsolete_rust, descriptor)
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
