//! Contracts and tooling for repository-owned TLA+ verification evidence.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current persisted manifest and evidence schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// A strict list of semantic mutations for one TLA+ module.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationManifest {
    /// Persisted schema version.
    pub schema_version: u32,
    /// TLA+ module name without an extension.
    pub model: String,
    /// Semantic mutations in deterministic execution order.
    pub mutations: Vec<MutationCase>,
}

/// One exact source replacement tied to one property.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationCase {
    /// Stable mutation identifier used by the requirements ledger.
    pub id: String,
    /// Property expected to kill this mutation.
    pub property: String,
    /// Human-readable semantic mutation operator.
    pub operator: String,
    /// Exact source text that must occur once.
    pub from: String,
    /// Replacement source text.
    pub to: String,
}

impl MutationCase {
    /// Applies this mutation only when its source span occurs exactly once.
    pub fn materialize(&self, source: &str) -> Result<String, String> {
        let matches = source.match_indices(&self.from).collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "mutation {} source span must occur exactly once, found {}",
                self.id,
                matches.len()
            ));
        }
        let offset = matches[0].0;
        let mut mutated = String::with_capacity(source.len() - self.from.len() + self.to.len());
        mutated.push_str(&source[..offset]);
        mutated.push_str(&self.to);
        mutated.push_str(&source[offset + self.from.len()..]);
        Ok(mutated)
    }
}

/// Digest-bound results from one complete manifest execution.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationEvidence {
    /// Persisted schema version.
    pub schema_version: u32,
    /// TLA+ module name without an extension.
    pub model: String,
    /// UTC timestamp recorded by the runner.
    pub generated_at: String,
    /// TLC version reported by the pinned tool.
    pub tlc_version: String,
    /// SHA-256 of the original TLA+ module.
    pub module_sha256: String,
    /// SHA-256 of the configuration used by TLC.
    pub config_sha256: String,
    /// SHA-256 of the mutation manifest.
    pub manifest_sha256: String,
    /// SHA-256 of the TLA+ tools JAR.
    pub jar_sha256: String,
    /// Results in manifest order.
    pub results: Vec<MutationResult>,
}

/// Result of executing one semantic mutation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationResult {
    /// Stable mutation identifier.
    pub id: String,
    /// Property expected to detect the semantic defect.
    pub property: String,
    /// Classified execution outcome.
    pub outcome: MutationOutcome,
    /// Bounded diagnostic explaining the classification.
    pub detail: String,
}

/// Exhaustive outcome classification for one mutation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOutcome {
    /// TLC found a safety counterexample.
    KilledSafety,
    /// TLC found a temporal property counterexample.
    KilledTemporal,
    /// TLC completed without detecting the mutation.
    Survived,
    /// Execution exceeded the configured timeout.
    Timeout,
    /// TLC or Java could not execute reliably.
    ToolError,
    /// The mutation was intentionally not executed.
    NotRun,
}

impl MutationOutcome {
    /// Returns true only for genuine TLC counterexamples.
    pub const fn is_killed(self) -> bool {
        matches!(self, Self::KilledSafety | Self::KilledTemporal)
    }
}

/// Parses and validates a mutation manifest.
pub fn parse_manifest(json: &str) -> Result<MutationManifest, String> {
    let manifest: MutationManifest =
        serde_json::from_str(json).map_err(|error| error.to_string())?;
    validate_schema(manifest.schema_version)?;
    validate_tla_identifier("model", &manifest.model)?;
    if manifest.mutations.is_empty() {
        return Err("manifest must contain at least one mutation".to_owned());
    }
    let mut ids = HashSet::new();
    for mutation in &manifest.mutations {
        if !is_mutation_id(&mutation.id) {
            return Err(format!("invalid mutation id {}", mutation.id));
        }
        if !ids.insert(mutation.id.as_str()) {
            return Err(format!("duplicate mutation id {}", mutation.id));
        }
        validate_tla_identifier("property", &mutation.property)?;
        for (field, value) in [
            ("operator", mutation.operator.as_str()),
            ("from", mutation.from.as_str()),
            ("to", mutation.to.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "mutation {} requires non-empty {field}",
                    mutation.id
                ));
            }
        }
    }
    Ok(manifest)
}

/// Parses and validates mutation evidence.
pub fn parse_evidence(json: &str) -> Result<MutationEvidence, String> {
    let evidence: MutationEvidence =
        serde_json::from_str(json).map_err(|error| error.to_string())?;
    validate_schema(evidence.schema_version)?;
    validate_tla_identifier("model", &evidence.model)?;
    if evidence.generated_at.trim().is_empty() {
        return Err("generatedAt must not be empty".to_owned());
    }
    if evidence.tlc_version.trim().is_empty() {
        return Err("tlcVersion must not be empty".to_owned());
    }
    for (field, digest) in [
        ("moduleSha256", evidence.module_sha256.as_str()),
        ("configSha256", evidence.config_sha256.as_str()),
        ("manifestSha256", evidence.manifest_sha256.as_str()),
        ("jarSha256", evidence.jar_sha256.as_str()),
    ] {
        if !is_sha256(digest) {
            return Err(format!(
                "{field} must be 64 lowercase hexadecimal characters"
            ));
        }
    }
    let mut ids = HashSet::new();
    for result in &evidence.results {
        if !is_mutation_id(&result.id) {
            return Err(format!("invalid mutation result id {}", result.id));
        }
        if !ids.insert(result.id.as_str()) {
            return Err(format!("duplicate mutation result {}", result.id));
        }
        validate_tla_identifier("property", &result.property)?;
        if result.detail.trim().is_empty() {
            return Err(format!("mutation result {} requires detail", result.id));
        }
    }
    Ok(evidence)
}

/// Computes the lowercase SHA-256 digest of a file without loading it all at once.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_schema(version: u32) -> Result<(), String> {
    if version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(format!(
            "unsupported schemaVersion {version}; expected {SCHEMA_VERSION}"
        ))
    }
}

fn validate_tla_identifier(field: &str, value: &str) -> Result<(), String> {
    let mut characters = value.chars();
    let valid = characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_');
    if valid {
        Ok(())
    } else {
        Err(format!("invalid {field} identifier {value}"))
    }
}

fn is_mutation_id(value: &str) -> bool {
    value.starts_with("M-")
        && value.len() > 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
