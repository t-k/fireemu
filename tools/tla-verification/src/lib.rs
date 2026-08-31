//! Contracts and tooling for repository-owned TLA+ verification evidence.

pub mod event_trace;

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current persisted manifest and evidence schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// SHA-256 of the repository-pinned TLA+ tools 1.8.0 JAR.
pub const TLA2TOOLS_1_8_0_SHA256: &str =
    "eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a";

static UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

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

/// Full-property disposition report for regenerated mutation candidates.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageReport {
    /// Persisted schema version.
    pub schema_version: u32,
    /// Date on which the candidate set was regenerated.
    pub date: String,
    /// Relationship to the earlier count-only observation.
    pub historical_observation: HistoricalObservation,
    /// Modules included in this frozen candidate cohort.
    pub models: Vec<String>,
    /// Every candidate in the regenerated repository-owned manifests.
    pub candidates: Vec<TriageCandidate>,
}

/// Audit note for a historical observation that lacked a result artifact.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoricalObservation {
    /// Candidate count reported by the earlier experiment.
    pub reported_count: u32,
    /// Whether individual historical candidates can be mapped.
    pub mapping: HistoricalMapping,
    /// Why the old observation can or cannot be mapped to current candidates.
    pub rationale: String,
}

/// Supported historical-candidate mapping states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalMapping {
    /// No stable identifiers or result artifact survived from the old run.
    Unreproducible,
}

/// One regenerated candidate and its full-property disposition.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageCandidate {
    /// Stable mutation identifier.
    pub candidate_id: String,
    /// TLA+ module name.
    pub model: String,
    /// Property expected to detect the mutation.
    pub property: String,
    /// Human-readable mutation operator.
    pub operator: String,
    /// Exact original source span replaced by the mutant.
    pub source_span: String,
    /// Result from the referenced full-configuration evidence.
    pub outcome: MutationOutcome,
    /// Repository-relative evidence file, required for accepted coverage.
    pub evidence: Option<String>,
    /// Final disposition after full-property analysis.
    pub disposition: TriageDisposition,
    /// Nonempty explanation for the disposition.
    pub rationale: String,
}

/// Exhaustive disposition of a regenerated candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageDisposition {
    /// An already-configured property detected the candidate.
    Covered,
    /// A new property was added to detect the candidate.
    PropertyAdded,
    /// The candidate is behaviorally equivalent under the model bounds.
    Equivalent,
    /// The candidate does not represent a valid semantic defect.
    Invalid,
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

/// Inputs and process controls for one complete mutation run.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Original TLA+ module.
    pub module: PathBuf,
    /// TLC configuration copied unchanged for every mutation.
    pub config: PathBuf,
    /// Semantic mutation manifest.
    pub manifest: PathBuf,
    /// Pinned TLA+ tools JAR.
    pub jar: PathBuf,
    /// Atomic destination for generated evidence.
    pub evidence: PathBuf,
    /// Java executable, overridable for testing.
    pub java_bin: PathBuf,
    /// Maximum wall-clock time for one mutant.
    pub timeout: Duration,
}

/// Executes every mutation in a fresh directory and atomically writes its evidence.
pub fn run_mutations(options: &RunOptions) -> Result<MutationEvidence, String> {
    let source = fs::read_to_string(&options.module)
        .map_err(|error| format!("read {}: {error}", options.module.display()))?;
    let manifest_json = fs::read_to_string(&options.manifest)
        .map_err(|error| format!("read {}: {error}", options.manifest.display()))?;
    let manifest = parse_manifest(&manifest_json)?;
    let module_name = options
        .module
        .file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "module path must have a UTF-8 file stem".to_owned())?;
    if manifest.model != module_name {
        return Err(format!(
            "manifest model {} does not match module {module_name}",
            manifest.model
        ));
    }
    let config_bytes = fs::read(&options.config)
        .map_err(|error| format!("read {}: {error}", options.config.display()))?;
    File::open(&options.jar).map_err(|error| format!("read {}: {error}", options.jar.display()))?;

    for mutation in &manifest.mutations {
        mutation.materialize(&source)?;
    }

    let tlc_version = query_tlc_version(
        &options.java_bin,
        &options.jar,
        options.timeout.min(Duration::from_secs(5)),
    );
    let mut results = Vec::with_capacity(manifest.mutations.len());
    for mutation in &manifest.mutations {
        let mutated = mutation.materialize(&source)?;
        let work = TemporaryDirectory::new("tla-mutant")?;
        let module_file_name = required_file_name(&options.module)?;
        let config_file_name = required_file_name(&options.config)?;
        fs::write(work.path.join(&module_file_name), mutated)
            .map_err(|error| format!("write mutated module: {error}"))?;
        fs::write(work.path.join(&config_file_name), &config_bytes)
            .map_err(|error| format!("write copied config: {error}"))?;

        let execution = execute_tlc(
            &options.java_bin,
            &options.jar,
            &work.path,
            &module_file_name,
            &config_file_name,
            options.timeout,
        );
        let (outcome, detail) = classify_execution(execution);
        results.push(MutationResult {
            id: mutation.id.clone(),
            property: mutation.property.clone(),
            outcome,
            detail,
        });
    }

    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_secs()
        .to_string();
    let evidence = MutationEvidence {
        schema_version: SCHEMA_VERSION,
        model: manifest.model,
        generated_at,
        tlc_version,
        module_sha256: sha256_file(&options.module).map_err(|error| error.to_string())?,
        config_sha256: sha256_file(&options.config).map_err(|error| error.to_string())?,
        manifest_sha256: sha256_file(&options.manifest).map_err(|error| error.to_string())?,
        jar_sha256: sha256_file(&options.jar).map_err(|error| error.to_string())?,
        results,
    };
    write_evidence_atomic(&options.evidence, &evidence)?;
    Ok(evidence)
}

/// Verifies evidence freshness, manifest completeness, property binding, and killed outcomes.
pub fn verify_evidence(
    module: &Path,
    config: &Path,
    manifest: &Path,
    jar: &Path,
    evidence: &Path,
) -> Result<MutationEvidence, String> {
    let jar_digest = sha256_file(jar).map_err(|error| error.to_string())?;
    verify_evidence_with_jar_digest(module, config, manifest, evidence, &jar_digest)
}

/// Verifies evidence when the trusted JAR digest is supplied out of band.
pub fn verify_evidence_with_jar_digest(
    module: &Path,
    config: &Path,
    manifest: &Path,
    evidence: &Path,
    expected_jar_digest: &str,
) -> Result<MutationEvidence, String> {
    if !is_sha256(expected_jar_digest) {
        return Err("expected JAR digest must be lowercase SHA-256".to_owned());
    }
    let evidence_value = parse_evidence(
        &fs::read_to_string(evidence)
            .map_err(|error| format!("read {}: {error}", evidence.display()))?,
    )?;
    for (label, actual, recorded) in [
        (
            "module",
            sha256_file(module).map_err(|error| error.to_string())?,
            evidence_value.module_sha256.as_str(),
        ),
        (
            "config",
            sha256_file(config).map_err(|error| error.to_string())?,
            evidence_value.config_sha256.as_str(),
        ),
        (
            "manifest",
            sha256_file(manifest).map_err(|error| error.to_string())?,
            evidence_value.manifest_sha256.as_str(),
        ),
        (
            "jar",
            expected_jar_digest.to_owned(),
            evidence_value.jar_sha256.as_str(),
        ),
    ] {
        if actual != recorded {
            return Err(format!("{label} digest mismatch"));
        }
    }
    let manifest_value = parse_manifest(
        &fs::read_to_string(manifest)
            .map_err(|error| format!("read {}: {error}", manifest.display()))?,
    )?;
    if evidence_value.model != manifest_value.model {
        return Err(format!(
            "evidence model {} does not match manifest model {}",
            evidence_value.model, manifest_value.model
        ));
    }
    if evidence_value.results.len() != manifest_value.mutations.len() {
        return Err(format!(
            "evidence has {} results for {} manifest mutations",
            evidence_value.results.len(),
            manifest_value.mutations.len()
        ));
    }
    for (mutation, result) in manifest_value.mutations.iter().zip(&evidence_value.results) {
        if mutation.id != result.id {
            return Err(format!(
                "evidence result {} does not match manifest mutation {}",
                result.id, mutation.id
            ));
        }
        if mutation.property != result.property {
            return Err(format!(
                "mutation {} evidence property {} does not match {}",
                mutation.id, result.property, mutation.property
            ));
        }
        if !result.outcome.is_killed() {
            return Err(format!(
                "mutation {} was not killed: {:?}",
                mutation.id, result.outcome
            ));
        }
    }
    Ok(evidence_value)
}

/// Verifies every repository mutation manifest against its same-model evidence.
pub fn verify_repository_evidence(root: &Path, jar: &Path) -> Result<Vec<String>, String> {
    let mutation_directory = root.join("verification/tla/mutations");
    if !mutation_directory.exists() {
        return Ok(Vec::new());
    }
    let mut manifests = fs::read_dir(&mutation_directory)
        .map_err(|error| format!("read {}: {error}", mutation_directory.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    manifests.sort();
    let mut verified = Vec::with_capacity(manifests.len());
    for manifest in manifests {
        let model = manifest
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("{} has no UTF-8 model name", manifest.display()))?;
        let tla_directory = root.join("verification/tla");
        verify_evidence(
            &tla_directory.join(format!("{model}.tla")),
            &tla_directory.join(format!("{model}.cfg")),
            &manifest,
            jar,
            &tla_directory.join("evidence").join(format!("{model}.json")),
        )?;
        verified.push(model.to_owned());
    }
    Ok(verified)
}

/// Verifies that a triage report exactly covers its frozen model cohort and evidence rows.
pub fn verify_triage_report(root: &Path, report_path: &Path) -> Result<usize, String> {
    let report = parse_triage(
        &fs::read_to_string(report_path)
            .map_err(|error| format!("read {}: {error}", report_path.display()))?,
    )?;
    let tla_directory = root.join("verification/tla");
    let mut expected_count = 0_usize;
    for model in &report.models {
        let manifest_path = tla_directory
            .join("mutations")
            .join(format!("{model}.json"));
        let manifest = parse_manifest(
            &fs::read_to_string(&manifest_path)
                .map_err(|error| format!("read {}: {error}", manifest_path.display()))?,
        )?;
        if manifest.model != *model {
            return Err(format!(
                "triage model {model} does not match manifest model {}",
                manifest.model
            ));
        }
        expected_count += manifest.mutations.len();
        for mutation in &manifest.mutations {
            let candidate = report
                .candidates
                .iter()
                .find(|candidate| candidate.candidate_id == mutation.id)
                .ok_or_else(|| format!("triage is missing candidate {}", mutation.id))?;
            if candidate.model != *model
                || candidate.property != mutation.property
                || candidate.operator != mutation.operator
                || candidate.source_span != mutation.from
            {
                return Err(format!(
                    "triage candidate {} does not match its mutation manifest",
                    mutation.id
                ));
            }
            let evidence_reference = candidate.evidence.as_deref().ok_or_else(|| {
                format!(
                    "triage candidate {} requires evidence",
                    candidate.candidate_id
                )
            })?;
            let relative_evidence = Path::new(evidence_reference);
            if relative_evidence.is_absolute()
                || relative_evidence
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(format!(
                    "triage candidate {} has an unsafe evidence path",
                    candidate.candidate_id
                ));
            }
            let evidence_path = root.join(relative_evidence);
            let evidence = parse_evidence(
                &fs::read_to_string(&evidence_path)
                    .map_err(|error| format!("read {}: {error}", evidence_path.display()))?,
            )?;
            let result = evidence
                .results
                .iter()
                .find(|result| result.id == mutation.id)
                .ok_or_else(|| {
                    format!(
                        "triage candidate {} is missing from {}",
                        mutation.id,
                        evidence_path.display()
                    )
                })?;
            if evidence.model != *model
                || result.property != mutation.property
                || result.outcome != candidate.outcome
                || !result.outcome.is_killed()
            {
                return Err(format!(
                    "triage candidate {} does not match killed evidence",
                    mutation.id
                ));
            }
        }
    }
    if report.candidates.len() != expected_count {
        return Err(format!(
            "triage has {} candidates for {expected_count} manifest mutations",
            report.candidates.len()
        ));
    }
    Ok(expected_count)
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

/// Parses and validates a full-property triage report.
pub fn parse_triage(json: &str) -> Result<TriageReport, String> {
    let report: TriageReport = serde_json::from_str(json).map_err(|error| error.to_string())?;
    validate_schema(report.schema_version)?;
    if report.date.trim().is_empty() {
        return Err("triage date must not be empty".to_owned());
    }
    if report.historical_observation.reported_count == 0 {
        return Err("historical reportedCount must be positive".to_owned());
    }
    if report.historical_observation.rationale.trim().is_empty() {
        return Err("historical observation requires non-empty rationale".to_owned());
    }
    if report.candidates.is_empty() {
        return Err("triage must contain at least one candidate".to_owned());
    }
    if report.models.is_empty() {
        return Err("triage must contain at least one model".to_owned());
    }
    let mut models = HashSet::new();
    for model in &report.models {
        validate_tla_identifier("model", model)?;
        if !models.insert(model.as_str()) {
            return Err(format!("duplicate triage model {model}"));
        }
    }
    let mut ids = HashSet::new();
    for candidate in &report.candidates {
        if !is_mutation_id(&candidate.candidate_id) {
            return Err(format!(
                "invalid triage candidate id {}",
                candidate.candidate_id
            ));
        }
        if !ids.insert(candidate.candidate_id.as_str()) {
            return Err(format!(
                "duplicate triage candidate {}",
                candidate.candidate_id
            ));
        }
        validate_tla_identifier("model", &candidate.model)?;
        if !models.contains(candidate.model.as_str()) {
            return Err(format!(
                "triage candidate {} uses unlisted model {}",
                candidate.candidate_id, candidate.model
            ));
        }
        validate_tla_identifier("property", &candidate.property)?;
        for (field, value) in [
            ("operator", candidate.operator.as_str()),
            ("sourceSpan", candidate.source_span.as_str()),
            ("rationale", candidate.rationale.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!(
                    "triage candidate {} requires non-empty {field}",
                    candidate.candidate_id
                ));
            }
        }
        if matches!(
            candidate.disposition,
            TriageDisposition::Covered | TriageDisposition::PropertyAdded
        ) {
            if candidate
                .evidence
                .as_deref()
                .is_none_or(|path| path.trim().is_empty())
            {
                return Err(format!(
                    "triage candidate {} requires evidence",
                    candidate.candidate_id
                ));
            }
            if !candidate.outcome.is_killed() {
                return Err(format!(
                    "triage candidate {} requires a killed outcome",
                    candidate.candidate_id
                ));
            }
        }
    }
    Ok(report)
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

fn write_evidence_atomic(path: &Path, evidence: &MutationEvidence) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "evidence path must have a parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("create evidence directory {}: {error}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "evidence path must have a UTF-8 file name".to_owned())?;
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        let mut json = serde_json::to_vec_pretty(evidence).map_err(|error| error.to_string())?;
        json.push(b'\n');
        file.write_all(&json)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|error| {
            format!(
                "rename {} to {}: {error}",
                temporary.display(),
                path.display()
            )
        })?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn query_tlc_version(java_bin: &Path, jar: &Path, timeout: Duration) -> String {
    let mut command = Command::new(java_bin);
    command
        .args([OsString::from("-cp"), jar.as_os_str().to_owned()])
        .args(["tlc2.TLC", "-version"]);
    match execute_command(&mut command, timeout) {
        Execution::Completed { stdout, .. } => {
            let text = String::from_utf8_lossy(&stdout);
            text.lines()
                .find(|line| !line.trim().is_empty())
                .map(str::trim)
                .map_or_else(|| "unreported".to_owned(), str::to_owned)
        }
        Execution::Timeout | Execution::LaunchError(_) => "unreported".to_owned(),
    }
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(prefix: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            UNIQUE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).map_err(|error| format!("create {}: {error}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

enum Execution {
    Completed {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    Timeout,
    LaunchError(String),
}

fn execute_tlc(
    java_bin: &Path,
    jar: &Path,
    workdir: &Path,
    module_file_name: &OsString,
    config_file_name: &OsString,
    timeout: Duration,
) -> Execution {
    let mut command = Command::new(java_bin);
    command
        .current_dir(workdir)
        .arg("-cp")
        .arg(jar)
        .arg("tlc2.TLC")
        .arg("-workers")
        .arg("auto")
        .arg("-deadlock")
        .arg("-config")
        .arg(config_file_name)
        .arg(module_file_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    execute_command(&mut command, timeout)
}

fn execute_command(command: &mut Command, timeout: Duration) -> Execution {
    let mut child = match command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return Execution::LaunchError(error.to_string()),
    };
    let stdout = child.stdout.take().map(|mut stdout| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stdout.read_to_end(&mut bytes);
            bytes
        })
    });
    let stderr = child.stderr.take().map(|mut stderr| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        })
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Execution::LaunchError(error.to_string());
            }
        }
    };
    let stdout = stdout
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    let stderr = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    match status {
        Some(status) => Execution::Completed {
            status,
            stdout,
            stderr,
        },
        None => Execution::Timeout,
    }
}

fn classify_execution(execution: Execution) -> (MutationOutcome, String) {
    match execution {
        Execution::Timeout => (MutationOutcome::Timeout, "TLC timed out".to_owned()),
        Execution::LaunchError(error) => (MutationOutcome::ToolError, bounded_detail(&error)),
        Execution::Completed {
            status,
            stdout,
            stderr,
        } => {
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
            let temporal_violation = text.contains("Temporal properties were violated")
                || text.contains("Temporal property") && text.contains("was violated");
            let outcome = if temporal_violation {
                MutationOutcome::KilledTemporal
            } else if text.contains("Invariant") && text.contains("is violated")
                || text.contains("Action property") && text.contains("is violated")
            {
                MutationOutcome::KilledSafety
            } else if status.success() {
                MutationOutcome::Survived
            } else {
                MutationOutcome::ToolError
            };
            let status_label = status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| format!("exit {code}"));
            (outcome, bounded_detail(&format!("{status_label}: {text}")))
        }
    }
}

fn bounded_detail(value: &str) -> String {
    const MAX_CHARS: usize = 4096;
    let normalized = value.trim();
    if normalized.chars().count() <= MAX_CHARS {
        normalized.to_owned()
    } else {
        normalized.chars().take(MAX_CHARS).collect()
    }
}

fn required_file_name(path: &Path) -> Result<OsString, String> {
    path.file_name()
        .map(std::ffi::OsStr::to_owned)
        .ok_or_else(|| format!("{} must have a file name", path.display()))
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
