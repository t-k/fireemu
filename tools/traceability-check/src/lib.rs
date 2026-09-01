//! Requirement traceability check (spec 32, CI step 31.1 #12 and #16).
//!
//! Verifies, without touching the runtime:
//!
//! - `verification/mutants/catalog.json` has unique IDs (single source of truth, spec 27.5);
//! - `verification/loom/scenarios.json` has unique names (spec 23.3);
//! - every requirement references only defined mutant IDs, Loom scenarios, TLA+/Quint models and
//!   integration test files;
//! - every critical mutant is referenced by at least one critical requirement;
//! - every critical requirement with status `implemented` has a dynamic test, a formal or
//!   systematic artifact, a mutation or negative test, an owner and a status;
//! - every artifact of a requirement with status `implemented` or `partial` resolves to a real
//!   repository artifact: a `#[kani::proof]` function under `verification/kani`, a test function
//!   under a `tests/` directory, a `fuzz/fuzz_targets/<name>.rs` file, an existing conformance
//!   path, a Loom function under `verification/loom/src`, a property in the named TLA+ or Quint
//!   model, or an existing integration test file.
//!
//! An artifact that is planned but not written yet is written as `pending:<name>` (see
//! `docs/verification-ledger.md`). A pending artifact is never resolved and never counts as
//! evidence for a critical requirement's gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fireemu_verification_quint::evidence::validate_evidence_file as validate_quint_evidence_file;
use fireemu_verification_quint::model::{model as quint_model, ModelDescriptor};
use serde::Deserialize;
use tla_verification::{sha256_file, verify_evidence_with_jar_digest, TLA2TOOLS_1_8_0_SHA256};

/// Prefix that marks an artifact as declared but not written yet.
pub const PENDING_PREFIX: &str = "pending:";

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MutantCatalog {
    schema_version: u32,
    #[allow(dead_code)]
    source: String,
    mutants: Vec<Mutant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutant {
    id: String,
    fault: String,
    critical: bool,
    #[serde(default)]
    #[allow(dead_code)]
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LoomScenarios {
    schema_version: u32,
    #[allow(dead_code)]
    source: String,
    scenarios: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RequirementsFile {
    schema_version: u32,
    #[allow(dead_code)]
    source: String,
    requirements: Vec<Requirement>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Requirement {
    id: String,
    statement: String,
    criticality: String,
    status: String,
    owner: String,
    #[serde(default)]
    #[allow(dead_code)]
    note: String,
    artifacts: Artifacts,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    #[serde(default)]
    tla: Option<String>,
    #[serde(default)]
    quint: Option<String>,
    #[serde(default)]
    loom: Vec<String>,
    #[serde(default)]
    kani: Option<String>,
    #[serde(default)]
    property: Option<String>,
    #[serde(default)]
    fuzz: Option<String>,
    #[serde(default)]
    mutation: Vec<String>,
    #[serde(default)]
    conformance: Option<String>,
    #[serde(default)]
    integration: Vec<String>,
}

/// Outcome of a traceability run.
#[derive(Debug, Default)]
pub struct Report {
    /// Findings that fail the gate, in ledger order.
    pub problems: Vec<String>,
    /// Artifacts explicitly marked `pending:`, in ledger order. Never evidence.
    pub pending: Vec<String>,
}

impl Report {
    /// Whether the gate passes.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// An artifact reference as written in the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactRef<'a> {
    /// Declared but not written yet; never resolved, never evidence.
    Pending(&'a str),
    /// Must resolve to a repository artifact.
    Named(&'a str),
    /// Empty or whitespace-only; always a problem.
    Empty,
}

fn artifact_ref(raw: &str) -> ArtifactRef<'_> {
    if let Some(rest) = raw.strip_prefix(PENDING_PREFIX) {
        let rest = rest.trim();
        if rest.is_empty() {
            ArtifactRef::Empty
        } else {
            ArtifactRef::Pending(rest)
        }
    } else {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            ArtifactRef::Empty
        } else {
            ArtifactRef::Named(trimmed)
        }
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn is_requirement_id(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}

fn is_snake_case(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_tla_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn safe_tla_reference(reference: &str) -> Option<(&str, &str)> {
    let (module, property) = reference.split_once("::")?;
    if property.contains("::") || !is_tla_identifier(property) {
        return None;
    }
    let path = Path::new(module);
    let file_name = path.file_name()?.to_str()?;
    if file_name != module
        || !path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("tla"))
        || !path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(is_tla_identifier)
    {
        return None;
    }
    Some((module, property))
}

fn safe_quint_reference(reference: &str) -> Option<(&str, &str)> {
    let (module, property) = reference.split_once("::")?;
    if property.contains("::") || !is_tla_identifier(property) {
        return None;
    }
    let path = Path::new(module);
    let file_name = path.file_name()?.to_str()?;
    if file_name != module
        || path.extension() != Some(std::ffi::OsStr::new("qnt"))
        || !path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(is_tla_identifier)
    {
        return None;
    }
    Some((module, property))
}

fn strip_tla_comments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    let mut block_depth = 0_u32;
    let mut line_comment = false;
    while let Some(character) = characters.next() {
        let next = characters.peek().copied();
        if line_comment {
            if character == '\n' {
                line_comment = false;
                output.push(character);
            }
        } else if block_depth > 0 {
            if character == '(' && next == Some('*') {
                block_depth += 1;
                characters.next();
            } else if character == '*' && next == Some(')') {
                block_depth -= 1;
                characters.next();
            } else if character == '\n' {
                output.push(character);
            }
        } else if character == '\\' && next == Some('*') {
            line_comment = true;
            characters.next();
        } else if character == '(' && next == Some('*') {
            block_depth = 1;
            characters.next();
        } else {
            output.push(character);
        }
    }
    output
}

fn tla_defines_property(source: &str, property: &str) -> bool {
    strip_tla_comments(source).lines().any(|line| {
        line.trim_start()
            .strip_prefix(property)
            .is_some_and(|rest| rest.trim_start().starts_with("=="))
    })
}

fn cfg_registered_properties(config: &str) -> BTreeSet<String> {
    let mut properties = BTreeSet::new();
    let mut collecting = false;
    for line in strip_tla_comments(config).lines() {
        for token in line.split_whitespace() {
            if is_cfg_directive(token) {
                collecting = matches!(
                    token,
                    "INVARIANT" | "INVARIANTS" | "PROPERTY" | "PROPERTIES"
                );
            } else if collecting && is_tla_identifier(token) {
                properties.insert(token.to_owned());
            }
        }
    }
    properties
}

fn is_cfg_directive(token: &str) -> bool {
    matches!(
        token,
        "CONSTANT"
            | "CONSTANTS"
            | "CONSTRAINT"
            | "CONSTRAINTS"
            | "ACTION_CONSTRAINT"
            | "ACTION_CONSTRAINTS"
            | "INIT"
            | "NEXT"
            | "VIEW"
            | "SYMMETRY"
            | "TYPE"
            | "TYPE_CONSTRAINT"
            | "CHECK_DEADLOCK"
            | "ALIAS"
            | "POSTCONDITION"
            | "PERIODIC"
            | "INVARIANT"
            | "INVARIANTS"
            | "PROPERTY"
            | "PROPERTIES"
    )
}

/// Everything the checker can resolve an artifact name against.
struct RepoIndex {
    /// Functions carrying `#[kani::proof]` under `verification/kani`.
    kani_proofs: BTreeSet<String>,
    /// Functions defined in Rust files under a `tests/` directory anywhere in the workspace.
    test_fns: BTreeSet<String>,
    /// File stems under any `fuzz/fuzz_targets` directory.
    fuzz_targets: BTreeSet<String>,
    /// Concatenated `verification/loom/src` sources.
    loom_src: String,
}

impl RepoIndex {
    fn build(root: &Path) -> Self {
        let mut rust_files = Vec::new();
        let mut fuzz_targets = BTreeSet::new();
        for top in ["crates", "tools", "verification"] {
            collect(&root.join(top), &mut rust_files, &mut fuzz_targets);
        }
        collect_fuzz_dir(&root.join("fuzz"), &mut fuzz_targets);
        let mut kani_proofs = BTreeSet::new();
        let kani_root = root.join("verification/kani");
        let mut test_fns = BTreeSet::new();
        for path in &rust_files {
            let Ok(text) = fs::read_to_string(path) else {
                continue;
            };
            if path.starts_with(&kani_root) {
                collect_kani_proofs(&text, &mut kani_proofs);
            }
            if is_under_tests_dir(path) {
                collect_fn_names(&text, &mut test_fns);
            }
        }
        Self {
            kani_proofs,
            test_fns,
            fuzz_targets,
            loom_src: read_dir_sources(&root.join("verification/loom/src")),
        }
    }
}

fn is_under_tests_dir(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case("tests"))
}

/// Recursively collects `.rs` files and `fuzz/fuzz_targets` entries, skipping build output.
fn collect(dir: &Path, rust_files: &mut Vec<PathBuf>, fuzz_targets: &mut BTreeSet<String>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.is_dir() {
            if matches!(name.as_str(), "target" | ".git" | "node_modules") {
                continue;
            }
            if name == "fuzz" {
                collect_fuzz_dir(&path, fuzz_targets);
            }
            collect(&path, rust_files, fuzz_targets);
        } else if path.extension().is_some_and(|x| x == "rs") {
            rust_files.push(path);
        }
    }
}

fn collect_fuzz_dir(fuzz_dir: &Path, fuzz_targets: &mut BTreeSet<String>) {
    let Ok(rd) = fs::read_dir(fuzz_dir.join("fuzz_targets")) else {
        return;
    };
    for entry in rd.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "rs") {
            if let Some(stem) = path.file_stem() {
                fuzz_targets.insert(stem.to_string_lossy().into_owned());
            }
        }
    }
}

/// Names of functions annotated with `#[kani::proof]`. Other attributes may sit in between.
fn collect_kani_proofs(text: &str, out: &mut BTreeSet<String>) {
    let mut armed = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        if line.contains("#[kani::proof]") {
            armed = true;
            continue;
        }
        if let Some(name) = fn_name(line) {
            if armed {
                out.insert(name.to_owned());
            }
            armed = false;
        }
    }
}

fn collect_fn_names(text: &str, out: &mut BTreeSet<String>) {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        if let Some(name) = fn_name(line) {
            out.insert(name.to_owned());
        }
    }
}

/// The identifier of a `fn name(` definition on `line`, if any.
fn fn_name(line: &str) -> Option<&str> {
    let mut rest = line;
    loop {
        let at = rest.find("fn ")?;
        let before_ok = at == 0
            || !rest.as_bytes()[at - 1].is_ascii_alphanumeric() && rest.as_bytes()[at - 1] != b'_';
        let tail = &rest[at + 3..];
        let name: &str = tail
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or_default();
        let after = tail[name.len()..].trim_start();
        if before_ok && !name.is_empty() && (after.starts_with('(') || after.starts_with('<')) {
            return Some(name);
        }
        rest = tail;
    }
}

fn read_dir_sources(dir: &Path) -> String {
    let mut out = String::new();
    if let Ok(rd) = fs::read_dir(dir) {
        let mut paths: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rs")) {
                if let Ok(t) = fs::read_to_string(&p) {
                    out.push_str(&t);
                    out.push('\n');
                }
            }
        }
    }
    out
}

/// Which artifact categories a requirement can actually prove things with. One flag per
/// category on purpose: the gate below reads them by name.
#[derive(Default)]
#[allow(clippy::struct_excessive_bools)]
struct Evidence {
    tla: bool,
    quint: bool,
    loom: bool,
    kani: bool,
    property: bool,
    fuzz: bool,
    mutation: bool,
    conformance: bool,
    integration: bool,
}

/// Runs every traceability rule against the repository rooted at `root`.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn check(root: &Path) -> Report {
    let mut report = Report::default();
    let problems = &mut report.problems;
    let mutants: MutantCatalog = match read_json(&root.join("verification/mutants/catalog.json")) {
        Ok(v) => v,
        Err(e) => {
            report.problems.push(e);
            return report;
        }
    };
    let loom: LoomScenarios = match read_json(&root.join("verification/loom/scenarios.json")) {
        Ok(v) => v,
        Err(e) => {
            report.problems.push(e);
            return report;
        }
    };
    let reqs: RequirementsFile =
        match read_json(&root.join("verification/requirements/requirements.json")) {
            Ok(v) => v,
            Err(e) => {
                report.problems.push(e);
                return report;
            }
        };
    for (name, v) in [
        ("mutants", mutants.schema_version),
        ("loom", loom.schema_version),
        ("requirements", reqs.schema_version),
    ] {
        if v != 1 {
            problems.push(format!("{name}: unsupported schemaVersion {v}"));
        }
    }

    // Mutant catalog: unique, well-formed, non-empty fault text.
    let mut mutant_ids = BTreeMap::new();
    for m in &mutants.mutants {
        if !m.id.starts_with("M-") || !is_requirement_id(&m.id) {
            problems.push(format!("mutant {}: malformed id", m.id));
        }
        if m.fault.trim().is_empty() {
            problems.push(format!("mutant {}: empty fault description", m.id));
        }
        if mutant_ids.insert(m.id.clone(), m.critical).is_some() {
            problems.push(format!("mutant {}: duplicate id", m.id));
        }
    }

    // Loom scenarios: unique snake_case names.
    let mut loom_names = BTreeSet::new();
    for s in &loom.scenarios {
        if !is_snake_case(s) {
            problems.push(format!("loom scenario {s:?}: must be snake_case"));
        }
        if !loom_names.insert(s.clone()) {
            problems.push(format!("loom scenario {s}: duplicate"));
        }
    }

    let index = RepoIndex::build(root);

    // Requirements.
    let mut req_ids = BTreeSet::new();
    let mut referenced_mutants: BTreeSet<String> = BTreeSet::new();
    for r in &reqs.requirements {
        let id = r.id.as_str();
        if !is_requirement_id(id) {
            problems.push(format!("requirement {id}: malformed id"));
        }
        if !req_ids.insert(id.to_owned()) {
            problems.push(format!("requirement {id}: duplicate id"));
        }
        if r.statement.trim().is_empty() {
            problems.push(format!("requirement {id}: empty statement"));
        }
        if !matches!(r.criticality.as_str(), "critical" | "important" | "normal") {
            problems.push(format!(
                "requirement {id}: unknown criticality {}",
                r.criticality
            ));
        }
        if !matches!(r.status.as_str(), "planned" | "partial" | "implemented") {
            problems.push(format!("requirement {id}: unknown status {}", r.status));
        }
        if r.owner.trim().is_empty() {
            problems.push(format!("requirement {id}: missing owner"));
        }
        // Artifacts of a requirement that claims to be built must resolve; a `planned`
        // requirement describes work that does not exist yet.
        let resolve = matches!(r.status.as_str(), "implemented" | "partial");
        let a = &r.artifacts;
        let mut have = Evidence::default();
        let mut unresolved_mutants = Vec::new();
        let mut resolved_tla = None;
        let mut resolved_quint: Option<(&'static ModelDescriptor, &str)> = None;

        for m in &a.mutation {
            if mutant_ids.contains_key(m) {
                have.mutation = true;
            } else {
                unresolved_mutants.push(m.as_str());
            }
            referenced_mutants.insert(m.clone());
        }

        for s in &a.loom {
            match artifact_ref(s) {
                ArtifactRef::Empty => problems.push(format!("requirement {id}: empty loom name")),
                ArtifactRef::Pending(name) => {
                    report.pending.push(format!("{id}: loom {name}"));
                }
                ArtifactRef::Named(name) => {
                    if !loom_names.contains(name) {
                        problems.push(format!(
                            "requirement {id}: references undefined loom scenario {name}"
                        ));
                    } else if resolve && !index.loom_src.contains(&format!("fn {name}(")) {
                        problems.push(format!(
                            "requirement {id}: loom scenario {name} has no test function under verification/loom/src"
                        ));
                    } else {
                        have.loom = true;
                    }
                }
            }
        }

        if let Some(tla) = &a.tla {
            match artifact_ref(tla) {
                ArtifactRef::Empty => {
                    problems.push(format!("requirement {id}: empty tla artifact"));
                }
                ArtifactRef::Pending(name) => report.pending.push(format!("{id}: tla {name}")),
                ArtifactRef::Named(name) => match safe_tla_reference(name) {
                    Some((module, property)) => {
                        if resolve {
                            let path = root.join("verification/tla").join(module);
                            match fs::read_to_string(&path) {
                                Ok(text) if tla_defines_property(&text, property) => {
                                    let config_name = Path::new(module).with_extension("cfg");
                                    let config_path =
                                        root.join("verification/tla").join(&config_name);
                                    match fs::read_to_string(&config_path) {
                                        Ok(config)
                                            if cfg_registered_properties(&config)
                                                .contains(property) =>
                                        {
                                            have.tla = true;
                                            resolved_tla = Some((module, property));
                                        }
                                        Ok(_) => problems.push(format!(
                                            "requirement {id}: TLA+ config {} does not register {property}",
                                            config_name.display()
                                        )),
                                        Err(_) => problems.push(format!(
                                            "requirement {id}: TLA+ config {} is missing",
                                            config_name.display()
                                        )),
                                    }
                                }
                                Ok(_) => problems.push(format!(
                                    "requirement {id}: TLA+ module {module} does not define {property}"
                                )),
                                Err(_) => problems.push(format!(
                                    "requirement {id}: TLA+ module {module} is missing"
                                )),
                            }
                        } else {
                            have.tla = true;
                        }
                    }
                    _ => problems.push(format!(
                        "requirement {id}: tla artifact must be Module.tla::Property"
                    )),
                },
            }
        }

        if let Some(quint) = &a.quint {
            match artifact_ref(quint) {
                ArtifactRef::Empty => {
                    problems.push(format!("requirement {id}: empty quint artifact"));
                }
                ArtifactRef::Pending(name) => {
                    report.pending.push(format!("{id}: quint {name}"));
                }
                ArtifactRef::Named(name) => match safe_quint_reference(name) {
                    Some((module, property)) => {
                        if resolve {
                            let model_name = Path::new(module)
                                .file_stem()
                                .and_then(|stem| stem.to_str())
                                .expect("safe Quint reference has a UTF-8 stem");
                            match quint_model(model_name) {
                                Ok(descriptor) if descriptor.property(property).is_ok() => {
                                    let expected_module = Path::new(descriptor.spec)
                                        .file_name()
                                        .and_then(|file| file.to_str());
                                    if expected_module != Some(module) {
                                        problems.push(format!(
                                            "requirement {id}: Quint registry path for {model_name} does not match {module}"
                                        ));
                                    } else if !root
                                        .join("verification/quint/specs")
                                        .join(module)
                                        .is_file()
                                    {
                                        problems.push(format!(
                                            "requirement {id}: Quint spec {module} is missing"
                                        ));
                                    } else {
                                        have.quint = true;
                                        resolved_quint = Some((descriptor, property));
                                    }
                                }
                                Ok(_) => problems.push(format!(
                                    "requirement {id}: Quint model {model_name} does not register {property}"
                                )),
                                Err(_) => problems.push(format!(
                                    "requirement {id}: Quint model {model_name} is not registered"
                                )),
                            }
                        } else {
                            have.quint = true;
                        }
                    }
                    None => problems.push(format!(
                        "requirement {id}: quint artifact must be Model.qnt::Property"
                    )),
                },
            }
        }

        let mut formal_mutant_ids = BTreeSet::new();
        if resolve {
            if let Some((module, property)) = resolved_tla {
                let model = Path::new(module)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .expect("safe TLA reference has a UTF-8 stem");
                let tla_root = root.join("verification/tla");
                let manifest = tla_root.join("mutations").join(format!("{model}.json"));
                let evidence = tla_root.join("evidence").join(format!("{model}.json"));
                let jar = root.join(".tools/tla2tools-1.8.0.jar");
                let jar_digest = if jar.is_file() {
                    sha256_file(&jar)
                        .map_err(|error| error.to_string())
                        .unwrap_or_else(|_| TLA2TOOLS_1_8_0_SHA256.to_owned())
                } else {
                    TLA2TOOLS_1_8_0_SHA256.to_owned()
                };
                match verify_evidence_with_jar_digest(
                    &tla_root.join(module),
                    &tla_root.join(format!("{model}.cfg")),
                    &manifest,
                    &evidence,
                    &jar_digest,
                ) {
                    Ok(verified) => {
                        let mut matching_property_mutation = false;
                        for result in verified.results {
                            formal_mutant_ids.insert(result.id.clone());
                            if a.mutation.contains(&result.id)
                                && result.property == property
                                && result.outcome.is_killed()
                            {
                                matching_property_mutation = true;
                                have.mutation = true;
                            }
                        }
                        if !matching_property_mutation {
                            problems.push(format!(
                                "requirement {id}: no referenced killed TLA mutation for property {property}"
                            ));
                        }
                    }
                    Err(error) => problems.push(format!(
                        "requirement {id}: TLA+ mutation evidence for {model} is invalid: {error}"
                    )),
                }
            }

            if let Some((descriptor, property)) = resolved_quint {
                let quint_root = root.join("verification/quint");
                let evidence_path = quint_root
                    .join("evidence")
                    .join(format!("{}.json", descriptor.name));
                match validate_quint_evidence_file(root, &evidence_path, descriptor) {
                    Ok(verified) => {
                        let mut matching_property_mutation = false;
                        for result in verified.mutations {
                            formal_mutant_ids.insert(result.id.clone());
                            if a.mutation.contains(&result.id)
                                && result.property == property
                                && result.outcome.is_killed()
                            {
                                matching_property_mutation = true;
                                have.mutation = true;
                            }
                        }
                        if !matching_property_mutation {
                            problems.push(format!(
                                "requirement {id}: no referenced killed Quint mutation for property {property}"
                            ));
                        }
                    }
                    Err(error) => problems.push(format!(
                        "requirement {id}: Quint evidence for {} is invalid: {error}",
                        descriptor.name
                    )),
                }
            }
        }
        for mutation in unresolved_mutants {
            if !formal_mutant_ids.contains(mutation) {
                problems.push(format!(
                    "requirement {id}: references undefined mutant {mutation}"
                ));
            }
        }

        if let Some(kani) = &a.kani {
            match artifact_ref(kani) {
                ArtifactRef::Empty => {
                    problems.push(format!("requirement {id}: empty kani artifact"));
                }
                ArtifactRef::Pending(name) => report.pending.push(format!("{id}: kani {name}")),
                ArtifactRef::Named(name) => {
                    if !is_snake_case(name) {
                        problems.push(format!(
                            "requirement {id}: kani harness {name} must be a snake_case function name"
                        ));
                    } else if resolve && !index.kani_proofs.contains(name) {
                        problems.push(format!(
                            "requirement {id}: kani harness {name} is not a #[kani::proof] function under verification/kani"
                        ));
                    } else {
                        have.kani = true;
                    }
                }
            }
        }

        if let Some(property) = &a.property {
            match artifact_ref(property) {
                ArtifactRef::Empty => {
                    problems.push(format!("requirement {id}: empty property artifact"));
                }
                ArtifactRef::Pending(name) => report.pending.push(format!("{id}: property {name}")),
                ArtifactRef::Named(name) => {
                    if !is_snake_case(name) {
                        problems.push(format!(
                            "requirement {id}: property test {name} must be a snake_case function name"
                        ));
                    } else if resolve && !index.test_fns.contains(name) {
                        problems.push(format!(
                            "requirement {id}: property test {name} is not defined in any tests/ source file"
                        ));
                    } else {
                        have.property = true;
                    }
                }
            }
        }

        if let Some(fuzz) = &a.fuzz {
            match artifact_ref(fuzz) {
                ArtifactRef::Empty => {
                    problems.push(format!("requirement {id}: empty fuzz artifact"));
                }
                ArtifactRef::Pending(name) => report.pending.push(format!("{id}: fuzz {name}")),
                ArtifactRef::Named(name) => {
                    if !is_snake_case(name) {
                        problems.push(format!(
                            "requirement {id}: fuzz target {name} must be a snake_case target name"
                        ));
                    } else if resolve && !index.fuzz_targets.contains(name) {
                        problems.push(format!(
                            "requirement {id}: fuzz target {name} has no fuzz/fuzz_targets/{name}.rs"
                        ));
                    } else {
                        have.fuzz = true;
                    }
                }
            }
        }

        if let Some(conformance) = &a.conformance {
            match artifact_ref(conformance) {
                ArtifactRef::Empty => {
                    problems.push(format!("requirement {id}: empty conformance artifact"));
                }
                ArtifactRef::Pending(name) => {
                    report.pending.push(format!("{id}: conformance {name}"));
                }
                ArtifactRef::Named(name) => {
                    if Path::new(name).is_absolute() {
                        problems.push(format!(
                            "requirement {id}: conformance artifact {name} must be a repository-relative path"
                        ));
                    } else if resolve && !root.join(name).exists() {
                        problems.push(format!(
                            "requirement {id}: conformance artifact {name} does not exist"
                        ));
                    } else {
                        have.conformance = true;
                    }
                }
            }
        }

        for t in &a.integration {
            match artifact_ref(t) {
                ArtifactRef::Empty => {
                    problems.push(format!("requirement {id}: empty integration artifact"));
                }
                ArtifactRef::Pending(name) => {
                    report.pending.push(format!("{id}: integration {name}"));
                }
                ArtifactRef::Named(name) => {
                    if root.join(name).is_file() {
                        have.integration = true;
                    } else {
                        problems.push(format!(
                            "requirement {id}: integration test {name} does not exist"
                        ));
                    }
                }
            }
        }

        if r.criticality == "critical" && r.status == "implemented" {
            let dynamic = have.integration || have.property;
            let formal =
                have.tla || have.quint || have.kani || have.loom || have.property || have.fuzz;
            let mutation = have.mutation || have.conformance;
            if !dynamic {
                problems.push(format!(
                    "critical requirement {id}: no resolved dynamic test"
                ));
            }
            if !formal {
                problems.push(format!(
                    "critical requirement {id}: no resolved formal or systematic artifact"
                ));
            }
            if !mutation {
                problems.push(format!(
                    "critical requirement {id}: no resolved mutation or negative test"
                ));
            }
        }
    }

    // Every critical mutant must be referenced by at least one critical requirement.
    for (m, critical) in &mutant_ids {
        if *critical && !referenced_mutants.contains(m) {
            problems.push(format!(
                "critical mutant {m} is not referenced by any requirement"
            ));
        }
    }
    report
}
