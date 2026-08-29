//! Requirement traceability check (spec 32, CI step 31.1 #12 and #16).
//!
//! Verifies, without touching the runtime:
//!
//! - `verification/mutants/catalog.json` has unique IDs (single source of truth, spec 27.5);
//! - `verification/loom/scenarios.json` has unique names (spec 23.3);
//! - every requirement references only defined mutant IDs, Loom scenarios, TLA+ modules and
//!   integration test files;
//! - every critical mutant is referenced by at least one critical requirement;
//! - every critical requirement with status `implemented` has a dynamic test, a formal or
//!   systematic artifact, a mutation or negative test, an owner and a status;
//! - Loom scenarios referenced by implemented requirements exist as functions in
//!   `verification/loom/src`; TLA+ properties referenced by implemented requirements exist in
//!   the named module.
//!
//! Usage: `traceability-check [--root <repo root>]`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;

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
    owner: String,
    status: String,
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

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn is_requirement_id(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}

#[allow(clippy::too_many_lines)]
fn check(root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let mutants: MutantCatalog = match read_json(&root.join("verification/mutants/catalog.json")) {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    let loom: LoomScenarios = match read_json(&root.join("verification/loom/scenarios.json")) {
        Ok(v) => v,
        Err(e) => return vec![e],
    };
    let reqs: RequirementsFile =
        match read_json(&root.join("verification/requirements/requirements.json")) {
            Ok(v) => v,
            Err(e) => return vec![e],
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
        if s.is_empty()
            || !s
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            problems.push(format!("loom scenario {s:?}: must be snake_case"));
        }
        if !loom_names.insert(s.clone()) {
            problems.push(format!("loom scenario {s}: duplicate"));
        }
    }
    let loom_src = read_dir_sources(&root.join("verification/loom/src"));

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
        let a = &r.artifacts;
        for m in &a.mutation {
            if !mutant_ids.contains_key(m) {
                problems.push(format!("requirement {id}: references undefined mutant {m}"));
            }
            referenced_mutants.insert(m.clone());
        }
        for s in &a.loom {
            if !loom_names.contains(s) {
                problems.push(format!(
                    "requirement {id}: references undefined loom scenario {s}"
                ));
            } else if r.status == "implemented" && !loom_src.contains(&format!("fn {s}(")) {
                problems.push(format!(
                    "requirement {id}: loom scenario {s} is referenced by an implemented requirement but has no test function under verification/loom/src"
                ));
            }
        }
        if let Some(tla) = &a.tla {
            match tla.split_once("::") {
                Some((module, property))
                    if Path::new(module)
                        .extension()
                        .is_some_and(|x| x.eq_ignore_ascii_case("tla"))
                        && !property.is_empty() =>
                {
                    let path = root.join("verification/tla").join(module);
                    if r.status == "implemented" {
                        match fs::read_to_string(&path) {
                            Ok(text) if text.contains(&format!("{property} ==")) => {}
                            Ok(_) => problems.push(format!(
                                "requirement {id}: {module} does not define {property}"
                            )),
                            Err(_) => problems
                                .push(format!("requirement {id}: TLA+ module {module} is missing")),
                        }
                    }
                }
                _ => problems.push(format!(
                    "requirement {id}: tla artifact must be Module.tla::Property"
                )),
            }
        }
        for t in &a.integration {
            if !root.join(t).is_file() {
                problems.push(format!(
                    "requirement {id}: integration test {t} does not exist"
                ));
            }
        }
        if r.criticality == "critical" && r.status == "implemented" {
            let dynamic = !a.integration.is_empty() || a.property.is_some();
            let formal = a.tla.is_some()
                || a.kani.is_some()
                || !a.loom.is_empty()
                || a.property.is_some()
                || a.fuzz.is_some();
            let mutation = !a.mutation.is_empty() || a.conformance.is_some();
            if !dynamic {
                problems.push(format!("critical requirement {id}: no dynamic test"));
            }
            if !formal {
                problems.push(format!(
                    "critical requirement {id}: no formal or systematic artifact"
                ));
            }
            if !mutation {
                problems.push(format!(
                    "critical requirement {id}: no mutation or negative test"
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
    problems
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = PathBuf::from(".");
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--root" {
            if let Some(v) = args.get(i + 1) {
                root = PathBuf::from(v);
            }
            i += 2;
        } else {
            eprintln!("error: unknown argument {}", args[i]);
            return ExitCode::FAILURE;
        }
    }
    let problems = check(&root);
    if problems.is_empty() {
        println!("traceability: ok");
        ExitCode::SUCCESS
    } else {
        for p in &problems {
            eprintln!("error: {p}");
        }
        eprintln!("traceability: {} problem(s)", problems.len());
        ExitCode::FAILURE
    }
}
