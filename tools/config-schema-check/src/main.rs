//! Canonical config schema check (spec 17, CI 31.1 #15).
//!
//! - every file under `spec/config/examples/` must satisfy `firebase-testd.schema.json` and
//!   the cross-field rules below;
//! - every file under `spec/config/invalid-examples/` must be rejected by at least one of them;
//! - referenced limit catalogs must exist under `spec/limits/`.
//!
//! Cross-field rules (spec 17, 3.5, 8.9.19) that JSON Schema alone cannot express:
//!
//! 1. `standard` edition never combines with `mongodb-compatible` API mode;
//! 2. `limits.catalog` must belong to the configured edition;
//! 3. `limits.queryCatalog` is required (`firestore-standard-query-*`) for Standard and must be
//!    `null` for Enterprise;
//! 4. `pipeline.executionMode = proxy` and `textSearch.fidelity = upstream-proxy` require
//!    `profile = conformance`;
//! 5. `visibilityPolicy = virtual-lag` requires a non-null `visibilityLag`;
//! 6. `fidelity = strict-validation-only` forbids `scorePrecision = exact`.
//!
//! Usage: `config-schema-check [--root <repo root>]`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::Value;

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_str()
}

fn is_null_at(v: &Value, path: &[&str]) -> bool {
    let mut cur = v;
    for key in path {
        match cur.get(key) {
            Some(next) => cur = next,
            None => return true,
        }
    }
    cur.is_null()
}

/// Cross-field rules. Returns every violated rule.
fn cross_field_problems(cfg: &Value, root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let profile = str_at(cfg, &["profile"]).unwrap_or_default();
    let edition = str_at(cfg, &["firestore", "edition"]).unwrap_or_default();
    let api_mode = str_at(cfg, &["firestore", "apiMode"]).unwrap_or_default();

    if edition == "standard" && api_mode == "mongodb-compatible" {
        problems.push("standard edition cannot use the mongodb-compatible API mode".to_owned());
    }

    if let Some(catalog) = str_at(cfg, &["limits", "catalog"]) {
        let expected = match edition {
            "standard" => "firestore-standard-",
            "enterprise" => "firestore-enterprise-native-",
            _ => "",
        };
        if !expected.is_empty() && !catalog.starts_with(expected) {
            problems.push(format!(
                "limits.catalog {catalog} does not belong to edition {edition}"
            ));
        }
        if !root
            .join("spec/limits")
            .join(format!("{catalog}.json"))
            .is_file()
        {
            problems.push(format!(
                "limits.catalog {catalog} has no spec/limits/{catalog}.json"
            ));
        }
    }

    match (edition, str_at(cfg, &["limits", "queryCatalog"])) {
        ("standard", None) => {
            problems.push("standard edition requires limits.queryCatalog".to_owned());
        }
        ("standard", Some(q)) => {
            if !root.join("spec/limits").join(format!("{q}.json")).is_file() {
                problems.push(format!(
                    "limits.queryCatalog {q} has no spec/limits/{q}.json"
                ));
            }
        }
        ("enterprise", Some(q)) => {
            problems.push(format!(
                "enterprise edition must not reuse the Standard query catalog {q}; use null"
            ));
        }
        _ => {}
    }

    if let Some(rules_catalog) = str_at(cfg, &["limits", "rulesCatalog"]) {
        if !root
            .join("spec/limits")
            .join(format!("{rules_catalog}.json"))
            .is_file()
        {
            problems.push(format!(
                "limits.rulesCatalog {rules_catalog} has no spec/limits entry"
            ));
        }
    }

    let pipeline_mode = str_at(cfg, &["firestore", "pipeline", "executionMode"]).unwrap_or("");
    let fidelity = str_at(cfg, &["firestore", "textSearch", "fidelity"]).unwrap_or("");
    if profile != "conformance" {
        if pipeline_mode == "proxy" {
            problems.push("pipeline.executionMode proxy requires profile conformance".to_owned());
        }
        if fidelity == "upstream-proxy" {
            problems
                .push("textSearch.fidelity upstream-proxy requires profile conformance".to_owned());
        }
    }

    if str_at(cfg, &["firestore", "textSearch", "visibilityPolicy"]) == Some("virtual-lag")
        && is_null_at(cfg, &["firestore", "textSearch", "visibilityLag"])
    {
        problems.push("visibilityPolicy virtual-lag requires textSearch.visibilityLag".to_owned());
    }

    if fidelity == "strict-validation-only"
        && str_at(cfg, &["firestore", "textSearch", "scorePrecision"]) == Some("exact")
    {
        problems.push("strict-validation-only cannot declare scorePrecision exact".to_owned());
    }

    problems
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).collect())
        .unwrap_or_default();
    files.retain(|p| {
        p.extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("json"))
    });
    files.sort();
    files
}

fn run(root: &Path) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let schema_path = root.join("spec/config/firebase-testd.schema.json");
    let schema = read_json(&schema_path).map_err(|e| vec![e])?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|e| vec![format!("{}: invalid schema: {e}", schema_path.display())])?;

    let examples = json_files(&root.join("spec/config/examples"));
    if examples.is_empty() {
        problems.push("no config examples found".to_owned());
    }
    for path in &examples {
        let cfg = match read_json(path) {
            Ok(v) => v,
            Err(e) => {
                problems.push(e);
                continue;
            }
        };
        for err in validator.iter_errors(&cfg) {
            problems.push(format!(
                "{}: schema: {err} at {}",
                path.display(),
                err.instance_path
            ));
        }
        for p in cross_field_problems(&cfg, root) {
            problems.push(format!("{}: {p}", path.display()));
        }
    }

    let invalid = json_files(&root.join("spec/config/invalid-examples"));
    for path in &invalid {
        let cfg = match read_json(path) {
            Ok(v) => v,
            Err(e) => {
                problems.push(e);
                continue;
            }
        };
        let schema_rejects = !validator.is_valid(&cfg);
        let rules_reject = !cross_field_problems(&cfg, root).is_empty();
        if !schema_rejects && !rules_reject {
            problems.push(format!(
                "{}: expected rejection but the config was accepted",
                path.display()
            ));
        }
    }

    if problems.is_empty() {
        println!(
            "config schema: ok ({} valid examples, {} invalid examples rejected)",
            examples.len(),
            invalid.len()
        );
        Ok(())
    } else {
        Err(problems)
    }
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
    match run(&root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(problems) => {
            for p in &problems {
                eprintln!("error: {p}");
            }
            ExitCode::FAILURE
        }
    }
}
