//! Freshness and completeness tests for mutation evidence.

use std::fs;
use std::path::{Path, PathBuf};

use tla_verification::{sha256_file, verify_evidence};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("evidence-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create fixture");
        Self { root }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, contents).expect("write fixture");
        path
    }

    fn evidence_json(&self, results: &str) -> String {
        format!(
            r#"{{
                "schemaVersion": 1,
                "model": "Model",
                "generatedAt": "2026-08-31T00:00:00Z",
                "tlcVersion": "TLC fixture",
                "moduleSha256": "{}",
                "configSha256": "{}",
                "manifestSha256": "{}",
                "jarSha256": "{}",
                "results": {results}
            }}"#,
            sha256_file(&self.root.join("Model.tla")).expect("module digest"),
            sha256_file(&self.root.join("Model.cfg")).expect("config digest"),
            sha256_file(&self.root.join("Model.json")).expect("manifest digest"),
            sha256_file(&self.root.join("tla2tools.jar")).expect("jar digest"),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn prepare(name: &str) -> Fixture {
    let fixture = Fixture::new(name);
    fixture.write("Model.tla", "---- MODULE Model ----\nSafe == TRUE\n====\n");
    fixture.write("Model.cfg", "INVARIANT Safe\n");
    fixture.write(
        "Model.json",
        r#"{
            "schemaVersion": 1,
            "model": "Model",
            "mutations": [
                {"id":"M-MODEL-001","property":"Safe","operator":"one","from":"TRUE","to":"FALSE"},
                {"id":"M-MODEL-002","property":"Safe","operator":"two","from":"Safe ==","to":"Safe /= "}
            ]
        }"#,
    );
    fixture.write("tla2tools.jar", "jar");
    fixture
}

fn paths(fixture: &Fixture) -> [PathBuf; 5] {
    [
        fixture.root.join("Model.tla"),
        fixture.root.join("Model.cfg"),
        fixture.root.join("Model.json"),
        fixture.root.join("tla2tools.jar"),
        fixture.root.join("evidence.json"),
    ]
}

#[test]
fn fresh_complete_killed_evidence_verifies() {
    let fixture = prepare("fresh");
    fixture.write(
        "evidence.json",
        &fixture.evidence_json(
            r#"[
                {"id":"M-MODEL-001","property":"Safe","outcome":"killed_safety","detail":"counterexample"},
                {"id":"M-MODEL-002","property":"Safe","outcome":"killed_temporal","detail":"temporal counterexample"}
            ]"#,
        ),
    );
    let [module, config, manifest, jar, evidence] = paths(&fixture);

    verify_evidence(&module, &config, &manifest, &jar, &evidence).expect("fresh evidence");
}

#[test]
fn every_input_digest_is_checked() {
    for changed in ["Model.tla", "Model.cfg", "Model.json", "tla2tools.jar"] {
        let fixture = prepare(changed);
        fixture.write(
            "evidence.json",
            &fixture.evidence_json(
                r#"[
                    {"id":"M-MODEL-001","property":"Safe","outcome":"killed_safety","detail":"counterexample"},
                    {"id":"M-MODEL-002","property":"Safe","outcome":"killed_safety","detail":"counterexample"}
                ]"#,
            ),
        );
        fixture.write(changed, "changed after evidence");
        let [module, config, manifest, jar, evidence] = paths(&fixture);

        let error = verify_evidence(&module, &config, &manifest, &jar, &evidence)
            .expect_err("stale evidence");
        assert!(error.contains("digest mismatch"), "{changed}: {error}");
    }
}

#[test]
fn missing_extra_or_property_mismatched_results_are_rejected() {
    let cases = [
        (
            "missing",
            r#"[{"id":"M-MODEL-001","property":"Safe","outcome":"killed_safety","detail":"counterexample"}]"#,
        ),
        (
            "extra",
            r#"[
                {"id":"M-MODEL-001","property":"Safe","outcome":"killed_safety","detail":"counterexample"},
                {"id":"M-MODEL-002","property":"Safe","outcome":"killed_safety","detail":"counterexample"},
                {"id":"M-MODEL-003","property":"Safe","outcome":"killed_safety","detail":"counterexample"}
            ]"#,
        ),
        (
            "property",
            r#"[
                {"id":"M-MODEL-001","property":"Wrong","outcome":"killed_safety","detail":"counterexample"},
                {"id":"M-MODEL-002","property":"Safe","outcome":"killed_safety","detail":"counterexample"}
            ]"#,
        ),
    ];

    for (name, results) in cases {
        let fixture = prepare(name);
        fixture.write("evidence.json", &fixture.evidence_json(results));
        let [module, config, manifest, jar, evidence] = paths(&fixture);
        assert!(verify_evidence(&module, &config, &manifest, &jar, &evidence).is_err());
    }
}
