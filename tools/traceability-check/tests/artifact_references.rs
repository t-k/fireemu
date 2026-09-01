//! Table-driven fixtures for artifact resolution (TRACE-REF-01..06).
//!
//! Each case builds a throw-away repository root with a minimal ledger plus the artifact files
//! the case needs, runs the checker over it, and asserts on the reported problems and on the
//! pending list. Roots are removed when the case ends, including on an assertion failure.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tla_verification::sha256_file;
use traceability_check::check;

/// A throw-away repository root that removes itself when dropped.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("trace-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn write_ledger(&self, requirement: &Value) {
        self.write_ledger_only(requirement);
        if let Some(tla) = requirement["artifacts"]["tla"].as_str() {
            if !tla.starts_with("pending:") {
                let (module, property) = tla.split_once("::").expect("fixture TLA reference");
                if self.root.join("verification/tla").join(module).is_file()
                    && self
                        .root
                        .join("verification/tla")
                        .join(Path::new(module).with_extension("cfg"))
                        .is_file()
                {
                    self.write_tla_evidence(
                        Path::new(module)
                            .file_stem()
                            .and_then(|stem| stem.to_str())
                            .expect("fixture model"),
                        property,
                        "M-TLA-001",
                        "killed_safety",
                    );
                }
            }
        }
    }

    fn write_ledger_only(&self, requirement: &Value) {
        self.write(
            "verification/mutants/catalog.json",
            &json!({
                "schemaVersion": 1,
                "source": "fixture",
                "mutants": [{"id": "M-FIX-001", "fault": "fixture fault", "critical": false}],
            })
            .to_string(),
        );
        self.write(
            "verification/loom/scenarios.json",
            &json!({"schemaVersion": 1, "source": "fixture", "scenarios": ["fixture_scenario"]})
                .to_string(),
        );
        self.write(
            "verification/requirements/requirements.json",
            &json!({
                "schemaVersion": 1,
                "source": "fixture",
                "requirements": [requirement],
            })
            .to_string(),
        );
    }

    fn write_tla_manifest(&self, model: &str, property: &str, mutation_id: &str) {
        self.write(
            &format!("verification/tla/mutations/{model}.json"),
            &json!({
                "schemaVersion": 1,
                "model": model,
                "mutations": [{
                    "id": mutation_id,
                    "property": property,
                    "operator": "fixture-semantic-defect",
                    "from": "====",
                    "to": "\\* mutated\n====",
                }],
            })
            .to_string(),
        );
        self.write(".tools/tla2tools-1.8.0.jar", "fixture jar");
    }

    fn write_tla_evidence(&self, model: &str, property: &str, mutation_id: &str, outcome: &str) {
        self.write_tla_manifest(model, property, mutation_id);
        let tla_root = self.root.join("verification/tla");
        let evidence = json!({
            "schemaVersion": 1,
            "model": model,
            "generatedAt": "2026-08-31T00:00:00Z",
            "tlcVersion": "TLC fixture",
            "moduleSha256": sha256_file(&tla_root.join(format!("{model}.tla"))).unwrap(),
            "configSha256": sha256_file(&tla_root.join(format!("{model}.cfg"))).unwrap(),
            "manifestSha256": sha256_file(&tla_root.join("mutations").join(format!("{model}.json"))).unwrap(),
            "jarSha256": sha256_file(&self.root.join(".tools/tla2tools-1.8.0.jar")).unwrap(),
            "results": [{
                "id": mutation_id,
                "property": property,
                "outcome": outcome,
                "detail": "fixture outcome",
            }],
        });
        self.write(
            &format!("verification/tla/evidence/{model}.json"),
            &evidence.to_string(),
        );
    }

    fn copy_event_delivery_quint_authority(&self) {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let evidence_relative = "verification/quint/evidence/EventDelivery.json";
        let evidence_text =
            fs::read_to_string(source_root.join(evidence_relative)).expect("source Quint evidence");
        let evidence: Value = serde_json::from_str(&evidence_text).expect("Quint evidence JSON");
        for relative in evidence["boundInputs"]
            .as_array()
            .expect("bound Quint inputs")
            .iter()
            .map(|value| value.as_str().expect("bound input path"))
        {
            let contents = fs::read(source_root.join(relative)).expect("read bound Quint input");
            let destination = self.root.join(relative);
            fs::create_dir_all(destination.parent().expect("bound input parent"))
                .expect("create bound input parent");
            fs::write(destination, contents).expect("copy bound Quint input");
        }
        self.write(evidence_relative, &evidence_text);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A requirement with the evidence every critical implemented requirement needs, so that a case
/// only has to add the artifact it is about.
fn requirement(status: &str, artifacts: &Value) -> Value {
    let mutations = if matches!(status, "implemented" | "partial")
        && artifacts["tla"]
            .as_str()
            .is_some_and(|tla| !tla.starts_with("pending:"))
    {
        json!(["M-FIX-001", "M-TLA-001"])
    } else {
        json!(["M-FIX-001"])
    };
    let mut merged = json!({
        "mutation": mutations,
        "integration": ["crates/fixture/tests/it.rs"],
    });
    let base = merged.as_object_mut().unwrap();
    for (k, v) in artifacts.as_object().unwrap() {
        base.insert(k.clone(), v.clone());
    }
    json!({
        "id": "FIX-001",
        "statement": "fixture statement",
        "criticality": "critical",
        "owner": "fixtures",
        "status": status,
        "artifacts": merged,
    })
}

/// What a case expects from the run.
enum Expect {
    /// The gate fails and at least one problem contains this text.
    Problem(&'static str),
    /// The gate passes and the pending list has exactly this many entries.
    OkWithPending(usize),
}

struct Case {
    name: &'static str,
    status: &'static str,
    artifacts: Value,
    /// Extra files (path, contents) created under the fixture root.
    files: Vec<(&'static str, &'static str)>,
    expect: Expect,
}

const KANI_SOURCE: &str = r"
#[cfg(kani)]
mod harnesses {
    /// A comment mentioning fn ghost_harness() must not resolve.
    #[kani::proof]
    #[kani::unwind(4)]
    fn real_harness() {
        assert!(true);
    }
}
";

const PROPERTY_SOURCE: &str = r"
proptest! {
    #[test]
    fn prop_real_property(x in 0u8..8) {
        prop_assert!(x < 8);
    }
}
";

const TLA_SOURCE: &str = r"---- MODULE Model ----
Safe == TRUE
TemporalSafe == <>TRUE
====
";

#[allow(clippy::too_many_lines)]
fn cases() -> Vec<Case> {
    let integration = ("crates/fixture/tests/it.rs", "#[test] fn it() {}");
    vec![
        // TRACE-REF-01: a missing Kani harness fails validation.
        Case {
            name: "kani-missing",
            status: "implemented",
            artifacts: json!({"kani": "no_such_harness"}),
            files: vec![integration, ("verification/kani/src/lib.rs", KANI_SOURCE)],
            expect: Expect::Problem(
                "kani harness no_such_harness is not a #[kani::proof] function",
            ),
        },
        // A name that appears only in a comment is not a harness.
        Case {
            name: "kani-comment-only",
            status: "implemented",
            artifacts: json!({"kani": "ghost_harness"}),
            files: vec![integration, ("verification/kani/src/lib.rs", KANI_SOURCE)],
            expect: Expect::Problem("kani harness ghost_harness"),
        },
        // TRACE-REF-03: a real harness resolves.
        Case {
            name: "kani-valid",
            status: "implemented",
            artifacts: json!({"kani": "real_harness"}),
            files: vec![integration, ("verification/kani/src/lib.rs", KANI_SOURCE)],
            expect: Expect::OkWithPending(0),
        },
        // TRACE-REF-02: a missing property test fails validation.
        Case {
            name: "property-missing",
            status: "implemented",
            artifacts: json!({"property": "prop_no_such_property"}),
            files: vec![
                integration,
                ("crates/fixture/tests/props.rs", PROPERTY_SOURCE),
            ],
            expect: Expect::Problem(
                "property test prop_no_such_property is not defined in any tests/ source file",
            ),
        },
        // A function outside a tests/ directory is not a property test.
        Case {
            name: "property-outside-tests",
            status: "implemented",
            artifacts: json!({"property": "prop_real_property"}),
            files: vec![integration, ("crates/fixture/src/lib.rs", PROPERTY_SOURCE)],
            expect: Expect::Problem("property test prop_real_property is not defined"),
        },
        // TRACE-REF-03: a real property test resolves.
        Case {
            name: "property-valid",
            status: "implemented",
            artifacts: json!({"property": "prop_real_property"}),
            files: vec![
                integration,
                ("crates/fixture/tests/props.rs", PROPERTY_SOURCE),
            ],
            expect: Expect::OkWithPending(0),
        },
        // A property definition is not evidence unless the same-stem cfg checks it.
        Case {
            name: "tla-property-not-configured",
            status: "implemented",
            artifacts: json!({"tla": "Model.tla::Safe"}),
            files: vec![
                integration,
                ("verification/tla/Model.tla", TLA_SOURCE),
                ("verification/tla/Model.cfg", "INIT Init\nNEXT Next\n"),
            ],
            expect: Expect::Problem("Model.cfg does not register Safe"),
        },
        // Comments and constant assignments never register a property.
        Case {
            name: "tla-property-comment-only",
            status: "implemented",
            artifacts: json!({"tla": "Model.tla::Safe"}),
            files: vec![
                integration,
                ("verification/tla/Model.tla", TLA_SOURCE),
                (
                    "verification/tla/Model.cfg",
                    "\\* INVARIANT Safe\nCONSTANTS NamedProperty = Safe\n",
                ),
            ],
            expect: Expect::Problem("Model.cfg does not register Safe"),
        },
        // Singular same-line directives are supported by TLC and by the gate.
        Case {
            name: "tla-singular-same-line",
            status: "implemented",
            artifacts: json!({"tla": "Model.tla::TemporalSafe"}),
            files: vec![
                integration,
                ("verification/tla/Model.tla", TLA_SOURCE),
                ("verification/tla/Model.cfg", "PROPERTY TemporalSafe\n"),
            ],
            expect: Expect::OkWithPending(0),
        },
        // Plural directives may list property names on following lines.
        Case {
            name: "tla-plural-multiline",
            status: "implemented",
            artifacts: json!({"tla": "Model.tla::Safe"}),
            files: vec![
                integration,
                ("verification/tla/Model.tla", TLA_SOURCE),
                (
                    "verification/tla/Model.cfg",
                    "INVARIANTS\n  Safe\nPROPERTIES\n  TemporalSafe\n",
                ),
            ],
            expect: Expect::OkWithPending(0),
        },
        Case {
            name: "tla-same-stem-config-missing",
            status: "implemented",
            artifacts: json!({"tla": "Model.tla::Safe"}),
            files: vec![
                integration,
                ("verification/tla/Model.tla", TLA_SOURCE),
                ("verification/tla/Other.cfg", "INVARIANT Safe\n"),
            ],
            expect: Expect::Problem("TLA+ config Model.cfg is missing"),
        },
        Case {
            name: "tla-unsafe-module-path",
            status: "implemented",
            artifacts: json!({"tla": "../Model.tla::Safe"}),
            files: vec![integration],
            expect: Expect::Problem("tla artifact must be Module.tla::Property"),
        },
        // TRACE-REF-05: a missing fuzz target fails validation.
        Case {
            name: "fuzz-missing",
            status: "implemented",
            artifacts: json!({"fuzz": "no_such_target"}),
            files: vec![integration],
            expect: Expect::Problem(
                "fuzz target no_such_target has no fuzz/fuzz_targets/no_such_target.rs",
            ),
        },
        // TRACE-REF-03: a real fuzz target resolves.
        Case {
            name: "fuzz-valid",
            status: "implemented",
            artifacts: json!({"fuzz": "parse_rules"}),
            files: vec![
                integration,
                (
                    "crates/fixture/fuzz/fuzz_targets/parse_rules.rs",
                    "// target",
                ),
            ],
            expect: Expect::OkWithPending(0),
        },
        // TRACE-REF-05: a missing conformance artifact fails validation.
        Case {
            name: "conformance-missing",
            status: "implemented",
            artifacts: json!({"conformance": "verification/conformance/rules"}),
            files: vec![integration],
            expect: Expect::Problem(
                "conformance artifact verification/conformance/rules does not exist",
            ),
        },
        // TRACE-REF-03: a real conformance artifact resolves.
        // A conformance artifact is mutation evidence, not a formal artifact: a `partial`
        // requirement carries it without the critical implemented gate applying.
        Case {
            name: "conformance-valid",
            status: "partial",
            artifacts: json!({"conformance": "verification/conformance/rules/cases.json"}),
            files: vec![
                integration,
                ("verification/conformance/rules/cases.json", "[]"),
            ],
            expect: Expect::OkWithPending(0),
        },
        // TRACE-REF-04: a pending artifact is not evidence for a critical implemented gate.
        Case {
            name: "pending-is-not-formal-evidence",
            status: "implemented",
            artifacts: json!({"kani": "pending:future_harness"}),
            files: vec![integration],
            expect: Expect::Problem(
                "critical requirement FIX-001: no resolved formal or systematic artifact",
            ),
        },
        // TRACE-REF-06: a partial requirement may hold pending artifacts; they are reported.
        Case {
            name: "pending-on-partial-is-reported",
            status: "partial",
            artifacts: json!({
                "kani": "pending:future_harness",
                "property": "pending:prop_future",
                "fuzz": "pending:future_target",
                "conformance": "pending:verification/conformance/future",
                "tla": "pending:Future.tla::FutureProperty",
            }),
            files: vec![integration],
            expect: Expect::OkWithPending(5),
        },
        // A pending marker without a name is a malformed reference, not a free pass.
        Case {
            name: "pending-without-a-name",
            status: "partial",
            artifacts: json!({"kani": "pending:"}),
            files: vec![integration],
            expect: Expect::Problem("requirement FIX-001: empty kani artifact"),
        },
        // A planned requirement describes artifacts that do not exist yet.
        Case {
            name: "planned-artifacts-are-not-resolved",
            status: "planned",
            artifacts: json!({"kani": "future_harness", "property": "prop_future"}),
            files: vec![integration],
            expect: Expect::OkWithPending(0),
        },
        // A partial requirement resolves its artifacts like an implemented one.
        Case {
            name: "partial-artifacts-are-resolved",
            status: "partial",
            artifacts: json!({"kani": "no_such_harness"}),
            files: vec![integration],
            expect: Expect::Problem("requirement FIX-001: kani harness no_such_harness"),
        },
        // An empty artifact string never resolves.
        Case {
            name: "empty-property",
            status: "implemented",
            artifacts: json!({"property": "   "}),
            files: vec![integration],
            expect: Expect::Problem("requirement FIX-001: empty property artifact"),
        },
        // A missing integration test fails whatever the status.
        Case {
            name: "integration-missing",
            status: "planned",
            artifacts: json!({}),
            files: vec![],
            expect: Expect::Problem("integration test crates/fixture/tests/it.rs does not exist"),
        },
    ]
}

#[test]
fn artifact_references_resolve_or_fail_per_category() {
    for case in cases() {
        let fixture = Fixture::new(case.name);
        for (path, contents) in &case.files {
            fixture.write(path, contents);
        }
        fixture.write_ledger(&requirement(case.status, &case.artifacts));
        let report = check(&fixture.root);
        match case.expect {
            Expect::Problem(text) => {
                assert!(
                    report.problems.iter().any(|p| p.contains(text)),
                    "case {}: expected a problem containing {text:?}, got {:?}",
                    case.name,
                    report.problems
                );
            }
            Expect::OkWithPending(count) => {
                assert!(
                    report.problems.is_empty(),
                    "case {}: expected no problems, got {:?}",
                    case.name,
                    report.problems
                );
                assert_eq!(
                    report.pending.len(),
                    count,
                    "case {}: pending list {:?}",
                    case.name,
                    report.pending
                );
            }
        }
    }
}

#[test]
fn the_repository_ledger_matches_the_repository() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let report = check(root);
    assert!(
        report.problems.is_empty(),
        "the repository ledger does not match the repository: {:?}",
        report.problems
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn tla_backed_requirements_need_fresh_killed_property_mutations() {
    struct EvidenceCase {
        name: &'static str,
        mutation_ids: &'static [&'static str],
        evidence_property: &'static str,
        outcome: Option<&'static str>,
        stale_config: bool,
        expected: Option<&'static str>,
    }

    let cases = [
        EvidenceCase {
            name: "tla-evidence-valid",
            mutation_ids: &["M-FIX-001", "M-TLA-001"],
            evidence_property: "Safe",
            outcome: Some("killed_safety"),
            stale_config: false,
            expected: None,
        },
        EvidenceCase {
            name: "tla-evidence-missing",
            mutation_ids: &["M-FIX-001", "M-TLA-001"],
            evidence_property: "Safe",
            outcome: None,
            stale_config: false,
            expected: Some("mutation evidence"),
        },
        EvidenceCase {
            name: "tla-evidence-stale",
            mutation_ids: &["M-FIX-001", "M-TLA-001"],
            evidence_property: "Safe",
            outcome: Some("killed_safety"),
            stale_config: true,
            expected: Some("config digest mismatch"),
        },
        EvidenceCase {
            name: "tla-evidence-unreferenced",
            mutation_ids: &["M-FIX-001"],
            evidence_property: "Safe",
            outcome: Some("killed_safety"),
            stale_config: false,
            expected: Some("no referenced killed TLA mutation for property Safe"),
        },
        EvidenceCase {
            name: "tla-evidence-property-mismatch",
            mutation_ids: &["M-FIX-001", "M-TLA-001"],
            evidence_property: "OtherSafe",
            outcome: Some("killed_safety"),
            stale_config: false,
            expected: Some("no referenced killed TLA mutation for property Safe"),
        },
        EvidenceCase {
            name: "tla-evidence-survived",
            mutation_ids: &["M-FIX-001", "M-TLA-001"],
            evidence_property: "Safe",
            outcome: Some("survived"),
            stale_config: false,
            expected: Some("was not killed"),
        },
    ];

    for case in cases {
        let fixture = Fixture::new(case.name);
        fixture.write("crates/fixture/tests/it.rs", "#[test] fn it() {}");
        fixture.write("verification/tla/Model.tla", TLA_SOURCE);
        fixture.write("verification/tla/Model.cfg", "INVARIANT Safe\n");
        let requirement = json!({
            "id": "FIX-001",
            "statement": "fixture statement",
            "criticality": "critical",
            "owner": "fixtures",
            "status": "implemented",
            "artifacts": {
                "tla": "Model.tla::Safe",
                "mutation": case.mutation_ids,
                "integration": ["crates/fixture/tests/it.rs"],
            },
        });
        fixture.write_ledger_only(&requirement);
        if let Some(outcome) = case.outcome {
            fixture.write_tla_evidence("Model", case.evidence_property, "M-TLA-001", outcome);
        } else {
            fixture.write_tla_manifest("Model", case.evidence_property, "M-TLA-001");
        }
        if case.stale_config {
            fixture.write(
                "verification/tla/Model.cfg",
                "INVARIANT Safe\n\\* changed\n",
            );
        }

        let report = check(&fixture.root);
        match case.expected {
            None => assert!(
                report.problems.is_empty(),
                "case {}: {:?}",
                case.name,
                report.problems
            ),
            Some(expected) => assert!(
                report
                    .problems
                    .iter()
                    .any(|problem| problem.contains(expected)),
                "case {}: expected {expected:?}, got {:?}",
                case.name,
                report.problems
            ),
        }
    }
}

#[test]
fn quint_backed_requirements_need_safe_fresh_killed_property_evidence() {
    #[derive(Clone, Copy)]
    enum Change {
        None,
        MissingSpec,
        MissingEvidence,
        StaleSpec,
        StaleManifest,
        Survived,
        PropertyMismatch,
        UnknownEvidenceField,
    }

    struct EvidenceCase {
        name: &'static str,
        reference: &'static str,
        mutation_ids: &'static [&'static str],
        change: Change,
        expected: Option<&'static str>,
    }

    let cases = [
        EvidenceCase {
            name: "quint-evidence-valid",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::None,
            expected: None,
        },
        EvidenceCase {
            name: "quint-unsafe-path",
            reference: "../EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::None,
            expected: Some("quint artifact must be Model.qnt::Property"),
        },
        EvidenceCase {
            name: "quint-property-unregistered",
            reference: "EventDelivery.qnt::UnknownProperty",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::None,
            expected: Some("does not register UnknownProperty"),
        },
        EvidenceCase {
            name: "quint-spec-missing",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::MissingSpec,
            expected: Some("Quint spec EventDelivery.qnt is missing"),
        },
        EvidenceCase {
            name: "quint-evidence-missing",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::MissingEvidence,
            expected: Some("Quint evidence for EventDelivery is invalid"),
        },
        EvidenceCase {
            name: "quint-spec-stale",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::StaleSpec,
            expected: Some("digest mismatch for verification/quint/specs/EventDelivery.qnt"),
        },
        EvidenceCase {
            name: "quint-manifest-stale",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::StaleManifest,
            expected: Some("mutation manifest"),
        },
        EvidenceCase {
            name: "quint-mutant-survived",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::Survived,
            expected: Some("is not killed"),
        },
        EvidenceCase {
            name: "quint-property-mismatch",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::PropertyMismatch,
            expected: Some("mutation evidence mismatch"),
        },
        EvidenceCase {
            name: "quint-unknown-evidence-field",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001", "M-TLA-EVENT-LEGAL-001"],
            change: Change::UnknownEvidenceField,
            expected: Some("unknown field"),
        },
        EvidenceCase {
            name: "quint-unreferenced-kill",
            reference: "EventDelivery.qnt::LegalStateTransitions",
            mutation_ids: &["M-FIX-001"],
            change: Change::None,
            expected: Some(
                "no referenced killed Quint mutation for property LegalStateTransitions",
            ),
        },
    ];

    for case in cases {
        let fixture = Fixture::new(case.name);
        fixture.copy_event_delivery_quint_authority();
        let requirement = json!({
            "id": "FIX-001",
            "statement": "fixture statement",
            "criticality": "critical",
            "owner": "fixtures",
            "status": "implemented",
            "artifacts": {
                "quint": case.reference,
                "mutation": case.mutation_ids,
                "integration": ["verification/quint/tests/event_delivery_connect.rs"],
            },
        });
        fixture.write_ledger_only(&requirement);

        let spec = fixture
            .root
            .join("verification/quint/specs/EventDelivery.qnt");
        let manifest = fixture
            .root
            .join("verification/quint/mutations/EventDelivery.json");
        let evidence_path = fixture
            .root
            .join("verification/quint/evidence/EventDelivery.json");
        match case.change {
            Change::None => {}
            Change::MissingSpec => fs::remove_file(spec).expect("remove owned spec"),
            Change::MissingEvidence => {
                fs::remove_file(evidence_path).expect("remove owned evidence");
            }
            Change::StaleSpec => fs::write(spec, "// stale\n").expect("change owned spec"),
            Change::StaleManifest => {
                fs::write(manifest, "{}\n").expect("change owned manifest");
            }
            Change::Survived | Change::PropertyMismatch | Change::UnknownEvidenceField => {
                let text = fs::read_to_string(&evidence_path).expect("read owned evidence");
                let mut evidence: Value = serde_json::from_str(&text).expect("evidence JSON");
                match case.change {
                    Change::Survived => evidence["mutations"][2]["outcome"] = "survived".into(),
                    Change::PropertyMismatch => {
                        evidence["mutations"][2]["property"] = "AttemptsBounded".into();
                    }
                    Change::UnknownEvidenceField => evidence["unknown"] = true.into(),
                    _ => unreachable!(),
                }
                fixture.write(
                    "verification/quint/evidence/EventDelivery.json",
                    &evidence.to_string(),
                );
            }
        }

        let report = check(&fixture.root);
        match case.expected {
            None => assert!(
                report.problems.is_empty(),
                "case {}: {:?}",
                case.name,
                report.problems
            ),
            Some(expected) => assert!(
                report
                    .problems
                    .iter()
                    .any(|problem| problem.contains(expected)),
                "case {}: expected {expected:?}, got {:?}",
                case.name,
                report.problems
            ),
        }
    }
}
