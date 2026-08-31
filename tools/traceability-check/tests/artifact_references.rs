//! Table-driven fixtures for artifact resolution (TRACE-REF-01..06).
//!
//! Each case builds a throw-away repository root with a minimal ledger plus the artifact files
//! the case needs, runs the checker over it, and asserts on the reported problems and on the
//! pending list. Roots are removed when the case ends, including on an assertion failure.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A requirement with the evidence every critical implemented requirement needs, so that a case
/// only has to add the artifact it is about.
fn requirement(status: &str, artifacts: &Value) -> Value {
    let mut merged = json!({
        "mutation": ["M-FIX-001"],
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
