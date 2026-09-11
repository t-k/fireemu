//! Conservative claims, reference integrity and generated-document regression tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use compat_check::inventory::{check, generate};
use serde_json::{json, Value};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "inventory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let f = Self(root);
        f.write("Cargo.toml", "[workspace.package]\nversion = \"0.7.0\"\n");
        f.json("conformance/package.json", json!({"dependencies":{"firebase":"12.18.0","firebase-admin":"14.3.0","firebase-tools":"15.28.2"}}));
        f.json("spec/compatibility/contract.json", json!({"profiles":{"strict":{},"emulator":{}},"surfaces":[{"claims":[{"id":"CLAIM","capabilities":[{"id":"CAP","status":"implemented"}]}]}]}));
        f.json("crates/fireemu/src/capabilities.json", json!({"CAP":{"status":"implemented","notes":["A | table <tag>\nnext line"],"unimplemented":["External delivery"]}}));
        f.json("verification/requirements/requirements.json", json!({"requirements":[{"id":"REQ","status":"implemented","statement":"A requirement","artifacts":{"tests":["some_test"]}}]}));
        f.json("spec/compatibility/inventory.json", json!({
            "schemaVersion":1,"target":"source-tree","inventoryStatus":"incomplete",
            "goals":["AUTH-CORE","AUTH-IP-MAIN","FS-STD-NATIVE","FS-ENT-NATIVE","FS-MONGODB","FS-ADMIN","FS-SDK","MANAGED-SERVICE-BOUNDARY"],
            "profiles":["strict","emulator"],"evidence":[],
            "debt":["Full source enumeration and version-bound run receipts remain open."]
        }));
        f.json("spec/compatibility/sources/index.json", json!({"schemaVersion":1,"sources":[{
            "id":"SOURCE","url":"https://firebase.google.com/docs/auth/web/totp-mfa",
            "kind":"guide","language":"en","review":"discovered",
            "sections":[{"id":"entry","classification":"unknown","reason":"Awaiting section review","requirements":[]}]
        }]}));
        f.json(
            "spec/compatibility/surfaces/index.json",
            json!({"schemaVersion":1,"surfaces":[{
                "id":"SURFACE","source":"SOURCE","locator":"mfaEnrollment:start",
                "kind":"method","transport":"REST","classification":"requirement",
                "reason":"Local requirement mapping only","requirements":["REQ"]
            }]}),
        );
        f.json(
            "spec/compatibility/features.json",
            json!({"schemaVersion":1,"features":[{
                "id":"FEATURE","title":"Example feature","goal":"AUTH-IP-MAIN",
                "appliesTo":"Identity Platform; configured project; REST",
                "sources":["SOURCE"],"surfaces":["SURFACE"],"requirements":["REQ"],
                "capabilities":["CAP"],"claims":["CLAIM"],
                "limitations":["Exact production behavior is not attested."]
            }]}),
        );
        f.write("docs/compatibility/evidence-note.md", "evidence\n");
        f.json(
            "spec/compatibility/gaps.json",
            json!({"schemaVersion":1,"policy":"Filing is not closure.","gaps":[{
                "id":"GAP-1","feature":"FEATURE","kind":"unobserved",
                "scope":"Something not yet observed.",
                "implementationStatus":"implemented","localTestStatus":"passing",
                "productionObservationStatus":"none","comparisonStatus":"none",
                "evidenceRefs":["docs/compatibility/evidence-note.md"],
                "nextAction":"Observe it.","blockedReason":"","requiresProductionChange":false
            }]}),
        );
        f
    }
    fn write(&self, path: &str, value: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }
    #[allow(clippy::needless_pass_by_value)]
    fn json(&self, path: &str, value: Value) {
        self.write(path, &value.to_string());
    }
    fn mutate(&self, path: &str, change: impl FnOnce(&mut Value)) {
        let mut value: Value =
            serde_json::from_str(&fs::read_to_string(self.0.join(path)).unwrap()).unwrap();
        change(&mut value);
        self.json(path, value);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn aggregation_slice_link_does_not_promote_broad_labels() {
    let f = Fixture::new();
    f.mutate("spec/compatibility/features.json", |v| {
        v["features"][0]["id"] = json!("FS-AGGREGATIONS");
    });
    f.mutate("spec/compatibility/gaps.json", |v| {
        v["gaps"][0]["feature"] = json!("FS-AGGREGATIONS");
    });
    generate(&f.0).unwrap();
    let page = fs::read_to_string(f.0.join("docs/compatibility/authentication.md")).unwrap();
    assert!(page.contains("(aggregation-evidence.md)"));
    assert!(page.contains("Not attested | Not attested | Not attested"));
}

#[test]
fn auth_observation_link_does_not_promote_broad_labels() {
    let f = Fixture::new();
    f.mutate("spec/compatibility/features.json", |v| {
        v["features"][0]["id"] = json!("AUTH-USERS");
    });
    f.mutate("spec/compatibility/gaps.json", |v| {
        v["gaps"][0]["feature"] = json!("AUTH-USERS");
    });
    generate(&f.0).unwrap();
    let page = fs::read_to_string(f.0.join("docs/compatibility/authentication.md")).unwrap();
    assert!(page.contains("(auth-basic-evidence.md)"));
    assert!(page.contains("(auth-basic-v2.md)"));
    assert!(page.contains("(auth-basic-v2-approval.md)"));
    assert!(page.contains("(auth-profile.md)"));
    assert!(page.contains("(auth-profile-approval.md)"));
    assert!(page.contains("(auth-display-name.md)"));
    assert!(page.contains("(auth-display-name-approval.md)"));
    assert!(page.contains("(auth-password.md)"));
    assert!(page.contains("(auth-password-approval.md)"));
    assert!(page.contains("(auth-session-token.md)"));
    assert!(page.contains("(auth-session-v2.md)"));
    assert!(page.contains("(auth-session-v2-approval.md)"));
    assert!(page.contains("(auth-session-continuity.md)"));
    assert!(page.contains("(auth-session-continuity-approval.md)"));
    assert!(page.contains("(auth-password-rejection.md)"));
    assert!(page.contains("(auth-password-rejection-approval.md)"));
    assert!(page.contains("(auth-password-minimum.md)"));
    assert!(page.contains("(auth-password-minimum-approval.md)"));
    assert!(page.contains("(auth-password-maximum.md)"));
    assert!(page.contains("(auth-password-maximum-approval.md)"));
    assert!(page.contains("acquisition-time candidate status"));
    assert!(page.contains("Not attested | Not attested | Not attested"));
}

#[test]
fn generated_matrix_separates_implementation_from_execution() {
    let f = Fixture::new();
    generate(&f.0).unwrap();
    assert!(check(&f.0).is_ok());
    let page = fs::read_to_string(f.0.join("docs/compatibility/authentication.md")).unwrap();
    assert!(page.contains("Implemented, unverified"));
    assert!(page.contains("Not attested"));
    assert!(page.contains("External delivery"));
    assert!(page.contains("&#124;"));
    assert!(!page.contains("<tag>"));
    assert!(!page.contains("Verified |"));
    let overview = fs::read_to_string(f.0.join("docs/compatibility/README.md")).unwrap();
    assert!(overview.contains("FS-MONGODB"));
    assert!(overview.contains("incomplete"));
    assert!(overview.contains("not a release attestation"));
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the mutation table beside its common invariant checks.
fn inventory_mutations_cannot_turn_mapping_into_verification() {
    type Mutation = (&'static str, &'static str, fn(&mut Value));
    let mutations: &[Mutation] = &[
        ("schema", "inventory.json", |v| {
            v["schemaVersion"] = json!(2);
        }),
        ("missing goal", "inventory.json", |v| {
            v["goals"].as_array_mut().unwrap().pop();
        }),
        ("release claim", "inventory.json", |v| {
            v["target"] = json!("release");
        }),
        ("false completeness", "inventory.json", |v| {
            v["inventoryStatus"] = json!("complete");
        }),
        ("unknown profile", "inventory.json", |v| {
            v["profiles"] = json!(["made-up"]);
        }),
        ("zero execution", "inventory.json", |v| {
            v["evidence"] = json!([{"status":"passed","executed":0}]);
        }),
        ("unbound execution", "inventory.json", |v| {
            v["evidence"] = json!([{"status":"passed","executed":1}]);
        }),
        ("unknown field", "inventory.json", |v| {
            v["verified"] = json!(true);
        }),
        ("unknown requirement", "features.json", |v| {
            v["features"][0]["requirements"] = json!(["MISSING"]);
        }),
        ("unknown capability", "features.json", |v| {
            v["features"][0]["capabilities"] = json!(["MISSING"]);
        }),
        ("unknown claim", "features.json", |v| {
            v["features"][0]["claims"] = json!(["MISSING"]);
        }),
        ("unknown source", "features.json", |v| {
            v["features"][0]["sources"] = json!(["MISSING"]);
        }),
        ("unknown surface", "features.json", |v| {
            v["features"][0]["surfaces"] = json!(["MISSING"]);
        }),
        ("unknown goal", "features.json", |v| {
            v["features"][0]["goal"] = json!("MISSING");
        }),
        ("gap names an unknown feature", "gaps.json", |v| {
            v["gaps"][0]["feature"] = json!("MISSING");
        }),
        ("gap comparison without an observation", "gaps.json", |v| {
            v["gaps"][0]["comparisonStatus"] = json!("matches-in-scope");
        }),
        ("gap fixed without passing tests", "gaps.json", |v| {
            v["gaps"][0]["implementationStatus"] = json!("fixed");
            v["gaps"][0]["localTestStatus"] = json!("none");
        }),
        ("gap evidence that does not exist", "gaps.json", |v| {
            v["gaps"][0]["evidenceRefs"] = json!(["docs/compatibility/missing.md"]);
        }),
        ("gap with an invented status", "gaps.json", |v| {
            v["gaps"][0]["productionObservationStatus"] = json!("verified");
        }),
        ("duplicate feature", "features.json", |v| {
            let row = v["features"][0].clone();
            v["features"].as_array_mut().unwrap().push(row);
        }),
        ("duplicate source", "sources/index.json", |v| {
            let row = v["sources"][0].clone();
            v["sources"].as_array_mut().unwrap().push(row);
        }),
        ("invented review", "sources/index.json", |v| {
            v["sources"][0]["review"] = json!("reviewed");
        }),
        ("bad review", "sources/index.json", |v| {
            v["sources"][0]["review"] = json!("verified");
        }),
        ("bad url", "sources/index.json", |v| {
            v["sources"][0]["url"] = json!("javascript:alert(1)");
        }),
        ("table delimiter in url", "sources/index.json", |v| {
            v["sources"][0]["url"] = json!("https://firebase.google.com/docs/auth|shift");
        }),
        ("control character in url", "sources/index.json", |v| {
            v["sources"][0]["url"] = json!("https://firebase.google.com/docs/auth\u{0}");
        }),
        ("missing classification", "sources/index.json", |v| {
            v["sources"][0]["sections"][0]
                .as_object_mut()
                .unwrap()
                .remove("classification");
        }),
        ("empty reason", "sources/index.json", |v| {
            v["sources"][0]["sections"][0]["reason"] = json!(" ");
        }),
        ("unknown section requirement", "sources/index.json", |v| {
            v["sources"][0]["sections"][0]["requirements"] = json!(["MISSING"]);
        }),
        ("unclassified mapping", "surfaces/index.json", |v| {
            v["surfaces"][0]["classification"] = json!("unknown");
        }),
        ("empty mapping", "surfaces/index.json", |v| {
            v["surfaces"][0]["requirements"] = json!([]);
        }),
        ("unknown transport", "surfaces/index.json", |v| {
            v["surfaces"][0]["transport"] = json!("magic");
        }),
        ("unknown surface source", "surfaces/index.json", |v| {
            v["surfaces"][0]["source"] = json!("MISSING");
        }),
        ("wrong array type", "features.json", |v| {
            v["features"][0]["requirements"] = json!("REQ");
        }),
    ];
    for (name, path, mutation) in mutations {
        let f = Fixture::new();
        generate(&f.0).unwrap();
        let before = fs::read(f.0.join("docs/compatibility/README.md")).unwrap();
        f.mutate(&format!("spec/compatibility/{path}"), mutation);
        assert!(generate(&f.0).is_err(), "accepted mutation: {name}");
        assert!(!check(&f.0).is_ok(), "check accepted mutation: {name}");
        assert_eq!(
            before,
            fs::read(f.0.join("docs/compatibility/README.md")).unwrap(),
            "invalid input wrote output: {name}"
        );
    }
}

#[test]
fn missing_or_edited_generated_pages_fail_read_only_checks() {
    let f = Fixture::new();
    generate(&f.0).unwrap();
    let path = f.0.join("docs/compatibility/sources.md");
    fs::write(&path, "manually claimed verified").unwrap();
    assert!(!check(&f.0).is_ok());
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "manually claimed verified"
    );
    generate(&f.0).unwrap();
    let before = fs::read(&path).unwrap();
    generate(&f.0).unwrap();
    assert_eq!(before, fs::read(&path).unwrap());
    fs::remove_file(&path).unwrap();
    assert!(!check(&f.0).is_ok());
    assert!(!path.exists());
}

#[test]
fn new_requirements_remain_visible_as_mapping_debt() {
    let f = Fixture::new();
    f.mutate("verification/requirements/requirements.json", |v| {
        v["requirements"].as_array_mut().unwrap().push(json!({"id":"UNMAPPED","statement":"Pending mapping","status":"planned","artifacts":{}}));
    });
    generate(&f.0).unwrap();
    let page = fs::read_to_string(f.0.join("docs/compatibility/requirements.md")).unwrap();
    assert!(page.contains("UNMAPPED"));
    assert!(page.contains("Unmapped"));
}

#[test]
fn absent_requirement_mapping_is_unknown_not_zero_unfinished() {
    let f = Fixture::new();
    f.mutate("spec/compatibility/features.json", |v| {
        v["features"][0]["requirements"] = json!([]);
    });
    generate(&f.0).unwrap();
    let page = fs::read_to_string(f.0.join("docs/compatibility/authentication.md")).unwrap();
    assert!(page.contains("| 0 / unknown |"));
}

#[test]
fn repository_inventory_is_current() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let report = check(&root);
    assert!(report.is_ok(), "{}", report.problems.join("\n"));
}

#[test]
fn validation_and_fixture_capabilities_never_become_local_execution_labels() {
    for (precision, label) in [
        ("strict-validation-only", "Validation only"),
        ("fixture-idp", "Mock/fixture only"),
    ] {
        let f = Fixture::new();
        f.mutate("crates/fireemu/src/capabilities.json", |v| {
            v["CAP"]["precision"] = json!(precision);
        });
        generate(&f.0).unwrap();
        let page = fs::read_to_string(f.0.join("docs/compatibility/authentication.md")).unwrap();
        assert!(page.contains(label), "missing {label}");
        assert!(!page.contains("Implemented, unverified"));
    }
}

#[test]
fn bounded_capability_model_never_strengthens_execution_claims() {
    // Exhaust the two-capability abstraction: three statuses and three precision classes.
    // This checks the projection only, not runtime Firebase equivalence.
    let states = ["implemented", "partial", "unsupported"];
    let precisions = ["local", "strict-validation-only", "fixture-idp"];
    for left in states {
        for right in states {
            for left_precision in precisions {
                for right_precision in precisions {
                    let f = Fixture::new();
                    f.mutate("crates/fireemu/src/capabilities.json", |v| {
                        v["CAP"]["status"] = json!(left);
                        v["CAP"]["precision"] = json!(left_precision);
                        v["CAP2"] = json!({"status":right,"precision":right_precision});
                    });
                    f.mutate("spec/compatibility/contract.json", |v| {
                        v["surfaces"][0]["claims"][0]["capabilities"] = json!([
                            {"id":"CAP","status":left},{"id":"CAP2","status":right}
                        ]);
                    });
                    f.mutate("spec/compatibility/features.json", |v| {
                        v["features"][0]["capabilities"] = json!(["CAP", "CAP2"]);
                    });
                    generate(&f.0).unwrap();
                    let page = fs::read_to_string(f.0.join("docs/compatibility/authentication.md"))
                        .unwrap();
                    let row = page
                        .lines()
                        .find(|line| line.starts_with("| FEATURE:"))
                        .unwrap();
                    assert!(!row.contains("Verified"));
                    assert_eq!(row.matches("Not attested").count(), 3);
                    if row.contains("Implemented, unverified") {
                        assert_eq!((left, right), ("implemented", "implemented"));
                        assert_eq!((left_precision, right_precision), ("local", "local"));
                    }
                    if left == "unsupported" && right == "unsupported" {
                        assert!(
                            row.contains("| Unsupported |"),
                            "unsupported state was strengthened: {row}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn capability_identifiers_cannot_inject_markdown_or_html() {
    let f = Fixture::new();
    let malicious = "CAP`\n<script>alert(1)</script>";
    f.mutate("crates/fireemu/src/capabilities.json", |v| {
        let cap = v.as_object_mut().unwrap().remove("CAP").unwrap();
        v[malicious] = cap;
    });
    f.mutate("spec/compatibility/contract.json", |v| {
        v["surfaces"][0]["claims"][0]["capabilities"][0]["id"] = json!(malicious);
    });
    f.mutate("spec/compatibility/features.json", |v| {
        v["features"][0]["capabilities"] = json!([malicious]);
    });
    generate(&f.0).unwrap();
    let page = fs::read_to_string(f.0.join("docs/compatibility/authentication.md")).unwrap();
    assert!(!page.contains("<script>"));
    assert!(!page.contains(malicious));
}

#[test]
fn cli_preflights_the_existing_contract_before_overwriting_pages() {
    // This fixture is valid for the inventory but deliberately not a complete legacy contract.
    let f = Fixture::new();
    f.write(
        "docs/compatibility/README.md",
        "preserve this reviewed document",
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_compat-check"))
        .args(["--root", f.0.to_str().unwrap(), "--write-inventory"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(f.0.join("docs/compatibility/README.md")).unwrap(),
        "preserve this reviewed document"
    );
}
