//! Table-driven fixtures for the compatibility gate (CC-01..CC-08).
//!
//! Each case builds a throw-away repository root that passes every rule, mutates exactly one
//! thing, runs the checker over it and asserts on the reported problems. The last test runs the
//! checker over this repository, so `cargo nextest run` fails as soon as the contract, the
//! capability manifest and the README drift apart.

use std::fs;
use std::path::{Path, PathBuf};

use compat_check::check;
use serde_json::{json, Value};

/// A throw-away repository root that removes itself when dropped.
struct Fixture {
    root: PathBuf,
}

const CLAIM: &str = "fireemu is compatible with the listed Local Emulator Suite products as \
shipped by firebase-tools 15.28.2 -- Cloud Firestore -- and claims nothing about Realtime \
Database, which is deferred.";

const TEST_SOURCE: &str = "
#[test]
fn a_real_test() {
    assert!(true);
}
";

impl Fixture {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("compat-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let fixture = Self { root };
        fixture.write("crates/fixture/tests/it.rs", TEST_SOURCE);
        fixture.write("conformance/fixtures/firestore/a-scenario.json", "{}");
        fixture.write(
            "conformance/package.json",
            &json!({"dependencies": {"firebase-tools": "15.28.2"}}).to_string(),
        );
        fixture.write(
            "spec/config/fireemu.schema.json",
            &json!({
                "type": "object",
                "properties": {
                    "firestore": {
                        "type": "object",
                        "properties": {
                            "indexValidationPolicy": {"enum": ["firebase", "conservative", "emulator"]},
                            "enforceLimits": {"type": "boolean"},
                        },
                    },
                },
            })
            .to_string(),
        );
        fixture.write(
            "README.md",
            &format!("# fixture\n\nSome prose.\n\n{CLAIM}\n\nRealtime Database is deferred.\n"),
        );
        fixture
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn write_manifest(&self, manifest: &Value) {
        self.write(
            "crates/fireemu/src/capabilities.json",
            &manifest.to_string(),
        );
    }

    fn write_contract(&self, contract: &Value) {
        self.write("spec/compatibility/contract.json", &contract.to_string());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A manifest every case starts from: one implemented entry and one unsupported entry.
fn manifest() -> Value {
    json!({
        "FS-RPC-1": {
            "status": "implemented",
            "implemented": ["GetDocument", "Commit"],
            "notes": ["ExecutePipeline is owned by FS-PIPE-RPC-1"],
        },
        "FS-PIPE-RPC-1": {
            "status": "implemented",
            "implemented": ["ExecutePipeline decode and validation"],
        },
        "AC-REPLAY-1": {"status": "unsupported", "notes": ["fails closed"]},
    })
}

/// A contract every case starts from. It passes every rule against [`manifest`].
fn contract() -> Value {
    json!({
        "schemaVersion": 1,
        "auditDate": "2026-08-30",
        "baseline": {
            "package": "firebase-tools",
            "version": "15.28.2",
            "pinnedBy": "conformance/package.json",
            "officialEmulators": ["firestore", "database"],
        },
        "claim": {"sentence": CLAIM, "documents": ["README.md"]},
        "profiles": {
            "firebase": {
                "intent": "reproduce the official emulator",
                "sets": {"firestore.indexValidationPolicy": "firebase", "firestore.enforceLimits": false},
            },
        },
        "vocabulary": {
            "scopeDisclaimers": ["deferred", "not planned"],
            "sharedTerms": [{
                "term": "ExecutePipeline",
                "status": "implemented",
                "owners": ["FS-PIPE-RPC-1"],
            }],
        },
        "surfaces": [
            {
                "id": "firestore",
                "title": "Cloud Firestore",
                "scope": "active",
                "official": true,
                "officialEmulator": "firestore",
                "state": "claimed",
                "decision": "active supported surface",
                "claims": [
                    {
                        "id": "FS-CLAIM-RPC",
                        "statement": "the gRPC service is served",
                        "capabilities": [{"id": "FS-RPC-1", "status": "implemented"}],
                        "evidence": {
                            "tests": ["a_real_test"],
                            "integration": ["crates/fixture/tests/it.rs"],
                            "conformance": ["firestore/a-scenario"],
                        },
                    },
                    {
                        "id": "FS-CLAIM-PIPELINE",
                        "statement": "pipelines are validated",
                        "capabilities": [
                            {"id": "FS-PIPE-RPC-1", "status": "implemented"},
                            {"id": "AC-REPLAY-1", "status": "unsupported"},
                        ],
                        "evidence": {"integration": ["crates/fixture/tests/it.rs"]},
                    },
                ],
            },
            {
                "id": "database",
                "title": "Firebase Realtime Database",
                "scope": "deferred",
                "official": true,
                "officialEmulator": "database",
                "state": "none",
                "decision": "deferred for low expected near-term demand",
                "prohibitedClaimTerms": ["Realtime Database"],
                "claims": [],
            },
        ],
    })
}

/// Replaces the value at a dotted path inside a JSON object, creating nothing.
fn set(value: &mut Value, path: &str, new: Value) {
    let mut node = value;
    let parts: Vec<&str> = path.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        node = match part.parse::<usize>() {
            Ok(i) => node.get_mut(i).expect(path),
            Err(_) => node.get_mut(*part).expect(path),
        };
    }
    let last = parts[parts.len() - 1];
    match last.parse::<usize>() {
        Ok(i) => *node.get_mut(i).expect(path) = new,
        Err(_) => {
            node.as_object_mut()
                .expect(path)
                .insert(last.to_owned(), new);
        }
    }
}

struct Case {
    name: &'static str,
    /// Mutates the starting contract, the starting manifest and the README.
    mutate: fn(&mut Value, &mut Value, &Fixture),
    /// The gate must fail with a problem containing this text, or pass when `None`.
    expect: Option<&'static str>,
}

#[allow(clippy::too_many_lines)]
fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "baseline-passes",
            mutate: |_, _, _| {},
            expect: None,
        },
        // CC-01: a duplicate surface id.
        Case {
            name: "duplicate-surface",
            mutate: |contract, _, _| {
                let first = contract["surfaces"][0].clone();
                contract["surfaces"].as_array_mut().unwrap().push(first);
            },
            expect: Some("CC-01: surface firestore is declared twice"),
        },
        // CC-01: an unknown scope.
        Case {
            name: "unknown-scope",
            mutate: |contract, _, _| set(contract, "surfaces/1/scope", json!("maybe")),
            expect: Some("has scope \"maybe\""),
        },
        // CC-02: an upstream upgrade fails closed until the contract is reconciled with it.
        Case {
            name: "upstream-upgrade-opens-debt",
            mutate: |_, _, fixture| {
                fixture.write(
                    "conformance/package.json",
                    &json!({"dependencies": {"firebase-tools": "15.29.0"}}).to_string(),
                );
            },
            expect: Some(
                "pins firebase-tools \"15.28.2\" while conformance/package.json installs \"15.29.0\"",
            ),
        },
        // CC-02: a claim sentence that does not name the pinned version is not version-qualified.
        Case {
            name: "claim-without-version",
            mutate: |contract, _, fixture| {
                let vague = "fireemu is compatible with Cloud Firestore. Realtime Database is deferred.";
                set(contract, "claim/sentence", json!(vague));
                fixture.write("README.md", &format!("# fixture\n\n{vague}\n"));
            },
            expect: Some("does not name the pinned firebase-tools version \"15.28.2\""),
        },
        // CC-02: an official emulator of the pinned baseline that no surface enumerates.
        Case {
            name: "inventory-gap",
            mutate: |contract, _, _| {
                contract["baseline"]["officialEmulators"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("hosting"));
            },
            expect: Some("CC-02: official emulator \"hosting\" of the pinned baseline is not enumerated"),
        },
        // CC-02: a surface naming an emulator the baseline does not ship.
        Case {
            name: "inventory-invention",
            mutate: |contract, _, _| set(contract, "surfaces/1/officialEmulator", json!("quantum")),
            expect: Some("which firebase-tools 15.28.2 does not ship"),
        },
        // CC-03: an implemented capability bound to nothing that exists.
        Case {
            name: "evidence-missing",
            mutate: |contract, _, _| {
                set(contract, "surfaces/0/claims/0/evidence", json!({}));
            },
            expect: Some("CC-03: capability FS-RPC-1 is implemented but claim FS-CLAIM-RPC binds it to no existing executed test or conformance fixture"),
        },
        // CC-03: a test name that does not resolve.
        Case {
            name: "evidence-stale-test",
            mutate: |contract, _, _| {
                set(contract, "surfaces/0/claims/0/evidence", json!({"tests": ["a_ghost_test"]}));
            },
            expect: Some("test a_ghost_test is not a function defined in any tests/ source file"),
        },
        // CC-03: an integration path that does not exist.
        Case {
            name: "evidence-stale-integration",
            mutate: |contract, _, _| {
                set(contract, "surfaces/0/claims/0/evidence", json!({"integration": ["crates/fixture/tests/gone.rs"]}));
            },
            expect: Some("integration file crates/fixture/tests/gone.rs does not exist"),
        },
        // CC-03: a conformance fixture that does not exist.
        Case {
            name: "evidence-stale-fixture",
            mutate: |contract, _, _| {
                set(contract, "surfaces/0/claims/0/evidence", json!({"conformance": ["firestore/no-such-scenario"]}));
            },
            expect: Some("conformance fixture firestore/no-such-scenario has no conformance/fixtures/firestore/no-such-scenario.json"),
        },
        // CC-04: the manifest and the contract disagree on status.
        Case {
            name: "status-disagreement",
            mutate: |_, manifest, _| set(manifest, "FS-RPC-1/status", json!("partial")),
            expect: Some("CC-04: claim FS-CLAIM-RPC declares capability FS-RPC-1 as \"implemented\" while the manifest declares it \"partial\""),
        },
        // CC-04: a manifest entry no claim covers.
        Case {
            name: "uncovered-capability",
            mutate: |_, manifest, _| {
                set(manifest, "ST-OBJ-1", json!({"status": "implemented", "implemented": ["objects"]}));
            },
            expect: Some("CC-04: capability ST-OBJ-1 (implemented) is in the manifest and in no claim"),
        },
        // CC-04: a claim naming a capability the manifest does not declare.
        Case {
            name: "invented-capability",
            mutate: |contract, _, _| {
                set(contract, "surfaces/0/claims/0/capabilities/0/id", json!("FS-GHOST-1"));
            },
            expect: Some("names capability FS-GHOST-1, which the manifest does not declare"),
        },
        // CC-05: the README does not carry the claim sentence.
        Case {
            name: "readme-without-claim",
            mutate: |_, _, fixture| {
                fixture.write("README.md", "# fixture\n\nRealtime Database is deferred.\n");
            },
            expect: Some("CC-05: README.md does not carry the version-qualified claim sentence"),
        },
        // CC-05: the sentence still matches when the README wraps it across lines.
        Case {
            name: "readme-claim-wrapped",
            mutate: |_, _, fixture| {
                // Wrapping may not separate a deferred product from its disclaimer: CC-06 reads
                // one line at a time, which is why the README keeps the claim on a single line.
                let wrapped = CLAIM.replace(" -- ", "\n-- ");
                fixture.write(
                    "README.md",
                    &format!("# fixture\n\n{wrapped}\n\nRealtime Database is deferred.\n"),
                );
            },
            expect: None,
        },
        // CC-06: a deferred product listed as implemented in the manifest.
        Case {
            name: "deferred-in-manifest",
            mutate: |_, manifest, _| {
                set(
                    manifest,
                    "FS-RPC-1/implemented",
                    json!(["GetDocument", "Realtime Database references"]),
                );
            },
            expect: Some("CC-06: manifest entry FS-RPC-1 lists \"Realtime Database\" as implemented"),
        },
        // CC-06: a deferred product named in the README without saying it is deferred.
        Case {
            name: "deferred-in-readme",
            mutate: |_, _, fixture| {
                fixture.write(
                    "README.md",
                    &format!("# fixture\n\n{CLAIM}\n\nfireemu serves Realtime Database too.\n"),
                );
            },
            expect: Some("names \"Realtime Database\" without saying it is deferred"),
        },
        // CC-06: a deferred surface may not carry a parity claim at all.
        Case {
            name: "deferred-with-claims",
            mutate: |contract, _, _| {
                let claim = contract["surfaces"][0]["claims"][0].clone();
                set(contract, "surfaces/1/claims", json!([claim]));
            },
            expect: Some("CC-06: surface database is deferred and may not carry parity claims"),
        },
        // CC-06: a deferred surface with no prohibited terms cannot be policed at all.
        Case {
            name: "deferred-without-terms",
            mutate: |contract, _, _| set(contract, "surfaces/1/prohibitedClaimTerms", json!([])),
            expect: Some("declares no prohibitedClaimTerms"),
        },
        // CC-07: an unimplemented item that cross-references an implemented capability.
        Case {
            name: "cross-reference-contradiction",
            mutate: |_, manifest, _| {
                set(
                    manifest,
                    "FS-RPC-1/unimplemented",
                    json!(["pipeline execution (FS-PIPE-RPC-1)"]),
                );
            },
            expect: Some("it names FS-PIPE-RPC-1, which the manifest declares implemented"),
        },
        // CC-07: a shared term the contract calls implemented, listed as unimplemented.
        Case {
            name: "shared-term-contradiction",
            mutate: |_, manifest, _| {
                set(manifest, "FS-RPC-1/unimplemented", json!(["ExecutePipeline"]));
            },
            expect: Some("while the contract declares \"ExecutePipeline\" implemented"),
        },
        // CC-07: the README denying a shared term the contract calls implemented.
        Case {
            name: "shared-term-readme-denial",
            mutate: |_, _, fixture| {
                fixture.write(
                    "README.md",
                    &format!("# fixture\n\n{CLAIM}\n\nRealtime Database is deferred.\n\nExecutePipeline is not implemented.\n"),
                );
            },
            expect: Some("says \"ExecutePipeline\" is not implemented while the contract declares it implemented"),
        },
        // CC-07: a shared term whose owner does not carry the declared status.
        Case {
            name: "shared-term-owner-disagreement",
            mutate: |contract, _, _| {
                set(contract, "vocabulary/sharedTerms/0/owners", json!(["AC-REPLAY-1"]));
            },
            expect: Some("is declared \"implemented\" while its owner AC-REPLAY-1 is \"unsupported\""),
        },
        // CC-08: a profile setting a key the canonical schema does not define.
        Case {
            name: "profile-unknown-key",
            mutate: |contract, _, _| {
                set(contract, "profiles/firebase/sets", json!({"firestore.pretendMode": "on"}));
            },
            expect: Some("sets firestore.pretendMode, which spec/config/fireemu.schema.json does not define"),
        },
        // CC-08: a profile setting a value the schema's enum does not allow.
        Case {
            name: "profile-bad-enum",
            mutate: |contract, _, _| {
                set(contract, "profiles/firebase/sets", json!({"firestore.indexValidationPolicy": "lenient"}));
            },
            expect: Some("sets firestore.indexValidationPolicy = \"lenient\", which is not one of"),
        },
        // CC-08: a profile setting a boolean key to something else.
        Case {
            name: "profile-bad-type",
            mutate: |contract, _, _| {
                set(contract, "profiles/firebase/sets", json!({"firestore.enforceLimits": "yes"}));
            },
            expect: Some("but the schema declares a boolean"),
        },
    ]
}

#[test]
fn every_failure_class_is_caught() {
    for case in cases() {
        let fixture = Fixture::new(case.name);
        let mut contract = contract();
        let mut manifest = manifest();
        (case.mutate)(&mut contract, &mut manifest, &fixture);
        fixture.write_contract(&contract);
        fixture.write_manifest(&manifest);

        let report = check(&fixture.root);
        match case.expect {
            None => assert!(
                report.is_ok(),
                "case {}: expected no problems, got {:?}",
                case.name,
                report.problems
            ),
            Some(text) => assert!(
                report.problems.iter().any(|p| p.contains(text)),
                "case {}: expected a problem containing {text:?}, got {:?}",
                case.name,
                report.problems
            ),
        }
    }
}

#[test]
fn the_repository_matches_its_compatibility_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let report = check(root);
    assert!(
        report.is_ok(),
        "the repository and its compatibility contract disagree: {:?}",
        report.problems
    );
}
