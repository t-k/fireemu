//! Table-driven fixtures for the compatibility gate (CC-01..CC-10).
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
        fixture.write_fixture(
            "firestore/a-scenario",
            &json!([{"id": "read", "status": "parity", "value": {"status": 200}}]),
        );
        fixture.write(
            "conformance/package.json",
            &json!({"dependencies": {"firebase-tools": "15.28.2"}}).to_string(),
        );
        fixture.write_config_schema(&json!(["emulator"]));
        fixture.write_divergences(&json!({
            "schemaVersion": 2,
            "divergences": {},
            "firestoreMatrixDivergences": {},
            "rulesMatrixDivergences": {},
        }));
        fixture.write(
            "README.md",
            &format!("# fixture\n\nSome prose.\n\n{CLAIM}\n\nRealtime Database is deferred.\n"),
        );
        fixture
    }

    /// The canonical configuration schema, with `accepted` as the profile key's enum.
    fn write_config_schema(&self, accepted: &Value) {
        self.write(
            "spec/config/fireemu.schema.json",
            &json!({
                "type": "object",
                "properties": {
                    "profile": {"enum": accepted},
                    "firestore": {
                        "type": "object",
                        "properties": {
                            "apiMode": {"enum": ["native", "mongodb-compatible"]},
                            "enforceLimits": {"type": "boolean"},
                        },
                    },
                },
            })
            .to_string(),
        );
    }

    /// A recorded conformance fixture with the given steps, in the shape
    /// `conformance/src/record.mjs` writes.
    fn write_fixture(&self, name: &str, steps: &Value) {
        self.write(
            &format!("conformance/fixtures/{name}.json"),
            &json!({"schemaVersion": 1, "id": name, "steps": steps}).to_string(),
        );
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

    fn write_divergences(&self, divergences: &Value) {
        self.write("conformance/divergences.json", &divergences.to_string());
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
            "emulator": {
                "intent": "reproduce the official emulator",
                "sets": {"firestore.enforceLimits": false},
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

/// A complete, otherwise valid register for `firestore/a-scenario#read` whose authority
/// names `fixture`.
fn forged_register(fixture: &str) -> Value {
    json!({
        "schemaVersion": 2,
        "divergences": {
            "firestore/a-scenario#read": {
                "documents": "README.md",
                "reason": "forged on purpose",
                "authority": {
                    "kind": "production-spec",
                    "sourceUrls": ["https://firebase.google.com/docs/firestore"],
                    "checkedOn": "2026-09-05",
                    "officialBaseline": {"package": "firebase-tools", "version": "15.28.2"},
                    "fixture": fixture,
                    "approvalRecord": "README.md"
                }
            }
        },
        "firestoreMatrixDivergences": {},
        "rulesMatrixDivergences": {},
    })
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
        // CC-06: release wording is scoped the same way as the README.
        Case {
            name: "scoped-document-leaks-a-deferred-product",
            mutate: |contract, _, fixture| {
                fixture.write(
                    "npm/fireemu/package.json",
                    &json!({"name": "fireemu", "description": "the whole Emulator Suite, Realtime Database included"}).to_string(),
                );
                set(contract, "claim/scopedDocuments", json!(["npm/fireemu/package.json"]));
            },
            expect: Some("CC-06: npm/fireemu/package.json:1 names \"Realtime Database\" without saying it is deferred"),
        },
        Case {
            name: "scoped-document-missing",
            mutate: |contract, _, _| {
                set(contract, "claim/scopedDocuments", json!(["npm/absent/package.json"]));
            },
            expect: Some("CC-06: claim.scopedDocuments names npm/absent/package.json, which cannot be read"),
        },
        // CC-08: a profile setting a key the canonical schema does not define.
        Case {
            name: "profile-unknown-key",
            mutate: |contract, _, _| {
                set(contract, "profiles/emulator/sets", json!({"firestore.pretendMode": "on"}));
            },
            expect: Some("sets firestore.pretendMode, which spec/config/fireemu.schema.json does not define"),
        },
        // CC-08: a profile setting a value the schema's enum does not allow.
        Case {
            name: "profile-bad-enum",
            mutate: |contract, _, _| {
                set(contract, "profiles/emulator/sets", json!({"firestore.apiMode": "lenient"}));
            },
            expect: Some("sets firestore.apiMode = \"lenient\", which is not one of"),
        },
        // CC-08: a profile setting a boolean key to something else.
        Case {
            name: "profile-bad-type",
            mutate: |contract, _, _| {
                set(contract, "profiles/emulator/sets", json!({"firestore.enforceLimits": "yes"}));
            },
            expect: Some("but the schema declares a boolean"),
        },
        // CC-08: a declared key is a statement of intent and must say why it is not a switch.
        Case {
            name: "profile-declared-without-status",
            mutate: |contract, _, _| {
                set(
                    contract,
                    "profiles/emulator/declared",
                    json!({"firestore.enforceLimits": {"value": false, "note": "by hand"}}),
                );
            },
            expect: Some("both sets and declares firestore.enforceLimits"),
        },
        Case {
            name: "profile-declared-bad-status",
            mutate: |contract, _, _| {
                set(
                    contract,
                    "profiles/emulator/declared",
                    json!({"firestore.apiMode": {"value": "native", "status": "someday", "note": "x"}}),
                );
                set(contract, "profiles/emulator/sets", json!({"firestore.enforceLimits": false}));
            },
            expect: Some("declares firestore.apiMode with status Some(\"someday\")"),
        },
        Case {
            name: "profile-declared-value-the-schema-refuses",
            mutate: |contract, _, _| {
                set(
                    contract,
                    "profiles/emulator/declared",
                    json!({"firestore.apiMode": {"value": "lenient", "status": "hand-written", "note": "x"}}),
                );
                set(contract, "profiles/emulator/sets", json!({"firestore.enforceLimits": false}));
            },
            expect: Some("sets firestore.apiMode = \"lenient\", which is not one of"),
        },
        Case {
            name: "profile-declared-is-accepted",
            mutate: |contract, _, _| {
                set(
                    contract,
                    "profiles/emulator/declared",
                    json!({"firestore.apiMode": {"value": "native", "status": "hand-written", "note": "read by the loader"}}),
                );
                set(contract, "profiles/emulator/sets", json!({"firestore.enforceLimits": false}));
            },
            expect: None,
        },
        // CC-08: a profile no run can select, because the schema's profile key does not
        // accept its name. A declared profile that is not a runtime switch is a document.
        Case {
            name: "profile-name-the-schema-refuses",
            mutate: |contract, _, fixture| {
                let profile = contract["profiles"]["emulator"].clone();
                set(contract, "profiles", json!({"lenient": profile}));
                fixture.write_config_schema(&json!(["emulator"]));
            },
            expect: Some("profile lenient is declared but"),
        },
        // CC-08: the other direction -- a name a run can select that the contract does not
        // declare, so nothing says what it means.
        Case {
            name: "profile-name-the-contract-omits",
            mutate: |_, _, fixture| {
                fixture.write_config_schema(&json!(["emulator", "strict"]));
            },
            expect: Some("accepts profile strict, which"),
        },
        // CC-09: a fixture step recorded as debt invalidates the claim that cites the fixture.
        Case {
            name: "debt-step-fails-the-claim",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([
                        {"id": "read", "status": "parity", "value": {"status": 200}},
                        {"id": "write", "status": "debt", "oracle": {"status": 400}, "testd": {"status": 200}},
                    ]),
                );
            },
            expect: Some(
                "CC-09: claim FS-CLAIM-RPC: conformance fixture firestore/a-scenario step write is debt",
            ),
        },
        // CC-09: the same debt step, excluded from the claim's scope in the contract with an
        // owning issue, does not fail it.
        Case {
            name: "explicitly-excluded-debt-step-passes",
            mutate: |contract, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([
                        {"id": "read", "status": "parity", "value": {"status": 200}},
                        {"id": "write", "status": "debt", "oracle": {"status": 400}, "testd": {"status": 200}},
                    ]),
                );
                set(
                    contract,
                    "surfaces/0/claims/0/evidence/conformance",
                    json!([{
                        "fixture": "firestore/a-scenario",
                        "excludedSteps": [{
                            "step": "write",
                            "issue": "docs.local/issues/open/fix-the-write.md",
                            "reason": "the status code differs; the claim covers reads until the issue closes",
                        }],
                    }]),
                );
            },
            expect: None,
        },
        // CC-09: an exclusion must carry the issue that owns the debt and a reason.
        Case {
            name: "exclusion-without-an-issue",
            mutate: |contract, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([
                        {"id": "read", "status": "parity", "value": {"status": 200}},
                        {"id": "write", "status": "debt", "oracle": {"status": 400}, "testd": {"status": 200}},
                    ]),
                );
                set(
                    contract,
                    "surfaces/0/claims/0/evidence/conformance",
                    json!([{
                        "fixture": "firestore/a-scenario",
                        "excludedSteps": [{"step": "write", "reason": "differs"}],
                    }]),
                );
            },
            expect: Some("CC-09: claim FS-CLAIM-RPC: excluded step write of firestore/a-scenario names no owning issue"),
        },
        // CC-09: an exclusion that names a step which is no longer debt is stale and must go.
        Case {
            name: "stale-exclusion-fails",
            mutate: |contract, _, _| {
                set(
                    contract,
                    "surfaces/0/claims/0/evidence/conformance",
                    json!([{
                        "fixture": "firestore/a-scenario",
                        "excludedSteps": [{
                            "step": "read",
                            "issue": "docs.local/issues/open/fix-the-read.md",
                            "reason": "no longer true",
                        }],
                    }]),
                );
            },
            expect: Some(
                "CC-09: claim FS-CLAIM-RPC: excluded step read of firestore/a-scenario is parity, not debt; the exclusion is stale",
            ),
        },
        // CC-10: a documented divergence without structured authority is not justified.
        Case {
            name: "documented-divergence-without-authority-is-refused",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([{
                        "id": "read",
                        "status": "documented-divergence",
                        "documents": "README.md",
                        "oracle": {"status": 200},
                        "testd": {"status": 404},
                    }]),
                );
            },
            expect: Some("CC-10: firestore/a-scenario#read has no authority entry"),
        },
        // CC-10: a justified divergence remains evidence when its authority is complete.
        Case {
            name: "documented-divergence-with-authority-is-evidence",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([{
                        "id": "read",
                        "status": "documented-divergence",
                        "documents": "README.md",
                        "oracle": {"status": 200},
                        "testd": {"status": 404},
                    }]),
                );
                fixture.write_divergences(&json!({
                    "schemaVersion": 2,
                    "divergences": {
                        "firestore/a-scenario#read": {
                            "documents": "README.md",
                            "reason": "the local policy is intentionally stricter",
                            "authority": {
                                "kind": "intentional-local-policy",
                                "sourceUrls": ["https://firebase.google.com/docs/emulator-suite"],
                                "checkedOn": "2026-09-05",
                                "officialBaseline": {"package": "firebase-tools", "version": "15.28.2"},
                                "fixture": "conformance/fixtures/firestore/a-scenario.json#read",
                                "approvalRecord": "README.md#policy"
                            }
                        }
                    },
                    "firestoreMatrixDivergences": {},
                    "rulesMatrixDivergences": {},
                }));
            },
            expect: None,
        },
        Case {
            name: "unverified-authority-cannot-justify-a-documented-divergence",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([{"id": "read", "status": "documented-divergence"}]),
                );
                fixture.write_divergences(&json!({
                    "schemaVersion": 2,
                    "divergences": {
                        "firestore/a-scenario#read": {
                            "documents": "README.md",
                            "reason": "not yet verified",
                            "authority": {
                                "kind": "unverified",
                                "sourceUrls": ["https://firebase.google.com/docs/emulator-suite"],
                                "checkedOn": "2026-09-05",
                                "officialBaseline": {"package": "firebase-tools", "version": "15.28.2"},
                                "fixture": "conformance/fixtures/firestore/a-scenario.json#read",
                                "issue": "docs.local/issues/open/verify.md",
                                "approvalRecord": "README.md#policy"
                            }
                        }
                    },
                    "firestoreMatrixDivergences": {},
                    "rulesMatrixDivergences": {},
                }));
            },
            expect: Some("CC-10: firestore/a-scenario#read is unverified and cannot justify a documented divergence"),
        },
        Case {
            name: "authority-source-must-be-https",
            mutate: |_, _, fixture| {
                fixture.write_divergences(&json!({
                    "schemaVersion": 2,
                    "divergences": {
                        "firestore/a-scenario#read": {
                            "authority": {
                                "kind": "production-spec",
                                "sourceUrls": ["http://example.test/spec"],
                                "checkedOn": "2026-09-05",
                                "officialBaseline": {"package": "firebase-tools", "version": "15.28.2"},
                                "fixture": "conformance/fixtures/firestore/a-scenario.json#read",
                                "decidedBy": "fireemu maintainers"
                            }
                        }
                    },
                    "firestoreMatrixDivergences": {},
                    "rulesMatrixDivergences": {},
                }));
            },
            expect: Some("authority sourceUrls must contain only non-empty HTTPS URLs"),
        },
        Case {
            name: "authority-must-name-an-existing-divergence-row",
            mutate: |_, _, fixture| {
                fixture.write_divergences(&json!({
                    "schemaVersion": 2,
                    "divergences": {
                        "firestore/a-scenario#read": {
                            "authority": {
                                "kind": "production-spec",
                                "sourceUrls": ["https://firebase.google.com/docs/firestore"],
                                "checkedOn": "2026-09-05",
                                "officialBaseline": {"package": "firebase-tools", "version": "15.28.2"},
                                "fixture": "conformance/fixtures/firestore/missing.json#read",
                                "decidedBy": "fireemu maintainers"
                            }
                        }
                    },
                    "firestoreMatrixDivergences": {},
                    "rulesMatrixDivergences": {},
                }));
            },
            expect: Some("does not name an existing documented-divergence row"),
        },
        Case {
            name: "matrix-row-cannot-outlive-its-authority",
            mutate: |_, _, fixture| {
                fixture.write(
                    "conformance/pubsub-matrix.json",
                    &json!({
                        "programs": [{
                            "id": "delivery",
                            "steps": [{"id": "push", "status": "documented-divergence"}]
                        }]
                    })
                    .to_string(),
                );
            },
            expect: Some(
                "CC-10: conformance/pubsub-matrix.json row pubsub-probe/delivery#push has no authority entry",
            ),
        },
        // CC-10: the Rules program recording has no register section, so a divergence written
        // into it is a promotion nothing authorized.
        Case {
            name: "rules-program-recording-cannot-pin-an-unauthorized-divergence",
            mutate: |_, _, fixture| {
                fixture.write(
                    "conformance/rules-programs.json",
                    &json!({
                        "version": 1,
                        "programs": [{
                            "id": "budget-get-10",
                            "area": "budget",
                            "oracle": {"steps": {"read": {"status": 404}}},
                            "divergence": {"fireemu": {"steps": {"read": {"status": 200}}}}
                        }]
                    })
                    .to_string(),
                );
            },
            expect: Some(
                "CC-10: conformance/rules-programs.json row budget-get-10 records a divergence, but Rules programs have no authority section in conformance/divergences.json",
            ),
        },
        // CC-10: an authority fixture must be a repository-relative conformance file; a
        // hand-written file elsewhere in the repository, outside it, reached by traversal or
        // through a symbolic link is not evidence.
        Case {
            name: "authority-fixture-outside-conformance-is-refused",
            mutate: |_, _, fixture| {
                fixture.write(
                    "docs/forged/evil.json",
                    &json!({"id": "firestore/a-scenario", "steps": [{"id": "read", "status": "documented-divergence"}]}).to_string(),
                );
                fixture.write_divergences(&forged_register("docs/forged/evil.json#read"));
            },
            expect: Some("CC-10: firestore/a-scenario#read authority fixture must be a repository-relative conformance file"),
        },
        Case {
            name: "authority-fixture-absolute-path-is-refused",
            mutate: |_, _, fixture| {
                fixture.write(
                    "docs/forged/evil.json",
                    &json!({"id": "firestore/a-scenario", "steps": [{"id": "read", "status": "documented-divergence"}]}).to_string(),
                );
                let absolute = fixture.root.join("docs/forged/evil.json");
                fixture.write_divergences(&forged_register(&format!("{}#read", absolute.display())));
            },
            expect: Some("authority fixture must be a repository-relative conformance file"),
        },
        Case {
            name: "authority-fixture-traversal-is-refused",
            mutate: |_, _, fixture| {
                fixture.write(
                    "docs/forged/evil.json",
                    &json!({"id": "firestore/a-scenario", "steps": [{"id": "read", "status": "documented-divergence"}]}).to_string(),
                );
                fixture.write_divergences(&forged_register("conformance/../docs/forged/evil.json#read"));
            },
            expect: Some("authority fixture must be a repository-relative conformance file"),
        },
        Case {
            name: "authority-fixture-backslash-is-refused",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([{"id": "read", "status": "documented-divergence"}]),
                );
                fixture.write_divergences(&forged_register("conformance\\fixtures\\firestore\\a-scenario.json#read"));
            },
            expect: Some("authority fixture must be a repository-relative conformance file"),
        },
        #[cfg(unix)]
        Case {
            name: "authority-fixture-symlink-out-of-the-repository-is-refused",
            mutate: |_, _, fixture| {
                let outside = fixture.root.parent().unwrap().join(format!(
                    "compat-outside-{}.json",
                    fixture.root.file_name().unwrap().to_string_lossy()
                ));
                fs::write(
                    &outside,
                    json!({"id": "firestore/a-scenario", "steps": [{"id": "read", "status": "documented-divergence"}]}).to_string(),
                )
                .unwrap();
                let link = fixture.root.join("conformance/fixtures/firestore/linked.json");
                fs::create_dir_all(link.parent().unwrap()).unwrap();
                std::os::unix::fs::symlink(&outside, &link).unwrap();
                fixture.write_divergences(&forged_register("conformance/fixtures/firestore/linked.json#read"));
            },
            expect: Some("authority fixture must stay inside the repository"),
        },
        // CC-10: an object-shaped matrix row without a `divergence` is a parity row; binding an
        // authority to it would promote an agreeing row to a divergence with a forged answer.
        Case {
            name: "authority-cannot-bind-a-matrix-row-whose-mark-pins-another-answer",
            mutate: |_, _, fixture| {
                fixture.write(
                    "conformance/firestore-matrix.json",
                    &json!({"programs": [{"id": "values/type-order", "steps": {"ascending": {"oracle": {"status": 200}, "divergence": {"fireemu": {"status": 500}}}}}]}).to_string(),
                );
                fixture.write_divergences(&json!({
                    "schemaVersion": 2,
                    "divergences": {},
                    "firestoreMatrixDivergences": {
                        "values/type-order#ascending": {
                            "fireemu": {"status": 409},
                            "reason": "the register drifted from the recording",
                            "authority": {
                                "kind": "production-spec",
                                "sourceUrls": ["https://firebase.google.com/docs/firestore"],
                                "checkedOn": "2026-09-05",
                                "officialBaseline": {"package": "firebase-tools", "version": "15.28.2"},
                                "fixture": "conformance/firestore-matrix.json#values/type-order#ascending",
                                "approvalRecord": "README.md"
                            }
                        }
                    },
                    "rulesMatrixDivergences": {},
                }));
            },
            expect: Some("does not name an existing documented-divergence row"),
        },
        Case {
            name: "authority-cannot-bind-a-parity-matrix-row",
            mutate: |_, _, fixture| {
                fixture.write(
                    "conformance/firestore-matrix.json",
                    &json!({"programs": [{"id": "values/type-order", "steps": {"ascending": {"status": 200}}}]}).to_string(),
                );
                fixture.write_divergences(&json!({
                    "schemaVersion": 2,
                    "divergences": {},
                    "firestoreMatrixDivergences": {
                        "values/type-order#ascending": {
                            "fireemu": "forged-answer",
                            "reason": "promoting a parity row that the recording never marked divergent",
                            "authority": {
                                "kind": "production-spec",
                                "sourceUrls": ["https://firebase.google.com/docs/firestore"],
                                "checkedOn": "2026-09-05",
                                "officialBaseline": {"package": "firebase-tools", "version": "15.28.2"},
                                "fixture": "conformance/firestore-matrix.json#values/type-order#ascending",
                                "approvalRecord": "README.md"
                            }
                        }
                    },
                    "rulesMatrixDivergences": {},
                }));
            },
            expect: Some("does not name an existing documented-divergence row"),
        },
        // CC-10: a source URL with a control character, or a non-string list element, is not a
        // valid HTTPS URL list.
        Case {
            name: "authority-source-url-control-character-is-refused",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([{"id": "read", "status": "documented-divergence"}]),
                );
                let mut register = forged_register("conformance/fixtures/firestore/a-scenario.json#read");
                register["divergences"]["firestore/a-scenario#read"]["authority"]["sourceUrls"] =
                    json!(["https://example.test/a\u{0}b"]);
                fixture.write_divergences(&register);
            },
            expect: Some("authority sourceUrls must contain only non-empty HTTPS URLs"),
        },
        Case {
            name: "authority-source-url-non-string-element-is-refused",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([{"id": "read", "status": "documented-divergence"}]),
                );
                let mut register = forged_register("conformance/fixtures/firestore/a-scenario.json#read");
                register["divergences"]["firestore/a-scenario#read"]["authority"]["sourceUrls"] =
                    json!(["https://example.test/x", 5]);
                fixture.write_divergences(&register);
            },
            expect: Some("authority sourceUrls must contain only non-empty HTTPS URLs"),
        },
        Case {
            name: "authority-fixture-extension-is-case-sensitive-like-the-node-gate",
            mutate: |_, _, fixture| {
                fixture.write(
                    "conformance/fixtures/firestore/COPY.JSON",
                    &json!({"id": "firestore/a-scenario", "steps": [{"id": "read", "status": "documented-divergence"}]}).to_string(),
                );
                fixture.write_divergences(&forged_register("conformance/fixtures/firestore/COPY.JSON#read"));
            },
            expect: Some("authority fixture must be a repository-relative conformance file"),
        },
        Case {
            name: "authority-fixture-must-match-its-register-key",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/other-scenario",
                    &json!([{"id": "read", "status": "documented-divergence"}]),
                );
                fixture.write_divergences(&json!({
                    "schemaVersion": 2,
                    "divergences": {
                        "firestore/a-scenario#read": {
                            "documents": "README.md",
                            "reason": "misbound on purpose",
                            "authority": {
                                "kind": "production-spec",
                                "sourceUrls": ["https://firebase.google.com/docs/firestore"],
                                "checkedOn": "2026-09-05",
                                "officialBaseline": {"package": "firebase-tools", "version": "15.28.2"},
                                "fixture": "conformance/fixtures/firestore/other-scenario.json#read",
                                "approvalRecord": "README.md"
                            }
                        }
                    },
                    "firestoreMatrixDivergences": {},
                    "rulesMatrixDivergences": {},
                }));
            },
            expect: Some("authority fixture points to different row firestore/other-scenario#read"),
        },
        Case {
            name: "contract-divergence-needs-structured-authority",
            mutate: |contract, _, _| {
                contract
                    .pointer_mut("/profiles/emulator")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(
                        "officialEmulatorDivergences".to_owned(),
                        json!([{"key": "free.text", "note": "not enough"}]),
                    );
            },
            expect: Some("CC-10: free.text has no authority object"),
        },
        // CC-09: a row no local oracle can answer (production-only) is not emulator evidence,
        // so a fixture made only of such rows proves nothing.
        Case {
            name: "pending-only-fixture-is-not-evidence",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([{"id": "read", "status": "pending", "reason": "needs production"}]),
                );
            },
            expect: Some(
                "CC-09: claim FS-CLAIM-RPC: conformance fixture firestore/a-scenario carries no parity or documented-divergence step",
            ),
        },
        // CC-09: a status the conformance suite does not define cannot be counted either way.
        Case {
            name: "unknown-step-status",
            mutate: |_, _, fixture| {
                fixture.write_fixture(
                    "firestore/a-scenario",
                    &json!([{"id": "read", "status": "probably-fine", "value": {}}]),
                );
            },
            expect: Some("CC-09: claim FS-CLAIM-RPC: conformance fixture firestore/a-scenario step read has status \"probably-fine\""),
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
