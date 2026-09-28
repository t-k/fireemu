//! Production denominator exact-set and evidence-state regression tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use compat_check::production_inventory::check;
use serde_json::{json, Value};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "production-inventory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("spec/compatibility/upstream/2026-09-09-retry")).unwrap();
        let fixture = Self(root);
        fixture.json(
            "spec/compatibility/upstream/2026-09-09-retry/discovery.json",
            &json!({
                "schemaVersion": 1,
                "definitions": [
                    {
                        "id": "identitytoolkit-v1",
                        "url": "https://identitytoolkit.googleapis.com/$discovery/rest?version=v1",
                        "revision": "20260813",
                        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "surfaces": [
                            {"locator":"identitytoolkit.accounts.signUp","kind":"method","transport":"REST","classification":"unknown","requirements":[]},
                            {"locator":"schemas/SignupNewUserRequest/properties/email","kind":"field","transport":"REST","classification":"unknown","requirements":[]}
                        ]
                    },
                    {
                        "id": "firestore-v1",
                        "url": "https://firestore.googleapis.com/$discovery/rest?version=v1",
                        "revision": "20260826",
                        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "surfaces": [
                            {"locator":"firestore.projects.databases.documents.runQuery","kind":"method","transport":"REST","classification":"unknown","requirements":[]},
                            {"locator":"firestore.projects.databases.documents.executePipeline","kind":"method","transport":"REST","classification":"unknown","requirements":[]},
                            {"locator":"schemas/GoogleFirestoreAdminV1Database/properties/databaseEdition/enum/ENTERPRISE","kind":"method","transport":"REST","classification":"unknown","requirements":[]},
                            {"locator":"schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/MONGODB_COMPATIBLE_API","kind":"method","transport":"REST","classification":"unknown","requirements":[]},
                            {"locator":"schemas/GoogleFirestoreAdminV1Database/properties/type/enum/DATASTORE_MODE","kind":"method","transport":"REST","classification":"unknown","requirements":[]}
                        ]
                    }
                ]
            }),
        );
        fixture.json(
            "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v1.json",
            &denominator(),
        );
        fixture
    }

    fn json(&self, path: &str, value: &Value) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn mutate(&self, change: impl FnOnce(&mut Value)) {
        let path = self
            .0
            .join("spec/compatibility/denominators/ip-fs-standard-2026-09-14.v1.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        change(&mut value);
        self.json(
            "spec/compatibility/denominators/ip-fs-standard-2026-09-14.v1.json",
            &value,
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn target(id: &str, definition: &str, locator: &str, feature: &str, scope: &str) -> Value {
    json!({
        "id": id,
        "definition": definition,
        "locator": locator,
        "kind": "method",
        "transport": "REST",
        "featureGroup": feature,
        "scope": scope,
        "scopeReason": if scope == "enterprise-only" {"Firestore Enterprise-only Pipeline surface"} else {"Application-facing target"},
        "evidenceState": "waiting-oracle",
        "receiptRefs": []
    })
}

fn denominator() -> Value {
    let source = "spec/compatibility/upstream/2026-09-09-retry/discovery.json";
    json!({
        "schemaVersion": 1,
        "goal": "IP-FS-PRODUCTION-COMPATIBILITY",
        "denominatorVersion": "ip-fs-standard-2026-09-14.v1",
        "sourceSnapshot": source,
        "sourceSnapshotSha256": "c".repeat(64),
        "parentDenominator": null,
        "definitions": [
            {"id":"identitytoolkit-v1","revision":"20260813","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            {"id":"firestore-v1","revision":"20260826","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
        ],
        "targets": [
            target("identitytoolkit-v1:method:REST:identitytoolkit.accounts.signUp", "identitytoolkit-v1", "identitytoolkit.accounts.signUp", "AUTH-ACCOUNT", "target"),
            json!({
                "id":"identitytoolkit-v1:field:REST:schemas/SignupNewUserRequest/properties/email",
                "definition":"identitytoolkit-v1","locator":"schemas/SignupNewUserRequest/properties/email","kind":"field","transport":"REST",
                "featureGroup":"AUTH-ACCOUNT","scope":"target","scopeReason":"Application-facing target","evidenceState":"waiting-oracle","receiptRefs":[]
            }),
            target("firestore-v1:method:REST:firestore.projects.databases.documents.runQuery", "firestore-v1", "firestore.projects.databases.documents.runQuery", "FS-QUERY-INDEX", "target"),
            target("firestore-v1:method:REST:firestore.projects.databases.documents.executePipeline", "firestore-v1", "firestore.projects.databases.documents.executePipeline", "FS-ENTERPRISE-EXCLUDED", "enterprise-only"),
            target("firestore-v1:method:REST:schemas/GoogleFirestoreAdminV1Database/properties/databaseEdition/enum/ENTERPRISE", "firestore-v1", "schemas/GoogleFirestoreAdminV1Database/properties/databaseEdition/enum/ENTERPRISE", "FS-ENTERPRISE-EXCLUDED", "enterprise-only"),
            target("firestore-v1:method:REST:schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/MONGODB_COMPATIBLE_API", "firestore-v1", "schemas/GoogleFirestoreAdminV1Index/properties/apiScope/enum/MONGODB_COMPATIBLE_API", "FS-ENTERPRISE-EXCLUDED", "enterprise-only"),
            target("firestore-v1:method:REST:schemas/GoogleFirestoreAdminV1Database/properties/type/enum/DATASTORE_MODE", "firestore-v1", "schemas/GoogleFirestoreAdminV1Database/properties/type/enum/DATASTORE_MODE", "FS-DATASTORE-EXCLUDED", "outside-goal")
        ]
    })
}

#[test]
fn exact_pinned_target_set_is_accepted() {
    let fixture = Fixture::new();
    assert!(check(&fixture.0).is_ok());
}

#[test]
fn removing_or_adding_a_target_is_rejected() {
    let fixture = Fixture::new();
    fixture.mutate(|value| {
        value["targets"].as_array_mut().unwrap().pop();
    });
    let report = check(&fixture.0);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.contains("target set")));

    let fixture = Fixture::new();
    fixture.mutate(|value| {
        value["targets"].as_array_mut().unwrap().push(target(
            "firestore-v1:method:REST:invented",
            "firestore-v1",
            "invented",
            "FS-DATA-WRITE",
            "target",
        ));
    });
    let report = check(&fixture.0);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.contains("target set")));
}

#[test]
fn source_revision_and_surface_shape_are_bound() {
    for change in [
        |value: &mut Value| value["definitions"][0]["revision"] = json!("latest"),
        |value: &mut Value| value["definitions"][0]["unbound"] = json!(true),
        |value: &mut Value| value["targets"][0]["kind"] = json!("field"),
        |value: &mut Value| value["targets"][0]["transport"] = json!("gRPC"),
    ] {
        let fixture = Fixture::new();
        fixture.mutate(change);
        assert!(!check(&fixture.0).is_ok());
    }
}

#[test]
fn evidence_cannot_be_promoted_without_a_bound_receipt() {
    for state in [
        "local-verified",
        "oracle-compared",
        "repaired",
        "compat-verified",
    ] {
        let fixture = Fixture::new();
        fixture.mutate(|value| value["targets"][0]["evidenceState"] = json!(state));
        let report = check(&fixture.0);
        assert!(report
            .problems
            .iter()
            .any(|problem| problem.contains("receipt")));
    }
}

#[test]
fn an_existing_file_is_not_enough_to_promote_evidence() {
    let fixture = Fixture::new();
    fixture.json(
        "spec/compatibility/evidence/unbound.json",
        &json!({"status":"passed"}),
    );
    fixture.mutate(|value| {
        value["targets"][0]["evidenceState"] = json!("compat-verified");
        value["targets"][0]["receiptRefs"] = json!(["spec/compatibility/evidence/unbound.json"]);
    });

    let report = check(&fixture.0);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.contains("schema 1 cannot accept evidence promotion")));
}

#[test]
fn initial_schema_rejects_unverified_receipt_references() {
    let fixture = Fixture::new();
    fixture.json(
        "spec/compatibility/evidence/unbound.json",
        &json!({"status":"passed"}),
    );
    fixture.mutate(|value| {
        value["targets"][0]["receiptRefs"] = json!(["spec/compatibility/evidence/unbound.json"]);
    });

    let report = check(&fixture.0);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.contains("schema 1 receiptRefs must remain empty")));
}

#[test]
fn enterprise_exclusion_is_explicit_and_cannot_hide_a_standard_target() {
    let fixture = Fixture::new();
    fixture.mutate(|value| value["targets"][2]["scope"] = json!("enterprise-only"));
    assert!(!check(&fixture.0).is_ok());

    let fixture = Fixture::new();
    fixture.mutate(|value| value["targets"][3]["featureGroup"] = json!("FS-DATA-WRITE"));
    assert!(!check(&fixture.0).is_ok());

    let fixture = Fixture::new();
    fixture.mutate(|value| value["targets"][4]["scope"] = json!("target"));
    assert!(!check(&fixture.0).is_ok());

    let fixture = Fixture::new();
    fixture.mutate(|value| value["targets"][5]["scope"] = json!("target"));
    assert!(!check(&fixture.0).is_ok());

    let fixture = Fixture::new();
    fixture.mutate(|value| value["targets"][6]["scope"] = json!("target"));
    assert!(!check(&fixture.0).is_ok());
}

#[test]
fn initial_version_and_absent_predecessor_are_bound() {
    let fixture = Fixture::new();
    fixture.mutate(|value| value["denominatorVersion"] = json!("mutable-name"));
    assert!(!check(&fixture.0).is_ok());

    let fixture = Fixture::new();
    let previous = denominator();
    fixture.json("spec/compatibility/denominators/fixture-v0.json", &previous);
    fixture.mutate(|value| {
        value["parentDenominator"] = json!("spec/compatibility/denominators/fixture-v0.json");
    });
    let report = check(&fixture.0);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.contains("initial denominator must not name a predecessor")));
}

#[test]
fn source_snapshot_path_is_bound_to_the_version() {
    let fixture = Fixture::new();
    let original = fixture
        .0
        .join("spec/compatibility/upstream/2026-09-09-retry/discovery.json");
    let alternate = "spec/compatibility/upstream/2026-09-09-retry/alternate.json";
    fs::copy(&original, fixture.0.join(alternate)).unwrap();
    fixture.mutate(|value| value["sourceSnapshot"] = json!(alternate));

    let report = check(&fixture.0);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.contains("sourceSnapshot must match")));
}

#[cfg(unix)]
#[test]
fn source_snapshot_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let source = fixture
        .0
        .join("spec/compatibility/upstream/2026-09-09-retry/discovery.json");
    let real = fixture.0.join("real-discovery.json");
    fs::rename(&source, &real).unwrap();
    symlink(&real, &source).unwrap();

    let report = check(&fixture.0);
    assert!(report
        .problems
        .iter()
        .any(|problem| problem.contains("symlink")));
}
