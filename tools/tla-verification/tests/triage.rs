//! Repository integration coverage for the frozen full-property triage cohort.

use std::path::Path;

use tla_verification::verify_triage_report;

#[test]
fn repository_triage_covers_every_frozen_manifest_candidate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let report = root.join("verification/tla/triage/2026-08-31-full-property.json");

    let count = verify_triage_report(root, &report).expect("complete triage");

    assert_eq!(count, 22);
}
