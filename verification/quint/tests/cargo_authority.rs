//! Canonical Cargo dependency authority contracts.

use std::path::{Path, PathBuf};

use fireemu_verification_quint::cargo_authority::{build_authority, validate_authority_file};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("verification/quint must have a repository parent")
        .to_path_buf()
}

#[test]
fn checked_in_authority_matches_the_locked_reachable_dependency_graph() {
    let root = repository_root();
    validate_authority_file(
        &root,
        &root.join("verification/quint/evidence/cargo-authority.json"),
    )
    .expect("checked-in Cargo authority must be current");
}

#[test]
fn a_relative_repository_root_produces_the_same_authority() {
    let root = repository_root();
    let previous = std::env::current_dir().expect("current directory");
    std::env::set_current_dir(&root).expect("enter repository root");
    let relative = build_authority(Path::new(".")).expect("relative root must resolve");
    std::env::set_current_dir(previous).expect("restore current directory");
    let absolute = build_authority(&root).expect("absolute root must resolve");
    assert_eq!(relative, absolute);
}

#[test]
fn authority_is_path_independent_and_excludes_unrelated_workspace_packages() {
    let root = repository_root();
    let authority = build_authority(&root).expect("Cargo metadata must resolve offline");
    let serialized = serde_json::to_string(&authority).expect("authority must serialize");
    assert!(!serialized.contains(root.to_string_lossy().as_ref()));
    assert!(!serialized.contains("fireemu-adapter-ui"));
    assert_eq!(authority.root_package, "fireemu-verification-quint");
    assert_eq!(authority.target, "x86_64-unknown-linux-gnu");
    assert!(authority
        .packages
        .iter()
        .any(|package| package.name == "quint-connect"));
    for build_dependency in ["autocfg", "version_check"] {
        assert!(
            authority
                .packages
                .iter()
                .any(|package| package.name == build_dependency),
            "reachable build dependency is missing: {build_dependency}"
        );
    }
    assert!(
        authority
            .packages
            .iter()
            .all(|package| package.name != "proptest"),
        "dev-only dependencies must remain outside the authority"
    );
}
