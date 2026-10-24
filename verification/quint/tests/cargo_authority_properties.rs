//! Generated contracts for canonical Cargo graph identity and repository confinement.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fireemu_verification_quint::cargo_authority::{build_authority, CargoAuthority};
use fireemu_verification_quint::model::all_models;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use serde_json::{json, Value};

static CARGO_ENVIRONMENT: Mutex<()> = Mutex::new(());

struct MetadataFixture {
    directory: tempfile::TempDir,
    root: PathBuf,
    previous_cargo: Option<std::ffi::OsString>,
}

impl MetadataFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("metadata fixture directory");
        let root = fs::canonicalize(directory.path()).expect("canonical fixture root");
        Self {
            directory,
            root,
            previous_cargo: std::env::var_os("CARGO"),
        }
    }

    fn resolve(&self, metadata: &Value) -> Result<CargoAuthority, String> {
        let executable = self.directory.path().join("cargo-fixture");
        fs::write(&executable, "#!/bin/sh\nexec /bin/cat \"$0.json\"\n")
            .expect("metadata executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("executable permissions");
        fs::write(
            self.directory.path().join("cargo-fixture.json"),
            serde_json::to_vec(metadata).expect("metadata JSON"),
        )
        .expect("metadata response");
        std::env::set_var("CARGO", executable);
        build_authority(&self.root)
    }
}

impl Drop for MetadataFixture {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous_cargo {
            std::env::set_var("CARGO", previous);
        } else {
            std::env::remove_var("CARGO");
        }
    }
}

fn package(id: &str, name: &str, manifest: &Path) -> Value {
    json!({
        "id": id,
        "name": name,
        "version": "1.0.0",
        "source": null,
        "manifest_path": manifest,
        "targets": []
    })
}

fn dependency(id: &str, kind: &Value) -> Value {
    json!({"pkg": id, "dep_kinds": [{"kind": kind, "target": null}]})
}

fn node(id: &str, features: &[String], dependencies: &[Value]) -> Value {
    json!({"id": id, "features": features, "deps": dependencies})
}

fn metadata(root: &Path, features: &[String]) -> Value {
    let mut packages = vec![package(
        "verification",
        "fireemu-verification-quint",
        &root.join("verification/quint/Cargo.toml"),
    )];
    let mut nodes = vec![node(
        "verification",
        features,
        &[
            dependency("normal", &Value::Null),
            dependency("dev", &json!("dev")),
        ],
    )];
    let owners = all_models()
        .flat_map(|model| model.production_sources.iter().copied())
        .map(|source| Path::new(source).components().take(2).collect::<PathBuf>())
        .collect::<BTreeSet<_>>();
    for (index, owner) in owners.iter().enumerate() {
        let id = format!("owner-{index}");
        packages.push(package(
            &id,
            owner
                .file_name()
                .expect("owner name")
                .to_str()
                .expect("UTF-8 owner"),
            &root.join(owner).join("Cargo.toml"),
        ));
        nodes.push(node(&id, features, &[]));
    }
    for (id, dependencies) in [
        ("normal", vec![dependency("build", &json!("build"))]),
        ("build", vec![]),
        ("dev", vec![]),
        ("unrelated", vec![]),
    ] {
        packages.push(package(
            id,
            id,
            &root.join("fixtures").join(id).join("Cargo.toml"),
        ));
        nodes.push(node(id, features, &dependencies));
    }
    json!({"packages": packages, "resolve": {"nodes": nodes}})
}

fn reorder(values: &mut [Value], selector: u64) {
    if !values.is_empty() {
        let length = u64::try_from(values.len()).expect("fixture length");
        values.rotate_left(usize::try_from(selector % length).expect("bounded rotation"));
        if selector & 2 != 0 {
            values.reverse();
        }
    }
}

fn permute(metadata: &mut Value, selectors: &[u64; 4]) {
    reorder(
        metadata["packages"].as_array_mut().expect("packages"),
        selectors[0],
    );
    let nodes = metadata["resolve"]["nodes"].as_array_mut().expect("nodes");
    reorder(nodes, selectors[1]);
    for node in nodes {
        reorder(node["deps"].as_array_mut().expect("deps"), selectors[2]);
        reorder(
            node["features"].as_array_mut().expect("features"),
            selectors[3],
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct("proptest-regressions/cargo_authority_properties.txt"))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn canonical_graph_is_invariant_under_generated_order_and_location(
        selectors in any::<[u64; 4]>(),
        generated_features in prop::collection::vec("[a-z][a-z0-9_]{0,8}", 0..8),
    ) {
        let _environment = CARGO_ENVIRONMENT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut features = BTreeSet::from(["a_default".to_owned(), "z_boundary".to_owned()]);
        features.extend(generated_features);
        let features: Vec<_> = features.into_iter().collect();
        let first = MetadataFixture::new();
        let baseline = first.resolve(&metadata(&first.root, &features)).expect("baseline graph");
        let second = MetadataFixture::new();
        let mut changed = metadata(&second.root, &features);
        permute(&mut changed, &selectors);
        let reordered = second.resolve(&changed).expect("permuted graph");
        prop_assert_eq!(&baseline, &reordered);
        let names: BTreeSet<_> = baseline.packages.iter().map(|package| package.name.as_str()).collect();
        prop_assert!(names.contains("normal"));
        prop_assert!(names.contains("build"));
        prop_assert!(!names.contains("dev"));
        prop_assert!(!names.contains("unrelated"));
        let serialized = serde_json::to_string(&reordered).expect("authority JSON");
        prop_assert!(!serialized.contains(first.root.to_str().expect("first root")));
        prop_assert!(!serialized.contains(second.root.to_str().expect("second root")));
    }

    #[test]
    fn generated_outside_repository_manifests_are_rejected(name in "[a-z]{1,16}") {
        let _environment = CARGO_ENVIRONMENT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = MetadataFixture::new();
        let mut changed = metadata(&fixture.root, &[]);
        let packages = changed["packages"].as_array_mut().expect("packages");
        let normal = packages.iter_mut().find(|package| package["id"] == "normal").expect("normal package");
        normal["manifest_path"] = json!(fixture.root.parent().expect("root parent").join(name).join("Cargo.toml"));
        let error = fixture.resolve(&changed).expect_err("outside repository manifest");
        prop_assert!(error.contains("outside repository"), "{error}");
    }
}
