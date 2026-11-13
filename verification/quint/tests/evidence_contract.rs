//! Model-neutral evidence contracts for the Quint verification authority.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fireemu_verification_quint::evidence::{
    current_input_digest, expected_bound_inputs, validate_evidence_file, validate_evidence_json,
};
use fireemu_verification_quint::model::{all_models, model, ModelDescriptor};

const EVIDENCE: &str = include_str!("../evidence/EventDelivery.json");
const TAMPER_TARGETS: [&str; 9] = [
    ".github/workflows/quint.yml",
    "rust-toolchain.toml",
    "crates/fireemu-core-events/src/state.rs",
    "verification/quint/evidence/cargo-authority.json",
    "verification/quint/run-verification.sh",
    "verification/quint/specs/EventDelivery.qnt",
    "verification/quint/configs/EventDelivery.json",
    "verification/quint/mutations/EventDelivery.json",
    "verification/quint/src/event_delivery.rs",
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("verification/quint must have a repository parent")
        .to_path_buf()
}

fn descriptor() -> &'static ModelDescriptor {
    model("EventDelivery").expect("EventDelivery must remain registered")
}

#[test]
fn every_registered_model_binds_all_descriptor_inputs() {
    let root = repository_root();
    for descriptor in all_models() {
        let inputs = expected_bound_inputs(&root, descriptor, None).expect("current inputs");
        let relative_inputs = [
            descriptor.spec,
            descriptor.config,
            descriptor.mutation_manifest,
        ]
        .map(|path| format!("verification/quint/{path}"));
        for path in relative_inputs.iter().map(String::as_str).chain(
            [descriptor.driver, descriptor.connect_test]
                .into_iter()
                .chain(descriptor.production_sources.iter().copied())
                .chain(descriptor.additional_evidence_inputs.iter().copied()),
        ) {
            assert!(
                inputs.iter().any(|input| input == path),
                "{} omitted descriptor input {path}",
                descriptor.name
            );
        }
    }
}

fn assert_rejected(value: &serde_json::Value) {
    let json = serde_json::to_string(value).expect("changed evidence must serialize");
    assert!(
        validate_evidence_json(&json, descriptor(), Some(&repository_root())).is_err(),
        "changed evidence unexpectedly validated: {json}"
    );
}

#[test]
fn checked_in_evidence_satisfies_the_generic_contract() {
    validate_evidence_json(EVIDENCE, descriptor(), Some(&repository_root()))
        .expect("checked-in evidence must validate");
}

#[test]
fn unrelated_workspace_and_ci_inputs_are_not_bound() {
    let evidence: serde_json::Value = serde_json::from_str(EVIDENCE).expect("valid evidence JSON");
    let bound_inputs = evidence["boundInputs"]
        .as_array()
        .expect("bound inputs")
        .iter()
        .map(|value| value.as_str().expect("bound input string"))
        .collect::<Vec<_>>();
    for unrelated in ["Cargo.toml", "Cargo.lock", ".github/workflows/ci.yml"] {
        assert!(
            !bound_inputs.contains(&unrelated),
            "unrelated input remains bound: {unrelated}"
        );
    }
}

#[test]
fn every_registered_model_has_current_checked_in_evidence() {
    let root = repository_root();
    for descriptor in all_models() {
        let path = root
            .join("verification/quint/evidence")
            .join(format!("{}.json", descriptor.name));
        validate_evidence_file(&root, &path, descriptor).unwrap_or_else(|error| {
            panic!(
                "{} checked-in evidence is invalid: {error}",
                descriptor.name
            )
        });
    }
}

#[test]
fn checked_in_evidence_binds_the_apalache_distribution() {
    let evidence: serde_json::Value = serde_json::from_str(EVIDENCE).expect("valid evidence JSON");
    assert_eq!(evidence["tools"]["apalache"], "0.56.1");
    assert_eq!(
        evidence["tools"]["apalacheArchiveSha256"],
        "91125e5a3646b9c9d3a7d921d3323f321fac5071909f72b3960c66ff2f998ee1"
    );
    assert_eq!(
        evidence["tools"]["apalacheLauncherSha256"],
        "bda52d2dbdbc7f6e95289a69dfe7ddeb162493ddd3501898d33ea7d1da3a8cd7"
    );
    assert_eq!(
        evidence["tools"]["apalacheJarSha256"],
        "4753c0ebb2cbb266e2c6ac19ab5ca3827d726cc80fd1fc5d7c1eeb64736cd60b"
    );
}

#[test]
fn mutation_results_are_exact_ordered_and_killed() {
    let baseline: serde_json::Value = serde_json::from_str(EVIDENCE).expect("valid evidence JSON");

    let mut missing = baseline.clone();
    missing["mutations"]
        .as_array_mut()
        .expect("mutations array")
        .pop();
    assert_rejected(&missing);

    let mut extra = baseline.clone();
    let duplicate = extra["mutations"][0].clone();
    extra["mutations"]
        .as_array_mut()
        .expect("mutations array")
        .push(duplicate);
    assert_rejected(&extra);

    let mut reordered = baseline.clone();
    reordered["mutations"]
        .as_array_mut()
        .expect("mutations array")
        .swap(0, 1);
    assert_rejected(&reordered);

    for outcome in ["survived", "timeout", "tool_error"] {
        let mut changed = baseline.clone();
        changed["mutations"][0]["outcome"] = outcome.into();
        assert_rejected(&changed);
    }

    let mut wrong_property = baseline;
    wrong_property["mutations"][0]["property"] = "AttemptsBounded".into();
    assert_rejected(&wrong_property);
}

#[test]
fn every_bound_input_tamper_invalidates_evidence() {
    let baseline: serde_json::Value = serde_json::from_str(EVIDENCE).expect("valid evidence JSON");
    let bound_inputs = baseline["boundInputs"]
        .as_array()
        .expect("evidence must record bound inputs")
        .iter()
        .map(|value| value.as_str().expect("bound input must be a string"))
        .collect::<Vec<_>>();

    for target in TAMPER_TARGETS {
        assert!(
            bound_inputs.contains(&target),
            "missing tamper target {target}"
        );
        let temporary = OwnedTestRepository::copy_inputs(&bound_inputs).expect("copy bound inputs");
        validate_evidence_json(EVIDENCE, descriptor(), Some(&temporary.path))
            .expect("untampered copied fixture must validate");
        let path = temporary.path.join(target);
        let mut bytes = fs::read(&path).expect("read copied bound input");
        if target == "verification/quint/evidence/cargo-authority.json" {
            let mut authority: serde_json::Value =
                serde_json::from_slice(&bytes).expect("valid authority");
            authority["packages"][0]["version"] = "tampered-version".into();
            bytes = serde_json::to_vec(&authority).expect("serialize authority");
        } else if std::path::Path::new(AsRef::<str>::as_ref(&target))
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            let mut json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
            json["tampered"] = true.into();
            bytes = serde_json::to_vec(&json).expect("serialize JSON");
        } else if std::path::Path::new(AsRef::<str>::as_ref(&target))
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        {
            bytes.extend_from_slice(b"\nconst _: () = ();\n");
        } else {
            bytes.push(b'!');
        }
        fs::write(&path, bytes).expect("tamper copied bound input");
        assert!(
            validate_evidence_json(EVIDENCE, descriptor(), Some(&temporary.path)).is_err(),
            "tampered input unexpectedly validated: {target}"
        );
    }
}

struct OwnedTestRepository {
    path: PathBuf,
}

impl OwnedTestRepository {
    fn copy_inputs(relative_paths: &[&str]) -> std::io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fireemu-quint-generic-evidence-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        for relative in relative_paths {
            let destination = path.join(relative);
            fs::create_dir_all(destination.parent().unwrap_or(Path::new(".")))?;
            fs::copy(repository_root().join(relative), destination)?;
        }
        Ok(Self { path })
    }
}

impl Drop for OwnedTestRepository {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn firestore_value_changes_invalidate_dependent_model_evidence() {
    const TARGET: &str = "crates/fireemu-core-firestore/src/value.rs";
    let root = repository_root();
    for name in [
        "AtomicCommitOutbox",
        "FirestoreListenRefresh",
        "TransactionConditionalLock",
    ] {
        let descriptor = model(name).expect("registered Firestore model");
        let json =
            fs::read_to_string(root.join(format!("verification/quint/evidence/{name}.json")))
                .expect("checked-in evidence");
        let evidence: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let inputs: Vec<_> = evidence["boundInputs"]
            .as_array()
            .expect("bound inputs")
            .iter()
            .map(|value| value.as_str().expect("bound path"))
            .collect();
        assert!(inputs.contains(&TARGET), "{name} must bind value semantics");
        let fixture = OwnedTestRepository::copy_inputs(&inputs).expect("copy inputs");
        validate_evidence_json(&json, descriptor, Some(&fixture.path))
            .expect("untampered fixture must validate");
        let path = fixture.path.join(TARGET);
        let mut bytes = fs::read(&path).expect("read value source");
        bytes.extend_from_slice(b"\nconst _: () = ();\n");
        fs::write(path, bytes).expect("mutate value source only");
        let error = validate_evidence_json(&json, descriptor, Some(&fixture.path))
            .expect_err("value-only change must stale evidence");
        assert!(
            error.contains(&format!("digest mismatch for {TARGET}")),
            "unexpected evidence failure: {error}"
        );
    }
}

#[test]
fn transitive_helper_tampering_and_inventory_changes_stale_evidence() {
    let root = repository_root();
    for (name, target) in [
        ("SessionEpoch", "crates/fireemu-core-types/src/ids.rs"),
        ("AuthTotp", "crates/fireemu-core-auth/src/sha1.rs"),
        ("AuthTotp", "crates/fireemu-core-types/src/time.rs"),
    ] {
        let descriptor = model(name).expect("registered model");
        let json =
            fs::read_to_string(root.join(format!("verification/quint/evidence/{name}.json")))
                .expect("checked-in evidence");
        let evidence: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let inputs: Vec<_> = evidence["boundInputs"]
            .as_array()
            .expect("bound inputs")
            .iter()
            .map(|path| path.as_str().expect("path"))
            .collect();
        assert!(inputs.contains(&target), "{name} must bind {target}");
        for operation in ["edit", "add", "delete", "unrelated"] {
            let fixture = OwnedTestRepository::copy_inputs(&inputs).expect("copy semantic inputs");
            validate_evidence_json(&json, descriptor, Some(&fixture.path))
                .expect("copied baseline must validate before any mutation");
            let path = fixture.path.join(target);
            match operation {
                "edit" => {
                    let mut bytes = fs::read(&path).expect("read helper");
                    bytes.extend_from_slice(b"\nconst _: () = ();\n");
                    fs::write(&path, bytes).expect("edit helper");
                }
                "add" => fs::write(
                    path.with_file_name("new_semantic_helper.rs"),
                    "pub fn helper() {}\n",
                )
                .expect("add source"),
                "delete" => fs::remove_file(&path).expect("remove source"),
                "unrelated" => {
                    let unrelated = fixture.path.join("tools/unrelated/src/lib.rs");
                    fs::create_dir_all(unrelated.parent().expect("unrelated parent"))
                        .expect("unrelated directory");
                    fs::write(unrelated, "pub fn unrelated() {}\n").expect("unrelated source");
                }
                _ => unreachable!(),
            }
            let result = validate_evidence_json(&json, descriptor, Some(&fixture.path));
            if operation == "unrelated" {
                result.expect("unrelated source must preserve evidence");
            } else {
                let error = result.expect_err("transitive helper mutation must stale evidence");
                assert!(
                    error.contains(if operation == "edit" {
                        "digest mismatch"
                    } else {
                        "bound inputs mismatch"
                    }),
                    "unexpected failure for {name}/{operation}: {error}"
                );
            }
        }
    }
}

#[test]
fn evidence_validation_without_repository_inventory_fails_closed() {
    let error = validate_evidence_json(EVIDENCE, descriptor(), None)
        .expect_err("source-bound evidence requires repository inventory");
    assert!(error.contains("repository root is required"), "{error}");
}

const TEST_ONLY_PROBE_CASES: [(&str, &str, &str, bool); 20] = [
    ("", "", "tests/binding_probe.rs", false),
    ("", "", "benches/binding_probe.rs", false),
    ("", "", "examples/binding_probe.rs", false),
    (
        "#[cfg(test)]\nmod binding_probe;\n",
        "",
        "src/binding_probe.rs",
        false,
    ),
    (
        "#[cfg(test)]\n#[allow(dead_code)]\n/// Test module.\nmod binding_probe;\n",
        "",
        "src/binding_probe.rs",
        false,
    ),
    (
        "#[cfg(test)]\nmod binding_probe;\n",
        "",
        "src/binding_probe/mod.rs",
        false,
    ),
    (
        "#[cfg(test)]\nmod binding_probe;\n#[cfg(test)]\nmod binding_probe;\n",
        "",
        "src/binding_probe.rs",
        false,
    ),
    (
        "#[cfg(test)]\nmod binding_probe;\nmod binding_probe;\n",
        "",
        "src/binding_probe.rs",
        true,
    ),
    (
        "#[cfg(test)]\n#[path = \"binding_probe.rs\"]\nmod redirected;\n",
        "",
        "src/binding_probe.rs",
        true,
    ),
    (
        "#[cfg(test)]\nmod binding_probe;\n#[path = \"binding_probe.rs\"]\nmod redirected;\n",
        "",
        "src/binding_probe.rs",
        true,
    ),
    (
        "#[cfg(test)]\nmod binding_probe;\n",
        "#[path = \"binding_probe.rs\"]\nmod redirected;\n",
        "src/binding_probe.rs",
        true,
    ),
    (
        "#[cfg(test)]\nmod binding_probe;\ninclude!(\"binding_probe.rs\");\n",
        "",
        "src/binding_probe.rs",
        true,
    ),
    (
        "#[cfg(test)]\nmod binding_probe;\n",
        "include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/binding_probe.rs\"));\n",
        "src/binding_probe.rs",
        true,
    ),
    (
        "#[cfg(test)]\nmod binding_probe;\n",
        "include!(env!(\"GENERATED_SOURCE\"));\n",
        "src/binding_probe.rs",
        true,
    ),
    (
        "#[path = \"elsewhere.rs\"]\n#[cfg(test)]\nmod binding_probe;\n",
        "",
        "src/binding_probe.rs",
        true,
    ),
    (
        "#[cfg(all(test))]\nmod binding_probe;\n",
        "",
        "src/binding_probe.rs",
        true,
    ),
    (
        "/*\n#[cfg(test)]\nmod binding_probe;\n*/\n",
        "",
        "src/binding_probe.rs",
        true,
    ),
    (
        "const TEXT: &str = r#\"\n#[cfg(test)]\nmod binding_probe;\n\"#;\n",
        "",
        "src/binding_probe.rs",
        true,
    ),
    ("mod binding_probe;\n", "", "src/binding_probe.rs", true),
    ("", "", "src/state.rs", true),
];

#[test]
fn test_only_file_edits_preserve_evidence_and_other_references_remain_bound() {
    let root = repository_root();
    let descriptor = descriptor();
    let inputs = expected_bound_inputs(&root, descriptor, None).expect("current inputs");
    let inputs: Vec<_> = inputs.iter().map(String::as_str).collect();
    for (declaration, other_source, relative, bound) in TEST_ONLY_PROBE_CASES {
        let fixture = OwnedTestRepository::copy_inputs(&inputs).expect("copy current inputs");
        let parent = fixture.path.join("crates/fireemu-core-events/src/lib.rs");
        let mut source = fs::read_to_string(&parent).expect("parent module");
        source.push_str(declaration);
        fs::write(parent, source).expect("declare probe module");
        if !other_source.is_empty() {
            fs::write(
                fixture.path.join("crates/fireemu-core-events/src/other.rs"),
                other_source,
            )
            .expect("other source reference");
        }
        let relative = format!("crates/fireemu-core-events/{relative}");
        let path = fixture.path.join(&relative);
        fs::create_dir_all(path.parent().expect("probe parent")).expect("probe directory");
        if !path.exists() {
            fs::write(&path, "pub fn probe() {}\n").expect("probe source");
        }
        let required =
            expected_bound_inputs(&fixture.path, descriptor, None).expect("fixture inputs");
        assert_eq!(
            required.contains(&relative),
            bound,
            "{declaration:?} / {other_source:?} / {relative}"
        );
        let mut evidence: serde_json::Value =
            serde_json::from_str(EVIDENCE).expect("evidence metadata");
        evidence["boundInputs"] = serde_json::to_value(&required).expect("bound inputs");
        evidence["digests"] = serde_json::to_value(
            required
                .iter()
                .map(|relative| {
                    (
                        relative.clone(),
                        current_input_digest(&fixture.path, relative).expect("current digest"),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
        .expect("digests");
        let json = serde_json::to_string(&evidence).expect("fixture evidence");
        validate_evidence_json(&json, descriptor, Some(&fixture.path)).expect("current baseline");
        let original = fs::read(&path).expect("probe bytes");
        let mut edited = original.clone();
        edited.extend_from_slice(b"\n#[cfg(test)] mod added_inline { #[test] fn new_test() {} }\n");
        fs::write(&path, edited).expect("edit probe");
        let result = validate_evidence_json(&json, descriptor, Some(&fixture.path));
        if bound {
            assert!(result
                .expect_err("production edit must stale evidence")
                .contains("digest mismatch"));
        } else {
            result.expect("test-only edit must preserve evidence");
        }
        fs::write(&path, original).expect("restore probe");
        evidence["boundInputs"]
            .as_array_mut()
            .expect("inputs")
            .retain(|value| value != "crates/fireemu-core-events/src/state.rs");
        evidence["digests"]
            .as_object_mut()
            .expect("digests")
            .remove("crates/fireemu-core-events/src/state.rs");
        let error = validate_evidence_json(&evidence.to_string(), descriptor, Some(&fixture.path))
            .expect_err("omitted production input must be rejected");
        assert!(error.contains("bound inputs mismatch"), "{error}");
    }
}

#[test]
fn test_only_edits_follow_each_models_binding() {
    let root = repository_root();
    for descriptor in all_models() {
        let inputs = expected_bound_inputs(&root, descriptor, None).expect("current inputs");
        let moved_modules = [
            (
                "crates/fireemu-core-auth/src/mfa.rs",
                "crates/fireemu-core-auth/src/mfa/critical_mutant_gaps.rs",
            ),
            (
                "crates/fireemu-adapter-functions/src/runtime.rs",
                "crates/fireemu-adapter-functions/src/runtime/restart_budget_tests.rs",
            ),
            (
                "crates/fireemu-adapter-functions/src/runtime.rs",
                "crates/fireemu-adapter-functions/src/runtime/task_completion_tests.rs",
            ),
            (
                "crates/fireemu-adapter-functions/src/runtime.rs",
                "crates/fireemu-adapter-functions/src/runtime/schedule_capacity_tests.rs",
            ),
            (
                "crates/fireemu-adapter-functions/src/runtime.rs",
                "crates/fireemu-adapter-functions/src/runtime/storage_event_instant_tests.rs",
            ),
            (
                "crates/fireemu-adapter-functions/src/runtime.rs",
                "crates/fireemu-adapter-functions/src/runtime/event_frame_member_tests.rs",
            ),
        ];
        let paths: Vec<_> = inputs.iter().map(String::as_str).collect();
        let fixture = OwnedTestRepository::copy_inputs(&paths).expect("copy inputs");
        let mut evidence: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join(format!(
                "verification/quint/evidence/{}.json",
                descriptor.name
            )))
            .expect("evidence metadata"),
        )
        .expect("valid metadata");
        evidence["boundInputs"] = serde_json::to_value(&inputs).expect("inputs");
        evidence["digests"] = serde_json::to_value(
            inputs
                .iter()
                .map(|relative| {
                    (
                        relative.clone(),
                        current_input_digest(&fixture.path, relative).expect("current digest"),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
        .expect("digests");
        let json = evidence.to_string();
        validate_evidence_json(&json, descriptor, Some(&fixture.path)).expect("current baseline");
        for (parent, child) in moved_modules {
            if !inputs.iter().any(|path| path == parent) {
                continue;
            }
            let path = fixture.path.join(child);
            fs::create_dir_all(path.parent().expect("module parent")).expect("module directory");
            let original = fs::read(&path).ok();
            for bytes in ["#[test] fn added_test() {}\n", "/* unfinished test edit"] {
                fs::write(&path, bytes).expect("edit separate test module");
                let result = validate_evidence_json(&json, descriptor, Some(&fixture.path));
                if inputs.iter().any(|input| input == child) {
                    assert!(result
                        .expect_err("bound edit must stale evidence")
                        .contains("digest mismatch"));
                } else {
                    result.unwrap_or_else(|error| panic!("{} / {child}: {error}", descriptor.name));
                }
            }
            if let Some(original) = original {
                fs::write(&path, original).expect("restore separate test module");
            }
        }
        let path = fixture.path.join(descriptor.connect_test);
        fs::create_dir_all(path.parent().expect("test parent")).expect("test directory");
        for bytes in ["// Original test.\n", "// Changed test.\n"] {
            fs::write(&path, bytes).expect("edit test file");
            let result = validate_evidence_json(&json, descriptor, Some(&fixture.path));
            if inputs.iter().any(|input| input == descriptor.connect_test) {
                assert!(result
                    .expect_err("bound edit must stale evidence")
                    .contains("digest mismatch"));
            } else {
                result.unwrap_or_else(|error| panic!("{}: {error}", descriptor.name));
            }
        }
    }
}
