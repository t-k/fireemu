//! Model-neutral evidence contracts for the Quint verification authority.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fireemu_verification_quint::evidence::validate_evidence_json;
use fireemu_verification_quint::model::{model, ModelDescriptor};

const EVIDENCE: &str = include_str!("../evidence/EventDelivery.json");
const TAMPER_TARGETS: [&str; 9] = [
    ".github/workflows/ci.yml",
    "Cargo.lock",
    "crates/fireemu-core-events/src/state.rs",
    "verification/quint/run-pilot.sh",
    "verification/quint/specs/EventDelivery.qnt",
    "verification/quint/specs/tlc-config.json",
    "verification/quint/mutations/EventDelivery.json",
    "verification/quint/src/event_delivery.rs",
    "verification/quint/tests/event_delivery_connect.rs",
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

fn assert_rejected(value: serde_json::Value) {
    let json = serde_json::to_string(&value).expect("changed evidence must serialize");
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
fn mutation_results_are_exact_ordered_and_killed() {
    let baseline: serde_json::Value = serde_json::from_str(EVIDENCE).expect("valid evidence JSON");

    let mut missing = baseline.clone();
    missing["mutations"]
        .as_array_mut()
        .expect("mutations array")
        .pop();
    assert_rejected(missing);

    let mut extra = baseline.clone();
    let duplicate = extra["mutations"][0].clone();
    extra["mutations"]
        .as_array_mut()
        .expect("mutations array")
        .push(duplicate);
    assert_rejected(extra);

    let mut reordered = baseline.clone();
    reordered["mutations"]
        .as_array_mut()
        .expect("mutations array")
        .swap(0, 1);
    assert_rejected(reordered);

    for outcome in ["survived", "timeout", "tool_error"] {
        let mut changed = baseline.clone();
        changed["mutations"][0]["outcome"] = outcome.into();
        assert_rejected(changed);
    }

    let mut wrong_property = baseline;
    wrong_property["mutations"][0]["property"] = "AttemptsBounded".into();
    assert_rejected(wrong_property);
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
        let path = temporary.path.join(target);
        let mut bytes = fs::read(&path).expect("read copied bound input");
        bytes.push(b'!');
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
